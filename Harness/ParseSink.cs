using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace MapleShark2.Harness {
    /// <summary>One typed read performed by a decoder script.</summary>
    public struct ReadEvent {
        public int Offset;      // relative to packet start
        public int Size;
        public string Type;     // "Byte", "Int32", "Field", ...
        public string Label;    // the name the script gave it
        public string NodePath; // "Item/ItemStats" — where in the tree it landed
        public string Value;    // rendered value, for value-class comparison across builds

        public override string ToString() => $"{Offset,5}  {Size,3}  {Type,-8} {NodePath}{(NodePath.Length > 0 ? "/" : "")}{Label} = {Value}";
    }

    /// <summary>
    /// Headless stand-in for MapleShark2.UI.StructureForm.
    ///
    /// Scripts reach this through <c>import structure_form as sf</c> (script_api.py), so the six public
    /// members below are a duck-typed contract with script_api.py — their names and signatures must match
    /// StructureForm's exactly or every script breaks. It is bound once per engine when script_api is first
    /// imported, so this instance must live as long as its engine and be mutated per packet via Begin(),
    /// never swapped out.
    ///
    /// Unlike StructureForm this allocates no UI nodes; it optionally records a flat read trace instead.
    /// </summary>
    public sealed class ParseSink {
        private readonly Stack<string> nodes = new Stack<string>();
        private readonly List<ReadEvent> trace = new List<ReadEvent>();
        private BoundedByteReader reader;

        // Always-on lightweight failure context (no trace allocation). Maintained even when TraceEnabled
        // is false so ScriptHost can compose an over-read signature without a full trace: the normalized
        // node path (rebuilt only on Start/EndNode, never per read) plus the last read's label and type.
        private readonly List<string> normNodes = new List<string>();
        private string normPath = "";
        private string lastLabel = "";
        private string lastType = "";

        // Optional per-field value aggregation (--fields). Null on the normal path => zero overhead.
        private Dictionary<string, FieldAgg> fieldCtx;

        public bool TraceEnabled { get; set; }
        public IReadOnlyList<ReadEvent> Trace => trace;

        /// <summary>Normalized current node path (digit runs collapsed to '#'), for failure signatures.</summary>
        public string NormNodePath => normPath;

        /// <summary>Label of the last read attempted (set before the read, so it names a failing read).</summary>
        public string LastLabel => lastLabel;

        /// <summary>Type name of the last read attempted.</summary>
        public string LastType => lastType;

        /// <summary>Set the per-field aggregation target for the next packet, or null to disable.</summary>
        public void SetFieldContext(Dictionary<string, FieldAgg> ctx) => fieldCtx = ctx;

        /// <summary>Messages the script emitted via log(). Scripts use these to flag their own uncertainty.</summary>
        public List<string> Logs { get; } = new List<string>();

        public void Begin(BoundedByteReader packetReader) {
            reader = packetReader;
            nodes.Clear();
            trace.Clear();
            Logs.Clear();
            normNodes.Clear();
            normPath = "";
            lastLabel = "";
            lastType = "";
        }

        private string CurrentPath => nodes.Count == 0 ? "" : string.Join("/", ReverseNodes());

        private IEnumerable<string> ReverseNodes() {
            var array = nodes.ToArray();
            Array.Reverse(array);
            return array;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Record(int offset, int size, string type, string label, string value) {
            if (!TraceEnabled) return;
            trace.Add(new ReadEvent {
                Offset = offset, Size = size, Type = type,
                Label = label ?? "", NodePath = CurrentPath, Value = value,
            });
        }

        // ---- structure_form contract (must mirror StructureForm) ----

        public T Add<T>(string name) where T : struct {
            // Set the failure context BEFORE the read so, if the read over-runs, it names the field that
            // was being decoded (where the parse diverged) rather than the previous successful one.
            lastType = typeof(T).Name;
            lastLabel = name ?? "";
            int offset = reader.Consumed;
            T value = reader.Read<T>(); // throws OverReadException past the end
            Record(offset, Unsafe.SizeOf<T>(), lastType, name, Convert.ToString(value));
            if (fieldCtx != null) {
                FieldFor(name, lastType).AddNumeric(Convert.ToDouble(value), value.ToString());
            }

            return value;
        }

        public byte[] AddField(string name, int length) {
            lastType = "Field";
            lastLabel = name ?? "";
            int offset = reader.Consumed;
            byte[] data = reader.ReadBytes(length);
            Record(offset, length, "Field", name, Hex(data));
            if (fieldCtx != null) FieldFor(name, "Field").AddBlob(data.Length);
            return data;
        }

        public void StartNode(string name) {
            nodes.Push(name ?? "");
            normNodes.Add(NormDigits(name ?? ""));
            normPath = string.Join("/", normNodes);
        }

        public void EndNode(bool expand) {
            if (nodes.Count > 0) nodes.Pop();
            if (normNodes.Count > 0) {
                normNodes.RemoveAt(normNodes.Count - 1);
                normPath = string.Join("/", normNodes);
            }
        }

        public int Remaining() => reader.Available;

        public void Log(string message, string level) {
            Logs.Add($"[{level}] {message}");
        }

        // ---- helpers ----

        /// <summary>
        /// Resolve the aggregate for the current field. The key is the normalized node path plus the
        /// digit-normalized label and the read's type name — so "StatOption 3/Value" and
        /// "StatOption 12/Value" collapse to the same field across builds. One key-string allocation per
        /// read is the only cost (and only when --fields is set); the node path is cached, not rebuilt.
        /// </summary>
        private FieldAgg FieldFor(string label, string type) {
            string key = normPath + "/" + NormDigits(label ?? "") + ":" + type;
            if (!fieldCtx.TryGetValue(key, out FieldAgg agg)) {
                fieldCtx[key] = agg = new FieldAgg();
            }

            return agg;
        }

        /// <summary>Collapse every run of decimal digits to a single '#'. Allocation-free when there are none.</summary>
        public static string NormDigits(string s) {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            bool any = false;
            for (int i = 0; i < s.Length; i++) {
                if (s[i] >= '0' && s[i] <= '9') { any = true; break; }
            }

            if (!any) return s;

            var sb = new StringBuilder(s.Length);
            bool inDigits = false;
            foreach (char c in s) {
                if (c >= '0' && c <= '9') {
                    if (!inDigits) { sb.Append('#'); inDigits = true; }
                } else {
                    sb.Append(c);
                    inDigits = false;
                }
            }

            return sb.ToString();
        }

        private static string Hex(byte[] data) {
            if (data.Length == 0) return "";
            var sb = new StringBuilder();
            int n = Math.Min(data.Length, 16);
            for (int i = 0; i < n; i++) sb.Append(data[i].ToString("X2"));
            if (data.Length > n) sb.Append("..");
            return sb.ToString();
        }
    }
}

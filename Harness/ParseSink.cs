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

        public bool TraceEnabled { get; set; }
        public IReadOnlyList<ReadEvent> Trace => trace;

        /// <summary>Messages the script emitted via log(). Scripts use these to flag their own uncertainty.</summary>
        public List<string> Logs { get; } = new List<string>();

        public void Begin(BoundedByteReader packetReader) {
            reader = packetReader;
            nodes.Clear();
            trace.Clear();
            Logs.Clear();
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
            int offset = reader.Consumed;
            T value = reader.Read<T>(); // throws OverReadException past the end
            Record(offset, Unsafe.SizeOf<T>(), typeof(T).Name, name, Convert.ToString(value));
            return value;
        }

        public byte[] AddField(string name, int length) {
            int offset = reader.Consumed;
            byte[] data = reader.ReadBytes(length);
            Record(offset, length, "Field", name, Hex(data));
            return data;
        }

        public void StartNode(string name) {
            nodes.Push(name ?? "");
        }

        public void EndNode(bool expand) {
            if (nodes.Count > 0) nodes.Pop();
        }

        public int Remaining() => reader.Available;

        public void Log(string message, string level) {
            Logs.Add($"[{level}] {message}");
        }

        // ---- helpers ----

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

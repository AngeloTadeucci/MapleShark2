using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using IronPython.Hosting;
using Microsoft.Scripting.Hosting;

namespace MapleShark2.Harness {
    /// <summary>
    /// Owns one IronPython engine per source build, with compiled-script caching.
    ///
    /// Differences from MapleShark2.Tools.ScriptManager, all deliberate:
    ///  - Scripts are Compile()d once and cached. ScriptManager re-reads and re-parses the .py from disk on
    ///    every single execution (its own TODO at ScriptManager.cs:61). That is survivable for one packet on
    ///    click; it is not survivable for millions.
    ///  - No FileSystemWatcher. A baseline run must be deterministic; scripts must not reload mid-measurement.
    ///  - Engine warm-up is synchronous. ScriptManager warms up on a fire-and-forget Task, which races the
    ///    first execution.
    /// </summary>
    public sealed class ScriptHost : IDisposable {
        private readonly string scriptsRoot;
        private readonly bool versionPathFirst;
        private readonly Dictionary<uint, Engine> engines = new Dictionary<uint, Engine>();

        private sealed class Engine {
            public ScriptEngine ScriptEngine;
            public ParseSink Sink;
            public Dictionary<string, CompiledCode> Compiled;
        }

        /// <param name="scriptsRoot">e.g. "…/MapleShark2 - Ochi/Scripts"</param>
        /// <param name="versionPathFirst">
        /// False reproduces shipping behaviour: ScriptManager.cs:88 adds the shared root to sys.path before
        /// :73 appends the version folder, so a shared root module shadows its version-specific override —
        /// backwards from what the README describes. The baseline must reproduce the bug rather than quietly
        /// fix it, or measured numbers won't describe the tool anyone is actually running. True tests the fix.
        /// </param>
        public ScriptHost(string scriptsRoot, bool versionPathFirst = false) {
            this.scriptsRoot = scriptsRoot;
            this.versionPathFirst = versionPathFirst;
        }

        public static string ScriptFolder(string root, uint build) => Path.Combine(root, "0", build.ToString());

        public static string ScriptPath(string root, uint build, bool outbound, ushort opcode) =>
            Path.Combine(ScriptFolder(root, build), outbound ? "Outbound" : "Inbound", $"0x{opcode:X4}.py");

        public string PathFor(uint build, bool outbound, ushort opcode) =>
            ScriptPath(scriptsRoot, build, outbound, opcode);

        public bool HasScript(uint build, bool outbound, ushort opcode) => File.Exists(PathFor(build, outbound, opcode));

        private Engine GetEngine(uint build) {
            if (engines.TryGetValue(build, out Engine cached)) return cached;

            ScriptEngine engine = Python.CreateEngine();
            var sink = new ParseSink();

            ICollection<string> paths = engine.GetSearchPaths();
            string versionFolder = ScriptFolder(scriptsRoot, build);
            if (versionPathFirst) {
                paths.Add(versionFolder);
                paths.Add(scriptsRoot);
            } else {
                paths.Add(scriptsRoot);
                paths.Add(versionFolder);
            }

            engine.SetSearchPaths(paths);

            // script_api.py does `import structure_form as sf` at module scope, binding sf exactly once when
            // the module is first imported. The sink therefore has to outlive every script this engine runs
            // and be mutated per packet — swapping the object would leave scripts writing into a dead one.
            engine.Runtime.Globals.SetVariable("structure_form", sink);
            engine.Execute("import script_api");

            var built = new Engine {
                ScriptEngine = engine,
                Sink = sink,
                Compiled = new Dictionary<string, CompiledCode>(),
            };

            engines[build] = built;
            return built;
        }

        /// <summary>Warm an engine so first-execution compile cost stays out of the measurement.</summary>
        public void Warm(uint build) => GetEngine(build);

        /// <summary>
        /// Shut down and drop one build's engine. The matrix sweep visits each source build exactly once,
        /// source-major; keeping ~40 IronPython runtimes alive simultaneously is pointless retention.
        /// A later Execute for the same build transparently recreates the engine.
        /// </summary>
        public void Release(uint build) {
            if (engines.Remove(build, out Engine engine)) {
                engine.ScriptEngine.Runtime.Shutdown();
            }
        }

        private readonly Dictionary<uint, string> envHashes = new Dictionary<uint, string>();
        private static readonly Dictionary<string, string> fileHashes = new Dictionary<string, string>();

        /// <summary>SHA-256 (first 12 hex chars) of one file — identity of a single opcode script.</summary>
        public static string FileSha(string path) {
            if (fileHashes.TryGetValue(path, out string cached)) return cached;
            using var sha = SHA256.Create();
            string hash = Convert.ToHexString(sha.ComputeHash(File.ReadAllBytes(path)))
                .Substring(0, 12).ToLowerInvariant();
            fileHashes[path] = hash;
            return hash;
        }

        /// <summary>
        /// Identity of the resolved decoder environment for one source build: the sys.path order flag plus
        /// every importable module — the top level of both search-path entries (shared root, incl.
        /// script_api.py/common.py/item.py, and the version folder). A manifest edge is evidence about
        /// script content, not a build number; hashing only the opcode file would miss exactly the shared
        /// modules Phase 2 edits. The opcode file itself is hashed separately per row (script_sha).
        /// </summary>
        public string EnvHash(uint build) {
            if (envHashes.TryGetValue(build, out string cached)) return cached;
            using IncrementalHash sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            sha.AppendData(new[] { versionPathFirst ? (byte) 1 : (byte) 0 });
            foreach (string dir in new[] { scriptsRoot, ScriptFolder(scriptsRoot, build) }) {
                if (!Directory.Exists(dir)) continue;
                foreach (string file in Directory.GetFiles(dir, "*.py")
                             .OrderBy(f => Path.GetFileName(f), StringComparer.OrdinalIgnoreCase)) {
                    sha.AppendData(Encoding.UTF8.GetBytes(Path.GetFileName(file)));
                    sha.AppendData(File.ReadAllBytes(file));
                }
            }

            string hash = Convert.ToHexString(sha.GetHashAndReset()).Substring(0, 12).ToLowerInvariant();
            envHashes[build] = hash;
            return hash;
        }

        /// <summary>Build dirs present under the scripts root, ascending.</summary>
        public IReadOnlyList<uint> AvailableBuilds() {
            string root = Path.Combine(scriptsRoot, "0");
            var builds = new List<uint>();
            if (!Directory.Exists(root)) return builds;
            foreach (string dir in Directory.GetDirectories(root)) {
                if (uint.TryParse(Path.GetFileName(dir), out uint build)) builds.Add(build);
            }

            builds.Sort();
            return builds;
        }

        /// <summary>
        /// Walk <paramref name="lineage"/> down from <paramref name="target"/> and return the first build whose
        /// dir holds this script, or null. The lineage is passed in rather than derived: which builds may
        /// inherit from which is a protocol fact, not something to guess from build-number proximity.
        /// </summary>
        public uint? Resolve(uint target, IReadOnlyList<uint> lineage, bool outbound, ushort opcode) {
            foreach (uint build in lineage.Where(b => b <= target).OrderByDescending(b => b)) {
                if (HasScript(build, outbound, opcode)) return build;
            }

            return null;
        }

        /// <summary>
        /// Run the decoder from <paramref name="sourceBuild"/> against one packet. Returns the outcome;
        /// the sink's trace is valid until the next call on the same source build.
        /// </summary>
        public ParseResult Execute(uint sourceBuild, RawPacket packet, bool trace,
            Dictionary<string, FieldAgg> fieldCtx = null) {
            string path = PathFor(sourceBuild, packet.Outbound, packet.Opcode);
            if (!File.Exists(path)) {
                return new ParseResult { Outcome = Outcome.NoScript, Declared = packet.Data.Length };
            }

            Engine engine = GetEngine(sourceBuild);

            if (!engine.Compiled.TryGetValue(path, out CompiledCode compiled)) {
                try {
                    compiled = engine.ScriptEngine.CreateScriptSourceFromFile(path).Compile();
                } catch (Exception ex) {
                    // A script that doesn't even parse is a defect in the script, distinct from a bad parse.
                    engine.Compiled[path] = null;
                    return new ParseResult {
                        Outcome = Outcome.CompileError, Declared = packet.Data.Length,
                        Error = Describe(ex), ScriptPath = path,
                    };
                }

                engine.Compiled[path] = compiled;
            }

            if (compiled == null) {
                return new ParseResult { Outcome = Outcome.CompileError, Declared = packet.Data.Length, ScriptPath = path };
            }

            var reader = new BoundedByteReader(packet.Data, 0, packet.Data.Length);
            engine.Sink.TraceEnabled = trace;
            engine.Sink.Begin(reader);
            engine.Sink.SetFieldContext(fieldCtx);

            try {
                // Fresh scope per packet, matching ScriptSource.Execute()'s no-arg behaviour in the GUI.
                // A reused scope would leak variables between packets and let one packet's state silently
                // satisfy the next packet's branch conditions.
                compiled.Execute(engine.ScriptEngine.CreateScope());
            } catch (OverReadException ex) {
                return new ParseResult {
                    Outcome = Outcome.OverRead, Reason = ex.Reason, Declared = reader.Length,
                    Consumed = reader.Consumed, Error = ex.Message, ScriptPath = path,
                    Signature = Signature(ex.Reason, ex.Message, engine.Sink),
                    Trace = trace ? Snapshot(engine.Sink) : null,
                };
            } catch (Exception ex) {
                // IronPython wraps script-raised errors; an OverReadException can arrive nested inside one.
                OverReadException inner = FindOverRead(ex);
                if (inner != null) {
                    return new ParseResult {
                        Outcome = Outcome.OverRead, Reason = inner.Reason, Declared = reader.Length,
                        Consumed = reader.Consumed, Error = inner.Message, ScriptPath = path,
                        Signature = Signature(inner.Reason, inner.Message, engine.Sink),
                        Trace = trace ? Snapshot(engine.Sink) : null,
                    };
                }

                return new ParseResult {
                    Outcome = Outcome.Threw, Declared = reader.Length, Consumed = reader.Consumed,
                    Error = Describe(ex), ScriptPath = path,
                    Trace = trace ? Snapshot(engine.Sink) : null,
                };
            }

            return new ParseResult {
                Outcome = reader.Available == 0 ? Outcome.OkExact : Outcome.UnderRead,
                Declared = reader.Length, Consumed = reader.Consumed,
                ScriptPath = path, Trace = trace ? Snapshot(engine.Sink) : null,
            };
        }

        /// <summary>
        /// Compose a per-failure signature for an over-read: the over-read reason, the exception message with
        /// every digit run collapsed to '#', the normalized node path, and the last read's label/type. This
        /// lets the classifier tell "same defect the decoder already has at home" from "new failure mode on
        /// the edge" without a rate comparison (PLAN.md §4.8). Sanitized so it survives CSV/sparse encoding:
        /// no ',' '|' or newline (all -> ';').
        /// </summary>
        private static string Signature(OverReadReason reason, string message, ParseSink sink) {
            string msg = ParseSink.NormDigits(message ?? "");
            string label = ParseSink.NormDigits(sink.LastLabel ?? "");
            string sig = $"{reason}: {msg} @ {sink.NormNodePath} [{label}:{sink.LastType}]";
            return sig.Replace(',', ';').Replace('|', ';').Replace('\r', ';').Replace('\n', ';');
        }

        private static List<ReadEvent> Snapshot(ParseSink sink) => new List<ReadEvent>(sink.Trace);

        private static OverReadException FindOverRead(Exception ex) {
            for (Exception e = ex; e != null; e = e.InnerException) {
                if (e is OverReadException over) return over;
            }

            return null;
        }

        private static string Describe(Exception ex) {
            string message = ex.Message ?? ex.GetType().Name;
            return message.Length > 300 ? message.Substring(0, 300) : message;
        }

        public void Dispose() {
            foreach (Engine engine in engines.Values) {
                engine.ScriptEngine.Runtime.Shutdown();
            }

            engines.Clear();
        }
    }

    public enum Outcome {
        /// <summary>No decoder exists for this (build, opcode, direction).</summary>
        NoScript,

        /// <summary>Decoder consumed the packet exactly. The only outcome that is unambiguously good.</summary>
        OkExact,

        /// <summary>Decoder stopped early. Expected for incomplete scripts; also what a desync can look like.</summary>
        UnderRead,

        /// <summary>Decoder ran past the end, or decoded a negative length. Unambiguously wrong.</summary>
        OverRead,

        /// <summary>Script raised a non-bounds error.</summary>
        Threw,

        /// <summary>Script does not compile.</summary>
        CompileError,
    }

    public sealed class ParseResult {
        public Outcome Outcome;
        public OverReadReason Reason;
        public int Declared;
        public int Consumed;
        public string Error;
        public string ScriptPath;
        public string Signature;
        public List<ReadEvent> Trace;

        public double ConsumedFraction => Declared == 0 ? 1.0 : (double) Consumed / Declared;
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using IronPython.Hosting;
using MapleShark2.UI;
using Microsoft.Scripting.Hosting;
using NLog;

namespace MapleShark2.Tools {
    public class ScriptManager {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private static readonly Regex LocaleVersionRegex = new Regex(@"^(\d+)[\\/](\d+)[\\/].+$");
        
        private readonly StructureForm form;
        private readonly Dictionary<(byte Locale, uint Version), ScriptEngine> engines;
        private readonly ScriptManifest manifest = new ScriptManifest();
        
        // ReSharper disable once PrivateFieldCanBeConvertedToLocalVariable
        // This needs to be a field to avoid being GCed.
        private readonly FileSystemWatcher watcher;

        public ScriptManager(StructureForm form) {
            this.form = form;
            this.engines = new Dictionary<(byte Locale, uint Version), ScriptEngine>();

            // reloads modules for all engines when changed
            // Watch scripts root folder (script_api.py & others)
            Helpers.MakeSureFileDirectoryExists(Helpers.GetScriptsRoot() + Path.DirectorySeparatorChar);
            SeedScriptApi();
            watcher = new FileSystemWatcher {
                Path = Helpers.GetScriptsRoot(),
                Filter = "*.py",
                IncludeSubdirectories = true,
                EnableRaisingEvents = true,
            };

            watcher.Changed += (sender, args) => {
                // Exclude version specific modules.
                Match match = LocaleVersionRegex.Match(args.Name);
                if (match.Success) {
                    byte locale = byte.Parse(match.Groups[1].Value);
                    uint version = uint.Parse(match.Groups[2].Value);
                    // Exclude opcode scripts in Inbound|Outbound.
                    if (Regex.IsMatch(args.Name, @$"^{locale}[\\/]{version}[\\/](Inbound|Outbound)[\\/].+$")) {
                        return;
                    }
                    
                    OnVersionedScriptChanged(locale, version);
                    return;
                }

                OnRootScriptChanged();
            };
        }

        /// <summary>
        /// Absorbs the process-wide one-time cost of the first IronPython engine (DLR init, assembly
        /// loads, compiler JIT — measured 0.7-1.3s) on a background thread at startup, so the first
        /// session's engine.create on the UI thread only pays the per-engine cost. The throwaway
        /// engine executes a trivial script to also warm the parse/compile path.
        /// </summary>
        public static void PrewarmEngine() {
            Task.Run(() => {
                using PerfLog.Scope perf = PerfLog.Time("engine.prewarm", always: true);
                try {
                    Python.CreateEngine().Execute("0");
                } catch (Exception ex) {
                    logger.Warn(ex, "Engine pre-warm failed");
                }
            });
        }

        /// <summary>
        /// A resolved decoder: the script to run and the build whose engine (and module surface) it runs
        /// under. Fallback decoders come from the compatibility manifest — measured, accepted edges only.
        /// </summary>
        public readonly struct Decoder {
            public byte Locale { get; init; }
            public uint Build { get; init; }
            public string Path { get; init; }
            public bool IsFallback { get; init; }
            public bool DistributionSuspect { get; init; }
        }

        // Resolution order: the packet's own build first; otherwise the best manifest-accepted,
        // hash-validated edge. Unknown/insufficient edges resolve to nothing — never a silent guess.
        public bool TryResolveDecoder(byte locale, uint version, bool outbound, ushort opcode, out Decoder decoder) {
            string scriptPath = Helpers.GetScriptPath(locale, version, outbound, opcode);
            if (File.Exists(scriptPath)) {
                decoder = new Decoder { Locale = locale, Build = version, Path = scriptPath, IsFallback = false };
                return true;
            }

            // Deliberately uncached hash validation: every fallback resolve re-reads and re-hashes the
            // source build's module surface on the caller's (UI) thread — a suspected per-click cost.
            using (PerfLog.Scope perf = PerfLog.Time("manifest.resolve")) {
                perf.SetDetail($"build={version} opcode=0x{opcode:X4}");
                if (manifest.TryResolve(locale, version, outbound, opcode, out ScriptManifest.Resolution res)) {
                    decoder = new Decoder {
                        Locale = locale, Build = res.SourceBuild,
                        Path = Helpers.GetScriptPath(locale, res.SourceBuild, outbound, opcode),
                        IsFallback = true,
                        DistributionSuspect = res.DistributionSuspect,
                    };
                    return true;
                }
            }

            decoder = default;
            return false;
        }

        public void ExecuteScript(Decoder decoder) {
            using PerfLog.Scope perf = PerfLog.Time("script.exec");
            perf.SetDetail(
                $"build={decoder.Build} script={Path.GetFileName(decoder.Path)}{(decoder.IsFallback ? " fallback" : "")}");

            // The engine is keyed by the decoder's own build so its imports resolve against the module
            // surface it was measured with, not the packet's build.
            ScriptEngine engine = GetEngine(decoder.Locale, decoder.Build);
            ScriptSource script = engine.CreateScriptSourceFromFile(decoder.Path);
            // TODO: Compile scripts for reuse? "script.Compile();"
            script.Execute();
        }

        // Returns the engine for the specified locale/version with caching.
        public ScriptEngine GetEngine(byte locale, uint version) {
            if (engines.TryGetValue((locale, version), out ScriptEngine engine)) {
                return engine;
            }

            // Cold engine creation runs on the caller's (UI) thread: DLR init plus first-touch assembly
            // loads make the first engine of the process a prime freeze suspect — always log it.
            using (PerfLog.Scope perf = PerfLog.Time("engine.create", always: true)) {
                perf.SetDetail($"locale={locale} build={version}");
                engine = CreateBaseEngine();
                ICollection<string> paths = engine.GetSearchPaths();
                // Version folder before the shared root: a version-specific module (common.py, item.py)
                // must shadow the shared one, not the other way around.
                paths.Add(Helpers.GetScriptFolder(locale, version));
                paths.Add(Helpers.GetScriptsRoot());
                engine.SetSearchPaths(paths);
            }
            new Task(() => {
                // Warm up these modules because they are commonly used. Missing modules are not fatal
                // here (a fresh Scripts folder may not have them yet) — the real import error surfaces
                // when a script actually runs.
                foreach (string module in new[] { "script_api", "common" }) {
                    try {
                        engine.Execute($"import {module}");
                    } catch (Exception ex) {
                        logger.Warn("Engine warm-up: could not import '{0}' for locale {1} build {2}: {3}",
                            module, locale, version, ex.Message);
                    }
                }
            }).Start();

            engines[(locale, version)] = engine;
            PerfLog.Gauge("engines", engines.Count);
            return engine;
        }

        // A fresh checkout/debug run has an empty Scripts folder next to the exe; scripts cannot run
        // without script_api.py, so seed the shipped copy. Never overwrite an existing file — the
        // compatibility manifest binds evidence to the deployed root's module contents (env hash).
        private static void SeedScriptApi() {
            string target = Path.Combine(Helpers.GetScriptsRoot(), "script_api.py");
            if (File.Exists(target)) return;

            string shipped = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "script_api.py");
            if (!File.Exists(shipped)) {
                logger.Warn("script_api.py missing from Scripts root and no shipped copy at {0}", shipped);
                return;
            }

            File.Copy(shipped, target);
            logger.Info("Seeded script_api.py into {0}", Helpers.GetScriptsRoot());
        }

        private ScriptEngine CreateBaseEngine() {
            ScriptEngine engine = Python.CreateEngine();
            engine.Runtime.Globals.SetVariable("structure_form", form);

            return engine;
        }

        private void OnRootScriptChanged() {
            // Clear all engines so they can be reloaded with updated modules.
            engines.Clear();
        }

        private void OnVersionedScriptChanged(byte locale, uint version) {
            // Remove affected engine so it can be reloaded with updated modules.
            engines.Remove((locale, version));
        }
    }
}

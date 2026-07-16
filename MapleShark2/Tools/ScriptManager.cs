using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using IronPython.Hosting;
using MapleShark2.UI;
using Microsoft.Scripting.Hosting;

namespace MapleShark2.Tools {
    public class ScriptManager {
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
        /// A resolved decoder: the script to run and the build whose engine (and module surface) it runs
        /// under. Fallback decoders come from the compatibility manifest — measured, accepted edges only.
        /// </summary>
        public readonly struct Decoder {
            public byte Locale { get; init; }
            public uint Build { get; init; }
            public string Path { get; init; }
            public bool IsFallback { get; init; }
        }

        // Resolution order: the packet's own build first; otherwise the best manifest-accepted,
        // hash-validated edge. Unknown/insufficient edges resolve to nothing — never a silent guess.
        public bool TryResolveDecoder(byte locale, uint version, bool outbound, ushort opcode, out Decoder decoder) {
            string scriptPath = Helpers.GetScriptPath(locale, version, outbound, opcode);
            if (File.Exists(scriptPath)) {
                decoder = new Decoder { Locale = locale, Build = version, Path = scriptPath, IsFallback = false };
                return true;
            }

            if (manifest.TryResolve(locale, version, outbound, opcode, out uint sourceBuild)) {
                decoder = new Decoder {
                    Locale = locale, Build = sourceBuild,
                    Path = Helpers.GetScriptPath(locale, sourceBuild, outbound, opcode),
                    IsFallback = true,
                };
                return true;
            }

            decoder = default;
            return false;
        }

        public void ExecuteScript(Decoder decoder) {
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

            engine = CreateBaseEngine();
            ICollection<string> paths = engine.GetSearchPaths();
            // Version folder before the shared root: a version-specific module (common.py, item.py)
            // must shadow the shared one, not the other way around.
            paths.Add(Helpers.GetScriptFolder(locale, version));
            paths.Add(Helpers.GetScriptsRoot());
            engine.SetSearchPaths(paths);
            new Task(() => {
                // Warm up these modules because they are commonly used
                engine.Execute("import script_api");
                engine.Execute("import common");
            }).Start();

            engines[(locale, version)] = engine;
            return engine;
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

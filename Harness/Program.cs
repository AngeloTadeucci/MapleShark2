using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace MapleShark2.Harness {
    /// <summary>
    /// Phase 0/1 verification harness.
    ///
    /// Answers one question the length-distribution analysis cannot: does a decoder script actually parse a
    /// given packet? Everything upstream of this — "97.7% stable", "78.8% coverage" — is inferred from packet
    /// *lengths*, having never run a script. This runs them, and reports what happened.
    ///
    /// Modes:
    ///   home     source build == target build. The baseline. Also the harness's own self-test: if V12 scripts
    ///            don't parse V12 packets, the harness is wrong, not the scripts.
    ///   edge     source build != target build. Measures one compatibility edge.
    ///   chain    --chain. Evaluates ONE resolver policy (nearest-in-lineage script wins). Policy evaluation
    ///            only: if the nearest script fails where an older one would work, chain never measures the
    ///            older edge. Do not use its output as compatibility evidence.
    ///   matrix   --matrix. Phase 1 evidence generation: every build holding a script for an observed
    ///            (opcode, direction) runs against a seeded reservoir sample of the target's packets.
    ///            Cross-lineage sources (V12 vs KMS2 targets) are included; targets with no script dir of
    ///            their own work (2489/2491/2493/2538 have sniffs but no scripts).
    /// </summary>
    public static class Program {
        private const string DefaultScripts = @"D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts";
        private const string DefaultSniffs = @"D:\Projetos\MapleStory2\MapleShark2-Sniffs";

        private sealed class Options {
            public string Scripts = DefaultScripts;
            public string Sniffs = DefaultSniffs;
            public uint? TargetBuild;
            public uint? SourceBuild;   // null => home build (source == target)
            public HashSet<ushort> Opcodes = new HashSet<ushort>();
            public string Direction;    // "in" | "out" | null
            public int Sample = int.MaxValue;
            public int SampleErrors = 3;
            public int Seed = 1;
            public string Out;
            public string Csv;
            public bool VersionPathFirst;
            public bool Chain;
            public bool Matrix;
            public List<uint> Lineage;
            public List<uint> Sources;  // --matrix only: restrict candidate source builds

            public string Sampling => Sample == int.MaxValue ? "all" : $"reservoir;n={Sample};seed={Seed}";
        }

        private sealed class Run {
            public readonly Dictionary<(ushort Opcode, bool Outbound, uint Source), Bucket> Buckets =
                new Dictionary<(ushort, bool, uint), Bucket>();
            public long Considered;
            public long Executed;
        }

        public static int Main(string[] args) {
            Options options;
            try {
                options = Parse(args);
            } catch (Exception ex) {
                Console.Error.WriteLine("error: " + ex.Message);
                Usage();
                return 2;
            }

            if (options.TargetBuild == null) {
                Console.Error.WriteLine("error: --build is required");
                Usage();
                return 2;
            }

            if (options.Matrix && options.Chain) {
                Console.Error.WriteLine("error: --matrix and --chain are different experiments; pick one");
                return 2;
            }

            if (options.Matrix && options.SourceBuild != null) {
                Console.Error.WriteLine("error: --matrix enumerates every source; use --sources a,b,c to restrict");
                return 2;
            }

            if (options.Matrix && options.Sample == int.MaxValue) {
                Console.Error.WriteLine("error: --matrix multiplies every packet by every candidate source; " +
                                        "an explicit --sample is required (evidence floor is ~300 per edge)");
                return 2;
            }

            uint target = options.TargetBuild.Value;
            uint source = options.SourceBuild ?? target;
            bool home = source == target && !options.Chain && !options.Matrix;

            Console.Error.WriteLine($"scripts   : {options.Scripts}");
            Console.Error.WriteLine($"sniffs    : {options.Sniffs}");
            Console.Error.WriteLine($"mode      : {Mode(options, source, target)}");
            Console.Error.WriteLine($"target    : build {target}");
            Console.Error.WriteLine($"sampling  : {options.Sampling}");
            if (options.Opcodes.Count > 0) {
                Console.Error.WriteLine("opcodes   : " + string.Join(", ", options.Opcodes.OrderBy(o => o).Select(o => $"0x{o:X4}")));
            }

            // Home/edge address one specific source build, which must exist. Chain and matrix resolve sources
            // per opcode and must NOT require the target to have its own script dir — four archived builds
            // have sniffs but no scripts, and they are exactly the targets fallback exists for.
            if (!options.Chain && !options.Matrix &&
                !Directory.Exists(ScriptHost.ScriptFolder(options.Scripts, source))) {
                Console.Error.WriteLine($"error: no script folder for build {source} at {ScriptHost.ScriptFolder(options.Scripts, source)}");
                return 2;
            }

            var sw = Stopwatch.StartNew();

            Console.Error.Write("scanning headers... ");
            List<string> files = FindFiles(options.Sniffs, target);
            Console.Error.WriteLine($"{files.Count} file(s) at build {target}");
            if (files.Count == 0) return 1;

            Run run;
            using (var host = new ScriptHost(options.Scripts, options.VersionPathFirst)) {
                if (options.Matrix) {
                    run = RunMatrix(host, files, options);
                } else if (options.Sample != int.MaxValue) {
                    run = RunSampled(host, files, options, source, target);
                } else {
                    run = RunStreaming(host, files, options, source, target);
                }
            }

            Console.Error.WriteLine();
            Console.Error.WriteLine($"considered {run.Considered:N0}, executed {run.Executed:N0} in {sw.Elapsed.TotalSeconds:F1}s");

            string report = Report(run, source, target, options);
            if (options.Out != null) {
                File.WriteAllText(options.Out, report);
                Console.Error.WriteLine("report -> " + options.Out);
            }

            Console.Out.Write(report);

            if (options.Csv != null) {
                File.WriteAllText(options.Csv, Csv(run, target, options));
                Console.Error.WriteLine("csv    -> " + options.Csv);
            }

            return 0;
        }

        private static string Mode(Options options, uint source, uint target) {
            if (options.Matrix) return $"MATRIX (every candidate source) -> {target}";
            if (options.Chain) return $"CHAIN (resolver policy, not evidence) -> {target}";
            return source == target ? "HOME (baseline / self-test)" : $"EDGE {source} -> {target}";
        }

        private static bool Wanted(Options options, RawPacket packet) {
            if (options.Opcodes.Count > 0 && !options.Opcodes.Contains(packet.Opcode)) return false;
            if (options.Direction == "in" && packet.Outbound) return false;
            if (options.Direction == "out" && !packet.Outbound) return false;
            return true;
        }

        /// <summary>
        /// Original streaming pass: execute every considered packet as it is read. Only used without
        /// --sample; with a cap this would degenerate to first-N, which demonstrably misses variants
        /// (chained 0x003D: 0 over-reads in the first 1,500 vs 6 in a 2,000-packet dedicated run).
        /// </summary>
        private static Run RunStreaming(ScriptHost host, List<string> files, Options options, uint source, uint target) {
            var run = new Run();
            List<uint> lineage = Lineage(host, options, target);
            if (!options.Chain) host.Warm(source);

            var resolved = new Dictionary<(ushort, bool), uint?>();
            int done = 0;

            foreach (string file in files) {
                List<RawPacket> packets;
                try {
                    packets = MsbReader.Read(file).Item2;
                } catch (Exception ex) {
                    Console.Error.WriteLine($"  skip {Path.GetFileName(file)}: {ex.Message}");
                    continue;
                }

                foreach (RawPacket packet in packets) {
                    if (!Wanted(options, packet)) continue;
                    run.Considered++;

                    uint? from = source;
                    if (options.Chain) {
                        var key = (packet.Opcode, packet.Outbound);
                        if (!resolved.TryGetValue(key, out from)) {
                            resolved[key] = from = host.Resolve(target, lineage, packet.Outbound, packet.Opcode);
                        }
                    }

                    Bucket bucket = BucketFor(run, packet, from);
                    bucket.Seen++;
                    Execute(host, run, bucket, packet, from, options);
                }

                if (++done % 50 == 0) {
                    Console.Error.WriteLine($"  {done}/{files.Count} files, {run.Executed:N0} packets parsed");
                }
            }

            return run;
        }

        /// <summary>Two-pass: seeded reservoir sample per (opcode, direction), then execute the samples.</summary>
        private static Run RunSampled(ScriptHost host, List<string> files, Options options, uint source, uint target) {
            var run = new Run();
            List<uint> lineage = Lineage(host, options, target);
            if (!options.Chain) host.Warm(source);

            (Dictionary<(ushort, bool), long> seen, Dictionary<(ushort, bool), List<RawPacket>> samples) =
                Collect(files, options, run);

            foreach (((ushort opcode, bool outbound), List<RawPacket> packets) in samples.OrderBy(e => e.Key)) {
                uint? from = options.Chain
                    ? host.Resolve(target, lineage, outbound, opcode)
                    : source;

                Bucket bucket = BucketFor(run, opcode, outbound, from);
                bucket.Seen = seen[(opcode, outbound)];
                foreach (RawPacket packet in packets) {
                    Execute(host, run, bucket, packet, from, options);
                }
            }

            return run;
        }

        /// <summary>
        /// Phase 1 evidence generation: every candidate source build against the target's samples.
        /// Source-major so each IronPython engine lives exactly as long as its build is being measured.
        /// </summary>
        private static Run RunMatrix(ScriptHost host, List<string> files, Options options) {
            var run = new Run();
            (Dictionary<(ushort, bool), long> seen, Dictionary<(ushort, bool), List<RawPacket>> samples) =
                Collect(files, options, run);

            List<uint> sources = host.AvailableBuilds()
                .Where(b => options.Sources == null || options.Sources.Contains(b))
                .ToList();
            Console.Error.WriteLine($"sources   : {sources.Count} candidate builds x {samples.Count} opcode/direction buckets");

            foreach (uint src in sources) {
                var keys = samples.Keys
                    .Where(k => host.HasScript(src, k.Item2, k.Item1))
                    .OrderBy(k => k)
                    .ToList();
                if (keys.Count == 0) continue;

                long before = run.Executed;
                foreach ((ushort opcode, bool outbound) in keys) {
                    Bucket bucket = BucketFor(run, opcode, outbound, src);
                    bucket.Seen = seen[(opcode, outbound)];
                    foreach (RawPacket packet in samples[(opcode, outbound)]) {
                        Execute(host, run, bucket, packet, src, options);
                    }
                }

                host.Release(src);
                Console.Error.WriteLine($"  src {src}: {keys.Count} script(s), {run.Executed - before:N0} executions");
            }

            // An (opcode, direction) no build can decode still needs a row, or coverage math silently
            // forgets the traffic exists.
            foreach (((ushort opcode, bool outbound), List<RawPacket> packets) in samples) {
                if (sources.Any(s => run.Buckets.ContainsKey((opcode, outbound, s)))) continue;
                Bucket bucket = BucketFor(run, opcode, outbound, null);
                bucket.Seen = seen[(opcode, outbound)];
                foreach (RawPacket _ in packets) {
                    bucket.Add(new ParseResult { Outcome = Outcome.NoScript, Declared = 0 }, 0);
                    bucket.Executed++;
                    run.Executed++;
                }
            }

            return run;
        }

        /// <summary>
        /// Pass 1: count every considered packet per (opcode, direction) and keep a uniform reservoir
        /// sample of --sample per bucket (algorithm R, seeded — deterministic given the sorted file list).
        /// </summary>
        private static (Dictionary<(ushort, bool), long>, Dictionary<(ushort, bool), List<RawPacket>>)
            Collect(List<string> files, Options options, Run run) {
            var rng = new Random(options.Seed);
            var seen = new Dictionary<(ushort, bool), long>();
            var samples = new Dictionary<(ushort, bool), List<RawPacket>>();
            int done = 0;

            foreach (string file in files) {
                List<RawPacket> packets;
                try {
                    packets = MsbReader.Read(file).Item2;
                } catch (Exception ex) {
                    Console.Error.WriteLine($"  skip {Path.GetFileName(file)}: {ex.Message}");
                    continue;
                }

                foreach (RawPacket packet in packets) {
                    if (!Wanted(options, packet)) continue;
                    run.Considered++;

                    var key = (packet.Opcode, packet.Outbound);
                    seen.TryGetValue(key, out long n);
                    seen[key] = ++n;

                    if (!samples.TryGetValue(key, out List<RawPacket> list)) {
                        samples[key] = list = new List<RawPacket>();
                    }

                    if (list.Count < options.Sample) {
                        list.Add(packet);
                    } else {
                        int j = rng.Next((int) Math.Min(n, int.MaxValue));
                        if (j < options.Sample) list[j] = packet;
                    }
                }

                if (++done % 100 == 0) {
                    Console.Error.WriteLine($"  scan {done}/{files.Count} files, {run.Considered:N0} packets seen");
                }
            }

            Console.Error.WriteLine($"  sampled {samples.Values.Sum(l => (long) l.Count):N0} of {run.Considered:N0} packets " +
                                    $"across {samples.Count} opcode/direction buckets");
            return (seen, samples);
        }

        private static List<uint> Lineage(ScriptHost host, Options options, uint target) {
            if (!options.Chain) return null;
            // Lineage: explicit if given, else the KMS2 (>=2000) / GMS2 (12) split the archive shows.
            // Deriving it is fine for a measurement; the product resolver must take it as config.
            List<uint> lineage = options.Lineage ??
                host.AvailableBuilds().Where(b => target >= 2000 ? b >= 2000 : b < 2000).ToList();
            Console.Error.WriteLine("lineage   : " + string.Join(", ", lineage));
            return lineage;
        }

        private static Bucket BucketFor(Run run, RawPacket packet, uint? source) =>
            BucketFor(run, packet.Opcode, packet.Outbound, source);

        private static Bucket BucketFor(Run run, ushort opcode, bool outbound, uint? source) {
            var key = (opcode, outbound, source ?? 0);
            if (!run.Buckets.TryGetValue(key, out Bucket bucket)) {
                run.Buckets[key] = bucket = new Bucket();
            }

            return bucket;
        }

        private static void Execute(ScriptHost host, Run run, Bucket bucket, RawPacket packet, uint? from,
            Options options) {
            if (from == null) {
                bucket.Add(new ParseResult { Outcome = Outcome.NoScript, Declared = packet.Data.Length },
                    options.SampleErrors);
                bucket.Executed++;
                run.Executed++;
                return;
            }

            bool trace = bucket.SampleTraces.Count < options.SampleErrors;
            ParseResult result = host.Execute(from.Value, packet, trace);
            bucket.SourceBuild = from.Value;
            bucket.Executed++;
            run.Executed++;
            bucket.Add(result, options.SampleErrors);

            // Manifest identity: an edge is evidence about script content, not a build number.
            if (bucket.ScriptSha == null && result.ScriptPath != null) {
                bucket.ScriptSha = ScriptHost.FileSha(result.ScriptPath);
                bucket.EnvSha = host.EnvHash(from.Value);
            }
        }

        private static List<string> FindFiles(string root, uint build) {
            var found = new List<string>();
            foreach (string path in Directory.EnumerateFiles(root, "*.msb", SearchOption.AllDirectories)) {
                try {
                    if (MsbReader.ReadHeader(path).Build == build) found.Add(path);
                } catch {
                    // A header we cannot parse cannot be attributed to a build; excluding it is correct here,
                    // and the strict full-file pass already established all 1417 parse cleanly.
                }
            }

            // Deterministic order — the reservoir sample must reproduce given the same seed.
            found.Sort(StringComparer.OrdinalIgnoreCase);
            return found;
        }

        private sealed class Bucket {
            public long Seen;
            public long Executed;
            public readonly long[] Outcomes = new long[6];
            public long NegativeLength;
            public readonly long[] ConsumedHist = new long[101]; // percent buckets, 0..100
            public readonly List<string> SampleErrors = new List<string>();
            public readonly List<List<ReadEvent>> SampleTraces = new List<List<ReadEvent>>();
            public string ScriptPath;
            public uint SourceBuild;
            public string ScriptSha;
            public string EnvSha;

            public void Add(ParseResult result, int maxSamples) {
                Outcomes[(int) result.Outcome]++;
                if (result.ScriptPath != null) ScriptPath = result.ScriptPath;

                if (result.Outcome == Outcome.OverRead && result.Reason == OverReadReason.NegativeLength) {
                    NegativeLength++;
                }

                if (result.Outcome != Outcome.NoScript && result.Outcome != Outcome.CompileError) {
                    int pct = (int) Math.Round(Math.Min(1.0, Math.Max(0.0, result.ConsumedFraction)) * 100);
                    ConsumedHist[pct]++;
                }

                bool bad = result.Outcome == Outcome.OverRead || result.Outcome == Outcome.Threw
                                                             || result.Outcome == Outcome.CompileError;
                if (bad && result.Error != null && SampleErrors.Count < maxSamples) {
                    SampleErrors.Add(result.Error);
                    if (result.Trace != null) SampleTraces.Add(result.Trace);
                }
            }

            public long Parsed => Executed - Outcomes[(int) Outcome.NoScript] - Outcomes[(int) Outcome.CompileError];

            public double Percentile(int p) {
                long total = ConsumedHist.Sum();
                if (total == 0) return 0;
                long want = (long) Math.Ceiling(total * p / 100.0);
                long cum = 0;
                for (int i = 0; i <= 100; i++) {
                    cum += ConsumedHist[i];
                    if (cum >= want) return i;
                }

                return 100;
            }

            /// <summary>Sparse "pct:count|pct:count" encoding so the manifest stays reclassifiable
            /// without re-running millions of packets. p50/p90 alone cannot re-derive a decision.</summary>
            public string Hist() {
                var parts = new List<string>();
                for (int i = 0; i <= 100; i++) {
                    if (ConsumedHist[i] > 0) parts.Add(i + ":" + ConsumedHist[i]);
                }

                return parts.Count == 0 ? "-" : string.Join("|", parts);
            }
        }

        private static string Report(Run run, uint source, uint target, Options options) {
            var sb = new StringBuilder();
            bool home = source == target && !options.Chain && !options.Matrix;

            sb.AppendLine($"# Harness — {(options.Matrix ? $"MATRIX -> {target}" : options.Chain ? $"CHAINED -> {target}" : home ? "HOME baseline" : $"EDGE {source} -> {target}")}");
            sb.AppendLine();
            sb.AppendLine($"scripts from build : {(options.Matrix ? "(matrix, see src column)" : options.Chain ? "(chained, see src column)" : source.ToString())}");
            sb.AppendLine($"packets from build : {target}");
            sb.AppendLine($"packets considered : {run.Considered:N0}");
            sb.AppendLine($"packets executed   : {run.Executed:N0}" + (options.Sample != int.MaxValue ? $"  ({options.Sampling})" : ""));
            sb.AppendLine();

            long[] totals = new long[6];
            foreach (Bucket bucket in run.Buckets.Values) {
                for (int i = 0; i < 6; i++) totals[i] += bucket.Outcomes[i];
            }

            long ran = totals.Sum() - totals[(int) Outcome.NoScript] - totals[(int) Outcome.CompileError];
            sb.AppendLine("## Totals (weighted by executed packets)");
            if (options.Matrix) {
                sb.AppendLine();
                sb.AppendLine("NOTE: matrix totals aggregate every candidate source, including known-bad ones.");
                sb.AppendLine("They describe the evidence run, not achievable coverage. Use the CSV per edge.");
            }

            sb.AppendLine();
            sb.AppendLine($"{"outcome",-14} {"packets",12}   share");
            foreach (Outcome outcome in Enum.GetValues(typeof(Outcome))) {
                long n = totals[(int) outcome];
                if (n == 0) continue;
                sb.AppendLine($"{outcome,-14} {n,12:N0}   {Pct(n, run.Executed)}");
            }

            sb.AppendLine();
            if (ran > 0) {
                long ok = totals[(int) Outcome.OkExact];
                long over = totals[(int) Outcome.OverRead];
                sb.AppendLine($"of packets a script actually ran on ({ran:N0}):");
                sb.AppendLine($"  clean (consumed exactly) : {Pct(ok, ran)}");
                sb.AppendLine($"  over-read (WRONG)        : {Pct(over, ran)}");
                sb.AppendLine($"  under-read (ambiguous)   : {Pct(totals[(int) Outcome.UnderRead], ran)}");
            }

            sb.AppendLine();
            sb.AppendLine("## Per opcode" + (options.Matrix ? " x source" : ""));
            sb.AppendLine();
            sb.AppendLine($"{"opcode",-8}{"dir",-5}{"src",7}{"seen",12}{"ran",10}{"clean",9}{"under",9}{"over",9}{"threw",8}{"consumed p50/p90",20}");

            foreach (KeyValuePair<(ushort Opcode, bool Outbound, uint Source), Bucket> entry in run.Buckets
                         .OrderByDescending(e => e.Value.Seen)
                         .ThenBy(e => e.Key.Opcode)
                         .ThenBy(e => e.Key.Source)) {
                Bucket b = entry.Value;
                string dir = entry.Key.Outbound ? "OUT" : "IN";
                if (b.Parsed == 0) {
                    string why = b.Outcomes[(int) Outcome.CompileError] > 0 ? "COMPILE-ERR" : "no script";
                    string src = b.SourceBuild != 0 ? b.SourceBuild.ToString() : "-";
                    sb.AppendLine($"0x{entry.Key.Opcode:X4}  {dir,-5}{src,7}{b.Seen,12:N0}{"-",10}{"",9}{"",9}{"",9}{"",8}  {why}");
                    continue;
                }

                sb.AppendLine(
                    $"0x{entry.Key.Opcode:X4}  {dir,-5}{b.SourceBuild,7}{b.Seen,12:N0}{b.Parsed,10:N0}" +
                    $"{Pct(b.Outcomes[(int) Outcome.OkExact], b.Parsed),9}" +
                    $"{Pct(b.Outcomes[(int) Outcome.UnderRead], b.Parsed),9}" +
                    $"{Pct(b.Outcomes[(int) Outcome.OverRead], b.Parsed),9}" +
                    $"{Pct(b.Outcomes[(int) Outcome.Threw], b.Parsed),8}" +
                    $"{b.Percentile(50) + "% / " + b.Percentile(90) + "%",20}");
            }

            var failing = run.Buckets.Where(e => e.Value.SampleErrors.Count > 0)
                .OrderByDescending(e => e.Value.Outcomes[(int) Outcome.OverRead] + e.Value.Outcomes[(int) Outcome.Threw])
                .ToList();

            if (failing.Count > 0) {
                sb.AppendLine();
                sb.AppendLine("## Sample failures");
                foreach (KeyValuePair<(ushort Opcode, bool Outbound, uint Source), Bucket> entry in failing.Take(12)) {
                    Bucket b = entry.Value;
                    sb.AppendLine();
                    sb.AppendLine($"### 0x{entry.Key.Opcode:X4} {(entry.Key.Outbound ? "OUT" : "IN")}" +
                                  (entry.Key.Source != 0 ? $" src {entry.Key.Source}" : "") +
                                  $"  over={b.Outcomes[(int) Outcome.OverRead]:N0} threw={b.Outcomes[(int) Outcome.Threw]:N0}" +
                                  (b.NegativeLength > 0 ? $" negative-length={b.NegativeLength:N0}" : ""));
                    if (b.ScriptPath != null) sb.AppendLine($"script: {b.ScriptPath}");
                    foreach (string error in b.SampleErrors) sb.AppendLine("  ! " + error);

                    if (b.SampleTraces.Count > 0) {
                        List<ReadEvent> trace = b.SampleTraces[0];
                        sb.AppendLine($"  last reads before failure (of {trace.Count}):");
                        foreach (ReadEvent read in trace.Skip(Math.Max(0, trace.Count - 8))) {
                            sb.AppendLine("    " + read);
                        }
                    }
                }
            }

            return sb.ToString();
        }

        private static string Csv(Run run, uint target, Options options) {
            var sb = new StringBuilder();
            sb.AppendLine("source_build,target_build,opcode,direction,seen,executed,ran,no_script,ok_exact," +
                          "under_read,over_read,threw,compile_error,negative_length,consumed_p50,consumed_p90," +
                          "script_sha,env_sha,consumed_hist,sampling");
            foreach (KeyValuePair<(ushort Opcode, bool Outbound, uint Source), Bucket> e in run.Buckets
                         .OrderBy(e => e.Key.Opcode)
                         .ThenBy(e => e.Key.Outbound)
                         .ThenBy(e => e.Key.Source)) {
                Bucket b = e.Value;
                string src = b.SourceBuild != 0 ? b.SourceBuild.ToString() : "-";
                sb.AppendLine(string.Join(",", new[] {
                    src, target.ToString(), $"0x{e.Key.Opcode:X4}", e.Key.Outbound ? "OUT" : "IN",
                    b.Seen.ToString(), b.Executed.ToString(), b.Parsed.ToString(),
                    b.Outcomes[(int) Outcome.NoScript].ToString(), b.Outcomes[(int) Outcome.OkExact].ToString(),
                    b.Outcomes[(int) Outcome.UnderRead].ToString(), b.Outcomes[(int) Outcome.OverRead].ToString(),
                    b.Outcomes[(int) Outcome.Threw].ToString(), b.Outcomes[(int) Outcome.CompileError].ToString(),
                    b.NegativeLength.ToString(),
                    b.Percentile(50).ToString(CultureInfo.InvariantCulture),
                    b.Percentile(90).ToString(CultureInfo.InvariantCulture),
                    b.ScriptSha ?? "-", b.EnvSha ?? "-", b.Hist(), options.Sampling,
                }));
            }

            return sb.ToString();
        }

        private static string Pct(long n, long total) =>
            total == 0 ? "-" : (100.0 * n / total).ToString("F1", CultureInfo.InvariantCulture) + "%";

        private static Options Parse(string[] args) {
            var options = new Options();
            for (int i = 0; i < args.Length; i++) {
                string arg = args[i];
                string Next(string name) {
                    if (i + 1 >= args.Length) throw new ArgumentException($"{name} needs a value");
                    return args[++i];
                }

                switch (arg) {
                    case "--scripts": options.Scripts = Next(arg); break;
                    case "--sniffs": options.Sniffs = Next(arg); break;
                    case "--build": options.TargetBuild = uint.Parse(Next(arg)); break;
                    case "--source": options.SourceBuild = uint.Parse(Next(arg)); break;
                    case "--dir": options.Direction = Next(arg).ToLowerInvariant(); break;
                    case "--sample": options.Sample = int.Parse(Next(arg)); break;
                    case "--sample-errors": options.SampleErrors = int.Parse(Next(arg)); break;
                    case "--seed": options.Seed = int.Parse(Next(arg)); break;
                    case "--out": options.Out = Next(arg); break;
                    case "--csv": options.Csv = Next(arg); break;
                    case "--version-path-first": options.VersionPathFirst = true; break;
                    case "--chain": options.Chain = true; break;
                    case "--matrix": options.Matrix = true; break;
                    case "--lineage": options.Lineage = Next(arg).Split(',').Select(uint.Parse).ToList(); break;
                    case "--sources": options.Sources = Next(arg).Split(',').Select(uint.Parse).ToList(); break;
                    case "--opcode": {
                        string value = Next(arg);
                        options.Opcodes.Add(value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                            ? Convert.ToUInt16(value.Substring(2), 16)
                            : ushort.Parse(value));
                        break;
                    }
                    case "-h":
                    case "--help": Usage(); Environment.Exit(0); break;
                    default: throw new ArgumentException("unknown argument: " + arg);
                }
            }

            return options;
        }

        private static void Usage() {
            Console.Error.WriteLine(@"
Harness — run decoder scripts against captured packets and report what happened.

  --build <N>          REQUIRED. Target build: which packets to run against.
  --source <N>         Script source build. Default = --build (home baseline).
                       Set differently to measure one compatibility edge.
  --chain              Nearest-in-lineage resolver policy. Policy evaluation only —
                       NOT edge evidence; a failing nearest script hides working older ones.
  --matrix             Phase 1 evidence: run EVERY build holding a script for each observed
                       (opcode, direction) against the target's samples. Requires --sample.
  --sources <a,b,c>    Matrix only: restrict candidate source builds.
  --lineage <a,b,c>    Chain only: explicit lineage (default: KMS2/GMS2 split from script dirs).
  --opcode <0xNNNN>    Restrict to opcode (repeatable).
  --dir <in|out>       Restrict to direction.
  --sample <N>         Packets per (opcode, direction), seeded uniform reservoir sample.
                       Default: all (streaming, no sampling).
  --seed <N>           Reservoir RNG seed. Default: 1. Recorded in the CSV.
  --sample-errors <N>  Failure samples kept per bucket. Default: 3.
  --scripts <dir>      Scripts root. Default: Ochi tree.
  --sniffs <dir>       Sniff archive root.
  --out <file>         Write the text report.
  --csv <file>         Write the aggregate as CSV (includes script/env hashes + consumed histogram).
  --version-path-first Put the version dir ahead of the shared root on sys.path
                       (tests the ScriptManager.cs:88 shadowing bug; default reproduces it).

Examples:
  Harness --build 12 --sample 2000                    # baseline / self-test
  Harness --build 2546 --source 2527 --opcode 0x0058  # one compatibility edge
  Harness --build 2546 --matrix --sample 1500 --csv matrix-2546.csv   # Phase 1 evidence
");
        }
    }
}

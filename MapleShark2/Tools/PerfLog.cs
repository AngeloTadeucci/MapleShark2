using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using NLog;

namespace MapleShark2.Tools {
    /// <summary>
    /// Lightweight perf instrumentation (Phase 3 evidence gathering). Everything writes to the
    /// dedicated "perf" logger, routed to perf.log by nlog.config. Three mechanisms:
    ///  - Time(): stopwatch scopes around suspected choke points, silent unless the scope exceeds
    ///    ThresholdMs (or always=true), so hours of healthy capture produce no noise.
    ///  - StartWatchdog(): a background heartbeat through the UI message pump; any hang beyond the
    ///    threshold is logged together with the scope active when the hang was detected, which
    ///    attributes freezes even in code that has no scope of its own.
    ///  - Gauge() + StartCounters(): a periodic one-line snapshot of process memory, GC activity and
    ///    app-level gauges (queue depth, tab/packet/row counts) so "the machine chugs when tabs stack
    ///    up" can be correlated against retention instead of guessed at.
    /// </summary>
    public static class PerfLog {
        private static readonly Logger logger = LogManager.GetLogger("perf");

        /// <summary>Scopes faster than this are not logged. Watchdog attribution still sees them.</summary>
        public static int ThresholdMs { get; set; } = 20;

        private static readonly ConcurrentDictionary<string, long> gauges =
            new ConcurrentDictionary<string, long>();

        private static Scope currentScope;
        private static System.Threading.Timer counterTimer;

        public static Scope Time(string name, bool always = false) => new Scope(name, always);

        public static void Gauge(string name, long value) => gauges[name] = value;

        public sealed class Scope : IDisposable {
            private readonly string name;
            private readonly bool always;
            private readonly long start;
            private readonly Scope parent;
            private volatile string detail;
            private volatile bool completed;

            internal Scope(string name, bool always) {
                this.name = name;
                this.always = always;
                start = Stopwatch.GetTimestamp();
                parent = Volatile.Read(ref currentScope);
                Volatile.Write(ref currentScope, this);
            }

            public void SetDetail(string value) => detail = value;

            private double ElapsedMs => (Stopwatch.GetTimestamp() - start) * 1000.0 / Stopwatch.Frequency;

            public void Dispose() {
                completed = true;
                Volatile.Write(ref currentScope, parent);
                double ms = ElapsedMs;
                if (always || ms >= ThresholdMs) {
                    logger.Info("{0} {1:F1} ms{2}", name, ms, detail == null ? "" : " " + detail);
                }
            }

            internal string Describe() {
                string state = completed ? "completed" : $"open {ElapsedMs:F0} ms";
                return $"{name} ({state}){(detail == null ? "" : " " + detail)}";
            }
        }

        /// <summary>
        /// Starts the UI-hang watchdog. Call once from the main form after its handle exists.
        /// A heartbeat is posted through the message pump every second; if it is not serviced within
        /// hangThresholdMs the hang is logged with its total duration and the perf scope that was
        /// active at detection time (snapshotted while still hung — by the time the pump resumes,
        /// the culprit frame is gone).
        /// </summary>
        public static void StartWatchdog(Control ui, int hangThresholdMs = 500) {
            var thread = new Thread(() => {
                while (!ui.IsDisposed) {
                    // Never disposed: the pump may Set() it long after a timed-out wait, and Set on a
                    // disposed event would throw on the UI thread. It holds no kernel handle here.
                    var pumped = new ManualResetEventSlim();
                    long start = Stopwatch.GetTimestamp();
                    try {
                        ui.BeginInvoke(new Action(pumped.Set));
                    } catch (Exception) {
                        return; // Handle destroyed; app is shutting down.
                    }

                    if (!pumped.Wait(hangThresholdMs)) {
                        Scope at = Volatile.Read(ref currentScope);
                        string during = at?.Describe() ?? "no perf scope";
                        bool resumed = pumped.Wait(TimeSpan.FromMinutes(5));
                        double ms = (Stopwatch.GetTimestamp() - start) * 1000.0 / Stopwatch.Frequency;
                        logger.Warn("UI hang {0:F0} ms{1} (at +{2} ms: {3})",
                            ms, resumed ? "" : " (STILL HUNG)", hangThresholdMs, during);
                    }

                    Thread.Sleep(1000);
                }
            }) { IsBackground = true, Name = "perf-watchdog" };
            thread.Start();
        }

        /// <summary>Logs one "counters" line every periodSeconds: memory, GC and app gauges.</summary>
        public static void StartCounters(int periodSeconds = 5) {
            if (counterTimer != null) return;

            int period = periodSeconds * 1000;
            counterTimer = new System.Threading.Timer(_ => {
                try {
                    using var proc = Process.GetCurrentProcess();
                    string extra = gauges.IsEmpty
                        ? ""
                        : " " + string.Join(" ", gauges.OrderBy(kv => kv.Key, StringComparer.Ordinal)
                            .Select(kv => $"{kv.Key}={kv.Value}"));
                    logger.Info("counters managed_mb={0} ws_mb={1} private_mb={2} gc0={3} gc1={4} gc2={5}{6}",
                        GC.GetTotalMemory(false) / (1024 * 1024),
                        proc.WorkingSet64 / (1024 * 1024),
                        proc.PrivateMemorySize64 / (1024 * 1024),
                        GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2),
                        extra);
                } catch (Exception) {
                    // Instrumentation must never take the app down.
                }
            }, null, period, period);
        }
    }
}

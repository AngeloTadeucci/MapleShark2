using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using MapleShark2.Tools;
using NLog;
using NLog.Config;
using NLog.Targets;

internal static class Program {
    private static int passed;
    private static int failed;

    private static void Check(string name, bool cond, string extra = null) {
        if (cond) { passed++; Console.WriteLine($"PASS: {name}"); }
        else { failed++; Console.WriteLine($"FAIL: {name}{(extra == null ? "" : $" ({extra})")}"); }
    }

    [STAThread]
    private static int Main() {
        // Capture the "perf" logger into memory for behavioral assertions.
        var mem = new MemoryTarget("mem") { Layout = "${level}|${message}" };
        var config = new LoggingConfiguration();
        config.AddRule(LogLevel.Trace, LogLevel.Fatal, mem, "perf");
        LogManager.Configuration = config;

        string[] Logs() => mem.Logs.ToArray();

        // --- Threshold gating ---
        using (PerfLog.Time("scope.fast")) { }
        Check("fast scope below threshold is silent", !Logs().Any(l => l.Contains("scope.fast")));

        using (PerfLog.Scope slow = PerfLog.Time("scope.slow")) {
            slow.SetDetail("d=1");
            Thread.Sleep(60);
        }

        string slowLine = Logs().FirstOrDefault(l => l.Contains("scope.slow"));
        Check("slow scope above threshold is logged", slowLine != null);
        Check("slow scope carries detail", slowLine != null && slowLine.Contains("d=1"));

        using (PerfLog.Scope always = PerfLog.Time("scope.always", always: true)) {
            always.SetDetail("d=2");
        }

        Check("always-scope logged even when fast", Logs().Any(l => l.Contains("scope.always") && l.Contains("d=2")));

        // --- Stage accumulators ---
        Check("accums start empty", PerfLog.FlushAccums() == "");
        long t1 = PerfLog.Begin();
        Thread.Sleep(30);
        PerfLog.Accum("stage.b", t1);
        long t2 = PerfLog.Begin();
        PerfLog.Accum("stage.a", t2);
        long t3 = PerfLog.Begin();
        PerfLog.Accum("stage.a", t3);
        string accums = PerfLog.FlushAccums();
        Check("accums aggregate count per stage", accums.Contains("stage.a=") && accums.Contains("ms/2"), accums);
        Check("accums record elapsed time", accums.Contains("stage.b=3") || accums.Contains("stage.b=4"), accums);
        Check("accums sorted by name", accums.IndexOf("stage.a") < accums.IndexOf("stage.b"), accums);
        Check("flush clears accums", PerfLog.FlushAccums() == "");

        // --- Gauges + counters ---
        PerfLog.Gauge("test.gauge", 42);
        PerfLog.StartCounters(periodSeconds: 1);
        Thread.Sleep(2500);
        string counters = Logs().FirstOrDefault(l => l.Contains("counters "));
        Check("counters line emitted", counters != null);
        Check("counters include process stats", counters != null && counters.Contains("managed_mb="));
        Check("counters include app gauges", counters != null && counters.Contains("test.gauge=42"));

        // --- Watchdog: real message pump, real hang ---
        Form form = null;
        var ready = new ManualResetEventSlim();
        var uiThread = new Thread(() => {
            form = new Form { ShowInTaskbar = false, WindowState = FormWindowState.Minimized, Opacity = 0 };
            form.Shown += (s, e) => ready.Set();
            Application.Run(form);
        });
        uiThread.SetApartmentState(ApartmentState.STA);
        uiThread.Start();
        Check("test form pumps messages", ready.Wait(10000));

        PerfLog.StartWatchdog(form, hangThresholdMs: 200);
        Thread.Sleep(400); // Let at least one healthy heartbeat through first.

        form.Invoke(() => {
            // An open scope during the hang: the watchdog must attribute the hang to it.
            using (PerfLog.Time("blocking.op", always: true)) {
                Thread.Sleep(2500);
            }
        });

        string hangLine = null;
        for (int i = 0; i < 100 && hangLine == null; i++) {
            Thread.Sleep(100);
            hangLine = Logs().FirstOrDefault(l => l.Contains("UI hang"));
        }

        Check("watchdog detects UI hang", hangLine != null);
        Check("hang is Warn level", hangLine != null && hangLine.StartsWith("Warn|"));
        Check("hang attributed to the open scope", hangLine != null && hangLine.Contains("blocking.op"),
            hangLine);

        form.Invoke(() => form.Close());
        uiThread.Join(5000);

        // --- Routing through the app's real nlog.config: perf -> perf.log only ---
        string nlogConfig = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "MapleShark2", "nlog.config"));
        if (!File.Exists(nlogConfig)) {
            Console.WriteLine($"SKIP: routing test (nlog.config not found at {nlogConfig})");
        } else {
            // NLog resolves relative file targets against the app base directory, same as the GUI.
            string perfLog = Path.Combine(AppContext.BaseDirectory, "perf.log");
            string appLog = Path.Combine(AppContext.BaseDirectory, "mapleshark2.log");
            try {
                if (File.Exists(perfLog)) File.Delete(perfLog);
                if (File.Exists(appLog)) File.Delete(appLog);

                LogManager.Setup().SetupExtensions(ext =>
                    ext.RegisterAssembly(typeof(NLog.Windows.Forms.RichTextBoxTarget).Assembly));
                LogManager.Configuration = new XmlLoggingConfiguration(nlogConfig);

                LogManager.GetLogger("perf").Info("perf-routing-marker 1.0 ms");
                LogManager.GetLogger("SomeClass").Warn("app-routing-marker");
                LogManager.Flush();
                LogManager.Configuration = null; // Close file targets so the files can be read.

                string perfText = File.Exists(perfLog) ? File.ReadAllText(perfLog) : "";
                string appText = File.Exists(appLog) ? File.ReadAllText(appLog) : "";

                Check("perf entry lands in perf.log", perfText.Contains("perf-routing-marker"));
                Check("perf entry does NOT land in mapleshark2.log", !appText.Contains("perf-routing-marker"));
                Check("app Warn still lands in mapleshark2.log", appText.Contains("app-routing-marker"));
                Check("app Warn does NOT land in perf.log", !perfText.Contains("app-routing-marker"));
            } finally {
                LogManager.Configuration = null; // Release file handles before cleanup.
                try { File.Delete(perfLog); } catch { /* best effort */ }
                try { File.Delete(appLog); } catch { /* best effort */ }
            }
        }

        Console.WriteLine($"\n{passed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
    }
}

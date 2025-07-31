using System.Text.Json;
using Serilog;
using PacketDotNet;
using Serilog.Events;
using SharpPcap;
using SharpPcap.LibPcap;
using Sniffer.Tools;

namespace Sniffer;

public class Program {
    private static readonly ILogger Logger = Log.ForContext<Program>();
    private static PcapDevice? _device;
    private static readonly List<RawCapture> PacketQueue = [];
    private static readonly HashSet<PacketSession> Sessions = [];
    private static readonly Timer ProcessTimer = new(ProcessPacketQueue, null, TimeSpan.Zero, TimeSpan.FromMilliseconds(100));
    private static SnifferConfig _config = new();

    public static async Task Main(string[] args) {
        // Initialize Serilog
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.Console(outputTemplate: "{Timestamp:HH:mm:ss.fff} [{Level:u3}] {Message:lj} {Exception}{NewLine}", restrictedToMinimumLevel: LogEventLevel.Information)
            .WriteTo.File("sniffer.log",
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {SourceContext}: {Message:lj} {Exception}{NewLine}")
            .CreateLogger();

        Console.WriteLine("MapleStory2 Packet Sniffer");
        Console.WriteLine("==========================");

        // Load configuration
        LoadConfiguration(args);

        // Setup network adapter
        if (!SetupAdapter()) {
            Console.WriteLine("Failed to setup network adapter. Exiting...");
            return;
        }

        Console.WriteLine($"Listening on {_config.Interface} for ports {_config.LowPort}-{_config.HighPort}");
        Console.WriteLine("Press Ctrl+C to stop...");

        // Handle graceful shutdown
        Console.CancelKeyPress += (_, e) => {
            e.Cancel = true;
            Shutdown();
            Environment.Exit(0);
        };

        // Keep the application running
        await Task.Delay(Timeout.Infinite);
    }

    private static void LoadConfiguration(string[] args) {
        // Load from config file if it exists
        string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "sniffer-config.json");
        if (File.Exists(configPath)) {
            try {
                string json = File.ReadAllText(configPath);
                var fileConfig = JsonSerializer.Deserialize<SnifferConfig>(json);
                if (fileConfig != null) {
                    _config = fileConfig;
                }
            } catch (Exception ex) {
                Console.WriteLine($"Warning: Failed to load config file: {ex.Message}");
            }
        }

        // Override with command line arguments
        for (int i = 0; i < args.Length; i++) {
            switch (args[i]) {
                case "--interface" when i + 1 < args.Length:
                    _config.Interface = args[++i];
                    break;
                case "--low-port" when i + 1 < args.Length:
                    if (ushort.TryParse(args[++i], out ushort lowPort))
                        _config.LowPort = lowPort;
                    break;
                case "--high-port" when i + 1 < args.Length:
                    if (ushort.TryParse(args[++i], out ushort highPort))
                        _config.HighPort = highPort;
                    break;
                case "--list-interfaces":
                    ListInterfaces();
                    Environment.Exit(0);
                    break;
                case "--help":
                    ShowHelp();
                    Environment.Exit(0);
                    break;
            }
        }
    }

    private static void ListInterfaces() {
        Console.WriteLine("Available network interfaces:");
        Console.WriteLine("============================");

        foreach (LibPcapLiveDevice device in LibPcapLiveDeviceList.Instance) {
            string status = device.IsActive() ? "Active" : "Inactive";
            string name = device.Interface.FriendlyName ?? device.Interface.Description ?? device.Interface.Name;
            Console.WriteLine($"  {device.Interface.Name} - {name} ({status})");
        }
    }

    private static void ShowHelp() {
        Console.WriteLine("MapleStory2 Packet Sniffer");
        Console.WriteLine("Usage: dotnet run [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --interface <name>    Network interface to capture on");
        Console.WriteLine("  --low-port <port>     Lower bound of port range (default: 20000)");
        Console.WriteLine("  --high-port <port>    Upper bound of port range (default: 33001)");
        Console.WriteLine("  --list-interfaces     List available network interfaces");
        Console.WriteLine("  --help               Show this help message");
        Console.WriteLine();
        Console.WriteLine("Configuration file: sniffer-config.json");
    }

    private static bool SetupAdapter() {
        if (_device != null) {
            _device.StopCapture();
            _device.Close();
        }

        // If no interface specified, try to find the first active physical adapter
        if (string.IsNullOrEmpty(_config.Interface)) {
            foreach (LibPcapLiveDevice pcapDevice in LibPcapLiveDeviceList.Instance) {
                if (pcapDevice.IsActive() && pcapDevice.IsConnected()) {
                    _config.Interface = pcapDevice.Interface.Name;
                    Logger.Information("Auto-selected interface: {InterfaceName}", pcapDevice.Interface.FriendlyName ?? pcapDevice.Interface.Description);
                    break;
                }
            }
        }

        // Find the specified interface
        foreach (LibPcapLiveDevice pcapDevice in LibPcapLiveDeviceList.Instance) {
            if (pcapDevice.Interface.Name == _config.Interface) {
                _device = pcapDevice;
                break;
            }
        }

        if (_device == null) {
            Console.WriteLine($"Error: Network interface '{_config.Interface}' not found.");
            Console.WriteLine("Use --list-interfaces to see available interfaces.");
            return false;
        }

        try {
            _device.Open(DeviceModes.Promiscuous, 10);
        } catch (Exception ex) {
            Logger.Warning("Failed to set device in promiscuous mode: {ErrorMessage}", ex.Message);
            try {
                _device.Open();
            } catch (Exception ex2) {
                Console.WriteLine($"Error: Failed to open network interface: {ex2.Message}");
                return false;
            }
        }

        _device.OnPacketArrival += device_OnPacketArrival;
        _device.Filter = $"tcp portrange {_config.LowPort}-{_config.HighPort}";

        try {
            _device.StartCapture();
        } catch (Exception ex) {
            Console.WriteLine($"Error: Failed to start packet capture: {ex.Message}");
            return false;
        }

        return true;
    }

    private static void device_OnPacketArrival(object sender, PacketCapture e) {
        lock (PacketQueue) {
            PacketQueue.Add(e.GetPacket());
        }
    }

    private static bool InPortRange(ushort port) {
        return port >= _config.LowPort && port <= _config.HighPort;
    }

    private static void ProcessPacketQueue(object? state) {
        List<RawCapture> curQueue;
        lock (PacketQueue) {
            curQueue = new List<RawCapture>(PacketQueue);
            PacketQueue.Clear();
        }

        DateTime now = DateTime.Now;

        // Clean up old sessions (less aggressive than before)
        List<PacketSession> sessionsToRemove = Sessions.Where(s => s.ShouldClose(now)).ToList();
        foreach (var session in sessionsToRemove) {
            Sessions.Remove(session);
            Logger.Debug("Removed inactive session (total active sessions: {SessionCount})", Sessions.Count);
        }

        foreach (RawCapture packet in curQueue) {
            try {
                var tcpPacket = Packet.ParsePacket(packet.LinkLayerType, packet.Data).Extract<TcpPacket>();
                if (tcpPacket == null) continue;

                PacketSession? session;
                PacketSession.Results? result;

                if (tcpPacket is {Synchronize: true, Acknowledgment: false} && InPortRange(tcpPacket.DestinationPort)) {
                    // New connection
                    session = new PacketSession();
                    Sessions.Add(session);
                    Logger.Debug("New session created (total active sessions: {SessionCount})", Sessions.Count);
                    result = session.BufferTcpPacket(tcpPacket, packet.Timeval.Date);
                } else {
                    // Existing connection
                    session = Sessions.FirstOrDefault(s => s.MatchTcpPacket(tcpPacket));
                    if (session == null) {
                        continue;
                    }
                    result = session.BufferTcpPacket(tcpPacket, packet.Timeval.Date);
                }

                switch (result) {
                    case PacketSession.Results.CloseMe:
                        Sessions.Remove(session);
                        break;
                    case PacketSession.Results.Terminated:
                        Sessions.Remove(session);
                        break;
                }
            } catch (Exception ex) {
                Logger.Error(ex, "Exception while processing packet queue");
            }
        }
    }

    private static void Shutdown() {
        Logger.Information("Shutting down packet sniffer...");
        ProcessTimer.Dispose();
        _device?.StopCapture();
        _device?.Close();
        Log.CloseAndFlush();
    }
}
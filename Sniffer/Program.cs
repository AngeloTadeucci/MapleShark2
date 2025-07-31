using System.Text.Json;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Sniffer.Tools;

namespace Sniffer;

public class Program {
    private static readonly Logger logger = LogManager.GetCurrentClassLogger();
    private static PcapDevice? device;
    private static readonly List<RawCapture> packetQueue = new();
    private static readonly HashSet<PacketSession> sessions = new();
    private static readonly Timer processTimer = new(ProcessPacketQueue, null, TimeSpan.Zero, TimeSpan.FromMilliseconds(100));
    private static SnifferConfig config = new();

    public static async Task Main(string[] args) {
        Console.WriteLine("MapleStory2 Packet Sniffer");
        Console.WriteLine("==========================");

        // Load configuration
        LoadConfiguration(args);

        // Setup network adapter
        if (!SetupAdapter()) {
            Console.WriteLine("Failed to setup network adapter. Exiting...");
            return;
        }

        Console.WriteLine($"Listening on {config.Interface} for ports {config.LowPort}-{config.HighPort}");
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
                    config = fileConfig;
                }
            } catch (Exception ex) {
                Console.WriteLine($"Warning: Failed to load config file: {ex.Message}");
            }
        }

        // Override with command line arguments
        for (int i = 0; i < args.Length; i++) {
            switch (args[i]) {
                case "--interface" when i + 1 < args.Length:
                    config.Interface = args[++i];
                    break;
                case "--low-port" when i + 1 < args.Length:
                    if (ushort.TryParse(args[++i], out ushort lowPort))
                        config.LowPort = lowPort;
                    break;
                case "--high-port" when i + 1 < args.Length:
                    if (ushort.TryParse(args[++i], out ushort highPort))
                        config.HighPort = highPort;
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
        if (device != null) {
            device.StopCapture();
            device.Close();
        }

        // If no interface specified, try to find the first active physical adapter
        if (string.IsNullOrEmpty(config.Interface)) {
            foreach (LibPcapLiveDevice pcapDevice in LibPcapLiveDeviceList.Instance) {
                if (pcapDevice.IsActive() && pcapDevice.IsConnected()) {
                    config.Interface = pcapDevice.Interface.Name;
                    logger.Info($"Auto-selected interface: {pcapDevice.Interface.FriendlyName ?? pcapDevice.Interface.Description}");
                    break;
                }
            }
        }

        // Find the specified interface
        foreach (LibPcapLiveDevice pcapDevice in LibPcapLiveDeviceList.Instance) {
            if (pcapDevice.Interface.Name == config.Interface) {
                device = pcapDevice;
                break;
            }
        }

        if (device == null) {
            Console.WriteLine($"Error: Network interface '{config.Interface}' not found.");
            Console.WriteLine("Use --list-interfaces to see available interfaces.");
            return false;
        }

        try {
            device.Open(DeviceModes.Promiscuous, 10);
        } catch (Exception ex) {
            logger.Warn($"Failed to set device in promiscuous mode: {ex.Message}");
            try {
                device.Open();
            } catch (Exception ex2) {
                Console.WriteLine($"Error: Failed to open network interface: {ex2.Message}");
                return false;
            }
        }

        device.OnPacketArrival += device_OnPacketArrival;
        device.Filter = $"tcp portrange {config.LowPort}-{config.HighPort}";

        try {
            device.StartCapture();
        } catch (Exception ex) {
            Console.WriteLine($"Error: Failed to start packet capture: {ex.Message}");
            return false;
        }

        return true;
    }

    private static void device_OnPacketArrival(object sender, PacketCapture e) {
        lock (packetQueue) {
            packetQueue.Add(e.GetPacket());
        }
    }

    private static bool InPortRange(ushort port) {
        return port >= config.LowPort && port <= config.HighPort;
    }

    private static void ProcessPacketQueue(object? state) {
        List<RawCapture> curQueue;
        lock (packetQueue) {
            curQueue = new List<RawCapture>(packetQueue);
            packetQueue.Clear();
        }

        DateTime now = DateTime.Now;

        // Clean up old sessions (less aggressive than before)
        var sessionsToRemove = sessions.Where(s => s.ShouldClose(now)).ToList();
        foreach (var session in sessionsToRemove) {
            sessions.Remove(session);
            logger.Debug($"Removed inactive session (total active sessions: {sessions.Count})");
        }

        foreach (RawCapture packet in curQueue) {
            try {
                var tcpPacket = Packet.ParsePacket(packet.LinkLayerType, packet.Data).Extract<TcpPacket>();
                if (tcpPacket == null) continue;

                PacketSession? session = null;
                PacketSession.Results? result;

                if (tcpPacket.Synchronize && !tcpPacket.Acknowledgment && InPortRange(tcpPacket.DestinationPort)) {
                    // New connection
                    session = new PacketSession();
                    sessions.Add(session);
                    logger.Debug($"New session created (total active sessions: {sessions.Count})");
                    result = session.BufferTcpPacket(tcpPacket, packet.Timeval.Date);
                } else {
                    // Existing connection
                    session = sessions.FirstOrDefault(s => s.MatchTcpPacket(tcpPacket));
                    if (session == null) {
                        continue;
                    }
                    result = session.BufferTcpPacket(tcpPacket, packet.Timeval.Date);
                }

                switch (result) {
                    case PacketSession.Results.CloseMe:
                        sessions.Remove(session);
                        break;
                    case PacketSession.Results.Terminated:
                        sessions.Remove(session);
                        break;
                }
            } catch (Exception ex) {
                logger.Error(ex, "Exception while processing packet queue");
            }
        }
    }

    private static void Shutdown() {
        logger.Info("Shutting down packet sniffer...");
        processTimer.Dispose();
        device?.StopCapture();
        device?.Close();
    }
}
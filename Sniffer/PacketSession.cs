using System.Text.Json;
using Maple2.PacketLib.Crypto;
using Maple2.PacketLib.Tools;
using Sniffer.Tools;
using Serilog;
using PacketDotNet;

namespace Sniffer;

public class PacketSession {
    public enum Results {
        Show,
        Continue,
        Terminated,
        CloseMe
    }

    private static readonly ILogger logger = Log.ForContext<PacketSession>();

    private bool terminated = false;
    private ushort localPort = 0;
    private ushort remotePort = 0;
    private uint build = 0;
    private byte locale = 0;

    private DateTime startTime;
    private DateTime lastActivity;
    private int packetCount = 0;
    private bool clearedPackets = false;
    private MapleCipher.Decryptor? outDecryptor;
    private MapleCipher.Decryptor? inDecryptor;
    private readonly TcpReassembler tcpReassembler = new();

    public PacketSession() {
        startTime = DateTime.Now;
        lastActivity = DateTime.Now;
    }

    public bool MatchTcpPacket(TcpPacket tcpPacket) {
        if (terminated) return false;
        if (tcpPacket.SourcePort == localPort && tcpPacket.DestinationPort == remotePort) return true;
        if (tcpPacket.SourcePort == remotePort && tcpPacket.DestinationPort == localPort) return true;
        return false;
    }

    public bool ShouldClose(DateTime currentTime) {
        // Only close sessions that have no packets AND haven't been active for 5+ seconds
        // This matches the logic in MainForm.SessionForm.CloseMe()
        if (!clearedPackets && packetCount == 0 && (currentTime - startTime).TotalSeconds >= 5) {
            return true;
        }

        // Also close sessions that have been inactive for a longer period (30 seconds)
        // to handle cases where the connection is lost but not properly terminated
        if ((currentTime - lastActivity).TotalSeconds >= 30) {
            return true;
        }

        return false;
    }

    public Results BufferTcpPacket(TcpPacket tcpPacket, DateTime arrivalTime) {
        if (terminated) return Results.Terminated;

        // Handle TCP connection termination
        if (tcpPacket.Finished || tcpPacket.Reset) {
            terminated = true;
            return packetCount == 0 ? Results.CloseMe : Results.Terminated;
        }

        if (localPort == 0) {
            localPort = tcpPacket.DestinationPort;
            remotePort = tcpPacket.SourcePort;
        }

        bool isOutbound = tcpPacket.SourcePort == localPort;
        tcpReassembler.ReassembleStream(tcpPacket);

        // Update activity timestamp
        lastActivity = arrivalTime;

        MapleStream packetStream = isOutbound ? tcpReassembler.OutStream : tcpReassembler.InStream;
        bool show = false;

        try {
            while (packetStream.TryRead(out byte[] packet)) {
                logger.Debug("Processing packet: {Packet}", packet);
                Results result = ProcessPacket(packet, isOutbound, arrivalTime);
                switch (result) {
                    case Results.Continue:
                        continue;
                    case Results.Show:
                        show = true;
                        break;
                    default:
                        return result;
                }
            }
        } catch (Exception ex) {
            logger.Error(ex, "Exception while buffering packets");
            terminated = true;
            return Results.Terminated;
        }

        return show ? Results.Show : Results.Continue;
    }

    private Results ProcessPacket(byte[] bytes, bool isOutbound, DateTime timestamp) {
        if (terminated) return Results.Terminated;

        if (build == 0) {
            logger.Debug("Processing handshake packet");
            // Handle handshake packet
            var packet = new ByteReader(bytes);
            packet.Read<ushort>(); // rawSeq
            int length = packet.ReadInt();
            if (bytes.Length - 6 < length) {
                logger.Debug("Connection on port {LocalPort} did not have a MapleStory2 Handshake", localPort);
                return Results.CloseMe;
            }

            ushort opcode = packet.Read<ushort>();
            if (opcode != 0x01) {
                logger.Debug("Connection on port {LocalPort} did not have a valid MapleStory2 Connection Header", localPort);
                return Results.CloseMe;
            }

            uint version = packet.Read<uint>();
            uint siv = packet.Read<uint>();
            uint riv = packet.Read<uint>();
            uint blockIV = packet.Read<uint>();
            byte type = packet.ReadByte();

            build = version;
            locale = 0; // Unknown locale for CLI

            outDecryptor = new MapleCipher.Decryptor(build, siv, blockIV);
            inDecryptor = new MapleCipher.Decryptor(build, riv, blockIV);

            var decodedPacket = inDecryptor.Decrypt(bytes); // Advance the IV
            logger.Debug("Decrypted handshake packet: {Packet}", decodedPacket);

            // Output handshake packet
            OutputPacket(new PacketInfo {
                Timestamp = timestamp,
                Outbound = isOutbound,
                Opcode = opcode,
                Name = "RequestVersion",
                Build = build,
                Data = decodedPacket.ToString(),
            });

            packetCount++;
            logger.Information("[CONNECTION] MapleStory2 V{Build} session established on port {LocalPort}", build, localPort);
            return Results.Show;
        }

        try {
            MapleCipher.Decryptor decryptor = isOutbound ? outDecryptor! : inDecryptor!;
            ByteReader packet = decryptor.Decrypt(bytes);
            logger.Debug("Decrypted packet: {Packet}", packet);

            if (packet.Available == 0) {
                return Results.Continue;
            }

            ushort opcode = packet.Peek<ushort>();
            byte[] data = packet.Buffer[2..packet.Length];

            // Output decrypted packet
            OutputPacket(new PacketInfo {
                Timestamp = timestamp,
                Outbound = isOutbound,
                Opcode = opcode,
                Name = $"Unknown_{opcode:X4}", // No packet definitions in CLI mode
                Build = build,
                Data = packet.ToString(),
            });

            packetCount++;
            return Results.Continue;
        } catch (ArgumentException ex) {
            logger.Error(ex, "Exception while processing packets");
            return Results.CloseMe;
        }
    }

    private static void OutputPacket(PacketInfo packetInfo) {
        string json = JsonSerializer.Serialize(packetInfo, new JsonSerializerOptions {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        Console.WriteLine(json);
    }
}

public class PacketInfo {
    public DateTime Timestamp { get; set; }
    public bool Outbound { get; set; }
    public ushort Opcode { get; set; }
    public string Name { get; set; } = "";
    public uint Build { get; set; }
    public string Data { get; set; } = "";
}
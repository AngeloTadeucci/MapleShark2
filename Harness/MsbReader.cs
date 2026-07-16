using System;
using System.Collections.Generic;
using System.IO;

namespace MapleShark2.Harness {
    public sealed class MsbMetadata {
        public string LocalEndpoint;
        public ushort LocalPort;
        public string RemoteEndpoint;
        public ushort RemotePort;
        public byte Locale;
        public uint Build;
        public ushort FileFormat;
    }

    public sealed class RawPacket {
        public DateTime Timestamp;
        public bool Outbound;
        public ushort Opcode;

        /// <summary>Packet payload, excluding the opcode. Exactly sized.</summary>
        public byte[] Data;
    }

    /// <summary>
    /// UI-independent .msb reader. Mirrors MapleShark2.Tools.FileLoader.ReadMsbFile framing exactly,
    /// but throws instead of showing a MessageBox, so it can run headless over the whole archive.
    /// </summary>
    public static class MsbReader {
        /// <summary>Parse only the header. Lets a run filter 1417 files by build without decoding 10M packets.</summary>
        public static MsbMetadata ReadHeader(string path) {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 12))
            using (var reader = new BinaryReader(stream)) {
                return ReadHeader(reader, path);
            }
        }

        private static MsbMetadata ReadHeader(BinaryReader reader, string path) {
            var metadata = new MsbMetadata();
            ushort version = reader.ReadUInt16();
            metadata.FileFormat = version;

            if (version < 0x2000) {
                metadata.Build = version;
                metadata.LocalPort = reader.ReadUInt16();
                metadata.Locale = 0;
            } else if (version == 0x2012) {
                metadata.Locale = (byte) reader.ReadUInt16();
                metadata.Build = reader.ReadUInt16();
                metadata.LocalPort = reader.ReadUInt16();
            } else if (version == 0x2014) {
                metadata.LocalEndpoint = reader.ReadString();
                metadata.LocalPort = reader.ReadUInt16();
                metadata.RemoteEndpoint = reader.ReadString();
                metadata.RemotePort = reader.ReadUInt16();
                metadata.Locale = (byte) reader.ReadUInt16();
                metadata.Build = reader.ReadUInt16();
            } else if (version == 0x2015 || version >= 0x2020) {
                metadata.LocalEndpoint = reader.ReadString();
                metadata.LocalPort = reader.ReadUInt16();
                metadata.RemoteEndpoint = reader.ReadString();
                metadata.RemotePort = reader.ReadUInt16();
                metadata.Locale = reader.ReadByte();
                metadata.Build = reader.ReadUInt32();
            } else {
                throw new InvalidDataException($"{Path.GetFileName(path)}: unsupported msb format 0x{version:X4}");
            }

            return metadata;
        }

        public static (MsbMetadata, List<RawPacket>) Read(string path) {
            var packets = new List<RawPacket>();

            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16))
            using (var reader = new BinaryReader(stream)) {
                MsbMetadata metadata = ReadHeader(reader, path);
                ushort version = metadata.FileFormat;

                while (stream.Position < stream.Length) {
                    long timestamp = reader.ReadInt64();
                    int size = version < 0x2027 ? reader.ReadUInt16() : reader.ReadInt32();
                    ushort opcode = reader.ReadUInt16();

                    bool outbound;
                    if (version >= 0x2020) {
                        outbound = reader.ReadBoolean();
                    } else {
                        outbound = (size & 0x8000) != 0;
                        size = (ushort) (size & 0x7FFF);
                    }

                    if (size < 0 || stream.Position + size > stream.Length) {
                        throw new InvalidDataException(
                            $"{Path.GetFileName(path)}: packet at 0x{stream.Position:X} declares {size} bytes, " +
                            $"only {stream.Length - stream.Position} remain");
                    }

                    byte[] data = reader.ReadBytes(size);
                    if (version >= 0x2025 && version < 0x2030) {
                        reader.ReadUInt32(); // preDecodeIV
                        reader.ReadUInt32(); // postDecodeIV
                    }

                    packets.Add(new RawPacket {
                        Timestamp = new DateTime(timestamp),
                        Outbound = outbound,
                        Opcode = opcode,
                        Data = data,
                    });
                }

                return (metadata, packets);
            }
        }
    }
}

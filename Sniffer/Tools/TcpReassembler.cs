using System;
using Maple2.PacketLib.Tools;
using PacketDotNet;
using PacketDotNet.Utils;

namespace Sniffer.Tools {
    public class TcpReassembler {
        /// <summary>
        /// A class that represent a node in a linked list that holds partial Tcp session
        /// fragments
        /// </summary>
        private class TcpFragment {
            public ulong Sequence;
            public ulong Length;
            public ulong DataLength;
            public byte[]? Data;
            public TcpFragment? Next;
        };

        // holds two linked list of the session data, one for each direction
        private readonly TcpFragment?[] fragments = new TcpFragment?[2];

        // holds the last sequence number for each direction
        private readonly ulong[] sequence = new ulong[2];
        private readonly long[] srcIp = new long[2];
        private readonly uint[] srcPort = new uint[2];

        public readonly MapleStream InStream = new MapleStream();
        public readonly MapleStream OutStream = new MapleStream();

        /// <summary>
        /// Buffers tcp data to reassemble the packet stream.
        /// </summary>
        /// <param name="tcpPacket"></param>
        public void ReassembleStream(TcpPacket tcpPacket) {
            ByteArraySegment tcpData = tcpPacket.PayloadDataSegment;
            if (tcpData == null || tcpData.Length == 0) {
                return;
            }

            var ipPacket = (IPPacket) tcpPacket.ParentPacket;
            if (ipPacket.Version == IPVersion.IPv6) {
                return;
            }

            int maxLength = tcpData.BytesLength - tcpData.Offset;
            int length = Math.Min(tcpData.Length, maxLength);

            byte[] payloadBytes = new byte[length];
            Array.Copy(tcpData.Bytes, tcpData.Offset, payloadBytes, 0, length);

            ReassembleTcp(tcpPacket.SequenceNumber, (ulong) length, payloadBytes, (ulong) length, tcpPacket.Synchronize,
                ipPacket.SourceAddress.Address, tcpPacket.SourcePort);
        }

        /// <summary>
        /// Reconstructs the tcp session
        /// </summary>
        /// <param name="sequence">Sequence number of the tcp packet</param>
        /// <param name="length">The size of the original packet data</param>
        /// <param name="data">The captured data</param>
        /// <param name="dataLength">The length of the captured data</param>
        /// <param name="synFlag"></param>
        /// <param name="srcIp">The source ip address</param>
        /// <param name="srcPort">The source port</param>
        private void ReassembleTcp(ulong sequence, ulong length, byte[] data, ulong dataLength, bool synFlag,
            long srcIp, ushort srcPort) {
            bool first = false;
            int srcIndex = 0;

            /* Now check if the packet is for this connection. */
            if (this.srcIp[0] == 0 && this.srcPort[0] == 0) {
                /* this is the first packet we have seen */
                this.srcIp[0] = srcIp;
                this.srcPort[0] = srcPort;
                this.sequence[0] = sequence + length;
                if (synFlag) {
                    this.sequence[0]++;
                }

                srcIndex = 0;
                first = true;
            } else if (this.srcIp[0] == srcIp && this.srcPort[0] == srcPort) {
                srcIndex = 0;
            } else {
                if (this.srcIp[1] == 0 && this.srcPort[1] == 0) {
                    /* this is the first packet of the second src */
                    this.srcIp[1] = srcIp;
                    this.srcPort[1] = srcPort;
                    this.sequence[1] = sequence + length;
                    if (synFlag) {
                        this.sequence[1]++;
                    }

                    srcIndex = 1;
                    first = true;
                } else if (this.srcIp[1] == srcIp && this.srcPort[1] == srcPort) {
                    srcIndex = 1;
                } else {
                    return;
                }
            }

            if (first) {
                /* this is the first time we have seen this src's packet */
                if (data != null) {
                    WritePacketData(srcIndex, data);
                }

                return;
            }

            /* if we are here, we have already seen this src, let's
            try and figure out if this packet is in the right place */
            if (sequence < this.sequence[srcIndex]) { // retransmitted packet
                /* this sequence number seems dated, but it may have more info than we have already seen. */
                ulong newSequence = sequence + length;
                if (newSequence > this.sequence[srcIndex]) {
                    /* this one has more than we have seen. let's get the payload that we have not seen. */
                    ulong offset = this.sequence[srcIndex] - sequence;
                    if (dataLength > offset) {
                        WritePacketData(srcIndex, data, (int) offset);
                    }

                    this.sequence[srcIndex] = newSequence;

                    /* done with the packet, see if it caused a fragment to fit */
                    while (CheckFragments(srcIndex)) { }
                }
            } else if (sequence == this.sequence[srcIndex]) { // right on time
                this.sequence[srcIndex] += length;
                if (synFlag) {
                    this.sequence[srcIndex]++;
                }

                if (data != null) {
                    WritePacketData(srcIndex, data);
                }

                /* done with the packet, see if it caused a fragment to fit */
                while (CheckFragments(srcIndex)) { }
            } else if (dataLength > 0 && sequence > this.sequence[srcIndex]) { // out of order packet
                var tmpFragment = new TcpFragment {
                    Data = data,
                    Sequence = sequence,
                    Length = length,
                    DataLength = dataLength,
                    Next = fragments[srcIndex],
                };

                fragments[srcIndex] = tmpFragment;
            }
        }

        /* here we search through all the frag we have collected to see if one fits */
        private bool CheckFragments(int index) {
            TcpFragment? prev = null;
            TcpFragment? current = fragments[index];
            ulong minSequence = current?.Sequence ?? 0;
            while (current != null) {
                if (minSequence > current.Sequence) {
                    minSequence = current.Sequence;
                }

                if (current.Sequence < sequence[index]) {
                    /* this sequence number seems dated, but check the end to make
                    sure it has no more info than we have already seen */
                    ulong newSequence = current.Sequence + current.Length;
                    if (newSequence > sequence[index]) {
                        /* this one has more than we have seen. let's get the payload that we have not seen.
                        This happens when part of this frame has been retransmitted */
                        ulong offset = sequence[index] - current.Sequence;
                        if (current.DataLength > offset) {
                            WritePacketData(index, current.Data, (int) offset);
                        }

                        sequence[index] = newSequence;
                    }

                    /* Remove the fragment from the list as the "new" part of it has been processed
                    or its data has been seen already in another packet. */
                    if (prev != null) {
                        prev.Next = current.Next;
                    } else {
                        fragments[index] = current.Next;
                    }

                    return true;
                }

                if (current.Sequence == sequence[index]) {
                    /* this fragment fits the stream */
                    if (current.Data != null) {
                        WritePacketData(index, current.Data);
                    }

                    sequence[index] += current.Length;
                    if (prev != null) {
                        prev.Next = current.Next;
                    } else {
                        fragments[index] = current.Next;
                    }

                    return true;
                }

                prev = current;
                current = current.Next;
            }

            return false;
        }

        /// <summary>
        /// Writes the payload data to the file
        /// </summary>
        /// <param name="index"></param>
        /// <param name="data"></param>
        /// <param name="offset">Offset of the data buffer to be written</param>
        private void WritePacketData(int index, byte[] data, int offset = 0) {
            // Nothing to do when there is no data to be written.
            int dataLength = data.Length - offset;
            if (dataLength <= 0) {
                return;
            }

            if (index == 0) {
                InStream.Write(data, offset, dataLength);
            } else {
                OutStream.Write(data, offset, dataLength);
            }
        }
    }
}

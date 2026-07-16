using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace MapleShark2.Tools {
    /// <summary>
    /// A reader that bounds every read/skip against an explicit <c>(offset, count)</c> segment of the
    /// backing array, instead of against the length of the whole array like
    /// <see cref="Maple2.PacketLib.Tools.ByteReader"/> does.
    ///
    /// <para>This is the Phase 3 precondition (see docs/CAMPAIGN.md §5 Phase 3). Over-read detection in the GUI
    /// currently works <i>only because</i> every packet owns an exactly-sized array, so the packet's
    /// segment happens to equal the whole backing array. The moment buffers are pooled or shared,
    /// <see cref="Maple2.PacketLib.Tools.ByteReader"/> would bound reads against the oversized backing
    /// storage and silently stop detecting over-reads. Bounding against the segment keeps the detection
    /// intact regardless of how the buffer was allocated.</para>
    ///
    /// <para>The exception contract intentionally mirrors <see cref="Maple2.PacketLib.Tools.ByteReader"/>:
    /// out-of-bounds reads/skips (including negative lengths) throw <see cref="IndexOutOfRangeException"/>,
    /// not a bespoke type, because scripts and <c>StructureForm</c>'s catch already depend on that being
    /// what surfaces. This differs deliberately from <c>Harness/BoundedByteReader</c>, which throws its
    /// own <c>OverReadException</c> for headless diagnostics.</para>
    /// </summary>
    public sealed class SegmentByteReader {
        /// <summary>The backing array. Reads never leave the [start, end) window inside it.</summary>
        public byte[] Buffer { get; }

        private readonly int start;
        private readonly int end;

        /// <summary>Absolute position inside <see cref="Buffer"/> (not relative to the segment).</summary>
        public int Position { get; private set; }

        /// <summary>Bytes remaining in the segment.</summary>
        public int Available => end - Position;

        public SegmentByteReader(byte[] array, int offset, int count) {
            if (array == null) throw new ArgumentNullException(nameof(array));
            if (offset < 0 || count < 0 || offset + count > array.Length) {
                throw new ArgumentOutOfRangeException(nameof(count), "segment does not fit inside array");
            }

            Buffer = array;
            start = offset;
            end = offset + count;
            Position = offset;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void CheckLength(int length) {
            int index = Position + length;
            // index < Position also catches negative lengths / integer overflow, matching ByteReader.
            if (index > end || index < Position) {
                throw new IndexOutOfRangeException(
                    $"Not enough space in packet: wanted {length} byte(s) at offset {Position - start}, " +
                    $"only {Available} of {end - start} remain\n");
            }
        }

        public T Read<T>() where T : struct {
            int size = Unsafe.SizeOf<T>();
            CheckLength(size);
            var value = MemoryMarshal.Read<T>(new ReadOnlySpan<byte>(Buffer, Position, size));
            Position += size;
            return value;
        }

        public byte[] ReadBytes(int count) {
            CheckLength(count);
            var bytes = new byte[count];
            System.Buffer.BlockCopy(Buffer, Position, bytes, 0, count);
            Position += count;
            return bytes;
        }

        public void Skip(int count) {
            int index = Position + count;
            if (index > end || index < start) { // Allow backwards seeking, but only within the segment.
                throw new IndexOutOfRangeException(
                    $"Not enough space in packet: cannot skip {count} byte(s) from offset {Position - start}\n");
            }

            Position = index;
        }

        public void Reset() => Position = start;
    }
}

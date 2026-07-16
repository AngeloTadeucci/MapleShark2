using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace MapleShark2.Harness {
    /// <summary>
    /// Why this exists instead of Maple2.PacketLib.ByteReader:
    /// ByteReader bounds against <c>packet.Length</c> — the length of the whole backing array — so it
    /// only detects over-read while every packet owns an exactly-sized array. That holds for msb file
    /// loads today, but stops holding the moment buffers are pooled or shared. Over-read detection is
    /// the harness's core safety signal, so it is bounded by an explicit (array, offset, count) segment
    /// and cannot be silently disarmed by a change to how buffers are allocated.
    /// </summary>
    public sealed class BoundedByteReader {
        private readonly byte[] array;
        private readonly int start;
        private readonly int end;
        private int position;

        public BoundedByteReader(byte[] array, int offset, int count) {
            if (array == null) throw new ArgumentNullException(nameof(array));
            if (offset < 0 || count < 0 || offset + count > array.Length) {
                throw new ArgumentOutOfRangeException(nameof(count), "segment does not fit inside array");
            }

            this.array = array;
            start = offset;
            end = offset + count;
            position = offset;
        }

        /// <summary>Bytes consumed so far.</summary>
        public int Consumed => position - start;

        /// <summary>Bytes declared by the packet.</summary>
        public int Length => end - start;

        /// <summary>Bytes not yet consumed.</summary>
        public int Available => end - position;

        /// <summary>Absolute offset into the backing array, for trace records.</summary>
        public int AbsolutePosition => position;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Require(int length, string what) {
            // A negative length is never a legitimate read. It means a count/size field was decoded
            // from the wrong offset — i.e. the parse has already desynchronized. Surfacing it as a
            // distinct reason makes it a diagnostic rather than a confusing ArgumentException.
            if (length < 0) {
                throw new OverReadException(OverReadReason.NegativeLength,
                    $"{what}: negative length {length} at offset {Consumed}/{Length}");
            }

            if (position + length > end) {
                throw new OverReadException(OverReadReason.PastEnd,
                    $"{what}: wanted {length} byte(s) at offset {Consumed}, only {Available} of {Length} remain");
            }
        }

        public T Read<T>() where T : struct {
            int size = Unsafe.SizeOf<T>();
            Require(size, "Read<" + typeof(T).Name + ">");
            T value = MemoryMarshal.Read<T>(new ReadOnlySpan<byte>(array, position, size));
            position += size;
            return value;
        }

        public byte[] ReadBytes(int count) {
            Require(count, "ReadBytes");
            var buffer = new byte[count];
            Buffer.BlockCopy(array, position, buffer, 0, count);
            position += count;
            return buffer;
        }

        public void Skip(int count) {
            Require(count, "Skip");
            position += count;
        }

        public void Reset() => position = start;

        /// <summary>Remaining bytes, without consuming them. Used to describe the undecoded tail.</summary>
        public ArraySegment<byte> PeekRemaining() => new ArraySegment<byte>(array, position, Available);
    }

    public enum OverReadReason {
        /// <summary>Read would cross the end of the packet.</summary>
        PastEnd,

        /// <summary>A decoded length/count field was negative — the parse is already desynchronized.</summary>
        NegativeLength,
    }

    public sealed class OverReadException : Exception {
        public OverReadReason Reason { get; }

        public OverReadException(OverReadReason reason, string message) : base(message) {
            Reason = reason;
        }
    }
}

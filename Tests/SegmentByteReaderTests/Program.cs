using System;
using MapleShark2.Tools;

internal static class Program {
    private static int passed;
    private static int failed;

    private static void Check(string name, bool cond) {
        if (cond) { passed++; Console.WriteLine($"PASS: {name}"); }
        else { failed++; Console.WriteLine($"FAIL: {name}"); }
    }

    private static void ExpectThrows<TEx>(string name, Action action) where TEx : Exception {
        try {
            action();
            failed++;
            Console.WriteLine($"FAIL: {name} (no exception thrown)");
        } catch (TEx) {
            passed++;
            Console.WriteLine($"PASS: {name} (threw {typeof(TEx).Name})");
        } catch (Exception ex) {
            failed++;
            Console.WriteLine($"FAIL: {name} (threw {ex.GetType().Name}, expected {typeof(TEx).Name})");
        }
    }

    private static int Main() {
        // A 20-byte backing array; the packet lives in a segment at offset 5, count 8 -> bytes [5..13).
        // Surround with sentinel 0xFF so an out-of-segment read would be visibly wrong.
        byte[] backing = new byte[20];
        for (int i = 0; i < backing.Length; i++) backing[i] = 0xFF;
        // Segment contents: byte 0x11, ushort 0x3322 (LE: 22 33), int 0x08070605 (LE: 05 06 07 08), byte 0x99
        // offset: 5    6  7    8  9 10 11   12
        backing[5] = 0x11;
        backing[6] = 0x22; backing[7] = 0x33;
        backing[8] = 0x05; backing[9] = 0x06; backing[10] = 0x07; backing[11] = 0x08;
        backing[12] = 0x99;
        const int off = 5, cnt = 8; // end = 13

        // --- Reads within a segment at nonzero offset ---
        var r = new SegmentByteReader(backing, off, cnt);
        Check("initial Position == offset", r.Position == off);
        Check("initial Available == count", r.Available == cnt);

        byte b0 = r.Read<byte>();
        Check("Read<byte> value from segment offset", b0 == 0x11);
        Check("Position after byte", r.Position == off + 1);

        ushort u = r.Read<ushort>();
        Check("Read<ushort> little-endian from segment", u == 0x3322);
        Check("Available after ushort", r.Available == cnt - 3);

        int iv = r.Read<int>();
        Check("Read<int> little-endian from segment", iv == 0x08070605);

        byte[] tail = r.ReadBytes(1);
        Check("ReadBytes returns correct byte", tail.Length == 1 && tail[0] == 0x99);

        // --- Exact consume ---
        Check("Available == 0 after exact consume", r.Available == 0);
        Check("Position == end after exact consume", r.Position == off + cnt);

        // --- Past-end reads throw IndexOutOfRangeException (ByteReader contract) ---
        ExpectThrows<IndexOutOfRangeException>("Read<byte> past end throws", () => r.Read<byte>());
        ExpectThrows<IndexOutOfRangeException>("ReadBytes past end throws", () => r.ReadBytes(1));

        // A Read<int> that would straddle the segment boundary (only 1 byte left) must throw.
        var r2 = new SegmentByteReader(backing, off, cnt);
        r2.Skip(cnt - 1); // 1 byte remaining
        Check("Available == 1 before straddling read", r2.Available == 1);
        ExpectThrows<IndexOutOfRangeException>("Read<int> straddling segment end throws", () => r2.Read<int>());
        // ...and the position was not advanced by the failed read.
        Check("Position unchanged after failed read", r2.Position == off + cnt - 1);

        // --- Skip beyond end throws ---
        var r3 = new SegmentByteReader(backing, off, cnt);
        ExpectThrows<IndexOutOfRangeException>("Skip beyond end throws", () => r3.Skip(cnt + 1));
        Check("Position unchanged after failed skip", r3.Position == off);
        // Skip to exactly the end is allowed.
        r3.Skip(cnt);
        Check("Skip to exact end allowed", r3.Position == off + cnt && r3.Available == 0);

        // --- Negative length ---
        var r4 = new SegmentByteReader(backing, off, cnt);
        ExpectThrows<IndexOutOfRangeException>("ReadBytes(negative) throws", () => r4.ReadBytes(-1));
        Check("Position unchanged after negative ReadBytes", r4.Position == off);

        // --- Backwards skip / Reset semantics (used by MaplePacket.Reset) ---
        var r5 = new SegmentByteReader(backing, off, cnt);
        r5.Read<int>(); // advance 4
        Check("Position after advance", r5.Position == off + 4);
        // MaplePacket.Reset does reader.Skip(-reader.Position + segmentOffset) -> lands exactly at start.
        r5.Skip(-r5.Position + off);
        Check("backwards Skip to start", r5.Position == off);
        r5.Read<int>();
        r5.Reset();
        Check("Reset returns to start", r5.Position == off && r5.Available == cnt);
        // Skipping before the segment start must throw (cannot seek into a neighbouring packet's bytes).
        ExpectThrows<IndexOutOfRangeException>("Skip before segment start throws", () => r5.Skip(-1));

        // --- Constructor bounds: segment must fit inside array ---
        ExpectThrows<ArgumentOutOfRangeException>("ctor rejects offset+count > array", () => new SegmentByteReader(backing, 15, 10));
        ExpectThrows<ArgumentOutOfRangeException>("ctor rejects negative offset", () => new SegmentByteReader(backing, -1, 4));
        ExpectThrows<ArgumentNullException>("ctor rejects null array", () => new SegmentByteReader(null, 0, 0));

        // --- Segment at the very end of the array bounds correctly (regression for oversized-buffer case) ---
        // A reader over [5..13) must NOT be able to read the sentinel 0xFF at index 13 even though the
        // backing array extends further. This is the exact property pooling would otherwise break.
        var r6 = new SegmentByteReader(backing, off, cnt);
        r6.Skip(cnt);
        ExpectThrows<IndexOutOfRangeException>("cannot read past segment into larger backing array", () => r6.Read<byte>());

        Console.WriteLine();
        Console.WriteLine($"RESULT: {passed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
    }
}

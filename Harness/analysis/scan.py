import os, struct, collections, sys

ROOT = r"D:\Projetos\MapleStory2\MapleShark2-Sniffs"

def read_7bit_str(f):
    # BinaryWriter.Write(string): 7-bit encoded length prefix + UTF8
    count = 0; shift = 0
    while True:
        b = f.read(1)
        if not b: raise EOFError
        b = b[0]
        count |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
        if shift > 35: raise ValueError("bad 7bit len")
    return f.read(count).decode('utf-8', 'replace')

def parse(path):
    with open(path, 'rb') as f:
        ver = struct.unpack('<H', f.read(2))[0]
        if ver < 0x2000:
            build = ver
            struct.unpack('<H', f.read(2))[0]  # LocalPort
            return 0, build, ver
        if ver == 0x2012:
            loc = struct.unpack('<H', f.read(2))[0]
            build = struct.unpack('<H', f.read(2))[0]
            return loc, build, ver
        # 0x2014 .. 0x2030 : endpoints as strings
        read_7bit_str(f); f.read(2); read_7bit_str(f); f.read(2)
        loc = f.read(1)[0]
        build = struct.unpack('<I', f.read(4))[0]
        return loc, build, ver

rows = collections.Counter()
byver = collections.Counter()
errs = 0
for dirpath, _, names in os.walk(ROOT):
    for n in names:
        if not n.lower().endswith('.msb'): continue
        p = os.path.join(dirpath, n)
        top = os.path.relpath(p, ROOT).split(os.sep)[0]
        try:
            loc, build, ver = parse(p)
            rows[(top, loc, build)] += 1
            byver[ver] += 1
        except Exception as e:
            errs += 1

print("=== (archive dir, locale, build) -> count ===")
for (top, loc, build), c in sorted(rows.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2])):
    print(f"{top:14s} locale={loc:<3} build={build:<6} {c:5d} files")

print("\n=== distinct builds per archive ===")
per = collections.defaultdict(set)
for (top, loc, build) in rows: per[top].add(build)
for top, builds in sorted(per.items()):
    bs = sorted(builds)
    print(f"{top:14s} {len(bs):3d} distinct builds: {bs if len(bs)<=25 else str(bs[:25])+' ...'}")

print("\n=== msb file-format versions ===")
for v, c in sorted(byver.items()): print(f"  0x{v:04X}: {c}")
print(f"\nparse errors: {errs}")

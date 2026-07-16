"""Phase 5 feasibility: extract build-12 payloads for target opcodes (blind inference input).
Reuses drift.py framing. Writes payloads.pkl -> {(op,ob): [bytes,...]} capped per key.
Stdlib only. Run: py infer_extract.py"""
import os, struct, io, pickle, collections, random

ROOT = r"D:\Projetos\MapleStory2\MapleShark2-Sniffs"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                   "scratch_phase5", "payloads.pkl")
CAP = 6000          # payloads kept per (op,ob) via reservoir
random.seed(1)

# (op, ob)  ob: 0=IN, 1=OUT   (confirmed: ob==0 -> IN dir)
TARGETS = {
    (0x0059,0),(0x0024,0),(0x002F,0),(0x0012,1),(0x0023,0),
    (0x0077,0),(0x003E,0),(0x0080,0),(0x0011,0),(0x0048,0),
    (0x000B,1),(0x003D,0),(0x0020,1),(0x0021,0),(0x0057,0),
}

def r7(f):
    c=0;s=0
    while True:
        b=f.read(1)[0]; c|=(b&0x7F)<<s
        if not (b&0x80): break
        s+=7
    return f.read(c)

def parse_payloads(path):
    """Yield (op, ob, payload_bytes) for build-12 files only."""
    with open(path,'rb') as fh:
        data=fh.read()
    f=io.BytesIO(data)
    ver=struct.unpack('<H',f.read(2))[0]
    if ver<0x2000:
        build=ver; f.read(2); loc=0
    elif ver==0x2012:
        loc=struct.unpack('<H',f.read(2))[0]; build=struct.unpack('<H',f.read(2))[0]; f.read(2)
    elif ver==0x2014:
        r7(f); f.read(2); r7(f); f.read(2); loc=struct.unpack('<H',f.read(2))[0]; build=struct.unpack('<H',f.read(2))[0]
    elif ver==0x2015 or ver>=0x2020:
        r7(f); f.read(2); r7(f); f.read(2); loc=f.read(1)[0]; build=struct.unpack('<I',f.read(4))[0]
    else:
        return
    if build!=12:
        return
    end=len(data)
    while f.tell()<end:
        h=f.read(8)
        if len(h)<8: break
        if ver<0x2027:
            size=struct.unpack('<H',f.read(2))[0]
        else:
            size=struct.unpack('<i',f.read(4))[0]
        op=struct.unpack('<H',f.read(2))[0]
        if ver>=0x2020:
            ob=f.read(1)[0]!=0
        else:
            ob=(size&0x8000)!=0; size&=0x7FFF
        if size<0 or f.tell()+size>end: break
        payload=f.read(size)
        if 0x2025<=ver<0x2030: f.read(8)
        key=(op,1 if ob else 0)
        if key in TARGETS:
            yield key, payload

buckets=collections.defaultdict(list)
seen=collections.Counter()
files=0; b12files=0
for dp,_,ns in os.walk(ROOT):
    for n in ns:
        if not n.lower().endswith('.msb'): continue
        files+=1
        try:
            got=False
            for key,payload in parse_payloads(os.path.join(dp,n)):
                got=True
                seen[key]+=1
                b=buckets[key]
                if len(b)<CAP:
                    b.append(payload)
                else:
                    j=random.randint(0,seen[key]-1)
                    if j<CAP: b[j]=payload
            if got: b12files+=1
        except Exception: pass

os.makedirs(os.path.dirname(OUT),exist_ok=True)
pickle.dump({k:v for k,v in buckets.items()}, open(OUT,"wb"))
print(f"scanned {files} files, {b12files} contributed build-12 target packets")
for k in sorted(seen):
    op,ob=k
    print(f"0x{op:04X} {'IN ' if ob==0 else 'OUT'}  total_seen={seen[k]:>8}  kept={len(buckets[k]):>5}")

import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
import os, struct, collections, statistics, pickle

ROOT = r"D:\Projetos\MapleStory2\MapleShark2-Sniffs"

def r7(f):
    c=0;s=0
    while True:
        b=f.read(1)[0]; c|=(b&0x7F)<<s
        if not (b&0x80): break
        s+=7
    return f.read(c)

def parse(path):
    out=[]
    with open(path,'rb') as f:
        data=f.read()
    import io; f=io.BytesIO(data)
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
        return build_out(None)
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
        f.read(size)
        if 0x2025<=ver<0x2030: f.read(8)
        out.append((op,ob,size))
    return build,out

# (build, op, outbound) -> Counter(size)
rec=collections.defaultdict(collections.Counter)
files=0
for dp,_,ns in os.walk(ROOT):
    for n in ns:
        if not n.lower().endswith('.msb'): continue
        try:
            build,pkts=parse(os.path.join(dp,n))
            files+=1
            for op,ob,size in pkts: rec[(build,op,ob)][size]+=1
        except Exception: pass

pickle.dump(dict(rec), open(r_HERE,"wb"))
print(f"parsed {files} files")
tot=sum(sum(c.values()) for c in rec.values())
print(f"total packets: {tot:,}")

# aggregate corpora
v12=collections.defaultdict(collections.Counter)
kms=collections.defaultdict(collections.Counter)
for (b,op,ob),c in rec.items():
    if b==12: v12[(op,ob)].update(c)
    elif b>=2000: kms[(op,ob)].update(c)

print(f"\nV12  packets: {sum(sum(c.values()) for c in v12.values()):,}   distinct (op,dir): {len(v12)}")
print(f"KMS2 packets: {sum(sum(c.values()) for c in kms.values()):,}   distinct (op,dir): {len(kms)}")

sv, sk = set(v12), set(kms)
print(f"\n(op,dir) in BOTH      : {len(sv&sk)}")
print(f"(op,dir) V12 only     : {len(sv-sk)}")
print(f"(op,dir) KMS2 only    : {len(sk-sv)}")

import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
import os, pickle, collections
SR = r"D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0"
rec=pickle.load(open(_os.path.join(_HERE,"rec.pkl"),"rb"))

def ops(v):
    s=set()
    for d in ("Inbound","Outbound"):
        p=os.path.join(SR,v,d)
        if os.path.isdir(p):
            for f in os.listdir(p):
                if f.endswith(".py"): s.add((int(f[2:6],16), d=="Outbound"))
    return s
vers=sorted([d for d in os.listdir(SR) if d.isdigit()], key=int)
avail={int(v):ops(v) for v in vers}
kms_dirs=sorted([b for b in avail if b!=12])

# sniff traffic per build
traffic=collections.defaultdict(collections.Counter)
for (b,op,ob),c in rec.items(): traffic[b][(op,ob)] += sum(c.values())
files={12:764}
sniff_builds=sorted([b for b in traffic if b>=2000])

print("=== KMS2 coverage: exact-match vs KMS2-lineage chaining (NO V12 fallthrough) ===")
print(f"{'build':>6} {'packets':>12} {'exact':>7} {'chained':>8} {'%pkts exact':>12} {'%pkts chained':>14}")
te=tc=tp=0
for b in sniff_builds:
    ex=avail.get(b,set())
    ch=set()
    for v in [x for x in kms_dirs if x<=b]: ch|=avail[v]
    seen=traffic[b]; tot=sum(seen.values())
    pe=sum(n for k,n in seen.items() if k in ex)
    pc=sum(n for k,n in seen.items() if k in ch)
    te+=pe; tc+=pc; tp+=tot
    if tot>50000:
        print(f"{b:>6} {tot:>12,} {len(ex):>7} {len(ch):>8} {100*pe/tot:>11.1f}% {100*pc/tot:>13.1f}%")
print(f"\nALL KMS2: {tp:,} packets | exact {100*te/tp:.1f}% | KMS2-lineage chained {100*tc/tp:.1f}%")

# and if we WERE to (wrongly) add V12
tv=0
for b in sniff_builds:
    ch=set()
    for v in [x for x in kms_dirs if x<=b]: ch|=avail[v]
    ch|=avail[12]
    tv+=sum(n for k,n in traffic[b].items() if k in ch)
print(f"          (+V12 fallthrough would 'cover' {100*tv/tp:.1f}% -- but see stability data: cross-lineage is unsafe)")

# V12 corpus for comparison
v12t=traffic[12]; tot12=sum(v12t.values())
cov12=sum(n for k,n in v12t.items() if k in avail[12])
print(f"\nGMS2 V12: {tot12:,} packets | {len(avail[12])} scripts | {100*cov12/tot12:.1f}% of traffic has a decoder")

# how many KMS2 opcodes have NO script anywhere in KMS2 lineage
allk=set()
for v in kms_dirs: allk|=avail[v]
kall=set()
for b in sniff_builds: kall|=set(traffic[b])
print(f"\nKMS2 distinct (op,dir) seen in sniffs : {len(kall)}")
print(f"KMS2 (op,dir) with a script anywhere  : {len(kall&allk)}")
print(f"KMS2 (op,dir) with NO script at all   : {len(kall-allk)}")

import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
import os, pickle, collections
SP=_HERE
SR=r"D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0"
rec=pickle.load(open(SP+r"\rec.pkl","rb"))
per=collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
for (b,op,ob),c in rec.items(): per[b][(op,ob)].update(c)

def ops(v):
    s=set()
    for d in ("Inbound","Outbound"):
        p=os.path.join(SR,str(v),d)
        if os.path.isdir(p):
            for f in os.listdir(p):
                if f.endswith(".py"): s.add((int(f[2:6],16), d=="Outbound"))
    return s
vers=sorted([int(d) for d in os.listdir(SR) if d.isdigit()])
avail={v:ops(v) for v in vers}
kms_dirs=sorted([b for b in avail if b!=12])

# FINDING 1: which scripts actually carry the 2546 coverage, and do lengths match?
T=per[2546]; tot=sum(sum(c.values()) for c in T.values())
def source(b,k):
    for v in sorted([x for x in kms_dirs if x<=b], reverse=True):
        if k in avail[v]: return v
    return None
rows=[]
for k,c in T.items():
    s=source(2546,k)
    if s is None: continue
    n=sum(c.values())
    rows.append((n,k,s))
rows.sort(reverse=True)
cov=sum(n for n,_,_ in rows)
print(f"2546 total packets: {tot:,}   'covered' by chaining: {cov:,} ({100*cov/tot:.1f}%)\n")
print("top contributors to the 78.8% claim:")
print(f"{'opcode':>8} {'dir':>4} {'src':>5} {'pkts':>10} {'%all':>6} {'%cov':>6}  {'src lengths':>22} -> {'2546 lengths'}")
cum=0
for n,k,s in rows[:8]:
    op,ob=k
    sl=per[s][k]; tl=T[k]
    cum+=n
    f=lambda c: ("{"+",".join(str(x) for x in sorted(c)[:4])+("..." if len(c)>4 else "")+"}") if c else "{-}"
    print(f"  0x{op:04X} {'OUT' if ob else 'IN':>4} {s:>5} {n:>10,} {100*n/tot:>5.1f}% {100*n/cov:>5.1f}%  {f(sl):>22} -> {f(tl)}")
print(f"\ntop 8 = {100*cum/tot:.1f}% of all 2546 traffic, {100*cum/cov:.1f}% of the 'covered' set")

# how many of the covered opcodes are in the fixed-length population?
def fx(c): return len(c)==1
both_fixed=same=diff=0
for n,k,s in rows:
    if fx(per[s][k]) and fx(T[k]):
        both_fixed+=1
        if next(iter(per[s][k]))==next(iter(T[k])): same+=1
        else: diff+=1
print(f"\nof {len(rows)} chained opcodes for 2546: {both_fixed} are fixed-len in BOTH src+target ({same} same, {diff} diff)")
w_fixed=sum(n for n,k,s in rows if fx(per[s][k]) and fx(T[k]))
print(f"traffic weight of that fixed-len population: {100*w_fixed/tot:.1f}% of 2546 traffic")
print("=> the 97.7% fixed-length statistic speaks for only this slice; the rest is unevidenced")

# FINDING 2: did kdrift filter builds?
print("\n--- FINDING 2: adjacency check ---")
allk=sorted([b for b in per if b>=2000])
big=[b for b in allk if sum(sum(c.values()) for c in per[b].values())>20000]
print(f"all KMS2 builds in sniffs: {len(allk)}")
print(f"builds kept by >20k filter: {len(big)}  -> {len(big)-1} 'adjacent' transitions")
print(f"builds EXCLUDED: {len(allk)-len(big)}")
skipped=[(a,b,[x for x in allk if a<x<b]) for a,b in zip(big,big[1:]) if [x for x in allk if a<x<b]]
print(f"transitions labelled 'adjacent' that actually skip builds: {len(skipped)} / {len(big)-1}")
for a,b,sk in skipped[:6]: print(f"   {a}->{b} skips {sk}")

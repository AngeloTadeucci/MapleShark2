import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
import pickle, collections
rec=pickle.load(open(_os.path.join(_HERE,"rec.pkl"),"rb"))
per=collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
for (b,op,ob),c in rec.items(): per[b][(op,ob)].update(c)
builds=sorted([b for b in per if b>=2000])

def cmp2(A,B,MIN=5):
    both=[k for k in A if k in B and sum(A[k].values())>=MIN and sum(B[k].values())>=MIN]
    same=diff=0
    for k in both:
        a,b=A[k],B[k]
        if len(a)==1 and len(b)==1:
            if next(iter(a))==next(iter(b)): same+=1
            else: diff+=1
    return same,diff,len(both)

print("=== adjacent KMS2 builds: fixed-length opcode agreement ===")
print(f"{'pair':>14} {'fixed-both':>11} {'same':>6} {'diff':>6} {'stable%':>8}")
agg_s=agg_d=0
big=[b for b in builds if sum(sum(c.values()) for c in per[b].values())>20000]
for a,b in zip(big,big[1:]):
    s,d,n=cmp2(per[a],per[b])
    agg_s+=s; agg_d+=d
    pct = f"{100*s/(s+d):.0f}%" if s+d else "-"
    print(f"{a}->{b:<6} {s+d:>11} {s:>6} {d:>6} {pct:>8}")
print(f"\nadjacent-KMS2 aggregate: {agg_s} same, {agg_d} diff -> {100*agg_s/max(agg_s+agg_d,1):.1f}% stable")

# widest KMS2 span
s,d,n=cmp2(per[builds[0]],per[builds[-1]])
print(f"\nwidest KMS2 span {builds[0]}->{builds[-1]}: {s} same, {d} diff -> {100*s/max(s+d,1):.0f}% stable")

# 2546 (biggest archive) vs V12 and vs neighbours
v12=collections.defaultdict(collections.Counter)
for (bb,op,ob),c in rec.items():
    if bb==12: v12[(op,ob)].update(c)
for other,label in [(v12,"V12 (GMS2)"),(per[2533],"KMS2 2533"),(per[2549],"KMS2 2549")]:
    s,d,n=cmp2(per[2546],other)
    print(f"  2546 vs {label:12s}: {s:3d} same, {d:3d} diff -> {100*s/max(s+d,1):3.0f}% stable  (fixed-both n={s+d})")

# opcode set overlap
def ops(x): return set(x)
print("\n=== opcode-set overlap (any packet count) ===")
for other,label in [(v12,"V12 (GMS2)"),(per[2533],"KMS2 2533"),(per[2549],"KMS2 2549"),(per[2486],"KMS2 2486")]:
    A,B=ops(per[2546]),ops(other)
    print(f"  2546 ∩ {label:12s}: {len(A&B):3d} shared, {len(A-B):3d} only-2546, {len(B-A):3d} only-other  (jaccard {len(A&B)/len(A|B):.2f})")

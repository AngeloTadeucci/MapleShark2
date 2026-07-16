import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
import pickle, collections
rec=pickle.load(open(_os.path.join(_HERE,"rec.pkl"),"rb"))
v12=collections.defaultdict(collections.Counter); kms=collections.defaultdict(collections.Counter)
for (b,op,ob),c in rec.items():
    (v12 if b==12 else kms)[(op,ob)].update(c)

MIN=5
both=[k for k in v12 if k in kms and sum(v12[k].values())>=MIN and sum(kms[k].values())>=MIN]
print(f"(op,dir) in both with >={MIN} packets each: {len(both)}\n")

def fixed(c): return len(c)==1
cls=collections.Counter(); rows=[]
for k in both:
    a,b=v12[k],kms[k]
    fa,fb=fixed(a),fixed(b)
    if fa and fb:
        if next(iter(a))==next(iter(b)): c="FIXED_SAME"
        else: c="FIXED_DIFF"
    elif fa!=fb: c="SHAPE_DIFF"     # fixed in one, variable in other
    else:
        # both variable: compare size support overlap (Jaccard) + median
        sa,sb=set(a),set(b)
        j=len(sa&sb)/len(sa|sb)
        c="VAR_OVERLAP" if j>=0.5 else ("VAR_PARTIAL" if j>=0.1 else "VAR_DISJOINT")
    cls[c]+=1; rows.append((k,c,a,b))

print("=== classification of shared opcodes (V12 vs KMS2 length profile) ===")
for c,n in cls.most_common(): print(f"  {c:14s} {n:4d}  ({100*n/len(both):.0f}%)")

print("\n=== FIXED-LENGTH opcodes: the cleanest signal ===")
fs=[r for r in rows if r[1]=="FIXED_SAME"]; fd=[r for r in rows if r[1]=="FIXED_DIFF"]
print(f"  fixed in BOTH corpora: {len(fs)+len(fd)}")
print(f"    same length : {len(fs)}  ({100*len(fs)/max(len(fs)+len(fd),1):.0f}%)  -> structure almost certainly UNCHANGED")
print(f"    diff length : {len(fd)}  ({100*len(fd)/max(len(fs)+len(fd),1):.0f}%)  -> structure DEFINITELY CHANGED")
print("\n  examples of FIXED_DIFF (V12 len -> KMS2 len):")
for (op,ob),c,a,b in sorted(fd,key=lambda r:-sum(r[3].values()))[:14]:
    print(f"    0x{op:04X} {'OUT' if ob else 'IN ':3s}  {next(iter(a)):5d} -> {next(iter(b)):<5d}  (kms n={sum(b.values()):,})")
print("\n  examples of FIXED_SAME:")
for (op,ob),c,a,b in sorted(fs,key=lambda r:-sum(r[3].values()))[:8]:
    print(f"    0x{op:04X} {'OUT' if ob else 'IN ':3s}  {next(iter(a)):5d} == {next(iter(b)):<5d}  (kms n={sum(b.values()):,})")

# weight by traffic: what fraction of KMS2 packets belong to opcodes we'd get right?
w_same=sum(sum(b.values()) for (k,c,a,b) in rows if c in("FIXED_SAME","VAR_OVERLAP"))
w_diff=sum(sum(b.values()) for (k,c,a,b) in rows if c in("FIXED_DIFF","SHAPE_DIFF","VAR_DISJOINT"))
w_part=sum(sum(b.values()) for (k,c,a,b) in rows if c=="VAR_PARTIAL")
kms_only=sum(sum(kms[k].values()) for k in kms if k not in v12)
tot=sum(sum(c.values()) for c in kms.values())
print(f"\n=== KMS2 traffic weighted by whether a V12 decoder would plausibly work ===")
print(f"  likely OK        : {w_same:>10,}  ({100*w_same/tot:.1f}%)")
print(f"  partial/unsure   : {w_part:>10,}  ({100*w_part/tot:.1f}%)")
print(f"  definitely WRONG : {w_diff:>10,}  ({100*w_diff/tot:.1f}%)")
print(f"  no V12 decoder   : {kms_only:>10,}  ({100*kms_only/tot:.1f}%)")

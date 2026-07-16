import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
import csv, sys
rows=list(csv.DictReader(open(_os.path.join(_HERE,"..","baseline","chain-2546.csv"))))
tot=sum(int(r["seen"]) for r in rows)
# extrapolate each opcode's sampled outcome rates to its true traffic
acc={"clean":0.0,"under":0.0,"over":0.0,"threw":0.0,"noscript":0.0}
for r in rows:
    seen=int(r["seen"]); ran=int(r["ran"])
    if ran==0:
        acc["noscript"]+=seen; continue
    for k,col in (("clean","ok_exact"),("under","under_read"),("over","over_read"),("threw","threw")):
        acc[k]+= seen*(int(r[col])/ran)
print(f"build 2546 — traffic-weighted, chained (total {tot:,} packets)\n")
for k in ("noscript","clean","under","over","threw"):
    print(f"  {k:9s} {acc[k]:12,.0f}   {100*acc[k]/tot:5.1f}%")
ran_w=tot-acc["noscript"]
print(f"\n  a script ran on {ran_w:,.0f} packets ({100*ran_w/tot:.1f}% of traffic)  <- comparable to my '78.8% coverage'")
print(f"  of those:  clean {100*acc['clean']/ran_w:.1f}%   over-read {100*acc['over']/ran_w:.1f}%   under-read {100*acc['under']/ran_w:.1f}%")
print(f"\n  CLEAN as share of ALL 2546 traffic: {100*acc['clean']/tot:.1f}%")
print(f"  OVER-READ as share of ALL traffic  : {100*acc['over']/tot:.1f}%  ({acc['over']:,.0f} packets)")

print("\n--- biggest under-read / over-read contributors (traffic-weighted) ---")
bad=[]
for r in rows:
    seen=int(r["seen"]); ran=int(r["ran"])
    if ran==0: continue
    u=seen*(int(r["under_read"])/ran); o=seen*(int(r["over_read"])/ran)
    if u+o>1000: bad.append((u+o,r["opcode"],r["direction"],r["source_build"],u,o,r["consumed_p50"]))
for t,op,d,src,u,o,p50 in sorted(bad,reverse=True)[:8]:
    print(f"  {op} {d:3s} src={src:5s} under={u:10,.0f} over={o:9,.0f}  consumed_p50={p50}%")

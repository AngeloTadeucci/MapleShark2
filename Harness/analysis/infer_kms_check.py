"""Phase 5 KMS2 reality check: how many undocumented KMS2 (op,dir) pairs have enough
samples for corpus inference, given the method's measured sample hunger? Reads rec.pkl.
Stdlib only."""
import pickle, os, collections

HERE = os.path.dirname(os.path.abspath(__file__))
rec = pickle.load(open(os.path.join(HERE, "rec.pkl"), "rb"))
OCHI = r"D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0"

# documented (op,dir) across ALL KMS2 build dirs (>=2000). dir: Inbound=IN(ob0), Outbound=OUT(ob1)
documented = set()
for d in os.listdir(OCHI):
    if not d.isdigit(): continue
    b = int(d)
    if b < 2000: continue
    for sub, ob in (("Inbound", 0), ("Outbound", 1)):
        p = os.path.join(OCHI, d, sub)
        if os.path.isdir(p):
            for f in os.listdir(p):
                if f.endswith(".py") and f.startswith("0x"):
                    try: documented.add((int(f[2:6], 16), ob))
                    except: pass

# aggregate KMS2 traffic per (op,dir): total packets + merged length histogram
kms = collections.defaultdict(collections.Counter)
for (bd, op, ob), c in rec.items():
    if bd >= 2000:
        kms[(op, 1 if ob else 0)].update(c)

pairs = {k: sum(v.values()) for k, v in kms.items()}
undoc = {k: n for k, n in pairs.items() if k not in documented}

def nlens(k): return len(kms[k])
def maxlen_const(k): return nlens(k) <= 2   # fixed-length family

import statistics
ns = sorted(undoc.values())
print(f"KMS2 distinct (op,dir) pairs      : {len(pairs)}")
print(f"  documented (script exists)      : {len(pairs) - len(undoc)}")
print(f"  UNDOCUMENTED                    : {len(undoc)}")
print(f"  median samples (undoc)          : {statistics.median(ns)}")
print(f"  undoc pairs <=5 samples         : {sum(1 for n in ns if n<=5)}")
print(f"  undoc pairs <=100 samples       : {sum(1 for n in ns if n<=100)}")
tot_undoc_traffic = sum(undoc.values())
print(f"  total undoc traffic (packets)   : {tot_undoc_traffic:,}")

# top-10 traffic share among undoc
top = sorted(undoc.items(), key=lambda x: -x[1])[:10]
print(f"  top-10 undoc share of undoc traf: {sum(n for _,n in top)/tot_undoc_traffic*100:.1f}%")

# ---- method sample-floor model (derived from the V12 blind experiment) ----
# fixed-length family (<=2 lengths): trivially inferable at low n.
# variable single-structure: needs enough to expose string/array length variation.
# mode-dispatched: needs samples PER mode; a p-frequency mode needs ~F/p total.
FIXED_FLOOR = 30      # confirm a constant length
VAR_FLOOR   = 300     # expose variable structure with confidence (matches PLAN's 300 floor)

def tier(k):
    n = undoc[k]
    if maxlen_const(k):
        return "fixed" if n >= FIXED_FLOOR else "fixed-thin"
    else:
        return "var" if n >= VAR_FLOOR else "var-thin"

buckets = collections.Counter(tier(k) for k in undoc)
traf = collections.Counter()
for k in undoc: traf[tier(k)] += undoc[k]

print("\n--- inferability tiers (undocumented pairs) ---")
print(f"{'tier':<12}{'pairs':>7}{'%pairs':>8}{'traffic':>14}{'%traffic':>10}")
order = ["fixed","var","fixed-thin","var-thin"]
for t in order:
    print(f"{t:<12}{buckets[t]:>7}{buckets[t]/len(undoc)*100:>7.1f}%"
          f"{traf[t]:>14,}{traf[t]/tot_undoc_traffic*100:>9.1f}%")

inferable_pairs = buckets["fixed"] + buckets["var"]
inferable_traf  = traf["fixed"] + traf["var"]
print(f"\nREALISTICALLY INFERABLE (meets floor): {inferable_pairs}/{len(undoc)} pairs "
      f"({inferable_pairs/len(undoc)*100:.1f}%)  |  traffic {inferable_traf/tot_undoc_traffic*100:.1f}%")
print("NOTE: 'inferable' = enough samples to ATTEMPT structure; from the V12 gate, even")
print("      at-floor variable/mode opcodes recover consumption but NOT correct fine structure.")

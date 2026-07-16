import os, collections
ROOT = r"D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0"
vers = sorted([d for d in os.listdir(ROOT) if d.isdigit()], key=int)
kms = [v for v in vers if v != "12"]

def ops(v):
    s=set()
    for d in ("Inbound","Outbound"):
        p=os.path.join(ROOT,v,d)
        if os.path.isdir(p):
            s|={(d,f) for f in os.listdir(p) if f.endswith(".py")}
    return s

v12 = ops("12")
kms_all = set()
for v in kms: kms_all |= ops(v)

print(f"V12 (GMS2) opcodes with scripts : {len(v12)}")
print(f"KMS2 opcodes with scripts (any build): {len(kms_all)}")
ovl = kms_all & v12
new = kms_all - v12
print(f"\n  KMS2 opcodes that ALSO exist in V12 (=> overrides): {len(ovl)}  ({100*len(ovl)/max(len(kms_all),1):.0f}%)")
print(f"  KMS2 opcodes NOT in V12          (=> new/moved)  : {len(new)}  ({100*len(new)/max(len(kms_all),1):.0f}%)")
if new: print(f"    new: {sorted(x[1] for x in new)[:20]}")

print("\n=== coverage a KMS2 sniff gets TODAY (exact-match only) vs WITH fallback-to-V12 ===")
import struct
# sniff build -> file count (from earlier scan)
sniffs = {2464:1,2465:1,2486:48,2489:9,2490:3,2491:1,2492:7,2493:3,2495:9,2496:7,2497:2,2500:1,
          2502:31,2503:22,2504:9,2506:23,2507:66,2509:1,2511:11,2512:52,2513:3,2514:1,2516:7,
          2517:1,2518:3,2520:5,2521:15,2522:3,2524:8,2525:5,2527:1,2528:2,2529:22,2530:3,2531:2,
          2532:3,2533:7,2538:1,2546:233,2549:17,2550:4}
avail = {int(v): ops(v) for v in vers}
print(f"{'build':>6} {'sniffs':>7} {'exact':>7} {'+fallback':>10}")
tot_ex = tot_fb = tot_f = 0
for b in sorted(sniffs):
    ex = len(avail.get(b,set()))
    # walk down to nearest lower build dir, then V12
    fb = set()
    for v in sorted([x for x in avail if x<=b and x!=12], reverse=True): fb |= avail[v]
    fb |= v12
    tot_ex += ex*sniffs[b]; tot_fb += len(fb)*sniffs[b]; tot_f += sniffs[b]
    print(f"{b:>6} {sniffs[b]:>7} {ex:>7} {len(fb):>10}")
print(f"\nweighted avg decoders available per KMS2 sniff: exact={tot_ex/tot_f:.1f}  fallback={tot_fb/tot_f:.1f}")

import os, hashlib, collections

ROOT = r"D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0"
vers = sorted([d for d in os.listdir(ROOT) if d.isdigit()], key=int)

def h(p):
    with open(p,'rb') as f: return hashlib.sha1(f.read()).hexdigest()

# (direction, opcode) -> {version: hash}
table = collections.defaultdict(dict)
percount = {}
for v in vers:
    n = 0
    for direction in ("Inbound","Outbound"):
        d = os.path.join(ROOT, v, direction)
        if not os.path.isdir(d): continue
        for fn in os.listdir(d):
            if not fn.endswith(".py"): continue
            table[(direction, fn)][v] = h(os.path.join(d, fn))
            n += 1
    percount[v] = n

print("=== scripts per version dir ===")
for v in vers: print(f"  build {v:>5}: {percount[v]:4d} scripts")
print(f"\ntotal script files on disk: {sum(percount.values())}")
print(f"distinct (direction,opcode) keys: {len(table)}")

kms = [v for v in vers if v != "12"]
print(f"\n=== KMS2 only ({len(kms)} builds: {kms[0]}..{kms[-1]}) ===")
tot = distinct = 0
for k, m in table.items():
    hs = [m[v] for v in kms if v in m]
    if not hs: continue
    tot += len(hs); distinct += len(set(hs))
print(f"KMS2 script file instances : {tot}")
print(f"distinct contents          : {distinct}")
print(f"redundancy                 : {100*(1-distinct/tot):.1f}% of files are byte-identical dupes")

print("\n=== churn between adjacent KMS2 builds ===")
for a, b in zip(kms, kms[1:]):
    same = ch = add = rem = 0
    for k, m in table.items():
        x, y = m.get(a), m.get(b)
        if x and y: (same := same) if x==y else None
        if x and y:
            if x==y: same+=1
            else: ch+=1
        elif y and not x: add+=1
        elif x and not y: rem+=1
    print(f"  {a} -> {b}: {same:4d} identical, {ch:3d} changed, {add:3d} added, {rem:3d} removed")

# how many opcodes EVER change across KMS2
never = sum(1 for k,m in table.items() if len({m[v] for v in kms if v in m})==1 and any(v in m for v in kms))
ever  = sum(1 for k,m in table.items() if len({m[v] for v in kms if v in m})>1)
print(f"\nopcodes with ONE content across all KMS2 builds : {never}")
print(f"opcodes that ever differ across KMS2 builds     : {ever}")

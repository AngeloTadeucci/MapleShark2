"""Phase 5 feasibility: BLIND structure inference from bytes alone.

Reads payloads.pkl (build-12 target payloads), infers a decoder structure per
(op,dir) WITHOUT reading any real script, and emits MapleShark IronPython scripts
plus a JSON description of the inferred read sequence (for structural scoring).

Method (per docs/CAMPAIGN.md Phase 5):
  1. Cluster by first-byte mode (only if first byte behaves like a dispatcher) and
     length family.
  2. Within a cluster, a position-synchronised consensus walk over all samples:
     detect ushort-length-prefixed UTF-16 / ASCII strings, count-prefixed
     fixed-stride arrays, else fixed-width fields sliced by per-offset stats.
  3. Self-validate: score candidate global configs by exact-consumption fraction
     on the held-in samples; emit the winner. (Consumption-correct != semantically
     correct -- that gap is measured separately by structural scoring.)

Stdlib only. Run: py infer.py
"""
import os, struct, pickle, collections, json, statistics

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOADS = os.path.join(HERE, "..", "..", "scratch_phase5", "payloads.pkl")
OUTROOT = os.path.join(HERE, "..", "..", "scratch_phase5", "inferred")

U16 = lambda b, o: b[o] | (b[o+1] << 8)

# ------------------------------------------------------------------ detectors

def utf16_score(payload, o, L):
    """Fraction of the L chars that look like ASCII-in-UTF16LE (hi byte 0, lo printable)."""
    if L == 0:
        return 1.0
    end = o + 2 + 2*L
    if end > len(payload):
        return -1.0
    ok = 0
    for i in range(L):
        lo = payload[o+2+2*i]; hi = payload[o+3+2*i]
        if hi == 0 and (0x20 <= lo <= 0x7E):
            ok += 1
        elif hi <= 0x02:      # allow latin-1 / accented / small codepoints
            ok += 0.5
    return ok / L

def ascii_score(payload, o, L):
    if L == 0:
        return 1.0
    end = o + 2 + L
    if end > len(payload):
        return -1.0
    ok = 0
    for i in range(L):
        c = payload[o+2+i]
        if 0x20 <= c <= 0x7E:
            ok += 1
    return ok / L

def try_string(samples, pos, active):
    """Return ('uni'|'asc', kind_stats) if a length-prefixed string starts at pos
    across active samples, else None."""
    n = len(active)
    if n == 0:
        return None
    uni_ok = asc_ok = 0
    uni_nonempty = asc_nonempty = 0
    uni_content = asc_content = 0.0
    for i in active:
        p = samples[i]; o = pos[i]
        if o + 2 > len(p):
            return None
        L = U16(p, o)
        if L > 4000:
            uni = asc = -1.0
        else:
            uni = utf16_score(p, o, L)
            asc = ascii_score(p, o, L)
        if uni >= 0.9:
            uni_ok += 1
            if L > 0:
                uni_nonempty += 1; uni_content += uni
        if asc >= 0.9:
            asc_ok += 1
            if L > 0:
                asc_nonempty += 1; asc_content += asc
    uni_frac = uni_ok / n
    asc_frac = asc_ok / n
    # require near-universal validity AND that it isn't just an all-zero u16 field
    UNI = uni_frac >= 0.985 and uni_nonempty >= max(2, 0.15*n)
    ASC = asc_frac >= 0.985 and asc_nonempty >= max(2, 0.15*n)
    if UNI and ASC:
        # both structurally valid; prefer the one whose non-empty content scores higher
        cu = uni_content/max(1,uni_nonempty); ca = asc_content/max(1,asc_nonempty)
        return ('uni' if cu >= ca else 'asc',)
    if UNI:
        return ('uni',)
    if ASC:
        return ('asc',)
    return None

def try_array(samples, pos, active):
    """count-prefixed fixed-stride array: a small count C at pos followed by C*stride
    bytes that exactly consume the rest (tail may hold trailing fixed fields, so we
    only fire when it explains ALL remaining bytes). Conservative."""
    n = len(active)
    if n < 20:
        return None
    for cw, rd in ((1,'byte'),(2,'ushort'),(4,'int')):
        strides = collections.Counter()
        good = 0
        varied = set()
        for i in active:
            p = samples[i]; o = pos[i]
            if o + cw > len(p):
                good = -1; break
            C = int.from_bytes(p[o:o+cw],'little')
            rem = len(p) - (o+cw)
            varied.add(C)
            if C == 0:
                if rem == 0:
                    good += 1
                continue
            if 0 < C <= 4096 and rem % C == 0 and rem // C <= 512:
                strides[rem // C] += 1
                good += 1
        if good <= 0:
            continue
        if not strides:
            continue
        stride, sc = strides.most_common(1)[0]
        # need: consistent stride, count actually varies, and it explains ~all samples
        if sc / n >= 0.9 and len(varied) >= 3 and stride >= 1:
            return (rd, cw, stride)
    return None

# ------------------------------------------------------------- fixed-run slice

def slice_fixed_run(samples, starts, active, run_len):
    """Slice a fixed-width run of run_len bytes into primitives via per-offset stats.
    Returns list of (kind, width). Behavioural consumption is width-invariant; this is
    for structural naming only."""
    fields = []
    off = 0
    # gather column bytes
    def col(k):
        return [samples[i][starts[i]+k] for i in active
                if 0 <= starts[i]+k < len(samples[i])]
    def as_float(k):
        vals = []
        for i in active:
            s = starts[i]+k
            if s >= 0 and s+4 <= len(samples[i]):
                (f,) = struct.unpack_from('<f', samples[i], s)
                vals.append(f)
        return vals
    while off < run_len:
        rem = run_len - off
        # float32: 4 plausible bytes, values vary and are in coordinate-ish range
        if rem >= 4:
            fv = as_float(off)
            if fv:
                plausible = sum(1 for f in fv if f==f and abs(f) < 1e12 and (f==0.0 or 1e-12 < abs(f)))
                distinct = len(set(round(f,3) for f in fv))
                nonint = sum(1 for f in fv if f==f and f != int(f) if abs(f)<1e12)
                if plausible/len(fv) >= 0.97 and distinct > 3 and nonint/len(fv) >= 0.3:
                    fields.append(('float',4)); off += 4; continue
        # constant byte -> keep as byte
        c = col(off)
        if c and len(set(c)) == 1:
            fields.append(('byte',1)); off += 1; continue
        # default chunking: 4->int, else 2->short, else byte
        if rem >= 4:
            fields.append(('int',4)); off += 4
        elif rem >= 2:
            fields.append(('short',2)); off += 2
        else:
            fields.append(('byte',1)); off += 1
    return fields

# ------------------------------------------------------------- consensus walk

MAXDEPTH = 3

def walk(samples, start_off, max_steps=4000, depth=0):
    """Position-synchronised consensus walk. Returns (fields, exact_frac) where fields
    is a list of directives and exact_frac is the fraction of samples consumed exactly."""
    n = len(samples)
    pos = [start_off]*n
    fields = []
    fixed_run_start = [start_off]*n
    pending_fixed = [0]*n   # bytes accumulated in current fixed run, per sample (kept uniform)
    run_len = 0
    steps = 0

    def flush_fixed(active):
        nonlocal run_len
        if run_len > 0:
            starts = [pos[i]-run_len for i in range(n)]
            fs = slice_fixed_run(samples, starts, active, run_len)
            for kind, w in fs:
                fields.append({'op': kind})
            run_len = 0

    while steps < max_steps:
        steps += 1
        active = [i for i in range(n) if pos[i] < len(samples[i])]
        done = [i for i in range(n) if pos[i] == len(samples[i])]
        over = [i for i in range(n) if pos[i] > len(samples[i])]
        if not active:
            break
        # if a meaningful fraction has finished while others continue -> optional tail
        frac_done = len(done) / n
        if frac_done >= 0.02 and len(active) < n:
            flush_fixed(active + done)
            # remaining structure exists only for 'active'; wrap subsequent reads in a
            # remaining()-guard by recursing on the active subset from their positions.
            # Cap recursion depth: MS2 heavy packets nest arbitrarily and unbounded
            # nesting produces scripts IronPython's parser rejects. Past the cap we stop
            # and leave the tail as a safe under-read rather than guessing deeper.
            if depth < MAXDEPTH:
                sub = [samples[i][pos[i]:] for i in active]
                subfields, _ = walk(sub, 0, max_steps - steps, depth+1)
                if subfields:
                    fields.append({'op':'guard_begin'})
                    fields.extend(subfields)
                    fields.append({'op':'guard_end'})
            break

        s = try_string(samples, pos, active)
        if s is not None:
            flush_fixed(active)
            if s[0] == 'uni':
                fields.append({'op':'ustr'})
                for i in active:
                    L = U16(samples[i], pos[i]); pos[i] += 2 + 2*L
            else:
                fields.append({'op':'astr'})
                for i in active:
                    L = U16(samples[i], pos[i]); pos[i] += 2 + L
            continue

        a = try_array(samples, pos, active)
        if a is not None:
            flush_fixed(active)
            rd, cw, stride = a
            fields.append({'op':'array','count':rd,'cw':cw,'stride':stride})
            for i in active:
                C = int.from_bytes(samples[i][pos[i]:pos[i]+cw],'little')
                pos[i] += cw + C*stride
            continue

        # fixed byte
        run_len += 1
        for i in active:
            pos[i] += 1

    active_all = list(range(n))
    flush_fixed(active_all)
    exact = sum(1 for i in range(n) if pos[i] == len(samples[i])) / n
    over = sum(1 for i in range(n) if pos[i] > len(samples[i])) / n
    return fields, (exact, over)

# ------------------------------------------------------------- mode dispatch

def is_mode_byte(samples):
    """First byte is a dispatcher if it has low cardinality and different values imply
    different length distributions."""
    if not samples:
        return False, {}
    b0 = collections.Counter(p[0] for p in samples if len(p) >= 1)
    if not b0:
        return False, {}
    card = len(b0)
    if card > 24:
        return False, b0
    # length spread per mode
    per = collections.defaultdict(collections.Counter)
    for p in samples:
        if len(p) >= 1:
            per[p[0]][len(p)] += 1
    # overall distinct lengths
    allcard = len(set(len(p) for p in samples))
    if allcard <= 2:
        return False, b0            # fixed layout, first byte is a normal field
    # do modes carve the length distribution? compare mean length across common modes
    means = {}
    for m, c in per.items():
        tot = sum(c.values())
        if tot >= max(5, 0.01*len(samples)):
            means[m] = sum(l*k for l,k in c.items())/tot
    if len(means) >= 2:
        spread = max(means.values()) - min(means.values())
        if spread >= 2 and card >= 2:
            return True, b0
    return False, b0

# ------------------------------------------------------------------ emit

def emit_field(op, idx):
    m = {'byte':'add_byte','short':'add_short','int':'add_int','long':'add_long',
         'float':'add_float','ustr':'add_unicode_str','astr':'add_str'}
    if op in m:
        return f'{m[op]}("{op}_{idx}")'
    return None

def render(fields, indent):
    lines = []
    idx = [0]
    pad = '    '*indent
    def rec(fs, indent):
        pad = '    '*indent
        for f in fs:
            op = f['op']
            if op == 'array':
                cnt = {'byte':'add_byte','ushort':'add_ushort','int':'add_int'}[f['count']]
                lines.append(f'{pad}c_{idx[0]} = {cnt}("count_{idx[0]}")')
                lines.append(f'{pad}for _i in range(c_{idx[0]}):')
                st = f['stride']
                # emit stride as int/short/byte chunks
                inner = '    '*(indent+1)
                r = st
                while r >= 4:
                    lines.append(f'{inner}add_int("elem_{idx[0]}")'); r -= 4
                while r >= 2:
                    lines.append(f'{inner}add_short("elem_{idx[0]}")'); r -= 2
                while r >= 1:
                    lines.append(f'{inner}add_byte("elem_{idx[0]}")'); r -= 1
                if st == 0:
                    lines.append(f'{inner}pass')
                idx[0]+=1
            elif op == 'guard_begin':
                lines.append(f'{pad}if remaining() > 0:')
                return_marker.append(indent)
            elif op == 'guard_end':
                pass
            else:
                e = emit_field(op, idx[0]); idx[0]+=1
                if e:
                    lines.append(f'{pad}{e}')
    # handle guard nesting simply: process linearly, bumping indent between guard_begin/end
    return_marker=[]
    cur = indent
    for f in fields:
        op=f['op']
        pad='    '*cur
        if op=='guard_begin':
            lines.append(f'{pad}if remaining() > 0:')
            cur+=1; continue
        if op=='guard_end':
            cur=max(indent,cur-1); continue
        if op=='array':
            cnt={'byte':'add_byte','ushort':'add_ushort','int':'add_int'}[f['count']]
            lines.append(f'{pad}c_{idx[0]} = {cnt}("count_{idx[0]}")')
            lines.append(f'{pad}for _i in range(c_{idx[0]}):')
            st=f['stride']; inner='    '*(cur+1); r=st
            if st==0:
                lines.append(f'{inner}pass')
            while r>=4:
                lines.append(f'{inner}add_int("elem_{idx[0]}")'); r-=4
            while r>=2:
                lines.append(f'{inner}add_short("elem_{idx[0]}")'); r-=2
            while r>=1:
                lines.append(f'{inner}add_byte("elem_{idx[0]}")'); r-=1
            idx[0]+=1
        else:
            e=emit_field(op, idx[0]); idx[0]+=1
            if e: lines.append(f'{pad}{e}')
    if not lines:
        lines.append('    '*indent+'pass')
    return lines

def infer_one(op, ob, samples):
    dirname = 'Inbound' if ob==0 else 'Outbound'
    is_mode, b0 = is_mode_byte(samples)
    # candidate A: no dispatch, single walk
    fA, (exA, ovA) = walk(samples, 0)
    result = {'opcode':op,'dir':dirname,'n':len(samples)}
    best = None
    if is_mode:
        # candidate B: dispatch on first byte for common modes
        modes = [m for m,c in b0.most_common() if c >= max(5,0.01*len(samples))]
        branches = {}
        cov = 0; exact_tot = 0
        for m in modes:
            sub = [p for p in samples if len(p)>=1 and p[0]==m]
            # walk after consuming the mode byte
            fb, (exb, ovb) = walk([p[1:] for p in sub], 0)
            branches[m] = {'fields':fb,'n':len(sub),'exact':exb,'over':ovb}
            cov += len(sub); exact_tot += exb*len(sub)
        exB = exact_tot/max(1,len(samples))
        result['mode']=True
        result['branches']={hex(m):branches[m] for m in branches}
        result['exact_est']=exB
        best = ('mode', branches, modes)
    else:
        result['mode']=False
        result['fields']=fA
        result['exact_est']=exA
        best = ('flat', fA, None)
    # write script
    lines = ["from script_api import *", ""]
    if best[0]=='mode':
        _, branches, modes = best
        lines.append('m = add_byte("mode_0")')
        first=True
        for m in modes:
            kw = 'if' if first else 'elif'; first=False
            lines.append(f'{kw} m == {m}:')
            body = render(branches[m]['fields'], 1)
            lines.extend(body)
        lines.append('else:')
        lines.append('    pass')
    else:
        lines.extend(render(best[1], 0))
    script = "\n".join(lines) + "\n"
    outdir = os.path.join(OUTROOT, "0", "12", dirname)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, f"0x{op:04X}.py"), "w") as f:
        f.write(script)
    return result

def main():
    payloads = pickle.load(open(PAYLOADS,'rb'))
    os.makedirs(OUTROOT, exist_ok=True)
    # copy script_api.py into inferred root so scripts import cleanly
    import shutil
    src_api = r"D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\script_api.py"
    shutil.copy(src_api, os.path.join(OUTROOT, "script_api.py"))
    results = {}
    for (op,ob), samples in sorted(payloads.items()):
        r = infer_one(op, ob, samples)
        results[f"0x{op:04X}_{'IN' if ob==0 else 'OUT'}"] = r
        print(f"0x{op:04X} {'IN ' if ob==0 else 'OUT'}  mode={r['mode']!s:>5}  "
              f"exact_est={r['exact_est']*100:5.1f}%  n={r['n']}")
    json.dump(results, open(os.path.join(HERE,'..','..','scratch_phase5','inferred_desc.json'),'w'), indent=1, default=str)

if __name__ == '__main__':
    main()

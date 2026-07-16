"""Phase 1b value-class invariants (docs/CAMPAIGN.md sec. 5 Phase 1b, sec. 7 "clean != correct").

Scrutinizes ACCEPTED edges (manifest.csv state==accept) for in-bounds wrong parses that Phase 1's
consumption gate cannot see. It compares per-field value BEHAVIOUR between the edge (source script run
on the target build) and home (the same source script run on its own build), using the per-field stats
in baseline/matrix/fields-<target>.csv.

    edge  rows: fields-<target>.csv  where source_build == <source>, target_build == <target>
    home  rows: fields-<source>.csv  where source_build == target_build == <source>

Both sides are produced by the SAME script (the source's opcode .py), so the normalized `field_key`
column joins them directly: same labels, same node paths, digit runs normalized to '#'.

Two families of check (thresholds are calibration-derived — see the CALIBRATION note below):

  Absolute invariants (use the EXACT per-sample min/max columns, not the capped histogram):
    bool_escape    home only ever saw {0,1}; edge has a value outside {0,1}.        severity high
    count_neg      home is a small non-negative int (<= COUNT_SMALL); edge min < 0. severity high
    count_huge     home is a small non-negative int; edge max is absurd (>= COUNT_HUGE).  high
                   (count-like fields feed loops — we can't see the loop, so "small non-negative at
                    home, huge/negative at edge" is the desync signal; docs/CAMPAIGN.md's count=1714880544.)

  Distribution divergence (uses the capped distinct-value histogram, num fields only):
    dist_diverge   total-variation distance between home and edge value distributions.
                   severity high  if tvd >= TVD_HIGH, medium if tvd >= TVD_MED.

TVD is made robust to the capped "~other" bucket by treating '~other' as a single SHARED symbol on
both sides (see tvd_other). Two high-cardinality fields (IDs, timestamps, sequence numbers) each dump
their long disjoint tails into '~other', which then CANCEL rather than reading as maximal divergence —
so the metric only lights up when a CONCENTRATED home distribution (few dominant values) shifts to a
different support at the edge. This choice is what makes the noise floor low enough to gate on; the
alternative (per-value TVD over the union of explicit supports) scores ~0.9 on any high-entropy field
and is uninformative. Justification and the measured noise floor live in the calibration report.

Only fields with n >= FLOOR_N on BOTH sides are compared (below that, sampling noise dominates — see
calibration). Fields present on only one side are not comparable and are skipped (a structural, not
value, difference — that is Phase 1's territory, not Phase 1b's).

Per-edge rollup verdict:
    pass                every compared field within thresholds
    suspect             >= 1 flagged field
    insufficient-fields < MIN_FIELDS_FOR_VERDICT fields had n >= FLOOR_N on both sides

Phase 1b is a FLAG in this iteration: it never changes an accept/reject state (docs/CAMPAIGN.md reserves wiring
it into acceptance for a later decision). manifest.py --invariants joins the rollup verdict as an
advisory column only.

Usage:  py invariants.py [--floor-n 200] [--tvd-high 0.6] [--tvd-med 0.35]
                         [--count-small 4096] [--count-huge 65536]
                         [--min-fields 3] [--out-fields invariants.csv] [--out-edges invariants-edges.csv]
"""
import argparse
import csv
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MATRIX_DIR = HERE.parent / "baseline" / "matrix"

# --- calibration-derived defaults (see analysis report; overridable on the CLI) ---
FLOOR_N = 200            # min n on BOTH sides to compare a field
COUNT_SMALL = 4096       # home max at/below this + min>=0 => treat field as count/length-like
COUNT_HUGE = 65536       # edge max at/above this on a count-like field => absurd
COUNT_NEG = -256         # edge min at/below this on a count-like field => count went negative (desync)
TVD_HIGH = 0.60          # tvd at/above => high-severity divergence (well clear of the noise ceiling)
TVD_MED = 0.50           # tvd at/above => medium-severity divergence
                         # Calibration: on same-build seed pairs (pure sampling noise) at n>=200, tvd
                         # had p99=0.30 and a MAX of 0.48 across 1169 field comparisons — zero reached
                         # 0.50. Both firing tiers sit above that measured ceiling, so a fire is signal,
                         # not sampling luck. The deliberately-corrupted control (a same-width field
                         # swap on concentrated bytes) scored 0.537 and fires; high-entropy swaps score
                         # ~0 and are correctly invisible (the marginals are genuinely unchanged).
MIN_FIELDS_FOR_VERDICT = 3


# ----------------------------- parsing -----------------------------
def parse_values(s):
    """Capped 'v:count|v:count|~other:count' -> {str_value: count}. '-'/empty -> None (no histogram)."""
    if not s or s == "-":
        return None
    out = {}
    for part in s.split("|"):
        v, c = part.rsplit(":", 1)
        out[v] = int(c)
    return out


def to_int(x):
    """min/max columns are integer-valued for int fields; Single fields carry floats and, when a NaN
    value was seen, the literal 'NaN'/'Infinity'. Return None for those — the absolute checks are gated
    to integer/Boolean types and never touch a Single's min/max; dist_diverge uses the histogram, not
    min/max. So None here is harmless and just means 'no exact-range check for this field'."""
    try:
        return int(x)
    except ValueError:
        try:
            f = float(x)
        except ValueError:
            return None
        return int(f) if f == f and abs(f) != float("inf") else None


def load_fields():
    """(source,target,opcode,dir) -> {field_key: {kind,n,min,max,mean,values}} over all fields-*.csv."""
    idx = {}
    for f in sorted(MATRIX_DIR.glob("fields-*.csv")):
        with open(f, newline="") as fh:
            for r in csv.DictReader(fh):
                key = (r["source_build"], r["target_build"], r["opcode"], r["direction"])
                idx.setdefault(key, {})[r["field_key"]] = {
                    "kind": r["kind"],
                    "n": int(r["n"]),
                    "min": to_int(r["min"]),
                    "max": to_int(r["max"]),
                    "mean": float(r["mean"]),
                    "values": parse_values(r["values"]),
                }
    return idx


# ----------------------------- metric -----------------------------
def tvd_other(h, e):
    """Total-variation distance with '~other' treated as one SHARED symbol on both sides.

    h, e are {value_str: count} dicts (each may contain the literal key '~other'). Returns a value in
    [0,1], or None if either side is empty. Robust to the histogram cap: disjoint high-cardinality tails
    land in '~other' on both sides and cancel there instead of reading as maximal divergence.
    """
    if not h or not e:
        return None
    nh = sum(h.values())
    ne = sum(e.values())
    if nh == 0 or ne == 0:
        return None
    keys = set(h) | set(e)
    return 0.5 * sum(abs(h.get(k, 0) / nh - e.get(k, 0) / ne) for k in keys)


def other_frac(h):
    n = sum(h.values()) if h else 0
    return (h.get("~other", 0) / n) if n else 0.0


# ----------------------------- per-field checks -----------------------------
INT_TYPES = {"Byte", "Int16", "Int32", "Int64"}


def field_type(fk):
    """Declared type is the token after the last ':' in the normalized field key (e.g. 'Int16')."""
    return fk.rsplit(":", 1)[-1]


def check_field(fk, hf, ef, cfg):
    """Compare one field's home stats `hf` against edge stats `ef`.

    Returns a list of (check, edge_value, home_value, severity). Empty list == field looks fine.
    Assumes both sides already passed the n floor.

    Absolute checks are gated by the field's DECLARED type, not by coincidental sample range —
    calibration showed that gating on min/max alone fires on Single/Byte/Int64 fields that merely
    sampled {0,1} in one draw (pure noise). bool_escape needs a declared Boolean; count checks need a
    declared integer type (floats are never loop counts).
    """
    flags = []
    hmin, hmax = hf["min"], hf["max"]
    emin, emax = ef["min"], ef["max"]
    typ = field_type(fk)

    have_range = None not in (hmin, hmax, emin, emax)

    # --- absolute invariants on exact min/max ---
    if have_range and hf["kind"] == "num":
        # A declared boolean whose edge escapes {0,1} is a byte-misalignment desync.
        if typ == "Boolean" and hmin >= 0 and hmax <= 1 and (emax > 1 or emin < 0):
            flags.append(("bool_escape", f"[{emin},{emax}]", "[0,1]", "high"))
        # count/length-like: a declared integer, small & non-negative at home, that at the edge either
        # goes large-magnitude negative or absurdly huge. Two extra guards came from calibration:
        #   - hmax >= 1: a constant-zero home ([0,0]) tells us nothing about the field's true range, so
        #     a huge edge value there is not evidence of a desync (undersampled, not count-like).
        #   - count_neg threshold beyond a byte: a signed positional field (Int16 coord) sampling [0,1]
        #     then dipping to -1 is noise; a genuine count-gone-negative reads garbage high bytes and is
        #     large-magnitude (the count=1714880544-class desync). -256 excludes the coord noise.
        elif typ in INT_TYPES and hmin >= 0 and 1 <= hmax <= cfg.count_small:
            if emin <= cfg.count_neg:
                flags.append(("count_neg", str(emin), f"[{hmin},{hmax}]", "high"))
            elif emax >= cfg.count_huge:
                flags.append(("count_huge", str(emax), f"[{hmin},{hmax}]", "high"))

    # --- blob length desync (blob min/max are byte LENGTHS; length >= 0 always) ---
    if have_range and hf["kind"] == "blob":
        if hmax <= cfg.count_small and emax >= cfg.count_huge:
            flags.append(("len_huge", str(emax), f"[{hmin},{hmax}]", "high"))

    # --- distribution divergence (num histograms) ---
    if hf["kind"] == "num" and hf["values"] and ef["values"]:
        tvd = tvd_other(hf["values"], ef["values"])
        if tvd is not None and tvd >= cfg.tvd_med:
            sev = "high" if tvd >= cfg.tvd_high else "medium"
            hof = other_frac(hf["values"])
            flags.append(("dist_diverge",
                          f"tvd={tvd:.3f}",
                          f"home_other={hof:.2f}",
                          sev))
    return flags


class Cfg:
    def __init__(self, a):
        self.floor_n = a.floor_n
        self.count_small = a.count_small
        self.count_huge = a.count_huge
        self.count_neg = a.count_neg
        self.tvd_high = a.tvd_high
        self.tvd_med = a.tvd_med
        self.min_fields = a.min_fields


# ----------------------------- edge comparison -----------------------------
SEV_RANK = {"high": 3, "medium": 2, "low": 1}


def compare_edge(src, tgt, op, direction, fields, cfg):
    """Returns (field_flag_rows, rollup_row). rollup verdict in {pass,suspect,insufficient-fields}."""
    edge = fields.get((src, tgt, op, direction))
    home = fields.get((src, src, op, direction))
    field_rows = []
    if not edge or not home:
        rollup = dict(n_fields_compared=0, n_flagged=0, worst_check="-",
                      worst_severity="-", verdict="insufficient-fields")
        return field_rows, rollup

    n_compared = 0
    worst_sev = 0
    worst_check = "-"
    for fk, hf in home.items():
        ef = edge.get(fk)
        if ef is None:
            continue
        if hf["n"] < cfg.floor_n or ef["n"] < cfg.floor_n:
            continue
        n_compared += 1
        for check, ev, hv, sev in check_field(fk, hf, ef, cfg):
            field_rows.append(dict(source_build=src, target_build=tgt, opcode=op, direction=direction,
                                   field_key=fk, check=check, edge_value=ev, home_value=hv, severity=sev))
            if SEV_RANK[sev] > worst_sev:
                worst_sev = SEV_RANK[sev]
                worst_check = check

    if n_compared < cfg.min_fields:
        verdict = "insufficient-fields"
    elif field_rows:
        verdict = "suspect"
    else:
        verdict = "pass"
    rollup = dict(n_fields_compared=n_compared, n_flagged=len(field_rows),
                  worst_check=worst_check,
                  worst_severity={0: "-", 1: "low", 2: "medium", 3: "high"}[worst_sev],
                  verdict=verdict)
    return field_rows, rollup


def load_accepted_edges():
    """Edges to scrutinize: accepted edges PLUS edges rejected only by invariant quarantine.

    Including the quarantined edges makes the pipeline idempotent (sol-review-final finding 1):
    invariants -> quarantine -> re-run invariants must reproduce the same violation set, not drop
    the quarantined edges and let a re-classification silently re-accept them.
    """
    man = MATRIX_DIR / "manifest.csv"
    if not man.exists():
        sys.exit(f"missing {man} — run manifest.py first")
    edges = []
    with open(man, newline="") as fh:
        for r in csv.DictReader(fh):
            if r["state"] == "accept" or r["reason"].startswith(("quarantined", "value-class invariant")):
                edges.append(r)
    return edges


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--floor-n", type=int, default=FLOOR_N)
    ap.add_argument("--count-small", type=int, default=COUNT_SMALL)
    ap.add_argument("--count-huge", type=int, default=COUNT_HUGE)
    ap.add_argument("--count-neg", type=int, default=COUNT_NEG)
    ap.add_argument("--tvd-high", type=float, default=TVD_HIGH)
    ap.add_argument("--tvd-med", type=float, default=TVD_MED)
    ap.add_argument("--min-fields", type=int, default=MIN_FIELDS_FOR_VERDICT)
    ap.add_argument("--out-fields", default=str(MATRIX_DIR / "invariants.csv"))
    ap.add_argument("--out-edges", default=str(MATRIX_DIR / "invariants-edges.csv"))
    args = ap.parse_args()
    cfg = Cfg(args)

    fields = load_fields()
    accepted = load_accepted_edges()

    all_field_rows = []
    edge_rows = []
    for r in accepted:
        src, tgt, op, d = r["source_build"], r["target_build"], r["opcode"], r["direction"]
        frows, rollup = compare_edge(src, tgt, op, d, fields, cfg)
        all_field_rows.extend(frows)
        edge_rows.append(dict(source_build=src, target_build=tgt, opcode=op, direction=d,
                              quality=r.get("quality", "-"), edge_n=r.get("n", "-"), **rollup))

    with open(args.out_fields, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["source_build", "target_build", "opcode", "direction",
                                           "field_key", "check", "edge_value", "home_value", "severity"])
        w.writeheader()
        w.writerows(all_field_rows)

    with open(args.out_edges, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["source_build", "target_build", "opcode", "direction",
                                           "quality", "edge_n", "n_fields_compared", "n_flagged",
                                           "worst_check", "worst_severity", "verdict"])
        w.writeheader()
        w.writerows(edge_rows)

    # summary
    n_pass = sum(1 for e in edge_rows if e["verdict"] == "pass")
    n_susp = sum(1 for e in edge_rows if e["verdict"] == "suspect")
    n_insuf = sum(1 for e in edge_rows if e["verdict"] == "insufficient-fields")
    print(f"floor_n={cfg.floor_n} count_small={cfg.count_small} count_huge={cfg.count_huge} "
          f"tvd_med={cfg.tvd_med} tvd_high={cfg.tvd_high} min_fields={cfg.min_fields}")
    print(f"accepted edges scrutinized: {len(edge_rows)}")
    print(f"  pass:                {n_pass}")
    print(f"  suspect:             {n_susp}")
    print(f"  insufficient-fields: {n_insuf}")
    print(f"flagged field rows: {len(all_field_rows)}")
    print()
    checks = {}
    for fr in all_field_rows:
        checks[fr["check"]] = checks.get(fr["check"], 0) + 1
    for c, n in sorted(checks.items(), key=lambda x: -x[1]):
        print(f"  {c:14} {n}")
    print()
    susp = [e for e in edge_rows if e["verdict"] == "suspect"]
    susp.sort(key=lambda e: (-{"high": 3, "medium": 2, "low": 1, "-": 0}[e["worst_severity"]], -e["n_flagged"]))
    print("top suspect edges (worst_severity, n_flagged / n_compared):")
    for e in susp[:10]:
        print(f"  {e['source_build']:>5}->{e['target_build']:<5} {e['opcode']} {e['direction']:<3} "
              f"{e['worst_severity']:>6} {e['worst_check']:14} "
              f"{e['n_flagged']}/{e['n_fields_compared']} flagged")
    print(f"\nfields -> {args.out_fields}\nedges  -> {args.out_edges}")


if __name__ == "__main__":
    main()

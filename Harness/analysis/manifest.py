"""Phase 1 manifest classifier.

Consumes the raw matrix CSVs (baseline/matrix/matrix-<build>.csv) and stamps a verdict per edge:

    accept        safe for automatic resolver fallback
    reject        evidence against (over-read, broken/absent home behaviour, incomparable consumption)
    insufficient  not enough evidence either way — resolver treats as unknown

Raw evidence and verdicts are deliberately separate (docs/CAMPAIGN.md §5 Phase 1): re-running this script with a
new rule version re-classifies without re-running packets. Never edit the matrix CSVs.

Rule v3.1.0-quarantine:
  v2 (signatures) changed reject reasons only. v3.0 auto-gated on absolute Phase 1b invariants;
  sol-review-final reversed that (seed-split calibration doesn't cover drift; the count-like type gate
  is not semantic; deriving the gate from the current accept set was circular). v3.1 instead rejects
  edges on the committed, hand-reviewed quarantine.csv — invariants.py findings are flagged for human
  review and enter that file manually, never automatically. It also adds an env_sha home-join guard so
  matrix CSVs from different sweep generations are never compared. dist_diverge remains advisory.

  - compile_error > 0                      -> reject  (broken script)
  - over_read > 0                          -> reject, reason is now signature-aware:
        edge sig set subset-of home sig set (home also over-reads) -> "same defect as home"
        otherwise (or no home signature data)                      -> "NEW failure mode vs home"
  - home row missing (no sniffs for source)-> insufficient
  - home over_read > 0 (edge clean)        -> reject  (a home-broken decoder is never auto-trusted)
  - ran < FLOOR (300)                      -> insufficient  (0 failures at low n is not evidence;
                                                             ~300 zero-failure obs bound the rate <1%)
  - KS(edge consumed hist, home hist) > KS_MAX -> reject (consumption incomparable to home)
  - otherwise                              -> accept

Rate comparison against home is forbidden (docs/CAMPAIGN.md §4.8) — signatures match failure *mode*, never rate.

Compatibility != quality: an accepted edge additionally carries a quality tier from its consumed p50
(USEFUL >= 90, PARTIAL >= 50, STUB < 50). STUB edges are portable, not coverage.

Usage:  py manifest.py [--floor 300] [--ks-max 0.2] [--out manifest.csv]
"""
import argparse
import csv
import sys
from pathlib import Path

RULE_VERSION = "3.1.0-quarantine"
HERE = Path(__file__).resolve().parent
MATRIX_DIR = HERE.parent / "baseline" / "matrix"


def load_quarantine():
    """Hand-reviewed quarantined edges (quarantine.csv) -> {tuple: evidence}.

    sol-review-final finding 1 reversed rule v3's AUTOMATIC gating on absolute invariants: seed-split
    calibration doesn't cover drift, the count-like type gate is not semantic, and deriving the gate
    from the current manifest's accept set was circular. The catches themselves survived manual review
    (every one is a tight/constant home range exploding at the edge), so they live on as an explicit,
    committed, human-owned list. invariants.py output NEVER gates automatically — new violations are
    flagged for review and only enter this file by hand.
    """
    path = MATRIX_DIR / "quarantine.csv"
    quarantined = {}
    if not path.exists():
        return quarantined
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            key = (r["source_build"], r["target_build"], r["opcode"], r["direction"])
            quarantined[key] = r["evidence"]
    return quarantined


def parse_hist(s):
    """Sparse 'pct:count|pct:count' -> {pct: count}. '-' -> empty."""
    if not s or s == "-":
        return {}
    out = {}
    for part in s.split("|"):
        pct, count = part.split(":")
        out[int(pct)] = int(count)
    return out


def parse_sigs(s):
    """Sparse 'sig:count|sig:count' -> {sig: count}. '-'/None/missing -> empty.

    Like parse_hist, but a signature itself legitimately contains ':' (e.g. 'ReadBytes: wanted ...'),
    so split the count off the right. Old CSVs without the column arrive here as None -> {}.
    """
    if not s or s == "-":
        return {}
    out = {}
    for part in s.split("|"):
        sig, count = part.rsplit(":", 1)
        out[sig] = int(count)
    return out


def over_read_reason(over, edge_row, home_row):
    """v2 reject reason for an edge with over_read>0: 'same defect as home' vs 'NEW failure mode'.

    Never a rate comparison (docs/CAMPAIGN.md §4.8) — only the failure-signature *sets* are compared.
    """
    edge_sigs = set(parse_sigs(edge_row.get("over_sigs")))
    home_sigs = set(parse_sigs(home_row.get("over_sigs"))) if home_row is not None else set()
    home_over = int(home_row["over_read"]) if home_row is not None else 0
    if home_row is None or home_over == 0 or not home_sigs:
        return f"over_read={over}; NEW failure mode vs home (no home signature data)"
    if edge_sigs and edge_sigs <= home_sigs:
        return f"over_read={over}; same defect as home (signatures matched)"
    return f"over_read={over}; NEW failure mode vs home"


def ks_distance(a, b):
    """Kolmogorov-Smirnov distance between two consumed-percentage histograms."""
    ta, tb = sum(a.values()), sum(b.values())
    if ta == 0 or tb == 0:
        return None
    ca = cb = 0.0
    worst = 0.0
    for pct in range(101):
        ca += a.get(pct, 0) / ta
        cb += b.get(pct, 0) / tb
        worst = max(worst, abs(ca - cb))
    return worst


def load_rows():
    rows = []
    for f in sorted(MATRIX_DIR.glob("matrix-*.csv")):
        with open(f, newline="") as fh:
            for row in csv.DictReader(fh):
                rows.append(row)
    return rows


def quality(p50):
    if p50 >= 90:
        return "USEFUL"
    if p50 >= 50:
        return "PARTIAL"
    return "STUB"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--floor", type=int, default=300)
    ap.add_argument("--ks-max", type=float, default=0.2)
    ap.add_argument("--out", default=str(MATRIX_DIR / "manifest.csv"))
    ap.add_argument("--invariants", nargs="?", const=str(MATRIX_DIR / "invariants-edges.csv"),
                    default=None,
                    help="Optional: join Phase 1b per-edge verdicts (invariants-edges.csv, produced by "
                         "invariants.py) as an advisory `invariants` column. ADVISORY ONLY — it never "
                         "changes any accept/reject state (docs/CAMPAIGN.md reserves that for a later decision).")
    args = ap.parse_args()

    # Phase 1b advisory join (optional). Rollup verdict per (source,target,opcode,dir); missing -> '-'.
    inv_verdict = {}
    if args.invariants:
        inv_path = Path(args.invariants)
        if inv_path.exists():
            with open(inv_path, newline="") as fh:
                for iv in csv.DictReader(fh):
                    inv_verdict[(iv["source_build"], iv["target_build"],
                                 iv["opcode"], iv["direction"])] = iv["verdict"]
        else:
            print(f"warning: --invariants given but {inv_path} not found; column will be '-'",
                  file=sys.stderr)

    rows = load_rows()
    if not rows:
        sys.exit(f"no matrix CSVs under {MATRIX_DIR} — run the sweep first")

    quarantined = load_quarantine()
    if quarantined:
        print(f"rule v3.1: {len(quarantined)} hand-quarantined edges", file=sys.stderr)

    # Home behaviour: the source==target rows of each source's own run, keyed by (source, opcode, dir).
    home = {}
    for r in rows:
        if r["source_build"] == r["target_build"]:
            home[(r["source_build"], r["opcode"], r["direction"])] = r

    edges = [r for r in rows if r["source_build"] not in ("-",) and r["source_build"] != r["target_build"]]

    out_rows = []
    for r in edges:
        n = int(r["ran"])
        over = int(r["over_read"])
        h = home.get((r["source_build"], r["opcode"], r["direction"]))
        ks = ks_distance(parse_hist(r["consumed_hist"]), parse_hist(h["consumed_hist"])) if h else None

        if int(r["compile_error"]) > 0:
            state, reason = "reject", "compile_error"
        elif over > 0:
            # State is unchanged from v1 (still reject — accept set identical); only the reason is
            # signature-aware now, distinguishing an inherited home defect from a new edge failure mode.
            state, reason = "reject", over_read_reason(over, r, h)
        elif h is None:
            state, reason = "insufficient", "no home evidence (source has no sniffs)"
        elif h["script_sha"] != r["script_sha"]:
            state, reason = "insufficient", "script_sha mismatch home vs edge — stale evidence"
        elif int(h["over_read"]) > 0:
            state, reason = "reject", f"home decoder over-reads ({h['over_read']}/{h['ran']})"
        elif n < args.floor:
            state, reason = "insufficient", f"n={n} < floor {args.floor}"
        elif h["env_sha"] != r["env_sha"]:
            # PLAN promises home evidence joined by env_sha; matrix CSVs from different sweep
            # generations must never be compared (sol-review-final finding 6).
            state, reason = "insufficient", "env_sha mismatch home vs edge — mixed sweep generations"
        elif ks is not None and ks > args.ks_max:
            state, reason = "reject", f"consumed KS={ks:.3f} > {args.ks_max} vs home"
        elif (key := (r["source_build"], r["target_build"], r["opcode"], r["direction"])) in quarantined:
            state, reason = "reject", f"quarantined: manual review — {quarantined[key]}"
        else:
            state, reason = "accept", ""

        out_rows.append({
            "source_build": r["source_build"], "target_build": r["target_build"],
            "opcode": r["opcode"], "direction": r["direction"],
            "seen": r["seen"], "n": n,
            "ok_exact": r["ok_exact"], "under_read": r["under_read"], "over_read": over,
            "threw": r["threw"], "consumed_p50": r["consumed_p50"], "consumed_p90": r["consumed_p90"],
            "home_n": h["ran"] if h else "-", "home_over_read": h["over_read"] if h else "-",
            "home_p50": h["consumed_p50"] if h else "-",
            "over_sigs": r.get("over_sigs", "-"), "home_over_sigs": h.get("over_sigs", "-") if h else "-",
            "ks_vs_home": f"{ks:.3f}" if ks is not None else "-",
            "script_sha": r["script_sha"], "env_sha": r["env_sha"],
            "quality": quality(int(r["consumed_p50"])),
            "state": state, "reason": reason,
            "invariants": inv_verdict.get(
                (r["source_build"], r["target_build"], r["opcode"], r["direction"]), "-"),
            "rule_version": RULE_VERSION, "sampling": r["sampling"],
        })

    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)

    # Per-target exit-criteria summary (docs/CAMPAIGN.md §5): explicit denominators, never a corpus aggregate.
    # The resolver prefers a home script when one exists; edges only matter where home doesn't hold.
    # "Trusted" home = the target's own script with zero over-read, no compile error, and n >= floor.
    by_target = {}
    for r in rows:
        t = r["target_build"]
        key = (r["opcode"], r["direction"])
        by_target.setdefault(t, {})[key] = max(by_target.get(t, {}).get(key, 0), int(r["seen"]))

    home_trusted = {}
    for (src, opcode, direction), h in home.items():
        ok = (int(h["compile_error"]) == 0 and int(h["over_read"]) == 0 and int(h["ran"]) >= args.floor)
        if ok:
            home_trusted.setdefault(src, set()).add((opcode, direction))

    accepted = {}
    useful = {}
    insufficient_only = {}
    for e in out_rows:
        key = (e["target_build"], e["opcode"], e["direction"])
        if e["state"] == "accept":
            accepted.setdefault(key[0], set()).add(key[1:])
            if e["quality"] == "USEFUL":
                useful.setdefault(key[0], set()).add(key[1:])
        elif e["state"] == "insufficient":
            insufficient_only.setdefault(key[0], set()).add(key[1:])

    print(f"rule {RULE_VERSION}  floor={args.floor}  ks_max={args.ks_max}")
    print(f"edges: {len(out_rows)}  accept: {sum(1 for e in out_rows if e['state'] == 'accept')}"
          f"  reject: {sum(1 for e in out_rows if e['state'] == 'reject')}"
          f"  insufficient: {sum(1 for e in out_rows if e['state'] == 'insufficient')}")
    print()
    print(f"{'target':>7} {'traffic':>12} {'home%':>8} {'edge%':>8} {'TOTAL%':>8} "
          f"{'useful%':>8} {'insuff%':>8}")
    macro = []
    for t in sorted(by_target, key=lambda x: int(x)):
        seen = by_target[t]
        total = sum(seen.values())
        keys = set(seen.keys())
        home_keys = home_trusted.get(t, set()) & keys
        acc = {k for k in accepted.get(t, set()) if k not in home_keys}
        use = (useful.get(t, set()) | home_keys) & (home_keys | acc)
        ins = {k for k in insufficient_only.get(t, set()) if k not in acc and k not in home_keys}
        home_pct = sum(seen[k] for k in home_keys) / total * 100 if total else 0
        edge_pct = sum(seen[k] for k in acc if k in seen) / total * 100 if total else 0
        useful_pct = sum(seen[k] for k in use if k in seen) / total * 100 if total else 0
        ins_pct = sum(seen[k] for k in ins if k in seen) / total * 100 if total else 0
        macro.append(home_pct + edge_pct)
        print(f"{t:>7} {total:>12,} {home_pct:>7.1f}% {edge_pct:>7.1f}% {home_pct + edge_pct:>7.1f}% "
              f"{useful_pct:>7.1f}% {ins_pct:>7.1f}%")

    print()
    print(f"macro avg TOTAL trusted-traffic share: {sum(macro) / len(macro):.1f}%  (per-build mean, unweighted)")
    print("home%  = target's own scripts, zero over-read, n >= floor (resolver always prefers home)")
    print("edge%  = accepted fallback edges for traffic home doesn't cover")
    print("insuff%= traffic with only-insufficient evidence (resolver shows unknown, today's behaviour)")
    print("NOTE: trusted availability under the rule, NOT correctness (docs/CAMPAIGN.md sec. 7).")


if __name__ == "__main__":
    main()

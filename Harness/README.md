# Harness — Phase 0/1 verification

Runs decoder scripts against captured packets and reports what actually happened.

## Why it exists

Every claim about which decoders work on which builds was, until this existed, inferred from **packet
lengths** — comparing length distributions per opcode across builds, never once running a script. That
proxy turned out to be wrong in both directions (see `../docs/CAMPAIGN.md` §3). This runs the scripts.

## Build & run

```bash
dotnet build Harness/Harness.csproj -c Release

# Home baseline — scripts vs their own build. Also the harness's self-test:
# if V12 scripts don't parse V12 packets, the harness is broken, not the scripts.
dotnet run --project Harness/Harness.csproj -c Release --no-build -- --build 12 --sample 300

# One compatibility edge: does build 2527's 0x0058 script parse build 2546's packets?
dotnet run --project Harness/Harness.csproj -c Release --no-build -- \
    --build 2546 --source 2527 --opcode 0x0058

# Resolver-policy evaluation (nearest-in-lineage). NOT edge evidence — see below.
dotnet run --project Harness/Harness.csproj -c Release --no-build -- \
    --build 2546 --chain --sample 1500 --csv edges.csv --out report.md

# Phase 1 evidence: EVERY build holding a script for each observed (opcode, direction)
# runs against a seeded reservoir sample of the target's packets.
dotnet run --project Harness/Harness.csproj -c Release --no-build -- \
    --build 2546 --matrix --sample 1500 --csv matrix-2546.csv
```

Progress and diagnostics go to stderr; the report goes to stdout. `2>/dev/null` for just the report.

### `--chain` vs `--matrix`

`--chain` evaluates one resolver policy: nearest-in-lineage script wins. If the nearest script fails
where an older one would work, chain never measures the older edge, and its default lineage never
exercises V12 against KMS2 targets. Use it to ask "how would this resolver behave", never to generate
compatibility evidence. `--matrix` is the evidence generator: all candidate sources (cross-lineage
included), and it works on targets that have no script dir of their own (2489/2491/2493/2538). It
requires `--sample` — the per-edge multiplication is unbounded otherwise. Engines are released
source-major, so memory stays flat across ~40 builds.

### Sampling

With `--sample`, packets per (opcode, direction) are a **uniform reservoir sample** (algorithm R) seeded
by `--seed` (default 1) — deterministic given the sorted file list, and recorded in the CSV's `sampling`
column. The pre-rev-3 behaviour was first-N, which provably missed variants (chained `0x003D`: 0
over-reads in the first 1,500 vs 6 in a 2,000-packet dedicated run); committed baselines under
`baseline/` predate this change. Without `--sample`, every packet streams through unsampled.

### Flags

| flag | meaning |
|---|---|
| `--build <N>` | **Required.** Target build — which packets to run against. |
| `--source <N>` | Script source build. Default = `--build` (home baseline). Set differently to measure one compatibility edge. |
| `--chain` | Nearest-in-lineage resolver policy. Policy evaluation only, not edge evidence. |
| `--matrix` | Phase 1 edge enumeration: every candidate source per (opcode, direction). Requires `--sample`. |
| `--sources <a,b,c>` | Matrix only: restrict candidate source builds. |
| `--lineage <a,b,c>` | Chain only: explicit lineage. Default derives the KMS2 (>=2000) / GMS2 (12) split from the script dirs — fine for measuring, **not** for a product resolver. |
| `--opcode <0xNNNN>` | Restrict to opcode. Repeatable. |
| `--dir <in\|out>` | Restrict to direction. |
| `--sample <N>` | Packets per (opcode, direction), seeded reservoir sample. Default: all (streaming). |
| `--seed <N>` | Reservoir RNG seed. Default: 1. |
| `--sample-errors <N>` | Failure samples (with read traces) kept per bucket. Default: 3. |
| `--scripts <dir>` | Scripts root. Default: the Ochi tree. |
| `--sniffs <dir>` | Sniff archive root. |
| `--out <file>` / `--csv <file>` | Text report / aggregate CSV. |
| `--fields <file>` | Per-field value statistics CSV (Phase 1b groundwork): per (source, opcode, direction, normalized field key) — n, min/max/mean, capped distinct-value histogram. Zero overhead when absent. |
| `--version-path-first` | Put the version dir ahead of the shared root on `sys.path`. Default reproduces the `ScriptManager.cs:88` shadowing bug; this flag tests the fix. |

### CSV schema (rev 3)

One row per (source build, target build, opcode, direction). Besides the outcome counts and
`consumed_p50`/`consumed_p90`, rows carry:

| column | meaning |
|---|---|
| `script_sha` | SHA-256 (12 hex) of the opcode `.py` file. Manifest evidence is bound to script *content*, not build numbers — an edit invalidates the edge. |
| `env_sha` | Hash of the resolved decoder environment: sys.path order flag + every importable top-level `.py` on both search paths (`script_api.py`, `common.py`, `item.py`, version overrides). Catches shared-module edits that `script_sha` can't see. |
| `consumed_hist` | Sparse `pct:count\|pct:count` consumed-percentage histogram, so acceptance verdicts can be recomputed without re-running packets. p50/p90 alone can hide a rare catastrophic mode. |
| `sampling` | `all` or `reservoir;n=<N>;seed=<S>` — the evidence's provenance. |
| `over_sigs` | Per-bucket over-read failure signatures, `sig:count\|sig:count` (digits normalized to `#`, ≤16 distinct + `~other`). Rule v2 uses signature-SET comparison to label a reject "same defect as home" vs "NEW failure mode" — never rate comparison (docs/CAMPAIGN.md §4.8). Diagnostics only: the accept set is identical to rule v1 (verified tuple-for-tuple). |

The sweep driver is committed as `sweep.ps1` (idempotent; writes `matrix-*.csv`, `fields-*.csv`, and
`.md` reports into `baseline/matrix/`).

## Outcomes

| outcome | meaning |
|---|---|
| `NoScript` | No decoder for this (build, opcode, direction). |
| `OkExact` | Consumed the packet exactly. The only unambiguously good outcome — **but see the caveat below.** |
| `UnderRead` | Stopped early. Normal for incomplete scripts; also what a desync can look like. Ambiguous. |
| `OverRead` | Ran past the end, or decoded a negative length. **Unambiguously wrong.** |
| `Threw` | Non-bounds script error. |
| `CompileError` | The `.py` doesn't parse. Two exist today — see `../docs/CAMPAIGN.md` §6.8. |

**The caveat that matters: `OkExact` is not proof of correctness.** Over-read is a *floor*, not a
guarantee. A parse can consume exactly the right number of bytes and still be entirely wrong — reading the
wrong same-width primitive, taking a wrong branch that stays in bounds, or decoding reordered equal-width
fields. Never quote a `clean%` as a correctness figure. Closing that gap is Phase 1b in `../docs/CAMPAIGN.md`.

Compare an edge against the script's **home build**, not against zero: V12's own baseline is 95.6% clean /
1.3% over-read, so home builds are not clean either.

## Design notes

- **`BoundedByteReader`** is bounded by an explicit `(array, offset, count)`, unlike
  `Maple2.PacketLib.ByteReader`, which bounds against the whole backing array's length. That currently works
  only because msb loads hand out exactly-sized arrays. **Pooling would silently disarm over-read
  detection** — the harness's core safety signal. If the live path adopts pooled buffers, it must move to a
  segment-bounded reader first (`../docs/CAMPAIGN.md` §5 Phase 3).
- **`ParseSink`** is a headless stand-in for `MapleShark2.UI.StructureForm`. Its six public members are a
  duck-typed contract with `Resources/script_api.py` (`import structure_form as sf`) — the names and
  signatures must match `StructureForm`'s exactly or every script breaks. `script_api` binds `sf` once at
  first import, so the sink must outlive its engine and be mutated per packet via `Begin()`, never swapped.
- **`ScriptHost`** caches compiled scripts; `ScriptManager` re-reads and re-parses the `.py` from disk on
  every execution (its own TODO at `ScriptManager.cs:61`). Fine for one packet on click, fatal at 10M. It
  also drops the `FileSystemWatcher` (a baseline must be deterministic) and warms up synchronously
  (`ScriptManager` warms on a fire-and-forget `Task` that races the first execution).
- `InvariantGlobalization` must stay **false** — IronPython's `StringOps` static ctor builds
  `CultureInfo("en")` and dies under invariant mode.

## `analysis/`

Ad-hoc scripts behind `../docs/CAMPAIGN.md` §3–4. Run with `py <name>.py`; they resolve paths relative to
themselves.

`rec.pkl` caches `(build, opcode, direction) -> {length: count}` over all 10,095,157 packets. `drift.py`
regenerates it (~4 min); everything else reads it.

| script | what |
|---|---|
| `drift.py` | Parses the whole archive, writes `rec.pkl`, prints corpus totals + opcode-set overlap. |
| `cmp.py` | V12 vs KMS2 length-profile classification. **The source of the discredited stability inference — read §4 before trusting it.** |
| `kdrift.py` | Per-build drift. Note it filters to builds >20k packets, so its "adjacent" pairs skip builds (§4.2). |
| `verify.py` | Shows which opcodes actually carry the 78.8% figure, and the adjacency-filter bug. |
| `final.py` | Decoder **availability** per build — availability only, never parse success. |
| `tw.py` | Traffic-weights `../baseline/chain-2546.csv` into the §3 headline numbers. |
| `scan.py`, `dup.py`, `overlap.py` | Corpus/script-tree inventory. |

## `baseline/`

Committed outputs; the numbers quoted in `../docs/CAMPAIGN.md` §3.

| file | what |
|---|---|
| `home-12.md` / `.csv` | V12 home baseline — the self-test. 95.6% clean / 1.3% over / 3.0% under. |
| `chain-2546.md` / `.csv` | Build 2546 lineage-chained. Traffic-weighted: 78.8% of traffic gets a script, 93.0% of that parses clean → 73.3% of all traffic, vs ~1.0% today. |
| `e-<opcode>-<src>-<tgt>.md` | The four dominant 2546 opcodes, each as control (src vs its own build) and edge (src vs 2546). |
| `sol-review-rev1.md` | The gpt-5.6-sol review that killed rev 1's central claim. Read before re-proposing anything in `../docs/CAMPAIGN.md` §4. |
| `sol-review-rev2.md` | The sol review of the rev 2 Phase 1 kickoff assessment — source of the rev 3 redesign (`--matrix`, sample floors, signature matching, hash-bound evidence). |

The committed baselines predate rev 3: they were measured with first-N sampling, the pre-matrix CSV
schema, and the `ScriptManager.cs:88` sys.path bug reproduced (pre-2a). The matrix sweep supersedes
them as evidence:

| file | what |
|---|---|
| `matrix/matrix-<build>.csv/.md` | The Phase 1 evidence: full source × target sweep, n=1500, seed 1, `--version-path-first`, post-2a scripts. |
| `matrix/manifest.csv` | Verdicts stamped by `../analysis/manifest.py` (rule `1.0.0-conservative`). Re-run the classifier to re-stamp; never edit the raw CSVs. |
| `matrix/sweep.log` | stderr of the sweep runs (per-source execution counts). |

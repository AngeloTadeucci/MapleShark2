# MapleShark2 — Improvement Plan (rev 3)

Rev 1 was reviewed by gpt-5.6-sol and its central quantitative claim did not survive. Phase 0 was then
built and run; rev 2 replaced every estimate with a measurement. The rev 2 Phase 1 kickoff assessment
was in turn reviewed by sol (`Harness/baseline/sol-review-rev2.md`); rev 3 incorporates that review:
Phase 1 is redesigned around **edge enumeration** (`--matrix`) instead of `--chain`, the acceptance rule
is rebuilt (failure signatures + sample floors, not rate comparison), and §4 grows five new entries of
killed proposals.

**Where things live** (all paths relative to this file, `MapleShark2/`):

| path | what |
|---|---|
| `Harness/` | The Phase 0 harness. Builds via `dotnet build Harness/Harness.csproj -c Release`. |
| `Harness/README.md` | Harness usage + design notes. **Read this first.** |
| `Harness/analysis/` | The ad-hoc corpus analysis scripts behind §3–4. Run with `py <name>.py`. |
| `Harness/analysis/rec.pkl` | Cached (build, opcode, dir) -> length histogram over all 10,095,157 packets. Regenerate with `drift.py` (~4 min); every other script reads this cache. |
| `Harness/baseline/` | Committed measurement outputs — the numbers quoted in §3. |
| `Harness/baseline/sol-review-rev1.md` | The gpt-5.6-sol review that killed rev 1. Worth reading before re-proposing anything in §4. |
| `Harness/baseline/sol-review-rev2.md` | The sol review of the rev 2 Phase 1 kickoff assessment. Killed §4.8–4.12; source of the rev 3 Phase 1 design. |


## 1. Context

MapleStory 2 preservation tooling. All projects are open-source; the game is dead on every branch.

| path | what |
|---|---|
| `MapleShark2/` | The analyzer. C#/.NET 8, WinForms + SharpPcap. ~8k LOC. **Now also `Harness/`.** |
| `MapleShark2 - Ochi/` | Deployment snapshot of analyzer commit `4b5261b` (one behind `HEAD` `0db3ffc`). Carries the live `Scripts/` tree. **Not a divergent fork** — resolved, was an open question in rev 1. |
| `MapleShark2-Scripts/` | Git repo of decoder scripts — V12 only. Not the deployed tree. |
| `MapleShark2-Sniffs/` | 1417 `.msb` files, 10,095,157 packets. |
| `PrivateMaple2/` | Server emulator. `Session.cs:23` — `VERSION = 12`. |

**Two lineages.** GMS2/V12 (dead 2020, what the emulator implements) and KMS2/2464–2550 (dead now, 41
builds in the archive). The workflow was: sniff KMS2 (the live branch) → implement into a V12 emulator.
The lineage with ground truth is the one not being sniffed.

## 2. Phase 0 — DONE

`Harness/` (net8.0, no WinForms). Runs decoder scripts against captured packets and reports what happened.

- `BoundedByteReader` — bounded by explicit `(array, offset, count)`, not by backing-array length like
  `Maple2.PacketLib.ByteReader`. Throws `OverReadException` with `PastEnd` / `NegativeLength` reasons.
- `MsbReader` — UI-independent; `FileLoader`'s framing without the `MessageBox`. Header-only peek for filtering.
- `ParseSink` — headless `StructureForm` stand-in. Six-member duck-typed contract with `script_api.py`
  (`Add<T>`, `AddField`, `StartNode`, `EndNode`, `Remaining`, `Log`). Records a typed read trace.
- `ScriptHost` — one IronPython engine per source build, **compiled scripts cached** (`ScriptManager`
  re-parses from disk per execution — fine on click, fatal at 10M packets). No FileSystemWatcher;
  synchronous warm-up. Explicit-source or lineage-chained resolution.
- Aggregate reporting (per-opcode buckets + consumed-percentile histograms) plus sampled failure traces.
  No 10M-row JSONL.

```
Harness --build 12 --sample 300                     # home baseline / self-test
Harness --build 2546 --source 2527 --opcode 0x0058  # one compatibility edge
Harness --build 2546 --chain --csv edges.csv        # resolver-policy evaluation (NOT edge evidence)
Harness --build 2546 --matrix --sample 1500 --csv m.csv   # Phase 1 evidence: every source x target
```

**Added for Phase 1 (rev 3):** `--matrix` runs *every* build holding a script for each observed
(opcode, direction) against a seeded uniform reservoir sample of the target's packets — including
cross-lineage sources (V12 vs KMS2) and targets with no script dir of their own. `--chain` only ever
measured one resolver policy: it picks the nearest script and stops, so a failing nearest script hides
a working older one, and its default lineage never exercises V12 against KMS2 targets. First-N sampling
was replaced by seeded reservoir sampling everywhere (`--seed`, recorded in the CSV) — first-N
demonstrably missed variants (chained `0x003D`: 0 over-reads in the first 1,500 vs 6 in a 2,000-packet
dedicated run). The CSV now carries `script_sha` (opcode file), `env_sha` (importable-module surface +
sys.path order), and the sparse consumed histogram, so verdicts can be recomputed without re-running
packets and evidence is bound to script *content*, not build numbers.

## 3. Measurements (these replace rev 1's estimates)

### Self-test — V12 scripts vs V12 packets

```
clean (consumed exactly) : 95.6%
over-read (WRONG)        :  1.3%
under-read (ambiguous)   :  3.0%
```

Scripts parse their own build. **The msb framing is correct** — sol independently confirmed 1417/1417 files
parse to exactly 10,095,157 packets with zero framing errors. Note the home build is *not* perfect: 1.3%
over-read is the baseline defect rate, and is what edges must be compared against — **not zero**.

### Build 2546, lineage-chained, traffic-weighted (1,523,466 packets)

```
a script ran on          : 78.8% of traffic   <- rev 1's "78.8% coverage" availability claim: CORRECT
  of that:  clean        : 93.0%
            over-read    :  1.0%
            under-read   :  6.0%

CLEAN as share of ALL 2546 traffic : 73.3%    (vs ~1.0% today)
OVER-READ as share of all traffic  :  0.8%    (11,752 packets)
```

**The chained edge performs comparably to a home build** (93.0% clean / 1.0% over vs V12's 95.6% / 1.3%).
That is precisely sol's proposed acceptance criterion — compare against the script's home-build behaviour,
not against perfection — and lineage chaining passes it.

**Aggregation caveat (rev 3, from sol review 2):** those two headline figures are not apples-to-apples.
The 93.0% is traffic-extrapolated by `tw.py`; the 95.6% is the directly executed, per-opcode-capped
sample aggregate from `home-12.md`. Sol's recomputation of the home CSV traffic-weighted gives ~98.0%
clean / ~0.95% over among packets with a script (not independently re-verified — re-derive when `tw.py`
is updated for the manifest). The qualitative conclusion survives; the specific pairing doesn't. Compare
like-for-like in the manifest.

### The length-distribution proxy was wrong in both directions

Rev 1 inferred everything from packet lengths. Running the scripts shows the proxy misleading both ways:

| | length proxy predicted | measured |
|---|---|---|
| `0x0058 IN` (43.6% of 2546 traffic), src 2527 | source saw 5 distinct lengths, 2546 has 1,168 → looked catastrophic | **100.0% clean** on both home and edge. The variation was *content*, not structure. |
| `0x001C IN`, src 2507 | shared opcode, looked fine | **22.2% over-read on its OWN home build**; the edge (94.6% clean) is *better* than home. The script is just buggy. |

Both of sol's directions of attack land: variable-length buckets are weak evidence, and "same build" is no
guarantee of correctness.

### Real defects the harness found immediately

- **Two scripts do not compile at all**: `2502/Outbound/0x00A2.py`, `2507/Inbound/0x00EA.py`.
- `0x0021 IN` (ITEM_INVENTORY) **on its own 2546 script**: 1.8% clean, median **17%** of the packet consumed.
  The item packet is barely decoded even at home — this is `item.py`'s magic-ID dispatch failing.
- `0x003D IN` src 2520: median **4%** consumed. Deeply incomplete, not desynced.
- `0x004F IN` src 2507 — a genuine cross-build desync, caught with an actionable trace:
  ```
    0  1  Byte   byte  = 1
    1  4  Int32  count = 1714880544     <- 0x66325F20: ASCII bytes read as an int
    5  2  Int16  size  = 24931
    ! ReadBytes: wanted 24931 bytes at offset 7, only 38 of 45 remain
  ```
- `0x0017 IN` src 2528: 20 packets hit `NegativeLength` — a decoded count went negative, proving desync.

Over-read detection works, and the trace points at the field where the parse diverged.

## 4. What rev 1 got wrong (recorded so it isn't re-proposed)

1. **"78.8% coverage"** conflated decoder *availability* with parse success. The availability figure was
   right; it just wasn't evidence of anything until Phase 0 ran. It now is.
2. **"97.7% adjacent-build stability"** — `kdrift.py` filtered to builds >20k packets (dropping 21 of 41),
   then compared consecutive members of the *filtered* list; 10 of 19 "adjacent" transitions skip real
   builds. It also aggregates repeated observations of the same ~40 fixed-length opcodes. Honest phrasing:
   *"97.7% agreement among repeated fixed-length observations in well-populated builds"* — a much smaller
   claim, biased toward small housekeeping packets, covering only **2.5%** of 2546's traffic.
3. **Lineage as the safety boundary.** Superseded — see §5. Evidence per decoder, not build family.
4. **"Consume exactly N bytes" as the validation gate.** Wrong: incomplete scripts are normal. But rev 1's
   *reason* was also wrong ("30% of fields are Unknown" — Unknown fields are still consumed). The real
   reason is that many scripts are deliberately partial; `StructureForm.cs:57` exists to dump the tail.
5. **"3 retained byte[] copies per packet"** conflated allocation rate with retention; only the final
   decrypted payload is retained.
6. **"77 WriteTo / 24 ReadFrom"** — wrong (actual 154/47). The ~3:1 write-bias conclusion survives.
7. **`ByteReader` can't detect over-read** — wrong. It bounds against `packet.Length` and throws; msb loads
   give exactly-sized arrays. **But this is fragile**, see the Phase 3 conflict in §5.

Rev 2's Phase 1 kickoff assessment added five more (killed by `sol-review-rev2.md`):

8. **"Edge over-read ≤ home over-read rate ⇒ explained."** Rate comparison explains nothing: `0x001C`'s
   22.2%-broken home decoder would license ~91 target over-reads, and a new target-only desync hides
   under an unrelated home defect. Explanation requires matching failure *signatures* (mode, failure
   location, trace shape), not a lower rate. Sol called this the single highest-risk proposal.
9. **"Cross-lineage waits for Phase 1b; in-lineage can go automatic on Phase 1."** That is rev 1's
   lineage-as-safety-boundary again (§4.3), one layer down. In-lineage opcodes get repurposed too.
   Phase 1b gates automatic trust for *all* edges (§8 already said so); cross-lineage gets a stricter
   prior (higher evidence floor), never a categorical rule in either direction.
10. **"Calibrate Phase 1b on the four dominant 2546 opcodes as known-good controls."** They are not:
    only `0x0058` is a credible consumption control (`0x001C` 22.2% over at home, `0x003D` 4% consumed,
    `0x002E` n=19). Calibrate with within-build temporal splits, deliberately corrupted decoders, and
    V12 emulator ground truth instead. Home execution alone is never "known good".
11. **"The `item.py:76` set literal and `0x0021.py:48` if/elif change byte consumption."** They don't —
    the set literal permutes labels over structurally identical blocks and the `if` chains are
    behaviorally equivalent for mutually exclusive categories (verify when fixing). They corrupt field
    *identity*, which matters for Phase 1b, not for Phase 1 consumption baselines. Only the two compile
    errors and the sys.path order actually change execution.
12. **"The CSV lacks sample-size fields."** False — `seen`/`executed`/`ran` were already there. (What it
    did lack: home-side figures, content hashes, full histograms, sampling metadata. Fixed in rev 3.)

## 5. Plan

### Phase 1 — Compatibility manifest, then allowlisted fallback (redesigned in rev 3)

Not "lineage chaining is safe." **Evidence per decoder.** A script goes automatic only for edges that
passed. Redesign per `sol-review-rev2.md`: `--chain` cannot generate this evidence — it records one
resolver policy's choice, hides working older scripts behind failing nearer ones, and never exercises
V12 against KMS2 targets. Evidence comes from **`--matrix`** (built, smoke-tested): every build holding
a script for each observed (opcode, direction) runs against a seeded reservoir sample of the target.

1. **Evidence run:** `Harness --build <T> --matrix --sample 1500 --csv matrix-<T>.csv` for all 41 KMS2
   builds + V12 — including the four script-less targets (2489/2491/2493/2538). Rows are keyed
   `(source, target, opcode, direction)` and carry `script_sha`, `env_sha`, the sparse consumed
   histogram, and sampling metadata. Raw evidence is stored as-is; verdicts are stamped by a separate,
   versioned classifier so re-classification never requires re-running packets.
2. **Home reference:** a source's home figures come from its own matrix run (the `source == target`
   rows), joined by `env_sha` — never duplicated by hand. A source with scripts but no sniffs (2537) has
   no home distribution: its edges are at best `insufficient`, never silently accepted.
3. **Acceptance rule (per edge, three states — accept / reject / insufficient):**
   - **Sample floor.** Zero failures at low n is not evidence: 0-of-5 is consistent with ~45% true
     failure (exact one-sided 95% bound). ~300 zero-failure observations bound the rate below 1%;
     ~3,000 for 0.1%. Below the floor → `insufficient`, and the resolver treats it as unknown.
   - **Over-read:** any edge over-read rejects unless it matches a home failure *signature* (same mode,
     failure location, trace shape) — never rate comparison against home (§4.8).
   - **Consumption comparability:** compare the full consumed histograms home-vs-edge, mode-stratified;
     p50/p90 alone hides rare catastrophic modes.
   - **Compatibility ≠ quality.** These are separate axes in the manifest. A decoder that behaves
     identically on both builds but consumes 4% (`0x003D`) is *portable*, not *useful*; it must never be
     counted as coverage. (The matrix smoke test found exactly this: V12's `0x0058` parses 2546 packets
     "cleanly" at 7% consumed.)
4. Resolver consults the manifest and binds each accepted edge to its `script_sha`/`env_sha` — a script
   or shared-module edit invalidates the edge until re-measured. Unknown/insufficient edge → no script
   (today's behaviour) + a visible marker, never a silent guess.
5. **Cross-lineage is not forbidden and not categorically gated (§4.9):** same rule, stricter prior — a
   higher evidence floor for V12-on-KMS2 edges, since equal-numbered opcodes across lineages have a
   weaker semantic prior. Phase 1b gates *automatic* trust for all edges alike.

Measured expectation for 2546: 1.0% → ~73.3% of traffic cleanly parsed (chain-policy figure; the matrix
may beat it where chain's nearest script loses to an older one). Exit criteria are **per build**, with
explicit denominators: accepted-traffic share, accepted opcode/direction share, and insufficient share
per target build, plus macro and traffic-weighted averages across builds. If accepted traffic lands
below ~60% on the builds that matter, stop and re-plan — a corpus-wide aggregate dominated by V12+2546
must not hide failure on thin builds.

**Known gap:** clean ≠ correct. Over-read is a *floor*, not proof. A parse can consume exactly and be
entirely wrong (wrong same-width primitive, wrong branch that stays in bounds, reordered equal-width
fields). §Phase 1b addresses this; do not oversell "73.3%" as "73.3% correct."

**Cost note:** matrix multiplies sample × candidate sources. Measured: the full 42-target sweep at
n=1500 runs in **~6 minutes** total (msb reading is fast; IronPython execution ~10k packets/s), so
re-sweeping after any script change is cheap — always re-sweep rather than reasoning about staleness.

**Sweep results (2026-07-15, post-2a, `--version-path-first`, rule 1.0.0-conservative, floor=300,
ks_max=0.2):** 7,498 edges → 365 accept / 2,741 reject / 4,392 insufficient. Evidence in
`Harness/baseline/matrix/` (raw CSVs + `manifest.csv`); summary via `analysis/manifest.py`. Headlines:

- **2546: 59.7% of traffic trusted** (1.0% home + 58.8% accepted edges) vs ~1.0% today — right at the
  ~60% exit criterion, below the 73.3% chain-policy figure because the rule is conservative where chain
  was credulous. Exhibit: reservoir sampling found **3 real over-reads** on the 93%-clean
  2527→2546 `0x0058` edge that first-N sampling (and the committed baseline) called 100% clean; the
  rule rejects it and covers the opcode via the consistent-with-home 2521 edge instead.
- **V12: 84.8% trusted** (almost all home; the gap to 95.6% clean is floor-gating and home over-reads).
- **Thin builds (2491/2497/2514/2538) land at 0%** — with <5k packets total they can never meet the
  floor. Honest `insufficient`, resolver shows unknown. This is the low-n reality, not a rule defect.
- **2504/2513 (~4%) are honest rejections:** their dominant opcodes have only V12 cross-lineage
  candidates, which over-read on 93–100% of samples. Nothing in the archive decodes that traffic;
  that is Phase 5 territory.
- Macro average total trusted share: 46.6% (per-build, unweighted).

**Resolver integration (2026-07-15): DONE.** `ScriptManifest.cs` loads `Scripts/manifest.csv` (accepted
rows only), validates `script_sha` per resolve and `env_sha` per source build (algorithm mirrors the
harness byte-for-byte — verified by independent recomputation against sweep values), and picks
candidates by quality tier → clean fraction → newer build. `ScriptManager.TryResolveDecoder` prefers a
home script, falls back to the manifest, and executes fallback scripts under the *source* build's engine
(the module surface they were measured with). `StructureForm` shows a `[manifest] build N decoder` node
on fallback and a `[no decoder]` node when nothing validated resolves. Functional test (headless, against
the deployed tree): 2546/`0x0058`/IN resolves to build 2521 — the manifest's accepted edge — with both
hash checks passing; wrong locale and unknown opcodes resolve to nothing. **Not verified: the WinForms
flow end-to-end** (opening an msb in the GUI and clicking a 2546 packet) — needs a manual run.
`manifest.csv` is deployed to the Ochi tree.

**Remaining for Phase 1:** signature-matched over-read rescue (rule v2 — needs per-packet failure
signatures exported from the harness; numbers-neutral for acceptance, primarily diagnostics that
distinguish "new failure mode on edge" from "same defect as home").

### Phase 1b — Value-class invariants (closes the "clean but wrong" gap)

The read trace already records `(offset, width, type, label, node path, value)`. Add cheap invariants and
compare distributions to the home build:
- booleans that aren't 0/1; counts/lengths that are negative or absurd (`count = 1714880544` above);
- strings that aren't valid UTF-16; array lengths that don't match consumed bytes;
- per-field value-distribution divergence between home and edge (a field that is always 0..10 at home and
  uniformly random at the edge is a desync even when consumption is exact).

This is the only proposed mechanism that catches an in-bounds wrong parse.

**Calibration (rev 3, replaces "use the four dominant opcodes as known-good controls" — §4.10):** the
noise floor must be measured before the gate is trusted. Legitimate content drift across builds (new
items, different maps, different populations) will fire per-field divergence on healthy edges. Calibrate
with: within-build temporal splits (same build, different capture sessions — drift there is pure noise),
deliberately corrupted decoders (known-bad must fire), and V12 fields where the emulator provides
external ground truth. Only `0x0058` among the heavy 2546 opcodes is even a credible consumption
control. If the calibrated false-positive rate is high, Phase 1b becomes advisory ranking, not a gate —
find that out *before* wiring it into the resolver.

**DONE (2026-07-15/16), split verdict — absolute invariants gate, distributional advisory.**
`analysis/invariants.py` + `baseline/matrix/invariants{,-edges}.csv`. Calibration: seed-split
(same-build, different-sample) noise ceiling for the `~other`-robust TVD is 0.48 at n≥200 → thresholds
0.50/0.60 sit above pure sampling noise; type-gated absolute checks (bool_escape/count_neg/count_huge/
len_huge) show **zero** false positives on all calibration pairs. Corrupted-decoder control: catches
reorders/shifts that move a concentrated field's support (TVD 0.537); inherently blind to high-entropy
reorders and alignment-preserving retypes (marginals genuinely unchanged). Real result over the 365
accepted edges: 61 pass / 193 suspect / 111 insufficient-fields; validated concrete catch —
`2527→2525 0x0058 IN` `BufferSize` constant 26 at home, [−22858, 25600] at the edge: a clean-consuming
desync Phase 1 had accepted. **Rule 3.0.0-invariants** now rejects would-be accepts with absolute
violations: 12 edges flipped (365 → 353 accepts; 2546: 59.7% → 59.0%, macro 46.6% → 45.2%).
`dist_diverge` is advisory only until a *temporal-split* (content-drift) noise floor exists — its 193
suspects mix real desyncs with legitimate drift and must not gate.

### Phase 2 — Fix what the harness already found

Two non-compiling scripts (`2502/Outbound/0x00A2.py`, `2507/Inbound/0x00EA.py`); the defects list in §6.
These poison any baseline and are cheap.

**Ordering (rev 3):** the *execution-affecting* subset — the two compile errors and the §6.6 sys.path
decision — lands **before** the Phase 1 matrix sweep, or the manifest is measured against scripts that
are about to change. Pin `--version-path-first` to whatever the product resolver will ship. The
*label-only* defects (§6.3 set literal, §6.4 if/elif — see §4.11) don't move consumption numbers and can
land any time before Phase 1b, where field identity starts to matter. Any script edit after the sweep is
caught by `script_sha`/`env_sha` invalidation rather than by remembering to re-run.

**Phase 2a DONE (2026-07-15):** the two compile errors were Python-2 leading-zero literals; fixed in the
Ochi tree (values unchanged — `01` is 1 either way). `0x00A2` now parses 77.8% clean at home;
`0x00EA` compiles but is deliberately partial (one mode, 2% median consumed). The sys.path decision is
**version-path-first**, now shipped in `ScriptManager.cs` (version folder ahead of the shared root), and
measured before deciding: on 2546's home build (n=300/opcode, same seed) shared-first gives 43.0% clean /
**11.0% over-read**; version-first gives 53.9% clean / **0.0% over-read**. The shadowing bug was the
entire over-read rate of that sample. V12 is unaffected (its version modules match the shared root).
Consequence: the committed `chain-2546` baseline, measured with the bug reproduced, likely *understates*
achievable coverage. The matrix sweep runs with `--version-path-first`.

**Dropped from rev 1: deleting the locale dimension.** Sol's argument holds — it costs almost nothing,
explicit lineage config already solves the resolver problem, and "all *our* captures are 0" doesn't prove
no external script or capture uses nonzero. Keep it.

### Phase 3 — Performance (after profiling, and mind the conflict)

**Conflict with Phase 1, missed in rev 1:** over-read detection currently works *only because* every packet
owns an exactly-sized array. Pooling (`MapleCipher.TryDecrypt` rents from `ArrayPool`) makes buffers
oversized, silently disarming the harness's core safety signal. **Migrate the GUI/live path to a
segment-bounded reader before adopting pooled payloads.** `Harness/BoundedByteReader` is that reader.

Supported by code reading: capture pipeline runs on the UI timer (`MainForm.cs:342`); `packetQueue`
uncapped (`MainForm.cs:37`); GUI calls non-pooled `Decrypt` while `TryDecrypt` (`MapleCipher.cs:102`) is
pooled and unused; unshown partial-handshake `SessionForm`s never reaped (`MainForm.cs:94`);
`Opcodes.Exists` linear per packet (`SessionForm.cs:656`); `MapleStream.cs:47` memmoves per packet.

**Safe scope DONE (2026-07-15):** the segment-bounded reader migration landed —
`MapleShark2/Tools/SegmentByteReader.cs` (bounds every read against the packet's segment, preserves
`ByteReader`'s `IndexOutOfRangeException` contract; 28/28 bounds tests incl. the pooling-regression
case), `MaplePacket` migrated with an unchanged public API. Also: `Opcodes.Exists` linear scans → O(1)
`HashSet` tracking; never-shown half-open `SessionForm`s reaped from the existing UI timer via
`Dispose()` (deliberately not `Close()` — never-shown forms and mid-`RemoveWhere` mutation).
**Verified by build + unit tests + reasoning; NOT runtime-verified in a live capture.** Remaining Phase
3 items (pooled decrypt adoption, pipeline/timer restructure, `packetQueue` cap, `MapleStream` memmove)
stay gated on profiling per this section; the reader precondition for pooling is now satisfied.

Overstated in rev 1, per sol, and **not yet verified** — profile before prescribing: opcode rebuild
frequency, owner-draw cost (the column-header handler does render), retention vs allocation rate. Server
GC is not a fix for unbounded retention.

### Phase 4 — Generate the V12 layer from the emulator

Scope: **executed SendOp traces only.** V12/GMS2 only — wrong lineage for KMS2.

`DebugByteWriter` (`Maple2.Server.Core/Helpers/DebugByteWriter.cs`) has zero call sites and is the seed —
but rev 1's "already does ~90%" was wrong. It records primitive names, values, and offsets; it does **not**
record source field names, model-call boundaries, branch predicates, or `WriteBytes`/deflated blobs, and it
flattens nested writes. Needs a complete `IByteWriter` decorator plus Roslyn for names and call paths.

Read-side (`RecvOp`) needs a separate extraction path — write-side tracing covers server→client only.
Do not reuse the emulator's `ReadFrom` as a decoder: `ReadClass<T>` builds via `GetUninitializedObject`, so
`Item.ReadFrom`'s discriminator branches are dead on a zeroed object.

Prior art with a measured ceiling: `PrivateMaple2/tools/mapleshark/extract-emu-surface.js` — regex
extraction, 123 unique / 56 ambiguous / 43 none on mode attribution (~55%). Its own caveat says per-method
mode attribution in multi-SendOp files is out of scope.

**Phase 4a DONE (2026-07-15):** generator at `PrivateMaple2/Maple2.DecoderGen/` (standalone, not in
their .sln). Key constraint discovered: `ByteWriter`'s methods are non-virtual and `Packet.Of` hardcodes
the concrete type, so a decorator cannot intercept top-level builder bodies — only model
`WriteTo(IByteWriter)` calls. Design: static source extraction for provably-linear builders +
reflection for exact widths + 85 builders actually executed and byte-walked (85/85 exact) + the
capturing decorator reserved for the `WriteClass` tier in 4b. Results: **67 V12 scripts emitted**
(strict no-guess policy: 142 SendOps skipped — 88 control-flow, 36 WriteClass/metadata, 18 other),
validated against the real V12 corpus: **54/54 with data at zero over-read, 51/54 at 100% clean, 9
covering opcodes with no existing script** (independently re-verified: `0x00E3` 100% clean n=300;
`0x0101` 100% clean vs the existing script's 45% consumed). Output tree:
`Harness/generated-v12/` (self-sufficient scripts root; promotion into the deployed tree is a separate
decision — it would add V12 home coverage and manifest candidates).

**Found emulator bug:** `0x0039` LevelUp — emulator writes `Level` as short (2 bytes), the real wire
carries int (existing 100%-clean script reads int); generated script under-reads to 75% reproducing the
emulator faithfully. File upstream against Maple2.

**Phase 4b (remaining):** decorator-driven runtime traces for the 36 `WriteClass` opcodes
(CubePacketTests-style hand-built models), Roslyn for the 88 control-flow builders (loop/count pairing,
predicate extraction), struct field expansion, RecvOp static extraction (never execute `ReadFrom` —
`GetUninitializedObject` kills discriminators).

Blocker: writers branch on XML metadata invisible on the wire (`Item.cs:216` — Template/Pet/Music/Badge, no
discriminator). Resolvable via `item.Id` + a metadata lookup; `ItemAppearance` is worse (56/20/56/4 bytes,
selected by `Metadata.SlotNames`, written before four more `WriteClass` calls).

### Phase 5 — Corpus-driven inference, **feasibility-gated**

The only phase that creates knowledge. But sol's identifiability objection is serious and rev 1 ignored it:
among the 311 undocumented KMS2 opcode/direction pairs, **median sample count is 48**; 69 have ≤5; 173 have
≤100; the top ten are 88.8% of their traffic. "4M packets" is not 4M packets *per opcode*.

**Gate: prove it blind on V12 first.** Hide the known V12 scripts, infer layouts, score recovered
boundaries/types/branches against the real scripts. Only then point it at KMS2. Cluster by mode/prefix/
length family before any offset-entropy analysis — on variable-length packets, strings and arrays shift all
later offsets and entropy just measures content mixture. Prioritise the high-traffic tail; explicitly
classify the rare tail as insufficient-data rather than pretending otherwise.

Note `0x0021` (ITEM_INVENTORY) consumes 17% at home — the highest-value inference target is a packet whose
*home* decoder is already failing, and the emulator has V12 ground truth for it.

**GATE RUN (2026-07-15): verdict PARTIAL — inference is demoted to an assistive tool, never autonomous.**
Blind inference (`analysis/infer.py`, mode/length clustering first per this section's constraints) was
frozen, then scored on 15 V12 opcodes against ground truth. Reliable: fixed layouts, ushort-prefixed
strings, first-byte mode dispatch (5/6), single-level count arrays. Unreliable: fine typing (int vs
float/short is unidentifiable from bytes), nested arrays, polymorphic bodies (`0x0021` body
unrecovered, 63% clean). Aggregate structural score: ~61% boundary recall, ~59% type accuracy.
**Live proof of §7's top risk:** `0x0023` inferred a false array from a near-constant byte and still
scored 99.5% clean — plausible-but-wrong at its purest; behavioral clean% systematically overstates
correctness. Sample hunger: ~30 (fixed), ~300 (variable), ~300 *per mode* (dispatch). KMS2 projection:
138/311 undocumented pairs meet the attempt floor (99.7% of undocumented traffic by volume), but only
the 74 fixed-family pairs (**9.4% of traffic**) are in the reliably-correct zone; the variable/mode
class holding 90.3% is exactly where the method fails. The 173 thin pairs stay `insufficient`.
Consequence: Phase 5 output feeds human script-writing with per-field confidence ranking; it never
writes to a scripts tree.

### Phase 6 — Declarative schema (deferred, incremental)

Still the permanent fix: field names are bare string literals (4,798 `add_*` calls, 1,434 named "Unknown"),
IronPython 3.4.1 has no `match`/`case` (`ScriptTranslator.cs:91` downgrades `switch` → `if`/`elif`; its own
header: *"Really bad translator… you will certainly need to manually fix"*), and `item.py`'s ~150 magic IDs
silently desync. Phases 0/1 give it the regression harness that makes the migration safe.

## 6. Defects to fix regardless (all verified; sol independently confirmed each)

1. `DefinitionsContainer.cs:115` vs `Config.cs:73` — send/recv properties inverted between writer and reader.
   **FIXED — on the reader side.** The first fix went the wrong way (inverted the writer to match the
   reader) and was reverted. Ground truth: send/recv are named from the **server's** perspective,
   matching the emulator's SendOp/RecvOp — `RequestVersion` is a *server-sent* handshake message
   (emulator `Session.PerformHandshake` writes `SendOp.RequestVersion`) and lives in the deployed
   `send.properties`; V12 `Inbound/0x0001.py` is REQUEST_VERSION, so script-tree `Inbound` =
   server→client too. The writer already followed this; `Config.GetPropertiesFile` and its two menu
   callers were the inverted side and are now fixed.
2. `DefinitionsContainer.cs:114` — `return` where `continue` is meant; one `0xFFFF` truncates all output.
   **FIXED.**
3. `item.py:76` — set literal → the four stat blocks are mislabeled (`common.py:154` does it right).
   **FIXED** across all 10 `item.py` copies + the 6 self-contained `0x0021.py` variants (17 set-literal
   sites; 3-, 4- and 5-element variants), preserving the authors' written order.
4. `Inbound/0x0021.py:48` — `if` where `elif` is meant; ladder split in two. **FIXED** in the 6
   self-contained `0x0021.py` copies (every `item.py` already had `elif`). Sol's §4.11 equivalence claim
   was verified by measurement before re-sweeping: re-running the 2546 matrix with the identical seed
   after both fixes produced **zero** outcome/consumption diffs across all 353 rows, while 280 rows
   changed `script_sha`/`env_sha` — label-only confirmed, and the staleness detection demonstrably fires.
5. `MaplePacket.cs:41` — `Search` scans to `buffer.Array.Length`, not segment end. **FIXED** — bounded
   by `buffer.Offset + buffer.Count`.
6. `ScriptManager.cs:73` vs `:88` — sys.path order shadows version-specific modules (harness reproduces
   the bug by default; `--version-path-first` tests the fix). **FIXED** in `ScriptManager.cs` — version
   folder now precedes the shared root; measured impact in Phase 2a notes (11.0% → 0.0% over-read on
   2546 home).
7. Builds 2489/2491/2493/2538 have sniffs but no script dir; 2537 has a dir but no sniffs. (Harness-side:
   `--matrix`/`--chain` now run on script-less targets; 2537's edges are `insufficient` — no home data.)
8. **New:** `2502/Outbound/0x00A2.py` and `2507/Inbound/0x00EA.py` do not compile. **FIXED** — Python-2
   leading-zero literals (`01`/`05`/`06`), values unchanged.

## 7. Risks

| risk | status |
|---|---|
| **Clean ≠ correct.** Over-read is a floor. An in-bounds wrong parse is invisible to Phase 1's gate. | **PARTIALLY CLOSED (Phase 1b).** Absolute value-class invariants (zero calibrated FPs) now gate acceptance — 12 in-bounds desyncs ejected from the trusted set (rule v3). Remaining: high-entropy reorders and alignment-preserving retypes stay invisible to marginal stats; `dist_diverge` advisory pending temporal-split calibration. Still never quote coverage as "correct". |
| Sampling (1500/opcode) may miss rare variants of heavy opcodes. | Partially mitigated (rev 3): first-N replaced by seeded uniform reservoir sampling — first-N provably missed variants (`0x003D`). Rare *modes* within a heavy opcode remain under-sampled; stratify by mode in the manifest run. |
| Low-n edges accepted on statistically empty evidence. | Mitigated by design (rev 3): sample floor + `insufficient` third state; resolver treats `insufficient` as unknown. Floor: ~300 zero-failure obs for a 1% bound. |
| Manifest evidence goes stale when scripts or shared modules are edited (Phases 2/6 do exactly that). | Mitigated by design (rev 3): edges bound to `script_sha` + `env_sha` (importable-module surface + path order); mismatch invalidates the edge. |
| "Comparable to home" treats known-defective home decoders as truth. | **OPEN.** Home comparison establishes non-inferiority only. Compatibility and decoder quality are separate manifest states; portable-but-incomplete never counts as coverage. Phase 1b is the correctness axis. |
| Phase 1b fires on legitimate cross-build content drift (false positives). | **OPEN.** Calibrate the noise floor first (temporal splits, corrupted decoders, V12 ground truth) — see Phase 1b. If FP rate is high, it demotes to advisory. |
| Pooling silently disarms over-read detection. | Phase 3 ordering constraint above. |
| Phase 5 inference produces plausible-but-wrong layouts at scale — `item.py`'s failure mode, automated. | Blind-on-V12 gate; proposals ranked by confidence, never auto-applied. |
| "Fork, not rewrite" is directionally right but was never demonstrated: the msb corpus holds **already-decrypted** payloads, so it validates framing and says nothing about live capture, ciphers, or reassembly. | Restated as: *extend and refactor unless testing exposes a fundamental limitation.* Needs PCAP/live tests + profiling to become a real conclusion. |

## 8. Sequencing

```
Phase 0   harness                    DONE (+ rev 3: --matrix edge enumeration, reservoir sampling, hashes)
Phase 2a  compile errors + sys.path  DONE — fixed + measured (11.0% -> 0.0% over-read on 2546 home)
Phase 1   compatibility manifest     evidence + classifier DONE (see §5 sweep results);
                                     remaining: rule-v2 signature rescue, product resolver integration
Phase 1b  value-class invariants     closes "clean but wrong"; gates AUTOMATIC trust for ALL edges
Phase 2b  remaining defects          label-only script fixes before 1b (re-sweep after: it's 6 minutes)
Phase 3   perf                       profile first; AFTER the bounded-reader migration
Phase 4   V12 generation             SendOp traces only, V12 lineage only
Phase 5   inference                  gated on blind-V12 feasibility
Phase 6   schema                     deferred, incremental
```

Phases 2a, 1, 1b are the critical path, in that order. Phase 3 is independent once the reader constraint
is respected.

# gpt-5.6-sol review — rev 2 Phase 1 kickoff assessment (2026-07-15)

Reviews the Phase 1 kickoff assessment produced against PLAN.md rev 2 (what to do first, where the plan
is weakest). This review triggered PLAN.md rev 3. Companion to `sol-review-rev1.md`, which reviewed the
original plan's quantitative claims.

Overall: the assessment is directionally useful but not safe to execute. Its proposed acceptance rule is unsound, two factual premises are false, and it misses that the current harness cannot generate the manifest described in Phase 1.

## “What I’d do first”

### 1. Pull Phase 2 fixes forward — PARTIAL

Fix the two compile errors before authoritative measurements. Decide and pin `--version-path-first` before the sweep because import resolution changes the actual decoder environment. Those parts are right.

The assessment is wrong that all four script defects change byte consumption:

- `item.py:76` permutes labels over four structurally identical stat blocks. It corrupts field identity, so it matters to Phase 1b, but it does not change how many bytes are consumed.
- The two `if` chains in `0x0021.py:48` are behaviorally equivalent for the mutually exclusive item categories. Changing the second `if` to `elif` does not fix the measured 17% consumption.
- The two compile errors plainly affect execution.
- Search-path ordering can change imported code and therefore parsing.

So fix all four before Phase 1b and before hashing artifacts, but do not pretend the set/`elif` edits invalidate Phase 1 consumption measurements. [PLAN.md §6.3–6.8](/D:/Projetos/MapleStory2/MapleShark2/PLAN.md:236)

The ordering is also premature: first make the sweep enumerate the intended edges and define artifact identity. Otherwise the assessment merely fixes scripts before running the wrong experiment.

### 2. Extend the CSV schema — PARTIAL

Home results, mode/variant identity, and artifact provenance are required.

But “sample-size fields” are already present: `seen`, `executed`, and `ran` are in both the CSV header and implementation. [chain-2546.csv](/D:/Projetos/MapleStory2/MapleShark2/Harness/baseline/chain-2546.csv:1), [Program.cs](/D:/Projetos/MapleStory2/MapleShark2/Harness/Program.cs:327)

A top-level “script-content hash” is insufficient. Decoder behavior depends on:

- the opcode script;
- imported shared and version-specific modules such as `item.py`, `common.py`, and `script_api.py`;
- search-path order;
- harness/API semantics and IronPython version.

Hash the resolved decoder environment or conservatively hash the applicable root/version script trees plus execution configuration. Otherwise the proposed hash will remain unchanged when precisely the shared modules named in Phase 2 are edited.

Also missing are corpus identity, harness/rule version, lineage configuration, sampling method, and enough distribution data to recompute the decision. Home statistics should preferably be a normalized artifact keyed by decoder-environment hash, not duplicated into every edge.

### 3. Turn acceptance into code — PARTIAL

Encoding a versioned decision rule is correct. The proposed rule is not.

“Home over-read rate ≥ edge over-read rate” does not explain anything. It only compares counts. The measured `0x001C IN` example would license 91 target over-reads because its home decoder has an even worse 22.2% rate. A new target-only desynchronization could hide beneath an unrelated home defect. Explanation requires at least the same mode, failure location, trace signature, and cause—not merely a lower rate. [home control](/D:/Projetos/MapleStory2/MapleShark2/Harness/baseline/e-0x001C-2507-2507.md:1), [edge](/D:/Projetos/MapleStory2/MapleShark2/Harness/baseline/e-0x001C-2507-2546.md:1)

P50/p90 is also too lossy. A rare catastrophic mode can leave both percentiles unchanged. An ordinary two-sample significance test is not an equivalence test: failing to find a difference does not establish comparability, while huge samples will flag harmless content drift.

The harness does not already retain “full histograms” suitable for this:

- It has only a 101-bin, rounded consumed-percentage histogram in memory.
- CSV exports only p50/p90.
- Successful read traces are discarded; only sampled failure traces are retained. [Program.cs](/D:/Projetos/MapleStory2/MapleShark2/Harness/Program.cs:191), [Program.cs](/D:/Projetos/MapleStory2/MapleShark2/Harness/Program.cs:139)

Store raw measurements separately from derived `accept/reject/insufficient`, and stamp the rule version. The manifest should remain reclassifiable without rerunning millions of packets.

## Claimed weaknesses

### 1. Low-n evidence — AGREE, with a statistical correction

The conclusion is right. Zero observed failures at low `n` is not acceptance evidence.

The wording is technically wrong:

- The rule of three gives approximately `3/5 = 60%`, not 45%.
- Approximately 45% is the exact one-sided 95% upper bound: `1 − 0.05^(1/5) ≈ 45.1%`.

So the quoted number is defensible, but not “by the rule of three.”

The evidence problem is real. The `0x002E` home control has only 19 observations, while several chain rows have single-digit `n`. A minimum must be derived from the tolerated unseen failure rate: roughly 299 zero-failure observations bound it below 1% at one-sided 95% confidence; roughly 2,995 are needed for 0.1%.

A universal minimum alone is insufficient. The packets must also cover modes and must not be merely the first `N` chronologically. `Program.cs` takes the first `N` encountered per opcode, not a random sample.

### 2. No invalidation story — AGREE

This is a real defect, not ceremony. The scripts are mutable runtime artifacts, and Phases 2 and 6 explicitly edit them. A stale allowlist silently authorizing changed code is unacceptable.

The proposed remedy is incomplete because hashing only the opcode file misses imported dependency changes. Use a dependency/environment hash or a conservative script-bundle hash. The manifest also needs its measurement-rule and harness versions.

### 3. Cross-lineage Phase 1 acceptance — PARTIAL

The elevated risk is real: same-numbered opcodes across V12 and KMS2 have a weaker semantic prior than nearby KMS2 builds.

The assessment then repeats rev 1’s mistake by turning lineage back into a safety boundary. The prior review explicitly established that in-lineage opcodes can also be repurposed and that evidence—not family—is the boundary. [sol-review-rev1.md finding 3](/D:/Projetos/MapleStory2/MapleShark2/Harness/baseline/sol-review-rev1.md:1)

The correct conclusion is not “Phase 1 is enough in-lineage but Phase 1b is required cross-lineage.” Phase 1b must gate automatic trust for all edges unless there is independent semantic identity evidence. Cross-lineage should receive a stricter prior, not a categorical rule masquerading as validation.

This also contradicts [PLAN.md §8](/D:/Projetos/MapleStory2/MapleShark2/PLAN.md:261), which says Phase 1b “gates trust in Phase 1.”

### 4. Phase 1b noise floor — AGREE, but the proposed controls are bad

Legitimate content drift will produce per-field distribution drift. Calibration and mode conditioning are mandatory.

Calling the four dominant controls “known good” or “clean” contradicts the baselines:

- `0x0058`: strong consumption control, 449 home packets.
- `0x002E`: clean but only 19 home packets.
- `0x001C`: 22.2% home over-read.
- `0x003D`: 98.4% home under-read, p50/p90 consumption 4%/4%.

Only `0x0058` is a credible consumption control, and even it is not semantic ground truth. [baseline controls](/D:/Projetos/MapleStory2/MapleShark2/Harness/baseline/e-0x0058-2527-2527.md:1)

Calibrate with within-build resampling/temporal splits, mode-conditioned distributions, deliberately corrupted decoders, and V12 cases where emulator semantics provide external ground truth. Home execution alone is not “known good.”

### 5. Exit criterion only for 2546 — PARTIAL

Per-build acceptance coverage is necessary. A corpus-wide aggregate would be dominated by V12 and build 2546 and could hide failure on thin builds.

But the assessment overstates the textual defect. [PLAN.md §5](/D:/Projetos/MapleStory2/MapleShark2/PLAN.md:151) places the exit criterion after the 2546 expectation but says “if the manifest build-out” falls below 60%; it is ambiguous, not explicitly restricted to 2546.

The actual defect is that the denominator and aggregation are undefined. Report at least:

- accepted traffic share per target build;
- accepted opcode/direction share per build;
- insufficient-evidence share;
- macro average across builds;
- corpus-traffic-weighted average.

“Early builds have fewer candidates” is plausible, not demonstrated. Longer fallback history also creates more protocol-drift exposure, so 2546 is not automatically the best case.

## What the assessment missed

### Critical: `--chain` cannot produce the promised compatibility matrix

Phase 1 says to emit evidence keyed by `(source, target, opcode, direction)`, but the current chain implementation selects only the first/newest script and stops. [ScriptHost.Resolve](/D:/Projetos/MapleStory2/MapleShark2/Harness/ScriptHost.cs:108)

Consequences:

- If the nearest script fails but an older script works, the older edge is never measured.
- The manifest is a record of one resolver choice, not a compatibility matrix.
- Default KMS2 lineage explicitly excludes V12, so Phase 1’s cross-lineage promise is never exercised.
- Even an explicit lineage still tests V12 only when no later KMS2 script exists.

Worse, the 42-build sweep is not currently runnable as stated. `Program.cs` requires a same-build script folder before it enters chain resolution. [Program.cs](/D:/Projetos/MapleStory2/MapleShark2/Harness/Program.cs:72) The plan itself says builds 2489, 2491, 2493, and 2538 have sniffs but no script directory. [PLAN.md §6.7](/D:/Projetos/MapleStory2/MapleShark2/PLAN.md:246)

Phase 1 first needs an edge-enumeration mode that runs every eligible source script against every applicable target, including targets without a script directory. `--chain` is for evaluating a particular resolver policy, not generating candidate evidence.

There is a second unhandled hole: build 2537 has a script directory but no sniffs. Its `0x0051` decoder therefore has no home distribution, making the plan’s mandatory home comparison impossible. That must become `insufficient` or use a separately justified reference—not be silently skipped.

### Historical weakness: home behavior is still being treated as truth

The plan admits home scripts are defective, then makes “comparable to home” the acceptance basis. The assessment makes this worse by using home failure rate to explain target failures.

Home comparison establishes, at most, non-inferiority to the existing decoder. It does not establish correctness or even utility:

- `0x001C` is known broken at home.
- `0x003D` consumes only 4% at home.
- `0x0021` consumes 17% on its exact build.
- `0x00B3` in the chain consumes effectively 0%.

Compatibility and decoder quality need separate states. “The same incomplete behavior occurs on both builds” may establish portability of an incomplete decoder, but it must not be counted as useful or correct coverage.

## Direct contradictions with the evidence

- “Sample-size fields are missing” is false; `seen`, `executed`, and `ran` already exist.
- The set-literal and `if`/`elif` fixes do not alter consumption.
- The four dominant controls are not four clean controls.
- The harness does not export full histograms or successful per-field distributions.
- Default `--chain` cannot test cross-lineage edges, contrary to the plan’s Phase 1 promise.
- The proposed all-build sweep fails immediately on four KMS2 targets with no script directory.
- The plan’s aggregate comparison “93.0% chain vs 95.6% home” is not apples-to-apples. The chain figure is traffic-extrapolated by `tw.py`; 95.6% is the directly executed, per-opcode-capped sample aggregate from `home-12.md`. Traffic-weighting the home CSV produces approximately 98.0% clean and 0.95% over-read among packets with a script, not 95.6%/1.3%.
- Sampling is visibly unstable: chained `0x003D` at 1,500 packets reports zero over-read, while the dedicated 2,000-packet edge finds six over-reads. The first-N sweep is already missing variants in a headline opcode.

**Single highest-risk decision:** allowing any edge to go automatic under the assessment’s “home over-read rate ≥ edge rate means explained” rule before Phase 1b, because it converts known-bad home decoders into licenses for target-build failures and still cannot detect exact-length wrong parses.
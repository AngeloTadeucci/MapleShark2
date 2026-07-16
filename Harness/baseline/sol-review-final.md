The campaign materially improved MapleShark2, but “all phases executed to their gates” is not defensible. The strongest deliverables are the matrix corpus, bounded reader, generated-script source traces, and schema compiler. The weakest are Phase 1b’s gate and every result whose supporting experiment stayed in a scratchpad.

1. Rule v3 absolute-invariant gating — DISAGREE

Seed splitting is not enough grounds to gate automatic resolution.

- A seed split tests sampling stability within the same underlying distribution. It does not test legitimate temporal, session, population, or cross-build drift.
- “Zero calibrated false positives” is not zero false-positive probability, and no calibration script/report or V12 semantic-ground-truth result is committed.
- The type gate is not semantic. Any `Byte`/`Int16`/`Int32`/`Int64` whose home sample happens to lie in 1..4096 is treated as count-like. The 13 flags include fields named `?`, `Short / #`, `Unknown`, and `plot number`, not established counts. See [invariants.py](/D:/Projetos/MapleStory2/MapleShark2/Harness/analysis/invariants.py:145).
- It excludes unsigned integer types, so it is simultaneously over-broad for signed positional/unknown fields and under-inclusive for plausible unsigned counts.
- The pipeline is circular. `invariants.py` examines only currently accepted edges, while `manifest.py` rejects using its output. Rerunning invariants against the 353-edge v3 manifest drops the 12 rejected edges; rerunning the manifest can then reaccept them. See [invariants.py](/D:/Projetos/MapleStory2/MapleShark2/Harness/analysis/invariants.py:262) and [manifest.py](/D:/Projetos/MapleStory2/MapleShark2/Harness/analysis/manifest.py:170).

The `2527→2525 0x0058` BufferSize result is a compelling catch. It justifies a high-severity warning or a manually reviewed rejection, not an automatically generalized 12-edge gate.

2. `dist_diverge` advisory — PARTIAL

Not gating the 193 suspects was correct. Cross-build value distributions can legitimately change, and seed-split calibration does not establish a cross-session drift floor.

But “advisory” currently means practically inert: the product resolver ignores the invariant verdict. It should surface a warning such as `[manifest: distribution suspect]`, log it, and expose the flagged fields. It should not block resolution or alter candidate ordering until temporal-split calibration exists.

3. Phase 4 validation regime — PARTIAL

For one opcode, 0 failures in 500 samples gives a one-sided 95% upper bound of about 0.60%, stronger than the plan’s approximately 1% at n=300. So n=500 is reasonable as a per-opcode smoke threshold.

It is not enough for the broader “166 validated scripts” claim:

- Across 138 tested opcodes, a simultaneous 95% claim that every over-read rate is below 1% needs roughly 788 zero-failure samples per opcode.
- Uniform opcode sampling does not protect rare modes. A dangerous 0.1% mode will usually be absent from 500 samples.
- Prefix safety is the real safety argument; sampling only tests whether the generator implemented that argument correctly.
- Only 138 of 166 scripts had corpus data. The other 28 were not behaviorally validated.
- “Full” means full extraction of the emulator’s builder, not proven wire correctness. The two emulator/wire divergences demonstrate the distinction.

The 57 partial files are marked only by source comments and the separate [generation report](/D:/Projetos/MapleStory2/MapleShark2/Harness/generated-v12/generation-report.txt:120). The GUI does show an `Undefined` tail, which helps, but there is no visible “safe partial” decoder status. Calling these “coverage” invites misinterpretation. Completeness needs product-visible metadata.

4. Phase 5 PARTIAL / assistive-only — PARTIAL

The operational decision is right: inference must remain assistive-only. The reported gate is not strong enough to support its numerical conclusions.

Holes:

- `infer.py` tunes/self-validates on the same held-in samples it inferred from. See [infer.py](/D:/Projetos/MapleStory2/MapleShark2/Harness/analysis/infer.py:13).
- The 15 targets were manually hardcoded, not randomly or stratifiably selected. See [infer_extract.py](/D:/Projetos/MapleStory2/MapleShark2/Harness/analysis/infer_extract.py:13).
- The code does not read real scripts, so it is blind in that narrow sense. But “frozen, then scored” is unauditable: inference, claims, and result were committed together.
- The scoring implementation, inferred descriptions, generated scripts, and per-target results were deliberately left in `scratch_phase5`, which no longer exists.
- Hand-written V12 scripts are imperfect ground truth.
- Fixed observed length does not make a KMS2 pair “reliably correct”; it only makes byte boundaries easier. Same-width types and semantics remain unidentified.

Therefore the 61%/59% aggregates and the “74 reliably-correct fixed-family pairs” projection should not be treated as evidence of generalization. Assistive-only remains the right consequence.

5. Phase 6 exact-equivalence bar — DISAGREE

Identical outcome counts and consumed histograms under the same seed are necessary regression checks, not exact equivalence.

They can miss:

- Different packets changing outcome while aggregate counts remain equal.
- Different per-packet consumption with the same aggregate histogram.
- Signed/unsigned, int/float, or other equal-width retypes.
- Wrong labels, node paths, and nesting.
- Swapped equal-width fields.
- Wrong branch predicates whose branches consume equal widths.
- Different extracted values despite identical offsets.
- Missing modes not present in that seed.

The harness already records typed traces. Migration equivalence should compare per packet: outcome, consumed bytes, exception signature, and the ordered `(offset, width, type, label, node path, value)` trace. The prose-only results in [DESIGN.md](/D:/Projetos/MapleStory2/MapleShark2/Schema/DESIGN.md:173) are also not committed as reproducible CSV artifacts.

The compiler itself is real and deterministic; its `--check` succeeds. What fails is the word “exact.”

6. Resolver integration — PARTIAL

Quality tier → clean fraction is reasonable. “Newer build” is an unsupported final tie-breaker: it can prefer a distant future decoder over a temporally nearer source. Evidence strength, invariant status, and distance would be more defensible.

Concrete ways it can serve a wrong decoder:

- `env_sha` is cached forever. After the first successful resolution, changing `common.py` or `item.py` clears IronPython engines but not `ScriptManifest.envHashCache`; new module code can execute under an old accepted hash. See [ScriptManifest.cs](/D:/Projetos/MapleStory2/MapleShark2/MapleShark2/Tools/ScriptManifest.cs:169).
- PLAN says home rows are joined by `env_sha`, but the classifier checks only `script_sha`. See [manifest.py](/D:/Projetos/MapleStory2/MapleShark2/Harness/analysis/manifest.py:175).
- The product accepts any row whose `state` is `accept`; it does not require rule `3.0.0-invariants`.
- A home script always wins without quality or hash validation, even when it is known defective.
- Forty-two accepted STUB edges can resolve automatically, some consuming essentially nothing.
- Locale 0 is actually `MapleLocale.UNKNOWN`, not a real locale. The guard blocks known nonzero locales but cannot prove an old locale-less capture belongs to the calibrated region. See [MapleLocales.cs](/D:/Projetos/MapleStory2/MapleShark2/MapleShark2/Logging/MapleLocales.cs:2).
- The 12-character hashes are adequate against accidental changes, but are not a security boundary.

7. Oversold status claims

These are the overstatements I found:

- Phase 1 “DONE”: the GUI flow was not exercised live; `env_sha` staleness is not actually prevented; rule version is not enforced; classifier home evidence is not joined by `env_sha`.
- Phase 1b “DONE”: required temporal and external-ground-truth calibration was not performed or committed, and the v3 pipeline is non-idempotent.
- Phase 2a/2b “DONE”: the Ochi script fixes live in a non-version-controlled external tree, so the repaired deployed input cannot be reconstructed from this repository.
- Phase 3 “verified by unit tests”: no test project or committed 28-case test artifact exists. It is implementation plus an unpreserved ad hoc test run. Live session reaping also remains untested, as PLAN admits.
- Phase 4 “166 validated scripts”: 28 had no corpus data, 57 are explicitly partial, and zero-over-read does not validate field correctness. “43 new-coverage opcodes” is decoder availability/prefix coverage, not complete protocol coverage.
- Phase 5 “blind gate” and its numerical scores: the scoring evidence and scratch artifacts are absent; target representativeness is unestablished.
- Phase 6 “proven exactly equivalent”: only aggregate consumption behavior was compared, and the comparison outputs are not committed. The 98.3% figure is syntactic expressibility of `add_*` calls, not 98.3% of decoder semantics safely migrated.
- The top-level commit/status phrase “all phases executed to their gates” is therefore false for Phase 1b and unauditable for Phases 4–6.

8. Highest-value remaining work

Manually reverse-engineer and commit mode-stratified schemas for the top undocumented KMS2 variable/mode opcodes—the top ten account for 88.8% of undocumented traffic.

That work should use independent capture sessions, per-mode sampling, typed trace comparison, and human semantic labeling. It directly creates the missing KMS2 protocol knowledge. Live GUI testing, temporal calibration, and broader V12 generation matter, but none of them substitutes for understanding the high-traffic KMS2 packets that the inference experiment could not recover.

The one decision I would reverse: rule v3’s automatic gating on absolute invariants. Demote it to visible advisory/manual quarantine until semantic count identification, temporal calibration, reproducible calibration artifacts, and a non-circular classifier pipeline exist.
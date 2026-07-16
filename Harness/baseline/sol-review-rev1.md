The plan’s central quantitative justification does not hold. The `.msb` parser and corpus totals are correct, but “97.7% stable” does not support automatic KMS2 fallback, and “78.8% coverage” is only script-file availability—not demonstrated parsing coverage.

## Prioritized findings

1. **Critical — The 78.8% headline is almost entirely unsupported by the 97.7% test**

`final.py` counts a packet as “covered” whenever any older KMS2 directory contains a same-numbered script. It never examines the packet or runs that script.

For build 2546, the four scripts responsible for most of that estimate are:

| Opcode | Source build | Share of all 2546 traffic | Source→2546 length buckets |
|---|---:|---:|---:|
| `0x0058 IN` | 2527 | 43.55% | 5 → 1,168 |
| `0x001C IN` | 2507 | 11.07% | 5 → 13 |
| `0x002E IN` | 2528 | 7.01% | 3 → 9 |
| `0x003D IN` | 2520 | 4.55% | 3 → 58 |

Together they are 66.2% of all 2546 traffic and 84% of the claimed covered traffic. None belongs to the fixed-length population underlying 97.7%. One of them, `0x002E`, has only 19 source-build observations.

Therefore the fixed-length statistic provides almost no evidence for the actual 78.8% gain.

**Correction:** Rename 78.8% to “decoder-availability ceiling.” Before enabling fallback, build a per-`(source build, target build, opcode, direction, mode/variant)` compatibility matrix by actually executing the decoder. The four dominant opcodes should be the first experiment, not the entire archive.

2. **High — “All adjacent KMS2 builds are 97.7% stable” is factually misleading**

[kdrift.py](<C:/Users/atade/AppData/Local/Temp/claude/D--Projetos-MapleStory2/85c11678-c90a-4caf-abc3-c22a46b1f81e/scratchpad/kdrift.py>) first removes every build with at most 20,000 packets, then compares consecutive members of that filtered list. It produces 19 transitions from 20 builds, excluding 21 of the 41 KMS2 builds. Pairs such as `2496→2502` skip actual intervening builds.

Additionally:

- `733/17` aggregates repeated observations of the same opcodes across transitions; they are not 750 independent opcode structures.
- Each opcode needs only five packets to qualify.
- An opcode observed in only one exercised mode is classified as fixed even if the protocol is variable.
- Equal total length does not establish equal field order, types, branch meaning, or semantics.
- Different total length establishes a changed packet shape, but does not prove an incomplete old decoder cannot still parse a valid prefix.

The fixed subset is strongly biased toward small housekeeping packets. The examples—four-byte acknowledgements and small control messages—are not representative of movement, inventory, item, NPC-control, or state packets.

**Correction:** Report this as “97.7% agreement among repeated fixed-length observations in well-populated builds.” Calculate compatibility specifically for fallback candidates and their actual source-to-target spans. Report unique opcodes, traffic weighting, mode coverage, sample counts, and uncertainty separately.

3. **Critical — Lineage is not a sufficient automatic safety boundary**

Rejecting blanket KMS2→V12 fallback is well supported: 10 of 31 fixed pairs differ for 2546 versus V12, same-length matches are not proof, and many numeric opcode pairs are absent from the V12 corpus.

But the plan applies weaker skepticism within KMS2. “Same lineage” does not prevent:

- an opcode being repurposed;
- mode additions or removals;
- same-width semantic changes;
- removal of an opcode without a tombstone;
- a script being a one-off investigative artifact rather than an inheritable delta.

The sparse directories do not prove overlay intent. The current resolver never performs inheritance, and no README or manifest declares these scripts compatible with later builds. Sparse directories could simply contain the few packets investigated during each capture period.

**Correction:** Treat old scripts as candidates, not inherited truth. Resolution should consult an explicit generated/curated compatibility manifest. A script becomes automatic only for target variants that passed validation. Conversely, a V12 script that independently passes strong validation need not be forbidden merely because it crosses lineage; the safe boundary is evidence per decoder, not build family.

4. **High — Phase 1b’s validation gate cannot establish decoder correctness**

The plan’s rationale contains a category error: 30% of fields being named `Unknown` does not imply scripts under-read packets. Unknown fields are still consumed. Whether trailing bytes are normal must be measured on each script’s home build.

Over-read is a useful bounds violation, but it misses the most dangerous cases:

- reading the wrong same-width primitive;
- reordered fields with unchanged width;
- choosing a wrong branch that remains within bounds;
- misreading a count that happens to remain plausible;
- desynchronizing and later resynchronizing;
- decoding plausible garbage from valid UTF-8/UTF-16 or numeric bytes;
- stopping before a suffix where the protocol changed;
- exact consumption of a wholly wrong layout.

Comparing `%consumed` against the home build still misses all same-width errors and changes beyond an incomplete script’s stopping point.

The proposed aggregate `<1%` over-read threshold is also unsafe: on 1.5 million packets it permits roughly 15,000 bad parses, and heavy safe opcodes can mask total failure of a rare opcode.

**Correction:** Validate per compatibility edge and variant. Record a typed read trace `(offset, width, type, label, node/branch path, returned value class)`, plus invariants for booleans, enums, counts, strings, array lengths, and nested buffer sizes. Compare target traces and value distributions with the home build. Quarantine a candidate on its first unexplained exception or over-read; do not use a traffic-wide average.

Also report two distinct metrics:

- packet availability: a script was selected;
- byte/field coverage: how much the script actually and plausibly decoded.

5. **High — The harness is necessary, but Phase 0 understates its implementation scope**

A regression harness is not gold-plating here; the plan needs one before any fallback. But it cannot simply reuse the existing CLI:

- `Sniffer` references only `Maple2.PacketLib`.
- [FileLoader.cs](D:/Projetos/MapleStory2/MapleShark2/MapleShark2/Tools/FileLoader.cs:84) lives in the WinForms project and displays a `MessageBox` on errors.
- [ScriptManager.cs](D:/Projetos/MapleStory2/MapleShark2/MapleShark2/Tools/ScriptManager.cs:20) is coupled to `StructureForm`.
- [StructureForm.cs](D:/Projetos/MapleStory2/MapleShark2/MapleShark2/UI/StructureForm.cs:39) allocates UI tree nodes while decoding.
- Each script is currently recreated from disk on every execution; ten million packets will require compilation caching and controlled engine state.
- Per-packet JSONL for ten million packets will be unnecessarily large; aggregate output plus sampled failures is preferable.

The `ByteReader` concern is also slightly misdiagnosed. [ByteReader.cs](D:/Projetos/MapleStory2/MapleShark2/Maple2.PacketLib/Tools/ByteReader.cs:13) bounds against the backing array, not an `ArraySegment`. However, `FileLoader.ReadBytes(size)` currently returns a packet-sized array, and live decryption also creates an exact packet array. Thus over-read is detectable in the current file harness. The [MaplePacket.Search bug](D:/Projetos/MapleStory2/MapleShark2/MapleShark2/Logging/MaplePacket.cs:41) does not prove packets currently share an oversized backing array.

Pooling would make the segment-bound issue real.

**Correction:** Extract a small UI-independent decode core with a reader bounded by `(array, offset, count)`, a parse-event sink, cached compiled scripts, and aggregate reporting. Start with a stratified sample of the dominant fallback candidates, then scale to the corpus.

I independently performed a strict framing/EOF pass: all 1,417 files parsed completely, yielding exactly 10,095,157 packets, with 868 `0x2027` and 549 `0x2030` files and zero framing errors. The original handling of 32-bit size, 16-bit opcode, direction byte, and `0x2027` IV trailers is correct.

6. **High — Phase 5 assumes statistical identifiability the corpus does not have**

The four million KMS2 packets are extremely concentrated. Among the 311 undocumented opcode/direction pairs:

- median sample count is only 48;
- 69 have at most 5 packets;
- 173 have at most 100;
- 262 have at most 1,000;
- the top ten account for 88.8% of their traffic.

Per-offset entropy is especially fragile on variable-length packets: strings, arrays, repeated structures, and mixed modes shift all later offsets. Without clustering and alignment, entropy boundaries mostly measure content mixtures.

**Correction:** Make Phase 5 first prove itself blind on V12: hide known scripts, infer layouts, and score recovered boundaries/types/branches against the scripts and emulator. Cluster by mode/prefix/length family before offset analysis. Prioritize high-traffic undocumented opcodes and explicitly classify the rare tail as insufficient-data, rather than claiming four million packets are enough for all 311.

7. **High — Phase 4 overstates what `DebugByteWriter` provides**

The zero-call-site claim is correct, but “already does ~90%” is not supported.

[DebugByteWriter.cs](D:/Projetos/MapleStory2/PrivateMaple2/Maple2.Server.Core/Helpers/DebugByteWriter.cs:22) records primitive method names, runtime values, and offsets. It does not record:

- source field/member names;
- model-call boundaries or a nested tree;
- branch predicates;
- semantic discriminators;
- `WriteBytes` blobs and deflated sub-buffers.

It can preserve nested primitive writes passed through `IByteWriter`, but flattens them and loses their model context. That cannot replace `unk_N` fields without additional source analysis.

The “77 WriteTo / 24 ReadFrom” claim is stale against the current tree: direct search finds 166 `WriteTo` declarations and 50 `ReadFrom` declarations. `RuntimeHelpers.GetUninitializedObject` does break the `Item` branch based on pre-populated `Template/Pet/Music/Badge`, but it does not make every discriminator branch in every `ReadFrom` dead.

Finally, write-side tracing only covers server→client structures. Generating `RecvOp` constants does not generate client→server decoder layouts.

**Correction:** Scope Phase 4 to executed SendOp traces. Use a complete `IByteWriter` decorator plus Roslyn/source instrumentation for field names and call paths. Treat raw/deflated writes explicitly. Design a separate read-side extraction path for handlers.

8. **Medium — Several performance diagnoses are asserted more strongly than the code supports**

Supported:

- capture processing runs from the UI timer;
- `packetQueue` is uncapped;
- `TryDecrypt` is pooled but the GUI calls `Decrypt`;
- unshown partial-handshake sessions can remain in the `sessions` set;
- `Opcodes.Exists` is linear;
- `MapleStream` memmoves remaining bytes.

Overstated or wrong:

- Opcode sorting/rebuilding is not performed once per newly seen opcode. It occurs once per `BufferTcpPacket` call when the opcode count changed, although repeated rebuilds during login can still be expensive.
- The owner-draw handlers are not all no-ops: the column-header handler performs custom rendering. A 10 ms timer also does not itself prove 24,000 draw callbacks per second.
- Three byte-array copies are transient allocation stages, not three arrays retained per packet. The final decrypted payload is retained; earlier capture/reassembly arrays become collectible.
- Enabling server GC is not a remedy for unbounded retention and may increase desktop memory usage.

**Correction:** Profile the deployed build during login and a long session before prescribing changes. Separate retained memory from allocation rate. Fix ownership/lifetime before adopting pooled payloads.

9. **Medium — Sequencing needs a Phase −1, and locale deletion should be dropped**

The “which fork is the base?” question is already cheaply answerable. The deployed `MapleShark2.dll` reports product commit `4b5261b…`, which exists in the `MapleShark2` repository. Current `HEAD` is one small commit later. Its `Maple2.PacketLib.dll` reports the same `f781f354…` commit as the checked-out submodule. “Ochi” is therefore a deployment snapshot with a live scripts tree, not an untraceable source fork.

Before Phase 0:

- pin the analyzer source commit;
- treat Ochi’s `Scripts` as a separate runtime artifact;
- compare its shared modules with source resources;
- establish deterministic script behavior and fix known parser-script defects that would poison baselines.

Phase 2 provides little value. Locale occupies negligible space and remains useful metadata and namespace protection. “All captures happen to contain zero” does not prove no external historical scripts or captures use nonzero locales. Explicit lineage configuration already solves the resolver problem.

**Correction:** Preserve locale in storage and APIs, or deprecate it only after inventorying supported external assets. Move performance work after profiling. Run a Phase 5 feasibility benchmark before investing heavily in V12 generation.

10. **Medium — “Fork, not rewrite” is plausible, but not demonstrated by the evidence presented**

The `.msb` corpus contains already-decoded payloads. It validates file framing, not live capture, TCP reassembly, cipher correctness, loss behavior, or long-session robustness. Therefore it cannot substantiate “crypto/reassembly is correct and working.”

The conclusion is still likely directionally right: reuse of existing capture and protocol machinery is lower risk than a rewrite, and a rewrite cannot invent KMS2 structures. But it should be conditional on:

- tests over representative PCAP/live-session inputs;
- profiling;
- confirming required UX/workflows;
- isolating reusable protocol code from the current UI.

Phrase the decision as “extend and refactor the existing implementation unless Phase −1 tests expose a fundamental limitation,” not as already proven.

## Code claims that checked out

These are well supported:

- Exact-match/no-fallback in [ScriptManager.cs](D:/Projetos/MapleStory2/MapleShark2/MapleShark2/Tools/ScriptManager.cs:53) and [DefinitionsContainer.cs](D:/Projetos/MapleStory2/MapleShark2/MapleShark2/Logging/DefinitionsContainer.cs:24).
- `0x2027` versus `0x2030` framing in [FileLoader.cs](D:/Projetos/MapleStory2/MapleShark2/MapleShark2/Tools/FileLoader.cs:130).
- `MaplePacket.Search` exceeding its segment.
- `DefinitionsContainer.SaveProperties` using `return` for `0xFFFF`.
- The send/recv reader-writer inversion.
- Root module search path preceding the version directory.
- `item.py` using an unordered set for four stat blocks.
- `Inbound/0x0021.py` starting a second `if` chain at mode 13.
- `DebugByteWriter`/`Packet.DebugOf` having zero external call sites.
- The GUI using non-pooled `Decrypt`.

The revised safe core should be: establish a bounded headless decoder, measure home-build behavior, validate individual compatibility edges and variants, then enable only an allowlisted fallback. The current plan instead jumps from a biased protocol-shape proxy to lineage-wide automatic inheritance.
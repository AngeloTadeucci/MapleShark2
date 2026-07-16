# Declarative packet schema — design (Phase 6)

Status: incremental start. Compiler (`compile.py`), three migrated opcodes, and a harness
equivalence proof exist; see the bottom of this file and `../PLAN.md` §5 Phase 6.

## Why

The deployed decoders are hand-written IronPython. Measured over the Ochi tree (`coverage.py`):
**12,437 `add_*` field calls across 430 scripts, 24.4 % of them named literally `"Unknown"`**
(the V12 subtree alone is 4,714 calls / 26 % Unknown — the ~4,798 figure in `../PLAN.md`).
Three structural problems follow, all called out in the plan:

1. Field names are bare string literals — no schema, no cross-build diff, no validation that
   `0x0021` in build 2527 and 2546 describe the *same* field.
2. IronPython 3.4.1 has no `match`/`case`; `ScriptTranslator.cs:91` downgrades `switch`→`if`/`elif`
   with a header that admits *"you will certainly need to manually fix"*. Mode dispatch is
   copy-pasted `if/elif` ladders.
3. `item.py`'s ~150 magic-ID branches (`id / 100000 == 113`) are open-coded and silently desync.

A declarative schema fixes identity (names/types are data), makes dispatch first-class, and lets
one source of truth generate every build's decoder. Phases 0/1 give the regression harness that
makes migrating without behaviour change *provable* — which is the whole point of doing this now.

## Format: JSON (not YAML)

**Chosen: JSON.** Rationale:

- **The compiler must run on stdlib `py` (deliverable constraint).** Python's standard library has a
  JSON parser and *no* YAML parser. A YAML choice would force either a third-party dependency
  (violates the constraint) or a hand-rolled YAML subset parser (a new, untested surface exactly
  where correctness matters most). JSON is zero-dependency and total.
- **Reviewable diffs / pleasant authoring** — YAML's usual advantages — are recovered by *vocabulary
  design*, not by the container format: every field is a **single flat object on one line**
  (`{ "f": "i16", "n": "BufferSize" }`), so schemas read as one-op-per-line lists and diffs stay
  line-oriented. See `schemas/2527/Inbound/0x0058.json` — it is as skimmable as the `.py` it replaces.
- JSON is universally tooled (editors, `jq`, CI validators, `json.dumps(sort_keys=True)` for canonical
  hashing). YAML's footguns (`no`→`false`, sexagesimal, anchors) are pure downside for a format whose
  values are opcodes and type codes.

If hand-authoring ever becomes the bottleneck, a thin YAML→JSON front-end can be added *without
touching the compiler or the on-disk contract* — JSON stays the canonical intermediate.

## The schema language

Two schema *kinds*, discriminated by `"kind"`:

- `"opcode"` → compiles to one decoder `.py`.
- `"blocks"` → contributes reusable named blocks (the `common.py`/`item.py` pattern) to a generated
  `schema_common.py`.

### Opcode schema

```json
{ "kind": "opcode", "opcode": "0x004D", "build": 2546, "dir": "in",
  "doc": "…", "imports": ["schema_common"],
  "blocks": { "<local block>": { "params": [...], "body": [ <op> … ] } },
  "body": [ <op> … ] }
```

`blocks` here are *opcode-private* helper functions (e.g. `0x0058`'s `npc_control_buffer`), emitted as
local `def`s in the same file. Shared blocks live in `"blocks"` schema files instead.

### Ops (the body vocabulary)

Every op is a one-key-discriminated object. This is the full set the compiler implements:

| op | example | emits |
|---|---|---|
| **field** | `{ "f":"i16", "n":"BufferSize", "bind":"size" }` | `size = add_short("BufferSize")` |
| **raw bytes** | `{ "f":"bytes", "n":"Cap", "len":"13 * 4" }` | `add_field("Cap", 13 * 4)` |
| **node** | `{ "node":"JumpInfo", "expand":true, "do":[…] }` | `with Node("JumpInfo", True): …` |
| **block call** | `{ "call":"coordS", "args":["Position"] }` | `decode_coordS("Position")` |
| **loop** | `{ "loop":{"count":"count"}, "var":"i", "node":"NpcControl {i}", "expand":true, "do":[…] }` | `for i in range(count): with Node("NpcControl " + str(i), True): …` |
| **switch** | `{ "switch":"mode", "cases":{"3":[…],"9":[…]}, "else":[…] }` | `if mode == 3: … elif mode == 9: … else: …` |
| **if** | `{ "if":"seqId == -2 or seqId == -3", "do":[…], "elif":[{"cond":…,"do":…}], "else":[…] }` | `if …: … elif …: … else: …` |
| **escape** | `{ "py":["… raw IronPython …"] }` | verbatim, behind a loud comment |

**Type codes** (`"f"`) map 1:1 to `script_api.py` functions — this table is load-bearing, a wrong
map changes byte consumption:

`u8`→`add_byte` `i8`→`add_sbyte` `u16`→`add_ushort` `i16`→`add_short` (signed!) `u32`→`add_uint`
`i32`→`add_int` `u64`→`add_ulong` `i64`→`add_long` `f32`→`add_float` `f64`→`add_double`
`bool`→`add_bool` `str`→`add_str` (ushort-prefixed UTF-8) `wstr`→`add_unicode_str`
(ushort-prefixed ×2 UTF-16) `bytes`→`add_field(name, len)`.

`i16` mapping to the *signed* `add_short` is exactly why `SequenceId` can be `-2`; a `u16` slip would
silently break the JumpInfo branch. Types are explicit precisely so this is reviewable, not implicit.

### Expression grammar and the escape hatch

`if`/`switch`/`loop count`/`bytes len`/node-name placeholders all take **expressions over
previously-bound field values** (`bind` captures a read's value under a name). The grammar is
**constrained, not arbitrary Python**: the compiler parses each expression with the stdlib `ast` in
`eval` mode and walks it against a strict allowlist — bound identifiers, int/str/bool literals,
comparisons (`== != < <= > >=`), boolean (`and or not`), arithmetic (`+ - * / // %`) and bitwise
(`& | ^ << >> ~`) operators, parentheses. **Calls, attribute access, subscripts, lambdas,
comprehensions are rejected.** Valid expressions are re-emitted canonically via `ast.unparse` (this
canonicalisation is part of what makes output deterministic regardless of author whitespace), and
IronPython's expression syntax is a superset of the allowlist, so the text runs unchanged.

**Decision on the escape hatch.** The constrained grammar is deliberately rich enough for real
dispatch predicates, including `item.py`'s magic-ID pattern — `id // 100000 == 113`,
`id == 11400608 or id == 11500523` are pure `BinOp`/`Compare`/`BoolOp` and compile as-is. The
coverage census confirms this: `item.py`'s magic-ID branches are **not** in the needs-extension set.
So the primary answer is *a constrained expression grammar, not an escape-to-python block*.

An explicit `{"py":[…]}` escape op nonetheless exists as a **loud last resort** (emitted behind a
`# escape-to-python (schema could not express this)` comment). Justification for keeping it but
discouraging it: it disqualifies a schema from the static guarantees the vocabulary otherwise gives
(field-identity extraction, cross-build structural diff), so it must be visible in review and rare.
Measured need across the whole corpus: effectively zero — see coverage below.

## Shared blocks and per-build inheritance/override

Shared blocks mirror the `common.py`/`item.py`/`stats.py` reuse pattern. A `"blocks"` schema with no
`build` key defines **base** (all-builds) blocks; a `"blocks"` schema *with* a `build` key defines
**per-build overrides**.

Resolution, per build `B`: `resolved = base ∪ overrides[B]`, with `overrides[B]` winning on name
collision. The compiler emits:

- `<root>/schema_common.py` — the base set.
- `<root>/0/<B>/schema_common.py` — **only when build B overrides something**, carrying the *full*
  resolved set as a drop-in shadow.

This deliberately reproduces the version-folder-ahead-of-shared-root semantics that `../PLAN.md` §6.6
fixed (`ScriptManager.cs` version dir before the shared root on `sys.path`, tested by the harness's
`--version-path-first`). Under `--version-path-first`, `from schema_common import *` in a build-`B`
decoder resolves `0/<B>/schema_common.py` first and falls back to the root copy — identical shadowing
to the deployed resolver, so a per-build block override behaves exactly like a version-folder module
override does today. No new resolution concept is introduced; the schema rides the mechanism that
already ships.

## Identity / hashing (manifest evidence binding)

The Phase 1 manifest binds every accepted edge to `script_sha` (SHA-256 of the opcode `.py`) and
`env_sha` (hash of the importable-module surface + `sys.path` order), and invalidates the edge when
either changes (`ScriptHost.FileSha`/`EnvHash`). The schema plugs into this **without changing the
harness**:

- **Determinism is the contract.** Same schema → byte-identical `.py` (fixed op emission order,
  `\n`-only newlines, canonical `ast.unparse` expressions, JSON-insertion-order case ladders,
  4-space indent). Verified: two independent compiles `diff -r` clean. Therefore the harness's
  existing `script_sha` over the generated `.py` is a **stable, content-addressed identity for the
  schema**. A schema edit changes the `.py` bytes → changes `script_sha` → invalidates the edge,
  exactly as a hand-edit does. Nothing downstream needs to know a schema was involved.
- **Provenance without a new column.** Each generated file carries a `# schema_sha: <12hex>` header —
  SHA-256 of the *canonical* schema JSON (`json.dumps(sort_keys=True, separators=(',',':'))`). This
  ties the emitted `.py` back to the exact schema object for audit, and because it is a pure function
  of the schema it does not disturb determinism. `schema_sha` and `script_sha` move together; the
  former is the human-facing analog of the latter.
- Shared-block modules carry their own `schema_sha(blocks)` header, and because they are `.py` on the
  import path they already fold into `env_sha` — so a shared-block edit invalidates every dependent
  edge through the mechanism the harness already implements.

## Migration story (purely additive; zero harness/analyzer change)

The design is *additive* — schemas and `.py` coexist, and schemas **compile to `.py`**:

1. `script_api.py` is the fixed harness/GUI contract (`ParseSink`'s duck-typed surface). It is
   **never generated** — it is copied into the scripts root unchanged. Generated decoders call the
   same `add_*`/`Node` API the hand-written ones do.
2. A schema compiles to an ordinary decoder `.py` in the deployed tree's exact style and layout
   (`0/<build>/<Inbound|Outbound>/0x00NN.py` + `schema_common.py` at the root). The deployed analyzer,
   the resolver (`ScriptManifest.cs`), and the harness see only `.py` files and their hashes — they
   are byte-for-byte oblivious to whether a human or `compile.py` wrote them.
3. Migration proceeds opcode-by-opcode: translate a script to a schema, compile, run the harness
   equivalence check (below), and once the compiled output is proven identical, the schema becomes the
   source of truth and the hand-written `.py` is regenerated from it. No big-bang rewrite; the tree is
   always in a runnable state; every step is regression-checked by Phase 0/1 infrastructure that needs
   **no modification**.

## Equivalence proof (deliverable 3)

Three real scripts, chosen for feature coverage, hand-translated to schemas, compiled, and run
through the committed harness binary against the same seeded reservoir sample as the real tree
(`--sample 1000 --seed 1 --version-path-first`, same seed ⇒ same packets ⇒ exact comparison):

| opcode (build) | features exercised | ok_exact | under | over | consumed_hist | verdict |
|---|---|---|---|---|---|---|
| `0x0058` IN (2527) NPC_CONTROL | count loop, per-iter node, local block, shared blocks (coordS/coordF), nested node, `if b`, compound `if seqId==-2 or ==-3`, state `switch` w/ empty cases | **449 / 449** | 0 | 0 | `100:449` | **identical** |
| `0x004D` IN (2546) mode dispatch | first-byte `switch` (3 modes), count loop, `wstr`/`i64`/`i32`, a real NegativeLength over-read | **830** | 169 | 1 | `2:1\|3:165\|5:1\|44:2\|48:1\|100:830` | **identical** (incl. `over_sigs`) |
| `0x0016` IN (2546) REQUEST_FIELD_ENTER | simple fixed, `message==0` guard, shared `coordF` | **314 / 314** | 0 | 0 | `100:314` | **identical** |

Only `script_sha`/`env_sha` differ between the schema tree and the real tree (different files, by
construction) — every behavioural column (`ok_exact`/`under_read`/`over_read`/`negative_length`/
`consumed_hist`, and even the `over_sigs` failure signature) is byte-identical. The equivalence bar
is met exactly.

## Migration-coverage breakdown (deliverable 4)

`coverage.py` parses every decoder with `ast` and classifies each `add_*` call by whether the schema
vocabulary above can express its enclosing construct.

**Full Ochi tree (430 scripts, 12,437 `add_*` calls):**

| bucket | calls | share |
|---|---|---|
| **Covered by current vocabulary** | 12,223 | **98.3 %** |
| Needs extension: `foreach` over a literal list (`for i in ["Active","Passive",…]`) | 192 | 1.5 % |
| Needs extension: `remaining()` inside a condition (`if remaining() > 72`) | 20 | 0.2 % |
| Needs extension: sentinel `while` loop (`while m != 1`) — **1 script** | 1 | <0.1 % |
| Nested-arith on a read (expressible; flagged for review) | 1 | <0.1 % |

The V12 subtree (the `../PLAN.md` scope) is 4,714 calls with the same ~98 % coverage.

**What this says about extensions and the escape hatch:**

- **The magic-ID dispatch is already covered.** `item.py`'s `id // 100000 == 113` and
  `id == 11400608 or …` compile through the constrained expression grammar untouched — they do *not*
  appear in the needs-extension set. This directly answers the escape-hatch question: a **constrained
  expression grammar** is the right primitive, and it is sufficient for the hardest real dispatch in
  the corpus. Arbitrary-Python escape is *not* required for `item.py`.
- The only genuinely-missing constructs are two small, bounded extensions:
  1. **`foreach` over a literal list** (1.5 %): the skill-tree / stat-delta blocks iterate a fixed list
     of node labels (`["Active","Passive","Special","Consumable"]`). A `{"foreach":[…], "var":"i",
     "node":"{i}", …}` op covers every occurrence — no expression escape, just a bounded loop over
     literals. This is the single highest-value extension.
  2. **`remaining()` as a grammar primitive** (0.2 %): whitelist a nullary `remaining()` in the
     expression grammar so `if remaining() > 36` and a `while remaining()`-style loop compile. Pair it
     with a `while` op to also absorb the one sentinel loop.
- The explicit `{"py":[…]}` escape is therefore **genuinely last-resort**: after the two extensions
  above, effectively nothing in the corpus needs arbitrary Python. Keeping it is cheap insurance;
  needing it is a code smell.

Recommended extension order for the full migration: `foreach`-literal → `remaining()`/`while`. That
lifts coverage from 98.3 % to ~99.9 % of `add_*` calls with two additive, well-scoped ops, leaving
the escape hatch for the long tail that should probably be fixed by hand anyway.

## Files

```
Schema/
  DESIGN.md                       this file
  compile.py                      stdlib schema → IronPython compiler (deterministic)
  coverage.py                     ast-based migration-coverage census
  schemas/
    blocks/common.json            shared blocks: coordS, coordF
    2527/Inbound/0x0058.json      NPC_CONTROL
    2546/Inbound/0x004D.json      mode dispatch
    2546/Inbound/0x0016.json      REQUEST_FIELD_ENTER
```

Reproduce: `py compile.py --schemas schemas --out <root>`, copy `script_api.py` into `<root>`, then
run the harness binary against `<root>` and the Ochi tree with identical flags and diff the CSVs.

#!/usr/bin/env py
"""
MapleShark2 declarative packet schema -> IronPython 3.4 decoder compiler.

Phase 6 (see ../PLAN.md). Reads declarative JSON schemas and emits IronPython
decoder scripts in the exact style the deployed tree uses (`from script_api import *`,
`add_byte(...)`, `with Node(...)`, ...). The generated scripts are byte-for-byte
deterministic: same schema in -> identical .py out, so `script_sha` in the harness /
resolver manifest binds to schema content transitively.

STDLIB ONLY (runs with `py compile.py ...`). No YAML, no third-party deps.

Layout produced under --out <root> (a scripts root the harness can consume directly):

    <root>/schema_common.py              base shared blocks
    <root>/0/<build>/schema_common.py    per-build shared-block OVERRIDE set (only when a
                                         build overrides a block) -- shadows the base copy
                                         under --version-path-first, mirroring PLAN.md 6.6
    <root>/0/<build>/<Inbound|Outbound>/0x00NN.py   one decoder per opcode schema

`script_api.py` is NOT generated -- it is the fixed harness/GUI contract and must be
copied into <root> unchanged (see DESIGN.md "Migration story").

Usage:
    py compile.py --schemas <dir> --out <dir> [--check]

    --schemas   directory tree of *.json schema files (recursively scanned)
    --out       output scripts root
    --check     compile to memory and verify determinism (compile twice, compare),
                do not write files
"""

import argparse
import ast
import hashlib
import json
import os
import sys

# ----------------------------------------------------------------------------
# Type code -> script_api.py function name. This mapping is load-bearing: it must
# match the deployed API surface exactly or byte consumption diverges.
# ----------------------------------------------------------------------------
TYPE_FUNC = {
    "u8": "add_byte",       # unsigned byte
    "i8": "add_sbyte",      # signed byte
    "u16": "add_ushort",
    "i16": "add_short",     # SIGNED int16 (matters: seqId == -2 needs a signed read)
    "u32": "add_uint",
    "i32": "add_int",
    "u64": "add_ulong",
    "i64": "add_long",
    "f32": "add_float",
    "f64": "add_double",
    "bool": "add_bool",     # 1 byte, false iff 0
    "str": "add_str",       # ushort length prefix, 1 byte/char, UTF-8
    "wstr": "add_unicode_str",  # ushort length prefix (*2), UTF-16
    # "bytes" handled specially -> add_field(name, length)
}

INDENT = "    "


class SchemaError(Exception):
    pass


# ----------------------------------------------------------------------------
# Constrained expression grammar. Conditions / counts / lengths / switch keys are
# small arithmetic-boolean expressions over previously-bound field values. We parse
# with the stdlib `ast` in eval mode, walk the tree against a strict node allowlist
# (no calls, no attribute access, no subscripts, no names-with-dots), then re-emit
# canonically with ast.unparse. Canonical re-emission is what guarantees determinism
# regardless of author whitespace, and IronPython's expression syntax is a superset
# of what we allow, so the emitted text runs unchanged.
#
# This is the "escape hatch" answer: arbitrary Python is NOT allowed here; the grammar
# is intentionally just rich enough for real dispatch predicates, incl. item.py's
# magic-ID pattern `id // 100000 == 113`. For the rare construct the vocabulary can't
# reach, an explicit {"py": [...]} op emits verbatim lines (see emit_op) -- loud,
# reviewable, and the exception rather than the rule.
# ----------------------------------------------------------------------------
_ALLOWED_NODES = (
    ast.Expression,
    ast.BoolOp, ast.And, ast.Or,
    ast.UnaryOp, ast.Not, ast.USub, ast.UAdd, ast.Invert,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
    ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift,
    ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.Name, ast.Load, ast.Constant,
)


def compile_expr(src):
    """Validate `src` against the constrained grammar and return canonical text."""
    if not isinstance(src, (str, int)):
        raise SchemaError("expression must be a string or int, got %r" % (src,))
    text = str(src)
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError as e:
        raise SchemaError("bad expression %r: %s" % (text, e))
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise SchemaError(
                "disallowed construct %s in expression %r "
                "(only bound identifiers, int/str literals, comparisons, boolean and "
                "arithmetic/bitwise operators are permitted; use {\"py\": [...]} to escape)"
                % (type(node).__name__, text))
        if isinstance(node, ast.Constant) and not isinstance(node.value, (int, str, bool)):
            raise SchemaError("only int/str/bool literals allowed, got %r" % (node.value,))
    return ast.unparse(tree.body)


def compile_template(src):
    """Node-name template with {var} placeholders -> a Python string expression.

    "NpcControl {i}"  -> '"NpcControl " + str(i)'
    "JumpInfo"        -> '"JumpInfo"'
    "{label}CoordS"   -> 'str(label) + "CoordS"'
    """
    if not isinstance(src, str):
        raise SchemaError("node/name template must be a string, got %r" % (src,))
    parts = []
    buf = ""
    i = 0
    while i < len(src):
        c = src[i]
        if c == "{":
            end = src.find("}", i)
            if end == -1:
                raise SchemaError("unterminated { in template %r" % src)
            var = src[i + 1:end].strip()
            if buf:
                parts.append(json.dumps(buf))
                buf = ""
            parts.append("str(%s)" % compile_expr(var))
            i = end + 1
        else:
            buf += c
            i += 1
    if buf or not parts:
        parts.append(json.dumps(buf))
    return " + ".join(parts)


# ----------------------------------------------------------------------------
# Op emitters. Each returns a list of source lines (already indented at `depth`).
# ----------------------------------------------------------------------------
def line(depth, text):
    return INDENT * depth + text


def emit_body(ops, depth):
    if not isinstance(ops, list):
        raise SchemaError("body must be a list of ops, got %r" % (ops,))
    out = []
    for op in ops:
        out.extend(emit_op(op, depth))
    if not out:
        out.append(line(depth, "pass"))
    return out


def _field_call(op):
    t = op["f"]
    name = op.get("n", "")
    if t == "bytes":
        length = op.get("len", 0)
        return "add_field(%s, %s)" % (json.dumps(name), compile_expr(length))
    if t not in TYPE_FUNC:
        raise SchemaError("unknown field type %r" % t)
    return "%s(%s)" % (TYPE_FUNC[t], json.dumps(name))


def emit_op(op, depth):
    if not isinstance(op, dict):
        raise SchemaError("op must be an object, got %r" % (op,))

    # --- primitive / string / bytes field ---------------------------------
    if "f" in op:
        call = _field_call(op)
        if "bind" in op:
            if op["f"] == "bytes":
                raise SchemaError("cannot bind the result of a raw 'bytes' field")
            return [line(depth, "%s = %s" % (_ident(op["bind"]), call))]
        return [line(depth, call)]

    # --- call a shared/local block ---------------------------------------
    if "call" in op:
        args = op.get("args", [])
        rendered = ", ".join(json.dumps(a) if isinstance(a, str) else compile_expr(a) for a in args)
        return [line(depth, "decode_%s(%s)" % (_ident(op["call"]), rendered))]

    # --- count/fixed loop (checked before 'node': a loop may carry a per-
    #     iteration node, so it owns both the 'loop' and 'node' keys) --------
    if "loop" in op:
        spec = op["loop"]
        var = _ident(op.get("var", "i"))
        if "count" in spec:
            rng = "range(%s)" % compile_expr(spec["count"])
        elif "times" in spec:
            rng = "range(%s)" % compile_expr(spec["times"])
        else:
            raise SchemaError("loop needs 'count' or 'times'")
        head = line(depth, "for %s in %s:" % (var, rng))
        inner = op.get("do", [])
        if "node" in op:
            expand = bool(op.get("expand", False))
            node_line = line(depth + 1, "with Node(%s, %s):" % (
                compile_template(op["node"]), "True" if expand else "False"))
            return [head, node_line] + emit_body(inner, depth + 2)
        return [head] + emit_body(inner, depth + 1)

    # --- named node ------------------------------------------------------
    if "node" in op:
        expand = bool(op.get("expand", False))
        name_expr = compile_template(op["node"])
        head = line(depth, "with Node(%s, %s):" % (name_expr, "True" if expand else "False"))
        return [head] + emit_body(op.get("do", []), depth + 1)

    # --- switch (first-byte mode dispatch / value dispatch) ---------------
    if "switch" in op:
        sel = compile_expr(op["switch"])
        cases = op.get("cases", {})
        if not isinstance(cases, dict):
            raise SchemaError("switch cases must be an object")
        out = []
        first = True
        for key, body in cases.items():  # JSON preserves author order
            kw = "if" if first else "elif"
            first = False
            cond = "%s == %s" % (sel, compile_expr(key))
            out.append(line(depth, "%s %s:" % (kw, cond)))
            out.extend(emit_body(body, depth + 1))
        if "else" in op:
            if first:
                # switch with only an else -> plain body
                return emit_body(op["else"], depth)
            out.append(line(depth, "else:"))
            out.extend(emit_body(op["else"], depth + 1))
        if not out:
            return [line(depth, "pass")]
        return out

    # --- conditional -----------------------------------------------------
    if "if" in op:
        out = [line(depth, "if %s:" % compile_expr(op["if"]))]
        out.extend(emit_body(op.get("do", []), depth + 1))
        for clause in op.get("elif", []):
            out.append(line(depth, "elif %s:" % compile_expr(clause["cond"])))
            out.extend(emit_body(clause.get("do", []), depth + 1))
        if "else" in op:
            out.append(line(depth, "else:"))
            out.extend(emit_body(op["else"], depth + 1))
        return out

    # --- explicit escape-to-python (loud, reviewable, last resort) --------
    if "py" in op:
        raw = op["py"]
        if isinstance(raw, str):
            raw = [raw]
        return [line(depth, "# --- escape-to-python (schema could not express this) ---")] + \
               [line(depth, str(l)) for l in raw]

    raise SchemaError("unrecognized op: %r" % (op,))


def _ident(name):
    if not isinstance(name, str) or not name.isidentifier():
        raise SchemaError("not a valid identifier: %r" % (name,))
    return name


# ----------------------------------------------------------------------------
# Schema loading / block resolution / module emission
# ----------------------------------------------------------------------------
def canonical_sha(obj):
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:12]


def emit_block_def(name, spec):
    params = spec.get("params", [])
    for p in params:
        _ident(p)
    header = "def decode_%s(%s):" % (_ident(name), ", ".join(params))
    body = emit_body(spec.get("body", []), 1)
    return [header] + body


def emit_common_module(blocks, schema_shas):
    """Emit a schema_common.py from a {name: blockspec} dict (author order)."""
    lines = [
        "# GENERATED FROM SCHEMA -- do not edit by hand. See Schema/DESIGN.md.",
        "# schema_sha(blocks): %s" % canonical_sha(blocks),
        "from script_api import *",
        "",
        "",
    ]
    first = True
    for name, spec in blocks.items():
        if not first:
            lines.append("")
            lines.append("")
        first = False
        lines.extend(emit_block_def(name, spec))
    return "\n".join(lines) + "\n"


def emit_opcode_module(schema):
    opcode = schema["opcode"]
    doc = schema.get("doc")
    imports = schema.get("imports", [])
    local_blocks = schema.get("blocks", {})

    lines = [
        "# GENERATED FROM SCHEMA -- do not edit by hand. See Schema/DESIGN.md.",
        "# opcode: %s  build: %s  dir: %s" % (opcode, schema["build"], schema["dir"]),
        "# schema_sha: %s" % canonical_sha(schema),
    ]
    if doc:
        lines.append("''' %s '''" % doc)
    lines.append("from script_api import *")
    for imp in imports:
        lines.append("from %s import *" % _ident(imp))
    lines.append("")

    # local (opcode-private) blocks
    for name, spec in local_blocks.items():
        lines.append("")
        lines.extend(emit_block_def(name, spec))
        lines.append("")

    lines.append("")
    lines.extend(emit_body(schema["body"], 0))
    return "\n".join(lines) + "\n"


def load_schemas(root):
    schemas = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.endswith(".json"):
                continue
            path = os.path.join(dirpath, fn)
            with open(path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError as e:
                    raise SchemaError("%s: %s" % (path, e))
            data["__path__"] = path
            schemas.append(data)
    return schemas


def build(schemas):
    """Return {relpath: text} for every module to emit. Deterministic."""
    # Partition
    base_blocks = {}          # name -> spec (base / all-builds)
    build_block_overrides = {}  # build -> {name -> spec}
    opcodes = []
    for s in schemas:
        kind = s.get("kind")
        if kind == "blocks":
            b = s.get("build")
            target = base_blocks if b is None else build_block_overrides.setdefault(int(b), {})
            for name, spec in s.get("blocks", {}).items():
                if name in target:
                    raise SchemaError("duplicate block %r (build=%s)" % (name, b))
                target[name] = spec
        elif kind == "opcode":
            opcodes.append(s)
        else:
            raise SchemaError("%s: unknown schema kind %r" % (s.get("__path__"), kind))

    out = {}
    schema_shas = {}

    # Base shared module at the root.
    if base_blocks:
        out["schema_common.py"] = emit_common_module(base_blocks, schema_shas)

    # Per-build override modules shadow the base copy under --version-path-first,
    # mirroring PLAN.md 6.6's version-folder-ahead-of-shared-root semantics. Each
    # build override module carries the FULL resolved set (base + overrides) so it is
    # a drop-in shadow.
    for b, overrides in sorted(build_block_overrides.items()):
        resolved = dict(base_blocks)
        resolved.update(overrides)  # per-build override wins
        rel = os.path.join("0", str(b), "schema_common.py")
        out[rel.replace("\\", "/")] = emit_common_module(resolved, schema_shas)

    # Opcode decoders.
    for s in sorted(opcodes, key=lambda x: (int(x["build"]), x["dir"], x["opcode"])):
        build_no = int(s["build"])
        direction = "Outbound" if s["dir"].lower() in ("out", "outbound") else "Inbound"
        opcode = s["opcode"]
        if not opcode.lower().startswith("0x"):
            raise SchemaError("opcode must be 0xNNNN, got %r" % opcode)
        fname = "0x%04X.py" % int(opcode, 16)
        rel = "/".join(["0", str(build_no), direction, fname])
        text = emit_opcode_module(s)
        if rel in out:
            raise SchemaError("two schemas target %s" % rel)
        out[rel] = text

    return out


def main(argv):
    ap = argparse.ArgumentParser(description="Compile declarative packet schemas to IronPython decoders.")
    ap.add_argument("--schemas", required=True, help="schema source dir (recursively scanned for *.json)")
    ap.add_argument("--out", help="output scripts root")
    ap.add_argument("--check", action="store_true", help="verify determinism, do not write")
    args = ap.parse_args(argv)

    schemas = load_schemas(args.schemas)
    modules = build(schemas)

    # Determinism self-check: compile a second time and compare.
    modules2 = build(load_schemas(args.schemas))
    if modules != modules2:
        print("ERROR: non-deterministic output", file=sys.stderr)
        return 1

    if args.check or not args.out:
        for rel in sorted(modules):
            print("%s  (%d bytes)" % (rel, len(modules[rel].encode("utf-8"))))
        print("OK: %d module(s), deterministic" % len(modules), file=sys.stderr)
        return 0

    for rel, text in sorted(modules.items()):
        dest = os.path.join(args.out, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        # newline="" so we control exact bytes (\n only) -> byte-identical across OSes.
        with open(dest, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        print("wrote %s" % dest)
    print("OK: %d module(s)" % len(modules), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

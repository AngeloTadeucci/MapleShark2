#!/usr/bin/env py
"""
Migration-coverage census for the declarative schema (Phase 6, deliverable 4).

Scans every decoder script in the Ochi tree, parses each with the stdlib `ast`, and
classifies every add_*/decode_* call by whether the schema vocabulary in compile.py can
express the construct it lives in -- or whether it needs a schema extension (and which).

STDLIB ONLY. Run:  py coverage.py [--scripts <dir>]
"""

import argparse
import ast
import os
import sys
from collections import Counter

DEFAULT_SCRIPTS = r"D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts"

# The field-producing API (each call consumes bytes). add_field == raw bytes.
FIELD_FUNCS = {
    "add_byte", "add_sbyte", "add_ushort", "add_short", "add_uint", "add_int",
    "add_ulong", "add_long", "add_float", "add_double", "add_bool",
    "add_str", "add_unicode_str", "add_field",
    "add_byte_coord", "add_short_coord", "add_float_coord",
}
# Calls the schema models directly (block invocation) or as structural no-ops.
STRUCT_FUNCS = {"start_node", "end_node", "log"}

# Modules that are pure API/lib, not decoders -- excluded from the call census.
SKIP_BASENAMES = {"script_api.py"}


class Classifier(ast.NodeVisitor):
    def __init__(self):
        self.field_calls = 0
        self.covered = 0
        self.needs_ext = 0
        self.reasons = Counter()          # reason -> field-call count
        self.unknown_named = 0
        self.block_calls = 0              # decode_* invocations
        self.enclosure_ext = []          # stack of active extension reasons

    # ---- expression-grammar check (mirrors compile_expr's allowlist) ------
    ALLOWED_EXPR = (
        ast.BoolOp, ast.And, ast.Or,
        ast.UnaryOp, ast.Not, ast.USub, ast.UAdd, ast.Invert,
        ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
        ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift,
        ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
        ast.Name, ast.Load, ast.Constant,
    )

    def expr_ok(self, node):
        for n in ast.walk(node):
            if not isinstance(n, self.ALLOWED_EXPR):
                return False
            if isinstance(n, ast.Constant) and not isinstance(n.value, (int, str, bool)):
                return False
        return True

    # ---- helpers ---------------------------------------------------------
    @staticmethod
    def call_name(node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            return node.func.id
        return None

    def is_range_call(self, node):
        return self.call_name(node) == "range"

    def is_node_ctx(self, item):
        # with Node(...) as ...:  -> context expr is a Call to Node
        return isinstance(item.context_expr, ast.Call) and \
            isinstance(item.context_expr.func, ast.Name) and item.context_expr.func.id == "Node"

    # ---- traversal with an enclosure-extension stack ---------------------
    def push(self, reason):
        self.enclosure_ext.append(reason)

    def pop(self):
        self.enclosure_ext.pop()

    def current_ext(self):
        return self.enclosure_ext[-1] if self.enclosure_ext else None

    def visit_Module(self, node):
        self.generic_body(node.body)

    def visit_FunctionDef(self, node):
        # block definition: params must be simple (no *args/defaults with calls)
        self.generic_body(node.body)

    def generic_body(self, body):
        for stmt in body:
            self.visit_stmt(stmt)

    def visit_stmt(self, stmt):
        # Assignment: name = <call/expr>
        if isinstance(stmt, ast.Assign):
            self.handle_value(stmt.value)
            return
        if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self.handle_value(stmt.value)
            return
        if isinstance(stmt, ast.Expr):
            self.handle_value(stmt.value)
            return
        if isinstance(stmt, ast.If):
            ext = None if self.expr_ok(stmt.test) else "cond:non-grammar-expression"
            if ext:
                self.push(ext)
            self.generic_body(stmt.body)
            self.generic_body(stmt.orelse)
            if ext:
                self.pop()
            return
        if isinstance(stmt, ast.For):
            if self.is_range_call(stmt.iter):
                # count/fixed loop -- expressible
                self.generic_body(stmt.body)
                self.generic_body(stmt.orelse)
            else:
                # for x in {..}/[..]/other -- needs a foreach-over-literal extension
                self.push("loop:foreach-literal-or-nonrange")
                self.generic_body(stmt.body)
                self.generic_body(stmt.orelse)
                self.pop()
            return
        if isinstance(stmt, ast.With):
            node_ctx = all(self.is_node_ctx(it) for it in stmt.items)
            if node_ctx:
                self.generic_body(stmt.body)
            else:
                self.push("with:non-node-context")
                self.generic_body(stmt.body)
                self.pop()
            return
        if isinstance(stmt, ast.FunctionDef):
            self.visit_FunctionDef(stmt)
            return
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass)):
            return
        if isinstance(stmt, (ast.While, ast.Try)):
            reason = "while-loop" if isinstance(stmt, ast.While) else "try-except"
            self.push(reason)
            for sub in ast.iter_child_nodes(stmt):
                if isinstance(sub, ast.stmt):
                    self.visit_stmt(sub)
            self.pop()
            return
        # Return / AugAssign / Delete / etc. -- structural, may carry a call
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call):
                self.tally_call(sub, extra=None)

    def handle_value(self, value):
        """A call or expression on the RHS of an assign / as a statement."""
        name = self.call_name(value)
        if name in FIELD_FUNCS:
            self.tally_call(value)
            return
        if name and name.startswith("decode_"):
            self.block_calls += 1
            # arguments may embed calls; check for field calls nested in args
            for arg in value.args:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Call) and self.call_name(sub) in FIELD_FUNCS:
                        self.tally_call(sub)
            return
        if name in STRUCT_FUNCS or name == "Node":
            return
        # Some other expression: descend for any nested field calls (e.g. count = add_int(...) * 2)
        found = False
        for sub in ast.walk(value):
            if isinstance(sub, ast.Call) and self.call_name(sub) in FIELD_FUNCS:
                self.tally_call(sub, extra="nested-arith-on-read" if not found else None)
                found = True

    def tally_call(self, call, extra="_default"):
        self.field_calls += 1
        # Unknown-named?
        if call.args:
            a0 = call.args[0]
            if isinstance(a0, ast.Constant) and isinstance(a0.value, str) and \
                    a0.value.strip().lower() == "unknown":
                self.unknown_named += 1
        ext = self.current_ext()
        if extra not in (None, "_default"):
            ext = ext or extra
        if ext:
            self.needs_ext += 1
            self.reasons[ext] += 1
        else:
            self.covered += 1


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--scripts", default=DEFAULT_SCRIPTS)
    args = ap.parse_args(argv)

    total = Classifier()
    files = 0
    parse_fail = []
    for dirpath, _dirs, fnames in os.walk(args.scripts):
        for fn in sorted(fnames):
            if not fn.endswith(".py") or fn in SKIP_BASENAMES:
                continue
            path = os.path.join(dirpath, fn)
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
            try:
                tree = ast.parse(src)
            except SyntaxError as e:
                parse_fail.append((path, str(e)))
                continue
            files += 1
            total.visit(tree)

    print("scripts scanned         : %d  (parse failures: %d)" % (files, len(parse_fail)))
    for p, e in parse_fail:
        print("  PARSE-FAIL %s: %s" % (p, e))
    print("total add_* field calls : %d" % total.field_calls)
    print('named "Unknown"         : %d  (%.1f%%)' % (
        total.unknown_named, 100.0 * total.unknown_named / max(1, total.field_calls)))
    print("decode_* block calls    : %d" % total.block_calls)
    print()
    print("COVERED by schema vocab : %d  (%.1f%%)" % (
        total.covered, 100.0 * total.covered / max(1, total.field_calls)))
    print("NEEDS extension/escape  : %d  (%.1f%%)" % (
        total.needs_ext, 100.0 * total.needs_ext / max(1, total.field_calls)))
    print()
    print("extension reasons (by field-call count):")
    for reason, n in total.reasons.most_common():
        print("  %-34s %6d  (%.1f%%)" % (reason, n, 100.0 * n / max(1, total.field_calls)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

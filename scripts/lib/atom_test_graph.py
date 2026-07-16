# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# atom_test_graph.py — DERIVE the atom-code <-> test reference graph (Layer A3).
#
# Why this exists:
#   A3's own docstring says the implementation tag is "earned by CODE READ". That
#   is the defect one level up, and R311y339-y341 cost three rounds to it: reading
#   reaches a CLAIM ("PARTIAL, named residual"), never a proof. R311y342 then found
#   a live wire defect (an alias id wider than both upstreams' u16) that reading had
#   only ever labelled -- a failing test settled it in seconds.
#
#   So COMPLETE must rest on a test, and the join must be DERIVED, not authored.
#   This module is the A3 twin of A4's `crossimpl_corpus.py`: A4 derives WHICH tests
#   can witness a foreign impl by resolving the harness call graph; this derives
#   WHICH tests reference an atom's OWN cfg-gated code.
#
# Why the naive rule was rejected (R311y343, measured before building):
#   "a test whose #[cfg] names the atom" rejects 9 of 46 COMPLETE atoms. All 9 are
#   FALSE positives -- their proof is an integration test in a SIBLING crate, where
#   the manifest enables the feature and no cfg appears at all. codec-fragment is
#   the type case: `layer3_fragment.rs:27` does `use wz_codecs::fragment::Fragment`,
#   and that module is exactly what `#[cfg(feature = "codec-fragment")]` gates
#   (`wz-codecs/src/lib.rs`). The cfg and the test never meet in one file. So the
#   join cannot be cfg-to-cfg; it must go through the SYMBOL the cfg gates.
#
# The derivation, in two arms (neither authored):
#   ARM 1 (ownership) -- atom -> the symbols its cfg gates. NAMING a feature in a
#       cfg is not owning the item: `send_wire` sits behind
#       `any(declare-final, declare-subscriber, ..)` with 8+ OR-contributors, and
#       turning declare-final off elides NOTHING there. So the cfg is parsed as a
#       BOOLEAN EXPRESSION and X owns the item iff X is NECESSARY to it -- set X
#       false, everything else true, and the gate must evaluate false. `all(..)`
#       conjunctions and a bare `feature = "X"` qualify; `any(..)` arms do not.
#       (This is the solo-vs-OR-contributor distinction every hand grading of this
#       catalog has had to make in prose; here it is derived. Without it the
#       derivation credits declare-final with owning the whole send seam and
#       reports the very atom this round exists to catch as PASS -- measured.)
#       `not(X)` gates are the atom's OFF arm, not its code, and are excluded.
#       Each cfg naming the feature is parsed with paren balancing (a multi-line
#       `any(..)` puts the name on its own line), then the gated item is resolved:
#         `mod N` / `fn N` / `struct N` / `enum N` / `trait N`  -> N
#         a bare `{` block or a `let` (the cfg sits INSIDE a body) -> the ENCLOSING
#             `fn`, walked backwards. This arm is what catches the dead-gated-code
#             class: declare-final's only gated block lives inside
#             `send_declare_final`, whose name then has zero test references.
#         `use` -> skipped. An import is not a symbol the atom owns.
#   ARM 2 (reference) -- symbol -> the test contexts that name it. A test context is
#       any file under `crates/*/tests/` (integration; the manifest carries the
#       feature) or any `#[cfg(test)]`/`#[cfg(all(test..))]` module in src (unit).
#       A symbol's own definition site does not count as a reference to itself.
#
# What a hit means, honestly:
#   "a test names a symbol this atom gates". That is a NECESSARY condition for
#   COMPLETE, not a sufficient one -- it does not prove the test asserts the right
#   thing. It is exactly the A4-5 containment shape: an atom no test can even name
#   cannot have been proven by one, and that alone kills the class R311y342 found by
#   hand. Treat a miss as dispositive and a hit as permission to grade.

import os
import re

_CFG_START = re.compile(r"#\[cfg(?:_attr)?\(")
_FEAT = re.compile(r'feature\s*=\s*"([A-Za-z0-9_-]+)"')
_ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
    r"(mod|fn|struct|enum|trait|const|static|type)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_FN_BACK = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_TEST_MOD = re.compile(r"#\[cfg\((?:all\()?\s*test\b")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Symbols too generic to carry evidence: a test naming `new` proves nothing.
_NOISE = frozenset(
    """new default drop clone fmt from into next len is_empty get set run
    build encode decode main tests test id value inner kind body header""".split()
)


def _cfg_body(blob):
    """The text inside the outermost `#[cfg(..)]` parens."""
    i = blob.find("(")
    if i < 0:
        return ""
    depth = 0
    for j in range(i, len(blob)):
        if blob[j] == "(":
            depth += 1
        elif blob[j] == ")":
            depth -= 1
            if depth == 0:
                return blob[i + 1 : j]
    return blob[i + 1 :]


def _split_top(s):
    """Split on commas that are not inside nested parens."""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def _eval(expr, off):
    """Evaluate a cfg predicate with feature `off` false and every other true."""
    e = expr.strip()
    for op in ("all", "any", "not"):
        if e.startswith(op) and e[len(op) :].lstrip().startswith("("):
            args = [a for a in _split_top(_cfg_body(e)) if a.strip()]
            vals = [_eval(a, off) for a in args]
            if op == "all":
                return all(vals)
            if op == "any":
                return any(vals)
            return not vals[0] if vals else True
    m = _FEAT.search(e)
    if m:
        return m.group(1) != off
    return True  # target_os, test, etc. -- not a feature axis; treat as satisfied


def _necessary_features(blob):
    """The features X for which this cfg is FALSE when X is off. Derived."""
    body = _cfg_body(blob)
    if not body:
        return set()
    out = set()
    for f in set(_FEAT.findall(body)):
        if not _eval(body, f):
            out.add(f)
    return out


def _rs_files(root="crates"):
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "target"]
        for f in files:
            if f.endswith(".rs"):
                yield os.path.join(base, f)


def _attr_end(lines, i):
    """Index of the line where the `#[cfg(..)]` starting at `i` closes."""
    depth = 0
    for j in range(i, min(i + 24, len(lines))):
        depth += lines[j].count("(") - lines[j].count(")")
        if depth <= 0 and j >= i:
            return j
    return i


def _gated_symbol(lines, i):
    """The symbol the cfg attribute at `lines[i]` gates, or None."""
    j = _attr_end(lines, i) + 1
    while j < len(lines):
        s = lines[j].strip()
        if not s or s.startswith("//") or s.startswith("#["):
            j += 1
            continue
        break
    if j >= len(lines):
        return None
    m = _ITEM.match(lines[j])
    if m:
        return m.group(2)
    if lines[j].lstrip().startswith("use "):
        return None  # an import is not an owned symbol
    # A `{` block or a statement: the cfg sits inside a body. Walk back to the fn.
    for k in range(i, max(-1, i - 400), -1):
        m = _FN_BACK.match(lines[k])
        if m:
            return m.group(1)
    return None


def ownership():
    """atom -> {symbol}: the symbols each feature's cfg sites gate. Derived."""
    owned = {}
    for path in _rs_files():
        try:
            lines = open(path, encoding="utf-8").read().splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines):
            if not _CFG_START.search(ln):
                continue
            blob = "\n".join(lines[i : _attr_end(lines, i) + 1])
            feats = _necessary_features(blob)
            if not feats:
                continue
            sym = _gated_symbol(lines, i)
            if not sym or sym in _NOISE:
                continue
            for f in feats:
                owned.setdefault(f, set()).add(sym)
    return owned


def _test_regions():
    """(path, set_of_identifiers) for every test context in the tree. Derived."""
    for path in _rs_files():
        try:
            lines = open(path, encoding="utf-8").read().splitlines()
        except OSError:
            continue
        parts = path.replace(os.sep, "/").split("/")
        if "tests" in parts[:-1]:  # crates/<c>/tests/*.rs -- integration
            yield path, set(_IDENT.findall("\n".join(lines)))
            continue
        for i, ln in enumerate(lines):  # #[cfg(test)] mod tests { .. } -- unit
            if _TEST_MOD.search(ln):
                yield path, set(_IDENT.findall("\n".join(lines[i:])))
                break


def referenced_symbols():
    """The set of identifiers any test context names. Derived."""
    out = set()
    for _p, idents in _test_regions():
        out |= idents
    return out


def graph():
    """atom -> (owned_symbols, symbols_a_test_names). Derived, nothing authored."""
    owned = ownership()
    seen = referenced_symbols()
    return {a: (syms, syms & seen) for a, syms in owned.items()}

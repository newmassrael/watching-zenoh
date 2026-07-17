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
#         `mod N` / `fn N` / `struct N` / `enum N` / `trait N` / `const N`  -> N.
#             `const fn N` is an FN named N -- `const` there is a modifier, and
#             reading it as the item kind yields the keyword `fn` as the symbol.
#         `impl T` / `impl Trait for T` -> T, the self type. An impl block
#             declares no name of its own, so it is not an item; its methods are
#             reached through T.
#         a VARIANT or FIELD of an enum/struct -> its own name. Which of these a
#             line is cannot be read off the line (`Vsock(VsockStream),` and a
#             bare `{` are both "not an item"), so it is decided by walking back
#             to the nearest ENCLOSING declaration: an `fn` means the cfg sits in
#             a body, an `enum`/`struct`/`union` means it sits on a member.
#         a bare `{` block or a `let` (the cfg sits INSIDE a body) -> the ENCLOSING
#             `fn`, walked backwards. This arm is what catches the dead-gated-code
#             class: declare-final's only gated block lives inside
#             `send_declare_final`, whose name then has zero test references.
#         `use` -> skipped. An import is not a symbol the atom owns.
#   ARM 2 (reference) -- symbol -> the test contexts that name it, where a test
#       context is one that EXECUTES. A test that never runs is not a test, so a
#       region whose every test is `#[ignore]`d contributes nothing (78 of this
#       tree's 332 regions execute nothing). A test context is any file under
#       `crates/*/tests/` (integration; the manifest carries the feature), or a
#       brace-matched `#[cfg(test)]`/`#[cfg(all(test..))]` module BODY in src --
#       a test module is not the TAIL of its file, and a file may hold several.
#       A symbol's own definition site does not count as a reference to itself.
#
# What a hit means, honestly:
#   "an executing test names a symbol this atom gates". That is a NECESSARY
#   condition for COMPLETE, not a sufficient one -- it does not prove the test
#   asserts the right thing. It is exactly the A4-5 containment shape: an atom no
#   test can even name cannot have been proven by one, and that alone kills the
#   class R311y342 found by hand. Treat a miss as dispositive and a hit as
#   permission to grade.
#
#   The granularity is the test REGION, not the test fn: within a region that
#   does execute, an identifier named only by an #[ignore]d test still counts.
#   Measured residual -- 3 of 332 regions are partially ignored, and 15 hold no
#   test fn at all (helper modules, left crediting: a false FAIL blocks a real
#   atom, where a false PASS merely fails to catch one). Closing it needs the
#   per-fn call graph A4 resolves in crossimpl_corpus.py.
#
# Why it guards itself (R311y344):
#   R311y343 shipped this module calibrated -- 47 of 47 COMPLETE atoms passed --
#   and the calibration was TRUE while the derivation underneath it was wrong in
#   six distinct ways, because a gate that only ever passes cannot tell a correct
#   derivation from a broken one. Every one was found by measuring this module's
#   OUTPUT against the source, never by re-reading it. `_selftest()` pairs each
#   defect with the twin arm that must survive its fix, and Layer A3 runs it
#   before it trusts a single answer.

import os
import re

_CFG_START = re.compile(r"#\[cfg(?:_attr)?\(")
_FEAT = re.compile(r'feature\s*=\s*"([A-Za-z0-9_-]+)"')
# R311y344 — `const` is BOTH an item kind (`const NAME: T = ..`) and an fn
# modifier (`const fn NAME(..)`). Reading the alternation left-to-right takes the
# first meaning always, so `pub const fn new() -> Self` parsed as a const ITEM
# whose NAME is the literal keyword `fn` — 3 sites, and the symbol they own is a
# Rust keyword no test can ever name. The lookahead consumes `const` as a
# modifier only when an `fn` actually follows it.
_MODS = r"(?:const\s+(?=(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*fn\b))?" \
        r"(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
_ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?" + _MODS +
    r"(mod|fn|struct|enum|trait|const|static|type)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_FN_BACK = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?" + _MODS +
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
# R311y344 — the other thing a cfg can be enclosed BY. See _gated_symbol.
_TYPE_BACK = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:enum|struct|union)\s+[A-Za-z_][A-Za-z0-9_]*"
)
_DECL_NAME = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)")
_IMPL_HEAD = re.compile(r"^\s*(?:unsafe\s+)?impl\b")
_GENERICS = re.compile(r"<[^<>]*(?:<[^<>]*>[^<>]*)*>")
_TY_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A keyword is never a symbol. `_DECL_NAME` is a deliberately loose "first word on
# the line" match, so the closed set of things it must never yield is spelled out
# rather than trusted to the regex.
_KEYWORDS = frozenset(
    """impl where for in if else match let fn mod use pub struct enum union trait
    const static type unsafe async move ref return loop while dyn crate super
    self Self as break continue""".split()
)
_TEST_MOD = re.compile(r"#\[cfg\((?:all\()?\s*test\b")
_MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)")
_TEST_ATTR = re.compile(r"#\[(?:tokio::)?test\b|#\[rstest\b")
_IGNORE_ATTR = re.compile(r"#\[ignore\b")
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


def _op_of(e):
    """(op, args) for an `all(..)`/`any(..)`/`not(..)` node, else (None, [])."""
    for op in ("all", "any", "not"):
        if e.startswith(op) and e[len(op) :].lstrip().startswith("("):
            return op, [a for a in _split_top(_cfg_body(e)) if a.strip()]
    return None, []


def _sat(expr, off, want=True):
    """Can `expr` be `want` with feature `off` forced false and the rest free?

    Necessity is a SATISFIABILITY question, not an evaluation. Evaluating with
    "off false, everything else true" is wrong the moment a `not(..)` appears:
    `all(not(transport-multilink), any(.., declare-final, ..))` is FALSE under
    that assignment for EVERY feature, so every feature reads as necessary --
    measured, and it credited declare-final with owning `session_send_available`,
    which it merely OR-contributes to. Asking instead "is there any build where
    this compiles WITHOUT X" gets the multilink-off arm right.

    Features are treated as independent free variables; a cfg naming the same
    feature both plainly and under `not(..)` would need a real solver, and none
    in this tree does.
    """
    e = expr.strip()
    op, args = _op_of(e)
    if op == "not":
        return _sat(args[0], off, not want) if args else want
    if op == "all":
        return all(_sat(a, off, True) for a in args) if want \
            else any(_sat(a, off, False) for a in args)
    if op == "any":
        return any(_sat(a, off, True) for a in args) if want \
            else all(_sat(a, off, False) for a in args)
    m = _FEAT.search(e)
    if m:
        # `off` is pinned false; any other feature is free to take either value.
        return (m.group(1) != off) if want else True
    return want  # target_os, test, .. -- not a feature axis; satisfiable either way


def _necessary_features(blob):
    """The features X without which this cfg can never be true. Derived."""
    body = _cfg_body(blob)
    if not body:
        return set()
    return {f for f in set(_FEAT.findall(body)) if not _sat(body, f, True)}


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


def _item_line(lines, i):
    """Index of the item line the attribute at `lines[i]` applies to.

    Further attributes, doc comments and blanks are stepped over -- each
    attribute WHOLE, via _attr_end's paren balancing. R311y344: walking them by
    `startswith("#[")` alone lands in the MIDDLE of a multi-line attribute, whose
    continuation lines are bare `feature = "x",` text. The live case is a test
    module carrying two attributes:

        #[cfg(test)]
        #[cfg(all(
            feature = "query-reply",
        ))]
        mod reply_timestamp_decode_isolation_tests {

    where the naive walk stops on `feature = "alloc",` and never sees the `mod`.
    """
    j = _attr_end(lines, i) + 1
    while j < len(lines):
        s = lines[j].strip()
        if not s or s.startswith("//"):
            j += 1
            continue
        if s.startswith("#["):
            j = _attr_end(lines, j) + 1
            continue
        break
    return j


def _impl_self_type(line):
    """The SELF type of an `impl` header: `impl T`, `impl Tr for T` -> T.

    A cfg'd `impl` block is not an `_ITEM` (it declares no new name), so it fell
    through to the walk-back and was credited to whatever fn happened to precede
    it — 42 sites tree-wide, the single largest misattribution class. The self
    type is the symbol a test must name to reach the gated methods.
    """
    m = _IMPL_HEAD.match(line)
    if not m:
        return None
    rest = _GENERICS.sub(" ", line[m.end() :])  # `impl<T: Bound>` must not yield T
    if " for " in rest:
        rest = rest.split(" for ", 1)[1]  # `impl Trait for Type` -> the Type
    m2 = _TY_NAME.search(rest)
    return m2.group(0) if m2 else None


def _gated_symbol(lines, i):
    """The symbol the cfg attribute at `lines[i]` gates, or None."""
    j = _item_line(lines, i)
    if j >= len(lines):
        return None
    m = _ITEM.match(lines[j])
    if m:
        return m.group(2)
    if lines[j].lstrip().startswith("use "):
        return None  # an import is not an owned symbol
    if _IMPL_HEAD.match(lines[j]):
        return _impl_self_type(lines[j])
    # Neither an item, an import, nor an impl. The cfg gates either a VARIANT / FIELD of an
    # enclosing type, or a block / statement inside an enclosing fn body — and
    # which one it is is NOT a property of this line: `Vsock(VsockStream),` and a
    # bare `{` are both merely "not an item". So resolve it by walking back to
    # whichever declaration ENCLOSES it, and let that decide.
    #
    # R311y344 — walking back for a `fn` ONLY was the defect. It sails straight
    # past the `enum` that actually encloses a variant and lands on the last fn
    # before the type, crediting one feature with a symbol a DIFFERENT feature
    # gates. Measured on the real tree: `transport-link-vsock` owned `with_quic`,
    # which is `#[cfg(feature = "transport-link-quic")]` (session_open.rs) — and
    # 29 cfg sites tree-wide were misattributed, all in the transport-link family
    # this gate is most often asked to grade. The pollution is silent and it runs
    # one way: a phantom symbol can only ADD to `owned`, so it can only make the
    # gate PASS an atom it should have failed.
    for k in range(i, max(-1, i - 400), -1):
        m = _FN_BACK.match(lines[k])
        if m:
            return m.group(1)  # inside a body -> the enclosing fn is the symbol
        if _TYPE_BACK.match(lines[k]):
            # Inside an enum / struct / union declaration: the variant or field
            # the cfg sits on is the symbol. The TYPE is not gated by it — only
            # this member is, so crediting the type would be the same error one
            # level up.
            d = _DECL_NAME.match(lines[j])
            if not d or d.group(1) in _KEYWORDS:
                return None
            return d.group(1)
    return None


def _scan_lines(lines):
    """feature -> {symbol} for ONE file. The seam ownership() and the self-check
    share, so the guard drives the same code the tree walk does."""
    owned = {}
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


def ownership():
    """atom -> {symbol}: the symbols each feature's cfg sites gate. Derived."""
    owned = {}
    for path in _rs_files():
        try:
            lines = open(path, encoding="utf-8").read().splitlines()
        except OSError:
            continue
        for f, syms in _scan_lines(lines).items():
            owned.setdefault(f, set()).update(syms)
    return owned


def _test_is_ignored(lines, k):
    """Is the test whose test-attribute sits at `lines[k]` #[ignore]d? One item's
    attributes are contiguous, so the block is scanned both ways: `#[ignore]` is
    written above the test attr about as often as below it."""
    for direction in (1, -1):
        m = k
        while 0 <= m < len(lines) and abs(m - k) < 8:
            s = lines[m].strip()
            if _IGNORE_ATTR.search(s):
                return True
            if s.startswith("#[") or s.startswith("//") or not s:
                m += direction
                continue
            break  # the item itself, or ordinary code: the attr block ended
    return False


def _region_idents(lines):
    """The identifiers a test region names, or None if the region executes
    nothing. The seam _test_regions() and the self-check share.

    R311y344 — a test that never runs is not a test. This arm harvested every
    identifier in a test file without ever looking at `#[ignore]`, so an atom
    whose ONLY witnesses are ignored tests read as proven by one. That is this
    repo's own named disease twice over ("a proof that never runs is not a
    proof"; "a skip is green"), installed in the gate built to enforce it: 78 of
    the 332 test regions in this tree execute NOTHING, and R311y343's own
    exemplar is one of them — transport-link-vsock's two tests are both
    #[ignore]d, and it still read as owning 8 test-named symbols.

    Granularity is the REGION, not the test fn, and that is a measured choice,
    not a shortcut: of 332 regions, 329 are all-or-nothing (all tests ignored, or
    none), so per-fn resolution would change the answer for exactly 3. Those 3
    are the named residual -- a helper in a partially-ignored file can still be
    credited to an executing test that never calls it. Closing that needs the
    per-fn call graph A4 resolves in crossimpl_corpus.py, which is its own round.
    The 15 regions holding zero test fns at all (helper modules) are left
    crediting, deliberately: dropping them would UNDER-credit a helper that an
    executing test in another file genuinely reaches, and a false FAIL blocks a
    real atom, where a false PASS only fails to catch one.
    """
    tests = [k for k, ln in enumerate(lines) if _TEST_ATTR.search(ln)]
    if tests and all(_test_is_ignored(lines, k) for k in tests):
        return None
    return set(_IDENT.findall("\n".join(lines)))


def _test_spans(lines):
    """(first, last) line index of every `#[cfg(test)] mod N { .. }` BODY.

    R311y344 — this arm used to take the FIRST `#[cfg(test)]` in a src file and
    harvest every identifier from there to EOF. A test module is not the tail of
    its file: 161 src files in this tree carry top-level PRODUCTION items after
    their first test module, and every one of those items was being read as
    something a test names. wz-runtime-tokio/src/lib.rs is the type case -- its
    first test attribute sits on line 103 and the harvest ran to 1715, so 58
    top-level `pub fn` / `pub mod` declarations, including `pub mod
    vsock_pipeline`, counted as test evidence for the atoms that gate them. One
    file donated 171. So the span is brace-matched, and a file may hold several.
    """
    spans = []
    for i, ln in enumerate(lines):
        if not _TEST_MOD.search(ln):
            continue
        j = _item_line(lines, i)
        if j >= len(lines) or not _MOD_DECL.match(lines[j]):
            continue
        if lines[j].rstrip().endswith(";"):
            # `#[cfg(test)] mod N;` -- the body is N.rs / N/mod.rs, which is
            # walked as its own file. Resolved by _test_file_mods, not here.
            continue
        depth, end, opened = 0, None, False
        for k in range(j, len(lines)):
            depth += lines[k].count("{") - lines[k].count("}")
            opened = opened or "{" in lines[k]
            if opened and depth <= 0:
                end = k
                break
        spans.append((j, end if end is not None else len(lines) - 1))
    return spans


def _test_file_mods(path, lines):
    """Paths of `#[cfg(test)] mod N;` bodies -- test code living in its own file.

    Without this the fix above would DROP them: such a file carries no
    `#[cfg(test)]` of its own, so nothing would ever mark it as test code.
    """
    out = []
    base = os.path.dirname(path)
    for i, ln in enumerate(lines):
        if not _TEST_MOD.search(ln):
            continue
        for j in range(i + 1, min(i + 6, len(lines))):
            m = _MOD_DECL.match(lines[j])
            if not m:
                continue
            if not lines[j].rstrip().endswith(";"):
                break
            for cand in (
                os.path.join(base, m.group(1) + ".rs"),
                os.path.join(base, m.group(1), "mod.rs"),
            ):
                if os.path.isfile(cand):
                    out.append(cand)
            break
    return out


def _test_regions():
    """(path, set_of_identifiers) for every test context in the tree. Derived."""
    extra = []
    for path in _rs_files():
        try:
            lines = open(path, encoding="utf-8").read().splitlines()
        except OSError:
            continue
        parts = path.replace(os.sep, "/").split("/")
        if "tests" in parts[:-1]:  # crates/<c>/tests/*.rs -- integration
            idents = _region_idents(lines)
            if idents is not None:
                yield path, idents
            continue
        extra.extend(_test_file_mods(path, lines))
        for first, last in _test_spans(lines):  # #[cfg(test)] mod tests { .. }
            idents = _region_idents(lines[first : last + 1])
            if idents is not None:
                yield path, idents
    for path in extra:
        try:
            lines = open(path, encoding="utf-8").read().splitlines()
        except OSError:
            continue
        idents = _region_idents(lines)
        if idents is not None:
            yield path, idents


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


# ── Self-check ─────────────────────────────────────────────────────────────────
#
# R311y344 — a derivation nobody falsifies is prose with a parser. Both arms of
# this module shipped with a defect R311y343 did not catch, and both were found
# by MEASURING the output rather than re-reading the code, so the guard belongs
# here, wired into the Layer A3 lane (audit-catalog-status.sh) which runs on
# every hosted CI push. It executes whenever the gate it guards executes.
#
# Each fixture is a PAIR: the defect, and the twin that must keep working. The
# twin is the point -- both fixes narrow an over-broad arm, and an over-narrow
# replacement would pass the defect case while silently destroying the arm's
# real job (R311y343's headline: declare-final's gated block is INSIDE a fn, and
# resolving it to the enclosing fn is exactly what catches dead gated code).

_SELFTEST_OWNERSHIP = '''\
impl DialConfig {
    #[cfg(feature = "feat-quic")]
    pub fn with_quic(mut self, quic: QuicDialConfig) -> Self {
        self.quic = Some(quic);
        self
    }
}

pub enum DialedLink {
    Tcp(TcpStream),
    #[cfg(all(feature = "feat-vsock", target_os = "linux"))]
    Vsock(VsockStream),
    #[cfg(feature = "feat-udp")]
    Udp { socket: UdpSocket, peer: SocketAddr },
}

pub fn send_declare_final(&self) -> Result<(), SendError> {
    #[cfg(feature = "feat-final")]
    {
        let _ = self.emit_final();
    }
    Ok(())
}

#[cfg(feature = "feat-udp-drv")]
impl UdpDriver {
    pub fn poll(&mut self) -> Option<LinkEvent> {
        None
    }
}

#[cfg(feature = "feat-ws-drv")]
impl<T: Clone> LinkDriver<T> for WsDriver<T> {
    fn close(&mut self) {}
}

#[cfg(feature = "feat-keepalive")]
pub const fn encode_keep_alive() -> [u8; 1] {
    [0x20]
}

#[cfg(feature = "feat-limits")]
pub const MAX_CHUNKS: usize = 32;
'''

_SELFTEST_ALL_IGNORED = '''\
#[tokio::test]
#[ignore = "needs the vsock_loopback kernel module"]
async fn vsock_round_trip() {
    let _ = vsock_pipeline::dial_vsock(addr).await;
}
'''

_SELFTEST_ONE_RUNS = '''\
#[tokio::test]
#[ignore = "needs a foreign binary"]
async fn interop_round_trip() {
    let _ = quic_pipeline::dial_quic(addr).await;
}

#[tokio::test]
async fn loopback_round_trip() {
    let _ = quic_pipeline::dial_quic(addr).await;
}
'''


_SELFTEST_SPANS = '''\
#[cfg(test)]
mod early_tests {
    #[test]
    fn a_unit_test() {
        assert!(inside_the_test_mod());
    }
}

pub mod vsock_pipeline;

pub fn compiled_plugins(version: &str) -> Vec<AdminPlugin> {
    production_only_symbol(version)
}

#[cfg(all(test, feature = "adminspace-core"))]
mod later_tests {
    #[test]
    fn another_unit_test() {
        assert!(also_inside_a_test_mod());
    }
}

#[cfg(test)]
#[cfg(all(
    feature = "alloc",
    feature = "query-reply",
    not(feature = "pubsub-timestamp"),
))]
mod two_attribute_tests {
    #[test]
    fn a_third_unit_test() {
        assert!(behind_a_multiline_attr());
    }
}
'''


def _selftest():
    """Falsify both arms against hand-built fixtures. Returns a list of failures."""
    bad = []

    def eq(label, got, want):
        if got != want:
            bad.append("%s\n      got  %r\n      want %r" % (label, got, want))

    own = _scan_lines(_SELFTEST_OWNERSHIP.splitlines())

    # ARM 1, the DEFECT (R311y344): a cfg on an enum VARIANT is not a cfg inside
    # a body. Walking back for the enclosing `fn` crosses the `enum` boundary and
    # lands on whatever function happened to precede the type -- in the real tree,
    # `transport-link-vsock` was credited with owning `with_quic`, a fn gated by
    # `transport-link-quic`. The variant's own name is the symbol the atom owns.
    eq("ARM1 variant: vsock must own its variant, not the preceding fn",
       own.get("feat-vsock"), {"Vsock"})
    eq("ARM1 variant: a struct-form variant resolves to the variant name",
       own.get("feat-udp"), {"Udp"})
    eq("ARM1 twin: an item cfg still resolves to the item",
       own.get("feat-quic"), {"with_quic"})
    # ARM 1, the DEFECT (R311y344): an `impl` block declares no new name, so it is
    # not an _ITEM and fell through to the walk-back too -- 42 sites, the largest
    # single misattribution class. The self type is the symbol.
    eq("ARM1 impl: an inherent impl resolves to its self type",
       own.get("feat-udp-drv"), {"UdpDriver"})
    eq("ARM1 impl: `impl<T> Trait<T> for Type<T>` resolves to the Type, not the "
       "trait and not the generic parameter",
       own.get("feat-ws-drv"), {"WsDriver"})
    # ARM 1, the DEFECT (R311y344): `const` is an item kind AND an fn modifier.
    # Read left-to-right, `pub const fn encode_keep_alive()` yields the keyword
    # `fn` as the owned SYMBOL -- a name no test can ever reference.
    eq("ARM1 const fn: `const fn N` is an fn named N, not a const named `fn`",
       own.get("feat-keepalive"), {"encode_keep_alive"})
    # ARM 1, the TWIN: a genuine `const` item must still resolve to its own name.
    eq("ARM1 twin: a real const item still resolves to the const's name",
       own.get("feat-limits"), {"MAX_CHUNKS"})
    # ARM 1, the TWIN that must not regress: a cfg INSIDE a fn body still walks
    # back to that fn. This is the arm that catches dead gated code.
    eq("ARM1 twin: a cfg inside a body still resolves to the enclosing fn",
       own.get("feat-final"), {"send_declare_final"})

    # ARM 2, the DEFECT (R311y344): a test that never runs is not a test. This
    # module harvested every identifier in a test file without ever looking at
    # #[ignore], so an atom whose ONLY witnesses are ignored tests read as proven.
    eq("ARM2 ignored: a region whose every test is #[ignore]d proves nothing",
       _region_idents(_SELFTEST_ALL_IGNORED.splitlines()), None)
    # ARM 2, the TWIN: a region with at least one executing test still counts.
    got = _region_idents(_SELFTEST_ONE_RUNS.splitlines())
    eq("ARM2 twin: a region with one executing test still contributes",
       got is not None and "quic_pipeline" in got, True)

    # ARM 2, the DEFECT (R311y344): a test module is not the TAIL of its file.
    # Harvesting from the first #[cfg(test)] to EOF swept up every production
    # item declared after it -- 161 src files in this tree, one of them donating
    # 171 top-level items.
    span_lines = _SELFTEST_SPANS.splitlines()
    spans = _test_spans(span_lines)
    named = set()
    for _f, _l in spans:
        named |= _region_idents(span_lines[_f : _l + 1]) or set()
    eq("ARM2 spans: every test module in the file is found, including one behind "
       "two attributes where the second is multi-line",
       len(spans), 3)
    eq("ARM2 spans: a test mod behind a multi-line 2nd attribute is harvested",
       "behind_a_multiline_attr" in named, True)
    eq("ARM2 spans: a production item after a test mod is NOT test evidence",
       {"vsock_pipeline", "compiled_plugins", "production_only_symbol"} & named,
       set())
    # ARM 2, the TWIN: the test modules' own bodies must still be harvested --
    # both the first and the one that follows the production code.
    eq("ARM2 twin: the first test mod's body is still harvested",
       "inside_the_test_mod" in named, True)
    eq("ARM2 twin: a test mod AFTER production code is still harvested",
       "also_inside_a_test_mod" in named, True)
    return bad


if __name__ == "__main__":
    import sys as _sys

    if "--selftest" in _sys.argv:
        _bad = _selftest()
        if _bad:
            print("atom_test_graph self-check FAIL: %d" % len(_bad))
            for _b in _bad:
                print("    - %s" % _b)
            _sys.exit(1)
        print("atom_test_graph self-check OK")
        _sys.exit(0)
    print(__doc__ or "atom_test_graph: --selftest", file=_sys.stderr)
    _sys.exit(2)

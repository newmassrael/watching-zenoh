#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y259 — the CROSS-IMPL PROOF corpus: one predicate, two consumers.

This module answers two questions about `crates/wz-integration-tests/tests/*.rs`,
and it is the SINGLE definition of both. Layer C0 (test discipline) and Layer A4
(cross-impl proof audit) both consume it, so the two gates cannot drift into two
spellings of the same question — which they had already done: C0's inline grep
(`wz_ap_demo_binary()|zenoh_pico_cli_binary(`) misses `pubkey_zenohd_interop.rs`
and `usrpwd_zenohd_interop.rs`, which spawn zenohd and nothing else.

  Q1 (C0):  does this test spawn an EXTERNAL BINARY?  -> it must carry #[ignore],
            or a fresh CI checkout without the binaries panics in Layer C1.
  Q2 (A4):  does this test witness a FOREIGN IMPLEMENTATION?  -> only then may it
            claim `wz-proves:`.

These are NOT the same question: `wz_ap_demo_binary()` is a wz binary (external,
but not foreign), so a wz<->wz e2e is Q1-yes / Q2-no.

## Why a call-graph resolver and not a grep

The foreign binaries are reached through wrapper helpers. `wz_to_zenohd_router.rs`
and `wz_router_hat_zenohd_interop.rs` spawn zenohd via `spawn_zenohd(...)` and never
name `zenohd_binary(` — a 3-token grep mis-classifies BOTH of the flagship zenohd
proofs as pico-only, and a future zenohd-only test written against the wrapper would
drop out of the corpus silently. So we resolve `common::*` transitively from the two
foreign roots.

Comments and string literals are stripped before matching. Otherwise a lone
`// zenohd_binary(` comment line in a wz<->wz test buys it corpus membership, and the
integrity invariant (a wz<->wz test may not claim foreign proof) would be enforced by
the very artifact it exists to constrain.

## The four proof classes

  codec   the test LINKS the real vendored zenoh-pico C library (crates/zenoh-pico-sys)
          and byte-compares wz's encoder against pico's `_z_*_encode`. Differential
          parity. These are NOT #[ignore]d -- they run in Layer C1 on every push, which
          makes them the only foreign proof hosted CI executes unconditionally.
  pico    the test spawns a real zenoh-pico C CLI binary (live wire).
  pico-lib  the test reaches the real vendored zenoh-pico as a LIBRARY in its own
          process -- `dlopen`ing `libzenohpico.so` and calling its functions, or
          linking an upstream example against it as the reference arm of a
          compile-twice differential. R311y536. It is a class of its own rather
          than more `pico` or more `codec`, for the reason FOREIGN_ROOTS gives
          about zenoh-ext: `pico` says SPAWNS A CLI (this spawns nothing, or
          spawns a binary that IS pico), and `codec` says statically linked via
          crates/zenoh-pico-sys AND not `#[ignore]`d, which is load-bearing --
          the codec class is documented as the only foreign proof hosted CI runs
          unconditionally, and these need the CMake build product so they are
          `#[ignore]`d. Folding them into either would have made a true record
          mildly false.
  zenohd  the test spawns the real zenoh-full router binary (live wire).
  zenoh-ext  the test spawns a real zenoh-ext EXAMPLE application (live wire).
             Distinct from `zenohd` because the advanced-pubsub plane lives in
             the zenoh-ext LIBRARY, not in the router: only an application built
             on it holds an AdvancedCache, so only this class can witness `@adv`.

Linking the foreign implementation is a stronger proof than spawning it, so `codec` is
a first-class class, not an afterthought.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "crates" / "wz-integration-tests" / "tests"
LIB_RS = REPO_ROOT / "crates" / "wz-integration-tests" / "src" / "lib.rs"

# The foreign roots: the functions that resolve a foreign binary path. `zenohd_binary`
# is the STOCK zenohd; `zenohd_unixpipe_binary` (R311y392) and `zenohd_vsock_binary`
# (R311y400) are the SAME zenoh-full router built with an extra transport feature its
# `default` set omits (transport_unixpipe / transport_vsock). They resolve a genuine
# zenohd binary, so a test that spawns one over the variant oracle IS a foreign zenohd
# witness. Omitting them (the pre-R311y402 state) mis-classed every unixpipe/vsock
# acceptor test as pico-only: the dataplane file's `zenohd->wz` claims then failed A4-7
# against a `[pico]` class, and Layer A4 was red for 6 rounds unseen (pre-push stopped
# running A4 at R311y386). Any future feature-variant oracle resolver belongs here too.
FOREIGN_ROOTS = {
    "zenoh_pico_cli_binary": "pico",
    "zenohd_binary": "zenohd",
    "zenohd_unixpipe_binary": "zenohd",
    "zenohd_vsock_binary": "zenohd",
    # R311y505 — the shared-memory-enabled variant, the third of the same shape.
    # It is the ONLY oracle that carries `init::ext::Shm` at all (zenoh's `default`
    # omits `shared-memory`), so every §5.1/§5.13 SHM establishment claim rests on
    # it and a test that spawns it IS a foreign zenohd witness.
    "zenohd_shm_binary": "zenohd",
    # R311y442 — the zenoh-ext EXAMPLE applications (`z_advanced_pub` /
    # `z_advanced_sub`), a class of their own rather than more `zenohd` roots.
    # They are the real zenoh-full Rust stack at the pinned version, but they are
    # not the router: they carry an `AdvancedCache` and an `AdvancedSubscriber`,
    # which zenohd does not have and cannot witness. Folding them into `zenohd`
    # would have been one dict entry and would have made every claim in that
    # family read `wz->zenohd` against a counterparty that is not zenohd — a
    # record that is mildly false to whoever reads it next.
    "zenoh_ext_example_binary": "zenoh-ext",
    # R311y536 — the real pico as a LIBRARY. Both resolvers were previously
    # inlined in the test files (a `project_root().join(..)` for the dlopen
    # oracle, a local `libdir` for the compile-twice reference arm), so this
    # classifier saw NO foreign artifact in either and Layer A4 rejected five
    # true `wz->pico` claims as wz-vs-wz. The lesson is the one this dict's
    # header already states in the other direction: a foreign artifact reached
    # WITHOUT a registered resolver is a foreign artifact the audit cannot see,
    # so the resolver is the thing that must be shared, not the path.
    "zenoh_pico_shared_library": "pico-lib",
    "zenoh_pico_library_dir": "pico-lib",
}
# A wz binary is EXTERNAL (needs #[ignore]) but not FOREIGN (cannot witness parity).
# The package each root resolves to is what Layer A4's containment arm needs: the
# feature closure it checks a claim against must be the closure of the binary the test
# actually drives.
WZ_BINARY_ROOTS = {
    "wz_ap_demo_binary": "wz-ap-demo",
    "wz_e2e_pubsub_binary": "wz-e2e-pubsub",
    "wz_e2e_queryable_binary": "wz-e2e-queryable",
    "wz_e2e_zget_binary": "wz-e2e-zget",
    "wz_e2e_liveliness_binary": "wz-e2e-liveliness",
    "wz_e2e_liveliness_token_binary": "wz-e2e-liveliness-token",
    "wz_e2e_declare_observer_binary": "wz-e2e-declare-observer",
    # The §5.27 api-compat-pico artifact is a cdylib, not an executable: the
    # thing under test is a foreign C program linked AGAINST wz. It still
    # belongs here rather than in FOREIGN_ROOTS -- the implementation answering
    # every `z_*` call is wz's, so a test driving it is external-but-not-foreign
    # exactly like `wz_ap_demo_binary`, and its foreignness has to come from the
    # counterparty it talks to (a real pico CLI). Mapping it to the package
    # keeps A4-5 honest: the claim gets checked against the closure of the build
    # that PRODUCES the .so, not against this test crate's own dev-dep graph
    # (which cannot contain the atom -- see feature_closure.binary_closure).
    "wz_capi_pico_cdylib": "wz-capi-pico",
    # R311y500 — the §5.27 `api-compat-c` artifact, the zenoh-c ABI twin of the
    # entry above and here for the identical reason: a foreign C program linked
    # against WZ's cdylib is external-but-not-foreign, because the implementation
    # answering every `z_*` call is wz's. Its foreignness has to come from the
    # counterparty, which for both legs of the interop file is a real pico CLI.
    # Omitting this maps the file to IN_PROCESS_PKG and A4-5 then checks
    # `api-compat-c` against this test crate's dev-dep graph, which cannot contain
    # it — a true claim refuted by a missing dict entry.
    "wz_capi_c_cdylib": "wz-capi-c",
}
# A test that spawns no wz binary exercises the library in-process, i.e. the test
# crate's own (dev-dependency) feature graph.
IN_PROCESS_PKG = "wz-integration-tests"
# Linking the real zenoh-pico C library in-process.
PICO_FFI_CRATE = "zenoh_pico_sys"

CLAIM_RE = re.compile(
    r"^\s*//[/!]?\s*wz-proves:\s*(?P<atom>[A-Za-z0-9_-]+)\s+"
    r"(?P<kind>wz->pico|pico->wz|wz->zenoh-ext|zenoh-ext->wz|wz->zenohd|zenohd->wz|codec-parity)"
    r"\s*(?P<partial>partial)?\s*$"
)
# A corpus test that witnesses NO atom must say so, with a reason, rather than be
# left blank -- otherwise invariant A4-4 (every corpus test declares) would force an
# invented claim, which is the exact fabrication this gate exists to prevent. The
# roll-up prints the count and the list, so `none` is a REPORTED state, not a hole.
NONE_RE = re.compile(r"^\s*//[/!]?\s*wz-proves:\s*none\s*--\s*(?P<reason>\S.*?)\s*$")
KINDS = {
    "wz->pico",
    "pico->wz",
    "wz->zenohd",
    "zenohd->wz",
    "wz->zenoh-ext",
    "zenoh-ext->wz",
    "codec-parity",
}
# Which foreign classes can legitimately produce each proof kind.
#
# A directional pico proof does NOT require a spawned CLI: the `codec` class LINKS
# pico's real C encoder, so `layer3_inbound_init` feeding pico's `_z_init_encode`
# output into wz's decoder is a genuine `pico->wz` witness -- the foreign bytes are
# foreign either way. Only `codec-parity` (a byte-for-byte differential against the
# linked C encoder) is exclusive to the linked class, and only zenohd can witness a
# zenohd kind.
KIND_CLASS = {
    # R311y536 — `pico-lib` joins both directional pico kinds on the same
    # reasoning the note above gives for `codec`: linking or dlopening the real
    # implementation is a STRONGER witness than spawning it, so a kind that
    # accepts the spawned CLI must accept the library.
    "wz->pico": {"pico", "codec", "pico-lib"},
    "pico->wz": {"pico", "codec", "pico-lib"},
    "wz->zenohd": {"zenohd"},
    "zenohd->wz": {"zenohd"},
    # R311y488 corrected the second half of this note. It used to read "the router
    # has no cache to answer from and pico has no such plane at all". The router
    # half stands; the pico half was FALSE, and it was a build fact mistaken for an
    # implementation fact: zenoh-pico ships `z_advanced_pub` / `z_advanced_sub` and
    # `Z_FEATURE_ADVANCED_PUBLICATION` / `_SUBSCRIPTION`, both DEFAULTING TO 0, so
    # every advanced example in this tree compiled to a stub `main` until
    # `scripts/build-zenoh-pico-cli.sh` set them. The advanced plane is therefore
    # witnessable by the `pico` class too, and `apfull_advanced_pubsub_pico_interop`
    # claims it through `wz->pico` / `pico->wz` rather than through a new kind —
    # those kinds already carry the right class set, and adding an `advanced`-only
    # kind would have encoded the retired assumption a second time.
    "wz->zenoh-ext": {"zenoh-ext"},
    "zenoh-ext->wz": {"zenoh-ext"},
    "codec-parity": {"codec"},
}

TEST_ATTR_RE = re.compile(r"^\s*#\[(?:tokio::)?test\b")


def strip_code(src: str) -> str:
    """Blank out comments, string literals and char literals, PRESERVING line structure.

    Every stripped character becomes a space and newlines are kept, so line N of the
    output is line N of the input. That matters twice:

      - corpus membership and `#[test]` detection must read CODE (a `#[test]` inside a
        /* ... */ block is a dead test and must not carry a proof claim), while the
        claims themselves are COMMENTS and must be read from the raw text. Both are
        keyed by line number, so the two views have to stay aligned.
      - a `r#"..."#` JSON fixture must not leak an identifier. This file previously used
        a naive stripper that mishandled raw strings, char literals (`'"'`) and Rust's
        NESTED block comments -- any of which could desync the scan or leak a foreign
        harness token into "code", buying a wz<->wz test corpus membership. That would
        have let the integrity invariant (A4-3) be defeated by the very artifact it
        exists to constrain.
    """
    out: list[str] = []
    i, n = 0, len(src)

    def keep(ch: str) -> None:
        out.append("\n" if ch == "\n" else " ")

    while i < n:
        c = src[i]
        # line comment
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                keep(src[i])
                i += 1
            continue
        # block comment -- Rust allows nesting
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 0
            while i < n:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    keep(src[i]); keep(src[i + 1]); i += 2
                    continue
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    keep(src[i]); keep(src[i + 1]); i += 2
                    if depth == 0:
                        break
                    continue
                keep(src[i]); i += 1
            continue
        # raw string: r"..." / r#"..."# / br##"..."##
        m = re.match(r'(?:b?r)(#*)"', src[i:])
        if m and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            hashes = m.group(1)
            close = '"' + hashes
            end = src.find(close, i + m.end())
            end = n if end == -1 else end + len(close)
            while i < end:
                keep(src[i]); i += 1
            continue
        # normal string
        if c == '"':
            keep(c); i += 1
            while i < n:
                if src[i] == "\\":
                    keep(src[i]); i += 1
                    if i < n:
                        keep(src[i]); i += 1
                    continue
                if src[i] == '"':
                    keep(src[i]); i += 1
                    break
                keep(src[i]); i += 1
            continue
        # char literal -- but NOT a lifetime (`&'a str`, `<'a>`)
        if c == "'" and not re.match(r"'[A-Za-z_][A-Za-z0-9_]*[^']", src[i:i + 3] or "'"):
            j = i + 1
            if j < n and src[j] == "\\":
                j += 2
            else:
                j += 1
            if j < n and src[j] == "'":
                while i <= j:
                    keep(src[i]); i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def helper_classes() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Resolve every `common::*` helper transitively to what it can reach.

    Returns (foreign_classes_by_helper, wz_packages_by_helper). Both are resolved
    through the CALL GRAPH, not by grepping the test for the root's name: the flagship
    zenohd proofs reach zenohd through `spawn_zenohd`, never naming `zenohd_binary(`.
    The same is true of the wz side -- a future `spawn_wz_ap_demo()` wrapper would make
    every caller look like an in-process test, and A4-5 would then check the WRONG
    binary's feature closure (the two closures are not nested).
    """
    src = strip_code(LIB_RS.read_text())
    # Every helper is a fn at one indent level inside `pub mod common { ... }`.
    chunks: dict[str, str] = {}
    parts = re.split(r"\n    (?:pub )?fn ", src)
    for part in parts[1:]:
        m = re.match(r"([A-Za-z0-9_]+)", part)
        if m:
            chunks[m.group(1)] = part

    def resolve(name: str, seen: frozenset[str]) -> tuple[set[str], set[str]]:
        if name in seen:
            return set(), set()
        body = chunks.get(name)
        if body is None:
            return set(), set()
        seen = seen | {name}
        classes: set[str] = set()
        pkgs: set[str] = set()
        for ident in set(re.findall(r"[A-Za-z0-9_]+", body)):
            if ident in FOREIGN_ROOTS:
                classes.add(FOREIGN_ROOTS[ident])
            if ident in WZ_BINARY_ROOTS:
                pkgs.add(WZ_BINARY_ROOTS[ident])
            if ident in chunks and ident != name:
                sub_c, sub_p = resolve(ident, seen)
                classes |= sub_c
                pkgs |= sub_p
        return classes, pkgs

    by_helper: dict[str, set[str]] = {}
    pkgs_by_helper: dict[str, set[str]] = {}
    for name in chunks:
        classes, pkgs = resolve(name, frozenset())
        if classes:
            by_helper[name] = classes
        if pkgs:
            pkgs_by_helper[name] = pkgs
    if not chunks or not by_helper:
        raise RuntimeError(
            "crossimpl_corpus: resolved NO harness helpers from %s. The `pub mod common`"
            " fn-indent split has broken (a reformat?), and every derived number would"
            " silently shrink with the corpus. Fix the parser -- do not let this pass."
            % LIB_RS
        )
    return by_helper, pkgs_by_helper


class TestFn:
    def __init__(self, name: str, line: int):
        self.name = name
        self.line = line
        self.claims: list[tuple[str, str, bool]] = []  # (atom, kind, partial)
        self.none_reason: str | None = None
        self.has_ignore = False
        self.bad_claim_lines: list[tuple[int, str]] = []

    @property
    def declared(self) -> bool:
        """The test said something -- either it names atoms, or it says `none -- why`."""
        return bool(self.claims) or self.none_reason is not None


class CorpusFile:
    def __init__(self, path: Path):
        self.path = path
        self.classes: set[str] = set()
        self.spawns_external = False
        self.binaries: list[str] = [IN_PROCESS_PKG]
        self.tests: list[TestFn] = []
        self.stray_claims: list[tuple[int, str]] = []  # claims not attached to a #[test]


def scan_file(path: Path, by_helper: dict[str, set[str]],
              pkgs_by_helper: dict[str, set[str]]) -> CorpusFile:
    raw = path.read_text()
    code = strip_code(raw)
    idents = set(re.findall(r"[A-Za-z0-9_]+", code))

    cf = CorpusFile(path)
    pkgs: set[str] = set()
    for ident in idents:
        if ident in FOREIGN_ROOTS:
            cf.classes.add(FOREIGN_ROOTS[ident])
        if ident in by_helper:
            cf.classes |= by_helper[ident]
        if ident in WZ_BINARY_ROOTS:
            pkgs.add(WZ_BINARY_ROOTS[ident])
        if ident in pkgs_by_helper:
            pkgs |= pkgs_by_helper[ident]
    if PICO_FFI_CRATE in idents:
        cf.classes.add("codec")
    cf.spawns_external = bool(pkgs or (idents & set(FOREIGN_ROOTS)) or (idents & set(by_helper)))
    # A file may drive several wz binaries. Carry them ALL: the containment arm unions
    # their closures, and a union is a superset, so it can never produce a false FAIL --
    # only a weaker true one. Picking one (the previous behaviour, and the alphabetically
    # first at that, which is wz-ap-demo with its 110-feature union) would have validated
    # a tight subset binary's claims against the fattest closure in the tree.
    cf.binaries = sorted(pkgs) if pkgs else [IN_PROCESS_PKG]

    # Attach claims to the #[test] fn they precede. A claim block is the run of comment
    # lines immediately above the attribute stack (mirrors how Layer C0 already reasons
    # about #[ignore] adjacency).
    #
    # Claims are read from the RAW text (they are comments) but the #[test] attribute is
    # read from the STRIPPED text -- so a test that has been commented OUT with /* ... */
    # is not a test, and cannot carry its atoms into `proven`. ("Comment out the flaky
    # interop test" must not keep its proofs green.) strip_code preserves line structure,
    # so the two views stay index-aligned.
    lines = raw.splitlines()
    code_lines = code.splitlines()
    while len(code_lines) < len(lines):
        code_lines.append("")

    pending: list[tuple[int, str, str, bool]] = []
    pending_none: str | None = None
    pending_bad: list[tuple[int, str]] = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        m = CLAIM_RE.match(line)
        if m:
            atom, kind, partial = m.group("atom"), m.group("kind"), bool(m.group("partial"))
            pending.append((idx + 1, atom, kind, partial))
            continue
        n = NONE_RE.match(line)
        if n:
            pending_none = n.group("reason")
            continue
        if "wz-proves" in line:
            pending_bad.append((idx + 1, stripped))
            continue
        if TEST_ATTR_RE.match(code_lines[idx]):
            # Find the fn name below the attribute stack (in code, not raw).
            j = idx
            fn_name = "?"
            has_ignore = False
            # Attributes ABOVE the #[test] line count too: `#[ignore]` written first
            # would otherwise leave has_ignore False, and the test would be reported as
            # executing on every push via Layer C1 while cargo skipped it.
            k = idx - 1
            while k >= 0 and code_lines[k].strip().startswith("#["):
                if code_lines[k].strip().startswith("#[ignore"):
                    has_ignore = True
                k -= 1
            while j < len(code_lines):
                s = code_lines[j].strip()
                if s.startswith("#[ignore"):
                    has_ignore = True
                fm = re.match(r"(?:pub )?(?:async )?fn ([A-Za-z0-9_]+)", s)
                if fm:
                    fn_name = fm.group(1)
                    break
                j += 1
            t = TestFn(fn_name, idx + 1)
            t.has_ignore = has_ignore
            t.claims = [(a, k, p) for (_, a, k, p) in pending]
            t.none_reason = pending_none
            t.bad_claim_lines = list(pending_bad)
            cf.tests.append(t)
            pending, pending_none, pending_bad = [], None, []
            continue
        if stripped.startswith("//") or stripped == "":
            continue
        # Any other code line breaks the adjacency run.
        if pending or pending_bad:
            cf.stray_claims.extend([(ln, f"{a} {k}") for (ln, a, k, _p) in pending])
            cf.stray_claims.extend(pending_bad)
        pending, pending_none, pending_bad = [], None, []
    if pending or pending_bad:
        cf.stray_claims.extend([(ln, f"{a} {k}") for (ln, a, k, _p) in pending])
        cf.stray_claims.extend(pending_bad)
    return cf


def scan_all() -> list[CorpusFile]:
    by_helper, pkgs_by_helper = helper_classes()
    return [
        scan_file(p, by_helper, pkgs_by_helper)
        for p in sorted(TESTS_DIR.glob("*.rs"))
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list-corpus", action="store_true",
                    help="foreign-corpus files: <path>\\t<classes>")
    ap.add_argument("--list-spawn", action="store_true",
                    help="files spawning an external binary (Layer C0 predicate)")
    ap.add_argument("--list-claims", action="store_true",
                    help="<path>\\t<fn>\\t<atom>\\t<kind>\\t<partial>")
    args = ap.parse_args()

    files = scan_all()
    if args.list_spawn:
        for cf in files:
            if cf.spawns_external:
                print(cf.path.relative_to(REPO_ROOT))
    if args.list_corpus:
        for cf in files:
            if cf.classes:
                print("%s\t%s" % (cf.path.relative_to(REPO_ROOT),
                                  ",".join(sorted(cf.classes))))
    if args.list_claims:
        for cf in files:
            for t in cf.tests:
                for atom, kind, partial in t.claims:
                    print("%s\t%s\t%s\t%s\t%s" % (
                        cf.path.relative_to(REPO_ROOT), t.name, atom, kind,
                        "partial" if partial else "full"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

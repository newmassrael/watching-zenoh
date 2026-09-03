#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y259 (no register item) — the CROSS-IMPL PROOF corpus: one predicate, two consumers.

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
import bisect
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
    # R311y841 — the CORE `zenoh-examples` applications (`z_queryable` /
    # `z_get`), a class of their own on the reasoning the zenoh-ext entry above
    # states. They are the real zenoh-full Rust stack at the pinned version and
    # they are NOT the router: `z_queryable` DECLARES a queryable and answers
    # queries, which zenohd does not do and cannot witness, and `z_get` is a
    # querier with a `--target` flag no other oracle in this tree has. Folding
    # them into `zenohd` would make every claim in this family read
    # `wz->zenohd` against a counterparty that is not zenohd.
    "zenoh_core_example_binary": "zenoh-core",
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
    # R311y565 — the real `libzenohc.so`, zenoh's REFERENCE implementation, as a
    # library. Registered for the reason the pico entries above were registered
    # at R311y536, and it had the identical consequence: the `api-compat-c`
    # twice-and-diff legs LINK and RUN that library on every Layer C1cc pass, and
    # with no root here the classifier saw no foreign artifact, so A4 forbade
    # them a claim and the atom's strongest witness went uncounted. A class of
    # its own rather than more `zenohd` roots: zenoh-c is the cbindgen wrapper
    # over zenoh Rust, not the router, and folding it in would make every claim
    # read `wz->zenohd` against a counterparty that is not zenohd.
    "zenoh_c_shared_library": "zenoh-c-lib",
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
    r"(?P<kind>wz->pico|pico->wz|wz->zenoh-ext|zenoh-ext->wz|wz->zenoh-c|zenoh-c->wz"
    # R311y841 — `wz->zenoh` / `zenoh->wz` MUST follow the two hyphen-suffixed
    # zenoh kinds above: alternation is first-match, so listing the shorter one
    # first would claim the `wz->zenoh` prefix of `wz->zenoh-ext` and leave
    # `-ext` to fail the tail anchor.
    r"|wz->zenohd|zenohd->wz|wz->zenoh|zenoh->wz|codec-parity)"
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
    # R311y841 — the core zenoh example applications. Distinct from `zenohd`
    # because the counterparty is a zenoh SESSION with a queryable, not the
    # router; see the `zenoh_core_example_binary` note in FOREIGN_ROOTS.
    "wz->zenoh",
    "zenoh->wz",
    # R311y565 — the reference implementation, linked rather than spawned. There
    # is no zenoh-c BINARY to spawn: zenoh-c is a library, so the only witness
    # shape available is the compile-once-link-twice differential, which is also
    # the strongest one.
    "wz->zenoh-c",
    "zenoh-c->wz",
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
    # R311y841 — only the core zenoh examples can witness a `zenoh` kind, for
    # the same reason only zenohd can witness a zenohd one. `zenoh-ext` is NOT
    # accepted here: those binaries carry the advanced plane and, for the
    # QUERYABLE question this kind exists for, they are a different application.
    "wz->zenoh": {"zenoh-core"},
    "zenoh->wz": {"zenoh-core"},
    # Only the library can witness a zenoh-c kind, for the same reason only
    # zenohd can witness a zenohd one — and unlike pico there is no spawned-CLI
    # alternative to also accept.
    "wz->zenoh-c": {"zenoh-c-lib"},
    "zenoh-c->wz": {"zenoh-c-lib"},
    # R311y628 — `pico-lib` joins, on this dict's OWN stated reasoning: "linking
    # or dlopening the real implementation is a STRONGER witness than spawning
    # it, so a kind that accepts the spawned CLI must accept the library." That
    # note is R311y536's, which added `pico-lib` to the two DIRECTIONAL pico
    # kinds and did not revisit this one — `codec-parity` predates the class
    # existing, so its `{codec}` was never a judgement about dlopen, it was
    # written before dlopen was an option here.
    #
    # The two classes are the same thing by the property that matters: the real
    # C implementation running in THIS process, adjudicating wz's answer. The
    # only difference is link-time versus runtime resolution, and the runtime
    # form is if anything the stricter one — `RTLD_LOCAL` keeps the two `z_*`
    # symbol sets apart, where a program linking both resolves each name once
    # and can silently compare a library against itself.
    #
    # NOT a loosening: the spawn classes (`pico`, `zenohd`, ...) are still
    # refused, which is what this entry exists to say. Measured by probe — a
    # `codec-parity` claim from a spawned-CLI file still fails A4-7.
    "codec-parity": {"codec", "pico-lib"},
}

TEST_ATTR_RE = re.compile(r"^\s*#\[(?:tokio::)?test\b")

# R2280 (open-debt item 619) — the `#[ignore]` REASON, read ACROSS LINES.
#
# Layer C0's ownership arm used to carry its own line-oriented
# `#\[ignore\s*=\s*"(.*?)"\s*\]`, which cannot see an attribute whose string
# literal is `\`-continued onto the next line. Measured R2280 over
# `crates/wz-integration-tests/tests`: 78 of the 449 reasons are written that
# way, and `--count-reasons` re-derives both numbers at any later date. The
# reason is what names the owning lane, so a reader blind to 78 of them is one
# that would swallow a future declaration whole. Two parsers for one predicate
# is the shape R2279 removed from the arm above it; this is the module's answer
# and the arm consumes it.
#
# `pos`-anchored rather than `^`-anchored: `pattern.match(s, pos)` starts AT pos,
# and a leading `\s*` would skip blank lines forward onto an unrelated attribute,
# so the leading run is `[ \t]*`.
IGNORE_REASON_RE = re.compile(
    r'[ \t]*#\[\s*ignore\s*=\s*"(?P<reason>(?:[^"\\]|\\.)*)"\s*\]', re.S)

_RUST_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0",
                 '"': '"', "'": "'", "\\": "\\"}


def unescape_rust_string(lit: str) -> str:
    """Resolve the escapes a Rust string literal carries, line continuation included.

    A `\\` at end of line drops the newline AND the next line's leading
    whitespace, which is how every multi-line reason in this crate is written.
    Without that rule the joined reason would carry the source's indentation, and
    a matcher keyed on word spacing would read a different sentence than rustc
    does.
    """
    out: list[str] = []
    i, n = 0, len(lit)
    while i < n:
        c = lit[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= n:
            break
        e = lit[i]
        i += 1
        if e == "\n":
            while i < n and lit[i] in " \t\r":
                i += 1
            continue
        out.append(_RUST_ESCAPES.get(e, e))
    return "".join(out)


def line_starts_of(text: str) -> list[int]:
    """Offset of every line start, index-aligned with `text.splitlines()`."""
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())
    return starts


def attribute_spans(code: str) -> dict[int, int]:
    """`#[...]` attributes as {first line index: last line index}, read from CODE.

    From the comment- and string-stripped view, so a `[` inside a reason string
    or a doc comment cannot unbalance the count. The attribute walk around a
    `#[test]` moves by LINES, and a `\\`-continued `#[ignore = ".."]` occupies
    two of them; the second is blank in the stripped view, which is what stopped
    the upward walk dead.
    """
    starts = line_starts_of(code)
    spans: dict[int, int] = {}
    n = len(code)
    for m in re.finditer(r"#\[", code):
        i, depth = m.end(), 1
        while i < n and depth:
            if code[i] == "[":
                depth += 1
            elif code[i] == "]":
                depth -= 1
            i += 1
        if depth:
            continue
        first = bisect.bisect_right(starts, m.start()) - 1
        last = bisect.bisect_right(starts, i - 1) - 1
        spans[first] = last
    return spans


def ignore_reason_at(raw: str, starts: list[int], idx: int) -> str | None:
    """The reason of the `#[ignore = ".."]` that begins on raw line `idx`."""
    m = IGNORE_REASON_RE.match(raw, starts[idx])
    return unescape_rust_string(m.group("reason")) if m else None


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


def _helper_chunks() -> dict[str, str]:
    """Every `common::*` helper, mapped to its source text.

    Extracted from [`helper_classes`] at R2325 so the SECOND question asked of
    the same parse — [`helper_idents`], which resolves what a helper can REACH
    rather than which class it belongs to — cannot drift into a second spelling
    of the fn-indent split. The module header's warning about C0 and A4 growing
    two greps of one question applies to this parse just as much: it is the
    single place that knows a helper is `fn` at one indent inside
    `pub mod common { .. }`.
    """
    src = strip_code(LIB_RS.read_text())
    chunks: dict[str, str] = {}
    parts = re.split(r"\n    (?:pub )?fn ", src)
    for part in parts[1:]:
        m = re.match(r"([A-Za-z0-9_]+)", part)
        if m:
            chunks[m.group(1)] = part
    return chunks


def helper_idents() -> dict[str, frozenset[str]]:
    """Every `common::*` helper, mapped to the identifiers it can REACH.

    R2325 (open-debt item 9). [`helper_classes`] answers "which foreign class /
    wz package does this helper resolve", which is the two questions this module
    was built for. A third consumer needs a different projection of the same
    call graph: `binary_freshness_lint` has to know whether a fixture's route to
    `wz-ap-demo` ever reaches `Command::spawn`, because a demo run to COMPLETION
    and a demo held ALIVE are two different exposures to a stale binary, and the
    fixture names only the helper.

    Returning the identifier set rather than a boolean is deliberate: the
    predicate belongs to the consumer that has the reason for it, and a second
    consumer asking a different question of the same helper does not need a
    second traversal here. The same guard as `helper_classes` — an empty parse
    is a FAILURE, not an empty answer, because every derived number would
    silently shrink with the corpus.
    """
    chunks = _helper_chunks()
    if not chunks:
        raise RuntimeError(
            "crossimpl_corpus: resolved NO harness helpers from %s. The `pub mod common`"
            " fn-indent split has broken (a reformat?), and every derived number would"
            " silently shrink with the corpus. Fix the parser -- do not let this pass."
            % LIB_RS
        )

    memo: dict[str, frozenset[str]] = {}

    def resolve(name: str, seen: frozenset[str]) -> frozenset[str]:
        if name in seen:
            return frozenset()
        cached = memo.get(name)
        if cached is not None:
            return cached
        body = chunks.get(name)
        if body is None:
            return frozenset()
        seen = seen | {name}
        idents = set(re.findall(r"[A-Za-z0-9_]+", body))
        out = set(idents)
        for ident in idents:
            if ident in chunks and ident != name:
                out |= resolve(ident, seen)
        frozen = frozenset(out)
        # Only a resolution that saw the WHOLE subtree is cacheable: one cut
        # short by `seen` is correct for its caller and wrong for everyone else.
        if not (seen - {name}):
            memo[name] = frozen
        return frozen

    return {name: resolve(name, frozenset()) for name in chunks}


def helper_classes() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Resolve every `common::*` helper transitively to what it can reach.

    Returns (foreign_classes_by_helper, wz_packages_by_helper). Both are resolved
    through the CALL GRAPH, not by grepping the test for the root's name: the flagship
    zenohd proofs reach zenohd through `spawn_zenohd`, never naming `zenohd_binary(`.
    The same is true of the wz side -- a future spawn_wz_ap_demo() wrapper would make
    every caller look like an in-process test, and A4-5 would then check the WRONG
    binary's feature closure (the two closures are not nested).
    """
    # Every helper is a fn at one indent level inside `pub mod common { ... }`.
    chunks = _helper_chunks()

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


def local_fn_bodies(code: str) -> dict[str, str]:
    """Every `fn NAME` in one file, mapped to its brace-matched body.

    R311y571 — the per-TEST half of [`helper_classes`]. That one resolves the
    shared `common::*` helpers; this one resolves a file's OWN functions, which
    is where a twice-and-diff leg keeps its `run_both_arms()`. Both are needed
    for the same reason: a test reaches a foreign implementation through a call,
    not by naming the resolver.

    Any indent and any `fn`, so `impl` methods and functions nested inside
    `mod tests` are included — a harness struct's method is as much a route to
    the oracle as a free function is.
    """
    bodies: dict[str, str] = {}
    for m in re.finditer(r"\bfn\s+([A-Za-z0-9_]+)", code):
        name = m.group(1)
        open_at = code.find("{", m.end())
        if open_at < 0:
            continue
        depth, i, n = 0, open_at, len(code)
        while i < n:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        # Later definitions win only if the earlier one was not closed; a name
        # defined twice in one file (an `impl` twin) contributes both bodies.
        bodies[name] = bodies.get(name, "") + code[open_at:i]
    return bodies


def pico_ffi_imports(code: str) -> set[str]:
    """Names a file pulls in from `zenoh_pico_sys`, so a test that CALLS one is
    reaching the linked C library even though it never names the crate.

    The `codec` class is the only one attached to a crate rather than to a
    resolver function, and that difference is exactly what a naive per-test scan
    gets wrong: `use zenoh_pico_sys::{_z_scout_encode, ...}` sits at the top of
    the file and the test body says `_z_scout_encode(..)`. Measured before it
    was believed — the first version of the per-test resolver reported 56 codec
    tests as reaching nothing, which was its own blind spot and not a finding.
    """
    names: set[str] = set()
    for m in re.finditer(r"\buse\s+" + PICO_FFI_CRATE + r"\s*::\s*(\{[^}]*\}|[A-Za-z0-9_]+)",
                         code):
        names |= set(re.findall(r"[A-Za-z0-9_]+", m.group(1)))
    for m in re.finditer(PICO_FFI_CRATE + r"\s*::\s*([A-Za-z0-9_]+)", code):
        names.add(m.group(1))
    names.discard("self")
    return names


def reexec_edges(raw_code: str, local: dict[str, str]) -> dict[str, set[str]]:
    """Call edges a RE-EXEC harness makes through a string literal.

    `layer3_keyexpr_canon.rs` measures pico's real `_z_keyexpr_canonize` by
    re-running the test binary with `--exact <name>`, because the outcome under
    test is a SIGABRT that would take the parent process with it. The name is a
    string, `strip_code` removes strings, and the call graph then ends at the
    spawning helper -- three true `codec-parity` claims looked self-witnessed.

    Only an EXACT match against a function this file defines counts, and only
    inside a string literal. A comment is deliberately not enough: this module's
    header records that a lone `// zenohd_binary(` comment must never buy a test
    its corpus membership, and the same reasoning applies to an edge.
    """
    edges: dict[str, set[str]] = {}
    for name, body in local.items():
        found = {lit for lit in re.findall(r'"([^"\\\n]*)"', body) if lit in local}
        if found:
            edges[name] = found
    return edges


def reachable_classes(fn_name: str, local: dict[str, str],
                      by_helper: dict[str, set[str]],
                      ffi_names: frozenset[str] = frozenset(),
                      edges: dict[str, set[str]] | None = None) -> set[str]:
    """The foreign classes ONE function can reach, through the call graph."""
    classes: set[str] = set()
    seen: set[str] = set()
    stack = [fn_name]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        body = local.get(name)
        if body is None:
            continue
        for ident in set(re.findall(r"[A-Za-z0-9_]+", body)):
            if ident in FOREIGN_ROOTS:
                classes.add(FOREIGN_ROOTS[ident])
            if ident in by_helper:
                classes |= by_helper[ident]
            if ident == PICO_FFI_CRATE or ident in ffi_names:
                classes.add("codec")
            if ident in local and ident not in seen:
                stack.append(ident)
        for target in (edges or {}).get(name, ()):
            if target not in seen:
                stack.append(target)
    return classes


def reachable_idents(fn_name: str, local: dict[str, str],
                     edges: dict[str, set[str]] | None = None) -> frozenset[str]:
    """Every identifier ONE function can reach, through the same call graph.

    R2325 (open-debt item 9). [`reachable_classes`] and [`reachable_external`]
    each walk this graph and fold it into their own answer as they go, which is
    right for them and useless to a third question. `binary_freshness_lint` asks
    TWO things of one walk — does this fixture reach the demo, and does its route
    hold the demo ALIVE — and folding either into the traversal would mean
    walking twice or teaching this module a predicate that is not its business.

    Deliberately identifiers and not classes: the caller owns the meaning. What
    is shared is the graph — local fns, plus the string-literal re-exec edges
    [`reexec_edges`] resolves, which is exactly the hole that made three
    self-witnessed claims look proven.
    """
    seen: set[str] = set()
    stack = [fn_name]
    idents: set[str] = set()
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        body = local.get(name)
        if body is None:
            continue
        here = set(re.findall(r"[A-Za-z0-9_]+", body))
        idents |= here
        for ident in here:
            if ident in local and ident not in seen:
                stack.append(ident)
        for target in (edges or {}).get(name, ()):
            if target not in seen:
                stack.append(target)
    return frozenset(idents)


def reachable_external(fn_name: str, local: dict[str, str],
                       by_helper: dict[str, set[str]],
                       pkgs_by_helper: dict[str, set[str]],
                       edges: dict[str, set[str]] | None = None) -> bool:
    """Q1, ONE LEVEL FINER — does THIS TEST reach an external binary?

    R2279 (open-debt item 618). `CorpusFile.spawns_external` answers Q1 for the
    FILE, and Layer C0 held every `#[test]` in such a file to `#[ignore]`. That
    over-approximates for exactly the reason [`TestFn.classes`] was split out of
    `CorpusFile.classes` one question over: a file that spawns a binary
    somewhere made every test in it a binary-dep test, whether or not the test
    calls anything that spawns.

    The cost was not hypothetical. R2277 added a pure vocabulary assertion —
    it spawns nothing, needs no oracle, and belongs in Layer C1 — to a file
    that spawns zenohd, and the file-scoped rule had no way to say so: adding
    `#[ignore]` to satisfy it reds C0's OWN skip-token gate instead, because an
    ignored test in a `zenohd`-named fixture must carry a Layer E token, and
    then Layer E would sweep a test Layer E cannot run. There was no edit that
    made both gates green, which is what a rule stated one level too coarse
    looks like from inside.

    The ROOT SET is `CorpusFile.spawns_external`'s, unchanged, so this is a
    refinement rather than a different question: a test this returns True for
    always sits in a file that predicate is also True for. The linked-library
    (`codec`) route is deliberately NOT a root here, exactly as it is not one
    there -- linking pico needs no binary on disk, which is why codec tests run
    unignored in Layer C1 and are the only foreign proof every push executes.
    """
    seen: set[str] = set()
    stack = [fn_name]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        body = local.get(name)
        if body is None:
            continue
        for ident in set(re.findall(r"[A-Za-z0-9_]+", body)):
            if ident in FOREIGN_ROOTS or ident in by_helper:
                return True
            if ident in WZ_BINARY_ROOTS or ident in pkgs_by_helper:
                return True
            if ident in local and ident not in seen:
                stack.append(ident)
        for target in (edges or {}).get(name, ()):
            if target not in seen:
                stack.append(target)
    return False


class TestFn:
    def __init__(self, name: str, line: int):
        self.name = name
        self.line = line
        self.claims: list[tuple[str, str, bool]] = []  # (atom, kind, partial)
        self.none_reason: str | None = None
        self.has_ignore = False
        # R2280 — the reason string of that `#[ignore]`, joined across `\`
        # continuations, or None for a bare `#[ignore]` / no attribute at all.
        # `has_ignore` alone cannot answer WHO runs the test, which is the
        # question Layer C0's ownership arm asks.
        self.ignore_reason: str | None = None
        self.bad_claim_lines: list[tuple[int, str]] = []
        # R311y571 — the classes THIS test reaches, as opposed to the ones its
        # FILE reaches. See `CorpusFile.classes`.
        self.classes: set[str] = set()
        # R2279 — Q1 at the same resolution. See `reachable_external`.
        self.spawns_external = False

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
    local_bodies = local_fn_bodies(code)
    ffi_names = frozenset(pico_ffi_imports(code))
    edges = reexec_edges(raw, local_fn_bodies(raw))

    lines = raw.splitlines()
    code_lines = code.splitlines()
    while len(code_lines) < len(lines):
        code_lines.append("")

    # R2280 — the two indexes the `#[ignore]` reason reader needs: where each raw
    # line begins (the reason is read from RAW, since strip_code blanks string
    # literals) and which attribute a given LAST line belongs to (the reason may
    # be `\`-continued, so an attribute is not one line).
    line_starts = line_starts_of(raw)
    while len(line_starts) < len(lines):
        line_starts.append(len(raw))
    attr_first_line = {last: first for first, last in attribute_spans(code).items()}

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
            ignore_reason: str | None = None
            # Attributes ABOVE the #[test] line count too: `#[ignore]` written first
            # would otherwise leave has_ignore False, and the test would be reported as
            # executing on every push via Layer C1 while cargo skipped it.
            #
            # R2280 — the walk moves attribute by attribute, not line by line. A
            # `\`-continued `#[ignore = ".."]` above a `#[test]` ends on a line
            # that is BLANK in the stripped view, and the old `startswith("#[")`
            # test stopped there, reading the attribute as absent. Measured R2280:
            # all 449 `#[ignore]`s in this crate sit BELOW their `#[test]`, so
            # that arm is a latent hole, not a live one -- which is the reason to
            # fix it while the shared reader is being written rather than to claim
            # a gate over an empty population.
            k = idx - 1
            while k >= 0:
                start = attr_first_line.get(k)
                if start is None:
                    break
                if code_lines[start].strip().startswith("#[ignore"):
                    has_ignore = True
                    ignore_reason = ignore_reason_at(raw, line_starts, start) or ignore_reason
                k = start - 1
            while j < len(code_lines):
                s = code_lines[j].strip()
                if s.startswith("#[ignore"):
                    has_ignore = True
                    ignore_reason = ignore_reason_at(raw, line_starts, j) or ignore_reason
                fm = re.match(r"(?:pub )?(?:async )?fn ([A-Za-z0-9_]+)", s)
                if fm:
                    fn_name = fm.group(1)
                    break
                j += 1
            t = TestFn(fn_name, idx + 1)
            t.ignore_reason = ignore_reason
            t.classes = reachable_classes(fn_name, local_bodies, by_helper, ffi_names, edges)
            t.spawns_external = reachable_external(
                fn_name, local_bodies, by_helper, pkgs_by_helper, edges)
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


# R2280 (open-debt item 619) — the reason reader's own fixture.
#
# Every shape here is one the LINE-oriented reader Layer C0 used to carry would
# have got wrong, plus the two directions in which a looser reader would invent a
# reason. A fixture that only holds shapes the old code already handled proves
# the new code compiles, not that it fixed anything -- so the selftest asserts,
# for the continuation cases, that the line-wise spelling really does miss them.
_SELFTEST_FIXTURE = '''\
#[test]
#[ignore = "single line; Layer Z runs via --ignored"]
fn one_line_reason() {}

#[test]
#[ignore = "continued; \\
            Layer Q runs via --ignored"]
fn continued_reason() {}

#[test]
#[ignore = "three; \\
            parts; \\
            Layer M runs via --ignored"]
fn thrice_continued_reason() {}

#[test]
#[ignore]
fn bare_ignore() {}

#[ignore = "above the test; \\
            Layer Ewire runs via --ignored"]
#[test]
fn reason_above_the_test() {}

#[test]
#[ignore = "carries a \\"quoted\\" word; Layer G runs via --ignored"]
fn escaped_quote_in_reason() {}

#[test]
#[ignore = "mentions [a bracket] before Layer F runs via --ignored"]
fn bracket_in_reason() {}

/// A doc comment that merely writes #[ignore = "Layer Z runs via --ignored"]
/// must not become this test's reason.
#[test]
fn documented_but_not_ignored() {}

#[test]
fn plain_test() {}
'''

_SELFTEST_EXPECTED = {
    "one_line_reason": "single line; Layer Z runs via --ignored",
    "continued_reason": "continued; Layer Q runs via --ignored",
    "thrice_continued_reason": "three; parts; Layer M runs via --ignored",
    "bare_ignore": None,
    "reason_above_the_test": "above the test; Layer Ewire runs via --ignored",
    "escaped_quote_in_reason": 'carries a "quoted" word; Layer G runs via --ignored',
    "bracket_in_reason": "mentions [a bracket] before Layer F runs via --ignored",
    "documented_but_not_ignored": None,
    "plain_test": None,
}
# The tests whose reason the old reader could not see AT ALL. The selftest
# re-runs that reader over the fixture and requires it to still miss them --
# otherwise the fixture has drifted into shapes that never needed fixing.
_SELFTEST_LINE_BLIND = {"continued_reason", "thrice_continued_reason",
                        "reason_above_the_test"}
_SELFTEST_MUST_IGNORE = {"one_line_reason", "continued_reason",
                         "thrice_continued_reason", "bare_ignore",
                         "reason_above_the_test", "escaped_quote_in_reason",
                         "bracket_in_reason"}


def selftest() -> bool:
    import tempfile

    by_helper, pkgs_by_helper = helper_classes()
    ok = True
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "reason_reader_fixture.rs"
        path.write_text(_SELFTEST_FIXTURE)
        cf = scan_file(path, by_helper, pkgs_by_helper)
        seen = {t.name: t.ignore_reason for t in cf.tests}
        if set(seen) != set(_SELFTEST_EXPECTED):
            print("SELFTEST the fixture's tests were not all found: got %s"
                  % sorted(seen), file=sys.stderr)
            return False
        for name, want in _SELFTEST_EXPECTED.items():
            if seen[name] != want:
                ok = False
                print("SELFTEST %s: reason is %r, expected %r"
                      % (name, seen[name], want), file=sys.stderr)
        for t in cf.tests:
            want_ignored = t.name in _SELFTEST_MUST_IGNORE
            if t.has_ignore != want_ignored:
                ok = False
                print("SELFTEST %s: has_ignore is %s, expected %s"
                      % (t.name, t.has_ignore, want_ignored), file=sys.stderr)

    # The CONTROL. A line-oriented reader over the same fixture must still be
    # blind to exactly the continued shapes; if it is not, this fixture has
    # stopped exercising the defect it was written for.
    line_re = re.compile(r'#\[ignore\s*=\s*"(.*?)"\s*\]')
    for name in sorted(_SELFTEST_LINE_BLIND):
        reason = _SELFTEST_EXPECTED[name]
        assert reason is not None
        if any(line_re.search(ln) and reason in line_re.search(ln).group(1)
               for ln in _SELFTEST_FIXTURE.splitlines()):
            ok = False
            print("SELFTEST CONTROL %s: a line-oriented reader CAN read this "
                  "reason, so the fixture no longer covers the defect" % name,
                  file=sys.stderr)
    if ok:
        print("crossimpl_corpus selftest: %d reason shape(s) read, %d of them "
              "invisible to a line-oriented reader"
              % (len(_SELFTEST_EXPECTED), len(_SELFTEST_LINE_BLIND)))
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list-corpus", action="store_true",
                    help="foreign-corpus files: <path>\\t<classes>")
    ap.add_argument("--list-spawn", action="store_true",
                    help="files spawning an external binary (the coarse Q1)")
    ap.add_argument("--list-spawn-tests", action="store_true",
                    help="<path>\\t<line>\\t<fn>\\t<reaches>\\t<ignored> for every test "
                         "in a spawn-class file (Layer C0 predicate, R2279)")
    ap.add_argument("--list-claims", action="store_true",
                    help="<path>\\t<fn>\\t<atom>\\t<kind>\\t<partial>")
    ap.add_argument("--list-ignore-reasons", action="store_true",
                    help="<path>\\t<line>\\t<fn>\\t<reason> for every #[ignore] test "
                         "that carries a reason, continuations joined (R2280)")
    ap.add_argument("--count-reasons", action="store_true",
                    help="the reason census this module's header quotes: how many "
                         "reasons exist and how many a LINE-oriented reader misses")
    ap.add_argument("--selftest", action="store_true",
                    help="drive the reason reader over the shapes the old "
                         "line-oriented one swallowed (R2280)")
    args = ap.parse_args()

    if args.selftest:
        return 0 if selftest() else 1

    files = scan_all()
    if args.list_ignore_reasons:
        for cf in files:
            for t in cf.tests:
                if t.ignore_reason is None:
                    continue
                print("%s\t%d\t%s\t%s" % (
                    cf.path.relative_to(REPO_ROOT), t.line, t.name, t.ignore_reason))
    if args.count_reasons:
        # The measurement the module header and Layer C0's ownership arm both
        # quote, re-derived rather than restated. `line_only` is what a reader
        # that matched `#[ignore = ".."]` within a single line would have found;
        # the gap between it and `reasons` is the blind spot item 619 was filed
        # for, and it is a number that can move in either direction.
        line_re = re.compile(r'#\[ignore\s*=\s*"(.*?)"\s*\]')
        owner_re = re.compile(r"Layer\s+([A-Za-z0-9]+)\s+runs via")
        wide_re = re.compile(r"Layer\s+([A-Za-z0-9]+)")
        tests = reasons = line_only = bare = owned = mentions = 0
        distinct: set[str] = set()
        for cf in files:
            raw_lines = cf.path.read_text().splitlines()
            for t in cf.tests:
                tests += 1
                if t.ignore_reason is None:
                    bare += 1 if t.has_ignore else 0
                    continue
                reasons += 1
                distinct.add(t.ignore_reason)
                if owner_re.search(t.ignore_reason):
                    owned += 1
                if wide_re.search(t.ignore_reason):
                    mentions += 1
                if any(line_re.search(ln) for ln in raw_lines[t.line - 1:t.line + 4]):
                    line_only += 1
        print("tests=%d ignore_with_reason=%d readable_line_wise=%d "
              "continuation_only=%d bare_ignore=%d"
              % (tests, reasons, line_only, reasons - line_only, bare))
        # The four figures `lane_reach_gate.py`'s header argues from, so that
        # header can be re-derived instead of re-asserted. `wide` minus `owned`
        # is the number of tests a matcher loose enough to see every spelling
        # would invent an owner for.
        print("distinct_reasons=%d mention_a_layer=%d declare_an_owner=%d "
              "would_be_invented=%d"
              % (len(distinct), mentions, owned, mentions - owned))
    if args.list_spawn:
        for cf in files:
            if cf.spawns_external:
                print(cf.path.relative_to(REPO_ROOT))
    if args.list_spawn_tests:
        # EVERY test in a spawn-class file, both verdicts spelled out, because
        # the consumer has to be able to count its own population and refuse an
        # empty one. Printing only the violations would make "nothing to check"
        # and "nothing wrong" the same output.
        for cf in files:
            if not cf.spawns_external:
                continue
            for t in cf.tests:
                print("%s\t%d\t%s\t%d\t%d" % (
                    cf.path.relative_to(REPO_ROOT), t.line, t.name,
                    1 if t.spawns_external else 0,
                    1 if t.has_ignore else 0))
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

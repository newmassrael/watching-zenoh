#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2355 (no register item) — a function that PRODUCES a TCP socket for a wz
link must reach the per-link TCP tuning SSOT.

Closes no register item: the defect was found while closing the
`transport-link-ws` ATOM, by reading the upstream link families rather than by
working a register entry, and no entry named it.

THE DEFECT THIS EXISTS FOR, and why no test could have found it.

zenoh sets `TCP_NODELAY` inside each link family's SHARED dial+accept
constructor, so every TCP-backed zenoh link runs with Nagle off in both
directions -- `io/zenoh-links/zenoh-link-tcp/src/unicast.rs` @
`socket.set_nodelay(true)`, `io/zenoh-links/zenoh-link-tls/src/unicast.rs` @
`tcp_stream.set_nodelay(true)`, `io/zenoh-links/zenoh-link-ws/src/unicast.rs` @
`get_stream(&socket).set_nodelay(true)`.

Those are the pin's REPO paths, deliberately, and in the anchored form: this
file is TRACKED, so it sits inside the population the citation gate scans, and
the registry-layout paths written first (`zenoh-link-*-<version>/src/..`) match
none of the pin's top-level roots and so were graded by nothing at all.

wz applied the same tuning at each CALLER of its shared connect primitive
instead. Four production dials reach TCP through
`iface_bind::connect_tcp_bound`; TWO of them took the step (`dial_tcp`,
`dial_tcp_host`) and TWO did not (`dial_ws`, `dial_tls`). The accept half was
uniform, because tcp/ws/tls all accept through `accept_tcp_on`, which did tune
-- so the divergence was DIAL-ONLY and scheme-specific.

Nothing failed. A link with Nagle on carries every byte; it just pays an ack
round-trip on small frames. `cargo test` cannot fail on a socket option nobody
reads, which is this tree's recorded lesson that a missing step needs a gate
rather than a test. The registry entry for `transport-link-ws` did not name it
either -- it named the accept seam, which is who NOTICED, not the population.

THE POPULATION IS DERIVED, NOT LISTED.

A hand-written list of dial seams has exactly the property that failed here:
someone adds the fifth one and forgets. So the scan derives it from the
signatures:

  PRODUCER  = a fn whose RETURN type mentions `TcpStream` and whose parameter
              list does NOT. It makes the socket, so it owns the tuning.
  CONSUMER  = a fn that TAKES a `TcpStream`. It was handed an already-tuned
              socket (`accept_ws`, `accept_tls`, `wire_tcp_stream`), so
              requiring it to tune again would be wrong, not merely noisy.

That discriminator is the whole design. `dial_ws() -> io::Result<WebSocketStream<TcpStream>>`
and `dial_tls() -> io::Result<TlsStream<TcpStream>>` are producers by their own
return types, with no list naming them, which is what makes a sixth family
land here on the day it is written.

REACHABILITY, NOT A NAME LIST -- and this is where the first draft was wrong.

The obvious rule is "a producer must NAME the tuning SSOT in its body", with
`configure_tcp_stream` / `connect_tcp_bound` / `accept_tcp_on` as the accepted
names. That rule PASSES THE DEFECT. `dial_ws` and `dial_tls` both called
`connect_tcp_bound` all along; what did not tune was `connect_tcp_bound`
ITSELF. The break was one link deeper than the leaf, so a gate that stops at
the leaf could never see it -- it would have reported OK on the exact tree this
file exists because of.

So the chain is resolved, and its ROOT is derived from the syscall rather than
declared:

  root      = a fn whose body calls `set_nodelay(`. Nothing names it here; the
              tuning is whatever actually sets the option.
  reaching  = the least fixpoint of "a fn whose body mentions the name of a
              reaching fn". Delegation counts to any depth, so `accept_tcp` ->
              `accept_tcp_on` -> `configure_tcp_stream` -> `set_nodelay`
              resolves, and so would a fifth family added tomorrow.
  offender  = a producer that is not reaching.

Run against this tree BEFORE the fix, that rule names `dial_ws` and `dial_tls`
and nothing else -- the measured population of the defect, arrived at without
either name appearing in this file.

WHAT THIS IS NOT. Resolution is by NAME, not by import path, so two distinct
functions sharing a name would be conflated -- and that error direction is
towards PASSING, which is the wrong way for a gate to be wrong. It is accepted
because the population is one crate's link pipelines, and the floor below
catches the case where the reader stops matching the tree altogether.

Nor does it check every PATH through a body: an arm that called the primitive
and another that called `TcpStream::connect` would satisfy it. That hole is why
the two e2e assertions exist next to it (`ws_e2e.rs` /
`tls_e2e.rs::a_*_link_disables_nagle_on_both_the_dial_and_the_accept_half`),
which read `nodelay()` back off the real socket on both halves. The scan
answers "does this producer reach the tuning at all"; the tests answer "does
the shipped door actually deliver it". Neither subsumes the other, and closing
the defect needed both: the tests prove the two broken schemes are fixed, the
scan is what a seventh scheme trips over.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# ONE copy of the "blank comments and string literals, keep offsets" rule. The
# doc comments in these very modules quote `TcpStream::connect` while EXPLAINING
# why a bound dial cannot use it, so a scan that read prose would classify the
# explanation as the code.
from solo_plane_page_lint import blank_noncode  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

# Where wz's link backends live. Every TCP-backed link pipeline is in this one
# crate; the C ABI and the demo consume its seams rather than making sockets.
CRATE = Path("crates/wz-runtime-tokio")

# The socket type whose tuning is at stake.
TCP = "TcpStream"

# The ROOT of the reachability walk. Not a wz function name -- the syscall
# wrapper that actually sets the option, so the walk starts from what the
# tuning IS rather than from what this tree currently calls it. Renaming
# `configure_tcp_stream` does not blind the gate; deleting the `set_nodelay`
# call empties the root set and every producer becomes an offender, which is
# the correct verdict rather than a silent pass.
TUNING_CALL = "set_nodelay("

# The PER-ITEM opt-out, for a producer that genuinely makes a socket no wz link
# rides (a probe, a proxy). Deliberately verbose: a marker typed by accident is
# a gate that turns itself off.
#
# It is matched against ONE item's own text (`_attribution_window`), not the
# file's. Reading it file-wide -- which the first draft did -- means a single
# marker anywhere silently exempts every producer in that file, so the one
# escape hatch this gate has would be wider than the sentence describing it.
# An exemption no second derivation bounds is not an exemption, it is an off
# switch, and this tree has paid for that shape before.
EXEMPT = "TCP-TUNING-NOT-A-LINK"

# Below this the scan resolved the wrong root or read the wrong crate. A run
# that found nothing to look at must not report OK -- the "a population of zero
# reports green" trap this tree has paid for more than once.
MIN_PRODUCERS = 4

# `fn NAME(...ARGS...) -> RET {`, tolerating the `pub`/`pub(crate)`/`async`
# prefixes and a multi-line signature. The body is taken by brace walk from the
# opening `{`, so a signature spanning lines is not a special case.
FN = re.compile(r"\bfn\s+(?P<name>\w+)\s*(?P<rest>\()", re.S)

# A call site: an identifier immediately followed by `(`. Word-anchored, so
# `dial_tcp_host(` is NOT read as a call to `dial_tcp` -- the substring reading
# that made the first walk useless.
CALL = re.compile(r"\b(\w+)\s*\(")


def _match_paren(text: str, open_idx: int) -> int:
    """Index just past the `)` closing the `(` at `open_idx`, or -1."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def _match_brace(text: str, open_idx: int) -> int:
    """Index just past the `}` closing the `{` at `open_idx`, or -1."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def _attribution_window(raw: str, start: int, end: int) -> str:
    """The RAW text one item's opt-out marker may live in.

    That is the item itself plus the contiguous comment / attribute block
    directly above it -- Rust's own attachment rule, so a marker written where a
    reader would write it (in the comment explaining WHY this socket is not a
    link) is found, and one written about a DIFFERENT function is not.

    Read from `raw` rather than the blanked copy on purpose: the marker lives in
    a comment, which `blank_noncode` has erased by design. Offsets are shared
    between the two, which is what makes the slice legal.

    A blank line ENDS the walk, and so does an attribute continuation line -- so
    a multi-line `#[cfg(any(..))]` above a marker truncates the window early.
    That direction is deliberate: a window that is too SMALL fails to exempt, and
    a gate that asks a person to look is wrong in the safe direction. A window
    that is too LARGE stops being a gate.
    """
    win = raw.rfind("\n", 0, start) + 1
    while win > 0:
        prev_end = win - 1  # the newline closing the line above
        prev_start = raw.rfind("\n", 0, prev_end) + 1
        above = raw[prev_start:prev_end].strip()
        if above.startswith("//") or above.startswith("#["):
            win = prev_start
            continue
        break
    return raw[win:end]


def _test_spans(text: str) -> list[tuple[int, int]]:
    """Byte spans of `#[cfg(test)] mod ... { .. }`, which the scan skips.

    A unit test that stands up a bare listener is not a link producer, and
    `link_pipeline.rs`'s own `#[cfg(test)]` module does exactly that.
    """
    spans: list[tuple[int, int]] = []
    for m in re.finditer(r"#\[cfg\(test\)\]", text):
        brace = text.find("{", m.end())
        if brace < 0:
            continue
        # Only a `mod` block; a `#[cfg(test)]` on a single fn is rare here and
        # would be caught by the fn walk anyway.
        head = text[m.end() : brace]
        if "mod " not in head:
            continue
        end = _match_brace(text, brace)
        if end > 0:
            spans.append((m.start(), end))
    return spans


def _functions(root: Path) -> tuple[list[dict], int]:
    """Every non-test fn in the crate's `src`, with its args / return / body."""
    fns: list[dict] = []
    scanned = 0
    for path in sorted((root / CRATE / "src").rglob("*.rs")):
        raw = path.read_text(encoding="utf-8", errors="replace")
        text = blank_noncode(raw)
        scanned += 1
        skip = _test_spans(text)
        for m in FN.finditer(text):
            if any(lo <= m.start() < hi for lo, hi in skip):
                continue
            args_end = _match_paren(text, m.start("rest"))
            if args_end < 0:
                continue
            brace = text.find("{", args_end)
            if brace < 0:
                continue
            end = _match_brace(text, brace)
            if end < 0:
                continue
            fns.append(
                {
                    "file": str(path.relative_to(root)),
                    "fn": m.group("name"),
                    "line": text.count("\n", 0, m.start()) + 1,
                    "args": text[m.start("rest") : args_end],
                    # A `where` clause or a trailing generic can carry the type
                    # name without it being the return; the return segment is
                    # what precedes the body brace, which is where `-> ..` lives.
                    "ret": text[args_end:brace],
                    "body": text[brace:end],
                    # THIS item's raw text, not the file's — see
                    # `_attribution_window` for why the difference is the whole
                    # difference between an exemption and an off switch.
                    "scope": _attribution_window(raw, m.start(), end),
                }
            )
    return fns, scanned


def _reaching(fns: list[dict]) -> set[str]:
    """Least fixpoint of "calls something that reaches the tuning".

    Seeded from the syscall, NOT from a name this file declares -- which is the
    whole reason it catches the R2355 shape, where every leaf named the right
    primitive and the primitive was the thing that did not tune.

    TWO RULES KEEP THE WALK FROM EATING THE CRATE, and both were learned by
    watching it do exactly that. A first pass propagated through SUBSTRINGS of
    the body, which made the closure 1179 functions wide out of 1396: `new`
    entered it, and after that every body containing the letters `new` was
    "reaching", including `connect_tcp_bound` on the tree where it demonstrably
    was not. The selftest passed throughout, because its fixtures were tidier
    than the tree -- a fixture with no `new` in it cannot measure what `new`
    does.

      1. CALL SITES, not substrings. Each body contributes the identifiers it
         actually calls (`\\bNAME(`), so `dial_tcp_host(` is not a call to
         `dial_tcp` and prose is already blanked out.

      2. UNAMBIGUOUS NAMES ONLY. Resolution here is by name, so a name this
         crate defines more than once cannot be resolved to one body and does
         not propagate: `new` (49 definitions) and `connect` (3) are exactly
         the collisions that blew the first walk up, while every name on the
         real chain -- `configure_tcp_stream`, `connect_tcp_bound`,
         `accept_tcp_on`, `dial_tcp` -- is defined exactly once.

    Rule 2 errs towards NOT propagating, so a producer that reaches the tuning
    only through an ambiguously-named helper is reported as an offender. That
    is the right direction for a gate to be wrong in: it asks a person to look,
    rather than reporting green on a chain it could not actually follow.
    """
    import collections

    defs = collections.Counter(f["fn"] for f in fns)
    unambiguous = {name for name, n in defs.items() if n == 1}

    calls = {}
    for f in fns:
        calls[id(f)] = {m.group(1) for m in CALL.finditer(f["body"])} & unambiguous

    reaching = {f["fn"] for f in fns if TUNING_CALL in f["body"]}
    changed = True
    while changed:
        changed = False
        for f in fns:
            if f["fn"] in reaching:
                continue
            if calls[id(f)] & reaching:
                reaching.add(f["fn"])
                changed = True
    return reaching


def producers(root: Path) -> tuple[list[dict], list[dict], list[dict], int]:
    """`(offenders, satisfied, exempted, files scanned)`."""
    fns, scanned = _functions(root)
    reaching = _reaching(fns)

    offenders: list[dict] = []
    satisfied: list[dict] = []
    exempted: list[dict] = []
    for f in fns:
        if TCP not in f["ret"]:
            continue
        # CONSUMER: handed a socket someone else made and tuned.
        if TCP in f["args"]:
            continue
        entry = {"file": f["file"], "fn": f["fn"], "line": f["line"]}
        if EXEMPT in f["scope"]:
            # Scoped to THIS item's own comment block + body, so a marker on a
            # sibling probe cannot quietly exempt the producer next to it.
            exempted.append(entry)
        elif f["fn"] in reaching:
            satisfied.append(entry)
        else:
            offenders.append(entry)
    return offenders, satisfied, exempted, scanned


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(REPO_ROOT))
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="drive the classifier over fixtures shaped like this tree",
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    root = Path(args.root)
    offenders, satisfied, exempted, scanned = producers(root)

    total = len(offenders) + len(satisfied) + len(exempted)
    print(
        "tcp-tuning-seam: %d producer(s) in %d file(s) -- %d reach the tuning "
        "SSOT, %d exempt, %d do not" % (total, scanned, len(satisfied), len(exempted), len(offenders))
    )
    for e in satisfied:
        print("  ok   %s:%d  %s" % (e["file"], e["line"], e["fn"]))
    for e in exempted:
        print("  skip %s:%d  %s  (%s)" % (e["file"], e["line"], e["fn"], EXEMPT))

    if total < MIN_PRODUCERS:
        print(
            "FAIL: only %d TCP-socket producer(s) found, expected at least %d.\n"
            "      This scan reports on what it DERIVED; a population that "
            "collapsed means the reader stopped matching the tree, not that the "
            "tree stopped making sockets." % (total, MIN_PRODUCERS)
        )
        return 1

    if offenders:
        print(
            "FAIL: %d function(s) produce a TcpStream for a wz link without "
            "reaching the per-link TCP tuning:" % len(offenders)
        )
        for e in offenders:
            print("    - %s:%d  %s" % (e["file"], e["line"], e["fn"]))
        print(
            "      Route the socket through `iface_bind::connect_tcp_bound` (dial)\n"
            "      or `link_pipeline::accept_tcp_on` (accept), which apply\n"
            "      `configure_tcp_stream`. zenoh sets TCP_NODELAY in every link\n"
            "      family's shared dial+accept constructor; a wz dial that skips\n"
            "      it runs with Nagle ON and no test can observe the difference.\n"
            "      If the socket genuinely backs no wz link, say so in the body\n"
            "      with the `%s` marker." % EXEMPT
        )
        return 1

    print("tcp-tuning-seam OK")
    return 0


def selftest() -> int:
    """Fixtures in the SHAPES this tree actually writes, not tidy ones.

    Each case pins one classifier decision. The two that matter most are the
    consumer (`accept_ws` takes a tuned socket and must NOT be asked to tune)
    and the wrapped-return producer (`dial_ws` returns `WebSocketStream<TcpStream>`
    and IS one) -- get either backwards and the gate either cannot fail or
    cannot pass.
    """
    import tempfile

    # Every fixture carries the tuning primitive, because a tree with NO root
    # makes every producer an offender and the interesting decisions would all
    # be masked by that one fact. `TUNE` is the shape this tree has: a plain fn
    # whose body calls the option setter.
    TUNE = (
        "fn configure_tcp_stream(stream: &TcpStream) {\n"
        "    let _ = stream.set_nodelay(true);\n}\n"
    )
    # The intermediate link -- the one the first draft could not see past.
    PRIM_OK = (
        "async fn connect_tcp_bound(addr: SocketAddr) -> io::Result<TcpStream> {\n"
        "    let s = TcpStream::connect(addr).await?;\n"
        "    configure_tcp_stream(&s);\n    Ok(s)\n}\n"
    )
    PRIM_BROKEN = (
        "async fn connect_tcp_bound(addr: SocketAddr) -> io::Result<TcpStream> {\n"
        "    TcpStream::connect(addr).await\n}\n"
    )

    cases = [
        # (name, source, expect_offender, expect_satisfied, expect_exempt)
        (
            "bare producer delegating to a tuning primitive",
            TUNE
            + PRIM_OK
            + "pub async fn dial_tcp(addr: SocketAddr) -> io::Result<TcpStream> {\n"
            "    connect_tcp_bound(addr).await\n}\n",
            # `connect_tcp_bound` is itself a producer, and a reaching one.
            0,
            2,
            0,
        ),
        (
            "THE R2355 SHAPE: every leaf names the primitive, the primitive "
            "does not tune",
            TUNE
            + PRIM_BROKEN
            + "pub async fn dial_ws(addr: SocketAddr) -> io::Result<WebSocketStream<TcpStream>> {\n"
            "    let tcp = connect_tcp_bound(addr).await?;\n"
            "    Ok(client_async(tcp).await?)\n}\n"
            + "pub async fn dial_tcp(addr: SocketAddr) -> io::Result<TcpStream> {\n"
            "    let s = connect_tcp_bound(addr).await?;\n"
            "    configure_tcp_stream(&s);\n    Ok(s)\n}\n",
            # dial_ws + the primitive are offenders; dial_tcp tunes directly.
            # A leaf-only rule would have reported all three satisfied.
            2,
            1,
            0,
        ),
        (
            "consumer handed a tuned socket is not a producer",
            TUNE
            + PRIM_OK
            + "pub async fn accept_ws(tcp: TcpStream) -> io::Result<WebSocketStream<TcpStream>> {\n"
            "    accept_async(tcp).await.map_err(io::Error::other)\n}\n",
            0,
            1,
            0,
        ),
        (
            "multi-line signature, the shape rustfmt produces",
            TUNE
            + PRIM_OK
            + "pub async fn dial_tls(\n"
            "    addr: SocketAddr,\n"
            "    config: Arc<ClientConfig>,\n"
            ") -> io::Result<TlsStream<TcpStream>> {\n"
            "    let tcp = connect_tcp_bound(addr).await?;\n"
            "    Ok(TlsStream::Client(tcp))\n}\n",
            0,
            2,
            0,
        ),
        (
            "delegation resolves transitively, not just one hop",
            TUNE
            + PRIM_OK
            + "async fn accept_tcp_on(l: &TcpListener) -> io::Result<TcpStream> {\n"
            "    let (s, _) = l.accept().await?;\n"
            "    configure_tcp_stream(&s);\n    Ok(s)\n}\n"
            "pub async fn accept_tcp(l: TcpListener) -> io::Result<TcpStream> {\n"
            "    accept_tcp_on(&l).await\n}\n",
            0,
            3,
            0,
        ),
        (
            "prose naming the primitive does not satisfy a body that skips it",
            TUNE
            + PRIM_OK
            + "/// Delegates to `connect_tcp_bound`, which applies `configure_tcp_stream`.\n"
            "pub async fn dial_rogue(addr: SocketAddr) -> io::Result<TcpStream> {\n"
            "    TcpStream::connect(addr).await\n}\n",
            1,
            1,
            0,
        ),
        (
            "a brace inside a string literal does not run the body walk off",
            TUNE
            + PRIM_OK
            + 'pub async fn dial_braced(addr: SocketAddr) -> io::Result<TcpStream> {\n'
            '    log::info!("dial {{");\n'
            "    connect_tcp_bound(addr).await\n}\n"
            "pub async fn dial_after(addr: SocketAddr) -> io::Result<TcpStream> {\n"
            "    TcpStream::connect(addr).await\n}\n",
            1,
            2,
            0,
        ),
        (
            "a producer inside #[cfg(test)] mod is not a link seam",
            TUNE
            + PRIM_OK
            + "#[cfg(test)]\nmod tests {\n"
            "    async fn probe(addr: SocketAddr) -> io::Result<TcpStream> {\n"
            "        TcpStream::connect(addr).await\n    }\n}\n",
            0,
            1,
            0,
        ),
        (
            "the marker exempts, and it lives in a comment",
            TUNE
            + PRIM_OK
            + "// TCP-TUNING-NOT-A-LINK: a bare probe socket, never a wz link.\n"
            "async fn probe(addr: SocketAddr) -> io::Result<TcpStream> {\n"
            "    TcpStream::connect(addr).await\n}\n",
            # `connect_tcp_bound` stays SATISFIED rather than being swept into
            # the exemption by a marker written about its neighbour.
            0,
            1,
            1,
        ),
        (
            "the marker does NOT reach the offender beside it",
            TUNE
            + PRIM_OK
            + "// TCP-TUNING-NOT-A-LINK: a bare probe socket, never a wz link.\n"
            "async fn probe(addr: SocketAddr) -> io::Result<TcpStream> {\n"
            "    TcpStream::connect(addr).await\n}\n"
            "pub async fn dial_rogue(addr: SocketAddr) -> io::Result<TcpStream> {\n"
            "    TcpStream::connect(addr).await\n}\n",
            # THE DISCRIMINATOR for the scoping fix. Read file-wide -- the shape
            # the first draft had -- this same fixture reports (0, 1, 2): the
            # probe's marker exempts `dial_rogue` too and the gate cannot fail on
            # a file that contains one marker. Scoped per item, the offender is
            # still named.
            1,
            1,
            1,
        ),
        (
            "deleting the tuning call empties the roots and offends everything",
            PRIM_BROKEN
            + "pub async fn dial_tcp(addr: SocketAddr) -> io::Result<TcpStream> {\n"
            "    connect_tcp_bound(addr).await\n}\n",
            2,
            0,
            0,
        ),
    ]

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = root / CRATE / "src"
        src.mkdir(parents=True)
        for i, (name, body, want_off, want_ok, want_ex) in enumerate(cases):
            for stale in src.glob("*.rs"):
                stale.unlink()
            (src / ("case%d.rs" % i)).write_text(body, encoding="utf-8")
            off, ok, ex, _ = producers(root)
            got = (len(off), len(ok), len(ex))
            want = (want_off, want_ok, want_ex)
            if got != want:
                print("  selftest FAIL  %s: got %s, want %s" % (name, got, want))
                failures += 1
            else:
                print("  selftest ok    %s" % name)

        # The floor is a real arm, not decoration: emptying the tree must FAIL.
        for stale in src.glob("*.rs"):
            stale.unlink()
        (src / "empty.rs").write_text("// nothing here\n", encoding="utf-8")
        off, ok, ex, _ = producers(root)
        if len(off) + len(ok) + len(ex) >= MIN_PRODUCERS:
            print("  selftest FAIL  an empty tree must not reach the floor")
            failures += 1
        else:
            print("  selftest ok    an empty tree is below the floor (would FAIL)")

    if failures:
        print("tcp-tuning-seam selftest: %d failure(s)" % failures)
        return 1
    print("tcp-tuning-seam selftest OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2973 (no register item) — WHICH HOSTS A SURFACE RUNS ON IS UPSTREAM'S
ANSWER, AND WZ HAS TO GIVE THE SAME ONE, BUILD AND RUN.

## Why the citation says no item while the file answers for two

The two gaps this gate was written to carry are open-debt items 851 and 852,
which live in the half of the register that is not the store, so there is no
`debt-` id to cite -- the standing `upstream_link_axis_gate.py` is in for item
593. Item 851 is BUILT (R2994: unixpipe is served on macOS, and `SERVE_GAPS` is
empty); item 852 is BUILT too (R2995: the serial link's logic is witnessed over
an in-memory stream on every host, and `EXEC_GAPS` is empty). Both tables stay,
and stay selftested, because a gap is how this gate is told about the next
host-restricted surface.

## What was wrong, measured at R2973

`platform-macos` and `platform-windows` claim wz runs on those hosts. The only
execution evidence was the `portability` job, and it ran ONE link: TCP. Nothing
said which host-restricted surfaces those hosts should carry, so nothing could
say what was missing, and five defects sat in that silence:

  * `transport-link-unixsock` compiled only on a Unix, yet every cfg site naming
    it named the feature alone. A Windows build that enabled it did not compile
    at all -- twelve errors against `x86_64-pc-windows-gnu` -- where upstream's
    crate declares its implementation under `target_family = "unix"` and simply
    serves nothing there.
  * `runtime-tokio-uring` did not compile off Linux either -- 54 errors, the
    `io-uring` crate itself, which sat in the host-independent dependency
    table. Upstream's `uring` puts its whole implementation under
    `target_os = "linux"` (`commons/zenoh-uring/src/lib.rs` @ `mod linux;`) and
    is inert elsewhere.
  * a vsock-only uring accessor in `stream_link.rs` named its feature and not
    the Linux host its one consumer lives on.
  * wz's unixpipe is `target_os = "linux"` while upstream's is `unix`: macOS is a
    host upstream runs that link on and wz does not (item 851).
  * the serial tests all open an `openpty` pair, which does not exist on
    Windows, so a Windows test build naming the feature did not compile, and
    upstream serves serial there (item 852 was the half that stayed open for a
    round: nothing could EXECUTE a serial link on a Windows runner, until R2995
    made the link's logic generic over its byte stream and ran it over an
    in-memory one).

The population is the thing that was missing, so the population is derived.

## Five arms

  1. UPSTREAM, from the pin. A LINK is served on a host when BOTH the registry's
     `pub use zenoh_link_<crate> as ..` in `io/zenoh-link/src/lib.rs` @
     `pub use zenoh_link_tcp as tcp;` and every
     `mod` the crate's own `src/lib.rs` declares are compiled there. The two are
     read together because each gates alone: unixsock is gated in the registry,
     unixpipe only inside its crate (`#[cfg(unix)] mod unix;`). A non-link
     FEATURE (`RUNTIME_FEATURES`) is served where every `mod` of the upstream
     crate it mirrors is compiled.
  2. WZ, from the cfg on the surface's `pub mod` in wz-runtime-tokio's
     `lib.rs`, with every feature on (the question is the HOST, not the
     feature). The link population is `pub enum LinkKind`, read by
     `upstream_link_axis_gate`, and `RUNTIME_LINKS` must cover it exactly. The
     two matrices must agree host by host, except where `SERVE_GAPS` names the
     debt -- and a gap row whose two sides have come to agree is a finding too,
     so a closed gap cannot linger as a stated one.
  3. SITES. In every workspace crate whose features REACH a host-restricted
     wz-runtime-tokio feature (cargo's own feature graph, through `dep/feat`
     forwards), naming such a feature must be INERT on a host that does not
     serve it -- upstream's rule. "Because of the feature" is measured, not
     guessed: each site's full predicate -- its file's context, every enclosing
     gated item, and itself -- is evaluated with every feature on, and again
     with that one feature off. On an unserved host the two must agree: a site
     that switches ON there compiles against a module that is not there (the
     twelve errors), one that switches OFF loses its fallback and leaves that
     host with neither arm.
  4. EVIDENCE. For macOS and Windows -- the two hosts no other lane runs -- each
     link wz serves names the integration-test targets that exercise it, and the
     target's own cfg must select at least one non-ignored test on that host
     under the leg's features. `--run <host>` builds the union feature set ONCE,
     then runs each target on its own deadline and requires every target to
     report a passing count of at least one; a target that stalls is killed
     with its tree and named by its last line, and the targets after it still
     report. `EXEC_GAPS` names what cannot run there, and a gap whose target
     now selects a test is stale. R3014: `PLANES` carries the surfaces that are
     not links (UDP multicast), each witnessed by an OPT-IN (`#[ignore]`) target
     that must select at least one opt-in test on the host and runs with
     `--ignored`, under the same one build, one deadline and one-pass rule.
  5. INTEROP. R3020. What a host owes the router interop is the part of it whose
     subject depends on the host, and the host-dependent surface of a transport is
     its links. So every link wz serves on a leg host has an opt-in test in
     `crates/wz-host-interop-tests` that dials a stock `zenohd` over it (`INTEROP`),
     or a row that says why not (`INTEROP_GAPS`, one reason: the pin's default
     `zenohd` omits the link, checked against the pin's own default feature list).
     Each test must exist, compile on the host, and be run by the Platform
     workflow's `interop` job. `INTEROP_PROMOTED` holds the two consecutive green
     hosted runs that turn a test from an observation into a gate, and a promoted
     test must be run by a step that is not `continue-on-error`; `--promoted HOST`
     prints the list that step runs, so the workflow holds no second copy.

The three graded hosts are the CI runners': Linux and Windows on x86_64, macOS
on aarch64 (`macos-latest`). Linux is the reference host: its links are graded
by the lanes that own each (C1al, C1ab, the E-layer interop), so no Linux leg is
declared here.

## What this does NOT see

A dependency API that exists only on some hosts (`SerialStream::pair` is
`#[cfg(unix)]` inside tokio-serial). No cfg in this tree names it, so arm 3
cannot; arm 4's `--run` on the real host is what catches it, which is why the
leg compiles every link it lists rather than only the ones it can execute.
Nor does it see a site inside a `macro_rules!` body: that is a template until
it expands.

## Arms by lane

`--selftest` needs nothing. `--check` grades arms 2-5 everywhere and arm 1
where a checkout of the pinned zenoh is reachable, and SAYS so when it is not;
`--require` turns that into a FAIL, which is how Layer Z runs it.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Sequence, TextIO

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import upstream_link_axis_gate as axis  # noqa: E402  the LinkKind population + pin root

ROOT = pathlib.Path(__file__).resolve().parents[2]

HOSTS = ("linux", "macos", "windows")
ALL_HOSTS = frozenset(HOSTS)
UNIX_HOSTS = frozenset({"linux", "macos"})
#: The architecture each graded host is, as the CI runners are.
HOST_ARCH = {"linux": "x86_64", "macos": "aarch64", "windows": "x86_64"}
#: The hosts this gate carries an execution leg for; see the module docstring.
LEG_HOSTS = ("macos", "windows")

RUNTIME = "wz-runtime-tokio"
RUNTIME_LIB = pathlib.Path("crates/wz-runtime-tokio/src/lib.rs")
RUNTIME_TESTS = pathlib.Path("crates/wz-runtime-tokio/tests")
#: Upstream's link registry, joined by part as the sibling gates join theirs: this
#: is a path to READ, not a claim about upstream, so it is not a citation.
REGISTRY = pathlib.Path("io") / "zenoh-link" / "src" / "lib.rs"

#: wz kind -> (its wz-runtime-tokio feature, the `pub mod` that implements it).
#: Knowledge, not population: the population is `pub enum LinkKind`, and this
#: must cover it exactly.
RUNTIME_LINKS: dict[str, tuple[str, str]] = {
    "Tcp": ("transport-link-tcp", "link_pipeline"),
    "Udp": ("transport-link-udp", "udp_pipeline"),
    "UdpReliable": ("transport-link-udp-reliable", "udp_reliable_pipeline"),
    "Tls": ("transport-link-tls", "tls_pipeline"),
    "Quic": ("transport-link-quic", "quic_pipeline"),
    "QuicDatagram": ("transport-link-quic-datagram", "quic_datagram_pipeline"),
    "Serial": ("transport-link-serial", "serial_pipeline"),
    "Unixpipe": ("transport-link-unixpipe", "unixpipe_pipeline"),
    "UnixsockStream": ("transport-link-unixsock", "unixsock_pipeline"),
    "Vsock": ("transport-link-vsock", "vsock_pipeline"),
    "Ws": ("transport-link-ws", "ws_pipeline"),
}

#: Host-restricted wz-runtime-tokio features that are not links -> (feature, its
#: `pub mod`, the upstream crate it mirrors). A DECLARED list, because "this wz
#: feature mirrors that upstream crate" is knowledge no manifest states; what
#: keeps it honest is arm 1, which reads the crate's own gates at the pin.
RUNTIME_FEATURES: dict[str, tuple[str, str, str]] = {
    "Uring": ("runtime-tokio-uring", "uring", "commons/zenoh-uring"),
}

#: (surface, host) where upstream serves it and wz does not -> (open-debt item,
#: why). Each row is a debt, never a design decision.
#:
#: Empty since item 851 was built (R2994): wz opened its FIFOs through tokio's
#: `pipe::OpenOptions::read_write`, which tokio compiles on Linux only, where
#: upstream opens them with std's `OpenOptions` (read + write + O_NONBLOCK) on
#: any Unix and drops only its advisory lock on macOS. wz now does the same, so
#: the gate derives unixpipe as served on macOS and a stale row here is a finding.
SERVE_GAPS: dict[tuple[str, str], tuple[int, str]] = {}

#: wz kind -> the wz-runtime-tokio integration-test targets that run it.
EVIDENCE: dict[str, tuple[str, ...]] = {
    "Tcp": ("accept_and_open_session", "connect_and_open_session"),
    "Udp": ("udp_seam_e2e",),
    "UdpReliable": ("udp_reliable_e2e",),
    "Tls": ("tls_e2e",),
    "Quic": ("quic_e2e",),
    "QuicDatagram": ("quic_datagram_e2e",),
    "Serial": ("serial_link_e2e",),
    "Unixpipe": ("unixpipe_e2e",),
    "UnixsockStream": ("unixsock_e2e",),
    "Vsock": ("vsock_e2e",),
    "Ws": ("ws_e2e",),
}

#: Surfaces that are not links, and the opt-in (`#[ignore]`) test targets that witness
#: them on a host -> (the hosts that owe it, the targets). The leg runs these with
#: `--ignored`, one build, one deadline, at least one pass.
#:
#: UDP multicast is one. Upstream serves it on every host (`zenoh-link-udp`), and wz's
#: fuller multicast suites are not evidence a host can be graded on: they run in
#: parallel on one machine-wide group port, and on a hosted Windows runner the same
#: scouting suite passed 6 of 6, then 4 of 6, then 5 of 6, a different test each
#: time, all of them OS interface selection. `multicast_host_roundtrip` is the narrow
#: deterministic witness of the host-specific part, wz's own two drivers on one host
#: over the interface that host lets a CI process send multicast out of (macOS: only
#: loopback; Windows: the default interface, never loopback; the test's header holds
#: the measurements). It passed on both hosts. Multicast over a REAL interface is not
#: provable on a hosted macOS runner at all, so this row does not claim it.
#:
#: Declared knowledge and not derived: no manifest says which surface a test target
#: witnesses, and the upstream arm reads link crates, not planes.
PLANES: dict[str, tuple[frozenset[str], tuple[str, ...]]] = {
    "UdpMulticast": (ALL_HOSTS, ("multicast_host_roundtrip",)),
}

#: (kind, host) that wz serves and BUILDS in the leg but no target can run
#: there -> (open-debt item, why).
#:
#: Empty since item 852 was built (R2995): every serial witness opened an
#: `openpty` pair (`SerialStream::pair`, `#[cfg(unix)]` in tokio-serial), which a
#: Windows runner does not have, so the leg compiled the serial link there and
#: executed none of it. The link's logic now runs over any `SerialByteStream`, and
#: `serial_link_e2e` instantiates it over an in-memory duplex on every host, so the
#: target selects tests on Windows and a stale row here is a finding.
EXEC_GAPS: dict[tuple[str, str], tuple[int, str]] = {}

#: The crate that holds the router interop a host owes, and the workflow whose
#: `interop` job runs it. Paths to READ, not claims about upstream.
HOST_INTEROP_TESTS = pathlib.Path("crates/wz-host-interop-tests/tests")
PLATFORM_WORKFLOW = pathlib.Path(".github/workflows/platform.yml")
#: The pin's manifest that names what `zenohd` is built with by default.
ZENOH_MANIFEST = pathlib.Path("zenoh") / "Cargo.toml"

#: wz link kind -> the opt-in test in the host-interop crate that dials a stock `zenohd`
#: over it. What a host owes the router interop is the part of it whose subject depends
#: on the host, and the host-dependent surface of a transport is its links, so this is
#: the INDEX of that part: every link wz serves on a host appears here or in
#: `INTEROP_GAPS`, and every opt-in test of the crate appears here.
INTEROP: dict[str, str] = {
    "Tcp": "wz_client_reaches_established_against_a_stock_zenohd_on_this_host",
    "Udp": "wz_client_reaches_established_against_a_stock_zenohd_over_udp_on_this_host",
    "UdpReliable": "wz_client_reaches_established_against_a_stock_zenohd_over_udp_reliable_on_this_host",
    "Tls": "wz_client_reaches_established_against_a_stock_zenohd_over_tls_on_this_host",
    "Quic": "wz_client_reaches_established_against_a_stock_zenohd_over_quic_on_this_host",
    "QuicDatagram": "wz_client_reaches_established_against_a_stock_zenohd_over_quic_datagram_on_this_host",
    "UnixsockStream": "wz_client_reaches_established_against_a_stock_zenohd_over_unixsock_on_this_host",
    "Ws": "wz_client_reaches_established_against_a_stock_zenohd_over_ws_on_this_host",
}

#: (kind, host) that wz serves and no interop test dials -> (reason, why). There is
#: ONE reason, because a gap that is a debt is an open-debt item and not a row here
#: (the two links that looked like debts, UdpReliable and QuicDatagram, were built
#: as rows instead): `router-omits` says the default `zenohd` does not serve the link,
#: so there is nothing to dial. It is a claim about the pin and the gate checks it
#: against the pin's own default feature list, so a router that gains the link turns
#: the row into a finding.
ROUTER_OMITS = "router-omits"
INTEROP_GAPS: dict[tuple[str, str], tuple[str, str]] = {
    ("Serial", "macos"): (ROUTER_OMITS, "`transport_serial` is not in zenoh's default features"),
    ("Serial", "windows"): (ROUTER_OMITS, "`transport_serial` is not in zenoh's default features"),
    ("Unixpipe", "macos"): (ROUTER_OMITS, "`transport_unixpipe` is not in zenoh's default features"),
}

#: (kind, host) -> the two hosted runs, consecutive, in which that host's test passed.
#: The owner's rule: an observation becomes a gate after two consecutive green hosted
#: runs on its host, counted in runs and not in days. A promoted test is run by a step
#: of the `interop` job that is NOT `continue-on-error`, so a red there fails the run
#: and reaches the previous-run gate; the step reads its list from `--promoted HOST`.
#: Evidence recorded by hand from the runs' own logs, and not derivable offline.
INTEROP_PROMOTED: dict[tuple[str, str], tuple[int, int]] = {
    ("Tcp", "macos"): (37102598609, 37105204094),
    ("Tcp", "windows"): (37102598609, 37105204094),
    # The four links first observed in 37105204094 and green again in 37109725746, on
    # both hosts. The second run is also the first in which the promoted-tests step ran,
    # and it passed there (one promoted test per host), so the step itself is proven.
    ("Ws", "macos"): (37105204094, 37109725746),
    ("Ws", "windows"): (37105204094, 37109725746),
    ("Udp", "macos"): (37105204094, 37109725746),
    ("Udp", "windows"): (37105204094, 37109725746),
    ("Tls", "macos"): (37105204094, 37109725746),
    ("Tls", "windows"): (37105204094, 37109725746),
    ("Quic", "macos"): (37105204094, 37109725746),
    ("Quic", "windows"): (37105204094, 37109725746),
    # The rows first observed in 37109725746 and green again in 37111623432: reliable UDP
    # and QUIC datagram on both hosts, a Unix socket on macOS (Windows does not serve it).
    # With these every row of INTEROP is promoted on every host that owes it. The second
    # run is also the first in which the pin was READ from the builder script and the
    # promoted-tests step ran five tests, and both passed on both hosts.
    ("UdpReliable", "macos"): (37109725746, 37111623432),
    ("UdpReliable", "windows"): (37109725746, 37111623432),
    ("QuicDatagram", "macos"): (37109725746, 37111623432),
    ("QuicDatagram", "windows"): (37109725746, 37111623432),
    ("UnixsockStream", "macos"): (37109725746, 37111623432),
}

#: wz link kind -> the opt-in test that carries a publication across that link. The
#: handshake rows above prove the two ends agree on the link's framing; they say nothing
#: about a Put that has to cross it, which is where a host's socket behaviour (a datagram
#: boundary, a stream that coalesces, a close that races the last write) would show. The
#: test starts a wz subscriber and a wz publisher on the SAME stock `zenohd` and requires
#: the value to arrive, with the publisher's side dialed over the link under test. It is
#: a second row per link and not a replacement: a red here with the handshake green says
#: the link connects and does not carry. Every link `INTEROP` dials owes one.
INTEROP_DATA: dict[str, str] = {
    "Tcp": "wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_tcp_on_this_host",
    "Udp": "wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_udp_on_this_host",
    "UdpReliable": "wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_udp_reliable_on_this_host",
    "Tls": "wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_tls_on_this_host",
    "Quic": "wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_quic_on_this_host",
    "QuicDatagram": "wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_quic_datagram_on_this_host",
    "UnixsockStream": "wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_unixsock_on_this_host",
    "Ws": "wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_ws_on_this_host",
}

#: The prefix every data test's name carries, which is also what the workflow's data
#: loop builds its test names from; the gate looks for it in the workflow the way it
#: looks for the TCP handshake test's name.
DATA_STEM = "wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_"

#: (kind, host) -> the two consecutive green hosted runs of that host's DATA test, by the
#: same rule as `INTEROP_PROMOTED` and read from the same place (the job log). Empty on
#: the day the rows land: they are observations first.
INTEROP_DATA_PROMOTED: dict[tuple[str, str], tuple[int, int]] = {}


# ─── Rust text: comments and literals masked, offsets kept ──────────────────


def _ident_char(c: str) -> bool:
    return c.isalnum() or c == "_"


_RAW_OPEN = re.compile(r'(?:br|rb|r)(#*)"')


def mask(text: str, literals: bool = True) -> str:
    """`text` with every comment and every literal's body blanked to spaces.

    Newlines survive and nothing moves, so an offset found in the mask indexes
    the original. A `#[cfg(` inside a doc comment or a string is therefore not a
    site. `literals=False` blanks the comments only, which is the text a cfg
    predicate is PARSED from: its strings are its feature names, and a comment
    between two of its arms (config.rs carries one) is not part of it.
    """
    out = list(text)
    n = len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    def blank_literal(a: int, b: int) -> None:
        if literals:
            blank(a, b)

    i = 0
    while i < n:
        c = text[i]
        if c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if c == "/" and text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue
        if c in "rb" and (i == 0 or not _ident_char(text[i - 1])):
            m = _RAW_OPEN.match(text, i)
            if m:
                close = '"' + m.group(1)
                j = text.find(close, m.end())
                j = n if j < 0 else j + len(close)
                blank_literal(m.end(), j - len(close))
                i = j
                continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank_literal(i + 1, j)
            i = j + 1
            continue
        if c == "'":
            if i + 1 < n and text[i + 1] == "\\":
                j = text.find("'", i + 3)
                j = n if j < 0 else j
                blank_literal(i + 1, j)
                i = j + 1
                continue
            if i + 2 < n and text[i + 2] == "'":
                blank_literal(i + 1, i + 2)
                i += 3
                continue
        i += 1
    return "".join(out)


# ─── cfg predicates ──────────────────────────────────────────────────────────


class UnknownCfg(ValueError):
    """A cfg atom this evaluator has no host answer for. Fail closed."""


_TOKEN = re.compile(
    r'\s*(?:(?P<id>[A-Za-z_][A-Za-z0-9_]*)|(?P<str>"(?:[^"\\]|\\.)*")|(?P<p>[(),=]))',
    re.S,
)


def _tokens(text: str, pos: int) -> Iterable[tuple[str, str, int]]:
    while True:
        m = _TOKEN.match(text, pos)
        if not m:
            raise ValueError(f"unreadable cfg predicate at offset {pos}")
        kind = m.lastgroup
        yield kind, m.group(kind), m.end()
        pos = m.end()


def parse_cfg(text: str, pos: int) -> tuple[tuple, int]:
    """Parse the predicate that starts at `pos` (just after `cfg(`).

    Returns (tree, offset just past the closing `)`). Trees are tuples:
    `("all"|"any"|"not", (args..))`, `("id", name)`, `("kv", key, value)`.
    """
    toks = _tokens(text, pos)
    look: list[tuple[str, str, int]] = []

    def peek() -> tuple[str, str, int]:
        if not look:
            look.append(next(toks))
        return look[0]

    def take() -> tuple[str, str, int]:
        t = peek()
        look.pop(0)
        return t

    def pred() -> tuple:
        kind, val, _ = take()
        if kind != "id":
            raise ValueError(f"cfg predicate expected a name, got {val!r}")
        if val in ("all", "any", "not") and peek()[1] == "(":
            take()
            args: list[tuple] = []
            while peek()[1] != ")":
                args.append(pred())
                if peek()[1] == ",":
                    take()
                elif peek()[1] != ")":
                    raise ValueError(f"cfg `{val}(..)` expected `,` or `)`")
            take()
            if val == "not" and len(args) != 1:
                raise ValueError("cfg `not(..)` takes exactly one predicate")
            return (val, tuple(args))
        if peek()[1] == "=":
            take()
            skind, sval, _ = take()
            if skind != "str":
                raise ValueError(f"cfg `{val} = ..` expected a string")
            return ("kv", val, sval[1:-1])
        return ("id", val)

    tree = pred()
    kind, val, end = take()
    if val != ")":
        raise ValueError(f"cfg predicate did not close, got {val!r}")
    return tree, end


#: Bare cfg names that are the same on every graded host. `test` is ON because
#: `cargo test` is the broadest compile of a crate; the doc-only names are off.
BARE = {"test": True, "debug_assertions": True, "doc": False, "docsrs": False, "miri": False}


def holds(tree: tuple, host: str, feat: Callable[[str], bool]) -> bool:
    tag = tree[0]
    if tag == "all":
        return all(holds(a, host, feat) for a in tree[1])
    if tag == "any":
        return any(holds(a, host, feat) for a in tree[1])
    if tag == "not":
        return not holds(tree[1][0], host, feat)
    if tag == "id":
        name = tree[1]
        if name == "unix":
            return host in UNIX_HOSTS
        if name == "windows":
            return host == "windows"
        if name in BARE:
            return BARE[name]
        raise UnknownCfg(name)
    key, value = tree[1], tree[2]
    if key == "feature":
        return feat(value)
    if key == "target_os":
        # A target_os that is none of the graded hosts (android, none, ...) is
        # simply false on all three -- not unknown.
        return host == value
    if key == "target_family":
        if value == "unix":
            return host in UNIX_HOSTS
        if value == "windows":
            return host == "windows"
        return False
    if key == "target_arch":
        return HOST_ARCH[host] == value
    if key == "target_pointer_width":
        return value == "64"
    raise UnknownCfg(f'{key} = "{value}"')


def hosts_of(preds: Iterable[tuple], feat: Callable[[str], bool]) -> frozenset[str]:
    preds = tuple(preds)
    return frozenset(h for h in HOSTS if all(holds(p, h, feat) for p in preds))


def features_named(tree: tuple) -> set[str]:
    if tree[0] in ("all", "any", "not"):
        out: set[str] = set()
        for a in tree[1]:
            out |= features_named(a)
        return out
    if tree[0] == "kv" and tree[1] == "feature":
        return {tree[2]}
    return set()


def render(tree: tuple) -> str:
    if tree[0] in ("all", "any", "not"):
        return f"{tree[0]}({', '.join(render(a) for a in tree[1])})"
    if tree[0] == "id":
        return tree[1]
    return f'{tree[1]} = "{tree[2]}"'


def everything(_feature: str) -> bool:
    return True


# ─── gated spans inside one file ─────────────────────────────────────────────

_ATTR = re.compile(r"#(!?)\[\s*cfg\s*\(")
_KEYWORD_ITEM = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:fn|mod|impl|struct|enum|trait|const|static|type|use|"
    r"extern|unsafe|async|union|macro_rules|let)\b"
)
_MOD_DECL = re.compile(r"\bmod\s+(?:r#)?([A-Za-z_]\w*)\s*;")
_MOD_INLINE = re.compile(r"\bmod\s+(?:r#)?([A-Za-z_]\w*)\s*\{")
_PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')
_MACRO_RULES = re.compile(r"\bmacro_rules!\s*[A-Za-z_]\w*\s*([({\[])")


def _close_bracket(masked: str, i: int) -> int:
    """Offset just past the bracket that closes the one at `i`."""
    depth = 0
    for j in range(i, len(masked)):
        c = masked[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return j + 1
    return len(masked)


def _skip_attrs(masked: str, i: int) -> int:
    n = len(masked)
    while True:
        while i < n and masked[i].isspace():
            i += 1
        if masked.startswith("#[", i):
            i = _close_bracket(masked, i + 1)
            continue
        return i


def item_span(masked: str, i: int) -> tuple[int, int]:
    """The item an outer attribute ending at `i` gates.

    A keyword item (fn, mod, impl, ...) ends at its `;` or at the `}` closing
    its first top-level block. Anything else -- a match arm, a field, a variant,
    a statement -- ALSO ends at the first top-level `,`. Where that is too short
    (a struct pattern's braces) the span under-covers, which can only make a
    nested site LOUDER, never quieter: a context this gate fails to see is a
    context it does not credit.
    """
    start = _skip_attrs(masked, i)
    keyword = bool(_KEYWORD_ITEM.match(masked, start))
    depth = 0
    for j in range(start, len(masked)):
        c = masked[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return start, j
            depth -= 1
            if depth == 0 and c == "}":
                return start, j + 1
        elif depth == 0 and (c == ";" or (c == "," and not keyword)):
            return start, j + 1
    return start, len(masked)


def _block_rest(masked: str, i: int) -> tuple[int, int]:
    """From `i` to the end of the block enclosing it (an inner attribute's reach)."""
    depth = 0
    for j in range(i, len(masked)):
        c = masked[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i, j
            depth -= 1
    return i, len(masked)


@dataclass(frozen=True)
class Site:
    line: int
    tree: tuple
    span: tuple[int, int]
    #: `#![cfg(..)]`: it gates the rest of its block (the whole file at top level).
    inner: bool


def cfg_sites(text: str, masked: str) -> list[Site]:
    """Every cfg attribute that gates compiled code.

    One inside a `macro_rules!` body is a TEMPLATE (`feature = $feat` is not a
    predicate until the macro expands), so it is not a site.
    """
    code = mask(text, literals=False)
    templates = [
        (m.end() - 1, _close_bracket(masked, m.end() - 1)) for m in _MACRO_RULES.finditer(masked)
    ]
    sites: list[Site] = []
    for m in _ATTR.finditer(masked):
        if any(a < m.start() < b for a, b in templates):
            continue
        tree, end = parse_cfg(code, m.end())
        close = masked.find("]", end)
        if close < 0:
            raise ValueError("cfg attribute never closes")
        span = _block_rest(masked, close + 1) if m.group(1) else item_span(masked, close + 1)
        sites.append(Site(text.count("\n", 0, m.start()) + 1, tree, span, bool(m.group(1))))
    return sites


def context_at(sites: list[Site], pos: int) -> list[tuple]:
    return [s.tree for s in sites if s.span[0] <= pos < s.span[1]]


# ─── the module tree of a crate target ──────────────────────────────────────


@dataclass
class SourceFile:
    path: pathlib.Path
    text: str
    masked: str
    sites: list[Site]


def source(text: str, path: pathlib.Path) -> SourceFile:
    masked = mask(text)
    try:
        sites = cfg_sites(text, masked)
    except ValueError as e:
        raise ValueError(f"{path}: {e}") from e
    return SourceFile(path, text, masked, sites)


def load(path: pathlib.Path, cache: dict[pathlib.Path, SourceFile]) -> SourceFile:
    if path not in cache:
        cache[path] = source(path.read_text(encoding="utf-8"), path)
    return cache[path]


def _attr_run_start(masked: str, pos: int) -> int:
    """Walk back from `pos` over whitespace and complete `#[..]` groups."""
    i = pos
    while True:
        j = i
        while j > 0 and masked[j - 1].isspace():
            j -= 1
        if j > 0 and masked[j - 1] == "]":
            depth, k = 0, j - 1
            while k >= 0:
                if masked[k] == "]":
                    depth += 1
                elif masked[k] == "[":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            if k > 0 and masked[k - 1] == "#":
                i = k - 1
                continue
        return i


def walk(
    root: pathlib.Path,
    read: Callable[[pathlib.Path], SourceFile],
    exists: Callable[[pathlib.Path], bool],
) -> tuple[list[tuple[SourceFile, tuple[tuple, ...]]], list[str]]:
    """Every file one crate target compiles, with the cfg context it is reached under."""
    out: list[tuple[SourceFile, tuple[tuple, ...]]] = []
    findings: list[str] = []
    seen: set[tuple[pathlib.Path, str]] = set()
    stack: list[tuple[pathlib.Path, tuple[tuple, ...], bool]] = [(root, (), True)]
    while stack:
        path, ctx, is_root = stack.pop()
        key = (path, repr(ctx))
        if key in seen:
            continue
        seen.add(key)
        src = read(path)
        out.append((src, ctx))
        inline = [
            (m.group(1), m.end() - 1, _close_bracket(src.masked, m.end() - 1))
            for m in _MOD_INLINE.finditer(src.masked)
        ]
        mod_root = is_root or path.name in ("lib.rs", "main.rs", "mod.rs")
        base = path.parent if mod_root else path.parent / path.stem
        for m in _MOD_DECL.finditer(src.masked):
            name = m.group(1)
            run = src.text[_attr_run_start(src.masked, m.start()) : m.start()]
            explicit = _PATH_ATTR.search(run)
            nested = [n for n, a, b in sorted(inline, key=lambda t: t[1]) if a < m.start() < b]
            here = base.joinpath(*nested) if nested else base
            if explicit:
                cands = [path.parent / explicit.group(1)]
            else:
                cands = [here / f"{name}.rs", here / name / "mod.rs"]
            child = next((c for c in cands if exists(c)), None)
            if child is None:
                findings.append(
                    f"{path}: `mod {name};` resolves to none of "
                    f"{[str(c) for c in cands]}, so its sites are ungraded"
                )
                continue
            stack.append((child, ctx + tuple(context_at(src.sites, m.start())), False))
    return out, findings


# ─── cargo's feature graph ───────────────────────────────────────────────────


@dataclass
class Package:
    name: str
    manifest: pathlib.Path
    features: dict[str, list[str]]
    deps: dict[str, str]
    roots: list[pathlib.Path] = field(default_factory=list)


def workspace_packages(crates: pathlib.Path) -> dict[str, Package]:
    proc = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=str(crates),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"`cargo metadata` failed: {proc.stderr.strip() or proc.returncode}")
    meta = json.loads(proc.stdout)
    out: dict[str, Package] = {}
    for p in meta["packages"]:
        deps = {(d.get("rename") or d["name"]): d["name"] for d in p.get("dependencies", [])}
        roots = [pathlib.Path(t["src_path"]) for t in p.get("targets", [])]
        out[p["name"]] = Package(
            p["name"], pathlib.Path(p["manifest_path"]), dict(p.get("features") or {}), deps, roots
        )
    return out


def reach(pkgs: dict[str, Package], pkg: str, feat: str) -> set[tuple[str, str]]:
    """Every (package, feature) that enabling `pkg/feat` turns on."""
    seen: set[tuple[str, str]] = set()
    stack = [(pkg, feat)]
    while stack:
        p, f = stack.pop()
        if (p, f) in seen or p not in pkgs:
            continue
        seen.add((p, f))
        for entry in pkgs[p].features.get(f, []):
            if entry.startswith("dep:"):
                continue
            if "/" in entry:
                dep, sub = entry.split("/", 1)
                target = pkgs[p].deps.get(dep.rstrip("?"))
                if target in pkgs:
                    stack.append((target, sub))
            elif entry in pkgs[p].features:
                stack.append((p, entry))
    return seen


def own_closure(pkgs: dict[str, Package], pkg: str, feats: Iterable[str]) -> frozenset[str]:
    out: set[str] = set()
    for f in feats:
        out |= {g for p, g in reach(pkgs, pkg, f) if p == pkg}
    return frozenset(out)


def bounded_features(
    pkgs: dict[str, Package], restricted: dict[str, frozenset[str]]
) -> dict[str, dict[str, frozenset[str]]]:
    """package -> {feature: the hosts every restricted runtime feature it turns on is served on}.

    `restricted` maps a wz-runtime-tokio feature to the hosts it is served on,
    for the features served on fewer than all of them.
    """
    out: dict[str, dict[str, frozenset[str]]] = {}
    for name, pkg in pkgs.items():
        for f in pkg.features:
            hit = {g for p, g in reach(pkgs, name, f) if p == RUNTIME and g in restricted}
            if not hit:
                continue
            bound = ALL_HOSTS
            for g in hit:
                bound &= restricted[g]
            out.setdefault(name, {})[f] = bound
    return out


# ─── arm 1 / arm 2: who serves what where ───────────────────────────────────


def _link_crate(kind: str) -> str:
    return "zenoh_link_" + axis.KINDS[kind][1].replace("-", "_")


def crate_hosts(crate_lib: str) -> tuple[list[tuple], frozenset[str]]:
    """Every `mod` a crate's lib.rs declares, and the hosts ALL of them compile on."""
    src = source(crate_lib, pathlib.Path("lib.rs"))
    preds: list[tuple] = []
    for m in _MOD_DECL.finditer(src.masked):
        preds += context_at(src.sites, m.start())
    return preds, hosts_of(preds, everything)


def upstream_link_served(
    registry: str, crate_lib: str, crate: str
) -> tuple[frozenset[str] | None, str]:
    """(hosts, how) for one upstream link crate, or (None, why) when unreadable."""
    reg = source(registry, REGISTRY)
    use = re.search(rf"\bpub use {re.escape(crate)} as \w+\s*;", reg.masked)
    if use is None:
        return None, f"no `pub use {crate} as ..` in the registry"
    preds = context_at(reg.sites, use.start())
    mods, _ = crate_hosts(crate_lib)
    preds += mods
    return hosts_of(preds, everything), " & ".join(render(p) for p in preds) or "ungated"


def wz_served(lib: str, module: str) -> tuple[frozenset[str] | None, str]:
    """The hosts wz compiles `pub mod <module>` on, every feature on."""
    src = source(lib, RUNTIME_LIB)
    decl = re.search(rf"\bpub mod {re.escape(module)}\s*;", src.masked)
    if decl is None:
        return None, f"no `pub mod {module};` in {RUNTIME_LIB}"
    preds = context_at(src.sites, decl.start())
    return hosts_of(preds, everything), " & ".join(render(p) for p in preds)


def _fmt(hosts: Iterable[str]) -> str:
    return "{" + ", ".join(h for h in HOSTS if h in hosts) + "}"


def matrix_findings(
    names: list[str],
    upstream: dict[str, frozenset[str]],
    wz: dict[str, frozenset[str]],
    gaps: dict[tuple[str, str], tuple[int, str]],
) -> list[str]:
    out: list[str] = []
    for name in names:
        up, mine = upstream[name], wz[name]
        for h in HOSTS:
            gap = gaps.get((name, h))
            if h in up and h not in mine and gap is None:
                out.append(
                    f"upstream serves {name} on {h} and wz does not, and no SERVE_GAPS "
                    f"row names the debt -- build it, or register the gap"
                )
            elif h in mine and h not in up:
                out.append(
                    f"wz serves {name} on {h}, where upstream's is inert -- wz must "
                    f"compile to what upstream does there, not to something of its own"
                )
            elif gap is not None and not (h in up and h not in mine):
                out.append(
                    f"SERVE_GAPS names ({name}, {h}) as item {gap[0]}, but wz and "
                    f"upstream now agree there -- the gap is closed: drop the row "
                    f"and close the item"
                )
    for name, _h in gaps:
        if name not in names:
            out.append(f"SERVE_GAPS names {name}, which is not a graded surface")
    return out


# ─── arm 3: every cfg site a restricted feature switches ────────────────────


def site_findings(
    files: list[tuple[SourceFile, tuple[tuple, ...]]],
    bounded: dict[str, frozenset[str]],
    rel: Callable[[pathlib.Path], str],
) -> tuple[list[str], int]:
    """(findings, sites graded) for one package's reached files.

    The rule is upstream's: on a host that does not serve the surface, naming
    the feature is INERT -- the build is the one it would be without it. So a
    site may not switch ON because of the feature there (it would compile
    against a module that is not there: the R2973 twelve errors), and it may not
    switch OFF either (the `not(feature)` fallback would vanish, leaving that
    host with neither arm).
    """
    out: list[str] = []
    graded = 0
    reported: set[tuple[str, int, str]] = set()
    for src, ctx in files:
        for site in src.sites:
            names = features_named(site.tree) & bounded.keys()
            if not names:
                continue
            full = ctx + tuple(context_at(src.sites, site.span[0])) + (site.tree,)
            for f in sorted(names):
                graded += 1
                on = hosts_of(full, everything)
                off = hosts_of(full, lambda g, f=f: g != f)
                key = (rel(src.path), site.line, f)
                if key in reported:
                    continue
                gained = (on - off) - bounded[f]
                lost = (off - on) - bounded[f]
                if gained:
                    reported.add(key)
                    out.append(
                        f"{key[0]}:{site.line}: `cfg({render(site.tree)})` switches ON "
                        f"with `{f}` on {_fmt(gained)}, where what it turns on is not "
                        f"served (served {_fmt(bounded[f])}) -- a build naming the "
                        f"feature there compiles this site against a module that is "
                        f"not there. Gate it on the host too."
                    )
                elif lost:
                    reported.add(key)
                    out.append(
                        f"{key[0]}:{site.line}: `cfg({render(site.tree)})` switches OFF "
                        f"with `{f}` on {_fmt(lost)}, where it is not served (served "
                        f"{_fmt(bounded[f])}) -- there the feature must be inert, and "
                        f"this fallback vanishes instead. Negate the feature AND its "
                        f"host together."
                    )
    return out, graded


# ─── arm 4: the execution legs ───────────────────────────────────────────────

_TEST_ATTR = re.compile(r"#\[\s*(?:tokio::)?test\b")
_FN = re.compile(r"\b(?:async\s+)?fn\s+([A-Za-z_]\w*)")


def head_features(src: SourceFile) -> tuple[frozenset[str] | None, str]:
    """The features a test target's inner `#![cfg]` needs, when it can be read.

    Only a conjunction of `feature = ..` atoms (plus host atoms) can be read as
    "enable these": an `any` has no single answer, and saying which branch the
    leg means is then the author's job, so it is refused rather than guessed.
    """
    trees = [s.tree for s in src.sites if s.inner and s.span[1] == len(src.masked)]
    feats: set[str] = set()

    def conj(tree: tuple) -> bool:
        if tree[0] == "all":
            return all(conj(a) for a in tree[1])
        if tree[0] == "kv" and tree[1] == "feature":
            feats.add(tree[2])
            return True
        return tree[0] == "id" or (tree[0] == "kv" and tree[1] != "feature")

    for t in trees:
        if not conj(t):
            return None, render(t)
    return frozenset(feats), " & ".join(render(t) for t in trees) or "ungated"


def runnable_tests(
    files: list[tuple[SourceFile, tuple[tuple, ...]]],
    host: str,
    enabled: frozenset[str],
    ignored: bool = False,
) -> list[str]:
    """The tests a target selects on `host` under `enabled`.

    `ignored=False` counts what a plain `cargo test` runs. `ignored=True` counts the
    opt-in `#[ignore]` tests instead, which is what a plane target's leg runs with
    `--ignored`: the two sets never overlap, so a target cannot satisfy the one
    question with the other's tests.
    """
    out: list[str] = []
    for src, ctx in files:
        for m in _TEST_ATTR.finditer(src.masked):
            run_end = _skip_attrs(src.masked, m.start())
            run = src.masked[_attr_run_start(src.masked, m.start()) : run_end]
            if bool(re.search(r"#\[\s*ignore\b", run)) != ignored:
                continue
            fn = _FN.match(src.masked, run_end)
            if fn is None:
                continue
            preds = ctx + tuple(context_at(src.sites, run_end))
            if hosts_of(preds, lambda f: f in enabled) & {host}:
                out.append(fn.group(1))
    return out


@dataclass
class Leg:
    host: str
    targets: list[str]
    features: frozenset[str]
    deferred: list[str]
    #: Targets (a subset of `targets`) that run their `#[ignore]` tests, with `--ignored`.
    ignored: frozenset[str] = frozenset()


def leg_findings(
    host: str,
    served: dict[str, frozenset[str]],
    target_files: Callable[[str], list[tuple[SourceFile, tuple[tuple, ...]]] | None],
    closure: Callable[[Iterable[str]], frozenset[str]],
    evidence: dict[str, tuple[str, ...]],
    exec_gaps: dict[tuple[str, str], tuple[int, str]],
    planes: Mapping[str, tuple[frozenset[str], tuple[str, ...]]] | None = None,
) -> tuple[Leg, list[str]]:
    out: list[str] = []
    targets: list[str] = []
    wanted: set[str] = set()
    deferred: list[str] = []
    rows: list[tuple[str, str]] = []
    for kind in sorted(served):
        if host not in served[kind]:
            if (kind, host) in exec_gaps:
                out.append(
                    f"EXEC_GAPS names ({kind}, {host}), but wz does not serve {kind} "
                    f"there at all -- that is a SERVE question, not an execution one"
                )
            continue
        names = evidence.get(kind)
        if not names:
            out.append(f"wz serves {kind} on {host} and EVIDENCE names no target that runs it")
            continue
        for name in names:
            rows.append((kind, name))
    heads: dict[str, frozenset[str]] = {}
    for kind, name in rows:
        files = target_files(name)
        if files is None:
            out.append(f"EVIDENCE names `{name}` for {kind}, and there is no tests/{name}.rs")
            continue
        feats, how = head_features(files[0][0])
        if feats is None:
            out.append(
                f"tests/{name}.rs is gated `{how}`, which names no single feature set -- "
                f"the leg cannot say what to enable for it"
            )
            continue
        heads[name] = feats
    # A PLANE is a surface that is not a link (multicast): its target's tests are
    # `#[ignore]`d opt-ins, so the leg runs them with `--ignored`. Its features join
    # the union build like a link's, before the closure is taken.
    plane_rows: list[tuple[str, str]] = []
    plane_heads: dict[str, frozenset[str]] = {}
    for plane, (plane_hosts, names) in sorted((planes or {}).items()):
        if host not in plane_hosts:
            continue
        for name in names:
            plane_rows.append((plane, name))
            files = target_files(name)
            if files is None:
                out.append(f"PLANES names `{name}` for {plane}, and there is no tests/{name}.rs")
                continue
            feats, how = head_features(files[0][0])
            if feats is None:
                out.append(
                    f"tests/{name}.rs is gated `{how}`, which names no single feature set -- "
                    f"the leg cannot say what to enable for it"
                )
                continue
            plane_heads[name] = feats
    # An exec-gap link is still BUILT: the union build is the only place its
    # module compiles on this host at all.
    for kind, name in rows:
        if name in heads:
            wanted |= heads[name]
    for feats in plane_heads.values():
        wanted |= feats
    enabled = closure(wanted)
    for kind, name in rows:
        if name not in heads:
            continue
        files = target_files(name)
        assert files is not None
        tests = runnable_tests(files, host, enabled)
        gap = exec_gaps.get((kind, host))
        if gap is not None:
            if tests:
                out.append(
                    f"EXEC_GAPS names ({kind}, {host}) as item {gap[0]}, but "
                    f"tests/{name}.rs now selects {len(tests)} test(s) there -- put "
                    f"it in the leg and close the item"
                )
            else:
                deferred.append(f"{kind} ({name}): item {gap[0]} -- {gap[1]}")
            continue
        if not tests:
            out.append(
                f"tests/{name}.rs is {kind}'s evidence on {host} and selects NO "
                f"runnable test there under the leg's features -- the leg would "
                f"pass it on an empty selection"
            )
            continue
        if name not in targets:
            targets.append(name)
    ignored_targets: set[str] = set()
    for plane, name in plane_rows:
        if name not in plane_heads:
            continue
        files = target_files(name)
        assert files is not None
        tests = runnable_tests(files, host, enabled, ignored=True)
        if not tests:
            out.append(
                f"tests/{name}.rs is {plane}'s evidence on {host} and selects NO opt-in "
                f"(`#[ignore]`) test there under the leg's features -- the leg would "
                f"pass it on an empty selection"
            )
            continue
        if name in targets:
            out.append(f"`{name}` is both a link's evidence and {plane}'s; a target runs one way")
            continue
        targets.append(name)
        ignored_targets.add(name)
    for kind, _h in exec_gaps:
        if kind not in served:
            out.append(f"EXEC_GAPS names {kind}, which `LinkKind` does not have")
    return Leg(host, targets, frozenset(wanted), deferred, frozenset(ignored_targets)), out


# ─── arm 5: the router interop a host owes ──────────────────────────────────

_OVER = re.compile(r"_over_(\w+)_on_this_host$")
_LINKS_ASSIGN = re.compile(r'^\s*links="([^"]*)"', re.M)


def scheme_of(test: str) -> str | None:
    """The link a host-interop test's name says it dials, or None for the TCP one.

    The name is the contract between the test file and the workflow: the workflow
    runs `..._over_<link>_on_this_host` once per token of its `links=` list, and a
    link name's hyphen is the test name's underscore.
    """
    m = _OVER.search(test)
    return m.group(1).replace("_", "-") if m else None


def workflow_runs(test: str, workflow: str) -> bool:
    """Whether the interop job runs `test`: the TCP one by name, the others by link."""
    scheme = scheme_of(test)
    if scheme is None:
        return test in workflow
    tokens: set[str] = set()
    for m in _LINKS_ASSIGN.finditer(workflow):
        tokens |= set(m.group(1).split())
    return scheme in tokens


def workflow_runs_data(test: str, workflow: str) -> bool:
    """Whether the interop job runs the DATA test `test`.

    The workflow builds every data test's name from `DATA_STEM` and one link token, and
    its loop covers TCP as well as the `links=` list, so TCP is run when the stem is
    there and any other link only when it is also a token of a `links=` list.
    """
    scheme = scheme_of(test)
    if scheme is None or DATA_STEM not in workflow:
        return False
    tokens: set[str] = {"tcp"}
    for m in _LINKS_ASSIGN.finditer(workflow):
        tokens |= set(m.group(1).split())
    return scheme in tokens


def gate_step_findings(workflow: str, promoted: Mapping[tuple[str, str], tuple[int, int]]) -> list[str]:
    """Whether the promoted tests are run by a step that can fail the job.

    "Promoted to a gate" means the difference between a step that cannot fail the run
    and one that can, so the table alone says nothing: a promoted row beside a workflow
    whose only interop step is `continue-on-error` is an observation wearing a gate's
    name. The step is the one that asks for the list (`--promoted`); it is found in the
    workflow's text, since this gate runs on hosts where no YAML reader is installed.
    """
    if not promoted:
        return []
    # Comment lines are dropped first: the comment that explains a step sits ABOVE its
    # `- name:` line and so belongs, by position, to the step before it.
    code = "\n".join(l for l in workflow.splitlines() if not l.lstrip().startswith("#"))
    blocks = re.split(r"(?m)^      - name: ", code)
    asking = [b for b in blocks[1:] if "--promoted" in b]
    if not asking:
        return [
            f"INTEROP_PROMOTED names {len(promoted)} test(s) and no step of {PLATFORM_WORKFLOW} "
            f"asks `--promoted` for the list -- nothing gates them"
        ]
    out = []
    for block in asking:
        if re.search(r"(?m)^\s*continue-on-error:\s*true\b", block):
            out.append(
                f"the step of {PLATFORM_WORKFLOW} that runs the promoted tests is "
                f"`continue-on-error`, so a red there cannot fail the job: that is an "
                f"observation, not a gate"
            )
        if "cargo test" not in block or "--ignored" not in block:
            out.append(
                f"the promoted-tests step of {PLATFORM_WORKFLOW} does not run `cargo test ... "
                f"--ignored`, which is how an opt-in test runs"
            )
    return out


def router_default_kinds(root: pathlib.Path) -> frozenset[str] | None:
    """The wz link kinds the pin's DEFAULT `zenohd` serves, read from the pin.

    `zenohd` is built with `zenoh/default`, so what it can listen on is the
    `transport_*` entries of that feature list. A kind maps to its upstream crate's
    suffix (`axis.KINDS`), and the feature spells a hyphen either way, so both sides
    are compared with hyphens folded to underscores. None when the manifest cannot be
    read, which is not the same as "serves nothing".
    """
    path = root / ZENOH_MANIFEST
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    section = re.search(r"^\[features\]\s*$(.*?)(?=^\[)", text, re.S | re.M)
    if section is None:
        return None
    default = re.search(r"^default\s*=\s*\[(.*?)\]", section.group(1), re.S | re.M)
    if default is None:
        return None
    served = {t.replace("-", "_") for t in re.findall(r'"([^"]+)"', default.group(1))}
    return frozenset(
        kind
        for kind, row in axis.KINDS.items()
        if "transport_" + row[1].replace("-", "_") in served
    )


def promotion_findings(
    label: str,
    table: Mapping[str, str],
    promoted: Mapping[tuple[str, str], tuple[int, int]],
    served: Mapping[str, frozenset[str]],
) -> list[str]:
    """What is wrong with the promoted rows of one interop table (`label` names it)."""
    out: list[str] = []
    for (kind, host), runs in promoted.items():
        if kind not in table or host not in served.get(kind, frozenset()):
            out.append(f"{label} names ({kind}, {host}), which has no interop test there")
        if len(set(runs)) != 2 or not all(isinstance(r, int) and r > 0 for r in runs):
            out.append(f"{label} ({kind}, {host}) needs two DISTINCT hosted run ids, got {runs!r}")
        elif runs[0] > runs[1]:
            out.append(f"{label} ({kind}, {host}) lists its runs newest first; oldest first")
    return out


def interop_findings(
    served: Mapping[str, frozenset[str]],
    tests_on_host: Mapping[str, frozenset[str]],
    all_tests: frozenset[str],
    workflow: str,
    router_default: frozenset[str] | None,
    interop: Mapping[str, str],
    gaps: Mapping[tuple[str, str], tuple[str, str]],
    promoted: Mapping[tuple[str, str], tuple[int, int]],
    data: Mapping[str, str],
    data_promoted: Mapping[tuple[str, str], tuple[int, int]],
    hosts: Sequence[str] = LEG_HOSTS,
) -> list[str]:
    out: list[str] = []
    for kind in sorted(served):
        for host in hosts:
            if host not in served[kind]:
                continue
            test, gap = interop.get(kind), gaps.get((kind, host))
            if test is not None and gap is None:
                # A link whose handshake is dialed also owes the data plane over it.
                dtest = data.get(kind)
                if dtest is None:
                    out.append(
                        f"INTEROP dials a stock router over {kind} and INTEROP_DATA has no row "
                        f"for it: a link that connects also owes a publication carried across it"
                    )
                else:
                    if dtest not in tests_on_host.get(host, frozenset()):
                        out.append(
                            f"INTEROP_DATA names `{dtest}` for {kind}, and the host-interop crate "
                            f"has no opt-in test of that name that compiles on {host}"
                        )
                    if not workflow_runs_data(dtest, workflow):
                        out.append(
                            f"`{dtest}` is {kind}'s data test and the `interop` job of "
                            f"{PLATFORM_WORKFLOW} never runs it -- a test nothing runs reports "
                            f"nothing"
                        )
            if test is not None and gap is not None:
                out.append(
                    f"INTEROP_GAPS names ({kind}, {host}), but INTEROP now dials it with "
                    f"`{test}` -- the gap is closed: drop the row"
                )
            elif test is not None:
                if test not in tests_on_host.get(host, frozenset()):
                    out.append(
                        f"INTEROP names `{test}` for {kind}, and the host-interop crate "
                        f"has no opt-in test of that name that compiles on {host}"
                    )
                if not workflow_runs(test, workflow):
                    out.append(
                        f"`{test}` is {kind}'s interop test and the `interop` job of "
                        f"{PLATFORM_WORKFLOW} never runs it -- a test nothing runs reports "
                        f"nothing"
                    )
                if router_default is not None and kind not in router_default:
                    out.append(
                        f"INTEROP dials a stock router over {kind}, and the pin's default "
                        f"`zenohd` does not serve it -- the test cannot pass"
                    )
            elif gap is not None:
                reason, _why = gap
                if reason != ROUTER_OMITS:
                    out.append(f"INTEROP_GAPS gives ({kind}, {host}) the reason `{reason}`, which is none this gate knows")
                elif router_default is not None and kind in router_default:
                    out.append(
                        f"INTEROP_GAPS says the default `zenohd` omits {kind}, and the pin's "
                        f"default feature list carries it -- build the row"
                    )
            else:
                out.append(
                    f"wz serves {kind} on {host} and nothing dials a stock router over it: "
                    f"add an INTEROP row, or an INTEROP_GAPS row that says why not"
                )
    for (kind, host) in gaps:
        if kind not in served or host not in served[kind]:
            out.append(f"INTEROP_GAPS names ({kind}, {host}), which wz does not serve")
    for kind, test in interop.items():
        if kind not in served:
            out.append(f"INTEROP names {kind}, which is not a link wz serves")
        elif test not in all_tests:
            out.append(f"INTEROP names `{test}` for {kind}, and no host-interop test has that name")
    for kind, test in data.items():
        if kind not in interop:
            out.append(f"INTEROP_DATA names {kind}, which INTEROP does not dial -- a data row needs its handshake row")
        elif test not in all_tests:
            out.append(f"INTEROP_DATA names `{test}` for {kind}, and no host-interop test has that name")
    named = set(interop.values()) | set(data.values())
    for test in sorted(all_tests - named):
        out.append(
            f"the host-interop crate has the opt-in test `{test}` and INTEROP names it for no "
            f"link -- the tables are the index of what a host owes, so add the row or drop the test"
        )
    out += promotion_findings("INTEROP_PROMOTED", interop, promoted, served)
    out += promotion_findings("INTEROP_DATA_PROMOTED", data, data_promoted, served)
    # A cause that is not about one host (a test the workflow never runs) is found once per
    # host the link is served on; it is one finding.
    return list(dict.fromkeys(out))


def host_interop_tests(
    cache: dict[pathlib.Path, SourceFile],
) -> tuple[dict[str, frozenset[str]], frozenset[str], dict[str, str], list[str]]:
    """The opt-in tests of the host-interop crate: those that compile on each leg host,
    every one on any host, the test target each lives in, and what could not be read.

    Derived from the crate's own `tests/` directory, so a new file is graded the day it
    exists and not the day someone remembers to list it.
    """
    findings: list[str] = []
    on_host: dict[str, set[str]] = {h: set() for h in LEG_HOSTS}
    every: set[str] = set()
    target_of: dict[str, str] = {}
    directory = ROOT / HOST_INTEROP_TESTS
    if not directory.is_dir():
        return (
            {h: frozenset() for h in LEG_HOSTS},
            frozenset(),
            {},
            [f"there is no {HOST_INTEROP_TESTS}: the router interop a host owes has no crate"],
        )
    for path in sorted(directory.glob("*.rs")):
        try:
            files, missing = walk(path, lambda p: load(p, cache), pathlib.Path.is_file)
        except (UnknownCfg, ValueError) as e:
            findings.append(f"{rel(path)}: {e}")
            continue
        findings += [m for m in missing if m not in findings]
        for host in HOSTS:
            for name in runnable_tests(files, host, frozenset(), ignored=True):
                every.add(name)
                target_of[name] = path.stem
                if host in on_host:
                    on_host[host].add(name)
    return {h: frozenset(v) for h, v in on_host.items()}, frozenset(every), target_of, findings


def interop_summary(
    served: Mapping[str, frozenset[str]],
    interop: Mapping[str, str],
    gaps: Mapping[tuple[str, str], tuple[str, str]],
    promoted: Mapping[tuple[str, str], tuple[int, int]],
    hosts: Sequence[str] = LEG_HOSTS,
    data: Mapping[str, str] | None = None,
    data_promoted: Mapping[tuple[str, str], tuple[int, int]] | None = None,
) -> list[str]:
    """Where each host stands on the router interop it owes, in numbers and by name.

    Whether a host's subset is complete is a question the owner asked in advance of
    closing anything, so the answer is printed by the gate that holds the tables, not
    counted by hand from them: owed rows, how many are gated, which are still only
    observed, and which links no stock router can be dialed over (with the reason).
    """
    out: list[str] = []
    for host in hosts:
        owed = sorted(k for k in served if host in served[k] and k in interop)
        gated = [k for k in owed if (k, host) in promoted]
        observed = [k for k in owed if (k, host) not in promoted]
        omitted = sorted(k for (k, h) in gaps if h == host)
        line = f"interop {host}: {len(owed)} owed, {len(gated)} gated"
        line += f", {len(observed)} observed ({', '.join(observed)})" if observed else ", none observed only"
        if omitted:
            line += f"; router omits {', '.join(omitted)}"
        if data is not None:
            owed_data = [k for k in owed if k in data]
            gated_data = [k for k in owed_data if (k, host) in (data_promoted or {})]
            line += f"; data plane: {len(owed_data)} owed, {len(gated_data)} gated"
            if len(gated_data) < len(owed_data):
                line += f", {len(owed_data) - len(gated_data)} observed"
        out.append(line)
    return out


def promoted_tests(
    host: str,
    interop: Mapping[str, str],
    promoted: Mapping[tuple[str, str], tuple[int, int]],
    target_of: Mapping[str, str],
    data: Mapping[str, str],
    data_promoted: Mapping[tuple[str, str], tuple[int, int]],
) -> list[tuple[str, str]]:
    """The (target, test) pairs the interop job must GATE on `host`: the handshake rows
    in kind order, then the data rows in kind order."""
    rows: list[tuple[str, str]] = []
    for table, earned in ((interop, promoted), (data, data_promoted)):
        for kind in sorted(table):
            if (kind, host) in earned and table[kind] in target_of:
                rows.append((target_of[table[kind]], table[kind]))
    return rows


_RUNNING = re.compile(r"^\s*Running (?:tests[\\/])?([A-Za-z0-9_-]+)\.rs\b")
_RESULT = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed")


def cargo_env(ambient: Mapping[str, str]) -> dict[str, str]:
    """The environment the leg's cargo runs under: the ambient one, colour off.

    `_RUNNING` is anchored at the start of the line, and the hosted workflow
    sets `CARGO_TERM_COLOR: always` for every job. Cargo then wraps the word in
    SGR escapes (`ESC[1m ESC[92m     Running ESC[0m tests\\ws_e2e.rs`), so no
    line matches, every target reads as "reported no result -- it did not run",
    and a Windows leg whose eight targets all PASSED fails. The leg parses
    cargo's human output, so the leg decides how cargo prints it rather than
    inheriting whatever the job happens to export -- the same fix, in the same
    place, as `scripts/install-zenoh-c-arm.sh` made for its own parser.
    """
    env = dict(ambient)
    env["CARGO_TERM_COLOR"] = "never"
    return env


def relay_lines(stream: Iterable[str], out: TextIO) -> list[str]:
    """Relay the leg's output as it arrives, one flush per line; return it stripped.

    A pipe is block-buffered. Unflushed, a stalled target shows nothing, and a
    job cancelled at its timeout loses what was buffered: the first hosted
    macOS leg sat in this step for the whole job and its log held no cargo
    line at all, only the runner's cleanup naming the process it killed.
    """
    lines: list[str] = []
    for line in stream:
        out.write(line)
        out.flush()
        lines.append(line.rstrip("\r\n"))
    return lines


def spawn_leg(cmd: list[str], cwd: str, ambient: Mapping[str, str]) -> subprocess.Popen[str]:
    """Start the leg's command with stdout and stderr merged, colour pinned off.

    On a Unix host it leads a process group of its own, so `kill_tree` can end
    cargo AND the test binary cargo started. Killing cargo alone leaves the binary
    holding the pipe open, and the relay would wait on it for the rest of the job.
    """
    group = {} if os.name == "nt" else {"start_new_session": True}
    return subprocess.Popen(
        cmd,
        cwd=cwd,
        env=cargo_env(ambient),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        **group,
    )


def kill_tree(proc: subprocess.Popen[str]) -> None:
    """End the process and everything it started."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False
        )
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


#: How long `sample` watches one process of a stalled tree. Five seconds is enough for a
#: thread blocked in a call to show the same frame at every tick; the selftest shortens
#: it, because the stalled tree it builds does not need a real observation window.
STALL_SAMPLE_S = 5


#: The process listing the stall diagnostics read. `pid` and `pgid` come first because
#: `group_pids` and `group_rows` read the first two columns; `-ww` keeps BSD `ps` from
#: cutting a command line at the window width.
PS_LISTING = ["ps", "-ax", "-ww", "-o", "pid,pgid,ppid,stat,command"]


def group_pids(ps_output: str, pgid: int) -> list[int]:
    """The pids of process group `pgid`, from `PS_LISTING` output.

    The leg leads a group of its own (`spawn_leg`), so the group is cargo and the
    test binary it started. Pure so the selftest can drive it without a ps.
    """
    pids: list[int] = []
    for line in ps_output.splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit() and int(parts[1]) == pgid:
            pids.append(int(parts[0]))
    return pids


def group_rows(ps_output: str, pgid: int) -> list[str]:
    """The listing's header and the rows of process group `pgid`, nothing else.

    The first stall log printed the whole machine's table, 500 lines of system
    daemons around the two processes that mattered.
    """
    lines = ps_output.splitlines()
    rows = [lines[0]] if lines and lines[0].split()[:1] == ["PID"] else []
    keep = set(group_pids(ps_output, pgid))
    for line in lines:
        parts = line.split(None, 1)
        if parts and parts[0].isdigit() and int(parts[0]) in keep:
            rows.append(line)
    return rows


def stall_diagnostic_commands(host: str, pids: Sequence[int]) -> list[list[str]]:
    """What to run, BEFORE the tree is killed, to learn where a stalled target stands.

    A stalled target left only its last output line, and that line names a phase,
    not a call: on macOS a pair-based serial test stood past its 240 s deadline
    with every wz-level bound unreached, so the stall is a call that never returns
    to the runtime, or a readiness that never arrives. Which of the two is
    visible in a stack sample, and only before the process is gone.

    macOS: `sample` (a stack of every thread) and `lsof` (the open descriptors, a
    pty pair among them) for each process. Windows: the process and socket
    tables, since no stack tool is installed on a hosted image. Elsewhere none:
    the leg's process rows are printed first by `capture_stall` on every unix
    host, and a host with less than a stack says so in the log instead of
    implying one.
    """
    if host == "windows":
        return [["tasklist", "/V"], ["netstat", "-ano"]]
    if host != "macos":
        return []
    cmds: list[list[str]] = []
    for pid in pids:
        cmds.append(["sample", str(pid), str(STALL_SAMPLE_S), "-file", f"/tmp/wz-stall-{pid}.txt"])
        cmds.append(["lsof", "-p", str(pid)])
    return cmds


def capture_stall(proc: subprocess.Popen[str], out: TextIO) -> None:
    """Print where a stalled target stands, then return so the caller can kill it."""
    host = _this_host()
    out.write(f"\n  platform-surface-matrix: STALL DIAGNOSTICS ({host}) -- the target is about to be killed\n")
    out.flush()
    pids: list[int] = []
    if os.name != "nt":
        try:
            listing = subprocess.run(
                PS_LISTING, capture_output=True, text=True, timeout=20, check=False
            ).stdout
            pids = group_pids(listing, proc.pid)
            out.write("  the leg's process group:\n")
            for row in group_rows(listing, proc.pid):
                out.write(f"    {row}\n")
        except (OSError, subprocess.SubprocessError) as e:
            out.write(f"  (could not list the process group: {e})\n")
    cmds = stall_diagnostic_commands(host, pids)
    if not cmds:
        out.write(f"  (no stack diagnostic is defined for {host}; the rows above are all there is)\n")
    for cmd in cmds:
        out.write(f"  $ {' '.join(cmd)}\n")
        out.flush()
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            text = (res.stdout or "") + (res.stderr or "")
        except (OSError, subprocess.SubprocessError) as e:
            text = f"(failed: {e})\n"
        out.write(text if text.endswith("\n") or not text else text + "\n")
        if cmd[0] == "sample":
            path = cmd[-1]
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    out.write(f.read())
            except OSError as e:
                out.write(f"(no sample file: {e})\n")
        out.flush()
    out.write("  platform-surface-matrix: END STALL DIAGNOSTICS\n")
    out.flush()


def run_bounded(
    cmd: list[str],
    cwd: str,
    ambient: Mapping[str, str],
    deadline_s: float | None,
    out: TextIO,
) -> tuple[list[str], int, bool]:
    """Run `cmd`, relaying its output, and end its whole tree at the deadline.

    Returns (lines, return code, whether the deadline ended it). `None` is no
    deadline, for a build whose length is the job's concern, not this leg's.

    A leg that is one process makes one stalled test erase what every later target
    would have said: the first hosted macOS leg printed nothing for the whole job,
    and a stalled `serial_pty_e2e` stood between it and the targets after it. Each
    target runs on its own clock instead, so a stall is named and the rest report.
    """
    proc = spawn_leg(cmd, cwd, ambient)
    fired = threading.Event()

    def expire() -> None:
        fired.set()
        # Look BEFORE the kill: a killed tree has no stack to sample.
        try:
            capture_stall(proc, out)
        except Exception as e:  # a diagnostic must never keep the kill from happening
            out.write(f"  (stall diagnostics failed: {e})\n")
        kill_tree(proc)

    timer = threading.Timer(deadline_s, expire) if deadline_s is not None else None
    if timer is not None:
        timer.daemon = True
        timer.start()
    try:
        assert proc.stdout is not None
        lines = relay_lines(proc.stdout, out)
        rc = proc.wait()
    finally:
        if timer is not None:
            timer.cancel()
    return lines, rc, fired.is_set()


def attribute_results(lines: Iterable[str]) -> dict[str, tuple[str, int]]:
    """target -> (verdict, passed), from cargo test's own output."""
    out: dict[str, tuple[str, int]] = {}
    current: str | None = None
    for line in lines:
        m = _RUNNING.match(line)
        if m:
            current = m.group(1)
            continue
        r = _RESULT.match(line)
        if r and current is not None:
            out[current] = (r.group(1), int(r.group(2)))
            current = None
    return out


def result_findings(leg: Leg, results: dict[str, tuple[str, int]], rc: int) -> list[str]:
    out: list[str] = []
    for t in leg.targets:
        got = results.get(t)
        if got is None:
            out.append(f"`{t}` reported no result -- it did not run")
        elif got[0] != "ok":
            out.append(f"`{t}` FAILED")
        elif got[1] < 1:
            out.append(f"`{t}` passed ZERO tests -- an empty selection is not evidence")
    if rc != 0 and not out:
        out.append(f"cargo exited {rc} with every target reporting green -- read the log")
    return out


#: How long ONE target may run, its build excluded. The Windows leg's whole step
#: (build and eight targets) took under three minutes, and the macOS step is
#: bounded at twenty, so a target that has not finished in four is stuck.
TARGET_DEADLINE_S = 240


def _leg_cargo(leg: Leg, *extra: str) -> list[str]:
    cmd = ["cargo", "test", *extra, "-p", RUNTIME]
    if leg.features:
        cmd += ["--features", ",".join(sorted(leg.features))]
    return cmd


def leg_build_command(leg: Leg) -> list[str]:
    """Build every target of the leg once, so no target's clock includes the build."""
    cmd = _leg_cargo(leg, "--no-run")
    for t in leg.targets:
        cmd += ["--test", t]
    return cmd


def leg_target_command(leg: Leg, target: str) -> list[str]:
    """Run one target, with the same features the build used.

    `--nocapture` because libtest prints a failing test's message only when its
    whole binary finishes. A binary that never does keeps the reason in a buffer, and
    the first hosted macOS run showed seven failed tests and no message for any.

    A plane target's tests are opt-in (`#[ignore]`): it runs with `--ignored`, and
    only it does, so a link target's `#[ignore]`d tests (real-time waits, a spawned
    foreign binary) stay out of the leg.
    """
    tail = ["--nocapture"] + (["--ignored"] if target in leg.ignored else [])
    return _leg_cargo(leg) + ["--test", target, "--", *tail]


# ─── the real tree ───────────────────────────────────────────────────────────


@dataclass
class Tree:
    kinds: list[str]
    #: surface -> the wz-runtime-tokio feature that names it
    feature_of: dict[str, str]
    served: dict[str, frozenset[str]]
    pkgs: dict[str, Package]
    cache: dict[pathlib.Path, SourceFile]
    findings: list[str]

    @property
    def names(self) -> list[str]:
        return self.kinds + list(RUNTIME_FEATURES)


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_tree() -> Tree:
    findings: list[str] = []
    link_text = (ROOT / axis.WZ_LINK).read_text(encoding="utf-8")
    kinds = axis.wz_kinds(link_text)
    findings += axis.population_findings(kinds, axis.KINDS)
    unmapped = [k for k in kinds if k not in RUNTIME_LINKS]
    if unmapped:
        findings.append(f"`LinkKind` has {unmapped}, which RUNTIME_LINKS does not map")
    stale = [k for k in RUNTIME_LINKS if k not in kinds]
    if stale:
        findings.append(f"RUNTIME_LINKS maps {stale}, which `LinkKind` does not have")
    pkgs = workspace_packages(ROOT / "crates")
    if RUNTIME not in pkgs:
        raise RuntimeError(f"`{RUNTIME}` is not a workspace member")
    lib = (ROOT / RUNTIME_LIB).read_text(encoding="utf-8")
    feature_of: dict[str, str] = {}
    modules: dict[str, str] = {}
    for kind in kinds:
        if kind in RUNTIME_LINKS:
            feature_of[kind], modules[kind] = RUNTIME_LINKS[kind]
    for name, (feat, module, _crate) in RUNTIME_FEATURES.items():
        feature_of[name], modules[name] = feat, module
    served: dict[str, frozenset[str]] = {}
    for name, feat in feature_of.items():
        if feat not in pkgs[RUNTIME].features:
            findings.append(f"{name}'s feature `{feat}` is not a {RUNTIME} feature")
            continue
        hosts, how = wz_served(lib, modules[name])
        if hosts is None:
            findings.append(f"{name}: {how}")
            continue
        if not hosts:
            findings.append(f"{name}'s `pub mod {modules[name]}` is served on NO host ({how})")
        served[name] = hosts
    return Tree(kinds, feature_of, served, pkgs, {}, findings)


def upstream_matrix(
    root: pathlib.Path, tree: Tree
) -> tuple[dict[str, frozenset[str]], list[str]]:
    findings: list[str] = []
    upstream: dict[str, frozenset[str]] = {}
    registry = (root / REGISTRY).read_text(encoding="utf-8")
    for name in tree.names:
        if name in RUNTIME_LINKS:
            crate = _link_crate(name)
            lib = root / "io" / "zenoh-links" / crate.replace("zenoh_link_", "zenoh-link-") / "src" / "lib.rs"
        else:
            lib = root / RUNTIME_FEATURES[name][2] / "src" / "lib.rs"
        if not lib.is_file():
            findings.append(f"{name}: upstream has no {lib.relative_to(root)}")
            continue
        text = lib.read_text(encoding="utf-8")
        try:
            if name in RUNTIME_LINKS:
                hosts, how = upstream_link_served(registry, text, crate)
            else:
                preds, hosts = crate_hosts(text)
                how = " & ".join(render(p) for p in preds) or "ungated"
                if not preds:
                    hosts = None
                    how = f"{lib.relative_to(root)} declares no gated `mod`, so it says nothing about hosts"
        except UnknownCfg as e:
            findings.append(f"{name}: upstream gates it on `{e}`, which this gate cannot place")
            continue
        if hosts is None:
            findings.append(f"{name}: {how}")
            continue
        upstream[name] = hosts
    return upstream, findings


def check(require: bool, quiet: bool = False) -> tuple[Tree | None, dict[str, Leg], int]:
    try:
        tree = read_tree()
    except (RuntimeError, OSError, ValueError, UnknownCfg) as e:
        print(f"platform-surface-matrix: FAIL -- cannot read the tree: {e}")
        return None, {}, 1
    findings = list(tree.findings)

    # arm 1 + 2
    root = axis.upstream_root()
    upstream: dict[str, frozenset[str]] = {}
    if root is None:
        if require:
            findings.append(
                "the UPSTREAM arm needs a checkout of the pinned zenoh and found none, "
                "and `--require` was given -- a skip must not report green"
            )
        elif not quiet:
            print(
                "  platform-surface-matrix: the UPSTREAM arm (which hosts upstream "
                "serves each surface on) is SKIPPED -- no checkout of the pinned zenoh "
                "here. The wz arms graded only; do not read this as 'wz matches upstream'."
            )
    else:
        upstream, got = upstream_matrix(root, tree)
        findings += got
        if len(upstream) == len(tree.names) and len(tree.served) == len(tree.names):
            findings += matrix_findings(tree.names, upstream, tree.served, SERVE_GAPS)

    # arm 3
    restricted = {
        tree.feature_of[n]: h for n, h in tree.served.items() if h != ALL_HOSTS
    }
    bounded = bounded_features(tree.pkgs, restricted)
    graded = 0
    reached: set[pathlib.Path] = set()
    for name in sorted(bounded):
        for target_root in tree.pkgs[name].roots:
            if not target_root.is_file():
                continue
            try:
                files, missing = walk(
                    target_root, lambda p: load(p, tree.cache), pathlib.Path.is_file
                )
                got, n = site_findings(files, bounded[name], rel)
            except (UnknownCfg, ValueError) as e:
                findings.append(f"{rel(target_root)}: {e}")
                continue
            findings += [m for m in missing if m not in findings]
            findings += [g for g in got if g not in findings]
            graded += n
            reached |= {src.path for src, _ctx in files}

    # arm 4
    def closure(feats: Iterable[str]) -> frozenset[str]:
        return own_closure(tree.pkgs, RUNTIME, list(feats) + ["default"])

    def target_files(name: str) -> list[tuple[SourceFile, tuple[tuple, ...]]] | None:
        path = ROOT / RUNTIME_TESTS / f"{name}.rs"
        if not path.is_file():
            return None
        files, missing = walk(path, lambda p: load(p, tree.cache), pathlib.Path.is_file)
        findings.extend(m for m in missing if m not in findings)
        return files

    links = {k: h for k, h in tree.served.items() if k in RUNTIME_LINKS}
    legs: dict[str, Leg] = {}
    for host in LEG_HOSTS:
        try:
            leg, got = leg_findings(host, links, target_files, closure, EVIDENCE, EXEC_GAPS, PLANES)
        except (UnknownCfg, ValueError) as e:
            findings.append(f"the {host} leg: {e}")
            continue
        findings += got
        legs[host] = leg

    # arm 5
    on_host, every, _target_of, got = host_interop_tests(tree.cache)
    findings += got
    try:
        workflow = (ROOT / PLATFORM_WORKFLOW).read_text(encoding="utf-8")
    except OSError as e:
        findings.append(f"cannot read {PLATFORM_WORKFLOW}: {e}")
        workflow = ""
    router_default = router_default_kinds(root) if root is not None else None
    findings += interop_findings(
        links, on_host, every, workflow, router_default, INTEROP, INTEROP_GAPS, INTEROP_PROMOTED,
        INTEROP_DATA, INTEROP_DATA_PROMOTED,
    )
    # The gating step runs both tables' promoted rows from one list, so either table
    # being non-empty is what requires it.
    findings += gate_step_findings(
        workflow, {**INTEROP_PROMOTED, **{(f"{k}/data", h): r for (k, h), r in INTEROP_DATA_PROMOTED.items()}}
    )

    if findings:
        print(f"platform-surface-matrix: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return tree, legs, 1
    if not quiet:
        against = f"graded against {root}" if root is not None else "upstream arm SKIPPED"
        print(
            f"  platform-surface-matrix: {len(tree.names)} surface(s) x {len(HOSTS)} "
            f"hosts, {against}; {graded} cfg site(s) naming a host-restricted feature, "
            f"over {len(reached)} reached file(s) in {len(bounded)} crate(s), inert "
            f"where unserved"
        )
        for name in tree.names:
            up = _fmt(upstream[name]) if name in upstream else "?"
            print(f"    {name:15s} upstream {up:24s} wz {_fmt(tree.served[name])}")
        for (name, h), (item, _why) in sorted(SERVE_GAPS.items()):
            print(f"    SERVE GAP {name} on {h}: open-debt item {item}")
        for host, leg in legs.items():
            print(f"    leg {host}: {len(leg.targets)} target(s): {', '.join(leg.targets)}")
            for d in leg.deferred:
                print(f"    leg {host} DOES NOT EXECUTE {d}")
        for line in interop_summary(
            links, INTEROP, INTEROP_GAPS, INTEROP_PROMOTED, data=INTEROP_DATA, data_promoted=INTEROP_DATA_PROMOTED
        ):
            print(f"    {line}")
    return tree, legs, 0


def _this_host() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform in ("win32", "cygwin", "msys"):
        return "windows"
    return sys.platform


def select_targets(leg: Leg, only: Sequence[str]) -> tuple[Leg | None, str]:
    """The leg narrowed to `only`, or why it cannot be.

    A narrowed leg is for DIAGNOSIS: isolating one stalling target so its stack
    sample is not drowned by its neighbours, and so a retry costs one target and
    not the leg. It never stands for the leg, and `run` says so in its verdict.
    A name the leg does not run is refused: a typo that silently selected nothing
    would pass a run that executed nothing.
    """
    unknown = [t for t in only if t not in leg.targets]
    if unknown:
        return None, (
            f"the {leg.host} leg does not run {', '.join(unknown)}; it runs {', '.join(leg.targets)}"
        )
    kept = [t for t in leg.targets if t in only]
    if not kept:
        return None, "--only named no target"
    return Leg(leg.host, kept, leg.features, leg.deferred, leg.ignored & set(kept)), ""


def run(host: str, only: Sequence[str] = ()) -> int:
    if host not in LEG_HOSTS:
        print(f"platform-surface-matrix: no leg is declared for `{host}` (legs: {LEG_HOSTS})")
        return 2
    if _this_host() != host:
        print(
            f"platform-surface-matrix: the {host} leg must run ON {host}; this is "
            f"{_this_host()}. A leg run elsewhere proves nothing about the host."
        )
        return 2
    # The leg relays cargo's own output, and this tree's test messages carry
    # non-ASCII (an em dash is enough). A Windows runner's stdout is a pipe in
    # the ANSI code page, where writing one raises rather than printing, and it
    # would take the leg down after the tests had passed.
    sys.stdout.reconfigure(errors="replace")
    _tree, legs, rc = check(require=False)
    if rc != 0:
        return rc
    leg = legs[host]
    full_targets = len(leg.targets)
    if only:
        narrowed, why = select_targets(leg, only)
        if narrowed is None:
            print(f"platform-surface-matrix: {why}")
            return 2
        leg = narrowed
    cwd = str(ROOT / "crates")
    build = leg_build_command(leg)
    print(f"  platform-surface-matrix: {host} leg: {' '.join(build)}", flush=True)
    _lines, build_rc, _hung = run_bounded(build, cwd, os.environ, None, sys.stdout)
    if build_rc != 0:
        print(f"platform-surface-matrix: {host} leg FAIL -- the leg did not build (cargo exited {build_rc})")
        return 1
    got: list[str] = []
    for target in leg.targets:
        cmd = leg_target_command(leg, target)
        print(f"  platform-surface-matrix: {host} leg: {' '.join(cmd)}", flush=True)
        lines, target_rc, hung = run_bounded(cmd, cwd, os.environ, TARGET_DEADLINE_S, sys.stdout)
        if hung:
            last = next((ln.strip() for ln in reversed(lines) if ln.strip()), "(it printed nothing)")
            got.append(
                f"`{target}` did not finish in {TARGET_DEADLINE_S} s and its tree was killed; "
                f"its last line: {last[:160]}"
            )
            continue
        one = Leg(host, [target], leg.features, [], leg.ignored)
        got += result_findings(one, attribute_results(lines), target_rc)
    if got:
        print(f"platform-surface-matrix: {host} leg FAIL -- {len(got)} finding(s)")
        for f in got:
            print(f"  {f}")
        return 1
    if only:
        print(
            f"  platform-surface-matrix: {host} leg PARTIAL: {len(leg.targets)} of {full_targets} "
            f"target(s) passed ({', '.join(leg.targets)}); a narrowed run is a diagnosis and proves "
            f"nothing about the other {full_targets - len(leg.targets)}"
        )
        return 0
    print(f"  platform-surface-matrix: {host} leg: all {len(leg.targets)} target(s) passed")
    for d in leg.deferred:
        print(f"  platform-surface-matrix: {host} leg DID NOT EXECUTE {d}")
    return 0


# ─── selftest ────────────────────────────────────────────────────────────────


def _src(text: str, name: str = "x.rs") -> SourceFile:
    return source(text, pathlib.Path(name))


def _hosts(expr: str) -> frozenset[str]:
    tree, _ = parse_cfg(expr + ")", 0)
    return hosts_of([tree], lambda f: f == "on")


def selftest() -> int:
    global STALL_SAMPLE_S
    sample_window = STALL_SAMPLE_S
    failures: list[str] = []

    def expect(label: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{label}: got {got!r}, want {want!r}")

    def refused(label: str, got: list[str], needle: str) -> None:
        if not any(needle in g for g in got):
            failures.append(f"{label}: expected a finding containing {needle!r}, got {got!r}")

    # predicates
    expect("unix", _hosts("unix"), UNIX_HOSTS)
    expect("all(feature, unix)", _hosts('all(feature = "on", unix)'), UNIX_HOSTS)
    expect("feature off", _hosts('all(feature = "off", unix)'), frozenset())
    expect("not macos", _hosts('not(target_os = "macos")'), frozenset({"linux", "windows"}))
    expect("family unix", _hosts('target_family = "unix"'), UNIX_HOSTS)
    expect("foreign os", _hosts('target_os = "android"'), frozenset())
    expect("any", _hosts('any(windows, target_os = "linux")'), frozenset({"linux", "windows"}))
    expect(
        "upstream's uring gate",
        _hosts('all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))'),
        frozenset({"linux"}),
    )
    expect("the runners' arch", _hosts('target_arch = "aarch64"'), frozenset({"macos"}))
    try:
        _hosts('target_endian = "little"')
        failures.append("an unknown cfg key was evaluated instead of refused")
    except UnknownCfg:
        pass

    # masking: a cfg in a comment, a string, or a raw string is not a site; a
    # comment INSIDE a predicate is not part of it; a macro body is a template
    s = _src(
        '// #[cfg(unix)]\n/* #[cfg(windows)] */\nconst A: &str = "#[cfg(unix)]";\n'
        "const B: &str = r#\"#[cfg(unix)]\"#;\nfn f<'a>(x: &'a u8) -> char { 'x' }\n"
        '#[cfg(feature = "on")]\nfn g() {}\n'
        '#[cfg(all(\n    unix, // a note\n    feature = "on"\n))]\nfn h() {}\n'
        "macro_rules! m { ($f:literal) => { #[cfg(feature = $f)] fn k() {} }; }\n"
    )
    expect("masked site count", len(s.sites), 2)
    expect("masked site line", s.sites[0].line, 6)
    expect("a commented predicate", render(s.sites[1].tree), 'all(unix, feature = "on")')

    # spans: an inner attribute reaches the file; a gated mod reaches its body
    s = _src('#![cfg(unix)]\nfn a() {}\n#[cfg(windows)]\nmod m {\n    fn b() {}\n}\nfn c() {}\n')
    pos_b = s.text.index("fn b")
    pos_c = s.text.index("fn c")
    expect("inner reach", [render(t) for t in context_at(s.sites, pos_c)], ["unix"])
    expect("mod reach", sorted(render(t) for t in context_at(s.sites, pos_b)), ["unix", "windows"])
    s = _src("match x {\n    #[cfg(unix)]\n    A => 1,\n    B => 2,\n}\n")
    expect("arm ends at comma", context_at(s.sites, s.text.index("B =>")), [])

    # arm 1: upstream's two link gates, read together, and a feature crate's
    registry = (
        '#[cfg(feature = "transport_tcp")]\npub use zenoh_link_tcp as tcp;\n'
        '#[cfg(all(feature = "transport_unixsock-stream", target_family = "unix"))]\n'
        "pub use zenoh_link_unixsock_stream as unixsock_stream;\n"
        '#[cfg(feature = "transport_unixpipe")]\npub use zenoh_link_unixpipe as unixpipe;\n'
        '#[cfg(all(feature = "transport_vsock", target_os = "linux"))]\n'
        "pub use zenoh_link_vsock as vsock;\n"
    )
    expect(
        "up tcp",
        upstream_link_served(registry, "mod unicast;\nmod utils;\n", "zenoh_link_tcp")[0],
        ALL_HOSTS,
    )
    expect(
        "up unixsock (registry gate)",
        upstream_link_served(registry, "mod unicast;\n", "zenoh_link_unixsock_stream")[0],
        UNIX_HOSTS,
    )
    expect(
        "up unixpipe (crate gate)",
        upstream_link_served(
            registry, "#[cfg(unix)]\nmod unix;\n#[cfg(unix)]\npub use unix::*;\n", "zenoh_link_unixpipe"
        )[0],
        UNIX_HOSTS,
    )
    expect(
        "up vsock",
        upstream_link_served(registry, '#[cfg(target_os = "linux")]\nmod unicast;\n', "zenoh_link_vsock")[0],
        frozenset({"linux"}),
    )
    expect("up absent", upstream_link_served(registry, "", "zenoh_link_ws")[0], None)
    uring = '#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]\nmod linux;\n'
    expect("up uring", crate_hosts(uring)[1], frozenset({"linux"}))

    # arm 2: wz's module cfg, and the matrix both ways
    lib = (
        '#[cfg(all(feature = "transport-link-unixsock", unix))]\npub mod unixsock_pipeline;\n'
        '#[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]\n'
        "pub mod unixpipe_pipeline;\n"
        '#[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]\npub mod uring;\n'
    )
    wz_u = wz_served(lib, "unixsock_pipeline")[0]
    wz_p = wz_served(lib, "unixpipe_pipeline")[0]
    expect("wz unixsock", wz_u, UNIX_HOSTS)
    expect("wz unixpipe", wz_p, frozenset({"linux"}))
    expect("wz uring as R2973 found it", wz_served(lib, "uring")[0], ALL_HOSTS)
    names = ["UnixsockStream", "Unixpipe", "Uring"]
    up = {"UnixsockStream": UNIX_HOSTS, "Unixpipe": UNIX_HOSTS, "Uring": frozenset({"linux"})}
    fixed = {"UnixsockStream": wz_u, "Unixpipe": wz_p, "Uring": frozenset({"linux"})}
    got = matrix_findings(names, up, fixed, {})
    refused("deficit without a gap", got, "upstream serves Unixpipe on macos")
    gap = {("Unixpipe", "macos"): (851, "x")}
    expect("deficit with its gap", matrix_findings(names, up, fixed, gap), [])
    got = matrix_findings(names, up, {**fixed, "Uring": ALL_HOSTS}, gap)
    refused("the uring excess", got, "wz serves Uring on windows")
    got = matrix_findings(names, up, {**fixed, "Unixpipe": UNIX_HOSTS}, gap)
    refused("stale gap", got, "the gap is closed")

    # arm 3: the R2973 twelve-error shape, its repair, and what must stay quiet
    bound = {"transport-link-unixsock": UNIX_HOSTS}
    before = _src(
        '#[cfg(all(feature = "transport-link-unixsock", feature = "transport-unicast"))]\nfn a() {}\n'
    )
    got, n = site_findings([(before, ())], bound, str)
    refused("the unixsock site R2973 found", got, "switches ON with `transport-link-unixsock` on {windows}")
    expect("graded count", n, 1)
    after = _src(
        '#[cfg(all(feature = "transport-link-unixsock", feature = "transport-unicast", unix))]\nfn a() {}\n'
    )
    expect("the repaired site", site_findings([(after, ())], bound, str)[0], [])
    either = _src(
        '#[cfg(any(feature = "transport-link-tcp", all(feature = "transport-link-unixsock", unix)))]\nfn a() {}\n'
    )
    expect("a site the feature does not switch", site_findings([(either, ())], bound, str)[0], [])
    nested = _src('#[cfg(unix)]\nmod m {\n    #[cfg(feature = "transport-link-unixsock")]\n    fn a() {}\n}\n')
    expect("a nested site inherits its mod", site_findings([(nested, ())], bound, str)[0], [])
    bare = _src('#[cfg(feature = "transport-link-unixsock")]\nfn a() {}\n')
    unix_ctx = (parse_cfg("unix)", 0)[0],)
    expect("a file reached under unix", site_findings([(bare, unix_ctx)], bound, str)[0], [])
    refused("the same file reached bare", site_findings([(bare, ())], bound, str)[0], "{windows}")
    fallback = _src('#[cfg(not(feature = "transport-link-unixsock"))]\nfn a() {}\n')
    refused("a fallback that vanishes", site_findings([(fallback, ())], bound, str)[0], "switches OFF")
    kept = _src('#[cfg(not(all(feature = "transport-link-unixsock", unix)))]\nfn a() {}\n')
    expect("the fallback negated with its host", site_findings([(kept, ())], bound, str)[0], [])

    # arm 4: heads, runnable tests, gaps
    serial = _src(
        '#![cfg(all(feature = "transport-link-serial", unix))]\n'
        "#[tokio::test]\nasync fn a() {}\n#[test]\n#[ignore]\nfn b() {}\n",
        "serial_link_e2e.rs",
    )
    expect("head features", head_features(serial)[0], frozenset({"transport-link-serial"}))
    feats = frozenset({"transport-link-serial"})
    expect("runnable on macos", runnable_tests([(serial, ())], "macos", feats), ["a"])
    expect("runnable on windows", runnable_tests([(serial, ())], "windows", feats), [])
    # R2995 -- the shape item 852 was closed with: a file gated on the feature
    # alone, one test that runs everywhere and one that needs a tty. The host
    # gate sits on the TEST, so the file is selected on every host and Windows
    # runs the part that does not need a device.
    mixed = _src(
        '#![cfg(feature = "transport-link-serial")]\n'
        "#[tokio::test]\nasync fn everywhere() {}\n"
        "#[cfg(unix)]\n#[tokio::test]\nasync fn tty_only() {}\n",
        "serial_link_e2e.rs",
    )
    expect(
        "a per-test host gate on macos",
        runnable_tests([(mixed, ())], "macos", feats),
        ["everywhere", "tty_only"],
    )
    expect(
        "a per-test host gate on windows",
        runnable_tests([(mixed, ())], "windows", feats),
        ["everywhere"],
    )
    either_head = _src('#![cfg(any(feature = "a", feature = "b"))]\n#[test]\nfn t() {}\n')
    expect("an `any` head is refused", head_features(either_head)[0], None)
    files = {"serial_link_e2e": [(serial, ())]}
    tf = files.get
    served = {"Serial": ALL_HOSTS}
    ev = {"Serial": ("serial_link_e2e",)}
    leg, got = leg_findings("windows", served, tf, frozenset, ev, {})
    refused("an empty selection", got, "selects NO runnable test")
    xgap = {("Serial", "windows"): (852, "no COM pair")}
    leg, got = leg_findings("windows", served, tf, frozenset, ev, xgap)
    expect("the declared exec gap", got, [])
    expect("the gap is reported", len(leg.deferred), 1)
    expect("the gap's link is still built", sorted(leg.features), ["transport-link-serial"])
    leg, got = leg_findings("macos", served, tf, frozenset, ev, {})
    expect(
        "the macos leg",
        (leg.targets, sorted(leg.features), got),
        (["serial_link_e2e"], ["transport-link-serial"], []),
    )
    leg, got = leg_findings("macos", served, tf, frozenset, ev, {("Serial", "macos"): (852, "x")})
    refused("a stale exec gap", got, "now selects 1 test(s)")
    leg, got = leg_findings("macos", {"Serial": ALL_HOSTS, "Ws": ALL_HOSTS}, tf, frozenset, ev, {})
    refused("a served link with no evidence", got, "EVIDENCE names no target")

    # a PLANE target: opt-in tests, run with --ignored, features joined to the union
    witness = _src(
        '#![cfg(all(feature = "transport-multicast", feature = "locator-iface"))]\n'
        "#[tokio::test]\n#[ignore = \"opt-in\"]\nasync fn round_trips() {}\n"
        "#[test]\nfn a_plain_one() {}\n",
        "multicast_host_roundtrip.rs",
    )
    mc = {"UdpMulticast": (ALL_HOSTS, ("multicast_host_roundtrip",))}
    pfiles = {"serial_link_e2e": [(serial, ())], "multicast_host_roundtrip": [(witness, ())]}
    mfeats = frozenset({"transport-multicast", "locator-iface"})
    expect("a plane counts its ignored tests", runnable_tests([(witness, ())], "macos", mfeats, ignored=True), ["round_trips"])
    expect("and not the plain one", runnable_tests([(witness, ())], "macos", mfeats), ["a_plain_one"])
    leg, got = leg_findings("macos", served, pfiles.get, frozenset, ev, {}, mc)
    expect(
        "the plane joins the macos leg",
        (leg.targets, sorted(leg.ignored), sorted(leg.features), got),
        (
            ["serial_link_e2e", "multicast_host_roundtrip"],
            ["multicast_host_roundtrip"],
            ["locator-iface", "transport-link-serial", "transport-multicast"],
            [],
        ),
    )
    expect(
        "only the plane runs --ignored",
        (
            "--ignored" in leg_target_command(leg, "multicast_host_roundtrip"),
            "--ignored" in leg_target_command(leg, "serial_link_e2e"),
        ),
        (True, False),
    )
    expect("the plane is built with the leg", "multicast_host_roundtrip" in leg_build_command(leg), True)
    narrowed, why = select_targets(leg, ["multicast_host_roundtrip"])
    expect("a narrowed leg keeps the plane's mode", narrowed.ignored if narrowed else None, frozenset({"multicast_host_roundtrip"}))
    narrowed, why = select_targets(leg, ["serial_link_e2e"])
    expect("and drops it with the target", narrowed.ignored if narrowed else None, frozenset())
    no_optin = _src(
        '#![cfg(all(feature = "transport-multicast", feature = "locator-iface"))]\n#[test]\nfn plain() {}\n',
        "multicast_host_roundtrip.rs",
    )
    leg, got = leg_findings(
        "macos", served, {**pfiles, "multicast_host_roundtrip": [(no_optin, ())]}.get, frozenset, ev, {}, mc
    )
    refused("a plane with no opt-in test", got, "selects NO opt-in")
    leg, got = leg_findings("macos", served, {"serial_link_e2e": [(serial, ())]}.get, frozenset, ev, {}, mc)
    refused("a plane target that does not exist", got, "no tests/multicast_host_roundtrip.rs")
    leg, got = leg_findings("macos", served, pfiles.get, frozenset, ev, {}, {"UdpMulticast": (frozenset({"linux"}), ("multicast_host_roundtrip",))})
    expect("a plane another host owes is not this host's", ("multicast_host_roundtrip" in leg.targets, got), (False, []))

    # arm 5: the router interop a host owes
    t_tcp = "wz_client_reaches_established_against_a_stock_zenohd_on_this_host"
    t_ws = "wz_client_reaches_established_against_a_stock_zenohd_over_ws_on_this_host"
    t_ur = "wz_client_reaches_established_against_a_stock_zenohd_over_udp_reliable_on_this_host"
    t_us = "wz_client_reaches_established_against_a_stock_zenohd_over_unixsock_on_this_host"
    expect("tcp has no link in its name", scheme_of(t_tcp), None)
    expect("a link's underscore is the scheme's hyphen", scheme_of(t_ur), "udp-reliable")
    expect("reliable udp is not plain udp", scheme_of(t_ur) == "udp", False)
    wf = 'x\n  links="ws udp udp-reliable"\n  if mac; then\n    links="$links unixsock"\n  fi\n  --exact ' + t_tcp + "\n"
    expect("the workflow runs tcp by name", workflow_runs(t_tcp, wf), True)
    expect("the workflow runs a link by its token", workflow_runs(t_ur, wf), True)
    expect("a token is whole, not a prefix", workflow_runs(t_ur, 'links="ws udp"'), False)
    expect("udp is not run because udp-reliable is", workflow_runs(
        "wz_client_reaches_established_against_a_stock_zenohd_over_udp_on_this_host", 'links="ws udp-reliable"'), False)
    expect("a link nothing names is not run", workflow_runs(t_ws, 'links="udp"'), False)
    expect("the tcp test is not run by a links list", workflow_runs(t_tcp, 'links="ws"'), False)

    d_tcp = DATA_STEM + "tcp_on_this_host"
    d_ws = DATA_STEM + "ws_on_this_host"
    d_us = DATA_STEM + "unixsock_on_this_host"
    d_ur = DATA_STEM + "udp_reliable_on_this_host"
    expect("a data test's scheme is read as a handshake test's is", (scheme_of(d_tcp), scheme_of(d_ur)), ("tcp", "udp-reliable"))
    wfd = f'links="ws udp-reliable"\n  for s in tcp $links; do --exact "{DATA_STEM}${{s}}_on_this_host"; done\n'
    expect("the data loop covers tcp without a links token", workflow_runs_data(d_tcp, wfd), True)
    expect("the data loop covers a link by its token", workflow_runs_data(d_ur, wfd), True)
    expect("a link no links list names has no data run", workflow_runs_data(d_us, wfd), False)
    expect("no data stem, no data run", workflow_runs_data(d_tcp, 'links="ws"\n'), False)

    served5 = {"Tcp": ALL_HOSTS, "Ws": ALL_HOSTS, "Serial": ALL_HOSTS, "UnixsockStream": UNIX_HOSTS}
    inter5 = {"Tcp": t_tcp, "Ws": t_ws, "UnixsockStream": t_us}
    data5 = {"Tcp": d_tcp, "Ws": d_ws, "UnixsockStream": d_us}
    gaps5 = {("Serial", "macos"): (ROUTER_OMITS, "x"), ("Serial", "windows"): (ROUTER_OMITS, "x")}
    on5 = {"macos": frozenset({t_tcp, t_ws, t_us, d_tcp, d_ws, d_us}), "windows": frozenset({t_tcp, t_ws, d_tcp, d_ws})}
    all5 = frozenset({t_tcp, t_ws, t_us, d_tcp, d_ws, d_us})
    wf5 = f'links="ws unixsock"\n--exact {t_tcp}\nfor s in tcp $links; do --exact "{DATA_STEM}${{s}}_on_this_host"; done\n'
    default5 = frozenset({"Tcp", "Ws", "UnixsockStream"})

    def arm5(**over: object) -> list[str]:
        args = dict(
            served=served5, on=on5, every=all5, wf=wf5, default=default5, inter=inter5, gaps=gaps5,
            promoted={}, data=data5, data_promoted={},
        )
        args.update(over)
        return interop_findings(
            args["served"], args["on"], args["every"], args["wf"], args["default"], args["inter"], args["gaps"],  # type: ignore[arg-type]
            args["promoted"], args["data"], args["data_promoted"],  # type: ignore[arg-type]
        )

    expect("a consistent interop arm is green", arm5(), [])
    expect("it is also green with no upstream checkout", arm5(default=None), [])
    refused("a link nothing dials", arm5(inter={"Tcp": t_tcp, "UnixsockStream": t_us}), "nothing dials a stock router over it")
    refused("an unserved gap row", arm5(gaps={**gaps5, ("Vsock", "macos"): (ROUTER_OMITS, "x")}), "which wz does not serve")
    refused("a gap on a link that is dialed", arm5(gaps={**gaps5, ("Ws", "macos"): (ROUTER_OMITS, "x")}), "the gap is closed")
    refused("a gap whose reason is unknown", arm5(gaps={**gaps5, ("Serial", "macos"): ("because", "x")}), "none this gate knows")
    refused("router-omits is false when the pin carries the link", arm5(default=default5 | {"Serial"}), "build the row")
    refused("a dialed link the router omits", arm5(default=frozenset({"Tcp", "UnixsockStream"})), "cannot pass")
    refused("a test that does not compile on the host", arm5(on={**on5, "windows": frozenset({t_tcp})}), "no opt-in test of that name that compiles on windows")
    refused("a test the workflow never runs", arm5(wf='links="ws"\n--exact ' + t_tcp), "never runs it")
    refused("a test the table does not name", arm5(every=all5 | {"stray_on_this_host"}), "names it for no link")
    refused("a table name with no test", arm5(every=frozenset({t_tcp, t_ws})), "no host-interop test has that name")
    refused("a table kind wz does not serve", arm5(inter={**inter5, "Vsock": t_ws}), "not a link wz serves")
    good = {("Tcp", "macos"): (101, 102)}
    expect("promotion with two distinct ordered runs is green", arm5(promoted=good), [])
    refused("promotion with one run twice", arm5(promoted={("Tcp", "macos"): (101, 101)}), "two DISTINCT hosted run ids")
    refused("promotion with a non-run", arm5(promoted={("Tcp", "macos"): (101, 0)}), "two DISTINCT hosted run ids")
    refused("promotion newest first", arm5(promoted={("Tcp", "macos"): (102, 101)}), "oldest first")
    refused("promotion of a link with no test", arm5(promoted={("Serial", "macos"): (101, 102)}), "no interop test there")
    refused("promotion on a host that does not serve it", arm5(promoted={("UnixsockStream", "windows"): (101, 102)}), "no interop test there")
    # the data plane is a second table over the same links
    refused("a dialed link with no data row", arm5(data={"Tcp": d_tcp, "Ws": d_ws}), "INTEROP_DATA has no row")
    refused("a data row for a link nothing dials", arm5(data={**data5, "Vsock": d_ws}), "which INTEROP does not dial")
    refused("a data test that does not compile on the host", arm5(on={**on5, "windows": frozenset({t_tcp, t_ws, d_tcp})}), "INTEROP_DATA names")
    refused("a data test the workflow never runs", arm5(wf=f'links="ws unixsock"\n--exact {t_tcp}\n'), "is Ws's data test and the `interop` job")
    refused("a data row whose test does not exist", arm5(every=frozenset({t_tcp, t_ws, t_us, d_tcp, d_ws})), "no host-interop test has that name")
    refused("a data test the tables do not name", arm5(data={"Tcp": d_tcp, "Ws": d_ws}, every=all5), "names it for no link")
    dgood = {("Tcp", "macos"): (201, 202)}
    expect("a promoted data row with two ordered runs is green", arm5(data_promoted=dgood), [])
    refused("a data promotion with one run twice", arm5(data_promoted={("Tcp", "macos"): (201, 201)}), "INTEROP_DATA_PROMOTED (Tcp, macos) needs two DISTINCT")
    refused("a data promotion newest first", arm5(data_promoted={("Tcp", "macos"): (202, 201)}), "INTEROP_DATA_PROMOTED (Tcp, macos) lists its runs newest first")
    refused("a data promotion with no data row", arm5(data_promoted={("Serial", "macos"): (201, 202)}), "INTEROP_DATA_PROMOTED names (Serial, macos)")
    refused("a data promotion on a host that does not serve it", arm5(data_promoted={("UnixsockStream", "windows"): (201, 202)}), "INTEROP_DATA_PROMOTED names (UnixsockStream, windows)")
    expect(
        "the gated list is the promoted tests, with their targets, in kind order",
        promoted_tests("macos", inter5, {("Ws", "macos"): (1, 2), ("Tcp", "macos"): (1, 2)}, {t_tcp: "a", t_ws: "b"}, {}, {}),
        [("a", t_tcp), ("b", t_ws)],
    )
    expect("another host's promotion is not this host's", promoted_tests("windows", inter5, good, {t_tcp: "a"}, {}, {}), [])
    expect(
        "the data rows follow the handshake rows in the gated list",
        promoted_tests(
            "macos", inter5, {("Tcp", "macos"): (1, 2)}, {t_tcp: "a", d_tcp: "c", d_ws: "d"}, data5,
            {("Ws", "macos"): (1, 2), ("Tcp", "macos"): (1, 2)},
        ),
        [("a", t_tcp), ("c", d_tcp), ("d", d_ws)],
    )
    expect(
        "the summary counts owed, gated and observed rows and names the omitted links",
        interop_summary(served5, inter5, gaps5, {("Tcp", "macos"): (1, 2), ("Ws", "macos"): (1, 2)}),
        [
            "interop macos: 3 owed, 2 gated, 1 observed (UnixsockStream); router omits Serial",
            "interop windows: 2 owed, 0 gated, 2 observed (Tcp, Ws); router omits Serial",
        ],
    )
    expect(
        "the summary adds the data plane's owed and gated counts when it is asked",
        interop_summary(served5, inter5, gaps5, {("Tcp", "macos"): (1, 2)}, data=data5, data_promoted={("Tcp", "macos"): (1, 2)}),
        [
            "interop macos: 3 owed, 1 gated, 2 observed (UnixsockStream, Ws); router omits Serial; data plane: 3 owed, 1 gated, 2 observed",
            "interop windows: 2 owed, 0 gated, 2 observed (Tcp, Ws); router omits Serial; data plane: 2 owed, 0 gated, 2 observed",
        ],
    )
    expect(
        "a fully gated host says so",
        interop_summary({"Tcp": ALL_HOSTS}, {"Tcp": t_tcp}, {}, {("Tcp", "macos"): (1, 2), ("Tcp", "windows"): (1, 2)}),
        ["interop macos: 1 owed, 1 gated, none observed only", "interop windows: 1 owed, 1 gated, none observed only"],
    )
    gate_ok = (
        "jobs:\n    steps:\n      - name: observe\n        continue-on-error: true\n        run: cargo test x\n"
        "      - name: gate\n        run: |\n          python m.py --promoted \"$h\"\n          cargo test -- --ignored --exact t\n"
    )
    expect("a promoted row with a step that can fail is green", gate_step_findings(gate_ok, good), [])
    expect("no promotion needs no gating step", gate_step_findings("nothing here", {}), [])
    refused("a promoted row with no step that asks for the list", gate_step_findings("      - name: observe\n        run: cargo test\n", good), "nothing gates them")
    refused(
        "a promoted row whose step is continue-on-error",
        gate_step_findings(gate_ok.replace("      - name: gate\n", "      - name: gate\n        continue-on-error: true\n"), good),
        "an observation, not a gate",
    )
    refused("a gating step that does not run the opt-in tests", gate_step_findings(gate_ok.replace("--ignored", ""), good), "does not run `cargo test")
    commented = "      # prints --promoted HOST\n      - name: gate\n        run: |\n          python m.py --promoted h\n          cargo test -- --ignored\n"
    expect("a comment naming the flag does not move the step's boundary", gate_step_findings("      - name: before\n        run: x\n" + commented, good), [])
    with tempfile.TemporaryDirectory() as td:
        manifest = pathlib.Path(td) / "zenoh"
        manifest.mkdir()
        (manifest / "Cargo.toml").write_text(
            '[features]\nauth = []\ndefault = [\n  "transport_tcp",\n  "transport_quic_datagram",\n'
            '  "transport_unixsock-stream",\n  "transport_udp",\n]\nunstable = []\n[dependencies]\n'
        )
        expect(
            "the router's default links are read from the pin, hyphen or underscore",
            router_default_kinds(pathlib.Path(td)),
            frozenset({"Tcp", "QuicDatagram", "UnixsockStream", "Udp", "UdpReliable"}),
        )
        (manifest / "Cargo.toml").write_text("[package]\nname = 'x'\n")
        expect("a manifest with no feature list is unreadable, not empty", router_default_kinds(pathlib.Path(td)), None)
    expect("no manifest is unreadable, not empty", router_default_kinds(pathlib.Path("/nonexistent-pin")), None)

    # the runner's attribution of cargo's output
    lines = [
        "     Running tests/tls_e2e.rs (target/debug/deps/tls_e2e-1)",
        "test result: ok. 8 passed; 0 failed; 0 ignored",
        "     Running tests\\ws_e2e.rs (target\\debug\\deps\\ws_e2e-2.exe)",
        "test result: ok. 0 passed; 0 failed; 5 ignored",
    ]
    res = attribute_results(lines)
    expect("attribution", res, {"tls_e2e": ("ok", 8), "ws_e2e": ("ok", 0)})
    leg = Leg("macos", ["tls_e2e", "ws_e2e", "quic_e2e"], frozenset(), [])
    got = result_findings(leg, res, 0)
    refused("zero passed", got, "`ws_e2e` passed ZERO")
    refused("never ran", got, "`quic_e2e` reported no result")
    one = Leg("macos", ["tls_e2e"], frozenset(), [])
    expect("all green", result_findings(one, res, 0), [])
    refused("rc without a red target", result_findings(one, res, 101), "exited 101")

    # the leg's cargo prints what `_RUNNING` can read whatever the job exports:
    # a REAL child process, started under the hosted workflow's own setting,
    # reports the colour it was handed. A Windows leg whose eight targets all
    # passed was failed by "reported no result" before this was pinned.
    probe = spawn_leg(
        [sys.executable, "-c", "import os; print(os.environ.get('CARGO_TERM_COLOR'))"],
        str(ROOT),
        {**os.environ, "CARGO_TERM_COLOR": "always", "WZ_PSM_PROBE": "kept"},
    )
    seen = (probe.communicate()[0] or "").strip()
    expect("leg cargo colour under an `always` job", seen, "never")
    expect(
        "the rest of the ambient environment is kept",
        cargo_env({"CARGO_TERM_COLOR": "always", "WZ_PSM_PROBE": "kept"}),
        {"CARGO_TERM_COLOR": "never", "WZ_PSM_PROBE": "kept"},
    )

    # the relay flushes every line as it arrives, so a stalled target leaves its
    # last line in the log instead of in a buffer the cancel throws away
    class Recorder:
        def __init__(self) -> None:
            self.events: list[str] = []

        def write(self, _s: str) -> int:
            self.events.append("write")
            return 0

        def flush(self) -> None:
            self.events.append("flush")

    rec = Recorder()
    relayed = relay_lines(["a\n", "b\r\n", "c\n"], rec)  # type: ignore[arg-type]
    expect("each relayed line is flushed", rec.events, ["write", "flush"] * 3)
    expect("relayed lines come back stripped", relayed, ["a", "b", "c"])

    # the plan: one build for the union, then one run per target on the same features
    plan = Leg("macos", ["a_e2e", "b_e2e"], frozenset({"f2", "f1"}), [])
    expect(
        "one build covers every target",
        leg_build_command(plan),
        ["cargo", "test", "--no-run", "-p", RUNTIME, "--features", "f1,f2",
         "--test", "a_e2e", "--test", "b_e2e"],
    )
    expect(
        "a target runs alone, uncaptured, on the build's features",
        leg_target_command(plan, "b_e2e"),
        ["cargo", "test", "-p", RUNTIME, "--features", "f1,f2",
         "--test", "b_e2e", "--", "--nocapture"],
    )

    # stall diagnostics: which pids are the leg's, and what each host is asked to show
    listing = (
        "  PID  PGID  PPID STAT COMMAND\n"
        "  100   100     1 S<s  cargo test\n"
        "  101   100   100 S<   /x/deps/serial_link_e2e-1 --nocapture\n"
        "  102   200     1 Ss   an unrelated process\n"
        "  103  1001     1 Ss   a group whose id merely starts with 100\n"
        "not a row\n"
    )
    expect("the leg's group", group_pids(listing, 100), [100, 101])
    expect("no group", group_pids(listing, 999), [])
    expect(
        "only the leg's rows are printed, under the header",
        group_rows(listing, 100),
        [listing.splitlines()[0], listing.splitlines()[1], listing.splitlines()[2]],
    )
    expect("a group with no process prints its header only", group_rows(listing, 999), [listing.splitlines()[0]])
    expect("the listing is not cut at the window width", "-ww" in PS_LISTING, True)
    mac = stall_diagnostic_commands("macos", [100, 101])
    expect("macos samples every process of the group", [c[0] for c in mac], ["sample", "lsof", "sample", "lsof"])
    expect(
        "macos sample is bounded and named",
        mac[0],
        ["sample", "100", str(STALL_SAMPLE_S), "-file", "/tmp/wz-stall-100.txt"],
    )
    expect("linux has the group rows and no stack tool", stall_diagnostic_commands("linux", [100]), [])
    expect(
        "windows shows the process and socket tables",
        [c[0] for c in stall_diagnostic_commands("windows", [])],
        ["tasklist", "netstat"],
    )

    # a narrowed leg: only what the leg runs, in the leg's order, and a typo is refused
    full = Leg("macos", ["a_e2e", "b_e2e", "c_e2e"], frozenset({"f"}), ["d"])
    narrowed, why = select_targets(full, ["c_e2e", "a_e2e"])
    expect("narrowed targets keep the leg's order", (narrowed.targets if narrowed else None, why), (["a_e2e", "c_e2e"], ""))
    expect("narrowing keeps features and deferrals", (narrowed.features, narrowed.deferred) if narrowed else None, (frozenset({"f"}), ["d"]))
    narrowed, why = select_targets(full, ["a_e2e", "typo_e2e"])
    expect("a typo selects nothing", narrowed, None)
    refused("a typo is named", [why], "does not run typo_e2e")

    # a target that stalls is ended with its whole tree at its deadline, and one that
    # finishes is left alone. The stalled one is a child that starts a grandchild
    # holding the same pipe, the shape of cargo and the test binary it started: ending
    # only the child would leave the relay waiting on the grandchild.
    if os.name != "nt":
        py = sys.executable
        STALL_SAMPLE_S = 1  # a real observation window would only slow the fixture
        tree = (
            "import subprocess, sys, time\n"
            "print('before', flush=True)\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(25)'])\n"
            "time.sleep(25)\n"
        )
        began = time.monotonic()
        stall_log = io.StringIO()
        stalled, _rc, hung = run_bounded([py, "-c", tree], str(ROOT), os.environ, 1.0, stall_log)
        expect(
            "a stalled tree is ended at its deadline",
            (hung, stalled, time.monotonic() - began < 15),
            (True, ["before"], True),
        )
        # ...and it is LOOKED AT first: the banner is in the log before the tree is gone,
        # and on a unix host the process listing names the stalled interpreter.
        logged = stall_log.getvalue()
        expect("the stall is looked at before the kill", "STALL DIAGNOSTICS" in logged, True)
        expect("the stall diagnostics end cleanly", "END STALL DIAGNOSTICS" in logged, True)
        expect("the listing names the stalled tree", "time.sleep(25)" in logged, True)
        STALL_SAMPLE_S = sample_window
        done, done_rc, done_hung = run_bounded(
            [py, "-c", "import sys\nprint('a')\nprint('b')\nsys.exit(3)\n"],
            str(ROOT), os.environ, 30.0, io.StringIO(),
        )
        expect("a command that finishes is not marked stalled", (done, done_rc, done_hung), (["a", "b"], 3, False))

    if failures:
        print(f"platform-surface-matrix selftest: FAIL -- {len(failures)}")
        for f in failures:
            print(f"  {f}")
        return 1
    print("  platform-surface-matrix selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="grade the real tree")
    mode.add_argument("--selftest", action="store_true", help="drive every verdict on fixtures")
    mode.add_argument("--legs", metavar="HOST", help="print HOST's leg command without running it")
    mode.add_argument("--run", metavar="HOST", help="run HOST's leg; must be run ON that host")
    mode.add_argument(
        "--promoted",
        metavar="HOST",
        help="print the router-interop tests promoted to a gate on HOST, one `target<TAB>test` per line",
    )
    ap.add_argument("--require", action="store_true", help="the upstream arm must run")
    ap.add_argument(
        "--only",
        metavar="TARGET[,TARGET...]",
        help="with --run: run only these targets of the leg (a diagnosis, reported PARTIAL)",
    )
    args = ap.parse_args(argv)
    if args.only is not None and not args.run:
        ap.error("--only narrows a run; it needs --run HOST")
    only = [t for t in (args.only or "").split(",") if t]
    if args.only is not None and not only:
        ap.error("--only named no target")
    if args.selftest:
        return selftest()
    if args.check:
        return check(args.require)[2]
    if args.promoted:
        # The list a gating step runs. The tree is graded first, so a table that no longer
        # matches the crate prints nothing instead of a list that is wrong.
        tree, _legs, rc = check(require=False, quiet=True)
        if rc != 0 or tree is None:
            return rc or 2
        _on_host, _every, target_of, _got = host_interop_tests(tree.cache)
        host = args.promoted.lower()
        if host not in LEG_HOSTS:
            ap.error(f"--promoted names {host!r}; the hosts with a leg are {LEG_HOSTS}")
        for target, test in promoted_tests(host, INTEROP, INTEROP_PROMOTED, target_of, INTEROP_DATA, INTEROP_DATA_PROMOTED):
            print(f"{target}\t{test}")
        return 0
    host = (args.legs or args.run).lower()
    if args.run:
        return run(host, only)
    _tree, legs, rc = check(require=False, quiet=True)
    if rc != 0 or host not in legs:
        return rc or 2
    print(" ".join(leg_build_command(legs[host])))
    for target in legs[host].targets:
        print(" ".join(leg_target_command(legs[host], target)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""zenoh-pico's own API tests and example programs, run against a built pico C ABI library.

    pico_upstream_programs.py --package ZIP --zenohd EXE [--sets SETS] [--only IDS] [--no-control]
    pico_upstream_programs.py --host-library PROFILE --zenohd EXE [--sets SETS] [--only IDS] [--no-control]
    pico_upstream_programs.py --list
    pico_upstream_programs.py --selftest

`--package` runs them on a Windows host against the library of a Windows package (the zip
`pico_windows_package.py --build` makes): the package is extracted and held to its manifest, and
every program is compiled with MSVC's cl of the package's width against the package's own headers
and the import library of every library of its form, as a program of that package is, and run with
the package's release DLL beside it. That is the release form when the package is the one a release
ships (`--stdlib nostd`, profile `host-peer-ext`).

`--host-library` runs them on Linux against the library without `std` built here from a registered
profile (`os-posix` in the place of `engine-coop`, the `capi-nostd` profile and configuration, for
the host's own target), compiled with `cc` against zenoh-pico's headers with the config.h of that
build, rendered as the package renders it. It is the same run on the host a developer has.

`--sets` narrows the run to some of `tests`, `c11`, `c99` and `windows` (every set the host runs
when it is not given); `--only` to scenarios by id (`c11/z_sub`, `tests/z_api_bytes_test`), a
diagnosis. `--list` prints every scenario and every program left out, with its reason.

## What runs

THE PROGRAMS are zenoh-pico's, unmodified, from the pinned `vendor/zenoh-pico`: the API tests the
integration lane runs (`crates/wz-integration-tests/tests/it/files/pico_upstream_api_tests_on_wz.rs`),
built as upstream's CMake builds them for the host (the TCP proxy beside the two that take it, on a
Unix only), and the example programs of `examples/unix/c11`, `examples/unix/c99` and, on Windows,
`examples/windows`. Two units are linked beside every program and change none of its text
(`crates/wz-capi-pico/tests/c/upstream`): `unbuffered_stdout.c`, so what a program prints reaches the
file it is read from line by line and a program that ends only when stopped is read as surely as one
that returns; and on Windows, for the Unix programs, `msvc-posix/unistd.h`, the POSIX calls they make
beside the API (getopt, sleep and two thread calls). `test_encoding_with_id` carries the one
correction the integration lane carries, by exact match. Every program left out is in `NOT_RUN` with
its reason, and the selftest holds the table to the vendored tree, so a program upstream adds is a
red there until it is placed.

THE PEERS are real: a program that talks to another is paired with zenoh-pico's own counterpart
program built against zenoh-pico itself, which is compiled from the pinned tree with CMake as the
same build (every switch the declaration answers set from the library's features,
`wz_config.pico_reference`, as the size gate and the performance matrix build it), through a stock
zenohd started afresh for each scenario. A routed API test is handed the router's locator as
`argv[1]`, as upstream's `tests/api.sh` hands it. The programs that find a router by scouting
(`examples/windows`, the C99 ping and pong) find this one the way they are written to.

THE CONTROL runs first: each scenario is run with zenoh-pico in the place of the library too, and a
scenario the control cannot pass is NOT-MEASURED (the host cannot carry it): never a pass, and never
a red of the library. `--no-control` skips it, for a narrowed run by hand.

## What a pass is

A program that should end exits 0 within its scenario's bound; one that runs until stopped is still
running when it is stopped; every witness line of the scenario was printed by the process it names;
and no program compiled to the stub `main` of a header that lacks a switch it needs, read two ways:
the text the stubs print, and the executable importing the call its body makes from the library
(`z_open` for a program with a session), read with `nm` on Linux and `dumpbin /imports` on Windows.
A one-shot program that can lose a race with a declaration still on its way through the router (a
get, a put, a ping) is started again, up to its scenario's attempts, while its peer stays up.

One verdict line per scenario and library (`pico-upstream on <host> <width>: <id> on <library>:`
then PASS, FAIL with the reason, or NOT-MEASURED with the reason), appended to GITHUB_STEP_SUMMARY
when that is set, with the tail of each process's output under a line that is not PASS. Exit 0 every
scenario passed on the library, 1 one failed or was not measured, 2 a refusal (an input that is not
what it claims, or a build that did not happen).
"""

from __future__ import annotations

import argparse
import io
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pico_windows_package as pwp  # noqa: E402  the package's reader and compiler, the library's build pieces
import wz_config  # noqa: E402  the declaration, the feature table and the reference's switches

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
PICO = ROOT / "vendor" / "zenoh-pico"
HARNESS = CRATES / "wz-capi-pico" / "tests" / "c" / "upstream"
UNBUFFERED = HARNESS / "unbuffered_stdout.c"
MSVC_POSIX = HARNESS / "msvc-posix"

HOSTS = ("linux", "windows")
SETS = ("tests", "c11", "c99", "windows")
# The sets a host compiles: zenoh-pico's Windows programs call the Windows API, which Linux has not.
HOST_SETS = {"linux": ("tests", "c11", "c99"), "windows": ("tests", "windows", "c11", "c99")}
# The library a host without `std` is built with in the place of `engine-coop` (wz-capi-pico's
# Cargo.toml); Windows has its own, `pico_windows_package.NOSTD_FEATURE`.
POSIX_FEATURE = "os-posix"
# The router's locator in a program's arguments, filled in when the router is up.
ROUTER = "{router}"
# How long a router gets to accept, a process to say it is up, and the pause after it did before the
# other side starts: a declaration crosses the router in well under it.
ROUTER_READY_S = 30.0
READY_S = 30.0
SETTLE_S = 2.0
# What a side that prints nothing when it is up gets before the other starts.
QUIET_START_S = 4.0
# How long the witnesses of a one-shot program get after it ended: its peer prints what it got.
GRACE_S = 3.0
POLL_S = 0.1
# How long an upstream API test gets: several walk a matrix with a sleep per cell.
TEST_BOUND_S = 400.0
# What the stub `main` of a test or an example prints when its header lacks a switch it needs.
STUB_MARKERS = ("Missing config token to build this test", "ERROR: Zenoh pico was compiled without")
TAIL_LINES = 40


class Refusal(Exception):
    """The run will not be made as asked."""


# ---------------------------------------------------------------------------
# The programs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Program:
    """One of zenoh-pico's programs (`path` under `vendor/zenoh-pico`) and how upstream builds it.
    `body` is the call a compiled body imports from the library, whose absence is a stub `main`
    (None: the program has no stub arm). `proxy`: upstream's CMake links `tests/utils/tcp_proxy.c`
    and defines `Z_ADVANCED_PUBSUB_TEST_USE_TCP_PROXY` for it on a Unix. `correction` is
    `(found, replacement)`, `found` occurring once in the program."""

    path: str
    body: str | None = "z_open"
    proxy: bool = False
    correction: tuple[str, str] | None = None

    @property
    def name(self) -> str:
        return pathlib.PurePosixPath(self.path).stem

    @property
    def set(self) -> str:
        return set_of(self.path)


def set_of(path: str) -> str:
    """The set a program of zenoh-pico's tree belongs to, by its directory."""
    parent = pathlib.PurePosixPath(path).parent.as_posix()
    sets = {"tests": "tests", "examples/unix/c11": "c11", "examples/unix/c99": "c99", "examples/windows": "windows"}
    if parent not in sets:
        raise Refusal(f"{path} is in no set of zenoh-pico's programs this runner knows")
    return sets[parent]


def test(name: str, **kw) -> Program:
    return Program(f"tests/{name}.c", **kw)


def c11(name: str, **kw) -> Program:
    return Program(f"examples/unix/c11/{name}.c", **kw)


def c99(name: str, **kw) -> Program:
    return Program(f"examples/unix/c99/{name}.c", **kw)


def win(name: str, **kw) -> Program:
    return Program(f"examples/windows/{name}.c", **kw)


# `test_encoding_with_id` drops `e2` and then checks it, where it means the `e4` it just made; the
# integration lane's `ENCODING_CHECKS_E4` says why the real library passes the text by accident.
ENCODING_CHECKS_E4 = (
    'z_encoding_from_substr(&e4, "custom_id;custom_schema", 16);\n    assert(z_internal_encoding_check(&e2));',
    'z_encoding_from_substr(&e4, "custom_id;custom_schema", 16);\n    assert(z_internal_encoding_check(&e4));',
)

# The API tests that need no network have no stub arm, so they import no particular call.
ALONE_TESTS = ("z_api_null_drop_test", "z_api_double_drop_test", "z_api_bytes_test", "z_api_encoding_test")
ROUTED_TESTS = ("z_api_alignment_test", "z_api_liveliness_test", "z_api_cancellation_test", "z_api_matching_test",
                "z_api_connectivity_test", "z_api_queryable_test", "z_api_advanced_pubsub_test",
                "z_api_callback_drop_on_undeclare_test", "z_api_batching_test")
PROXIED_TESTS = ("z_api_advanced_pubsub_test", "z_api_callback_drop_on_undeclare_test")

C11_EXAMPLES = ("z_advanced_pub", "z_advanced_sub", "z_bytes", "z_get", "z_get_attachment", "z_get_channel",
                "z_get_lat", "z_get_liveliness", "z_info", "z_liveliness", "z_ping", "z_pong", "z_pub",
                "z_pub_attachment", "z_pub_thr", "z_pull", "z_put", "z_querier", "z_queryable",
                "z_queryable_attachment", "z_queryable_channel", "z_queryable_lat", "z_scout", "z_sub",
                "z_sub_attachment", "z_sub_channel", "z_sub_liveliness", "z_sub_thr")
C99_EXAMPLES = ("z_get", "z_info", "z_ping", "z_pong", "z_pub", "z_pull", "z_put", "z_queryable", "z_scout", "z_sub")
WINDOWS_EXAMPLES = ("z_get", "z_info", "z_ping", "z_pong", "z_pub", "z_pull", "z_put", "z_queryable", "z_scout",
                    "z_sub")
# What a body imports where it is not `z_open`: the scout opens no session, and the bytes program
# has no stub arm at all.
BODY_OF = {"z_scout": "z_scout", "z_bytes": None}


def example(make, name: str) -> Program:
    return make(name, body=BODY_OF.get(name, "z_open"))


PROGRAM_LIST = (
    [test(n, body=None, correction=ENCODING_CHECKS_E4 if n == "z_api_encoding_test" else None) for n in ALONE_TESTS]
    + [test(n, proxy=n in PROXIED_TESTS) for n in ROUTED_TESTS]
    + [example(c11, n) for n in C11_EXAMPLES]
    + [example(c99, n) for n in C99_EXAMPLES]
    + [example(win, n) for n in WINDOWS_EXAMPLES]
)
PROGRAMS = {p.path: p for p in PROGRAM_LIST}

# zenoh-pico's programs of the same directories that are not run here, each with its reason.
_SINGLE_THREAD = ("a program of zenoh-pico's single-threaded arm (`Z_FEATURE_MULTI_THREAD 0`); the library "
                  "run here is the multi-threaded one, so its header compiles the program to its stub")
_TLS = "a program of the TLS link, which the library run here does not carry"
_PRIVATE = ("reaches zenoh-pico's private layer, which a drop-in whose handles are opaque does not have; the "
            "integration lane pins the symbols it lacks")
_LOCAL = ("session-local delivery (`Z_FEATURE_LOCAL_SUBSCRIBER`, `Z_FEATURE_LOCAL_QUERYABLE`) is off in the "
          "release profile, as in zenoh-pico's default build; the integration lane runs it on its local arm")
NOT_RUN = {
    "examples/unix/c11/z_pub_st.c": _SINGLE_THREAD,
    "examples/unix/c11/z_sub_st.c": _SINGLE_THREAD,
    "examples/unix/c99/z_pub_st.c": _SINGLE_THREAD,
    "examples/unix/c99/z_sub_st.c": _SINGLE_THREAD,
    "examples/windows/z_pub_st.c": _SINGLE_THREAD,
    "examples/windows/z_sub_st.c": _SINGLE_THREAD,
    "examples/unix/c11/z_pub_tls.c": _TLS,
    "examples/unix/c11/z_sub_tls.c": _TLS,
    "tests/z_api_admin_space_test.c": _PRIVATE,
    "tests/z_api_source_info_test.c": _PRIVATE,
    "tests/z_api_timestamp_test.c": _PRIVATE,
    "tests/z_api_local_queryable_test.c": _LOCAL,
    "tests/z_api_local_subscriber_test.c": _LOCAL,
}


def population(pico: pathlib.Path) -> set[str]:
    """The programs of zenoh-pico's tree this runner answers for: every example of the three example
    directories and every `z_api_*_test` of `tests/`."""
    out = {p.relative_to(pico).as_posix() for d in ("examples/unix/c11", "examples/unix/c99", "examples/windows")
           for p in (pico / d).glob("*.c")}
    out |= {p.relative_to(pico).as_posix() for p in (pico / "tests").glob("z_api_*_test.c")}
    return out


# ---------------------------------------------------------------------------
# The scenarios
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Proc:
    """One process of a scenario: a program, its arguments (`ROUTER` filled in), whether it ends by
    itself (exit 0 expected) or runs until stopped, and the text it prints once it is up."""

    program: str
    args: tuple[str, ...] = ()
    ends: bool = True
    ready: str | None = None


@dataclass(frozen=True)
class Scenario:
    """The subject, built against the library under test; its peer, always zenoh-pico's own build;
    which of a pair starts first (`subject`, or None for the peer; a lone subject names none); the
    lines that must be printed, by role (`subject` or `peer`), as regular expressions over the
    output with its line ends made LF; whether a router is started; how many times the second
    process may be started; how long one start of it may take before it is started again; and the
    bound of the whole scenario."""

    subject: Proc
    peer: Proc | None = None
    first: str | None = None
    witnesses: tuple[tuple[str, str], ...] = ()
    router: bool = True
    attempts: int = 1
    attempt_s: float | None = None
    bound_s: float = 90.0

    @property
    def id(self) -> str:
        program = PROGRAMS[self.subject.program]
        return f"{program.set}/{program.name}"


E = ("-e", ROUTER)
UP = "Press CTRL-C"
PONG_UP = "Pong app is running"
# What the programs print, made into the witnesses below.
SUB_GOT_PUB = r">> \[Subscriber\] Received \('demo/example/zenoh-pico-pub'"
SUB_GOT_PUT = r">> \[Subscriber\] Received \('demo/example/zenoh-pico-put'"
PULLED = r">> \[Subscriber\] Pulled \('demo/example/zenoh-pico-pub'"
GOT_REPLY = r">> Received (PUT )?\('demo/example/zenoh-pico-queryable'"
GOT_QUERY = r">> \[Queryable handler\] Received Query 'demo/example/"
ATTACHED = r"with attachment:"
ROUTER_ID = r"Routers IDs:\n [0-9a-f]{2,}"
HELLO_ROUTER = r"Hello \{ zid: Some\([0-9A-F]+\), whatami: \"router\""
NUMBERS = r"(?m)^[0-9]+$"
RATES = r"(?m)^[0-9]+\.[0-9]{3}$"
RTTS = r"[0-9]+ bytes: seq=[0-9]+ rtt=[0-9]+"
ALIVE = r"New alive token \('group1/zenoh-pico'\)"
DROPPED = r"Dropped token \('group1/zenoh-pico'\)"
ADVANCED_GOT = r">> \[Advanced Subscriber\] Received PUT \('demo/example/zenoh-pico-pub'"


def p(path_of, name: str, args: tuple[str, ...] = (), ends: bool = True, ready: str | None = None) -> Proc:
    return Proc(path_of(name).path, args, ends, ready)


def scenarios_of(dialect, routed_by_argument: bool) -> list[Scenario]:
    """The pairs every example set has: a subscriber, a publisher, a put, a get, a queryable, a pull,
    an info, a scout and a ping and pong, each the subject once. `routed_by_argument`: the set's
    programs take the router as `-e`; otherwise they find it by scouting."""
    e = E if routed_by_argument else ()
    # Ending after one sample is the C11 subscriber's `-n`; the other sets have no such option.
    sub_once = e + ("-n", "1") if dialect is c11 else e
    sub_ends = dialect is c11
    pub_n = e + ("-n", "10") if dialect in (c11, c99) else e
    pub_ends = dialect in (c11, c99)
    ping_args = (e + ("-n", "20", "-w", "500")) if dialect is c11 else ("-n", "20", "-w", "500")
    ping_witness = NUMBERS if dialect is c11 else RTTS
    pong_ready = PONG_UP if dialect is c11 else None
    # The C11 pong takes the router as `-e`; the C99 and Windows pongs take no argument and scout.
    pong_args = E if dialect is c11 else ()
    queryable_ends = dialect is c11
    queryable_args = e + ("-n", "1") if dialect is c11 else e
    return [
        Scenario(p(dialect, "z_sub", sub_once, ends=sub_ends, ready=UP), p(dialect, "z_pub", e, ends=False),
                 first="subject", witnesses=(("subject", SUB_GOT_PUB),)),
        Scenario(p(dialect, "z_pub", pub_n, ends=pub_ends), p(dialect, "z_sub", e, ends=False, ready=UP),
                 witnesses=(("peer", SUB_GOT_PUB),)),
        Scenario(p(dialect, "z_put", e), p(dialect, "z_sub", e, ends=False, ready=UP),
                 witnesses=(("peer", SUB_GOT_PUT),), attempts=3),
        Scenario(p(dialect, "z_get", e), p(dialect, "z_queryable", e, ends=False, ready=UP),
                 witnesses=(("subject", GOT_REPLY),), attempts=3),
        Scenario(p(dialect, "z_queryable", queryable_args, ends=queryable_ends, ready=UP), p(dialect, "z_get", e),
                 first="subject", witnesses=(("subject", GOT_QUERY), ("peer", GOT_REPLY)), attempts=3),
        Scenario(p(dialect, "z_pull", e, ends=False, ready="Pulling data every"), p(dialect, "z_pub", e, ends=False),
                 first="subject", witnesses=(("subject", PULLED),)),
        Scenario(p(dialect, "z_info", e, ends=dialect is win), witnesses=(("subject", ROUTER_ID),)),
        Scenario(p(dialect, "z_scout"), witnesses=(("subject", HELLO_ROUTER),)),
        Scenario(p(dialect, "z_ping", ping_args), p(dialect, "z_pong", pong_args, ends=False, ready=pong_ready),
                 witnesses=(("subject", ping_witness),), attempts=3, attempt_s=30.0),
        Scenario(p(dialect, "z_pong", pong_args, ends=False, ready=pong_ready), p(dialect, "z_ping", ping_args),
                 first="subject", witnesses=(("peer", ping_witness),), attempts=3, attempt_s=30.0),
    ]


def c11_only_scenarios() -> list[Scenario]:
    """The C11 programs the other sets do not have."""
    return [
        Scenario(p(c11, "z_bytes"), router=False),
        Scenario(p(c11, "z_pub_attachment", E + ("-n", "10")), p(c11, "z_sub_attachment", E, ends=False, ready=UP),
                 witnesses=(("peer", SUB_GOT_PUB), ("peer", ATTACHED))),
        Scenario(p(c11, "z_sub_attachment", E + ("-n", "1"), ready=UP), p(c11, "z_pub_attachment", E, ends=False),
                 first="subject", witnesses=(("subject", SUB_GOT_PUB), ("subject", ATTACHED))),
        Scenario(p(c11, "z_get_attachment", E), p(c11, "z_queryable_attachment", E, ends=False, ready=UP),
                 witnesses=(("subject", GOT_REPLY), ("subject", ATTACHED)), attempts=3),
        Scenario(p(c11, "z_queryable_attachment", E + ("-n", "1"), ready=UP), p(c11, "z_get_attachment", E),
                 first="subject", witnesses=(("subject", GOT_QUERY), ("subject", ATTACHED), ("peer", GOT_REPLY)),
                 attempts=3),
        Scenario(p(c11, "z_get_channel", E), p(c11, "z_queryable", E, ends=False, ready=UP),
                 witnesses=(("subject", GOT_REPLY),), attempts=3),
        Scenario(p(c11, "z_queryable_channel", E, ends=False, ready="Creating Queryable"), p(c11, "z_get", E),
                 first="subject", witnesses=(("subject", GOT_QUERY), ("peer", GOT_REPLY)), attempts=3),
        Scenario(p(c11, "z_sub_channel", E, ends=False, ready="Declaring Subscriber"), p(c11, "z_pub", E, ends=False),
                 first="subject", witnesses=(("subject", SUB_GOT_PUB),)),
        Scenario(p(c11, "z_querier", E + ("-n", "5")), p(c11, "z_queryable", E, ends=False, ready=UP),
                 witnesses=(("subject", GOT_REPLY),)),
        Scenario(p(c11, "z_liveliness", E + ("-t", "3")), p(c11, "z_sub_liveliness", E, ends=False, ready=UP),
                 witnesses=(("peer", ALIVE), ("peer", DROPPED))),
        Scenario(p(c11, "z_sub_liveliness", E, ends=False, ready=UP), p(c11, "z_liveliness", E + ("-t", "3")),
                 first="subject", witnesses=(("subject", ALIVE), ("subject", DROPPED))),
        Scenario(p(c11, "z_get_liveliness", E), p(c11, "z_liveliness", E, ends=False, ready=UP),
                 witnesses=(("subject", r">> Alive token \('group1/zenoh-pico'\)"),), attempts=3),
        Scenario(p(c11, "z_advanced_pub", E, ends=False), p(c11, "z_advanced_sub", E, ends=False, ready=UP),
                 witnesses=(("peer", ADVANCED_GOT),)),
        Scenario(p(c11, "z_advanced_sub", E, ends=False, ready=UP), p(c11, "z_advanced_pub", E, ends=False),
                 first="subject", witnesses=(("subject", ADVANCED_GOT),)),
        # The throughput pair runs 20 s on the publisher's side and 23 s on the subscriber's, and
        # prints a rate only for a window that counted a sample; neither says when it is up.
        Scenario(p(c11, "z_pub_thr", E), p(c11, "z_sub_thr", E), witnesses=(("peer", RATES),), bound_s=120.0),
        Scenario(p(c11, "z_sub_thr", E), p(c11, "z_pub_thr", E), first="subject", witnesses=(("subject", RATES),),
                 bound_s=120.0),
        # The queryable of the latency pair answers for 20 s; the querier's 50 round trips end well
        # inside them.
        Scenario(p(c11, "z_get_lat", E + ("-n", "50", "-w", "500")), p(c11, "z_queryable_lat", E),
                 witnesses=(("subject", NUMBERS),), bound_s=120.0),
        Scenario(p(c11, "z_queryable_lat", E), p(c11, "z_get_lat", E + ("-n", "50", "-w", "500")), first="subject",
                 witnesses=(("peer", NUMBERS),), bound_s=120.0),
    ]


def test_scenarios() -> list[Scenario]:
    """Each API test alone, or beside a router with its locator as `argv[1]`, its own asserts the
    verdict."""
    alone = [Scenario(p(test, n), router=False, bound_s=TEST_BOUND_S) for n in ALONE_TESTS]
    routed = [Scenario(p(test, n, (ROUTER,)), bound_s=TEST_BOUND_S) for n in ROUTED_TESTS]
    return alone + routed


SCENARIOS = (test_scenarios() + scenarios_of(c11, True) + c11_only_scenarios() + scenarios_of(c99, True)
             + scenarios_of(win, False))


# ---------------------------------------------------------------------------
# Pure pieces (the selftest drives them)
# ---------------------------------------------------------------------------


def corrected(text: str, correction: tuple[str, str] | None, name: str) -> str:
    """The program's text with its correction made; a correction whose text no longer occurs
    exactly once is refused, so a changed upstream text reds rather than being skipped."""
    if correction is None:
        return text
    found, replacement = correction
    count = text.count(found)
    if count != 1:
        raise Refusal(f"{name} has the line its correction replaces {count} times, not once: the correction "
                      "is stale")
    return text.replace(found, replacement, 1)


def normalized(raw: bytes) -> str:
    """A process's output as text with its line ends LF (a Windows program writes CR LF)."""
    return raw.decode("utf-8", errors="replace").replace("\r\n", "\n")


def nm_imports(listing: str) -> set[str]:
    """The names `nm --undefined-only` lists, a versioned reference read as its name."""
    out = set()
    for line in listing.splitlines():
        words = line.split()
        if words:
            out.add(words[-1].split("@", 1)[0])
    return out


DUMPBIN_ENTRY = re.compile(r"^\s+[0-9A-Fa-f]+\s+([A-Za-z_][A-Za-z0-9_@?$]*)\s*$")


def dumpbin_imports(listing: str) -> set[str]:
    """The names `dumpbin /imports` lists under every module an executable imports from: each by-name
    import is a line of its hint and its name."""
    return {m.group(1) for line in listing.splitlines() if (m := DUMPBIN_ENTRY.match(line))}


def reference_flags(switches: dict[str, int]) -> list[str]:
    """The CMake definitions of zenoh-pico's switches, in name order."""
    return [f"-D{name}={value}" for name, value in sorted(switches.items())]


def refused_switches(switches: dict[str, int], header: str) -> list[str]:
    """The switches asked of zenoh-pico's build that its generated config.h does not state as asked."""
    on, _ = wz_config.pico_flag_states(header)
    return sorted(name for name, value in switches.items()
                  if (value and name not in on) or (not value and name in on))


def order_of(sc: Scenario) -> list[tuple[str, Proc]]:
    """The processes of a scenario in the order they start."""
    if sc.peer is None:
        return [("subject", sc.subject)]
    pair = [("subject", sc.subject), ("peer", sc.peer)]
    return pair if sc.first == "subject" else pair[::-1]


@dataclass
class Record:
    """What one process of a scenario did: its last start's output, its exit status (None when it
    was stopped while it still ran) and how many times it was started."""

    role: str
    proc: Proc
    status: int | None
    text: str
    starts: int = 1


def missing_witnesses(sc: Scenario, texts: dict[str, str]) -> list[tuple[str, str]]:
    """The witnesses of a scenario not yet printed by the process each names."""
    return [(role, pattern) for role, pattern in sc.witnesses
            if not re.search(pattern, texts.get(role, ""), re.M)]


def judge(sc: Scenario, records: list[Record], bound_s: float) -> list[str]:
    """Why a played scenario is not a pass; empty when it is."""
    why = []
    for rec in records:
        marker = next((m for m in STUB_MARKERS if m in rec.text), None)
        if marker is not None:
            why.append(f"the {rec.role} compiled to its stub main (it printed '{marker}')")
        if rec.proc.ends and rec.status is None:
            why.append(f"the {rec.role} did not end within {bound_s:.0f} s")
        elif rec.proc.ends and rec.status != 0:
            why.append(f"the {rec.role} exited {rec.status}")
        elif not rec.proc.ends and rec.status is not None:
            why.append(f"the {rec.role} exited {rec.status} before it was stopped")
    texts = {rec.role: rec.text for rec in records}
    for role, pattern in missing_witnesses(sc, texts):
        why.append(f"the {role} printed no line matching /{pattern}/")
    return why


def tail(text: str, lines: int = TAIL_LINES) -> str:
    return "\n".join(text.splitlines()[-lines:])


def selected(host: str, sets: list[str] | None, only: list[str] | None) -> list[Scenario]:
    """The scenarios a run on `host` plays: those of the sets it names (every set of the host when
    none), narrowed to the ids `only` names; a set the host does not run and an unknown id are
    refused."""
    host_sets = HOST_SETS[host]
    chosen = list(host_sets) if not sets else sets
    for s in chosen:
        if s not in host_sets:
            raise Refusal(f"a {host} host does not run the set {s} (it runs {', '.join(host_sets)})")
    out = [sc for sc in SCENARIOS if PROGRAMS[sc.subject.program].set in chosen]
    if only:
        known = {sc.id for sc in out}
        unknown = sorted(set(only) - known)
        if unknown:
            raise Refusal(f"no scenario {', '.join(unknown)} among the sets {', '.join(chosen)}")
        out = [sc for sc in out if sc.id in only]
    return out


def scenario_findings(sc: Scenario) -> list[str]:
    """Where one scenario disagrees with the program table or with itself."""
    findings = []
    procs = [sc.subject] + ([sc.peer] if sc.peer is not None else [])
    roles = {"subject"} | ({"peer"} if sc.peer is not None else set())
    for proc in procs:
        if proc.program not in PROGRAMS:
            findings.append(f"{sc.id}: {proc.program} is not a program of the table")
        elif PROGRAMS[proc.program].set != PROGRAMS[sc.subject.program].set:
            findings.append(f"{sc.id}: its peer {proc.program} is of another set than its subject")
        if (ROUTER in proc.args) and not sc.router:
            findings.append(f"{sc.id}: {proc.program} is handed a router the scenario does not start")
    if sc.first is not None and sc.first not in ("subject", "peer"):
        findings.append(f"{sc.id}: starts with a {sc.first}, which is neither its subject nor its peer")
    elif sc.first is not None and sc.peer is None:
        findings.append(f"{sc.id}: orders a pair it does not have (it has no peer, and starts with the {sc.first})")
    for role, pattern in sc.witnesses:
        if role not in roles:
            findings.append(f"{sc.id}: a witness of a {role} it does not have")
        try:
            re.compile(pattern)
        except re.error as err:
            findings.append(f"{sc.id}: witness /{pattern}/ is no regular expression ({err})")
    if not sc.witnesses and not any(proc.ends for proc in procs):
        findings.append(f"{sc.id}: nothing in it ends and nothing is witnessed, so it would pass having shown "
                        "nothing")
    if sc.attempts < 1:
        findings.append(f"{sc.id}: attempts below one")
    return findings


def table_findings(pico: pathlib.Path) -> list[str]:
    """Where the program table and the scenarios disagree with the vendored tree or with each
    other."""
    findings = []
    pop = population(pico)
    if not pop:
        findings.append(f"no program of zenoh-pico under {pico}: the submodule is not checked out")
    for path in sorted(pop - set(PROGRAMS) - set(NOT_RUN)):
        findings.append(f"{path} is a program of zenoh-pico that is neither run nor left out with a reason")
    for path in sorted(set(PROGRAMS) & set(NOT_RUN)):
        findings.append(f"{path} is run and left out at once")
    for path in sorted((set(PROGRAMS) | set(NOT_RUN)) - pop):
        findings.append(f"{path} is named here and is no program of zenoh-pico at the pin")
    subjects: dict[str, int] = {}
    for sc in SCENARIOS:
        subjects[sc.subject.program] = subjects.get(sc.subject.program, 0) + 1
        findings += scenario_findings(sc)
    for path in sorted(PROGRAMS):
        if subjects.get(path, 0) != 1:
            findings.append(f"{path} is the subject of {subjects.get(path, 0)} scenarios, not one")
    return findings


# ---------------------------------------------------------------------------
# The libraries and the compilers
# ---------------------------------------------------------------------------


@dataclass
class Library:
    """A library the programs are compiled against: the letter of its arm (W the library under test,
    P zenoh-pico), what a verdict line calls it, its include directories, what links it (Linux: cc's
    words; Windows: its import libraries) and the files a program needs beside it to run (Windows:
    its DLLs; Linux: nothing, the link records the run path)."""

    letter: str
    label: str
    includes: list[pathlib.Path]
    link: list[str]
    runtime: list[pathlib.Path]


def say(line: str) -> None:
    pwp.say(line)


class Linux:
    name = "linux"
    width = os.uname().machine if hasattr(os, "uname") else ""

    def compile(self, program: Program, lib: Library, work: pathlib.Path) -> pathlib.Path | None:
        src = prepared(program, work)
        includes = list(lib.includes) + ([PICO / "tests"] if program.set == "tests" else [])
        extra = [PICO / "tests" / "utils" / "tcp_proxy.c"] if program.proxy else []
        defines = ["Z_ADVANCED_PUBSUB_TEST_USE_TCP_PROXY"] if program.proxy else []
        exe = work / program.name
        # pico's own build compiles every example and test as C11 with the compiler's extensions
        # (`set(CMAKE_C_STANDARD 11)`, the examples' `C_STANDARD 11` property), which its Unix
        # header relies on.
        cmd = (["cc", "-std=gnu11", "-DZENOH_LINUX", "-pthread"] + [f"-I{d}" for d in includes]
               + [f"-D{d}" for d in defines] + [str(src)] + [str(x) for x in extra] + [str(UNBUFFERED)]
               + ["-o", str(exe)] + lib.link)
        built = subprocess.run(cmd, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               encoding="utf-8", errors="replace")
        if built.returncode != 0:
            print(built.stdout, flush=True)
            return None
        return exe

    def imports(self, exe: pathlib.Path, work: pathlib.Path) -> set[str] | None:
        listed = subprocess.run(["nm", "--undefined-only", str(exe)], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
        return nm_imports(listed.stdout) if listed.returncode == 0 else None


class Windows:
    name = "windows"

    def __init__(self, vcvars: str, width: str):
        self.vs = pwp.vs_root()
        self.vcvars = vcvars
        self.width = width

    def run_in_vs(self, work: pathlib.Path, name: str, lines: list[str]) -> bool:
        """Whether every line, run in order in the environment `vcvarsall.bat` sets up for the width,
        succeeded."""
        bat = work / f"{name}.bat"
        text = ("@echo off\r\n" + f'call "{self.vs}\\VC\\Auxiliary\\Build\\vcvarsall.bat" {self.vcvars} > nul\r\n'
                + f'cd /d "{work}"\r\n')
        for line in lines:
            text += line + "\r\nif errorlevel 1 exit /b 1\r\n"
        bat.write_text(text + "exit /b 0\r\n", encoding="ascii")
        return subprocess.run(["cmd.exe", "/c", str(bat)]).returncode == 0

    def compile(self, program: Program, lib: Library, work: pathlib.Path) -> pathlib.Path | None:
        src = prepared(program, work)
        includes = list(lib.includes) + ([PICO / "tests"] if program.set == "tests" else [])
        if program.set in ("c11", "c99"):
            includes.append(MSVC_POSIX)
        exe = work / f"{program.name}.exe"
        # zenoh-pico's Windows build is C11 with `ZENOH_WINDOWS` (`cl_script` gives both); the C11
        # atomics of the throughput and latency programs are behind their own switch; `/MD` is the C
        # runtime zenoh-pico's own DLL is built against; the programs' text is UTF-8.
        words = (["/MD", "/utf-8", "/experimental:c11atomics"] + [f'/I"{d}"' for d in includes]
                 + [f'"{src}"', f'"{UNBUFFERED}"'] + [f'"{x}"' for x in lib.link] + [f'/Fe:"{exe}"'])
        if not pwp.run_cl(self.vs, self.vcvars, work, program.name, " ".join(words)) or not exe.is_file():
            return None
        for dll in lib.runtime:
            shutil.copy2(dll, work / dll.name)
        return exe

    def imports(self, exe: pathlib.Path, work: pathlib.Path) -> set[str] | None:
        listing = work / "imports.txt"
        if not self.run_in_vs(work, "imports", [f'dumpbin /nologo /imports "{exe}" > "{listing}"']):
            return None
        return dumpbin_imports(listing.read_text(encoding="utf-8", errors="replace"))


def prepared(program: Program, work: pathlib.Path) -> pathlib.Path:
    """The program's source to compile: upstream's file, or a copy with its correction made."""
    src = PICO / program.path
    if not src.is_file():
        raise Refusal(f"{src} is missing; run `git submodule update --init vendor/zenoh-pico`")
    if program.correction is None:
        return src
    copy = work / src.name
    copy.write_text(corrected(src.read_text(encoding="utf-8"), program.correction, program.name),
                    encoding="utf-8", newline="\n")
    return copy


def package_library(archive: pathlib.Path, scratch: pathlib.Path) -> tuple[Library, list[str], str]:
    """The release build of a Windows package's library, the features it was built with and its width."""
    top = pwp.extract_zip(archive, scratch / "package")
    findings = pwp.verify_findings(top)
    if findings:
        raise Refusal(f"{archive.name} does not match its manifest: {'; '.join(findings)}")
    manifest = json.loads((top / pwp.MANIFEST).read_text(encoding="utf-8"))
    arch = pwp.arch_of_target(manifest.get("target", ""))
    libraries = pwp.FORMS[pwp.form_of(manifest)]
    features = manifest.get("features")
    if not isinstance(features, list) or not features:
        raise Refusal(f"{archive.name}'s manifest lists no features of the build")
    lib = Library(LIBRARY, f"{top.name} (release)", [top / "include"],
                  [str(top / "release" / "lib" / f"{name}.lib") for name in libraries],
                  [top / "release" / "bin" / f"{name}.dll" for name in libraries])
    for path in [pathlib.Path(x) for x in lib.link] + lib.runtime:
        if not path.is_file():
            raise Refusal(f"{archive.name} has no {path.relative_to(top).as_posix()}")
    return lib, features, arch


def host_triple() -> str:
    for line in pwp.run(["rustc", "-vV"], CRATES).splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    raise Refusal("rustc names no host target")


def host_library(profile: str, scratch: pathlib.Path) -> tuple[Library, list[str]]:
    """The library without `std` of a registered profile, built here for the host's own target, and
    its features, with zenoh-pico's headers carrying the config.h of exactly that build."""
    if not sys.platform.startswith("linux"):
        raise Refusal("--host-library builds the POSIX library without std, on Linux; a Windows host runs a "
                      "package (--package)")
    stated = pwp.stated_in_environment(dict(os.environ))
    if stated:
        raise Refusal(f"the environment states {', '.join(stated)}; the library is its profile's alone, so "
                      "unset them")
    decl = wz_config.load_decl()
    plan = pwp.resolve_profile(decl, profile)
    table = wz_config.manifest_features(wz_config.MANIFESTS["pico"])
    features = pwp.nostd_features(plan["features"], table, POSIX_FEATURE)
    env = {**os.environ, **plan["env"]}
    target = host_triple()
    report = pwp.run(["cargo", "build", "-p", pwp.CRATE, "--lib", "--no-default-features", "--features",
                      ",".join(features), "--profile", pwp.NOSTD_PROFILE, "--config", pwp.NOSTD_CONFIG,
                      "--target", target, "--message-format=json-render-diagnostics"], CRATES, env)
    built = pwp.pick(pwp.artifact_files(report, pwp.LIBRARY), ".so")
    if built is None:
        raise Refusal(f"cargo reported no single shared library of {pwp.LIBRARY}")
    libdir = scratch / "lib-W"
    libdir.mkdir(parents=True)
    shutil.copy2(built, libdir / built.name)
    include = pwp.pico_include(pwp.run(["cargo", "build", "-p", "zenoh-pico-sys",
                                        "--message-format=json-render-diagnostics"], CRATES, env))
    arm = scratch / "include-W"
    shutil.copytree(include, arm)
    (arm / "zenoh-pico" / "config.h").write_text(pwp.arm_header(decl, features, plan["env"]), encoding="utf-8",
                                                 newline="\n")
    link = ["-L", str(libdir), f"-l{pwp.LIBRARY}", f"-Wl,-rpath,{libdir}"]
    return Library(LIBRARY, f"{pwp.LIBRARY} {profile} without std ({target})", [arm], link, []), features


def export_pico(into: pathlib.Path) -> pathlib.Path:
    """The pinned zenoh-pico tree, exported afresh: its configure writes a header into its source
    tree, which must not dirty the submodule."""
    archive = subprocess.run(["git", "-C", str(PICO), "archive", "--format=tar", "HEAD"], capture_output=True)
    if archive.returncode != 0:
        raise Refusal(f"git could not export {PICO}: {archive.stderr.decode(errors='replace').strip()}")
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
        tar.extractall(into, filter="data")
    return into


def reference_library(host, features: list[str], scratch: pathlib.Path) -> Library:
    """zenoh-pico built as the same build as the library of `features`: every switch the declaration
    answers set from those features (`wz_config.pico_reference`), a shared library, no examples and
    no tests; its headers are its source tree's with the config.h its CMake generated on top."""
    table = wz_config.manifest_features(wz_config.MANIFESTS["pico"])
    try:
        enabled = wz_config.enabled_features(table, features)
    except KeyError as err:
        raise Refusal(f"the library names a feature this tree's wz-capi-pico does not have: {err}") from None
    switches = wz_config.pico_reference(wz_config.load_decl(), enabled)
    src = export_pico(scratch / "pico-src")
    build = scratch / "pico-build"
    configure = ["cmake", "-S", str(src), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                 "-DBUILD_EXAMPLES=OFF", "-DBUILD_TESTING=OFF", *reference_flags(switches)]
    if host.name == "windows":
        # NMake in the environment of the package's width: the compiler of that width builds it.
        quoted = " ".join(f'"{w}"' if " " in w or "\\" in w else w for w in configure)
        built = host.run_in_vs(scratch, "pico-reference",
                               [quoted + ' -G "NMake Makefiles"', f'cmake --build "{build}"'])
    else:
        built = (subprocess.run(configure).returncode == 0
                 and subprocess.run(["cmake", "--build", str(build), "--parallel", str(os.cpu_count() or 1)])
                 .returncode == 0)
    if not built:
        raise Refusal("zenoh-pico did not build as the reference")
    header = (build / "include" / "zenoh-pico" / "config.h").read_text(encoding="utf-8")
    refused = refused_switches(switches, header)
    if refused:
        say(f"pico-upstream on {host.name} {host.width}: zenoh-pico's build does not state as asked: "
            f"{', '.join(refused)}")
    include = scratch / "include-P"
    shutil.copytree(src / "include", include)
    shutil.copytree(build / "include", include, dirs_exist_ok=True)
    label = "zenoh-pico (control)"
    if host.name == "windows":
        def one(pattern: str) -> pathlib.Path:
            hits = [x for x in build.rglob(pattern) if "CMakeFiles" not in x.parts]
            if len(hits) != 1:
                raise Refusal(f"the reference build left {len(hits)} {pattern} under {build}, not one")
            return hits[0]
        return Library(REFERENCE, label, [include], [str(one("zenohpico.lib"))], [one("zenohpico.dll")])
    libdir = build / "lib"
    if not (libdir / "libzenohpico.so").exists():
        raise Refusal(f"the reference build left no libzenohpico.so in {libdir}")
    return Library(REFERENCE, label, [include], ["-L", str(libdir), "-lzenohpico", f"-Wl,-rpath,{libdir}"], [])


# ---------------------------------------------------------------------------
# The router and the processes
# ---------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def accepts(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            return True
    except OSError:
        return False


class Router:
    """A stock zenohd for one scenario, listening on every address so that the Hello it answers a
    scout with carries a locator a client can dial (on the loopback form alone it answers with
    none), its multicast scouting as its defaults have it."""

    def __init__(self, zenohd: pathlib.Path, work: pathlib.Path):
        self.port = free_port()
        self.log = work / "zenohd.log"
        self.out = open(self.log, "wb")
        self.proc = subprocess.Popen([str(zenohd), "-l", f"tcp/0.0.0.0:{self.port}", "--rest-http-port", "none"],
                                     stdout=self.out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     env={**os.environ, "RUST_LOG": "info"})
        deadline = time.monotonic() + ROUTER_READY_S
        while time.monotonic() < deadline and self.proc.poll() is None and not accepts(self.port):
            time.sleep(POLL_S)
        if self.proc.poll() is not None or not accepts(self.port):
            self.stop()
            raise RuntimeError(f"zenohd did not accept on {self.port} within {ROUTER_READY_S:.0f} s\n"
                               + tail(normalized(self.log.read_bytes())))
        # Its scouting socket opens beside its listener.
        time.sleep(1.0)

    @property
    def locator(self) -> str:
        return f"tcp/127.0.0.1:{self.port}"

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.out.close()


class Running:
    """One start of a process of a scenario, its output going to a file of its own."""

    def __init__(self, role: str, proc: Proc, exe: pathlib.Path, locator: str, work: pathlib.Path, start: int):
        self.role = role
        self.proc = proc
        self.log = work / f"{role}-{start}.log"
        self.out = open(self.log, "wb")
        args = [a.replace(ROUTER, locator) for a in proc.args]
        # A pong waits on its standard input for a `q`: an open pipe nobody writes keeps it waiting.
        self.popen = subprocess.Popen([str(exe), *args], cwd=exe.parent, stdin=subprocess.PIPE, stdout=self.out,
                                      stderr=subprocess.STDOUT)
        self.started = time.monotonic()
        self.ended_at: float | None = None
        self.stopped = False

    def text(self) -> str:
        return normalized(self.log.read_bytes())

    def poll(self) -> int | None:
        status = self.popen.poll()
        if status is not None and self.ended_at is None:
            self.ended_at = time.monotonic()
        return status

    def stop(self) -> None:
        if self.popen.poll() is None:
            self.stopped = True
            self.popen.kill()
        self.popen.wait()
        self.poll()
        if self.popen.stdin is not None:
            self.popen.stdin.close()
        self.out.close()

    def record(self, starts: int) -> Record:
        return Record(self.role, self.proc, None if self.stopped else self.popen.returncode, self.text(), starts)


def wait_ready(run: Running, ready: str | None, deadline: float) -> None:
    """Until the process says it is up (or a quiet one has had its time), it ends, or the deadline."""
    if ready is None:
        time.sleep(min(QUIET_START_S, max(0.0, deadline - time.monotonic())))
        return
    while time.monotonic() < deadline and run.poll() is None and ready not in run.text():
        time.sleep(POLL_S)


def play(sc: Scenario, exes: dict[str, pathlib.Path], locator: str, work: pathlib.Path) -> list[Record]:
    """Run a scenario once and return what each process did. The second process is started again
    while its witnesses are missing, when it ended cleanly or outlived `attempt_s`, up to the
    scenario's attempts."""
    deadline = time.monotonic() + sc.bound_s
    order = order_of(sc)
    running: dict[str, Running] = {}
    starts = {role: 1 for role, _ in order}
    try:
        first_role, first = order[0]
        running[first_role] = Running(first_role, first, exes[first_role], locator, work, 1)
        if len(order) == 2:
            wait_ready(running[first_role], first.ready, min(deadline, time.monotonic() + READY_S))
            time.sleep(SETTLE_S)
            second_role, second = order[1]
            if running[first_role].poll() is None or first.ends:
                running[second_role] = Running(second_role, second, exes[second_role], locator, work, 1)
        while time.monotonic() < deadline:
            texts = {role: run.text() for role, run in running.items()}
            witnessed = not missing_witnesses(sc, texts)
            if witnessed and all(run.poll() is not None for run in running.values() if run.proc.ends):
                break
            if any(run.poll() is not None for run in running.values() if not run.proc.ends):
                break
            if any(run.poll() not in (None, 0) for run in running.values()):
                break
            if len(order) == 2 and order[1][0] in running:
                role, again = order[1]
                run = running[role]
                status = run.poll()
                ended_clean = status == 0 and run.ended_at is not None and time.monotonic() - run.ended_at >= GRACE_S
                overdue = (sc.attempt_s is not None and status is None
                           and time.monotonic() - run.started >= sc.attempt_s)
                if not witnessed and (ended_clean or overdue) and starts[role] < sc.attempts:
                    run.stop()
                    starts[role] += 1
                    running[role] = Running(role, again, exes[role], locator, work, starts[role])
            time.sleep(POLL_S)
    finally:
        for run in running.values():
            run.stop()
    return [running[role].record(starts[role]) for role, _ in order if role in running]


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


@dataclass
class Built:
    """A program compiled against one library, or why it is not."""

    exe: pathlib.Path | None
    why: str = ""


class Runner:
    def __init__(self, host, subject: Library, reference: Library, zenohd: pathlib.Path, scratch: pathlib.Path,
                 control: bool):
        self.host = host
        self.libs = {LIBRARY: subject, REFERENCE: reference}
        self.zenohd = zenohd
        self.scratch = scratch
        self.control = control
        self.built: dict[tuple[str, str], Built] = {}

    def line(self, sc: Scenario, lib: Library, verdict: str) -> None:
        say(f"pico-upstream on {self.host.name} {self.host.width}: {sc.id} on {lib.label}: {verdict}")

    def build(self, path: str, letter: str) -> Built:
        key = (path, letter)
        if key in self.built:
            return self.built[key]
        program = PROGRAMS[path]
        work = self.scratch / "build" / letter / program.set / program.name
        work.mkdir(parents=True, exist_ok=True)
        exe = self.host.compile(program, self.libs[letter], work)
        if exe is None:
            done = Built(None, f"{program.path} did not compile or link against {self.libs[letter].label}")
        elif program.body is None:
            done = Built(exe)
        else:
            imported = self.host.imports(exe, work)
            if imported is None:
                done = Built(None, f"what {program.path} imports could not be read")
            elif program.body not in imported:
                done = Built(None, f"{program.path} compiled to a main that never calls {program.body}: the header "
                                   "lacks a switch its body is gated on, so nothing would run")
            else:
                done = Built(exe)
        self.built[key] = done
        return done

    def attempt(self, sc: Scenario, letters: dict[str, str], tag: str) -> tuple[str, bool]:
        """One play of the scenario with each role's program built against the library its letter
        names: why it is not a pass (empty for a pass), and whether it measured the library at all. A
        router that did not come up, or a program that did not build against zenoh-pico, measured
        nothing."""
        exes = {}
        for role, proc in order_of(sc):
            built = self.build(proc.program, letters[role])
            if built.exe is None:
                return built.why, letters[role] == LIBRARY
            exes[role] = built.exe
        work = self.scratch / "runs" / sc.id.replace("/", "-") / tag
        work.mkdir(parents=True, exist_ok=True)
        router = None
        try:
            if sc.router:
                router = Router(self.zenohd, work)
            records = play(sc, exes, router.locator if router else "", work)
        except RuntimeError as err:
            return str(err), False
        finally:
            if router is not None:
                router.stop()
        why = judge(sc, records, sc.bound_s)
        if why and router is not None:
            print(f"--- zenohd ({sc.id}, {tag})\n{tail(normalized(router.log.read_bytes()))}", flush=True)
        if why:
            for rec in records:
                print(f"--- {rec.role} {rec.proc.program} ({sc.id}, {tag}, start {rec.starts}, "
                      f"status {rec.status})\n{tail(rec.text)}", flush=True)
        return "; ".join(why), True

    def scenario(self, sc: Scenario) -> str:
        """PASS, FAIL or NOT-MEASURED for the scenario on the library under test."""
        reference, subject = self.libs[REFERENCE], self.libs[LIBRARY]
        if self.control:
            why, _ = self.attempt(sc, {"subject": REFERENCE, "peer": REFERENCE}, "control")
            self.line(sc, reference, "PASS" if not why else f"FAIL: {why}")
            if why:
                self.line(sc, subject, f"NOT-MEASURED: the control did not pass, so the host cannot carry it ({why})")
                return "NOT-MEASURED"
        why, measured = self.attempt(sc, {"subject": LIBRARY, "peer": REFERENCE}, "subject")
        if not why:
            self.line(sc, subject, "PASS")
            return "PASS"
        if not measured:
            self.line(sc, subject, f"NOT-MEASURED: {why}")
            return "NOT-MEASURED"
        self.line(sc, subject, f"FAIL: {why}")
        return "FAIL"

    def run(self, scenarios: list[Scenario]) -> int:
        tally = {"PASS": 0, "FAIL": 0, "NOT-MEASURED": 0}
        for sc in scenarios:
            tally[self.scenario(sc)] += 1
        subject = self.libs[LIBRARY]
        say(f"pico-upstream on {self.host.name} {self.host.width}: {tally['PASS']}/{len(scenarios)} scenario(s) "
            f"pass on {subject.label}; {tally['FAIL']} fail, {tally['NOT-MEASURED']} not measured"
            + ("" if self.control else " (no control was run)"))
        return 0 if tally["PASS"] == len(scenarios) else 1


def cmd_run(args: argparse.Namespace) -> int:
    zenohd = pathlib.Path(args.zenohd)
    if not zenohd.is_file():
        raise Refusal(f"no zenohd at {zenohd}")
    sets = [s for s in args.sets.split(",") if s] if args.sets else None
    only = [s for s in args.only.split(",") if s] if args.only else None
    scenarios = selected("windows" if args.package else "linux", sets, only)
    if args.package and sys.platform != "win32":
        raise Refusal("a package is run on a Windows host: its programs are compiled with MSVC's cl")
    # A process the run stopped can hold its log a moment longer on Windows; what is left is a
    # temporary directory's, not a verdict.
    with tempfile.TemporaryDirectory(prefix="pico-upstream-", ignore_cleanup_errors=True) as tmp:
        scratch = pathlib.Path(tmp)
        if args.package:
            subject, features, arch = package_library(pathlib.Path(args.package), scratch)
            host = Windows(pwp.ARCHES[arch][1], arch)
        else:
            host = Linux()
            subject, features = host_library(args.host_library, scratch)
        reference = reference_library(host, features, scratch)
        return Runner(host, subject, reference, zenohd, scratch, not args.no_control).run(scenarios)


def cmd_list() -> int:
    for host in HOSTS:
        for sc in selected(host, None, None):
            peer = f" with {sc.peer.program}" if sc.peer else ""
            print(f"{host}: {sc.id}{peer}{'' if sc.router else ' (no router)'}")
    for path, why in sorted(NOT_RUN.items()):
        print(f"not run: {path}: {why}")
    return 0


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------


def selftest() -> int:
    ok = bad = 0

    def expect(name: str, cond: bool, detail: object = "") -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  pico-upstream selftest FAIL: {name} {detail}", file=sys.stderr)

    def refused(call) -> bool:
        try:
            call()
        except Refusal:
            return True
        return False

    findings = table_findings(PICO)
    expect("the table holds against the vendored tree", findings == [], findings)
    expect("the harness units exist", UNBUFFERED.is_file() and (MSVC_POSIX / "unistd.h").is_file())
    expect("every API test the integration lane runs is run here",
           {p.name for p in PROGRAM_LIST if p.set == "tests"} == set(ALONE_TESTS) | set(ROUTED_TESTS)
           and len(ALONE_TESTS) + len(ROUTED_TESTS) == 13)
    expect("a routed test is handed the router as its one argument and the others none",
           all((sc.subject.args == (ROUTER,)) == sc.router for sc in SCENARIOS if PROGRAMS[sc.subject.program].set
               == "tests"))
    expect("the proxy is the two tests upstream's Unix arm links it to",
           {p.name for p in PROGRAM_LIST if p.proxy} == set(PROXIED_TESTS))

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        for rel in ("examples/unix/c11/z_sub.c", "examples/windows/z_new.c", "tests/z_api_x_test.c",
                    "tests/z_other_test.c"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("int main(void) { return 0; }\n", encoding="utf-8")
        expect("the population is the examples and the API tests, nothing else",
               population(root) == {"examples/unix/c11/z_sub.c", "examples/windows/z_new.c", "tests/z_api_x_test.c"})
        found = table_findings(root)
        expect("a program upstream adds is a finding until it is placed",
               any("examples/windows/z_new.c is a program of zenoh-pico" in f for f in found), found)
        expect("a program named here that the tree lacks is a finding",
               any("examples/unix/c11/z_pub.c is named here and is no program" in f for f in found))
        expect("an empty tree is a finding, never a pass", table_findings(root / "none") != [])

    expect("the sets are read off the directories",
           set_of("tests/z_api_bytes_test.c") == "tests" and set_of("examples/unix/c11/z_sub.c") == "c11"
           and set_of("examples/unix/c99/z_sub.c") == "c99" and set_of("examples/windows/z_sub.c") == "windows")
    expect("a directory of no set is refused", refused(lambda: set_of("examples/zephyr/z_sub.c")))
    expect("Linux does not run zenoh-pico's Windows programs",
           all(PROGRAMS[sc.subject.program].set != "windows" for sc in selected("linux", None, None)))
    expect("Windows runs all four sets",
           {PROGRAMS[sc.subject.program].set for sc in selected("windows", None, None)} == set(SETS))
    expect("a set the host does not run is refused", refused(lambda: selected("linux", ["windows"], None)))
    expect("an unknown id is refused", refused(lambda: selected("linux", None, ["c11/z_nothing"])))
    expect("an id narrows to its one scenario",
           [sc.id for sc in selected("windows", None, ["c99/z_sub"])] == ["c99/z_sub"])

    text = ('a\nz_encoding_from_substr(&e4, "custom_id;custom_schema", 16);\n'
            '    assert(z_internal_encoding_check(&e2));\n')
    expect("the correction replaces its one line",
           "check(&e4));" in corrected(text, ENCODING_CHECKS_E4, "t") and "check(&e2));" not in
           corrected(text, ENCODING_CHECKS_E4, "t"))
    expect("a correction found twice is refused",
           refused(lambda: corrected(text + text, ENCODING_CHECKS_E4, "t")))
    expect("a correction not found is refused", refused(lambda: corrected("a\n", ENCODING_CHECKS_E4, "t")))
    vendored = PICO / "tests" / "z_api_encoding_test.c"
    expect("the vendored encoding test has the corrected line once",
           vendored.is_file() and not refused(lambda: corrected(vendored.read_text(encoding="utf-8"),
                                                                ENCODING_CHECKS_E4, "z_api_encoding_test")))
    expect("no correction leaves the text as it is", corrected("x", None, "t") == "x")

    expect("line ends are made LF", normalized(b"a\r\nb\n") == "a\nb\n")
    expect("nm's undefined names, a versioned one read as its name",
           nm_imports("                 U z_open\n                 U __libc_start_main@GLIBC_2.34\n")
           == {"z_open", "__libc_start_main"})
    listing = ("Dump of file z_sub.exe\n\n  Section contains the following imports:\n\n    wz_capi_pico.dll\n"
               "             140012000 Import Address Table\n\n                           1A z_open\n"
               "                          2B z_open_options_default\n\n    KERNEL32.dll\n"
               "                          5E4 Sleep\n\n  Summary\n\n        1000 .data\n")
    expect("dumpbin's imports by name", dumpbin_imports(listing) == {"z_open", "z_open_options_default", "Sleep"},
           dumpbin_imports(listing))
    expect("a longer name is not z_open", "z_open" not in dumpbin_imports("                  2B z_open_x\n"))
    expect("the reference's switches in name order",
           reference_flags({"Z_FEATURE_B": 0, "Z_FEATURE_A": 1}) == ["-DZ_FEATURE_A=1", "-DZ_FEATURE_B=0"])
    header = "#define Z_FEATURE_A 1\n#define Z_FEATURE_B 0\n"
    expect("a switch the header states as asked is not refused",
           refused_switches({"Z_FEATURE_A": 1, "Z_FEATURE_B": 0}, header) == [])
    expect("a switch the header states otherwise is refused",
           refused_switches({"Z_FEATURE_A": 0, "Z_FEATURE_B": 1}, header) == ["Z_FEATURE_A", "Z_FEATURE_B"])

    sc = Scenario(Proc("examples/unix/c11/z_get.c", E), Proc("examples/unix/c11/z_queryable.c", E, ends=False),
                  witnesses=(("subject", GOT_REPLY), ("peer", GOT_QUERY)))
    good = [Record("peer", sc.peer, None, " >> [Queryable handler] Received Query 'demo/example/**'\n"),
            Record("subject", sc.subject, 0, ">> Received PUT ('demo/example/zenoh-pico-queryable': 'x')\n")]
    expect("the peer first unless the scenario says the subject", [r for r, _ in order_of(sc)] == ["peer", "subject"])
    expect("a pair that says the subject starts with it",
           [r for r, _ in order_of(Scenario(sc.subject, sc.peer, first="subject"))] == ["subject", "peer"])
    lone = Scenario(Proc("examples/unix/c11/z_info.c", E), witnesses=(("subject", ROUTER_ID),))
    expect("a lone subject that names no first holds and starts alone",
           scenario_findings(lone) == [] and [r for r, _ in order_of(lone)] == ["subject"], scenario_findings(lone))
    expect("a lone subject that names a first orders a pair it does not have",
           any("orders a pair it does not have" in f
               for f in scenario_findings(Scenario(lone.subject, first="peer", witnesses=lone.witnesses))))
    expect("a first that is neither role is a finding",
           any("neither its subject nor its peer" in f for f in scenario_findings(Scenario(sc.subject, sc.peer,
                                                                                            first="router"))))
    expect("a pair as the table writes it holds", scenario_findings(sc) == [], scenario_findings(sc))
    expect("a pair that ended as it should with every witness passes", judge(sc, good, 1.0) == [],
           judge(sc, good, 1.0))

    def changed(index: int, **kw) -> list[Record]:
        out = [Record(r.role, r.proc, r.status, r.text) for r in good]
        for key, value in kw.items():
            setattr(out[index], key, value)
        return out

    expect("a one-shot that did not end is red",
           any("did not end" in w for w in judge(sc, changed(1, status=None), 1.0)))
    expect("a one-shot that exited non-zero is red", any("exited 3" in w for w in judge(sc, changed(1, status=3), 1.0)))
    expect("a server that exited before it was stopped is red",
           any("before it was stopped" in w for w in judge(sc, changed(0, status=0), 1.0)))
    expect("a missing witness is red", any("the subject printed no line" in w
                                          for w in judge(sc, changed(1, text="nothing\n"), 1.0)))
    expect("a witness printed by the other process does not count",
           any("the peer printed no line" in w for w in judge(sc, changed(0, text=good[1].text), 1.0)))
    expect("a stub main is red even with a clean exit",
           any("stub main" in w for w in judge(sc, changed(1, text=good[1].text + STUB_MARKERS[0] + "\n"), 1.0)))
    expect("the router id is read across its line",
           not missing_witnesses(Scenario(Proc("examples/windows/z_info.c"), witnesses=(("subject", ROUTER_ID),)),
                                 {"subject": "Own ID: 01ab\nRouters IDs:\n 9f8e7d\nPeers IDs:\n"}))
    expect("a rate of the throughput pair", re.search(RATES, "x\n1234.567\n", re.M) is not None
           and re.search(RATES, "0.5\n", re.M) is None)
    print(f"  pico-upstream selftest: {ok}/{ok + bad} arm(s) pass")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="zenoh-pico's own programs on a pico C ABI library",
                                     usage=__doc__.split("\n\n")[1])
    parser.add_argument("--package")
    parser.add_argument("--host-library")
    parser.add_argument("--zenohd")
    parser.add_argument("--sets")
    parser.add_argument("--only")
    parser.add_argument("--no-control", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.selftest:
            return selftest()
        if args.list:
            return cmd_list()
        if bool(args.package) == bool(args.host_library) or not args.zenohd:
            print(__doc__, file=sys.stderr)
            return 2
        return cmd_run(args)
    except (Refusal, pwp.Refusal) as err:
        print(f"  pico-upstream REFUSED: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

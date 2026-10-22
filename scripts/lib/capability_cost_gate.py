#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3397 (no register item) -- what a capability costs, and that a build without it pays nothing.

## Why this exists

The C ABI crates are composed from capability features (`peer`, `scout`, `link-udp`, `query`,
...): a build that leaves one out is supposed to link neither the ABI doors nor the runtime plane
behind them. That is a claim about the BINARY, and nothing graded the binary. It broke without a
word once already: the node-clock feature (`time-hlc`) pulled the runtime's storage module, which
pulled the whole query plane, into a build that answered no query. It was found by reading a
symbol table by hand, and the same hand-reading found that `peer` alone did not compile, because
the accept loop had been getting its request codec from that same leak.

This gate reads the binary. For each case in [`CASES`] it builds the library with exactly that
feature set and checks four facts about it:

  1. SIZE        the text segment (`size`) is within the case's budget;
  2. ABSENCE     no defined symbol matches a FORBIDDEN pattern: the plane the case left out;
  3. PRESENCE    a symbol matches every REQUIRED pattern: the plane the case put in;
  4. EXPORTS     the library exports the pinned number of C symbols, where one is pinned.

PRESENCE is what makes ABSENCE mean something. A forbidden pattern that no build can match is a
check that cannot fail (`--selftest` pins the matcher, and the full builds here are the live
control: every pattern a client build is forbidden is REQUIRED of a build that has the plane).

## What a budget is, and is not

A budget is a ceiling a measured size sits under with a small margin, not a target. It moves in
the commit that moves the size, with the new measurement stated; a size that grew without anyone
choosing it is what this gate exists to refuse. The sizes are `size` text on the pinned toolchain
(`rust-toolchain.toml`) and are comparable only to themselves: a different compiler moves them,
which is why the margin is a percentage and not a byte count.

Usage:
    capability_cost_gate.py --check [ID...]    build every case (or the named ones), grade it
    capability_cost_gate.py --measure [ID...]  build the same and print what was measured
    capability_cost_gate.py --selftest     grade the grader on synthetic input
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
TARGET = CRATES / "target" / "release"

PICO_BASE = "serial-drive-own-thread,rx-busy-poll"

# Planes a build without the capability must not carry, as demangled-symbol patterns. The same
# patterns are REQUIRED of a build that has the capability.
ACCEPT = r"accept_loop::(accept_any|accept_loop_|AcceptEvent|SpawnedFaces|next_spawned)"
RESPONDER = r"scouting_responder|ScoutingResponder"
SCOUTING = r"scouting_glue|scouting_fanout|ScoutFanOut"
GOSSIP = r"gossip_plane|GossipPlane"
UDP = r"udp_pipeline|UdpDriver|udp_writer"
CLOCK = r"uhlc|NodeClock"
ADVANCED = r"advanced_publisher|AdvancedPublisher"
# pico's two header arms (`multi-thread`): each exports doors the other must not. A build
# without the capability is the single-threaded arm, so the two are each other's absence.
THREADED = r"^(z_mutex_init|zp_start_read_task)$"
SINGLE_THREADED = r"^(zp_spin_once|zp_read)$"


@dataclass(frozen=True)
class Case:
    id: str
    package: str
    lib: str
    features: str | None  # None: the crate's default features
    max_text: int
    forbid: tuple[str, ...] = ()
    require: tuple[str, ...] = ()
    exports: int | None = None
    note: str = field(default="", compare=False)


# Budgets are the measured text plus about two percent. See the module doc.
CASES: tuple[Case, ...] = (
    Case("pico-client", "wz-capi-pico", "libwz_capi_pico.so", PICO_BASE, 1_915_000,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, THREADED),
         require=(SINGLE_THREADED,),
         note="a single-threaded pub/sub client that dials TCP: no listener, no scouting, "
              "no UDP, no clock"),
    Case("pico-client-udp", "wz-capi-pico", "libwz_capi_pico.so", PICO_BASE + ",link-udp", 1_975_000,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED),
         require=(UDP, SINGLE_THREADED)),
    Case("pico-peer", "wz-capi-pico", "libwz_capi_pico.so", PICO_BASE + ",peer", 3_100_000,
         forbid=(GOSSIP, CLOCK, ADVANCED, THREADED),
         require=(ACCEPT, RESPONDER, SCOUTING, UDP, SINGLE_THREADED),
         note="peer implies scout and with it the UDP group"),
    Case("pico-default", "wz-capi-pico", "libwz_capi_pico.so", None, 4_030_000,
         forbid=(SINGLE_THREADED,),
         require=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, THREADED),
         exports=802,
         note="every capability on: the symbol count is the drop-in's. 809 -> 802 when the "
              "seven single-threaded entry points left the multi-threaded arm"),
    Case("capic-client", "wz-capi-c", "libwz_capi_c.so", "", 3_000_000,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED)),
    Case("capic-scout", "wz-capi-c", "libwz_capi_c.so", "scout", 3_275_000,
         forbid=(ACCEPT, RESPONDER, GOSSIP, CLOCK, ADVANCED), require=(SCOUTING, UDP)),
    Case("capic-peer", "wz-capi-c", "libwz_capi_c.so", "peer", 4_065_000,
         forbid=(GOSSIP, CLOCK, ADVANCED), require=(ACCEPT, RESPONDER, SCOUTING, UDP)),
    Case("capic-default", "wz-capi-c", "libwz_capi_c.so", None, 9_045_000,
         require=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED), exports=835,
         note="zenoh-c's default links and pubkey auth (rustls on ring, quinn, tungstenite, "
              "rsa): 8,866,359 measured, up from about 5.1 MB without them"),
)


@dataclass
class Measured:
    text: int
    symbols: list[str]  # demangled names of the defined symbols
    exports: int


def grade(case: Case, got: Measured) -> list[str]:
    """The findings for one case; empty when it passes. Pure, so the selftest can drive it."""
    findings: list[str] = []
    if got.text > case.max_text:
        findings.append(
            f"{case.id}: text is {got.text} bytes, over its budget of {case.max_text} "
            f"({got.text - case.max_text} over). Either the size grew without anyone choosing it "
            f"(find what linked in: nm -C --size-sort), or the growth is the point and the "
            f"budget moves in this commit with the new measurement stated."
        )
    for pattern in case.forbid:
        hits = [s for s in got.symbols if re.search(pattern, s)]
        if hits:
            findings.append(
                f"{case.id}: {len(hits)} symbol(s) match `{pattern}`, a plane this build leaves "
                f"out (first: {hits[0][:140]}). Something the feature set does not name is "
                f"pulling it in."
            )
    for pattern in case.require:
        if not any(re.search(pattern, s) for s in got.symbols):
            findings.append(
                f"{case.id}: no symbol matches `{pattern}`, a plane this build has. Either the "
                f"build lost the capability or the pattern can no longer match, and an absence "
                f"check built on it grades nothing."
            )
    if case.exports is not None and got.exports != case.exports:
        findings.append(
            f"{case.id}: exports {got.exports} C symbols, pinned at {case.exports}. A symbol "
            f"was added or lost in the build every consumer links."
        )
    return findings


def build(case: Case) -> Measured:
    cmd = ["cargo", "build", "--release", "-p", case.package, "--quiet"]
    if case.features is not None:
        cmd += ["--no-default-features"]
        if case.features:
            cmd += ["--features", case.features]
    subprocess.run(cmd, cwd=CRATES, check=True)
    lib = TARGET / case.lib
    size_out = subprocess.run(["size", str(lib)], capture_output=True, text=True, check=True).stdout
    text = int(size_out.splitlines()[1].split()[0])
    names = subprocess.run(
        ["nm", "-C", "--defined-only", str(lib)], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    symbols = [line.split(" ", 2)[2] for line in names if line.count(" ") >= 2]
    dynamic = subprocess.run(
        ["nm", "-D", "--defined-only", str(lib)], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    exports = sum(1 for line in dynamic if len(line.split()) == 3 and line.split()[1] == "T")
    return Measured(text=text, symbols=symbols, exports=exports)


def cmd_check(measure_only: bool, only: list[str]) -> int:
    unknown = [i for i in only if i not in {c.id for c in CASES}]
    if unknown:
        print(f"  capability-cost: no such case: {unknown}", file=sys.stderr)
        return 2
    rc = 0
    for case in CASES:
        if only and case.id not in only:
            continue
        got = build(case)
        print(f"  capability-cost: {case.id}: text {got.text} of {case.max_text} "
              f"({100 * got.text // case.max_text}%), {got.exports} exports")
        if measure_only:
            continue
        for finding in grade(case, got):
            print(f"  capability-cost FAIL: {finding}", file=sys.stderr)
            rc = 1
    if rc == 0 and not measure_only:
        print(f"  capability-cost: {len(only) or len(CASES)} case(s) within budget, absent where absent, "
              f"present where present")
    return rc


def cmd_selftest() -> int:
    ok = 0
    bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  capability-cost selftest FAIL: {name}", file=sys.stderr)

    case = Case("t", "p", "l", "", 1000, forbid=(ACCEPT,), require=(UDP,), exports=3)
    clean = Measured(text=900, symbols=["wz::udp_pipeline::wire", "wz::other"], exports=3)
    expect("a build inside every bound passes", grade(case, clean) == [])
    expect("a size over budget is a finding",
           len(grade(case, Measured(1001, clean.symbols, 3))) == 1)
    expect("a size AT the budget passes", grade(case, Measured(1000, clean.symbols, 3)) == [])
    leaked = Measured(900, clean.symbols + ["wz::accept_loop::accept_any"], 3)
    expect("a DialIntent a scouting build keeps is not the accept loop",
           grade(case, Measured(900, clean.symbols + ["wz::accept_loop::DialIntent"], 3)) == [])
    expect("a forbidden plane that is present is a finding", len(grade(case, leaked)) == 1)
    lost = Measured(900, ["wz::other"], 3)
    expect("a required plane that is absent is a finding", len(grade(case, lost)) == 1)
    expect("a wrong export count is a finding", len(grade(case, Measured(900, clean.symbols, 4))) == 1)
    expect("an unpinned export count is not graded",
           grade(Case("t", "p", "l", "", 1000), Measured(900, [], 99)) == [])
    # The control that keeps ABSENCE honest: every pattern a case forbids is required by some
    # case in the table, so a forbidden pattern that no build can match cannot stay unnoticed.
    required = {p for c in CASES for p in c.require}
    forbidden = {p for c in CASES for p in c.forbid}
    expect("every forbidden pattern is required of a build that has the plane",
           forbidden <= required)
    expect("case ids are unique", len({c.id for c in CASES}) == len(CASES))
    expect("a patterned plane's own symbol matches its pattern",
           all(re.search(p, s) for p, s in (
               (ACCEPT, "wz_runtime_tokio::accept_loop::accept_loop_offering_spawned"),
               (RESPONDER, "ScoutingResponder::new"),
               (SCOUTING, "wz_runtime_tokio::scouting_glue::drive"),
               (GOSSIP, "wz_runtime_tokio::gossip_plane::GossipPlane"),
               (UDP, "wz_runtime_tokio::udp_pipeline::wire_udp_socket"),
               (CLOCK, "uhlc::HLC::new_timestamp"),
               (ADVANCED, "wz_runtime_tokio::advanced_publisher::put"))))
    print(f"  capability-cost selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("--check", "--measure", "--selftest") or (
        argv[1] == "--selftest" and len(argv) != 2
    ):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return cmd_selftest()
    return cmd_check(measure_only=argv[1] == "--measure", only=argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))

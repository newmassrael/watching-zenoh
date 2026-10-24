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

## The denominator

A pico case is also measured against zenoh-pico built as the SAME build: the pinned submodule,
Release and shared, with every switch `deploy/wz-config.toml` answers set from that answer for
the case's features (`wz_config.pico_reference`). The gate builds it on the host it builds wz on,
reads back the header pico generated to find any switch pico built otherwise than asked, and
prints the ratio. The ratio is printed, not graded: the text budget already holds wz's size, and
what this adds is that a size claim against pico is a number this gate printed, with its
toolchain beside it, and never one copied from elsewhere. Rounds 3393 to 3395 divided by a
libzenohpico of unrecorded build; round 3472 corrected them with a reference whose switches were
chosen by hand, and three of them (interest, matching, the receive cache) were set otherwise
than the declaration says wz has them.

Usage:
    capability_cost_gate.py --check [ID...]    build every case (or the named ones), grade it
    capability_cost_gate.py --measure [ID...]  build the same and print what was measured
    capability_cost_gate.py --selftest     grade the grader on synthetic input
"""

from __future__ import annotations

import hashlib
import io
import os
import pathlib
import re
import subprocess
import sys
import tarfile
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wz_config  # noqa: E402  (the one declaration, and its resolver)

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
PICO_SOURCE = ROOT / "vendor" / "zenoh-pico"
# The reference builds, one directory per (pin, switches, toolchain), so a run that asks for the
# same build again reads it instead of building it.
PICO_BUILDS = CRATES / "target" / "pico-reference"
# A case's library is under the directory of the cargo profile it was built with.
TARGET = CRATES / "target"

PICO_BASE = "engine-tokio,serial-drive-own-thread,rx-busy-poll"

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
# pico's connectivity plane (`connectivity`), which the default build has and a build of
# upstream's default header does not.
CONNECTIVITY = r"^(z_info_transports|z_declare_transport_events_listener)$"
# The multicast transport (`multicast-transport`, open-debt item 913): the group face and its
# pipeline, which pico's default build has (`Z_FEATURE_MULTICAST_TRANSPORT`) and zenoh-c's too.
MULTICAST = r"multicast_glue|multicast_pipeline|MulticastLinkDriver"
# The engine a pico build runs its sessions on (`engine-tokio` / `engine-coop`,
# docs/capi-pico-on-coop-engine.md): a build of one links none of the other.
TOKIO_ENGINE = r"wz_capi_core::|wz_runtime_tokio::"
COOP_ENGINE = r"wz_capi_coop::"


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
    # The cargo profile (`crates/Cargo.toml`). It is not a capability, so it leaves the pico
    # reference alone: that is derived from the features only.
    profile: str = "release"
    note: str = field(default="", compare=False)


# Budgets are the measured text plus about two percent. See the module doc.
CASES: tuple[Case, ...] = (
    Case("pico-client", "wz-capi-pico", "libwz_capi_pico.so", PICO_BASE, 1_830_000,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, THREADED,
                 CONNECTIVITY, MULTICAST, COOP_ENGINE),
         require=(SINGLE_THREADED, TOKIO_ENGINE),
         note="a single-threaded pub/sub client that dials TCP: no listener, no scouting, "
              "no UDP, no clock, no unstable API. 1,794,085 measured, down from 1,868,267 "
              "with the unstable API and the connectivity plane"),
    Case("pico-client-small", "wz-capi-pico", "libwz_capi_pico.so", PICO_BASE, 1_498_000,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, THREADED,
                 CONNECTIVITY, MULTICAST),
         require=(SINGLE_THREADED,), profile="capi-small",
         note="the pico-client build with panics aborting: the like-for-like of zenoh-pico's C. "
              "1,468,134 measured against pico-client's 1,790,361 (-18.0%)"),
    Case("pico-client-udp", "wz-capi-pico", "libwz_capi_pico.so", PICO_BASE + ",link-udp", 1_892_000,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST),
         require=(UDP, SINGLE_THREADED)),
    # The same client on the cooperative engine: the program steps its session, and no runtime
    # thread or tokio is linked. Its links dial UDP in every build, so it is compared with the
    # pico that pico-client-udp is (`link-udp` names that here; it adds nothing to this build).
    Case("pico-client-coop", "wz-capi-pico", "libwz_capi_pico.so", "engine-coop,link-udp",
         880_000,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
         exports=443,
         note="the single-threaded client of pico-client-udp on the cooperative engine: "
              "865,723 measured against pico-client-udp's 1,867,697 (2.15 against 4.63 times "
              "the same pico). Its exports are pico-client's 441 and two that are not the C "
              "ABI's: `_critical_section_1_0_acquire` and `_release`, the std implementation "
              "the cooperative runtime's critical sections need, which rustc exports from a "
              "cdylib. The count drops to 441 when that runtime takes a hosted lock instead"),
    Case("pico-peer", "wz-capi-pico", "libwz_capi_pico.so", PICO_BASE + ",peer", 2_946_000,
         forbid=(GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY, MULTICAST),
         require=(ACCEPT, RESPONDER, SCOUTING, UDP, SINGLE_THREADED),
         note="peer implies scout and with it the UDP group"),
    Case("pico-default", "wz-capi-pico", "libwz_capi_pico.so", None, 4_300_000,
         forbid=(SINGLE_THREADED,),
         require=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, THREADED,
                  CONNECTIVITY, MULTICAST),
         exports=802,
         note="every capability on: the symbol count is the drop-in's. 809 -> 802 when the "
              "seven single-threaded entry points left the multi-threaded arm. 4,216,542 "
              "measured with the multicast transport pico's default has (open-debt item 913), "
              "3,790,610 without it"),
    Case("capic-client", "wz-capi-c", "libwz_capi_c.so", "", 3_000_000,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, MULTICAST)),
    Case("capic-client-small", "wz-capi-c", "libwz_capi_c.so", "", 1_834_000,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, MULTICAST),
         profile="capi-small",
         note="the capic-client build with panics aborting: 1,797,992 measured against "
              "capic-client's 2,172,515 (-17.2%)"),
    Case("capic-scout", "wz-capi-c", "libwz_capi_c.so", "scout", 3_275_000,
         forbid=(ACCEPT, RESPONDER, GOSSIP, CLOCK, ADVANCED, MULTICAST),
         require=(SCOUTING, UDP)),
    Case("capic-peer", "wz-capi-c", "libwz_capi_c.so", "peer", 4_065_000,
         forbid=(GOSSIP, CLOCK, ADVANCED, MULTICAST), require=(ACCEPT, RESPONDER, SCOUTING, UDP)),
    Case("capic-default", "wz-capi-c", "libwz_capi_c.so", None, 9_210_000,
         require=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, MULTICAST),
         exports=835,
         note="zenoh-c's default links and pubkey auth (rustls on ring, quinn, tungstenite, "
              "rsa): 8,866,359 measured, up from about 5.1 MB without them; 9,029,823 with "
              "the multicast transport (open-debt item 913)"),
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
    cmd = ["cargo", "build", "--profile", case.profile, "-p", case.package, "--quiet"]
    if case.features is not None:
        cmd += ["--no-default-features"]
        if case.features:
            cmd += ["--features", case.features]
    subprocess.run(cmd, cwd=CRATES, check=True)
    lib = TARGET / case.profile / case.lib
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


@dataclass(frozen=True)
class Reference:
    """zenoh-pico built as the same build as a case: its text, the pin it was built from, the
    toolchain, and the switches pico built otherwise than asked."""

    text: int
    pin: str
    toolchain: str
    refused: tuple[str, ...]


def case_features(case: Case) -> set[str]:
    """The features of the case's package its build turns on, as cargo resolves them."""
    feats = wz_config.manifest_features(CRATES / case.package / "Cargo.toml")
    start = ["default"] if case.features is None else [f for f in case.features.split(",") if f]
    return wz_config.enabled_features(feats, start)


def first_line(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()[0]


def run_quiet(cmd: list[str]) -> None:
    """Run a build step with its output held, and show the end of it if the step fails: a
    reference that could not be built is a failure of this gate, and it says why."""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-20:])
        raise RuntimeError(f"`{' '.join(cmd)}` exited {proc.returncode}:\n{tail}")


def refused_switches(asked: dict[str, int], header: str) -> list[str]:
    """The switches pico's generated header states otherwise than `asked`: pico's CMake turns
    some off when another is off (matching without interest, scouting without the UDP unicast
    link), and a reference that silently differs from the build it stands for is the defect this
    gate's denominator exists to remove."""
    on, _ = wz_config.pico_flag_states(header)
    return sorted(s for s, v in asked.items() if (s in on) != bool(v))


def pico_reference_build(asked: dict[str, int]) -> Reference:
    """Build zenoh-pico with `asked` set, from an export of the pinned submodule (pico's CMake
    writes a header into its source tree, which must not dirty the submodule), and measure it."""
    pin = subprocess.run(["git", "-C", str(PICO_SOURCE), "rev-parse", "HEAD"], capture_output=True,
                         text=True, check=True).stdout.strip()
    toolchain = f"{first_line(['cc', '--version'])}; {first_line(['cmake', '--version'])}"
    flags = [f"-D{s}={v}" for s, v in sorted(asked.items())]
    key = hashlib.sha256("\n".join([pin, toolchain, *flags]).encode()).hexdigest()[:16]
    work = PICO_BUILDS / key
    lib = work / "build" / "lib" / "libzenohpico.so"
    if not lib.exists():
        archive = subprocess.run(["git", "-C", str(PICO_SOURCE), "archive", "--format=tar", "HEAD"],
                                 capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(work / "src", filter="data")
        run_quiet(["cmake", "-S", str(work / "src"), "-B", str(work / "build"),
                   "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                   "-DBUILD_EXAMPLES=OFF", "-DBUILD_TESTING=OFF", *flags])
        run_quiet(["cmake", "--build", str(work / "build"), "--parallel", str(os.cpu_count() or 1)])
    header = (work / "build" / "include" / "zenoh-pico" / "config.h").read_text()
    size_out = subprocess.run(["size", str(lib)], capture_output=True, text=True, check=True).stdout
    return Reference(text=int(size_out.splitlines()[1].split()[0]), pin=pin[:12],
                     toolchain=toolchain, refused=tuple(refused_switches(asked, header)))


def report_reference(case: Case, got: Measured) -> None:
    """Print the case's size against zenoh-pico built as the same build. Only the pico ABI's
    cases have one here: zenoh-c's original is a Rust build of its own the lanes that install the
    oracle provision, and this lane does not."""
    if case.package != "wz-capi-pico":
        print(f"  capability-cost: {case.id}: no same-build reference in this lane (zenoh-c's is "
              f"provisioned only where the oracle is installed)")
        return
    asked = wz_config.pico_reference(wz_config.load_decl(), case_features(case))
    ref = pico_reference_build(asked)
    print(f"  capability-cost: {case.id}: zenoh-pico {ref.pin} as the same build: text "
          f"{ref.text}; wz is {got.text / ref.text:.2f} times it ({ref.toolchain})")
    if ref.refused:
        print(f"  capability-cost: {case.id}: pico built {', '.join(ref.refused)} otherwise than "
              f"asked, so the two builds differ there")


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
        report_reference(case, got)
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
               (ADVANCED, "wz_runtime_tokio::advanced_publisher::put"),
               (UDP, "wz_runtime_coop::udp_link::UdpDriver<S> as Drop>::drop"),
               (TOKIO_ENGINE, "wz_capi_core::faces::SharedSession::publish_on_wire_all"),
               (COOP_ENGINE, "wz_capi_coop::engine::CoopEngine<L,C>::open"))))
    # The denominator's own check: a switch pico built otherwise than asked is named, both ways.
    asked = {"Z_FEATURE_MATCHING": 1, "Z_FEATURE_INTEREST": 0, "Z_FEATURE_QUERY": 0}
    expect("a reference built as asked differs nowhere",
           refused_switches(asked, "#define Z_FEATURE_MATCHING 1\n#define Z_FEATURE_INTEREST 0\n"
                                   "#define Z_FEATURE_QUERY 0\n") == [])
    expect("a switch pico turned off, or on, against the ask is named",
           refused_switches(asked, "#define Z_FEATURE_MATCHING 0\n#define Z_FEATURE_INTEREST 0\n"
                                   "#define Z_FEATURE_QUERY 1\n")
           == ["Z_FEATURE_MATCHING", "Z_FEATURE_QUERY"])
    expect("a case's features are its package's as cargo resolves them",
           {"serial-drive-own-thread", "rx-busy-poll"}
           <= case_features(next(c for c in CASES if c.id == "pico-client"))
           and "peer" in case_features(next(c for c in CASES if c.id == "pico-default")))
    # A profile is a compile property, not a capability: a case that differs from another only in
    # its profile must be divided by the same pico, or the ratio moves from both sides at once.
    by_id = {c.id: c for c in CASES}
    expect("a profile twin has its base case's features, and so its pico reference",
           all(case_features(by_id[small]) == case_features(by_id[base])
               for small, base in (("pico-client-small", "pico-client"),
                                   ("capic-client-small", "capic-client"))))
    expect("every case's profile is one crates/Cargo.toml defines",
           {c.profile for c in CASES} <= {"release"} | set(
               re.findall(r"^\[profile\.([\w-]+)\]", (CRATES / "Cargo.toml").read_text(), re.M)))
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

#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The host performance matrix of the pico C ABI (docs/pico-perf-matrix.md): round trip, throughput,
CPU and peak RSS of `perf_probe.c` built against libwz_capi_pico (arm W), against zenoh-pico built
as the same build (arm P) and, when the environment names one, against an external library of the pico
API (arm X), per transport and with batching off and on; and the gate that holds a run's cells to their
committed rows.

`scripts/pico-compare.sh perf` builds the arms and runs this; the subcommands are its steps.

    perf_matrix.py bench-stdlib [STDLIB]
        the standard library arm W is built with: STDLIB (std or nostd, PICO_CMP_STDLIB) when given, to
        compare the two forms, else the one form the pico C ABI's release ships
        (`pico_windows_package.RELEASE_STDLIBS`), so a run reads what ships unless told another
    perf_matrix.py reference --out DIR --engine ENGINE --stdlib STDLIB
        zenoh-pico built as the same build as wz-capi-pico for zenoh-pico's preset
        (configs/zenoh-pico_defconfig, `wz_config.preset_features`) on ENGINE (tokio or coop, what
        `wz_config.py --bench-engine` resolved) with STDLIB (`bench-stdlib`): the build the capability
        cost gate measures
        (`capability_cost_gate.pico_reference_tree` under the gate's `build_env`, its switches from
        `wz_config.pico_reference`), linked and compiled as the gate builds the reference of arm W's form
        (`capability_cost_gate.reference_build` of the linker arguments of arm W's build, SHAPE_CASES:
        without `std`, C with no unwind tables and the script that discards the rest), its library copied
        to DIR/lib-P, its headers to DIR/include-P, and what both arms are built as (the reference's pin,
        toolchain, switches, linker arguments and C flags, the wz features and arm W's profile and
        configuration) to DIR/reference.json, the engine (`wz_engine`) and the standard library
        (`wz_stdlib`) among it, which the run's record and the gate read
    perf_matrix.py wz-arm --out DIR --arm ARM --engine ENGINE --stdlib STDLIB [--features F,...]
        arm ARM (W, or Wapp with app-transport), wz-capi-pico-lib: zenoh-pico's preset on ENGINE with STDLIB
        and the capabilities F over it (`wz_config.preset_named_features`), built as the size gate builds
        the case of that form
        (SHAPE_CASES, `capability_cost_gate.case_build` in the gate's `build_env`: its profile, its cargo
        configuration files, its linker), its library copied to DIR/lib-ARM and pico's headers to
        DIR/include-ARM: the reference export's (`reference` first), with the config.h of the build's
        feature list (`wz_config.pico_config_header`) in place of the reference's
    perf_matrix.py preset-arm --out DIR --original ORIGINAL --stdlib STDLIB
        arm W of the parity matrix's pico family (scripts/pico-compare.sh parity pico): wz-capi-pico-lib for
        configs/ORIGINAL_defconfig alone, its features and its limits and policies from the one resolver
        (`wz_config.configuration_of`, `capability_cost_gate.case_limits`), with STDLIB (`bench-stdlib`), built as
        the size gate builds the case of that form, as `wz-arm` builds its own; its library copied to
        DIR/lib-W, its log to DIR/build-wz.log, and two lines naming the build printed for the run's record
    perf_matrix.py pico-sys-include REPORT
        the include directory of the one zenoh-pico-sys build cargo's JSON REPORT names
    perf_matrix.py resident-text RESULT LIBRARY [ARM]
        the code of LIBRARY (the run's lib-W or lib-P copy) each role of arm ARM (W by default) held
        resident in the run whose perf.json is RESULT, made with PERF_SMAPS=1: the present pages of its
        executable mapping, named by the crate of each text symbol on them and by the planes a perf run
        never calls (docs/win-budget/rss.md, R3); for a library a run-text list laid out (its .text.run), the
        pages each role held outside the fault-around windows of that code, named by crate (section 5.4); exit 1
        when a role held any (a function the list does not place ran: the list is stale), 3 when the run printed
        no page map of it
    perf_matrix.py run-text LIBRARY SCRIPT TRACE...
        the functions of LIBRARY (the run's lib-W or lib-P copy) the callgrind profiles TRACE (a run with
        --trace-text) say ran, by the bytes of text they are and the fault-around windows they span laid
        out together, and for SCRIPT (crates/wz-capi-pico/link/run-text.ld; `-` writes nothing) the linker
        script's statement that lays them out together ahead of the rest of the text, its head kept
        (docs/win-budget/rss.md, section 5.4); exit 2 when an input was refused, 3 when no profile names a
        text symbol of LIBRARY. `scripts/pico-compare.sh run-text` runs the traced run and this for both arms
    perf_matrix.py run-text-order SCRIPT LISTING OUT
        lld-link's order file (`/ORDER:@OUT`) of the functions the run-text list SCRIPT places, made of the
        names a listing of a Windows link holds (LISTING: the last word of each line, as a list of names, `nm`
        and lld-link's `/lldmap` with `/demangle:no` write one), a name placed when its patterns are a line of
        the list whatever its hash (docs/win-budget/rss.md, section 5.4); exit 2 when an input was refused, 3
        when no name of LISTING is one the list places
    perf_matrix.py external-record OUT [WHY]
        the record of arm X written to OUT: with WHY, not measured for that reason; without, built from
        the library and the headers WZ_PERF_EXTERNAL_LIB and WZ_PERF_EXTERNAL_INCLUDE name (its label,
        WZ_PERF_EXTERNAL_NAME, and the digests of both, kept in the run's local result file only)
    perf_matrix.py run --bin-dir DIR --run DIR [--reps 3] [--sizes 8,64,1024] [--transports ...]
                       [--batching off,on] [--workloads rtt,thr] [--client-cpus 4-7] [--server-cpus 8-11]
                       [--pings 20000] [--warmup-ms 3000] [--window-s 5] [--timeout-ms 100]
                       [--reference-record FILE] [--external-record FILE] [--trace-text DIR]
        the matrix; DIR (--bin-dir) holds perf_probe_P, perf_probe_W and perf_probe_Wapp, and perf_probe_X
        when the external record says arm X was built. With --trace-text every probe runs under callgrind
        (TEXT_TRACE_TOOL), its profile written to DIR by cell, role and pid, for `run-text`: the figures of
        such a run are the tracer's, its record says so (`text_trace`) and the gate refuses it
    perf_matrix.py --gate RESULT [--table TABLE] [--external-table FILE] [--without-external]
        the gate over a run's perf.json: every cell of W over P held to its row of TABLE (by default the
        committed table of the run's platform, PLATFORMS: deploy/pico_perf_ceiling.json for a run on
        Linux, deploy/pico_perf_ceiling_windows.json for one on Windows, and a table of another platform,
        or of rows filled from arm W of another engine or another standard library, is refused), and W
        over X to the rows of the table outside the repository
        (--external-table, by default WZ_PERF_EXTERNAL_TABLE) when the run measured arm X. Exit 0 every
        row held, 1 a row failed, 2 an input refused, 3 nothing failed but a row or arm X was not
        measured (--without-external: a run without arm X is not that)
    perf_matrix.py --check-table TABLE
        the committed table's shape, and that its rows are the population of the default matrix
    perf_matrix.py windows-plan PACKAGE OUT
        the plan of a run on Windows (scripts/host-bench/windows/perf_matrix.ps1), written to OUT: arm W is
        the library of the Windows package PACKAGE (the zip pico_windows_package.py builds, without `std`
        as a release ships it unless built otherwise; its manifest's `stdlib` is recorded as the Linux
        reference records its own), verified against its manifest, and arm P zenoh-pico built as the
        same build, its switches derived from the package's features as `reference` derives them from the
        bench's build; arm W is planned as zenoh-pico's preset when the package's manifest says it is
        (`pico_windows_package.py --build OUT --preset zenoh-pico`), and a package that says so and is not
        the preset's build (its features, its conformance digest) is refused; with the figures, the
        reasons a cell is not applicable and the rules of a cell the runner applies, so the runner states
        none of its own. A package built from a commit whose inputs of that derivation differ from this
        tree's is refused
    perf_matrix.py idle-cpus [SECONDS] [PER_SIDE]
        each CPU's busy share over SECONDS (default 5) and its physical core, and a pinning of two sides of
        at least PER_SIDE (default 4) CPUs of whole cores, the least busy first, printed as the words
        `pico-compare.sh perf` reads; on a shared host a moment's idle CPUs are a guess the run's own
        validity check then grades
    perf_matrix.py pin-sides CLIENT_VAR=[CPUS] SERVER_VAR=[CPUS]
        the CPUs of the two sides of a pair, printed as `<client> <server> <how>` on one line: a side whose
        CPUS are given is used as given, a side whose CPUS are empty is chosen from this host's topology
        (topology_pinning: two whole physical cores a side, one when the host has too few, the core of CPU 0
        left to the system); exit 2 with the reason when a given CPU cannot be run on or the host has too few
        cores. `pico-compare.sh` calls it before a mode that pins builds or runs anything
    perf_matrix.py --selftest
        the readers, the figures and the pinning on synthetic input

A CELL is one arm, transport, batching, workload and payload size in one repetition. Its two programs are
started afresh, the server side (pong, sub) pinned to --server-cpus and the client side (ping, pub) to
--client-cpus, in peer mode:

  * tcp        the server listens on tcp/127.0.0.1:<port>, the client connects;
  * udp        the same over udp/127.0.0.1:<port>; arms W and X, since a zenoh-pico peer accepts streams
               only and arm P records the cell as not applicable (NOT_APPLICABLE says why); arm W only
               when its build has the udp/ listener (wz-capi-pico's udp-listen, which zenoh-pico's preset
               leaves off), and otherwise records the cell as not applicable (not_applicable); an external
               library is asked, and a cell it cannot open is its lost cell;
  * multicast  both listen on the group udp/224.0.0.224:<port>#iface=lo;
  * program    wz only (perf_probe_Wapp, built with the `app-transport` capability): every link goes
               over a transport the program supplies, an AF_UNIX stream of its own (perf_probe.c, -T);
               the pico API has no such door, so arms P and X record the cell as not applicable.

The client side of every cell declares its publisher a second after its open, as upstream's z_pub_thr
does, and on tcp, udp and the program transport puts nothing it counts until that publisher matches the
server side's subscriber (perf_probe.c -M): a zenoh-pico publisher that knows of no subscriber sends
nothing and still counts the put. Both arms run the same arguments. Built against wz, the probe states the
counts its roles hold on their session at once (perf_probe.c, PERF_WZ_ARM), past the few a session of the
pico ABI opens its tables at; the selftest counts the roles' declarations against them.

  * rtt  pong, then ping: --pings round trips of the size after --warmup-ms, each waited for up to
         --timeout-ms. Figures: the percentiles p50, p90 and p99 and the mean and extremes (microseconds),
         the round trips lost, the CPU of each side per round trip over its own active span, and of each
         process its whole CPU (user, system) and its peak RSS.
  * thr  sub, then pub: the publisher puts as fast as the session takes them; the subscriber reads its
         count over a --window-s window that starts --warmup-ms after its first sample. Figures: messages
         and payload bytes a second delivered in the window, the rate the publisher put, the CPU per
         message of each side (the publisher's over its loop per put, the subscriber's over the window per
         message delivered) and their sum, the puts not delivered, and the whole CPU and peak RSS of each
         process. A window that did not lie inside the publisher's loop (both read the one monotonic clock)
         is no rate. After its loop the publisher puts an end marker that carries its count of puts that
         answered success, and keeps its session until it is stopped; the subscriber says how many it had
         been handed when the first marker reached it, and it is given DRAIN_S to hand on its backlog first.
         On a reliable stream (STREAM_TRANSPORTS) a put under congestion control block is delivered or
         refused, so a marker that never came, or a count it was not handed, loses the cell (`delivery`):
         a library that answers success for a put it dropped has its puts' CPU spent on nothing.

A cell is VALID only when the pinned CPUs were used by nothing else while it ran (nodrop.py's rule: their
busy time less the CPU of the two processes, over the CPU seconds the cell had, at most 10 percent); a
disturbed cell is run again, up to six times, and a cell disturbed in all six is run once more after the
last repetition (`second_pass` in its record), since a shared host is busy in stretches. A cell whose
program did not give its figures is LOST with the reason, once: a transport an arm cannot open is a fact of
the arm, and running it again would only say so again. A throughput cell that delivered nothing says which
side stopped (`stall_note`: the publisher's lost match and peers, the subscriber's last growth). The order of the arms alternates by repetition (P W, W P, ...) so a drift of the host over
the run falls on both alike.

The run directory holds `cells.jsonl` (one line per cell, written as it ends), `perf.json` (the record,
the metrics and which way each is better, every cell, and the summary: per transport, batching, workload
and size, the median of each figure over the measured repetitions of each arm and W over P), `report.txt`
(the summary as text) and each program's output.

ARM X is a library of the pico API that this repository does not hold: a shared library and its headers
(its own config.h among them), named by WZ_PERF_EXTERNAL_LIB and WZ_PERF_EXTERNAL_INCLUDE, with the
optional WZ_PERF_EXTERNAL_NAME (a label) and WZ_PERF_EXTERNAL_CC_ARGS (words added to the probe's compile
and link). The same perf_probe.c is built against it. Its name, paths and figures stay in the run's local
files; with the variables unset, or a probe that did not build against it, the arm is NOT-MEASURED with
the reason, and it never passes in its place.

THE GATE (--gate) reads a cell of a pair (W over P, W over X) as the COST RATIO of one figure: wz's over
the reference's for a figure better when lower, the reference's over wz's for one better when higher, so
below 1 is wz ahead in every row. The ratio of the medians of the measured repetitions, with its bootstrap
95% interval (kit_compare.bootstrap_ratio), and the verdict of decision D1 of docs/upstream-parity.md:
WIN when the whole interval is below 1, LOSS when above, TIE otherwise. A row of the pair's table is
`{"locked": true}` (WIN only), `{"ratio_at_most": R}` (the upper end of the interval at most R, times
one plus the table's tolerance), `{"reference_lost": WHY}` (the reference lost every repetition, so the
cell has no ratio), or null (not filled: a failure that prints the row to paste). A cell with no row
fails: the population cannot grow without one. A WIN on a ratcheted row prints the edit that locks it, a
reading under the ratchet the tighter value, and the cells that are not WIN print as the debts, largest
ratio first (decision D10).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import inspect
import io
import json
import math
import os
import pathlib
import random
import re
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from nodrop import FOREIGN_LIMIT, MAX_RUNS, busy_seconds, cpu_list  # noqa: E402
from parity import BALLAST_MIB, CHILD_MIB, Lost, Process  # noqa: E402
from kit_compare import bootstrap_ratio  # noqa: E402
import elf_facts  # noqa: E402

SCHEMA = "wz-pico-perf/1"
TRANSPORTS = ("tcp", "udp", "multicast", "program")
WORKLOADS = ("rtt", "thr")
#: P zenoh-pico as the same build, W wz, X an external library of the pico API (when the environment names one).
ARMS = ("P", "W", "X")
DEFAULT_SIZES = (8, 64, 1024)
#: The seconds a server side is given before the client side starts.
SETTLE_S = 1.5
#: The seconds the publisher goes on putting after the subscriber's window should have ended.
PUB_TAIL_S = 3
#: The seconds a program waits for a peer before it gives up, and again for a match (perf_probe.c).
PEER_WAIT_S = 10
#: The seconds the client side waits after its open before it declares its publisher (perf_probe.c).
PREPARE_S = 1
#: The longest a client side can take before its first counted put.
READY_S = PREPARE_S + 2 * PEER_WAIT_S
GROUP = "224.0.0.224"
#: What a session of the program transport is told to listen on and to dial: the transport carries it,
#: no socket of the system's is opened for it (TEST-NET-1).
PROGRAM_LOCATOR = "tcp/192.0.2.1:7447"
#: The cells an arm has no such transport for, and why. A zenoh-pico peer listening on a udp/ unicast
#: locator binds the socket but its accept task takes streams only, so a peer dialling it never completes
#: its handshake (its open fails with _Z_ERR_TRANSPORT_RX_DURATION_EXPIRED, -120):
#: `vendor/zenoh-pico/src/transport/unicast/accept.c` @ `_z_tcp_accept(`
NOT_APPLICABLE = {
    ("P", "program"): "zenoh-pico has no transport a program supplies (zext_transport_* is wz's own door)",
    ("P", "udp"): "a zenoh-pico peer accepts streams only, so a udp/ listener answers no dialling peer "
                  "(its open fails with -120, the handshake's receive timeout)",
    ("X", "program"): "a library of the pico API has no transport a program supplies (zext_transport_* is "
                      "wz's own door)",
}
#: The wz-capi-pico feature that gives a peer its unicast udp/ listener. zenoh-pico's preset leaves it off
#: (configs/zenoh-pico_defconfig: CONFIG_WZ_CAP_UDP_LISTEN=n), as zenoh-pico's own peer has no such listener,
#: and a build without it refuses a udp/ endpoint to listen on (`IpLinks::open_listener`; the open fails with
#: -102): `crates/wz-capi-coop/src/tests.rs` @
#: `fn a_build_without_the_udp_listener_refuses_a_udp_endpoint_to_listen_on(`
UDP_LISTENER_FEATURE = "udp-listen"
W_UDP_WITHOUT_LISTENER = ("arm W's build has no udp/ listener (wz-capi-pico's udp-listen is off, as in zenoh-pico's "
                          "preset), so its server side refuses a udp/ endpoint to listen on (its open fails with "
                          "-102)")


def not_applicable(w_features) -> dict[tuple[str, str], str]:
    """The cells an arm has no such transport for, and why, for a run whose arm W is built with `w_features`
    (the wz-capi-pico features its build turns on, as cargo resolves them): NOT_APPLICABLE, and arm W's udp
    cells when that build has no udp/ listener (UDP_LISTENER_FEATURE)."""
    absent = dict(NOT_APPLICABLE)
    if UDP_LISTENER_FEATURE not in set(w_features):
        absent[("W", "udp")] = W_UDP_WITHOUT_LISTENER
    return absent

#: Every figure a cell can carry, and which way it is better. `perf.json` carries this table, so a reader
#: of the file needs nothing else to tell a gain from a loss.
METRICS = {
    "rtt_p50_us": "lower", "rtt_p90_us": "lower", "rtt_p99_us": "lower", "rtt_mean_us": "lower",
    "rtt_min_us": "lower", "rtt_max_us": "lower", "round_trips": "higher", "lost": "lower",
    "ping_cpu_ns_per_rtt": "lower", "pong_cpu_ns_per_rtt": "lower",
    "msgs_per_s": "higher", "bytes_per_s": "higher", "offered_msgs_per_s": "higher", "put_failed": "lower",
    "undelivered": "lower",
    "cpu_ns_per_msg_pub": "lower", "cpu_ns_per_msg_sub": "lower", "cpu_ns_per_msg": "lower",
    "cpu_user_s_client": "lower", "cpu_sys_s_client": "lower", "cpu_user_s_server": "lower",
    "cpu_sys_s_server": "lower", "rss_kib_client": "lower", "rss_kib_server": "lower", "rss_kib": "lower",
}

#: What a mapping of a probe's resident set is counted as (`smaps_class`), when the run asks with PERF_SMAPS=1
#: (perf_probe.c; docs/win-budget/rss.md, cell R0): the library of the arm, the C library, the loader, the
#: compiler's runtime, any other library, the program itself, the brk heap, the main thread's stack, every
#: anonymous mapping (the session's arena, the pools' pages, the other threads' stacks, a malloc arena), the
#: kernel's pages and the rest.
SMAPS_CLASSES = ("library", "libc", "loader", "libgcc_s", "other_libraries", "program", "heap", "stack",
                 "anonymous", "kernel", "other")
#: The figures of the rollup each probe prints, summed over a cell's two processes as `smaps_rollup_<key>`.
SMAPS_ROLLUP_KEYS = ("rss_kib", "pss_kib", "anonymous_kib", "private_dirty_kib")
#: The libraries a matrix arm is: wz's pico C library and zenoh-pico.
SMAPS_ARM_LIBRARIES = ("libwz_capi_pico", "libzenohpico")
#: A cell's figures of the resident set by part, each the two processes' sum, which the summary and the report
#: carry with W over P as they carry every figure.
SMAPS_FIGURES = tuple(f"smaps_{c}_kib" for c in SMAPS_CLASSES) + tuple(f"smaps_rollup_{k}" for k in SMAPS_ROLLUP_KEYS)
METRICS.update({name: "lower" for name in SMAPS_FIGURES})

PING_KEYS = ("round_trips", "lost", "aborted", "p50_ns", "p90_ns", "p99_ns", "min_ns", "max_ns", "mean_ns",
             "all_round_trips", "cpu_ns")
PONG_KEYS = ("answered", "cpu_ns", "stopped_by")
PUB_KEYS = ("sent", "failed", "elapsed_ns", "cpu_ns", "start_ns", "end_ns")
SUB_KEYS = ("received", "bytes", "window_ns", "cpu_ns", "start_ns", "end_ns")
SUB_END_KEYS = ("total", "last_growth_ns", "peers")
SUB_MARK_KEYS = ("pub_sent", "received_before_end")
#: The last line of a role that ran (perf_probe.c): the program's own peak resident set.
USAGE_KEYS = ("peak_rss_kib",)
#: How that line starts. Every role prints it as it ends, so it says nothing of why a role ended.
USAGE_PREFIX = "perf_probe usage "
#: The lines a probe prints of its resident set by mapping, when PERF_SMAPS=1 asks (perf_probe.c).
SMAPS_PREFIX = "perf_probe smaps "
#: The transports whose links are reliable streams: a put under congestion control block is delivered there or
#: refused, so one that answered success and never arrived loses its cell (`delivery`). A zenoh-pico peer, whose
#: stream sockets do not block, leaves a batch it could not write whole to no one and answers success
#: (docs/pico-perf-matrix.md section 4).
STREAM_TRANSPORTS = ("tcp", "program")
#: The seconds the subscriber is given, once the publisher printed its result, to hand on its backlog up to the
#: publisher's end marker: the socket buffers of a loopback stream hold seconds of what a slow reader has not read.
DRAIN_S = 20
#: The same wait on a transport of datagrams, which may lose the marker as it loses any put: the figure is then
#: not given, and the cell is not lost for it.
MARK_WAIT_S = 2


class Disturbed(Lost):
    """A cell whose pinned CPUs something else used in every run: the host's state at that time, which a
    later pass may not meet."""


def stall_note(pub: dict[str, str], sub_end: dict[str, str] | None) -> str:
    """Which side stopped, in a throughput cell that delivered nothing in its window, from the publisher's
    line and the subscriber's last one. A publisher that lost its match, or listed no peer at its end, put
    into nothing: a zenoh-pico put that has no subscriber, or no peer, returns success and sends nothing. A
    publisher that kept both while the subscriber's count stopped growing means the subscriber stopped
    taking what was sent."""
    start = int(pub["start_ns"])
    facts = [f"{pub.get('batch_cycles', '?')} batch window(s)", f"{pub['failed']} put(s) failed"]
    lost_match = int(pub.get("lost_match_ns", "0"))
    if lost_match:
        facts.append(f"the publisher matched no subscriber from {(lost_match - start) / 1e9:.2f} s into its loop")
    facts.append(f"the publisher listed {pub.get('peers_at_end', '?')} peer(s) at its end")
    if sub_end is not None:
        grew = int(sub_end["last_growth_ns"])
        when = f"{(grew - start) / 1e9:.2f} s into the publisher's loop" if grew else "never"
        facts.append(f"the subscriber received {sub_end['total']} in all, its count last grew {when}, and it "
                     f"listed {sub_end['peers']} peer(s) at its end")
    if lost_match or pub.get("peers_at_end") == "0":
        side = "the sending side lost the subscriber, and its puts went nowhere"
    elif pub.get("matched_at_end") == "1" and sub_end is not None:
        side = ("the publisher still matched its subscriber at its end, so what stopped is on the receiving "
                "side or the link between")
    else:
        side = "which side stopped is not told by these lines"
    return f"{side} ({'; '.join(facts)})"


# -- the readers ------------------------------------------------------------------------------------------

def fields(text: str, role: str, keys: tuple[str, ...]) -> dict[str, str] | None:
    """The `key=value` words of the last line `perf_probe <role> ...` in `text` that carries every one of
    `keys`, or None when no line does."""
    found = None
    prefix = f"perf_probe {role} "
    for line in text.splitlines():
        if not line.startswith(prefix):
            continue
        words = dict(w.split("=", 1) for w in line[len(prefix):].split() if "=" in w)
        if all(k in words for k in keys):
            found = words
    return found


def last_words(text: str) -> str:
    """What a program said last, for the reason of a lost cell: its last line before the usage line it ends
    with (USAGE_PREFIX) and its resident set by mapping (SMAPS_PREFIX), or that line when it said nothing else."""
    lines = [line for line in text.splitlines() if line.strip()]
    said = [line for line in lines if not line.startswith((USAGE_PREFIX, SMAPS_PREFIX))] or lines
    return said[-1][:160] if said else "nothing"


@dataclass(frozen=True)
class Usage:
    """A reaped process's whole CPU and its peak resident set, None when the program did not say it."""

    user_s: float
    sys_s: float
    rss_kib: int | None
    #: What its resident set was made of (`smaps_of`), when the run asked with PERF_SMAPS=1.
    smaps: dict | None = None


def peak_rss_kib(text: str) -> int | None:
    """The peak resident set a program printed as its last line (perf_probe.c), or None when it printed
    none (it was killed, or /proc gave it no figure)."""
    found = fields(text, "usage", USAGE_KEYS)
    return None if found is None else int(found["peak_rss_kib"])


def smaps_class(name: str) -> str:
    """The part of the resident set (SMAPS_CLASSES) a mapping of the name /proc/self/smaps gives it is."""
    if not name:
        return "anonymous"
    if name == "[heap]":
        return "heap"
    if name == "[stack]":
        return "stack"
    if name in ("[vdso]", "[vvar]", "[vvar_vclock]", "[vsyscall]"):
        return "kernel"
    if name.startswith("["):
        return "other"
    base = name.rsplit("/", 1)[-1]
    if base.startswith(SMAPS_ARM_LIBRARIES):
        return "library"
    if base.startswith("libc.so"):
        return "libc"
    if base.startswith("ld-linux"):
        return "loader"
    if base.startswith("libgcc_s"):
        return "libgcc_s"
    if base.startswith("perf_probe"):
        return "program"
    if ".so" in base:
        return "other_libraries"
    return "other"


def smaps_of(text: str) -> dict | None:
    """What a program printed of its resident set (perf_probe.c, PERF_SMAPS=1): its rollup's figures, the
    resident KiB of each part (SMAPS_CLASSES, every part present, 0 for none) and each mapping as it printed
    it, an executable mapping of a file with the pages of it the process held (`page_map`, a hex digit for
    four pages, lowest first); None when it printed no rollup (the run did not ask, or /proc gave nothing)."""
    rollup = None
    regions = []
    pages: dict[str, dict] = {}
    for line in text.splitlines():
        if line.startswith(SMAPS_PREFIX + "rollup "):
            words = dict(w.split("=", 1) for w in line[len(SMAPS_PREFIX + "rollup "):].split() if "=" in w)
            rollup = {k: int(words[k]) for k in SMAPS_ROLLUP_KEYS if k in words}
        elif line.startswith(SMAPS_PREFIX + "region "):
            head, _, name = line[len(SMAPS_PREFIX + "region "):].partition("name=")
            words = dict(w.split("=", 1) for w in head.split() if "=" in w)
            regions.append({"name": name.strip(), "perms": words.get("perms", ""),
                            "size_kib": int(words.get("size_kib", 0)), "rss_kib": int(words.get("rss_kib", 0)),
                            "private_dirty_kib": int(words.get("private_dirty_kib", 0)),
                            "start": words.get("start", "")})
        elif line.startswith(SMAPS_PREFIX + "pages "):
            words = dict(w.split("=", 1) for w in line[len(SMAPS_PREFIX + "pages "):].split() if "=" in w)
            pages[words.get("start", "")] = {"pages": int(words.get("pages", 0)),
                                             "present_pages": int(words.get("present", 0)),
                                             "page_map": words.get("map", "")}
    if rollup is None:
        return None
    for region in regions:
        region.update(pages.get(region["start"], {}))
    parts = dict.fromkeys(SMAPS_CLASSES, 0)
    for region in regions:
        parts[smaps_class(region["name"])] += region["rss_kib"]
    return {"rollup": rollup, "parts": parts, "regions": regions}


def smaps_figures(client: dict | None, server: dict | None) -> dict:
    """A cell's figures of its resident set by part (SMAPS_FIGURES), each the two processes' sum, and each
    side's reading; none when a side printed none, so a sum never stands for one process."""
    if client is None or server is None:
        return {}
    figures: dict = {f"smaps_{c}_kib": client["parts"][c] + server["parts"][c] for c in SMAPS_CLASSES}
    for key in SMAPS_ROLLUP_KEYS:
        if key in client["rollup"] and key in server["rollup"]:
            figures[f"smaps_rollup_{key}"] = client["rollup"][key] + server["rollup"][key]
    figures["smaps_client"] = client
    figures["smaps_server"] = server
    return figures


# -- which code of a library a run holds resident (docs/win-budget/rss.md, R3) ------------------------------

#: A demangled name with no path is one of the pico ABI's C doors when it carries a door's prefix.
C_DOOR_PREFIXES = ("z_", "ze_", "zp_", "wz_", "_z_")
#: The planes a perf run never calls, by a word their symbols' names carry (rss.md section 2.1); the groups
#: overlap the crates.
UNCALLED_NAME_GROUPS = (("advanced", ("advanced",)), ("liveliness", ("liveliness", "token")),
                        ("scouting", ("scout",)), ("connectivity", ("connectivity",)),
                        ("float formatting", ("flt2dec", "float")), ("digest", ("sha2", "digest")))
#: The page the probe's page map counts in (perf_probe.c, print_pages, on the hosts the matrix runs on).
PAGE_BYTES = 4096
ELF_PT_LOAD = 1
ELF_PF_X = 1
ELF_PHDR = struct.Struct("<IIQQQQQQ")


def exec_segment(data: bytes) -> tuple[int, int]:
    """The address and memory size of the one executable loaded segment of a 64-bit little-endian ELF file,
    which the probe's page map of the library's executable mapping covers from its first page. Another file,
    or one with no or several such segments, is refused (Refused)."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise Refused("not a 64-bit little-endian ELF file")
    (phoff,) = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    if phentsize < ELF_PHDR.size or phoff + phnum * phentsize > len(data):
        raise Refused("its program headers do not fit the file")
    found = []
    for index in range(phnum):
        p_type, p_flags, _, p_vaddr, _, _, p_memsz, _ = ELF_PHDR.unpack_from(data, phoff + index * phentsize)
        if p_type == ELF_PT_LOAD and p_flags & ELF_PF_X:
            found.append((p_vaddr, p_memsz))
    if len(found) != 1:
        raise Refused(f"it has {len(found)} executable loaded segments, and a page map covers one")
    return found[0]


def present_pages(page_map: str, pages: int) -> set[int]:
    """The pages a probe's `page_map` says were present (perf_probe.c, print_pages): a hex digit for four
    pages, the lowest page in the lowest bit of the first digit; none at or past `pages`."""
    out: set[int] = set()
    for at, digit in enumerate(page_map):
        value = int(digit, 16)
        out.update(at * 4 + bit for bit in range(4) if value >> bit & 1 and at * 4 + bit < pages)
    return out


def text_symbols(listing: str) -> list[tuple[int, int, str]]:
    """The text symbols that have a size in `nm --defined-only -S -C` output, as (address, size, name); a
    demangled name may hold spaces, so it is the rest of its line."""
    out = []
    for line in listing.splitlines():
        words = line.split(maxsplit=3)
        if len(words) == 4 and words[2] in ("t", "T"):
            with contextlib.suppress(ValueError):
                out.append((int(words[0], 16), int(words[1], 16), words[3]))
    return out


def symbol_crate(name: str) -> str:
    """The crate a demangled text symbol is counted at: the first segment of its path (a generic at the
    crate that defines it, an impl at its type's), `C doors` for an unmangled door, `other` for the rest."""
    path = name.lstrip("<&*")
    if "::" not in path:
        return "C doors" if path.startswith(C_DOOR_PREFIXES) else "other"
    crate = path.split("::", 1)[0]
    return crate if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", crate) else "other"


def resident_text(symbols: list[tuple[int, int, str]], base: int, pages: set[int]) -> dict:
    """For each crate (`crates`) and each group of UNCALLED_NAME_GROUPS (`groups`): the bytes of its text
    symbols (`text`) and the bytes of them on `pages` (`resident`), the present pages of a mapping whose
    first page starts at the address `base`. A resident byte is one a fault brought in, by the run's own
    execution or by fault-around; the page map does not tell the two apart."""
    out: dict = {"crates": {}, "groups": {}}
    for addr, size, name in symbols:
        on = 0
        if size:
            for page in range((addr - base) // PAGE_BYTES, (addr + size - 1 - base) // PAGE_BYTES + 1):
                if page in pages:
                    on += (min(addr + size, base + (page + 1) * PAGE_BYTES)
                           - max(addr, base + page * PAGE_BYTES))
        lower = name.lower()
        rows = [out["crates"].setdefault(symbol_crate(name), {"text": 0, "resident": 0})]
        rows += [out["groups"].setdefault(group, {"text": 0, "resident": 0})
                 for group, words in UNCALLED_NAME_GROUPS if any(word in lower for word in words)]
        for row in rows:
            row["text"] += size
            row["resident"] += on
    return out


def library_regions(doc: dict, arm: str, library: str) -> list[tuple[str, dict]]:
    """Each executable mapping of `library` (its file name) with a page map that a probe of arm `arm` printed in a
    run's result, with the role it was read in, `<transport> <workload> <client|server>`."""
    out: list[tuple[str, dict]] = []
    for cell in doc.get("cells", []):
        if cell.get("arm") != arm:
            continue
        for side in ("client", "server"):
            reading = (cell.get("figures") or {}).get(f"smaps_{side}") or {}
            for region in reading.get("regions", []):
                if pathlib.Path(region.get("name", "")).name == library and region.get("page_map"):
                    out.append((f"{cell.get('transport')} {cell.get('workload')} {side}", region))
    return out


def role_pages(doc: dict, arm: str, library: str) -> dict[str, tuple[set[int], int]]:
    """The present pages of `library`'s executable mapping (its file name) in each role of arm `arm` of a
    run's result, by `<transport> <workload> <client|server>`, the union over that role's cells, with the
    pages of the mapping; a role whose probes printed no page map is absent."""
    out: dict[str, tuple[set[int], int]] = {}
    for key, region in library_regions(doc, arm, library):
        pages, count = out.get(key, (set(), 0))
        pages |= present_pages(region["page_map"], region.get("pages", 0))
        out[key] = (pages, max(count, region.get("pages", 0)))
    return out


def run_section(data: bytes) -> tuple[int, int] | None:
    """The address and size of the code a run-text list laid out together (RUN_TEXT_SECTION) in an ELF library;
    None when its link wrote no such section (no list, or a list that placed nothing). A file whose section
    headers do not read is refused (Refused)."""
    try:
        found = [section for section in elf_facts.sections(data) if section.name == RUN_TEXT_SECTION]
    except (elf_facts.ElfError, struct.error) as why:
        raise Refused(f"its section headers do not read: {why}") from None
    return (found[0].addr, found[0].size) if found else None


def outside_run(pages: set[int], start: int, base: int, run_end: int) -> set[int]:
    """Of the present `pages` of a library's executable mapping, those in no fault-around window that reaches the
    run's laid-out code. The mapping starts at the virtual address `start` with the page of the file's address
    `base`, and what lies from there to `run_end` (the file's address RUN_TEXT_SECTION ends at) is the code
    ahead of `.text`, the PLT among it, and the list's functions. A fault maps pages only inside the window of
    FAULT_AROUND_BYTES of the address space that holds it, so a page present past the window of the run's last
    byte was mapped by a fault past it: code ran there that the list does not place."""
    last = (start + run_end - base - 1) // FAULT_AROUND_BYTES
    return {page for page in pages if (start + page * PAGE_BYTES) // FAULT_AROUND_BYTES > last}


def role_outside_run(doc: dict, arm: str, library: str, base: int, run_end: int) -> dict[str, set[int]]:
    """For each role of `role_pages`, the pages of `library` its processes held outside the windows of the run's
    laid-out code (`outside_run`, each process by the address its own mapping started at, since the windows are
    the address space's and each process maps the library elsewhere), the union over them. A page map with no
    start address is refused (Refused): its windows cannot be told."""
    out: dict[str, set[int]] = {}
    for key, region in library_regions(doc, arm, library):
        try:
            start = int(region.get("start", ""), 16)
        except ValueError:
            raise Refused(f"a page map of {library} in role {key} has no start address") from None
        pages = present_pages(region["page_map"], region.get("pages", 0))
        out.setdefault(key, set()).update(outside_run(pages, start, base, run_end))
    return out


def cmd_resident_text(result: pathlib.Path, library: pathlib.Path, arm: str) -> int:
    """Each role's resident code of `library` in a run made with PERF_SMAPS=1, named by crate and by the planes
    a run never calls (rss.md R3), and for a library whose text a run-text list laid out (`run_section`) the
    pages each role held outside the windows of that code, named by crate (`role_outside_run`, rss.md section
    5.4): exit 0 when it named some and none lay outside, 1 when a role held code outside the laid-out run (a
    function the list does not place ran: the list is stale), 2 when an input was refused, 3 when the run
    printed no page map of that library for arm `arm`."""
    try:
        doc = json.loads(result.read_text(encoding="utf-8"))
        data = library.read_bytes()
        vaddr, _ = exec_segment(data)
        span = run_section(data)
        listing = subprocess.run(["nm", "--defined-only", "-S", "-C", str(library)], capture_output=True,
                                 text=True, check=True).stdout
    except (OSError, ValueError, struct.error, subprocess.CalledProcessError, Refused) as why:
        print(f"perf-matrix: resident-text refused: {why}", file=sys.stderr, flush=True)
        return 2
    name = library.resolve().name
    roles = role_pages(doc, arm, name)
    if not roles:
        print(f"perf-matrix: resident-text NOT-MEASURED, {result} holds no page map of {library.name} for arm "
              f"{arm} (a run with PERF_SMAPS=1 prints one)", flush=True)
        return 3
    symbols = text_symbols(listing)
    base = vaddr - vaddr % PAGE_BYTES
    try:
        outside = {} if span is None else role_outside_run(doc, arm, name, base, span[0] + span[1])
    except Refused as why:
        print(f"perf-matrix: resident-text refused: {why}", file=sys.stderr, flush=True)
        return 2
    for role, (pages, mapped) in sorted(roles.items()):
        named = resident_text(symbols, base, pages)
        print(f"resident-text {arm} {role}: {len(pages)} of {mapped} page(s) present", flush=True)
        for kind in ("crates", "groups"):
            for key, row in sorted(named[kind].items(), key=lambda item: (-item[1]["resident"], item[0])):
                print(f"  {kind[:-1]} {key}: {row['resident']} of {row['text']} byte(s) resident", flush=True)
        if span is not None:
            held = outside.get(role, set())
            print(f"  outside the laid-out run: {len(held)} page(s)", flush=True)
            stray = resident_text(symbols, base, held)["crates"]
            for key, row in sorted(stray.items(), key=lambda item: (-item[1]["resident"], item[0])):
                if row["resident"]:
                    print(f"    crate {key}: {row['resident']} byte(s) resident", flush=True)
    if span is None:
        print(f"perf-matrix: resident-text {library.name} has no {RUN_TEXT_SECTION}: its text lies in the "
              "linker's own order", flush=True)
        return 0
    stale = sorted(role for role, held in outside.items() if held)
    if stale:
        print(f"perf-matrix: resident-text STALE, {len(stale)} role(s) held code of {library.name} outside its "
              f"laid-out run ({'; '.join(stale)}): a function the list does not place ran, so the list is made "
              "again (scripts/pico-compare.sh run-text)", flush=True)
        return 1
    print(f"perf-matrix: resident-text every role held the code of {library.name} inside the windows of its "
          f"laid-out run ({span[1]} byte(s) of {RUN_TEXT_SECTION})", flush=True)
    return 0


# -- the code a run executes, laid out in one place (docs/win-budget/rss.md, section 5.4) ----------------------

#: What a run with --trace-text starts each probe under: callgrind counts every function a process executes, a
#: path run once (the open, the handshake) as surely as the loop, where a sampling profile misses what runs
#: rarely; the names stay mangled, as the library's sections are named.
TEXT_TRACE_TOOL = ("valgrind", "-q", "--tool=callgrind", "--demangle=no")
#: The window a read fault on a file mapping maps around it from the page cache (the kernel's
#: `fault_around_bytes`, 65536 unless an administrator changed it): the unit in which a library's text becomes
#: resident.
FAULT_AROUND_BYTES = 65536
#: The hash a legacy-mangled Rust name's path ends in, which changes with the build while the path does not; a
#: suffix the compiler gives a copy of the function (`.llvm.<n>`) may follow it.
RUST_NAME_HASH = re.compile(r"17h[0-9a-f]{16}E(?=\.|$)")
#: What the hash is matched by in a section pattern: any sixteen characters.
RUST_HASH_PATTERN = "17h" + "?" * 16 + "E"
#: The characters a GNU ld input section pattern takes unquoted that a legacy-mangled Rust name or a C name holds;
#: a function of a name with any other is left in the linker's own order.
SECTION_NAME = re.compile(r"[A-Za-z0-9_.$]+")
#: The output section the script lays the run's code in, ahead of `.text` in the same executable segment.
RUN_TEXT_SECTION = ".text.run"
#: The script the library's link reads (crates/.cargo/capi-run-text.toml): its head comment is written by hand and
#: kept, its SECTIONS statement written by `run-text`.
RUN_TEXT_SCRIPT = ROOT / "crates" / "wz-capi-pico" / "link" / "run-text.ld"
#: Where the script's statement starts: the first line that is the word alone.
RUN_TEXT_START = re.compile(r"^SECTIONS\n", re.MULTILINE)
#: How the statement lists one function: the patterns of its sections inside `*( )`.
RUN_TEXT_LINE = re.compile(r"    \*\((.+)\)")


def traced_command(program: list[str], out: pathlib.Path) -> list[str]:
    """`program` started under callgrind (TEXT_TRACE_TOOL), its profile written to `out` and the process's pid, so
    a cell run again writes a profile of its own."""
    return [*TEXT_TRACE_TOOL, f"--callgrind-out-file={out}.%p", *program]


def traced_functions(text: str, library: str) -> set[str]:
    """The functions of the object whose file name is `library` that a callgrind profile says ran: each `fn=` under
    an `ob=` of it, and each `cfn=` whose `cob=` is it, or that has no `cob=` and is called from it. Callgrind
    names a string once with its id, `(3) name`, and by `(3)` alone after, objects and functions each in a table
    of their own; a name it marks with a recursion depth (`'2`) is the function's."""
    objects: dict[str, str] = {}
    functions: dict[str, str] = {}

    def named(table: dict[str, str], value: str) -> str:
        found = re.fullmatch(r"\((\d+)\)(?: (.*))?", value.strip())
        if found is None:
            return value.strip()
        if found.group(2) is not None:
            table[found.group(1)] = found.group(2).strip()
        return table.get(found.group(1), "")

    out: set[str] = set()
    ob = ""
    cob: str | None = None
    for line in text.splitlines():
        key, eq, value = line.partition("=")
        if not eq:
            continue
        if key == "ob":
            ob = named(objects, value)
        elif key == "cob":
            cob = named(objects, value)
        elif key in ("fn", "cfn"):
            name = re.sub(r"'\d+$", "", named(functions, value))
            where = ob if key == "fn" or cob is None else cob
            if key == "cfn":
                cob = None
            if name and pathlib.PurePath(where).name == library:
                out.add(name)
    return out


def section_patterns(name: str) -> str | None:
    """The GNU ld input section patterns that match the function `name` where the compiler put it: its own section
    (`.text.<name>`, one a function) and the one of a function the compiler judged cold (`.text.unlikely.<name>`),
    a Rust name's hash matched by any (RUST_HASH_PATTERN), so the pattern holds across builds while the function's
    path does; None for a name a pattern does not take unquoted."""
    if not SECTION_NAME.fullmatch(name):
        return None
    stem = RUST_NAME_HASH.sub(RUST_HASH_PATTERN, name)
    return f".text.{stem} .text.unlikely.{stem}"


def run_text_body(patterns: list[str]) -> str:
    """The script's SECTIONS statement: one output section, RUN_TEXT_SECTION, of the functions `patterns` name (a
    line each, in the order given), inserted before `.text`, so the run's code lies together ahead of the rest and
    every function no line names keeps the linker's own order. With no line the section is empty, and the linker
    writes none."""
    lines = "".join(f"    *({pattern})\n" for pattern in patterns)
    return f"SECTIONS\n{{\n  {RUN_TEXT_SECTION} :\n  {{\n{lines}  }}\n}}\nINSERT BEFORE .text;\n"


def run_text_parts(script: str) -> tuple[str, list[str]]:
    """A run-text script's head (everything before its SECTIONS statement) and the patterns its statement lists; a
    script with no statement, or with one `run_text_body` does not write, is refused (Refused)."""
    found = RUN_TEXT_START.search(script)
    if found is None:
        raise Refused("it holds no SECTIONS statement at the start of a line")
    head, body = script[:found.start()], script[found.start():]
    patterns = [m.group(1) for line in body.splitlines() if (m := RUN_TEXT_LINE.fullmatch(line))]
    if run_text_body(patterns) != body:
        raise Refused("its SECTIONS statement is not one `run-text` writes")
    return head, patterns


def run_text_plan(traced: set[str], sizes: dict[str, int]) -> tuple[list[str], list[str], list[str]]:
    """Of the `traced` names, the functions the library defines a text symbol of (`sizes`, by name), the ones of
    them a pattern places, and the script's lines for those, each list sorted, so a list made again differs by what
    changed."""
    ran = sorted(name for name in traced if name in sizes)
    placed = [name for name in ran if section_patterns(name) is not None]
    lines = sorted({pattern for name in placed if (pattern := section_patterns(name)) is not None})
    return ran, placed, lines


def cmd_run_text(library: pathlib.Path, script: pathlib.Path, traces: list[pathlib.Path]) -> int:
    """The functions of `library` the callgrind profiles `traces` say ran, and the SECTIONS statement of `script`
    (none for `-`) that lays them out together, its head kept (rss.md section 5.4): exit 0 when read, 2 when an
    input was refused, 3 when no profile names a text symbol of `library`."""
    writes = str(script) != "-"
    try:
        _, text_bytes = exec_segment(library.read_bytes())
        listing = subprocess.run(["nm", "--defined-only", "-S", str(library)], capture_output=True, text=True,
                                 check=True).stdout
        head, before = run_text_parts(script.read_text(encoding="utf-8")) if writes else ("", [])
        traced: set[str] = set()
        for trace in traces:
            traced |= traced_functions(trace.read_text(encoding="utf-8", errors="replace"), library.resolve().name)
    except (OSError, ValueError, struct.error, subprocess.CalledProcessError, Refused) as why:
        print(f"perf-matrix: run-text refused: {why}", file=sys.stderr, flush=True)
        return 2
    sizes = {name: size for _, size, name in text_symbols(listing)}
    ran, placed, lines = run_text_plan(traced, sizes)
    if not ran:
        print(f"perf-matrix: run-text NOT-MEASURED, none of {len(traces)} profile(s) names a text symbol of "
              f"{library.name} (a run with --trace-text writes them)", flush=True)
        return 3
    ran_bytes = sum(sizes[name] for name in ran)
    placed_bytes = sum(sizes[name] for name in placed)
    windows = -(-placed_bytes // FAULT_AROUND_BYTES) + 1
    print(f"perf-matrix: run-text {library.name}: {len(ran)} function(s) ran, {ran_bytes} of the {text_bytes} "
          f"byte(s) of its executable segment; {len(placed)} placed by {len(lines)} line(s), {placed_bytes} "
          f"byte(s), which laid out together span at most {windows} window(s) of {FAULT_AROUND_BYTES} bytes; "
          f"{len(ran) - len(placed)} left in the linker's order by their name; {len(traced) - len(ran)} traced "
          f"name(s) of no text symbol it defines", flush=True)
    if writes:
        script.write_text(head + run_text_body(lines), encoding="utf-8")
        added, dropped = list_change(before, lines)
        print(f"perf-matrix: run-text wrote {script}: {added} line(s) added and {dropped} dropped against the list "
              "it replaced", flush=True)
    return 0


def list_change(before: list[str], after: list[str]) -> tuple[int, int]:
    """The lines a list made again adds, and the lines it drops, against the list it replaces."""
    return len(set(after) - set(before)), len(set(before) - set(after))


def order_names(lines: list[str], names: list[str]) -> list[str]:
    """The `names` the run-text list `lines` places, for a linker that orders functions by their exact names
    (lld-link's `/ORDER:@file`, rss.md section 5.4): a name is placed when its own patterns (`section_patterns`)
    are a line of the list, so a build whose hashes are another target's is placed by the lines a Linux trace
    made. In the list's order and by name within a line, each name once."""
    rank = {line: at for at, line in enumerate(lines)}
    keyed = {(rank[pattern], name) for name in names
             if (pattern := section_patterns(name)) is not None and pattern in rank}
    return [name for _, name in sorted(keyed)]


def link_names(text: str) -> list[str]:
    """The symbol names a listing holds: the last word of each line, where a list of names, `nm`'s output and
    lld-link's map (`/lldmap` with `/demangle:no`) each write one; a word that is no function's name places
    nothing (`order_names`)."""
    return [words[-1] for line in text.splitlines() if (words := line.split())]


def cmd_run_text_order(script: pathlib.Path, listing: pathlib.Path, out: pathlib.Path) -> int:
    """lld-link's order file of the functions the run-text list of `script` places, of the names the link listing
    `listing` holds (`link_names`), one a line, written to `out` (rss.md section 5.4): exit 0 when written, 2
    when an input was refused, 3 when no name of the listing is one the list places, and nothing is written."""
    try:
        _, lines = run_text_parts(script.read_text(encoding="utf-8"))
        names = link_names(listing.read_text(encoding="utf-8", errors="replace"))
    except (OSError, Refused) as why:
        print(f"perf-matrix: run-text-order refused: {why}", file=sys.stderr, flush=True)
        return 2
    ordered = order_names(lines, names)
    if not ordered:
        print(f"perf-matrix: run-text-order NOT-MEASURED, none of the {len(names)} name(s) of {listing} is a "
              f"function the {len(lines)} line(s) of {script} place", flush=True)
        return 3
    try:
        out.write_text("".join(f"{name}\n" for name in ordered), encoding="utf-8")
    except OSError as why:
        print(f"perf-matrix: run-text-order refused: {why}", file=sys.stderr, flush=True)
        return 2
    print(f"perf-matrix: run-text-order wrote {out}: {len(ordered)} name(s), placed by "
          f"{len({section_patterns(name) for name in ordered})} of the list's {len(lines)} line(s)", flush=True)
    return 0


def usage_of(proc: Process) -> Usage:
    """The CPU of the reaped child and the peak resident set the program printed. The maxrss of the reaped
    child is not that figure: Linux keeps the resident set a process had before its exec as a floor of it,
    and the child is a copy of this runner until it executes the program."""
    text = proc.text()
    rss, smaps = peak_rss_kib(text), smaps_of(text)
    if proc.rusage is None:
        return Usage(0.0, 0.0, rss, smaps)
    return Usage(proc.rusage.ru_utime, proc.rusage.ru_stime, rss, smaps)


def process_figures(client: Usage, server: Usage) -> dict:
    both = None if client.rss_kib is None or server.rss_kib is None else client.rss_kib + server.rss_kib
    figures = {"cpu_user_s_client": client.user_s, "cpu_sys_s_client": client.sys_s,
               "cpu_user_s_server": server.user_s, "cpu_sys_s_server": server.sys_s,
               "rss_kib_client": client.rss_kib, "rss_kib_server": server.rss_kib, "rss_kib": both}
    figures.update(smaps_figures(client.smaps, server.smaps))
    return figures


def rtt_figures(ping: dict[str, str], pong: dict[str, str] | None, client: Usage,
                server: Usage) -> dict[str, float | None]:
    """The figures of a round-trip cell from what ping and pong printed. Raises Lost when no round trip
    was counted. pong's CPU per round trip is None when it was stopped by a signal: its window then holds
    the idle time after the last ping."""
    counted = int(ping["round_trips"])
    if counted == 0:
        raise Lost(f"no round trip came back ({ping['lost']} lost)")
    figures: dict[str, float | None] = {
        "rtt_p50_us": int(ping["p50_ns"]) / 1e3, "rtt_p90_us": int(ping["p90_ns"]) / 1e3,
        "rtt_p99_us": int(ping["p99_ns"]) / 1e3, "rtt_mean_us": int(ping["mean_ns"]) / 1e3,
        "rtt_min_us": int(ping["min_ns"]) / 1e3, "rtt_max_us": int(ping["max_ns"]) / 1e3,
        "round_trips": counted, "lost": int(ping["lost"]),
        "ping_cpu_ns_per_rtt": int(ping["cpu_ns"]) / max(1, int(ping["all_round_trips"])),
        "pong_cpu_ns_per_rtt": None,
    }
    if pong is not None and pong["stopped_by"] == "stop" and int(pong["answered"]) > 0:
        figures["pong_cpu_ns_per_rtt"] = int(pong["cpu_ns"]) / int(pong["answered"])
    figures.update(process_figures(client, server))
    return figures


def thr_figures(pub: dict[str, str], sub: dict[str, str], client: Usage,
                server: Usage) -> dict[str, float | None]:
    """The figures of a throughput cell from what pub and sub printed. Raises Lost when the subscriber's
    window did not lie inside the publisher's loop, or nothing was delivered in it."""
    if not int(pub["start_ns"]) <= int(sub["start_ns"]) <= int(sub["end_ns"]) <= int(pub["end_ns"]):
        raise Lost("the subscriber's window was not inside the publisher's loop "
                   f"(window {sub['start_ns']}..{sub['end_ns']}, loop {pub['start_ns']}..{pub['end_ns']})")
    received, sent = int(sub["received"]), int(pub["sent"])
    if received == 0 or sent == 0:
        raise Lost(f"{sent} put, {received} delivered in the window")
    window_s = int(sub["window_ns"]) / 1e9
    pub_cpu = int(pub["cpu_ns"]) / sent
    sub_cpu = int(sub["cpu_ns"]) / received
    figures: dict[str, float | None] = {
        "msgs_per_s": received / window_s, "bytes_per_s": int(sub["bytes"]) / window_s,
        "offered_msgs_per_s": sent / (int(pub["elapsed_ns"]) / 1e9), "put_failed": int(pub["failed"]),
        "cpu_ns_per_msg_pub": pub_cpu, "cpu_ns_per_msg_sub": sub_cpu, "cpu_ns_per_msg": pub_cpu + sub_cpu,
    }
    figures.update(process_figures(client, server))
    return figures


def delivery(transport: str, put: dict[str, str], mark: dict[str, str] | None) -> int | None:
    """The puts that answered success and had not been handed to the subscriber when the publisher's first end
    marker reached it, or None when no marker did. On a reliable stream (STREAM_TRANSPORTS) a put under congestion
    control block is delivered or refused, so a put that answered success and was not delivered, or a marker that
    never came, loses the cell (Lost); on a transport of datagrams the count is a figure of the cell."""
    sent = int(put["sent"])
    stream = transport in STREAM_TRANSPORTS
    if mark is None:
        if stream:
            raise Lost(f"the publisher's end marker ({put.get('end_marks', '?')} put(s) of it answered success) did "
                       f"not reach the subscriber in {DRAIN_S} s, on a reliable stream under congestion control "
                       "block")
        return None
    if int(mark["pub_sent"]) != sent:
        raise Lost(f"the end marker carried {mark['pub_sent']} puts and the publisher said {sent}")
    missing = sent - int(mark["received_before_end"])
    if stream and missing != 0:
        raise Lost(f"{sent} puts answered success and {mark['received_before_end']} reached the subscriber before "
                   "the publisher's end marker, on a reliable stream under congestion control block: "
                   + (f"{missing} answered success and were never delivered" if missing > 0
                      else f"{-missing} more were delivered than were put"))
    return missing


def endpoint_args(transport: str, port: int, name: str) -> tuple[list[str], list[str]]:
    """The arguments of the server side and of the client side of `transport`. On a transport that carries
    declarations the client side waits until its publisher matches a subscriber (perf_probe.c -M): a
    zenoh-pico publisher sends nothing, and still counts the put, while it knows of no subscriber. A
    group of the pico preset carries no declarations and sends every put, so it has nothing to wait for."""
    if transport == "tcp":
        where = f"tcp/127.0.0.1:{port}"
        return ["-l", where], ["-e", where, "-M"]
    if transport == "udp":
        where = f"udp/127.0.0.1:{port}"
        return ["-l", where], ["-e", where, "-M"]
    if transport == "multicast":
        where = f"udp/{GROUP}:{port}#iface=lo"
        return ["-l", where], ["-l", where]
    if transport == "program":
        return ["-l", PROGRAM_LOCATOR, "-T", name], ["-e", PROGRAM_LOCATOR, "-T", name, "-M"]
    raise ValueError(f"no transport {transport}")


def binary_name(arm: str, transport: str, absent: dict[tuple[str, str], str]) -> str | None:
    """The program a cell runs, or None when the arm has no such transport (`absent`, of `not_applicable`)."""
    if (arm, transport) in absent:
        return None
    return "perf_probe_Wapp" if transport == "program" else f"perf_probe_{arm}"


#: The probe's source, and the switch of its builds against wz's library, which state before the open the
#: counts PROBE_LIMITS_MACRO names: a session of the pico ABI opens its tables at fewer.
PROBE_SOURCE = HERE / "perf_probe.c"
WZ_PROBE_SWITCH = "PERF_WZ_ARM"
PROBE_LIMITS_MACRO = "PERF_SESSION_LIMITS"
#: The roles of the probe (`run_<role>` in perf_probe.c).
PROBE_ROLES = ("ping", "pong", "pub", "sub")


def probe_session_limits(source: str) -> dict[str, int]:
    """The counts the probe's PROBE_LIMITS_MACRO states, by limit id, as zext.h reads the value of
    ZEXT_CONFIG_LIMITS_KEY (NAME=count items, comma separated). ValueError for a source that defines it
    other than once, or an item that is no NAME=count."""
    found = re.findall(rf'^#define {PROBE_LIMITS_MACRO} "([^"]*)"$', source, re.M)
    if len(found) != 1:
        raise ValueError(f"perf_probe.c defines {PROBE_LIMITS_MACRO} {len(found)} time(s), not once")
    stated: dict[str, int] = {}
    for item in found[0].split(","):
        name, eq, count = item.partition("=")
        if not eq or not name or not count.isdigit():
            raise ValueError(f"{PROBE_LIMITS_MACRO} item `{item}` is no NAME=count")
        stated[name] = int(count)
    return stated


def probe_role_holds(source: str) -> dict[str, dict[str, int]]:
    """What each role's body (`static int run_<role>(` to its closing brace) declares on its session: its
    subscribers (`declare_subscriber(`), its publishers (`declare_publisher(` and `client_publisher(`), and the
    keys they name, one each. ValueError for a role whose body is not found once."""
    holds: dict[str, dict[str, int]] = {}
    for role in PROBE_ROLES:
        bodies = re.findall(rf"^static int run_{role}\(.*?^\}}$", source, re.M | re.S)
        if len(bodies) != 1:
            raise ValueError(f"perf_probe.c has {len(bodies)} body(ies) of run_{role}, not one")
        subscribers = bodies[0].count("declare_subscriber(")
        publishers = bodies[0].count("declare_publisher(") + bodies[0].count("client_publisher(")
        holds[role] = {"MAX_SUBSCRIPTIONS": subscribers, "MAX_PUBLISHERS": publishers,
                       "MAX_DECLARED_KEYEXPRS": subscribers + publishers}
    return holds


def probe_states_limits(source: str) -> bool:
    """Whether the probe, built with WZ_PROBE_SWITCH, hands PROBE_LIMITS_MACRO to its config under
    ZEXT_CONFIG_LIMITS_KEY before it opens its session."""
    stated = re.search(rf"^#ifdef {WZ_PROBE_SWITCH}\n(?:(?!^#endif).)*?zp_config_insert\([^;]*"
                       rf"ZEXT_CONFIG_LIMITS_KEY, {PROBE_LIMITS_MACRO}\)", source, re.M | re.S)
    opened = source.find("z_open(&session")
    return stated is not None and opened != -1 and stated.end() < opened


def probe_builds(script: str) -> dict[str, str]:
    """The words after each `perf_probe_build "$dir" <arm>` of scripts/pico-compare.sh, by arm, its
    continuation lines joined."""
    joined = script.replace("\\\n", " ")
    builds: dict[str, str] = {}
    for line in joined.splitlines():
        words = line.split()
        if len(words) >= 3 and words[:2] == ["perf_probe_build", '"$dir"']:
            builds[words[2]] = " ".join(words[3:])
    return builds


def pico_sys_include(lines: list[str]) -> str:
    """The include directory of the one zenoh-pico-sys build script a cargo JSON report names. A report
    with none, or with two (a tree that holds the output of another feature list beside this one), is a
    ValueError: a program compiled against another arm's headers allocates the other arm's structs."""
    found = set()
    for line in lines:
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") == "build-script-executed" and "zenoh-pico-sys" in msg.get("package_id", ""):
            found.add(os.path.join(msg["out_dir"], "include"))
    if len(found) != 1:
        raise ValueError(f"cargo reported {len(found)} zenoh-pico-sys build(s) for this feature list, not one")
    return found.pop()


def suggest_pinning(busy: dict[int, float], core_of: dict[int, tuple[int, int]],
                    per_side: int) -> tuple[list[int], list[int]] | None:
    """The client side's CPUs and the server side's, each at least `per_side` CPUs made of whole physical
    cores (every CPU of a core on one side, so the two sides share no core), the least busy cores first:
    a core is as busy as its busiest CPU. None when the host has too few cores for both."""
    cores: dict[tuple[int, int], list[int]] = {}
    for cpu, core in core_of.items():
        cores.setdefault(core, []).append(cpu)
    ranked = sorted(cores.values(), key=lambda cpus: (max(busy.get(c, 1.0) for c in cpus), min(cpus)))
    sides = []
    for _ in range(2):
        side: list[int] = []
        while ranked and len(side) < per_side:
            side.extend(ranked.pop(0))
        if len(side) < per_side:
            return None
        sides.append(sorted(side))
    return sides[0], sides[1]


def cpu_busy_shares(seconds: float) -> dict[int, float]:
    """Each CPU's busy share over `seconds` (/proc/stat: user, nice, system and steal over every column)."""

    def sample() -> dict[int, tuple[int, int]]:
        out = {}
        with open("/proc/stat", encoding="ascii") as stat:
            for line in stat:
                words = line.split()
                if words and words[0].startswith("cpu") and words[0] != "cpu":
                    ticks = [int(x) for x in words[1:9]]
                    out[int(words[0][3:])] = (ticks[0] + ticks[1] + ticks[2] + ticks[7], sum(ticks))
        return out

    first = sample()
    time.sleep(seconds)
    second = sample()
    return {cpu: (second[cpu][0] - first[cpu][0]) / max(1, second[cpu][1] - first[cpu][1])
            for cpu in second if cpu in first}


def cpu_cores() -> dict[int, tuple[int, int]]:
    """Each online CPU's physical core, as (package, core id) from sysfs."""
    out = {}
    for topology in sorted(pathlib.Path("/sys/devices/system/cpu").glob("cpu[0-9]*/topology")):
        cpu = int(topology.parent.name[3:])
        try:
            out[cpu] = (int((topology / "physical_package_id").read_text()),
                        int((topology / "core_id").read_text()))
        except (OSError, ValueError):
            continue
    return out


def cmd_idle_cpus(seconds: float, per_side: int) -> int:
    busy = cpu_busy_shares(seconds)
    core_of = {cpu: core for cpu, core in cpu_cores().items() if cpu in busy}
    for cpu in sorted(busy):
        print(f"  cpu{cpu:<3} core {core_of.get(cpu, ('?', '?'))}  busy {busy[cpu] * 100:5.1f}%")
    pinning = suggest_pinning(busy, core_of, per_side)
    if pinning is None:
        print(f"perf-matrix: this host has too few cores for two sides of {per_side} CPUs", flush=True)
        return 1
    client, server = pinning
    print(f"PICO_CMP_CLIENT_CPUS={','.join(map(str, client))} PICO_CMP_SERVER_CPUS={','.join(map(str, server))}",
          flush=True)
    return 0


#: The CPU whose physical core a pinning from the topology leaves to the system: interrupts, timers and the
#: kernel's housekeeping threads land there, and a side pinned beside them would measure them.
SYSTEM_CPU = 0
#: Whole physical cores a side is given from the topology, then what it falls back to on a host with too few:
#: one core is still a pair of threads on an SMT host, and a process held to a single thread measured a 2 ms
#: scheduler tick in both libraries.
SIDE_CORES = (2, 1)


def topology_pinning(core_of: dict[int, tuple[int, int]], allowed: set[int],
                     given: list[tuple[str, str]]) -> tuple[list[list[int]], str]:
    """The CPUs of each side of a pair (client, then server), in the order of `given`: a (variable, CPU list)
    per side, the list empty for a side the host's topology chooses.

    A given side is used as it is, once each of its CPUs is one this process may run on. A side not given is
    SIDE_CORES[0] whole physical cores, or SIDE_CORES[1] a side when too few are left: every CPU of a core on
    one side, so the sides share no core, cores of more threads first (a hybrid CPU's performance cores),
    then the lowest CPU. Left out: the core of SYSTEM_CPU, every core a given side touches, and a core one of
    whose CPUs this process may not run on. Returns the sides and how they were chosen; Refused with the
    sentence that says why when a given CPU cannot be run on or the host has too few cores."""
    sides: list[list[int] | None] = []
    for name, spec in given:
        if not spec:
            sides.append(None)
            continue
        try:
            cpus = sorted(set(cpu_list(spec)))
        except ValueError:
            cpus = []
        if not cpus:
            raise Refused(f"{name}={spec} is not a CPU list (6,7 or 4-7)")
        outside = [cpu for cpu in cpus if cpu not in allowed]
        if outside:
            raise Refused(f"{name}={spec} names CPU {','.join(map(str, outside))}, which this process "
                          f"may not run on (it may run on {','.join(map(str, sorted(allowed)))})")
        sides.append(cpus)
    missing = [name for (name, _), side in zip(given, sides) if side is None]
    if not missing:
        return [side for side in sides if side is not None], "given"
    taken = {cpu for side in sides if side is not None for cpu in side}
    cores: dict[tuple[int, int], list[int]] = {}
    for cpu, core in core_of.items():
        cores.setdefault(core, []).append(cpu)
    reserved = core_of.get(SYSTEM_CPU)
    free = sorted((sorted(cpus) for core, cpus in cores.items()
                   if core != reserved and all(c in allowed and c not in taken for c in cpus)),
                  key=lambda cpus: (-len(cpus), cpus[0]))
    for per_side in SIDE_CORES:
        if len(free) < per_side * len(missing):
            continue
        for i, side in enumerate(sides):
            if side is None:
                chosen = free[:per_side]
                del free[:per_side]
                sides[i] = sorted(cpu for cpus in chosen for cpu in cpus)
        how = (f"{' and '.join(missing)} from the topology, {per_side} whole core{'s' if per_side > 1 else ''} "
               f"a side, the core of CPU {SYSTEM_CPU} left to the system")
        return [side for side in sides if side is not None], how
    beside = " or a given side" if taken else ""
    raise Refused(f"this host has {len(free)} whole core{'' if len(free) == 1 else 's'} this process may run on "
                  f"outside the core of CPU {SYSTEM_CPU}{beside}, and {' and '.join(missing)} need one core "
                  f"a side at least; name the CPUs of each side to run here")


def cmd_pin_sides(words: list[str]) -> int:
    given = []
    for word in words:
        name, eq, spec = word.partition("=")
        if not eq or not name:
            print(__doc__, file=sys.stderr)
            return 64
        given.append((name, spec))
    try:
        sides, how = topology_pinning(cpu_cores(), set(os.sched_getaffinity(0)), given)
    except Refused as why:
        print(f"perf-matrix: {why}", file=sys.stderr)
        return 2
    print(" ".join(",".join(map(str, side)) for side in sides), how, flush=True)
    return 0


def second_pass(cells: list[dict]) -> list[int]:
    """The cells to run once more at the end: those lost because the host was busy, and no other (a cell
    that failed on its own would fail the same way again)."""
    return [i for i, cell in enumerate(cells) if cell["status"] == "lost" and cell.get("disturbed")]


def numbers(figures: dict) -> dict[str, float]:
    return {k: v for k, v in figures.items()
            if isinstance(v, (int, float)) and not isinstance(v, bool)}


def summarize(cells: list[dict]) -> list[dict]:
    """Per transport, batching, workload and size: for each arm the number of measured repetitions, the
    lost ones, and the median of each figure; and W over P of each figure both arms have, and W over X
    when the run has arm X."""
    groups: dict[tuple, dict[str, dict]] = {}
    for cell in cells:
        key = (cell["transport"], cell["batching"], cell["workload"], cell["size"])
        arm = groups.setdefault(key, {}).setdefault(cell["arm"], {"figures": [], "lost": 0, "status": set(),
                                                                  "foreign": [], "irq": []})
        arm["status"].add(cell["status"])
        if cell["status"] == "measured":
            arm["figures"].append(numbers(cell["figures"]))
            # How much of the pinned CPUs others took while the repetition was read (Windows also records the
            # interrupts' and DPCs' share), so a row says how quiet the host was.
            for share, said in (("foreign", "foreign_share"), ("irq", "irq_share")):
                if isinstance(cell.get(said), (int, float)):
                    arm[share].append(float(cell[said]))
        elif cell["status"] == "lost":
            arm["lost"] += 1
    rows = []
    for key in sorted(groups, key=lambda k: (TRANSPORTS.index(k[0]), k[1], k[2], k[3])):
        arms = {}
        for name, arm in sorted(groups[key].items()):
            figs = arm["figures"]
            names = sorted({n for f in figs for n in f})
            arms[name] = {"measured": len(figs), "lost": arm["lost"],
                          "not_applicable": "not-applicable" in arm["status"],
                          "median": {n: statistics.median([f[n] for f in figs if n in f]) for n in names},
                          "foreign_max": max(arm["foreign"], default=None),
                          "irq_max": max(arm["irq"], default=None)}
        row = {"transport": key[0], "batching": key[1], "workload": key[2], "size": key[3], "arms": arms,
               "w_over_p": median_ratios(arms, "P")}
        if "X" in arms:
            row["w_over_x"] = median_ratios(arms, "X")
        rows.append(row)
    return rows


def median_ratios(arms: dict, ref: str) -> dict[str, float]:
    """W's median over the reference's, for each figure both have."""
    ratio = {}
    if ref in arms and "W" in arms:
        for n, w in arms["W"]["median"].items():
            r = arms[ref]["median"].get(n)
            if r:
                ratio[n] = w / r
    return ratio


def report_lines(rows: list[dict]) -> list[str]:
    """The summary as text: one block per row, one line per figure, P and W medians and W over P, and X's
    median and W over X when the run has arm X."""
    out = []
    for row in rows:
        out.append(f"{row['transport']} batching={'on' if row['batching'] else 'off'} {row['workload']} "
                   f"{row['size']} B")
        arms = row["arms"]
        for arm in ARMS:
            if arm in arms:
                a = arms[arm]
                state = "not applicable" if a["not_applicable"] else f"{a['measured']} measured, {a['lost']} lost"
                if a.get("foreign_max") is not None:
                    state += f", foreign share at most {a['foreign_max'] * 100:.2f}%"
                if a.get("irq_max") is not None:
                    state += f", interrupts and DPCs at most {a['irq_max'] * 100:.2f}%"
                out.append(f"  {arm}: {state}")
        names = sorted({n for a in arms.values() for n in a["median"]})
        for n in names:
            p = shown(arms.get("P", {}).get("median", {}).get(n), ".4g")
            w = shown(arms.get("W", {}).get("median", {}).get(n), ".4g")
            r = shown(row["w_over_p"].get(n), ".3f")
            line = f"    {n:<22} P {p:>12}  W {w:>12}  W/P {r:>7}"
            if "w_over_x" in row:
                x = shown(arms.get("X", {}).get("median", {}).get(n), ".4g")
                line += f"  X {x:>12}  W/X {shown(row['w_over_x'].get(n), '.3f'):>7}"
            out.append(f"{line}  ({METRICS.get(n, '?')} is better)")
    return out


def shown(value: float | None, spec: str) -> str:
    return "-" if value is None else format(value, spec)


# -- the runs -----------------------------------------------------------------------------------------------

def await_line(proc: Process, role: str, keys: tuple[str, ...], seconds: float) -> dict[str, str] | None:
    """The line of `role` that carries `keys` once `proc` printed it, waited for up to `seconds`; None when it was
    not printed by then, or the process ended without it."""
    deadline = time.monotonic() + seconds
    while True:
        ended = proc.reap(0)
        found = fields(proc.text(), role, keys)
        if found is not None or ended or time.monotonic() >= deadline:
            return found
        time.sleep(0.05)


class Matrix:
    def __init__(self, args: argparse.Namespace, run: pathlib.Path, absent: dict[tuple[str, str], str]):
        self.args = args
        self.run = run
        self.absent = absent
        self.cpus = sorted(set(cpu_list(args.client_cpus)) | set(cpu_list(args.server_cpus)))
        self.serial = 0

    def start(self, binary: str, role: str, argv: list[str], side: str, tag: str) -> Process:
        cpus = self.args.client_cpus if side == "client" else self.args.server_cpus
        program = [str(pathlib.Path(self.args.bin_dir) / binary), role, *argv]
        if self.args.trace_text:
            program = traced_command(program, pathlib.Path(self.args.trace_text) / f"{tag}.{role}")
        return Process(program, cpus, self.run / f"{tag}.{role}.out", {})

    def place(self, transport: str) -> tuple[list[str], list[str]]:
        self.serial += 1
        return endpoint_args(transport, 20000 + random.randrange(20000),
                             f"wz-perf-{os.getpid()}-{self.serial}")

    def timed(self, body) -> tuple[dict, float]:
        """Run `body` until it gave figures while the pinned CPUs were used by nothing else (up to six
        runs): the figures and the share of those CPUs something else used. A Lost from the body ends the
        cell at once."""
        shares = []
        for _ in range(MAX_RUNS):
            busy0, wall0 = busy_seconds(self.cpus), time.monotonic()
            figures, procs = body()
            wall = time.monotonic() - wall0
            own = sum(p.own_seconds() for p in procs)
            foreign = max(0.0, busy_seconds(self.cpus) - busy0 - own) / (wall * len(self.cpus))
            if foreign <= FOREIGN_LIMIT:
                return figures, foreign
            shares.append(f"{foreign * 100:.0f}%")
            time.sleep(5)
        raise Disturbed(f"the pinned CPUs were used by something else in {MAX_RUNS} runs ({', '.join(shares)})")

    def rtt(self, binary: str, transport: str, batching: bool, size: int, tag: str) -> tuple[dict, float]:
        args = self.args
        flags = ["-b"] if batching else []
        deadline = (args.warmup_ms / 1e3 + READY_S + args.pings * 1e-3
                    + (args.pings // 10 + 1) * args.timeout_ms / 1e3 + 30)

        def body():
            server, client = self.place(transport)
            pong = self.start(binary, "pong", ["-m", "peer", *server, *flags], "server", tag)
            ping = None
            try:
                time.sleep(SETTLE_S)
                ping = self.start(binary, "ping", ["-m", "peer", *client, "-s", str(size), "-n", str(args.pings),
                                                   "-w", str(args.warmup_ms), "-o", str(args.timeout_ms), *flags],
                                  "client", tag)
                done = ping.reap(deadline)
                ping.stop()
                pong.reap(5.0)
            finally:
                if ping is not None:
                    ping.stop()
                pong.stop()
            if not done:
                raise Lost(f"ping did not finish in {deadline:.0f} s")
            got = fields(ping.text(), "ping", PING_KEYS)
            if got is None:
                raise Lost(f"ping gave no result; it said: {last_words(ping.text())}; pong said: "
                           f"{last_words(pong.text())}")
            figures = rtt_figures(got, fields(pong.text(), "pong", PONG_KEYS), usage_of(ping), usage_of(pong))
            return figures, [ping, pong]

        return self.timed(body)

    def thr(self, binary: str, transport: str, batching: bool, size: int, tag: str) -> tuple[dict, float]:
        args = self.args
        flags = ["-b"] if batching else []
        pub_s = math.ceil(args.warmup_ms / 1e3 + args.window_s) + PUB_TAIL_S

        def body():
            server, client = self.place(transport)
            sub = self.start(binary, "sub", ["-m", "peer", *server, "-w", str(args.warmup_ms),
                                             "-t", str(args.window_s)], "server", tag)
            pub = None
            ended = False
            try:
                time.sleep(SETTLE_S)
                pub = self.start(binary, "pub", ["-m", "peer", *client, "-s", str(size), "-t", str(pub_s), *flags],
                                 "client", tag)
                # The publisher keeps its session after its result, so what it sent is not cut off by its close
                # while the subscriber still reads it; both are stopped once the subscriber said what reached it.
                if await_line(pub, "pub", PUB_KEYS, pub_s + READY_S + 30) is not None:
                    await_line(sub, "sub", SUB_MARK_KEYS, DRAIN_S if transport in STREAM_TRANSPORTS else MARK_WAIT_S)
                else:
                    ended = pub.reap(0)
            finally:
                if pub is not None:
                    pub.stop()
                sub.stop()
            put = fields(pub.text(), "pub", PUB_KEYS)
            got = fields(sub.text(), "sub", SUB_KEYS)
            if put is None:
                raise Lost(f"pub gave no result; it said: {last_words(pub.text())}" if ended
                           else "pub did not finish in time")
            if got is None:
                raise Lost(f"sub gave no window; it said: {last_words(sub.text())}")
            try:
                figures = thr_figures(put, got, usage_of(pub), usage_of(sub))
                missing = delivery(transport, put, fields(sub.text(), "sub", SUB_MARK_KEYS))
            except Lost as why:
                raise Lost(f"{why}; {stall_note(put, fields(sub.text(), 'sub', SUB_END_KEYS))}") from None
            if missing is not None:
                figures["undelivered"] = missing
            return figures, [pub, sub]

        return self.timed(body)

    def cell(self, arm: str, transport: str, batching: bool, workload: str, size: int, rep: int) -> dict:
        cell = {"arm": arm, "transport": transport, "batching": batching, "workload": workload, "size": size,
                "rep": rep}
        binary = binary_name(arm, transport, self.absent)
        if binary is None:
            cell.update(status="not-applicable", why=self.absent[(arm, transport)], figures={})
            return cell
        tag = f"r{rep}-{arm}-{transport}-{'b' if batching else 'n'}-{workload}-{size}"
        try:
            run = self.rtt if workload == "rtt" else self.thr
            figures, foreign = run(binary, transport, batching, size, tag)
            cell.update(status="measured", figures=figures, foreign_share=foreign)
        except Disturbed as why:
            cell.update(status="lost", why=str(why), figures={}, disturbed=True)
        except Lost as why:
            cell.update(status="lost", why=str(why), figures={})
        return cell


def first_line(cmd: list[str], cwd: pathlib.Path | None = None) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return out.splitlines()[0] if out else "unknown"


def run_engine(builds: dict) -> str | None:
    """The engine a run's arm W was built on, as the record of its build states it (`reference --engine`);
    `None` when it states none, or no engine."""
    engine = builds.get("wz_engine")
    return engine if engine in ENGINES else None


def run_stdlib(builds: dict) -> str | None:
    """The standard library a run's arm W was built with, as the record of its build states it (`reference
    --stdlib`); `None` when it states none, or no standard library."""
    stdlib = builds.get("wz_stdlib")
    return stdlib if stdlib in STDLIBS else None


def run_preset(builds: dict) -> str | None:
    """The preset a run's arm W was built as, as the record of its build states it (`reference` writes
    `wz_preset`); `None` when it states none, or no preset of PRESETS: a build of the crate's default features."""
    preset = builds.get("wz_preset")
    return preset if preset in PRESETS else None


def build_said(preset: str | None) -> str:
    """The build a preset names, in a sentence."""
    return f"{preset}'s preset" if preset is not None else "the crate's default features"


def host_record(args: argparse.Namespace) -> dict:
    cpu = "unknown"
    try:
        for line in pathlib.Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"],
                            capture_output=True, text=True)
    record = {
        "tree": first_line(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        # A tree with changes is not the commit named; None when git could not say.
        "tree_dirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
        "host": socket.gethostname(), "kernel": os.uname().release, "cpu": cpu, "threads": os.cpu_count(),
        "cc": first_line(["cc", "--version"]), "rustc": first_line(["rustc", "-V"], ROOT / "crates"),
        "client_cpus": args.client_cpus, "server_cpus": args.server_cpus, "reps": args.reps,
        "sizes": args.sizes, "pings": args.pings, "warmup_ms": args.warmup_ms, "window_s": args.window_s,
        "timeout_ms": args.timeout_ms, "foreign_limit": FOREIGN_LIMIT, "platform": DEFAULT_PLATFORM,
    }
    if args.reference_record:
        record["builds"] = json.loads(pathlib.Path(args.reference_record).read_text(encoding="utf-8"))
    record["engine"] = run_engine(record.get("builds") or {})
    record["stdlib"] = run_stdlib(record.get("builds") or {})
    record["preset"] = run_preset(record.get("builds") or {})
    record["external"] = (json.loads(pathlib.Path(args.external_record).read_text(encoding="utf-8"))
                          if args.external_record else
                          {"status": "not-measured", "why": "the run was given no record of arm X"})
    return record


def cmd_run(args: argparse.Namespace) -> int:
    transports = [t for t in args.transports.split(",") if t]
    workloads = [w for w in args.workloads.split(",") if w]
    batchings = [b for b in args.batching.split(",") if b]
    sizes = [int(s) for s in args.sizes.split(",") if s]
    unknown = ([t for t in transports if t not in TRANSPORTS] + [w for w in workloads if w not in WORKLOADS]
               + [b for b in batchings if b not in ("off", "on")])
    if unknown or not (transports and workloads and batchings and sizes):
        print(f"perf-matrix: unknown or empty selection {unknown}", flush=True)
        return 64
    if min(sizes) < 8:
        print("perf-matrix: a payload is at least 8 bytes (the round trip's sequence number)", flush=True)
        return 64
    record = host_record(args)
    if record["engine"] is None or record["stdlib"] is None:
        print("perf-matrix: NOT-MEASURED, the run names no record of the build it measures that states its "
              "engine and its standard library (--reference-record, written by `reference --engine --stdlib`)",
              flush=True)
        return 2
    w_features = (record.get("builds") or {}).get("wz_features")
    if not isinstance(w_features, list):
        print("perf-matrix: NOT-MEASURED, the record of the build the run measures lists no features of arm W "
              "(`wz_features`, written by `reference`), so which transports arm W carries is unknown", flush=True)
        return 2
    absent = not_applicable(w_features)
    arms = run_arms(record["external"])
    wanted = {binary_name(arm, t, absent) for arm in arms for t in transports} - {None}
    missing = sorted(b for b in wanted if not os.access(pathlib.Path(args.bin_dir) / b, os.X_OK))
    if missing:
        print(f"perf-matrix: NOT-MEASURED, {args.bin_dir} lacks {', '.join(missing)}", flush=True)
        return 2
    if "X" not in arms:
        print(f"perf-matrix: arm X NOT-MEASURED, {record['external'].get('why', 'no reason given')}", flush=True)
    if args.trace_text:
        if shutil.which(TEXT_TRACE_TOOL[0]) is None:
            print(f"perf-matrix: NOT-MEASURED, --trace-text runs the probes under {TEXT_TRACE_TOOL[0]}, which this "
                  "host has not", flush=True)
            return 2
        pathlib.Path(args.trace_text).mkdir(parents=True, exist_ok=True)
        record["text_trace"] = True
    run = pathlib.Path(args.run)
    run.mkdir(parents=True, exist_ok=False)
    record["started"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    matrix = Matrix(args, run, absent)
    plan = [(rep, transport, batching, size, workload, arm)
            for rep in range(1, args.reps + 1)
            for transport in transports
            for batching in batchings
            for size in sizes
            for workload in workloads
            for arm in (arms if rep % 2 else arms[::-1])]
    print(f"perf-matrix: {args.reps} repetition(s) of {', '.join(transports)} x batching {', '.join(batchings)} "
          f"x {', '.join(workloads)} x {', '.join(map(str, sizes))} B, arms {', '.join(arms)}; client side on "
          f"{args.client_cpus}, server side on {args.server_cpus}; arm W on the {record['engine']} engine, "
          f"{record['stdlib']}", flush=True)
    with (run / "cells.jsonl").open("w", encoding="utf-8") as log:

        def run_one(spec: tuple, again: bool) -> dict:
            rep, transport, batching, size, workload, arm = spec
            cell = matrix.cell(arm, transport, batching == "on", workload, size, rep)
            if again:
                cell["second_pass"] = True
            log.write(json.dumps(cell, sort_keys=True) + "\n")
            log.flush()
            shown = cell.get("why") or ", ".join(
                f"{k} {v:.4g}" for k, v in sorted(numbers(cell["figures"]).items())
                if k in ("rtt_p50_us", "rtt_p99_us", "msgs_per_s", "cpu_ns_per_msg"))
            print(f"  {'again ' if again else ''}r{rep} {arm} {transport} batching={batching} {workload} {size} B: "
                  f"{cell['status']}: {shown}", flush=True)
            return cell

        cells = [run_one(spec, False) for spec in plan]
        # A shared host is busy in stretches: a cell disturbed in every run of its first turn is run once
        # more at the end, when the stretch may be over, and the later result is the cell's.
        deferred = second_pass(cells)
        if deferred:
            print(f"perf-matrix: {len(deferred)} cell(s) were disturbed by the host; one more pass over them",
                  flush=True)
        for index in deferred:
            cells[index] = run_one(plan[index], True)
    record["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rows = summarize(cells)
    doc = {"schema": SCHEMA, "record": record, "metrics": METRICS, "cells": cells, "summary": rows}
    (run / "perf.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (run / "report.txt").write_text("\n".join(report_lines(rows)) + "\n", encoding="utf-8")
    print(f"perf-matrix: {sum(c['status'] == 'measured' for c in cells)} measured, "
          f"{sum(c['status'] == 'lost' for c in cells)} lost, "
          f"{sum(c['status'] == 'not-applicable' for c in cells)} not applicable; {run}/perf.json", flush=True)
    return 0


#: The size gate's case whose build arm W is built as, by the engine and the standard library of the run
#: (`capability_cost_gate.CASES`): its profile, its cargo configuration files and so its linker arguments, with
#: the bench's features in the place of the case's (`bench_case`). The library timed here is then built as the
#: library whose size the gate measures, and its reference zenoh-pico by the gate's rule for that build
#: (`capability_cost_gate.reference_build`): without `std`, C with no unwind tables, linked with the script
#: that discards what the C runtime still brings, as the size ratio of that form is read.
SHAPE_CASES = {("coop", "nostd"): "pico-client-coop-nostd"}
#: The tokio engine's library links `std` and unwinds, which no size case of the pico ABI builds any more (its
#: C library has no `std` form): it is built by the shipping profile with no configuration file, as the size
#: gate builds the zenoh-c ABI on the same engine.
TOKIO_SHAPE = "the tokio engine's own build"


def shape_name(engine: str, stdlib: str) -> str:
    """What arm W's form is built as, for a record and a line: its size case, or the tokio engine's own build."""
    if (engine, stdlib) == ("tokio", "std"):
        return TOKIO_SHAPE
    shape = SHAPE_CASES.get((engine, stdlib))
    if shape is None:
        raise Refused(f"no size case builds wz-capi-pico on the {engine} engine with {stdlib}")
    return shape


def bench_stdlib(stated: str, released: tuple[str, ...]) -> str:
    """The standard library a run builds arm W with: `stated` when the caller names one (PICO_CMP_STDLIB), to
    compare the two forms, else the one form the pico C ABI's release ships (`released`,
    `pico_windows_package.RELEASE_STDLIBS`, the one declaration of it), so a table filled by default reads what
    ships. A name that is no standard library, and a release of no form or of more than one with none named,
    are refused (Refused)."""
    if stated:
        if stated not in STDLIBS:
            raise Refused(f"`{stated}` is no standard library arm W is built with; one of {', '.join(STDLIBS)}")
        return stated
    if len(released) != 1 or released[0] not in STDLIBS:
        raise Refused(f"the release ships {', '.join(released) or 'no form'}, so a run names the standard library "
                      f"it measures (PICO_CMP_STDLIB, one of {', '.join(STDLIBS)})")
    return released[0]


def bench_case(arm: str, engine: str, stdlib: str, named: list[str]):
    """Arm `arm`'s build as a case of the size gate: the case of its form (SHAPE_CASES) with the bench's feature
    list `named` (`wz_config.preset_named_features`, zenoh-pico's preset on the run's engine) in the place of
    the case's, or on the tokio engine that list alone. A form no case builds is refused (Refused)."""
    import capability_cost_gate as cost

    shape = shape_name(engine, stdlib)
    features = ",".join(named)
    if shape == TOKIO_SHAPE:
        return cost.Case(f"perf-{arm}", "wz-capi-pico", "libwz_capi_pico.so", features, 0)
    base = {case.id: case for case in cost.CASES}[shape]
    return cost.Case(f"perf-{arm}", base.package, base.lib, features, 0, profile=base.profile,
                     cargo_configs=base.cargo_configs)


def built_as(case) -> str:
    """The crate and features cargo builds `case` as (`capability_cost_gate.case_build`): a case names the ABI
    crate and its features, and the build is of the pico C library crate, the features through its dependency."""
    import capability_cost_gate as cost

    return f"-p {cost.artifact_package(case.package)} --features {cost.artifact_features(case.package, case.features)}"


def cmd_reference(out: pathlib.Path, engine: str, stdlib: str) -> int:
    """zenoh-pico built as the same build as wz-capi-pico for zenoh-pico's preset on `engine` with `stdlib`,
    by the size gate's rule for arm W's form, into `out`."""
    # The gate's builder and resolver, imported here and not at the top: the selftest needs neither.
    import capability_cost_gate as cost
    import wz_config

    table = wz_config.manifest_features(wz_config.MANIFESTS["pico"])
    decl = wz_config.load_decl()
    try:
        kconf = wz_config.pico_bench_configuration()
        features = wz_config.preset_features(engine, [], table, stdlib, decl, kconf)
        program_features = wz_config.preset_features(engine, ["app-transport"], table, stdlib, decl, kconf)
        shape = bench_case("W", engine, stdlib,
                           wz_config.preset_named_features(engine, [], table, stdlib, decl, kconf))
    except (wz_config.PresetError, KeyError, ValueError, OSError, Refused) as error:
        print(f"perf-matrix: NOT-MEASURED, {error}", flush=True)
        return 2
    asked = wz_config.pico_reference(decl, features)
    # The gate's build rule too: the reference's key holds the rule's C flags and epoch, so the
    # library timed here is the one the gate's size and ratio are read from.
    try:
        env, _ = cost.build_env()
    except ValueError as error:
        print(f"perf-matrix: NOT-MEASURED, the build normalisation refused this host: {error}", flush=True)
        return 2
    # Linked and compiled as the gate builds the reference of arm W's form, from the linker arguments arm W's
    # build is given (`wz-arm` builds it by the same plan).
    try:
        plan = cost.case_build(shape, env)
    except wz_config.PresetError as error:
        print(f"perf-matrix: NOT-MEASURED, the limits of arm W's build did not resolve: {error}", flush=True)
        return 2
    link, cflags = cost.reference_build(plan.link_args)
    work, pin, toolchain = cost.pico_reference_tree(asked, env, link, cflags)
    header = work / "build" / "include" / "zenoh-pico" / "config.h"
    refused = cost.refused_switches(asked, header.read_text(encoding="utf-8"))
    lib = out / "lib-P"
    inc = out / "include-P"
    for stale in (lib, inc):
        if stale.exists():
            shutil.rmtree(stale)
    lib.mkdir(parents=True)
    libraries = sorted((work / "build" / "lib").glob("libzenohpico.so*"))
    if not libraries:
        print(f"perf-matrix: NOT-MEASURED, no libzenohpico.so under {work / 'build' / 'lib'}", flush=True)
        return 2
    for path in libraries:
        shutil.copy2(path, lib / path.name, follow_symlinks=False)
    # pico's headers are its source tree's, with the config.h its CMake generated for this build on top.
    shutil.copytree(work / "src" / "include", inc, symlinks=True)
    shutil.copytree(work / "build" / "include", inc, dirs_exist_ok=True)
    record = {"reference_pin": pin, "reference_toolchain": toolchain, "reference_switches": asked,
              "reference_refused": refused, "reference_link_args": list(link), "reference_cflags": list(cflags),
              "wz_features": sorted(features), "wz_program_transport_features": sorted(program_features),
              "wz_engine": engine, "wz_stdlib": stdlib, "wz_preset": wz_config.PICO_BENCH_ORIGINAL,
              "wz_build": {"size_case": shape_name(engine, stdlib), "profile": shape.profile,
                           "cargo_configs": list(shape.cargo_configs), "link_args": list(plan.link_args)}}
    (out / "reference.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"perf-matrix: reference zenoh-pico {pin[:12]} as the same build ({toolchain}); "
          f"{len(asked)} switches set from the declaration; linked with {list(link)} and compiled with "
          f"{list(cflags)} beyond the rule's, as the size gate builds the reference of "
          f"{shape_name(engine, stdlib)}", flush=True)
    if refused:
        print(f"perf-matrix: pico built {', '.join(refused)} otherwise than asked, so the two builds differ "
              f"there (reference.json says so)", flush=True)
    return 0


def cmd_wz_arm(out: pathlib.Path, arm: str, engine: str, stdlib: str, asked: list[str]) -> int:
    """Arm `arm`, wz-capi-pico-lib: zenoh-pico's preset on `engine` with `stdlib` and the capabilities `asked`,
    built as the size gate builds the case of its form (`bench_case`, `capability_cost_gate.case_build` in the
    gate's `build_env`), its library copied to OUT/lib-ARM and pico's headers to OUT/include-ARM. The headers are
    the reference export's (`reference` writes OUT/include-P first), the pinned pico's own, with the config.h of
    this build's feature list in the place of the reference's: a program compiled against another config.h
    allocates the option structs of another build."""
    import capability_cost_gate as cost
    import wz_config

    table = wz_config.manifest_features(wz_config.MANIFESTS["pico"])
    decl = wz_config.load_decl()
    try:
        kconf = wz_config.pico_bench_configuration()
        named = wz_config.preset_named_features(engine, asked, table, stdlib, decl, kconf)
        header = wz_config.pico_config_header(decl, wz_config.enabled_features(table, named), dict(os.environ))
        case = bench_case(arm, engine, stdlib, named)
        env, _ = cost.build_env()
        plan = cost.case_build(case, env)
    except (wz_config.PresetError, KeyError, ValueError, OSError, Refused) as error:
        print(f"perf-matrix: NOT-MEASURED, arm {arm}: {error}", flush=True)
        return 2
    conflicts = wz_config.pico_header_conflicts(decl, "pico", header)
    if conflicts:
        print(f"perf-matrix: NOT-MEASURED, the config.h of arm {arm} reads back as another build: "
              f"{'; '.join(conflicts)}", flush=True)
        return 2
    reference_include = out / "include-P"
    if not (reference_include / "zenoh-pico" / "config.h").is_file():
        print(f"perf-matrix: NOT-MEASURED, {reference_include} holds no headers of the reference: run "
              "`reference` first", flush=True)
        return 2
    log = out / f"build-wz-{arm}.log"
    with log.open("w", encoding="utf-8") as stream:
        built = subprocess.run(list(plan.cmd), cwd=cost.CRATES, env=dict(plan.env), stdout=stream,
                               stderr=subprocess.STDOUT)
    if built.returncode != 0:
        print(f"perf-matrix: NOT-MEASURED, arm {arm} ({built_as(case)}) did not build (see {log})", flush=True)
        return 2
    lib = out / f"lib-{arm}"
    inc = out / f"include-{arm}"
    for stale in (lib, inc):
        if stale.exists():
            shutil.rmtree(stale)
    lib.mkdir(parents=True)
    shutil.copy2(plan.lib, lib / plan.lib.name)
    shutil.copytree(reference_include, inc, symlinks=True)
    (inc / "zenoh-pico" / "config.h").write_text(header, encoding="utf-8")
    print(f"perf-matrix: arm {arm}: {built_as(case)} on the {engine} engine, {stdlib}, built as the size gate's "
          f"{shape_name(engine, stdlib)} (profile {case.profile}, {list(case.cargo_configs) or 'no'} cargo "
          f"configuration, linker arguments {list(plan.link_args)}), {len(named)} feature(s) named, under "
          f"{len(plan.limits)} limit and policy value(s) of its ABI's own preset", flush=True)
    return 0


def cmd_preset_arm(out: pathlib.Path, original: str, stdlib: str) -> int:
    """Arm W of the parity matrix (docs/upstream-parity.md section 5b) for the pico family: wz-capi-pico-lib for
    configs/<original>_defconfig alone, its features from the one resolver's configuration
    (`wz_config.configuration_of`), with `stdlib`, built as the size gate builds the case of that form
    (`bench_case`, `capability_cost_gate.case_build` in the gate's `build_env`), and so under the limits and
    policies of that same configuration (`capability_cost_gate.case_limits`, `wz_config.build_of`), so the
    parity's size and memory cells read the library a release ships unless told another form; its library copied
    to OUT/lib-W and its build's log to OUT/build-wz.log. The two lines it prints are the run record's."""
    import capability_cost_gate as cost
    import wz_config

    if wz_config.BASE_ABI.get(original) != "pico":
        print(f"perf-matrix: NOT-MEASURED, `{original}` is no original built through the pico ABI", flush=True)
        return 2
    table = wz_config.manifest_features(wz_config.MANIFESTS["pico"])
    decl = wz_config.load_decl()
    try:
        named = wz_config.resolved_features(decl, "pico", wz_config.configuration_of("pico", []))
        engine = wz_config.statement_engine("pico", wz_config.enabled_features(table, named))
        if engine != "coop":
            raise Refused(f"configs/{original}_defconfig builds the {engine} engine, and arm W is built in a "
                          "form of the cooperative one")
        wz_config.engine_stdlib(engine, stdlib)
        case = bench_case("W", engine, stdlib, named)
        env, _ = cost.build_env()
        plan = cost.case_build(case, env)
    except (wz_config.PresetError, KeyError, ValueError, OSError, Refused) as error:
        print(f"perf-matrix: NOT-MEASURED, arm W of {original}: {error}", flush=True)
        return 2
    with (out / "build-wz.log").open("w", encoding="utf-8") as stream:
        built = subprocess.run(list(plan.cmd), cwd=cost.CRATES, env=dict(plan.env), stdout=stream,
                               stderr=subprocess.STDOUT)
    if built.returncode != 0:
        print(f"perf-matrix: NOT-MEASURED, arm W of {original} ({built_as(case)}) did not build "
              f"(see {out / 'build-wz.log'})", flush=True)
        return 2
    lib = out / "lib-W"
    lib.mkdir(parents=True, exist_ok=True)
    shutil.copy2(plan.lib, lib / plan.lib.name)
    print(f"wz_build={built_as(case)}; stdlib {stdlib}, profile {case.profile}, "
          f"cargo configuration {list(case.cargo_configs) or 'none'}, linker arguments {list(plan.link_args)} "
          f"(the size gate's {shape_name(engine, stdlib)})", flush=True)
    print(f"wz_build_env={' '.join(plan.limits)}", flush=True)
    return 0


# -- arm X: an external library of the pico API ------------------------------------------------------------

#: The variables that name arm X. The library and its headers are a deployment's; the repository holds only
#: this mechanism, so their name, paths and figures are written to the run's local files and nowhere else.
EXTERNAL_LIB = "WZ_PERF_EXTERNAL_LIB"
EXTERNAL_INCLUDE = "WZ_PERF_EXTERNAL_INCLUDE"
EXTERNAL_NAME = "WZ_PERF_EXTERNAL_NAME"
#: The table of W over X, which holds the deployment's figures and so lives outside the repository.
EXTERNAL_TABLE = "WZ_PERF_EXTERNAL_TABLE"


def sha256_of(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def external_record(env: dict[str, str], why: str) -> dict:
    """The record of arm X: not measured, with `why`, or built from what the environment names, with the
    digests of the library and of its config.h so a run says which build it timed."""
    if why:
        return {"status": "not-measured", "why": why}
    lib = pathlib.Path(env[EXTERNAL_LIB]).resolve()
    config = pathlib.Path(env[EXTERNAL_INCLUDE]).resolve() / "zenoh-pico" / "config.h"
    return {"status": "built", "name": env.get(EXTERNAL_NAME) or "unnamed", "library": str(lib),
            "library_sha256": sha256_of(lib), "config_h": str(config), "config_h_sha256": sha256_of(config)}


def run_arms(external: dict) -> tuple[str, ...]:
    """The arms a run measures: P and W always, X when its record says it was built."""
    return ARMS if external.get("status") == "built" else ("P", "W")


def cmd_external_record(out: pathlib.Path, why: str) -> int:
    try:
        record = external_record(dict(os.environ), why)
    except (KeyError, OSError) as error:
        print(f"perf-matrix: the record of arm X could not be made: {error}", file=sys.stderr)
        return 2
    out.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


# -- the gate -------------------------------------------------------------------------------------------------

#: The committed tables of W over P: of runs on Linux, and of runs on Windows. A platform's rows are filled
#: from its own runs and judge only those: the two hosts differ in their sockets, scheduler and clocks, so a
#: ratio read on one says nothing of the other.
CEILING = ROOT / "deploy" / "pico_perf_ceiling.json"
CEILING_WINDOWS = ROOT / "deploy" / "pico_perf_ceiling_windows.json"
#: The platforms a run is made on (`record.platform`, a table's `platform`), each with its committed table. A
#: run or a table that names none is Linux's, as every one was before the field.
PLATFORMS = {"linux": CEILING, "windows-x64": CEILING_WINDOWS}
DEFAULT_PLATFORM = "linux"
#: The most of the pinned CPUs something other than a cell's two processes may take while the cell is read
#: (`foreign_limit` of a run's record), per platform; a cell over it is run again (`max_runs`). Linux's is
#: nodrop's. Windows' is held far lower: on the Windows host a share of 0.2 to 1.1% split each arm's
#: repetitions of a round trip's p99 between about 60 us and 150 to 180 us and let a run of three
#: repetitions set ceilings of 1.5 to 3.0 that no library caused, where the readings of a quiet host share
#: at most WINDOWS_FOREIGN_LIMIT: 94 of 96 cells of two quiet runs shared 0.17% or less, the other two
#: 0.48 and 0.55% (docs/c-abi-migration/win-p99.md section 2).
WINDOWS_FOREIGN_LIMIT = 0.002
FOREIGN_LIMITS = {"linux": FOREIGN_LIMIT, "windows-x64": WINDOWS_FOREIGN_LIMIT}
TABLE_SCHEMA = "wz-pico-perf-ceiling/1"
#: The engines arm W is built on, as `wz_config.PICO_ENGINES` names them: a run records the one it measured
#: and a table the one its rows were filled from, and the gate refuses a run against another engine's rows.
ENGINES = ("tokio", "coop")
#: The standard libraries arm W is built with, as `wz_config.PICO_STDLIBS` names them: a run records the one it
#: measured and a table the one its rows were filled from, and the gate refuses a run against another's rows, as
#: it refuses another engine's.
STDLIBS = ("std", "nostd")
#: The standard library of a reading that names none: every library was built with `std` before the field.
UNSTATED_STDLIB = "std"
#: The builds arm W is compared as, by the original whose preset in wz it is (`wz_config.PICO_BENCH_ORIGINAL`):
#: a run records the one its build states (`reference` writes `wz_preset`) and a table the one its rows were
#: filled from, and the gate refuses a run against another build's rows. A run that states none measured the
#: crate's default features, which carry planes zenoh-pico's own build has not.
PRESETS = ("zenoh-pico",)
PAIR_NAMES = {"P": "W/P", "X": "W/X"}
#: The figures the gate holds, per workload: the round trip at its middle and its tail, the CPU the
#: answering side spent per answer, the delivered rate and the CPU a delivered message cost both sides, and
#: the peak resident set. ping's CPU is not held: it holds the probe's own spin while it waits, so it is the
#: round trip again. The two sides of cpu_ns_per_msg are held as their sum.
GATED = {"rtt": ("rtt_p50_us", "rtt_p99_us", "pong_cpu_ns_per_rtt", "rss_kib"),
         "thr": ("msgs_per_s", "cpu_ns_per_msg", "rss_kib")}
#: The measured repetitions each arm needs before a cell has an interval.
MIN_REPS = 3
#: The tolerance a new table of W over X is written with; a table states its own.
DEFAULT_TOLERANCE = 0.05
ROW_KINDS = ("locked", "ratio_at_most", "reference_lost")


class Refused(Exception):
    """An input the gate cannot judge by: a file it cannot read, or a table of the wrong shape."""


def row_key(transport: str, batching: bool, workload: str, size: int, metric: str) -> str:
    return f"{transport}/{'on' if batching else 'off'}/{workload}/{size}/{metric}"


def key_order(key: str) -> tuple:
    """The order the matrix runs its cells in, and each workload's held figures in the order GATED names them."""
    transport, batching, workload, size, metric = key.split("/")
    held = GATED.get(workload, ())
    return (TRANSPORTS.index(transport) if transport in TRANSPORTS else len(TRANSPORTS), batching, workload,
            int(size) if size.isdigit() else 0, held.index(metric) if metric in held else len(held), metric)


def population(ref: str, absent: dict[tuple[str, str], str], sizes: tuple[int, ...] = DEFAULT_SIZES) -> list[str]:
    """Every row a full run of the matrix gives the pair of W and `ref`: each transport both arms have
    (`absent`, of `not_applicable`), both batchings, both workloads, each size and each held figure."""
    return [row_key(t, b, w, s, m)
            for t in TRANSPORTS if binary_name("W", t, absent) and binary_name(ref, t, absent)
            for b in (False, True) for w in WORKLOADS for s in sizes for m in GATED[w]]


def ceil3(value: float) -> float:
    """`value` rounded up to three decimals, so the reading a ratchet is written from passes it."""
    return math.ceil(value * 1000 - 1e-9) / 1000


@dataclass(frozen=True)
class Reading:
    """What a run says of one row: `ratio` with the cost ratio, its interval and its verdict, or why it has
    none (`wz-lost`, `reference-lost`, `too-few`)."""

    state: str
    why: str = ""
    point: float = 0.0
    lo: float = 0.0
    hi: float = 0.0
    verdict: str = ""

    def shown(self) -> str:
        return f"{self.verdict}, cost ratio {self.point:.3f} [{self.lo:.3f}, {self.hi:.3f}]"


def cost_ratio(metric: str, wz: list[float], ref: list[float]) -> tuple[float, float, float]:
    """The cost ratio of a figure and its 95% bootstrap interval: wz over the reference when the figure is
    better lower, the reference over wz when better higher, so below 1 is wz ahead either way."""
    return bootstrap_ratio(wz, ref) if METRICS[metric] == "lower" else bootstrap_ratio(ref, wz)


def verdict_of(lo: float, hi: float) -> str:
    return "WIN" if hi < 1.0 else "LOSS" if lo > 1.0 else "TIE"


def readings(cells: list[dict], ref: str) -> dict[str, Reading]:
    """Every row of the pair of W and `ref` that a run's cells have, read. A repetition the host disturbed
    is no repetition; any other lost repetition of wz fails its rows, since what wz could not do once is a
    defect, not noise. A reference that lost every repetition leaves its rows without a ratio."""
    groups: dict[tuple, dict[str, dict]] = {}
    for cell in cells:
        key = (cell["transport"], cell["batching"], cell["workload"], cell["size"])
        arm = groups.setdefault(key, {}).setdefault(cell["arm"], {"figures": [], "lost": [], "na": False})
        if cell["status"] == "measured":
            arm["figures"].append(numbers(cell["figures"]))
        elif cell["status"] == "lost" and not cell.get("disturbed"):
            arm["lost"].append(f"r{cell['rep']}: {cell.get('why', 'no reason given')}")
        elif cell["status"] == "not-applicable":
            arm["na"] = True
    out: dict[str, Reading] = {}
    for (transport, batching, workload, size), arms in groups.items():
        wz, other = arms.get("W"), arms.get(ref)
        if wz is None or other is None or wz["na"] or other["na"]:
            continue
        for metric in GATED.get(workload, ()):
            key = row_key(transport, batching, workload, size, metric)
            if wz["lost"]:
                out[key] = Reading("wz-lost", f"wz lost {len(wz['lost'])} repetition(s) ({wz['lost'][0]})")
                continue
            if not other["figures"] and other["lost"]:
                out[key] = Reading("reference-lost", f"the reference lost every repetition ({other['lost'][0]})")
                continue
            ws = [f[metric] for f in wz["figures"] if f.get(metric, 0) > 0]
            rs = [f[metric] for f in other["figures"] if f.get(metric, 0) > 0]
            if len(ws) < MIN_REPS or len(rs) < MIN_REPS:
                out[key] = Reading("too-few", f"{len(ws)} repetition(s) of wz and {len(rs)} of the reference gave "
                                              f"{metric}, and an interval needs {MIN_REPS} of each")
                continue
            point, lo, hi = cost_ratio(metric, ws, rs)
            out[key] = Reading("ratio", point=point, lo=lo, hi=hi, verdict=verdict_of(lo, hi))
    return out


def fill_row(reading: Reading | None) -> dict | None:
    """The row a reading writes: WIN is locked at once, any other ratio is a ratchet at the upper end of its
    interval, a reference that lost the cell says so; a reading with no ratio writes nothing."""
    if reading is None:
        return None
    if reading.state == "ratio":
        return {"locked": True} if reading.verdict == "WIN" else {"ratio_at_most": ceil3(reading.hi)}
    if reading.state == "reference-lost":
        return {"reference_lost": reading.why}
    return None


@dataclass(frozen=True)
class Judged:
    """One row's outcome (PASS, FAIL, NOT-MEASURED), the sentence that says why, and the row to write in
    its place when the gate has one to suggest."""

    key: str
    outcome: str
    sentence: str
    edit: dict | None = None
    reading: Reading | None = None


def judge(found: dict[str, Reading], rows: dict, tolerance: float) -> list[Judged]:
    """Every row of the table and every row the run has, judged."""
    out = []
    for key in sorted(set(found) | set(rows), key=key_order):
        reading = found.get(key)
        fill = fill_row(reading)
        if reading is None:
            out.append(Judged(key, "NOT-MEASURED", "this run did not measure the cell"))
            continue
        if key not in rows:
            out.append(Judged(key, "FAIL", "the run has this cell and the table has no row for it: a row is added "
                                           "with the cell, never left out", fill, reading))
            continue
        row = rows[key]
        if row is None:
            how = ("paste the row below" if fill is not None
                   else f"this run cannot fill it ({reading.why})")
            out.append(Judged(key, "FAIL", f"the row is not filled; {how}", fill, reading))
            continue
        if reading.state == "wz-lost":
            out.append(Judged(key, "FAIL", reading.why, None, reading))
        elif reading.state == "too-few":
            out.append(Judged(key, "NOT-MEASURED", reading.why, None, reading))
        elif reading.state == "reference-lost":
            if "reference_lost" in row:
                out.append(Judged(key, "PASS", f"the reference still loses this cell: {reading.why}", None, reading))
            else:
                out.append(Judged(key, "NOT-MEASURED", f"{reading.why}, so the row is not judged", None, reading))
        elif "reference_lost" in row:
            out.append(Judged(key, "FAIL", f"the reference measures this cell now ({reading.shown()}); write the "
                                           f"row from the reading", fill, reading))
        elif row.get("locked"):
            if reading.verdict == "WIN":
                out.append(Judged(key, "PASS", reading.shown(), None, reading))
            else:
                out.append(Judged(key, "FAIL", f"locked to WIN, and this run read {reading.shown()}", None, reading))
        else:
            limit = row["ratio_at_most"]
            if reading.hi > limit * (1 + tolerance):
                out.append(Judged(key, "FAIL", f"{reading.shown()}: the upper end exceeds the ratchet {limit} by more "
                                               f"than the tolerance {tolerance}", None, reading))
            elif reading.verdict == "WIN":
                out.append(Judged(key, "PASS", f"{reading.shown()}: a WIN, so lock the row", {"locked": True},
                                  reading))
            elif ceil3(reading.hi) < limit:
                out.append(Judged(key, "PASS", f"{reading.shown()}: under the ratchet {limit}, so tighten it",
                                  {"ratio_at_most": ceil3(reading.hi)}, reading))
            else:
                out.append(Judged(key, "PASS", f"{reading.shown()}: within the ratchet {limit}", None, reading))
    return out


def debts(judged: list[Judged]) -> list[Judged]:
    """The rows a run read as a ratio that is not a WIN, the largest upper end first: the order they are paid
    in."""
    owed = [j for j in judged if j.reading is not None and j.reading.state == "ratio" and j.reading.verdict != "WIN"]
    return sorted(owed, key=lambda j: -j.reading.hi)


def outcome_of(judged: list[Judged]) -> str:
    outcomes = {j.outcome for j in judged}
    return "FAIL" if "FAIL" in outcomes else "NOT-MEASURED" if "NOT-MEASURED" in outcomes or not judged else "PASS"


def exit_status(outcomes: list[str]) -> int:
    return 1 if "FAIL" in outcomes else 3 if "NOT-MEASURED" in outcomes else 0


def refuse_duplicates(pairs: list[tuple[str, object]]) -> dict:
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise Refused(f"the key {key} is written twice")
        seen[key] = value
    return seen


def row_error(value: object) -> str | None:
    """Why a row of a table is malformed, or None when it is one of the four shapes."""
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) != 1 or next(iter(value)) not in ROW_KINDS:
        return f"a row is null or an object of one of {', '.join(ROW_KINDS)}, not {json.dumps(value)}"
    kind, given = next(iter(value.items()))
    if kind == "locked" and given is not True:
        return "`locked` is true or the row is something else"
    if kind == "ratio_at_most" and (isinstance(given, bool) or not isinstance(given, (int, float)) or given <= 0):
        return "`ratio_at_most` is a positive number"
    if kind == "reference_lost" and (not isinstance(given, str) or not given.strip()):
        return "`reference_lost` says why, in words"
    return None


def parse_table(text: str, pair: str) -> tuple[dict, float]:
    """The rows and the tolerance of a table of `pair` (W/P or W/X)."""
    try:
        doc = json.loads(text, object_pairs_hook=refuse_duplicates)
    except ValueError as error:
        raise Refused(f"not JSON: {error}") from None
    if not isinstance(doc, dict) or doc.get("schema") != TABLE_SCHEMA:
        raise Refused(f"the schema is not {TABLE_SCHEMA}")
    if doc.get("pair") != pair:
        raise Refused(f"the table is of the pair {doc.get('pair')}, and this one judges {pair}")
    tolerance = doc.get("tolerance")
    if isinstance(tolerance, bool) or not isinstance(tolerance, (int, float)) or not 0 <= tolerance < 1:
        raise Refused("`tolerance` is a number from 0 up to, not including, 1")
    rows = doc.get("rows")
    if not isinstance(rows, dict):
        raise Refused("`rows` is an object of row keys")
    for key, value in rows.items():
        parts = key.split("/")
        if len(parts) != 5 or parts[1] not in ("off", "on") or not parts[3].isdigit():
            raise Refused(f"{key} is not <transport>/<off|on>/<workload>/<size>/<figure>")
        error = row_error(value)
        if error:
            raise Refused(f"{key}: {error}")
    return rows, float(tolerance)


def table_engine(text: str) -> str | None:
    """The engine a table says its rows were filled from, `None` when it says none; one that is no
    engine is refused."""
    try:
        doc = json.loads(text)
    except ValueError as error:
        raise Refused(f"not JSON: {error}") from None
    engine = doc.get("engine") if isinstance(doc, dict) else None
    if engine is not None and engine not in ENGINES:
        raise Refused(f"`engine` is one of {', '.join(ENGINES)}, not {engine!r}")
    return engine


def table_stdlib(text: str) -> str | None:
    """The standard library a table says arm W was built with when its rows were filled, `None` when it says
    none; one that is no standard library is refused."""
    try:
        doc = json.loads(text)
    except ValueError as error:
        raise Refused(f"not JSON: {error}") from None
    stdlib = doc.get("stdlib") if isinstance(doc, dict) else None
    if stdlib is not None and stdlib not in STDLIBS:
        raise Refused(f"`stdlib` is one of {', '.join(STDLIBS)}, not {stdlib!r}")
    return stdlib


def table_preset(text: str) -> str | None:
    """The preset a table says arm W was built as when its rows were filled, `None` when it says none; one that
    is no preset of PRESETS is refused."""
    try:
        doc = json.loads(text)
    except ValueError as error:
        raise Refused(f"not JSON: {error}") from None
    preset = doc.get("preset") if isinstance(doc, dict) else None
    if preset is not None and preset not in PRESETS:
        raise Refused(f"`preset` is one of {', '.join(PRESETS)}, not {preset!r}")
    return preset


def preset_named(record: object, what: str) -> str | None:
    """The preset a run's record names, `None` when it names none (arm W built of the crate's default features);
    one that is no preset of PRESETS is refused."""
    preset = record.get("preset") if isinstance(record, dict) else None
    if preset is not None and preset not in PRESETS:
        raise Refused(f"{what} names the preset {preset!r}, and arm W is built as one of {', '.join(PRESETS)}")
    return preset


def stdlib_named(record: object, what: str) -> str:
    """The standard library a run's record names, `std` when it names none (UNSTATED_STDLIB); one that is no
    standard library is refused."""
    stdlib = record.get("stdlib") if isinstance(record, dict) else None
    if stdlib is None:
        return UNSTATED_STDLIB
    if stdlib not in STDLIBS:
        raise Refused(f"{what} names the standard library {stdlib!r}, and arm W is built with one of "
                      f"{', '.join(STDLIBS)}")
    return stdlib


def platform_named(doc: object, what: str) -> str:
    """The platform a run's record or a table names, Linux when it names none; one that is no platform of
    PLATFORMS is refused."""
    platform = doc.get("platform") if isinstance(doc, dict) else None
    if platform is None:
        return DEFAULT_PLATFORM
    if platform not in PLATFORMS:
        raise Refused(f"{what} names the platform {platform!r}, and a run is made on one of {', '.join(PLATFORMS)}")
    return platform


def limit_said(record: object, platform: str, what: str) -> None:
    """Refuse a run whose cells were let share their CPUs more than its platform allows (FOREIGN_LIMITS): its
    rows would be read off a host busier than the rows of a table may be. A record that states no limit was
    run under its platform's, as every Linux run was before the field."""
    limit = FOREIGN_LIMITS[platform]
    said = record.get("foreign_limit", limit) if isinstance(record, dict) else limit
    if isinstance(said, bool) or not isinstance(said, (int, float)) or said > limit:
        raise Refused(f"{what} let a cell's pinned CPUs be shared up to {said!r}, and a run on {platform} is read "
                      f"at a share of at most {limit}: run it again with a plan of this tree")


def table_platform(text: str) -> str:
    """The platform a table's rows were filled on."""
    try:
        doc = json.loads(text)
    except ValueError as error:
        raise Refused(f"not JSON: {error}") from None
    return platform_named(doc, "the table")


def load_table(path: pathlib.Path, pair: str) -> tuple[dict, float, str | None, str, str | None, str | None]:
    """The rows, the tolerance, the engine, the platform, the standard library and the preset of the table at
    `path`."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise Refused(f"{path} cannot be read: {error}") from None
    try:
        rows, tolerance = parse_table(text, pair)
        return (rows, tolerance, table_engine(text), table_platform(text), table_stdlib(text),
                table_preset(text))
    except Refused as why:
        raise Refused(f"{path}: {why}") from None


def inside(path: pathlib.Path, roots: list[pathlib.Path]) -> bool:
    resolved = path.resolve()
    return any(resolved == root or root in resolved.parents for root in roots)


def repository_roots() -> list[pathlib.Path]:
    """This checkout, and the main checkout of its repository when this is a worktree of it: a table of
    the deployment's figures may sit in neither."""
    roots = [ROOT.resolve()]
    common = first_line(["git", "-C", str(ROOT), "rev-parse", "--path-format=absolute", "--git-common-dir"])
    if common != "unknown":
        roots.append(pathlib.Path(common).resolve().parent)
    return roots


def table_document(pair: str, rows: dict, tolerance: float, engine: str, platform: str, stdlib: str,
                   preset: str | None) -> str:
    return json.dumps({"schema": TABLE_SCHEMA, "pair": pair, "engine": engine, "platform": platform,
                       "stdlib": stdlib, "preset": preset, "tolerance": tolerance, "rows": rows}, indent=1)


def print_pair(pair: str, table: str, tolerance: float | None, judged: list[Judged]) -> str:
    """The pair's rows that did not simply pass, the rows to write, the debts, and the pair's outcome."""
    outcome = outcome_of(judged)
    counts = {o: sum(j.outcome == o for j in judged) for o in ("PASS", "FAIL", "NOT-MEASURED")}
    print(f"perf-gate {pair}: {len(judged)} row(s), {counts['PASS']} pass, {counts['FAIL']} fail, "
          f"{counts['NOT-MEASURED']} not measured (table {table}, tolerance {tolerance})", flush=True)
    for j in judged:
        if j.outcome != "PASS" or j.edit is not None:
            print(f"  {j.outcome} {j.key}: {j.sentence}", flush=True)
    edits = {j.key: j.edit for j in judged if j.edit is not None}
    if edits:
        print(f"perf-gate {pair}: rows to write into the table's `rows` (each replaces the row of its key):",
              flush=True)
        for key, value in edits.items():
            print(f"  {json.dumps(key)}: {json.dumps(value)},", flush=True)
    owed = debts(judged)
    if owed:
        print(f"perf-gate {pair}: {len(owed)} cell(s) not WIN, the debts, largest ratio first:", flush=True)
        for j in owed:
            print(f"  {j.key}: {j.reading.shown()}", flush=True)
    print(f"perf-gate {pair}: {outcome}", flush=True)
    return outcome


def gate_pair(ref: str, cells: list[dict], table: pathlib.Path | None, roots: list[pathlib.Path],
              engine: str, platform: str, stdlib: str, preset: str | None) -> str:
    """Judge the pair of W and `ref`, arm W measured on `engine` with `stdlib` and built as `preset` in a run on
    `platform`. A table of W over X inside the repository is refused; one that is not named, or does not exist
    yet, fails with the whole table to write printed. A table whose rows were filled from another engine, another
    standard library, another build or on another platform is refused, and so is a table of W over P that does not
    say its engine, its standard library or its build."""
    pair = PAIR_NAMES[ref]
    found = readings(cells, ref)
    if ref == "X":
        if table is not None and inside(table, roots):
            raise Refused(f"{table} is inside the repository; the table of W/X holds the external library's "
                          f"figures and lives outside it")
        if table is None or not table.exists():
            where = (f"name a file outside the repository in {EXTERNAL_TABLE}" if table is None
                     else f"{table} does not exist")
            rows = {key: fill_row(found[key]) for key in sorted(found, key=key_order)}
            print(f"perf-gate {pair}: arm X was measured and no table judges it ({where}); the table this run "
                  f"writes, to be kept outside the repository:", flush=True)
            print(table_document(pair, rows, DEFAULT_TOLERANCE, engine, platform, stdlib, preset), flush=True)
            print(f"perf-gate {pair}: FAIL", flush=True)
            return "FAIL"
    if table is None:
        raise Refused(f"no table of {pair} was named")
    rows, tolerance, filled_from, filled_on, filled_with, filled_as = load_table(table, pair)
    if filled_on != platform:
        raise Refused(f"{table} holds rows of runs on {filled_on}, and this run was made on {platform}: judge "
                      f"it against the table of its own platform ({PLATFORMS[platform].relative_to(ROOT)})")
    if filled_from is None and ref == "P":
        raise Refused(f"{table} does not say which engine its rows were filled from (`engine`)")
    if filled_from is not None and filled_from != engine:
        raise Refused(f"{table} holds rows filled from the {filled_from} engine, and this run measured the "
                      f"{engine} engine: judge it against a table of its own engine, or run that engine "
                      f"(PICO_CMP_ENGINE={filled_from})")
    if filled_with is None and ref == "P":
        raise Refused(f"{table} does not say which standard library arm W was built with when its rows were "
                      "filled (`stdlib`)")
    if filled_with is not None and filled_with != stdlib:
        raise Refused(f"{table} holds rows filled from arm W built {filled_with}, and this run measured it built "
                      f"{stdlib}: judge it against a table of its own form, or run that form "
                      f"(PICO_CMP_STDLIB={filled_with})")
    if filled_as is None and ref == "P":
        raise Refused(f"{table} does not say which build arm W was when its rows were filled (`preset`)")
    if filled_as is not None and filled_as != preset:
        raise Refused(f"{table} holds rows filled from arm W built as {build_said(filled_as)}, and this run "
                      f"measured it built as {build_said(preset)}: judge it against a table of its own build, or "
                      f"build arm W as the table's (perf_matrix.py wz-arm)")
    print(f"perf-gate {pair}: arm W on the {engine} engine, {stdlib}, {build_said(preset)}", flush=True)
    return print_pair(pair, str(table), tolerance, judge(found, rows, tolerance))


def cmd_gate(args: argparse.Namespace) -> int:
    try:
        doc = json.loads(pathlib.Path(args.result).read_text(encoding="utf-8"))
        if doc.get("schema") != SCHEMA:
            raise Refused(f"{args.result} is not a result of schema {SCHEMA}")
        if (doc.get("record") or {}).get("text_trace"):
            raise Refused(f"{args.result} is a run whose probes ran under a tracer (--trace-text): its figures are "
                          "the tracer's, not the libraries'")
        cells = doc["cells"]
        engine = doc.get("record", {}).get("engine")
        if engine not in ENGINES:
            raise Refused(f"{args.result} does not say which engine arm W was built on")
        platform = platform_named(doc.get("record"), f"the record of {args.result}")
        limit_said(doc.get("record"), platform, args.result)
        stdlib = stdlib_named(doc.get("record"), f"the record of {args.result}")
        preset = preset_named(doc.get("record"), f"the record of {args.result}")
        external = doc.get("record", {}).get("external") or {
            "status": "not-measured", "why": "the run's record says nothing of arm X"}
        # A transport the run left out says why in its record (a group the host's network does not carry);
        # its rows are then not measured, and the reason is printed beside them.
        for transport, why in sorted((doc.get("record", {}).get("not_measured") or {}).items()):
            print(f"perf-gate: the run did not measure {transport}: {why}", flush=True)
        table = pathlib.Path(args.table) if args.table else PLATFORMS[platform]
        outcomes = [gate_pair("P", cells, table, [], engine, platform, stdlib, preset)]
        if external.get("status") == "built":
            named = args.external_table or os.environ.get(EXTERNAL_TABLE, "")
            outcomes.append(gate_pair("X", cells, pathlib.Path(named) if named else None, repository_roots(),
                                      engine, platform, stdlib, preset))
        elif args.without_external:
            print(f"perf-gate W/X: not asked (--without-external); arm X NOT-MEASURED, {external.get('why')}",
                  flush=True)
        else:
            print(f"perf-gate W/X: NOT-MEASURED, {external.get('why')}", flush=True)
            outcomes.append("NOT-MEASURED")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, Refused) as why:
        print(f"perf-gate: refused: {why}", file=sys.stderr, flush=True)
        return 2
    return exit_status(outcomes)


def check_table(path: pathlib.Path) -> int:
    """A committed table's shape, and its rows exactly the population of the default matrix of W over P. A table
    is the one its platform's runs are judged by (PLATFORMS), so the table of one platform cannot stand where the
    other's is read."""
    try:
        rows, tolerance, engine, platform, stdlib, preset = load_table(path, PAIR_NAMES["P"])
    except Refused as why:
        print(f"perf-gate table: refused: {why}", file=sys.stderr)
        return 2
    if path.resolve() != PLATFORMS[platform].resolve():
        print(f"  perf-gate table FAIL: {path} holds rows of runs on {platform}, whose table is "
              f"{PLATFORMS[platform].relative_to(ROOT)}", file=sys.stderr)
        return 1
    if engine is None:
        print(f"  perf-gate table FAIL: {path} does not say which engine its rows were filled from (`engine`)",
              file=sys.stderr)
        return 1
    if stdlib is None:
        print(f"  perf-gate table FAIL: {path} does not say which standard library arm W was built with when its "
              "rows were filled (`stdlib`)", file=sys.stderr)
        return 1
    if preset is None:
        print(f"  perf-gate table FAIL: {path} does not say which build arm W was when its rows were filled "
              "(`preset`)", file=sys.stderr)
        return 1
    # Arm P has no udp cell, so whether arm W's build listens on udp/ does not move the pair's rows.
    wanted = set(population("P", NOT_APPLICABLE))
    missing = sorted(wanted - set(rows), key=key_order)
    extra = sorted(set(rows) - wanted, key=key_order)
    for key in missing:
        print(f"  perf-gate table FAIL: no row for {key}, a cell of the default matrix", file=sys.stderr)
    for key in extra:
        print(f"  perf-gate table FAIL: the row {key} is no cell of the default matrix", file=sys.stderr)
    if missing or extra:
        return 1
    filled = sum(value is not None for value in rows.values())
    print(f"  perf-gate table: {len(rows)} row(s), the population of the default matrix; {filled} filled, "
          f"{len(rows) - filled} not yet (tolerance {tolerance}), filled from the {engine} engine, {stdlib}, "
          f"{build_said(preset)}, on {platform}")
    return 0


# -- a run on Windows ----------------------------------------------------------------------------------------

#: What `windows-plan` writes and scripts/host-bench/windows/perf_matrix.ps1 reads.
WINDOWS_PLAN_SCHEMA = "wz-pico-perf-windows-plan/3"
WINDOWS_PLATFORM = "windows-x64"
#: The width of Windows a plan is made for, by the package's name for it (pico_windows_package.ARCHES).
WINDOWS_ARCH = "x64"
#: The files the reference's switches are derived from besides the package's feature list: the declaration,
#: the feature table of the crate, the pinned pico and the derivation itself. A package built from a commit
#: where one of them differs from this tree's would be paired with another build of pico than its own.
PLAN_INPUTS = ("deploy/wz-config.toml", "crates/wz-capi-pico/Cargo.toml", "vendor/zenoh-pico",
               "scripts/lib/wz_config.py")
#: Why a transport is not run on Windows at all. The program transport's stream in perf_probe.c is an AF_UNIX
#: socket in Linux's abstract namespace, read with poll and woken through pipe2, none of which Windows has.
WINDOWS_NOT_RUN = {
    "program": "the program transport of perf_probe.c is an AF_UNIX stream in Linux's abstract namespace, "
               "read with poll and woken through pipe2, and is not built on Windows",
}


def windows_plan(manifest: dict, statement: dict, table: dict, decl: dict, target: str,
                 preset_of: Callable[[str, str], set[str]], preset_digest: str) -> dict:
    """What a run on Windows measures, from a package's manifest and build statement: arm W is the package's
    library, built for `target` with the features its manifest lists on the engine its statement states and with
    the standard library its manifest states (`pico_windows_package.stdlib_of`: every package is the library
    without `std`, so none is on the tokio engine), and arm P zenoh-pico built as the same build, every switch
    the declaration answers set from those features (`wz_config.pico_reference`), as `reference` derives the
    Linux arm from the bench's build. The plan states the build the package is (`wz_preset`) as its manifest
    states it (`pico_windows_package.manifest_preset`, the package `--build OUT --preset zenoh-pico` makes): a
    package of zenoh-pico's preset is planned as that preset, and one of a registered profile as none, with what it
    has beyond the preset and what it lacks of it, so the gate refuses to judge it against the preset's table. A
    package whose manifest names the preset is held to it: its features are exactly the ones `preset_of(engine,
    stdlib)` names (`wz_config.preset_features`, the one declaration the Linux arms are built from) and its
    statement's digest is `preset_digest`, the preset's own, so its limits and policies are the preset's too.
    `table` is the feature table of wz-capi-pico, `decl` the declaration. A package of another width, one that
    names a feature the crate lacks, one whose statement's engine is not the one its features run, one whose
    manifest states no standard library, or one its features do not build, one whose manifest states neither a
    profile nor a preset, and one that names a preset it is not the build of, are refused."""
    import pico_windows_package as pwp
    import wz_config

    if manifest.get("target") != target:
        raise Refused(f"the package is built for {manifest.get('target')!r}, and a run on {WINDOWS_PLATFORM} "
                      f"links one built for {target}")
    features = manifest.get("features")
    if not isinstance(features, list) or not features or not all(isinstance(f, str) for f in features):
        raise Refused("the package's manifest lists no features of the build")
    try:
        enabled = wz_config.enabled_features(table, features)
    except KeyError as error:
        raise Refused(f"the package names a feature this tree's wz-capi-pico does not have: {error}") from None
    engine = statement.get("engine")
    if engine not in ENGINES:
        raise Refused(f"the package's build statement names no engine of the pico ABI ({engine!r})")
    runs_on = wz_config.statement_engine("pico", enabled)
    if runs_on != engine:
        raise Refused(f"the package's statement says the {engine} engine, and its features run the {runs_on} one")
    try:
        stdlib = pwp.stdlib_of(manifest)
    except pwp.Refusal as why:
        raise Refused(f"the package's manifest: {why}") from None
    try:
        wz_config.engine_stdlib(engine, stdlib)
    except wz_config.PresetError as why:
        raise Refused(f"the package's manifest says it is built {stdlib}: {why}") from None
    try:
        named = pwp.manifest_preset(manifest)
    except pwp.Refusal as why:
        raise Refused(f"the package's manifest: {why}") from None
    preset = preset_of(engine, stdlib)
    beyond, short = sorted(enabled - preset), sorted(preset - enabled)
    if named is not None:
        if named not in PRESETS:
            raise Refused(f"the package is {named}'s preset, and arm W is compared as {', '.join(PRESETS)}'s")
        if beyond or short:
            raise Refused(f"the package's manifest says it is {named}'s preset, and its features are not the "
                          f"preset's (beyond it: {', '.join(beyond) or 'none'}; short of it: "
                          f"{', '.join(short) or 'none'})")
        if statement.get("digest") != preset_digest:
            raise Refused(f"the package's manifest says it is {named}'s preset, and its build statement "
                          f"({statement.get('digest')}) is not the preset's ({preset_digest}): a limit or a "
                          f"policy differs")
    return {"wz_features": sorted(features), "wz_engine": engine, "wz_stdlib": stdlib,
            "wz_preset": named,
            "wz_beyond_preset": beyond, "wz_short_of_preset": short,
            "reference_switches": wz_config.pico_reference(decl, enabled),
            # The runner reads which cells to record as not applicable from here, so a package whose build has
            # no udp/ listener is planned no udp cell of arm W, which it could not open.
            "not_applicable": {f"{arm}/{transport}": why
                               for (arm, transport), why in not_applicable(enabled).items()}}


def plan_input_drift(commit: str) -> list[str]:
    """The inputs of the reference's derivation (PLAN_INPUTS) that differ between `commit`, the package's,
    and this tree as it is; a commit git does not know is refused."""
    if not commit:
        raise Refused("the package's manifest names no commit it was built from")
    known = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", f"{commit}^{{commit}}"], capture_output=True)
    if known.returncode != 0:
        raise Refused(f"this repository does not have the package's commit {commit[:12]}; fetch it first")
    drift = []
    for path in PLAN_INPUTS:
        same = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", commit, "--", path], capture_output=True)
        if same.returncode != 0:
            drift.append(path)
    return drift


def cmd_windows_plan(package: pathlib.Path, out: pathlib.Path) -> int:
    """The plan of a run on Windows, from the package zip `package`, written to `out`."""
    import pico_windows_package as pwp
    import wz_config

    try:
        with tempfile.TemporaryDirectory() as scratch:
            top = pwp.extract_zip(package, pathlib.Path(scratch))
            findings = pwp.verify_findings(top)
            if findings:
                raise Refused(f"{package.name} does not match its manifest: {'; '.join(findings)}")
            manifest = json.loads((top / pwp.MANIFEST).read_text(encoding="utf-8"))
            statement = json.loads((top / pwp.STATEMENT).read_text(encoding="utf-8"))
            name = top.name
        commit = (manifest.get("built_from") or {}).get("commit", "")
        drift = plan_input_drift(commit)
        if drift:
            raise Refused(f"the package was built from {commit[:12]}, and this tree differs from it in "
                          f"{', '.join(drift)}, from which arm P's switches are derived: make the plan in a "
                          f"checkout of that commit")
        table = wz_config.manifest_features(wz_config.MANIFESTS["pico"])
        decl = wz_config.load_decl()
        kconf = wz_config.pico_bench_configuration()

        def preset_of(engine: str, stdlib: str) -> set[str]:
            return wz_config.preset_features(engine, [], table, stdlib, decl, kconf)

        # The digest names the build alone, not where it was read from, so the derivation's words are none.
        preset_digest = wz_config.resolved_statement(decl, "pico", kconf, {"kind": "presets", "inputs": []})["digest"]
        plan = windows_plan(manifest, statement, table, decl, pwp.ARCHES[WINDOWS_ARCH][0], preset_of, preset_digest)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, pwp.Refusal, Refused, wz_config.PresetError) as why:
        print(f"perf-matrix: windows-plan refused: {why}", file=sys.stderr, flush=True)
        return 2
    status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"],
                            capture_output=True, text=True)
    doc = {
        "schema": WINDOWS_PLAN_SCHEMA, "platform": WINDOWS_PLATFORM,
        "tree": first_line(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "tree_dirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
        "package": {"name": name, "zip": package.name, "sha256": sha256_of(package), "commit": commit,
                    "profile": manifest.get("profile"), "preset": manifest.get("preset"),
                    "form": manifest.get("form"), "libraries": manifest.get("libraries"),
                    "target": manifest.get("target"), "rustc": (manifest.get("toolchain") or {}).get("rustc"),
                    "statement_digest": manifest.get("statement_digest")},
        "reference_pin": first_line(["git", "-C", str(ROOT / "vendor" / "zenoh-pico"), "rev-parse", "HEAD"]),
        **plan,
        # What the runner applies and records, stated once here so the two runners cannot drift apart.
        "metrics": METRICS,
        "transports": list(TRANSPORTS), "workloads": list(WORKLOADS), "arms": ["P", "W"],
        "not_run": WINDOWS_NOT_RUN,
        "line_keys": {"ping": list(PING_KEYS), "pong": list(PONG_KEYS), "pub": list(PUB_KEYS),
                      "sub": list(SUB_KEYS), "sub_end": list(SUB_END_KEYS), "sub_mark": list(SUB_MARK_KEYS)},
        "stream_transports": list(STREAM_TRANSPORTS), "drain_s": DRAIN_S, "mark_wait_s": MARK_WAIT_S,
        "foreign_limit": FOREIGN_LIMITS[WINDOWS_PLATFORM], "max_runs": MAX_RUNS, "settle_s": SETTLE_S,
        "pub_tail_s": PUB_TAIL_S, "ready_s": READY_S, "group": GROUP, "schema_of_result": SCHEMA,
    }
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"perf-matrix: the plan of a run on Windows: arm W {name} on the {plan['wz_engine']} engine, "
          f"{plan['wz_stdlib']}, arm P "
          f"zenoh-pico {doc['reference_pin'][:12]} with {len(plan['reference_switches'])} switches set; {out}",
          flush=True)
    return 0


# -- the selftest -------------------------------------------------------------------------------------------

def started_peak_rss() -> tuple[Usage, int, int]:
    """A program started as a cell starts one, by a runner that holds BALLAST_MIB, which holds CHILD_MIB
    and prints its VmHWM as perf_probe.c does: what the runner reads of it, the maxrss of the reaped child
    (the control, which carries the runner's resident set), and the KiB the runner held."""
    ballast = bytes([1]) * (BALLAST_MIB << 20)
    program = (f"held = bytes([1]) * ({CHILD_MIB} << 20)\n"
               "status = open('/proc/self/status').read().splitlines()\n"
               "kib = next(line.split()[1] for line in status if line.startswith('VmHWM:'))\n"
               "print('perf_probe usage peak_rss_kib=' + kib)\n")
    with tempfile.TemporaryDirectory(prefix="perf-matrix-selftest-") as tmp:
        proc = Process([sys.executable, "-I", "-c", program], str(min(os.sched_getaffinity(0))),
                       pathlib.Path(tmp) / "usage.out", {})
        proc.reap(30.0)
        proc.stop()
        usage = usage_of(proc)
    return usage, 0 if proc.rusage is None else int(proc.rusage.ru_maxrss), len(ballast) >> 10


def cmd_selftest() -> int:
    ok = 0
    bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  perf-matrix selftest FAIL: {name}", file=sys.stderr)

    def lost(call) -> bool:
        try:
            call()
        except Lost:
            return True
        return False

    def refused_call(call) -> bool:
        try:
            call()
        except Refused:
            return True
        return False

    ping_text = ("noise\nperf_probe ping round_trips=4 lost=1 aborted=0 p50_ns=20000 p90_ns=30000 p99_ns=90000 "
                 "min_ns=15000 max_ns=90000 mean_ns=40000 all_round_trips=10 cpu_ns=500000\n")
    ping = fields(ping_text, "ping", PING_KEYS)
    expect("a role's line is read word by word", ping is not None and ping["p99_ns"] == "90000")
    expect("a line missing a key is not the role's result",
           fields("perf_probe ping round_trips=4 lost=1\n", "ping", PING_KEYS) is None)
    sub_text = ("perf_probe sub received=500 bytes=32000 window_ns=2000000000 cpu_ns=1000000 start_ns=20 "
                "end_ns=30\nperf_probe sub total=900\n")
    expect("the sub's window line is found before its total line",
           (fields(sub_text, "sub", SUB_KEYS) or {}).get("received") == "500")
    expect("another role's line is not read", fields(sub_text, "pub", PUB_KEYS) is None)

    client, server = Usage(1.0, 0.5, 4000), Usage(0.25, 0.125, 6000)
    pong = {"answered": "20", "cpu_ns": "200000", "stopped_by": "stop"}
    figs = rtt_figures(ping, pong, client, server)
    expect("a round trip's percentiles are microseconds",
           figs["rtt_p50_us"] == 20.0 and figs["rtt_p99_us"] == 90.0 and figs["lost"] == 1)
    expect("each side's CPU is per round trip of its own span",
           figs["ping_cpu_ns_per_rtt"] == 50000.0 and figs["pong_cpu_ns_per_rtt"] == 10000.0)
    expect("a pong stopped by a signal gives no CPU per round trip",
           rtt_figures(ping, dict(pong, stopped_by="signal"), client, server)["pong_cpu_ns_per_rtt"] is None)
    expect("the peak RSS of a cell is the two processes'", figs["rss_kib"] == 10000)
    expect("a program's peak RSS is the last line it printed",
           peak_rss_kib("perf_probe usage peak_rss_kib=1234\n") == 1234
           and peak_rss_kib("perf_probe ping round_trips=4\n") is None)
    unsaid = process_figures(Usage(1.0, 0.5, None), server)
    expect("a side that printed no peak RSS leaves the cell's sum out and keeps the other side's",
           unsaid["rss_kib"] is None and unsaid["rss_kib_client"] is None and unsaid["rss_kib_server"] == 6000)
    smaps_text = ("perf_probe sub received=500\n"
                  "perf_probe smaps rollup rss_kib=3000 pss_kib=1800 anonymous_kib=700 private_dirty_kib=800 "
                  "private_clean_kib=10 shared_clean_kib=2000 shared_dirty_kib=0\n"
                  "perf_probe smaps region start=7f00 perms=r-xp size_kib=1116 rss_kib=1000 pss_kib=500 "
                  "private_dirty_kib=0 anonymous_kib=0 name=/run/lib-W/libwz_capi_pico.so\n"
                  "perf_probe smaps pages start=7f00 pages=6 map=f2 present=5\n"
                  "perf_probe smaps region start=7f40 perms=rw-p size_kib=64 rss_kib=56 pss_kib=56 "
                  "private_dirty_kib=56 anonymous_kib=56 name=/run/lib-W/libwz_capi_pico.so\n"
                  "perf_probe smaps region start=7e00 perms=rw-p size_kib=288 rss_kib=40 pss_kib=40 "
                  "private_dirty_kib=40 anonymous_kib=40 name=\n"
                  "perf_probe smaps region start=5500 perms=rw-p size_kib=132 rss_kib=8 pss_kib=8 "
                  "private_dirty_kib=8 anonymous_kib=8 name=[heap]\n"
                  "perf_probe smaps region start=7f80 perms=r-xp size_kib=140 rss_kib=60 pss_kib=30 "
                  "private_dirty_kib=0 anonymous_kib=0 name=/lib/x86_64-linux-gnu/libgcc_s.so.1\n"
                  "perf_probe usage peak_rss_kib=3100\n")
    read_smaps = smaps_of(smaps_text)
    expect("a program's resident set is read by part, the mappings of one library summed",
           read_smaps is not None and read_smaps["rollup"]["rss_kib"] == 3000
           and read_smaps["parts"]["library"] == 1056 and read_smaps["parts"]["anonymous"] == 40
           and read_smaps["parts"]["heap"] == 8 and read_smaps["parts"]["libgcc_s"] == 60
           and read_smaps["parts"]["libc"] == 0 and len(read_smaps["regions"]) == 5
           and read_smaps["regions"][2]["size_kib"] == 288)
    expect("an executable mapping carries the pages of it the process held, and another mapping none",
           read_smaps is not None and read_smaps["regions"][0]["page_map"] == "f2"
           and read_smaps["regions"][0]["present_pages"] == 5 and read_smaps["regions"][0]["pages"] == 6
           and "page_map" not in read_smaps["regions"][1])
    expect("a mapping is counted as the part its name says",
           [smaps_class(n) for n in ("", "[heap]", "[stack]", "[vdso]", "/usr/lib/libc.so.6",
                                     "/usr/lib/ld-linux-x86-64.so.2", "/x/lib-P/libzenohpico.so",
                                     "/x/bin/perf_probe_W", "/usr/lib/libm.so.6", "[anon:x]")]
           == ["anonymous", "heap", "stack", "kernel", "libc", "loader", "library", "program",
               "other_libraries", "other"])
    # A library of two loaded segments, the second executable at 0x1000 for 0x3000 bytes.
    elf = bytearray(64 + 2 * ELF_PHDR.size)
    elf[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", elf, 0x20, 64)
    struct.pack_into("<HH", elf, 0x36, ELF_PHDR.size, 2)
    ELF_PHDR.pack_into(elf, 64, ELF_PT_LOAD, 4, 0, 0, 0, 0x800, 0x800, 0x1000)
    ELF_PHDR.pack_into(elf, 64 + ELF_PHDR.size, ELF_PT_LOAD, 5, 0x1000, 0x1000, 0x1000, 0x3000, 0x3000, 0x1000)
    expect("a library's executable segment is its one loaded segment with the execute flag",
           exec_segment(bytes(elf)) == (0x1000, 0x3000))
    two = bytearray(elf)
    ELF_PHDR.pack_into(two, 64, ELF_PT_LOAD, 5, 0, 0, 0, 0x800, 0x800, 0x1000)
    expect("a file that is no ELF, or a library of two executable segments, is refused",
           refused_call(lambda: exec_segment(b"MZ" + bytes(80))) and refused_call(lambda: exec_segment(bytes(two))))
    expect("a page map is read four pages a digit, the lowest page in the lowest bit, none past its pages",
           present_pages("f2", 6) == {0, 1, 2, 3, 5} and present_pages("f2", 5) == {0, 1, 2, 3}
           and present_pages("", 0) == set())
    listing = ("0000000000001000 0000000000000100 T wz_session_core::session::open\n"
               "0000000000004000 D data_only\n"
               "0000000000002ff0 0000000000000020 t wz_capi_pico::advanced::put\n"
               "0000000000003000 0000000000000010 T z_put\n"
               "0000000000003010 0000000000000010 t <wz_codecs::Frame as core::fmt::Debug>::fmt\n"
               "0000000000003020 W weak_without_size\n")
    symbols = text_symbols(listing)
    expect("nm's text symbols with a size are read, a demangled name with its spaces",
           [s[2] for s in symbols] == ["wz_session_core::session::open", "wz_capi_pico::advanced::put", "z_put",
                                       "<wz_codecs::Frame as core::fmt::Debug>::fmt"]
           and symbols[1][:2] == (0x2ff0, 0x20))
    expect("a symbol is counted at its path's first crate, an unmangled door as a door",
           [symbol_crate(s[2]) for s in symbols] == ["wz_session_core", "wz_capi_pico", "C doors", "wz_codecs"]
           and symbol_crate("main") == "other")
    named = resident_text(symbols, 0x1000, {0, 2})
    expect("a symbol's bytes on the present pages are resident, a symbol across a page counted in part",
           named["crates"]["wz_session_core"] == {"text": 0x100, "resident": 0x100}
           and named["crates"]["wz_capi_pico"] == {"text": 0x20, "resident": 0x10}
           and named["crates"]["C doors"] == {"text": 0x10, "resident": 0x10}
           and named["groups"] == {"advanced": {"text": 0x20, "resident": 0x10}})
    expect("no present page leaves nothing resident",
           all(row["resident"] == 0 for row in resident_text(symbols, 0x1000, set())["crates"].values()))
    profile = ("version: 1\ncmd: perf_probe_W sub -l tcp/127.0.0.1:1 a=b\nevents: Ir\n"
               "ob=(1) /r/lib-W/libwz_capi_pico.so\nfl=(1) ???\nfn=(1) z_open\n0 12\n"
               "cob=(2) /usr/lib/libc.so.6\ncfi=(2) ???\ncfn=(2) malloc\ncalls=1 0\n0 30\n"
               "cfn=(3) _ZN14wz_session_core4open17h0123456789abcdefE\ncalls=1 0\n0 40\n"
               "fn=(4) _ZN9wz_codecs5frame4read17hfedcba9876543210E'2\n0 5\n"
               "ob=(2)\nfn=(2)\n0 7\nfn=(5) free\n0 2\nob=(1)\nfn=(1)\n0 1\n")
    expect("a callgrind profile names the functions of one object that ran, a name by its id after its first",
           traced_functions(profile, "libwz_capi_pico.so")
           == {"z_open", "_ZN14wz_session_core4open17h0123456789abcdefE",
               "_ZN9wz_codecs5frame4read17hfedcba9876543210E"}
           and traced_functions(profile, "libc.so.6") == {"malloc", "free"}
           and traced_functions(profile, "libzenohpico.so") == set() and traced_functions("", "x") == set())
    hashed = "_ZN14wz_session_core4open17h0123456789abcdefE"
    stem = "_ZN14wz_session_core4open17h" + "?" * 16 + "E"
    expect("a function's sections are matched by its name, a Rust name's hash by any, a C name as it is",
           section_patterns(hashed) == f".text.{stem} .text.unlikely.{stem}"
           and section_patterns("z_open") == ".text.z_open .text.unlikely.z_open"
           and section_patterns("_ZN4core3ptr13drop_in_place$LT$u8$GT$17h0000000000000000E")
           == ".text._ZN4core3ptr13drop_in_place$LT$u8$GT$17h" + "?" * 16 + "E"
           + " .text.unlikely._ZN4core3ptr13drop_in_place$LT$u8$GT$17h" + "?" * 16 + "E"
           and section_patterns("_ZN3foo3bar17h0123E")
           == ".text._ZN3foo3bar17h0123E .text.unlikely._ZN3foo3bar17h0123E")
    expect("a name a pattern does not take unquoted is not placed",
           section_patterns("z_open@plt") is None and section_patterns("a b") is None and section_patterns("") is None)
    body = run_text_body([".text.a .text.unlikely.a", ".text.b .text.unlikely.b"])
    expect("the script's statement is one section inserted before .text with a line a function, and reads back",
           body == ("SECTIONS\n{\n  .text.run :\n  {\n    *(.text.a .text.unlikely.a)\n"
                    "    *(.text.b .text.unlikely.b)\n  }\n}\nINSERT BEFORE .text;\n")
           and run_text_parts("/* head */\n" + body) == ("/* head */\n", [".text.a .text.unlikely.a",
                                                                         ".text.b .text.unlikely.b"])
           and run_text_parts(run_text_body([])) == ("", []))
    expect("a script with no statement, or with a statement run-text does not write, is refused",
           refused_call(lambda: run_text_parts("/* SECTIONS\n */\n"))
           and refused_call(lambda: run_text_parts(body.replace("BEFORE", "AFTER")))
           and refused_call(lambda: run_text_parts(body + "/* more */\n")))
    committed = RUN_TEXT_SCRIPT.read_text(encoding="utf-8")
    try:
        committed_head, committed_lines = run_text_parts(committed)
    except Refused:
        committed_head, committed_lines = "", None
    expect("the committed run-text script is one run-text writes, under a head that carries the license",
           committed_lines is not None and "SPDX-License-Identifier:" in committed_head
           and committed_head + run_text_body(committed_lines) == committed)
    ran, placed, lines = run_text_plan({"z_put", hashed, "z_open@plt", "not_in_it"},
                                       {"z_put": 16, hashed: 64, "z_open@plt": 8, "other": 4})
    expect("the plan keeps the traced names the library defines, places those a pattern takes, a line each",
           ran == sorted([hashed, "z_open@plt", "z_put"]) and placed == sorted([hashed, "z_put"])
           and lines == sorted([f".text.{stem} .text.unlikely.{stem}", ".text.z_put .text.unlikely.z_put"]))
    expect("two builds of one function are one line",
           run_text_plan({hashed, hashed.replace("0123456789abcdef", "fedcba9876543210")},
                         {hashed: 1, hashed.replace("0123456789abcdef", "fedcba9876543210"): 1})[2]
           == [f".text.{stem} .text.unlikely.{stem}"])
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        no_library = cmd_run_text(ROOT / "no-such-library.so", RUN_TEXT_SCRIPT, [])
    expect("run-text refuses a library it cannot read, and writes no script",
           no_library == 2 and RUN_TEXT_SCRIPT.read_text(encoding="utf-8") == committed)
    expect("a traced probe runs under callgrind, its profile named by its cell, its role and its pid",
           traced_command(["/b/perf_probe_W", "sub", "-l", "x"], pathlib.Path("/t/r1.sub"))
           == [*TEXT_TRACE_TOOL, "--callgrind-out-file=/t/r1.sub.%p", "/b/perf_probe_W", "sub", "-l", "x"])
    suffixed = "_ZN3foo3bar17h" + "?" * 16 + "E.llvm.42"
    expect("a hash a suffix of the compiler's follows is matched by any, the suffix as it is, and a hash inside a "
           "path is not one",
           section_patterns("_ZN3foo3bar17h0123456789abcdefE.llvm.42") == f".text.{suffixed} .text.unlikely.{suffixed}"
           and section_patterns("_ZN3foo3bar17h0123456789abcdefEx")
           == ".text._ZN3foo3bar17h0123456789abcdefEx .text.unlikely._ZN3foo3bar17h0123456789abcdefEx")
    expect("a list made again counts the lines it adds and the lines it drops",
           list_change(["a", "b"], ["b", "c", "d"]) == (2, 1) and list_change([], []) == (0, 0))
    linux = ["z_put", hashed, "_ZN9wz_codecs5frame4read17hfedcba9876543210E"]
    listed = run_text_plan(set(linux), dict.fromkeys(linux, 8))[2]
    windows = ["_ZN9wz_codecs5frame4read17h1111111111111111E", "z_put", "z_other",
               "_ZN14wz_session_core4open17h2222222222222222E", "z_put", "a b"]
    ordered = ["_ZN14wz_session_core4open17h2222222222222222E", "_ZN9wz_codecs5frame4read17h1111111111111111E",
               "z_put"]
    expect("lld-link's order is the other build's own names of the functions the list places, in the list's order",
           order_names(listed, windows) == ordered
           and order_names(listed, ["z_other"]) == [] and order_names([], windows) == [])
    expect("a listing's names are the last word of each line: a list's, nm's, a map's",
           link_names("z_put\n0000000000001000 T z_open\n\n  140001000 00000010 16  _ZN3foo3bar17h0123456789abcdefE\n")
           == ["z_put", "z_open", "_ZN3foo3bar17h0123456789abcdefE"])
    with tempfile.TemporaryDirectory() as scratch:
        where = pathlib.Path(scratch)
        (where / "run-text.ld").write_text("/* head */\n" + run_text_body(listed), encoding="utf-8")
        (where / "map.txt").write_text("\n".join(windows[:4]) + "\n", encoding="utf-8")
        (where / "other.txt").write_text("z_other\n", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            wrote = cmd_run_text_order(where / "run-text.ld", where / "map.txt", where / "order.txt")
            unplaced = cmd_run_text_order(where / "run-text.ld", where / "other.txt", where / "none.txt")
            unread = cmd_run_text_order(where / "missing.ld", where / "map.txt", where / "missing.txt")
        expect("run-text-order writes the order file of a listing, and nothing when no name is placed or an input "
               "is refused",
               wrote == 0 and (where / "order.txt").read_text(encoding="utf-8") == "".join(f"{n}\n" for n in ordered)
               and unplaced == 3 and not (where / "none.txt").exists()
               and unread == 2 and not (where / "missing.txt").exists())
    code = (".text", elf_facts.SHT_PROGBITS, b"\x90" * 16, None)
    expect("a library's laid-out run is its .text.run section, a library without one has none, and a file that is "
           "no ELF is refused",
           run_section(elf_facts.build_elf([code, (RUN_TEXT_SECTION, elf_facts.SHT_PROGBITS, b"\x90" * 48, None)]))
           == (0, 48)
           and run_section(elf_facts.build_elf([code])) is None
           and refused_call(lambda: run_section(b"MZ" + bytes(80))))
    expect("a page lies outside the laid-out run when its fault-around window in the address space is past the "
           "window of the run's last byte",
           outside_run({0, 13, 28, 29, 40}, 0x53000, 0x1000, 0xF000) == {29, 40}
           and outside_run({0, 13, 15, 16}, 0x50000, 0x1000, 0xF000) == {16}
           and outside_run(set(), 0x50000, 0x1000, 0xF000) == set())
    import capability_cost_gate as cost

    expect("the size gate reads the script and the section run-text writes, and counts the lines it writes",
           (cost.CRATES / cost.RUN_TEXT_SCRIPT).resolve() == RUN_TEXT_SCRIPT.resolve()
           and cost.RUN_TEXT_SECTION == RUN_TEXT_SECTION
           and cost.run_text_lines(run_text_body([".text.a .text.unlikely.a", ".text.b .text.unlikely.b"])) == 2
           and cost.run_text_lines("/* head */\n" + run_text_body([])) == 0)
    run_doc = {"cells": [
        {"arm": "W", "transport": "tcp", "workload": "thr", "figures": {
            "smaps_client": {"regions": [{"name": "/r/lib-W/libwz_capi_pico.so", "pages": 6, "page_map": "12"},
                                         {"name": "/lib/libc.so.6", "pages": 4, "page_map": "f"}]},
            "smaps_server": {"regions": [{"name": "/r/lib-W/libwz_capi_pico.so", "pages": 6, "page_map": "1"}]}}},
        {"arm": "W", "transport": "tcp", "workload": "thr", "figures": {
            "smaps_client": {"regions": [{"name": "/r/lib-W/libwz_capi_pico.so", "pages": 6, "page_map": "4"}]}}},
        {"arm": "P", "transport": "tcp", "workload": "thr", "figures": {
            "smaps_client": {"regions": [{"name": "/r/lib-P/libzenohpico.so.1", "pages": 2, "page_map": "3"}]}}},
        {"arm": "W", "transport": "udp", "workload": "rtt", "figures": {}}]}
    expect("a role's pages are the union over its cells of the library's own mapping, by arm",
           role_pages(run_doc, "W", "libwz_capi_pico.so") == {"tcp thr client": ({0, 2, 5}, 6),
                                                              "tcp thr server": ({0}, 6)}
           and role_pages(run_doc, "P", "libzenohpico.so.1") == {"tcp thr client": ({0, 1}, 2)}
           and role_pages(run_doc, "X", "libwz_capi_pico.so") == {})
    library = "/r/lib-W/libwz_capi_pico.so"
    laid_doc = {"cells": [{"arm": "W", "transport": "tcp", "workload": "rtt", "figures": {
        "smaps_client": {"regions": [{"name": library, "pages": 48, "page_map": "00001", "start": "50000"}]},
        "smaps_server": {"regions": [{"name": library, "pages": 48, "page_map": "00001", "start": "53000"}]}}}]}
    expect("each process's pages outside the laid-out run are read by where its own mapping started",
           role_outside_run(laid_doc, "W", "libwz_capi_pico.so", 0x1000, 0xF000)
           == {"tcp rtt client": {16}, "tcp rtt server": set()}
           and role_outside_run(laid_doc, "P", "libwz_capi_pico.so", 0x1000, 0xF000) == {})
    expect("a page map with no start address is refused, since its windows cannot be told",
           refused_call(lambda: role_outside_run(run_doc, "W", "libwz_capi_pico.so", 0x1000, 0xF000)))
    expect("a program that printed no rollup has no resident set by part",
           smaps_of("perf_probe usage peak_rss_kib=3100\n") is None)
    by_part = process_figures(Usage(1.0, 0.5, 4000, read_smaps), Usage(0.25, 0.125, 6000, read_smaps))
    expect("a cell's resident set by part is its two processes' sum, beside its peak",
           by_part["smaps_library_kib"] == 2112 and by_part["smaps_rollup_rss_kib"] == 6000
           and by_part["smaps_libc_kib"] == 0 and by_part["rss_kib"] == 10000
           and by_part["smaps_client"] is read_smaps)
    expect("every figure of the resident set by part is a figure the summary knows, and lower is better",
           set(numbers(by_part)) - set(numbers(figs)) == set(SMAPS_FIGURES)
           and all(METRICS[n] == "lower" for n in SMAPS_FIGURES))
    expect("a side that printed no resident set by part leaves every such figure out",
           not any(n.startswith("smaps_") for n in process_figures(Usage(1.0, 0.5, 4000, read_smaps), server)))
    expect("a lost cell's last words are not its resident set by part",
           last_words(smaps_text) == "perf_probe sub received=500")
    started, control, held = started_peak_rss()
    expect("control: the maxrss of a reaped child carries the resident set of the runner that started it",
           control >= held)
    expect("the peak RSS read of a started program is its own, not its runner's",
           started.rss_kib is not None and CHILD_MIB << 10 <= started.rss_kib < held)
    expect("no round trip counted is a lost cell",
           lost(lambda: rtt_figures(dict(ping, round_trips="0"), pong, client, server)))

    pub = {"sent": "1000", "failed": "0", "elapsed_ns": "4000000000", "cpu_ns": "2000000", "start_ns": "10",
           "end_ns": "40"}
    sub = fields(sub_text, "sub", SUB_KEYS)
    tfigs = thr_figures(pub, sub, client, server)
    expect("throughput is what the window delivered over its length",
           tfigs["msgs_per_s"] == 250.0 and tfigs["bytes_per_s"] == 16000.0 and tfigs["offered_msgs_per_s"] == 250.0)
    expect("CPU per message is each side's over its own count, summed",
           tfigs["cpu_ns_per_msg_pub"] == 2000.0 and tfigs["cpu_ns_per_msg_sub"] == 2000.0
           and tfigs["cpu_ns_per_msg"] == 4000.0)
    expect("a window that began before the publisher's loop is no rate",
           lost(lambda: thr_figures(dict(pub, start_ns="25"), sub, client, server)))
    expect("a window that ended after the publisher's loop is no rate",
           lost(lambda: thr_figures(dict(pub, end_ns="29"), sub, client, server)))
    expect("nothing delivered is a lost cell",
           lost(lambda: thr_figures(pub, dict(sub, received="0"), client, server)))
    # Delivery: the publisher's count against what the subscriber had been handed at its end marker.
    whole = {"pub_sent": "1000", "received_before_end": "1000"}
    expect("every put delivered on a reliable stream is no loss, and the figure says none was missed",
           delivery("tcp", pub, whole) == 0 and delivery("program", pub, whole) == 0)
    expect("a put that answered success and was not delivered loses a cell of a reliable stream",
           lost(lambda: delivery("tcp", pub, dict(whole, received_before_end="900")))
           and lost(lambda: delivery("program", pub, dict(whole, received_before_end="900"))))
    expect("more delivered than put loses a cell of a reliable stream too",
           lost(lambda: delivery("tcp", pub, dict(whole, received_before_end="1001"))))
    expect("an end marker that never came loses a cell of a reliable stream, and is no figure on datagrams",
           lost(lambda: delivery("tcp", pub, None)) and delivery("udp", pub, None) is None
           and delivery("multicast", pub, None) is None)
    expect("on datagrams what did not arrive is a figure, not a loss",
           delivery("multicast", pub, dict(whole, received_before_end="900")) == 100
           and delivery("udp", pub, dict(whole, received_before_end="990")) == 10)
    expect("a marker that carries another count than the publisher's is a lost cell on any transport",
           lost(lambda: delivery("multicast", pub, dict(whole, pub_sent="999")))
           and lost(lambda: delivery("tcp", pub, dict(whole, pub_sent="999"))))
    expect("the reliable streams are transports of the matrix, and the drain outlasts the datagrams' wait",
           set(STREAM_TRANSPORTS) <= set(TRANSPORTS) and "multicast" not in STREAM_TRANSPORTS
           and "udp" not in STREAM_TRANSPORTS and DRAIN_S > MARK_WAIT_S > 0)
    expect("the subscriber's end-marker line is told apart from its window line and its last line",
           fields("perf_probe sub end pub_sent=5 received_before_end=5\n", "sub", SUB_KEYS) is None
           and fields("perf_probe sub end pub_sent=5 received_before_end=5\n", "sub", SUB_END_KEYS) is None
           and (fields("perf_probe sub end pub_sent=5 received_before_end=4\n", "sub", SUB_MARK_KEYS) or {})
           .get("received_before_end") == "4"
           and fields(sub_text, "sub", SUB_MARK_KEYS) is None)
    expect("every figure a cell carries says which way is better",
           set(numbers(figs)) | set(numbers(tfigs)) <= set(METRICS)
           and set(METRICS.values()) == {"lower", "higher"})

    expect("tcp and udp listen on one side and dial from the other",
           endpoint_args("tcp", 7447, "n") == (["-l", "tcp/127.0.0.1:7447"], ["-e", "tcp/127.0.0.1:7447", "-M"])
           and endpoint_args("udp", 7447, "n")[1] == ["-e", "udp/127.0.0.1:7447", "-M"])
    expect("both members of a group listen on it, and the client waits for no match there",
           endpoint_args("multicast", 7447, "n")[0] == endpoint_args("multicast", 7447, "n")[1]
           == ["-l", f"udp/{GROUP}:7447#iface=lo"])
    expect("the program transport names its stream on both sides",
           endpoint_args("program", 7447, "n") == (["-l", PROGRAM_LOCATOR, "-T", "n"],
                                                   ["-e", PROGRAM_LOCATOR, "-T", "n", "-M"]))
    expect("on every transport that carries declarations the client side alone waits for a match",
           all("-M" in endpoint_args(t, 1, "n")[1] and "-M" not in endpoint_args(t, 1, "n")[0]
               for t in ("tcp", "udp", "program")))
    expect("an unknown transport is refused", lost_value(lambda: endpoint_args("serial", 1, "n")))
    # Arm W's build as zenoh-pico's preset has it (no udp/ listener), and one with the listener.
    preset_absent = not_applicable(["os-host", "peer"])
    listening_absent = not_applicable(["os-host", "peer", UDP_LISTENER_FEATURE])
    expect("arm P has no program transport and arm W runs it from its own build",
           binary_name("P", "program", preset_absent) is None
           and binary_name("W", "program", preset_absent) == "perf_probe_Wapp"
           and binary_name("P", "tcp", preset_absent) == "perf_probe_P"
           and binary_name("W", "multicast", preset_absent) == "perf_probe_W")
    expect("arm P has no udp cell; arm W runs udp from a build with a udp/ listener and records a build without "
           "one as not applicable, saying why",
           binary_name("P", "udp", listening_absent) is None
           and binary_name("W", "udp", listening_absent) == "perf_probe_W"
           and binary_name("W", "udp", preset_absent) is None
           and preset_absent[("W", "udp")] == W_UDP_WITHOUT_LISTENER
           and set(preset_absent) - set(listening_absent) == {("W", "udp")}
           and listening_absent == NOT_APPLICABLE)
    expect("every arm and transport has a program or a reason it has none",
           all(binary_name(a, t, absent) is not None or (a, t) in absent
               for absent in (preset_absent, listening_absent) for a in ARMS for t in TRANSPORTS))

    expect("a lost cell is named by what a program said before its usage line, the usage line when it said "
           "nothing else",
           last_words("perf_probe ping: unable to declare the stop publisher\nperf_probe usage peak_rss_kib=3296\n")
           == "perf_probe ping: unable to declare the stop publisher"
           and last_words("perf_probe usage peak_rss_kib=3296\n") == "perf_probe usage peak_rss_kib=3296"
           and last_words("\n") == "nothing")
    probe = PROBE_SOURCE.read_text(encoding="utf-8")
    stated = probe_session_limits(probe)
    holds = probe_role_holds(probe)
    expect("CONTROL: the roles' declarations are counted, and two of them hold more than one entity of a kind",
           set(holds) == set(PROBE_ROLES) and holds["pong"]["MAX_SUBSCRIPTIONS"] == 2
           and holds["ping"]["MAX_PUBLISHERS"] == 2 and holds["pong"]["MAX_DECLARED_KEYEXPRS"] == 3)
    expect("the probe states, against wz, at least what each role declares on its session at once",
           all(stated.get(limit, 0) >= count for role in holds.values() for limit, count in role.items()))
    expect("the probe hands those counts to its config before it opens, in its build against wz alone",
           probe_states_limits(probe)
           and not probe_states_limits(probe.replace(f"#ifdef {WZ_PROBE_SWITCH}\n    if (zp_config_insert",
                                                     "    if (zp_config_insert")))
    expect("a statement that is no NAME=count, or none, is refused",
           lost_value(lambda: probe_session_limits(f'#define {PROBE_LIMITS_MACRO} "MAX_PUBLISHERS"\n'))
           and lost_value(lambda: probe_session_limits("")))
    builds = probe_builds((ROOT / "scripts" / "pico-compare.sh").read_text(encoding="utf-8"))
    expect("both wz probes are built with the switch and zext.h, and the reference's without the switch",
           set(builds) == {"P", "W", "Wapp"}
           and all(f"-D{WZ_PROBE_SWITCH}" in builds[arm] and "crates/wz-capi-core/include" in builds[arm]
                   for arm in ("W", "Wapp"))
           and f"-D{WZ_PROBE_SWITCH}" not in builds["P"])
    windows = (HERE / "windows" / "perf_matrix.ps1").read_text(encoding="utf-8").splitlines()
    windows_arms = {arm: [line for line in windows if f"@{{ Arm = '{arm}';" in line] for arm in ("P", "W")}
    expect("the Windows matrix builds arm W's probe with the switch and the reference's without it",
           all(len(found) == 1 for found in windows_arms.values())
           and f"/D{WZ_PROBE_SWITCH}" in windows_arms["W"][0] and f"/D{WZ_PROBE_SWITCH}" not in windows_arms["P"][0]
           and any("$cl + $arm.Defines" in line for line in windows))

    built = json.dumps({"reason": "build-script-executed", "package_id": "path+file:///x#zenoh-pico-sys@1.0",
                        "out_dir": "/o/one"})
    other = json.dumps({"reason": "build-script-executed", "package_id": "path+file:///x#zenoh-pico-sys@1.0",
                        "out_dir": "/o/two"})
    unrelated = json.dumps({"reason": "build-script-executed", "package_id": "path+file:///x#wz-capi-pico@1.0",
                            "out_dir": "/o/three"})
    expect("the one pico header arm a build names is its include directory",
           pico_sys_include(["Compiling", built, unrelated, built]) == os.path.join("/o/one", "include"))
    expect("no pico header arm, or two, is refused",
           lost_value(lambda: pico_sys_include([unrelated]))
           and lost_value(lambda: pico_sys_include([built, other])))

    def cell(arm, status, rep, value):
        return {"arm": arm, "transport": "tcp", "batching": False, "workload": "thr", "size": 8, "rep": rep,
                "status": status, "figures": {"msgs_per_s": value} if status == "measured" else {}}

    rows = summarize([cell("P", "measured", 1, 100.0), cell("P", "measured", 2, 300.0),
                      cell("P", "measured", 3, 200.0), cell("W", "measured", 1, 400.0),
                      cell("W", "lost", 2, 0.0)])
    expect("a row holds each arm's median over its measured repetitions and its lost ones",
           len(rows) == 1 and rows[0]["arms"]["P"]["median"]["msgs_per_s"] == 200.0
           and rows[0]["arms"]["W"]["measured"] == 1 and rows[0]["arms"]["W"]["lost"] == 1)
    expect("W over P is the ratio of the medians", rows[0]["w_over_p"]["msgs_per_s"] == 2.0)
    only_w = summarize([cell("W", "measured", 1, 5.0),
                        {"arm": "P", "transport": "program", "batching": False, "workload": "thr", "size": 8,
                         "rep": 1, "status": "not-applicable", "figures": {}}])
    expect("a row with one arm measured has no ratio, and a cell not applicable says so",
           all(r["w_over_p"] == {} for r in only_w)
           and any(r["arms"].get("P", {}).get("not_applicable") for r in only_w))
    expect("the report names every figure of a row", any("msgs_per_s" in line for line in report_lines(rows)))

    # Four cores of two threads (core i holds CPUs i and i + 4); core 2 idle, core 1 nearly, core 3
    # half busy on one thread, core 0 busy.
    core_of = {cpu: (0, cpu % 4) for cpu in range(8)}
    busy = {0: 0.9, 4: 0.8, 1: 0.1, 5: 0.0, 2: 0.0, 6: 0.0, 3: 0.0, 7: 0.5}
    expect("the least busy whole cores go to the client side first, then the server side",
           suggest_pinning(busy, core_of, 2) == ([2, 6], [1, 5]))
    expect("a side is filled with whole cores until it has enough CPUs, and the sides share no core",
           suggest_pinning(busy, core_of, 3) == ([1, 2, 5, 6], [0, 3, 4, 7]))
    expect("a host with too few cores for both sides is refused", suggest_pinning(busy, core_of, 5) is None)

    def pinned(topology: dict[int, tuple[int, int]], allowed: set[int], client: str = "", server: str = ""):
        try:
            return topology_pinning(topology, allowed, [("C", client), ("S", server)])
        except Refused as why:
            return str(why)

    # A hybrid host: six cores of two threads (core i holds CPUs 2i and 2i + 1), then ten of one thread.
    hybrid = {cpu: (0, cpu // 2) for cpu in range(12)}
    hybrid.update({cpu: (0, cpu - 6) for cpu in range(12, 22)})
    sides, how = pinned(hybrid, set(hybrid))
    expect("on a hybrid host each side is two two-thread cores, past the core of CPU 0",
           sides == [[2, 3, 4, 5], [6, 7, 8, 9]] and "2 whole cores a side" in how)
    # Four cores of two threads, core i holding CPUs i and i + 4: three are left past the core of CPU 0.
    eight = {cpu: (0, cpu % 4) for cpu in range(8)}
    sides, how = pinned(eight, set(eight))
    expect("an eight-thread host falls back to one whole core a side",
           sides == [[1, 5], [2, 6]] and "1 whole core a side" in how)
    two = {0: (0, 0), 1: (0, 1), 2: (0, 0), 3: (0, 1)}
    expect("a host with one core past the core of CPU 0 is refused, and says so",
           pinned(two, set(two)).startswith("this host has 1 whole core"))
    expect("a core one of whose CPUs this process may not run on is not a candidate",
           pinned(eight, {0, 1, 2, 3, 4, 5, 6})[0] == [[1, 5], [2, 6]]
           and pinned(eight, {0, 1, 2, 3, 4, 5}).startswith("this host has 1 whole core"))
    sides, how = pinned(eight, set(eight), client="3,7")
    expect("a given side is kept and the other side avoids its core",
           sides == [[3, 7], [1, 2, 5, 6]] and how.startswith("S from the topology, 2 whole cores"))
    expect("two given sides are used as given", pinned(eight, set(eight), "1", "2") == ([[1], [2]], "given"))
    expect("a given CPU this process may not run on is refused by its variable",
           pinned(eight, set(eight), client="6,7,8").startswith("C=6,7,8 names CPU 8"))
    expect("a given side that is not a CPU list is refused",
           pinned(eight, set(eight), server="x").startswith("S=x is not"))

    stalled_pub = {"sent": "9", "failed": "0", "start_ns": "1000000000", "batch_cycles": "5",
                   "lost_match_ns": "3500000000", "matched_at_end": "0", "peers_at_end": "0"}
    sub_end = {"total": "40", "last_growth_ns": "3400000000", "peers": "0"}
    note = stall_note(stalled_pub, sub_end)
    expect("a publisher that lost its match put into nothing, and the note says when",
           note.startswith("the sending side lost the subscriber") and "from 2.50 s into its loop" in note
           and "last grew 2.40 s into" in note)
    kept = dict(stalled_pub, lost_match_ns="0", matched_at_end="1", peers_at_end="1")
    expect("a publisher that kept its subscriber points at the receiving side",
           stall_note(kept, sub_end).startswith("the publisher still matched its subscriber"))
    expect("without the subscriber's last line the note does not guess",
           stall_note(kept, None).startswith("which side stopped is not told"))
    expect("only a cell the host disturbed is run again",
           second_pass([{"status": "lost", "disturbed": True}, {"status": "lost"}, {"status": "measured"},
                        {"status": "not-applicable"}]) == [0])
    # The reference is the cost gate's own build, called by name from `cmd_reference`: a merge that
    # took the gate's file from one side dropped `pico_reference_tree` once, and every run after it
    # ended NOT-MEASURED with no static check saying why (2026-11-21, merge 32aae4911).
    # The build is asked for under the gate's rule, so a builder that no longer takes the rule's
    # environment would build a library the gate never measured.
    import capability_cost_gate as cost
    expect("the cost gate still builds the reference this matrix links, under its build rule",
           all(callable(getattr(cost, name, None))
               for name in ("pico_reference_tree", "refused_switches", "build_env"))
           and "env" in inspect.signature(cost.pico_reference_tree).parameters)
    # Arm W is built by the plan of the size case of its form, and the reference by the gate's rule for it.
    expect("the cost gate still plans a case's build and the reference of its linker arguments",
           all(callable(getattr(cost, name, None)) for name in ("case_build", "reference_build"))
           and {"link", "cflags"} <= set(inspect.signature(cost.pico_reference_tree).parameters))
    cases = {case.id: case for case in cost.CASES}
    expect("each form of arm W is built as a size case of the pico ABI of that form",
           all(SHAPE_CASES[key] in cases and cases[SHAPE_CASES[key]].package == "wz-capi-pico"
               for key in SHAPE_CASES)
           and cases[SHAPE_CASES[("coop", "nostd")]].profile == "capi-nostd"
           and cost.NOSTD_CONFIG in cases[SHAPE_CASES[("coop", "nostd")]].cargo_configs
           and cost.DISCARD_UNWIND_CONFIG in cases[SHAPE_CASES[("coop", "nostd")]].cargo_configs
           and set(SHAPE_CASES) == {("coop", "nostd")})
    bare = bench_case("W", "coop", "nostd", ["os-host", "link-udp"])
    on_tokio = bench_case("Wapp", "tokio", "std", ["engine-tokio", "app-transport"])
    expect("arm W's case is its form's case with the bench's features, and the tokio engine's is its own build",
           bare.features == "os-host,link-udp" and bare.profile == "capi-nostd"
           and bare.cargo_configs == cases["pico-client-coop-nostd"].cargo_configs and bare.id == "perf-W"
           and on_tokio.features == "engine-tokio,app-transport" and on_tokio.package == "wz-capi-pico"
           and on_tokio.profile == cost.SHIP_PROFILE and on_tokio.cargo_configs == ()
           and shape_name("tokio", "std") == TOKIO_SHAPE
           and shape_name("coop", "nostd") == "pico-client-coop-nostd")
    expect("a form no size case builds is refused",
           refused_call(lambda: bench_case("W", "tokio", "nostd", []))
           and refused_call(lambda: bench_case("W", "coop", "std", [])))
    with contextlib.redirect_stdout(io.StringIO()) as said:
        not_pico = cmd_preset_arm(pathlib.Path("."), "zenoh-c", "nostd")
    expect("the parity's preset arm is built for an original of the pico ABI only, and refuses another unbuilt",
           not_pico == 2 and "no original built through the pico ABI" in said.getvalue())
    bare_plan = cost.case_build(bare, {}, "x86_64-unknown-linux-gnu",
                                {"unix", 'target_os="linux"', 'target_env="gnu"', 'target_family="unix"'}, limits={})
    tokio_plan = cost.case_build(on_tokio, {}, limits={})
    expect("each form of arm W is built as the pico C library crate, the bench's features through the ABI",
           bare_plan.cmd[4:6] == ("-p", "wz-capi-pico-lib") and tokio_plan.cmd[4:6] == ("-p", "wz-capi-pico-lib")
           and bare_plan.cmd[-1] == "abi/os-host,abi/link-udp"
           and tokio_plan.cmd[-1] == "abi/engine-tokio,abi/app-transport"
           and bare_plan.lib.name == tokio_plan.lib.name == "libwz_capi_pico.so"
           and built_as(bare) == "-p wz-capi-pico-lib --features abi/os-host,abi/link-udp")
    nostd_reference = cost.reference_build(bare_plan.link_args)
    expect("the reference of arm W without std is compiled without unwind tables and linked as arm W is",
           set(cost.NO_UNWIND_CFLAGS) <= set(nostd_reference[1])
           and cost.PACKED_RELOCS_LINK in nostd_reference[0] and cost.GNU_LD in nostd_reference[0])
    # -- the standard library ---------------------------------------------------------------------------
    expect("a run builds the standard library it is told, else the one form the release ships",
           bench_stdlib("std", ("nostd",)) == "std" and bench_stdlib("", ("nostd",)) == "nostd"
           and bench_stdlib("", ("std",)) == "std")
    expect("a name that is no standard library, or a release of two forms with none named, is refused",
           refused_call(lambda: bench_stdlib("alloc", ("nostd",)))
           and refused_call(lambda: bench_stdlib("", ("std", "nostd")))
           and refused_call(lambda: bench_stdlib("", ())))
    expect("a run's standard library is the one its build's record states, and nothing else",
           run_stdlib({"wz_stdlib": "nostd"}) == "nostd" and run_stdlib({}) is None
           and run_stdlib({"wz_stdlib": "alloc"}) is None)
    expect("a reading that names no standard library is of a library with std; one that names another is refused",
           stdlib_named({}, "r") == "std" and stdlib_named({"stdlib": "nostd"}, "r") == "nostd"
           and refused_call(lambda: stdlib_named({"stdlib": "alloc"}, "r")))
    import pico_windows_package as pwp
    import wz_config
    expect("the build a run names is the preset a bench against zenoh-pico builds",
           PRESETS == (wz_config.PICO_BENCH_ORIGINAL,))
    expect("the standard libraries a run names are the ones a bench builds, and a package states one of them",
           STDLIBS == wz_config.PICO_STDLIBS and set(pwp.STDLIBS) <= set(STDLIBS)
           and set(pwp.RELEASE_STDLIBS) <= set(pwp.STDLIBS))
    # -- arm X ------------------------------------------------------------------------------------------
    expect("arm X runs every transport but the program's, from a probe of its own, whatever arm W's build is",
           all(binary_name("X", "udp", absent) == "perf_probe_X" and binary_name("X", "tcp", absent) == "perf_probe_X"
               and binary_name("X", "program", absent) is None for absent in (preset_absent, listening_absent)))
    expect("the udp/ listener arm W's udp cells are read from is a feature of wz-capi-pico",
           UDP_LISTENER_FEATURE in wz_config.manifest_features(wz_config.MANIFESTS["pico"]))
    expect("a run measures arm X only when its record says it was built",
           run_arms({"status": "built"}) == ("P", "W", "X")
           and run_arms({"status": "not-measured", "why": "unset"}) == ("P", "W") and run_arms({}) == ("P", "W"))
    expect("arm X with a reason is a record of that reason, never a build",
           external_record({}, "unset") == {"status": "not-measured", "why": "unset"})
    with tempfile.TemporaryDirectory() as scratch:
        base = pathlib.Path(scratch)
        (base / "inc" / "zenoh-pico").mkdir(parents=True)
        (base / "inc" / "zenoh-pico" / "config.h").write_text("#define Z_FEATURE_BATCHING 1\n", encoding="utf-8")
        (base / "libx.so").write_bytes(b"x")
        built = external_record({EXTERNAL_LIB: str(base / "libx.so"), EXTERNAL_INCLUDE: str(base / "inc")}, "")
        expect("a built arm X records its library and its config.h by digest, and a label even when none is given",
               built["status"] == "built" and built["name"] == "unnamed"
               and built["library_sha256"] == hashlib.sha256(b"x").hexdigest()
               and built["config_h_sha256"] == hashlib.sha256(b"#define Z_FEATURE_BATCHING 1\n").hexdigest())
    with_x = summarize([cell("P", "measured", 1, 100.0), cell("W", "measured", 1, 300.0),
                        cell("X", "measured", 1, 150.0)])
    expect("a run with arm X has W over X beside W over P, and its report shows both",
           with_x[0]["w_over_p"]["msgs_per_s"] == 3.0 and with_x[0]["w_over_x"]["msgs_per_s"] == 2.0
           and any("W/X" in line for line in report_lines(with_x)))
    expect("a run without arm X has no W over X", "w_over_x" not in rows[0])

    # -- the gate ---------------------------------------------------------------------------------------
    def gcell(arm, rep, figures, status="measured", why="", disturbed=False, workload="rtt"):
        c = {"arm": arm, "transport": "tcp", "batching": False, "workload": workload, "size": 8, "rep": rep,
             "status": status, "figures": figures if status == "measured" else {}}
        if why:
            c["why"] = why
        if disturbed:
            c["disturbed"] = True
        return c

    def series(arm, values, metric="rtt_p50_us", workload="rtt"):
        return [gcell(arm, i + 1, {metric: v}, workload=workload) for i, v in enumerate(values)]

    p50 = row_key("tcp", False, "rtt", 8, "rtt_p50_us")
    rate = row_key("tcp", False, "thr", 8, "msgs_per_s")
    expect("a row's key names its transport, batching, workload, size and figure",
           p50 == "tcp/off/rtt/8/rtt_p50_us" and row_key("multicast", True, "thr", 64, "rss_kib")
           == "multicast/on/thr/64/rss_kib")
    win = readings(series("W", [10.0, 11.0, 12.0]) + series("P", [20.0, 21.0, 22.0]), "P")[p50]
    expect("a lower figure's cost ratio is wz over the reference, and a whole interval under 1 is WIN",
           win.state == "ratio" and win.verdict == "WIN" and win.hi < 1 and abs(win.point - 11.0 / 21.0) < 1e-9)
    faster = readings(series("W", [200.0, 210.0, 220.0], "msgs_per_s", "thr")
                      + series("P", [100.0, 105.0, 110.0], "msgs_per_s", "thr"), "P")[rate]
    expect("a higher figure's cost ratio is the reference over wz, so wz's larger rate reads under 1",
           faster.verdict == "WIN" and abs(faster.point - 0.5) < 1e-9)
    tie = readings(series("W", [10.0, 20.0, 30.0]) + series("P", [15.0, 20.0, 25.0]), "P")[p50]
    loss = readings(series("W", [30.0, 31.0, 32.0]) + series("P", [20.0, 21.0, 22.0]), "P")[p50]
    expect("an interval across 1 is TIE and one above it LOSS", tie.verdict == "TIE" and loss.verdict == "LOSS")
    expect("the other held figures of a group the run gave no samples of are too few for an interval",
           readings(series("W", [10.0, 11.0, 12.0]) + series("P", [20.0, 21.0, 22.0]), "P")[
               row_key("tcp", False, "rtt", 8, "rtt_p99_us")].state == "too-few")
    wz_lost = series("W", [10.0, 11.0]) + [gcell("W", 3, {}, "lost", "ping gave no result")]
    expect("a repetition wz lost on its own fails the cell",
           readings(wz_lost + series("P", [20.0, 21.0, 22.0]), "P")[p50].state == "wz-lost")
    disturbed = series("W", [10.0, 11.0]) + [gcell("W", 3, {}, "lost", "busy", disturbed=True)]
    expect("a repetition the host disturbed is no repetition, and two are too few",
           readings(disturbed + series("P", [20.0, 21.0, 22.0]), "P")[p50].state == "too-few")
    ref_lost = [gcell("P", r, {}, "lost", "pub gave no result") for r in (1, 2, 3)]
    gone = readings(series("W", [10.0, 11.0, 12.0]) + ref_lost, "P")[p50]
    expect("a reference that lost every repetition leaves the cell without a ratio, saying why",
           gone.state == "reference-lost" and "pub gave no result" in gone.why)
    expect("a pair the run has no arm for has no rows", readings(series("W", [1.0, 2.0, 3.0]), "X") == {})

    def one(reading, row, present=True, tolerance=0.05):
        return judge({p50: reading} if reading is not None else {}, {p50: row} if present else {}, tolerance)[0]

    expect("a locked row passes a WIN and fails anything else",
           one(win, {"locked": True}).outcome == "PASS" and one(tie, {"locked": True}).outcome == "FAIL"
           and one(loss, {"locked": True}).outcome == "FAIL")
    held = one(tie, {"ratio_at_most": ceil3(tie.hi)})
    expect("a ratchet written from a reading holds that reading and suggests nothing",
           held.outcome == "PASS" and held.edit is None)
    expect("a ratchet the upper end exceeds within the tolerance holds",
           one(tie, {"ratio_at_most": tie.hi / 1.04}).outcome == "PASS")
    expect("a ratchet the upper end exceeds beyond the tolerance fails",
           one(tie, {"ratio_at_most": tie.hi / 1.06}).outcome == "FAIL"
           and one(tie, {"ratio_at_most": tie.hi / 1.01}, tolerance=0.0).outcome == "FAIL")
    tighter = one(tie, {"ratio_at_most": ceil3(tie.hi) + 0.5})
    expect("a reading under the ratchet passes and prints the tighter value",
           tighter.outcome == "PASS" and tighter.edit == {"ratio_at_most": ceil3(tie.hi)})
    locks = one(win, {"ratio_at_most": 1.2})
    expect("a WIN on a ratcheted row passes and prints the edit that locks it",
           locks.outcome == "PASS" and locks.edit == {"locked": True})
    missing = one(win, None, present=False)
    expect("a cell with no row fails, with the row to add",
           missing.outcome == "FAIL" and missing.edit == {"locked": True})
    unfilled = one(tie, None)
    expect("a null row fails, with the row the reading writes",
           unfilled.outcome == "FAIL" and unfilled.edit == {"ratio_at_most": ceil3(tie.hi)})
    expect("a null row a run cannot read fails with no row to write",
           one(Reading("too-few", "two repetitions"), None).edit is None
           and one(Reading("too-few", "two repetitions"), None).outcome == "FAIL")
    expect("a row whose cell the run did not measure is not measured",
           one(None, {"locked": True}).outcome == "NOT-MEASURED")
    expect("a cell wz lost fails whatever its row",
           one(Reading("wz-lost", "lost"), {"ratio_at_most": 9.0}).outcome == "FAIL")
    expect("too few repetitions leave a filled row not measured",
           one(Reading("too-few", "two"), {"locked": True}).outcome == "NOT-MEASURED")
    expect("a reference that still loses the cell passes its row",
           one(gone, {"reference_lost": "pico lost it"}).outcome == "PASS")
    expect("a reference that lost a ratcheted cell leaves it not measured",
           one(gone, {"ratio_at_most": 1.0}).outcome == "NOT-MEASURED")
    expect("a null row of a cell the reference lost is written as such",
           one(gone, None).edit == {"reference_lost": gone.why})
    back = one(tie, {"reference_lost": "pico lost it"})
    expect("a reference that measures the cell again fails its row, with the row the reading writes",
           back.outcome == "FAIL" and back.edit == {"ratio_at_most": ceil3(tie.hi)})
    far = readings(series("W", [40.0, 41.0, 42.0]) + series("P", [10.0, 11.0, 12.0]), "P")[p50]
    owed = debts(judge({"a/off/rtt/8/x": tie, "b/off/rtt/8/x": far, "c/off/rtt/8/x": win}, {}, 0.05))
    expect("the debts are the readings that are not WIN, the largest upper end first",
           far.hi > tie.hi and [j.key for j in owed] == ["b/off/rtt/8/x", "a/off/rtt/8/x"])
    expect("a failure fails the gate, a row not measured is not a pass, and only every row held is",
           exit_status(["PASS", "FAIL", "NOT-MEASURED"]) == 1 and exit_status(["PASS", "NOT-MEASURED"]) == 3
           and exit_status(["PASS", "PASS"]) == 0 and outcome_of([]) == "NOT-MEASURED")
    expect("a value rounds up to three decimals for its ratchet", ceil3(0.9301) == 0.931 and ceil3(0.93) == 0.93)

    def table(rows, pair="W/P", tolerance=0.05, schema=TABLE_SCHEMA, engine="tokio", platform=None, stdlib="std",
              preset=PRESETS[0]):
        doc = {"schema": schema, "pair": pair, "tolerance": tolerance, "rows": rows}
        if preset is not None:
            doc["preset"] = preset
        if engine is not None:
            doc["engine"] = engine
        if platform is not None:
            doc["platform"] = platform
        if stdlib is not None:
            doc["stdlib"] = stdlib
        return json.dumps(doc)

    def refused(text, pair="W/P"):
        try:
            parse_table(text, pair)
        except Refused:
            return True
        return False

    good = {p50: {"locked": True}, rate: {"ratio_at_most": 1.25},
            row_key("tcp", False, "thr", 8, "rss_kib"): {"reference_lost": "why"},
            row_key("tcp", True, "thr", 8, "rss_kib"): None}
    expect("a table of the four row shapes is read", parse_table(table(good), "W/P") == (good, 0.05))
    expect("a table of another schema or another pair is refused",
           refused(table(good, schema="other")) and refused(table(good, pair="W/X")))
    expect("a tolerance outside [0, 1) is refused",
           refused(table(good, tolerance=1)) and refused(table(good, tolerance=-0.1)))
    expect("a key written twice is refused",
           refused('{"schema": "%s", "pair": "W/P", "tolerance": 0.05, "rows": {"%s": null, "%s": null}}'
                   % (TABLE_SCHEMA, p50, p50)))
    expect("every malformed row is refused",
           all(refused(table({p50: bad})) for bad in ({"locked": False}, {"ratio_at_most": 0},
                                                      {"ratio_at_most": True}, {"reference_lost": " "},
                                                      {"locked": True, "ratio_at_most": 1.0}, {"ceiling": 1.0}, 1.0)))
    expect("a key that is not a cell's is refused", refused(table({"tcp/rtt/8/rtt_p50_us": None})))
    expect("the default population of W over P holds tcp and multicast whatever arm W's build, of W over X udp "
           "too when arm W listens on udp/",
           len(population("P", preset_absent)) == 2 * 2 * 3 * 7
           and population("P", listening_absent) == population("P", preset_absent)
           == population("P", NOT_APPLICABLE)
           and len(population("X", listening_absent)) == 3 * 2 * 3 * 7
           and len(population("X", preset_absent)) == 2 * 2 * 3 * 7
           and all(key.split("/")[0] in ("tcp", "multicast") for key in population("P", preset_absent))
           and population("P", preset_absent) == sorted(population("P", preset_absent), key=key_order))
    expect("a path in a checkout is inside it, a path beside it is not",
           inside(ROOT / "deploy" / "x.json", [ROOT.resolve()])
           and not inside(ROOT.parent / "elsewhere.json", [ROOT.resolve()]))

    thr = {"msgs_per_s": 200.0, "cpu_ns_per_msg": 1000.0, "rss_kib": 4000}
    slow = {"msgs_per_s": 100.0, "cpu_ns_per_msg": 3000.0, "rss_kib": 8000}
    run_cells = ([gcell("W", r, dict(thr, msgs_per_s=thr["msgs_per_s"] + r), workload="thr") for r in (1, 2, 3)]
                 + [gcell("P", r, dict(slow, msgs_per_s=slow["msgs_per_s"] + r), workload="thr") for r in (1, 2, 3)])
    keys = [row_key("tcp", False, "thr", 8, m) for m in GATED["thr"]]
    locked = {key: {"locked": True} for key in keys}

    def gate(cells, record, table_rows, external_table="", without=False, x_rows=None, schema=SCHEMA,
             table_engine_="tokio", table_platform_=None, table_stdlib_="std", x_stdlib="std",
             table_preset_=PRESETS[0], x_preset=PRESETS[0]):
        with tempfile.TemporaryDirectory() as scratch:
            base = pathlib.Path(scratch)
            (base / "perf.json").write_text(json.dumps({"schema": schema, "record": record, "cells": cells}),
                                            encoding="utf-8")
            if external_table == "absent":
                external_table = str(base / "no-such-table.json")
            (base / "table.json").write_text(table(table_rows, engine=table_engine_, platform=table_platform_,
                                                   stdlib=table_stdlib_, preset=table_preset_), encoding="utf-8")
            if x_rows is not None:
                where = base / "x.json"
                where.write_text(table(x_rows, pair="W/X", stdlib=x_stdlib, preset=x_preset), encoding="utf-8")
                external_table = str(where)
            args = argparse.Namespace(result=str(base / "perf.json"), table=str(base / "table.json"),
                                      external_table=external_table, without_external=without)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return cmd_gate(args)

    no_x = {"engine": "tokio", "preset": PRESETS[0], "external": {"status": "not-measured", "why": "unset"}}
    expect("a run without arm X is NOT-MEASURED for W/X even when W/P holds",
           gate(run_cells, no_x, locked) == 3)
    expect("asked W/P alone, a run whose every row holds passes", gate(run_cells, no_x, locked, without=True) == 0)
    expect("a row missing from the table fails the gate",
           gate(run_cells, no_x, {k: v for k, v in locked.items() if k != keys[0]}, without=True) == 1)
    x_cells = run_cells + [dict(c, arm="X") for c in run_cells if c["arm"] == "P"]
    built_x = {"engine": "tokio", "preset": PRESETS[0], "external": {"status": "built", "name": "lab"}}
    expect("a run that measured arm X and was given no table of it fails, asked W/P alone or not",
           gate(x_cells, built_x, locked, external_table="absent") == 1
           and gate(x_cells, built_x, locked, external_table="absent", without=True) == 1)
    expect("a run that measured arm X passes when both tables hold every row",
           gate(x_cells, built_x, locked, x_rows=locked) == 0)
    expect("a table of W/X inside the repository is refused",
           gate(x_cells, built_x, locked, external_table=str(ROOT / "deploy" / "x.json")) == 2)
    expect("a result of another schema is refused", gate(run_cells, no_x, locked, schema="wz-other/1") == 2)
    expect("a run whose probes ran under the tracer is refused, one that says it did not is judged",
           gate(run_cells, dict(no_x, text_trace=True), locked, without=True) == 2
           and gate(run_cells, dict(no_x, text_trace=False), locked, without=True) == 0)
    # The engine: a run states the one arm W was built on and a table the one its rows were filled from, and
    # a run is judged only against rows of its own engine.
    expect("a run of the engine its table was filled from is judged",
           gate(run_cells, dict(no_x, engine="coop"), locked, without=True, table_engine_="coop") == 0)
    expect("a run of another engine than its table's is refused",
           gate(run_cells, dict(no_x, engine="coop"), locked, without=True) == 2)
    expect("a run whose record names no engine is refused",
           gate(run_cells, {"external": no_x["external"]}, locked, without=True) == 2)
    expect("a table of W/P that does not say its engine is refused",
           gate(run_cells, no_x, locked, without=True, table_engine_=None) == 2)

    def engine_refused(text):
        try:
            table_engine(text)
        except Refused:
            return True
        return False

    expect("a table that names what is no engine is refused, and one that names an engine is read",
           engine_refused(table(good, engine="fast")) and not engine_refused(table(good))
           and table_engine(table(good, engine="coop")) == "coop"
           and table_engine(table(good, engine=None)) is None)
    expect("a run's engine is the one its build's record states, and nothing else",
           run_engine({"wz_engine": "coop"}) == "coop" and run_engine({}) is None
           and run_engine({"wz_engine": "fast"}) is None)
    # The platform: a run states the one it was made on and a table the one its rows were filled on, and a run
    # is judged only against rows of its own platform; one that names none is Linux's.
    on_windows = dict(no_x, engine="coop", platform=WINDOWS_PLATFORM)
    expect("a run on Windows is judged against a table of Windows",
           gate(run_cells, on_windows, locked, without=True, table_engine_="coop",
                table_platform_=WINDOWS_PLATFORM) == 0)
    expect("a run on Windows against a table of Linux is refused, and a run on Linux against one of Windows",
           gate(run_cells, on_windows, locked, without=True, table_engine_="coop") == 2
           and gate(run_cells, no_x, locked, without=True, table_platform_=WINDOWS_PLATFORM) == 2
           and gate(run_cells, dict(no_x, platform="linux"), locked, without=True,
                    table_platform_=WINDOWS_PLATFORM) == 2)
    expect("a run on Linux that names its platform is judged as one that names none",
           gate(run_cells, dict(no_x, platform="linux"), locked, without=True) == 0
           and gate(run_cells, no_x, locked, without=True, table_platform_="linux") == 0)
    expect("a run or a table that names no platform of the matrix is refused",
           gate(run_cells, dict(no_x, platform="windows-arm64"), locked, without=True) == 2
           and gate(run_cells, no_x, locked, without=True, table_platform_="plan9") == 2)
    expect("a run on Windows read under a looser foreign-use limit than Windows' is refused, one under it judged",
           gate(run_cells, dict(on_windows, foreign_limit=FOREIGN_LIMIT), locked, without=True,
                table_engine_="coop", table_platform_=WINDOWS_PLATFORM) == 2
           and gate(run_cells, dict(on_windows, foreign_limit=WINDOWS_FOREIGN_LIMIT), locked, without=True,
                    table_engine_="coop", table_platform_=WINDOWS_PLATFORM) == 0
           and gate(run_cells, dict(no_x, foreign_limit=FOREIGN_LIMIT), locked, without=True) == 0)
    expect("each platform's runs are judged by default against its own committed table",
           PLATFORMS[DEFAULT_PLATFORM] == CEILING and PLATFORMS[WINDOWS_PLATFORM] == CEILING_WINDOWS
           and set(PLATFORMS) == {DEFAULT_PLATFORM, WINDOWS_PLATFORM})
    # The standard library: a run states the one arm W was built with and a table the one its rows were filled
    # from, and a run is judged only against rows of its own form; a reading that names none was built with std.
    bare_run = dict(no_x, engine="coop", stdlib="nostd")
    expect("a run without std is judged against a table filled without std",
           gate(run_cells, bare_run, locked, without=True, table_engine_="coop", table_stdlib_="nostd") == 0)
    expect("a run of the other standard library than its table's is refused, either way",
           gate(run_cells, bare_run, locked, without=True, table_engine_="coop") == 2
           and gate(run_cells, dict(bare_run, stdlib="std"), locked, without=True, table_engine_="coop",
                    table_stdlib_="nostd") == 2)
    expect("a reading that names no standard library is one with std, and is judged against a table of std",
           gate(run_cells, no_x, locked, without=True) == 0
           and gate(run_cells, no_x, locked, without=True, table_stdlib_="nostd") == 2)
    expect("a table of W/P that does not say its standard library is refused, and one of W/X need not",
           gate(run_cells, no_x, locked, without=True, table_stdlib_=None) == 2
           and gate(x_cells, built_x, locked, x_rows=locked, x_stdlib=None) == 0
           and gate(x_cells, built_x, locked, x_rows=locked, x_stdlib="nostd") == 2)
    expect("a reading or a table that names what is no standard library is refused",
           gate(run_cells, dict(no_x, stdlib="alloc"), locked, without=True) == 2
           and gate(run_cells, no_x, locked, without=True, table_stdlib_="alloc") == 2)
    expect("a table written for a run states the standard library it was filled from",
           json.loads(table_document("W/P", {}, 0.05, "coop", "linux", "nostd", PRESETS[0]))["stdlib"] == "nostd")
    # The build: a run states the preset arm W was built as and a table the one its rows were filled from, and a
    # run is judged only against rows of its own build; a run that states none measured the crate's default
    # features, which no committed table holds.
    expect("a run of the preset its table was filled from is judged",
           gate(run_cells, no_x, locked, without=True) == 0
           and gate(run_cells, no_x, locked, without=True, table_preset_=PRESETS[0]) == 0)
    expect("a run of the crate's default features is refused against a table of the preset",
           gate(run_cells, {k: v for k, v in no_x.items() if k != "preset"}, locked, without=True) == 2)
    expect("a table of W/P that does not say its build is refused, and one of W/X need not",
           gate(run_cells, no_x, locked, without=True, table_preset_=None) == 2
           and gate(x_cells, built_x, locked, x_rows=locked, x_preset=None) == 0
           and gate(x_cells, built_x, locked, x_rows=locked, x_preset="zenoh-c") == 2)
    expect("a reading or a table that names what is no preset is refused",
           gate(run_cells, dict(no_x, preset="zenoh-c"), locked, without=True) == 2
           and gate(run_cells, no_x, locked, without=True, table_preset_="zenoh-c") == 2)
    expect("a run's build is the preset its build's record states, and nothing else",
           run_preset({"wz_preset": PRESETS[0]}) == PRESETS[0] and run_preset({}) is None
           and run_preset({"wz_preset": "zenoh-c"}) is None
           and preset_named({}, "r") is None and preset_named({"preset": PRESETS[0]}, "r") == PRESETS[0]
           and refused_call(lambda: preset_named({"preset": "zenoh-c"}, "r")))
    expect("a table written for a run states the build it was filled from",
           json.loads(table_document("W/P", {}, 0.05, "coop", "linux", "nostd", PRESETS[0]))["preset"]
           == PRESETS[0])

    # -- the plan of a run on Windows ------------------------------------------------------------------------
    feature_table = {"default": ["os-host"], "engine-tokio": [], "os-host": [], "advanced": [],
                     "app-transport": ["advanced"], "udp-listen": [], "peer-ext": ["udp-listen"]}
    switch_rows = {"switches": [
        {"original": "zenoh-pico", "switch": "Z_FEATURE_ADVANCED_PUBLICATION", "class": "maps",
         "anchor": "wz-capi-pico/advanced"},
        {"original": "zenoh-pico", "switch": "Z_FEATURE_MATCHING", "class": "always"},
        {"original": "zenoh-pico", "switch": "Z_FEATURE_RAWETH_TRANSPORT", "class": "never"},
        {"original": "zenoh-pico", "switch": "BATCH_UNICAST_SIZE", "class": "maps", "anchor": "wz-capi-pico/x"},
        {"original": "zenoh-c", "switch": "Z_FEATURE_SHARED_MEMORY", "class": "always"}]}
    x64 = "x86_64-pc-windows-msvc"
    package_manifest = {"target": x64, "features": ["os-host", "app-transport"], "stdlib": "nostd",
                        "profile": None, "preset": PRESETS[0]}
    profile_manifest = dict(package_manifest, profile="p", preset=None)
    package_build = {"os-host", "app-transport", "advanced"}
    digest = "sha256:" + "1" * 64
    package_statement = {"engine": "coop", "digest": digest}

    def package_preset(engine, stdlib):
        return package_build if (engine, stdlib) == ("coop", "nostd") else set()

    def narrower_preset(engine, stdlib):
        return {"os-host", "zenoh-pico-only"}

    planned = windows_plan(package_manifest, package_statement, feature_table, switch_rows, x64, package_preset,
                           digest)
    expect("a plan pairs the package's library with pico built with the switches its features answer",
           planned["reference_switches"] == {"Z_FEATURE_ADVANCED_PUBLICATION": 1, "Z_FEATURE_MATCHING": 1,
                                             "Z_FEATURE_RAWETH_TRANSPORT": 0}
           and planned["wz_engine"] == "coop" and planned["wz_features"] == ["app-transport", "os-host"]
           and planned["wz_stdlib"] == "nostd")
    expect("a package whose manifest names zenoh-pico's preset, and that is its build, is planned as that build",
           planned["wz_preset"] == PRESETS[0] and planned["wz_beyond_preset"] == []
           and planned["wz_short_of_preset"] == [])
    other = windows_plan(profile_manifest, package_statement, feature_table, switch_rows, x64, narrower_preset,
                         digest)
    expect("a package of a profile is planned as no preset, with what it has beyond the preset and lacks",
           other["wz_preset"] is None and other["wz_beyond_preset"] == ["advanced", "app-transport"]
           and other["wz_short_of_preset"] == ["zenoh-pico-only"])
    same = windows_plan(profile_manifest, package_statement, feature_table, switch_rows, x64, package_preset, digest)
    expect("a package of a profile is planned as no preset even when its features are the preset's",
           same["wz_preset"] is None and same["wz_beyond_preset"] == [] and same["wz_short_of_preset"] == [])
    listening = windows_plan(dict(profile_manifest, features=["os-host", "peer-ext"]), package_statement,
                             feature_table, switch_rows, x64, package_preset, digest)
    expect("a plan records arm W's udp cells as not applicable when the package has no udp/ listener, and plans "
           "them when a feature it names brings one",
           planned["not_applicable"] == {f"{a}/{t}": why for (a, t), why in not_applicable([]).items()}
           and planned["not_applicable"]["W/udp"] == W_UDP_WITHOUT_LISTENER
           and listening["not_applicable"] == {f"{a}/{t}": why for (a, t), why in NOT_APPLICABLE.items()})
    tokio_manifest = {"target": x64, "features": ["engine-tokio", "app-transport"], "stdlib": "std"}

    def plan_refused(manifest, statement, preset_of=package_preset):
        try:
            windows_plan(manifest, statement, feature_table, switch_rows, x64, preset_of, digest)
        except Refused:
            return True
        return False

    expect("a package whose manifest names the preset is refused when its features or its statement are not the "
           "preset's",
           plan_refused(package_manifest, package_statement, narrower_preset)
           and plan_refused(package_manifest, dict(package_statement, digest="sha256:" + "2" * 64))
           and plan_refused(package_manifest, {"engine": "coop"}))
    expect("a package whose manifest names no build, both builds, or a preset of no pico original is refused",
           plan_refused(dict(package_manifest, preset=None), package_statement)
           and plan_refused(dict(package_manifest, profile="p"), package_statement)
           and plan_refused(dict(package_manifest, preset="zenoh-c"), package_statement))

    expect("a package of another width, or one that lists no features, is refused",
           plan_refused(dict(package_manifest, target="i686-pc-windows-msvc"), {"engine": "coop"})
           and plan_refused(dict(package_manifest, features=[]), {"engine": "coop"}))
    expect("a package that names a feature the crate does not have is refused",
           plan_refused(dict(package_manifest, features=["os-host", "gone"]), {"engine": "coop"}))
    expect("a package on the tokio engine is refused, as every package is the C library without std",
           plan_refused(tokio_manifest, {"engine": "tokio"})
           and plan_refused(dict(tokio_manifest, stdlib="nostd"), {"engine": "tokio"}))
    expect("a statement whose engine is not the one the package's features run is refused",
           plan_refused(package_manifest, {"engine": "tokio"})
           and plan_refused(dict(package_manifest, features=["engine-tokio"]), {"engine": "coop"})
           and plan_refused(package_manifest, {}))
    expect("a package whose manifest states no standard library, or one no package is built with, is refused",
           plan_refused({k: v for k, v in package_manifest.items() if k != "stdlib"}, {"engine": "coop"})
           and plan_refused(dict(package_manifest, stdlib="std"), {"engine": "coop"})
           and plan_refused(dict(package_manifest, stdlib="alloc"), {"engine": "coop"}))
    expect("a run on Windows leaves out only the transport perf_probe.c does not build there",
           set(WINDOWS_NOT_RUN) == {"program"})
    # The plan reads the package by the packager's own names, called from `cmd_windows_plan` alone, so a
    # rename there would surface only when a plan is made.
    import pico_windows_package as pwp
    expect("the packager still names the width, the files and the readers a plan is made from",
           pwp.ARCHES[WINDOWS_ARCH][0] == x64 and isinstance(pwp.MANIFEST, str) and isinstance(pwp.STATEMENT, str)
           and callable(getattr(pwp, "extract_zip", None)) and callable(getattr(pwp, "verify_findings", None)))
    import wz_config
    expect("the engines a table names are the ones a bench builds on", ENGINES == wz_config.PICO_ENGINES)
    print(f"  perf-matrix selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def lost_value(call) -> bool:
    """Whether `call` refuses with a ValueError."""
    try:
        call()
    except ValueError:
        return True
    return False


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return cmd_selftest()
    if len(argv) == 3 and argv[1] == "--check-table":
        return check_table(pathlib.Path(argv[2]))
    if len(argv) >= 2 and argv[1] == "--gate":
        gate = argparse.ArgumentParser(prog="perf_matrix.py --gate")
        gate.add_argument("result")
        gate.add_argument("--table", default="")
        gate.add_argument("--external-table", default="")
        gate.add_argument("--without-external", action="store_true")
        return cmd_gate(gate.parse_args(argv[2:]))
    if len(argv) in (3, 4) and argv[1] == "external-record":
        return cmd_external_record(pathlib.Path(argv[2]), argv[3] if len(argv) == 4 else "")
    if len(argv) == 4 and argv[1] == "windows-plan":
        return cmd_windows_plan(pathlib.Path(argv[2]), pathlib.Path(argv[3]))
    if len(argv) == 3 and argv[1] == "pico-sys-include":
        try:
            print(pico_sys_include(pathlib.Path(argv[2]).read_text(encoding="utf-8").splitlines()))
        except (OSError, ValueError) as why:
            print(f"perf-matrix: {why}", file=sys.stderr)
            return 1
        return 0
    if len(argv) in (2, 3) and argv[1] == "bench-stdlib":
        import pico_windows_package as pwp
        try:
            print(bench_stdlib(argv[2] if len(argv) == 3 else "", tuple(pwp.RELEASE_STDLIBS)))
        except Refused as why:
            print(f"perf-matrix: {why}", file=sys.stderr)
            return 2
        return 0
    if len(argv) >= 2 and argv[1] in ("reference", "wz-arm"):
        build = argparse.ArgumentParser(prog=f"perf_matrix.py {argv[1]}")
        build.add_argument("--out", required=True)
        build.add_argument("--engine", required=True, choices=ENGINES)
        build.add_argument("--stdlib", required=True, choices=STDLIBS)
        if argv[1] == "wz-arm":
            build.add_argument("--arm", required=True)
            build.add_argument("--features", default="")
        asked = build.parse_args(argv[2:])
        if argv[1] == "reference":
            return cmd_reference(pathlib.Path(asked.out), asked.engine, asked.stdlib)
        return cmd_wz_arm(pathlib.Path(asked.out), asked.arm, asked.engine, asked.stdlib,
                          [f for f in asked.features.split(",") if f])
    if len(argv) >= 2 and argv[1] == "preset-arm":
        preset = argparse.ArgumentParser(prog="perf_matrix.py preset-arm")
        preset.add_argument("--out", required=True)
        preset.add_argument("--original", required=True)
        preset.add_argument("--stdlib", required=True, choices=STDLIBS)
        asked = preset.parse_args(argv[2:])
        return cmd_preset_arm(pathlib.Path(asked.out), asked.original, asked.stdlib)
    if len(argv) in (4, 5) and argv[1] == "resident-text":
        return cmd_resident_text(pathlib.Path(argv[2]), pathlib.Path(argv[3]), argv[4] if len(argv) == 5 else "W")
    if len(argv) == 5 and argv[1] == "run-text-order":
        return cmd_run_text_order(pathlib.Path(argv[2]), pathlib.Path(argv[3]), pathlib.Path(argv[4]))
    if len(argv) >= 5 and argv[1] == "run-text":
        return cmd_run_text(pathlib.Path(argv[2]), pathlib.Path(argv[3]), [pathlib.Path(a) for a in argv[4:]])
    if len(argv) == 4 and argv[1] == "pin-sides":
        return cmd_pin_sides(argv[2:])
    if 2 <= len(argv) <= 4 and argv[1] == "idle-cpus":
        try:
            seconds = float(argv[2]) if len(argv) > 2 else 5.0
            per_side = int(argv[3]) if len(argv) > 3 else 4
        except ValueError:
            print(__doc__, file=sys.stderr)
            return 64
        return cmd_idle_cpus(seconds, per_side)
    if len(argv) < 2 or argv[1] != "run":
        print(__doc__, file=sys.stderr)
        return 64
    parser = argparse.ArgumentParser(prog="perf_matrix.py run")
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)))
    parser.add_argument("--transports", default=",".join(TRANSPORTS))
    parser.add_argument("--batching", default="off,on")
    parser.add_argument("--workloads", default=",".join(WORKLOADS))
    parser.add_argument("--client-cpus", default="4-7")
    parser.add_argument("--server-cpus", default="8-11")
    parser.add_argument("--pings", type=int, default=20000)
    parser.add_argument("--warmup-ms", type=int, default=3000)
    parser.add_argument("--window-s", type=int, default=5)
    parser.add_argument("--timeout-ms", type=int, default=100)
    parser.add_argument("--reference-record", default="")
    parser.add_argument("--external-record", default="")
    parser.add_argument("--trace-text", default="")
    return cmd_run(parser.parse_args(argv[2:]))


if __name__ == "__main__":
    sys.exit(main(sys.argv))

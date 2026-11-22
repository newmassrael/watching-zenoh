#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The host performance matrix of the pico C ABI (docs/pico-perf-matrix.md): round trip, throughput,
CPU and peak RSS of `perf_probe.c` built against libwz_capi_pico (arm W), against zenoh-pico built
as the same build (arm P) and, when the environment names one, against an external library of the pico
API (arm X), per transport and with batching off and on; and the gate that holds a run's cells to their
committed rows.

`scripts/pico-compare.sh perf` builds the arms and runs this; the subcommands are its steps.

    perf_matrix.py reference --out DIR --engine ENGINE
        zenoh-pico built as the same build as wz-capi-pico's default capabilities on ENGINE (tokio or
        coop, what `wz_config.py --bench-engine` resolved, `wz_config.bench_features`): the build the
        capability cost gate measures (`capability_cost_gate.pico_reference_tree` under the gate's
        `build_env`, its switches from `wz_config.pico_reference`), its library copied to DIR/lib-P,
        its headers to DIR/include-P, and what both arms are built as (the reference's pin, toolchain and switches, the wz features) to
        DIR/reference.json, the engine among it (`wz_engine`), which the run's record and the gate read
    perf_matrix.py pico-sys-include REPORT
        the include directory of the one zenoh-pico-sys build cargo's JSON REPORT names
    perf_matrix.py external-record OUT [WHY]
        the record of arm X written to OUT: with WHY, not measured for that reason; without, built from
        the library and the headers WZ_PERF_EXTERNAL_LIB and WZ_PERF_EXTERNAL_INCLUDE name (its label,
        WZ_PERF_EXTERNAL_NAME, and the digests of both, kept in the run's local result file only)
    perf_matrix.py run --bin-dir DIR --run DIR [--reps 3] [--sizes 8,64,1024] [--transports ...]
                       [--batching off,on] [--workloads rtt,thr] [--client-cpus 4-7] [--server-cpus 8-11]
                       [--pings 20000] [--warmup-ms 3000] [--window-s 5] [--timeout-ms 100]
                       [--reference-record FILE] [--external-record FILE]
        the matrix; DIR (--bin-dir) holds perf_probe_P, perf_probe_W and perf_probe_Wapp, and perf_probe_X
        when the external record says arm X was built
    perf_matrix.py --gate RESULT [--table TABLE] [--external-table FILE] [--without-external]
        the gate over a run's perf.json: every cell of W over P held to its row of TABLE (by default the
        committed table of the run's platform, PLATFORMS: deploy/pico_perf_ceiling.json for a run on
        Linux, deploy/pico_perf_ceiling_windows.json for one on Windows, and a table of another platform
        is refused), and W over X to the rows of the table outside the repository
        (--external-table, by default WZ_PERF_EXTERNAL_TABLE) when the run measured arm X. Exit 0 every
        row held, 1 a row failed, 2 an input refused, 3 nothing failed but a row or arm X was not
        measured (--without-external: a run without arm X is not that)
    perf_matrix.py --check-table TABLE
        the committed table's shape, and that its rows are the population of the default matrix
    perf_matrix.py windows-plan PACKAGE OUT
        the plan of a run on Windows (scripts/host-bench/windows/perf_matrix.ps1), written to OUT: arm W is
        the library of the Windows package PACKAGE (the zip pico_windows_package.py builds), verified
        against its manifest, and arm P zenoh-pico built as the same build, its switches derived from the
        package's features as `reference` derives them from the bench's build; with the figures, the
        reasons a cell is not applicable and the rules of a cell the runner applies, so the runner states
        none of its own. A package built from a commit whose inputs of that derivation differ from this
        tree's is refused
    perf_matrix.py idle-cpus [SECONDS] [PER_SIDE]
        each CPU's busy share over SECONDS (default 5) and its physical core, and a pinning of two sides of
        at least PER_SIDE (default 4) CPUs of whole cores, the least busy first, printed as the words
        `pico-compare.sh perf` reads; on a shared host a moment's idle CPUs are a guess the run's own
        validity check then grades
    perf_matrix.py --selftest
        the readers, the figures and the pinning on synthetic input

A CELL is one arm, transport, batching, workload and payload size in one repetition. Its two programs are
started afresh, the server side (pong, sub) pinned to --server-cpus and the client side (ping, pub) to
--client-cpus, in peer mode:

  * tcp        the server listens on tcp/127.0.0.1:<port>, the client connects;
  * udp        the same over udp/127.0.0.1:<port>; arms W and X, since a zenoh-pico peer accepts streams
               only and arm P records the cell as not applicable (NOT_APPLICABLE says why); an external
               library is asked, and a cell it cannot open is its lost cell;
  * multicast  both listen on the group udp/224.0.0.224:<port>#iface=lo;
  * program    wz only (perf_probe_Wapp, built with the `app-transport` capability): every link goes
               over a transport the program supplies, an AF_UNIX stream of its own (perf_probe.c, -T);
               the pico API has no such door, so arms P and X record the cell as not applicable.

The client side of every cell declares its publisher a second after its open, as upstream's z_pub_thr
does, and on tcp, udp and the program transport puts nothing it counts until that publisher matches the
server side's subscriber (perf_probe.c -M): a zenoh-pico publisher that knows of no subscriber sends
nothing and still counts the put. Both arms run the same arguments.

  * rtt  pong, then ping: --pings round trips of the size after --warmup-ms, each waited for up to
         --timeout-ms. Figures: the percentiles p50, p90 and p99 and the mean and extremes (microseconds),
         the round trips lost, the CPU of each side per round trip over its own active span, and of each
         process its whole CPU (user, system) and its peak RSS.
  * thr  sub, then pub: the publisher puts as fast as the session takes them; the subscriber reads its
         count over a --window-s window that starts --warmup-ms after its first sample. Figures: messages
         and payload bytes a second delivered in the window, the rate the publisher put, the CPU per
         message of each side (the publisher's over its loop per put, the subscriber's over the window per
         message delivered) and their sum, and the whole CPU and peak RSS of each process. A window that
         did not lie inside the publisher's loop (both read the one monotonic clock) is no rate.

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
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from nodrop import FOREIGN_LIMIT, MAX_RUNS, busy_seconds, cpu_list  # noqa: E402
from parity import Lost, Process  # noqa: E402
from kit_compare import bootstrap_ratio  # noqa: E402

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
    ("P", "program"): "zenoh-pico has no transport a program supplies (wz_ext_transport_* is wz's own door)",
    ("P", "udp"): "a zenoh-pico peer accepts streams only, so a udp/ listener answers no dialling peer "
                  "(its open fails with -120, the handshake's receive timeout)",
    ("X", "program"): "a library of the pico API has no transport a program supplies (wz_ext_transport_* is "
                      "wz's own door)",
}

#: Every figure a cell can carry, and which way it is better. `perf.json` carries this table, so a reader
#: of the file needs nothing else to tell a gain from a loss.
METRICS = {
    "rtt_p50_us": "lower", "rtt_p90_us": "lower", "rtt_p99_us": "lower", "rtt_mean_us": "lower",
    "rtt_min_us": "lower", "rtt_max_us": "lower", "round_trips": "higher", "lost": "lower",
    "ping_cpu_ns_per_rtt": "lower", "pong_cpu_ns_per_rtt": "lower",
    "msgs_per_s": "higher", "bytes_per_s": "higher", "offered_msgs_per_s": "higher", "put_failed": "lower",
    "cpu_ns_per_msg_pub": "lower", "cpu_ns_per_msg_sub": "lower", "cpu_ns_per_msg": "lower",
    "cpu_user_s_client": "lower", "cpu_sys_s_client": "lower", "cpu_user_s_server": "lower",
    "cpu_sys_s_server": "lower", "rss_kib_client": "lower", "rss_kib_server": "lower", "rss_kib": "lower",
}

PING_KEYS = ("round_trips", "lost", "aborted", "p50_ns", "p90_ns", "p99_ns", "min_ns", "max_ns", "mean_ns",
             "all_round_trips", "cpu_ns")
PONG_KEYS = ("answered", "cpu_ns", "stopped_by")
PUB_KEYS = ("sent", "failed", "elapsed_ns", "cpu_ns", "start_ns", "end_ns")
SUB_KEYS = ("received", "bytes", "window_ns", "cpu_ns", "start_ns", "end_ns")
SUB_END_KEYS = ("total", "last_growth_ns", "peers")


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
    """What a program said last, for the reason of a lost cell."""
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1][:160] if lines else "nothing"


@dataclass(frozen=True)
class Usage:
    """A reaped process's whole CPU and its peak resident set."""

    user_s: float
    sys_s: float
    rss_kib: int


def usage_of(proc: Process) -> Usage:
    if proc.rusage is None:
        return Usage(0.0, 0.0, 0)
    return Usage(proc.rusage.ru_utime, proc.rusage.ru_stime, int(proc.rusage.ru_maxrss))


def process_figures(client: Usage, server: Usage) -> dict[str, float]:
    return {"cpu_user_s_client": client.user_s, "cpu_sys_s_client": client.sys_s,
            "cpu_user_s_server": server.user_s, "cpu_sys_s_server": server.sys_s,
            "rss_kib_client": client.rss_kib, "rss_kib_server": server.rss_kib,
            "rss_kib": client.rss_kib + server.rss_kib}


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


def thr_figures(pub: dict[str, str], sub: dict[str, str], client: Usage, server: Usage) -> dict[str, float]:
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
    figures: dict[str, float] = {
        "msgs_per_s": received / window_s, "bytes_per_s": int(sub["bytes"]) / window_s,
        "offered_msgs_per_s": sent / (int(pub["elapsed_ns"]) / 1e9), "put_failed": int(pub["failed"]),
        "cpu_ns_per_msg_pub": pub_cpu, "cpu_ns_per_msg_sub": sub_cpu, "cpu_ns_per_msg": pub_cpu + sub_cpu,
    }
    figures.update(process_figures(client, server))
    return figures


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


def binary_name(arm: str, transport: str) -> str | None:
    """The program a cell runs, or None when the arm has no such transport."""
    if (arm, transport) in NOT_APPLICABLE:
        return None
    return "perf_probe_Wapp" if transport == "program" else f"perf_probe_{arm}"


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
        arm = groups.setdefault(key, {}).setdefault(cell["arm"], {"figures": [], "lost": 0, "status": set()})
        arm["status"].add(cell["status"])
        if cell["status"] == "measured":
            arm["figures"].append(numbers(cell["figures"]))
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
                          "median": {n: statistics.median([f[n] for f in figs if n in f]) for n in names}}
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

class Matrix:
    def __init__(self, args: argparse.Namespace, run: pathlib.Path):
        self.args = args
        self.run = run
        self.cpus = sorted(set(cpu_list(args.client_cpus)) | set(cpu_list(args.server_cpus)))
        self.serial = 0

    def start(self, binary: str, role: str, argv: list[str], side: str, tag: str) -> Process:
        cpus = self.args.client_cpus if side == "client" else self.args.server_cpus
        return Process([str(pathlib.Path(self.args.bin_dir) / binary), role, *argv], cpus,
                       self.run / f"{tag}.{role}.out", {})

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
            try:
                time.sleep(SETTLE_S)
                pub = self.start(binary, "pub", ["-m", "peer", *client, "-s", str(size), "-t", str(pub_s), *flags],
                                 "client", tag)
                done = pub.reap(pub_s + READY_S + 30)
            finally:
                if pub is not None:
                    pub.stop()
                sub.stop()
            if not done:
                raise Lost("pub did not finish in time")
            put = fields(pub.text(), "pub", PUB_KEYS)
            got = fields(sub.text(), "sub", SUB_KEYS)
            if put is None:
                raise Lost(f"pub gave no result; it said: {last_words(pub.text())}")
            if got is None:
                raise Lost(f"sub gave no window; it said: {last_words(sub.text())}")
            try:
                return thr_figures(put, got, usage_of(pub), usage_of(sub)), [pub, sub]
            except Lost as why:
                raise Lost(f"{why}; {stall_note(put, fields(sub.text(), 'sub', SUB_END_KEYS))}") from None

        return self.timed(body)

    def cell(self, arm: str, transport: str, batching: bool, workload: str, size: int, rep: int) -> dict:
        cell = {"arm": arm, "transport": transport, "batching": batching, "workload": workload, "size": size,
                "rep": rep}
        binary = binary_name(arm, transport)
        if binary is None:
            cell.update(status="not-applicable", why=NOT_APPLICABLE[(arm, transport)], figures={})
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
    if record["engine"] is None:
        print("perf-matrix: NOT-MEASURED, the run names no record of the build it measures that states its "
              "engine (--reference-record, written by `reference --engine`)", flush=True)
        return 2
    arms = run_arms(record["external"])
    wanted = {binary_name(arm, t) for arm in arms for t in transports} - {None}
    missing = sorted(b for b in wanted if not os.access(pathlib.Path(args.bin_dir) / b, os.X_OK))
    if missing:
        print(f"perf-matrix: NOT-MEASURED, {args.bin_dir} lacks {', '.join(missing)}", flush=True)
        return 2
    if "X" not in arms:
        print(f"perf-matrix: arm X NOT-MEASURED, {record['external'].get('why', 'no reason given')}", flush=True)
    run = pathlib.Path(args.run)
    run.mkdir(parents=True, exist_ok=False)
    record["started"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    matrix = Matrix(args, run)
    plan = [(rep, transport, batching, size, workload, arm)
            for rep in range(1, args.reps + 1)
            for transport in transports
            for batching in batchings
            for size in sizes
            for workload in workloads
            for arm in (arms if rep % 2 else arms[::-1])]
    print(f"perf-matrix: {args.reps} repetition(s) of {', '.join(transports)} x batching {', '.join(batchings)} "
          f"x {', '.join(workloads)} x {', '.join(map(str, sizes))} B, arms {', '.join(arms)}; client side on "
          f"{args.client_cpus}, server side on {args.server_cpus}; arm W on the {record['engine']} engine", flush=True)
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


def cmd_reference(out: pathlib.Path, engine: str) -> int:
    """zenoh-pico built as the same build as wz-capi-pico's default capabilities on `engine`, into
    `out`."""
    # The gate's builder and resolver, imported here and not at the top: the selftest needs neither.
    import capability_cost_gate as cost
    import wz_config

    table = wz_config.manifest_features(cost.CRATES / "wz-capi-pico" / "Cargo.toml")
    try:
        features = wz_config.bench_features(engine, [], table)
        program_features = wz_config.bench_features(engine, ["app-transport"], table)
    except wz_config.PresetError as error:
        print(f"perf-matrix: NOT-MEASURED, {error}", flush=True)
        return 2
    asked = wz_config.pico_reference(wz_config.load_decl(), features)
    # The gate's build rule too: the reference's key holds the rule's C flags and epoch, so the
    # library timed here is the one the gate's size and ratio are read from.
    try:
        env, _ = cost.build_env()
    except ValueError as error:
        print(f"perf-matrix: NOT-MEASURED, the build normalisation refused this host: {error}", flush=True)
        return 2
    work, pin, toolchain = cost.pico_reference_tree(asked, env)
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
              "reference_refused": refused, "wz_features": sorted(features),
              "wz_program_transport_features": sorted(program_features), "wz_engine": engine}
    (out / "reference.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"perf-matrix: reference zenoh-pico {pin[:12]} as the same build ({toolchain}); "
          f"{len(asked)} switches set from the declaration", flush=True)
    if refused:
        print(f"perf-matrix: pico built {', '.join(refused)} otherwise than asked, so the two builds differ "
              f"there (reference.json says so)", flush=True)
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
TABLE_SCHEMA = "wz-pico-perf-ceiling/1"
#: The engines arm W is built on, as `wz_config.PICO_ENGINES` names them: a run records the one it measured
#: and a table the one its rows were filled from, and the gate refuses a run against another engine's rows.
ENGINES = ("tokio", "coop")
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


def population(ref: str, sizes: tuple[int, ...] = DEFAULT_SIZES) -> list[str]:
    """Every row a full run of the matrix gives the pair of W and `ref`: each transport both arms have, both
    batchings, both workloads, each size and each held figure."""
    return [row_key(t, b, w, s, m)
            for t in TRANSPORTS if binary_name("W", t) and binary_name(ref, t)
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


def platform_named(doc: object, what: str) -> str:
    """The platform a run's record or a table names, Linux when it names none; one that is no platform of
    PLATFORMS is refused."""
    platform = doc.get("platform") if isinstance(doc, dict) else None
    if platform is None:
        return DEFAULT_PLATFORM
    if platform not in PLATFORMS:
        raise Refused(f"{what} names the platform {platform!r}, and a run is made on one of {', '.join(PLATFORMS)}")
    return platform


def table_platform(text: str) -> str:
    """The platform a table's rows were filled on."""
    try:
        doc = json.loads(text)
    except ValueError as error:
        raise Refused(f"not JSON: {error}") from None
    return platform_named(doc, "the table")


def load_table(path: pathlib.Path, pair: str) -> tuple[dict, float, str | None, str]:
    """The rows, the tolerance, the engine and the platform of the table at `path`."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise Refused(f"{path} cannot be read: {error}") from None
    try:
        rows, tolerance = parse_table(text, pair)
        return rows, tolerance, table_engine(text), table_platform(text)
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


def table_document(pair: str, rows: dict, tolerance: float, engine: str, platform: str) -> str:
    return json.dumps({"schema": TABLE_SCHEMA, "pair": pair, "engine": engine, "platform": platform,
                       "tolerance": tolerance, "rows": rows}, indent=1)


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
              engine: str, platform: str) -> str:
    """Judge the pair of W and `ref`, arm W measured on `engine` in a run on `platform`. A table of W over X
    inside the repository is refused; one that is not named, or does not exist yet, fails with the whole table to
    write printed. A table whose rows were filled from another engine, or on another platform, is refused, and
    so is a table of W over P that does not say its engine."""
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
            print(table_document(pair, rows, DEFAULT_TOLERANCE, engine, platform), flush=True)
            print(f"perf-gate {pair}: FAIL", flush=True)
            return "FAIL"
    if table is None:
        raise Refused(f"no table of {pair} was named")
    rows, tolerance, filled_from, filled_on = load_table(table, pair)
    if filled_on != platform:
        raise Refused(f"{table} holds rows of runs on {filled_on}, and this run was made on {platform}: judge "
                      f"it against the table of its own platform ({PLATFORMS[platform].relative_to(ROOT)})")
    if filled_from is None and ref == "P":
        raise Refused(f"{table} does not say which engine its rows were filled from (`engine`)")
    if filled_from is not None and filled_from != engine:
        raise Refused(f"{table} holds rows filled from the {filled_from} engine, and this run measured the "
                      f"{engine} engine: judge it against a table of its own engine, or run that engine "
                      f"(PICO_CMP_ENGINE={filled_from})")
    print(f"perf-gate {pair}: arm W on the {engine} engine", flush=True)
    return print_pair(pair, str(table), tolerance, judge(found, rows, tolerance))


def cmd_gate(args: argparse.Namespace) -> int:
    try:
        doc = json.loads(pathlib.Path(args.result).read_text(encoding="utf-8"))
        if doc.get("schema") != SCHEMA:
            raise Refused(f"{args.result} is not a result of schema {SCHEMA}")
        cells = doc["cells"]
        engine = doc.get("record", {}).get("engine")
        if engine not in ENGINES:
            raise Refused(f"{args.result} does not say which engine arm W was built on")
        platform = platform_named(doc.get("record"), f"the record of {args.result}")
        external = doc.get("record", {}).get("external") or {
            "status": "not-measured", "why": "the run's record says nothing of arm X"}
        # A transport the run left out says why in its record (a group the host's network does not carry);
        # its rows are then not measured, and the reason is printed beside them.
        for transport, why in sorted((doc.get("record", {}).get("not_measured") or {}).items()):
            print(f"perf-gate: the run did not measure {transport}: {why}", flush=True)
        table = pathlib.Path(args.table) if args.table else PLATFORMS[platform]
        outcomes = [gate_pair("P", cells, table, [], engine, platform)]
        if external.get("status") == "built":
            named = args.external_table or os.environ.get(EXTERNAL_TABLE, "")
            outcomes.append(gate_pair("X", cells, pathlib.Path(named) if named else None, repository_roots(),
                                      engine, platform))
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
        rows, tolerance, engine, platform = load_table(path, PAIR_NAMES["P"])
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
    wanted = set(population("P"))
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
          f"{len(rows) - filled} not yet (tolerance {tolerance}), filled from the {engine} engine on {platform}")
    return 0


# -- a run on Windows ----------------------------------------------------------------------------------------

#: What `windows-plan` writes and scripts/host-bench/windows/perf_matrix.ps1 reads.
WINDOWS_PLAN_SCHEMA = "wz-pico-perf-windows-plan/1"
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


def windows_plan(manifest: dict, statement: dict, table: dict, decl: dict, target: str) -> dict:
    """What a run on Windows measures, from a package's manifest and build statement: arm W is the package's
    library, built for `target` with the features its manifest lists on the engine its statement states, and
    arm P zenoh-pico built as the same build, every switch the declaration answers set from those features
    (`wz_config.pico_reference`), as `reference` derives the Linux arm from the bench's build. `table` is the
    feature table of wz-capi-pico, `decl` the declaration. A package of another width, one that names a feature
    the crate lacks, and one whose statement's engine is not the one its features run are refused."""
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
    return {"wz_features": sorted(features), "wz_engine": engine,
            "reference_switches": wz_config.pico_reference(decl, enabled)}


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
        plan = windows_plan(manifest, statement, table, wz_config.load_decl(), pwp.ARCHES[WINDOWS_ARCH][0])
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, pwp.Refusal, Refused) as why:
        print(f"perf-matrix: windows-plan refused: {why}", file=sys.stderr, flush=True)
        return 2
    status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"],
                            capture_output=True, text=True)
    doc = {
        "schema": WINDOWS_PLAN_SCHEMA, "platform": WINDOWS_PLATFORM,
        "tree": first_line(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "tree_dirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
        "package": {"name": name, "zip": package.name, "sha256": sha256_of(package), "commit": commit,
                    "form": manifest.get("form"), "libraries": manifest.get("libraries"),
                    "target": manifest.get("target"), "rustc": (manifest.get("toolchain") or {}).get("rustc"),
                    "statement_digest": manifest.get("statement_digest")},
        "reference_pin": first_line(["git", "-C", str(ROOT / "vendor" / "zenoh-pico"), "rev-parse", "HEAD"]),
        **plan,
        # What the runner applies and records, stated once here so the two runners cannot drift apart.
        "metrics": METRICS,
        "transports": list(TRANSPORTS), "workloads": list(WORKLOADS), "arms": ["P", "W"],
        "not_applicable": {f"{arm}/{transport}": why for (arm, transport), why in NOT_APPLICABLE.items()},
        "not_run": WINDOWS_NOT_RUN,
        "line_keys": {"ping": list(PING_KEYS), "pong": list(PONG_KEYS), "pub": list(PUB_KEYS),
                      "sub": list(SUB_KEYS), "sub_end": list(SUB_END_KEYS)},
        "foreign_limit": FOREIGN_LIMIT, "max_runs": MAX_RUNS, "settle_s": SETTLE_S, "pub_tail_s": PUB_TAIL_S,
        "ready_s": READY_S, "group": GROUP, "schema_of_result": SCHEMA,
    }
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"perf-matrix: the plan of a run on Windows: arm W {name} on the {plan['wz_engine']} engine, arm P "
          f"zenoh-pico {doc['reference_pin'][:12]} with {len(plan['reference_switches'])} switches set; {out}",
          flush=True)
    return 0


# -- the selftest -------------------------------------------------------------------------------------------

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
    expect("arm P has no program transport and arm W runs it from its own build",
           binary_name("P", "program") is None and binary_name("W", "program") == "perf_probe_Wapp"
           and binary_name("P", "tcp") == "perf_probe_P" and binary_name("W", "multicast") == "perf_probe_W")
    expect("arm P has no udp cell, and arm W runs udp from its default build",
           binary_name("P", "udp") is None and binary_name("W", "udp") == "perf_probe_W")
    expect("every arm and transport has a program or a reason it has none",
           all(binary_name(a, t) is not None or (a, t) in NOT_APPLICABLE for a in ARMS for t in TRANSPORTS))

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
    # -- arm X ------------------------------------------------------------------------------------------
    expect("arm X runs every transport but the program's, from a probe of its own",
           binary_name("X", "udp") == "perf_probe_X" and binary_name("X", "tcp") == "perf_probe_X"
           and binary_name("X", "program") is None)
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

    def table(rows, pair="W/P", tolerance=0.05, schema=TABLE_SCHEMA, engine="tokio", platform=None):
        doc = {"schema": schema, "pair": pair, "tolerance": tolerance, "rows": rows}
        if engine is not None:
            doc["engine"] = engine
        if platform is not None:
            doc["platform"] = platform
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
    expect("the default population of W over P holds tcp and multicast, of W over X udp too",
           len(population("P")) == 2 * 2 * 3 * 7 and len(population("X")) == 3 * 2 * 3 * 7
           and all(key.split("/")[0] in ("tcp", "multicast") for key in population("P"))
           and population("P") == sorted(population("P"), key=key_order))
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
             table_engine_="tokio", table_platform_=None):
        with tempfile.TemporaryDirectory() as scratch:
            base = pathlib.Path(scratch)
            (base / "perf.json").write_text(json.dumps({"schema": schema, "record": record, "cells": cells}),
                                            encoding="utf-8")
            if external_table == "absent":
                external_table = str(base / "no-such-table.json")
            (base / "table.json").write_text(table(table_rows, engine=table_engine_, platform=table_platform_),
                                             encoding="utf-8")
            if x_rows is not None:
                where = base / "x.json"
                where.write_text(table(x_rows, pair="W/X"), encoding="utf-8")
                external_table = str(where)
            args = argparse.Namespace(result=str(base / "perf.json"), table=str(base / "table.json"),
                                      external_table=external_table, without_external=without)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return cmd_gate(args)

    no_x = {"engine": "tokio", "external": {"status": "not-measured", "why": "unset"}}
    expect("a run without arm X is NOT-MEASURED for W/X even when W/P holds",
           gate(run_cells, no_x, locked) == 3)
    expect("asked W/P alone, a run whose every row holds passes", gate(run_cells, no_x, locked, without=True) == 0)
    expect("a row missing from the table fails the gate",
           gate(run_cells, no_x, {k: v for k, v in locked.items() if k != keys[0]}, without=True) == 1)
    x_cells = run_cells + [dict(c, arm="X") for c in run_cells if c["arm"] == "P"]
    built_x = {"engine": "tokio", "external": {"status": "built", "name": "lab"}}
    expect("a run that measured arm X and was given no table of it fails, asked W/P alone or not",
           gate(x_cells, built_x, locked, external_table="absent") == 1
           and gate(x_cells, built_x, locked, external_table="absent", without=True) == 1)
    expect("a run that measured arm X passes when both tables hold every row",
           gate(x_cells, built_x, locked, x_rows=locked) == 0)
    expect("a table of W/X inside the repository is refused",
           gate(x_cells, built_x, locked, external_table=str(ROOT / "deploy" / "x.json")) == 2)
    expect("a result of another schema is refused", gate(run_cells, no_x, locked, schema="wz-other/1") == 2)
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
    expect("each platform's runs are judged by default against its own committed table",
           PLATFORMS[DEFAULT_PLATFORM] == CEILING and PLATFORMS[WINDOWS_PLATFORM] == CEILING_WINDOWS
           and set(PLATFORMS) == {DEFAULT_PLATFORM, WINDOWS_PLATFORM})

    # -- the plan of a run on Windows ------------------------------------------------------------------------
    feature_table = {"default": ["engine-tokio"], "engine-tokio": [], "engine-coop": [], "advanced": [],
                     "app-transport": ["advanced"]}
    switch_rows = {"switches": [
        {"original": "zenoh-pico", "switch": "Z_FEATURE_ADVANCED_PUBLICATION", "class": "maps",
         "anchor": "wz-capi-pico/advanced"},
        {"original": "zenoh-pico", "switch": "Z_FEATURE_MATCHING", "class": "always"},
        {"original": "zenoh-pico", "switch": "Z_FEATURE_RAWETH_TRANSPORT", "class": "never"},
        {"original": "zenoh-pico", "switch": "BATCH_UNICAST_SIZE", "class": "maps", "anchor": "wz-capi-pico/x"},
        {"original": "zenoh-c", "switch": "Z_FEATURE_SHARED_MEMORY", "class": "always"}]}
    x64 = "x86_64-pc-windows-msvc"
    package_manifest = {"target": x64, "features": ["engine-coop", "app-transport"]}
    planned = windows_plan(package_manifest, {"engine": "coop"}, feature_table, switch_rows, x64)
    expect("a plan pairs the package's library with pico built with the switches its features answer",
           planned["reference_switches"] == {"Z_FEATURE_ADVANCED_PUBLICATION": 1, "Z_FEATURE_MATCHING": 1,
                                             "Z_FEATURE_RAWETH_TRANSPORT": 0}
           and planned["wz_engine"] == "coop" and planned["wz_features"] == ["app-transport", "engine-coop"])

    def plan_refused(manifest, statement):
        try:
            windows_plan(manifest, statement, feature_table, switch_rows, x64)
        except Refused:
            return True
        return False

    expect("a package of another width, or one that lists no features, is refused",
           plan_refused(dict(package_manifest, target="i686-pc-windows-msvc"), {"engine": "coop"})
           and plan_refused(dict(package_manifest, features=[]), {"engine": "coop"}))
    expect("a package that names a feature the crate does not have is refused",
           plan_refused(dict(package_manifest, features=["engine-coop", "gone"]), {"engine": "coop"}))
    expect("a statement whose engine is not the one the package's features run is refused",
           plan_refused(package_manifest, {"engine": "tokio"})
           and plan_refused(dict(package_manifest, features=["engine-tokio"]), {"engine": "coop"})
           and plan_refused(package_manifest, {}))
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
    if len(argv) == 6 and argv[1] == "reference" and argv[2] == "--out" and argv[4] == "--engine":
        if argv[5] not in ENGINES:
            print(f"perf-matrix: --engine is one of {', '.join(ENGINES)}", file=sys.stderr)
            return 64
        return cmd_reference(pathlib.Path(argv[3]), argv[5])
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
    return cmd_run(parser.parse_args(argv[2:]))


if __name__ == "__main__":
    sys.exit(main(sys.argv))

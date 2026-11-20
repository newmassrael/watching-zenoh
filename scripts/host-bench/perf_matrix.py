#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The host performance matrix of the pico C ABI (docs/pico-perf-matrix.md): round trip, throughput,
CPU and peak RSS of `perf_probe.c` built against libwz_capi_pico (arm W) and against zenoh-pico built
as the same build (arm P), per transport and with batching off and on.

`scripts/pico-compare.sh perf` builds the arms and runs this; the subcommands are its steps.

    perf_matrix.py reference --out DIR
        zenoh-pico built as the same build as wz-capi-pico's default features: the build the
        capability cost gate measures (`capability_cost_gate.pico_reference_tree`, its switches from
        `wz_config.pico_reference`), its library copied to DIR/lib-P, its headers to DIR/include-P, and
        what both arms are built as (the reference's pin, toolchain and switches, the wz features) to
        DIR/reference.json
    perf_matrix.py pico-sys-include REPORT
        the include directory of the one zenoh-pico-sys build cargo's JSON REPORT names
    perf_matrix.py run --bin-dir DIR --run DIR [--reps 3] [--sizes 8,64,1024] [--transports ...]
                       [--batching off,on] [--workloads rtt,thr] [--client-cpus 4-7] [--server-cpus 8-11]
                       [--pings 20000] [--warmup-ms 3000] [--window-s 5] [--timeout-ms 100]
                       [--reference-record FILE]
        the matrix; DIR (--bin-dir) holds perf_probe_P, perf_probe_W and perf_probe_Wapp
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
  * udp        the same over udp/127.0.0.1:<port>; arm W only, since a zenoh-pico peer accepts streams
               only and arm P records the cell as not applicable (NOT_APPLICABLE says why);
  * multicast  both listen on the group udp/224.0.0.224:<port>#iface=lo;
  * program    wz only (perf_probe_Wapp, built with the `app-transport` capability): every link goes
               over a transport the program supplies, an AF_UNIX stream of its own (perf_probe.c, -T);
               zenoh-pico has no such door, so arm P records the cell as not applicable.

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
"""

from __future__ import annotations

import argparse
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
import time
from dataclasses import dataclass

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from nodrop import FOREIGN_LIMIT, MAX_RUNS, busy_seconds, cpu_list  # noqa: E402
from parity import Lost, Process  # noqa: E402

SCHEMA = "wz-pico-perf/1"
TRANSPORTS = ("tcp", "udp", "multicast", "program")
WORKLOADS = ("rtt", "thr")
ARMS = ("P", "W")
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
    lost ones, and the median of each figure; and W over P of each figure both arms have."""
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
        ratio = {}
        if "P" in arms and "W" in arms:
            for n, w in arms["W"]["median"].items():
                p = arms["P"]["median"].get(n)
                if p:
                    ratio[n] = w / p
        rows.append({"transport": key[0], "batching": key[1], "workload": key[2], "size": key[3],
                     "arms": arms, "w_over_p": ratio})
    return rows


def report_lines(rows: list[dict]) -> list[str]:
    """The summary as text: one block per row, one line per figure, P and W medians and W over P."""
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
            out.append(f"    {n:<22} P {p:>12}  W {w:>12}  W/P {r:>7}  ({METRICS.get(n, '?')} is better)")
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
        "timeout_ms": args.timeout_ms, "foreign_limit": FOREIGN_LIMIT,
    }
    if args.reference_record:
        record["builds"] = json.loads(pathlib.Path(args.reference_record).read_text(encoding="utf-8"))
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
    wanted = {binary_name(arm, t) for arm in ARMS for t in transports} - {None}
    missing = sorted(b for b in wanted if not os.access(pathlib.Path(args.bin_dir) / b, os.X_OK))
    if missing:
        print(f"perf-matrix: NOT-MEASURED, {args.bin_dir} lacks {', '.join(missing)}", flush=True)
        return 2
    run = pathlib.Path(args.run)
    run.mkdir(parents=True, exist_ok=False)
    record = host_record(args)
    record["started"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    matrix = Matrix(args, run)
    plan = [(rep, transport, batching, size, workload, arm)
            for rep in range(1, args.reps + 1)
            for transport in transports
            for batching in batchings
            for size in sizes
            for workload in workloads
            for arm in (ARMS if rep % 2 else ARMS[::-1])]
    print(f"perf-matrix: {args.reps} repetition(s) of {', '.join(transports)} x batching {', '.join(batchings)} "
          f"x {', '.join(workloads)} x {', '.join(map(str, sizes))} B, arms P and W; client side on "
          f"{args.client_cpus}, server side on {args.server_cpus}", flush=True)
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


def cmd_reference(out: pathlib.Path) -> int:
    """zenoh-pico built as the same build as wz-capi-pico's default features, into `out`."""
    # The gate's builder and resolver, imported here and not at the top: the selftest needs neither.
    import capability_cost_gate as cost
    import wz_config

    table = wz_config.manifest_features(cost.CRATES / "wz-capi-pico" / "Cargo.toml")
    features = wz_config.pico_build_features("tokio", [], table)
    program_features = wz_config.pico_build_features("tokio", ["app-transport"], table)
    asked = wz_config.pico_reference(wz_config.load_decl(), features)
    work, pin, toolchain = cost.pico_reference_tree(asked)
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
              "wz_program_transport_features": sorted(program_features)}
    (out / "reference.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"perf-matrix: reference zenoh-pico {pin[:12]} as the same build ({toolchain}); "
          f"{len(asked)} switches set from the declaration", flush=True)
    if refused:
        print(f"perf-matrix: pico built {', '.join(refused)} otherwise than asked, so the two builds differ "
              f"there (reference.json says so)", flush=True)
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
    if len(argv) == 3 and argv[1] == "pico-sys-include":
        try:
            print(pico_sys_include(pathlib.Path(argv[2]).read_text(encoding="utf-8").splitlines()))
        except (OSError, ValueError) as why:
            print(f"perf-matrix: {why}", file=sys.stderr)
            return 1
        return 0
    if len(argv) == 4 and argv[1] == "reference" and argv[2] == "--out":
        return cmd_reference(pathlib.Path(argv[3]))
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
    parser.add_argument("--sizes", default="8,64,1024")
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
    return cmd_run(parser.parse_args(argv[2:]))


if __name__ == "__main__":
    sys.exit(main(sys.argv))

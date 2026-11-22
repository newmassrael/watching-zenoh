#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The MCU speed matrix of the pico C ABI (docs/mcu-speed-matrix.md): instructions per put and per received
sample, the round trip, the throughput and the stack and heap of one program of the pico API on an emulated
MCU, built against zenoh-pico (arm P) and linked to wz's pico C ABI (arm W) on the same board, kernel and
network stack, and the gate that holds a run's cells to the committed rows of
deploy/pico_perf_ceiling_mcu.json.

`scripts/mcu-speed.sh` builds the images and the host peer and runs this; the subcommands are its steps.

    mcu_speed.py run --images DIR --peer FILE --pacer FILE --zenohd FILE --run DIR [--board mps2/an385]
                     [--qemu-machine MACHINE] [--qemu qemu-system-arm] [--reps 3] [--sizes 8,64,1024]
                     [--threads st,mt] [--workloads put,sub,rtt] [--puts 2000] [--window-ms 2000]
                     [--warmup-ms 500] [--offer-rate 1000] [--round-trips 500] [--warmup-round-trips 50]
                     [--timeout-ms 200] [--router-log FILTER]
        the matrix; DIR (--images) holds <arm>-<threads>.elf for each arm and threading arm asked, --peer the
        host probe (scripts/host-bench/perf_probe.c built against zenoh-pico on the host), --pacer the host
        publisher that offers a stated rate (scripts/host-bench/paced_pub.c, built the same way), --zenohd the
        router both images dial. --qemu-machine, when given, must be the board's own machine. --router-log
        hands the router a log filter (its RUST_LOG), to read what it was sent and what it answered.
    mcu_speed.py --gate RESULT [--table TABLE]
        the gate over a run's mcu-speed.json: every cell of W over P held to its row of TABLE (by default the
        committed deploy/pico_perf_ceiling_mcu.json). Exit 0 every row held, 1 a row failed, 2 an input
        refused, 3 nothing failed but a row was not measured
    mcu_speed.py --check-table TABLE
        the committed table's shape, and that its rows are the population of the default matrix of its
        platform
    mcu_speed.py --selftest
        the readers, the figures, the readings and the gate on synthetic consoles and runs

THE TARGET. One QEMU machine Zephyr runs on with its own Ethernet driver (BOARDS), the board the Zephyr
lanes already boot with a network (Layer Qza). QEMU runs with -icount: each guest instruction advances the
guest's clock by 2^shift ns, so the cycles the kernel counts while a thread runs are a count of the
instructions it ran, the same on every run of the same work whatever the host is doing. The guest sleeps in
real time (sleep=on), because the host peer answers in real time: with sleep=off an idle guest would jump
to its next deadline while a datagram from the host is still on its way, and its timeouts and leases would
fire where a board's would not. So an instruction count is the emulator's and deterministic, and a time is
the guest's work at one instruction per 2^shift ns plus the real time the host side took, which is the same
host, router and probe for both arms.

A CELL is one arm, threading arm, workload and payload size in one repetition, and one boot: QEMU starts the
image with the cell on its command line (semihosting), the image opens a client session to the router over
QEMU's user network and runs the workload against the host probe, which is a peer of the same router:

  * put  the probe subscribes (perf/thr), the image puts --puts samples as fast as the session takes them
         once its publisher matches; figures: instructions per put (every thread but the idle thread, over
         the loop and the network stack's tail), puts a second over the loop, and the share the probe got.
  * sub  the image subscribes, the pacer puts --offer-rate samples a second once it matches; from the
         image's first sample it waits --warmup-ms, then counts over a --window-ms window: instructions
         per sample, samples a second of the window, and samples a second of busy time (the most the core
         could take if receiving were all it did). The offer is paced because a publisher that puts as fast
         as its session takes them floods QEMU's user network: it drops what the guest cannot take, the
         guest's session starves and the router ends it, and nothing is delivered to either arm.
  * rtt  the probe answers perf/ping on perf/pong; the image times --round-trips after
         --warmup-round-trips, each waited for up to --timeout-ms: the percentiles in microseconds and the
         instructions per round trip.

After its workload the image says the sum of every thread's stack high-water mark and the kernel heap's
peak. A cell whose image or probe did not give its figures is LOST with the reason. The order of the arms
alternates by repetition, so a drift of the host falls on both.

THE GATE reads each row as perf_matrix.py's does (decision D10 of docs/upstream-parity.md): the cost ratio
of the medians, wz over the reference when lower is better and the reference over wz when higher is
better, with its bootstrap 95% interval over at least three repetitions of each arm, D1's verdict, and
perf_matrix.py's judge, lock, ratchet and debt order. A row key is
<machine>/<threads>/<workload>/<size>/<figure>, and a table states the platform its rows were read on: a
run on another machine or at another -icount shift is refused against it.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import re
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import perf_matrix as pm  # noqa: E402  -- D10's reading, verdict, judge and ratchet

SCHEMA = "wz-mcu-speed/1"
TABLE_SCHEMA = "wz-pico-perf-ceiling-mcu/1"
TABLE = ROOT / "deploy" / "pico_perf_ceiling_mcu.json"
PAIR = "W/P"
ARMS = ("P", "W")
THREADS = ("st", "mt")
WORKLOADS = ("put", "sub", "rtt")
DEFAULT_SIZES = (8, 64, 1024)
#: The guest's clock advances 2^ICOUNT_SHIFT ns per instruction. At 0 the emulated core is faster than the
#: host emulates it, so a busy guest's clock runs behind the host's and no lease the guest holds expires
#: early; and the busy nanoseconds are the instructions themselves.
ICOUNT_SHIFT = 0
#: The probe's payload carries its sequence number in its first eight bytes, and the image's buffer holds
#: a kilobyte.
MIN_SIZE, MAX_SIZE = 8, 1024


@dataclass(frozen=True)
class Board:
    machine: str
    cpu: str


#: The boards the matrix runs on: the Zephyr board, and the QEMU machine and core that run its image.
BOARDS = {"mps2/an385": Board("mps2-an385", "cortex-m3")}
DEFAULT_BOARD = "mps2/an385"
#: Where QEMU's user network answers for the host, and the MAC it gives the guest.
GUEST_HOST = "10.0.2.2"
GUEST_MAC = "52:54:00:12:34:56"

#: Every figure a cell can carry, and which way it is better.
METRICS = {
    "instr_per_put": "lower", "put_msgs_per_s": "higher", "put_failed": "lower", "delivered_share": "higher",
    "instr_per_sample": "lower", "sub_msgs_per_s": "higher", "sub_bytes_per_s": "higher",
    "sub_msgs_per_busy_s": "higher",
    "rtt_p50_us": "lower", "rtt_p90_us": "lower", "rtt_p99_us": "lower", "rtt_mean_us": "lower",
    "rtt_min_us": "lower", "rtt_max_us": "lower", "instr_per_rtt": "lower", "lost": "lower",
    "stack_bytes": "lower", "heap_peak_bytes": "lower",
}
#: The figures the gate holds, per workload. The share the probe got of a put loop is read, not held: a
#: datagram the emulator's network drops is the network's, and both arms send into the same one.
GATED = {
    "put": ("instr_per_put", "put_msgs_per_s", "stack_bytes", "heap_peak_bytes"),
    "sub": ("instr_per_sample", "sub_msgs_per_busy_s", "stack_bytes", "heap_peak_bytes"),
    "rtt": ("rtt_p50_us", "rtt_p99_us", "instr_per_rtt", "stack_bytes", "heap_peak_bytes"),
}

TAG = "MCU-SPEED"
RESULT_KEYS = {
    "put": ("size", "sent", "failed", "loop_cycles", "busy_cycles", "hz"),
    "sub": ("size", "received", "bytes", "window_cycles", "busy_cycles", "hz"),
    "rtt": ("size", "round_trips", "lost", "attempts", "p50_cycles", "p90_cycles", "p99_cycles", "min_cycles",
            "max_cycles", "mean_cycles", "busy_cycles", "hz"),
}
MEMORY_KEYS = ("stack_used", "heap_peak", "heap_size")

#: Seconds: a probe's declarations before the image boots, an image's boot to its READY line, a cell's
#: whole run, and the router's start.
SETTLE_S = 1.0
READY_S = 60.0
CELL_S = 300.0
ROUTER_S = 20.0


class Lost(Exception):
    """A cell that gave no figures: the reason is the message."""


# -- reading a console ---------------------------------------------------------------------------------------

def words(line: str) -> dict[str, str]:
    """The key=value words of a line."""
    out = {}
    for word in line.split():
        key, eq, value = word.partition("=")
        if eq:
            out[key] = value
    return out


def tagged(text: str, kind: str) -> list[str]:
    """The lines of a console that are the image's lines of one kind, the emulator's carriage returns gone."""
    head = f"{TAG} {kind}"
    out = []
    for raw in text.splitlines():
        line = raw.replace("\r", "").strip()
        if line == head or line.startswith(head + " "):
            out.append(line)
    return out


def integers(line: str, keys: tuple[str, ...]) -> dict[str, int] | None:
    """The integer values of the keys in a line, or None when one is missing or no number."""
    found = words(line)
    out = {}
    for key in keys:
        value = found.get(key, "")
        if not value.isdigit():
            return None
        out[key] = int(value)
    return out


def result_of(text: str, workload: str) -> dict[str, int] | None:
    for line in reversed(tagged(text, "RESULT")):
        if words(line).get("workload") == workload:
            return integers(line, RESULT_KEYS[workload])
    return None


def memory_of(text: str) -> dict[str, int] | None:
    lines = tagged(text, "MEMORY")
    return integers(lines[-1], MEMORY_KEYS) if lines else None


def stacks_of(text: str) -> list[dict]:
    out = []
    for line in tagged(text, "STACK"):
        found = words(line)
        if found.get("used", "").isdigit() and found.get("size", "").isdigit():
            out.append({"thread": found.get("thread", "unnamed"), "used": int(found["used"]),
                        "size": int(found["size"])})
    return out


def failure_of(text: str) -> str | None:
    lines = tagged(text, "FAIL")
    return words(lines[-1]).get("why", "no reason given") if lines else None


def probe_total(text: str) -> int | None:
    """What the host probe's subscriber was handed in all, from its last line (perf_probe.c)."""
    for raw in reversed(text.splitlines()):
        if raw.startswith("perf_probe sub total="):
            value = words(raw).get("total", "")
            return int(value) if value.isdigit() else None
    return None


# -- the figures ---------------------------------------------------------------------------------------------

def instructions(cycles: int, hz: int, shift: int) -> float:
    """The guest instructions that many cycles of the kernel's counter are under -icount shift=SHIFT."""
    return cycles * 1e9 / hz / (1 << shift)


def micros(cycles: int, hz: int) -> float:
    return cycles * 1e6 / hz


def memory_figures(memory: dict[str, int] | None) -> dict[str, float]:
    if memory is None:
        raise Lost("the image did not report its memory")
    return {"stack_bytes": float(memory["stack_used"]), "heap_peak_bytes": float(memory["heap_peak"])}


def put_figures(result: dict[str, int], memory: dict[str, int] | None, delivered: int | None,
                shift: int) -> dict[str, float | None]:
    hz, sent = result["hz"], result["sent"]
    if hz <= 0:
        raise Lost("the image reported no cycle rate")
    if sent == 0:
        raise Lost(f"no put returned success ({result['failed']} failed)")
    if result["loop_cycles"] <= 0:
        raise Lost("the put loop took no cycles")
    figures: dict[str, float | None] = {
        "instr_per_put": instructions(result["busy_cycles"], hz, shift) / sent,
        "put_msgs_per_s": sent * hz / result["loop_cycles"],
        "put_failed": float(result["failed"]),
        "delivered_share": None if delivered is None else delivered / sent,
    }
    figures.update(memory_figures(memory))
    return figures


def sub_figures(result: dict[str, int], memory: dict[str, int] | None, shift: int) -> dict[str, float | None]:
    hz, received = result["hz"], result["received"]
    if hz <= 0:
        raise Lost("the image reported no cycle rate")
    if received == 0:
        raise Lost("nothing was delivered in the window")
    if result["window_cycles"] <= 0:
        raise Lost("the window took no cycles")
    figures: dict[str, float | None] = {
        "instr_per_sample": instructions(result["busy_cycles"], hz, shift) / received,
        "sub_msgs_per_s": received * hz / result["window_cycles"],
        "sub_bytes_per_s": result["bytes"] * hz / result["window_cycles"],
        "sub_msgs_per_busy_s": received * hz / result["busy_cycles"] if result["busy_cycles"] > 0 else None,
    }
    figures.update(memory_figures(memory))
    return figures


def rtt_figures(result: dict[str, int], memory: dict[str, int] | None, shift: int) -> dict[str, float | None]:
    hz = result["hz"]
    if hz <= 0:
        raise Lost("the image reported no cycle rate")
    if result["round_trips"] == 0 or result["attempts"] == 0:
        raise Lost("no round trip was answered")
    if result["lost"] * 10 > result["attempts"]:
        raise Lost(f"{result['lost']} of {result['attempts']} round trips were lost")
    figures: dict[str, float | None] = {
        "rtt_p50_us": micros(result["p50_cycles"], hz), "rtt_p90_us": micros(result["p90_cycles"], hz),
        "rtt_p99_us": micros(result["p99_cycles"], hz), "rtt_mean_us": micros(result["mean_cycles"], hz),
        "rtt_min_us": micros(result["min_cycles"], hz), "rtt_max_us": micros(result["max_cycles"], hz),
        "instr_per_rtt": instructions(result["busy_cycles"], hz, shift) / result["attempts"],
        "lost": float(result["lost"]),
    }
    figures.update(memory_figures(memory))
    return figures


def cell_figures(workload: str, console: str, probe: str, shift: int) -> dict[str, float | None]:
    """A cell's figures from the image's console and the probe's output, or Lost with the reason."""
    why = failure_of(console)
    if why is not None:
        raise Lost(f"the image failed: {why}")
    result = result_of(console, workload)
    if result is None:
        raise Lost("the image gave no result line")
    memory = memory_of(console)
    if workload == "put":
        return put_figures(result, memory, probe_total(probe), shift)
    if workload == "sub":
        return sub_figures(result, memory, shift)
    return rtt_figures(result, memory, shift)


# -- the processes of a cell ---------------------------------------------------------------------------------

def free_port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


class Console:
    """A program whose output is read line by line as it comes, and written to a log."""

    def __init__(self, argv: list[str], log: pathlib.Path):
        self.lines: list[str] = []
        self.lock = threading.Lock()
        self.log = log.open("w", encoding="utf-8")
        self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            line = raw.decode("utf-8", errors="replace").replace("\r", "").rstrip("\n")
            with self.lock:
                self.lines.append(line)
            self.log.write(line + "\n")
            self.log.flush()

    def wait_for(self, kinds: tuple[str, ...], seconds: float) -> str | None:
        """The first of the image's lines of one of the kinds, or None when none came in time or the
        program ended without one."""
        until = time.monotonic() + seconds
        seen = 0
        while True:
            ended = self.proc.poll() is not None and not self.reader.is_alive()
            with self.lock:
                fresh = self.lines[seen:]
                seen = len(self.lines)
            for line in fresh:
                for kind in kinds:
                    if line.strip().startswith(f"{TAG} {kind}"):
                        return line.strip()
            if ended or time.monotonic() >= until:
                return None
            time.sleep(0.05)

    def text(self) -> str:
        with self.lock:
            return "\n".join(self.lines) + "\n"

    def stop(self) -> str:
        stop_process(self.proc)
        self.reader.join(timeout=5)
        self.log.close()
        return self.text()


class Probe:
    """One run of the host probe, its output in a file."""

    def __init__(self, argv: list[str], out: pathlib.Path):
        self.out = out
        self.fh = out.open("w", encoding="utf-8")
        self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.fh, stderr=subprocess.STDOUT)

    def stop(self) -> str:
        stop_process(self.proc)
        self.fh.close()
        return self.out.read_text(encoding="utf-8", errors="replace")


@dataclass(frozen=True)
class Plan:
    """What every cell of a run is given."""

    qemu: str
    board: str
    peer: str
    pacer: str
    offer_rate: int
    endpoint: str  # the host probe's way to the router
    locator: str  # the image's way to the router
    shift: int
    puts: int
    window_ms: int
    warmup_ms: int
    round_trips: int
    warmup_round_trips: int
    timeout_ms: int


def cell_args(plan: Plan, workload: str, size: int) -> list[str]:
    """The image's command line for one cell (src/main.c of deploy/zephyr-mcu-speed)."""
    if workload == "put":
        tail = [plan.puts, 0, 0]
    elif workload == "sub":
        tail = [plan.window_ms, plan.warmup_ms, 0]
    else:
        tail = [plan.round_trips, plan.warmup_round_trips, plan.timeout_ms]
    return ["mcu-speed", plan.locator, workload, str(size)] + [str(v) for v in tail]


def qemu_argv(plan: Plan, image: pathlib.Path, args: list[str]) -> list[str]:
    board = BOARDS[plan.board]
    return [plan.qemu, "-machine", board.machine, "-cpu", board.cpu, "-nographic", "-monitor", "none",
            "-serial", "stdio", "-icount", f"shift={plan.shift},align=off,sleep=on",
            "-nic", f"user,model=lan9118,mac={GUEST_MAC}",
            "-semihosting-config", "enable=on,target=native," + ",".join(f"arg={a}" for a in args),
            "-kernel", str(image)]


def probe_argv(plan: Plan, role: str, size: int) -> list[str]:
    """The host probe in its role, a peer of the router. Its long durations are ended by the run."""
    base = [plan.peer, role, "-m", "peer", "-e", plan.endpoint]
    if role == "sub":
        return base + ["-w", "0", "-t", "3600"]
    if role == "pub":
        # The pacer reads its options from the first word, and waits for its publisher to match.
        return [plan.pacer, "-m", "peer", "-e", plan.endpoint, "-k", "perf/thr", "-s", str(size),
                "-r", str(plan.offer_rate), "-t", "3600", "-w"]
    return base


def run_cell(plan: Plan, image: pathlib.Path, workload: str, size: int, stem: pathlib.Path) -> dict:
    """One cell: its figures, or Lost."""
    qemu = qemu_argv(plan, image, cell_args(plan, workload, size))
    probe = None
    console = None
    console_text = ""
    probe_text = ""
    try:
        if workload in ("put", "rtt"):
            probe = Probe(probe_argv(plan, "sub" if workload == "put" else "pong", size),
                          stem.with_name(stem.name + ".probe"))
            time.sleep(SETTLE_S)
            console = Console(qemu, stem.with_name(stem.name + ".console"))
        else:
            console = Console(qemu, stem.with_name(stem.name + ".console"))
            ready = console.wait_for(("READY", "FAIL"), READY_S)
            if ready is None:
                raise Lost(f"the image said nothing ready in {READY_S:.0f} s")
            if ready.startswith(f"{TAG} FAIL"):
                raise Lost(f"the image failed: {words(ready).get('why', 'no reason given')}")
            probe = Probe(probe_argv(plan, "pub", size), stem.with_name(stem.name + ".probe"))
        if console.wait_for(("DONE", "FAIL"), CELL_S) is None:
            raise Lost(f"the image did not finish in {CELL_S:.0f} s")
        if workload == "put":
            # The probe's subscriber is handed what the router still forwards after the loop.
            time.sleep(0.5)
    finally:
        if console is not None:
            console_text = console.stop()
        if probe is not None:
            probe_text = probe.stop()
    return cell_figures(workload, console_text, probe_text, plan.shift)


def start_router(zenohd: str, udp: int, tcp: int, log: pathlib.Path, log_filter: str = "") -> subprocess.Popen:
    fh = log.open("w", encoding="utf-8")
    env = dict(os.environ, RUST_LOG=log_filter) if log_filter else None
    proc = subprocess.Popen([zenohd, "--no-multicast-scouting", "-l", f"udp/127.0.0.1:{udp}",
                             "-l", f"tcp/127.0.0.1:{tcp}"], stdin=subprocess.DEVNULL, stdout=fh,
                            stderr=subprocess.STDOUT, env=env)
    until = time.monotonic() + ROUTER_S
    while time.monotonic() < until:
        if proc.poll() is not None:
            raise Lost(f"the router exited ({proc.returncode}); see {log}")
        try:
            with socket.create_connection(("127.0.0.1", tcp), timeout=0.5):
                return proc
        except OSError:
            time.sleep(0.2)
    stop_process(proc)
    raise Lost(f"the router did not listen in {ROUTER_S:.0f} s; see {log}")


def first_line(argv: list[str]) -> str:
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    lines = (done.stdout or done.stderr).strip().splitlines()
    return lines[0] if lines else ""


def platform_of(board: str, shift: int) -> dict:
    return {"board": board, "qemu_machine": BOARDS[board].machine, "qemu_cpu": BOARDS[board].cpu,
            "icount_shift": shift}


def summarize(cells: list[dict]) -> list[dict]:
    """Per threading arm, workload and size: each arm's measured and lost repetitions and medians, and W
    over P of each figure both have."""
    groups: dict[tuple, dict[str, list[dict]]] = {}
    for cell in cells:
        key = (cell["threads"], cell["workload"], cell["size"])
        groups.setdefault(key, {}).setdefault(cell["arm"], []).append(cell)
    out = []
    for key in sorted(groups, key=lambda k: (THREADS.index(k[0]), WORKLOADS.index(k[1]), k[2])):
        threads, workload, size = key
        row: dict = {"threads": threads, "workload": workload, "size": size, "arms": {}}
        medians: dict[str, dict[str, float]] = {}
        for arm, runs in groups[key].items():
            measured = [c["figures"] for c in runs if c["status"] == "measured"]
            med = {}
            for metric in METRICS:
                values = [f[metric] for f in measured if isinstance(f.get(metric), (int, float))]
                if values:
                    med[metric] = statistics.median(values)
            medians[arm] = med
            row["arms"][arm] = {"measured": len(measured),
                                "lost": sum(c["status"] == "lost" for c in runs), "median": med}
        if "W" in medians and "P" in medians:
            row["w_over_p"] = {m: medians["W"][m] / medians["P"][m] for m in medians["W"]
                               if medians["P"].get(m)}
        out.append(row)
    return out


def report_lines(rows: list[dict]) -> list[str]:
    out = []
    for row in rows:
        out.append(f"{row['threads']} {row['workload']} {row['size']} B")
        for arm in ARMS:
            got = row["arms"].get(arm)
            if got is None:
                continue
            shown = ", ".join(f"{m} {v:.3f}" for m, v in got["median"].items())
            out.append(f"  {arm}: {got['measured']} measured, {got['lost']} lost; {shown}")
        if row.get("w_over_p"):
            out.append("  W/P: " + ", ".join(f"{m} {v:.3f}" for m, v in row["w_over_p"].items()))
    return out


def cmd_run(args: argparse.Namespace) -> int:
    board = args.board
    if board not in BOARDS:
        print(f"mcu-speed: no board {board}; the boards are {', '.join(BOARDS)}", file=sys.stderr)
        return 2
    if args.qemu_machine and args.qemu_machine != BOARDS[board].machine:
        print(f"mcu-speed: {board} runs on the QEMU machine {BOARDS[board].machine}, not {args.qemu_machine}",
              file=sys.stderr)
        return 2
    try:
        sizes = [int(s) for s in args.sizes.split(",") if s]
    except ValueError:
        print(f"mcu-speed: --sizes is a comma list of numbers, not {args.sizes}", file=sys.stderr)
        return 2
    threads = [t for t in args.threads.split(",") if t]
    workloads = [w for w in args.workloads.split(",") if w]
    bad = ([str(s) for s in sizes if not MIN_SIZE <= s <= MAX_SIZE] + [t for t in threads if t not in THREADS]
           + [w for w in workloads if w not in WORKLOADS])
    if bad or not sizes or not threads or not workloads or args.reps < 1:
        print(f"mcu-speed: refused: {', '.join(bad) or 'an empty list or no repetition'}", file=sys.stderr)
        return 2
    images = pathlib.Path(args.images)
    missing = [f"{a}-{t}.elf" for a in ARMS for t in threads if not (images / f"{a}-{t}.elf").is_file()]
    if missing:
        print(f"mcu-speed: refused: {images} holds no {', '.join(missing)}", file=sys.stderr)
        return 2
    if args.offer_rate < 1:
        print("mcu-speed: refused: --offer-rate is at least one sample a second", file=sys.stderr)
        return 2
    for tool in (args.peer, args.pacer, args.zenohd):
        if not os.access(tool, os.X_OK):
            print(f"mcu-speed: refused: {tool} is not an executable", file=sys.stderr)
            return 2

    run = pathlib.Path(args.run)
    run.mkdir(parents=True, exist_ok=True)
    udp, tcp = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_STREAM)
    plan = Plan(qemu=args.qemu, board=board, peer=args.peer, pacer=args.pacer, offer_rate=args.offer_rate,
                endpoint=f"tcp/127.0.0.1:{tcp}",
                locator=f"udp/{GUEST_HOST}:{udp}", shift=ICOUNT_SHIFT, puts=args.puts, window_ms=args.window_ms,
                warmup_ms=args.warmup_ms, round_trips=args.round_trips,
                warmup_round_trips=args.warmup_round_trips, timeout_ms=args.timeout_ms)
    record = {
        "platform": platform_of(board, ICOUNT_SHIFT),
        "tree": first_line(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "changes": first_line(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"]) != "",
        "qemu": first_line([args.qemu, "--version"]), "zenohd": first_line([args.zenohd, "--version"]),
        "host": socket.gethostname(), "sizes": sizes, "threads": threads, "workloads": workloads,
        "reps": args.reps, "puts": args.puts, "window_ms": args.window_ms, "warmup_ms": args.warmup_ms,
        "offer_rate": args.offer_rate, "router_log": args.router_log,
        "round_trips": args.round_trips, "warmup_round_trips": args.warmup_round_trips,
        "timeout_ms": args.timeout_ms, "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        router = start_router(args.zenohd, udp, tcp, run / "zenohd.log", args.router_log)
    except Lost as why:
        print(f"mcu-speed: refused: {why}", file=sys.stderr)
        return 2
    cells: list[dict] = []
    try:
        with (run / "cells.jsonl").open("w", encoding="utf-8") as jsonl:
            for rep in range(1, args.reps + 1):
                order = ARMS if rep % 2 else tuple(reversed(ARMS))
                for thread_arm in threads:
                    for workload in workloads:
                        for size in sizes:
                            for arm in order:
                                if router.poll() is not None:
                                    print(f"mcu-speed: refused: the router exited ({router.returncode})",
                                          file=sys.stderr)
                                    return 2
                                cell = {"arm": arm, "threads": thread_arm, "workload": workload, "size": size,
                                        "rep": rep}
                                try:
                                    cell["figures"] = run_cell(
                                        plan, images / f"{arm}-{thread_arm}.elf", workload, size,
                                        run / f"r{rep}-{arm}-{thread_arm}-{workload}-{size}")
                                    cell["status"] = "measured"
                                except Lost as why:
                                    cell["status"] = "lost"
                                    cell["why"] = str(why)
                                cells.append(cell)
                                jsonl.write(json.dumps(cell, sort_keys=True) + "\n")
                                jsonl.flush()
                                said = f": {cell['why']}" if "why" in cell else ""
                                print(f"mcu-speed: r{rep} {arm} {thread_arm} {workload} {size} B "
                                      f"{cell['status']}{said}", flush=True)
    finally:
        stop_process(router)
    record["end"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rows = summarize(cells)
    doc = {"schema": SCHEMA, "record": record, "metrics": METRICS, "cells": cells, "summary": rows}
    (run / "mcu-speed.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (run / "report.txt").write_text("\n".join(report_lines(rows)) + "\n", encoding="utf-8")
    print("\n".join(report_lines(rows)), flush=True)
    print(f"mcu-speed: {sum(c['status'] == 'measured' for c in cells)} of {len(cells)} cell(s) measured; "
          f"{run / 'mcu-speed.json'}", flush=True)
    return 0


# -- the gate ------------------------------------------------------------------------------------------------

def row_key(machine: str, threads: str, workload: str, size: int, metric: str) -> str:
    return f"{machine}/{threads}/{workload}/{size}/{metric}"


def population(machine: str, sizes: tuple[int, ...] = DEFAULT_SIZES) -> list[str]:
    """Every row a full run of the matrix on one machine gives: each threading arm, workload, size and held
    figure."""
    return [row_key(machine, t, w, s, m) for t in THREADS for w in WORKLOADS for s in sizes for m in GATED[w]]


def cost_ratio(metric: str, wz: list[float], ref: list[float]) -> tuple[float, float, float]:
    """D10's cost ratio, so below 1 is wz ahead whichever way the figure is better."""
    if METRICS[metric] == "lower":
        return pm.bootstrap_ratio(wz, ref)
    return pm.bootstrap_ratio(ref, wz)


def held_values(figures: list[dict], metric: str) -> list[float]:
    return [float(f[metric]) for f in figures
            if isinstance(f.get(metric), (int, float)) and not isinstance(f.get(metric), bool) and f[metric] > 0]


def readings(cells: list[dict], machine: str) -> dict[str, pm.Reading]:
    """Every row of W over P that a run's cells have, read. Any lost repetition of wz fails its rows: no
    other work shares the emulated core, so what wz could not do once is a defect. A reference that lost
    every repetition leaves its rows without a ratio."""
    groups: dict[tuple, dict[str, dict]] = {}
    for cell in cells:
        key = (cell["threads"], cell["workload"], cell["size"])
        arm = groups.setdefault(key, {}).setdefault(cell["arm"], {"figures": [], "lost": []})
        if cell["status"] == "measured":
            arm["figures"].append(cell["figures"])
        elif cell["status"] == "lost":
            arm["lost"].append(f"r{cell['rep']}: {cell.get('why', 'no reason given')}")
    out: dict[str, pm.Reading] = {}
    for (threads, workload, size), arms in groups.items():
        wz, ref = arms.get("W"), arms.get("P")
        if wz is None or ref is None or workload not in GATED:
            continue
        for metric in GATED[workload]:
            key = row_key(machine, threads, workload, size, metric)
            if wz["lost"]:
                out[key] = pm.Reading("wz-lost", f"wz lost {len(wz['lost'])} repetition(s) ({wz['lost'][0]})")
                continue
            if not ref["figures"] and ref["lost"]:
                out[key] = pm.Reading("reference-lost",
                                      f"the reference lost every repetition ({ref['lost'][0]})")
                continue
            ws, rs = held_values(wz["figures"], metric), held_values(ref["figures"], metric)
            if len(ws) < pm.MIN_REPS or len(rs) < pm.MIN_REPS:
                out[key] = pm.Reading("too-few", f"{len(ws)} repetition(s) of wz and {len(rs)} of the reference "
                                                 f"gave {metric}, and an interval needs {pm.MIN_REPS} of each")
                continue
            point, lo, hi = cost_ratio(metric, ws, rs)
            out[key] = pm.Reading("ratio", point=point, lo=lo, hi=hi, verdict=pm.verdict_of(lo, hi))
    return out


def key_error(key: str, machine: str) -> str | None:
    parts = key.split("/")
    if len(parts) != 5:
        return "the key is not <machine>/<threads>/<workload>/<size>/<figure>"
    on, threads, workload, size, metric = parts
    if on != machine:
        return f"the key is of the machine {on}, and the table's platform is {machine}"
    if threads not in THREADS:
        return f"the threading arm is one of {', '.join(THREADS)}"
    if workload not in WORKLOADS:
        return f"the workload is one of {', '.join(WORKLOADS)}"
    if not size.isdigit():
        return "the size is a number of bytes"
    if metric not in GATED[workload]:
        return f"the figure is one the gate holds of {workload}: {', '.join(GATED[workload])}"
    return None


#: The register item a row of this table that is not a WIN is filed under (decision D5 of
#: docs/upstream-parity.md): the gate writes it into each ratchet it prints, and a ratchet that names
#: none is refused.
DEBT_DEFAULT = "debt-mcu-speed-behind-pico"
DEBT_ID = re.compile(r"debt-[a-z0-9][a-z0-9-]*")


def entry_error(row: object) -> str | None:
    """Why one row of a table is malformed, or None: `{"held": <a row of perf_matrix's four shapes>,
    "debt": <a debt id or null>}`, and a held row that is not a WIN names its debt."""
    if not isinstance(row, dict) or set(row) != {"held", "debt"}:
        return 'a row is {"held": ..., "debt": ...} and nothing else'
    held, debt = row["held"], row["debt"]
    error = pm.row_error(held)
    if error:
        return error
    if debt is not None and not (isinstance(debt, str) and DEBT_ID.fullmatch(debt)):
        return "a row's debt is debt-<id> of the store's inventory, or null"
    if isinstance(held, dict) and not held.get("locked") and debt is None:
        return f"a row that is not locked names its debt ({DEBT_DEFAULT}, or the item it is filed under)"
    return None


def held_rows(rows: dict) -> dict:
    """What the judge reads of a table's rows: each key's held row."""
    return {key: row["held"] for key, row in rows.items()}


def parse_table(text: str) -> tuple[dict, float, dict]:
    """The rows, the tolerance and the platform of a table."""
    try:
        doc = json.loads(text, object_pairs_hook=pm.refuse_duplicates)
    except ValueError as error:
        raise pm.Refused(f"not JSON: {error}") from None
    if not isinstance(doc, dict) or doc.get("schema") != TABLE_SCHEMA:
        raise pm.Refused(f"the schema is not {TABLE_SCHEMA}")
    if doc.get("pair") != PAIR:
        raise pm.Refused(f"the table is of the pair {doc.get('pair')}, and this gate judges {PAIR}")
    platform = doc.get("platform")
    shift = platform.get("icount_shift") if isinstance(platform, dict) else None
    if (not isinstance(platform, dict) or platform.get("board") not in BOARDS or isinstance(shift, bool)
            or not isinstance(shift, int) or platform != platform_of(platform["board"], shift)):
        raise pm.Refused(f"`platform` is the board, QEMU machine, QEMU core and -icount shift of one of "
                         f"{', '.join(BOARDS)}, as a run records them")
    tolerance = doc.get("tolerance")
    if isinstance(tolerance, bool) or not isinstance(tolerance, (int, float)) or not 0 <= tolerance < 1:
        raise pm.Refused("`tolerance` is a number from 0 up to, not including, 1")
    rows = doc.get("rows")
    if not isinstance(rows, dict):
        raise pm.Refused("`rows` is an object of row keys")
    machine = platform["qemu_machine"]
    for key, value in rows.items():
        error = key_error(key, machine) or entry_error(value)
        if error:
            raise pm.Refused(f"{key}: {error}")
    return rows, float(tolerance), platform


def load_table(path: pathlib.Path) -> tuple[dict, float, dict]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise pm.Refused(f"{path} cannot be read: {error}") from None
    try:
        return parse_table(text)
    except pm.Refused as why:
        raise pm.Refused(f"{path}: {why}") from None


def gate(doc: dict, table: pathlib.Path) -> str:
    """Judge a run's cells against the table's rows: the outcome, printed with its rows, edits and debts."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise pm.Refused(f"the result is not of schema {SCHEMA}")
    rows, tolerance, platform = load_table(table)
    ran_on = doc.get("record", {}).get("platform")
    if ran_on != platform:
        raise pm.Refused(f"the run was made on {json.dumps(ran_on)}, and {table} holds rows read on "
                         f"{json.dumps(platform)}: judge it against a table of its own platform")
    judged = pm.judge(readings(doc["cells"], platform["qemu_machine"]), held_rows(rows), tolerance)
    outcome = pm.print_pair(f"{PAIR} on {platform['board']}", str(table), tolerance, judged)
    edits = {j.key: j.edit for j in judged if j.edit is not None}
    if edits:
        print("mcu-speed-gate: the same rows in this table's shape, each with its debt:", flush=True)
        for key, held in edits.items():
            debt = rows.get(key, {}).get("debt") or (None if held.get("locked") else DEBT_DEFAULT)
            print(f"  {json.dumps(key)}: {json.dumps({'held': held, 'debt': debt})},", flush=True)
    return outcome


def cmd_gate(result: pathlib.Path, table: pathlib.Path) -> int:
    try:
        doc = json.loads(result.read_text(encoding="utf-8"))
        outcome = gate(doc, table)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, pm.Refused) as why:
        print(f"mcu-speed-gate: refused: {why}", file=sys.stderr, flush=True)
        return 2
    return pm.exit_status([outcome])


def check_table(path: pathlib.Path) -> int:
    """The committed table's shape, and its rows exactly the population of the default matrix."""
    try:
        rows, tolerance, platform = load_table(path)
    except pm.Refused as why:
        print(f"mcu-speed-gate table: refused: {why}", file=sys.stderr)
        return 2
    wanted = set(population(platform["qemu_machine"]))
    missing = sorted(wanted - set(rows))
    extra = sorted(set(rows) - wanted)
    for key in missing:
        print(f"  mcu-speed-gate table FAIL: no row for {key}, a cell of the default matrix", file=sys.stderr)
    for key in extra:
        print(f"  mcu-speed-gate table FAIL: the row {key} is no cell of the default matrix", file=sys.stderr)
    if missing or extra:
        return 1
    filled = sum(row["held"] is not None for row in rows.values())
    print(f"  mcu-speed-gate table: {len(rows)} row(s), the population of the default matrix on "
          f"{platform['board']}; {filled} filled, {len(rows) - filled} not yet (tolerance {tolerance})")
    return 0


# -- the selftest --------------------------------------------------------------------------------------------

def _console(workload: str, result: str, memory: str = "stack_used=9000 heap_peak=4000 heap_size=262144") -> str:
    return ("*** Booting Zephyr OS ***\r\nMCU-SPEED BOOT arm=W threads=st\r\n"
            f"MCU-SPEED READY workload={workload} size=64\r\n"
            f"MCU-SPEED RESULT workload={workload} size=64 {result}\r\n"
            "MCU-SPEED STACK thread=main used=3000 size=16384\r\n"
            f"MCU-SPEED MEMORY {memory}\r\nMCU-SPEED DONE\r\n")


def _cells(wz: list[float], ref: list[float], workload: str = "put", lost: str = "") -> list[dict]:
    """Synthetic cells of one threading arm, workload and size: every held figure of a repetition takes
    the repetition's value, so a row's ratio is the two lists'."""
    out = []
    for arm, values in (("W", wz), ("P", ref)):
        for rep, value in enumerate(values, 1):
            cell = {"arm": arm, "threads": "st", "workload": workload, "size": 64, "rep": rep}
            if arm == lost:
                cell.update(status="lost", why="the image failed: open")
            else:
                cell.update(status="measured", figures={m: value for m in GATED[workload]})
            out.append(cell)
    return out


def cmd_selftest() -> int:
    ok = 0
    bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  mcu-speed selftest FAIL: {name}", file=sys.stderr)

    def lost(call) -> str:
        try:
            call()
        except Lost as why:
            return str(why)
        return ""

    def refused(call) -> str:
        try:
            call()
        except pm.Refused as why:
            return str(why)
        return ""

    # The console.
    put = _console("put", "sent=1000 failed=0 loop_cycles=2500000 busy_cycles=1250000 hz=25000000")
    result = result_of(put, "put")
    expect("a result line is read through the emulator's carriage returns",
           result is not None and result["busy_cycles"] == 1250000 and result["hz"] == 25000000)
    expect("a result of another workload is not read", result_of(put, "rtt") is None)
    expect("a result line missing a key is no result",
           result_of("MCU-SPEED RESULT workload=put size=64 sent=1\n", "put") is None)
    expect("the memory line is read", (memory_of(put) or {}).get("stack_used") == 9000)
    expect("a stack line is read", stacks_of(put) == [{"thread": "main", "used": 3000, "size": 16384}])
    expect("a failure says why", failure_of("MCU-SPEED FAIL why=open\n") == "open")
    expect("a line that only begins like the tag is not the image's",
           tagged("MCU-SPEEDY RESULT x=1\n", "RESULT") == [])
    expect("the probe's total is read",
           probe_total("perf_probe sub received=1 bytes=2 window_ns=3\n"
                       "perf_probe sub total=900 last_growth_ns=1 peers=1\n") == 900)

    # The figures: 1,250,000 cycles of a 25 MHz counter are 50 ms, 50,000,000 instructions at shift 0.
    figs = cell_figures("put", put, "perf_probe sub total=800 last_growth_ns=1 peers=1\n", 0)
    expect("instructions per put are the busy cycles at one instruction a nanosecond",
           math.isclose(figs["instr_per_put"], 50000.0))
    expect("a shift of 1 halves the instructions",
           math.isclose(cell_figures("put", put, "", 1)["instr_per_put"], 25000.0))
    expect("puts a second are over the loop's cycles", math.isclose(figs["put_msgs_per_s"], 10000.0))
    expect("the share the probe got is read", math.isclose(figs["delivered_share"], 0.8))
    expect("a probe that printed no total leaves the share unknown",
           cell_figures("put", put, "", 0)["delivered_share"] is None)
    expect("the stack and heap are the memory line's",
           figs["stack_bytes"] == 9000 and figs["heap_peak_bytes"] == 4000)
    sub = _console("sub", "received=500 bytes=32000 window_cycles=50000000 busy_cycles=25000000 hz=25000000")
    figs = cell_figures("sub", sub, "", 0)
    expect("instructions per sample", math.isclose(figs["instr_per_sample"], 2000000.0))
    expect("samples a second over the window", math.isclose(figs["sub_msgs_per_s"], 250.0))
    expect("samples a second of busy time are the core's capacity",
           math.isclose(figs["sub_msgs_per_busy_s"], 500.0))
    rtt = _console("rtt", "round_trips=100 lost=0 attempts=100 p50_cycles=2500 p90_cycles=5000 p99_cycles=25000 "
                          "min_cycles=2000 max_cycles=30000 mean_cycles=3000 busy_cycles=250000 hz=25000000")
    figs = cell_figures("rtt", rtt, "", 0)
    expect("a percentile is microseconds",
           math.isclose(figs["rtt_p50_us"], 100.0) and math.isclose(figs["rtt_p99_us"], 1000.0))
    expect("instructions per round trip are over every attempt", math.isclose(figs["instr_per_rtt"], 100000.0))
    expect("a failed image is lost with its reason",
           "open" in lost(lambda: cell_figures("put", "MCU-SPEED FAIL why=open\n", "", 0)))
    expect("a console with no result is lost",
           "no result" in lost(lambda: cell_figures("put", "MCU-SPEED BOOT\n", "", 0)))
    expect("a put loop with nothing sent is lost", "no put" in lost(lambda: cell_figures(
        "put", _console("put", "sent=0 failed=5 loop_cycles=10 busy_cycles=10 hz=25000000"), "", 0)))
    expect("a window that delivered nothing is lost", "nothing" in lost(lambda: cell_figures(
        "sub", _console("sub", "received=0 bytes=0 window_cycles=10 busy_cycles=10 hz=25000000"), "", 0)))
    expect("a run that lost over a tenth of its round trips is lost", "were lost" in lost(lambda: cell_figures(
        "rtt", _console("rtt", "round_trips=80 lost=20 attempts=100 p50_cycles=1 p90_cycles=1 p99_cycles=1 "
                               "min_cycles=1 max_cycles=1 mean_cycles=1 busy_cycles=1 hz=25000000"), "", 0)))
    expect("a console with no memory line is lost", "memory" in lost(lambda: cell_figures(
        "put", put.replace("MCU-SPEED MEMORY", "MCU-SPEED SOMETHING"), "", 0)))

    # The command lines of a cell.
    plan = Plan(qemu="qemu-system-arm", board=DEFAULT_BOARD, peer="/p", pacer="/q", offer_rate=1000,
                endpoint="tcp/127.0.0.1:2",
                locator="udp/10.0.2.2:1", shift=0, puts=2000, window_ms=2000, warmup_ms=500, round_trips=500,
                warmup_round_trips=50, timeout_ms=200)
    argv = qemu_argv(plan, pathlib.Path("/i.elf"), cell_args(plan, "rtt", 64))
    expect("QEMU runs the board's machine and core", argv[1:5] == ["-machine", "mps2-an385", "-cpu", "cortex-m3"])
    expect("QEMU counts instructions and sleeps in real time",
           argv[argv.index("-icount") + 1] == "shift=0,align=off,sleep=on")
    expect("the cell is the image's command line", argv[argv.index("-semihosting-config") + 1] ==
           "enable=on,target=native,arg=mcu-speed,arg=udp/10.0.2.2:1,arg=rtt,arg=64,arg=500,arg=50,arg=200")
    expect("a put cell carries its puts", cell_args(plan, "put", 8)[4:] == ["2000", "0", "0"])
    expect("a sub cell carries its window and warm-up", cell_args(plan, "sub", 8)[4:] == ["2000", "500", "0"])
    pacer = probe_argv(plan, "pub", 64)
    expect("the sub cell's publisher is the pacer, at the offered rate, on the probe's key",
           pacer[0] == "/q" and pacer[pacer.index("-r") + 1] == "1000" and pacer[pacer.index("-k") + 1] == "perf/thr")
    expect("the probe is a peer of the router",
           probe_argv(plan, "pong", 64)[2:6] == ["-m", "peer", "-e", "tcp/127.0.0.1:2"])

    # The readings.
    found = readings(_cells([1.0, 1.0, 1.0], [2.0, 2.0, 2.0]), "m")
    expect("a figure better lower and smaller in wz is a WIN", found["m/st/put/64/instr_per_put"].verdict == "WIN")
    expect("a rate better higher and smaller in wz is a LOSS",
           found["m/st/put/64/put_msgs_per_s"].verdict == "LOSS")
    found = readings(_cells([1.0, 1.0, 1.0], [1.0, 1.0, 1.0]), "m")
    expect("equal figures are a TIE", found["m/st/put/64/stack_bytes"].verdict == "TIE")
    found = readings(_cells([1.0, 1.0], [2.0, 2.0, 2.0]), "m")
    expect("two repetitions give no interval", found["m/st/put/64/instr_per_put"].state == "too-few")
    found = readings(_cells([1.0, 1.0, 1.0], [2.0, 2.0, 2.0], lost="W"), "m")
    expect("a repetition wz lost fails its rows", found["m/st/put/64/instr_per_put"].state == "wz-lost")
    found = readings(_cells([1.0, 1.0, 1.0], [2.0, 2.0, 2.0], lost="P"), "m")
    expect("a reference that lost every repetition says so",
           found["m/st/put/64/instr_per_put"].state == "reference-lost")
    found = readings(_cells([1.0, 1.0, 1.0], [2.0, 2.0, 2.0], workload="rtt"), "m")
    expect("a round-trip cell gives its five held rows", len(found) == len(GATED["rtt"]))

    # The table.
    machine = BOARDS[DEFAULT_BOARD].machine
    expect("the default matrix is two threading arms, three workloads, three sizes and their figures",
           len(population(machine)) == len(THREADS) * len(DEFAULT_SIZES) * sum(len(v) for v in GATED.values()))

    def table_text(rows: dict, **head) -> str:
        doc = {"schema": TABLE_SCHEMA, "pair": PAIR, "platform": platform_of(DEFAULT_BOARD, 0),
               "tolerance": 0.05, "rows": rows}
        doc.update(head)
        return json.dumps(doc)

    rows_null = {key: {"held": None, "debt": None} for key in population(machine)}
    expect("a table of null rows is read", parse_table(table_text(rows_null))[0] == rows_null)
    expect("another schema is refused", "schema" in refused(lambda: parse_table(table_text({}, schema="x"))))
    expect("another pair is refused", "pair" in refused(lambda: parse_table(table_text({}, pair="W/X"))))
    expect("a platform that is not the board's is refused", "platform" in refused(
        lambda: parse_table(table_text({}, platform=dict(platform_of(DEFAULT_BOARD, 0), qemu_machine="virt")))))
    expect("a tolerance of 1 is refused", "tolerance" in refused(lambda: parse_table(table_text({}, tolerance=1))))
    empty = {"held": None, "debt": None}
    expect("a key of another machine is refused", "machine" in refused(
        lambda: parse_table(table_text({"virt/st/put/8/instr_per_put": empty}))))
    expect("a figure the gate does not hold is refused", "figure" in refused(
        lambda: parse_table(table_text({f"{machine}/st/put/8/delivered_share": empty}))))
    put8 = f"{machine}/st/put/8/instr_per_put"
    expect("a row of no known shape is refused", "row" in refused(
        lambda: parse_table(table_text({put8: {"held": {"win": True}, "debt": None}}))))
    expect("a row that is no held-and-debt pair is refused", "row" in refused(
        lambda: parse_table(table_text({put8: {"locked": True}}))))
    expect("a ratchet that names no debt is refused", "debt" in refused(
        lambda: parse_table(table_text({put8: {"held": {"ratio_at_most": 1.2}, "debt": None}}))))
    expect("a debt that is no id is refused", "debt" in refused(
        lambda: parse_table(table_text({put8: {"held": {"ratio_at_most": 1.2}, "debt": "later"}}))))
    expect("a ratchet with its debt and a lock without one are read", parse_table(table_text({
        put8: {"held": {"ratio_at_most": 1.2}, "debt": DEBT_DEFAULT},
        f"{machine}/st/put/8/stack_bytes": {"held": {"locked": True}, "debt": None}}))[0][put8]["debt"] == DEBT_DEFAULT)
    expect("a key written twice is refused", "twice" in refused(
        lambda: parse_table('{"schema": "%s", "schema": "%s"}' % (TABLE_SCHEMA, TABLE_SCHEMA))))

    # The gate, end to end, over a run of one cell and a table in a temporary directory.
    cells = _cells([1.0, 1.0, 1.0], [2.0, 2.0, 2.0])
    run = {"schema": SCHEMA, "record": {"platform": platform_of(DEFAULT_BOARD, 0)}, "cells": cells}
    rate = f"{machine}/st/put/64/put_msgs_per_s"
    with tempfile.TemporaryDirectory() as tmp:
        table = pathlib.Path(tmp) / "t.json"
        table.write_text(table_text(rows_null), encoding="utf-8")
        with open(os.devnull, "w", encoding="utf-8") as sink:
            stdout, sys.stdout = sys.stdout, sink
            try:
                outcome_null = gate(run, table)
                held = dict(rows_null)
                for key in readings(cells, machine):
                    held[key] = {"held": {"locked": True}, "debt": None}
                held[rate] = {"held": {"ratio_at_most": 2.0}, "debt": DEBT_DEFAULT}
                table.write_text(table_text(held), encoding="utf-8")
                outcome_held = gate(run, table)
                locked = dict(held)
                locked[rate] = {"held": {"locked": True}, "debt": None}
                outcome_lost_lock = pm.outcome_of(pm.judge(readings(cells, machine), held_rows(locked), 0.05))
                other = dict(run, record={"platform": platform_of(DEFAULT_BOARD, 1)})
                why_other = refused(lambda: gate(other, table))
            finally:
                sys.stdout = stdout
    expect("a null row fails", outcome_null == "FAIL")
    expect("a run that holds every row it has and misses the rest is not measured", outcome_held == "NOT-MEASURED")
    expect("a locked row that reads a LOSS fails", outcome_lost_lock == "FAIL")
    expect("a run on another platform is refused", "platform" in why_other)

    print(f"  mcu-speed selftest: {ok} passed, {bad} failed")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return cmd_selftest()
    if len(argv) == 3 and argv[1] == "--check-table":
        return check_table(pathlib.Path(argv[2]))
    if len(argv) >= 2 and argv[1] == "--gate":
        parser = argparse.ArgumentParser(prog="mcu_speed.py --gate")
        parser.add_argument("result")
        parser.add_argument("--table", default=str(TABLE))
        args = parser.parse_args(argv[2:])
        return cmd_gate(pathlib.Path(args.result), pathlib.Path(args.table))
    if len(argv) < 2 or argv[1] != "run":
        print(__doc__, file=sys.stderr)
        return 64
    parser = argparse.ArgumentParser(prog="mcu_speed.py run")
    parser.add_argument("--images", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--pacer", required=True)
    parser.add_argument("--zenohd", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--board", default=DEFAULT_BOARD)
    parser.add_argument("--qemu-machine", default="")
    parser.add_argument("--qemu", default="qemu-system-arm")
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)))
    parser.add_argument("--threads", default=",".join(THREADS))
    parser.add_argument("--workloads", default=",".join(WORKLOADS))
    parser.add_argument("--puts", type=int, default=2000)
    parser.add_argument("--window-ms", type=int, default=2000)
    parser.add_argument("--warmup-ms", type=int, default=500)
    parser.add_argument("--offer-rate", type=int, default=1000)
    parser.add_argument("--router-log", default="")
    parser.add_argument("--round-trips", type=int, default=500)
    parser.add_argument("--warmup-round-trips", type=int, default=50)
    parser.add_argument("--timeout-ms", type=int, default=200)
    return cmd_run(parser.parse_args(argv[2:]))


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The boots of a host parity run (docs/upstream-parity.md section 5b): upstream's own example programs,
built once against the original (arm P) and once against the wz preset that stands in for it (arm W),
run on one host in alternating boots. It writes a run directory of the shape the verdict module reads
(`scripts/lib/kit_compare.py --run <dir>`), the shape the kit lane's compare runs have:

    <run>/manifest.tsv              one line per boot: round, image, the boot's directory
    <run>/<image>-r<round>/host.json   the boot's figures, one per metric, and the workloads it lost
    <run>/<image>-r<round>/*.out    what each program printed
    <run>/sizes/<image>/binary      a copy of the file the size cells read, and `binary.stripped`

A BOOT is one image running every workload once, each program started afresh:

  * rtt        z_pong listens, z_ping connects and makes --pings round trips of 8 bytes after its
               warm-up; the boot's figure is the median round trip (microseconds);
  * thr_<n>B   z_sub_thr listens, z_pub_thr connects and publishes n bytes as fast as it can; after
               --warmup-s the subscriber's reports of --window-s seconds are read: the boot's
               throughput is their median (messages a second), and the CPU of both processes over the
               same window (/proc/<pid>/stat) divided by what the median rate delivers in it is the
               CPU per message (nanoseconds); a window short of the subscriber's reports is lost with
               the publisher's own reports beside them where it prints any (zenoh-pico's does), so a
               subscriber that stopped receiving under the flood is told from a host that was busy;
  * pubsub     z_sub listens, z_put connects, puts once and leaves; the subscriber must print the sample;
  * query      z_queryable listens, z_get connects and must print a reply;
  * heap       pubsub, query and thr at the largest size run again with heap_peak.so preloaded: the
               heap peak of the two processes, summed (bytes). The timed workloads run without it, so
               the shim's cost is in no time or CPU figure.

The RSS of a workload is the peak resident set of each of its two processes, summed (KiB). Each program
is started under the launcher --rss-wrapper (fork_rss.c), which forks it and reports its maxrss: the
maxrss of a child this runner reaps itself is at least this runner's own resident set, which Linux keeps
across the child's exec, so every program would read as at least the runner. Every figure of a pair is
the sum of its two processes, because both arms run both sides: a cost moved from one side to the other
is the same cost.

A timed workload (rtt, thr) is VALID only when the CPUs it was pinned to were used by nothing else
(nodrop.py's rule: the busy time of those CPUs less the CPU time of the two processes, over the CPU
seconds the workload had, at most 10 percent); an invalid one is run again, up to six times. A
functional workload (pubsub, query) that did not deliver is run again, up to three times. A workload
that never became valid leaves its metrics out of the boot and says why in `lost`.

The ORDER of the boots alternates by round (A B, B A, A B, ...) as the kit lane's compare does, so a
drift of the host over the run falls on both images alike.

    parity.py --family pico|c|rust --bin-dir DIR --run DIR --boots N --image KEY --reference KEY
              --rss-wrapper PATH [--sizes 8,1024] [--client-cpus 4-7] [--server-cpus 8-11] [--pings 20000]
              [--warmup-s 3] [--window-s 10] [--heap-shim PATH] [--size-binary P=PATH --size-binary W=PATH]
    parity.py --selftest
              the launcher, built here with cc, read from a runner that holds BALLAST_MIB

DIR holds <program>_P and <program>_W for z_put z_sub z_get z_queryable z_pub_thr z_sub_thr z_ping
z_pong. The client side (z_ping, z_pub_thr, z_put, z_get) is pinned to --client-cpus and the server
side to --server-cpus.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import pathlib
import random
import re
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from nodrop import FOREIGN_LIMIT, MAX_RUNS, busy_seconds, cpu_list  # noqa: E402

CLOCK_TICKS = os.sysconf("SC_CLK_TCK")
PROGRAMS = ("z_put", "z_sub", "z_get", "z_queryable", "z_pub_thr", "z_sub_thr", "z_ping", "z_pong")
FAMILIES = ("pico", "c", "rust")
#: The seconds a listener is given before the other side connects to it.
SETTLE_S = 1.5
#: A functional workload that did not deliver is run again this many times in all.
FUNCTIONAL_RUNS = 3
#: The fewest subscriber reports a throughput window must hold to give a median.
MIN_REPORTS = 5

#: zenoh-c and zenoh print `rtt=<n>µs`; zenoh-pico prints the bare number.
RTT_TAGGED = re.compile(r"rtt=(\d+(?:\.\d+)?)")
#: A throughput report: zenoh-pico prints the bare rate, zenoh-c and zenoh `<rate> msg/s`. The lines a
#: subscriber prints when it is dropped (`Received ... msg/s`, `Stats being dropped ...`) do not match.
BARE_NUMBER = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(?:msg/s)?\s*$")
#: z_sub of all three: `>> [Subscriber] Received (...)` or `Received PUT (...)`.
DELIVERED = re.compile(r">> \[Subscriber\] Received")
#: z_get of all three prints a reply as `>> Received ('key': 'value')` (zenoh-pico: `>> Received PUT (`);
#: zenoh-pico also prints `>> Received query final notification`, which is no reply.
REPLIED = re.compile(r">> Received[^\n]*\('")
#: The lines of a launcher's report (fork_rss.c), each read only once its newline is written.
REPORT_PID = re.compile(r"^pid=(\d+)\n", re.M)
REPORT_RSS = re.compile(r"^peak_rss_kib=(\d+)\n", re.M)
#: The seconds a launcher is given to fork its program.
LAUNCH_WAIT_S = 5.0


class Lost(Exception):
    """A workload that did not give a valid figure: the reason is the message."""


def rates(lines: list[str]) -> list[float]:
    """The positive rates among the lines a throughput program printed."""
    found = [float(m.group(1)) for m in map(BARE_NUMBER.match, lines) if m]
    return [r for r in found if r > 0]


def shortfall(before: list[float], window: list[float], published: list[float]) -> str:
    """Why a throughput window holds fewer than MIN_REPORTS rates of the subscriber, from its rates
    before the window and in it and the publisher's own rates in it. zenoh-pico's z_pub_thr prints its
    rate as its subscriber does (zenoh-c's and zenoh's print none), and a publisher that goes on
    reporting while its subscriber is silent is a pair whose link stopped delivering: a failure of the
    pair under the flood, which a busy host or a slow start does not explain and a retry does not cure."""
    said = f"the subscriber reported {len(window)} rates in the window, fewer than {MIN_REPORTS}"
    if len(published) < MIN_REPORTS:
        return said
    if before:
        return (f"{said}, and {len(before)} before it, while the publisher reported {len(published)} in "
                "the window: the subscriber stopped receiving while the publisher went on putting")
    return (f"{said} and none before it, while the publisher reported {len(published)} in the window: "
            "nothing the publisher put was received")


def endpoint() -> str:
    return f"tcp/127.0.0.1:{20000 + random.randrange(20000)}"


def common(family: str, role: str, where: str) -> list[str]:
    """The session's arguments, as each family's examples take them: peer mode, one endpoint, and for
    zenoh-c and zenoh the multicast scouting off, so a session meets only the other side and never a
    node of another run on the host (zenoh-pico's peer does not scout here)."""
    words = ["-m", "peer", "-l" if role == "listen" else "-e", where]
    if family != "pico":
        words.append("--no-multicast-scouting")
    return words


def ping_args(family: str, pings: int, warmup_s: float, where: str) -> list[str]:
    if family == "pico":
        return ["-s", "8", "-n", str(pings), "-w", str(int(warmup_s * 1000)), *common(family, "connect", where)]
    if family == "c":
        return ["8", "-n", str(pings), "-w", str(int(warmup_s * 1000)), *common(family, "connect", where)]
    return ["8", "-n", str(pings), "-w", f"{warmup_s:g}", *common(family, "connect", where)]


def pub_thr_args(family: str, size: int, where: str) -> list[str]:
    if family == "pico":
        return ["-s", str(size), *common(family, "connect", where)]
    return [str(size), *common(family, "connect", where)]


def sub_thr_args(family: str, where: str) -> list[str]:
    if family == "pico":
        return common(family, "listen", where)
    # Rounds of upstream's default size, and more of them than a window holds: the subscriber is
    # stopped, it does not stop by itself inside the window.
    return ["-s", "1000000", *common(family, "listen", where)]


class Process:
    """One program of a workload, pinned, its output line-buffered into a file. It is reaped with
    wait4, which gives its resource use whether it exited or was stopped by a signal.

    Started under the launcher `rss_wrapper` (fork_rss.c), the program is forked by the launcher and
    not by this runner, and the launcher's report holds the program's pid and its peak resident set:
    the maxrss of a child this runner reaps is at least this runner's own resident set, which Linux keeps
    across the child's exec. `pid` is then the launcher's, which is waited for and signalled (it passes a
    stop on), and `program_pid` the program's, whose /proc entries are read."""

    def __init__(self, argv: list[str], cpus: str, out: pathlib.Path, env: dict[str, str],
                 rss_wrapper: str | None = None):
        self.out_path = out
        self.out = out.open("wb")
        pinned = ["taskset", "-c", cpus, "stdbuf", "-oL", "-eL", *argv]
        self.report: pathlib.Path | None = None
        if rss_wrapper is None:
            full = dict(os.environ)
            full.update(env)
            self.popen = subprocess.Popen(pinned, stdout=self.out, stderr=subprocess.STDOUT, env=full)
        else:
            self.report = out.with_suffix(".rss")
            # A retried workload starts under the same name: a report left by the last try is not this one's.
            self.report.unlink(missing_ok=True)
            # Set after the launcher's fork, so a preloaded shim counts the program and never the launcher.
            assigned = [f"{name}={value}" for name, value in env.items()]
            self.popen = subprocess.Popen([rss_wrapper, str(self.report), *(["env", *assigned] if assigned else []),
                                           *pinned], stdout=self.out, stderr=subprocess.STDOUT)
        self.pid = self.popen.pid
        self.status: int | None = None
        self.rusage = None
        self.program_pid = self.pid if self.report is None else self.forked_pid()

    def report_text(self) -> str:
        try:
            return "" if self.report is None else self.report.read_text(encoding="ascii", errors="replace")
        except OSError:
            return ""

    def forked_pid(self) -> int | None:
        """The program's pid once the launcher's report names it; None when the launcher ended, or did
        not fork it in LAUNCH_WAIT_S."""
        deadline = time.monotonic() + LAUNCH_WAIT_S
        while True:
            # Read after the look at the launcher, so a launcher that wrote the line and ended is not missed.
            ended = self.reap(0)
            found = REPORT_PID.search(self.report_text())
            if found is not None:
                return int(found.group(1))
            if ended or time.monotonic() >= deadline:
                return None
            time.sleep(0.005)

    def reap(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while self.rusage is None:
            pid, status, rusage = os.wait4(self.pid, os.WNOHANG)
            if pid == self.pid:
                self.status, self.rusage = status, rusage
                # The Popen object must not wait for a child that is gone.
                self.popen.returncode = os.waitstatus_to_exitcode(status)
                break
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)
        return True

    def stop(self) -> None:
        if self.rusage is None:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if not self.reap(5.0):
                # The program is killed and not its launcher, so the launcher still reaps it and reports.
                launched = self.report is not None and self.program_pid is not None
                with contextlib.suppress(ProcessLookupError):
                    os.kill(self.program_pid if launched else self.pid, signal.SIGKILL)
                if not self.reap(5.0) and launched:
                    os.kill(self.pid, signal.SIGKILL)
                    self.reap(5.0)
        self.out.close()

    def cpu_seconds(self) -> float | None:
        """User and system time of all the program's threads so far, or None when it has ended."""
        if self.program_pid is None:
            return None
        try:
            text = pathlib.Path(f"/proc/{self.program_pid}/stat").read_text(encoding="ascii", errors="replace")
        except OSError:
            return None
        fields = text[text.rindex(")") + 2:].split()
        if fields[0] == "Z":
            return None
        return (int(fields[11]) + int(fields[12])) / CLOCK_TICKS

    def own_seconds(self) -> float:
        return 0.0 if self.rusage is None else self.rusage.ru_utime + self.rusage.ru_stime

    def rss_kib(self) -> int:
        """The program's peak resident set, as its launcher read it. Raises Lost when there is none: a
        program started without the launcher, whose reaped maxrss is at least this runner's, or one whose
        launcher ended before it could report."""
        if self.report is None:
            raise Lost(f"{self.out_path.name} was started without the launcher that reads its peak resident set")
        found = REPORT_RSS.search(self.report_text())
        if found is None:
            raise Lost(f"{self.out_path.name}: its launcher reported no peak resident set")
        return int(found.group(1))

    def text(self) -> str:
        return self.out_path.read_text(encoding="utf-8", errors="replace")


class Boot:
    """One image's boot: where its programs are, how they are pinned, and where they write."""

    def __init__(self, args: argparse.Namespace, arm: str, directory: pathlib.Path):
        self.args = args
        self.family = args.family
        self.arm = arm
        self.dir = directory
        self.cpus = sorted(set(cpu_list(args.client_cpus)) | set(cpu_list(args.server_cpus)))

    def program(self, name: str) -> str:
        return str(pathlib.Path(self.args.bin_dir) / f"{name}_{self.arm}")

    def start(self, name: str, argv: list[str], side: str, tag: str, heap: bool = False) -> Process:
        env = {}
        if heap:
            env = {"LD_PRELOAD": self.args.heap_shim, "HEAP_PEAK_FILE": str(self.dir / f"{tag}.{name}.heap")}
        cpus = self.args.client_cpus if side == "client" else self.args.server_cpus
        return Process([self.program(name), *argv], cpus, self.dir / f"{tag}.{name}.out", env,
                       self.args.rss_wrapper)

    def heap_peak(self, tag: str, name: str) -> int:
        path = self.dir / f"{tag}.{name}.heap"
        data = path.read_bytes() if path.exists() else b""
        if len(data) < 16:
            raise Lost(f"{name} left no heap figures in {path.name} (was the shim preloaded?)")
        return struct.unpack("<qq", data[:16])[0]

    # -- the timed workloads ------------------------------------------------------------------------

    def timed(self, body) -> dict[str, float]:
        """Run `body` until it gave figures while the pinned CPUs were used by nothing else (up to
        six runs; a run that gave no figures counts as one)."""
        reasons = []
        for _ in range(MAX_RUNS):
            busy0, wall0 = busy_seconds(self.cpus), time.monotonic()
            try:
                figures, procs = body()
            except Lost as why:
                reasons.append(str(why))
                time.sleep(1)
                continue
            wall = time.monotonic() - wall0
            own = sum(p.own_seconds() for p in procs)
            foreign = max(0.0, busy_seconds(self.cpus) - busy0 - own) / (wall * len(self.cpus))
            if foreign <= FOREIGN_LIMIT:
                return figures
            reasons.append(f"the pinned CPUs were {foreign * 100:.0f}% used by something else")
            time.sleep(5)
        raise Lost("no valid run in " + str(MAX_RUNS) + ": " + "; ".join(reasons))

    def rtt(self) -> dict[str, float]:
        args = self.args

        def body():
            where = endpoint()
            pong = self.start("z_pong", common(self.family, "listen", where), "server", "rtt")
            try:
                time.sleep(SETTLE_S)
                ping = self.start("z_ping", ping_args(self.family, args.pings, args.warmup_s, where), "client", "rtt")
                done = ping.reap(args.warmup_s + 120.0)
                ping.stop()
            finally:
                pong.stop()
            if not done:
                raise Lost("z_ping did not finish in time")
            reader = BARE_NUMBER.match if self.family == "pico" else RTT_TAGGED.search
            rtts = [float(m.group(1)) for m in map(reader, ping.text().splitlines()) if m]
            if len(rtts) != args.pings:
                raise Lost(f"z_ping printed {len(rtts)} round trips of {args.pings}")
            return {"rtt_us": statistics.median(rtts), "rss_kib_rtt": ping.rss_kib() + pong.rss_kib()}, [ping, pong]

        return self.timed(body)

    def thr(self, size: int) -> dict[str, float]:
        args = self.args

        def body():
            where = endpoint()
            sub = self.start("z_sub_thr", sub_thr_args(self.family, where), "server", f"thr{size}")
            pub = None
            try:
                time.sleep(SETTLE_S)
                pub = self.start("z_pub_thr", pub_thr_args(self.family, size, where), "client", f"thr{size}")
                time.sleep(args.warmup_s)
                lines0 = len(sub.text().splitlines())
                pub0 = len(pub.text().splitlines())
                cpu0 = (pub.cpu_seconds(), sub.cpu_seconds())
                t0 = time.monotonic()
                time.sleep(args.window_s)
                cpu1 = (pub.cpu_seconds(), sub.cpu_seconds())
                t1 = time.monotonic()
                lines = sub.text().splitlines()
                pub_lines = pub.text().splitlines()
            finally:
                if pub is not None:
                    pub.stop()
                sub.stop()
            if None in cpu0 or None in cpu1:
                raise Lost("a side of the throughput pair ended inside the window")
            reports = rates(lines[lines0:])
            if len(reports) < MIN_REPORTS:
                raise Lost(shortfall(rates(lines[:lines0]), reports, rates(pub_lines[pub0:])))
            rate = statistics.median(reports)
            cpu = (cpu1[0] - cpu0[0]) + (cpu1[1] - cpu0[1])
            return {f"throughput_{size}B": rate,
                    f"cpu_ns_per_msg_{size}B": cpu / (t1 - t0) / rate * 1e9,
                    f"rss_kib_thr_{size}B": pub.rss_kib() + sub.rss_kib()}, [pub, sub]

        return self.timed(body)

    # -- the functional workloads -------------------------------------------------------------------

    def functional(self, body) -> dict[str, float]:
        reasons = []
        for _ in range(FUNCTIONAL_RUNS):
            try:
                return body()
            except Lost as why:
                reasons.append(str(why))
                time.sleep(1)
        raise Lost("; ".join(reasons))

    def pair(self, server: str, client: str, tag: str, proof: re.Pattern, proof_of: str,
             heap: bool) -> tuple[Process, Process]:
        where = endpoint()
        srv = self.start(server, common(self.family, "listen", where), "server", tag, heap)
        cli = None
        try:
            time.sleep(SETTLE_S)
            cli = self.start(client, common(self.family, "connect", where), "client", tag, heap)
            done = cli.reap(30.0)
            watched = srv if proof_of == "server" else cli
            deadline = time.monotonic() + 5.0
            while not proof.search(watched.text()) and time.monotonic() < deadline:
                time.sleep(0.05)
            delivered = bool(proof.search(watched.text()))
        finally:
            if cli is not None:
                cli.stop()
            srv.stop()
        if not done:
            raise Lost(f"{client} did not finish in time")
        if not delivered:
            raise Lost(f"{proof_of} side printed no {'sample' if proof is DELIVERED else 'reply'}")
        return srv, cli

    def pubsub(self, heap: bool) -> dict[str, float]:
        def body():
            sub, put = self.pair("z_sub", "z_put", "pubsub" + (".heap" if heap else ""), DELIVERED, "server", heap)
            if heap:
                return {"heap_peak_pubsub": self.heap_peak("pubsub.heap", "z_sub")
                        + self.heap_peak("pubsub.heap", "z_put")}
            return {"rss_kib_pubsub": sub.rss_kib() + put.rss_kib()}

        return self.functional(body)

    def query(self, heap: bool) -> dict[str, float]:
        def body():
            qbl, get = self.pair("z_queryable", "z_get", "query" + (".heap" if heap else ""), REPLIED, "client", heap)
            if heap:
                return {"heap_peak_query": self.heap_peak("query.heap", "z_queryable")
                        + self.heap_peak("query.heap", "z_get")}
            return {"rss_kib_query": qbl.rss_kib() + get.rss_kib()}

        return self.functional(body)

    def thr_heap(self, size: int) -> dict[str, float]:
        args = self.args

        def body():
            where = endpoint()
            tag = f"thr{size}.heap"
            sub = self.start("z_sub_thr", sub_thr_args(self.family, where), "server", tag, heap=True)
            pub = None
            try:
                time.sleep(SETTLE_S)
                pub = self.start("z_pub_thr", pub_thr_args(self.family, size, where), "client", tag, heap=True)
                time.sleep(args.warmup_s + args.window_s)
                alive = pub.cpu_seconds() is not None and sub.cpu_seconds() is not None
            finally:
                if pub is not None:
                    pub.stop()
                sub.stop()
            if not alive:
                raise Lost("a side of the throughput pair ended before it was stopped")
            if not any(BARE_NUMBER.match(line) for line in sub.text().splitlines()):
                raise Lost("the subscriber reported no rate")
            return {f"heap_peak_thr_{size}B": self.heap_peak(tag, "z_sub_thr") + self.heap_peak(tag, "z_pub_thr")}

        return self.functional(body)

    def run(self) -> dict:
        values: dict[str, float] = {}
        lost: dict[str, str] = {}
        sizes = [int(s) for s in self.args.sizes.split(",")]
        steps = [("rtt", self.rtt)]
        steps += [(f"thr_{s}B", lambda s=s: self.thr(s)) for s in sizes]
        steps += [("pubsub", lambda: self.pubsub(False)), ("query", lambda: self.query(False))]
        if self.args.heap_shim:
            steps += [("heap_pubsub", lambda: self.pubsub(True)), ("heap_query", lambda: self.query(True)),
                      (f"heap_thr_{max(sizes)}B", lambda: self.thr_heap(max(sizes)))]
        for name, step in steps:
            try:
                values.update(step())
            except Lost as why:
                lost[name] = str(why)
        return {"values": values, "lost": lost}


def keep_sizes(run: pathlib.Path, key: str, binary: str) -> None:
    """The file the size cells read, copied into the run with a stripped copy beside it: the run keeps
    what was measured, whatever is rebuilt after it."""
    where = run / "sizes" / key
    where.mkdir(parents=True, exist_ok=True)
    shutil.copy2(os.path.realpath(binary), where / "binary")
    subprocess.run(["strip", "--strip-unneeded", "-o", str(where / "binary.stripped"), str(where / "binary")],
                   check=True)


# -- the selftest -------------------------------------------------------------------------------------------

#: What the selftest's runner holds while it starts a program, and what that program holds of its own.
BALLAST_MIB = 200
CHILD_MIB = 32


def gone(pid: int | None, seconds: float) -> bool:
    """Whether process `pid` no longer runs within `seconds`: it has no /proc entry, or is a zombie that
    whoever adopted it has not reaped yet."""
    deadline = time.monotonic() + seconds
    while pid is not None:
        try:
            text = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
        except OSError:
            return True
        if text[text.rindex(")") + 2:].startswith("Z"):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


def rss_or_none(proc: Process) -> int | None:
    try:
        return proc.rss_kib()
    except Lost:
        return None


def within(rss: int | None, low: int, high: int) -> bool:
    return rss is not None and low <= rss < high


def cmd_selftest() -> int:
    ok = 0
    bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  parity selftest FAIL: {name}", file=sys.stderr)

    with tempfile.TemporaryDirectory(prefix="parity-selftest-") as tmp:
        where = pathlib.Path(tmp)
        launcher = str(where / "fork_rss")
        source = pathlib.Path(__file__).resolve().parent / "fork_rss.c"
        if shutil.which("cc") is None:
            print("  parity selftest FAIL: no cc on PATH to build fork_rss.c", file=sys.stderr)
            return 1
        built = subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-o", launcher, str(source)],
                               capture_output=True, text=True)
        if built.returncode != 0:
            print(f"  parity selftest FAIL: fork_rss.c did not build:\n{built.stdout}{built.stderr}", file=sys.stderr)
            return 1
        ballast = bytes([1]) * (BALLAST_MIB << 20)
        held = len(ballast) >> 10
        cpu = str(min(os.sched_getaffinity(0)))
        holds = [sys.executable, "-I", "-c", f"held = bytes([1]) * ({CHILD_MIB} << 20)\n"
                 "import os, sys, time\n"
                 "print('mark=' + os.environ.get('PARITY_SELFTEST_MARK', ''), flush=True)\n"
                 "if sys.argv[1:] == ['wait']:\n"
                 "    time.sleep(60)\n"]

        ended = Process(holds, cpu, where / "ended.out", {}, launcher)
        reaped = ended.reap(30.0)
        ended.stop()
        expect("a program started under the launcher is waited for through it, and its status is the program's",
               reaped and ended.status is not None and os.waitstatus_to_exitcode(ended.status) == 0)
        expect("the launcher reports the program's pid, not its own",
               ended.program_pid is not None and ended.program_pid != ended.pid)
        expect("the peak RSS read of a program that ended is its own, not its runner's",
               within(rss_or_none(ended), CHILD_MIB << 10, held))

        stopped = Process([*holds, "wait"], cpu, where / "stopped.out", {"PARITY_SELFTEST_MARK": "set"}, launcher)
        deadline = time.monotonic() + 30.0
        while "mark=" not in stopped.text() and time.monotonic() < deadline:
            time.sleep(0.05)
        try:
            launcher_env = pathlib.Path(f"/proc/{stopped.pid}/environ").read_bytes()
        except OSError:
            launcher_env = b"unread"
        running = stopped.cpu_seconds() is not None
        stopped.stop()
        expect("an environment given for the program is the program's and not the launcher's",
               "mark=set" in stopped.text() and b"unread" != launcher_env
               and b"PARITY_SELFTEST_MARK=" not in launcher_env)
        expect("the CPU read of a running program is the program's", running)
        expect("a stop sent to the launcher ends the program, and the launcher ends as a shell reports it",
               stopped.status is not None and os.waitstatus_to_exitcode(stopped.status) == 128 + signal.SIGTERM
               and gone(stopped.program_pid, 5.0))
        expect("the peak RSS read of a program stopped by a signal is its own, not its runner's",
               within(rss_or_none(stopped), CHILD_MIB << 10, held))

        killed = Process([*holds, "wait"], cpu, where / "killed.out", {}, launcher)
        os.kill(killed.pid, signal.SIGKILL)
        killed.reap(5.0)
        killed.stop()
        expect("a launcher killed hard leaves no program behind, and no peak RSS to read",
               gone(killed.program_pid, 5.0) and rss_or_none(killed) is None)

        bare = Process(holds, cpu, where / "bare.out", {})
        bare.reap(30.0)
        bare.stop()
        expect("control: the maxrss of a child this runner reaps itself carries the runner's resident set",
               bare.rusage is not None and int(bare.rusage.ru_maxrss) >= held)
        expect("a program started without the launcher is refused a peak RSS", rss_or_none(bare) is None)

    expect("a throughput program's rates are its positive bare numbers, with or without msg/s",
           rates(["3965575.130", "0.000", "Received 5 msg/s", "12 msg/s", "Stats being dropped"]) == [3965575.13, 12.0])
    flood = [1.5e7] * 100
    expect("a subscriber that reported and went silent while its publisher reported is a link that stopped",
           "stopped receiving while the publisher went on putting" in shortfall([3.9e6] * 4, [], flood))
    expect("a subscriber that never reported while its publisher did received nothing",
           "nothing the publisher put was received" in shortfall([], [], flood))
    expect("without the publisher's rates the shortfall is the subscriber's count alone",
           shortfall([3.9e6] * 4, [1.0], []) == f"the subscriber reported 1 rates in the window, fewer than {MIN_REPORTS}")
    print(f"  parity selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return cmd_selftest()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--family", required=True, choices=FAMILIES)
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--boots", type=int, required=True, help="boots of each image")
    parser.add_argument("--image", required=True, help="the key of arm W (wz) in the run")
    parser.add_argument("--reference", required=True, help="the key of arm P (the original) in the run")
    parser.add_argument("--sizes", default="8,1024")
    parser.add_argument("--client-cpus", default="4-7")
    parser.add_argument("--server-cpus", default="8-11")
    parser.add_argument("--pings", type=int, default=20000)
    parser.add_argument("--warmup-s", type=float, default=3.0)
    parser.add_argument("--window-s", type=float, default=10.0)
    parser.add_argument("--heap-shim", default="")
    parser.add_argument("--rss-wrapper", required=True, help="the launcher built from fork_rss.c")
    parser.add_argument("--size-binary", action="append", default=[], help="ARM=PATH, the file of an arm's size cells")
    args = parser.parse_args()

    missing = [f"{p}_{arm}" for p in PROGRAMS for arm in "PW"
               if not os.access(pathlib.Path(args.bin_dir) / f"{p}_{arm}", os.X_OK)]
    if missing:
        print(f"parity: NOT-MEASURED, {args.bin_dir} lacks {', '.join(missing)}", flush=True)
        return 2
    if args.heap_shim and not os.path.isfile(args.heap_shim):
        print(f"parity: NOT-MEASURED, no heap shim at {args.heap_shim}", flush=True)
        return 2
    if not os.access(args.rss_wrapper, os.X_OK):
        print(f"parity: NOT-MEASURED, no launcher that reads a peak resident set at {args.rss_wrapper}", flush=True)
        return 2
    run = pathlib.Path(args.run)
    run.mkdir(parents=True, exist_ok=False)
    keys = {"P": args.reference, "W": args.image}
    for spec in args.size_binary:
        arm, _, path = spec.partition("=")
        if arm not in keys or not path:
            print(f"parity: --size-binary takes P=PATH or W=PATH, not {spec}", flush=True)
            return 64
        keep_sizes(run, keys[arm], path)

    print(f"parity: family {args.family}, {args.boots} boots of {keys['P']} (P) and {keys['W']} (W), "
          f"alternating; client side on {args.client_cpus}, server side on {args.server_cpus}; "
          f"sizes {args.sizes}; {args.pings} round trips; throughput window {args.window_s:g} s after "
          f"{args.warmup_s:g} s; heap shim {'on' if args.heap_shim else 'off'}", flush=True)
    with (run / "manifest.tsv").open("w", encoding="utf-8") as manifest:
        for rnd in range(1, args.boots + 1):
            order = ("P", "W") if rnd % 2 else ("W", "P")
            for arm in order:
                key = keys[arm]
                sub = f"{key}-r{rnd}"
                (run / sub).mkdir()
                result = Boot(args, arm, run / sub).run()
                result.update({"image": key, "arm": arm, "round": rnd, "family": args.family})
                (run / sub / "host.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n",
                                                     encoding="utf-8")
                manifest.write(f"{rnd}\t{key}\t{sub}\n")
                manifest.flush()
                shown = ", ".join(f"{k} {v:.4g}" for k, v in sorted(result["values"].items()))
                print(f"  parity {key} r{rnd}: {shown}", flush=True)
                for name, why in sorted(result["lost"].items()):
                    print(f"  parity {key} r{rnd}: LOST {name}: {why}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

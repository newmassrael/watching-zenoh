#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The no-drop rate of a publisher and a subscriber pair (RFC 2544): the highest rate OFFERED at which
nothing is lost.

The upstream throughput examples send as fast as they can and print what the subscriber saw. That says
how fast a side can go, and it breaks down when one side cannot take the other's full rate: the control
of scripts/pico-compare.sh (pico on both sides) read "no samples", so no cell of it could be graded.
Here the publisher (`paced_pub.c`) OFFERS a stated rate and the subscriber (`count_sub.c`) counts what
it is delivered; a rate stands when every message was delivered and the rate was really offered.

A TRIAL at rate R for T seconds PASSES when all of these hold:
  * no put returned an error;
  * the subscriber counted as many messages as the publisher put (no loss, no duplicate);
  * the rate was offered: the puts took at most 102 percent of T and at least 98 percent of R * T
    messages were put. (A slot that starts a millisecond late is a stall of the publisher's thread, not a
    shortfall of its capacity, and is only printed: the catch-up of the next slots puts what was owed.)
A trial is VALID only when the pinned CPUs were not used by anything else: the busy time of those CPUs
(/proc/stat) less the CPU time of the two processes (getrusage of the children), over the CPU seconds the
trial had, is at most 10 percent. An invalid trial is run again, up to six runs, and a rate whose trials
stay invalid stops the search (the host was busy, which is no rate). A rate FAILS when it fails twice.
The SEARCH doubles the rate from a start until a rate fails (or the cap), then bisects between the last
pass and the first fail to a resolution of 5 percent. A pair whose lowest rate does not pass is reported
as having no valid rate, and the pair that is the CONTROL (the same library on both sides) must have
one: a cell graded against a control that passes nothing is not graded.

  nodrop.py --bin-dir DIR [--sizes 8,64,1024] [--reps 3] [--trial-s 3] [--pairs PP,WW,PW,WP]
            [--pub-cpus 6,7] [--sub-cpus 10,11] [--wz-env "VAR=value ..."]

DIR holds paced_pub_P, count_sub_P (built against zenoh-pico) and paced_pub_W, count_sub_W (against
libwz_capi_pico). A pair is `<publisher><subscriber>`.
"""

from __future__ import annotations

import argparse
import os
import random
import re
import resource
import shlex
import statistics
import subprocess
import sys
import time

CLOCK_TICKS = os.sysconf("SC_CLK_TCK")
FOREIGN_LIMIT = 0.10
MAX_RUNS = 6

START_RATE = 20000.0
CAP_RATE = 8_000_000.0
FLOOR_RATE = 500.0
RESOLUTION = 0.05
SENT = re.compile(
    r"paced_pub sent=(\d+) failed=(\d+) elapsed_s=([0-9.]+) late_slots=(\d+)")
RECEIVED = re.compile(r"count_sub received=(\d+)")


def command(variant: str, cpus: str, wz_env: str, argv: list[str]) -> list[str]:
    words: list[str] = []
    if variant == "W" and wz_env:
        words = ["env", *shlex.split(wz_env)]
    return [*words, "taskset", "-c", cpus, *argv]


BATCH = False  # set by --batch: the puts of a 1 ms slot are one batch (paced_pub -b)
LAST_FOREIGN = ""  # the shares of the pinned CPUs that something else used, in the last disturbed trials


def cpu_list(spec: str) -> list[int]:
    """`6,7` or `6-9,12` as the CPUs they name."""
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            low, high = part.split("-")
            out.extend(range(int(low), int(high) + 1))
        elif part:
            out.append(int(part))
    return out


def busy_seconds(cpus: list[int]) -> float:
    """The seconds the CPUs have run tasks (user, nice, system, and the time a hypervisor took), from
    /proc/stat. The time spent in interrupts and soft interrupts is NOT counted: the packets of a loopback
    TCP stream are handled there, they are the cost of the two processes under test and not of anything
    else, and the kernel books them to the CPU and not to a process, so counting them would read the test's
    own traffic as somebody else's work."""
    total = 0
    wanted = {f"cpu{n}" for n in cpus}
    with open("/proc/stat", encoding="ascii") as stat:
        for line in stat:
            fields = line.split()
            if fields and fields[0] in wanted:
                user, nice, system, idle, iowait, irq, softirq, steal = (int(x) for x in fields[1:9])
                total += user + nice + system + steal
    return total / CLOCK_TICKS


def children_seconds() -> float:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def trial(bin_dir: str, pub: str, sub: str, size: int, rate: float, seconds: int,
          pub_cpus: str, sub_cpus: str, wz_env: str) -> dict:
    """One trial: the result is a dict with `passed`, the figures and the `foreign` share of the pinned CPUs
    (what ran there besides the two processes), or a `why` it could not run."""
    cpus = sorted(set(cpu_list(pub_cpus)) | set(cpu_list(sub_cpus)))
    busy0, own0, wall0 = busy_seconds(cpus), children_seconds(), time.monotonic()
    port = 20000 + random.randrange(20000)
    endpoint = f"tcp/127.0.0.1:{port}"
    sub_cmd = command(sub, sub_cpus, wz_env,
                      ["timeout", str(seconds + 12), os.path.join(bin_dir, f"count_sub_{sub}"),
                       "-m", "peer", "-l", endpoint, "-d", str(seconds + 6)])
    pub_cmd = command(pub, pub_cpus, wz_env,
                      ["timeout", str(seconds + 12), os.path.join(bin_dir, f"paced_pub_{pub}"),
                       "-m", "peer", "-e", endpoint, "-s", str(size), "-r", f"{rate:.1f}",
                       "-t", str(seconds), *(["-b"] if BATCH else [])])
    sub_proc = subprocess.Popen(sub_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        time.sleep(2.0)
        pub_done = subprocess.run(pub_cmd, capture_output=True, text=True, timeout=seconds + 20)
        sub_out, _ = sub_proc.communicate(timeout=seconds + 20)
    except subprocess.TimeoutExpired:
        sub_proc.kill()
        sub_proc.communicate()
        return {"passed": False, "why": "a side did not finish"}
    sent = SENT.search(pub_done.stdout)
    received = RECEIVED.search(sub_out)
    if not sent:
        return {"passed": False, "why": "the publisher printed no result: " + pub_done.stdout.strip()[-80:]}
    if not received:
        return {"passed": False, "why": "the subscriber printed no result: " + sub_out.strip()[-80:]}
    wall = time.monotonic() - wall0
    foreign = max(0.0, (busy_seconds(cpus) - busy0) - (children_seconds() - own0)) / (wall * len(cpus))
    puts, failed, elapsed, late = int(sent[1]), int(sent[2]), float(sent[3]), int(sent[4])
    counted = int(received[1])
    reasons = []
    if failed:
        reasons.append(f"{failed} puts failed")
    if counted != puts:
        reasons.append(f"{puts} put, {counted} counted")
    if elapsed > seconds * 1.02:
        reasons.append(f"the puts took {elapsed:.2f} s of {seconds}")
    if puts < 0.98 * rate * seconds:
        reasons.append(f"{puts} put of {rate * seconds:.0f} offered")
    return {"passed": not reasons, "why": "; ".join(reasons), "put": puts, "counted": counted,
            "elapsed": elapsed, "late": late, "foreign": foreign}


def valid_trial(bin_dir: str, pub: str, sub: str, size: int, rate: float, seconds: int,
                pub_cpus: str, sub_cpus: str, wz_env: str) -> tuple[dict | None, int]:
    """The first trial in which the pinned CPUs were not used by anything else (up to six runs, with a pause
    after a disturbed one: a shared host is busy in bursts), and the runs made; None when all six were
    disturbed (their shares are in LAST_FOREIGN)."""
    global LAST_FOREIGN
    shares = []
    for run in range(1, MAX_RUNS + 1):
        result = trial(bin_dir, pub, sub, size, rate, seconds, pub_cpus, sub_cpus, wz_env)
        if result.get("foreign", 0.0) <= FOREIGN_LIMIT:
            return result, run
        shares.append(result["foreign"])
        time.sleep(5)
    LAST_FOREIGN = ", ".join(f"{share * 100:.0f}%" for share in shares)
    return None, MAX_RUNS


def judge(bin_dir: str, pub: str, sub: str, size: int, rate: float, seconds: int,
          pub_cpus: str, sub_cpus: str, wz_env: str) -> tuple[str, str, int]:
    """(`pass`, `fail` or `busy`, why, the runs made): a rate fails when it fails twice."""
    args = (bin_dir, pub, sub, size, rate, seconds, pub_cpus, sub_cpus, wz_env)
    first, runs = valid_trial(*args)
    if first is None:
        return "busy", f"the pinned CPUs were used by something else in {MAX_RUNS} runs ({LAST_FOREIGN})", runs
    if first["passed"]:
        return "pass", "", runs
    second, more = valid_trial(*args)
    runs += more
    if second is None:
        return "busy", f"the pinned CPUs were used by something else in {MAX_RUNS} runs ({LAST_FOREIGN})", runs
    if second["passed"]:
        return "pass", "", runs
    return "fail", second["why"], runs


def search(bin_dir: str, pub: str, sub: str, size: int, seconds: int, pub_cpus: str, sub_cpus: str,
           wz_env: str) -> tuple[float | None, int, str]:
    """(the no-drop rate or None, the trials run, a note)."""
    trials = 0
    rate = START_RATE
    last_pass = 0.0
    first_fail = None
    why_fail = ""

    def at(rate: float) -> str:
        """`pass` or `fail` at the rate; `busy` ends the search (the note is why_fail). The note keeps
        the reason of the last rate that did NOT pass."""
        nonlocal trials, why_fail
        verdict, why, runs = judge(bin_dir, pub, sub, size, rate, seconds, pub_cpus, sub_cpus, wz_env)
        trials += runs
        if verdict != "pass":
            why_fail = why
        return verdict

    while rate <= CAP_RATE:
        verdict = at(rate)
        if verdict == "busy":
            return None, trials, f"the host was busy at {rate:.0f}: {why_fail}"
        if verdict == "pass":
            last_pass = rate
            rate *= 2
        else:
            first_fail = rate
            break
    if first_fail is None:
        return last_pass, trials, f"no loss up to the cap of {CAP_RATE:.0f}"
    if last_pass == 0.0:
        rate = first_fail / 4
        while rate >= FLOOR_RATE:
            verdict = at(rate)
            if verdict == "busy":
                return None, trials, f"the host was busy at {rate:.0f}: {why_fail}"
            if verdict == "pass":
                last_pass = rate
                break
            first_fail = rate
            rate /= 4
        if last_pass == 0.0:
            return None, trials, f"nothing passes down to {FLOOR_RATE:.0f}: {why_fail}"
    while first_fail - last_pass > RESOLUTION * last_pass:
        middle = (first_fail + last_pass) / 2
        verdict = at(middle)
        if verdict == "busy":
            return None, trials, f"the host was busy at {middle:.0f}: {why_fail}"
        if verdict == "pass":
            last_pass = middle
        else:
            first_fail = middle
    return last_pass, trials, f"first failure at {first_fail:.0f}: {why_fail}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--sizes", default="8,64,1024")
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--trial-s", type=int, default=3)
    parser.add_argument("--pairs", default="PP,WW,PW,WP")
    parser.add_argument("--pub-cpus", default="6,7")
    parser.add_argument("--sub-cpus", default="10,11")
    parser.add_argument("--wz-env", default="")
    parser.add_argument("--batch", action="store_true",
                        help="the puts of each 1 ms slot are one batch (zp_batch_start / zp_batch_stop)")
    args = parser.parse_args()
    global BATCH
    BATCH = args.batch

    print(f"no-drop rate (RFC 2544), trials of {args.trial_s} s, resolution {RESOLUTION * 100:.0f} percent; "
          f"puts {'batched per 1 ms slot' if BATCH else 'one by one'}; "
          f"publisher on {args.pub_cpus}, subscriber on {args.sub_cpus}; wz env: {args.wz_env or 'none'}",
          flush=True)
    results: dict[tuple[str, int], list[float | None]] = {}
    for size in (int(s) for s in args.sizes.split(",")):
        for pair in args.pairs.split(","):
            pub, sub = pair[0], pair[1]
            for rep in range(1, args.reps + 1):
                rate, trials, note = search(args.bin_dir, pub, sub, size, args.trial_s,
                                            args.pub_cpus, args.sub_cpus, args.wz_env)
                results.setdefault((pair, size), []).append(rate)
                shown = "no valid rate" if rate is None else f"{rate:.0f} msg/s"
                print(f"  nodrop pub={pub} sub={sub} size={size} rep{rep}: {shown} "
                      f"(trials {trials}; {note})", flush=True)
    print("summary (median of the reps, msg/s):", flush=True)
    for (pair, size), rates in results.items():
        valid = [r for r in rates if r is not None]
        shown = "no valid rate" if not valid else f"{statistics.median(valid):.0f} (n={len(valid)}/{len(rates)})"
        print(f"  pair {pair} size {size}: {shown}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

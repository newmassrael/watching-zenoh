#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3723 (no register item) -- the verdict of a compare run of the kit lane, cell by cell
(docs/upstream-parity.md step M1, decision D1).

## What this reads

`scripts/kit-lane.sh compare <image>... --boots N` flashes each image in alternating order (the
order of the images on odd rounds, the reverse on even rounds), boots it, asks it the lane's GETs
and captures the session's datagrams at the host's wire. It leaves one directory per run:

    <run>/manifest.tsv          one line per boot: round, image, the boot's directory
    <run>/<image>-r<round>/     cap.txt (tcpdump -tt -n -q), console.raw, rest.json, elf.path

## What it prints

For each image, its size (`size` of the ELF: text, data, bss, and flash = text + data, static
RAM = data + bss), the firmware's stack line where it prints one, and the wire turnaround of each
boot: for every datagram the node sent right after one the router sent, the gap between the two as
the host's clock saw them. A GET is one query in and one reply out, so the gap is what the node
(its stack, its driver and its session) took to answer; the rest of the round trip is the router,
the REST plugin and the host. Datagrams shorter than `MIN_DATAGRAM` (a KeepAlive) are not a query
or a reply and are left out on both sides.

A compare build also carries the memory report (CONFIG_WZ_MEMORY_REPORT, step M3): the kernel
heap's peak and every thread's stack, which both programs allocate from and run on. The last block
of each boot's report is read (its figures are high-water marks) and the image's worst boot is its
figure: the heap peak, the stack the threads used summed over them (pico runs a read task and a
lease task beside `main`, and a comparison of one thread with one thread of two is the error of
2026-10-22), and the stack they reserve.

Then each image against the reference (`--ref`, the first image by default), by decision D1:

* size and memory are one figure per build: WIN when the image's is smaller, LOSS when larger, TIE
  when equal;
* the turnaround is one median per boot, and the cell is the ratio of the median of the image's
  boot medians to the reference's, with a bootstrap 95% interval over the boots (resampled with
  replacement, seeded, so a run prints the same interval twice). WIN when the whole interval is
  below 1, LOSS when it is above 1, TIE otherwise. A TIE is not a claim either way.

It judges a run and grades nothing: the committed matrix (`deploy/upstream_parity.json`) is where a
verdict becomes a row. Exit 0 when the run was read, 2 when it could not be.

With `--format rows` it prints the cells as JSON rows, the shape `deploy/upstream_parity.json`
holds them in (decision D6), so a committed row is this module's output and never a figure copied
by hand.

Usage:
    kit_compare.py --run <run dir> [--ref <image>] [--node <ip>] [--format report|rows]
    kit_compare.py --selftest
"""

from __future__ import annotations

import json
import pathlib
import random
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass, field

#: The kit's own address on the bench network (CONFIG_NET_CONFIG_MY_IPV4_ADDR of the images).
NODE_DEFAULT = "192.168.100.10"
#: A datagram shorter than this carries no query and no reply: a KeepAlive is a handful of bytes.
MIN_DATAGRAM = 16
BOOTSTRAP_ROUNDS = 10_000
BOOTSTRAP_SEED = 20261026
#: tcpdump -tt -n -q: `<epoch>.<us> IP <src>.<port> > <dst>.<port>: UDP, length <n>`.
CAPTURE_LINE = re.compile(r"^(\d+\.\d+) IP (\S+?)\.(\d+) > (\S+?)\.(\d+): UDP, length (\d+)")
#: The wz firmware's high-water mark of its main stack (`StackWatch`).
STACK_LINE = re.compile(r"stack: peak (\d+) of (\d+) bytes")
#: The memory report every compare build carries (deploy/zephyr-common/wz_memory_report.c): one
#: heap line, then one line per thread, printed together whenever a figure moved.
HEAP_LINE = re.compile(r"mem: heap peak (\d+) of (\d+) bytes")
THREAD_LINE = re.compile(r"mem: stack (\S+) (\d+) of (\d+) bytes")


@dataclass
class Size:
    text: int
    data: int
    bss: int

    @property
    def flash(self) -> int:
        return self.text + self.data

    @property
    def ram(self) -> int:
        return self.data + self.bss


@dataclass(frozen=True)
class Memory:
    """One boot's memory report, its last block: every figure in it is a high-water mark."""

    heap_peak: int
    heap_pool: int
    stacks: tuple[tuple[str, int, int], ...]  # (thread, used, size)

    @property
    def stack_used(self) -> int:
        return sum(used for _, used, _ in self.stacks)

    @property
    def stack_reserved(self) -> int:
        return sum(size for _, _, size in self.stacks)


@dataclass
class Image:
    key: str
    size: Size | None = None
    stack: tuple[int, int] | None = None
    boot_medians: list[float] = field(default_factory=list)  # milliseconds, one per boot
    memory: list[Memory] = field(default_factory=list)  # one per boot that reported

    def worst_memory(self) -> Memory | None:
        """The boot whose heap peak and summed stack were the largest: the image's cost is what it
        needed on its worst boot."""
        if not self.memory:
            return None
        return max(self.memory, key=lambda m: (m.heap_peak, m.stack_used))


def turnarounds(capture: str, node: str) -> list[float]:
    """The node's turnarounds in a capture, in milliseconds."""
    events: list[tuple[float, bool]] = []
    for line in capture.splitlines():
        m = CAPTURE_LINE.match(line)
        if m and int(m.group(6)) >= MIN_DATAGRAM:
            events.append((float(m.group(1)), m.group(2) == node))
    return [(t1 - t0) * 1000.0 for (t0, from0), (t1, from1) in zip(events, events[1:])
            if not from0 and from1]


def berkeley_size(elf: pathlib.Path) -> Size:
    out = subprocess.run(["arm-none-eabi-size", str(elf)], check=True, capture_output=True,
                         text=True).stdout.splitlines()
    text, data, bss = (int(v) for v in out[1].split()[:3])
    return Size(text, data, bss)


def last_stack_line(console: str) -> tuple[int, int] | None:
    found = STACK_LINE.findall(console)
    return (int(found[-1][0]), int(found[-1][1])) if found else None


def last_memory_report(console: str) -> Memory | None:
    """The last block of the memory report: its heap line and the thread lines that follow it."""
    lines = console.replace("\r", "").splitlines()
    starts = [i for i, line in enumerate(lines) if HEAP_LINE.search(line)]
    if not starts:
        return None
    heap = HEAP_LINE.search(lines[starts[-1]])
    stacks = []
    for line in lines[starts[-1] + 1:]:
        m = THREAD_LINE.search(line)
        if not m:
            break
        stacks.append((m.group(1), int(m.group(2)), int(m.group(3))))
    return Memory(int(heap.group(1)), int(heap.group(2)), tuple(stacks))


def bootstrap_ratio(sample: list[float], ref: list[float]) -> tuple[float, float, float]:
    """The ratio of the median of `sample` to that of `ref`, and its 95% bootstrap interval."""
    rng = random.Random(BOOTSTRAP_SEED)
    ratios = sorted(
        statistics.median(rng.choices(sample, k=len(sample)))
        / statistics.median(rng.choices(ref, k=len(ref)))
        for _ in range(BOOTSTRAP_ROUNDS))
    point = statistics.median(sample) / statistics.median(ref)
    return point, ratios[int(0.025 * BOOTSTRAP_ROUNDS)], ratios[int(0.975 * BOOTSTRAP_ROUNDS) - 1]


def verdict_interval(lo: float, hi: float) -> str:
    if hi < 1.0:
        return "WIN"
    if lo > 1.0:
        return "LOSS"
    return "TIE"


def verdict_size(mine: int, ref: int) -> str:
    return "WIN" if mine < ref else "LOSS" if mine > ref else "TIE"


def read_run(run: pathlib.Path, node: str) -> dict[str, Image]:
    images: dict[str, Image] = {}
    for line in (run / "manifest.tsv").read_text().splitlines():
        if not line.strip():
            continue
        _round, key, sub = line.split("\t")
        boot = run / sub
        image = images.setdefault(key, Image(key))
        elf = pathlib.Path((boot / "elf.path").read_text().strip())
        size = berkeley_size(elf)
        if image.size is not None and image.size != size:
            raise ValueError(f"{key}: two boots of one image read two sizes ({image.size}, {size})")
        image.size = size
        console = (boot / "console.raw").read_text(errors="replace")
        image.stack = last_stack_line(console) or image.stack
        memory = last_memory_report(console)
        if memory is not None:
            image.memory.append(memory)
        gaps = turnarounds((boot / "cap.txt").read_text(errors="replace"), node)
        if gaps:
            image.boot_medians.append(statistics.median(gaps))
    return images


def report(images: dict[str, Image], ref_key: str) -> list[str]:
    out: list[str] = []
    for image in images.values():
        s = image.size
        if s is not None:
            out.append(f"kit-compare: {image.key}: text {s.text}, data {s.data}, bss {s.bss}; "
                       f"flash {s.flash}, static RAM {s.ram}")
        out.append(f"kit-compare: {image.key}: stack "
                   + (f"peak {image.stack[0]} of {image.stack[1]} bytes" if image.stack
                      else "not reported by the firmware"))
        worst = image.worst_memory()
        if worst is None:
            out.append(f"kit-compare: {image.key}: no memory report (a build without "
                       f"CONFIG_WZ_MEMORY_REPORT)")
        else:
            out.append(f"kit-compare: {image.key}: worst of {len(image.memory)} boot(s): heap peak "
                       f"{worst.heap_peak} of {worst.heap_pool}; {len(worst.stacks)} thread(s) "
                       f"used {worst.stack_used} of {worst.stack_reserved} bytes of stack")
            for thread, used, size in worst.stacks:
                out.append(f"kit-compare: {image.key}:   {thread} {used} of {size}")
        if image.boot_medians:
            m = image.boot_medians
            out.append(f"kit-compare: {image.key}: turnaround over {len(m)} boot(s): median "
                       f"{statistics.median(m):.3f} ms, boots {min(m):.3f} to {max(m):.3f}")
        else:
            out.append(f"kit-compare: {image.key}: no query/reply pair in any capture")
    for c in cells(images, ref_key):
        if c.metric == "turnaround":
            if c.verdict is None:
                out.append(f"kit-compare: cell turnaround: {c.image} vs {c.reference}: fewer than "
                           f"two boots with pairs on a side, no verdict")
            else:
                out.append(f"kit-compare: cell turnaround: {c.image} vs {c.reference}: ratio "
                           f"{c.ratio:.3f} [{c.low:.3f}, {c.high:.3f}] over {c.boots[0]} and "
                           f"{c.boots[1]} boots -> {c.verdict}")
        else:
            ratio = f"{c.ratio:.3f}" if c.ratio is not None else "n/a"
            out.append(f"kit-compare: cell {c.metric}: {c.image} {c.mine} vs {c.reference} "
                       f"{c.theirs} ({ratio}) -> {c.verdict}")
    return out


@dataclass(frozen=True)
class Cell:
    """One cell of the matrix: an image held to the reference on one metric (decision D1)."""

    image: str
    reference: str
    metric: str
    mine: float | None
    theirs: float | None
    ratio: float | None
    low: float | None  # the interval, for a metric measured over boots
    high: float | None
    boots: tuple[int, int] | None
    verdict: str | None  # WIN, TIE, LOSS, or None when there is nothing to judge


def cells(images: dict[str, Image], ref_key: str) -> list[Cell]:
    """Every cell of every image against the reference, in the order the report prints them."""
    out: list[Cell] = []
    ref = images[ref_key]
    for image in images.values():
        if image.key == ref_key:
            continue
        if image.size is not None and ref.size is not None:
            for metric in ("text", "flash", "ram"):
                mine, theirs = getattr(image.size, metric), getattr(ref.size, metric)
                out.append(Cell(image.key, ref_key, metric, mine, theirs, mine / theirs, None, None,
                                None, verdict_size(mine, theirs)))
        mine_mem, ref_mem = image.worst_memory(), ref.worst_memory()
        if mine_mem is not None and ref_mem is not None:
            for metric in ("heap_peak", "stack_used", "stack_reserved"):
                mine, theirs = getattr(mine_mem, metric), getattr(ref_mem, metric)
                out.append(Cell(image.key, ref_key, metric, mine, theirs,
                                mine / theirs if theirs else None, None, None,
                                (len(image.memory), len(ref.memory)), verdict_size(mine, theirs)))
        boots = (len(image.boot_medians), len(ref.boot_medians))
        if min(boots) >= 2:
            point, lo, hi = bootstrap_ratio(image.boot_medians, ref.boot_medians)
            out.append(Cell(image.key, ref_key, "turnaround",
                            statistics.median(image.boot_medians),
                            statistics.median(ref.boot_medians), point, lo, hi, boots,
                            verdict_interval(lo, hi)))
        else:
            out.append(Cell(image.key, ref_key, "turnaround", None, None, None, None, None, boots,
                            None))
    return out


def rows(images: dict[str, Image], ref_key: str, run: str) -> list[dict]:
    """The cells as the committed matrix holds them (`deploy/upstream_parity.json`, decision D6):
    every figure the verdict rests on, and the run it was read from."""
    return [{
        "image": c.image, "reference": c.reference, "metric": c.metric,
        "image_value": c.mine, "reference_value": c.theirs,
        "ratio": None if c.ratio is None else round(c.ratio, 4),
        "interval": None if c.low is None else [round(c.low, 4), round(c.high, 4)],
        "boots": None if c.boots is None else list(c.boots),
        "verdict": c.verdict, "run": run,
    } for c in cells(images, ref_key)]


def selftest() -> int:
    fails = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal fails
        print(f"  kit-compare selftest: {'ok  ' if cond else 'FAIL'} {name}")
        fails += not cond

    host, node = "192.168.100.1", NODE_DEFAULT
    cap = "\n".join([
        f"1.000000 IP {host}.7447 > {node}.5000: UDP, length 60",
        f"1.000210 IP {node}.5000 > {host}.7447: UDP, length 140",
        f"1.100000 IP {host}.7447 > {node}.5000: UDP, length 4",       # a KeepAlive in
        f"1.100050 IP {node}.5000 > {host}.7447: UDP, length 4",       # and one out
        f"1.200000 IP {host}.7447 > {node}.5000: UDP, length 60",
        f"1.200230 IP {node}.5000 > {host}.7447: UDP, length 140",
        f"1.300000 IP {node}.5000 > {host}.7447: UDP, length 140",     # the node, unasked
        "garbage line",
    ])
    gaps = turnarounds(cap, node)
    expect("a query and its reply give one gap each", len(gaps) == 2)
    expect("the gaps are the node's time", abs(gaps[0] - 0.21) < 1e-6 and abs(gaps[1] - 0.23) < 1e-6)
    expect("a KeepAlive pair is not a turnaround", all(g > 0.1 for g in gaps))
    expect("the router's address as the node finds the router's own gaps",
           turnarounds(cap, host) != gaps)

    expect("the last stack line is the one read",
           last_stack_line("stack: peak 10 of 20 bytes\nx\nstack: peak 30 of 40 bytes") == (30, 40))
    expect("no stack line is None", last_stack_line("nothing") is None)

    console = "\r\n".join([
        "mem: heap peak 100 of 4096 bytes",
        "mem: stack main 900 of 2048 bytes",
        "ZEPHYR-PICO READY 5a1c0ffee001 udp/192.168.100.1:7447",
        "mem: heap peak 300 of 4096 bytes",
        "mem: stack main 1000 of 2048 bytes",
        "mem: stack pthread_0 500 of 1024 bytes",
        "some later line",
    ])
    memory = last_memory_report(console)
    expect("the last block of the memory report is the one read",
           memory is not None and memory.heap_peak == 300 and memory.heap_pool == 4096)
    expect("the block's threads are summed and the line after it is not one of them",
           memory is not None and memory.stack_used == 1500 and memory.stack_reserved == 3072)
    expect("a console with no report has none", last_memory_report("nothing") is None)
    image = Image("x", memory=[Memory(10, 99, (("a", 5, 9),)), Memory(20, 99, (("a", 1, 9),))])
    expect("the worst boot is the one with the larger heap peak",
           image.worst_memory() is not None and image.worst_memory().heap_peak == 20)

    faster = [0.20, 0.201, 0.199, 0.202, 0.200, 0.198]
    slower = [0.21, 0.211, 0.209, 0.212, 0.210, 0.208]
    _, lo, hi = bootstrap_ratio(faster, slower)
    expect("a clearly faster image is a WIN", verdict_interval(lo, hi) == "WIN")
    _, lo, hi = bootstrap_ratio(slower, faster)
    expect("a clearly slower image is a LOSS", verdict_interval(lo, hi) == "LOSS")
    overlap = [0.205, 0.195, 0.215, 0.190, 0.210, 0.200]
    _, lo, hi = bootstrap_ratio(overlap, [0.200, 0.210, 0.195, 0.205, 0.198, 0.212])
    expect("overlapping boots are a TIE", verdict_interval(lo, hi) == "TIE")
    expect("the interval is the same on a second reading",
           bootstrap_ratio(overlap, faster) == bootstrap_ratio(overlap, faster))
    expect("a smaller build is a WIN, an equal one a TIE, a larger one a LOSS",
           (verdict_size(1, 2), verdict_size(2, 2), verdict_size(3, 2)) == ("WIN", "TIE", "LOSS"))

    images = {"pico": Image("pico", Size(100, 10, 50), None, slower),
              "wz": Image("wz", Size(90, 10, 40), (6000, 9216), faster)}
    lines = report(images, "pico")
    expect("the report names every cell of the image against the reference",
           sum(" cell " in line for line in lines) == 4)
    images["pico"].memory = [Memory(9416, 16384, (("main", 2944, 4096), ("pthread_0", 2736, 4096)))]
    images["wz"].memory = [Memory(0, 131072, (("main", 5928, 9216),))]
    lines = report(images, "pico")
    expect("with a memory report on both sides, its three cells join the four",
           sum(" cell " in line for line in lines) == 7)
    expect("a heap nobody allocated from is a WIN against one that was",
           any("cell heap_peak: wz 0 vs pico 9416" in line and line.endswith("WIN") for line in lines))
    expect("stack is summed over the threads: pico's two against wz's one",
           any("cell stack_used: wz 5928 vs pico 5680" in line and line.endswith("LOSS")
               for line in lines))
    table = rows(images, "pico", "run-x")
    expect("the rows are the report's cells, one for one",
           len(table) == sum(" cell " in line for line in lines))
    expect("a row carries its figures, its verdict and its run",
           any(r["metric"] == "heap_peak" and r["image_value"] == 0 and r["verdict"] == "WIN"
               and r["run"] == "run-x" for r in table))
    expect("a turnaround row carries its interval and its boots",
           any(r["metric"] == "turnaround" and len(r["interval"]) == 2 and r["boots"] == [6, 6]
               for r in table))
    expect("a firmware that prints no stack line is said to, not read as zero",
           any("pico: stack not reported" in line for line in lines))
    print(f"  kit-compare selftest: {'PASS' if not fails else f'{fails} FAIL'}")
    return 1 if fails else 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--selftest"]:
        return selftest()
    args = dict(zip(argv[::2], argv[1::2]))
    if "--run" not in args or len(argv) % 2:
        print(__doc__.split("Usage:")[1], file=sys.stderr)
        return 64
    run = pathlib.Path(args["--run"])
    try:
        images = read_run(run, args.get("--node", NODE_DEFAULT))
    except (OSError, ValueError, IndexError, subprocess.CalledProcessError) as error:
        print(f"kit-compare: the run {run} could not be read: {error}", file=sys.stderr)
        return 2
    if not images:
        print(f"kit-compare: the run {run} has no boots", file=sys.stderr)
        return 2
    ref = args.get("--ref", next(iter(images)))
    if ref not in images:
        print(f"kit-compare: the reference {ref} is not an image of the run ({', '.join(images)})",
              file=sys.stderr)
        return 2
    output = args.get("--format", "report")
    if output == "rows":
        print(json.dumps(rows(images, ref, run.name), indent=1))
    elif output == "report":
        for line in report(images, ref):
            print(line)
    else:
        print(f"kit-compare: --format is report or rows, not {output}", file=sys.stderr)
        return 64
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

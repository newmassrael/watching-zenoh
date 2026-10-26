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

Then each image against the reference (`--ref`, the first image by default), by decision D1:

* size is one figure per build: WIN when the image is smaller, LOSS when larger, TIE when equal;
* the turnaround is one median per boot, and the cell is the ratio of the median of the image's
  boot medians to the reference's, with a bootstrap 95% interval over the boots (resampled with
  replacement, seeded, so a run prints the same interval twice). WIN when the whole interval is
  below 1, LOSS when it is above 1, TIE otherwise. A TIE is not a claim either way.

It judges a run and grades nothing: the committed matrix (`deploy/upstream_parity.json`) is where a
verdict becomes a row. Exit 0 when the run was read, 2 when it could not be.

Usage:
    kit_compare.py --run <run dir> [--ref <image>] [--node <ip>]
    kit_compare.py --selftest
"""

from __future__ import annotations

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


@dataclass
class Image:
    key: str
    size: Size | None = None
    stack: tuple[int, int] | None = None
    boot_medians: list[float] = field(default_factory=list)  # milliseconds, one per boot


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
        if image.boot_medians:
            m = image.boot_medians
            out.append(f"kit-compare: {image.key}: turnaround over {len(m)} boot(s): median "
                       f"{statistics.median(m):.3f} ms, boots {min(m):.3f} to {max(m):.3f}")
        else:
            out.append(f"kit-compare: {image.key}: no query/reply pair in any capture")
    ref = images[ref_key]
    for image in images.values():
        if image.key == ref_key:
            continue
        if image.size is not None and ref.size is not None:
            for metric in ("text", "flash", "ram"):
                mine, theirs = getattr(image.size, metric), getattr(ref.size, metric)
                out.append(f"kit-compare: cell {metric}: {image.key} {mine} vs {ref_key} {theirs} "
                           f"({mine / theirs:.3f}) -> {verdict_size(mine, theirs)}")
        if len(image.boot_medians) >= 2 and len(ref.boot_medians) >= 2:
            point, lo, hi = bootstrap_ratio(image.boot_medians, ref.boot_medians)
            out.append(f"kit-compare: cell turnaround: {image.key} vs {ref_key}: ratio {point:.3f} "
                       f"[{lo:.3f}, {hi:.3f}] over {len(image.boot_medians)} and "
                       f"{len(ref.boot_medians)} boots -> {verdict_interval(lo, hi)}")
        else:
            out.append(f"kit-compare: cell turnaround: {image.key} vs {ref_key}: fewer than two boots "
                       f"with pairs on a side, no verdict")
    return out


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
    for line in report(images, ref):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

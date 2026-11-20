#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R4563 (no register item) -- the kit images held under zenoh-pico's, cell by cell, in the run
that built them (docs/upstream-parity.md decision D8).

## What was missing

The committed matrix (`deploy/upstream_parity.json`, decision D6) read the no_std fixed client
and the heap client as WIN against single-threaded zenoh-pico in every cell, by 1,224 bytes of text
and 1,320 of flash. Every gate after it held an image to its OWN committed figure
(`deploy/text_budget.json`, `scripts/lib/text_owner_gate.py`), and a change that grew the image
moved that figure in the same commit. Nothing held an image to pico's, so the text cell went from
WIN to LOSS a row move at a time and no gate said so.

## What is held

For each pair of the matrix (below), both images are built by the kit lane in the same run, as
compare builds, and every cell a build alone decides is judged by decision D1: WIN when the wz
image's figure is smaller, and only WIN passes. TIE and LOSS fail, and the finding says that no
budget move clears it. The cells:

- `text`, `flash` and `ram`: the Berkeley sizes of the linked ELF as `kit_compare.py` reads them
  (flash = text + data, static RAM = data + bss, the kernel heap pool and every stack included).
- `stack_objects`: the bytes of every stack object the image holds (each thread's and the
  interrupt stack), found by type and not by name: a variable of the debug information whose type
  is an array of Zephyr's `struct z_thread_stack_element`, at an address the symbol table holds
  (a stack the link dropped is not in the image). A stack embedded in a structure is a member and
  not a variable, so it is in static RAM and not in this cell: the receive thread of the Ethernet
  driver both images run (`deploy/zephyr-eth-wzmac`) keeps its stack so. The reading is refused
  when it does not find the main thread's stack, which every image has.
- `storage_block`: an image with a kernel heap pool takes its node's storage block from it at
  start, and that block is the floor of its heap peak. Its build states the block as an absolute
  symbol (`wz_storage_block_bytes`, `deploy/zephyr-admin-node/rust/src/fixed_client.rs`); the
  reference's heap peak is a reading of a boot and not of a build, so this one cell holds the block
  under the reference's heap peak in the matrix's run. An image with a heap pool whose build does
  not state its block is refused.

Every figure here is fixed by the build: the toolchain, the Zephyr tree and the paths are the run's
own, so a cell means what it says. The boot readings (stack used, heap peak, turnaround) stay the
matrix's rows, measured on the kit.

## The pairs

The pairs are the (image, reference) rows of the matrix's latest run, read from the file and not
written a second time. The kit lane's Layer Qzk judges the pairs whose image is one of the images
it builds (`scripts/kit-lane.sh images`); a pair of two zenoh-pico arms records which arm is the
reference and is not a wz image under a ceiling.

## The same conditions

Both sides are compare builds (`BUILD_VARIANT=compare`, `deploy/zephyr-common/memory_report.conf`):
the matrix's size cells were read off those builds, so this reads the same cells, and the memory
report's thread and code are in both images alike. A pair where either image was built without
the report (`CONFIG_WZ_MEMORY_REPORT`, an absolute symbol of every Zephyr image's configuration)
is refused, naming the side.

## Modes

`--pairs IMAGE...` prints `<image> <reference>` for each pair of the latest run whose image is
named; `--check IMAGE REFERENCE --image-elf ELF --reference-elf ELF` judges one pair;
`--selftest` drives the readers and the rule on synthetic outputs.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kit_compare import Size, verdict_size  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "deploy" / "upstream_parity.json"

#: The element type of every stack object Zephyr's stack macros define: a thread's or a kernel
#: stack, an array of them, and the stack of a thread defined at build time.
STACK_ELEMENT = "z_thread_stack_element"
#: The main thread's stack, which every Zephyr image has: a reading that does not find it has not
#: read the image's stacks.
MAIN_STACK = "z_main_stack"
#: The absolute symbol the wz client states its storage block with.
STORAGE_BLOCK = "wz_storage_block_bytes"
#: The kernel heap pool and the memory report, as the image's configuration states them.
HEAP_POOL = "CONFIG_HEAP_MEM_POOL_SIZE"
MEMORY_REPORT = "CONFIG_WZ_MEMORY_REPORT"
#: The reference's heap peak in the matrix's run, which the storage block is held under.
HEAP_PEAK_METRIC = "heap_peak"

RAM_KINDS = frozenset("bBdD")
ABSOLUTE_KINDS = frozenset("aA")
#: The debug information entries a stack object's type passes through.
QUALIFIERS = frozenset(("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
                        "DW_TAG_atomic_type"))
KEPT_TAGS = QUALIFIERS | {"DW_TAG_variable", "DW_TAG_array_type", "DW_TAG_structure_type"}

_DIE = re.compile(r"^\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?")
_ATTR = re.compile(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s?(.*)$")
_REF = re.compile(r"<0x([0-9a-f]+)>")
_ADDR = re.compile(r"DW_OP_addr: ([0-9a-f]+)")

NO_BUDGET = ("a budget move cannot clear it: take the bytes back, or the owner decides "
             "(docs/upstream-parity.md D8)")


class Refused(Exception):
    """A pair or a build the gate cannot judge: the reason is the message."""


# ── the matrix ──────────────────────────────────────────────────────────────────────────────────


def latest_run(matrix: dict) -> dict:
    runs = matrix.get("runs") or []
    if not runs:
        raise Refused(f"{MATRIX.relative_to(ROOT)} holds no run")
    return max(runs, key=lambda run: str(run.get("run", "")))


def pairs_of(run: dict) -> list[tuple[str, str]]:
    """The (image, reference) pairs of a run's rows, in the order the rows first name them."""
    seen: list[tuple[str, str]] = []
    for row in run.get("rows", []):
        pair = (row["image"], row["reference"])
        if pair not in seen:
            seen.append(pair)
    return seen


def held_pairs(run: dict, images: Iterable[str]) -> list[tuple[str, str]]:
    names = set(images)
    return [pair for pair in pairs_of(run) if pair[0] in names]


def reference_heap_peak(run: dict, image: str, reference: str) -> int | None:
    for row in run.get("rows", []):
        if (row["image"], row["reference"], row["metric"]) == (image, reference, HEAP_PEAK_METRIC):
            value = row.get("reference_value")
            return None if value is None else int(value)
    return None


# ── the build ───────────────────────────────────────────────────────────────────────────────────


def berkeley(size_output: str) -> Size:
    """`size` of one ELF: its second line's first three columns."""
    lines = size_output.strip().splitlines()
    if len(lines) < 2:
        raise Refused(f"size printed no figures: {size_output.strip()!r}")
    text, data, bss = (int(v) for v in lines[1].split()[:3])
    return Size(text, data, bss)


@dataclass(frozen=True)
class Symbols:
    """What `nm -S` says of an image: its absolute symbols and its sized RAM objects."""

    absolute: dict[str, int]
    ram_at: dict[int, int]  # address -> the largest RAM object there
    ram_named: dict[str, int]  # name -> address


def symbols(nm_output: str) -> Symbols:
    absolute: dict[str, int] = {}
    ram_at: dict[int, int] = {}
    ram_named: dict[str, int] = {}
    for line in nm_output.splitlines():
        parts = line.split()
        try:
            if len(parts) == 3 and parts[1] in ABSOLUTE_KINDS:
                absolute[parts[2]] = int(parts[0], 16)
            elif len(parts) == 4 and parts[2] in ABSOLUTE_KINDS:
                absolute[parts[3]] = int(parts[0], 16)
            elif len(parts) == 4 and parts[2] in RAM_KINDS:
                address, size = int(parts[0], 16), int(parts[1], 16)
                ram_at[address] = max(size, ram_at.get(address, 0))
                ram_named.setdefault(parts[3], address)
        except ValueError:
            continue
    return Symbols(absolute, ram_at, ram_named)


def _name(value: str) -> str:
    """A name attribute as readelf prints it: plain, or after the form that holds it."""
    value = value.strip()
    if value.startswith("(") and "): " in value:
        return value.rsplit("): ", 1)[1].strip()
    return value


def stack_addresses(listing: Iterable[str]) -> set[int]:
    """The addresses of the stack objects in `readelf --debug-dump=info` output: every variable
    with a static address whose type is an array of `STACK_ELEMENT`, through typedefs and
    qualifiers, its type read from its declaration when the definition only points at one."""
    types: dict[int, tuple[str, str | None, int | None]] = {}
    variables: dict[int, dict] = {}
    current: dict | None = None

    def keep(entry: dict | None) -> None:
        if entry is None:
            return
        if entry["tag"] == "DW_TAG_variable":
            variables[entry["offset"]] = entry
        else:
            types[entry["offset"]] = (entry["tag"], entry.get("name"), entry.get("type"))

    for line in listing:
        head = _DIE.match(line)
        if head:
            keep(current)
            tag = head.group(3)
            current = {"offset": int(head.group(2), 16), "tag": tag} if tag in KEPT_TAGS else None
            continue
        if current is None:
            continue
        attr = _ATTR.match(line)
        if attr is None:
            continue
        key, value = attr.groups()
        if key == "DW_AT_name":
            current["name"] = _name(value)
        elif key in ("DW_AT_type", "DW_AT_specification"):
            ref = _REF.search(value)
            if ref:
                current["type" if key == "DW_AT_type" else "spec"] = int(ref.group(1), 16)
        elif key == "DW_AT_location":
            addr = _ADDR.search(value)
            if addr:
                current["addr"] = int(addr.group(1), 16)
    keep(current)

    def strip(ref: int | None) -> int | None:
        seen: set[int] = set()
        while ref is not None and ref in types and types[ref][0] in QUALIFIERS and ref not in seen:
            seen.add(ref)
            ref = types[ref][2]
        return ref

    def is_stack(ref: int | None) -> bool:
        array = types.get(strip(ref))
        if array is None or array[0] != "DW_TAG_array_type":
            return False
        element = types.get(strip(array[2]))
        return element is not None and element[0] == "DW_TAG_structure_type" \
            and element[1] == STACK_ELEMENT

    found: set[int] = set()
    for variable in variables.values():
        if "addr" not in variable:
            continue
        ref = variable.get("type")
        if ref is None and variable.get("spec") in variables:
            ref = variables[variable["spec"]].get("type")
        if is_stack(ref):
            found.add(variable["addr"])
    return found


@dataclass(frozen=True)
class Build:
    """The figures of one image that its build alone decides."""

    key: str
    size: Size
    stack_objects: int
    heap_pool: int
    storage_block: int | None
    memory_report: bool


def read_build(key: str, size_output: str, nm_output: str, addresses: set[int]) -> Build:
    """One image's figures from its `size`, its `nm -S` and the stack objects of its debug
    information (`stack_addresses`)."""
    syms = symbols(nm_output)
    main = syms.ram_named.get(MAIN_STACK)
    if main is None:
        raise Refused(f"{key}: the symbol table has no {MAIN_STACK}: not a Zephyr image as built")
    if main not in addresses:
        raise Refused(f"{key}: the debug information names no stack object at {MAIN_STACK} "
                      f"(0x{main:08x}), so the stacks of the image cannot be read; a build "
                      "without debug information, or a Zephyr whose stack element was renamed")
    return Build(
        key=key,
        size=berkeley(size_output),
        stack_objects=sum(syms.ram_at[a] for a in addresses if a in syms.ram_at),
        heap_pool=syms.absolute.get(HEAP_POOL, 0),
        storage_block=syms.absolute.get(STORAGE_BLOCK),
        memory_report=syms.absolute.get(MEMORY_REPORT, 0) == 1,
    )


# ── the rule ────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Cell:
    metric: str
    mine: int
    theirs: int
    verdict: str
    whence: str  # where the reference's figure is from


def cells(image: Build, reference: Build, run: dict) -> list[Cell]:
    """Every build-decided cell of the pair, or Refused when the two are not built alike."""
    unlike = [b.key for b in (image, reference) if not b.memory_report]
    if unlike:
        raise Refused(f"{image.key} vs {reference.key}: {', '.join(unlike)} built without "
                      f"{MEMORY_REPORT}; the cells are of compare builds on both sides "
                      "(BUILD_VARIANT=compare)")
    same_run = "this run's build"
    out = [Cell(metric, getattr(image.size, metric), getattr(reference.size, metric),
                verdict_size(getattr(image.size, metric), getattr(reference.size, metric)),
                same_run) for metric in ("text", "flash", "ram")]
    out.append(Cell("stack_objects", image.stack_objects, reference.stack_objects,
                    verdict_size(image.stack_objects, reference.stack_objects), same_run))
    if image.heap_pool > 0:
        if image.storage_block is None:
            raise Refused(f"{image.key}: the image has a kernel heap pool of {image.heap_pool} "
                          f"bytes and its build does not state the storage block it takes "
                          f"from it ({STORAGE_BLOCK})")
        peak = reference_heap_peak(run, image.key, reference.key)
        if peak is None:
            raise Refused(f"{image.key} vs {reference.key}: the matrix's run {run.get('run')} "
                          f"has no {HEAP_PEAK_METRIC} row for the pair, which the storage "
                          "block is held under")
        out.append(Cell("storage_block", image.storage_block, peak,
                        verdict_size(image.storage_block, peak),
                        f"the {HEAP_PEAK_METRIC} of run {run.get('run')}"))
    return out


def judge(image: str, reference: str, cell_list: list[Cell]) -> tuple[list[str], list[str]]:
    """The report lines and the findings (empty when every cell is a WIN)."""
    lines: list[str] = []
    findings: list[str] = []
    for c in cell_list:
        diff = c.mine - c.theirs
        lines.append(f"pico-ceiling: {image} vs {reference}: {c.metric} {c.mine} against "
                     f"{c.theirs} ({diff:+d} bytes, {c.whence}) -> {c.verdict}")
        if c.verdict != "WIN":
            findings.append(f"{image} vs {reference}: {c.metric} is {c.mine} bytes against "
                            f"{c.theirs} ({diff:+d}, {c.whence}), a {c.verdict}; only a WIN "
                            f"passes (D1), and {NO_BUDGET}")
    return lines, findings


# ── the tools ───────────────────────────────────────────────────────────────────────────────────


def tool(names: tuple[str, ...], given: str | None) -> str:
    if given:
        return given
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    raise Refused(f"none of {', '.join(names)} is on PATH")


def build_of(key: str, elf: str, nm: str, size: str, readelf: str) -> Build:
    size_out = subprocess.run([size, elf], check=True, capture_output=True, text=True).stdout
    nm_out = subprocess.run([nm, "-S", elf], check=True, capture_output=True, text=True).stdout
    # The listing is tens of megabytes: it is read as it is written, and read to its end before
    # anything else is judged, so the dump is never left blocked on a full pipe.
    with subprocess.Popen([readelf, "--debug-dump=info", elf], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True, errors="replace") as dump:
        assert dump.stdout is not None
        addresses = stack_addresses(dump.stdout)
    if dump.returncode != 0:
        raise Refused(f"{key}: {readelf} --debug-dump=info {elf} ended {dump.returncode}")
    return read_build(key, size_out, nm_out, addresses)


def load_matrix() -> dict:
    return json.loads(MATRIX.read_text(encoding="utf-8"))


def check(image: str, reference: str, image_elf: str, reference_elf: str,
          nm_arg: str | None, size_arg: str | None, readelf_arg: str | None) -> int:
    try:
        run = latest_run(load_matrix())
        if (image, reference) not in pairs_of(run):
            raise Refused(f"{image} vs {reference} is not a pair of the matrix's run "
                          f"{run.get('run')} ({MATRIX.relative_to(ROOT)})")
        nm = tool(("arm-none-eabi-nm", "nm"), nm_arg)
        size = tool(("arm-none-eabi-size", "size"), size_arg)
        readelf = tool(("arm-none-eabi-readelf", "readelf"), readelf_arg)
        mine = build_of(image, image_elf, nm, size, readelf)
        theirs = build_of(reference, reference_elf, nm, size, readelf)
        lines, findings = judge(image, reference, cells(mine, theirs, run))
    except (Refused, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"pico-ceiling: FAIL {error}")
        return 1
    for line in lines:
        print(line)
    for finding in findings:
        print(f"pico-ceiling: FAIL {finding}")
    if findings:
        return 1
    print(f"pico-ceiling: OK {image} under {reference} in all {len(lines)} cells")
    return 0


def pairs_mode(images: list[str]) -> int:
    try:
        run = latest_run(load_matrix())
    except (Refused, OSError, ValueError) as error:
        print(f"pico-ceiling: FAIL {error}", file=sys.stderr)
        return 1
    held = held_pairs(run, images)
    if not held:
        print(f"pico-ceiling: FAIL the matrix's run {run.get('run')} pairs none of "
              f"{', '.join(images) or 'no image'} with a reference: a ceiling with no "
              "population is not a pass", file=sys.stderr)
        return 1
    for image, reference in held:
        print(f"{image} {reference}")
    return 0


# ── selftest ────────────────────────────────────────────────────────────────────────────────────

_LISTING = """\
 <0><b>: Abbrev Number: 1 (DW_TAG_compile_unit)
    <c>   DW_AT_name        : (indirect line string, offset: 0x0): kernel/init.c
 <1><a0>: Abbrev Number: 10 (DW_TAG_structure_type)
    <a1>   DW_AT_name        : (indirect string, offset: 0x10): z_thread_stack_element
    <a5>   DW_AT_declaration : 1
 <1><a8>: Abbrev Number: 11 (DW_TAG_typedef)
    <a9>   DW_AT_name        : (indirect string, offset: 0x18): k_thread_stack_t
    <ad>   DW_AT_type        : <0xa0>
 <1><b0>: Abbrev Number: 12 (DW_TAG_array_type)
    <b1>   DW_AT_type        : <0xa0>
 <2><b5>: Abbrev Number: 14 (DW_TAG_subrange_type)
    <b6>   DW_AT_type        : <0x30>
    <ba>   DW_AT_upper_bound : 4799
 <2><bc>: Abbrev Number: 0
 <1><c0>: Abbrev Number: 13 (DW_TAG_variable)
    <c1>   DW_AT_name        : (indirect string, offset: 0x20): z_main_stack
    <c5>   DW_AT_type        : <0xb0>
    <c9>   DW_AT_location    : 5 byte block: 3 0 10 1 28 \t(DW_OP_addr: 28011000)
 <1><d0>: Abbrev Number: 12 (DW_TAG_array_type)
    <d1>   DW_AT_type        : <0xa8>
 <1><d8>: Abbrev Number: 15 (DW_TAG_volatile_type)
    <d9>   DW_AT_type        : <0xd0>
 <1><e0>: Abbrev Number: 16 (DW_TAG_variable)
    <e1>   DW_AT_name        : rx_stack
    <e5>   DW_AT_type        : <0xd8>
    <e7>   DW_AT_declaration : 1
 <1><f0>: Abbrev Number: 17 (DW_TAG_variable)
    <f1>   DW_AT_specification: <0xe0>
    <f5>   DW_AT_location    : 5 byte block: 3 0 20 1 28 \t(DW_OP_addr: 28012000)
 <1><100>: Abbrev Number: 13 (DW_TAG_variable)
    <101>   DW_AT_name        : (indirect string, offset: 0x30): dropped_stack
    <105>   DW_AT_type        : <0xb0>
    <109>   DW_AT_location    : 5 byte block: 3 0 0 0 0 \t(DW_OP_addr: 0)
 <1><110>: Abbrev Number: 18 (DW_TAG_base_type)
    <111>   DW_AT_name        : char
 <1><118>: Abbrev Number: 12 (DW_TAG_array_type)
    <119>   DW_AT_type        : <0x110>
 <1><120>: Abbrev Number: 13 (DW_TAG_variable)
    <121>   DW_AT_name        : (indirect string, offset: 0x40): net_buf_data
    <125>   DW_AT_type        : <0x118>
    <129>   DW_AT_location    : 5 byte block: 3 0 30 1 28 \t(DW_OP_addr: 28013000)
"""


def _nm(main: int, rx: int, pool: int, block: int | None, report: bool) -> str:
    lines = [
        f"28011000 {main:08x} B z_main_stack",
        f"28012000 {rx:08x} B rx_stack",
        "28013000 00001200 b net_buf_data",
        "28014000 00002c4c B kheap__system_heap",
        "100824a8 00000034 T wz_stack_usage",
        f"{pool:08x} A {HEAP_POOL}",
    ]
    if block is not None:
        lines.append(f"{block:08x} A {STORAGE_BLOCK}")
    if report:
        lines.append(f"00000001 A {MEMORY_REPORT}")
    return "\n".join(lines)


def _size(text: int, data: int, bss: int) -> str:
    return ("   text\t   data\t    bss\t    dec\t    hex\tfilename\n"
            f" {text}\t {data}\t {bss}\t {text + data + bss}\t 0\tzephyr.elf\n")


def selftest() -> int:
    failures: list[str] = []

    def expect(what: str, got, want) -> None:
        if got != want:
            failures.append(f"{what}: got {got!r}, wanted {want!r}")

    def refused(what: str, call) -> str:
        try:
            call()
        except Refused as error:
            return str(error)
        failures.append(f"{what}: not refused")
        return ""

    stacks = stack_addresses(_LISTING.splitlines())
    expect("stack objects are found by type, through a typedef, a qualifier and a declaration",
           stacks, {0x28011000, 0x28012000, 0})
    expect("a name after its string form", _name("(indirect string, offset: 0x10): z_main_stack"),
           "z_main_stack")

    run = {"run": "20261031T063515", "rows": [
        {"image": "pico-mt", "reference": "pico-st", "metric": "text", "reference_value": 100},
        {"image": "wz-heap", "reference": "pico-st", "metric": "text", "reference_value": 100},
        {"image": "wz-heap", "reference": "pico-st", "metric": "heap_peak", "reference_value": 9280},
        {"image": "wz-fixed", "reference": "pico-st", "metric": "text", "reference_value": 100},
    ]}
    older = {"run": "20261020T000000", "rows": [
        {"image": "wz-old", "reference": "pico-st", "metric": "text", "reference_value": 1}]}
    expect("the latest run is the one read", latest_run({"runs": [run, older]})["run"], run["run"])
    expect("the pairs are read once each, in the rows' order", pairs_of(run),
           [("pico-mt", "pico-st"), ("wz-heap", "pico-st"), ("wz-fixed", "pico-st")])
    expect("only the pairs of the lane's images are held",
           held_pairs(run, ["wz-fixed", "wz-heap", "wz-get"]),
           [("wz-heap", "pico-st"), ("wz-fixed", "pico-st")])
    expect("a lane with no image in the matrix holds nothing", held_pairs(run, ["wz-get"]), [])

    pico = read_build("pico-st", _size(144844, 1620, 113696), _nm(0x2040, 0x640, 13312, None, True),
                      stacks)
    expect("the reference's stack objects are its main and network stacks", pico.stack_objects,
           0x2040 + 0x640)
    expect("a build with no heap symbol of its own has no storage block", pico.storage_block, None)

    def wz(text: int, main: int = 0x1280, block: int | None = 8384, pool: int = 11264,
           report: bool = True, key: str = "wz-heap") -> Build:
        return read_build(key, _size(text, 1524, 104000), _nm(main, 0x640, pool, block, report),
                          stacks)

    win = cells(wz(143620), pico, run)
    expect("the cells of a heap image", [c.metric for c in win],
           ["text", "flash", "ram", "stack_objects", "storage_block"])
    expect("a smaller image wins every cell", {c.verdict for c in win}, {"WIN"})
    lines, findings = judge("wz-heap", "pico-st", win)
    expect("a pair of WINs has no finding", findings, [])
    expect("each cell is a line", len(lines), 5)
    expect("the storage block is held under the matrix's heap peak",
           [c.theirs for c in win if c.metric == "storage_block"], [9280])

    tie = cells(wz(144844), pico, run)
    _, findings = judge("wz-heap", "pico-st", tie)
    expect("an equal text is a TIE and fails", [c.verdict for c in tie if c.metric == "text"],
           ["TIE"])
    expect("a TIE's finding says no budget clears it",
           any("text is 144844" in f and "TIE" in f and "cannot clear" in f for f in findings), True)

    loss = cells(wz(155796, main=0x2100), pico, run)
    _, findings = judge("wz-heap", "pico-st", loss)
    expect("a larger text, flash and stack are three LOSS findings",
           sorted(f.split(": ")[1].split(" is ")[0] for f in findings),
           ["flash", "stack_objects", "text"])
    expect("a finding carries both figures and the difference",
           any("155796 bytes against 144844 (+10952" in f for f in findings), True)

    fixed = cells(wz(143620, block=None, pool=0, key="wz-fixed"), pico, run)
    expect("an image with no heap pool has no storage block cell",
           "storage_block" in [c.metric for c in fixed], False)

    big = cells(wz(143620, block=9280), pico, run)
    expect("a block as large as the reference's peak is a TIE",
           [c.verdict for c in big if c.metric == "storage_block"], ["TIE"])

    reason = refused("a heap image that does not state its block",
                     lambda: cells(wz(143620, block=None), pico, run))
    expect("the refusal names the symbol", STORAGE_BLOCK in reason, True)
    reason = refused("a reference built without the memory report", lambda: cells(
        wz(143620), read_build("pico-st", _size(1, 1, 1), _nm(0x2040, 0x640, 0, None, False),
                               stacks), run))
    expect("the refusal names the side without the report", reason.startswith(
        "wz-heap vs pico-st: pico-st built without"), True)
    reason = refused("an image built without the memory report",
                     lambda: cells(wz(143620, report=False), pico, run))
    expect("the refusal names the image's side", "wz-heap built without" in reason, True)
    reason = refused("a pair with no heap peak row", lambda: cells(
        wz(143620), pico, {"run": "x", "rows": [
            {"image": "wz-heap", "reference": "pico-st", "metric": "text"}]}))
    expect("the refusal names the missing row", HEAP_PEAK_METRIC in reason, True)
    reason = refused("a listing with no stack type", lambda: read_build(
        "wz-heap", _size(1, 1, 1), _nm(0x1280, 0x640, 0, None, True), set()))
    expect("the refusal names the main stack", MAIN_STACK in reason, True)
    refused("a symbol table with no main stack",
            lambda: read_build("x", _size(1, 1, 1), "00000001 A CONFIG_X", stacks))
    refused("a matrix with no run", lambda: latest_run({"runs": []}))
    refused("size with no figures", lambda: berkeley("text data bss"))

    if failures:
        for failure in failures:
            print(f"pico-ceiling: selftest FAIL -- {failure}")
        return 1
    print("pico-ceiling: selftest OK -- reads the pairs of the latest run and holds only the "
          "lane's images, finds stack objects by type through typedefs, qualifiers and "
          "declarations, judges WIN, TIE and LOSS cell by cell with both figures, holds a heap "
          "image's storage block under the reference's heap peak, and refuses a build without "
          "the memory report on either side, a heap image with no block, a pair with no heap "
          "peak and a reading with no main stack")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pairs", nargs="*", metavar="IMAGE",
                      help="print the pairs of the latest run whose image is named")
    mode.add_argument("--check", nargs=2, metavar=("IMAGE", "REFERENCE"), help="judge one pair")
    mode.add_argument("--selftest", action="store_true", help="drive the readers and the rule")
    parser.add_argument("--image-elf", help="the wz image's ELF, built as a compare build")
    parser.add_argument("--reference-elf", help="the reference's ELF, built as a compare build")
    parser.add_argument("--nm", help="the nm of the toolchain that linked the ELFs")
    parser.add_argument("--size", help="the size of the toolchain that linked the ELFs")
    parser.add_argument("--readelf", help="a GNU readelf (it reads the debug information)")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.pairs is not None:
        return pairs_mode(args.pairs)
    if not args.image_elf or not args.reference_elf:
        parser.error("--check needs --image-elf and --reference-elf")
    return check(args.check[0], args.check[1], args.image_elf, args.reference_elf,
                 args.nm, args.size, args.readelf)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R4580 (no register item) -- what a kit image's size moved by between two trees, read from the
two ELFs one run built.

## Why it exists

A kit image that grew (a text gate refusal, a pico ceiling cell gone from WIN, a static RAM that
no longer fits) is attributed by building it before and after the change and comparing the two
builds. Two builds compare only when they share a toolchain, a Zephyr workspace and the paths the
debug information and the link see, so sessions ran Layer Qzk once per tree with `bx --host` pinning
both runs to one build machine. The pin was chosen from memory, went stale, and one pinned run
waited 50 minutes for its machine. `scripts/kit-size-delta.sh` builds both trees in ONE run, so the
two ELFs are of one machine by construction and the run needs no `--host`; this module reads the
pair it leaves.

## What it prints

For one image, first the cells the pico ceiling gate judges (`pico_ceiling_gate.py`, read by its own
`build_of`), base, head and the delta:

- `text`, `flash` and `ram`: the Berkeley sizes (flash = text + data, static RAM = data + bss);
- `stack_objects`: the bytes of every stack object the image holds, found by type;
- `storage_block`: the block a heap client states it takes from the kernel heap, on the side
  that states one (an image with no heap client has no row).

Then the owners of code and read-only data whose bytes moved (`text_owner_gate.py`'s reading),
and the symbols that changed, largest movers first, in two families: code and read-only data (what
the text and flash cells count) and data and bss (what the static RAM cell counts). The symbol
diff is `footprint_attribution.py`'s: names matched with their hashes stripped, instance counts on
both sides, and a growth that vanished symbols explain tagged ABSORBED with their names.

When the base tree does not build the image (an image the change added), the base column is `-`
with the reason the caller gives, and there is no symbol diff.

It grades nothing: a growth is a finding to read, not a failure. Exit 0 when the ELFs were read,
2 when they could not be (a file that is not there, a tool that does not run, an image whose debug
information names no main stack) or the arguments are wrong.

## Modes

`--image KEY --head-elf ELF (--base-elf ELF | --base-absent REASON)` reads one pair;
`--selftest` drives the report on synthetic builds and symbol tables.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from footprint_attribution import attribute, parse_nm, total  # noqa: E402
from kit_compare import Size  # noqa: E402
from pico_ceiling_gate import Build, Refused, build_of, tool  # noqa: E402
from text_owner_gate import owners  # noqa: E402

PREFIX = "kit-size-delta"
#: The cells, in the order the ceiling gate judges them.
CELLS = ("text", "flash", "ram", "stack_objects", "storage_block")
#: The nm kinds of what the text and flash cells count (code and read-only data, as the text gate
#: reads them) and of what the static RAM cell counts.
FLASH_KINDS = frozenset("tTwWrRvV")
RAM_KINDS = frozenset("dDbB")
SYMBOLS_DEFAULT = 40


@dataclass(frozen=True)
class Side:
    """One tree's build of the image: its figures and its `nm -S -C` listing."""

    build: Build
    listing: str


def figures(build: Build | None) -> dict[str, int | None]:
    if build is None:
        return {cell: None for cell in CELLS}
    return {
        "text": build.size.text,
        "flash": build.size.flash,
        "ram": build.size.ram,
        "stack_objects": build.stack_objects,
        "storage_block": build.storage_block,
    }


def _figure(value: int | None) -> str:
    return "-" if value is None else str(value)


def _delta(base: int | None, head: int | None) -> str:
    return "-" if base is None or head is None else f"{head - base:+d}"


def cell_lines(key: str, base: Build | None, head: Build) -> list[str]:
    theirs, mine = figures(base), figures(head)
    out = [f"{PREFIX}: {key}: {'cell':<14} {'base':>9} {'head':>9} {'delta':>9}"]
    for cell in CELLS:
        if theirs[cell] is None and mine[cell] is None:
            # Only the storage block can be absent from a build that was read: no heap client.
            continue
        out.append(f"{PREFIX}: {key}: {cell:<14} {_figure(theirs[cell]):>9} "
                   f"{_figure(mine[cell]):>9} {_delta(theirs[cell], mine[cell]):>9}")
    return out


def family(listing: str, kinds: frozenset[str]) -> str:
    """The lines of an `nm -S -C` listing whose symbol kind is one of `kinds`; a line with no
    size (an undefined or an absolute symbol) carries no bytes and is left out."""
    keep = []
    for line in listing.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[2] in kinds:
            keep.append(line)
    return "\n".join(keep)


def owner_lines(key: str, base_listing: str, head_listing: str) -> list[str]:
    old, new = owners(base_listing), owners(head_listing)
    moved = sorted(((name, old.get(name, 0), new.get(name, 0)) for name in set(old) | set(new)
                    if old.get(name, 0) != new.get(name, 0)),
                   key=lambda row: (-abs(row[2] - row[1]), row[0]))
    out = [f"{PREFIX}: {key}: owners of code and read-only data whose bytes moved: {len(moved)}"]
    for name, before, after in moved:
        out.append(f"{after - before:+8d} {before:8d} {after:8d}  {name}")
    return out


def symbol_lines(key: str, label: str, base_listing: str, head_listing: str,
                 limit: int) -> list[str]:
    old, new = parse_nm(base_listing, True), parse_nm(head_listing, True)
    (old_bytes, old_count), (new_bytes, new_count) = total(old, None), total(new, None)
    out = [f"{PREFIX}: {key}: {label}: {old_bytes} -> {new_bytes} B "
           f"({new_bytes - old_bytes:+d}), {old_count} -> {new_count} symbol(s)"]
    rows = attribute(old, new)
    if not rows:
        out.append(f"{PREFIX}: {key}: {label}: no symbol changed")
        return out
    out.append(f"{'delta':>8} {'base':>8} {'head':>8} {'inst':>7}  tag / symbol")
    for row in rows[:limit]:
        out.append(f"{row.delta:+8d} {row.old:8d} {row.new:8d} "
                   f"{row.old_count:>3}->{row.new_count:<3} {row.tag}  {row.name}")
        if row.absorbed:
            out.append(f"{'':36}<- " + ", ".join(f"{name} ({size} B)"
                                                for name, size in row.absorbed))
    rest = rows[limit:]
    if rest:
        out.append(f"{PREFIX}: {key}: {label}: {len(rest)} more changed symbol(s), "
                   f"{sum(row.delta for row in rest):+d} B between them (--symbols prints more)")
    return out


def report(key: str, base: Side | None, head: Side, limit: int, base_rev: str, head_rev: str,
           base_absent: str) -> list[str]:
    out = [f"{PREFIX}: {key}: base {base_rev}, head {head_rev}"]
    out += cell_lines(key, base.build if base is not None else None, head.build)
    if base is None:
        out.append(f"{PREFIX}: {key}: no base build: {base_absent}")
        return out
    out += owner_lines(key, base.listing, head.listing)
    out += symbol_lines(key, "code and read-only data", family(base.listing, FLASH_KINDS),
                        family(head.listing, FLASH_KINDS), limit)
    out += symbol_lines(key, "data and bss", family(base.listing, RAM_KINDS),
                        family(head.listing, RAM_KINDS), limit)
    return out


def side(key: str, elf: str, nm: str, size: str, readelf: str) -> Side:
    if not Path(elf).is_file():
        raise Refused(f"{key}: {elf} is not a file")
    listing = subprocess.run([nm, "-S", "-C", elf], check=True, capture_output=True,
                             text=True).stdout
    return Side(build_of(key, elf, nm, size, readelf), listing)


# ── selftest ────────────────────────────────────────────────────────────────────────────────────

_BASE_NM = """\
10000100 00000200 T wz_session_core::drive::step::h0123456789abcdef
10000300 000000d4 t wz_session_core::drive::check::h1111111111111111
10000400 00000040 T z_impl_k_sleep
10000500 00000080 R wz_codecs::TABLE::h2222222222222222
10000600 00000080 r old_rodata
28000000 00001000 B z_main_stack
28001000 00000100 D wz_config_block
         U undefined_thing
00000001 A CONFIG_WZ_MEMORY_REPORT
"""
_HEAD_NM = """\
10000100 000002d8 T wz_session_core::drive::step::haaaaaaaaaaaaaaaa
10000400 00000040 T z_impl_k_sleep
10000500 000000a0 R wz_codecs::TABLE::hbbbbbbbbbbbbbbbb
10000700 00000030 T wz_codecs::new_fn::hcccccccccccccccc
28000000 00001200 B z_main_stack
28001000 00000100 D wz_config_block
28002000 00000020 b new_counter
00000001 A CONFIG_WZ_MEMORY_REPORT
"""


def _build(text: int, data: int, bss: int, stacks: int, block: int | None) -> Build:
    return Build(key="k", size=Size(text, data, bss), stack_objects=stacks,
                 heap_pool=11264 if block is not None else 0, storage_block=block,
                 memory_report=True)


def selftest() -> int:
    failures: list[str] = []

    def expect(what: str, got, want) -> None:
        if got != want:
            failures.append(f"{what}: got {got!r}, wanted {want!r}")

    base = _build(143620, 1524, 104000, 4736, 8384)
    head = _build(144100, 1524, 104512, 5248, 8384)
    lines = cell_lines("k", base, head)
    cells = {line.split()[2]: line.split()[3:] for line in lines[1:]}
    expect("every cell is a row, in the ceiling gate's order", list(cells), list(CELLS))
    expect("text: base, head and the delta", cells["text"], ["143620", "144100", "+480"])
    expect("flash is text and data", cells["flash"], ["145144", "145624", "+480"])
    expect("static RAM is data and bss", cells["ram"], ["105524", "106036", "+512"])
    expect("an unchanged figure reads +0", cells["storage_block"], ["8384", "8384", "+0"])

    fixed = cell_lines("k", _build(1, 1, 1, 1, None), _build(2, 1, 1, 1, None))
    expect("no heap client on either side: no storage block row",
           any(" storage_block " in line for line in fixed), False)
    added = cell_lines("k", _build(1, 1, 1, 1, None), _build(2, 1, 1, 1, 8384))
    expect("a block only the head states: the base column is '-' and so is the delta",
           [line.split()[3:] for line in added if " storage_block " in line],
           [["-", "8384", "-"]])
    alone = cell_lines("k", None, head)
    expect("no base build: every base figure and delta is '-'",
           [line.split()[3:] for line in alone[1:] if " text " in line], [["-", "144100", "-"]])

    flash = family(_BASE_NM, FLASH_KINDS)
    expect("code and read-only data, local and global, are the flash family",
           [line.split()[2] for line in flash.splitlines()], ["T", "t", "T", "R", "r"])
    expect("data and bss are the RAM family",
           [line.split()[2] for line in family(_BASE_NM, RAM_KINDS).splitlines()], ["B", "D"])
    expect("an undefined and an absolute symbol are in neither",
           any("undefined_thing" in s or "CONFIG_" in s
               for s in (flash, family(_BASE_NM, RAM_KINDS))), False)

    rows = symbol_lines("k", "code", family(_BASE_NM, FLASH_KINDS),
                        family(_HEAD_NM, FLASH_KINDS), SYMBOLS_DEFAULT)
    expect("the family total is both sides' bytes and symbols", rows[0],
           "kit-size-delta: k: code: 1044 -> 1000 B (-44), 5 -> 4 symbol(s)")
    table = [line for line in rows[2:] if not line.startswith(" " * 36)]
    names = [line.split()[-1] for line in table]
    expect("the largest mover first, then by size of the move",
           names, ["wz_session_core::drive::step", "wz_session_core::drive::check",
                   "old_rodata", "wz_codecs::new_fn", "wz_codecs::TABLE"])
    expect("a growth the vanished callee explains is ABSORBED and names it",
           [line.split()[4] for line in table if line.endswith("drive::step")], ["ABSORBED"])
    expect("the absorbed callee is named under its absorber",
           any(line.strip() == "<- wz_session_core::drive::check (212 B)" for line in rows), True)
    expect("a symbol matched across builds despite its hash, with both sizes",
           [line.split()[:3] for line in table if line.endswith("drive::step")],
           [["+216", "512", "728"]])
    expect("a symbol only the head has is NEW",
           any(line.split()[4] == "NEW" and line.endswith("new_fn") for line in table), True)
    expect("a symbol only the base has is VANISHED",
           any(line.split()[4] == "VANISHED" and line.endswith("old_rodata") for line in table),
           True)
    expect("an unchanged symbol is not a row", any("k_sleep" in line for line in rows), False)

    capped = symbol_lines("k", "code", family(_BASE_NM, FLASH_KINDS),
                          family(_HEAD_NM, FLASH_KINDS), 2)
    expect("past the limit the rest is one line with its count and its bytes", capped[-1],
           "kit-size-delta: k: code: 3 more changed symbol(s), -48 B between them "
           "(--symbols prints more)")
    same = symbol_lines("k", "data", family(_BASE_NM, RAM_KINDS), family(_BASE_NM, RAM_KINDS), 5)
    expect("two equal tables say no symbol changed", same[-1],
           "kit-size-delta: k: data: no symbol changed")
    ram = symbol_lines("k", "data", family(_BASE_NM, RAM_KINDS), family(_HEAD_NM, RAM_KINDS), 5)
    expect("a grown stack and a new counter are the RAM family's movers",
           [line.split()[-1] for line in ram[2:]], ["z_main_stack", "new_counter"])

    moved = owner_lines("k", _BASE_NM, _HEAD_NM)
    expect("the owners that moved, largest first",
           [line.split()[-1] for line in moved[1:]], ["c:old", "wz_codecs", "wz_session_core"])
    expect("an owner's delta, base and head", moved[2].split()[:3], ["+80", "128", "208"])
    expect("an owner the head no longer has reads 0 there", moved[1].split()[:3],
           ["-128", "128", "0"])

    whole = report("k", Side(base, _BASE_NM), Side(head, _HEAD_NM), 5, "origin/main 5b0779b24",
                   "abc plus its uncommitted changes", "")
    expect("the report names both revisions first", whole[0],
           "kit-size-delta: k: base origin/main 5b0779b24, head abc plus its uncommitted changes")
    expect("the report holds the cells, the owners and both symbol families",
           [any(marker in line for line in whole) for marker in
            (" text ", "owners of code", ": code and read-only data: ", ": data and bss: ")],
           [True, True, True, True])
    lone = report("k", None, Side(head, _HEAD_NM), 5, "origin/main", "abc", "not in its images")
    expect("with no base build the reason is said and nothing is diffed", lone[-1],
           "kit-size-delta: k: no base build: not in its images")
    expect("with no base build there is no symbol table",
           any(": code and read-only data: " in line for line in lone), False)

    def exit_of(argv: list[str]) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            try:
                code = main(argv)
            except SystemExit as stop:
                code = int(stop.code or 0)
        return code, err.getvalue()

    tools = ["--nm", "nm", "--size", "size", "--readelf", "readelf"]
    code, said = exit_of(["--image", "k", "--head-elf", "/nonexistent/zephyr.elf",
                          "--base-absent", "x", *tools])
    expect("an ELF that is not there is refused with 2", code, 2)
    expect("the refusal names the file", "/nonexistent/zephyr.elf is not a file" in said, True)
    code, _ = exit_of(["--image", "k", "--head-elf", "h.elf", *tools])
    expect("neither a base ELF nor the reason there is none is refused", code, 2)
    code, _ = exit_of(["--head-elf", "h.elf", "--base-elf", "b.elf", *tools])
    expect("no image key is refused", code, 2)
    code, _ = exit_of(["--image", "k", "--head-elf", "h.elf", "--base-elf", "b.elf",
                       "--symbols", "0", *tools])
    expect("a symbol count under one is refused", code, 2)

    if failures:
        for failure in failures:
            print(f"{PREFIX}: selftest FAIL -- {failure}")
        return 1
    print(f"{PREFIX}: selftest OK -- prints the ceiling gate's cells for base, head and the "
          "delta, leaves out a storage block neither side states and marks a figure one side "
          "lacks, splits the symbol table into code and data families, diffs each largest "
          "mover first with a count of the rest, ranks the owners that moved, says why there "
          "is no base, and refuses a missing ELF, a missing base reason, a missing key and a "
          "symbol count under one")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--selftest", action="store_true", help="drive the report on fixtures")
    parser.add_argument("--image", help="the image key the ELFs are builds of")
    parser.add_argument("--head-elf", help="the image as this tree builds it")
    parser.add_argument("--base-elf", help="the image as the base tree builds it")
    parser.add_argument("--base-absent", help="why there is no base ELF, said in its place")
    parser.add_argument("--base-rev", default="(not named)", help="the base, as the report says it")
    parser.add_argument("--head-rev", default="(not named)", help="the head, as the report says it")
    parser.add_argument("--symbols", type=int, default=SYMBOLS_DEFAULT,
                        help="changed symbols printed per family, largest movers first")
    parser.add_argument("--nm", help="the nm of the toolchain that linked the ELFs")
    parser.add_argument("--size", help="the size of the toolchain that linked the ELFs")
    parser.add_argument("--readelf", help="a GNU readelf (it reads the debug information)")
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.image or not args.head_elf:
        parser.error("--image and --head-elf are required")
    if args.base_elf is None and not args.base_absent:
        parser.error("--base-elf, or --base-absent saying why the base has none")
    if args.symbols < 1:
        parser.error("--symbols is a count of one or more")
    try:
        nm = tool(("arm-none-eabi-nm", "nm"), args.nm)
        size = tool(("arm-none-eabi-size", "size"), args.size)
        readelf = tool(("arm-none-eabi-readelf", "readelf"), args.readelf)
        head = side(args.image, args.head_elf, nm, size, readelf)
        base = side(args.image, args.base_elf, nm, size, readelf) if args.base_elf else None
    except (Refused, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"{PREFIX}: {args.image}: the ELFs could not be read: {error}", file=sys.stderr)
        return 2
    for line in report(args.image, base, head, args.symbols, args.base_rev, args.head_rev,
                       args.base_absent or ""):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

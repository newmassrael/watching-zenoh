#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4502 (no register item) -- attribute a footprint change between two builds
by SIZE as well as by delta, and say which growth is inlining.

The item this answers, open-debt item 427, lives in the agent-memory half of
the register, which has no store id for `gate_provenance_lint.py` to resolve;
it is named in prose instead.

## The defect

Footprint changes in this tree are attributed by a per-symbol `nm -S` diff
written into a comment by hand (scripts/check-footprint.sh holds a dozen). A
delta alone cannot tell "this function grew" from "this function absorbed its
callees": when the optimiser inlines `check_eventless_transitions` and
`process_internal_queue` into `run_main_event_loop`, the two callees vanish as
symbols and the loop grows by about their size, and a delta table reads that as
the loop's own cost. An attribution made that way was refuted from its own nm
output, where the two callees were already missing. The opposite error rides
along: the same symbol grew 528 B over a range where the whole engine grew
346 B, because other symbols shrank, so the symbol's delta over-states the
change as well as mis-placing it. And a report claimed five instantiations of
a symbol the binary held three of, because nobody counted.

## What this prints

For two revisions -- each an ELF, read with `nm --print-size -C` (the nm of the
target's toolchain via `--nm`), or a file already holding that listing --
matched by demangled name with the rustc hash and crate disambiguators
stripped:

* the TOTAL of the section family read (text symbols unless `--all-sections`)
  and of every `--scope` regex given: old, new, delta. Attribution is made
  against an enclosing scope's total, never a single symbol's delta, and a
  symbol whose delta exceeds its scope's is called out as over-stated;
* each changed symbol with its old and new SIZE, its delta and its INSTANCE
  count in each revision, so "N instances grew" is checked against the binary;
* a grown symbol whose growth is matched, within a tolerance, by the summed
  sizes of symbols that VANISHED is tagged ABSORBED and names them; the rest
  is GREW. Each vanished symbol is given to at most one absorber, the largest
  growth first. A match is evidence of inlining, not proof: a vanished
  function can also have been deleted while an unrelated one grew by a
  similar amount, which is why the candidates are named for a reader to check.

It grades nothing and exits 0 on any pair it can read; its `--selftest` drives
the matcher over fixtures and Layer C0 runs that.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field

#: Symbol types read by default: text, strong and weak.
TEXT_TYPES = frozenset("tTwW")

#: Hash and disambiguator spellings that differ between two builds of the same
#: function: the legacy mangling's `::h<16 hex>`, v0's `[<hex>]` crate
#: disambiguator, and LLVM's `.llvm.<n>` local-symbol suffix.
_HASH = re.compile(r"::h[0-9a-f]{16}$")
_DISAMBIGUATOR = re.compile(r"\[[0-9a-f]{4,}\]")
_LLVM_SUFFIX = re.compile(r"\.llvm\.\d+$")


def stable_name(name: str) -> str:
    """The name a symbol keeps across two builds of the same source."""
    name = _LLVM_SUFFIX.sub("", name)
    name = _HASH.sub("", name)
    return _DISAMBIGUATOR.sub("", name)


def parse_nm(text: str, all_sections: bool) -> dict[str, list[int]]:
    """`{stable name: [size of each instance]}` from `nm --print-size` output.

    A line without a size (an undefined or absolute symbol) carries no bytes and
    is skipped; a demangled name may hold spaces, so it is the rest of the
    line."""
    out: dict[str, list[int]] = {}
    for line in text.splitlines():
        parts = line.split(None, 3)
        if len(parts) != 4:
            continue
        _, size, kind, name = parts
        if len(kind) != 1 or (not all_sections and kind not in TEXT_TYPES):
            continue
        try:
            n = int(size, 16)
        except ValueError:
            continue
        out.setdefault(stable_name(name.strip()), []).append(n)
    return out


@dataclass
class Row:
    name: str
    old: int
    new: int
    old_count: int
    new_count: int
    tag: str = ""
    absorbed: list[tuple[str, int]] = field(default_factory=list)

    @property
    def delta(self) -> int:
        return self.new - self.old


def subset_matching(items: list[tuple[str, int]], low: int, high: int) -> list[int] | None:
    """Indices of a subset of `items` whose sizes sum into `[low, high]`, or None.

    A dynamic programme over reachable sums, items taken largest first, so the
    subset found tends to be the one with the fewest members."""
    if high < 0:
        return None
    order = sorted(range(len(items)), key=lambda i: -items[i][1])
    reach: dict[int, tuple[int, ...]] = {0: ()}
    for i in order:
        size = items[i][1]
        if size <= 0:
            continue
        for total, members in list(reach.items()):
            nxt = total + size
            if nxt <= high and nxt not in reach:
                reach[nxt] = members + (i,)
        for total in sorted(reach):
            if low <= total <= high and total > 0:
                return list(reach[total])
    for total in sorted(reach):
        if low <= total <= high and total > 0:
            return list(reach[total])
    return None


def tolerance_of(delta: int, floor: int, fraction: float) -> int:
    return max(floor, int(abs(delta) * fraction))


def attribute(
    old: dict[str, list[int]],
    new: dict[str, list[int]],
    floor: int = 16,
    fraction: float = 0.1,
) -> list[Row]:
    """One row per symbol that changed, with GREW / ABSORBED / SHRANK / NEW /
    VANISHED tags, the absorbers matched against the vanished pool."""
    rows: dict[str, Row] = {}
    for name in sorted(set(old) | set(new)):
        o, n = old.get(name, []), new.get(name, [])
        row = Row(name, sum(o), sum(n), len(o), len(n))
        if row.old == row.new and row.old_count == row.new_count:
            continue
        if not o:
            row.tag = "NEW"
        elif not n:
            row.tag = "VANISHED"
        elif row.delta > 0:
            row.tag = "GREW"
        elif row.delta < 0:
            row.tag = "SHRANK"
        else:
            row.tag = "SAME-SIZE"
        rows[name] = row

    pool = [(r.name, r.old) for r in rows.values() if r.tag == "VANISHED"]
    grown = sorted((r for r in rows.values() if r.tag == "GREW"), key=lambda r: -r.delta)
    for row in grown:
        tol = tolerance_of(row.delta, floor, fraction)
        found = subset_matching(pool, row.delta - tol, row.delta + tol)
        if found is None:
            continue
        taken = [pool[i] for i in found]
        row.tag = "ABSORBED"
        row.absorbed = sorted(taken, key=lambda t: -t[1])
        for name, _ in taken:
            rows[name].tag = f"VANISHED into {row.name}"
        pool = [p for i, p in enumerate(pool) if i not in set(found)]
    return sorted(rows.values(), key=lambda r: (-abs(r.delta), r.name))


def total(table: dict[str, list[int]], scope: re.Pattern[str] | None) -> tuple[int, int]:
    """`(bytes, instances)` of the symbols in `scope` (all when None)."""
    sizes = [s for name, v in table.items() if scope is None or scope.search(name) for s in v]
    return sum(sizes), len(sizes)


def report(
    old: dict[str, list[int]],
    new: dict[str, list[int]],
    scopes: list[str],
    floor: int,
    fraction: float,
    family: str,
) -> list[str]:
    out: list[str] = []
    patterns: list[tuple[str, re.Pattern[str] | None]] = [(f"all {family}", None)]
    patterns += [(s, re.compile(s)) for s in scopes]
    scope_delta: dict[str, int] = {}
    for label, pattern in patterns:
        (ob, oc), (nb, nc) = total(old, pattern), total(new, pattern)
        scope_delta[label] = nb - ob
        out.append(
            f"scope {label!r}: {ob} -> {nb} B ({nb - ob:+d}), "
            f"{oc} -> {nc} instance(s)"
        )
    rows = attribute(old, new, floor, fraction)
    out.append(f"{'delta':>8} {'old':>8} {'new':>8} {'inst':>7}  tag / symbol")
    for r in rows:
        line = (
            f"{r.delta:+8d} {r.old:8d} {r.new:8d} {r.old_count:>3}->{r.new_count:<3} "
            f"{r.tag}  {r.name}"
        )
        if r.absorbed:
            names = ", ".join(f"{n} ({s} B)" for n, s in r.absorbed)
            line += f"\n{'':36}<- {names}"
        out.append(line)
    for r in rows:
        for label, pattern in patterns:
            if pattern is not None and not pattern.search(r.name):
                continue
            d = scope_delta[label]
            if r.delta > 0 and r.delta > d:
                out.append(
                    f"over-stated: {r.name} grew {r.delta:+d} B while scope {label!r} "
                    f"grew {d:+d} B -- other symbols in it shrank; attribute to the "
                    f"scope's total, not to this symbol"
                )
    return out


def read_listing(path: str, nm: str) -> str:
    """The `nm --print-size -C` listing of `path`: run on an ELF, read from a
    text file that already holds one."""
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if magic == b"\x7fELF":
        done = subprocess.run(
            [nm, "--print-size", "--size-sort", "-C", path],
            capture_output=True,
            text=True,
            check=False,
        )
        if done.returncode != 0:
            raise SystemExit(f"footprint-attribution: {nm} exited {done.returncode} on {path}: {done.stderr.strip()}")
        return done.stdout
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


_OLD = """\
00000100 00000200 T engine::Engine<P>::run_main_event_loop::h0123456789abcdef
00000300 000000d4 t engine::Engine<P>::check_eventless_transitions::h1111111111111111
00000400 00000136 t engine::Engine<P>::process_internal_queue::h2222222222222222
00000500 00000040 T other[1a2b3c4d]::f
00000600 00000010 D data_thing
00000700 00000020 T engine::Engine<Q>::step::h4444444444444444
00000800 00000020 T engine::Engine<Q>::step::h5555555555555555
00000900 00000020 T engine::Engine<Q>::step::h6666666666666666
         U undefined_thing
"""
_NEW = """\
00000100 00000410 T engine::Engine<P>::run_main_event_loop::haaaaaaaaaaaaaaa
00000500 00000020 T other[9f8e7d6c]::f
00000600 00000040 D data_thing
00000700 00000020 T engine::Engine<Q>::step::h4444444444444444
00000800 00000020 T engine::Engine<Q>::step::h5555555555555555
00000900 00000020 T engine::Engine<Q>::step::h6666666666666666
00000a00 00000020 T engine::Engine<Q>::step::h7777777777777777
00000b00 00000020 T engine::Engine<Q>::step::h8888888888888888
"""


def selftest() -> None:
    old, new = parse_nm(_OLD, False), parse_nm(_NEW, False)
    assert "data_thing" not in old, "selftest: a data symbol was read as text"
    assert "undefined_thing" not in old, "selftest: a sizeless symbol was read"
    assert "other::f" in old and "other::f" in new, "selftest: the disambiguator was kept"
    assert len(old["engine::Engine<Q>::step"]) == 3, "selftest: instances were merged"
    rows = {r.name: r for r in attribute(old, new)}

    loop = rows["engine::Engine<P>::run_main_event_loop"]
    # 0x200 -> 0x410 is +528; the two vanished callees are 212 + 310 = 522.
    assert loop.delta == 528 and loop.tag == "ABSORBED", f"selftest: loop {loop}"
    assert {n for n, _ in loop.absorbed} == {
        "engine::Engine<P>::check_eventless_transitions",
        "engine::Engine<P>::process_internal_queue",
    }, f"selftest: absorbed {loop.absorbed}"
    assert rows["engine::Engine<P>::process_internal_queue"].tag.startswith("VANISHED into"), (
        "selftest: an absorbed callee was not tied to its absorber"
    )
    assert rows["other::f"].tag == "SHRANK" and rows["other::f"].delta == -32
    step = rows["engine::Engine<Q>::step"]
    assert (step.old_count, step.new_count) == (3, 5), f"selftest: instances {step}"
    assert step.tag == "GREW", "selftest: two new instances read as anything but growth"

    # The control: the same loop growth with callees too small to explain it
    # stays GREW, and the callees stay VANISHED with no absorber.
    small = _OLD.replace("000000d4", "00000010").replace("00000136", "00000010")
    rows = {r.name: r for r in attribute(parse_nm(small, False), new)}
    assert rows["engine::Engine<P>::run_main_event_loop"].tag == "GREW", (
        "selftest: growth no vanished set explains was tagged ABSORBED"
    )
    assert rows["engine::Engine<P>::process_internal_queue"].tag == "VANISHED"

    # Data is read only when asked for.
    assert parse_nm(_OLD, True)["data_thing"] == [16]

    # The scope total and the over-statement: the loop grew +528 while the
    # Engine<P> scope grew 1040 - 1034 = +6.
    lines = report(old, new, [r"Engine<P>"], 16, 0.1, "text")
    assert any(l.startswith("scope 'Engine<P>': 1034 -> 1040 B (+6)") for l in lines), lines
    assert any(l.startswith("over-stated: engine::Engine<P>::run_main_event_loop") for l in lines), (
        "selftest: a symbol growing more than its scope was not called out"
    )

    assert subset_matching([("a", 5), ("b", 7)], 12, 12) is not None
    assert subset_matching([("a", 5), ("b", 7)], 8, 11) is None
    assert stable_name("x::y::h0123456789abcdef.llvm.42") == "x::y"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--old", help="the earlier ELF, or its nm --print-size -C listing")
    parser.add_argument("--new", help="the later ELF, or its nm --print-size -C listing")
    parser.add_argument("--nm", default="nm", help="the target toolchain's nm (default: nm)")
    parser.add_argument("--scope", action="append", default=[], help="a regex over symbol names; repeatable")
    parser.add_argument("--all-sections", action="store_true", help="read data symbols too")
    parser.add_argument("--tolerance", type=int, default=16, help="bytes an absorption may miss by (floor)")
    parser.add_argument("--tolerance-fraction", type=float, default=0.1, help="fraction of the growth it may miss by")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        print("footprint-attribution: selftest ok")
        return 0
    if not args.old or not args.new:
        parser.error("--old and --new are both required")
    old = parse_nm(read_listing(args.old, args.nm), args.all_sections)
    new = parse_nm(read_listing(args.new, args.nm), args.all_sections)
    if not old or not new:
        print(
            f"footprint-attribution: FAIL -- read {len(old)} and {len(new)} sized "
            f"symbol(s); an empty listing attributes nothing",
            file=sys.stderr,
        )
        return 1
    family = "symbols" if args.all_sections else "text"
    for line in report(old, new, args.scope, args.tolerance, args.tolerance_fraction, family):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

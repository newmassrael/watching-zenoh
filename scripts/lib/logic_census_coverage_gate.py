#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""EVERY CRATE IS READ BY A SLICE OF THE LOGIC CENSUS, OR LEFT OUT WITH A REASON.

## The defect

`docs/zenoh-logic-as-sce-kinds.md` classifies wz's hand-written protocol logic
against SCE's kinds, slice by slice. Its six slices were scoped by hand, and the
crates nobody named were simply not there: the cooperative engine's C ABI
(`wz-capi-coop`), the protocol logic inside the other C ABI crates, the MCU
network stacks, `wz-node-time`, `wz-app-frame` and more. Nothing in the slices
says a crate is missing, so "is anything left out?" had no answer but a reread.

## What this holds

`docs/zenoh-logic-as-sce-kinds/crates.md` has one row per crate. The population
is DERIVED: every tracked `crates/<dir>/Cargo.toml`. A finding is

- a crate with no row, or with two;
- a row naming a directory that holds no tracked crate;
- a row whose slice has no file `docs/zenoh-logic-as-sce-kinds/<slice>.md`, or
  whose slice file never names the crate (as `crates/<crate>/` or `` `<crate>` ``);
- an exclusion whose kind is not one of the listed kinds, or that gives no reason.

A table read as empty, or a tree with no crate, is a FAILURE: that is the gate
having lost its subject, not a census with nothing to cover.

## What this does NOT claim

That a slice classified every FILE of its crate (a slice names its crate and its
scope; which files it read is that slice's text), or that a classification is
right. It holds that no crate is silently outside the census.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CENSUS_DIR = "docs/zenoh-logic-as-sce-kinds"
TABLE = f"{CENSUS_DIR}/crates.md"

EXCLUSION_KINDS = ("test", "build", "binding", "example", "analyzer", "measurement", "facade")

ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*$")
SLICE = re.compile(r"^S[0-9]+$")


def parse_table(text: str) -> tuple[list[tuple[str, str, str]], list[str]]:
    """(crate, where, reason) per table row, plus the rows that could not be read.
    A line that starts like a crate row and does not fit the three columns is a
    finding, so a malformed row cannot drop out of the population unseen."""
    rows: list[tuple[str, str, str]] = []
    bad: list[str] = []
    for line in text.splitlines():
        if not line.startswith("| `"):
            continue
        m = ROW.match(line)
        if m is None:
            bad.append(f"row not read as `| crate | where | reason |`: {line.strip()[:120]}")
            continue
        rows.append((m.group(1), m.group(2), m.group(3)))
    return rows, bad


def findings(rows: list[tuple[str, str, str]], crates: set[str],
             slice_text: dict[str, str]) -> list[str]:
    out: list[str] = []
    seen: dict[str, int] = {}
    for crate, _, _ in rows:
        seen[crate] = seen.get(crate, 0) + 1
    for crate in sorted(crates):
        if crate not in seen:
            out.append(f"`{crate}` has no row: name the slice that reads it, or exclude it "
                       f"with a kind and a reason")
    for crate, n in sorted(seen.items()):
        if n > 1:
            out.append(f"`{crate}` has {n} rows; give it one")
        if crate not in crates:
            out.append(f"`{crate}` has a row but `crates/{crate}/Cargo.toml` is not tracked")
    for crate, where, reason in rows:
        if where.startswith("excluded:"):
            kind = where[len("excluded:"):].strip()
            if kind not in EXCLUSION_KINDS:
                out.append(f"`{crate}`: exclusion kind `{kind}` is not one of "
                           f"{', '.join(EXCLUSION_KINDS)}")
            if not reason:
                out.append(f"`{crate}`: excluded without a reason")
            continue
        slices = [s.strip() for s in where.split(",") if s.strip()]
        if not slices:
            out.append(f"`{crate}`: names no slice and is not excluded")
        for s in slices:
            if not SLICE.match(s):
                out.append(f"`{crate}`: `{s}` is not a slice name (`S<n>`) or `excluded: <kind>`")
                continue
            text = slice_text.get(s)
            if text is None:
                out.append(f"`{crate}`: slice {s} has no file {CENSUS_DIR}/{s}.md")
            elif f"crates/{crate}/" not in text and f"`{crate}`" not in text:
                out.append(f"`{crate}`: slice {s} never names it (as `crates/{crate}/` "
                           f"or `{crate}` in code)")
    return out


def tracked_crates(root: Path) -> set[str]:
    run = subprocess.run(["git", "-C", str(root), "ls-files", "crates/*/Cargo.toml"],
                         capture_output=True, text=True, check=True)
    return {Path(p).parent.name for p in run.stdout.split()}


def check() -> int:
    table = REPO_ROOT / TABLE
    if not table.is_file():
        print(f"logic-census-coverage: FAIL -- {TABLE} is missing", file=sys.stderr)
        return 1
    rows, bad = parse_table(table.read_text(encoding="utf-8"))
    crates = tracked_crates(REPO_ROOT)
    if not rows or not crates:
        print("logic-census-coverage: FAIL -- read "
              f"{len(rows)} row(s) and {len(crates)} tracked crate(s); the gate lost its "
              "subject and must not pass over an empty population", file=sys.stderr)
        return 1
    slice_text = {p.stem: p.read_text(encoding="utf-8")
                  for p in (REPO_ROOT / CENSUS_DIR).glob("S*.md")}
    found = bad + findings(rows, crates, slice_text)
    if found:
        print("logic-census-coverage: FAIL -- a crate is outside the logic census unseen:",
              file=sys.stderr)
        for f in found:
            print(f"  - {f}", file=sys.stderr)
        return 1
    excluded = sum(1 for _, w, _ in rows if w.startswith("excluded:"))
    print(f"logic-census-coverage: ok -- {len(crates)} crate(s): {len(crates) - excluded} "
          f"read by a slice, {excluded} excluded with a reason")
    return 0


TABLE_SAMPLE = """\
| Crate | Where | Reason |
|---|---|---|
| `alpha` | S1, S2 | |
| `beta` | excluded: test | Helpers for alpha's tests. |
| `gamma` | excluded: test | |
| `delta` | excluded: whim | Because. |
| `eps` | S3 | |
| `zeta` | S9 | |
| `eta` | sometimes | |
| `alpha` | S1 | |
| `ghost` | S1 | |
| `theta | S1 | |
"""


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, got, want) -> None:
        ok = got == want
        print(f"  selftest -- {name}: {'ok' if ok else f'FAIL got {got!r} want {want!r}'}")
        if not ok:
            failures.append(name)

    rows, bad = parse_table(TABLE_SAMPLE)
    expect("the header and rule lines are not rows", [r[0] for r in rows][:2], ["alpha", "beta"])
    expect("a row whose crate cell is not closed is a finding, not dropped",
           len(bad) == 1 and "theta" in bad[0], True)
    crates = {"alpha", "beta", "gamma", "delta", "eps", "zeta", "eta", "iota"}
    slices = {"S1": "reads `alpha` and `ghost`", "S2": "scope: crates/alpha/src/",
              "S3": "reads nothing named"}
    got = findings(rows, crates, slices)

    def has(fragment: str) -> bool:
        return any(fragment in f for f in got)

    expect("a tracked crate with no row is a finding", has("`iota` has no row"), True)
    expect("a crate with two rows is a finding", has("`alpha` has 2 rows"), True)
    expect("a row for an untracked crate is a finding",
           has("`ghost` has a row but `crates/ghost/Cargo.toml` is not tracked"), True)
    expect("a slice naming the crate in code passes", has("`alpha`: slice S1"), False)
    expect("a slice naming the crate by path passes", has("`alpha`: slice S2"), False)
    expect("a slice that never names its crate is a finding", has("`eps`: slice S3 never"), True)
    expect("a slice with no file is a finding", has("`zeta`: slice S9 has no file"), True)
    expect("an exclusion without a reason is a finding", has("`gamma`: excluded without"), True)
    expect("an exclusion with a reason passes",
           any(f.startswith("`beta`") for f in got), False)
    expect("an unknown exclusion kind is a finding", has("`delta`: exclusion kind `whim`"), True)
    expect("a where that is neither slice nor exclusion is a finding",
           has("`eta`: `sometimes` is not a slice name"), True)
    expect("a crate name that is a prefix of another is not taken for it",
           findings([("ab", "S1", "")], {"ab"}, {"S1": "reads `abc` and crates/abc/"}) != [],
           True)
    expect("an empty table reads as no rows, which the check refuses",
           parse_table("| Crate | Where | Reason |\n|---|---|---|\n")[0], [])
    print(f"logic-census-coverage selftest: "
          f"{'OK' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    return selftest() if args.selftest else check()


if __name__ == "__main__":
    sys.exit(main())

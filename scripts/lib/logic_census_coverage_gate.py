#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4542 (no register item) -- every crate is read by a slice of the logic census, or
left out with a reason.

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

## The file level (2026-11-20)

The crate level passed while whole files were outside the census: S7 named
`wz-capi-pico` and its rows never reached its end-to-end, replay, key-id and
stream-supervision doors (about 6,700 lines), and the application transport of
the session core and both runtimes had no row anywhere. A crate row says a slice
read the crate; it does not say the slice read each file.

`docs/zenoh-logic-as-sce-kinds/files.md` has one row per tracked `.rs` file under
`src/` of every crate a slice reads (`| path | slices | reason |`). The
population is DERIVED from `git ls-files`. A finding is

- a file with no row, or with two; a row for a file outside that population;
- a slice that crates.md does not name for the file's crate;
- a slice none of whose ROWS (table lines `| <id> | ...`) cites the file, by its
  full path, by a cited directory `crates/<crate>/src/<dir>/` that holds it, or
  by its path below `src/` or a tail of it at a `/` (the short form the first six
  slices use); a scope paragraph naming a whole `src/` does not cover a file;
- an exclusion whose kind is not `test`, `generated` or `scope`, or that gives no
  reason; a `scope` exclusion must name the slice whose scope paragraph leaves
  the file out, and that slice must name the file.

## What this does NOT claim

That a row classified a file RIGHT, or that a short-form citation names the very
file (a tail such as `lib.rs` matches every crate root a slice reads). It holds
that no crate and no file is silently outside the census.
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
FILE_TABLE = f"{CENSUS_DIR}/files.md"

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


# ---- file level --------------------------------------------------------------------------

FILE_EXCLUSION_KINDS = ("test", "generated", "scope")
TABLE_ROW_LINE = re.compile(r"^\|\s*[0-9A-Z][0-9A-Za-z.-]*\s*\|")
FILE_PATH = re.compile(r"^crates/([^/]+)/src/(.+\.rs)$")
DIR_CITE = re.compile(r"crates/([^/`\s]+)/src/((?:[^/`\s:,]+/)*)(?=[`\s,;)]|$)")


def slice_rows(slice_text: dict[str, str]) -> dict[str, str]:
    """Only the table rows of each slice (`| <id> | ...`), joined. A file is covered by
    what a ROW says, not by a scope paragraph that names a whole `src/`."""
    return {s: "\n".join(line for line in t.splitlines() if TABLE_ROW_LINE.match(line))
            for s, t in slice_text.items()}


def split_path(path: str) -> tuple[str, str]:
    m = FILE_PATH.match(path)
    if m is None:
        raise ValueError(path)
    return m.group(1), m.group(2)


def is_test_named(rel: str) -> bool:
    leaf = rel.rsplit("/", 1)[-1]
    return (leaf in ("tests.rs", "test.rs") or leaf.endswith(("_tests.rs", "_test.rs"))
            or "/tests/" in f"/{rel}")


def rows_name_file(rows: str, crate: str, rel: str) -> bool:
    """Whether a slice's rows name `crates/<crate>/src/<rel>`: by its full path; by a cited
    directory `crates/<crate>/src/<dir>/` that holds it; or by a short form the first six
    slices use (`lib.rs:120`, `rt/router_forward.rs:610`), which is the file's path below
    `src/` or a tail of it at a `/`. A bare `mod.rs` / `lib.rs` tail needs its directory
    for a file below `src/` itself is the only one it can name."""
    if f"crates/{crate}/src/{rel}" in rows:
        return True
    for m in DIR_CITE.finditer(rows):
        if m.group(1) == crate and rel.startswith(m.group(2)):
            return True
    parts = rel.split("/")
    for i in range(len(parts)):
        tail = "/".join(parts[i:])
        if i == len(parts) - 1 and tail in ("mod.rs",) and len(parts) > 1:
            continue
        if re.search(r"(?<![\w.-])" + re.escape(tail) + r"(?=[`:,;\s)]|$)", rows):
            return True
    return False


def tracked_files(root: Path, crate_rows: list[tuple[str, str, str]]) -> list[str]:
    read = [c for c, w, _ in crate_rows if not w.startswith("excluded:")]
    if not read:
        return []
    run = subprocess.run(["git", "-C", str(root), "ls-files", "--"]
                         + [f"crates/{c}/src" for c in read],
                         capture_output=True, text=True, check=True)
    return sorted(p for p in run.stdout.split() if p.endswith(".rs"))


def file_findings(file_rows: list[tuple[str, str, str]], files: list[str],
                  crate_rows: list[tuple[str, str, str]],
                  rows_of: dict[str, str], slice_text: dict[str, str]) -> list[str]:
    out: list[str] = []
    crate_slices = {c: {s.strip() for s in w.split(",")} for c, w, _ in crate_rows
                    if not w.startswith("excluded:")}
    seen: dict[str, int] = {}
    for path, _, _ in file_rows:
        seen[path] = seen.get(path, 0) + 1
    population = set(files)
    for path in files:
        if path not in seen:
            out.append(f"`{path}` has no row in files.md: name the slice whose rows cite it, "
                       f"or exclude it with a kind and a reason")
    for path, n in sorted(seen.items()):
        if n > 1:
            out.append(f"`{path}` has {n} rows in files.md; give it one")
        if path not in population:
            out.append(f"`{path}` has a row in files.md but is not a tracked file of a crate "
                       f"a slice reads")
    for path, where, reason in file_rows:
        if path not in population:
            continue
        crate, rel = split_path(path)
        if where.startswith("excluded:"):
            kind = where[len("excluded:"):].strip()
            if kind not in FILE_EXCLUSION_KINDS:
                out.append(f"`{path}`: exclusion kind `{kind}` is not one of "
                           f"{', '.join(FILE_EXCLUSION_KINDS)}")
            if not reason:
                out.append(f"`{path}`: excluded without a reason")
            if kind == "scope":
                named = re.findall(r"\bS[0-9]+\b", reason)
                leaf = rel.rsplit("/", 1)[-1][:-3]
                if not named or not any(leaf in slice_text.get(s, "") for s in named):
                    out.append(f"`{path}`: a `scope` exclusion names the slice whose scope "
                               f"paragraph leaves the file out, and that slice names it")
            continue
        slices = [s.strip() for s in where.split(",") if s.strip()]
        if not slices:
            out.append(f"`{path}`: names no slice and is not excluded")
        for s in slices:
            if not SLICE.match(s):
                out.append(f"`{path}`: `{s}` is not a slice name or `excluded: <kind>`")
            elif s not in crate_slices.get(crate, set()):
                out.append(f"`{path}`: slice {s} is not one crates.md names for `{crate}`")
            elif not rows_name_file(rows_of.get(s, ""), crate, rel):
                out.append(f"`{path}`: no row of slice {s} cites it (by path, a cited "
                           f"directory, or its path below src/)")
    return out


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
    file_table = REPO_ROOT / FILE_TABLE
    if not file_table.is_file():
        found.append(f"{FILE_TABLE} is missing")
        file_rows: list[tuple[str, str, str]] = []
        files: list[str] = []
    else:
        file_rows, file_bad = parse_table(file_table.read_text(encoding="utf-8"))
        files = tracked_files(REPO_ROOT, rows)
        if not file_rows or not files:
            print("logic-census-coverage: FAIL -- read "
                  f"{len(file_rows)} file row(s) and {len(files)} tracked file(s); the gate "
                  "lost its subject and must not pass over an empty population",
                  file=sys.stderr)
            return 1
        found += file_bad + file_findings(file_rows, files, rows, slice_rows(slice_text),
                                          slice_text)
    if found:
        print("logic-census-coverage: FAIL -- a crate or a file is outside the logic census "
              "unseen:", file=sys.stderr)
        for f in found:
            print(f"  - {f}", file=sys.stderr)
        print(f"  A new file is placed by a row of a slice that cites it (or a new row "
              f"classifying it, as {CENSUS_DIR}.md section 2 defines the classes) and a "
              f"row in {FILE_TABLE}; the header of each table says what a row holds.",
              file=sys.stderr)
        return 1
    excluded = sum(1 for _, w, _ in rows if w.startswith("excluded:"))
    files_excluded = sum(1 for _, w, _ in file_rows if w.startswith("excluded:"))
    print(f"logic-census-coverage: ok -- {len(crates)} crate(s): {len(crates) - excluded} "
          f"read by a slice, {excluded} excluded with a reason; {len(files)} file(s) of "
          f"those crates: {len(files) - files_excluded} cited by a slice's rows, "
          f"{files_excluded} excluded with a reason")
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

    # ---- file level
    slice_docs = {
        "S1": "Scope: `crates/alpha/src/` whole.\n\n| # | R | Where |\n|---|---|---|\n"
              "| 1 | x | `crates/alpha/src/full.rs:10` |\n"
              "| 2 | y | `crates/alpha/src/deep/` |\n"
              "| 3 | z | `lib.rs:20`, `rt/short.rs:5` |\n",
        "S2": "Left out: `quiet.rs` (fixtures only).\n\n| 1 | w | `crates/beta/src/b.rs:1` |\n",
    }
    rows_of = slice_rows(slice_docs)
    expect("a scope paragraph is not a row", "whole" in rows_of["S1"], False)
    expect("a full path is a citation", rows_name_file(rows_of["S1"], "alpha", "full.rs"), True)
    expect("a cited directory covers a file below it",
           rows_name_file(rows_of["S1"], "alpha", "deep/inner/f.rs"), True)
    expect("a path tail is a citation", rows_name_file(rows_of["S1"], "alpha", "a/rt/short.rs"),
           True)
    expect("a crate root by its short name is a citation",
           rows_name_file(rows_of["S1"], "alpha", "lib.rs"), True)
    expect("a name that only contains a cited one is not cited",
           rows_name_file(rows_of["S1"], "alpha", "unfull.rs"), False)
    expect("a whole src/ named in a scope paragraph covers nothing",
           rows_name_file(rows_of["S1"], "alpha", "other.rs"), False)
    expect("a bare mod.rs tail does not cite a module's mod.rs",
           rows_name_file("| 1 | m | `mod.rs:3` |", "alpha", "x/mod.rs"), False)
    expect("a test-named file is recognised",
           [is_test_named(r) for r in ("a_tests.rs", "tests.rs", "t/tests/x.rs", "attest.rs")],
           [True, True, True, False])
    crate_rows = [("alpha", "S1", ""), ("beta", "S2", "")]
    files = ["crates/alpha/src/full.rs", "crates/alpha/src/lib.rs", "crates/alpha/src/other.rs",
             "crates/alpha/src/twice.rs", "crates/beta/src/b.rs", "crates/beta/src/quiet.rs",
             "crates/beta/src/loud.rs", "crates/beta/src/bare.rs"]
    file_rows = [("crates/alpha/src/full.rs", "S1", ""), ("crates/alpha/src/lib.rs", "S2", ""),
                 ("crates/alpha/src/other.rs", "S1", ""),
                 ("crates/alpha/src/twice.rs", "excluded: test", "x"),
                 ("crates/alpha/src/twice.rs", "excluded: test", "x"),
                 ("crates/beta/src/b.rs", "S2", ""),
                 ("crates/beta/src/quiet.rs", "excluded: scope", "S2 leaves it out"),
                 ("crates/beta/src/loud.rs", "excluded: scope", "S2 leaves it out"),
                 ("crates/beta/src/gone.rs", "S2", "")]
    got = file_findings(file_rows, files, crate_rows, rows_of, slice_docs)

    def fhas(fragment: str) -> bool:
        return any(fragment in f for f in got)

    expect("a file with no row is a finding", fhas("`crates/beta/src/bare.rs` has no row"), True)
    expect("a file with two rows is a finding", fhas("`crates/alpha/src/twice.rs` has 2 rows"),
           True)
    expect("a row for a file outside the population is a finding",
           fhas("`crates/beta/src/gone.rs` has a row in files.md but"), True)
    expect("a slice crates.md does not name for the crate is a finding",
           fhas("`crates/alpha/src/lib.rs`: slice S2 is not one"), True)
    expect("a slice whose rows never cite the file is a finding",
           fhas("`crates/alpha/src/other.rs`: no row of slice S1"), True)
    expect("a cited file passes", fhas("`crates/alpha/src/full.rs`"), False)
    expect("a scope exclusion the slice names passes", fhas("`crates/beta/src/quiet.rs`"), False)
    expect("a scope exclusion the slice never names is a finding",
           fhas("`crates/beta/src/loud.rs`: a `scope` exclusion"), True)
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

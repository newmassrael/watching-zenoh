#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4582 (no register item) -- how much of a change to the code its tests notice, held so that it
can only grow.

## What was missing

The gates of this tree ask whether the code does what its tests say. Only one asked the converse,
whether the tests would notice the code doing something else: Layer C0mut severs, widens and steps
each leg of the analyzer's verdict and requires a test to fail (`verdict_leg_mutation.py`). The
session core, the codecs and the pico C ABI had no such measure, so a module could be run line by
line by its tests and still hold a branch no test depends on.

## What is measured

A scope of `deploy/mutation_ratchet.json` names a crate and files of it. Layer Cmut hands each scope
to cargo-mutants, which changes the files one mutant at a time (a function body replaced by a value
of its type, an operator swapped, a match arm deleted) in a copy of the cargo workspace and runs the
crate's own tests against each change. A mutant ends one of four ways:

    caught    a test failed: the change is noticed
    missed    every test passed: the change goes unnoticed, which is a test that does not exist
    unviable  the change does not build, so it measures nothing
    timeout   the tests did not end in time; counted and not graded, since a machine's speed
              moves it

The kill rate of a scope is caught / (caught + missed).

## What is held

Each scope has a row, its four counts and its kill rate, committed after a measurement. A run of the
scope fails when its kill rate falls below the row's, or when its missed count rises above the
row's even at the same rate (a scope that grew by code no test reaches). A null row was never
measured, and fails with the commands that measure and fill it. A better run passes and prints the
tighter row to commit. Every missed mutant is printed with its place and its change: that list is
what the scope owes, one test for each line.

A run that cannot be read as a measurement is refused rather than read as clean: a baseline (the
unmutated tests) that did not pass, a scope the lane ran with no mutant in its outcomes, a mutant in
a file no scope declares, one mutant counted twice, a summary this gate does not know, or outcomes
written by another cargo-mutants than the table pins. The pin is the table's because the rows count
the mutants of one version: another version mutates the same code differently, so moving the pin
re-measures the rows in the same commit.

## Modes

    --selftest              every rule driven through a fixture that breaks it, and a clean one
    --declared              the table: scopes well formed, files present, disjoint and written by
                            hand, rows consistent (Layer C0)
    --parts, --parts-json   the scope names, one a line or as a JSON array (the fleet planner, the
                            nightly workflow's matrix)
    --tool-version          the cargo-mutants version the table pins
    --argv SCOPE --output DIR [--jobs N]
                            the arguments of cargo-mutants for SCOPE, NUL-separated
    --check OUTCOMES... [--expect SCOPE,...]
                            judge outcomes files against the rows
    --rows OUTCOMES...      the rows the outcomes measure, to commit

`--table PATH` reads another table than the committed one.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TABLE = Path("deploy/mutation_ratchet.json")
# The cargo workspace cargo-mutants copies; its outcomes name files relative to it.
WORKSPACE = "crates"

SCOPE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
TABLE_KEYS = {"cargo_mutants_version", "scopes"}
SCOPE_KEYS = {"package", "files", "timeout_multiplier", "why", "row"}
COUNTS = ("caught", "missed", "unviable", "timeout")
ROW_KEYS = {*COUNTS, "kill_rate"}
# How cargo-mutants sums up the run of one mutant, and the count it falls in.
SUMMARY = {
    "CaughtMutant": "caught",
    "MissedMutant": "missed",
    "Unviable": "unviable",
    "Timeout": "timeout",
}
# A generated file is regenerated from its source, so a test it lacks is owed by that source.
GENERATED = re.compile(r"_generated\.rs$")

NULL_ROW = (
    "scope {name} has no row in {table}: it was never measured. Measure it with "
    "`WZ_DECLINED_EXPECT= WZ_CMUT_PART={name} bash scripts/run-ci.sh --layer Cmut` (the nightly "
    "job arms WZ_DECLINED_EXPECT empty the same way), print its row with "
    "`python3 scripts/lib/mutation_ratchet_gate.py --rows <its outcomes.json>` and commit that "
    "object as scopes.{name}.row. The row this run measured: {row}"
)


@dataclass(frozen=True)
class Row:
    caught: int
    missed: int
    unviable: int
    timeout: int

    @property
    def judged(self) -> int:
        return self.caught + self.missed

    def kill_rate(self) -> float:
        return round(self.caught / self.judged, 4)

    def as_json(self) -> dict:
        return {
            "caught": self.caught,
            "missed": self.missed,
            "unviable": self.unviable,
            "timeout": self.timeout,
            "kill_rate": self.kill_rate(),
        }


@dataclass(frozen=True)
class Scope:
    name: str
    package: str
    files: tuple[str, ...]
    timeout_multiplier: float
    row: Row | None


@dataclass(frozen=True)
class Table:
    version: str
    scopes: dict[str, Scope]

    def owner_of(self) -> dict[str, Scope]:
        return {f: s for s in self.scopes.values() for f in s.files}


@dataclass
class Measure:
    counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(COUNTS, 0))
    missed: list[str] = field(default_factory=list)

    def row(self) -> Row:
        return Row(*(self.counts[k] for k in COUNTS))


def package_dirs(root: Path) -> dict[str, str]:
    """Package name -> the directory of the workspace member that is it, read from the
    `[package]` section of each member's manifest."""
    out: dict[str, str] = {}
    for manifest in sorted((root / WORKSPACE).glob("*/Cargo.toml")):
        text = manifest.read_text(encoding="utf-8")
        section = re.search(r"^\[package\][ \t]*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
        if section is None:
            continue
        name = re.search(r'^name\s*=\s*"([^"]+)"', section.group(1), re.M)
        if name is not None:
            out[name.group(1)] = manifest.parent.name
    return out


def _number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def parse_row(row: object) -> tuple[Row | None, str]:
    """The row, or why it is not one."""
    if not isinstance(row, dict) or set(row) != ROW_KEYS:
        return None, f"has exactly the keys {', '.join(sorted(ROW_KEYS))}"
    counts = [row[k] for k in COUNTS]
    if any(isinstance(c, bool) or not isinstance(c, int) or c < 0 for c in counts):
        return None, "counts are non-negative integers"
    parsed = Row(*counts)
    if parsed.judged == 0:
        return None, "judges no mutant (caught + missed is 0), so it holds nothing"
    rate = row["kill_rate"]
    if not _number(rate) or abs(rate - parsed.kill_rate()) > 5e-7:
        return None, (
            f"kill_rate {rate!r} is not caught / (caught + missed) to four places, "
            f"{parsed.kill_rate()}"
        )
    return parsed, ""


def load_table(doc: object, root: Path) -> tuple[Table | None, list[str], list[str]]:
    """The table, what is wrong with it, and what is not wrong but not done yet."""
    findings: list[str] = []
    notes: list[str] = []
    if not isinstance(doc, dict) or set(doc) != TABLE_KEYS:
        return None, [f"{TABLE} is an object with exactly the keys {', '.join(sorted(TABLE_KEYS))}"], notes
    version = doc["cargo_mutants_version"]
    if not isinstance(version, str) or not VERSION.match(version):
        findings.append(f"cargo_mutants_version {version!r} is not a MAJOR.MINOR.PATCH version")
        version = ""
    raw = doc["scopes"]
    if not isinstance(raw, dict) or not raw:
        findings.append("scopes declares no scope, and a table of none measures nothing")
        return None, findings, notes
    packages = package_dirs(root)
    owner: dict[str, str] = {}
    scopes: dict[str, Scope] = {}
    for name, body in raw.items():
        where = f"scope {name}"
        if not SCOPE_NAME.match(name):
            findings.append(f"{where}: a scope name is lowercase letters, digits and '-', which a fleet unit carries")
        if not isinstance(body, dict) or set(body) != SCOPE_KEYS:
            findings.append(f"{where}: its keys are exactly {', '.join(sorted(SCOPE_KEYS))}")
            continue
        package, files, multiplier, why = (body[k] for k in ("package", "files", "timeout_multiplier", "why"))
        if not isinstance(why, str) or not why.strip():
            findings.append(f"{where}: why says what the scope measures and why these files")
        crate = packages.get(package) if isinstance(package, str) else None
        if crate is None:
            findings.append(f"{where}: no member of {WORKSPACE}/ is the package {package!r}")
        if not _number(multiplier) or multiplier <= 0:
            findings.append(f"{where}: timeout_multiplier {multiplier!r} is not a positive number")
            multiplier = 0.0
        if not isinstance(files, list) or not files:
            findings.append(f"{where}: files is a list of at least one file")
            files = []
        kept: list[str] = []
        for path in files:
            if not isinstance(path, str):
                findings.append(f"{where}: {path!r} is not a path")
                continue
            kept.append(path)
            if crate is not None and not path.startswith(f"{WORKSPACE}/{crate}/src/"):
                findings.append(f"{where}: {path} is not under {WORKSPACE}/{crate}/src/, the package's own source")
            elif not path.endswith(".rs"):
                findings.append(f"{where}: {path} is not a Rust source file")
            elif GENERATED.search(path):
                findings.append(
                    f"{where}: {path} is generated; a test it lacks is owed by the source it is "
                    f"generated from, so it is not a scope's file"
                )
            elif not (root / path).is_file():
                findings.append(f"{where}: {path} does not exist")
            if path in owner:
                findings.append(f"{where}: {path} is also in scope {owner[path]}, and a mutant is counted by one scope")
            else:
                owner[path] = name
        row = None
        if body["row"] is None:
            notes.append(f"{where}: no row yet, never measured")
        else:
            row, why_not = parse_row(body["row"])
            if row is None:
                findings.append(f"{where}: its row {why_not}")
        scopes[name] = Scope(name, package if isinstance(package, str) else "", tuple(kept), float(multiplier), row)
    return Table(version, scopes), findings, notes


def read_table(path: Path, root: Path) -> tuple[Table | None, list[str], list[str]]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        return None, [f"{path} is unreadable ({err})"], []
    return load_table(doc, root)


def describe(mutant: dict) -> str:
    """Where a mutant is and what it changes, as a line a person can act on."""
    name = mutant.get("name")
    if isinstance(name, str) and name:
        return f"{WORKSPACE}/{name}" if name.startswith(str(mutant.get("file"))) else name
    span = mutant.get("span") if isinstance(mutant.get("span"), dict) else {}
    start = span.get("start") if isinstance(span.get("start"), dict) else {}
    function = mutant.get("function") if isinstance(mutant.get("function"), dict) else {}
    place = f"{WORKSPACE}/{mutant.get('file')}:{start.get('line', '?')}:{start.get('column', '?')}"
    within = f" in {function['function_name']}" if function.get("function_name") else ""
    return f"{place}: {mutant.get('genre', '?')} replaced with {mutant.get('replacement')!r}{within}"


def read_outcomes(path: Path, table: Table, measures: dict[str, Measure], seen: dict[str, str]) -> list[str]:
    """Add one outcomes file's mutants to `measures`; return why any of it is not a measurement."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        return [f"{path} is unreadable ({err}), so the run it records measured nothing"]
    if not isinstance(doc, dict) or not isinstance(doc.get("outcomes"), list):
        return [f"{path} holds no outcomes list; it is not a cargo-mutants outcomes file"]
    findings: list[str] = []
    version = doc.get("cargo_mutants_version")
    if version is not None and version != table.version:
        findings.append(
            f"{path} was written by cargo-mutants {version}, and the rows count the mutants of "
            f"{table.version}"
        )
    outcomes = [o for o in doc["outcomes"] if isinstance(o, dict)]
    baselines = [o for o in outcomes if o.get("scenario") == "Baseline"]
    if len(baselines) != 1:
        findings.append(
            f"{path} holds {len(baselines)} baseline runs; one run of the unmutated tests is what "
            f"gives a caught mutant its meaning"
        )
    elif baselines[0].get("summary") != "Success":
        findings.append(
            f"{path}: the unmutated tests did not pass (baseline {baselines[0].get('summary')!r}), so "
            f"no mutant's outcome means anything"
        )
    owner = table.owner_of()
    for outcome in outcomes:
        scenario = outcome.get("scenario")
        if scenario == "Baseline":
            continue
        mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
        if not isinstance(mutant, dict):
            findings.append(f"{path} holds a scenario this gate does not read: {scenario!r}")
            continue
        scope = owner.get(f"{WORKSPACE}/{mutant.get('file')}")
        package = mutant.get("package")
        if scope is None or (package is not None and package != scope.package):
            findings.append(
                f"{path}: {describe(mutant)} (package {package!r}) is in no scope of {TABLE}; the "
                f"run mutated code the table does not declare"
            )
            continue
        count = SUMMARY.get(outcome.get("summary"))
        if count is None:
            findings.append(
                f"{path}: {describe(mutant)} ended {outcome.get('summary')!r}, which is none of "
                f"{', '.join(SUMMARY)}"
            )
            continue
        key = f"{scope.name} {json.dumps(mutant, sort_keys=True)}"
        if key in seen:
            findings.append(
                f"{path}: {describe(mutant)} is counted again (first in {seen[key]}); a run given "
                f"twice counts its mutants twice"
            )
            continue
        seen[key] = str(path)
        measure = measures.setdefault(scope.name, Measure())
        measure.counts[count] += 1
        if count == "missed":
            measure.missed.append(describe(mutant))
    return findings


def read_all(paths: list[Path], table: Table) -> tuple[dict[str, Measure], list[str]]:
    measures: dict[str, Measure] = {}
    seen: dict[str, str] = {}
    findings: list[str] = []
    for path in paths:
        findings += read_outcomes(path, table, measures, seen)
    return measures, findings


def row_line(name: str, row: Row) -> str:
    return f"scopes.{name}.row = {json.dumps(row.as_json())}"


def judge(table: Table, measures: dict[str, Measure], expect: list[str]) -> tuple[list[str], list[str]]:
    """What fails and the tighter rows to commit, printing each scope's measurement and every
    missed mutant on the way."""
    findings: list[str] = []
    tighter: list[str] = []
    for name in expect:
        if name not in table.scopes:
            findings.append(f"--expect names {name}, which is no scope of {TABLE}")
        elif name not in measures:
            findings.append(
                f"scope {name} ran and its outcomes hold no mutant of it: a run that mutated "
                f"nothing is not a measurement"
            )
    for name in sorted(measures):
        got = measures[name].row()
        rate = f"{got.kill_rate():.4f}" if got.judged else "none"
        print(
            f"  Cmut {name}: caught {got.caught}, missed {got.missed}, unviable {got.unviable}, "
            f"timeout {got.timeout}, kill rate {rate}"
        )
        for line in sorted(measures[name].missed):
            print(f"    missed: {line}")
        if got.judged == 0:
            findings.append(
                f"scope {name}: no mutant was caught or missed (each was unviable or timed out), so "
                f"its tests were never asked anything"
            )
            continue
        row = table.scopes[name].row
        if row is None:
            findings.append(NULL_ROW.format(name=name, table=TABLE, row=json.dumps(got.as_json())))
            continue
        worse: list[str] = []
        if got.missed > row.missed:
            worse.append(f"missed {got.missed} where the row holds {row.missed}")
        if got.caught * row.judged < row.caught * got.judged:
            worse.append(f"kill rate {got.kill_rate():.4f} where the row holds {row.kill_rate():.4f}")
        if worse:
            findings.append(
                f"scope {name}: {'; '.join(worse)}. Each missed mutant above is a test to write; a "
                f"row is lowered only by a commit that says why"
            )
        elif got.missed < row.missed or got.caught * row.judged > row.caught * got.judged:
            tighter.append(row_line(name, got))
    return findings, tighter


def mutants_argv(scope: Scope, output: str, jobs: int) -> list[str]:
    """The arguments of `cargo-mutants` for one scope, run from the workspace. No
    `--in-place`: the mutants are built in a copy, never in the checkout."""
    argv = ["mutants", "--package", scope.package]
    for path in scope.files:
        argv += ["--file", path[len(WORKSPACE) + 1 :]]
    argv += [
        "--output", output,
        "--timeout-multiplier", f"{scope.timeout_multiplier:g}",
        "--jobs", str(jobs),
    ]
    return argv


def selftest() -> int:
    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / WORKSPACE / "wz-demo" / "src"
        src.mkdir(parents=True)
        (src.parent / "Cargo.toml").write_text(
            '[package]\nname = "wz-demo"\nversion = "0.1.0"\n\n[dependencies.decoy]\nname = "decoy"\n',
            encoding="utf-8",
        )
        for leaf in ("a.rs", "b.rs", "caps_generated.rs"):
            (src / leaf).write_text("fn f() {}\n", encoding="utf-8")
        assert package_dirs(root) == {"wz-demo": "wz-demo"}, (
            f"{package_dirs(root)}: the package name is read from [package] only"
        )
        cases += 1

        def row(caught: int, missed: int, unviable: int = 0, timeout: int = 0) -> dict:
            return Row(caught, missed, unviable, timeout).as_json()

        def doc(**edits: object) -> dict:
            scopes = {
                "demo-a": {
                    "package": "wz-demo", "files": ["crates/wz-demo/src/a.rs"],
                    "timeout_multiplier": 3, "why": "fixture", "row": row(8, 2),
                },
                "demo-b": {
                    "package": "wz-demo", "files": ["crates/wz-demo/src/b.rs"],
                    "timeout_multiplier": 2.5, "why": "fixture", "row": None,
                },
            }
            for key, value in edits.items():
                scope, attribute = key.split("__")
                scopes[scope.replace("_", "-")][attribute] = value
            return {"cargo_mutants_version": "1.2.3", "scopes": scopes}

        table, findings, notes = load_table(doc(), root)
        assert table is not None and not findings, findings
        assert notes == ["scope demo-b: no row yet, never measured"], notes
        cases += 1

        for edits, needle, what in (
            ({"demo_a__files": ["crates/wz-demo/src/caps_generated.rs"]}, "generated", "a generated file"),
            ({"demo_a__files": ["crates/wz-demo/src/gone.rs"]}, "does not exist", "a missing file"),
            ({"demo_b__files": ["crates/wz-demo/src/a.rs"]}, "also in scope", "a file in two scopes"),
            ({"demo_a__files": ["crates/wz-other/src/a.rs"]}, "own source", "another crate's file"),
            ({"demo_a__package": "wz-nowhere"}, "no member", "an unknown package"),
            ({"demo_a__timeout_multiplier": 0}, "timeout_multiplier", "a zero multiplier"),
            ({"demo_a__timeout_multiplier": True}, "timeout_multiplier", "a boolean multiplier"),
            ({"demo_a__why": " "}, "why", "an empty reason"),
            ({"demo_a__row": {**row(8, 2), "kill_rate": 0.9}}, "kill_rate", "a rate its counts do not give"),
            ({"demo_a__row": {"caught": 0, "missed": 0, "unviable": 5, "timeout": 0, "kill_rate": 0.0}},
             "judges no mutant", "a row of only unviable mutants"),
            ({"demo_a__row": {**row(8, 2), "caught": -1}}, "non-negative", "a negative count"),
            ({"demo_a__row": {"caught": 8}}, "exactly the keys", "a row missing keys"),
        ):
            _, findings, _ = load_table(doc(**edits), root)
            assert any(needle in f for f in findings), f"{what} was accepted: {findings}"
            cases += 1
        bad_name = doc()
        bad_name["scopes"]["Demo_A"] = bad_name["scopes"].pop("demo-a")
        _, findings, _ = load_table(bad_name, root)
        assert any("lowercase" in f for f in findings), f"a scope name a unit cannot carry was accepted: {findings}"
        cases += 1
        _, findings, _ = load_table({"cargo_mutants_version": "1.2", "scopes": doc()["scopes"]}, root)
        assert any("MAJOR.MINOR.PATCH" in f for f in findings), findings
        cases += 1
        _, findings, _ = load_table({"cargo_mutants_version": "1.2.3", "scopes": {}}, root)
        assert any("declares no scope" in f for f in findings), findings
        cases += 1

        assert mutants_argv(table.scopes["demo-b"], "/w/out", 2) == [
            "mutants", "--package", "wz-demo", "--file", "wz-demo/src/b.rs", "--output", "/w/out",
            "--timeout-multiplier", "2.5", "--jobs", "2",
        ], mutants_argv(table.scopes["demo-b"], "/w/out", 2)
        assert "--in-place" not in mutants_argv(table.scopes["demo-a"], "/w/out", 1)
        cases += 1

        written = 0

        def outcomes(mutants: list[tuple[int, str, str]], baseline: object = "Success",
                     version: object = "1.2.3", file: str = "wz-demo/src/a.rs") -> Path:
            nonlocal written
            written += 1
            body: dict = {"outcomes": []}
            if baseline is not None:
                body["outcomes"].append({"scenario": "Baseline", "summary": baseline})
            for line, summary, replacement in mutants:
                body["outcomes"].append({
                    "scenario": {"Mutant": {
                        "package": "wz-demo", "file": file,
                        "function": {"function_name": "f", "return_type": "-> u8"},
                        "span": {"start": {"line": line, "column": 5}, "end": {"line": line, "column": 9}},
                        "replacement": replacement, "genre": "FnValue",
                    }},
                    "summary": summary,
                })
            if version is not None:
                body["cargo_mutants_version"] = version
            path = root / f"outcomes-{written}.json"
            path.write_text(json.dumps(body), encoding="utf-8")
            return path

        def run(caught: int, missed: int, unviable: int = 0, **kw: object) -> list[tuple[int, str, str]]:
            first = int(kw.get("first", 1))
            kinds = ["CaughtMutant"] * caught + ["MissedMutant"] * missed + ["Unviable"] * unviable
            return [(first + i, kind, "0") for i, kind in enumerate(kinds)]

        def check(paths: list[Path], expect: tuple[str, ...] = (), table: Table = table) -> tuple[list[str], list[str]]:
            with contextlib.redirect_stdout(io.StringIO()):
                measures, found = read_all(paths, table)
                judged, tighter = judge(table, measures, list(expect))
            return found + judged, tighter

        findings, tighter = check([outcomes(run(8, 2))], ("demo-a",))
        assert findings == [] and tighter == [], (findings, tighter)
        cases += 1
        findings, _ = check([outcomes(run(8, 2), version=None)], ("demo-a",))
        assert findings == [], f"outcomes that do not state their version were refused: {findings}"
        cases += 1
        findings, _ = check([outcomes(run(8, 3))])
        assert any("missed 3 where the row holds 2" in f for f in findings), findings
        cases += 1
        findings, _ = check([outcomes(run(7, 2))])
        assert any("kill rate 0.7778 where the row holds 0.8000" in f for f in findings), findings
        assert not any("missed 2 where" in f for f in findings), f"an unchanged missed count was graded: {findings}"
        cases += 1
        findings, tighter = check([outcomes(run(9, 1))])
        assert findings == [] and tighter == [row_line("demo-a", Row(9, 1, 0, 0))], (findings, tighter)
        cases += 1
        findings, tighter = check([outcomes(run(4, 1))])
        assert findings == [] and tighter == [row_line("demo-a", Row(4, 1, 0, 0))], (
            f"the same rate with fewer missed is a tighter row: {findings} {tighter}"
        )
        cases += 1
        findings, _ = check([outcomes(run(3, 1), file="wz-demo/src/b.rs")], ("demo-b",))
        assert len(findings) == 1 and "--rows" in findings[0] and "WZ_CMUT_PART=demo-b" in findings[0], findings
        assert '"caught": 3' in findings[0], f"a null row's failure names the row to commit: {findings}"
        cases += 1
        for path, needle, what in (
            (outcomes(run(8, 2), baseline="Failure"), "did not pass", "a baseline that failed"),
            (outcomes(run(8, 2), baseline=None), "0 baseline runs", "no baseline"),
            (outcomes(run(8, 2), version="9.9.9"), "written by cargo-mutants 9.9.9", "another version"),
            (outcomes(run(8, 2), file="wz-demo/src/c.rs"), "no scope", "a file no scope declares"),
            (outcomes([(1, "Exploded", "0")] + run(8, 2, first=2)), "Exploded", "an unknown summary"),
            (outcomes(run(0, 0, 4)), "never asked", "a run of only unviable mutants"),
        ):
            findings, _ = check([path])
            assert any(needle in f for f in findings), f"{what} was read as a measurement: {findings}"
            cases += 1
        twice = outcomes(run(8, 2))
        findings, _ = check([twice, twice])
        assert any("counted again" in f for f in findings), findings
        cases += 1
        findings, _ = check([outcomes(run(8, 2))], ("demo-a", "demo-b"))
        assert any("scope demo-b ran" in f for f in findings), f"a scope that ran and measured nothing passed: {findings}"
        cases += 1
        findings, _ = check([outcomes(run(8, 2))], ("demo-z",))
        assert any("no scope of" in f for f in findings), findings
        cases += 1
        with contextlib.redirect_stdout(io.StringIO()) as shown:
            measures, _ = read_all([outcomes(run(1, 1))], table)
            judge(table, measures, [])
        assert "missed: crates/wz-demo/src/a.rs:2:5: FnValue replaced with '0' in f" in shown.getvalue(), (
            shown.getvalue()
        )
        cases += 1
    print(f"mutation_ratchet_gate selftest: {cases} cases pass")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="hold each mutation scope to its committed row")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--declared", action="store_true", help="check the table itself")
    mode.add_argument("--parts", action="store_true", help="the scope names, one a line")
    mode.add_argument("--parts-json", action="store_true", help="the scope names as a JSON array")
    mode.add_argument("--tool-version", action="store_true", help="the pinned cargo-mutants version")
    mode.add_argument("--argv", metavar="SCOPE", help="cargo-mutants arguments for SCOPE, NUL-separated")
    mode.add_argument("--check", nargs="+", type=Path, metavar="OUTCOMES", help="judge outcomes files")
    mode.add_argument("--rows", nargs="+", type=Path, metavar="OUTCOMES", help="print the rows they measure")
    ap.add_argument("--table", type=Path, default=ROOT / TABLE)
    ap.add_argument("--expect", default="", help="with --check: comma-separated scopes the run covered")
    ap.add_argument("--output", help="with --argv: the directory cargo-mutants writes mutants.out in")
    ap.add_argument("--jobs", type=int, default=1, help="with --argv: mutants built at once")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    table, findings, notes = read_table(args.table, ROOT)
    if args.declared:
        for note in notes:
            print(f"  mutation-ratchet NOTE: {note}")
        if findings or table is None:
            for finding in findings:
                print(f"  mutation-ratchet FAIL: {finding}", file=sys.stderr)
            return 1
        measured = sum(1 for s in table.scopes.values() if s.row is not None)
        files = sum(len(s.files) for s in table.scopes.values())
        print(
            f"  mutation-ratchet: {len(table.scopes)} scope(s) over {files} file(s), {measured} "
            f"measured, cargo-mutants {table.version}"
        )
        return 0
    if findings or table is None:
        for finding in findings:
            print(f"  mutation-ratchet FAIL: {finding}", file=sys.stderr)
        print(f"  mutation-ratchet FAIL: {args.table} is not a table this gate can use", file=sys.stderr)
        return 1
    if args.parts:
        for scope in table.scopes.values():
            print(" ".join([scope.name, *scope.files]))
        return 0
    if args.parts_json:
        print(json.dumps(list(table.scopes)))
        return 0
    if args.tool_version:
        print(table.version)
        return 0
    if args.argv is not None:
        if args.argv not in table.scopes:
            print(f"  mutation-ratchet FAIL: {args.argv} is no scope of {args.table}", file=sys.stderr)
            return 1
        if not args.output or args.jobs < 1:
            ap.error("--argv needs --output DIR and a --jobs of at least 1")
        sys.stdout.write("".join(f"{a}\0" for a in mutants_argv(table.scopes[args.argv], args.output, args.jobs)))
        return 0
    paths = args.check if args.check is not None else args.rows
    measures, findings = read_all(paths, table)
    if args.rows is not None:
        for name in sorted(measures):
            got = measures[name].row()
            if got.judged == 0:
                findings.append(f"scope {name}: no mutant was caught or missed, so it has no row to commit")
            else:
                print(row_line(name, got))
        for finding in findings:
            print(f"  mutation-ratchet FAIL: {finding}", file=sys.stderr)
        return 1 if findings or not measures else 0
    expect = [e for e in args.expect.split(",") if e]
    judged, tighter = judge(table, measures, expect)
    findings += judged
    for line in tighter:
        print(f"  mutation-ratchet TIGHTER (commit it): {line}")
    for finding in findings:
        print(f"  mutation-ratchet FAIL: {finding}", file=sys.stderr)
    if findings:
        return 1
    if not measures:
        print("  mutation-ratchet FAIL: the outcomes hold no mutant at all", file=sys.stderr)
        return 1
    print(f"  mutation-ratchet: {len(measures)} scope(s) held to their rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())

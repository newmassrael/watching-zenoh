#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4610 (no register item) -- the line, branch and function coverage of the cooperative engine's
crates, held per crate to a committed floor so that it can only rise.

## The reading

Layer Vcov (`scripts/verify.sh coverage`) runs the tests of each unit of `verify_plan.py` built with
`-Cinstrument-coverage -Zcoverage-options=branch` on the pinned nightly, merges every profile the test
processes wrote, and exports the merge over every test executable with `llvm-cov export`. This gate
reads that export. A crate's figure is the sum over its source files: the files under
`crates/<crate>/src/`, without the files that hold only tests (a `tests` directory, `tests.rs`, a
name ending `_tests.rs`). A test module inside a source file is counted with it: the export does not
tell a `#[cfg(test)]` module's lines from the code beside it. A line is counted once whichever
executables reached it, so a crate's figure is what the tests of all five crates reach of it, in
every feature set a unit built.

## The table

`deploy/coverage_floor.json`, schema `wz-coverage-floor/1`: a `tolerance` in percentage points and one row
a crate,

    {"lines": <percent or null>, "branches": <percent or null>, "functions": <percent or null>}

each the covered share of the crate's lines, branches and functions, rounded DOWN to two places so
that a floor never sits above the reading it was set from.

## The rules of --check

    a measure below its floor by more than the tolerance            FAIL
    a crate of the table the export holds no line of                FAIL
    a measure the export counts nothing of (no branch region: the
    build was not made with branch coverage)                        FAIL
    an export or a table that cannot be read                        FAIL
    a row not filled yet                                            NOT-MEASURED
    a measure above its floor                                       PASS, the tighter row printed
    a measure at its floor, or below it within the tolerance        PASS

NOT-MEASURED is never a pass: the exit status is 1 for a FAIL, 3 for NOT-MEASURED and no FAIL, and
0 only when every measure was judged and held. The functions no test reached are written to
`--uncovered-out`, one a line with the crate, the file and line, and the name: a function is uncovered
when no instantiation of it ran, so a generic that one test reached through one type is covered.

## Modes

    --selftest               every rule driven through a fixture that breaks it, and a clean one
    --declared               the table well formed, and its crates exactly the coverage lane's
                             (`verify_plan.py --crates coverage`), each with its sources
    --check EXPORT           judge an export against the table; `--summary-out` and `--uncovered-out`
                             write the per-crate summary (JSON) and the uncovered functions
    --fill EXPORT            print the `crates` object an export writes, to commit; a filled row is never
                             loosened by it

`--table PATH` reads another table than the committed one.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TABLE = Path("deploy/coverage_floor.json")
SCHEMA = "wz-coverage-floor/1"
SUMMARY_SCHEMA = "wz-coverage-summary/1"
EXPORT_TYPE = "llvm.coverage.json.export"
TABLE_KEYS = {"about", "schema", "tolerance", "crates"}
MEASURES = ("lines", "branches", "functions")
NOUN = {"lines": "line", "branches": "branch", "functions": "function"}
# The tolerance is in percentage points; a run's interleaving can move which lines a threaded
# test reaches, never by whole points.
MAX_TOLERANCE = 5
LAYER = "Vcov"
LEGACY_HASH = re.compile(r"h[0-9a-f]{16}")
LEGACY_ESCAPES = {"$SP$": "@", "$BP$": "*", "$RF$": "&", "$LT$": "<", "$GT$": ">", "$LP$": "(",
                  "$RP$": ")", "$C$": ","}
LEGACY_UNICODE = re.compile(r"\$u([0-9a-f]+)\$")


class Refused(Exception):
    """A table or an export that cannot be read as one."""


@dataclass(frozen=True)
class Judged:
    crate: str
    measure: str
    outcome: str
    sentence: str
    figure: float | None = None


def floor_percent(covered: int, count: int) -> float:
    """The covered share in percent, rounded down to two places."""
    return (covered * 10000 // count) / 100


def is_test_file(rest: str) -> bool:
    """Whether a path under a crate's `src/` holds only tests."""
    parts = rest.split("/")
    name = parts[-1]
    return "tests" in parts[:-1] or name == "tests.rs" or name.endswith("_tests.rs")


def place(filename: str, crates: list[str]) -> tuple[str, str] | None:
    """The crate a source file belongs to and its path from the tree's root, or None for a file
    outside every crate's sources or one that holds only tests."""
    norm = filename.replace("\\", "/")
    for crate in crates:
        marker = f"crates/{crate}/src/"
        if norm.startswith(marker):
            at = 0
        else:
            at = norm.find("/" + marker)
            if at < 0:
                continue
            at += 1
        rest = norm[at + len(marker):]
        if is_test_file(rest):
            return None
        return crate, norm[at:]
    return None


def demangle(name: str) -> str:
    """A legacy Rust symbol's path without its hash; any other name as it is. A local function's
    record carries its file in front of the symbol, which is dropped."""
    at = name.find("_ZN")
    if at < 0:
        return name
    text = name[at + 3:]
    parts: list[str] = []
    i = 0
    while i < len(text) and text[i] != "E":
        j = i
        while j < len(text) and text[j] in "0123456789":
            j += 1
        if j == i:
            return name
        length = int(text[i:j])
        part = text[j:j + length]
        if len(part) != length:
            return name
        parts.append(part)
        i = j + length
    if i >= len(text) or not parts:
        return name
    if LEGACY_HASH.fullmatch(parts[-1]):
        parts.pop()
    return "::".join(_unescape(part) for part in parts)


def _unescape(part: str) -> str:
    if part.startswith("_$"):
        part = part[1:]
    part = part.replace("..", "::")
    for escape, char in LEGACY_ESCAPES.items():
        part = part.replace(escape, char)
    return LEGACY_UNICODE.sub(lambda m: chr(int(m.group(1), 16)), part)


@dataclass
class Reading:
    """What an export says of the crates: each measure's covered and counted, and the functions
    no instantiation of which ran."""

    tallies: dict
    uncovered: dict


def read_export(doc: object, crates: list[str]) -> Reading:
    if not isinstance(doc, dict) or doc.get("type") != EXPORT_TYPE:
        raise Refused(f"the export is not an {EXPORT_TYPE} document")
    data = doc.get("data")
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        raise Refused("the export holds no data object")
    tallies = {crate: {m: [0, 0] for m in MEASURES} for crate in crates}
    for entry in data[0].get("files") or []:
        where = place(str(entry.get("filename", "")), crates)
        if where is None:
            continue
        summary = entry.get("summary") or {}
        for measure in MEASURES:
            figures = summary.get(measure) or {}
            tallies[where[0]][measure][0] += int(figures.get("covered", 0))
            tallies[where[0]][measure][1] += int(figures.get("count", 0))
    ran: dict[tuple[str, str, int], tuple[int, str]] = {}
    for function in data[0].get("functions") or []:
        filenames = function.get("filenames") or []
        regions = function.get("regions") or []
        if not filenames or not regions or len(regions[0]) < 6:
            continue
        index = regions[0][5]
        path = filenames[index] if isinstance(index, int) and 0 <= index < len(filenames) else filenames[0]
        where = place(str(path), crates)
        if where is None:
            continue
        key = (where[0], where[1], int(regions[0][0]))
        count = int(function.get("count", 0))
        best = ran.get(key)
        if best is None or count > best[0]:
            ran[key] = (count, demangle(str(function.get("name", ""))))
    uncovered: dict[str, list[str]] = {crate: [] for crate in crates}
    for (crate, path, line), (count, name) in sorted(ran.items()):
        if count == 0:
            uncovered[crate].append(f"{path}:{line}\t{name}")
    return Reading(tallies, uncovered)


def _number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def refuse_duplicates(pairs: list[tuple[str, object]]) -> dict:
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise Refused(f"the key {key} is written twice")
        seen[key] = value
    return seen


def load_table(text: str) -> tuple[float, dict[str, dict[str, float | None]]]:
    """The tolerance and the rows of a table; Refused with every finding when it is not one."""
    try:
        doc = json.loads(text, object_pairs_hook=refuse_duplicates)
    except ValueError as error:
        raise Refused(f"the table is not JSON: {error}") from None
    if not isinstance(doc, dict) or set(doc) != TABLE_KEYS:
        raise Refused(f"the table is an object with exactly the keys {', '.join(sorted(TABLE_KEYS))}")
    findings: list[str] = []
    if doc["schema"] != SCHEMA:
        findings.append(f"the schema is not {SCHEMA}")
    tolerance = doc["tolerance"]
    if not _number(tolerance) or not 0 <= tolerance < MAX_TOLERANCE:
        findings.append(f"`tolerance` is a number of percentage points from 0 up to, not including, "
                        f"{MAX_TOLERANCE}")
    raw = doc["crates"]
    rows: dict[str, dict[str, float | None]] = {}
    if not isinstance(raw, dict) or not raw:
        findings.append("`crates` holds no crate, and a table of none holds nothing")
    else:
        for crate, row in raw.items():
            if not isinstance(row, dict) or set(row) != set(MEASURES):
                findings.append(f"{crate}: a row has exactly the keys {', '.join(MEASURES)}")
                continue
            for measure in MEASURES:
                value = row[measure]
                if value is None:
                    continue
                if not _number(value) or not 0 <= value <= 100:
                    findings.append(f"{crate} {measure}: a floor is null or a percent from 0 to 100, "
                                    f"not {value!r}")
                elif abs(value * 100 - round(value * 100)) > 1e-6:
                    findings.append(f"{crate} {measure}: the floor {value} has more than two decimal "
                                    f"places, which no row --fill writes has")
            rows[crate] = {m: row[m] for m in MEASURES}
    if findings:
        raise Refused("; ".join(findings))
    return float(tolerance), rows


def judge(reading: Reading, tolerance: float, rows: dict) -> list[Judged]:
    out: list[Judged] = []
    for crate, row in rows.items():
        tally = reading.tallies.get(crate)
        if tally is None or tally["lines"][1] == 0:
            out.append(Judged(crate, "lines", "FAIL",
                              "the export holds no line of the crate's sources: its tests did not run "
                              "under the instrumented build, or the export left them out"))
            continue
        for measure in MEASURES:
            covered, count = tally[measure]
            if count == 0:
                why = (" (no branch region: the build was not made with branch coverage, "
                       "-Zcoverage-options=branch)" if measure == "branches" else "")
                out.append(Judged(crate, measure, "FAIL", f"the export counts no {NOUN[measure]}{why}"))
                continue
            figure = floor_percent(covered, count)
            floor = row[measure]
            shown = f"{figure:.2f}% ({covered} of {count})"
            if floor is None:
                out.append(Judged(crate, measure, "NOT-MEASURED",
                                  f"{shown}; the row is not filled yet", figure))
            elif figure < floor - tolerance - 1e-9:
                out.append(Judged(crate, measure, "FAIL",
                                  f"{shown} is below its floor {floor:.2f}% by more than the tolerance "
                                  f"of {tolerance} point(s)", figure))
            elif figure > floor + 1e-9:
                out.append(Judged(crate, measure, "PASS",
                                  f"{shown} is above its floor {floor:.2f}%: commit the tighter row",
                                  figure))
            else:
                out.append(Judged(crate, measure, "PASS", f"{shown}, floor {floor:.2f}%", figure))
    return out


def filled_rows(judged: list[Judged], rows: dict) -> dict:
    """The rows a reading writes: each measure's figure where it is above the row or the row is not
    filled, and the row as it is otherwise."""
    out = {crate: dict(row) for crate, row in rows.items()}
    for item in judged:
        if item.figure is None:
            continue
        floor = out[item.crate][item.measure]
        if floor is None or item.figure > floor:
            out[item.crate][item.measure] = item.figure
    return out


def format_rows(rows: dict) -> str:
    body = ",\n".join(f"    {json.dumps(crate)}: {json.dumps(row)}" for crate, row in rows.items())
    return '  "crates": {\n' + body + "\n  }"


def summary_of(reading: Reading) -> dict:
    return {"schema": SUMMARY_SCHEMA, "crates": {
        crate: {m: {"covered": c, "count": n, "percent": floor_percent(c, n) if n else None}
                for m, (c, n) in tally.items()}
        for crate, tally in reading.tallies.items()}}


def check(doc: object, table_text: str, summary_out: Path | None = None,
          uncovered_out: Path | None = None) -> int:
    try:
        tolerance, rows = load_table(table_text)
        reading = read_export(doc, list(rows))
    except Refused as error:
        print(f"  coverage-floor FAIL: {error}", file=sys.stderr)
        return 1
    if summary_out is not None:
        summary_out.write_text(json.dumps(summary_of(reading), indent=2) + "\n", encoding="utf-8")
    if uncovered_out is not None:
        lines = [f"{crate}\t{entry}" for crate, entries in reading.uncovered.items() for entry in entries]
        uncovered_out.write_text(f"# functions no test reached: {len(lines)}\n" + "".join(
            line + "\n" for line in lines), encoding="utf-8")
    judged = judge(reading, tolerance, rows)
    for item in judged:
        stream = sys.stderr if item.outcome == "FAIL" else sys.stdout
        print(f"  coverage-floor {item.outcome} {item.crate} {item.measure}: {item.sentence}", file=stream)
    for crate, entries in reading.uncovered.items():
        print(f"  coverage-floor: {crate}: {len(entries)} function(s) no test reached")
    failed = any(item.outcome == "FAIL" for item in judged)
    unmeasured = any(item.outcome == "NOT-MEASURED" for item in judged)
    if not failed and (unmeasured or any("tighter" in item.sentence for item in judged)):
        print("  coverage-floor: the rows this reading writes, to commit in " + str(TABLE) + ":")
        print(format_rows(filled_rows(judged, rows)))
    if failed:
        return 1
    if unmeasured:
        print(f"  coverage-floor NOT-MEASURED: a row is not filled yet (Layer {LAYER} reads no pass from it)",
              file=sys.stderr)
        return 3
    return 0


def fill(doc: object, table_text: str) -> tuple[dict | None, list[str]]:
    try:
        tolerance, rows = load_table(table_text)
        reading = read_export(doc, list(rows))
    except Refused as error:
        return None, [str(error)]
    judged = judge(reading, tolerance, rows)
    notes = [f"{i.crate} {i.measure}: {i.sentence}" for i in judged if i.outcome == "FAIL"]
    notes += [f"{i.crate} {i.measure}: kept at its floor, above this reading" for i in judged
              if i.figure is not None and rows[i.crate][i.measure] is not None
              and i.figure < rows[i.crate][i.measure]]
    return filled_rows(judged, rows), notes


def declared(table_text: str, plan_crates: list[str], root: Path = ROOT) -> list[str]:
    try:
        _tolerance, rows = load_table(table_text)
    except Refused as error:
        return [str(error)]
    findings = [f"{crate}: the coverage lane tests it and the table has no row for it"
                for crate in plan_crates if crate not in rows]
    findings += [f"{crate}: a row of the table, and the coverage lane tests no such crate"
                 for crate in rows if crate not in plan_crates]
    findings += [f"{crate}: crates/{crate}/src is not a directory of the tree"
                 for crate in rows if not (root / "crates" / crate / "src").is_dir()]
    return findings


# ─── selftest ──────────────────────────────────────────────────────────────


def _mangle(*parts: str) -> str:
    return "_ZN" + "".join(f"{len(part)}{part}" for part in parts) + "E"


def _file(path: str, lines: tuple[int, int], branches: tuple[int, int], functions: tuple[int, int]) -> dict:
    def fig(covered: int, count: int) -> dict:
        return {"covered": covered, "count": count, "percent": 100.0 * covered / count if count else 0}
    return {"filename": path, "summary": {"lines": fig(*lines), "branches": fig(*branches),
                                          "functions": fig(*functions), "regions": fig(1, 1)}}


def _function(name: str, path: str, line: int, count: int) -> dict:
    return {"name": name, "count": count, "regions": [[line, 1, line + 3, 2, count, 0, 0, 0]],
            "filenames": [path]}


def _export(files: list[dict], functions: list[dict], kind: str = EXPORT_TYPE) -> dict:
    return {"type": kind, "version": "2.0.1", "data": [{"files": files, "functions": functions}]}


def _table(rows: dict, tolerance: object = 0.1, schema: str = SCHEMA) -> str:
    return json.dumps({"about": "fixture", "schema": schema, "tolerance": tolerance, "crates": rows})


def _row(lines: object = None, branches: object = None, functions: object = None) -> dict:
    return {"lines": lines, "branches": branches, "functions": functions}


def _run(doc: object, table_text: str) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = check(doc, table_text)
    return status, out.getvalue() + err.getvalue()


def selftest() -> int:
    cases = 0
    a_lib = "/r/crates/wz-a/src/lib.rs"
    files = [
        _file(a_lib, (80, 100), (5, 10), (8, 10)),
        _file("/r/crates/wz-a/src/tests/x.rs", (50, 50), (2, 2), (5, 5)),
        _file("/r/crates/wz-a/src/declare/lent_tests.rs", (9, 9), (1, 1), (1, 1)),
        _file("/r/crates/wz-b/src/lib.rs", (10, 10), (2, 4), (2, 2)),
        _file("/r/crates/wz-ab/src/lib.rs", (0, 999), (0, 99), (0, 9)),
        _file("/home/u/.cargo/registry/src/x/lib.rs", (0, 999), (0, 99), (0, 9)),
    ]
    drop = _mangle("_$LT$wz_a..bounded..BoundedVec$LT$T$GT$$u20$as$u20$core..ops..Drop$GT$", "drop",
                   "h0123456789abcdef")
    functions = [
        _function(_mangle("wz_a", "reached_by_one", "h1111111111111111"), a_lib, 10, 0),
        _function(_mangle("wz_a", "reached_by_one", "h2222222222222222"), a_lib, 10, 3),
        _function(_mangle("wz_a", "never", "h3333333333333333"), a_lib, 20, 0),
        _function("crates/wz-a/src/lib.rs;" + drop, a_lib, 30, 0),
        _function(_mangle("wz_a", "tests", "a_test", "h4444444444444444"), "/r/crates/wz-a/src/tests/x.rs", 5, 0),
    ]
    doc = _export(files, functions)
    held = _row(80.0, 50.0, 80.0)
    b_held = _row(100.0, 50.0, 100.0)

    # The reading: only each crate's sources, its test files left out, a neighbour's name not taken.
    reading = read_export(doc, ["wz-a", "wz-b"])
    assert reading.tallies["wz-a"] == {"lines": [80, 100], "branches": [5, 10], "functions": [8, 10]}, reading.tallies
    assert reading.tallies["wz-b"] == {"lines": [10, 10], "branches": [2, 4], "functions": [2, 2]}, reading.tallies
    cases += 1

    # A function is uncovered when no instantiation of it ran; a test file's is not listed; a
    # local function's file prefix and the symbol's hash are dropped.
    assert reading.uncovered["wz-a"] == [
        "crates/wz-a/src/lib.rs:20\twz_a::never",
        "crates/wz-a/src/lib.rs:30\t<wz_a::bounded::BoundedVec<T> as core::ops::Drop>::drop",
    ], reading.uncovered
    assert reading.uncovered["wz-b"] == []
    assert demangle("_RNvCs1234_4wz_a5never") == "_RNvCs1234_4wz_a5never", "a v0 name is kept as it is"
    assert demangle("_ZN4wz_a3fooE") == "wz_a::foo" and demangle("_ZN4wz_a9truncated") == "_ZN4wz_a9truncated"
    assert floor_percent(2, 3) == 66.66 and floor_percent(1, 1) == 100.0
    cases += 1

    # A clean reading at its floors passes; a reading within the tolerance below them passes.
    status, shown = _run(doc, _table({"wz-a": held, "wz-b": b_held}))
    assert status == 0 and "FAIL" not in shown and "tighter" not in shown, shown
    status, shown = _run(doc, _table({"wz-a": _row(80.05, 50.0, 80.0), "wz-b": b_held}))
    assert status == 0, shown
    cases += 1

    # A fall past the tolerance fails, naming the crate and the measure.
    status, shown = _run(doc, _table({"wz-a": _row(81.0, 50.0, 80.0), "wz-b": b_held}))
    assert status == 1 and "FAIL wz-a lines" in shown, shown
    cases += 1

    # A rise passes and prints the tighter row, never a looser one.
    status, shown = _run(doc, _table({"wz-a": _row(70.0, 50.0, 80.0), "wz-b": b_held}))
    assert status == 0 and "tighter" in shown and '"lines": 80.0' in shown, shown
    rows, notes = fill(doc, _table({"wz-a": _row(90.0, 40.0, None), "wz-b": b_held}))
    assert rows is not None and rows["wz-a"] == _row(90.0, 50.0, 80.0), rows
    assert any("kept at its floor" in note for note in notes), notes
    cases += 1

    # A row not filled yet is NOT-MEASURED, never a pass, and the rows to commit are printed.
    status, shown = _run(doc, _table({"wz-a": _row(), "wz-b": b_held}))
    assert status == 3 and "NOT-MEASURED" in shown and '"wz-a": {"lines": 80.0' in shown, shown
    cases += 1

    # A crate the export holds no line of fails; so does a crate with no branch counted.
    status, shown = _run(doc, _table({"wz-a": held, "wz-b": b_held, "wz-c": _row()}))
    assert status == 1 and "FAIL wz-c lines" in shown and "no line" in shown, shown
    no_branch = _export([_file(a_lib, (80, 100), (0, 0), (8, 10))], [])
    status, shown = _run(no_branch, _table({"wz-a": held}))
    assert status == 1 and "branch coverage" in shown, shown
    cases += 1

    # An export that is none is refused.
    for bad in (_export(files, functions, kind="llvm.other"), {"type": EXPORT_TYPE, "data": []}, []):
        status, shown = _run(bad, _table({"wz-a": held}))
        assert status == 1 and "FAIL" in shown, shown
        cases += 1

    # A malformed table is refused, each shape by name.
    for text, needle in (
        (_table({"wz-a": held}, schema="other/1"), "schema"),
        (_table({"wz-a": held}, tolerance=7), "tolerance"),
        (_table({"wz-a": held}, tolerance=True), "tolerance"),
        (_table({}), "holds no crate"),
        (_table({"wz-a": {"lines": 1.0}}), "exactly the keys"),
        (_table({"wz-a": _row(101.0, 1.0, 1.0)}), "percent from 0 to 100"),
        (_table({"wz-a": _row(80.123, 1.0, 1.0)}), "two decimal"),
        (_table({"wz-a": _row("80", 1.0, 1.0)}), "percent from 0 to 100"),
        ('{"about": 1, "about": 2}', "written twice"),
        ("not json", "not JSON"),
    ):
        status, shown = _run(doc, text)
        assert status == 1 and needle in shown, f"a table with {needle!r} was used: {shown}"
        cases += 1

    # --declared ties the table to the lane's crates and to the tree.
    clean = _table({"wz-session-core": _row(), "wz-capi-coop": _row()})
    assert declared(clean, ["wz-session-core", "wz-capi-coop"]) == []
    found = declared(clean, ["wz-session-core"])
    assert any("tests no such crate" in f for f in found), found
    found = declared(clean, ["wz-session-core", "wz-capi-coop", "wz-session-mcu"])
    assert any("has no row" in f for f in found), found
    found = declared(_table({"wz-no-such-crate": _row()}), ["wz-no-such-crate"])
    assert any("not a directory" in f for f in found), found
    cases += 1

    print(f"coverage_floor_gate selftest: {cases} cases pass")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="hold the coverage of each crate to its floor")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--declared", action="store_true", help="check the table and its crates")
    mode.add_argument("--check", type=Path, metavar="EXPORT", help="judge an llvm-cov export")
    mode.add_argument("--fill", type=Path, metavar="EXPORT", help="print the rows an export writes")
    ap.add_argument("--table", type=Path, default=ROOT / TABLE)
    ap.add_argument("--summary-out", type=Path)
    ap.add_argument("--uncovered-out", type=Path)
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    try:
        table_text = args.table.read_text(encoding="utf-8")
    except OSError as error:
        print(f"  coverage-floor FAIL: {args.table} cannot be read: {error}", file=sys.stderr)
        return 1
    if args.declared:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from verify_plan import crates_of

        findings = declared(table_text, crates_of("coverage"))
        for finding in findings:
            print(f"  coverage-floor FAIL: {finding}", file=sys.stderr)
        if findings:
            return 1
        _tolerance, rows = load_table(table_text)
        measured = sum(1 for row in rows.values() for value in row.values() if value is not None)
        print(f"  coverage-floor: {len(rows)} crate(s) declared, {measured} of "
              f"{len(rows) * len(MEASURES)} floor(s) measured")
        return 0
    path = args.check if args.check is not None else args.fill
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"  coverage-floor FAIL: the export {path} cannot be read: {error}", file=sys.stderr)
        return 1
    if args.check is not None:
        for out in (args.summary_out, args.uncovered_out):
            if out is not None:
                out.parent.mkdir(parents=True, exist_ok=True)
        return check(doc, table_text, args.summary_out, args.uncovered_out)
    rows, notes = fill(doc, table_text)
    if rows is None:
        for note in notes:
            print(f"  coverage-floor FAIL: {note}", file=sys.stderr)
        return 1
    for note in notes:
        print(f"  coverage-floor NOTE: {note}", file=sys.stderr)
    print(format_rows(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())

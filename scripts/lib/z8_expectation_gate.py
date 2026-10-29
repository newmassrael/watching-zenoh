#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3932 (no register item) -- Z8 (docs/zenoh-api-on-the-engine.md, section 6): what the upstream
test files must still do.

`z8_upstream_suite.py measure` runs the integration tests of upstream's `zenoh` against the patched
graph and writes one row per file. A measurement nobody compares with anything is a number that
drifts: a repair that breaks a file passes every gate that does not run the file. This gate is
the comparison. `docs/z8-expected.tsv` holds, for each file, the outcome it has and the fewest
tests that pass in it:

    name <TAB> status <TAB> min_passed <TAB> lane <TAB> reason

  * `pass`   the file compiles, runs at least `min_passed` tests and none fails;
  * `fail`   the file compiles and some test fails, as recorded; the gate holds `min_passed`, so a
             test that used to pass and does not is a failure, and the reason says what the others
             wait for;
  * `empty`  the file runs no test, as recorded (its tests are ignored upstream).

A file that does better than its row is not a failure and is reported as a line to raise: the row
is raised in the commit that made it better, so that the next regression is seen.

    z8_expectation_gate.py --names              the files the hosted lane runs, one per line
    z8_expectation_gate.py --check REPORT.tsv   grade the report of a measurement
    z8_expectation_gate.py --selftest           the parser and the verdicts, on text
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXPECTED = ROOT / "docs" / "z8-expected.tsv"

STATUSES = ("pass", "fail", "empty")


def parse_table(text: str) -> dict[str, tuple[str, int, bool, str]]:
    """`name -> (status, min_passed, lane, reason)` of the table; a malformed row is an error."""
    rows: dict[str, tuple[str, int, bool, str]] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        cells = line.split("\t")
        if len(cells) != 5:
            raise ValueError(
                f"line {number}: {len(cells)} cells, 5 expected (name, status, min_passed, lane, reason)"
            )
        name, status, minimum, lane, reason = (cell.strip() for cell in cells)
        if status not in STATUSES:
            raise ValueError(f"line {number}: status {status!r} is not one of {STATUSES}")
        if not minimum.isdigit():
            raise ValueError(f"line {number}: min_passed {minimum!r} is not a count")
        if lane not in ("yes", "no"):
            raise ValueError(f"line {number}: lane {lane!r} is not yes or no")
        if name in rows:
            raise ValueError(f"line {number}: {name} is graded twice")
        rows[name] = (status, int(minimum), lane == "yes", reason)
    return rows


def parse_expected(text: str) -> dict[str, tuple[str, int, str]]:
    """`name -> (status, min_passed, reason)`: the table without its lane column."""
    return {name: (status, minimum, reason) for name, (status, minimum, _lane, reason) in parse_table(text).items()}


def lane_names(text: str) -> list[str]:
    """The files the hosted lane runs, in the order of the table."""
    return [name for name, (_status, _minimum, lane, _reason) in parse_table(text).items() if lane]


def parse_report(text: str) -> dict[str, tuple[str, int]]:
    """`name -> (status, passed)` of a measurement report (`z8_upstream_suite.py measure`)."""
    rows: dict[str, tuple[str, int]] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cells = line.split("\t")
        if len(cells) < 2:
            continue
        passed = re.search(r"\bpassed=(\d+)", cells[2]) if len(cells) > 2 else None
        rows[cells[0]] = (cells[1], int(passed.group(1)) if passed else 0)
    return rows


def grade(
    expected: dict[str, tuple[str, int, str]], measured: dict[str, tuple[str, int]]
) -> tuple[list[str], list[str]]:
    """`(failures, notes)`: a file below its row, and a file above it."""
    failures: list[str] = []
    notes: list[str] = []
    for name, (status, minimum, _reason) in sorted(expected.items()):
        if name not in measured:
            failures.append(f"{name}: not measured, and the table grades it")
            continue
        got_status, passed = measured[name]
        if got_status != status:
            if status in ("fail", "empty") and got_status == "pass":
                notes.append(f"{name}: now passes ({passed} tests); set its row to `pass {passed}`")
                continue
            failures.append(f"{name}: expected {status}, measured {got_status} ({passed} passed)")
            continue
        if passed < minimum:
            failures.append(f"{name}: {passed} tests pass, the row holds {minimum}")
        elif passed > minimum:
            notes.append(f"{name}: {passed} tests pass, the row holds {minimum}; raise it")
    for name in sorted(set(measured) - set(expected)):
        notes.append(f"{name}: measured, and the table does not grade it")
    return failures, notes


def check(report: pathlib.Path) -> int:
    try:
        expected = parse_expected(EXPECTED.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"z8-expectation: {EXPECTED}: {error}")
        return 1
    if not report.is_file():
        print(f"z8-expectation: no report at {report}: the measurement did not write one")
        return 1
    measured = parse_report(report.read_text(encoding="utf-8"))
    # Only the files the measurement covered are graded: a lane that runs a part of the suite
    # grades that part, and a file it does not run is neither passed nor failed.
    scope = {name: row for name, row in expected.items() if name in measured}
    failures, notes = grade(scope, measured)
    for note in notes:
        print(f"z8-expectation: note: {note}")
    for failure in failures:
        print(f"z8-expectation: FAIL: {failure}")
    if not measured:
        print("z8-expectation: FAIL: the report grades no file")
        return 1
    print(
        f"z8-expectation: {len(scope)} of {len(expected)} graded file(s) measured, "
        f"{len(failures)} below the table"
    )
    return 1 if failures else 0


def selftest() -> int:
    text = (
        "# a comment\n"
        "keyexpr\tpass\t15\tyes\tall of it\n"
        "routing\tfail\t6\tyes\tthe linkstate query of a peer\n"
        "open_time\tempty\t0\tyes\tignored upstream\n"
        "regions\tfail\t1\tno\tslow\n"
    )
    table = parse_expected(text)
    assert table["routing"] == ("fail", 6, "the linkstate query of a peer"), table
    assert lane_names(text) == ["keyexpr", "routing", "open_time"], lane_names(text)
    del table["regions"]
    for bad in (
        "a\tpass\n",
        "a\tmaybe\t1\tyes\tx\n",
        "a\tpass\tmany\tyes\tx\n",
        "a\tpass\t1\tsometimes\tx\n",
        "a\tpass\t1\tyes\tx\na\tpass\t1\tyes\tx\n",
    ):
        try:
            parse_expected(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad!r}")
    report = parse_report(
        "# features: unstable\n"
        "keyexpr\tpass\tran=15 passed=15 ignored=0\n"
        "routing\tfail\tran=8 passed=6 ignored=2 [gossip_regression_1]\n"
        "open_time\tempty\tran=0 passed=0 ignored=6\n"
    )
    assert report["routing"] == ("fail", 6), report
    failures, notes = grade(table, report)
    assert failures == [] and notes == [], (failures, notes)
    worse = dict(report, keyexpr=("pass", 14), routing=("fail", 5))
    failures, _ = grade(table, worse)
    assert len(failures) == 2, failures
    broken = dict(report, keyexpr=("fail", 15))
    failures, _ = grade(table, broken)
    assert failures == ["keyexpr: expected pass, measured fail (15 passed)"], failures
    better = dict(report, routing=("pass", 8), keyexpr=("pass", 16))
    failures, notes = grade(table, better)
    assert failures == [] and len(notes) == 2, (failures, notes)
    failures, _ = grade(table, {"keyexpr": ("pass", 15)})
    assert failures and "not measured" in failures[0], failures
    print("z8-expectation selftest: OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", metavar="REPORT", type=pathlib.Path)
    ap.add_argument("--names", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.names:
        try:
            print("\n".join(lane_names(EXPECTED.read_text(encoding="utf-8"))))
        except (OSError, ValueError) as error:
            print(f"z8-expectation: {EXPECTED}: {error}", file=sys.stderr)
            return 1
        return 0
    if args.check:
        return check(args.check)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

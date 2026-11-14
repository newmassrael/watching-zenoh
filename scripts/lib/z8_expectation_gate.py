#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3934 (no register item) -- Z8 (docs/zenoh-api-on-the-engine.md, section 6): what upstream's tests,
its ecosystem crate and its example programs must still do against the patched graph.

`z8_upstream_suite.py` measures the graph in two bridges, and each writes a report that nobody would
compare with anything unless this gate did: a measurement that is not compared drifts, and a repair
that breaks a file passes every gate that does not run the file.

THE TEST BRIDGE (`measure`) runs the integration tests of upstream's `zenoh` and the tests of its
ecosystem crate `zenoh-ext` (the names that begin with `zenoh-ext.`) and writes one row per file.
`docs/z8-expected.tsv` holds, for each, the outcome it has and the fewest tests that pass in it:

    name <TAB> status <TAB> min_passed <TAB> lane <TAB> reason

  * `pass`        the file compiles, runs at least `min_passed` tests and none fails;
  * `fail`        the file compiles and some test fails, as recorded; the gate holds `min_passed`,
                  so a test that used to pass and does not is a failure, and the reason says what
                  the others wait for;
  * `empty`       the file runs no test, as recorded (its tests are ignored upstream);
  * `no-compile`  the file does not compile against the graph, as recorded; the reason names what
                  the graph lacks;
  * `unmeasured`  the row is declared and no measurement has set it yet: whatever is measured is a
                  note that says what to set it to, never a failure.

THE EXAMPLES BRIDGE (`examples-run`) builds upstream's example programs twice, against upstream's
own crates (`stock`, the control) and against the family (`wz`), runs each scenario of
`docs/z8-examples-expected.tsv` on both, and writes one row per scenario. A row of that table
declares the scenario and its verdict:

    name <TAB> roles <TAB> observe <TAB> status <TAB> lane <TAB> reason

`roles` are started in order, separated by ` ; `: `NAME:stand=PROGRAM ARGS` starts a program that
stays up until the scenario ends (it is given a moment to come up before the next one starts), and
`NAME:run:SECONDS=PROGRAM ARGS` starts one and waits for it to end, stopping it after SECONDS.
`observe` is what the scenario must show, separated by ` ; `: `ROLE =N TEXT` (exactly N lines of
the role's output contain TEXT), `ROLE >=N TEXT` (at least N do) and `ROLE exit N` (the role ended
by itself with status N). `{ep}` in an argument or a text is the scenario's endpoint
(`tcp/127.0.0.1:<port>`, a port free when the scenario starts) and `{port}` that port. The
statuses of a scenario:

  * `same`        both arms show every observation, the lines each observation selects have the
                  same shape on both (digits and identities aside) and every role ends the same way;
  * `differs`     the stock arm shows the row and the wz arm does not, or shows it differently;
  * `no-compile`  a program of the scenario does not compile against the family;
  * `unmeasured`  as for the tests.

A measured `control` (the stock arm itself does not show the row) fails a graded row: the row, or
the host it ran on, is wrong, and it judges nothing until it is mended. A file or a scenario that
does better than its row is not a failure and is reported as a line to raise: the row is raised in
the commit that made it better, so that the next regression is seen.

    z8_expectation_gate.py --names [--examples] [--all]  the rows the hosted lane runs (or all)
    z8_expectation_gate.py --check REPORT.tsv             grade the report of the test bridge
    z8_expectation_gate.py --check-examples REPORT.tsv    grade the report of the examples bridge
    z8_expectation_gate.py --selftest                     the parsers and the verdicts, on text
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shlex
import sys
from typing import NamedTuple

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXPECTED = ROOT / "docs" / "z8-expected.tsv"
EXAMPLES_EXPECTED = ROOT / "docs" / "z8-examples-expected.tsv"

STATUSES = ("pass", "fail", "empty", "no-compile", "unmeasured")
EXAMPLE_STATUSES = ("same", "differs", "no-compile", "unmeasured")
#: The order of the measured verdicts of a scenario, worst first: a measurement below its row fails.
EXAMPLE_RANK = {"no-compile": 0, "differs": 1, "same": 2}
#: The words of a role or a text that the harness replaces, one value per scenario run.
PLACEHOLDERS = ("{ep}", "{port}")
#: The separator of the roles and of the observations of a row: a `;` with a space on each side, so
#: that a text may hold a bare `;`.
SEPARATOR = " ; "


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


def lane_names(text: str, all_rows: bool = False) -> list[str]:
    """The files the hosted lane runs (every file with `all_rows`), in the order of the table."""
    return [name for name, (_status, _minimum, lane, _reason) in parse_table(text).items() if lane or all_rows]


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
        if status == "unmeasured":
            notes.append(f"{name}: measured {got_status} ({passed} tests pass); set its row to `{got_status} {passed}`")
            continue
        if got_status != status:
            if status in ("fail", "empty") and got_status == "pass":
                notes.append(f"{name}: now passes ({passed} tests); set its row to `pass {passed}`")
                continue
            if status == "no-compile":
                # Any outcome of a file that compiles is one a file that does not compile is below.
                notes.append(f"{name}: compiles now and is {got_status} ({passed} tests pass); set its row")
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


class Role(NamedTuple):
    """One program of a scenario: `stand` stays up to the end, `run` is waited for `seconds`."""

    name: str
    mode: str
    seconds: float
    program: str
    args: tuple[str, ...]


class Observation(NamedTuple):
    """What a role must show: `=` or `>=` a count of lines that contain `text`, or `exit` a status."""

    role: str
    op: str
    count: int
    text: str


class Scenario(NamedTuple):
    roles: tuple[Role, ...]
    observations: tuple[Observation, ...]
    status: str
    lane: bool
    reason: str


ROLE = re.compile(r"^([a-z][a-z0-9_]*):(stand|run)(?::(\d+(?:\.\d+)?))?=(z_[a-z0-9_]+)(?:\s+(.*))?$")
OBSERVATION = re.compile(r"^([a-z][a-z0-9_]*)\s+(?:(>=|=)(\d+)\s+(\S.*)|exit\s+(-?\d+))$")


def check_placeholders(text: str, number: int) -> None:
    """Refuse a word in braces that is not a placeholder: `{prot}` is a typo, not a literal. A brace
    that does not hold one word (`Hello { zid: .. }`, a line a program prints) is text."""
    for word in re.findall(r"\{[a-z_]+\}", text):
        if word not in PLACEHOLDERS:
            raise ValueError(f"line {number}: {word} is not one of the placeholders {PLACEHOLDERS}")


def parse_roles(cell: str, number: int) -> tuple[Role, ...]:
    roles: list[Role] = []
    for part in (p.strip() for p in cell.split(SEPARATOR)):
        m = ROLE.match(part)
        if not m:
            raise ValueError(
                f"line {number}: role {part!r} is neither `NAME:stand=PROGRAM ARGS` nor `NAME:run:SECONDS=PROGRAM ARGS`"
            )
        name, mode, seconds, program, rest = m.groups()
        if mode == "run" and seconds is None:
            raise ValueError(f"line {number}: the run role {name} does not say how many seconds it may run")
        if mode == "stand" and seconds is not None:
            raise ValueError(f"line {number}: the stand role {name} runs to the end of the scenario and takes no seconds")
        if any(role.name == name for role in roles):
            raise ValueError(f"line {number}: the role {name} is declared twice")
        args = tuple(shlex.split(rest or ""))
        check_placeholders(" ".join(args), number)
        roles.append(Role(name, mode, float(seconds) if seconds else 0.0, program, args))
    return tuple(roles)


def parse_observations(cell: str, roles: tuple[Role, ...], number: int) -> tuple[Observation, ...]:
    names = {role.name for role in roles}
    out: list[Observation] = []
    for part in (p.strip() for p in cell.split(SEPARATOR)):
        m = OBSERVATION.match(part)
        if not m:
            raise ValueError(
                f"line {number}: observation {part!r} is none of `ROLE =N TEXT`, `ROLE >=N TEXT`, `ROLE exit N`"
            )
        role, op, count, text, code = m.groups()
        if role not in names:
            raise ValueError(f"line {number}: the observation names the role {role}, which the row does not declare")
        if code is not None:
            out.append(Observation(role, "exit", int(code), ""))
            continue
        check_placeholders(text, number)
        out.append(Observation(role, op, int(count), text))
    return tuple(out)


def parse_examples_table(text: str) -> dict[str, Scenario]:
    """`name -> Scenario` of the examples table; a malformed row is an error."""
    rows: dict[str, Scenario] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        cells = line.split("\t")
        if len(cells) != 6:
            raise ValueError(
                f"line {number}: {len(cells)} cells, 6 expected (name, roles, observe, status, lane, reason)"
            )
        name, roles_cell, observe_cell, status, lane, reason = (cell.strip() for cell in cells)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
            raise ValueError(f"line {number}: the name {name!r} is not a word of lower-case letters, digits and `_`")
        if status not in EXAMPLE_STATUSES:
            raise ValueError(f"line {number}: status {status!r} is not one of {EXAMPLE_STATUSES}")
        if lane not in ("yes", "no"):
            raise ValueError(f"line {number}: lane {lane!r} is not yes or no")
        if name in rows:
            raise ValueError(f"line {number}: {name} is declared twice")
        roles = parse_roles(roles_cell, number)
        rows[name] = Scenario(roles, parse_observations(observe_cell, roles, number), status, lane == "yes", reason)
    return rows


def example_lane_names(text: str, all_rows: bool = False) -> list[str]:
    """The scenarios the hosted lane runs (every scenario with `all_rows`), in the order of the table."""
    return [name for name, row in parse_examples_table(text).items() if row.lane or all_rows]


def parse_examples_report(text: str) -> dict[str, str]:
    """`name -> status` of a report of the examples bridge (`z8_upstream_suite.py examples-run`)."""
    rows: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cells = line.split("\t")
        if len(cells) >= 2:
            rows[cells[0]] = cells[1]
    return rows


def grade_examples(expected: dict[str, str], measured: dict[str, str]) -> tuple[list[str], list[str]]:
    """`(failures, notes)` of a report of the examples bridge against `name -> status` of the table."""
    failures: list[str] = []
    notes: list[str] = []
    for name, status in sorted(expected.items()):
        if name not in measured:
            failures.append(f"{name}: not measured, and the table grades it")
            continue
        got = measured[name]
        if status == "unmeasured":
            if got == "control":
                notes.append(f"{name}: the stock arm does not show the row; mend the row before it is set")
            else:
                notes.append(f"{name}: measured {got}; set its row to `{got}`")
            continue
        if got == "control":
            failures.append(
                f"{name}: the stock arm does not show the row, so the row judges nothing: the row or the host is wrong"
            )
            continue
        if got not in EXAMPLE_RANK:
            failures.append(f"{name}: measured {got!r}, which is no verdict of a scenario")
            continue
        if EXAMPLE_RANK[got] < EXAMPLE_RANK[status]:
            failures.append(f"{name}: expected {status}, measured {got}")
        elif EXAMPLE_RANK[got] > EXAMPLE_RANK[status]:
            notes.append(f"{name}: now {got}, the row holds {status}; set its row to `{got}`")
    for name in sorted(set(measured) - set(expected)):
        notes.append(f"{name}: measured, and the table does not declare it")
    return failures, notes


def verdict(prefix: str, failures: list[str], notes: list[str], scope: int, total: int, unit: str) -> int:
    for note in notes:
        print(f"{prefix}: note: {note}")
    for failure in failures:
        print(f"{prefix}: FAIL: {failure}")
    print(f"{prefix}: {scope} of {total} graded {unit} measured, {len(failures)} below the table")
    return 1 if failures else 0


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
    if not measured:
        print("z8-expectation: FAIL: the report grades no file")
        return 1
    # Only the files the measurement covered are graded: a lane that runs a part of the suite
    # grades that part, and a file it does not run is neither passed nor failed.
    scope = {name: row for name, row in expected.items() if name in measured}
    failures, notes = grade(scope, measured)
    return verdict("z8-expectation", failures, notes, len(scope), len(expected), "file(s)")


def check_examples(report: pathlib.Path) -> int:
    try:
        expected = {name: row.status for name, row in parse_examples_table(EXAMPLES_EXPECTED.read_text(encoding="utf-8")).items()}
    except (OSError, ValueError) as error:
        print(f"z8-examples-expectation: {EXAMPLES_EXPECTED}: {error}")
        return 1
    if not report.is_file():
        print(f"z8-examples-expectation: no report at {report}: the examples bridge did not write one")
        return 1
    measured = parse_examples_report(report.read_text(encoding="utf-8"))
    if not measured:
        print("z8-examples-expectation: FAIL: the report grades no scenario")
        return 1
    scope = {name: status for name, status in expected.items() if name in measured}
    failures, notes = grade_examples(scope, measured)
    return verdict("z8-examples-expectation", failures, notes, len(scope), len(expected), "scenario(s)")


def selftest_tests() -> None:
    text = (
        "# a comment\n"
        "keyexpr\tpass\t15\tyes\tall of it\n"
        "routing\tfail\t6\tyes\tthe linkstate query of a peer\n"
        "open_time\tempty\t0\tyes\tignored upstream\n"
        "regions\tfail\t1\tno\tslow\n"
        "zenoh-ext.lib\tunmeasured\t0\tyes\tnot measured yet\n"
        "zenoh-ext.advanced\tno-compile\t0\tno\tthe graph lacks the task crate\n"
    )
    table = parse_expected(text)
    assert table["routing"] == ("fail", 6, "the linkstate query of a peer"), table
    assert lane_names(text) == ["keyexpr", "routing", "open_time", "zenoh-ext.lib"], lane_names(text)
    assert lane_names(text, all_rows=True) == [
        "keyexpr", "routing", "open_time", "regions", "zenoh-ext.lib", "zenoh-ext.advanced"
    ], lane_names(text, all_rows=True)
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
        "zenoh-ext.lib\tno-compile\terror[E0432]: unresolved import\n"
        "zenoh-ext.advanced\tno-compile\terror[E0432]: unresolved import\n"
    )
    assert report["routing"] == ("fail", 6), report
    assert report["zenoh-ext.lib"] == ("no-compile", 0), report
    failures, notes = grade(table, report)
    # The unmeasured row is a note that names what to set it to, never a failure.
    assert failures == [] and notes == ["zenoh-ext.lib: measured no-compile (0 tests pass); set its row to `no-compile 0`"], (
        failures, notes)
    worse = dict(report, keyexpr=("pass", 14), routing=("fail", 5))
    failures, _ = grade(table, worse)
    assert len(failures) == 2, failures
    broken = dict(report, keyexpr=("fail", 15))
    failures, _ = grade(table, broken)
    assert failures == ["keyexpr: expected pass, measured fail (15 passed)"], failures
    better = dict(report, routing=("pass", 8), keyexpr=("pass", 16))
    failures, notes = grade(table, better)
    assert failures == [] and len(notes) == 3, (failures, notes)
    # A file recorded as not compiling that compiles is a line to raise; one recorded as compiling
    # that does not is a failure.
    compiles = dict(report, **{"zenoh-ext.advanced": ("fail", 3)})
    failures, notes = grade(table, compiles)
    assert failures == [] and any(n.startswith("zenoh-ext.advanced: compiles now and is fail") for n in notes), notes
    regressed = dict(report, keyexpr=("no-compile", 0))
    failures, _ = grade(table, regressed)
    assert failures == ["keyexpr: expected pass, measured no-compile (0 passed)"], failures
    failures, _ = grade(table, {"keyexpr": ("pass", 15)})
    assert failures and "not measured" in failures[0], failures


def selftest_examples() -> None:
    text = (
        "# scenarios\n"
        "put_sub\tsub:stand=z_sub -l {ep} --no-multicast-scouting ; put:run:10=z_put -e {ep}\t"
        "sub =1 >> [Subscriber] Received PUT ('demo/example/zenoh-rs-put': 'Put from Rust!') ; put exit 0\t"
        "same\tyes\tmeasured\n"
        "pub_sub\tsub:stand=z_sub -l {ep} ; pub:run:6=z_pub -e {ep} -p 'a b;c'\t"
        "sub >=3 Received PUT ('demo/example/zenoh-rs-pub': '[\tdiffers\tno\tthe count\n"
        "scout\tsub:stand=z_sub -l {ep} ; scout:run:5=z_scout\tscout >=1 locators: [tcp/127.0.0.1:{port}]\t"
        "unmeasured\tno\tnot measured\n"
        "forward\tf:stand=z_forward -l {ep} ; put:run:10=z_put -e {ep}\tf exit 0\tno-compile\tyes\tthe task crate\n"
    )
    rows = parse_examples_table(text)
    assert list(rows) == ["put_sub", "pub_sub", "scout", "forward"], rows
    put_sub = rows["put_sub"]
    assert put_sub.roles == (
        Role("sub", "stand", 0.0, "z_sub", ("-l", "{ep}", "--no-multicast-scouting")),
        Role("put", "run", 10.0, "z_put", ("-e", "{ep}")),
    ), put_sub.roles
    assert put_sub.observations == (
        Observation("sub", "=", 1, ">> [Subscriber] Received PUT ('demo/example/zenoh-rs-put': 'Put from Rust!')"),
        Observation("put", "exit", 0, ""),
    ), put_sub.observations
    # Quoted arguments are one word, and a bare `;` inside one is not a separator.
    assert rows["pub_sub"].roles[1].args == ("-e", "{ep}", "-p", "a b;c"), rows["pub_sub"].roles
    assert rows["pub_sub"].observations[0].op == ">=" and rows["pub_sub"].observations[0].count == 3
    assert example_lane_names(text) == ["put_sub", "forward"], example_lane_names(text)
    assert example_lane_names(text, all_rows=True) == ["put_sub", "pub_sub", "scout", "forward"]
    for bad in (
        "a\tsub:stand=z_sub\tsub exit 0\tsame\tyes\n",
        "A\tsub:stand=z_sub\tsub exit 0\tsame\tyes\tx\n",
        "a\tsub:stand=z_sub\tsub exit 0\tmaybe\tyes\tx\n",
        "a\tsub:stand=z_sub\tsub exit 0\tsame\tsometimes\tx\n",
        "a\tsub:run=z_sub\tsub exit 0\tsame\tyes\tx\n",
        "a\tsub:stand:3=z_sub\tsub exit 0\tsame\tyes\tx\n",
        "a\tsub:stand=sub\tsub exit 0\tsame\tyes\tx\n",
        "a\tsub:stand=z_sub ; sub:run:1=z_put\tsub exit 0\tsame\tyes\tx\n",
        "a\tsub:stand=z_sub -l {prot}\tsub exit 0\tsame\tyes\tx\n",
        "a\tsub:stand=z_sub\tpub exit 0\tsame\tyes\tx\n",
        "a\tsub:stand=z_sub\tsub ~1 text\tsame\tyes\tx\n",
        "a\tsub:stand=z_sub\tsub =1\tsame\tyes\tx\n",
        "a\tsub:stand=z_sub\tsub =1 at {where}\tsame\tyes\tx\n",
        "a\tsub:stand=z_sub\tsub exit 0\tsame\tyes\tx\na\tsub:stand=z_sub\tsub exit 0\tsame\tyes\tx\n",
    ):
        try:
            parse_examples_table(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad!r}")
    # A brace that holds no single word is text a program prints, not a placeholder.
    parse_examples_table("a\ts:run:5=z_scout\ts >=1 Hello { zid: x }\tunmeasured\tno\tx\n")
    expected = {name: row.status for name, row in rows.items()}
    report = parse_examples_report(
        "# arms: stock wz\nput_sub\tsame\tsub =1: stock 1, wz 1\npub_sub\tdiffers\tsub >=3: stock 5, wz 0\n"
        "scout\tcontrol\tscout >=1: stock 0\nforward\tno-compile\tz_forward: error[E0432]\n"
    )
    assert report == {"put_sub": "same", "pub_sub": "differs", "scout": "control", "forward": "no-compile"}, report
    failures, notes = grade_examples(expected, report)
    assert failures == [] and notes == ["scout: the stock arm does not show the row; mend the row before it is set"], (
        failures, notes)
    worse = dict(report, put_sub="differs", pub_sub="no-compile")
    failures, _ = grade_examples(expected, worse)
    assert failures == ["pub_sub: expected differs, measured no-compile", "put_sub: expected same, measured differs"], failures
    better = dict(report, pub_sub="same", forward="differs", scout="same")
    failures, notes = grade_examples(expected, better)
    assert failures == [] and notes == [
        "forward: now differs, the row holds no-compile; set its row to `differs`",
        "pub_sub: now same, the row holds differs; set its row to `same`",
        "scout: measured same; set its row to `same`",
    ], (failures, notes)
    # A control that fails a graded row is a failure whatever the wz arm did.
    failures, _ = grade_examples(expected, dict(report, put_sub="control"))
    assert failures and failures[0].startswith("put_sub: the stock arm does not show the row"), failures
    failures, _ = grade_examples(expected, dict(report, put_sub="timeout"))
    assert failures == ["put_sub: measured 'timeout', which is no verdict of a scenario"], failures
    failures, notes = grade_examples({"put_sub": "same"}, {"put_sub": "same", "other": "same"})
    assert failures == [] and notes == ["other: measured, and the table does not declare it"], notes
    failures, _ = grade_examples(expected, {"put_sub": "same"})
    assert failures and all("not measured" in f for f in failures), failures


def selftest() -> int:
    selftest_tests()
    selftest_examples()
    # The committed tables parse: a row this gate refuses would fail the lane only once it ran.
    parse_table(EXPECTED.read_text(encoding="utf-8"))
    parse_examples_table(EXAMPLES_EXPECTED.read_text(encoding="utf-8"))
    print("z8-expectation selftest: OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", metavar="REPORT", type=pathlib.Path)
    ap.add_argument("--check-examples", metavar="REPORT", type=pathlib.Path)
    ap.add_argument("--names", action="store_true")
    ap.add_argument("--examples", action="store_true", help="--names: the scenarios of the examples table")
    ap.add_argument("--all", action="store_true", help="--names: every row, the lane's and the others")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.names:
        table = EXAMPLES_EXPECTED if args.examples else EXPECTED
        try:
            text = table.read_text(encoding="utf-8")
            names = example_lane_names(text, args.all) if args.examples else lane_names(text, args.all)
        except (OSError, ValueError) as error:
            print(f"z8-expectation: {table}: {error}", file=sys.stderr)
            return 1
        print("\n".join(names))
        return 0
    if args.check:
        return check(args.check)
    if args.check_examples:
        return check_examples(args.check_examples)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

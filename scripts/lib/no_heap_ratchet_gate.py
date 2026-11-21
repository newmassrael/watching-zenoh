#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4584 (no register item) -- what the pico C ABI on the cooperative engine allocates after a
session opens, held per operation family so that it can only fall, until it is zero.

## The target

The owner's decision of 2026-11-21: the pico C ABI runs on the cooperative engine with no heap
after a session opens. Every byte a session needs is reserved at open from the configured limits
(docs/upstream-parity.md D12). The migration is held by this ratchet: the allocations a family of
operations makes after open may only fall, and a family that reached zero is locked there.

## The reading

Layer C1nh runs `crates/wz-capi-pico/tests/no_heap_after_open.rs` on the cooperative engine. Once two
sessions are open over the program's own transport, each family runs a warm-up and then a fixed
number of rounds with the allocator counting, and the test prints one line a family:

    no-heap: <family> allocs=<n> bytes=<b> rounds=<r>
    no-heap: <family> not-built

The gate reads every line that carries `no-heap:` (libtest may write the test's name on that line
before it) and no other line. A line that carries it and is neither form is refused, as is a
family read twice and a count of no round: a reading that cannot be read is not read as clean.

## The table

`deploy/no_heap_ratchet.json`, schema `wz-no-heap-ratchet/1`: a `tolerance` and one row a family,

    {"allocs_per_round": <number or null>, "locked": <bool>, "debt": <id or null>}

`allocs_per_round` is the reading's allocations over its rounds rounded up to three places. A row
at 0 is locked, a locked row holds 0 and owes no debt, and a row above 0 or not measured yet
names the store inventory entry it is registered under (`debt-<id>`), or `debt-TBD` until it is.

## The rules of --check

    a family above its row times one plus the tolerance           FAIL
    a locked family that allocates at all                          FAIL
    a family of the table the reading has no line for              FAIL
    a family of the reading the table has no row for               FAIL
    a row above 0 whose debt is still the placeholder              FAIL
    a malformed reading or table                                   FAIL
    a row not filled yet, or a family the build did not have       NOT-MEASURED
    a family below its row                                         PASS, the tighter row printed
    a family that read 0                                           PASS, the locked row printed

NOT-MEASURED is never a pass: the exit status is 1 for a FAIL, 3 for NOT-MEASURED and no FAIL,
and 0 only when every row was judged and held.

## Modes

    --selftest           every rule driven through a fixture that breaks it, and a clean one
    --declared           the table well formed, and its families exactly the ones the test
                         declares (Layer C0, no build)
    --check READING      judge a reading against the table
    --fill READING       print the `families` object a reading writes, to commit; a filled row is
                         never loosened by it

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
TABLE = Path("deploy/no_heap_ratchet.json")
# The test whose families the table holds; `--declared` reads their names from it.
TEST_FILE = Path("crates/wz-capi-pico/tests/no_heap_after_open.rs")
SCHEMA = "wz-no-heap-ratchet/1"
TABLE_KEYS = {"about", "schema", "tolerance", "families"}
ROW_KEYS = {"allocs_per_round", "locked", "debt"}
PREFIX = "no-heap:"
NOT_BUILT = "not-built"
FAMILY_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
MEASURED = re.compile(r"^allocs=(\d+) bytes=(\d+) rounds=(\d+)$")
# A debt is an entry of the store's inventory (`debt-<id>`), as every new open debt is; the
# placeholder stands only until the row is measured.
DEBT_ID = re.compile(r"debt-[a-z0-9][a-z0-9-]*")
DEBT_PLACEHOLDER = "debt-TBD"
# A row is the reading's allocations a round rounded UP to three places, so the ceiling never
# sits under the reading it was set from.
PLACES = 1000
# One family of the test's `FAMILIES` table: `("<name>", Round::<round>, Part::<part>)`.
DECLARED_FAMILY = re.compile(r'^\s*\("([^"]+)",\s*Round::\w+,\s*Part::\w+\),?\s*$', re.M)
LAYER = "C1nh"


class Refused(Exception):
    """A table that cannot be read as one."""


@dataclass(frozen=True)
class Reading:
    """One family's line: its counts, or None for each when the build has not the family."""

    family: str
    allocs: int | None
    nbytes: int | None
    rounds: int | None

    @property
    def built(self) -> bool:
        return self.allocs is not None

    def ceiling(self) -> float:
        """The allocations a round, rounded up to three places."""
        assert self.allocs is not None and self.rounds
        return -(-self.allocs * PLACES // self.rounds) / PLACES

    def shown(self) -> str:
        return (f"{self.allocs} allocation(s) of {self.nbytes} byte(s) in {self.rounds} round(s), "
                f"{self.allocs / self.rounds:.3f} a round")


@dataclass(frozen=True)
class Row:
    ceiling: float | None
    locked: bool
    debt: str | None


@dataclass(frozen=True)
class Judged:
    """One family's outcome (PASS, FAIL, NOT-MEASURED), the sentence that says why, and the row to
    commit in its place when there is one to suggest."""

    family: str
    outcome: str
    sentence: str
    edit: dict | None = None


def parse_reading(text: str) -> tuple[dict[str, Reading], list[str]]:
    """The families a reading holds, and what in it could not be read."""
    found: dict[str, Reading] = {}
    findings: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        at = line.find(PREFIX)
        if at < 0:
            continue
        family, _, body = line[at + len(PREFIX):].strip().partition(" ")
        where = f"reading line {number} ({line.strip()!r})"
        if not FAMILY_NAME.match(family):
            findings.append(f"{where}: names no family (lowercase letters, digits and '-')")
            continue
        body = body.strip()
        if body == NOT_BUILT:
            reading = Reading(family, None, None, None)
        else:
            measured = MEASURED.match(body)
            if measured is None:
                findings.append(f"{where}: is neither `allocs=<n> bytes=<b> rounds=<r>` nor `not-built`")
                continue
            allocs, nbytes, rounds = (int(g) for g in measured.groups())
            if rounds == 0:
                findings.append(f"{where}: counts no round, so it measures nothing")
                continue
            reading = Reading(family, allocs, nbytes, rounds)
        if family in found:
            findings.append(f"{where}: family {family} is read twice")
            continue
        found[family] = reading
    if not found and not findings:
        findings.append(f"the reading holds no `{PREFIX}` line: the measurement did not run, or "
                        f"printed nothing this gate reads")
    return found, findings


def _number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def parse_row(family: str, row: object) -> tuple[Row | None, list[str]]:
    """The row, or what is wrong with it."""
    if not isinstance(row, dict) or set(row) != ROW_KEYS:
        return None, [f"{family}: a row has exactly the keys {', '.join(sorted(ROW_KEYS))}"]
    ceiling, locked, debt = row["allocs_per_round"], row["locked"], row["debt"]
    out: list[str] = []
    if ceiling is not None and (not _number(ceiling) or ceiling < 0):
        out.append(f"{family}: allocs_per_round is null or a number of at least 0, not {ceiling!r}")
    elif ceiling is not None and abs(ceiling * PLACES - round(ceiling * PLACES)) > 1e-6:
        out.append(f"{family}: allocs_per_round {ceiling} has more than three decimal places, which "
                   f"no row --fill writes has")
    if not isinstance(locked, bool):
        out.append(f"{family}: locked is true or false, not {locked!r}")
    if debt is not None and not (isinstance(debt, str)
                                 and (DEBT_ID.fullmatch(debt) or debt == DEBT_PLACEHOLDER)):
        out.append(f"{family}: debt is null, `debt-<id>` or {DEBT_PLACEHOLDER}, not {debt!r}")
    if out:
        return None, out
    if locked:
        if ceiling != 0:
            out.append(f"{family}: a locked row holds 0 allocations a round, not {ceiling}")
        if debt is not None:
            out.append(f"{family}: a locked row owes nothing, so its debt is null, not {debt}")
    elif ceiling == 0:
        out.append(f"{family}: a row at 0 is locked: write {format_row(family, LOCKED_ROW)}")
    elif debt is None:
        out.append(f"{family}: a row above 0 or not measured yet names the debt it is registered "
                   f"under (`debt-<id>`, or {DEBT_PLACEHOLDER} until it is)")
    return (None if out else Row(ceiling, locked, debt)), out


def parse_table(doc: object) -> tuple[float, dict[str, Row]]:
    """The tolerance and the rows of a table document; Refused with every finding when it is not
    one this gate can use."""
    if not isinstance(doc, dict) or set(doc) != TABLE_KEYS:
        raise Refused(f"the table is an object with exactly the keys {', '.join(sorted(TABLE_KEYS))}")
    findings: list[str] = []
    if doc["schema"] != SCHEMA:
        findings.append(f"the schema is not {SCHEMA}")
    tolerance = doc["tolerance"]
    if not _number(tolerance) or not 0 <= tolerance < 1:
        findings.append("`tolerance` is a number from 0 up to, not including, 1")
    raw = doc["families"]
    rows: dict[str, Row] = {}
    if not isinstance(raw, dict) or not raw:
        findings.append("`families` holds no family, and a table of none holds nothing")
    else:
        for family, body in raw.items():
            if not FAMILY_NAME.match(family):
                findings.append(f"{family!r}: a family name is lowercase letters, digits and '-'")
                continue
            row, found = parse_row(family, body)
            findings += found
            if row is not None:
                rows[family] = row
    if findings:
        raise Refused("; ".join(findings))
    return float(tolerance), rows


def refuse_duplicates(pairs: list[tuple[str, object]]) -> dict:
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise Refused(f"the key {key} is written twice")
        seen[key] = value
    return seen


def load_table(text: str) -> tuple[float, dict[str, Row]]:
    try:
        doc = json.loads(text, object_pairs_hook=refuse_duplicates)
    except ValueError as error:
        raise Refused(f"not JSON: {error}") from None
    return parse_table(doc)


LOCKED_ROW = {"allocs_per_round": 0, "locked": True, "debt": None}


def format_row(family: str, row: dict) -> str:
    return f"{json.dumps(family)}: {json.dumps(row)}"


def row_json(row: Row) -> dict:
    return {"allocs_per_round": row.ceiling, "locked": row.locked, "debt": row.debt}


def fill_row(reading: Reading, row: Row | None) -> dict:
    """The row a measured reading writes: locked at 0, or its ceiling with the debt the row names
    (the placeholder for a family that had none)."""
    if reading.allocs == 0:
        return dict(LOCKED_ROW)
    debt = row.debt if row is not None and row.debt is not None else DEBT_PLACEHOLDER
    return {"allocs_per_round": reading.ceiling(), "locked": False, "debt": debt}


def judge(found: dict[str, Reading], rows: dict[str, Row], tolerance: float) -> list[Judged]:
    """Every family of the table and of the reading, judged."""
    out: list[Judged] = []
    for family in sorted(set(found) | set(rows)):
        reading, row = found.get(family), rows.get(family)
        if row is None:
            assert reading is not None
            edit = fill_row(reading, None) if reading.built else None
            out.append(Judged(family, "FAIL", "the reading has this family and the table has no row "
                                              "for it: a row is added with the family, never left out",
                              edit))
            continue
        if reading is None:
            out.append(Judged(family, "FAIL", "the table holds this family and the reading has no "
                                              "line for it: the measurement stopped counting it, or "
                                              "stopped before it"))
            continue
        if not reading.built:
            out.append(Judged(family, "NOT-MEASURED", "the build that was measured has not this "
                                                      "family's capability (not-built), so its row "
                                                      "is not judged"))
            continue
        shown = reading.shown()
        if row.ceiling is None:
            out.append(Judged(family, "NOT-MEASURED", f"{shown}; the row is not filled, so nothing "
                                                      f"holds the family yet: commit the row below",
                              fill_row(reading, row)))
            continue
        if row.locked:
            if reading.allocs == 0:
                out.append(Judged(family, "PASS", f"{shown}; locked at 0"))
            else:
                out.append(Judged(family, "FAIL", f"{shown}; the family is locked at 0 allocations a "
                                                  f"round, so what allocates after open again is the "
                                                  f"regression to take back"))
            continue
        per_round = reading.allocs / reading.rounds
        if per_round > row.ceiling * (1 + tolerance):
            out.append(Judged(family, "FAIL", f"{shown}; above the row's {row.ceiling} a round by more "
                                              f"than the tolerance {tolerance}: allocations after open "
                                              f"may only fall"))
            continue
        if row.debt is None or not DEBT_ID.fullmatch(row.debt):
            out.append(Judged(family, "FAIL", f"{shown}; a family that still allocates is an open debt, "
                                              f"and its row names {row.debt!r}: register it in the "
                                              f"store's inventory and write its `debt-<id>`"))
            continue
        if reading.allocs == 0:
            out.append(Judged(family, "PASS", f"{shown}; it reached 0, so lock the row and close "
                                              f"{row.debt}", dict(LOCKED_ROW)))
        elif reading.ceiling() < row.ceiling:
            out.append(Judged(family, "PASS", f"{shown}; under the row's {row.ceiling}, so tighten it",
                              fill_row(reading, row)))
        else:
            out.append(Judged(family, "PASS", f"{shown}; within the row's {row.ceiling}"))
    return out


def exit_status(judged: list[Judged], findings: list[str]) -> int:
    outcomes = {j.outcome for j in judged}
    if findings or "FAIL" in outcomes:
        return 1
    return 3 if "NOT-MEASURED" in outcomes else 0


def check(reading_text: str, table_text: str) -> int:
    """Judge a reading against a table, print every family's outcome, and return the status."""
    try:
        tolerance, rows = load_table(table_text)
    except Refused as why:
        print(f"  no-heap-ratchet FAIL: the table is refused: {why}", file=sys.stderr)
        return 1
    found, findings = parse_reading(reading_text)
    for finding in findings:
        print(f"  no-heap-ratchet FAIL: {finding}", file=sys.stderr)
    if findings:
        return 1
    judged = judge(found, rows, tolerance)
    for j in judged:
        stream = sys.stderr if j.outcome == "FAIL" else sys.stdout
        print(f"  no-heap-ratchet {j.outcome} {j.family}: {j.sentence}", file=stream)
        if j.edit is not None:
            print(f"  no-heap-ratchet ROW (commit it): {format_row(j.family, j.edit)}", file=stream)
    status = exit_status(judged, findings)
    counts = {o: sum(1 for j in judged if j.outcome == o) for o in ("PASS", "FAIL", "NOT-MEASURED")}
    verdict = {0: "PASS", 1: "FAIL", 3: "NOT-MEASURED"}[status]
    print(f"  no-heap-ratchet: {verdict}, {len(judged)} family(ies): {counts['PASS']} held, "
          f"{counts['FAIL']} failed, {counts['NOT-MEASURED']} not measured (Layer {LAYER})")
    return status


def fill(reading_text: str, table_text: str) -> tuple[dict | None, list[str]]:
    """The `families` object a reading writes over a table, and what kept it from being written.
    A filled row is never loosened: a reading above it keeps the row and says so."""
    try:
        _tolerance, rows = load_table(table_text)
    except Refused as why:
        return None, [f"the table is refused: {why}"]
    found, findings = parse_reading(reading_text)
    if findings:
        return None, findings
    notes: list[str] = []
    out: dict[str, dict] = {}
    for family in sorted(set(rows) | set(found)):
        row, reading = rows.get(family), found.get(family)
        if reading is None or not reading.built:
            out[family] = row_json(row) if row is not None else {
                "allocs_per_round": None, "locked": False, "debt": DEBT_PLACEHOLDER}
            continue
        written = fill_row(reading, row)
        if row is not None and row.ceiling is not None and written["allocs_per_round"] > row.ceiling:
            notes.append(f"{family}: the reading ({reading.shown()}) is above its row, which is "
                         f"kept: a fill never loosens a row")
            written = row_json(row)
        out[family] = written
    return out, notes


def declared_families(text: str) -> list[str]:
    return DECLARED_FAMILY.findall(text)


def declared(table_text: str, test_text: str) -> list[str]:
    """What keeps the table from holding exactly the families the test declares."""
    try:
        _tolerance, rows = load_table(table_text)
    except Refused as why:
        return [f"the table is refused: {why}"]
    families = declared_families(test_text)
    if not families:
        return [f"{TEST_FILE} declares no family this gate can read (`('<name>', Round, Part)` "
                f"in `FAMILIES`): the reader stopped matching, which a green would hide"]
    out = [f"family {f} is declared twice in {TEST_FILE}" for f in sorted(set(families))
           if families.count(f) > 1]
    out += [f"family {f} is measured by {TEST_FILE} and has no row in the table: a row is added "
            f"with the family" for f in sorted(set(families) - set(rows))]
    out += [f"family {f} has a row and {TEST_FILE} measures no such family" for f in
            sorted(set(rows) - set(families))]
    return out


# ---------------------------------------------------------------------------------------------
# The selftest.

def _table(**rows: dict) -> str:
    return json.dumps({"about": "fixture", "schema": SCHEMA, "tolerance": 0.05, "families": rows})


def _row(ceiling: float | None, locked: bool = False, debt: str | None = "debt-demo") -> dict:
    return {"allocs_per_round": ceiling, "locked": locked, "debt": debt}


def _line(family: str, allocs: int, rounds: int = 100, nbytes: int = 640) -> str:
    return f"{PREFIX} {family} allocs={allocs} bytes={nbytes} rounds={rounds}"


def _run(reading: str, table: str) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = check(reading, table)
    return status, out.getvalue() + err.getvalue()


def selftest() -> int:
    cases = 0
    base = _table(**{"put-small": _row(2.0), "get": _row(0, locked=True, debt=None)})
    clean = "\n".join(["   Compiling noise", "test allocations ... " + _line("put-small", 200),
                       _line("get", 0), "test result: ok. 1 passed"])

    status, shown = _run(clean, base)
    assert status == 0, (status, shown)
    assert "FAIL" not in shown, shown
    cases += 1

    # A rise above the row by more than the tolerance fails; within the tolerance it holds.
    status, shown = _run(clean.replace("allocs=200", "allocs=211"), base)
    assert status == 1 and "FAIL put-small" in shown and "may only fall" in shown, shown
    cases += 1
    status, shown = _run(clean.replace("allocs=200", "allocs=209"), base)
    assert status == 0, f"a reading within the tolerance failed: {shown}"
    cases += 1

    # A fall passes and prints the tighter row; a fall to 0 prints the locked row.
    status, shown = _run(clean.replace("allocs=200", "allocs=150"), base)
    assert status == 0, shown
    assert format_row("put-small", _row(1.5)) in shown, f"a fall printed no row to commit: {shown}"
    cases += 1
    status, shown = _run(clean.replace("allocs=200", "allocs=0"), base)
    assert status == 0 and format_row("put-small", LOCKED_ROW) in shown, shown
    cases += 1

    # The ceiling is rounded up, never down: 1 in 3 rounds is 0.334.
    assert Reading("x", 1, 0, 3).ceiling() == 0.334, Reading("x", 1, 0, 3).ceiling()
    cases += 1

    # A locked row above 0 fails.
    status, shown = _run(clean.replace(_line("get", 0), _line("get", 1)), base)
    assert status == 1 and "FAIL get" in shown and "locked at 0" in shown, shown
    cases += 1

    # A family of the table the reading lacks fails; one the table lacks fails.
    status, shown = _run(clean.replace(_line("get", 0), ""), base)
    assert status == 1 and "FAIL get" in shown and "has no line" in shown, shown
    cases += 1
    status, shown = _run(clean + "\n" + _line("replay", 5), base)
    assert status == 1 and "FAIL replay" in shown and "no row" in shown, shown
    cases += 1

    # A null row reads NOT-MEASURED with the row a fill writes, and so does a family not built.
    nulled = _table(**{"put-small": _row(None, debt=DEBT_PLACEHOLDER),
                       "get": _row(0, locked=True, debt=None)})
    status, shown = _run(clean, nulled)
    assert status == 3 and "NOT-MEASURED put-small" in shown, shown
    assert format_row("put-small", _row(2.0, debt=DEBT_PLACEHOLDER)) in shown, shown
    assert "PASS put-small" not in shown, f"a null row passed: {shown}"
    cases += 1
    status, shown = _run(clean.replace(_line("put-small", 200), f"{PREFIX} put-small {NOT_BUILT}"),
                         base)
    assert status == 3 and "NOT-MEASURED put-small" in shown, shown
    cases += 1

    # A filled row above 0 still on the placeholder fails: the debt is registered first.
    placeholder = _table(**{"put-small": _row(2.0, debt=DEBT_PLACEHOLDER),
                            "get": _row(0, locked=True, debt=None)})
    status, shown = _run(clean, placeholder)
    assert status == 1 and "register it" in shown, shown
    cases += 1

    # Malformed lines are refused rather than skipped.
    for bad, needle in (
        (f"{PREFIX} put-small allocs=2 bytes=3", "neither"),
        (f"{PREFIX} put-small allocs=-2 bytes=3 rounds=100", "neither"),
        (f"{PREFIX} Put_Small allocs=2 bytes=3 rounds=100", "names no family"),
        (f"{PREFIX} put-small allocs=2 bytes=3 rounds=0", "counts no round"),
        (_line("put-small", 200) + "\n" + _line("put-small", 200), "read twice"),
    ):
        status, shown = _run(bad + "\n" + _line("get", 0), base)
        assert status == 1 and needle in shown, f"{bad!r} was read: {shown}"
        cases += 1
    status, shown = _run("running 1 test\ntest result: ok. 1 passed", base)
    assert status == 1 and "holds no" in shown, shown
    cases += 1

    # A malformed table is refused, each shape by name.
    for doc, needle in (
        (_table(**{"put-small": _row(1.0, locked=True, debt=None)}), "locked row holds 0"),
        (_table(**{"put-small": _row(0, debt=None)}), "is locked"),
        (_table(**{"put-small": _row(0, locked=True)}), "owes nothing"),
        (_table(**{"put-small": _row(1.0, debt=None)}), "names the debt"),
        (_table(**{"put-small": _row(1.0, debt="TBD")}), "debt is null"),
        (_table(**{"put-small": _row(1.2345)}), "three decimal places"),
        (_table(**{"put-small": _row(-1)}), "at least 0"),
        (_table(**{"put-small": {"allocs_per_round": 1}}), "exactly the keys"),
        (_table(), "holds no family"),
        (json.dumps({"schema": SCHEMA}), "exactly the keys"),
        ('{"about": 1, "about": 2}', "written twice"),
    ):
        status, shown = _run(_line("put-small", 0), doc)
        assert status == 1 and needle in shown, f"a table with {needle!r} was used: {shown}"
        cases += 1

    # --fill writes the measured rows and never loosens a filled one.
    rows, notes = fill(clean.replace("allocs=200", "allocs=300"), base)
    assert rows is not None and rows["put-small"] == _row(2.0) and notes, (rows, notes)
    rows, notes = fill(clean.replace("allocs=200", "allocs=150"), nulled)
    assert rows is not None and rows["put-small"] == _row(1.5, debt=DEBT_PLACEHOLDER), rows
    assert rows["get"] == LOCKED_ROW and not notes, (rows, notes)
    rows, notes = fill("noise only", base)
    assert rows is None and notes, (rows, notes)
    cases += 1

    # --declared ties the table to the families the test declares.
    test_text = ('const FAMILIES: [(&str, Round, Part); 2] = [\n'
                 '    ("put-small", Round::PutSmall, Part::Calling),\n'
                 '    ("get", Round::Get, Part::Calling),\n];\n')
    assert declared(base, test_text) == [], declared(base, test_text)
    missing = declared(base, test_text.replace('    ("get", Round::Get, Part::Calling),\n', ""))
    assert any("measures no such family" in f for f in missing), missing
    extra = declared(base, test_text.replace("];", '    ("e2e", Round::E2e, Part::All),\n];'))
    assert any("has no row" in f for f in extra), extra
    assert any("declares no family" in f for f in declared(base, "nothing here")), "no family read"
    cases += 1

    print(f"no_heap_ratchet_gate selftest: {cases} cases pass")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="hold the allocations after open of each family")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--declared", action="store_true", help="check the table and its families")
    mode.add_argument("--check", type=Path, metavar="READING", help="judge a reading")
    mode.add_argument("--fill", type=Path, metavar="READING", help="print the rows a reading writes")
    ap.add_argument("--table", type=Path, default=ROOT / TABLE)
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    try:
        table_text = args.table.read_text(encoding="utf-8")
    except OSError as error:
        print(f"  no-heap-ratchet FAIL: {args.table} cannot be read: {error}", file=sys.stderr)
        return 1
    if args.declared:
        findings = declared(table_text, (ROOT / TEST_FILE).read_text(encoding="utf-8"))
        for finding in findings:
            print(f"  no-heap-ratchet FAIL: {finding}", file=sys.stderr)
        if findings:
            return 1
        _tolerance, rows = load_table(table_text)
        measured = sum(1 for row in rows.values() if row.ceiling is not None)
        locked = sum(1 for row in rows.values() if row.locked)
        print(f"  no-heap-ratchet: {len(rows)} family(ies) declared, {measured} measured, "
              f"{locked} locked at 0")
        return 0
    path = args.check if args.check is not None else args.fill
    try:
        reading_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        print(f"  no-heap-ratchet FAIL: the reading {path} cannot be read: {error}", file=sys.stderr)
        return 1
    if args.check is not None:
        return check(reading_text, table_text)
    rows, notes = fill(reading_text, table_text)
    if rows is None:
        for note in notes:
            print(f"  no-heap-ratchet FAIL: {note}", file=sys.stderr)
        return 1
    for note in notes:
        print(f"  no-heap-ratchet NOTE: {note}", file=sys.stderr)
    body = ",\n".join(f"    {format_row(family, row)}" for family, row in rows.items())
    print('  "families": {\n' + body + "\n  }")
    return 0


if __name__ == "__main__":
    sys.exit(main())

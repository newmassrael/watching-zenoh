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
sessions are open over the program's own transport, each family is measured in a number of
independent windows, each a warm-up and then a fixed number of rounds with the allocator counting,
and the test prints one line a family:

    no-heap: <family> allocs=<n> bytes=<b> rounds=<r> windows=<k> max_allocs=<m>
    no-heap: <family> not-built

`allocs` and `bytes` are those of the window that allocated least, `rounds` the rounds of one
window, `windows` how many windows were counted and `max_allocs` the allocations of the window that
allocated most.

## Why the least window

A family counted over the sessions' threads as well as the calling one reads, besides what the
operation itself allocates, whatever the threads' interleaving adds: how many times the receiving
thread runs in a round, and the work one round's messages leave for the next. On one commit such a
family's single window varied by more than any tolerance a ratchet can hold. The interleaving only
adds allocations to a window; it never takes away the ones the operation makes, so the least of
independent windows is the operation's own cost, and it is what an unlocked row grades. A row
locked at 0 claims the operation allocates nothing at all, so it grades the most: a family whose
row is locked fails when any window allocates.

The gate reads every line that carries `no-heap:` (libtest may write the test's name on that line
before it) and no other line. A line that carries it and is neither form is refused, as is a
family read twice, a count of no round or no window, a most below the least, and one window whose
least and most differ: a reading that cannot be read is not read as clean.

## The table

`deploy/no_heap_ratchet.json`, schema `wz-no-heap-ratchet/1`: a `tolerance` and one row a family,

    {"allocs_per_round": <number or null>, "locked": <bool>, "debt": <id or null>}

`allocs_per_round` is the least window's allocations over its rounds, rounded up to three places.
A family is locked once every window reads 0; a family whose least window reads 0 while another
window does not keeps an unlocked row at its most window's figure, the least figure above 0 the
reading supports. A row at 0 is locked, a locked row holds 0 and owes no debt, and a row above 0
or not measured yet names the store inventory entry it is registered under (`debt-<id>`), or
`debt-TBD` until it is.

## The rules of --check

    a family whose least window is above its row times one plus
    the tolerance                                                  FAIL
    a locked family that allocates in any window                   FAIL
    a family of the table the reading has no line for              FAIL
    a family of the reading the table has no row for               FAIL
    a row above 0 whose debt is still the placeholder              FAIL
    a malformed reading or table                                   FAIL
    a row not filled yet, or a family the build did not have       NOT-MEASURED
    a family below its row                                         PASS, the tighter row printed
    a family that read 0 in every window                           PASS, the locked row printed

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
# What the table says of each capability of the measured build's profile: the families that
# measure it, or the reason it has no path after a session opens, read where the code says so.
CAPABILITIES_KEY = "capabilities"
CAPABILITY_KEYS = ({"families"}, {"reason"})
# A reason names the code it is read from as `<file>:<line>`.
REASON_CITE = re.compile(r"[\w./-]+\.(?:rs|h|c|py|toml|json5?):\d+")
ROW_KEYS = {"allocs_per_round", "locked", "debt"}
PREFIX = "no-heap:"
NOT_BUILT = "not-built"
FAMILY_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
MEASURED = re.compile(r"^allocs=(\d+) bytes=(\d+) rounds=(\d+) windows=(\d+) max_allocs=(\d+)$")
MEASURED_FORM = "allocs=<n> bytes=<b> rounds=<r> windows=<k> max_allocs=<m>"
# A debt is an entry of the store's inventory (`debt-<id>`), as every new open debt is; the
# placeholder stands only until the row is measured.
DEBT_ID = re.compile(r"debt-[a-z0-9][a-z0-9-]*")
DEBT_PLACEHOLDER = "debt-TBD"
# A row is the reading's allocations a round rounded UP to three places, so the ceiling never
# sits under the reading it was set from.
PLACES = 1000
# One family of the test's `FAMILIES` table: `("<name>", Round::<round>, Part::<part>)`, on one
# line or spread over several as rustfmt writes an entry too wide for one, with its trailing comma.
DECLARED_FAMILY = re.compile(
    r'^\s*\(\s*"([^"]+)",\s*Round::\w+,\s*Part::\w+,?\s*\),?\s*$', re.M)
LAYER = "C1nh"


class Refused(Exception):
    """A table that cannot be read as one."""


@dataclass(frozen=True)
class Reading:
    """One family's line: the least window's counts, the rounds of a window, the windows counted
    and the most window's allocations, or None for each when the build has not the family."""

    family: str
    allocs: int | None
    nbytes: int | None
    rounds: int | None
    windows: int | None = None
    max_allocs: int | None = None

    @property
    def built(self) -> bool:
        return self.allocs is not None

    def _per_round_up(self, allocs: int) -> float:
        assert self.rounds
        return -(-allocs * PLACES // self.rounds) / PLACES

    def ceiling(self) -> float:
        """The least window's allocations a round, rounded up to three places."""
        assert self.allocs is not None
        return self._per_round_up(self.allocs)

    def zero_everywhere(self) -> bool:
        """Whether every window read 0, which is what locks a family."""
        return self.max_allocs == 0

    def figure(self) -> float:
        """The figure of the unlocked row this reading writes: the least window's, or, when that
        is 0 and another window's is not, the most window's (a row at 0 is a locked one)."""
        assert self.allocs is not None and self.max_allocs is not None
        return self.ceiling() if self.allocs > 0 else self._per_round_up(self.max_allocs)

    def shown(self) -> str:
        assert self.allocs is not None and self.max_allocs is not None and self.rounds
        return (f"least of {self.windows} window(s): {self.allocs} allocation(s) of {self.nbytes} "
                f"byte(s) in {self.rounds} round(s), {self.allocs / self.rounds:.3f} a round; "
                f"most: {self.max_allocs}, {self.max_allocs / self.rounds:.3f} a round")


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
                findings.append(f"{where}: is neither `{MEASURED_FORM}` nor `{NOT_BUILT}`")
                continue
            allocs, nbytes, rounds, windows, max_allocs = (int(g) for g in measured.groups())
            if rounds == 0:
                findings.append(f"{where}: counts no round, so it measures nothing")
                continue
            if windows == 0:
                findings.append(f"{where}: counts no window, so it measures nothing")
                continue
            if max_allocs < allocs:
                findings.append(f"{where}: its most window ({max_allocs}) is below its least "
                                f"({allocs}), which no count of windows gives")
                continue
            if windows == 1 and max_allocs != allocs:
                findings.append(f"{where}: one window is both the least and the most, so "
                                f"max_allocs is allocs")
                continue
            reading = Reading(family, allocs, nbytes, rounds, windows, max_allocs)
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
    if not isinstance(doc, dict) or not TABLE_KEYS <= set(doc) <= TABLE_KEYS | {CAPABILITIES_KEY}:
        keys = ", ".join(sorted(TABLE_KEYS))
        raise Refused(f"the table is an object with exactly the keys {keys}, and "
                      f"{CAPABILITIES_KEY} besides them or not")
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


@dataclass(frozen=True)
class CapabilityRow:
    """What the table says of one capability: the families that measure it, or why it has none."""

    families: tuple[str, ...]
    reason: str | None


def parse_capabilities(doc: dict) -> dict[str, CapabilityRow]:
    """The table's rows of capabilities; Refused when one is not a list of families or a reason
    that names the code it is read from."""
    raw = doc.get(CAPABILITIES_KEY, {})
    if not isinstance(raw, dict):
        raise Refused(f"`{CAPABILITIES_KEY}` is an object of one row per capability")
    out: dict[str, CapabilityRow] = {}
    findings: list[str] = []
    for cap, body in raw.items():
        if not isinstance(body, dict) or set(body) not in CAPABILITY_KEYS:
            findings.append(f"capability {cap}: a row is {{\"families\": [...]}} or {{\"reason\": \"...\"}}")
            continue
        if "families" in body:
            families = body["families"]
            if (not isinstance(families, list) or not families
                    or not all(isinstance(f, str) and FAMILY_NAME.match(f) for f in families)):
                findings.append(f"capability {cap}: `families` is a list of one family name or more")
                continue
            out[cap] = CapabilityRow(tuple(families), None)
        else:
            reason = body["reason"]
            if not isinstance(reason, str) or not REASON_CITE.search(reason):
                findings.append(f"capability {cap}: a reason names the code it is read from, as "
                                f"<file>:<line>")
                continue
            out[cap] = CapabilityRow((), reason)
    if findings:
        raise Refused("; ".join(findings))
    return out


def load_capabilities(text: str) -> dict[str, CapabilityRow]:
    try:
        doc = json.loads(text, object_pairs_hook=refuse_duplicates)
    except ValueError as error:
        raise Refused(f"not JSON: {error}") from None
    if not isinstance(doc, dict):
        raise Refused("the table is not an object")
    return parse_capabilities(doc)


def coverage(capabilities: set[str], rows: dict[str, CapabilityRow],
             found: dict[str, Reading]) -> list[Judged]:
    """Each capability of the measured build's profile, judged: measured by its families, each
    read and built, or stated to have no path after open; anything else is NOT-MEASURED, as a
    family the build lacks is, so the lane never passes on a capability it does not hold."""
    out: list[Judged] = []
    for cap in sorted(capabilities):
        row = rows.get(cap)
        name = f"capability {cap}"
        if row is None:
            out.append(Judged(name, "NOT-MEASURED", "the profile has it, and neither a family "
                                                    "measures it nor a reason row says it has no "
                                                    "path after open"))
        elif row.reason is not None:
            out.append(Judged(name, "PASS", f"no path after open: {row.reason}"))
        else:
            missing = [f for f in row.families if f not in found or not found[f].built]
            if missing:
                out.append(Judged(name, "NOT-MEASURED", f"its families {', '.join(missing)} were "
                                                        f"not read, or not built"))
            else:
                out.append(Judged(name, "PASS", f"measured by {', '.join(row.families)}"))
    return out


def profile_capabilities(profile: Path) -> set[str]:
    """The capabilities of the pico C ABI that `profile`, merged as the packager merges it, turns
    on: the population `coverage` holds. Read by the one resolver, `wz_config.py`."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import wz_config  # noqa: E402  the declaration and its Kconfig resolver

    decl = wz_config.load_decl()
    kconf = wz_config.resolve([profile])
    return {cid for cid in wz_config.resolved_caps(decl, kconf)
            if "pico" in decl["caps"][cid].get("abis", [])}


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
    """The row a measured reading writes: locked at 0 when every window read 0, or its figure with
    the debt the row names (the placeholder for a family that had none)."""
    if reading.zero_everywhere():
        return dict(LOCKED_ROW)
    debt = row.debt if row is not None and row.debt is not None else DEBT_PLACEHOLDER
    return {"allocs_per_round": reading.figure(), "locked": False, "debt": debt}


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
            if reading.zero_everywhere():
                out.append(Judged(family, "PASS", f"{shown}; locked at 0"))
            else:
                out.append(Judged(family, "FAIL", f"{shown}; the family is locked at 0 allocations "
                                                  f"a round and a window allocated, so what "
                                                  f"allocates after open is the regression"))
            continue
        assert reading.allocs is not None and reading.rounds
        per_round = reading.allocs / reading.rounds
        if per_round > row.ceiling * (1 + tolerance):
            out.append(Judged(family, "FAIL", f"{shown}; its least window is above the row's "
                                              f"{row.ceiling} a round by more than the tolerance "
                                              f"{tolerance}: allocations after open may only fall"))
            continue
        if row.debt is None or not DEBT_ID.fullmatch(row.debt):
            out.append(Judged(family, "FAIL", f"{shown}; a family that still allocates is an open debt, "
                                              f"and its row names {row.debt!r}: register it in the "
                                              f"store's inventory and write its `debt-<id>`"))
            continue
        if reading.zero_everywhere():
            out.append(Judged(family, "PASS", f"{shown}; it reached 0 in every window, so lock the "
                                              f"row and close {row.debt}", dict(LOCKED_ROW)))
            continue
        not_yet = ("" if reading.allocs > 0 else
                   "; its least window reads 0 but another does not, and a family is locked only "
                   "when every window reads 0")
        if reading.figure() < row.ceiling:
            out.append(Judged(family, "PASS", f"{shown}; under the row's {row.ceiling}, so tighten "
                                              f"it{not_yet}", fill_row(reading, row)))
        else:
            out.append(Judged(family, "PASS", f"{shown}; within the row's {row.ceiling}{not_yet}"))
    return out


def exit_status(judged: list[Judged], findings: list[str]) -> int:
    outcomes = {j.outcome for j in judged}
    if findings or "FAIL" in outcomes:
        return 1
    return 3 if "NOT-MEASURED" in outcomes else 0


def check(reading_text: str, table_text: str, capabilities: set[str] | None = None) -> int:
    """Judge a reading against a table, print every family's outcome, and return the status; with
    `capabilities`, the profile's, each judged by its row too (`coverage`)."""
    try:
        tolerance, rows = load_table(table_text)
        cap_rows = load_capabilities(table_text)
    except Refused as why:
        print(f"  no-heap-ratchet FAIL: the table is refused: {why}", file=sys.stderr)
        return 1
    found, findings = parse_reading(reading_text)
    for finding in findings:
        print(f"  no-heap-ratchet FAIL: {finding}", file=sys.stderr)
    if findings:
        return 1
    judged = judge(found, rows, tolerance)
    if capabilities is not None:
        judged += coverage(capabilities, cap_rows, found)
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


def _line(family: str, allocs: int, rounds: int = 100, nbytes: int = 640, windows: int = 5,
          max_allocs: int | None = None) -> str:
    most = allocs if max_allocs is None else max_allocs
    return (f"{PREFIX} {family} allocs={allocs} bytes={nbytes} rounds={rounds} windows={windows} "
            f"max_allocs={most}")


def _run(reading: str, table: str) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = check(reading, table)
    return status, out.getvalue() + err.getvalue()


def _run_caps(reading: str, table: str, capabilities: set[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = check(reading, table, capabilities)
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

    # The row grades the least window: a least above the row by more than the tolerance fails,
    # within it holds, and a most far above the row with the least held passes.
    status, shown = _run(clean.replace(_line("put-small", 200), _line("put-small", 211)), base)
    assert status == 1 and "FAIL put-small" in shown and "may only fall" in shown, shown
    cases += 1
    status, shown = _run(clean.replace(_line("put-small", 200), _line("put-small", 209)), base)
    assert status == 0, f"a reading within the tolerance failed: {shown}"
    cases += 1
    status, shown = _run(clean.replace(_line("put-small", 200),
                                       _line("put-small", 200, max_allocs=900)), base)
    assert status == 0 and "FAIL" not in shown, f"a noisy most failed a held least: {shown}"
    cases += 1

    # A fall passes and prints the tighter row; a fall to 0 in every window prints the locked row.
    status, shown = _run(clean.replace(_line("put-small", 200), _line("put-small", 150)), base)
    assert status == 0, shown
    assert format_row("put-small", _row(1.5)) in shown, f"a fall printed no row to commit: {shown}"
    cases += 1
    status, shown = _run(clean.replace(_line("put-small", 200), _line("put-small", 0)), base)
    assert status == 0 and format_row("put-small", LOCKED_ROW) in shown, shown
    cases += 1

    # A least of 0 with a most above it is not locked: the row it prints is the most's figure.
    status, shown = _run(clean.replace(_line("put-small", 200),
                                       _line("put-small", 0, max_allocs=30)), base)
    assert status == 0 and format_row("put-small", LOCKED_ROW) not in shown, shown
    assert format_row("put-small", _row(0.3)) in shown and "every window" in shown, shown
    cases += 1

    # The ceiling is rounded up, never down: 1 in 3 rounds is 0.334.
    assert Reading("x", 1, 0, 3, 1, 1).ceiling() == 0.334, Reading("x", 1, 0, 3, 1, 1).ceiling()
    cases += 1

    # A locked row fails when any window allocates, the least one or another.
    for least, most in ((1, 1), (0, 1)):
        status, shown = _run(clean.replace(_line("get", 0), _line("get", least, max_allocs=most)),
                             base)
        assert status == 1 and "FAIL get" in shown and "locked at 0" in shown, (least, most, shown)
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
        (f"{PREFIX} put-small allocs=2 bytes=3 rounds=100", "neither"),
        (f"{PREFIX} put-small allocs=2 bytes=3 rounds=100 windows=5", "neither"),
        (_line("put-small", -2), "neither"),
        (_line("Put_Small", 2), "names no family"),
        (_line("put-small", 2, rounds=0), "counts no round"),
        (_line("put-small", 2, windows=0), "counts no window"),
        (_line("put-small", 200, max_allocs=199), "below its least"),
        (_line("put-small", 200, windows=1, max_allocs=201), "one window"),
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
        (json.dumps({**json.loads(_table()), "extra": 1}), "exactly the keys"),
        ('{"about": 1, "about": 2}', "written twice"),
    ):
        status, shown = _run(_line("put-small", 0), doc)
        assert status == 1 and needle in shown, f"a table with {needle!r} was used: {shown}"
        cases += 1

    # --fill writes the least window's figure, locks only a family at 0 in every window, and
    # never loosens a filled row.
    rows, notes = fill(clean.replace(_line("put-small", 200), _line("put-small", 300)), base)
    assert rows is not None and rows["put-small"] == _row(2.0) and notes, (rows, notes)
    rows, notes = fill(clean.replace(_line("put-small", 200),
                                     _line("put-small", 150, max_allocs=400)), nulled)
    assert rows is not None and rows["put-small"] == _row(1.5, debt=DEBT_PLACEHOLDER), rows
    assert rows["get"] == LOCKED_ROW and not notes, (rows, notes)
    rows, notes = fill(clean.replace(_line("put-small", 200), _line("put-small", 0, max_allocs=7)),
                       nulled)
    assert rows is not None and rows["put-small"] == _row(0.07, debt=DEBT_PLACEHOLDER), rows
    rows, notes = fill(clean.replace(_line("get", 0), _line("get", 0, max_allocs=2)), base)
    assert rows is not None and rows["get"] == LOCKED_ROW and notes, (rows, notes)
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

    # An entry rustfmt spreads over several lines is read as one on a line is.
    spread = test_text.replace('    ("get", Round::Get, Part::Calling),\n',
                               '    (\n        "get",\n        Round::Get,\n        Part::Calling,\n'
                               '    ),\n')
    assert declared_families(spread) == ["put-small", "get"], declared_families(spread)
    assert declared(base, spread) == [], declared(base, spread)
    cases += 1

    # Each capability of the profile is held by a row: its families read and built, or a reason
    # that names its code; one with neither, or whose family was not built, is NOT-MEASURED.
    caps_table = json.dumps({"about": "fixture", "schema": SCHEMA, "tolerance": 0.05,
                             "families": {"put-small": _row(2.0), "get": _row(0, locked=True, debt=None)},
                             CAPABILITIES_KEY: {"query": {"families": ["get"]},
                                                "scout": {"reason": "src/scout.rs:10 opens no session"}}})
    status, shown = _run_caps(clean, caps_table, {"query", "scout"})
    assert status == 0, shown
    status, shown = _run_caps(clean, caps_table, {"query", "scout", "connectivity"})
    assert status == 3 and "NOT-MEASURED capability connectivity" in shown, shown
    status, shown = _run_caps(clean.replace(_line("get", 0), f"{PREFIX} get {NOT_BUILT}"), caps_table,
                              {"query"})
    assert status == 3 and "NOT-MEASURED capability query" in shown, shown
    uncited = caps_table.replace("src/scout.rs:10 opens no session", "opens no session")
    status, shown = _run_caps(clean, uncited, {"scout"})
    assert status == 1 and "names the code" in shown, shown
    status, shown = _run(clean, caps_table)
    assert status == 0, f"a table with capabilities read without a profile failed: {shown}"
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
    ap.add_argument("--profile", type=Path, metavar="PROFILE",
                    help="with --check: every capability this profile turns on is held by a row")
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
        capabilities = None
        if args.profile is not None:
            try:
                capabilities = profile_capabilities(args.profile)
            except Exception as error:  # noqa: BLE001  the resolver's refusal, said as a failure
                print(f"  no-heap-ratchet FAIL: the profile {args.profile} did not resolve: {error}",
                      file=sys.stderr)
                return 1
            if not capabilities:
                print(f"  no-heap-ratchet FAIL: the profile {args.profile} resolved to no capability "
                      f"of the pico C ABI: the reader stopped matching, which a pass would hide",
                      file=sys.stderr)
                return 1
        return check(reading_text, table_text, capabilities)
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

#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4583 (debt-pico-host-size-ceiling) -- the pico ceiling of the host libraries
(docs/upstream-parity.md D9): the one reader and judge of `deploy/pico_host_ceiling.json`.

The citation is the round that set the ceiling up and the open-debt item the table measures: every
row that is no WIN is registered under it, and the table is how that debt is read.

A lane that measures a library of the pico ABI against zenoh-pico built as the same build holds
the ratio of their texts under a row of that table. The rule of a row (a lock at WIN, or a ratchet
set from a stated reading under the open-debt item the case is registered with, moving only down)
is written once, here, and a lane names its own cases and how it reads them; no lane's builds are
this module's. `capability_cost_gate.py` (Layer C1cs) is such a lane, and its `ceiling_cases` is
the population `table_findings` holds the table to (a case without a row, or a row for no case,
fails).
"""

from __future__ import annotations

import json
import math
import pathlib
import re
import sys
from fractions import Fraction

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from kit_compare import verdict_size  # noqa: E402  (decision D1's size verdict, one copy)

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The committed table: per pico case, the ratio it may not exceed, or its lock at WIN.
HOST_CEILING = ROOT / "deploy" / "pico_host_ceiling.json"
HOST_CEILING_SCHEMA = 1
# How far over its ratchet a ratio may read before the case fails, relative to the ratchet. Two
# readings of one tree on one host are equal (both builds are deterministic), so this is only the
# spread between hosts, and it is MEASURED, not assumed: on 2026-11-21 one tree read
# pico-client-coop at 1,012,762 bytes on the coordinating host and 1,030,646 on a build host
# (1.77 percent), while zenoh-pico read 403,086 on both, so the ratio does NOT cancel what a host
# does to wz's own build (its Rust toolchain's linking, not the C compiler). 2.5 percent covers that
# spread with a margin. It narrows to the spread of one image when every host builds in the image
# the tree declares (the same-build-environment work); until then a row is filled from the hosts
# that grade it. It bounds only what the ratio forgives: the case's byte budget still holds it.
RATIO_TOLERANCE = 0.025
# A ratchet is the reading's ratio rounded UP to four places, so the bound never sits under the
# reading it was set from.
RATIO_PLACES = 10_000
# A debt is an entry of the store's inventory (`debt-<id>`, status active), as every new open
# debt is since 2026-11-13; a row is held to the shape of its id here.
DEBT_ID = re.compile(r"debt-[a-z0-9][a-z0-9-]*")
DEBT_PLACEHOLDER = "debt-TBD"
READING_KEYS = ("date", "wz_text", "pico_text", "pico_pin", "toolchain")
ROW_KEYS = frozenset(("verdict", "ratio_at_most", "debt", "reading"))
CEILING_NO_BUDGET = ("no budget or row move clears it: take the bytes back, or the owner "
                     "decides (docs/upstream-parity.md D9)")


def load_ceiling(path: pathlib.Path = HOST_CEILING) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def ceiling_rows(table: dict | None) -> dict:
    rows = table.get("cases") if isinstance(table, dict) else None
    return rows if isinstance(rows, dict) else {}


def ceil_ratio(wz_text: int, pico_text: int) -> float:
    """wz text over pico text, rounded up to four places in exact arithmetic."""
    return math.ceil(Fraction(wz_text * RATIO_PLACES, pico_text)) / RATIO_PLACES


def ceiling_reading(wz_text: int, pico_text: int, pin: str, toolchain: str, date: str) -> dict:
    return {"date": date, "wz_text": wz_text, "pico_text": pico_text, "pico_pin": pin,
            "toolchain": toolchain}


def ceiling_row(reading: dict, debt: str | None) -> dict:
    """The row a reading sets: locked when it is a WIN (D1), a ratchet at its ratio otherwise,
    under the debt item the case is registered with (a placeholder while it has none)."""
    row: dict = {}
    if verdict_size(reading["wz_text"], reading["pico_text"]) == "WIN":
        row["verdict"] = "win"
        if debt and DEBT_ID.fullmatch(debt):
            row["debt"] = debt
    else:
        row["ratio_at_most"] = ceil_ratio(reading["wz_text"], reading["pico_text"])
        row["debt"] = debt if debt and DEBT_ID.fullmatch(debt) else DEBT_PLACEHOLDER
    row["reading"] = reading
    return row


def format_row(case_id: str, row: dict) -> str:
    return f"{json.dumps(case_id)}: {json.dumps(row)}"


def reading_findings(case_id: str, reading: object) -> list[str]:
    if not isinstance(reading, dict) or set(reading) != set(READING_KEYS):
        return [f"{case_id}: its reading must state exactly {', '.join(READING_KEYS)}"]
    out: list[str] = []
    for key in ("wz_text", "pico_text"):
        if type(reading[key]) is not int or reading[key] <= 0:
            out.append(f"{case_id}: its reading's {key} is not a positive byte count")
    for key in ("date", "pico_pin", "toolchain"):
        if not isinstance(reading[key], str) or not reading[key]:
            out.append(f"{case_id}: its reading's {key} is empty")
    return out


def row_findings(case_id: str, row: object) -> list[str]:
    """What makes a row of the table no row of the ceiling. A row whose `ratio_at_most` is null
    is well formed here (the unfilled form) and refused by `grade_ceiling`."""
    if not isinstance(row, dict):
        return [f"{case_id}: its row is not an object"]
    out = [f"{case_id}: its row has the unknown key {key!r}" for key in sorted(set(row) - ROW_KEYS)]
    locked = "verdict" in row
    if locked == ("ratio_at_most" in row):
        return out + [f"{case_id}: its row must state either `verdict` (locked) or "
                      f"`ratio_at_most` (ratchet), and states {'both' if locked else 'neither'}"]
    if locked:
        if row["verdict"] != "win":
            out.append(f"{case_id}: a locked row's verdict is \"win\" and nothing else (D1: only "
                       f"WIN counts), not {row['verdict']!r}")
        found = reading_findings(case_id, row.get("reading"))
        out += found
        if not found and verdict_size(row["reading"]["wz_text"], row["reading"]["pico_text"]) != "WIN":
            out.append(f"{case_id}: the row is locked at WIN on a reading that is no WIN")
        if "debt" in row and not (isinstance(row["debt"], str) and DEBT_ID.fullmatch(row["debt"])):
            out.append(f"{case_id}: a locked row's debt, when stated, is the item its WIN closed "
                       f"(`debt-<id>`, an entry of the store's inventory)")
        return out
    if not isinstance(row.get("debt"), str):
        out.append(f"{case_id}: a ratchet row states the debt item it is registered under")
    at_most = row["ratio_at_most"]
    if at_most is None:
        if row.get("reading") is not None:
            out.append(f"{case_id}: an unfilled row (`ratio_at_most` null) states no reading")
        return out
    if isinstance(at_most, bool) or not isinstance(at_most, (int, float)) or at_most <= 0:
        return out + [f"{case_id}: its ratio_at_most is not a positive number"]
    found = reading_findings(case_id, row.get("reading"))
    if found:
        return out + found
    reading = row["reading"]
    if at_most != ceil_ratio(reading["wz_text"], reading["pico_text"]):
        out.append(f"{case_id}: its ratio_at_most {at_most} is not its reading's ratio rounded up "
                   f"to four places ({ceil_ratio(reading['wz_text'], reading['pico_text'])}): the "
                   f"ratchet is set from a stated reading and from nothing else")
    if verdict_size(reading["wz_text"], reading["pico_text"]) == "WIN":
        out.append(f"{case_id}: a ratchet row set from a WIN; lock it: "
                   f"{format_row(case_id, ceiling_row(reading, row.get('debt')))}")
    return out


def table_findings(table: dict | None, case_ids: list[str]) -> list[str]:
    """What keeps the table from holding each of `case_ids` with one well-formed row. Static: it
    needs no build, so a run of some cases still grades the whole table."""
    where = HOST_CEILING.relative_to(ROOT)
    if table is None:
        return [f"{where} is missing: every pico case is held under zenoh-pico by its row there"]
    if not isinstance(table, dict) or table.get("schema") != HOST_CEILING_SCHEMA:
        return [f"{where} is not schema {HOST_CEILING_SCHEMA}"]
    rows = table.get("cases")
    if not isinstance(rows, dict):
        return [f"{where} has no `cases` object"]
    out: list[str] = []
    for case_id in case_ids:
        if case_id not in rows:
            out.append(f"{case_id}: no row in {where}: a pico case is held under zenoh-pico from "
                       f"the commit that adds it, so the population cannot grow past the ceiling; "
                       f"the lane that measures it prints its row")
    for case_id, row in rows.items():
        if case_id not in case_ids:
            out.append(f"{case_id}: a row in {where} for no case of the lanes that measure one")
        else:
            out += row_findings(case_id, row)
    return out


def grade_ceiling(case_id: str, row: dict, reading: dict,
                  remeasure: str = "") -> tuple[list[str], list[str]]:
    """The findings and the notes for one case's reading against its well-formed row. Pure, so
    the selftest can drive it. `remeasure` is the command of the lane that measures the case,
    which an unfilled row names as the one that prints the row again."""
    wz_text, pico_text = reading["wz_text"], reading["pico_text"]
    ratio = wz_text / pico_text
    verdict = verdict_size(wz_text, pico_text)
    said = (f"{case_id}: wz text {wz_text} against zenoh-pico {pico_text} as the same build, "
            f"ratio {ratio:.4f}, {verdict}")
    if "verdict" in row:
        if verdict != "WIN":
            return [f"{said}. The case is locked at WIN (since {row['reading']['date']}); "
                    f"{CEILING_NO_BUDGET}"], []
        return [], []
    debt = row.get("debt")
    at_most = row["ratio_at_most"]
    if at_most is None:
        return [f"{said}. Its row in {HOST_CEILING.relative_to(ROOT)} states no ratio_at_most, so "
                f"the case is held to nothing. Fill it from the host that grades it: paste "
                f"{format_row(case_id, ceiling_row(reading, debt))} over the row, with `debt` the "
                f"store inventory entry (`debt-<id>`) the case is registered under (D5)"
                + (f"; {remeasure} prints the same row" if remeasure else "")], []
    findings: list[str] = []
    notes: list[str] = []
    if not (isinstance(debt, str) and DEBT_ID.fullmatch(debt)):
        findings.append(f"{case_id}: its row names no registered debt ({debt!r}): a case that is no "
                        f"WIN is an open-debt item, paid largest ratio first (D5), and its row "
                        f"says which (`debt-<id>`, an entry of the store's inventory)")
    if verdict == "WIN":
        findings.append(f"{said}. A case that reached WIN is locked at WIN from now on: replace its "
                        f"row with {format_row(case_id, ceiling_row(reading, debt))} and close "
                        f"{debt}")
        return findings, notes
    limit = at_most * (1 + RATIO_TOLERANCE)
    if ratio > limit:
        then = row["reading"]
        host = ("" if then["toolchain"] == reading["toolchain"] else
                f"; the row was read with {then['toolchain']}, this run with {reading['toolchain']}")
        findings.append(f"{said}, over its ratchet {at_most} (with the {RATIO_TOLERANCE:.1%} "
                        f"tolerance, {limit:.4f}; set {then['date']} from {then['wz_text']} against "
                        f"{then['pico_text']}){host}. A ratchet only moves down: {CEILING_NO_BUDGET}")
    elif ratio * (1 + RATIO_TOLERANCE) < at_most:
        notes.append(f"{case_id}: ratio {ratio:.4f} is under its ratchet {at_most} by more than the "
                     f"tolerance; commit the tighter row: {format_row(case_id, ceiling_row(reading, debt))}")
    return findings, notes

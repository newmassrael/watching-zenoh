#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The atomic store's ledger as one mapping, read without `mnemosyne-cli`.

R4403 (no register item) -- the store's ledger is sealed into segment files
(mnemosyne Round 1344, schema v49): the main file `docs/.atomic/workspace.atomic.json`
keeps the unsealed entries and lists each segment under `ledger_layout` with the sha256
of its bytes; the segments are `docs/.atomic/ledger/segment-NNNN.json`. A publishable
field is written only where it differs from its audit twin. A script that read
`changelog_entries` out of the main file alone would now see a few hundred entries of
four thousand and take that for the ledger, so every script reads it here.

This reads the ledger the way mnemosyne's `AtomicStore::load` does, and refuses what it
refuses: a segment that is missing, whose bytes are not the ones the main file pins,
written at another generation, or holding an entry the main file or an earlier segment
holds. An absent publishable field is filled from its audit twin, so an entry here is
the entry mnemosyne holds in memory.

    atomic_ledger.py --check      read the ledger of this tree; print its size, exit 0
    atomic_ledger.py --selftest   every refusal and the happy path on a store made here
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
STORE = pathlib.Path("docs") / ".atomic" / "workspace.atomic.json"

# The audit field each publishable field mirrors, and what an absent audit field is.
TWINS = {
    "publishable_decision_summary": ("decision_summary", None),
    "publishable_changes_bullets": ("changes_bullets", []),
    "publishable_verification_bullets": ("verification_bullets", []),
    "publishable_impact_refs": ("impact_refs", []),
    "publishable_carry_forward_bullets": ("carry_forward_bullets", []),
}


class LedgerRefused(Exception):
    """The store's ledger cannot be read as one; the message names the file and why."""


def store_files(root: pathlib.Path | None = None) -> list[pathlib.Path]:
    """The main file and every segment it lists, in the order `load` reads them."""
    root = root or ROOT
    main = root / STORE
    data = json.loads(main.read_text(encoding="utf-8"))
    segments = (data.get("ledger_layout") or {}).get("segments") or []
    return [main] + [main.parent / s["file"] for s in segments]


def changelog_entries(root: pathlib.Path | None = None) -> dict:
    """Every changelog entry of the store at `root`, by id, publishable fields filled."""
    root = root or ROOT
    main = root / STORE
    if not main.is_file():
        return {}
    data = json.loads(main.read_text(encoding="utf-8"))
    version = data.get("schema_version")
    entries = dict(data.get("changelog_entries") or {})
    for segment in (data.get("ledger_layout") or {}).get("segments") or []:
        name = segment.get("file", "?")
        path = main.parent / name
        try:
            raw = path.read_bytes()
        except OSError as err:
            raise LedgerRefused(f"ledger segment `{name}`: it cannot be read: {err}") from err
        got = hashlib.sha256(raw).hexdigest()
        if got != segment.get("sha256"):
            raise LedgerRefused(
                f"ledger segment `{name}`: its sha256 is {got}, the main file records "
                f"{segment.get('sha256')}"
            )
        body = json.loads(raw)
        if body.get("schema_version") != version:
            raise LedgerRefused(
                f"ledger segment `{name}`: written at schema {body.get('schema_version')}, "
                f"the main file at {version}"
            )
        for entry_id, entry in (body.get("changelog_entries") or {}).items():
            if entry_id in entries:
                raise LedgerRefused(
                    f"ledger segment `{name}`: entry `{entry_id}` is also in the main file "
                    "or an earlier segment"
                )
            entries[entry_id] = entry
    if isinstance(version, int) and version >= 49:
        for entry in entries.values():
            for publishable, (audit, empty) in TWINS.items():
                if publishable not in entry:
                    entry[publishable] = entry.get(audit, empty)
    return entries


def selftest() -> int:
    failed = 0

    def expect(name: str, ok: bool) -> None:
        nonlocal failed
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
        failed += 0 if ok else 1

    def write_store(root: pathlib.Path, main_entries: dict, segments: dict) -> None:
        atomic = root / STORE.parent
        (atomic / "ledger").mkdir(parents=True, exist_ok=True)
        rows = []
        for name, seg_entries in segments.items():
            raw = json.dumps({"schema_version": 49, "changelog_entries": seg_entries}).encode()
            (atomic / name).write_bytes(raw)
            rows.append({"file": name, "entries": len(seg_entries),
                         "sha256": hashlib.sha256(raw).hexdigest()})
        doc = {"changelog_entries": main_entries, "schema_version": 49}
        if rows:
            doc["ledger_layout"] = {"segment_entries": 1, "segments": rows}
        (root / STORE).write_text(json.dumps(doc), encoding="utf-8")

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        write_store(root, {"Round 2": {"decision_summary": "two"}},
                    {"ledger/segment-0001.json": {"Round 1": {
                        "decision_summary": "one", "changes_bullets": ["c"],
                        "publishable_changes_bullets": []}}})
        got = changelog_entries(root)
        expect("the main file and its segment read as one ledger", sorted(got) == ["Round 1", "Round 2"])
        expect("an absent publishable field reads as its audit twin",
               got["Round 2"]["publishable_decision_summary"] == "two")
        expect("a publishable field redacted to nothing stays redacted",
               got["Round 1"]["publishable_changes_bullets"] == [])
        expect("the store files are the main file and its segment",
               [p.name for p in store_files(root)] == ["workspace.atomic.json", "segment-0001.json"])

        segment = root / STORE.parent / "ledger/segment-0001.json"
        segment.write_bytes(segment.read_bytes() + b" ")
        try:
            changelog_entries(root)
            expect("a changed segment is refused", False)
        except LedgerRefused as err:
            expect("a changed segment is refused", "sha256" in str(err))
        segment.unlink()
        try:
            changelog_entries(root)
            expect("a missing segment is refused", False)
        except LedgerRefused as err:
            expect("a missing segment is refused", "cannot be read" in str(err))

        write_store(root, {"Round 1": {}}, {"ledger/segment-0001.json": {"Round 1": {}}})
        try:
            changelog_entries(root)
            expect("an entry held twice is refused", False)
        except LedgerRefused as err:
            expect("an entry held twice is refused", "also in" in str(err))
    print(f"atomic_ledger selftest: {'FAILED' if failed else 'ok'}")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--check"]:
        try:
            entries = changelog_entries()
        except LedgerRefused as err:
            print(f"atomic_ledger: REFUSED {err}", file=sys.stderr)
            return 1
        print(f"atomic_ledger: {len(entries)} entries in {len(store_files())} file(s)")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

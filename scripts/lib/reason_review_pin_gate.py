#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3182 (no register item) -- a file a standing atom reason cites may not change
without the round that changes it being shown the reason.

The citation is `no register item` for the reason `reason_citation_gate.py` and
`store_reason_citation_gate.py` give for theirs: the item this answers, unregistered
open-debt item 756, lives in the operator's agent-memory register, which has no
store `debt-` id for `gate_provenance_lint.py` to resolve. It is named in prose.

## The defect, measured five times in one session

An atom's reason is the LIVE verdict on what that atom still owes. Its clauses
make claims about this tree's own code, and nothing re-reads a clause when the
code it describes moves. Five instances were found by hand on one day: a doc
comment claiming the same election as an upstream the pin does not carry; a reason
counting two runtime-mutable slices after a later round made three; a reason
saying a storage host never sees the admin write permit while the host reads it
and a per-request witness stands; two rounds that landed with no reason update at
all; and a reason citing six call sites whose resolution is all the citation gate
checks. In every one the code moved and the reason kept asserting the old state,
and a stale assertion reads as a fact: the next reader has no cause to doubt it.

## Why the existing gates do not reach it

`reason_citation_gate.py` asks whether a cited path still exists and whether a
cited line is inside the file. `store_reason_citation_gate.py` asks whether an
UPSTREAM claim resolves at the pin. Both are about the CITATION. Neither asks
whether the thing the cited file holds is still what the sentence says, because
that is a claim in prose and no program can grade it (open-debt item 751 settles
that). A green citation gate is a statement about resolution, not about truth.

## What this does instead -- it does not judge, it puts the reason in front of the
## round that touched its evidence

For every atom whose reason says work REMAINS (PARTIAL, UNBUILT or UNVERIFIED),
each tracked wz file the reason cites -- resolved through the census's own
resolver, so this and the census cannot disagree about what a reason cites -- is
PINNED here to the git blob it had when a round last read that reason against it.
The pin lives in the review table named by `PINS_DOC`, one row per (atom, file).

  * a pair with no row                 -> FAIL, the row is missing
  * a row whose blob is not the file's  -> FAIL, the file moved since the reason
                                           was last read against it
  * a row with no pair                  -> FAIL, the atom left the population or
                                           stopped citing the file; drop the row
  * a malformed or duplicate row        -> FAIL

The population is DERIVED from the store and the tracked tree, never listed. A
population of zero is the NORMAL state once every atom is built, so it is not a
failure; the rule is "a cited file moved and nobody signed", not "something must
exist". What keeps the gate from being an instrument that cannot go red is the
selftest, which drives every rule in both directions over fixtures and mutates
every pair's blob to prove that no pair is skipped.

## What a pin is and is not

It is NOT evidence that the reason is true. A round can move a pin without
reading anything; nothing here can stop that, and the table says so. What it
removes is the silent case: today a round edits a cited file and the reason that
describes it is never on screen. After this, the push of that edit fails until
the reason has been opened and the row rewritten, and the row carries the round
that did it. That is the same shape the hosted-red acknowledgements have, and it
is the whole claim: VISIBILITY from the gate, JUDGEMENT from the round.

The granularity is the whole file, deliberately. A citation's line number drifts
with any insertion above it, so a narrower pin would either be line-keyed and rot
at once, or need a parser for what a sentence is about. A file edited often by
other work costs each citing atom a row move per edit, and that cost is the price
of the property; an atom whose reason cites a hot file is exactly the atom whose
reason should be re-read often.

## Seeding

`--emit --round <id>` prints the table for the tree as it stands. A row written
that way under the id `seed` says the pin was TAKEN, not that the reason was read
against that file; the first real edit to the file replaces it with a round id.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import depth_axis_census as dc  # noqa: E402

PINS_DOC = "docs/reason-review-pins.md"

# The tags that assert work still remains. Restated from the A3 audit's own
# TAGS_REMAINING because that table lives inside a shell heredoc and cannot be
# imported; the audit asserts the closed tag set, so a new remaining tag fails
# THERE first and lands here in the same change.
REMAINING_TAGS = ("UNBUILT", "PARTIAL", "UNVERIFIED")

ROUND_ID = re.compile(r"^(?:seed|R\d+[A-Za-z0-9-]*)$")
ROW = re.compile(
    r"^\|\s*([^|\s]+)\s*\|\s*([^|\s]+)\s*\|\s*([0-9a-f]{40})\s*\|\s*([^|\s]+)\s*\|\s*$"
)
SEPARATOR = re.compile(r"^\|[\s:|-]+\|\s*$")
HEADER = ("atom", "file", "blob", "round")


def remaining_reasons(entries: dict) -> dict[str, str]:
    """`{atom: reason}` for every atom whose reason head tag says work remains.

    Pure, so the selftest drives the same selection the live read uses. The two
    non-atom prefixes of the inventory are excluded by the census's own
    constants, never restated.
    """
    out: dict[str, str] = {}
    for eid, entry in entries.items():
        if eid.startswith(dc.PRESET_PREFIX) or eid.startswith(dc.DEBT_PREFIX):
            continue
        reason = (entry or {}).get("reason") or ""
        head = dc.HEAD_TAG.match(reason)
        if head and head.group(1).upper() in REMAINING_TAGS:
            out[eid] = reason
    return out


def population(
    reasons: dict[str, str], paths: list[str]
) -> tuple[dict[tuple[str, str], int], int, int, int]:
    """`(pairs, citations, ambiguous, upstream)`.

    `pairs` maps (atom, file) to how many times the reason cites that file. A
    citation pins only when it resolves to exactly ONE tracked file: several
    candidates is ambiguity (counted, never guessed at -- the reason citation
    gate ratchets those), none reads as upstream, which this tree holds no
    oracle for.
    """
    pairs: dict[tuple[str, str], int] = {}
    citations = ambiguous = upstream = 0
    for atom in sorted(reasons):
        for match in dc.CITATION.finditer(reasons[atom]):
            candidates = dc.resolve_citation(match.group(1), paths)
            if not candidates:
                upstream += 1
                continue
            if len(candidates) > 1:
                ambiguous += 1
                continue
            citations += 1
            key = (atom, candidates[0])
            pairs[key] = pairs.get(key, 0) + 1
    return pairs, citations, ambiguous, upstream


def read_pins(text: str) -> tuple[dict[tuple[str, str], tuple[str, str]], list[str]]:
    """`({(atom, file): (blob, round)}, findings)` from the review table."""
    rows: dict[tuple[str, str], tuple[str, str]] = {}
    findings: list[str] = []
    seen_header = False
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("|") or SEPARATOR.match(line):
            continue
        cells = tuple(c.strip() for c in line.strip().strip("|").split("|"))
        if cells == HEADER:
            seen_header = True
            continue
        match = ROW.match(line)
        if not match:
            findings.append(
                f"{PINS_DOC} line {number}: a table row that is not "
                f"`| atom | file | 40-hex blob | round |` -- {line.strip()[:80]!r}"
            )
            continue
        atom, path, blob, rnd = match.groups()
        if not ROUND_ID.match(rnd):
            findings.append(
                f"{PINS_DOC} line {number}: round `{rnd}` is neither `seed` nor a "
                f"round id (R followed by digits)"
            )
            continue
        if (atom, path) in rows:
            findings.append(
                f"{PINS_DOC} line {number}: a second row for ({atom}, {path}); a "
                f"pin is one row, replaced in place"
            )
            continue
        rows[(atom, path)] = (blob, rnd)
    if not seen_header:
        findings.append(f"{PINS_DOC} has no `| atom | file | blob | round |` header row")
    return rows, findings


def grade(
    pairs: dict[tuple[str, str], int],
    rows: dict[tuple[str, str], tuple[str, str]],
    blobs: dict[str, str],
) -> list[str]:
    """Findings for a population, its pins, and the files' current blobs. Pure."""
    findings: list[str] = []
    for atom, path in sorted(pairs):
        row = rows.get((atom, path))
        if row is None:
            findings.append(
                f"atom `{atom}` cites {path} and no row pins it. Read the reason "
                f"against the file, then add the row (`--emit --round <id>` prints it)."
            )
            continue
        current = blobs.get(path)
        if current is None:
            findings.append(f"atom `{atom}` cites {path}, which has no readable blob.")
        elif current != row[0]:
            findings.append(
                f"atom `{atom}` cites {path}, and that file changed since round "
                f"{row[1]} pinned it ({row[0][:10]} -> {current[:10]}). Re-read the "
                f"reason against the file -- its claims about this tree are only as "
                f"current as that read -- then set the row to {current} and this "
                f"round's id."
            )
    for atom, path in sorted(set(rows) - set(pairs)):
        findings.append(
            f"a row pins ({atom}, {path}) but the atom no longer says work remains "
            f"or no longer cites that file; drop the row."
        )
    return findings


def blobs_of(paths: list[str]) -> dict[str, str]:
    """The git blob id of each path as the worktree holds it, in ONE call."""
    if not paths:
        return {}
    done = subprocess.run(
        ["git", "hash-object", "--stdin-paths"],
        cwd=ROOT,
        input="\n".join(paths) + "\n",
        capture_output=True,
        text=True,
    )
    ids = done.stdout.split()
    if done.returncode != 0 or len(ids) != len(paths):
        raise dc.Fatal(
            f"`git hash-object` returned {len(ids)} id(s) for {len(paths)} path(s) "
            f"(rc {done.returncode}): {done.stderr.strip()[:200]}"
        )
    return dict(zip(paths, ids))


def live() -> tuple[dict[tuple[str, str], int], int, int, int, dict[str, str]]:
    import json

    try:
        data = json.loads((ROOT / dc.STORE).read_text())
    except (OSError, ValueError) as exc:
        raise dc.Fatal(f"the inventory store {dc.STORE} could not be read ({exc})") from exc
    entries = data.get("inventory_entries")
    if not isinstance(entries, dict) or not entries:
        raise dc.Fatal(f"{dc.STORE} holds no `inventory_entries` mapping.")
    pairs, citations, ambiguous, upstream = population(
        remaining_reasons(entries), dc.tracked()
    )
    return pairs, citations, ambiguous, upstream, blobs_of(sorted({p for _a, p in pairs}))


def read_doc() -> str:
    try:
        return (ROOT / PINS_DOC).read_text()
    except OSError as exc:
        raise dc.Fatal(f"{PINS_DOC} could not be read ({exc})") from exc


def emit(round_id: str) -> int:
    if not ROUND_ID.match(round_id):
        print(f"--round `{round_id}` is neither `seed` nor a round id", file=sys.stderr)
        return 2
    pairs, _c, _a, _u, blobs = live()
    print("| atom | file | blob | round |")
    print("|---|---|---|---|")
    for atom, path in sorted(pairs):
        print(f"| {atom} | {path} | {blobs[path]} | {round_id} |")
    return 0


def check() -> int:
    pairs, citations, ambiguous, upstream, blobs = live()
    rows, findings = read_pins(read_doc())
    findings += grade(pairs, rows, blobs)
    print(
        f"reason-review-pins: {len({a for a, _p in pairs})} remaining atom(s) make "
        f"{citations} wz citation(s) over {len(pairs)} (atom, file) pair(s); "
        f"{ambiguous} ambiguous and {upstream} upstream citation(s) are not pinned; "
        f"{len(rows)} row(s) in {PINS_DOC}"
    )
    if findings:
        print("reason-review-pins: FAIL", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print("reason-review-pins: OK")
    return 0


# -- Self-check ----------------------------------------------------------------
#
# Fixture paths are built by CONCATENATION: this file is tracked text, and a
# rooted path literal in it that matches no tracked file would be read by the
# upstream citation gate as a citation of upstream.

_A = "crates/wz-" + "fixture/src/" + "alpha" + ".rs"
_B = "crates/wz-" + "fixture/src/" + "beta" + ".rs"
_TWIN_ONE = "crates/wz-" + "fixture/src/" + "twin" + ".rs"
_TWIN_TWO = "crates/wz-" + "other/src/" + "twin" + ".rs"
_PATHS = [_A, _B, _TWIN_ONE, _TWIN_TWO]


def _blob(tag: str) -> str:
    return (tag * 40)[:40]


def _selftest() -> list[str]:
    bad: list[str] = []

    def eq(label: str, got, want) -> None:
        if got != want:
            bad.append(f"{label}\n      got  {got!r}\n      want {want!r}")

    entries = {
        "alpha": {"reason": f"PARTIAL: names {_A}:12 and again {_A}, plus {_B}."},
        "gamma": {"reason": f"UNBUILT -- reads {_B}"},
        "delta": {"reason": f"COMPLETE: closed in {_A}"},
        "eps": {"reason": "UNVERIFIED lanes cite nothing"},
        "preset-x": {"reason": f"PARTIAL: {_A}"},
        "debt-y": {"reason": f"PARTIAL: {_A}"},
    }
    reasons = remaining_reasons(entries)
    eq("population: only the remaining tags, never a preset- or debt- row",
       sorted(reasons), ["alpha", "eps", "gamma"])
    pairs, citations, ambiguous, upstream = population(reasons, _PATHS)
    eq("population: one pair per (atom, file) however often it is cited",
       sorted(pairs), [("alpha", _A), ("alpha", _B), ("gamma", _B)])
    eq("population: a repeated citation is counted, not collapsed",
       (pairs[("alpha", _A)], citations), (2, 4))

    amb_pairs, _c, amb, up = population(
        {"alpha": f"PARTIAL: {'crates/wz-' + 'other/src/' + 'twin' + '.rs'} and "
                  f"{'twin' + '.rs'} and {'crates/zz-' + 'gone/src/' + 'nowhere' + '.rs'}"},
        _PATHS,
    )
    eq("population: an exact path pins, a bare name matching two files is ambiguous, "
       "an unmatched path reads as upstream",
       (sorted(amb_pairs), amb, up), ([("alpha", _TWIN_TWO)], 1, 1))

    blobs = {_A: _blob("a"), _B: _blob("b")}
    table = (
        "# Review pins\n\nprose that is not a row\n\n"
        "| atom | file | blob | round |\n|---|---|---|---|\n"
        f"| alpha | {_A} | {blobs[_A]} | R9 |\n"
        f"| alpha | {_B} | {blobs[_B]} | seed |\n"
        f"| gamma | {_B} | {blobs[_B]} | R9 |\n"
    )
    rows, parse = read_pins(table)
    eq("table: a clean table parses with no finding", (len(rows), parse), (3, []))
    eq("rule clean: pins that equal the files' blobs are silent",
       grade(pairs, rows, blobs), [])

    # RULE: a cited file moved. Red-first twin of the silent case above.
    moved = dict(blobs, **{_A: _blob("c")})
    got = grade(pairs, rows, moved)
    eq("rule moved: exactly the one (atom, file) whose blob changed is named",
       (len(got), "alpha" in got[0] and _A in got[0] and "changed" in got[0]), (1, True))
    # The same blob change must reach every atom that cites the file.
    moved_b = dict(blobs, **{_B: _blob("c")})
    eq("rule moved: a file cited by two atoms is reported once per atom",
       len(grade(pairs, rows, moved_b)), 2)
    # No pair may be skipped: poison every blob and every pair must answer.
    eq("rule moved: poisoning every blob reds every pair (none is skipped)",
       len(grade(pairs, rows, {p: _blob("f") for p in blobs})), len(pairs))

    # RULE: a pair with no row.
    partial_rows = {k: v for k, v in rows.items() if k != ("gamma", _B)}
    got = grade(pairs, partial_rows, blobs)
    eq("rule missing: a pair with no row is named",
       (len(got), "gamma" in got[0] and "no row" in got[0]), (1, True))

    # RULE: a row with no pair (the atom left the population, or stopped citing).
    orphan = {**rows, ("delta", _A): (blobs[_A], "R9")}
    got = grade(pairs, orphan, blobs)
    eq("rule orphan: a row whose atom no longer says work remains is named",
       (len(got), "delta" in got[0] and "drop the row" in got[0]), (1, True))

    # RULE: a duplicate and a malformed row, and a table with no header.
    _r, parse = read_pins(table + f"| alpha | {_A} | {blobs[_A]} | R10 |\n")
    eq("rule table: a second row for one pair is refused", len(parse), 1)
    _r, parse = read_pins(table + "| alpha | " + _A + " | not-a-blob | R9 |\n")
    eq("rule table: a blob that is not 40 hex digits is refused", len(parse), 1)
    _r, parse = read_pins(table + f"| beta | {_A} | {blobs[_A]} | someday |\n")
    eq("rule table: a round that is neither seed nor a round id is refused",
       len(parse), 1)
    _r, parse = read_pins("no table here at all\n")
    eq("rule table: a document with no header row is refused", len(parse), 1)

    # THE TWIN THAT KEEPS THE GATE HONEST: nothing remains, nothing is pinned.
    none_pairs, _c, _a, _u = population(remaining_reasons({"delta": {"reason": "COMPLETE"}}), _PATHS)
    eq("twin: an empty population against an empty table is silent, not a failure",
       grade(none_pairs, {}, {}), [])
    eq("twin: an empty population against a stale row still reds the row",
       len(grade(none_pairs, {("alpha", _A): (blobs[_A], "R9")}, {})), 1)
    return bad


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="grade the tree (default)")
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--emit", action="store_true", help="print the table for the tree")
    parser.add_argument("--round", default=None, help="round id for --emit rows")
    args = parser.parse_args()
    if args.selftest:
        bad = _selftest()
        if bad:
            print(f"reason_review_pin_gate self-check FAIL: {len(bad)}")
            for entry in bad:
                print(f"    - {entry}")
            return 1
        print("reason_review_pin_gate self-check OK")
        return 0
    try:
        if args.emit:
            if not args.round:
                print("--emit needs --round <id|seed>", file=sys.stderr)
                return 2
            return emit(args.round)
        return check()
    except dc.Fatal as exc:
        print(f"reason-review-pins: cannot grade -- {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

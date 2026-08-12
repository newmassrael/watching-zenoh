#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y741 (N43) -- a gate must say WHICH register item it answers for.

R311y742 refined the wording, because the first form said "closes" and that was
too narrow to be true. `count_guard_lint.py` IS the measurement for base item
§7.1, and §7.1 is still OPEN -- it reports 53 bare guards, 22 checked, 31 out of
scope every run. A gate like that is exactly what the register needs to find,
and "closes" would have forced it to either lie or stay silent. What the
citation names is the item this gate ANSWERS FOR: it closed the item, or it
stands as the item's standing measurement.

## The problem this is the structural half of

The open-debt register carries ~196 base items. R311y739 re-counted them and
found the count was right, but could only re-establish whether FOUR of them
were still open -- because nothing in the tree points back at a register item.
Deciding "is §7.1 closed?" means re-investigating the tree, which is the same
investigation that was done when the item was first opened. The waste is built
into the arrangement, and it is why that list drifts.

`solo_plane_page_lint.py` already showed the fix: its docstring opens
`R311y621 (§7.14)`, so anyone asking about §7.14 finds the gate that closed it
in one grep. As of R311y740 that convention was followed by 11 of 33 gate
scripts under `scripts/lib` -- a convention nothing enforced.

## What is required

Every gate script's header (first 60 lines, after SPDX / shebang) must open
with a provenance citation:

    R311y<round> (<item>)      e.g. R311y621 (§7.14), R311y736 (N28)

where `<item>` is a §-numbered base item, a carry `N<nn>`, or `CENSUS` for the
domain-census axis. When the gate answers for no register item at all -- and
most predate the register, closing a DEFECT found that round rather than a
listed debt -- the explicit escape hatch:

    R311y<round> (no register item)

The escape hatch is NAMED on purpose. Silence cannot distinguish "this gate
closes nothing" from "nobody wrote it down", and it was that ambiguity, not
the absence of an item, that made the register unmaintainable. Declaring
"nothing" costs one line and is a real answer.

## The citation is checked against the REGISTER (R311y743, carry N48)

R311y741 could only check the SHAPE of a citation, because the register lived
in the operator's notes rather than in the tree — so `(§9.9)` passed. R311y743
moved the carry axis into the atomic store's INVENTORY, the same record type
the 213 atoms already use, under a `debt-` prefix. A `N<nn>` citation is now
resolved against `debt-carry-N<nn>`: naming an item the store does not hold is
a FAIL that prints the id.

Why the store and not a text file: the two debt axes in this project have
opposite drift histories. The atoms are typed, section-bound inventory entries
that four gates re-derive, and four independent re-measurements produced
identical numbers; the register's lists were prose, and R311y739 could
re-establish the open/closed state of four of roughly two hundred. The
difference is the mechanism, not the content.

STILL SHAPE-ONLY: `§N.N` base items and `CENSUS`. The §F base list has not
migrated yet, so a `(§9.9)` citation still passes. That is the remaining half
of N48 and it is stated here rather than implied by silence.

## Baseline, and why it is now EMPTY

R311y741 carried the 22 pre-convention gates in a named baseline because
retrofitting them meant investigating what each closed. R311y742 did that
investigation and it was far cheaper than feared: every one of those files
ALREADY stated what it was for, usually under a heading like "the defect this
closes". Eighteen answered `(no register item)` -- they close a defect found in
their own round, not a listed debt -- and four named an item: `§5.27` twice,
`§7.1` for the count-guard measurement, and `CENSUS` for the domain census.

The baseline stays as a mechanism at size zero rather than being deleted. An
empty set that is still CHECKED in both directions is what stops the list
silently regrowing; deleting it would leave the next hurried gate with nowhere
to be caught. It is NOT an exemption list to add to -- the way off it is the
citation:

  * a script here that now complies      -> FAIL, remove it from the baseline
  * a script here that no longer exists  -> FAIL, remove it from the baseline
  * a script not here that does not comply -> FAIL, name what it answers for
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import inventory_kinds

# `R<round> (<item>)` where <item> is a §-item, a carry N<nn>, CENSUS, or the
# explicit no-item declaration. Anchored to a citation so a bare round number in
# running prose does not satisfy it.
#
# The round half is deliberately loose. This tree's round ids are not one shape:
# `R290`, `R121d`, `R311n`, `R311di-13` and `R311y740` are all in use, and
# R311y742 found that out the hard way -- a `R311y\d+` form retrofitted 21 of 22
# gates and then reported `feature_implies.py` as undeclared when it had said
# `R311n (no register item)` all along. What this gate is for is the ITEM, so
# the round pattern must not become a second, accidental convention.
#
# R311y750 (N40) — the item half is a comma-separated LIST, not a single item.
# One gate can answer for more than one register entry: the self-report gate
# closes N40 (nothing gated the sweep) and N41 (its vocabulary was guessed) in
# one mechanism, because measuring the vocabulary is what makes the gate
# possible. Citing only one of them would make the other unfindable by `--emit`,
# which is the join the register's open/closed column is supposed to be
# mechanical through. A one-item citation parses exactly as before.
_ITEM = r"(?:§[^,)]{1,24}|N\d{1,2}|CENSUS|no register item)"
PROVENANCE = re.compile(
    rf"R\d+[a-z]{{0,3}}(?:-\d+)?\d*\s*\(\s*{_ITEM}(?:\s*,\s*{_ITEM})*\s*\)"
)

HEADER_LINES = 60

# EMPTY as of R311y742: all 22 pre-convention gates were retrofitted from what
# each file's own header already said it closed, so the baseline has nothing
# left to carry. It stays as a named, both-directions-checked mechanism rather
# than being deleted -- the next gate written in a hurry lands here or nowhere,
# and an empty set that is still CHECKED is what keeps the list from silently
# regrowing. NOT an exemption list to add to: the way off it is the citation.
BASELINE: set[str] = set()


def gate_scripts(lib_root: Path) -> list[Path]:
    return sorted(
        [p for p in lib_root.glob("*.py") if p.name != "__init__.py"]
        + list(lib_root.glob("*.sh")),
        key=lambda p: p.name,
    )


def citation(path: Path) -> str | None:
    """The item this gate answers for, or None when it carries no citation."""
    with path.open(encoding="utf-8") as fh:
        head = "".join(line for _, line in zip(range(HEADER_LINES), fh))
    m = PROVENANCE.search(head)
    if m is None:
        return None
    inner = m.group(0)
    return inner[inner.index("(") + 1 : inner.rindex(")")].strip()


def items(cite: str) -> list[str]:
    """The individual register items a citation names (R311y750, N40)."""
    return [part.strip() for part in cite.split(",") if part.strip()]


def complies(path: Path) -> bool:
    return citation(path) is not None


def emit(scripts: list[Path]) -> int:
    """R311y742 (N49) -- walk the citations the OTHER way.

    The lint alone makes every gate declare its item; that is only half of what
    carry N43 wanted. The half that makes the register's open/closed column
    mechanical is being able to ask "which gate answers §7.1?" and get an
    answer without reading 34 files. This prints one `<item>\tTAB\t<script>`
    row per citing gate, sorted, so the register can be joined against the tree
    instead of remembered.

    Gates that answer for no register item are counted but not listed as items
    -- they are the majority and listing them would bury the four that matter.
    """
    rows: list[tuple[str, str]] = []
    none_count = 0
    for p in scripts:
        cite = citation(p)
        if cite is None:
            continue
        if cite == "no register item":
            none_count += 1
            continue
        for item in items(cite):
            rows.append((item, p.name))

    for item, name in sorted(rows):
        print(f"{item}\t{name}")
    print(
        f"# {len(rows)} gate(s) answer for a register item; "
        f"{none_count} declare none; {len(scripts)} scanned",
    )
    return 0


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    lib_root = repo_root / "scripts" / "lib"
    scripts = gate_scripts(lib_root)

    # A scan that finds nothing must not report green -- the same rule every
    # other gate here follows, and the reason is that an empty population is
    # indistinguishable from total compliance.
    if not scripts:
        print(
            f"gate-provenance: FAIL -- found ZERO gate scripts under {lib_root}. "
            f"A gate that cannot see its subject must not pass.",
            file=sys.stderr,
        )
        return 1

    if len(sys.argv) == 2 and sys.argv[1] == "--emit":
        return emit(scripts)
    if len(sys.argv) != 1:
        print("usage: gate_provenance_lint.py [--emit]", file=sys.stderr)
        return 2

    # R311y743 (N48) — resolve every carry citation against the store. A gate
    # that cannot read its input must not report green, so an unreadable
    # inventory is a FAIL rather than a skipped check.
    #
    # R311y747 (N54) — AND THIS GATE HAS TWO HALVES WITH DIFFERENT INPUTS, which
    # is what R311y743 did not notice when it added the store read. The SHAPE
    # half reads only the gate scripts; the RESOLUTION half reads the store
    # through `mnemosyne-cli`. Layer C0 runs on the hosted job that DELIBERATELY
    # does not provision that tool -- the install is ~88s and was split out to
    # the Layers A+B job for exactly that reason -- so an unconditional FAIL
    # reddened every hosted run from R311y743 on, while every local run stayed
    # green because a dev box has the tool on PATH.
    #
    # So the halves are armed separately, in this tree's own idiom: absent tool
    # is a SKIP of the RESOLUTION half where nothing provisions it, and a FAIL
    # under `WZ_C0_REQUIRE`, which ci.yml sets on the job that DOES provision it
    # (the same rule as WZ_A3_REQUIRE / WZ_A5_REQUIRE: a lane that skips where
    # its input is provisioned is a provisioning regression wearing a green
    # badge). The shape half runs unconditionally either way -- it never needed
    # the store, and silencing it too would have been the wider hole.
    registered: set[str] | None
    try:
        registered = set(inventory_kinds.debt())
    except Exception as exc:  # noqa: BLE001 - the reason is reported, not swallowed
        if os.environ.get("WZ_C0_REQUIRE"):
            print(
                f"gate-provenance: FAIL -- required (WZ_C0_REQUIRE set) but the "
                f"store inventory cannot be read ({exc}). The citation check "
                f"cannot run, and a gate that cannot read its input must not "
                f"pass where its input is provisioned.",
                file=sys.stderr,
            )
            return 1
        registered = None
        # STDERR, and that is load-bearing rather than a style choice: run-ci
        # invokes this gate with `>/dev/null`, so a skip announced on stdout is
        # a skip nobody can see -- which is the exact shape ("a half that goes
        # quiet reads as a half that passed") this arming exists to avoid.
        # MEASURED: the notice was invisible in the Layer C0 log until it moved
        # here.
        print(
            f"gate-provenance: RESOLUTION HALF SKIPPED -- the store inventory "
            f"is unreadable here ({exc}); the shape half below still runs, and "
            f"the hosted job that provisions mnemosyne-cli runs this half under "
            f"WZ_C0_REQUIRE",
            file=sys.stderr,
        )

    names = {p.name for p in scripts}
    failures = []
    declared = 0

    for path in scripts:
        item = citation(path)
        ok = item is not None
        if ok:
            declared += 1
        # A carry citation must name an item the store actually holds. §-items
        # and CENSUS stay shape-only until the base list migrates.
        if registered is not None and item:
            for one in items(item):
                if not (one.startswith("N") and one[1:].isdigit()):
                    continue
                if f"debt-carry-{one}" not in registered:
                    failures.append(
                        f"{path.name}: cites `{one}`, which the store's debt "
                        f"inventory does not hold. Register it "
                        f"(`add-inventory-entry --id debt-carry-{one}`) or correct "
                        f"the citation -- a citation nothing can resolve is the "
                        f"shape R311y741 could not catch"
                    )
        if ok and path.name in BASELINE:
            failures.append(
                f"{path.name}: now carries its provenance citation -- remove it "
                f"from BASELINE in this file, so the baseline can only shrink"
            )
        elif not ok and path.name not in BASELINE:
            failures.append(
                f"{path.name}: no provenance citation in the first {HEADER_LINES} "
                f"lines. Open the header with `R311y<round> (<item>)` naming the "
                f"register item this gate closes, or `R311y<round> "
                f"(no register item)` if it closes none"
            )

    for stale in sorted(BASELINE - names):
        failures.append(
            f"{stale}: listed in BASELINE but no such gate script exists -- "
            f"remove the stale entry"
        )

    if failures:
        print("gate-provenance: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(
            "\n  A gate that does not name what it closed leaves the open-debt "
            "register unable to tell, mechanically, whether that item is still "
            "open (R311y741, carry N43).",
            file=sys.stderr,
        )
        return 1

    # R311y747 (N54) — the resolution half's state is IN THE OK LINE, not only
    # in the skip notice above it. A reader scanning for the green word must be
    # able to see which halves earned it, or a permanently-skipped half reads as
    # a passing one.
    resolved = (
        f"{len(registered)} debt item(s) registered"
        if registered is not None
        else "citation resolution SKIPPED (no store here)"
    )
    print(
        f"gate-provenance OK -- {declared} of {len(scripts)} gate script(s) "
        f"declare what they answer for; {resolved}; "
        f"{len(BASELINE)} carried from before the convention"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

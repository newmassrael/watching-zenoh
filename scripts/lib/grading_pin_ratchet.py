#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2394 (no register item) — how many atoms are still GRADED against a zenoh
this tree no longer pins, as a number a command produces rather than one a
session remembers.

The citation is `no register item` for the reason `debt_plane_census.py` and
`config_key_fixture_gate.py` both give for theirs: the item this answers for --
unregistered open-debt item 675 -- lives in the agent-memory register, which has
no store id for `gate_provenance_lint.py` to resolve. Naming "nothing" is a real
answer; the item is named in prose throughout this header.

## The defect

An atom's inventory `reason` opens with its grade -- `PARTIAL:` or `COMPLETE:`
-- and then says what that grade was measured against. A large share of them say
`1.5.0`. The tree's pin is not 1.5.0 and has not been for some time: the oracle
pin (`scripts/build-zenohd.sh`) and the upstream checkout the citation gates
resolve against are both 1.10.0.

A `PARTIAL` graded two versions back is merely stale -- it says work remains,
and work does remain. A `COMPLETE` graded two versions back is a false
statement: it asserts parity with an upstream that has since moved, and it is
asserted about the upstream this tree exists to replace. R2394 measured one and
the measurement refuted it inside ten minutes -- `access-downsampling` was
COMPLETE against 1.5.0 while the pin's downsampling filter reads Put and Del
through separate selector bits that wz's three-variant mirror could not express.

## Why a RATCHET and not a red

The honest repair is per-atom: re-measure against the pin, write down what the
re-measurement changed, then move the declaration. That is a round's work each,
and there are dozens. A gate that turned all of them red at once would stop the
tree, and a gate that stops the tree gets switched off -- this register has the
precedent. So the budget starts at what the population MEASURED on the landing
commit and may only go down.

The direction that matters is UP. A new atom graded against 1.5.0, or an old one
whose re-write reintroduces the declaration, is the drift this exists to catch,
and it is caught the moment it lands rather than whenever someone next counts.

Both directions FAIL, which is this tree's established ratchet shape (see
`store_reason_citation_gate.py`):

  * ABOVE the budget -- an atom was graded against the stale version. Repair the
    GRADING, never the budget.
  * BELOW the budget -- a round re-measured one. Lower the budget in that SAME
    commit, so the number can never quietly drift away from what it counts.

## WHAT THE COUNT IS, and what it is NOT (R2396)

It is the number of graded atoms that do NOT DECLARE a pin measurement. That is
not the same as the number never measured at the pin, and the difference was
found by this gate's SECOND customer rather than reasoned out in advance.

`declare-token` was in the population, and R2383 had already re-measured it at
the pin and written the result into the reason -- in its own words, before this
marker existed. Measured at that commit, 14 of the 60 are in that position:
their prose asserts a pin reading somewhere, in a spelling no regex can be
trusted to grade, because "mentions 1.10.0" is exactly the substitution this
gate exists to refuse.

So the number over-states the WORK and states the DECLARATION exactly, which is
the honest thing for it to measure: prose cannot be graded, a declaration can.
Paying one of the 14 is therefore cheaper than paying a fresh one -- but it is
NOT a stamp, and `declare-token` is the proof. Both of the pin claims R2383
wrote cited a path that does not exist at the pin (one repository-name segment
too many), so the round that stamped the marker had to read the pin to find the
claims true and the citations dead. A round that had trusted the prose would
have propagated two dead citations; a round that had read the citation gate's
"unresolved" finding as a verdict on the CLAIM would have re-opened a grade that
is correct. Verify, then declare.

## What it derives rather than declares

The population is read out of the store: every `inventory_entries` value whose
`reason` begins with a grade tag and mentions the stale version. Nothing here
lists atom ids, so an atom renamed or added is inside the count by construction.

A population that collapses to zero REASONS is a reader that stopped matching
the store, not a store that stopped making claims, and it FAILS -- the "a
population of zero reports green" trap this tree has paid for more than once.
The zero that legitimately ends this gate is a zero STALE count against a
non-zero graded population, and only that pair is reported as done.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
STORE = ROOT / "docs/.atomic/workspace.atomic.json"

#: The version an atom must no longer be graded against. This is deliberately a
#: LITERAL rather than "whatever is not the pin": the question is not "does the
#: reason mention some version" but "does it still declare the one the tree has
#: moved off", and only a named string answers that without re-reading prose.
STALE_VERSION = "1.5.0"

#: The marker a round writes when it has re-measured an atom AGAINST THE PIN.
#:
#: The first draft of this gate had no such marker and asked only "does the
#: reason mention 1.5.0". That predicate FAILED ON ITS OWN FIRST CUSTOMER, which
#: is how it was found: R2394 re-measured `access-downsampling`, refuted its
#: COMPLETE grade, built the missing kind and rewrote the reason -- and the
#: count did not move, because an honest re-measurement has to NAME the version
#: it refuted in order to say what changed. A predicate that counts the record
#: of the repair as the debt punishes exactly the rounds that pay it, and the
#: only way to satisfy it would have been to delete the history.
#:
#: So the discriminator is not "which version numbers appear" but "has a round
#: DECLARED that this atom's grade was re-measured at the pin". `transport-stats`
#: had already coined the phrase for its own re-declaration in R2371, so this
#: adopts it rather than inventing a second spelling.
#:
#: THE RESIDUE, STATED RATHER THAN HIDDEN: a marker is a declaration, and this
#: gate cannot tell a declaration backed by a measurement from one that is not.
#: What it does stop is the cheap bulk edit the register warned about -- a
#: substitution of the version string across every reason clears nothing here,
#: because the marker is per-atom prose naming the round that measured it, and
#: the ratchet below forces the budget down in that same commit.
PIN_DECLARED = "PIN RE-DECLARED"

#: The grade tags an inventory reason opens with. A reason that opens with
#: neither is not a grading claim at all (the store also carries `debt-` items,
#: whose reasons are register prose), so it is outside the population.
GRADE_TAGS = ("PARTIAL:", "COMPLETE:")

#: Seeded at what `--count` PRINTS for this commit's PARENT: 61.
#:
#: Derived, not remembered. 62 graded reasons name the stale version there; one
#: of them, `transport-stats`, already carries the pin marker because R2371
#: re-declared it, which leaves 61 in the population.
#:
#: 61 -> 60 (R2394). The round re-measured `access-downsampling` against the pin,
#: found the refutation described above, BUILT the missing kind rather than
#: re-tagging, and re-declared that atom -- this ratchet's "removed one"
#: direction. The split was 43 PARTIAL / 17 COMPLETE after the move.
#:
#: 60 -> 59 (R2396). `declare-token`, and it is the case that taught this gate
#: what its own number MEANS -- see WHAT THE COUNT IS BELOW. R2383 had already
#: re-measured that atom at the pin and written the result down; what was
#: missing was the DECLARATION, not the measurement. This round re-verified both
#: of its claims by reading the pin -- the envelope writes ext_qos only when it
#: differs from DEFAULT and counts it into the header's Z flag, and the body's
#: extension chain is still consumed while that flag rides -- found them true,
#: repaired the two dead paths they cited, and stamped the marker. The split is
#: 43 PARTIAL / 16 COMPLETE after the move.
BUDGET = 59

#: A reader that matches nothing has stopped matching the store. Well below the
#: real graded population (MEASURED at the landing commit: 312 inventory
#: entries, of which 132 open with a grade tag), so it fires on a broken reader
#: rather than on a tree that legitimately paid the debt down.
MIN_GRADED = 40


def graded_reasons(store: dict) -> list[tuple[str, str]]:
    """Every (atom id, reason) whose reason opens with a grade tag.

    Derived from the store's own inventory rather than from any list here, so an
    atom added or renamed is inside the population without an edit.
    """
    out: list[tuple[str, str]] = []
    for atom_id, entry in sorted((store.get("inventory_entries") or {}).items()):
        if not isinstance(entry, dict):
            continue
        reason = entry.get("reason") or ""
        if reason.startswith(GRADE_TAGS):
            out.append((atom_id, reason))
    return out


def stale(reasons: list[tuple[str, str]]) -> list[tuple[str, str, str]]:
    """The graded reasons that name the stale version and carry no pin marker.

    Returns (atom id, grade, first line of the declaring context) so a failure
    names what to re-measure rather than only how many there are.
    """
    out: list[tuple[str, str, str]] = []
    for atom_id, reason in reasons:
        if STALE_VERSION not in reason:
            continue
        # An atom a round has RE-MEASURED at the pin is out of the population
        # even though it still names the version it was re-measured off; see
        # PIN_DECLARED for why the naive predicate counted the repair as debt.
        if PIN_DECLARED in reason:
            continue
        grade = reason.split(":", 1)[0]
        where = ""
        for m in re.finditer(re.escape(STALE_VERSION), reason):
            start = max(0, m.start() - 60)
            where = " ".join(reason[start : m.end() + 20].split())
            break
        out.append((atom_id, grade, where))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--count",
        action="store_true",
        help="print the stale count alone and exit 0; the SSOT for the budget",
    )
    ap.add_argument(
        "--list",
        action="store_true",
        help="print every stale atom with its grade, newest budget move first",
    )
    args = ap.parse_args()

    try:
        store = json.loads(STORE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"  grading-pin-ratchet: FAIL cannot read the store: {exc}")
        return 1

    reasons = graded_reasons(store)
    if len(reasons) < MIN_GRADED:
        print(
            f"  grading-pin-ratchet: FAIL only {len(reasons)} graded reason(s) "
            f"found, below the {MIN_GRADED} floor -- this reader has stopped "
            f"matching the store, which is not the same as the debt being paid"
        )
        return 1

    rows = stale(reasons)
    count = len(rows)

    if args.count:
        print(count)
        return 0

    if args.list:
        for atom_id, grade, where in sorted(rows, key=lambda r: (r[1], r[0])):
            print(f"  {grade:9} {atom_id}")
            if where:
                print(f"            ...{where}")

    partial = sum(1 for _, g, _ in rows if g == "PARTIAL")
    complete = count - partial
    print(
        f"  grading-pin-ratchet: {count} graded reason(s) still declare "
        f"{STALE_VERSION} (PARTIAL {partial} / COMPLETE {complete}) of "
        f"{len(reasons)} graded, budget {BUDGET}"
    )

    if count > BUDGET:
        print(
            f"  grading-pin-ratchet: FAIL {count} > {BUDGET} -- an atom is "
            f"graded against {STALE_VERSION}, which the tree does not pin. "
            f"Re-measure it against the pin and move its declaration; do NOT "
            f"raise the budget, and do NOT substitute the version string, "
            f"which makes the claim true only in its letters. Run with --list "
            f"to see which atoms are in the population."
        )
        return 1

    if count < BUDGET:
        print(
            f"  grading-pin-ratchet: FAIL {count} < {BUDGET} -- this commit "
            f"re-measured an atom against the pin, which is the direction this "
            f"ratchet is for. Lower BUDGET to {count} in "
            f"scripts/lib/grading_pin_ratchet.py, in this same commit, and say "
            f"in the note above which atom moved and what the re-measurement "
            f"changed."
        )
        return 1

    if count == 0:
        print(
            "  grading-pin-ratchet: DONE -- every graded atom declares the pin. "
            "This gate now asserts by machine what open-debt item 675 asked for."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

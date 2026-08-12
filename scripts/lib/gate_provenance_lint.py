#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y741 (N43) -- a gate must say WHICH open item it closes.

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

or, when the gate genuinely closes no register item -- a census tool, a
build-support scanner -- the explicit escape hatch:

    R311y<round> (no register item)

The escape hatch is NAMED on purpose. Silence cannot distinguish "this gate
closes nothing" from "nobody wrote it down", and it was that ambiguity, not
the absence of an item, that made the register unmaintainable. Declaring
"nothing" costs one line and is a real answer.

## What this CANNOT check, stated plainly

The register lives in the operator's notes, not in this repository, so this
lint validates the SHAPE of the citation and never that the item exists or
that the gate truly closes it. A citation can therefore be wrong; it cannot
be absent. That is a smaller guarantee than it looks like it should be, and
pretending otherwise would be the failure mode this file exists to fight.

## Baseline, and why it is a SET

22 scripts predate the convention. Retrofitting them means investigating what
each closed -- exactly the cost this lint exists to stop paying -- so they are
carried in an explicit baseline rather than silently exempted. The baseline is
a SET of names, not a count: a count is satisfied by any 22 scripts, so one
new undeclared gate could hide behind one retrofitted one. Membership is
checked in BOTH directions, so the baseline cannot rot:

  * a script here that now complies      -> FAIL, remove it from the baseline
  * a script here that no longer exists  -> FAIL, remove it from the baseline
  * a script not here that does not comply -> FAIL, name what it closes
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# `R311y<round> (<item>)` where <item> is a §-item, a carry N<nn>, or the
# explicit no-item declaration. Anchored to a citation so a bare round number
# in running prose does not satisfy it.
PROVENANCE = re.compile(
    r"R311y\d+\s*\(\s*(?:§[^)]{1,24}|N\d{1,2}|no register item)\s*\)"
)

HEADER_LINES = 60

# Scripts that predate R311y741. NOT an exemption list to grow -- every entry
# is a gate whose closed item nobody recorded, and the only correct way off
# this list is to write the citation.
BASELINE = {
    "apfull_membership.py",
    "atom_test_graph.py",
    "capi_c_coverage.py",
    "capi_c_opaque_arms.py",
    "count_guard_lint.py",
    "crossimpl_audit.py",
    "crossimpl_corpus.py",
    "discarded_evidence_lint.py",
    "dissect_feature_census.py",
    "dissect_name_census.py",
    "domain_census.py",
    "duplicate_module_lint.py",
    "expired_blocker_lint.py",
    "feature_closure.py",
    "feature_implies.py",
    "python_floor_lint.py",
    "unsequenced_probe_lint.py",
    "unwired_lane_lint.py",
    "nda-scan.sh",
    "schema-pin-gate.sh",
    "test-zenoh-c-oracle-arm.sh",
    "zenoh-c-oracle-arm.sh",
}


def gate_scripts(lib_root: Path) -> list[Path]:
    return sorted(
        [p for p in lib_root.glob("*.py") if p.name != "__init__.py"]
        + list(lib_root.glob("*.sh")),
        key=lambda p: p.name,
    )


def complies(path: Path) -> bool:
    with path.open(encoding="utf-8") as fh:
        head = "".join(line for _, line in zip(range(HEADER_LINES), fh))
    return PROVENANCE.search(head) is not None


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

    names = {p.name for p in scripts}
    failures = []
    declared = 0

    for path in scripts:
        ok = complies(path)
        if ok:
            declared += 1
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

    print(
        f"gate-provenance OK -- {declared} of {len(scripts)} gate script(s) "
        f"declare what they close; {len(BASELINE)} carried from before the "
        f"convention"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

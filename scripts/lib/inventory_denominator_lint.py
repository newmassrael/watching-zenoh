#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y758 (N53) -- the ATOM DENOMINATOR gate.

## The defect, which already happened and exited GREEN

Layer A5 prints `201 of 213 inventory atoms` and Layer A3 prints `atoms=213`.
Both numerators are checked to death -- A5 re-derives membership from cargo's own
feature closure and re-validates every exclusion against the live inventory, A3
tags every atom's implementation axis and refuses an untagged one. Nothing
checked the DENOMINATOR.

R311y743 widened `inventory_kinds.is_atom` while moving the debt register into
the store, and A5 printed `201 of 215` and exited 0. Two entries that are not
atoms had entered the population that decides "how much of the protocol is
this", and every gate over it stayed green, because a denominator that grows
makes each individual assertion EASIER rather than harder. The register carried
that as N53.

## Why a pinned number would be the wrong gate

`atoms == 213` in a constant is a gate that reds on every legitimate atom
addition and decays into a reflex edit -- which is precisely how a wrong one
slips through (the `dissect_name_census` docstring records this exact decay for
golden JSON tests). It also pins a COUNT, and this workspace's own rule is to
pin a SET: a count is satisfied by any 213 entries, including 212 atoms plus one
debt item.

## What it asserts: two INDEPENDENT discriminators must name the same set

The store answers "which entries are atoms" two ways that do not share a
mechanism:

  * BY PREFIX -- `inventory_kinds.is_atom`, defined by exclusion (neither
    `preset-` nor `debt-`). This is the predicate all four gates consume, and
    the one R311y743 widened.
  * BY STRUCTURE -- an entry carrying a `section_ref`. Atoms are bound to the
    spec section that specifies them; preset bundles and debt items are not
    bound to anything, and cannot be, because no section specifies a bundle or
    a debt.

Measured at R311y758: 213 atoms, all 213 with a section_ref; 6 presets and 73
debt items, none with one. The two discriminators agree exactly, and they agree
for different reasons -- which is what makes the comparison load-bearing rather
than circular. Widening the prefix predicate moves one set and not the other.

It also asserts the kinds PARTITION the store: every entry is exactly one kind,
so a fourth prefix cannot arrive and be absorbed into the atom count by the
`is_atom`-by-exclusion definition (the same shape one namespace over).

## Anti-vacuity is FIRST, not last

An empty store satisfies every set comparison below. This workspace has shipped
a gate whose population was zero and which reported green for it, so the counts
are floored before anything is compared: no kind may be empty, and a store that
reads as fewer entries than kinds is a FAIL rather than a pass.

Exit 0 with the census when the discriminators agree; exit 1 naming the
disagreeing ids otherwise.
"""

from __future__ import annotations

import os
import sys

import inventory_kinds

# The floor exists to catch an EMPTY or truncated read, not to pin the census --
# pinning is the SET comparison below. Each kind must be non-empty, which is the
# weakest statement that still refuses a vacuous pass.
MIN_PER_KIND = 1


def _kind_of(eid: str) -> str:
    """Exactly one kind per id, asserted rather than assumed by the caller."""
    kinds = []
    if inventory_kinds.is_preset(eid):
        kinds.append("preset")
    if inventory_kinds.is_debt(eid):
        kinds.append("debt")
    if inventory_kinds.is_atom(eid):
        kinds.append("atom")
    if len(kinds) != 1:
        return "+".join(kinds) if kinds else "<none>"
    return kinds[0]


def main() -> int:
    # A gate that cannot read its input must not report green. Where nothing
    # provisions `mnemosyne-cli` this SKIPs; where the job DOES provision it,
    # `WZ_C0_REQUIRE` turns the same condition into a FAIL -- the idiom
    # WZ_A3_REQUIRE / WZ_A5_REQUIRE / gate_provenance_lint already follow.
    try:
        entries = inventory_kinds.load_entries()
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        if os.environ.get("WZ_C0_REQUIRE"):
            print(
                f"inventory-denominator: FAIL -- required (WZ_C0_REQUIRE set) but the "
                f"store inventory cannot be read ({exc}). The denominator cannot be "
                f"checked, and a gate that cannot read its input must not pass where "
                f"that input is provisioned.",
                file=sys.stderr,
            )
            return 1
        # STDERR on purpose: run-ci may invoke this with `>/dev/null`, and a skip
        # announced on stdout is a skip nobody can see.
        print(
            f"inventory-denominator: SKIPPED -- the store inventory is unreadable "
            f"here ({exc}); the hosted job that provisions mnemosyne-cli runs this "
            f"under WZ_C0_REQUIRE",
            file=sys.stderr,
        )
        return 0

    failures: list[str] = []

    ids = [inventory_kinds.entry_id(e) for e in entries]
    if any(i is None for i in ids):
        failures.append(
            f"{sum(1 for i in ids if i is None)} inventory entry(ies) carry no id; "
            f"the kind of an unnamed entry cannot be decided"
        )
    ids = [i for i in ids if i]

    by_kind: dict[str, set[str]] = {}
    for eid in ids:
        by_kind.setdefault(_kind_of(eid), set()).add(eid)

    # (0) ANTI-VACUITY, before any comparison -- an empty store passes every set
    # equality below.
    for kind in ("atom", "preset", "debt"):
        n = len(by_kind.get(kind, ()))
        if n < MIN_PER_KIND:
            failures.append(
                f"kind `{kind}` has {n} entry(ies), below the floor of {MIN_PER_KIND}. "
                f"An empty kind satisfies every set comparison in this gate, so this "
                f"is a FAIL rather than a trivially clean run -- the store read is "
                f"empty or truncated."
            )

    # (1) PARTITION -- every id is exactly one kind. An id matching two
    # predicates, or none, means the kind space stopped being a partition and
    # `is_atom`-by-exclusion is silently absorbing something.
    for kind, members in sorted(by_kind.items()):
        if kind in ("atom", "preset", "debt"):
            continue
        failures.append(
            f"{len(members)} id(s) resolve to kind `{kind}` rather than exactly one of "
            f"atom / preset / debt: {sorted(members)[:5]}. `is_atom` is defined by "
            f"EXCLUSION, so a kind space that is no longer a partition folds the "
            f"remainder into the atom denominator."
        )

    # (2) THE TWO DISCRIMINATORS -- prefix vs structure. This is the check N53
    # names: the sets must be equal, and they are computed from facts that do not
    # share a mechanism.
    by_prefix = by_kind.get("atom", set())
    by_structure = {
        eid
        for eid, e in ((inventory_kinds.entry_id(e), e) for e in entries)
        if eid and e.get("section_ref")
    }

    prefix_only = sorted(by_prefix - by_structure)
    structure_only = sorted(by_structure - by_prefix)
    for eid in prefix_only:
        failures.append(
            f"`{eid}` counts as an ATOM by prefix but carries NO section_ref. Either it "
            f"is an atom and is unbound to the section that specifies it, or the kind "
            f"predicate widened and a non-atom entered the denominator that A5's "
            f"'N of M' and A3's 'atoms=M' both report."
        )
    for eid in structure_only:
        failures.append(
            f"`{eid}` carries a section_ref but does NOT count as an atom by prefix "
            f"(kind={_kind_of(eid)}). The denominator SHRANK: an atom bound to a spec "
            f"section has dropped out of the population every gate grades against."
        )

    print(
        f"inventory denominator: {len(by_prefix)} atom(s) by prefix, "
        f"{len(by_structure)} by section_ref binding"
    )
    for kind in ("atom", "preset", "debt"):
        print(f"  {kind}: {len(by_kind.get(kind, ()))}")

    if failures:
        print()
        print("inventory-denominator FAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("inventory-denominator OK -- prefix and section_ref binding name the same set")
    return 0


if __name__ == "__main__":
    sys.exit(main())

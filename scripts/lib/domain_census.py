#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y315 — domain census: every `domain-<X>` feature must name every `<X>-*` atom.

## Why this exists

`docs/feature_inventory.md`, `wz/Cargo.toml::domain-query` and `::domain-pubsub` each
carried a HAND-MAINTAINED list of atoms. All three drifted from the store, and the drift
was not cosmetic: `domain-query` omitted `query-value` (added R311y248), and that omission
is the traced origin of a "10 query atoms" census that a later round carried as fact and
audited against. A wrong denominator makes a burn-down report progress it has not made.

The root cause was never the list — it was that `query-value` had no facade forward in
`wz/Cargo.toml` at all, so the list COULD NOT name it. Nothing noticed for 67 rounds
because nothing compared the list to the store.

## The invariant

    for each `domain-<X>` feature in the wz facade:
        { atoms in the store with prefix `<X>-` } SUBSET OF { features domain-<X> lists }

A domain list is a census. A census that disagrees with the SSOT is a lie with a number
attached, and this file is the only thing that checks it.

## How it reads the feature table

Via `cargo metadata`, i.e. cargo's OWN parse — never a regex over Cargo.toml. This is not
fastidiousness: the R311y315 session wrote the naive regex first, and it counted a quoted
`"11"` inside a COMMENT as a listed feature, reporting 13 members for a 12-member list.
Ask cargo; do not re-implement cargo (the same rule `feature_closure.py` states).

## The carry ledger

Three domains diverged BEFORE this check existed. They are carried, not silently skipped:
the check prints them every run and fails only on a NEW divergence — the same
`ledger=N carry` vs `new=+M reject` shape Mnemosyne's orphan ledger uses.

Each carry's reason is deliberately "not yet established". That is the honest state: the
`domain-*` lists carry no stated policy anywhere in the tree, so whether these omissions
are intentional (sub-namespace grouping / unbuilt atoms withheld) or are the same accident
`query-value` was HAS NOT BEEN AUDITED. Do not invent a reason to close a row; audit it,
then delete the row. Removing a row without an audit is silence-bypass.
"""

import json
import subprocess
import sys

# Domains whose list already disagreed with the store at R311y315, with the
# per-domain count measured at that point. A row is a promise to audit, not a
# blessing. Shrink this dict; never grow it without a recorded reason.
CARRY = {
    "domain-routing": (9, "not yet established whether the 9 omissions are intentional"),
    "domain-storage": (13, "storage-backend-* / storage-mgr-* sub-namespaces; unaudited"),
    "domain-transport": (5, "not yet established whether the 5 omissions are intentional"),
}


def facade_features(manifest_dir):
    """The `wz` facade's feature table, as cargo itself parses it."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=manifest_dir,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for pkg in json.loads(out)["packages"]:
        if pkg["name"] == "wz":
            return pkg["features"]
    raise SystemExit("domain census: no `wz` package in cargo metadata")


def store_atoms():
    """Inventory atom ids from the Mnemosyne store (the SSOT)."""
    out = subprocess.run(
        ["mnemosyne-cli", "query", "--list-inventory", "--json"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {row["id"] for row in json.loads(out)}


def audit(manifest_dir):
    feats = facade_features(manifest_dir)
    atoms = store_atoms()
    new_divergence, carried = [], []

    for name in sorted(k for k in feats if k.startswith("domain-")):
        prefix = name[len("domain-") :] + "-"
        # `dep:x` and `crate/feat` entries are plumbing, not atom names.
        listed = {f for f in feats[name] if not f.startswith("dep:") and "/" not in f}
        missing = sorted({a for a in atoms if a.startswith(prefix)} - listed)
        if not missing:
            continue
        if name in CARRY and len(missing) == CARRY[name][0]:
            carried.append((name, missing))
        else:
            new_divergence.append((name, missing))

    for name, missing in carried:
        print(f"  domain census carry: {name} omits {len(missing)} atom(s) "
              f"-- {CARRY[name][1]}")
    for name, missing in new_divergence:
        expected = CARRY.get(name, (0, ""))[0]
        drift = f" (carry expected {expected})" if name in CARRY else ""
        print(f"  domain census FAIL: {name} omits {len(missing)}{drift}: "
              f"{', '.join(missing)}")

    print(f"  domain census: {len(carried)} carried / {len(new_divergence)} new")
    if new_divergence:
        print("  A domain list that omits a domain atom is a census that disagrees")
        print("  with the store. Either add the atom (check the wz facade actually")
        print("  FORWARDS it -- a missing forward is why query-value was absent), or")
        print("  audit the omission and add a CARRY row stating the reason.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(audit(sys.argv[1] if len(sys.argv) > 1 else "crates"))

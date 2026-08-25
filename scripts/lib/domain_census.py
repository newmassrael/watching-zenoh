#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y315 (CENSUS) — domain census: every `domain-<X>` feature must name every `<X>-*` atom.

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

import inventory_kinds
import sys

# Domains whose list already disagreed with the store at R311y315. A row is a
# promise to audit, not a blessing. Shrink this dict; never grow it without a
# recorded reason.
#
# Each row pins the exact SET of omitted atoms, never a count. R311y315's first
# draft pinned `len(missing)` and an adversarial review broke it in one move:
# rename an atom in the store, touch no Cargo.toml, and the count stays equal so
# a brand-new omission passes green — the gate built to stop census rot, rotting
# by the very mechanism it exists to catch. A COUNT IS A CITATION. Pin the set.
CARRY = {
    "domain-routing": (
        {
            "routing-data-route-compute",
            "routing-interceptor-framework",
            "routing-interceptor-hotreload",
            "routing-interest-broker",
            "routing-interest-pending-gc",
            "routing-namespace",
            "routing-query-route-compute",
            "routing-route-cache",
            "routing-token-tables",
        },
        "not yet established whether these omissions are intentional",
    ),
    "domain-storage": (
        {
            "storage-backend-capability",
            "storage-backend-external-db",
            "storage-backend-filesystem",
            "storage-backend-memory-volume",
            "storage-backend-rocksdb",
            "storage-backend-volume-trait",
            "storage-mgr-complete-flag",
            "storage-mgr-config",
            "storage-mgr-dynamic-volume-loading",
            "storage-mgr-garbage-collection",
            "storage-mgr-multi-storage-host",
            "storage-mgr-strip-prefix",
            "storage-mgr-wildcard-updates",
        },
        "storage-backend-* / storage-mgr-* sub-namespaces; unaudited",
    ),
    "domain-transport": (
        {
            "transport-link-quic-datagram",
            "transport-link-unixpipe",
            "transport-multilink",
            "transport-qos",
            "transport-stats",
        },
        "not yet established whether these omissions are intentional",
    ),
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
    """Atom ids from the Mnemosyne store (the SSOT), EXCLUDING presets.

    `--list-inventory` returns inventory ENTRIES, which is atoms + `preset-*`
    bundles. Layer A3 draws the same line ("excluding presets (bundles, not
    atoms)") and prints the atom count; conflating the two is how R311y315's
    banner reported the store as having 219 atoms when it has 213.

    R311y743 — the line itself now lives in `inventory_kinds`, shared by all
    four consumers, so a third entry kind cannot be counted as an atom by
    whichever consumer forgot to filter it.
    """
    return set(inventory_kinds.atoms())


def audit(manifest_dir):
    feats = facade_features(manifest_dir)
    atoms = store_atoms()
    new_divergence, carried = [], []

    for name in sorted(k for k in feats if k.startswith("domain-")):
        prefix = name[len("domain-") :] + "-"
        # `dep:x` and `crate/feat` entries are plumbing, not atom names.
        listed = {f for f in feats[name] if not f.startswith("dep:") and "/" not in f}
        missing = {a for a in atoms if a.startswith(prefix)} - listed
        if not missing:
            continue
        expected = CARRY[name][0] if name in CARRY else set()
        if missing == expected:
            carried.append((name, missing))
        else:
            # Set difference, so a rename shows as one appeared + one resolved
            # rather than hiding inside an unchanged count.
            new_divergence.append((name, missing - expected, expected - missing))

    for name, missing in carried:
        print(f"  domain census carry: {name} omits {len(missing)} atom(s) "
              f"-- {CARRY[name][1]}")
    for name, appeared, resolved in new_divergence:
        if appeared:
            print(f"  domain census FAIL: {name} omits atom(s) no carry covers: "
                  f"{', '.join(sorted(appeared))}")
        if resolved:
            print(f"  domain census FAIL: {name} no longer omits "
                  f"{', '.join(sorted(resolved))} -- the carry row is stale; "
                  f"drop those entries from CARRY to record the progress")

    # The subset check above asks "does the list name every atom?". A census can
    # also disagree the other way: name something the store does not have. That
    # is latent today (zero phantoms across every domain-*) but it is the same
    # lie, so it is checked rather than assumed.
    phantom = []
    for name in sorted(k for k in feats if k.startswith("domain-")):
        prefix = name[len("domain-") :] + "-"
        listed = {f for f in feats[name] if not f.startswith("dep:") and "/" not in f}
        extra = sorted(f for f in listed if f.startswith(prefix) and f not in atoms)
        if extra:
            phantom.append((name, extra))
            print(f"  domain census FAIL: {name} names non-atom(s): {', '.join(extra)}")

    print(f"  domain census: {len(carried)} carried / "
          f"{len(new_divergence) + len(phantom)} new")
    if new_divergence or phantom:
        print("  A domain list is a census; disagreeing with the store is a lie with")
        print("  a number attached. To fix an OMISSION add the atom -- and check the")
        print("  wz facade actually FORWARDS it, since a missing forward, not a lazy")
        print("  list, is why query-value was absent. To record PROGRESS on a carried")
        print("  row, delete the resolved atoms from that row's set in CARRY. To defer")
        print("  an omission, add it to CARRY with the reason it is deferred -- never")
        print("  a reason invented to silence the row.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(audit(sys.argv[1] if len(sys.argv) > 1 else "crates"))

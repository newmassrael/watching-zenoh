#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y496 — the `preset-ap-full` MEMBERSHIP gate (run-ci Layer A5).

`preset-ap-full` is the artifact that answers "does the whole thing build and run
together". Its membership had been maintained by hand, and it drifted four rounds
running -- each time a WHOLE FAMILY, each time found by accident while doing
something else:

  R311y461  routing-token-tables   the router-scope liveliness-token plane
  R311y488  ext-pubsub-*           the entire advanced pub/sub family
  R311y489  adminspace-*           seven of the eight adminspace atoms
  R311y491  router-hat-*           the run-mode's own atom, while carrying its plumbing
  R311y496  storage-mgr-* etc.     the storage manager and every backend

None of those omissions was recorded as a decision anywhere -- not in the preset's
comment, not in the ledger, not in the atoms' inventory reasons. They were not
decisions; they were things nobody had noticed. Four consecutive rounds of the same
shape is a missing gate, not five separate mistakes, so this is the gate.

## What it asserts

1. EVERY inventory atom that is a declared `wz` cargo feature is in the
   `preset-ap-full` closure, unless it is on EXCLUSIONS below.
2. Every EXCLUSIONS entry names a real atom, is genuinely NOT a member (a stale
   exclusion is a lie about the preset), and SATISFIES ITS CATEGORY'S PREDICATE
   against the inventory. That last one is what stops this table from becoming
   the silencing mechanism it exists to replace: an atom cannot be excluded as
   `out-of-scope` unless the inventory says OUT-OF-SCOPE, and the inventory is
   mutated through Mnemosyne's typed primitives with a ledger entry behind it.
3. The `wz-ap-demo` `preset-ap-full` closure covers every non-preset feature that
   manifest declares -- the demo's own "held back" rule, mechanised. A demo key
   whose atom the preset carries may not sit unreachable, and a demo key added
   ahead of its atom fails on assertion 1.

## What it does NOT assert

That the preset BUILDS -- Layer C4 does that, and it is the reason a membership
addition cannot be waved through: an atom that does not compose reds C4. And that
a member is EXERCISED: membership is a build claim, proof is Layer A4's axis.
Adding an atom here moves neither A3 nor A4, and saying otherwise would be the
over-claim R311y493 had to correct by appending a round.

Usage:
    python3 scripts/lib/apfull_membership.py            # gate; non-zero on violation
    python3 scripts/lib/apfull_membership.py --report   # print the membership, always 0
"""

import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WZ_MANIFEST = os.path.join(REPO_ROOT, "crates", "wz", "Cargo.toml")
DEMO_MANIFEST = os.path.join(REPO_ROOT, "crates", "wz-ap-demo", "Cargo.toml")
PRESET = "preset-ap-full"

# ── The exclusion table ───────────────────────────────────────────────────────
#
# Each entry: atom -> (category, why). The category's PREDICATE (below) is
# re-checked against the live inventory on every run, so an entry cannot outlive
# the fact that justifies it.
EXCLUSIONS = {
    # A preset names ONE platform, and this one names `platform-linux`. These are
    # not omissions but the complement of that choice -- they are mutually
    # exclusive with it, not additional to it.
    "platform-bare-metal": ("alt-platform", "this preset is the Linux deploy"),
    "platform-freertos": ("alt-platform", "this preset is the Linux deploy"),
    "platform-macos": ("alt-platform", "this preset is the Linux deploy"),
    "platform-qnx": ("alt-platform", "this preset is the Linux deploy"),
    "platform-windows": ("alt-platform", "this preset is the Linux deploy"),
    "platform-zephyr": ("alt-platform", "this preset is the Linux deploy"),
    # R311y498 — the same shape one layer further out, and it was found the hard
    # way: the two C ABIs SHARE the `z_*` symbol namespace (both export z_open,
    # z_put, z_session_loan, ... with different type layouts), so a binary can
    # offer one or the other and linking both is a duplicate-symbol error. The
    # preset names `api-compat-pico`; `api-compat-c` is its alternative, not an
    # addition. The wz facade turns enabling both into a compile_error, so this
    # exclusion records a constraint the code already enforces.
    "api-compat-c": ("alt-abi", "this preset offers the zenoh-pico C ABI"),
    # Same shape one layer up: the preset names `runtime-tokio`, and an alternate
    # executor is a replacement for it rather than a companion to it.
    "runtime-async-std": ("alt-runtime", "this preset runs on tokio"),
    "runtime-coop": ("alt-runtime", "this preset runs on tokio"),
    "runtime-no-std": ("alt-runtime", "this preset runs on tokio"),
    # Ratified OUT-OF-SCOPE by user decision 2026-07-13 (R311y256): third-party
    # system adapters, not protocol surface. The Durable-storage capability they
    # would demonstrate is carried by `storage-backend-filesystem`, which IS a
    # member as of R311y496.
    "storage-backend-rocksdb": ("out-of-scope", "third-party system adapter"),
    "storage-backend-external-db": ("out-of-scope", "third-party system adapter"),
    # The `unbuilt` CATEGORY and its predicate remain defined below with no entry
    # using them, deliberately: it is the exclusion an atom lands in when work is
    # scheduled but not done, and both atoms that ever used it (R311y497's
    # storage-mgr-dynamic-volume-loading, R311y498's api-compat-c) left it the only
    # way it can be left -- by being built.
    # R311y498 REMOVED the `api-compat-c` entry that sat here. It was the LAST
    # atom this gate printed as OPEN, and it expired the only way an `unbuilt`
    # exclusion can: by being built (slice 1 — upstream's own z_put.c links and
    # runs against the wz cdylib, Layer C1cc). preset-ap-full carries it beside
    # its zenoh-pico twin. The exclusion table is now entirely alt-platform,
    # alt-runtime and ratified out-of-scope — no OPEN items remain.
    # R311y497 REMOVED the `storage-mgr-dynamic-volume-loading` entry that sat
    # here, and the way it left is the point of this table. R311y256 deprecated
    # that atom as OBVIATED while writing the condition into its own reason -- "if
    # plugin-dynamic-loading is ever built, this returns with it" -- R311y492 fired
    # the condition, and R311y496 returned it to `reserved` with an UNBUILT tag and
    # made this gate PRINT it every run so it could not go quiet a second time.
    # R311y497 BUILT it (wz-volume-abi + a dlopen volume host + a client-selectable
    # volume on the storage-add wire, Layers C1bv/E14), so it is a MEMBER and an
    # exclusion for it would now be false. It was not re-categorised or
    # re-worded: an `unbuilt` exclusion expires by being built, and this is what
    # that expiry looks like.
}


def _predicate_alt_platform(atom, entry):
    return atom.startswith("platform-") and atom != "platform-linux"


def _predicate_alt_runtime(atom, entry):
    return atom.startswith("runtime-") and atom not in (
        "runtime-tokio",
        "runtime-tokio-uring",
        "runtime-zero-copy",
    )


def _predicate_alt_abi(atom, entry):
    """An `api-compat-*` OTHER than the one this preset carries.

    Mirrors the alt-platform / alt-runtime predicates: the exclusion is legitimate
    only while the atom really is an alternative to a member, so naming an atom
    that is not an `api-compat-*` fails here rather than being taken on trust.
    """
    return atom.startswith("api-compat-") and atom != "api-compat-pico"


def _predicate_out_of_scope(atom, entry):
    return entry["reason"].lstrip().upper().startswith("OUT-OF-SCOPE")


def _predicate_unbuilt(atom, entry):
    return "UNBUILT" in entry["reason"].upper()


PREDICATES = {
    "alt-platform": (_predicate_alt_platform, "a `platform-*` other than platform-linux"),
    "alt-runtime": (_predicate_alt_runtime, "a `runtime-*` other than the tokio set"),
    "alt-abi": (_predicate_alt_abi, "an `api-compat-*` other than api-compat-pico"),
    "out-of-scope": (_predicate_out_of_scope, "an inventory reason tagged OUT-OF-SCOPE"),
    "unbuilt": (_predicate_unbuilt, "an inventory reason tagged UNBUILT"),
}


def cargo_features(manifest):
    """The package's declared `[features]` table, as cargo resolves it.

    Asks cargo rather than parsing the manifest: a regex over quoted strings
    counts feature names that appear in COMMENTS too, which is exactly how a
    137-member list was once reported as 138 (R311y461).
    """
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--manifest-path", manifest],
        cwd=os.path.join(REPO_ROOT, "crates"),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    ).stdout
    meta = json.loads(out)
    name = os.path.basename(os.path.dirname(manifest))
    pkg = next(p for p in meta["packages"] if p["name"] == name)
    return pkg["features"]


def closure(features, root):
    """The set of THIS package's features that enabling `root` turns on.

    Cross-package edges (`dep/feat`, `dep?/feat`) are skipped: they name another
    package's feature, and this gate is about this manifest's own claims.
    """
    seen, stack = set(), [root]
    while stack:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f)
        for m in features.get(f, []):
            if "/" in m or "?" in m:
                continue
            stack.append(m)
    return seen


def inventory():
    """atom id -> {status, reason}, presets excluded (they are bundles, not atoms)."""
    out = subprocess.run(
        ["mnemosyne-cli", "query", "--list-inventory", "--json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    ).stdout
    data = json.loads(out)
    entries = data if isinstance(data, list) else data.get("entries", data.get("inventory", []))
    atoms = {}
    for e in entries:
        aid = e.get("id") or e.get("inventory_id")
        if not aid or aid.startswith("preset-"):
            continue
        atoms[aid] = {"status": e.get("status"), "reason": (e.get("reason") or "")}
    return atoms


def main():
    report_only = "--report" in sys.argv
    atoms = inventory()
    wz_features = cargo_features(WZ_MANIFEST)
    members = closure(wz_features, PRESET)
    atom_members = sorted(a for a in atoms if a in members)
    omitted = sorted(a for a in atoms if a in wz_features and a not in members)

    print(f"preset-ap-full: {len(members)} feature(s) in closure, "
          f"{len(atom_members)} of {len(atoms)} inventory atoms")

    failures = []

    # (1) every omitted atom must be on the table.
    for a in omitted:
        if a not in EXCLUSIONS:
            failures.append(
                f"atom `{a}` (status={atoms[a]['status']}) is a wz feature but is NEITHER a "
                f"member of {PRESET} NOR on the exclusion table in "
                f"scripts/lib/apfull_membership.py. Add it to the preset, or add it to "
                f"EXCLUSIONS with a category whose predicate the inventory supports."
            )

    # (2) every table entry must be real, still omitted, and still justified.
    for a, (category, why) in sorted(EXCLUSIONS.items()):
        if a not in atoms:
            failures.append(f"exclusion `{a}` names no inventory atom (renamed or removed?)")
            continue
        if a in members:
            failures.append(
                f"exclusion `{a}` is STALE: the atom IS a member of {PRESET}. "
                f"Remove the entry — an exclusion that does not exclude misdescribes the preset."
            )
            continue
        predicate, expected = PREDICATES.get(category, (None, None))
        if predicate is None:
            failures.append(f"exclusion `{a}` has unknown category `{category}`")
            continue
        if not predicate(a, atoms[a]):
            failures.append(
                f"exclusion `{a}` claims category `{category}`, which requires {expected}, "
                f"but the inventory says status={atoms[a]['status']} "
                f"reason={atoms[a]['reason'][:60]!r}. The exclusion no longer holds."
            )

    # (3) the demo binary must be able to reach everything the preset claims.
    demo_features = cargo_features(DEMO_MANIFEST)
    demo_members = closure(demo_features, PRESET)
    held_back = sorted(
        k for k in demo_features
        if k not in demo_members and k != "default" and not k.startswith("preset-")
    )
    for k in held_back:
        failures.append(
            f"wz-ap-demo declares `{k}` but `{PRESET}` does not reach it, so the AP-full "
            f"BINARY compiles the capability in and cannot reach it from argv. Either add "
            f"the key to the demo's preset-ap-full, or (if its atom is genuinely absent) "
            f"say so — the demo manifest's own held-back rule is what this checks."
        )

    print(f"exclusions: {len(EXCLUSIONS)} atom(s) deliberately out")
    for a, (category, why) in sorted(EXCLUSIONS.items()):
        marker = "  OPEN " if category == "unbuilt" else "       "
        print(f"{marker}- {a}  [{category}] {why}")
    print(f"wz-ap-demo held-back keys: {len(held_back)}")

    if failures and not report_only:
        print()
        print("apfull-membership FAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    if failures:
        print()
        print(f"(--report: {len(failures)} violation(s) not enforced)")
        return 0
    print("apfull-membership OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4491 (no register item) -- Layer C1bf: the configurations every workspace member is clippied
in, and which shard runs each.

THE POPULATION. Every member of the `crates` workspace, in each of its LARGEST configurations:
one build with every feature on, or, for a crate that refuses some combination of its own
features by `compile_error!`, each set its manifest declares under `[package.metadata.wz-docs]`.
The sets are `doc_feature_sets.py`'s, read through its `cargo_arguments`, so the documentation
lanes and this one hold one statement of what a crate can hold at once, and a crate that grows a
refusal declares it in one place. A manifest whose sets leave a feature in none of them is
refused there and fails this plan, by name.

THE TARGETS. Every configuration is clippied with every target (`--all-targets`), unless its set
declares `clippy-targets`, a list of cargo target selectors, in the same manifest table. That is
for a set whose test targets cannot be built on its configuration: a dev-dependency follows its
own features and not the crate's, so a crate whose selector replaces forms that its
dev-dependencies are written over has tests only on the other set. The manifest says why beside
the declaration; this plan holds the declaration to known selectors.

WHY EVERY MEMBER. A struct literal, a match or an import names the items of the build its author
made, and a feature that is never on together with another is a composition no lane compiles.
The lane once held a list of the crates that showed one shape of that defect (a `cfg`-gated
`pub` field) and an audit that re-derived the list; the list went red each time a crate grew the
shape, and the other shapes (a type that changes with a feature, an item a feature removes) were
in no list. The population is the workspace now, and there is nothing to keep in step with it.

THE PARTITION. Longest first, onto the shard with the least load so far, ties to the lower
shard: the standard greedy schedule, deterministic, so every shard computes the same partition
and each runs only its own part. The weight of a configuration is the seconds
`allfeat_clippy_costs.txt` records for it; one it does not record weighs `UNMEASURED_SECONDS`,
which is a weight and not a measurement, and with no row at all the partition is a round robin
in the fixed order. The lane prints `C1bf cost: <crate> <label> <seconds>` for each
configuration it ran, which is the table's row form. A row that names a configuration the
workspace no longer has is refused: a weight nobody can spend moves the partition and says
nothing.

Usage:
    allfeat_clippy_plan.py plan [--shard I --shards N]   one `<crate> <label> <cargo argument>...`
                                                         line per configuration of shard I, the
                                                         target arguments first
    allfeat_clippy_plan.py --check                       the whole plan's refusals, one line
                                                         when there are none (pre-push gate 2z)
    allfeat_clippy_plan.py --selftest
Exit: 0 printed; 1 usage or the workspace could not be read; 2 a manifest's sets or the cost
table are wrong.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import doc_feature_sets

ROOT = Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
COSTS = Path(__file__).resolve().parent / "allfeat_clippy_costs.txt"
UNMEASURED_SECONDS = 60
ALL_TARGETS = "--all-targets"
# The cargo target selectors a set may narrow its clippy to.
TARGET_SELECTORS = (ALL_TARGETS, "--lib", "--bins", "--tests", "--examples", "--benches")

Configuration = tuple[str, str, list[str]]


class PlanError(Exception):
    """The configurations or their weights cannot be decided."""


def workspace_packages() -> list[dict]:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=CRATES,
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        print(f"allfeat-clippy: cargo metadata failed: {out.stderr.strip()}", file=sys.stderr)
        raise SystemExit(1)
    packages = sorted(json.loads(out.stdout)["packages"], key=lambda p: p["name"])
    if not packages:
        print("allfeat-clippy: cargo metadata listed no workspace member", file=sys.stderr)
        raise SystemExit(1)
    return packages


def declared_targets(package: dict) -> dict[str, list[str]]:
    """`set name -> target arguments` for each set that declares `clippy-targets`.

    A set that declares none is clippied with every target. One that declares a list is
    clippied with those cargo target selectors and no others: a set whose test targets cannot
    be built on its own configuration (a dev-dependency that cannot follow its features) says so
    in its manifest, beside the reason, rather than in a list kept here.
    """
    config = (package.get("metadata") or {}).get(doc_feature_sets.METADATA_KEY) or {}
    out: dict[str, list[str]] = {}
    for entry in config.get("feature-sets") or []:
        if "clippy-targets" not in entry:
            continue
        targets = entry["clippy-targets"]
        name = entry.get("name")
        if (
            not isinstance(targets, list)
            or not targets
            or len(set(targets)) != len(targets)
            or any(t not in TARGET_SELECTORS for t in targets)
            or (ALL_TARGETS in targets and len(targets) > 1)
        ):
            raise PlanError(
                f"{package['name']}: the set {name!r} declares clippy-targets {targets!r}; want a "
                f"non-empty list of distinct selectors from {list(TARGET_SELECTORS)}, "
                f"{ALL_TARGETS} alone"
            )
        out[name] = list(targets)
    return out


def configurations(packages: list[dict]) -> list[Configuration]:
    """`[(crate, label, cargo arguments)]` for the workspace, in the fixed order. The arguments
    are the targets, then the features."""
    listed: list[Configuration] = []
    for package in packages:
        try:
            arguments = doc_feature_sets.cargo_arguments(package)
        except doc_feature_sets.ManifestError as error:
            raise PlanError(f"{package['name']}: {error}") from error
        targets = declared_targets(package)
        listed.extend(
            (package["name"], label, targets.get(label, [ALL_TARGETS]) + args)
            for label, args in arguments
        )
    return listed


def parse_costs(text: str) -> dict[tuple[str, str], int]:
    """`(crate, label) -> seconds` from the table's text: `<crate> <label> <seconds> <source>`."""
    costs: dict[tuple[str, str], int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split(maxsplit=3)
        if len(fields) < 4 or not fields[2].isdigit():
            raise PlanError(
                f"cost table line {number}: want `<crate> <label> <seconds> <source>`: {line!r}"
            )
        key = (fields[0], fields[1])
        if key in costs:
            raise PlanError(f"cost table line {number}: {key[0]} {key[1]} is recorded twice")
        costs[key] = int(fields[2])
    return costs


def weights(listed: list[Configuration], costs: dict[tuple[str, str], int]) -> list[int]:
    known = {(crate, label) for crate, label, _ in listed}
    stale = sorted(key for key in costs if key not in known)
    if stale:
        raise PlanError(
            f"the cost table names {len(stale)} configuration(s) the workspace does not have: "
            + ", ".join(f"{crate} {label}" for crate, label in stale[:8])
        )
    return [costs.get((crate, label), UNMEASURED_SECONDS) for crate, label, _ in listed]


def partition(weight: list[int], shards: int) -> list[int]:
    """The shard of each configuration: longest first onto the least loaded shard."""
    load = [0] * shards
    owner = [0] * len(weight)
    for index in sorted(range(len(weight)), key=lambda i: (-weight[i], i)):
        target = min(range(shards), key=lambda s: (load[s], s))
        owner[index] = target
        load[target] += weight[index]
    return owner


def plan(
    listed: list[Configuration], costs: dict[tuple[str, str], int], shard: int, shards: int
) -> list[Configuration]:
    if shards < 1 or not 0 <= shard < shards:
        raise PlanError(f"shard {shard} of {shards} is not a shard")
    owner = partition(weights(listed, costs), shards)
    return [entry for entry, s in zip(listed, owner) if s == shard]


def selftest() -> int:
    # The population follows the manifest: a crate with no sets is one configuration of every
    # feature, a crate with sets is one per set, and a manifest with a hole fails the plan.
    plain = {"name": "plain", "features": {"a": [], "b": []}}
    split = {
        "name": "split",
        "features": {"ap": [], "mcu": []},
        "metadata": {
            doc_feature_sets.METADATA_KEY: {
                "feature-sets": [
                    {"name": "ap-only", "except": ["mcu"]},
                    {"name": "mcu-only", "except": ["ap"]},
                ]
            }
        },
    }
    listed = configurations([plain, split])
    assert [(c, label) for c, label, _ in listed] == [
        ("plain", "all"),
        ("split", "ap-only"),
        ("split", "mcu-only"),
    ], listed
    assert listed[0][2] == [ALL_TARGETS, doc_feature_sets.ALL_FEATURES], listed
    assert listed[1][2] == [ALL_TARGETS, doc_feature_sets.NO_DEFAULT_FEATURES, "--features=ap"], (
        listed
    )

    # A set may narrow its targets, and only that set is narrowed: the other set of the same
    # crate keeps every target. A declaration that is not a list of distinct known selectors, or
    # that pairs `--all-targets` with another, fails the plan by the crate's name.
    def narrowed(targets: object) -> dict:
        return {
            "name": "narrowed",
            "features": {"heap": [], "slot": []},
            "metadata": {
                doc_feature_sets.METADATA_KEY: {
                    "feature-sets": [
                        {"name": "heap", "except": ["slot"]},
                        {"name": "slot", "except": ["heap"], "clippy-targets": targets},
                    ]
                }
            },
        }

    lib_only = configurations([narrowed(["--lib"])])
    assert [(label, args) for _, label, args in lib_only] == [
        ("heap", [ALL_TARGETS, doc_feature_sets.NO_DEFAULT_FEATURES, "--features=heap"]),
        ("slot", ["--lib", doc_feature_sets.NO_DEFAULT_FEATURES, "--features=slot"]),
    ], lib_only
    two = configurations([narrowed(["--lib", "--bins"])])
    assert two[1][2][:2] == ["--lib", "--bins"], two
    for bad in ([], ["--lob"], ["--lib", "--lib"], [ALL_TARGETS, "--lib"], "--lib"):
        try:
            configurations([narrowed(bad)])
        except PlanError as error:
            assert "narrowed" in str(error) and "slot" in str(error), error
        else:
            raise AssertionError(f"accepted clippy-targets {bad!r}")
    holed = {
        "name": "holed",
        "features": {"ap": [], "mcu": [], "both": ["ap", "mcu"]},
        "metadata": dict(split["metadata"]),
    }
    try:
        configurations([holed])
    except PlanError as error:
        assert "holed" in str(error) and "both" in str(error), error
    else:
        raise AssertionError("a manifest with a feature in no set was planned")

    # The table: rows read, comments and blank lines skipped, a short row and a repeated one refused.
    costs = parse_costs("# c l s source\n\nsplit ap-only 300 hosted run 1\n")
    assert costs == {("split", "ap-only"): 300}, costs
    for bad in ("split ap-only 300\n", "split ap-only many seconds\n",
                "split ap-only 1 a\nsplit ap-only 2 b\n"):
        try:
            parse_costs(bad)
        except PlanError:
            pass
        else:
            raise AssertionError(f"accepted the table {bad!r}")

    # Weights: a recorded configuration weighs its seconds, any other UNMEASURED_SECONDS, and a row
    # for a configuration that is gone is refused.
    assert weights(listed, costs) == [UNMEASURED_SECONDS, 300, UNMEASURED_SECONDS]
    try:
        weights(listed, {("gone", "all"): 5})
    except PlanError as error:
        assert "gone all" in str(error), error
    else:
        raise AssertionError("a stale cost row was accepted")

    # The partition: the heavy configuration alone, the rest filling the lighter shards, ties to
    # the lower shard; with equal weights it is a round robin in the fixed order.
    assert partition([10, 100, 10, 10, 10], 2) == [1, 0, 1, 1, 1]
    assert partition([5, 5, 5, 5, 5], 2) == [0, 1, 0, 1, 0]
    assert partition([7], 3) == [0]

    # The shards together are the population, each configuration in exactly one of them.
    wide = [(f"c{i}", "all", []) for i in range(11)]
    wide_costs = {("c3", "all"): 400, ("c7", "all"): 200}
    seen = []
    for shard in range(4):
        seen.extend(crate for crate, _, _ in plan(wide, wide_costs, shard, 4))
    assert sorted(seen) == sorted(crate for crate, _, _ in wide), seen
    assert len(seen) == len(set(seen)), seen
    assert [c for c, _, _ in plan(wide, wide_costs, 0, 4)] == ["c3"], plan(wide, wide_costs, 0, 4)
    for shard, shards in ((4, 4), (-1, 4), (0, 0)):
        try:
            plan(wide, wide_costs, shard, shards)
        except PlanError:
            pass
        else:
            raise AssertionError(f"planned shard {shard} of {shards}")

    # The committed table names configurations by the labels this plan gives them.
    parse_costs(COSTS.read_text(encoding="utf-8"))

    print("allfeat-clippy-plan selftest: OK")
    return 0


def workspace_plan(shard: int, shards: int) -> tuple[list[Configuration], list[Configuration]]:
    """`(every configuration, the ones of shard I)` for this tree's manifests and cost table."""
    listed = configurations(workspace_packages())
    return listed, plan(listed, parse_costs(COSTS.read_text(encoding="utf-8")), shard, shards)


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--check"]:
        # The plan's refusals without its listing: a manifest whose sets leave a feature out
        # and a cost row naming a configuration the workspace no longer has are both made by
        # what a round changes, so the push that makes them is refused, not the next C1bf.
        try:
            listed, _ = workspace_plan(0, 1)
        except PlanError as error:
            print(f"allfeat-clippy: {error}", file=sys.stderr)
            return 2
        print(f"allfeat-clippy: OK -- {len(listed)} configuration(s) planned")
        return 0
    if not argv or argv[0] != "plan":
        print(__doc__, file=sys.stderr)
        return 1
    shard, shards = 0, 1
    rest = argv[1:]
    try:
        while rest:
            flag, value, rest = rest[0], rest[1], rest[2:]
            if flag == "--shard":
                shard = int(value)
            elif flag == "--shards":
                shards = int(value)
            else:
                raise ValueError(flag)
    except (IndexError, ValueError):
        print(__doc__, file=sys.stderr)
        return 1
    try:
        listed, mine = workspace_plan(shard, shards)
    except PlanError as error:
        print(f"allfeat-clippy: {error}", file=sys.stderr)
        return 2
    print(
        f"allfeat-clippy: shard {shard} of {shards}: {len(mine)} of {len(listed)} configuration(s)",
        file=sys.stderr,
    )
    for crate, label, arguments in mine:
        print(" ".join([crate, label, *arguments]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

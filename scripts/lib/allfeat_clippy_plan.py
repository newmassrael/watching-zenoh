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
                                                         line per configuration of shard I
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


def configurations(packages: list[dict]) -> list[Configuration]:
    """`[(crate, label, cargo arguments)]` for the workspace, in the fixed order."""
    listed: list[Configuration] = []
    for package in packages:
        try:
            arguments = doc_feature_sets.cargo_arguments(package)
        except doc_feature_sets.ManifestError as error:
            raise PlanError(f"{package['name']}: {error}") from error
        listed.extend((package["name"], label, args) for label, args in arguments)
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
    assert listed[0][2] == [doc_feature_sets.ALL_FEATURES], listed
    assert listed[1][2] == [doc_feature_sets.NO_DEFAULT_FEATURES, "--features=ap"], listed
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


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
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
        listed = configurations(workspace_packages())
        mine = plan(listed, parse_costs(COSTS.read_text(encoding="utf-8")), shard, shards)
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

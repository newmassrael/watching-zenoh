#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4576 (no register item) -- which census members a hosted Layer C1cn shard examines,
which test legs a hosted Layer C1bnl shard runs, and which cases a hosted Layer C1cs shard builds.

## Why this exists

The census of `nondefault-tests-gate.sh --census` lists every member twice and is the whole
clock of a C1cn census job. It used to take the members whose position in the member list is
congruent to the shard number. Run 44778189472 measured what that does: the 44 members cost
2,389 s together, and five of them cost 1,483 s (wz-runtime-tokio 569, wz-capi-pico 348,
wz-capi-core 230, wz-session-core 174, wz-capi-c 162). A position says nothing about cost, so
the two shards read 1,047 s and 1,342 s, and run 44790303307 on a slower runner took 97 and
100 percent of the 1800 s budget. No count of shards fixes that while the split ignores cost:
by position over three shards, one shard would hold tokio, capi-pico, session-core, zenoh and
capi-c.

So the split is by measured cost. Each member has a weight in seconds
(`c1cn_census_weights.tsv`), and the members are dealt heaviest first to the least loaded
shard (longest processing time first). Every shard computes the same plan from the same tree,
so the plan is a partition: each member is examined by exactly one shard, whatever the
weights say.

## What the weights may and may not decide

They decide BALANCE only, never COVERAGE. A member with no row is planned at the median weight
and named on stderr; a row for a crate that is no member is named on stderr and ignored. Both
leave every member examined, so neither refuses. A table that drifts shows up as an unbalanced
pair of census jobs, which `job-budget-margin.sh` already reports; refresh the table from the
`(Ns)` the census prints after every member.

## The test legs of Layer C1bnl

The legs of `nondefault-tests-gate.sh --all-legs` were split the same way, by position, and run
45051019628 read its four shards at 869, 1,647, 810 and 995 s of legs, the second at 99 percent
of its 1800 s budget with every leg green: it held the 543 s `wz-capture` leg and the 227 s
`wz-runtime-tokio` one. They are planned here too, as items named by each leg's key (its
package, filter and feature CRC, `--list-legs`), over `c1bnl_leg_weights.tsv`
(`--weights`), under the same rule: the weights decide the balance, never which legs run.

## The cases of Layer C1cs

`capability_cost_gate.py --shards N --shard K` calls [`plan`] itself over its size and statement
cases and `c1cs_case_weights.tsv` (`CASE_WEIGHTS`): one job read 1,114 s of its 1200 s budget
at run 45051019628.
"""

from __future__ import annotations

import argparse
import pathlib
import statistics
import sys

HERE = pathlib.Path(__file__).resolve().parent
WEIGHTS = HERE / "c1cn_census_weights.tsv"
LEG_WEIGHTS = HERE / "c1bnl_leg_weights.tsv"
CASE_WEIGHTS = HERE / "c1cs_case_weights.tsv"


def read_weights(text: str) -> dict[str, int]:
    weights: dict[str, int] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 2 or not fields[1].isdigit():
            raise ValueError(f"line {number}: {raw!r} is not '<crate> <seconds>'")
        if fields[0] in weights:
            raise ValueError(f"line {number}: {fields[0]} has a second row")
        weights[fields[0]] = int(fields[1])
    return weights


def read_members(text: str) -> list[tuple[str, str]]:
    """`<crate> <tier>` lines, as `nondefault-features-gate.sh --list-members` prints them."""
    members = []
    for raw in text.splitlines():
        fields = raw.split()
        if fields:
            members.append((fields[0], fields[1] if len(fields) > 1 else ""))
    return members


def plan(members: list[tuple[str, str]], weights: dict[str, int], shards: int,
         notes: list[str]) -> list[list[str]]:
    """The members of each shard, dealt heaviest first to the least loaded shard."""
    known = [weights[name] for name, _ in members if name in weights]
    fallback = int(statistics.median(known)) if known else 1
    cost: dict[str, int] = {}
    for name, tier in members:
        if tier == "excluded":
            cost[name] = 0  # the census only names it, it lists nothing
        elif name in weights:
            cost[name] = weights[name]
        else:
            cost[name] = fallback
            notes.append(f"{name} has no weight; planned at the median, {fallback} s")
    names = {name for name, _ in members}
    for name in sorted(set(weights) - names):
        notes.append(f"{name} has a weight but is no member; the row is ignored")
    loads = [0] * shards
    out: list[list[str]] = [[] for _ in range(shards)]
    for name in sorted(cost, key=lambda n: (-cost[n], n)):
        target = min(range(shards), key=lambda s: (loads[s], s))
        loads[target] += cost[name]
        out[target].append(name)
    return out


def selftest() -> int:
    members = read_members("a all-targets\nb all-targets\nc excluded\nd all-targets\ne all-targets\n")
    weights = read_weights("# comment\na 100\nb 60\nd 50  # trailing\nz 7\n")
    notes: list[str] = []
    parts = plan(members, weights, 2, notes)
    # A partition: every member exactly once.
    flat = sorted(n for part in parts for n in part)
    assert flat == ["a", "b", "c", "d", "e"], flat
    # Heaviest first to the least loaded, ties by name: a 100, b 60, e 60 (the median of the
    # members' weights), d 50, c 0.
    assert parts == [["a", "d"], ["b", "e", "c"]], parts
    # The unmeasured member and the stale row are named, not refused.
    assert any(n.startswith("e has no weight") for n in notes), notes
    assert any(n.startswith("z has a weight") for n in notes), notes
    # The plan does not depend on the member order, so every shard computes the same one.
    assert plan(list(reversed(members)), weights, 2, []) == parts
    # One shard holds everything.
    assert sorted(plan(members, weights, 1, [])[0]) == flat
    # More shards than members leaves some empty and still covers all.
    assert sorted(n for p in plan(members, weights, 9, []) for n in p) == flat
    # A malformed table is refused: it would make the weights silently mean nothing.
    for bad in ("a\n", "a x\n", "a 1\na 2\n"):
        try:
            read_weights(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad!r}")
    # The committed tables read.
    read_weights(WEIGHTS.read_text(encoding="utf-8"))
    read_weights(LEG_WEIGHTS.read_text(encoding="utf-8"))
    read_weights(CASE_WEIGHTS.read_text(encoding="utf-8"))
    print("census-shard-plan selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--shards", type=int)
    parser.add_argument("--shard", type=int)
    parser.add_argument("--weights", type=pathlib.Path, default=WEIGHTS)
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.shards is None or args.shard is None or not 0 <= args.shard < args.shards:
        print("census-shard-plan: FAIL -- give --shards N and --shard K with 0 <= K < N",
              file=sys.stderr)
        return 2
    try:
        weights = read_weights(args.weights.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        print(f"census-shard-plan: FAIL -- {args.weights}: {err}", file=sys.stderr)
        return 2
    members = read_members(sys.stdin.read())
    if not members:
        print("census-shard-plan: FAIL -- no members on stdin", file=sys.stderr)
        return 2
    notes: list[str] = []
    parts = plan(members, weights, args.shards, notes)
    for note in notes:
        print(f"census-shard-plan: {note}", file=sys.stderr)
    for name in parts[args.shard]:
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

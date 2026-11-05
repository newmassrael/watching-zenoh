#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4268 (no register item) -- the gate as a set of units the fleet can judge.

The debt this starts to repay is not in the store's `debt-` register: it is the
measurement of 2026-11-05 below, so the citation says `no register item`.

## The defect, measured

Hosted CI is where this tree's full gate gives its verdict, and it gives almost
none. Run 41939089182 queued its 44 jobs at 00:22 and was still running at
05:45; the seven CI runs created behind it (rounds 4247 to 4254) ran zero jobs
each, because the workflow's concurrency group keeps one running run and
replaces the pending one. Sampled every 20 minutes from 00:20 to 05:20, the
hosted jobs running on the account were 19 to 21 every time: the plan's cap of
20, of which another repository held 13 to 19. The runner pool is shared by
every repository of the account, so how fast this tree is judged is decided
outside it.

## The structure this is the first step of

A commit enters `main` only after its own tree passed the whole gate, and the
gate runs where this tree's owner decides the capacity: the build fleet. That
is the Not Rocket Science Rule (G. Hoare, 2014), and the fleet already holds its
parts, decided under the same instruction this round received:

  * a set of checks spread over the machines, unit by unit (bx RFC 0004);
  * a unit's pass kept under the content of its inputs, so an unchanged unit
    is not run again (RFC 0020, a constructive trace in the sense of Mokhov,
    Mitchell and Peyton Jones, *Build Systems a la Carte*);
  * the image a unit runs in, declared by the tree and part of the key
    (RFC 0034);
  * one integrator per branch that lands only what its gates judged (RFC 0024).

What the tree owes is a list of what it measures. This file is that list: the
planner of `[checks.ci]` in `bx.toml`, whose units bx hands out.

## What a unit is

One lane of `scripts/run-ci.sh` -- the line `run_layer <id> <function>` of its
dispatch table -- run by itself, the way a hosted job runs it:

    env WZ_DECLINED_EXPECT= bash scripts/run-ci.sh --layer <id>

The empty `WZ_DECLINED_EXPECT` is the hosted workflow's own assertion
(`ci.yml`, workflow `env`): a lane that ran nothing is a failure, not a pass.
Without it a unit on a machine that lacks the lane's oracle would decline and
report 0, which is a green that measured nothing.

Every unit names the same `exclusive` token. A hosted job has a machine to
itself; the lanes were written for that, and some of them bind fixed ports and
fixed paths. Until a unit runs in an image and a network of its own (RFC 0034),
two lanes do not share a machine at once. The parallelism is across machines.

The list is the dispatch table, in its order, and nothing else: every lane of
the table is wired into hosted CI (`unwired_lane_lint.py`), so the table is the
gate. A table this reader cannot find is a failure, never an empty plan.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RUNCI = Path("scripts/run-ci.sh")

# A dispatch line, exactly as the table writes it. Anchored at column 0: the
# lane functions call `run_layer` nowhere else, and a match inside a comment
# or a heredoc would add a lane the script never runs.
DISPATCH = re.compile(r"^run_layer ([A-Za-z0-9]+) (layer_[a-z0-9_]+) \|\| overall=1$", re.M)

# The token every unit shares (see the docstring). One name, so the rule is in
# one place and can be lifted in one place.
EXCLUSIVE = "run-ci-lane"


def lanes(text: str) -> list[str]:
    """The lane ids of the dispatch table, in order. Raises on a table that
    is empty or that registers one id twice (`--layer X` runs every lane under
    X, so the second would ride the first's unit unseen)."""
    ids = [m.group(1) for m in DISPATCH.finditer(text)]
    if not ids:
        raise ValueError("no `run_layer <id> layer_<fn> || overall=1` line in the dispatch table")
    seen: set[str] = set()
    twice = sorted({i for i in ids if i in seen or seen.add(i)})
    if twice:
        raise ValueError(f"lane id(s) registered twice: {', '.join(twice)}")
    return ids


def unit(lane: str) -> dict:
    return {
        "name": lane,
        "argv": ["env", "WZ_DECLINED_EXPECT=", "bash", str(RUNCI), "--layer", lane],
        "exclusive": [EXCLUSIVE],
    }


def plan(text: str, only: list[str] | None) -> list[dict]:
    ids = lanes(text)
    if only is not None:
        unknown = [o for o in only if o not in ids]
        if unknown:
            raise ValueError(f"--only names no lane: {', '.join(unknown)}")
        ids = [i for i in ids if i in only]
    return [unit(i) for i in ids]


def selftest() -> int:
    table = (
        "run_layer A layer_a_x || overall=1\n"
        "# run_layer Z layer_z_in_a_comment || overall=1\n"
        "    run_layer Y layer_y_indented || overall=1\n"
        "run_layer C1 layer_c1_y || overall=1\n"
    )
    cases = 0
    got = [u["name"] for u in plan(table, None)]
    assert got == ["A", "C1"], f"the table reads {got}, want ['A', 'C1'] (comment and indented lines are not lanes)"
    cases += 1
    u = plan(table, ["C1"])[0]
    assert u["argv"] == ["env", "WZ_DECLINED_EXPECT=", "bash", "scripts/run-ci.sh", "--layer", "C1"], u
    assert u["exclusive"] == [EXCLUSIVE], u
    cases += 1
    for bad, why in (
        ("", "an empty table"),
        ("run_layer A layer_a || overall=1\nrun_layer A layer_b || overall=1\n", "an id registered twice"),
    ):
        try:
            plan(bad, None)
        except ValueError:
            cases += 1
        else:
            raise AssertionError(f"{why} was planned instead of refused")
    try:
        plan(table, ["Nope"])
    except ValueError:
        cases += 1
    else:
        raise AssertionError("--only with an unknown lane was planned instead of refused")
    print(f"runci_plan selftest: {cases} cases pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="print run-ci.sh's lanes as bx check units (JSON Lines)")
    ap.add_argument("--only", help="comma-separated lane ids: plan these and no others")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--check", action="store_true", help="plan, and print only how many units (for a hook)")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not RUNCI.is_file():
        print(f"runci_plan: {RUNCI} not found (run from the repository root)", file=sys.stderr)
        return 2
    only = [o for o in args.only.split(",") if o] if args.only is not None else None
    try:
        units = plan(RUNCI.read_text(encoding="utf-8"), only)
    except ValueError as e:
        print(f"runci_plan: {e}", file=sys.stderr)
        return 2
    if args.check:
        print(f"runci_plan: OK -- {len(units)} lane(s) of {RUNCI} planned as units of [checks.ci]")
        return 0
    for u in units:
        print(json.dumps(u, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())

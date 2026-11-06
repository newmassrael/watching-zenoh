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

    python3 scripts/lib/runci_plan.py --layer <id>

which reads `ci.yml` where the unit runs and does what the hosted job does for
that lane, in its order:

  1. Every provisioning line of the lane's job that comes before the lane
     (`bash scripts/build-*.sh`, `install-*.sh`, `provision-*.sh`: the zenohd,
     zenoh-pico CLI, zenoh-c and Kconfig oracles), under the env the hosted
     step gives it. Each is the repository's own script, idempotent, and keeps
     what it builds where the next run finds it (zenohd in the machine's oracle
     store, `scripts/lib/oracle_store.py`), so a machine pays a build once. A
     hosted step marked "cache miss only" is run every time, because the
     script's own fast path is the cache here. A provisioning line that fails
     fails the unit, as it fails the hosted job.
  2. `bash scripts/run-ci.sh --layer <id>` under the env the hosted lane gets:
     the workflow's, the job's and the step's, merged in that order. That
     carries `WZ_DECLINED_EXPECT=` (a lane that ran nothing is a failure) and
     every `WZ_*_REQUIRE=1` that arms a leg, so a leg that would skip for want of
     its oracle fails here as it fails there.

What is not carried, and why:

  * `CARGO_*` keys of the workflow. They tune the hosted runner's builds for
    its disk; how cargo builds on a build machine is that machine's policy
    (bx's), and no verdict depends on either.
  * The keys that split a lane over hosted jobs. A key whose value is a matrix
    expression is the shard index, and the count beside it (the same name with
    an `S`, `WZ_LEGS_SHARD` of `WZ_LEGS_SHARDS`) goes with it; a key whose value
    differs between the jobs that run one lane (`WZ_C1CN_PART`) is the part. A
    unit runs the whole lane, which is what each of those keys unset means.
  * Any other expression (`GH_TOKEN`): a secret of the hosted run, which a
    build machine does not hold.
  * Steps that need `sudo` (apt packages, a kernel module, a raised limit):
    they change the machine, which a unit may not. Those are the image's
    (stage 2) or a machine's declaration in `bx.toml`.

Until 2026-11-06 a unit ran `env WZ_DECLINED_EXPECT= bash scripts/run-ci.sh
--layer <id>` and nothing else: it got neither the oracles the hosted job
provisions nor the env that arms a leg. A full run of the set placed lanes on
machines whose slot had never built a zenoh-pico CLI or zenohd, and five of them
failed as "ran nothing" (E, E6i, E8t, C1cd, Z); a lane that ran some of its legs
passed with the rest skipped, which hosted would have failed.

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
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

RUNCI = Path("scripts/run-ci.sh")
CI_YML = Path(".github/workflows/ci.yml")

# A provisioning line of a hosted step: the repository's own script, by itself, with plain
# arguments (`install-zenoh-c-arm.sh unstable`). A line that does anything else is not one.
PREP = re.compile(r"^bash (scripts/(?:build|install|provision)-[\w.-]+\.sh)((?: [\w.=-]+)*)$")

# A lane line of a hosted step, the only form `ci.yml` writes.
LANE = re.compile(r"^bash scripts/run-ci\.sh --layer ([A-Za-z0-9]+)$")

# The workflow keys that tune the hosted runner's cargo and not a lane (see the docstring).
BUILD_TUNING_PREFIX = "CARGO_"

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


@dataclass
class Hosted:
    """What the hosted job does for one lane: the provisioning lines before it, each with its
    env, and the env the lane runs under."""

    env: dict[str, str]
    prep: list[tuple[dict[str, str], list[str]]] = field(default_factory=list)


def _carried(env: dict) -> dict[str, str]:
    """The keys of a hosted env a unit carries (see the docstring), as strings."""
    def text(value: object) -> str:
        # YAML reads `true` as a bool; the runner hands the step the word it was written as.
        return str(value).lower() if isinstance(value, bool) else str(value)

    out = {
        str(k): text(v)
        for k, v in env.items()
        if not str(k).startswith(BUILD_TUNING_PREFIX) and "${{" not in text(v)
    }
    for k, v in env.items():
        if "${{" in text(v) and "matrix." in text(v):
            out.pop(str(k) + "S", None)
    return out


def hosted_runs(workflow: dict) -> dict[str, Hosted]:
    """Each lane of the workflow and what its job does for it. A lane run by more than one
    job (a part each) is run whole: the env keys those jobs agree on, and every provisioning
    line any of them runs before it, in order."""
    top = workflow.get("env") or {}
    found: dict[str, list[Hosted]] = {}
    for job in (workflow.get("jobs") or {}).values():
        job_env = job.get("env") or {}
        prep: list[tuple[dict[str, str], list[str]]] = []
        for step in job.get("steps") or []:
            env = _carried({**top, **job_env, **(step.get("env") or {})})
            for raw in (step.get("run") or "").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                m = PREP.match(line)
                if m:
                    prep.append((env, [m.group(1), *m.group(2).split()]))
                    continue
                m = LANE.match(line)
                if m:
                    found.setdefault(m.group(1), []).append(Hosted(env, list(prep)))
    merged: dict[str, Hosted] = {}
    for lane, runs in found.items():
        env = {k: v for k, v in runs[0].env.items() if all(r.env.get(k) == v for r in runs[1:])}
        prep: list[tuple[dict[str, str], list[str]]] = []
        for run in runs:
            for p in run.prep:
                if p not in prep:
                    prep.append(p)
        merged[lane] = Hosted(env, prep)
    return merged


def read_workflow() -> dict:
    import yaml  # the gates that read ci.yml use PyYAML too

    return yaml.safe_load(CI_YML.read_text(encoding="utf-8"))


def unit(lane: str) -> dict:
    return {
        "name": lane,
        "argv": ["python3", "scripts/lib/runci_plan.py", "--layer", lane],
        "exclusive": [EXCLUSIVE],
    }


def plan(text: str, only: list[str] | None, hosted: dict[str, Hosted]) -> list[dict]:
    """The units. Raises on a lane the workflow does not run: its unit would have nothing to
    say how the hosted job runs it (`unwired_lane_lint.py` holds the same set)."""
    ids = lanes(text)
    if only is not None:
        unknown = [o for o in only if o not in ids]
        if unknown:
            raise ValueError(f"--only names no lane: {', '.join(unknown)}")
        ids = [i for i in ids if i in only]
    unwired = [i for i in ids if i not in hosted]
    if unwired:
        raise ValueError(f"lane(s) no step of {CI_YML} runs: {', '.join(unwired)}")
    return [unit(i) for i in ids]


def run_lane(lane: str, hosted: dict[str, Hosted]) -> int:
    """Do for `lane` what its hosted job does (the docstring's two steps)."""
    if lane not in hosted:
        print(f"runci_plan: no step of {CI_YML} runs lane {lane}", file=sys.stderr)
        return 2
    h = hosted[lane]
    base = dict(os.environ)
    for env, argv in h.prep:
        shown = " ".join([*(f"{k}={v}" for k, v in env.items() if k not in base or base[k] != v), "bash", *argv])
        print(f"runci_plan: {lane}: provisioning as the hosted job does: {shown}", flush=True)
        rc = subprocess.call(["bash", *argv], env={**base, **env})
        if rc != 0:
            print(f"runci_plan: {lane}: provisioning failed (rc={rc}): bash {' '.join(argv)}", file=sys.stderr)
            return rc
    print(f"runci_plan: {lane}: env {' '.join(f'{k}={v}' for k, v in sorted(h.env.items()))}", flush=True)
    return subprocess.call(["bash", str(RUNCI), "--layer", lane], env={**base, **h.env})


def selftest() -> int:
    table = (
        "run_layer A layer_a_x || overall=1\n"
        "# run_layer Z layer_z_in_a_comment || overall=1\n"
        "    run_layer Y layer_y_indented || overall=1\n"
        "run_layer C1 layer_c1_y || overall=1\n"
    )
    workflow = {
        "env": {"WZ_DECLINED_EXPECT": "", "CARGO_INCREMENTAL": "0", "RUST_BACKTRACE": 1},
        "jobs": {
            "interop": {
                "env": {"WZ_PICO_REQUIRE": "1"},
                "steps": [
                    {"run": "bash scripts/build-zenohd.sh", "env": {"ZENOHD_ALLOW_CLONE": "1"},
                     "if": "steps.c.outputs.cache-hit != 'true'"},
                    {"run": "# bash scripts/build-in-a-comment.sh\nbash scripts/run-ci.sh --layer A"},
                    {"run": "bash scripts/install-zenoh-c-arm.sh unstable\nsudo apt-get install -y x"},
                    {"run": "bash scripts/run-ci.sh --layer C1", "env": {"WZ_C1_REQUIRE": True}},
                ],
            },
            "legs": {
                "strategy": {"matrix": {"shard": [0, 1]}},
                "env": {"WZ_LEGS_SHARD": "${{ matrix.shard }}", "WZ_LEGS_SHARDS": "2", "WZ_PART": "one"},
                "steps": [{"run": "bash scripts/run-ci.sh --layer C1", "env": {"GH_TOKEN": "${{ secrets.T }}"}}],
            },
        },
    }
    hosted = hosted_runs(workflow)
    cases = 0
    got = [u["name"] for u in plan(table, None, hosted)]
    assert got == ["A", "C1"], f"the table reads {got}, want ['A', 'C1'] (comment and indented lines are not lanes)"
    cases += 1
    u = plan(table, ["C1"], hosted)[0]
    assert u["argv"] == ["python3", "scripts/lib/runci_plan.py", "--layer", "C1"], u
    assert u["exclusive"] == [EXCLUSIVE], u
    cases += 1
    a = hosted["A"]
    assert a.env == {"WZ_DECLINED_EXPECT": "", "RUST_BACKTRACE": "1", "WZ_PICO_REQUIRE": "1"}, (
        f"lane A carries {a.env}: the workflow's and the job's env, no CARGO_ key"
    )
    assert a.prep == [
        ({"WZ_DECLINED_EXPECT": "", "RUST_BACKTRACE": "1", "WZ_PICO_REQUIRE": "1", "ZENOHD_ALLOW_CLONE": "1"},
         ["scripts/build-zenohd.sh"])
    ], f"lane A provisions {a.prep}: the line before it with its step's env, a commented one not"
    cases += 1
    c1 = hosted["C1"]
    assert [argv for _, argv in c1.prep] == [
        ["scripts/build-zenohd.sh"], ["scripts/install-zenoh-c-arm.sh", "unstable"]
    ], f"lane C1 provisions {c1.prep}: every line before it, a sudo line not"
    assert c1.env == {"WZ_DECLINED_EXPECT": "", "RUST_BACKTRACE": "1"}, (
        f"lane C1 carries {c1.env}: run by two jobs, it keeps the keys they agree on; the shard "
        f"index, its count, the secret, the part and a one-job key are dropped"
    )
    cases += 1
    for bad, why in (
        ("", "an empty table"),
        ("run_layer A layer_a || overall=1\nrun_layer A layer_b || overall=1\n", "an id registered twice"),
        ("run_layer B layer_b || overall=1\n", "a lane no hosted step runs"),
    ):
        try:
            plan(bad, None, hosted)
        except ValueError:
            cases += 1
        else:
            raise AssertionError(f"{why} was planned instead of refused")
    try:
        plan(table, ["Nope"], hosted)
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
    ap.add_argument("--layer", help="run this lane as its hosted job does (what a unit runs)")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    for path in (RUNCI, CI_YML):
        if not path.is_file():
            print(f"runci_plan: {path} not found (run from the repository root)", file=sys.stderr)
            return 2
    hosted = hosted_runs(read_workflow())
    if args.layer is not None:
        return run_lane(args.layer, hosted)
    only = [o for o in args.only.split(",") if o] if args.only is not None else None
    try:
        units = plan(RUNCI.read_text(encoding="utf-8"), only, hosted)
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

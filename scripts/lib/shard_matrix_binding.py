#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3768 (no register item) -- a sharded job's matrix lists exactly the shards its count names.

## Why this exists

A lane that outgrows its time budget is split into N jobs of one matrix, each running the part
of the work whose position is congruent to its shard number. The script that does the work reads
two numbers from the job's environment, `WZ_<X>_SHARDS` (how many) and `WZ_<X>_SHARD` (which),
and checks that the second is below the first. It cannot see the matrix. A matrix that loses an
entry leaves every remaining job green and the work of the lost shard run by nobody, and the
workflow's comments have said "change the list and the count together" in three places, which
is a request and not a check.

## What it checks

For every job whose `env` holds a `WZ_<X>_SHARDS`:

    1. it also holds `WZ_<X>_SHARD`, and that value is `${{ matrix.shard }}`
    2. the job's `strategy.matrix.shard` is exactly `[0, 1, ..., N-1]` for the N it names
    3. the count is at least 2 (a "sharded" job of one is a job)

and for every job whose `env` holds a `WZ_<X>_SHARD` with no `WZ_<X>_SHARDS` beside it, that
the pair is incomplete.
"""

from __future__ import annotations

import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github/workflows/ci.yml"
MATRIX_REF = "${{ matrix.shard }}"
SHARDS = re.compile(r"^(WZ_[A-Z0-9_]+)_SHARDS$")


def findings(workflow: dict) -> list[str]:
    out: list[str] = []
    for name, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        env = job.get("env") or {}
        counted = {m.group(1) for key in env if (m := SHARDS.match(key))}
        singles = {
            key[: -len("_SHARD")]
            for key in env
            if key.endswith("_SHARD") and key != "WZ_SHARD"
        }
        for stem in sorted(singles - counted):
            out.append(f"job `{name}` sets {stem}_SHARD with no {stem}_SHARDS beside it")
        for stem in sorted(counted):
            count_text = str(env[f"{stem}_SHARDS"])
            if not count_text.isdigit() or int(count_text) < 2:
                out.append(f"job `{name}`: {stem}_SHARDS={count_text!r} is not a count of 2 or more")
                continue
            count = int(count_text)
            which = str(env.get(f"{stem}_SHARD", ""))
            if which != MATRIX_REF:
                out.append(
                    f"job `{name}`: {stem}_SHARD={which!r}, not {MATRIX_REF!r}, so the shard a "
                    "job runs is not the one its matrix entry names"
                )
            listed = ((job.get("strategy") or {}).get("matrix") or {}).get("shard")
            if listed != list(range(count)):
                out.append(
                    f"job `{name}`: {stem}_SHARDS={count} but its matrix lists {listed!r}, "
                    f"not {list(range(count))!r}; the shards left out run in no job"
                )
    return out


def selftest() -> int:
    def job(count="2", which=MATRIX_REF, shards=(0, 1), stem="WZ_A"):
        env = {f"{stem}_SHARDS": count}
        if which is not None:
            env[f"{stem}_SHARD"] = which
        return {"env": env, "strategy": {"matrix": {"shard": list(shards)}}}

    assert findings({"jobs": {"a": job(), "b": {"steps": []}}}) == []
    assert findings({"jobs": {"a": job("4", shards=(0, 1, 2, 3))}}) == []
    # The defect this exists for: an entry dropped from the matrix, or added without the count.
    assert any("run in no job" in f for f in findings({"jobs": {"a": job("4", shards=(0, 1, 2))}}))
    assert any("run in no job" in f for f in findings({"jobs": {"a": job("2", shards=(0, 1, 2))}}))
    # A matrix that repeats an entry, or does not start at 0.
    assert any("run in no job" in f for f in findings({"jobs": {"a": job("2", shards=(0, 0))}}))
    assert any("run in no job" in f for f in findings({"jobs": {"a": job("2", shards=(1, 2))}}))
    # The shard the script reads is not the matrix entry.
    assert any("not '${{ matrix.shard }}'" in f for f in findings({"jobs": {"a": job(which="0")}}))
    assert any("no WZ_A_SHARDS" in f for f in findings(
        {"jobs": {"a": {"env": {"WZ_A_SHARD": MATRIX_REF}}}}))
    assert any("count of 2 or more" in f for f in findings({"jobs": {"a": job("1", shards=(0,))}}))
    assert any("count of 2 or more" in f for f in findings({"jobs": {"a": job("two")}}))
    print("shard-matrix-binding selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    workflow = yaml.safe_load(CI_YML.read_text(encoding="utf-8"))
    problems = findings(workflow)
    for problem in problems:
        print(f"shard-matrix-binding: FAIL -- {problem}", file=sys.stderr)
    if problems:
        return 1
    sharded = sorted(
        name
        for name, job in workflow["jobs"].items()
        if isinstance(job, dict) and any(SHARDS.match(key) for key in (job.get("env") or {}))
    )
    if not sharded:
        print("shard-matrix-binding: FAIL -- no job is sharded, so this gate reads nothing",
              file=sys.stderr)
        return 1
    print(f"shard-matrix-binding: OK -- {len(sharded)} sharded job(s): {sharded}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

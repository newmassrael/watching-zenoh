#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3768 (no register item) -- Layer C1cn is split into a census half and a builds half, and
the halves must both run.

## Why this exists

Layer C1cn asks two questions of every crate that has a non-default feature: does the
code behind the feature compile (the builds: the compile gate, the domain bundles, the
lifecycle guard), and does anything run the tests only that feature reaches (the census).
The census is sharded over the crates; the builds ran once, in the last shard. That shard
read 93 percent of its 1800 s budget while the first read half of it, because the builds
are most of its time and no choice of census positions moves them.

`WZ_C1CN_PART` splits the layer: `census` runs the census slice of the job's shard and
none of the builds, `builds` runs the builds and no census. The workflow then has one job
of each kind, and that is a pair of facts in two places, which is the shape every gate of
this directory exists to bind. Drop the builds job and the crates stop being compiled with
their features while every job stays green; run the builds twice and a job pays for
nothing.

## What it checks

    1. every job that runs `--layer C1cn` sets `WZ_C1CN_PART` to `census` or `builds`
    2. exactly one job sets `builds`
    3. at least one job sets `census`, and a census job names its shard
       (`WZ_CENSUS_SHARD`) and the count (`WZ_CENSUS_SHARDS`)
"""

from __future__ import annotations

import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github/workflows/ci.yml"
LAYER = "--layer C1cn"
PARTS = ("census", "builds")


def _runs_layer(job: dict) -> bool:
    return any(
        isinstance(step, dict) and LAYER in str(step.get("run", ""))
        for step in (job.get("steps") or [])
    )


def findings(workflow: dict) -> list[str]:
    jobs = workflow.get("jobs") or {}
    out: list[str] = []
    parts: dict[str, list[str]] = {part: [] for part in PARTS}
    for name, job in jobs.items():
        if not isinstance(job, dict) or not _runs_layer(job):
            continue
        env = job.get("env") or {}
        part = str(env.get("WZ_C1CN_PART", ""))
        if part not in PARTS:
            out.append(
                f"job `{name}` runs Layer C1cn with WZ_C1CN_PART={part!r}, "
                f"which is none of {PARTS}"
            )
            continue
        parts[part].append(name)
        if part == "census" and not (
            "WZ_CENSUS_SHARD" in env and "WZ_CENSUS_SHARDS" in env
        ):
            out.append(f"census job `{name}` does not name its shard and the shard count")
    if len(parts["builds"]) != 1:
        out.append(
            f"Layer C1cn's builds run in {len(parts['builds'])} job(s) "
            f"{parts['builds']}, not exactly one"
        )
    if not parts["census"]:
        out.append("no job runs the census half of Layer C1cn")
    return out


def selftest() -> int:
    def job(part, extra=None):
        env = {"WZ_C1CN_PART": part} if part else {}
        env.update(extra or {})
        return {"env": env, "steps": [{"run": f"bash scripts/run-ci.sh {LAYER}"}]}

    shard = {"WZ_CENSUS_SHARD": "0", "WZ_CENSUS_SHARDS": "2"}
    good = {"jobs": {"a": job("census", shard), "b": job("builds"), "c": {"steps": []}}}
    assert findings(good) == [], findings(good)
    # The builds job dropped: the defect this gate exists for.
    assert any("not exactly one" in f for f in findings({"jobs": {"a": job("census", shard)}}))
    # The builds run twice.
    twice = {"jobs": {"a": job("census", shard), "b": job("builds"), "c": job("builds")}}
    assert any("not exactly one" in f for f in findings(twice))
    # No census.
    assert any("census half" in f for f in findings({"jobs": {"b": job("builds")}}))
    # A job that runs the layer with no part, or a misspelt one.
    assert any("none of" in f for f in findings({"jobs": {"a": job(None), "b": job("builds")}}))
    assert any("none of" in f for f in findings({"jobs": {"a": job("build")}}))
    # A census job that does not name its shard.
    assert any("shard" in f for f in findings({"jobs": {"a": job("census"), "b": job("builds")}}))
    # A job that does not run the layer is not in the population.
    assert findings({"jobs": {"a": job("census", shard), "b": job("builds"), "c": {"steps": [{"run": "true"}]}}}) == []
    print("c1cn-part-binding selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    workflow = yaml.safe_load(CI_YML.read_text(encoding="utf-8"))
    problems = findings(workflow)
    for problem in problems:
        print(f"c1cn-part-binding: FAIL -- {problem}", file=sys.stderr)
    if problems:
        return 1
    jobs = workflow["jobs"]
    census = [n for n, j in jobs.items() if isinstance(j, dict) and _runs_layer(j)
              and (j.get("env") or {}).get("WZ_C1CN_PART") == "census"]
    print(f"c1cn-part-binding: OK -- census in {census}, builds in one job")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

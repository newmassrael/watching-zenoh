#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y892 (debt-job-budget-binding) — a job time budget is ONE fact in TWO places.

## Why this exists

`job-budget-margin.sh` is handed a budget in seconds and asked whether the job is
approaching it. That number has to be the job's `timeout-minutes`, because the thing the
gate is protecting against is the RUNNER killing the job -- and the runner reads
`timeout-minutes`, not the argument. ci.yml says so in prose, at every call site: "the two
numbers are one fact, so move that and move this."

Prose is not a binding. R311y892 moved a job from 20 minutes to 15 and had to remember to
move both, and nothing would have said anything if only one had moved. Move the argument
alone and the gate measures against a ceiling that is not the ceiling; move
`timeout-minutes` alone and the gate is calibrated to a budget the job no longer has -- in
the direction that matters, a job could then be cancelled at its real ceiling with the
margin gate reporting comfort all the way up.

This is the same shape `mnemosyne.toml::[tool] pin` and `MNEMOSYNE_REV` are in, and that
pair has a gate for exactly this reason (CLAUDE.md, R311y462).

## What it checks

    1. every job that runs `job-budget-margin.sh` declares `timeout-minutes`
    2. its budget argument equals `timeout-minutes * 60`
    3. that job also carries the STAMP step the margin step reads -- the two are a pair,
       and a margin step whose stamp is missing is a gate that can only ever fail
       (`job-budget-margin.sh` refuses an unreadable stamp, which Layer C0b pins)

## What it does NOT check

That every job HAS a budget gate. Most do not, and that is a decision rather than an
oversight -- so the population is REPORTED instead, and a reader can see the ratio rather
than assume it. A gate that demanded one per job would be arguing for work nobody has
scoped.
"""

from __future__ import annotations

import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github/workflows/ci.yml"

# `bash scripts/lib/job-budget-margin.sh "$RUNNER_TEMP/wz_job_start" 1800 90 30`
MARGIN = re.compile(r"job-budget-margin\.sh\s+(\S+)\s+(\d+)")
# `date +%s > "$RUNNER_TEMP/wz_job_start"`
STAMP = re.compile(r"date\s+\+%s\s*>\s*(\S+)")


def _steps(job: dict) -> list[dict]:
    return [s for s in (job.get("steps") or []) if isinstance(s, dict)]


def _runs(job: dict) -> list[str]:
    return [s["run"] for s in _steps(job) if isinstance(s.get("run"), str)]


def main() -> int:
    if not CI_YML.is_file():
        print(f"  job-budget-binding FAIL: cannot read {CI_YML}", file=sys.stderr)
        return 1

    doc = yaml.safe_load(CI_YML.read_text(encoding="utf-8"))
    jobs = (doc or {}).get("jobs") or {}
    if not jobs:
        print("  job-budget-binding FAIL: ci.yml declares no jobs", file=sys.stderr)
        return 1

    failures: list[str] = []
    gated = 0

    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        runs = _runs(job)
        margins = [m for run in runs for m in MARGIN.finditer(run)]
        if not margins:
            continue
        gated += 1

        timeout = job.get("timeout-minutes")
        if not isinstance(timeout, int):
            failures.append(
                f"job {name!r} runs job-budget-margin.sh but declares no integer "
                "`timeout-minutes` -- the gate would be measuring against a ceiling "
                "nothing sets"
            )
            continue

        stamps = {s.group(1) for run in runs for s in STAMP.finditer(run)}
        for stamp_arg, budget in ((m.group(1), int(m.group(2))) for m in margins):
            if budget != timeout * 60:
                failures.append(
                    f"job {name!r} budgets {budget}s but `timeout-minutes: {timeout}` "
                    f"is {timeout * 60}s -- one fact, two places, and only one moved"
                )
            if stamp_arg not in stamps:
                failures.append(
                    f"job {name!r} reads its start stamp from {stamp_arg} and no step "
                    "in that job writes it -- the margin gate can only ever fail"
                )

    if not gated:
        # Population zero is not a pass: it means the parse stopped matching, and a
        # census that measured nothing must not report clean.
        print(
            "  job-budget-binding FAIL: no job runs job-budget-margin.sh -- either "
            "every budget gate was removed or this lint stopped recognising them",
            file=sys.stderr,
        )
        return 1

    if failures:
        print("  job-budget-binding FAIL:", file=sys.stderr)
        for f in failures:
            print(f"    {f}", file=sys.stderr)
        return 1

    print(
        f"  job-budget-binding: {gated} of {len(jobs)} job(s) carry a time-budget gate, "
        "each bound to its own `timeout-minutes` and to a stamp its job writes"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

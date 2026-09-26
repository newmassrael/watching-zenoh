#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2872 (no register item) — every cache in this repository's CI saves as an ordinary STEP.

## The defect, measured twice

The combined `actions/cache` action saves in a POST step, and that post step
does not run when the job ends red. A cache is therefore warmed only by a job
that also went green, so a red anywhere after the cached work throws the work
away, and the next run pays it again.

* Register item 350 (R311y883) found it on the apt archives and split them into
  `actions/cache/restore` + `actions/cache/save`. It fixed the members it was
  looking at and left the class open: seven combined caches remained, every
  one of them an oracle build.
* R2872 met one of those seven. R2863 moved the zenohd key; run 36156369002
  built zenohd and then went red on E6i, so nothing was saved; run 36207477909
  rebuilt it cold and was cut off at 56 minutes inside that build, which took
  every Layer E/Z leg and cross-mcu's artifact download with it.

A fix applied member by member is the arrangement that failed, so this gate
states the class and derives the members.

## What it checks, over every cache step in every workflow and composite action

1. No step `uses: actions/cache@...` (the combined form). Any version.
2. Every `actions/cache/restore` step has, in the SAME job, an
   `actions/cache/save` step whose key either references the restore
   (`steps.<id>.`) or is the restore's key text verbatim. A restore nobody
   saves for is a cache that never warms.

It does NOT require the save to carry `always()`. Measured: two correct saves
(the Zephyr workspace and the rocksdb-engine composite) gate on `success()` or on
nothing, and both are right. Each is an ordinary step placed straight after the
work it saves, so a LATER red cannot reach it. The defect is the post step,
not the condition.

## The population is derived, and zero is a failure

The steps are read by parsing `.github/workflows/*.yml` and
`.github/actions/**/action.yml`, never from a list. A parse that yields no
cache step at all FAILS: this repository has dozens, so zero means the reader
stopped reading.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def _steps_by_job(doc: dict) -> dict[str, list[dict]]:
    """Workflow jobs, or a composite action's steps under one pseudo-job."""
    if isinstance(doc.get("jobs"), dict):
        return {
            name: list(job.get("steps") or [])
            for name, job in doc["jobs"].items()
            if isinstance(job, dict)
        }
    runs = doc.get("runs") or {}
    return {"<composite>": list(runs.get("steps") or [])}


def _uses(step: dict) -> str:
    return str(step.get("uses") or "")


def check(docs: dict[str, dict]) -> tuple[list[str], int]:
    """(failures, cache steps seen) over `{path: parsed yaml}`."""
    failures: list[str] = []
    seen = 0
    for path, doc in sorted(docs.items()):
        for job, steps in _steps_by_job(doc).items():
            restores = []
            saves = []
            for step in steps:
                uses = _uses(step)
                if not uses.startswith("actions/cache"):
                    continue
                seen += 1
                name = step.get("name") or step.get("id") or uses
                if uses.startswith("actions/cache@"):
                    failures.append(
                        f"{path} [{job}] `{name}`: the COMBINED actions/cache, which "
                        "saves in a post step that does not run when the job ends red. "
                        "Split it into actions/cache/restore + an actions/cache/save "
                        "step placed right after the step that proves the cached "
                        "work complete."
                    )
                elif uses.startswith("actions/cache/restore@"):
                    restores.append(step)
                elif uses.startswith("actions/cache/save@"):
                    saves.append(step)
            save_keys = [str((s.get("with") or {}).get("key") or "") for s in saves]
            for step in restores:
                rid = step.get("id")
                key = str((step.get("with") or {}).get("key") or "")
                paired = any(
                    (rid and f"steps.{rid}." in sk) or (key and sk == key) for sk in save_keys
                )
                if not paired:
                    failures.append(
                        f"{path} [{job}] `{step.get('name') or rid}`: a restore with no "
                        "save in its job (no save key references "
                        f"`steps.{rid}.` or repeats its key), so this cache never warms."
                    )
    return failures, seen


def load_tree() -> dict[str, dict]:
    files = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
    files += sorted((REPO_ROOT / ".github" / "actions").glob("**/action.yml"))
    return {
        str(f.relative_to(REPO_ROOT)): yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for f in files
    }


def main() -> int:
    docs = load_tree()
    failures, seen = check(docs)
    print(
        f"workflow-cache-save: {seen} cache step(s) across {len(docs)} workflow/action "
        "file(s)"
    )
    if seen == 0:
        print(
            "workflow-cache-save FAIL: parsed ZERO cache steps. This repository has "
            "dozens, so the reader stopped reading; a green here would grade nothing.",
            file=sys.stderr,
        )
        return 1
    if failures:
        print("workflow-cache-save FAIL:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("workflow-cache-save: OK -- no combined cache, and every restore has its save")
    return 0


def selftest() -> int:
    def wf(*steps: dict) -> dict:
        return {"jobs": {"j": {"steps": list(steps)}}}

    restore = {
        "id": "c",
        "uses": "actions/cache/restore@v4",
        "with": {"path": "p", "key": "k-1"},
    }
    save_ref = {
        "uses": "actions/cache/save@v4",
        "with": {"path": "p", "key": "${{ steps.c.outputs.cache-primary-key }}"},
    }
    save_literal = {"uses": "actions/cache/save@v4", "with": {"path": "p", "key": "k-1"}}
    cases = [
        ("combined cache", {"a.yml": wf({"uses": "actions/cache@v4"})}, "COMBINED"),
        ("combined cache, other version", {"a.yml": wf({"uses": "actions/cache@v3"})}, "COMBINED"),
        ("restore with no save", {"a.yml": wf(restore)}, "never warms"),
        (
            "save in ANOTHER job does not pair",
            {"a.yml": {"jobs": {"x": {"steps": [restore]}, "y": {"steps": [save_ref]}}}},
            "never warms",
        ),
        ("save by reference pairs", {"a.yml": wf(restore, save_ref)}, None),
        ("save by verbatim key pairs", {"a.yml": wf(restore, save_literal)}, None),
        (
            "composite action is read",
            {"x/action.yml": {"runs": {"using": "composite", "steps": [{"uses": "actions/cache@v4"}]}}},
            "COMBINED",
        ),
    ]
    bad = 0
    for label, docs, want in cases:
        failures, seen = check(docs)
        got = "\n".join(failures)
        ok = (want is None and not failures) or (want is not None and want in got)
        print(f"  {'ok ' if ok else 'BAD'}  {label}: expected {want or 'clean'}")
        bad += not ok
    failures, seen = check({"a.yml": wf({"run": "true"})})
    if seen != 0:
        print("  BAD  a workflow with no cache step counted one")
        bad += 1
    else:
        print("  ok   an empty population is seen as zero (main() FAILs on it)")
    print(f"  {len(cases) + 1 - bad}/{len(cases) + 1} arm(s) behaved as claimed")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    if sys.argv[1:]:
        print(f"usage: {sys.argv[0]} [--selftest]", file=sys.stderr)
        sys.exit(2)
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4490 (no register item) -- what a hosted run that ended `cancelled` graded,
read from its JOBS rather than from the word.

The item this answers, open-debt item 944, lives in the agent-memory half of the
register, which has no store id for `gate_provenance_lint.py` to resolve; this
sentence and `no register item` in the citation are the honest pair.

## Why the run-level word is not enough

`ci.yml` groups runs by ref and never cancels one in flight, so a push that
lands while a run WAITS replaces the waiting one, and that run ends `cancelled`
having executed no job. `previous-run-gate.sh` and
`newest_completed_ancestor_run.py` were built on that one shape and stepped over
every `cancelled` run as "replaced". Two other shapes end in the same word:

  * a job that STARTED and ran into its `timeout-minutes` is cancelled by the
    runner, and the run ends `cancelled`. Run 42929004554 (attempt 1): the
    isolated-crate lanes started 00:47:20, ran to 01:17:48 and the runner wrote
    "The job has exceeded the maximum execution time of 30m0s". That is a red;
  * a run in which some jobs FAILED and others timed out also ends `cancelled`.
    Run 43058242762: two jobs `failure` and three jobs past their limits, and
    the gates stepped over it as a replacement.

## What decides, per job

  REPLACED     the job never started: no runner was assigned and no step ran.
               A queued job carries a `started_at` all the same (it is the
               queue time; `hosted_pending_kind.py` measured that), so the
               timestamp is NOT the start signal.
  TIMED_OUT    the job started, the runner states the limit it enforced
               ("exceeded the maximum execution time of <d>") and the job's own
               duration, `completed_at - started_at`, reached that limit. The
               limit is read from the runner's statement and not re-derived from
               the workflow: the runner states the value it enforced after
               expressions, matrix expansion and the 360-minute default, which a
               second reading of the YAML would have to reproduce.
  INCONSISTENT the runner states a limit but the duration falls short of it.
               Not a pass and not a clean timeout: a reader looks.
  INTERRUPTED  the job started and was cancelled with no limit stated: a person
               cancelled it, or a sibling's failure did.
  FAILED       the job ended `failure`, `timed_out` or `startup_failure`.
  PASSED       `success`, `skipped` or `neutral`.

A conclusion this file does not know is refused, never bucketed.

## What decides, per run (only runs whose word is `cancelled`)

  RED       a FAILED or TIMED_OUT job; resolved conclusion `failure` or
            `timed_out`, which both readers already grade red.
  AMBER     an INTERRUPTED or INCONSISTENT job, or a run that started some jobs
            and left others unstarted; resolved conclusion
            `cancelled_after_start`, a word both readers grade amber.
  REPLACED  no job started at all (including a run that materialised no job,
            the shape of every replaced run measured on 2026-11-14); the
            conclusion stays `cancelled` and is stepped over as before.
  UNREAD    the jobs could not be fetched; resolved conclusion
            `cancelled_unread`, which the gate announces as a reading that did
            not happen. It is never read as a replacement.

Modes (one required, no default):
    --resolve-runs   stdin: a `gh run list --json ...` array; stdout: the same
                     array with each cancelled run's conclusion resolved
    --run <id>       fetch and classify one run: `KIND<TAB>detail`
    --check          stdin: `{"jobs": [...], "annotations": {"<job id>": [...]}}`
    --selftest       the fixtures below, three of them real runs
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime

PASSED = "PASSED"
FAILED = "FAILED"
REPLACED = "REPLACED"
TIMED_OUT = "TIMED_OUT"
INCONSISTENT = "INCONSISTENT"
INTERRUPTED = "INTERRUPTED"

RED = "RED"
AMBER = "AMBER"
UNREAD = "UNREAD"

# The run-level conclusion each verdict is rewritten to. `failure` and
# `timed_out` are in both readers' RED sets; `cancelled_after_start` and
# `cancelled_unread` are words neither knows, so `newest_completed_ancestor_run`
# grades the first amber, and both readers name the second explicitly.
RESOLVED = {
    REPLACED: "cancelled",
    UNREAD: "cancelled_unread",
}
AFTER_START = "cancelled_after_start"

JOB_PASS = frozenset({"success", "skipped", "neutral"})
JOB_FAIL = frozenset({"failure", "timed_out", "startup_failure"})

LIMIT = re.compile(
    r"exceeded the maximum execution time of\s+"
    r"(?:(?P<h>\d+)h)?(?:(?P<m>\d+)m)?(?:(?P<s>\d+(?:\.\d+)?)s)?"
)

# GitHub stamps jobs to the second, so a job cut at exactly its limit can read
# one second short of it.
RESOLUTION_S = 1.0


class ReadError(RuntimeError):
    """The jobs of a run could not be read. Never a replacement."""


def _ts(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def stated_limit_s(annotations: list[dict]) -> float | None:
    """The limit the runner says it enforced, in seconds, or None."""
    for a in annotations or []:
        m = LIMIT.search(str(a.get("message") or ""))
        if not m or not any(m.group(k) for k in ("h", "m", "s")):
            continue
        return (
            int(m.group("h") or 0) * 3600
            + int(m.group("m") or 0) * 60
            + float(m.group("s") or 0)
        )
    return None


def job_started(job: dict) -> bool:
    if str(job.get("runner_name") or "").strip():
        return True
    return any(
        isinstance(s, dict) and s.get("conclusion") not in (None, "skipped")
        for s in job.get("steps") or []
    )


def classify_job(job: dict, annotations: list[dict]) -> tuple[str, str]:
    """`(kind, detail)` for one job of a finished run. Raises ValueError."""
    if not isinstance(job, dict):
        raise ValueError("a job entry is not an object")
    name = job.get("name") or "?"
    if job.get("status") != "completed":
        raise ValueError(
            f"job {name!r} is {job.get('status')!r}: only a finished run is classified"
        )
    c = job.get("conclusion")
    if c in JOB_PASS:
        return PASSED, f"{name}: {c}"
    if c in JOB_FAIL:
        return FAILED, f"{name}: {c}"
    if c != "cancelled":
        raise ValueError(
            f"job {name!r} concluded {c!r}, which this file does not know; "
            "unclassified is not a pass"
        )
    if not job_started(job):
        return REPLACED, f"{name}: cancelled before it started"
    start, end = _ts(job.get("started_at")), _ts(job.get("completed_at"))
    if start is None or end is None:
        raise ValueError(f"job {name!r} started but carries no start or end time")
    ran = (end - start).total_seconds()
    limit = stated_limit_s(annotations)
    if limit is None:
        return INTERRUPTED, f"{name}: cancelled after {ran:.0f}s with no time limit stated"
    if ran + RESOLUTION_S >= limit:
        return TIMED_OUT, f"{name}: ran {ran:.0f}s against its {limit:.0f}s limit"
    return (
        INCONSISTENT,
        f"{name}: the runner states a {limit:.0f}s limit but the job ran {ran:.0f}s",
    )


def classify_run(payload: dict) -> tuple[str, str, str]:
    """`(verdict, detail, resolved conclusion)` for a run that ended `cancelled`."""
    if not isinstance(payload, dict) or not isinstance(payload.get("jobs"), list):
        raise ValueError(
            "the payload carries no `jobs` list; a payload that was never read is "
            "not a run without jobs"
        )
    notes = payload.get("annotations") or {}
    kinds: dict[str, list[str]] = {}
    for job in payload["jobs"]:
        jid = str(job.get("id")) if isinstance(job, dict) else ""
        kind, detail = classify_job(job, notes.get(jid) or [])
        kinds.setdefault(kind, []).append(detail)
    if kinds.get(FAILED):
        return RED, "; ".join(kinds[FAILED] + kinds.get(TIMED_OUT, [])), "failure"
    if kinds.get(TIMED_OUT):
        return RED, "; ".join(kinds[TIMED_OUT]), "timed_out"
    if kinds.get(INTERRUPTED) or kinds.get(INCONSISTENT):
        return (
            AMBER,
            "; ".join(kinds.get(INTERRUPTED, []) + kinds.get(INCONSISTENT, [])),
            AFTER_START,
        )
    if not kinds.get(PASSED):
        n = len(kinds.get(REPLACED, []))
        return REPLACED, f"no job started ({n} job(s) materialised)", RESOLVED[REPLACED]
    return (
        AMBER,
        f"{len(kinds[PASSED])} job(s) finished and {len(kinds.get(REPLACED, []))} "
        "never started: the run was stopped part way and graded only part of the commit",
        AFTER_START,
    )


def _gh_json(path: str) -> object:
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if r.returncode != 0:
        raise ReadError(f"gh api {path}: {r.stderr.strip()[:200] or 'failed'}")
    try:
        return json.loads(r.stdout)
    except ValueError as exc:
        raise ReadError(f"gh api {path}: not JSON ({exc})") from exc


def fetch(run_id: str) -> dict:
    """The run's jobs (latest attempt) and the annotations of its started cancelled jobs."""
    jobs: list[dict] = []
    page = 1
    while True:
        doc = _gh_json(
            f"repos/{{owner}}/{{repo}}/actions/runs/{run_id}/jobs?per_page=100&page={page}"
        )
        if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), list):
            raise ReadError(f"run {run_id}: the jobs answer has no `jobs` list")
        jobs.extend(doc["jobs"])
        total = doc.get("total_count")
        if not isinstance(total, int):
            raise ReadError(f"run {run_id}: the jobs answer has no `total_count`")
        if len(jobs) >= total or not doc["jobs"]:
            break
        page += 1
    if len(jobs) < total:
        raise ReadError(f"run {run_id}: read {len(jobs)} of {total} job(s)")
    notes: dict[str, list] = {}
    for job in jobs:
        if job.get("conclusion") == "cancelled" and job_started(job):
            got = _gh_json(f"repos/{{owner}}/{{repo}}/check-runs/{job['id']}/annotations")
            notes[str(job["id"])] = got if isinstance(got, list) else []
    return {"jobs": jobs, "annotations": notes}


def resolve_run(run: dict, reader=fetch) -> dict:
    """A copy of `run` whose `cancelled` conclusion says what the jobs graded."""
    out = dict(run)
    if run.get("status") != "completed" or run.get("conclusion") != "cancelled":
        return out
    try:
        verdict, detail, word = classify_run(reader(str(run.get("databaseId"))))
    except (ReadError, ValueError) as exc:
        verdict, detail, word = UNREAD, str(exc), RESOLVED[UNREAD]
    out["conclusion"] = word
    out["cancelledKind"] = verdict
    out["cancelledDetail"] = detail
    return out


# -- selftest -----------------------------------------------------------------


def _job(jid, name, conclusion, started, completed, runner=True, steps=True):
    return {
        "id": jid,
        "name": name,
        "status": "completed",
        "conclusion": conclusion,
        "started_at": started,
        "completed_at": completed,
        "runner_name": f"GitHub Actions {jid % 100000}" if runner else None,
        "steps": (
            [{"name": "Set up job", "status": "completed", "conclusion": "success"}]
            if steps
            else []
        ),
    }


def _limit_note(minutes: int) -> list[dict]:
    return [
        {
            "annotation_level": "failure",
            "message": f"The job has exceeded the maximum execution time of {minutes}m0s",
        },
        {"annotation_level": "failure", "message": "The operation was canceled."},
    ]


def _fixtures() -> dict[str, tuple[dict, str, str]]:
    """name -> (payload, verdict, resolved conclusion).

    The first three are REAL runs read with `gh api` on 2026-11-14, cut to the
    jobs that decide them plus one passing control.
    """
    # Run 42929004554, attempt 1 (c0455d6f22): the isolated-crate lanes ran into
    # their 30-minute limit; every other job of the 52 passed.
    timeout_run = {
        "jobs": [
            _job(130222699651, "validate (Layers A + C0)", "success",
                 "2026-11-11T00:19:51Z", "2026-11-11T00:39:26Z"),
            _job(130222700113,
                 "isolated-crate lanes (what --workspace unification cannot express)",
                 "cancelled", "2026-11-11T00:47:20Z", "2026-11-11T01:17:48Z"),
        ],
        "annotations": {"130222700113": _limit_note(30)},
    }
    # Run 43058242762 (c2350691b4): two jobs failed and three ran into their
    # limits (30, 20 and 30 minutes); the run ended `cancelled`.
    mixed_run = {
        "jobs": [
            _job(130653395879, "validate (Layers A + C0)", "success",
                 "2026-11-11T16:39:25Z", "2026-11-11T17:04:08Z"),
            _job(130653395627, "validate + verify + test", "cancelled",
                 "2026-11-11T16:25:52Z", "2026-11-11T16:56:04Z"),
            _job(130653395884, "gate provenance (Layer C0)", "failure",
                 "2026-11-11T16:25:52Z", "2026-11-11T16:55:01Z"),
            _job(130653395894,
                 "session-core feature planes (Layers C1c, C1d, C1e, C1f, C1g, C1own, C1h)",
                 "failure", "2026-11-11T16:32:24Z", "2026-11-11T16:51:45Z"),
            _job(130653396071, "capability cost of the C ABI builds (Layer C1cs)",
                 "cancelled", "2026-11-11T16:25:52Z", "2026-11-11T16:46:09Z"),
            _job(130653396386, "analyzer-crate docs (Layer C1bz)", "cancelled",
                 "2026-11-11T16:54:08Z", "2026-11-11T17:24:23Z"),
        ],
        "annotations": {
            "130653395627": _limit_note(30),
            "130653396071": _limit_note(20),
            "130653396386": _limit_note(30),
        },
    }
    # Run 43546308708 (38cba277af): replaced while it waited. GitHub answers
    # `total_count: 0` for it, as for every one of the 39 replaced CI runs
    # among the 40 newest cancelled ones on 2026-11-14.
    replaced_run = {"jobs": [], "annotations": {}}

    # Constructed: a queued job cancelled before a runner took it. Its
    # `started_at` is set (the queue time), which is exactly the field that must
    # not be read as a start.
    unstarted_job = {
        "jobs": [
            _job(1, "queued then replaced", "cancelled",
                 "2026-11-14T00:00:00Z", "2026-11-14T00:00:05Z",
                 runner=False, steps=False)
        ]
    }
    interrupted = {
        "jobs": [
            _job(2, "cancelled by hand", "cancelled",
                 "2026-11-14T00:00:00Z", "2026-11-14T00:05:00Z")
        ],
        "annotations": {"2": [{"message": "The operation was canceled."}]},
    }
    inconsistent = {
        "jobs": [
            _job(3, "limit stated, duration short", "cancelled",
                 "2026-11-14T00:00:00Z", "2026-11-14T00:10:00Z")
        ],
        "annotations": {"3": _limit_note(30)},
    }
    partial = {
        "jobs": [
            _job(4, "finished", "success", "2026-11-14T00:00:00Z", "2026-11-14T00:05:00Z"),
            _job(5, "never ran", "cancelled", "2026-11-14T00:00:00Z",
                 "2026-11-14T00:05:00Z", runner=False, steps=False),
        ]
    }
    one_second_short = {
        "jobs": [
            _job(6, "cut at the limit, stamped a second early", "cancelled",
                 "2026-11-14T00:00:01Z", "2026-11-14T00:30:00Z")
        ],
        "annotations": {"6": _limit_note(30)},
    }
    return {
        "real 42929004554 attempt 1: one job past its limit": (timeout_run, RED, "timed_out"),
        "real 43058242762: failures and timeouts under `cancelled`": (mixed_run, RED, "failure"),
        "real 43546308708: replaced, no job materialised": (replaced_run, REPLACED, "cancelled"),
        "a queued job with a started_at is not a start": (unstarted_job, REPLACED, "cancelled"),
        "a started job cancelled with no limit stated": (interrupted, AMBER, AFTER_START),
        "a limit stated but not reached": (inconsistent, AMBER, AFTER_START),
        "a run stopped part way": (partial, AMBER, AFTER_START),
        "a cut stamped one second short of the limit": (one_second_short, RED, "timed_out"),
    }


def _refused() -> dict[str, dict]:
    return {
        "no jobs key": {"annotations": {}},
        "unknown job conclusion": {
            "jobs": [_job(7, "x", "stale", "2026-11-14T00:00:00Z", "2026-11-14T00:01:00Z")]
        },
        "a job still running": {
            "jobs": [dict(_job(8, "x", None, "2026-11-14T00:00:00Z", None), status="in_progress")]
        },
        "started with no end time": {
            "jobs": [_job(9, "x", "cancelled", "2026-11-14T00:00:00Z", None)]
        },
    }


def selftest() -> int:
    bad = 0
    seen = set()
    for name, (payload, verdict, word) in _fixtures().items():
        try:
            got = classify_run(payload)
        except ValueError as exc:
            print(f"  BAD  {name}: refused ({exc})")
            bad += 1
            continue
        seen.add(got[0])
        ok = got[0] == verdict and got[2] == word
        print(f"  {'ok ' if ok else 'BAD'}  {name}: {got[0]} / {got[2]}")
        if not ok:
            print(f"        want {verdict} / {word}; detail: {got[1]}")
        bad += not ok
    for name, payload in _refused().items():
        try:
            got = classify_run(payload)
        except ValueError:
            print(f"  ok   refused: {name}")
            continue
        print(f"  BAD  {name}: classified {got[0]} instead of being refused")
        bad += 1
    if seen != {RED, AMBER, REPLACED}:
        print(f"  BAD  the fixtures reached only {sorted(seen)}")
        bad += 1

    # The resolution the two readers consume: a replaced run keeps its word, a
    # timed-out one becomes a red word, and a failed read is never a replacement.
    fx = _fixtures()
    runs = [
        {"databaseId": 1, "status": "completed", "conclusion": "cancelled"},
        {"databaseId": 2, "status": "completed", "conclusion": "cancelled"},
        {"databaseId": 3, "status": "completed", "conclusion": "cancelled"},
        {"databaseId": 4, "status": "completed", "conclusion": "success"},
    ]
    payloads = {
        "1": fx["real 43546308708: replaced, no job materialised"][0],
        "2": fx["real 42929004554 attempt 1: one job past its limit"][0],
    }

    def reader(rid: str) -> dict:
        if rid not in payloads:
            raise ReadError(f"run {rid}: no answer")
        return payloads[rid]

    words = [resolve_run(r, reader)["conclusion"] for r in runs]
    want = ["cancelled", "timed_out", "cancelled_unread", "success"]
    ok = words == want
    print(f"  {'ok ' if ok else 'BAD'}  resolution of a run list: {words}")
    bad += not ok
    total = len(_fixtures()) + len(_refused()) + 2
    print(f"hosted-cancelled-kind selftest: {total - bad}/{total} arm(s) behaved as claimed")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--check"]:
        try:
            verdict, detail, word = classify_run(json.load(sys.stdin))
        except ValueError as exc:
            print(f"UNCLASSIFIED\t{exc}")
            return 1
        print(f"{verdict}\t{word}\t{detail}")
        return 0
    if len(argv) == 2 and argv[0] == "--run":
        try:
            verdict, detail, word = classify_run(fetch(argv[1]))
        except (ReadError, ValueError) as exc:
            print(f"{UNREAD}\t{RESOLVED[UNREAD]}\t{exc}")
            return 1
        print(f"{verdict}\t{word}\t{detail}")
        return 0
    if argv == ["--resolve-runs"]:
        try:
            runs = json.load(sys.stdin)
        except ValueError as exc:
            print(f"hosted-cancelled-kind: stdin is not JSON: {exc}", file=sys.stderr)
            return 1
        if not isinstance(runs, list):
            print("hosted-cancelled-kind: stdin is not a run list", file=sys.stderr)
            return 1
        json.dump([resolve_run(r) if isinstance(r, dict) else r for r in runs], sys.stdout)
        return 0
    print(
        "usage: hosted_cancelled_kind.py --resolve-runs < runs.json | --run <id> "
        "| --check < payload.json | --selftest",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

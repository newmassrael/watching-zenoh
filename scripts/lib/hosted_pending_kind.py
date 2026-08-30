#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2198 (no register item) — WHAT A RUN THAT SAYS `queued` IS ACTUALLY DOING,
DERIVED FROM ITS JOBS RATHER THAN FROM THE WORD.

## Why the citation says no item while the file answers for one

The debt this answers, 545, lives in the register half that is NOT the store,
so there is no `debt-` id to cite and the provenance convention's explicit
escape hatch is the honest form. Its siblings `prose_dep_graph_gate.py` and
`prose_build_closure_gate.py` stand in the same place for the same reason.

## The item, and which third of it this is

Item 545 was filed over two hosted reds nobody attributed while the hosted
queue stood for 23 hours. R2177 re-measured and REFUTED both premises: the two
reds were already green, and the queue was not standing (29 completed of the
last 30 runs). What survived is the thing nobody looked at when the item was
opened, and R2177 named it exactly:

    run-level `status` covers TWO states with ONE word. The same instant that
    `gh run view <id> --json status` answered `queued`, `--json jobs` answered
    completed 1 / in_progress 4 / queued 15.

So what is missing is not a gate but a DISCRIMINATOR: the predicate separating
"queued, and not one job has started" from "queued, and the jobs are running".
This is that predicate.

## MEASURED THIS ROUND, and it is why the word is not merely imprecise

Run `33293532416` (`d7b0d55f`), read at 2026-08-30T05:0xZ:

    gh run view … --json status   ->  "queued"
    gh run view … --json jobs     ->  completed 7, in_progress 12, queued 1

Seven of that run's twenty jobs had already FINISHED while the run called
itself `queued`. `previous-run-gate.sh` renders that word into "still running",
which is true here by luck; it renders a run with zero jobs started into the
same sentence, and that one is the state item 545 was opened over. One word,
two states, and the sentence a reader gets does not distinguish them.

## The population is the JOB LIST, and run-level status is NOT an input

That constraint is the item's, and it is enforced structurally: `classify`
reads `jobs` and nothing else. A payload carrying a top-level `status` is
classified identically with it and without it, and the fixture below contains
one whose top-level word DISAGREES with its jobs, so an implementation that
reached for the word fails the selftest instead of passing quietly.

## ⚠ `startedAt` IS NOT A START SIGNAL — measured, and it looks like one

A job whose status is `queued` still carries a populated `startedAt`: in the
run above, the one queued job's `startedAt` was `2026-08-30T04:54:5xZ`, the
run's own queue time, not a start. Reading "startedAt is set" as "this job
started" would classify every unstarted run as moving, which is the defect
this file exists to remove, arrived at from the other side. Only `status`
answers it.

## Unclassified is RED, and an absent job list is not an empty one

Three kinds are answers: MOVING (a job has finished or is running), UNSTARTED
(jobs exist, every one of them queued), NOJOBS (the run exists and has
materialised no job yet). Anything else -- a status word this file does not
know, a payload with no `jobs` key at all -- exits non-zero and says so. A
missing key is emphatically not an empty list: treating it as one would report
NOJOBS for a payload that was never read, which is this workspace's most
repeated defect shape rebuilt inside the discriminator meant to retire it.

## What this deliberately does NOT decide

WHETHER AN UNSTARTED RUN IS STALLED. That needs a threshold on how long a run
normally waits before its first job starts, and nobody has measured that
distribution -- the register's own instruction is to probe before prescribing.
So this names the state and reports the run's age when the caller supplies it,
and asserts nothing about when waiting becomes stalling. When the queue next
stands, that measurement is the next round's, and this file is where it lands.

Its live subjects, stated rather than implied: MOVING has two real ones today;
UNSTARTED and NOJOBS have none right now and are exercised by the fixture,
which is what keeps them from being dead code rather than a count that cannot
fail.
"""

from __future__ import annotations

import json
import sys

# The job status words GitHub emits, split by what each says about STARTING.
# A word outside both sets is refused by name rather than bucketed by guess.
STARTED = frozenset({"completed", "in_progress"})
NOT_STARTED = frozenset({"queued", "waiting", "requested", "pending"})

MOVING = "MOVING"
UNSTARTED = "UNSTARTED"
NOJOBS = "NOJOBS"


def classify(payload: dict) -> tuple[str, str]:
    """(kind, one-line detail) from the JOB LIST alone.

    Raises ValueError for anything it cannot adjudicate -- an absent `jobs`
    key, a job with no status, or a status word it does not know. The caller
    turns that into a non-zero exit; it must never become a bucket.
    """
    if not isinstance(payload, dict) or "jobs" not in payload:
        raise ValueError(
            "the payload carries no `jobs` key. That is not an empty job "
            "list: a payload that was never read must not be classified as a "
            "run with no jobs. Pass `gh run view <id> --json jobs`."
        )
    jobs = payload["jobs"]
    if not isinstance(jobs, list):
        raise ValueError("`jobs` is not a list")

    if not jobs:
        return (
            NOJOBS,
            "the run exists and has materialised no job yet -- nothing is "
            "queued because nothing has been created",
        )

    counts: dict[str, int] = {}
    for job in jobs:
        status = job.get("status") if isinstance(job, dict) else None
        if not status:
            raise ValueError("a job in this payload carries no `status`")
        if status not in STARTED and status not in NOT_STARTED:
            raise ValueError(
                "a job reports status %r, which this file does not know. "
                "Unclassified is not a pass: add the word to STARTED or to "
                "NOT_STARTED, having decided which it means." % (status,)
            )
        counts[status] = counts.get(status, 0) + 1

    tally = ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
    started = sum(n for s, n in counts.items() if s in STARTED)
    if started:
        return (
            MOVING,
            f"{started} of {len(jobs)} job(s) have started or finished "
            f"({tally}) -- the run is progressing whatever the run-level word "
            f"says",
        )
    return (
        UNSTARTED,
        f"none of {len(jobs)} job(s) has started ({tally}) -- the run-level "
        f"word and this state are the pair item 545 was opened over",
    )


def _fixture() -> dict[str, tuple[dict, str]]:
    """name -> (payload, expected kind). The first two are REAL, read today.

    Shape note: every `queued` job below keeps a populated `startedAt`, because
    that is what GitHub actually sends and it is the field an implementation is
    most likely to mistake for a start signal.
    """

    def job(status: str, name: str, started: str = "2026-08-30T05:00:00Z") -> dict:
        return {
            "name": name,
            "status": status,
            "conclusion": "success" if status == "completed" else "",
            "startedAt": started,
        }

    # Run 33293532416 (d7b0d55f), 2026-08-30T05:0xZ. Its run-level word was
    # `queued` while seven jobs had already finished -- so the top-level
    # `status` here DISAGREES with the jobs on purpose. An implementation that
    # reads the word cannot get MOVING out of this.
    real_moving = {
        "status": "queued",
        "jobs": [job("completed", f"done-{i}") for i in range(7)]
        + [job("in_progress", f"run-{i}") for i in range(12)]
        + [job("queued", "wait-0")],
    }
    # Run 33293914556 (e152e59e), read in the same breath: barely begun, and
    # the run-level word is the SAME `queued`. Two very different runs, one
    # word -- which is the whole of item 545's surviving third.
    real_early = {
        "status": "queued",
        "jobs": [job("queued", f"wait-{i}") for i in range(18)]
        + [job("in_progress", f"run-{i}") for i in range(2)],
    }
    return {
        "real-moving": (real_moving, MOVING),
        "real-early": (real_early, MOVING),
        "unstarted": ({"status": "queued", "jobs": [job("queued", "w")] * 20}, UNSTARTED),
        "waiting-word": ({"jobs": [job("waiting", "w")]}, UNSTARTED),
        "nojobs": ({"status": "queued", "jobs": []}, NOJOBS),
        "one-done": ({"jobs": [job("completed", "d"), job("queued", "w")]}, MOVING),
    }


def _refused() -> dict[str, dict]:
    """Payloads that must RAISE. Unclassified is not a pass."""
    return {
        "no-jobs-key": {"status": "queued"},
        "jobs-not-a-list": {"jobs": "queued"},
        "unknown-status": {"jobs": [{"name": "x", "status": "sleeping"}]},
        "status-missing": {"jobs": [{"name": "x"}]},
    }


def selftest() -> int:
    for name, (payload, expected) in _fixture().items():
        try:
            kind, _ = classify(payload)
        except ValueError as exc:
            print(
                f"hosted-pending-kind: SELFTEST FAIL -- fixture {name!r} must "
                f"classify as {expected} and was refused: {exc}"
            )
            return 1
        if kind != expected:
            print(
                f"hosted-pending-kind: SELFTEST FAIL -- fixture {name!r} is "
                f"{expected} and the classifier said {kind}. The two REAL "
                f"payloads both carry a top-level `status` of 'queued' that "
                f"disagrees with their jobs; reading that word instead of the "
                f"job list lands here."
            )
            return 1
    for name, payload in _refused().items():
        try:
            kind, _ = classify(payload)
        except ValueError:
            continue
        print(
            f"hosted-pending-kind: SELFTEST FAIL -- payload {name!r} must be "
            f"REFUSED and was classified {kind}. An absent job list is not an "
            f"empty one and an unknown status word is not a queued job; "
            f"unclassified is RED, not a bucket."
        )
        return 1
    print(
        "hosted-pending-kind: selftest OK -- separates a run whose jobs are "
        "moving from one where none has started and one with no job at all, "
        "on two REAL payloads whose run-level word disagrees with their jobs; "
        "refuses an absent job list, a non-list, an unknown status word and a "
        "job with no status"
    )
    return 0


def check() -> int:
    """Classify a `gh run view <id> --json jobs` payload read from stdin."""
    try:
        payload = json.load(sys.stdin)
    except ValueError as exc:
        print(f"UNREADABLE\tstdin is not JSON: {exc}")
        return 1
    try:
        kind, detail = classify(payload)
    except ValueError as exc:
        print(f"UNCLASSIFIED\t{exc}")
        return 1
    print(f"{kind}\t{detail}")
    return 0


def main(argv: list[str]) -> int:
    """A required mode with no default -- R2104b paid for a script that decided
    its mode by what was NOT in `sys.argv`."""
    if argv == ["--check"]:
        return check()
    if argv == ["--selftest"]:
        return selftest()
    print("usage: hosted_pending_kind.py --check < jobs.json | --selftest")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2639 (N70) — a red must not be able to hide behind a queue.

## The measurement

`previous-run-gate.sh` (pre-push gate 2c) grades the hosted run of the commit
being replaced. When that run has not finished it prints PENDING and passes,
deliberately: the standing rule is push-and-continue, and the next push grades
it. That trade holds while the queue is one or two pushes deep.

On 2026-09-15 it was eleven. Verdicts were arriving about eight hours after the
push that created them, so EVERY push found its predecessor pending, and the gate
passed every time while the last three runs that had actually finished were all
RED -- two of them on the same defect, unrecorded for eleven rounds. "No red"
had come to mean "nothing was measured", which is the defect class this
repository names most often, rebuilt inside the gate that exists to catch it.

## What this module decides

Given the runs gh reports and the set of commits that are ancestors of the one
being graded, it names the NEWEST COMPLETED run on that history, and classifies
it. The gate then refuses on a red one exactly as it refuses on a red immediate
predecessor -- same acknowledgement, same per-run id.

It does NOT wait, and it does not grade pending runs: a run still going is
skipped, not blamed. What changes is only this: when nothing recent has
finished, the gate looks FURTHER BACK for something that did, instead of
reporting that it found no red.

## A cancelled run is stepped over, not graded

ci.yml groups by ref and never cancels a run in flight, but a group keeps only
one WAITING run, so a push replaces the waiting one and that run ends
`cancelled` having executed no job. Under that policy a cancelled run is the
ordinary result of a burst of pushes, and it graded nothing, so it is skipped
exactly as a pending one is. It is never counted as green. If nothing on the
history graded anything the answer is NONE, which the gate announces as "measured
nothing" rather than as a pass. Earlier this module reported a cancelled run as
AMBER, which was right while a cancellation could only be an anomaly.

## Unless its jobs say it graded something (open-debt item 944)

"Cancelled" is also the word for a run whose job STARTED and ran into its
`timeout-minutes`, and for a run in which jobs failed and others then timed out
(run 43058242762). With `--resolve-cancelled` each cancelled candidate is read
through `hosted_cancelled_kind.py`, newest first and only until a graded run is
found: a run whose jobs never started is still stepped over, a timed-out or
failed one is graded red, a run stopped part way amber, and a run whose jobs
could not be read is answered `UNREAD` rather than stepped over.

## Why the ancestor set is required

A run's `headSha` may belong to another branch or to a commit this history never
contained. Grading such a run would blame the pushing branch for someone else's
red, so a run is considered only when its head commit is an ancestor of (or is)
the commit under grade. An empty ancestor set therefore yields NONE, never a
pass: a population of zero is not a green.

Output (one TSV line):
    GREEN   <run id>  <head sha>
    RED     <workflow>  <run id>  <conclusion>  <head sha>
    AMBER   <workflow>  <run id>  <conclusion>  <head sha>
    NONE    <number of runs considered>
    UNREAD  <run id>  <why its jobs could not be read>

With `--backlog`, a second line (see `backlog`; absent when the payload could
not be read):
    BACKLOG <pushes>  <runs>  since-graded | whole-window
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hosted_cancelled_kind  # noqa: E402

GREEN = {"success"}
RED = {"failure", "timed_out", "startup_failure"}


def classify(conclusion):
    if conclusion in GREEN:
        return "GREEN"
    return "RED" if conclusion in RED else "AMBER"


def newest_completed(runs, ancestors, resolve=None):
    """The newest completed run whose head commit is in `ancestors`.

    `runs` is what `gh run list --json` gives. Order is not trusted: gh returns
    newest first today, and a verdict that depends on that would be a verdict
    resting on an undocumented ordering, so `createdAt` decides when it is
    present and input order only breaks ties.

    A cancelled run is skipped, like a pending one: it executed nothing, so it
    is the newest run that GRADED something this function is asked for. With
    `resolve` (a run -> run function) a cancelled run is first read by its jobs,
    newest first, and skipped only when they say it was replaced.
    """
    considered = []
    for i, r in enumerate(runs):
        if not isinstance(r, dict):
            continue
        if r.get("status") != "completed":
            continue
        if r.get("conclusion") == "cancelled" and resolve is None:
            continue
        head = r.get("headSha") or ""
        if head not in ancestors:
            continue
        considered.append((r.get("createdAt") or "", -i, r))
    considered.sort(key=lambda t: (t[0], t[1]), reverse=True)
    for _, _, r in considered:
        if r.get("conclusion") == "cancelled":
            r = resolve(r)
            if r.get("conclusion") == "cancelled":
                continue
        return r
    return None


def backlog(runs, ancestors, graded):
    """`(pushes, runs, scope)` on this history NEWER than `graded`.

    Open-debt item 670. Gate 2c passes a pending predecessor because the next
    push grades it, which assumes runs finish; when they do not, the number of
    pushes no verdict has reached grows and nothing said how long it was. This
    counts it: every run on the history newer than the one that graded
    something is pending or was stepped over, so each is a push without a
    verdict. `pushes` counts distinct head commits, `runs` every workflow run.

    The order is `newest_completed`'s (`createdAt`, then input order). `scope`
    is `since-graded`, or `whole-window` when nothing in `runs` graded anything,
    in which case the count is a LOWER bound: the backlog reaches past the runs
    gh was asked for. Whether a length should refuse a push is the owner's
    decision; this only measures it.
    """
    keyed = []
    for i, r in enumerate(runs):
        if isinstance(r, dict) and (r.get("headSha") or "") in ancestors:
            keyed.append(((r.get("createdAt") or "", -i), r))
    floor = None
    if graded is not None:
        for key, r in keyed:
            if r.get("databaseId") == graded.get("databaseId"):
                floor = key
                break
    newer = [r for key, r in keyed if floor is None or key > floor]
    if graded is not None and floor is None:
        # The graded run is not among those read; nothing can be ordered
        # against it, so nothing is counted rather than everything.
        newer = []
    heads = {r.get("headSha") for r in newer}
    scope = "since-graded" if graded is not None else "whole-window"
    return len(heads), len(newer), scope


def backlog_line(runs, ancestors, graded):
    pushes, count, scope = backlog(runs, ancestors, graded)
    return "BACKLOG\t%d\t%d\t%s" % (pushes, count, scope)


def verdict_line(runs, ancestors, resolve=None):
    return format_verdict(newest_completed(runs, ancestors, resolve), runs)


def format_verdict(r, runs):
    if r is None:
        return "NONE\t%d" % len(runs)
    if r.get("conclusion") == "cancelled_unread":
        return "UNREAD\t%s\t%s" % (r.get("databaseId"), r.get("cancelledDetail") or "")
    kind = classify(r.get("conclusion"))
    rid = str(r.get("databaseId"))
    head = (r.get("headSha") or "")[:12]
    if kind == "GREEN":
        return "GREEN\t%s\t%s" % (rid, head)
    return "%s\t%s\t%s\t%s\t%s" % (
        kind, r.get("workflowName") or "?", rid, r.get("conclusion"), head)


def selftest() -> int:
    ok = True
    A, B, C = "a" * 40, "b" * 40, "c" * 40
    anc = {A, B, C}

    def case(label, runs, ancestors, want_prefix, resolve=None):
        nonlocal ok
        got = verdict_line(runs, ancestors, resolve)
        if not got.startswith(want_prefix):
            ok = False
            print("selftest FAIL: %s: want %s, got %s" % (label, want_prefix, got),
                  file=sys.stderr)
        return got.split("\t")[0]

    def run(rid, status, conclusion, head, created, wf="CI"):
        return {"databaseId": rid, "status": status, "conclusion": conclusion,
                "headSha": head, "createdAt": created, "workflowName": wf}

    seen = set()
    # The shape that asked for this module: the newest runs are pending and the
    # newest FINISHED one is red.
    seen.add(case("red behind a queue", [
        run(3, "queued", None, C, "2026-09-15T09:00:00Z"),
        run(2, "in_progress", None, B, "2026-09-15T08:00:00Z"),
        run(1, "completed", "failure", A, "2026-09-15T02:00:00Z"),
    ], anc, "RED\tCI\t1\tfailure"))
    # A red on another branch is not this history's red.
    seen.add(case("foreign red ignored", [
        run(9, "completed", "failure", "d" * 40, "2026-09-15T09:00:00Z"),
        run(1, "completed", "success", A, "2026-09-15T02:00:00Z"),
    ], anc, "GREEN\t1"))
    # Input order must not decide; createdAt must.
    seen.add(case("newest wins regardless of input order", [
        run(1, "completed", "failure", A, "2026-09-15T02:00:00Z"),
        run(5, "completed", "success", B, "2026-09-15T07:00:00Z"),
    ], anc, "GREEN\t5"))
    # A cancelled run executed nothing and is stepped over. The red behind it
    # must still be found: a cancellation is not a place for a red to hide.
    seen.add(case("red behind a cancelled run", [
        run(4, "completed", "cancelled", B, "2026-09-15T07:00:00Z"),
        run(1, "completed", "failure", A, "2026-09-15T02:00:00Z"),
    ], anc, "RED\tCI\t1\tfailure"))
    seen.add(case("green behind a cancelled run", [
        run(4, "completed", "cancelled", B, "2026-09-15T07:00:00Z"),
        run(1, "completed", "success", A, "2026-09-15T02:00:00Z"),
    ], anc, "GREEN\t1"))
    # And a cancellation is never promoted to a pass: with nothing behind it the
    # answer is NONE, which the gate announces as measuring nothing.
    seen.add(case("cancelled alone is not a pass", [
        run(4, "completed", "cancelled", B, "2026-09-15T07:00:00Z"),
    ], anc, "NONE\t1"))
    seen.add(case("a conclusion that is neither green nor red is amber", [
        run(6, "completed", "action_required", B, "2026-09-15T07:00:00Z"),
    ], anc, "AMBER\tCI\t6\taction_required"))
    seen.add(case("nothing finished", [
        run(3, "queued", None, C, "2026-09-15T09:00:00Z"),
    ], anc, "NONE\t1"))
    seen.add(case("empty population is not a pass", [], anc, "NONE\t0"))
    seen.add(case("empty ancestor set is not a pass", [
        run(1, "completed", "success", A, "2026-09-15T02:00:00Z"),
    ], set(), "NONE\t1"))

    # Item 944: the cancelled runs read by their jobs. The payloads are the
    # real ones `hosted_cancelled_kind.py` carries (a replaced run with no job,
    # 42929004554's attempt that ran into its limit); run 7 cannot be read.
    fx = hosted_cancelled_kind._fixtures()
    payloads = {
        "5": fx["real 43546308708: replaced, no job materialised"][0],
        "6": fx["real 42929004554 attempt 1: one job past its limit"][0],
    }

    def reader(rid):
        if rid not in payloads:
            raise hosted_cancelled_kind.ReadError("run %s: no answer" % rid)
        return payloads[rid]

    def resolve(r):
        return hosted_cancelled_kind.resolve_run(r, reader)

    seen.add(case("a timed-out cancelled run is red, not a replacement", [
        run(6, "completed", "cancelled", B, "2026-09-15T07:00:00Z"),
        run(1, "completed", "success", A, "2026-09-15T02:00:00Z"),
    ], anc, "RED\tCI\t6\ttimed_out", resolve))
    seen.add(case("a replaced run is still stepped over when read by its jobs", [
        run(5, "completed", "cancelled", C, "2026-09-15T08:00:00Z"),
        run(1, "completed", "success", A, "2026-09-15T02:00:00Z"),
    ], anc, "GREEN\t1", resolve))
    seen.add(case("a cancelled run whose jobs cannot be read is not stepped over", [
        run(7, "completed", "cancelled", C, "2026-09-15T08:00:00Z"),
        run(1, "completed", "success", A, "2026-09-15T02:00:00Z"),
    ], anc, "UNREAD\t7", resolve))

    # Item 670: the length of the history no verdict has reached. Each arm
    # states the line; the controls are the graded tip (zero) and a foreign
    # run (not counted), so a counter that answered one number fails here.
    def backlog_case(label, runs, ancestors, want, resolve=None):
        nonlocal ok
        graded = newest_completed(runs, ancestors, resolve)
        got = backlog_line(runs, ancestors, graded)
        if got != want:
            ok = False
            print("selftest FAIL: backlog, %s: want %r, got %r" % (label, want, got),
                  file=sys.stderr)

    backlog_case("two pushes queued behind a red", [
        run(3, "queued", None, C, "2026-09-15T09:00:00Z"),
        run(2, "in_progress", None, B, "2026-09-15T08:00:00Z"),
        run(1, "completed", "failure", A, "2026-09-15T02:00:00Z"),
    ], anc, "BACKLOG\t2\t2\tsince-graded")
    backlog_case("two workflows of one push are one push", [
        run(4, "queued", None, C, "2026-09-15T09:00:00Z", wf="Other"),
        run(3, "queued", None, C, "2026-09-15T09:00:00Z"),
        run(1, "completed", "success", A, "2026-09-15T02:00:00Z"),
    ], anc, "BACKLOG\t1\t2\tsince-graded")
    backlog_case("a stepped-over cancellation is a push without a verdict", [
        run(4, "completed", "cancelled", B, "2026-09-15T07:00:00Z"),
        run(1, "completed", "failure", A, "2026-09-15T02:00:00Z"),
    ], anc, "BACKLOG\t1\t1\tsince-graded")
    backlog_case("a run on another history is not this backlog", [
        run(9, "queued", None, "d" * 40, "2026-09-15T09:00:00Z"),
        run(1, "completed", "success", A, "2026-09-15T02:00:00Z"),
    ], anc, "BACKLOG\t0\t0\tsince-graded")
    backlog_case("a graded tip has no backlog", [
        run(5, "completed", "success", B, "2026-09-15T07:00:00Z"),
        run(1, "completed", "failure", A, "2026-09-15T02:00:00Z"),
    ], anc, "BACKLOG\t0\t0\tsince-graded")
    backlog_case("nothing graded: the whole window, a lower bound", [
        run(3, "queued", None, C, "2026-09-15T09:00:00Z"),
        run(2, "queued", None, B, "2026-09-15T08:00:00Z"),
    ], anc, "BACKLOG\t2\t2\twhole-window")

    # Anti-vacuity: a classifier that answered one word for everything would
    # pass a case list that happened to expect only that word.
    if seen != {"GREEN", "RED", "AMBER", "NONE", "UNREAD"}:
        ok = False
        print("selftest FAIL: the cases exercised only %s" % sorted(seen), file=sys.stderr)

    print("newest-completed-ancestor-run selftest:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="newest_completed_ancestor_run.py")
    p.add_argument("--ancestors-file",
                   help="file of candidate commit shas, one per line; a run is "
                        "considered only when its headSha is one of them")
    p.add_argument("--resolve-cancelled", action="store_true",
                   help="read each cancelled candidate by its jobs (gh api) "
                        "before stepping over it")
    p.add_argument("--backlog", action="store_true",
                   help="print a second line, BACKLOG <pushes> <runs> <scope>: "
                        "the runs on this history newer than the graded one")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.ancestors_file:
        p.error("--ancestors-file is required (or --selftest)")
    with open(args.ancestors_file) as fh:
        ancestors = {line.strip() for line in fh if line.strip()}
    try:
        runs = json.load(sys.stdin)
    except ValueError:
        print("NONE\t0")
        return 0
    if not isinstance(runs, list):
        print("NONE\t0")
        return 0
    resolve = hosted_cancelled_kind.resolve_run if args.resolve_cancelled else None
    graded = newest_completed(runs, ancestors, resolve)
    print(format_verdict(graded, runs))
    if args.backlog:
        print(backlog_line(runs, ancestors, graded))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

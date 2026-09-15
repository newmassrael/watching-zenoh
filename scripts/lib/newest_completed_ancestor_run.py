#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
"""
from __future__ import annotations

import argparse
import json
import sys

GREEN = {"success"}
RED = {"failure", "timed_out", "startup_failure"}


def classify(conclusion):
    if conclusion in GREEN:
        return "GREEN"
    return "RED" if conclusion in RED else "AMBER"


def newest_completed(runs, ancestors):
    """The newest completed run whose head commit is in `ancestors`.

    `runs` is what `gh run list --json` gives. Order is not trusted: gh returns
    newest first today, and a verdict that depends on that would be a verdict
    resting on an undocumented ordering, so `createdAt` decides when it is
    present and input order only breaks ties.
    """
    considered = []
    for i, r in enumerate(runs):
        if not isinstance(r, dict):
            continue
        if r.get("status") != "completed":
            continue
        head = r.get("headSha") or ""
        if head not in ancestors:
            continue
        considered.append((r.get("createdAt") or "", -i, r))
    if not considered:
        return None
    considered.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return considered[0][2]


def verdict_line(runs, ancestors):
    r = newest_completed(runs, ancestors)
    if r is None:
        return "NONE\t%d" % len(runs)
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

    def case(label, runs, ancestors, want_prefix):
        nonlocal ok
        got = verdict_line(runs, ancestors)
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
    seen.add(case("cancelled is amber", [
        run(4, "completed", "cancelled", B, "2026-09-15T07:00:00Z"),
    ], anc, "AMBER\tCI\t4\tcancelled"))
    seen.add(case("nothing finished", [
        run(3, "queued", None, C, "2026-09-15T09:00:00Z"),
    ], anc, "NONE\t1"))
    seen.add(case("empty population is not a pass", [], anc, "NONE\t0"))
    seen.add(case("empty ancestor set is not a pass", [
        run(1, "completed", "success", A, "2026-09-15T02:00:00Z"),
    ], set(), "NONE\t1"))

    # Anti-vacuity: a classifier that answered one word for everything would
    # pass a case list that happened to expect only that word.
    if seen != {"GREEN", "RED", "AMBER", "NONE"}:
        ok = False
        print("selftest FAIL: the cases exercised only %s" % sorted(seen), file=sys.stderr)

    print("newest-completed-ancestor-run selftest:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="newest_completed_ancestor_run.py")
    p.add_argument("--ancestors-file",
                   help="file of candidate commit shas, one per line; a run is "
                        "considered only when its headSha is one of them")
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
    print(verdict_line(runs, ancestors))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

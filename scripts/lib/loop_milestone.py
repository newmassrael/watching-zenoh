#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2628 (no register item) — an agent loop's milestone must be judged against a baseline taken when the run STARTED.

## The measurement that asked for this

The atom loop's milestone read "build one atom PARTIAL -> COMPLETE; the oracle
is `audit-catalog-status.sh`'s REMAINING WORK going down by one". That sentence
names no baseline. Round 2626 moved REMAINING 39 -> 38 and its run ended; the
next run was handed the same sentence, measured 38, saw the ledger's 39 -> 38,
and declared the milestone reached WITHOUT BUILDING ANYTHING. An independent
checker, shown the same sentence, agreed -- both were right about the sentence.
Three consecutive runs closed that way, identical to the byte (8 iterations,
11169 bytes each), with HEAD never moving. A drop that happened before a run
began was read as that run's achievement, because nothing said "before".

The written milestone also carried its own absolute target (58 -> 57) while the
tree stood at 38: a number typed into prose rots, and this one was 20 behind.

## What this does

`snapshot` measures the baseline -- HEAD and REMAINING WORK -- at the moment a
launcher starts a run, and prints it. The launcher writes that baseline INTO the
milestone text, so the sentence the agent and its checker read is anchored.

`check` is the milestone predicate. REACHED requires all of:
  * the tracked tree is clean (REMAINING is read off the working tree, and an
    uncommitted edit is not work this loop has landed);
  * HEAD is not the snapshot's commit (a run that committed nothing moved
    nothing, whatever the number says);
  * the snapshot's commit is an ancestor of HEAD (otherwise the two numbers are
    not measurements of one line of history);
  * the audit is EXACT (a lower bound cannot say that one step was taken);
  * REMAINING now <= REMAINING at the snapshot - 1.

`refuse-relaunch` is the launcher's guard. Given the PREVIOUS launch's snapshot,
it refuses when HEAD still equals that snapshot's commit: the previous run moved
nothing, so launching the same work again would repeat it. That is the refusal
which would have stopped the three runs above.

## The numbers come from the oracle, not from here

REMAINING is computed by `audit-catalog-status.sh`, which writes what it
computed to the path named by `WZ_A3_REMAINING_JSON`. This module never re-derives
the tally and never greps the printed line. It also requires the oracle's own
exit status to be 0: the file is written before the invariant verdicts, and a
red audit is not a baseline.

## What this does NOT do

It does not bind the agent-loop driver's verdict to this exit status. The driver
asks an LLM checker to judge the milestone text; the text names this command as
the only oracle, and that is as far as a caller can reach from here. Nor does it
pick the next atom, or detect a stall across runs that each commit something
but close nothing -- a relaunch is refused only when HEAD did not move at all.

Exit status:
  snapshot         0 measured   2 cannot measure
  check            0 REACHED    3 NOT REACHED   2 cannot judge
  refuse-relaunch  0 allowed    1 refused       2 cannot read the previous snapshot
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ORACLE = REPO_ROOT / "scripts" / "audit-catalog-status.sh"

REACHED, NOT_REACHED, CANNOT_JUDGE = "REACHED", "NOT REACHED", "CANNOT JUDGE"
EXIT = {REACHED: 0, NOT_REACHED: 3, CANNOT_JUDGE: 2}

# The override names the exact commit it acknowledges, so an acknowledgement
# cannot outlive the situation it was given for (same shape as WZ_ACK_RED).
RELAUNCH_ACK_ENV = "WZ_LOOP_RELAUNCH_ACK"


class MeasureError(Exception):
    """A measurement that could not be taken. Never read as a verdict."""


# ─── pure predicates (driven by --selftest) ─────────────────────────────────

def judge(*, start_sha: str, remaining_start: int, head: str, remaining_now: int,
          exact_now: bool, descends: bool, clean: bool) -> tuple[str, str]:
    """The milestone predicate. Returns (verdict, why)."""
    if not clean:
        return CANNOT_JUDGE, ("the tracked tree has uncommitted changes, and REMAINING is "
                              "read off the working tree -- commit or discard them first")
    if not exact_now:
        return CANNOT_JUDGE, ("the audit reports a LOWER BOUND, which cannot say that one "
                              "step was taken")
    if head == start_sha:
        return NOT_REACHED, (f"HEAD is still the snapshot's commit {start_sha[:12]} -- this "
                             "run has committed nothing, whatever REMAINING says")
    if not descends:
        return CANNOT_JUDGE, (f"the snapshot's commit {start_sha[:12]} is not an ancestor of "
                              f"HEAD {head[:12]}, so the two numbers are not one history")
    target = remaining_start - 1
    if remaining_now <= target:
        return REACHED, (f"REMAINING {remaining_start} -> {remaining_now} across "
                         f"{start_sha[:12]}..{head[:12]}")
    return NOT_REACHED, (f"REMAINING is {remaining_now}; it must be <= {target} "
                         f"(baseline {remaining_start} at {start_sha[:12]})")


def relaunch_refusal(*, previous: dict | None, head: str, ack: str | None) -> tuple[bool, str]:
    """Returns (refused, why)."""
    if previous is None:
        return False, ("no previous snapshot -- this is a first launch, so the relaunch "
                       "refusal is UNARMED for it")
    prev_sha = previous["start_sha"]
    if head != prev_sha:
        return False, f"HEAD moved since the previous launch ({prev_sha[:12]} -> {head[:12]})"
    if ack and ack == prev_sha:
        return False, (f"HEAD has not moved since the previous launch ({prev_sha[:12]}), and "
                       f"{RELAUNCH_ACK_ENV} acknowledges exactly that commit")
    return True, (f"HEAD is still {prev_sha[:12]}, the commit the previous launch started "
                  "from: that run moved nothing, so launching the same work again repeats "
                  "it. Find out why it stopped first. To launch anyway, set "
                  f"{RELAUNCH_ACK_ENV}={prev_sha}")


def parse_oracle(payload: dict) -> tuple[list[str], bool]:
    """Validate the oracle's JSON. A missing key is a broken oracle, not an empty set."""
    if not isinstance(payload, dict):
        raise MeasureError("oracle output is not a JSON object")
    for key in ("remaining", "exact"):
        if key not in payload:
            raise MeasureError(f"oracle output lacks '{key}'")
    remaining = payload["remaining"]
    if not isinstance(remaining, list) or not all(isinstance(a, str) for a in remaining):
        raise MeasureError("oracle 'remaining' is not a list of atom ids")
    if not isinstance(payload["exact"], bool):
        raise MeasureError("oracle 'exact' is not a boolean")
    return remaining, payload["exact"]


# ─── measurements ───────────────────────────────────────────────────────────

def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(REPO_ROOT), *args],
                          capture_output=True, text=True)


def head_sha() -> str:
    r = _git("rev-parse", "--verify", "HEAD^{commit}")
    if r.returncode != 0:
        raise MeasureError(f"git rev-parse HEAD failed: {r.stderr.strip()}")
    return r.stdout.strip()


def resolve_commit(sha: str) -> str:
    r = _git("rev-parse", "--verify", f"{sha}^{{commit}}")
    if r.returncode != 0:
        raise MeasureError(f"'{sha}' does not name a commit in this repository")
    return r.stdout.strip()


def is_ancestor(ancestor: str, descendant: str) -> bool:
    r = _git("merge-base", "--is-ancestor", ancestor, descendant)
    if r.returncode not in (0, 1):
        raise MeasureError(f"git merge-base failed: {r.stderr.strip()}")
    return r.returncode == 0


def tree_is_clean() -> bool:
    r = _git("status", "--porcelain", "--untracked-files=no")
    if r.returncode != 0:
        raise MeasureError(f"git status failed: {r.stderr.strip()}")
    return r.stdout.strip() == ""


def measure_remaining() -> tuple[list[str], bool]:
    with tempfile.TemporaryDirectory(prefix="loop-milestone-") as tmp:
        out = Path(tmp) / "remaining.json"
        env = dict(os.environ, WZ_A3_REMAINING_JSON=str(out))
        r = subprocess.run(["bash", str(ORACLE)], cwd=REPO_ROOT, env=env,
                           capture_output=True, text=True)
        if r.returncode != 0:
            tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-5:])
            raise MeasureError(f"the oracle exited {r.returncode}; a red audit is not a "
                               f"baseline. Its last lines:\n{tail}")
        if not out.exists():
            # The oracle SKIPs with exit 0 when mnemosyne-cli or python3 is absent,
            # and a skip measured nothing.
            last = (r.stdout.strip().splitlines() or ["(no output)"])[-1]
            raise MeasureError(f"the oracle exited 0 but wrote no result, so nothing was "
                               f"measured. Its last line: {last}")
        try:
            return parse_oracle(json.loads(out.read_text()))
        except json.JSONDecodeError as e:
            raise MeasureError(f"oracle result is not JSON: {e}") from e


# ─── commands ───────────────────────────────────────────────────────────────

def cmd_snapshot(_args) -> int:
    try:
        clean = tree_is_clean()
        head = head_sha()
        remaining, exact = measure_remaining()
    except MeasureError as e:
        print(f"loop-milestone snapshot: CANNOT MEASURE -- {e}", file=sys.stderr)
        return 2
    if not clean:
        print("loop-milestone snapshot: CANNOT MEASURE -- the tracked tree has uncommitted "
              "changes, so REMAINING would not describe HEAD", file=sys.stderr)
        return 2
    if not exact:
        print("loop-milestone snapshot: CANNOT MEASURE -- the audit reports a lower bound, "
              "which cannot anchor a one-step milestone", file=sys.stderr)
        return 2
    json.dump({"start_sha": head, "remaining_start": len(remaining),
               "remaining_atoms": remaining}, sys.stdout, indent=1)
    print()
    return 0


def cmd_check(args) -> int:
    try:
        start = resolve_commit(args.start_sha)
        clean = tree_is_clean()
        head = head_sha()
        descends = is_ancestor(start, head)
        remaining, exact = measure_remaining()
    except MeasureError as e:
        print(f"loop-milestone check: {CANNOT_JUDGE} -- {e}")
        return EXIT[CANNOT_JUDGE]
    verdict, why = judge(start_sha=start, remaining_start=args.remaining_start, head=head,
                         remaining_now=len(remaining), exact_now=exact,
                         descends=descends, clean=clean)
    # The population is printed on every path: a verdict without the numbers it
    # was read from cannot be told apart from a check that measured nothing.
    print(f"loop-milestone check: baseline {args.remaining_start} at {start[:12]}; "
          f"now {len(remaining)} at {head[:12]} (exact={exact}, clean={clean})")
    print(f"loop-milestone check: {verdict} -- {why}")
    return EXIT[verdict]


def cmd_refuse_relaunch(args) -> int:
    previous = None
    path = Path(args.previous)
    if path.exists():
        try:
            previous = json.loads(path.read_text())
            if not isinstance(previous, dict) or not isinstance(previous.get("start_sha"), str):
                raise ValueError("no 'start_sha'")
        except (ValueError, json.JSONDecodeError) as e:
            print(f"loop-milestone refuse-relaunch: cannot read {path}: {e}", file=sys.stderr)
            return 2
    try:
        head = head_sha()
    except MeasureError as e:
        print(f"loop-milestone refuse-relaunch: {e}", file=sys.stderr)
        return 2
    refused, why = relaunch_refusal(previous=previous, head=head,
                                    ack=os.environ.get(RELAUNCH_ACK_ENV))
    print(f"loop-milestone refuse-relaunch: {'REFUSED' if refused else 'allowed'} -- {why}")
    return 1 if refused else 0


# ─── selftest ───────────────────────────────────────────────────────────────

def selftest() -> int:
    a, b = "a" * 40, "b" * 40
    base = dict(start_sha=a, remaining_start=38, exact_now=True, descends=True, clean=True)
    cases = [
        # (label, overrides, expected verdict)
        # RED-FIRST: the three runs that asked for this module. HEAD never moved
        # and REMAINING stood at the baseline; the old sentence read that as reached.
        ("run 380 shape: nothing committed, number unchanged",
         dict(head=a, remaining_now=38), NOT_REACHED),
        ("commits landed but no atom closed", dict(head=b, remaining_now=38), NOT_REACHED),
        ("number fell with no commit", dict(head=a, remaining_now=37), NOT_REACHED),
        ("one atom closed in this run", dict(head=b, remaining_now=37), REACHED),
        ("more than one atom closed", dict(head=b, remaining_now=35), REACHED),
        ("an atom was re-opened", dict(head=b, remaining_now=39), NOT_REACHED),
        ("lower-bound audit", dict(head=b, remaining_now=37, exact_now=False), CANNOT_JUDGE),
        ("history does not descend", dict(head=b, remaining_now=37, descends=False), CANNOT_JUDGE),
        ("dirty tree", dict(head=b, remaining_now=37, clean=False), CANNOT_JUDGE),
    ]
    ok = True
    seen = set()
    for label, over, want in cases:
        got, why = judge(**{**base, **over})
        seen.add(got)
        if got != want:
            ok = False
            print(f"selftest FAIL: {label}: want {want}, got {got} ({why})", file=sys.stderr)
    # Anti-vacuity: a predicate that answered one verdict for everything would
    # pass a case list that happened to expect only that verdict.
    if seen != {REACHED, NOT_REACHED, CANNOT_JUDGE}:
        ok = False
        print(f"selftest FAIL: the cases exercised only {sorted(seen)}", file=sys.stderr)

    refusals = [
        ("first launch", dict(previous=None, head=a, ack=None), False),
        ("previous run moved nothing", dict(previous={"start_sha": a}, head=a, ack=None), True),
        ("previous run committed", dict(previous={"start_sha": a}, head=b, ack=None), False),
        ("ack names that commit", dict(previous={"start_sha": a}, head=a, ack=a), False),
        ("ack names another commit", dict(previous={"start_sha": a}, head=a, ack=b), True),
    ]
    for label, kw, want in refusals:
        got, why = relaunch_refusal(**kw)
        if got != want:
            ok = False
            print(f"selftest FAIL: relaunch '{label}': want refused={want}, got {got} ({why})",
                  file=sys.stderr)

    for label, payload in [("no remaining", {"exact": True}),
                           ("no exact", {"remaining": []}),
                           ("remaining not a list", {"remaining": 3, "exact": True}),
                           ("exact not a bool", {"remaining": [], "exact": "yes"})]:
        try:
            parse_oracle(payload)
        except MeasureError:
            continue
        ok = False
        print(f"selftest FAIL: oracle payload '{label}' was accepted", file=sys.stderr)
    if parse_oracle({"remaining": ["x"], "exact": True}) != (["x"], True):
        ok = False
        print("selftest FAIL: a well-formed oracle payload was misread", file=sys.stderr)

    print("loop-milestone selftest:", "OK" if ok else "FAILED",
          f"({len(cases)} verdict cases, {len(refusals)} relaunch cases)")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    p = argparse.ArgumentParser(prog="loop_milestone.py",
                                description="Judge an agent loop's milestone against a start-of-run baseline.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("snapshot", help="print HEAD and REMAINING WORK as JSON")
    c = sub.add_parser("check", help="judge the milestone against a snapshot")
    c.add_argument("--start-sha", required=True)
    c.add_argument("--remaining-start", required=True, type=int)
    r = sub.add_parser("refuse-relaunch", help="refuse when the previous launch moved nothing")
    r.add_argument("--previous", required=True, help="the previous launch's snapshot file")
    args = p.parse_args(argv)
    return {"snapshot": cmd_snapshot, "check": cmd_check,
            "refuse-relaunch": cmd_refuse_relaunch}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

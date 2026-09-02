#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2274 (N57, N42) -- a lane that exits 0 having run NOTHING must not print
the same verdict as one that worked.

`debt-carry-N57` reads: "a lane that exits 0 without running anything is
indistinguishable from one that passed, and nothing gates it. ... Each says so
in its own output, so the evidence exists; what is missing is anything that
reads it. Today a person greps the lane's lines by hand."

`debt-carry-N42` reads: "a wrong --features set selects zero tests and reports
green." That is the same defect one level down -- the lane runs, `cargo test`
runs, and the filter selects nothing. `_runci_guarded_test` in `run-ci.sh`
closes it for the call sites that go through it; MEASURED at this round, 81
`cargo test` lines do and 410 do not. Editing 410 sites is not the repayment;
reading the lane's own output once, where every one of them reports, is.

Both items name the same missing organ, so one file answers for both: the thing
that READS a lane's output on the PASS path.

## What a lane's own output already says

Every decline in `run-ci.sh` is printed, by four `_*_unavailable` helpers and by
inline `echo`s that share their vocabulary -- the token `SKIP`. Every libtest
run prints `test result: ok. N passed`. Nothing consumed either, so
`Layer Qz pass (0s)` and `run-ci: all required layers pass` were the verdict of
a run that did nothing at all. Reproduced as a command before any edit:

    WZ_ZEPHYR_VENV=/nonexistent bash scripts/run-ci.sh --layer Qz
      Qz SKIP (Zephyr venv absent: /nonexistent -- set WZ_ZEPHYR_VENV)
      Layer Qz pass (0s)
      run-ci: all required layers pass          <- rc=0

## The classification is TOTAL -- there is no unclassified bucket

Given a lane's own lines (the run's framing lines removed) and rc == 0:

  ZEROTEST  at least one libtest summary, and the SUM of `passed` over all of
            them is 0. The lane's tests selected nothing.        (N42)
  DECLINED  no work line at all, and at least one decline line.  (N57)
  SILENT    no work line and no decline line: the lane printed nothing.
  WORKED    anything else.

A work line is any non-blank line that is not a decline line, so the residual
class is WORK, not "unknown" -- the escape hatch this tree keeps finding cannot
arise here, because nothing can fall outside the four.

ZEROTEST outranks WORKED deliberately: a lane that builds, prints progress, and
then selects zero tests has work lines and is still the defect N42 names.

## All THREE non-WORKED classes are FINDINGS -- R2275 removed the fourth

R2274 shipped this file with SILENT held OUT of the findings, in an UNDECIDED
bucket that was reported and counted but never asserted on. The reason was
honest and measured: 9 lanes were silent on success at that round, so calling
their pass "ran nothing" would have been false. The residue was filed as
open-debt item 615 rather than papered over.

R2275 repaid it, and the bucket is gone. Two things were re-measured first,
because the item's own numbers turned out to be partly the READING's fault:

  * Over the archived corpus (4882 logs, 15183 (log,lane) pass pairs) with the
    slice boundary fixed -- see `find_slice` -- the tally is WORKED 14178,
    SILENT 902, DECLINED 103, ZEROTEST 0, and per lane at its MOST RECENT
    observation exactly SEVEN are silent: C2, C3, C1h, C1bm, C1bq, C1br, C1own.
    B2, the ninth name in item 615, was NEVER silent; the substring boundary
    was cutting its slice at its own evidence line. C1bl had already been fixed.

  * Over hosted run 33568402673 (266 (job,lane) pass pairs, the whole matrix):
    WORKED 253, SILENT 11 -- C1bm, C1bq, C1br, C1h, C1own, C3 -- DECLINED 2,
    and both declines were C2, which had just run a full workspace clippy and
    printed only its `C2 deploy SKIP` line. The reading was making a FALSE claim
    about C2 on every hosted run, not merely an undecided one.

Those seven lanes now end their success path on a line whose count they derived
from the work (`_runci_lane_did` in `run-ci.sh`). So silence no longer means
"quiet but working" anywhere in this tree, and it is classified as what it now
is: a lane whose pass carries no evidence at all. `run_layer` FAILS such a lane
outright rather than routing it through `WZ_DECLINED_EXPECT` -- a decline is a
lane SAYING it did not run, which a caller may legitimately expect, whereas
there is no configuration in which "printed nothing" is the expected shape.

ZEROTEST firing 0 times in 15183 real lane runs is the other half of that
measurement: the N42 reading does not fire spuriously on real output, including
the `cargo test --workspace` runs whose per-target summaries are individually
`0 passed`. It is the SUM over the lane that decides.

## Why the reading is a SLICE of the run's own log, and not a capture

`run-ci.sh` already self-tees all output to `RUNCI_LOG_FILE`, so the evidence is
on disk without any new plumbing. Three other ways to get a lane's output were
built far enough to be measured this round, and two were REFUSED:

  * The DEBUG-trap leg trace `run_layer` already keeps for its FAIL path
    ("reached 3 of 7 guarded legs"). REFUSED: 41 of 155 lane functions have
    ZERO guarded legs by that derivation -- and `layer_qz_zephyr_boot` and
    `layer_g_cross_compile_cortex_m`, the two lanes N57 names, are both in that
    41. The instrument would have been blind to its own item's examples.

  * `"$@" 2>&1 | tee "$lane.log"`, whose flush IS deterministic (bash waits for
    the pipeline's last element). REFUSED: a pipeline runs the lane in a
    SUBSHELL, and three globals cross lane boundaries -- `WZ_ZENOHD_BIN` and
    `WZ_ZENOH_CORE_EXAMPLES_DIR` (set by Layer Z, read by M, Ewirez, E5z) and
    `WZ_ZENOH_C_PREFIX` (set by C1ce, read by C1cc, C1cd). Capturing this way
    would have silently taken the oracle away from five lanes.

  * `"$@" > "$lane.log" 2>&1` then replay. No subshell, no race -- but it ends
    live streaming, and R311y889 (item 362) paid a round for exactly that: a
    lane killed by the job's `timeout-minutes` would leave nothing in the job
    log.

So the slice: the lines between the run's own `──── Layer X ────` header and
its `Layer X pass (Ns)` verdict. The verdict line is printed BEFORE the read
and is therefore the sentinel -- waiting for it to appear in the log is what
makes the read race-free against the self-tee, which is asynchronous and would
otherwise hand back a truncated tail. Nothing about the lane's execution
changes: same shell, same fds, same liveness.

## The vocabulary is pinned BOTH WAYS against run-ci.sh itself

`--audit` derives the decline-helper family from `run-ci.sh` (`_*_unavailable`)
and requires, for every member:

  * its SKIP branch emits a line this file classifies as a DECLINE, and
  * its REQUIRE branch (the `WZ_*_REQUIRE` arm) emits a line it does NOT.

A helper that renames `SKIP` fails the first; a FAIL line drifting into the
decline vocabulary fails the second. An empty family is RED -- a vocabulary
gate whose subject has vanished is not passing, it has lost its subject.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# `run_layer`'s own lines: `[2026-09-02T08:18:17+0900] INFO  ...`. Only the
# runner prints these, so removing them leaves exactly the lane's own output.
FRAMING = re.compile(r"^\[\d{4}-\d{2}-\d{2}T[\d:+\-]+\]\s+(?:INFO|ERROR|WARN)\b")

# The decline vocabulary. One token, because that is what run-ci.sh actually
# writes -- and `--audit` is what keeps this sentence true rather than a
# comment claiming it.
DECLINE = re.compile(r"\bSKIP\b")

# libtest's summary, `--quiet` included. Both verdict words, because a lane
# that FAILED its tests is not this file's subject but its count still is.
LIBTEST = re.compile(r"^\s*test result: (?:ok|FAILED)\.\s+(\d+)\s+passed\b")

HEADER_OF = "──── Layer {name} ────"
VERDICT_OF = "Layer {name} pass ("

# The classes whose evidence says the lane's pass is not evidence of work.
# R2275 put SILENT among them and deleted the UNDECIDED bucket it used to sit
# in: every lane in this tree now prints one derived line on its success path,
# so "printed nothing" is no longer a state a working lane can be in. An
# unclassified pass is the escape hatch this repo keeps finding, and a bucket
# that is reported but never asserted on is exactly that hatch.
FINDINGS = ("ZEROTEST", "DECLINED", "SILENT")
CLASSES = (*FINDINGS, "WORKED")


class ReadError(RuntimeError):
    """The slice could not be established. Never a silent green."""


def lane_lines(slice_text: str) -> list[str]:
    """The lane's own lines: framing removed, blank lines dropped."""
    out = []
    for line in slice_text.splitlines():
        if FRAMING.match(line):
            continue
        if not line.strip():
            continue
        out.append(line)
    return out


def classify(slice_text: str) -> tuple[str, str]:
    """`(verdict, detail)` -- total over the four classes, no residue."""
    lines = lane_lines(slice_text)
    declines = [ln for ln in lines if DECLINE.search(ln)]
    work = [ln for ln in lines if not DECLINE.search(ln)]
    summaries = [m for m in (LIBTEST.match(ln) for ln in lines) if m]
    passed = sum(int(m.group(1)) for m in summaries)

    if summaries and passed == 0:
        return (
            "ZEROTEST",
            f"{len(summaries)} libtest summary/summaries, 0 test(s) executed "
            "in total -- the filter or the --features set selected nothing",
        )
    if work:
        return ("WORKED", f"{len(work)} work line(s), {len(declines)} decline(s)")
    if declines:
        return (
            "DECLINED",
            f"{len(declines)} decline(s) and no work line -- the lane ran nothing",
        )
    return ("SILENT", "no output at all -- the lane left no evidence it ran")


def find_slice(text: str, lane: str) -> str | None:
    """The lane's own lines out of a whole run log, or None if not complete yet.

    BOTH boundaries must be RUN_LAYER's own lines, not merely lines that contain
    the words. R2275: `layer_b2_regen_diff` ends its success path with
    `echo "Layer B2 pass (committed out/** == regenerated, ...)"`, and a bare
    substring search stopped the slice THERE -- at the lane's own evidence line,
    leaving an empty slice that read as SILENT. The lane was never silent; the
    reading was. The framing prefix is what only `run_layer` writes, so requiring
    it makes the boundary unambiguous.

    This is the ONE place the boundary is decided. R2275 found the first draft
    with the same rule spelled a second time inside a measurement script, which
    is how the B2 defect survived its own fix for a turn.
    """
    header = HEADER_OF.format(name=lane)
    verdict = VERDICT_OF.format(name=lane)
    lines = text.split("\n")
    h = v = -1
    for i, ln in enumerate(lines):
        if not FRAMING.match(ln):
            continue
        if header in ln:
            h, v = i, -1
        elif v < 0 and h >= 0 and verdict in ln:
            v = i
    if h >= 0 and v > h:
        return "\n".join(lines[h + 1 : v]) + "\n"
    return None


def slice_from_log(log: Path, lane: str, wait_s: float) -> str:
    """The lane's slice, waiting for the verdict sentinel to be flushed.

    `run-ci.sh` writes through an asynchronous `tee`, so the bytes a lane just
    printed are not necessarily in the file yet. The verdict line is printed
    before this runs, which makes it a sentinel: once IT is in the file, so is
    everything the lane wrote before it.
    """
    deadline = time.monotonic() + wait_s
    while True:
        try:
            text = log.read_text(errors="replace")
        except OSError as exc:  # pragma: no cover - unreadable log
            raise ReadError(f"cannot read {log}: {exc}") from exc
        got = find_slice(text, lane)
        if got is not None:
            return got
        if time.monotonic() >= deadline:
            header = HEADER_OF.format(name=lane)
            missing = "header" if header not in text else "verdict"
            raise ReadError(
                f"lane {lane}: the {missing} line never reached {log} within "
                f"{wait_s}s -- the decline reading could not be performed, "
                "which is not the same as a lane that worked"
            )
        time.sleep(0.02)


# ── --audit: the vocabulary, pinned both ways against run-ci.sh ──────────────

FAMILY = re.compile(r"^(_[a-z0-9_]*unavailable)\(\)\s*\{\s*$")
ECHO = re.compile(r"""^\s*echo\s+"(.*)"\s*(?:>&2)?\s*$""")


def helper_bodies(runci: str) -> dict[str, list[str]]:
    """`helper -> its body lines`, derived from the file, never listed here."""
    lines = runci.split("\n")
    found: dict[str, list[str]] = {}
    for i, line in enumerate(lines):
        m = FAMILY.match(line)
        if not m:
            continue
        body = []
        for j in range(i + 1, len(lines)):
            if re.match(r"^\}\s*$", lines[j]):
                break
            body.append(lines[j])
        found[m.group(1)] = body
    return found


def audit(runci_text: str) -> list[str]:
    """Findings; empty means the vocabulary still matches what run-ci.sh says."""
    bad: list[str] = []
    fam = helper_bodies(runci_text)
    if not fam:
        return [
            "no `_*_unavailable` helper found in run-ci.sh -- the decline "
            "vocabulary has lost its subject, which is not a pass"
        ]
    for name, body in sorted(fam.items()):
        # The REQUIRE arm is the part guarded by `if [[ -n "${WZ_*_REQUIRE" ]]`;
        # everything after its `fi` is the decline arm. Derived from the body's
        # own shape rather than from line numbers written down here.
        cut = next(
            (k for k, ln in enumerate(body) if re.match(r"^\s*fi\s*$", ln)), None
        )
        if cut is None:
            bad.append(
                f"{name}: no `fi` -- cannot tell its REQUIRE arm from its decline arm"
            )
            continue
        require_arm = [m.group(1) for ln in body[:cut] if (m := ECHO.match(ln))]
        decline_arm = [m.group(1) for ln in body[cut + 1 :] if (m := ECHO.match(ln))]
        if not decline_arm:
            bad.append(
                f"{name}: its decline arm prints nothing, so a decline leaves no evidence"
            )
        for msg in decline_arm:
            if not DECLINE.search(msg):
                bad.append(
                    f"{name}: decline line is not in the decline vocabulary: {msg!r}"
                )
        for msg in require_arm:
            if DECLINE.search(msg):
                bad.append(f"{name}: its REQUIRE (FAIL) line reads as a DECLINE: {msg!r}")
    return bad


# ── selftest ────────────────────────────────────────────────────────────────

FIXTURE_REASON = {
    "declined": "N57's own shape: one SKIP line and nothing else",
    "worked": "a lane that printed work must stay WORKED",
    "worked_with_skip": "one skipped leg among work is NOT a declined lane",
    "zerotest": "N42's shape: summaries present, 0 executed in total",
    "zerotest_amid_work": "ZEROTEST outranks WORKED -- work lines do not hide it",
    "tests_ran": "a real test run is WORKED even with 0-test targets among it",
    "silent": "a lane that printed nothing left no evidence either",
    "framing_only": "the runner's own lines are not the lane's evidence",
}

CASES = [
    ("declined", "  Qz SKIP (Zephyr venv absent: /nope)\n", "DECLINED"),
    ("worked", "  gate: OK (3 things)\n", "WORKED"),
    ("worked_with_skip", "  G.6 t SKIP (no toolchain)\n  G.1 built ok\n", "WORKED"),
    ("zerotest", "test result: ok. 0 passed; 0 failed; 0 ignored\n", "ZEROTEST"),
    (
        "zerotest_amid_work",
        "   Compiling wz-session-core\n"
        "test result: ok. 0 passed; 0 failed; 2 ignored\n",
        "ZEROTEST",
    ),
    (
        "tests_ran",
        "test result: ok. 0 passed; 0 failed; 0 ignored\n"
        "test result: ok. 12 passed; 0 failed; 0 ignored\n",
        "WORKED",
    ),
    ("silent", "\n   \n", "SILENT"),
    ("framing_only", "[2026-09-02T08:18:17+0900] INFO  Layer X pass (0s)\n", "SILENT"),
]


def _selftest_classify() -> list[str]:
    bad = []
    seen = set()
    for name, text, want in CASES:
        got, _ = classify(text)
        seen.add(name)
        if got != want:
            bad.append(
                f"classify[{name}]: want {want}, got {got} ({FIXTURE_REASON[name]})"
            )
    missing = set(FIXTURE_REASON) - seen
    if missing:
        bad.append(f"FIXTURE_REASON documents cases no arm runs: {sorted(missing)}")
    # Both directions over the class set: every class must be produced by at
    # least one fixture, or the table could pass while a whole class is
    # unreachable -- including SILENT, which R2275 promoted into FINDINGS.
    produced = {classify(t)[0] for _, t, _ in CASES}
    for cls in CLASSES:
        if cls not in produced:
            bad.append(f"no fixture reaches the {cls} class -- it is never exercised")
    # And the partition itself: exactly one class is not a finding. R2275's
    # repayment IS the shrinking of this residue, so a later round that quietly
    # re-opens an undecided bucket -- any second non-finding class -- reopens
    # item 615 and has to say so here first.
    if set(CLASSES) - set(FINDINGS) != {"WORKED"}:
        bad.append(
            "the only class that is not a finding must be WORKED; a second "
            f"un-asserted class is the escape hatch item 615 closed: {sorted(set(CLASSES) - set(FINDINGS))}"
        )
    if produced - set(CLASSES):
        bad.append(f"classify returned a class no table names: {produced - set(CLASSES)}")
    return bad


def _selftest_slice() -> list[str]:
    bad = []
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "run.log"
        log.write_text(
            "[2026-01-01T00:00:00+0900] INFO  ──── Layer Qz ────\n"
            "  Qz SKIP (venv absent)\n"
            "[2026-01-01T00:00:01+0900] INFO  Layer Qz pass (0s)\n"
            "[2026-01-01T00:00:01+0900] INFO  ──── Layer G ────\n"
            "  G built\n"
            "[2026-01-01T00:00:02+0900] INFO  Layer G pass (1s)\n"
        )
        for lane, want in (("Qz", "DECLINED"), ("G", "WORKED")):
            got, _ = classify(slice_from_log(log, lane, 1.0))
            if got != want:
                bad.append(f"slice[{lane}]: want {want}, got {got}")
        # R2275, and this is the shape the FIRST implementation swallowed:
        # a lane whose own evidence line CONTAINS the verdict sentence. Layer B2
        # really does end with `echo "Layer B2 pass (committed out/** == ...)"`,
        # and a substring boundary stopped the slice there and called the lane
        # SILENT. Only the FRAMED line is run_layer's.
        collide = Path(td) / "collide.log"
        collide.write_text(
            "[2026-01-01T00:00:00+0900] INFO  ──── Layer B2 ────\n"
            "Layer B2 pass (committed out/** == regenerated, no absolute path)\n"
            "[2026-01-01T00:00:01+0900] INFO  Layer B2 pass (2s)\n"
        )
        got, _ = classify(slice_from_log(collide, "B2", 1.0))
        if got != "WORKED":
            bad.append(
                f"slice[B2 collision]: want WORKED, got {got} -- a lane whose own "
                "evidence line contains the verdict sentence must not read as SILENT"
            )
        # A slice that never arrives must RAISE, not return an empty lane --
        # which would classify as SILENT and read as a finding about the lane
        # rather than about the reading.
        try:
            slice_from_log(log, "Nope", 0.05)
        except ReadError:
            pass
        else:
            bad.append("a missing lane returned a slice instead of refusing")
    return bad


def _selftest_audit(root: Path) -> list[str]:
    bad = []
    runci = (root / "scripts" / "run-ci.sh").read_text()
    live = audit(runci)
    if live:
        bad.append(f"audit is RED on the real run-ci.sh: {live}")
    # Four mutations, each RED, plus the empty-population arm.
    muts = [
        (
            "renamed decline token",
            lambda t: t.replace('echo "  Qz SKIP ($1)"', 'echo "  Qz SKIPPED ($1)"', 1),
            "decline line is not in the decline vocabulary",
        ),
        (
            "FAIL line drifts into the vocabulary",
            lambda t: t.replace(
                'echo "  Qz FAIL — required (WZ_QZ_REQUIRE set) but $1" >&2',
                'echo "  Qz FAIL — SKIP required (WZ_QZ_REQUIRE set) but $1" >&2',
                1,
            ),
            "reads as a DECLINE",
        ),
        (
            "decline arm prints nothing",
            lambda t: t.replace('echo "  Qz SKIP ($1)"', ": # nothing", 1),
            "prints nothing",
        ),
        (
            "family removed",
            lambda t: re.sub(r"^_[a-z0-9_]*unavailable\(\)", "_gone()", t, flags=re.M),
            "lost its subject",
        ),
    ]
    for label, mutate, needle in muts:
        text = mutate(runci)
        if text == runci:
            bad.append(f"mutation {label!r} changed nothing -- it is not a probe")
            continue
        found = audit(text)
        if not any(needle in f for f in found):
            bad.append(f"mutation {label!r} did not go RED (findings={found})")
    return bad


def _selftest_witness(root: Path) -> list[str]:
    """The end-to-end arm: run-ci.sh itself, with an oracle pointed away.

    This is the only arm that proves the READING is wired rather than merely
    written. A missing `run-ci.sh` is reported as a finding, never as a pass.
    """
    runci = root / "scripts" / "run-ci.sh"
    if not runci.is_file():
        return [f"{runci} absent -- the end-to-end arm could not run"]
    env = dict(os.environ)
    env["WZ_ZEPHYR_VENV"] = "/nonexistent-venv-for-the-selftest"
    env.pop("WZ_QZ_REQUIRE", None)
    env.pop("WZ_DECLINED_EXPECT", None)
    env["RUNCI_LOG_DIR"] = tempfile.mkdtemp(prefix="lane-decline-selftest-")
    try:
        proc = subprocess.run(
            ["bash", str(runci), "--layer", "Qz"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:  # pragma: no cover
        return ["the end-to-end arm timed out"]
    finally:
        shutil.rmtree(env["RUNCI_LOG_DIR"], ignore_errors=True)
    out = proc.stdout + proc.stderr
    bad = []
    if "ran nothing" not in out:
        bad.append(
            "run-ci.sh --layer Qz with its oracle removed did not report that "
            "the lane ran nothing -- the reading is not wired into run_layer"
        )
    if re.search(r"all required layers pass\s*$", out, re.M):
        bad.append(
            "the run still ended on an unqualified `all required layers pass` "
            "while a lane had run nothing"
        )
    if proc.returncode != 0:
        bad.append(
            "a DECLINE failed the run outright. It must not: a decline is a "
            "lane saying it did not run, which a caller may legitimately "
            "expect, and `WZ_DECLINED_EXPECT` is where that is asserted"
        )
    bad += _selftest_silent_lane_reds(root, runci, env)
    return bad


def _selftest_silent_lane_reds(root: Path, runci: Path, env: dict) -> list[str]:
    """R2275 (item 615): a lane that prints NOTHING must FAIL, by mutation.

    The subject is `run-ci.sh` itself, so the probe is a mutated COPY of it run
    from the repo root -- deleting the one `echo` that is Layer Qz's entire
    output turns a DECLINED lane into a SILENT one without touching anything
    else. Asserting the class membership in `CLASSES` alone would prove only
    that this file's table was edited; this proves the RUN goes red.

    The copy lives outside the tree. `run-ci.sh` resolves its lane spans from
    `BASH_SOURCE`, which follows the copy, while every path it uses for work is
    relative to the working directory, which stays the repository root. The one
    thing it reaches for beside itself is `lib/`, which it `source`s from its
    OWN directory -- hence the symlink, without which the probe runs with a
    library the real script has and prints a spurious error while doing it.
    """
    text = runci.read_text()
    needle = 'echo "  Qz SKIP ($1)"'
    if needle not in text:
        return [
            f"the mutation probe's subject is gone from run-ci.sh ({needle!r}) "
            "-- it is not a probe any more"
        ]
    mutant_dir = tempfile.mkdtemp(prefix="lane-decline-silent-")
    mutant = Path(mutant_dir) / "run-ci-silent-mutant.sh"
    mutant.write_text(text.replace(needle, ":", 1))
    (Path(mutant_dir) / "lib").symlink_to(runci.parent / "lib")
    env = dict(env)
    env["RUNCI_LOG_DIR"] = tempfile.mkdtemp(prefix="lane-decline-silent-log-")
    try:
        proc = subprocess.run(
            ["bash", str(mutant), "--layer", "Qz"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:  # pragma: no cover
        return ["the silent-lane mutation arm timed out"]
    finally:
        shutil.rmtree(mutant_dir, ignore_errors=True)
        shutil.rmtree(env["RUNCI_LOG_DIR"], ignore_errors=True)
    out = proc.stdout + proc.stderr
    bad = []
    if proc.returncode == 0:
        bad.append(
            "a lane mutated to print NOTHING still passed the run -- silence is "
            "back to being an un-asserted class, which is item 615"
        )
    if "printed NOTHING" not in out:
        bad.append(
            "the run did not say the lane printed nothing, so its red (if any) "
            "does not name the defect"
        )
    return bad


def selftest(root: Path) -> int:
    bad = (
        _selftest_classify()
        + _selftest_slice()
        + _selftest_audit(root)
        + _selftest_witness(root)
    )
    if bad:
        print("  lane decline read SELFTEST FAIL:", file=sys.stderr)
        for b in bad:
            print(f"    - {b}", file=sys.stderr)
        return 1
    print(
        "  lane decline read: selftest OK "
        f"({len(CASES)} classification fixture(s) over {len(CLASSES)} classes, "
        f"{len(FINDINGS)} of them findings, slice + collision + refusal, "
        "4 audit mutations, run-ci.sh --layer Qz driven with its oracle "
        "removed, and a run-ci.sh mutated to make that lane print NOTHING, "
        "which must go red)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="read a lane's own output on the pass path")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--read", action="store_true", help="classify one lane from a run log")
    g.add_argument("--audit", action="store_true", help="pin the decline vocabulary")
    g.add_argument("--selftest", action="store_true")
    ap.add_argument("--log", type=Path)
    ap.add_argument("--lane")
    ap.add_argument("--wait", type=float, default=10.0)
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = ap.parse_args()

    if args.selftest:
        return selftest(args.root)
    if args.audit:
        runci = (args.root / "scripts" / "run-ci.sh").read_text()
        found = audit(runci)
        if found:
            print("  lane decline vocabulary FAIL:", file=sys.stderr)
            for f in found:
                print(f"    - {f}", file=sys.stderr)
            return 1
        n = len(helper_bodies(runci))
        print(f"  lane decline vocabulary: OK ({n} decline helper(s), pinned both ways)")
        return 0

    if not args.log or not args.lane:
        ap.error("--read needs --log and --lane")
    try:
        verdict, detail = classify(slice_from_log(args.log, args.lane, args.wait))
    except ReadError as exc:
        print(f"UNREAD {exc}")
        return 2
    print(f"{verdict} {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

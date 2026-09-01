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

## Only TWO of the four are FINDINGS, and a measurement is why

The first draft called SILENT a finding too -- a lane that printed nothing is
surely as indistinguishable as one that printed a SKIP. MEASURED before that
claim was allowed to stand, by running this classifier over every historical
run log this tree keeps (`crates/target/run-ci-logs`, 4878 logs, 15189
(log,lane) pairs that reached a pass verdict):

    WORKED   14032  92.4%   144 lane(s)
    SILENT    1055   6.9%    12 lane(s)
    DECLINED   102   0.7%     6 lane(s)   M, C1br, C1ce, Qz, Z, C1bs
    ZEROTEST     0   0.0%     0 lane(s)

and then, per lane, at its MOST RECENT observation: 9 of those 12 are silent
STILL -- C2, C3, C1h, C1bl, C1bm, C1bq, C1br, C1own, B2. They are legitimate:
`cargo clippy` that finds nothing prints nothing, and it did the work.

So SILENT is REPORTED and COUNTED but is NOT claimed as "ran nothing" and does
NOT enter the armed expectation. The reading genuinely cannot separate "worked
quietly" from "did nothing quietly" for those lanes, and asserting a
discrimination it does not have would be the same defect one level up. The
repayment that WOULD separate them is for each of those lanes to print one line
of evidence; that residue is filed rather than papered over.

ZEROTEST firing 0 times in 15189 real lane runs is the other half of that
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

# The classes whose evidence PROVES the lane ran nothing. SILENT is deliberately
# not among them -- see the header's measurement: 9 lanes are silent on success
# to this day, and calling their pass "ran nothing" would be false.
FINDINGS = ("ZEROTEST", "DECLINED")
# Classified, counted and reported, but not claimed either way.
UNDECIDED = ("SILENT",)
CLASSES = (*FINDINGS, *UNDECIDED, "WORKED")


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


def slice_from_log(log: Path, lane: str, wait_s: float) -> str:
    """The lane's slice, waiting for the verdict sentinel to be flushed.

    `run-ci.sh` writes through an asynchronous `tee`, so the bytes a lane just
    printed are not necessarily in the file yet. The verdict line is printed
    before this runs, which makes it a sentinel: once IT is in the file, so is
    everything the lane wrote before it.
    """
    header = HEADER_OF.format(name=lane)
    verdict = VERDICT_OF.format(name=lane)
    deadline = time.monotonic() + wait_s
    while True:
        try:
            text = log.read_text(errors="replace")
        except OSError as exc:  # pragma: no cover - unreadable log
            raise ReadError(f"cannot read {log}: {exc}") from exc
        h = text.rfind(header)
        if h >= 0:
            v = text.find(verdict, h)
            if v >= 0:
                return text[text.find("\n", h) + 1 : text.rfind("\n", h, v) + 1]
        if time.monotonic() >= deadline:
            missing = "header" if h < 0 else "verdict"
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
    # unreachable -- including SILENT, which is not a finding but is still a
    # verdict this file hands back and run-ci.sh routes on.
    produced = {classify(t)[0] for _, t, _ in CASES}
    for cls in CLASSES:
        if cls not in produced:
            bad.append(f"no fixture reaches the {cls} class -- it is never exercised")
    # And the partition itself: FINDINGS and UNDECIDED must not overlap, and
    # together with WORKED must cover exactly what `classify` can return.
    if set(FINDINGS) & set(UNDECIDED):
        bad.append("FINDINGS and UNDECIDED overlap -- a class cannot be both")
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
        f"({len(CASES)} classification fixture(s) over 4 classes, "
        "slice + refusal, 4 audit mutations, and run-ci.sh --layer Qz driven "
        "with its oracle removed)"
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

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3150 (no register item) -- WHAT AN ORDINARY PUSH RUNS, AS A LIST THAT CAN FAIL.

The citation is `no register item`: open-debt item 897 lives in the operator's
agent-memory register, which has no store `debt-` id for `gate_provenance_lint`
to resolve; the honest pair is this sentence and `no register item` above.

## The defect

`.githooks/pre-push` has two regions. Everything up to the policy boundary
(`if [[ "${WZ_PREPUSH_EXTENDED:-0}" != "1" ]]; then ... exit 0`) runs on EVERY
push; everything after it runs only when a person sets `WZ_PREPUSH_EXTENDED=1`.
The owner's 2026-09-23 instruction put the boundary directly after gate 2c, so
the ~90 gates the hook is known for -- the 87-entry round-fed array, the
upstream-citation gate, the changed-crate tests -- are all BELOW it.

Nothing said so in a form that could fail. `round_fed_gate_reach.py` grades
which gates the hook NAMES, and its own text records that it checks reach "in
that EXTENDED sweep, not execution on an ordinary push". So a gate could be
"run by the hook" in every sense any checker used and run on no push at all,
and on 2026-10-09 three of them were: one push raised the root-less citation
ratchet of `upstream_citation_anchor_gate.py` (the hook names it, below the
boundary), one made a doc-link blind-spot check red (hosted Layer C0d, which
the hook never named), and several moved a test set without moving a count
guard. Seven hosted runs went red for cheap, deterministic, tree-only checks
that a local run takes seconds to answer.

## What this holds

A short table of the checks that MUST sit above the boundary, each with the
seconds it was measured at and the incident that put it there; and a short
table of checks that deliberately stay hosted, each with the reason, so that a
deferral is a written decision rather than a silence. Both tables are printed on
every run. The check is textual on purpose, over the hook's own code lines (a
comment does not run), with a backslash-continued command read as one line:

  * a REQUIRED check absent from the default region is a finding, and one that
    appears only AFTER the boundary is named as the shape this gate exists for;
  * a default-region run of a DEFERRED check is a finding too -- a deferral the
    hook has quietly stopped honouring is a stale claim about cost;
  * a default-region run of `guarded_count_gate.py` without `--count-only` or
    `--cached-only` is a finding: its full run builds one cargo target per guard
    it reaches, and a single cold guard measured 473s. The ordinary push runs it
    with `--cached-only` (item 898), and that row must keep its exit status: a
    line ending `|| true` is a report, not a check, and is a finding too;
  * an `echo`/`printf` line that merely NAMES a command does not run it (it
    neither satisfies a required row nor trips a forbidden one), the same way a
    comment does not; one that chains another command is read as code;
  * a hook with no boundary, or two, is a finding: the split is the subject, so
    a scanner that found none has agreed with nothing.

## What this does NOT claim

That the listed checks are sufficient. They are the ones with a measured cost
under a minute whose absence cost a hosted run. A check that is not listed is
not thereby deferred; it is simply unlisted, and `round_fed_gate_reach.py`
still grades it in the extended sweep.

Usage:
    python3 scripts/lib/hook_default_region_gate.py            # grade the real hook
    python3 scripts/lib/hook_default_region_gate.py --selftest
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK_REL = ".githooks/pre-push"

#: The line that ends the ordinary push. Matched on the code line, not a
#: comment, and required to be unique: two of them would make "before the
#: boundary" mean two things.
BOUNDARY = re.compile(r'^\s*if \[\[ "\$\{WZ_PREPUSH_EXTENDED:-0\}" != "1" \]\]; then\s*$')

#: A command whose exit status is thrown away.
DISCARDS_RC = re.compile(r"\|\|\s*(true|:)(\s|;|$)")


class Required(NamedTuple):
    """A check an ordinary push must run."""

    needles: tuple[str, ...]  # all on ONE logical line of the default region
    seconds: str  # measured wall clock, quoted as the measurement was taken
    why: str
    #: True when the row's exit status is a verdict the hook must act on, so the
    #: line must not end `|| true`.
    judges: bool = False


class Deferred(NamedTuple):
    """A check that stays hosted, and the written reason."""

    needle: str
    why: str


#: Seconds are one clean-tree run on the development machine at the time of
#: writing (load average 4), quoted to the precision the measurement had. They
#: are a record of why each sits here, not a budget this gate enforces.
REQUIRED: tuple[Required, ...] = (
    Required(
        ("scripts/lib/upstream_citation_anchor_gate.py",),
        "10.7 (form arm 9.9)",
        "root-less citation ratchet: a README paragraph naming two upstream "
        "source lines without a root raised it by one and hosted Layer C0 "
        "went red, for a gate the hook named only below the boundary",
    ),
    Required(
        ("scripts/lib/store_reason_citation_gate.py",),
        "0.5",
        "the citation gate's sibling over the store's atom reasons",
    ),
    Required(
        ("scripts/lib/prose_feature_gate.py",),
        "0.3",
        "the citation gate's second sibling, over cargo commands written in prose",
    ),
    Required(
        ("scripts/run-ci.sh", "--layer C0d"),
        "4.8",
        "the doc-link dependent expansion, including the check that no macro "
        "emits a doc link into another workspace crate; a macro in "
        "wz-capi-dissect made it red on hosted CI after a green hook",
    ),
    Required(
        ("scripts/run-ci.sh", "--layer C0e"),
        "1.1",
        "the inventory tag reader; reads the store's predicates, tree only",
    ),
    Required(
        ("scripts/run-ci.sh", "--layer C0f"),
        "0.8",
        "the Layer Z demo-feature restore pair; reads run-ci.sh as text",
    ),
    Required(
        ("scripts/lib/count_guard_lint.py",),
        "0.3",
        "the statically derivable run-ci count guards (187 of 435); the rest "
        "need a build and are the next row's subject",
    ),
    Required(
        ("scripts/lib/guarded_count_gate.py", "--cached-only"),
        "2.0 (the selection-only report it replaced: 2.0; parsing 491 guards dominates)",
        "the count guards this push reaches, judged from the per-clone cache "
        "and NEVER built: a cached number that disagrees with the declared one "
        "refuses the push (a known wrong number, free to detect); a guard with "
        "no measurement for this tree is printed as DEFERRED and passes, "
        "because measuring it builds one cargo target per guard (473s cold) and "
        "hosted CI judges it. A count moved without its number reddened hosted "
        "runs repeatedly",
        judges=True,
    ),
    Required(
        ("scripts/lib/hook_default_region_gate.py",),
        "0.1",
        "this table: without it the rows above can be moved below the "
        "boundary by a change that no other gate reads as a change in cost",
    ),
)

DEFERRED: tuple[Deferred, ...] = (
    Deferred(
        "scripts/run-ci.sh --layer U",
        "needs the network and a GitHub token (9.4s when reachable) and goes "
        "red whenever upstream publishes a release, which is a fact about the "
        "world and not about this push; a push blocked on it would be refused "
        "for a reason it did not cause. Its own lane header says it is "
        "deliberately not in the hook",
    ),
)

#: A default-region use of this module is allowed ONLY with one of its
#: companions (the two modes that never build).
FORBIDDEN_UNLESS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (
        "scripts/lib/guarded_count_gate.py",
        ("--count-only", "--cached-only"),
        "the full run builds one cargo target per count guard the push reaches; "
        "one cold guard (wz-runtime-zephyr, 1 of 435) measured 473s through the "
        "build machine, against the hook's whole ordinary cost of about two "
        "minutes",
    ),
)


def code_lines(src: str) -> list[tuple[int, str]]:
    """The hook's code, one entry per LOGICAL line.

    A whole-line comment is dropped (a comment does not run), and a line ending
    in a backslash is joined to the next, so a command wrapped for width reads
    as the one command it is. The number is the physical line the logical one
    starts on.
    """
    out: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    for no, raw in enumerate(src.split("\n"), 1):
        stripped = raw.strip()
        if not pending and stripped.startswith("#"):
            continue
        if not pending:
            start = no
        if raw.rstrip().endswith("\\"):
            pending.append(raw.rstrip()[:-1])
            continue
        pending.append(raw)
        out.append((start, " ".join(p.strip() for p in pending)))
        pending = []
    if pending:
        out.append((start, " ".join(p.strip() for p in pending)))
    return [(no, text) for no, text in out if not _is_inert_message(text)]


#: A message line: `echo`/`printf` and nothing that chains another command.
_MESSAGE = re.compile(r"^(echo|printf)\s")
_CHAINS = re.compile(r"\||&&|;|\$\(|`")


def _is_inert_message(text: str) -> bool:
    """True for an `echo`/`printf` line that cannot run anything else.

    A hint that NAMES a command ("measure now: python3 .../gate.py --range x")
    does not run it, exactly as a comment does not, and must neither satisfy a
    REQUIRED row nor trip a FORBIDDEN one. A line that chains a command after
    the message (a pipe, `;`, `&&`, a substitution, a backtick) is not inert and
    is read as code, which is the conservative direction.
    """
    return bool(_MESSAGE.match(text.strip())) and not _CHAINS.search(text)


def split_regions(
    lines: list[tuple[int, str]]
) -> tuple[list[tuple[int, str]], list[tuple[int, str]], list[str]]:
    """`(default, extended, problems)` around the single policy boundary."""
    hits = [i for i, (_, text) in enumerate(lines) if BOUNDARY.match(text)]
    if len(hits) != 1:
        return (
            [],
            [],
            [
                f"the hook has {len(hits)} policy boundary line(s) matching "
                f"`if [[ \"${{WZ_PREPUSH_EXTENDED:-0}}\" != \"1\" ]]; then`, "
                "wanted exactly 1: the split between an ordinary push and the "
                "extended sweep is this gate's subject, so a hook it cannot "
                "split has not been graded"
            ],
        )
    return lines[: hits[0]], lines[hits[0] :], []


def grade(src: str) -> list[str]:
    """Every finding for a hook's text; empty means it holds."""
    default, extended, problems = split_regions(code_lines(src))
    if problems:
        return problems
    if not default:
        return ["the default region is empty: nothing runs on an ordinary push"]
    findings: list[str] = []

    def on_one_line(region: list[tuple[int, str]], needles: tuple[str, ...]) -> bool:
        return any(all(n in text for n in needles) for _, text in region)

    for req in REQUIRED:
        if on_one_line(default, req.needles):
            continue
        what = " ".join(req.needles)
        if on_one_line(extended, req.needles):
            findings.append(
                f"`{what}` runs only AFTER the policy boundary, i.e. only when "
                "WZ_PREPUSH_EXTENDED=1 is set. That is the shape that let seven "
                "hosted runs go red: the hook names the check and no ordinary "
                f"push runs it. ({req.why})"
            )
        else:
            findings.append(f"`{what}` is not in the hook at all. ({req.why})")

    for d in DEFERRED:
        if on_one_line(default, (d.needle,)):
            findings.append(
                f"`{d.needle}` runs on an ordinary push, but this gate records "
                f"it as deferred: {d.why}. Either the deferral is stale or the "
                "call does not belong here."
            )

    for needle, companions, why in FORBIDDEN_UNLESS:
        for no, text in default:
            if needle in text and not any(c in text for c in companions):
                findings.append(
                    f"line {no}: `{needle}` runs on an ordinary push without "
                    f"{' or '.join(f'`{c}`' for c in companions)}: {why}"
                )
    # A verdict-bearing row whose exit code is thrown away is a report, not a
    # check: the pre-item-898 spelling of the count-guard row ended `|| true`.
    for req in REQUIRED:
        if not req.judges:
            continue
        for no, text in default:
            if all(n in text for n in req.needles) and DISCARDS_RC.search(text):
                findings.append(
                    f"line {no}: `{' '.join(req.needles)}` has its exit status "
                    "discarded (`|| true`): the row exists to refuse a push on a "
                    "known wrong number, and a discarded status is a report"
                )
    return findings


def report() -> None:
    print("hook-default-region: checks an ORDINARY push (no WZ_PREPUSH_EXTENDED) must run")
    for r in REQUIRED:
        print(f"  RUNS      {' '.join(r.needles):<62} {r.seconds}s")
    for d in DEFERRED:
        print(f"  DEFERRED  {d.needle:<62} stays on hosted CI")


def check(root: Path) -> int:
    hook = root / HOOK_REL
    try:
        src = hook.read_text()
    except OSError as exc:
        print(f"hook-default-region: FAIL -- cannot read {HOOK_REL}: {exc}", file=sys.stderr)
        return 1
    report()
    findings = grade(src)
    for f in findings:
        print(f"hook-default-region: FAIL -- {f}", file=sys.stderr)
    if findings:
        return 1
    print(
        f"hook-default-region: OK -- {len(REQUIRED)} check(s) sit above the policy "
        f"boundary of {HOOK_REL}, {len(DEFERRED)} deferral(s) are still deferred"
    )
    return 0


def _fixture_hook(default_cmds: list[str], extended_cmds: list[str], boundary: int = 1) -> str:
    """A hook-shaped text: `default_cmds`, the boundary, `extended_cmds`."""
    parts = ["#!/usr/bin/env bash", "set -euo pipefail", *default_cmds]
    parts += [
        'if [[ "${WZ_PREPUSH_EXTENDED:-0}" != "1" ]]; then',
        "    exit 0",
        "fi",
    ] * boundary
    parts += extended_cmds
    return "\n".join(parts) + "\n"


def _every_required() -> list[str]:
    """One command line per REQUIRED row, spelled the way the hook spells it."""
    cmds = []
    for r in REQUIRED:
        if r.needles[0] == "scripts/run-ci.sh":
            cmds.append(f"bash scripts/run-ci.sh {r.needles[1]}")
        elif r.needles[0].endswith(".py") and len(r.needles) == 2:
            cmds.append(f"python3 {r.needles[0]} --range x {r.needles[1]}")
        else:
            cmds.append(f"python3 {r.needles[0]}")
    return cmds


def selftest() -> int:
    failures: list[str] = []
    every = _every_required()
    moved = 1  # index of a row to push below the boundary; any row will do
    rows: list[tuple[str, str, int, str]] = [
        ("every required check above the boundary", _fixture_hook(every, []), 0, ""),
        (
            "the same checks, one command wrapped across lines by a backslash",
            _fixture_hook(
                [every[0], every[1] + " \\", "    --extra-flag", *every[2:]], []
            ),
            0,
            "",
        ),
        (
            "a check named only in the extended sweep: the 2026-10-09 shape",
            _fixture_hook(every[:moved] + every[moved + 1 :], [every[moved]]),
            1,
            "AFTER the policy boundary",
        ),
        (
            "a check absent from the hook altogether",
            _fixture_hook(every[:moved] + every[moved + 1 :], []),
            1,
            "not in the hook at all",
        ),
        (
            "a check present only as a comment above the boundary",
            _fixture_hook(["# " + every[moved], *every[:moved], *every[moved + 1 :]], []),
            1,
            "not in the hook at all",
        ),
        ("a hook with no policy boundary", "\n".join(every) + "\n", 1, "0 policy boundary"),
        (
            "a hook with two policy boundaries",
            _fixture_hook(every, [], boundary=2),
            1,
            "2 policy boundary",
        ),
        (
            "the count gate run in full on an ordinary push",
            _fixture_hook(
                [*every, "python3 scripts/lib/guarded_count_gate.py --range a..b"], []
            ),
            1,
            "without `--count-only`",
        ),
        (
            "the selection-only spelling no longer stands in for the cached verdict",
            _fixture_hook(
                [
                    *[c for c in every if "--cached-only" not in c],
                    "python3 scripts/lib/guarded_count_gate.py --range a..b --count-only",
                ],
                [],
            ),
            1,
            "not in the hook at all",
        ),
        (
            "the cached verdict spelled without the build-free flag but with --range only",
            _fixture_hook(
                [
                    *[c for c in every if "--cached-only" not in c],
                    "python3 scripts/lib/guarded_count_gate.py --range a..b",
                ],
                [],
            ),
            1,
            "without `--count-only` or `--cached-only`",
        ),
        (
            "a hint that only NAMES the count gate without a flag is not a run of it",
            _fixture_hook(
                [
                    *every,
                    'echo "measure now: python3 scripts/lib/guarded_count_gate.py '
                    '--range a..b"',
                ],
                [],
            ),
            0,
            "",
        ),
        (
            "an echo naming a required check does not stand in for running it",
            _fixture_hook(
                [
                    *every[:moved],
                    f'echo "run {every[moved]} some time"',
                    *every[moved + 1 :],
                ],
                [],
            ),
            1,
            "not in the hook at all",
        ),
        (
            "an echo piped into the count gate is code, and is read as code",
            _fixture_hook(
                [*every, 'echo x | python3 scripts/lib/guarded_count_gate.py --range a..b'],
                [],
            ),
            1,
            "without `--count-only` or `--cached-only`",
        ),
        (
            "the cached verdict with its exit status discarded, the old report shape",
            _fixture_hook(
                [
                    *[c for c in every if "--cached-only" not in c],
                    "python3 scripts/lib/guarded_count_gate.py --range a..b "
                    "--cached-only || true",
                ],
                [],
            ),
            1,
            "exit status discarded",
        ),
        (
            "a deferred check that has crept into the ordinary push",
            _fixture_hook([*every, "bash scripts/run-ci.sh --layer U"], []),
            1,
            "records it as deferred",
        ),
    ]
    for label, text, want_rc, want_msg in rows:
        got = grade(text)
        rc = 1 if got else 0
        if rc != want_rc:
            failures.append(f"{label}: expected rc={want_rc}, got {rc}: {got}")
        elif want_msg and not any(want_msg in g for g in got):
            failures.append(f"{label}: no finding says {want_msg!r}: {got}")

    # The rows above would all pass against a grader that checked nothing if
    # the real hook were not also held to the same table, so the selftest ends
    # on the population: every REQUIRED row must be spelled by SOMETHING the
    # fixture builder can produce, i.e. the table and `_every_required` agree.
    if len(every) != len(REQUIRED):
        failures.append("the fixture builder does not cover every REQUIRED row")

    for f in failures:
        print(f"hook-default-region: SELFTEST FAIL -- {f}", file=sys.stderr)
    if failures:
        return 1
    print(
        "hook-default-region: selftest passed -- a hook holding every row is green "
        "(also with a command wrapped by a backslash); a row only below the "
        "boundary, absent, or only in a comment is red and the first is named "
        "as the extended-only shape; no boundary and two boundaries are red; "
        "the count gate without --count-only/--cached-only, the cached verdict "
        "with its exit status discarded, the selection-only spelling standing in "
        "for the verdict, and a deferred check in the ordinary region are red; "
        "an echo naming a command neither satisfies nor trips a row"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return check(REPO_ROOT)


if __name__ == "__main__":
    sys.exit(main())

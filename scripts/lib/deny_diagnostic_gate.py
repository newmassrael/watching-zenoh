#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R2329 (no register item) — every host that BRANCHES on
`AdminAnswerOutcome::DeniedRead` must emit the deny diagnostic, and must emit
the one the library words.

The citation is `no register item` in the sense `debt_plane_census.py` uses: the
item this answers for -- unregistered open-debt item 13 -- lives in an
agent-memory register outside this repository, which has no store id for
`gate_provenance_lint.py` to resolve. The item is named in prose below.

## What item 13 said, and what re-measuring found

Item 13: "the deny LOG LINE is verified by no lane -- no lane captures host
stderr. `#[must_use] AdminAnswerOutcome` only forces the host to CONSUME the
outcome; that the line actually goes out is backed by reading four call sites,
and nothing else."

Re-measured, the premise HOLDS and the count is stale. Nothing in the tree
asserts the sentence -- `grep` for it finds only emit sites and one doc
comment, no test. And there are FIVE branching sites, not four: four in
`wz-ap-demo/src/runner.rs` and one in `wz-runtime-tokio/src/session/mod.rs`.
The population grew while the item aged, which is the ordinary way an item's
number goes stale here.

## What `#[must_use]` can and cannot do

It forces a host to LOOK at the outcome. It cannot force the host to say the
right thing, and until this round every host said it by hand: the same sentence
written out five times with no shared source. That is the copies-of-one-needle
hazard this workspace has already paid for once -- R2230 found one predicate
inlined four times, fixed two, and left a finder that found while a counter
counted zero.

It is worse here than a wording drift, because the sentence is ALSO what any
future witness would grep for. Five spellings mean a witness can match some
hosts and silently miss others, and one of the five already wrapped across a
line continuation, so a literal grep for the whole sentence did not find it at
all. R2329 hoisted the wording into
`wz_session_core::adminspace::denied_read_diagnostic`, and this gate is what
keeps it there.

## The derivation

THE POPULATION is every line that COMPARES against
`AdminAnswerOutcome::DeniedRead` -- `== …::DeniedRead`. That separates hosts
from the other two kinds structurally, with no file list: the library PRODUCES
the variant (`return AdminAnswerOutcome::DeniedRead;`, 2 sites) and its unit
tests ASSERT it (`assert_eq!(outcome, …)`, 2 sites). Only a host asks "was it
denied?" in order to do something about it. Measured today: 5 compare, 2
return, 2 assert, 3 declaration/doc mentions.

THE REQUIREMENT is that the branch this comparison drives calls
`denied_read_diagnostic`, found by walking the `if` body by brace balance from
the brace that opens it -- not by a fixed line window, which would pass a host
that emits far below or fail one with a long comment. The four demo sites carry
6-line comments between the comparison and the emit.

A population of ZERO is a HARD FAIL. So is the wording function going missing:
if `denied_read_diagnostic` is not defined, every host has necessarily gone
back to inlining, and a gate whose requirement cannot be satisfied must say so
rather than pass.

## What this does NOT claim, and it is exactly item 13's complaint

It checks that the code EMITS, not that the line reaches stderr. It is a lint
reading the same five call sites a person would read -- mechanically, so it
cannot drift and a sixth site is covered the day it lands, which is strictly
more than prose could do. It is NOT the runtime witness item 13 asked for: no
lane here captures the demo's stderr and greps for this sentence. That residue
is stated in the round's carry rather than papered over, and the hoisting above
is what would make such a witness cheap -- one needle, one spelling, one place
to change it.
"""

import argparse
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = pathlib.Path("crates")

# The wording's single source, and the call every host must make.
WORDING_FN = "denied_read_diagnostic"
WORDING_DEF = re.compile(rf"^\s*pub fn {WORDING_FN}\s*\(", re.M)

# A HOST site: it COMPARES, which is what a branch does. `return …::DeniedRead`
# (the producer) and `assert_eq!(…, …::DeniedRead)` (its tests) are excluded by
# construction rather than by naming their files.
COMPARE_RE = re.compile(r"==\s*(?:[A-Za-z0-9_:]*::)?AdminAnswerOutcome::DeniedRead")


def if_body(lines: list[str], start: int) -> tuple[str, int]:
    """The block opened at or after `start`, by brace balance. `("", start)` if none.

    Balanced from the first `{` at or after the comparison, so the six-line
    comments the demo sites carry between the condition and the `log::error!`
    are inside the body rather than beyond a line window.
    """
    depth = 0
    opened = False
    out: list[str] = []
    for i in range(start, min(len(lines), start + 400)):
        line = lines[i]
        out.append(line)
        for ch in line:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
        if opened and depth <= 0:
            return "\n".join(out), i + 1
    return "\n".join(out), start


def run(root: pathlib.Path) -> int:
    crates = root / CRATES
    if not crates.is_dir():
        raise SystemExit(f"deny-diagnostic: FAIL -- {CRATES} is missing")

    sources = sorted(crates.rglob("*.rs"))
    wording_defined = any(WORDING_DEF.search(p.read_text(errors="replace")) for p in sources)
    if not wording_defined:
        raise SystemExit(
            f"deny-diagnostic: FAIL -- no `pub fn {WORDING_FN}` anywhere under {CRATES}. "
            "That function is the ONE place the deny sentence is worded; without it every "
            "host has necessarily gone back to writing it by hand, which is the exact "
            "state R2329 removed. A requirement that cannot be satisfied must not pass."
        )

    sites = 0
    fail: list[str] = []
    for path in sources:
        text = path.read_text(errors="replace")
        if "DeniedRead" not in text:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if not COMPARE_RE.search(line):
                continue
            sites += 1
            body, _ = if_body(lines, i)
            if WORDING_FN not in body:
                rel = path.relative_to(root)
                fail.append(
                    f"  deny-diagnostic: SILENT   {rel}:{i + 1}\n"
                    f"    This host branches on `AdminAnswerOutcome::DeniedRead` and its "
                    f"branch never calls `{WORDING_FN}`.\n"
                    f"    `#[must_use]` made you LOOK at the outcome; it cannot make you "
                    f"say anything. A read gate that denies SILENTLY is the asymmetry the "
                    f"enum was introduced to remove — the write host has always logged.\n"
                    f"    Fix: `log::error!(\"{{}}\", "
                    f"wz_session_core::adminspace::{WORDING_FN}(view.keyexpr()))`. Do not "
                    f"re-inline the sentence: five hand-written copies is the state this "
                    f"gate exists to prevent, and a witness greps for ONE spelling."
                )

    if sites == 0:
        raise SystemExit(
            "deny-diagnostic: FAIL -- derived ZERO hosts branching on "
            "`AdminAnswerOutcome::DeniedRead`. A gate that found no subjects must not "
            "report a pass; either the comparison is spelled some way this reader does "
            "not match, or the admin read gate has lost its hosts."
        )

    print(f"  deny-diagnostic: {sites} host(s) branch on DeniedRead, each emitting via `{WORDING_FN}`")
    print(
        "  deny-diagnostic: NOT covered here -- that the line reaches stderr at runtime. "
        "This reads the call sites mechanically; no lane captures the demo's stderr and "
        "greps for the sentence, which is open-debt item 13's own residue"
    )
    if fail:
        print()
        for line in fail:
            print(line)
        return 1
    return 0


def selftest() -> int:
    """The three shapes, and both hard failures.

    The SILENT fixture is the pre-R2329 hazard in miniature: a host that
    consumes the outcome and says nothing. The producer/assert fixture is what
    keeps the population honest -- if those counted, the gate would demand a
    log line from the library and its own unit tests.
    """
    failures: list[str] = []

    def drive(files: dict[str, str]) -> int:
        with tempfile.TemporaryDirectory() as d:
            tmp = pathlib.Path(d)
            for rel, body in files.items():
                p = tmp / CRATES / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(body)
            try:
                return run(tmp)
            except SystemExit:
                return 2

    lib = f"pub fn {WORDING_FN}(keyexpr: &str) -> String {{ format!(\"{{keyexpr}}\") }}\n"

    good = {
        "a/src/lib.rs": lib,
        "b/src/host.rs": (
            "fn h() {\n"
            "    if answer(view) == AdminAnswerOutcome::DeniedRead {\n"
            "        // a comment between the branch and the emit, as the demo has\n"
            f"        log::error!(\"{{}}\", {WORDING_FN}(view.keyexpr()));\n"
            "    }\n"
            "}\n"
        ),
    }
    if drive(good) != 0:
        failures.append("a host that emits via the shared wording was reported as failing")

    silent = dict(good)
    silent["b/src/host.rs"] = (
        "fn h() {\n"
        "    if answer(view) == AdminAnswerOutcome::DeniedRead {\n"
        "        // consumed, and says nothing\n"
        "        return;\n"
        "    }\n"
        "}\n"
    )
    if drive(silent) != 1:
        failures.append("a host that branches and emits nothing was not caught")

    inlined = dict(good)
    inlined["b/src/host.rs"] = (
        "fn h() {\n"
        "    if answer(view) == AdminAnswerOutcome::DeniedRead {\n"
        "        log::error!(\"Received GET on '{}' but adminspace.permissions.read=false \"\n"
        "                    \"in configuration\", view.keyexpr());\n"
        "    }\n"
        "}\n"
    )
    if drive(inlined) != 1:
        failures.append("a host that re-inlined the sentence was accepted")

    # The producer and its tests must NOT be counted as hosts: a fixture with
    # only those has a population of zero and must hard-fail rather than pass.
    producer_only = {
        "a/src/lib.rs": lib
        + (
            "fn produce() -> AdminAnswerOutcome {\n"
            "    return AdminAnswerOutcome::DeniedRead;\n"
            "}\n"
            "#[test]\n"
            "fn t() { assert_eq!(outcome, AdminAnswerOutcome::DeniedRead); }\n"
        ),
    }
    if drive(producer_only) != 2:
        failures.append("returns and asserts were counted as hosts, or zero hosts did not fail")

    # The wording function going missing is a hard failure, not a pass.
    if drive({"b/src/host.rs": good["b/src/host.rs"]}) != 2:
        failures.append("a tree with no wording function did not hard-fail")

    if failures:
        print("  deny-diagnostic: SELFTEST FAILED")
        for f in failures:
            print(f"    - {f}")
        return 1
    print(
        "  deny-diagnostic: selftest passed "
        "(silent host, re-inlined host, 2 hard failures, 1 clean)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="deny_diagnostic_gate.py",
        description=(
            "Every host branching on AdminAnswerOutcome::DeniedRead must emit the deny "
            "diagnostic, through the one function that words it."
        ),
    )
    ap.add_argument("--check", action="store_true", help="read the real tree (default)")
    ap.add_argument("--selftest", action="store_true", help="drive the shapes against fixtures")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y750 (N40, N41) — the SELF-REPORT gate.

## The class

A comment saying "this is not built yet" is an unfiled defect report. It is
written by the person best placed to know, at the moment they know it, and then
it is counted by nobody: no register entry, no gate, no round. The workspace has
paid for that repeatedly -- R311y565 built `expired_blocker_lint.py` after EIGHT
such comments outlived their own blockers, and that lint watches three C-ABI
crates for one narrow phrasing family. Nothing watched the rest of the tree, and
nothing watched for a NEW one arriving.

Carry N40 named the gap ("the self-report sweep has no gate"). Carry N41 named
the reason a sweep alone would not close it: the sweep's VOCABULARY was three
phrases somebody guessed (`not built` / `nothing plumbs` / `for now`), and
`deferred` / `follow-up` / `left for later` had never been searched at all.

## The vocabulary is MEASURED, and the measurement is the interesting part

Swept over 676 crate source and test files at R311y750, counting COMMENT lines
only. The guessed vocabulary matched 24 lines. The unsearched candidates matched
far more -- and almost all of it is ordinary design prose, which is the finding:

    deferred 458   follow-up 107   not yet 91   stub 49   placeholder 43
    dead code 34   future round 32  no caller 24  no consumer 18
    later round 17  followup 14   never called 11  once we 3  temporarily 1

`deferred` at 458 is not 458 unfiled defects. It is `deferred-fire drain site`,
`deferred crypto handshake`, `a deferred responder` -- mechanism names. Gating on
raw vocabulary would have produced a gate that is 99% noise and would have been
switched off, which is the failure mode a guessed vocabulary hides: the guess
looked clean only because it was narrow.

So the vocabulary is split into two tiers, and BOTH are carried here on purpose:

  * [`STRONG`][] — phrasings that assert THIS TREE does not do something. Gated.
  * [`CENSUS`][] — the rest. Counted and PRINTED on every run, never gated. They
    are here so the next round inherits the measurement instead of re-guessing,
    and so a phrase that starts trending is visible before it is a class.

## What is gated, exactly

A finding is a CONJUNCTION, as in `expired_blocker_lint.py`:

  1. a contiguous COMMENT BLOCK contains a [`STRONG`][] phrase; and
  2. that block names no tracker -- no `R<round>`, no `debt-<id>`, no
     `carry N<k>`, no `§<n>`.

Both halves are needed. Self-reports are legitimate and common in this tree; 34
of the 46 strong-signal blocks at authoring time already cite the round or item
that owns them, and those are exactly the ones that are NOT a problem. The defect
is the untracked one.

## The baseline, and why it is counts rather than a flag

[`BASELINE`][] carries the sites that predate the rule, keyed `path::phrase` with
a COUNT. A count rather than a membership flag because a file already carrying
one grandfathered `HACK` would otherwise absorb a second one silently. Checked in
BOTH directions: a baseline entry whose count DROPS reds asking to shrink it, so
the carry can only get smaller, and a stale entry naming a file that no longer
fires reds too.

Reading the baseline is worthwhile: eleven of the twelve grandfathered sites are
not self-reports at all -- a deliberate `Sync` omission, two feature-gating
statements, zenoh's own "Quick hack" quoted back, a rationale HEADING ("Why this
is NOT built on the query plane"). That ratio is the honest scope of the class in
this tree, and it is why this gate is a tripwire for what ARRIVES rather than a
cleanup list.

Exit 0 with the census when clean; exit 1 listing every finding otherwise.
"""

from __future__ import annotations

import pathlib
import re
import sys

# ── the two vocabulary tiers ──────────────────────────────────────────────
#
# `token` phrases match case-sensitively on a word boundary: `HACK` is a marker,
# `hacked` is a verb, and a substring match cannot tell them apart. `prose`
# phrases match case-insensitively as substrings, because a sentence chooses its
# own capitalisation and punctuation.
STRONG: list[tuple[str, str]] = [
    ("not built", "prose"),
    ("not wired", "prose"),
    ("nothing plumbs", "prose"),
    ("no production caller", "prose"),
    ("not implemented", "prose"),
    ("left for later", "prose"),
    ("for now", "prose"),
    ("TODO", "token"),
    ("FIXME", "token"),
    ("XXX", "token"),
    ("HACK", "token"),
]

# Counted, printed, never gated. See the module docstring for why.
CENSUS: list[tuple[str, str]] = [
    ("deferred", "prose"),
    ("follow-up", "prose"),
    ("followup", "prose"),
    ("not yet", "prose"),
    ("stub", "prose"),
    ("placeholder", "prose"),
    ("dead code", "prose"),
    ("future round", "prose"),
    ("no caller", "prose"),
    ("no consumer", "prose"),
    ("later round", "prose"),
    ("never called", "prose"),
    ("once we", "prose"),
    ("temporarily", "prose"),
]

# A block "names a tracker" when it points at something that can be looked up:
# a round in the atomic changelog, a `debt-*` inventory id, a carry item, or a
# section. Deliberately permissive about the shape of a round citation -- the
# citation GATE (`validate-workspace`, Round 783) is what checks that a cited
# round resolves; this one only asks whether the sentence points anywhere.
TRACKER = re.compile(r"R\d+[a-z]*\d*|debt-[a-z0-9-]+|carry N\d+|§")

COMMENT = re.compile(r"^\s*(//!|///|//|\*/|\*|/\*)")

# Sites that predate the rule: `path::phrase` -> count. See the docstring.
BASELINE: dict[str, int] = {
    "crates/wz-capi-c/src/ffi.rs::not implemented": 1,
    "crates/wz-integration-tests/tests/pubkey_zenohd_interop.rs::TODO": 1,
    "crates/wz-runtime-tokio/src/accept_loop.rs::not wired": 3,
    "crates/wz-runtime-tokio/src/lib.rs::not built": 1,
    "crates/wz-runtime-tokio/src/link_interfaces.rs::not built": 1,
    "crates/wz-session-core/src/declare/liveliness_get.rs::not built": 1,
}
# NOT baselined, and worth saying why: the first pass carried three `HACK`
# entries, all of them from `hack` inside ordinary prose -- zenoh's own "Quick
# hack" quoted back, and a `Send` hack naming a known pattern. Matching the
# marker case-sensitively on a word boundary removed all three, which is the
# reason `HACK` / `TODO` / `FIXME` / `XXX` are `token` rather than `prose`.


def sources(root: pathlib.Path) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for pattern in ("crates/*/src/**/*.rs", "crates/*/tests/**/*.rs"):
        for p in sorted(root.glob(pattern)):
            if "target" in p.parts:
                continue
            out.append(p)
    return out


def matcher(phrase: str, mode: str):
    if mode == "token":
        rx = re.compile(rf"\b{re.escape(phrase)}\b")
        return lambda text: bool(rx.search(text))
    low = phrase.lower()
    return lambda text: low in text.lower()


def blocks(lines: list[str]) -> list[tuple[int, list[str]]]:
    """Contiguous runs of comment lines, as (1-based start line, lines)."""
    out: list[tuple[int, list[str]]] = []
    cur: list[str] = []
    start = 0
    for i, line in enumerate(lines, 1):
        if COMMENT.match(line):
            if not cur:
                start = i
            cur.append(line)
        elif cur:
            out.append((start, cur))
            cur = []
    if cur:
        out.append((start, cur))
    return out


def main() -> int:
    root = pathlib.Path(".")
    files = sources(root)
    if not files:
        print(
            "self-report gate FAIL: no crate sources matched; the population "
            "pattern has drifted or this ran from the wrong cwd",
            file=sys.stderr,
        )
        return 1

    strong_m = [(p, matcher(p, m)) for p, m in STRONG]
    census_m = [(p, matcher(p, m)) for p, m in CENSUS]

    census_counts: dict[str, int] = {p: 0 for p, _ in CENSUS}
    strong_counts: dict[str, int] = {p: 0 for p, _ in STRONG}
    cited_blocks = 0
    findings: list[str] = []
    fired: dict[str, int] = {}

    for path in files:
        try:
            lines = path.read_text().splitlines()
        except OSError as exc:  # unreadable input is a FAIL, never a skip
            print(f"self-report gate FAIL: {path}: {exc}", file=sys.stderr)
            return 1
        rel = path.as_posix()
        for start, block in blocks(lines):
            text = "\n".join(block)
            for phrase, hit in census_m:
                if hit(text):
                    census_counts[phrase] += 1
            hits = [phrase for phrase, hit in strong_m if hit(text)]
            if not hits:
                continue
            for phrase in hits:
                strong_counts[phrase] += 1
            if TRACKER.search(text):
                cited_blocks += len(hits)
                continue
            for phrase in hits:
                key = f"{rel}::{phrase}"
                fired[key] = fired.get(key, 0) + 1
                if fired[key] > BASELINE.get(key, 0):
                    findings.append(
                        f"{rel}:{start}: comment block asserts `{phrase}` and "
                        f"names no tracker (no R<round> / debt-<id> / carry N<k> "
                        f"/ §<n>)"
                    )

    # ANTI-VACUITY, on the set rather than per phrase. A single phrase falling to
    # zero is progress; the WHOLE strong set falling to zero means the matcher or
    # the population broke and the gate is asserting nothing.
    total_strong = sum(strong_counts.values())
    if total_strong == 0:
        print(
            "self-report gate FAIL: the strong vocabulary matched NOTHING in "
            f"{len(files)} file(s). A gate that finds nothing to judge is not "
            "clean, it is broken -- check COMMENT / the phrase modes.",
            file=sys.stderr,
        )
        return 1

    # The baseline can only shrink, so a site that stopped firing must leave it.
    for key, carried in sorted(BASELINE.items()):
        now = fired.get(key, 0)
        if now < carried:
            findings.append(
                f"{key}: BASELINE carries {carried} but {now} fire(s) now -- "
                f"lower or drop the entry in this file so the carry can only "
                f"shrink"
            )

    if findings:
        print("Layer C0 FAIL: untracked self-report(s):", file=sys.stderr)
        for f in sorted(findings):
            print(f"    - {f}", file=sys.stderr)
        print("", file=sys.stderr)
        print(
            "  A comment declaring work undone is a defect report nobody filed.",
            file=sys.stderr,
        )
        print(
            "  Name the round, the `debt-*` id or the carry item that owns it,",
            file=sys.stderr,
        )
        print("  or finish the work and delete the sentence.", file=sys.stderr)
        return 1

    carried = sum(BASELINE.values())
    print(
        f"  self-report gate: {len(files)} file(s), {total_strong} strong-signal "
        f"block-hit(s), {cited_blocks} tracked, {carried} carried in BASELINE, "
        f"0 untracked"
    )
    print(
        "    strong: "
        + " ".join(f"{p}={n}" for p, n in sorted(strong_counts.items()) if n)
    )
    print(
        "    census (measured, NOT gated): "
        + " ".join(f"{p}={n}" for p, n in sorted(census_counts.items()) if n)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

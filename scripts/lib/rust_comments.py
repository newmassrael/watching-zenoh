#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2131 (no register item) — one place that knows a Rust comment is not data.

The citation is `no register item` for the reason `debt_plane_census.py` gives
for its own: the item this serves -- unregistered open-debt item 402 -- lives in
the agent-memory register, which has no store id for `gate_provenance_lint.py`
to resolve.

## The defect this exists for, three times in the same shape

A sweep reads Rust source looking for a literal, an attribute or an identifier,
and finds one inside a COMMENT. Item 402 is the ledger of it:

  * R2083, `deepenable_audit.py`: five quoted phrases inside `//` rationales
    between a constant's entries were counted as entries. `HONOURED_CONFIG_KEYS`
    read 35 where it has 30, and that wrong number reached this project's own
    notes and a round's ledger before anyone noticed. That script now strips,
    and this module is where its stripping moved so the next sweep inherits it.
  * MEASURED THIS ROUND, `count_guard_lint.py`: a doc comment carrying
    `#[test] #[ignore]` on one line -- the shape a file uses to SHOW the
    attribute it is about -- makes the lint report the guarded file as having
    one more test than it has, and accuse `run-ci.sh` of a stale number. The
    accusation is false in both halves it offers.
  * MEASURED THIS ROUND, `analysis_surface_parity.py`: R2130's claim resolver
    accepted a token that occurs only inside a comment, so a reason could name
    something that exists nowhere but prose and still resolve. The round that
    built that resolver introduced this instance, which is why it is repaid
    here rather than filed.

## Why over-inclusion is NOT uniformly safe

Item 402 records the belief that over-collecting is the safe direction, and for
`dissect_name_census.py` it is: a literal wrongly claimed must be DECLARED, and
declaring one costs a line. That census counts a comment's literals on purpose
and its failure message says so at the point of failure.

It was not safe in the other three. A count that is too high is a wrong number
published as a measurement; a claim that resolves against prose is a check that
passes on nothing. Every FLOOR is structurally blind to this direction -- too
many always clears a minimum -- so the only thing that catches it is stripping.

## What this deliberately does not do

It is not a Rust lexer. It removes `/* ... */` spans and everything from a `//`
to the end of its line, and it does NOT try to tell a `//` inside a string
literal from a real comment. A sweep that must be exact about string contents
should not be using this; the sweeps that use it are looking for attributes,
identifiers and quoted names, none of which occur after a URL on the same line.
The limit is written here rather than discovered later.
"""

from __future__ import annotations

import re

_BLOCK = re.compile(r"/\*.*?\*/", re.S)


def strip_comments(text: str) -> str:
    """`text` with comment bodies blanked, and every line still in place.

    Lines are PRESERVED, not deleted: callers report `file:line`, and a stripper
    that dropped lines would move every number it reports afterwards. What is
    removed is replaced by nothing, so the line survives and its content does
    not.
    """
    text = _BLOCK.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    out = []
    for line in text.split("\n"):
        cut = line.find("//")
        out.append(line if cut < 0 else line[:cut])
    return "\n".join(out)


def selftest() -> int:
    cases: list[tuple[str, str, str]] = [
        ("line comment", "let a = 1; // #[test]\n", "#[test]"),
        ("doc comment", "//! #[test] #[ignore]\nfn real() {}\n", "#[test]"),
        ("triple slash", "/// `wz_probe_name`\n", "wz_probe_name"),
        ("block comment", "/* fn hidden() { \"key\" } */\nfn real() {}\n", "hidden"),
    ]
    bad = []
    for name, src, needle in cases:
        stripped = strip_comments(src)
        if needle in stripped:
            bad.append(f"{name}: `{needle}` survived stripping")
        # LINE COUNT IS PART OF THE CONTRACT: a caller reporting file:line must
        # get the same line numbers before and after.
        if stripped.count("\n") != src.count("\n"):
            bad.append(f"{name}: stripping moved the line numbering")
    # THE CONTROL, in the same selftest: code must SURVIVE. Without this every
    # assertion above is satisfied by a function that returns the empty string.
    keep = strip_comments("fn real() {}\n// gone\n")
    if "fn real() {}" not in keep:
        bad.append("control: stripping removed code, not just comments")
    if "gone" in keep:
        bad.append("control: a whole-line comment survived")
    for line in bad:
        print(f"  rust-comments FAIL -- {line}")
    if bad:
        return 1
    print(f"  rust-comments: selftest ok ({len(cases)} case(s) plus the control)")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())

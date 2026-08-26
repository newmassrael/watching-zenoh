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

## R2137 (unregistered open-debt item 126) — WHY THIS IS A SCANNER NOW

The first cut was two regexes: blank every `/* ... */` span, then cut each line
at its first `//`. It ran the BLOCK pass first, over text in which line comments
and string literals were still present, and a `/*` is two characters that occur
constantly in this tree for reasons that have nothing to do with comments:

    //! ... `<ke>/@adv/pub/**` was refused by wz's R300 gate ...
    ("a/b", "a/*"),
    r#" /* block comment */ "#          <- json5.rs's own parser fixture

Each of those opens a span that runs to the next `*/` — which arrives hundreds
of lines later inside `demo/example/**/@adv/pub/**`, taking every line between
with it. MEASURED 2026-08-26 over `crates/**/*.rs`: **48 of 752 files** had a
line of ordinary code blanked this way, and the damage is silent because the
line SURVIVES (blank), so the line numbering the callers report stays right
while the content they read is gone.

That is the direction this module exists to refuse. `count_guard_lint.py` read
`wz_advanced_pubsub_zenoh_ext_interop.rs` as having 3 `#[ignore]`d tests where
it has 13, and would have accused `run-ci.sh:12658` of a stale guard whose
number is correct. Over-stripping and over-counting fail the same way: a wrong
number published as a measurement.

So the pass is now a single left-to-right scan that knows which construct it is
inside. `//` wins over `/*` when both start at the same place, a string literal
is data rather than a comment, and a raw string has no escapes at all.

## What this deliberately does not do

It is not a full Rust lexer, and two limits are worth naming. It does not
resolve `cfg`, `include!` or macro expansion — what it returns is the text as
written. And it decides `'` by shape: `'\n'` and `'"'` are character literals,
`'a` and `'static` are lifetimes. A construct that is neither would be read as
a lifetime, which leaves the following text scanned as ordinary code — the
conservative direction here, since it strips less rather than more.
"""

from __future__ import annotations

import re

_IDENT_CHAR = re.compile(r"[A-Za-z0-9_]")


def _raw_string_open(text: str, i: int) -> tuple[int, str] | None:
    """`(body_start, terminator)` if a raw string opens at `i`, else None.

    `r"..."`, `r#"..."#`, `br##"..."##` — the hash count is part of the
    terminator, which is the whole point of the form: a raw string may contain
    its own quote character, so nothing but the matching `"###` closes it.
    """
    j = i
    if text[j] == "b":
        j += 1
    if j >= len(text) or text[j] != "r":
        return None
    j += 1
    hashes = 0
    while j < len(text) and text[j] == "#":
        hashes += 1
        j += 1
    if j >= len(text) or text[j] != '"':
        return None
    return j + 1, '"' + "#" * hashes


def _at_token_start(text: str, i: int) -> bool:
    """True when `i` begins a token — a prefix letter is only a string prefix
    there. Without this, the `r` at the end of `for` or `iter` would be read as
    a raw-string opener whenever a quote happened to follow."""
    return i == 0 or not _IDENT_CHAR.match(text[i - 1])


def strip_comments(text: str) -> str:
    """`text` with comment bodies blanked, and every line still in place.

    Lines are PRESERVED, not deleted: callers report `file:line`, and a stripper
    that dropped lines would move every number it reports afterwards. What is
    removed is replaced by nothing, so the line survives and its content does
    not.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]

        # A line comment wins whenever it starts here: `//*` is a line comment,
        # not a block one, and the old two-pass order got exactly this wrong.
        if c == "/" and text.startswith("//", i):
            nl = text.find("\n", i)
            i = n if nl < 0 else nl  # the newline itself is emitted below
            continue

        # Block comments NEST in Rust: `/* /* */ */` is one comment.
        if c == "/" and text.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    if text[i] == "\n":
                        out.append("\n")
                    i += 1
            continue

        # A raw string has NO escapes, so only its own terminator ends it.
        if c in "br" and _at_token_start(text, i):
            opened = _raw_string_open(text, i)
            if opened:
                body, term = opened
                end = text.find(term, body)
                end = n if end < 0 else end + len(term)
                out.append(text[i:end])
                i = end
                continue

        # An ordinary (or byte) string: a `b` prefix needs no case of its own,
        # it is emitted as the plain character it is and the quote lands here.
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                if text[i] == "\\":
                    out.append(text[i : i + 2])
                    i += 2
                    continue
                out.append(text[i])
                i += 1
                if text[i - 1] == '"':
                    break
            continue

        # `'` is a character literal or a lifetime, decided by shape. Only the
        # literal can carry a quote (`'"'`) or a backslash, and reading one as a
        # lifetime would leave that quote to open a string that never closes.
        if c == "'":
            escaped = i + 1 < n and text[i + 1] == "\\"
            single = i + 2 < n and text[i + 2] == "'"
            if escaped or single:
                j = i + 1
                while j < n:
                    if text[j] == "\\":
                        j += 2
                        continue
                    if text[j] == "'":
                        j += 1
                        break
                    j += 1
                out.append(text[i:j])
                i = j
                continue

        out.append(c)
        i += 1
    return "".join(out)


def selftest() -> int:
    cases: list[tuple[str, str, str]] = [
        ("line comment", "let a = 1; // #[test]\n", "#[test]"),
        ("doc comment", "//! #[test] #[ignore]\nfn real() {}\n", "#[test]"),
        ("triple slash", "/// `wz_probe_name`\n", "wz_probe_name"),
        ("block comment", "/* fn hidden() { \"key\" } */\nfn real() {}\n", "hidden"),
        # Rust nests block comments; a non-greedy `/\*.*?\*/` closes at the
        # first `*/` and leaves the outer comment's tail as live text.
        ("nested block comment", "/* outer /* inner */ still_inside */\n", "still_inside"),
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

    # R2137 — the SURVIVAL cases: a `/*` that is not a comment opener must not
    # blank the code that follows it. Every fixture is a real shape from this
    # tree, and every one is built so the NEEDLE SITS INSIDE the span the old
    # two-pass stripper would have taken.
    #
    # That last clause is the whole design, and the first draft of these cases
    # got it wrong: each fixture happened to close its own phantom span before
    # the needle, so all six passed against the old implementation as well and
    # would have been born green. MEASURED both ways — the three below now fail
    # on the old stripper (0 -> 3) and pass on this one.
    survives: list[tuple[str, str, str]] = [
        (
            "`/*` inside a line comment",
            "//! a `<ke>/@adv/pub/**` note\n"
            "fn real() {}\n"
            "//! and `**/@adv` closes it\n",
            "fn real() {}",
        ),
        (
            "`/*` inside a string literal",
            'let k = ("a/b", "a/*");\n'
            "fn real() {}\n"
            'let j = ("**/x", "y");\n',
            "fn real() {}",
        ),
        (
            "a comment shape inside a raw string",
            'let s = r#"/* opened"#;\n'
            "fn real() {}\n"
            'let t = r#"*/ closed"#;\n',
            "fn real() {}",
        ),
    ]
    for name, src, needle in survives:
        stripped = strip_comments(src)
        if needle in stripped:
            continue
        bad.append(f"{name}: `{needle}` was blanked by a phantom comment span")

    # The other half of the raw-string case: what a raw string HOLDS is data, so
    # it survives too. Without this, the case above is satisfied by a stripper
    # that blanks raw-string bodies.
    if "not a comment" not in strip_comments('let s = r#"// not a comment"#;\n'):
        bad.append("raw string: its own body was stripped as a comment")
    # And a raw string must not swallow the rest of the file: `"#` closes it.
    if "fn real" not in strip_comments('let s = r#""#;\nfn real() {}\n'):
        bad.append("raw string: the terminator was not honoured")

    # The two `'` decisions, each written as "what must be GONE", because that
    # is the direction a misread shows up in: reading `'"'` as a lifetime opens
    # a string that runs on and hides a real comment inside it, and reading a
    # lifetime as a character literal consumes code as literal text.
    if "hidden by a quote" in strip_comments(
        "let q = '\"';\n// hidden by a quote\nlet r = \"x\";\n"
    ):
        bad.append("char literal: `'\"'` was read as a lifetime plus a string")
    if "hidden by a lifetime" in strip_comments(
        "fn f<'a>(y: &'a str) -> &'a str {\n    // hidden by a lifetime\n    y\n}\n"
    ):
        bad.append("lifetime: `'a` was read as a character literal")
    for line in bad:
        print(f"  rust-comments FAIL -- {line}")
    if bad:
        return 1
    print(
        f"  rust-comments: selftest ok ({len(cases)} stripping case(s), "
        f"{len(survives)} survival case(s), plus the controls)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())

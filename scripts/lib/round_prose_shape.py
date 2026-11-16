#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4502 (no register item) -- a ledger bullet file holds one bullet per line,
and a hard-wrapped paragraph is refused before it freezes.

The item this answers, open-debt item 182, lives in the agent-memory half of
the register, which has no store id for `gate_provenance_lint.py` to resolve;
it is named in prose instead.

## The defect

`mnemosyne-cli append-changelog-entry` reads `--changes-file`,
`--verification-file` and `--carry-file` as ONE BULLET PER NON-EMPTY LINE
(`parse_bullets_file`: each line trimmed, a leading `- ` dropped). A paragraph
wrapped at a column therefore becomes a bullet per physical line. One round
went in that way with 43, 56 and 27 bullets where its neighbours had 2 to 6:
every word was there and the structure was gone, and the ledger is frozen, so
the only correction is another entry. `scripts/append-round.sh` checked the
impact ids and nothing about the bullets.

## What is refused

A line that CONTINUES the one before it rather than starting a bullet:

* an indented line that does not itself open with `- ` (the hanging indent of
  a wrapped list item), or
* a line opening with a lower-case letter after a line that ends without
  closing punctuation (`.`, `:`, `;`, `!`, `?`, a closing bracket or quote, a
  backtick): the shape of a sentence broken at a column.

A bullet that legitimately opens lower-case after an unterminated bullet is
refused too; ending the previous bullet with a full stop answers it. The
decision file is prose and is not read here.
"""

from __future__ import annotations

import sys

#: What a complete bullet ends with.
CLOSERS = tuple(".:;!?)]}\"'`")


def continuations(text: str) -> list[tuple[int, str]]:
    """`(line number, why)` for each line that continues the previous one."""
    found: list[tuple[int, str]] = []
    previous = ""
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip():
            continue
        body = line.lstrip()
        if line != body and not body.startswith("- "):
            found.append((number, "an indented line that opens no bullet"))
        elif previous and body[:1].islower() and not previous.endswith(CLOSERS):
            found.append((number, "a lower-case line after a line with no closing punctuation"))
        previous = body
    return found


def selftest() -> None:
    clean = [
        "QUIC: per-class frame budget on the link driver.\nRuntime: Close deletes the transport.\n",
        "- first bullet\n- second bullet\n",
        "Open: interest ids (818); route_push stamping (741)\nThe register is updated after this lands.\n",
        "One bullet ending in a `symbol`\nwz-capi-c: a crate named lower-case after a closed line.\n",
        "\n\nA bullet after blank lines.\n",
    ]
    wrapped = [
        ("The gate reads every line of the file and\nrefuses the ones that continue a sentence.\n", [2]),
        ("- a list item whose text\n  hangs under the dash\n", [2]),
        ("Changes in this round\nwere many and\nwrapped at a column.\n", [2, 3]),
    ]
    for text in clean:
        assert continuations(text) == [], f"selftest: refused {text!r}: {continuations(text)}"
    for text, lines in wrapped:
        got = [n for n, _ in continuations(text)]
        assert got == lines, f"selftest: {text!r} gave {got}, want {lines}"


def main() -> int:
    args = sys.argv[1:]
    if args == ["--selftest"]:
        selftest()
        print("round-prose-shape: selftest ok")
        return 0
    if not args or args[0] != "--bullets":
        print("usage: round_prose_shape.py --bullets FILE... | --selftest", file=sys.stderr)
        return 2
    selftest()
    findings: list[str] = []
    for path in args[1:]:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        for number, why in continuations(text):
            findings.append(f"{path}:{number}: {why}")
    if findings:
        print("round-prose-shape: FAIL -- a bullet file is hard-wrapped; each line becomes a bullet:", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print("  Write one bullet per line, unwrapped, and end each with its punctuation.", file=sys.stderr)
        return 1
    print(f"  round-prose-shape: {len(args) - 1} bullet file(s), one bullet per line")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R311y919 (no register item) — how many ANALYZER-PLANE debts are still open,
as a number a command produces rather than one a session remembers.

It closes no register item on purpose: it is the INSTRUMENT a repayment loop
measures itself with, not the repayment of anything. The debt it does surface is
its own -- item 454, that this input lives outside the repository.

## Why this exists

The analyzer's open debts live in an agent-memory register outside this
repository, and until this round the only way to answer "how many are left" was
to read it and judge. That was done twice in one session and gave two different
answers -- 25 by a keyword sweep and 73 by reading all 380 open items -- because
the register is written in Korean and names CONCEPTS ("the interest plane", "the
verdict", "the report") that share no token with any crate name. Open-debt item
190 had already recorded that a keyword sweep is structurally a FLOOR; this is
its third demonstration.

So the judgement is made once, written into the register as a ROSTER, and this
script is what reads it back. A repayment loop needs a completion condition it
cannot talk itself out of, and a number one command prints is that.

## What it checks, and why each direction matters

1. Every rostered number EXISTS in the register. A roster naming an item that
   was renumbered away is a roster that has stopped pointing at anything.
2. Every rostered number is OPEN. A closed item still on the roster inflates the
   remaining count, which is the direction that makes a loop run forever.
3. No open item's number exceeds `swept_through`. This is the ratchet: a debt
   filed after the sweep arrives UNJUDGED, and without this the roster goes
   quietly stale the moment the next round files a residue -- which every round
   in this series does.
4. The roster's two classes are disjoint, and the owner-decision class is
   reported separately rather than folded into the target. An item whose own
   text says "nobody has decided whether to" is not work a loop can finish, and
   counting it would make the completion condition unreachable.

## What it deliberately does NOT do

It does not judge. Nothing here decides whether an item is analyzer-plane -- the
roster is a human judgement recorded in the register, and a script that
re-derived it from keywords would reintroduce exactly the floor this file
exists to replace.

## Why it is NOT wired into a CI layer

Its input is machine-local: the register lives in the agent-memory directory,
which no clone and no CI runner has. A gate whose input is absent must FAIL
rather than skip -- "a population of zero is green" is this workspace's most
expensive recurring defect -- so wiring it into a hosted layer would make every
CI run red. It therefore exits 2 (not 0) when the register is unreadable, and
lives as a LOCAL tool until the roster moves into the store, which is where
`debt-carry-N48` already says debt items belong. That move is open-debt item
454.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys

DEFAULT_REGISTER = (
    pathlib.Path.home()
    / ".claude"
    / "projects"
    / "-home-coin-watching-zenoh"
    / "memory"
    / "project_open_debt_unregistered.md"
)

BEGIN = "<!-- ANALYZER-ROSTER-BEGIN -->"
END = "<!-- ANALYZER-ROSTER-END -->"

# The register numbers items in THREE shapes and a reader that knows only one
# reports dozens of items as absent. Both forms, always -- see the register's
# own "이 파일을 기계로 셀 때" section, and open-debt item 295.
ITEM_FORMS = (
    re.compile(r"^-\s*\*\*\s*(?:[^\w\s]+\s*)*(\d{1,3})\.\s", re.M),
    re.compile(r"^(\d{1,3})\.\s", re.M),
)


def register_path() -> pathlib.Path:
    """The register, overridable so a damage probe can point at a fixture."""
    override = os.environ.get("WZ_DEBT_REGISTER")
    return pathlib.Path(override) if override else DEFAULT_REGISTER


def items(text: str) -> dict[int, str]:
    """Every item's number mapped to its TITLE LINE.

    The title carries the closed marker, so open/closed is read from the same
    line the number is on rather than from a window that could reach the next
    item's.
    """
    found: dict[int, str] = {}
    for form in ITEM_FORMS:
        for m in form.finditer(text):
            line_end = text.find("\n", m.start())
            line = text[m.start() : line_end if line_end >= 0 else len(text)]
            found[int(m.group(1))] = line
    return found


def is_open(title: str) -> bool:
    return "✅" not in title and "CLOSED" not in title


def roster(text: str) -> tuple[set[int], set[int], int]:
    """The rostered target set, the owner-decision set, and `swept_through`."""
    try:
        block = text.split(BEGIN, 1)[1].split(END, 1)[0]
    except IndexError:
        raise SystemExit(
            f"debt-plane-census: FAIL -- no {BEGIN} block in the register. "
            f"The roster IS the denominator; without it this script would "
            f"report zero remaining, which reads exactly like done."
        )
    target: set[int] = set()
    owner: set[int] = set()
    swept: int | None = None
    for line in block.splitlines():
        line = line.strip()
        if line.startswith("plane:analyzer-owner-decision"):
            owner |= {int(n) for n in re.findall(r"\d{1,3}", line.split("=", 1)[1])}
        elif line.startswith("plane:analyzer"):
            target |= {int(n) for n in re.findall(r"\d{1,3}", line.split("=", 1)[1])}
        elif line.startswith("swept_through"):
            swept = int(line.split("=", 1)[1].strip())
    if swept is None:
        raise SystemExit("debt-plane-census: FAIL -- the roster names no `swept_through`")
    return target, owner, swept


def main() -> int:
    path = register_path()
    if not path.is_file():
        # EXIT 2, never 0. The register is machine-local, and a reader that
        # cannot see its input must not report a clean count -- see the module
        # doc's last section.
        print(
            f"debt-plane-census: UNREADABLE -- {path} is absent. This tool reads "
            f"an agent-memory register that no clone carries; it is local-only "
            f"until open-debt item 454 moves the roster into the store.",
            file=sys.stderr,
        )
        return 2
    text = path.read_text(encoding="utf-8")
    found = items(text)
    target, owner, swept = roster(text)

    findings: list[str] = []
    for n in sorted(target | owner):
        if n not in found:
            findings.append(f"the roster names item {n} and the register has no such item")
    for n in sorted(target | owner):
        if n in found and not is_open(found[n]):
            findings.append(
                f"item {n} is CLOSED and still on the roster -- a closed item left "
                f"here inflates the remaining count, which is the direction that "
                f"makes a repayment loop never finish"
            )
    both = target & owner
    if both:
        findings.append(
            f"item(s) {sorted(both)} are in BOTH classes; the owner-decision set is "
            f"the target's complement, not a label on top of it"
        )
    unjudged = sorted(n for n, t in found.items() if is_open(t) and n > swept)
    if unjudged:
        findings.append(
            f"open item(s) {unjudged} are numbered past `swept_through = {swept}`, so "
            f"nothing has judged whether they are analyzer-plane. Judge them and move "
            f"the marker in the same edit"
        )

    if findings:
        print("debt-plane-census: FAIL")
        for f in findings:
            print(f"  - {f}")
        print("\n  Edit the ANALYZER-ROSTER block in the register in the same round.")
        return 1

    remaining = sorted(n for n in target if n in found and is_open(found[n]))
    print(
        f"  debt-plane-census: analyzer open = {len(remaining)} "
        f"({len(owner)} held for an owner decision, swept through {swept})"
    )
    if remaining:
        print(f"  remaining: {' '.join(str(n) for n in remaining)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

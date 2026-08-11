#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R311y717 (§C G5) — every site that DISCARDS captured evidence must account for it.

## The defect this closes

R311y713 made the flow table's exit an obligation a TYPE enforces: `FlowTable`
has no `remove`, its only door hands back a `#[must_use] Exiting` that panics if
dropped unconsumed, and the carry counters are module-private so a caller has
nowhere to write a partial accounting. That closed the FLOW half.

It did not close the others. Four more sites discard captured evidence -- the
per-flow frame list on the stream side and on the datagram side, the scouting
list, the skipped-packet list and the scout-asker list -- and each accounts for
what it dropped by a HAND-WRITTEN `self.drops.X += n` beside the removal. Every
one of them is correct today. Nothing makes the next one correct.

That is precisely the shape this workspace has paid for repeatedly (R311y612,
y649, y650, y656 each fixed one INSTANCE of an obligation written as prose, and
R311y713 ended that particular one by making it a type). The register carried it
as §C G5: "the other multi-exit invariants have not been looked at".

## What it flags

A removal from a collection inside `crates/wz-capture/src/**` -- `.drain(`,
`.remove(`, `.pop(`, `.pop_front(`, `.swap_remove(`, `.retain(` -- whose
surrounding statement window contains no ACCOUNTING token and which is not
registered below with a reason.

`core::mem::take` / `mem::take` are not removals in this sense: they move a whole
collection to a caller that still holds it, and every such site in this tree
hands it straight to something that counts it.

## Why a window and not a type

Because the collections that need it are `pub` fields read across the crate, and
making five of them private is a bigger change than the defect warrants -- it
would move the public shape of `FlowDissection` for a bookkeeping rule. A gate
that reds on an unaccounted removal gets the same guarantee at the boundary that
matters: a new site cannot ship silently. When one of those fields next needs to
move for its own reasons, the type is the better answer and this lint retires.

## The allow-list IS the point

An entry here is a claim that the site owes nothing, with the reason written
down. Adding one is cheap and visible in review; forgetting to account is not.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "crates" / "wz-capture" / "src"

REMOVAL = re.compile(r"\.(drain|remove|pop|pop_front|swap_remove|retain)\s*\(")

# Anything that counts, censuses or hands the removed value to something that
# does. A removal whose window holds one of these has stated what it lost.
ACCOUNTING = (
    # A LOSS tally: this many pieces of evidence are gone and the report says so.
    "self.drops.",
    "dropped_frames",
    "self.dropped[",
    "self.stats.",
    # The stream assembler's own discarded-bytes tally, which its caller adds
    # to `drops.stream_bytes`.
    "self.discarded +=",
    # A CENSUS of what went, which is the stronger form: not only how many but
    # what they were (R311y713 §B10).
    ".add(&",
    "census",
    # A COORDINATE advance. These bytes were CONSUMED rather than discarded --
    # the deframer handed them upward and stepped the stream position over them
    # -- and a position that keeps advancing is what proves nothing was quietly
    # skipped (R311y661).
    "self.base +=",
)

# (file, the exact source line, why it owes nothing). Matched on the STRIPPED
# line so indentation drift does not silently retire an entry.
ALLOWED = [
    (
        "agg.rs",
        "while let Some(node) = stack.pop() {",
        "a traversal's own work list, built and consumed inside one call; "
        "nothing captured is in it",
    ),
    (
        "agg.rs",
        "self.tables[dir_index(direction)].remove(&u.id);",
        "an UNDECLARE ending a keyexpr binding. The BINDING is removed, not "
        "evidence -- the records it named are already in their rows, and the "
        "id becoming unresolved again is the point (R311y622)",
    ),
    (
        "exchange.rs",
        "let Some(entry) = open.remove(&key) else {",
        "an exchange leaving the OPEN set because it completed; the entry is "
        "folded into the totals on the next line rather than dropped",
    ),
    (
        "exit.rs",
        "Exiting(Some(self.rows.remove(idx)))",
        "THE DOOR ITSELF (R311y713 B1). This is the one removal `FlowTable` "
        "has, and what it returns is the obligation: a `#[must_use] Exiting` "
        "that panics if it is dropped unconsumed. Accounting here would be a "
        "second opinion about the flow the caller is about to account for",
    ),
    (
        "lib.rs",
        "self.askers.drain(..cut);",
        "returns the count to its caller, which adds it to "
        "`drops.scout_askers` (lib.rs:3313). The accounting is one frame up "
        "because the bound is enforced by a helper that owns no counters",
    ),
    (
        "filter.rs",
        'nodes.pop().expect("just checked length")',
        "the expression parser's own operand stack, built and consumed inside "
        "one parse; nothing captured is in it",
    ),
    (
        "frag.rs",
        'let done = self.pending.remove(&key).expect("present");',
        "a chain COMPLETING. The reassembled message is returned to the "
        "caller on the next line -- the opposite of a discard",
    ),
    (
        "tcp.rs",
        "let (seq, packet_index, payload, _) = self.pending.remove(i);",
        "a held segment being DELIVERED into the stream now that the bytes "
        "before it have arrived; it leaves the pending list because it is no "
        "longer pending",
    ),
    (
        "ws.rs",
        "self.pending_resync.pop_front()",
        "a resync marker being handed to the reader that asked for it. The "
        "marker IS the accounting; consuming it is how it reaches a report",
    ),
]


def indent_of(line):
    return len(line) - len(line.lstrip())


def windows(text):
    """Yield (line_no, stripped_line, window) for every removal in `text`.

    The window is the removal's OWN BLOCK, not a fixed number of lines either
    side. Measured, on this lint's own falsify probe: with a six-line window,
    deleting the accounting beside `flow.frames.drain(..cut)` still passed --
    a SIBLING `if` below it counts something else, and a gate that a
    neighbour's counter can satisfy is a gate that reads indentation as
    argument. So the walk stops the moment indentation falls below the
    removal's, which is the closing brace of the block it is in.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("///"):
            continue
        if not REMOVAL.search(line):
            continue
        own = indent_of(line)
        # A method-chain CONTINUATION (`.retain(..)` on its own line) is
        # indented deeper than the statement it belongs to, so measuring the
        # block from it would cut the statement's own accounting off. Walk up
        # to the line that starts the statement and take its indentation.
        j = i
        while j > 0 and lines[j].strip().startswith("."):
            j -= 1
        own = min(own, indent_of(lines[j]))
        lo = i
        while lo > 0 and indent_of(lines[lo - 1]) >= own and lines[lo - 1].strip():
            lo -= 1
        hi = i + 1
        while hi < len(lines) and (
            not lines[hi].strip() or indent_of(lines[hi]) >= own
        ):
            hi += 1
        # COMMENTS ARE NOT ACCOUNTING, and this line is why the rule is worth
        # spelling out: with them included, deleting the census beside
        # `flow.frames.drain(..cut)` still passed, because the comment ABOVE it
        # says "censused BEFORE the drain" and the scan read the word. A gate
        # that a comment can satisfy is a gate that grades prose.
        code = [
            re.sub(r"//.*$", "", ln)
            for ln in lines[lo:hi]
            if not ln.strip().startswith(("//", "///"))
        ]
        yield i + 1, stripped, "\n".join(code)


def main():
    if not SRC.is_dir():
        print(f"discard-site: {SRC} is not a directory", file=sys.stderr)
        return 2
    findings = []
    seen_allowed = set()
    total = 0
    for path in sorted(SRC.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        for line_no, stripped, window in windows(text):
            total += 1
            allowed = [
                a for a in ALLOWED if a[0] == path.name and a[1] == stripped
            ]
            if allowed:
                seen_allowed.add((allowed[0][0], allowed[0][1]))
                continue
            if any(token in window for token in ACCOUNTING):
                continue
            findings.append(f"{path.name}:{line_no}: {stripped}")

    # A registered site that no longer exists is a stale claim, and a stale
    # allow-list is how a gate quietly stops gating.
    stale = [
        f"{f}: {line}"
        for f, line, _ in ALLOWED
        if (f, line) not in seen_allowed
    ]

    if findings or stale:
        if findings:
            print(
                "discard-site FAIL: evidence removed with nothing accounting "
                "for it. Count what was dropped beside the removal, or "
                "register the site in ALLOWED with a reason:",
                file=sys.stderr,
            )
            for f in findings:
                print(f"  {f}", file=sys.stderr)
        if stale:
            print(
                "discard-site FAIL: registered sites that no longer exist -- "
                "remove them, or the list is excusing nothing:",
                file=sys.stderr,
            )
            for s in stale:
                print(f"  {s}", file=sys.stderr)
        return 1

    print(
        f"discard-site OK: {total} removal site(s) in wz-capture, "
        f"{len(ALLOWED)} registered as owing nothing"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

# R311y717 (§C G3) — the scan's REACH, which was the other half of the register
# entry. G5 asked whether other multi-exit sites look like the flow table's; G3
# asked whether a sweep confined to one crate can answer that. It cannot: the
# planes above `wz-capture` hold their own bounded collections, and a discard in
# `wz-capi-dissect` loses exactly as much evidence as one here.
#
# `wz-tls-record` is deliberately absent: it is a record layer with no bounded
# retention of its own, and adding it would be scope by reflex rather than by a
# collection that can lose something.
SRCS = [
    ROOT / "crates" / "wz-capture" / "src",
    ROOT / "crates" / "wz-capi-dissect" / "src",
    ROOT / "crates" / "wz-analyze" / "src",
    ROOT / "crates" / "wz-replay" / "src",
]

# R311y752 (carry N12) — individual FILES, for a subject that moved out from
# under a directory.
#
# `messages.rs` held this gate's two registered sites and moved to
# `wz-session-core::passive_messages` in that round. Adding the whole crate was
# MEASURED first and adds 61 unrelated findings -- retain/remove sites across
# `bounded`, `decl_sink`, `liveliness_get` and the rest -- so widening here would
# have meant registering 61 sites in one hurried pass, which is the shape an
# allow-list stops meaning anything in. Naming the file keeps the gate's SUBJECT
# identical across the move, which is what a move must not change.
#
# The residue, stated: a NEW discard site elsewhere in wz-session-core is
# unwatched. It was unwatched before the move too, so this is not a regression --
# but widening the scan to that crate is a real gap and its own round's work.
SRC_FILES = [
    ROOT / "crates" / "wz-session-core" / "src" / "passive_messages.rs",
]

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

# (crate/file, the exact source line, why it owes nothing). Matched on the
# STRIPPED line so indentation drift does not silently retire an entry, and on
# the CRATE-QUALIFIED name because widening the scan to four crates put three
# `lib.rs` in the population -- a bare file name would let one crate's entry
# excuse another crate's site.
ALLOWED = [
    (
        "wz-session-core/passive_messages.rs",
        "frame: Some(self.0.remove(0)),",
        "R311y723 — THE DOOR ITSELF. This removal accounts for nothing on "
        "purpose: it hands back a `#[must_use] Discarded` whose destructor "
        "PANICS unless the caller took the frame, so the obligation is moved "
        "into the type system rather than discharged here. Registering the one "
        "site that makes every other site impossible to get wrong",
    ),
    (
        "wz-session-core/passive_messages.rs",
        "out.remove(0)",
        "R311y723 — a TEST fixture taking the single decoded frame out of the "
        "observer's return value. Nothing captured is discarded: the vector is "
        "a local the call just produced",
    ),
    (
        "wz-capture/agg.rs",
        "while let Some(node) = stack.pop() {",
        "a traversal's own work list, built and consumed inside one call; "
        "nothing captured is in it",
    ),
    (
        "wz-capture/agg.rs",
        "self.tables[dir_index(direction)].remove(&u.id);",
        "an UNDECLARE ending a keyexpr binding. The BINDING is removed, not "
        "evidence -- the records it named are already in their rows, and the "
        "id becoming unresolved again is the point (R311y622)",
    ),
    (
        "wz-capture/interest.rs",
        "match open.remove(&(dir, kind, id)) {",
        "R311y869 — a declaration leaving the OPEN index because an "
        "`Undeclare` closed it. The DECLARATION is not discarded, which is "
        "that plane's central design point: it stays in `self.interests` and "
        "the removal's only effect is to stamp `withdrawn_at` on it. The arm "
        "that finds NOTHING is the one that accounts -- it counts an "
        "`orphan_withdrawal`, which is how a reader learns the declaration "
        "list is a floor",
    ),
    (
        "wz-capture/interest.rs",
        "match asked.remove(&(dir, interest.interest_id)) {",
        "R311y870 — an `Interest(Final)` closing the asker's own request. The "
        "REQUEST is not discarded: it stays in `self.requests` and the removal "
        "only stamps `cancelled_at` on it, so a later answer cannot be credited "
        "to a question the asker has stopped. The arm that finds NOTHING "
        "accounts, as its twin does -- an `orphan_answer`, which is how a "
        "reader learns the request list is a floor",
    ),
    (
        "wz-capture/exchange.rs",
        "let Some(entry) = open.remove(&key) else {",
        "an exchange leaving the OPEN set because it completed; the entry is "
        "folded into the totals on the next line rather than dropped",
    ),
    (
        "wz-capture/exit.rs",
        "Exiting(Some(self.rows.remove(idx)))",
        "THE DOOR ITSELF (R311y713 B1). This is the one removal `FlowTable` "
        "has, and what it returns is the obligation: a `#[must_use] Exiting` "
        "that panics if it is dropped unconsumed. Accounting here would be a "
        "second opinion about the flow the caller is about to account for",
    ),
    (
        "wz-capture/lib.rs",
        "self.askers.drain(..cut);",
        "returns the count to its caller, which adds it to "
        "`drops.scout_askers` (lib.rs:3313). The accounting is one frame up "
        "because the bound is enforced by a helper that owns no counters",
    ),
    (
        "wz-capture/filter.rs",
        'nodes.pop().expect("just checked length")',
        "the expression parser's own operand stack, built and consumed inside "
        "one parse; nothing captured is in it",
    ),
    (
        "wz-capture/frag.rs",
        'let done = self.pending.remove(&key).expect("present");',
        "a chain COMPLETING. The reassembled message is returned to the "
        "caller on the next line -- the opposite of a discard",
    ),
    (
        "wz-capture/tcp.rs",
        "let (seq, packet_index, payload, _) = self.pending.remove(i);",
        "a held segment being DELIVERED into the stream now that the bytes "
        "before it have arrived; it leaves the pending list because it is no "
        "longer pending",
    ),
    (
        "wz-capture/ws.rs",
        "self.pending_resync.pop_front()",
        "a resync marker being handed to the reader that asked for it. The "
        "marker IS the accounting; consuming it is how it reaches a report",
    ),
    (
        "wz-capture/payload_cbor.rs",
        "self.pop(mark);",
        "R311y916 — the CBOR walk's own PATH, truncated back to the mark its "
        "`push` returned as it leaves a container. Not a collection at all: "
        "`Walk::pop` shortens a `String` that is being rebuilt on the way down, "
        "and every row the walk emitted below it already carries its own copy "
        "of the path it was at. Nothing captured is in it. Registered rather "
        "than renamed -- `pop` is the right name for the inverse of `push` on a "
        "path stack, and dodging a lint's regex by renaming a correct method is "
        "the workaround this list exists to make unnecessary. This is the red "
        "R311y914 shipped and two pushes carried, because the pre-push hook "
        "does not run Layer C0",
    ),
    (
        "wz-replay/lib.rs",
        "out.pop();",
        "one character off a rendered STRING -- the trailing newline, so a "
        "timing note can be appended to the line. Nothing captured is in it",
    ),
    (
        "wz-replay/live.rs",
        "writer_handle.drain().await;",
        "the WRITER flushing on teardown, which is the opposite of a discard: "
        "it is what makes sure everything queued reached the wire before the "
        "session closes. Named `drain` for the same reason a buffer is",
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
    missing = [str(d) for d in SRCS if not d.is_dir()]
    missing += [str(f) for f in SRC_FILES if not f.is_file()]
    if missing:
        # A scan whose subject moved must FAIL rather than report zero: an
        # empty population is the shape a gate goes quiet in. This is what
        # caught the R311y752 move -- twice, once as a stale ALLOWED entry and
        # once as a named file that had gone.
        print(f"discard-site: not readable: {missing}", file=sys.stderr)
        return 2
    findings = []
    seen_allowed = set()
    total = 0
    paths = sorted({p for d in SRCS for p in d.rglob("*.rs")} | set(SRC_FILES))
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for line_no, stripped, window in windows(text):
            total += 1
            qualified = f"{path.parents[1].name}/{path.name}"
            allowed = [
                a for a in ALLOWED if a[0] == qualified and a[1] == stripped
            ]
            if allowed:
                seen_allowed.add((allowed[0][0], allowed[0][1]))
                continue
            if any(token in window for token in ACCOUNTING):
                continue
            findings.append(f"{qualified}:{line_no}: {stripped}")

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
        f"discard-site OK: {total} removal site(s) across {len(SRCS)} crate(s) "
        f"and {len(SRC_FILES)} named file(s), "
        f"{len(ALLOWED)} registered as owing nothing"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

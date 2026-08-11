#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y722 (§1.1f) — every list of decoded messages is in the enumeration the
census planes walk.

## The omission this ends, counted

Four planes census the decoded transport messages — throughput, exchanges,
payloads, nodes. Each used to name the tables it knew about, so a NEW producer
reached whichever plane its author remembered and the rest reported it as empty.
That has shipped FIVE times: R311y668, y678, y699, y700, and R311y720, whose own
carry recorded a whole serial line reaching the flow listing and none of the
planes.

R311y721 replaced the five call sites with one enumeration
(`Dissection::message_lists`); R311y722 gated it on fields typed
`Vec<PassiveFrame>`; and R311y723 asked what that gate could not see.

## The two holes R311y722 had, and which layer closed each

1. It read one CRATE. A producer in `wz-analyze` was never looked at. THIS scan
   now reads the whole workspace.
2. It read a container SHAPE. `Vec<(SerialFrame, PassiveFrame)>` — the exact
   form the serial list had one round earlier — matched nothing, and so would
   `[Vec<PassiveFrame>; 2]` or a map of them. Widening the regex would have
   chased shapes forever, so R311y723 made the population a NAME instead:
   decoded messages live in `MessageList` (`wz-capture/src/messages.rs`), whose
   deref target is a SLICE, so growth and removal have exactly one door each.
   A field that holds messages says `MessageList` whatever it is wrapped in.

## What this layer is FOR, given the other two

`MessageList` makes the population unambiguous; the exhaustive destructures in
`message_list_census` make a new field on an EXISTING owner fail to compile.
Neither can catch a whole NEW owner struct — a sixth type, anywhere, holding a
`MessageList` that no enumeration reaches. That is this gate's job, and it is
the only one of the three that can do it.

## What counts as reached

The enumeration names a field directly (`self.serial_frames`), or names a method
that does (`frame_lists`). So the scan follows one hop: a field named in
`message_lists` is reached, and so is a field named in any method
`message_lists` calls. One hop and not a full call graph, deliberately — a
deeper walk would start proving things about code this gate cannot read, and the
shape it has to catch is a field nobody mentions anywhere.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The WHOLE workspace: a producer in any crate is a producer.
CRATES = REPO_ROOT / "crates"

# The enumeration every plane walks.
ENUMERATION = "message_lists"

# A field whose declaration MENTIONS the type, in any container. `=` is the one
# character excluded: a struct declaration has none, and allowing `;` is what
# lets `[MessageList; 2]` -- an array of them, one per direction, which is a
# shape this crate already uses for other per-direction state -- be seen. This is the
# whole point of R311y723's newtype: `frames: MessageList`,
# `kept: [MessageList; 2]`, `by_id: BTreeMap<u64, MessageList>` and
# `rows: Vec<(Origin, MessageList)>` all match, where a shape-based pattern
# caught only the first.
PRODUCER_TYPE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*([^=]*\bMessageList\b[^=]*),\s*$")

# A struct LITERAL field looks identical to a declaration -- `frames:
# messages::MessageList::new(),` beside `frames: messages::MessageList,` -- and
# MEASURED, the right-hand side cannot tell them apart: a first attempt read a
# `(` as "this is a call" and a tuple TYPE
# (`Vec<(usize, MessageList)>`) has one too, so a cross-crate probe wrapped in a
# tuple sailed through the gate. What separates them is WHERE they are, so the
# scan tracks struct-item blocks and counts fields only inside one.
STRUCT_OPEN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+\w+")

# A method opening line, so the scan can take one hop out of the enumeration.
FN_OPEN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(")

# Producers that are deliberately NOT in the enumeration, each with the reason.
# A registration is a claim a reader can check, which is the whole difference
# between this and deleting the gate.
EXEMPT = {
    # The QUIC pass's own outcome list in `wz-analyze` is not a dissection
    # field; nothing here should ever match it, and the entry exists so that a
    # future move of that list is a decision rather than a silence.
}

# Below this the scan resolved the wrong root or read the wrong crate: the
# dissection has held at least this many producers since R311y718.
MIN_PRODUCERS = 3


def method_bodies(text: str) -> dict[str, str]:
    """Every method's body, brace-counted.

    Line-oriented rather than a regex over the whole file, for the reason
    `solo_plane_page_lint` states: a Rust body contains braces in string
    literals and closures, and a lazy match would end it at the first inner
    close.
    """
    out: dict[str, str] = {}
    lines = text.splitlines()
    at = 0
    while at < len(lines):
        match = FN_OPEN.match(lines[at])
        if not match:
            at += 1
            continue
        name = match.group(1)
        depth = 0
        started = False
        body: list[str] = []
        while at < len(lines):
            line = lines[at]
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            body.append(line)
            at += 1
            if started and depth <= 0:
                break
        out.setdefault(name, "\n".join(body))
    return out


def main() -> int:
    files = sorted(CRATES.rglob("*.rs"))
    # Vendored trees are somebody else's code and carry no planes of ours.
    files = [f for f in files if "/target/" not in f.as_posix()]
    if not files:
        print(f"message-producer lint: FAIL no sources under {CRATES}")
        return 1

    producers: list[tuple[str, str]] = []
    bodies: dict[str, str] = {}
    for path in files:
        text = path.read_text(encoding="utf-8")
        bodies.update(method_bodies(text))
        # The type's OWN definition is not a field of it. By file name, because
        # the module is one file.
        if path.name == "messages.rs":
            continue
        depth = 0
        in_struct = False
        for line in text.splitlines():
            stripped = line.strip()
            # Doc comments and ordinary comments carry the type in prose all
            # over this crate; only a real field declaration counts.
            if stripped.startswith("//"):
                continue
            if not in_struct and STRUCT_OPEN.match(line) and "{" in line:
                in_struct = True
                depth = 0
            if in_struct:
                found = PRODUCER_TYPE.match(line)
                if found:
                    producers.append(
                        (path.relative_to(REPO_ROOT).as_posix(), found.group(1))
                    )
                depth += line.count("{") - line.count("}")
                if depth <= 0 and "}" in line:
                    in_struct = False

    if len(producers) < MIN_PRODUCERS:
        print(
            "message-producer lint: FAIL only %d producer(s) found; the scan is "
            "reading the wrong tree (expected at least %d)"
            % (len(producers), MIN_PRODUCERS)
        )
        return 1

    enumeration = bodies.get(ENUMERATION)
    if enumeration is None:
        print(
            "message-producer lint: FAIL `%s` not found -- the enumeration the "
            "planes walk is gone or renamed, and this gate cannot speak for a "
            "door that does not exist" % ENUMERATION
        )
        return 1

    # One hop: the enumeration's own text, plus the body of every method it
    # names. See the module doc for why one and not a full call graph.
    reach = enumeration
    for name, body in bodies.items():
        if name != ENUMERATION and re.search(r"\b%s\b" % re.escape(name), enumeration):
            reach += "\n" + body

    findings = []
    for rel, field in producers:
        if field in EXEMPT:
            continue
        if re.search(r"\b%s\b" % re.escape(field), reach):
            continue
        findings.append((rel, field))

    if findings:
        for rel, field in findings:
            print(
                "message-producer lint: FAIL %s: the field `%s` holds a "
                "`MessageList` and `%s` does not reach it" % (rel, field, ENUMERATION)
            )
        print(
            "    Every list of decoded messages must be in the enumeration the\n"
            "    four census planes walk, or registered in EXEMPT with the\n"
            "    reason. A producer outside it is censused by nothing, and the\n"
            "    planes report the traffic as absent rather than as unread --\n"
            "    which has shipped five times (R311y668, y678, y699, y700, y720)."
        )
        return 1

    print(
        "message-producer lint: OK (%d list(s) of decoded messages, all reached by `%s`; "
        "%d exempt)" % (len(producers), ENUMERATION, len(EXEMPT))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

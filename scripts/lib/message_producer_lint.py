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
(`Dissection::message_lists`) and wrote down what it had not done: "a sixth
producer added beside it reaches the planes only if its author adds it here.
That is strictly better than five call sites, and it is still a convention."

This is the gate that ends the convention. A `Vec<PassiveFrame>` field is a
producer of census rows by construction — it is the only type those planes
consume — so the rule is mechanical: every one of them must be reachable from
the enumeration, or be registered here with the reason it is not.

## Why the field TYPE and not a list of names

A hand-kept list of producers would have to be updated by the same person who
forgot to add the producer, which is the failure this gate exists to catch. The
type is the population and the compiler maintains it.

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

# The crate that owns the dissection and its planes.
CRATE = REPO_ROOT / "crates/wz-capture/src"

# The enumeration every plane walks, and the type that makes a field a producer.
ENUMERATION = "message_lists"
PRODUCER_TYPE = re.compile(r"^\s*(?:pub\s+)?(\w+)\s*:\s*(?:alloc::vec::)?Vec<PassiveFrame>\s*,")

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
    files = sorted(CRATE.rglob("*.rs"))
    if not files:
        print(f"message-producer lint: FAIL no sources under {CRATE}")
        return 1

    producers: list[tuple[str, str]] = []
    bodies: dict[str, str] = {}
    for path in files:
        text = path.read_text(encoding="utf-8")
        bodies.update(method_bodies(text))
        for line in text.splitlines():
            # Doc comments and ordinary comments carry the type in prose all
            # over this crate; only a real field declaration counts.
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            found = PRODUCER_TYPE.match(line)
            if found:
                producers.append((path.relative_to(REPO_ROOT).as_posix(), found.group(1)))

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
                "message-producer lint: FAIL %s: `%s: Vec<PassiveFrame>` is a "
                "producer of census rows and `%s` does not reach it" % (rel, field, ENUMERATION)
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

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2116 (no register item) — the HEADER has to say which doors were subsumed,
and the library is what says whether it is right.

Closes item 466 of the unregistered register, which lives outside this
repository -- hence the citation above, the same way `cdylib_soname_gate.py`
does for item 521.

## The gap

R311y932 gave `wz_dissect_readable_surfaces` a `doors` axis, so a consumer can
ASK which door is the current shape for each job. A consumer reading
`wz_dissect.h` still saw nine entry points in a row with nothing to separate a
current one from an older one it should not reach for. Measured before writing
this, over the header: `subsume`, `supersede`, `prefer` and `instead` return
six hits and not one of them is about one door joining another -- they are
ordinary prose ("a document instead of a struct tree").

That matters because a header is what a linking consumer reads FIRST, and often
only. "Ask the library at runtime" is a fine answer for a program and no answer
at all for the person choosing which symbol to call.

## Why a gate and not just the comments

Item 466 names the trap itself: adding `/* SUBSUMED BY ... */` lines is prose,
and prose is what item 450 already cost a round for. A comment that nobody
measures goes stale on the day a tenth door arrives, and it goes stale
SILENTLY, in the direction that matters -- a consumer told that a door is
current when it is not.

So the comment is given a checkable FORM and the library is made the oracle.
The population is not read out of the header and not read out of the Rust
source: it is READ OUT OF THE ARTIFACT, by loading the release cdylib and
calling `wz_dissect_readable_surfaces` the way a consumer would. What the
header claims is then held against what the shipped library answers, in both
directions:

  * a door the library calls subsumed, with no marker in the header beside its
    declaration -- the reader is not told;
  * a marker naming a different successor than the library does -- the reader
    is told something false, which is worse;
  * a marker beside a door the library calls CURRENT -- a stale line left
    behind when a door stopped being the older shape;
  * a marker nowhere near any door's declaration -- a line that reads as a
    statement and pins nothing.

## Where the marker has to be

Inside the comment block that precedes the door's own declaration, which is
where a person reading about that symbol already is. The span is delimited
mechanically: from the end of the previous `int wz_dissect_*(` declaration to
this one. A marker in the file's general prose is refused by the last check
above, because a subsumption a reader can only find by searching is the state
this item began in.
"""

from __future__ import annotations

import ctypes
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = ROOT / "crates" / "wz-capi-dissect" / "include" / "wz_dissect.h"
CDYLIB = ROOT / "crates" / "target" / "release" / "libwz_capi_dissect.so"

# The one spelling. A form rather than a sentence, so a reader writes the prose
# and the gate reads the fact out of it.
MARKER = re.compile(r"SUBSUMED BY (wz_dissect_[a-z_0-9]+)")

# A door's own declaration, at column zero, which is how every entry point in
# this header is written.
DECL = re.compile(r"^int (wz_dissect_[a-z_0-9]+)\(", re.M)


def doors() -> list[dict]:
    """Every door and its successor, ASKED OF THE SHIPPED LIBRARY.

    Not parsed out of the Rust `Door` walk and not out of the header: those are
    the two things being held against each other, and a gate that read either
    of them would be comparing a file with itself.
    """
    lib = ctypes.CDLL(str(CDYLIB))
    lib.wz_dissect_readable_surfaces.restype = ctypes.c_int
    lib.wz_dissect_readable_surfaces.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
    lib.wz_dissect_string_free.restype = None
    lib.wz_dissect_string_free.argtypes = [ctypes.c_char_p]
    out = ctypes.c_char_p()
    rc = lib.wz_dissect_readable_surfaces(ctypes.byref(out))
    if rc != 0 or not out.value:
        print(
            f"capi-header-subsumption: FAIL -- the library's readable-surfaces "
            f"door returned {rc}, so the door set could not be read from the "
            f"artifact at all.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        document = json.loads(out.value.decode())
    finally:
        lib.wz_dissect_string_free(out)
    return document.get("doors", [])


def spans(text: str) -> list[tuple[str, int, int]]:
    """Each door declaration's own stretch of header: (symbol, start, end).

    The stretch runs from the end of the PREVIOUS declaration to the end of
    this one, which is exactly the comment block a reader has in front of them
    when they read about that symbol.
    """
    out: list[tuple[str, int, int]] = []
    previous = 0
    for m in DECL.finditer(text):
        end = text.find(";", m.end())
        end = len(text) if end < 0 else end
        out.append((m.group(1), previous, end))
        previous = end
    return out


def main() -> int:
    if not CDYLIB.is_file():
        # A gate that cannot read its input must not report green. The lane
        # builds this artifact immediately before calling here.
        print(
            f"capi-header-subsumption: FAIL -- {CDYLIB.relative_to(ROOT)} is "
            f"absent. The lane must build the release cdylib before this gate "
            f"runs; a door set read from nothing is not a door set.",
            file=sys.stderr,
        )
        return 1

    listed = doors()
    if not listed:
        print(
            "capi-header-subsumption: FAIL -- the library reported ZERO doors. "
            "An empty population is indistinguishable from total compliance, so "
            "it cannot pass.",
            file=sys.stderr,
        )
        return 1

    text = HEADER.read_text()
    by_symbol = {name: (start, end) for name, start, end in spans(text)}
    if not by_symbol:
        print(
            "capi-header-subsumption: FAIL -- no entry-point declaration was "
            "found in the header, so every check below would be vacuous.",
            file=sys.stderr,
        )
        return 1

    findings: list[str] = []
    claimed: list[tuple[int, str]] = []  # (offset, successor) of every marker
    for m in MARKER.finditer(text):
        claimed.append((m.start(), m.group(1)))

    subsumed = 0
    for door in listed:
        name = door.get("name")
        successor = door.get("subsumed_by")
        if name not in by_symbol:
            findings.append(
                f"the library reports the door `{name}` and the header declares "
                f"no such entry point -- a consumer cannot call what it cannot "
                f"see declared"
            )
            continue
        start, end = by_symbol[name]
        here = [s for offset, s in claimed if start <= offset < end]
        if successor:
            subsumed += 1
            if not here:
                findings.append(
                    f"the library says `{name}` was subsumed by `{successor}` "
                    f"and nothing beside its declaration in the header says so. "
                    f"A reader choosing a symbol reads the header, not the "
                    f"runtime document -- write `SUBSUMED BY {successor}` into "
                    f"that door's own comment"
                )
            elif here != [successor]:
                # EXACTLY ONE, not "the right one is among them". Found by
                # mutation: a span carrying both the true successor and a
                # second, contradicting line passed a membership test while a
                # reader in front of it has two answers and no way to pick.
                # Under-reporting is the one failure a gate must not have.
                findings.append(
                    f"the header says `{name}` was subsumed by "
                    f"{', '.join('`' + s + '`' for s in here)} and the library "
                    f"says exactly `{successor}`. A door has ONE current shape, "
                    f"so a second line beside it -- or a different name -- "
                    f"tells a consumer something false, which is worse than "
                    f"telling it nothing"
                )
        elif here:
            findings.append(
                f"the header marks `{name}` as subsumed by "
                f"{', '.join('`' + s + '`' for s in here)} and the library says "
                f"it is the CURRENT shape -- a line left behind, pointing a "
                f"reader away from the door it should use"
            )

    reachable = [(offset, s) for offset, s in claimed]
    for offset, successor in reachable:
        if not any(start <= offset < end for start, end in by_symbol.values()):
            line = text.count("\n", 0, offset) + 1
            findings.append(
                f"line {line} says `SUBSUMED BY {successor}` and it sits beside "
                f"no door's declaration, so it states a fact a reader can only "
                f"find by searching -- which is the state this axis was added "
                f"to end"
            )

    if findings:
        print("capi-header-subsumption: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(
        f"  capi-header-subsumption: {len(listed)} door(s) the library reports, "
        f"{subsumed} of them subsumed and each said so beside its own "
        f"declaration; {len(claimed)} marker(s) in the header, none stale"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

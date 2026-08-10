#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y639 (§4.30) — a payload total may only be written by the door that can
say "unknown".

THE DEFECT THIS EXISTS FOR, twice, in the same shape. `KeyexprCounts` carries a
byte total and a count of records whose payload this build cannot size. Every
carrier arm of `agg::classify` used to write the total directly --
`counts.payload_bytes = <field>.len() as u64` -- and a plain assignment cannot
express "unknown", so an arm whose payload is NOT the field it looks like had no
way to say so:

  * R311y637: a `Query`'s value rides its ext chain, so the arm reported 0
    application bytes for a query carrying seven. A confident zero.
  * R311y639: a `MsgPut` / `Err` whose chain carries the SHM marker
    (`zextunit!(0x2, true)`) holds a DESCRIPTOR in its payload slot -- the data
    never traversed the network -- and the marker also switches the field's
    framing to a slice sequence. The arm reported that slot's length as an
    application byte total.

Both were fixed by routing the write through `KeyexprCounts::record_payload`,
whose parameter is an `Option`: a carrier that reaches the counter through it
is ASKED the question at the only moment the answer is available. This gate is
what makes the door mandatory. A third carrier -- another ext-borne payload, an
SHM descriptor on a body this crate does not decode yet -- can otherwise still
be added with a bare assignment, exactly as the two above were, and every test
would pass because a test cannot observe a question that was never asked.

WHY A STATIC SCAN. The invariant is "no code of this SHAPE exists", which is a
fact about the source. No assertion can observe its own absence, the same reason
`solo_plane_page_lint` and `literal_wire_flag_lint` read source rather than
running anything.

THE GUARDED FIELD SET IS READ, NEVER LISTED. It is whatever `record_payload`
itself writes, so a third counter added to the door is in scope the moment it is
declared. A hand-kept list here would have to be updated by the same author who
took the side door.

WHAT IT DOES NOT SEE, stated rather than implied. Folds are allowed and not
inspected further: an assignment whose right-hand side reads a guarded field is
a total flowing into a bigger total, which is not a measurement entering the
system. So a fold that folded the WRONG counter would pass. And the scan reads
assignments and struct literals; a counter mutated through a `&mut` alias handed
to another function would not be seen. Both historical defects were plain
assignments in `classify`, which is the shape this covers.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The crate whose payload totals this speaks for.
CRATE = Path("crates/wz-capture")

# The door, and the type it guards.
DOOR = "record_payload"
GUARDED_TYPE = "KeyexprCounts"

FN_OPEN = re.compile(rf"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+{DOOR}\s*\(")
SELF_WRITE = re.compile(r"self\.(\w+)\s*(?:\+|-|\*|/)?=[^=]")

# Below this the scan resolved the wrong root or read the wrong tree. The
# capture crate carries a dozen source files; a run that read fewer found
# nothing to look at and must not report OK -- the failure mode
# `duplicate_module_lint` shipped with on its first run (0 files, exit 0).
MIN_FILES = 8


def blank_noncode(text: str) -> str:
    """Replace comment and string-literal CONTENT with spaces, keeping offsets.

    Prose is not code, and this file's own doc comments quote
    `counts.payload_bytes = <field>.len()` when explaining the defect. A scan
    that read them would report the explanation as the finding.
    """
    out: list[str] = []
    i, n = 0, len(text)

    def blank(seg: str) -> str:
        return "".join(c if c == "\n" else " " for c in seg)

    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(blank(text[i:j]))
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(blank(text[i:j]))
            i = j
        elif c == "r" and i + 1 < n and text[i + 1] in '#"':
            k = i + 1
            while k < n and text[k] == "#":
                k += 1
            if k < n and text[k] == '"':
                close = '"' + "#" * (k - i - 1)
                j = text.find(close, k + 1)
                j = n if j < 0 else j + len(close)
                out.append(blank(text[i:j]))
                i = j
            else:
                out.append(c)
                i += 1
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(blank(text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def body_span(lines: list[str], start: int) -> tuple[int, int]:
    """`[start, end)` of the brace-delimited body opening at or after `start`."""
    depth = 0
    opened = False
    k = start
    while k < len(lines):
        depth += lines[k].count("{") - lines[k].count("}")
        opened = opened or "{" in lines[k]
        if opened and depth <= 0:
            return start, k + 1
        k += 1
    return start, len(lines)


def find_door(files: dict[Path, list[str]]) -> tuple[Path, int, int, set[str]]:
    """Locate `record_payload` and read the field set it writes."""
    for path, lines in files.items():
        for i, line in enumerate(lines):
            if FN_OPEN.match(line):
                lo, hi = body_span(lines, i)
                fields = set()
                for row in lines[lo:hi]:
                    fields.update(SELF_WRITE.findall(row))
                return path, lo, hi, fields
    return Path(), 0, 0, set()


def main() -> int:
    root = REPO_ROOT / CRATE
    files: dict[Path, list[str]] = {}
    for path in sorted(root.rglob("*.rs")):
        if "target" in path.parts:
            continue
        files[path] = blank_noncode(
            path.read_text(encoding="utf-8", errors="replace")
        ).splitlines()

    if len(files) < MIN_FILES:
        print(
            f"payload-measurement lint: FAIL — scanned {len(files)} file(s) "
            f"under {CRATE}, fewer than the {MIN_FILES} that tree has. A "
            f"checker that found nothing to read must not report OK.",
            file=sys.stderr,
        )
        return 1

    door_path, door_lo, door_hi, guarded = find_door(files)
    if not guarded:
        print(
            f"payload-measurement lint: FAIL — no `fn {DOOR}` writing any "
            f"`self.<field>` was found under {CRATE}. Either the door was "
            f"renamed or removed, in which case this gate is blind and the "
            f"invariant it carries needs a new home, or the scan is wrong. "
            f"Either way it must not report OK.",
            file=sys.stderr,
        )
        return 1

    # An assignment to a guarded field. `\w+(?:\.\w+)*` so `self.x`, `counts.x`
    # and `row.totals.x` are all reached.
    assign = re.compile(
        r"(?<![\w.])((?:\w+\.)+(" + "|".join(sorted(guarded)) + r"))\s*(\+?=)(?!=)(.*)$"
    )
    # A struct literal naming a guarded field: the other way into the counter.
    literal = re.compile(
        r"\b" + GUARDED_TYPE + r"\s*\{|^\s*(" + "|".join(sorted(guarded)) + r")\s*:"
    )

    findings: list[str] = []
    writes = 0
    folds = 0
    for path, lines in files.items():
        in_literal = 0
        for i, line in enumerate(lines):
            if path == door_path and door_lo <= i < door_hi:
                continue
            if re.search(r"\b" + GUARDED_TYPE + r"\s*\{", line):
                in_literal = 3
            elif in_literal:
                in_literal -= 1
                m = re.match(
                    r"^\s*(" + "|".join(sorted(guarded)) + r")\s*:", line
                )
                if m:
                    findings.append(
                        f"{path.relative_to(REPO_ROOT)}:{i + 1}: "
                        f"`{GUARDED_TYPE}` literal sets `{m.group(1)}` directly"
                    )
            m = assign.search(line)
            if not m:
                continue
            writes += 1
            rhs = m.group(4)
            # A FOLD: the right-hand side reads a guarded field, so this is a
            # total flowing into a bigger total, not a measurement entering.
            if any(re.search(r"\.\s*" + f + r"\b", rhs) for f in guarded):
                folds += 1
                continue
            findings.append(
                f"{path.relative_to(REPO_ROOT)}:{i + 1}: "
                f"`{m.group(1)} {m.group(3)}{rhs.rstrip()}`"
            )

    if writes == 0:
        print(
            f"payload-measurement lint: FAIL — no write to any of "
            f"{sorted(guarded)} was found outside `{DOOR}`. The fold in "
            f"`KeyexprCounts::add` is one, so a scan seeing none read the wrong "
            f"tree or its pattern no longer matches this crate's source.",
            file=sys.stderr,
        )
        return 1

    if findings:
        print("payload-measurement lint: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            f"\nA payload total must enter through `KeyexprCounts::{DOOR}`, "
            f"whose parameter is\nan `Option`: a carrier whose payload is not "
            f"the field it looks like can then SAY\nso. R311y637 (a query's "
            f"value rides an ext) and R311y639 (an SHM descriptor\nstands in "
            f"for data that never crossed the wire) were both bare assignments "
            f"of\nthis exact shape, and both reported a confident number for a "
            f"quantity no length\non the wire holds.",
            file=sys.stderr,
        )
        return 1

    print(
        f"payload-measurement lint: OK ({len(files)} file(s) under {CRATE}; "
        f"door `{DOOR}` guards {sorted(guarded)}; {writes} write(s) outside it, "
        f"all {folds} of them folds)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

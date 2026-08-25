#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y621 (§7.14) — every report PLANE must appear ALONE on some page.

THE DEFECT THIS EXISTS FOR, and it was measured rather than argued. R311y618
severed one leg of `CaptureReport::is_complete` and all 229 tests stayed green:
the report pages that would have caught it attached TWO planes at once, and the
other plane already produced the verdict, so neither leg gated anything. A test
with two sufficient causes gates neither of them.

The remedy was to put ONE plane on the page, and it has since been applied by
hand six times across R311y618, R311y620 and R311y621. Nothing required it. A
fourth plane added tomorrow could ship with only a multi-plane page behind it,
every test would pass, and its leg of the completeness verdict would be exactly
as unguarded as the one R311y618 found.

WHY A STATIC SCAN. The invariant is "a test of this shape EXISTS", which is a
fact about the source. No build fails when it does not hold and no assertion can
observe its own absence -- the same reason `literal_wire_flag_lint` reads source
rather than running anything.

WHAT IT IS NOT. It does not claim the solo page is a GOOD page, only that the
plane has been put on a page by itself at least once. A plane whose solo page
asserts nothing would satisfy this, and that is the honest limit of a scan:
this gate is about the SHAPE that makes an assertion capable of gating, not
about the assertion.

THE PLANE SET IS READ, NEVER LISTED. The builders are discovered from
`CaptureReport`'s own `with_*` methods, so a new plane is IN SCOPE the moment it
is declared. A hand-kept list here would have to be updated by the same person
who forgot the page, which is the failure this gate exists to catch.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The crate whose report plane this speaks for.
CRATE = Path("crates/wz-capture")

# `CaptureReport`'s attach-a-plane builders ARE the plane set.
BUILDER = re.compile(r"^\s*pub fn with_(\w+)\s*\(", re.M)

# A test function's opening line. The scan is line-oriented and brace-counted
# rather than regex-over-the-whole-body: a Rust test body contains braces in
# string literals and closures, and a lazy `\{.*?\}` would end the body at the
# first inner close.
TEST_ATTR = re.compile(r"^\s*#\[test\]\s*$")
FN_OPEN = re.compile(r"^\s*(?:async\s+)?fn\s+(\w+)\s*\(")

# The two shapes that matter inside a body.
ENTRY = "CaptureReport::of("
ATTACH = re.compile(r"\.with_(\w+)\s*\(")

# Below this the scan resolved the wrong root or read the wrong crate. The
# capture crate carries a dozen source files; a run that read fewer found
# nothing to look at and must not report OK — the failure mode
# `duplicate_module_lint` shipped with on its first run (0 files, exit 0).
MIN_FILES = 8


def blank_noncode(text: str) -> str:
    """Replace comment and string-literal CONTENT with spaces, keeping offsets.

    Two things depend on this and the first was found by the scan getting it
    wrong. Braces inside a string literal are not braces: this crate asserts on
    `"\\"gaps\\":{\\"halted_batches\\":0"`, whose single `{` ran the body walk
    436 lines past the test and swallowed every test behind it. And prose is not
    code: the doc comments here quote `.with_throughput(...)` when explaining
    what a page attaches, so a scan that read them would credit a plane with a
    page that does not exist.

    Blanking rather than deleting, so line and column structure survive and the
    caller can still walk the text line by line.
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


def solo_pages(root: Path) -> tuple[dict[str, list[str]], int, int]:
    """`(plane -> [test names attaching it ALONE], tests seen, files scanned)`."""
    solo: dict[str, list[str]] = {}
    tests_seen = 0
    scanned = 0
    for path in sorted((root / CRATE).rglob("*.rs")):
        if "target" in path.parts:
            continue
        scanned += 1
        raw = path.read_text(encoding="utf-8", errors="replace")
        lines = blank_noncode(raw).splitlines()
        i = 0
        while i < len(lines):
            if not TEST_ATTR.match(lines[i]):
                i += 1
                continue
            # Walk to the `fn` line: attributes may sit between them
            # (`#[cfg(feature = "reassembly")]` does, in this crate).
            j = i + 1
            while j < len(lines) and not FN_OPEN.match(lines[j]):
                j += 1
            if j >= len(lines):
                break
            name = FN_OPEN.match(lines[j]).group(1)
            # Brace-count the body from the `fn` line, over masked source so a
            # brace in a string literal cannot run the walk off the end.
            depth = 0
            opened = False
            k = j
            body: list[str] = []
            while k < len(lines):
                code = lines[k]
                body.append(code)
                depth += code.count("{") - code.count("}")
                opened = opened or "{" in code
                if opened and depth <= 0:
                    break
                k += 1
            text = "\n".join(body)
            i = k + 1
            if ENTRY not in text:
                continue
            tests_seen += 1
            attached = sorted(set(ATTACH.findall(text)))
            if len(attached) == 1:
                solo.setdefault(attached[0], []).append(f"{path.name}::{name}")
    return solo, tests_seen, scanned


def main() -> int:
    report = REPO_ROOT / CRATE / "src" / "report.rs"
    if not report.is_file():
        print(
            f"solo-plane-page lint: FAIL — {report} is not there. The plane set "
            f"is READ from it, so a scan that cannot find it has no set to "
            f"check and must not report OK.",
            file=sys.stderr,
        )
        return 1
    planes = sorted(set(BUILDER.findall(report.read_text(encoding="utf-8"))))
    if not planes:
        print(
            "solo-plane-page lint: FAIL — no `with_*` builder found in "
            f"{report.relative_to(REPO_ROOT)}. Either the report grew a "
            "different way of attaching a plane, in which case this gate is "
            "blind and must be taught the new shape, or the scan is wrong.",
            file=sys.stderr,
        )
        return 1

    solo, tests_seen, scanned = solo_pages(REPO_ROOT)

    if scanned < MIN_FILES:
        print(
            f"solo-plane-page lint: FAIL — scanned {scanned} file(s) under "
            f"{CRATE}, fewer than the {MIN_FILES} that tree has. A checker that "
            f"found nothing to read must not report OK.",
            file=sys.stderr,
        )
        return 1
    if tests_seen == 0:
        print(
            "solo-plane-page lint: FAIL — no test builds a `CaptureReport` at "
            "all. Every plane would then be trivially uncovered, and a gate "
            "that reports the vacuous case as a finding hides the real one.",
            file=sys.stderr,
        )
        return 1

    missing = [p for p in planes if p not in solo]
    if missing:
        print("solo-plane-page lint: FAIL", file=sys.stderr)
        for p in missing:
            print(f"  plane `with_{p}` appears on no page by itself", file=sys.stderr)
        print(
            "\nA report page that attaches two planes gates NEITHER of them: "
            "R311y618\nsevered one leg of `is_complete` and all 229 tests "
            "stayed green, because\nthe other plane on the same page already "
            "produced the verdict.\nAdd a test that builds `CaptureReport::of` "
            "with this plane and no other.",
            file=sys.stderr,
        )
        return 1

    detail = ", ".join(f"{p}={len(solo[p])}" for p in planes)
    print(
        f"solo-plane-page lint: OK ({len(planes)} report plane(s), each on a "
        f"page by itself: {detail}; {tests_seen} report test(s) over "
        f"{scanned} file(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

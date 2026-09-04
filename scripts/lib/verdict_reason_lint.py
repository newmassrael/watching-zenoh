#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y725 (N2) — every `VerdictReason` arrives with a name, a doc and a test.

WHAT THIS GATES. `wz_capture::report::VerdictReason` is the SSOT for what
`complete: false` means: every leg of the verdict is a variant, its `name()` is
a WIRE FORMAT that goes out in the export and, through `wz-replay --alert`, onto
a live deployment's own bus, and its doc comment is the only place a reader
learns what the leg means. R311y716 built the enumeration precisely so a leg
could not be added, removed or absorbed by a neighbour silently. Nothing then
required a new variant to carry any of the three.

WHY IT IS A DEBT AND NOT A PREFERENCE. R311y715 MEASURED the state the
enumeration replaced: nine of the twenty-four boolean guards in `is_complete`
bound nothing, so severing one left every test green. That was found by a sweep
run BY HAND, and a hand-run sweep gates nothing — the register carried this as
N2 for exactly that reason. A variant added tomorrow could ship undocumented,
unnamed and untested, and the only thing that would notice is the same person
who forgot.

THE POPULATION IS READ, NEVER LISTED. The variants come from the enum's own
declaration, so a new one is IN SCOPE the moment it is declared. A hand-kept
list here would have to be updated by whoever forgot the test.

WHAT "BOUND BY A TEST" MEANS, AND WHAT IT DOES NOT. A variant is bound when
`VerdictReason::Variant` appears inside some `#[test]` body in this workspace.
That is a NECESSARY condition and not a sufficient one: a test that names a
variant and asserts nothing about it would satisfy this gate, exactly as
`solo_plane_page_lint` does not claim its solo page is a good page. The shape is
what makes an assertion capable of gating; the assertion is the author's.

THE SUFFICIENT CONDITION IS A DIFFERENT GATE, and it exists:
`verdict_leg_mutation.py` severs each leg in turn and requires a test to redden.
This one is the cheap structural half that runs in Layer C0 on every commit; that
one is the expensive behavioural half. Keep both — the mutation sweep cannot tell
an undocumented variant from a documented one, and this cannot tell a naming test
from an asserting one.

R311y726 REMOVED a second binding path this gate used to accept — the variant's
wire name appearing as a string literal in a verdict-ish test. MEASURED before
removing it: all 23 variants were bound by the code form and NOT ONE relied on
the string form, so the path bound nothing and could only ever have bound
something by accident. A test quoting an unrelated snake_case word would have
satisfied it.

COMMENTS DO NOT COUNT, and that rule is R311y717's, learned the hard way: the
first `discard_site_lint` was satisfied by the word "censused" appearing in a
comment. A gate a comment can satisfy is a gate that scores prose. Comments are
blanked before any match here — in both directions, so a doc comment quoting
`VerdictReason::SnMissing` cannot bind it either.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The declaration this gate reads its population out of.
ENUM_FILE = Path("crates/wz-capture/src/report.rs")
ENUM_NAME = "VerdictReason"

# The enum's opening line, and one variant inside it. Variants here are unit
# variants; a future variant with fields would open with `Name {` and this
# pattern would miss it, which is why `MIN_VARIANTS` below refuses a scan that
# suddenly found fewer.
ENUM_OPEN = re.compile(rf"^\s*pub enum {ENUM_NAME}\s*\{{\s*$", re.M)
VARIANT = re.compile(r"^\s{4}([A-Z]\w*)\s*(?:,|\{|\()")

# `Self::Variant => "wire_name",` inside `name()`.
NAME_ARM = re.compile(r"^\s*Self::(\w+)\s*=>\s*\"([a-z0-9_]+)\"\s*,\s*$", re.M)

# A test function's opening line. Line-oriented and brace-counted rather than a
# regex over the body, for the reason `solo_plane_page_lint` states: a Rust test
# body holds braces inside string literals and closures.
TEST_ATTR = re.compile(r"^\s*#\[test\]\s*$")
FN_OPEN = re.compile(r"^\s*(?:async\s+)?fn\s+(\w+)\s*\(")

# How a test names a variant in CODE. The path prefix varies by crate
# (`crate::report::`, `wz_capture::report::`, or a bare `use`d name), so the
# qualifier is what is matched and the leading path is not.
QUALIFIED = re.compile(rf"{ENUM_NAME}::(\w+)")

# Below these the scan read the wrong tree and must not report OK — the failure
# mode `duplicate_module_lint` shipped with on its first run (0 files, exit 0).
MIN_FILES = 40
MIN_VARIANTS = 20


def blank(seg: str) -> str:
    """`seg` with every non-newline character replaced, so offsets survive."""
    return "".join(c if c == "\n" else " " for c in seg)


def mask(text: str) -> str:
    """Blank comment and string-literal content, keeping line structure.

    Comments go because a gate a comment can satisfy is a gate that scores prose
    (R311y717). String literals go because the brace walk that finds a test body
    would otherwise run past its own end on a `{` inside `"\\"gaps\\":{"` — the
    defect `solo_plane_page_lint` records having been bitten by, where one
    literal swallowed 436 lines and every test behind them.
    """
    out: list[str] = []
    i, n = 0, len(text)
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


def declared(source: str) -> tuple[list[str], dict[str, str]]:
    """`([variant, ...], {variant: wire_name})` read out of the declaration."""
    opened = ENUM_OPEN.search(source)
    if not opened:
        return [], {}
    variants: list[str] = []
    for line in source[opened.end() :].splitlines():
        if line.startswith("}"):
            break
        hit = VARIANT.match(line)
        if hit:
            variants.append(hit.group(1))
    return variants, {v: n for v, n in NAME_ARM.findall(source)}


def undocumented(source: str, variants: list[str]) -> list[str]:
    """Variants whose declaration has no `///` directly above it.

    Read from the RAW source, which is the one place in this gate that wants
    comments: the doc IS the subject here, where everywhere else a comment is
    something to be blanked before matching.
    """
    lines = source.splitlines()
    opened = ENUM_OPEN.search(source)
    start = source[: opened.end()].count("\n") if opened else 0
    missing: list[str] = []
    for at in range(start, len(lines)):
        if lines[at].startswith("}"):
            break
        hit = VARIANT.match(lines[at])
        if not hit or hit.group(1) not in variants:
            continue
        above = lines[at - 1].strip() if at else ""
        if not above.startswith("///"):
            missing.append(hit.group(1))
    return missing


def test_bindings(root: Path) -> tuple[dict[str, list[str]], int, int]:
    """`(variant -> [test names that name it], tests seen, files scanned)`."""
    bound: dict[str, list[str]] = {}
    tests_seen = 0
    scanned = 0
    for path in sorted((root / "crates").rglob("*.rs")):
        # RELATIVE (R2338): whether an ABSOLUTE test means the same thing is a
        # fact about where the tree happens to sit, not about this walk.
        if "target" in path.relative_to(root).parts:
            continue
        scanned += 1
        raw = path.read_text(encoding="utf-8", errors="replace")
        walkable = mask(raw).splitlines()
        i = 0
        while i < len(walkable):
            if not TEST_ATTR.match(walkable[i]):
                i += 1
                continue
            j = i + 1
            while j < len(walkable) and not FN_OPEN.match(walkable[j]):
                j += 1
            if j >= len(walkable):
                break
            name = FN_OPEN.match(walkable[j]).group(1)
            depth = 0
            opened = False
            k = j
            while k < len(walkable):
                code = walkable[k]
                depth += code.count("{") - code.count("}")
                opened = opened or "{" in code
                if opened and depth <= 0:
                    break
                k += 1
            tests_seen += 1
            body_code = "\n".join(walkable[j : k + 1])
            i = k + 1
            rel = path.relative_to(root).as_posix()
            for variant in QUALIFIED.findall(body_code):
                bound.setdefault(variant, []).append(f"{rel}::{name}")
    return bound, tests_seen, scanned


def main() -> int:
    source_path = REPO_ROOT / ENUM_FILE
    if not source_path.is_file():
        print(
            f"verdict-reason lint: FAIL — {ENUM_FILE} is not there. The "
            "population is READ from it, so a scan that cannot find it has "
            "nothing to check and must not report OK.",
            file=sys.stderr,
        )
        return 1
    source = source_path.read_text(encoding="utf-8")
    variants, wire = declared(source)
    if len(variants) < MIN_VARIANTS:
        print(
            f"verdict-reason lint: FAIL — read {len(variants)} variant(s) of "
            f"`{ENUM_NAME}`, fewer than the {MIN_VARIANTS} this enum has had "
            "since R311y716. Either the declaration changed shape (a variant "
            "with fields opens differently) and this scan is now blind, or the "
            "scan is wrong. A gate that lost its population must not pass.",
            file=sys.stderr,
        )
        return 1

    failures: list[str] = []

    unnamed = [v for v in variants if v not in wire]
    for v in unnamed:
        failures.append(
            f"  `{ENUM_NAME}::{v}` has no arm in `name()` — its wire name is "
            "what the export and `wz-replay --alert` publish"
        )
    seen: dict[str, str] = {}
    for v in variants:
        n = wire.get(v)
        if n is None:
            continue
        if n in seen:
            failures.append(
                f"  `{ENUM_NAME}::{v}` and `{ENUM_NAME}::{seen[n]}` both export "
                f"the wire name `{n}` — a consumer cannot tell them apart"
            )
        seen[n] = v

    for v in undocumented(source, variants):
        failures.append(
            f"  `{ENUM_NAME}::{v}` has no doc comment — the doc is the only "
            "place a reader learns what this leg of the verdict means"
        )

    bound, tests_seen, scanned = test_bindings(REPO_ROOT)
    if scanned < MIN_FILES:
        print(
            f"verdict-reason lint: FAIL — scanned {scanned} file(s) under "
            f"crates/, fewer than the {MIN_FILES} this tree has. A checker "
            "that found nothing to read must not report OK.",
            file=sys.stderr,
        )
        return 1
    if tests_seen == 0:
        print(
            "verdict-reason lint: FAIL — no `#[test]` body was walked at all. "
            "Every variant would then be reported unbound, and a gate that "
            "reports the vacuous case as a finding hides the real one.",
            file=sys.stderr,
        )
        return 1

    for v in variants:
        if v in bound:
            continue
        failures.append(
            f"  `{ENUM_NAME}::{v}` is named by no test — no `#[test]` body "
            f"mentions `{ENUM_NAME}::{v}`. R311y715 measured what an unbound "
            "leg costs: severing it left every test green"
        )

    if failures:
        print("verdict-reason lint: FAIL", file=sys.stderr)
        for line in failures:
            print(line, file=sys.stderr)
        print(
            f"\n`{ENUM_NAME}` is the SSOT for what `complete: false` means. A "
            "variant\nwithout a name is invisible to every consumer; without a "
            "doc, unreadable;\nwithout a test, ungated — which is the state "
            "R311y715 found nine legs in.",
            file=sys.stderr,
        )
        return 1

    print(
        f"verdict-reason lint: OK ({len(variants)} `{ENUM_NAME}` variant(s), "
        f"each named, documented and bound by a test; {tests_seen} test(s) "
        f"over {scanned} file(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

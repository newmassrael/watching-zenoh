#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2288 (no register item) -- every refusal the framing loop can return has
a test that fires it, and an unmarked refusal is RED.

## The citation, and why it is the escape hatch rather than a number

This answers the numeric open-debt register's item 610, which lives in the
operator's notes rather than in the store, so `gate_provenance_lint`'s item
grammar cannot resolve it -- `_ITEM` admits `§...`, `N<n>`, a lowercase
`debt-<name>`, `CENSUS` or `no register item`, and a bare `610` is none of
those. `zenoh_c_archive_arm.py` (item 612) and `sn_resolution_words.py`
(item 611) hold the same position: declare the escape hatch on the first line
and name the item in the body, because a citation the lint cannot check is not
a citation. This file opened with `(open-debt item 610)` instead, which parses
as nothing at all, so Layer C0 read it as a gate that names nothing -- and that
red masked the other 97 legs of `layer_c0_test_discipline`.

## The class this exists for, which has now leaked twice

A guard that cannot fire looks exactly like a guard that works. Both compile,
both pass `cargo test`, both read in review as "we handle that case" -- and
neither the compiler nor any lane in this repo can tell them apart, because a
`return LinkEvent::Lost { .. }` is well-typed whether or not any input reaches
it. The cost is not the dead code; it is the false statement the dead code
makes to the next reader about what this program checks.

  * R2268 found one in the pico plane and paid it off there.
  * R2271 found the SAME shape in `poll_framed` while trying to build a control
    group for item 577: the control it wanted -- "a malformed but non-empty
    batch is still fatal" -- could not be written, because the arm it would
    have exercised had no path to being true. It filed item 610 rather than
    deleting quietly, which was right, and R2288 is that item.

Twice is the threshold this repo uses for building an instrument instead of
fixing an instance, so this is the instrument.

## What it checks, and why each direction matters

1. The population is DERIVED from the function body, not listed here. The
   gate parses `poll_framed` out of the source by finding its signature and
   walking braces to its end, then counts every `LinkEvent::Lost` returned
   inside it. A list would have to be edited by the same commit that adds a
   refusal, which is precisely the commit that will forget.

2. Every refusal carries `// REACHED-BY: <test> (<LostCause>)` on a line above
   it. An UNMARKED refusal is RED, never a pass -- the escape hatch this gate
   would otherwise grow is "the marker is optional when it is obvious", and
   item 610's arm looked obvious for two rounds.

3. The named test EXISTS, as a `fn <name>` in the same file. A marker naming a
   test nobody wrote is a sentence, and this repo has measured what sentences
   are worth: they are not re-checked by anyone.

4. The `LostCause` in the marker MATCHES the one the site actually returns.
   Without this the marker degrades into a comment: `PeerClosed` and `OsError`
   exist as separate causes precisely so a caller can tell a peer hanging up
   from the OS failing, and a marker that may name either says nothing about
   which was tested.

5. The named test MENTIONS that cause in its own body. This is the direction
   that keeps a test from being pointed at by a marker while asserting
   something else entirely -- the R2194 shape, where a table of declared
   reasons goes unjudged by any independent derivation.

6. A POPULATION OF ZERO IS A FAILURE. If the function is renamed, moved, or
   restructured past what this parse understands, the honest report is "I could
   not find the subject", not a green run over an empty set. The negative
   result and the dead probe look identical, and this repo has paid for that
   confusion more than once.

## Why a script and not a `#[test]`

The subject is the SOURCE TEXT -- which refusals exist and whether each is
spoken for. A Rust test can assert what the function DOES for an input it
supplies; it structurally cannot enumerate the arms the function contains, so
it can never notice the arm nobody supplied an input for. That gap is the
entire defect item 610 recorded.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
SUBJECT = REPO / "crates" / "wz-runtime-tokio" / "src" / "lib.rs"
FUNCTION = "poll_framed"

SIGNATURE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?async fn " + FUNCTION + r"\b", re.M)
REFUSAL = re.compile(r"return\s+LinkEvent::Lost\s*\{")
CAUSE = re.compile(r"cause:\s*LostCause::(\w+)")
MARKER = re.compile(r"//\s*REACHED-BY:\s*(\w+)\s*\(\s*(\w+)\s*\)")


def function_body(text: str) -> tuple[int, int]:
    """Byte span of `poll_framed`'s body, derived by walking braces.

    Deliberately not a regex over the whole function: the body contains string
    literals and nested blocks, and a regex that stops at the first `}` would
    silently shrink the population -- the failure mode this gate exists to
    prevent, turned on the gate itself.
    """
    sig = SIGNATURE.search(text)
    if not sig:
        raise SystemExit(
            f"framing-refusal-gate: FAIL -- no `async fn {FUNCTION}` in "
            f"{SUBJECT.relative_to(REPO)}. The subject moved or was renamed; "
            f"a gate that cannot find its subject must not report green."
        )
    open_brace = text.find("{", sig.end())
    if open_brace < 0:
        raise SystemExit("framing-refusal-gate: FAIL -- no body brace after the signature")
    depth = 0
    i = open_brace
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return open_brace, i
        i += 1
    raise SystemExit("framing-refusal-gate: FAIL -- unbalanced braces walking the body")


def defined_functions(text: str) -> set[str]:
    return set(re.findall(r"\bfn\s+(\w+)", text))


def test_body(text: str, name: str) -> str | None:
    """The source of `fn <name>`, brace-walked, so check 5 reads the real body."""
    m = re.search(r"\bfn\s+" + re.escape(name) + r"\b", text)
    if not m:
        return None
    open_brace = text.find("{", m.end())
    if open_brace < 0:
        return None
    depth = 0
    i = open_brace
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace : i + 1]
        i += 1
    return None


def audit(text: str) -> list[str]:
    start, end = function_body(text)
    body = text[start:end]
    known = defined_functions(text)
    failures: list[str] = []
    sites = list(REFUSAL.finditer(body))

    # Check 6 -- the population guard. A parse that finds nothing is a broken
    # parse, not a clean function: this loop has always been able to refuse.
    if not sites:
        failures.append(
            f"no `return LinkEvent::Lost` found inside {FUNCTION} -- either the "
            f"refusals moved or this parse stopped understanding the body. A "
            f"population of zero is not a pass."
        )
        return failures

    for site in sites:
        line_no = text[:start].count("\n") + body[: site.start()].count("\n") + 1
        cause_m = CAUSE.search(body, site.end())
        actual = cause_m.group(1) if cause_m else None

        # The marker sits on the lines immediately above the `return`.
        preceding = body[: site.start()].rsplit("\n", 4)[-4:]
        marker = None
        for line in reversed(preceding):
            hit = MARKER.search(line)
            if hit:
                marker = hit
                break

        if marker is None:
            failures.append(
                f"line {line_no}: a `LinkEvent::Lost` refusal with no "
                f"`// REACHED-BY: <test> ({actual})` marker above it. An "
                f"unclassified refusal is RED: item 610 was an arm that looked "
                f"handled and could not fire."
            )
            continue

        named, declared = marker.group(1), marker.group(2)

        if named not in known:
            failures.append(
                f"line {line_no}: marker names `{named}`, which is not a "
                f"function in this file. A marker pointing at no test is prose."
            )
            continue

        if actual is None:
            failures.append(f"line {line_no}: refusal has no `LostCause::` to compare the marker against")
            continue

        if declared != actual:
            failures.append(
                f"line {line_no}: marker declares `{declared}` but the site "
                f"returns `LostCause::{actual}`."
            )
            continue

        tb = test_body(text, named)
        if tb is None:
            failures.append(f"line {line_no}: could not read the body of `{named}`")
        elif f"LostCause::{actual}" not in tb:
            failures.append(
                f"line {line_no}: `{named}` never mentions `LostCause::{actual}`, "
                f"so nothing ties it to the refusal that names it."
            )

    return failures


def selftest() -> int:
    """Drive both verdicts against MUTATED copies of the real source.

    ⛔ The fixtures are derived from the file the gate actually reads, not
    hand-written -- a fixture written to match the parser tests the parser
    against itself. Each mutation is a shape the PRE-R2288 tree contained or
    would have accepted, so a gate that swallowed any of them would have let
    item 610 stand.
    """
    text = SUBJECT.read_text(encoding="utf-8")
    if audit(text):
        print("framing-refusal-gate selftest: FAIL -- the live source is already red")
        return 1

    cases: list[tuple[str, str]] = []

    # M1: a refusal with its marker stripped -- item 610's own shape.
    cases.append(("unmarked refusal", re.sub(r"\n\s*//\s*REACHED-BY:[^\n]*", "", text, count=1)))

    # M2: a marker naming a test nobody wrote.
    cases.append(
        (
            "marker names a nonexistent test",
            text.replace("REACHED-BY: a_stream_that_ends_before_the_prefix_loses_the_link", "REACHED-BY: no_such_test", 1),
        )
    )

    # M3: a marker whose cause disagrees with the site.
    cases.append(
        (
            "marker cause disagrees with the site",
            text.replace(
                "// REACHED-BY: an_io_error_reading_the_prefix_loses_the_link (OsError)",
                "// REACHED-BY: an_io_error_reading_the_prefix_loses_the_link (PeerClosed)",
                1,
            ),
        )
    )

    # M4: a NEW refusal added the way a future round would add one.
    cases.append(
        (
            "a newly added refusal",
            text.replace(
                "                    Ok(n) => {\n                        *offset += n;\n                    }",
                "                    Ok(n) if n == 999 => {\n"
                "                        return LinkEvent::Lost {\n"
                "                            cause: LostCause::OsError,\n"
                "                        };\n"
                "                    }\n"
                "                    Ok(n) => {\n                        *offset += n;\n                    }",
                1,
            ),
        )
    )

    # M5: the subject renamed -- the population guard, check 6.
    cases.append(("subject renamed away", text.replace("async fn poll_framed", "async fn poll_framed_renamed")))

    rc = 0
    for name, mutated in cases:
        if mutated == text:
            print(f"framing-refusal-gate selftest: FAIL -- mutation '{name}' changed nothing (dead probe)")
            rc = 1
            continue
        try:
            found = audit(mutated)
        except SystemExit as exc:
            found = [str(exc)]
        if found:
            print(f"framing-refusal-gate selftest: mutation '{name}' -> RED (correct)")
        else:
            print(f"framing-refusal-gate selftest: FAIL -- mutation '{name}' passed the gate")
            rc = 1
    return rc


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selftest":
        return selftest()
    if len(argv) > 1:
        print(f"framing-refusal-gate: unknown argument {argv[1]!r}", file=sys.stderr)
        return 2

    text = SUBJECT.read_text(encoding="utf-8")
    failures = audit(text)
    if failures:
        print("framing-refusal-gate: FAIL")
        for f in failures:
            print(f"  {f}")
        print(
            "  Every refusal this framing loop can return must name the test "
            "that fires it. Add the test and the `// REACHED-BY:` marker, or "
            "remove the refusal -- an arm that cannot fire is open-debt 610."
        )
        return 1

    start, end = function_body(text)
    n = len(REFUSAL.findall(text[start:end]))
    print(f"framing-refusal-gate: pass -- {n} refusal(s) in {FUNCTION}, each named by a test that fires it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

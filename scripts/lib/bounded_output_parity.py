#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y887 (debt-bounded-output-parity) — pin that EVERY BOUNDED READ SAYS
WHAT ITS CEILING COST.

## The failure this ends

wz has three doors that read a capture under `DissectionLimits`, and one
command-line flag. Each of them emits a document carrying `dropped_by_limits`,
the five counters that say what staying inside the ceilings threw away, and
each of them does so because a test written in the round it landed says so:

  * R311y748 for the bounded summary, and its group was asserted a round later;
  * R311y885 for the bounded census, which had NO such group until that round —
    a plane made short by an evicted flow read exactly like a quiet network;
  * R311y885 again for `wz-analyze --bounded`, whose group rode `--health`, so
    the combination a person actually types said nothing at all.

That is three habits, not a rule. A FOURTH door added without its own test is
silent again, and silent in the way that is hardest to notice: the document
comes back, the planes are short, and nothing in it is wrong — there is simply
no sentence saying a ceiling bit. R311y885's own residue said so and this file
is the answer to it.

`analysis_surface_parity.py` is the gate for which SURFACE reaches a capability.
This is the gate for what that capability's OUTPUT must contain, which is one
layer in, and it is deliberately the same shape: a table nobody can leave
un-updated, failing in BOTH directions.

## What it checks

1. Every entry point that builds a BOUNDED dissection is named in the table.
   The population is read from the code — a function whose body calls
   `from_capture_bounded` / `from_capture_declaring_bounded` — and not from a
   naming convention, because `wz_dissect_pcap_census_where_limited` takes its
   ceiling as an ARGUMENT and no `_bounded` suffix would have found it.
2. Every row names a door that still exists.
3. Every row names a TEST that exists and whose body asserts on
   `dropped_by_limits`. A row whose test was renamed away is a row that has
   stopped holding anything.
4. Every EMITTER a bounded door writes through renders the group at all. This
   is the half a per-door test cannot see: all three doors could pass their own
   assertions against one emitter and a fourth document could still have no
   group to carry.

## What it deliberately does NOT check

That the counters are CORRECT. That is what the pinned tests do, off a capture
whose 1 025 flows put one past the live-tap ceiling; a static reader cannot
evaluate arithmetic and should not pretend to. This gate answers "is there a
door that could bite and say nothing", which is the question that goes
unasked between rounds.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CAPI = ROOT / "crates" / "wz-capi-dissect" / "src" / "lib.rs"
CLI = ROOT / "crates" / "wz-analyze" / "src" / "lib.rs"
CAPTURE_REPORT = ROOT / "crates" / "wz-capture" / "src" / "report.rs"
CAPTURE_CENSUS = ROOT / "crates" / "wz-capture" / "src" / "census_json.rs"

# The group every bounded read's document must carry, spelled as the JSON KEY
# appears in Rust source — quotes included.
#
# R311y887 — the quotes are load-bearing and were added after the emitter damage
# probe went green TWICE. A bare `dropped_by_limits` is a substring of
# `dropped_by_limits_json`, the emitter FUNCTION, so a body that renamed the key
# it writes while still calling that function satisfied the check by the call.
# The gate must look for what the DOCUMENT carries, and only the quoted form is
# that.
GROUP = "dropped_by_limits"
GROUP_KEY = r"\"dropped_by_limits\""

# The constructors that build a dissection under caps. A function calling one
# of these is a door this gate has an opinion about.
BOUNDED_CTORS = ("from_capture_bounded", "from_capture_declaring_bounded")

# door -> (file holding its test, test function name, one-line note)
#
# The note is the deliverable, same as in `analysis_surface_parity.py`: it says
# which document the door emits and therefore which emitter has to carry the
# group.
DOORS = {
    "wz_dissect_pcap_summary_bounded": (
        CAPI,
        "the_bounded_door_reports_a_bound_that_bit",
        "emits the SUMMARY document; the group rides its `health` object.",
    ),
    "wz_dissect_pcap_census_bounded": (
        CAPI,
        "the_census_reports_what_its_caps_cost",
        "emits the CENSUS document, which gained the group in R311y885 — it "
        "had none, so this door would have bitten in silence.",
    ),
    "wz_dissect_pcap_census_where_limited": (
        CAPI,
        "a_narrowed_census_can_be_bounded_and_says_what_the_bound_cost",
        "emits the census NARROWED by a selector, under a preset passed as an "
        "argument. Found by its CONSTRUCTOR and not by its name, which is why "
        "the population rule here is not a suffix match.",
    ),
    "--bounded": (
        CLI,
        "a_bound_is_never_silent_even_without_the_health_flag",
        "the command line's flag. The group rides `--bounded` itself and not "
        "`--health`, because asking for a ceiling is asking to be told when it "
        "bites.",
    ),
}

# The emitters a bounded door's document is written by. Each must render the
# group; a door pointed at an emitter that does not is silent whatever its own
# test says.
EMITTERS = {
    CAPTURE_REPORT: ("health_json", "the summary document's health object"),
    CAPTURE_CENSUS: ("census_json_where", "the census document"),
}


def _strip_comments(text: str) -> str:
    """Drop whole-line `//` and `///` lines.

    R311y887 — this gate's FIRST finding was its own, and it came from here.
    A slice that runs to the next function's marker also holds that function's
    DOC COMMENT, and `wz_dissect_pcap_census_bounded`'s doc names
    `Dissection::from_capture_bounded` in prose. So the unbounded census door
    was reported as bounded: a population read off text that mentions a
    constructor rather than off code that calls one.

    Dropping comment LINES is enough and is deliberately not a tokenizer. A
    comment naming a constructor must not count — a door is bounded because it
    calls one, and prose about a sibling is exactly the evidence this gate was
    fooled by once.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("//")
    )


def _extern_c_bodies(src: str) -> dict[str, str]:
    """Every `extern "C"` function in `src`, sliced to the next one, comments
    removed.

    Slicing between markers rather than brace-matching on purpose: the bodies
    here hold Rust format strings full of `{{`, and a brace counter that has to
    know about those is a parser this gate does not need. The last function runs
    to the test module, which is where the file's `extern "C"` items stop.
    """
    marks = [
        (m.start(), m.group(1))
        for m in re.finditer(r'pub (?:unsafe )?extern "C" fn (wz_[a-z_0-9]+)', src)
    ]
    end = src.find("\nmod tests {")
    if end < 0:
        end = len(src)
    bodies: dict[str, str] = {}
    for i, (at, name) in enumerate(marks):
        stop = marks[i + 1][0] if i + 1 < len(marks) else end
        bodies[name] = _strip_comments(src[at:stop])
    return bodies


def _fn_body(src: str, name: str) -> str | None:
    """One `fn name(` and everything up to the next `fn` at any indent, COMMENTS
    REMOVED.

    R311y887 — the comment stripping is here because the damage probe for the
    emitter arm went GREEN without it. `census_json_where`'s body carries the
    line "It is the SAME rendering `health_json` embeds
    (`report::dropped_by_limits_json`)", and that comment contains the very
    substring this gate searches for — so renaming the emitted KEY left the arm
    satisfied by prose explaining the key. That is this workspace's measured
    shape: a text-driven check contented by a comment about the thing rather
    than the thing.
    """
    m = re.search(rf"\bfn {re.escape(name)}\s*\(", src)
    if m is None:
        return None
    rest = src[m.end() :]
    nxt = re.search(r"\n\s*(?:pub )?(?:async )?fn ", rest)
    return _strip_comments(rest[: nxt.start()] if nxt else rest)


def main() -> int:
    capi = CAPI.read_text()
    cli = CLI.read_text()

    # (1) THE POPULATION, read from the code.
    found: set[str] = set()
    for name, body in _extern_c_bodies(capi).items():
        if any(ctor in body for ctor in BOUNDED_CTORS):
            found.add(name)
    # The command line has one bounded arm rather than a door per document: it
    # builds ONE dissection and every document folds over it. The flag is the
    # thing a person reaches for, so the flag is what the table names.
    if any(ctor in _strip_comments(cli) for ctor in BOUNDED_CTORS):
        found.add("--bounded")

    if not found:
        print(
            "bounded-output-parity: FAIL -- found NO bounded reader in either "
            "surface. An empty population is indistinguishable from total "
            "compliance, so it cannot pass; the constructor names this gate "
            "looks for have probably been renamed.",
            file=sys.stderr,
        )
        return 1

    findings: list[str] = []

    # (2) both directions between the code and the table.
    for door in sorted(found - set(DOORS)):
        findings.append(
            f"`{door}` builds a bounded dissection and this table does not name "
            f"it. Add it with the test that asserts its document carries "
            f"`{GROUP}` -- a door that can bite and cannot say so is the whole "
            f"reason this gate exists"
        )
    for door in sorted(set(DOORS) - found):
        findings.append(
            f"the table names `{door}` and no bounded reader by that name is "
            f"left in the source -- the row is stale"
        )

    # (3) every row's test exists and asserts on the group.
    for door, (path, test, _note) in sorted(DOORS.items()):
        if door not in found:
            continue  # already reported as stale above
        body = _fn_body(path.read_text(), test)
        if body is None:
            findings.append(
                f"`{door}`'s row names test `{test}`, which is not in "
                f"{path.name} -- a renamed test holds nothing"
            )
        elif GROUP_KEY not in body:
            findings.append(
                f"`{door}`'s row names test `{test}` and that test does not "
                f"assert on the `{GROUP}` KEY. It may still assert something "
                f"true; it is not asserting the thing this row claims"
            )

    # (4) the emitters render the group at all.
    for path, (fn, what) in sorted(EMITTERS.items(), key=lambda kv: kv[0].name):
        body = _fn_body(path.read_text(), fn)
        if body is None:
            findings.append(
                f"`{fn}` is not in {path.name}, so {what} has no emitter this "
                f"gate can read"
            )
        elif GROUP_KEY not in body:
            findings.append(
                f"`{fn}` in {path.name} does not render the `{GROUP}` KEY, so "
                f"{what} cannot say what a ceiling cost however many doors are "
                f"pinned"
            )

    if findings:
        print("bounded-output-parity: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print(
            f"\n  Edit {pathlib.Path(__file__).name} in the same commit as the "
            f"change.",
            file=sys.stderr,
        )
        return 1

    print(
        f"  bounded-output-parity: {len(found)} bounded reader(s), each pinned to a "
        f"test that asserts `{GROUP}`; {len(EMITTERS)} emitter(s) render it"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

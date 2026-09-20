#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2753 (no register item) -- a DIFFERENTIAL test must not grade a side against
an INTEGER LITERAL when the other side is standing in the same function.

The citation is `no register item` in the sense this convention uses: the class
had none. That is the finding rather than an omission -- nothing in this tree
asked whether the sentence justifying a pinned value was still true, so there
was no item to answer for, and this gate is what makes the class answerable.

THE DEFECT, and why a month of hosted runs could not see it.

`pico_zscout_source_on_wz_capi_matches_the_real_pico_against_a_zenohd` runs
upstream's `z_scout.c` twice -- once linked to wz's cdylib, once to the REAL
`libzenohpico.so` -- against one router, in one window. It then counted wz's
Hello lines and asserted `== 1`.

`1` was TRUE when it was written. The doc paragraph above it said why, in prose:
wz emitted one Scout for the whole budget, so one responder produced one line.
A month later a commit made wz ask on every multicast-capable interface --
deliberately, because both references do -- and on a multi-homed host the
responder answers each ask. The count became 3 and the assertion became wrong,
while the oracle's output sat in a variable one line above, uncounted.

Nothing connected the two. A value-pin gate asks whether the VALUE still
matches; no gate here asks whether the SENTENCE that justified the value is
still true, and a sentence cannot be graded. So the repair is not to grade
prose. It is to notice that a differential test reaching for a literal is
reaching PAST an answer it could have computed, and that reaching past it is
the mechanical fact this gate can see.

A consumer found it. Their lane ran on a multi-homed host; this tree's CI runner
has one interface, where the count is 1, the literal keeps holding, and the axis
is invisible by construction. That is not a gap in the runner -- it is why the
check has to be structural rather than empirical.

THE POPULATION IS DERIVED FROM BOTH SIDES, which is the whole design.

  SIDES     = the subjects a test fn holds two of. Derived: any helper applied
              to TWO DISTINCT subjects pairs them, so `h(&a, ..)` and `h(&b, ..)`
              make {a, b} the sides. Never a naming convention -- `oracle` and
              `wz` are spellings, and a gate keyed on spellings grades the
              spelling.
  GRADED    = a binding produced by applying ANY helper to ONE of those sides.
  OFFENDER  = `assert_eq!(<graded>, <integer literal>)`.

An EMPTY population is a FAILURE, not a pass. A scan that finds no differential
test has lost its subject -- this crate is where they live -- and reporting OK
from there is the "population of zero reports green" trap this tree refuses
elsewhere.

⚠⚠ THE FIRST DESIGN WAS REFUTED BY ITS OWN CONTROL, and the refutation is why
the rule reads as it does. That draft required the GRADED binding's helper to be
the twice-applied one. Run against the tree as it stood before the repair -- the
tree that provably carried the defect -- it reported ZERO offenders, because the
counting helper had been applied to ONE side only. That IS the defect: the
missing second application is the thing being complained about, so a rule that
demands it can never see the case. The pairing and the grading are therefore
separate questions here: one helper establishes that two sides exist, and any
helper's binding over either side is then gradeable against its twin.

⚠ WHAT THIS GATE DELIBERATELY DOES NOT CLAIM. It does not say a literal is
always wrong: a differential test may legitimately pin a fact about its own
fixture, and those bindings are not produced from a paired side, so they are
outside the population by construction rather than by exception.

⚠ THE SIDES SET IS OVER-INCLUSIVE, MEASURED RATHER THAN GUESSED. Any helper
over two subjects pairs them, and that includes incidental ones -- a process
builder taking `.arg(&a)` and `.arg(&b)` pairs the two paths as well. So `sides`
holds more than the two outputs a reader would name. That direction is the safe
one (it widens what can be complained about, never narrows it), and it is
measured: over the 190 differential fns in this crate it yields ZERO offenders
once the two real ones are repaired. It is recorded here instead of tightened
because the tightening that suggests itself -- demand the pairing helper be the
grading one -- is exactly the refuted first design above.

⚠ The finding is scoped to the fn body that holds both sides, which is why the
scan brace-matches bodies instead of reading the file as lines -- a literal in a
helper fn with no second side is not a finding.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Where differential tests live. A DIRECTORY, not a file list: a new
#: differential leg is adopted by this gate the moment it lands.
TEST_DIR = pathlib.Path("crates/wz-integration-tests/tests")

#: `fn name(` -- the signature that opens a body. Async and plain alike.
_FN = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*\(")

#: `helper(&subject` -- one application of a helper to a subject held by the fn.
_APPLY = re.compile(r"\b([A-Za-z_]\w*)\s*\(\s*&([A-Za-z_]\w*)")

#: `let binding = helper(&subject` -- the binding that carries one side.
_BIND = re.compile(r"\blet\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\(\s*&([A-Za-z_]\w*)")

#: `assert_eq!(binding, 12` -- grading a side against an integer literal.
_GRADE = re.compile(r"\bassert_eq!\s*\(\s*([A-Za-z_]\w*)\s*,\s*(\d+)\s*[,)]")


def _bodies(text: str) -> list[tuple[str, str]]:
    """Every `fn` body in `text`, brace-matched, as (name, body)."""
    out: list[tuple[str, str]] = []
    for m in _FN.finditer(text):
        open_at = text.find("{", m.end())
        if open_at < 0:
            continue
        depth = 0
        for i in range(open_at, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    out.append((m.group(1), text[open_at : i + 1]))
                    break
    return out


def paired_sides(body: str) -> set[str]:
    """The subjects this body holds two of, derived from any twice-applied helper.

    The helper that PAIRS need not be the helper that GRADES -- see the module
    doc's refutation paragraph, which is this function's whole reason for being
    separate from the grading step.
    """
    seen: dict[str, set[str]] = {}
    for helper, subject in _APPLY.findall(body):
        seen.setdefault(helper, set()).add(subject)
    sides: set[str] = set()
    for subjects in seen.values():
        if len(subjects) >= 2:
            sides |= subjects
    return sides


def scan(root: pathlib.Path) -> tuple[int, list[str]]:
    """(differential fn count, offenders). Raises SystemExit on a lost subject."""
    test_dir = root / TEST_DIR
    if not test_dir.is_dir():
        print("differential-literal: FAIL -- %s does not exist, so this scan has "
              "no subject; a gate that cannot read its population must not "
              "report OK" % TEST_DIR, file=sys.stderr)
        raise SystemExit(2)

    population = 0
    offenders: list[str] = []
    for path in sorted(test_dir.rglob("*.rs")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for fn_name, body in _bodies(text):
            sides = paired_sides(body)
            if not sides:
                continue
            population += 1
            graded: dict[str, tuple[str, str]] = {}
            for binding, helper, subject in _BIND.findall(body):
                if subject in sides:
                    graded[binding] = (helper, subject)
            for binding, literal in _GRADE.findall(body):
                if binding in graded:
                    helper, subject = graded[binding]
                    offenders.append(
                        "%s::%s -- `assert_eq!(%s, %s)` grades `%s(&%s, ..)` "
                        "against a literal while this fn also holds %s"
                        % (path.relative_to(root), fn_name, binding, literal,
                           helper, subject,
                           ", ".join(sorted(sides - {subject})))
                    )
    return population, offenders


def check(root: pathlib.Path) -> int:
    population, offenders = scan(root)
    print("  differential-literal: %d differential test fn(s) read" % population)
    if population == 0:
        print("differential-literal: FAIL -- the population is EMPTY. This crate "
              "is where differential tests live, so an empty population means "
              "the derivation stopped matching the tree, not that the tree is "
              "clean. Fix the predicate; never read this as OK.", file=sys.stderr)
        return 1
    for line in offenders:
        print("  differential-literal: %s" % line, file=sys.stderr)
    if offenders:
        print("differential-literal: FAIL -- %d side(s) graded against a literal. "
              "Compute the other side with the same helper and compare against "
              "it; a literal cannot notice that the sentence justifying it "
              "expired, and that is how R2753's month-old `== 1` survived."
              % len(offenders), file=sys.stderr)
        return 1
    print("differential-literal: OK -- every differential leg grades against its "
          "own other side")
    return 0


def selftest() -> int:
    #: What makes a body differential: ONE helper over TWO subjects.
    PAIR = ("    let la = line_for(&wz_out, p).unwrap();\n"
            "    let lb = line_for(&oracle_out, p).unwrap();\n")

    cases = [
        ("THE REAL SHAPE — a DIFFERENT helper over ONE paired side, graded "
         "against a literal, is an OFFENDER",
         "fn t() {\n" + PAIR + "    let a = lines_for(&wz_out, p).count();\n"
         "    assert_eq!(a, 1, \"x\");\n}\n", 1, 1),
        ("the same helper over BOTH sides, compared to each other, is not",
         "fn t() {\n" + PAIR + "    let a = lines_for(&wz_out, p).count();\n"
         "    let b = lines_for(&oracle_out, p).count();\n"
         "    assert_eq!(a, b, \"x\");\n}\n", 1, 0),
        ("a floor on the other side is not a grade against a side",
         "fn t() {\n" + PAIR + "    let b = lines_for(&oracle_out, p).count();\n"
         "    assert!(b >= 1, \"x\");\n}\n", 1, 0),
        ("a literal about something NOT taken from a paired side is outside",
         "fn t() {\n" + PAIR + "    let n = parts.len();\n"
         "    assert_eq!(n, 3, \"x\");\n}\n", 1, 0),
        ("ONE subject is not a pair, so its literal is outside",
         "fn t() {\n    let la = line_for(&wz_out, p).unwrap();\n"
         "    let a = lines_for(&wz_out, p).count();\n"
         "    assert_eq!(a, 1, \"x\");\n}\n", 0, 0),
        ("two subjects in DIFFERENT fns do not pair either",
         "fn t() {\n    let la = line_for(&wz_out, p).unwrap();\n"
         "    let a = lines_for(&wz_out, p).count();\n"
         "    assert_eq!(a, 1, \"x\");\n}\n"
         "fn u() {\n    let lb = line_for(&oracle_out, p).unwrap();\n}\n", 0, 0),
    ]

    failures = 0
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="wz-diflit-selftest-"))
    try:
        (tmp / TEST_DIR).mkdir(parents=True, exist_ok=True)
        for name, body, want_pop, want_off in cases:
            (tmp / TEST_DIR / "case.rs").write_text(body, encoding="utf-8")
            pop, offenders = scan(tmp)
            ok = (pop == want_pop) and (len(offenders) == want_off)
            if not ok:
                print("  selftest FAIL  %s: population=%d want %d, offenders=%d "
                      "want %d" % (name, pop, want_pop, len(offenders), want_off))
                failures += 1
            else:
                print("  selftest ok    %s" % name)

        # An EMPTY population must FAIL rather than read as clean.
        (tmp / TEST_DIR / "case.rs").write_text("fn t() {\n    let x = 1;\n}\n",
                                                encoding="utf-8")
        if check(tmp) == 0:
            print("  selftest FAIL  an empty population must not report OK")
            failures += 1
        else:
            print("  selftest ok    an empty population FAILs")

        # A subject this gate cannot read at all must FAIL, never pass silently.
        shutil.rmtree(tmp / TEST_DIR)
        try:
            scan(tmp)
            print("  selftest FAIL  a missing test directory must not be a pass")
            failures += 1
        except SystemExit:
            print("  selftest ok    a test directory this gate cannot read FAILs")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("differential-literal selftest: %d failure(s)" % failures)
        return 1
    print("differential-literal selftest OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="read the real tree")
    ap.add_argument("--selftest", action="store_true", help="drive the verdicts")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.check:
        return check(ROOT)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

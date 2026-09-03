#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2293 (no register item) — a test whose ORACLE cannot construct the input
its branch needs measures nothing, and until this round nothing said so.

The citation is `no register item` for the reason `config_key_fixture_gate.py`
and `debt_plane_census.py` give for theirs: the item this closes --
unregistered open-debt item 625 -- lives in the operator's register file
outside this repository, not under the store's `debt-` prefix, so there is no
id here for `--emit` to resolve.

## The instance the class was found in

R2289 ran ten mutations against the SHM provider plane. Nine were caught. The
survivor was `wz-capi-c/src/shm.rs`'s
`a_backend_that_under_delivers_is_refused_and_the_chunk_returned`: deleting wz's
`descriptor.len < size` check left it GREEN, because the test harness's own
`alloc_fn` refused the oversized request FIRST. The branch under test was never
entered. The test answered the same whether the code existed or not, and the
only signal that anything was wrong was the mutation that passed.

The repair was not a stronger assertion. It was a HARNESS that could misbehave
(`under_deliver`), plus an assertion INSIDE the same test that the harness had
actually been asked (`alloc_calls == 1`).

## What this gate measures, and why it is derived rather than listed

The population is not "tests" and not "branches" -- item 625's own steer is to
derive from the set of inputs the ORACLE can construct. So:

* A KNOB is a `bool` field on a struct declared inside a `#[cfg(test)]` module
  which the module's NON-test code reads. "Non-test code" is the test double
  itself -- the callback the production path calls back into -- so a bool it
  branches on is, by construction, a switch on what inputs the oracle can
  produce. An ordinary bool that only test bodies touch is not a knob and is
  not in the population.
* A RECORD is a counter or log field on a struct in that same module: `usize`,
  `u32`, `u64`, `AtomicUsize`, or a `Vec<..>`. These are what the double writes
  down about what it was asked.

ONE rule, in the direction that makes a vacuous test loud:

* Every `#[test]` that sets a knob READS at least one record in its own body.
  A test that configures its double to misbehave and then never asks whether
  the double was called cannot tell "the code under test refused" from "the
  fixture refused" -- which is exactly what the survivor could not tell.

A population of zero FAILS. That is the trap this whole gate is about, so it
must not be the way it reports success.

## The rule this gate does NOT carry, and why -- measured, R2293

The first draft also required every knob to be SET by some test, on the
argument that a knob nobody sets is a branch of the oracle nobody reaches. Run
against the tree it reported five, and every one was a FALSE POSITIVE: a knob
given its interesting value through a STRUCT LITERAL (`decode_ok: false`)
rather than through a field assignment. Widening the setter pattern to include
literals does not rescue the rule, it destroys it -- every field of every
struct literal is "set", including to the value that reaches nothing, and the
rule can no longer fail. Deciding which literal value is the interesting one
needs the default, and the default is not derivable from the source shape.

So the rule is gone rather than exempted. What is left is the half that IS
soundly derivable, which is also the half item 625's instance is about.

## What it does NOT reach, stated rather than implied

⚠ IT WOULD NOT HAVE CAUGHT R2289'S SURVIVOR. That draft had no knob at all --
the harness simply refused, and `under_deliver` did not exist yet -- so there
was nothing for this derivation to see. What this gate holds is the REPAIR and
every knob-configured test written after it: once a double can misbehave, the
test that switches it on must say the double was asked. The class's first
instance is caught by the mutation that found it, not by a static rule; that is
the honest half, and item 625 asks for it to be written down.

The roster is "bools the double branches on", which is a SUPERSET of
misbehaviour knobs -- a double's own one-shot state flag lands in it too. The
rule only bites on the ones a `#[test]` configures, so the superset costs
nothing and keeps the derivation off a judgement about intent.

The general form of item 625 is mutation testing over the suite, and this is
not that. This gate sees only doubles that switch on A BOOL FIELD; a double
that refuses unconditionally, or switches on an enum, or is a closure captured
per test, is outside its derivation. The item says as much, and puts the
general instrument on the same line as open-debt item 374.
"""

import re
import subprocess
import sys

# One test scope: `#[cfg(test)]` on the line(s) before a `mod <name> {`.
# `#[cfg(all(test, ..))]` counts too -- the shape that guards a module needing
# more than `test` alone, which several crates here use.
TEST_MOD_RE = re.compile(
    r"#\[cfg\((?:test|all\(\s*test\b[^)]*\))\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{"
)

# A `#[test]` (or `#[tokio::test]`) function's opening brace.
TEST_FN_RE = re.compile(r"#\[(?:\w+::)?test\b[^\]]*\]\s*(?:(?:async|pub|unsafe)\s+)*fn\s+(\w+)\s*\([^)]*\)\s*(?:->[^{]+)?\{")

# One field per line, which is what rustfmt produces and therefore what every
# tracked file here looks like. The trailing comma is optional so a struct's
# LAST field is still seen -- rustfmt writes one, but a fixture need not.
BOOL_FIELD_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*bool\s*(?:,|$)", re.M)
RECORD_FIELD_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*"
    r"(?:usize|u32|u64|AtomicUsize|Vec\s*<)",
    re.M,
)


def strip_comments(text):
    """Blank out `//` and `/* */` comments, preserving offsets and newlines.

    Offsets are preserved because every downstream span (module bodies, test
    bodies) is computed on this same string; replacing a comment with spaces
    keeps every later index valid.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 0
            while i < n:
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    if depth == 0:
                        break
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def span_from_brace(text, open_idx):
    """`(start, end)` of the body whose `{` is at `open_idx`, exclusive of it."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return open_idx + 1, i
        i += 1
    return open_idx + 1, n


def test_scopes(text):
    """Every `#[cfg(test)] mod ..` body span in `text`."""
    return [
        span_from_brace(text, m.end() - 1)
        for m in TEST_MOD_RE.finditer(text)
    ]


def test_fns(text, start, end):
    """`(name, body_start, body_end)` for each `#[test]` fn inside a span."""
    out = []
    for m in TEST_FN_RE.finditer(text, start, end):
        b_start, b_end = span_from_brace(text, m.end() - 1)
        out.append((m.group(1), b_start, b_end))
    return out


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def scan_file(path, text):
    """`(findings, knobs)` for one file.

    `knobs` is the roster itself rather than a count, so `--list` can print
    WHICH knobs the derivation reached. A number alone is the shape this tree
    keeps getting caught by: 8 is indistinguishable from 8 of the wrong thing.
    """
    stripped = strip_comments(text)
    findings = []
    knobs_seen = []
    for start, end in test_scopes(stripped):
        scope = stripped[start:end]
        bools = set(BOOL_FIELD_RE.findall(scope))
        records = set(RECORD_FIELD_RE.findall(scope))
        if not bools:
            continue
        fns = test_fns(stripped, start, end)
        # Text of the scope with every `#[test]` body blanked: what is left is
        # the double's own code, so a bool read here is a branch on the oracle.
        outside = list(scope)
        for _, b_start, b_end in fns:
            for i in range(b_start - start, b_end - start):
                if outside[i] != "\n":
                    outside[i] = " "
        outside = "".join(outside)

        for field in sorted(bools):
            # READ by the double, in a non-assignment position. `self.x = true`
            # inside the double is the double RECORDING something, not
            # branching on it, and counting that as a knob is what made the
            # first draft report five false positives.
            # The lookahead must swallow the whitespace ITSELF: written as
            # `\b\s*(?!=..)` the `\s*` backtracks to zero and the lookahead
            # then sees a space instead of the `=`, so every assignment matched
            # anyway. Measured on the `recorded-bool` selftest fixture.
            read_re = re.compile(r"\.\s*" + re.escape(field) + r"\b(?!\s*=[^=])")
            if not read_re.search(outside):
                continue  # not read by the double: an ordinary test-local bool
            set_re = re.compile(r"\w+\s*\.\s*" + re.escape(field) + r"\s*=\s*(?:true|false)\s*;")
            setters = []
            for name, b_start, b_end in fns:
                body = stripped[b_start:b_end]
                if set_re.search(body):
                    setters.append((name, body))
            # The roster carries the SETTER COUNT, because that -- not the knob
            # count -- is what this gate actually graded. A knob no test
            # configures passes the rule by having nothing to check, and a
            # summary that printed only "8 knobs" would read as 8 judgements.
            knobs_seen.append((field, line_of(stripped, start), len(setters)))
            for name, body in setters:
                if not any(
                    re.search(r"\.\s*" + re.escape(rec) + r"\b", body)
                    for rec in records
                ):
                    findings.append(
                        (
                            field,
                            line_of(stripped, start),
                            "UNWITNESSED",
                            f"`{name}` configures the double to misbehave and "
                            "then reads none of what it records — it cannot "
                            "tell the code's refusal from the fixture's",
                        )
                    )
    return findings, knobs_seen


def tracked_rust_files():
    out = subprocess.run(
        ["git", "ls-files", "*.rs"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    return [p for p in out if not p.startswith("vendor/")]


SELFTEST_VACUOUS = """
#[cfg(test)]
mod tests {
    struct State {
        alloc_calls: usize,
    }
    struct Harness {
        state: State,
        always_fail: bool,
    }
    fn alloc(h: &mut Harness) -> Option<u8> {
        h.state.alloc_calls += 1;
        if h.always_fail {
            return None;
        }
        Some(1)
    }
    #[test]
    fn a_refusal_is_the_backends() {
        let mut h = Harness {
            state: State { alloc_calls: 0 },
            always_fail: false,
        };
        h.always_fail = true;
        assert!(alloc(&mut h).is_none());
    }
}
"""

SELFTEST_WITNESSED = SELFTEST_VACUOUS.replace(
    "        assert!(alloc(&mut h).is_none());",
    "        assert!(alloc(&mut h).is_none());\n"
    "        assert_eq!(h.state.alloc_calls, 1);",
)

SELFTEST_UNSET = SELFTEST_VACUOUS.replace("        h.always_fail = true;\n", "")

# A bool the DOUBLE writes down (rather than branches on) is a record, not a
# knob. The first draft counted `self.x = true` inside the double as a read and
# reported five false positives on this shape.
SELFTEST_RECORDED_BOOL = """
#[cfg(test)]
mod tests {
    struct Harness {
        calls: usize,
        was_asked: bool,
    }
    fn alloc(h: &mut Harness) -> Option<u8> {
        h.calls += 1;
        h.was_asked = true;
        Some(1)
    }
    #[test]
    fn a_recorded_bool_is_not_a_knob() {
        let mut h = Harness {
            calls: 0,
            was_asked: false,
        };
        h.was_asked = true;
        assert!(alloc(&mut h).is_some());
    }
}
"""

SELFTEST_NOT_A_KNOB = """
#[cfg(test)]
mod tests {
    struct Opts {
        calls: usize,
        verbose: bool,
    }
    #[test]
    fn a_plain_bool_is_not_a_knob() {
        let mut o = Opts {
            calls: 0,
            verbose: false,
        };
        o.verbose = true;
        assert!(o.verbose);
    }
}
"""


def selftest():
    """Drive the gate against fixtures the OLD shape would have swallowed.

    Each case names the direction it pins. `WITNESSED` is the one that stops
    the gate from being satisfiable by refusing everything, and
    `SELFTEST_NOT_A_KNOB` is
    what stops it from firing on every bool in the tree.
    """
    cases = [
        ("vacuous", SELFTEST_VACUOUS, {"UNWITNESSED"}, 1),
        ("witnessed", SELFTEST_WITNESSED, set(), 1),
        # A knob no test sets is NOT a finding — see the docstring for the
        # measurement that removed that rule. It still has to be COUNTED, or
        # dropping the rule would quietly shrink the population too.
        ("unset", SELFTEST_UNSET, set(), 1),
        ("not-a-knob", SELFTEST_NOT_A_KNOB, set(), 0),
        ("recorded-bool", SELFTEST_RECORDED_BOOL, set(), 0),
    ]
    ok = True
    for name, src, want_kinds, want_knobs in cases:
        findings, roster = scan_file("<selftest>", src)
        knobs = len(roster)
        _ = sum(setters for _, _, setters in roster)
        kinds = {kind for _, _, kind, _ in findings}
        if kinds != want_kinds or knobs != want_knobs:
            ok = False
            print(
                f"  selftest {name}: FAIL — kinds {sorted(kinds)} "
                f"(want {sorted(want_kinds)}), knobs {knobs} (want {want_knobs})"
            )
        else:
            print(f"  selftest {name}: ok")
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv[1:]:
        return selftest()
    listing = "--list" in sys.argv[1:]
    if [a for a in sys.argv[1:] if a != "--list"]:
        print(f"test-double-knob-gate: unknown argument {sys.argv[1]!r}")
        return 2

    findings = []
    roster = []
    for path in tracked_rust_files():
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        rows, seen = scan_file(path, text)
        roster.extend((path, line, field, setters) for field, line, setters in seen)
        for field, line, kind, detail in rows:
            findings.append((path, line, field, kind, detail))
    knobs = len(roster)
    graded = sum(setters for _, _, _, setters in roster)

    if listing:
        for path, line, field, setters in sorted(roster):
            print(f"{path}:{line} {field} (configured by {setters} test(s))")

    if knobs == 0 or graded == 0:
        what = "knob" if knobs == 0 else "test that configures one"
        print(
            f"test-double-knob-gate: FAIL — the derivation found NO {what} at "
            "all. A population of zero is the exact failure this gate is "
            "about, so it reports red rather than green: either the derivation "
            "has drifted off the source shape, or every misbehaving double in "
            "this tree has been removed."
        )
        return 1

    if findings:
        print(f"test-double-knob-gate: FAIL — {len(findings)} finding(s) over {knobs} knob(s)")
        for path, line, field, kind, detail in findings:
            print(f"  {path}:{line} [{kind}] `{field}` — {detail}")
        print(
            "  A test double that can misbehave exists to carry input the code "
            "under test must refuse. If nothing asserts that the double was "
            "ASKED, the test passes on a fixture that refused on the code's "
            "behalf — measured, R2289, open-debt item 625."
        )
        return 1

    print(
        f"test-double-knob-gate: {knobs} knob(s) derived, {graded} configured "
        "by a test and each one witnessed"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

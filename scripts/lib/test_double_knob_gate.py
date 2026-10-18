#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
* A RECORD is a field of a struct declared in that same module which the
  double's non-test code WRITES -- assigns, or mutates through (`+=`,
  `.push(`, `.fetch_add(`, `.set(`, `.borrow_mut()`, `.lock()`, ...). That is
  what "the double writes down what it was asked" means, and it is read off the
  double rather than off the field's TYPE. Open-debt item 903 replaced a list
  of type names (`usize`, `u32`, `u64`, `AtomicUsize`, `Vec<`), which was wrong
  both ways: it missed every record held behind interior mutability
  (`RefCell<usize>`, `Cell<..>`, `Arc<AtomicUsize>`, a `Mutex`-held struct),
  and it counted a plain `usize` the double only reads (a size, a headroom).
  A test could then pass by assigning that configuration, or by reading a
  counter nothing ever incremented.

ONE rule, in the direction that makes a vacuous test loud:

* Every `#[test]` that sets a knob READS at least one record in its own body.
  Reading is a mention that is not an assignment target: resetting a counter
  is not looking at it. A test that configures its double to misbehave and then never asks whether
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

What a record is NOT proven to be, after item 903: it is a field the double
writes, found by NAME across the module's non-test code and by the std
vocabulary for mutation. A field the double writes for another reason (a pool's
free-list, handed out and taken back) is a record to this derivation, so a test
that reads only that has not necessarily asked the double the question that
matters. And a mutation spelled through a method this vocabulary does not know
(`log.record(x)`) leaves the field out of the population, which can only turn a
witnessed test red and never an unwitnessed one green. The first is the
residual; the second is why it is the safe direction.

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

# A struct declaration with a braced body: `struct Name<T> where .. {`. The
# fields of a RECORD candidate are read from these bodies and from nowhere else,
# so a parameter on a wrapped `fn` signature or a `name: value` line of a
# struct literal is never mistaken for a field.
STRUCT_RE = re.compile(r"\bstruct\s+\w+\s*(?:<[^{;]*>)?\s*(?:where[^{;]*)?\{")
# One declared field of such a body: `name: Type,` on a line of its own.
ANY_FIELD_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*[^\s=]", re.M)

# What WRITING a field looks like in the double's own code, by receiver-agnostic
# shape: the record is reached through `self`, through a guard (`st.alloc_calls`)
# or through a clone, so the receiver is not part of the pattern.
#
# ASSIGNMENT covers `=` and every compound form; `=>`, `==` are not writes. The
# lookahead is written to swallow the operator ITSELF for the reason the knob
# read pattern below carries.
_WRITE_VERBS = (
    r"borrow_mut|lock|write|get_mut|set|replace|take|swap|store|send|try_send|"
    r"fetch_\w+|compare_exchange\w*|push\w*|pop\w*|insert|extend\w*|append|"
    r"clear|remove|truncate|drain|retain|entry"
)


def writes_field(field, code):
    """Does `code` WRITE the field `field`: assign it or mutate through it.

    The mutation verbs are the std vocabulary for mutating a collection, a cell,
    a mutex-held value or an atomic, which is what `written` means whatever the
    field's declared type. A custom method this does not know (`log.record(x)`)
    makes the field NOT a record, and that errs towards a finding: a field
    missed here can only turn a witnessed test red, never an unwitnessed one
    green.
    """
    name = re.escape(field)
    assign = re.search(r"\.\s*" + name + r"\s*(?:[+\-*/%|&^]|<<|>>)?=(?![=>])", code)
    mutate = re.search(r"\.\s*" + name + r"\s*\.\s*(?:" + _WRITE_VERBS + r")\s*\(", code)
    return bool(assign or mutate)


def reads_field(field, body):
    """Does a test body READ `field`: mention it other than as an assignment target.

    A test that resets a counter (`h.calls = 0`) has written what it is
    supposed to be reading. The lookahead swallows the whitespace and the
    (compound) operator for the reason `read_re` below does.
    """
    return bool(
        re.search(
            r"\.\s*" + re.escape(field) + r"\b(?!\s*(?:[+\-*/%|&^]|<<|>>)?=[^=])",
            body,
        )
    )


def struct_fields(scope):
    """`{field: is_bool}` over the fields of every struct body in `scope`."""
    fields = {}
    for m in STRUCT_RE.finditer(scope):
        start, end = span_from_brace(scope, m.end() - 1)
        body = scope[start:end]
        bools = set(BOOL_FIELD_RE.findall(body))
        for name in ANY_FIELD_RE.findall(body):
            fields[name] = name in bools
    return fields


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
    """`(findings, knobs, records)` for one file.

    `knobs` and `records` are the rosters themselves rather than counts, so
    `--list` can print WHICH fields the derivation reached. A number alone is
    the shape this tree keeps getting caught by: 8 is indistinguishable from 8
    of the wrong thing.
    """
    stripped = strip_comments(text)
    findings = []
    knobs_seen = []
    records_seen = []
    for start, end in test_scopes(stripped):
        scope = stripped[start:end]
        bools = set(BOOL_FIELD_RE.findall(scope))
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

        # READ by the double, in a non-assignment position. `self.x = true`
        # inside the double is the double RECORDING something, not
        # branching on it, and counting that as a knob is what made the
        # first draft report five false positives.
        # The lookahead must swallow the whitespace ITSELF: written as
        # `\b\s*(?!=..)` the `\s*` backtracks to zero and the lookahead
        # then sees a space instead of the `=`, so every assignment matched
        # anyway. Measured on the `recorded-bool` selftest fixture.
        knob_fields = {
            field
            for field in bools
            if re.search(r"\.\s*" + re.escape(field) + r"\b(?!\s*=[^=])", outside)
        }
        # A RECORD is a field the double WRITES, whatever its declared type
        # (open-debt item 903). The first draft listed type names -- `usize`,
        # `u32`, `u64`, `AtomicUsize`, `Vec<` -- and that list was wrong in
        # both directions: it did not see `RefCell<usize>`, `Cell<..>` or
        # `Arc<AtomicUsize>`, which is what a double handed only `&self` must
        # use, and it counted every plain `usize` field, including one the
        # double merely READS (`headroom`), so a test could pass by assigning
        # the configuration it had just set. What makes a field a record is
        # that the double writes it down when it is called; the type is
        # incidental. A knob is a branch input and is never its own witness.
        records = {
            field
            for field in struct_fields(scope)
            if field not in knob_fields and writes_field(field, outside)
        }
        records_seen.extend((field, line_of(stripped, start)) for field in sorted(records))

        for field in sorted(knob_fields):
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
                if not any(reads_field(rec, body) for rec in records):
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
    return findings, knobs_seen, records_seen


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


# A record held behind interior mutability. `RefCell<usize>` is what a double
# that is only ever handed `&self` has to use, and the type-name list this gate
# first carried did not name it, so a test that DID ask the double was told it
# had not (measured on `tx_lease.rs`, whose `aborts` is a `RefCell<usize>`).
SELFTEST_INTERIOR_RECORD = """
#[cfg(test)]
mod tests {
    use core::cell::RefCell;
    struct Harness {
        asked: RefCell<usize>,
        always_fail: bool,
    }
    fn alloc(h: &Harness) -> Option<u8> {
        *h.asked.borrow_mut() += 1;
        if h.always_fail {
            return None;
        }
        Some(1)
    }
    #[test]
    fn a_refusal_is_the_backends() {
        let mut h = Harness {
            asked: RefCell::new(0),
            always_fail: false,
        };
        h.always_fail = true;
        assert!(alloc(&h).is_none());
        assert_eq!(*h.asked.borrow(), 1);
    }
}
"""

# A `usize` the double only READS is configuration, not a record: counting it
# let a test pass by assigning it (`h.headroom = ..`) or by reading a counter the
# double never writes. Both are in the test body; neither says the double was
# asked, which is what the rule requires.
SELFTEST_CONFIG_NOT_RECORD = """
#[cfg(test)]
mod tests {
    struct Harness {
        calls: usize,
        headroom: usize,
        always_fail: bool,
    }
    fn alloc(h: &mut Harness) -> Option<u8> {
        if h.always_fail || h.headroom > 3 {
            return None;
        }
        Some(1)
    }
    #[test]
    fn a_refusal_is_the_backends() {
        let mut h = Harness {
            calls: 0,
            headroom: 0,
            always_fail: false,
        };
        h.always_fail = true;
        h.headroom = 9;
        assert!(alloc(&mut h).is_none());
        assert_eq!(h.calls, 0);
    }
}
"""

# Resetting a record is not reading it: the test writes the counter and never
# looks at what the double wrote into it.
SELFTEST_RECORD_ASSIGNED = SELFTEST_WITNESSED.replace(
    "        assert_eq!(h.state.alloc_calls, 1);",
    "        h.state.alloc_calls = 0;",
)

# A bool the DOUBLE writes down is a record, so a test that sets a knob and then
# reads it HAS asked the double.
SELFTEST_BOOL_RECORD = """
#[cfg(test)]
mod tests {
    struct Harness {
        was_asked: bool,
        always_fail: bool,
    }
    fn alloc(h: &mut Harness) -> Option<u8> {
        h.was_asked = true;
        if h.always_fail {
            return None;
        }
        Some(1)
    }
    #[test]
    fn a_refusal_is_the_backends() {
        let mut h = Harness {
            was_asked: false,
            always_fail: false,
        };
        h.always_fail = true;
        assert!(alloc(&mut h).is_none());
        assert!(h.was_asked);
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
        ("interior-record", SELFTEST_INTERIOR_RECORD, set(), 1),
        ("config-not-record", SELFTEST_CONFIG_NOT_RECORD, {"UNWITNESSED"}, 1),
        ("record-assigned", SELFTEST_RECORD_ASSIGNED, {"UNWITNESSED"}, 1),
        ("bool-record", SELFTEST_BOOL_RECORD, set(), 1),
    ]
    ok = True
    for name, src, want_kinds, want_knobs in cases:
        findings, roster, _records = scan_file("<selftest>", src)
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
    record_roster = []
    for path in tracked_rust_files():
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        rows, seen, recs = scan_file(path, text)
        roster.extend((path, line, field, setters) for field, line, setters in seen)
        record_roster.extend((path, line, field) for field, line in recs)
        for field, line, kind, detail in rows:
            findings.append((path, line, field, kind, detail))
    knobs = len(roster)
    graded = sum(setters for _, _, _, setters in roster)
    records = len(record_roster)

    if listing:
        for path, line, field, setters in sorted(roster):
            print(f"{path}:{line} {field} (configured by {setters} test(s))")
        for path, line, field in sorted(record_roster):
            print(f"{path}:{line} {field} (record: written by the double)")

    if knobs == 0 or graded == 0 or records == 0:
        what = (
            "knob"
            if knobs == 0
            else "test that configures one"
            if graded == 0
            else "record the double writes"
        )
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
        f"by a test and each one witnessed, over {records} record field(s) "
        "the doubles write"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

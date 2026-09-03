#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2311 (no register item) - a foreign one-shot query is not a verdict.

The citation is `no register item` for the reason `config_key_fixture_gate.py`
and `test_double_knob_gate.py` give for theirs: the item this closes --
unregistered open-debt item 645 -- lives in the operator's register file
outside this repository, not under the store's `debt-` prefix, so there is no
id here for `--emit` to resolve. The item is named in prose throughout.

Hosted Layer Ewirez failed in 0.17s with "the stock querier got no reply"
while every local run passed, and the mechanism is an ORDERING, not a flake:

  * Both foreign example families print their readiness line BEFORE the call
    that declares. Upstream `examples/examples/z_queryable.rs` prints
    "Declaring Queryable on" and calls `declare_queryable` on the NEXT
    statement; zenoh-pico's `examples/unix/c11/z_queryable.c`, `z_sub.c` and
    `z_querier.c` print theirs above the matching `z_declare_*`.
  * So that line proves the declarer's SESSION is open and nothing about the
    ROUTER having registered anything.
  * A querier that dials the router separately can therefore arrive first. The
    router finalizes its query against an empty route at once, the one-shot
    prints no reply and EXITS, and a test that believes that single result
    reads a lost race as a routing failure.

The window is a scheduling quantity: measured on this tree's own binaries an
idle host closes it before the querier's process spawn finishes, which is why
this cannot be left to be caught by running the tests.

WHAT THIS GATE DERIVES. The population is every tracked integration test that
resolves BOTH a foreign DECLARER binary and a foreign QUERIER binary - that
pairing is what creates a declaration which must propagate before a query. It
is read out of the resolver call sites, not listed here, and an EMPTY
population is a FAILURE: a gate whose subject vanished must not report green.

WHAT IT REQUIRES. Every spawn of the querier binary must sit under a bounded
retry of the whole one-shot, in one of two forms, and the gate names which one
it found for each file so an omission cannot read as coverage:

  helper - `run_query_until_answered(...)`, the shared predicate in
           `wz-integration-tests/src/lib.rs`.
  inline - a `for <v> in 1..=<N>` loop whose brace span contains the spawn.

A DENY leg, where the absence of a reply is the finding, is not an exception to
this: it passes `attempts = 1` through the helper and says so at the call site,
which keeps the intent readable instead of indistinguishable from an oversight.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# The two roles. A file needs one of each to be able to have the window at all.
#
# The declarer list is the QUERY-answering side only. A subscriber or a
# liveliness token has the same pre-await marker, but nothing queries it, so it
# cannot lose this particular race - its counterpart is a publisher, and every
# publisher in this tree repeats (`z_pub -n 30`, one Put per second), which is
# already self-healing across a route install. Widening the list to them would
# put 4000-line drop-in conformance files in the population for spawns that
# have no window at all, which is a population chosen for its size rather than
# for the defect.
DECLARER_BINS = ("z_queryable", "z_storage")
QUERIER_BINS = ("z_get", "z_querier")

# `let <name> = <something>_binary("<bin>")`, which is how every one of these
# tests names the executable it is about to spawn. The VARIABLE is what the
# spawn sites then reference, so it is derived here rather than assumed.
BIND_RE = re.compile(
    r"\blet\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"[A-Za-z_][A-Za-z0-9_]*_binary\(\s*\"(?P<bin>[a-z0-9_]+)\"",
)
RETRY_RE = re.compile(r"\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+1\.\.=")
HELPER = "run_query_until_answered"


def tracked_tests(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "crates/wz-integration-tests/tests/*.rs"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [root / p for p in out]


STRING_RE = re.compile(r"r#*\"(?:[^\"]|\"(?!#))*\"#*|\"(?:\\.|[^\"\\])*\"")


def code_only(line: str) -> str:
    """The line with string literals and a trailing `//` comment removed.

    Brace counting MUST NOT see `{}` that belong to a format specifier or to
    prose. Without this the span of a `for x in 1..=N` block runs past its real
    end - a `panic!("... {ATTEMPTS} attempts")` alone unbalances it - and the
    gate then reports later, unrelated spawns as covered by a retry that does
    not contain them. That is the failure mode where a gate cannot fail, and
    this one did: three files read `ok [inline]` on runaway spans before the
    stripping went in.
    """
    line = STRING_RE.sub('""', line)
    cut = line.find("//")
    return line if cut < 0 else line[:cut]


def retry_spans(lines: list[str]) -> list[tuple[int, int]]:
    """Line ranges (0-based, inclusive) covered by a `for x in 1..=N` block."""
    spans: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        if not RETRY_RE.search(line):
            continue
        depth = 0
        opened = False
        for j in range(i, len(lines)):
            code = code_only(lines[j])
            depth += code.count("{") - code.count("}")
            if code.count("{"):
                opened = True
            if opened and depth <= 0:
                spans.append((i, j))
                break
        else:
            spans.append((i, len(lines) - 1))
    return spans


FN_RE = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")


def enclosing_fn(lines: list[str], index: int) -> str | None:
    """Name of the `fn` the given line sits in, by scanning upward."""
    for j in range(index, -1, -1):
        m = FN_RE.match(lines[j])
        if m:
            return m.group(1)
    return None


def helper_calls(lines: list[str]) -> tuple[set[str], list[tuple[int, int]]]:
    """What each `run_query_until_answered(...)` call reaches.

    Returns the identifiers it names AND its own line span. Both are needed,
    because the attempt factory is written two ways and the gate has to accept
    both: as a NAMED function (`|| spawn_zget(...)`), where the spawn lives in
    that function and is found by name, and as an INLINE closure, where the
    spawn is lexically inside the call and is found by span. The call's
    argument list is delimited by parentheses, so the span is taken by counting
    them - over `code_only`, since a panic message in the closure is full of
    unbalanced ones.
    """
    named: set[str] = set()
    spans: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        # `code_only`, not the raw line: a DOC COMMENT that names the helper is
        # not a call to it. Reading the raw line made every function whose
        # doc-comment says "see [`run_query_until_answered`]" look like an
        # attempt factory - which is how the first control-group mutation of
        # this gate went undetected, since the fixed site's spawner documents
        # itself that way.
        if HELPER not in code_only(line):
            continue
        depth = 0
        opened = False
        for j in range(i, len(lines)):
            code = code_only(lines[j])
            depth += code.count("(") - code.count(")")
            if code.count("("):
                opened = True
                named.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", code))
            if opened and depth <= 0:
                spans.append((i, j))
                break
    return named, spans


def audit(path: Path) -> tuple[bool, list[int], str]:
    """(in_population, offending spawn descriptions, verdict word)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    # var -> binary, SCOPED TO THE ENCLOSING `fn`. Scoping is not tidiness: the
    # C-ABI drop-in suite rebinds one name (`dropin`) to a different upstream
    # example in every test, so a file-wide map makes `.arg(&dropin)` read as a
    # querier spawn in the thirty-odd tests that spawn a subscriber or a
    # publisher through it. That over-match was 38 of this gate's first 44
    # findings.
    declarers: set[tuple[str | None, str]] = set()
    queriers: set[tuple[str | None, str]] = set()
    for m in BIND_RE.finditer(text):
        line_no = text[: m.start()].count("\n")
        scope = enclosing_fn(lines, line_no)
        if m.group("bin") in DECLARER_BINS:
            declarers.add((scope, m.group("var")))
        if m.group("bin") in QUERIER_BINS:
            queriers.add((scope, m.group("var")))
    if not declarers or not queriers:
        return False, [], "-"

    verdict = "helper" if any(HELPER in code_only(line) for line in lines) else "inline"

    spans = retry_spans(lines)
    # A spawn reached through the helper is NOT lexically inside the call: the
    # closure passed to `run_query_until_answered` calls an attempt factory,
    # and the spawn lives in THAT function. So the second accepted form is
    # resolved by name - the enclosing `fn` of the spawn appears inside a
    # helper call - rather than by nesting. Getting this wrong is not
    # hypothetical: the first draft of this gate reported the very site the
    # round had just fixed as an offender.
    helper_named, helper_spans = helper_calls(lines)
    spans.extend(helper_spans)

    # A spawn of the querier binary: `.arg(&z_get)` / `.arg(z_get)`, counted
    # only where the name is bound to a querier IN THAT FUNCTION.
    spawn_re = re.compile(r"\.arg\(\s*&?([A-Za-z_][A-Za-z0-9_]*)\s*\)")
    offenders: list[int] = []
    for i, line in enumerate(lines):
        m = spawn_re.search(line)
        if not m:
            continue
        scope = enclosing_fn(lines, i)
        var = m.group(1)
        # Either the name is bound to a querier in THIS function, or it is the
        # PARAMETER a spawner function receives it through. The second form is
        # not a guess: every spawner here names that parameter after the
        # upstream executable (`fn spawn_zget(z_get: &Path, ...)`), so the
        # querier binary names are the derivation. Without it, function-scoping
        # hides exactly the sites it was added to expose - the spawn moves one
        # function away from the `let` and stops being seen.
        if (scope, var) not in queriers and var not in QUERIER_BINS:
            continue
        if any(lo <= i <= hi for lo, hi in spans):
            continue
        if scope in helper_named:
            continue
        offenders.append(i + 1)
    return True, offenders, verdict


# Each fixture is a shape THE EARLIER DRAFTS OF THIS GATE SWALLOWED, not an
# invented one - every `want_fail=True` case below is a bug the control group
# caught while this round was writing it. A selftest whose fixtures only
# exercise the finished logic proves the logic runs, not that it discriminates.
SELFTEST: tuple[tuple[str, bool, str], ...] = (
    (
        "plain one-shot",
        True,
        """
fn t() {
    let z_queryable = zenoh_core_example_binary("z_queryable");
    let z_get = zenoh_core_example_binary("z_get");
    let c = Command::new("stdbuf").arg(&z_get).spawn();
}
""",
    ),
    (
        "retried through the shared helper, inline closure",
        False,
        """
fn t() {
    let z_queryable = zenoh_core_example_binary("z_queryable");
    let z_get = zenoh_core_example_binary("z_get");
    let r = run_query_until_answered("l", QueryAttempts::UpTo(6), N, B, || {
        let c = Command::new("stdbuf").arg(&z_get).spawn();
        (c, out)
    });
}
""",
    ),
    (
        "retried through the shared helper, named factory",
        False,
        """
fn spawn_zget(z_get: &Path) -> (ChildGuard, File) {
    let c = Command::new("stdbuf").arg(z_get).spawn();
    (c, out)
}
fn t() {
    let z_queryable = zenoh_core_example_binary("z_queryable");
    let z_get = zenoh_core_example_binary("z_get");
    let r = run_query_until_answered("l", QueryAttempts::UpTo(6), N, B, || spawn_zget(&z_get));
}
""",
    ),
    (
        "a DOC COMMENT naming the helper is not a call to it",
        True,
        # The ONLY spawn is inside the doc-commented factory, and nothing calls
        # the helper. If a doc mention is read as a call, that factory is
        # excused and the fixture reports clean - which is what the real file
        # did under the first control-group mutation.
        """
/// See [`run_query_until_answered`] for why one attempt is not a verdict.
fn spawn_zget(z_get: &Path) -> (ChildGuard, File) {
    let c = Command::new("stdbuf").arg(z_get).spawn();
    (c, out)
}
fn t() {
    let z_queryable = zenoh_core_example_binary("z_queryable");
    let z_get = zenoh_core_example_binary("z_get");
    let (c, r) = spawn_zget(&z_get);
}
""",
    ),
    (
        "a brace inside a format string must not extend a retry span",
        True,
        """
fn t() {
    let z_queryable = zenoh_core_example_binary("z_queryable");
    let z_get = zenoh_core_example_binary("z_get");
    for attempt in 1..=ATTEMPTS {
        let q = spawn_queryable();
    }
    panic!("gave up after {ATTEMPTS} attempts");
    let c = Command::new("stdbuf").arg(&z_get).spawn();
}
""",
    ),
    (
        "a name rebound to a NON-querier binary is not a querier spawn",
        False,
        """
fn t() {
    let z_queryable = zenoh_core_example_binary("z_queryable");
    let z_get = zenoh_core_example_binary("z_get");
    let r = run_query_until_answered("l", QueryAttempts::UpTo(6), N, B, || {
        let c = Command::new("stdbuf").arg(&z_get).spawn();
        (c, out)
    });
}
fn other() {
    let dropin = dropin_binary("z_sub", dir);
    let c = Command::new("stdbuf").arg(&dropin).spawn();
}
""",
    ),
    (
        "no declarer means no window, so the file is out of the population",
        False,
        """
fn t() {
    let z_get = zenoh_core_example_binary("z_get");
    let c = Command::new("stdbuf").arg(&z_get).spawn();
}
""",
    ),
)


def selftest() -> int:
    import tempfile

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, want_fail, src in SELFTEST:
            path = Path(tmp) / "fixture.rs"
            path.write_text(src, encoding="utf-8")
            in_pop, offenders, _ = audit(path)
            got_fail = bool(offenders)
            if not in_pop and want_fail:
                print(f"  FAIL selftest {name!r}: fixture fell out of the population")
                failures += 1
                continue
            if got_fail != want_fail:
                print(
                    f"  FAIL selftest {name!r}: expected "
                    f"{'a finding' if want_fail else 'no finding'}, got "
                    f"{len(offenders)} finding(s)"
                )
                failures += 1
            else:
                print(f"  ok   selftest {name!r}")
    if failures:
        print(f"foreign-query-readiness: SELFTEST FAILED ({failures})", file=sys.stderr)
        return 1
    print(f"foreign-query-readiness: selftest ok ({len(SELFTEST)} fixture(s))")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    root = Path(__file__).resolve().parents[2]
    population: list[tuple[Path, list[int], str]] = []
    for path in tracked_tests(root):
        in_pop, offenders, verdict = audit(path)
        if in_pop:
            population.append((path, offenders, verdict))

    if not population:
        print(
            "foreign-query-readiness: FAIL - the derived population is EMPTY. "
            "No tracked integration test resolves both a foreign declarer and a "
            "foreign querier, so either the resolver names moved or this gate "
            "lost its subject. A population of zero must not report green.",
            file=sys.stderr,
        )
        return 1

    failed = 0
    print(f"foreign-query-readiness: {len(population)} file(s) in the derived population")
    for path, offenders, verdict in sorted(population):
        rel = path.relative_to(root)
        if offenders:
            failed += 1
            print(f"  FAIL {rel} - {len(offenders)} un-retried querier spawn(s)")
            for line_no in offenders:
                print(f"        {rel}:{line_no}")
        else:
            print(f"  ok   {rel} [{verdict}]")

    if failed:
        print(
            f"\nforeign-query-readiness: FAIL - {failed} file(s) spawn a foreign "
            "querier outside any bounded retry.\n"
            "A foreign one-shot that arrives before the declaration it queries "
            "has propagated is finalized against an empty route and exits with "
            "no reply; believing that single result is how hosted Layer Ewirez "
            "went red (run 33737007770) while every local run passed.\n"
            "Route the spawn through `run_query_until_answered(...)`. A deny "
            "leg passes `attempts = 1` and stays inside the helper, so its "
            "intent is legible rather than indistinguishable from an oversight.",
            file=sys.stderr,
        )
        return 1
    print("foreign-query-readiness: ok - every foreign querier spawn is retried")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4499 (no register item) -- a multi-process test asserts only on a process
it has waited on.

The item this answers, open-debt item 657, lives in the agent-memory half of the
register, which has no store id for `gate_provenance_lint.py` to resolve; this
names it in prose instead.

THE DEFECT. A multi-process e2e waits for ONE process's log line, stops every
process, then asserts on ANOTHER process's captured log. The awaited line does
not, in general, say the other process has done anything: hosted run
33955622442 failed exactly so, the dialing peer confirming a mesh edge, the
test stopping it at once, and the accepting peer ending with no edge because
it lost its neighbour before it ingested the neighbour's link-state. The fix is
synchronisation, not product: wait on the asserted process for its own line
before anything it depends on is stopped.

THE SHAPE, read from source. In each test fn (`#[test]` / `#[tokio::test]`)
that both waits on a capture (`wait_for_substring`, `wait_for_capture_alive`)
and reads one (`let C = read_captured(&mut R)`), every capture `C` that an
assertion's CONDITION reads positively (`assert!(C.contains(..) ..)`) must come
from a reader `R` the same fn waits on. A negated read (`!C.contains`) is an
absence claim and out of scope; so is a `contains` in a panic message or an
`if`, which grades nothing.

WHAT IS EXEMPT, and why it is a list. Some asserted processes are complete
when they are read without any log wait: they were waited on to EXIT, or the
asserted lines are the process's own shutdown totals of things that by the
test's construction never happen, which no neighbour's stopping can change.
A scan cannot tell those from a missing wait, so each is named in `EXEMPT` with
its reason. The list is checked in both directions: an unlisted one-sided
assertion is a FAIL, and so is an entry that no longer matches one (a stale
exemption is how a list becomes permission).

POPULATIONS. The fns that wait and read must be non-empty, or the scan has
stopped seeing the corpus and would pass on nothing.

Usage:
    python3 scripts/lib/one_sided_wait_lint.py [--check]
    python3 scripts/lib/one_sided_wait_lint.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS_GLOB = "crates/**/tests/**/*.rs"

# (path relative to the root, test fn, reader) -> why the reader needs no wait.
EXEMPT: dict[tuple[str, str, str], str] = {
    (
        "crates/wz-integration-tests/tests/it/files/pico_c_examples_on_wz_capi_dropin.rs",
        "pico_zqueryable_source_on_wz_capi_answers_real_pico_zget",
        "get_reader",
    ): "waited in a helper: `run_query_until_answered` returns the reader only once the "
    "reply line is in it, and `finish_get_example` waits for the get to exit",
    (
        "crates/wz-integration-tests/tests/it/files/pico_c_examples_on_wz_capi_dropin.rs",
        "pico_zgetliveliness_source_on_wz_capi_sees_a_real_pico_token_through_zenohd",
        "get_out",
    ): "exited: `bounded_exit` waits for the one-shot get to exit before its capture is read",
    (
        "crates/wz-integration-tests/tests/it/files/wz_router_terminates_a_pico_liveliness_get.rs",
        "a_wz_router_terminates_a_pico_liveliness_get_instead_of_letting_it_time_out",
        "pico_stdout_reader",
    ): "exited: the get's completion is its exit, polled with `try_wait` before the read",
    (
        "crates/wz-integration-tests/tests/it/files/apfull_router_reconcile_pico_interop.rs",
        "apfull_without_the_reconcile_the_two_picos_cannot_reach_each_other",
        "r1_reader",
    ): "own totals: the leg's subject is that R1 never links to R2 without the reconcile; "
    "its shutdown counts (dialed 0, a routers-net of one, nothing forwarded) are that "
    "absence, and stopping a neighbour first cannot add a link it never had",
}

TEST_FN_RE = re.compile(
    r"#\[(?:tokio::)?test[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)"
)
WAIT_RES = (
    re.compile(r"\bwait_for_substring\(\s*&mut\s+([A-Za-z0-9_]+)\s*,"),
    re.compile(
        r"\bwait_for_capture_alive\([^,()]*(?:\([^()]*\))?[^,()]*,\s*&mut\s+([A-Za-z0-9_]+)\s*,"
    ),
)
CAPTURE_RE = re.compile(
    r"\blet\s+(?:mut\s+)?([A-Za-z0-9_]+)\s*=\s*read_captured\(\s*&mut\s+([A-Za-z0-9_]+)\s*\)"
)
ASSERT_RE = re.compile(r"\b(?:debug_)?assert!\s*\(")


def blank(src: str) -> str:
    """`src` with comments and the contents of string and char literals blanked,
    offsets and newlines kept, so braces and parentheses can be counted."""
    out = list(src)
    i, n = 0, len(src)

    def wipe(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            wipe(i, j)
            i = j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            wipe(i, j)
            i = j
            continue
        prev_ident = i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_")
        m = None if prev_ident else re.match(r'b?r(#*)"', src[i : i + 40])
        if m:
            start = i + len(m.group(0))
            end = src.find('"' + m.group(1), start)
            end = n if end < 0 else end
            wipe(start, end)
            i = end + 1 + len(m.group(1))
            continue
        if src[i] == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            wipe(i + 1, j)
            i = j + 1
            continue
        if src[i] == "'" and not prev_ident:
            m = re.match(r"'(?:\\u\{[0-9a-fA-F]+\}|\\.|[^\\'])'", src[i : i + 12])
            if m:
                wipe(i + 1, i + len(m.group(0)) - 1)
                i += len(m.group(0))
                continue
        i += 1
    return "".join(out)


def balanced(src: str, open_at: int, opener: str, closer: str) -> int:
    """Index of the `closer` that balances the `opener` at `open_at`."""
    depth = 0
    for k in range(open_at, len(src)):
        if src[k] == opener:
            depth += 1
        elif src[k] == closer:
            depth -= 1
            if depth == 0:
                return k
    return len(src) - 1


def test_fns(src: str):
    """(name, offset, body) of each test fn of blanked `src`."""
    for m in TEST_FN_RE.finditer(src):
        start = src.find("{", m.end())
        if start < 0:
            continue
        yield m.group(1), m.start(), src[start : balanced(src, start, "{", "}") + 1]


def assert_conditions(body: str):
    """The first argument of each `assert!` in `body`: the condition it grades."""
    for m in ASSERT_RE.finditer(body):
        open_at = m.end() - 1
        close = balanced(body, open_at, "(", ")")
        inner = body[open_at + 1 : close]
        depth = 0
        for k, c in enumerate(inner):
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == "," and depth == 0:
                inner = inner[:k]
                break
        yield inner


def reads_positively(condition: str, capture: str) -> bool:
    pattern = r"(!\s*)?\b" + re.escape(capture) + r"\s*\.\s*contains\s*\("
    for m in re.finditer(pattern, condition):
        if not m.group(1):
            return True
    return False


def scan_source(rel: str, raw: str):
    """(population, findings) of one file: the fns that wait and read, and each
    (rel, fn, capture, reader, line) asserted on without a wait."""
    src = blank(raw)
    population = 0
    findings = []
    for name, offset, body in test_fns(src):
        if "read_captured" not in body or not any(r.search(body) for r in WAIT_RES):
            continue
        population += 1
        waited = {m.group(1) for r in WAIT_RES for m in r.finditer(body)}
        conditions = list(assert_conditions(body))
        seen = set()
        for cap, reader in CAPTURE_RE.findall(body):
            if reader in waited or (cap, reader) in seen:
                continue
            seen.add((cap, reader))
            if any(reads_positively(c, cap) for c in conditions):
                line = raw.count("\n", 0, offset) + 1
                findings.append((rel, name, cap, reader, line))
    return population, findings


def scan(root: Path):
    population = 0
    findings = []
    for path in sorted(root.glob(CORPUS_GLOB)):
        rel = str(path.relative_to(root))
        pop, found = scan_source(rel, path.read_text(encoding="utf-8"))
        population += pop
        findings.extend(found)
    return population, findings


def verdict(population: int, findings, exempt) -> list[str]:
    """Every failure, as a line; empty when the corpus holds."""
    errors = []
    if population == 0:
        errors.append("no test fn both waits on and reads a capture: the scan sees no corpus")
    matched = set()
    for rel, name, cap, reader, line in findings:
        key = (rel, name, reader)
        if key in exempt:
            matched.add(key)
            continue
        errors.append(
            f"{rel}:{line} {name}: asserts on `{cap}` (read from `{reader}`) without "
            f"waiting on `{reader}`; wait on it for the asserted event before stopping "
            "what it depends on, or exempt it with the reason it is complete unwaited"
        )
    for key in sorted(set(exempt) - matched):
        errors.append(f"stale exemption {key}: it matches no one-sided assertion any more")
    return errors


def check() -> int:
    population, findings = scan(ROOT)
    errors = verdict(population, findings, EXEMPT)
    for e in errors:
        print(f"one-sided-wait: FAIL -- {e}")
    if errors:
        return 1
    print(
        f"one-sided-wait: OK -- {population} test fn(s) wait on and read captures; "
        f"{len(EXEMPT)} exempt one-sided read(s), none unexplained"
    )
    return 0


SELFTEST_ONE_SIDED = """
#[test]
fn t() {
    let a = wait_for_substring(&mut b_reader, "x", D);
    graceful_terminate(a_guard.child_mut(), D);
    let a_captured = read_captured(&mut a_reader);
    assert!(a_captured.contains("event"), "{a_captured}");
}
"""


def selftest() -> int:
    cases = [
        ("a positive read of an unwaited process is found", SELFTEST_ONE_SIDED, 1, 1),
        (
            "waiting on the asserted process clears it",
            SELFTEST_ONE_SIDED.replace(
                "let a = wait",
                'let _w = wait_for_substring(&mut a_reader, "event", D);\n    let a = wait',
            ),
            1,
            0,
        ),
        (
            "an absence claim is out of scope",
            SELFTEST_ONE_SIDED.replace("assert!(a_captured", "assert!(!a_captured"),
            1,
            0,
        ),
        (
            "a read in the panic message grades nothing",
            SELFTEST_ONE_SIDED.replace(
                'assert!(a_captured.contains("event"), "{a_captured}")',
                'assert!(ok, "{}", a_captured.contains("event"))',
            ),
            1,
            0,
        ),
        (
            "a needle inside a string is not code",
            SELFTEST_ONE_SIDED.replace('"x"', '"wait_for_substring(&mut a_reader, "'),
            1,
            1,
        ),
        (
            "the liveness-aware wait counts as a wait",
            SELFTEST_ONE_SIDED.replace(
                "let a = wait",
                "let _w = wait_for_capture_alive(child.child_mut(), &mut a_reader, D, "
                '"e", f);\n    let a = wait',
            ),
            1,
            0,
        ),
        (
            "a fn that never waits is not in the population",
            '#[test]\nfn t() { let c = read_captured(&mut r); assert!(c.contains("x")); }\n',
            0,
            0,
        ),
    ]
    failures = 0
    for label, src, want_pop, want_found in cases:
        pop, found = scan_source("x.rs", src)
        if (pop, len(found)) != (want_pop, want_found):
            failures += 1
            print(
                f"selftest FAIL: {label}: population {pop}, found {len(found)}; "
                f"wanted {want_pop}, {want_found}"
            )
    pop, found = scan_source("x.rs", SELFTEST_ONE_SIDED)
    key = ("x.rs", "t", "a_reader")
    directions = [
        ("an unlisted finding fails", verdict(pop, found, {}), True),
        ("an exempt finding passes", verdict(pop, found, {key: "why"}), False),
        ("a stale exemption fails", verdict(pop, [], {key: "why"}), True),
        ("an empty population fails", verdict(0, [], {}), True),
    ]
    for label, errors, want_fail in directions:
        if bool(errors) != want_fail:
            failures += 1
            print(f"selftest FAIL: {label}: {errors}")
    if failures:
        return 1
    print(f"one-sided-wait selftest: {len(cases) + len(directions)} case(s) behaved as claimed")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv in ([], ["--check"]):
        return check()
    print(__doc__.split("Usage:")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

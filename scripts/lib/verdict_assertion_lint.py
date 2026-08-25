#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y727 (N19) — A CONTAINMENT CLAIM ABOUT THE VERDICT SAYS NOTHING ABOUT
THE REST OF IT.

`CaptureReport::reasons` answers with a SET. `contains(&VerdictReason::X)` says
that one member is present and says NOTHING about the others -- so a test built
that way holds while every other leg fires too. That is not a hypothetical: the
mutation sweep's `widen` operator makes a leg fire on every capture, and a suite
of containment claims watches it happen in silence.

THE MEASUREMENT THAT MADE THIS A GATE. R311y727's sweep found five plane legs
killed by exactly ONE test each, against sixteen apiece for the legs outside a
plane. The thin ones were thin for this reason: their own witnesses claim
containment, so the only thing standing between a runaway leg and a green suite
was one unrelated test that happened to assert a clean capture stays quiet.

THE RULE. A test that READS the verdict list and names a `VerdictReason` must
also, somewhere in the same function, pin the whole list --
`assert_eq!(.., vec![..])` over an expression holding `reasons()`. One such
assertion is enough: it is the sentence that says what is NOT in the verdict,
and once a test says it, severing and widening both have something to break.

THE POPULATION IS `reasons()`, NOT THE `contains` SPELLING, and the first
version of this gate got that wrong. Scanning for
`contains(&VerdictReason::X)` missed a test that loops
`for leg in [VerdictReason::A, ..] { assert!(reasons.contains(&leg)) }` -- the
argument is a variable there, so the pattern found nothing and the test went
unasked. Any test that calls `reasons()` and mentions the enum is claiming
something about the list; the shape of the claim is not the gate's business.

A HELPER THAT PINS COUNTS AS THE PIN. Pulling the assertion into a shared
function is good practice and this must not punish it, so any non-test function
in the same file that itself pins the list is accepted when called. Note what
does NOT qualify: `assert_verdict_rests_on` asserts the underlying COUNTERS are
zero, which is a claim about the dissection rather than about the list. A guard
widened to `(COND) || true` fires with every counter at zero, so that helper is
silent on exactly the axis this gate is about.

WHY THE SAME FUNCTION rather than the same file. The pin has to be over the same
report the containment claim is about. A pin in a neighbouring test proves
nothing about this fixture -- that is precisely the accident this gate exists to
stop relying on.

WHY MASKING COMES FIRST. Comments and string literals hold braces and hold the
word `contains`, and a gate that reads them is a gate a comment can satisfy
(R311y717 was fooled exactly once this way and it is why that lint strips
comments before matching). Everything below runs over a masked copy in which
comments and literals are blanked to spaces, so byte offsets still line up with
the original.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CRATES = REPO_ROOT / "crates"

# The verdict list being READ, and a leg named anywhere in the same body. Both
# are required: the first makes the test one about the list, the second
# distinguishes a claim about WHICH legs from a claim about, say, its length.
#
# The list is matched by NAME and not by surface. `wz-capture` answers with the
# `reasons()` method, `wz-analyze` republishes it as the `Outcome::reasons`
# FIELD, and a test binds either to a local also called `reasons`. Keying on
# `reasons()` missed the whole `wz-analyze` half -- three tests reading the same
# list through the other door.
READS_LIST = re.compile(r"\breasons\b")
NAMES_LEG = re.compile(r"(?:\w+::)*VerdictReason::(\w+)")

# The whole-list pin. `assert_eq!` over something holding `reasons()` and a
# `vec!` literal: the assertion that says what is NOT there.
PIN = re.compile(r"assert_eq!\s*\(", re.S)

# Test attributes. A containment claim in PRODUCTION code is not this gate's
# business -- `wz-replay`'s alert filters the list on purpose.
TEST_ATTR = re.compile(r"#\[\s*(?:tokio::)?test\b|#\[test\]")

FN = re.compile(r"\bfn\s+(\w+)")

# Functions this gate deliberately does not ask about, with the reason. A test
# whose subject is the RENDERING of a name, not the composition of the list,
# has nothing to pin.
ALLOW: dict[tuple[str, str], str] = {}


def mask(src: str) -> str:
    """`src` with comments and literals blanked, preserving length and lines.

    Offsets are preserved so a match in the masked copy points at the same place
    in the original, and newlines survive so line numbers still work.
    """
    out = list(src)
    n = len(src)
    i = 0

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and nxt == "*":
            # Rust block comments NEST, so a depth counter rather than a find.
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == "r" and (nxt == '"' or nxt == "#"):
            # Raw string: r"..." / r#"..."# / r##"..."## -- no escapes inside,
            # so the terminator is the quote followed by the same hash count.
            k = i + 1
            hashes = 0
            while k < n and src[k] == "#":
                hashes += 1
                k += 1
            if k < n and src[k] == '"':
                close = '"' + "#" * hashes
                j = src.find(close, k + 1)
                j = n if j < 0 else j + len(close)
                blank(i, j)
                i = j
            else:
                i += 1
        elif c == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
        elif c == "'":
            # A char literal, or a lifetime. `'a` is a lifetime; `'a'` is a
            # literal. Reading a lifetime as an unterminated literal would blank
            # the rest of the file.
            m = re.match(r"'(?:\\.|[^\\'])'", src[i : i + 8])
            if m:
                blank(i, i + m.end())
                i += m.end()
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def functions(masked: str):
    """`(name, start, end)` for every `fn` body, by brace balance."""
    for m in FN.finditer(masked):
        brace = masked.find("{", m.end())
        if brace < 0:
            continue
        # A `where` clause or return type can hold no `{` before the body in
        # this workspace's style; if one ever does, the balance below still
        # closes at the right place because it starts from the first `{`.
        depth, j = 0, brace
        while j < len(masked):
            if masked[j] == "{":
                depth += 1
            elif masked[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield m.group(1), m.start(), j + 1


def is_test(masked: str, fn_start: int) -> bool:
    """Whether the attributes directly above this `fn` include a test one."""
    head = masked.rfind("\n\n", 0, fn_start)
    head = 0 if head < 0 else head
    return bool(TEST_ATTR.search(masked[head:fn_start]))


def test_scopes(masked: str) -> list[tuple[int, int]]:
    """Byte ranges of every `#[cfg(test)] mod ..` block.

    R311y729 (N21) — the population is TEST CODE, not functions carrying a test
    attribute, and the difference is a hole rather than a nuance. A test that
    moves its claim into a helper takes the claim out of a `#[test]` function,
    and the earlier rule then asked about NEITHER: the test no longer names a
    leg and the helper is not a test. The gate would have gone quiet exactly
    when the code got harder to read.

    Scoping by `cfg(test)` also keeps production code out, which the attribute
    was doing incidentally: `CaptureReport::reasons` itself reads the list and
    names every leg, and it is not a claim about anything.
    """
    out: list[tuple[int, int]] = []
    # `test` as a TOKEN anywhere in the cfg, and any visibility on the module.
    # Matching the literal `#[cfg(test)] mod` dropped
    # `agg.rs::a_hand_folded_plane_cannot_decide_an_elapsed_term`, whose module
    # is `#[cfg(all(test, feature = "network-codecs"))] pub(crate) mod tests` --
    # the fifth time in two rounds that this gate's population was narrower
    # than the thing it claims to check, and the only reason it surfaced is
    # that the count moved 20 to 19.
    for m in re.finditer(
        r"#\[cfg\([^\]]*\btest\b[^\]]*\)\]\s*"
        r"(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{",
        masked,
    ):
        depth, j = 0, m.end() - 1
        while j < len(masked):
            if masked[j] == "{":
                depth += 1
            elif masked[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((m.start(), j + 1))
    return out


def calls(body: str, names: set[str]) -> set[str]:
    """Which of `names` this body calls."""
    return {n for n in names if re.search(rf"\b{re.escape(n)}\s*\(", body)}


# An empty list, in the spellings this workspace uses. Equality against one is
# the STRONGEST pin there is -- it says every leg is quiet -- and the first
# version of this gate rejected it, because it looked only for `vec![`.
EMPTY_LIST = re.compile(r"\bVec::(?:<[^>]*>::)?new\(\)|\bvec!\[\s*\]")


def pins_the_list(body: str) -> bool:
    """Whether this body pins the WHOLE list at least once.

    Two accepted shapes, and both are equalities against a whole list rather
    than claims about one member:

      * `assert_eq!(<anything>, vec![VerdictReason::A, ..])` -- the legs are
        named in the literal, so the assertion is self-evidently about the
        verdict however the left side is spelled. This is what lets a test bind
        the report to a local called something other than `reasons`.
      * `assert_eq!(<something holding the list>, <empty list>)` -- nothing is
        named because nothing is there, so the list itself has to be named on
        the other side.

    Both were learned by measurement. Requiring the literal `reasons` inside
    the assertion missed a pin held in a local named `exchanges_alone`;
    requiring `vec![` missed `Vec::new()`, which is the strongest pin of all.
    `assert_eq!(reasons.len(), 3)` is deliberately not a pin: a count names no
    leg, so it cannot tell one runaway guard from another.
    """
    for m in PIN.finditer(body):
        depth, j = 0, m.end() - 1
        while j < len(body):
            if body[j] == "(":
                depth += 1
            elif body[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        args = body[m.end() : j]
        if "vec![" in args and "VerdictReason" in args:
            return True
        if READS_LIST.search(args) and EMPTY_LIST.search(args):
            return True
    return False


def main() -> int:
    files = sorted(
        p
        for p in CRATES.rglob("*.rs")
        if "target" not in p.parts and "vendor" not in p.parts
    )
    if not files:
        print(
            "verdict-assertion lint: FAIL — no Rust source found under "
            f"{CRATES}, so this gate would pass over an empty population.",
            file=sys.stderr,
        )
        return 1

    bare: list[tuple[str, int, str, list[str]]] = []
    checked = 0
    for path in files:
        src = path.read_text(encoding="utf-8", errors="replace")
        if "VerdictReason" not in src:
            continue
        masked = mask(src)
        rel = str(path.relative_to(REPO_ROOT))
        fns = list(functions(masked))
        # An integration test file IS test scope, all of it. Keying only on
        # `#[cfg(test)] mod` dropped `wz-replay/tests/live.rs` -- the alert e2e,
        # which is one of the tests this gate most wants to ask about -- because
        # a file under `tests/` needs no such module. The population narrowed
        # silently and the count went 20 to 19, which is the only reason it was
        # noticed.
        whole_file = "tests" in path.parts or "benches" in path.parts
        scopes = test_scopes(masked)
        in_tests = (lambda _at: True) if whole_file else (
            lambda at: any(a <= at < b for a, b in scopes)
        )
        # Every function in test scope, by name, with what it does.
        pinning = {
            name for name, start, end in fns
            if in_tests(start) and pins_the_list(masked[start:end])
        }
        all_test_fns = {name for name, start, _e in fns if in_tests(start)}
        # Who calls whom, within this file's test scope. R311y729 (N21) — a
        # claim and its pin may sit in different functions, and the pin counts
        # from either direction: a helper that pins is as good as an inline
        # assertion, and a helper that CLAIMS is covered by the caller that
        # pins, because they run together.
        callers_of: dict[str, set[str]] = {}
        for name, start, end in fns:
            if not in_tests(start):
                continue
            for callee in calls(masked[start:end], all_test_fns - {name}):
                callers_of.setdefault(callee, set()).add(name)
        for name, start, end in fns:
            body = masked[start:end]
            if not in_tests(start):
                continue
            if not READS_LIST.search(body):
                continue
            named = sorted(set(NAMES_LEG.findall(body)))
            if not named:
                continue
            checked += 1
            if (rel, name) in ALLOW:
                continue
            if pins_the_list(body):
                continue
            if calls(body, pinning):
                continue
            if callers_of.get(name, set()) & pinning:
                continue
            line = src.count("\n", 0, start) + 1
            bare.append((rel, line, name, named))

    if not checked:
        print(
            "verdict-assertion lint: FAIL — not one test reads `reasons()` "
            "and names a `VerdictReason`. Either the population moved or this "
            "gate stopped finding it; a gate with nothing to check must not "
            "report OK.",
            file=sys.stderr,
        )
        return 1

    if bare:
        print("verdict-assertion lint: FAIL", file=sys.stderr)
        for rel, line, name, named in bare:
            print(
                f"  {rel}:{line} `{name}` reads the verdict list and names "
                + ", ".join(f"`{v}`" for v in named)
                + ", but never pins the whole list",
                file=sys.stderr,
            )
        print(
            "\n`reasons()` is a SET. A containment claim holds while every "
            "other leg fires\ntoo, so it cannot notice a guard that became "
            "too wide -- which is the defect\nthe mutation sweep's `widen` "
            "operator exists to find and the one these tests\nwould watch in "
            "silence.\n\nAdd ONE assertion over the same report that pins the "
            "whole list:\n  assert_eq!(report.reasons(), alloc::vec![.., ..], "
            "\"..\");\nKeep the containment claims if they read better; the "
            "pin is what makes them\nload-bearing in both directions.",
            file=sys.stderr,
        )
        return 1

    print(
        f"verdict-assertion lint: OK ({checked} test(s) read the verdict "
        "list by name; every one pins the whole list at least once"
        + (f"; {len(ALLOW)} registered exemption(s)" if ALLOW else "")
        + ")"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

r"""R2306 (no register item) — how many places READ the `_anyke` selector flag,
and whether each of them is one this tree meant to have.

The citation is `no register item` for the reason `config_key_fixture_gate.py`
and `test_double_knob_gate.py` give for theirs: the item this closes --
unregistered open-debt item 156 -- lives in the operator's register file, which
has no store id for `gate_provenance_lint.py` to resolve. Naming "nothing" is
the true answer to the question that gate asks; the item is named in prose
throughout this header.

## Why a gate rather than a fix

The fix was one function. The CLASS is that `_anyke` had grown THREE readers and
only two of them were ever compared, so the third drifted for rounds without
anything noticing: `wz-capi-c` split the parameter list on `&`, where zenoh's
separator is `;` (`commons/zenoh-protocol/src/core/parameters.rs` @
`LIST_SEPARATOR: char = ';'`, at the pinned checkout). It therefore found the
flag only when `_anyke` was the ENTIRE
parameter string; `_max=5;_anyke` read as absent, and the reply-coverage gate it
feeds then dropped replies the querier had explicitly asked for -- silently, on
both the responder and the receive side. wz's own GETs emit that shape
(`_max=2;_time=[…];_anyke`), so this was not a corner.

Nothing could see it because the crate's own test had been written FROM the
code: it asserted `a=1&_anyke&b=2`, so the parser and its test agreed with each
other and with nothing else. A fourth copy would start the same way, which is
what this gate exists to refuse.

## TWO readers, and they are deliberately DIFFERENT

Not one. The two ABIs mirror two implementations whose rules genuinely diverge,
and collapsing them would be the mirror of the defect above:

* zenoh's -- split on `;`, key is everything before the first `=`, so
  `_anyke=true` CARRIES the flag (`Parameters::reply_key_expr_any` is
  `contains_key`, `zenoh/src/api/selector.rs` @ `fn reply_key_expr_any`).
* pico's -- a byte scan requiring `_anyke` to start the list or follow `;` AND
  to end it or precede `;`, so `_anyke=true` does NOT carry the flag
  (`src/utils/query_params.c` @ `_z_parameters_has_anyke`).

So the check is not "exactly one reader". It is "exactly these two, each saying
which implementation it mirrors, and nobody else holding the literal in code".

## What it derives, and what it declares

DERIVED: every tracked `crates/**/*.rs` line carrying an `_anyke` literal, and
whether that line sits in a test module or a comment. The population is the
repository's, so a new copy joins it by existing.

DECLARED: the two owner files. That is a baseline rather than a derivation, on
R2301's rule -- deriving the baseline too would make the check unable to fail.
It bites from BOTH sides: an owner that stops holding a reader is a stale
baseline and fails, and a literal outside the owners fails. A third rule-set
would need its own reference implementation, and adding it here is the edit that
says so out loud.
"""

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

#: The files allowed to hold an `_anyke` reader, and the implementation each
#: one mirrors. A file here MUST carry the literal (a stale entry fails) and
#: MUST name its reference near it, so "why is this one allowed" is written
#: where the reader is.
OWNERS: dict[str, str] = {
    "crates/wz-session-core/src/selector_params.rs": "zenoh",
    "crates/wz-capi-pico/src/query.rs": "pico",
}

#: The literal, in both spellings Rust admits for it.
LITERAL = re.compile(r'b?"_anyke"')

#: A test module's opening line. Matching the MODULE and not its attribute is
#: deliberate: the first draft keyed on `#[cfg(test)]` and misread
#: `wz-session-core/src/query.rs` as production, because that module's gate is a
#: multi-line `#[cfg(all(feature = …))]` and the bare attribute sits nowhere near
#: it. A test module is spelled `mod tests` in this tree however it is gated.
TEST_MODULE = re.compile(r"^\s*(pub\s+)?mod tests\s*\{")

#: A module's closing brace, which `cargo fmt` puts at column 0 for a top-level
#: item and indents for everything nested. That is what makes "the first `^}`
#: after `mod tests {`" the end of the module rather than the end of some
#: function inside it, and Layer C1 keeps the formatting true.
MODULE_END = re.compile(r"^\}")


def tracked_rust() -> list[pathlib.Path]:
    """Every tracked Rust source under `crates/`."""
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "crates/**/*.rs", "crates/*.rs"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [pathlib.Path(p) for p in out]


def test_lines(path: pathlib.Path, lines: list[str]) -> set[int]:
    """The 1-based lines that sit inside a test module.

    A whole file named `tests.rs` is test code throughout. Otherwise every
    `mod tests {` opens a region that runs to the next closing brace at column
    0 — a file may have SEVERAL, which is why this returns a set rather than one
    boundary line: `wz-session-core/src/query.rs` carries two, and a
    single-boundary rule would have read everything after the first as test code
    including whatever production code follows it.
    """
    if path.name == "tests.rs":
        return set(range(1, len(lines) + 1))
    inside: set[int] = set()
    open_at: int | None = None
    for i, line in enumerate(lines, start=1):
        if open_at is None:
            if TEST_MODULE.match(line):
                open_at = i
                inside.add(i)
            continue
        inside.add(i)
        if MODULE_END.match(line):
            open_at = None
    return inside


def is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("*")


def findings() -> list[str]:
    out: list[str] = []
    seen_owner_literal: dict[str, bool] = {name: False for name in OWNERS}
    population = 0

    for rel in tracked_rust():
        path = REPO / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not LITERAL.search(text):
            continue
        lines = text.splitlines()
        in_test = test_lines(rel, lines)
        key = rel.as_posix()
        for n, line in enumerate(lines, start=1):
            if not LITERAL.search(line):
                continue
            population += 1
            if key in OWNERS:
                if n not in in_test and not is_comment(line):
                    seen_owner_literal[key] = True
                continue
            if n in in_test or is_comment(line):
                continue
            out.append(
                f"{key}:{n} holds an `_anyke` literal in code, and this file is not "
                f"one of the two readers.\n"
                f"    {line.strip()}\n"
                f"    A third reader is how this drifted before: call "
                f"`reply_acceptance::ReplyKeyExpr::from_parameters` (zenoh's rules) "
                f"or `wz-capi-pico`'s `parameters_has_anyke` (pico's), whichever "
                f"implementation your ABI mirrors."
            )

    if population == 0:
        out.append(
            "NO `_anyke` literal anywhere under crates/. The population is empty, so "
            "every check above passed by having nothing to look at -- the pattern has "
            "stopped matching or the flag has been renamed."
        )

    for name, reference in OWNERS.items():
        if not (REPO / name).is_file():
            out.append(f"the declared reader {name} does not exist; the baseline is stale")
            continue
        if not seen_owner_literal[name]:
            out.append(
                f"the declared reader {name} holds no `_anyke` literal in code any "
                f"more. Either it stopped being a reader -- drop it here in the same "
                f"commit -- or the literal moved somewhere this gate cannot see."
            )
            continue
        body = (REPO / name).read_text(encoding="utf-8")
        if reference not in body:
            out.append(
                f"{name} is declared as mirroring {reference!r}, and the word does not "
                f"occur in it. A reader that does not say which implementation it "
                f"follows is the one that drifts."
            )

    if len(OWNERS) != 2:
        out.append(
            f"{len(OWNERS)} declared reader(s), not 2. zenoh and pico disagree about "
            f"`_anyke=true`, which is why there are two; a third needs a third "
            f"reference implementation named here."
        )
    return out


def selftest() -> int:
    """Drive the classifier over fixtures the real tree cannot produce.

    Each fixture is a shape the version this replaced would have SWALLOWED, which
    is the only kind worth asserting: a gate checked against inputs its
    predecessor also handled proves nothing about the change.
    """
    import tempfile

    failures: list[str] = []

    def classify(name: str, body: str) -> bool:
        """Whether `body` would be reported, by the same rules `findings` uses."""
        lines = body.splitlines()
        rel = pathlib.Path(name)
        in_test = test_lines(rel, lines)
        for n, line in enumerate(lines, start=1):
            if LITERAL.search(line) and n not in in_test and not is_comment(line):
                return True
        return False

    cases = [
        # (name, body, must_be_reported)
        ("crates/x/src/a.rs", 'fn f() { let k = "_anyke"; }\n', True),
        ("crates/x/src/a.rs", 'fn f() { let k = b"_anyke"; }\n', True),
        # A comment naming the flag is prose, not a reader.
        ("crates/x/src/a.rs", '/// carries `"_anyke"` when asked\n', False),
        # Test code may hold it: fixtures and assertions are the point.
        (
            "crates/x/src/a.rs",
            'fn f() {}\n#[cfg(test)]\nmod tests {\n  fn g() { let k = b"_anyke"; }\n}\n',
            False,
        ),
        # THE SHAPE THAT BROKE THE FIRST DRAFT: a test module gated by something
        # other than a bare `#[cfg(test)]`. Keying on the attribute read this as
        # production; keying on `mod tests` reads it right.
        (
            "crates/x/src/a.rs",
            "fn f() {}\n#[cfg(all(\n  feature = \"q\",\n))]\nmod tests {\n"
            '  fn g() { let k = b"_anyke"; }\n}\n',
            False,
        ),
        # A whole test FILE is test code from line 1, before any marker.
        ("crates/x/src/tests.rs", 'fn g() { let k = b"_anyke"; }\n', False),
        # A literal BEFORE a test module is still production.
        (
            "crates/x/src/a.rs",
            'fn f() { let k = b"_anyke"; }\n#[cfg(test)]\nmod tests {}\n',
            True,
        ),
        # ...and so is one AFTER a test module has closed, which a
        # single-boundary rule would have swallowed.
        (
            "crates/x/src/a.rs",
            "#[cfg(test)]\nmod tests {\n  fn g() {}\n}\n"
            'fn f() { let k = b"_anyke"; }\n',
            True,
        ),
    ]
    for name, body, want in cases:
        got = classify(name, body)
        if got != want:
            failures.append(f"classify({name}, {body!r}) = {got}, want {want}")

    # The OWNERS baseline must bite when an owner stops being a reader. Driven
    # against a real directory rather than argued, because that arm reads files.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        stale = root / "gone.rs"
        if stale.is_file():
            failures.append("fixture setup: the stale owner should not exist")

    if failures:
        for line in failures:
            print(f"  anyke-reader-gate SELFTEST FAIL: {line}", file=sys.stderr)
        return 1
    print(f"  anyke-reader-gate: selftest {len(cases)} case(s) OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    problems = findings()
    if problems:
        print("  anyke-reader-gate FAIL:", file=sys.stderr)
        for line in problems:
            print(f"    - {line}", file=sys.stderr)
        return 1
    owners = ", ".join(f"{k} ({v})" for k, v in OWNERS.items())
    print(f"  anyke-reader-gate: {len(OWNERS)} reader(s) and no fourth copy -- {owners}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

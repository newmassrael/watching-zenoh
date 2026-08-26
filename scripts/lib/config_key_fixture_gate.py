#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2138 (no register item) — moving a key into HONOURED changes a fixture in
ANOTHER CRATE, behind `#[ignore]`, and nothing said so.

The citation is `no register item` for the reason `debt_plane_census.py` gives
for its own: the item this closes -- unregistered open-debt item 224 -- lives in
the agent-memory register, which has no store id for `gate_provenance_lint.py`
to resolve. Naming "nothing" is a real answer here; the item is named in prose
throughout this header.

## The defect, measured twice before this existed

`HONOURED_CONFIG_KEYS` lives in `wz-runtime-tokio`. The drop-in leg of
`wz-integration-tests/tests/wz_reads_a_stock_zenohd_config.rs` carries a
HAND-WRITTEN JSON5 config and asserts that it names EVERY honoured key, so that
every flag the expansion can emit is one the demo is actually asked to accept.
Add a key and that assertion is wrong until someone edits the JSON5.

R311y845 moved three keys and did not, so hosted Layer Z went red (run
32097227053). R311y846 then added a fourth, which would have redded the same
assertion for a second reason. Neither round could have seen it locally:

  * the test is `#[ignore]`d — it needs `target/zenohd/zenohd` and a
    `--features zenoh-config` demo, so only Layer Z runs it, on hosted CI;
  * `pre-push` runs the CHANGED CRATES' tests, and the change is in
    `wz-runtime-tokio` while the fixture is in `wz-integration-tests`;
  * the unit tests that DO run look at the same key list and know nothing about
    any fixture.

## Why a static gate can answer it at all

BOTH SIDES ARE READABLE WITHOUT BUILDING ANYTHING. The key set is a
`&[&str]` in `zenoh_config.rs`; the fixture is a `format!` literal in the test.
So this reads both and compares, which costs milliseconds and is why it belongs
in a static lane AND in `pre-push` rather than behind a zenohd build.

## What it derives rather than declares

Nothing here carries a copy of anything:

  * the key set comes from the Rust constant, comments stripped (`rust_const`,
    the reader R2083 fixed after a regex counted quoted phrases inside the
    array's own `//` rationales as entries);
  * the fixture comes from its `let client_source = format!(r#"…"#)` binding,
    anchored to that binding;
  * the EXCEPTION is parsed out of the test's own `.filter(|k| *k != "…")`
    chain. A copy here would be the very drift this gate exists to catch, one
    level up.

Every anchor is a HARD FAIL when it does not match. A gate that cannot find its
subject must not report on it — and a silently empty population is the shape
this file's sibling (`count_guard_lint.py`) had to be taught to refuse.

Usage:
    python3 scripts/lib/config_key_fixture_gate.py [--verbose]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it

# `rust_const` is IMPORTED rather than copied. It is the one definition that was
# repaired after R2083's miscount, and a second copy would be a second thing to
# repair. That it lives in an audit script rather than a shared home is open-debt
# item 537's business, not this gate's; the dependency fails LOUDLY (ImportError)
# if that script is reshaped, which is the acceptable direction.
import deepenable_audit  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
KEY_SOURCE = REPO_ROOT / "crates" / "wz-runtime-tokio" / "src" / "zenoh_config.rs"
FIXTURE_TEST = (
    REPO_ROOT
    / "crates"
    / "wz-integration-tests"
    / "tests"
    / "wz_reads_a_stock_zenohd_config.rs"
)
CRATES = REPO_ROOT / "crates"

# The key sets a fixture can depend on. Derived from the Rust source below rather
# than trusted: a name here that no longer exists is reported, not ignored.
KEY_SETS = (
    "HONOURED_CONFIG_KEYS",
    "UNHONOURED_UPSTREAM_CONFIG_KEYS",
    "CONFIG_KEYS_PROVEN_ON_THE_WIRE",
    "DEEPENABLE_UPSTREAM_KEYS",
)

TEST_ATTR_RE = re.compile(r"#\[(?:tokio::)?test\b")
# The literal ends at `"#` and then the `format!` call's own `)`. Requiring a
# COMMA there is wrong and was measured wrong: this `format!` uses inline
# captured identifiers, so it has NO trailing arguments, and the comma form ran
# past the real close and swallowed four hundred lines of Rust as if they were
# config.
FIXTURE_RE = re.compile(
    r"let client_source = format!\(\s*r#\"(.*?)\"#\s*,?\s*\)", re.S
)
# The test's own exception list, anchored to the iteration it belongs to so that
# a `!=` comparison anywhere else in this 2700-line file cannot be mistaken for
# one.
EXCEPTION_RE = re.compile(
    r"HONOURED_CONFIG_KEYS\s*\.iter\(\)\s*\.copied\(\)\s*"
    r"((?:\.filter\([^)]*\)\s*)*)\.collect\(\)"
)
JSON5_TOKEN = re.compile(r'"[^"]*"|[A-Za-z_][A-Za-z0-9_]*|[{}\[\]:,]|[^\s{}\[\]:,"]+')


def rel(path: Path) -> str:
    """`path` relative to the repo when it is inside it, else as given.

    Not defensive decoration: `Path.relative_to` RAISES for anything outside the
    tree, and the raise lands while BUILDING A FAILURE MESSAGE — so the gate
    would crash instead of saying what is wrong, which is the one moment it must
    still speak. Measured while probing the anchor-miss branch against a copy
    outside the repo, and that is also the shape any future caller pointing this
    at a staged tree would hit.
    """
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def dependent_tests() -> list[tuple[str, int, str, bool, list[str]]]:
    """`(file, line, fn, ignored, key_sets)` for every test fn reading a key set.

    This is the POPULATION, and it is derived by walking `crates/**/*.rs` rather
    than by listing the files anyone remembers. The `ignored` flag is the whole
    point: those are the ones no default lane reaches, so they are the ones a
    round moving a key will not hear from.
    """
    rows = []
    for path in sorted(CRATES.rglob("*.rs")):
        src = rust_comments.strip_comments(path.read_text())
        if not any(k in src for k in KEY_SETS):
            continue
        lines = src.split("\n")
        starts = [i for i, ln in enumerate(lines) if TEST_ATTR_RE.search(ln)]
        for n, i in enumerate(starts):
            end = starts[n + 1] if n + 1 < len(starts) else len(lines)
            body = "\n".join(lines[i:end])
            used = [k for k in KEY_SETS if k in body]
            if not used:
                continue
            name = re.search(r"fn\s+([A-Za-z0-9_]+)", body)
            # The attribute block is the run of `#[...]` lines around `#[test]`;
            # `#[ignore]` sits on either side of it.
            j = i
            while j > 0 and lines[j - 1].lstrip().startswith("#["):
                j -= 1
            k = i
            while k + 1 < len(lines) and lines[k + 1].lstrip().startswith("#["):
                k += 1
            block = "\n".join(lines[j : k + 1])
            rows.append(
                (
                    rel(path),
                    i + 1,
                    name.group(1) if name else "?",
                    "#[ignore" in block,
                    used,
                )
            )
    return rows


def fixture_key_paths(literal: str) -> list[str]:
    """Every KEY PATH the JSON5 fixture names, interior nodes included.

    Interior nodes are not an afterthought: `connect/retry` is an honoured key
    whose value is an object, so a leaf-only walk reports it missing. That was
    measured on this very fixture — the first draft called it unnamed when the
    fixture names it three lines from the top.
    """
    # `format!` doubles its braces, and `{port}` is an interpolation rather than
    # a key. Neutralise the interpolation FIRST, or un-doubling turns `{port}`
    # into a stray brace.
    body = re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", '"<interp>"', literal)
    body = body.replace("{{", "{").replace("}}", "}")
    # JSON5 comments are Rust comments, and this fixture is more comment than
    # config — every block carries the round that put it there.
    body = rust_comments.strip_comments(body)

    toks = JSON5_TOKEN.findall(body)
    paths: list[str] = []
    stack: list[str | None] = []
    pending: str | None = None
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok == "{":
            stack.append(pending)
            pending = None
        elif tok == "}":
            if stack:
                stack.pop()
            pending = None
        elif tok == ",":
            pending = None
        elif tok != ":" and i + 1 < len(toks) and toks[i + 1] == ":":
            name = tok.strip('"')
            paths.append("/".join([p for p in stack if p] + [name]))
            if i + 2 < len(toks) and toks[i + 2] == "{":
                pending = name
        i += 1
    return paths


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    failures: list[str] = []

    # ── the population, derived ──────────────────────────────────────
    rows = dependent_tests()
    ignored = [r for r in rows if r[3]]
    reachable = [r for r in rows if not r[3]]
    if not rows:
        print(
            "config-key-fixture FAIL: no test reads any of "
            f"{', '.join(KEY_SETS)}. Either those constants were renamed or this "
            "gate's walk broke — both make a green run meaningless.",
            file=sys.stderr,
        )
        return 1
    if not ignored:
        print(
            "config-key-fixture FAIL: no key-set-dependent test is `#[ignore]`d, "
            "so this gate is guarding nothing. That is either a real improvement "
            "(the fixtures reached a default lane) or a broken walk — say which, "
            "in the round that caused it.",
            file=sys.stderr,
        )
        return 1

    # ── the one coupling a static read can settle ────────────────────
    honoured = deepenable_audit.rust_const("HONOURED_CONFIG_KEYS")
    if not honoured:
        print(
            "config-key-fixture FAIL: HONOURED_CONFIG_KEYS read as empty.",
            file=sys.stderr,
        )
        return 1

    test_src = FIXTURE_TEST.read_text()
    m = FIXTURE_RE.search(test_src)
    if not m:
        print(
            "config-key-fixture FAIL: could not anchor the drop-in fixture on "
            "`let client_source = format!(r#\"…\"#)` in "
            f"{rel(FIXTURE_TEST)}. The fixture moved or was "
            "renamed; re-anchor this gate rather than deleting it.",
            file=sys.stderr,
        )
        return 1
    e = EXCEPTION_RE.search(test_src)
    if not e:
        print(
            "config-key-fixture FAIL: could not anchor the fixture's own "
            "exception list (`HONOURED_CONFIG_KEYS.iter().copied().filter(…)"
            ".collect()`). This gate refuses to carry its own copy of that "
            "list, so it cannot proceed without reading the test's.",
            file=sys.stderr,
        )
        return 1

    excepted = re.findall(r'\*k\s*!=\s*"([^"]+)"', e.group(1))
    named = set(fixture_key_paths(m.group(1)))
    in_scope = [k for k in honoured if k not in excepted]
    missing = [k for k in in_scope if k not in named]

    if not in_scope:
        print(
            "config-key-fixture FAIL: every honoured key is excepted, so nothing "
            "was checked.",
            file=sys.stderr,
        )
        return 1

    if missing:
        failures.append(
            f"the drop-in fixture in {rel(FIXTURE_TEST)} does "
            f"not name {len(missing)} honoured key(s): {', '.join(missing)}. "
            f"That leg asserts the fixture names every honoured key a connecting "
            f"client can carry, so it will RED — and only on hosted Layer Z, "
            f"which needs zenohd and a `--features zenoh-config` demo. Add the "
            f"key to the JSON5 in the round that honours it, or except it there "
            f"with a reason."
        )

    # Keys that are honoured but deliberately absent, and the OTHER ignored
    # fixtures whose oracle is a running binary. Counted and named, because an
    # unexplained skip is how a gate becomes decorative — and a LUMPED skip
    # count is the same failure one step later.
    stale_exceptions = [k for k in excepted if k not in honoured]
    if stale_exceptions:
        failures.append(
            f"the fixture excepts {', '.join(stale_exceptions)}, which "
            f"HONOURED_CONFIG_KEYS no longer contains — an exception that has "
            f"outlived its fact still narrows the check."
        )

    if args.verbose:
        for f, ln, name, _ig, used in ignored:
            print(f"  guard {f}:{ln} {name} <- {','.join(used)}")
        for f, ln, name, _ig, used in reachable:
            print(f"  local {f}:{ln} {name} <- {','.join(used)}")
        for k in excepted:
            print(f"  skip  {k} — excepted by the fixture's own filter")

    print(
        f"config-key-fixture: {len(honoured)} honoured key(s); "
        f"{len(in_scope)} checked against the drop-in fixture, "
        f"{len(excepted)} excepted by the test's own filter"
    )
    print(
        f"  population: {len(rows)} key-set-dependent test(s) — "
        f"{len(ignored)} behind `#[ignore]` (no default lane reaches them), "
        f"{len(reachable)} a default lane does"
    )
    # The other ignored legs are named so the list is a list, not a number: this
    # gate settles ONE of them statically and says so.
    others = [r for r in ignored if r[2] != "a_wz_node_configured_only_by_a_stock_zenoh_config_reaches_a_real_zenohd"]
    print(
        f"  of those {len(ignored)}, this gate settles the drop-in fixture "
        f"statically; the other {len(others)} judge wz against a RUNNING zenohd, "
        f"which no static read can stand in for"
    )

    if failures:
        print("config-key-fixture FAIL:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

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

## The three sites, and why they accumulate here

Each is a different obligation the SAME pair of files carries, and each was
added by the round that found it. They share this gate because they share the
reason a static read is the only local answer: both sides are on disk, and the
leg that would otherwise notice needs a built zenohd and runs only hosted.

  * the DROP-IN fixture must name every honoured key (R2138, item 224);
  * the DEFAULTS leg must CLASS every honoured key (R2142, item 225's red —
    the round that moved two keys updated the first site and not this one, so
    this gate went green while hosted Layer Z went red);
  * the CENSUS fixture must fill NO key that would move the denominator
    (R2147, item 217).

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
# ── the FOURTH site's inputs (R2202, open-debt item 220) ──
DEMO_ARGS = CRATES / "wz-ap-demo" / "src" / "args.rs"
DEMO_MANIFEST = CRATES / "wz-ap-demo" / "Cargo.toml"
RUN_CI = REPO_ROOT / "scripts" / "run-ci.sh"
# The test whose lane build decides whether a wire claim was measurable at all.
WIRE_LEG_TEST = "wz_reads_a_stock_zenohd_config"

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


# ── the SECOND site in the same file (R2142, open-debt item 225's red) ──
#
# The drop-in fixture is not the only thing a honoured key obliges. The same
# file's `the_defaults_each_implementation_falls_back_to_are_pinned_against_a_
# real_zenohd` partitions EVERY honoured key into four classes and asserts the
# union is exactly `HONOURED_CONFIG_KEYS`. R2141 moved two keys into that list,
# updated the fixture this gate already covered, and did not class them — so
# this gate went green and hosted Layer Z went red (run 33022841480).
#
# That is the same defect shape this file was built for, one assertion over. It
# is settled here for the same reason: both sides are on disk, and the lane that
# would otherwise catch it needs a built zenohd and only runs hosted.
DEFAULT_CLASS_CONSTS = (
    "STATED",
    "THE_TREE_ANSWERS_NULL",
    "A_BLOCK_ON_ONE_SIDE_AND_LEAVES_ON_THE_OTHER",
)
# The fourth class is a `Vec` of (key, expected) pairs rather than a `&[&str]`,
# so it is anchored on its own binding and only the tuple's FIRST position is
# read. Anchoring on the binding keeps a `("…", …)` tuple elsewhere in this
# 2700-line file from being mistaken for a class member.
CLAIMS_RE = re.compile(
    r"let claims: Vec<\(&str, String\)> = vec!\[(.*?)\n    \];", re.S
)


def local_const(src: str, name: str) -> list[str] | None:
    """A `const NAME: &[&str] = &[…]` declared INSIDE a function body.

    `deepenable_audit.rust_const` reads the reader's own source at module
    scope; these live inside the test fn, so they need their own anchor. Same
    comment-stripping discipline, and for the same measured reason: these arrays
    carry `//` rationales that quote key-shaped phrases.
    """
    # Non-greedy to the FIRST `];`, and deliberately NOT requiring a newline
    # before it: `STATED` is declared on ONE line, and a newline-anchored form
    # ran past it into the next array — which this gate's own duplicate check
    # caught, reporting 17 keys in two classes (R2142, measured).
    m = re.search(r"const " + name + r": &\[&str\] = &\[(.*?)\];", src, re.S)
    if not m:
        return None
    return re.findall(r'"([^"]+)"', rust_comments.strip_comments(m.group(1)))


def default_class_keys(src: str) -> tuple[dict[str, list[str]], list[str]]:
    """Every honoured key's class in the defaults leg, plus anchor failures."""
    classes: dict[str, list[str]] = {}
    problems: list[str] = []
    for name in DEFAULT_CLASS_CONSTS:
        found = local_const(src, name)
        if found is None:
            problems.append(
                f"could not anchor `const {name}: &[&str]` in "
                f"{rel(FIXTURE_TEST)} — the defaults leg's classes moved or "
                f"were renamed; re-anchor this gate rather than dropping the "
                f"check"
            )
            continue
        classes[name] = found
    m = CLAIMS_RE.search(src)
    if not m:
        problems.append(
            "could not anchor the defaults leg's `let claims: Vec<(&str, "
            "String)> = vec![…]` — the compared class is where a key with a "
            "real wz-side default lives, so this gate cannot account for the "
            "surface without it"
        )
    else:
        body = rust_comments.strip_comments(m.group(1))
        classes["claims"] = re.findall(r'\(\s*"([^"]+)"\s*,', body)
    return classes, problems


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


# ── the FOURTH site (R2202, open-debt item 220) ──
#
# `CONFIG_KEYS_PROVEN_ON_THE_WIRE` says a leg READ the key off a frame the node
# wrote. That claim is about the build the leg runs on, and nothing checked that
# the lane actually builds a node the key can reach.
#
# It is not hypothetical: `transport/multicast/qos/enabled` is the first wire key
# whose sink is COMPILED OUT of a narrow build — `--multicast-qos` exits(2)
# without `transport-qos`, so `config_keys_the_demo_drops` drops the key — and
# the demo's own classification test therefore has to defer it to `no sink` in
# any build lacking the feature. That deferral is only sound while the LANE has
# the feature; if it did not, the key would be claimed wire-proven by a node that
# cannot expand it, and the classification test would report a clean partition in
# every build while the claim was true in none.
#
# Both sides are on disk — the drop guards are `cfg!` expressions in the demo's
# source, the lane's feature list is the `--features` on the build line that
# precedes the leg's own invocation — so a static read answers it, which is what
# puts it in this file rather than behind a zenohd.
GUARD_RE = re.compile(
    r"if\s+!cfg!\((.*?)\)\s*\{(.*?)\n    \}", re.S
)
CFG_FEATURE_RE = re.compile(r'feature\s*=\s*"([^"]+)"')
DROPS_FN_RE = re.compile(
    r"fn config_keys_the_demo_drops\(\) -> Vec<&'static str> \{(.*?)\n    out\n",
    re.S,
)
# `name = ["a", "wz/b"]` in the demo manifest's `[features]` table. Only the
# entries WITHOUT a `/` are this package's own features; `wz/x` enables a feature
# of the facade, which no `cfg!` in the demo's own source can read.
MANIFEST_FEATURES_RE = re.compile(r"^\[features\]$(.*?)^\[", re.S | re.M)
MANIFEST_ROW_RE = re.compile(r"^([A-Za-z0-9_-]+)\s*=\s*\[(.*?)\]", re.S | re.M)


def drop_guards(src: str) -> tuple[list[tuple[str, list[str]]], list[str]]:
    """`(cfg expression, keys it drops)` for every guard in the drop list.

    Derived from the function's own body, never listed here: a guard added
    without this gate hearing about it is exactly the drift the file exists for.
    """
    m = DROPS_FN_RE.search(src)
    if not m:
        return [], [
            f"could not anchor `fn config_keys_the_demo_drops` in "
            f"{rel(DEMO_ARGS)} — the drop guards are one half of this check, so "
            f"re-anchor it rather than dropping the check"
        ]
    body = rust_comments.strip_comments(m.group(1))
    guards = [
        (expr.strip(), re.findall(r'out\.push\("([^"]+)"\)', block))
        for expr, block in GUARD_RE.findall(body)
    ]
    guards = [(expr, keys) for expr, keys in guards if keys]
    if not guards:
        return [], [
            f"read ZERO drop guards out of `config_keys_the_demo_drops` in "
            f"{rel(DEMO_ARGS)}. An empty guard set makes every wire claim look "
            f"reachable, which is the one direction this check must never "
            f"report as clean."
        ]
    return guards, []


def cfg_satisfied(expr: str, features: frozenset[str]) -> bool:
    """Whether a `cfg!` expression holds for `features`.

    Three shapes occur and each is read for what it means, not matched loosely:
    a bare `feature = "x"`, an `all(..)` of them, and an `any(..)` of them. An
    expression in none of those shapes RAISES rather than defaulting either way —
    a guard this reader cannot understand must not be silently satisfied.
    """
    names = CFG_FEATURE_RE.findall(expr)
    if not names:
        raise ValueError(f"no feature named in cfg expression {expr!r}")
    if expr.startswith("all("):
        return all(n in features for n in names)
    if expr.startswith("any("):
        return any(n in features for n in names)
    if len(names) == 1 and expr.startswith("feature"):
        return names[0] in features
    raise ValueError(f"unrecognised cfg expression {expr!r}")


def demo_feature_closure(named: frozenset[str]) -> frozenset[str]:
    """`named` plus every demo feature they transitively enable.

    Resolved from the demo's own manifest rather than by asking cargo, because
    this gate runs in `pre-push` where a cargo invocation is the whole budget.
    The transitive step is load-bearing and was measured to be: R2202's lane line
    names `router-multicast-faces`, which enables `router-hat-router` without
    naming it, so a literal membership test would refuse a feature the build has.
    """
    table: dict[str, list[str]] = {}
    block = MANIFEST_FEATURES_RE.search(DEMO_MANIFEST.read_text())
    if block:
        for name, body in MANIFEST_ROW_RE.findall(block.group(1)):
            table[name] = [
                v for v in re.findall(r'"([^"]+)"', body) if "/" not in v
            ]
    out = set(named)
    queue = list(named)
    while queue:
        for nxt in table.get(queue.pop(), []):
            if nxt not in out:
                out.add(nxt)
                queue.append(nxt)
    return frozenset(out)


def wire_leg_lane_features() -> tuple[frozenset[str], list[str]]:
    """The `--features` of the demo build that the wire leg's lane runs on.

    ANCHORED on the leg's own invocation and then scanned BACKWARD to the nearest
    demo build, rather than unioning every build line in the file: a feature some
    OTHER lane passes says nothing about the binary this leg spawns, and a union
    would let one lane's feature satisfy another lane's claim.
    """
    txt = RUN_CI.read_text()
    invocation = txt.find(f"--test {WIRE_LEG_TEST} ")
    if invocation < 0:
        return frozenset(), [
            f"could not find the wire leg's `--test {WIRE_LEG_TEST}` invocation "
            f"in {rel(RUN_CI)} — without it this gate cannot say which build the "
            f"wire claims were measured on"
        ]
    builds = list(
        re.finditer(
            r"cargo build -p wz-ap-demo[^\n|)]*?--features ([A-Za-z0-9_,-]+)",
            txt[:invocation],
        )
    )
    if not builds:
        return frozenset(), [
            f"found the wire leg's invocation in {rel(RUN_CI)} but no "
            f"`cargo build -p wz-ap-demo --features …` before it — the lane's "
            f"binary is what the wire claims are about"
        ]
    return frozenset(builds[-1].group(1).split(",")), []


def fixture_fn_literal(src: str, name: str) -> str | None:
    """The JSON5 literal a `fn <name>(port: u16) -> String` returns.

    The two config-building fns are anchored on their SIGNATURE rather than on a
    `let`, because they are free functions rather than bindings inside a test.
    Same close as `FIXTURE_RE` and for the same measured reason — no trailing
    argument, so no comma to require.
    """
    m = re.search(
        r"fn " + name + r"\(port: u16\) -> String \{\s*format!\(\s*r#\"(.*?)\"#\s*,?\s*\)",
        src,
        re.S,
    )
    return m.group(1) if m else None


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

    # ── the SECOND site: the defaults leg's four-class accounting ────
    classes, class_problems = default_class_keys(test_src)
    failures.extend(class_problems)
    accounted: list[str] = []
    for members in classes.values():
        accounted.extend(members)
    if not class_problems:
        if not accounted:
            failures.append(
                "the defaults leg's four classes read as EMPTY — an accounting "
                "of nothing passes every comparison below, which is the one "
                "direction this gate must never report as clean."
            )
        dupes = sorted({k for k in accounted if accounted.count(k) > 1})
        if dupes:
            failures.append(
                f"the defaults leg classes {', '.join(dupes)} twice — a key in "
                f"two classes is two different decisions about one silence."
            )
        unclassed = [k for k in honoured if k not in set(accounted)]
        if unclassed:
            failures.append(
                f"the defaults leg does not class {', '.join(unclassed)}. Every "
                f"honoured key needs a decision about what wz falls back to when "
                f"the file is silent — compared, or named as one the tree cannot "
                f"answer. This is what redded hosted Layer Z after R2141, and "
                f"only a built zenohd would otherwise say so."
            )
        orphaned = [k for k in set(accounted) if k not in honoured]
        if orphaned:
            failures.append(
                f"the defaults leg classes {', '.join(sorted(orphaned))}, which "
                f"HONOURED_CONFIG_KEYS no longer contains — a class that has "
                f"outlived its key."
            )

    # ── the THIRD site: the CENSUS fixture (R2147, open-debt item 217) ───
    #
    # The census leg's denominator is whatever a running zenohd resolves from
    # `census_config`, and several upstream keys are OPAQUE SUBTREES that
    # serialise as one leaf when unset and as their own contents when filled.
    # So a fixture that fills one of them makes the census measure the FIXTURE:
    # measured (R311y842), the same run against `operator_config` reported
    # `metadata/name` where the canonical surface has `metadata`.
    #
    # That reason lived only in the fixture's doc comment. The constants half of
    # it is now a unit test in `zenoh_config.rs`
    # (`the_census_denominator_is_the_surface_of_a_document_that_fills_nothing`);
    # this is the FIXTURE half, and it is here for the same reason the two sites
    # above are — the fixture is in `wz-integration-tests`, the deepenable list
    # is in `wz-runtime-tokio`, and the leg that would notice needs a built
    # zenohd and runs only on hosted Layer Z.
    deepenable = deepenable_audit.rust_const("DEEPENABLE_UPSTREAM_KEYS")
    if not deepenable:
        print(
            "config-key-fixture FAIL: DEEPENABLE_UPSTREAM_KEYS read as empty, so "
            "no path can sit below one and the census check below would pass on "
            "any fixture at all.",
            file=sys.stderr,
        )
        return 1

    def below_a_deepenable_key(path: str) -> str | None:
        for key in deepenable:
            if path.startswith(key + "/"):
                return key
        return None

    census_literal = fixture_fn_literal(test_src, "census_config")
    control_literal = fixture_fn_literal(test_src, "operator_config")
    census_filled: list[tuple[str, str]] = []
    control_filled: list[tuple[str, str]] = []
    if census_literal is None or control_literal is None:
        missing_fn = "census_config" if census_literal is None else "operator_config"
        failures.append(
            f"could not anchor `fn {missing_fn}(port: u16) -> String` in "
            f"{rel(FIXTURE_TEST)}. The census denominator comes from that "
            f"fixture, so this gate cannot say whether it fills a subtree — "
            f"re-anchor it rather than dropping the check."
        )
    else:
        census_filled = [
            (p, k)
            for p in fixture_key_paths(census_literal)
            if (k := below_a_deepenable_key(p)) is not None
        ]
        # The POSITIVE CONTROL, and it is not decoration. This check can only be
        # trusted if it can SEE the shape it forbids, and the file already
        # contains one: `operator_config` fills `metadata`. A control that stops
        # finding it means the walk broke, and a broken walk reports every
        # fixture clean.
        control_filled = [
            (p, k)
            for p in fixture_key_paths(control_literal)
            if (k := below_a_deepenable_key(p)) is not None
        ]
        if census_filled:
            failures.append(
                "the census fixture fills "
                + ", ".join(f"`{p}` (below `{k}`)" for p, k in census_filled)
                + f" in {rel(FIXTURE_TEST)}. Those are subtrees a real zenohd "
                f"resolves as ONE leaf when unset, so the census would report "
                f"the fixture's surface as the upstream denominator. Keep "
                f"`census_config` filling nothing optional; put the shape in "
                f"`operator_config`, which is not what the denominator is taken "
                f"from."
            )
        if not control_filled:
            failures.append(
                f"the positive control found NO filled subtree in "
                f"`operator_config` ({rel(FIXTURE_TEST)}). That fixture is "
                f"supposed to look like a real operator's file, and the census "
                f"check above is only meaningful if this walk can see the shape "
                f"it forbids — an empty control means the walk broke, not that "
                f"the tree is clean."
            )

    # ── the FOURTH site: the LANE that measured a wire claim (R2202, item 220) ──
    #
    # See the block comment above `drop_guards` for the defect. In one sentence:
    # a wire-proven key whose sink this build can compile out is only honestly
    # wire-proven while the LANE running the leg carries the feature that keeps
    # the sink, and nothing said so.
    guards, guard_problems = drop_guards(DEMO_ARGS.read_text())
    failures.extend(guard_problems)
    lane_named, lane_problems = wire_leg_lane_features()
    failures.extend(lane_problems)
    wire_keys = deepenable_audit.rust_const("CONFIG_KEYS_PROVEN_ON_THE_WIRE")
    lane_closure: frozenset[str] = frozenset()
    unreachable: list[tuple[str, str]] = []
    control_dropped: list[str] = []
    in_lane_scope: list[tuple[str, str]] = []
    if guards and lane_named:
        lane_closure = demo_feature_closure(lane_named)
        try:
            for expr, keys in guards:
                held = cfg_satisfied(expr, lane_closure)
                # The POSITIVE CONTROL, and it is over EVERY guard rather than
                # only the in-scope ones, so it stays live even in a tree where
                # no wire key has a feature-dependent sink. With no features at
                # all, every guarded key must read as dropped; if one does not,
                # the expression reader is broken and a clean verdict below would
                # mean nothing.
                if not cfg_satisfied(expr, frozenset()):
                    control_dropped.extend(keys)
                for key in keys:
                    if key not in wire_keys:
                        continue
                    in_lane_scope.append((key, expr))
                    if not held:
                        unreachable.append((key, expr))
        except ValueError as e:
            failures.append(
                f"a drop guard in {rel(DEMO_ARGS)} is in a shape this gate "
                f"cannot read ({e}); teach the reader the shape rather than "
                f"letting an unread guard count as satisfied"
            )
        for key, expr in unreachable:
            failures.append(
                f"`{key}` is in CONFIG_KEYS_PROVEN_ON_THE_WIRE and the lane that "
                f"runs the wire leg builds wz-ap-demo WITHOUT what `!cfg!({expr})` "
                f"needs, so the demo drops the key there. A wire claim is a claim "
                f"that a leg read the value off a frame the node WROTE; a node "
                f"that cannot expand the key writes no such frame. Add the "
                f"feature to that lane's build line, or take the key out of the "
                f"wire list."
            )
        if not control_dropped:
            failures.append(
                f"the positive control dropped NO key when handed an empty "
                f"feature set, so `cfg_satisfied` is not reading the guards in "
                f"{rel(DEMO_ARGS)}. A reader that answers 'satisfied' to "
                f"everything reports every lane clean."
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
    if classes:
        breakdown = ", ".join(
            f"{name}={len(members)}" for name, members in sorted(classes.items())
        )
        print(
            f"  defaults leg: {len(set(accounted))} honoured key(s) classed "
            f"({breakdown})"
        )
    if census_literal is not None and control_literal is not None:
        # The control's finding is printed rather than merely asserted: it is
        # the evidence that a clean census line means something.
        print(
            f"  census fixture: {len(deepenable)} denominator-shifting key(s), "
            f"{len(census_filled)} filled by `census_config`; control "
            f"`operator_config` fills "
            + ", ".join(f"{p}" for p, _ in control_filled)
        )

    if guards and lane_named:
        # The scope is printed as a LIST rather than a count, and beside the
        # control, because an empty scope is a legitimate tree state — no wire
        # key with a feature-dependent sink — and the reader has to be able to
        # tell that from a check that stopped working.
        print(
            f"  wire lane: {len(wire_keys)} wire-proven key(s), "
            f"{len(in_lane_scope)} with a feature-dependent sink "
            f"({', '.join(k for k, _ in in_lane_scope) or 'none'}); the leg's "
            f"lane names {len(lane_named)} feature(s), {len(lane_closure)} after "
            f"the manifest's own closure; control drops "
            f"{len(control_dropped)} key(s) at no features"
        )

    if failures:
        print("config-key-fixture FAIL:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

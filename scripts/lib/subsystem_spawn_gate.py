#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2366 (no register item) — a production task must name the SUBSYSTEM it runs
on, so `WZ_RUNTIME` paces a running node instead of five runtimes nobody uses.

The citation is `no register item` for the reason `debt_plane_census.py` gives
for its own: what this answers for is the `runtime-tokio` atom's surviving
residual, which lives in the atomic store's inventory reason rather than as a
§-numbered register item `gate_provenance_lint.py` can resolve.

## The defect, in the residual's own words

    "nothing in wz SELECTS a subsystem. Every wz spawn still goes through
    TokioRuntime onto the ambient runtime, so WZ_RUNTIME is inert in a real
    node and the max_blocking_threads dial is reachable by no caller."

R311y825 built the partition — five runtimes under zenoh's own names, defaults
and handover, with an isolation test that keeps the pre-fix measurement green as
its discriminator. What it did not do is REACH production: every seam kept
spawning onto whichever runtime was ambient, so an operator could tune all five
and pace nothing. A substrate with no caller is the shape this gate exists to
stop coming back.

## Why a gate and not a test

`cargo test` cannot fail on a spawn that names no subsystem. Every partition
test builds its own pool or names a subsystem itself, so the whole target passes
unchanged against a tree where no production code ever named one — which is
precisely the tree R311y825 left behind, and it was green for many rounds. The
property is about the SOURCE, so the source is what gets read.

## The two derivations, and why there are two

A one-sided check here is the "a population of zero reports green" trap. If this
only swept for the ambient spellings, deleting every spawn in the tree would
report a clean partition; if it only counted named ones, a single named site
beside twenty ambient ones would pass.

  * AMBIENT — `tokio::spawn`, `tokio::task::spawn`, `tokio::task::spawn_blocking`
    and `TokioRuntime.spawn`, in production code, outside the substrate that
    DEFINES them. Must be empty.
  * NAMED — `WzRuntime::<Subsystem>.` and `PartitionedRuntime::<CONST>.`
    prefixed spawns, same population rule. Must be non-empty, and the set of
    subsystems it reaches must be all five: upstream names all five
    (`commons/zenoh-runtime/src/lib.rs` @ `pub enum ZRuntime`, 48 sites), so
    a wz that reached only two would be reporting a partition it does not have.

Neither number is written down here. Both come out of the same walk, and the
SUBSYSTEM SET is asserted rather than a count, because a count cannot tell four
`tx` sites from one of each.

## What is production, and what is the substrate

Production is `crates/*/src/**.rs` minus `#[cfg(test)]` blocks: `tests/` targets
are free to reach for the ambient runtime, and several must (tokio's paused
clock is per-runtime, so a test that advances time has to share a runtime with
what it observes).

The substrate is `wz-runtime-tokio/src/runtime_impl.rs` and `runtime_pool.rs` —
the two modules that DEFINE ambient spawning and partitioned spawning. A gate
that counted their own definitions would be asking them not to exist.

The `spawn_on` escapes take a `tokio::runtime::Handle` and spawn through it.
They are not in either population by construction — the runtime is the caller's
argument, not a spelling in this file — and that is the right answer: the seam
that hands the choice to its caller has not made one.

Usage:
    python3 scripts/lib/subsystem_spawn_gate.py [--verbose]
    python3 scripts/lib/subsystem_spawn_gate.py --selftest
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it

REPO_ROOT = Path(__file__).resolve().parents[2]
CRATES = REPO_ROOT / "crates"

# The two modules that DEFINE spawning. Their own bodies are what every other
# site delegates to, so they are excluded by identity rather than by a rule.
SUBSTRATE = (
    CRATES / "wz-runtime-tokio" / "src" / "runtime_impl.rs",
    CRATES / "wz-runtime-tokio" / "src" / "runtime_pool.rs",
)

# The subsystems the partition declares. Derived from the Rust enum below rather
# than listed, so a variant added upstream-side and mirrored in wz widens this
# gate's obligation instead of silently leaving a subsystem unreached.
SUBSYSTEM_SOURCE = CRATES / "wz-runtime-tokio" / "src" / "runtime_pool.rs"
SUBSYSTEM_ENUM_RE = re.compile(r"pub enum WzRuntime \{(.*?)\n\}", re.S)
SUBSYSTEM_VARIANT_RE = re.compile(r"^\s{4}([A-Z][A-Za-z0-9]*),", re.M)

# The ambient spellings: a task put on "whichever runtime is current".
#
# The LAST alternative was added by this gate's own control probe, which found
# it green where it had to be red. Handing `WriterHandle::spawn_on` a
# `Handle::current()` puts the writer back on the ambient runtime as surely as
# `tokio::spawn` does — it is the same defect under a different spelling, and
# the first three alternatives could not see it. A delegating seam is only as
# named as its argument.
#
# ⚠ THE LIMIT, stated rather than implied: this reads the handle AT the call. A
# production site that bound `let h = Handle::current();` and passed `h` two
# lines later would evade it, and no static reader of this size follows that.
# `Handle::current()` elsewhere is deliberately NOT swept — `wz-capi-core`
# captures one to `enter()` a face's runtime from a C application thread, which
# is not a task placement and would be a false positive.
AMBIENT_RE = re.compile(
    r"(?<![\w:])(?:tokio::spawn|tokio::task::spawn|tokio::task::spawn_blocking"
    r"|TokioRuntime\s*\.\s*spawn)\s*\("
    r"|(?<![\w])spawn(?:_on|_blocking)?\s*\(\s*(?:tokio::runtime::)?Handle::current\(\)"
)

# A site that NAMES its subsystem. Both spellings reach the same pool:
# `WzRuntime::Rx.spawn(..)` returns tokio's own `JoinHandle`, and
# `PartitionedRuntime::RX.spawn(..)` returns the trait-wrapped one, so a call
# site picks whichever the surrounding types already use.
#
# `.handle()` is in the verb set beside the two spawns, and it is not padding:
# the two `spawn_on` seams hand their runtime to the caller, and the caller
# names it by fetching a subsystem's handle. Leaving `handle` out made this gate
# blind to exactly the sites whose choice is most easily reverted — the
# convenience form could start passing `Handle::current()` and nothing here
# would move.
#
# ⚠ The lookbehind rejects a WORD character only, NOT a `::`. A path-qualified
# `crate::runtime_pool::WzRuntime::Net` is the same reach as a bare one, and the
# first draft of this gate excluded `:` as well — which quietly dropped eleven
# of the twenty-five sites this round wrote, printed `14 named`, and reported
# green. A gate must be able to explain every number it prints.
NAMED_RE = re.compile(
    r"(?<![\w])(?:WzRuntime::([A-Z][A-Za-z0-9]*)|PartitionedRuntime::([A-Z][A-Z0-9_]*))"
    r"\s*\.\s*(?:spawn(?:_blocking)?|handle)\s*\("
)

# `PartitionedRuntime`'s constants spell the subsystem in SCREAMING_CASE. Read
# from the source so a renamed constant reds here rather than quietly dropping
# its subsystem out of the reached set.
CONST_RE = re.compile(
    r"pub const ([A-Z][A-Z0-9_]*): Self = Self::new\(WzRuntime::([A-Z][A-Za-z0-9]*)\);"
)


def cfg_test_spans(text: str) -> list[tuple[int, int]]:
    """Character spans of every `#[cfg(test)]` item, by brace matching."""
    spans: list[tuple[int, int]] = []
    for m in re.finditer(r"#\[cfg\(test\)\]", text):
        i = text.find("{", m.end())
        if i < 0:
            continue
        depth = 0
        j = i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        spans.append((m.start(), j))
    return spans


def production_sources() -> list[Path]:
    """Every `crates/*/src/**.rs` outside the substrate, sorted."""
    out = [
        p
        for p in sorted(CRATES.glob("*/src/**/*.rs"))
        if p.resolve() not in {s.resolve() for s in SUBSTRATE}
    ]
    return out


def scan(text: str, pattern: re.Pattern[str]) -> list[tuple[int, re.Match[str]]]:
    """Matches outside comments and outside `#[cfg(test)]`, with 1-based lines."""
    stripped = rust_comments.strip_comments(text)
    skip = cfg_test_spans(stripped)
    hits = []
    for m in pattern.finditer(stripped):
        if any(a <= m.start() <= b for a, b in skip):
            continue
        hits.append((stripped.count("\n", 0, m.start()) + 1, m))
    return hits


def declared_subsystems() -> set[str]:
    src = SUBSYSTEM_SOURCE.read_text()
    body = SUBSYSTEM_ENUM_RE.search(rust_comments.strip_comments(src))
    if body is None:
        raise SystemExit(
            f"subsystem-spawn FAIL: cannot find `pub enum WzRuntime` in "
            f"{SUBSYSTEM_SOURCE.relative_to(REPO_ROOT)}; this gate must not "
            f"report on a partition it cannot read"
        )
    variants = set(SUBSYSTEM_VARIANT_RE.findall(body.group(1)))
    if not variants:
        raise SystemExit("subsystem-spawn FAIL: `WzRuntime` declares no variant")
    return variants


def const_map() -> dict[str, str]:
    src = rust_comments.strip_comments(SUBSYSTEM_SOURCE.read_text())
    return {c: variant for c, variant in CONST_RE.findall(src)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    declared = declared_subsystems()
    consts = const_map()
    unknown_const = {c: v for c, v in consts.items() if v not in declared}
    if unknown_const:
        print(
            f"subsystem-spawn FAIL: `PartitionedRuntime` constant(s) {unknown_const} "
            f"name a subsystem `WzRuntime` does not declare",
            file=sys.stderr,
        )
        return 1

    ambient: list[str] = []
    reached: dict[str, list[str]] = {}
    named_total = 0

    for path in production_sources():
        text = path.read_text()
        rel = path.relative_to(REPO_ROOT)
        for line, _ in scan(text, AMBIENT_RE):
            ambient.append(f"{rel}:{line}")
        for line, m in scan(text, NAMED_RE):
            variant = m.group(1) or consts.get(m.group(2) or "")
            if variant is None or variant not in declared:
                print(
                    f"subsystem-spawn FAIL: {rel}:{line} names "
                    f"`{m.group(0)}`, which resolves to no declared subsystem",
                    file=sys.stderr,
                )
                return 1
            reached.setdefault(variant, []).append(f"{rel}:{line}")
            named_total += 1

    failures: list[str] = []
    if ambient:
        failures.append(
            f"{len(ambient)} production spawn(s) name no subsystem, so they land "
            f"on whichever runtime is ambient and `WZ_RUNTIME` cannot pace them: "
            + ", ".join(ambient)
        )
    if named_total == 0:
        failures.append(
            "no production spawn names a subsystem at all — the partition has no "
            "caller, which is the state this gate exists to refuse (and is why an "
            "empty ambient sweep alone must not report green)"
        )
    unreached = sorted(declared - set(reached))
    if unreached:
        failures.append(
            f"declared subsystem(s) {unreached} are reached by no production "
            f"spawn; zenoh names all {len(declared)} of its own, so a partition "
            f"this narrow is one wz does not have"
        )

    if args.verbose or failures:
        print(
            f"  subsystem-spawn: {named_total} named production spawn(s) over "
            f"{len(declared)} subsystem(s) "
            + ", ".join(
                f"{v}={len(reached.get(v, []))}" for v in sorted(declared)
            )
            + f"; {len(ambient)} ambient"
        )
    if args.verbose:
        for variant in sorted(reached):
            for site in reached[variant]:
                print(f"    {variant}: {site}")

    if failures:
        print("subsystem-spawn FAIL:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    return 0


def selftest() -> int:
    """Drive both derivations over fixtures, so the reader is graded too."""
    consts = const_map()
    declared = declared_subsystems()

    cases: list[tuple[str, str, int, int]] = [
        # (name, source, expected ambient hits, expected named hits)
        ("bare tokio spawn", "fn f() { tokio::spawn(g()); }", 1, 0),
        (
            "commented-out spawn",
            "fn f() { /* tokio::spawn(g()); */ let _ = 1; }",
            0,
            0,
        ),
        (
            "doc comment naming the spelling",
            "/// was `tokio::spawn(fut)` before R2366\nfn f() {}",
            0,
            0,
        ),
        (
            "under cfg(test)",
            "#[cfg(test)]\nmod t {\n    fn f() { tokio::spawn(g()); }\n}",
            0,
            0,
        ),
        ("named by enum", "fn f() { WzRuntime::Rx.spawn(g()); }", 0, 1),
        (
            "named by constant",
            "fn f() { PartitionedRuntime::ACCEPTOR.spawn(g()); }",
            0,
            1,
        ),
        ("blocking, named", "fn f() { WzRuntime::Application.spawn_blocking(g); }", 0, 1),
        (
            "path-qualified is the same reach",
            "fn f() { crate::runtime_pool::WzRuntime::Net.spawn(g()); }",
            0,
            1,
        ),
        (
            "a longer identifier ending in the type name is NOT",
            "fn f() { MyWzRuntime::Net.spawn(g()); }",
            0,
            0,
        ),
        (
            "naming a subsystem's handle is naming it",
            "fn f() { WzRuntime::Tx.handle().clone() }",
            0,
            1,
        ),
        (
            "handle parameter is neither",
            "fn f(h: tokio::runtime::Handle) { h.spawn(g()); }",
            0,
            0,
        ),
        (
            "TokioRuntime is ambient",
            "fn f() { TokioRuntime.spawn(g()); }",
            1,
            0,
        ),
        (
            "ambient blocking spawn",
            "fn f() { tokio::task::spawn_blocking(g); }",
            1,
            0,
        ),
        # The case this gate's own control probe found it blind to.
        (
            "a delegation fed the current handle is ambient",
            "fn f() { Self::spawn_on(tokio::runtime::Handle::current(), rx, t) }",
            1,
            0,
        ),
        (
            "a delegation fed a named handle is not",
            "fn f() { Self::spawn_on(WzRuntime::Tx.handle().clone(), rx, t) }",
            0,
            1,
        ),
        (
            "capturing a handle to enter() is not a task placement",
            "fn f() { let _g = tokio::runtime::Handle::current().enter(); }",
            0,
            0,
        ),
    ]

    failures = []
    for name, src, want_ambient, want_named in cases:
        got_ambient = len(scan(src, AMBIENT_RE))
        got_named = len(scan(src, NAMED_RE))
        if got_ambient != want_ambient or got_named != want_named:
            failures.append(
                f"{name}: expected ambient={want_ambient} named={want_named}, "
                f"got ambient={got_ambient} named={got_named}"
            )

    # The constant table must resolve, or the SCREAMING_CASE half of NAMED_RE
    # silently classifies nothing.
    missing = sorted(declared - set(consts.values()))
    if missing:
        failures.append(
            f"`PartitionedRuntime` has no constant for subsystem(s) {missing}, so "
            f"a call site spelling them that way would resolve to nothing"
        )

    if failures:
        print("subsystem-spawn SELFTEST FAIL:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print(f"  subsystem-spawn selftest: {len(cases)} case(s) OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

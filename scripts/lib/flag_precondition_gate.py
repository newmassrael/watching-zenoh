#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2144 (no register item) — THE PRECONDITION SET, DERIVED FROM BOTH SIDES.

The citation is `no register item` for the reason its siblings give: the item
this closes -- unregistered open-debt item 218 -- lives in the agent-memory
register, which has no store id for `gate_provenance_lint.py` to resolve. The
item is named in prose throughout this header.

## The defect, and why its neighbour does not already cover it

R311y844 found the shape by TRIPPING OVER IT three times: the expansion emitted
`--scout-timeout-ms` unconditionally, and `main` refuses that flag without
`--scout`, so a VALID stock config expanded into a node that exits(2). The three
kinds of precondition it hit -- a cargo feature, a sibling flag, an endpoint
scheme -- were each found by RUNNING the demo, never by reading it.

R2140 (item 219) built the dynamic half:
`every_flag_the_expansion_emits_carries_the_precondition_main_refuses_without`
expands each fixture row in three shapes and asserts the resulting argv carries
the partner. That gate is real and this one does not replace it. But it can only
judge a rule some shape actually STAGES, and measured on this tree it stages 3
of 11:

    argv-precondition: 11 rule(s) ... 34 check(s) over 32 row(s) x 3 shape(s)
      skip --autoconnect-strategy       — no shape emits it
      skip --reconnect                  — no shape emits it
      ... (8 of the 11)

Item 218 is exactly that skip bucket. "No shape emits it" is an OBSERVATION, and
it lumps three different facts under one sentence: the expansion has no emission
site for the flag at all; it has one that this build's features compile out; or
it has one and the fixture table simply never triggers it. Only the third is a
hole, and the sentence cannot tell you which you are looking at. Measured while
building this: SEVEN of those eight flags have no site anywhere in `args.rs`,
and `--scout-autoconnect-strategy` HAS one (`args.rs:988`) -- so today the bucket
is already six parts derivable fact and one part accident.

## What this derives, and from where

Both sides are on disk, so neither has to be staged:

  * the RULES come from the same files the Rust gate reads, and that file list is
    read out of ITS `REFUSAL_SOURCES` const rather than copied -- so a third
    source joins both readers at once, or this one fails loudly;
  * the SITES come from `args.rs`: every `Expansion::pair` / `Expansion::presence`
    call and every raw `added.push`, with the table-driven ones resolved through
    the `for (key, flag, ...) in [...]` literal they loop over. R2140 measured
    what happens to a reader that does not do this: a regex over
    `exp.pair("k", "--flag"` literals missed 22 emissions and reported a
    population of 3.

The invariant is then decidable WITHOUT running anything:

    a flag the binary refuses without a partner is either one the expansion has
    no site for, or one it emits only behind a guard.

That is the y844 defect, statically. It does not say the guard is the RIGHT one
-- that is the dynamic gate's half, when a shape reaches it -- and the breakdown
below prints, for every guarded site, whether the partner is named in the guard
directly, through one binding, or not textually at all.

## What it will not tell you, stated rather than hidden

A precondition the binary does not enforce BY REFUSING is not in the derived
rule set. `--tls-ca` is the standing example: emitting it into a run with no
`tls/` link opens a file for nothing, and `main` refuses nothing, so its guard
(`NO_TLS_LINK`) lands in the "guarded for a reason the binary does not refuse"
class rather than against a rule. Deriving THAT class needs an oracle for what
the binary DOES with a flag, not for what it refuses -- a different seam.

Every anchor is a HARD FAIL when it does not resolve, and an empty population is
a failure rather than a clean run. A gate that cannot find its subject must not
report on it.

Usage:
    python3 scripts/lib/flag_precondition_gate.py [--verbose]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SRC = REPO_ROOT / "crates" / "wz-ap-demo" / "src"
ARGS_RS = DEMO_SRC / "args.rs"

# The Rust gate's own list of files the binary refuses from. Anchored, not
# copied: R2141 had to ADD `args.rs` beside `main.rs` when a flag pair validated
# inside its own parser turned out to be invisible to a `main.rs`-only reader,
# and a second hand-maintained copy of that list is a second thing to get wrong.
REFUSAL_SOURCES_RE = re.compile(
    r"const REFUSAL_SOURCES: &\[&str\] = &\[(.*?)\];", re.S
)
INCLUDE_STR_RE = re.compile(r'include_str!\("([^"]+)"\)')

# Where the expansion's own source ends. Every emission site is above the first
# test module; a `"--publish"` inside a test's shape constant is not an emission
# and must never be read as one.
TEST_MODULE_ANCHOR = "#[cfg(all(test"

CALL_RE = re.compile(r"exp\.(pair|presence)\s*\(")
PUSH_RE = re.compile(r"exp\.added\.push\s*\(")
# A table-driven site's loop. The array is written INLINE at some sites and
# BOUND TO A NAME at others (`let preconditioned: [...] = [...]`), and a reader
# that knows only the inline form does not merely miss those sites -- measured on
# this gate's own first run, it walked PAST the named table to an earlier inline
# one and attributed five flags to the wrong keys. Both forms, or a failure.
FOR_TABLE_RE = re.compile(r"for\s*\(([^)]*)\)\s*in\s*(\[|[A-Za-z_][A-Za-z0-9_]*)", re.S)
LET_RE = r"let\s+%s\s*(?::[^=]*)?=\s*"


class GateFailure(Exception):
    """An anchor did not resolve, or the population came back empty."""


# ── reading Rust ────────────────────────────────────────────────────


def string_literals(src: str) -> list[str]:
    """Every double-quoted literal, escapes left as written.

    Deliberately naive about comments, matching the Rust helper this mirrors:
    both sweeps want OVER-inclusion on the rule side, where a flag named in a
    comment and nowhere else is still a rule someone wrote down.
    """
    out: list[str] = []
    i = 0
    while i < len(src):
        if src[i] != '"':
            i += 1
            continue
        start = i + 1
        j = start
        while j < len(src) and src[j] != '"':
            j += 2 if src[j] == "\\" else 1
        out.append(src[start : min(j, len(src))])
        i = min(j, len(src)) + 1
    return out


def flatten(lit: str) -> str:
    """A refusal literal with its `\\`-continuations flattened.

    THE MESSAGES SPAN LINES. `--query-timeout-ms requires --query` is written as
    a `\\`-continued literal, and R2140 measured a line-at-a-time reader finding
    four of these where there were twenty.
    """
    out: list[str] = []
    i = 0
    while i < len(lit):
        c = lit[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        j = i + 1
        if j < len(lit) and lit[j].isspace():
            while j < len(lit) and lit[j].isspace():
                j += 1
            out.append(" ")
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def first_flag(text: str) -> str | None:
    at = text.find("--")
    if at < 0:
        return None
    token = ""
    for ch in text[at:]:
        if ch.isalnum() or ch == "-":
            token += ch
        else:
            break
    return token if len(token) > 2 else None


def balanced(src: str, open_paren: int) -> str:
    """The text between `(` at `open_paren` and its matching `)`."""
    depth = 0
    i = open_paren
    in_str = False
    while i < len(src):
        c = src[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return src[open_paren + 1 : i]
        i += 1
    raise GateFailure(
        f"unbalanced parenthesis at offset {open_paren} in {ARGS_RS.name}: this "
        "reader cannot see where the call ends, so it must not report on it"
    )


def split_args(text: str) -> list[str]:
    """Top-level comma split, respecting nesting and string literals."""
    out: list[str] = []
    depth = 0
    in_str = False
    cur = ""
    i = 0
    while i < len(text):
        c = text[i]
        if in_str:
            cur += c
            if c == "\\":
                cur += text[i + 1 : i + 2]
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            cur += c
        elif c in "([{":
            depth += 1
            cur += c
        elif c in ")]}":
            depth -= 1
            cur += c
        elif c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += c
        i += 1
    if cur.strip():
        out.append(cur.strip())
    return out


def as_literal(arg: str) -> str | None:
    arg = arg.strip()
    if arg.startswith('"') and arg.endswith('"') and len(arg) >= 2:
        return arg[1:-1]
    return None


# ── the two derived populations ─────────────────────────────────────


def refusal_sources() -> list[Path]:
    """The files the binary refuses from, read out of the Rust gate's const."""
    src = ARGS_RS.read_text()
    m = REFUSAL_SOURCES_RE.search(src)
    if not m:
        raise GateFailure(
            "flag-precondition: FAIL -- `const REFUSAL_SOURCES` was not found in "
            f"{ARGS_RS.name}. That const is where the Rust gate names the files "
            "the binary refuses from, and this gate reads it so the two cannot "
            "disagree. If it was renamed, move this anchor in the same commit."
        )
    names = INCLUDE_STR_RE.findall(m.group(1))
    if not names:
        raise GateFailure(
            "flag-precondition: FAIL -- `REFUSAL_SOURCES` resolved to no "
            "`include_str!` file. An empty source list would derive zero rules "
            "and pass everything."
        )
    paths = []
    for name in names:
        path = DEMO_SRC / name
        if not path.is_file():
            raise GateFailure(
                f"flag-precondition: FAIL -- `REFUSAL_SOURCES` names {name}, "
                f"which is not a file at {path}."
            )
        paths.append(path)
    return paths


def refusal_rules(sources: list[Path]) -> tuple[list[tuple[str, str]], list[str]]:
    """`(flag, needs)` pairs, and the flags whose precondition is a feature."""
    pairs: list[tuple[str, str]] = []
    feature_gated: list[str] = []
    for path in sources:
        for lit in string_literals(path.read_text()):
            flat = flatten(lit)
            # The `wz-ap-demo: ` prefix is OPTIONAL -- `main` carries it in its
            # own refusals and ADDS it to the ones a parser in `args.rs` hands
            # back, so requiring it is requiring the refusal to live in one file.
            body = flat[len("wz-ap-demo: ") :] if flat.startswith("wz-ap-demo: ") else flat
            if " requires " not in body:
                continue
            before, after = body.split(" requires ", 1)
            flag = first_flag(before)
            if flag is None:
                continue
            if "feature" in after and not after.lstrip().startswith("--"):
                if flag not in feature_gated:
                    feature_gated.append(flag)
                continue
            needs = first_flag(after)
            if needs is None:
                continue
            if (flag, needs) not in pairs:
                pairs.append((flag, needs))
    return pairs, feature_gated


class Site:
    """One place the expansion can put a flag on the argv."""

    def __init__(self, flag: str, key: str, guard: str, where: str, at: int = 0) -> None:
        self.flag = flag
        self.key = key
        self.guard = guard  # the RESOLVED source text of the `blocked` argument
        self.where = where  # `pair` / `presence` / `push`
        self.at = at  # byte offset of the call, so a binding resolves from here

    @property
    def guarded(self) -> bool:
        return self.guard.strip() != "None"


def expansion_source() -> str:
    """`args.rs` above its first test module, comments blanked."""
    src = ARGS_RS.read_text()
    idx = src.find(TEST_MODULE_ANCHOR)
    if idx < 0:
        raise GateFailure(
            f"flag-precondition: FAIL -- no `{TEST_MODULE_ANCHOR}` module "
            f"attribute in {ARGS_RS.name}. This reader cuts the file there so a "
            "flag literal inside a test's shape constant is never read as an "
            "emission; without the cut it would over-report silently."
        )
    return rust_comments.strip_comments(src[:idx])


def resolve_binding(src: str, before: int, name: str) -> str | None:
    """The most recent `let <name> = ...` initializer before `before`."""
    last = None
    for m in re.finditer(LET_RE % re.escape(name), src[:before]):
        last = m
    if last is None:
        return None
    tail = src[last.end() :]
    depth = 0
    in_str = False
    for i, c in enumerate(tail):
        if in_str:
            if c == "\\":
                continue
            if c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth == 0:
            return tail[:i]
    return None


def resolve_table(src: str, call_at: int, binding: str) -> tuple[list[str], list[list[str]]]:
    """The loop bindings and the rows of the table a site's call sits inside.

    The table-driven sites are `for (key, flag, ...) in <table>`, and R2140
    measured what a reader that stops at literal call sites reports: a population
    of 3 where there were 25. An unresolvable one is a FAILURE here, never a skip
    -- under-reporting is the one defect this gate must not have.

    Rows come back as COLUMN TEXT, not as `(key, flag)`, because the guard is a
    per-row column at some sites (`preconditioned`) and a loop-body binding at
    others (the tls table's `let blocked = (!usable).then_some(...)`). A reader
    that assumed the second shape everywhere would read a row whose guard column
    is `None` as guarded -- the false negative this gate exists to refuse.
    """
    tables = [m for m in FOR_TABLE_RE.finditer(src[:call_at])]
    for m in reversed(tables):
        names = [n.strip() for n in m.group(1).split(",")]
        if binding not in names:
            continue
        # The NEAREST loop that binds this name is the one the call is inside.
        # Falling through to an older one when this table cannot be read is how
        # the first draft of this reader misattributed five flags, so from here
        # every failure is raised rather than searched past.
        if m.group(2) == "[":
            body = balanced(src, m.end() - 1)
        else:
            init = resolve_binding(src, m.start(), m.group(2))
            if init is None or "[" not in init:
                raise GateFailure(
                    "flag-precondition: FAIL -- the loop at offset "
                    f"{m.start()} iterates `{m.group(2)}`, and this reader found "
                    "no `let` binding an array literal to that name. The flags "
                    "that table emits would go uncounted."
                )
            body = balanced(init, init.index("["))
        rows: list[list[str]] = []
        for row in split_args(body):
            row = row.strip()
            if not row.startswith("("):
                continue
            cols = split_args(balanced(row, 0))
            if len(cols) != len(names):
                raise GateFailure(
                    f"flag-precondition: FAIL -- a row of the table at offset "
                    f"{m.start()} has {len(cols)} column(s) for {len(names)} "
                    "loop binding(s). This reader will not guess which column "
                    "is the flag."
                )
            rows.append(cols)
        if not rows:
            raise GateFailure(
                "flag-precondition: FAIL -- the table binding "
                f"`{binding}` at offset {m.start()} yielded no `(key, flag)` "
                "row this reader could read. A table whose rows stopped being "
                "tuple literals needs this reader moved in the same commit."
            )
        return names, rows
    raise GateFailure(
        f"flag-precondition: FAIL -- an emission site passes `{binding}` as its "
        "flag and no enclosing `for (...) in [...]` table binds that name. This "
        "reader will not guess which flag reaches the argv."
    )


def guard_text(src: str, call_at: int, arg: str) -> str:
    """The guard's own source. An identifier is resolved to what it was bound to.

    Resolved FROM THE CALL BACKWARDS, not from the end of the file: `blocked` is
    the name of half a dozen different guards in this source, and the last one
    in the file is almost never the one a given site passes.
    """
    a = arg.strip()
    if a != "None" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", a):
        init = resolve_binding(src, call_at, a)
        if init is None:
            raise GateFailure(
                f"flag-precondition: FAIL -- an emission site at offset "
                f"{call_at} guards with `{a}`, and this reader found neither a "
                "`let` for it before the call nor a loop column of that name. A "
                "guard it cannot read is a guard it must not grade."
            )
        return init
    return a


def emission_sites(src: str) -> list[Site]:
    sites: list[Site] = []
    for m in CALL_RE.finditer(src):
        args = split_args(balanced(src, m.end() - 1))
        if len(args) < 3:
            raise GateFailure(
                f"flag-precondition: FAIL -- an `exp.{m.group(1)}` call at "
                f"offset {m.start()} has {len(args)} argument(s); this reader "
                "expects (key, flag, value, blocked)."
            )
        guard = args[-1]
        flag_lit = as_literal(args[1])
        key_lit = as_literal(args[0])
        if flag_lit is not None and key_lit is not None:
            sites.append(
                Site(flag_lit, key_lit, guard_text(src, m.start(), guard), m.group(1), m.start())
            )
            continue
        if flag_lit is None:
            binding = args[1].strip()
            names, rows = resolve_table(src, m.start(), binding)
            flag_col = names.index(binding)
            if "key" not in names:
                raise GateFailure(
                    f"flag-precondition: FAIL -- the table behind the "
                    f"`exp.{m.group(1)}` call at offset {m.start()} binds no "
                    "`key`, so this reader cannot name the config key that "
                    "emits the flag."
                )
            key_col = names.index("key")
            # The guard is a per-row COLUMN when the loop binds it, and a
            # loop-body `let` otherwise. Both, or the row is not graded.
            guard_col = names.index(guard.strip()) if guard.strip() in names else None
            for cols in rows:
                flag = as_literal(cols[flag_col])
                key = as_literal(cols[key_col])
                if flag is None or key is None:
                    raise GateFailure(
                        "flag-precondition: FAIL -- a row of the table behind "
                        f"offset {m.start()} has a non-literal key or flag "
                        f"({cols[key_col]!r}, {cols[flag_col]!r}). Skipping it "
                        "would drop an emission from the population."
                    )
                row_guard = (
                    cols[guard_col]
                    if guard_col is not None
                    else guard_text(src, m.start(), guard)
                )
                sites.append(Site(flag, key, row_guard, m.group(1), m.start()))
            continue
        raise GateFailure(
            f"flag-precondition: FAIL -- an `exp.{m.group(1)}` call at offset "
            f"{m.start()} names flag `{flag_lit}` with a key this reader cannot "
            "resolve."
        )
    for m in PUSH_RE.finditer(src):
        arg = balanced(src, m.end() - 1).strip()
        lit = first_flag(arg) if '"--' in arg else None
        if lit is not None:
            sites.append(Site(lit, "(endpoint arm)", "None", "push"))
            continue
        inner = re.fullmatch(r"String::from\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", arg)
        if inner:
            init = resolve_binding(src, m.start(), inner.group(1))
            if init is None:
                raise GateFailure(
                    "flag-precondition: FAIL -- a raw `added.push` at offset "
                    f"{m.start()} pushes `{inner.group(1)}`, and this reader "
                    "found no `let` for it. A flag reaching the argv through a "
                    "binding this gate cannot resolve is exactly the emission "
                    "it would miss."
                )
            flags = [f for f in re.findall(r'"(--[a-z0-9-]+)"', init)]
            if not flags:
                raise GateFailure(
                    "flag-precondition: FAIL -- the binding behind the "
                    f"`added.push` at offset {m.start()} names no flag literal."
                )
            for flag in flags:
                sites.append(Site(flag, "(endpoint arm)", "None", "push"))
            continue
        # A push with no flag literal and no flag-valued binding is the VALUE
        # half of a `flag, value` pair. Named in the breakdown rather than
        # dropped, so a new one that IS a flag is visible.
        sites.append(Site("", "(value)", arg, "push-value"))
    return sites


# ── the checks ──────────────────────────────────────────────────────


def partner_naming(site: Site, needs: str, src: str) -> str:
    """How the site's guard names the partner: directly, via a binding, or not."""
    if needs in site.guard:
        return "named in the guard"
    for ident in re.findall(r"\b([a-z_][a-z0-9_]*)\b", site.guard):
        init = resolve_binding(src, site.at, ident)
        if init and needs in init:
            return f"named through `{ident}`"
    return "not named textually"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    try:
        sources = refusal_sources()
        rules, feature_gated = refusal_rules(sources)
        src = expansion_source()
        sites = emission_sites(src)
    except GateFailure as exc:
        print(str(exc), file=sys.stderr)
        return 1

    flag_sites = [s for s in sites if s.flag]
    value_pushes = [s for s in sites if not s.flag]

    if not rules:
        print(
            "flag-precondition: FAIL -- no `<flag> requires <flag>` refusal was "
            f"derived from {', '.join(p.name for p in sources)}. With no rules "
            "every site below would pass unexamined.",
            file=sys.stderr,
        )
        return 1
    if not flag_sites:
        print(
            "flag-precondition: FAIL -- no emission site was derived from "
            f"{ARGS_RS.name}. A population of zero is the shape where a broken "
            "reader reports everything covered.",
            file=sys.stderr,
        )
        return 1

    ruled = {flag for flag, _ in rules}
    failures: list[str] = []

    # THE INVARIANT. A flag the binary refuses without a partner is either one
    # the expansion has no site for, or one it emits only behind a guard.
    guarded_by_rule: list[str] = []
    for flag, needs in rules:
        for site in [s for s in flag_sites if s.flag == flag]:
            if not site.guarded:
                failures.append(
                    f"{site.key} emits `{flag}` with no precondition "
                    f"(`blocked: None`), and the binary refuses `{flag}` without "
                    f"`{needs}`. A stock config naming that key expands into a "
                    "node that exits(2) -- R311y844's defect, in a new place. "
                    "Give the site a `blocked` guard, or say why the refusal "
                    "cannot reach it."
                )
                continue
            naming = partner_naming(site, needs, src)
            if naming == "not named textually":
                # A guard that does not mention the partner is not evidence about
                # the partner. MEASURED while building this: dropping the sibling
                # half of this site's guard and leaving its `no_sink` half in
                # place is invisible to the dynamic gate at `--features
                # zenoh-config` -- the key is dropped in that build, so no shape
                # emits the flag and the rule comes back as `skip`. Requiring the
                # guard to NAME what it guards against is what makes that
                # decidable here, and all three of this tree's rule-sites already
                # do (two directly, one through `autoconnect_expanded`).
                failures.append(
                    f"{site.key} emits `{flag}` behind a guard that never names "
                    f"`{needs}`, which is the flag the binary refuses it without. "
                    f"The guard reads `{site.guard.strip()[:60]}`. Name the "
                    "partner in the guard, or through one binding, so the "
                    "precondition is checkable where it is written."
                )
                continue
            guarded_by_rule.append(f"{flag} <- {site.key} ({naming})")

    no_site = [f"{flag} requires {needs}" for flag, needs in rules if flag not in {s.flag for s in flag_sites}]

    # THE OTHER DIRECTION. Every site lands in exactly one class, and the union
    # is the whole population -- an accounting that does not add up is a reader
    # that stopped seeing something.
    guarded_other = [s for s in flag_sites if s.guarded and s.flag not in ruled]
    unguarded_free = [s for s in flag_sites if not s.guarded and s.flag not in ruled]
    ruled_sites = [s for s in flag_sites if s.flag in ruled]
    accounted = len(guarded_other) + len(unguarded_free) + len(ruled_sites)
    if accounted != len(flag_sites):
        print(
            f"flag-precondition: FAIL -- {accounted} site(s) classified of "
            f"{len(flag_sites)}. The classes are meant to partition the "
            "population; one that does not is a reader with a blind spot.",
            file=sys.stderr,
        )
        return 1

    print(
        f"flag-precondition: {len(rules)} rule(s) from "
        f"{'+'.join(p.name for p in sources)}; {len(flag_sites)} emission site(s) "
        f"in {ARGS_RS.name}"
    )
    print(
        f"  sites: {len(ruled_sites)} guarded against a rule, "
        f"{len(guarded_other)} guarded for a reason the binary does not refuse, "
        f"{len(unguarded_free)} unguarded and unrefused"
    )
    print(
        f"  rules: {len(guarded_by_rule)} reach a site, {len(no_site)} have no "
        f"site in this source, {len(feature_gated)} are about a cargo feature"
    )
    for line in guarded_by_rule:
        print(f"    rule-site {line}")
    for line in no_site:
        print(f"    no site   {line} -- the expansion has no place that emits it")
    if args.verbose:
        for site in guarded_other:
            print(f"    other     {site.flag} <- {site.key}: {site.guard.strip()[:70]}")
        for site in unguarded_free:
            print(f"    free      {site.flag} <- {site.key}")
        for site in value_pushes:
            print(f"    value     push {site.guard.strip()[:60]}")

    if failures:
        print("", file=sys.stderr)
        print("flag-precondition: FAIL", file=sys.stderr)
        for line in failures:
            print(f"  {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

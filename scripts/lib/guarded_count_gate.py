#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2167 (no register item) — RUN the count guards a static read cannot resolve,
when the push moves the test set they count.

The citation is `no register item` for `debt_plane_census.py`'s reason: the
class this answers for has never had a store row. It lives in `run-ci.sh`
prose, which is precisely the arrangement that failed.

## The defect, measured three times

`count_guard_lint.py` (R311y569, widened R2137) checks a count guard by READING
both sides: `N` in `run-ci.sh`, and the `#[test]` census of the file the guard
names. That works only when the test set does not depend on the build
configuration, so the lint declares the rest OUT OF SCOPE — 189 of 291 guards
as of this round — and says why for each. That list is honest and it is also a
hole: a guard nothing checks statically is a guard nothing checks at all until
its lane runs on hosted CI, which is a round later at best.

`C1AY stock_config_tests` is that hole three times over. Its module is
`#[cfg(all(test, feature = "zenoh-config"))]` and its invocation applies a
substring filter, so it is out of scope on TWO of the lint's counts:

  * R2112 (`1c119ac2`) added a case and left the count at 32; hosted C1ay was
    red from that commit until R2117 found it while doing something else;
  * R2124 (`fda06748`) added another and left it at 33; R2129 paid it off;
  * R2166 (`4bf43166`) added `every_argv_only_key_says_which_kind_of_unproven_it_is`
    and left BOTH legs (37 and 42) where they were. Hosted run 33132637389 went
    red on the same push, and R2167 — this round — is the repayment.

Each round wrote the reason into a comment beside the guard, and the comment
R2117 wrote is quoted almost verbatim by the one R2124 wrote. A memo is not a
mechanism; this is the mechanism.

## Why this one must RUN, and why that is still cheap

The number is not derivable without resolving `#[cfg]` against a feature set,
which is a build. So this gate builds — but only when the push has plausibly
moved the test set a guard counts, and only the guards that push reaches:

  * the PACKAGE must be one the push changed;
  * the diff must add or remove a line that can change which tests EXIST — a
    `#[test]` / `#[ignore]` / `#[cfg]` / `#[cfg_attr]` attribute, or a `mod`
    declaration. A push that edits test BODIES cannot move a count and pays
    nothing. R2158 is why `#[cfg]` is in that list and `#[test]` alone is not:
    it moved two counts by REMOVING a feature gate above tests that already
    existed;
  * the guard's SELECTION must reach a changed file — `--test T` needs
    `tests/T.rs` itself to have changed, everything else needs a changed file
    under `src/`;
  * and when the guard applies a substring filter, that filter must occur in a
    changed file of that package, or in the MODULE PATH such a file gives its
    tests. R2631 added the second half: a libtest filter matches
    `auth_dispatch::tests::a_test`, a path the file `src/auth_dispatch.rs`
    never spells, and text-only matching let `C1y auth_dispatch` go unreached
    while that push moved its count.

MEASURED on R2166's own commit: 3 guards selected out of the 17 that name
`wz-ap-demo`, and out of 291 in the file. The whole C1ay lane is 175s; the two
legs this would have run are 27s and 17s.

## The one thing it deliberately does NOT do

It does not decide whether a guard is statically checkable. `count_guard_lint.py`
owns that judgement, and a second copy of it here would drift from the first the
day either moved — the very failure both gates are about, one level up. The
populations therefore OVERLAP rather than partition: a guard this selects may
also be checked statically, and running it twice costs time, never correctness.
Both read the same guard table through the same parser, imported from that file.

## The residue, stated rather than hidden

The filter test asks whether the filter STRING occurs in a file the push
changed. A test added to `src/a.rs` inside a module declared in `src/b.rs` is
therefore not selected when only `a.rs` changed. Widening it to the whole
package would select all 17 `wz-ap-demo` guards on any test edit, which is the
175s lane, so the narrow rule is a deliberate trade and not an oversight.
Hosted CI remains the full answer.

## Item 787 (with 759 and 752) — why the oracle was not asked, and what changed

Three pushes of this tree left a count guard behind and each surfaced only on a
hosted run: C1l (27 -> 37, `6a108810`), C1aq (25 -> 23, `5f9e0417`) and C1ns
(24 -> 26, `05b66969`). The register's reading was a SELECTION hole: the oracle
picked a guard only when the guard's own line changed. MEASURED at each of those
commits, with the gate as the commit carried it, that reading is false: all three
guards were SELECTED (`wz-session-core ... --lib reassembly`, `wz-runtime-tokio
... --lib advanced_`, `wz-runtime-zephyr --lib`) without their lines changing.

What the measurement found instead is that the oracle's answer was never asked
for. Selecting a guard is free; MEASURING it is one cargo build per feature
set. 4 guards cost 492 s cold and 146 s warm on this tree, 74 guards cost ~25
minutes on R2708's push, and for that reason the hook prints the count and
defers the run (`WZ_PREPUSH_COUNT_GUARD`). A gate whose verdict costs more than
the push is a gate nobody runs, so a moved count reached origin three times
while the selection was right every time.

So the repair is mostly cost, and the selection changes below are the holes the
measurement did find:

  * the guard's OWN line changing now selects it. The ledger entry that repaired
    C1ns records the oracle "reached none of the changed lines" from a range
    that edited only `run-ci.sh`, i.e. a number edited to the wrong value was
    unverifiable by the one tool that exists to verify it;
  * a `Cargo.toml` / `build.rs` change reaches every guard of its package. A
    feature table moves a count with no `#[cfg]` line in any diff;
  * the target kind is read: `--lib` reads `src/`, `--test T` reads `tests/T.rs`
    and the shared helper modules under `tests/`, and a guard that names neither
    reads both. Before, `tests/` never reached a guard that named no target;
  * "did the test set change" compares the shape of the file at the range's
    base with the shape at its head (attributes, `mod`, `fn`, `macro_rules!`
    and macro invocations, including multi-line attributes) instead of grepping
    diff lines, so a feature moved on the second line of a `#[cfg(any(...))]`
    counts;
  * a libtest filter with `::` is a necessary condition per segment, so
    `foo::tests::` is no longer unreachable from a file whose text never spells
    that path, and removed tests count (the filter is looked for in the OLD text
    too);
  * the guards the shell assembles are RESOLVED, by running the lane in a bash
    sandbox (`guarded_count_shell.py`), not deferred. What stays deferred is
    named with the reason;
  * a guard that selects `--ignored` tests is measured by LISTING them
    (`-- --ignored --list`): those tests run against hosted-provisioned inputs
    (a `zenohd` binary, a pico CLI) a developer machine lacks, and the count of
    tests `--ignored` selects is the count the lane's run prints when they pass.

Cost: a measurement is cached under the clone's git directory, keyed by the
command and a digest of the package's shape (its manifest closure plus the
attribute/`mod`/`fn`/macro lines of every source file). A push that edits bodies
re-asks nothing; the author who ran the gate while the work was warm pays
nothing again at push time. The routable guards of one run go through ONE `bx`
call instead of one each, because the per-call overhead was ~17 of ~36 warm
seconds. `--cached-only` answers from the cache and never builds.

759: bx's refusal to run on a tree with untracked files is reported as an
ENVIRONMENT error naming the files, not as "measured nothing". 752: a second
measurement in the same worktree is refused at once, naming the first, instead of
queueing behind a cargo lock the first holds.

Exit codes, one meaning each (a caller that has to act on the difference, the
pre-push hook, must be able to tell them apart):

    0  every reached guard was judged and equals its declared number (or none
       is reached)
    1  a measured or cached count DISAGREES with the declared number: a known
       wrong number
    2  nothing could be judged: run-ci.sh parsed to no guards, the range could
       not be read, bx declined the tree, a run printed no summary, or the
       tool itself failed. This says nothing about any count
    3  `--cached-only` only: no reached guard disagrees, but at least one has no
       measurement for this tree, so it was not judged
    4  another measurement already holds this worktree's lock

`--cached-only` prints one line starting `guarded-count gate: cached-only:` with
the reached / equal / disagree / not-measured counts, so a caller need not parse
the per-guard lines.

Usage:
    python3 scripts/lib/guarded_count_gate.py --range <base>..<head> [--verbose]
    python3 scripts/lib/guarded_count_gate.py --range <base>..<head> --count-only
    python3 scripts/lib/guarded_count_gate.py --range <base>..<head> --cached-only
    python3 scripts/lib/guarded_count_gate.py --selftest
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import count_guard_lint as cgl  # noqa: E402  -- after the path insert
import feature_closure  # noqa: E402  -- the one reader of run-ci.sh's builds
import guarded_count_shell as gcs  # noqa: E402  -- what bash makes of a guard
import rust_comments  # noqa: E402  -- comments are not attributes (R2131)

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNCI = REPO_ROOT / "scripts" / "run-ci.sh"
CRATES = REPO_ROOT / "crates"

# A line whose addition or removal can change which tests EXIST. Test BODIES are
# deliberately absent: editing one cannot move a count, and including them would
# make every crate push pay for a build.
#
# Kept for the callers that hand `select` diff lines and no file shapes (the
# selftest's older arms); the gate itself decides from `shape_lines` below.
TRIGGER_RE = re.compile(
    r"#\[(?:tokio::)?test\b"
    r"|#\[ignore\b"
    r"|#\[cfg\b"
    r"|#\[cfg_attr\b"
    r"|^\s*(?:pub\s+)?mod\s+[A-Za-z0-9_]+\s*[;{]"
)
SUMMARY_RE = re.compile(r"^test result: ok\. (\d+) passed", re.M)
LIST_SUMMARY_RE = re.compile(r"^(\d+) tests?, \d+ benchmarks?$", re.M)

# Item 787 — the shape of a source file: every line that can change WHICH tests
# exist or what their paths are, and no line that cannot. Two texts with equal
# shapes have the same test set unless a macro they invoke generates tests, which
# is why a macro invocation that is not a std one counts as shape.
STD_MACROS = frozenset(
    "assert assert_eq assert_ne debug_assert debug_assert_eq debug_assert_ne "
    "println eprintln print eprint format write writeln vec panic unreachable "
    "todo unimplemented matches dbg env option_env concat stringify include "
    "include_str include_bytes cfg line file column module_path compile_error "
    "thread_local lazy_static format_args".split()
)
ATTR_START_RE = re.compile(r"^\s*#!?\[")
FN_RE = re.compile(r"\bfn\s+[A-Za-z_]")
MOD_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_]")
MACRO_DEF_RE = re.compile(r"\bmacro_rules!")
MACRO_CALL_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)!\s*[({\[]")
MANIFEST_FILES = frozenset({"Cargo.toml", "build.rs"})


DOC_FENCE_RE = re.compile(r"^\s*//[/!][ \t]*```")


def doc_fences(text):
    """The fence lines of doc-comment code blocks: each block is a doc-test, and
    a guard that runs doc-tests counts it. The rest of a doc comment is not
    shape (R2131), and a fence is the one part of it that is."""
    return [f"doc-test {ln.strip()}" for ln in text.split("\n") if DOC_FENCE_RE.match(ln)]


@functools.lru_cache(maxsize=8192)
def shape_lines(text):
    """The lines of Rust source `text` that decide which tests exist, as a tuple
    (cached: comment stripping is the slow part and one run reads a text from
    several places).

    Comments are stripped first (R2131: a doc comment that SHOWS `#[test]` is
    not one). An attribute is kept whole across its lines, because the feature
    that gates a test sits on the second line of `#[cfg(any(...))]` as often as
    on the first.
    """
    out = doc_fences(text)
    depth = 0
    for raw in rust_comments.strip_comments(text).split("\n"):
        line = raw.strip()
        if not line:
            continue
        if depth > 0 or ATTR_START_RE.match(line):
            out.append(line)
            depth += line.count("[") - line.count("]")
            if depth < 0:
                depth = 0
            continue
        if FN_RE.search(line) or MOD_RE.match(line) or MACRO_DEF_RE.search(line):
            out.append(line)
            continue
        m = MACRO_CALL_RE.match(line)
        if m and m.group(1).split("::")[-1] not in STD_MACROS:
            out.append(line)
    return tuple(out)


# An attribute that can change which tests exist or where they are. Others
# (`derive`, `allow`, `inline`, ...) are noise on a line that is not a shape line
# itself.
TEST_ATTR_WORD_RE = re.compile(r"\b(?:cfg|cfg_attr|test|ignore|path)\b|test\b")
OUTLINE_MOD_RE = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
INLINE_MOD_RE = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{?\s*$")
FN_NAME_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")


@functools.lru_cache(maxsize=8192)
def shape_items(text):
    """`((attrs, head), ...)`: each shape line with the attributes written directly
    above it, so a change can be told apart by WHAT it governs.

    `fn` heads govern one test; `mod name;` governs the file that name resolves
    to; everything else (an inline `mod name {`, a macro, an inner `#![...]`) is
    structure whose reach a diff line cannot say.
    """
    items = [((), f) for f in doc_fences(text)]
    attrs = []
    cur = []
    depth = 0
    for raw in rust_comments.strip_comments(text).split("\n"):
        line = raw.strip()
        if not line:
            continue
        if depth > 0 or ATTR_START_RE.match(line):
            cur.append(line)
            depth += line.count("[") - line.count("]")
            if depth <= 0:
                depth = 0
                joined = " ".join(cur)
                cur = []
                if joined.startswith("#!"):
                    items.append(((), joined))
                else:
                    attrs.append(joined)
            continue
        is_shape = bool(
            FN_RE.search(line)
            or MOD_RE.match(line)
            or MACRO_DEF_RE.search(line)
            or (
                (m := MACRO_CALL_RE.match(line))
                and m.group(1).split("::")[-1] not in STD_MACROS
            )
        )
        if is_shape:
            items.append((tuple(attrs), line))
        elif any(TEST_ATTR_WORD_RE.search(a) for a in attrs):
            items.append((tuple(attrs), line))
        attrs = []
    return tuple(items)


def _counter_diff(a, b):
    """Items of `a` not matched by an item of `b`, as a list (multiset)."""
    left = list(b)
    out = []
    for it in a:
        if it in left:
            left.remove(it)
        else:
            out.append(it)
    return out


def outline_mod_file(rel, attrs, name, exists):
    """Crate-relative path of the file `mod name;` written in `rel` resolves to,
    or None when no candidate `exists`. A `#[path = "..."]` attribute wins."""
    parent, _, stem_ext = rel.rpartition("/")
    stem = stem_ext[: -len(".rs")] if stem_ext.endswith(".rs") else stem_ext
    for a in attrs:
        m = re.search(r'path\s*=\s*"([^"]+)"', a)
        if m:
            cand = f"{parent}/{m.group(1)}" if parent else m.group(1)
            return cand if exists(cand) else None
    # A crate root (`lib.rs`, `main.rs`, and each top-level file of `tests/`,
    # `examples/`, `benches/`, which cargo builds as a crate of its own) keeps
    # its child modules beside it; any other file keeps them in a directory named
    # for itself.
    root_like = stem in ("lib", "main", "mod") or (
        rel.count("/") == 1 and rel.split("/", 1)[0] in ("tests", "examples", "benches")
    )
    base = parent if root_like else f"{parent}/{stem}"
    for cand in (f"{base}/{name}.rs", f"{base}/{name}/mod.rs"):
        if exists(cand):
            return cand
    return None


def filter_haystack(d, rel, read_text, old_text):
    """What a libtest filter must be found in for the change to `rel` to reach
    it: the module path of the file, plus the names the DIFFERENCE between the
    old and new shape governs.

    * a changed `fn` contributes its name and every enclosing-capable inline
      `mod` of the file (a test's path runs through them);
    * a changed `mod name;` contributes the file it resolves to, whole: its
      tests appear or vanish with the declaration (R2158's `#[cfg]` removed
      above a `mod`), though that file's own text did not move;
    * anything else is structure a diff line cannot bound, and contributes the
      file's whole shape.
    """
    new_items = shape_items(read_text(d, rel))
    old_items = shape_items(old_text(d, rel))
    delta = _counter_diff(new_items, old_items) + _counter_diff(old_items, new_items)
    parts = [module_path_prefix(rel)]
    structural = False
    need_inline = False

    def exists(p):
        return bool(read_text(d, p) or old_text(d, p))

    for attrs, head in delta:
        mo = OUTLINE_MOD_RE.match(head)
        if FN_RE.search(head):
            parts.append(head)
            need_inline = True
        elif mo:
            parts.append(head)
            target = outline_mod_file(rel, attrs, mo.group(1), exists)
            if target is None:
                structural = True
            else:
                parts.append(module_path_prefix(target))
                parts.extend(
                    h for _a, h in shape_items(read_text(d, target)) + shape_items(old_text(d, target))
                )
        else:
            structural = True
    if need_inline or structural:
        parts.extend(h for _a, h in new_items + old_items if INLINE_MOD_RE.match(h))
    if structural:
        parts.extend(h for _a, h in new_items + old_items)
    return "\n".join(parts)

# R2650 — a shell variable this file assigns ONE whitespace-free literal, and the
# uses of it that can therefore be resolved.
#
# # Why this exists, and why announcing the gap was not enough
#
# `select` defers any guard whose command the shell assembles, because a command
# this runner cannot reproduce cannot be measured. That is right, and it is also
# a HOLE: `C1y linkstate+access` reads `--features "$access"`, so the gate has
# never been able to check it. The hole was documented at the sibling `C1y
# interceptor` guard in R2631, with a MANUAL remedy -- run the command by hand
# after working out which skipped guards a push's tests could fall under -- and
# R2650 is the second red it cost, which is the point at which a rule that needs
# remembering is the wrong instrument.
#
# Resolution is deliberately narrow. A name assigned two DIFFERENT literals is
# left unresolved, and so is a value carrying whitespace: expanding those would
# make a guard measurable and WRONG, which is worse than deferring it, because a
# deferral is at least visible in the count this gate prints.
LITERAL_ASSIGN_RE = re.compile(
    r"^[ \t]*(?:local[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=\"([^\"$`]*)\"[ \t]*$", re.M
)
VAR_USE_RE = re.compile(
    r"\"\$(?P<quoted>[A-Za-z_][A-Za-z0-9_]*)\"|\$(?P<bare>[A-Za-z_][A-Za-z0-9_]*)"
)


def literal_vars(text):
    """`{name: value}` for each variable this file assigns exactly one literal."""
    seen = {}
    for name, value in LITERAL_ASSIGN_RE.findall(text):
        if any(c.isspace() for c in value):
            seen[name] = None
        elif name in seen and seen[name] != value:
            seen[name] = None
        elif name not in seen:
            seen[name] = value
    return {k: v for k, v in seen.items() if v is not None}


def expand_literal_vars(logical, vars_):
    """`"$access"` -> the literal, leaving every unresolvable use untouched.

    The quotes go with it: they are what made the token unreproducible, and the
    value is whitespace-free by construction, so dropping them cannot change how
    the command tokenizes.
    """

    def sub(m):
        name = m.group("quoted") or m.group("bare")
        return vars_.get(name, m.group(0))

    return VAR_USE_RE.sub(sub, logical)


class Guard:
    """One count guard, as `run-ci.sh` writes it."""

    def __init__(self, lineno, spelling, want, cmd, prelude=()):
        self.lineno = lineno
        self.spelling = spelling
        self.want = want
        self.cmd = cmd
        # Everything the line puts BEFORE `cargo` -- in practice an `env
        # VAR=... VAR=...` prefix. Carried rather than dropped because it is
        # part of what makes the command reproducible, and because dropping it
        # hid a shell expansion from the very check that exists to notice one:
        # R2200's Layer Z guard reads `env WZ_ZENOHD_BIN="$zenohd" ... cargo
        # test ...`, and with the prefix discarded the remaining tokens carry no
        # `$` at all.
        self.prelude = tuple(prelude)
        joined = " ".join(cmd)
        m = cgl.PKG_RE.search(joined)
        self.pkg = m.group(1) if m else None
        m = cgl.TEST_BIN_RE.search(joined)
        self.test_target = m.group(1) if m else None
        start = cmd.index("test") + 1 if "test" in cmd else len(cmd)
        _exact, self.filters, _skip = cgl.libtest_selection(cmd, start)
        # Item 787 -- which targets of the package the command compiles tests
        # for. Empty means cargo's default: the lib, the bins, every integration
        # test and the doc tests.
        self.target_kinds = frozenset(
            kind
            for flag, kind in (
                ("--lib", "lib"), ("--bin", "bin"), ("--bins", "bin"),
                ("--test", "test"), ("--tests", "test"), ("--doc", "doc"),
                ("--example", "example"), ("--examples", "example"),
                ("--bench", "bench"), ("--benches", "bench"),
            )
            if flag in cmd
        )
        # The run-ci.sh lines the guard's logical line spans; set by
        # `parse_guards`, a single line for a guard built from a fixture.
        self.span = (lineno, lineno)
        # Why the shell's assembly of this command could not be resolved, or
        # None. A guard with a reason stays DEFERRED and the reason is printed.
        self.unresolved_reason = None
        # True when `guarded_count_shell` produced this command by running the
        # lane, so `select` does not defer it for its `$`.
        self.resolved_by_shell = False
        # Item 787 -- the command asks libtest for `#[ignore]`d tests, which are
        # the ones that need inputs a developer machine does not have.
        self.lists_ignored = "--ignored" in cmd
        # Set by `select`: why this guard was picked.
        self.reason = ""
        # The words the line spells for the command; `_guard_from` sets the
        # real thing, a fixture-built guard falls back to its command.
        self.words = list(cmd)

    @property
    def where(self):
        return f"run-ci.sh:{self.lineno}"

    def label(self):
        return f"{self.where} [{self.spelling}] {' '.join(self.cmd)}"

    @property
    def needs_inputs(self):
        """The line hands the command machine-provisioned inputs (`env X=...`)."""
        return any(gcs.ENV_ASSIGN_RE.match(t) for t in self.prelude)

    @property
    def list_measurable(self):
        """True when the count can be read by LISTING the tests rather than
        running them: `--ignored` with an explicit target, so the listing is
        the set the run would execute and no doc-test harness is involved."""
        return self.lists_ignored and bool(self.target_kinds - {"doc"})

    @property
    def whole_command(self):
        """Every token the line spells for this guard, prefix included.

        What `SHELL_EXPANSION_RE` must be asked about: a command this runner
        cannot reproduce is unreproducible whichever half the shell assembles.
        """
        return self.prelude + tuple(self.cmd)


def parse_guards(text):
    """Every count guard with a NUMERIC expectation, in both spellings.

    A `+` expectation asserts that something ran, not how much; nothing here can
    contradict it, so it is not in the population. The parser itself is
    `count_guard_lint`'s — one guard table, read one way.
    """
    guards = []
    vars_ = literal_vars(text)
    for lineno, logical in cgl.logical_lines(text):
        if logical.lstrip().startswith("#"):
            continue
        # BEFORE the parse, so every field derived from the command -- package,
        # test target, libtest filters -- is read off the resolved spelling
        # rather than off one the shell would have rewritten.
        logical = expand_literal_vars(logical, vars_)
        m = cgl.HELPER_RE.search(logical)
        if m:
            seg = logical[m.start():]
            g = _guard_from(lineno, "helper", int(m.group(1)), seg)
            if g:
                guards.append(g)
            continue
        for seg in logical.split("&&"):
            if not (cgl.CARGO_TEST_RE.search(seg) and cgl.GUARD_RE.search(seg)):
                continue
            want = int(cgl.GUARD_RE.search(seg).group(1))
            g = _guard_from(lineno, "bare", want, seg)
            if g:
                guards.append(g)
    guards = resolve_shell_assembled(text, guards)
    attach_spans(text, guards)
    attach_demo_builds(text, guards)
    return guards


def attach_spans(text, guards):
    """Record the physical lines each guard's logical line covers, so a range
    that edits ANY of them (the number, a comment folded into the command, the
    label) selects the guard."""
    ends = {}
    lines = text.split("\n")
    for start, _logical in cgl.logical_lines(text):
        end = start
        while end <= len(lines) and lines[end - 1].rstrip().endswith("\\"):
            end += 1
        ends[start] = end
    for g in guards:
        g.span = (g.lineno, ends.get(g.lineno, g.lineno))
    return guards


def _is_assembled(guard):
    return any(cgl.SHELL_EXPANSION_RE.search(t) for t in guard.whole_command)


def resolve_shell_assembled(text, guards):
    """Replace each guard whose command the shell assembles with the commands
    the shell assembles for it, one guard per distinct command.

    A guard the sandbox cannot reproduce faithfully is returned UNCHANGED with
    `unresolved_reason` set; `select` defers it and the gate prints the reason.
    See `guarded_count_shell` for what "faithfully" means.
    """
    assembled = [g for g in guards if _is_assembled(g)]
    if not assembled:
        return guards
    lanes = gcs.lane_calls(text, [g.lineno for g in assembled])
    fns = gcs.functions(text)
    out = []
    for g in guards:
        if g not in assembled:
            out.append(g)
            continue
        lane = gcs.enclosing(fns, g.lineno)
        calls = lanes.get(lane) if lane else None
        if lane is None:
            g.unresolved_reason = "the line sits outside every function, so no lane runs it"
            out.append(g)
            continue
        if calls is None:
            g.unresolved_reason = f"the sandbox could not run `{lane}`"
            out.append(g)
            continue
        kind = "helper" if g.spelling == "helper" else "cargo"
        mine = [c for c in calls if c.line == g.lineno and c.kind == kind]
        if kind == "cargo":
            mine = [c for c in mine if c.args[:1] == ["test"]]
        if not mine:
            g.unresolved_reason = (
                f"`{lane}` never reached this line in the sandbox (a loop over "
                "command output, or a branch on a file or tool a developer "
                "machine lacks)"
            )
            out.append(g)
            continue
        made, why = [], ""
        seen = set()
        for c in mine:
            argv = c.args[2:] if kind == "helper" else ["cargo"] + c.args
            ok, why = gcs.match_call(g.words, argv)
            if not ok:
                continue
            key = tuple(argv)
            if key in seen:
                continue
            seen.add(key)
            want = g.want
            if kind == "helper":
                try:
                    want = int(c.args[1])
                except ValueError:
                    pass
            at = argv.index("cargo")
            # The VALUE of an `env NAME=value` assignment is whatever the sandbox
            # had to put there (a hosted-only binary's path). It is never used,
            # and keeping it would leak the sandbox's temp directory into the
            # report, so only the NAME is carried.
            prelude = tuple(
                w.split("=", 1)[0] + "=<provisioned>" if gcs.ENV_ASSIGN_RE.match(w) else w
                for w in argv[:at]
            )
            inst = Guard(g.lineno, g.spelling, want, argv[at:], prelude)
            inst.resolved_by_shell = True
            made.append(inst)
        if made:
            out.extend(made)
        else:
            g.unresolved_reason = why or "the shell's result did not match the line"
            out.append(g)
    return out


# R2236 — the `wz-ap-demo` build a guard's own lane runs before it.
#
# Cargo uplifts every feature variant of one bin to ONE path (the R311y269
# note in run-ci), so `crates/target/debug/wz-ap-demo` is whatever the LAST
# build left there. A lane provisions its own demo and then runs its guards;
# this gate runs a guard's command ALONE, so it inherits whatever the previous
# pre-push step happened to build -- and a Layer Z guard against a
# default-feature demo does not print a wrong count, it prints
# `test result: FAILED` with six `wz_ap_demo_binary` preconditions panicking.
# The gate then reports UNMEASURED, and the hook fails a push on a gate that
# says, in its own words, that it measured nothing.
#
# MEASURED, R2236: with the Layer Z feature set the guarded command prints
# `test result: ok. 6 passed`; rebuilt at bare `cargo build -p wz-ap-demo` the
# same command prints `test result: FAILED. 0 passed; 6 failed`.
#
# So the build line is DERIVED rather than listed: scan BACKWARD from the
# guard for the nearest `cargo build -p wz-ap-demo ... --features <list>` that
# is still inside the same top-level lane function. A hand-kept table of
# "which guards need a demo" would be the escape hatch this file exists to
# avoid -- it would go stale the round a lane moves its build line, and
# nothing would measure that.
# R2248 — the feature list is OPTIONAL, and requiring it was a hole rather than
# a narrowing. The clause this regex serves is "a lane that builds the demo is a
# lane whose guards depend on machine-local provisioning", and a FEATURELESS
# `cargo build -p wz-ap-demo --quiet` is such a build: Layer Ewire runs exactly
# that, and its guards need `target/zenoh-pico-cli/z_put` besides. With the
# features mandatory those guards read as demo-free, were routed to a build
# host, and came back with no libtest summary at all -- `UNMEASURED`, which is
# this gate refusing to invent a number and is why the hole surfaced instead of
# passing. A guard's routing must follow the DEMO, not the feature list.
# R2845 — `/` is in the class: E6f's second build names `wz/transport-stats`,
# and a truncated `…,wz` would provision a demo cargo refuses to build.
# R2861 — the builds are now read by `feature_closure.cargo_builds`, the one
# reader of run-ci.sh's builds. The per-line regex this used matched a
# `--features \` line with its optional group EMPTY, so a demo built with its
# list on the next line — Layer M's admin build, and 18 others — was routed
# here as a FEATURELESS demo.
FN_OPEN_RE = re.compile(r"^[a-z_][a-z0-9_]*\(\) \{")


def demo_build_lines(text):
    """{0-based line index: "a,b,c"} for each line a `wz-ap-demo` build starts
    on, `""` for a featureless one. The last build wins where one line starts
    two."""
    out = {}
    for offset, pkg, feats in feature_closure.cargo_builds(text):
        if pkg == "wz-ap-demo":
            out[text.count("\n", 0, offset)] = ",".join(feats)
    return out


def attach_demo_builds(text, guards):
    """Give each guard the feature list its own lane builds the demo with.

    `None` when the enclosing lane builds no demo -- that guard's command does
    not depend on one, and running a build for it would be a cost with no
    claim behind it.
    """
    lines = text.splitlines()
    builds = demo_build_lines(text)
    for g in guards:
        features = None
        for i in range(min(g.lineno, len(lines)) - 1, -1, -1):
            line = lines[i]
            if FN_OPEN_RE.match(line):
                break  # left the lane; a build in another one is not this guard's
            if i in builds:
                # `""` (a featureless build) and `None` (no build in this lane)
                # are DIFFERENT answers and the caller branches on which. A
                # falsy-test would fold them and put the featureless case back
                # on the build host.
                features = builds[i]
                break
        g.demo_features = features
    return guards


def _guard_from(lineno, spelling, want, seg):
    toks = cgl.command_tokens(seg)
    if "cargo" not in toks:
        return None
    at = toks.index("cargo")
    cmd = toks[at:]
    if len(cmd) < 2 or cmd[1] != "test":
        return None
    # The tokens before `cargo` are the guard's label and any `env` prefix. Only
    # the run of tokens from `env` onwards is part of the COMMAND; the label is
    # the helper's own argument and its quoting says nothing about whether the
    # command can be reproduced.
    prelude = toks[toks.index("env", 0, at):at] if "env" in toks[:at] else ()
    g = Guard(lineno, spelling, want, cmd, prelude)
    # Every word the line spells for the command the helper RUNS, wrapper and
    # all (`timeout "$BUDGET" env X=... cargo ...`): what the sandbox's recorded
    # argv is compared with. `prelude` keeps only the `env` run, which is all the
    # rest of this file needs of the words before `cargo`.
    m = cgl.HELPER_RE.match(seg) if spelling == "helper" else None
    g.words = cgl.command_tokens(seg[m.end():]) if m else list(cmd)
    return g


def dir_for_package(pkg, manifest_names):
    for d, name in manifest_names.items():
        if name == pkg:
            return d
    return None


def package_manifest_names(crates_root=None):
    root = crates_root or CRATES
    names = {}
    if not root.is_dir():
        return names
    for manifest in sorted(root.glob("*/Cargo.toml")):
        for line in manifest.read_text().split("\n"):
            m = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if m:
                names[manifest.parent.name] = m.group(1)
                break
    return names


def module_path_prefix(rel):
    """The libtest path prefix every test in crate-relative `rel` carries, or "".

    R2631. A libtest filter is matched against a test's MODULE PATH
    (`auth_dispatch::tests::a_test`), and that path comes from the FILE'S PATH,
    not from anything the file says: `src/auth_dispatch.rs` never spells
    `auth_dispatch`. `select` used to search only file TEXT, so a guard whose
    filter is the module path of the very file a push changed was invisible
    unless that text happened to name itself -- R2631 measured `C1y
    auth_dispatch` (declared 6, printed 7) passing this gate unreached.

    The trailing `::` is the boundary, and it is what makes this safe to add: the
    prefix of `src/extauth_pubkey_store.rs` is `extauth_pubkey_store::`, which a
    filter `extauth_pubkey::` does not occur in (R2627's substring lesson).
    `lib.rs` / `main.rs` are the crate root and contribute nothing; `a/mod.rs` is
    module `a`.
    """
    if not (rel.startswith("src/") and rel.endswith(".rs")):
        return ""
    parts = rel[len("src/"):-len(".rs")].split("/")
    if parts[-1] == "mod":
        parts = parts[:-1]
    if parts in ([], ["lib"], ["main"]):
        return ""
    return "::".join(parts) + "::"


# ── reading a Cargo manifest without `tomllib` ───────────────────────────
#
# `tomllib` is stdlib from python 3.11 and the hosted floor is 3.10 (the lint in
# `python_floor_lint.py` refuses the import, after it killed Layer C0 once).
# `cargo metadata` is the sanctioned reader, but it reads the manifest ON DISK,
# and this gate needs the manifest as it was at the range's BASE. So this is a
# reader for the subset a Cargo.toml uses: tables, arrays of tables, dotted
# keys, strings (basic, literal, multi-line), arrays, inline tables, booleans and
# numbers. It refuses what it does not read (a date, a stray token) by returning
# None, and every caller turns a refusal into "this edit cannot be bounded",
# which selects the whole package: the direction a parser failure must err in.


class ManifestSyntax(Exception):
    pass


class _Toml:
    BARE = re.compile(r"[A-Za-z0-9_-]+")
    SCALAR = re.compile(r"[^\s,\]}#]+")
    ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "b": "\b", "f": "\f"}

    def __init__(self, text):
        self.s = text
        self.i = 0

    def err(self, why):
        raise ManifestSyntax(f"{why} at offset {self.i}")

    def peek(self):
        return self.s[self.i : self.i + 1]

    def ws(self, newlines=True):
        s = self.s
        while self.i < len(s):
            c = s[self.i]
            if c in " \t\r" or (newlines and c == "\n"):
                self.i += 1
            elif c == "#":
                while self.i < len(s) and s[self.i] != "\n":
                    self.i += 1
            else:
                break

    def key(self):
        parts = []
        while True:
            self.ws(False)
            if self.peek() in ('"', "'"):
                parts.append(self.string())
            else:
                m = self.BARE.match(self.s, self.i)
                if not m:
                    self.err("expected a key")
                parts.append(m.group(0))
                self.i = m.end()
            self.ws(False)
            if self.peek() == ".":
                self.i += 1
                continue
            return parts

    def string(self):
        s = self.s
        q = s[self.i]
        if s.startswith(q * 3, self.i):
            end = s.find(q * 3, self.i + 3)
            if end < 0:
                self.err("unterminated multi-line string")
            body = s[self.i + 3 : end]
            self.i = end + 3
            return body[1:] if body.startswith("\n") else body
        self.i += 1
        out = []
        while True:
            if self.i >= len(s) or s[self.i] == "\n":
                self.err("unterminated string")
            c = s[self.i]
            if c == q:
                self.i += 1
                return "".join(out)
            if c == "\\" and q == '"':
                esc = s[self.i + 1 : self.i + 2]
                if esc not in self.ESCAPES:
                    self.err("unsupported escape")
                out.append(self.ESCAPES[esc])
                self.i += 2
                continue
            out.append(c)
            self.i += 1

    def value(self):
        self.ws(False)
        c = self.peek()
        if c in ('"', "'"):
            return self.string()
        if c == "[":
            self.i += 1
            arr = []
            while True:
                self.ws()
                if self.peek() == "]":
                    self.i += 1
                    return arr
                arr.append(self.value())
                self.ws()
                if self.peek() == ",":
                    self.i += 1
        if c == "{":
            self.i += 1
            tbl = {}
            while True:
                self.ws()
                if self.peek() == "}":
                    self.i += 1
                    return tbl
                path = self.key()
                self.ws(False)
                if self.peek() != "=":
                    self.err("expected =")
                self.i += 1
                _put(tbl, path, self.value())
                self.ws()
                if self.peek() == ",":
                    self.i += 1
        m = self.SCALAR.match(self.s, self.i)
        if not m:
            self.err("expected a value")
        raw = m.group(0)
        self.i = m.end()
        if raw in ("true", "false"):
            return raw == "true"
        for conv in (int, float):
            try:
                return conv(raw.replace("_", ""))
            except ValueError:
                pass
        self.err(f"unsupported value `{raw}`")


def _put(tbl, path, val):
    for p in path[:-1]:
        nxt = tbl.setdefault(p, {})
        tbl = nxt[-1] if isinstance(nxt, list) else nxt
    tbl[path[-1]] = val


def parse_manifest(text):
    """The manifest as nested dicts and lists, or `None` when this reader does
    not understand it (callers then treat the manifest as opaque)."""
    try:
        p = _Toml(text)
        doc, cur = {}, None
        cur = doc
        while True:
            p.ws()
            if p.i >= len(p.s):
                return doc
            if p.s.startswith("[[", p.i):
                p.i += 2
                path = p.key()
                if not p.s.startswith("]]", p.i):
                    p.err("expected ]]")
                p.i += 2
                parent = doc
                for k in path[:-1]:
                    parent = parent.setdefault(k, {})
                    parent = parent[-1] if isinstance(parent, list) else parent
                cur = {}
                parent.setdefault(path[-1], []).append(cur)
            elif p.peek() == "[":
                p.i += 1
                path = p.key()
                if p.peek() != "]":
                    p.err("expected ]")
                p.i += 1
                cur = doc
                for k in path:
                    cur = cur.setdefault(k, {})
                    cur = cur[-1] if isinstance(cur, list) else cur
            else:
                path = p.key()
                p.ws(False)
                if p.peek() != "=":
                    p.err("expected =")
                p.i += 1
                _put(cur, path, p.value())
    except (ManifestSyntax, IndexError, TypeError, AttributeError):
        return None


# What a manifest edit can move. A guard's test set depends on the features its
# build turns on, so a `Cargo.toml` edit reaches a guard when it changes a feature
# the guard's build activates (directly, through `default`, or through another
# feature's list), and not otherwise. Anything this reader cannot bound -- a
# `[[test]]` / `[lib]` / `[workspace]` table, `autotests`, a dependency that is a
# workspace crate (cargo UNIFIES its feature requests into the package's own
# build: wz-runtime-tokio's test-support dev-dependency turns `transport-unicast`
# on for its tests) -- reaches every guard of the package. A registry
# dependency's own `features` cannot, so they do not.
IRRELEVANT_PACKAGE_KEYS = frozenset(
    "version description license license-file repository homepage documentation "
    "readme authors keywords categories rust-version exclude include publish "
    "metadata".split()
)
OPAQUE_TABLES = ("test", "bin", "lib", "example", "bench", "workspace", "patch")


def _dep_tables(doc):
    for t in DEP_TABLES:
        if isinstance(doc.get(t), dict):
            yield doc[t]
    for tgt in (doc.get("target") or {}).values():
        for t in DEP_TABLES:
            if isinstance(tgt.get(t), dict):
                yield tgt[t]


def manifest_effect(old_text, new_text):
    """The feature names a manifest edit changes the meaning of, or `None` when
    the edit cannot be bounded to features."""
    old, new = parse_manifest(old_text), parse_manifest(new_text)
    if old is None or new is None:
        return None
    if old == new:
        return set()
    for t in OPAQUE_TABLES:
        if old.get(t) != new.get(t):
            return None
    po, pn = old.get("package") or {}, new.get("package") or {}
    for k in set(po) | set(pn):
        if k not in IRRELEVANT_PACKAGE_KEYS and po.get(k) != pn.get(k):
            return None
    fo, fn = old.get("features") or {}, new.get("features") or {}

    def feature_value(v):
        # `dep:name` turns an optional dependency on and nothing else: it never
        # sets a `cfg(feature = ...)`, so a list that differs only in `dep:`
        # entries has the same meaning to every test.
        return [x for x in v if not x.startswith("dep:")] if isinstance(v, list) else v

    changed = {
        k for k in set(fo) | set(fn)
        if feature_value(fo.get(k)) != feature_value(fn.get(k))
    }
    hidden = {
        x[4:]
        for table in (fo, fn)
        for v in table.values()
        if isinstance(v, list)
        for x in v
        if x.startswith("dep:")
    }

    def deps(doc):
        merged = {}
        for table in _dep_tables(doc):
            merged.update(table)
        return merged

    do, dn = deps(old), deps(new)
    for name in set(do) | set(dn):
        a, b = do.get(name), dn.get(name)
        if a == b:
            continue
        for v in (a, b):
            if isinstance(v, dict) and (v.get("path") or v.get("workspace")):
                return None
        # An optional dependency is an implicit feature of its own name, unless
        # some feature list says `dep:name`, which hides it.
        if name not in hidden and any(
            isinstance(v, dict) and v.get("optional") for v in (a, b)
        ):
            changed.add(name)
    # Everything else that moved (`[profile]`, `[lints]`, versions of plain
    # registry dependencies) cannot change which tests exist.
    return changed


def build_features(g, doc_tables):
    """The feature names `g`'s build turns on, closed over the feature tables in
    `doc_tables` (a list of `[features]` dicts, old and new together), or None
    for `--all-features`."""
    cmd = list(g.cmd)
    if "--all-features" in cmd:
        return None
    seen, todo = set(), []
    for i, t in enumerate(cmd):
        vals = []
        if t in ("--features", "-F") and i + 1 < len(cmd):
            vals = [cmd[i + 1]]
        elif t.startswith("--features="):
            vals = [t.split("=", 1)[1]]
        for v in vals:
            for name in re.split(r"[,\s]+", v.strip('"')):
                if not name:
                    continue
                if "/" in name:
                    pkg, _, feat = name.partition("/")
                    if pkg.rstrip("?") != g.pkg:
                        continue
                    name = feat
                todo.append(name)
    if "--no-default-features" not in cmd:
        todo.append("default")
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        for table in doc_tables:
            for implied in table.get(f, []) if isinstance(table.get(f), list) else []:
                if implied.startswith("dep:"):
                    continue
                if "/" in implied:
                    pkg, _, feat = implied.partition("/")
                    if pkg.rstrip("?") == g.pkg:
                        todo.append(feat)
                else:
                    todo.append(implied)
    return seen


def manifest_reaches(g, effect, old_text, new_text):
    """Does the manifest edit with `effect` change anything `g`'s build sees?"""
    if effect is None:
        return True
    if not effect:
        return False
    tables = []
    for text in (old_text, new_text):
        doc = parse_manifest(text)
        if doc is None:
            return True
        tables.append(doc.get("features") or {})
    active = build_features(g, tables)
    return True if active is None else bool(active & effect)


def reach_files(g, rels):
    """The changed `.rs` files of `g`'s package that its command compiles tests
    from, by the targets it names.

    A top-level `tests/X.rs` is its own binary and belongs to `--test X` alone;
    a file in a subdirectory of `tests/` is a helper module any binary may
    declare, so it belongs to every integration-test guard of the package.
    """
    out = []
    kinds = g.target_kinds
    for r in rels:
        if not r.endswith(".rs") or r in MANIFEST_FILES:
            continue
        in_src = r.startswith("src/")
        in_tests = r.startswith("tests/")
        if g.test_target is not None:
            hit = r == f"tests/{g.test_target}.rs" or (in_tests and r.count("/") >= 2)
        elif kinds:
            hit = (
                (in_src and bool(kinds & {"lib", "bin", "doc"}))
                or (in_tests and "test" in kinds)
                or (r.startswith("examples/") and "example" in kinds)
                or (r.startswith("benches/") and "bench" in kinds)
            )
        else:
            hit = in_src or in_tests or r.startswith(("examples/", "benches/"))
        if hit:
            out.append(r)
    return out


IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def filter_may_match(flt, haystack):
    """Necessary condition for a libtest substring filter to select a test whose
    path is built from the identifiers in `haystack`.

    A test's path is `module::path::name` and libtest matches the filter as a
    SUBSTRING of it. A filter such as `reassembly::tests::` therefore spans
    several identifiers that no file spells in one run of text, so it is cut at
    `::` and each piece is held to what a substring can do at that position: the
    first piece ends an identifier, the middle ones ARE identifiers, the last
    begins one, and a filter with no `::` sits inside one. The `::` boundary is
    what keeps `extauth_pubkey::` from being reached by `extauth_pubkey_store`
    (R2627's substring lesson). Adjacency is not required, so this can select a
    guard whose filter does not in the end match and never the reverse, which
    is the direction a cost-driven gate may err in.
    """
    idents = set(IDENT_RE.findall(haystack))
    pieces = flt.split("::")
    if len(pieces) == 1:
        return any(flt in i for i in idents)
    first, last = pieces[0], pieces[-1]
    if first and not any(i.endswith(first) for i in idents):
        return False
    if any(p and p not in idents for p in pieces[1:-1]):
        return False
    return not last or any(i.startswith(last) for i in idents)


def select(
    guards,
    changed_files,
    changed_lines,
    manifest_names,
    read_text,
    old_text=None,
    shape_changed=None,
    run_ci_lines=frozenset(),
):
    """`(selected, skipped)` — which guards this push must RUN, and why not.

    `changed_files`  repo-relative paths the push touched.
    `changed_lines`  {crate dir: [added/removed line bodies]} from `-U0`.
    `read_text`      crate-dir-relative path -> current text (injectable so the
                     selftest never needs a tree on disk).
    `old_text`       the same at the range's base; `None` reads as "".
    `shape_changed`  {crate dir: {rel}} -- the changed files whose `shape_lines`
                     differ between base and head. `None` (the selftest's older
                     arms) falls back to grepping the diff lines.
    `run_ci_lines`   the lines of `run-ci.sh` the range edited; a guard whose own
                     logical line is among them is selected whatever else moved.
    """
    by_dir = {}
    for f in changed_files:
        m = re.match(r"crates/([^/]+)/(.*)$", f)
        if m:
            by_dir.setdefault(m.group(1), []).append(m.group(2))

    triggered = {
        d for d, lines in changed_lines.items() if any(TRIGGER_RE.search(l) for l in lines)
    }
    old_text = old_text or (lambda d, rel: "")
    manifest_memo = {}

    selected, skipped = [], []
    for g in guards:
        if g.pkg is None:
            skipped.append((g, "names no package"))
            continue
        if g.unresolved_reason is not None:
            skipped.append(
                (g, f"the shell assembles part of this command: {g.unresolved_reason}")
            )
            continue
        if not g.resolved_by_shell and _is_assembled(g):
            skipped.append((g, "the shell assembles part of this command"))
            continue
        if run_ci_lines and any(g.span[0] <= n <= g.span[1] for n in run_ci_lines):
            g.reason = "its own line in run-ci.sh changed"
            selected.append(g)
            continue
        d = dir_for_package(g.pkg, manifest_names)
        if d is None or d not in by_dir:
            continue
        rels = by_dir[d]
        manifest = "build.rs" in rels
        if "Cargo.toml" in rels:
            if d not in manifest_memo:
                o, n = old_text(d, "Cargo.toml"), read_text(d, "Cargo.toml")
                manifest_memo[d] = (manifest_effect(o, n), o, n)
            effect, o, n = manifest_memo[d]
            manifest = manifest or manifest_reaches(g, effect, o, n)
        reachable = reach_files(g, rels)
        if shape_changed is None:
            reachable = reachable if d in triggered else []
        else:
            reachable = [r for r in reachable if r in shape_changed.get(d, ())]
        if not reachable and not manifest:
            continue
        # A manifest edit can move a count with no source line anywhere (a
        # feature table, a default feature, an optional dependency), and nothing
        # in a file's text says which guard of the package it reaches, so no
        # filter narrows it.
        if g.filters and not manifest:
            # A test's path is its file's module path, the `mod` names inside
            # it and its `fn` name, and every one of those is a SHAPE line. The
            # filter is therefore looked for in the shape of the file (new and
            # old) and not in its whole text: a 4000-line `lib.rs` spells
            # nearly every word, and searching it selected the guard for any
            # filter at all.
            if shape_changed is None:
                haystack = "\n".join(
                    "\n".join(shape_lines(read_text(d, r)) + shape_lines(old_text(d, r)))
                    for r in reachable
                )
            else:
                haystack = "\n".join(
                    filter_haystack(d, r, read_text, old_text) for r in reachable
                )
            haystack += "\n" + "\n".join(changed_lines.get(d, []))
            # R2631 — and the module path each reachable file GIVES its tests,
            # which no file text contains. See `module_path_prefix`.
            haystack += "\n" + "\n".join(module_path_prefix(r) for r in reachable)
            if not any(filter_may_match(f, haystack) for f in g.filters):
                continue
        g.reason = "its package's manifest changed" if manifest else (
            "the test set of " + ", ".join(sorted(reachable)[:3]) + " changed"
        )
        selected.append(g)
    return selected, skipped


def verdict(want, rc, output, listing=False):
    """`(status, counts_seen)` — and THREE statuses, not two.

    `_runci_guarded_test` greps the whole captured output, so ANY summary line
    matching satisfies it. Reading only the last one would make this gate and
    the lane disagree about the same run, which is worse than either verdict.

    The third status is the one this file was WRONG about until it was probed.
    The first draft folded "no libtest summary at all" into "the count moved",
    and every guard then reported `declares 37 passed, the run printed no
    summary line` — a sentence that reads as a measurement of a number when in
    fact NOTHING was measured. That is R2164's class exactly: a gate covering
    two kinds of failure with one verdict pronounces on a subject it never
    reached. `UNMEASURED` is a broken instrument and says so; `MOVED` is the
    count claim and is the only one that means edit the constant.

    ⛔⛔ R2661 — THE `rc` CHECK COMES FIRST, and until this round it did not,
    which left `FAILED` nearly unreachable and sent its cases to `UNMEASURED`.
    `SUMMARY_RE` matches `test result: ok.` alone, so a guard whose test binary
    goes RED prints `test result: FAILED. 38 passed; 1 failed`, parses to no
    counts, and was reported as "NO libtest summary — this gate measured
    nothing". That sentence is false about that run, and it is DIRECTIONAL: it
    sends the reader after a feature set that does not compile, which is a
    different repair in a different file. `FAILED` used to fire only when some
    OTHER binary in the same run happened to print an `ok` line, so the common
    shape reported the rare cause. Ordering by what is KNOWN fixes it — a
    non-zero exit is a fact about the run whether or not a count was readable,
    and only `rc == 0` with no summary means the output never carried one,
    which is the `$BX` log-routing hole its own arm below pins. This is the
    same class the paragraph above is proud of having closed once: two kinds of
    failure under one verdict.
    """
    counts = [
        int(m.group(1))
        for m in (LIST_SUMMARY_RE if listing else SUMMARY_RE).finditer(output)
    ]
    if rc != 0:
        return "FAILED", counts
    if not counts:
        return "UNMEASURED", counts
    return ("OK" if want in counts else "MOVED"), counts


def list_argv(cmd):
    """The command that LISTS the tests `cmd` would run, for a `--ignored` guard.

    The ignored tests of this tree exist to run against inputs a developer
    machine lacks (a `zenohd` binary, a pico CLI, a vendored example build), so
    running them here answers about the machine and not about the count. What
    the guard asserts, though, is how many tests `--ignored` SELECTS, and libtest
    prints exactly that with `--list --ignored`: one `N tests, M benchmarks`
    line per test binary, the same granularity the lane's own grep reads.

    Arguments that only shape a RUN are dropped (`--quiet`, `--nocapture`,
    `--test-threads`); the selection ones (`--ignored`, `--exact`, filters, `--`)
    stay, in order.
    """
    head, tail = list(cmd), []
    if "--" in cmd:
        at = cmd.index("--")
        head, tail = list(cmd[:at]), list(cmd[at + 1 :])
    head = [t for t in head if t not in ("--quiet", "-q")]
    kept, skip_next = [], False
    for t in tail:
        if skip_next:
            skip_next = False
            continue
        if t in ("--quiet", "-q", "--nocapture", "--show-output"):
            continue
        if t == "--test-threads":
            skip_next = True
            continue
        if t.startswith("--test-threads="):
            continue
        kept.append(t)
    return head + ["--"] + kept + ["--list"]


# Item 759 -- the two ways `bx` declines to run a tree it cannot ship faithfully.
# Both are statements about the WORKSPACE (someone left a file in it), not about
# the count a guard declares, and reading either as "measured nothing" sent the
# author after their own build.
BX_ENVIRONMENT_RE = re.compile(
    r"(neither tracked nor ignored|the remote working tree differs from this one)"
)


def bx_environment_problem(output):
    """The lines of a `bx` log that name a polluted tree, or "" when there are none."""
    if not BX_ENVIRONMENT_RE.search(output):
        return ""
    keep = []
    for ln in output.split("\n"):
        if BX_ENVIRONMENT_RE.search(ln) or ln.startswith("bx:   ") or ln.startswith("  "):
            keep.append(ln.strip())
    return "\n".join(k for k in keep if k)[:1500]


def run_guard(g, verbose):
    """Run one guard and read its libtest summary out of the run's OWN output.

    ⚠ `$BX` NEEDS THE LOG, NOT THE PIPE. The wrapper prints a banner and puts
    the wrapped command's output in a file, so capturing its stdout yields a
    run with no summary line in it — which is how the probe above found the
    `UNMEASURED` hole. The banner names the file; this reads it. When it names
    none, that is an INPUT error and the caller is told so, rather than a
    number being invented for it.
    """
    listing = g.list_measurable
    cmd = list_argv(g.cmd) if listing else list(g.cmd)
    bx = os.environ.get("BX", "")
    routed = bool(bx) and os.access(bx, os.X_OK)
    # R2236 — provision the demo the guard's own lane provisions, FIRST. See
    # `attach_demo_builds`: without this the command runs against whatever the
    # previous pre-push step left at the one uplifted bin path, and a Layer Z
    # guard then fails its preconditions instead of reporting a count.
    #
    # Item 787: a guard measured by LISTING its tests never starts the demo, so
    # it needs no demo build and has nothing machine-local to depend on.
    features = None if listing else getattr(g, "demo_features", None)
    if features is not None:
        # ...and run it HERE, never through `$BX`. A lane that builds a demo is
        # a lane whose guards depend on machine-local provisioning -- the demo
        # at the one uplifted bin path, plus `target/zenohd/zenohd` and
        # `target/zenoh-pico-cli/*`, none of which a remote builder has.
        # MEASURED, R2236: routed to a build host the same command reported
        # `z_sub binary missing at /home/<other-host>/.../target/zenoh-pico-cli/z_sub`
        # and `--peer requires the routing-peer feature`, i.e. it was answering
        # about a machine that was never provisioned. "Has a demo build" is the
        # DERIVED test for that dependence; a hand-kept list of oracle-needing
        # guards would go stale the round a lane moves.
        routed = False
        build = ["cargo", "build", "-p", "wz-ap-demo", "--quiet"]
        if features:
            build[4:4] = ["--features", features]
        if verbose:
            print(f"  provisioning {' '.join(build)}")
        pre = subprocess.run(
            build, cwd=str(REPO_ROOT / "crates"), capture_output=True, text=True
        )
        if pre.returncode != 0:
            # Say WHICH half failed. A build error here is not a count claim,
            # and folding it into the run's verdict would blame the guard.
            if verbose:
                print(f"  demo build failed for {g.where}:\n{pre.stdout}{pre.stderr}")
            return "UNMEASURED", [], ""
    if routed:
        cmd = [bx, "--label", f"guard-count-{g.lineno}", "--"] + cmd
    if verbose:
        print(f"  running {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, cwd=str(REPO_ROOT / "crates"), capture_output=True, text=True
    )
    output = proc.stdout + proc.stderr
    if routed:
        m = re.search(r"full log: (\S+)", output)
        if not m:
            return "UNMEASURED", [], ""
        try:
            output += "\n" + Path(m.group(1)).read_text()
        except OSError:
            return "UNMEASURED", [], ""
        problem = bx_environment_problem(output)
        if problem and proc.returncode != 0:
            return "ENVIRONMENT", [], problem
    status, counts = verdict(g.want, proc.returncode, output, listing)
    return status, counts, ""


def run_batch(guards, verbose):
    """Measure routable guards through ONE `bx` call. `{id(guard): (status,
    counts, note)}`.

    MEASURED on this tree, warm: 4 guards cost 146 s as four `bx` calls, ~36 s
    each, of which ~19 s was the remote build-and-run and the rest the per-call
    overhead (the ssh round trips, the tree-equality proof, the log). The calls
    are independent commands in the same working directory, so they go through
    one shell on the builder, each between a BEGIN and an RC marker that the
    log carries back, and each is judged by the same `verdict` a lone run is.
    """
    bx = os.environ.get("BX", "")
    cwd = str(REPO_ROOT / "crates")
    script = []
    cmds = []
    # The log also carries the command line bx was given, so a marker that
    # could be read out of THAT would be read as output. A per-run tag makes the
    # markers this run's own.
    tag = f"{os.getpid()}-{time.time_ns()}"
    for i, g in enumerate(guards):
        argv = list_argv(g.cmd) if g.list_measurable else list(g.cmd)
        cmds.append(argv)
        script.append(f'echo "@@GUARD-{tag}-BEGIN {i}"')
        script.append(" ".join(shlex.quote(t) for t in argv))
        script.append(f'echo "@@GUARD-{tag}-RC {i} $?"')
    if verbose:
        for argv in cmds:
            print(f"  batching {' '.join(argv)}")
    proc = subprocess.run(
        [bx, "--label", "guard-count-batch", "--", "bash", "-c", "\n".join(script)],
        cwd=cwd, capture_output=True, text=True,
    )
    output = proc.stdout + proc.stderr
    m = re.search(r"full log: (\S+)", output)
    if m:
        try:
            output += "\n" + Path(m.group(1)).read_text()
        except OSError:
            m = None
    return read_batch(tag, guards, output, logged=bool(m))


def read_batch(tag, guards, output, logged=True):
    """Judge each guard of a batch from the text `bx` produced."""
    unmeasured = {id(g): ("UNMEASURED", [], "") for g in guards}
    problem = bx_environment_problem(output)
    if problem and f"@@GUARD-{tag}-BEGIN 0\n" not in output:
        return {id(g): ("ENVIRONMENT", [], problem) for g in guards}
    if not logged:
        return unmeasured
    results = {}
    for i, g in enumerate(guards):
        seg = re.search(
            rf"@@GUARD-{tag}-BEGIN {i}\n(.*?)@@GUARD-{tag}-RC {i} (\d+)", output, re.S
        )
        if not seg:
            results[id(g)] = ("UNMEASURED", [], "")
            continue
        status, counts = verdict(
            g.want, int(seg.group(2)), seg.group(1), g.list_measurable
        )
        results[id(g)] = (status, counts, "")
    return results


def changed_from_git(rng):
    files = subprocess.run(
        # --no-renames: a moved test file is a deletion AND an addition. With
        # rename detection only the new path is named, and the tests that left
        # the old one are never looked at.
        ["git", "diff", "--no-renames", "--name-only", rng, "--", "crates/"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, check=True,
    ).stdout.split("\n")
    files = [f for f in files if f]
    raw = subprocess.run(
        ["git", "diff", "--no-renames", "-U0", rng, "--", "crates/"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, check=True,
    ).stdout
    lines = {}
    cur = None
    for ln in raw.split("\n"):
        # The `---` side names the crate of a deleted file, whose `+++` side is
        # /dev/null; reading only `+++` attributed its removed lines to the
        # crate of the file before it.
        m = re.match(r"^(?:\+\+\+ b|--- a)/crates/([^/]+)/", ln)
        if m:
            cur = m.group(1)
            continue
        if ln.startswith("--- ") or ln.startswith("+++ "):
            continue
        if cur and (ln.startswith("+") or ln.startswith("-")):
            lines.setdefault(cur, []).append(ln[1:])
    return files, lines


def _read_worktree(d, rel):
    p = CRATES / d / rel
    try:
        return p.read_text()
    except (OSError, UnicodeDecodeError):
        return ""


def range_base(rng):
    """The revision the range's left side names, as the tree `git diff` compares
    against (`A..B` -> A; `A...B` -> the merge base; an empty side is HEAD)."""
    if "..." in rng:
        a, b = rng.split("...", 1)
        out = subprocess.run(
            ["git", "merge-base", a or "HEAD", b or "HEAD"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()
    if ".." in rng:
        return rng.split("..", 1)[0] or "HEAD"
    raise SystemExit(f"guarded-count gate: `{rng}` is not a base..head range")


def blobs_at(rev, paths):
    """`{path: text}` for the paths that exist at `rev`, in ONE git process."""
    if not paths:
        return {}
    spec = "".join(f"{rev}:{p}\n" for p in paths).encode()
    raw = subprocess.run(
        ["git", "cat-file", "--batch"], input=spec, cwd=str(REPO_ROOT),
        capture_output=True, check=True,
    ).stdout
    out, at = {}, 0
    for p in paths:
        nl = raw.index(b"\n", at)
        header = raw[at:nl].decode("utf-8", "replace")
        at = nl + 1
        if header.endswith(" missing"):
            continue
        size = int(header.split()[2])
        out[p] = raw[at : at + size].decode("utf-8", "replace")
        at += size + 1
    return out


def run_ci_changed_lines(rng):
    """The lines of `scripts/run-ci.sh` the range adds or rewrites, new side."""
    raw = subprocess.run(
        ["git", "diff", "-U0", rng, "--", "scripts/run-ci.sh"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, check=True,
    ).stdout
    lines = set()
    for m in re.finditer(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", raw, re.M):
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) is not None else 1
        lines.update(range(start, start + count))
    return lines


class Changes:
    """What a range did, in the terms `select` asks."""

    def __init__(self, files, lines, shape_changed, old, run_ci_lines):
        self.files = files
        self.lines = lines
        self.shape_changed = shape_changed
        self.old = old
        self.run_ci_lines = run_ci_lines

    def old_text(self, d, rel):
        return self.old.get(f"crates/{d}/{rel}", "")


def changes_from_git(rng):
    files, lines = changed_from_git(rng)
    base = range_base(rng)
    sources = []
    for f in files:
        m = re.match(r"crates/([^/]+)/(.*)$", f)
        if m and (m.group(2).endswith(".rs") or m.group(2) in MANIFEST_FILES):
            sources.append((f, m.group(1), m.group(2)))
    old = blobs_at(base, [f for f, _d, _r in sources])
    shape_changed = {}
    for f, d, rel in sources:
        if rel in MANIFEST_FILES:
            hit = True
        else:
            hit = shape_lines(old.get(f, "")) != shape_lines(_read_worktree(d, rel))
        if hit:
            shape_changed.setdefault(d, set()).add(rel)
    return Changes(files, lines, shape_changed, old, run_ci_changed_lines(rng))


# ── the measurement cache ────────────────────────────────────────────────
#
# A guard's count is a function of its command and of the package's test set. The
# first is the key; the second is summarised by a DIGEST of the package's shape:
# its manifest and `build.rs`, and the `shape_lines` of every source file, for
# the package and for every workspace crate it depends on (a dependency's
# manifest can switch a feature of the package on, and a macro it exports can
# generate tests). Body edits change none of that, so they re-ask nothing.
#
# The digest is deliberately a function of the WORKTREE and not of the range: it
# is the tree a measurement is taken on, and two worktrees of one clone that hold
# the same text share their answers.

DIGEST_VERSION = "1"
CACHE_LIMIT = 4000
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _manifest_deps(manifest_path):
    """Names a Cargo manifest depends on, across every dependency table and the
    target-specific ones. A rename (`package = "..."`) contributes both names.
    `None` when the manifest cannot be read, which the caller takes as "every
    workspace crate"."""
    try:
        doc = parse_manifest(manifest_path.read_text())
    except (OSError, UnicodeDecodeError):
        return None
    if doc is None:
        return None
    names = set()

    def take(table):
        for key, val in (table or {}).items():
            names.add(key)
            if isinstance(val, dict) and "package" in val:
                names.add(val["package"])

    for t in DEP_TABLES:
        take(doc.get(t))
    for tgt in (doc.get("target") or {}).values():
        for t in DEP_TABLES:
            take(tgt.get(t))
    return names


def crate_closure(d, manifest_names, root=None):
    """`d` and the crate dirs of every workspace crate it depends on, sorted."""
    root = root or CRATES
    by_name = {name: dd for dd, name in manifest_names.items()}
    seen, todo = set(), [d]
    while todo:
        cur = todo.pop()
        if cur in seen:
            continue
        seen.add(cur)
        deps = _manifest_deps(root / cur / "Cargo.toml")
        for name in by_name if deps is None else deps:
            dep = by_name.get(name)
            if dep and dep not in seen:
                todo.append(dep)
    return sorted(seen)


_SHAPE_MEMO = {}


def crate_shape_digest(d, root=None):
    """sha256 over one crate's manifest, `build.rs` and source shapes."""
    root = root or CRATES
    key = (str(root), d)
    if key in _SHAPE_MEMO:
        return _SHAPE_MEMO[key]
    h = hashlib.sha256()
    base = root / d
    for name in sorted(MANIFEST_FILES):
        try:
            h.update(f"{name}\0".encode() + (base / name).read_bytes() + b"\0")
        except OSError:
            h.update(f"{name}\0-\0".encode())
    for sub in ("src", "tests", "benches", "examples"):
        for p in sorted((base / sub).rglob("*.rs")) if (base / sub).is_dir() else []:
            h.update(f"{p.relative_to(base)}\0".encode())
            h.update(file_shape_hash(p).encode())
            h.update(b"\0")
    _SHAPE_MEMO[key] = h.hexdigest()
    return _SHAPE_MEMO[key]


# Reading ~700 sources and stripping their comments costs seconds; a file whose
# size and mtime are what they were when its shape was last hashed has the same
# shape. The table lives in the measurement cache file and is only ever a
# shortcut: a miss recomputes, and a wrong entry needs a file edited without its
# size or nanosecond mtime moving.
FILE_SHAPES = {}
FILE_SHAPES_DIRTY = [False]
FILE_SHAPES_LIMIT = 60000


def file_shape_hash(p):
    try:
        st = p.stat()
    except OSError:
        return "-"
    key = str(p)
    hit = FILE_SHAPES.get(key)
    if hit and hit[0] == st.st_mtime_ns and hit[1] == st.st_size:
        return hit[2]
    try:
        text = p.read_text()
    except (OSError, UnicodeDecodeError):
        text = ""
    digest = hashlib.sha256("\n".join(shape_lines(text)).encode()).hexdigest()
    FILE_SHAPES[key] = [st.st_mtime_ns, st.st_size, digest]
    FILE_SHAPES_DIRTY[0] = True
    return digest


def package_digest(g, manifest_names, root=None):
    """The digest a measurement of `g` is cached under, or None when its package
    is not a workspace crate this tree can read."""
    d = dir_for_package(g.pkg, manifest_names) if g.pkg else None
    if d is None:
        return None
    root = root or CRATES
    h = hashlib.sha256(DIGEST_VERSION.encode())
    try:
        h.update((root / "Cargo.toml").read_bytes())
    except OSError:
        pass
    for dep in crate_closure(d, manifest_names, root):
        h.update(dep.encode() + b"\0" + crate_shape_digest(dep, root).encode())
    return h.hexdigest()


def cache_key(g, digest):
    """Names the command (and the NAMES of its env inputs, never their values),
    the way it is measured, and the package shape."""
    env_names = sorted(t.split("=", 1)[0] for t in g.prelude if gcs.ENV_ASSIGN_RE.match(t))
    mode = "list" if g.list_measurable else "run"
    return hashlib.sha256(
        json.dumps([mode, env_names, list(g.cmd), digest]).encode()
    ).hexdigest()


def default_cache_path():
    env = os.environ.get("WZ_GUARDED_COUNT_CACHE")
    if env:
        return Path(env)
    try:
        common = subprocess.run(
            ["git", "rev-parse", "--git-common-dir"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    p = Path(common)
    if not p.is_absolute():
        p = REPO_ROOT / p
    return p / "wz-guarded-count-cache.json"


class Cache:
    """`key -> counts` for measurements that ran to a summary. A failed or
    unmeasured run is never stored: absence is the only honest record of one."""

    def __init__(self, path):
        self.path = path
        self.entries = {}
        self.dirty = False
        if path is not None:
            try:
                data = json.loads(path.read_text())
                if isinstance(data, dict) and data.get("version") == DIGEST_VERSION:
                    self.entries = dict(data.get("entries", {}))
                    FILE_SHAPES.update(data.get("files", {}))
            except (OSError, ValueError):
                pass

    def get(self, key):
        return self.entries.get(key)

    def put(self, key, counts):
        self.entries.pop(key, None)
        self.entries[key] = counts
        self.dirty = True

    def save(self):
        if self.path is None or not (self.dirty or FILE_SHAPES_DIRTY[0]):
            return
        while len(self.entries) > CACHE_LIMIT:
            self.entries.pop(next(iter(self.entries)))
        while len(FILE_SHAPES) > FILE_SHAPES_LIMIT:
            FILE_SHAPES.pop(next(iter(FILE_SHAPES)))
        tmp = self.path.with_name(self.path.name + f".{os.getpid()}.tmp")
        try:
            tmp.write_text(
                json.dumps(
                    {
                        "version": DIGEST_VERSION,
                        "entries": self.entries,
                        "files": FILE_SHAPES,
                    }
                )
            )
            os.replace(tmp, self.path)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass


def cached_verdict(want, counts):
    return ("OK" if want in counts else "MOVED"), counts


# ── one measurement at a time per worktree (item 752) ────────────────────────
#
# Two measurements in one worktree contend for cargo's build-directory lock, and
# the register records the outcome: both wait, nobody computes, and the pusher
# reads it as a slow push. A refusal is cheaper than a wait that can become a
# deadlock, so the second caller is turned away at once and told who has it.


class Busy(Exception):
    pass


class MeasurementLock:
    def __init__(self, path):
        self.path = path
        self.fh = None

    def __enter__(self):
        import fcntl

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a+")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.fh.seek(0)
            holder = self.fh.read().strip() or "an unnamed run"
            self.fh.close()
            raise Busy(holder)
        self.fh.seek(0)
        self.fh.truncate()
        self.fh.write(f"pid {os.getpid()}, started {time.strftime('%H:%M:%S')}")
        self.fh.flush()
        return self

    def __exit__(self, *exc):
        if self.fh is not None:
            self.fh.close()


def lock_path():
    try:
        gd = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return Path(os.environ.get("TMPDIR", "/tmp")) / "wz-guarded-count.lock"
    p = Path(gd)
    if not p.is_absolute():
        p = REPO_ROOT / p
    return p / "wz-guarded-count.lock"


EXIT_OK = 0
EXIT_DISAGREE = 1
EXIT_CANNOT_JUDGE = 2
EXIT_UNMEASURED = 3
EXIT_BUSY = 4

CACHED_ONLY_PREFIX = "guarded-count gate: cached-only:"


def cached_only_line(reached, equal, disagree, unmeasured):
    """The one line `--cached-only` ends on, for a caller that must not parse
    the per-guard lines."""
    return (
        f"{CACHED_ONLY_PREFIX} {reached} reached, {equal} equal to the declared "
        f"number, {disagree} disagree, {unmeasured} not measured for this tree"
    )


def final_exit_code(moved, broken, environment, unmeasured):
    """The exit code of a run that judged what it could. Precedence is the
    point: "could not judge" outranks everything (a number read from a broken
    run proves nothing), a count known to be wrong is reported as wrong even
    when other guards were not measured, and only then does "unmeasured"
    outrank "judged equal"."""
    if environment or broken:
        return EXIT_CANNOT_JUDGE
    if moved:
        return EXIT_DISAGREE
    if unmeasured:
        return EXIT_UNMEASURED
    return EXIT_OK


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--range", dest="rng")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    # Which `run-ci.sh` to read the declared numbers from. The worktree's is the
    # only answer a HOOK ever wants — the push is what it is gating. This exists
    # so the gate can be aimed at a PAST state and shown to fail there, which is
    # how R2167 established that it would have caught R2166 rather than
    # asserting it. A gate whose enforcement was never measured is a claim.
    ap.add_argument("--run-ci", dest="runci", default=None)
    # R2709b — SELECT AND STOP, running nothing.
    #
    # R2709 moved this gate off the hook's default path because running its
    # selection costs a cargo build per guard (measured: 74 guards, ~25 minutes
    # on R2708's push). The deferral message that replaced it said the same
    # sentence whatever the push contained, so a round that had actually moved a
    # count read the identical line as one that could not have -- which is the
    # "a skip that cannot be told from a pass" shape this workspace files
    # against its own instruments.
    #
    # This mode answers only the cheap half of the question: HOW MANY guards
    # this push reaches. It is the same `select` the full run uses, deliberately
    # -- a second copy of that rule in the hook would drift from this one the
    # day either moved, which is this gate's own subject one level up.
    ap.add_argument("--count-only", action="store_true")
    # Item 787 -- answer from the measurement cache and NEVER build. A guard the
    # push reaches whose package shape the cache has seen is judged against the
    # count it recorded; one it has not seen is reported as not measured, exit 3.
    # This is the mode a hook can afford: it costs a digest, not a build.
    ap.add_argument("--cached-only", action="store_true")
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--cache-file", default=None)
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.rng:
        print("usage: guarded_count_gate.py --range <base>..<head>", file=sys.stderr)
        return 2

    runci = Path(args.runci) if args.runci else RUNCI
    guards = parse_guards(runci.read_text())
    if not guards:
        print(
            "guarded-count gate FAIL: parsed ZERO count guards out of "
            f"{RUNCI.relative_to(REPO_ROOT)}. Either the guard population "
            "changed shape or the parser did — both make a green run "
            "meaningless.",
            file=sys.stderr,
        )
        return EXIT_CANNOT_JUDGE

    changes = changes_from_git(args.rng)
    manifest_names = package_manifest_names()
    selected, skipped = select(
        guards,
        changes.files,
        changes.lines,
        manifest_names,
        _read_worktree,
        old_text=changes.old_text,
        shape_changed=changes.shape_changed,
        run_ci_lines=changes.run_ci_lines,
    )

    # Which of the reached guards the cache already answers. A digest per
    # package, computed once.
    cache = Cache(None if args.no_cache else (Path(args.cache_file) if args.cache_file else default_cache_path()))
    digests = {}
    keys = {}
    for g in selected:
        if g.pkg not in digests:
            digests[g.pkg] = package_digest(g, manifest_names)
        if digests[g.pkg] is not None:
            keys[id(g)] = cache_key(g, digests[g.pkg])
    hits = {id(g): cache.get(keys[id(g)]) for g in selected if id(g) in keys}
    hits = {k: v for k, v in hits.items() if v is not None}
    cache.save()  # the file-shape table, if this run had to rebuild part of it

    if args.count_only:
        # ONE LINE, and it says which of the two things happened rather than
        # leaving a reader to infer it from a number. Exit 0 either way: this
        # mode reports, it does not judge -- the judging is the full run's, and
        # hosted CI's.
        if selected:
            cold = len(selected) - len(hits)
            print(
                f"guarded-count gate: this push reaches {len(selected)} count "
                f"guard(s) of {len(guards)}; {len(hits)} already measured on this "
                f"exact package shape (cache), {cold} NOT measured here. A count "
                "this push moved will red the hosted lane that owns it; run "
                "`python3 scripts/lib/guarded_count_gate.py --range "
                f"{args.rng}` to see it now instead."
            )
        else:
            print(
                f"guarded-count gate: this push reaches 0 of {len(guards)} count "
                "guard(s) — its diff cannot move one, so there is nothing to run."
            )
        return 0

    print(
        f"guarded-count gate: {len(guards)} numeric count guard(s) in "
        f"run-ci.sh; {len(selected)} reached by this push"
    )
    # R2650 — the DEFERRALS print with the measurement, every time, not behind
    # `--verbose`. A gate that reports what it measured and stays quiet about
    # what it could not is read as complete, and this one was: the guard whose
    # features the shell assembles has never been checked here, and its move
    # reached origin twice before a hosted lane said so. Printing them is what
    # turns "89 reached" from a result into a result WITH a boundary.
    #
    # Item 787: what stays deferred now is the residue after the lane has been
    # RUN in a sandbox (`guarded_count_shell`), and each line says why that run
    # could not stand in for the hosted one.
    shell_deferred = [g for g, why in skipped if "shell assembles" in why]
    if shell_deferred:
        print(
            f"guarded-count gate: {len(shell_deferred)} guard(s) DEFERRED — the "
            "shell assembles part of their command and the sandbox could not "
            "reproduce it, so ONLY the hosted lane that owns them measures "
            "these. A green above does not cover them:"
        )
        for g, why in skipped:
            if "shell assembles" in why:
                print(
                    f"  DEFERRED  {g.where}: {' '.join(g.whole_command)}\n"
                    f"            why: {g.unresolved_reason or why}"
                )
    if args.verbose and skipped:
        for g, why in skipped:
            print(f"  unrunnable {g.where}: {why}")
    if not selected:
        print("  no guard's test set is moved by this push; nothing to run.")
        if args.cached_only:
            print(cached_only_line(0, 0, 0, 0))
        return EXIT_OK
    if args.verbose:
        for g in selected:
            print(f"  reached  {g.where}: {g.reason}")

    started = time.time()
    results = {}
    for g in selected:
        if id(g) in hits:
            status, counts = cached_verdict(g.want, hits[id(g)])
            results[id(g)] = (status, counts, "", True)
    todo = [g for g in selected if id(g) not in results]
    if args.cached_only:
        if todo:
            print(
                f"guarded-count gate: {len(todo)} reached guard(s) have no "
                "measurement for this package shape in the cache and were NOT "
                "run (--cached-only):"
            )
            for g in todo:
                print(f"  UNMEASURED  {g.where}: {' '.join(g.cmd)}")
    elif todo:
        try:
            with MeasurementLock(lock_path()):
                results.update(measure(todo, args.verbose))
        except Busy as who:
            print(
                "guarded-count gate: another measurement is already running in "
                f"this worktree ({who}). Two of them contend for cargo's build "
                "lock and neither finishes, so this one stops; run it again when "
                "the other has ended.",
                file=sys.stderr,
            )
            return EXIT_BUSY
        for g in todo:
            status, counts, _note, _from_cache = results[id(g)]
            if status in ("OK", "MOVED") and id(g) in keys:
                cache.put(keys[id(g)], counts)
        cache.save()

    moved, broken, environment = [], [], []
    # Only a --cached-only run leaves guards unjudged: a full run measured them.
    unmeasured = todo if args.cached_only else []
    for g in selected:
        if id(g) not in results:
            continue
        status, counts, note, from_cache = results[id(g)]
        seen = ", ".join(str(c) for c in counts)
        if status == "OK":
            print(f"  OK  {g.where}: {g.want} passed" + ("  (cached)" if from_cache else ""))
        elif status == "ENVIRONMENT":
            environment.append((g.where, note))
        elif status == "MOVED":
            moved.append(
                f"{g.where}: declares {g.want} passed, the run printed {seen}\n"
                f"      {' '.join(g.cmd)}"
            )
        elif status == "FAILED":
            # R2661 — say WHICH non-zero this was. A guard whose tests went red
            # reads no `ok` summary, so `seen` is empty, and the reader must be
            # sent to the failure rather than to a missing summary.
            saw = f"it printed {seen}" if counts else "it printed no passing summary"
            broken.append(
                f"{g.where}: the command exited non-zero ({saw}) — re-run it and "
                f"read the failure; a RED test lands HERE, not in the "
                f"no-summary case\n"
                f"      {' '.join(g.cmd)}"
            )
        else:
            broken.append(
                f"{g.where}: NO libtest summary in the run's output — this gate "
                f"measured nothing, so it is not saying the count is wrong\n"
                f"      {' '.join(g.cmd)}"
            )

    n_cached = sum(1 for r in results.values() if r[3])
    print(
        f"guarded-count gate: {len(results)} of {len(selected)} reached guard(s) "
        f"judged ({n_cached} from the cache, {len(results) - n_cached} measured) "
        f"in {time.time() - started:.0f}s"
    )
    if args.cached_only:
        print(
            cached_only_line(
                len(selected),
                sum(1 for r in results.values() if r[0] == "OK"),
                len(moved),
                len(todo),
            )
        )
    if environment:
        # Item 759 -- the tree bx was handed is not one it can ship. That is a
        # fact about the WORKSPACE (a file somebody left in it), so it is named
        # as such, apart from "your build is broken", and it comes first: until
        # it is cleared nothing below it was measured.
        print("", file=sys.stderr)
        print("guarded-count gate ENVIRONMENT ERROR:", file=sys.stderr)
        by_note = {}
        for where, note in environment:
            by_note.setdefault(note, []).append(where)
        for note, wheres in by_note.items():
            print(
                f"  - bx declined to run this tree for {len(wheres)} guard(s) "
                f"({', '.join(wheres[:4])}{', ...' if len(wheres) > 4 else ''}), "
                f"which says nothing about their counts:\n      "
                + note.replace("\n", "\n      "),
                file=sys.stderr,
            )
        print(
            "\n  Commit, `git add`, or delete the files bx names (they may be "
            "another session's:\n  look before removing), then run this again. "
            "No count was read.",
            file=sys.stderr,
        )
        return final_exit_code(moved, broken, environment, unmeasured)
    if broken:
        print("", file=sys.stderr)
        print("guarded-count gate INPUT ERROR:", file=sys.stderr)
        for f in broken:
            print(f"  - {f}", file=sys.stderr)
        print(
            "\n  Fix the run before reading anything into the numbers above.",
            file=sys.stderr,
        )
        return final_exit_code(moved, broken, environment, unmeasured)
    if moved:
        print("", file=sys.stderr)
        print("guarded-count gate FAIL:", file=sys.stderr)
        for f in moved:
            print(f"  - {f}", file=sys.stderr)
        print("", file=sys.stderr)
        print(
            "  This push moves a test set a run-ci count guard counts, and the "
            "guard\n  still declares the old number. Move the constant IN THIS "
            "COMMIT, and move\n  it to what the command above PRINTED — never "
            "to what the diff suggests: the\n  module's other cases are "
            "`#[cfg]`-gated, so counting the diff has produced\n  the wrong "
            "number before (run-ci.sh's own comment records it).",
            file=sys.stderr,
        )
        return final_exit_code(moved, broken, environment, unmeasured)
    # Under --cached-only `todo` is what the cache could not answer: nothing
    # cached moved, but part of the push was not read at all. EXIT_UNMEASURED is
    # its own code: it is neither "green" nor "the count moved". A full run
    # measures everything in `todo`, so there it is always empty here.
    return final_exit_code(moved, broken, environment, unmeasured)


def measure(guards, verbose):
    """`{id(guard): (status, counts, note, False)}` for guards the cache could
    not answer.

    Guards that need the machine (a demo build the lane provisions first) run
    one by one HERE. The rest go to the builder in one batch when `$BX` names
    one, else one by one locally; the batch is only worth its shell when there
    is more than one of them.
    """
    bx = os.environ.get("BX", "")
    routed = bool(bx) and os.access(bx, os.X_OK)
    # One command measured once: several guards in a lane repeat a command with
    # a different label or a different line, and a repeat is the same count.
    groups = {}
    for g in guards:
        groups.setdefault(
            (g.list_measurable, tuple(g.prelude), tuple(g.cmd), getattr(g, "demo_features", None)),
            [],
        ).append(g)
    reps = [members[0] for members in groups.values()]
    local = [
        g for g in reps
        if getattr(g, "demo_features", None) is not None and not g.list_measurable
    ]
    rest = [g for g in reps if g not in local]
    out = {}
    if routed and len(rest) > 1:
        for gid, (status, counts, note) in run_batch(rest, verbose).items():
            out[gid] = (status, counts, note, False)
        rest = []
    for g in local + rest:
        status, counts, note = run_guard(g, verbose)
        out[id(g)] = (status, counts, note, False)
    for members in groups.values():
        status, counts, note, fc = out[id(members[0])]
        for g in members[1:]:
            # The count is shared; each member's own declared number is judged.
            same = status in ("OK", "MOVED")
            out[id(g)] = (
                cached_verdict(g.want, counts)[0] if same else status,
                counts, note, fc,
            )
    return out


# ── selftest ────────────────────────────────────────────────────────────
# Each arm is a case an obvious implementation gets WRONG. An arm that would be
# green against a naive version measures nothing, which is the trap R2137 found
# in six of its own fixtures — so the reason each one discriminates is named.

FIXTURE = """
    _runci_guarded_test "C1AY stock_config_tests 37" 37 \\
        cargo test -p demo-crate --features zenoh-config stock_config_tests --quiet || return 1
    _runci_guarded_test "C1AY topology 4" 4 \\
        cargo test -p demo-crate --features zenoh-config --test topology_binary --quiet || return 1
    _runci_guarded_test "C1AY other 9" 9 \\
        cargo test -p other-crate --features x other_tests --quiet || return 1
    _runci_guarded_test "C1AY loop $leg 2" 2 \\
        cargo test -p demo-crate --exact "$leg" --quiet || return 1
    _runci_guarded_test "Z oracle 3" 3 env DEMO_ORACLE_BIN="$oracle" \\
        cargo test -p demo-crate --test topology_binary --quiet || return 1
    _runci_guarded_test "Z fixed 5" 5 env DEMO_ORACLE_BIN=/opt/fixed \\
        cargo test -p demo-crate --test topology_binary --quiet || return 1
"""

MANIFESTS = {"demo": "demo-crate", "other": "other-crate", "third": "other-crate"}
SRC = {
    ("demo", "src/args.rs"): "mod stock_config_tests {\n fn a() {}\n}\n",
    ("demo", "tests/topology_binary.rs"): "#[test]\nfn t() {}\n",
}


def _reader(d, rel):
    return SRC.get((d, rel), "")


def selftest():
    guards = parse_guards(FIXTURE)
    arms = []

    def arm(name, cond, why):
        arms.append((name, bool(cond), why))

    arm(
        "parse: every numeric guard, the unrunnable ones carried too",
        len(guards) == 6 and [g.want for g in guards] == [37, 4, 9, 2, 3, 5],
        "a parser that cut at the label would find the wrong command",
    )

    # The R2166 case itself: the added test's NAME appears nowhere in the
    # guard's filter — only the enclosing MODULE does. An implementation that
    # matched the filter against added function names misses it entirely.
    sel, skip = select(
        guards,
        ["crates/demo/src/args.rs"],
        {"demo": ["    #[test]", "    fn every_argv_only_key_says_which_kind() {}"]},
        MANIFESTS,
        _reader,
    )
    arm(
        "R2166: filter matches the MODULE, not the added fn",
        [g.want for g in sel] == [37],
        "matching the filter against the added fn name finds nothing",
    )
    arm(
        "the $leg guard is reported unrunnable, not silently dropped",
        any("shell assembles" in w for _g, w in skip),
        "a silent drop reads exactly like coverage",
    )

    # R2200: the expansion is in the `env` PREFIX, which the parser used to
    # discard before this check ever saw it. The remaining tokens carry no `$`,
    # so the old reader selected the guard, ran it somewhere the shell-supplied
    # oracle does not exist, and reported UNMEASURED -- a broken instrument
    # blocking a push over a count it never read. The control below is the half
    # that keeps this from being a blanket excuse for an `env` prefix.
    sel_env, skip_env = select(
        guards,
        ["crates/demo/tests/topology_binary.rs"],
        {"demo": ["#[test]"]},
        MANIFESTS,
        _reader,
    )
    arm(
        "R2200: a shell-assembled env PREFIX makes the guard unrunnable",
        3 not in [g.want for g in sel_env]
        and any(g.want == 3 and "shell assembles" in w for g, w in skip_env),
        "the prefix is part of the command; dropping it hides the expansion",
    )
    arm(
        "CONTROL: a LITERAL env prefix stays runnable",
        5 in [g.want for g in sel_env],
        "skipping every `env` prefix would excuse the reproducible ones too",
    )

    # R2631: the filter is the MODULE PATH of the changed file, and the file's
    # TEXT never spells it. Text-only matching left `C1y auth_dispatch` unreached
    # while the push moved its count 6 -> 7. The two controls are what keep the
    # repair from being "select on any change": a different module with the SAME
    # text is not reached, and a longer module name does not satisfy a `name::`
    # filter across the boundary.
    mp_guards = parse_guards(
        '    _runci_guarded_test "C1AY auth 6" 6 \\\n'
        "        cargo test -p demo-crate --features x --lib auth_dispatch --quiet || return 1\n"
        '    _runci_guarded_test "C1AY pubkey 12" 12 \\\n'
        "        cargo test -p demo-crate --features x --lib extauth_pubkey:: --quiet || return 1\n"
    )
    body = "mod tests {\n    #[test]\n    fn t() {}\n}\n"

    def mp_reader(_d, _rel):
        return body

    def wants(changed):
        s, _ = select(mp_guards, [f"crates/demo/{changed}"], {"demo": ["    #[test]"]},
                      MANIFESTS, mp_reader)
        return sorted(g.want for g in s)

    arm(
        "R2631: a filter naming the changed file's MODULE PATH reaches the guard",
        wants("src/auth_dispatch.rs") == [6],
        "the file text never spells its own module name, so text-only matching misses it",
    )
    arm(
        "CONTROL: the same text in a DIFFERENT module reaches nothing",
        wants("src/other_module.rs") == [],
        "reaching every guard on any change would be the 175s lane, not a repair",
    )
    arm(
        "R2631: a `name::` filter reaches the module it names",
        wants("src/extauth_pubkey.rs") == [12],
        "the anchored spelling must still select its own module",
    )
    arm(
        "CONTROL: `extauth_pubkey::` is NOT reached by `extauth_pubkey_store`",
        wants("src/extauth_pubkey_store.rs") == [],
        "without the `::` boundary a longer module name would satisfy the filter",
    )
    arm(
        "module_path_prefix: crate roots contribute nothing, mod.rs names its dir",
        module_path_prefix("src/lib.rs") == ""
        and module_path_prefix("src/main.rs") == ""
        and module_path_prefix("src/interceptor/mod.rs") == "interceptor::"
        and module_path_prefix("src/interceptor/access_control.rs") == "interceptor::access_control::"
        and module_path_prefix("tests/x.rs") == "",
        "a wrong root would make every src change reach every unfiltered-looking guard",
    )

    # A package the push did not touch must not be selected. An implementation
    # that ran every guard for a changed FILE SET would pull `other-crate` in.
    sel, _ = select(
        guards, ["crates/demo/src/args.rs"], {"demo": ["#[test]"]}, MANIFESTS, _reader
    )
    arm(
        "an untouched package is not selected",
        all(g.pkg == "demo-crate" for g in sel),
        "running every guard makes the gate the 175s lane",
    )

    # `--test T` reaches only its OWN file. Selecting it because the crate
    # changed would build a target the push cannot have moved.
    sel, _ = select(
        guards, ["crates/demo/src/args.rs"], {"demo": ["#[test]"]}, MANIFESTS, _reader
    )
    arm(
        "a --test guard is NOT reached by a src/ change",
        all(g.test_target is None for g in sel),
        "'the crate changed' would select it and build for nothing",
    )
    sel, _ = select(
        guards,
        ["crates/demo/tests/topology_binary.rs"],
        {"demo": ["#[test]"]},
        MANIFESTS,
        _reader,
    )
    arm(
        # NON-EMPTY first, `all` second. `all` over an empty list is true, so
        # the second half alone would report green on exactly the failure this
        # arm exists to catch. The count is deliberately NOT pinned: how many
        # guards the fixture aims at this target is a property of the fixture,
        # and pinning it made this arm red when R2200 widened the fixture for a
        # different rule.
        "a --test guard IS reached by its own file",
        sel and all(g.test_target == "topology_binary" for g in sel),
        "the previous arm alone would also pass if nothing were ever selected",
    )

    # A body-only edit cannot move a count. Without the trigger this builds on
    # every crate push.
    sel, _ = select(
        guards,
        ["crates/demo/src/args.rs"],
        {"demo": ["    assert_eq!(a, b);"]},
        MANIFESTS,
        _reader,
    )
    arm(
        "a body-only edit triggers nothing",
        sel == [],
        "no trigger means every crate push pays for a build",
    )

    # R2158's shape: a feature gate REMOVED above tests that already existed.
    # `#[test]`-only triggering misses it, and that push moved two counts.
    sel, _ = select(
        guards,
        ["crates/demo/src/args.rs"],
        {"demo": ['    #[cfg(feature = "routing-peer")]']},
        MANIFESTS,
        _reader,
    )
    arm(
        "R2158: a removed #[cfg] triggers",
        [g.want for g in sel] == [37],
        "triggering on #[test] alone misses the gate-removal shape",
    )

    # The lane greps the WHOLE output. A verdict reading only the last summary
    # disagrees with the lane about the same run.
    arm(
        "verdict: any summary line satisfies, as the lane does",
        verdict(38, 0, "test result: ok. 38 passed\ntest result: ok. 0 passed")
        == ("OK", [38, 0]),
        "reading the last summary contradicts _runci_guarded_test",
    )
    arm(
        "verdict: a moved count is MOVED and reports what it saw",
        verdict(37, 0, "test result: ok. 38 passed") == ("MOVED", [38]),
        "the number seen is what the author must copy",
    )
    arm(
        "verdict: a non-zero exit is not a count claim",
        verdict(38, 101, "test result: ok. 38 passed") == ("FAILED", [38]),
        "a crashed run can still have printed a passing summary",
    )
    # R2661 — THE SHAPE THE ARM ABOVE DOES NOT COVER, and the common one. A
    # single-binary guard whose tests go RED prints `FAILED`, never `ok`, so
    # `counts` is empty; with the `not counts` test first this answered
    # UNMEASURED and the report said "NO libtest summary — measured nothing",
    # which is false about the run and points at a compile error rather than at
    # the failing test. `FAILED` was reachable only when some OTHER binary in
    # the same run printed an `ok` line, i.e. never for the usual guard.
    #
    # MEASURED against both orderings before it was written: of the five
    # verdict fixtures, this is the ONLY one whose answer moves, so the reorder
    # is behaviour-preserving everywhere an arm already looked.
    arm(
        "verdict: a RED test binary is FAILED, not UNMEASURED",
        verdict(38, 101, "test result: FAILED. 38 passed; 1 failed") == ("FAILED", []),
        "reporting a red run as 'no summary' sends the reader to the wrong file",
    )
    # The hole the R2166 probe found in THIS file: routed through `$BX` the
    # summary is in a log the wrapper names, so the captured stdout has none,
    # and the first draft called that `declares 37, printed no summary line` —
    # a sentence about a number, from a run that measured none.
    arm(
        "verdict: no summary at all is UNMEASURED, not a moved count",
        verdict(37, 0, "bx: exit=0 in 27s — full log: /x.log")
        == ("UNMEASURED", []),
        "folding it into MOVED pronounces on a subject never reached",
    )

    # R2236 — the demo a guard's lane provisions, DERIVED. The fixture carries
    # the shape the previous implementation swallowed: a guard whose lane builds
    # the demo (so the guard depends on machine-local provisioning) and a guard
    # in a LATER function that must NOT inherit that build. Without the second
    # arm the derivation could be "the nearest build anywhere above", which is
    # green on the first arm alone and wrong for every lane after a demo lane.
    demo_fixture = "\n".join(
        [
            "layer_with_a_demo() {",
            "    (cd crates && cargo build -p wz-ap-demo --features quic,routing-peer"
            " --quiet) || return 1",
            "    _runci_guarded_test A 6 cargo test -p p --test t -- --ignored",
            "}",
            "layer_without_one() {",
            "    _runci_guarded_test B 3 cargo test -p p --test u -- --ignored",
            "}",
            # R2248 — the shape the OLD regex swallowed: Layer Ewire's build
            # names no features, and requiring them read this lane as demo-free.
            "layer_with_a_featureless_demo() {",
            "    (cd crates && cargo build -p wz-ap-demo --quiet) || return 1",
            "    _runci_guarded_test C 1 cargo test -p p --test v -- --ignored",
            "}",
        ]
    )
    dg = parse_guards(demo_fixture)
    arm(
        "R2236: a guard inherits its OWN lane's demo build",
        len(dg) == 3 and dg[0].demo_features == "quic,routing-peer",
        "a guard run without its lane's demo answers about the wrong binary",
    )
    arm(
        "R2236: the scan stops at the function boundary (the control)",
        len(dg) == 3 and dg[1].demo_features is None,
        "inheriting a previous lane's build would provision the wrong features",
    )
    arm(
        "R2248: a FEATURELESS demo build is still a demo build",
        len(dg) == 3 and dg[2].demo_features == "",
        "requiring --features read Layer Ewire as demo-free, routed its guard "
        "to a build host that has no zenoh-pico CLI, and the run came back "
        "with no libtest summary at all",
    )
    arm(
        "R2248: and `` is not `None` -- the two answers stay apart (the control)",
        len(dg) == 3 and dg[2].demo_features is not None and dg[1].demo_features is None,
        "folding the featureless case into None puts it back on the build host",
    )

    # R2650 — the literal-assignment pass, with its refusals as controls. A
    # resolver that only ever resolves cannot show that it declines the cases it
    # must decline, and a WRONG expansion is worse than the deferral it replaces.
    lv = literal_vars(
        'local access="a,b"\n'
        'dup="one"\n'
        'dup="two"\n'
        'spaced="-D warnings"\n'
        'computed="$other"\n'
    )
    arm(
        "R2650: one literal assignment resolves",
        lv.get("access") == "a,b",
        "the guard whose features the shell assembles stays unmeasurable, which "
        "is the hole this pass exists to close",
    )
    arm(
        "R2650: a name assigned two DIFFERENT literals is refused (the control)",
        "dup" not in lv,
        "guessing between them would make a guard measurable and WRONG, which "
        "is worse than deferring it",
    )
    arm(
        "R2650: a value carrying whitespace is refused (the control)",
        "spaced" not in lv,
        "dropping the quotes around it would re-tokenize the command",
    )
    arm(
        "R2650: a value that is itself an expansion is refused (the control)",
        "computed" not in lv,
        "resolving one level and calling it literal would substitute a `$`",
    )
    arm(
        "R2650: an unresolvable use is left exactly as written",
        expand_literal_vars('--features "$access" --lib x', lv)
        == "--features a,b --lib x"
        and expand_literal_vars('--features "$dup"', lv) == '--features "$dup"',
        "rewriting a use this pass cannot resolve would hide the deferral it is "
        "supposed to leave visible",
    )

    selftest_787(arm)
    selftest_exit_codes(arm)

    bad =[(n, w) for n, ok, w in arms if not ok]
    print(f"guarded-count gate selftest: {len(arms) - len(bad)}/{len(arms)} arm(s) OK")
    for name, ok, _ in arms:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if bad:
        print("", file=sys.stderr)
        for name, why in bad:
            print(f"selftest FAIL: {name} — {why}", file=sys.stderr)
        return 1
    return 0


# ── selftest, item 787 ───────────────────────────────────────────────────
# The three pushes that left a guard behind (C1l, C1aq, C1ns), as fixtures, and
# each rule this item added with the control that keeps it from becoming "select
# everything". The mutant the register named -- select a guard only when its own
# line changed -- turns every arm of the first three groups red.

SHELL_FIXTURE = r"""
BUDGET=180

lane_loop() {
    local F="x"
    local G="$F,zenoh-config"
    for leg in alpha beta; do
        _runci_guarded_test "L $leg" 1 \
            cargo test -p demo-crate --features "$G" --test t -- --ignored --quiet \
            --exact "$leg" || return 1
    done
    if [[ -x "$tools/no-such-tool" ]]; then
        _runci_guarded_test "behind a file test" 5 \
            cargo test -p demo-crate --features "$G" --lib --quiet || return 1
    fi
    local empty
    empty="$(python3 nothing.py)"
    _runci_guarded_test "from a command" 2 \
        cargo test -p demo-crate --features "$empty" --quiet || return 1
    _runci_guarded_test "wrapped" 4 \
        timeout "$BUDGET" env DEMO_BIN="$tools/bin" \
        cargo test -p demo-crate --lib --quiet || return 1
    _runci_guarded_test "quoted literal" 6 \
        cargo test -p demo-crate --features "x,zenoh-config" --lib --quiet || return 1
}
"""


def selftest_exit_codes(arm):
    """The five outcomes a caller must tell apart, and the line it reads."""
    arm(
        "exit code: judged equal and fully measured is 0",
        final_exit_code([], [], [], []) == EXIT_OK,
        "the pass case",
    )
    arm(
        "exit code: a count that disagrees is 1, with or without unmeasured guards",
        final_exit_code(["m"], [], [], []) == EXIT_DISAGREE
        and final_exit_code(["m"], [], [], ["u"]) == EXIT_DISAGREE,
        "a known wrong number must not be downgraded to 'not measured' by "
        "another guard's absence from the cache",
    )
    arm(
        "exit code: only unmeasured guards is 3, distinct from a disagreement",
        final_exit_code([], [], [], ["u"]) == EXIT_UNMEASURED
        and EXIT_UNMEASURED not in (EXIT_OK, EXIT_DISAGREE, EXIT_CANNOT_JUDGE),
        "the hook passes on this and refuses on 1",
    )
    arm(
        "exit code: a run that could not be read is 2, never 1",
        final_exit_code([], ["b"], [], []) == EXIT_CANNOT_JUDGE
        and final_exit_code([], [], ["e"], []) == EXIT_CANNOT_JUDGE
        and final_exit_code(["m"], ["b"], [], []) == EXIT_CANNOT_JUDGE,
        "a number read from a broken run proves nothing, so it outranks a "
        "disagreement beside it",
    )
    arm(
        "exit code: the exit codes are five distinct values",
        len({EXIT_OK, EXIT_DISAGREE, EXIT_CANNOT_JUDGE, EXIT_UNMEASURED, EXIT_BUSY}) == 5,
        "two outcomes sharing a code is the defect this block exists to prevent",
    )
    line = cached_only_line(10, 9, 0, 1)
    arm(
        "cached-only: the summary line carries every count and the prefix a caller greps",
        line.startswith(CACHED_ONLY_PREFIX)
        and "10 reached" in line
        and "9 equal" in line
        and "0 disagree" in line
        and "1 not measured" in line
        and "\n" not in line,
        "the hook prints this line instead of parsing per-guard output",
    )
    import io
    import contextlib

    def crash():
        raise OSError("range unreadable")

    saved = globals()["main"]
    globals()["main"] = crash
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            rc = run()
    finally:
        globals()["main"] = saved
    arm(
        "exit code: a crash inside the tool exits 2, not Python's default 1",
        rc == EXIT_CANNOT_JUDGE,
        "an uncaught exception would read as 'a count disagrees'",
    )


def selftest_787(arm):
    def guard(cmd, want=1, lineno=10):
        return Guard(lineno, "helper", want, cmd.split())

    def pick(guards, files_new, files_old, run_ci_lines=frozenset(), unchanged=None):
        unchanged = unchanged or {}
        keys = sorted(set(files_new) | set(files_old))
        shape = {}
        for d, rel in keys:
            if rel in MANIFEST_FILES or shape_lines(files_old.get((d, rel), "")) != shape_lines(
                files_new.get((d, rel), "")
            ):
                shape.setdefault(d, set()).add(rel)

        def new_text(d, rel):
            return files_new.get((d, rel), unchanged.get((d, rel), ""))

        def old_text(d, rel):
            return files_old.get((d, rel), unchanged.get((d, rel), ""))

        sel, _ = select(
            guards,
            [f"crates/{d}/{rel}" for d, rel in keys],
            {},
            MANIFESTS,
            new_text,
            old_text=old_text,
            shape_changed=shape,
            run_ci_lines=run_ci_lines,
        )
        return sel

    # ---- the three pushes that left a guard behind ------------------------
    # C1l (`6a108810`): ten tests joined `reassembly_dispatch`; the guard's own
    # line did not change.
    g_l = guard("cargo test -p demo-crate --features x --lib reassembly --quiet", 27)
    g_group = guard("cargo test -p demo-crate --features x --lib group --quiet", 9)
    old_l = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn a() {}\n}\n"
    new_l = old_l + (
        "#[cfg(test)]\nmod unknown_ring_tests {\n    #[test]\n    fn ring() {}\n}\n"
    )
    sel = pick(
        [g_l, g_group],
        {("demo", "src/reassembly_dispatch.rs"): new_l},
        {("demo", "src/reassembly_dispatch.rs"): old_l},
    )
    arm(
        "C1l: tests added to a module the filter names select the guard, its line unchanged",
        sel == [g_l],
        "selecting only on the guard's own line misses all three leaks",
    )

    # C1aq (`5f9e0417`): three tests replaced by one, a new module declared in
    # lib.rs, a new file. The unrelated `group` guard must not ride along.
    g_adv = guard("cargo test -p demo-crate --features x --lib advanced_ --quiet", 25)
    sel = pick(
        [g_adv, g_group],
        {
            ("demo", "src/advanced_cache.rs"): "mod t {\n    #[test]\n    fn one() {}\n}\n",
            ("demo", "src/time_range.rs"): "mod t {\n    #[test]\n    fn two() {}\n}\n",
            ("demo", "src/lib.rs"): "mod advanced_cache;\nmod time_range;\n",
        },
        {
            ("demo", "src/advanced_cache.rs"): (
                "mod t {\n    #[test]\n    fn one() {}\n    #[test]\n    fn two() {}\n"
                "    #[test]\n    fn three() {}\n}\n"
            ),
            ("demo", "src/lib.rs"): "mod advanced_cache;\n",
        },
    )
    arm(
        "C1aq: removed tests in a module the filter names select the guard",
        sel == [g_adv],
        "tests that LEFT a file are as much a move as tests that joined it",
    )

    # C1ns (`05b66969`): two tests added to the lib of a package whose guard has
    # no filter.
    g_ns = guard("cargo test -p demo-crate --lib --quiet", 24)
    sel = pick(
        [g_ns],
        {("demo", "src/lib.rs"): "#[test]\nfn a() {}\n#[test]\nfn b() {}\n#[test]\nfn c() {}\n"},
        {("demo", "src/lib.rs"): "#[test]\nfn a() {}\n"},
    )
    arm(
        "C1ns: tests added to the lib select an unfiltered --lib guard",
        sel == [g_ns],
        "a guard with no filter has nothing to narrow it and must follow its target",
    )
    sel = pick(
        [g_ns],
        {("demo", "src/lib.rs"): "#[test]\nfn a() {\n    assert_eq!(1, 2);\n}\n"},
        {("demo", "src/lib.rs"): "#[test]\nfn a() {\n    assert_eq!(1, 1);\n}\n"},
    )
    arm(
        "CONTROL: a body-only edit reaches nothing",
        sel == [],
        "selecting on any change in the package is the 175s lane for every push",
    )
    g_line = guard("cargo test -p demo-crate --lib --quiet", 24, lineno=10)
    g_line.span = (10, 12)
    arm(
        "the fix range: only run-ci.sh changed, and the edited guard is selected",
        pick([g_line], {}, {}, run_ci_lines=frozenset({11})) == [g_line],
        "the ledger records the oracle reaching nothing from a range that only edited the number",
    )
    arm(
        "CONTROL: an edit to another line of run-ci.sh selects nothing",
        pick([g_line], {}, {}, run_ci_lines=frozenset({13})) == [],
        "selecting every guard on any run-ci.sh edit would make a comment edit a build",
    )

    # ---- reach by target kind ---------------------------------------------
    g_lib = guard("cargo test -p demo-crate --lib --quiet", 3)
    g_t = guard("cargo test -p demo-crate --test foo --quiet", 3)
    g_all = guard("cargo test -p demo-crate --quiet", 3)
    one_test = "#[test]\nfn a() {}\n"
    sel = pick([g_lib, g_t, g_all], {("demo", "tests/foo.rs"): one_test}, {})
    arm(
        "tests/foo.rs reaches --test foo and the default target, not --lib",
        sel == [g_t, g_all],
        "before this item a guard naming no target was never reached from tests/",
    )
    sel = pick([g_lib, g_t, g_all], {("demo", "tests/bar.rs"): one_test}, {})
    arm(
        "CONTROL: tests/bar.rs does not reach --test foo",
        sel == [g_all],
        "a top-level tests/ file is a binary of its own",
    )
    sel = pick([g_lib, g_t, g_all], {("demo", "tests/common/mod.rs"): one_test}, {})
    arm(
        "a helper module under tests/ reaches every integration-test guard",
        sel == [g_t, g_all],
        "any binary may declare it",
    )

    # ---- filters ----------------------------------------------------------
    g_path = guard("cargo test -p demo-crate --lib foo::tests:: --quiet", 4)
    g_path_other = guard("cargo test -p demo-crate --lib bar::tests:: --quiet", 4)
    sel = pick(
        [g_path, g_path_other],
        {("demo", "src/foo.rs"): "mod tests {\n    #[test]\n    fn t() {}\n}\n"},
        {},
    )
    arm(
        "a filter that spans module and submodule is reached by the file that spells them",
        sel == [g_path],
        "no file spells foo::tests:: in one run of text",
    )
    g_removed = guard("cargo test -p demo-crate --lib removed_suite --quiet", 2)
    sel = pick(
        [g_removed],
        {},
        {("demo", "src/gone.rs"): "mod removed_suite {\n    #[test]\n    fn t() {}\n}\n"},
    )
    arm(
        "a deleted file's tests are found in its OLD shape",
        sel == [g_removed],
        "the current tree no longer spells the name the count lost",
    )
    g_gated = guard("cargo test -p demo-crate --lib gated_case --quiet", 1)
    g_unrelated = guard("cargo test -p demo-crate --lib unrelated_name --quiet", 1)
    g_sibling = guard("cargo test -p demo-crate --lib router_forward --quiet", 1)
    sel = pick(
        [g_gated, g_unrelated, g_sibling],
        {("demo", "src/lib.rs"): "mod gated;\nmod router_forward;\n"},
        {("demo", "src/lib.rs"): "#[cfg(any())]\nmod gated;\nmod router_forward;\n"},
        unchanged={
            ("demo", "src/gated.rs"): "#[test]\nfn gated_case_runs() {}\n",
            ("demo", "src/router_forward.rs"): "#[test]\nfn forwards() {}\n",
        },
    )
    arm(
        "R2158: removing the #[cfg] above `mod gated;` reaches the tests of gated.rs",
        sel == [g_gated],
        "that file did not change; its tests appeared with the declaration",
    )
    arm(
        "CONTROL: the same edit does not reach guards whose filters name other modules",
        g_unrelated not in sel and g_sibling not in sel,
        "lib.rs declares every module, so matching a filter against its whole shape "
        "is how a one-line `mod` edit selected 74 guards",
    )
    arm(
        "filter_may_match: first piece ends an identifier, middle ones are identifiers",
        filter_may_match("xtra::mid::tail", "alpha_xtra mid tail_end")
        and not filter_may_match("xtra::mid::tail", "alpha_xtra mid_x tail_end")
        and not filter_may_match("pubkey::", "pubkey_store")
        and filter_may_match("pubkey::", "my_pubkey"),
        "libtest matches a SUBSTRING of the whole path, so each piece is held to its position",
    )

    # ---- manifests --------------------------------------------------------
    toml_old = (
        '[package]\nname = "demo-crate"\nversion = "0.1.0"\n'
        '[features]\ndefault = []\nx = []\nzenoh-config = ["x"]\nother = []\n'
    )

    def reached(toml_new, guards):
        return pick(
            guards,
            {("demo", "Cargo.toml"): toml_new},
            {("demo", "Cargo.toml"): toml_old},
        )

    g_fx = guard("cargo test -p demo-crate --features x --lib --quiet", 1)
    g_fz = guard("cargo test -p demo-crate --features zenoh-config --lib --quiet", 1)
    g_f0 = guard("cargo test -p demo-crate --lib --quiet", 1)
    arm(
        "a feature the build activates, edited in Cargo.toml, reaches the guard",
        reached(toml_old.replace("x = []", 'x = ["other"]'), [g_fx, g_fz, g_f0]) == [g_fx, g_fz],
        "a feature table moves a count with no #[cfg] line in any diff; zenoh-config implies x",
    )
    arm(
        "CONTROL: a feature no guard activates reaches nothing",
        reached(toml_old.replace("other = []", 'other = ["x"]'), [g_fx, g_fz, g_f0]) == [],
        "every manifest edit selecting the package's 160 guards is not a narrowing",
    )
    arm(
        "CONTROL: a `dep:` entry added to a feature list reaches nothing",
        reached(
            toml_old.replace('zenoh-config = ["x"]', 'zenoh-config = ["x", "dep:serde"]'),
            [g_fx, g_fz, g_f0],
        )
        == [],
        "dep: never sets a cfg(feature), so no test can see it",
    )
    arm(
        "CONTROL: a registry dependency with features reaches nothing",
        reached(
            toml_old + '[dependencies]\nserde = { version = "1", features = ["derive"] }\n',
            [g_fx, g_fz, g_f0],
        )
        == [],
        "only a workspace crate's feature requests unify into the package's build",
    )
    arm(
        "a workspace dependency edit reaches every guard of the package",
        reached(toml_old + '[dev-dependencies]\nsupport = { path = "../support" }\n', [g_fx, g_f0])
        == [g_fx, g_f0],
        "wz-runtime-tokio's test-support dev-dependency turns a feature ON for its tests",
    )
    arm(
        "a [[test]] table edit reaches every guard of the package",
        reached(toml_old + '[[test]]\nname = "t"\nrequired-features = ["x"]\n', [g_fx, g_f0])
        == [g_fx, g_f0],
        "a target table is not bounded to features",
    )

    # ---- the shell, asked --------------------------------------------------
    gs = parse_guards(SHELL_FIXTURE)
    legs = [x for x in gs if x.words and "--exact" in x.words and x.resolved_by_shell]
    arm(
        "shell: a for-loop yields one guard per leg, features joined by bash",
        [x.cmd[-1] for x in legs] == ["alpha", "beta"]
        and all("x,zenoh-config" in x.cmd for x in legs),
        "a reader of the text sees `$leg` and one line; bash runs the loop",
    )
    arm(
        "shell: a guard behind a file test is reached (the inputs are assumed present)",
        any(x.want == 5 and x.resolved_by_shell for x in gs),
        "otherwise every guard behind `[[ -x tool ]]` stays unobservable here",
    )
    arm(
        "shell: a quoted literal needs no lane to resolve and still resolves",
        any(x.want == 6 and x.resolved_by_shell and "x,zenoh-config" in x.cmd for x in gs),
        "the quotes were why it was deferred",
    )
    wrapped = [x for x in gs if x.want == 4]
    arm(
        "shell: a `timeout N env X=...` wrapper resolves; only the env NAME is kept",
        len(wrapped) == 1
        and wrapped[0].resolved_by_shell
        and wrapped[0].needs_inputs
        and all("tools" not in t for t in wrapped[0].prelude),
        "the sandbox's own paths must not leak into a report",
    )
    refused = [x for x in gs if x.want == 2]
    arm(
        "CONTROL: a word built from a command that produced nothing is refused with its reason",
        len(refused) == 1
        and not refused[0].resolved_by_shell
        and refused[0].unresolved_reason is not None
        and "came out as" in refused[0].unresolved_reason,
        "a measurable-and-WRONG command is worse than the deferral it replaces",
    )
    sel_shell, skip_shell = select(
        [refused[0]], ["crates/demo/src/lib.rs"], {}, MANIFESTS, lambda d, r: "", shape_changed={"demo": {"src/lib.rs"}}
    )
    arm(
        "CONTROL: a refused guard is reported deferred, with the reason, not dropped",
        sel_shell == [] and any("shell assembles" in w and "came out as" in w for _g, w in skip_shell),
        "a silent drop reads as coverage",
    )
    arm(
        "match_call: variables stand for text, env VALUES may be empty, lengths must agree",
        gcs.match_call(["cargo", '"$A,x"'], ["cargo", "q,x"])[0]
        and not gcs.match_call(["cargo", '"$A,x"'], ["cargo", ",x"])[0]
        and gcs.match_call(['DEMO="$p"', "cargo"], ["DEMO=", "cargo"])[0]
        and not gcs.match_call(["cargo", "test"], ["cargo"])[0]
        and not gcs.match_call(['"$(f)"'], ["x"])[0]
        and not gcs.match_call(["cargo", "test"], ["cargo", "build"])[0],
        "each refusal here is a way a recorded call would be believed wrongly",
    )

    # ---- measuring ---------------------------------------------------------
    full = [
        "cargo", "test", "-p", "demo-crate", "--test", "t", "--", "--ignored",
        "--quiet", "--test-threads=1", "--exact", "n",
    ]
    arm(
        "list_argv: selection arguments stay, run-shaping ones go, --list is last",
        list_argv(full)
        == ["cargo", "test", "-p", "demo-crate", "--test", "t", "--", "--ignored", "--exact", "n", "--list"]
        and list_argv(["cargo", "test", "-p", "p", "--quiet"]) == ["cargo", "test", "-p", "p", "--", "--list"]
        and list_argv(["cargo", "test", "--", "--test-threads", "1", "--ignored"])
        == ["cargo", "test", "--", "--ignored", "--list"],
        "listing a different set than the run selects would measure another count",
    )
    arm(
        "an --ignored guard with a target is measured by listing; without one, it is not",
        Guard(1, "helper", 1, full).list_measurable
        and not Guard(1, "helper", 1, ["cargo", "test", "-p", "p", "--", "--ignored"]).list_measurable
        and not Guard(1, "helper", 1, ["cargo", "test", "-p", "p", "--lib"]).list_measurable,
        "a run without a target includes the doc-test harness, which has no --list",
    )
    arm(
        "verdict: a listing reads `N tests`, a run reads `ok. N passed`, neither reads the other",
        verdict(3, 0, "3 tests, 0 benchmarks\n0 tests, 0 benchmarks", True) == ("OK", [3, 0])
        and verdict(4, 0, "3 tests, 0 benchmarks", True) == ("MOVED", [3])
        and verdict(3, 0, "3 tests, 0 benchmarks")[0] == "UNMEASURED"
        and verdict(3, 0, "test result: ok. 3 passed", True)[0] == "UNMEASURED",
        "one regex for both would call a listing's summary a run's",
    )
    polluted = (
        "bx: these files are neither tracked nor ignored, so `git ls-files` never\n"
        "bx: send them\nbx:   .push-r1.log\nbx: exit=1 in 0s\n"
    )
    arm(
        "759: bx refusing a tree with untracked files is an ENVIRONMENT error naming the file",
        ".push-r1.log" in bx_environment_problem(polluted)
        and bx_environment_problem("test result: ok. 1 passed") == "",
        "read as 'measured nothing' it sent the author after their own build",
    )
    gb = [Guard(1, "helper", 5, ["cargo", "test"]), Guard(2, "helper", 7, ["cargo", "test"])]
    tag = "T"
    ok_log = (
        '# cmd: echo "@@GUARD-T-BEGIN 0"\n'
        "@@GUARD-T-BEGIN 0\ntest result: ok. 5 passed; 0 failed\n@@GUARD-T-RC 0 0\n"
        "@@GUARD-T-BEGIN 1\ntest result: ok. 6 passed; 0 failed\n@@GUARD-T-RC 1 0\n"
    )
    got = read_batch(tag, gb, ok_log)
    arm(
        "batch: each guard is judged from its own segment, the command echo is not one",
        got[id(gb[0])][0] == "OK" and got[id(gb[1])] == ("MOVED", [6], ""),
        "a marker read out of bx's own header would hand a guard another's output",
    )
    got = read_batch(tag, gb, "bx: " + polluted, logged=False)
    arm(
        "batch: a polluted tree is ENVIRONMENT for every guard, once",
        all(got[id(x)][0] == "ENVIRONMENT" for x in gb),
        "nothing ran, so no guard may be called UNMEASURED or MOVED",
    )

    calls = []
    real_run_guard = globals()["run_guard"]
    saved_bx = os.environ.pop("BX", None)
    try:
        globals()["run_guard"] = lambda g, v: (calls.append(g) or ("OK", [5], ""))
        twin_a, twin_b = Guard(1, "helper", 5, ["cargo", "test", "-p", "p"]), Guard(
            2, "helper", 6, ["cargo", "test", "-p", "p"]
        )
        out = measure([twin_a, twin_b], False)
    finally:
        globals()["run_guard"] = real_run_guard
        if saved_bx is not None:
            os.environ["BX"] = saved_bx
    arm(
        "one command is measured once and each guard keeps its own verdict",
        len(calls) == 1 and out[id(twin_a)][0] == "OK" and out[id(twin_b)][0] == "MOVED",
        "a repeated command is a repeated count; paying for it twice is the cost problem",
    )

    # ---- the cache and its digest -----------------------------------------
    import tempfile

    with tempfile.TemporaryDirectory(prefix="wz-gcg-") as tmp:
        root = Path(tmp)
        for name, dep in (("a", None), ("b", "a")):
            (root / name / "src").mkdir(parents=True)
            deps = f'\n[dependencies]\n{dep} = {{ path = "../{dep}" }}\n' if dep else ""
            (root / name / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion = "0.1.0"\n{deps}'
            )
            (root / name / "src" / "lib.rs").write_text("#[test]\nfn t() {\n    assert!(true);\n}\n")
        (root / "Cargo.toml").write_text("[workspace]\n")
        names = package_manifest_names(root)
        gb_ = Guard(1, "helper", 1, ["cargo", "test", "-p", "b", "--lib"])

        def digest():
            _SHAPE_MEMO.clear()
            return package_digest(gb_, names, root)

        base = digest()
        (root / "a" / "src" / "lib.rs").write_text(
            "#[test]\nfn t() {\n    assert!(1 + 1 == 2, \"a longer body\");\n}\n"
        )
        body_only = digest()
        (root / "a" / "src" / "lib.rs").write_text(
            "#[test]\nfn t() {}\n#[test]\nfn added() {}\n"
        )
        added_test = digest()
        arm(
            "digest: a body edit in a DEPENDENCY keeps it, an added test there moves it",
            body_only == base and added_test != base,
            "the cache would otherwise re-ask on every edit, or never re-ask at all",
        )
        key_a = cache_key(gb_, base)
        arm(
            "cache key: the command, the mode and the digest all move it; env values do not",
            key_a != cache_key(gb_, added_test)
            and key_a != cache_key(Guard(1, "helper", 1, ["cargo", "test", "-p", "b"]), base)
            and cache_key(
                Guard(1, "helper", 1, ["cargo", "test"], ("env", "K=one")), base
            )
            == cache_key(Guard(1, "helper", 1, ["cargo", "test"], ("env", "K=two")), base),
            "a key that ignores the digest serves a count measured on a different test set",
        )
        cache_file = root / "cache.json"
        c = Cache(cache_file)
        c.put(key_a, [7, 0])
        c.save()
        c2 = Cache(cache_file)
        arm(
            "cache: a recorded count is read back; a missing key is None",
            c2.get(key_a) == [7, 0] and c2.get("absent") is None,
            "a cache that cannot answer 'no' answers 'yes' for everything",
        )
        cache_file.write_text('{"version": "0", "entries": {"%s": [9]}}' % key_a)
        arm(
            "cache: a file from another digest version is ignored",
            Cache(cache_file).get(key_a) is None,
            "the digest definition changed, so every key it produced is wrong",
        )
        lock = root / "lock"
        try:
            with MeasurementLock(lock):
                try:
                    with MeasurementLock(lock):
                        second = "entered"
                except Busy as who:
                    second = f"busy: {who}"
        finally:
            pass
        arm(
            "752: a second measurement in the worktree is turned away, naming the first",
            second.startswith("busy: pid "),
            "queued behind cargo's lock it becomes a deadlock the pusher reads as a slow push",
        )

    doc = parse_manifest(
        '# c\n[package]\nname = "a"  # tail\n[features]\ndefault = [\n  "x", # one\n  "y",\n]\n'
        'x = []\n[target.\'cfg(unix)\'.dependencies]\nlibc = { version = "0.2", optional = true }\n'
        '[[test]]\nname = "t"\n[[test]]\nname = "u"\n[dependencies.serde]\nversion = "1"\n'
    )
    arm(
        "parse_manifest: tables, multi-line arrays, quoted target keys, arrays of tables, comments",
        doc is not None
        and doc["features"]["default"] == ["x", "y"]
        and doc["target"]["cfg(unix)"]["dependencies"]["libc"]["optional"] is True
        and [t["name"] for t in doc["test"]] == ["t", "u"]
        and doc["dependencies"]["serde"]["version"] == "1"
        and doc["package"]["name"] == "a",
        "tomllib is not on the python floor, and a wrong parse selects the wrong guards",
    )
    arm(
        "CONTROL: parse_manifest refuses what it cannot read, so callers fall back to the whole package",
        parse_manifest("x = 1979-05-27\n") is None
        and manifest_effect("x = 1979-05-27\n", "[package]\nname = 'a'\n") is None,
        "a guessed parse would bound an edit it did not understand",
    )
    arm(
        "shape_lines: a doc comment SHOWING an attribute is not one; a doc-test fence is",
        shape_lines("/// #[test]\nfn f() {}\n") == ("fn f() {}",)
        and any("doc-test" in x for x in shape_lines("/// ```\n/// x\n/// ```\nfn f() {}\n")),
        "R2131's lesson, and a doc-test is a test a guard without --lib counts",
    )
    arm(
        "shape_lines: a feature on the SECOND line of a cfg attribute is shape",
        shape_lines('#[cfg(any(\n    feature = "x",\n))]\nfn f() {}\n')
        != shape_lines('#[cfg(any(\n    feature = "y",\n))]\nfn f() {}\n'),
        "a diff-line grep sees `feature = \"x\",` and no attribute",
    )


def run():
    """`main()` with the exit-code contract kept under a crash.

    An uncaught exception exits 1 in Python, which is this gate's "a count
    disagrees". A tool that fell over (an unreadable range, an unreadable
    run-ci.sh) said nothing about any count, so it exits EXIT_CANNOT_JUDGE.
    """
    try:
        return main()
    except Exception:
        import traceback

        traceback.print_exc()
        print(
            "guarded-count gate: the tool itself failed (traceback above); no "
            "count was judged",
            file=sys.stderr,
        )
        return EXIT_CANNOT_JUDGE


if __name__ == "__main__":
    sys.exit(run())

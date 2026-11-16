#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y569 (§7.1) — tie every run-ci COUNT GUARD to the test binary it guards.

## The debt this closes, and why it was derivable all along

`run-ci.sh` asserts test counts in two shapes. The good one is
`_runci_guarded_test "label" N cargo test ...`, which captures the output and
says which assertion failed. The other is a bare
`cargo test ... 2>&1 | grep -qE '^test result: ok\\. N passed'`, and the debt
ledger has carried it for rounds under two complaints:

  1. it fails OPAQUELY — `2>&1 | grep -q` swallows cargo's own diagnostic, so a
     compile error and a count change are the same red;
  2. **nothing ties N to the binary**. Rename a test, delete one, or add one,
     and the guard is simply wrong until some lane happens to run.

The second complaint also contains its own remedy, which is why it is worth a
gate rather than a round of manual auditing: BOTH SIDES ARE READABLE WITHOUT
RUNNING ANYTHING. `N` is in `run-ci.sh`; the number of `#[test]` functions is in
the test file. This script reads both and compares.

## R2137 (unregistered open-debt item 126) — BOTH spellings, not just the bare one

For its first rounds this read only the bare spelling. `run-ci.sh:4383` records
the reasoning for the exclusion, and it is sound as far as it goes: the helper
captures its output rather than racing a pipe, so when it fails it says which
assertion failed. What that argument does not address is WHEN it fails — on the
next hosted run of that lane, which for a Layer Z leg may be many pushes away.
The number itself is hand-written at the moment a test is added, and that is the
moment nothing local reads it.

MEASURED 2026-08-26: the class leaked THREE TIMES IN ONE DAY (R2112, R2124 via
`fda06748`, and `2020dd71`), and R2117 had already written the reason into a
comment beside one of them. A memo is not a mechanism. So the helper spelling is
in the population now, checked by the same code, and its floor is separate.

Item 126 also asked whether this was affordable, and deferred on the grounds
that nobody had measured `cargo test` per guard × feature subset. That question
turned out to be about a design nobody needs: NOTHING IS BUILT OR RUN here. Both
sides are read off disk, the whole sweep is milliseconds, and it belongs in a
static lane rather than in pre-push's changed-crate test set — which is
structurally blind to this class anyway, since a stale guard lives in
`run-ci.sh` and not in any crate.

## What it deliberately does NOT try to analyse

A test count is only statically derivable when the test set does not depend on
the build configuration. So a guard is IN SCOPE only when it selects ONE test
file with `-p PKG --test BIN` and that file has no `#[cfg(...)]` on any test
function or enclosing module. `--exact NAME` names the test and is checked
directly against the file's declarations — the rename this gate exists to catch.

Open-debt item 400 -- a SUBSTRING filter is derivable too, on such a file, and
leaving it out of scope is how three hand-written numbers went stale in one
round with this lint green. libtest's rule is plain: a test runs when its full
name (`mod::path::fn`) contains ANY filter and no `--skip` word. In a merged
target the full name is `files::<file>::<path>` and `wz_test_args`' third word
reaches libtest as `files::<file>::<word>`, so the filter is read back with
that prefix. The module path of each test is walked from the file with string
literals blanked, and a walk that disagrees with the attribute census puts the
guard out of scope rather than publishing a count from it. A filter the shell
assembles (a variable, a quote) stays out of scope.

Everything else is reported as OUT OF SCOPE **with the reason that applies to
it**, and counted. An unexplained skip is how a gate becomes decorative, and a
LUMPED reason is the same failure one step later: 134 of the skips are `--lib`
selections whose census would have to span every module in a crate's `src/`,
19 name no cargo target at all, 17 are feature-dependent test files, 9 name a
test through a shell variable, and 6 applied a substring filter (now in scope
where the file is countable, item 400). Those numbers are auditable; one total
of 185 would not be.

The in-scope set must be NON-EMPTY **per spelling**. A joint floor would still
be cleared by the bare guards alone, so a parser that stopped recognising
`_runci_guarded_test` would go quiet in exactly the way item 126 is about.

Usage:
    python3 scripts/lib/count_guard_lint.py [--verbose]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import retarget_test_refs  # noqa: E402
import rust_comments  # noqa: E402  -- after the path insert that finds it
import test_sources  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNCI = REPO_ROOT / "scripts" / "run-ci.sh"
CRATES = REPO_ROOT / "crates"

# The guard, in every spelling `run-ci.sh` actually uses. The escaped and
# unescaped dot are BOTH present in the file, which is exactly how an earlier
# recount of this population came out wrong — it matched one spelling and
# reported the other as absent.
GUARD_RE = re.compile(r"grep -qE ['\"]\^test result: ok\\?\. (\d+) passed")
# The HELPER spelling, `_runci_guarded_test <label> <N>`, where the label may be
# quoted and carry spaces. Only a NUMERIC N is a claim about a count; `+` asserts
# that something ran, which nothing static can contradict.
HELPER_RE = re.compile(
    r"_runci_guarded_test\s+(?:\"[^\"]*\"|'[^']*'|\S+)\s+(\d+)(?=\s)"
)
CARGO_TEST_RE = re.compile(r"\bcargo test\b")
PKG_RE = re.compile(r"-p\s+([A-Za-z0-9_-]+)")
TEST_BIN_RE = re.compile(r"--test\s+([A-Za-z0-9_]+)")
TEST_ATTR_RE = re.compile(r"#\[(?:tokio::)?test\b")

# Where the shell's own grammar takes over and libtest's arguments end. Reading
# past one of these is how `|| return 1` becomes a pair of "test name filters".
SHELL_OPS = frozenset(
    {"||", "&&", ";", "|", ">", ">>", "2>&1", "2>/dev/null", ">/dev/null"}
)
# Flags that CONSUME the next token. Without this list a `--features a,b` reads
# as the flag plus a bare word, and a bare word after `--test` is a filter.
VALUE_FLAGS = frozenset(
    {
        "-p", "--package", "--exclude", "--features", "-F", "--target",
        "--manifest-path", "--target-dir", "--profile", "-j", "--jobs",
        "--color", "--message-format", "-Z", "--config", "--bin", "--example",
        "--bench", "--test", "--skip", "--test-threads", "--logfile", "--format",
        "--shuffle-seed",
    }
)
# A name is derivable only when the shell has not put it there.
SHELL_EXPANSION_RE = re.compile(r"[$`\"']")
# A filter word as libtest receives it: a test path or a piece of one.
PLAIN_NAME_RE = re.compile(r"^[A-Za-z0-9_:]+$")


def mapped_logical_lines(text: str) -> list[tuple[str, list[tuple[int, int]]]]:
    """Join backslash continuations, keeping where each physical line begins.

    `run-ci.sh` writes its lanes as one `(cd crates && a && b && c)` subshell
    spread over many physical lines, so a physical-line scan sees a guard with
    no `cargo test` beside it and a `cargo test` with no guard. Each logical line
    comes with `(offset, physical line no)` for every physical line joined into
    it, so a match inside it can name the line it actually sits on.
    """
    out: list[tuple[str, list[tuple[int, int]]]] = []
    buf: str | None = None
    starts: list[tuple[int, int]] = []
    for i, line in enumerate(text.split("\n"), 1):
        if buf is None:
            buf, starts = line, [(0, i)]
        else:
            buf += " "
            starts.append((len(buf), i))
            buf += line.strip()
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
        else:
            out.append((buf, starts))
            buf = None
    if buf is not None:
        out.append((buf, starts))
    return out


def line_at(starts: list[tuple[int, int]], offset: int) -> int:
    """The physical line holding character `offset` of a mapped logical line."""
    line = starts[0][1]
    for begin, lineno in starts:
        if begin > offset:
            break
        line = lineno
    return line


def logical_lines(text: str) -> list[tuple[int, str]]:
    """`mapped_logical_lines` with each logical line's FIRST physical line no."""
    return [(starts[0][1], logical) for logical, starts in mapped_logical_lines(text)]


def guard_segments(text: str) -> list[tuple[int, str]]:
    """Every `&&`-separated segment that both runs cargo test and guards a count,
    with the physical line its guard sits on.

    Open-debt item 536: this used to report the logical line's FIRST physical
    line, which for a guard inside a multi-line `(cd crates && ...)` subshell is
    the subshell's opening line -- one to four lines off, and the same line for
    every guard of the subshell. The segment offsets are kept through the split
    so the guard's own line is named.
    """
    found = []
    for logical, starts in mapped_logical_lines(text):
        if logical.lstrip().startswith("#"):
            continue
        pos = 0
        for seg in logical.split("&&"):
            guard = GUARD_RE.search(seg)
            if CARGO_TEST_RE.search(seg) and guard:
                found.append((line_at(starts, pos + guard.start()), seg.strip()))
            pos += len(seg) + len("&&")
    return found


def helper_segments(text: str) -> list[tuple[int, str, int]]:
    """Every `_runci_guarded_test LABEL N ...` site whose N is a number.

    R2137 (unregistered open-debt item 126) — this spelling used to be outside
    this lint's population BY DESIGN, and `run-ci.sh:4383` carries the reasoning:
    the helper captures its output instead of racing a pipe, so when it fails it
    says which assertion failed. That is true and it is not enough. A legible
    failure still lands on a HOSTED run, and the number is written by hand at the
    moment a test is added — the one moment nothing local reads it.

    MEASURED 2026-08-26: the class leaked THREE TIMES IN ONE DAY (R2112, R2124,
    `2020dd71`), and R2117 had already written the reason into a comment beside
    one of them. So the remedy is not another note: a memo is not a mechanism.

    The derivable subset of this spelling is the same subset as the bare one, and
    it is checked by the same code below. What differs is only the `grep -q` pipe
    race, which this spelling structurally cannot have.
    """
    found = []
    for logical, starts in mapped_logical_lines(text):
        if logical.lstrip().startswith("#"):
            continue
        m = HELPER_RE.search(logical)
        if not m:
            continue
        found.append(
            (line_at(starts, m.start()), logical[m.start() :].strip(), int(m.group(1)))
        )
    return found


def command_tokens(seg: str) -> list[str]:
    """`seg`'s tokens, cut where the shell's own operators begin.

    `|| return 1` is not something libtest ever sees. Reading it as one produced
    a dozen phantom "filters" when this was first probed, and a phantom filter is
    worse than a missed one: it reports the site OUT OF SCOPE, which reads
    exactly like coverage.
    """
    toks = seg.split()
    for i, t in enumerate(toks):
        if t in SHELL_OPS:
            return toks[:i]
    return toks


def libtest_selection(toks: list[str], start: int) -> tuple[bool, list[str], bool]:
    """`(exact_mode, filters, has_skip)` for the tokens from `start` onward.

    libtest's own arguments begin at the STANDALONE `--` token, but a positional
    filter reaches libtest from either side of it — cargo forwards its own
    trailing positionals — and `run-ci.sh:12500` is that shape. So the scan
    covers both sides and the `--` is merely skipped.

    Splitting on the two-character SUBSTRING `--` instead, which the first draft
    of this did, makes `--quiet` read as the bare word `quiet` and therefore as a
    filter: the site is then declared out of scope for a narrowing that does not
    exist.
    """
    exact_mode = False
    filters: list[str] = []
    has_skip = False
    i = start
    while i < len(toks):
        t = toks[i]
        if t == "--":
            i += 1
        elif t == "--exact":
            exact_mode = True
            i += 1
        elif t == "--skip":
            has_skip = True
            i += 2
        elif t in VALUE_FLAGS:
            i += 2
        elif t.startswith("-"):
            i += 1
        else:
            filters.append(t)
            i += 1
    return exact_mode, filters, has_skip


def skip_words(toks: list[str], start: int) -> list[str]:
    """The value of every `--skip` from `start` onward."""
    return [toks[i + 1] for i in range(start, len(toks) - 1) if toks[i] == "--skip"]


MOD_OPEN_RE = re.compile(r"\bmod\s+([A-Za-z_]\w*)\s*\{")
FN_NAME_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)")


def test_paths(path: Path) -> list[tuple[str, bool]]:
    """`(path within the file, ignored)` for every `#[test]` fn of `path`.

    The path is the chain of inline `mod NAME {` blocks around the attribute,
    then the fn name: what libtest prints after the target's own prefix. Braces
    are counted with string and char literals blanked, since `format!("{x}")`
    would otherwise move every module boundary after it.
    """
    return test_paths_of(path.read_text())


def test_paths_of(source: str) -> list[tuple[str, bool]]:
    """`test_paths` over a source text."""
    text = rust_comments.strip_comments(source, blank_literals=True)
    opens = {m.end() - 1: m.group(1) for m in MOD_OPEN_RE.finditer(text)}
    lines = text.split("\n")
    line_mods: list[tuple[str, ...]] = []
    stack: list[tuple[str, int]] = []
    depth = 0
    pos = 0
    for ln in lines:
        line_mods.append(tuple(name for name, _ in stack))
        for k, ch in enumerate(ln):
            if ch == "{":
                name = opens.get(pos + k)
                if name is not None:
                    stack.append((name, depth))
                depth += 1
            elif ch == "}":
                depth -= 1
                if stack and stack[-1][1] == depth:
                    stack.pop()
        pos += len(ln) + 1
    out: list[tuple[str, bool]] = []
    for i, line in enumerate(lines):
        attr = TEST_ATTR_RE.search(line)
        if not attr:
            continue
        j = i
        while j > 0 and lines[j - 1].lstrip().startswith("#["):
            j -= 1
        k = i
        while k + 1 < len(lines) and lines[k + 1].lstrip().startswith("#["):
            k += 1
        ignored = "#[ignore" in "\n".join(lines[j:k + 1])
        # The first `fn` after the block is the test's own; an attribute whose
        # string spans lines can put it several lines down.
        rest = line[attr.end():] + "\n" + "\n".join(lines[i + 1:k + 12])
        fn = FN_NAME_RE.search(rest)
        if fn is None:
            continue
        out.append(("::".join(line_mods[i] + (fn.group(1),)), ignored))
    return out


def substring_selection(
    paths: list[tuple[str, bool]],
    filters: list[str],
    skips: list[str],
    ignored_run: bool,
    merged_stem: str | None,
) -> int:
    """How many of `paths` libtest runs for these filters and skips.

    `merged_stem` is the file's name when it is compiled into a merged target,
    where every test's full name starts `files::<stem>::` and the file's own
    filter word reaches libtest with that prefix in front of it.
    """
    prefix = f"files::{merged_stem}::" if merged_stem else ""
    wanted = [prefix + f for f in filters]
    n = 0
    for inner, ignored in paths:
        if ignored != ignored_run:
            continue
        full = prefix + inner
        if any(f in full for f in wanted) and not any(s in full for s in skips):
            n += 1
    return n


def macro_rules_line_spans(lines: list[str]) -> list[tuple[int, int]]:
    """The `(first, last)` line indexes of every `macro_rules!` body in `lines`.

    Brace-matched over comment-stripped text; a body that never closes runs to
    the end of the file, which keeps a test inside it uncounted rather than
    counted once.
    """
    spans: list[tuple[int, int]] = []
    i = 0
    while i < len(lines):
        if not re.search(r"\bmacro_rules!\s*\w+", lines[i]):
            i += 1
            continue
        depth = 0
        opened = False
        j = i
        while j < len(lines):
            for ch in lines[j]:
                if ch in "{([":
                    depth += 1
                    opened = True
                elif ch in "})]":
                    depth -= 1
            if opened and depth <= 0:
                break
            j += 1
        spans.append((i, min(j, len(lines) - 1)))
        i = j + 1
    return spans


def test_fn_census(path: Path) -> tuple[int, int, str | None]:
    """`(plain, ignored, why_not_countable)` for one test file.

    `why_not_countable` is None when the file's `#[test]` attributes ARE its
    tests. It names the reason otherwise:

    * ANY `#[cfg(...)]` on a test attribute block or on a top-level `mod` makes
      the test set a function of the feature flags, which this file cannot
      resolve;
    * a `#[test]` inside a `macro_rules!` body is a TEMPLATE: the tests are its
      expansions, one per invocation row, and a count of attributes counts the
      template once. Measured on `pico_upstream_api_tests_on_wz.rs`: one
      template and three written tests read as 4 where libtest runs 16, and the
      lint called a right guard stale.
    """
    # R2131 (unregistered open-debt item 402) — COMMENTS ARE NOT ATTRIBUTES.
    # `TEST_ATTR_RE` searches anywhere in a line, so a doc comment carrying
    # `#[test] #[ignore]` on one line -- the shape a file uses to SHOW the
    # attribute it is about -- was counted as a test. MEASURED on
    # `close_scope_zenohd_witness.rs`: one such line turned "1 #[ignore]d" into
    # 2 and made this lint accuse `run-ci.sh` of a stale guard, which was false.
    # Over-counting is the direction no floor can catch, and here it is not the
    # safe direction either: it publishes a wrong number as a measurement.
    lines = rust_comments.strip_comments(path.read_text()).split("\n")
    plain = ignored = 0
    conditional = any(re.match(r"\s*#\[cfg\(.*\)\]\s*$", ln) for ln in lines)
    templates = macro_rules_line_spans(lines)
    templated = False
    for i, line in enumerate(lines):
        if not TEST_ATTR_RE.search(line):
            continue
        if any(first <= i <= last for first, last in templates):
            templated = True
            continue
        # The attribute block is the run of `#[...]` lines around this one; an
        # `#[ignore]` may sit on either side of `#[test]`.
        j = i
        while j > 0 and lines[j - 1].lstrip().startswith("#["):
            j -= 1
        k = i
        while k + 1 < len(lines) and lines[k + 1].lstrip().startswith("#["):
            k += 1
        block = "\n".join(lines[j : k + 1])
        if "#[ignore" in block:
            ignored += 1
        else:
            plain += 1
    if conditional:
        return plain, ignored, "`#[cfg(...)]` makes the set feature-dependent"
    if templated:
        return plain, ignored, "a `#[test]` in a `macro_rules!` body is counted by its invocations"
    return plain, ignored, None


_BARE_FIXTURE = (
    "    (cd crates && cargo test -p p --test t -- --ignored --quiet 2>&1 \\\n"
    "        | tee /dev/stderr | grep -qE '^test result: ok\\. 3 passed') || return 1\n"
)


_BARE_PAIR_FIXTURE = (
    "    (cd crates \\\n"
    "        && cargo test -p p --test t --quiet 2>&1 \\\n"
    "        | grep -qE '^test result: ok\\. 3 passed' \\\n"
    "        && cargo test -p p --test u --quiet 2>&1 \\\n"
    "        | grep -qE '^test result: ok\\. 4 passed') || return 1\n"
)

_HELPER_FIXTURE = (
    "    echo start && \\\n"
    "        _runci_guarded_test C1 5 cargo test -p p --test t\n"
)


def _bare_parser_selftest() -> None:
    """The bare spelling's parser must still find a bare guard in a fixture.

    The real file holds none since item 858 (see the floor comment in `main`), so
    a parser that quietly stopped recognising the shape would otherwise be
    unobservable until the shape came back.
    """
    found = guard_segments(_BARE_FIXTURE)
    assert len(found) == 1 and GUARD_RE.search(found[0][1]).group(1) == "3", (
        "count-guard lint: the bare-spelling parser no longer recognises a bare "
        f"`| grep -qE '^test result: ok. N passed'` guard in its own fixture: {found}"
    )
    # Open-debt item 536: the guard sits on the fixture's SECOND physical line,
    # and two guards of one subshell must not share a line number.
    assert found[0][0] == 2, (
        "count-guard lint: the bare guard in the fixture sits on line 2, but the "
        f"parser reports line {found[0][0]}"
    )
    pair = guard_segments(_BARE_PAIR_FIXTURE)
    assert [ln for ln, _ in pair] == [3, 5], (
        "count-guard lint: two guards of one subshell must each report their own "
        f"line (3 and 5), got {[ln for ln, _ in pair]}"
    )
    helper = helper_segments(_HELPER_FIXTURE)
    assert [ln for ln, _, _ in helper] == [2], (
        "count-guard lint: a helper guard continued from an earlier line must "
        f"report its own line (2), got {[ln for ln, _, _ in helper]}"
    )


WZ_TEST_ARRAY = '"${WZ_TEST_ARGS[@]}"'
WZ_TEST_PREFIX_WORD = "${WZ_TEST_PREFIX}"


def filters_beside_the_array(text: str) -> list[str]:
    """The commands of `text` (run-ci.sh as written, NOT expanded) that expand `WZ_TEST_ARGS` and
    write a test filter of their own after it in a form that does not select that test.

    `wz_test_args C N` spells a merged file as `--test <target> files::N::`, which is a filter.
    libtest runs a test that matches ANY of its filters, so a name written after the array (on
    either side of `--`) does not narrow the file to that test: without `--exact` it widens the
    run to the whole file, and under `--exact` a bare name matches nothing, since the test's full
    name is `files::N::<test>`. The count of such a leg is then wrong or zero, and only the lane
    that runs it says so. MEASURED: hosted run 42061671165 redded Layers E5 (13 run where 4 were
    guarded) and C1cd (none selected), and 87 legs had the shape. `--exact NAME` read through
    `expand` still checks out against the file's declarations, which is why the guard check below
    cannot see it.

    Two forms select one test: the helper's third word (`wz_test_args C N <test>`), or
    `--exact "${WZ_TEST_PREFIX}<test>"`, where `--exact` makes the array's `files::N::` match
    nothing and the prefix makes the name whole. A filter beside the array passes only in the
    second form; a shell variable is a filter too.
    """
    found: list[str] = []
    for lineno, logical in logical_lines(text):
        if logical.lstrip().startswith("#") or WZ_TEST_ARRAY not in logical:
            continue
        for seg in logical.split("&&"):
            if WZ_TEST_ARRAY not in seg:
                continue
            toks = command_tokens(seg)
            if WZ_TEST_ARRAY not in toks:
                continue
            # A redirection or the `)` that closes a `$(...)` capture ends the command too
            # (`out="$(... --quiet 2>&1)"`): neither is a word libtest sees.
            for k, t in enumerate(toks):
                if ">" in t or t.startswith(")") or t.endswith(')"') or t.endswith(")"):
                    toks = toks[:k]
                    break
            if WZ_TEST_ARRAY not in toks:
                continue
            exact, filters, _ = libtest_selection(toks, toks.index(WZ_TEST_ARRAY) + 1)
            wrong = [
                f
                for f in filters
                if not (exact and f.strip('"').startswith(WZ_TEST_PREFIX_WORD))
            ]
            if wrong:
                found.append(
                    f"run-ci.sh:{lineno}: {' '.join(wrong)} written after "
                    f"`{WZ_TEST_ARRAY}`. After a merge the array ends in the filter "
                    f"`files::<file>::`, and libtest ORs its filters, so this runs the "
                    f"whole file (or, under `--exact`, nothing). Name the test as "
                    f"wz_test_args' third word, or as "
                    f'`--exact "{WZ_TEST_PREFIX_WORD}<test>"`.'
                )
    return found


def _filter_beside_array_selftest() -> None:
    """The check above must see a bare filter after `--`, a variable one, and a prefixed one
    without `--exact`, and pass both forms that select one test."""
    wrong = (
        "    wz_test_args C f\n"
        "    _runci_guarded_test L 1 cargo test -p C \\\n"
        f"        {WZ_TEST_ARRAY} -- --ignored --test-threads=1 \\\n"
        "        --exact name || return 1\n"
        f"    cargo test -p C {WZ_TEST_ARRAY} -- --exact \"$leg\" || return 1\n"
        f'    cargo test -p C {WZ_TEST_ARRAY} -- --ignored "{WZ_TEST_PREFIX_WORD}name" || return 1\n'
    )
    right = (
        "    wz_test_args C f name\n"
        "    _runci_guarded_test L 1 cargo test -p C \\\n"
        f"        {WZ_TEST_ARRAY} -- --ignored --test-threads=1 --skip other \\\n"
        "        --exact || return 1\n"
        f'    cargo test -p C {WZ_TEST_ARRAY} -- --ignored --quiet \\\n'
        f'        --exact "{WZ_TEST_PREFIX_WORD}$leg" || return 1\n'
    )
    assert len(filters_beside_the_array(wrong)) == 3 and not filters_beside_the_array(right), (
        "count-guard lint: the filter-beside-the-array check no longer reads its own fixture: "
        f"{filters_beside_the_array(wrong)} / {filters_beside_the_array(right)}"
    )


_SUBSTRING_FIXTURE = """\
#[test]
fn shm_top() {
    let open = "{";
    let _ = open;
}
mod shm_mod {
    #[test]
    fn inner() {}
    #[test] #[ignore]
    fn ignored_shm() {}
}
mod other {
    #[tokio::test]
    async fn the_shm_witness() {}
    #[test]
    fn unrelated() {}
}
"""


def _substring_selection_selftest() -> None:
    """Item 400: the module walk and libtest's matching rule over a fixture.

    The `"{"` literal is there because a walk that counted it would leave every
    later test one module too deep; the merged case is there because a filter
    that reaches libtest behind `files::<file>::` matches only from the start.
    """
    paths = test_paths_of(_SUBSTRING_FIXTURE)
    want_paths = [
        ("shm_top", False), ("shm_mod::inner", False),
        ("shm_mod::ignored_shm", True), ("other::the_shm_witness", False),
        ("other::unrelated", False),
    ]
    assert paths == want_paths, (
        f"count-guard lint: the module walk read {paths}, expected {want_paths}"
    )
    cases = [
        (["shm"], [], False, None, 3),
        (["shm"], [], True, None, 1),
        (["shm"], ["witness"], False, None, 2),
        (["shm"], [], False, "f", 2),
        (["other", "inner"], [], False, None, 3),
    ]
    for filters, skips, ignored_run, stem, want in cases:
        got = substring_selection(paths, filters, skips, ignored_run, stem)
        assert got == want, (
            f"count-guard lint: filters {filters} skip {skips} ignored={ignored_run} "
            f"merged={stem} select {got}, expected {want}"
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    _filter_beside_array_selftest()
    _substring_selection_selftest()
    beside = filters_beside_the_array(RUNCI.read_text())

    # A test file named by `wz_test_args <crate> <file>` and `"${WZ_TEST_ARGS[@]}"` is read as the
    # `--test <file>` it stands for (line numbers kept), so the guard is tied to the file in
    # whichever layout it is.
    text = retarget_test_refs.expand(RUNCI.read_text(), keep_lines=True)
    bare = guard_segments(text)
    helper = helper_segments(text)
    # ONE population, two spellings. The spelling is carried through because
    # exactly one hazard below is spelling-specific (the `grep -q` pipe race),
    # and because a report that merged the two would hide which half moved.
    segments = [
        (lineno, seg, int(GUARD_RE.search(seg).group(1)), "bare")
        for lineno, seg in bare
    ]
    segments += [(lineno, seg, want, "helper") for lineno, seg, want in helper]
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    failures: list[str] = []
    per_spelling: dict[str, list[int]] = {"bare": [0, 0], "helper": [0, 0]}

    for lineno, seg, want, spelling in segments:
        binm = TEST_BIN_RE.search(seg)
        pkgm = PKG_RE.search(seg)
        where = f"run-ci.sh:{lineno}"

        def note(bucket: list[str], line: str, _spelling: str = spelling) -> None:
            per_spelling[_spelling][0 if bucket is in_scope else 1] += 1
            bucket.append(f"[{_spelling}] {line}")

        # R2074 — a bare guard MUST select one cargo target, and this is a
        # FAILURE rather than an out-of-scope note because the hazard is not
        # about deriving the number at all.
        #
        # `grep -q` exits at its first match. If cargo goes on writing after
        # that -- which it does the moment the package has a second test target
        # -- the write hits a closed pipe and cargo dies, and `set -o pipefail`
        # turns that into a RED that names nothing. MEASURED: R2072 added a
        # second test target to `wz-ap-demo` and all six unconstrained guards in
        # Layer C1bl failed at once with rc=101 on hosted CI (run 32679319923),
        # while every command inside them passed when run on its own. It cost a
        # round to attribute.
        #
        # A guard that names `--lib`, `--test NAME`, `--bin NAME` or `--bins`
        # runs exactly one target, so its summary IS the last line and the race
        # cannot happen. That is why the other guards in this file were latent
        # and safe -- not by care, by accident of selection.
        #
        # It is spelling-specific: `_runci_guarded_test` captures into a
        # variable and greps THAT, so there is no pipe for cargo to die on. That
        # is the one asymmetry between the two spellings, and the reason the
        # helper is the recommended fix for a bare guard rather than the other
        # way round.
        if spelling == "bare" and not re.search(
            r"--lib\b|--test\s|--bin\s|--bins\b", seg
        ):
            failures.append(
                f"{where}: a bare `| grep -q` count guard that does not select "
                f"one cargo target. `grep -q` exits at its first match and "
                f"cargo then dies on the closed pipe as soon as the package "
                f"grows a second test target, which `set -o pipefail` reports "
                f"as an unattributable rc=101. Use `_runci_guarded_test` "
                f"(it captures instead of racing), or name the target."
            )
            continue

        if not binm or not pkgm:
            # Name WHICH shape it is. "not a `-p PKG --test BIN` selection" is
            # true of three different things, and a lumped reason is how 143 of
            # 235 sites become one undifferentiated number that nobody can audit.
            if re.search(r"--lib\b", seg):
                why = (
                    "selects the crate's whole `--lib` target, so the census "
                    "would have to span every module in `src/` — and each one's "
                    "`#[cfg]` gates with it"
                )
            elif not pkgm:
                why = "names no package"
            else:
                why = "names no cargo target, so the run spans every target"
            note(out_of_scope, f"{where}: {why}")
            continue
        pkg, binary = pkgm.group(1), binm.group(1)
        path = (test_sources.locate(CRATES / pkg / "tests", binary)
                or CRATES / pkg / "tests" / f"{binary}.rs")
        if not path.is_file():
            failures.append(
                f"{where}: guards `--test {binary}` in `{pkg}`, but "
                f"{path.relative_to(REPO_ROOT)} does not exist. A guard whose "
                f"binary is gone can only ever fail."
            )
            continue
        toks = command_tokens(seg)
        # Two options would make the count below wrong rather than absent, and a
        # wrong number is the one thing this file refuses to publish: a second
        # `--test` target adds a whole second file's cases to the run, and
        # `--include-ignored` unions the two censuses instead of choosing one.
        # NEITHER OCCURS TODAY (measured: 0 and 0), so this is a guard on the
        # classifier and not a coverage claim — it is here because the failure it
        # prevents is a FABRICATED one, which no later count can undo.
        unmodelled = [
            t for t in ("--include-ignored",) if t in toks
        ] + (["a second --test target"] if toks.count("--test") > 1 else [])
        if unmodelled:
            note(
                out_of_scope,
                f"{where}: {binm.group(1)} — {', '.join(unmodelled)}: this script "
                f"does not model that, and would otherwise publish a wrong count",
            )
            continue
        exact_mode, filters, has_skip = libtest_selection(
            toks, toks.index("--test") + 2
        )

        # `--exact NAME` is the OTHER derivable shape, and the more valuable of
        # the two: it names the test, so the check is "does that function still
        # exist in that file" — which is precisely the rename this whole gate
        # exists to catch. libtest's `--exact` matches the full path, so a bare
        # `fn NAME` at the file's top level or inside a module both count; the
        # search is therefore for the declaration, not for a full path match.
        if exact_mode:
            # `--exact "$leg"` is the loop shape: the name is assembled by the
            # shell, so nothing here can resolve it. That is a genuine skip, not
            # a defect — and it must be COUNTED as one, because the alternative
            # is searching the file for a literal `$leg`, finding nothing, and
            # reporting a missing test that exists.
            unresolvable = [n for n in filters if SHELL_EXPANSION_RE.search(n)]
            if unresolvable:
                note(
                    out_of_scope,
                    f"{where}: {binary} — `--exact {' '.join(unresolvable)}` names "
                    f"a shell variable, not a test",
                )
                continue
            exacts = filters
            source = path.read_text()
            missing = [
                name
                for name in exacts
                if not re.search(
                    r"\bfn\s+" + re.escape(name.rsplit("::", 1)[-1]) + r"\b", source
                )
            ]
            note(
                in_scope,
                f"{where}: {binary} --exact {' '.join(exacts)} guards {want}",
            )
            if missing:
                failures.append(
                    f"{where}: the guard names `--exact {' '.join(missing)}` in "
                    f"{path.relative_to(REPO_ROOT)}, which defines no such test "
                    f"function. libtest selects ZERO tests and still exits 0, so "
                    f"this is the silent form: the lane would pass having run "
                    f"nothing, until the count guard caught it — and only if the "
                    f"lane ran at all."
                )
            elif want != len(exacts):
                failures.append(
                    f"{where}: the guard expects `{want} passed` but names "
                    f"{len(exacts)} `--exact` test(s) in {binary}. One `--exact` "
                    f"selects one test, so the two numbers cannot both be right."
                )
            continue

        plain, ignored, why_not = test_fn_census(path)
        if why_not is not None:
            note(out_of_scope, f"{where}: {binary} — {why_not}")
            continue

        # Open-debt item 400 -- a substring filter or `--skip` on a countable
        # file is libtest's own rule applied to the names the file declares.
        if filters or has_skip:
            skips = skip_words(toks, toks.index("--test") + 2)
            # Only a plain test-path word is read: a variable or a quote is
            # assembled by the shell, and a `)` or `;` glued to a word is the
            # shell's, so the word libtest gets is not the one written here.
            assembled = [w for w in filters + skips if not PLAIN_NAME_RE.match(w)]
            if assembled:
                note(
                    out_of_scope,
                    f"{where}: {binary} — `{' '.join(assembled)}` is not a plain "
                    f"test-path word, so the set it selects is not on disk",
                )
                continue
            paths = test_paths(path)
            if len(paths) != plain + ignored:
                note(
                    out_of_scope,
                    f"{where}: {binary} — the module walk found {len(paths)} "
                    f"test(s) where the attribute census found {plain + ignored}",
                )
                continue
            merged_stem = path.stem if path.parent.name == "files" else None
            got = substring_selection(
                paths, filters, skips, "--ignored" in toks, merged_stem
            )
            sel = " ".join(filters) + (f" --skip {' '.join(skips)}" if skips else "")
            note(in_scope, f"{where}: {binary} {sel} guards {want}, file selects {got}")
            if got != want:
                failures.append(
                    f"{where}: the guard expects `{want} passed` from `--test "
                    f"{binary}` narrowed by `{sel}`, but the tests "
                    f"{path.relative_to(REPO_ROOT)} declares select {got}. A test "
                    f"whose name the filter matches joins the run silently; move "
                    f"the number in this commit, or rename the test."
                )
            continue
        got = ignored if "--ignored" in toks else plain
        kind = "#[ignore]d" if "--ignored" in toks else "plain"
        note(in_scope, f"{where}: {binary} guards {want}, file has {got} {kind}")
        if got != want:
            failures.append(
                f"{where}: the guard expects `{want} passed` from `--test {binary}` "
                f"but {path.relative_to(REPO_ROOT)} defines {got} {kind} test(s). "
                f"Either the guard's number is stale or a test was renamed out of "
                f"the run — both are silent until this lane happens to execute."
            )

    if args.verbose:
        for line in in_scope:
            print(f"  ok   {line}")
        for line in out_of_scope:
            print(f"  skip {line}")

    print(
        f"count-guard lint: {len(segments)} count guard(s) in run-ci.sh "
        f"({len(bare)} bare, {len(helper)} via _runci_guarded_test); "
        f"{len(in_scope)} statically checked, {len(out_of_scope)} out of scope"
    )
    # PER SPELLING, because the two are added and retired independently and a
    # merged total would hide one of them going to zero.
    for name in ("bare", "helper"):
        checked, skipped = per_spelling[name]
        print(f"  {name}: {checked} statically checked, {skipped} out of scope")
    # A gate that analysed nothing would exit 0 forever and read as coverage.
    # The floor is PER SPELLING for the same reason the report is: a parser that
    # stopped recognising `_runci_guarded_test` would still clear a joint floor
    # on the 26 bare guards, which is exactly the silence item 126 is about.
    #
    # R3191 (open-debt item 858) — THE BARE SPELLING NO LONGER HAS A FLOOR, AND
    # THAT IS THE POINT. Every bare `| tee | grep -qE` guard moved to
    # `_runci_guarded_test` (the shape races a SIGPIPE under pipefail), and
    # `build_evidence_lint.py` now refuses the shape outright, so the population
    # is legitimately ZERO. A floor on it would redden the repair. What the
    # floor guarded was the PARSER, not the population, so the parser is held
    # directly: `_bare_parser_selftest` reads a fixture and must find its guard,
    # which stays true whatever `run-ci.sh` holds.
    _bare_parser_selftest()
    for name in ("helper",):
        if per_spelling[name][0]:
            continue
        print(
            f"count-guard lint FAIL: NOTHING was statically checked for the "
            f"`{name}` spelling. Either that guard population changed shape or "
            f"this script's parser did — both make a green run meaningless.",
            file=sys.stderr,
        )
        return 1
    failures += beside
    if failures:
        print("count-guard lint FAIL:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

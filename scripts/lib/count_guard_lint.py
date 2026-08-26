#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
file with `-p PKG --test BIN`, that file has no `#[cfg(...)]` on any test
function or enclosing module, and the invocation applies no substring filter.
The one filtered shape that IS derivable is `--exact NAME`, which names the test
and is therefore checked directly against the file's declarations — the rename
this gate exists to catch.

Everything else is reported as OUT OF SCOPE **with the reason that applies to
it**, and counted. An unexplained skip is how a gate becomes decorative, and a
LUMPED reason is the same failure one step later: 134 of the skips are `--lib`
selections whose census would have to span every module in a crate's `src/`,
19 name no cargo target at all, 17 are feature-dependent test files, 9 name a
test through a shell variable, and 6 apply a substring filter. Those five
numbers are auditable; one total of 185 would not be.

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

import rust_comments  # noqa: E402  -- after the path insert that finds it

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


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations, keeping each logical line's FIRST line no.

    `run-ci.sh` writes its lanes as one `(cd crates && a && b && c)` subshell
    spread over many physical lines, so a physical-line scan sees a guard with
    no `cargo test` beside it and a `cargo test` with no guard.
    """
    out: list[tuple[int, str]] = []
    buf: str | None = None
    start = 0
    for i, line in enumerate(text.split("\n"), 1):
        if buf is None:
            buf, start = line, i
        else:
            buf += " " + line.strip()
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
        else:
            out.append((start, buf))
            buf = None
    if buf is not None:
        out.append((start, buf))
    return out


def guard_segments(text: str) -> list[tuple[int, str]]:
    """Every `&&`-separated segment that both runs cargo test and guards a count."""
    found = []
    for lineno, logical in logical_lines(text):
        if logical.lstrip().startswith("#"):
            continue
        for seg in logical.split("&&"):
            if CARGO_TEST_RE.search(seg) and GUARD_RE.search(seg):
                found.append((lineno, seg.strip()))
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
    for lineno, logical in logical_lines(text):
        if logical.lstrip().startswith("#"):
            continue
        m = HELPER_RE.search(logical)
        if not m:
            continue
        found.append((lineno, logical[m.start() :].strip(), int(m.group(1))))
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


def test_fn_census(path: Path) -> tuple[int, int, bool]:
    """`(plain, ignored, statically_countable)` for one test file.

    `statically_countable` is False when ANY `#[cfg(...)]` appears on a test
    attribute block or on a top-level `mod`, because then the test set is a
    function of the feature flags and this file cannot say what it is without
    resolving them.
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
    for i, line in enumerate(lines):
        if not TEST_ATTR_RE.search(line):
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
    return plain, ignored, not conditional


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    text = RUNCI.read_text()
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
        path = CRATES / pkg / "tests" / f"{binary}.rs"
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

        # Anything else narrows the set in a way this script would have to
        # re-implement libtest's substring matching to predict.
        if filters or has_skip:
            why = "--skip" if has_skip else f"the filter `{' '.join(filters)}`"
            note(
                out_of_scope,
                f"{where}: {binary} — {why} narrows the set by substring match",
            )
            continue
        plain, ignored, countable = test_fn_census(path)
        if not countable:
            note(
                out_of_scope,
                f"{where}: {binary} — `#[cfg(...)]` makes the set feature-dependent",
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
    for name in ("bare", "helper"):
        if per_spelling[name][0]:
            continue
        print(
            f"count-guard lint FAIL: NOTHING was statically checked for the "
            f"`{name}` spelling. Either that guard population changed shape or "
            f"this script's parser did — both make a green run meaningless.",
            file=sys.stderr,
        )
        return 1
    if failures:
        print("count-guard lint FAIL:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

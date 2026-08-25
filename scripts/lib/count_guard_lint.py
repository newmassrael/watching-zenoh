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

## What it deliberately does NOT try to analyse

A test count is only statically derivable when the test set does not depend on
the build configuration. So a guard is IN SCOPE only when its test file has no
`#[cfg(...)]` on any test function or enclosing module, and the invocation
applies no name filter. Everything else is reported as OUT OF SCOPE with its
reason, and counted — an unexplained skip is how a gate becomes decorative.

The in-scope set must be NON-EMPTY. A version of this that quietly analysed
nothing would exit 0 forever and read as coverage; this one fails instead.

Usage:
    python3 scripts/lib/count_guard_lint.py [--verbose]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNCI = REPO_ROOT / "scripts" / "run-ci.sh"
CRATES = REPO_ROOT / "crates"

# The guard, in every spelling `run-ci.sh` actually uses. The escaped and
# unescaped dot are BOTH present in the file, which is exactly how an earlier
# recount of this population came out wrong — it matched one spelling and
# reported the other as absent.
GUARD_RE = re.compile(r"grep -qE ['\"]\^test result: ok\\?\. (\d+) passed")
CARGO_TEST_RE = re.compile(r"\bcargo test\b")
PKG_RE = re.compile(r"-p\s+([A-Za-z0-9_-]+)")
TEST_BIN_RE = re.compile(r"--test\s+([A-Za-z0-9_]+)")
TEST_ATTR_RE = re.compile(r"#\[(?:tokio::)?test\b")


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


def test_fn_census(path: Path) -> tuple[int, int, bool]:
    """`(plain, ignored, statically_countable)` for one test file.

    `statically_countable` is False when ANY `#[cfg(...)]` appears on a test
    attribute block or on a top-level `mod`, because then the test set is a
    function of the feature flags and this file cannot say what it is without
    resolving them.
    """
    lines = path.read_text().split("\n")
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
    segments = guard_segments(text)
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    failures: list[str] = []

    for lineno, seg in segments:
        want = int(GUARD_RE.search(seg).group(1))
        binm = TEST_BIN_RE.search(seg)
        pkgm = PKG_RE.search(seg)
        where = f"run-ci.sh:{lineno}"

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
        if not re.search(r"--lib\b|--test\s|--bin\s|--bins\b", seg):
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
            out_of_scope.append(f"{where}: not a `-p PKG --test BIN` selection")
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
        after = seg.split("--test " + binary, 1)[1]
        tail = after.split("--", 1)[1] if "--" in after else ""
        tail = tail.split("2>&1", 1)[0]

        # `--exact NAME` is the OTHER derivable shape, and the more valuable of
        # the two: it names the test, so the check is "does that function still
        # exist in that file" — which is precisely the rename this whole gate
        # exists to catch. libtest's `--exact` matches the full path, so a bare
        # `fn NAME` at the file's top level or inside a module both count; the
        # search is therefore for the declaration, not for a full path match.
        exacts = re.findall(r"--exact\s+([A-Za-z0-9_:]+)", tail)
        if exacts:
            source = path.read_text()
            missing = [
                name
                for name in exacts
                if not re.search(
                    r"\bfn\s+" + re.escape(name.rsplit("::", 1)[-1]) + r"\b", source
                )
            ]
            in_scope.append(
                f"{where}: {binary} --exact {' '.join(exacts)} guards {want}"
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
        filters = [
            w
            for w in tail.split()
            if not w.startswith("-") and w not in {"|", "grep", "-qE"}
        ]
        if filters or "--skip" in tail:
            out_of_scope.append(f"{where}: {binary} — a substring filter narrows the set")
            continue
        plain, ignored, countable = test_fn_census(path)
        if not countable:
            out_of_scope.append(
                f"{where}: {binary} — `#[cfg(...)]` makes the set feature-dependent"
            )
            continue
        got = ignored if "--ignored" in seg else plain
        kind = "#[ignore]d" if "--ignored" in seg else "plain"
        in_scope.append(f"{where}: {binary} guards {want}, file has {got} {kind}")
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
        f"count-guard lint: {len(segments)} bare count guard(s) in run-ci.sh; "
        f"{len(in_scope)} statically checked, {len(out_of_scope)} out of scope"
    )
    # A gate that analysed nothing would exit 0 forever and read as coverage.
    if not in_scope:
        print(
            "count-guard lint FAIL: NOTHING was statically checked. Either the "
            "guard population changed shape or this script's parser did — both "
            "make a green run meaningless.",
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

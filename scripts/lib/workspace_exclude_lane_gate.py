#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R2328 (no register item) — a crate that Layer C1 EXCLUDES from
`cargo test --workspace` must be tested by some other lane, and nothing
required that.

The citation is `no register item` in the sense `debt_plane_census.py` uses: the
item this answers for -- unregistered open-debt item 12 -- lives in an
agent-memory register outside this repository, which has no store id for
`gate_provenance_lint.py` to resolve. The item is named in prose below.

## What item 12 asked, and what re-measuring found

Item 12: "no lint enumerates the test modules that NO `_runci_guarded_test`
filter names by name", citing two finds -- R311y780's `admin_read_permit` (only
the write twin was pinned) and R311y781's `quic` router-hat unit (found when a
refactor broke compilation).

Both instances are now pinned (`run-ci.sh` has
`C1AM admin_read_permit 1` and `C1BL router_hat_quic_listen 1`), and the item's
framing is REFUTED: "no guarded filter names it" does not imply "nothing runs
it". MEASURED -- 2766 of the 4567 `#[test]` fns under `crates/*/src/**` are
named by no guarded `--lib` filter, and that number is meaningless as a finding
because Layer C1 runs `cargo test --workspace`, which runs them. A population
that large is the signal that the criterion is wrong, the mirror of this
workspace's "a population of zero reports green".

The hazard the two finds actually shared is NARROWER, and R311y780 wrote it
down at the call site: `admin_read_permit_tests` "was running in no lane -- a
population-0 hole", because it sits behind `adminspace-read` and the workspace
build does not enable it. So the real question is "what does nothing RUN", and
it splits in two:

  * FEATURE-ONLY-REACHABLE tests. Already instrumented, by
    `nondefault-tests-gate.sh --census` (R2156, item 543), whose population is
    DERIVED -- what `cargo test -- --list` reports at `--all-features` minus
    what it reports at default features -- and every member of which must be
    run by a leg or named in `SKIPS`. It reports 11 crates and 2568 such tests
    today, all covered. Verified live rather than read: deleting the `wz-rest`
    row from its `LEGS` table makes it FAIL with
    `wz-rest has 4 test(s) only a feature build reaches`, and restoring it
    returns rc=0 byte-identically.
  * DEFAULT-REACHABLE tests. Run by Layer C1's `--workspace` -- EXCEPT for the
    members it excludes, and that is the corner nothing checked.

## The corner this closes

`layer_c1_cargo_test` excludes four members, each for a real reason (they force
`wz-session-core/no_std`, or reach a `not(transport-unicast)` API, so they
cannot coexist in one feature-unified graph), and each is tested isolated in its
own lane. MEASURED: all four are named by a `-p` test call elsewhere in
`run-ci.sh` today, so the correspondence holds.

Nothing required it. A fifth `--exclude` added for the same good reason and
without its lane leaves that crate's ENTIRE default test set running nowhere --
item 12's hazard, at whole-crate scale rather than one module, and invisible
because `--workspace` still exits 0. The exclusion is what makes it silent:
`cargo test` cannot fail on a crate it was told to skip.

## What it derives

  * THE POPULATION is every `--exclude <pkg>` inside `layer_c1_cargo_test`'s
    own body, read by brace-matching the function rather than by scanning the
    file -- an `--exclude` in some other lane is that lane's business. Zero
    excludes is a HARD FAIL, not a pass: this gate would then have no subjects,
    and a reader that lost its population must say so.
  * COVERAGE is a `cargo test` invocation naming that package with `-p`
    ANYWHERE ELSE in `run-ci.sh`, with the C1 function's own body removed from
    the search first -- otherwise the exclusion line itself could satisfy the
    requirement it creates.
  * MEMBERSHIP: every excluded name must be a real workspace member. An
    `--exclude` for a package that no longer exists is a clause with no
    subject, which this tree has twice found and struck (R311y794's `runtime/`
    SPDX rule, the atom register's residuals). It is read from
    `crates/Cargo.toml`'s `members` list.

## What it does NOT claim

That the isolated lane is EQUIVALENT to what `--workspace` would have run. It
checks that the crate is tested somewhere, not that the same tests are tested;
a lane running one filter of a crate satisfies this gate. Making that stronger
means comparing test SETS, which needs a build and belongs in a lane rather
than a lint -- and `nondefault-tests-gate.sh --census` is the shape it would
take.
"""

import argparse
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUN_CI = pathlib.Path("scripts/run-ci.sh")
MANIFEST = pathlib.Path("crates/Cargo.toml")

C1_FN = "layer_c1_cargo_test"
EXCLUDE_RE = re.compile(r"--exclude\s+([A-Za-z0-9_-]+)")
# `-p wz-session-lwip` on a `cargo test` line, or on a continuation of one.
DASH_P_RE = re.compile(r"-p\s+([A-Za-z0-9_-]+)")


def function_body(text: str, name: str) -> str | None:
    """The body of shell function `name`, by brace balance from its opener.

    Brace-matched rather than read to the next blank line: these lane functions
    contain nested `if`/`(` blocks, and a line-count heuristic would either
    truncate the excludes or run past into the next lane.
    """
    start = text.find(f"{name}() {{")
    if start == -1:
        return None
    depth = 0
    i = text.index("{", start)
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i : j + 1]
    return None


def workspace_members(root: pathlib.Path) -> set[str]:
    """The `members` list from `crates/Cargo.toml`, comment-stripped.

    Parsed rather than taken from `cargo metadata` so this stays a lint: it must
    run on a host with no toolchain, which is the same reason Layer C0's other
    readers parse instead of invoking cargo.
    """
    path = root / MANIFEST
    if not path.is_file():
        raise SystemExit(f"workspace-exclude-lane: FAIL -- {MANIFEST} is missing")
    text = path.read_text()
    m = re.search(r"^members\s*=\s*\[(.*?)^\]", text, re.S | re.M)
    if not m:
        raise SystemExit(
            f"workspace-exclude-lane: FAIL -- no `members = [...]` in {MANIFEST}; "
            "the membership axis has lost its input."
        )
    body = re.sub(r"#.*", "", m.group(1))
    return set(re.findall(r'"([^"]+)"', body))


def run(root: pathlib.Path) -> int:
    path = root / RUN_CI
    if not path.is_file():
        raise SystemExit(f"workspace-exclude-lane: FAIL -- {RUN_CI} is missing")
    text = path.read_text()

    body = function_body(text, C1_FN)
    if body is None:
        raise SystemExit(
            f"workspace-exclude-lane: FAIL -- no `{C1_FN}()` in {RUN_CI}. That "
            "function IS this gate's population; without it there is nothing to "
            "check and a pass would be a lie."
        )

    excludes: list[str] = []
    for name in EXCLUDE_RE.findall(body):
        if name not in excludes:
            excludes.append(name)
    if not excludes:
        raise SystemExit(
            f"workspace-exclude-lane: FAIL -- `{C1_FN}` excludes NOTHING, so this "
            "gate has no subjects. That is either a reader that stopped matching "
            "`--exclude`, or a genuinely un-excluded workspace test — in which "
            "case delete this gate rather than let it report green forever."
        )

    # The rest of the file, so the exclusion lines cannot satisfy themselves.
    elsewhere = text.replace(body, "")
    members = workspace_members(root)

    fail: list[str] = []
    for pkg in excludes:
        covered = pkg in DASH_P_RE.findall(elsewhere)
        member = pkg in members
        if not member:
            fail.append(
                f"  workspace-exclude-lane: NOT-A-MEMBER  {pkg} — `{C1_FN}` excludes "
                f"it but {MANIFEST}'s `members` does not list it.\n"
                f"    An `--exclude` for a package that does not exist is a clause "
                f"with no subject: it excludes nothing and quietly suggests the "
                f"crate is handled. Delete the exclude, or fix the name."
            )
            continue
        if not covered:
            fail.append(
                f"  workspace-exclude-lane: UNRUN        {pkg} — excluded from "
                f"`cargo test --workspace` and named by NO `-p` test call anywhere "
                f"else in {RUN_CI}.\n"
                f"    Its ENTIRE default test set therefore runs nowhere, and "
                f"nothing reds: `cargo test` cannot fail on a crate it was told to "
                f"skip (R311y780 paid for this at one-module scale — "
                f"`admin_read_permit_tests` \"was running in no lane\").\n"
                f"    Add an isolated lane (`cargo test -p {pkg} …`), the way the "
                f"other exclusions each have one."
            )
        else:
            print(f"  workspace-exclude-lane: RUN          {pkg}")

    print(
        f"  workspace-exclude-lane: {len(excludes)} member(s) excluded from "
        f"`{C1_FN}`, each checked for an isolated `-p` run and for membership"
    )
    print(
        "  workspace-exclude-lane: NOT covered here -- that the isolated lane runs "
        "the SAME tests `--workspace` would have. This checks the crate is tested "
        "somewhere, not that the set matches; comparing sets needs a build "
        "(nondefault-tests-gate.sh --census is that shape)"
    )
    if fail:
        print()
        for line in fail:
            print(line)
        return 1
    return 0


def selftest() -> int:
    """Both defect shapes and both population-zero refusals, against fixtures.

    The UNRUN fixture is the shape the tree is one edit away from: a fifth
    exclusion added with a real reason and no lane. A fixture built from the
    covered shape would pass against a reader that had stopped checking.
    """
    failures: list[str] = []

    def drive(runci: str, members: str = '"a"\n    "b"\n    "c"\n') -> int:
        with tempfile.TemporaryDirectory() as d:
            tmp = pathlib.Path(d)
            (tmp / "scripts").mkdir(parents=True)
            (tmp / "crates").mkdir(parents=True)
            (tmp / RUN_CI).write_text(runci)
            (tmp / MANIFEST).write_text(f"[workspace]\nmembers = [\n    {members}]\n")
            try:
                return run(tmp)
            except SystemExit:
                return 2

    covered = (
        "layer_c1_cargo_test() {\n"
        "    (cd crates && cargo test --workspace \\\n"
        "        --exclude a \\\n"
        "        --exclude b --quiet)\n"
        "}\n"
        "layer_x() {\n"
        "    cargo test -p a --quiet || return 1\n"
        "    cargo test -p b --quiet || return 1\n"
        "}\n"
    )
    if drive(covered) != 0:
        failures.append("a fully covered fixture was reported as failing")

    # A fifth exclusion with no lane.
    unrun = covered.replace("--exclude b --quiet", "--exclude b \\\n        --exclude c --quiet")
    if drive(unrun) != 1:
        failures.append("an excluded crate with no isolated `-p` run was not caught")

    # The exclusion line must not satisfy itself: `-p` appearing ONLY inside the
    # C1 body is not coverage.
    self_satisfying = (
        "layer_c1_cargo_test() {\n"
        "    (cd crates && cargo test --workspace --exclude a --quiet)\n"
        "    cargo test -p a --quiet\n"
        "}\n"
    )
    if drive(self_satisfying) != 1:
        failures.append("a `-p` inside the C1 body was accepted as an isolated lane")

    # An exclude for a non-member.
    ghost = covered.replace("--exclude a", "--exclude ghost")
    if drive(ghost) != 1:
        failures.append("an `--exclude` for a non-member was not caught")

    # POPULATION ZERO, both ways — they exit rather than return.
    if drive("layer_c1_cargo_test() {\n    cargo test --workspace --quiet\n}\n") != 2:
        failures.append("a C1 function excluding nothing did not hard-fail")
    if drive("layer_other() {\n    cargo test --workspace --exclude a\n}\n") != 2:
        failures.append("an absent C1 function did not hard-fail")

    if failures:
        print("  workspace-exclude-lane: SELFTEST FAILED")
        for f in failures:
            print(f"    - {f}")
        return 1
    print(
        "  workspace-exclude-lane: selftest passed "
        "(unrun, self-satisfying, non-member, 2 population-zero, 1 clean)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="workspace_exclude_lane_gate.py",
        description=(
            "Every member Layer C1 excludes from `cargo test --workspace` must be "
            "tested by another lane, and must actually be a member."
        ),
    )
    ap.add_argument("--check", action="store_true", help="read the real tree (default)")
    ap.add_argument("--selftest", action="store_true", help="drive the shapes against fixtures")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())

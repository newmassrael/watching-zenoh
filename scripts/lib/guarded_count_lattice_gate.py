#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R2327 (no register item) — several `_runci_guarded_test` calls run the SAME
cargo-test filter under DIFFERENT feature sets, and until this round nothing
required their asserted counts to be consistent with each other.

The citation is `no register item` in the sense `debt_plane_census.py` uses: the
item this closes -- unregistered open-debt item 11 -- lives in an agent-memory
register outside this repository, which has no store id for
`gate_provenance_lint.py` to resolve. The item is named in prose below.

## The defect, and the two times it was paid for

`_runci_guarded_test <label> <count> cargo test …` asserts an EXACT
`N passed`, because `cargo test <filter>` exits 0 when the filter matches
nothing. That guard is per-call. When one test module is selected by several
calls under different feature unions, adding a test to it moves several of those
numbers at once, and nothing said which.

MEASURED history, from the item: R311y772 raised the three `C1q` counts for
`--lib multicast_glue` and left the fourth site (`C1AX`, the same filter with
`routing-namespace` added) behind; R311y775 caught it and wrote a PROSE
prescription; R311y782 then repeated the identical miss one round later, and
R311y783 caught that one on hosted CI. A prose prescription failed on its very
next outing, which is this workspace's standing argument for gates over notes.

## What item 11 prescribed, and why this gate does something else

The item asked for a lint requiring the group's members to move BY THE SAME
DELTA, hedging that "both cases were +4, so same-delta is the first thing to
try -- but two points are not a design". Re-measured, that hedge was right and
the prescription is REFUTED: it cannot be the rule.

A test added to the module is either unconditional, in which case every site
moves, or `cfg`-gated on a feature, in which case ONLY the sites carrying that
feature move -- legitimately, by design, which is the whole reason these groups
have different numbers in the first place. A same-delta rule reds that, so it
would have to be suppressed on the ordinary case, and a rule suppressed on the
ordinary case is not a gate. "Did they ALL move" fails for the identical
reason.

What IS derivable is the FEATURE LATTICE. Enabling a feature can only compile
tests IN, never out, so within one group:

  MONOTONE  a strict feature SUPERSET must not assert a LOWER count than a
            subset. 47 comparable pairs today.
  AGREE     two calls with the SAME feature set (and the same
            `--no-default-features` posture) must assert the SAME count.
            3 pairs today.

## Why this is not `count_guard_lint.py` again

That lint (R311y569, and hook gate 4b since R2167) checks a guard's number
against the tests the SOURCE defines, and its own summary says what it cannot
reach: of 305 count guards, 111 are statically checked and **194 are out of
scope** -- almost all with the reason `#[cfg(...)] makes the set
feature-dependent`. Its comment in `.githooks/pre-push` calls that list "honest
and also the hole".

The lattice reaches the hole, because it never derives a count at all -- it
relates the hand-written numbers TO EACH OTHER, and feature-dependence is the
property that makes them relatable. MEASURED against that lint's own verbose
output: of the 47 comparable pairs here, **45 have BOTH sites out of its
scope**, and of the 56 distinct sites the lattice constrains, **53 are out of
its scope**. So the two instruments are near-disjoint by construction rather
than by hope, and neither subsumes the other.

Both axes are purely static -- no base revision, no build -- and MONOTONE
catches the leak that was actually paid for twice. Checked against the real numbers:
`C1q` base is `{transport-multicast}` at 23 and `C1AX` is
`{transport-multicast, routing-namespace}` at 26, a strict superset, so the
invariant requires 23 <= 26. Before R311y772 those were 19 and 22; R311y772
raised the subset to 23 and left the superset at 22, and 23 > 22 is exactly a
MONOTONE violation. The check that the item could not formulate is the one its
own history demands.

## What this gate does NOT catch, stated rather than hidden

The mirror case. If a round adds a test active under the BASE features, bumps
the superset sites and forgets the subset one, the subset simply stays lower --
which is legal, so nothing fires. That direction is not reachable by any static
rule over these numbers: a lower subset count is indistinguishable from a
correctly-lower subset count. Catching it needs the counts a real run produces,
which is Layer C1's job and not a lint's.

So this closes the half the history actually paid for and says which half it
leaves. It is not a claim that a guarded group can no longer drift.

## The derivation's own hazards, all three of which bit while writing this

Each of these produced a WRONG ANSWER from this round's own instrument before
being fixed, which is why they are written down rather than merely handled.
None of them announced itself: every one degraded into a plausible number.

  * CONTINUATIONS. Most of these calls put the `cargo test` on the next
    physical line after a `\`. A per-line reader finds 65 of them and misses
    the rest -- including `C1AX multicast_glue`, the one site the whole item is
    about. Lines are joined before parsing.
  * THE SHELL TAIL. Every call ends `|| return 1`. A naive "last positional
    argument is the filter" read takes `1` from that tail, which collapsed 161
    groups into a handful of nonsense buckets of 55 and 71 members -- and
    reported a green verdict over them.
  * THE FILTER AFTER `--`. Seven calls pass the test name to libtest rather
    than to cargo (`-- --ignored --quiet --test-threads=1 --exact "$leg"`), so
    a parser that stops at `--` returns `None` for their filter. That does not
    look like a failure; it looks like AGREEMENT. It grouped four DIFFERENT
    single-test selections under one key and had the gate assert that unrelated
    commands were identical -- 7 "equal-feature pairs" where the truthful
    reading is 3. A discriminator that goes missing makes things look MORE
    consistent, never less, which is why this axis needed the count audited by
    hand and not just its exit status read.

## A population of zero is a HARD FAIL on both axes

A tree with no comparable pairs would report green forever. Renaming the
helper, changing the call shape, or dropping every multi-site group leaves this
gate with no subjects, and it says so instead of passing.
"""

import argparse
import collections
import itertools
import pathlib
import re
import sys
import typing

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUN_CI = pathlib.Path("scripts/run-ci.sh")

# `_runci_guarded_test C1q 23 cargo test …` and
# `_runci_guarded_test "C1AX multicast_glue 26" 26 \` (label quoted, command on
# the joined continuation).
CALL_RE = re.compile(r'_runci_guarded_test\s+(?:"([^"]+)"|(\S+))\s+(\+|[0-9]+)\s+(.*)$')

# Where the cargo invocation ends and the shell resumes. See the module doc:
# taking the last positional without this reads `1` out of `|| return 1`.
SHELL_TAIL = ("||", "&&", ";")


class Call(typing.NamedTuple):
    line: int
    label: str
    expect: str
    package: str | None
    target: str | None
    filter: str | None
    features: frozenset[str]
    no_default: bool
    # The whole invocation, whitespace-collapsed, INCLUDING any environment
    # prefix (`WZ_ZENOH_C_PREFIX="$shm" _runci_guarded_test …`). The AGREE axis
    # keys on this rather than on the fields above, deliberately: its claim is
    # that two calls run the identical command, and only the command text can
    # support that. A key rebuilt from parsed fields asserts identity on the
    # axes the parser happens to model, and this round measured what that costs
    # — the env prefix alone distinguishes two C1cc/C1ce pairs whose parsed
    # fields are indistinguishable.
    normalized: str

    def where(self) -> str:
        return f"{RUN_CI}:{self.line} [{self.label}]"


def join_continuations(text: str) -> list[tuple[int, str]]:
    """Physical lines folded on trailing `\\`, each keeping its FIRST line number.

    The first number rather than the last so a diagnostic points at the
    `_runci_guarded_test` the reader will search for, not at the `cargo test`
    argument line underneath it.
    """
    lines = text.splitlines()
    out: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        start, buf = i + 1, lines[i]
        while buf.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            buf = buf.rstrip()[:-1] + " " + lines[i].strip()
        out.append((start, buf))
        i += 1
    return out


def cut_shell_tail(cmd: str) -> str:
    for sep in SHELL_TAIL:
        k = cmd.find(sep)
        if k != -1:
            cmd = cmd[:k]
    return cmd.strip()


def parse_cargo(cmd: str) -> tuple[str | None, str | None, str | None, frozenset[str], bool]:
    """`-p`, the target selector, the test-name filter, the features, the posture.

    The filter is the first bare positional, and it is looked for on BOTH sides
    of `--`. That is not defensive: MEASURED on this tree, seven guarded calls
    pass it to libtest instead of to cargo —

        cargo test -p wz-integration-tests --test zenoh_c_abi_symbol_census \
            -- --ignored --quiet --test-threads=1 --exact "$leg"

    — and a reader that stops at `--` returns `None` for all of them. This
    round's own first version did stop there, which grouped several DIFFERENT
    single-test selections as one filter and made the AGREE axis claim that
    unrelated commands were identical. A dropped discriminator does not read as
    an error; it reads as agreement.

    `--test-threads=1` is why the flag skip has to handle `--flag=value` as one
    token, and `--exact` is why it cannot assume every long flag takes a
    separate value argument.
    """
    toks = cmd.split()
    package = target = test_filter = None
    features: set[str] = set()
    no_default = False
    # Flags that consume the FOLLOWING token as their value. Everything else
    # beginning with `-` stands alone (or carries its value after `=`).
    takes_value = {"-p", "--package", "--features", "--test", "--bench", "--example", "--bin"}
    j = 0
    while j < len(toks):
        tok = toks[j]
        nxt = toks[j + 1] if j + 1 < len(toks) else None
        if tok in ("cargo", "test", "--"):
            j += 1
        elif tok in ("-p", "--package"):
            package = nxt
            j += 2
        elif tok == "--features":
            if nxt:
                features |= {f for f in nxt.split(",") if f}
            j += 2
        elif tok.startswith("--features="):
            features |= {f for f in tok.split("=", 1)[1].split(",") if f}
            j += 1
        elif tok == "--no-default-features":
            no_default = True
            j += 1
        elif tok == "--test":
            target = "--test " + (nxt or "?")
            j += 2
        elif tok == "--lib":
            target = "--lib"
            j += 1
        elif tok in takes_value:
            j += 2
        elif tok.startswith("-"):
            j += 1
        else:
            if test_filter is None:
                test_filter = tok
            j += 1
    return package, target, test_filter, frozenset(features), no_default


def read_calls(root: pathlib.Path) -> list[Call]:
    path = root / RUN_CI
    if not path.is_file():
        raise SystemExit(f"guarded-count-lattice: FAIL -- {RUN_CI} is missing")
    calls: list[Call] = []
    for line_no, line in join_continuations(path.read_text()):
        stripped = line.lstrip()
        # The helper's own definition, and prose about it, are not call sites.
        if stripped.startswith("#") or "_runci_guarded_test()" in line:
            continue
        match = CALL_RE.search(line)
        if not match:
            continue
        cmd = cut_shell_tail(match.group(4))
        if not cmd.startswith("cargo test"):
            continue
        package, target, test_filter, features, no_default = parse_cargo(cmd)
        # The env prefix sits BEFORE `_runci_guarded_test`, so it is on the
        # line but outside the match. Take it from the line's own head.
        prefix = line[: line.index("_runci_guarded_test")].strip()
        calls.append(
            Call(
                line=line_no,
                label=match.group(1) or match.group(2),
                expect=match.group(3),
                package=package,
                target=target,
                filter=test_filter,
                features=features,
                no_default=no_default,
                normalized=" ".join(f"{prefix} {cmd}".split()),
            )
        )
    return calls


def group(calls: list[Call]) -> dict[tuple, list[Call]]:
    """By (package, target, filter) — what SELECTS the tests, features aside.

    Features are deliberately NOT part of the key: varying them is the whole
    point, and folding them in would put every call in its own group and leave
    nothing to compare.
    """
    out: dict[tuple, list[Call]] = collections.defaultdict(list)
    for call in calls:
        out[(call.package, call.target, call.filter)].append(call)
    return out


def run(root: pathlib.Path) -> int:
    calls = read_calls(root)
    groups = {k: v for k, v in group(calls).items() if len(v) > 1}

    monotone_pairs = 0
    agree_pairs = 0
    fail: list[str] = []

    for key, members in sorted(groups.items(), key=lambda kv: str(kv[0])):
        numbered = [c for c in members if c.expect != "+"]
        for left, right in itertools.permutations(numbered, 2):
            if left.no_default != right.no_default:
                continue
            if not left.features < right.features:
                continue
            monotone_pairs += 1
            if int(left.expect) > int(right.expect):
                fail.append(
                    f"  guarded-count-lattice: MONOTONE  {key[0]} {key[1]} "
                    f"filter={key[2]!r}\n"
                    f"    subset   {left.where()} features={sorted(left.features)} "
                    f"asserts {left.expect}\n"
                    f"    superset {right.where()} features={sorted(right.features)} "
                    f"asserts {right.expect}\n"
                    f"    Enabling a feature can only compile tests IN, so the superset "
                    f"cannot run FEWER. Either a test was added and only some sites in "
                    f"this group were bumped (R311y772 and R311y782 each did exactly "
                    f"that, one round apart), or one of the two numbers is simply wrong.\n"
                    f"    Re-measure both, do not average them: run each command and "
                    f"read its `test result: ok. N passed`."
                )
    # AGREE keys on what SELECTS the tests — package, target, filter, features,
    # posture — and deliberately NOT on the environment prefix. An env var
    # cannot change which cases libtest picks, so two calls agreeing on all of
    # the above must assert the same count even when one of them is run against
    # a different oracle.
    #
    # That exclusion is the difference between an axis and nothing at all, and
    # it was MEASURED both ways. Keying on the byte-identical command text
    # (prefix included) yields ZERO pairs on this tree — no two guarded calls
    # are textually the same. Excluding the prefix yields THREE, and all three
    # are the same C1cc/C1ce pattern: one test binary run once with the default
    # zenoh-c and once under `WZ_ZENOH_C_PREFIX="$shm"`. Both arms select one
    # case and both assert 1. A byte-identical axis would have been a rule
    # whose claimed failure cannot occur, which this workspace deletes rather
    # than keeps behind a zero-population guard.
    by_selection: dict[tuple, list[Call]] = collections.defaultdict(list)
    for call in calls:
        if call.expect != "+":
            key = (call.package, call.target, call.filter, call.features, call.no_default)
            by_selection[key].append(call)
    for key, members in sorted(by_selection.items(), key=lambda kv: str(kv[0])):
        if len(members) < 2:
            continue
        for left, right in itertools.combinations(members, 2):
            agree_pairs += 1
            if int(left.expect) != int(right.expect):
                fail.append(
                    f"  guarded-count-lattice: AGREE     {key[0]} {key[1]} "
                    f"filter={key[2]!r} features={sorted(key[3])}\n"
                    f"    {left.where()} asserts {left.expect}\n"
                    f"      {left.normalized}\n"
                    f"    {right.where()} asserts {right.expect}\n"
                    f"      {right.normalized}\n"
                    f"    These select the SAME cases — same package, target, filter, "
                    f"features and default-features posture. Only the environment can "
                    f"differ between them, and an env var cannot change what libtest "
                    f"picks, so one of the two numbers is stale."
                )

    if monotone_pairs == 0:
        raise SystemExit(
            "guarded-count-lattice: FAIL -- derived ZERO comparable feature-subset "
            f"pairs from {len(calls)} guarded call(s) in {RUN_CI}. A gate that found "
            "no subjects must not report a pass; the reader has lost its population "
            "(a renamed helper, a changed call shape, or every multi-site group gone)."
        )
    if agree_pairs == 0:
        raise SystemExit(
            "guarded-count-lattice: FAIL -- derived ZERO equal-feature pairs. This axis "
            "had 3 today; its population reaching zero means the reader stopped "
            "matching feature sets, not that the tree stopped having duplicates."
        )

    print(
        f"  guarded-count-lattice: {len(calls)} guarded call(s), {len(groups)} group(s) "
        f"with 2+ sites; {monotone_pairs} subset pair(s) monotone, "
        f"{agree_pairs} equal-feature pair(s) agree"
    )
    print(
        "  guarded-count-lattice: NOT covered here -- a test added under the BASE "
        "features whose SUBSET site is forgotten leaves that site legally lower, so "
        "no static rule over these numbers can see it; Layer C1's real run is what does"
    )
    if fail:
        print()
        for line in fail:
            print(line)
        return 1
    return 0


def selftest() -> int:
    """Drive both axes against the shape the tree actually held, in both directions.

    The MONOTONE fixture is not invented: it is R311y772's miss, with the real
    filter, the real feature sets and the real numbers from before and after
    that round (`{transport-multicast}` 19 -> 23, superset
    `{transport-multicast, routing-namespace}` left at 22). A fixture built from
    the FIXED shape would pass against a reader that had stopped comparing.
    """
    failures: list[str] = []

    def drive(body: str) -> int:
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            tmp = pathlib.Path(d)
            (tmp / "scripts").mkdir(parents=True)
            (tmp / RUN_CI).write_text(body)
            try:
                return run(tmp)
            except SystemExit:
                return 2

    # `%` substitution, not `str.format`: the fixture is shell and carries
    # literal braces, which `format` reads as field names.
    base_tpl = (
        "layer_c1q() {\n"
        "    _runci_guarded_test C1q SUBN cargo test -p wz-runtime-tokio "
        "--features transport-multicast --lib multicast_glue --quiet \\\n"
        "        || return 1\n"
        '    _runci_guarded_test "C1AX multicast_glue" SUPN \\\n'
        "        cargo test -p wz-runtime-tokio "
        "--features transport-multicast,routing-namespace --lib multicast_glue "
        "--quiet || return 1\n"
        "    _runci_guarded_test C1z 4 cargo test -p wz-session-core "
        "--features alloc --lib storage --quiet || return 1\n"
        "    _runci_guarded_test C1z2 4 cargo test -p wz-session-core "
        "--features alloc --lib storage --quiet || return 1\n"
        "}\n"
    )

    def base(sub: str, sup: str) -> str:
        return base_tpl.replace("SUBN", sub).replace("SUPN", sup)

    # The tree BEFORE R311y772: subset 19, superset 22. Consistent.
    if drive(base("19", "22")) != 0:
        failures.append("the pre-R311y772 numbers were reported as inconsistent")
    # R311y772's actual miss: subset bumped to 23, superset left at 22.
    if drive(base("23", "22")) != 1:
        failures.append("R311y772's real miss (subset 23 > superset 22) was not caught")
    # The repair: both moved.
    if drive(base("23", "26")) != 0:
        failures.append("the repaired shape was reported as failing")

    # AGREE: the two identical C1z calls disagree.
    disagree = base("23", "26").replace(
        "_runci_guarded_test C1z2 4", "_runci_guarded_test C1z2 5"
    )
    if drive(disagree) != 1:
        failures.append("two identical commands asserting different counts were not caught")

    # The derivation's own two hazards, each as a fixture that must still be READ.
    # A continuation-only call (the C1AX shape) is already in `base`; a reader
    # that did not join lines would drop it and lose the monotone pair, which
    # this asserts by requiring the miss above to be CAUGHT rather than skipped.
    # The shell tail: a call whose filter would be `1` if the tail were kept.
    #
    # These fixtures name REAL packages and REAL features, and not for realism:
    # Layer C0's `prose-features` gate scans every `--features` literal in
    # every tracked file — this one included — and refuses a flag whose package
    # it cannot resolve. A synthetic `-p p --features x` is UNCLASSIFIED there,
    # which that gate reds rather than passes, and it redded this file on its
    # first Layer C0 run. A fixture is a tracked file like any other.
    tail_only = (
        "f() {\n"
        "    _runci_guarded_test A 3 cargo test -p wz-runtime-tokio "
        "--features transport-multicast --lib multicast_glue --quiet || return 1\n"
        "    _runci_guarded_test B 2 cargo test -p wz-runtime-tokio "
        "--features transport-multicast,reassembly --lib multicast_glue --quiet || return 1\n"
        "    _runci_guarded_test C 7 cargo test -p wz-runtime-tokio "
        "--features transport-multicast --lib session_glue --quiet || return 1\n"
        "    _runci_guarded_test D 7 cargo test -p wz-runtime-tokio "
        "--features transport-multicast --lib session_glue --quiet || return 1\n"
        "}\n"
    )
    if drive(tail_only) != 1:
        failures.append("a monotone violation was missed, so the shell tail is being parsed")

    # POPULATION ZERO, both axes — they exit rather than return, which is the
    # arm a selftest most easily leaves untested.
    if drive("f() { echo nothing; }\n") != 2:
        failures.append("a file with no guarded calls did not hard-fail")
    if drive(
        "f() {\n"
        "    _runci_guarded_test A 3 cargo test -p wz-runtime-tokio "
        "--features transport-multicast --lib multicast_glue --quiet || return 1\n"
        "    _runci_guarded_test B 4 cargo test -p wz-runtime-tokio "
        "--features transport-multicast,reassembly --lib multicast_glue --quiet || return 1\n"
        "}\n"
    ) != 2:
        failures.append("a tree with monotone pairs but NO equal-feature pair did not hard-fail")

    if failures:
        print("  guarded-count-lattice: SELFTEST FAILED")
        for f in failures:
            print(f"    - {f}")
        return 1
    print(
        "  guarded-count-lattice: selftest passed "
        "(R311y772's real miss caught, 2 clean shapes, AGREE, shell-tail, 2 population-zero)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="guarded_count_lattice_gate.py",
        description=(
            "Guarded cargo-test counts sharing one filter must be consistent with the "
            "feature lattice: a superset never asserts fewer, equal features agree."
        ),
    )
    ap.add_argument("--check", action="store_true", help="read the real tree (default)")
    ap.add_argument("--selftest", action="store_true", help="drive both axes against fixtures")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())

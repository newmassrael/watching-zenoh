#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2222 (no register item) -- which `wz-integration-tests` fixtures are run by
NO lane at all.

The citation is `no register item` for the reason its two neighbours give for
theirs: the items this answers -- unregistered open-debt items 568 and 569, the
consuming surface's 2026-08-31 claims -- live in the agent-memory register,
which has no store id for `gate_provenance_lint.py` to resolve.

## The class, measured four times

A fixture in this crate reaches a runner by exactly one of two routes. Layer E
sweeps the whole crate with `cargo test -p wz-integration-tests -- --ignored`
and a list of `--skip` tokens; a test whose fn name carries one of those tokens
is skipped there, and then some other lane has to name its file with
`--test <stem>`. Nothing has ever checked that the second half happened.

It has not happened four times, and each was found by hand, late:

  * R311y528 -- a drop-in leg "written, registered, and NOT RUN", found by
    reading a lane log and seeing `11 passed; 1 filtered out` in a twelve-leg
    file.
  * R311y842 -- `zenoh_config_emit_zenohd_interop`, which "had never been
    registered ANYWHERE" and so "has run on no hosted CI since the round that
    wrote it".
  * R2221 -- both fixtures it wrote for items 568 and 569, each naming Layer Z
    in its `#[ignore]` reason and each carrying the `zenohd` token in every fn
    name. The round measured the legs on a developer's machine, and no lane
    would have measured them again.
  * the same run, by this gate's first execution --
    `wz_adminspace_query_zenohd_interop` and
    `wz_querier_all_complete_vs_zenohd_storage`, neither of which any round had
    noticed.

The nearest existing check, R311y838's naming obligation in Layer C0, asks the
mirror-image question: a test that declares a non-E owner must carry a token so
Layer E does NOT run it. That closes the direction where a lane's fixture is run
by the wrong lane. This one closes the direction where it is run by none.

## Why the question is not asked of the prose

The obvious reading is the `#[ignore]` reason: it usually names an owner, in
prose, by a convention. Re-measured R2280 with the reason reader that now owns
that string (`crossimpl_corpus.ignore_reason_at`, which unlike the line-oriented
one this paragraph was first written against can read a `\\`-continued
attribute): 449 `#[ignore]` attributes carry 235 distinct reasons; 402 mention a
`Layer` and only 229 of those match R311y838's `Layer X runs via` spelling. So a
wider `Layer <token>` match would invent an owner for 173 tests out of sentences
that mention a lane without claiming one -- it reads `Layer E` off
`static_scout_dead_only_list_is_no_reachable`, whose reason says it "rides Layer
E with the sibling whose precondition it guards" and then explains that "Layer
C0 scopes the #[ignore] discipline to the file". A matcher loose enough to see
every ownership spelling is loose enough to invent owners, and this tree's
standing finding is that such a matcher yields a confidently wrong number.

(The four figures above were 362 / 183 / 157 / 114 when this was written, all
counted line-wise; every one of them was stale by R2280, which is why they are
now re-derivable by command -- `crossimpl_corpus.py --count-reasons` -- rather
than only assertable.)

So no reason string is read here. Reachability is derived from structure alone:
the fn names, the `#[ignore]` attributes, the token list scraped out of Layer
E's own sweep, and the `--test` names in run-ci.sh. Prose cannot make a fixture
run and does not get a vote in whether one does.

## What it checks

For every fixture with at least one test fn, one of these must hold:

  1. it has a test fn that is NOT `#[ignore]`d -- an ordinary
     `cargo test -p wz-integration-tests` runs that one;
  2. it has an `#[ignore]`d test fn whose name carries none of Layer E's skip
     tokens -- Layer E's `--ignored` sweep runs that one;
  3. run-ci.sh names its file stem after `--test`, on a line that is not a
     comment -- some lane runs the file.

Anything else is UNREACHABLE and RED. There is no exemption list: a fixture that
should genuinely never run has an answer already, which is to not be a fixture.

FAIL (exit 2, distinct from RED) when the gate cannot read its own inputs -- no
fixture carries a test fn, Layer E's sweep is not where the token list is
scraped from, or that scrape yields nothing. A gate that cannot see its subject
must not report green over it.
"""

import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]

TESTS_REL = "crates/wz-integration-tests/tests"
RUNCI_REL = "scripts/run-ci.sh"

# The lane whose sweep runs a fixture without naming it, and the command line
# the token list is scraped out of. Both are asserted rather than assumed: if
# either moves, this gate FAILs instead of grading against a stale shape.
SWEEP_FN = "layer_e_ap_demo_round_trip() {"
SWEEP_CMD = "cargo test -p wz-integration-tests --quiet -- --ignored"

TEST_ATTR = re.compile(r"#\[(?:tokio::)?test\b")
IGNORE_ATTR = re.compile(r"#\[ignore\b")
FN_NAME = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")
# R2221 found this the expensive way in run-ci.sh's own scanner: a module doc
# that MENTIONS `#[test]` armed the attribute loop, and the next ordinary helper
# fn was reported as a test. A phantom fn is worse here than there -- an
# untokened one would satisfy route 2 and report an unreachable fixture green.
RUST_COMMENT = re.compile(r"^\s*(?://|/\*|\*)")
BASH_COMMENT = re.compile(r"^\s*#")
NAMED_TEST = re.compile(r"--test\s+([A-Za-z0-9_]+)")
SKIP_TOKEN = re.compile(r"--skip\s+([A-Za-z0-9_]+)")


class Unreadable(Exception):
    """The gate cannot see its subject; exit 2, never 0."""


def skip_tokens(runci_text):
    """Layer E's own `--skip` list, scraped from Layer E's own invocation.

    Scoped to the function rather than the file for the reason R311y838
    recorded when it made the same scrape: a whole-file search finds this
    check's own prose first and reads English words as tokens.
    """
    at = runci_text.find("\n" + SWEEP_FN)
    if at < 0:
        raise Unreadable(
            "{} was not found in run-ci.sh, so the token list Layer E sweeps "
            "with cannot be read".format(SWEEP_FN.rstrip("() {"))
        )
    body = runci_text[at:runci_text.find("\n}", at)]
    if SWEEP_CMD not in body:
        raise Unreadable(
            "Layer E no longer runs `{}`, so what its sweep reaches is not what "
            "this gate grades against".format(SWEEP_CMD)
        )
    tokens = sorted(set(SKIP_TOKEN.findall(body)))
    if not tokens:
        raise Unreadable("Layer E's sweep names no --skip token")
    return tokens


def named_by_a_lane(runci_text):
    """File stems some lane runs by name.

    Comment lines are dropped first. A stem discussed in the prose beside a
    lane is not run by it, and a reader that counts the mention would report
    exactly the fixtures this gate exists to find as covered.
    """
    live = "\n".join(
        line for line in runci_text.splitlines() if not BASH_COMMENT.match(line)
    )
    return set(NAMED_TEST.findall(live))


def test_fns(source):
    """`(fn name, is_ignored)` for every test fn in one fixture."""
    out = []
    armed = False
    ignored = False
    for line in source.splitlines():
        if RUST_COMMENT.match(line):
            continue
        if TEST_ATTR.search(line):
            armed = True
            continue
        if IGNORE_ATTR.search(line):
            if armed:
                ignored = True
            continue
        m = FN_NAME.match(line)
        if armed and m:
            out.append((m.group(1), ignored))
            armed = False
            ignored = False
    return out


def unreachable(root):
    """Fixtures no route runs, plus the population they were drawn from."""
    runci = (root / RUNCI_REL).read_text(encoding="utf-8")
    tokens = skip_tokens(runci)
    named = named_by_a_lane(runci)

    population = []
    dead = []
    for path in sorted((root / TESTS_REL).glob("*.rs")):
        fns = test_fns(path.read_text(encoding="utf-8"))
        if not fns:
            continue
        population.append(path.stem)
        if any(not ignored for _, ignored in fns):
            continue
        if any(not any(t in fn for t in tokens) for fn, _ in fns):
            continue
        if path.stem in named:
            continue
        dead.append((path.stem, [fn for fn, _ in fns]))

    if not population:
        raise Unreadable(
            "no fixture under {} carries a test fn, so this gate graded "
            "nothing".format(TESTS_REL)
        )
    return dead, population, tokens


def check(root):
    try:
        dead, population, tokens = unreachable(root)
    except Unreadable as exc:
        print("  lane-reach: FAIL -- {}".format(exc))
        return 2
    if dead:
        print("  lane-reach: FAIL -- {} fixture(s) are run by NO lane".format(len(dead)))
        for stem, fns in dead:
            print("    {}: every test fn carries a Layer E skip token and no".format(stem))
            print("      `--test {}` appears in run-ci.sh; its legs are {}".format(
                stem, ", ".join(fns)))
        print("    Layer E's sweep skips {}".format(", ".join(tokens)))
        print("    Fix: register the file in the lane that provisions its")
        print("    binaries, with a count guard (`_runci_guarded_test <lane> <n>`),")
        print("    so a dropped #[ignore] cannot select zero tests and pass.")
        return 1
    print("  lane-reach: {} fixture(s) with tests, all reached by a lane".format(
        len(population)))
    return 0


# ── selftest ────────────────────────────────────────────────────────────

_SWEEP = """
layer_e_ap_demo_round_trip() {{
    (cd crates && {cmd} \\
        --skip zenohd --skip wz_peer) || return 1
}}
{extra}
"""


def _tree(tmp, fixtures, runci):
    root = pathlib.Path(tmp)
    (root / TESTS_REL).mkdir(parents=True)
    (root / "scripts").mkdir(parents=True)
    (root / RUNCI_REL).write_text(runci, encoding="utf-8")
    for name, body in fixtures.items():
        (root / TESTS_REL / (name + ".rs")).write_text(body, encoding="utf-8")
    return root


_IGNORED_TOKENED = '#[test]\n#[ignore = "e2e"]\nfn zenohd_answers_the_probe() {}\n'
_IGNORED_CLEAN = '#[test]\n#[ignore = "e2e"]\nfn a_plain_leg_runs_in_the_sweep() {}\n'
_PLAIN_TOKENED = "#[test]\nfn zenohd_unit_shaped_leg() {}\n"
# The shape R2221 measured in run-ci.sh's own scanner: a doc comment MENTIONING
# an attribute, then an ordinary helper. A reader that does not drop comment
# lines invents `a_helper_the_comment_armed` as an untokened test and reports
# this fixture reachable through Layer E's sweep.
_COMMENTED_ATTR = (
    "//! The `#[test]`s below all carry the token.\n"
    "fn a_helper_the_comment_armed() {}\n" + _IGNORED_TOKENED
)

_ARMS = [
    ("an ignored+tokened fixture no lane names is RED",
     {"only_zenohd": _IGNORED_TOKENED}, "", 1),
    ("the same fixture, named by a lane, is GREEN",
     {"only_zenohd": _IGNORED_TOKENED},
     "    cargo test -p wz-integration-tests --test only_zenohd\n", 0),
    ("an ignored fixture with an untokened leg rides Layer E's sweep",
     {"clean_leg": _IGNORED_CLEAN}, "", 0),
    ("a fixture with a non-ignored leg is run by an ordinary cargo test",
     {"plain_leg": _PLAIN_TOKENED}, "", 0),
    ("a stem named ONLY inside a run-ci comment is not run by it",
     {"only_zenohd": _IGNORED_TOKENED},
     "    # discussed here: cargo test --test only_zenohd\n", 1),
    ("a comment MENTIONING #[test] does not invent an untokened leg",
     {"only_zenohd": _COMMENTED_ATTR}, "", 1),
]


def selftest():
    rc = 0
    for label, fixtures, extra, want in _ARMS:
        with tempfile.TemporaryDirectory() as tmp:
            root = _tree(tmp, fixtures, _SWEEP.format(cmd=SWEEP_CMD, extra=extra))
            got = check(root)
        print("  selftest -- {}: {}".format(label, "ok" if got == want else
                                            "FAIL (want {}, got {})".format(want, got)))
        rc |= 0 if got == want else 1

    # The two unreadable arms. Each must exit 2 and not 0: a population of zero
    # and an unscrapable token list are the shapes that make every other arm
    # vacuous.
    with tempfile.TemporaryDirectory() as tmp:
        root = _tree(tmp, {}, _SWEEP.format(cmd=SWEEP_CMD, extra=""))
        got = check(root)
    print("  selftest -- an EMPTY fixture population FAILs, never passes: {}".format(
        "ok" if got == 2 else "FAIL (got {})".format(got)))
    rc |= 0 if got == 2 else 1

    with tempfile.TemporaryDirectory() as tmp:
        root = _tree(tmp, {"only_zenohd": _IGNORED_TOKENED},
                     "\nlayer_e_ap_demo_round_trip() {\n    true\n}\n")
        got = check(root)
    print("  selftest -- a sweep that no longer runs the graded command FAILs: "
          "{}".format("ok" if got == 2 else "FAIL (got {})".format(got)))
    rc |= 0 if got == 2 else 1

    with tempfile.TemporaryDirectory() as tmp:
        root = _tree(tmp, {"only_zenohd": _IGNORED_TOKENED},
                     "some_other_lane() {\n    true\n}\n")
        got = check(root)
    print("  selftest -- an ABSENT Layer E sweep FAILs rather than grading "
          "against no tokens: {}".format(
              "ok" if got == 2 else "FAIL (got {})".format(got)))
    rc |= 0 if got == 2 else 1
    return rc


def main(argv):
    if len(argv) != 2 or argv[1] not in ("--check", "--selftest"):
        print("usage: lane_reach_gate.py --check | --selftest", file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return selftest()
    return check(REPO)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

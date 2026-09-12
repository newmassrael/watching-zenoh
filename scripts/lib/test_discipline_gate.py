#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2585 (no register item) -- the three `#[ignore]` obligations of the
`wz-integration-tests` corpus, as a MODULE the push hook can reach.

The citation is `no register item` because what this answers is a hosted red,
not a register entry: the run for `dbc20e6f` (R2583) died in Layer C0 and
Layer E on one cause, recorded in `docs/hosted-red-acks.md` and the R2585
ledger entry.

## Why this is a module now

These three checks lived INLINE in `run-ci.sh`'s `layer_c0_test_discipline`,
as a bash loop and a Python heredoc. Every other check in that layer is a
`scripts/lib` module, and that difference is what let the red through. The push
hook's gate 2z runs a DERIVED population, `round_fed_gate_reach.py`, of modules
that enumerate the tracked corpus. A heredoc is not a module, so the derivation
could not contain it, and this layer is not runnable green on a developer
machine. R2581 added two `zenohd` storage legs whose fn names carried no skip
token. Nothing local graded them, hosted C0 was already dead on an earlier red
that hid this one, and after that red was repaired the hosted run redded in C0
AND Layer E, which ran the two legs against a lane with no zenohd.

As a module that imports `crossimpl_corpus`, this file is inside the derived
population, so the reach gate refuses a hook that does not run it.

## The three arms

1. BINARY-DEP (R235-hotfix, R2279). A test that reaches an external binary must
   carry `#[ignore]`, or Layer C1's `cargo test --workspace` panics on a fresh
   checkout where the binary is not built. PER TEST, not per file: a pure
   assertion in a file that spawns elsewhere owes nothing (R2277 found the
   file-level rule contradicting the naming arm).
2. NAMING (R311y455). Layer E sweeps with `-- --ignored` and `--skip <token>`,
   and libtest matches a skip against the FUNCTION name, not the file name. A
   fixture whose basename carries a token declares its family excluded, so every
   `#[ignore]`d test in it must carry a token too (any token: one match excludes
   it). Non-ignored tests owe nothing, because `--ignored` never enumerates them
   (R2279 measured exactly one such test).
3. OWNERSHIP (R311y838). A test whose `#[ignore]` reason says
   `Layer <X> runs via` with X other than E is asserting Layer E does not run
   it, so it owes a token that makes that true. The reason is read by
   `crossimpl_corpus.ignore_reason_at`, which joins `\\`-continued attributes
   (R2280: 78 of 449 reasons were invisible to the line reader before it).

The token list is scraped from Layer E's own sweep by `lane_reach_gate.skip_tokens`,
the reader the mirror-image gate (fixtures run by NO lane) already uses. The
inline heredoc carried a second, hand-kept copy of the list plus a check that
the two agreed. One scrape with a refusal on an unreadable sweep replaces both.

## Populations, and why each must be non-zero

Each arm reports the population it graded, and a zero is exit 2, never green:
no spawn-class test reaching a binary means the call-graph resolver stopped
resolving; no token-named fixture or no ownership declaration means the reader
stopped reading. The crate did not go quiet.

Exit codes: 0 green, 1 a finding, 2 the gate cannot see its subject.
"""

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import crossimpl_corpus as corpus  # noqa: E402
import lane_reach_gate  # noqa: E402

REPO = corpus.REPO_ROOT
OWNING_LANE = re.compile(r"Layer\s+([A-Za-z0-9]+)\s+runs via")


class Graded:
    """What one pass over the corpus found, with every population it read."""

    def __init__(self):
        self.binary_dep: list[str] = []
        self.naming: list[str] = []
        self.ownership: list[str] = []
        self.spawn_tests = 0
        self.reaching = 0
        self.token_named = 0
        self.owed_a_token = 0
        self.graded_owners = 0

    @property
    def findings(self) -> list[str]:
        return self.binary_dep + self.naming + self.ownership


def _rel(path) -> str:
    try:
        return str(pathlib.Path(path).relative_to(REPO))
    except ValueError:
        return str(path)


def grade(files, tokens) -> Graded:
    """Apply the three obligations to already-scanned corpus files."""
    g = Graded()
    for cf in files:
        stem_declares = any(t in cf.path.stem for t in tokens)
        if stem_declares:
            g.token_named += 1
        for t in cf.tests:
            where = "{}:{}: {}".format(_rel(cf.path), t.line, t.name)
            carries_token = any(tok in t.name for tok in tokens)

            if cf.spawns_external:
                g.spawn_tests += 1
                if t.spawns_external:
                    g.reaching += 1
                    if not t.has_ignore:
                        g.binary_dep.append(
                            "{} reaches an external binary and carries no #[ignore]".format(where))

            if stem_declares and t.has_ignore:
                g.owed_a_token += 1
                if not carries_token:
                    g.naming.append(
                        "{} carries NO Layer E skip token while its filename declares "
                        "the family".format(where))

            lane = OWNING_LANE.search(t.ignore_reason) if t.ignore_reason else None
            if lane:
                g.graded_owners += 1
                if lane.group(1) != "E" and not carries_token:
                    g.ownership.append(
                        "{} declares `Layer {} runs via --ignored` but carries NO Layer E "
                        "skip token, so Layer E's sweep runs it as well".format(
                            where, lane.group(1)))
    return g


def _empty_populations(g: Graded) -> list[str]:
    out = []
    if g.reaching == 0:
        out.append("not one of {} spawn-class test(s) reaches an external binary -- the "
                   "resolver failing, not a clean tree".format(g.spawn_tests))
    if g.token_named == 0:
        out.append("no fixture's basename carries a Layer E skip token -- the naming arm "
                   "graded nothing")
    if g.graded_owners == 0:
        out.append("no #[ignore] reason declares an owning lane -- the reason reader has "
                   "stopped reading (run `crossimpl_corpus.py --selftest` and "
                   "`--count-reasons`)")
    return out


def report(g: Graded, tokens) -> int:
    empty = _empty_populations(g)
    if empty:
        for line in empty:
            print("  test-discipline: FAIL -- {}".format(line))
        return 2
    if g.findings:
        print("  test-discipline: FAIL -- {} violation(s)".format(len(g.findings)))
        for line in g.findings:
            print("    {}".format(line))
        if g.binary_dep:
            print("    Binary-dep fix: add `#[ignore = \"binary-dep e2e (...); Layer <X> "
                  "runs via --ignored\"]` after the #[test]. Layer C1 panics on a fresh "
                  "checkout where the binary is not built.")
        if g.naming or g.ownership:
            print("    Token fix: rename the test fn so it contains a token (e.g. "
                  "`fn zenohd_<what_it_asserts>()`). libtest --skip matches the FUNCTION "
                  "name, not the file name and not the #[ignore] reason.")
            print("    Layer E's sweep skips {}".format(", ".join(tokens)))
        return 1
    print("  test-discipline: binary-dep {} of {} spawn-class test(s) reach an external "
          "binary, every one #[ignore]d; naming {} ignored test(s) in {} token-named "
          "fixture(s), every one tokened; ownership {} declared owner(s), every non-E "
          "one tokened".format(g.reaching, g.spawn_tests, g.owed_a_token, g.token_named,
                               g.graded_owners))
    return 0


def check(root=REPO) -> int:
    try:
        tokens = lane_reach_gate.skip_tokens(
            (root / lane_reach_gate.RUNCI_REL).read_text(encoding="utf-8"))
    except lane_reach_gate.Unreadable as exc:
        print("  test-discipline: FAIL -- {}".format(exc))
        return 2
    files = corpus.scan_all()
    if not files:
        print("  test-discipline: FAIL -- no wz-integration-tests fixture was scanned")
        return 2
    return report(grade(files, tokens), tokens)


# ── selftest ────────────────────────────────────────────────────────────
#
# Built from corpus OBJECTS rather than parsed fixtures: the reader has its own
# selftest (`crossimpl_corpus.py --selftest`, run first in Layer C0), and what is
# under test here is the verdict each arm returns for a shape it is given.

_TOKENS = ["zenohd", "wz_peer"]


def _test(name, *, ignore=False, reason=None, spawns=False, line=1):
    t = corpus.TestFn(name, line)
    t.has_ignore = ignore or reason is not None
    t.ignore_reason = reason
    t.spawns_external = spawns
    return t


def _file(stem, tests, *, spawns=False):
    cf = corpus.CorpusFile(pathlib.Path("crates/wz-integration-tests/tests/{}.rs".format(stem)))
    cf.spawns_external = spawns
    cf.tests = tests
    return cf


# A baseline that satisfies every arm and gives every population a member, so a
# case below can differ from it in ONE shape and the verdict is that shape's.
def _baseline():
    return [
        _file("wz_zenohd_interop", [
            _test("zenohd_answers", reason="e2e; Layer Z runs via --ignored", spawns=True),
        ], spawns=True),
    ]


_CASES = [
    ("the baseline is green", [], 0, None),
    ("an ignored untokened leg in a token-named fixture reds NAMING",
     [_file("wz_zenohd_storage", [_test("a_storage_leg", ignore=True)])], 1, "naming"),
    ("the same leg carrying a token is green",
     [_file("wz_zenohd_storage", [_test("zenohd_storage_leg", ignore=True)])], 0, None),
    ("any token satisfies naming, not only the filename's",
     [_file("wz_zenohd_gossip", [_test("wz_peer_gossips", ignore=True)])], 0, None),
    ("a NON-ignored untokened leg in a token-named fixture owes nothing",
     [_file("wz_zenohd_vocab", [_test("a_pure_vocabulary_assertion")])], 0, None),
    ("a non-E owner without a token reds OWNERSHIP",
     [_file("neutral_fixture", [_test("a_leg", reason="x; Layer Z runs via --ignored")])],
     1, "ownership"),
    ("an E owner owes no token",
     [_file("neutral_fixture", [_test("a_leg", reason="x; Layer E runs via --ignored")])],
     0, None),
    ("a spawning test without #[ignore] reds BINARY-DEP",
     [_file("spawner", [_test("spawns_a_binary", spawns=True)], spawns=True)],
     1, "binary_dep"),
    ("a non-spawning test in a spawn-class file owes no #[ignore]",
     [_file("spawner", [_test("pure_assertion")], spawns=True)], 0, None),
]


def selftest() -> int:
    rc = 0
    for label, extra, want, arm in _CASES:
        g = grade(_baseline() + extra, _TOKENS)
        got = 1 if g.findings else 0
        ok = got == want
        # The CONTROL half: a red case must red in the arm it names and no other,
        # or a finding from the wrong arm would satisfy it.
        if ok and arm is not None:
            by_arm = {"naming": g.naming, "ownership": g.ownership, "binary_dep": g.binary_dep}
            ok = bool(by_arm[arm]) and all(not v for k, v in by_arm.items() if k != arm)
        print("  selftest -- {}: {}".format(label, "ok" if ok else "FAIL"))
        rc |= 0 if ok else 1

    # Each population, emptied alone, must exit 2 rather than report green.
    empties = [
        ("no test reaching a binary",
         [_file("wz_zenohd_interop", [_test("zenohd_answers", reason="e2e; Layer Z runs via --ignored")])]),
        ("no token-named fixture",
         [_file("interop", [_test("zenohd_answers", reason="e2e; Layer Z runs via --ignored",
                                  spawns=True)], spawns=True)]),
        ("no declared owner",
         [_file("wz_zenohd_interop", [_test("zenohd_answers", ignore=True, spawns=True)],
                spawns=True)]),
    ]
    for label, files in empties:
        got = report(grade(files, _TOKENS), _TOKENS)
        print("  selftest -- {} exits 2, never 0: {}".format(label, "ok" if got == 2 else
                                                                "FAIL (got {})".format(got)))
        rc |= 0 if got == 2 else 1
    return rc


def main(argv) -> int:
    if len(argv) != 2 or argv[1] not in ("--check", "--selftest"):
        print("usage: test_discipline_gate.py --check | --selftest", file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return selftest()
    return check()


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2325 (no register item) — how much of the demo-spawning corpus can still be
fooled by a STALE `wz-ap-demo`, TRIAGED into the classes that move for different
reasons. Grown from R311y779, which counted it as one number.

The citation is `no register item` for the reason `config_key_fixture_gate.py`
gives for its own: the item this closes -- unregistered open-debt item 9 -- lives
in the agent-memory register, which has no store id for
`gate_provenance_lint.py` to resolve. The item is named in prose below.

## The defect this counts

`wz_ap_demo_binary()` returns whatever file exists at `crates/target/<profile>/`.
A fixture that spawns it is making a claim about the CURRENT tree; a binary built
before the change under test turns that into a claim about some past one, and the
failure mode is the worst kind -- it reads as "the feature does not work", so the
diagnosis goes hunting somewhere else.

That is not hypothetical. R311y774 wrote a witness for R311y771's Interest emit,
ran it against a demo predating that emit, and attributed the red to a
feature-closure defect that did not exist; R311y776 retracted the whole diagnosis.
The binary prints its feature banner either way, so nothing in the output
discriminates. `assert_demo_binary_newer_than_sources` is the check.

## R2325 — why ONE number was the wrong instrument

Open-debt item 9 said the carried `110` was untriaged: "cannot be misled by an
argv check" and "not fixed yet" were summed into one integer, so the number was
too big read as remaining debt and too small read as exposure. Re-measured, both
halves are real and they are NOT the same size:

  * too SMALL by 122, read as exposure. The old number counted FILES. 131 files
    drive the demo and they hold 293 test fns that reach it, of which 232 are
    subject-route fixtures with no check -- so the file count understated the
    exposed fixtures by more than a factor of two.
  * too BIG by 32, read as remaining work. 32 of the 293 are in two route
    classes a stale binary cannot silently mislead (24 probe, 8 refusal), and
    the old lint's own prose said so about ONE of them
    (`close_scope_zenohd_witness.rs`) while still counting its file.

The file resolution also broke the gate's stated contract. "A NEW spawning fixture
with no freshness check RAISES the number -> red" was FALSE: a fixture added to a
file already in the corpus moves no file count at all, and 110 of the 131 files
were uncovered, so that is where a new fixture normally lands. The `--selftest`
arm pins this -- it drives the retired per-file reader over the same synthetic
corpus and requires it to MISS the shape the fixture reader catches, which is the
only way to know the change fixed something rather than merely recounting.

What the file resolution had right is kept as printed context, not as the gate:
one edit in a shared helper can cover a whole file's fixtures (R311y840's
`spawn_wz_router`), so the FILE count is what predicts edit cost while the
FIXTURE count is what states exposure.

## The three classes, each DERIVED and each budgeted

`subject`  the demo must come UP and the fixture's verdict depends on what it
           then does. A stale build makes the awaited effect absent, and absence
           reads as a defect -- this is the class that cost R311y774 a round.
           Derived as: reaches the demo, and is neither of the two below.
`probe`    the fixture never names `wz_ap_demo_binary` outside the freshness call
           itself; its ONLY route to the demo is inside a `spawn_zenohd*`
           helper, where the demo is the handshake-readiness probe
           (`wait_for_zenohd_handshake_ready`) and not the subject.
`refusal`  the fixture runs the demo to COMPLETION (its route never reaches
           `Command::spawn`) and asserts a non-success exit. A stale build can
           still flip that verdict, but it flips it to "the demo accepted what it
           must reject", which names the demo rather than the feature under test.

Note what the `probe` derivation found. R311y839 declared that exemption in PROSE
for ONE file, and the structural form finds 24 fixtures in exactly the same
position -- and, more usefully, that the tree does NOT agree about them: 16 of
the 24 carry the freshness check anyway, on the opposite reasoning. See
`EXEMPT_ROUTE_CHECKED` for both quotations. A declared exemption does not scale
and it does not notice being contradicted, which is the standing reason this gate
derives its populations instead of listing them.

Both `probe` and `refusal` carry their own budget rather than being subtracted and
forgotten. A fixture that SLIDES into either class -- a readiness wait deleted, a
subject fixture rewritten as one-shot -- moves that budget and reds, so the
exemption cannot be reached by editing the fixture into it quietly.

The ROUTE is read with the freshness call's own argument masked out, which is not
a nicety: `assert_demo_binary_newer_than_sources(&wz_ap_demo_binary())` is the
only place four fixtures name the resolver, so an unmasked read makes the route
depend on whether the fixture checks -- and the live control group MEASURED that,
reclassifying four fixtures from subject to probe when the call was removed
instead of moving them from asserting to carried. A fixture whose only route IS
the call is not a class at all but a check with no subject, and it FAILS.

The `subject` budget is watched in BOTH directions, exactly as the Layer C1bz doc
budget is: a new unchecked subject fixture RAISES it (add the call, or say which
class it is really in), and fixing one LOWERS it (write the smaller number in the
same commit, or the gate quietly stops measuring). A subject fixture that arrives
WITH the check moves nothing, which is the freedom worth having.

## The population comes from the corpus SSOT, not a grep

`crossimpl_corpus` already resolves which fixtures drive which wz binary,
transitively through `common::*` wrapper helpers, and R2325 added the two
projections this needs: `reachable_idents` (per fixture) and `helper_idents` (per
harness helper). A grep for `wz_ap_demo_binary(` would miss every fixture that
reaches the demo through a wrapper -- the same hole that module was built to close
for Layer C0 and A4 -- and it is also what would make the `probe` class
invisible, since those eight fixtures reach the demo through a helper and nothing
else. An empty population is a hard FAIL here, not a green run.
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import crossimpl_corpus as corpus  # noqa: E402

# The binary whose staleness has actually cost a wrong diagnosis. The other wz
# e2e binaries (`wz-e2e-*`) have the same hole and are deliberately NOT counted
# here: none of them has been observed to mislead, and folding them in would mix
# a measured problem with an assumed one. Widening the scope is its own round.
WATCHED_BINARY = "wz-ap-demo"

FRESHNESS_CALL = "assert_demo_binary_newer_than_sources"

# The resolver a fixture names when the demo is ITS OWN subject. Reaching the
# demo without naming this means reaching it inside a harness helper.
DEMO_RESOLVER = "wz_ap_demo_binary"

# `Command::spawn` is the only route in this crate by which a child outlives the
# call that started it; `Command::output` runs to completion. The token is
# resolved through the call graph on both sides -- a fixture's own fns and the
# `common::*` helpers it calls -- because `spawn_listen_acceptor` spawns and the
# fixture only names the helper.
SPAWN_CALL = "spawn"

# What "asserts a refusal" looks like: the fixture reads the exit status. Both
# spellings, since `status.code()` and `status.success()` are both in the corpus.
REFUSAL_TOKENS = frozenset({"code", "success"})

# MEASURED at R2325, at FIXTURE resolution (R311y779's `110` was 131 files minus
# the 21 that carry the call; the same corpus holds 293 fixtures that reach the
# demo, of which 45 carry it).
#
#   293 reach the demo = 232 carried subject + 29 asserting subject
#                      + 24 probe + 8 refusal
#
# The 29 asserting subject fixtures are the zenohd-adjudicated witnesses grown
# from R311y774-y778 plus R311y840's `spawn_wz_router` file, which is not a
# coincidence: they are the ones whose red was actually misdiagnosed, so they are
# where the check got written.
CARRIED_SUBJECT = 232
PROBE_ROUTE = 24
REFUSAL_ONLY = 8

# THE LIVE POLICY SPLIT, budgeted so it cannot go back to being invisible.
#
# 16 of the 24 probe-route fixtures carry the freshness check anyway, and the two
# rounds that decided that wrote OPPOSITE reasons into the tree:
#
#   R311y839 (`close_scope_zenohd_witness.rs`) — exempt. "A stale demo can make
#     the probe fail to detect readiness, which surfaces as a connect or read
#     error on the next line, never as a wrong verdict about zenohd's byte."
#   R2200 (`wz_channel_reassembly_zenohd_interop.rs:265-272`) — exposed. "The
#     probe would fail to detect a router that is in fact up, and the next line
#     then panics with 'wz did not reach Established against zenohd', pointing
#     the investigation at the session layer for a defect that is in the build."
#
# Both are in the tree right now, 8 fixtures to 16. This gate does NOT adjudicate
# them -- picking a side is a decision about the harness, not a counting fix, and
# item 9 asked for the triage that makes the disagreement legible. What the budget
# buys is that the next round to touch a probe-route fixture has to move a number
# and say which side it took.
EXEMPT_ROUTE_CHECKED = 16


# The check's own argument is not a use of the demo. `assert_demo_binary_newer_
# than_sources(&wz_ap_demo_binary())` is the only place four fixtures name the
# resolver at all, and reading that as "the demo is this fixture's subject" makes
# the ROUTE depend on whether the fixture checks -- so removing the check would
# reclassify the fixture instead of reddening the budget. MEASURED at R2325: the
# control group did exactly that, moving four fixtures from subject to probe
# rather than from asserting to carried.
FRESHNESS_CALL_EXPR = re.compile(
    r"\b" + FRESHNESS_CALL + r"\s*\([^;]*\)\s*;"
)


class Triage:
    """The route classes and the checked/unchecked split, kept ORTHOGONAL.

    R2325 — they are two questions and summing them is what item 9 was about.
    `probe` and `refusal` are facts about how a fixture reaches the demo;
    carrying the check is a fact about what the author decided. A probe-route
    fixture that checks anyway is not a contradiction to hide, it is the
    disagreement between R311y839 (which declared that route exempt) and R2200
    (which declared it exposed and added the call), and it stays visible.
    """

    def __init__(self) -> None:
        self.files: list[Path] = []
        self.subject_carried: list[str] = []
        self.subject_asserting: list[str] = []
        self.probe: list[str] = []
        self.refusal: list[str] = []
        self.exempt_route_checked: list[str] = []
        self.orphan_check: list[str] = []

    @property
    def total(self) -> int:
        return (len(self.subject_carried) + len(self.subject_asserting)
                + len(self.probe) + len(self.refusal))


def classify(idents: frozenset[str], demo_routes: frozenset[str],
             spawning_helpers: frozenset[str]) -> str | None:
    """Which class ONE fixture is in, from the identifiers it can reach.

    Returns None when the fixture does not reach the demo at all -- a file in the
    corpus does not make every test in it a demo test, which is the same
    resolution mistake `reachable_external` was split out to fix.

    `probe` is decided FIRST and on the narrower fact (the fixture never names
    the resolver), because a fixture that reaches the demo BOTH directly and
    through a readiness probe is using it as a subject and must not be exempted
    by the incidental route.
    """
    if not (idents & demo_routes):
        return None
    if DEMO_RESOLVER not in idents:
        return "probe"
    holds_alive = SPAWN_CALL in idents or bool(idents & spawning_helpers)
    if not holds_alive and (idents & REFUSAL_TOKENS):
        return "refusal"
    return "subject"


def triage(tests_dir: Path | None = None) -> Triage:
    by_helper, pkgs_by_helper = corpus.helper_classes()
    helper_reach = corpus.helper_idents()
    demo_routes = frozenset(
        {DEMO_RESOLVER}
        | {h for h, p in pkgs_by_helper.items() if WATCHED_BINARY in p}
    )
    spawning_helpers = frozenset(
        h for h, idents in helper_reach.items() if SPAWN_CALL in idents
    )

    out = Triage()
    root = tests_dir if tests_dir is not None else corpus.TESTS_DIR
    for path in sorted(root.glob("*.rs")):
        cf = corpus.scan_file(path, by_helper, pkgs_by_helper)
        if WATCHED_BINARY not in cf.binaries:
            continue
        out.files.append(path)
        code = corpus.strip_code(path.read_text())
        local = corpus.local_fn_bodies(code)
        edges = corpus.reexec_edges(code, local)
        # The ROUTE is read with the check's own call masked out; whether the
        # fixture CHECKS is read from the unmasked graph. Two questions, two
        # reads -- see `FRESHNESS_CALL_EXPR`.
        route_local = corpus.local_fn_bodies(FRESHNESS_CALL_EXPR.sub(";", code))
        for t in cf.tests:
            idents = corpus.reachable_idents(t.name, local, edges)
            if not (idents & demo_routes):
                continue
            route = corpus.reachable_idents(t.name, route_local, edges)
            cls = classify(route, demo_routes, spawning_helpers)
            label = f"{path.name}::{t.name}"
            checked = FRESHNESS_CALL in idents
            if cls is None:
                # The check is the fixture's ONLY route to the demo: it asserts
                # the freshness of a binary it never uses. Not a class, a
                # defect -- and reported as one rather than folded into `probe`,
                # which would make a stray check look like an exemption.
                out.orphan_check.append(label)
                continue
            if cls == "probe":
                out.probe.append(label)
            elif cls == "refusal":
                out.refusal.append(label)
            elif checked:
                out.subject_asserting.append(label)
            else:
                out.subject_carried.append(label)
            if cls != "subject" and checked:
                out.exempt_route_checked.append(label)
    return out


def retired_file_count(tests_dir: Path | None = None) -> tuple[int, int]:
    """R311y779's reader, kept ONLY so the selftest can prove it was blind.

    Returns (files driving the demo, files with no freshness call anywhere in
    them). This is not a second opinion the gate consults -- it is the control
    group, and a control group that is not runnable is an assertion.
    """
    by_helper, pkgs_by_helper = corpus.helper_classes()
    root = tests_dir if tests_dir is not None else corpus.TESTS_DIR
    files = [
        cf for cf in (
            corpus.scan_file(p, by_helper, pkgs_by_helper)
            for p in sorted(root.glob("*.rs"))
        )
        if WATCHED_BINARY in cf.binaries
    ]
    missing = [f for f in files
               if FRESHNESS_CALL not in Path(f.path).read_text()]
    return len(files), len(missing)


def _budget_report(label: str, measured: int, carried: int, up: str, down: str) -> None:
    print(
        f"  binary-freshness FAIL: {label} is {measured}, carried number says {carried}",
        file=sys.stderr,
    )
    print(up if measured > carried else down, file=sys.stderr)


def check() -> int:
    t = triage()
    if t.total == 0:
        print(
            "  binary-freshness FAIL: NO fixture reaches "
            f"{WATCHED_BINARY}. The corpus resolution has broken -- a population of "
            "zero would report every budget met, which is the shape of a gate that "
            "has stopped measuring rather than of a corpus that got clean.",
            file=sys.stderr,
        )
        return 1

    ok = True
    if len(t.subject_carried) != CARRIED_SUBJECT:
        ok = False
        _budget_report(
            "subject fixtures without the freshness check",
            len(t.subject_carried), CARRIED_SUBJECT,
            "  A new fixture needs the demo ALIVE and does not check it. Add\n"
            f"    {FRESHNESS_CALL}(&demo);\n"
            "  right after the binary is resolved -- or, if the demo is only a\n"
            "  readiness probe there, or the fixture asserts a REFUSAL and runs it to\n"
            "  completion, it belongs in the probe / refusal budget instead, and that\n"
            "  is a structural fact this gate derives rather than a claim to write.",
            "  A fixture gained the check -- good. Lower the carried number in this\n"
            "  file in the SAME commit, or the gate quietly stops measuring (the drift\n"
            "  catch Layer C1bz's doc budget applies for the same reason).",
        )
        for label in sorted(t.subject_carried)[:5]:
            print(f"    - {label}", file=sys.stderr)
        if len(t.subject_carried) > 5:
            print(f"    ... and {len(t.subject_carried) - 5} more", file=sys.stderr)
    if len(t.probe) != PROBE_ROUTE:
        ok = False
        _budget_report(
            "fixtures reaching the demo only as a readiness probe",
            len(t.probe), PROBE_ROUTE,
            "  A fixture stopped naming the demo directly and now reaches it only\n"
            "  through a `spawn_zenohd*` helper. If that is what the fixture means,\n"
            "  raise this number; if the demo is still its subject, it has lost the\n"
            "  route it was testing.",
            "  A probe-route fixture now names the demo directly, so it is a subject\n"
            "  again and owes the freshness check. Lower this number and raise the\n"
            "  subject budget in the same commit.",
        )
        for label in sorted(t.probe):
            print(f"    - {label}", file=sys.stderr)
    if len(t.refusal) != REFUSAL_ONLY:
        ok = False
        _budget_report(
            "one-shot fixtures asserting a refusal",
            len(t.refusal), REFUSAL_ONLY,
            "  A fixture now runs the demo to completion and asserts its exit status.\n"
            "  That is the class staleness cannot silently mislead, so raise this\n"
            "  number -- but check it is not a subject fixture that LOST its readiness\n"
            "  wait, which reads identically here and is a defect.",
            "  A one-shot refusal fixture now holds the demo alive, so it is exposed\n"
            "  again. Lower this number and account for it in the subject budget.",
        )
        for label in sorted(t.refusal):
            print(f"    - {label}", file=sys.stderr)
    if len(t.exempt_route_checked) != EXEMPT_ROUTE_CHECKED:
        ok = False
        _budget_report(
            "exempt-route fixtures that carry the check anyway",
            len(t.exempt_route_checked), EXEMPT_ROUTE_CHECKED,
            "  Another probe-route fixture took R2200's side of the split. Raise this\n"
            "  number and say why the probe misleads there -- or, if the split is being\n"
            "  SETTLED, settle it for all 24 and retire this budget with the reason.",
            "  A probe-route fixture dropped the check, taking R311y839's side. Lower\n"
            "  this number and say why the probe cannot mislead there. Silently is the\n"
            "  one way this must not happen: 8 fixtures already read the same route the\n"
            "  other way.",
        )
        for label in sorted(t.exempt_route_checked):
            print(f"    - {label}", file=sys.stderr)
    if t.orphan_check:
        ok = False
        print(
            f"  binary-freshness FAIL: {len(t.orphan_check)} fixture(s) assert the "
            "demo's freshness and never use the demo. The check has no subject there "
            "-- either the fixture lost the route it was testing, or the call is a "
            "copy that should go.",
            file=sys.stderr,
        )
        for label in sorted(t.orphan_check):
            print(f"    - {label}", file=sys.stderr)

    if not ok:
        return 1

    n_files, n_files_missing = retired_file_count()
    print(
        f"binary-freshness lint: {t.total} fixture(s) in {n_files} file(s) reach "
        f"{WATCHED_BINARY} -- {len(t.subject_asserting)} subject fixture(s) assert "
        f"freshness, {len(t.subject_carried)} carried (a stale binary there reads as a "
        f"broken feature), {len(t.probe)} probe-route ({len(t.exempt_route_checked)} of "
        f"them checking anyway, the unsettled split), {len(t.refusal)} one-shot refusal. "
        f"Edit cost, not exposure: {n_files_missing} file(s) carry no call."
    )
    return 0


# --- selftest ---------------------------------------------------------------
#
# Every fixture here is a shape the RETIRED per-file reader got wrong, or a class
# boundary the new one has to hold. The two blind cases are the point: a file
# already in the corpus gaining a misleadable fixture moved no file count, and a
# COVERED file gaining one read as covered. A selftest that only held shapes the
# old code already handled would prove this file parses, not that it fixed
# anything.
#
# `_SELFTEST_ONESHOT_NO_STATUS` is here for the opposite reason -- it is a branch
# the LIVE corpus cannot currently reach. All 8 no-spawn fixtures in the tree
# assert a refusal, so the `REFUSAL_TOKENS` half of the refusal test is never
# exercised by real code, and a rule the fixture cannot even create is a rule
# that has never been walked.
_SELFTEST_FILES = {
    # An already-uncovered file with two subject fixtures. The old reader counts
    # the FILE once, so the second is free.
    "uncovered_two_subjects.rs": '''\
use wz_integration_tests::common::{read_captured, wz_ap_demo_binary};

#[test]
fn first_subject() {
    let demo = wz_ap_demo_binary();
    let child = Command::new(&demo).spawn().expect("x");
    let _ = read_captured(&mut child);
}

#[test]
fn second_subject() {
    let demo = wz_ap_demo_binary();
    let child = Command::new(&demo).spawn().expect("x");
    let _ = read_captured(&mut child);
}
''',
    # A COVERED file that also holds a fixture reaching the demo without the
    # call. The old reader reads the file as covered and reports nothing.
    "covered_but_leaky.rs": '''\
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wz_ap_demo_binary,
};

#[test]
fn checked_subject() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let child = Command::new(&demo).spawn().expect("x");
    let _ = read_captured(&mut child);
}

#[test]
fn unchecked_subject_in_a_covered_file() {
    let demo = wz_ap_demo_binary();
    let child = Command::new(&demo).spawn().expect("x");
    let _ = read_captured(&mut child);
}
''',
    # The refusal archetype: run to completion, assert the exit status.
    "oneshot_refusal.rs": '''\
use wz_integration_tests::common::wz_ap_demo_binary;

#[test]
fn refuses_the_flag() {
    let demo = wz_ap_demo_binary();
    let out = Command::new(&demo).arg("--peer").output().expect("x");
    assert_eq!(out.status.code(), Some(2));
}
''',
    # No spawn, no exit-status assertion. Not a refusal, so it stays a subject --
    # the branch the live corpus has no instance of.
    "oneshot_no_status.rs": '''\
use wz_integration_tests::common::wz_ap_demo_binary;

#[test]
fn reads_the_usage_text() {
    let demo = wz_ap_demo_binary();
    let out = Command::new(&demo).arg("--help").output().expect("x");
    assert!(String::from_utf8_lossy(&out.stdout).contains("--peer"));
}
''',
    # The probe route: the demo is never named, only the zenohd helper is.
    "probe_route_only.rs": '''\
use wz_integration_tests::common::{spawn_zenohd_on_ephemeral_tcp, read_captured};

#[test]
fn a_real_zenohd_answers() {
    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let _ = (port, read_captured(&mut zenohd));
}
''',
    # The probe route whose ONLY mention of the resolver is the check's own
    # argument. R2325's live control group is what taught this shape: reading it
    # as a subject makes the route depend on whether the fixture checks.
    "probe_route_checked_inline.rs": '''\
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured,
    spawn_zenohd_on_ephemeral_tcp, wz_ap_demo_binary,
};

#[test]
fn a_real_zenohd_answers_and_the_probe_is_checked() {
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let _ = (port, read_captured(&mut zenohd));
}
''',
    # The check with no subject: freshness asserted for a binary the fixture
    # never uses. A defect, not a class.
    "orphan_check.rs": '''\
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, wz_ap_demo_binary,
};

#[test]
fn checks_a_binary_it_never_runs() {
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    assert_eq!(2 + 2, 4);
}
''',
    # Reaches the demo BOTH ways. The incidental probe route must not exempt it.
    "probe_and_subject.rs": '''\
use wz_integration_tests::common::{
    spawn_zenohd_on_ephemeral_tcp, read_captured, wz_ap_demo_binary,
};

#[test]
fn wz_talks_through_a_real_zenohd() {
    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let demo = wz_ap_demo_binary();
    let child = Command::new(&demo).arg(port.to_string()).spawn().expect("x");
    let _ = (read_captured(&mut zenohd), child);
}
''',
    # In the tests dir, drives no wz-ap-demo. Must not enter any population.
    "not_in_the_population.rs": '''\
#[test]
fn pure_unit() {
    assert_eq!(2 + 2, 4);
}
''',
}

_SELFTEST_EXPECTED = {
    "uncovered_two_subjects.rs::first_subject": "subject-carried",
    "uncovered_two_subjects.rs::second_subject": "subject-carried",
    "covered_but_leaky.rs::checked_subject": "subject-asserting",
    "covered_but_leaky.rs::unchecked_subject_in_a_covered_file": "subject-carried",
    "oneshot_refusal.rs::refuses_the_flag": "refusal",
    "oneshot_no_status.rs::reads_the_usage_text": "subject-carried",
    "probe_route_only.rs::a_real_zenohd_answers": "probe",
    "probe_route_checked_inline.rs::a_real_zenohd_answers_and_the_probe_is_checked":
        "probe",
    "orphan_check.rs::checks_a_binary_it_never_runs": "orphan-check",
    "probe_and_subject.rs::wz_talks_through_a_real_zenohd": "subject-carried",
}

# The probe-route fixtures that carry the check: the live policy split, one
# instance, so the arm that counts it is walked by the fixture too.
_SELFTEST_EXEMPT_ROUTE_CHECKED = {
    "probe_route_checked_inline.rs::a_real_zenohd_answers_and_the_probe_is_checked",
}

# The CONTROL GROUP, as a mutation rather than as a comparison of two counts.
#
# These two files are the same two with the blind fixture DELETED, so the pair of
# corpora differs by exactly the shape at issue: a misleadable fixture arriving
# in a file the corpus already holds. The retired per-file reader must report the
# IDENTICAL pair of numbers across the two -- that is what "blind" means, and it
# is a claim that can fail -- while the fixture reader's subject count must drop
# by 2. Comparing the two readers' numbers on ONE corpus proves nothing: they
# happen to both be 5 here, which is arithmetic, not agreement.
_SELFTEST_BLIND_REMOVED = {
    "uncovered_two_subjects.rs": '''\
use wz_integration_tests::common::{read_captured, wz_ap_demo_binary};

#[test]
fn first_subject() {
    let demo = wz_ap_demo_binary();
    let child = Command::new(&demo).spawn().expect("x");
    let _ = read_captured(&mut child);
}
''',
    "covered_but_leaky.rs": '''\
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wz_ap_demo_binary,
};

#[test]
fn checked_subject() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let child = Command::new(&demo).spawn().expect("x");
    let _ = read_captured(&mut child);
}
''',
}

_SELFTEST_RETIRED_BLIND = {
    "uncovered_two_subjects.rs::second_subject",
    "covered_but_leaky.rs::unchecked_subject_in_a_covered_file",
}


def selftest() -> bool:
    ok = True
    with tempfile.TemporaryDirectory(prefix="wz-freshness-selftest-") as tmp:
        root = Path(tmp)
        for name, body in _SELFTEST_FILES.items():
            (root / name).write_text(body)

        t = triage(root)
        got: dict[str, str] = {}
        for label in t.subject_carried:
            got[label] = "subject-carried"
        for label in t.subject_asserting:
            got[label] = "subject-asserting"
        for label in t.probe:
            got[label] = "probe"
        for label in t.refusal:
            got[label] = "refusal"
        for label in t.orphan_check:
            got[label] = "orphan-check"

        if set(t.exempt_route_checked) != _SELFTEST_EXEMPT_ROUTE_CHECKED:
            ok = False
            print(
                "  binary-freshness selftest FAIL: exempt-route-checked read as "
                f"{sorted(t.exempt_route_checked)}, expected "
                f"{sorted(_SELFTEST_EXEMPT_ROUTE_CHECKED)}",
                file=sys.stderr,
            )

        for label, want in sorted(_SELFTEST_EXPECTED.items()):
            have = got.get(label)
            if have != want:
                ok = False
                print(
                    f"  binary-freshness selftest FAIL: {label} classified "
                    f"{have!r}, expected {want!r}",
                    file=sys.stderr,
                )
        for label in sorted(set(got) - set(_SELFTEST_EXPECTED)):
            ok = False
            print(
                f"  binary-freshness selftest FAIL: {label} entered a population "
                f"as {got[label]!r} and the fixture does not expect it",
                file=sys.stderr,
            )

        # The control group: the same corpus with the two blind fixtures
        # DELETED. The mutation is the shape at issue, so the retired reader has
        # to report the identical numbers across the pair and the fixture reader
        # has to drop by exactly 2.
        for label in sorted(_SELFTEST_RETIRED_BLIND):
            if got.get(label) != "subject-carried":
                ok = False
                print(
                    f"  binary-freshness selftest FAIL: {label} is the shape the "
                    "retired reader was blind to and the new reader no longer "
                    "catches it",
                    file=sys.stderr,
                )

        control = root / "control"
        control.mkdir()
        for name, body in _SELFTEST_FILES.items():
            (control / name).write_text(_SELFTEST_BLIND_REMOVED.get(name, body))

        before, after = retired_file_count(root), retired_file_count(control)
        if before != after:
            ok = False
            print(
                "  binary-freshness selftest FAIL: the retired per-file reader "
                f"reported {before} then {after} across the control pair. It was "
                "supposed to be BLIND to a misleadable fixture arriving in a file "
                "the corpus already holds -- if it can see this, the resolution "
                "change fixed nothing and this file's premise is wrong.",
                file=sys.stderr,
            )
        caught = len(t.subject_carried) - len(triage(control).subject_carried)
        if caught != len(_SELFTEST_RETIRED_BLIND):
            ok = False
            print(
                "  binary-freshness selftest FAIL: the fixture reader's subject "
                f"count moved by {caught} across the control pair, expected "
                f"{len(_SELFTEST_RETIRED_BLIND)}. The mutation the retired reader "
                "cannot see has to be one this reader can.",
                file=sys.stderr,
            )

        # A population of zero must FAIL rather than report every budget met.
        empty = Path(tmp) / "empty"
        empty.mkdir()
        if triage(empty).total != 0:
            ok = False
            print(
                "  binary-freshness selftest FAIL: an empty corpus produced a "
                "non-empty population",
                file=sys.stderr,
            )

    if ok:
        print(
            f"binary-freshness selftest: {len(_SELFTEST_EXPECTED)} fixture shape(s) "
            f"triaged, {len(_SELFTEST_RETIRED_BLIND)} of them invisible to the "
            "retired per-file reader"
        )
    return ok


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a]
    if not args or args == ["--check"]:
        return check()
    if args == ["--selftest"]:
        return 0 if selftest() else 1
    print(
        f"binary_freshness_lint: unknown argument {args!r}; "
        "expected --check (the default) or --selftest",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

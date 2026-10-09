#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2356 (no register item) -- upstream claims in the STORE's LIVE atom reasons
must be judged, the same way source-file claims already are.

WHAT WAS ACTUALLY MISSING, measured rather than assumed.

`upstream_citation_anchor_gate` is ALREADY a version-anchored, needle-based
oracle for upstream claims. It scans the tracked tree and skips three prefixes,
one of them the atomic store -- for a REASON that is written down beside the
constant: the store's LEDGER quotes citations verbatim, so scanning it would
grade frozen history.

That reason covers `changelog_entries`. It does NOT cover
`inventory_entries[*].reason`, which is the LIVE impl-axis verdict for each atom
-- prose REWRITTEN whenever an atom is re-graded (the store carries a
`CORRECTION (R311y440): ... no longer exists; the method is at ...`, which is an
edit to a reason, not a record of one). So the live verdicts were the one
population carrying upstream claims with no oracle, which is exactly what
`depth_axis_census` reports as "read as upstream and NOT judged (R2215: this
tree holds no oracle for them)".

  SKIP_PREFIXES IS NOT WIDENED, and that is the point. Grading the frozen
  ledger would demand repairs to entries that must not change. This gate
  reaches the reasons through the INVENTORY MAPPING instead, so the ledger
  stays out by construction rather than by a promise.

ONE CLASSIFIER, NOT A SECOND ONE. The bucket order is load-bearing -- the
absence marker is masked before anchors, anchors before line-form, line-form
before bare -- and re-implementing it would measure the re-implementation. The
reasons are materialised into a temp dir and the EXISTING `scan()` reads them.

THE RESOLVING ARM IS NOT OPTIONAL. `scan(.., rootless_loc=None)` is the source
gate's FORM arm: counts without resolution, and the same flag also gates the
absence marker's back-check (a path marked gone that upstream BROUGHT BACK).
The first draft passed `None` while handing over a real `ref`, so it still
emitted gone-path findings and looked like a full run while two arms were dark
-- MEASURED, that partial arm reported 4 findings where the resolving arm
reports 10. A gate that resolves half its axes must not print a verdict as
though it resolved all of them.

THE VERSION IS NOT OPTIONAL EITHER, for the reason the source gate records: its
own first draft resolved every citation against the previous pin and "reported a
completely different finding set with no sign anything was wrong".
`upstream_root()` returns the checkout that DECLARES the pinned version, or
None, and None is a FAIL here rather than a skip -- a gate that cannot read its
input must not report green.

NO UPSTREAM PATH LITERAL APPEARS IN THIS FILE. It is tracked, so it sits inside
the population the SOURCE gate scans, and a literal here would become a real
citation: classified, resolved, and -- since fixture paths cannot exist upstream
-- reported as a finding against the very file that exists to find such things.
Fixture paths are built by CONCATENATION. Verified before landing: scanning this
file and its fixtures with the source gate's own classifier moves no bucket.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import io
import json
import pathlib
import shutil
import sys
import tempfile
import typing

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import depth_axis_census as dc  # noqa: E402
import upstream_citation_anchor_gate as g  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
STORE = "docs/.atomic/workspace.atomic.json"

#: A population that collapsed means the reader stopped matching the store, not
#: that the store stopped making claims. Zero reasons must FAIL.
MIN_REASONS = 40

#: Two-directional ratchets, in the source gate's shape: ABOVE means this commit
#: ADDED a forbidden form (repair the citation, never the budget); BELOW means it
#: removed one (lower the budget in the same commit).
#:
#: The owner's decision of 2026-09-01 is that upstream claims carry no line
#: numbers. These are the debt that decision inherited in the store, seeded at
#: what the command PRINTED on the landing commit; they may only shrink.
#:
#: 29 -> 28 (R2368). R2366 re-tagged the `runtime-tokio` atom, and
#: `set-inventory-status --reason` replaces a whole reason blob, so the rewrite
#: took one line-form citation out of the store with it. The count therefore sat
#: exactly ON 29 at that commit's parent and BELOW it after, which is this
#: ratchet's "removed one" direction. R2366 did not follow it down, and nothing
#: local could say so: this gate runs in Layer Z, not in pre-push, so the push
#: published green and the red waited on the hosted run.
#:
#: 28 -> 27 (R2368). The `declare-final` re-tag replaced that reason blob too,
#: and its rewrite trades line numbers for `path` @ `needle` anchors: 64 -> 66
#: anchored, 28 -> 27 line-form. MEASURED BEFORE IT WAS WRITTEN, by grading the
#: draft through this gate's own `grade()` against a reasons dict with the draft
#: substituted -- which is why this number is exact rather than discovered by a
#: red. Only ONE of that reason's many line references was ever in this bucket;
#: the rest name wz's OWN files, which are not upstream claims.
#:
#: 27 -> 26 (R2369). The `liveliness-subscriber` re-tag replaced that reason
#: blob, and the one line-form citation it carried was the DEFECT the round
#: repaired: it named a line RANGE in the session API's liveliness module that
#: runs past the end of that 331-line file at the pin, because the builder had
#: moved. So this decrement retires a citation that was not merely
#: mis-formatted but NOT RESOLVING AT ALL. ⚠ That same re-tag then tried to ADD
#: a bare citation and this gate refused it, which is the ratchet working in its
#: other direction: the first mention of the builder's new path carried no
#: needle. Anchored, not budgeted.
#:
#: ⚠⚠ R2371 — the paragraph above DESCRIBES that path; it does not write it.
#: The literal was here until R2371 and it cost a hosted Layer C0 red for two
#: rounds: this file is tracked, so `upstream_citation_anchor_gate.py` scans it,
#: and a repaired citation QUOTED in the prose explaining the repair is
#: indistinguishable from a citation someone made -- it re-entered the very
#: root-less population the repair had just left (99 against a budget of 98).
#: That gate's own header carries the same warning about its own paragraphs;
#: this is the same class arriving in the sibling file.
#: 26 -> 24 (R2416). Followed DOWN, not repaired: the two that left were
#: carried out by the R2408..R2415 re-gradings, and this gate could not say so
#: because the leg ahead of it in Layer Z was red the whole time. Ratchets only
#: move down here; the direction is the gate's own instruction.
LINE_BUDGET = 24
#: 9 -> 7 (R2371). The `transport-stats` re-tag rewrote that atom's whole reason
#: against the pin. Its two bare citations both named the 1.5.0-era
#: transport-side stats module, which does not exist at 1.10.0 at all, so they
#: were not repointed but RETIRED — the replacement claims are anchored on the
#: stats crate that replaced it. One of the two was also a FINDING (see below),
#: which is why both ratchets move in the same commit.
#: 7 -> 6 (R2416), and this one was REPAIRED rather than followed. It stood at
#: 14 against a budget of 7 -- seven over, on a ratchet whose failure message
#: says never raise it -- and the overshoot was two defects, not one:
#:
#:   * THREE were `@ ABSENT` claims, the third citation direction R2337 gave
#:     this tree. `store_reasons_resolve.py` grades them and reports green;
#:     `scan()`, which this gate borrows, had never been taught the form, so it
#:     charged them to BARE. Neither gate was wrong about the store -- they
#:     disagreed about the grammar. Taught, in `upstream_citation_anchor_gate`.
#:   * FIVE were written `path` @ the `needle` -- a word between the `@` and the
#:     backtick, which defeats the anchor pattern in BOTH gates. They read as
#:     anchors to a person and were graded by nobody: the path was checked for
#:     existence and the needle was submitted to no resolver at all. Rewritten
#:     in the store, each onto a literal verified to occur in the cited file at
#:     the pin, which is what moved `anchored` 138 -> 143.
#:
#: The SIX that remain are a different defect and are left for their own rounds:
#: prose that never claimed to be an anchor.
BARE_BUDGET = 6

#: FINDINGS -- claims that do not resolve at the pin. Seeded at the inherited
#: count for the same reason the source gate seeded LINE_BUDGET at 294 rather
#: than demanding 294 repairs first: a ratchet that starts where the tree IS can
#: only shrink, while a gate that lands red is a gate someone disables.
#:
#: ⚠ WHAT THE REMAINING ONES ARE, so the number is never mistaken for noise.
#: Seven survive, and they are NOT citation-formatting defects -- they are STALE
#: GRADINGS. Five atoms were graded against zenoh 1.5.0 (57 of 78 PARTIAL atoms
#: still declare that version while the tree pins 1.10.0), and upstream has
#: since restructured underneath them:
#:   routing-token-tables, routing-peer, routing-interest-pending-gc,
#:   liveliness-token   -- cite the 1.5.0 HAT split (a p2p peer mode and a
#:     linkstate peer mode). At the pin the peer modes are COLLAPSED and the
#:     selection moved into a gateway keyed by bound + whatami, so neither the
#:     module paths NOR the functions they name (a token-interest declarer, a
#:     linkstate-peer token table) exist anywhere in the routing tree.
#:   adminspace-metrics -- cites a stats macro's non-discriminated arm and a
#:     plain-field metrics rendering. At the pin the macro is gone entirely and
#:     the surface is a label-indexed histogram in a separate stats crate.
#: Repairing these means RE-GRADING those atoms against the pin, which is a
#: round each, not a citation edit. Lower this number as each is re-graded.
#:
#: The other THREE are ordinary citation defects and each has its repair already
#: derived and its needle verified at the pin -- an absence marker for a path
#: cited BECAUSE it is gone, and two truncated paths whose real locations and
#: needles are known (one of them cites a line number that is exactly correct,
#: which is what proves the defect is the path rather than staleness). They are
#: not fixed HERE because `set-inventory-status --reason` replaces a whole
#: reason blob, so each is a surgical prose edit that belongs in its own commit
#: with its own before/after -- not a side effect of landing the instrument.
#:
#: 10 -> 9 (R2371). One of them was `transport-stats`, and it was repaired the
#: way the paragraph above prescribes: in its OWN round, as part of re-grading
#: that atom, not as a citation edit. Its unresolved claim named the 1.5.0
#: transport-side stats module; the atom was re-measured against the pin and the
#: claim replaced by anchored ones on the crate that succeeded it. That is the
#: "stale GRADING -> re-grade the atom" arm of this gate's own advice, taken.
#: 9 -> 8 (R2416). Followed DOWN, like LINE_BUDGET above and for the same
#: reason: a re-grading between R2408 and R2415 retired one unresolved claim
#: while this gate sat behind a red leg and could not report it.
FINDINGS_BUDGET = 8

#: ROOT-LESS AXIS (open debt 754). The classifier this gate borrows sorts every
#: citation into EIGHT buckets; until debt 754 was paid this gate held three and
#: computed the other five only to throw them away -- `rootless_line`,
#: `rootless_bare`, `rootless_stale_line`, the undeclared residue and their sum
#: were measured by `grade()` and never printed or budgeted, so "the store has
#: no root-less problem" and "nobody looked" printed the same thing. The source
#: gate budgets all five; these are the same five over the store's reasons, and
#: they are the only place a root-less claim in a LIVE atom reason is held.
#:
#: SEEDED AT WHAT THE COMMAND PRINTED on the landing commit, not at what anyone
#: would like them to be: a ratchet that starts where the tree is can only
#: shrink. Checked in both directions, like the three above -- ABOVE means a
#: root-less citation was written (give it its root, `path` @ `needle`), BELOW
#: means one was repaired (lower the budget in the same commit).
#:
#: The residue is measured over the store's OWN rooted citations and against the
#: tracked tree's directory names (the reasons are flat files, so the tree's
#: names are passed in rather than derived), which keeps this number a property
#: of the store alone: moving the source tree cannot move it.
ROOTLESS_LINE_BUDGET = 74
ROOTLESS_BARE_BUDGET = 10
ROOTLESS_STALE_LINE_BUDGET = 17
#: THE RESIDUE IS A TABLE, ONE ROW PER SEGMENT (open debt 799, the source gate's
#: item, which this store axis shares). A single sum cannot say whether a
#: change WROTE a root-less token or merely EXPOSED existing ones: a rooted
#: citation naming a directory nothing had cited with its root makes that name a
#: candidate and pulls every token already under it into the count. The rows
#: make the movement attributable and the refusal comes from the source gate's
#: `residue_ratchet_report`, so both gates describe an exposure the same way.
#: Seeded at what the command printed; rows only fall, a row at zero is deleted.
ROOTLESS_RESIDUE_BY_SEGMENT: dict[str, int] = {
    "auth": 1,
    "client": 1,
    "common": 3,
    "dispatcher": 10,
    "establishment": 20,
    "ext": 4,
    "multicast": 12,
    "net": 29,
    "router": 1,
    "storages_mgt": 7,
    "transport": 4,
    "unicast": 11,
    "universal": 3,
    "zenoh-backend-traits": 3,
    "zenoh-codec": 13,
    "zenoh-config": 8,
    "zenoh-link-commons": 1,
    "zenoh-link-serial": 1,
    "zenoh-link-udp": 1,
    "zenoh-link-ws": 4,
    "zenoh-protocol": 4,
    "zenoh-util": 1,
}


def rootless_undeclared_budget() -> int:
    """The residue budget as one figure: the sum of the per-segment rows."""
    return sum(ROOTLESS_RESIDUE_BY_SEGMENT.values())


#: The conservation check, as in the source gate: line + bare + residue. A
#: declaration moves an occurrence between the three and leaves this alone; a
#: new citation raises it whatever the others were set to.
ROOTLESS_TOTAL_BUDGET = 226


def live_reasons(root: pathlib.Path | None = None) -> dict[str, str]:
    """Every atom's LIVE reason -- not only the PARTIAL ones.

    `depth_axis_census.partial_atoms()` filters to PARTIAL because that is its
    subject. A citation in a COMPLETE atom's reason is just as much a claim
    about upstream, so the population here is every atom entry, with the preset
    and debt namespaces excluded exactly as the census excludes them.

    MEASURED: widening from the census's 78 PARTIAL reasons to all 214 live ones
    found ZERO additional findings, so the defect set is a property of the store
    rather than of the narrower slice.
    """
    data = json.loads(((root or ROOT) / STORE).read_text())
    entries = data.get("inventory_entries")
    if not isinstance(entries, dict):
        raise SystemExit("%s holds no `inventory_entries` mapping." % STORE)
    out = {}
    for eid, entry in entries.items():
        if eid.startswith(dc.PRESET_PREFIX) or eid.startswith(dc.DEBT_PREFIX):
            continue
        reason = (entry or {}).get("reason") or ""
        if reason.strip():
            out[eid] = reason
    return out


class Residue(typing.NamedTuple):
    """The root-less residue with its provenance: per-segment counts, which
    reason files' rooted citations taught each candidate segment, and which
    reason files hold each segment's tokens. The last two exist only so a
    refusal can say WHERE an exposure came from."""

    by_segment: dict[str, int]
    teachers: dict[str, list[str]]
    by_file: dict[str, collections.Counter]


NO_RESIDUE = Residue({}, {}, {})


def grade(reasons: dict[str, str], ref: pathlib.Path, own_dirs: set[str]):
    """Classify with the SOURCE gate's own scanner. Returns
    (counts, findings, residue).

    ⚠ `rootless_locations(ref)` IS PASSED, never `None` -- see the module
    docstring for the measurement that makes this non-negotiable.

    `counts` is the scanner's eight buckets. `residue` is the ninth
    measurement the source gate sizes beside them (open debt 754), by segment
    and with its provenance (open debt 799); its sum is the residue figure. It
    needs `own_dirs` -- the tracked tree's directory names -- because the
    reasons are materialised as flat files and have no directories of their
    own; without it `src/` and `tests/` would read as upstream candidates.
    """
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="wz-store-reasons-"))
    try:
        rels = []
        for atom, text in sorted(reasons.items()):
            rel = "%s.txt" % atom.replace("/", "_")
            (tmp / rel).write_text(text, encoding="utf-8")
            rels.append(rel)
        counts, findings = g.scan(rels, tmp, ref, g.rootless_locations(ref))
        residue = Residue(
            g.rootless_residue_by_segment(tmp, rels, own_dirs),
            g.rootless_candidate_teachers(tmp, rels, own_dirs),
            g.segment_occurrences_by_file(tmp, rels),
        )
        return counts, findings, residue
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _verdict(reasons, ref, counts, findings, residue: Residue = NO_RESIDUE) -> int:
    """The verdict layer, separated so the selftest can drive it directly."""
    if len(reasons) < MIN_REASONS:
        print(
            "FAIL: only %d live atom reason(s) found, expected at least %d. A "
            "population that collapsed means the reader stopped matching the "
            "store, not that the store stopped making claims."
            % (len(reasons), MIN_REASONS)
        )
        return 1
    if ref is None:
        print(
            "FAIL: no checkout declaring the pinned upstream version is "
            "reachable, so no claim here could be resolved. That is a SKIP, and "
            "a skip must not report green."
        )
        return 1

    print(
        "store-reason-citations: %d live atom reason(s) -- %d anchored, %d "
        "line-form (budget %d), %d bare (budget %d), %d marked @ REMOVED, "
        "%d marked @ ABSENT, %d unresolved (budget %d)"
        % (
            len(reasons),
            counts.get("anchored", 0),
            counts.get("line", 0),
            LINE_BUDGET,
            counts.get("bare", 0),
            BARE_BUDGET,
            counts.get("gone", 0),
            counts.get("absent", 0),
            len(findings),
            FINDINGS_BUDGET,
        )
    )
    rl_line = counts.get("rootless_line", 0)
    rl_bare = counts.get("rootless_bare", 0)
    rl_stale = counts.get("rootless_stale_line", 0)
    rl_residue = sum(residue.by_segment.values())
    residue_budget = rootless_undeclared_budget()
    rl_total = rl_line + rl_bare + rl_residue
    # One line per measurement the classifier produces, so an unseen axis can
    # never again read as a clean one (open debt 754).
    print(
        "store-reason-citations: root-less line %d (budget %d), root-less bare "
        "%d (budget %d), root-less stale line %d (budget %d)"
        % (rl_line, ROOTLESS_LINE_BUDGET, rl_bare, ROOTLESS_BARE_BUDGET,
           rl_stale, ROOTLESS_STALE_LINE_BUDGET)
    )
    print(
        "store-reason-citations: root-less residue %d (budget %d) under "
        "candidate segments no declaration covers; %d root-less in all "
        "(budget %d) -- declaring a segment moves an occurrence between "
        "these, it never changes the total"
        % (rl_residue, residue_budget, rl_total, ROOTLESS_TOTAL_BUDGET)
    )

    rc = 0
    for name, got, budget in (
        ("line", counts.get("line", 0), LINE_BUDGET),
        ("bare", counts.get("bare", 0), BARE_BUDGET),
    ):
        if got == budget:
            continue
        rc = 1
        if got > budget:
            print(
                "FAIL: %d %s-form citation(s), budget %d. This commit ADDED one. "
                "Upstream claims carry no line numbers (owner, 2026-09-01): "
                "write it as `path` @ `needle`; never raise the budget."
                % (got, name, budget)
            )
        else:
            print(
                "FAIL: %d %s-form citation(s), budget %d. This commit REMOVED "
                "one, which is the direction we want: lower %s_BUDGET to %d in "
                "this same commit so the ratchet holds."
                % (got, name, budget, name.upper(), got)
            )

    for label, got, budget, const in (
        ("root-less line-form", rl_line, ROOTLESS_LINE_BUDGET, "ROOTLESS_LINE_BUDGET"),
        ("root-less bare-form", rl_bare, ROOTLESS_BARE_BUDGET, "ROOTLESS_BARE_BUDGET"),
        ("root-less stale-line", rl_stale, ROOTLESS_STALE_LINE_BUDGET,
         "ROOTLESS_STALE_LINE_BUDGET"),
    ):
        if got == budget:
            continue
        rc = 1
        if got > budget:
            print(
                "FAIL: %d %s citation(s), budget %d. This commit ADDED one (or "
                "taught a new candidate segment). Write the citation with its "
                "root, in the `path` @ `needle` form; never raise the budget."
                % (got, label, budget)
            )
        else:
            print(
                "FAIL: %d %s citation(s), budget %d. This commit REMOVED one, "
                "which is the direction we want: lower %s to %d in this same "
                "commit so the ratchet holds." % (got, label, budget, const, got)
            )
    # The residue, one segment at a time (open debt 799): which segment moved
    # and which file's rooted citation taught it is what separates a token that
    # was WRITTEN from one that was merely EXPOSED.
    row_reports = g.residue_ratchet_report(
        ROOTLESS_RESIDUE_BY_SEGMENT, residue.by_segment, residue.teachers,
        residue.by_file, g.ROOTLESS_SEGMENTS,
        budget_name="ROOTLESS_RESIDUE_BY_SEGMENT",
    )
    if row_reports:
        rc = 1
        print(
            "FAIL: the root-less residue is %d against a budget of %d, and %d "
            "segment(s) moved:" % (rl_residue, residue_budget, len(row_reports))
        )
        for report in row_reports:
            print("    - %s" % report)
    if rl_total != ROOTLESS_TOTAL_BUDGET:
        rc = 1
        if rl_total > ROOTLESS_TOTAL_BUDGET:
            print(
                "FAIL: %d root-less occurrence(s) in all, budget %d. Declaring "
                "a segment cannot move this number -- an occurrence only "
                "leaves the residue for a bucket -- so a rise is a token that "
                "was WRITTEN or EXPOSED (a rooted citation of a directory "
                "nothing had cited with its root makes it a candidate and "
                "brings the tokens already under it into the count). The "
                "per-segment lines above say which. Give each token its root, "
                "in the `path` @ `needle` form; never raise this budget."
                % (rl_total, ROOTLESS_TOTAL_BUDGET)
            )
        else:
            print(
                "FAIL: %d root-less occurrence(s) in all, budget %d. This "
                "commit REMOVED one: a citation was given its root or marked "
                "@ REMOVED. Lower ROOTLESS_TOTAL_BUDGET to %d in this same "
                "commit so the ratchet holds."
                % (rl_total, ROOTLESS_TOTAL_BUDGET, rl_total)
            )

    if len(findings) != FINDINGS_BUDGET:
        rc = 1
        moved = "ADDED" if len(findings) > FINDINGS_BUDGET else "REMOVED"
        print(
            "FAIL: %d claim(s) do not resolve at the pin, budget %d. This commit "
            "%s one." % (len(findings), FINDINGS_BUDGET, moved)
        )
        for f in findings:
            print("    - %s" % (f,))
        print(
            "      A path that MOVED is repaired by repointing it and adding a\n"
            "      needle. A path named BECAUSE it is gone is repaired with the\n"
            "      absence marker -- making that one resolve would make a true\n"
            "      sentence false. A claim whose SUBJECT is gone upstream is a\n"
            "      stale GRADING: re-grade the atom, do not edit the citation."
        )
    if rc == 0:
        print("store-reason-citations OK")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="judge upstream claims in live atom reasons")
    ap.add_argument("--check", action="store_true", help="read the real store")
    ap.add_argument("--selftest", action="store_true", help="drive the classifier and the verdicts")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    reasons = live_reasons()
    if len(reasons) < MIN_REASONS:
        return _verdict(reasons, None, {}, [])
    ref = g.upstream_root()
    if ref is None:
        return _verdict(reasons, None, {}, [])
    own_dirs = g.own_directory_names(g.tracked_files(ROOT))
    counts, findings, residue = grade(reasons, ref, own_dirs)
    return _verdict(reasons, ref, counts, findings, residue)


# ── selftest ────────────────────────────────────────────────────────────────
# Fixture paths are BUILT, never written: a literal here would be a citation.
_ROOTDIR = "io"
_CRATE = "zzz-fixture-crate"
_GONE = _ROOTDIR + "/" + _CRATE + "/src/" + "vanished.rs"
_LIVES = _ROOTDIR + "/" + _CRATE + "/src/" + "present.rs"


# A DECLARED root-less segment, read from the source gate rather than written,
# so the fixture follows the declaration if it ever changes. The file lives
# under a `<segment>/` directory of the fake pin, which is what the per-citation
# resolution rule needs in order to find it exactly once.
_SEG = g.ROOTLESS_SEGMENTS[0]
_RL_LIVES = _SEG + "/" + "rl_present.rs"
# A token under a segment the fixture teaches through a ROOTED citation of the
# crate directory and that no declaration covers: the undeclared residue.
_RESIDUE = _CRATE + "/" + "src/" + "present.rs"


def _fake_pin(tmp: pathlib.Path) -> pathlib.Path:
    ref = tmp / "ref"
    p = ref / _ROOTDIR / _CRATE / "src"
    p.mkdir(parents=True)
    (p / "present.rs").write_text("fn needle_here() {}\n" * 20, encoding="utf-8")
    (p / _SEG).mkdir()
    (p / _SEG / "rl_present.rs").write_text("fn rl_here() {}\n" * 20, encoding="utf-8")
    return ref


def selftest() -> int:
    """Both layers. The classifier arms pin one bucket decision each; the
    verdict arms pin the three claims the docstring makes, including the
    no-checkout FAIL -- the one branch a run on a provisioned machine can never
    take, and therefore the one that would otherwise ship untested.

    The absence marker is driven in BOTH directions: a marked path that IS gone
    must not be a finding, and one that STILL EXISTS must be. Get either
    backwards and the marker becomes an off switch.
    """
    failures = 0
    cases = [
        ("an anchored claim on a live path resolves",
         "The surface is `%s` @ `needle_here`, mirrored here." % _LIVES,
         {"anchored": 1}, 0),
        ("a line-form claim counts as line, not anchored",
         "See %s:3 for the shape." % _LIVES, {"line": 1, "anchored": 0}, 0),
        ("a bare mention counts as bare",
         "The upstream file %s carries it." % _LIVES, {"bare": 1}, 0),
        ("a line PAST the end of a live file is a finding",
         "See %s:9999 for the shape." % _LIVES, {"line": 1}, 1),
        ("a claim on a path GONE at the pin is a finding",
         "See %s:12 for the shape." % _GONE, {"line": 1}, 1),
        ("a path marked absent, and it IS gone, is NOT a finding",
         "The old module `%s` @ REMOVED -- upstream folded it away." % _GONE,
         {"gone": 1}, 0),
        ("a path marked absent that STILL EXISTS is a finding",
         "The old module `%s` @ REMOVED -- upstream folded it away." % _LIVES,
         {"gone": 1}, 1),
        # R2416. The third direction, and the row that pins THIS gate's stake in
        # it: an `@ ABSENT` claim must land in its own bucket and NOT be charged
        # to `bare`. Seven rounds of this gate's red were that one number.
        ("a needle asserted absent, and it IS absent, is NOT a finding",
         "The capability is gone: `%s` @ ABSENT `fn withdrawn()`." % _LIVES,
         {"absent": 1, "bare": 0}, 0),
        ("a needle asserted absent that came BACK is a finding",
         "The capability is gone: `%s` @ ABSENT `needle_here`." % _LIVES,
         {"absent": 1, "bare": 0}, 1),
        # Open debt 754. The five root-less measurements are the ones the
        # verdict used to drop, so each gets a row pinning that the CLASSIFIER
        # puts the citation in that bucket and no other.
        ("a root-less line on a live file counts rootless_line, nothing stale",
         "See %s:3 for the shape." % _RL_LIVES,
         {"rootless_line": 1, "rootless_stale_line": 0, "rootless_bare": 0,
          "line": 0}, 0),
        ("a root-less line PAST the end is stale, and not a finding",
         "See %s:9999 for the shape." % _RL_LIVES,
         {"rootless_line": 1, "rootless_stale_line": 1}, 0),
        ("a root-less bare path counts rootless_bare, not bare",
         "The upstream file %s carries it." % _RL_LIVES,
         {"rootless_bare": 1, "bare": 0}, 0),
        ("a token under a taught segment no declaration covers is residue",
         "The surface is `%s` @ `needle_here`; compare %s too." % (_LIVES, _RESIDUE),
         {"rootless_undeclared": 1}, 0),
        ("a segment that is the TREE's own directory is not residue",
         "The surface is `%s` @ `needle_here`; compare %s too." % (_LIVES, _RESIDUE),
         {"rootless_undeclared": 0}, 0, {_CRATE}),
    ]
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="wz-store-selftest-"))
    try:
        ref = _fake_pin(tmp)
        for name, reason, want_counts, want_find, *own in cases:
            counts, findings, residue = grade(
                {"fixture-atom": reason}, ref, own[0] if own else set()
            )
            counts["rootless_undeclared"] = sum(residue.by_segment.values())
            bad = [k for k, v in want_counts.items() if counts.get(k, 0) != v]
            if bad or len(findings) != want_find:
                print("  selftest FAIL  %s: counts=%s findings=%d"
                      % (name, {k: counts.get(k, 0) for k in want_counts}, len(findings)))
                failures += 1
            else:
                print("  selftest ok    %s" % name)

        # Open debt 799: the residue keeps its PROVENANCE. The same two tokens
        # in one atom, with and without a rooted citation of their directory in
        # another atom -- the only difference between the two runs is the
        # teaching line, and the second must say which file it is in.
        tokens = {"atom-tokens": "Compare %s, and %s again." % (_RESIDUE, _RESIDUE)}
        teach = {"atom-teacher": "The surface is `%s` @ `needle_here`." % _LIVES}
        _c, _f, before = grade(tokens, ref, set())
        _c, _f, after = grade({**tokens, **teach}, ref, set())
        for name, ok in (
            ("tokens with no rooted citation of their directory are not residue",
             before.by_segment == {}),
            ("one teaching citation in ANOTHER atom exposes both tokens",
             after.by_segment == {_CRATE: 2}),
            ("the residue names the atom whose citation taught the segment",
             after.teachers.get(_CRATE) == ["atom-teacher.txt"]),
            ("the residue names the atom holding the exposed tokens",
             dict(after.by_file.get(_CRATE, {})) == {"atom-tokens.txt": 2}),
        ):
            if ok:
                print("  selftest ok    %s" % name)
            else:
                print("  selftest FAIL  %s" % name)
                failures += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    big = {("atom%03d" % i): "prose" for i in range(MIN_REASONS + 5)}
    clean = {"anchored": 3, "line": LINE_BUDGET, "bare": BARE_BUDGET, "gone": 1,
             "rootless_line": ROOTLESS_LINE_BUDGET,
             "rootless_bare": ROOTLESS_BARE_BUDGET,
             "rootless_stale_line": ROOTLESS_STALE_LINE_BUDGET}
    # The residue ON its per-segment budget, and the segment the moves below
    # are made on: the largest row, so a REMOVED move can never reach zero.
    clean_res = Residue(dict(ROOTLESS_RESIDUE_BY_SEGMENT), {}, {})
    big_seg = max(ROOTLESS_RESIDUE_BY_SEGMENT, key=ROOTLESS_RESIDUE_BY_SEGMENT.get)

    def moved(delta: int, seg: str = big_seg) -> Residue:
        rows = dict(ROOTLESS_RESIDUE_BY_SEGMENT)
        rows[seg] = rows.get(seg, 0) + delta
        return Residue(rows, {}, {})

    findings7 = ["f%d" % i for i in range(FINDINGS_BUDGET)]
    x = pathlib.Path("/x")
    verdicts = [
        ("a collapsed population FAILs", {"only": "one"}, None, {}, [], clean_res, 1),
        ("no checkout declaring the pin FAILs (not a skip)", big, None, {}, [],
         clean_res, 1),
        ("on-budget returns 0", big, x, clean, findings7, clean_res, 0),
        ("a line-form citation ADDED FAILs", big, x,
         dict(clean, line=LINE_BUDGET + 1), findings7, clean_res, 1),
        ("a line-form citation REMOVED FAILs (ratchet down)", big, x,
         dict(clean, line=LINE_BUDGET - 1), findings7, clean_res, 1),
        ("an ADDED unresolved claim FAILs", big, x, clean,
         findings7 + ["extra"], clean_res, 1),
        ("a REMOVED unresolved claim FAILs (ratchet down)", big, x,
         clean, findings7[:-1], clean_res, 1),
    ]
    # Open debt 754: each root-less measurement is checked in BOTH directions.
    # Every row moves exactly one measurement, so a verdict that still ignored
    # that measurement returns 0 and fails the row.
    for key, budget in (
        ("rootless_line", ROOTLESS_LINE_BUDGET),
        ("rootless_bare", ROOTLESS_BARE_BUDGET),
        ("rootless_stale_line", ROOTLESS_STALE_LINE_BUDGET),
    ):
        for word, delta in (("ADDED", 1), ("REMOVED", -1)):
            verdicts.append((
                "a %s %s occurrence FAILs" % (word, key), big, x,
                dict(clean, **{key: budget + delta}), findings7, clean_res, 1))
    for word, delta in (("ADDED", 1), ("REMOVED", -1)):
        verdicts.append((
            "a %s residue occurrence FAILs" % word, big, x, clean, findings7,
            moved(delta), 1))
    for name, reasons, ref, counts, findings, residue, want in verdicts:
        rc = _verdict(reasons, ref, counts, findings, residue)
        if rc != want:
            print("  selftest FAIL  %s: rc=%d want %d" % (name, rc, want))
            failures += 1
        else:
            print("  selftest ok    %s" % name)

    # PRINTED, not only checked: the defect of open debt 754 was that three
    # buckets were computed and never shown, so a pass and an unseen axis read
    # the same. The summary line must name every root-less measurement.
    shown = io.StringIO()
    with contextlib.redirect_stdout(shown):
        _verdict(big, x, clean, findings7, clean_res)
    text = shown.getvalue()
    for needle in ("root-less line", "root-less bare", "root-less stale",
                   "root-less residue", "root-less in all"):
        if needle not in text:
            print("  selftest FAIL  the summary never prints %r" % needle)
            failures += 1
        else:
            print("  selftest ok    the summary prints %r" % needle)

    # CONSERVATION: moving one occurrence from the residue into a declared
    # bucket is what a DECLARATION does. The three per-bucket ratchets must
    # fire, and the total must stay silent -- that silence is the proof it is
    # a declaration and not a new citation.
    shown = io.StringIO()
    with contextlib.redirect_stdout(shown):
        rc = _verdict(big, x,
                      dict(clean, rootless_line=ROOTLESS_LINE_BUDGET + 1),
                      findings7, moved(-1))
    if rc != 1 or "in all, budget" in shown.getvalue():
        print("  selftest FAIL  a declaration-shaped move fired the total (rc=%d)" % rc)
        failures += 1
    else:
        print("  selftest ok    a declaration-shaped move leaves the total silent")

    # The converse: a NEW citation raises the residue and nothing leaves, so
    # the total must fire on its own account.
    shown = io.StringIO()
    with contextlib.redirect_stdout(shown):
        rc = _verdict(big, x, clean, findings7, moved(1))
    if rc != 1 or "in all, budget" not in shown.getvalue():
        print("  selftest FAIL  a new root-less citation did not fire the total")
        failures += 1
    else:
        print("  selftest ok    a new root-less citation fires the total")

    # Open debt 799: WHAT THE REFUSAL SAYS about an exposure. A segment with no
    # row, taught by one atom and held by another, must be named with both.
    exposed = Residue(
        dict(ROOTLESS_RESIDUE_BY_SEGMENT, **{_CRATE: 2}),
        {_CRATE: ["atom-teacher.txt"]},
        {_CRATE: collections.Counter({"atom-tokens.txt": 2})},
    )
    shown = io.StringIO()
    with contextlib.redirect_stdout(shown):
        rc = _verdict(big, x, clean, findings7, exposed)
    text = shown.getvalue()
    for what, needle in (
        ("names the exposed segment", "NEW candidate segment `%s`" % _CRATE),
        ("names the atom whose citation taught it", "atom-teacher.txt"),
        ("names the atom holding the tokens, with the count", "atom-tokens.txt x2"),
        ("says the repair is a fixed point", "fixed point"),
        ("says the total can be moved by exposure", "EXPOSED"),
    ):
        if rc != 1 or needle not in text:
            print("  selftest FAIL  the exposure refusal never %s (rc=%d)" % (what, rc))
            failures += 1
        else:
            print("  selftest ok    the exposure refusal %s" % what)

    dead = [s for s, n in ROOTLESS_RESIDUE_BY_SEGMENT.items() if n <= 0]
    double = sorted(set(ROOTLESS_RESIDUE_BY_SEGMENT) & set(g.ROOTLESS_SEGMENTS))
    if dead or double:
        print("  selftest FAIL  residue table carries dead rows: zero %s, declared %s"
              % (dead, double))
        failures += 1
    else:
        print("  selftest ok    the residue table carries no dead row")

    if failures:
        print("store-reason-citations selftest: %d failure(s)" % failures)
        return 1
    print("store-reason-citations selftest OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

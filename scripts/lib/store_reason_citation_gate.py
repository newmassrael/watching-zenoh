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
import json
import pathlib
import shutil
import sys
import tempfile

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
LINE_BUDGET = 27
BARE_BUDGET = 9

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
FINDINGS_BUDGET = 10


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


def grade(reasons: dict[str, str], ref: pathlib.Path):
    """Classify with the SOURCE gate's own scanner. Returns (counts, findings).

    ⚠ `rootless_locations(ref)` IS PASSED, never `None` -- see the module
    docstring for the measurement that makes this non-negotiable.
    """
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="wz-store-reasons-"))
    try:
        rels = []
        for atom, text in sorted(reasons.items()):
            rel = "%s.txt" % atom.replace("/", "_")
            (tmp / rel).write_text(text, encoding="utf-8")
            rels.append(rel)
        return g.scan(rels, tmp, ref, g.rootless_locations(ref))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _verdict(reasons, ref, counts, findings) -> int:
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
        "line-form (budget %d), %d bare (budget %d), %d marked absent, %d "
        "unresolved (budget %d)"
        % (
            len(reasons),
            counts.get("anchored", 0),
            counts.get("line", 0),
            LINE_BUDGET,
            counts.get("bare", 0),
            BARE_BUDGET,
            counts.get("gone", 0),
            len(findings),
            FINDINGS_BUDGET,
        )
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
    counts, findings = grade(reasons, ref)
    return _verdict(reasons, ref, counts, findings)


# ── selftest ────────────────────────────────────────────────────────────────
# Fixture paths are BUILT, never written: a literal here would be a citation.
_ROOTDIR = "io"
_CRATE = "zzz-fixture-crate"
_GONE = _ROOTDIR + "/" + _CRATE + "/src/" + "vanished.rs"
_LIVES = _ROOTDIR + "/" + _CRATE + "/src/" + "present.rs"


def _fake_pin(tmp: pathlib.Path) -> pathlib.Path:
    ref = tmp / "ref"
    p = ref / _ROOTDIR / _CRATE / "src"
    p.mkdir(parents=True)
    (p / "present.rs").write_text("fn needle_here() {}\n" * 20, encoding="utf-8")
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
    ]
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="wz-store-selftest-"))
    try:
        ref = _fake_pin(tmp)
        for name, reason, want_counts, want_find in cases:
            counts, findings = grade({"fixture-atom": reason}, ref)
            bad = [k for k, v in want_counts.items() if counts.get(k, 0) != v]
            if bad or len(findings) != want_find:
                print("  selftest FAIL  %s: counts=%s findings=%d"
                      % (name, {k: counts.get(k, 0) for k in want_counts}, len(findings)))
                failures += 1
            else:
                print("  selftest ok    %s" % name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    big = {("atom%03d" % i): "prose" for i in range(MIN_REASONS + 5)}
    clean = {"anchored": 3, "line": LINE_BUDGET, "bare": BARE_BUDGET, "gone": 1}
    findings7 = ["f%d" % i for i in range(FINDINGS_BUDGET)]
    verdicts = [
        ("a collapsed population FAILs", {"only": "one"}, None, {}, [], 1),
        ("no checkout declaring the pin FAILs (not a skip)", big, None, {}, [], 1),
        ("on-budget returns 0", big, pathlib.Path("/x"), clean, findings7, 0),
        ("a line-form citation ADDED FAILs", big, pathlib.Path("/x"),
         dict(clean, line=LINE_BUDGET + 1), findings7, 1),
        ("a line-form citation REMOVED FAILs (ratchet down)", big, pathlib.Path("/x"),
         dict(clean, line=LINE_BUDGET - 1), findings7, 1),
        ("an ADDED unresolved claim FAILs", big, pathlib.Path("/x"), clean,
         findings7 + ["extra"], 1),
        ("a REMOVED unresolved claim FAILs (ratchet down)", big, pathlib.Path("/x"),
         clean, findings7[:-1], 1),
    ]
    for name, reasons, ref, counts, findings, want in verdicts:
        rc = _verdict(reasons, ref, counts, findings)
        if rc != want:
            print("  selftest FAIL  %s: rc=%d want %d" % (name, rc, want))
            failures += 1
        else:
            print("  selftest ok    %s" % name)

    if failures:
        print("store-reason-citations selftest: %d failure(s)" % failures)
        return 1
    print("store-reason-citations selftest OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

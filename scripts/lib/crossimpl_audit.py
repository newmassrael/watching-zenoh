#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y259 — Layer A4: join the catalog to the cross-impl proof corpus.

Driven by scripts/audit-crossimpl-proof.sh, which documents the motivation and the
seven invariants. This module is the join itself.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import crossimpl_corpus as corpus  # noqa: E402
import feature_closure as fc  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

# ── The DENOMINATOR, declared and gated ─────────────────────────────────────────
#
# `built` (= active + FOUNDATIONAL + PARTIAL, from the R311y257 implementation axis)
# is NOT the denominator: 25 of those atoms cannot be witnessed by ANY foreign peer,
# ever, by construction. Leaving them in would manufacture an unproven list that can
# never reach zero -- and a gate nobody can close is a gate everyone learns to ignore.
#
# So the exclusion is DECLARED here, per atom, with its reason -- and then made
# FALSIFIABLE by invariant A4-6: if any corpus test ever does witness one of these,
# the gate FAILS and the exclusion was wrong. That is "derive, then gate" applied to
# the denominator itself, not an exception to it.
#
# NOTE on what does NOT belong here: "pico does not implement this mechanism" is NOT
# a reason to exclude. A pico binary is still a perfectly good foreign counterparty
# for an atom pico itself lacks -- the canonical proof of `routing-routes` (which pico
# has no analog of) is pico-publisher -> wz-router -> pico-subscriber. Non-observable
# means no foreign peer can produce or observe ANY difference, not "the peer lacks the
# feature".
FOREIGN_NON_OBSERVABLE = {
    # Host / executor substrate — the wire is byte-identical either way.
    "platform-linux": "host substrate; no peer can tell which target triple wz was built for",
    "platform-bare-metal": "host substrate; selected by target-triple + no_std, not a wire trait",
    "platform-freertos": "host substrate; swaps clock/allocator, not the wire",
    "platform-zephyr": "host substrate; swaps clock/allocator, not the wire",
    "runtime-tokio": "executor choice is invisible on the wire (tokio vs coop emit identical bytes)",
    "runtime-coop": "executor choice is invisible on the wire",
    "runtime-no-std": "build shape, not wire shape",
    # Build-time mechanism.
    "plugin-static-registration": "cargo [features] + cfg IS the mechanism; no runtime artifact at all",
    # Pure cargo aliases / re-views of an atom that is itself counted.
    "link-frame": "alias view of codec-frame (the observable Frame envelope), would double-count",
    "link-fragment": "alias of transport-fragmentation",
    "link-batching": "alias of transport-batching",
    "attachment-encoding-aware": "typed DATA-VIEW over attachment-bytes; not a separate wire toggle",
    # Purely local state.
    "transport-stats": "byte/msg counters; counting bytes changes no byte",
    "routing-route-cache": "a cache: same routes, computed faster; unobservable by construction",
    # Internal seams / traits / factories — remove them and the wire is identical.
    "routing-interceptor-framework": "the factory seam; the wire effect belongs to the access-* interceptors",
    "router-hat-multihat": "Box<dyn Any> polymorphism seam; monomorphic router emits identical wire",
    "config-plugin-validator": "inert validator hook (self-declared foundational-inert)",
    "config-change-notifier": "in-process observer over the local config tree; no wire",
    "config-json-pointer-access": "local config-tree manipulation; no wire",
    "time-timestamp-source": "selector seam; the observable stamp belongs to pubsub-timestamp",
    "storage-backend-capability": "a struct+enum data model; effects belong to storage-backend/-history",
    "storage-backend-volume-trait": "a Rust factory trait; no independent wire artifact",
    "storage-mgr-config": "declarative data model; effects belong to the storage-mgr-* atoms",
    # Declared wz-superset with no zenoh analog / no wire surface.
    "switchboard": "P=no zenoh equiv; the wire is a plain Push (already codec-push/declare-subscriber). "
                   "What wz does with the decoded Sample is not foreign-observable",
    "pubsub-allow-loop": "same-process delivery; zero wz-session-core sites, so it emits no bytes",
}

IMPL_TAGS_BUILT = {"FOUNDATIONAL", "PARTIAL"}
KIND_CLASS = corpus.KIND_CLASS

# ── Execution disclosure ────────────────────────────────────────────────────────
#
# A proof that never runs is not a proof. The interop tests are #[ignore]d and their
# lanes SKIP (green) when the foreign binaries are absent, so "proven" could otherwise
# be reported off a test that has never executed anywhere — a number with MORE false
# authority than the hand estimate it replaces.
#
# Which lane carries which class is a small declared map; WHICH LANES HOSTED CI ACTUALLY
# RUNS is derived from .github/workflows/ci.yml, so the disclosure cannot rot when the
# workflow changes. Today: hosted CI never builds zenohd and never runs --layer Z, so
# every zenohd proof executes only in the local full run-ci (which the pre-push hook
# runs). That is disclosed, not hidden.
CLASS_LANES = {
    "codec": ["C1"],          # linked pico C; NOT #[ignore]d -- runs on every push
    "pico": ["E", "E2", "E6", "E7", "E8", "M"],
    "zenohd": ["Z"],
}


def hosted_ci_layers() -> set[str]:
    """Which lanes hosted CI runs -- from the `run:` STEPS of ci.yml, not its prose.

    Regexing the whole file scrapes lane names out of comments (it was picking up a
    phantom lane `X` from a sentence about `--layer X`), and a comment like "Layer Z is
    deliberately NOT run here" would then invert the one honest disclosure this gate
    makes. Parse what executes, not what is written about.
    """
    wf = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    if not wf.is_file():
        return set()
    lanes: set[str] = set()
    for line in wf.read_text().splitlines():
        s = line.strip()
        if not s.startswith("run:"):
            continue
        lanes.update(re.findall(r"--layer ([A-Za-z0-9]+)", s))
    return lanes


def layer_e_skips() -> list[str]:
    """The --skip substrings Layer E passes to libtest, derived from run-ci.sh.

    Layer E is the ONLY interop lane hosted CI runs, and it deliberately skips the test
    families that belong to lanes hosted CI does not run. A test's name matching any of
    these means Layer E does not execute it.
    """
    txt = (REPO_ROOT / "scripts" / "run-ci.sh").read_text()
    m = re.search(r"layer_e_ap_demo_round_trip\(\).*?\n}", txt, re.S)
    return re.findall(r"--skip ([A-Za-z0-9_]+)", m.group(0)) if m else []


def ci_executes(test, cf) -> bool:
    """Does hosted CI actually RUN this test?

    A proof that never runs is not a proof. 64 of the 133 corpus tests are #[ignore]d,
    and the lanes that would run them (Z / E2 / E6-E8 / M) are not in ci.yml -- hosted CI
    does not even build zenohd. Counting those claims into a single `proven` number would
    carry MORE false authority than the hand estimate this axis replaces, so the roll-up
    reports the two populations separately.

      - NOT #[ignore]d -> Layer C1 (`cargo test --workspace`) runs it on every push. This
        is how the 25 `codec` files (the linked-pico-C byte-compares) execute.
      - #[ignore]d     -> only Layer E among the hosted lanes runs ignored tests, and it
                          skips by test-name substring.
    """
    if not test.has_ignore:
        return "C1" in HOSTED
    if "E" not in HOSTED:
        return False
    return not any(s in test.name for s in E_SKIPS)


HOSTED = hosted_ci_layers()
E_SKIPS = layer_e_skips()

# Which binary a corpus test drives comes from the corpus module's CALL-GRAPH resolution
# (cf.binary), not from a grep in this file -- a grep here would re-introduce exactly the
# defect crossimpl_corpus.py exists to fix, and A4-5 would then check the wrong binary's
# closure (wz-integration-tests and wz-ap-demo are NOT nested: 17 denominator features
# are in the former and not the latter).


def impl_tag(reason: str | None) -> str | None:
    head = (reason or "").split(":")[0].split("(")[0].strip().upper()
    return head if head else None


def main() -> int:
    inv = json.load(open(os.environ["INV_FILE"]))
    entries = inv if isinstance(inv, list) else inv.get("entries", inv.get("inventory", []))

    status: dict[str, str] = {}
    reason: dict[str, str] = {}
    for e in entries:
        aid = e.get("id") or e.get("inventory_id")
        if not aid or aid.startswith("preset-"):
            continue
        status[aid] = e.get("status")
        # session-matching's reason is JSON null, not "" -- a .split() on it throws.
        reason[aid] = e.get("reason") or ""

    built = {
        a for a in status
        if status[a] == "active" or impl_tag(reason[a]) in IMPL_TAGS_BUILT
    }
    denominator = built - set(FOREIGN_NON_OBSERVABLE)

    # Include any file that is in the corpus OR says anything about proof -- including a
    # file whose only `wz-proves` line is MALFORMED. Filtering on `declared` alone would
    # drop a typo'd claim out of the scan before the malformed-line invariant could report
    # it, so the one lint that catches "you meant to claim something" would be the one
    # lint a typo escapes.
    files = [
        cf for cf in corpus.scan_all()
        if cf.classes
        or cf.stray_claims
        or any(t.declared or t.bad_claim_lines for t in cf.tests)
    ]

    fail_name, fail_denominator, fail_foreign = [], [], []
    fail_undeclared, fail_containment, fail_excluded, fail_kind, fail_malformed = [], [], [], [], []

    # (full/partial) x (all lanes / only the lanes hosted CI actually runs)
    proven_full: dict[str, set[str]] = {}   # atom -> {kinds}
    proven_partial: dict[str, set[str]] = {}
    ci_full: set[str] = set()
    ci_partial: set[str] = set()
    none_tests: list[tuple[str, str, str]] = []
    closures: dict[str, frozenset[str]] = {}
    n_ignored = 0

    for cf in files:
        rel = str(cf.path.relative_to(REPO_ROOT))
        pkg = cf.binary
        if pkg not in closures:
            closures[pkg] = fc.binary_closure(pkg)
        closure = closures[pkg]

        for ln, txt in cf.stray_claims:
            fail_malformed.append((rel, ln, txt))

        for t in cf.tests:
            for ln, txt in t.bad_claim_lines:
                fail_malformed.append((rel, ln, txt))

            if not cf.classes:
                # A4-3: a wz<->wz test may not claim foreign proof.
                if t.claims or t.none_reason:
                    fail_foreign.append((rel, t.name))
                continue

            # A4-4: every corpus test declares something.
            if not t.declared:
                fail_undeclared.append((rel, t.name))
                continue

            if t.has_ignore:
                n_ignored += 1
            runs_in_ci = ci_executes(t, cf)

            if t.none_reason is not None and not t.claims:
                none_tests.append((rel, t.name, t.none_reason))
                continue

            for atom, kind, partial in t.claims:
                if atom not in status:
                    fail_name.append((rel, t.name, atom))
                    continue
                if atom in FOREIGN_NON_OBSERVABLE:
                    fail_excluded.append((rel, t.name, atom))
                    continue
                if atom not in denominator:
                    fail_denominator.append((rel, t.name, atom, status[atom]))
                    continue
                if not (KIND_CLASS[kind] & cf.classes):
                    fail_kind.append((rel, t.name, atom, kind, ",".join(sorted(cf.classes))))
                    continue
                # A4-5 containment applies ONLY to cfg-gated (active) atoms.
                #
                # A FOUNDATIONAL atom has ZERO cfg(feature=..) sites by A3 invariant #2 --
                # its code is compiled unconditionally, whether or not its `= []` cargo key
                # happens to be enabled in this build graph. So "the feature is not enabled"
                # does NOT mean "the code is absent", and containment cannot refute it. Only
                # an active atom's code can actually be elided by not enabling its feature,
                # and that is exactly the case this arm is built to refute.
                if status[atom] == "active" and atom not in closure:
                    fail_containment.append((rel, t.name, atom, pkg))
                    continue
                bucket = proven_partial if partial else proven_full
                bucket.setdefault(atom, set()).add(kind)
                if runs_in_ci:
                    (ci_partial if partial else ci_full).add(atom)

    # An atom proven fully by ANY test outranks a partial claim elsewhere.
    full = set(proven_full)
    partial = set(proven_partial) - full
    unproven = sorted(denominator - full - partial)
    ci_full_only = ci_full
    ci_partial_only = ci_partial - ci_full
    ci_unproven = denominator - ci_full_only - ci_partial_only
    # The dishonest case the split exists to expose: an atom whose ONLY witness hosted CI
    # runs is a `partial`, promoted to `proven` by a `full` claim on a test CI never runs.
    promoted_by_unrun = sorted(full & ci_partial_only)

    ok = not (fail_name or fail_denominator or fail_foreign or fail_undeclared
              or fail_containment or fail_excluded or fail_kind or fail_malformed)

    corpus_files = [cf for cf in files if cf.classes]
    n_tests = sum(len(cf.tests) for cf in corpus_files)
    by_class: dict[str, int] = {}
    for cf in corpus_files:
        by_class[",".join(sorted(cf.classes))] = by_class.get(",".join(sorted(cf.classes)), 0) + 1

    print("=== cross-impl proof audit ===")
    print("  corpus: %d files / %d tests  [%s]" % (
        len(corpus_files), n_tests,
        " ".join("%s=%d" % (k, v) for k, v in sorted(by_class.items()))))
    print("  denominator = built(%d) - foreign-NON-observable(%d) = %d"
          % (len(built), len(FOREIGN_NON_OBSERVABLE), len(denominator)))
    print("  CROSS-IMPL PROOF [all lanes, incl. local-only]: proven=%d partial=%d unproven=%d"
          % (len(full), len(partial), len(unproven)))
    print("  CROSS-IMPL PROOF [executed by hosted CI]:       proven=%d partial=%d unproven=%d"
          % (len(ci_full_only), len(ci_partial_only), len(ci_unproven)))
    print("    (%d of the %d corpus tests are #[ignore]d. A proof that never runs is not a"
          % (n_ignored, n_tests))
    print("     proof, so the two populations are reported separately rather than fused into")
    print("     one number -- a fused number would carry MORE false authority than the hand")
    print("     estimate this axis replaces. Counts, never a percentage: R311jl already ruled")
    print("     that a single number against an unnamed denominator is the error here, and")
    print("     these are NOT comparable to the legacy ~75% zenoh-pico-parity figure.)")
    if promoted_by_unrun:
        print("  PROMOTED BY A TEST HOSTED CI NEVER RUNS (%d): %s"
              % (len(promoted_by_unrun), ", ".join(promoted_by_unrun)))
        print("     (hosted CI's only witness for each of these is a `partial`; the `full`")
        print("      claim comes from a lane it does not run.)")
    print("  UNPROVEN (%d, actionable): %s" % (len(unproven), ", ".join(unproven) if unproven else "(none)"))
    print("  witnesses-no-atom (declared `none`): %d" % len(none_tests))

    hosted = hosted_ci_layers()
    for cls in sorted(CLASS_LANES):
        lanes = CLASS_LANES[cls]
        run_here = [x for x in lanes if x in hosted]
        skipped = [x for x in lanes if x not in hosted]
        note = "hosted CI runs %s" % "/".join(run_here) if run_here else "NOT RUN in hosted CI"
        if skipped:
            note += "; %s only in the local full run-ci (pre-push)" % "/".join(skipped)
        print("  EXECUTION [%s]: %s" % (cls, note))

    if fail_malformed:
        ok = False
        print("FAIL: malformed or unattached wz-proves line: %d" % len(fail_malformed))
        for rel, ln, txt in fail_malformed:
            print("    - %s:%d  %s" % (rel, ln, txt))
        print("    (grammar: `// wz-proves: <atom> <kind> [partial]` or `// wz-proves: none -- <reason>`,")
        print("     immediately above the #[test] / #[tokio::test] attribute; kind in %s)"
              % "/".join(sorted(corpus.KINDS)))

    if fail_name:
        ok = False
        print("FAIL [A4-1] claimed atom is not in the inventory: %d" % len(fail_name))
        for rel, fn, atom in fail_name:
            print("    - %s::%s claims `%s` (renamed? typo? -> the proof silently vanished)" % (rel, fn, atom))

    if fail_denominator:
        ok = False
        print("FAIL [A4-2] claimed atom is not BUILT: %d" % len(fail_denominator))
        for rel, fn, atom, st in fail_denominator:
            print("    - %s::%s claims `%s` (status=%s). A claim of foreign proof for code "
                  "that is not built makes the numerator exceed the denominator." % (rel, fn, atom, st))

    if fail_foreign:
        ok = False
        print("FAIL [A4-3] wz<->wz test claims FOREIGN proof: %d" % len(fail_foreign))
        for rel, fn in fail_foreign:
            print("    - %s::%s (this file spawns/links no foreign implementation)" % (rel, fn))

    if fail_undeclared:
        ok = False
        print("FAIL [A4-4] corpus test declares nothing: %d" % len(fail_undeclared))
        print("    (an interop test that declares nothing contributes nothing, and the")
        print("     proof number silently under-reports. Say what it proves, or say")
        print("     `// wz-proves: none -- <why it witnesses no atom>`.)")
        for rel, fn in fail_undeclared:
            print("    - %s::%s" % (rel, fn))

    if fail_containment:
        ok = False
        print("FAIL [A4-5] claimed atom is NOT COMPILED into the binary under test: %d"
              % len(fail_containment))
        for rel, fn, atom, pkg in fail_containment:
            print("    - %s::%s claims `%s`, but it is not in %s's enabled-feature closure."
                  % (rel, fn, atom, pkg))
            print("      cfg-gated code that is not compiled cannot have been witnessed.")

    if fail_excluded:
        ok = False
        print("FAIL [A4-6] claimed atom is declared foreign-NON-observable: %d" % len(fail_excluded))
        for rel, fn, atom in fail_excluded:
            print("    - %s::%s claims `%s`" % (rel, fn, atom))
            print("      excluded because: %s" % FOREIGN_NON_OBSERVABLE[atom])
            print("      If this witness is REAL, the exclusion is WRONG -- remove it from")
            print("      FOREIGN_NON_OBSERVABLE (the denominator grows). That is the point of")
            print("      this invariant: the exclusion set is falsifiable by evidence.")

    if fail_kind:
        ok = False
        print("FAIL [A4-7] proof kind does not match the file's foreign class: %d" % len(fail_kind))
        for rel, fn, atom, kind, classes in fail_kind:
            print("    - %s::%s claims `%s %s` but the file's foreign classes are [%s]"
                  % (rel, fn, atom, kind, classes))

    if ok:
        print("cross-impl proof audit OK")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

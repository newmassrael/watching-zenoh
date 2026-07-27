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
# is NOT the denominator: the atoms below are excluded, because leaving them in would
# manufacture an unproven list that can never reach zero -- and a gate nobody can
# close is a gate everyone learns to ignore. NO COUNT IS WRITTEN HERE, deliberately
# (R311y314): this line used to say "25 of those atoms", R311y312 added 3 and did not
# update it, and the script PRINTS the real size four lines into its own stdout
# ("denominator = built(N) - foreign-NON-observable(28) = ..."). A count in a comment
# is a citation that nothing greps -- exactly the defect class R311y310 exists to
# name. `len(FOREIGN_NON_OBSERVABLE)` is the SSOT; read the stdout, not this header.
#
# R311y314 -- WHAT THIS SET ACTUALLY MEANS, reconciled with what it PRACTISES.
# The predicate stated below ("no foreign peer can produce or observe ANY difference")
# is TRUE of the substrate/seam/local-state entries and FALSE of the alias entries,
# and has been false since link-fragment / link-batching landed -- toggling
# `link-batching = ["transport-batching"]` demonstrably changes the wire, because the
# alias PULLS its vehicle. So this set holds TWO categories, and only the first
# matches the predicate:
#   (1) genuinely non-observable  -- host substrate, executor choice, internal seams,
#                                    local-only state. No peer can ever witness them.
#   (2) aliases / re-views        -- observable, but the observable BELONGS TO a
#                                    counted vehicle atom. Counting both double-counts
#                                    ONE artifact (link-frame's reason says exactly
#                                    that). Exclusion here is DE-DUPLICATION, not
#                                    non-observability.
# Category (2) costs falsifiability and the cost is real: A4-6 makes this set
# falsifiable by evidence ("witness one and the gate fails"), but a category-(2) entry
# CAN be witnessed -- the witness simply gets filed under the vehicle. For the qos
# trio the witness exists in this very tree (wz_qos_congestion_express_to_pico_zsub
# asserts a pico peer decoding all three bits) and reports as `pubsub-qos`. So A4-6
# cannot refute a category-(2) entry; only a human re-reading the vehicle mapping can.
# If you add to category (2), the burden is to show the named vehicle EXISTS, is in
# the denominator, and carries the proof -- a scripted cross-check of that is owed.
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
    # R311y312 — the three former per-field QoS features. R311y307 merged them
    # into `pubsub-qos` (one byte, one gate, one compile unit) and left them as
    # cargo aliases with ZERO cfg sites of their own. Same shape as link-frame
    # above, same reason: the observable artifact is ONE qos byte, and counting
    # the aliases beside the atom that gates it double-counts it. Their proofs
    # moved onto `pubsub-qos` in this same commit -- required, not tidiness:
    # A4-6 rejects a claim on an excluded atom and fires BEFORE A4-2/A4-5, so
    # splitting the exclusion from the re-point turns the gate red.
    "pubsub-congestion-control": "alias of pubsub-qos; the nodrop bit of the one qos byte",
    "pubsub-express": "alias of pubsub-qos; the express bit of the one qos byte",
    # NOT called a pure alias, deliberately: this key is
    # ["session-extqos", "pubsub-qos", ..], not ["pubsub-qos"]. The extra edge is
    # inert today (session-extqos is reserved/PARTIAL at 0 cfg sites and reaches
    # no transport-qos), but it is live in the manifest, so the accurate reason
    # names it rather than flattening it to "alias of pubsub-qos".
    "pubsub-priority": "qos-byte priority bits via pubsub-qos; extra session-extqos edge is inert",
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

# A SECOND, independent copy of tag knowledge (audit-catalog-status.sh:234 holds the
# closed set; its grammar is embedded in a bash heredoc and cannot be imported). The
# two must be changed together -- R311y299 carry: single-source the tag set.
#
# Why COMPLETE is deliberately ABSENT here: it means "built", so omitting it looks
# like a bug. It is inert because `built` (see main()) admits an atom via
# `status == "active"` OR this set, and audit-catalog-status.sh only permits COMPLETE
# on status=active -- so the first disjunct always carries it and this one is never
# consulted. That inertness is load-bearing on A3 actually running: if A3 is disarmed
# and a reserved atom is tagged COMPLETE, it silently leaves `built`, shrinking the
# denominator and the unproven count with nothing failing (R311y300: NOT "inflates the
# proven percentage" -- this gate prints counts, never a percentage, per R311jl). R311y299 gave
# A3 a WZ_A3_REQUIRE mode for exactly this class of forfeit. If COMPLETE is ever
# widened to reserved, it MUST be added here in the same commit.
IMPL_TAGS_BUILT = {"FOUNDATIONAL", "PARTIAL"}
KIND_CLASS = corpus.KIND_CLASS

# ── Host-gated hosted-CI legs ─────────────────────────────────────────────────────
#
# A `--test` target a hosted lane NAMES, but whose leg ECHO-SKIPS on the hosted runner
# instead of executing -- host-gated on a capability the runner lacks and ci.yml does
# NOT provision. ci_executes must not count these as hosted-CI-executed: a proof that
# echo-skips there has NO hosted witness, so it belongs in the PROVEN-WITH-NO-HOSTED-CI-
# WITNESS report, not the [executed by hosted CI] count. Without this, the static
# lane-names-the-target model (ci_executes) reads the leg as executed and the atom's
# ONLY witness silently vanishes from the no-witness safety report -- the exact
# skip-looks-green failure this axis exists to catch (R311y402 surfaced it: the vsock
# acceptor cross-impl became a counted zenohd proof, and its Layer Z leg echo-skips).
#
# Declared, with reason, and made FALSIFIABLE by assert_host_gated_ci_targets():
#   (a) each entry is still NAMED by a hosted lane -- else it excludes nothing (stale);
#   (b) its Layer Z leg is WZ_Z_REQUIRE-EXEMPT in run-ci.sh (a bare echo-skip, not the
#       `_z_unavailable` / WZ_Z_REQUIRE FAIL every RUNNING Z leg uses) -- else the leg
#       is REQUIRED to run on the hosted job and the exclusion is wrong.
# If ci.yml ever provisions the oracle (so the leg runs on hosted CI), REMOVE the entry
# -- the atom then earns a real hosted witness. Same "declare, then gate" shape as
# FOREIGN_NON_OBSERVABLE: the set is falsifiable by evidence, not a silent hardcode.
# The WZ_Z_REQUIRE signal is Layer-Z-specific, so this is NOT auto-derived across all
# lanes: a naive "oracle guard without the required-FAIL" scan false-matches the pico
# E6/E7 legs (their `[[ -x <pico> ]]` guard uses a different required mechanism), which
# is exactly the fragile-derivation this module warns against elsewhere.
HOST_GATED_CI_TARGETS = {
    "wz_vsock_acceptor_zenohd_interop":
        "AF_VSOCK loopback needs the vsock_loopback kernel module + a vsock-enabled "
        "zenohd oracle; the hosted runner has neither and ci.yml provisions neither, so "
        "the Layer Z vsock leg echo-skips even under WZ_Z_REQUIRE (run-ci.sh).",
}

# ── Execution disclosure ────────────────────────────────────────────────────────
#
# A proof that never runs is not a proof. The interop tests are #[ignore]d and their
# lanes SKIP (green) when the foreign binaries are absent, so "proven" could otherwise
# be reported off a test that has never executed anywhere — a number with MORE false
# authority than the hand estimate it replaces.
#
# Which lane carries which class is a small declared map; WHICH LANES HOSTED CI ACTUALLY
# RUNS is derived from .github/workflows/ci.yml, so the disclosure cannot rot when the
# workflow changes. (R311y264 wired E2/E6/E6b/E8/Z in, and the printed line moved with it
# without an edit here -- which is the property to keep.) Layer M used to be the hole
# named here: opt-in, so it ran on NO default path at all, not even the pre-push full run,
# and the atoms whose only witnesses live there sat in the headline `proven` regardless.
# R311y421 wired it onto the interop job with WZ_M_REQUIRE=1, so it is hosted now. It is
# STILL opt-in locally -- the guard opt_in_lanes() reads is deliberately unchanged, since
# a local sweep on a box without multicast should not hard-fail -- which is why the two
# populations can still differ for it. The PROVEN-WITH-NO-HOSTED-CI-WITNESS roll-up
# remains the thing to read; it is derived, so it will name whatever the next such lane is
# without an edit here.
# R311y271 — CLASS_LANES WAS HARDCODED, AND IT HAD ALREADY ROTTED. The comment above
# claimed "R311y264 wired E2/E6/E6b/E8/Z in, and the printed line moved with it without an
# edit here". It did not: the disclosure intersects this map with the hosted set, so a lane
# in hosted CI but ABSENT from the map is invisible to it -- and E6b was exactly that,
# printing "hosted CI runs E/E2/E6/E8" while E6b's pico proofs ran there all along. The
# roll-up COUNTS were right (ci_executes derives them end to end); only the sentence
# describing them lied, which is the failure this axis exists to catch, one level up.
#
# So it is derived now, from the same two sources ci_executes uses: the corpus (which class
# a test proves) and run-ci.sh's lane -> --test target map. Wiring a lane into the workflow
# now moves the disclosure as well as the number, with no edit here -- the property the old
# comment asserted and did not have.
def class_lanes(corpus_files) -> dict[str, list[str]]:
    """Which lanes carry each proof class. Derived; never hardcoded."""
    out: dict[str, set[str]] = {}
    for cf in corpus_files:
        lanes: set[str] = set()
        # NOT #[ignore]d -> `cargo test --workspace` (Layer C1) runs it every push.
        if any(not t.has_ignore for t in cf.tests):
            lanes.add("C1")
        # A dedicated lane that names this file as a --test target.
        for lane, targets in LANE_TARGETS.items():
            if cf.path.stem in targets:
                lanes.add(lane)
        # Layer E's --ignored catch-all, unless the fn name matches one of its --skips.
        if any(t.has_ignore and not any(s in t.name for s in E_SKIPS) for t in cf.tests):
            lanes.add("E")
        for cls in cf.classes:
            out.setdefault(cls, set()).update(lanes)
    return {cls: sorted(v) for cls, v in out.items()}


def opt_in_lanes() -> set[str]:
    """Lanes that run on NO default path -- not hosted CI, and not the local full run-ci.

    Layer M guards itself with `[[ "$ONLY_LAYER" != "M" && "${WZ_RUN_LAYER_M:-0}" -ne 1 ]]`,
    so `run-ci.sh` with no arguments -- which is exactly what the pre-push hook runs --
    SKIPs it. Calling that "local only" would be a lie: it is NOWHERE. The disclosure line
    used to say "only in the local full run-ci (pre-push)" for M, which was false, and the
    proofs whose ONLY witness lives there were counted in the headline `proven` with
    nothing naming them. Derived from the guard itself so it cannot drift.
    """
    return {
        lane
        for lane, body in lane_bodies().items()
        if re.search(r'ONLY_LAYER"? != "%s"' % re.escape(lane), body)
        and re.search(r"WZ_RUN_LAYER_%s" % re.escape(lane.upper()), body)
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


def run_ci_text() -> str:
    return (REPO_ROOT / "scripts" / "run-ci.sh").read_text()


def lane_bodies() -> dict[str, str]:
    """lane id -> the shell body of the function that lane registers.

    Derived from the `run_layer <ID> <fn>` registrations, so a lane renamed or added in
    run-ci.sh is picked up automatically. Hardcoding the mapping here would be the very
    prose-list-that-rots this axis exists to replace.
    """
    txt = run_ci_text()
    out: dict[str, str] = {}
    for lane, fn in re.findall(r"^run_layer (\S+) (\S+)", txt, re.M):
        m = re.search(r"^%s\(\) \{.*?^\}" % re.escape(fn), txt, re.S | re.M)
        if m:
            out[lane] = m.group(0)
    return out


def lane_test_targets() -> dict[str, set[str]]:
    """lane id -> the `--test <target>` names that lane runs explicitly."""
    return {
        lane: set(re.findall(r"--test ([A-Za-z0-9_]+)", body))
        for lane, body in lane_bodies().items()
    }


def layer_e_skips() -> list[str]:
    """The --skip substrings Layer E passes to libtest.

    Layer E is the CATCH-ALL ignored-test lane (no `--test` target of its own): it runs
    every #[ignore]d test in the crate EXCEPT the families that belong to dedicated lanes.
    So a test's fn name matching any of these means Layer E does not execute it, and only
    its dedicated lane can.
    """
    body = lane_bodies().get("E", "")
    return re.findall(r"--skip ([A-Za-z0-9_]+)", body)


def ci_executes(test, cf) -> bool:
    """Does hosted CI actually RUN this test?

    A proof that never runs is not a proof, so the roll-up reports the executed and the
    declared populations separately rather than fusing them. This is the predicate that
    separates them, and it is DERIVED end to end -- the hosted lane set comes from
    ci.yml's `run:` steps, and lane -> test-target comes from run-ci.sh -- so wiring a new
    lane into the workflow moves the number without anyone editing this file.

      - NOT #[ignore]d -> Layer C1 (`cargo test --workspace`) runs it. This is how the 26
        `codec` files (the linked-pico-C differentials) execute on every push.
      - #[ignore]d     -> a dedicated lane that names its `--test` target runs it, or
                          Layer E's catch-all does (unless its fn name matches a --skip).
    """
    if not test.has_ignore:
        return "C1" in HOSTED
    target = cf.path.stem
    # A hosted lane may NAME this target while its leg echo-skips on the runner; a leg
    # that never executes there is not a hosted witness (see HOST_GATED_CI_TARGETS).
    if target in HOST_GATED_CI_TARGETS:
        return False
    for lane, targets in LANE_TARGETS.items():
        if lane in HOSTED and target in targets:
            return True
    if "E" in HOSTED and not any(s in test.name for s in E_SKIPS):
        return True
    return False


HOSTED = hosted_ci_layers()
LANE_TARGETS = lane_test_targets()
E_SKIPS = layer_e_skips()


def assert_host_gated_ci_targets() -> list[str]:
    """Falsify the HOST_GATED_CI_TARGETS declarations; returns human-readable problems.

    (a) a declared target must still be NAMED by a hosted lane -- else it excludes
    nothing and is stale. (b) the leg that runs it must be WZ_Z_REQUIRE-EXEMPT in
    run-ci.sh: if the `local <oracle>=`-delimited leg chunk that names its `--test`
    also names WZ_Z_REQUIRE, the leg FAILs when required, i.e. it RUNS on the hosted
    job and the exclusion is wrong. Both are derived from the same sources ci_executes
    uses, so the declaration cannot rot silently into a lie the way a bare hardcode would.
    """
    problems: list[str] = []
    bodies = lane_bodies()
    for target in HOST_GATED_CI_TARGETS:
        hosting = [lane for lane in HOSTED if target in LANE_TARGETS.get(lane, set())]
        if not hosting:
            problems.append(
                "%s: declared host-gated but no hosted lane names it as a --test target "
                "(stale -- it excludes nothing; remove it)" % target)
            continue
        for lane in hosting:
            chunk = next(
                (c for c in re.split(r"\n\s+local ", bodies.get(lane, ""))
                 if re.search(r"--test %s\b" % re.escape(target), c)),
                "")
            if "WZ_Z_REQUIRE" in chunk or "_z_unavailable" in chunk:
                problems.append(
                    "%s: declared host-gated but its %s leg enforces the required-FAIL "
                    "(WZ_Z_REQUIRE / _z_unavailable), so it RUNS on the hosted job -- the "
                    "exclusion is wrong (remove it)"
                    % (target, lane))
    return problems

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
        # A file may drive several wz binaries; union their closures. A union is a
        # SUPERSET, so containment can never produce a false FAIL -- only a weaker true
        # one. (Picking one, as this used to, would have validated a tight subset
        # binary's claims against wz-ap-demo's 110-feature union.)
        pkg = "+".join(cf.binaries)
        if pkg not in closures:
            merged: set[str] = set()
            for b in cf.binaries:
                merged |= fc.binary_closure(b)
            closures[pkg] = frozenset(merged)
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
                # A FOUNDATIONAL atom has ZERO cfg(feature=..) sites of its OWN by A3
                # invariant #2, so not enabling its cargo key elides no code that names it,
                # and containment has nothing to refute. Only an active atom's code can be
                # elided by not enabling its feature, and that is the case this arm exists
                # to refute.
                #
                # R311y312 — the reason stated here USED to be "its code is compiled
                # unconditionally, whether or not its `= []` cargo key happens to be
                # enabled". That is FALSE of every alias-shaped FOUNDATIONAL in the tree,
                # which is 18 of the 57 (8 locator-* forwards, attachment-encoding-aware,
                # keyexpr-canon, link-batching, link-fragment, liveliness-historical-samples,
                # scouting-gossip, scouting-multicast, and post-y307 the three pubsub-qos
                # aliases -- R311y314 corrected this list, which said "9 locator-*" for 8
                # and omitted four members; DERIVE it, do not trust the prose): their key
                # is NOT `= []` and their
                # vehicle's code IS elided when the vehicle feature is off. The exemption
                # is still correct, but for the narrower reason above -- the atom names no
                # cfg site, so containment over ITS name is vacuous either way. The
                # alias-shaped ones escape a real check only because FOREIGN_NON_OBSERVABLE
                # short-circuits them first, which is why an alias belongs in that set.
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
    # The STRICTLY WORSE population, which used to have no line at all and was visible
    # only as an unexplained delta between the two headline counts: an atom sitting in
    # `proven` with NO hosted-CI witness of any kind. Some of these are proven only by a
    # lane that runs on no default path whatsoever (see opt_in_lanes) -- not hosted, not
    # even the pre-push full run. A headline number resting on those is the exact false
    # authority this axis exists to end, so it gets named.
    proven_without_ci_witness = sorted(full - ci_full_only - ci_partial_only)

    fail_host_gated = assert_host_gated_ci_targets()

    ok = not (fail_name or fail_denominator or fail_foreign or fail_undeclared
              or fail_containment or fail_excluded or fail_kind or fail_malformed
              or fail_host_gated)

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
    if proven_without_ci_witness:
        print("  PROVEN WITH NO HOSTED-CI WITNESS AT ALL (%d): %s"
              % (len(proven_without_ci_witness), ", ".join(proven_without_ci_witness)))
        print("     (these sit in the headline `proven` on tests hosted CI does not run.")
        print("      Check whether their lane runs on ANY default path -- an opt-in lane")
        print("      like M is skipped by the pre-push full run too, i.e. it runs NOWHERE.)")
    if promoted_by_unrun:
        print("  PROMOTED BY A TEST HOSTED CI NEVER RUNS (%d): %s"
              % (len(promoted_by_unrun), ", ".join(promoted_by_unrun)))
        print("     (hosted CI's only witness for each of these is a `partial`; the `full`")
        print("      claim comes from a lane it does not run.)")
    print("  UNPROVEN (%d, actionable): %s" % (len(unproven), ", ".join(unproven) if unproven else "(none)"))
    print("  witnesses-no-atom (declared `none`): %d" % len(none_tests))
    if HOST_GATED_CI_TARGETS:
        print("  HOST-GATED hosted-CI targets (named by a lane but echo-skip on the "
              "runner, so NOT counted as hosted-executed): %s"
              % ", ".join(sorted(HOST_GATED_CI_TARGETS)))

    hosted = hosted_ci_layers()
    opt_in = opt_in_lanes()
    lanes_by_class = class_lanes(corpus_files)
    for cls in sorted(lanes_by_class):
        lanes = lanes_by_class[cls]
        run_here = [x for x in lanes if x in hosted]
        local_only = [x for x in lanes if x not in hosted and x not in opt_in]
        nowhere = [x for x in lanes if x not in hosted and x in opt_in]
        note = "hosted CI runs %s" % "/".join(run_here) if run_here else "NOT RUN in hosted CI"
        if local_only:
            note += "; %s only in the local full run-ci (pre-push)" % "/".join(local_only)
        if nowhere:
            # An opt-in lane is skipped by `run-ci.sh` with no arguments, which is what the
            # pre-push hook runs. Calling it "local only" would be a lie: it runs NOWHERE.
            note += "; %s runs on NO default path (opt-in; not even the pre-push full run)" \
                % "/".join(nowhere)
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

    if fail_host_gated:
        ok = False
        print("FAIL [A4-8] HOST_GATED_CI_TARGETS declaration is stale/wrong: %d"
              % len(fail_host_gated))
        for p in fail_host_gated:
            print("    - %s" % p)

    if ok:
        print("cross-impl proof audit OK")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y259 (no register item) — Layer A4: join the catalog to the cross-impl proof corpus.

Driven by scripts/audit-crossimpl-proof.sh, which documents the motivation and the
seven invariants. This module is the join itself.
"""

from __future__ import annotations

import json
import os

import inventory_kinds
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
HOST_GATED_CI_TARGETS: dict[str, str] = {
    # R311y422 — EMPTY, and the emptiness is the point. This held exactly one entry,
    # wz_vsock_acceptor_zenohd_interop, on the reasoning that "AF_VSOCK loopback needs
    # the vsock_loopback kernel module + a vsock-enabled zenohd oracle; the hosted
    # runner has neither and ci.yml provisions neither". The second half was true and
    # fixable; the FIRST half was never measured, and run 30251723895 measured it
    # false -- `modprobe vsock_loopback` succeeds on the runner image and a bind on
    # VMADDR_CID_LOCAL returns a port. ci.yml now loads the module and builds the
    # oracle, and the Layer Z leg is no longer WZ_Z_REQUIRE-exempt, so the target
    # EXECUTES hosted and an entry here would be the stale-declaration case
    # assert_host_gated_ci_targets() exists to reject.
    #
    # Keep the mechanism: a genuinely host-gated target belongs here WITH its reason,
    # and the assertion falsifies the declaration in both directions -- it must still
    # be named by a hosted lane, and the leg running it must still be REQUIRE-exempt.
}

# ── A4-9: the foreign-adjudicator ratchet ──────────────────────────────────────
#
# The sum, over atoms, of DISTINCT corpus tests that foreign-adjudicate them. It is
# an EXACT match rather than a floor, and both directions of failure are the point:
#
#   * Below it, a foreign witness was DELETED or silently stopped being accepted --
#     the regression `proven`/`partial` cannot see, because dropping one of an atom's
#     three witnesses leaves that bit untouched.
#   * Above it, a round ADDED foreign adjudication and did not say so. That is the
#     failure R311y569 and R311y571 both named: work that closes a plane and moves
#     no number reads, to the next session, as a round that changed nothing.
#
# So a round that adds a witness bumps this line, in the same commit, and the diff
# carries the claim. Derived wholly from the source tree (the corpus scan), so unlike
# the census baselines of R311y567 it is NOT machine-dependent -- there is no arm to
# get wrong and no oracle to pair with.
#
# MEASURED at R311y572, three times, and the sequence is the justification for
# this constant existing at all: 785 before the round, 786 after the pico
# `source_info` adjudicator for the seven remaining option structs, 787 after the
# `accept_replies` adjudicator. `proven=128 partial=39` did not move once.
# R311y573 took it to 788 with the zenoh-ext families' adjudicator — and that
# one first landed at 787 because the file resolved the oracle by joining a
# path, so A4-3 read its `wz->zenoh-c` claim as a wz-vs-wz test. The counter did
# not move until the claim was real.
# R311y575 took it to 790, in two measured steps from one new file: 789 for the
# `api-compat-pico` claim on the cancellation-token adjudicator, then 790 for its
# `liveliness-get` claim, whose legE drives that atom's own option struct and its
# own cancellation registration. The second step is the one worth naming — it took
# `1-test-only` from 61 to 60 and `1-impl-only` from 113 to 112, which is the first
# time either of the two populations R311y572 NAMED has moved. `proven=128
# partial=39` did not move for either step, which is exactly the blindness this
# counter exists to cover.
# R311y628 took it to 801, in ONE step of five, and the step is a different
# shape from every one above it. Those added a witness for a behaviour someone
# had thought to check; this one added a GENERATED corpus -- the whole 8-bit
# transport header space against a body ladder -- and claimed the five transport
# codecs it drives through both decoders. Every claim is `partial` on purpose:
# the differential compares the ACCEPT/REJECT verdict, so it adjudicates each
# codec's BOUNDARY and not its contents.
# R311y630 took it to 802, in ONE step, and the step's shape is a MECHANISM
# WITNESS rather than a new plane. The previous round's generated corpus found
# 27 disagreements and could not say whose they were; the triage split them
# into a wz defect (18, now fixed) and a pico one (16, now pinned with an owner)
# -- and the pico half needed a test that MEASURES the mechanism instead of
# citing it, because "pico never reads the CLOSE ext chain" read off a source
# file is a claim about one build, while four chains no reader could rate alike
# getting one verdict from the linked library is the fact.
# R311y630b took it to 806, in one step of four, from the VOCABULARY oracle --
# the generator that walks the extension identities the wire spec NAMES rather
# than the header space uniformly. The measurement that justified it: over 1536
# blind-sweep strings the corpus produced ten distinct mandatory extension
# identities and not one of them was an identity either implementation defines,
# so the positive half of the admission rule had never been driven. Driving it
# found three disagreements, all pico's, including the one that matters --
# `frame::ext::QoS`, the single mandatory extension the data plane defines,
# which zenoh's Frame codec reads and pico's refuses.
# R311y630d took it to 808, in one step of two, from the SECOND NAMESPACE:
# pico exports `_z_scouting_message_decode` beside the transport one, so SCOUT
# and HELLO cost one symbol and no new machinery. The step is worth naming
# because of what it adjudicates rather than its size -- SCOUT is MID 0x01 and
# so is INIT, their extension spaces differ (none versus eight), and this is
# the measurement that `ExtCarrier` tells them apart against the REAL decoder
# rather than against wz's opinion of itself.
# R311y718 takes it to 817, two links, and the pair is the textbook case this
# counter exists for. R311y714 closed [REDACTED-REQ] by asking a live zenohd for
# `@/**` and reading back its node information and its link-state graph, which
# gave `adminspace-read` and `adminspace-router-linkstate` a THIRD adjudicating
# test each. Neither atom moved in proven/partial -- both were proven already --
# so the round that bought a foreign opinion reported changing nothing, and this
# gate's red was the only thing that disagreed. The two lines are worth naming
# for WHOSE opinion arrived: every prior witness of both atoms was pico, so this
# is the first zenohd adjudication either one has, i.e. the half that moved is
# `1-impl-only`, which is the half `links` was split out to make visible.
# R311y764 takes it to 820, THREE links in one step, and the fact worth naming
# is that it is one step rather than three. Each of R311y759 / y760 / y762 added
# exactly one wire witness and none of them moved this constant, so hosted A4 has
# been red on `1808ba7f`, `8f19661e` and `6f689628` -- three consecutive rounds
# that each read the previous run, saw a red, and did not attribute it. Measured
# rather than reconstructed: the audit re-run at `9eeb336a` (the last green)
# reports 817, at `1808ba7f` 818, at `8f19661e` 819, and here 820.
# WHOSE opinion the three bought:
#   * `session-unicast-open` <- pico_wire_dissection (y759, Layer Ewire) -- the
#     analyzer's first bytes from a foreign process rather than a fixture.
#   * `session-unicast-open` <- zenohd_wire_dissection (y760, Layer Ewirez) --
#     the same atom's first ROUTER adjudication; pico and zenohd are two impls.
#   * `routing-router` <- zenohd_wire_dissection (y762) -- a router given
#     something to route, so the bytes are ones only a router emits. It is
#     `partial` on purpose: N68 records that the Frames were counted, not opened.
# R311y774/y775 take it to 822, and BOTH links land on ONE atom that was already
# `partial`: `declare-interest`. That is exactly the case this constant was split
# out to make visible -- the atom's proven/partial bit did not move, so the two
# rounds would otherwise have reported buying nothing, when what they bought is
# the atom's FIRST foreign adjudication on either plane.
#   * `declare-interest` <- wz_matching_status_through_zenohd_router (y774) --
#     the SUBSCRIBERS interest, judged by a real zenohd deciding whether to
#     forward a real pico subscriber's declaration to wz's face. Its first run
#     was RED and found that `preset-ap-client` shipped the matching listener
#     without `declare-interest`, so the listener was inert behind a router.
#   * `declare-interest` <- wz_querier_matching_through_zenohd_router (y775) --
#     the QUERYABLES half, a separate file because it swaps the wire bit, the
#     registry, the feature gate, the router gate and the foreign process. The
#     pair is what makes each specific: damaging the querier's emit reds only
#     its own witness.
# R311y778 takes it to 823. `declare-final` had ONE adjudicating test before
# this (it is on the SINGLE-ADJUDICATOR list) and gains a second here:
#   * `declare-final` <- wz_router_terminates_a_pico_liveliness_get -- a real
#     zenoh-pico `z_get_liveliness` against a wz `routing-routes` router. It is
#     the atom's first witness for the CURRENT-interest terminator specifically,
#     and the requester is the one consumer in either upstream that observably
#     waits for it (pico's write filter ignores the message; see R311y777).
# R311y781 takes it to 824. `adminspace-read` gains a second adjudicating test:
#   * `adminspace-read` <- wz_router_adminspace_read_deny_seen_by_pico_z_get -- a
#     real zenoh-pico `z_get` against a `--no-admin-read` wz ROUTER, which until
#     this round could not deny at all (its admin host hardcoded `read: true`).
#     The atom's existing witness is the PEER deny (E6g); this one speaks for the
#     router tier, where `answer_router_admin_query`'s own gate lives and where the
#     suppressed legs -- linkstate DOT and route-successor -- exist only on a
#     two-router federation. A different host, a different answerer, same atom.
# R311y791 takes it to 825. `liveliness-history` gains a second adjudicating
# test, and it leaves the SINGLE-ADJUDICATOR list this run printed it on:
#   * `liveliness-history` <- wz_liveliness_history_replays_locally_to_a_late_
#     second_subscriber_behind_zenohd -- the atom's existing witness is a
#     subscriber declared BEFORE the session is driven, which zenohd serves off
#     its answer to that subscriber's own CURRENT interest. This one declares a
#     SECOND history subscriber after the first has seen the token, where zenohd
#     answers with the id it already used for the resource (`make_token_id`
#     reuses `local_tokens[res]`, hat/router/token.rs:978-990) and wz's
#     first-declaration-wins guard drops the reply -- so only the R311y790
#     declare-time local replay can serve it. Same atom, same router, a plane
#     the first witness cannot reach.
# R311y798 takes it to 828. `session-matching` gains THREE adjudicating tests,
# all in wz_querier_all_complete_vs_pico_queryable.rs, for the AllComplete axis
# R311y797 built and could not witness:
#   * a_pico_incomplete_queryable_is_refused_by_an_all_complete_wz_querier --
#     the REMOTE arm. pico's stock `z_queryable` declares `complete = false`,
#     at which value pico OMITS the QueryableInfo ext entirely
#     (codec/declarations.c:107-112), so this binds wz's reading of an ABSENT
#     ext against a real encoder rather than against wz's own fixture.
#   * an_incomplete_session_local_queryable_does_not_satisfy_the_all_complete_
#     querier -- the LOCAL arm, one argv token (`--queryable-complete`) away
#     from the leg below. Its session opener is a `z_sub` and not a
#     `z_queryable` deliberately: a falsify probe showed that with pico's own
#     queryable in scope the leg reddened for the REMOTE arm's defect too, so
#     it proved "something refuses" rather than "the local half refuses".
#   * a_complete_session_local_queryable_does_satisfy_the_all_complete_querier
#     -- the anti-vacuity twin of the other two. An AllComplete watch that were
#     simply inert would satisfy both silences; this one makes it speak.
# R311y799 takes it to 830. `session-matching` gains the ACCEPT half of the same
# axis, in wz_querier_all_complete_vs_zenohd_storage.rs, and the adjudicator is a
# DIFFERENT implementation from y798's on purpose:
#   * a_zenohd_storage_declared_complete_satisfies_an_all_complete_wz_querier --
#     the only leg in this corpus where a FOREIGN encoder SETS the completeness
#     bit. zenoh-pico structurally cannot: its stock z_queryable example takes no
#     completeness option, so a pico `complete = true` would need a patched
#     oracle. zenoh-full's storage-manager declares its storage's queryable with
#     `.complete(self.configuration.complete)` (service.rs:154) from a plain
#     config key, so a stock zenohd sets it from the command line.
#   * a_zenohd_storage_declared_incomplete_does_not_satisfy_it -- its twin, one
#     config key apart, without which the leg above would be satisfied by a wz
#     that ignored the bit entirely. It also carries the ordinary querier's rise
#     as the control that zenohd forwarded the declaration at all.
# Together they also MEASURE what y798 left open: whether the routed path
# preserves the declarer's bit, which it does with one storage behind the router.
# R311y803 takes it to 833, in wz_router_routes_liveliness_pico_interop.rs. The
# atom under grade is the LIVELINESS plane of the `routing-routes` STAR router,
# which recorded no token at all until this round, and the three links are two
# atoms across two legs:
#   * wz_router_carries_a_pico_token_and_retracts_it_when_the_holder_dies --
#     TWO links (`liveliness-subscriber` + `routing-routes`), because the fixture
#     grades both halves of one clause: pico A's token reaching pico B through
#     the router, and the retraction wz SYNTHESISES when it watches A die. The
#     driver of the second half is a SIGKILL rather than a SIGINT: on SIGINT
#     `z_liveliness` retracts its own token, so the graceful shape would witness
#     the PEER's withdrawal, an arm the rise already covers.
#   * wz_router_replays_a_pre_existing_pico_token_to_a_history_subscriber -- one
#     link, the CURRENT dump, with the ordering reversed so the token predates
#     the subscriber's session. Its `-h`-off twin declares `none`: it binds the
#     replay to the CURRENT bit and claims no atom of its own.
# The substrate is the point. `wz_router_hat_liveliness_history_pico_interop.rs`
# grades the same observable on `--router-hat`, whose token plane is a different
# atom (`routing-token-tables`) and was already built; the star router's was not.
# The exit_on_first round takes it to 836, in
# pico_c_examples_on_wz_capi_dropin.rs. ONE new leg,
# `pico_zscout_source_on_wz_capi_reports_every_zenohd_on_the_group`, carrying TWO
# links because it grades two atoms at once: `api-compat-pico` (upstream's own
# `z_scout.c`, unmodified, on wz's cdylib) and `scouting-active` (pico's
# `exit_on_first == false` survey arm, which wz gained this round). Its sibling
# spawns ONE zenohd and therefore cannot grade the second — a single answer is
# reported identically by a survey and by a first-answer lookup, measured by a
# damage probe that leaves the one-router leg green and reds this one.
# The solicited-declare routing round takes it to 838, in
# wz_liveliness_get_zenohd_pico_interop.rs. ONE new leg,
# `a_zenohd_answered_liveliness_get_does_not_fire_a_live_subscription`, TWO
# links because the rule spans two planes: `liveliness-get` (the answer reaches
# the requester) and `liveliness-subscriber` (and reaches nobody else). Its
# claim is an ABSENCE, which is why the file's lane is count-guarded in the same
# commit -- a de-selected absence assertion reports success by silence.
# The consolidation-byte round takes it to 842, in
# query_consolidation_wire_byte_divergence.rs. THREE new legs carrying FOUR
# links: the zenohd leg and the pico leg each grade `codec-request` on their own
# encoder, and the wz parity leg grades `query-consolidation` and `query-get`
# together because the byte it pins is meaningless without the request that
# carries it. proven/partial did NOT move -- all four atoms were already
# `partial` -- which is the case this counter exists for: a first witness on a
# NEW plane of an already-graded atom is invisible to the per-atom bit.
# The close-scope round takes it to 844, in close_scope_zenohd_witness.rs. ONE
# new leg, TWO links: it reads the scope flag off a Close a real zenohd wrote,
# which grades `codec-close` (the flag is a field of that message) and
# `session-unicast-open` (the Close it reads is the establishment-phase reject,
# reached by handing zenohd's accept FSM a KeepAlive where it demands an
# InitSyn). The leg exists because the round it lands with changed wz's own
# scope byte on the strength of a claim about zenoh's SOURCE, and the class of
# claim this tree keeps retracting is exactly that one -- R311y838 ratified a
# divergence off zenoh-pico's constructor and missed the cap one function later.
# The router QUERY-plane round takes it to 847, in
# wz_router_routes_pico_interop.rs. TWO new legs, THREE links, MEASURED not
# guessed (844 -> 847 is exactly the three `wz-proves` lines added). The
# headline leg grades `routing-routes` AND `declare-queryable`: a real pico
# `z_get` reaches a real pico `z_queryable` through a wz `--router`, so the
# router's query fan-out and the DeclareQueryable it built the route from are
# both under a foreign endpoint at each end. The empty-route leg grades
# `routing-routes` alone -- a query nothing matches must still be CLOSED, and
# what it grades is the router's own termination, not any queryable.
#
# The second leg's deadline is 5s rather than the file's usual 15s, and that is
# a load-bearing number rather than impatience: pico closes its OWN query at
# `Z_GET_TIMEOUT_DEFAULT 10000` and prints the identical final line, so a
# generous deadline makes the leg green whether or not wz answered. Measured
# both ways -- at 15s it stayed GREEN under the probe that deletes `route_query`
# outright; at 5s it reds, and the real router-sent final arrives in 50ms.
# R311y841 takes it to 849, in the NEW wz_router_query_target_zenoh_interop.rs.
# ONE leg, TWO links, MEASURED not guessed (847 -> 849 is exactly the two
# `wz-proves` lines added). It grades `routing-routes` AND `declare-queryable`
# against a counterparty class this tree did not have: the CORE zenoh examples
# (`zenoh-core`), which are the only foreign binaries that can declare a
# queryable `--complete` and query with an explicit `--target`. zenohd declares
# no queryable at all and zenoh-pico's hardcodes `complete = false`, so before
# this round the QueryTarget decision had no foreign adjudicator that could even
# express its input.
# R311y900 takes it to 853, in the NEW zenoh_ext_body_foreign_witness.rs. ONE
# leg, TWO links, MEASURED not guessed (851 -> 853 is exactly the two
# `wz-proves` lines added). It grades `codec-declare` and `codec-request`
# against a shape no other leg in this tree has: BOTH ENDS OF THE TAPPED
# CONNECTION ARE FOREIGN. A stock `z_queryable --complete` dials through the
# tap and a stock `zenohd` forwards a stock `z_get --target ALL_COMPLETE`
# query back through it, so wz appears only as the reader of the synthesised
# pcap. Every other foreign witness here puts wz on one half of the wire,
# which is the right shape for grading an ENCODER and the wrong one for
# grading a DECODER -- a decoder needs no seat at the table, and open-debt
# item 406 was filed because the Z64 extension-body walkers had only ever been
# judged against this tree's own producers.
# R311y902 takes it to 855, in the NEW zenoh_auth_body_foreign_witness.rs. ONE
# leg, TWO links, MEASURED not guessed (853 -> 855 is exactly the two
# `wz-proves` lines added). It grades `session-extauth` and
# `access-extauth-usrpwd` in the shape R311y900 opened: BOTH ENDS OF THE
# TAPPED CONNECTION ARE FOREIGN. The reason it had to be that shape is
# specific to auth and worth recording -- the usrpwd body that carries
# `{user, hmac}` is written by the DIALER, and every existing auth interop
# test in this tree has wz dialling, so pointing the dissector at those
# captures would have graded wz's encoder against wz's decoder. A stock
# `z_get` carrying `transport/auth/usrpwd/{user,password}` is the initiator
# here, and a stock zenohd holding the dictionary is the acceptor.
# Round 2020 (item 271) — 855 -> 856. The INTEREST plane gained a foreign
# adjudicator: `the_interest_plane_reads_a_real_zenohd_session` runs
# `wz_capture::interest::interests` over a real zenohd session, where every
# fixture that plane had ever seen was built by this tree's own encoders.
# R311y569 asked for this counter precisely so that closing a plane MOVES it,
# and the gate refused the push until the claim was written here — which is the
# counter working rather than an obstacle to it.
# R2094 (item 510) — 856 -> 859, in the NEW zenohd_scouts_wz_router_interop.rs.
# ONE leg, THREE links, MEASURED not guessed (856 -> 859 is exactly the three
# `wz-proves` lines added), and one of them takes `scouting-responder` OFF the
# SINGLE-ADJUDICATOR list this file prints. The atom's only foreign witness was
# `zenohd_scouts_wz_interop`, which drives the PEER role on a demo built without
# `router-hat-router` — so the role a stock zenoh client's autoconnect default
# actually asks for (`["router"]`, DEFAULT_CONFIG.json5:149) had answered nothing
# but this tree's own scouter, and R2089's witness is wz<->wz precisely because
# A4-3 refuses it a marker. `router-hat-router` gains its first foreign witness
# on the DISCOVERY plane for the same reason: its existing zenohd adjudicators
# all dial, or are dialled at, an endpoint the test hands over, and none of them
# establish that the run-mode can be FOUND.
# R2200 (item 558) — 859 -> 865, in the NEW wz_channel_reassembly_zenohd_interop.rs.
# TWO proof legs, THREE links each (their `wz-proves` lines are exactly the
# delta); the calibration TWIN beside each declares `none` and is counted
# nowhere, which is the arrangement A4-3 asks for. What moved is not that
# `transport-fragmentation` gained another zenohd witness -- it had two -- but
# that none of them said anything about CHANNELS: `priority`, `reliability`,
# `conduit` and `qos` appear in neither of those two files, while wz keys a
# reassembly chain on `(peer, reliable, priority)`. `transport-qos` gains
# witnesses in which the conduit is not merely negotiated but SEPARATES two
# chains that overlap on one link.
#
# The two proofs are two witnesses rather than one repeated because they take
# the chain key's halves SEPARATELY -- priorities at one reliability, then
# reliabilities at one priority. MEASURED: dropping `priority` from
# `find_active` reds the first and not the second, dropping `reliable` reds the
# second and not the first, so neither is a duplicate of the other and the
# count is honest at six.
FOREIGN_ADJUDICATOR_LINKS = 865

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
    # R311y800 — delegated to `inventory_kinds`, the one definition. This spelling
    # and `audit-catalog-status.sh`'s were identical and both correct; the FOURTH
    # copy (Layer A5's `unbuilt` predicate) was a substring search and redded a
    # hosted run on a reason that merely discussed the tag. Measured no-op here:
    # the two forms agree on all 219 atoms.
    return inventory_kinds.reason_head_tag(reason)


def main() -> int:
    inv = json.load(open(os.environ["INV_FILE"]))
    entries = inv if isinstance(inv, list) else inv.get("entries", inv.get("inventory", []))

    status: dict[str, str] = {}
    reason: dict[str, str] = {}
    # R311y743 — the atom/preset/debt line comes from `inventory_kinds`, the
    # ONE definition all four consumers share, rather than a fourth inline copy.
    for e in entries:
        aid = inventory_kinds.entry_id(e)
        if not aid or not inventory_kinds.is_atom(aid):
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
    # A4-8 (R311y571): the per-TEST half of A4-3. See its report block.
    fail_self_witness = []

    # (full/partial) x (all lanes / only the lanes hosted CI actually runs)
    proven_full: dict[str, set[str]] = {}   # atom -> {kinds}
    proven_partial: dict[str, set[str]] = {}
    ci_full: set[str] = set()
    ci_partial: set[str] = set()
    # A4-9 (R311y572) — the FOREIGN ADJUDICATOR CENSUS. See its report block for
    # what this is for; in short, `proven`/`partial` is one bit per atom, so the
    # first foreign witness for a NEW plane of an already-`partial` atom moves no
    # number at all and the work is invisible to this axis.
    adjudicators: dict[str, set[tuple[str, str]]] = {}   # atom -> {(file, test)}
    adjudicator_impls: dict[str, set[str]] = {}          # atom -> {foreign class}
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
                # A4-8 — the same question one level finer. A4-3 and A4-7 above
                # ask what the FILE reaches; this asks what THIS TEST reaches.
                # A file that spawns a foreign implementation anywhere licensed
                # every test in it to claim foreign proof, so a self-witnessing
                # test sat inside a foreign-classed file and counted.
                if not (KIND_CLASS[kind] & t.classes):
                    fail_self_witness.append(
                        (rel, t.name, atom, kind,
                         ",".join(sorted(cf.classes)) or "-",
                         ",".join(sorted(t.classes)) or "-"))
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
                # A4-9 — every claim that survives the checks above IS a foreign
                # adjudication: every KIND is a cross-impl kind, and A4-8 has just
                # established that THIS TEST's own call graph reaches the foreign
                # class the kind requires. So the census is exactly the accepted
                # claims, counted per atom rather than collapsed to a bit.
                adjudicators.setdefault(atom, set()).add((rel, t.name))
                adjudicator_impls.setdefault(atom, set()).update(KIND_CLASS[kind] & t.classes)

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

    # ── A4-9 — the foreign-adjudicator census ────────────────────────────────
    #
    # `proven` / `partial` / `unproven` is ONE BIT per atom, and R311y569 and
    # R311y571 both recorded the consequence: giving an already-`partial` atom
    # its first foreign witness for a NEW plane moves no counter, so the axis
    # reports the work as having changed nothing. R311y571 closed the half that
    # can REFUSE a bad claim (A4-8); this is the half that can COUNT a good one.
    #
    # Two numbers, because they answer different questions:
    #   * tests  — how many distinct corpus tests foreign-adjudicate this atom.
    #              A new plane's first witness moves this one.
    #   * impls  — how many distinct foreign IMPLEMENTATIONS answered. Five tests
    #              all driving the same spawned pico CLI are five opinions from
    #              ONE implementation, and that distinction is what stops the
    #              first number from being gamed by splitting a test in two.
    witness_links = sum(len(v) for v in adjudicators.values())
    single_witness = sorted(a for a, v in adjudicators.items() if len(v) == 1)
    single_impl = sorted(a for a, v in adjudicator_impls.items() if len(v) == 1)

    fail_host_gated = assert_host_gated_ci_targets()

    ok = not (fail_self_witness or fail_name or fail_denominator or fail_foreign or fail_undeclared
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
    print("  FOREIGN ADJUDICATORS [A4-9]: links=%d over %d atom(s); "
          "1-test-only=%d  1-impl-only=%d"
          % (witness_links, len(adjudicators), len(single_witness), len(single_impl)))
    print("     (`links` is the sum over atoms of DISTINCT foreign-adjudicating tests.")
    print("      proven/partial is one bit per atom, so a first foreign witness for a new")
    print("      plane of an already-`partial` atom moves nothing there; it moves this.")
    print("      `1-impl-only` is the sharper list: those atoms have several opinions but")
    print("      all from ONE foreign implementation.)")
    if single_witness:
        print("  SINGLE-ADJUDICATOR atoms (%d): %s"
              % (len(single_witness), ", ".join(single_witness)))
        print("     (exactly one test speaks for each. Not a failure -- an inventory of")
        print("      where a second, differently-shaped witness would buy the most.)")
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

    if witness_links != FOREIGN_ADJUDICATOR_LINKS:
        ok = False
        direction = "ROSE" if witness_links > FOREIGN_ADJUDICATOR_LINKS else "FELL"
        print("FAIL [A4-9] the foreign-adjudicator link count %s: measured %d, "
              "declared %d" % (direction, witness_links, FOREIGN_ADJUDICATOR_LINKS))
        if witness_links > FOREIGN_ADJUDICATOR_LINKS:
            print("    A round added foreign adjudication. Say so: set")
            print("    FOREIGN_ADJUDICATOR_LINKS = %d in scripts/lib/crossimpl_audit.py"
                  % witness_links)
            print("    in the SAME commit, so the diff carries the claim. This is the")
            print("    counter R311y569 asked for -- closing a plane is supposed to move it.")
        else:
            print("    A foreign witness was DELETED, or stopped being accepted by an")
            print("    invariant above. proven/partial cannot see this: an atom keeps its")
            print("    bit when one of its several witnesses goes away. Find which atom")
            print("    lost a test before touching the constant.")

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

    if fail_self_witness:
        ok = False
        print("FAIL [A4-8] a SELF-witnessing test claims foreign proof: %d"
              % len(fail_self_witness))
        print("    A4-3 and A4-7 ask what the FILE reaches. A file that spawns or")
        print("    links a foreign implementation ANYWHERE licensed every test in it")
        print("    to claim foreign proof, so a test that only ever drives wz could")
        print("    sit inside one and count. R311y569 and R311y570 both recorded")
        print("    that this axis cannot tell a self-witness from a foreign one;")
        print("    this is that distinction.")
        print("    The call graph is resolved through file-local fns, `common::*`")
        print("    helpers, `use zenoh_pico_sys::*` imports, and a re-exec whose")
        print("    target is named in a STRING literal. If a real foreign route is")
        print("    missed here it is one of those four shapes -- extend the resolver")
        print("    in crossimpl_corpus.py rather than weakening the claim.")
        for rel, fn, atom, kind, fclasses, tclasses in fail_self_witness:
            print("    - %s::%s claims `%s %s`; file reaches [%s] but this test "
                  "reaches [%s]" % (rel, fn, atom, kind, fclasses, tclasses))

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

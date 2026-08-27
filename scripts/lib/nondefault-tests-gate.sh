#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R2153 (no register item) — RUN the tests a non-default feature is the only way
# to reach. `nondefault-features-gate.sh` beside this one COMPILES them; nothing
# ran them before a push.
#
# The citation reads `no register item` for the reason `debt_plane_census.py`
# gives for its own: the item this closes -- unregistered open-debt item 542 --
# lives in the agent-memory register, which has no store id for
# `gate_provenance_lint.py` to resolve. The item is named in prose below.
#
# ## The defect, measured before this existed
#
# R2150 and R2151 each built an instrument in two halves, deliberately sharing no
# predicate: a PYTHON half that reads the tree (`unhonoured_kind_evidence_gate.py`,
# pre-push gate 2g) and a RUST half that owns the list shape
# (`#[test]`s in `wz-runtime-tokio`'s `zenoh_config`). Only the python half had a
# local gate.
#
#   * `zenoh_config` is `#[cfg(feature = "zenoh-config")]`, and that feature
#     is NOT in the crate's `default` set;
#   * pre-push gate 3 is `cargo test -p <pkg>` at default features, so it does
#     not compile the module at all;
#   * pre-push gate 7 is `cargo check -p <pkg> --all-features`, so it compiles
#     the tests and never runs them -- which is this item's whole point;
#   * the only place they ran was hosted Layer C1bn.
#
# MEASURED: seven `#[test]` fns in that module assert on the same constants the
# python gate parses, and all four of the Rust-half red-first probes R2150 and
# R2151 ran died at exit 101 while passing pre-push. The asymmetry was reported
# to the owner as two options -- close it, or leave it to hosted CI -- and the
# owner's answer on 2026-08-27 was to close it: run that half before the push,
# with the measured cost accepted.
#
# ## Why a shared script and not a line in the hook
#
# The lane and the hook must not be able to disagree about WHAT to run. Layer
# C1bn used to carry the command inline; it now calls this file, so there is one
# spelling of the leg and one guard on its result. Adding a leg is one row in
# LEGS below and both callers get it.
#
# ## What it refuses
#
#   * an empty LEGS table -- a gate whose population is zero reports green about
#     nothing;
#   * a malformed row;
#   * a leg whose feature field says `--all-features`. That spelling is refused
#     BY NAME, and the reason is the whole shape of this file -- see below;
#   * a leg that ran NO test. `cargo test` prints `ok` for a filter that selects
#     nothing, so "the leg passed" and "the leg ran" are different facts and only
#     the second one is worth anything;
#   * (`--census`) a test that only a feature build reaches and that no leg runs
#     and no SKIPS row excuses.
#
# ## Why the feature set is NAMED and `--all-features` is refused
#
# R2156 (open-debt item 543). The obvious way to widen this table is one row per
# crate reading `--all-features`, and it is wrong twice over:
#
#  1. It makes `--census` VACUOUS. The census defines the population as the tests
#     `--all-features` lists minus the ones default features list. A leg built
#     with `--all-features` therefore covers that set BY CONSTRUCTION -- the
#     remainder is zero for every tree, forever, and the check can never fire
#     again. That is this project's "a population of zero reports green" trap
#     with the population supplied by the check's own definition.
#  2. It silently absorbs the NEXT feature. Item 543's point is that nobody had
#     judged whether a feature-gated test is safe and quick to run locally;
#     `--all-features` makes that judgement never happen again, because tomorrow's
#     feature joins the leg without anyone deciding.
#
# A NAMED list is the pin. When a feature is added, its tests enter the census
# population and NOT the leg, the remainder goes positive, and someone has to
# decide: widen the leg, or write a SKIPS row saying why not. The list is spelled
# one feature per source line so that decision shows up as a one-line diff.
#
# MEASURED, and the reason this is not theory: `wz-ap-demo` at `--all-features`
# is RED, and correctly so. Its
# `stock_config_tests::a_key_that_is_read_while_reaching_nothing_is_not_reported_as_applied`
# is a ZERO-POPULATION guard over the keys a build drops; turn every feature on
# and no key is dropped, so the guard has no subject and fails on purpose. A
# crate-level `--all-features` leg could not have run that crate at all.
#
# ## What it does NOT cover, by name
#
# The census prints the split every run, so the honest answer is a command, not a
# sentence here. What is structurally out of reach:
#
#   * FEATURE COMBINATIONS. Each leg is ONE build. A defect that needs feature A
#     on and B off is invisible -- open-debt item 374, still without an
#     instrument;
#   * the `wz` facade crate, which `nondefault-features-gate.sh` excludes from
#     all-features entirely (a vendored `compile_error!`); `--list-members`
#     reports it as `excluded` and the census prints it as SKIPPED rather than
#     counting it silently;
#   * every test named in SKIPS, each of which carries its measured reason.
#
# Usage:
#   bash scripts/lib/nondefault-tests-gate.sh            # every leg
#   bash scripts/lib/nondefault-tests-gate.sh --list     # name them, run nothing
#   bash scripts/lib/nondefault-tests-gate.sh --census   # what is claimed by
#                                                        # nothing (a LANE, not
#                                                        # the hook: it builds
#                                                        # every crate twice)

set -uo pipefail

# `--census` decides set membership with `sort`/`comm`, and those two agree only
# when they collate the same way. This tree's shells are not all in the same
# locale, and a `comm` reading a differently-collated `sort` silently reports
# bogus differences -- which here would read as "a test nothing claims". Pinning
# the collation is what makes the population a fact rather than a locale.
export LC_ALL=C

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

# package|scope|features|test-name-filter|handed-off-tests
#
# The last two fields may be omitted; a row ending in `|` simply has neither.
#
# `handed-off-tests` is a comma-separated list of test paths THIS leg must not
# run because ANOTHER leg runs them properly. It is not an excuse and is not the
# same thing as SKIPS below: `--census` refuses a handoff whose test no other leg
# runs, so it can only ever move a test between legs, never out of the gate.
#
# `scope` is `hook` or `lane`, and it is the per-leg answer to the SECOND half of
# item 543's criterion. The item asks of every candidate leg whether it is "safe
# AND QUICK to run on a developer's machine"; `hook` says yes to both, `lane`
# says the leg is safe but too slow to sit in front of every push. A `lane` leg
# still RUNS -- Layer C1bn takes the whole table -- and `--census` counts it as
# claimed either way, so the split changes WHERE a leg runs and never whether it
# is covered. Every `lane` row carries its measured seconds.
#
# This is what keeps the standing pre-push policy honest instead of quietly
# reversing it: the hook stays fast, the full surface still runs, and the gate
# PRINTS what it deferred rather than letting a silent omission read as coverage.
#
# `features` is a comma-separated list of NON-DEFAULT feature names, never
# `--all-features` (refused by name below, for the reasons in the header). It may
# be written one feature per line with `\` continuations; whitespace is stripped,
# so the list stays diffable a line at a time.
#
# `test-name-filter` may be EMPTY, which means the whole crate at that feature
# set. An empty filter cannot hide a defect -- it runs MORE, not less -- and the
# ran-count guard below still refuses a leg that ended up running nothing.
LEGS=(
    # ── the two config-surface legs R2153 and the round before it added ──
    #
    # `zenoh_config::` is the module the two instruments live in; the filter is
    # the module path so a test ADDED there is covered without touching this row.
    "wz-runtime-tokio|hook|zenoh-config|zenoh_config::"
    # The demo's half of the same surface. Its
    # `a_key_that_is_read_while_reaching_nothing_is_not_reported_as_applied` is a
    # ZERO-POPULATION guard over the keys this build drops, which is exactly why
    # this leg names ONE feature: widen it and the guard loses its subject.
    # MEASURED: 35 tests, 4s.
    "wz-ap-demo|hook|zenoh-config|args::stock_config_tests::"
    # ── R2156 (item 543): the nine crates whose whole non-default surface
    #    was MEASURED safe to run locally ────────────────────────────────
    #
    # Each row names every non-default feature the crate has, so the census
    # population and the leg's build move together only when someone edits this
    # table. `cargo test -p <c> --all-features` was run for each before it was
    # written here -- that is the per-leg safety verdict item 543 asks for, and
    # these nine came back green:
    #
    #   capi-pico 100 tests 30s | capture 637 | coop 20 | core 7 | lwip 8
    #   mcu-session-acceptor 4  | packet-socket 9 (+2 ignored: the AF_PACKET
    #   arms degrade without privilege by design) | rest 16 | session-core 1645
    #
    # They are spelled out rather than `--all-features` for the reason in the
    # header: a named list is what makes the census a ratchet instead of a
    # tautology.
    "wz-capi-pico|hook|transport-link-quic,transport-link-tls,transport-link-unixpipe|"
    "wz-capture|hook|dissect|"
    "wz-mcu-session-acceptor|hook|buffer-pool-session-rx-slim,reassembly|"
    "wz-packet-socket|hook|tap|"
    "wz-rest|hook|rest-sse-subscribe|"
    "wz-runtime-coop|hook|\
        alloc,\
        codec-close,\
        codec-frame,\
        codec-init-body,\
        codec-keep-alive,\
        codec-open-body,\
        keyexpr-dollar-star,\
        keyexpr-includes,\
        keyexpr-wildcard-double,\
        keyexpr-wildcard-single,\
        reassembly,\
        scouting-static,\
        session-unicast,\
        session-unicast-accept,\
        session-unicast-open,\
        transport-batching,\
        transport-keepalive,\
        transport-qos\
        |"
    "wz-runtime-core|hook|alloc|"
    "wz-session-core|hook|\
        access-extauth-usrpwd,\
        adminspace-config-hotreload,\
        adminspace-core,\
        adminspace-introspection-handlers,\
        adminspace-metrics,\
        adminspace-plugins-handlers,\
        adminspace-router-linkstate,\
        attachment-bytes,\
        codec-close,\
        codec-declare,\
        codec-fragment,\
        codec-frame,\
        codec-hello,\
        codec-init-body,\
        codec-join,\
        codec-keep-alive,\
        codec-linkstate,\
        codec-open-body,\
        codec-push,\
        codec-request,\
        codec-response,\
        codec-response-final,\
        codec-scout,\
        declare-final,\
        declare-interest,\
        declare-keyexpr,\
        declare-queryable,\
        declare-subscriber,\
        declare-token,\
        declare-undeclare,\
        deferred-fire,\
        dissect,\
        dissect-serde,\
        ext-pubsub-group-membership,\
        ext-pubsub-serde-codec,\
        keyexpr-prefix,\
        liveliness-get,\
        liveliness-subscriber,\
        liveliness-token,\
        multicast-declarations,\
        no_macrostep_diagnostics,\
        no_std,\
        pubsub-attachment,\
        pubsub-congestion-control,\
        pubsub-delete,\
        pubsub-encoding,\
        pubsub-express,\
        pubsub-priority,\
        pubsub-put,\
        pubsub-qos,\
        pubsub-source-info,\
        pubsub-timestamp,\
        query-attachment,\
        query-queryable,\
        query-reply,\
        query-reply-err,\
        query-selector-parameters,\
        query-source-info,\
        query-value,\
        reassembly,\
        reply-source-info,\
        routing-namespace,\
        routing-routes,\
        scouting-active,\
        scouting-static,\
        session-extauth,\
        session-extcompression,\
        session-extqos,\
        session-extshm,\
        session-matching,\
        session-multicast,\
        session-reconnect,\
        session-unicast,\
        session-unicast-accept,\
        session-unicast-open,\
        storage-aligner,\
        storage-backend,\
        storage-history,\
        storage-mgr-garbage-collection,\
        storage-mgr-multi-storage-host,\
        storage-mgr-strip-prefix,\
        storage-mgr-wildcard-updates,\
        storage-replication,\
        switchboard,\
        transport-batching,\
        transport-compression,\
        transport-fragmentation,\
        transport-keepalive,\
        transport-link-raweth,\
        transport-link-serial,\
        transport-lowlatency,\
        transport-multilink,\
        transport-qos,\
        transport-shm,\
        transport-stats\
        |"
    "wz-session-lwip|hook|\
        buffer-pool-session-rx-slim,\
        codec-push,\
        codec-response,\
        codec-response-final,\
        liveliness-token,\
        loopif-multicast,\
        query-queryable,\
        reassembly,\
        transport-fragmentation,\
        transport-keepalive,\
        transport-multicast\
        |"
    # ── R2156 (item 543): wz-ap-demo's SECOND leg, and the HANDOFF ──────
    #
    # The row above runs the config surface at ONE feature, because the guard it
    # exists for needs a narrow build. Everything else this crate gates lives
    # across seven modules and four integration binaries -- MEASURED: a leg at
    # the five router/quic/adminspace features left 18 of the 65 unclaimed, so
    # "the modules a filter can name" was the wrong unit. This leg takes the
    # whole crate at every non-default feature instead.
    #
    # The fifth field is the HANDOFF: this leg does not run the zero-population
    # guard, because at 44 features no key is dropped, the guard has no subject
    # and fails BY DESIGN -- which is the same fact the header cites for refusing
    # `--all-features` legs. The narrow leg above runs it where it means
    # something. `--census` verifies the handoff rather than trusting it: a
    # per-leg skip whose test no OTHER leg runs is refused, so this field cannot
    # become a quiet way to drop a test.
    "wz-ap-demo|hook|\
        adminspace-config-hotreload,\
        adminspace-introspection-handlers,\
        adminspace-metrics,\
        adminspace-plugins-handlers,\
        adminspace-read,\
        adminspace-router-linkstate,\
        adminspace-write,\
        advanced,\
        group,\
        locator-iface,\
        namespace,\
        plugin-dynamic-loading,\
        preset-ap-full,\
        query-attachment,\
        quic,\
        quic-datagram,\
        router-connect-reconcile,\
        router-hat-router,\
        router-multicast-faces,\
        routing-interceptor-hotreload,\
        routing-interest-pending-gc,\
        routing-peer,\
        routing-router,\
        routing-router-hat,\
        routing-routes,\
        routing-token-tables,\
        scouting-active,\
        scouting-responder,\
        session-extcompression,\
        session-extqos,\
        session-extshm,\
        storage-backend,\
        storage-backend-filesystem,\
        storage-mgr-dynamic-volume-loading,\
        time-hlc,\
        tls,\
        transport-link-unixpipe,\
        transport-lowlatency,\
        transport-multilink,\
        transport-qos,\
        unixsock,\
        vsock,\
        ws,\
        zenoh-config\
        ||args::stock_config_tests::a_key_that_is_read_while_reaching_nothing_is_not_reported_as_applied"
    # ── R2156 (item 543): wz-runtime-tokio's WIDE leg ───────────────────
    #
    # The largest population in the workspace. `--all-features` is RED here, but
    # MEASURED: exactly TWO tests out of 1323. Excluding a whole FEATURE for two
    # tests would excuse hundreds of innocent ones, so the leg keeps every feature
    # and the two are named in SKIPS below -- the SET is pinned, not a count, and
    # each name carries what was measured about it.
    "wz-runtime-tokio|lane|\
        access-acl,\
        access-downsampling,\
        access-extauth-pubkey,\
        access-extauth-usrpwd,\
        access-quota,\
        adminspace-config-hotreload,\
        adminspace-core,\
        adminspace-introspection-handlers,\
        adminspace-metrics,\
        adminspace-plugins-handlers,\
        adminspace-read,\
        adminspace-router-linkstate,\
        adminspace-write,\
        config-mutate-runtime,\
        ext-pubsub-advanced-cache,\
        ext-pubsub-advanced-history,\
        ext-pubsub-advanced-publisher,\
        ext-pubsub-advanced-recovery,\
        ext-pubsub-advanced-subscriber,\
        ext-pubsub-group-membership,\
        ext-pubsub-sample-miss-detection,\
        ext-pubsub-serde-codec,\
        live-capture,\
        liveliness-get,\
        locator-iface,\
        multicast-declarations,\
        plugin-dynamic-loading,\
        reassembly,\
        reply-source-info,\
        router-connect-reconcile,\
        router-multicast-faces,\
        routing-accept,\
        routing-interceptor-hotreload,\
        routing-interest-pending-gc,\
        routing-namespace,\
        routing-peer,\
        routing-router-hat,\
        routing-routes,\
        routing-token-tables,\
        runtime-tokio-uring,\
        runtime-zero-copy,\
        scouting-active,\
        scouting-responder,\
        scouting-static,\
        session-extauth,\
        session-extcompression,\
        session-extqos,\
        session-extshm,\
        storage-aligner,\
        storage-backend,\
        storage-backend-filesystem,\
        storage-history,\
        storage-mgr-complete-flag,\
        storage-mgr-dynamic-volume-loading,\
        storage-mgr-garbage-collection,\
        storage-mgr-multi-storage-host,\
        storage-mgr-strip-prefix,\
        storage-mgr-wildcard-updates,\
        storage-replication,\
        switchboard,\
        time-hlc,\
        transport-compression,\
        transport-fragmentation,\
        transport-link-quic,\
        transport-link-quic-datagram,\
        transport-link-raweth,\
        transport-link-serial,\
        transport-link-tls,\
        transport-link-tls-keylog,\
        transport-link-unixpipe,\
        transport-link-unixsock,\
        transport-link-vsock,\
        transport-link-ws,\
        transport-lowlatency,\
        transport-multicast,\
        transport-multilink,\
        transport-qos,\
        transport-shm,\
        transport-stats,\
        zenoh-config\
        |"
)

# package|test-path|reason
#
# Tests a leg must NOT run, each with what was MEASURED about it. This is the
# only escape hatch, and it is deliberately the narrowest one available: a NAME,
# not a count and not a whole feature. `--census` refuses a row whose test no
# longer exists, so a rename cannot leave a silent excuse behind.
#
# A SKIPS row does double duty: the leg run passes `--skip <path>`, and the
# census treats the name as claimed. Both readings come from this one table, so
# "what we do not run" and "what we do not count" cannot drift apart.
SKIPS=(
    # Its premise is `ws`/`tls` name-dialling being UNWIRED, so it asserts a
    # typed `Unsupported` arrives before any I/O. Turn `transport-link-ws` on and
    # the dial IS wired, the premise is void, and the assertion fails on what the
    # NETWORK said -- MEASURED `left: NetworkUnreachable` after resolving
    # `example.org`, and it is what made the all-features run take 270s. A test
    # that reaches the network is the one thing item 543 says must never enter a
    # local hook, which is why the wide leg above still needs this row.
    "wz-runtime-tokio|session_open::tests::ws_and_tls_named_dial_is_unsupported_without_io|\
a wired ws/tls dial reaches the real network (measured: NetworkUnreachable on example.org:7447)"
    # A pinned OpenMetrics body. `transport-stats` adds four counters (tx_bytes,
    # rx_bytes, wz_tx_batches, wz_rx_batches) that the pinned text does not
    # carry, so the equality fails on a body that is CORRECT for the wider build.
    # Not a defect and not a network risk -- the pin simply describes a narrower
    # build than this leg makes.
    "wz-runtime-tokio|session::tests::declare_adminspace_metrics_get_returns_openmetrics_text|\
the pinned OpenMetrics text describes a build without transport-stats' four counters"
    # ⚠ NOT a premise problem like the two above -- this one is a genuine RACE,
    # and it is the first defect this widened table found rather than caused.
    # `transport-link-unixpipe` is non-default, so gate 3 never compiled this
    # module and NO leg ran it: the test had never executed in a gate at all.
    # MEASURED, alone, same tree, same feature set: run 1 hung and was killed at
    # the 180s timeout; runs 2 and 3 passed in ~1s. In a whole-crate run it hung
    # 719s before it was killed, while an earlier whole-crate run passed it. So
    # it is intermittent, roughly 1-in-3 here, and a hang -- not a failure -- so
    # a lane that ran it would not go red, it would STOP.
    # Skipped rather than fixed on purpose: the fix is a change to the two-dialer
    # FIFO rendezvous, which is a different seam from this table's, and pinning
    # it here keeps the leg's verdict meaningful in the meantime. It is filed as
    # open-debt item 544, and this row is what must be deleted when 544 closes.
    "wz-runtime-tokio|unixpipe_pipeline::tests::two_dialers_get_distinct_dedicated_pairs|\
an intermittent HANG in the two-dialer FIFO rendezvous (measured 1-in-3 alone, 719s in-suite); open-debt item 544"
)

if [[ ${#LEGS[@]} -eq 0 ]]; then
    echo "nondefault-tests: FAIL -- the LEGS table is empty. A gate with no" >&2
    echo "  population reports green about nothing; either restore the legs or" >&2
    echo "  delete this gate and say so." >&2
    exit 1
fi

# Whitespace is what lets a feature list be written one name per line.
leg_feats() { local f="${1}"; echo "${f//[[:space:]]/}"; }

# Every row's scope must be one of two words. A typo would otherwise read as
# "not hook", i.e. it would silently REMOVE a leg from the push gate -- the one
# direction a mistake here must never take.
for leg in "${LEGS[@]}"; do
    IFS='|' read -r _p _s _f _r _h <<<"$leg"
    if [[ "$_s" != "hook" && "$_s" != "lane" ]]; then
        echo "nondefault-tests: FAIL -- leg '$_p' has scope '$_s'; it must be" >&2
        echo "  'hook' or 'lane'. An unrecognised scope would drop the leg from" >&2
        echo "  the push gate without saying so." >&2
        exit 1
    fi
done

if [[ "${1:-}" == "--list" ]]; then
    for leg in "${LEGS[@]}"; do
        IFS='|' read -r pkg scope feats filter handoff <<<"$leg"
        echo "  [$scope] $pkg --features $(leg_feats "$feats") ${filter:-<whole crate>}"
        [[ -n "$handoff" ]] && echo "          hands off to another leg: $handoff"
    done
    for row in "${SKIPS[@]}"; do
        IFS='|' read -r pkg spath _ <<<"$row"
        echo "  $pkg SKIPS $spath"
    done
    exit 0
fi

# ─── --census (R2156, open-debt item 543) ───────────────────────────
#
# The LEGS table says what the hook RUNS. It does not say what the hook LEAVES,
# and item 542 shipped with a single leg precisely because nobody had counted the
# rest. This mode counts them, and then refuses the ones nothing claims.
#
# THE POPULATION IS DERIVED, not observed: per crate, the tests
# `cargo test -- --list` reports with `--all-features` minus the ones it reports
# at default features. Every member of that difference must be run by a leg or
# named in SKIPS. A crate whose difference is empty needs nothing.
#
# ⚠ LISTING at `--all-features` is not RUNNING at `--all-features`. `-- --list`
# compiles and enumerates; it never executes a test, so it is safe for crates
# whose all-features RUN is red (`wz-ap-demo` and `wz-runtime-tokio` both are).
# That distinction is what lets the population be defined this way while every
# leg is still built from a named feature set.
#
# It belongs in a LANE, not the hook: it builds every crate twice over. Layer
# C1cn already pays for the all-features side.
#
# ⚠ Two things measured while building this, so the next round does not
# re-derive them:
#   * `-- --list` INCLUDES `#[ignore]`d tests (wz-session-core lists 1646 and
#     runs 1645 + 1 ignored), so a listed count is not a run count;
#   * the difference is not one-way -- `wz-capi-c` LOSES a test under
#     `--all-features` -- so this counts only the "only with features" side and
#     says so rather than pretending all-features is a superset.
if [[ "${1:-}" == "--census" ]]; then
    members="$(bash "$here/nondefault-features-gate.sh" --list-members)" || {
        echo "nondefault-tests: FAIL -- could not read the member set from" \
             "nondefault-features-gate.sh --list-members" >&2
        exit 1
    }
    [[ -n "$members" ]] || {
        echo "nondefault-tests: FAIL -- the member set came back empty" >&2
        exit 1
    }

    tmp="$(mktemp -d)" || exit 1
    trap 'rm -rf "$tmp"' EXIT

    # `cargo test -- --list` for one package at one feature spelling, reduced to
    # sorted unique test paths. Never runs a test.
    list_names() {
        local pkg="$1" feats="$2" filter="$3"
        local -a argv=(test -p "$pkg")
        if [[ "$feats" == "@all" ]]; then
            argv+=(--all-features)
        elif [[ -n "$feats" ]]; then
            argv+=(--features "$feats")
        fi
        [[ -n "$filter" ]] && argv+=("$filter")
        (cd "$repo/crates" && cargo "${argv[@]}" -- --list 2>/dev/null) |
            grep -E ': test$' | sed 's/: test$//' | sort -u
    }

    rc=0
    total=0
    crates_with=0
    checked_rows=""
    while read -r pkg tier; do
        [[ -n "$pkg" ]] || continue
        if [[ "$tier" == "excluded" ]]; then
            echo "  census: $pkg SKIPPED -- gate 7 excludes it from all-features"
            continue
        fi

        list_names "$pkg" "" "" > "$tmp/d"
        list_names "$pkg" "@all" "" > "$tmp/a"
        comm -13 "$tmp/d" "$tmp/a" > "$tmp/diff"
        n="$(grep -c . < "$tmp/diff" || true)"
        [[ "$n" -eq 0 ]] && continue
        total=$((total + n))
        crates_with=$((crates_with + 1))

        # What the legs actually RUN, intersected with the population. Two traps
        # here, both measured:
        #   * claiming the whole crate because it has a leg -- `wz-ap-demo` has
        #     two legs and each runs a different part of its population;
        #   * crediting a leg with every population name its FILTER matches. A
        #     leg builds at its own named feature set, which is NOT
        #     `--all-features`: 42 of ap-demo's population match the narrow leg's
        #     filter while that leg's own build holds only 35 of them.
        # So each leg is asked what it LISTS, and that is intersected with the
        # population. A filter is not a build.
        # Both scopes count as covered here. The census answers "does anything
        # RUN this test", and a `lane` leg runs it -- just not in front of every
        # push. Scoping this by `hook` would report the lane's work as a gap.
        # Every name this package's SKIPS rows remove, from EVERY leg of it.
        : > "$tmp/gskip"
        for row in "${SKIPS[@]}"; do
            IFS='|' read -r sp spath _ <<<"$row"
            [[ "$sp" == "$pkg" ]] && echo "$spath" >> "$tmp/gskip"
        done
        sort -u "$tmp/gskip" -o "$tmp/gskip"

        : > "$tmp/cov"
        : > "$tmp/handed"
        for leg in "${LEGS[@]}"; do
            IFS='|' read -r lp _lscope lfeats lfilter lhand <<<"$leg"
            [[ "$lp" == "$pkg" ]] || continue
            list_names "$lp" "$(leg_feats "$lfeats")" "$lfilter" > "$tmp/leg"
            # LISTED is not RUN. Subtract what this leg is told to skip -- its
            # own handoffs and the package's SKIPS -- or the census would credit
            # a leg with tests it deliberately does not execute.
            : > "$tmp/legskip"
            cat "$tmp/gskip" >> "$tmp/legskip"
            if [[ -n "$lhand" ]]; then
                tr ',' '\n' <<<"${lhand//[[:space:]]/}" >> "$tmp/legskip"
                tr ',' '\n' <<<"${lhand//[[:space:]]/}" >> "$tmp/handed"
            fi
            grep -v '^$' "$tmp/legskip" | sort -u > "$tmp/legskip.s"
            comm -23 "$tmp/leg" "$tmp/legskip.s" > "$tmp/legruns"
            comm -12 "$tmp/diff" "$tmp/legruns" >> "$tmp/cov"
        done
        sort -u "$tmp/cov" -o "$tmp/cov"
        grep -v '^$' "$tmp/handed" | sort -u > "$tmp/handed.s"

        # A handoff is a CLAIM that another leg runs the test. Verify it: if the
        # name is not in what some leg actually runs, the field has quietly
        # dropped a test instead of moving it, which is the one thing it must
        # never be able to do.
        while read -r hname; do
            [[ -n "$hname" ]] || continue
            if ! grep -qxF -- "$hname" "$tmp/cov"; then
                echo "nondefault-tests: FAIL -- $pkg hands off $hname, but no" >&2
                echo "  other leg RUNS it. A handoff may move a test between" >&2
                echo "  legs; it may not remove it. Point a leg at it, or make" >&2
                echo "  it a SKIPS row with a reason." >&2
                rc=1
            fi
        done < "$tmp/handed.s"

        # A skipped name counts as claimed -- that is what a skip IS -- but only
        # for its own package, and only while the test still exists.
        : > "$tmp/exc"
        for row in "${SKIPS[@]}"; do
            IFS='|' read -r sp spath _ <<<"$row"
            [[ "$sp" == "$pkg" ]] || continue
            checked_rows="$checked_rows $sp>$spath"
            if ! grep -qxF -- "$spath" "$tmp/a"; then
                echo "nondefault-tests: FAIL -- SKIPS names $sp $spath, which" >&2
                echo "  no longer exists at --all-features. A renamed or deleted" >&2
                echo "  test must not leave its excuse behind. Drop the row." >&2
                rc=1
                continue
            fi
            grep -xF -- "$spath" "$tmp/diff" >> "$tmp/exc" || true
        done
        sort -u "$tmp/exc" -o "$tmp/exc"

        covered="$(grep -c . < "$tmp/cov" || true)"
        excused="$(grep -c . < "$tmp/exc" || true)"
        cat "$tmp/cov" "$tmp/exc" | sort -u > "$tmp/claimed"
        comm -13 "$tmp/claimed" "$tmp/diff" > "$tmp/rest"
        remainder="$(grep -c . < "$tmp/rest" || true)"

        if [[ "$remainder" -eq 0 ]]; then
            line="  census: $pkg $n only-with-features -- $covered run by a leg"
            [[ "$excused" -gt 0 ]] && line="$line, $excused skipped by name"
            echo "$line"
        else
            echo "nondefault-tests: FAIL -- $pkg has $n test(s) only a feature" >&2
            echo "  build reaches; legs run $covered and SKIPS excuses $excused," >&2
            echo "  leaving $remainder claimed by NOTHING. Widen a leg's feature" >&2
            echo "  list, add a leg, or write a SKIPS row saying why not." >&2
            head -10 "$tmp/rest" | sed 's/^/    unclaimed: /' >&2
            [[ "$remainder" -gt 10 ]] &&
                echo "    ... and $((remainder - 10)) more" >&2
            rc=1
        fi
    done <<<"$members"

    # A population of zero would make every check above vacuously green.
    if [[ "$total" -eq 0 ]]; then
        echo "nondefault-tests: FAIL -- no crate has a test that only a feature" >&2
        echo "  build reaches. Either the derivation is dead or this workspace" >&2
        echo "  stopped gating tests on features; both make this census report" >&2
        echo "  a clean tree while measuring nothing." >&2
        exit 1
    fi

    # The mirror defect: an excuse kept for a package the loop never reached, so
    # the staleness check above never ran on it.
    for row in "${SKIPS[@]}"; do
        IFS='|' read -r sp spath _ <<<"$row"
        if [[ " $checked_rows " != *" $sp>$spath "* ]]; then
            echo "nondefault-tests: FAIL -- SKIPS names $sp $spath, but the" >&2
            echo "  census never examined that package, so nothing checked the" >&2
            echo "  row is still true. Drop it, or make the package a member." >&2
            rc=1
        fi
    done

    echo "  census: $crates_with crate(s) carry $total test(s) only a feature build reaches"
    exit $rc
fi

# `--all-legs` is Layer C1bn's shape: hosted CI runs the whole table. With no
# argument this is the HOOK's shape and runs only the `hook` legs.
want_all=0
[[ "${1:-}" == "--all-legs" ]] && want_all=1

rc=0
deferred=()
for leg in "${LEGS[@]}"; do
    IFS='|' read -r pkg scope feats filter handoff <<<"$leg"
    feats="$(leg_feats "$feats")"
    handoff="${handoff//[[:space:]]/}"
    if [[ -z "$pkg" || -z "$feats" ]]; then
        echo "nondefault-tests: FAIL -- malformed leg row: '$leg'" >&2
        exit 1
    fi
    if [[ $want_all -eq 0 && "$scope" != "hook" ]]; then
        deferred+=("$pkg ${filter:-<whole crate>}")
        continue
    fi
    # Refused BY NAME, not merely absent. `--all-features` in a leg would make
    # `--census` vacuous -- the population is DEFINED as what all-features lists,
    # so such a leg covers it by construction and the check could never fire
    # again. The header carries the argument; this is the guard that enforces it.
    if [[ "$feats" == *"all-features"* ]]; then
        echo "nondefault-tests: FAIL -- leg '$pkg' asks for all-features." >&2
        echo "  Name the features instead. A leg built with every feature on" >&2
        echo "  covers the census population BY CONSTRUCTION, which turns the" >&2
        echo "  census into a check that can never fail again." >&2
        exit 1
    fi

    # What this leg must not run: the package's SKIPS (nothing runs these) plus
    # this leg's own handoffs (another leg runs these).
    skip_args=()
    for row in "${SKIPS[@]}"; do
        IFS='|' read -r sp spath _ <<<"$row"
        [[ "$sp" == "$pkg" ]] || continue
        skip_args+=(--skip "$spath")
    done
    if [[ -n "$handoff" ]]; then
        while IFS= read -r h; do
            [[ -n "$h" ]] && skip_args+=(--skip "$h")
        done < <(tr ',' '\n' <<<"$handoff")
    fi

    cargo_args=(test -p "$pkg" --features "$feats")
    [[ -n "$filter" ]] && cargo_args+=("$filter")
    cargo_args+=(--quiet)
    [[ ${#skip_args[@]} -gt 0 ]] && cargo_args+=(-- "${skip_args[@]}")

    out="$(cd "$repo/crates" && cargo "${cargo_args[@]}" 2>&1)"
    status=$?
    label="$pkg --features <$(awk -F, '{print NF}' <<<"$feats")> ${filter:-<whole crate>}"
    if [[ $status -ne 0 ]]; then
        echo "nondefault-tests: FAIL -- $label (exit $status)" >&2
        echo "$out" >&2
        rc=1
        continue
    fi
    # A filter that selects nothing still prints `ok`. Read the COUNT, which is
    # the only line that distinguishes "passed" from "ran". SUMMED across test
    # binaries rather than maxed: a whole-crate leg produces one line per binary,
    # and reporting the largest would under-report what the leg actually ran.
    ran="$(grep -oE '^test result: ok\. [0-9]+ passed' <<<"$out" |
        grep -oE '[0-9]+' | awk '{s+=$1} END {print s+0}')"
    if [[ -z "$ran" || "$ran" -lt 1 ]]; then
        echo "nondefault-tests: FAIL -- $label matched NO test." >&2
        echo "  The leg passed and ran nothing, which is the shape a renamed or" >&2
        echo "  moved module leaves behind. Re-point the leg in LEGS." >&2
        echo "$out" >&2
        rc=1
        continue
    fi
    echo "  nondefault-tests: $label -> $ran test(s)"
done

# An omission must never read as coverage. Whatever this invocation did NOT run
# is named here, with the reader pointed at where it does run -- the "print the
# breakdown, not the total" rule this project keeps relearning.
if [[ ${#deferred[@]} -gt 0 ]]; then
    echo "  nondefault-tests: ${#deferred[@]} leg(s) deferred to Layer C1bn" \
         "(scope=lane; hosted CI runs them via --all-legs):"
    for d in "${deferred[@]}"; do
        echo "    deferred: $d"
    done
fi

exit $rc

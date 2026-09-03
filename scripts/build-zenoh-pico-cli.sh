#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# build-zenoh-pico-cli.sh — build a curated set of zenoh-pico Unix
# C11 CLI binaries from the vendored submodule for AP MVP demo
# round-trip integration tests.
#
# The watching-zenoh AP MVP demo (wz-ap-demo) exercises its codec +
# session FSM against an external, foreign-implementation peer.
# Using the upstream zenoh-pico CLI binaries (z_put / z_pub / z_get /
# z_queryable / z_querier / z_sub / z_liveliness / z_sub_liveliness /
# z_get_liveliness) — built
# from the same submodule revision that zenoh-pico-sys binds against — gives
# that "external peer" without duplicating the vendor tree and without
# depending on a system zenoh-pico install.
#
# Output: target/zenoh-pico-cli/{z_put,z_pub,z_sub,z_get,z_queryable,z_querier,z_liveliness,z_sub_liveliness,z_get_liveliness}
#
# Re-runs are idempotent: CMake's incremental build skips unchanged
# work, and the install step uses `install -m 0755` (overwrite
# atomic).
#
# Note: zenoh-pico-sys/build.rs builds libzenohpico.a as a static
# library with examples/tools targets disabled (see its build.rs L40+
# policy). This script is the dedicated path for CLI executables and
# is intentionally separate from the sys crate — sys = FFI binding,
# this script = test-infra CLI binary build.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# R2326 (unregistered open-debt item 10) — the provenance stamp these artefacts
# carry. A pico binary states nothing about itself (no version string, an
# unversioned soname), so the record this writes is the only answer there is to
# "which submodule state is this oracle". See scripts/lib/vendored-oracle.sh.
# shellcheck source=scripts/lib/vendored-oracle.sh
source "$ROOT/scripts/lib/vendored-oracle.sh"

VENDOR_DIR="$ROOT/vendor/zenoh-pico"
EXAMPLES_DIR="$VENDOR_DIR/examples"
BUILD_DIR="$ROOT/target/zenoh-pico-build"
INSTALL_DIR="$ROOT/target/zenoh-pico-cli"

# Curated CLI binary set: the four that the AP MVP demo round-trip
# matrix needs (R121c+ integration tests). Adding more here costs
# only a few extra add_dependencies(examples ...) targets in the
# CMake build; the wz-codec coverage matrix decides which round
# adopts each new external CLI.
# R311y478 — z_pong joins as the counterparty for the §5.27 api-compat-pico
# drop-in witness. It is the ECHO half of upstream's latency pair: it subscribes
# `test/ping` and republishes each sample to `test/pong`. That makes it the only
# oracle in this set that exercises a wz-ABI program's publish AND subscribe in
# ONE round trip, which is what the `z_ping.c`-on-wz leg needs. Its own keyexprs
# are hard-coded in the example, so no flag threading is required.
# R311y481 — z_queryable_attachment joins as the ONLY stock oracle that reads
# an INBOUND Query's attachment. The plain z_queryable ignores it entirely
# (`z_queryable.c` never calls `z_query_attachment`), and z_get_attachment is the
# opposite direction (it ATTACHES to an outbound get and reads the REPLY). So a
# `query-attachment` witness — wz attaches, a foreign process decodes — has no
# other oracle in this set. Its handler runs
# `ze_deserializer_deserialize_sequence_length` then a per-element string pair
# and prints `with attachment:` + `i: <key>, <value>`
# (`z_queryable_attachment.c:32-37,71-87`), so wz must emit pico's
# `ze_serializer` kv-pair wire form, not an opaque blob — same constraint the
# y-era `z_sub_attachment` push witness already lives under.
# R311y488 — z_advanced_sub / z_advanced_pub join as the ONLY foreign oracles
# for the ADVANCED pub/sub plane. Before this the `ext-pubsub-*` atoms had a
# zenoh-ext (Rust) witness and no pico one, and could not have had: pico's
# advanced pub/sub is compiled OUT by the vendor default, so every advanced
# example in this tree was a `#else` STUB main. They are the pair, not one
# each way: z_advanced_sub carries the history/recovery/miss-detection and
# publisher-detection surface (liveliness token discovery), z_advanced_pub the
# cache + sequencing side.
# R311y532 — four more, added solely as COUNTERPARTIES so the remaining
# undriven drop-in programs get a foreign partner. Each is the other half of a
# pair whose wz-side half already links: z_ping answers a wz z_pong, z_get_lat
# drives a wz z_queryable_lat, z_pub_thr feeds a wz z_sub_thr, and
# z_get_attachment sends the attachment a wz z_queryable_attachment reads back.
# None of the four is a SUBJECT here (the wz-linked build of each is what the
# drop-in suite exercises); they exist so the verdict can come from outside.
# R311y534 — z_sub_tls + z_pub_tls join as the FOREIGN half of the TLS pair,
# BOTH of them, because the pair is directional: a wz-side publisher needs a
# foreign subscriber to report what it decoded, and a wz-side subscriber needs a
# foreign publisher to have produced the bytes. Building only one would leave one
# of the two TLS legs talking to wz on both ends. They are also what CALIBRATES
# the topology — foreign-to-foreign over the same TLS listen/connect pair, which
# is the run that says whether a red leg is wz's fault or the topology's.
# Turning
# `Z_FEATURE_LINK_TLS` on (see the configure below) gives `z_pub_tls.c` /
# `z_sub_tls.c` a real body on BOTH sides at once: the drop-in suite compiles
# them against wz's cdylib, and this builds upstream's own TLS-capable binary so
# the wz-side publisher has a counterparty that is not wz. Without it the TLS
# legs could only be wz talking to wz, which is the one topology that cannot
# distinguish "wz speaks TLS" from "wz and wz agree about something".
TARGETS=(z_put z_pub z_sub z_get z_queryable z_querier z_liveliness z_sub_liveliness z_get_liveliness z_sub_attachment z_pub_attachment z_pong z_queryable_attachment z_advanced_sub z_advanced_pub z_ping z_get_lat z_pub_thr z_get_attachment z_sub_tls z_pub_tls)

if [[ ! -e "$VENDOR_DIR/.git" && ! -f "$VENDOR_DIR/CMakeLists.txt" ]]; then
    echo "build-zenoh-pico-cli: vendor/zenoh-pico/ not initialized." >&2
    echo "  run: git -C \"$ROOT\" submodule update --init vendor/zenoh-pico" >&2
    exit 1
fi

if ! command -v cmake >/dev/null 2>&1; then
    echo "build-zenoh-pico-cli: cmake not found on PATH" >&2
    exit 1
fi

echo "build-zenoh-pico-cli: building from vendor/zenoh-pico/examples" >&2
echo "build-zenoh-pico-cli: pin = $(git -C "$VENDOR_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)" >&2

# R216 — wz-side build-time patch on vendor/zenoh-pico/examples/
# unix/c11/z_put.c. The patch switches the PUT congestion control
# default from upstream's DROP (constants.h::z_internal_congestion_
# control_default_push) to BLOCK. DROP is the right default for a
# sustained high-throughput publisher loop where dropping under
# back-pressure is preferable to head-of-line blocking; it is the
# wrong default for a one-shot CLI where the only PUT silently
# dropping on a keep_alive task / main thread mutex race breaks
# every Layer E integration test that round-trips through z_put.
# Pre-patch flake rate during R216 50x audit: ~6 % standalone,
# ~20 % under the parallel 5-test Layer E lane. The race lives in
# zenoh-pico tx.c::_z_transport_tx_send_n_msg where DROP semantics
# use try_lock — contended with the keep_alive worker's blocking
# lock — and drops the message on contention.
#
# Patch lifecycle: applied IN-PLACE (vendor/zenoh-pico/examples is
# inside a submodule but the staged-tree alternative collides with
# zenoh-pico's CMakeLists.txt which references `../cmake/helpers.
# cmake` and `configure_include_project ".." ...` — both relative
# to the in-tree examples path). A `trap` revert restores the file
# to its committed state on exit (success, error, or signal). The
# revert uses `git checkout` rather than a backup-file mv so an
# interrupted earlier run that left a partial patch behind is
# still cleaned up. THIRD_PARTY.md vendor/zenoh-pico section
# documents this divergence.
#
# R311y240 / R311y244 / R311y245 — SECOND + THIRD + FOURTH in-place
# example patches land below (z_sub_attachment.c qos+source_info print;
# z_queryable.c query source_info print; z_get.c reply source_info
# print). Bash keeps ONE `trap ... EXIT` handler, so a separate
# `trap ... EXIT` per file would SILENTLY REPLACE this one and disable
# the earlier reverts. All git-checkouts therefore live in ONE handler,
# wired once — which also makes the up-front restore-first cover every
# patched file.
restore_pico_example_patches() {
    if [[ -e "$VENDOR_DIR/.git" ]]; then
        git -C "$VENDOR_DIR" checkout -- examples/unix/c11/z_put.c 2>/dev/null || true
        git -C "$VENDOR_DIR" checkout -- examples/unix/c11/z_sub_attachment.c 2>/dev/null || true
        git -C "$VENDOR_DIR" checkout -- examples/unix/c11/z_queryable.c 2>/dev/null || true
        git -C "$VENDOR_DIR" checkout -- examples/unix/c11/z_get.c 2>/dev/null || true
    fi
}
trap restore_pico_example_patches EXIT

# Restore first so the patch anchor greps below match the committed
# shape even if a previous run aborted mid-build (leftover patches).
restore_pico_example_patches

z_put_src="$EXAMPLES_DIR/unix/c11/z_put.c"
if grep -q "z_put(z_loan(s), z_loan(ke), z_move(payload), NULL)" "$z_put_src"; then
    # Insert the BLOCK options struct just before the "Putting Data"
    # log line, then swap the NULL options argument for &opts. The
    # anchor lines are unique within z_put.c at the current pin.
    sed -i '
        /printf("Putting Data/i\
    z_put_options_t opts;\
    z_put_options_default(\&opts);\
    opts.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
        s|z_put(z_loan(s), z_loan(ke), z_move(payload), NULL)|z_put(z_loan(s), z_loan(ke), z_move(payload), \&opts)|
    ' "$z_put_src"
    if ! grep -q "Z_CONGESTION_CONTROL_BLOCK" "$z_put_src"; then
        echo "build-zenoh-pico-cli: BLOCK-congestion patch failed to land in $z_put_src" >&2
        exit 2
    fi
    echo "build-zenoh-pico-cli: applied BLOCK-congestion patch to z_put.c" >&2
else
    echo "build-zenoh-pico-cli: z_put.c upstream shape changed (NULL options literal absent);" >&2
    echo "  the wz-side BLOCK patch anchor is missing. Re-verify the patch against the" >&2
    echo "  current vendor pin (current: $(git -C "$VENDOR_DIR" rev-parse --short HEAD)) before continuing." >&2
    exit 2
fi

# R311y240 / R311y242 / R311y243 / R311y246 — wz-side build-time patch on
# vendor/zenoh-pico/examples/unix/c11/z_sub_attachment.c. The stock
# example prints the received sample's encoding / timestamp /
# attachment but NOT its sample kind, qos byte, or source_info. This
# patch adds `with kind:` (z_sample_kind — 0=PUT / 1=DELETE, stable API,
# the R311y246 Del-carrier discriminator) / `with priority:` /
# `with congestion:` / `with express:` (the packed QoS byte, stable API)
# and — under `#ifdef Z_FEATURE_UNSTABLE_API` —
# `with source_info eid: .. sn: ..` (z_sample_source_info is an UNSTABLE
# getter; the cmake config below sets -DZ_FEATURE_UNSTABLE_API=ON, and
# the #ifdef keeps the file compiling if a future config omits it). So
# the CLI becomes the FOREIGN witness for wz's Push metadata
# propagation: the QoS sub-fields (priority:
# tests/wz_priority_to_pico_zsub.rs, R311y240; congestion + express:
# tests/wz_qos_congestion_express_to_pico_zsub.rs, R311y242) and
# source_info (tests/wz_source_info_to_pico_zsub.rs, R311y243). Same
# lifecycle as the z_put patch above: applied in-place, reverted by the
# shared trap.
#
# Idempotency hazard (WHY the explicit marker check below): the z_put
# patch is self-guarding — its anchor `z_put(.., NULL)` is CONSUMED by
# the patch (rewritten to `&opts`), so a leftover-patched file fails the
# anchor grep and the else-branch exit 2 fires. This patch's anchor is a
# COMMENT (`// Check timestamp`) that SURVIVES the insert, so a restore
# miss (e.g. SIGKILL before the trap) would let a stale marker slip the
# anchor grep and DOUBLE-insert the printf. Hard-reject when the marker
# is already present so a dirty submodule tree errors loudly instead.
# THIRD_PARTY.md vendor/zenoh-pico section documents this divergence.
z_sub_att_src="$EXAMPLES_DIR/unix/c11/z_sub_attachment.c"
if grep -q "with priority:" "$z_sub_att_src"; then
    echo "build-zenoh-pico-cli: z_sub_attachment.c already prints 'with priority:'" >&2
    echo "  — either a prior patch was not reverted (dirty submodule tree; revert with" >&2
    echo "  'git -C \"$VENDOR_DIR\" checkout -- examples/unix/c11/z_sub_attachment.c')" >&2
    echo "  or a vendor-pin bump added a native priority print (re-verify the patch)." >&2
    exit 2
fi
if grep -q "// Check timestamp" "$z_sub_att_src"; then
    # `#`-delimited address: the anchor contains `//`, which would
    # collide with sed's default `/.../` delimiter. `\\n` becomes a
    # literal `\n` in the emitted C (GNU sed processes `\n` in i-text
    # as a real newline, which would split the string literal).
    sed -i '
        \#// Check timestamp#i\
    printf("    with kind: %d\\n", (int)z_sample_kind(sample));\
    printf("    with priority: %d\\n", (int)z_sample_priority(sample));\
    printf("    with congestion: %d\\n", (int)z_sample_congestion_control(sample));\
    printf("    with express: %d\\n", (int)z_sample_express(sample));\
#ifdef Z_FEATURE_UNSTABLE_API\
    const z_source_info_t *wz_si = z_sample_source_info(sample);\
    if (wz_si != NULL) {\
        z_entity_global_id_t wz_gid = z_source_info_id(wz_si);\
        printf("    with source_info eid: %u sn: %u\\n", (unsigned)z_entity_global_id_eid(\&wz_gid), (unsigned)z_source_info_sn(wz_si));\
    }\
#endif
    ' "$z_sub_att_src"
    # Post-insert marker tripwire (belt-and-suspenders, same shape as the
    # y240 single-line check). With `set -e` plus the `// Check timestamp`
    # anchor guard above, control only reaches here after an atomic sed
    # insert, so all three markers are expected present — this grep is NOT
    # a getter-existence check. A renamed vendor getter is still written
    # verbatim here and fails loudly at the C compile (undefined symbol);
    # a getter that decodes the wrong field is caught by the two
    # integration tests' runtime assertions. The tripwire's residual value
    # is narrow: it trips only if a future edit to the sed program above
    # stops emitting a line without failing sed's own exit code.
    if ! grep -q "with kind:" "$z_sub_att_src" ||
        ! grep -q "with priority:" "$z_sub_att_src" ||
        ! grep -q "with congestion:" "$z_sub_att_src" ||
        ! grep -q "with express:" "$z_sub_att_src" ||
        ! grep -q "with source_info" "$z_sub_att_src"; then
        echo "build-zenoh-pico-cli: qos/source_info-print patch failed to land in $z_sub_att_src" >&2
        exit 2
    fi
    echo "build-zenoh-pico-cli: applied kind+qos+source_info print patch (kind/priority/congestion/express/source_info) to z_sub_attachment.c" >&2
else
    echo "build-zenoh-pico-cli: z_sub_attachment.c upstream shape changed (// Check timestamp" >&2
    echo "  anchor absent); re-verify the priority patch against the current vendor pin" >&2
    echo "  (current: $(git -C "$VENDOR_DIR" rev-parse --short HEAD)) before continuing." >&2
    exit 2
fi

# R311y244 — THIRD in-place example patch on
# vendor/zenoh-pico/examples/unix/c11/z_queryable.c. The stock query
# handler prints the received query's keyexpr / parameters / value but
# NOT its source_info. This patch adds `with query source_info eid: ..
# sn: ..` (z_query_source_info + z_source_info_id / z_source_info_sn).
# Unlike the Put carrier's z_sample_source_info (UNSTABLE-gated,
# primitives.h:2218 block), these query / source-info getters are
# declared UNCONDITIONALLY (primitives.h:1013 / :1156, after the
# UNSTABLE block closes at :769), so NO `#ifdef Z_FEATURE_UNSTABLE_API`
# guard is needed here (they compile whether or not the flag is set;
# the cmake config sets it ON for z_sub_attachment regardless). This
# makes the CLI the FOREIGN witness for wz's QUERY-carrier source_info
# propagation (tests/wz_query_source_info_to_pico_zqueryable.rs).
#
# R311y548 EXTENDS it with `with query encoding:` (z_query_encoding, also
# declared unconditionally). R311y547 wired the zenoh-c ABI's
# `z_get_options_t::encoding` onto the Query value ext and could only prove it
# at the seam, recording an explicit NON-CLAIM: "no zenoh-pico example renders
# the encoding of a query it received". That was true of the STOCK example and
# is not a property of pico -- the accessor has always been there. Adding the
# print is the same move R311y240 made for the sample QoS, and it turns the
# non-claim into a foreign witness.
# Anchor
# is the `// Process value` comment (survives the insert), so — like the
# z_sub_attachment patch — hard-reject when the marker is already present
# rather than double-insert. Reverted by the shared trap.
z_qabl_src="$EXAMPLES_DIR/unix/c11/z_queryable.c"
if grep -q "with query source_info" "$z_qabl_src" || grep -q "with query encoding" "$z_qabl_src"; then
    echo "build-zenoh-pico-cli: z_queryable.c already carries a wz print patch" >&2
    echo "  — revert with 'git -C \"$VENDOR_DIR\" checkout -- examples/unix/c11/z_queryable.c'" >&2
    echo "  or re-verify the patch against the current vendor pin." >&2
    exit 2
fi
if grep -q "// Process value" "$z_qabl_src"; then
    sed -i '
        \#// Process value#i\
    const z_source_info_t *wz_qsi = z_query_source_info(query);\
    if (wz_qsi != NULL) {\
        z_entity_global_id_t wz_qgid = z_source_info_id(wz_qsi);\
        printf("    with query source_info eid: %u sn: %u\\n", (unsigned)z_entity_global_id_eid(\&wz_qgid), (unsigned)z_source_info_sn(wz_qsi));\
    }\
    z_owned_string_t wz_qenc;\
    z_encoding_to_string(z_query_encoding(query), \&wz_qenc);\
    printf("    with query encoding: %.*s\\n", (int)z_string_len(z_loan(wz_qenc)), z_string_data(z_loan(wz_qenc)));\
    z_drop(z_move(wz_qenc));
    ' "$z_qabl_src"
    if ! grep -q "with query encoding" "$z_qabl_src"; then
        echo "build-zenoh-pico-cli: query encoding-print patch failed to land in $z_qabl_src" >&2
        exit 2
    fi
    if ! grep -q "with query source_info" "$z_qabl_src"; then
        echo "build-zenoh-pico-cli: query source_info-print patch failed to land in $z_qabl_src" >&2
        exit 2
    fi
    echo "build-zenoh-pico-cli: applied query source_info-print patch to z_queryable.c" >&2
else
    echo "build-zenoh-pico-cli: z_queryable.c upstream shape changed (// Process value" >&2
    echo "  anchor absent); re-verify the query source_info patch against the current vendor pin" >&2
    echo "  (current: $(git -C "$VENDOR_DIR" rev-parse --short HEAD)) before continuing." >&2
    exit 2
fi

# R311y245 — FOURTH in-place example patch on
# vendor/zenoh-pico/examples/unix/c11/z_get.c. The stock reply handler
# prints the reply sample's keyexpr / payload but NOT its source_info.
# This patch adds `with reply source_info eid: .. sn: ..`
# (z_sample_source_info on the reply sample — a Reply body IS a Put
# push-body, so the same UNSTABLE getter reads it) under
# `#ifdef Z_FEATURE_UNSTABLE_API` (z_sample_source_info is UNSTABLE-gated,
# primitives.h:2218 block, so the guard IS needed here — unlike the
# unconditional z_query_source_info in the z_queryable patch). This makes
# the CLI the FOREIGN witness for wz's REPLY-carrier source_info
# propagation (tests/wz_reply_source_info_to_pico_zget.rs). Anchor is the
# `z_drop(z_move(replystr));` line (the reply-ok branch's cleanup, unique;
# the err branch drops `errstr`), which survives the insert — so, like the
# other example patches, hard-reject when the marker is already present
# rather than double-insert. Reverted by the shared trap.
z_get_src="$EXAMPLES_DIR/unix/c11/z_get.c"
if grep -q "with reply source_info" "$z_get_src"; then
    echo "build-zenoh-pico-cli: z_get.c already prints 'with reply source_info'" >&2
    echo "  — revert with 'git -C \"$VENDOR_DIR\" checkout -- examples/unix/c11/z_get.c'" >&2
    echo "  or re-verify the patch against the current vendor pin." >&2
    exit 2
fi
if grep -q "z_drop(z_move(replystr));" "$z_get_src"; then
    sed -i '
        \#z_drop(z_move(replystr));#i\
#ifdef Z_FEATURE_UNSTABLE_API\
        const z_source_info_t *wz_rsi = z_sample_source_info(sample);\
        if (wz_rsi != NULL) {\
            z_entity_global_id_t wz_rgid = z_source_info_id(wz_rsi);\
            printf("    with reply source_info eid: %u sn: %u\\n", (unsigned)z_entity_global_id_eid(\&wz_rgid), (unsigned)z_source_info_sn(wz_rsi));\
        }\
#endif
    ' "$z_get_src"
    if ! grep -q "with reply source_info" "$z_get_src"; then
        echo "build-zenoh-pico-cli: reply source_info-print patch failed to land in $z_get_src" >&2
        exit 2
    fi
    echo "build-zenoh-pico-cli: applied reply source_info-print patch to z_get.c" >&2
else
    echo "build-zenoh-pico-cli: z_get.c upstream shape changed (z_drop(z_move(replystr))" >&2
    echo "  anchor absent); re-verify the reply source_info patch against the current vendor pin" >&2
    echo "  (current: $(git -C "$VENDOR_DIR" rev-parse --short HEAD)) before continuing." >&2
    exit 2
fi

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

# --- Mbed TLS, the prerequisite `Z_FEATURE_LINK_TLS` adds -------------------
#
# pico resolves Mbed TLS through `pkg_search_module(MBEDTLS REQUIRED ...)`
# (CMakeLists.txt:479), which hard-fails the CONFIGURE step when no `.pc` is on
# the search path. Ubuntu's `libmbedtls-dev` ships headers and a `.so` and NO
# pkg-config metadata, so "the distro package is installed" is not the same
# condition — this provisions a pinned upstream Mbed TLS into a repo-local
# prefix instead, and puts only that prefix on PKG_CONFIG_PATH.
#
# Called rather than merely required so there is ONE entry point: run-ci and the
# hosted CI both reach the pico build through this script, and a separate
# provisioning step is a thing that can be forgotten in one of them. The
# installer is idempotent and returns immediately once the pin is in place.
bash "$ROOT/scripts/install-mbedtls.sh" >&2
MBEDTLS_PREFIX="${WZ_MBEDTLS_PREFIX:-$ROOT/target/mbedtls}"
export PKG_CONFIG_PATH="$MBEDTLS_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

# Configure (idempotent — CMake re-uses the build dir cache).
# R311y243 — Z_FEATURE_UNSTABLE_API=ON exposes the unstable per-sample
# getters (z_sample_source_info, primitives.h #ifdef block); the vendor
# default is 0 (CMakeLists.txt:316). Enabling it alone does NOT cascade
# other features on (the CMakeLists guards only DISABLE dependents when
# it is off), and it changes no wire behaviour, so the stable-API
# witnesses (priority/congestion/express/timestamp/encoding/attachment)
# are unaffected. Needed for tests/wz_source_info_to_pico_zsub.rs.
#
# Z_FEATURE_LINK_SERIAL=ON compiles pico's SERIAL link backend in. The
# vendor default is 0 (CMakeLists.txt:333) and the platform file
# cmake/platforms/linux.cmake:9 supplies the POSIX tty driver
# (src/link/transport/serial/tty_posix.c, guarded
# `Z_FEATURE_LINK_SERIAL == 1 && defined(ZENOH_LINUX)`), so a host pico
# CAN open a serial link over a tty/PTY device path. Needed for
# tests/pico_serial_link_to_wz_acceptor.rs. It ADDS a link type to the
# dispatch (link.c:68-70) and touches no existing transport, so the
# tcp/udp witnesses are unaffected.
#
# THE VALUE MUST BE `1`, NOT `ON`, and the difference is silent. The cache
# entry is a CMake STRING that is substituted VERBATIM into the generated
# `zenoh-pico/config.h`, while every consumer guards on
# `#if Z_FEATURE_LINK_SERIAL == 1` (link.c:68, serial_protocol.c:14,
# tty_posix.c:17, config/serial.h:29). `ON` is an undefined identifier in
# preprocessor arithmetic, so it evaluates to 0 and the whole serial link
# vanishes from the binary WHILE THE BUILD LOG STILL SHOWS tty_posix.c
# being compiled — the file is in the source list, its contents are inside
# the guard. Measured: with `ON`, `z_pub -e serial/...` prints "Unable to
# open session!" and strace shows it never `openat`s the device at all.
# `Z_FEATURE_UNSTABLE_API=ON` above is safe only because its consumers use
# `#ifdef`, which any non-empty value satisfies.
#
# Z_FEATURE_ADVANCED_PUBLICATION / _SUBSCRIPTION=1 compile pico's ADVANCED
# pub/sub in (vendor defaults 0, CMakeLists.txt:319/321). They obey the same
# `1`-not-`ON` rule as the serial flag — `z_advanced_sub.c:20` guards on
# `#if Z_FEATURE_ADVANCED_SUBSCRIPTION == 1` — and they fail LOUDER than a
# silent elision if they are off: the example's `#else` arm is a STUB main
# that prints "ERROR: Zenoh pico was compiled without ..." and exits -2. The
# witnesses assert the real markers, so a stub cannot pass one.
#
# There is a THIRD way these can end up 0 with the flag spelled right:
# CMakeLists.txt:386 FORCE-disables ADVANCED_PUBLICATION (with a cmake
# WARNING, not an error) unless UNSTABLE_API + PUBLICATION + LIVELINESS are
# all on. All three are on here — UNSTABLE_API from the line above,
# PUBLICATION and LIVELINESS from the vendor defaults — but a future flag
# change could break it silently, which is why the generated config.h is
# ASSERTED below rather than assumed.
#
# R311y534 — Z_FEATURE_LINK_TLS=1 compiles pico's TLS-over-TCP link in (vendor
# default 0, CMakeLists.txt:335) and obeys the same `1`-not-`ON` rule as the
# serial flag: `z_pub_tls.c:24` guards on `Z_FEATURE_LINK_TLS == 1`, so `ON`
# would evaluate to 0 in that `#if` and leave both TLS examples as their `#else`
# stub main.
#
# It is set on the PRIMARY arm, not on a fourth configure-only arm, and that is a
# MEASUREMENT rather than a convenience. Turning it on changes what `link.h`
# pulls in, so the worry is that it moves a public struct and silently invalidates
# the other 30 drop-in legs, which link ONE cdylib against these headers. Measured
# across the two configs over every `z_owned_*` / `z_loaned_*` / `z_view_*` /
# `z_moved_*` / `z_*_options_t` type the vendored headers declare — 86 of them —
# size AND alignment are identical in every case. TLS adds a link backend behind
# its own guard; it reshapes nothing the API surface exposes. So one header tree
# and one cdylib still serve every leg, and the TLS pair simply stops being the
# two programs with no body.
#
# The cost of the flag is a real dependency, not a macro: see the Mbed TLS
# provisioning above.
cmake -B "$BUILD_DIR" -S "$EXAMPLES_DIR" \
    -DCMAKE_C_STANDARD=11 \
    -DCMAKE_BUILD_TYPE=Release \
    -DZ_FEATURE_UNSTABLE_API=ON \
    -DZ_FEATURE_ADVANCED_PUBLICATION=1 \
    -DZ_FEATURE_ADVANCED_SUBSCRIPTION=1 \
    -DZ_FEATURE_LINK_SERIAL=1 \
    -DZ_FEATURE_LINK_TLS=1 >&2

# Read back what was actually COMPILED, not what was requested. Every
# mechanism that turns a requested pico feature into a compiled-out one is
# silent-to-quiet: `ON` evaluating to 0 in `#if`, and the CMakeLists
# prerequisite guards that FORCE a flag back to 0 with a mere warning. The
# generated header is the only place the truth is written down, so the
# STRING-valued flags this script sets are asserted against it here. A
# mismatch fails the build instead of shipping a stub binary that reads
# downstream as a wz interop defect.
GENERATED_CONFIG="$BUILD_DIR/zenohpico/include/zenoh-pico/config.h"
if [[ ! -f "$GENERATED_CONFIG" ]]; then
    echo "build-zenoh-pico-cli: generated config.h missing: $GENERATED_CONFIG" >&2
    exit 1
fi
for expect in \
    "Z_FEATURE_ADVANCED_PUBLICATION 1" \
    "Z_FEATURE_ADVANCED_SUBSCRIPTION 1" \
    "Z_FEATURE_LINK_SERIAL 1" \
    "Z_FEATURE_LINK_TLS 1"; do
    if ! grep -qx "#define $expect" "$GENERATED_CONFIG"; then
        echo "build-zenoh-pico-cli: requested '$expect' but the GENERATED config.h says:" >&2
        grep -E "^#define ${expect%% *}( |$)" "$GENERATED_CONFIG" >&2 \
            || echo "  (not defined at all)" >&2
        exit 1
    fi
done

# --- the SINGLE-THREADED header arm ----------------------------------------
#
# A second CONFIGURE (no build) whose only delta is `Z_FEATURE_MULTI_THREAD=0`.
# It exists for `z_pub_st.c` / `z_sub_st.c`, the two upstream examples whose
# whole `main` is guarded on `Z_FEATURE_MULTI_THREAD == 0`: against the primary
# header tree above they compile to a one-`printf` stub, so a leg driving them
# would exercise zero wz code.
#
# Only the HEADERS are produced here, and that is the whole point. A drop-in leg
# compiles upstream's source against these includes and links wz's cdylib — pico
# 's library is never involved — so the single-threaded arm needs no second
# libzenohpico and no second cdylib. That last clause was MEASURED rather than
# assumed: of every public owned type an upstream example stack-allocates, the
# only two whose size moves between the two configs are `z_owned_mutex_t`
# (40 -> 8) and `z_owned_condvar_t` (48 -> 8), and neither example names either
# type. Session, publisher, subscriber, bytes, sample, closure and handler are
# byte-identical across the arms, so ONE cdylib serves both. The counterparties
# stay the multi-threaded binaries installed above — `Z_FEATURE_MULTI_THREAD` is
# a host threading model, not a wire feature.
#
# Configure-only is deliberate: `cmake -B` writes the generated config.h during
# the configure step, and building the arm would cost a second full pico compile
# for headers we already have.
cmake -B "${BUILD_DIR}-st" -S "$EXAMPLES_DIR" \
    -DCMAKE_C_STANDARD=11 \
    -DCMAKE_BUILD_TYPE=Release \
    -DZ_FEATURE_UNSTABLE_API=ON \
    -DZ_FEATURE_ADVANCED_PUBLICATION=1 \
    -DZ_FEATURE_ADVANCED_SUBSCRIPTION=1 \
    -DZ_FEATURE_LINK_SERIAL=1 \
    -DZ_FEATURE_LINK_TLS=1 \
    -DZ_FEATURE_MULTI_THREAD=0 >&2

# Same read-back discipline as the primary arm, and for a sharper reason: this
# arm's ENTIRE purpose is one `#define`, so a request that silently failed to
# take would leave the legs compiling the stub `#else` branch and passing on a
# program that never calls into wz at all.
GENERATED_CONFIG_ST="${BUILD_DIR}-st/zenohpico/include/zenoh-pico/config.h"
if [[ ! -f "$GENERATED_CONFIG_ST" ]]; then
    echo "build-zenoh-pico-cli: single-threaded config.h missing: $GENERATED_CONFIG_ST" >&2
    exit 1
fi
if ! grep -qx "#define Z_FEATURE_MULTI_THREAD 0" "$GENERATED_CONFIG_ST"; then
    echo "build-zenoh-pico-cli: single-threaded arm did NOT take; its config.h says:" >&2
    grep -E "^#define Z_FEATURE_MULTI_THREAD( |$)" "$GENERATED_CONFIG_ST" >&2 \
        || echo "  (not defined at all)" >&2
    exit 1
fi

# Build only the curated CLI targets (avoids the full examples target
# set; faster + smaller install surface).
cmake --build "$BUILD_DIR" --target "${TARGETS[@]}" -j"$(nproc)" >&2

# Stage binaries into target/zenoh-pico-cli/ for integration tests
# to invoke by absolute path.
for bin in "${TARGETS[@]}"; do
    src="$BUILD_DIR/$bin"
    if [[ ! -x "$src" ]]; then
        echo "build-zenoh-pico-cli: expected binary missing: $src" >&2
        exit 1
    fi
    install -m 0755 "$src" "$INSTALL_DIR/$bin"
done

# R2326 (unregistered open-debt item 10) — record WHICH vendor/zenoh-pico state
# produced these artefacts.
#
# AFTER the build and the install, never before: a stamp written up front would
# assert freshness for artefacts that a failed cmake run left at their previous
# revision — the exact lie this record exists to prevent.
#
# BOTH roots are stamped because a resolver names both and they can diverge:
# `zenoh_pico_cli_binary` reads $INSTALL_DIR while `zenoh_pico_library_dir` and
# the pico ABI layout probe read $BUILD_DIR (its `lib/` and its generated
# `zenohpico/include/`). Deleting one of the two leaves the other in place, so
# one stamp covering both would answer for a root it had not seen.
#
# An unreadable submodule leaves them UNSTAMPED rather than stamped with a
# guess; `vendored_oracle_stamp_root` is what implements that, and the
# consumers report unstamped as its own verdict rather than as a match.
_wzpico_token="$(vendored_oracle_git_token "$VENDOR_DIR" || true)"
vendored_oracle_stamp_root "$INSTALL_DIR" "$_wzpico_token"
vendored_oracle_stamp_root "$BUILD_DIR" "$_wzpico_token"

echo "build-zenoh-pico-cli: installed ${#TARGETS[@]} binaries to $INSTALL_DIR" >&2
echo "build-zenoh-pico-cli: pin = ${_wzpico_token:-<unstamped: no git in $VENDOR_DIR>}" >&2
ls -la "$INSTALL_DIR" >&2

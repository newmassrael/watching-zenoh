#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
VENDOR_DIR="$ROOT/vendor/zenoh-pico"
EXAMPLES_DIR="$VENDOR_DIR/examples"
BUILD_DIR="$ROOT/target/zenoh-pico-build"
INSTALL_DIR="$ROOT/target/zenoh-pico-cli"

# Curated CLI binary set: the four that the AP MVP demo round-trip
# matrix needs (R121c+ integration tests). Adding more here costs
# only a few extra add_dependencies(examples ...) targets in the
# CMake build; the wz-codec coverage matrix decides which round
# adopts each new external CLI.
TARGETS=(z_put z_pub z_sub z_get z_queryable z_querier z_liveliness z_sub_liveliness z_get_liveliness z_sub_attachment z_pub_attachment)

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

# R311y240 / R311y242 / R311y243 — wz-side build-time patch on
# vendor/zenoh-pico/examples/unix/c11/z_sub_attachment.c. The stock
# example prints the received sample's encoding / timestamp /
# attachment but NOT its qos byte or source_info. This patch adds
# `with priority:` / `with congestion:` / `with express:` (the packed
# QoS byte, stable API) and — under `#ifdef Z_FEATURE_UNSTABLE_API` —
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
    if ! grep -q "with priority:" "$z_sub_att_src" ||
        ! grep -q "with congestion:" "$z_sub_att_src" ||
        ! grep -q "with express:" "$z_sub_att_src" ||
        ! grep -q "with source_info" "$z_sub_att_src"; then
        echo "build-zenoh-pico-cli: qos/source_info-print patch failed to land in $z_sub_att_src" >&2
        exit 2
    fi
    echo "build-zenoh-pico-cli: applied qos+source_info print patch (priority/congestion/express/source_info) to z_sub_attachment.c" >&2
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
# propagation (tests/wz_query_source_info_to_pico_zqueryable.rs). Anchor
# is the `// Process value` comment (survives the insert), so — like the
# z_sub_attachment patch — hard-reject when the marker is already present
# rather than double-insert. Reverted by the shared trap.
z_qabl_src="$EXAMPLES_DIR/unix/c11/z_queryable.c"
if grep -q "with query source_info" "$z_qabl_src"; then
    echo "build-zenoh-pico-cli: z_queryable.c already prints 'with query source_info'" >&2
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
    }
    ' "$z_qabl_src"
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

# Configure (idempotent — CMake re-uses the build dir cache).
# R311y243 — Z_FEATURE_UNSTABLE_API=ON exposes the unstable per-sample
# getters (z_sample_source_info, primitives.h #ifdef block); the vendor
# default is 0 (CMakeLists.txt:316). Enabling it alone does NOT cascade
# other features on (the CMakeLists guards only DISABLE dependents when
# it is off), and it changes no wire behaviour, so the stable-API
# witnesses (priority/congestion/express/timestamp/encoding/attachment)
# are unaffected. Needed for tests/wz_source_info_to_pico_zsub.rs.
cmake -B "$BUILD_DIR" -S "$EXAMPLES_DIR" \
    -DCMAKE_C_STANDARD=11 \
    -DCMAKE_BUILD_TYPE=Release \
    -DZ_FEATURE_UNSTABLE_API=ON >&2

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

echo "build-zenoh-pico-cli: installed ${#TARGETS[@]} binaries to $INSTALL_DIR" >&2
ls -la "$INSTALL_DIR" >&2

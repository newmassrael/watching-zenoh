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
# Using the upstream zenoh-pico CLI binaries (z_put / z_get /
# z_queryable / z_sub / z_liveliness / z_get_liveliness) — built from the
# same submodule revision that zenoh-pico-sys binds against — gives that
# "external peer" without duplicating the vendor tree and without
# depending on a system zenoh-pico install.
#
# Output: target/zenoh-pico-cli/{z_put,z_sub,z_get,z_queryable,z_liveliness,z_get_liveliness}
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
TARGETS=(z_put z_sub z_get z_queryable z_liveliness z_get_liveliness)

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
restore_z_put() {
    if [[ -e "$VENDOR_DIR/.git" ]]; then
        git -C "$VENDOR_DIR" checkout -- examples/unix/c11/z_put.c 2>/dev/null || true
    fi
}
trap restore_z_put EXIT

# Restore first so the patch anchor grep below matches the
# committed shape even if a previous run aborted mid-build.
restore_z_put

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

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

# Configure (idempotent — CMake re-uses the build dir cache).
cmake -B "$BUILD_DIR" -S "$EXAMPLES_DIR" \
    -DCMAKE_C_STANDARD=11 \
    -DCMAKE_BUILD_TYPE=Release >&2

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

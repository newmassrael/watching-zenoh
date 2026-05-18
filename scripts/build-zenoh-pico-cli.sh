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
# z_queryable / z_sub) — built from the same submodule revision that
# zenoh-pico-sys binds against — gives that "external peer" without
# duplicating the vendor tree and without depending on a system
# zenoh-pico install.
#
# Output: target/zenoh-pico-cli/{z_put,z_sub,z_get,z_queryable}
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
TARGETS=(z_put z_sub z_get z_queryable)

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

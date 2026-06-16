#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# build-zenohd.sh — build the zenoh-full REFERENCE router (zenohd v1.5.0)
# from the cargo git checkout, for wz <-> zenohd cross-impl interop tests
# (tests/zenohd_interop.rs, run-ci Layer Z).
#
# Every other interop test pairs wz with zenoh-PICO (the embedded C impl).
# zenohd is the canonical Rust router: dialing it as a client and completing
# the handshake + routing a Put through it is the ultimate wire-parity check.
# zenohd is NOT a wz build artifact, so this script builds it on demand from
# the same source cargo already resolved into its git cache.
#
# Output: target/zenohd/zenohd
#
# Built with zenoh 1.5.0's pinned toolchain (rust-toolchain.toml channel
# 1.85.0) to avoid any newer-rustc incompatibility. Re-runs are idempotent:
# the build target dir persists (incremental) and `install -m 0755` overwrites
# atomically. The build is heavy on a cold cache but fast incrementally because
# cargo has already compiled zenoh's dependency graph.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="$ROOT/target/zenohd"
BUILD_DIR="$ROOT/target/zenohd-build"
TOOLCHAIN="1.85.0"

# Locate the zenoh checkout (cargo git cache) that carries the zenohd crate.
# The directory is hash-named, so glob for the one with a zenohd/Cargo.toml.
ZH=""
for c in "$HOME"/.cargo/git/checkouts/zenoh-*/*/zenohd/Cargo.toml; do
    [[ -f "$c" ]] || continue
    ZH="$(cd "$(dirname "$c")/.." && pwd)"
    break
done
if [[ -z "$ZH" ]]; then
    echo "build-zenohd: no zenoh checkout with a zenohd crate found under" >&2
    echo "  ~/.cargo/git/checkouts/zenoh-*/ (the CLAUDE.md-referenced upstream" >&2
    echo "  checkout). zenoh is NOT a wz dependency, so this checkout is not" >&2
    echo "  auto-populated; obtain a zenoh 1.5.0 source tree there, or install" >&2
    echo "  the router directly with: cargo install zenohd@1.5.0 --locked" >&2
    echo "  and point the interop test at it via WZ_ZENOHD_BIN." >&2
    exit 1
fi
echo "build-zenohd: source = $ZH" >&2
echo "build-zenohd: zenoh version = $(grep -m1 '^version' "$ZH/Cargo.toml" | cut -d'"' -f2)" >&2

if ! rustup toolchain list 2>/dev/null | grep -q "^$TOOLCHAIN"; then
    echo "build-zenohd: toolchain $TOOLCHAIN not installed" >&2
    echo "  run: rustup toolchain install $TOOLCHAIN" >&2
    exit 1
fi

echo "build-zenohd: building zenohd (debug, +$TOOLCHAIN) ..." >&2
CARGO_TARGET_DIR="$BUILD_DIR" cargo "+$TOOLCHAIN" build -p zenohd \
    --manifest-path "$ZH/Cargo.toml"

mkdir -p "$INSTALL_DIR"
install -m 0755 "$BUILD_DIR/debug/zenohd" "$INSTALL_DIR/zenohd"
echo "build-zenohd: installed -> $INSTALL_DIR/zenohd" >&2
"$INSTALL_DIR/zenohd" --version 2>&1 | tail -1 >&2

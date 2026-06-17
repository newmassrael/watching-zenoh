#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# build-zenohd.sh — provision the zenoh-full REFERENCE router (zenohd v1.5.0)
# for wz <-> zenohd cross-impl interop tests (tests/wz_to_zenohd_router.rs,
# run-ci Layer Z).
#
# Every other interop test pairs wz with zenoh-PICO (the embedded C impl).
# zenohd is the canonical Rust router: dialing it as a client and completing
# the handshake + routing a Put through it is the ultimate wire-parity check.
# zenohd is NOT a wz dependency, so this script provisions it on demand.
#
# Two sources, in preference order — both produce the SAME release binary, so
# the reference oracle has ONE identity regardless of which source ran
# (R311pe fresh-clone reproducibility + R311pj source convergence, debt ③):
#   A. The cargo git checkout (~/.cargo/git/checkouts/zenoh-*/.../zenohd), when
#      present: a RELEASE build that reuses cargo's already-compiled zenoh
#      dependency graph (incremental, the developer fast path). The checkout's
#      version is asserted to equal ZENOHD_VERSION, so a cache that later resolves
#      a different zenoh fails fast instead of silently building a divergent
#      router.
#   B. Otherwise crates.io: `cargo install zenohd@<ver> --locked`, a release build
#      from the published, Cargo.lock-pinned source. This is what lets a fresh
#      `git clone` of wz provision zenohd with no manual ZENOHD step (the prior
#      script only PRINTED this command on a missing checkout and exited 1).
#      Reproducibility caveat: the pinned toolchain must already be installed —
#      the rustup check below hard-errors with the install hint if it is not.
#
# Set ZENOHD_FORCE_CRATES_IO=1 to skip the checkout glob and force source B
# (reproducibility self-test, and the path a fresh clone takes). Override the
# pinned version with ZENOHD_VERSION=x.y.z.
#
# Output: target/zenohd/zenohd
#
# Built with zenoh 1.5.0's pinned toolchain (channel 1.85.0) to avoid any
# newer-rustc incompatibility. Re-runs are idempotent: the checkout build is
# incremental, the crates.io install is a no-op when the version is already
# installed, and `install -m 0755` overwrites atomically.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="$ROOT/target/zenohd"
BUILD_DIR="$ROOT/target/zenohd-build"
TOOLCHAIN="1.85.0"
ZENOHD_VERSION="${ZENOHD_VERSION:-1.5.0}"

if ! rustup toolchain list 2>/dev/null | grep -q "^$TOOLCHAIN"; then
    echo "build-zenohd: toolchain $TOOLCHAIN not installed" >&2
    echo "  run: rustup toolchain install $TOOLCHAIN" >&2
    exit 1
fi

# Source A — locate the zenoh checkout (cargo git cache) that carries the
# zenohd crate. The directory is hash-named, so glob for the one with a
# zenohd/Cargo.toml. Skipped entirely when ZENOHD_FORCE_CRATES_IO=1.
ZH=""
if [[ "${ZENOHD_FORCE_CRATES_IO:-0}" -ne 1 ]]; then
    for c in "$HOME"/.cargo/git/checkouts/zenoh-*/*/zenohd/Cargo.toml; do
        [[ -f "$c" ]] || continue
        ZH="$(cd "$(dirname "$c")/.." && pwd)"
        break
    done
fi

if [[ -n "$ZH" ]]; then
    # R311pj — assert the checkout's version matches the pinned ZENOHD_VERSION so
    # a cargo cache that later resolves a different zenoh fails fast here rather
    # than silently building a divergent reference router. Build --release so
    # source A and source B yield the SAME profile (one oracle identity).
    checkout_version="$(grep -m1 '^version' "$ZH/Cargo.toml" | cut -d'"' -f2)"
    echo "build-zenohd: source = cargo git checkout $ZH (version $checkout_version)" >&2
    if [[ "$checkout_version" != "$ZENOHD_VERSION" ]]; then
        echo "build-zenohd: checkout version $checkout_version != pinned ZENOHD_VERSION=$ZENOHD_VERSION" >&2
        echo "  set ZENOHD_VERSION=$checkout_version, or ZENOHD_FORCE_CRATES_IO=1 for the crates.io path." >&2
        exit 1
    fi
    echo "build-zenohd: building zenohd (release, +$TOOLCHAIN) ..." >&2
    CARGO_TARGET_DIR="$BUILD_DIR" cargo "+$TOOLCHAIN" build -p zenohd --release \
        --manifest-path "$ZH/Cargo.toml"
    SRC_BIN="$BUILD_DIR/release/zenohd"
else
    # Source B — deterministic crates.io install (fresh-clone reproducible).
    # --locked pins to the published Cargo.lock; --root keeps the install tree
    # inside target/ so it is git-ignored and clean-able like any build output.
    echo "build-zenohd: no cargo git checkout found (or forced); installing" >&2
    echo "  zenohd@$ZENOHD_VERSION from crates.io (release, +$TOOLCHAIN, --locked) ..." >&2
    cargo "+$TOOLCHAIN" install "zenohd@$ZENOHD_VERSION" --locked \
        --root "$BUILD_DIR/cargo-install" --bin zenohd
    SRC_BIN="$BUILD_DIR/cargo-install/bin/zenohd"
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$SRC_BIN" "$INSTALL_DIR/zenohd"
echo "build-zenohd: installed -> $INSTALL_DIR/zenohd" >&2
"$INSTALL_DIR/zenohd" --version 2>&1 | tail -1 >&2

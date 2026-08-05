#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-zenoh-c-shm.sh — provision the SECOND §5.27 api-compat-c ORACLE:
# zenoh-c built WITH `Z_FEATURE_SHARED_MEMORY` and `Z_FEATURE_UNSTABLE_API`
# (R311y541).
#
# ## Why a second oracle at all
#
# `install-zenoh-c.sh` installs upstream's published standalone archive, and
# R311y540 MEASURED what that archive is: the build with neither feature. Two
# consequences follow, and this script exists for both.
#
#   1. SEVEN of upstream's 29 examples do not COMPILE against that header —
#      `z_advanced_pub`, `z_advanced_sub` and the five SHM ones. Layer C1cc
#      reports them as ORACLE-ONLY and keeps them out of the denominator, which
#      is honest but permanent: no amount of wz work moves them while the only
#      installed header cannot declare their types.
#   2. The type SIZES differ. Shared-memory moves 8 of the types wz declares and
#      unstable moves 2 (additively), so a header from this build is the only
#      thing that can check wz's other arms with a C COMPILER rather than with
#      upstream's size generator.
#
# `check-capi-c-opaque-arms.sh` already covers (2) from a source checkout, and
# it needs no install. This script covers (1), which does.
#
# ## It builds from SOURCE, because upstream publishes no such archive
#
# The release archive is one configuration. Everything else has to be built,
# which pulls the whole zenoh dependency graph — minutes, and network for
# zenoh-c's git dependency on zenoh. That is why this is on-demand rather than
# part of any default lane, exactly like `build-zenohd.sh`.
#
# The source is COPIED out of the reference checkout before building. zenoh-c's
# CMake generates `Cargo.toml` from `Cargo.toml.in` IN THE SOURCE TREE, so
# building in place would dirty the reference clone that Layer C1cc reads its
# examples from — and a reference that the build mutates is not a reference.
#
# The toolchain comes from the checkout's own `rust-toolchain.toml`, for the
# reason R311y540 measured: `z_owned_task_t` is 32 bytes under the pinned 1.85.0
# and 24 under 1.97.0, so a header built with the wrong compiler describes a
# different ABI than upstream ships.
#
# Output: target/zenoh-c-shm/{include,lib}
# Consumers point WZ_ZENOH_C_PREFIX at it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REF="${WZ_ZENOH_C_REF:-$HOME/zenoh-c-ref}"
PREFIX="${WZ_ZENOH_C_SHM_PREFIX:-$ROOT/target/zenoh-c-shm}"
SRC="$ROOT/target/zenoh-c-shm-src"
BUILD="$ROOT/target/zenoh-c-shm-build"

say() { printf '[install-zenoh-c-shm] %s\n' "$*"; }

if [[ -f "$PREFIX/include/zenoh.h" && -f "$PREFIX/lib/libzenohc.so" ]]; then
    say "already installed at $PREFIX"
    # Asserted rather than assumed: the whole point of this oracle is the two
    # features, and an install that lost them would look identical to the
    # default one and silently re-open both gaps.
    for feat in Z_FEATURE_SHARED_MEMORY Z_FEATURE_UNSTABLE_API; do
        if ! grep -q "^#define $feat" "$PREFIX/include/zenoh_configure.h"; then
            say "FAIL: the installed header does NOT define $feat, so it is not"
            say "      the oracle this script exists to provide. Remove $PREFIX"
            say "      and re-run."
            exit 1
        fi
    done
    say "verified: the installed header defines both features"
    exit 0
fi

if [[ ! -f "$REF/CMakeLists.txt" ]]; then
    say "FAIL: zenoh-c's SOURCE checkout is absent at $REF."
    say "      The release archive install-zenoh-c.sh provisions is not enough —"
    say "      this build needs the repository:"
    say "      git clone --depth 1 --branch 1.5.0 \\"
    say "      https://github.com/eclipse-zenoh/zenoh-c $REF"
    exit 1
fi
command -v cmake >/dev/null || { say "FAIL: cmake not found on PATH"; exit 1; }

CHANNEL="$(sed -n 's/^ *channel *= *"\([^"]*\)".*/\1/p' "$REF/rust-toolchain.toml" | head -1)"
[[ -n "$CHANNEL" ]] || { say "FAIL: no pinned channel in $REF/rust-toolchain.toml"; exit 1; }
if ! rustup toolchain list 2>/dev/null | grep -q "^${CHANNEL}"; then
    say "FAIL: zenoh-c pins toolchain $CHANNEL and it is not installed."
    say "      rustup toolchain install $CHANNEL"
    exit 1
fi
say "building with upstream's pinned toolchain $CHANNEL"

# COPY, do not build in place — see the header. `.git` and any prior build
# output are skipped; everything the build reads is source.
say "copying $REF -> $SRC"
rm -rf "$SRC"
mkdir -p "$SRC"
tar -C "$REF" --exclude=.git --exclude=target --exclude=build -cf - . | tar -C "$SRC" -xf -

rm -rf "$BUILD"
say "configuring (shared-memory + unstable API)"
cmake -S "$SRC" -B "$BUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DZENOHC_BUILD_WITH_SHARED_MEMORY=TRUE \
    -DZENOHC_BUILD_WITH_UNSTABLE_API=TRUE \
    -DZENOHC_BUILD_WITH_EXAMPLES=FALSE \
    -DZENOHC_BUILD_WITH_TESTS=FALSE

say "building (cold runs compile the whole zenoh graph; this takes minutes)"
cmake --build "$BUILD" --config Release
say "installing to $PREFIX"
cmake --install "$BUILD" --config Release

# The install is only useful if it IS the configuration asked for. Checked here
# rather than trusted, because every consumer downstream reads these defines to
# decide which wz arm to build.
for feat in Z_FEATURE_SHARED_MEMORY Z_FEATURE_UNSTABLE_API; do
    if ! grep -q "^#define $feat" "$PREFIX/include/zenoh_configure.h"; then
        say "FAIL: the build completed but its zenoh_configure.h does not define"
        say "      $feat. The CMake flag did not reach the cargo features."
        exit 1
    fi
done
[[ -f "$PREFIX/lib/libzenohc.so" ]] || {
    say "FAIL: no libzenohc.so under $PREFIX/lib"; exit 1; }

say "installed: $PREFIX"
say "point a lane at it with WZ_ZENOH_C_PREFIX=$PREFIX"

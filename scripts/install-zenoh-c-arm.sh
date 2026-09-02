#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-zenoh-c-arm.sh — provision ANY ONE of the four §5.27 api-compat-c
# ORACLE arms from source (R311y614).
#
# ## Why ONE script builds any arm
#
# `Z_FEATURE_UNSTABLE_API` and `Z_FEATURE_SHARED_MEMORY` are INDEPENDENT axes
# (`scripts/lib/zenoh-c-oracle-arm.sh`), so "the installed zenoh-c" names one of
# FOUR builds, and every gate that compares wz against it is arm-scoped. Two of
# the four were believed to have a provisioning path — the published archive
# via `install-zenoh-c.sh`, whose arm R2278 measured as `unstable-shm`, and a
# hosted CI build via the former `install-zenoh-c-shm.sh`, which built that SAME
# arm — so ONE of the four had a path and three had none. Copying that wrapper
# twice more was the alternative to this script; it would have put the toolchain
# pin, the source-copy rule and the CARGO_TERM_COLOR fix in four places that can
# drift, and each of those three is a measured fix with a round behind it.
#
# R2281 (open-debt item 617) retired that wrapper. Its whole content was "build
# `unstable-shm` at `target/zenoh-c-shm`", and once Layer C1ce was re-aimed at
# the `unstable` arm nothing read that prefix — a build nobody consumes, which
# `scripts/lib/zenoh_c_oracle_arms.py` now REDs on. Callers name the arm:
# `install-zenoh-c-arm.sh unstable`.
#
# `zenoh_c_abi_symbol_census.rs::BASELINES` carries a row PER ARM and hard-FAILS
# on an arm it has no row for: a ceiling from another arm would measure nothing,
# so the gate refuses rather than guesses. It had two rows while two arms could
# be built; it has four now, one of which — `unstable` — is the one Layer C1ce
# reaches since R2281. The other two are buildable here and reached by no lane.
#
# ## What is NOT generalised
#
# The prefix stays a parameter with the uniform default `target/zenoh-c-<arm>`.
# One rule, no per-arm row, and nothing to keep in step with a caller: a caller
# that wants another location passes it.
#
# Usage:
#   scripts/install-zenoh-c-arm.sh <arm> [prefix]
#   arm ∈ nounstable | unstable | nounstable-shm | unstable-shm
#
# Output: <prefix>/{include,lib}. Consumers point WZ_ZENOH_C_PREFIX at it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARM="${1:?usage: install-zenoh-c-arm.sh <arm> [prefix]}"
PREFIX="${2:-$ROOT/target/zenoh-c-$ARM}"
REF="${WZ_ZENOH_C_REF:-$HOME/zenoh-c-ref}"

# Per-arm scratch, so two arms can build CONCURRENTLY. The shm installer
# hardcoded one `-src` / `-build` pair, which is correct for one arm and silent
# corruption for two at once.
SRC="$ROOT/target/zenoh-c-$ARM-src"
BUILD="$ROOT/target/zenoh-c-$ARM-build"

say() { printf '[install-zenoh-c-arm %s] %s\n' "$ARM" "$*"; }

# ─── the VERSION an install carries, and the version its SOURCE says ─────────
#
# R2256 (open-debt item 594). The already-installed check below verified the
# ARM and nothing else, so moving the source pin left every previously built
# prefix in place and every consumer pointed at a build of the OLD upstream.
# Measured when this was written: `target/zenoh-c-unstable` and
# `target/zenoh-c-nounstable-shm` were 1.5.0 builds while `$REF` was 1.10.0,
# and three of the four rows in `zenoh_c_abi_symbol_census.rs::BASELINES` still
# carried 1.5.0 numbers because of it.
#
# `install-zenoh-c.sh` -- the OTHER installer, the one that unpacks upstream's
# published archive -- has asserted its install's version since it was written,
# and the census's doc comment points at that one. This script builds from
# source and never had the equivalent, so the arms it owns were the three that
# drifted. Same rule, both routes, now.
#
# Neither side is a constant written here. The install states its version in
# `zenoh_configure.h`, the source states its own in `version.txt`, and the
# check is that they agree -- so the pin is wherever the operator points `$REF`
# and there is no third place to drift.
_installed_version() {
    local h="$1/include/zenoh_configure.h"
    [[ -f "$h" ]] || return 1
    sed -n 's/^#define ZENOH_C "\(.*\)"$/\1/p' "$h" | head -1
}

_source_version() {
    local v="$REF/version.txt"
    [[ -f "$v" ]] || return 1
    tr -d '[:space:]' < "$v"
}

# The arm NAMES are the shared resolver's, not a second list. Spelling them
# again here is how the two would come to disagree about what `nounstable-shm`
# means, and the resolver already exists precisely because a guessed arm was a
# real defect.
case "$ARM" in
    nounstable)     want_unstable=FALSE; want_shm=FALSE ;;
    unstable)       want_unstable=TRUE;  want_shm=FALSE ;;
    nounstable-shm) want_unstable=FALSE; want_shm=TRUE  ;;
    unstable-shm)   want_unstable=TRUE;  want_shm=TRUE  ;;
    *)
        say "FAIL: unknown arm '$ARM'."
        say "      Expected one of the four names"
        say "      scripts/lib/zenoh-c-oracle-arm.sh prints:"
        say "      nounstable | unstable | nounstable-shm | unstable-shm"
        exit 1 ;;
esac

# An existing install is VERIFIED to be the arm asked for, never assumed. The
# check runs the shared resolver over it rather than grepping the two defines
# here, so "which arm is this prefix" has exactly one implementation and a
# mis-provisioned oracle cannot pass by matching a local copy of the rule.
if [[ -f "$PREFIX/include/zenoh.h" && -f "$PREFIX/lib/libzenohc.so" ]]; then
    got="$(bash "$ROOT/scripts/lib/zenoh-c-oracle-arm.sh" "$PREFIX")"
    if [[ "$got" != "$ARM" ]]; then
        say "FAIL: $PREFIX is already installed and it is the '$got' arm,"
        say "      not '$ARM'. Remove it and re-run, or pass a different prefix."
        exit 1
    fi
    # R2256 — and it must be the version the SOURCE is at. Without this the
    # prefix survives a pin move and every consumer measures the old upstream
    # while believing it measured the new one. An unreadable version on either
    # side is a FAIL, not a pass: a check that cannot read its input must not
    # report green.
    inst="$(_installed_version "$PREFIX" || true)"
    want="$(_source_version || true)"
    if [[ -z "$want" ]]; then
        say "FAIL: $REF/version.txt is absent or empty, so the version this"
        say "      install should carry cannot be established. Point"
        say "      WZ_ZENOH_C_REF at a zenoh-c checkout."
        exit 1
    fi
    if [[ -z "$inst" ]]; then
        say "FAIL: $PREFIX has no readable version in"
        say "      include/zenoh_configure.h, so it cannot be told apart from a"
        say "      build of another upstream. Remove it and re-run."
        exit 1
    fi
    if [[ "$inst" != "$want" ]]; then
        say "FAIL: $PREFIX is a $inst build and $REF is at $want. Moving the"
        say "      source pin does not move an installed artifact, so this"
        say "      prefix would answer for the wrong upstream. Remove it and"
        say "      re-run:  rm -rf $PREFIX $BUILD $SRC"
        exit 1
    fi
    say "already installed at $PREFIX (verified: $got, $inst)"
    exit 0
fi

if [[ ! -f "$REF/CMakeLists.txt" ]]; then
    say "FAIL: zenoh-c's SOURCE checkout is absent at $REF."
    say "      The release archive install-zenoh-c.sh provisions is not enough —"
    say "      this build needs the repository:"
    say "      git clone --depth 1 --branch 1.10.0 \\"
    say "      https://github.com/eclipse-zenoh/zenoh-c $REF"
    exit 1
fi
command -v cmake >/dev/null || { say "FAIL: cmake not found on PATH"; exit 1; }

# The toolchain comes from the checkout's own `rust-toolchain.toml`: R311y540
# measured `z_owned_task_t` at 32 bytes under the pinned 1.85.0 and 24 under
# 1.97.0, so a header built with the wrong compiler describes a different ABI
# than upstream ships.
CHANNEL="$(sed -n 's/^ *channel *= *"\([^"]*\)".*/\1/p' "$REF/rust-toolchain.toml" | head -1)"
[[ -n "$CHANNEL" ]] || { say "FAIL: no pinned channel in $REF/rust-toolchain.toml"; exit 1; }
if ! rustup toolchain list 2>/dev/null | grep -q "^${CHANNEL}"; then
    say "FAIL: zenoh-c pins toolchain $CHANNEL and it is not installed."
    say "      rustup toolchain install $CHANNEL"
    exit 1
fi
say "building with upstream's pinned toolchain $CHANNEL"

# COPY, do not build in place: zenoh-c's CMake generates `Cargo.toml` from
# `Cargo.toml.in` IN THE SOURCE TREE, so building in place would dirty the
# reference clone Layer C1cc reads its examples from — and a reference the build
# mutates is not a reference.
say "copying $REF -> $SRC"
rm -rf "$SRC"
mkdir -p "$SRC"
tar -C "$REF" --exclude=.git --exclude=target --exclude=build -cf - . | tar -C "$SRC" -xf -

rm -rf "$BUILD"
say "configuring (unstable=$want_unstable shared-memory=$want_shm)"
cmake -S "$SRC" -B "$BUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DZENOHC_BUILD_WITH_SHARED_MEMORY="$want_shm" \
    -DZENOHC_BUILD_WITH_UNSTABLE_API="$want_unstable" \
    -DZENOHC_BUILD_WITH_EXAMPLES=FALSE \
    -DZENOHC_BUILD_WITH_TESTS=FALSE

# CARGO_TERM_COLOR=never, and it is the whole fix for a hosted red that stood
# from R311y542 to R311y559.
#
# zenoh-c generates `zenoh_opaque.h` by compiling `build-resources/opaque-types`,
# whose `get_opaque_type_data!` macro DELIBERATELY panics at const-eval with
# `'type: X, align: A, size: S'` — and then PARSES those rustc diagnostics out of
# stderr. With colour forced ON (GitHub Actions sets `CARGO_TERM_COLOR: always`
# workflow-wide) rustc wraps every one of them in ANSI escapes, the
# plain-text-anchored parser matches zero, and the build dies with "there are 0
# errors in the input data". Locally cargo auto-disables colour into a pipe,
# which is why it never reproduced by hand.
export CARGO_TERM_COLOR=never

say "building (cold runs compile the whole zenoh graph; this takes minutes)"
cmake --build "$BUILD" --config Release
say "installing to $PREFIX"
cmake --install "$BUILD" --config Release

# The install is only useful if it IS the configuration asked for — and the
# question "which arm is this" is answered by the SHARED resolver, so a flag
# that failed to reach the cargo features is caught by the same rule every
# consumer downstream will apply.
[[ -f "$PREFIX/lib/libzenohc.so" ]] || {
    say "FAIL: no libzenohc.so under $PREFIX/lib"; exit 1; }
got="$(bash "$ROOT/scripts/lib/zenoh-c-oracle-arm.sh" "$PREFIX")"
if [[ "$got" != "$ARM" ]]; then
    say "FAIL: the build completed but its zenoh_configure.h says '$got',"
    say "      not '$ARM'. A CMake flag did not reach the cargo features."
    exit 1
fi

# R2256 — the freshly built artifact must carry its source's version too. The
# already-installed path above catches a stale prefix; this catches a build that
# somehow produced a different one, so the same rule holds on both routes into
# a usable oracle rather than only on the cheap one.
inst="$(_installed_version "$PREFIX" || true)"
want="$(_source_version || true)"
if [[ -z "$inst" || -z "$want" || "$inst" != "$want" ]]; then
    say "FAIL: the build installed version '${inst:-<unreadable>}' from a source"
    say "      at '${want:-<unreadable>}'. Those must agree; an oracle that does"
    say "      not say which upstream it is cannot bound anything."
    exit 1
fi

say "installed: $PREFIX (verified: $got, $inst)"
say "point a lane at it with WZ_ZENOH_C_PREFIX=$PREFIX"

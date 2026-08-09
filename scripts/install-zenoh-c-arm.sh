#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-zenoh-c-arm.sh — provision ANY ONE of the four §5.27 api-compat-c
# ORACLE arms from source (R311y614).
#
# ## Why this generalises `install-zenoh-c-shm.sh`
#
# `Z_FEATURE_UNSTABLE_API` and `Z_FEATURE_SHARED_MEMORY` are INDEPENDENT axes
# (`scripts/lib/zenoh-c-oracle-arm.sh`), so "the installed zenoh-c" names one of
# FOUR builds, and every gate that compares wz against it is arm-scoped. Two of
# the four had a provisioning path — the published archive (`nounstable`, via
# `install-zenoh-c.sh`) and the hosted CI build (`unstable-shm`, via
# `install-zenoh-c-shm.sh`) — and the other two had NONE. That is why
# `zenoh_c_abi_symbol_census.rs::BASELINES` carries two rows and hard-FAILS on
# the other two arms: a ceiling from another arm would measure nothing, so the
# gate refuses rather than guesses, and the refusal stood because nothing could
# build the oracle it was refusing without.
#
# Copying the shm installer twice more was the alternative. It would have put
# the toolchain pin, the source-copy rule and the CARGO_TERM_COLOR fix in four
# places that can drift, and each of those three is a measured fix with a round
# behind it.
#
# ## What is NOT generalised
#
# The prefix. `install-zenoh-c-shm.sh` keeps owning `target/zenoh-c-shm`,
# because that literal path is what `run-ci.sh`'s Layer C1ce and the CI
# provisioning step name. This script's own default is the uniform
# `target/zenoh-c-<arm>`, and the wrapper passes its historical path explicitly
# — one rule here, the exception where it is already owned.
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
    say "already installed at $PREFIX (verified: $got)"
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

say "installed: $PREFIX (verified: $got)"
say "point a lane at it with WZ_ZENOH_C_PREFIX=$PREFIX"

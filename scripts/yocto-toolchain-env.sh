#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R3529 (no register item) -- turn a Yocto SDK's environment script into the toolchain variables the
# package entry reads for aarch64-unknown-linux-gnu (docs/target-build-contract.md T2, T3).
#
# SOURCE it, with the SDK's environment script as the argument:
#
#     . scripts/yocto-toolchain-env.sh <sdk>/environment-setup-cortexa72-poky-linux
#
# The toolchain is the caller's (T2): this file selects no SDK and fetches none, and no SDK path is
# recorded in the tree. What it does is the part that is easy to get wrong by hand:
#
#   * the SDK's script is refused when LD_LIBRARY_PATH is set (the SDK's own rule, restated as an
#     error here because a sourced `return 1` in a lane reads as a silent skip);
#   * CC and AR become the variables of the triple. `CC` is a COMMAND WITH FLAGS (the tune and the
#     `--sysroot`), which cc-rs accepts and cargo's linker setting does not, so the linker is a
#     wrapper that executes that command, written into a directory of its own;
#   * the plain CC, CXX, CFLAGS and LDFLAGS the script exports are removed again: they are the TARGET
#     compiler, and a build script compiled for the BUILD host (cargo runs those) that picked them up
#     would be handed a cross compiler.
#
# Variables exported: CC_aarch64_unknown_linux_gnu, CXX_aarch64_unknown_linux_gnu,
# AR_aarch64_unknown_linux_gnu, CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER and, for crates that
# run bindgen, BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu. The wrapper directory is
# $WZ_YOCTO_WRAPPER_DIR (a fresh temporary directory unless the caller names one).

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "yocto-toolchain-env: usage: . scripts/yocto-toolchain-env.sh <SDK environment-setup script>" >&2
    return 1
fi
if [ -n "${LD_LIBRARY_PATH:-}" ]; then
    echo "yocto-toolchain-env: LD_LIBRARY_PATH is set; the SDK does not operate correctly with it" >&2
    return 1
fi

# shellcheck source=/dev/null
. "$1" || { echo "yocto-toolchain-env: the SDK's environment script failed" >&2; return 1; }

if [ -z "${CC:-}" ] || [ -z "${AR:-}" ] || [ -z "${SDKTARGETSYSROOT:-}" ]; then
    echo "yocto-toolchain-env: the script exported no CC, AR or SDKTARGETSYSROOT: not a Yocto SDK" >&2
    return 1
fi

WZ_YOCTO_WRAPPER_DIR="${WZ_YOCTO_WRAPPER_DIR:-$(mktemp -d)}"
export WZ_YOCTO_WRAPPER_DIR
{
    printf '#!/bin/sh\n'
    # The command is the SDK's own, word-split on purpose: it is a compiler and its flags.
    printf 'exec %s "$@"\n' "$CC"
} > "$WZ_YOCTO_WRAPPER_DIR/yocto-cc"
chmod +x "$WZ_YOCTO_WRAPPER_DIR/yocto-cc"

export CC_aarch64_unknown_linux_gnu="$CC"
export CXX_aarch64_unknown_linux_gnu="$CXX"
export AR_aarch64_unknown_linux_gnu="$AR"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$WZ_YOCTO_WRAPPER_DIR/yocto-cc"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu="--sysroot=$SDKTARGETSYSROOT"

unset CC CXX CPP LD CFLAGS CXXFLAGS CPPFLAGS LDFLAGS KCFLAGS AS

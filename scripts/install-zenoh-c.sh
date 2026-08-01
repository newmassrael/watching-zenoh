#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-zenoh-c.sh — provision the §5.27 `api-compat-c` ORACLE (R311y498).
#
# The zenoh-c oracle is THREE things, and Layer C1cc needs all of them:
#
#   1. the HEADERS (`zenoh.h` + friends) — cbindgen OUTPUT, so they ARE the ABI.
#      Upstream's own examples compile against these in both arms.
#   2. `libzenohc.so` — the REFERENCE arm. Compiling upstream's example against
#      wz shows it LINKS; running the same source against upstream's own
#      implementation is what shows wz's answers are the same answers.
#   3. the EXAMPLES — the corpus. A wz-authored C program calls what wz happens
#      to export, which is the bias that let the sibling atom sit at BUILT with
#      its headline claim unwitnessed. This round measured that bias: a
#      hand-picked 12-symbol list named four symbols zenoh-c never calls and
#      missed three it does.
#
# None of them is a wz dependency, so this script provisions them on demand,
# mirroring `build-zenohd.sh`'s role for the zenohd oracle.
#
# The version is PINNED to the same 1.5.0 the rest of the tree mirrors. A
# different zenoh-c is not a worse oracle, it is a DIFFERENT ABI — `zenoh_opaque.h`
# is generated per version and per `Z_FEATURE_*` set, and Layer C1cc's layout leg
# compares wz's footprints against whatever is installed. So the pin is asserted
# after install rather than assumed: an oracle that silently moved would turn a
# real drop-in into a red lane, or worse, a fake one into a green one.

set -euo pipefail

ZENOH_C_VERSION="${ZENOH_C_VERSION:-1.5.0}"
PREFIX="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"
EXAMPLES_PARENT="${WZ_ZENOH_C_REF:-$HOME/zenoh-c-ref}"

say() { printf '[install-zenoh-c] %s\n' "$*"; }

# ── 1+2. headers and the shared library ──────────────────────────────────────
#
# From the upstream RELEASE archive rather than a source build: zenoh-c is a
# cbindgen wrapper over the zenoh Rust crate, so building it from source pulls
# the whole zenoh dependency graph for an artifact upstream already publishes.
# The archive is the same thing a zenoh-c user installs, which is the point — the
# oracle must be what a real consumer has, not something wz assembled.
if [[ -f "$PREFIX/include/zenoh.h" && -f "$PREFIX/lib/libzenohc.so" ]]; then
    say "headers + libzenohc.so already at $PREFIX"
else
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    arch="$(uname -m)"
    case "$arch" in
        x86_64) target="x86_64-unknown-linux-gnu" ;;
        aarch64) target="aarch64-unknown-linux-gnu" ;;
        *) say "FAIL: no published zenoh-c archive for arch $arch"; exit 1 ;;
    esac
    url="https://github.com/eclipse-zenoh/zenoh-c/releases/download/${ZENOH_C_VERSION}/zenoh-c-${ZENOH_C_VERSION}-${target}-standalone.zip"
    say "fetching $url"
    if ! curl -fsSL "$url" -o "$tmp/zenoh-c.zip"; then
        say "FAIL: could not fetch the zenoh-c ${ZENOH_C_VERSION} release archive"
        exit 1
    fi
    unzip -q "$tmp/zenoh-c.zip" -d "$tmp/unpacked"
    mkdir -p "$PREFIX/include" "$PREFIX/lib"
    # The archive's internal layout has moved between releases, so FIND the
    # artifacts rather than assuming a path — an assumed path that stops matching
    # fails as "oracle absent", which is a SKIP, which is green.
    inc_dir="$(dirname "$(find "$tmp/unpacked" -name zenoh.h -print -quit)")"
    lib_file="$(find "$tmp/unpacked" -name 'libzenohc.so*' -print -quit)"
    if [[ -z "$inc_dir" || -z "$lib_file" ]]; then
        say "FAIL: the archive contained no zenoh.h and/or libzenohc.so"
        exit 1
    fi
    cp -r "$inc_dir"/. "$PREFIX/include/"
    cp "$lib_file" "$PREFIX/lib/libzenohc.so"
    say "installed headers + libzenohc.so into $PREFIX"
fi

# ── 3. the example corpus ────────────────────────────────────────────────────
if [[ -f "$EXAMPLES_PARENT/examples/z_put.c" ]]; then
    say "examples already at $EXAMPLES_PARENT/examples"
else
    say "cloning zenoh-c ${ZENOH_C_VERSION} examples into $EXAMPLES_PARENT"
    rm -rf "$EXAMPLES_PARENT"
    git clone --depth 1 --branch "$ZENOH_C_VERSION" \
        https://github.com/eclipse-zenoh/zenoh-c "$EXAMPLES_PARENT" >/dev/null 2>&1
fi

# ── the PIN assertion ────────────────────────────────────────────────────────
#
# Read from the installed header, not from what this script just did: on the
# already-present path above nothing was installed at all, and an oracle that
# drifted under a previous install is exactly what this catches.
installed="$(sed -n 's/^#define ZENOH_C "\(.*\)"$/\1/p' "$PREFIX/include/zenoh_configure.h" 2>/dev/null || true)"
if [[ "$installed" != "$ZENOH_C_VERSION" ]]; then
    say "FAIL: installed zenoh-c is '${installed:-unknown}', expected $ZENOH_C_VERSION."
    say "      zenoh_opaque.h is generated per version, so a different oracle is a"
    say "      DIFFERENT ABI — Layer C1cc's layout leg compares against whatever is"
    say "      installed here. Remove $PREFIX/include/zenoh*.h and re-run."
    exit 1
fi

# The Z_FEATURE set the archive was built with decides `z_put_options_t`'s layout
# (its fields are `#if defined(Z_FEATURE_UNSTABLE_API)`-gated) and which examples
# compile at all. Printed so a hosted log records WHICH ABI the run validated —
# "wz is a zenoh-c drop-in" is not a complete sentence without it.
say "oracle ready: zenoh-c $installed at $PREFIX, examples at $EXAMPLES_PARENT/examples"
say "feature set:"
grep -E '^#define Z_FEATURE_' "$PREFIX/include/zenoh_configure.h" | sed 's/^/  /'

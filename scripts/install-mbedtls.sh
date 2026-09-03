#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-mbedtls.sh — provision the Mbed TLS that zenoh-pico's TLS link needs.
#
# WHY THIS SCRIPT EXISTS AT ALL. zenoh-pico compiles its TLS backend only when
# `Z_FEATURE_LINK_TLS` is on, and turning it on has two consequences that reach
# past zenoh-pico's own library:
#
#   1. `include/zenoh-pico/link/link.h` then pulls
#      `link/transport/tls_stream.h`, which `#include`s `mbedtls/ssl.h`,
#      `mbedtls/entropy.h`, `mbedtls/ctr_drbg.h` and friends. So EVERY C program
#      that includes `zenoh-pico.h` needs the Mbed TLS headers on its include
#      path — including the §5.27 api-compat-pico drop-ins, which link wz's
#      cdylib and never touch libzenohpico at all.
#   2. `CMakeLists.txt:479` resolves Mbed TLS through
#      `pkg_search_module(MBEDTLS REQUIRED ...)`, i.e. through pkg-config, and
#      it hard-fails the CONFIGURE step when no `.pc` is found.
#
# Ubuntu 22.04's `libmbedtls-dev` (2.28.0) satisfies (1) and NOT (2): the Debian
# packaging ships the headers and the `.so` but no pkg-config metadata at all
# (`dpkg -L libmbedtls-dev | grep '\.pc$'` is empty), so a box with the distro
# package installed still fails pico's configure with "None of the required
# 'mbedtls-3>=3.0.0;mbedtls>=3.0.0;mbedtls>=2.0.0' found". Hand-writing the
# missing `.pc` would make the build depend on a file no package owns and no
# version bump updates, so this provisions Mbed TLS from its own pinned release
# instead — which ships the pkgconfig templates upstream generates.
#
# Same shape and same reasoning as `install-zenoh-c.sh`: a pinned,
# checksum-verified upstream artifact, installed into a repo-local prefix, never
# into the system. Nothing here needs root, and nothing here can shadow a
# system Mbed TLS for anything but the consumer that opts in by putting
# `$PREFIX/lib/pkgconfig` on `PKG_CONFIG_PATH` (which is exactly what
# `build-zenoh-pico-cli.sh` does, and only that script).
#
# The version is PINNED, and the pin is asserted after install rather than
# assumed. Mbed TLS 3.6 is the current long-term-support line, and zenoh-pico
# accepts 2.x or 3.x but FATAL_ERRORs on 4.x (`CMakeLists.txt:485`), so a
# floating "latest" would eventually break the pico configure with a message
# about a version this script chose silently.
#
# Output: $PREFIX/{include/mbedtls,lib/libmbed*.a,lib/pkgconfig/*.pc}
# Default $PREFIX: target/mbedtls (repo-local; `target/` is already ignored).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The pin. Moving it means moving BOTH constants together — the checksum is
# what makes the version a fact rather than a request.
MBEDTLS_VERSION="${MBEDTLS_VERSION:-3.6.4}"
MBEDTLS_SHA256="${MBEDTLS_SHA256:-ec35b18a6c593cf98c3e30db8b98ff93e8940a8c4e690e66b41dfc011d678110}"

PREFIX="${WZ_MBEDTLS_PREFIX:-$ROOT/target/mbedtls}"

# R2326 (unregistered open-debt item 10) — the provenance stamp this prefix
# carries, in the same shape and the same filename as every other foreign-oracle
# root under `target/`. See scripts/lib/vendored-oracle.sh.
#
# This oracle's source state is a PINNED RELEASE, not a git checkout, so its
# token is the version and not a rev — which is why that library carries two
# token kinds rather than assuming git. The version is not taken on trust
# either: it is written only after pkg-config has been asked what is actually
# installed and agreed with the pin, both on the fresh-install path and on the
# idempotent one.
# shellcheck source=scripts/lib/vendored-oracle.sh
source "$ROOT/scripts/lib/vendored-oracle.sh"
MBEDTLS_TOKEN="mbedtls-$MBEDTLS_VERSION"

say() { printf '[install-mbedtls] %s\n' "$*" >&2; }

# Idempotence is keyed on the PKG-CONFIG FILE and its reported version, not on
# the include dir: the whole point of this prefix is the `.pc`, and a tree left
# behind by an interrupted earlier run can have headers without one.
if [[ -f "$PREFIX/lib/pkgconfig/mbedtls.pc" ]]; then
    have="$(PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" pkg-config --modversion mbedtls 2>/dev/null || echo unknown)"
    if [[ "$have" == "$MBEDTLS_VERSION" ]]; then
        # Stamp on THIS path too, not only after a fresh install. The prefix
        # this branch found is untracked build output that predates the stamp
        # on every existing tree, and an idempotent run is the ONLY thing that
        # ever visits an already-correct prefix — so stamping only the install
        # path would leave every such tree permanently unstamped while its
        # version has just been verified by pkg-config above.
        vendored_oracle_stamp_root "$PREFIX" "$MBEDTLS_TOKEN"
        # R2327b — verify what was just stamped, for the reason
        # `vendored_oracle_assert_fresh` documents. No patch window here, so
        # immediately after the write is already the consumer's view.
        vendored_oracle_assert_fresh "$PREFIX" install-mbedtls \
    vendored_oracle_release_token "$0" MBEDTLS_VERSION mbedtls || exit 1
        say "Mbed TLS $MBEDTLS_VERSION already provisioned at $PREFIX"
        exit 0
    fi
    say "prefix holds Mbed TLS $have but the pin is $MBEDTLS_VERSION — rebuilding"
    rm -rf "$PREFIX"
fi

for tool in cmake curl sha256sum tar; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        say "FAIL: $tool not found on PATH"
        exit 1
    fi
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

url="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2"
say "fetching $url"
if ! curl -fsSL "$url" -o "$tmp/mbedtls.tar.bz2"; then
    say "FAIL: could not fetch the Mbed TLS ${MBEDTLS_VERSION} release archive"
    exit 1
fi

# Checksum BEFORE extraction, so a corrupted or substituted archive never gets
# as far as running its own CMakeLists.
actual="$(sha256sum "$tmp/mbedtls.tar.bz2" | cut -d' ' -f1)"
if [[ "$actual" != "$MBEDTLS_SHA256" ]]; then
    say "FAIL: checksum mismatch for mbedtls-${MBEDTLS_VERSION}.tar.bz2"
    say "  expected $MBEDTLS_SHA256"
    say "  actual   $actual"
    exit 1
fi
say "checksum OK ($MBEDTLS_SHA256)"

mkdir -p "$tmp/src"
tar -xjf "$tmp/mbedtls.tar.bz2" -C "$tmp/src" --strip-components=1

# Library only. The test suite and the sample programs are the bulk of an Mbed
# TLS build and none of it is a consumer here: pico links the three libraries,
# the drop-ins need only the headers.
#
# GEN_FILES=OFF: the release archive already carries the generated sources, and
# regenerating them would add a Python toolchain to this script's prerequisites.
#
# Position-independent code because libzenohpico is built as a shared library in
# the pico CLI arm, and a static archive linked into a `.so` must be PIC.
cmake -S "$tmp/src" -B "$tmp/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DENABLE_TESTING=OFF \
    -DENABLE_PROGRAMS=OFF \
    -DGEN_FILES=OFF >&2

cmake --build "$tmp/build" -j"$(nproc)" >&2
cmake --install "$tmp/build" >&2

# Read back what actually landed. `pkg_search_module` is the consumer, so the
# assertion is made THROUGH pkg-config rather than by listing files: a `.pc`
# present but unparseable (bad prefix substitution, missing Requires) would pass
# an `ls` and still fail pico's configure with the same opaque message this
# script exists to prevent.
for mod in mbedtls mbedx509 mbedcrypto; do
    if ! PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" pkg-config --exists "$mod"; then
        say "FAIL: installed tree has no usable pkg-config module '$mod'"
        say "  looked in $PREFIX/lib/pkgconfig"
        ls -la "$PREFIX/lib/pkgconfig" >&2 || true
        exit 1
    fi
    got="$(PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" pkg-config --modversion "$mod")"
    if [[ "$got" != "$MBEDTLS_VERSION" ]]; then
        say "FAIL: pkg-config reports $mod $got but the pin is $MBEDTLS_VERSION"
        exit 1
    fi
done

# The header check is separate and NOT redundant: pico's configure needs the
# `.pc`, but the drop-in compiles need `mbedtls/entropy.h` on the include path,
# and those are two different failures with two different messages.
if [[ ! -f "$PREFIX/include/mbedtls/entropy.h" ]]; then
    say "FAIL: $PREFIX/include/mbedtls/entropy.h missing after install"
    exit 1
fi

# AFTER every verification above, never before: the checks are what make the
# token a fact rather than a restatement of the pin.
vendored_oracle_stamp_root "$PREFIX" "$MBEDTLS_TOKEN"
vendored_oracle_assert_fresh "$PREFIX" install-mbedtls \
    vendored_oracle_release_token "$0" MBEDTLS_VERSION mbedtls || exit 1

say "Mbed TLS $MBEDTLS_VERSION installed at $PREFIX"
say "  pkg-config: $PREFIX/lib/pkgconfig"
say "  headers:    $PREFIX/include"

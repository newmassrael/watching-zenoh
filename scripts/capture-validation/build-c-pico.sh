#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The zenoh-c and zenoh-pico examples the validation corpus is captured with
# (docs/flow-zenoh-verdict.md §6.12): the two other implementations of the wire,
# at the pins this repository holds them at.
#
#     bash scripts/capture-validation/build-c-pico.sh
#
# zenoh-c: the pinned release (scripts/zenoh-c-oracle.pin) installed by
# scripts/install-zenoh-c.sh into target/validation/zenoh-c, NOT into the
# prefix other lanes read, and its examples compiled against it into
# target/validation/bin-c with the library beside them. zenoh-pico: the
# submodule's examples built by its own CMake into target/validation/bin-pico.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$ROOT/target/validation"
EXAMPLES=(z_pub z_sub z_get z_queryable)

prefix="$WORK/zenoh-c"
ref="$WORK/zenoh-c-ref"
WZ_ZENOH_C_PREFIX="$prefix" WZ_ZENOH_C_REF="$ref" bash "$ROOT/scripts/install-zenoh-c.sh"
src="$(dirname "$(find "$ref" -name parse_args.h -path '*examples*' | head -1)")"
out="$WORK/bin-c"
rm -rf "$out"
mkdir -p "$out"
install -m 0644 "$prefix/lib/libzenohc.so" "$out/libzenohc.so"
for ex in "${EXAMPLES[@]}"; do
    # shellcheck disable=SC2016  # `$ORIGIN` is the dynamic linker's, kept literal for the rpath
    cc -O2 -I "$prefix/include" -I "$src" "$src/$ex.c" -L "$out" -lzenohc \
        -Wl,-rpath,'$ORIGIN' -o "$out/$ex"
done

build="$WORK/pico-build"
# Static, so an example runs in the capture container without the library.
cmake -S "$ROOT/vendor/zenoh-pico" -B "$build" -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=ON -DBUILD_TESTING=OFF > "$WORK/pico-cmake.log"
cmake --build "$build" -j 4 --target "${EXAMPLES[@]}" > "$WORK/pico-build.log"
out="$WORK/bin-pico"
rm -rf "$out"
mkdir -p "$out"
for ex in "${EXAMPLES[@]}"; do
    install -m 0755 "$(find "$build" -type f -name "$ex" -perm -u+x | head -1)" "$out/$ex"
done
ls -la "$WORK/bin-c" "$WORK/bin-pico"

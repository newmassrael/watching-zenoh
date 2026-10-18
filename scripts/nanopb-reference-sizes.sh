#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Regenerate nanopb's own `#define <Message>_size` numbers for the reference
# schemas under crates/wz-capture/testdata/nanopb/ and hold `proto_nanopb` to them.
#
# The generator is installed into a THROWAWAY virtual environment and removed on
# exit: nothing is installed on the machine. Run it through `bx --host <builder>`,
# not on a developer machine.
#
#   bx --host pc2 --label nanopb-ref -- bash scripts/nanopb-reference-sizes.sh
#
# Two modes. With no argument it generates the headers in a fresh temporary
# directory and runs `proto_nanopb_tests` against them, armed. With
# `--generate DIR` it only generates, into DIR (which is kept), and writes
# `DIR/env`, a file of `export` lines that point the test at what it made: Layer
# C1bn uses that mode so the test is run by `run-ci.sh` itself, with the arming
# in front of `cargo` where the armed-oracle census reads it.
#
# Needs python3 with venv (`ensurepip`), network access to PyPI for the two pinned
# packages below, and the descriptor.proto that ships with libprotobuf-dev.
# Prints the generated sizes. `the_generators_own_sizes_are_the_numbers` reads the
# headers.
set -euo pipefail

# Both pinned: `nanopb` is the generator under test, and `protobuf` is the one
# package it imports whose version is not its own, so left unpinned a release of
# it would change what this oracle runs without any change in this tree.
NANOPB_VERSION="0.4.9.1"
PROTOBUF_VERSION="7.36.2"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data="$root/crates/wz-capture/testdata/nanopb"

generate() {
    local work="$1"
    python3 -m venv "$work/venv"
    "$work/venv/bin/pip" install --quiet \
        "nanopb==$NANOPB_VERSION" "protobuf==$PROTOBUF_VERSION"
    local pkg
    pkg="$("$work/venv/bin/python" -c 'import nanopb, os; print(os.path.dirname(nanopb.__file__))')"
    mkdir -p "$work/out"
    for schema in sizes shapes file_defaults; do
        "$work/venv/bin/python" "$pkg/generator/nanopb_generator.py" \
            -I "$data" -I "$pkg/generator/proto" -D "$work/out" "$schema.proto"
    done
    grep -H '^#define [A-Za-z_]*_size ' "$work"/out/*.pb.h
    {
        echo "export WZ_NANOPB_REFERENCE_DIR=\"$work/out\""
        echo "export WZ_NANOPB_PROTO=\"$pkg/generator/proto/nanopb.proto\""
    } > "$work/env"
}

if [[ "${1:-}" == "--generate" ]]; then
    [[ -n "${2:-}" ]] || { echo "usage: $0 [--generate DIR]" >&2; exit 2; }
    mkdir -p "$2"
    generate "$(cd "$2" && pwd)"
    exit 0
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/wz-nanopb-ref.XXXXXX")"
trap 'rm -rf "$work"' EXIT
generate "$work"
# shellcheck disable=SC1091
source "$work/env"
cd "$root/crates"
WZ_NANOPB_REFERENCE_REQUIRE=1 cargo test -p wz-capture --lib proto_nanopb_tests -- --nocapture

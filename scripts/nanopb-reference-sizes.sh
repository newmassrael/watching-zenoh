#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Regenerate nanopb's own `#define <Message>_size` numbers for the reference
# schemas under crates/wz-capture/testdata/nanopb/ and hold `proto_nanopb` to them.
#
# The generator is installed into a THROWAWAY virtual environment under a fresh
# temporary directory and removed on exit: nothing is installed on the machine.
# Run it through `bx --host <builder>`, not on a developer machine.
#
#   bx --host pc2 --label nanopb-ref -- bash scripts/nanopb-reference-sizes.sh
#
# Needs python3 with venv, protoc, and the descriptor.proto that ships with
# libprotobuf-dev. Prints the generated sizes, then runs
# `the_generators_own_sizes_are_the_numbers`, which reads the headers.
set -euo pipefail

NANOPB_VERSION="0.4.9.1"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data="$root/crates/wz-capture/testdata/nanopb"
work="$(mktemp -d "${TMPDIR:-/tmp}/wz-nanopb-ref.XXXXXX")"
trap 'rm -rf "$work"' EXIT

python3 -m venv "$work/venv"
"$work/venv/bin/pip" install --quiet "nanopb==$NANOPB_VERSION"
pkg="$("$work/venv/bin/python" -c 'import nanopb, os; print(os.path.dirname(nanopb.__file__))')"

mkdir "$work/out"
for schema in sizes shapes file_defaults; do
    "$work/venv/bin/python" "$pkg/generator/nanopb_generator.py" \
        -I "$data" -I "$pkg/generator/proto" -D "$work/out" "$schema.proto"
done
grep -H '^#define [A-Za-z_]*_size ' "$work"/out/*.pb.h

cd "$root/crates"
WZ_NANOPB_REFERENCE_DIR="$work/out" \
WZ_NANOPB_PROTO="$pkg/generator/proto/nanopb.proto" \
    cargo test -p wz-capture --lib proto_nanopb_tests -- --nocapture

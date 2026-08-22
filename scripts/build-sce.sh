#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# build-sce.sh — build the vendored sce-codegen binary from vendor/sce.
#
# Replaces the system-installed /usr/local/bin/sce-codegen as the
# watching-zenoh verification baseline. The submodule pin in
# vendor/sce locks the SCE revision; this script is the bridge from
# that revision to a runnable binary.
#
# Output: vendor/sce/target/release/sce-codegen
# Re-runs are idempotent — cargo's incremental build skips unchanged work.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCE_DIR="$ROOT/vendor/sce"
BIN="$SCE_DIR/target/release/sce-codegen"
STAMP="$SCE_DIR/target/release/.sce-codegen.pin"

# The provenance stamp this script writes is the ONLY record of which SCE
# revision the emitted binary came from — the binary itself carries no such
# marker, and its mtime answers a different question. Every consumer reads it
# through the same library. See scripts/lib/sce-codegen-oracle.sh for why
# existence and mtime were both the wrong question.
# shellcheck source=scripts/lib/sce-codegen-oracle.sh
source "$ROOT/scripts/lib/sce-codegen-oracle.sh"

if [[ ! -e "$SCE_DIR/.git" ]]; then
    echo "build-sce: vendor/sce not initialized." >&2
    echo "  run: git -C \"$ROOT\" submodule update --init vendor/sce" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "build-sce: cargo not found on PATH" >&2
    exit 1
fi

echo "build-sce: building sce-codegen from vendor/sce ..."
echo "build-sce: pin = $(git -C "$SCE_DIR" rev-parse --short HEAD)"

cd "$SCE_DIR"
# sce-codegen bin is feature-gated on `cli` (= clap dep). Build with
# the feature flag so the binary target is selected and emitted to
# target/release/.
cargo build --release --features cli --bin sce-codegen

if [[ ! -x "$BIN" ]]; then
    echo "build-sce: build succeeded but binary not at expected path" >&2
    echo "  expected: $BIN" >&2
    exit 1
fi

# AFTER the build, never before: a stamp written up front would assert
# freshness for a binary that a failed cargo run left at its previous
# revision — the exact lie this record exists to prevent.
sce_codegen_write_stamp "$SCE_DIR" "$STAMP"

echo "build-sce: done"
echo "  binary: $BIN"
echo "  pin: $(sce_codegen_stamped_token "$STAMP" || echo '<unstamped: no git in vendor/sce>')"
echo "  version: $("$BIN" 2>&1 | head -1 || true)"

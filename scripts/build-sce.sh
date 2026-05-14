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

echo "build-sce: done"
echo "  binary: $BIN"
echo "  version: $("$BIN" 2>&1 | head -1 || true)"

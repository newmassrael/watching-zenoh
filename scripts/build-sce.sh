#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# build-sce.sh — build the vendored sce-codegen binary from vendor/sce.
#
# Replaces the system-installed /usr/local/bin/sce-codegen as the
# watching-zenoh verification baseline. The submodule pin in
# vendor/sce locks the SCE revision; this script is the bridge from
# that revision to a runnable binary.
#
# Output: <the artifact root's place for vendor/sce>/target/release/sce-codegen, which is
# vendor/sce/target/release/sce-codegen when no WZ_ARTIFACT_ROOT is set
# (WZ_SCE_CODEGEN_BIN in scripts/lib/sce-codegen-oracle.sh), and, when vendor/sce has no
# changes of its own, a copy in the machine's oracle store that every checkout of the machine
# runs (`sce_codegen_store_entry`; "The store" in that file). When the store holds the build
# already, nothing is built.
# Re-runs are idempotent — cargo's incremental build skips unchanged work.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCE_DIR="$ROOT/vendor/sce"
# The binary is a product of the vendor/sce workspace, so it is built where the artifact root
# puts that workspace's products (scripts/lib/artifact-root.sh; the cargo shim it puts on PATH
# gives the workspace that target directory), and `wz_codegen_build::SceCodegen::locate` reads
# it there under the same rule.
# shellcheck source=scripts/lib/artifact-root.sh
source "$ROOT/scripts/lib/artifact-root.sh"
wz_artifact_root_init "$ROOT" || exit 2

# The provenance stamp this script writes is the ONLY record of which SCE
# revision the emitted binary came from — the binary itself carries no such
# marker, and its mtime answers a different question. Every consumer reads it
# through the same library. See scripts/lib/sce-codegen-oracle.sh for why
# existence and mtime were both the wrong question.
# shellcheck source=scripts/lib/sce-codegen-oracle.sh
source "$ROOT/scripts/lib/sce-codegen-oracle.sh"
# The library states where the checkout's binary and its stamp are, and where the store keeps a
# copy; this script writes both and every reader asks the library which one to run, so each place
# is written once.
BIN="$WZ_SCE_CODEGEN_BIN"
STAMP="$WZ_SCE_CODEGEN_STAMP"

if [[ ! -e "$SCE_DIR/.git" ]]; then
    echo "build-sce: vendor/sce not initialized." >&2
    echo "  run: git -C \"$ROOT\" submodule update --init vendor/sce" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "build-sce: cargo not found on PATH" >&2
    exit 1
fi

echo "build-sce: sce-codegen of vendor/sce, pin = $(git -C "$SCE_DIR" rev-parse --short HEAD)"

# The compiler is wz's, not the submodule's. vendor/sce carries its own
# rust-toolchain.toml (SCE pins its channel for its own lanes), and rustup would
# pick it from the directory this build runs in: a host provisioned for wz's
# pin, or a hosted runner that keeps only that toolchain
# (scripts/lib/rust-toolchain-pinned.sh), would then fetch another compiler or
# fail. The generator's output does not depend on the compiler that built it,
# and the SCE crates wz builds declare a rust-version below wz's channel, so one
# repository builds with the one compiler its root file names. The library reads
# the name, so the store entry's key names the compiler this build uses.
if ! WZ_CHANNEL="$(sce_codegen_toolchain "$ROOT")"; then
    echo "build-sce: $ROOT/rust-toolchain.toml names no channel (a \`channel = \"<name>\"\` line)" >&2
    exit 2
fi
export RUSTUP_TOOLCHAIN="$WZ_CHANNEL"
echo "build-sce: toolchain = $WZ_CHANNEL (wz's pin, not vendor/sce's)"

# What a build ended with, wherever it is.
report() {
    local bin="$1"
    echo "build-sce: done"
    echo "  binary: $bin"
    echo "  pin: $(sce_codegen_stamped_token "$(sce_codegen_stamp_of "$bin")" || echo '<unstamped: no git in vendor/sce>')"
    echo "  version: $("$bin" 2>&1 | head -1 || true)"
}

# Hold the lock of a store entry on fd 9 until this script ends, saying so each
# minute while another build of the entry holds it: a remote run that prints
# nothing for an hour is ended as hung, and that build can take longer. 1 when no
# lock can be taken here (no flock, or a store that cannot be written).
lock_entry() {
    local lock="$1" rc
    command -v flock >/dev/null 2>&1 || return 1
    mkdir -p -- "$(dirname "$lock")" 2>/dev/null || return 1
    { exec 9>>"$lock"; } 2>/dev/null || return 1
    while :; do
        rc=0
        flock -w 60 -E 75 9 || rc=$?
        case "$rc" in
            0) return 0 ;;
            75) echo "build-sce: another build of this sce-codegen holds $lock; waiting" ;;
            *) return 1 ;;
        esac
    done
}

# THE STORE ("The store" in scripts/lib/sce-codegen-oracle.sh). The entry is
# named by the source state, this script and the toolchain, so an entry that
# holds a build is the binary this run would make. A vendor/sce with changes of
# its own is no other checkout's, so it is built here and not kept there.
WANT="$(sce_codegen_source_token "$SCE_DIR" || true)"
ENTRY="$(sce_codegen_store_entry "$SCE_DIR" || true)"
if [[ -n "$ENTRY" ]] && ! sce_codegen_token_is_clean "$WANT"; then
    echo "build-sce: vendor/sce has changes of its own; built for this checkout only"
    ENTRY=""
fi
if [[ -n "$ENTRY" ]]; then
    if sce_codegen_entry_holds "$ENTRY" "$WANT"; then
        echo "build-sce: the oracle store holds this build; nothing built"
        sce_codegen_store_mark_used "$ENTRY/sce-codegen"
        report "$ENTRY/sce-codegen"
        exit 0
    fi
    if lock_entry "$ENTRY.lock"; then
        if sce_codegen_entry_holds "$ENTRY" "$WANT"; then
            echo "build-sce: another build put this build in the oracle store; nothing built"
            sce_codegen_store_mark_used "$ENTRY/sce-codegen"
            report "$ENTRY/sce-codegen"
            exit 0
        fi
    else
        echo "build-sce: no lock on $ENTRY.lock here; building without it"
    fi
fi

echo "build-sce: building sce-codegen from vendor/sce ..."
cd "$SCE_DIR"
# sce-codegen bin is feature-gated on `cli` (= clap dep). Build with
# the feature flag so the binary target is selected and emitted to
# target/release/. Cargo's own lines are its progress and are not filtered: a
# build that went quiet for an hour would be ended as hung. `9>&-`: the lock is
# this script's, and a process the build leaves running (a compiler cache's
# server) must not keep holding it after this script ends.
cargo build --release --features cli --bin sce-codegen 9>&-

if [[ ! -x "$BIN" ]]; then
    echo "build-sce: build succeeded but binary not at expected path" >&2
    echo "  expected: $BIN" >&2
    exit 1
fi

# AFTER the build, never before: a stamp written up front would assert
# freshness for a binary that a failed cargo run left at its previous
# revision — the exact lie this record exists to prevent.
sce_codegen_write_stamp "$SCE_DIR" "$STAMP"

# Kept in the store only when the source state did not move during the build:
# the entry is named by the state taken before it, and the stamp by the state
# after it.
USE="$BIN"
if [[ -n "$ENTRY" ]]; then
    if [[ "$(sce_codegen_stamped_token "$STAMP" || true)" != "$WANT" ]]; then
        echo "build-sce: vendor/sce changed during the build; not kept in the oracle store"
    elif sce_codegen_store_publish "$BIN" "$ENTRY" "$WANT"; then
        echo "build-sce: kept in the oracle store for every checkout of this machine"
        sce_codegen_store_prune "$ENTRY"
        USE="$ENTRY/sce-codegen"
    else
        echo "build-sce: the oracle store could not be written ($ENTRY); the build is this checkout's only" >&2
    fi
fi
report "$USE"

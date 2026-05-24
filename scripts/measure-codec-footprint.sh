#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# measure-codec-footprint.sh — R311a4 binary-size delta bench.
#
# Builds wz-ap-demo under four feature configurations: the full
# preset-ap-client baseline, the same with codec-init-body elided,
# the same with codec-open-body elided, and the same with both
# elided. Reports stripped binary size for each plus the byte delta
# vs the baseline.
#
# Why this exists: the R311a recanon cascade (R311a1..R311a4) claims
# that the codec-init-body / codec-open-body feature gates produce a
# real toggle of the SCXML codegen emit + InboundFrame variant +
# session_glue parse/handle path. Compile-level proof (cargo check
# --no-default-features passes) is necessary but not sufficient — a
# truthful catalog requires byte-level proof that turning the feature
# off actually removes bytes from a real binary. This script supplies
# that proof and seeds the measurement template every future
# R311b..R311l codec cascade will reuse.
#
# Implementation notes:
#   - Atomic feature list is parsed live from crates/wz/Cargo.toml's
#     preset-ap-client block so the bench stays in sync with preset
#     evolution; nothing is duplicated into this script.
#   - wz-ap-demo Cargo.toml carries `wz = { default-features = false }`
#     so `--no-default-features --features <explicit-list>` here is the
#     authoritative gate; production `cargo run -p wz-ap-demo` still
#     gets preset-ap-client via the demo crate's own default feature.
#   - Each configuration uses a dedicated --target-dir so cargo doesn't
#     spuriously re-link cached artifacts from a prior feature set.
#   - Stripping (--strip-all) removes debug symbols + section padding
#     that aren't part of the codec-feature footprint. `[profile.release]`
#     in crates/Cargo.toml uses lto=thin + codegen-units=1 already so
#     dead-code elimination is aggressive — measured delta reflects
#     actual codec-path code reachable from main.
set -euo pipefail

WS=$(git rev-parse --show-toplevel)
WZ_TOML="$WS/crates/wz/Cargo.toml"
TARGET_DIR_BASE="$WS/target/measure-codec-footprint"
BIN_NAME="wz-ap-demo"

# Parse preset-ap-client atomic feature list from wz/Cargo.toml.
PRESET_FEATURES=$(awk '
    /^preset-ap-client = \[/ { in_block=1; next }
    in_block && /^\]/        { in_block=0; next }
    in_block {
        gsub(/[",]/, "")
        gsub(/^[ \t]+|[ \t]+$/, "")
        if (length($0) > 0 && substr($0, 1, 1) != "#") print $0
    }
' "$WZ_TOML")

# Build a comma-separated `wz/feature` list excluding the names passed
# in $1 (also comma-separated). Empty $1 keeps the full preset.
build_feature_list() {
    local exclude_csv="$1"
    local list=""
    local f
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        if [[ ",$exclude_csv," == *",$f,"* ]]; then
            continue
        fi
        [[ -n "$list" ]] && list+=","
        list+="wz/$f"
    done <<< "$PRESET_FEATURES"
    echo "$list"
}

measure() {
    local label="$1"
    local features="$2"
    local subdir="$TARGET_DIR_BASE/$label"

    echo "=== Building $label ==="
    cargo build --release -p "$BIN_NAME" \
        --no-default-features --features "$features" \
        --target-dir "$subdir" 2>&1 | tail -3
    local bin="$subdir/release/$BIN_NAME"
    strip --strip-all "$bin"
    local size
    size=$(stat -c%s "$bin")
    printf "  %-32s %10s bytes (%s)\n" \
        "$label:" "$size" "$(numfmt --to=iec --suffix=B "$size")"
    echo "$size" > "$TARGET_DIR_BASE/.${label}.size"
}

mkdir -p "$TARGET_DIR_BASE"

measure "baseline"               "$(build_feature_list '')"
measure "minus-codec-init-body"  "$(build_feature_list 'codec-init-body')"
measure "minus-codec-open-body"  "$(build_feature_list 'codec-open-body')"
measure "minus-both"             "$(build_feature_list 'codec-init-body,codec-open-body')"

baseline=$(cat "$TARGET_DIR_BASE/.baseline.size")
minus_init=$(cat "$TARGET_DIR_BASE/.minus-codec-init-body.size")
minus_open=$(cat "$TARGET_DIR_BASE/.minus-codec-open-body.size")
minus_both=$(cat "$TARGET_DIR_BASE/.minus-both.size")

echo ""
echo "=== Footprint deltas (baseline minus configuration) ==="
printf "  baseline:                     %10s bytes\n" "$baseline"
printf "  minus codec-init-body delta:  %+10d bytes\n" "$((baseline - minus_init))"
printf "  minus codec-open-body delta:  %+10d bytes\n" "$((baseline - minus_open))"
printf "  minus both delta:             %+10d bytes\n" "$((baseline - minus_both))"

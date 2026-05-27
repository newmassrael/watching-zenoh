#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# check-footprint.sh — composable-framework footprint regression gate.
#
# R311bl mechanical gate. R311bj caveat (a)+(b) anchored the
# preset-cortex-m4-default footprint as a Round-N record but the
# values stay static unless a fresh Layer Q build measures them
# against a baseline. This script does the comparison so silent
# footprint creep (text drift / data drift) lands as a Layer Q
# FAIL instead of a successful Round N+k that quietly grew the
# composable-framework binary surface.
#
# North-star anchor: project_north_star Footprint test = "≥256
# bytes ROM reduction measurable when an atomic feature is
# disabled". The same 256-byte threshold is the per-axis tolerance
# band here, so a per-atomic-feature regression hits the gate at
# the same granularity the feature decomposition is decided.
#
# Axes:
#   text + data  — ROM axes. Hard gate, ±TOLERANCE bytes per axis.
#   bss          — RAM axis. Informational only. Per R311bj caveat
#                  (c) bss is dominated by HEAP_SIZE (256 KB
#                  embedded-alloc region) — a real preset deploy
#                  shrinks this and the baseline would drift on
#                  purpose. RAM regression detection belongs to a
#                  separate gate driven by lwIP MEM_SIZE +
#                  BoxFuture-per-spawn budget, not to this script.
#
# Usage:
#   scripts/check-footprint.sh <target-triple>
#
# Exit codes:
#   0  PASS (within band, or SKIP)
#   1  FAIL (out of band)
#   2  setup error (unknown target / bad argument)
set -uo pipefail

# ─── baseline ───────────────────────────────────────────────────────
#
# Per-target-triple baseline. Authoritative source: R311bj caveat
# (a)+(b) on §feature-inventory--composable-framework-atomic--
# preset-catalog/6-presets/6-7-preset-cortex-m4-default. Update
# both this table AND the §6.7 caveat together via a new Round
# entry — never one without the other (atomic ledger + CI gate
# must record the same footprint truth).
declare -A BASELINE_TEXT=(
    ["thumbv6m-none-eabi"]=23660
    ["thumbv7m-none-eabi"]=23652
    ["thumbv7em-none-eabihf"]=23724
    ["thumbv8m.main-none-eabi"]=24548
)
declare -A BASELINE_DATA=(
    ["thumbv6m-none-eabi"]=4
    ["thumbv7m-none-eabi"]=4
    ["thumbv7em-none-eabihf"]=4
    ["thumbv8m.main-none-eabi"]=4
)
declare -A BASELINE_BSS=(
    ["thumbv6m-none-eabi"]=11868
    ["thumbv7m-none-eabi"]=269916
    ["thumbv7em-none-eabihf"]=269916
    ["thumbv8m.main-none-eabi"]=269916
)

# Per-axis tolerance in bytes. Matches the north-star atomic-feature
# footprint threshold (≥256 bytes ROM reduction = "measurable").
TOLERANCE=256

# ─── argument parsing ──────────────────────────────────────────────
target="${1:-}"
if [[ -z "$target" ]]; then
    echo "check-footprint: usage: $0 <target-triple>" >&2
    exit 2
fi

if [[ -z "${BASELINE_TEXT[$target]:-}" ]]; then
    echo "check-footprint: no baseline for target '$target'" >&2
    echo "  add baseline to scripts/check-footprint.sh + matching caveat" \
         "to §6.7 in the same Round entry" >&2
    exit 2
fi

# ─── prerequisite tooling + binary ─────────────────────────────────
bin="deploy/mcu-qemu-demo/target/${target}/release/mcu-qemu-demo"
if [[ ! -f "$bin" ]]; then
    echo "  footprint SKIP (binary missing: $bin)"
    exit 0
fi
if ! command -v arm-none-eabi-size >/dev/null 2>&1; then
    echo "  footprint SKIP (arm-none-eabi-size not on PATH;" \
         "install binutils-arm-none-eabi)"
    exit 0
fi

# ─── measure ───────────────────────────────────────────────────────
# arm-none-eabi-size --format=berkeley output (line 2):
#   text  data  bss  dec  hex  filename
read -r meas_text meas_data meas_bss _ < <(
    arm-none-eabi-size --format=berkeley "$bin" \
        | awk 'NR==2 {print $1, $2, $3}'
)

base_text="${BASELINE_TEXT[$target]}"
base_data="${BASELINE_DATA[$target]}"
base_bss="${BASELINE_BSS[$target]}"

delta_text=$((meas_text - base_text))
delta_data=$((meas_data - base_data))
delta_bss=$((meas_bss - base_bss))

# Pretty-print with explicit signs so a developer reading the
# Layer Q lane output can see at a glance which axis moved.
fmt_delta() {
    local d="$1"
    if [[ "$d" -ge 0 ]]; then
        echo "+$d"
    else
        echo "$d"
    fi
}

# ─── gate ──────────────────────────────────────────────────────────
fail=0
text_status="OK"
data_status="OK"
if [[ "${delta_text#-}" -gt "$TOLERANCE" ]]; then
    text_status="FAIL"
    fail=1
fi
if [[ "${delta_data#-}" -gt "$TOLERANCE" ]]; then
    data_status="FAIL"
    fail=1
fi

# bss informational-only. ${delta_bss#-} flips sign to absolute for
# display + magnitude comparison if a future gate flips this axis
# from informational to enforcing.
bss_status="INFO"

echo "  footprint $target text=$meas_text ($(fmt_delta $delta_text)) $text_status / data=$meas_data ($(fmt_delta $delta_data)) $data_status / bss=$meas_bss ($(fmt_delta $delta_bss)) $bss_status [tol=±$TOLERANCE]"

if [[ "$fail" -ne 0 ]]; then
    echo "" >&2
    echo "check-footprint: $target out of band against R311bj caveat" >&2
    echo "  baseline: text=$base_text data=$base_data bss=$base_bss" >&2
    echo "  measured: text=$meas_text data=$meas_data bss=$meas_bss" >&2
    echo "  tolerance: ±$TOLERANCE bytes per ROM axis" >&2
    echo "" >&2
    echo "If the growth is intentional (new atomic feature, codec," >&2
    echo "  runtime primitive), land a Round N+k entry that:" >&2
    echo "  1. Updates scripts/check-footprint.sh BASELINE_* table." >&2
    echo "  2. Updates §6.7 caveat (a)/(b) with the new figure +" >&2
    echo "     rationale for the growth." >&2
    echo "If the growth is unintentional, root-cause the bytes" >&2
    echo "  before landing the change." >&2
    exit 1
fi

exit 0

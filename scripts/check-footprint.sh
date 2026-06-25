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
#   scripts/check-footprint.sh <target-triple> [artifact]
#
# artifact (default `qemu-demo`):
#   qemu-demo      — deploy/mcu-qemu-demo (the bare lwIP UDP floor; §6.7)
#   multicast-e2e  — deploy/mcu-multicast-e2e (the full multicast profile;
#                    R311mi). mps2-class targets only.
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
    # R311bq — thumbv6m baseline drops from 23660 -> 18584 (-5076 B)
    # because the microbit deploy now goes through the sync-only main
    # branch (cfg(not(target_has_atomic = "32")) in main.rs). The async
    # path's LwipRuntime + spawn wrapper + executor + timer queue
    # symbols are no longer referenced from .text, so LTO + dead-code
    # elimination drops them. The new figure is the honest "lwIP +
    # cortex-m-rt + portable-atomic + LwipUdpSocket<128, 2> sync
    # send/recv" baseline for nrf51-class deploys.
    #
    # R311iu — all four targets rebased upward for the R311ir lwIP IGMP
    # feature (scout multicast RX, udp/224.0.0.224:7446). LWIP_IGMP=1
    # links igmp.c into every runtime-lwip build via netif_set_up ->
    # igmp_start, independent of whether the Rust side ever joins a
    # group, so the cost is unconditional on this demo. Symbol-level
    # attribution on the thumbv7m ELF: 761 B of igmp_* .text (igmp_send
    # 164 / igmp_input 152 / igmp_lookup_group 76 / igmp_tmr 72 /
    # igmp_start 52 / igmp_init 28 / ...), the balance being the ip4
    # multicast-input path + the lwIP cyclic timer table entry + the
    # netif IGMP wrappers. thumbv6m grows more (+1024 vs +896) because
    # ARMv6-M lacks Thumb-2 so the same IGMP C compiles to more
    # instructions. Was: 18584 / 23652 / 23724 / 24548.
    #
    # R311y17 — rebased after the R311y15 monotonic-clock fix in
    # deploy/mcu-qemu-demo/src/main.rs. SystickClock gained a `last_us`
    # AtomicU64 monotonic floor (now_us() clamps its raw wraps-based
    # reading up to the max previously returned) to honour the
    # ClockSource monotonic contract; that 64-bit CAS clamp is emitted at
    # both now_us call sites (sys_now + SystickClockRef), growing demo
    # .text by ~216 B on CI's arm-none-eabi-gcc (+304 on thumbv7m put it
    # out of the +-256 band). text-only growth (data flat; bss INFO).
    # Was: 19608 / 24548 / 24636 / 25460 (R311iu).
    #
    # R311y21 — rebased after the SystickClock SSOT extraction into
    # wz-mcu-clock. The reload counter widened AtomicU32 -> AtomicU64 (the
    # 49.7-day overflow-freeze fix): on ARMv7-M (M3/M4/M7/M33) the 64-bit
    # atomic has no native instruction, so the ISR fetch_add + the two
    # now_us snapshot loads route through critical-section, growing mps2
    # .text by ~456..500 B (local arm-none-eabi-gcc). thumbv6m barely moves
    # (+8) because ARMv6-M already pays critical-section for every atomic
    # width, so the u32->u64 widening is free there. text-only growth
    # (data flat; bss INFO, +4 on thumbv6m for the wider static).
    # Local-gcc figures; a CI-gcc follow-up rebase may shift them <=256 B
    # per the footprint-baseline-CI-gcc rule. Was: 19764 / 24852 / 24920 /
    # 25744 (R311y17).
    ["thumbv6m-none-eabi"]=19772
    ["thumbv7m-none-eabi"]=25352
    ["thumbv7em-none-eabihf"]=25420
    ["thumbv8m.main-none-eabi"]=26200
)
declare -A BASELINE_DATA=(
    ["thumbv6m-none-eabi"]=4
    ["thumbv7m-none-eabi"]=4
    ["thumbv7em-none-eabihf"]=4
    ["thumbv8m.main-none-eabi"]=4
)
declare -A BASELINE_BSS=(
    # R311iu — +184 B uniform across all targets: the IGMP memp pool
    # (memp_memory_IGMP_GROUP_base 131 B + memp_tab_IGMP_GROUP 4 B +
    # ip4_default_multicast_netif 4 B + netif IGMP state). Target-
    # independent static pool, which is why the delta is identical on
    # the slim M0+ <128, 2> socket and the mps2 <1500, 8> default. bss
    # is INFO-only (HEAP_SIZE-dominated, R311bj caveat (c)); rebased for
    # an honest INFO delta. Was: 11868 / 269916 / 269916 / 269916.
    # R311y20 — rebased to the measured value (INFO axis, but the script's own
    # table+caveat co-maintenance rule means a recorded number must not be left
    # knowingly stale). +8 B from the R311y15 SystickClock `last_us` AtomicU64
    # static; the larger mps2 delta (270100 -> 272268) is accumulated lwIP/pool
    # drift since R311iu. Was: 12052 / 270100 / 270100 / 270100.
    # R311y21 — thumbv6m +4 (12060 -> 12064): the reload counter widened to
    # AtomicU64 in the wz-mcu-clock SSOT (4 extra static bytes). mps2 flat.
    ["thumbv6m-none-eabi"]=12064
    ["thumbv7m-none-eabi"]=272268
    ["thumbv7em-none-eabihf"]=272268
    ["thumbv8m.main-none-eabi"]=272268
)

# ─── multicast-e2e baseline ─────────────────────────────────────────
#
# The `multicast-e2e` artifact (deploy/mcu-multicast-e2e) links the FULL MCU
# multicast feature profile (session-lwip + transport-multicast +
# transport-fragmentation + codec-push) via run_multicast_e2e. Authoritative
# source: the §6.9 preset-mcu-multicast-pub footprint caveats (R311mj gave the
# profile a living preset Section, mirroring §6.7's anchor for the
# cortex-m4-default artifact; the figures originate from R311mi). Update this
# table AND the §6.9 footprint caveats together via a new Round entry — never
# one without the other (atomic ledger + CI gate record the same footprint
# truth), exactly as §6.7 governs the qemu-demo table.
#
# mps2-class only (M3 / M4 / M7): the 32 x 1536 multicast rx pool (~49 KB,
# slim-toggle-independent) does not fit nrf51's 16 KB SRAM, so there is no
# thumbv6m baseline (a slim multicast pool is a deferred item). .text is the
# multicast transport's ROM over the bare-UDP floor (~50 KB vs mcu-qemu-demo's
# ~20 KB); data the static .data; bss the 256 KB heap + lwIP/IGMP pools
# (HEAP_SIZE-dominated, INFO-only per the R311bj caveat (c)).
declare -A BASELINE_MC_TEXT=(
    # R311mi — initial measurement (cross-test lwIP port, opt-level=s + LTO).
    # R311pr — rebased after multicast/session feature accretion since R311mi
    # (R311mp~ns: publish/subscribe SSOT, Session typestate, seam refactors,
    # declare routing). text-only growth (data/bss flat), verified feature-driven
    # by symbol breakdown + 23-commit closure log; not a leak. Old: 50680/50484.
    # R311wz — SHRANK after the SCE pin bump to ba65f7a1b: the VLE 9-byte-cap fix
    # moved each codec's inline LEB128 emit to one shared runtime write_vle_uN
    # call, so the codec-heavy multicast binary lost duplicated VLE loops.
    # text-only reduction (data/bss flat); a code-size improvement, not a leak.
    # Old: 51260/51320 (R311pr).
    # R311y21 — GREW after the SystickClock SSOT extraction into wz-mcu-clock:
    # this bin GAINED the monotonic floor (it carried the pre-R311y15 floorless
    # copy) AND the AtomicU32 -> AtomicU64 reload-counter widening, both routed
    # through critical-section on ARMv7-M; +444 (M3) / +560 (M4F) local
    # arm-none-eabi-gcc. text-only growth (data flat); a CI-gcc follow-up rebase
    # may shift these <=256 B. Old: 50292/50328 (R311wz).
    ["thumbv7m-none-eabi"]=50736
    ["thumbv7em-none-eabihf"]=50888
)
declare -A BASELINE_MC_DATA=(
    ["thumbv7m-none-eabi"]=4
    ["thumbv7em-none-eabihf"]=4
)
declare -A BASELINE_MC_BSS=(
    # 256 KB heap + lwIP/IGMP static pools. INFO-only (HEAP_SIZE-dominated).
    # R311y21 — rebased 270100 -> 272268 (accumulated lwIP/pool drift, matching
    # the §6.7 mps2 bss the R311y20 demo rebase recorded; +4 of it is the
    # wz-mcu-clock AtomicU64 reload counter). INFO axis; co-maintenance rule.
    ["thumbv7m-none-eabi"]=272268
    ["thumbv7em-none-eabihf"]=272268
)

# Per-axis tolerance in bytes. Matches the north-star atomic-feature
# footprint threshold (≥256 bytes ROM reduction = "measurable").
TOLERANCE=256

# ─── argument parsing ──────────────────────────────────────────────
target="${1:-}"
if [[ -z "$target" ]]; then
    echo "check-footprint: usage: $0 <target-triple> [artifact]" >&2
    echo "  artifact: qemu-demo (default) | multicast-e2e" >&2
    exit 2
fi

# Select the artifact: which binary to size + which baseline table to gate
# against. `qemu-demo` (default) preserves the original single-artifact
# behaviour (the Q.3 lane calls `check-footprint.sh <target>`); `multicast-e2e`
# gates the R311mi multicast footprint bin. namerefs point _bt/_bd/_bb at the
# chosen baseline tables so the measure + gate logic below stays artifact-
# agnostic.
artifact="${2:-qemu-demo}"
case "$artifact" in
    qemu-demo)
        bin="deploy/mcu-qemu-demo/target/${target}/release/mcu-qemu-demo"
        declare -n _bt=BASELINE_TEXT _bd=BASELINE_DATA _bb=BASELINE_BSS
        baseline_anchor="§6.7 preset-cortex-m4-default caveat (a)/(b)"
        ;;
    multicast-e2e)
        bin="deploy/mcu-multicast-e2e/target/${target}/release/mcu-multicast-e2e"
        declare -n _bt=BASELINE_MC_TEXT _bd=BASELINE_MC_DATA _bb=BASELINE_MC_BSS
        baseline_anchor="the R311mi multicast footprint ledger entry"
        ;;
    *)
        echo "check-footprint: unknown artifact '$artifact'" \
             "(qemu-demo | multicast-e2e)" >&2
        exit 2
        ;;
esac

if [[ -z "${_bt[$target]:-}" ]]; then
    echo "check-footprint: no $artifact baseline for target '$target'" >&2
    echo "  add baseline to scripts/check-footprint.sh + matching caveat" \
         "to $baseline_anchor in the same Round entry" >&2
    exit 2
fi

# ─── prerequisite tooling + binary ─────────────────────────────────
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

base_text="${_bt[$target]}"
base_data="${_bd[$target]}"
base_bss="${_bb[$target]}"

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

echo "  footprint[$artifact] $target text=$meas_text ($(fmt_delta $delta_text)) $text_status / data=$meas_data ($(fmt_delta $delta_data)) $data_status / bss=$meas_bss ($(fmt_delta $delta_bss)) $bss_status [tol=±$TOLERANCE]"

if [[ "$fail" -ne 0 ]]; then
    echo "" >&2
    echo "check-footprint: $artifact $target out of band against $baseline_anchor" >&2
    echo "  baseline: text=$base_text data=$base_data bss=$base_bss" >&2
    echo "  measured: text=$meas_text data=$meas_data bss=$meas_bss" >&2
    echo "  tolerance: ±$TOLERANCE bytes per ROM axis" >&2
    echo "" >&2
    echo "If the growth is intentional (new atomic feature, codec," >&2
    echo "  runtime primitive), land a Round N+k entry that:" >&2
    echo "  1. Updates the matching scripts/check-footprint.sh baseline table" >&2
    echo "     (BASELINE_* for qemu-demo, BASELINE_MC_* for multicast-e2e)." >&2
    echo "  2. Updates $baseline_anchor with the new figure + rationale." >&2
    echo "If the growth is unintentional, root-cause the bytes" >&2
    echo "  before landing the change." >&2
    exit 1
fi

exit 0

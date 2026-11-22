#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The MCU speed matrix of the pico C ABI (docs/mcu-speed-matrix.md): the program of
# deploy/zephyr-mcu-speed built against zenoh-pico (arm P) and linked to wz (arm W), in pico's two
# threading arms, booted cell by cell under QEMU with -icount against a host probe and a zenohd router,
# and judged by scripts/host-bench/mcu_speed.py's gate against deploy/pico_perf_ceiling_mcu.json.
#
#   scripts/mcu-speed.sh [--board mps2/an385] [--qemu-machine mps2-an385] [--reps 3] [--sizes 8,64,1024]
#                        [--no-build] [-- <more options of mcu_speed.py run>]
#
# It builds what it runs into target/mcu-speed under the artifact root: the four images (west), and the
# host probe (scripts/host-bench/perf_probe.c against zenoh-pico from a copy of vendor/zenoh-pico, so the
# submodule is only read). With --no-build it runs what is there.
#
# What it needs: the Zephyr workspace (WZ_ZEPHYR_VENV and WZ_ZEPHYR_BASE, by default under
# ~/zephyrproject), qemu-system-arm, cmake and cc for the host probe, and a zenohd (WZ_ZENOHD_BIN, by
# default the oracle under the artifact root). A missing one is refused by name.
#
# Exit: the gate's (0 every row held, 1 a row failed, 2 an input refused, 3 a row not measured), and 2
# when something could not be built or the run was refused.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/artifact-root.sh
source "$ROOT/scripts/lib/artifact-root.sh"
wz_artifact_root_init "$ROOT" || exit 2

board="mps2/an385"
machine=""
reps=3
sizes="8,64,1024"
build=1
extra=()
while (($# > 0)); do
    case "$1" in
        --board)
            board="${2:?--board names a board}"
            shift 2
            ;;
        --qemu-machine)
            machine="${2:?--qemu-machine names a machine}"
            shift 2
            ;;
        --reps)
            reps="${2:?--reps is a number}"
            shift 2
            ;;
        --sizes)
            sizes="${2:?--sizes is a comma list}"
            shift 2
            ;;
        --no-build)
            build=0
            shift
            ;;
        --)
            shift
            extra=("$@")
            break
            ;;
        *)
            echo "mcu-speed: unknown argument $1 (see this script's header)" >&2
            exit 2
            ;;
    esac
done

refuse() {
    echo "mcu-speed: refused: $*" >&2
    exit 2
}

venv="${WZ_ZEPHYR_VENV:-$HOME/zephyrproject/.venv}"
zephyr_base="${WZ_ZEPHYR_BASE:-$HOME/zephyrproject/zephyr}"
zenohd="${WZ_ZENOHD_BIN:-$WZ_ARTIFACTS/target/zenohd/zenohd}"
out="$WZ_ARTIFACTS/target/mcu-speed"
images="$out/images"
peer="$out/bin/perf_probe"
pacer="$out/bin/paced_pub"
logs="$out/logs"

for tool in qemu-system-arm python3; do
    command -v "$tool" >/dev/null 2>&1 || refuse "$tool is not on PATH"
done
[[ -x "$zenohd" ]] || refuse "no zenohd at $zenohd (WZ_ZENOHD_BIN names another)"
mkdir -p "$images" "$out/bin" "$logs" || refuse "$out cannot be made"

# build_image <arm> <threads>: the image of one arm and threading arm, built from nothing, its ELF kept
# under the name the run looks for.
build_image() {
    local arm="$1" threads="$2"
    local dir="$out/build-$arm-$threads" log="$logs/west-$arm-$threads.log"
    if ! (
        # shellcheck source=/dev/null  # the Zephyr workspace's own venv
        source "$venv/bin/activate"
        export ZEPHYR_BASE="$zephyr_base"
        west build -p always -b "$board" -d "$dir" "$ROOT/deploy/zephyr-mcu-speed" -- \
            -DWZ_MCU_SPEED_ARM="$arm" -DWZ_MCU_SPEED_THREADS="$threads"
    ) >"$log" 2>&1; then
        tail -n 60 "$log" >&2
        refuse "the image of arm $arm ($threads) did not build (see $log)"
    fi
    cp "$dir/zephyr/zephyr.elf" "$images/$arm-$threads.elf" || refuse "the image of arm $arm ($threads) has no ELF"
    echo "mcu-speed: built arm $arm ($threads) for $board"
}

# build_peer: zenoh-pico for the host from a copy of the submodule (its CMake writes a header into the
# source tree it configures), and the host probe against it, the same build for both arms' cells.
build_peer() {
    local src="$out/pico-src" build="$out/pico-build" log="$logs/pico-host.log" lib
    command -v cmake >/dev/null 2>&1 || refuse "cmake is not on PATH (the host probe's zenoh-pico)"
    command -v cc >/dev/null 2>&1 || refuse "cc is not on PATH (the host probe)"
    [[ -f "$ROOT/vendor/zenoh-pico/CMakeLists.txt" ]] \
        || refuse "vendor/zenoh-pico is empty (git submodule update --init vendor/zenoh-pico)"
    rm -rf "$src"
    mkdir -p "$src" || refuse "$src cannot be made"
    tar -C "$ROOT/vendor/zenoh-pico" --exclude=./.git -cf - . | tar -C "$src" -xf - \
        || refuse "vendor/zenoh-pico did not copy to $src"
    chmod -R u+w "$src"
    if ! {
        cmake -S "$src" -B "$build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_STANDARD=11 -DBUILD_SHARED_LIBS=OFF \
            -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DZ_FEATURE_MATCHING=1 -DZ_FEATURE_BATCHING=1 \
            && cmake --build "$build" -j "$(nproc)"
    } >"$log" 2>&1; then
        tail -n 40 "$log" >&2
        refuse "zenoh-pico for the host did not build (see $log)"
    fi
    lib="$(find "$build" -name libzenohpico.a -print -quit)"
    [[ -n "$lib" ]] || refuse "the host build of zenoh-pico left no libzenohpico.a under $build"
    if ! cc -std=gnu11 -O2 "$ROOT/scripts/host-bench/perf_probe.c" -DZENOH_LINUX -I"$src/include" \
        -I"$build/include" -o "$peer" "$lib" -lpthread -lm >>"$log" 2>&1; then
        tail -n 40 "$log" >&2
        refuse "the host probe did not build (see $log)"
    fi
    # The publisher of a throughput cell offers a stated rate: one that puts as fast as its session
    # takes them floods the emulator's user network until the guest's session is ended.
    if ! cc -std=gnu11 -O2 "$ROOT/scripts/host-bench/paced_pub.c" -DZENOH_LINUX -I"$src/include" \
        -I"$build/include" -o "$pacer" "$lib" -lpthread -lm >>"$log" 2>&1; then
        tail -n 40 "$log" >&2
        refuse "the host pacer did not build (see $log)"
    fi
    echo "mcu-speed: built the host probe and pacer against zenoh-pico"
}

if ((build)); then
    [[ -f "$venv/bin/activate" ]] || refuse "no Zephyr venv at $venv (WZ_ZEPHYR_VENV names another)"
    [[ -d "$zephyr_base" ]] || refuse "no Zephyr tree at $zephyr_base (WZ_ZEPHYR_BASE names another)"
    # The physical path: Zephyr writes linker snippets relative to the tree, and a path through a link
    # resolves them wrong (the reason is written at _qz_toolchain in scripts/run-ci.sh).
    zephyr_base="$(cd "$zephyr_base" && pwd -P)"
    build_peer
    for arm in P W; do
        for threads in st mt; do
            build_image "$arm" "$threads"
        done
    done
fi

run="$out/runs/$(date -u +%Y%m%dT%H%M%S)"
args=(run --images "$images" --peer "$peer" --pacer "$pacer" --zenohd "$zenohd" --run "$run" --board "$board"
    --reps "$reps" --sizes "$sizes")
[[ -n "$machine" ]] && args+=(--qemu-machine "$machine")
if ! python3 "$ROOT/scripts/host-bench/mcu_speed.py" "${args[@]}" ${extra[@]+"${extra[@]}"}; then
    refuse "the run did not finish (above)"
fi
echo "$run" >"$out/last-run"
python3 "$ROOT/scripts/host-bench/mcu_speed.py" --gate "$run/mcu-speed.json" \
    --table "$ROOT/deploy/pico_perf_ceiling_mcu.json"

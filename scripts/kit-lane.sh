#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The kit lane: a T2G kit image built, flashed, run on the board and held to the row the repository
# commits for it (`deploy/resource_budget.json`, `scripts/lib/stack_frame_gate.py`), in one command whose
# every step says its own verdict. It is a LAB lane: it needs the kit, its debugger and a router on the
# host the kit is cabled to, so hosted CI cannot run it and it is not a `run_layer` of run-ci.sh.
#
#   scripts/kit-lane.sh preflight [--deep]   the host is ready: workspace, tools, console, interface, router
#   scripts/kit-lane.sh build <image>        west build, pad to the region, the stack gate on the ELF
#   scripts/kit-lane.sh run <image>          flash, boot, ask, and hold the run to its row
#   scripts/kit-lane.sh all <image>...       preflight, then build and run each
#   scripts/kit-lane.sh build-responder      the host node that answers the asking image (needs cargo)
#   scripts/kit-lane.sh list                 the images
#   scripts/kit-lane.sh --selftest           the table of images against the gates and the overlays
#
# Images are the keys of the stack gate: zephyr-client-fixed, zephyr-client-fixed-batching (they answer,
# and the host measures a GET through a router) and zephyr-client-fixed-get (it asks a responder, and its
# own console line carries the round trip).
#
# WHERE IT RUNS: from a checkout of this repository on the host the kit is attached to (the lane builds
# from the tree it lives in, so what was measured is what is in front of you). Send a tree there with
#   git ls-files -- . ':!vendor' | rsync -rlpgoD --checksum --files-from=- ./ <host>:<dir>/
# (plus vendor/sce and vendor/lwip), which stamps the files now: `-a` would carry the sender's times,
# and a build judges freshness by them.
#
# WHAT THE HOST OWNS, not the repository: the lab file (default ~/.config/wz-kit-lab.env, `KIT_LAB_ENV`
# names another) says where the debugger's tools, the router and the cable's interface are, which
# differ from host to host and are not for a committed file:
#   KIT_PROGTOOLS   directory holding openocd/bin/openocd and openocd/scripts (ModusToolbox programming tools)
#   KIT_ZENOHD      the zenohd the lane runs as the router: it needs the REST plugin beside it (answering
#                   images are measured through it), and its version is written to the run's record. Which
#                   build it is, is the lab's choice: it need not be the repository's oracle pin, and the
#                   kit's figures were taken against the lab's own
#   KIT_IFACE       the host's interface wired to the kit
#   KIT_HOST_IP     the address this host takes on it (the one the image dials: udp/<KIT_HOST_IP>:7447)
#   KIT_CONSOLE     the kit's serial console (default /dev/ttyACM0)
#   KIT_CM0P_SHA256 sha256 of the CM0+ region as the lab left it (the launcher): `preflight --deep` reads the
#                   region back and compares; without it the deep check says it has nothing to compare
# `KIT_LANE_HOME` (default ~/wz-kit-lane) is where builds, outputs and the lock live.
#
# WHAT IT WILL NOT DO: flash a file that is not the padded region it just built, flash while a debugger,
# a capture or a ping runs or the console is held, or run while another lane run holds the lock. The kit
# has a saved original CM0+ image (docs/storage-policy-and-link-layer.md, the lab's restore): this lane
# writes the M7_0 region only, and the CM0+ launcher it needs must already be in place.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_ENV="${KIT_LAB_ENV:-$HOME/.config/wz-kit-lab.env}"
LANE_HOME="${KIT_LANE_HOME:-$HOME/wz-kit-lane}"
ZEPHYR_HOME="${ZEPHYR_HOME:-$HOME/zephyrproject}"
BOARD="kit_t2g_b_h_lite/cyt4bf8cds/m7_0"
REGION_BYTES=524288 # the M7_0 image's code flash region of the CYT4BF8CDS
M7_ADDR=0x10080000
CM0P_ADDR=0x10000000
REST_PORT=18080
CLOCK_TAG="$(date +%Y%m%dT%H%M%S)"

# A non-interactive shell (ssh, a lane) does not read the profile that puts rustup's cargo on PATH; the
# build's cargo step then dies with "no such file or directory" and nothing says which file.
if ! command -v cargo >/dev/null 2>&1 && [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck source=/dev/null  # rustup's own file
    . "$HOME/.cargo/env"
fi

fails=0
say() { echo "KIT-LANE $*"; }
ok() { say "$1: ok   - $2"; }
bad() {
    say "$1: FAIL - $2" >&2
    fails=$((fails + 1))
}

# image key -> overlays, and whether it answers or asks. THE TABLE: `--selftest` holds it to the stack
# gate's population and to the files.
image_spec() {
    case "$1" in
        zephyr-client-fixed)
            OVERLAYS="overlays/t2g_zeth.conf;overlays/t2g_client.conf;overlays/t2g_client_fixed.conf"
            KIND=answer
            ;;
        zephyr-client-fixed-batching)
            OVERLAYS="overlays/t2g_zeth.conf;overlays/t2g_client.conf;overlays/t2g_client_fixed.conf;overlays/t2g_client_batching.conf"
            KIND=answer
            ;;
        zephyr-client-fixed-get)
            OVERLAYS="overlays/t2g_zeth.conf;overlays/t2g_client.conf;overlays/t2g_client_fixed.conf;overlays/t2g_client_get.conf"
            KIND=ask
            ;;
        *) return 1 ;;
    esac
}
IMAGES=(zephyr-client-fixed zephyr-client-fixed-batching zephyr-client-fixed-get)

load_lab() {
    if [[ ! -r "$LAB_ENV" ]]; then
        bad lab "no lab file $LAB_ENV: it says where the debugger's tools, the zenohd and the cable's interface are (see this script's header for the keys)"
        return 1
    fi
    # shellcheck source=/dev/null  # the host's own file
    . "$LAB_ENV"
    KIT_CONSOLE="${KIT_CONSOLE:-/dev/ttyACM0}"
    local missing=0 name
    for name in KIT_PROGTOOLS KIT_ZENOHD KIT_IFACE KIT_HOST_IP; do
        if [[ -z "${!name:-}" ]]; then
            bad lab "$LAB_ENV does not set $name"
            missing=1
        fi
    done
    [[ "$missing" -eq 0 ]]
}

openocd() { "$KIT_PROGTOOLS/openocd/bin/openocd" -s "$KIT_PROGTOOLS/openocd/scripts" "$@"; }

# The router's own version line, without the colour codes its logger puts around it.
router_version() {
    "$KIT_ZENOHD" --version 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | head -n 1 | sed 's/^.* zenohd: *//'
}

# ── preflight ───────────────────────────────────────────────────────────────────────────────────
preflight() {
    local deep="${1:-}" before="$fails"
    load_lab || return 1
    if "$ROOT/scripts/provision-zephyr.sh" --check >"$LANE_HOME/preflight-zephyr.log" 2>&1; then
        ok preflight "the Zephyr workspace and SDK are whole (scripts/provision-zephyr.sh --check)"
    else
        bad preflight "the Zephyr workspace or SDK is not whole: scripts/provision-zephyr.sh puts it back ($LANE_HOME/preflight-zephyr.log)"
    fi
    local tool
    for tool in west python3 arm-none-eabi-objcopy; do
        if [[ "$tool" == west ]]; then
            if "$ZEPHYR_HOME/.venv/bin/west" --version >/dev/null 2>&1; then
                ok preflight "west runs"
            else
                bad preflight "the venv's west does not run"
            fi
        elif command -v "$tool" >/dev/null && "$tool" --version >/dev/null 2>&1; then
            ok preflight "$tool runs"
        else
            bad preflight "$tool is not on PATH or does not run"
        fi
    done
    # The image's Rust half is built by cargo from the tree's own toolchain pin, for the kit's target; both
    # are asked of the directory the build runs in, where the pin applies.
    local libdir
    if cargo --version >/dev/null 2>&1; then
        ok preflight "cargo runs ($(cargo --version))"
        libdir="$(cd "$ROOT/deploy/zephyr-admin-node/rust" && rustc --print target-libdir --target thumbv7em-none-eabi 2>/dev/null)"
        if [[ -n "$libdir" ]] && compgen -G "$libdir/libcore-*.rlib" >/dev/null; then
            ok preflight "the toolchain of the tree has the kit's target (thumbv7em-none-eabi)"
        else
            bad preflight "the toolchain of the tree has no thumbv7em-none-eabi: rustup target add thumbv7em-none-eabi"
        fi
    else
        bad preflight "cargo does not run (not on PATH, and no ~/.cargo/env): the image's Rust half cannot be built"
    fi
    if openocd --version >/dev/null 2>&1; then
        ok preflight "openocd runs ($KIT_PROGTOOLS)"
    else
        bad preflight "openocd does not run: $KIT_PROGTOOLS/openocd/bin/openocd"
    fi
    if "$KIT_ZENOHD" --version >/dev/null 2>&1; then
        ok preflight "the router runs ($(router_version))"
    else
        bad preflight "the router does not run: $KIT_ZENOHD"
    fi
    if compgen -G "$(dirname "$KIT_ZENOHD")/libzenoh_plugin_rest.*" >/dev/null; then
        ok preflight "the REST plugin is beside the router"
    else
        bad preflight "no libzenoh_plugin_rest beside $KIT_ZENOHD: the answering images cannot be measured"
    fi
    if [[ -c "$KIT_CONSOLE" ]]; then
        if fuser "$KIT_CONSOLE" >/dev/null 2>&1; then
            bad preflight "the console $KIT_CONSOLE is held by a process"
        else
            ok preflight "the console $KIT_CONSOLE is there and free"
        fi
    else
        bad preflight "no console $KIT_CONSOLE: the kit is not attached, or its debugger is not powered"
    fi
    if ip link show "$KIT_IFACE" >/dev/null 2>&1; then
        ok preflight "the interface $KIT_IFACE exists"
    else
        bad preflight "no interface $KIT_IFACE"
    fi
    if sudo -n true 2>/dev/null; then
        ok preflight "sudo needs no password (the lane gives the interface its address)"
    else
        bad preflight "sudo asks for a password: the lane cannot give $KIT_IFACE its address"
    fi
    if pgrep -x '(openocd|tcpdump|ping)' >/dev/null; then
        bad preflight "a debugger, a capture or a ping is running (openocd, tcpdump or ping): the lane flashes when nothing else touches the kit"
    else
        ok preflight "no debugger, capture or ping is running"
    fi
    if [[ "$deep" == --deep ]]; then
        preflight_launcher
    fi
    [[ "$fails" -eq "$before" ]]
}

# The CM0+ launcher starts the M7_0 core: without it a run shows no boot line and says nothing else, so the
# deep check reads the CM0+ region back and compares it with what the lab recorded.
preflight_launcher() {
    if [[ -z "${KIT_CM0P_SHA256:-}" ]]; then
        bad preflight "KIT_CM0P_SHA256 is not set in $LAB_ENV: the deep check has nothing to compare the CM0+ region with"
        return
    fi
    local dir="$LANE_HOME/launcher-read"
    mkdir -p "$dir"
    rm -f "$dir/cm0p-read.bin"
    (
        cd "$dir" && timeout 120 "$KIT_PROGTOOLS/openocd/bin/openocd" -s "$KIT_PROGTOOLS/openocd/scripts" \
            -c "set ENABLE_ACQUIRE 0" -f interface/kitprog3.cfg -f target/infineon/cyt4bf.cfg \
            -c "init" -c "targets cat1c.cpu.cm70" -c "halt" \
            -c "dump_image cm0p-read.bin $CM0P_ADDR $REGION_BYTES" -c "resume" -c "shutdown"
    ) >"$dir/read.log" 2>&1
    local rc=$? got=""
    [[ -f "$dir/cm0p-read.bin" ]] && got="$(sha256sum "$dir/cm0p-read.bin" | cut -d' ' -f1)"
    if [[ "$rc" -eq 0 && "$got" == "$KIT_CM0P_SHA256" ]]; then
        ok preflight "the CM0+ region reads back as the lab left it (${got:0:16})"
    else
        bad preflight "the CM0+ region read back as '${got:0:16}' (openocd rc=$rc) and the lab recorded ${KIT_CM0P_SHA256:0:16} ($dir/read.log)"
    fi
}

# ── build ───────────────────────────────────────────────────────────────────────────────────────
build() {
    local key="$1" before="$fails"
    image_spec "$key" || { bad "$key" "not an image of this lane (scripts/kit-lane.sh list)"; return 1; }
    local dir="$LANE_HOME/build/$key" out="$LANE_HOME/out/$CLOCK_TAG-$key"
    mkdir -p "$out"
    local avail
    avail="$(LC_ALL=C free -m | awk '/^Mem:/ {print $7}')"
    if ! [[ "${avail:-}" =~ ^[0-9]+$ && "$avail" -ge 8000 ]]; then
        bad "$key" "less than 8 GB of memory is available, or the figure could not be read: a build here can take the host down"
        return 1
    fi
    # shellcheck source=/dev/null  # created by scripts/provision-zephyr.sh
    . "$ZEPHYR_HOME/.venv/bin/activate"
    export ZEPHYR_BASE="$ZEPHYR_HOME/zephyr"
    export CMAKE_BUILD_PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-8}" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
    if (
        cd "$ROOT" && nice -n 10 west build -b "$BOARD" -d "$dir" deploy/zephyr-admin-node -p auto -- \
            -DEXTRA_CONF_FILE="$OVERLAYS" -DEXTRA_DTC_OVERLAY_FILE=overlays/t2g_zeth.overlay
    ) >"$out/build.log" 2>&1; then
        ok "$key" "west build ($out/build.log)"
    else
        bad "$key" "west build failed ($out/build.log)"
        return 1
    fi
    local elf="$dir/zephyr/zephyr.elf" bin="$out/m7.bin"
    arm-none-eabi-objcopy -O binary "$elf" "$bin" || { bad "$key" "objcopy failed"; return 1; }
    local size
    size="$(stat -c %s "$bin")"
    if [[ "$size" -gt "$REGION_BYTES" ]]; then
        bad "$key" "the image is $size bytes, over the $REGION_BYTES of the region"
        return 1
    fi
    python3 -I - "$bin" "$REGION_BYTES" <<'PY'
import sys
path, region = sys.argv[1], int(sys.argv[2])
data = open(path, "rb").read()
open(path, "wb").write(data + b"\xff" * (region - len(data)))
PY
    local sha
    sha="$(sha256sum "$bin" | cut -d' ' -f1)"
    echo "$sha" >"$out/m7.sha256"
    echo "$elf" >"$out/elf.path"
    ok "$key" "$(arm-none-eabi-size "$elf" | awk 'NR==2 {printf "text %s, data %s, bss %s", $1, $2, $3}'); padded image sha256 ${sha:0:16}"
    if python3 "$ROOT/scripts/lib/stack_frame_gate.py" --check "$key" --elf "$elf" >"$out/stack-gate.log" 2>&1; then
        ok "$key" "the stack gate holds the image ($(grep -a 'stack-chain: OK' "$out/stack-gate.log" | head -n 1 | cut -c1-120))"
    else
        bad "$key" "the stack gate refuses the image ($out/stack-gate.log)"
    fi
    echo "$out" >"$LANE_HOME/last-out-$key"
    [[ "$fails" -eq "$before" ]]
}

# ── run ─────────────────────────────────────────────────────────────────────────────────────────
flash_region() {
    # flash_region <file> <expected sha256> <tag>
    local file="$1" want="$2" tag="$3" size got
    size="$(stat -c %s "$file")"
    got="$(sha256sum "$file" | cut -d' ' -f1)"
    if [[ "$size" -ne "$REGION_BYTES" ]]; then
        bad "$tag" "REFUSED: $file is $size bytes, not the $REGION_BYTES of the region"
        return 1
    fi
    if [[ "$got" != "$want" ]]; then
        bad "$tag" "REFUSED: $file has sha256 $got and the build recorded $want"
        return 1
    fi
    if fuser "$KIT_CONSOLE" >/dev/null 2>&1; then
        bad "$tag" "REFUSED: the console $KIT_CONSOLE is held"
        return 1
    fi
    if pgrep -x '(openocd|tcpdump|ping)' >/dev/null; then
        bad "$tag" "REFUSED: a debugger, a capture or a ping is running"
        return 1
    fi
    if timeout 180 "$KIT_PROGTOOLS/openocd/bin/openocd" -s "$KIT_PROGTOOLS/openocd/scripts" \
        -f interface/kitprog3.cfg -f target/infineon/cyt4bf.cfg \
        -c "cat1c sflash_restrictions 1; program $file $M7_ADDR verify exit" >"$OUT/flash.log" 2>&1 \
        && grep -aq 'Verified OK' "$OUT/flash.log"; then
        ok "$tag" "the M7_0 region was written and read back ($OUT/flash.log)"
    else
        bad "$tag" "the flash did not verify ($OUT/flash.log)"
        return 1
    fi
}

stop_all() {
    local pid
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    if [[ -n "${ADDR_ADDED:-}" ]]; then
        sudo -n ip addr del "$KIT_HOST_IP/24" dev "$KIT_IFACE" 2>/dev/null
        ADDR_ADDED=""
    fi
}

# The lines of the console that came AFTER the reset: the kit boots the image once on its own when the
# flash ends, with no router yet, and that boot's lines are not this run's.
count_lines() { grep -a -c "$1" "$OUT/console.raw" 2>/dev/null || true; }

run() {
    local key="$1" before="$fails"
    image_spec "$key" || { bad "$key" "not an image of this lane (scripts/kit-lane.sh list)"; return 1; }
    load_lab || return 1
    local built
    built="$(cat "$LANE_HOME/last-out-$key" 2>/dev/null || true)"
    if [[ -z "$built" || ! -f "$built/m7.bin" ]]; then
        bad "$key" "no built image for $key: scripts/kit-lane.sh build $key first"
        return 1
    fi
    OUT="$built"
    exec 9>"$LANE_HOME/kit.lock"
    if ! flock -n 9; then
        bad "$key" "another lane run holds $LANE_HOME/kit.lock: one run at a time touches the kit"
        return 1
    fi
    local responder="${KIT_RESPONDER:-$LANE_HOME/host-slot-node-get}"
    if [[ "$KIND" == ask && ! -x "$responder" ]]; then
        bad "$key" "no responder at $responder: scripts/kit-lane.sh build-responder"
        return 1
    fi
    {
        echo "image:  $key"
        echo "sha256: $(cat "$OUT/m7.sha256")"
        echo "router: $(router_version)"
        echo "tree:   $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo 'not a git checkout (a copy of a tree)')"
        echo "date:   $(date '+%F %T %Z')"
    } >"$OUT/record.txt"
    flash_region "$OUT/m7.bin" "$(cat "$OUT/m7.sha256")" "$key" || return 1

    PIDS=()
    ADDR_ADDED=""
    trap stop_all EXIT
    if ! sudo -n ip addr add "$KIT_HOST_IP/24" dev "$KIT_IFACE" 2>"$OUT/ip.log"; then
        bad "$key" "the interface $KIT_IFACE did not take $KIT_HOST_IP ($OUT/ip.log)"
        return 1
    fi
    ADDR_ADDED=1
    sleep 2
    stty -F "$KIT_CONSOLE" 115200 raw -echo -hupcl
    setsid timeout 600 cat "$KIT_CONSOLE" >"$OUT/console.raw" 2>"$OUT/console.err" </dev/null &
    PIDS+=("$!")
    local router_args=(--no-multicast-scouting -l "udp/$KIT_HOST_IP:7447" --plugin-search-dir "$(dirname "$KIT_ZENOHD")" '--cfg=id:"aaaaaaaaaaaaaaaa"')
    if [[ "$KIND" == answer ]]; then
        router_args+=(--rest-http-port "127.0.0.1:$REST_PORT")
    fi
    setsid "$KIT_ZENOHD" "${router_args[@]}" >"$OUT/router.log" 2>&1 </dev/null &
    PIDS+=("$!")
    sleep 3
    if [[ "$KIND" == ask ]]; then
        # A responder the router does not show leaves the getter with finals and no answers, which a run
        # reports as "finished" and measures nothing: prove it is reachable before the kit is reset.
        local attempt reachable=0
        for attempt in 1 2 3; do
            setsid "$responder" "$KIT_HOST_IP:7447" --local "$KIT_HOST_IP" --doc "demo/bench:165" \
                >"$OUT/responder.$attempt.log" 2>&1 </dev/null &
            local responder_pid=$!
            PIDS+=("$responder_pid")
            sleep 2
            if timeout 15 "$responder" "$KIT_HOST_IP:7447" --local "$KIT_HOST_IP" --get demo/bench --count 1 \
                >"$OUT/probe.$attempt.log" 2>&1 </dev/null; then
                reachable=1
                break
            fi
            kill "$responder_pid" 2>/dev/null
        done
        if [[ "$reachable" -ne 1 ]]; then
            bad "$key" "no responder was reachable through the router in three tries ($OUT/probe.*.log)"
            return 1
        fi
        ok "$key" "a responder is reachable through the router"
    fi

    local ready_before getter_before
    ready_before="$(count_lines 'ZEPHYR-WZ-CLIENT READY')"
    getter_before="$(count_lines 'ZEPHYR-WZ-GET done')"
    if timeout 60 "$KIT_PROGTOOLS/openocd/bin/openocd" -s "$KIT_PROGTOOLS/openocd/scripts" \
        -f interface/kitprog3.cfg -f target/infineon/cyt4bf.cfg -c "init" -c "reset run" -c "shutdown" \
        >"$OUT/reset.log" 2>&1; then
        ok "$key" "the kit was reset ($OUT/reset.log)"
    else
        bad "$key" "the reset failed ($OUT/reset.log)"
        return 1
    fi

    local waited=0 limit=60
    [[ "$KIND" == ask ]] && limit=150
    while [[ "$waited" -lt "$limit" ]]; do
        if [[ "$(count_lines 'ZEPHYR-WZ-CLIENT READY')" -gt "$ready_before" ]]; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    if [[ "$(count_lines 'ZEPHYR-WZ-CLIENT READY')" -le "$ready_before" ]]; then
        bad "$key" "no READY line after the reset in ${limit} s: the image did not start (is the CM0+ launcher in place? preflight --deep)"
        return 1
    fi
    ok "$key" "the image booted (READY line after the reset)"

    local results=() node_id
    node_id="$(grep -a -o 'ZEPHYR-WZ-CLIENT READY [0-9a-f]*' "$OUT/console.raw" | tail -n 1 | awk '{print $3}')"
    if [[ "$KIND" == answer ]]; then
        if python3 -I "$ROOT/scripts/lib/kit_rest_probe.py" "$REST_PORT" "$node_id" "$OUT/rest.json" 2000 >"$OUT/probe.log" 2>&1; then
            ok "$key" "the host asked the kit's two documents 2,000 times each ($OUT/probe.log)"
            results=(--result "$OUT/rest.json")
        else
            bad "$key" "the kit's session never answered through the router ($OUT/probe.log)"
            return 1
        fi
        # The firmware prints its stack high-water mark when it moves; let the last line come.
        sleep 12
    else
        waited=0
        while [[ "$waited" -lt "$limit" ]]; do
            if [[ "$(count_lines 'ZEPHYR-WZ-GET done')" -gt "$getter_before" ]]; then
                break
            fi
            sleep 1
            waited=$((waited + 1))
        done
        if [[ "$(count_lines 'ZEPHYR-WZ-GET done')" -le "$getter_before" ]]; then
            bad "$key" "no getter line after the reset in ${limit} s"
            return 1
        fi
        ok "$key" "the getter said how its queries went (a line after the reset)"
        sleep 3
    fi
    if grep -aq 'wz: FAIL' "$OUT/console.raw"; then
        bad "$key" "the console says 'wz: FAIL' ($(grep -a 'wz: FAIL' "$OUT/console.raw" | head -n 1))"
    else
        ok "$key" "the console has no 'wz: FAIL' line"
    fi
    if python3 "$ROOT/scripts/lib/resource_budget_gate.py" --measure "$key" --log "$OUT/console.raw" "${results[@]}" \
        >"$OUT/budget.log" 2>&1; then
        ok "$key" "the run is inside its row ($(tail -n 1 "$OUT/budget.log" | sed 's/^ *//'))"
    else
        bad "$key" "the run is outside its row: $(sed 's/^ *//' "$OUT/budget.log" | head -n 3 | tr '\n' ' ')"
    fi
    stop_all
    trap - EXIT
    [[ "$fails" -eq "$before" ]]
}

build_responder() {
    # The host node with the getter, built here from this tree: the peer the asking image asks.
    mkdir -p "$LANE_HOME"
    if (cd "$ROOT/deploy/host-slot-node" && cargo build --release -p host-slot-node --features get) >"$LANE_HOME/build-responder.log" 2>&1; then
        cp "$ROOT/deploy/host-slot-node/target/release/host-slot-node" "$LANE_HOME/host-slot-node-get"
        ok responder "built $LANE_HOME/host-slot-node-get ($LANE_HOME/build-responder.log)"
    else
        bad responder "the build failed ($LANE_HOME/build-responder.log)"
    fi
}

# ── selftest ────────────────────────────────────────────────────────────────────────────────────
selftest() {
    local key population
    population="$(python3 -I - "$ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts/lib")
import stack_frame_gate as g
print(" ".join(sorted(i.key for i in g.IMAGES if i.key.startswith("zephyr-client-fixed"))))
PY
)"
    local mine
    mine="$(printf '%s\n' "${IMAGES[@]}" | sort | tr '\n' ' ' | sed 's/ $//')"
    if [[ "$mine" == "$population" ]]; then
        ok selftest "the lane's images are the stack gate's zephyr-client-fixed images ($mine)"
    else
        bad selftest "the lane has [$mine] and the stack gate has [$population]"
    fi
    local overlay
    for key in "${IMAGES[@]}"; do
        image_spec "$key"
        IFS=';' read -ra files <<<"$OVERLAYS"
        for overlay in "${files[@]}"; do
            if [[ ! -f "$ROOT/deploy/zephyr-admin-node/$overlay" ]]; then
                bad selftest "$key names $overlay, which is not in deploy/zephyr-admin-node"
            fi
        done
        if python3 -I - "$ROOT" "$key" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts/lib")
import resource_budget_gate as r
sys.exit(0 if sys.argv[2] in r.population() else 1)
PY
        then
            ok selftest "$key has a row in the resource budget"
        else
            bad selftest "$key has no row in the resource budget: a run of it would be held to nothing"
        fi
    done
    [[ "$fails" -eq 0 ]]
}

# ── main ────────────────────────────────────────────────────────────────────────────────────────
cmd="${1:-}"
shift || true
mkdir -p "$LANE_HOME"
case "$cmd" in
    preflight) preflight "${1:-}" ;;
    build) [[ $# -ge 1 ]] || { echo "usage: $0 build <image>" >&2; exit 64; }; build "$1" ;;
    run) [[ $# -ge 1 ]] || { echo "usage: $0 run <image>" >&2; exit 64; }; run "$1" ;;
    all)
        [[ $# -ge 1 ]] || { echo "usage: $0 all <image>..." >&2; exit 64; }
        preflight "" || exit 1
        for key in "$@"; do
            build "$key" && run "$key"
        done
        ;;
    build-responder) build_responder ;;
    list) printf '%s\n' "${IMAGES[@]}" ;;
    --selftest) selftest ;;
    *)
        sed -n '9,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
        exit 64
        ;;
esac
status=$?
if [[ "$fails" -ne 0 ]]; then
    say "$fails step(s) failed" >&2
    exit 1
fi
exit "$status"

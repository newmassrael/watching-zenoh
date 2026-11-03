#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The kit lane: a T2G kit image built, flashed, run on the board and held to the row the repository
# commits for it (`deploy/resource_budget.json`, `scripts/lib/stack_frame_gate.py`), in one command whose
# every step says its own verdict. It is a LAB lane: it needs the kit, its debugger and a router on the
# host the kit is cabled to, so hosted CI cannot run it. Its `build` step needs none of those, and
# Layer Qzk of run-ci.sh runs it for every image on the hosted runner: an arena outgrown, a stack
# bound that moved or a text that grew is seen in the push that did it and not on the next kit day.
#
#   scripts/kit-lane.sh preflight [--deep]   the host is ready: workspace, tools, console, interface, router
#   scripts/kit-lane.sh build <image>        west build, pad to the region, the stack gate on the ELF
#   scripts/kit-lane.sh run <image>          flash, boot, ask, and hold the run to its row
#   scripts/kit-lane.sh all <image>...       preflight, then build and run each
#   scripts/kit-lane.sh compare [--boots N] <image>...   answering images side by side, alternating boots
#   scripts/kit-lane.sh build-responder      the host node that answers the asking image (needs cargo)
#   scripts/kit-lane.sh list                 the images
#   scripts/kit-lane.sh images               the images whose build needs no kit (the ones Layer Qzk builds)
#   scripts/kit-lane.sh --selftest           the table of images against the gates and the overlays
#
# Images are the keys of the stack gate: zephyr-client-heap (the fixed client with its storage on the
# kernel heap), zephyr-client-fixed, zephyr-client-fixed-batching (they answer,
# and the host measures a GET through a router), zephyr-client-fixed-get (it asks a responder, and its
# own console line carries the round trip) and zephyr-client-fixed-tls, a VERIFY image: it dials a router
# over the secure channel, the lane configures the router to pin the certificate the image prints, holds
# the run to the image's line that its peer is verified, and then measures a GET as for an answering
# image. A MEASURE image (zephyr-tls-fit, the secure channel's fit) runs alone, with no router: it is
# flashed, reset, and held to its own console verdict. COMPARE images (zephyr-pico-queryable and -st,
# zenoh-pico answering the same two GETs with its
# read and lease tasks and with the program stepping it) are run by
# `compare` beside answering images (docs/upstream-parity.md M1): each boot in alternating order, the
# session's datagrams captured at the host's wire, and scripts/lib/kit_compare.py's verdict per cell.
# The pico image builds from vendor/zenoh-pico, so a tree sent here carries that submodule too.
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
# `KIT_LANE_HOME` (default ~/wz-kit-lane) is where builds and outputs live. `KIT_LANE_LOCK` (default
# ~/.local/state/wz/kit.lock) is the kit's lock. It sits outside every lane home because the kit is one
# board, and sessions run the lane from homes of their own: a lock per home let two of them touch the
# kit at once (2026-10-27).
#
# WHAT IT WILL NOT DO: flash a file that is not the padded region it just built, flash while a debugger,
# a capture or a ping runs or the console is held, or run while another lane run holds the lock. The kit
# has a saved original CM0+ image (docs/storage-policy-and-link-layer.md, the lab's restore): this lane
# writes the M7_0 region only, and the CM0+ launcher it needs must already be in place.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_ENV="${KIT_LAB_ENV:-$HOME/.config/wz-kit-lab.env}"
LANE_HOME="${KIT_LANE_HOME:-$HOME/wz-kit-lane}"
KIT_LOCK="${KIT_LANE_LOCK:-$HOME/.local/state/wz/kit.lock}"
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

# image key -> the application, its overlays, and whether it answers, asks or only measures. THE TABLE:
# `--selftest` holds it to the stack gate's population and to the files.
image_spec() {
    APP=zephyr-admin-node
    READY_TAG="ZEPHYR-WZ-CLIENT READY"
    case "$1" in
        # COMPARE images (docs/upstream-parity.md M1): they answer the same two GETs with the same keys,
        # bodies and encoding as zephyr-client-fixed, and are run by `compare` beside it. They have no
        # stack gate row and no resource row: what a compare run reads of them is its own report.
        #
        # zenoh-pico with the wz client's planes (docs/upstream-parity.md step M2), in its two arms:
        # its own read and lease tasks, and the program stepping the session.
        zephyr-pico-queryable)
            APP=zephyr-pico-compare
            OVERLAYS="overlays/multi_thread.conf"
            KIND=answer
            READY_TAG="ZEPHYR-PICO READY"
            ;;
        zephyr-pico-queryable-st)
            APP=zephyr-pico-compare
            OVERLAYS=""
            KIND=answer
            READY_TAG="ZEPHYR-PICO READY"
            ;;
        # A MEASURE image runs alone on the kit, with no router and no network, and its console says
        # what it measured and whether it held (a line `<TAG> done ok=1`). The secure channel's fit
        # (decision D9 of docs/session-lifecycle-intent.md): Mbed TLS's mutual TLS 1.3 handshake
        # between two in-memory peers, each pinning the other's key.
        zephyr-tls-fit)
            APP=zephyr-tls-fit
            OVERLAYS=""
            KIND=measure
            DONE_TAG="TLS-FIT"
            ;;
        zephyr-client-fixed)
            OVERLAYS="overlays/t2g_zeth.conf;overlays/t2g_client.conf;overlays/t2g_client_fixed.conf"
            KIND=answer
            ;;
        zephyr-client-fixed-batching)
            OVERLAYS="overlays/t2g_zeth.conf;overlays/t2g_client.conf;overlays/t2g_client_fixed.conf;overlays/t2g_client_batching.conf"
            KIND=answer
            ;;
        # The same client on the heap profile of the storage (CONFIG_WZ_STORAGE_HEAP): the fixed
        # client's code with the node's storage block taken from the kernel heap at start. It has the
        # fixed client's stack, text and resource rows, and the compare run reads its heap.
        zephyr-client-heap)
            OVERLAYS="overlays/t2g_zeth.conf;overlays/t2g_client.conf;overlays/t2g_client_heap.conf"
            KIND=answer
            ;;
        zephyr-client-fixed-get)
            OVERLAYS="overlays/t2g_zeth.conf;overlays/t2g_client.conf;overlays/t2g_client_fixed.conf;overlays/t2g_client_get.conf"
            KIND=ask
            ;;
        # A VERIFY image dials a router over the secure channel (decision D9) and its console says
        # whether it reads the router as the holder of the key the router's zid names. The router
        # is configured from what the image prints: the certificate it pins is the image's own.
        zephyr-client-fixed-tls)
            OVERLAYS="overlays/t2g_zeth.conf;overlays/t2g_client.conf;overlays/t2g_client_fixed.conf;overlays/t2g_client_tls.conf"
            KIND=verify
            ;;
        # An ADMIN image is the product node that LISTENS over the secure channel (decision D14 of
        # docs/session-lifecycle-intent.md): the router dials it with a key the lane made before the build,
        # whose zid is the commander the image is built with for the status verb and for no other, and the
        # host asks the verbs through the router. Its rows are set by its first runs on the kit.
        zephyr-admin-fixed-tls)
            OVERLAYS="overlays/t2g_zeth.conf;overlays/qemu_admin_fixed_tls.conf;overlays/t2g_admin_fixed_tls.conf"
            KIND=admin
            READY_TAG="ZEPHYR-WZ-ADMIN READY"
            ;;
        *) return 1 ;;
    esac
}
IMAGES=(zephyr-client-fixed zephyr-client-fixed-batching zephyr-client-fixed-get zephyr-client-fixed-tls zephyr-client-heap)
# The measure images: not the stack gate's (their stack is what they report) and not yet a resource
# row's (the row is set from what they measure).
MEASURE_IMAGES=(zephyr-tls-fit)
# The admin images: the product node that listens, run against a router that dials it. Not the stack
# gate's yet (no row until a run sets it).
ADMIN_IMAGES=(zephyr-admin-fixed-tls)
# The compare images: run only by `compare`, beside the images above.
COMPARE_IMAGES=(zephyr-pico-queryable zephyr-pico-queryable-st)
is_compare_image() { [[ " ${COMPARE_IMAGES[*]} " == *" $1 "* ]]; }
# The port a verify image's router listens on for `tls/` (the image's CONFIG_WZ_CLIENT_ENDPOINT).
TLS_PORT=7448
# The address the kit's host takes on the cable (the one overlays/t2g_zeth.conf's plan and the client
# overlays dial) and the port the second peer of an admin image's run listens on for `tls/`: the
# locator the admin image is built to hint for that peer.
PEER_HOST=192.168.100.1
PEER_PORT=7449
# The port of a third peer an admin image's run WRITES as a connect endpoint (no zid is hinted for it).
ENDPOINT_PORT=7450

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

# The router's identity in $1: a P-256 key, a certificate self-signed over it, and the zid it names
# (decision D1: the first 16 bytes of SHA-256 over the key's DER SubjectPublicKeyInfo, which zenoh's
# configuration spells as hex of those bytes read little-endian, leading zeros dropped, because zenoh
# refuses an id with them). The zid is left in ROUTER_ID.
make_router_identity() {
    local dir="$1" digest
    mkdir -p "$dir"
    openssl ecparam -name prime256v1 -genkey -noout -out "$dir/router.key" 2>"$dir/router-id.log" &&
        openssl req -new -x509 -key "$dir/router.key" -subj /CN=wz-kit-router -days 3650 \
            -out "$dir/router.pem" 2>>"$dir/router-id.log" || return 1
    digest="$(openssl pkey -in "$dir/router.key" -pubout -outform DER 2>>"$dir/router-id.log" | sha256sum)"
    ROUTER_ID="$(zenoh_id_of_digest "$digest")"
    [[ -n "$ROUTER_ID" ]]
}

# The zid text a SHA-256 hex digest names: its first 16 bytes read as a little-endian number, leading
# zeros dropped (wz_session_core::zid_hex::write_zenoh_hex).
zenoh_id_of_digest() {
    local digest="${1:0:32}" le="" i
    for ((i = 30; i >= 0; i -= 2)); do
        le+="${digest:i:2}"
    done
    echo "${le#"${le%%[!0]*}"}"
}

# The zid the key of a PEM certificate names, derived here and not read from anything the node printed.
zenoh_id_of_certificate() {
    local digest
    digest="$(openssl x509 -in "$1" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum)"
    zenoh_id_of_digest "$digest"
}

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
        # The router is the pinned upstream's (UPSTREAM_VERSION of upstream_feature_census.py): a figure or
        # a verdict taken against another version says nothing about the one the images are held to.
        local pinned
        pinned="$(python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1] + "/scripts/lib"); from upstream_feature_census import UPSTREAM_VERSION as v; print(v)' "$ROOT")"
        if [[ -n "$pinned" && "$(router_version)" == "zenohd v$pinned "* ]]; then
            ok preflight "the router runs, at the pinned version ($(router_version))"
        else
            bad preflight "the router is '$(router_version)' and the pinned upstream is v$pinned: build it with scripts/build-zenohd.sh and name it in $LAB_ENV (KIT_ZENOHD)"
        fi
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
# BUILD_VARIANT=compare builds the image as a compare run holds it (the memory report on, see
# compare below) into a build directory and a record of its own, so a gated image's own build, the
# one `run` flashes and its rows describe, is never replaced by a compare build of it.
build() {
    local key="$1" before="$fails"
    image_spec "$key" || { bad "$key" "not an image of this lane (scripts/kit-lane.sh list)"; return 1; }
    local name="$key" confs="$OVERLAYS"
    if [[ "${BUILD_VARIANT:-}" == compare ]]; then
        name="compare-$key"
        confs="${confs:+$confs;}$ROOT/deploy/zephyr-common/memory_report.conf"
    fi
    # KIT_EXTRA_CONF names a conf file put after every overlay of the image: an experiment's, such as the
    # smallest kernel heap pool an image runs in (CONFIG_HEAP_MEM_POOL_SIZE). What it builds is not the
    # image a row describes, and a figure measured with it is not a row.
    if [[ -n "${KIT_EXTRA_CONF:-}" ]]; then
        confs="${confs:+$confs;}$KIT_EXTRA_CONF"
    fi
    local dir="$LANE_HOME/build/$name" out="$LANE_HOME/out/$CLOCK_TAG-$name"
    mkdir -p "$out"
    if [[ "$KIND" == admin ]]; then
        # The commanders are compiled in, so the router's key exists before the image: the run reads the
        # same key back from this directory. Status lists the router; close, reset and open list nobody.
        if ! make_router_identity "$out"; then
            bad "$key" "the router's identity could not be made ($out/router-id.log)"
            return 1
        fi
        local commander_id="$ROUTER_ID"
        # The second peer the run starts: the image is built to hint where it is, so the commander's
        # `open` for its zid has a locator to dial for it.
        if ! make_router_identity "$out/peer"; then
            bad "$key" "the peer's identity could not be made ($out/peer/router-id.log)"
            return 1
        fi
        local peer_id="$ROUTER_ID"
        {
            printf 'CONFIG_WZ_COMMANDERS_STATUS="%s"\n' "$commander_id"
            printf 'CONFIG_WZ_COMMANDERS_OPEN="%s"\n' "$commander_id"
            printf 'CONFIG_WZ_PEER_NODE_ZID="%s"\n' "$peer_id"
            printf 'CONFIG_WZ_PEER_NODE_LOCATOR="tls/%s:%s"\n' "$PEER_HOST" "$PEER_PORT"
        } >"$out/commanders.conf"
        echo "$commander_id" >"$out/router.zid"
        echo "$peer_id" >"$out/peer.zid"
        confs="${confs:+$confs;}$out/commanders.conf"
        ok "$key" "the router's key names zid $commander_id, built in as the commander of status and of open and of no other verb; the peer it opens is $peer_id at tls/$PEER_HOST:$PEER_PORT"
    fi
    local avail
    avail="$(LC_ALL=C free -m | awk '/^Mem:/ {print $7}')"
    local floor_mb="${KIT_LANE_MIN_AVAIL_MB:-8000}"
    if ! [[ "${avail:-}" =~ ^[0-9]+$ && "$avail" -ge "$floor_mb" ]]; then
        bad "$key" "less than $floor_mb MB of memory is available, or the figure could not be read: a build here can take the host down"
        return 1
    fi
    # shellcheck source=/dev/null  # created by scripts/provision-zephyr.sh
    . "$ZEPHYR_HOME/.venv/bin/activate"
    export ZEPHYR_BASE="$ZEPHYR_HOME/zephyr"
    export CMAKE_BUILD_PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-8}" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
    # The Rust half carries its line tables, which the stack bound gate reads to name the source line of each
    # call through a register; they are debug sections the flashed binary does not hold, and the text is the same.
    export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
    local extra=()
    if [[ -n "$confs" ]]; then
        extra+=(-DEXTRA_CONF_FILE="$confs")
    fi
    if [[ "$APP" == zephyr-admin-node ]]; then
        extra+=(-DEXTRA_DTC_OVERLAY_FILE=overlays/t2g_zeth.overlay)
    fi
    if [[ "${#extra[@]}" -gt 0 ]]; then
        extra=(-- "${extra[@]}")
    fi
    if (
        cd "$ROOT" && nice -n 10 west build -b "$BOARD" -d "$dir" "deploy/$APP" -p auto "${extra[@]}"
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
    if [[ "$KIND" == measure ]]; then
        ok "$key" "a measure image: its stack is one of the figures it reports, not the stack gate's"
    elif [[ "$KIND" == verify ]]; then
        ok "$key" "a verify image: no stack gate row yet, its first runs on the kit set it"
    elif is_compare_image "$key" || [[ "${BUILD_VARIANT:-}" == compare ]]; then
        ok "$key" "a compare build: not the stack gate's, a compare run reports what it reads of it"
    elif python3 "$ROOT/scripts/lib/stack_frame_gate.py" --check "$key" --elf "$elf" >"$out/stack-gate.log" 2>&1; then
        ok "$key" "the stack gate holds the image ($(grep -a 'stack-chain: OK' "$out/stack-gate.log" | head -n 1 | cut -c1-120))"
    else
        bad "$key" "the stack gate refuses the image ($out/stack-gate.log)"
    fi
    # The stack bound with the calls through a register followed, held to the rows of deploy/resource_budget.json
    # that commit one; it is the figure the quarter of free stack applies to, and the kit's reading lies under it.
    local bound_rows
    bound_rows="$(python3 "$ROOT/scripts/lib/stack_bound_gate.py" --list)"
    if [[ "$KIND" == measure || "$KIND" == verify || "$KIND" == admin ]] || is_compare_image "$key" || [[ "${BUILD_VARIANT:-}" == compare ]]; then
        :
    elif [[ $'\n'"$bound_rows"$'\n' == *$'\n'"$key"$'\n'* ]]; then
        if python3 "$ROOT/scripts/lib/stack_bound_gate.py" --check "$key" --elf "$elf" >"$out/stack-bound.log" 2>&1; then
            ok "$key" "the stack bound holds the image ($(grep -a 'stack-bound: OK' "$out/stack-bound.log" | head -n 1 | cut -c1-120))"
        else
            bad "$key" "the stack bound refuses the image ($out/stack-bound.log)"
        fi
    fi
    # The text of the image told by who owns it, held to the rows of deploy/text_budget.json; an image
    # with no row is not held, and a compare build is not the gate's.
    local text_rows
    text_rows="$(python3 "$ROOT/scripts/lib/text_owner_gate.py" --list)"
    if is_compare_image "$key" || [[ "${BUILD_VARIANT:-}" == compare ]]; then
        :
    elif [[ $'\n'"$text_rows"$'\n' == *$'\n'"$key"$'\n'* ]]; then
        if python3 "$ROOT/scripts/lib/text_owner_gate.py" --check "$key" --elf "$elf" >"$out/text-gate.log" 2>&1; then
            ok "$key" "the text gate holds the image ($(grep -a 'text-owner: OK' "$out/text-gate.log" | head -n 1 | cut -c1-120))"
        else
            bad "$key" "the text gate refuses the image ($out/text-gate.log)"
        fi
    fi
    echo "$out" >"$LANE_HOME/last-out-$name"
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
# The node's key id, the first word after the image's READY tag: the keys the host asks are under it.
ready_node_id() { grep -a -o "$READY_TAG [0-9a-f]*" "$OUT/console.raw" | tail -n 1 | awk '{print $NF}'; }

# Take the kit for the rest of this process (fd 9 closes, and the lock goes, when it exits), and say who
# holds it. $1 names the step for the refusal. The holder line is written only while the lock is held,
# so a refusal never quotes a run that has ended.
take_kit() {
    mkdir -p "$(dirname "$KIT_LOCK")"
    exec 9>>"$KIT_LOCK"
    if ! flock -n 9; then
        bad "$1" "the kit is held by another lane run ($(cat "$KIT_LOCK.owner" 2>/dev/null || echo unknown)); $KIT_LOCK lets one run at a time touch it"
        return 1
    fi
    printf 'pid=%s home=%s step=%s since=%s\n' "$$" "$LANE_HOME" "$1" "$(date -u +%FT%TZ)" >"$KIT_LOCK.owner"
}

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
    take_kit "$key" || return 1
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
    if [[ "$KIND" == measure ]]; then
        run_measure "$key"
        stop_all
        trap - EXIT
        [[ "$fails" -eq "$before" ]]
        return
    fi
    if [[ "$KIND" == admin ]]; then
        run_admin "$key"
        stop_all
        trap - EXIT
        [[ "$fails" -eq "$before" ]]
        return
    fi
    local limit=60
    if [[ "$KIND" == verify ]]; then
        # The router is configured from what the image prints, so the image comes up first; past
        # its verified line the run is an answering image's.
        run_verify "$key" || return 1
    else
        start_and_reset "$key" || return 1
        [[ "$KIND" == ask ]] && limit=150
    fi
    hold_the_run "$key" "$limit"
    stop_all
    trap - EXIT
    [[ "$fails" -eq "$before" ]]
}

# The router, the responder an asking image needs, and the reset, for an image that dials a router
# at a fixed configuration; then the image's READY line.
start_and_reset() {
    local key="$1"
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

    local ready_before
    ready_before="$(count_lines "$READY_TAG")"
    GETTER_BEFORE="$(count_lines 'ZEPHYR-WZ-GET done')"
    if [[ -n "${KIT_PROFILE_OUT:-}" ]]; then
        # A profile run: the debugger that resets the kit stays attached and samples the program counter
        # of the M7_0 core (DWT_PCSR) for as long as the probe of `hold_the_run` is asking, so the
        # functions the GET path runs through can be counted (scripts/lib/pc_profile.py). The tool
        # perturbs the run (the row of the budget is not held to it), so a profile is never a verdict.
        PROFILE_FLAG="$OUT/profile.go" PROFILE_OUT="$KIT_PROFILE_OUT" \
            setsid "$KIT_PROGTOOLS/openocd/bin/openocd" -s "$KIT_PROGTOOLS/openocd/scripts" \
            -f interface/kitprog3.cfg -f target/infineon/cyt4bf.cfg \
            -f "$ROOT/scripts/lib/pc_sample.tcl" >"$OUT/reset.log" 2>&1 </dev/null &
        PIDS+=("$!")
        ok "$key" "the kit was reset and is sampled while the probe asks ($OUT/reset.log -> $KIT_PROFILE_OUT)"
    elif timeout 60 "$KIT_PROGTOOLS/openocd/bin/openocd" -s "$KIT_PROGTOOLS/openocd/scripts" \
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
        if [[ "$(count_lines "$READY_TAG")" -gt "$ready_before" ]]; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    if [[ "$(count_lines "$READY_TAG")" -le "$ready_before" ]]; then
        bad "$key" "no READY line after the reset in ${limit} s: the image did not start (is the CM0+ launcher in place? preflight --deep)"
        return 1
    fi
    ok "$key" "the image booted (READY line after the reset)"
}

# What a run holds once the image is up: an answering image is asked its two documents through the
# router (an image over the secure channel too, once it read its router as verified), an asking one
# says how its queries went; then the console's FAIL lines and the image's row of the budget.
hold_the_run() {
    local key="$1" limit="$2" waited=0
    local results=() node_id
    node_id="$(ready_node_id)"
    if [[ "$KIND" == answer || "$KIND" == verify ]]; then
        local asks=2000
        if [[ -n "${KIT_PROFILE_OUT:-}" ]]; then
            asks="${KIT_PROFILE_QUERIES:-20000}"
            : >"$OUT/profile.go"
        fi
        if python3 -I "$ROOT/scripts/lib/kit_rest_probe.py" "$REST_PORT" "$node_id" "$OUT/rest.json" "$asks" >"$OUT/probe.log" 2>&1; then
            rm -f "$OUT/profile.go"
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
            if [[ "$(count_lines 'ZEPHYR-WZ-GET done')" -gt "$GETTER_BEFORE" ]]; then
                break
            fi
            sleep 1
            waited=$((waited + 1))
        done
        if [[ "$(count_lines 'ZEPHYR-WZ-GET done')" -le "$GETTER_BEFORE" ]]; then
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
    # A secure-channel image reports its arena's peak, and the arena keeps a quarter free.
    if [[ "$KIND" == verify ]]; then
        hold_the_arena "$key" "$OUT/console.raw"
    fi
    if python3 "$ROOT/scripts/lib/resource_budget_gate.py" --measure "$key" --log "$OUT/console.raw" "${results[@]}" \
        >"$OUT/budget.log" 2>&1; then
        ok "$key" "the run is inside its row ($(tail -n 1 "$OUT/budget.log" | sed 's/^ *//'))"
    else
        bad "$key" "the run is outside its row: $(sed 's/^ *//' "$OUT/budget.log" | head -n 3 | tr '\n' ' ')"
    fi
}

# A measure image after its flash: the console, a reset, and the image's own `<DONE_TAG> done` line.
# No router, no address on the interface: the image touches nothing but the kit.
run_measure() {
    local key="$1" done_before
    stty -F "$KIT_CONSOLE" 115200 raw -echo -hupcl
    setsid timeout 600 cat "$KIT_CONSOLE" >"$OUT/console.raw" 2>"$OUT/console.err" </dev/null &
    PIDS+=("$!")
    sleep 2
    done_before="$(count_lines "$DONE_TAG done")"
    # Where the console stood at the reset: the run's lines are the ones after it, and the boot the
    # flash caused printed its own set before.
    local mark
    mark="$(stat -c %s "$OUT/console.raw")"
    if timeout 60 "$KIT_PROGTOOLS/openocd/bin/openocd" -s "$KIT_PROGTOOLS/openocd/scripts" \
        -f interface/kitprog3.cfg -f target/infineon/cyt4bf.cfg -c "init" -c "reset run" -c "shutdown" \
        >"$OUT/reset.log" 2>&1; then
        ok "$key" "the kit was reset ($OUT/reset.log)"
    else
        bad "$key" "the reset failed ($OUT/reset.log)"
        return 1
    fi
    local waited=0 limit=180
    while [[ "$waited" -lt "$limit" ]]; do
        if [[ "$(count_lines "$DONE_TAG done")" -gt "$done_before" ]]; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    if [[ "$(count_lines "$DONE_TAG done")" -le "$done_before" ]]; then
        bad "$key" "no '$DONE_TAG done' line after the reset in ${limit} s ($OUT/console.raw)"
        return 1
    fi
    tail -c +"$((mark + 1))" "$OUT/console.raw" | grep -a "^$DONE_TAG" >"$OUT/measure.txt"
    local verdict
    verdict="$(grep -a "$DONE_TAG done" "$OUT/measure.txt" | tail -n 1)"
    if [[ "$verdict" == *" ok=1"* ]]; then
        ok "$key" "the image held what it measured: $verdict ($OUT/measure.txt)"
    else
        bad "$key" "the image says it did not hold: $verdict ($OUT/measure.txt)"
    fi
}

# A verify image after its flash: the interface's address, the console, and a reset with no router
# yet. The image prints its certificate (PEM) before it dials; the router is then configured as an
# operator configures one for that device: mutual TLS on, the image's certificate as the root it
# pins, and a zid that is the one the router's own key names (decision D1: the first 16 bytes of
# SHA-256 over the key's DER SubjectPublicKeyInfo, which zenoh's configuration spells as hex of
# those bytes read little-endian). The verdict is the image's own line once its session is up.
run_verify() {
    local key="$1"
    if ! sudo -n ip addr add "$KIT_HOST_IP/24" dev "$KIT_IFACE" 2>"$OUT/ip.log"; then
        bad "$key" "the interface $KIT_IFACE did not take $KIT_HOST_IP ($OUT/ip.log)"
        return 1
    fi
    ADDR_ADDED=1
    stty -F "$KIT_CONSOLE" 115200 raw -echo -hupcl
    setsid timeout 600 cat "$KIT_CONSOLE" >"$OUT/console.raw" 2>"$OUT/console.err" </dev/null &
    PIDS+=("$!")
    sleep 2
    local mark
    mark="$(stat -c %s "$OUT/console.raw")"
    if timeout 60 "$KIT_PROGTOOLS/openocd/bin/openocd" -s "$KIT_PROGTOOLS/openocd/scripts" \
        -f interface/kitprog3.cfg -f target/infineon/cyt4bf.cfg -c "init" -c "reset run" -c "shutdown" \
        >"$OUT/reset.log" 2>&1; then
        ok "$key" "the kit was reset ($OUT/reset.log)"
    else
        bad "$key" "the reset failed ($OUT/reset.log)"
        return 1
    fi
    # The run's lines are the ones after the reset.
    since() { tail -c +"$((mark + 1))" "$OUT/console.raw" | tr -d '\r'; }
    local waited=0
    while [[ "$waited" -lt 60 ]] && ! since | grep -aq -- '-----END CERTIFICATE-----'; do
        sleep 1
        waited=$((waited + 1))
    done
    since | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' >"$OUT/device.pem"
    if ! openssl x509 -in "$OUT/device.pem" -noout -subject >"$OUT/device.subject" 2>&1; then
        bad "$key" "the image printed no certificate a router can read in 60 s ($OUT/console.raw)"
        return 1
    fi
    ok "$key" "the image printed its certificate ($(cat "$OUT/device.subject"))"

    # The router's identity: a P-256 key, a certificate self-signed over it, and the zid it names.
    if ! make_router_identity "$OUT"; then
        bad "$key" "the router's identity could not be made ($OUT/router-id.log)"
        return 1
    fi
    local id="$ROUTER_ID"
    cat >"$OUT/router.json5" <<EOF
{ id: "$id", mode: "router",
  transport: { link: { tls: {
    listen_certificate: "$OUT/router.pem", listen_private_key: "$OUT/router.key",
    root_ca_certificate: "$OUT/device.pem", enable_mtls: true } } } }
EOF
    # The REST plugin is the host's view of the image, as for an answering image.
    setsid "$KIT_ZENOHD" --config "$OUT/router.json5" -l "tls/$KIT_HOST_IP:$TLS_PORT" \
        --no-multicast-scouting --plugin-search-dir "$(dirname "$KIT_ZENOHD")" \
        --rest-http-port "127.0.0.1:$REST_PORT" >"$OUT/router.log" 2>&1 </dev/null &
    PIDS+=("$!")
    ok "$key" "a router pins the image's certificate and claims zid $id ($OUT/router.json5)"

    waited=0
    while [[ "$waited" -lt 120 ]] && ! since | grep -aq 'session established, peer '; do
        sleep 1
        waited=$((waited + 1))
    done
    local verdict
    verdict="$(since | grep -a 'session established, peer ' | head -n 1)"
    if [[ -z "$verdict" ]]; then
        bad "$key" "no session in 120 s after the router came up ($OUT/console.raw, $OUT/router.log)"
        return 1
    elif [[ "$verdict" != *"peer verified"* ]]; then
        bad "$key" "the session is up but the image does not read the router as verified: $verdict"
        return 1
    fi
    ok "$key" "the image and the router verify each other: $verdict"
}

# An admin image after its flash (decision D14). The image LISTENS over the secure channel and prints its
# certificate and a READY line with the zid its key names; the router, whose key the image was built to
# list as the commander of status (build made it, and $OUT/router.zid is its zid), DIALS the image with
# mutual TLS and the image's certificate as the root it pins; the host then asks the verbs through the
# router's REST plugin. Status, which the router's key is listed for, must be answered with a status
# document, and close, which nobody is listed for, must be refused by name. The pair discriminates both
# ways: a node that could not tell the requester would refuse the status, and one that took the requester
# for anyone would answer the close.
run_admin() {
    local key="$1"
    if [[ ! -f "$OUT/router.key" || ! -f "$OUT/router.pem" || ! -s "$OUT/router.zid" ]]; then
        bad "$key" "the router's identity is not in $OUT: build the image again"
        return 1
    fi
    local router_id
    router_id="$(cat "$OUT/router.zid")"
    if ! sudo -n ip addr add "$KIT_HOST_IP/24" dev "$KIT_IFACE" 2>"$OUT/ip.log"; then
        bad "$key" "the interface $KIT_IFACE did not take $KIT_HOST_IP ($OUT/ip.log)"
        return 1
    fi
    ADDR_ADDED=1
    stty -F "$KIT_CONSOLE" 115200 raw -echo -hupcl
    setsid timeout 900 cat "$KIT_CONSOLE" >"$OUT/console.raw" 2>"$OUT/console.err" </dev/null &
    PIDS+=("$!")
    sleep 2
    local mark
    mark="$(stat -c %s "$OUT/console.raw")"
    if timeout 60 "$KIT_PROGTOOLS/openocd/bin/openocd" -s "$KIT_PROGTOOLS/openocd/scripts" \
        -f interface/kitprog3.cfg -f target/infineon/cyt4bf.cfg -c "init" -c "reset run" -c "shutdown" \
        >"$OUT/reset.log" 2>&1; then
        ok "$key" "the kit was reset ($OUT/reset.log)"
    else
        bad "$key" "the reset failed ($OUT/reset.log)"
        return 1
    fi
    since() { tail -c +"$((mark + 1))" "$OUT/console.raw" | tr -d '\r'; }
    local waited=0
    while [[ "$waited" -lt 90 ]] && ! since | grep -aq "$READY_TAG"; do
        sleep 1
        waited=$((waited + 1))
    done
    local ready node_id locator
    ready="$(since | grep -a "$READY_TAG" | tail -n 1)"
    node_id="$(awk '{print $3}' <<<"$ready")"
    locator="$(awk '{print $4}' <<<"$ready")"
    if [[ -z "$node_id" || "$locator" != tls/* ]]; then
        bad "$key" "no READY line with a zid and a tls/ locator in 90 s after the reset ($OUT/console.raw)"
        return 1
    fi
    since | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' >"$OUT/device.pem"
    if ! openssl x509 -in "$OUT/device.pem" -noout -subject >"$OUT/device.subject" 2>&1; then
        bad "$key" "the image printed no certificate a router can read ($OUT/console.raw)"
        return 1
    fi
    local derived
    derived="$(zenoh_id_of_certificate "$OUT/device.pem")"
    if [[ "$derived" != "$node_id" ]]; then
        bad "$key" "the READY line claims zid $node_id and the certificate's key names $derived"
        return 1
    fi
    ok "$key" "the image listens at $locator and the key of its certificate names the zid its READY line claims ($node_id)"

    cat >"$OUT/router.json5" <<EOF
{ id: "$router_id", mode: "router",
  connect: { endpoints: ["$locator"] },
  transport: { link: { tls: {
    root_ca_certificate: "$OUT/device.pem",
    connect_certificate: "$OUT/router.pem", connect_private_key: "$OUT/router.key",
    enable_mtls: true, verify_name_on_connect: false } } } }
EOF
    setsid "$KIT_ZENOHD" --config "$OUT/router.json5" -l "tcp/127.0.0.1:17447" \
        --no-multicast-scouting --plugin-search-dir "$(dirname "$KIT_ZENOHD")" \
        --rest-http-port "127.0.0.1:$REST_PORT" >"$OUT/router.log" 2>&1 </dev/null &
    local router_pid=$!
    PIDS+=("$router_pid")
    ok "$key" "a router claiming zid $router_id dials the image and pins its certificate ($OUT/router.json5)"

    # The verbs are asked through the router: under the node's zid, for a peer the lane names (the router).
    local base="http://127.0.0.1:$REST_PORT/@/$node_id/peer/session" attempt status_body="" close_body=""
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
        status_body="$(curl -s -m 10 "$base/status/$router_id" 2>/dev/null || true)"
        [[ "$status_body" =~ verdict[^a-z]+status ]] && break
        sleep 5
    done
    printf '%s\n' "$status_body" >"$OUT/status.json"
    close_body="$(curl -s -m 10 "$base/close/$router_id" 2>/dev/null || true)"
    printf '%s\n' "$close_body" >"$OUT/close.json"
    if [[ "$status_body" =~ verdict[^a-z]+status ]]; then
        ok "$key" "status was answered for the commander the image lists: the key of the router's session ($OUT/status.json)"
    else
        bad "$key" "status was not answered for the listed commander: '${status_body:0:160}' ($OUT/status.json, $OUT/router.log)"
    fi
    if [[ "$close_body" =~ verdict[^a-z]+refused ]]; then
        ok "$key" "close was refused by name: nobody is listed for it ($OUT/close.json)"
    else
        bad "$key" "close was not refused by name: '${close_body:0:160}' ($OUT/close.json)"
    fi

    # The open by zid. A second peer listens on the cable for `tls/`, pinning the image's certificate, and
    # the image was built with a hint for it (its zid and this locator): the commander asks the image to
    # open the peer, the image dials it FOR that zid, and the admin root of the image lists the session.
    if [[ "$KIT_HOST_IP" != "$PEER_HOST" ]]; then
        bad "$key" "the image hints its second peer at $PEER_HOST and this host takes $KIT_HOST_IP on the cable"
        return 1
    fi
    local peer_id
    peer_id="$(cat "$OUT/peer.zid")"
    # Before the open the image holds the router's session and not the peer's: the hint alone dials nobody.
    local root_before
    root_before="$(curl -s -m 10 "http://127.0.0.1:$REST_PORT/@/$node_id/peer" 2>/dev/null || true)"
    printf '%s\n' "$root_before" >"$OUT/root-before.json"
    if ! grep -aqE "\"peer\"[^a-f0-9]+$router_id" <<<"$root_before"; then
        bad "$key" "the admin root does not list the router's session before the open: '${root_before:0:160}' ($OUT/root-before.json)"
    elif grep -aqE "\"peer\"[^a-f0-9]+$peer_id" <<<"$root_before"; then
        bad "$key" "the image held the peer before it was asked to open it ($OUT/root-before.json)"
    else
        ok "$key" "before the open the admin root lists the router's session and not the peer's: a hint dials nobody ($OUT/root-before.json)"
    fi
    cat >"$OUT/peer/router.json5" <<EOF
{ id: "$peer_id", mode: "router",
  transport: { link: { tls: {
    listen_certificate: "$OUT/peer/router.pem", listen_private_key: "$OUT/peer/router.key",
    root_ca_certificate: "$OUT/device.pem", enable_mtls: true } } } }
EOF
    setsid "$KIT_ZENOHD" --config "$OUT/peer/router.json5" -l "tls/$PEER_HOST:$PEER_PORT" \
        --no-multicast-scouting --plugin-search-dir "$(dirname "$KIT_ZENOHD")" \
        >"$OUT/peer/router.log" 2>&1 </dev/null &
    local peer_pid=$!
    PIDS+=("$peer_pid")
    sleep 3
    local open_body
    open_body="$(curl -s -m 10 "$base/open/$peer_id" 2>/dev/null || true)"
    printf '%s\n' "$open_body" >"$OUT/open.json"
    if [[ "$open_body" =~ verdict[^a-z]+opening ]]; then
        ok "$key" "open was taken for the peer the image hints ($peer_id): the commander the image lists asked ($OUT/open.json)"
    else
        bad "$key" "open was not taken: '${open_body:0:160}' ($OUT/open.json, $OUT/peer/router.log)"
    fi
    local root_body="" held_router=0 held_peer=0
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
        root_body="$(curl -s -m 10 "http://127.0.0.1:$REST_PORT/@/$node_id/peer" 2>/dev/null || true)"
        grep -aqE "\"peer\"[^a-f0-9]+$router_id" <<<"$root_body" && held_router=1
        grep -aqE "\"peer\"[^a-f0-9]+$peer_id" <<<"$root_body" && held_peer=1
        [[ "$held_peer" -eq 1 && "$held_router" -eq 1 ]] && break
        sleep 5
    done
    printf '%s\n' "$root_body" >"$OUT/root.json"
    if [[ "$held_peer" -eq 1 && "$held_router" -eq 1 ]]; then
        ok "$key" "the admin root of the image lists both sessions: the router that dialled it and the peer it opened by zid ($OUT/root.json)"
    else
        bad "$key" "the admin root does not list both sessions (router $held_router, peer $held_peer): '${root_body:0:200}' ($OUT/root.json)"
    fi

    # The write of the connect endpoints, which the config subscriber serves: a third peer listens on the
    # cable, the router writes its locator as the image's endpoint, and the image dials it (no zid is hinted
    # for it) and reports the endpoint live; the admin root then lists its session. The image holds two
    # sessions at most (the router's and one it dials), so the peer it opened by zid goes first.
    kill "$peer_pid" 2>/dev/null
    wait "$peer_pid" 2>/dev/null
    sleep 5
    if ! make_router_identity "$OUT/endpoint-peer"; then
        bad "$key" "the endpoint peer's identity could not be made ($OUT/endpoint-peer/router-id.log)"
        return 1
    fi
    local endpoint_id="$ROUTER_ID"
    cat >"$OUT/endpoint-peer/router.json5" <<EOF
{ id: "$endpoint_id", mode: "router",
  transport: { link: { tls: {
    listen_certificate: "$OUT/endpoint-peer/router.pem", listen_private_key: "$OUT/endpoint-peer/router.key",
    root_ca_certificate: "$OUT/device.pem", enable_mtls: true } } } }
EOF
    setsid "$KIT_ZENOHD" --config "$OUT/endpoint-peer/router.json5" -l "tls/$PEER_HOST:$ENDPOINT_PORT" \
        --no-multicast-scouting --plugin-search-dir "$(dirname "$KIT_ZENOHD")" \
        >"$OUT/endpoint-peer/router.log" 2>&1 </dev/null &
    PIDS+=("$!")
    sleep 3
    local put_code
    put_code="$(curl -s -m 10 -o "$OUT/put.body" -w '%{http_code}' -X PUT -H 'content-type: application/json' \
        -d "[\"tls/$PEER_HOST:$ENDPOINT_PORT\"]" \
        "http://127.0.0.1:$REST_PORT/@/$node_id/peer/config/connect/endpoints" 2>/dev/null || true)"
    local held_endpoint=0 connect_body=""
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
        root_body="$(curl -s -m 10 "http://127.0.0.1:$REST_PORT/@/$node_id/peer" 2>/dev/null || true)"
        grep -aqE "\"peer\"[^a-f0-9]+$endpoint_id" <<<"$root_body" && held_endpoint=1
        [[ "$held_endpoint" -eq 1 ]] && break
        sleep 5
    done
    printf '%s\n' "$root_body" >"$OUT/root-endpoint.json"
    connect_body="$(curl -s -m 10 "http://127.0.0.1:$REST_PORT/@/$node_id/peer/status/connect" 2>/dev/null || true)"
    printf '%s\n' "$connect_body" >"$OUT/status-connect.json"
    if [[ "$held_endpoint" -eq 1 ]]; then
        ok "$key" "the write of the connect endpoints (HTTP $put_code) made the image dial the third peer: its admin root lists the session ($OUT/root-endpoint.json)"
    else
        bad "$key" "the write of the connect endpoints (HTTP $put_code) did not make the image dial the third peer: '${root_body:0:200}' ($OUT/root-endpoint.json, $OUT/endpoint-peer/router.log)"
    fi
    if grep -aqE "\"state\"[^a-z]+live" <<<"$connect_body"; then
        ok "$key" "the image reports the written endpoint live ($OUT/status-connect.json)"
    else
        bad "$key" "the image does not report the written endpoint live: '${connect_body:0:200}' ($OUT/status-connect.json)"
    fi

    # The control: the same image, asked through a router whose key is NOT the listed commander. The verb
    # that was answered must now be refused, or the answer above was the verb's and not the requester's.
    kill "$router_pid" 2>/dev/null
    wait "$router_pid" 2>/dev/null
    sleep 3
    local other="$OUT/other"
    if ! make_router_identity "$other"; then
        bad "$key" "the control router's identity could not be made ($other/router-id.log)"
        return 1
    fi
    local other_id="$ROUTER_ID" other_port=$((REST_PORT + 1))
    cat >"$other/router.json5" <<EOF
{ id: "$other_id", mode: "router",
  connect: { endpoints: ["$locator"] },
  transport: { link: { tls: {
    root_ca_certificate: "$OUT/device.pem",
    connect_certificate: "$other/router.pem", connect_private_key: "$other/router.key",
    enable_mtls: true, verify_name_on_connect: false } } } }
EOF
    setsid "$KIT_ZENOHD" --config "$other/router.json5" -l "tcp/127.0.0.1:17448" \
        --no-multicast-scouting --plugin-search-dir "$(dirname "$KIT_ZENOHD")" \
        --rest-http-port "127.0.0.1:$other_port" >"$other/router.log" 2>&1 </dev/null &
    PIDS+=("$!")
    local control_body=""
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
        control_body="$(curl -s -m 10 "http://127.0.0.1:$other_port/@/$node_id/peer/session/status/$other_id" 2>/dev/null || true)"
        [[ "$control_body" =~ verdict ]] && break
        sleep 5
    done
    printf '%s\n' "$control_body" >"$OUT/control.json"
    if [[ "$control_body" =~ verdict[^a-z]+refused ]]; then
        ok "$key" "status was refused to a router whose key is not listed ($other_id): the answer above was the requester's ($OUT/control.json)"
    else
        bad "$key" "status was not refused to an unlisted router: '${control_body:0:160}' ($OUT/control.json, $other/router.log)"
    fi
    if since | grep -aq 'wz: FAIL'; then
        bad "$key" "the console says 'wz: FAIL' ($(since | grep -a 'wz: FAIL' | head -n 1))"
    else
        ok "$key" "the console has no 'wz: FAIL' line"
    fi
    # The stack the firmware says it used over the run, against the image's row (no latency is held).
    since >"$OUT/console.run"
    if python3 "$ROOT/scripts/lib/resource_budget_gate.py" --measure "$key" --log "$OUT/console.run" \
        >"$OUT/budget.log" 2>&1; then
        ok "$key" "the run is inside its row ($(tail -n 1 "$OUT/budget.log" | sed 's/^ *//'))"
    else
        bad "$key" "the run is outside its row: $(sed 's/^ *//' "$OUT/budget.log" | head -n 3 | tr '\n' ' ')"
    fi
    # The channel's arena over the whole run (a session accepted, one dialled, an endpoint dialled).
    hold_the_arena "$key" "$OUT/console.run"
}

# The channel's arena over a run: the firmware's last `tls arena: peak N of M bytes` line in the console
# file $2 leaves a quarter of M free, as the stack does. An image that builds the secure channel reports it.
hold_the_arena() {
    local key="$1" console="$2" arena_line arena_peak_bytes arena_size
    arena_line="$(grep -a 'tls arena: peak' "$console" | tail -n 1)"
    arena_peak_bytes="$(sed -n 's/.*tls arena: peak \([0-9]*\) of \([0-9]*\) bytes.*/\1/p' <<<"$arena_line")"
    arena_size="$(sed -n 's/.*tls arena: peak \([0-9]*\) of \([0-9]*\) bytes.*/\2/p' <<<"$arena_line")"
    if [[ -z "$arena_peak_bytes" || -z "$arena_size" || "$arena_size" -eq 0 ]]; then
        bad "$key" "the console has no 'tls arena: peak N of M bytes' line: the firmware did not say what the channel's arena held"
    elif (( arena_peak_bytes * 4 > arena_size * 3 )); then
        bad "$key" "the channel's arena peaked at $arena_peak_bytes of $arena_size bytes: less than a quarter free"
    else
        ok "$key" "the channel's arena peaked at $arena_peak_bytes of $arena_size bytes, a quarter or more free"
    fi
}

# ── compare ─────────────────────────────────────────────────────────────────────────────────────
# Answering images side by side (docs/upstream-parity.md M1, decision D1). Every image is built as a
# compare build (BUILD_VARIANT=compare: the memory report of deploy/zephyr-common/memory_report.conf on,
# so both sides print their heap peak and every thread's stack the same way, step M3), then
# each round boots every image once, in the images' order on odd rounds and the reverse on even ones,
# so a drift of the bench over the run falls on both sides alike. A boot is: the flash written and read
# back, the router and the console, the reset, the READY line, a capture of the session's datagrams
# at the host's wire around the host's GETs, and the stack line the firmware prints when it moves.
# The verdict is scripts/lib/kit_compare.py's, against the first image named.
compare() {
    local boots=6 keys=() key
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --boots)
                [[ "${2:-}" =~ ^[1-9][0-9]*$ ]] || { bad compare "--boots takes a count"; return 1; }
                boots="$2"
                shift 2
                ;;
            *) keys+=("$1"); shift ;;
        esac
    done
    if [[ "${#keys[@]}" -lt 2 ]]; then
        bad compare "name two images or more: the first is the reference"
        return 1
    fi
    for key in "${keys[@]}"; do
        image_spec "$key" || { bad compare "$key is not an image of this lane (scripts/kit-lane.sh list)"; return 1; }
        [[ "$KIND" == answer ]] || { bad compare "$key does not answer the host's GETs, which is what is compared"; return 1; }
    done
    preflight "" || return 1
    for key in "${keys[@]}"; do
        BUILD_VARIANT=compare build "$key" || return 1
    done
    take_kit compare || return 1
    local run_dir="$LANE_HOME/compare/$CLOCK_TAG" round order built i
    mkdir -p "$run_dir"
    {
        echo "images: ${keys[*]}"
        echo "boots:  $boots"
        echo "router: $(router_version)"
        echo "tree:   $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo 'not a git checkout (a copy of a tree)')"
        echo "date:   $(date '+%F %T %Z')"
    } >"$run_dir/record.txt"
    : >"$run_dir/manifest.tsv"
    for ((round = 1; round <= boots; round++)); do
        order=("${keys[@]}")
        if ((round % 2 == 0)); then
            order=()
            for ((i = ${#keys[@]} - 1; i >= 0; i--)); do
                order+=("${keys[i]}")
            done
        fi
        for key in "${order[@]}"; do
            image_spec "$key"
            built="$(cat "$LANE_HOME/last-out-compare-$key")"
            OUT="$run_dir/$key-r$round"
            mkdir -p "$OUT"
            cp "$built/elf.path" "$built/m7.sha256" "$OUT/"
            compare_boot "$key" "$built/m7.bin" "$round" || return 1
            printf '%s\t%s\t%s\n' "$round" "$key" "$key-r$round" >>"$run_dir/manifest.tsv"
        done
    done
    if python3 -I "$ROOT/scripts/lib/kit_compare.py" --run "$run_dir" --ref "${keys[0]}" >"$run_dir/verdict.txt" 2>&1; then
        ok compare "the run was read ($run_dir/verdict.txt):"
        sed 's/^/    /' "$run_dir/verdict.txt"
    else
        bad compare "the run could not be read: $(head -n 3 "$run_dir/verdict.txt" | tr '\n' ' ')"
    fi
}

# The capture runs as root, so this user's `kill` in stop_all cannot end it; sudo hands the signal it is
# sent to tcpdump, which then writes out what it holds. A capture left running would refuse the next
# flash (flash_region), so every way out of a boot ends it.
CAPTURE_PID=""
stop_capture() {
    if [[ -n "$CAPTURE_PID" ]]; then
        sudo -n kill -INT "$CAPTURE_PID" 2>/dev/null
        wait "$CAPTURE_PID" 2>/dev/null
        CAPTURE_PID=""
    fi
}

end_boot() {
    stop_capture
    stop_all
    trap - EXIT
}

compare_boot() {
    local key="$1" bin="$2" tag="$1 (round $3)"
    flash_region "$bin" "$(cat "$OUT/m7.sha256")" "$tag" || return 1
    PIDS=()
    ADDR_ADDED=""
    trap end_boot EXIT
    start_and_reset "$key" || { end_boot; return 1; }
    local node_id
    node_id="$(ready_node_id)"
    # shellcheck disable=SC2024  # the capture is written as this user, into the boot's own directory
    sudo -n tcpdump -i "$KIT_IFACE" -n -tt -l -q "udp port 7447" >"$OUT/cap.txt" 2>"$OUT/cap.err" </dev/null &
    CAPTURE_PID=$!
    sleep 1
    if python3 -I "$ROOT/scripts/lib/kit_rest_probe.py" "$REST_PORT" "$node_id" "$OUT/rest.json" 2000 >"$OUT/probe.log" 2>&1; then
        ok "$tag" "the host asked the two documents 2,000 times each"
    else
        bad "$tag" "the image never answered through the router ($OUT/probe.log)"
        end_boot
        return 1
    fi
    sleep 1
    stop_capture
    # The firmware prints its stack high-water mark when it moves; let the last line come.
    sleep 12
    end_boot
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
print(" ".join(sorted(i.key for i in g.IMAGES if i.key.startswith("zephyr-client-"))))
PY
)"
    local mine
    mine="$(printf '%s\n' "${IMAGES[@]}" | sort | tr '\n' ' ' | sed 's/ $//')"
    if [[ "$mine" == "$population" ]]; then
        ok selftest "the lane's images are the stack gate's zephyr-client images ($mine)"
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
# The table's own rows: the population is what the table must hold, not what it holds.
sys.exit(0 if sys.argv[2] in r.read_table().get("images", {}) else 1)
PY
        then
            ok selftest "$key has a row in the resource budget"
        else
            bad selftest "$key has no row in the resource budget: a run of it would be held to nothing"
        fi
        if [[ "$KIND" == verify ]]; then
            if grep -q "tls/[0-9.]*:$TLS_PORT" "$ROOT/deploy/zephyr-admin-node/overlays/t2g_client_tls.conf"; then
                ok selftest "$key dials the port its router is given ($TLS_PORT)"
            else
                bad selftest "$key's overlay does not dial tls/ on port $TLS_PORT, where its router listens"
            fi
        fi
    done
    for key in "${COMPARE_IMAGES[@]}"; do
        if ! image_spec "$key" || [[ "$KIND" != answer ]]; then
            bad selftest "$key is listed as a compare image and does not answer"
            continue
        fi
        IFS=';' read -ra files <<<"$OVERLAYS"
        for overlay in "${files[@]}"; do
            [[ -f "$ROOT/deploy/$APP/$overlay" ]] || bad selftest "$key names $overlay, which is not in deploy/$APP"
        done
        # The tag the lane waits for and takes the node's key id from must be one the image prints.
        if grep -rqF "$READY_TAG {}" "$ROOT/deploy/$APP/rust/src" 2>/dev/null \
            || grep -qF "$READY_TAG %s" "$ROOT/deploy/$APP/src/main.c" 2>/dev/null; then
            ok selftest "$key is a compare image of deploy/$APP that prints '$READY_TAG <id>'"
        else
            bad selftest "$key waits for '$READY_TAG', which deploy/$APP never prints with an id"
        fi
        if is_compare_image "$key" && [[ " ${IMAGES[*]} " == *" $key "* ]]; then
            bad selftest "$key is both a compare image and a gated one"
        fi
    done
    for key in "${ADMIN_IMAGES[@]}"; do
        if ! image_spec "$key" || [[ "$KIND" != admin ]]; then
            bad selftest "$key is listed as an admin image and the table does not say so"
            continue
        fi
        IFS=';' read -ra files <<<"$OVERLAYS"
        for overlay in "${files[@]}"; do
            [[ -f "$ROOT/deploy/$APP/$overlay" ]] || bad selftest "$key names $overlay, which is not in deploy/$APP"
        done
        if grep -rqF "$READY_TAG {} {}" "$ROOT/deploy/$APP/rust/src"; then
            ok selftest "$key is an admin image of deploy/$APP that prints '$READY_TAG <zid> <locator>'"
        else
            bad selftest "$key waits for '$READY_TAG', which deploy/$APP never prints with a zid and a locator"
        fi
    done
    for key in "${MEASURE_IMAGES[@]}"; do
        if ! image_spec "$key" || [[ "$KIND" != measure || -z "${DONE_TAG:-}" ]]; then
            bad selftest "$key is listed as a measure image and the table does not say how it ends"
        elif [[ ! -f "$ROOT/deploy/$APP/CMakeLists.txt" ]]; then
            bad selftest "$key builds deploy/$APP, which is not an application"
        elif ! grep -q "$DONE_TAG done" "$ROOT/deploy/$APP/src/main.c"; then
            bad selftest "$key waits for '$DONE_TAG done', which deploy/$APP never prints"
        else
            ok selftest "$key is a measure image of deploy/$APP that ends on '$DONE_TAG done'"
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
    compare) compare "$@" ;;
    build-responder) build_responder ;;
    list) printf '%s\n' "${IMAGES[@]}" "${ADMIN_IMAGES[@]}" "${MEASURE_IMAGES[@]}" "${COMPARE_IMAGES[@]}" ;;
    images) printf '%s\n' "${IMAGES[@]}" "${ADMIN_IMAGES[@]}" ;; # the images `build` holds to their rows with no kit
    --selftest) selftest ;;
    *)
        sed -n '12,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
        exit 64
        ;;
esac
status=$?
if [[ "$fails" -ne 0 ]]; then
    say "$fails step(s) failed" >&2
    exit 1
fi
exit "$status"

#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The passive hold of the fixed-memory profile witnessed on the Zephyr image that ships it, under
# QEMU (decision D18 of docs/session-lifecycle-intent.md): the scenario of
# crates/wz-integration-tests/tests/it/files/wz_declared_commander_zenohd_target_matrix.rs against
# deploy/zephyr-admin-node built for mps2/an385 with a commander compiled in.
#
#   scripts/zephyr-passive-witness.sh keys <dir>    make the commander's key in <dir>, and the overlay
#                                                   that lists the zid it names for open, close, status
#   scripts/zephyr-passive-witness.sh build <dir>   west build the image with that overlay, <dir>/build
#   scripts/zephyr-passive-witness.sh run <dir>     run the matrix's QEMU leg against that image
#   scripts/zephyr-passive-witness.sh all <dir>     the three in order
#
# The image's commanders are compiled in (CONFIG_WZ_COMMANDERS_*, read when the image is compiled),
# so the key exists before the image does, and the leg is handed the same key back: the router that
# dials the image holds it, and the image proves its zid on that link. The zid is the one
# scripts/lib/wz_node.py --zid-of prints, which is the tool the leg reads the key's zid with, so the
# list compiled in and the zid the leg expects are derived once. scripts/kit-lane.sh makes the kit's
# passive commander with `keys` too.
#
# Layer Qza runs `keys` and builds and runs the leg with run-ci's own west and test helpers; `build`
# and `run` are the same steps for a person, with the Zephyr workspace of WZ_ZEPHYR_VENV and
# WZ_ZEPHYR_BASE (default ~/zephyrproject), and the zenohd and examples the leg finds as every zenohd
# leg does (WZ_ZENOHD_BIN, WZ_ZENOH_CORE_EXAMPLES_DIR).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX_TEST="files::wz_declared_commander_zenohd_target_matrix::zenohd_zephyr_image_passive_intent_holds_the_session_a_stock_client_opens_and_not_a_claim_of_its_zid"

usage() {
    sed -n '10,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 64
}

# The directory, made and named by its physical path: the overlay is handed to CMake by that path.
absolute_dir() {
    mkdir -p "$1" && (cd "$1" && pwd -P)
}

keys() {
    local dir zid
    dir="$(absolute_dir "$1")" || return 1
    if ! openssl ecparam -name prime256v1 -genkey -noout -out "$dir/commander.key" 2>"$dir/keys.log" ||
        ! openssl req -new -x509 -key "$dir/commander.key" -subj /CN=wz-passive-commander -days 3650 \
            -out "$dir/commander.pem" 2>>"$dir/keys.log"; then
        echo "zephyr-passive-witness: the commander's key could not be made ($dir/keys.log)" >&2
        return 1
    fi
    chmod 600 "$dir/commander.key"
    if ! zid="$(python3 "$ROOT/scripts/lib/wz_node.py" --zid-of "$dir/commander.pem" 2>>"$dir/keys.log")" ||
        ! [[ "$zid" =~ ^[0-9a-f]+$ ]]; then
        echo "zephyr-passive-witness: no zid for the commander's key ($dir/keys.log)" >&2
        return 1
    fi
    printf '%s\n' "$zid" >"$dir/commander.zid"
    {
        printf 'CONFIG_WZ_COMMANDERS_OPEN="%s"\n' "$zid"
        printf 'CONFIG_WZ_COMMANDERS_CLOSE="%s"\n' "$zid"
        printf 'CONFIG_WZ_COMMANDERS_STATUS="%s"\n' "$zid"
    } >"$dir/commanders.conf"
    echo "zephyr-passive-witness: the commander's key names zid $zid, listed for open, close and status ($dir/commanders.conf)"
}

build() {
    local dir venv base
    dir="$(absolute_dir "$1")" || return 1
    if [[ ! -f "$dir/commanders.conf" ]]; then
        echo "zephyr-passive-witness: no commanders in $dir: run \`keys $dir\` first" >&2
        return 1
    fi
    venv="${WZ_ZEPHYR_VENV:-$HOME/zephyrproject/.venv}"
    base="${WZ_ZEPHYR_BASE:-$HOME/zephyrproject/zephyr}"
    # The physical path, never one through a link (the reason is written at `_qz_toolchain` in
    # scripts/run-ci.sh).
    base="$(cd "$base" && pwd -P)" || return 1
    (
        # shellcheck source=/dev/null  # created by scripts/provision-zephyr.sh
        . "$venv/bin/activate" || exit 1
        export ZEPHYR_BASE="$base"
        cd "$ROOT" &&
            west build -b mps2/an385 -d "$dir/build" deploy/zephyr-admin-node -- \
                -DEXTRA_CONF_FILE="overlays/qemu_admin_fixed_tls.conf;$dir/commanders.conf"
    ) >"$dir/build.log" 2>&1 || {
        echo "zephyr-passive-witness: the image did not build ($dir/build.log)" >&2
        return 1
    }
    echo "zephyr-passive-witness: built $dir/build/zephyr/zephyr.elf"
}

run() {
    local dir elf
    dir="$(absolute_dir "$1")" || return 1
    elf="$dir/build/zephyr/zephyr.elf"
    if [[ ! -f "$elf" ]]; then
        echo "zephyr-passive-witness: no image at $elf: run \`build $dir\` first" >&2
        return 1
    fi
    (
        cd "$ROOT/crates" &&
            WZ_ZEPHYR_PASSIVE_QEMU_ELF="$elf" \
                WZ_ZEPHYR_PASSIVE_COMMANDER_CERT="$dir/commander.pem" \
                WZ_ZEPHYR_PASSIVE_COMMANDER_KEY="$dir/commander.key" \
                cargo test -p wz-integration-tests --test it "$MATRIX_TEST" -- \
                --ignored --exact --test-threads=1
    ) >"$dir/run.log" 2>&1
    # A filter that matches nothing runs nothing and exits 0: the verdict is the count.
    if grep -q '^test result: ok\. 1 passed' "$dir/run.log"; then
        echo "zephyr-passive-witness: the passive hold held on the image under QEMU ($dir/run.log)"
        return 0
    fi
    echo "zephyr-passive-witness: the QEMU leg did not pass, or did not run ($dir/run.log)" >&2
    return 1
}

cmd="${1:-}"
dir="${2:-}"
[[ -n "$cmd" && -n "$dir" ]] || usage
case "$cmd" in
    keys) keys "$dir" ;;
    build) build "$dir" ;;
    run) run "$dir" ;;
    all) keys "$dir" && build "$dir" && run "$dir" ;;
    *) usage ;;
esac

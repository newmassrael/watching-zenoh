#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The application-plane oracle lane: wz's protected frames and replay answers held byte for
# byte, and verdict for verdict, against a deployed peer's OWN build, by exchanging them with
# it over the loopback, both ways. The peer's build lives outside this repository and is named
# by the environment; the repository holds only this lane, wz's party and the judge.
#
#   scripts/app-plane-oracle.sh             run the lane (NOT-MEASURED when the variables are unset)
#   scripts/app-plane-oracle.sh --selftest  the judge on synthetic transcripts, and nothing else
#
#   WZ_APP_PLANE_ORACLE_DIR      the CMake source directory of the deployment's party: a project
#                                that builds `app-plane-oracle-peer` at the top of its build
#                                directory, a program over the deployment's own layer that speaks
#                                the party contract of docs/app-plane-oracle.md
#   WZ_APP_PLANE_ORACLE_PROFILE  the lane file: the checks, each with the profile and values
#                                documents wz's party protects and judges by (same page)
#   WZ_APP_PLANE_ORACLE_CMAKE_ARGS  optional words added to the party project's configure (where
#                                the deployment's checkouts are, which toolchain); a word that sets
#                                one of the two bound variables below to another value is refused
#   WZ_APP_PLANE_ORACLE_SCRATCH  optional; where the builds and transcripts go (default under the
#                                artifact root, target/app-plane-oracle)
#
# The party project is configured OUT OF TREE into the scratch directory, with
#   -DWZ_ORACLE_PICO_INCLUDE=<pico headers of the wz library's arm>;<wz extension header dir>
#   -DWZ_ORACLE_PICO_LIBRARY=<the wz pico library it may link in place of zenoh-pico>
# so a deployment whose glue sits on zenoh-pico's API can run its own layer over wz's drop-in,
# and, after the caller's words, with the two variables bound to the lane file:
#   -DWZ_ORACLE_KEY_WIRE:STRING=<the key-wire form wz's party names keys in, on both sides>
#   -DWZ_ORACLE_KEY_IDS:FILEPATH=<a {"dictionary": [...]} file of the lane file's key ids>
# A fresh cache each run; a party that never reads either, or is configured with another value,
# is refused before any exchange, so a key wire the two parties do not share never shows up as
# a timeout.
#
# A LOCAL lane, opt-in by its variables: it needs a deployment's build, which no hosted runner
# has, so it is not a layer of scripts/run-ci.sh (every layer there is wired into the hosted
# workflow, scripts/lib/unwired_lane_lint.py). Linux only.
#
# Exit status: 0 PASS; 1 FAIL (a check disagreed, a party did not finish, or the judge's own
# selftest failed); 2 a lane file, a variable or the deployment's party's configure refused;
# 3 NOT-MEASURED (the variables are unset,
# or a side did not build, so nothing was exchanged). A NOT-MEASURED run has shown nothing.

set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 2
here="scripts/app-plane-oracle"

not_measured() {
    echo "app-plane-oracle: NOT-MEASURED, $*"
    exit 3
}

py="$(command -v python3 || true)"
if [ -z "$py" ]; then
    not_measured "no python3 on PATH to prepare and judge the checks"
fi

if [ "${1:-}" = "--selftest" ]; then
    "$py" "$here/oracle.py" --selftest
    exit $?
fi
if [ "$#" -ne 0 ]; then
    echo "usage: $0 [--selftest]" >&2
    exit 2
fi

# Products of this checkout, under the artifact root (scripts/lib/artifact-root.sh).
# shellcheck source=scripts/lib/artifact-root.sh
source "$root/scripts/lib/artifact-root.sh"
wz_artifact_root_init "$root" || exit 2
scratch="${WZ_APP_PLANE_ORACLE_SCRATCH:-$WZ_ARTIFACTS/target/app-plane-oracle}"
mkdir -p "$scratch" || exit 2

# The judge first: a lane whose judge fails its own fixtures grades nothing.
if ! "$py" "$here/oracle.py" --selftest > "$scratch/selftest.log" 2>&1; then
    echo "app-plane-oracle: the judge failed its selftest (see $scratch/selftest.log): FAIL"
    exit 1
fi
echo "app-plane-oracle: the judge passed its selftest"

party_dir="${WZ_APP_PLANE_ORACLE_DIR:-}"
lane_file="${WZ_APP_PLANE_ORACLE_PROFILE:-}"
if [ -z "$party_dir" ] || [ -z "$lane_file" ]; then
    not_measured "WZ_APP_PLANE_ORACLE_DIR and WZ_APP_PLANE_ORACLE_PROFILE are not both set; docs/app-plane-oracle.md says what they name"
fi
if [ ! -f "$party_dir/CMakeLists.txt" ]; then
    echo "app-plane-oracle: WZ_APP_PLANE_ORACLE_DIR=$party_dir holds no CMakeLists.txt" >&2
    exit 2
fi
if [ ! -f "$lane_file" ]; then
    echo "app-plane-oracle: WZ_APP_PLANE_ORACLE_PROFILE=$lane_file is not a file" >&2
    exit 2
fi

rm -rf "$scratch/runs" "$scratch/checks"
"$py" "$here/oracle.py" prepare "$lane_file" "$scratch"
rc=$?
if [ "$rc" -ne 0 ]; then
    exit 2
fi

# The caller's configure words are checked against the lane file's binding before anything is
# built; the lane's own words go after them.
peer_cmake_args=()
if [ -n "${WZ_APP_PLANE_ORACLE_CMAKE_ARGS:-}" ]; then
    read -r -a peer_cmake_args <<< "$WZ_APP_PLANE_ORACLE_CMAKE_ARGS"
fi
if ! "$py" "$here/oracle.py" party-words "$scratch" ${peer_cmake_args[@]+"${peer_cmake_args[@]}"}; then
    exit 2
fi
bound_args=()
while IFS= read -r line; do
    [ -n "$line" ] && bound_args+=("$line")
done < "$scratch/party-words"

# ── wz's party, once per reply shape the checks need ─────────────────────────────────────

features="e2e-sender,e2e-receiver,segment-sender,replay-cache"
extra_features="$(tr -d '[:space:]' < "$scratch/wz-features")"
if [ -n "$extra_features" ]; then
    features="$features,$extra_features"
fi
build_env=()
while IFS= read -r line; do
    [ -n "$line" ] && build_env+=("$line")
done < "$scratch/wz-build-env"
connect_mode="$(tr -d '[:space:]' < "$scratch/connect-mode")"

lib_dir="$WZ_ARTIFACTS/crates/target/debug"
build_wz() {
    local variant="$1" out="$scratch/wz-$1" shape
    case "$variant" in
        segmented) shape=segmented ;;
        *) shape=frame-per-sample ;;
    esac
    mkdir -p "$out" || return 1
    # The library is copied out once built: the next variant's build replaces the one in the
    # target directory, and a party runs against the copy of its own variant.
    env ${build_env[@]+"${build_env[@]}"} WZ_POLICY_REPLAY_REPLY_SHAPE="$shape" \
        PICO_C_PROGRAM_OUT="$out/wz_party" \
        bash scripts/pico-c-program.sh "$here/wz_party.c" "app-plane oracle party ($variant)" "$features" \
        > "$out/build.log" 2>&1 || return 1
    cp "$lib_dir/libwz_capi_pico.so" "$out/" || return 1
}

variants="$(cut -f3 "$scratch/checks.tsv" | sort -u)"
first_variant=""
for variant in $variants; do
    if ! build_wz "$variant"; then
        not_measured "wz's party did not build for the $variant shape (see $scratch/wz-$variant/build.log)"
    fi
    [ -z "$first_variant" ] && first_variant="$variant"
    echo "app-plane-oracle: wz's party built for the $variant shape"
done

# ── the deployment's party ───────────────────────────────────────────────────────────────

if ! command -v cmake > /dev/null 2>&1; then
    not_measured "no cmake on PATH to build the deployment's party"
fi
peer_build="$scratch/peer-build"
# No cached word of an earlier configure survives, and CMake names every word given here that
# the project never reads, which the read-back refuses.
rm -f "$peer_build/CMakeCache.txt"
if ! cmake -S "$party_dir" -B "$peer_build" \
    -DWZ_ORACLE_PICO_INCLUDE="$scratch/wz-$first_variant/pico-arm-include-wz_party;$root/crates/wz-capi-core/include" \
    -DWZ_ORACLE_PICO_LIBRARY="$scratch/wz-$first_variant/libwz_capi_pico.so" \
    ${peer_cmake_args[@]+"${peer_cmake_args[@]}"} ${bound_args[@]+"${bound_args[@]}"} \
    > "$scratch/peer-configure.log" 2>&1; then
    not_measured "the deployment's party did not configure (see $scratch/peer-configure.log)"
fi
if ! "$py" "$here/oracle.py" party-readback "$scratch" "$peer_build" "$scratch/peer-configure.log"; then
    exit 2
fi
if ! cmake --build "$peer_build" --parallel > "$scratch/peer-build.log" 2>&1; then
    not_measured "the deployment's party did not build (see $scratch/peer-build.log)"
fi
peer_exe="$peer_build/app-plane-oracle-peer"
if [ ! -x "$peer_exe" ]; then
    not_measured "the deployment's project built no $peer_exe"
fi
echo "app-plane-oracle: the deployment's party built"

# ── the exchanges ────────────────────────────────────────────────────────────────────────

free_port() {
    "$py" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

# Wait until a party's transcript holds the line, while the party runs; 1 when it ended or
# 30 seconds passed first.
wait_line() {
    local file="$1" line="$2" pid="$3" waited=0
    while [ "$waited" -lt 300 ]; do
        if [ -f "$file" ] && grep -qx "$line" "$file"; then
            return 0
        fi
        if ! kill -0 "$pid" 2> /dev/null; then
            return 1
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    return 1
}

# party <who> <variant> <args...>: one party, wz's against its variant's library copy.
party() {
    local who="$1" variant="$2"
    shift 2
    if [ "$who" = wz ]; then
        LD_LIBRARY_PATH="$scratch/wz-$variant${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
            timeout 120 "$scratch/wz-$variant/wz_party" "$@"
    else
        timeout 120 "$peer_exe" "$@"
    fi
}

# One direction of one check: the sending side (sender or cache) and the receiving side
# (receiver or asker), each with its own copy of the check directory.
exchange() {
    local name="$1" kind="$2" variant="$3" direction="$4"
    local run="$scratch/runs/$name/$direction" sender receiver send_role receive_role
    if [ "$direction" = wz-sends ]; then
        sender=wz
        receiver=peer
    else
        sender=peer
        receiver=wz
    fi
    if [ "$kind" = e2e ]; then
        send_role=send
        receive_role=receive
    else
        send_role=serve
        receive_role=ask
    fi
    mkdir -p "$run/check" || return 1
    cp -R "$scratch/checks/$name/." "$run/check/" || return 1
    local locator
    locator="tcp/127.0.0.1:$(free_port)"

    local listen_pid connect_pid
    if [ "$kind" = e2e ]; then
        # The receiver listens; the sender dials, probes until the lane has seen the receiver
        # hear a probe, then sends its plan.
        party "$receiver" "$variant" "$receive_role" "$run/check" listen "$locator" \
            > "$run/receive.out" 2> "$run/receive.err" &
        listen_pid=$!
        wait_line "$run/receive.out" ready "$listen_pid" || true
        party "$sender" "$variant" "$send_role" "$run/check" connect "$locator" "$connect_mode" \
            > "$run/send.out" 2> "$run/send.err" &
        connect_pid=$!
        if wait_line "$run/receive.out" probe "$listen_pid"; then
            touch "$run/check/go"
        fi
        wait "$listen_pid"
        echo "$?" > "$run/receive.rc"
        touch "$run/check/stop"
        wait "$connect_pid"
        echo "$?" > "$run/send.rc"
    else
        # The cache listens and serves; the asker dials and asks as the queryable appears.
        party "$sender" "$variant" "$send_role" "$run/check" listen "$locator" \
            > "$run/send.out" 2> "$run/send.err" &
        listen_pid=$!
        wait_line "$run/send.out" ready "$listen_pid" || true
        party "$receiver" "$variant" "$receive_role" "$run/check" connect "$locator" "$connect_mode" \
            > "$run/receive.out" 2> "$run/receive.err" &
        connect_pid=$!
        wait "$connect_pid"
        echo "$?" > "$run/receive.rc"
        touch "$run/check/stop"
        wait "$listen_pid"
        echo "$?" > "$run/send.rc"
    fi
    echo "app-plane-oracle: $name $direction exchanged (send rc $(cat "$run/send.rc"), receive rc $(cat "$run/receive.rc"))"
}

while IFS=$'\t' read -r name kind variant; do
    [ -n "$name" ] || continue
    exchange "$name" "$kind" "$variant" wz-sends
    exchange "$name" "$kind" "$variant" peer-sends
done < "$scratch/checks.tsv"

"$py" "$here/oracle.py" judge "$scratch"
exit $?

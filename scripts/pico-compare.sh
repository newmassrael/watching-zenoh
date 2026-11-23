#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Same-condition comparison of the wz zenoh-pico C ABI library with zenoh-pico itself, on THIS host.
#
#   scripts/pico-compare.sh rtt [reps]        round trip of the upstream z_ping / z_pong examples
#   scripts/pico-compare.sh thr [reps] [sizes...]
#                                             delivered messages per second of the upstream z_pub_thr / z_sub_thr
#                                             examples, send side and receive side, per payload size
#   scripts/pico-compare.sh nodrop [reps] [sizes]
#                                             the highest rate OFFERED at which nothing is lost (RFC 2544), with
#                                             scripts/host-bench's paced publisher and counting subscriber, which
#                                             are built against each library from the same source: the control
#                                             (pico on both sides) has a number where `thr` has none
#   scripts/pico-compare.sh nodrop-c [reps] [sizes]
#                                             the same search for the zenoh-c family: the benches built against the
#                                             pinned zenoh-c release (variant P) and against wz-capi-c (variant W),
#                                             which is provisioned and built under target/ by the mode itself
#   scripts/pico-compare.sh parity <pico|c|rust> [boots] [sizes]
#                                             the host side of the parity matrix (docs/upstream-parity.md section 5b):
#                                             upstream's own example programs (z_put z_sub z_get z_queryable z_pub_thr
#                                             z_sub_thr z_ping z_pong) built from one source against the original, which
#                                             this mode builds from its pinned source with its default switches, and
#                                             against the wz preset configs/<original>_defconfig; run in alternating
#                                             boots (default 24 of each) by scripts/host-bench/parity.py, and judged
#                                             cell by cell by scripts/lib/kit_compare.py, whose `--format rows` output
#                                             is what deploy/upstream_parity.json holds. The run is left under
#                                             target/pico-compare/parity-runs/host-<family>-<time>/ (its verdict.txt,
#                                             rows.json and record.txt beside the boots)
#   scripts/pico-compare.sh fanin [rounds] [publishers] [size] [hz] [seconds] [block|drop] [pairs]
#                                             several publishers of large samples to one subscriber (defaults 4
#                                             rounds of each arm, 3 publishers of 4,000,000 bytes at 20 Hz for 10 s,
#                                             congestion control block): one program (conformance/host-bench/
#                                             wz_fanin.rs) built over upstream's zenoh and with the family patched in,
#                                             as `parity rust` builds upstream's examples, run by
#                                             scripts/host-bench/fanin.py in rounds that alternate the arms over TCP
#                                             loopback; a round is a DEFECT of its arm when a sample arrives corrupt,
#                                             duplicated, reordered or foreign, or, under block, does not arrive.
#                                             Left under target/pico-compare/fanin-runs/host-<time>/ (report.txt,
#                                             rounds.jsonl, record.txt); exit 0 clean, 1 a defect, 2 not run
#   scripts/pico-compare.sh perf [reps] [sizes]
#                                             the performance matrix of the pico ABI (docs/pico-perf-matrix.md):
#                                             round trip p50/p90/p99, throughput in messages and bytes a second,
#                                             CPU and peak RSS, per transport (tcp, udp, multicast, a transport
#                                             the program supplies) and with batching off and on, of one program
#                                             (scripts/host-bench/perf_probe.c) built against wz-capi-pico and
#                                             against zenoh-pico built as the same build (the capability cost
#                                             gate's reference); run by scripts/host-bench/perf_matrix.py, left
#                                             under target/pico-compare/perf-runs/host-<time>/ (perf.json,
#                                             report.txt, cells.jsonl), and judged by its gate against
#                                             deploy/pico_perf_ceiling.json. With WZ_PERF_EXTERNAL_LIB and
#                                             WZ_PERF_EXTERNAL_INCLUDE set, a third arm: the same program
#                                             against that external library of the pico API, judged against
#                                             the table WZ_PERF_EXTERNAL_TABLE names outside the repository
#   scripts/pico-compare.sh batch [sizes] [count]
#                                             the unicast batch size on the wire: zenoh-pico built once per size
#                                             (BATCH_UNICAST_SIZE, default sizes 512,2048,8192) against one
#                                             wz-capi-pico build with `config-document` whose sessions are handed
#                                             each size by their configuration document (`wz/limits`); one program
#                                             (scripts/host-bench/batch_probe.c) puts [count] (1200) samples in a
#                                             batching window through a relay that reads each batch's length off the
#                                             stream; run by scripts/host-bench/batch_control.py, left under
#                                             target/pico-compare/batch-runs/host-<time>/ (batch.json, report.txt),
#                                             exit 0 when every batch of every cell stayed within its size and
#                                             reached it, 1 when one did not, 2 when a cell was not measured
#
# Both sides of every pair are built from the SAME example source: once against the vendored zenoh-pico
# library and once against `libwz_capi_pico`, in place of it. A number printed here is therefore the
# library's, with the example, the host, the pinning and the transport held equal. Peer mode over TCP
# loopback.
#
# Run it on a build host through `bx --host <host> -- bash scripts/pico-compare.sh ...`: the libraries are
# built in that tree, and what the script prints is read from bx's log. A hybrid-CPU host needs the
# pinning stated, because the default layout is the one measured on a 22-thread hybrid host (a physical
# core is a pair of threads; each process gets one pair, never one thread: a process pinned to a single
# CPU measured a 2 ms scheduler tick in BOTH libraries).
#
# Environment: PICO_CMP_PING_CPUS / PICO_CMP_PONG_CPUS / PICO_CMP_PUB_CPUS / PICO_CMP_SUB_CPUS (defaults
# 6,7 / 8,9 / 6,7 / 10,11), PICO_CMP_WZ_ENV (extra `VAR=value` words put in front of every wz process,
# for example WZ_CAPI_RX_BUSY_POLL_US=10), PICO_CMP_NO_BUILD=1 (use the libraries already built), PICO_CMP_ENGINE
# (`tokio` or `coop`: the engine the wz library is built on, to compare the two; unset, the one the package for a
# host ships on, which its profile configs/profiles/host-peer-ext.conf chooses). `rtt`, `thr`, `nodrop`, `profile`,
# `tids`, `perf` and `batch` build the wz library on that engine and print it with their readings; `parity`
# builds each original's preset and `nodrop-c` the zenoh-c family, which have one engine each.
# `parity` pins the client side of a pair (z_ping, z_pub_thr, z_put, z_get) to PICO_CMP_CLIENT_CPUS and the
# server side to PICO_CMP_SERVER_CPUS (defaults 4-7 and 8-11: two physical cores a side on the 22-thread
# hybrid bench host, because zenoh-c and zenoh run several threads a process and one SMT pair would bind
# them where it binds pico's one); PICO_CMP_PINGS (default 20000), PICO_CMP_WARMUP_S (3) and
# PICO_CMP_WINDOW_S (10) set the round trips and the throughput window.
#
# What it does NOT show: anything about an MCU, and the cost in CPU of a lower round trip: read the
# per-process CPU separately before claiming a latency win.

set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 2

ping_cpus="${PICO_CMP_PING_CPUS:-6,7}"
pong_cpus="${PICO_CMP_PONG_CPUS:-8,9}"
pub_cpus="${PICO_CMP_PUB_CPUS:-6,7}"
sub_cpus="${PICO_CMP_SUB_CPUS:-10,11}"
wz_env="${PICO_CMP_WZ_ENV:-}"

# Products of this checkout, under the artifact root (scripts/lib/artifact-root.sh).
# shellcheck source=scripts/lib/artifact-root.sh
source "$root/scripts/lib/artifact-root.sh"
wz_artifact_root_init "$root" || exit 2

examples="$root/vendor/zenoh-pico/examples/unix/c11"
pico_lib="$WZ_ARTIFACTS/target/zenoh-pico-build/lib"
wz_lib="$WZ_ARTIFACTS/crates/target/release"
out="$WZ_ARTIFACTS/target/pico-compare"
mkdir -p "$out/bin"

# The engine the wz library is built on: one answer for every build of it below (`wz_config.py --bench-engine`,
# which reads the package's profile unless PICO_CMP_ENGINE names one), whose cargo words come from the same tool
# (`--bench-cargo-args`), so no mode names an engine of its own. A build leaves the engine in a stamp beside what it
# built; a run with PICO_CMP_NO_BUILD=1 reads the stamp and refuses a PICO_CMP_ENGINE that names another.
wz_engine=""
resolve_wz_engine() {
    if [ -z "${PICO_CMP_ENGINE:-}" ]; then
        bash scripts/provision-kconfiglib.sh >"$out/build-kconfiglib.log" 2>&1 \
            || { echo "pico-compare: NOT-MEASURED, kconfiglib did not install (see $out/build-kconfiglib.log)"; exit 2; }
    fi
    wz_engine="$(python3 -I scripts/lib/wz_config.py --bench-engine ${PICO_CMP_ENGINE:+"$PICO_CMP_ENGINE"})" \
        || { echo "pico-compare: NOT-MEASURED, the engine of the wz library did not resolve"; exit 2; }
}

# wz_cargo_args <features>: the cargo words of the wz library on $wz_engine with <features> (a comma list, empty for
# none) over its default capabilities.
wz_cargo_args() {
    python3 -I scripts/lib/wz_config.py --bench-cargo-args "$wz_engine" ${1:+"$1"}
}

# stamped_engine <engine>: the engine a build of the library found recorded, held against PICO_CMP_ENGINE.
stamped_engine() {
    wz_engine="${1:-unknown}"
    if [ -n "${PICO_CMP_ENGINE:-}" ] && [ "$PICO_CMP_ENGINE" != "$wz_engine" ]; then
        echo "pico-compare: PICO_CMP_ENGINE=$PICO_CMP_ENGINE, and the library PICO_CMP_NO_BUILD=1 finds is built on the $wz_engine engine" >&2
        exit 2
    fi
}

if [ "${PICO_CMP_NO_BUILD:-0}" != 1 ] && [ "${1:-}" != nodrop-c ] && [ "${1:-}" != parity ] && [ "${1:-}" != perf ] \
    && [ "${1:-}" != batch ] && [ "${1:-}" != fanin ]; then
    resolve_wz_engine
    bash scripts/build-zenoh-pico-cli.sh >"$out/build-pico.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, the pico library did not build (see $out/build-pico.log)"; exit 2; }
    wz_args="$(wz_cargo_args "")" \
        || { echo "pico-compare: NOT-MEASURED, no cargo words for the $wz_engine engine"; exit 2; }
    rm -f "$out/wz-engine"
    # shellcheck disable=SC2086 # the cargo words are words on purpose
    (cd crates && cargo build --release -p wz-capi-pico $wz_args) >"$out/build-wz.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, the wz library did not build (see $out/build-wz.log)"; exit 2; }
    echo "$wz_engine" >"$out/wz-engine"
fi
case "${1:-}" in
    rtt | thr | nodrop | profile | tids)
        [ -n "$wz_engine" ] || stamped_engine "$(cat "$out/wz-engine" 2>/dev/null)"
        ;;
esac

include=(
    -I"$WZ_ARTIFACTS/target/zenoh-pico-build/zenohpico/include"
    -I"$root/vendor/zenoh-pico/include"
    -I"$WZ_ARTIFACTS/target/mbedtls/include"
)

# build_example <example> <P|W>
build_example() {
    local example="$1" variant="$2" lib name
    if [ "$variant" = P ]; then
        lib="$pico_lib"
        name=zenohpico
    else
        lib="$wz_lib"
        name=wz_capi_pico
    fi
    cc -O2 "$examples/$example.c" -DZENOH_LINUX "${include[@]}" -o "$out/bin/${example}_$variant" \
        -L"$lib" "-l$name" "-Wl,-rpath,$lib" -lpthread 2>"$out/build-${example}_$variant.log" \
        || { echo "pico-compare: NOT-MEASURED, $example against $variant did not build"; exit 2; }
}

# build_bench <name> <P|W>: one of scripts/host-bench's programs (not an upstream example), against the library
# of the variant, with the same flags as the examples.
build_bench() {
    local name="$1" variant="$2" lib libname
    if [ "$variant" = P ]; then
        lib="$pico_lib"
        libname=zenohpico
    else
        lib="$wz_lib"
        libname=wz_capi_pico
    fi
    cc -O2 "$root/scripts/host-bench/$name.c" -DZENOH_LINUX "${include[@]}" -o "$out/bin/${name}_$variant" \
        -L"$lib" "-l$libname" "-Wl,-rpath,$lib" -lpthread 2>"$out/build-${name}_$variant.log" \
        || { echo "pico-compare: NOT-MEASURED, $name against $variant did not build (see $out/build-${name}_$variant.log)"; exit 2; }
}

# build_zenoh_c_family: the zenoh-c counterpart of the pico family, for `nodrop-c`. Variant P is the zenoh-c
# release (its headers and libzenohc.so at the pinned version), variant W the wz library that stands in for it
# (wz-capi-c built for the features of that release's zenoh_configure.h, the way Layer C1cc builds it). The
# release is install-zenoh-c.sh's, at that installer's own default prefix: it is the published archive's arm,
# which Layer C1cc already reads there, and a second install of one arm elsewhere is what
# scripts/lib/zenoh_c_oracle_arms.py refuses. The benches are the same source (scripts/host-bench, BENCH_ZENOHC)
# built against each, into $out/bin-c under the names the search program looks for.
build_zenoh_c_family() {
    local prefix="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"
    local ref="${WZ_ZENOH_C_REF:-$HOME/zenoh-c-ref}"
    local wz_c_lib="$WZ_ARTIFACTS/crates/target/release" args bench variant lib libname
    mkdir -p "$out/bin-c"
    WZ_ZENOH_C_PREFIX="$prefix" WZ_ZENOH_C_REF="$ref" bash scripts/install-zenoh-c.sh >"$out/build-zenoh-c.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, the zenoh-c release did not install (see $out/build-zenoh-c.log)"; exit 2; }
    bash scripts/provision-kconfiglib.sh >"$out/build-kconfiglib.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, kconfiglib did not install (see $out/build-kconfiglib.log)"; exit 2; }
    args="$(python3 -I scripts/lib/wz_config.py --drop-in-features c "$prefix/include/zenoh_configure.h")" \
        || { echo "pico-compare: NOT-MEASURED, no drop-in features for $prefix/include/zenoh_configure.h"; exit 2; }
    # shellcheck disable=SC2086 # the cargo arguments are words on purpose
    (cd crates && cargo build --release -p wz-capi-c $args) >"$out/build-wz-c.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, wz-capi-c did not build (see $out/build-wz-c.log)"; exit 2; }
    for bench in paced_pub count_sub; do
        for variant in P W; do
            if [ "$variant" = P ]; then
                lib="$prefix/lib"
                libname=zenohc
            else
                lib="$wz_c_lib"
                libname=wz_capi_c
            fi
            cc -O2 -DBENCH_ZENOHC "$root/scripts/host-bench/$bench.c" -I"$prefix/include" -o "$out/bin-c/${bench}_$variant" \
                -L"$lib" "-l$libname" "-Wl,-rpath,$lib" -lpthread 2>"$out/build-${bench}_c_$variant.log" \
                || { echo "pico-compare: NOT-MEASURED, $bench against $variant (zenoh-c family) did not build (see $out/build-${bench}_c_$variant.log)"; exit 2; }
        done
    done
}

case "${1:-}" in
    parity | perf | batch | fanin)
        # each builds its own arms (parity, perf, batch and fanin below)
        ;;
    nodrop-c)
        build_zenoh_c_family
        ;;
    nodrop|profile|tids)
        for bench in paced_pub count_sub; do
            for variant in P W; do
                build_bench "$bench" "$variant"
            done
        done
        ;;
    *)
        for example in z_ping z_pong z_pub_thr z_sub_thr; do
            for variant in P W; do
                build_example "$example" "$variant"
            done
        done
        ;;
esac

# compose <variant> <cpus> <command...>: the pinned command line, in CMD, with the wz environment
# words in front of a wz process. A line `"${CMD[@]}" &` is then the process itself, which `kill`
# reaches; a function that ran it would leave a subshell in between.
CMD=()
compose() {
    local variant="$1" cpus="$2" words=()
    shift 2
    CMD=()
    if [ "$variant" = W ] && [ -n "$wz_env" ]; then
        read -r -a words <<<"$wz_env"
        CMD+=(env "${words[@]}")
    fi
    CMD+=(taskset -c "$cpus" "$@")
}

# median <file> <skip>: the median of the numbers in a file, leaving out the first <skip>.
median() {
    python3 -I - "$1" "$2" <<'PY'
import statistics, sys
values = []
for word in open(sys.argv[1]).read().split():
    try:
        values.append(float(word))
    except ValueError:
        pass
values = values[int(sys.argv[2]):]
print(f"{statistics.median(values):.1f} n={len(values)}" if values else "no samples")
PY
}

rtt() {
    local reps="${1:-3}" variant rep port dir
    echo "round trip, 8 B, 20000 round trips; ping on $ping_cpus, pong on $pong_cpus; wz env: ${wz_env:-none}; wz engine: $wz_engine"
    for variant in P W; do
        for rep in $(seq 1 "$reps"); do
            port=$((20000 + RANDOM % 20000))
            dir="$(mktemp -d)"
            compose "$variant" "$pong_cpus" timeout 60 "$out/bin/z_pong_$variant" -m peer -l "tcp/127.0.0.1:$port"
            "${CMD[@]}" >"$dir/pong" 2>&1 &
            local pong=$!
            sleep 2
            compose "$variant" "$ping_cpus" timeout 50 "$out/bin/z_ping_$variant" -m peer -e "tcp/127.0.0.1:$port" -s 8 -n 20000 -w 500
            "${CMD[@]}" >"$dir/ping" 2>&1
            kill "$pong" 2>/dev/null
            wait "$pong" 2>/dev/null
            echo "  rtt $variant rep$rep: median(us) $(median "$dir/ping" 0)"
            rm -rf "$dir"
        done
    done
}

# one_thr <direction> <publisher variant> <subscriber variant> <size> <rep>
one_thr() {
    local direction="$1" pv="$2" sv="$3" size="$4" rep="$5" port dir
    port=$((20000 + RANDOM % 20000))
    dir="$(mktemp -d)"
    compose "$sv" "$sub_cpus" stdbuf -oL timeout 17 "$out/bin/z_sub_thr_$sv" -m peer -l "tcp/127.0.0.1:$port"
    "${CMD[@]}" >"$dir/sub" 2>&1 &
    local sub=$!
    sleep 2
    compose "$pv" "$pub_cpus" timeout 12 "$out/bin/z_pub_thr_$pv" -m peer -e "tcp/127.0.0.1:$port" -s "$size"
    "${CMD[@]}" >"$dir/pub" 2>&1
    wait "$sub" 2>/dev/null
    local result lines
    result="$(median "$dir/sub" 3)"
    echo "  $direction pub=$pv sub=$sv size=$size rep$rep: msg/s $result"
    # A run that delivered few measurement lines did not run at full rate, or did not run: say what
    # each side printed last, because a number taken from three lines is not a rate to compare.
    lines="${result##*n=}"
    if [ "$result" = "no samples" ] || [ "${lines:-0}" -lt 20 ]; then
        echo "    publisher said: $(tail -n 2 "$dir/pub" | tr '\n' '|')"
        echo "    subscriber said: $(tail -n 2 "$dir/sub" | tr '\n' '|')"
    fi
    rm -rf "$dir"
}

thr() {
    local reps="${1:-2}" size rep
    shift
    local sizes="${*:-8 64 1024 8192}"
    echo "delivered msg/s counted by the subscriber; publisher on $pub_cpus, subscriber on $sub_cpus; wz env: ${wz_env:-none}; wz engine: $wz_engine"
    for size in $sizes; do
        for rep in $(seq 1 "$reps"); do
            one_thr TX P W "$size" "$rep"
            one_thr TX W W "$size" "$rep"
            one_thr RX W P "$size" "$rep"
            one_thr RX W W "$size" "$rep"
            # the control: pico on both sides, which says whether a pico side that collapses does so
            # against any peer or only against wz
            one_thr CONTROL P P "$size" "$rep"
        done
    done
}

# nodrop [reps] [sizes]: the highest rate OFFERED at which nothing is lost (RFC 2544), for the four pairs of
# libraries and the control; scripts/host-bench/nodrop.py states the trial and the search.
nodrop() {
    local reps="${1:-3}" sizes="${2:-8,64,1024}"
    local batch=()
    [ "${PICO_CMP_BATCH:-0}" = 1 ] && batch=(--batch)
    echo "wz engine: $wz_engine"
    python3 -I "$root/scripts/host-bench/nodrop.py" --bin-dir "$out/bin" --reps "$reps" --sizes "$sizes" \
        --pub-cpus "$pub_cpus" --sub-cpus "$sub_cpus" --wz-env "$wz_env" "${batch[@]}"
}

# profile [size] [rate]: the system calls of the PUBLISHER of scripts/host-bench/paced_pub.c for 3 seconds at
# a stated rate, counted by `strace -f -c`, for each library. strace slows the process, so no rate is read
# from it: what it says is how many calls of each kind one put costs (the sent count is the divisor).
profile() {
    local size="${1:-1024}" rate="${2:-50000}" variant port dir
    echo "system calls of the publisher, $size B at $rate msg/s for 3 s; publisher on $pub_cpus, subscriber on $sub_cpus; wz engine: $wz_engine"
    for variant in P W; do
        port=$((20000 + RANDOM % 20000))
        dir="$(mktemp -d)"
        compose "$variant" "$sub_cpus" timeout 25 "$out/bin/count_sub_$variant" -m peer -l "tcp/127.0.0.1:$port" -d 12
        "${CMD[@]}" >"$dir/sub" 2>&1 &
        local sub=$!
        sleep 2
        compose "$variant" "$pub_cpus" strace -f -c -o "$dir/strace" "$out/bin/paced_pub_$variant" -m peer \
            -e "tcp/127.0.0.1:$port" -s "$size" -r "$rate" -t 3 ${PICO_CMP_DROP:+-d}
        "${CMD[@]}" >"$dir/pub" 2>&1
        wait "$sub" 2>/dev/null
        echo "  profile pub=$variant: $(tail -n 1 "$dir/pub")"
        echo "  profile sub=$variant: $(tail -n 1 "$dir/sub")"
        echo "  calls by kind (publisher, all its threads):"
        sed -n 1,14p "$dir/strace" | sed 's/^/    /'
        rm -rf "$dir"
    done
}

# tids [size] [rate]: the calls of `sendto`, `futex` and `epoll_wait` of the publisher for 2 seconds, counted
# per THREAD (`strace -f -o`, then the thread ids of its own lines): which thread sends, and which threads
# hand work to each other. The first thread listed is the one that runs `main`.
tids() {
    local size="${1:-1024}" rate="${2:-5000}" variant port dir
    echo "calls per thread of the publisher, $size B at $rate msg/s for 2 s; wz engine: $wz_engine"
    for variant in P W; do
        port=$((20000 + RANDOM % 20000))
        dir="$(mktemp -d)"
        compose "$variant" "$sub_cpus" timeout 25 "$out/bin/count_sub_$variant" -m peer -l "tcp/127.0.0.1:$port" -d 10
        "${CMD[@]}" >"$dir/sub" 2>&1 &
        local sub=$!
        sleep 2
        compose "$variant" "$pub_cpus" strace -f -e trace=sendto,futex,epoll_wait,pselect6,poll,recvfrom -o "$dir/strace" \
            "$out/bin/paced_pub_$variant" -m peer -e "tcp/127.0.0.1:$port" -s "$size" -r "$rate" -t 2 ${PICO_CMP_DROP:+-d}
        "${CMD[@]}" >"$dir/pub" 2>&1
        wait "$sub" 2>/dev/null
        echo "  tids pub=$variant: $(tail -n 1 "$dir/pub")"
        echo "  main thread: $(sed -n 1p "$dir/strace" | cut -d' ' -f1)"
        echo "  calls (count, thread id, call):"
        awk '{ split($2, a, "("); c[$1 " " a[1]]++ } END { for (k in c) print c[k], k }' "$dir/strace" | sort -rn | sed -n 1,14p | sed 's/^/    /'
        rm -rf "$dir"
    done
}

# nodrop-c [reps] [sizes]: `nodrop` for the zenoh-c family, with the same benches, trial and search. In the pair
# letters P is the zenoh-c release and W is the wz library standing in for it (wz-capi-c), not zenoh-pico.
nodrop_c() {
    local reps="${1:-3}" sizes="${2:-8,64,1024}"
    local batch=()
    [ "${PICO_CMP_BATCH:-0}" = 1 ] && batch=(--batch)
    echo "zenoh-c family: P is the zenoh-c release, W is wz-capi-c"
    python3 -I "$root/scripts/host-bench/nodrop.py" --bin-dir "$out/bin-c" --reps "$reps" --sizes "$sizes" \
        --pub-cpus "$pub_cpus" --sub-cpus "$sub_cpus" --wz-env "$wz_env" "${batch[@]}"
}

# ── parity: the host side of the parity matrix (docs/upstream-parity.md section 5b) ──────────────────────
#
# Each family builds its two arms into $out/parity/<family>: bin/<program>_P against the original and
# bin/<program>_W against the wz preset, from ONE source per program, and lib-P / lib-W hold the libraries the
# programs run against (copies: a later build of the same crate under target/ does not change what a run
# measured). A builder sets PARITY_REFERENCE and PARITY_IMAGE (the run's image keys), PARITY_SIZE_P and
# PARITY_SIZE_W (the file each arm's size cells read) and PARITY_NOTES (lines for the run's record.txt).

PARITY_PROGRAMS=(z_put z_sub z_get z_queryable z_pub_thr z_sub_thr z_ping z_pong)

parity_fail() {
    echo "pico-compare: NOT-MEASURED, $*"
    exit 2
}

# parity_fail_log <log> <message>: parity_fail, with the first errors of <log> printed before it. A run through bx
# leaves its logs in the build host's account, where the person reading bx's own log may not reach them.
parity_fail_log() {
    local log="$1"
    shift
    grep -m 5 -A 12 -E '^error' "$log"
    parity_fail "$@"
}

# The cargo arguments of the wz build of an original's preset: configs/<original>_defconfig alone, resolved.
# It runs in a command substitution, so its refusal goes to stderr and the caller exits.
parity_preset_args() {
    python3 -I scripts/lib/wz_config.py --original-features "$1" \
        || { echo "pico-compare: NOT-MEASURED, configs/$1_defconfig did not resolve (wz_config.py --original-features $1)" >&2; return 2; }
}

# zenoh-pico: the original is upstream's DEFAULT build (no switch passed; build-zenoh-pico-cli.sh configures that arm
# as `zenoh-pico-build-default`, and this builds its shared library), wz is wz-capi-pico built for
# configs/zenoh-pico_defconfig. The programs are compiled against the default arm's headers.
parity_build_pico() {
    local dir="$1" default="$WZ_ARTIFACTS/target/zenoh-pico-build-default" args lib_p example variant name
    bash scripts/build-zenoh-pico-cli.sh >"$dir/build-pico.log" 2>&1 \
        || parity_fail "the pico arms did not configure (see $dir/build-pico.log)"
    cmake --build "$default" --target zenohpico_shared -j"$(nproc)" >>"$dir/build-pico.log" 2>&1 \
        || parity_fail "pico's default arm did not build (see $dir/build-pico.log)"
    lib_p="$(find "$default" -name 'libzenohpico.so' -print -quit)"
    [ -n "$lib_p" ] || parity_fail "no libzenohpico.so under $default"
    args="$(parity_preset_args zenoh-pico)" || exit 2
    # shellcheck disable=SC2086 # the cargo arguments are words on purpose
    (cd crates && cargo build --release -p wz-capi-pico $args) >"$dir/build-wz.log" 2>&1 \
        || parity_fail "wz-capi-pico did not build for the preset (see $dir/build-wz.log)"
    cp -a "$(dirname "$lib_p")"/libzenohpico.so* "$dir/lib-P/" || parity_fail "the pico library did not copy"
    cp "$WZ_ARTIFACTS/crates/target/release/libwz_capi_pico.so" "$dir/lib-W/" || parity_fail "the wz library did not copy"
    for example in "${PARITY_PROGRAMS[@]}"; do
        for variant in P W; do
            name=zenohpico
            [ "$variant" = W ] && name=wz_capi_pico
            cc -std=gnu11 -O2 "$root/vendor/zenoh-pico/examples/unix/c11/$example.c" -DZENOH_LINUX \
                -I"$default/zenohpico/include" -I"$root/vendor/zenoh-pico/include" -o "$dir/bin/${example}_$variant" \
                -L"$dir/lib-$variant" "-l$name" "-Wl,-rpath,$dir/lib-$variant" -lpthread \
                2>"$dir/build-${example}_$variant.log" \
                || parity_fail "$example against $variant did not build (see $dir/build-${example}_$variant.log)"
        done
    done
    PARITY_REFERENCE="zenoh-pico-$(git -C "$root/vendor/zenoh-pico" rev-parse --short=12 HEAD)"
    PARITY_IMAGE="wz-zenoh-pico_defconfig"
    PARITY_SIZE_P="$(readlink -f "$dir/lib-P/libzenohpico.so")"
    PARITY_SIZE_W="$dir/lib-W/libwz_capi_pico.so"
    PARITY_NOTES="original=zenoh-pico default build (cmake, no switch), $(grep -c '^#define Z_FEATURE_[A-Z_]* 1' "$default/zenohpico/include/zenoh-pico/config.h") switches on in its config.h
wz_cargo_args=-p wz-capi-pico $args"
}

# zenoh-c: the original is upstream's default build from the pinned source (install-zenoh-c-arm.sh nounstable: cmake
# Release, ZENOHC_BUILD_WITH_UNSTABLE_API and ZENOHC_BUILD_WITH_SHARED_MEMORY at their default FALSE, upstream's
# own pinned toolchain), wz is wz-capi-c built for configs/zenoh-c_defconfig. The programs are upstream's examples
# of the pinned source, compiled against the original's headers.
parity_build_c() {
    local dir="$1" prefix="$WZ_ARTIFACTS/target/zenoh-c-nounstable" ref="${WZ_ZENOH_C_REF:-$HOME/zenoh-c-ref}"
    local args drop_in example variant name
    if [ ! -f "$ref/examples/z_ping.c" ]; then
        WZ_ZENOH_C_REF="$ref" bash scripts/install-zenoh-c.sh >"$dir/build-zenoh-c-source.log" 2>&1 \
            || parity_fail "the zenoh-c source did not install (see $dir/build-zenoh-c-source.log)"
    fi
    WZ_ZENOH_C_REF="$ref" bash scripts/install-zenoh-c-arm.sh nounstable "$prefix" >"$dir/build-zenoh-c.log" 2>&1 \
        || parity_fail "zenoh-c's default arm did not build (see $dir/build-zenoh-c.log)"
    args="$(parity_preset_args zenoh-c)" || exit 2
    drop_in="$(python3 -I scripts/lib/wz_config.py --drop-in-features c "$prefix/include/zenoh_configure.h" 2>&1)" \
        || drop_in="not derived: $drop_in"
    # shellcheck disable=SC2086 # the cargo arguments are words on purpose
    (cd crates && cargo build --release -p wz-capi-c $args) >"$dir/build-wz.log" 2>&1 \
        || parity_fail "wz-capi-c did not build for the preset (see $dir/build-wz.log)"
    cp -a "$prefix/lib"/libzenohc.so* "$dir/lib-P/" || parity_fail "the zenoh-c library did not copy"
    cp "$WZ_ARTIFACTS/crates/target/release/libwz_capi_c.so" "$dir/lib-W/" || parity_fail "the wz library did not copy"
    for example in "${PARITY_PROGRAMS[@]}"; do
        for variant in P W; do
            name=zenohc
            [ "$variant" = W ] && name=wz_capi_c
            cc -std=gnu11 -O2 "$ref/examples/$example.c" -I"$ref/examples" -I"$prefix/include" \
                -o "$dir/bin/${example}_$variant" -L"$dir/lib-$variant" "-l$name" "-Wl,-rpath,$dir/lib-$variant" -lpthread \
                2>"$dir/build-${example}_$variant.log" \
                || parity_fail "$example against $variant did not build (see $dir/build-${example}_$variant.log)"
        done
    done
    PARITY_REFERENCE="zenoh-c-$(sed -n 's/^ZENOH_C_VERSION=//p' scripts/zenoh-c-oracle.pin)"
    PARITY_IMAGE="wz-zenoh-c_defconfig"
    PARITY_SIZE_P="$(readlink -f "$dir/lib-P/libzenohc.so")"
    PARITY_SIZE_W="$dir/lib-W/libwz_capi_c.so"
    PARITY_NOTES="original=zenoh-c nounstable arm built from $ref ($(sed -n 's/^ *channel *= *"\([^"]*\)".*/\1/p' "$ref/rust-toolchain.toml" | head -1) toolchain)
wz_cargo_args=-p wz-capi-c $args
wz_drop_in_args_for_the_original_header=$drop_in"
}

# zenoh: upstream's examples package of the pinned tree, generated twice (z8_upstream_suite.py examples): `stock`
# over upstream's zenoh from the registry, `wz` with the family patched in and wz-capi-core given the preset's
# features. One manifest but for that, upstream's release profile and Cargo.lock, the repository's compiler.
# parity_build_rust <dir> [program...]: the programs built, PARITY_PROGRAMS when none is named (`fanin` names
# its own, which the package holds beside upstream's).
parity_build_rust() {
    local dir="$1" args feats arm variant pkg example programs=() wanted=()
    shift
    wanted=("$@")
    [ "${#wanted[@]}" -gt 0 ] || wanted=("${PARITY_PROGRAMS[@]}")
    args="$(parity_preset_args zenoh)" || exit 2
    feats="$(sed -n 's/.*--features \([^ ]*\).*/\1/p' <<<"$args")"
    for example in "${wanted[@]}"; do
        programs+=(--example "$example")
    done
    for arm in stock wz; do
        variant=P
        [ "$arm" = wz ] && variant=W
        pkg="$(python3 -I scripts/lib/z8_upstream_suite.py examples --arm "$arm" --core-features "$feats" 2>"$dir/generate-$arm.log")" \
            || parity_fail "the $arm examples package was not generated (see $dir/generate-$arm.log)"
        # The package's directory is the last line printed (a first clone of the tree may print before it).
        pkg="${pkg##*$'\n'}"
        [ -f "$pkg/Cargo.toml" ] || parity_fail "the $arm examples package is not at '$pkg'"
        (cd "$pkg" && cargo build --release --target-dir "$pkg/target" "${programs[@]}") >"$dir/build-rust-$arm.log" 2>&1 \
            || parity_fail_log "$dir/build-rust-$arm.log" "the $arm examples did not build (see $dir/build-rust-$arm.log)"
        for example in "${wanted[@]}"; do
            cp "$pkg/target/release/examples/$example" "$dir/bin/${example}_$variant" \
                || parity_fail "$example of the $arm arm did not copy"
        done
    done
    PARITY_REFERENCE="zenoh-$(sed -n 's/^UPSTREAM_VERSION = "\([^"]*\)".*/\1/p' scripts/lib/upstream_feature_census.py)"
    PARITY_IMAGE="wz-zenoh_defconfig"
    PARITY_SIZE_P="$dir/bin/z_put_P"
    PARITY_SIZE_W="$dir/bin/z_put_W"
    PARITY_NOTES="original=upstream's examples package over zenoh from the registry; size cells read z_put
wz_cargo_args=wz-capi-core features $feats (from: $args), unified with what the family's crates select"
}

# parity <family> [boots] [sizes]
parity() {
    local family="${1:-}" boots="${2:-24}" sizes="${3:-8,1024}" dir tag run rc
    case "$family" in
        pico | c | rust) ;;
        *) echo "usage: $0 parity <pico|c|rust> [boots] [sizes]" >&2; exit 2 ;;
    esac
    dir="$out/parity/$family"
    rm -rf "$dir"
    mkdir -p "$dir/bin" "$dir/lib-P" "$dir/lib-W"
    bash scripts/provision-kconfiglib.sh >"$dir/build-kconfiglib.log" 2>&1 \
        || parity_fail "kconfiglib did not install (see $dir/build-kconfiglib.log)"
    cc -O2 -shared -fPIC -o "$dir/bin/heap_peak.so" "$root/scripts/host-bench/heap_peak.c" 2>"$dir/build-heap-shim.log" \
        || parity_fail "the heap shim did not build (see $dir/build-heap-shim.log)"
    "parity_build_$family" "$dir"
    tag="host-$family-$(date -u +%Y%m%dT%H%M%S)"
    run="$out/parity-runs/$tag"
    python3 -I "$root/scripts/host-bench/parity.py" --family "$family" --bin-dir "$dir/bin" --run "$run" \
        --boots "$boots" --sizes "$sizes" --image "$PARITY_IMAGE" --reference "$PARITY_REFERENCE" \
        --client-cpus "${PICO_CMP_CLIENT_CPUS:-4-7}" --server-cpus "${PICO_CMP_SERVER_CPUS:-8-11}" \
        --pings "${PICO_CMP_PINGS:-20000}" --warmup-s "${PICO_CMP_WARMUP_S:-3}" --window-s "${PICO_CMP_WINDOW_S:-10}" \
        --heap-shim "$dir/bin/heap_peak.so" --size-binary "P=$PARITY_SIZE_P" --size-binary "W=$PARITY_SIZE_W"
    rc=$?
    [ -d "$run" ] || parity_fail "the boots did not start (parity.py exit $rc)"
    {
        echo "run=$tag"
        echo "family=$family"
        echo "tree=$(git rev-parse HEAD)"
        echo "host=$(hostname)"
        echo "kernel=$(uname -r)"
        echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
        echo "threads=$(nproc)"
        echo "cc=$(cc --version | head -1)"
        echo "rustc=$(cd crates && rustc -V)"
        echo "boots=$boots of each image, alternating; sizes=$sizes"
        echo "client_cpus=${PICO_CMP_CLIENT_CPUS:-4-7} server_cpus=${PICO_CMP_SERVER_CPUS:-8-11}"
        echo "reference=$PARITY_REFERENCE image=$PARITY_IMAGE"
        echo "$PARITY_NOTES"
        echo "parity_exit=$rc"
    } >"$run/record.txt"
    python3 -I "$root/scripts/lib/kit_compare.py" --run "$run" --ref "$PARITY_REFERENCE" >"$run/verdict.txt" 2>&1 \
        || { cat "$run/verdict.txt"; parity_fail "the run $run could not be read"; }
    python3 -I "$root/scripts/lib/kit_compare.py" --run "$run" --ref "$PARITY_REFERENCE" --format rows >"$run/rows.json" \
        || parity_fail "the rows of $run could not be written"
    cat "$run/record.txt" "$run/verdict.txt"
    echo "pico-compare: parity run $run (verdict.txt, rows.json, record.txt)"
    return "$rc"
}

# ── perf: the performance matrix of the pico ABI (docs/pico-perf-matrix.md) ──────────────────────────────
#
# One program, scripts/host-bench/perf_probe.c, built three times into $out/perf/bin: perf_probe_P against
# zenoh-pico built as the same build as wz-capi-pico's default capabilities on the engine resolved above (the
# capability cost gate's reference, which perf_matrix.py reference builds or finds), perf_probe_W against that
# wz-capi-pico build and perf_probe_Wapp against it with the `app-transport` capability, the one arm that
# carries the program transport cell. Each arm's library is copied beside it (lib-<arm>), so a later build of
# the same crate does not change what a run measured. PICO_CMP_NO_BUILD=1 runs the programs already there.

perf_fail() {
    echo "pico-compare: NOT-MEASURED, $*"
    exit 2
}

# perf_external_arm <dir>: arm X, the same program against a library of the pico API this repository does not
# hold, named by the environment (docs/pico-perf-matrix.md section 1): WZ_PERF_EXTERNAL_LIB the shared library,
# WZ_PERF_EXTERNAL_INCLUDE its headers with its own zenoh-pico/config.h, WZ_PERF_EXTERNAL_CC_ARGS optional words
# added to the probe's compile and link, WZ_PERF_EXTERNAL_NAME an optional label. The library is linked where it
# lies, with its directory as the run path, because its own name may differ from the name it is loaded by. Unset,
# or a probe that did not build against it, writes a record that says why, and the arm is NOT-MEASURED: the
# matrix runs P and W, and the gate says so. The record (perf_matrix.py external-record) carries the label and the
# digests of the library and its config.h into the run's local result file only.
perf_external_arm() {
    local dir="$1" lib="${WZ_PERF_EXTERNAL_LIB:-}" inc="${WZ_PERF_EXTERNAL_INCLUDE:-}" why="" lib_dir
    local cc_args=()
    rm -f "$dir/bin/perf_probe_X" "$dir/external.json"
    if [ -z "$lib" ] || [ -z "$inc" ]; then
        why="WZ_PERF_EXTERNAL_LIB and WZ_PERF_EXTERNAL_INCLUDE are not both set; docs/pico-perf-matrix.md says what they name"
    elif [ ! -f "$lib" ]; then
        echo "pico-compare: WZ_PERF_EXTERNAL_LIB=$lib is not a file" >&2
        exit 2
    elif [ ! -f "$inc/zenoh-pico.h" ] || [ ! -f "$inc/zenoh-pico/config.h" ]; then
        echo "pico-compare: WZ_PERF_EXTERNAL_INCLUDE=$inc holds no zenoh-pico.h beside its zenoh-pico/config.h" >&2
        exit 2
    else
        if [ -n "${WZ_PERF_EXTERNAL_CC_ARGS:-}" ]; then
            read -r -a cc_args <<< "$WZ_PERF_EXTERNAL_CC_ARGS"
        fi
        lib_dir="$(cd "$(dirname "$lib")" && pwd)"
        if ! cc -std=gnu11 -O2 "$root/scripts/host-bench/perf_probe.c" -DZENOH_LINUX -I"$inc" \
            -o "$dir/bin/perf_probe_X" "$lib" "-Wl,-rpath,$lib_dir" -lpthread ${cc_args[@]+"${cc_args[@]}"} \
            2>"$dir/build-probe-X.log"; then
            rm -f "$dir/bin/perf_probe_X"
            why="perf_probe did not build against the external library (see $dir/build-probe-X.log)"
        fi
    fi
    if [ -n "$why" ]; then
        echo "pico-compare: arm X NOT-MEASURED, $why"
        python3 -I "$root/scripts/host-bench/perf_matrix.py" external-record "$dir/external.json" "$why" \
            || perf_fail "the record of arm X could not be written"
    else
        python3 -I "$root/scripts/host-bench/perf_matrix.py" external-record "$dir/external.json" \
            || perf_fail "the record of arm X could not be written"
        echo "pico-compare: arm X built against the external library"
    fi
}

# perf_wz_arm <dir> <arm> <features>: wz-capi-pico in release for its default features and <features> (a comma
# list, empty for none), its library copied to <dir>/lib-<arm> and the pico headers of its own arm to
# <dir>/include-<arm>: the headers its zenoh-pico-sys build installs, with the config.h of the same feature list
# (wz_config.py --pico-config-h) in place of the vendored default one, as scripts/pico-c-program.sh compiles a
# program. Against the vendored header a program allocates the option structs of another arm.
perf_wz_arm() {
    local dir="$1" arm="$2" features="$3" report inc args
    args="$(wz_cargo_args "$features")" \
        || perf_fail "arm $arm has no build on the $wz_engine engine (wz_config.py --bench-cargo-args $wz_engine '$features')"
    report="$dir/build-wz-$arm.json"
    # shellcheck disable=SC2086 # the cargo words are words on purpose
    (cd crates && cargo build --release --message-format=json-render-diagnostics -p zenoh-pico-sys \
        -p wz-capi-pico $args) >"$report" 2>"$dir/build-wz-$arm.log" \
        || perf_fail "wz-capi-pico for arm $arm did not build (see $dir/build-wz-$arm.log)"
    inc="$(python3 -I "$root/scripts/host-bench/perf_matrix.py" pico-sys-include "$report")" \
        || perf_fail "the build of arm $arm named no single pico header arm"
    rm -rf "$dir/include-$arm" "$dir/lib-$arm"
    mkdir -p "$dir/include-$arm" "$dir/lib-$arm"
    cp -R "$inc"/. "$dir/include-$arm"/ || perf_fail "the pico headers of arm $arm did not copy"
    python3 -I scripts/lib/wz_config.py --bench-config-h "$wz_engine" ${features:+"$features"} \
        >"$dir/include-$arm/zenoh-pico/config.h" \
        || perf_fail "the config.h of arm $arm did not render (wz_config.py --bench-config-h $wz_engine '$features')"
    cp "$wz_lib/libwz_capi_pico.so" "$dir/lib-$arm/" || perf_fail "the library of arm $arm did not copy"
}

# recorded_engine <reference.json>: the engine arm W was built on, as the record of its build states it.
recorded_engine() {
    python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("wz_engine", "unknown"))' \
        "$1" 2>/dev/null || echo unknown
}

# perf_probe_build <dir> <arm> <library name> [compiler words...]
perf_probe_build() {
    local dir="$1" arm="$2" name="$3"
    shift 3
    cc -std=gnu11 -O2 "$root/scripts/host-bench/perf_probe.c" -DZENOH_LINUX -I"$dir/include-$arm" "$@" \
        -o "$dir/bin/perf_probe_$arm" -L"$dir/lib-$arm" "-l$name" "-Wl,-rpath,$dir/lib-$arm" -lpthread \
        2>"$dir/build-probe-$arm.log" \
        || perf_fail "perf_probe against arm $arm did not build (see $dir/build-probe-$arm.log)"
}

# perf_matrix [reps] [sizes]: build the arms (unless PICO_CMP_NO_BUILD=1), run the matrix and judge the run. The
# cells can be narrowed with PICO_CMP_PERF_TRANSPORTS, PICO_CMP_PERF_BATCHING and PICO_CMP_PERF_WORKLOADS (comma
# lists of perf_matrix.py's words); the pinning is parity's, PICO_CMP_CLIENT_CPUS and PICO_CMP_SERVER_CPUS. The
# exit is the gate's (docs/pico-perf-matrix.md section 5): 0 every row held, 1 a row failed, 2 an input refused,
# 3 nothing failed but a row, or arm X when the environment names it, was not measured; a run that did not
# finish exits as before, 2 when it measured nothing.
perf_matrix() {
    local reps="${1:-3}" sizes="${2:-8,64,1024}" dir="$out/perf" run rc
    local external_args=() gate_args=()
    if [ "${PICO_CMP_NO_BUILD:-0}" != 1 ]; then
        rm -rf "${dir:?}/bin"
        mkdir -p "$dir/bin"
        bash scripts/provision-kconfiglib.sh >"$dir/build-kconfiglib.log" 2>&1 \
            || perf_fail "kconfiglib did not install (see $dir/build-kconfiglib.log)"
        resolve_wz_engine
        python3 -I "$root/scripts/host-bench/perf_matrix.py" reference --out "$dir" --engine "$wz_engine" \
            >"$dir/build-reference.log" 2>&1 \
            || perf_fail "the zenoh-pico reference did not build (see $dir/build-reference.log)"
        cat "$dir/build-reference.log"
        perf_wz_arm "$dir" W ""
        perf_wz_arm "$dir" Wapp app-transport
        perf_probe_build "$dir" P zenohpico
        perf_probe_build "$dir" W wz_capi_pico
        perf_probe_build "$dir" Wapp wz_capi_pico -DPERF_PROGRAM_TRANSPORT -I"$root/crates/wz-capi-core/include"
        perf_external_arm "$dir"
    else
        stamped_engine "$(recorded_engine "$dir/reference.json")"
    fi
    echo "pico-compare: arm W on the $(recorded_engine "$dir/reference.json") engine"
    if [ -f "$dir/external.json" ]; then
        external_args=(--external-record "$dir/external.json")
    fi
    run="$out/perf-runs/host-$(date -u +%Y%m%dT%H%M%S)"
    python3 -I "$root/scripts/host-bench/perf_matrix.py" run --bin-dir "$dir/bin" --run "$run" --reps "$reps" \
        --sizes "$sizes" --transports "${PICO_CMP_PERF_TRANSPORTS:-tcp,udp,multicast,program}" \
        --batching "${PICO_CMP_PERF_BATCHING:-off,on}" --workloads "${PICO_CMP_PERF_WORKLOADS:-rtt,thr}" \
        --client-cpus "${PICO_CMP_CLIENT_CPUS:-4-7}" --server-cpus "${PICO_CMP_SERVER_CPUS:-8-11}" \
        --pings "${PICO_CMP_PINGS:-20000}" --reference-record "$dir/reference.json" ${external_args[@]+"${external_args[@]}"}
    rc=$?
    if [ -f "$run/report.txt" ]; then
        cat "$run/report.txt"
    fi
    if [ "$rc" -ne 0 ]; then
        return "$rc"
    fi
    # The question of a run is W over P, and W over X too when the environment names the external library: with
    # the library unset the gate still prints that arm X was not measured, and does not count it.
    if [ -z "${WZ_PERF_EXTERNAL_LIB:-}" ]; then
        gate_args=(--without-external)
    fi
    python3 -I "$root/scripts/host-bench/perf_matrix.py" --gate "$run/perf.json" \
        --table "$root/deploy/pico_perf_ceiling.json" ${gate_args[@]+"${gate_args[@]}"}
}

# batch_probe_build <dir> <arm> <library name> [compiler words...]: the batch probe against an arm's library and
# headers, as perf_probe_build builds the performance probe.
batch_probe_build() {
    local dir="$1" arm="$2" name="$3"
    shift 3
    cc -std=gnu11 -O2 "$root/scripts/host-bench/batch_probe.c" -DZENOH_LINUX -I"$dir/include-$arm" "$@" \
        -o "$dir/bin/batch_probe_$arm" -L"$dir/lib-$arm" "-l$name" "-Wl,-rpath,$dir/lib-$arm" -lpthread \
        2>"$dir/build-probe-$arm.log" \
        || perf_fail "batch_probe against arm $arm did not build (see $dir/build-probe-$arm.log)"
}

# batch_control [sizes] [count]: build the arms (unless PICO_CMP_NO_BUILD=1) and run the batch size cells. Arm P is
# zenoh-pico built as the same build once per size, arm W one wz-capi-pico build with the document door, which each
# session of the run is handed its size through. The exit is batch_control.py's.
batch_control() {
    local sizes="${1:-512,2048,8192}" count="${2:-1200}" dir="$out/batch" run size
    local list=()
    IFS=, read -r -a list <<<"$sizes"
    if [ "${PICO_CMP_NO_BUILD:-0}" != 1 ]; then
        rm -rf "${dir:?}/bin"
        mkdir -p "$dir/bin"
        bash scripts/provision-kconfiglib.sh >"$dir/build-kconfiglib.log" 2>&1 \
            || perf_fail "kconfiglib did not install (see $dir/build-kconfiglib.log)"
        resolve_wz_engine
        python3 -I "$root/scripts/host-bench/batch_control.py" reference --out "$dir" --engine "$wz_engine" \
            --sizes "$sizes" >"$dir/build-reference.log" 2>&1 \
            || perf_fail "the zenoh-pico builds did not finish (see $dir/build-reference.log)"
        cat "$dir/build-reference.log"
        perf_wz_arm "$dir" W config-document
        for size in "${list[@]}"; do
            batch_probe_build "$dir" "P$size" zenohpico
        done
        batch_probe_build "$dir" W wz_capi_pico -DBATCH_PROBE_DOCUMENT -I"$root/crates/wz-capi-core/include"
    else
        stamped_engine "$(recorded_engine "$dir/reference.json")"
    fi
    run="$out/batch-runs/host-$(date -u +%Y%m%dT%H%M%S)"
    python3 -I "$root/scripts/host-bench/batch_control.py" run --bin-dir "$dir/bin" --lib-dir "$dir" --run "$run" \
        --sizes "$sizes" --count "$count"
}

# ── fanin: several publishers of large samples to one subscriber ──────────────────────────────────────────────
#
# fanin [rounds] [publishers] [size] [hz] [seconds] [block|drop] [pairs]: wz_fanin built for both arms of the Rust
# family (parity_build_rust), then scripts/host-bench/fanin.py over TCP loopback on this host. With
# PICO_CMP_NO_BUILD=1 the programs a previous fanin built are run again.
fanin() {
    local rounds="${1:-4}" pubs="${2:-3}" size="${3:-4000000}" hz="${4:-20}" seconds="${5:-10}" cc="${6:-block}"
    local pairs="${7:-PP,WW}"
    local dir="$out/fanin" run rc
    if [ "${PICO_CMP_NO_BUILD:-0}" = 1 ]; then
        [ -x "$dir/bin/wz_fanin_P" ] && [ -x "$dir/bin/wz_fanin_W" ] \
            || parity_fail "PICO_CMP_NO_BUILD=1 and no wz_fanin of an earlier fanin under $dir/bin"
        PARITY_REFERENCE="(not rebuilt)" PARITY_IMAGE="(not rebuilt)" PARITY_NOTES="programs of an earlier fanin build"
    else
        rm -rf "$dir"
        mkdir -p "$dir/bin"
        bash scripts/provision-kconfiglib.sh >"$dir/build-kconfiglib.log" 2>&1 \
            || parity_fail "kconfiglib did not install (see $dir/build-kconfiglib.log)"
        parity_build_rust "$dir" wz_fanin
    fi
    run="$out/fanin-runs/host-$(date -u +%Y%m%dT%H%M%S)"
    python3 -I "$root/scripts/host-bench/fanin.py" --bin-dir "$dir/bin" --run "$run" --rounds "$rounds" \
        --publishers "$pubs" --size "$size" --hz "$hz" --seconds "$seconds" --cc "$cc" --pairs "$pairs"
    rc=$?
    [ -d "$run" ] || parity_fail "the rounds did not start (fanin.py exit $rc)"
    {
        echo "tree=$(git rev-parse HEAD)"
        echo "host=$(hostname)"
        echo "kernel=$(uname -r)"
        echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
        echo "threads=$(nproc)"
        echo "rustc=$(cd crates && rustc -V)"
        echo "rounds=$rounds of each pair, alternating; pairs=$pairs publishers=$pubs size=$size hz=$hz seconds=$seconds cc=$cc"
        echo "reference=$PARITY_REFERENCE image=$PARITY_IMAGE"
        echo "$PARITY_NOTES"
        echo "fanin_exit=$rc"
    } >"$run/record.txt"
    echo "pico-compare: fanin run $run (report.txt, rounds.jsonl, record.txt)"
    return "$rc"
}

mode="${1:-}"
[ "$#" -gt 0 ] && shift
case "$mode" in
    tids) tids "$@" ;;
    rtt) rtt "$@" ;;
    thr) thr "$@" ;;
    nodrop) nodrop "$@" ;;
    nodrop-c) nodrop_c "$@" ;;
    profile) profile "$@" ;;
    parity) parity "$@" ;;
    perf) perf_matrix "$@" ;;
    batch) batch_control "$@" ;;
    fanin) fanin "$@" ;;
    *)
        echo "usage: $0 rtt [reps] | thr [reps] [sizes...] | nodrop [reps] [sizes,comma,separated] | nodrop-c [reps] [sizes] | profile [size] [rate] | parity <pico|c|rust> [boots] [sizes] | perf [reps] [sizes,comma,separated] | batch [sizes,comma,separated] [count] | fanin [rounds] [publishers] [size] [hz] [seconds] [block|drop] [pairs]" >&2
        exit 2
        ;;
esac

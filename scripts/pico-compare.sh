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
# for example WZ_CAPI_RX_BUSY_POLL_US=10), PICO_CMP_NO_BUILD=1 (use the libraries already built).
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

examples="$root/vendor/zenoh-pico/examples/unix/c11"
pico_lib="$root/target/zenoh-pico-build/lib"
wz_lib="$root/crates/target/release"
out="$root/target/pico-compare"
mkdir -p "$out/bin"

if [ "${PICO_CMP_NO_BUILD:-0}" != 1 ]; then
    bash scripts/build-zenoh-pico-cli.sh >"$out/build-pico.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, the pico library did not build (see $out/build-pico.log)"; exit 2; }
    (cd crates && cargo build --release -p wz-capi-pico) >"$out/build-wz.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, the wz library did not build (see $out/build-wz.log)"; exit 2; }
fi

include=(
    -I"$root/target/zenoh-pico-build/zenohpico/include"
    -I"$root/vendor/zenoh-pico/include"
    -I"$root/target/mbedtls/include"
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

case "${1:-}" in
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
    echo "round trip, 8 B, 20000 round trips; ping on $ping_cpus, pong on $pong_cpus; wz env: ${wz_env:-none}"
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
    echo "delivered msg/s counted by the subscriber; publisher on $pub_cpus, subscriber on $sub_cpus; wz env: ${wz_env:-none}"
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
    python3 -I "$root/scripts/host-bench/nodrop.py" --bin-dir "$out/bin" --reps "$reps" --sizes "$sizes" \
        --pub-cpus "$pub_cpus" --sub-cpus "$sub_cpus" --wz-env "$wz_env" "${batch[@]}"
}

# profile [size] [rate]: the system calls of the PUBLISHER of scripts/host-bench/paced_pub.c for 3 seconds at
# a stated rate, counted by `strace -f -c`, for each library. strace slows the process, so no rate is read
# from it: what it says is how many calls of each kind one put costs (the sent count is the divisor).
profile() {
    local size="${1:-1024}" rate="${2:-50000}" variant port dir
    echo "system calls of the publisher, $size B at $rate msg/s for 3 s; publisher on $pub_cpus, subscriber on $sub_cpus"
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
    echo "calls per thread of the publisher, $size B at $rate msg/s for 2 s"
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

mode="${1:-}"
[ "$#" -gt 0 ] && shift
case "$mode" in
    tids) tids "$@" ;;
    rtt) rtt "$@" ;;
    thr) thr "$@" ;;
    nodrop) nodrop "$@" ;;
    profile) profile "$@" ;;
    *)
        echo "usage: $0 rtt [reps] | thr [reps] [sizes...] | nodrop [reps] [sizes,comma,separated] | profile [size] [rate]" >&2
        exit 2
        ;;
esac

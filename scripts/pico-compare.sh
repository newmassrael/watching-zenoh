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
#   scripts/pico-compare.sh subprofile [size] [count] [rate]
#                                             where the SUBSCRIBER's time goes, for each library: scripts/host-bench's
#                                             count_sub, fed by its paced_pub, run under `strace -f -c` (the system
#                                             calls of each kind one received message costs), `perf stat` (its
#                                             instructions, cycles, switches, migrations, cache and branch misses),
#                                             `perf record` (the top functions, self and with children) and
#                                             valgrind's callgrind (the exact instructions, in all and by function),
#                                             each counter at two counts over the same seconds so that start and end
#                                             cancel, callgrind's in a window of the connected time beside an idle
#                                             run (subprofile below). Left under
#                                             target/pico-compare/subprofile-runs/host-<time>/ (report.txt,
#                                             record.txt, per-message.tsv, each run's tables and the tools' files); exit
#                                             0 when every leg of both arms was measured, 2 when one was not. The wz
#                                             arm is the library a release ships (see THE WZ ARM OF THE INSTRUCTION
#                                             COUNTS below), PICO_CMP_STDLIB=std naming the other form
#   scripts/pico-compare.sh opprofile [ops] [size]
#                                             what ONE OPERATION costs in instructions, for each library, under
#                                             callgrind at two counts so that start and end cancel: put, get with the
#                                             queryable that answers it (counted in a window of the connected time,
#                                             beside an idle run), declare and undeclare of a subscriber, a
#                                             publisher and a queryable, open and close, and the paced loop alone
#                                             (scripts/host-bench/op_probe.c; opprofile below). The wz arm as
#                                             subprofile's. Left under target/pico-compare/opprofile-runs/host-<time>/
#   scripts/pico-compare.sh selftest          the helpers the modes lean on (selftest below), on no build and no pinning
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
#                                             the table WZ_PERF_EXTERNAL_TABLE names outside the repository.
#                                             wz-capi-pico is built in the form the release ships, without
#                                             `std` unless PICO_CMP_STDLIB=std names the other, as the size
#                                             gate builds that form (perf_matrix.py wz-arm)
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
# built in that tree, and what the script prints is read from bx's log. The pinning is chosen from the
# host's topology unless it is stated (pin_sides below): two whole physical cores a side, every thread of a
# core on one side, the core of CPU 0 left to the system, and one core a side on a host with too few; a host
# with fewer than that is refused before anything is built. A process is never pinned to one thread of an SMT
# core: a process pinned to a single CPU measured a 2 ms scheduler tick in BOTH libraries.
#
# Environment: PICO_CMP_PING_CPUS / PICO_CMP_PONG_CPUS (`rtt`) and PICO_CMP_PUB_CPUS / PICO_CMP_SUB_CPUS
# (`thr`, `nodrop`, `nodrop-c`, `profile`, `tids`, `subprofile`, `opprofile`), each unset one from the topology,
# PICO_CMP_WZ_ENV (extra `VAR=value` words put in front of every wz process,
# for example WZ_CAPI_RX_BUSY_POLL_US=10), PICO_CMP_NO_BUILD=1 (use the libraries already built), PICO_CMP_ENGINE
# (`tokio` or `coop`: the engine the wz library is built on, to compare the two; unset, the one the package for a
# host ships on, which its profile configs/profiles/host-peer-ext.conf chooses). `rtt`, `thr`, `nodrop`, `profile`,
# `tids`, `perf` and `batch` build the wz library on that engine and print it with their readings; `parity`
# builds each original's preset and `nodrop-c` the zenoh-c family, which have one engine each. PICO_CMP_STDLIB
# (`std` or `nostd`, `perf` only): the standard library the wz library is built with, to compare the two;
# unset, the one form the release ships (perf_matrix.py bench-stdlib).
# `parity` and `perf` pin the client side of a pair (z_ping, z_pub_thr, z_put, z_get) to PICO_CMP_CLIENT_CPUS
# and the server side to PICO_CMP_SERVER_CPUS (unset, from the topology: two whole cores a side where the host
# has them, because zenoh-c and zenoh run several threads a process and one SMT pair would bind them where it
# binds pico's one); PICO_CMP_PINGS (default 20000), PICO_CMP_WARMUP_S (3) and
# PICO_CMP_WINDOW_S (10) set the round trips and the window of the free-running throughput pair (a diagnostic of
# `parity`, not a cell), and PICO_CMP_NODROP_TRIAL_S (3) the seconds of a trial of parity's no-drop search.
# PICO_CMP_TRANSPORT (`subprofile`, `opprofile`): tcp, the default, or multicast, the transport the pair
# measured runs on (the transport of subprofile and opprofile, below).
#
# What it does NOT show: anything about an MCU, and the cost in CPU of a lower round trip: read the
# per-process CPU separately before claiming a latency win.

set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 2

wz_env="${PICO_CMP_WZ_ENV:-}"

# THE CPUS EACH SIDE OF A PAIR RUNS ON. A variable that names them is used as given; an unset one takes its side
# from this host's topology (perf_matrix.py pin-sides), so a host of another shape than the one the fixed layout
# was measured on is pinned to CPUs it has instead of every cell failing in taskset. A host with too few cores is
# refused here, before anything is built or run, and the CPUs chosen are printed and carried into each record.
client_cpus=""
server_cpus=""
pin_sides() {
    local client_var="$1" server_var="$2" words how
    words="$(python3 -I "$root/scripts/host-bench/perf_matrix.py" pin-sides "$client_var=${!client_var:-}" \
        "$server_var=${!server_var:-}")" \
        || { echo "pico-compare: NOT-MEASURED, no pinning on this host (perf_matrix.py pin-sides said why above)"; exit 2; }
    read -r client_cpus server_cpus how <<<"$words"
    echo "pico-compare: pinning $client_var=$client_cpus $server_var=$server_cpus ($how)"
}
ping_cpus=""
pong_cpus=""
pub_cpus=""
sub_cpus=""
case "${1:-}" in
    rtt)
        pin_sides PICO_CMP_PING_CPUS PICO_CMP_PONG_CPUS
        ping_cpus="$client_cpus"
        pong_cpus="$server_cpus"
        ;;
    thr | nodrop | nodrop-c | profile | tids | subprofile | opprofile)
        pin_sides PICO_CMP_PUB_CPUS PICO_CMP_SUB_CPUS
        pub_cpus="$client_cpus"
        sub_cpus="$server_cpus"
        ;;
    parity | perf)
        pin_sides PICO_CMP_CLIENT_CPUS PICO_CMP_SERVER_CPUS
        ;;
esac

# Products of this checkout, under the artifact root (scripts/lib/artifact-root.sh).
# shellcheck source=scripts/lib/artifact-root.sh
source "$root/scripts/lib/artifact-root.sh"
wz_artifact_root_init "$root" || exit 2

examples="$root/vendor/zenoh-pico/examples/unix/c11"
pico_lib="$WZ_ARTIFACTS/target/zenoh-pico-build/lib"
# The wz library of every mode is built as a deployer receives it (crates/Cargo.toml `ship`: fat LTO, one
# codegen unit), so a comparison with the original reads the library that ships and every arm one profile.
wz_profile=ship
wz_lib="$WZ_ARTIFACTS/crates/target/$wz_profile"
# The pico C library is a crate of its own, wz-capi-pico-lib (wz-capi-pico is the ABI's rlib). On the cooperative
# engine it has no `std` (docs/win-budget/std-heap.md, S1) and is built as that library ships: the `capi-nostd`
# profile and its configuration, for the host's own target, in a directory of its own. On the tokio engine it links
# `std` and is built as the zenoh-c library is. pico_form sets the words and the directory of that build for
# $wz_engine, once the engine is known.
wz_pico_args=(--profile "$wz_profile")
wz_pico_lib="$wz_lib"
pico_form() {
    local triple
    if [ "$wz_engine" = coop ]; then
        triple="$(rustc -vV | sed -n 's/^host: //p')"
        [ -n "$triple" ] || { echo "pico-compare: NOT-MEASURED, rustc named no host target"; exit 2; }
        wz_pico_args=(--profile capi-nostd --config .cargo/capi-nostd.toml --target "$triple")
        wz_pico_lib="$WZ_ARTIFACTS/crates/target/$triple/capi-nostd"
    else
        wz_pico_args=(--profile "$wz_profile")
        wz_pico_lib="$wz_lib"
    fi
}
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
    pico_form
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
    pico_form
}

if [ "${PICO_CMP_NO_BUILD:-0}" != 1 ] && [ "${1:-}" != nodrop-c ] && [ "${1:-}" != parity ] && [ "${1:-}" != perf ] \
    && [ "${1:-}" != batch ] && [ "${1:-}" != fanin ] && [ "${1:-}" != subprofile ] && [ "${1:-}" != opprofile ] \
    && [ "${1:-}" != selftest ]; then
    resolve_wz_engine
    bash scripts/build-zenoh-pico-cli.sh >"$out/build-pico.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, the pico library did not build (see $out/build-pico.log)"; exit 2; }
    wz_args="$(wz_cargo_args "")" \
        || { echo "pico-compare: NOT-MEASURED, no cargo words for the $wz_engine engine"; exit 2; }
    rm -f "$out/wz-engine"
    # shellcheck disable=SC2086 # the cargo words are words on purpose
    (cd crates && cargo build "${wz_pico_args[@]}" -p wz-capi-pico-lib $wz_args) >"$out/build-wz.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, the wz library did not build (see $out/build-wz.log)"; exit 2; }
    echo "$wz_engine" >"$out/wz-engine"
fi
case "${1:-}" in
    rtt | thr | nodrop | profile | tids)
        [ -n "$wz_engine" ] || stamped_engine "$(cat "$out/wz-engine" 2>/dev/null)"
        ;;
esac

# THE WZ ARM OF THE INSTRUCTION COUNTS (subprofile, opprofile) is the library a release ships: wz-capi-pico-lib for
# configs/zenoh-pico_defconfig under the limits and policies it sets, in the release's form (no_std, no heap after
# the open) unless PICO_CMP_STDLIB names the other, built as the size gate builds that case: the same build as arm
# W of `parity pico` (perf_matrix.py preset-arm). A count read off another form says nothing of what ships.
# PICO_CMP_ENGINE does not apply: the defconfig states the engine. With PICO_CMP_NO_BUILD=1 the library of an
# earlier build is read, and its record names its form.
shipped_dir="$out/shipped"
wz_bench_lib="$wz_pico_lib"
case "${1:-}" in
    subprofile | opprofile)
        if [ "${PICO_CMP_NO_BUILD:-0}" != 1 ]; then
            bash scripts/provision-kconfiglib.sh >"$out/build-kconfiglib.log" 2>&1 \
                || { echo "pico-compare: NOT-MEASURED, kconfiglib did not install (see $out/build-kconfiglib.log)"; exit 2; }
            bash scripts/build-zenoh-pico-cli.sh >"$out/build-pico.log" 2>&1 \
                || { echo "pico-compare: NOT-MEASURED, the pico library did not build (see $out/build-pico.log)"; exit 2; }
            rm -rf "$shipped_dir"
            mkdir -p "$shipped_dir"
            shipped_stdlib="$(python3 -I "$root/scripts/host-bench/perf_matrix.py" bench-stdlib ${PICO_CMP_STDLIB:+"$PICO_CMP_STDLIB"})" \
                || { echo "pico-compare: NOT-MEASURED, the standard library of the wz arm did not resolve"; exit 2; }
            python3 -I "$root/scripts/host-bench/perf_matrix.py" preset-arm --out "$shipped_dir" --original zenoh-pico \
                --stdlib "$shipped_stdlib" >"$shipped_dir/build.txt" \
                || { cat "$shipped_dir/build.txt"; grep -m 5 -A 12 -E '^error' "$shipped_dir/build-wz.log"
                     echo "pico-compare: NOT-MEASURED, the shipped wz arm did not build (see $shipped_dir/build-wz.log)"; exit 2; }
        fi
        [ -f "$shipped_dir/lib-W/libwz_capi_pico.so" ] && [ -f "$shipped_dir/build.txt" ] \
            || { echo "pico-compare: NOT-MEASURED, no shipped wz arm under $shipped_dir (PICO_CMP_NO_BUILD=1 reads an earlier build)"; exit 2; }
        wz_bench_lib="$shipped_dir/lib-W"
        wz_engine="$(tr '\n' ' ' <"$shipped_dir/build.txt")"
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
        lib="$wz_pico_lib"
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
        lib="$wz_bench_lib"
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
    local wz_c_lib="$wz_lib" args bench variant lib libname
    mkdir -p "$out/bin-c"
    WZ_ZENOH_C_PREFIX="$prefix" WZ_ZENOH_C_REF="$ref" bash scripts/install-zenoh-c.sh >"$out/build-zenoh-c.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, the zenoh-c release did not install (see $out/build-zenoh-c.log)"; exit 2; }
    bash scripts/provision-kconfiglib.sh >"$out/build-kconfiglib.log" 2>&1 \
        || { echo "pico-compare: NOT-MEASURED, kconfiglib did not install (see $out/build-kconfiglib.log)"; exit 2; }
    args="$(python3 -I scripts/lib/wz_config.py --drop-in-features c "$prefix/include/zenoh_configure.h")" \
        || { echo "pico-compare: NOT-MEASURED, no drop-in features for $prefix/include/zenoh_configure.h"; exit 2; }
    # shellcheck disable=SC2086 # the cargo arguments are words on purpose
    (cd crates && cargo build --profile "$wz_profile" -p wz-capi-c $args) >"$out/build-wz-c.log" 2>&1 \
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
    opprofile)
        for bench in op_probe count_sub; do
            for variant in P W; do
                build_bench "$bench" "$variant"
            done
        done
        ;;
    nodrop|profile|tids|subprofile)
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

# bench_port [range file]: a TCP port for the listener of one run on loopback. Not one of the kernel's ephemeral
# ports (the range the file states, /proc/sys/net/ipv4/ip_local_port_range unless one is given), from which the
# host hands the local end of every connection it makes, other runs' on this host among them: a listener given
# one of those finds it taken now and then, its session does not open, and the session that dials it then does
# not open either. From 20000 up to the range when a thousand ports lie there, else above the range; and not a
# port a socket of this host holds now (ss), when ss is on PATH.
bench_port() {
    local file="${1:-/proc/sys/net/ipv4/ip_local_port_range}" low=32768 high=60999 first last port held=" "
    if read -r first last 2>/dev/null <"$file" && [[ "$first" =~ ^[0-9]+$ ]] && [[ "$last" =~ ^[0-9]+$ ]]; then
        low="$first"
        high="$last"
    fi
    if [ $((low - 20000)) -ge 1000 ]; then
        first=20000
        last=$((low - 1))
    elif [ $((65535 - high)) -ge 1000 ]; then
        first=$((high + 1))
        last=65535
    else
        first=20000
        last=65535
    fi
    if command -v ss >/dev/null 2>&1; then
        held=" $(ss -Htan 2>/dev/null | awk '{ n = split($4, a, ":"); printf "%s ", a[n] }')"
    fi
    for _ in $(seq 1 50); do
        port=$((first + (RANDOM * 32768 + RANDOM) % (last - first + 1)))
        case "$held" in
            *" $port "*) ;;
            *) break ;;
        esac
    done
    echo "$port"
}

# peer_alive <pid>: whether the process runs still. A child that ended and that the shell has not waited for is a
# zombie, which kill -0 still finds.
peer_alive() {
    local state
    state="$(sed -n 's/^.*) \([A-Za-z]\) .*$/\1/p' "/proc/$1/stat" 2>/dev/null)"
    [ -n "$state" ] && [ "$state" != Z ] && [ "$state" != X ]
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
            port="$(bench_port)"
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
    port="$(bench_port)"
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
        port="$(bench_port)"
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
        port="$(bench_port)"
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

# ── the transport of subprofile and opprofile ──────────────────────────────────────────────────────────────
#
# PICO_CMP_TRANSPORT (subprofile, opprofile): tcp, the default, where the receiving side listens on
# tcp/127.0.0.1:<port> and the sending side connects to it, or multicast, where both listen on the group
# udp/224.0.0.224:<port>#iface=lo as the multicast cells of the performance matrix do (perf_matrix.py
# endpoint_args), so the counts are of the group's send and receive paths (docs/win-budget/ir-multicast.md).
# The window and the idle run are the same on either.
bench_transport="${PICO_CMP_TRANSPORT:-tcp}"

# bench_transport_ok: whether PICO_CMP_TRANSPORT names a transport these modes run; says why not, and fails.
bench_transport_ok() {
    case "$bench_transport" in
        tcp | multicast) return 0 ;;
    esac
    echo "pico-compare: NOT-MEASURED, PICO_CMP_TRANSPORT=$bench_transport is not tcp or multicast"
    return 1
}

# bench_ends <port>: the endpoint words of the receiving side, in LISTEN_END, and of the sending side, in
# SEND_END, on <port> of the transport PICO_CMP_TRANSPORT names.
LISTEN_END=()
SEND_END=()
bench_ends() {
    if [ "$bench_transport" = multicast ]; then
        LISTEN_END=(-l "udp/224.0.0.224:$1#iface=lo")
        SEND_END=(-l "udp/224.0.0.224:$1#iface=lo")
    else
        LISTEN_END=(-l "tcp/127.0.0.1:$1")
        SEND_END=(-e "tcp/127.0.0.1:$1")
    fi
}

# ── subprofile: where the subscriber's time goes ─────────────────────────────────────────────────────────────
#
# subprofile [size] [count] [rate]: count_sub of each library, fed [size] (8) byte messages by paced_pub of the
# same library, under four tools in turn: `strace -f -c`, `perf stat`, `perf record` and valgrind's callgrind. A
# counter charges a run's start and end (the library's load, the session's open and close, the timers of the time
# it listens) to whatever count it received, and strace and callgrind slow the subscriber too far for a rate to be
# read from them. So each arm runs twice under each counter, fed PICO_CMP_SUBPROF_BASE (2000) and [count] (12000)
# messages: what the second run counts past the first, over the messages it received past the first, is what one
# message costs, and what the two share cancels. They share it only when the two runs are the same in all but the
# count, so both put their messages over the SAME seconds, the ones [count] takes at [rate] (10000) a second, the
# smaller count at the rate that puts it in them: a publisher connected for longer in one run than in the other
# leaves the subscriber's timers and idle loop a different time with a peer and without one. callgrind runs the
# subscriber some fifty times slower, so its [rate] is PICO_CMP_SUBPROF_CALLGRIND_RATE (1000), and its subscriber
# counts only a window (scripts/host-bench/bench_window.h): from PICO_CMP_SUBPROF_GUARD_MS (1000) before the first
# put to that past the drain below, which the publisher, connected until after it, puts its run inside, so that
# the time before the publisher connects and after it leaves, where zenoh-pico's executor polls its timers in a
# loop, is in neither count; the other tools count the whole process, whose time without a peer is now as long in
# both runs, so it cancels on average and not run by run. callgrind also runs a third time with no message in the same window (the idle run), and
# "net" is the larger run past that one over its messages: the cost of a message at [rate] with nothing of the
# window's own in it, beside the difference of the two counts, which reads the cost between the two rates.
# `perf record` samples, and is read as shares of the larger run alone. callgrind's publisher waits
# PICO_CMP_SUBPROF_WAIT_S (8) for the subscriber to listen, where the other tools wait 2; every subscriber listens
# PICO_CMP_SUBPROF_SLACK_S (10) past the last put, to drain what it is behind. The libraries keep no frame pointers
# (the `ship` profile, cmake Release), so `perf record` unwinds by their unwind tables (PICO_CMP_SUBPROF_CALLGRAPH,
# default dwarf; fp for a build that keeps them).

SUBPROF_EVENTS=instructions,cycles,context-switches,cpu-migrations,cache-misses,branch-misses

# monotonic_ns: CLOCK_MONOTONIC now, in nanoseconds: the clock of the instants the benches take with -a.
monotonic_ns() {
    python3 -I -c 'import time; print(time.clock_gettime_ns(time.CLOCK_MONOTONIC))'
}

# callgrind_window <stem>: the part file callgrind wrote when the window of the process of <stem> closed
# (--dump-before, bench_window.h), the one file <stem>.callgrind.<part>; fails when there is not exactly one.
callgrind_window() {
    local files=() glob
    glob="$(shopt -p nullglob)"
    shopt -s nullglob
    files=("$1".callgrind.[0-9]*)
    eval "$glob"
    [ "${#files[@]}" -eq 1 ] || return 1
    echo "${files[0]}"
}

# callgrind_calls <callgrind file> <function>: how many times the run called the function of that exact name, the
# calls of every caller summed: the `calls=` lines under each `cfn=` that names it, where callgrind writes a name
# once with its number and the number alone after that.
callgrind_calls() {
    python3 -I - "$1" "$2" <<'PY'
import re
import sys

names, total, into = {}, 0, False
line_of_fn = re.compile(r"^(c?fn)=(?:\((\d+)\)(?: (.*))?|(.*))$")
with open(sys.argv[1], encoding="utf-8", errors="replace") as lines:
    for line in lines:
        line = line.rstrip("\n")
        found = line_of_fn.match(line)
        if found:
            kind, number, given, plain = found.groups()
            if number is not None and given is not None:
                names[number] = given
            name = names.get(number) if number is not None else plain
            into = kind == "cfn" and name == sys.argv[2]
        elif into and line.startswith("calls="):
            total += int(line[len("calls="):].split()[0])
print(total)
PY
}

# subprofile_trial <tool> <variant> <count> <seconds> <size> <listen> <lead> <slack> <guard> <stem>: one run of the
# subscriber of <variant> under <tool> (strace, perfstat, perfrecord or callgrind) for <listen> seconds, and of the
# publisher, started <lead> seconds after it and putting <count> messages over <seconds>; under callgrind the
# subscriber counts the window of bench_window.h around them, <guard> ms before the first put to <slack> s and
# <guard> ms past the end of <seconds>. Leaves <stem>.sub, <stem>.pub and the tool's files.
subprofile_trial() {
    local tool="$1" variant="$2" count="$3" seconds="$4" size="$5" listen="$6" lead="$7" slack="$8" guard="$9"
    local stem="${10}"
    local port pace start tool_words=() window=() hold=()
    pace="$(awk -v c="$count" -v s="$seconds" 'BEGIN { printf "%.6f", c / s }')"
    case "$tool" in
        strace) tool_words=(strace -f -c -o "$stem.strace") ;;
        perfstat) tool_words=(perf stat -x "," -o "$stem.perfstat" -e "$SUBPROF_EVENTS" --) ;;
        perfrecord)
            tool_words=(perf record -g --call-graph "${PICO_CMP_SUBPROF_CALLGRAPH:-dwarf}" -o "$stem.perf.data" --)
            ;;
        *)
            tool_words=(valgrind --tool=callgrind "--callgrind-out-file=$stem.callgrind"
                "--zero-before=bench_window_open*" "--dump-before=bench_window_close*")
            ;;
    esac
    if [ "$tool" = callgrind ]; then
        # The first put three seconds after the publisher starts: its open, its second for the subscriber's
        # declaration and its own declaration come in the first two, before the window opens; it stays connected
        # a guard past the window's end.
        start=$(($(monotonic_ns) + (lead + 3) * 1000000000))
        window=(-a "$start" -t $((seconds + slack)) -g "$guard")
        hold=(-a "$start" -g $((slack * 1000 + 2 * guard)))
    fi
    port="$(bench_port)"
    bench_ends "$port"
    compose "$variant" "$sub_cpus" timeout $((listen + lead + 120)) "${tool_words[@]}" "$out/bin/count_sub_$variant" \
        -m peer "${LISTEN_END[@]}" -d "$listen" "${window[@]}"
    "${CMD[@]}" >"$stem.sub" 2>&1 &
    local sub=$!
    sleep "$lead"
    compose "$variant" "$pub_cpus" timeout $((seconds + slack + 60)) "$out/bin/paced_pub_$variant" -m peer \
        "${SEND_END[@]}" -s "$size" -r "$pace" -t "$seconds" "${hold[@]}"
    "${CMD[@]}" >"$stem.pub" 2>&1
    wait "$sub" 2>/dev/null
}

# subprofile_number <file> <word>: the number a program printed after `<word>=` on its last line that has one.
subprofile_number() {
    sed -n "s/.*$2=\([0-9][0-9]*\).*/\1/p" "$1" 2>/dev/null | tail -n 1
}

# subprofile_ir <callgrind file>: the instructions a run executed in all, from the file's own total.
subprofile_ir() {
    sed -n 's/^\(summary\|totals\): *\([0-9][0-9]*\).*/\2/p' "$1" 2>/dev/null | tail -n 1
}

# subprofile_table <strace|perfstat|annotate> <lower> <upper> <messages> [top]: the rows of two runs' tables, each
# system call kind's count (strace -c), each event's count (perf stat -x) or each function's instructions
# (callgrind_annotate) in the upper run past the lower one, over the <messages> the upper run received past the
# lower; the largest first, the first [top] of them. A table with no row prints nothing.
subprofile_table() {
    python3 -I - "$@" <<'PY'
import re
import sys

kind, lower, upper, messages = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
top = int(sys.argv[5]) if len(sys.argv) > 5 else 0
# callgrind_annotate's row: the count, a share when it prints one, then the function.
ROW = re.compile(r"^\s*([\d,]+)\s+(?:\(\s*[\d.]+%\)\s+)?(\S.*?)\s*$")
# A hybrid CPU's counters come one row per core type (`cpu_core/cycles/`), and a restricted one carries `:u`.
PMU = re.compile(r"^cpu_\w+/(.*)/$")


def strace_rows(path):
    rows = {}
    for line in open(path, errors="replace"):
        words = line.split()
        # "% time  seconds  usecs/call  calls  [errors]  syscall": the calls are the fourth word either way.
        if len(words) < 5 or words[0].startswith(("%", "-")) or words[-1] == "total":
            continue
        try:
            rows[words[-1]] = int(words[3])
        except ValueError:
            pass
    return rows


def perfstat_rows(path):
    rows = {}
    for line in open(path, errors="replace"):
        fields = line.strip().split(",")
        if len(fields) < 3 or line.startswith("#"):
            continue
        try:
            value = int(float(fields[0]))
        except ValueError:
            # "<not counted>" or "<not supported>": a core type the process did not run on, or no such counter.
            continue
        event = PMU.sub(r"\1", fields[2]).split(":")[0]
        rows[event] = rows.get(event, 0) + value
    return rows


def annotate_rows(path):
    rows = {}
    for line in open(path, errors="replace"):
        match = ROW.match(line)
        if match and match.group(2) != "PROGRAM TOTALS":
            name = match.group(2)
            rows[name] = rows.get(name, 0) + int(match.group(1).replace(",", ""))
    return rows


read = {"strace": strace_rows, "perfstat": perfstat_rows}.get(kind, annotate_rows)
low, high = read(lower), read(upper)
rows = sorted(((high.get(k, 0) - low.get(k, 0), k) for k in set(low) | set(high)), reverse=True)
for extra, name in rows[:top] if top else rows:
    print(f"    {extra / messages:14.3f}  {name}")
PY
}

# subprofile_has <tool>: whether the programs the leg runs are on PATH.
subprofile_has() {
    case "$1" in
        strace) command -v strace >/dev/null 2>&1 ;;
        perfstat | perfrecord) command -v perf >/dev/null 2>&1 ;;
        *) command -v valgrind >/dev/null 2>&1 && command -v callgrind_annotate >/dev/null 2>&1 ;;
    esac
}

# subprofile_records <stem> <variant> <listing>: the top 25 rows of `perf report` of one run, without children or
# with them, its whole listing left beside the data.
subprofile_records() {
    local stem="$1" variant="$2" listing="$3"
    perf report -i "$stem.perf.data" --stdio "--$listing" --sort dso,symbol -g none --percent-limit 0 \
        >"$stem.$listing.txt" 2>&1
    echo "  perf record sub=$variant: top 25 by share of samples, --$listing:"
    grep -E '^ +[0-9]+\.[0-9]+%' "$stem.$listing.txt" | head -n 25 | sed 's/^/  /'
}

# window_lead_ok <sender output> <guard ms> <what>: whether the sender's session was open (open_lead_ms=) longer
# before the start instant than the receiver's window opens before it, so that the window holds no time without
# a peer; says why not, and fails, when it was not.
window_lead_ok() {
    local lead
    lead="$(subprofile_number "$1" open_lead_ms)"
    [ -n "$lead" ] && [ "$lead" -gt "$2" ] && return 0
    echo "  $3: NOT-MEASURED, in ${1##*/} the sender's session was open ${lead:-?} ms before the start instant, not more than the window's guard of $2 ms"
    return 1
}

# subprofile_arm <tool> <variant> <base> <count> <guard> <run>: the lines of one arm under one tool, from its runs;
# returns 2 when the arm was not measured. Under callgrind the counts are those of the subscriber's window, the
# idle run's included, and the arm's two figures go to <run>/per-message.tsv.
subprofile_arm() {
    local tool="$1" variant="$2" base="$3" count="$4" guard="$5" run="$6"
    local lo="$run/$tool-$variant-$base" hi="$run/$tool-$variant-$count" idle="$run/$tool-$variant-0"
    local sent_lo sent_hi recv_0 recv_lo recv_hi messages ir_0 ir_lo ir_hi cg_0 cg_lo cg_hi per net listing rows
    local word=received stem
    # Under callgrind the divisor is what the subscriber received inside the window its instructions are of.
    [ "$tool" = callgrind ] && word=in_window
    sent_hi="$(subprofile_number "$hi.pub" sent)"
    recv_hi="$(subprofile_number "$hi.sub" "$word")"
    if [ "$tool" = perfrecord ]; then
        echo "  perf record sub=$variant: n=$count sent=${sent_hi:-?} received=${recv_hi:-?}"
        if [ ! -s "$hi.perf.data" ]; then
            echo "  perf record sub=$variant: NOT-MEASURED, perf left no samples (perf_event_paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null); see $hi.sub)"
            return 2
        fi
        subprofile_records "$hi" "$variant" no-children
        subprofile_records "$hi" "$variant" children
        return 0
    fi
    sent_lo="$(subprofile_number "$lo.pub" sent)"
    recv_lo="$(subprofile_number "$lo.sub" "$word")"
    echo "  $tool sub=$variant: n=$base sent=${sent_lo:-?} $word=${recv_lo:-?}; n=$count sent=${sent_hi:-?} $word=${recv_hi:-?}"
    if [ -z "$recv_lo" ] || [ -z "$recv_hi" ] || [ "$recv_hi" -le "$recv_lo" ]; then
        echo "  $tool sub=$variant: NOT-MEASURED, the larger run did not receive more than the smaller one"
        echo "    publisher said: $(tail -n 2 "$hi.pub" 2>/dev/null | tr '\n' '|')"
        echo "    subscriber said: $(tail -n 2 "$hi.sub" 2>/dev/null | tr '\n' '|')"
        return 2
    fi
    messages=$((recv_hi - recv_lo))
    # A message put and never received is not in the divisor; saying so keeps a short drain from passing unseen.
    if [ "$recv_lo" != "${sent_lo:-}" ] || [ "$recv_hi" != "${sent_hi:-}" ]; then
        echo "  $tool sub=$variant: $word is not sent; the costs below are over the messages received"
    fi
    case "$tool" in
        strace | perfstat)
            if [ ! -s "$lo.$tool" ] || [ ! -s "$hi.$tool" ]; then
                echo "  $tool sub=$variant: NOT-MEASURED, $tool left no table (see $lo.sub and $hi.sub)"
                return 2
            fi
            rows="$(subprofile_table "$tool" "$lo.$tool" "$hi.$tool" "$messages")"
            if [ -z "$rows" ]; then
                echo "  $tool sub=$variant: NOT-MEASURED, $tool counted nothing (see $lo.$tool and $hi.$tool)"
                return 2
            fi
            echo "  $tool sub=$variant: per received message (n=$count past n=$base, over $messages messages):"
            echo "$rows"
            return 0
            ;;
    esac
    for stem in "$idle" "$lo" "$hi"; do
        window_lead_ok "$stem.pub" "$guard" "callgrind sub=$variant" || return 2
    done
    if ! cg_0="$(callgrind_window "$idle")" || ! cg_lo="$(callgrind_window "$lo")" \
        || ! cg_hi="$(callgrind_window "$hi")"; then
        echo "  callgrind sub=$variant: NOT-MEASURED, a subscriber left no window dump (see $idle.sub, $lo.sub and $hi.sub)"
        return 2
    fi
    ir_0="$(subprofile_ir "$cg_0")"
    ir_lo="$(subprofile_ir "$cg_lo")"
    ir_hi="$(subprofile_ir "$cg_hi")"
    recv_0="$(subprofile_number "$idle.sub" in_window)"
    if [ -z "$ir_0" ] || [ -z "$ir_lo" ] || [ -z "$ir_hi" ] || [ -z "$recv_0" ] || [ "$recv_hi" -le "$recv_0" ]; then
        echo "  callgrind sub=$variant: NOT-MEASURED, a window left no total or the idle run no count (see $idle.sub, $lo.sub and $hi.sub)"
        return 2
    fi
    per="$(awk -v a="$ir_lo" -v b="$ir_hi" -v m="$messages" 'BEGIN { printf "%.1f", (b - a) / m }')"
    net="$(awk -v a="$ir_0" -v b="$ir_hi" -v m="$((recv_hi - recv_0))" 'BEGIN { printf "%.1f", (b - a) / m }')"
    echo "  callgrind sub=$variant: Ir in the window n=0 $ir_0 (received $recv_0), n=$base $ir_lo, n=$count $ir_hi; per received message $per (n=$count past n=$base, over $messages messages); net $net (n=$count past the idle run, over $((recv_hi - recv_0)))"
    printf '%s\t%s\t%s\n' "$variant" "$per" "$net" >>"$run/per-message.tsv"
    for listing in no yes; do
        callgrind_annotate --threshold=100 --inclusive="$listing" "$cg_0" >"$idle.inclusive-$listing.txt" 2>&1
        callgrind_annotate --threshold=100 --inclusive="$listing" "$cg_lo" >"$lo.inclusive-$listing.txt" 2>&1
        callgrind_annotate --threshold=100 --inclusive="$listing" "$cg_hi" >"$hi.inclusive-$listing.txt" 2>&1
        echo "  callgrind sub=$variant: top 25 functions by Ir per received message, inclusive=$listing:"
        subprofile_table annotate "$lo.inclusive-$listing.txt" "$hi.inclusive-$listing.txt" "$messages" 25
    done
    echo "  callgrind sub=$variant: top 25 functions by Ir per received message net of the idle run, inclusive=no:"
    subprofile_table annotate "$idle.inclusive-no.txt" "$hi.inclusive-no.txt" $((recv_hi - recv_0)) 25
}

# subprofile_summary <per-message.tsv>: callgrind's two figures of each arm, P and W and W over P.
subprofile_summary() {
    python3 -I - "$1" <<'PY'
import sys

rows = {}
for line in open(sys.argv[1], encoding="utf-8"):
    arm, per, net = line.rstrip("\n").split("\t")
    rows[arm] = (float(per), float(net))


def show(arm, i):
    return f"{rows[arm][i]:>12.1f}" if arm in rows else f"{'-':>12}"


def ratio(i):
    return f"{rows['W'][i] / rows['P'][i]:>7.2f}" if "P" in rows and "W" in rows and rows["P"][i] else f"{'-':>7}"


print("  summary, callgrind Ir per received message (net: the larger run past the idle run of the same window):")
print(f"    {'':<10} {'P':>12} {'W':>12} {'W/P':>7}")
print(f"    {'per':<10} {show('P', 0)} {show('W', 0)} {ratio(0)}")
print(f"    {'net':<10} {show('P', 1)} {show('W', 1)} {ratio(1)}")
PY
}

subprofile() {
    local size="${1:-8}" count="${2:-12000}" rate="${3:-10000}" base="${PICO_CMP_SUBPROF_BASE:-2000}"
    local cg_rate="${PICO_CMP_SUBPROF_CALLGRIND_RATE:-1000}" wait_s="${PICO_CMP_SUBPROF_WAIT_S:-8}"
    local slack="${PICO_CMP_SUBPROF_SLACK_S:-10}" guard="${PICO_CMP_SUBPROF_GUARD_MS:-1000}"
    local run tool variant n lead trial_rate seconds listen status=0 counts=()
    for n in "$size" "$count" "$rate" "$base" "$cg_rate" "$wait_s" "$slack" "$guard"; do
        [[ "$n" =~ ^[0-9]+$ ]] || { echo "pico-compare: NOT-MEASURED, $n is not a whole number"; exit 2; }
    done
    [ "$rate" -gt 0 ] && [ "$cg_rate" -gt 0 ] && [ "$count" -gt "$base" ] \
        || { echo "pico-compare: NOT-MEASURED, a rate is 0 or [count] $count is not above PICO_CMP_SUBPROF_BASE $base"; exit 2; }
    # Under callgrind the publisher is connected and declared about two seconds before its first put
    # (subprofile_trial): a guard that long would open the window before it is.
    [ "$guard" -lt 2000 ] \
        || { echo "pico-compare: NOT-MEASURED, PICO_CMP_SUBPROF_GUARD_MS $guard is not under the publisher's 2000 ms lead"; exit 2; }
    bench_transport_ok || exit 2
    run="$out/subprofile-runs/host-$(date -u +%Y%m%dT%H%M%S)"
    mkdir -p "$run"
    : >"$run/per-message.tsv"
    {
        echo "tree=$(git rev-parse HEAD)"
        echo "host=$(hostname)"
        echo "kernel=$(uname -r)"
        echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
        echo "perf_event_paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
        echo "perf=$(perf --version 2>/dev/null)"
        echo "valgrind=$(valgrind --version 2>/dev/null)"
        echo "strace=$(strace -V 2>/dev/null | head -1)"
        echo "size=$size base=$base count=$count rate=$rate callgrind_rate=$cg_rate wait_s=$wait_s slack_s=$slack guard_ms=$guard"
        echo "transport=$bench_transport"
        echo "callgraph=${PICO_CMP_SUBPROF_CALLGRAPH:-dwarf} events=$SUBPROF_EVENTS"
        echo "sub_cpus=$sub_cpus pub_cpus=$pub_cpus wz_env=${wz_env:-none} wz_engine=$wz_engine"
    } >"$run/record.txt"
    echo "subscriber profile over $bench_transport, $size B, n=$base and n=$count over the seconds n=$count takes at $rate msg/s (callgrind $cg_rate, in a window with an idle run); subscriber on $sub_cpus, publisher on $pub_cpus; wz env: ${wz_env:-none}; wz engine: $wz_engine" \
        | tee -a "$run/report.txt"
    for tool in strace perfstat perfrecord callgrind; do
        if ! subprofile_has "$tool"; then
            echo "  $tool: NOT-MEASURED, the program it runs is not on PATH" | tee -a "$run/report.txt"
            status=2
            continue
        fi
        lead=2
        trial_rate="$rate"
        if [ "$tool" = callgrind ]; then
            lead="$wait_s"
            trial_rate="$cg_rate"
        fi
        counts=("$base" "$count")
        [ "$tool" = perfrecord ] && counts=("$count")
        [ "$tool" = callgrind ] && counts=(0 "$base" "$count")
        # One span of puts for every count of a tool (paced_pub takes whole seconds), and one listening time,
        # long enough for it.
        seconds=$(((count + trial_rate - 1) / trial_rate))
        listen=$((lead + 2 + seconds + slack))
        for variant in P W; do
            for n in "${counts[@]}"; do
                subprofile_trial "$tool" "$variant" "$n" "$seconds" "$size" "$listen" "$lead" "$slack" "$guard" \
                    "$run/$tool-$variant-$n"
            done
            subprofile_arm "$tool" "$variant" "$base" "$count" "$guard" "$run" >"$run/arm.txt" || status=2
            tee -a "$run/report.txt" <"$run/arm.txt"
            rm -f "$run/arm.txt"
        done
    done
    [ -s "$run/per-message.tsv" ] && subprofile_summary "$run/per-message.tsv" | tee -a "$run/report.txt"
    echo "pico-compare: subprofile run $run (report.txt, record.txt, per-message.tsv, the tables and tool files of each run)"
    return "$status"
}

# ── opprofile: what one operation costs, in instructions ───────────────────────────────────────────────────
#
# opprofile [ops] [size]: scripts/host-bench/op_probe.c of each library does one operation [count] times spread
# over PICO_CMP_OPPROF_SECONDS (20) under valgrind's callgrind, and again [base] times over the same seconds, so the
# library's load, the session's open and close and what it does by the clock cancel (subprofile's two counts):
# what the larger run executed past the smaller one, over the operations it did past the smaller, is what one
# operation costs. The operations (op_probe.c states each): put (the publisher's), get (the querier's wait for the
# final notification included) with the queryable that answers it counted in the same runs, declare-sub,
# declare-pub and declare-qbl (each with its undeclare), open (a session opened and closed) and none, the paced loop
# alone, whose cost every other operation carries and which the summary takes off the op role ("net"). The peer of
# every operation but get is count_sub of the same library, listening and not counted. [ops] is a comma list (all
# of them), [size] the payload of a put and of a reply (8). The counts: PICO_CMP_OPPROF_BASE and
# PICO_CMP_OPPROF_COUNT (2000 and 12000), PICO_CMP_OPPROF_GET_BASE and _GET_COUNT (200 and 1200),
# PICO_CMP_OPPROF_OPEN_BASE and _OPEN_COUNT (20 and 120). Each run's span begins at one instant both processes are
# given (-a, scripts/host-bench/bench_window.h), PICO_CMP_OPPROF_LEAD_S (8) and PICO_CMP_OPPROF_SETTLE_S (3) after
# the peer starts: the counted process connects after the lead and has the settle for the peer's declarations.
# The peer listens on a port of bench_port, outside the host's ephemeral range, and a peer gone by the end of the
# lead is started again on another (opprofile_trial).
#
# THE QUERYABLE'S COUNT IS A WINDOW. It listens the same time in every run, and that is not enough: before the
# querier connects and after it leaves it has no peer, and zenoh-pico's executor then polls its timers in a loop
# whose instructions follow how fast the host turned it, tens of millions a run and a different number in each,
# which the subtraction would charge to the queries (bench_window.h says where). So the queryable counts only from
# PICO_CMP_OPPROF_GUARD_MS (1000) before the instant to as long past the end of the span, inside the time the
# querier, which stays connected twice that past the span, is connected; and it runs a third time with no query in
# the same window (the idle run, count 0), so that its line has a net figure as the op role has one: the larger run
# past the idle one over its queries, beside the difference of the two counts. Beside them the line counts the
# executor's turns and link reads in each window (opprofile_turns): while the querier is connected the read task
# waits in the socket, so a turn a query is the library's own and a turn count far past the reads is a poll
# that the window did not keep out. The op role counts its whole
# process, which is connected from its start to its end. Both arms are built as subprofile's are (the wz arm in the
# form a release ships). Left under target/pico-compare/opprofile-runs/host-<time>/ (report.txt, record.txt,
# per-op.tsv, each run's files); exit 0 when every operation of both arms was measured, 2 when one was not.

OPPROF_OPS=put,get,declare-sub,declare-pub,declare-qbl,open,none

# The operations opprofile measures over multicast (PICO_CMP_TRANSPORT): the put the multicast cells of the
# performance matrix carry, and the paced loop its net is taken from; [ops] unset there means these.
OPPROF_GROUP_OPS=put,none

# opprofile_counts <op>: the smaller and the larger count of <op>.
opprofile_counts() {
    case "$1" in
        get) echo "${PICO_CMP_OPPROF_GET_BASE:-200} ${PICO_CMP_OPPROF_GET_COUNT:-1200}" ;;
        open) echo "${PICO_CMP_OPPROF_OPEN_BASE:-20} ${PICO_CMP_OPPROF_OPEN_COUNT:-120}" ;;
        *) echo "${PICO_CMP_OPPROF_BASE:-2000} ${PICO_CMP_OPPROF_COUNT:-12000}" ;;
    esac
}

# opprofile_trial <op> <variant> <count> <size> <seconds> <lead> <settle> <guard> <stem>: one run of op_probe doing
# <op> <count> times under callgrind, its span beginning <lead> + <settle> seconds from its peer's start, and of its
# peer: the queryable of the same library, under callgrind too and counting the window around the span, for get;
# count_sub, not counted, for the others. The operation's session stays open 2 x <guard> ms past the span, past the
# window. A peer that is gone when the lead ends did not open its session, and op_probe, which connects to it,
# would not open its own: the trial starts again on another port, up to PICO_CMP_OPPROF_TRIES (3) times, each
# attempt a line of the report, and after the last leaves <stem>.op saying so and returns 3. Leaves <stem>.op,
# <stem>.callgrind, <stem>.peer and, for get, the queryable's <stem>.peer.callgrind.<part> (the window) and
# <stem>.peer.callgrind (what followed it).
opprofile_trial() {
    local op="$1" variant="$2" count="$3" size="$4" seconds="$5" lead="$6" settle="$7" guard="$8" stem="$9"
    local port listen peer start try tries="${PICO_CMP_OPPROF_TRIES:-3}"
    listen=$((lead + settle + seconds + 15))
    for try in $(seq 1 "$tries"); do
        port="$(bench_port)"
        bench_ends "$port"
        start=$(($(monotonic_ns) + (lead + settle) * 1000000000))
        rm -f "$stem".peer.callgrind*
        if [ "$op" = get ]; then
            compose "$variant" "$sub_cpus" timeout $((listen + 120)) valgrind --tool=callgrind \
                "--callgrind-out-file=$stem.peer.callgrind" "--zero-before=bench_window_open*" \
                "--dump-before=bench_window_close*" "$out/bin/op_probe_$variant" -o queryable -m peer \
                "${LISTEN_END[@]}" -s "$size" -d "$listen" -a "$start" -t "$seconds" -g "$guard"
        else
            compose "$variant" "$sub_cpus" timeout $((listen + 60)) "$out/bin/count_sub_$variant" -m peer \
                "${LISTEN_END[@]}" -d "$listen"
        fi
        "${CMD[@]}" >"$stem.peer" 2>&1 &
        peer=$!
        sleep "$lead"
        peer_alive "$peer" && break
        wait "$peer" 2>/dev/null
        echo "  op=$op arm=$variant n=$count: the peer on ${LISTEN_END[1]} was gone before the count (try $try of $tries); it said: $(grep -v '^==' "$stem.peer" 2>/dev/null | tail -n 1)" \
            | tee -a "${stem%/*}/report.txt"
        if [ "$try" -eq "$tries" ]; then
            echo "pico-compare: op_probe not run, its peer did not stay up in $tries tries (see ${stem##*/}.peer)" >"$stem.op"
            return 3
        fi
    done
    compose "$variant" "$pub_cpus" timeout $((settle + seconds + 300)) valgrind --tool=callgrind \
        "--callgrind-out-file=$stem.callgrind" "$out/bin/op_probe_$variant" -o "$op" -m peer \
        "${SEND_END[@]}" -n "$count" -t "$seconds" -a "$start" -g $((2 * guard)) -s "$size"
    "${CMD[@]}" >"$stem.op" 2>&1
    # count_sub is not counted, so it need not listen out its time; the queryable is, and does.
    [ "$op" = get ] || kill "$peer" 2>/dev/null
    wait "$peer" 2>/dev/null
}

# opprofile_tables <ops> <lo stem> <hi stem> <lo file> <hi file>: callgrind_annotate of two counted files, left
# beside their stems, and the top 20 functions by Ir per operation, self, of the upper past the lower.
opprofile_tables() {
    local ops="$1" lo="$2" hi="$3" lo_file="$4" hi_file="$5" listing
    for listing in no yes; do
        callgrind_annotate --threshold=100 --inclusive="$listing" "$lo_file" >"$lo.inclusive-$listing.txt" 2>&1
        callgrind_annotate --threshold=100 --inclusive="$listing" "$hi_file" >"$hi.inclusive-$listing.txt" 2>&1
    done
    subprofile_table annotate "$lo.inclusive-no.txt" "$hi.inclusive-no.txt" "$ops" 20
}

# opprofile_role <op> <variant> <lo stem> <hi stem> <ops> <base> <count> <run>: the line of the operation's process
# of one arm (op_probe doing <op>), its per-operation instructions appended to <run>/per-op.tsv, and its top
# functions; returns 2 when it was not measured.
opprofile_role() {
    local op="$1" variant="$2" lo="$3" hi="$4" ops="$5" base="$6" count="$7" run="$8"
    local ir_lo ir_hi per
    ir_lo="$(subprofile_ir "$lo.callgrind")"
    ir_hi="$(subprofile_ir "$hi.callgrind")"
    if [ -z "$ir_lo" ] || [ -z "$ir_hi" ]; then
        echo "  op=$op arm=$variant role=op: NOT-MEASURED, callgrind left no total (see $lo and $hi)"
        return 2
    fi
    per="$(awk -v a="$ir_lo" -v b="$ir_hi" -v m="$ops" 'BEGIN { printf "%.1f", (b - a) / m }')"
    echo "  op=$op arm=$variant role=op: Ir n=$base $ir_lo, n=$count $ir_hi; per operation $per (over $ops)"
    printf '%s\t%s\t%s\t%s\t%s\n' "$op" "$variant" op "$per" - >>"$run/per-op.tsv"
    echo "  op=$op arm=$variant role=op: top 20 functions by Ir per operation, self (inclusive=no):"
    opprofile_tables "$ops" "$lo" "$hi" "$lo.callgrind" "$hi.callgrind"
    return 0
}

# opprofile_executor_fn <turn|read> <variant>: the function each turn of the arm's executor calls once, and the task
# a turn runs when its link has bytes: zenoh-pico's background executor calls _z_executor_spin once a turn and the
# unicast read task from it; wz's cooperative executor makes one pass over its task table a turn, and no read
# function is named for it unless PICO_CMP_OPPROF_READ_W names one. PICO_CMP_OPPROF_TURN_<P|W> and
# PICO_CMP_OPPROF_READ_P name others.
opprofile_executor_fn() {
    case "$1-$2" in
        turn-P) echo "${PICO_CMP_OPPROF_TURN_P:-_z_executor_spin}" ;;
        read-P) echo "${PICO_CMP_OPPROF_READ_P:-_zp_unicast_read_task_fn}" ;;
        turn-W) echo "${PICO_CMP_OPPROF_TURN_W:-<wz_runtime_coop::executor::ExecutorState>::run_among}" ;;
        *) echo "${PICO_CMP_OPPROF_READ_W:-}" ;;
    esac
}

# opprofile_turns <variant> <idle file> <lo file> <hi file> <in idle> <in hi> <base> <count>: the lines of the
# queryable's executor turns and link reads in each window, and each per query, the larger run past the idle run
# over the queries it answered past it. A turn per read is a turn of work; turns well past the reads are an
# executor that polled the clock in the window (bench_window.h), which counts as the host turned it.
opprofile_turns() {
    local variant="$1" cg_0="$2" cg_lo="$3" cg_hi="$4" in_0="$5" in_hi="$6" base="$7" count="$8"
    local what fn n_0 n_lo n_hi
    for what in turn read; do
        fn="$(opprofile_executor_fn "$what" "$variant")"
        [ -n "$fn" ] || continue
        n_0="$(callgrind_calls "$cg_0" "$fn")"
        n_lo="$(callgrind_calls "$cg_lo" "$fn")"
        n_hi="$(callgrind_calls "$cg_hi" "$fn")"
        if [ -z "$n_0" ] || [ -z "$n_lo" ] || [ -z "$n_hi" ] || [ "$n_hi" = 0 ]; then
            echo "  op=get arm=$variant role=peer: no call of $fn in the window (PICO_CMP_OPPROF_${what^^}_$variant names the $what function)"
            continue
        fi
        echo "  op=get arm=$variant role=peer: $what calls ($fn) in the window n=0 $n_0, n=$base $n_lo, n=$count $n_hi; per query $(awk -v a="$n_0" -v b="$n_hi" -v m="$((in_hi - in_0))" 'BEGIN { printf "%.2f", (b - a) / m }') (n=$count past the idle run)"
    done
}

# opprofile_peer <variant> <idle stem> <lo stem> <hi stem> <base> <count> <guard> <run>: the queryable's line of one
# arm, from the windows of its three runs: per query the larger run past the smaller over the queries it answered
# past them, and net the larger past the idle run over its own; both appended to <run>/per-op.tsv, with the top
# functions of each; returns 2 when it was not measured.
opprofile_peer() {
    local variant="$1" idle="$2" lo="$3" hi="$4" base="$5" count="$6" guard="$7" run="$8"
    local stem cg_0 cg_lo cg_hi ir_0 ir_lo ir_hi in_0 in_lo in_hi per net listing
    for stem in "$idle" "$lo" "$hi"; do
        window_lead_ok "$stem.op" "$guard" "op=get arm=$variant role=peer" || return 2
        if [ "$(subprofile_number "$stem.peer" in_window)" != "$(subprofile_number "$stem.peer" answered)" ]; then
            echo "  op=get arm=$variant role=peer: ${stem##*/} answered a query outside its window; the costs below are over the queries inside it"
        fi
    done
    if ! cg_0="$(callgrind_window "$idle.peer")" || ! cg_lo="$(callgrind_window "$lo.peer")" \
        || ! cg_hi="$(callgrind_window "$hi.peer")"; then
        echo "  op=get arm=$variant role=peer: NOT-MEASURED, a queryable left no window dump (see $idle.peer, $lo.peer and $hi.peer)"
        return 2
    fi
    ir_0="$(subprofile_ir "$cg_0")"
    ir_lo="$(subprofile_ir "$cg_lo")"
    ir_hi="$(subprofile_ir "$cg_hi")"
    in_0="$(subprofile_number "$idle.peer" in_window)"
    in_lo="$(subprofile_number "$lo.peer" in_window)"
    in_hi="$(subprofile_number "$hi.peer" in_window)"
    if [ -z "$ir_0" ] || [ -z "$ir_lo" ] || [ -z "$ir_hi" ] || [ -z "$in_0" ] || [ -z "$in_lo" ] || [ -z "$in_hi" ] \
        || [ "$in_hi" -le "$in_lo" ] || [ "$in_lo" -le "$in_0" ]; then
        echo "  op=get arm=$variant role=peer: NOT-MEASURED, a window left no total, or the queryable did not answer more in each larger run (in the window: n=0 ${in_0:-?}, n=$base ${in_lo:-?}, n=$count ${in_hi:-?})"
        return 2
    fi
    per="$(awk -v a="$ir_lo" -v b="$ir_hi" -v m="$((in_hi - in_lo))" 'BEGIN { printf "%.1f", (b - a) / m }')"
    net="$(awk -v a="$ir_0" -v b="$ir_hi" -v m="$((in_hi - in_0))" 'BEGIN { printf "%.1f", (b - a) / m }')"
    echo "  op=get arm=$variant role=peer: Ir in the window n=0 $ir_0, n=$base $ir_lo, n=$count $ir_hi; per query $per (over $((in_hi - in_lo))); net $net (n=$count past the idle run, over $((in_hi - in_0)))"
    printf '%s\t%s\t%s\t%s\t%s\n' get "$variant" peer "$per" "$net" >>"$run/per-op.tsv"
    opprofile_turns "$variant" "$cg_0" "$cg_lo" "$cg_hi" "$in_0" "$in_hi" "$base" "$count"
    echo "  op=get arm=$variant role=peer: top 20 functions by Ir per query, self (inclusive=no):"
    opprofile_tables "$((in_hi - in_lo))" "$lo.peer" "$hi.peer" "$cg_lo" "$cg_hi"
    for listing in no yes; do
        callgrind_annotate --threshold=100 --inclusive="$listing" "$cg_0" >"$idle.peer.inclusive-$listing.txt" 2>&1
    done
    echo "  op=get arm=$variant role=peer: top 20 functions by Ir per query net of the idle run, self (inclusive=no):"
    subprofile_table annotate "$idle.peer.inclusive-no.txt" "$hi.peer.inclusive-no.txt" "$((in_hi - in_0))" 20
    return 0
}

# opprofile_arm <op> <variant> <base> <count> <guard> <run>: the lines of one operation of one arm; returns 2 when
# it was not measured.
opprofile_arm() {
    local op="$1" variant="$2" base="$3" count="$4" guard="$5" run="$6"
    local lo="$run/$op-$variant-$base" hi="$run/$op-$variant-$count"
    local done_lo done_hi late_lo late_hi status=0
    done_lo="$(subprofile_number "$lo.op" "done")"
    done_hi="$(subprofile_number "$hi.op" "done")"
    echo "  op=$op arm=$variant: n=$base: $(tail -n 1 "$lo.op" 2>/dev/null); n=$count: $(tail -n 1 "$hi.op" 2>/dev/null)"
    if [ -z "$done_lo" ] || [ -z "$done_hi" ] || [ "$done_hi" -le "$done_lo" ]; then
        echo "  op=$op arm=$variant: NOT-MEASURED, the larger run did not do more operations than the smaller one"
        echo "    op_probe said: $(tail -n 2 "$hi.op" 2>/dev/null | tr '\n' '|')"
        echo "    its peer said: $(tail -n 2 "$hi.peer" 2>/dev/null | tr '\n' '|')"
        return 2
    fi
    late_lo="$(subprofile_number "$lo.op" late)"
    late_hi="$(subprofile_number "$hi.op" late)"
    # A late operation stretched its run past the seconds both runs were to take, and what the session does by the
    # clock no longer cancels: the figure stands, the line says it carries that.
    if [ "${late_lo:-0}" != 0 ] || [ "${late_hi:-0}" != 0 ]; then
        echo "  op=$op arm=$variant: operations were late (n=$base ${late_lo:-?}, n=$count ${late_hi:-?}); the runs' times differ by that"
    fi
    if [ "$op" = get ] && { [ "$(subprofile_number "$lo.op" replies)" != "$done_lo" ] \
        || [ "$(subprofile_number "$hi.op" replies)" != "$done_hi" ]; }; then
        echo "  op=$op arm=$variant: a get finished without its reply; the costs below are over the gets done"
    fi
    opprofile_role "$op" "$variant" "$lo" "$hi" $((done_hi - done_lo)) "$base" "$count" "$run" || status=2
    if [ "$op" = get ]; then
        opprofile_peer "$variant" "$run/get-$variant-0" "$lo" "$hi" "$base" "$count" "$guard" "$run" || status=2
    fi
    return "$status"
}

# opprofile_summary <per-op.tsv>: each operation's instructions for P and W, W over P, and net: for the op role
# its figure less the paced loop's (op=none, of the same arm), for the peer role the larger run past the idle run.
opprofile_summary() {
    python3 -I - "$1" <<'PY'
import sys

rows = {}
for line in open(sys.argv[1], encoding="utf-8"):
    op, arm, role, per, net = line.rstrip("\n").split("\t")
    rows[(op, role, arm)] = (float(per), None if net == "-" else float(net))
loop = {arm: rows[("none", "op", arm)][0] if ("none", "op", arm) in rows else None for arm in "PW"}


def show(value, width):
    return f"{value:>{width}.1f}" if value is not None else f"{'-':>{width}}"


def ratio(a, b, width):
    return f"{b / a:>{width}.2f}" if a and b is not None else f"{'-':>{width}}"


print("  summary, Ir per operation (net: the op role less the paced loop, op=none, of the same arm; the peer role")
print("  the larger run past the idle run of the same window):")
print(f"    {'operation':<16} {'role':<5} {'P':>12} {'W':>12} {'W/P':>7} {'P net':>12} {'W net':>12} {'W/P net':>8}")
for op, role in sorted({(op, role) for op, role, _ in rows}):
    if op == "none":
        continue
    per, net = {}, {}
    for arm in "PW":
        value, over_idle = rows.get((op, role, arm), (None, None))
        per[arm] = value
        if role == "op":
            net[arm] = value - loop[arm] if value is not None and loop[arm] is not None else None
        else:
            net[arm] = over_idle
    print(f"    {op:<16} {role:<5} {show(per['P'], 12)} {show(per['W'], 12)} {ratio(per['P'], per['W'], 7)} "
          f"{show(net['P'], 12)} {show(net['W'], 12)} {ratio(net['P'], net['W'], 8)}")
PY
}

opprofile() {
    local ops="${1:-$OPPROF_OPS}" size="${2:-8}" seconds="${PICO_CMP_OPPROF_SECONDS:-20}"
    local lead="${PICO_CMP_OPPROF_LEAD_S:-8}" settle="${PICO_CMP_OPPROF_SETTLE_S:-3}"
    local guard="${PICO_CMP_OPPROF_GUARD_MS:-1000}"
    local run op variant n base count status=0 list=() counts=()
    for n in "$size" "$seconds" "$lead" "$settle" "$guard" "${PICO_CMP_OPPROF_TRIES:-3}"; do
        [[ "$n" =~ ^[0-9]+$ ]] || { echo "pico-compare: NOT-MEASURED, $n is not a whole number"; exit 2; }
    done
    [ "${PICO_CMP_OPPROF_TRIES:-3}" -ge 1 ] \
        || { echo "pico-compare: NOT-MEASURED, PICO_CMP_OPPROF_TRIES is 0, and a run needs one try"; exit 2; }
    # The querier opens its session in the settle; a guard as long would open the queryable's window first.
    [ "$guard" -lt $((settle * 1000)) ] \
        || { echo "pico-compare: NOT-MEASURED, PICO_CMP_OPPROF_GUARD_MS $guard is not under PICO_CMP_OPPROF_SETTLE_S $settle"; exit 2; }
    if ! subprofile_has callgrind; then
        echo "pico-compare: NOT-MEASURED, valgrind or callgrind_annotate is not on PATH"
        exit 2
    fi
    bench_transport_ok || exit 2
    [ -n "${1:-}" ] || [ "$bench_transport" != multicast ] || ops="$OPPROF_GROUP_OPS"
    IFS=, read -r -a list <<<"$ops"
    for op in "${list[@]}"; do
        case ",$OPPROF_OPS," in
            *",$op,"*) ;;
            *) echo "pico-compare: NOT-MEASURED, $op is not one of $OPPROF_OPS"; exit 2 ;;
        esac
        case ",$OPPROF_GROUP_OPS," in
            *",$op,"*) ;;
            *) if [ "$bench_transport" = multicast ]; then
                   echo "pico-compare: NOT-MEASURED, $op is not measured over multicast, only $OPPROF_GROUP_OPS"
                   exit 2
               fi ;;
        esac
        read -r base count <<<"$(opprofile_counts "$op")"
        [[ "$base" =~ ^[0-9]+$ ]] && [[ "$count" =~ ^[0-9]+$ ]] && [ "$count" -gt "$base" ] \
            || { echo "pico-compare: NOT-MEASURED, the counts of $op ($base, $count) are not two whole numbers, the second larger"; exit 2; }
        if [ "$op" = get ] && [ "$base" -eq 0 ]; then
            echo "pico-compare: NOT-MEASURED, PICO_CMP_OPPROF_GET_BASE is 0, the count of the idle run"
            exit 2
        fi
    done
    run="$out/opprofile-runs/host-$(date -u +%Y%m%dT%H%M%S)"
    mkdir -p "$run"
    : >"$run/per-op.tsv"
    {
        echo "tree=$(git rev-parse HEAD)"
        echo "host=$(hostname)"
        echo "kernel=$(uname -r)"
        echo "cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
        echo "valgrind=$(valgrind --version 2>/dev/null)"
        echo "ops=$ops size=$size seconds=$seconds lead_s=$lead settle_s=$settle guard_ms=$guard"
        echo "transport=$bench_transport"
        for op in "${list[@]}"; do
            echo "counts $op=$(opprofile_counts "$op")"
        done
        echo "op_cpus=$pub_cpus peer_cpus=$sub_cpus wz_env=${wz_env:-none}"
        echo "pico_lib=$pico_lib"
        echo "wz=$wz_engine"
    } >"$run/record.txt"
    echo "instructions per operation over $bench_transport, $size B, ops $ops over $seconds s a run; operation on $pub_cpus, peer on $sub_cpus; wz env: ${wz_env:-none}; wz arm: $wz_engine" \
        | tee -a "$run/report.txt"
    for op in "${list[@]}"; do
        read -r base count <<<"$(opprofile_counts "$op")"
        counts=("$base" "$count")
        # The queryable's idle run: the same window with no query in it.
        [ "$op" = get ] && counts=(0 "$base" "$count")
        for variant in P W; do
            for n in "${counts[@]}"; do
                opprofile_trial "$op" "$variant" "$n" "$size" "$seconds" "$lead" "$settle" "$guard" "$run/$op-$variant-$n"
            done
            opprofile_arm "$op" "$variant" "$base" "$count" "$guard" "$run" >"$run/arm.txt" || status=2
            tee -a "$run/report.txt" <"$run/arm.txt"
            rm -f "$run/arm.txt"
        done
    done
    opprofile_summary "$run/per-op.tsv" | tee -a "$run/report.txt"
    echo "pico-compare: opprofile run $run (report.txt, record.txt, per-op.tsv, each run's files)"
    return "$status"
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
# The paced pair of the throughput cell (parity.py's no-drop search), scripts/host-bench's C sources, built for the
# C families against each arm's library as the examples are; the Rust family has none.
PARITY_BENCHES=(paced_pub count_sub)

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

# The wz build of an original's preset, configs/<original>_defconfig alone, as the one resolver gives every build
# (`wz_config.py --resolve-build <abi>` with no preset): the cargo arguments on its first line, then the
# WZ_LIMIT_<NAME>=<n> and WZ_POLICY_<NAME>=<value> lines the build runs under, without which it would hold every
# build constant at its host default and not at the value the defconfig sets. Each helper runs in a command
# substitution, so a refusal goes to stderr and the caller exits.
parity_preset_build() {
    local abi
    case "$1" in
        zenoh-pico) abi=pico ;;
        zenoh-c) abi=c ;;
        zenoh) abi=core ;;
        *) echo "pico-compare: no ABI builds the original $1" >&2; return 2 ;;
    esac
    python3 -I scripts/lib/wz_config.py --resolve-build "$abi" \
        || { echo "pico-compare: NOT-MEASURED, configs/$1_defconfig did not resolve (wz_config.py --resolve-build $abi)" >&2; return 2; }
}

# The cargo arguments of that build.
parity_preset_args() {
    local build
    build="$(parity_preset_build "$1")" || return 2
    printf '%s\n' "${build%%$'\n'*}"
}

# The limits and policies of that build, one a line; none when it sets none.
parity_preset_env() {
    local build
    build="$(parity_preset_build "$1")" || return 2
    [[ "$build" != *$'\n'* ]] || printf '%s\n' "${build#*$'\n'}"
}

# zenoh-pico: the original is upstream's DEFAULT build (no switch passed; build-zenoh-pico-cli.sh configures that arm
# as `zenoh-pico-build-default`, and this builds its shared library), wz is wz-capi-pico built for
# configs/zenoh-pico_defconfig, under the limits and policies it sets, in the form the pico C ABI's release ships, or
# the one PICO_CMP_STDLIB names (perf_matrix.py bench-stdlib), as the size gate builds that form (perf_matrix.py
# preset-arm, which applies what parity_preset_env gives the other families): a C library has no
# unwinder and no symbolizer of its own, and the library with `std` carries both. The programs are compiled
# against the default arm's headers.
parity_build_pico() {
    local dir="$1" default="$WZ_ARTIFACTS/target/zenoh-pico-build-default" stdlib built lib_p example variant name
    bash scripts/build-zenoh-pico-cli.sh >"$dir/build-pico.log" 2>&1 \
        || parity_fail "the pico arms did not configure (see $dir/build-pico.log)"
    cmake --build "$default" --target zenohpico_shared -j"$(nproc)" >>"$dir/build-pico.log" 2>&1 \
        || parity_fail "pico's default arm did not build (see $dir/build-pico.log)"
    lib_p="$(find "$default" -name 'libzenohpico.so' -print -quit)"
    [ -n "$lib_p" ] || parity_fail "no libzenohpico.so under $default"
    stdlib="$(python3 -I "$root/scripts/host-bench/perf_matrix.py" bench-stdlib ${PICO_CMP_STDLIB:+"$PICO_CMP_STDLIB"})" \
        || parity_fail "the standard library of the wz preset did not resolve (bench-stdlib said why above)"
    built="$(python3 -I "$root/scripts/host-bench/perf_matrix.py" preset-arm --out "$dir" --original zenoh-pico \
        --stdlib "$stdlib")" \
        || parity_fail_log "$dir/build-wz.log" "wz-capi-pico-lib was not built for the preset: $built"
    cp -a "$(dirname "$lib_p")"/libzenohpico.so* "$dir/lib-P/" || parity_fail "the pico library did not copy"
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
    for example in "${PARITY_BENCHES[@]}"; do
        for variant in P W; do
            name=zenohpico
            [ "$variant" = W ] && name=wz_capi_pico
            cc -std=gnu11 -O2 "$root/scripts/host-bench/$example.c" -DZENOH_LINUX \
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
$built"
}

# zenoh-c: the original is upstream's default build from the pinned source (install-zenoh-c-arm.sh nounstable: cmake
# Release, ZENOHC_BUILD_WITH_UNSTABLE_API and ZENOHC_BUILD_WITH_SHARED_MEMORY at their default FALSE, upstream's
# own pinned toolchain), wz is wz-capi-c built for configs/zenoh-c_defconfig. The programs are upstream's examples
# of the pinned source, compiled against the original's headers.
parity_build_c() {
    local dir="$1" prefix="$WZ_ARTIFACTS/target/zenoh-c-nounstable" ref="${WZ_ZENOH_C_REF:-$HOME/zenoh-c-ref}"
    local args env_lines drop_in example variant name
    local -a build_env=()
    if [ ! -f "$ref/examples/z_ping.c" ]; then
        WZ_ZENOH_C_REF="$ref" bash scripts/install-zenoh-c.sh >"$dir/build-zenoh-c-source.log" 2>&1 \
            || parity_fail "the zenoh-c source did not install (see $dir/build-zenoh-c-source.log)"
    fi
    WZ_ZENOH_C_REF="$ref" bash scripts/install-zenoh-c-arm.sh nounstable "$prefix" >"$dir/build-zenoh-c.log" 2>&1 \
        || parity_fail "zenoh-c's default arm did not build (see $dir/build-zenoh-c.log)"
    args="$(parity_preset_args zenoh-c)" || exit 2
    env_lines="$(parity_preset_env zenoh-c)" || exit 2
    [ -z "$env_lines" ] || mapfile -t build_env <<<"$env_lines"
    drop_in="$(python3 -I scripts/lib/wz_config.py --drop-in-features c "$prefix/include/zenoh_configure.h" 2>&1)" \
        || drop_in="not derived: $drop_in"
    # shellcheck disable=SC2086 # the cargo arguments are words on purpose
    (cd crates && env "${build_env[@]}" cargo build --profile "$wz_profile" -p wz-capi-c $args) >"$dir/build-wz.log" 2>&1 \
        || parity_fail "wz-capi-c did not build for the preset (see $dir/build-wz.log)"
    cp -a "$prefix/lib"/libzenohc.so* "$dir/lib-P/" || parity_fail "the zenoh-c library did not copy"
    cp "$wz_lib/libwz_capi_c.so" "$dir/lib-W/" || parity_fail "the wz library did not copy"
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
    for example in "${PARITY_BENCHES[@]}"; do
        for variant in P W; do
            name=zenohc
            [ "$variant" = W ] && name=wz_capi_c
            cc -std=gnu11 -O2 -DBENCH_ZENOHC "$root/scripts/host-bench/$example.c" -I"$prefix/include" \
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
wz_build_env=${build_env[*]}
wz_drop_in_args_for_the_original_header=$drop_in"
}

# zenoh: upstream's examples package of the pinned tree, generated twice (z8_upstream_suite.py examples): `stock`
# over upstream's zenoh from the registry, `wz` with the family patched in and wz-capi-core given the preset's
# features. One manifest but for that, upstream's release profile and Cargo.lock, the repository's compiler.
# parity_build_rust <dir> [program...]: the programs built, PARITY_PROGRAMS when none is named (`fanin` names
# its own, which the package holds beside upstream's).
parity_build_rust() {
    local dir="$1" args env_lines feats arm variant pkg example programs=() wanted=() build_env=() arm_env=()
    shift
    wanted=("$@")
    [ "${#wanted[@]}" -gt 0 ] || wanted=("${PARITY_PROGRAMS[@]}")
    args="$(parity_preset_args zenoh)" || exit 2
    env_lines="$(parity_preset_env zenoh)" || exit 2
    [ -z "$env_lines" ] || mapfile -t build_env <<<"$env_lines"
    feats="$(sed -n 's/.*--features \([^ ]*\).*/\1/p' <<<"$args")"
    for example in "${wanted[@]}"; do
        programs+=(--example "$example")
    done
    for arm in stock wz; do
        variant=P
        arm_env=()
        if [ "$arm" = wz ]; then
            variant=W
            arm_env=("${build_env[@]}")
        fi
        pkg="$(python3 -I scripts/lib/z8_upstream_suite.py examples --arm "$arm" --core-features "$feats" 2>"$dir/generate-$arm.log")" \
            || parity_fail "the $arm examples package was not generated (see $dir/generate-$arm.log)"
        # The package's directory is the last line printed (a first clone of the tree may print before it).
        pkg="${pkg##*$'\n'}"
        [ -f "$pkg/Cargo.toml" ] || parity_fail "the $arm examples package is not at '$pkg'"
        (cd "$pkg" && env "${arm_env[@]}" cargo build --release --target-dir "$pkg/target" "${programs[@]}") \
            >"$dir/build-rust-$arm.log" 2>&1 \
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
wz_cargo_args=wz-capi-core features $feats (from: $args), unified with what the family's crates select
wz_build_env=${build_env[*]}"
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
    cc -O2 -o "$dir/bin/fork_rss" "$root/scripts/host-bench/fork_rss.c" 2>"$dir/build-fork-rss.log" \
        || parity_fail "the launcher that reads a peak resident set did not build (see $dir/build-fork-rss.log)"
    "parity_build_$family" "$dir"
    tag="host-$family-$(date -u +%Y%m%dT%H%M%S)"
    run="$out/parity-runs/$tag"
    python3 -I "$root/scripts/host-bench/parity.py" --family "$family" --bin-dir "$dir/bin" --run "$run" \
        --boots "$boots" --sizes "$sizes" --image "$PARITY_IMAGE" --reference "$PARITY_REFERENCE" \
        --client-cpus "$client_cpus" --server-cpus "$server_cpus" \
        --pings "${PICO_CMP_PINGS:-20000}" --warmup-s "${PICO_CMP_WARMUP_S:-3}" --window-s "${PICO_CMP_WINDOW_S:-10}" \
        --nodrop-trial-s "${PICO_CMP_NODROP_TRIAL_S:-3}" \
        --heap-shim "$dir/bin/heap_peak.so" --rss-wrapper "$dir/bin/fork_rss" \
        --size-binary "P=$PARITY_SIZE_P" --size-binary "W=$PARITY_SIZE_W"
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
        echo "client_cpus=$client_cpus server_cpus=$server_cpus"
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
# zenoh-pico built as the same build as wz-capi-pico's default capabilities on the engine and with the standard
# library resolved above (the capability cost gate's reference, which perf_matrix.py reference builds or finds,
# by the gate's rule for that form), perf_probe_W against that wz-capi-pico build and perf_probe_Wapp against it
# with the `app-transport` capability, the one arm that carries the program transport cell; both wz builds are
# made as the size gate makes the case of their form (perf_matrix.py wz-arm). Each arm's library is copied
# beside it (lib-<arm>), so a later build of the same crate does not change what a run measured. Both wz probes
# are built with PERF_WZ_ARM and wz_ext.h, so their sessions state the counts the roles hold (perf_probe.c).
# PICO_CMP_NO_BUILD=1 runs the programs already there.

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

# perf_wz_arm <dir> <arm> <features>: wz-capi-pico-lib built as pico_form says for its default features and <features> (a comma
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
    (cd crates && cargo build "${wz_pico_args[@]}" --message-format=json-render-diagnostics -p zenoh-pico-sys \
        -p wz-capi-pico-lib $args) >"$report" 2>"$dir/build-wz-$arm.log" \
        || perf_fail "wz-capi-pico-lib for arm $arm did not build (see $dir/build-wz-$arm.log)"
    inc="$(python3 -I "$root/scripts/host-bench/perf_matrix.py" pico-sys-include "$report")" \
        || perf_fail "the build of arm $arm named no single pico header arm"
    rm -rf "$dir/include-$arm" "$dir/lib-$arm"
    mkdir -p "$dir/include-$arm" "$dir/lib-$arm"
    cp -R "$inc"/. "$dir/include-$arm"/ || perf_fail "the pico headers of arm $arm did not copy"
    python3 -I scripts/lib/wz_config.py --bench-config-h "$wz_engine" ${features:+"$features"} \
        >"$dir/include-$arm/zenoh-pico/config.h" \
        || perf_fail "the config.h of arm $arm did not render (wz_config.py --bench-config-h $wz_engine '$features')"
    cp "$wz_pico_lib/libwz_capi_pico.so" "$dir/lib-$arm/" || perf_fail "the library of arm $arm did not copy"
}

# recorded_engine <reference.json>: the engine arm W was built on, as the record of its build states it.
recorded_engine() {
    python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("wz_engine", "unknown"))' \
        "$1" 2>/dev/null || echo unknown
}

# recorded_stdlib <reference.json>: the standard library arm W was built with, as the record of its build states it.
recorded_stdlib() {
    python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("wz_stdlib", "unknown"))' \
        "$1" 2>/dev/null || echo unknown
}

# The standard library the perf matrix builds the wz library with, as the engine above: PICO_CMP_STDLIB when it names
# one, else the form the release ships. With PICO_CMP_NO_BUILD=1 it is the one the build found records, and a
# PICO_CMP_STDLIB that names another is refused.
wz_stdlib=""
resolve_wz_stdlib() {
    wz_stdlib="$(python3 -I "$root/scripts/host-bench/perf_matrix.py" bench-stdlib ${PICO_CMP_STDLIB:+"$PICO_CMP_STDLIB"})" \
        || perf_fail "the standard library of the wz library did not resolve"
}

stamped_stdlib() {
    wz_stdlib="${1:-unknown}"
    if [ -n "${PICO_CMP_STDLIB:-}" ] && [ "$PICO_CMP_STDLIB" != "$wz_stdlib" ]; then
        echo "pico-compare: PICO_CMP_STDLIB=$PICO_CMP_STDLIB, and the library PICO_CMP_NO_BUILD=1 finds is built $wz_stdlib" >&2
        exit 2
    fi
}

# perf_matrix_wz_arm <dir> <arm> <features>: arm <arm> of the perf matrix, wz-capi-pico on $wz_engine with $wz_stdlib
# and <features> (a comma list, empty for none) over its default capabilities, built as the size gate builds the case
# of that form, its library in <dir>/lib-<arm> and its headers in <dir>/include-<arm> (perf_matrix.py wz-arm, which
# prints why when it builds nothing).
perf_matrix_wz_arm() {
    local dir="$1" arm="$2" features="$3"
    python3 -I "$root/scripts/host-bench/perf_matrix.py" wz-arm --out "$dir" --arm "$arm" --engine "$wz_engine" \
        --stdlib "$wz_stdlib" ${features:+--features "$features"} \
        || perf_fail "arm $arm was not built (perf_matrix.py wz-arm said why above)"
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
# lists of perf_matrix.py's words); the pinning is parity's (pin_sides above). The
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
        resolve_wz_stdlib
        python3 -I "$root/scripts/host-bench/perf_matrix.py" reference --out "$dir" --engine "$wz_engine" \
            --stdlib "$wz_stdlib" >"$dir/build-reference.log" 2>&1 \
            || perf_fail "the zenoh-pico reference did not build (see $dir/build-reference.log)"
        cat "$dir/build-reference.log"
        perf_matrix_wz_arm "$dir" W ""
        perf_matrix_wz_arm "$dir" Wapp app-transport
        perf_probe_build "$dir" P zenohpico
        perf_probe_build "$dir" W wz_capi_pico -DPERF_WZ_ARM -I"$root/crates/wz-capi-core/include"
        perf_probe_build "$dir" Wapp wz_capi_pico -DPERF_WZ_ARM -DPERF_PROGRAM_TRANSPORT \
            -I"$root/crates/wz-capi-core/include"
        perf_external_arm "$dir"
    else
        stamped_engine "$(recorded_engine "$dir/reference.json")"
        stamped_stdlib "$(recorded_stdlib "$dir/reference.json")"
    fi
    echo "pico-compare: arm W on the $(recorded_engine "$dir/reference.json") engine, $(recorded_stdlib "$dir/reference.json")"
    if [ -f "$dir/external.json" ]; then
        external_args=(--external-record "$dir/external.json")
    fi
    run="$out/perf-runs/host-$(date -u +%Y%m%dT%H%M%S)"
    python3 -I "$root/scripts/host-bench/perf_matrix.py" run --bin-dir "$dir/bin" --run "$run" --reps "$reps" \
        --sizes "$sizes" --transports "${PICO_CMP_PERF_TRANSPORTS:-tcp,udp,multicast,program}" \
        --batching "${PICO_CMP_PERF_BATCHING:-off,on}" --workloads "${PICO_CMP_PERF_WORKLOADS:-rtt,thr}" \
        --client-cpus "$client_cpus" --server-cpus "$server_cpus" \
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

# selftest: the helpers the runs lean on, read on this host with no library built and no CPU pinned; one line
# each, and exit 0 when every one holds, 1 when one does not.
selftest_failed=0
selftest_check() {
    if [ "$2" = "$3" ]; then
        echo "  ok   $1"
    else
        echo "  FAIL $1: $2, not $3"
        selftest_failed=1
    fi
}
selftest() {
    local dir port held p
    selftest_failed=0
    dir="$(mktemp -d)"
    printf '32768\t60999\n' >"$dir/range"
    held=yes
    for _ in $(seq 1 200); do
        port="$(bench_port "$dir/range")"
        if [ "$port" -lt 20000 ] || [ "$port" -gt 32767 ]; then
            held="no, $port"
        fi
    done
    selftest_check "bench_port takes a port from 20000 below an ephemeral range of 32768-60999" "$held" yes
    printf '10000\t40000\n' >"$dir/range"
    held=yes
    for _ in $(seq 1 200); do
        port="$(bench_port "$dir/range")"
        if [ "$port" -le 40000 ] || [ "$port" -gt 65535 ]; then
            held="no, $port"
        fi
    done
    selftest_check "bench_port takes a port above an ephemeral range of 10000-40000" "$held" yes
    sh -c 'exit 1' &
    p=$!
    sleep 1
    if peer_alive "$p"; then held=alive; else held=gone; fi
    wait "$p" 2>/dev/null
    selftest_check "peer_alive: a peer that exited, not yet waited for, is gone" "$held" gone
    sleep 30 &
    p=$!
    if peer_alive "$p"; then held=alive; else held=gone; fi
    kill "$p" 2>/dev/null
    wait "$p" 2>/dev/null
    selftest_check "peer_alive: a peer that runs is alive" "$held" alive
    printf '%s\n' 'fn=(1) main' 'cfn=(2) _z_executor_spin' 'calls=3 0' '0 30' 'fn=(3) other' 'cfn=(2)' 'calls=4 0' \
        '0 40' 'cfn=(4) _z_executor_spin_once' 'calls=100 0' '0 1' 'fn=(2)' '0 5' >"$dir/calls.callgrind"
    selftest_check "callgrind_calls sums the calls of one name, given once and then by its number" \
        "$(callgrind_calls "$dir/calls.callgrind" _z_executor_spin)" 7
    rm -rf "$dir"
    if [ "$selftest_failed" = 0 ]; then
        echo "pico-compare: selftest passed"
        return 0
    fi
    echo "pico-compare: selftest FAILED"
    return 1
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
    subprofile) subprofile "$@" ;;
    opprofile) opprofile "$@" ;;
    parity) parity "$@" ;;
    perf) perf_matrix "$@" ;;
    batch) batch_control "$@" ;;
    fanin) fanin "$@" ;;
    selftest) selftest ;;
    *)
        echo "usage: $0 rtt [reps] | thr [reps] [sizes...] | nodrop [reps] [sizes,comma,separated] | nodrop-c [reps] [sizes] | profile [size] [rate] | subprofile [size] [count] [rate] | opprofile [ops,comma,separated] [size] | parity <pico|c|rust> [boots] [sizes] | perf [reps] [sizes,comma,separated] | batch [sizes,comma,separated] [count] | fanin [rounds] [publishers] [size] [hz] [seconds] [block|drop] [pairs] | selftest" >&2
        exit 2
        ;;
esac

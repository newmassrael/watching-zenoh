#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# fuzz.sh -- build, replay and run the fuzz targets of `crates/wz-fuzz`, the
# C ABI doors of `wz-capi-dissect`, `wz-capi-replay` and `wz-capi-c` (the
# config verdict and the end-to-end sender) a consumer hands outside bytes to.
#
#   bash scripts/fuzz.sh build                     build every target (ASan)
#   bash scripts/fuzz.sh regress [TARGET...]       every seed and every committed
#                                                  reproducer through each target, once
#   bash scripts/fuzz.sh run TARGET SECONDS [JOBS] fuzz one target for SECONDS
#   bash scripts/fuzz.sh sweep SECONDS [JOBS]      fuzz every target in turn, past a failure
#   bash scripts/fuzz.sh targets                   print the targets
#
# `regress` is what Layer Fz of scripts/run-ci.sh runs: it passes when every
# input ran and none failed, and it counts what ran, so a target that read no
# input is a failure and not a pass. `run` keeps its corpus between runs under
# $WZ_FUZZ_HOME (default crates/target/fuzz) and writes a crash to
# $WZ_FUZZ_HOME/artifacts/TARGET/; a crash is made a regression by copying the
# file into crates/wz-fuzz/regressions/TARGET/ in the commit that fixes it.
#
# The targets are built by the nightly `crates/wz-fuzz/rust-toolchain.toml`
# pins (rustup installs it on first use), with the instrumentation flags
# cargo-fuzz passes, so no machine needs cargo-fuzz itself; a person who has it
# may still run `cargo fuzz run <target>` inside crates/wz-fuzz.
#
# Exit codes: 0 pass; 1 a target failed or ran nothing; 2 usage or a missing tool.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_dir="$repo_root/crates/wz-fuzz"
fuzz_home="${WZ_FUZZ_HOME:-$repo_root/crates/target/fuzz}"
build_dir="$fuzz_home/build"
seeds_py="$repo_root/scripts/lib/fuzz_seeds.py"
triple="x86_64-unknown-linux-gnu"
# A capture seed is at most 64 KiB plus the eight bytes of arguments in front;
# the fuzzer may grow an input to this.
max_len=$((64 * 1024 + 64))

usage() {
    sed -n '/^#   bash/p' "${BASH_SOURCE[0]}" | sed 's/^# *//' >&2
    exit 2
}

targets() {
    python3 "$seeds_py" --targets
}

# What cargo-fuzz 0.13 passes for `build -O --debug-assertions` with
# AddressSanitizer: libFuzzer's coverage counters, its comparison tracing, no
# branch folding that would hide an edge, `cfg(fuzzing)`, and the checks a
# debug build has. The standard library is the toolchain's own, built without
# the sanitizer, which `-Cunsafe-allow-abi-mismatch` accepts by name: ASan then
# watches every allocation and access of wz's code, and not those inside std.
fuzz_rustflags=(
    -Cpasses=sancov-module
    -Cllvm-args=-sanitizer-coverage-level=4
    -Cllvm-args=-sanitizer-coverage-inline-8bit-counters
    -Cllvm-args=-sanitizer-coverage-pc-table
    -Cllvm-args=-sanitizer-coverage-trace-compares
    -Cllvm-args=-simplifycfg-branch-fold-threshold=0
    --cfg fuzzing
    -Zsanitizer=address
    -Cunsafe-allow-abi-mismatch=sanitizer
    -Cdebug-assertions
    -Coverflow-checks
    -Cforce-frame-pointers=yes
)

build() {
    command -v cargo >/dev/null || { echo "fuzz.sh: no cargo on PATH" >&2; exit 2; }
    command -v rustup >/dev/null || { echo "fuzz.sh: no rustup on PATH (the targets need its pinned nightly)" >&2; exit 2; }
    local channel
    channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$fuzz_dir/rust-toolchain.toml")"
    [[ -n "$channel" ]] || { echo "fuzz.sh: crates/wz-fuzz/rust-toolchain.toml names no channel" >&2; exit 2; }
    rustup toolchain install "$channel" --profile minimal >/dev/null
    local bins=()
    for target in "$@"; do bins+=(--bin "$target"); done
    ((${#bins[@]})) || bins=(--bins)
    # From inside the fuzz directory, so its rust-toolchain.toml picks the
    # compiler and not the product workspace's stable. `--target` keeps the
    # flags off build scripts and proc macros, as cargo-fuzz does.
    (cd "$fuzz_dir" && RUSTFLAGS="${fuzz_rustflags[*]}" \
        cargo build --release --locked --target "$triple" --target-dir "$build_dir" "${bins[@]}")
}

binary() {
    echo "$build_dir/$triple/release/$1"
}

seed_dir() {
    local dir="$fuzz_home/seeds/$1"
    rm -rf "$dir"
    python3 "$seeds_py" "$1" "$dir" >/dev/null
    echo "$dir"
}

regress() {
    local selected=("$@")
    ((${#selected[@]})) || mapfile -t selected < <(targets)
    build
    local fail=0 target dir inputs log ran
    for target in "${selected[@]}"; do
        dir="$(seed_dir "$target")"
        inputs=("$dir"/*)
        if [[ -d "$fuzz_dir/regressions/$target" ]]; then
            shopt -s nullglob
            inputs+=("$fuzz_dir/regressions/$target"/*)
            shopt -u nullglob
        fi
        log="$fuzz_home/regress-$target.log"
        if "$(binary "$target")" -rss_limit_mb=4096 -timeout=60 "${inputs[@]}" >"$log" 2>&1; then
            ran="$(grep -c '^Executed ' "$log" || true)"
            if [[ "$ran" -ne "${#inputs[@]}" ]]; then
                echo "fuzz.sh: FAIL $target -- ran=$ran of ${#inputs[@]} input(s); log $log" >&2
                fail=1
            else
                echo "fuzz.sh: pass $target -- ran=$ran input(s)"
            fi
        else
            echo "fuzz.sh: FAIL $target -- an input failed; log $log" >&2
            grep -m1 -B2 -A25 'panicked\|ERROR: AddressSanitizer\|ERROR: LeakSanitizer\|deadly signal' "$log" >&2 || tail -40 "$log" >&2
            fail=1
        fi
    done
    return "$fail"
}

run() {
    local target="$1" seconds="$2" jobs="${3:-1}"
    build "$target"
    local corpus="$fuzz_home/corpus/$target" artifacts="$fuzz_home/artifacts/$target/"
    mkdir -p "$corpus" "$artifacts"
    local seeds
    seeds="$(seed_dir "$target")"
    local regressions=()
    [[ -d "$fuzz_dir/regressions/$target" ]] && regressions=("$fuzz_dir/regressions/$target")
    # The first directory is the one libFuzzer adds to; the seeds and the
    # reproducers are read and left as they are.
    "$(binary "$target")" "$corpus" "$seeds" "${regressions[@]}" \
        -max_total_time="$seconds" -max_len="$max_len" -timeout=10 -rss_limit_mb=4096 \
        -artifact_prefix="$artifacts" -jobs="$jobs" -workers="$jobs" -print_final_stats=1
}

sweep() {
    local seconds="$1" jobs="${2:-1}" fail=0 target
    while read -r target; do
        if run "$target" "$seconds" "$jobs"; then
            echo "fuzz.sh: sweep $target -- no failure in ${seconds}s"
        else
            echo "fuzz.sh: sweep $target -- FAILED; inputs in $fuzz_home/artifacts/$target/" >&2
            fail=1
        fi
    done < <(targets)
    return "$fail"
}

case "${1:-}" in
    build) shift; build "$@" ;;
    regress) shift; regress "$@" ;;
    run) shift; (($# >= 2)) || usage; run "$@" ;;
    sweep) shift; (($# >= 1)) || usage; sweep "$@" ;;
    targets) targets ;;
    *) usage ;;
esac

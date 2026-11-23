#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# verify.sh -- the measured verification of the cooperative engine's crates (docs/verification.md):
# line and branch coverage, the thread and address sanitizers and the Miri interpreter, each over
# the tests of the units scripts/lib/verify_plan.py resolves: the crates in the feature sets the
# shipped builds give them.
#
#   bash scripts/verify.sh coverage                 the units' tests instrumented; the merged export
#   bash scripts/verify.sh tsan tests|programs      the units' tests, or the C programs, under ThreadSanitizer
#   bash scripts/verify.sh asan tests|programs      the same under AddressSanitizer
#   bash scripts/verify.sh miri                     the interpreter's units
#   bash scripts/verify.sh units LANE               print the lane's units as they resolve
#
# Layers Vcov, Vtsan, Vasan and Vmiri of scripts/run-ci.sh run these; Vcov then holds the export to
# deploy/coverage_floor.json (scripts/lib/coverage_floor_gate.py).
#
# Every lane builds with the nightly crates/wz-fuzz/rust-toolchain.toml pins: branch coverage, the
# sanitizers, -Zbuild-std and the interpreter are a nightly's alone, and one pinned nightly serves
# every tool that needs one, moved in a commit of its own. The script installs it, and the
# components a lane needs (llvm-tools, rust-src, miri), where they are missing.
#
# The sanitizer lanes build the standard library with the sanitizer too (-Zbuild-std): without it
# ThreadSanitizer does not see std's own synchronisation and reads every lock as a race, and
# AddressSanitizer does not see what std does with memory wz handed it. AddressSanitizer runs with
# leak detection off, and the interpreter with its leak check off: the tests lend places of arenas
# they leak on purpose, so that a lent place outlives every row; a leak is not a memory-safety
# defect, and these lanes judge memory safety.
#
# Products under $WZ_ARTIFACTS/target/verify/<lane>/ (scripts/lib/artifact-root.sh): each unit's log,
# and for coverage the merged profile, the export and what the gate writes from it. The builds go to
# $WZ_ARTIFACTS/crates/target/verify/<lane>/, one target directory a lane, because each lane's flags
# change every crate's build.
#
# Exit codes: 0 pass; 1 a unit failed, a sanitizer reported, or a unit ran no test; 2 usage or a
# missing tool.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/artifact-root.sh
source "$repo_root/scripts/lib/artifact-root.sh"
wz_artifact_root_init "$repo_root" || exit 2
out_home="$(realpath -m "${WZ_VERIFY_HOME:-$WZ_ARTIFACTS/target/verify}")"
build_home="$(realpath -m "$WZ_ARTIFACTS/crates/target/verify")"
plan_py="$repo_root/scripts/lib/verify_plan.py"
channel=""
host=""
unit_lines=()

usage() {
    sed -n '/^#   bash/p' "${BASH_SOURCE[0]}" | sed 's/^# *//' >&2
    exit 2
}

# The pinned nightly and the host it builds for, with the components named added where missing.
toolchain() {
    command -v cargo >/dev/null || { echo "verify.sh: no cargo on PATH" >&2; exit 2; }
    command -v rustup >/dev/null || { echo "verify.sh: no rustup on PATH (the lanes need its pinned nightly)" >&2; exit 2; }
    channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$repo_root/crates/wz-fuzz/rust-toolchain.toml")"
    [[ -n "$channel" ]] || { echo "verify.sh: crates/wz-fuzz/rust-toolchain.toml names no channel" >&2; exit 2; }
    rustup toolchain install "$channel" --profile minimal >/dev/null
    if (($#)); then
        rustup component add --toolchain "$channel" "$@" >/dev/null
    fi
    host="$(rustc "+$channel" -vV | sed -n 's/^host: //p')"
    [[ -n "$host" ]] || { echo "verify.sh: rustc +$channel names no host target" >&2; exit 2; }
}

# The lane's units, resolved, into unit_lines. A lane with a unit of the C library or of a kit
# image provisions the pinned Kconfig interpreter first, which resolves the library's profile.
read_units() {
    local lane="$1" provision="$2" listing
    if [[ "$provision" == provision ]]; then
        bash "$repo_root/scripts/provision-kconfiglib.sh"
    fi
    if ! listing="$(cd "$repo_root" && python3 "$plan_py" --units "$lane")"; then
        echo "verify.sh: the units of $lane did not resolve (scripts/lib/verify_plan.py)" >&2
        exit 1
    fi
    mapfile -t unit_lines <<<"$listing"
    if ((${#unit_lines[@]} == 0)) || [[ -z "${unit_lines[0]}" ]]; then
        echo "verify.sh: lane $lane has no unit" >&2
        exit 1
    fi
}

# The libtest count of a captured run, summed over its summary lines.
passed_in() {
    awk '/^test result: (ok|FAILED)\./ { for (i = 1; i <= NF; i++) if ($(i+1) ~ /^passed/) n += $i } END { print n + 0 }' "$1"
}

# Whether a captured run holds a sanitizer's report. The run's exit status is the report's verdict
# for the process cargo started; this reads the report of a child process a test started and did
# not judge.
reported_in() {
    grep -Eq '(WARNING|ERROR): (ThreadSanitizer|AddressSanitizer|LeakSanitizer)|SUMMARY: (ThreadSanitizer|AddressSanitizer)' "$1"
}

# Run one unit's tests, streamed and kept in LOG:
#   run_unit LOG LABEL CRATE CARGO_ARGS TEST_ARGS COMMAND...
# runs COMMAND... -p CRATE CARGO_ARGS --no-fail-fast -- TEST_ARGS from crates/. It fails when the
# command fails, when a sanitizer reported, and when no test passed.
run_unit() {
    local log="$1" label="$2" crate="$3" cargo_args="$4" test_args="$5" rc passed
    shift 5
    local -a ca=() ta=()
    read -r -a ca <<<"$cargo_args"
    read -r -a ta <<<"$test_args"
    set +e
    (cd "$repo_root/crates" && "$@" -p "$crate" "${ca[@]}" --no-fail-fast -- "${ta[@]}") 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    set -e
    passed="$(passed_in "$log")"
    if ((rc != 0)); then
        echo "verify.sh: FAIL $label -- exit $rc; log $log" >&2
        return 1
    fi
    if reported_in "$log"; then
        echo "verify.sh: FAIL $label -- a sanitizer reported; log $log" >&2
        return 1
    fi
    if ((passed == 0)); then
        echo "verify.sh: FAIL $label -- no test passed, so the unit measured nothing; log $log" >&2
        return 1
    fi
    echo "verify.sh: pass $label -- passed=$passed"
}

# Every unit of unit_lines under COMMAND..., past a failure: test_lane LANE COMMAND...
test_lane() {
    local lane="$1" fail=0 ran=0 line id crate cargo_args test_args
    shift
    mkdir -p "$out_home/$lane"
    for line in "${unit_lines[@]}"; do
        IFS='|' read -r id crate cargo_args test_args <<<"$line"
        if run_unit "$out_home/$lane/$id-$crate.log" "$lane $id $crate" "$crate" "$cargo_args" "$test_args" "$@"; then
            ran=$((ran + 1))
        else
            fail=1
        fi
    done
    echo "verify.sh: $lane -- $ran of ${#unit_lines[@]} unit(s) passed"
    return "$fail"
}

coverage() {
    toolchain llvm-tools
    local tools
    tools="$(rustc "+$channel" --print sysroot)/lib/rustlib/$host/bin"
    if [[ ! -x "$tools/llvm-profdata" || ! -x "$tools/llvm-cov" ]]; then
        echo "verify.sh: no llvm-profdata or llvm-cov in $tools (the llvm-tools component)" >&2
        exit 2
    fi
    read_units coverage provision
    local home="$out_home/coverage" target_dir="$build_home/coverage"
    rm -rf "$home"
    mkdir -p "$home/profiles"
    # Branch regions need the nightly's option; the legacy mangling is what the gate's list of
    # uncovered functions reads back into paths.
    local -x RUSTFLAGS="-Cinstrument-coverage -Zcoverage-options=branch -Csymbol-mangling-version=legacy -Zunstable-options"
    local -x LLVM_PROFILE_FILE="$home/profiles/%m-%p.profraw"
    local fail=0 line id crate cargo_args test_args report listed
    local -a ca=() objects=() profiles=() object_args=()
    for line in "${unit_lines[@]}"; do
        IFS='|' read -r id crate cargo_args test_args <<<"$line"
        read -r -a ca <<<"$cargo_args"
        report="$home/build-$id-$crate.json"
        # The unit's test executables, from cargo's own report of the build the run below reuses.
        if ! (cd "$repo_root/crates" && cargo "+$channel" test --locked --no-run \
            --message-format=json-render-diagnostics --target "$host" --target-dir "$target_dir" \
            -p "$crate" "${ca[@]}") >"$report"; then
            echo "verify.sh: FAIL coverage $id $crate -- the build failed" >&2
            fail=1
            continue
        fi
        if ! listed="$(python3 "$plan_py" --executables "$report")"; then
            fail=1
            continue
        fi
        mapfile -t -O "${#objects[@]}" objects <<<"$listed"
        run_unit "$home/test-$id-$crate.log" "coverage $id $crate" "$crate" "$cargo_args" "$test_args" \
            cargo "+$channel" test --locked --target "$host" --target-dir "$target_dir" || fail=1
    done
    if ((fail)); then
        echo "verify.sh: coverage -- a unit failed, so no export is written" >&2
        return 1
    fi
    shopt -s nullglob
    profiles=("$home/profiles"/*.profraw)
    shopt -u nullglob
    if ((${#profiles[@]} == 0)); then
        echo "verify.sh: FAIL coverage -- the tests wrote no profile" >&2
        return 1
    fi
    "$tools/llvm-profdata" merge -sparse "${profiles[@]}" -o "$home/merged.profdata"
    mapfile -t objects < <(printf '%s\n' "${objects[@]}" | sort -u)
    object_args=("${objects[0]}")
    for line in "${objects[@]:1}"; do
        object_args+=(-object "$line")
    done
    # The sources of other trees (the registry, the toolchain, the vendored SCE, generated code
    # under a target directory) are left out here; the gate keeps each measured crate's own.
    "$tools/llvm-cov" export -format=text -skip-expansions -instr-profile="$home/merged.profdata" \
        -ignore-filename-regex='(/\.cargo/|/\.rustup/|^/rustc/|/vendor/|/target/)' \
        "${object_args[@]}" >"$home/export.json"
    echo "verify.sh: coverage -- ${#unit_lines[@]} unit(s), ${#objects[@]} test executable(s)," \
        "${#profiles[@]} profile(s); export $home/export.json"
}

# The C programs of verify_plan.py --programs, each built against the library made with the
# sanitizer and run (scripts/pico-c-program.sh under WZ_PICO_SANITIZER): the package's build, the
# cooperative engine with the profile's capabilities.
programs() {
    local lane="$1" sanitizer="$2" features listing line program what log rc fail=0 ran=0
    local -a program_lines=()
    bash "$repo_root/scripts/provision-kconfiglib.sh"
    if ! features="$(cd "$repo_root" && python3 "$plan_py" --library-features)"; then
        echo "verify.sh: the C library's capabilities did not resolve" >&2
        return 1
    fi
    listing="$(python3 "$plan_py" --programs)"
    mapfile -t program_lines <<<"$listing"
    mkdir -p "$out_home/$lane"
    for line in "${program_lines[@]}"; do
        IFS='|' read -r program what <<<"$line"
        log="$out_home/$lane/program-$(basename "${program%.c}").log"
        set +e
        (cd "$repo_root" && WZ_PICO_ENGINE=coop WZ_PICO_SANITIZER="$sanitizer" WZ_EXAMPLE_GROUP_IFACE=lo \
            bash scripts/pico-c-program.sh "$program" "$what" "$features") 2>&1 | tee "$log"
        rc=${PIPESTATUS[0]}
        set -e
        if ((rc != 0)); then
            echo "verify.sh: FAIL $lane $program -- exit $rc; log $log" >&2
            fail=1
        elif reported_in "$log"; then
            echo "verify.sh: FAIL $lane $program -- a sanitizer reported; log $log" >&2
            fail=1
        else
            ran=$((ran + 1))
        fi
    done
    echo "verify.sh: $lane -- $ran of ${#program_lines[@]} C program(s) passed"
    return "$fail"
}

sanitized() {
    local lane="$1" part="$2" sanitizer
    case "$lane" in
        tsan) sanitizer=thread ;;
        *) sanitizer=address ;;
    esac
    case "$part" in
        tests | programs) ;;
        *) usage ;;
    esac
    toolchain rust-src
    local -x RUSTFLAGS="-Zsanitizer=$sanitizer -Cforce-frame-pointers=yes"
    local -x TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1"
    local -x ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:detect_stack_use_after_return=1"
    if [[ "$part" == programs ]]; then
        programs "$lane" "$sanitizer"
        return
    fi
    read_units "$lane" provision
    test_lane "$lane" cargo "+$channel" test -Zbuild-std --target "$host" --target-dir "$build_home/$lane"
}

interpret() {
    toolchain miri rust-src
    read_units miri none
    local -x MIRIFLAGS="-Zmiri-ignore-leaks"
    (cd "$repo_root/crates" && cargo "+$channel" miri setup)
    test_lane miri cargo "+$channel" miri test --locked --target-dir "$build_home/miri"
}

case "${1:-}" in
    coverage) coverage ;;
    tsan | asan)
        (($# == 2)) || usage
        sanitized "$1" "$2"
        ;;
    miri) interpret ;;
    units)
        (($# == 2)) || usage
        bash "$repo_root/scripts/provision-kconfiglib.sh"
        cd "$repo_root" && python3 "$plan_py" --units "$2"
        ;;
    *) usage ;;
esac

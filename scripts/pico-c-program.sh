#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Build one zenoh-pico C program against the wz cdylib on THIS host, run it, and print
# one verdict line.
#
#   scripts/pico-c-program.sh <source.c> <what the program shows>
#
# The program is compiled against zenoh-pico's OWN headers for the host (the ones the
# vendored library's build installs), with the config.h of the wz library's arm in place of
# the vendored default one (`wz_config.py --pico-config-h`, from the same feature list the
# library is built with), linked against the wz library in place of libzenohpico, and run. It is the evidence a platform tag needs
# that a pico program, not only a Rust test through the exported symbols, sees the
# layout and the behaviour pico's headers promise.
#
# macOS compiles with `cc`. Windows compiles with MSVC's `cl` through the Visual Studio
# environment, the compiler pico's own build uses: pico's Windows header names an inline
# function `__asm__`, which a GNU-mode compiler reads as a keyword. Linux compiles with
# `cc`: the hosted runners of the `capi` job are macOS and Windows, and the C examples'
# job (`capi-examples`) runs on Linux and Windows.
#
# On a Unix the language is pico's own build's: its CMake asks for C11
# (`vendor/zenoh-pico/CMakeLists.txt` @ `set(CMAKE_C_STANDARD 11)`) and never turns CMake's
# compiler extensions off, so it compiles with `-std=gnu11`, which its Unix header relies on. That header types the clock as `struct timespec` and includes
# only `<sys/time.h>` for it, plus `<pthread.h>` in the multi-threaded arm; under strict
# `-std=c11` glibc's `<sys/time.h>` declares no `timespec`, so the single-threaded arm, which
# has no `<pthread.h>` to bring in `<time.h>`, does not compile, while pico's own build of the
# same header does.
#
# The library is built in the caller's environment, so a build default the caller states
# there (a `WZ_POLICY_<NAME>`, a `WZ_LIMIT_<NAME>`) is the library's, and a limit stated
# there is the value of the rendered header's switch too; a source file given with a feature
# list is linked against the library with those features.
#
# WZ_PICO_ENGINE names the engine the library runs its sessions on: `tokio` (or unset), or
# `coop`, the cooperative engine alone (`--no-default-features` with `os-host` and the feature
# list), whose header arm is rendered with `--engine coop`. The library is the C library's crate,
# `wz-capi-pico-lib`, each feature named through its dependency on the ABI crate (`abi/`).
#
# WZ_PICO_FORM names the standard library of the library, which its engine decides: `std` for the
# tokio engine, `nostd` for the cooperative one (docs/win-budget/std-heap.md, S1: the C library on
# that engine has no `std` form), built as the host library without `std` is: the `capi-nostd`
# profile and its configuration (`crates/.cargo/capi-nostd.toml`), for the host's own target, so it
# lives in a target directory of its own. Unset, it is the engine's; a form the engine's library
# does not have is refused.
#
# WZ_PICO_PROGRAM_ROLES, when set, is a list of words the program is run with, one process each,
# all at once, each given its role and one loopback port the script picks (`<exe> <role> <port>`):
# the shape of a program whose sessions cannot share a thread, as two single-threaded sessions
# that dial each other cannot. The program passes when every process exits 0.
#
# WZ_PICO_SANITIZER, when set, is `thread`, `address` or `undefined`, on Linux, for either form of
# the library (scripts/verify.sh, Layers Vtsan and Vasan, run it on the cooperative engine).
# `undefined` is the C compiler's UndefinedBehaviorSanitizer over the program alone, every report
# fatal (`-fno-sanitize-recover`), and the library built as it is without a sanitizer: Rust has no
# such sanitizer, and its own undefined behaviour is the interpreter's lane (Layer Vmiri). With
# `thread` or `address` the library and the program are built under that sanitizer.
# The library is built by the nightly crates/wz-fuzz/rust-toolchain.toml pins, with `-Zsanitizer` and
# its standard library rebuilt under it (`-Zbuild-std`, for the host's own target), since rustc
# refuses to link crates built with another sanitizer. The library without `std` keeps its own
# profile and configuration (the dev profile unwinds, and a library without `std` cannot), so the
# standard library is rebuilt with the abort runtime that profile asks for, in a target directory
# of its own, which keeps the build without a sanitizer from being replaced by it. The program is
# compiled with the C compiler's `-fsanitize` and linked against the sanitizer runtime that nightly ships, linked whole and its symbols exported: the
# library's instrumentation calls into the runtime of the compiler that instrumented it, which a
# system compiler's own runtime can be older than.
#
# Reads RUNNER_OS and RUNNER_TEMP, which the Actions runner sets, and appends its verdict
# to GITHUB_STEP_SUMMARY when that is set. Exit status 0 means the program built, ran and
# passed. A failure to build is reported as NOT-MEASURED and is a non-zero exit too: a
# step that could not compile its program has not shown that the program passes.
#
# A program may state lines its run prints, one `expect-line: <line>` each in its source's comment
# (` * expect-line: ...`, crates/wz-capi-pico/examples/c/example_common.h): the run passes only when
# it exits 0 AND prints each as a whole line of its output, so a program that exits 0 without having
# done what it states fails. The roles' processes print together, so a program run with
# WZ_PICO_PROGRAM_ROLES states no such line, and one that does is refused.
#
# PICO_C_PROGRAM_OUT=<path> builds the program to <path> and does not run it, on Linux and
# macOS: for a caller that runs it itself, with arguments (scripts/app-plane-oracle.sh). The
# header tree of the library's arm is left beside it, as <dir>/pico-arm-include-<name>, so
# that caller can compile other programs against the same arm.

set -u

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <source.c> <what the program shows> [<wz-capi-pico features>]" >&2
    exit 2
fi
src="$1"
what="$2"
# The capabilities beyond the default build that the program's doors need (a comma list of
# wz-capi-pico features); none for a program of the default build.
features="${3:-}"
engine="${WZ_PICO_ENGINE:-tokio}"
case "$engine" in
    tokio | coop) ;;
    *)
        echo "pico-c-program: WZ_PICO_ENGINE is \`tokio\` or \`coop\`, not \`$engine\`" >&2
        exit 2
        ;;
esac
engine_form=std
[ "$engine" = coop ] && engine_form=nostd
form="${WZ_PICO_FORM:-$engine_form}"
case "$form" in
    std | nostd)
        if [ "$form" != "$engine_form" ]; then
            echo "pico-c-program: the $engine engine's library is built $engine_form, not $form" >&2
            exit 2
        fi
        ;;
    *)
        echo "pico-c-program: WZ_PICO_FORM is \`std\` or \`nostd\`, not \`$form\`" >&2
        exit 2
        ;;
esac
roles="${WZ_PICO_PROGRAM_ROLES:-}"
# wz's extension header, for a program that uses a zext_* door.
ext_inc="$PWD/crates/wz-capi-core/include"
os="${RUNNER_OS:-$(uname -s)}"
# Products of this checkout, under the artifact root (scripts/lib/artifact-root.sh).
# shellcheck source=scripts/lib/artifact-root.sh
source "$(dirname "$0")/lib/artifact-root.sh"
wz_artifact_root_init "$PWD" || exit 2
lib_dir="$WZ_ARTIFACTS/crates/target/debug"
sanitizer="${WZ_PICO_SANITIZER:-}"
case "$sanitizer" in
    "") ;;
    undefined)
        if [ "$os" != Linux ]; then
            echo "pico-c-program: WZ_PICO_SANITIZER is read on Linux" >&2
            exit 2
        fi
        ;;
    thread | address)
        if [ "$os" != Linux ]; then
            echo "pico-c-program: WZ_PICO_SANITIZER is read on Linux" >&2
            exit 2
        fi
        RUSTUP_TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"$/\1/p' crates/wz-fuzz/rust-toolchain.toml)"
        if [ -z "$RUSTUP_TOOLCHAIN" ]; then
            echo "pico-c-program: crates/wz-fuzz/rust-toolchain.toml names no channel" >&2
            exit 2
        fi
        export RUSTUP_TOOLCHAIN
        export RUSTFLAGS="-Zsanitizer=$sanitizer -Cforce-frame-pointers=yes"
        ;;
    *)
        echo "pico-c-program: WZ_PICO_SANITIZER is \`thread\`, \`address\` or \`undefined\`, not \`$sanitizer\`" >&2
        exit 2
        ;;
esac

say() {
    echo "$1"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        echo "$1" >> "$GITHUB_STEP_SUMMARY"
    fi
}

if [ ! -f "$src" ]; then
    echo "pico-c-program: no such source: $src" >&2
    exit 2
fi
# Read as bash 3.2 reads a list (no `mapfile`); [[:space:]] takes a CR of a source checked out
# with CRLF line ends too.
expected=()
while IFS= read -r line; do
    expected+=("$line")
done < <(sed -n 's/^[[:space:]]*\*[[:space:]]*expect-line: \(.*[^[:space:]]\)[[:space:]]*$/\1/p' "$src")
if [ -n "$roles" ] && [ "${#expected[@]}" -gt 0 ]; then
    echo "pico-c-program: $src states the lines its run prints, which a run of roles does not read" >&2
    exit 2
fi

# The crate's default build is the cooperative engine (docs/c-abi-engine-and-memory.md, P1). The
# tokio engine is that build's list with `os-host` replaced by the tokio option's features
# (`wz_config.py --build-cargo-args tokio`), without the default features, and the program's
# capabilities; its header is the default build's, as the capabilities are. The cooperative engine
# here is `os-host` in front of the program's capabilities alone, built without `std` (below), and
# the header renderer is told that engine.
build_features="$features"
engine_args=()
header_engine=()
if [ "$engine" = coop ]; then
    build_features="os-host${features:+,$features}"
    engine_args=(--no-default-features)
    header_engine=(--engine coop)
else
    if [ "$os" = Windows ]; then
        list_py="$(command -v python || command -v python3 || true)"
    else
        list_py="$(command -v python3 || command -v python || true)"
    fi
    if [ -z "$list_py" ] || ! tokio_words="$("$list_py" scripts/lib/wz_config.py \
            --build-cargo-args tokio "$features")"; then
        say "pico-program-probe on ${os}: the tokio engine's feature list did not resolve NOT-MEASURED"
        exit 1
    fi
    tokio_words="${tokio_words#--no-default-features --features }"
    build_features="${tokio_words//abi\//}"
    engine_args=(--no-default-features)
fi
if [ "$form" = nostd ]; then
    host_triple="$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')"
    if [ -z "$host_triple" ]; then
        say "pico-program-probe on ${os}: rustc named no host target NOT-MEASURED"
        exit 1
    fi
    engine_args=(--no-default-features --profile capi-nostd --config .cargo/capi-nostd.toml
        --target "$host_triple")
    lib_dir="$WZ_ARTIFACTS/crates/target/$host_triple/capi-nostd"
fi
if [ "$sanitizer" = thread ] || [ "$sanitizer" = address ]; then
    host_triple="$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')"
    if [ -z "$host_triple" ]; then
        say "pico-program-probe on ${os}: rustc named no host target NOT-MEASURED"
        exit 1
    fi
    if [ "$form" = nostd ]; then
        sanitized_dir="$WZ_ARTIFACTS/crates/target/sanitizer-$sanitizer"
        engine_args+=("-Zbuild-std=std,panic_abort" --target-dir "$sanitized_dir")
        lib_dir="$sanitized_dir/$host_triple/capi-nostd"
    else
        engine_args+=(-Zbuild-std --target "$host_triple")
        lib_dir="$WZ_ARTIFACTS/crates/target/$host_triple/debug"
    fi
fi
feature_args=()
if [ -n "$build_features" ]; then
    feature_args=(--features "abi/${build_features//,/,abi/}")
fi
# Cargo's own report of the build names the include directory: the vendored library's build script
# installs the headers of the arm THIS feature list selects into its own out directory, and a tree
# built with another feature list holds others beside it. Picking the newest of them by time read
# the wrong arm whenever cargo kept this build's script output from an earlier run, and a program
# compiled against another arm's struct sizes than the library's smashed its stack.
build_report="$(mktemp)"
# Expanded as `${a[@]+...}`: macOS's bash 3.2 reads an empty array as unbound under `set -u`.
if ! (cd crates && cargo build --message-format=json-render-diagnostics -p zenoh-pico-sys \
    -p wz-capi-pico-lib ${engine_args[@]+"${engine_args[@]}"} \
    ${feature_args[@]+"${feature_args[@]}"}) > "$build_report"; then
    say "pico-program-probe on ${os}: the pico headers and the cdylib did not build NOT-MEASURED"
    exit 1
fi

# On Windows `python` first: a `python3` there may be the store's launcher stub, which runs nothing.
if [ "$os" = Windows ]; then
    py="$(command -v python || command -v python3 || true)"
else
    py="$(command -v python3 || command -v python || true)"
fi
if [ -z "$py" ]; then
    say "pico-program-probe on ${os}: no python to read cargo's build report NOT-MEASURED"
    exit 1
fi
inc="$("$py" - "$build_report" <<'PY'
import json, os, sys
found = set()
for line in open(sys.argv[1], encoding="utf-8"):
    if not line.startswith("{"):
        continue
    msg = json.loads(line)
    if msg.get("reason") == "build-script-executed" and "zenoh-pico-sys" in msg.get("package_id", ""):
        found.add(os.path.join(msg["out_dir"], "include"))
if len(found) != 1:
    sys.exit(f"cargo reported {len(found)} zenoh-pico-sys build(s) for this feature list, not one")
print(found.pop())
PY
)" || {
    say "pico-program-probe on ${os}: the build named no single pico header arm NOT-MEASURED"
    exit 1
}
rm -f "$build_report"
if command -v cygpath > /dev/null 2>&1; then
    inc="$(cygpath -u "$inc")"
fi
echo "pico headers: $inc"

out_exe="${PICO_C_PROGRAM_OUT:-}"
if [ -n "$out_exe" ]; then
    if [ "$os" = Windows ]; then
        echo "pico-c-program: PICO_C_PROGRAM_OUT is read on Linux and macOS only" >&2
        exit 2
    fi
    temp="$(dirname "$out_exe")"
    mkdir -p "$temp"
elif command -v cygpath > /dev/null 2>&1 && [ -n "${RUNNER_TEMP:-}" ]; then
    temp="$(cygpath -u "$RUNNER_TEMP")"
else
    temp="${RUNNER_TEMP:-$(mktemp -d)}"
fi

# The vendored library installs the config.h of pico's DEFAULT configuration (no unstable API, no
# advanced plane, no connectivity events), and the wz library this program links is the arm its
# feature list builds: the default build has all three. Against the vendored header a program
# allocates the option structs of the other arm and the library's `*_options_default` writes past
# them. So the program is compiled against the header of the library's own arm, rendered from the
# same feature list (`wz_config.py --pico-config-h`). It is a copy of the installed tree with that
# one file replaced, and the only include directory of pico's: a header found beside another
# vendored header first (MSVC searches the directories of the open includes before /I) would
# otherwise still be the vendored one.
arm_inc="$temp/pico-arm-include-$(basename "${src%.c}")"
rm -rf "$arm_inc"
mkdir -p "$arm_inc"
cp -R "$inc"/. "$arm_inc"/
if ! "$py" scripts/lib/wz_config.py --pico-config-h ${header_engine[@]+"${header_engine[@]}"} \
    "$features" > "$arm_inc/zenoh-pico/config.h"; then
    say "pico-program-probe on ${os}: the header of the library's arm did not render NOT-MEASURED"
    exit 1
fi
inc="$arm_inc"
echo "pico headers of this build's arm: $inc"
exe="${out_exe:-$temp/$(basename "${src%.c}")}"
compiled=FAIL
compiler=none
case "$os" in
    macOS)
        compiler=cc
        cc -std=gnu11 -DZENOH_MACOS -I"$inc" -I"$ext_inc" "$src" -o "$exe" -L"$lib_dir" -lwz_capi_pico -Wl,-rpath,"$lib_dir" && compiled=PASS
        ;;
    Linux)
        compiler=cc
        if [ "$sanitizer" = undefined ]; then
            cc -std=gnu11 -DZENOH_LINUX -fsanitize=undefined -fno-sanitize-recover=undefined \
                -fno-omit-frame-pointer -g -I"$inc" -I"$ext_inc" "$src" -o "$exe" \
                -L"$lib_dir" -lwz_capi_pico -Wl,-rpath,"$lib_dir" && compiled=PASS
        elif [ -n "$sanitizer" ]; then
            case "$sanitizer" in
                thread) runtime_name=tsan ;;
                *) runtime_name=asan ;;
            esac
            runtime=""
            for candidate in "$(rustc --print sysroot)/lib/rustlib/$host_triple/lib"/librustc*_rt."$runtime_name".a; do
                if [ -f "$candidate" ]; then
                    runtime="$candidate"
                fi
            done
            if [ -z "$runtime" ]; then
                say "pico-program-probe on ${os}: the pinned nightly ships no ${runtime_name} runtime NOT-MEASURED"
                exit 1
            fi
            cc -std=gnu11 -DZENOH_LINUX -fsanitize="$sanitizer" -fno-omit-frame-pointer -g -I"$inc" -I"$ext_inc" \
                -c "$src" -o "$exe.o" &&
                cc "$exe.o" -o "$exe" -L"$lib_dir" -lwz_capi_pico -Wl,-rpath,"$lib_dir" \
                    -Wl,--whole-archive "$runtime" -Wl,--no-whole-archive -Wl,--export-dynamic \
                    -lpthread -lm -ldl -lrt && compiled=PASS
        else
            cc -std=gnu11 -DZENOH_LINUX -I"$inc" -I"$ext_inc" "$src" -o "$exe" -L"$lib_dir" -lwz_capi_pico -Wl,-rpath,"$lib_dir" && compiled=PASS
        fi
        ;;
    Windows)
        compiler=cl
        vswhere="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
        vsroot="$("$vswhere" -latest -products '*' -property installationPath)"
        bat="$temp/build_$(basename "${src%.c}").bat"
        {
            printf '@echo off\r\n'
            printf 'call "%s\\VC\\Auxiliary\\Build\\vcvars64.bat" > nul\r\n' "$vsroot"
            printf 'cd /d "%s"\r\n' "$(cygpath -w "$temp")"
            printf 'cl /nologo /std:c11 /DZENOH_WINDOWS /I"%s" /I"%s" "%s" "%s" /Fe:"%s"\r\n' \
                "$(cygpath -w "$inc")" "$(cygpath -w "$ext_inc")" "$(cygpath -w "$PWD/$src")" \
                "$(cygpath -w "$lib_dir/wz_capi_pico.dll.lib")" "$(cygpath -w "$exe.exe")"
        } > "$bat"
        cmd.exe //c "$(cygpath -w "$bat")" && compiled=PASS
        exe="$exe.exe"
        ;;
esac

if [ "$compiled" != PASS ]; then
    say "pico-program-probe on ${os} (${compiler}): the program did not compile or link NOT-MEASURED"
    exit 1
fi

if [ -n "$out_exe" ]; then
    say "pico-program-probe on ${os} (${compiler}): ${what}: built ${exe} against ${lib_dir}"
    exit 0
fi

result=FAIL
if [ -z "$roles" ]; then
    run_log="$temp/$(basename "${src%.c}").out"
    PATH="$lib_dir:$PATH" "$exe" | tee "$run_log"
    [ "${PIPESTATUS[0]}" -eq 0 ] && result=PASS
    for line in ${expected[@]+"${expected[@]}"}; do
        if ! tr -d '\r' < "$run_log" | grep -Fqx -- "$line"; then
            echo "pico-c-program: the program printed no line \`$line\`, which its source states"
            result=FAIL
        fi
    done
    rm -f "$run_log"
else
    # One loopback port for every process of the run, picked here as the session programs pick
    # theirs: a fixed number would collide with a second run on the same host.
    port=$((20000 + RANDOM % 20000))
    read -r -a role_list <<< "$roles"
    pids=()
    for role in "${role_list[@]}"; do
        PATH="$lib_dir:$PATH" "$exe" "$role" "$port" &
        pids+=("$!")
    done
    result=PASS
    i=0
    for role in "${role_list[@]}"; do
        if ! wait "${pids[$i]}"; then
            echo "pico-c-program: the \`$role\` process of the program failed"
            result=FAIL
        fi
        i=$((i + 1))
    done
fi
say "pico-program-probe on ${os} (${compiler}): ${what}: ${result}"
[ "$result" = PASS ]

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
# The library is built in the caller's environment, so a build default the caller states
# there (a `WZ_POLICY_<NAME>`, a `WZ_LIMIT_<NAME>`) is the library's, and a limit stated
# there is the value of the rendered header's switch too; a source file given with a feature
# list is linked against the library with those features.
#
# WZ_PICO_ENGINE names the engine the library runs its sessions on: `tokio` (or unset), the
# default build's, or `coop`, the cooperative engine alone (`--no-default-features` with
# `engine-coop` and the feature list), whose header arm is rendered with `--engine coop`. A
# cooperative build replaces the default one in the same target directory, so a step that asks
# for it comes after the steps that link the default library.
#
# WZ_PICO_PROGRAM_ROLES, when set, is a list of words the program is run with, one process each,
# all at once, each given its role and one loopback port the script picks (`<exe> <role> <port>`):
# the shape of a program whose sessions cannot share a thread, as two single-threaded sessions
# that dial each other cannot. The program passes when every process exits 0.
#
# Reads RUNNER_OS and RUNNER_TEMP, which the Actions runner sets, and appends its verdict
# to GITHUB_STEP_SUMMARY when that is set. Exit status 0 means the program built, ran and
# passed. A failure to build is reported as NOT-MEASURED and is a non-zero exit too: a
# step that could not compile its program has not shown that the program passes.

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
roles="${WZ_PICO_PROGRAM_ROLES:-}"
# wz's extension header, for a program that uses a wz_ext_* door.
ext_inc="$PWD/crates/wz-capi-core/include"
os="${RUNNER_OS:-$(uname -s)}"
# Products of this checkout, under the artifact root (scripts/lib/artifact-root.sh).
# shellcheck source=scripts/lib/artifact-root.sh
source "$(dirname "$0")/lib/artifact-root.sh"
wz_artifact_root_init "$PWD" || exit 2
lib_dir="$WZ_ARTIFACTS/crates/target/debug"

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

# The cooperative engine is the build without the default features (which name the tokio
# engine), with `engine-coop` in front of the program's capabilities; the header renderer adds
# `engine-coop` itself when it is told the engine.
build_features="$features"
engine_args=()
header_engine=()
if [ "$engine" = coop ]; then
    build_features="engine-coop${features:+,$features}"
    engine_args=(--no-default-features)
    header_engine=(--engine coop)
fi
feature_args=()
if [ -n "$build_features" ]; then
    feature_args=(--features "wz-capi-pico/${build_features//,/,wz-capi-pico/}")
fi
# Cargo's own report of the build names the include directory: the vendored library's build script
# installs the headers of the arm THIS feature list selects into its own out directory, and a tree
# built with another feature list holds others beside it. Picking the newest of them by time read
# the wrong arm whenever cargo kept this build's script output from an earlier run, and a program
# compiled against another arm's struct sizes than the library's smashed its stack.
build_report="$(mktemp)"
# Expanded as `${a[@]+...}`: macOS's bash 3.2 reads an empty array as unbound under `set -u`.
if ! (cd crates && cargo build --message-format=json-render-diagnostics -p zenoh-pico-sys \
    -p wz-capi-pico ${engine_args[@]+"${engine_args[@]}"} \
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

if command -v cygpath > /dev/null 2>&1 && [ -n "${RUNNER_TEMP:-}" ]; then
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
exe="$temp/$(basename "${src%.c}")"
compiled=FAIL
compiler=none
case "$os" in
    macOS)
        compiler=cc
        cc -std=c11 -DZENOH_MACOS -I"$inc" -I"$ext_inc" "$src" -o "$exe" -L"$lib_dir" -lwz_capi_pico -Wl,-rpath,"$lib_dir" && compiled=PASS
        ;;
    Linux)
        compiler=cc
        cc -std=c11 -DZENOH_LINUX -I"$inc" -I"$ext_inc" "$src" -o "$exe" -L"$lib_dir" -lwz_capi_pico -Wl,-rpath,"$lib_dir" && compiled=PASS
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

result=FAIL
if [ -z "$roles" ]; then
    PATH="$lib_dir:$PATH" "$exe" && result=PASS
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

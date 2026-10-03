#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Build one zenoh-pico C program against the wz cdylib on THIS host, run it, and print
# one verdict line.
#
#   scripts/pico-c-program.sh <source.c> <what the program shows>
#
# The program is compiled against zenoh-pico's OWN headers for the host (the ones the
# vendored library's build installs, with the generated config), linked against the wz
# library in place of libzenohpico, and run. It is the evidence a platform tag needs
# that a pico program, not only a Rust test through the exported symbols, sees the
# layout and the behaviour pico's headers promise.
#
# macOS compiles with `cc`. Windows compiles with MSVC's `cl` through the Visual Studio
# environment, the compiler pico's own build uses: pico's Windows header names an inline
# function `__asm__`, which a GNU-mode compiler reads as a keyword. Linux is accepted so
# that the script can be exercised where it is written; the hosted runners are macOS and
# Windows.
#
# Reads RUNNER_OS and RUNNER_TEMP, which the Actions runner sets, and appends its verdict
# to GITHUB_STEP_SUMMARY when that is set. Exit status 0 means the program built, ran and
# passed. A failure to build is reported as NOT-MEASURED and is a non-zero exit too: a
# step that could not compile its program has not shown that the program passes.

set -u

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <source.c> <what the program shows>" >&2
    exit 2
fi
src="$1"
what="$2"
os="${RUNNER_OS:-$(uname -s)}"
lib_dir="$PWD/crates/target/debug"

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

if ! (cd crates && cargo build -p zenoh-pico-sys -p wz-capi-pico); then
    say "pico-program-probe on ${os}: the pico headers and the cdylib did not build NOT-MEASURED"
    exit 1
fi

# The newest include directory the vendored library's build installed: a restored build
# cache can hold an older one beside it.
# shellcheck disable=SC2012
inc="$PWD/$(ls -dt crates/target/debug/build/zenoh-pico-sys-*/out/include | head -n 1)"
echo "pico headers: $inc"

if command -v cygpath > /dev/null 2>&1 && [ -n "${RUNNER_TEMP:-}" ]; then
    temp="$(cygpath -u "$RUNNER_TEMP")"
else
    temp="${RUNNER_TEMP:-$(mktemp -d)}"
fi
exe="$temp/$(basename "${src%.c}")"
compiled=FAIL
compiler=none
case "$os" in
    macOS)
        compiler=cc
        cc -std=c11 -DZENOH_MACOS -I"$inc" "$src" -o "$exe" -L"$lib_dir" -lwz_capi_pico -Wl,-rpath,"$lib_dir" && compiled=PASS
        ;;
    Linux)
        compiler=cc
        cc -std=c11 -DZENOH_LINUX -I"$inc" "$src" -o "$exe" -L"$lib_dir" -lwz_capi_pico -Wl,-rpath,"$lib_dir" && compiled=PASS
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
            printf 'cl /nologo /std:c11 /DZENOH_WINDOWS /I"%s" "%s" "%s" /Fe:"%s"\r\n' \
                "$(cygpath -w "$inc")" "$(cygpath -w "$PWD/$src")" \
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
PATH="$lib_dir:$PATH" "$exe" && result=PASS
say "pico-program-probe on ${os} (${compiler}): ${what}: ${result}"
[ "$result" = PASS ]

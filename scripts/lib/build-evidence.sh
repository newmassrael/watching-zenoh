#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R4500 (no register item) -- what a failed BUILD prints: its first error lines,
# then its tail.
#
# The item this answers, open-debt item 370, lives in the agent-memory half of
# the register, which has no store id for `gate_provenance_lint.py` to resolve;
# it is named in prose instead.
#
# THE DEFECT. A failure path that prints `tail -40 "$log"` shows the cause only
# when the cause is among the last forty lines. A rustc error followed by a
# page of `warning:` notes, a cmake configure error followed by ninja's
# teardown, or a test binary whose first panic is followed by forty passing
# tests all put the cause above the window, and the dump then reads like a
# failure with no cause -- the quiet form of a build that discards its output.
# Forty, sixty and twenty were guesses; no window size is right for every log.
#
# THE RULE. Print the first lines that carry a compiler, linker, build-tool or
# test-harness error marker (with their line numbers, so the reader can open
# the log at them), and then the tail. The tail keeps the context the window
# used to give; the first-error lines make the cause visible wherever it sits.
# When no line carries a marker, say so, so an empty first section is never
# read as "there was no error".
#
# `build_evidence_lint.py` refuses a `tail` of a file a build wrote, so a new
# failure path uses this function rather than a window of its own.
#
# The shebang is for shellcheck: this file is sourced, never run, and sourcing
# it only defines functions.

# The markers of the toolchains the tree's builds run: rustc and cargo
# (`error[E0425]:`, `error: could not compile`), gcc/clang/ld
# (`file.c:3:1: error:`, `fatal error:`, `undefined reference`), cmake
# (`CMake Error`), ninja (`FAILED:`), make (`make[2]: ***`), libtest
# (`panicked at`, `test x ... FAILED`) and west's own `FATAL ERROR`.
WZ_BUILD_ERROR_MARKERS='^error(\[E[0-9]+\])?:|^[[:space:]]*error:|: (fatal )?error:|^FAILED:|CMake Error|^make(\[[0-9]+\])?: \*\*\*|undefined reference to|panicked at|^test .* \.\.\. FAILED|FATAL ERROR|^ERROR:'

# wz_build_evidence <log> [<tail-lines>] [<first-lines>]
#
# <log> is a file, or `-` for the build output on stdin (a caller that captured
# it into a variable passes `<<<"$out"`). Writes to stdout; a caller on a
# failure path redirects it (`>&2`).
wz_build_evidence() {
    local log="$1" tail_n="${2:-40}" first_n="${3:-12}" text
    if [[ "$log" == "-" ]]; then
        text="$(cat)"
    elif [[ -r "$log" ]]; then
        text="$(cat "$log")"
    else
        echo "  -- the build log $log is not readable; nothing to show --"
        return 0
    fi
    _wz_build_evidence_of "$text" "$tail_n" "$first_n"
    [[ "$log" == "-" ]] || echo "  -- full log: $log --"
}

_wz_build_evidence_of() {
    local text="$1" tail_n="$2" first_n="$3" first
    first="$(grep -n -m "$first_n" -E "$WZ_BUILD_ERROR_MARKERS" <<<"$text" || true)"
    if [[ -n "$first" ]]; then
        echo "  -- the first error line(s) of the build, with their line numbers --"
        printf '%s\n' "$first"
    else
        echo "  -- no line of the build carries an error marker; the tail follows --"
    fi
    echo "  -- the build's last ${tail_n} line(s) --"
    tail -n "$tail_n" <<<"$text"
}

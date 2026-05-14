#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# verify-codegen.sh — drive sce-codegen across all supported backends
# for a watching-zenoh SCXML source, optionally byte-diffing against
# an SCE-upstream fixture that should emit identical generated code.
#
# Usage:
#   scripts/verify-codegen.sh <scxml> [<sce-upstream-fixture>]
#
# Two-layer verification (Round 14 design choice — option C):
#   1. emit-success: each backend runs to exit 0 and writes ≥1 file.
#   2. byte-golden (only if upstream fixture supplied): the per-backend
#      emit-tree of the watching-zenoh source is byte-equivalent to the
#      emit-tree of the SCE-upstream fixture after RFC §5.O traceability-
#      anchor normalization (Round 18 — Layer 2 활성화). Validates that
#      the only difference between the two SCXML inputs (SPDX header
#      block + author-side stem) does not leak into generated code
#      bodies.
#
# RFC §5.O traceability anchors (source-hash + SCE-MAP) are *required*
# to differ between two SCXML inputs that have different file paths or
# byte contents — that is their job (Round 15 finding). Stripping them
# before diff yields the body-equivalence check that the byte-golden
# acceptance gate semantically intends. Stripped patterns:
#   - `source-hash: <hex64>`
#   - `SCE-MAP: <path>:<line>` (handles both plain-comment and rust
#     `#![doc = "..."]` forms)
#
# Pair viability still requires file-name alignment via the root
# `name="…"` attribute on both SCXML inputs (Round 14 carry #1 closed
# in R15). Pairs whose upstream fixture lacks a matching `name=` will
# fail Layer 2 with missing-file diagnostics, not body mismatch.
#
# Backends: rust, cpp, kotlin, go, c11, python.
# A backend that the vendored SCE revision does not (yet) support is
# reported as "skip:<reason>" rather than a hard failure — the result
# table makes the partial-support state explicit so R14 audit trace can
# record the empirical surface, not the design-intent surface.
#
# Exit codes:
#   0  all emitted backends succeeded; golden diff matched where checked.
#   1  one or more backends failed emit, or golden-diff mismatch.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCE_CODEGEN="$ROOT/vendor/sce/target/release/sce-codegen"

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 <scxml> [<sce-upstream-fixture>]" >&2
    exit 2
fi

INPUT="$1"
UPSTREAM="${2:-}"

if [[ ! -f "$INPUT" ]]; then
    echo "verify-codegen: input not found: $INPUT" >&2
    exit 2
fi
if [[ -n "$UPSTREAM" && ! -f "$UPSTREAM" ]]; then
    echo "verify-codegen: upstream fixture not found: $UPSTREAM" >&2
    exit 2
fi
if [[ ! -x "$SCE_CODEGEN" ]]; then
    echo "verify-codegen: $SCE_CODEGEN not built. run scripts/build-sce.sh" >&2
    exit 2
fi

BACKENDS=("rust" "cpp" "kotlin" "go" "c11" "python")

# Generate emits Go imports relative to a hosting module prefix; supply
# a stable dummy so the Go backend can produce output for fixtures that
# do not declare imports (algorithm kind typically does not).
GO_MOD_PREFIX="watching-zenoh/verify"

WORK="$(mktemp -d -t sce-verify-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

emit() {
    local label="$1" backend="$2" scxml="$3"
    local out="$WORK/$label/$backend"
    mkdir -p "$out"

    local stderr_file="$out/.stderr"
    local extra_args=()
    if [[ "$backend" == "go" ]]; then
        extra_args+=("--go-module-prefix" "$GO_MOD_PREFIX")
    fi

    "$SCE_CODEGEN" generate \
        --language "$backend" \
        --output-dir "$out" \
        "${extra_args[@]}" \
        "$scxml" \
        >/dev/null 2>"$stderr_file"
    local code=$?
    echo "$code"
}

count_emitted() {
    local dir="$1"
    # Anything under $dir except the .stderr scratch file.
    find "$dir" -type f ! -name ".stderr" | wc -l
}

normalize_tree() {
    # Strip RFC §5.O traceability anchors (source-hash + SCE-MAP) and
    # the wall-clock `generated-at` epoch in place. The anchors are
    # required to differ between two SCXML inputs with different
    # paths/bytes; `generated-at` differs when paired emit invocations
    # cross a second boundary. The Layer 2 acceptance gate checks body
    # equivalence, not these per-invocation lines.
    local dir="$1"
    find "$dir" -type f ! -name ".stderr" -print0 \
        | while IFS= read -r -d '' f; do
            sed -i \
                -e 's/source-hash: [0-9a-f]\{64\}/source-hash: <STRIPPED>/' \
                -e 's/SCE-MAP: [^"[:space:]]\{1,\}:[0-9]\{1,\}/SCE-MAP: <STRIPPED>/' \
                -e 's/generated-at: [0-9]\{1,\}/generated-at: <STRIPPED>/' \
                "$f"
        done
}

n_pass=0
n_fail=0
n_diff_match=0
n_diff_mismatch=0

printf "verify-codegen: input    = %s\n" "$INPUT"
printf "verify-codegen: upstream = %s\n" "${UPSTREAM:-<none>}"
printf "verify-codegen: sce      = %s (vendor pin)\n" "$SCE_CODEGEN"
echo

# Layer 1: emit each backend on $INPUT (and on $UPSTREAM if given).
printf "%-8s | %-12s | %-7s | %s\n" backend status files note
printf "%-8s-+-%-12s-+-%-7s-+-%s\n" "--------" "------------" "-------" "----"

for be in "${BACKENDS[@]}"; do
    code_in=$(emit input "$be" "$INPUT")
    files_in=$(count_emitted "$WORK/input/$be")
    note=""

    if [[ "$code_in" -eq 0 && "$files_in" -gt 0 ]]; then
        layer1="ok"
        n_pass=$((n_pass+1))
    else
        layer1="fail($code_in)"
        n_fail=$((n_fail+1))
        # Capture short reason from stderr.
        if [[ -s "$WORK/input/$be/.stderr" ]]; then
            note="stderr: $(head -1 "$WORK/input/$be/.stderr" | cut -c1-50)"
        fi
    fi

    # Layer 2 only if upstream supplied AND layer 1 passed for input.
    layer2=""
    if [[ -n "$UPSTREAM" && "$layer1" == "ok" ]]; then
        code_up=$(emit upstream "$be" "$UPSTREAM")
        files_up=$(count_emitted "$WORK/upstream/$be")
        if [[ "$code_up" -ne 0 || "$files_up" -eq 0 ]]; then
            layer2="up:fail"
        else
            # Normalize RFC §5.O traceability anchors on both sides
            # before diff, then compare emit trees byte-by-byte.
            normalize_tree "$WORK/input/$be"
            normalize_tree "$WORK/upstream/$be"
            if diff -rq \
                    --exclude=".stderr" \
                    "$WORK/input/$be" "$WORK/upstream/$be" \
                    >"$WORK/$be.diff" 2>&1; then
                layer2="match"
                n_diff_match=$((n_diff_match+1))
            else
                layer2="MISMATCH"
                n_diff_mismatch=$((n_diff_mismatch+1))
                note="${note:+$note; }diff: $(head -1 "$WORK/$be.diff" | cut -c1-50)"
            fi
        fi
    fi

    status="$layer1"
    if [[ -n "$layer2" ]]; then
        status="$layer1/$layer2"
    fi
    printf "%-8s | %-12s | %-7s | %s\n" "$be" "$status" "$files_in" "$note"
done

echo
printf "verify-codegen: emit pass=%d fail=%d" "$n_pass" "$n_fail"
if [[ -n "$UPSTREAM" ]]; then
    printf " | golden match=%d mismatch=%d" "$n_diff_match" "$n_diff_mismatch"
fi
echo

if [[ "$n_fail" -gt 0 || "$n_diff_mismatch" -gt 0 ]]; then
    exit 1
fi
exit 0

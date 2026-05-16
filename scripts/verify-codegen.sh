#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# verify-codegen.sh — drive sce-codegen across all supported backends
# for a watching-zenoh SCXML source, optionally body-diffing against
# an SCE-upstream fixture that should emit body-equivalent generated
# code (after stem normalization per the watching-zenoh symbol naming
# convention; see sources/README.md "Symbol naming convention").
#
# Usage:
#   scripts/verify-codegen.sh <scxml> [<sce-upstream-fixture>]
#
# Verification layers:
#
#   Layer 1 — emit-success: each backend runs to exit 0 and writes ≥1
#             file. Catches codegen regressions ("Python statechart not
#             supported", missing template, malformed SCXML, etc.).
#
#   Layer 2 — body-golden (only if upstream fixture supplied): the
#             per-backend emit-tree of the watching-zenoh source is
#             body-equivalent to the emit-tree of the SCE-upstream
#             fixture AFTER STEM NORMALIZATION and RFC §5.O
#             traceability-anchor strip.
#
#             R39 closure of the R31-R38 stale carry: previously this
#             layer reported MISMATCH whenever the input/upstream pair
#             had different file stems (the wz convention). That was a
#             misclassification — the body content matched, only the
#             filename + per-language-cased symbol differed. The R39
#             normalization fix extracts each side's file stem and
#             substitutes ALL its case variants
#             (snake_case / PascalCase / camelCase / SCREAMING_SNAKE_CASE)
#             with a canonical __STEM__ placeholder in BOTH filenames
#             AND file contents, then byte-diffs the normalized trees.
#             True body match → `golden=match`. True semantic
#             divergence → `golden=mismatch`.
#
#             Caveat — Layer 2 is structurally tautological for body-
#             byte-identical SCXML inputs: same SCXML body + same SCE
#             codegen = same output by construction. Layer 2's actual
#             job is to catch the case where a wz author accidentally
#             diverges the SCXML body from the SCE fixture without an
#             audit-traced rationale. The real interop validation is
#             Layer 3 (below).
#
#   Layer 3 — wire-interop (NOT YET IMPLEMENTED — Phase 2 walking
#             skeleton dependency, R40+): wz-emitted encoder produces
#             wire bytes for a logical message; zenoh-pico's own
#             `_z_*_encode` produces wire bytes for the same logical
#             message; the two byte sequences MUST be byte-equivalent.
#             This is the ONLY layer that proves real wire interop.
#             Layer 3 lands alongside the `crates/sce_link_runtime_*`
#             walking skeleton; until then, every codec SCXML's "real
#             world correctness" is a spec assumption, not a tested
#             property.
#
# RFC §5.O traceability anchors (source-hash + SCE-MAP) are *required*
# to differ between two SCXML inputs with different paths or byte
# contents — that is their job (Round 15 finding). Stripping them
# before diff yields the body-equivalence check that the byte-golden
# acceptance gate semantically intends.
#
# Backends: rust, cpp, kotlin, go, c11, python. Vendor pin 11f1032d
# closes the Python statechart 6th-backend parity gap (R30 bump).
#
# Exit codes:
#   0  all backends emit-success; Layer 2 body-match where it ran.
#   1  one or more backends fail emit, OR Layer 2 body-mismatch.
#   2  usage error (missing input, missing fixture, sce-codegen
#      binary not built).
#
# See sources/README.md "Symbol naming convention (architectural
# decision — R39)" for the wz-stem rationale and the Layer 2/3
# distinction.

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

# sce-codegen Go backend wants an import-path prefix; supply a stable
# dummy so fixtures without explicit imports still emit cleanly.
GO_MOD_PREFIX="watching-zenoh/verify"

WORK="$(mktemp -d -t sce-verify-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# Extract the file stem (basename without `.scxml` extension).
extract_stem() {
    local path="$1"
    local base
    base="$(basename "$path")"
    echo "${base%.scxml}"
}

# Print one stem per line for each `<sce:import src="X.scxml">`
# directive in the supplied SCXML file (1 level — does not recurse
# into the imported codecs). Each import contributes its own stem to
# the per-pair stem set for normalize_tree because the generator emits
# `use super::<stem>::<PascalStem>` references in the consumer's
# output. Without the import stems, codecs with imports (msg_put,
# ext_entry, etc.) cannot reach golden=match even when bodies are
# semantically equivalent.
extract_import_stems() {
    local path="$1"
    grep -oE 'src="[^"]+\.scxml"' "$path" \
        | sed -E 's|src="||; s|\.scxml"||; s|.*/||'
}

# Print the 4 case variants of a snake_case stem (one per line):
#   snake_case / PascalCase / camelCase / SCREAMING_SNAKE_CASE.
# Order of emission matters only for legibility; the substitution loop
# in normalize_tree applies all four against each file. The variants
# are mutually substring-free for typical zenoh-pico-style names
# (snake has no uppercase; Pascal/camel have no underscores; SCREAMING
# has no lowercase), so substitution order is irrelevant.
stem_variants() {
    local snake="$1"
    local -a parts
    IFS=_ read -ra parts <<< "$snake"
    local pascal=""
    for p in "${parts[@]}"; do
        pascal+="${p^}"
    done
    local camel="${pascal,}"
    local screaming="${snake^^}"
    printf '%s\n%s\n%s\n%s\n' "$snake" "$pascal" "$camel" "$screaming"
}

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
    find "$dir" -type f ! -name ".stderr" | wc -l
}

# normalize_tree <dir> <stem1> [<stem2> ...]
#
#   Step 1. Rename each emit file's basename, substituting all 4 case
#           variants of EACH supplied stem with `__STEM__`.
#   Step 2. In each emit file's content, substitute all 4 case
#           variants of EACH supplied stem with `__STEM__`.
#   Step 3. Strip RFC §5.O traceability anchors (source-hash + SCE-MAP)
#           and the wall-clock `generated-at` epoch.
#   Step 4. Mask SCXML line-number embeds:
#             - `SCXML L<N>:` → `SCXML L<L>:` (test-vector messages,
#                                              "at " and "@" forms)
#             - `_l<N>(`     → `_l<L>(`     (test fn name suffix)
#           These differ between wz and SCE inputs because wz adds a
#           5-line SPDX header block, shifting every subsequent line.
#
# The CALLER passes BOTH the wz-side stem AND the SCE-side stem so
# every cross-mention (e.g., a template comment that hardcodes
# `KeepAlive` as a prose example happens to match the wz Pascal
# variant of `keep_alive`) is normalized symmetrically on both trees.
# After normalize_tree runs identically on both <input> and <upstream>
# emit trees, the two trees can be byte-diffed and a match indicates
# body-equivalent codegen (modulo the by-design stem + anchor +
# epoch + line-number differences).
normalize_tree() {
    local dir="$1"
    shift
    local -a stems=("$@")

    # Collect variants for ALL stems (union of 4-variant sets), then
    # sort by length DESCENDING so substituting a shorter variant
    # can't corrupt a longer one (e.g., the wz stem `close` is a
    # suffix of the SCE stem `codec_variant_session_close`; if `close`
    # substitutes first, `codec_variant_session___STEM__` results and
    # the longer SCE-stem pattern no longer matches anywhere).
    local -a variants_unsorted=()
    for stem in "${stems[@]}"; do
        local -a one
        mapfile -t one < <(stem_variants "$stem")
        variants_unsorted+=("${one[@]}")
    done
    local -a variants
    mapfile -t variants < <(
        printf '%s\n' "${variants_unsorted[@]}" \
            | awk '{ print length, $0 }' \
            | sort -k1,1nr -k2 -u \
            | cut -d' ' -f2-
    )

    # Step 1: rename file basenames (collect list first so mv during
    # iteration doesn't trip the find traversal).
    local -a files
    mapfile -d '' -t files < <(find "$dir" -type f ! -name ".stderr" -print0)
    for f in "${files[@]}"; do
        local d
        d="$(dirname "$f")"
        local b
        b="$(basename "$f")"
        local new_b="$b"
        for v in "${variants[@]}"; do
            new_b="${new_b//$v/__STEM__}"
        done
        if [[ "$b" != "$new_b" ]]; then
            mv "$f" "$d/$new_b"
        fi
    done

    # Step 2 + 3 + 4: substitute variants in content + strip anchors +
    # mask line numbers, all in one sed invocation per file.
    mapfile -d '' -t files < <(find "$dir" -type f ! -name ".stderr" -print0)
    for f in "${files[@]}"; do
        local -a sed_args=()
        for v in "${variants[@]}"; do
            sed_args+=(-e "s|${v}|__STEM__|g")
        done
        sed_args+=(
            -e 's/source-hash: [0-9a-f]\{64\}/source-hash: <STRIPPED>/'
            -e 's/SCE-MAP: [^"[:space:]]\{1,\}:[0-9]\{1,\}/SCE-MAP: <STRIPPED>/'
            -e 's/generated-at: [0-9]\{1,\}/generated-at: <STRIPPED>/'
            -e 's/SCXML L[0-9]\{1,\}:/SCXML L<L>:/g'
            -e 's/_l[0-9]\{1,\}(/_l<L>(/g'
            -e 's/__STEM__L[0-9]\{1,\}(/__STEM__L<L>(/g'
        )
        sed -i "${sed_args[@]}" "$f"

        # Step 5: collapse multi-line continuations (`\n` followed by
        # an indented continuation) into single-space joins. SCE
        # codegen line-wraps long-identifier statements
        # (`std::variant<...>` after the SCE Pascal stem expansion,
        # `let x =\n    very::long::call(...)` after stem expansion).
        # Post stem-normalize, both wz and SCE bodies are
        # semantically identical; only the WRAP DECISION differs (made
        # before normalize from the pre-normalize identifier length).
        # The collapse normalizes both sides to a single-line form, so
        # bytewise diff catches real semantic divergence and ignores
        # cosmetic wrap differences. Layer 2 is body equivalence, not
        # literal byte equality.
        sed -i ':a;N;$!ba;s/\n[ \t]\{1,\}/ /g' "$f"

        # Step 6: sort consecutive `#include` lines within each file.
        # SCE cpp/c11 codegen emits includes in alphabetical order of
        # the SOURCE filename (pre-normalize). wz uses short stems
        # (`timestamp.h`, `encoding.h`, `ext_entry.h`) while SCE uses
        # long stems (`codec_zenoh_timestamp.h`, etc.). After Step 1's
        # stem normalize they all become `__STEM__.h`, but the LINE
        # ORDER reflects the pre-normalize alphabetical sort — so the
        # multiset of include lines is identical, but the SEQUENCE is
        # not. Sorting each include block normalizes the sequence too,
        # making Layer 2 robust to per-import alphabetical ordering.
        # Only `#include` lines are sorted (cpp/c11); other languages'
        # `use`/`import` directives are untouched (Rust `use` order
        # can be semantically meaningful; SCE templates emit them in
        # a deterministic order that already matches across pairs).
        # Implementation uses perl (universally available on Linux);
        # mawk lacks `asort` and POSIX awk lacks deterministic block
        # sorting without external piping.
        perl -e '
            my @out; my @block; my $in = 0;
            while (<>) {
                chomp;
                if (/^#include /) { push @block, $_; $in = 1; next; }
                if ($in) { push @out, sort @block; @block = (); $in = 0; }
                push @out, $_;
            }
            push @out, sort @block if $in;
            print "$_\n" for @out;
        ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
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

INPUT_STEM="$(extract_stem "$INPUT")"
UPSTREAM_STEM=""
if [[ -n "$UPSTREAM" ]]; then
    UPSTREAM_STEM="$(extract_stem "$UPSTREAM")"
fi

# Collect the full stem set for normalize_tree: root stem + 1-level
# imports of each side. The union is applied to BOTH trees so import-
# stem references in either side's emit (e.g., `super::timestamp::`
# on wz vs `super::codec_zenoh_timestamp::` on SCE) normalize to a
# common __STEM__ placeholder.
declare -a ALL_STEMS=("$INPUT_STEM")
mapfile -t -O ${#ALL_STEMS[@]} ALL_STEMS < <(extract_import_stems "$INPUT")
if [[ -n "$UPSTREAM" ]]; then
    ALL_STEMS+=("$UPSTREAM_STEM")
    mapfile -t -O ${#ALL_STEMS[@]} ALL_STEMS < <(extract_import_stems "$UPSTREAM")
fi

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
        if [[ -s "$WORK/input/$be/.stderr" ]]; then
            note="stderr: $(head -1 "$WORK/input/$be/.stderr" | cut -c1-50)"
        fi
    fi

    layer2=""
    if [[ -n "$UPSTREAM" && "$layer1" == "ok" ]]; then
        code_up=$(emit upstream "$be" "$UPSTREAM")
        files_up=$(count_emitted "$WORK/upstream/$be")
        if [[ "$code_up" -ne 0 || "$files_up" -eq 0 ]]; then
            layer2="up:fail"
        else
            # Apply ALL involved stems (root + 1-level imports of
            # both sides) to BOTH trees so cross-mentions and import
            # stem references normalize symmetrically. See
            # normalize_tree + extract_import_stems docstrings.
            normalize_tree "$WORK/input/$be" "${ALL_STEMS[@]}"
            normalize_tree "$WORK/upstream/$be" "${ALL_STEMS[@]}"
            # `-w` (ignore all whitespace including newlines): SCE
            # codegen emits long-identifier statements as single-line
            # for short stems (`crc16_ccitt::crc16_ccitt(...)`) and
            # multi-line wrap for long stems
            # (`AlgorithmCrc16::algorithm_crc16(\n    ...args)`). Post
            # stem-normalize both forms are semantically the same
            # `__STEM__::__STEM__(args)` body; the wrap decision was
            # made pre-normalize from the longer SCE-stem identifier
            # length. -w correctly classifies this as match. Layer 2
            # is about body equivalence, not literal byte equality
            # (literal byte equality is wire-bytes territory — Layer 3).
            if diff -wrq \
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
if [[ -n "$UPSTREAM" ]]; then
    printf "verify-codegen: layer 3 (wire-interop against zenoh-pico)"
    printf " not yet implemented; depends on crates/ walking skeleton.\n"
fi

if [[ "$n_fail" -gt 0 || "$n_diff_mismatch" -gt 0 ]]; then
    exit 1
fi
exit 0

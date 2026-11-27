#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# c11-lane.sh -- Layer Bc: the C11 emission of wz's SCE sources, compiled for a
# microcontroller with no C library, weighed, and held to the vectors its
# documents state.
#
#     bash scripts/c11-lane.sh            judge the tree
#     bash scripts/c11-lane.sh --record   write the figures measured into the budget
#
# WHY. wz is to generate Rust and C11 from one source set (docs/zenoh-logic-as-sce-kinds.md,
# section 5, items 1 and 5). Until this lane the C11 half was emitted and judged by
# nothing but its exit status (Layer B's Layer 1); no lane compiled it, linked it or
# ran it (section 9 of that document). The structure is SCE's own C11 gate (SCE ADR
# 0110, vendor/sce/scripts/gates/c11-mcu.sh) applied to wz's documents:
#
#   1. GENERATE. Every document under sources/codecs and sources/algorithms, with the
#      standard documents they import, as ONE set: `sce-codegen orchestrate -l c11
#      --deploy deploy/codec_node.yaml`. A deployment is a property of the set (SCE
#      refuses `generate --with-imports --deploy` for that reason), and C11 holds every
#      list in an array of the capacity the deployment gives it.
#   2. COMPILE. Each unit's header alone, as its own translation unit, with SCE ADR
#      0110 D3's flags (Cortex-M4, -ffreestanding -nostdlib -Werror) and every inline
#      function kept (-fkeep-inline-functions -fkeep-static-functions): the units are
#      header-only, so without them a unit compiles to nothing and nothing is judged.
#   3. FREESTANDING. A unit's object may leave undefined only the four memory
#      functions every C environment supplies (SCE ADR 0110 D1) and what libgcc of the
#      same multilib defines. Any other undefined symbol is a call into a hosted
#      library and fails, named.
#   4. WEIGH. .text, .rodata, .data and .bss of each unit's object (the unit and what
#      it includes; the runtime is header-only too) against deploy/c11/footprint.tsv,
#      in both directions, by the compiler that file names. A figure moves only by a
#      commit that re-records it and says what the bytes bought.
#   5. VECTORS. A document's <sce:test-vector> rows are emitted as <unit>_test.h. Each
#      is compiled with the host's cc and run; every row must hold, and the number of
#      rows the sidecar runs must be the number the document states, so a sidecar that
#      runs nothing is not a pass.
#
# A unit that does not compile is a failure unless deploy/c11/refusals.tsv names it
# with the error it gives. A named unit that compiles, or fails with other words,
# fails too: the table only shrinks by the fix it waits for.
#
# The compiler is Arm's build of the release SCE pins
# (vendor/sce/scripts/install_arm_gnu_toolchain.sh, ARM_GNU_TOOLCHAIN_REV), installed by
# scripts/install-arm-gnu-toolchain.sh: the budget's figures are that build's. A machine
# without it, or without the pinned sce-codegen, ends "could not run" (exit 3), which
# the lane's caller turns into a failure when WZ_BC_REQUIRE is set.
#
# Exit: 0 the tree holds; 1 it does not; 3 could not run.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/lib/artifact-root.sh
source "$ROOT/scripts/lib/artifact-root.sh"
wz_artifact_root_init "$ROOT" >/dev/null || exit 3
# shellcheck source=scripts/lib/sce-codegen-oracle.sh
source "$ROOT/scripts/lib/sce-codegen-oracle.sh"

RECORD=0
case "${1:-}" in
    "") ;;
    --record) RECORD=1 ;;
    *) echo "c11-lane: unknown argument '$1' (none, or --record)" >&2; exit 2 ;;
esac

SCE="$ROOT/vendor/sce"
DEPLOY="deploy/codec_node.yaml"
BUDGET="deploy/c11/footprint.tsv"
REFUSALS="deploy/c11/refusals.tsv"
OUT="$(wz_artifact_dir target/c11-lane)"
GEN="$OUT/generated"
OBJ="$OUT/obj"
HOST="$OUT/host"
REPORT="$OUT/report.md"

cannot_run() { echo "c11-lane: could not run: $1" >&2; exit 3; }
fail() { echo "c11-lane: FAIL: $1" >&2; exit 1; }

# ── the toolchain: Arm's build of the release SCE pins ──────────────────────────
INSTALLER="$SCE/scripts/install_arm_gnu_toolchain.sh"
[[ -f "$INSTALLER" ]] || cannot_run "vendor/sce holds no scripts/install_arm_gnu_toolchain.sh (submodule not checked out?)"
REV="$(sed -n 's/^ARM_GNU_TOOLCHAIN_REV="\(.*\)"$/\1/p' "$INSTALLER")"
[[ -n "$REV" ]] || fail "$INSTALLER states no ARM_GNU_TOOLCHAIN_REV=\"...\" line"
TOOLCHAIN="${ARM_GNU_TOOLCHAIN_ROOT:-$HOME/.local/share/arm-gnu-toolchain/$REV}"
GCC="$TOOLCHAIN/bin/arm-none-eabi-gcc"
NM="$TOOLCHAIN/bin/arm-none-eabi-nm"
SIZE="$TOOLCHAIN/bin/arm-none-eabi-size"
[[ -x "$GCC" && -x "$NM" && -x "$SIZE" ]] \
    || cannot_run "Arm GNU Toolchain $REV is not installed at $TOOLCHAIN; run: bash scripts/install-arm-gnu-toolchain.sh"
GCC_VERSION="$("$GCC" --version | sed -n '1p')"
[[ "$GCC_VERSION" == *"Arm GNU Toolchain $REV"* ]] \
    || cannot_run "$GCC is '$GCC_VERSION', not Arm GNU Toolchain $REV"
HOST_CC="${CC:-cc}"
command -v "$HOST_CC" >/dev/null 2>&1 || cannot_run "no host C compiler '$HOST_CC' to run the document vectors with"

# ── the generator: the pinned sce-codegen ───────────────────────────────────────
rc=0
sce_codegen_ensure "Layer Bc" || rc=$?
case "$rc" in
    0) ;;
    2) cannot_run "the pinned sce-codegen is unavailable (see the line above)" ;;
    *) fail "the pinned sce-codegen could not be built" ;;
esac
CODEGEN="$(sce_codegen_binary "$WZ_SCE_DIR")"

# SCE ADR 0110 D3's flags, and every inline function kept (see the header).
TARGET_FLAGS=(-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16)
CFLAGS=("${TARGET_FLAGS[@]}" -std=c11 -ffreestanding -nostdlib -Os -ffunction-sections -fdata-sections
        -Wall -Wextra -Wpedantic -Werror -fkeep-inline-functions -fkeep-static-functions)
INCLUDES=(-I "$SCE/backends/c/runtime/include" -I "$SCE/backends/c/forge-runtime/include" -I "$GEN")

rm -rf "$OUT"
mkdir -p "$GEN" "$OBJ" "$HOST"

# ── 1. generate the set ─────────────────────────────────────────────────────────
mapfile -t DOCUMENTS < <(LC_ALL=C ls sources/codecs/*.scxml sources/algorithms/*.scxml)
(( ${#DOCUMENTS[@]} > 0 )) || fail "no document under sources/codecs or sources/algorithms"
# The standard documents the set imports, read from the documents' own imports.
mapfile -t STANDARD < <(python3 - "${DOCUMENTS[@]}" <<'PY'
import sys
import xml.etree.ElementTree as ET
seen = set()
for path in sys.argv[1:]:
    for node in ET.parse(path).iter():
        src = node.get("src") or ""
        if node.tag.endswith("}import") and src.startswith("sce:std/"):
            seen.add(src)
print("\n".join(sorted(seen)))
PY
)
ARGS=()
for doc in "${DOCUMENTS[@]}" "${STANDARD[@]}"; do
    [[ -n "$doc" ]] && ARGS+=(--document "$doc")
done
rc=0
sce_codegen_spawn "$CODEGEN" "$WZ_SCE_DIR" "$OUT/generate.stderr" \
    orchestrate -l c11 --deploy "$DEPLOY" --input-root sources --output-dir "$GEN" "${ARGS[@]}" \
    >"$OUT/generate.stdout" || rc=$?
if (( rc != 0 )); then
    cat "$OUT/generate.stderr" >&2
    fail "the C11 generation of the set exited $rc"
fi

UNITS=()
declare -A IS_UNIT
for header in "$GEN"/*.h; do
    [[ -e "$header" && "$header" != *_test.h ]] || continue
    UNITS+=("$(basename "$header" .h)")
    IS_UNIT["$(basename "$header" .h)"]=1
done
(( ${#UNITS[@]} > 0 )) || fail "the generation wrote no header into $GEN"

# ── what may stay undefined in a freestanding object ────────────────────────────
LIBGCC="$("$GCC" "${TARGET_FLAGS[@]}" -print-libgcc-file-name)"
[[ -f "$LIBGCC" ]] || cannot_run "the toolchain names no libgcc for ${TARGET_FLAGS[*]} ($LIBGCC)"
declare -A ALLOWED=([memcpy]=1 [memset]=1 [memmove]=1 [memcmp]=1)
while read -r sym; do
    ALLOWED["$sym"]=1
done < <("$NM" -g --defined-only "$LIBGCC" 2>/dev/null | awk 'NF == 3 { print $3 }')

# ── the declared refusals and the budget ────────────────────────────────────────
declare -A REFUSED_HEADER REFUSED_MESSAGE
while IFS=$'\t' read -r unit header message _cause; do
    [[ -z "$unit" || "$unit" == \#* ]] && continue
    REFUSED_HEADER["$unit"]="$header"
    REFUSED_MESSAGE["$unit"]="$message"
done < "$REFUSALS"

TOLERANCE="$(sed -n 's/^# tolerance: \([0-9][0-9]*\)$/\1/p' "$BUDGET")"
MEASURED_WITH="$(sed -n 's/^# measured-with: \(.*\)$/\1/p' "$BUDGET")"
[[ -n "$TOLERANCE" ]] || fail "$BUDGET states no '# tolerance: <bytes>' line"
declare -A WANT
while IFS=$'\t' read -r unit text rodata data bss; do
    [[ -z "$unit" || "$unit" == \#* ]] && continue
    WANT["$unit"]="$text $rodata $data $bss"
done < "$BUDGET"

FAILURES=()
MEASURED=()
OUT_OF_BAND=()
UNMEASURED=()
COMPILED=0
REFUSED_AS_DECLARED=0

# The first error a compile log names: the header it is in and its words, without the
# path and position, which move with the generator's layout and say nothing of the fault.
first_error() {
    sed -n 's|^\(.*/\)\{0,1\}\([^/:]*\.[ch]\):[0-9]*:[0-9]*: error: \(.*\)$|\2\t\3|p' "$1" | sed -n '1p'
}

{
    printf '# Layer Bc: the C11 emission of the SCE sources\n\n'
    printf -- '- Compiler: %s\n' "$GCC_VERSION"
    printf -- "- Flags: \`%s\`\n" "${CFLAGS[*]}"
    printf -- "- Set: %d documents and %d standard document(s), deployment \`%s\`\n\n" "${#DOCUMENTS[@]}" "${#STANDARD[@]}" "$DEPLOY"
    printf '| Unit | .text | .rodata | .data | .bss | verdict |\n|---|---|---|---|---|---|\n'
} > "$REPORT"

for unit in "${UNITS[@]}"; do
    src="$OBJ/$unit.c"
    obj="$OBJ/$unit.o"
    log="$OBJ/$unit.log"
    printf '#include "%s.h"\n' "$unit" > "$src"
    rc=0
    "$GCC" "${CFLAGS[@]}" "${INCLUDES[@]}" -c "$src" -o "$obj" >"$log" 2>&1 || rc=$?

    # ── 2. a unit that does not compile ──
    if (( rc != 0 )); then
        got="$(first_error "$log")"
        if [[ -n "${REFUSED_HEADER[$unit]+x}" ]]; then
            want="${REFUSED_HEADER[$unit]}"$'\t'"${REFUSED_MESSAGE[$unit]}"
            if [[ "$got" == "$want" ]]; then
                REFUSED_AS_DECLARED=$((REFUSED_AS_DECLARED + 1))
                printf '| %s | | | | | refused as declared |\n' "$unit" >> "$REPORT"
                continue
            fi
            FAILURES+=("$unit: refused with other words than $REFUSALS declares: got '${got//$'\t'/: }', declared '${want//$'\t'/: }'")
        else
            FAILURES+=("$unit: does not compile for the target with SCE ADR 0110 D3's flags: ${got//$'\t'/: }")
            sed -n '1,20p' "$log" >&2
        fi
        printf '| %s | | | | | does not compile |\n' "$unit" >> "$REPORT"
        continue
    fi
    if [[ -n "${REFUSED_HEADER[$unit]+x}" ]]; then
        FAILURES+=("$unit: compiles, and $REFUSALS still names it as refused; remove its row")
    fi
    COMPILED=$((COMPILED + 1))

    # ── 3. freestanding ──
    hosted=()
    while read -r sym; do
        [[ -z "${ALLOWED[$sym]+x}" ]] && hosted+=("$sym")
    done < <("$NM" -u "$obj" | awk '{ print $NF }')
    if (( ${#hosted[@]} > 0 )); then
        FAILURES+=("$unit: calls what no freestanding image has: ${hosted[*]}")
    fi

    # ── 4. weigh ──
    read -r text rodata data bss < <("$SIZE" -A -d "$obj" |
        awk '$1 ~ /^\.text/ { t += $2 } $1 ~ /^\.rodata/ { r += $2 }
             $1 ~ /^\.data/ { d += $2 } $1 ~ /^\.bss/ { b += $2 }
             END { printf "%d %d %d %d\n", t, r, d, b }')
    MEASURED+=("$unit"$'\t'"$text"$'\t'"$rodata"$'\t'"$data"$'\t'"$bss")
    verdict="within budget"
    if [[ -z "${WANT[$unit]+x}" ]]; then
        UNMEASURED+=("$unit")
        verdict="unmeasured"
    else
        read -r wt wr wd wb <<<"${WANT[$unit]}"
        for pair in "text $text $wt" "rodata $rodata $wr" "data $data $wd" "bss $bss $wb"; do
            read -r name got want <<<"$pair"
            if (( got > want + TOLERANCE || got < want - TOLERANCE )); then
                OUT_OF_BAND+=("$unit .$name is $got, budget $want (band $((want - TOLERANCE))..$((want + TOLERANCE)))")
                verdict="out of budget"
            fi
        done
    fi
    printf '| %s | %d | %d | %d | %d | %s |\n' "$unit" "$text" "$rodata" "$data" "$bss" "$verdict" >> "$REPORT"
done

# A budget row or a refusal whose unit the set no longer has names nothing. Membership is
# read from the set, not from a pipe into `grep -q`: under pipefail a grep that stops at its
# first match leaves the writer a SIGPIPE and the pipe reads as "absent".
for unit in "${!WANT[@]}"; do
    [[ -n "${IS_UNIT[$unit]+x}" ]] \
        || FAILURES+=("$BUDGET holds a row for '$unit', which the set does not generate")
done
for unit in "${!REFUSED_HEADER[@]}"; do
    [[ -n "${IS_UNIT[$unit]+x}" ]] \
        || FAILURES+=("$REFUSALS names '$unit', which the set does not generate")
done

# ── 5. the document vectors, on the host ────────────────────────────────────────
VECTOR_UNITS=0
VECTOR_ROWS=0
for sidecar in "$GEN"/*_test.h; do
    [[ -e "$sidecar" ]] || continue
    unit="$(basename "$sidecar" _test.h)"
    doc=""
    for candidate in "${DOCUMENTS[@]}"; do
        [[ "$candidate" == */"$unit".scxml ]] && { doc="$candidate"; break; }
    done
    [[ -n "$doc" ]] || { FAILURES+=("$unit: a vector sidecar of no document of the set"); continue; }
    stated="$(grep -c '<sce:test-vector[ >]' "$doc" || true)"
    runs="$(grep -o '@SCXML L[0-9]*' "$sidecar" | LC_ALL=C sort -u | wc -l)"
    if (( runs != stated )); then
        FAILURES+=("$unit: the document states $stated vector(s) and its sidecar runs $runs")
        continue
    fi
    prog="$HOST/$unit"
    printf '#include <stdio.h>\n#include "%s.h"\n#include "%s_test.h"\nint main(void) {\n    int failures = test_vector_%s();\n    printf("%%d\\n", failures);\n    return failures != 0;\n}\n' \
        "$unit" "$unit" "$unit" > "$prog.c"
    if ! "$HOST_CC" -std=c11 -Wall -Wextra -Wpedantic -Werror "${INCLUDES[@]}" "$prog.c" -o "$prog" >"$prog.log" 2>&1; then
        sed -n '1,20p' "$prog.log" >&2
        FAILURES+=("$unit: its vector sidecar does not compile on the host")
        continue
    fi
    rc=0
    "$prog" >"$prog.out" 2>&1 || rc=$?
    if (( rc != 0 )); then
        cat "$prog.out" >&2
        FAILURES+=("$unit: $(tail -n 1 "$prog.out") of its $runs document vector(s) failed")
        continue
    fi
    VECTOR_UNITS=$((VECTOR_UNITS + 1))
    VECTOR_ROWS=$((VECTOR_ROWS + runs))
done

{
    printf "\n- Compiled freestanding: %d; refused as \`%s\` declares: %d\n" "$COMPILED" "$REFUSALS" "$REFUSED_AS_DECLARED"
    printf -- '- Document vectors held on the host: %d row(s) of %d document(s)\n' "$VECTOR_ROWS" "$VECTOR_UNITS"
} >> "$REPORT"

if (( RECORD )); then
    {
        sed -n '/^#/p' "$BUDGET" | sed "s|^# measured-with: .*$|# measured-with: $GCC_VERSION|"
        printf '%s\n' "${MEASURED[@]}" | LC_ALL=C sort
    } > "$BUDGET.new"
    mv "$BUDGET.new" "$BUDGET"
    echo "c11-lane: recorded ${#MEASURED[@]} unit(s) into $BUDGET with $GCC_VERSION; read the diff and say in the commit what the bytes bought"
fi

if (( ${#FAILURES[@]} > 0 )); then
    printf '  [Bc] %s\n' "${FAILURES[@]}" >&2
    fail "${#FAILURES[@]} finding(s); the report is $REPORT"
fi
if (( ! RECORD )); then
    if (( ${#UNMEASURED[@]} > 0 )); then
        fail "$BUDGET holds no figures for: ${UNMEASURED[*]}; measure them with --record and say in the commit what was measured"
    fi
    if (( ${#OUT_OF_BAND[@]} > 0 )); then
        printf '  [Bc] %s\n' "${OUT_OF_BAND[@]}" >&2
        printf '  [Bc] running %s; the budget was measured with %s\n' "$GCC_VERSION" "$MEASURED_WITH" >&2
        fail "a unit's cost on the target is outside its budget; re-record with --record if the change is meant"
    fi
fi
echo "Bc: $COMPILED unit(s) compiled with no C library and weighed, $REFUSED_AS_DECLARED refused as declared, $VECTOR_ROWS document vector(s) of $VECTOR_UNITS document(s) held"

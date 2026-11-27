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
#   1. GENERATE. Every document under sources/ (codecs, algorithms, statecharts, buffer
#      pools, event schemas, links, the feature model), with the standard documents
#      they import, as ONE set: `sce-codegen orchestrate -l c11 --deploy
#      deploy/codec_node.yaml`. One set because a node is built from one source set
#      under one deployment: a deployment is a property of the set (SCE refuses
#      `generate --with-imports --deploy` for that reason), its cross-document
#      validators (links, reassembly) judge the set together, and C11 holds every list
#      in an array of the capacity the deployment gives it. The generator refuses the
#      whole set when it refuses one document, so a document deploy/c11/refusals.tsv
#      declares refused by the generator is left out of the set and generated alone,
#      with the same arguments, where it must be refused with the declared words.
#   2. COMPILE. A unit with a translation unit of its own (`<unit>.c`, a statechart's
#      machine) is compiled as SCE's own gate compiles a machine: that file, with SCE
#      ADR 0110 D3's flags exactly (Cortex-M4, -ffreestanding -nostdlib -Werror); its
#      functions have external linkage, so every one is compiled and judged. The
#      saved-state unit (`*_saved`) is not: a deployment that does not persist does
#      not link it, and it is the one unit that may use the hosted library (D2). A
#      header-only unit (a codec, an algorithm, a schema, a pool) is its header alone,
#      as its own translation unit, with D3's flags and every inline function kept
#      (-fkeep-inline-functions -fkeep-static-functions): without them it compiles to
#      nothing and nothing is judged.
#   3. FREESTANDING. A unit's object may leave undefined only the four memory
#      functions every C environment supplies (SCE ADR 0110 D1), what libgcc of the
#      same multilib defines, and the seams: the functions SCE's runtime headers
#      declare for a core to call and a deployment to define (D2), read as the SCE
#      gate links them, from SCE's MCU board (backends/c/mcu/seams.c): what that file
#      defines that a header of SCE's runtime declares, as the compiler's own
#      -aux-info reads both. Any other undefined symbol is a call into a hosted
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
# A document the generator refuses, a unit that does not compile and a unit that calls
# something hosted are each a failure unless deploy/c11/refusals.tsv names it with what
# it gives. A named one that passes, or fails with other words, fails too: the table
# only shrinks by the fix it waits for.
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

# SCE ADR 0110 D3's flags, exactly; a header-only unit adds every inline function kept
# (see the header).
TARGET_FLAGS=(-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16)
D3_FLAGS=("${TARGET_FLAGS[@]}" -std=c11 -ffreestanding -nostdlib -Os -ffunction-sections -fdata-sections
          -Wall -Wextra -Wpedantic -Werror)
KEEP_FLAGS=(-fkeep-inline-functions -fkeep-static-functions)
# The checkout's and the artifact root's absolute paths, mapped away. A unit that reaches
# assert() carries __FILE__ in .rodata, so without this a figure measured the length of the
# directory the tree was checked out in: the pools' .rodata moved by one byte between two
# worktrees whose names differ by one character, and a hosted runner's path is another.
PATH_FLAGS=("-ffile-prefix-map=$ROOT/=" "-ffile-prefix-map=$WZ_ARTIFACTS/=")
INCLUDES=(-I "$SCE/backends/c/runtime/include" -I "$SCE/backends/c/forge-runtime/include" -I "$GEN")

rm -rf "$OUT"
mkdir -p "$GEN" "$OBJ" "$HOST" "$OUT/refused"

FAILURES=()
MEASURED=()
OUT_OF_BAND=()
UNMEASURED=()
COMPILED=0
REFUSED_AS_DECLARED=0
CALLS_AS_DECLARED=0
GENERATION_REFUSED=0

# ── the declared refusals ───────────────────────────────────────────────────────
# Keyed by a unit, or by a document's path for one the generator refuses.
declare -A REFUSED_WHERE REFUSED_WORDS
while IFS=$'\t' read -r unit where words _cause; do
    [[ -z "$unit" || "$unit" == \#* ]] && continue
    REFUSED_WHERE["$unit"]="$where"
    REFUSED_WORDS["$unit"]="$words"
done < "$REFUSALS"

# The standard documents the documents given import, read from their own imports.
standard_imports() {
    python3 - "$@" <<'PY'
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
}

# The words of the generator's first error, without the file and position it names,
# which move with the tree's layout and say nothing of the fault.
generator_error() {
    sed -n 's|^[^ :]*\(:[0-9][0-9]*\)*: \(.*[Ee]rror: .*\)$|\2|p' "$1" | sed -n '1p'
}

# Generate the documents given as one set, with the standard documents they import, into
# the directory $1, its standard error into the file $2. Returns the generator's status.
generate_set() {
    local into="$1" errf="$2" doc
    shift 2
    local args=() standard=()
    mapfile -t standard < <(standard_imports "$@")
    for doc in "$@" "${standard[@]}"; do
        [[ -n "$doc" ]] && args+=(--document "$doc")
    done
    sce_codegen_spawn "$CODEGEN" "$WZ_SCE_DIR" "$errf" \
        orchestrate -l c11 --deploy "$DEPLOY" --input-root sources --output-dir "$into" "${args[@]}"
}

# ── 1. generate the set ─────────────────────────────────────────────────────────
mapfile -t SOURCES < <(LC_ALL=C ls sources/*/*.scxml)
(( ${#SOURCES[@]} > 0 )) || fail "no document under sources/"
declare -A IS_SOURCE
DOCUMENTS=()
for doc in "${SOURCES[@]}"; do
    IS_SOURCE["$doc"]=1
    if [[ "${REFUSED_WHERE[$doc]:-}" != generate ]]; then
        DOCUMENTS+=("$doc")
        continue
    fi
    # Declared refused by the generator: generated alone, with the arguments the set takes.
    alone="$OUT/refused/$(basename "$doc" .scxml)"
    mkdir -p "$alone"
    rc=0
    generate_set "$alone" "$alone.stderr" "$doc" >"$alone.stdout" || rc=$?
    case "$rc" in
        0)
            FAILURES+=("$doc: generates, and $REFUSALS still names it as refused by the generator; remove its row so it joins the set")
            ;;
        125 | 126)
            cat "$alone.stderr" >&2
            fail "the generation of $doc could not be judged (sce_codegen_spawn returned $rc)"
            ;;
        *)
            got="$(generator_error "$alone.stderr")"
            if [[ "$got" == "${REFUSED_WORDS[$doc]}" ]]; then
                GENERATION_REFUSED=$((GENERATION_REFUSED + 1))
            else
                cat "$alone.stderr" >&2
                FAILURES+=("$doc: refused by the generator with other words than $REFUSALS declares: got '$got', declared '${REFUSED_WORDS[$doc]}'")
            fi
            ;;
    esac
done
(( ${#DOCUMENTS[@]} > 0 )) || fail "every document under sources/ is declared refused"
mapfile -t STANDARD < <(standard_imports "${DOCUMENTS[@]}")
rc=0
generate_set "$GEN" "$OUT/generate.stderr" "${DOCUMENTS[@]}" >"$OUT/generate.stdout" || rc=$?
if (( rc != 0 )); then
    cat "$OUT/generate.stderr" >&2
    fail "the C11 generation of the set exited $rc"
fi

UNITS=()
declare -A IS_UNIT
for header in "$GEN"/*.h; do
    [[ -e "$header" ]] || continue
    unit="$(basename "$header" .h)"
    case "$unit" in *_test | *_saved) continue ;; esac
    UNITS+=("$unit")
    IS_UNIT["$unit"]=1
done
(( ${#UNITS[@]} > 0 )) || fail "the generation wrote no header into $GEN"
# Every translation unit the generator wrote is a unit's, but the saved-state one (D2).
for source in "$GEN"/*.c; do
    [[ -e "$source" ]] || continue
    unit="$(basename "$source" .c)"
    case "$unit" in *_saved) continue ;; esac
    [[ -n "${IS_UNIT[$unit]+x}" ]] \
        || FAILURES+=("$(basename "$source"): a translation unit with no header of its name, which no unit compiles")
done

# ── what may stay undefined in a freestanding object ────────────────────────────
LIBGCC="$("$GCC" "${TARGET_FLAGS[@]}" -print-libgcc-file-name)"
[[ -f "$LIBGCC" ]] || cannot_run "the toolchain names no libgcc for ${TARGET_FLAGS[*]} ($LIBGCC)"
declare -A ALLOWED=([memcpy]=1 [memset]=1 [memmove]=1 [memcmp]=1)
while read -r sym; do
    ALLOWED["$sym"]=1
done < <("$NM" -g --defined-only "$LIBGCC" 2>/dev/null | awk 'NF == 3 { print $3 }')
# The seams: what SCE's board defines (the definitions its gate links a machine with)
# that a header of SCE's runtime declares, each as the compiler read it.
BOARD_SEAMS="$SCE/backends/c/mcu/seams.c"
[[ -f "$BOARD_SEAMS" ]] || fail "vendor/sce holds no backends/c/mcu/seams.c, the seams SCE's gate links a machine with"
"$GCC" "${D3_FLAGS[@]}" "${INCLUDES[@]}" -I "$SCE/backends/c/mcu" -fsyntax-only -aux-info "$OBJ/seams.aux" \
    "$BOARD_SEAMS" >"$OBJ/seams.log" 2>&1 \
    || { cat "$OBJ/seams.log" >&2; fail "SCE's board seams ($BOARD_SEAMS) do not compile with D3's flags"; }
mapfile -t SEAMS < <(python3 - "$OBJ/seams.aux" "$BOARD_SEAMS" \
    "$SCE/backends/c/runtime/include" "$SCE/backends/c/forge-runtime/include" <<'PY'
import os
import re
import sys
aux, board, *roots = sys.argv[1:]
board = os.path.realpath(board)
roots = [os.path.realpath(r) + os.sep for r in roots]
# "/* <file>:<line>:<N|O><C|F> */ <declaration>": C a declaration, F a definition.
line_re = re.compile(r"^/\* (.+):\d+:[NO]([CF]) \*/ (.*?)\b([A-Za-z_]\w*) \(")
declared, defined = set(), set()
with open(aux, encoding="utf-8") as f:
    for line in f:
        m = line_re.match(line)
        if not m or "static" in m.group(3).split():
            continue
        path, kind, name = os.path.realpath(m.group(1)), m.group(2), m.group(4)
        if kind == "F" and path == board:
            defined.add(name)
        elif kind == "C" and any(path.startswith(r) for r in roots):
            declared.add(name)
print("\n".join(sorted(defined & declared)))
PY
)
[[ ${#SEAMS[@]} -gt 0 && -n "${SEAMS[0]}" ]] \
    || fail "$BOARD_SEAMS defines no function a header of SCE's runtime declares; the seams could not be read"
for sym in "${SEAMS[@]}"; do
    ALLOWED["$sym"]=1
done

# ── the budget ──────────────────────────────────────────────────────────────────
TOLERANCE="$(sed -n 's/^# tolerance: \([0-9][0-9]*\)$/\1/p' "$BUDGET")"
MEASURED_WITH="$(sed -n 's/^# measured-with: \(.*\)$/\1/p' "$BUDGET")"
[[ -n "$TOLERANCE" ]] || fail "$BUDGET states no '# tolerance: <bytes>' line"
declare -A WANT
while IFS=$'\t' read -r unit text rodata data bss; do
    [[ -z "$unit" || "$unit" == \#* ]] && continue
    WANT["$unit"]="$text $rodata $data $bss"
done < "$BUDGET"

# The first error a compile log names: the header it is in and its words, without the
# path and position, which move with the generator's layout and say nothing of the fault.
first_error() {
    sed -n 's|^\(.*/\)\{0,1\}\([^/:]*\.[ch]\):[0-9]*:[0-9]*: error: \(.*\)$|\2\t\3|p' "$1" | sed -n '1p'
}

{
    printf '# Layer Bc: the C11 emission of the SCE sources\n\n'
    printf -- '- Compiler: %s\n' "$GCC_VERSION"
    printf -- "- Flags: \`%s\`; a header-only unit adds \`%s\`\n" "${D3_FLAGS[*]}" "${KEEP_FLAGS[*]}"
    printf -- "- Set: %d documents and %d standard document(s), deployment \`%s\`; %d document(s) left out as refused by the generator\n" \
        "${#DOCUMENTS[@]}" "${#STANDARD[@]}" "$DEPLOY" "$(( ${#SOURCES[@]} - ${#DOCUMENTS[@]} ))"
    printf -- "- Seams a unit may leave undefined (\`%s\` defines, SCE's runtime declares): %s\n\n" \
        "${BOARD_SEAMS#"$ROOT"/}" "${SEAMS[*]}"
    printf '| Unit | .text | .rodata | .data | .bss | verdict |\n|---|---|---|---|---|---|\n'
} > "$REPORT"

for unit in "${UNITS[@]}"; do
    obj="$OBJ/$unit.o"
    log="$OBJ/$unit.log"
    if [[ -f "$GEN/$unit.c" ]]; then
        src="$GEN/$unit.c"
        flags=("${D3_FLAGS[@]}" "${PATH_FLAGS[@]}")
    else
        src="$OBJ/$unit.c"
        printf '#include "%s.h"\n' "$unit" > "$src"
        flags=("${D3_FLAGS[@]}" "${PATH_FLAGS[@]}" "${KEEP_FLAGS[@]}")
    fi
    declared_where="${REFUSED_WHERE[$unit]:-}"
    rc=0
    "$GCC" "${flags[@]}" "${INCLUDES[@]}" -c "$src" -o "$obj" >"$log" 2>&1 || rc=$?

    # ── 2. a unit that does not compile ──
    if (( rc != 0 )); then
        got="$(first_error "$log")"
        if [[ -n "$declared_where" ]]; then
            want="$declared_where"$'\t'"${REFUSED_WORDS[$unit]}"
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
    if [[ -n "$declared_where" && "$declared_where" != undefined ]]; then
        FAILURES+=("$unit: compiles, and $REFUSALS still names it as refused; remove its row")
    fi
    COMPILED=$((COMPILED + 1))

    # ── 3. freestanding ──
    hosted=()
    while read -r sym; do
        [[ -z "${ALLOWED[$sym]+x}" ]] && hosted+=("$sym")
    done < <("$NM" -u "$obj" | awk '{ print $NF }' | LC_ALL=C sort -u)
    calls=""
    if (( ${#hosted[@]} > 0 )); then
        if [[ "$declared_where" == undefined && "${hosted[*]}" == "${REFUSED_WORDS[$unit]}" ]]; then
            CALLS_AS_DECLARED=$((CALLS_AS_DECLARED + 1))
            calls="; calls ${hosted[*]} as declared"
        elif [[ "$declared_where" == undefined ]]; then
            FAILURES+=("$unit: calls other hosted symbols than $REFUSALS declares: got '${hosted[*]}', declared '${REFUSED_WORDS[$unit]}'")
        else
            FAILURES+=("$unit: calls what no freestanding image has: ${hosted[*]}")
        fi
    elif [[ "$declared_where" == undefined ]]; then
        FAILURES+=("$unit: calls nothing hosted, and $REFUSALS still names it as calling '${REFUSED_WORDS[$unit]}'; remove its row")
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
    printf '| %s | %d | %d | %d | %d | %s%s |\n' "$unit" "$text" "$rodata" "$data" "$bss" "$verdict" "$calls" >> "$REPORT"
done

# A budget row or a refusal whose unit the set no longer has names nothing. Membership is
# read from the set, not from a pipe into `grep -q`: under pipefail a grep that stops at its
# first match leaves the writer a SIGPIPE and the pipe reads as "absent".
for unit in "${!WANT[@]}"; do
    [[ -n "${IS_UNIT[$unit]+x}" ]] \
        || FAILURES+=("$BUDGET holds a row for '$unit', which the set does not generate")
done
for unit in "${!REFUSED_WHERE[@]}"; do
    if [[ "${REFUSED_WHERE[$unit]}" == generate ]]; then
        [[ -n "${IS_SOURCE[$unit]+x}" ]] \
            || FAILURES+=("$REFUSALS names the document '$unit', which is not under sources/")
    else
        [[ -n "${IS_UNIT[$unit]+x}" ]] \
            || FAILURES+=("$REFUSALS names '$unit', which the set does not generate")
    fi
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
    printf "\n- Compiled freestanding: %d, of which %d call what \`%s\` declares; refused as it declares: %d unit(s), %d document(s) by the generator\n" \
        "$COMPILED" "$CALLS_AS_DECLARED" "$REFUSALS" "$REFUSED_AS_DECLARED" "$GENERATION_REFUSED"
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
echo "Bc: $COMPILED unit(s) compiled with no C library and weighed, $CALLS_AS_DECLARED calling what is declared, $REFUSED_AS_DECLARED refused as declared, $GENERATION_REFUSED document(s) refused by the generator as declared, $VECTOR_ROWS document vector(s) of $VECTOR_UNITS document(s) held"

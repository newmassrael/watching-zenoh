#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y418 (no register item) — the atomic-store schema pin gate, shared by
# .githooks/pre-commit and .githooks/pre-push (R311y418).
#
# WHAT IT GRADES: whether the atomic store that a given git tree carries can be
# opened by the mnemosyne-cli that hosted CI installs. mnemosyne-atomic rejects
# `on_disk_version > CURRENT_SCHEMA_VERSION` outright and cannot lazy-migrate
# down, so a local mutate that migrates the store past the pinned reader turns
# every hosted run red at Layer A and skips A2/A3/A4/B/B2 behind it.
#
# The class has fired FOUR times, each time discovered only on hosted CI:
#   R311y15   store=23 expected <= 9    (pin 48117d24 -> bb01cc6b)
#   R311y401  store=41 expected <= 39   (repaired at R311y403, -> d9e2beed)
#   R311y406  store=42 expected <= 41   (pin -> b95b45d0)
#   R311y416  store=43 expected <= 42   (repaired at R311y417, -> d7f048b5)
# R311y417's carry called it "a class that has now fired twice"; enumerating
# the ledger instead of inheriting that number is what produced the four.
#
# WHICH TREE: always a git object spec, never the working tree. Hosted CI grades
# what was COMMITTED, so the gate must grade the same artifact — pre-commit
# passes ':' (the index, i.e. what this commit will contain) and pre-push passes
# '<sha>:' (the commits actually being pushed). Grading the working tree was the
# first cut and it was wrong in both directions: it let an index-only staging
# escape unseen, and it blocked unrelated commits over a migration that was
# still uncommitted and therefore red nowhere.
#
# This file is PURE FUNCTION DEFINITIONS. Sourcing it must stay side-effect
# free — the hooks source it, and a hook that executes its dependencies is how
# the first cut of this round briefly ran `cargo install` from a commit hook.
# Do not add top-level statements.

WZ_PIN_SCRIPT="scripts/install-mnemosyne-cli.sh"
WZ_ATOMIC_STORE="docs/.atomic/workspace.atomic.json"

# _wz_extract_one <content> <var-name> <value-regex>
# Prints the single captured value, or fails loudly. Anything other than
# exactly one match is an error, never a fallback: a text contract across two
# files is only safe while it is incapable of degrading quietly.
_wz_extract_one() {
    local content="$1" var="$2" value_re="$3" hits count
    hits="$(sed -nE "s/^${var}=\"?(${value_re})\"?[[:space:]]*$/\1/p" <<<"$content")"
    if [[ -z "$hits" ]]; then
        count=0
    else
        count="$(printf '%s\n' "$hits" | wc -l | tr -d '[:space:]')"
    fi
    if [[ "$count" != "1" ]]; then
        echo "  expected exactly 1 ${var} assignment in ${WZ_PIN_SCRIPT};" >&2
        echo "  found ${count}. Required form: ${var}=\"<value>\" on one line," >&2
        echo "  unindented, unquoted or double-quoted, with no trailing comment." >&2
        return 1
    fi
    printf '%s' "$hits"
}

# wz_pin_ceiling <spec-prefix>   e.g. ':' or '<sha>:'
# The decimal ceiling is bounded to 6 digits and forbids a leading zero: bash
# `(( ))` reads 043 as octal 35 (a false red) and errors out entirely on 08/09
# — and an erroring `(( ))` inside an `if` is FALSE, which would have skipped
# the comparison and passed the commit. A gate must not fail open on its own
# arithmetic.
wz_pin_ceiling() {
    local spec="$1" src
    if ! src="$(git show "${spec}${WZ_PIN_SCRIPT}" 2>/dev/null)"; then
        echo "  cannot read ${WZ_PIN_SCRIPT} at '${spec}' — untracked, deleted," >&2
        echo "  or absent from that tree. The CI schema pin and this gate are" >&2
        echo "  one contract." >&2
        return 1
    fi
    _wz_extract_one "$src" MNEMOSYNE_MAX_SCHEMA '0|[1-9][0-9]{0,5}'
}

# wz_pin_rev <spec-prefix> — the pinned mnemosyne commit (40 hex chars).
wz_pin_rev() {
    local spec="$1" src
    src="$(git show "${spec}${WZ_PIN_SCRIPT}" 2>/dev/null)" || return 1
    _wz_extract_one "$src" MNEMOSYNE_REV '[0-9a-f]{40}'
}

# wz_store_schema <spec-prefix> — the store's schema_version at that tree.
# python3 rather than a grep because a JSON parse is indifferent to how the
# store is serialized and type-checks the value; the literal `schema_version`
# also occurs 22 times in ledger prose inside this file, so only the structure
# distinguishes the key from a quotation of it. python3's absence is a hard
# FAIL, never a skip — a gate that cannot read its input must not report green
# (scripts/run-ci.sh:1061, Layer C0). run-ci.sh Layers D (:4603) and F (:4873)
# do SKIP-green on python3, but each sits behind a WZ_*_REQUIRE arming flag
# with a hosted hard-fail behind it; a git hook has neither, so a skip there
# would be permanent and unobserved.
wz_store_schema() {
    local spec="$1" value
    if ! command -v python3 >/dev/null 2>&1; then
        echo "  python3 not on PATH — needed to read ${WZ_ATOMIC_STORE}." >&2
        return 1
    fi
    if ! value="$(git show "${spec}${WZ_ATOMIC_STORE}" 2>/dev/null | python3 -c '
import json, sys

version = json.load(sys.stdin).get("schema_version")
if isinstance(version, bool) or not isinstance(version, int):
    sys.exit("schema_version absent or not an integer")
print(version)
' 2>/dev/null)"; then
        echo "  cannot read schema_version from ${WZ_ATOMIC_STORE} at '${spec}'" >&2
        echo "  — file absent from that tree, malformed JSON, or the key is" >&2
        echo "  missing / not an integer." >&2
        return 1
    fi
    if [[ ! "$value" =~ ^(0|[1-9][0-9]{0,5})$ ]]; then
        echo "  unexpected schema_version '${value}' in ${WZ_ATOMIC_STORE}" >&2
        return 1
    fi
    printf '%s' "$value"
}

# wz_schema_pin_gate <spec-prefix> <hook-label> <what-label>
# 0 = the store at that tree is within the pinned reader's ceiling.
wz_schema_pin_gate() {
    local spec="$1" hook="$2" what="$3" ceiling store
    if ! ceiling="$(wz_pin_ceiling "$spec")"; then
        echo "${hook}: cannot resolve the CI schema pin (${what})." >&2
        return 1
    fi
    if ! store="$(wz_store_schema "$spec")"; then
        echo "${hook}: cannot resolve the store schema (${what})." >&2
        return 1
    fi
    if (( store > ceiling )); then
        echo "${hook}: atomic store schema OUTRUNS the pinned CI mnemosyne-cli." >&2
        echo "    graded  ${what}" >&2
        echo "    store   ${WZ_ATOMIC_STORE}  schema_version = ${store}" >&2
        echo "    CI pin  ${WZ_PIN_SCRIPT}  MNEMOSYNE_MAX_SCHEMA = ${ceiling}" >&2
        echo "" >&2
        echo "  A reader whose ceiling is below the store cannot lazy-migrate" >&2
        echo "  down, so hosted Layer A would fail with" >&2
        echo "    schema version mismatch: store=${store} expected <= ${ceiling}" >&2
        echo "  and skip A2/A3/A4/B/B2 behind it. This class has fired four" >&2
        echo "  times (R311y15, y401, y406, y416), every time on hosted CI." >&2
        echo "" >&2
        echo "  fix: in ${WZ_PIN_SCRIPT}, move MNEMOSYNE_REV to a PUSHED" >&2
        echo "       mnemosyne rev whose CURRENT_SCHEMA_VERSION >= ${store}," >&2
        echo "       and set MNEMOSYNE_MAX_SCHEMA to that number, in its own" >&2
        echo "       commit." >&2
        return 1
    fi
    return 0
}

# wz_local_cli_pin_gate <hook-label> <spec-prefix>
# Does the mnemosyne-cli ON PATH read the same schema the pin claims?
#
# R311y420. R311y419 built scripts/verify-mnemosyne-pin.sh, which asks the
# INSTALLED binary its CURRENT_SCHEMA_VERSION — but it runs from the
# installer's tail, and hooks never install, so the check could not fire
# locally. It does not need to install: the hooks already REQUIRE
# mnemosyne-cli on PATH, and `describe-schema` is a pure report of the
# binary's own constant (no store read — verified at R311y419 against a store
# hand-set to 999). So the hook can ask directly.
#
# WHAT IT CATCHES THAT THE OTHER TWO GATES CANNOT, and it is the important
# one: both of those grade AFTER a mutation has already happened.
# wz_schema_pin_gate compares the STORE to the ceiling, so it fires once the
# store has been migrated; the co-change gate only proves two constants moved
# together. This one fires BEFORE the next mutate, on the condition that
# CAUSES the migration — a PATH binary that reads a different schema than the
# reader CI installs. That is exactly the shape of R311y401 / y406 / y416,
# each of which was discovered on hosted CI after the store had already been
# committed and pushed.
#
# Both directions are a block, and both are real:
#   local > ceiling  -> the next mutate migrates the store past the pinned
#                       reader; hosted Layer A reds.
#   local < ceiling  -> this binary cannot open a store the pin permits, so
#                       any local validate is grading something CI is not.
# The remedy for either is the same: `bash scripts/install-mnemosyne-cli.sh`,
# which installs the pinned rev AND re-runs the R311y419 check.
wz_local_cli_pin_gate() {
    local hook="$1" spec="$2" ceiling actual
    command -v mnemosyne-cli >/dev/null 2>&1 || return 0   # caller already gates this
    command -v python3 >/dev/null 2>&1 || {
        echo "${hook}: python3 not on PATH — cannot read describe-schema." >&2
        return 1
    }
    ceiling="$(wz_pin_ceiling "$spec")" || {
        echo "${hook}: cannot resolve the CI schema pin." >&2
        return 1
    }
    if ! actual="$(mnemosyne-cli describe-schema --json 2>/dev/null | python3 -c '
import json, sys

version = json.load(sys.stdin).get("schema_version")
if isinstance(version, bool) or not isinstance(version, int):
    sys.exit("schema_version absent or not an integer")
print(version)
' 2>/dev/null)"; then
        echo "${hook}: \`mnemosyne-cli describe-schema --json\` gave no usable" >&2
        echo "  schema_version. If the subcommand changed upstream, re-point" >&2
        echo "  this gate and scripts/verify-mnemosyne-pin.sh together." >&2
        return 1
    fi
    if [[ "$actual" != "$ceiling" ]]; then
        echo "${hook}: the mnemosyne-cli ON PATH is not the reader CI pins." >&2
        echo "    on PATH   $(command -v mnemosyne-cli)" >&2
        echo "              reads schema ${actual}" >&2
        echo "    CI pin    ${WZ_PIN_SCRIPT}  MNEMOSYNE_MAX_SCHEMA = ${ceiling}" >&2
        echo "" >&2
        if (( actual > ceiling )); then
            echo "  This binary is AHEAD of the pin, so the next store mutate" >&2
            echo "  migrates the schema past the reader hosted CI installs and" >&2
            echo "  Layer A reds — after the commit is already pushed. That is" >&2
            echo "  how R311y401, y406 and y416 each got out." >&2
        else
            echo "  This binary is BEHIND the pin, so it cannot open every" >&2
            echo "  store CI would accept; a local validate is grading" >&2
            echo "  something the hosted gate is not." >&2
        fi
        echo "" >&2
        echo "  fix: bash ${WZ_PIN_SCRIPT}" >&2
        echo "       (installs the pinned rev and re-runs the y419 check)" >&2
        return 1
    fi
    return 0
}

# wz_schema_pin_cochange_gate <hook-label>
# The two constants are one fact in two forms, and the ceiling is the gate's
# only oracle — so raising it by one character silences the gate entirely while
# CI still installs the old reader. This refuses an index that moves
# MNEMOSYNE_MAX_SCHEMA without moving MNEMOSYNE_REV.
#
# DISCLOSED LIMIT: this proves the two moved together, NOT that the new rev's
# CURRENT_SCHEMA_VERSION actually equals the new ceiling. Verifying that needs
# the pinned build, which no git hook has — hooks never install. R311y419 built
# it where the build does exist: scripts/verify-mnemosyne-pin.sh, run from the
# tail of scripts/install-mnemosyne-cli.sh, so it fires on both workflows and on
# any local install. The split is therefore honest but real — a ceiling can be
# wrong locally for as long as nobody reinstalls the pinned CLI, and the first
# thing that notices is hosted CI.
wz_schema_pin_cochange_gate() {
    local hook="$1" idx_ceiling head_ceiling idx_rev head_rev
    git rev-parse --verify --quiet HEAD >/dev/null || return 0   # initial commit
    idx_ceiling="$(wz_pin_ceiling ':')" || return 1
    head_ceiling="$(wz_pin_ceiling 'HEAD:' 2>/dev/null)" || return 0  # newly added
    [[ "$idx_ceiling" == "$head_ceiling" ]] && return 0
    idx_rev="$(wz_pin_rev ':')" || return 1
    head_rev="$(wz_pin_rev 'HEAD:' 2>/dev/null)" || return 0
    if [[ "$idx_rev" == "$head_rev" ]]; then
        echo "${hook}: MNEMOSYNE_MAX_SCHEMA moved ${head_ceiling} -> ${idx_ceiling}" >&2
        echo "  but MNEMOSYNE_REV did not move." >&2
        echo "" >&2
        echo "  The ceiling is this gate's only oracle. Raising it alone does" >&2
        echo "  not make the pinned reader newer — it just stops the gate from" >&2
        echo "  reporting, and hosted Layer A reds exactly as before." >&2
        echo "" >&2
        echo "  fix: move MNEMOSYNE_REV to a PUSHED mnemosyne rev whose" >&2
        echo "       CURRENT_SCHEMA_VERSION is ${idx_ceiling}, in the same commit" >&2
        echo "       (crates/mnemosyne-atomic/src/lib.rs defines the constant)." >&2
        return 1
    fi
    return 0
}

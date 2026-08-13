#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y782 — append a round to the atomic ledger, with its `--impact` ids
# resolved against the section space FIRST.
#
# ## Why this exists, measured
#
# Six rounds have now cited an impact_ref that names no section: Round 193,
# R311y327, y503 (twice), y579 and R311y782 itself. Every one has the identical
# shape -- an id composed from the atom's SUBJECT rather than copied out of
# `list_sections`, which yields a plausible name for the right topic and no
# existing section. `§5.4-session` is what a person says; the store's id is
# `feature-inventory--...--preset-catalog/5-atomic-feature-catalog/5-4-session`.
#
# Four of those corrections each wrote the lesson down as prose, and it recurred
# anyway. y579a stopped restating it and named the real gap instead: nothing
# checks an impact_ref against the section space AT APPEND TIME. That is the
# whole of the problem, because the window is one call wide --
# `validate-workspace` does catch these, but by then `append-changelog-entry`
# has FROZEN the entry, and a frozen entry cannot be corrected by an edit. The
# cheapest fix (retype the id) is unavailable; what remains is an orphan-ledger
# row plus a whole re-citing round. So the cost of being half a second late is
# roughly a hundred times the cost of being on time.
#
# This closes that window. Every `--impact` id is resolved BEFORE the append,
# and a miss refuses with the near-miss candidates rather than a bare "no".
#
# ## Usage
#
#   scripts/append-round.sh --entry-id "Round N" --decision-file <f> \
#       --changes-file <f> --verification-file <f> --carry-file <f> \
#       --impact <id>[,<id>...]
#
# Arguments are passed through to `mnemosyne-cli append-changelog-entry`
# UNCHANGED; this script adds a precondition and takes nothing away. A leading
# `§` on an id is accepted and stripped for the lookup, because that is how the
# CLI itself stores them.
#
# ## --check-only
#
# Resolves the ids and exits WITHOUT appending. That is what Layer C0i runs, in
# both directions, and the flag exists for that reason: a refusal is the whole
# value here, so it has to be something a lane can fail. R311y783 added it
# because C0's store-reader gate refused this script for the right reason --
# "a gate nothing runs cannot fail" -- and it was correct: R311y782 shipped the
# check with no witness that it discriminates.
#
# The flag is stripped before the pass-through, so it is not handed to the CLI.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    echo "append-round: FAIL mnemosyne-cli is not on PATH" >&2
    echo "  A gate that cannot read its input must not report green." >&2
    exit 1
fi

# Collect the --impact list. Both spellings are accepted because the CLI
# accepts both; a gate that understood only one would be bypassable by typing
# the other.
impact=""
saw_impact=0
check_only=0
prev=""
passthrough=()
for arg in "$@"; do
    case "$prev" in
        --impact) impact="$arg"; saw_impact=1 ;;
    esac
    case "$arg" in
        --impact=*) impact="${arg#--impact=}"; saw_impact=1 ;;
        --check-only) check_only=1; prev="$arg"; continue ;;
    esac
    passthrough+=("$arg")
    prev="$arg"
done

if [[ $saw_impact -eq 0 ]]; then
    echo "append-round: FAIL no --impact given" >&2
    echo "  An entry with empty impact_refs is nearly always incomplete" >&2
    echo "  planning (mnemosyne://concepts/workflow). Name the sections the" >&2
    echo "  round actually moved." >&2
    exit 1
fi

# The section space, once. Read rather than queried per id: 200+ ids is one
# process instead of one process each, and the near-miss suggestion below needs
# the whole set anyway.
sections="$(mnemosyne-cli query --list-sections)"
if [[ -z "$sections" ]]; then
    echo "append-round: FAIL the section space came back EMPTY" >&2
    echo "  Every id would 'miss' and the refusal would be meaningless." >&2
    exit 1
fi

missing=0
# The list is comma-separated (one --impact flag carrying every id), which is
# the shape CLAUDE.md documents.
IFS=',' read -r -a impact_ids <<< "$impact"
for raw in "${impact_ids[@]}"; do
    # Trim surrounding whitespace and the spoken-form section mark.
    id="${raw#"${raw%%[![:space:]]*}"}"
    id="${id%"${id##*[![:space:]]}"}"
    id="${id#§}"
    [[ -z "$id" ]] && continue
    if grep -Fxq -- "$id" <<< "$sections"; then
        continue
    fi
    missing=1
    echo "append-round: FAIL impact ref names no section: '$id'" >&2
    # The observed failure is always a SUFFIX of a real id, so offer those.
    # Searched twice: literally, and with `.` normalised to `-`, because the
    # spoken form of a section number uses dots (`5.4-session`) where the id
    # uses dashes (`5-4-session`). Without that second pass the suggestion
    # misses on the very shape it exists to catch -- measured: the R311y782
    # refusal printed "no candidates" for an id whose target was one
    # punctuation class away.
    cands="$(grep -F -- "$id" <<< "$sections" || true)"
    if [[ -z "$cands" ]]; then
        cands="$(grep -F -- "${id//./-}" <<< "$sections" || true)"
    fi
    if [[ -n "$cands" ]]; then
        echo "  Did you mean one of:" >&2
        # shellcheck disable=SC2001
        sed 's/^/    /' <<< "$cands" >&2
    else
        echo "  No section id contains that text at all." >&2
    fi
done

if [[ $missing -ne 0 ]]; then
    echo "append-round: REFUSED -- nothing was appended." >&2
    echo "  This is the cheap moment. After append-changelog-entry the entry" >&2
    echo "  is frozen (Round 161 §41) and the fix costs an orphan-ledger row" >&2
    echo "  plus a re-citing round. Copy the id out of \`list_sections\`." >&2
    exit 1
fi

if [[ $check_only -eq 1 ]]; then
    echo "append-round: OK ${#impact_ids[@]} impact ref(s) resolve; --check-only, nothing appended"
    exit 0
fi

exec mnemosyne-cli append-changelog-entry "${passthrough[@]}"

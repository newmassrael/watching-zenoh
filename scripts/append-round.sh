#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
#
# R2743 — what `--check-only` grades is WHAT IT WAS GIVEN. With an `--impact`
# alone (Layer C0i's three arms) it resolves the ids and stops; hand it prose
# files as well and it also runs the two prose preconditions over them, which
# makes it a faithful dry run of everything an append would refuse. The prose
# checks used to run above this exit unconditionally, so the ids-only form --
# the only form the lane uses -- was refused for carrying no prose, which is
# the Layer C0i red in run 35463726230.

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
# R2729 — the round's own prose files, collected the same way the impact list
# is: off THIS invocation's argv, never a list written down here. They are the
# population of the home-path precondition below.
prose_files=()
for arg in "$@"; do
    case "$prev" in
        --impact) impact="$arg"; saw_impact=1 ;;
        --decision-file|--changes-file|--verification-file|--carry-file)
            prose_files+=("$arg") ;;
    esac
    case "$arg" in
        --impact=*) impact="${arg#--impact=}"; saw_impact=1 ;;
        --decision-file=*|--changes-file=*|--verification-file=*|--carry-file=*)
            prose_files+=("${arg#*=}") ;;
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

# ─── the two PROSE preconditions ────────────────────────────────────
#
# R2743 moved them below the impact resolution and put them behind THIS
# condition, and the move is the repair rather than a tidy-up.
#
# Both grade `${prose_files[@]}`, and both refuse an EMPTY population on the
# rule they are right to hold: a gate that scanned nothing must not report
# green. But `--check-only` supplies no prose BY CONSTRUCTION -- its contract is
# "resolve the ids and append nothing", so Layer C0i invokes it with an
# `--impact` and nothing else. Run unconditionally above the exit below, a
# precondition on the round's prose therefore asks a mode with no subject to
# produce one, and refuses every correct invocation of it.
#
# So the condition is the SUBJECT, not the mode: run when there is prose to
# grade, and run for a real append whatever it was given -- an append with no
# prose still meets the empty-population refusal, which is what keeps prose
# effectively mandatory for an entry. `--check-only` WITH prose is then a
# faithful dry run of both, which is the only locally gradable witness that
# they are reached at all.
#
# ⛔ WHAT MADE THIS SURVIVE FOUR ROUNDS: hosted `$HOME` is `/home/runner`, which
# `wz_home_path_term_state` classifies as a shared CI home and SKIPS -- so the
# home-path check returned 0 before it could reach its own empty-population
# refusal, and Layer C0i went on reporting green while its POSITIVE arm was
# already dead on any developer's machine (measured: rc=1, "no prose file was
# given"). R2742's citation gate has no CI-home escape, so it removed the mask
# rather than introducing the defect. The lesson is the placement, not either
# gate.
#
# ⚠ AND NEITHER IS WITNESSABLE HOSTED, which is why no C0i arm was added for
# them here: the home-path check skips on the CI home and the citation check
# skips with no pinned checkout, so a negative arm that must see a REFUSAL
# cannot get one on a runner. Registered rather than bolted on.
#
# Nothing has been appended at this point, so both keep the property their own
# comments claim: this is still the cheap moment, the prose is still a file,
# and no frozen entry is being asked to change.
if (( check_only == 0 )) || (( ${#prose_files[@]} > 0 )); then
    # R2729 — a home path that freezes costs a push that can never pass
    # (pre-push gate 0b), which is what wedged R2723-R2728.
    # shellcheck disable=SC1091  # constant path, resolved at run time
    if ! source "$repo_root/scripts/lib/home-path-scan.sh"; then
        echo "append-round: FAIL scripts/lib/home-path-scan.sh missing or unreadable" >&2
        echo "  A gate that cannot read its input must not report green." >&2
        exit 1
    fi
    # The `+` expansion is not style: `set -u` is on, and an EMPTY array must
    # reach the function as zero arguments so it can FAIL on an empty
    # population rather than die here with an unbound-variable error that
    # reads like a bug.
    wz_home_path_files 'append-round' ${prose_files[@]+"${prose_files[@]}"} || exit 1

    # R2742 — the SECOND precondition on the same population. An upstream
    # citation in ledger prose is graded by NOTHING once the entry freezes --
    # the anchor gate's `SKIP_PREFIXES` holds `docs/.atomic/` on purpose,
    # because grading frozen history would demand repairs to entries that must
    # not change. So the ledger is a population carrying upstream claims with
    # no oracle, which is exactly what `store_reason_citation_gate` exists for
    # one field over.
    #
    # MEASURED before wiring, over all 2740 entries: 97 anchored citations, ONE
    # of which does not resolve at the pin (Round 2723's, which gives
    # `get_port_mut` a `pub(crate)` the pin does not). One percent, permanent.
    if ! python3 "$repo_root/scripts/lib/upstream_citation_anchor_gate.py" --prose \
        ${prose_files[@]+"${prose_files[@]}"}; then
        echo "" >&2
        echo "append-round: the entry was NOT appended." >&2
        echo "  Fix the citation in the prose file and re-run: this is the last" >&2
        echo "  moment it is editable, which is the whole reason the check is" >&2
        echo "  here rather than at push time." >&2
        exit 1
    fi
fi

if [[ $check_only -eq 1 ]]; then
    echo "append-round: OK ${#impact_ids[@]} impact ref(s) resolve; --check-only, nothing appended"
    exit 0
fi

exec mnemosyne-cli append-changelog-entry "${passthrough[@]}"

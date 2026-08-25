#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y619 (no register item) — confidential-vocabulary gate for the push path.
#
# The shebang is for SHELLCHECK, not for execution: this file is sourced, never
# run, and `scripts/lib/schema-pin-gate.sh` beside it carries one for the same
# reason. Without it shellcheck cannot know the dialect and raises SC2148 — which
# is exactly how this file first reached origin red.
#
# WHY THIS IS A HOOK AND NOT A RULE
#
# This repository is PUBLIC and its main branch is unprotected by deliberate
# decision. It has already leaked once: a client document was QUOTED into a
# commit, reached origin, and needed `git filter-repo` plus a force push to
# remove — after which the content had still been public. That class of loss is
# the one thing here that a revert does not undo.
#
# Until now the only thing standing between that document's vocabulary and
# origin was an agent remembering a rule. That is not a gate. Autonomous pushes
# make it less of one: an unattended loop drops attention-based rules first.
#
# WHERE THE TERMS LIVE, AND WHY NOT HERE
#
# `$GIT_DIR/wz-nda-terms.txt` — inside `.git/`, which is structurally
# unpushable. Putting the term list in a tracked file would BE the leak: the
# list is a verbatim extract of the protected vocabulary, and committing it
# publishes exactly what it exists to keep out. Override with `WZ_NDA_TERMS`.
#
# WHY AN ABSENT LIST FAILS
#
# A gate that cannot read its input must not report green — the rule this repo
# already applies to the python3-backed schema pin. An empty word list is the
# same failure wearing a passing exit code: it matches nothing and greens every
# push -> [[feedback_a_vacuous_proof_passes_on_absence]]. So "no terms" has to
# be DECLARED (the `!acknowledged-empty` sentinel) rather than merely absent —
# an explicit statement that there is nothing to protect, made by the person who
# would know, instead of inferred from a missing file.
#
# WHAT IT SCANS
#
# Added lines of the pushed range AND the commit messages in it. The message is
# not a lesser vector: the incident this exists for put the material in a commit
# body. Matching is word-boundary and fixed-string — a substring sweep over a
# repo this size is all false positives, and the same word-boundary rule is what
# the manual scrubs used.

# Print every configured term, one per line, on stdout. Sentinel and comments
# are filtered out; the caller distinguishes the two empty cases.
_wz_nda_terms_file() {
    if [[ -n "${WZ_NDA_TERMS:-}" ]]; then
        printf '%s\n' "$WZ_NDA_TERMS"
        return 0
    fi
    printf '%s/wz-nda-terms.txt\n' "$(git rev-parse --git-dir)"
}

# wz_nda_scan <range>  e.g. wz_nda_scan "origin/main..HEAD"
# 0 = clean, 1 = blocked.
wz_nda_scan() {
    local range="$1"
    local terms_file
    terms_file="$(_wz_nda_terms_file)"

    if [[ ! -r "$terms_file" ]]; then
        echo "nda-scan: no term list at $terms_file" >&2
        echo "  This gate stands between a public repo and the vocabulary of a" >&2
        echo "  client document that has already leaked here once. It refuses to" >&2
        echo "  report green on an input it could not read." >&2
        echo "" >&2
        echo "  Create it (it lives in .git/ so it can never be pushed):" >&2
        echo "    one protected term per line; '#' comments; blank lines ignored" >&2
        echo "  Or, if there is genuinely nothing to protect, declare that:" >&2
        echo "    echo '!acknowledged-empty' > $terms_file" >&2
        return 1
    fi

    # Strip comments and blanks once; the sentinel is looked for in the same
    # pass so a file holding ONLY comments cannot pass as "declared empty".
    local live sentinel=0 count
    live="$(grep -v '^[[:space:]]*#' "$terms_file" | grep -v '^[[:space:]]*$' || true)"
    if grep -qx '!acknowledged-empty' <<<"$live"; then
        sentinel=1
        live="$(grep -vx '!acknowledged-empty' <<<"$live" || true)"
    fi
    count="$(grep -c . <<<"$live" || true)"
    [[ -z "$live" ]] && count=0

    if [[ "$count" -eq 0 ]]; then
        if [[ $sentinel -eq 1 ]]; then
            echo "nda-scan: term list DECLARED EMPTY by $terms_file — nothing to match."
            return 0
        fi
        echo "nda-scan: $terms_file holds no terms and no '!acknowledged-empty'" >&2
        echo "  An empty word list matches nothing and greens every push, which is" >&2
        echo "  a passing exit code for a check that did not run." >&2
        return 1
    fi

    local tmp_terms hits=0
    tmp_terms="$(mktemp)"
    printf '%s\n' "$live" > "$tmp_terms"

    # Added lines only: a diff that DELETES protected text is a scrub, and
    # blocking it would block the fix. `git diff -U0` keeps the file/line
    # context lines this walk attributes hits to.
    local file="" line
    while IFS= read -r line; do
        case "$line" in
            '+++ b/'*) file="${line#+++ b/}" ;;
            '@@'*)     : ;;
            '+'*)
                if grep -qiwF -f "$tmp_terms" <<<"${line:1}"; then
                    echo "nda-scan: BLOCKED — protected vocabulary in ${file:-<unknown>}" >&2
                    grep -oiwF -f "$tmp_terms" <<<"${line:1}" \
                        | sort -u | sed 's/^/  term: /' >&2
                    hits=1
                fi
                ;;
        esac
    done < <(git diff -U0 "$range" 2>/dev/null || true)

    # The commit MESSAGES in the range, which is where the known incident put it.
    if git log --format=%B "$range" 2>/dev/null | grep -qiwF -f "$tmp_terms"; then
        echo "nda-scan: BLOCKED — protected vocabulary in a commit message" >&2
        git log --format=%B "$range" 2>/dev/null \
            | grep -oiwF -f "$tmp_terms" | sort -u | sed 's/^/  term: /' >&2
        hits=1
    fi

    rm -f "$tmp_terms"

    if [[ $hits -ne 0 ]]; then
        echo "" >&2
        echo "  Rewrite the material in this repo's OWN vocabulary — what it" >&2
        echo "  REQUIRES, not what it is called. Do not push and scrub after:" >&2
        echo "  origin is public, and a filter-repo does not un-publish." >&2
        return 1
    fi

    echo "nda-scan: clean ($count term(s) checked over $range)"
    return 0
}

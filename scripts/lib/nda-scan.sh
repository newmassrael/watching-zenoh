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
# body. Only ADDED lines: a diff that deletes the vocabulary is a scrub, and
# blocking it would block the fix. Records that are frozen by design — the
# ledger, the acknowledgement rows — are therefore never asked to change.
#
# TWO KINDS OF TERM
#
# A plain line is a WORD: fixed-string, word-bounded, case-insensitive. A
# substring sweep over a repo this size is all false positives, and the same
# word-boundary rule is what the manual scrubs used.
#
# A line beginning `re:` is a SHAPE: an extended regular expression,
# case-sensitive, matched anywhere in the line, so it carries its own boundaries
# (`\b`). A word cannot say "this prefix followed by any digits": `grep -w` needs
# the character after the match to be a non-word character, and a digit is one.
# Vocabulary of that kind — a tracker's ticket ids, minted without end — is not a
# finite list. A pattern that does not compile matches nothing and would green
# every push, so it is REFUSED, not skipped; so is an empty one, which matches
# every line.
#
# `wz_nda_scan_message` is the same match applied to one commit message, so the
# refusal can come at commit time. Waiting for the push leaves the commits
# already made stranded behind a gate that will not open until they are reworded.

# Print the path of the term list on stdout.
_wz_nda_terms_file() {
    if [[ -n "${WZ_NDA_TERMS:-}" ]]; then
        printf '%s\n' "$WZ_NDA_TERMS"
        return 0
    fi
    # The COMMON dir, not `--git-dir`: in a linked worktree the latter is
    # `.git/worktrees/<name>/`, which never holds this file, so every push from
    # a worktree failed here on a list it could not find rather than on a term.
    # The list is one per repository, and the common dir is where one lives.
    printf '%s/wz-nda-terms.txt\n' "$(git rev-parse --git-common-dir)"
}

# wz_nda_terms_readable — 0 when a term list exists to be read. The commit-msg
# hook asks first: at commit time an absent list must not block every commit of
# a fresh clone. The push gate is the one that refuses on absence.
wz_nda_terms_readable() {
    [[ -r "$(_wz_nda_terms_file)" ]]
}

# _wz_nda_prepare <dir> — split the list into <dir>/fixed (words) and
# <dir>/patterns (shapes, `re:` stripped) and set WZ_NDA_TERM_COUNT.
#   0 = ready to scan     1 = refuse (unreadable, empty undeclared, bad pattern)
#   3 = declared empty: nothing to match, the caller passes
_wz_nda_prepare() {
    local dir="$1" terms_file live sentinel=0 rc=0
    terms_file="$(_wz_nda_terms_file)"

    if [[ ! -r "$terms_file" ]]; then
        echo "nda-scan: no term list at $terms_file" >&2
        echo "  This gate stands between a public repo and the vocabulary of a" >&2
        echo "  client document that has already leaked here once. It refuses to" >&2
        echo "  report green on an input it could not read." >&2
        echo "" >&2
        echo "  Create it (it lives in .git/ so it can never be pushed):" >&2
        echo "    one protected term per line; '#' comments; blank lines ignored;" >&2
        echo "    a line 're:<pattern>' is an extended regular expression" >&2
        echo "  Or, if there is genuinely nothing to protect, declare that:" >&2
        echo "    echo '!acknowledged-empty' > $terms_file" >&2
        return 1
    fi

    # Strip comments and blanks once; the sentinel is looked for in the same
    # pass so a file holding ONLY comments cannot pass as "declared empty".
    live="$(grep -v '^[[:space:]]*#' "$terms_file" | grep -v '^[[:space:]]*$' || true)"
    if grep -qx '!acknowledged-empty' <<<"$live"; then
        sentinel=1
        live="$(grep -vx '!acknowledged-empty' <<<"$live" || true)"
    fi

    WZ_NDA_TERM_COUNT=0
    if [[ -n "$live" ]]; then
        WZ_NDA_TERM_COUNT="$(grep -c . <<<"$live" || true)"
    fi

    if [[ "$WZ_NDA_TERM_COUNT" -eq 0 ]]; then
        if [[ $sentinel -eq 1 ]]; then
            return 3
        fi
        echo "nda-scan: $terms_file holds no terms and no '!acknowledged-empty'" >&2
        echo "  An empty word list matches nothing and greens every push, which is" >&2
        echo "  a passing exit code for a check that did not run." >&2
        return 1
    fi

    : > "$dir/fixed"
    : > "$dir/patterns"
    grep -v '^re:' <<<"$live" > "$dir/fixed" || true
    { grep '^re:' <<<"$live" || true; } | sed 's/^re://' > "$dir/patterns"

    if [[ -s "$dir/patterns" ]]; then
        # An empty pattern matches every line; one that does not compile makes
        # grep exit 2 and the caller's `|| true` would read that as "no match".
        if grep -q '^$' "$dir/patterns"; then
            echo "nda-scan: a 're:' term in $terms_file is empty; it would match every line" >&2
            return 1
        fi
        grep -E -f "$dir/patterns" </dev/null >/dev/null 2>&1 || rc=$?
        if [[ $rc -ge 2 ]]; then
            echo "nda-scan: a 're:' term in $terms_file is not a valid extended regular expression" >&2
            echo "  A pattern that cannot compile matches nothing, which would green every push." >&2
            return 1
        fi
    fi
    return 0
}

# _wz_nda_report_terms <matches> — the matched terms, one per line, on stderr.
_wz_nda_report_terms() {
    printf '%s\n' "$1" | sed 's/^/  term: /' >&2
}

# _wz_nda_matches <dir> — text on stdin; prints each distinct term it matched,
# one per line, and nothing when it matched none.
_wz_nda_matches() {
    local dir="$1" text
    text="$(cat)"
    {
        grep -oiwF -f "$dir/fixed" <<<"$text" || true
        grep -oE -f "$dir/patterns" <<<"$text" || true
    } | sort -u
}

# wz_nda_scan <range>  e.g. wz_nda_scan "origin/main..HEAD"
# 0 = clean, 1 = blocked.
wz_nda_scan() {
    local range="$1" dir rc=0 hits=0 file="" line found
    dir="$(mktemp -d)"
    _wz_nda_prepare "$dir" || rc=$?
    case $rc in
        0) ;;
        3)
            rm -rf "$dir"
            echo "nda-scan: term list DECLARED EMPTY by $(_wz_nda_terms_file) — nothing to match."
            return 0
            ;;
        *)
            rm -rf "$dir"
            return 1
            ;;
    esac

    # Added lines only: a diff that DELETES protected text is a scrub, and
    # blocking it would block the fix. `git diff -U0` keeps the file/line
    # context lines this walk attributes hits to.
    while IFS= read -r line; do
        case "$line" in
            '+++ b/'*) file="${line#+++ b/}" ;;
            '@@'*)     : ;;
            '+'*)
                found="$(_wz_nda_matches "$dir" <<<"${line:1}")"
                if [[ -n "$found" ]]; then
                    echo "nda-scan: BLOCKED — protected vocabulary in ${file:-<unknown>}" >&2
                    _wz_nda_report_terms "$found"
                    hits=1
                fi
                ;;
        esac
    done < <(git diff -U0 "$range" 2>/dev/null || true)

    # The commit MESSAGES in the range, which is where the known incident put it.
    found="$(git log --format=%B "$range" 2>/dev/null | _wz_nda_matches "$dir" || true)"
    if [[ -n "$found" ]]; then
        echo "nda-scan: BLOCKED — protected vocabulary in a commit message" >&2
        _wz_nda_report_terms "$found"
        hits=1
    fi

    rm -rf "$dir"

    if [[ $hits -ne 0 ]]; then
        echo "" >&2
        echo "  Rewrite the material in this repo's OWN vocabulary — what it" >&2
        echo "  REQUIRES, not what it is called. Do not push and scrub after:" >&2
        echo "  origin is public, and a filter-repo does not un-publish." >&2
        return 1
    fi

    echo "nda-scan: clean ($WZ_NDA_TERM_COUNT term(s) checked over $range)"
    return 0
}

# wz_nda_scan_message <file> — the same match over one commit message.
# 0 = clean (or declared empty), 1 = blocked or the list could not be used.
wz_nda_scan_message() {
    local msg_file="$1" dir rc=0 found
    dir="$(mktemp -d)"
    _wz_nda_prepare "$dir" || rc=$?
    case $rc in
        0) ;;
        3)
            rm -rf "$dir"
            return 0
            ;;
        *)
            rm -rf "$dir"
            return 1
            ;;
    esac

    found="$(_wz_nda_matches "$dir" < "$msg_file")"
    rm -rf "$dir"
    if [[ -n "$found" ]]; then
        echo "nda-scan: BLOCKED — protected vocabulary in this commit message" >&2
        _wz_nda_report_terms "$found"
        echo "  Say what the change REQUIRES in this repo's own words, not what the" >&2
        echo "  request was called elsewhere." >&2
        return 1
    fi
    return 0
}

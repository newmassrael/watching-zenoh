#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The IDENTITY gate — which addresses may author or commit in this tree.
#
# ## What it is for, measured
#
# Eight commits dated 2026-08-21 reached this PUBLIC repository authored with
# a work address rather than the one every other commit carries. A history
# rewrite the same week removed them from `main` and that did NOT un-publish
# them: GitHub keeps unreachable objects, was still serving all eight by SHA
# four days later, and went on listing the other account in the repository's
# contributor sidebar the whole time. Deleting and recreating the repository
# is what actually removed them -- and that cost 1146 workflow runs of CI
# history. This gate exists so the next one costs a refused commit instead.
#
# ## Why a config could not have caught it
#
# `git config user.email` was ALREADY correct, in this clone's `.git/config`
# and in `~/.gitconfig` both. The eight commits came from a different
# environment. A config is a DEFAULT and it is per-clone; a gate has to be
# something that travels with the tree, which is what a tracked hook is.
#
# ## Why it grades `git var`, never `git config`
#
# The identity a commit will carry is not what the config says. Both
# `GIT_AUTHOR_EMAIL` and `GIT_COMMITTER_EMAIL` in the environment override it,
# `git commit --author` overrides it again, and `git -c user.email=` overrides
# it for one invocation. `git var GIT_AUTHOR_IDENT` is git answering with what
# it will actually stamp, after all of that. A gate that reads the config is
# grading a different question from the one that matters.
#
# ## Why an ALLOW-list and not a deny-list
#
# Two reasons, and the first is specific to this incident. Naming the
# offending address here would write it back into a tracked file of a public
# repository, which is exactly the exposure that was just paid for. The
# second is general: an allow-list fails CLOSED for an identity nobody has
# thought about, where a deny-list passes everything it has not been taught.
#
# ## Two callers, one list
#
# `pre-commit` grades the identity the NEXT commit would carry; `pre-push`
# grades every commit in the range being pushed. Both are needed and neither
# subsumes the other -- the same split `schema-pin-gate.sh` documents at
# length. pre-commit runs only for `git commit`, so cherry-pick, rebase,
# merge and `--no-verify` reach origin without it; and a commit made on a
# machine whose hooks are not installed is caught only at the push, which is
# the shape this incident actually had.
#
# bash 3.2-clean: no `${var,,}`, no negative array subscripts, no `mapfile`.

# The identities this repository accepts. Add a new one DELIBERATELY, in its
# own commit -- an edit here is a statement about who may write history that
# origin publishes.
WZ_ALLOWED_IDENT_EMAILS=(
    "newmassrael@gmail.com"
)

# "Name <email> 1756100000 +0900" -> "email".
#
# Cut on the angle brackets rather than on whitespace: a display name may
# contain spaces, and a field-counting parse silently returns the wrong token
# when it does -- silently, which is the failure mode this whole file is
# about.
wz_ident_email() {
    local ident="$1"
    ident="${ident#*<}"
    printf '%s' "${ident%%>*}"
}

wz_ident_allowed() {
    local email="$1" allowed
    for allowed in "${WZ_ALLOWED_IDENT_EMAILS[@]}"; do
        if [ "$email" = "$allowed" ]; then
            return 0
        fi
    done
    return 1
}

# The shared refusal. Printed by both callers so the two hooks cannot drift
# into explaining the same rule differently.
wz_ident_refuse() {
    local hook="$1" what="$2" email="$3"
    echo "${hook}: ${what} <${email}>," >&2
    echo "  which is not an identity this repository accepts." >&2
    echo "" >&2
    echo "  Measured 2026-08-25: eight commits reached this PUBLIC repo under" >&2
    echo "  a different address. Rewriting history did NOT un-publish them --" >&2
    echo "  they stayed reachable by SHA and the repository had to be deleted" >&2
    echo "  and recreated, costing 1146 runs of CI history." >&2
    echo "" >&2
    echo "  fix, in this clone:" >&2
    echo "    git config user.email ${WZ_ALLOWED_IDENT_EMAILS[0]}" >&2
    echo "    git config user.name  <your name>" >&2
    echo "  and check the environment too -- these override the config:" >&2
    echo "    env | grep -E '^GIT_(AUTHOR|COMMITTER)_EMAIL='" >&2
    echo "" >&2
    echo "  If a NEW identity is genuinely meant to write here, add it to" >&2
    echo "  WZ_ALLOWED_IDENT_EMAILS in scripts/lib/ident-gate.sh --" >&2
    echo "  deliberately, in its own commit." >&2
}

# pre-commit's arm: the identity the commit ABOUT TO BE MADE would carry.
wz_ident_gate_pending() {
    local hook="$1" role verb ident email
    set -- AUTHOR authored COMMITTER committed
    while [ $# -gt 0 ]; do
        role="$1"
        verb="$2"
        shift 2
        if ! ident="$(git var "GIT_${role}_IDENT")"; then
            echo "${hook}: \`git var GIT_${role}_IDENT\` failed; cannot" >&2
            echo "  determine the identity this commit would carry. A gate" >&2
            echo "  that cannot read its input must not report green." >&2
            return 1
        fi
        email="$(wz_ident_email "$ident")"
        if [ -z "$email" ]; then
            echo "${hook}: could not read an email out of GIT_${role}_IDENT." >&2
            echo "  git said: ${ident}" >&2
            return 1
        fi
        if ! wz_ident_allowed "$email"; then
            wz_ident_refuse "$hook" "this commit would be ${verb} as" "$email"
            return 1
        fi
    done
    return 0
}

# pre-push's arm: every commit in the range being published.
#
# `range` is `<base>..<tip>` when origin already has the ref, and a bare
# `<tip>` when it does not -- which is the NEW-REPOSITORY case, and grading
# the whole history there is the point rather than an accident. That is the
# state this repository was in minutes after the recreation, and it is when a
# stray identity would otherwise be republished wholesale.
#
# Reports EVERY offending commit rather than the first, because the fix is a
# rebase whose scope the author needs to know before starting it.
wz_ident_gate_range() {
    local hook="$1" range="$2" sha email bad=0 shown=0
    local log
    if ! log="$(git log --format='%H %ae%n%H %ce' "$range" --)"; then
        echo "${hook}: \`git log ${range}\` failed; cannot determine which" >&2
        echo "  identities this push would publish. A gate that cannot read" >&2
        echo "  its input must not report green." >&2
        return 1
    fi
    while IFS=' ' read -r sha email; do
        [ -n "$sha" ] || continue
        if ! wz_ident_allowed "$email"; then
            if [ "$bad" -eq 0 ]; then
                wz_ident_refuse "$hook" "this push would publish commits by" "$email"
                echo "" >&2
                echo "  offending commits in ${range}:" >&2
            fi
            bad=$((bad + 1))
            if [ "$shown" -lt 20 ]; then
                echo "    ${sha} <${email}>" >&2
                shown=$((shown + 1))
            fi
        fi
    done <<EOF
$log
EOF
    if [ "$bad" -gt 0 ]; then
        if [ "$bad" -gt "$shown" ]; then
            echo "    ... and $((bad - shown)) more" >&2
        fi
        return 1
    fi
    return 0
}

# ─── selftest ───────────────────────────────────────────────────────
#
# `wz_ident_gate_range` is reachable only from `pre-push`, and a gate nothing
# can execute cannot be told apart from a gate that always passes -- the
# objection `apt-install.sh` states for its own bounded-wait core and answers
# the same way. This drives every arm against a throwaway repository, so the
# rules stay gradable without a push.
#
# Run: bash scripts/lib/ident-gate.sh --selftest
wz_ident_gate_selftest() {
    local tmp pass=0 fail=0 good bad
    good="${WZ_ALLOWED_IDENT_EMAILS[0]}"
    bad="nobody@example.invalid"
    tmp="$(mktemp -d)" || return 1

    _t() { # name, expected-rc, actual-rc
        if [ "$2" -eq "$3" ]; then
            echo "  ok    $1  (rc=$3)"
            pass=$((pass + 1))
        else
            echo "  FAIL  $1  want rc=$2, got rc=$3"
            fail=$((fail + 1))
        fi
    }

    (
        cd "$tmp" || exit 1
        git init -q .
        git config user.name  probe
        git config user.email "$good"
        echo a > a.txt && git add a.txt
        git commit -q -m 'good one'
        echo b > b.txt && git add b.txt
        GIT_AUTHOR_EMAIL="$bad" GIT_AUTHOR_NAME=probe git commit -q -m 'bad author'
        echo c > c.txt && git add c.txt
        GIT_COMMITTER_EMAIL="$bad" GIT_COMMITTER_NAME=probe git commit -q -m 'bad committer'
        echo d > d.txt && git add d.txt
        git commit -q -m 'good again'
    ) || { rm -rf "$tmp"; return 1; }

    local base tip only_good
    base="$(git -C "$tmp" rev-list --max-parents=0 HEAD)"
    tip="$(git -C "$tmp" rev-parse HEAD)"
    only_good="$base"

    # A range whose commits are all allowed.
    ( cd "$tmp" && wz_ident_gate_range 'selftest' "$only_good" ) >/dev/null 2>&1
    _t "a clean range passes" 0 $?

    # The whole history, which carries a bad AUTHOR and a bad COMMITTER.
    ( cd "$tmp" && wz_ident_gate_range 'selftest' "$tip" ) >/dev/null 2>&1
    _t "a bad author or committer in the range fails" 1 $?

    # The bad-author commit specifically, as a base..tip range.
    ( cd "$tmp" && wz_ident_gate_range 'selftest' "${base}..${tip}" ) >/dev/null 2>&1
    _t "base..tip form fails on the same history" 1 $?

    # It must name EVERY offender, not just the first -- the rebase scope.
    local named
    named="$( cd "$tmp" && wz_ident_gate_range 'selftest' "$tip" 2>&1 >/dev/null \
              | command grep -c "$bad" )"
    if [ "$named" -ge 2 ]; then
        echo "  ok    every offending commit is named  (${named} lines)"
        pass=$((pass + 1))
    else
        echo "  FAIL  only ${named} offender line(s); the rebase scope needs all"
        fail=$((fail + 1))
    fi

    # A range git cannot read must FAIL, never pass green.
    ( cd "$tmp" && wz_ident_gate_range 'selftest' 'no-such-ref-at-all' ) >/dev/null 2>&1
    _t "an unreadable range fails rather than passing" 1 $?

    # The pending-identity arm, both roles.
    ( cd "$tmp" && wz_ident_gate_pending 'selftest' ) >/dev/null 2>&1
    _t "pending: an allowed identity passes" 0 $?
    ( cd "$tmp" && GIT_AUTHOR_EMAIL="$bad" wz_ident_gate_pending 'selftest' ) >/dev/null 2>&1
    _t "pending: a bad author fails" 1 $?
    ( cd "$tmp" && GIT_COMMITTER_EMAIL="$bad" wz_ident_gate_pending 'selftest' ) >/dev/null 2>&1
    _t "pending: a bad committer fails" 1 $?

    # A display name carrying spaces and angle brackets must still parse.
    local parsed
    parsed="$(wz_ident_email "Some One <who@example.com> 1756100000 +0900")"
    if [ "$parsed" = "who@example.com" ]; then
        echo "  ok    a spaced display name still yields the email"
        pass=$((pass + 1))
    else
        echo "  FAIL  parsed '${parsed}', want 'who@example.com'"
        fail=$((fail + 1))
    fi

    rm -rf "$tmp"
    echo "ident-gate selftest: $((pass))/$((pass + fail)) arm(s) pass"
    [ "$fail" -eq 0 ]
}

if [ "${1:-}" = "--selftest" ]; then
    wz_ident_gate_selftest
    exit $?
fi

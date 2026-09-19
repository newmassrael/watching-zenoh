#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R2064 (no register item) — HOME-DIRECTORY PATH gate for the push path.
#
# The citation says NO REGISTER ITEM, and the reason is worth one sentence
# because "none" here does not mean "nothing was tracked". The class this gate
# closes was raised by the owner directly, and what it could NOT close -- the
# 137 home-path lines already inside the append-only ledger -- is carried as
# item 492 in the operator's own register, which lives OUTSIDE the store. The
# store's `debt-` namespace, which is what this citation is resolved against,
# has no entry for it; citing one would be inventing an id, and that collision
# is a cost this project has already paid once. R2069 added this line after the
# hosted lane caught its absence: a gate written in a hurry lands in the
# provenance lint or nowhere, and this one landed there.
#
# The shebang is for SHELLCHECK, not for execution: this file is sourced, never
# run, exactly as `nda-scan.sh` and `schema-pin-gate.sh` beside it are.
#
# WHY THIS IS A HOOK AND NOT A RULE
#
# The same argument `nda-scan.sh` makes, one notch smaller in harm and identical
# in shape. This repository is PUBLIC. A push publishes, and deleting later does
# not un-publish. CLAUDE.md has forbidden machine-local absolute paths in tracked
# files since R311y302 -- which is itself the proof, because that round found an
# absolute checkout path that had rotted to a directory no longer existing and
# had been cited for months. Until now the only thing between a developer's home
# layout and origin was an agent remembering that rule, and an unattended loop
# drops attention-based rules first.
#
# A home path is two defects at once: it LEAKS the layout, and it is WRONG on
# every other clone. `.mcp.json` carried `--workspace <a home path>` as a
# FUNCTIONAL argument that no second clone could have used -- and the server's
# own `--help` says the flag may simply be omitted.
#
# WHY THE TERM IS `$HOME` AND NOT A PATTERN
#
# The first draft matched `/home/<name>` and found THREE hits that are zenoh KEY
# EXPRESSIONS -- `/home/temp` in two dissect fixtures. A keyexpr is not a
# directory, and no pattern over `/home/...` can tell them apart without
# guessing. What is actually at stake is narrower and exactly knowable: the home
# directory of the person whose push would publish it. `$HOME` is that, it needs
# no configuration, it is right on every clone, and writing it into a tracked
# file would itself be the leak -- so it is read at run time and never stored.
#
# WHY THE STORE IS A CEILING AND NOT A BAN
#
# `docs/.atomic/workspace.atomic.json` is an APPEND-ONLY audit ledger: an entry
# is frozen once written and corrections arrive only as later entries. Paths
# already inside it cannot be removed without rewriting history -- the operation
# the 2026-08-14 NDA scrub was, and the owner's call rather than a gate's. So the
# store gets a ceiling that may not be EXCEEDED, and everything else gets zero.
#
# ⚠ THE CEILING IS NOT AN EQUALITY, and the reason is that the term is `$HOME`:
# on a second developer's clone the count is legitimately 0. So a fall is not a
# finding here. What is a finding is a NEW entry naming the home of whoever is
# pushing -- which is the only moment it is still preventable.
#
# ⚠ WHY NOT EXCLUDE THE STORE: because that is where the next leak would go.
# Every round of this workspace appends prose to that file, so an exclusion would
# aim the gate away from its own most likely target.
#
# ─── R2729 — WHY A PUSH GATE ALONE COULD NOT CLOSE THIS ─────────────────────
#
# MEASURED, not argued: R2723 through R2728 committed and did not land, and for
# four of those rounds the stated cause was environmental. It was this gate.
# `Round 2725`'s ledger entry spells this home directory literally -- inside the
# grep pattern of the bullet that reports having CHECKED for home paths -- so
# the store went 137 -> 139 lines and every push since has been refused. Five
# rounds of work sat on one machine behind a gate firing exactly as designed.
#
# THE GATE WAS RIGHT AND STILL ARRIVED TOO LATE, which is the structural point.
# Its own refusal says "this push is the last moment it can be stopped", and
# that is true only of the push. By then `append-changelog-entry` has FROZEN the
# entry, the audit half of the ledger has no setter (`redact-term` reaches the
# publishable half alone, and it has no per-entry scope), and CLAUDE.md forbids
# editing the sidecar. So the one moment the gate names is the first moment at
# which the finding is no longer repairable. A gate that can only refuse, never
# be satisfied, wedges the branch.
#
# This is the same window `scripts/append-round.sh` was built to close for
# impact refs, and its header states the economics that apply here unchanged:
# the check that runs one call earlier costs a retype, and the one that runs one
# call later costs a round. So the term is now checked at BOTH earlier moments,
# from the one definition below:
#
#   * `wz_home_path_files`   -- the round's own prose files, BEFORE the append.
#     Nothing enters the store at all, so nothing freezes.
#   * `wz_home_path_pending` -- the INDEX, before the commit. Route-independent:
#     it grades staged content whatever produced it, so a direct
#     `mnemosyne-cli append-changelog-entry` (which CLAUDE.md documents as still
#     working) is covered by the same check as the wrapper. Naming only the
#     wrapper would be a population written as a list of known subjects, which
#     is the defect the R2578 acks row is about.
#
# ⚠ THE PENDING CHECK IS A DELTA, NOT THE CEILING ABOVE, and it has to be: 137
# home-path lines are already committed, so an absolute scan of the index would
# refuse every commit this repository will ever make. What is preventable is an
# INCREASE, and an increase is what it measures.
#
# ⚠ AND THE CEILING STAYS. These two do not replace it -- cherry-pick, rebase,
# merge and `--no-verify` all skip the commit hook entirely, which is the same
# argument check 3 makes for carrying the schema pin in both hooks.

# Shared precondition for every entry point below: is there a term to scan for,
# and is it a developer's home rather than a shared CI one?
#
# Echoes nothing on the ordinary path so a caller can decide how to report.
# Returns 0 = scan, 1 = refuse (no term), 2 = skip (CI home).
wz_home_path_term_state() {
    # A gate that cannot read its input must not report green -- the rule this
    # repo already applies to the python3-backed schema pin.
    if [[ -z "${HOME:-}" || "$HOME" == "/" ]]; then
        return 1
    fi
    # The CI runner's home is a public constant of GitHub Actions, identical for
    # every user of this repository, and the footprint comments depend on its
    # LENGTH and say so. There is no developer layout to leak there.
    if [[ "$HOME" == "/home/runner" || "$HOME" == "/root" ]]; then
        return 2
    fi
    return 0
}

# R2729 — refuse a ledger append whose own prose names this home directory.
#
# `$1` is the label to report under; every remaining argument is one file the
# round is about to hand `append-changelog-entry`. THE POPULATION IS THE
# CALLER'S ARGV, which is how `append-round.sh` knows it: the same `--*-file`
# values it passes through to the CLI, never a list written here. A population
# of zero is a FAIL rather than a green, because a gate handed nothing has
# measured nothing -- and the count it scanned is printed either way, since the
# signal is the number and not the exit status.
wz_home_path_files() {
    local label="${1:-append-round}"
    shift || true
    local state=0
    wz_home_path_term_state || state=$?
    if (( state == 1 )); then
        echo "  $label FAIL: \$HOME is unset or /, so there is no term to scan for" >&2
        return 1
    fi
    if (( state == 2 )); then
        echo "  $label home-paths: skipped -- \$HOME is $HOME, a shared CI home"
        return 0
    fi

    if (( $# == 0 )); then
        echo "  $label FAIL: no prose file was given, so the home-path check" >&2
        echo "    scanned NOTHING and must not report green." >&2
        return 1
    fi

    local scanned=0 found=0 f hits
    for f in "$@"; do
        [[ -n "$f" ]] || continue
        if [[ ! -f "$f" ]]; then
            echo "  $label FAIL: prose file '$f' does not exist, so it could not" >&2
            echo "    be scanned for a home path." >&2
            return 1
        fi
        scanned=$((scanned + 1))
        hits="$(grep -acF "$HOME" "$f" 2>/dev/null || true)"
        [[ -n "$hits" ]] || hits=0
        if (( hits > 0 )); then
            found=$((found + hits))
            echo "  $label FAIL: '$f' names this machine's home directory on $hits line(s)" >&2
            grep -anF "$HOME" "$f" | cut -d: -f1 | sed 's/^/    line /' >&2
        fi
    done

    if (( found > 0 )); then
        echo "  Nothing was appended. THIS IS THE CHEAP MOMENT: the file is still" >&2
        echo "  a file. After append-changelog-entry the entry is frozen, the audit" >&2
        echo "  half has no setter, and the only thing left is a push that can" >&2
        echo "  never pass (pre-push gate 0b). R2725 is that round." >&2
        echo "  Name the thing, not the path (CLAUDE.md External references)." >&2
        return 1
    fi
    echo "  $label home-paths: $scanned prose file(s) scanned, 0 home-path line(s)"
    return 0
}

# R2729 — refuse a COMMIT that ADDS a line naming this home directory.
#
# `$1` is the label to report under. The population is derived from the index
# (`git diff --cached`), so it covers whatever produced the content; the count
# scanned is printed so a population of zero is visible rather than silent.
wz_home_path_pending() {
    local label="${1:-pre-commit}"
    local state=0
    wz_home_path_term_state || state=$?
    if (( state == 1 )); then
        echo "  $label FAIL: \$HOME is unset or /, so there is no term to scan for" >&2
        return 1
    fi
    if (( state == 2 )); then
        echo "  $label home-paths: skipped -- \$HOME is $HOME, a shared CI home"
        return 0
    fi

    local staged
    staged="$(git diff --cached --name-only --diff-filter=ACMR)" || {
        echo "  $label FAIL: could not list the staged files" >&2
        return 1
    }

    local have_head=0
    git rev-parse --verify -q HEAD >/dev/null 2>&1 && have_head=1

    local scanned=0 added_total=0 report="" f now before
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        scanned=$((scanned + 1))
        now="$(git show ":$f" 2>/dev/null | grep -acF "$HOME" || true)"
        [[ -n "$now" ]] || now=0
        before=0
        if (( have_head )); then
            before="$(git show "HEAD:$f" 2>/dev/null | grep -acF "$HOME" || true)"
            [[ -n "$before" ]] || before=0
        fi
        if (( now > before )); then
            added_total=$((added_total + now - before))
            report+="    $f: $before -> $now line(s)"$'\n'
        fi
    done <<<"$staged"

    echo "  $label home-paths: $scanned staged file(s) scanned, $added_total added line(s)"
    if (( added_total > 0 )); then
        echo "  $label FAIL: this commit ADDS $added_total line(s) naming this home" >&2
        printf '%s' "$report" >&2
        echo "    Origin is public and a push does not un-publish. A home path" >&2
        echo "    leaks the layout AND is wrong on every other clone." >&2
        echo "    Name the thing, not the path (CLAUDE.md External references);" >&2
        echo "    where a LENGTH is what a measurement rests on, give the length." >&2
        echo "    If the store is what grew, revert it and re-append with the" >&2
        echo "    prose fixed -- once appended, the entry is frozen and pre-push" >&2
        echo "    gate 0b will refuse the push permanently (R2725)." >&2
        return 1
    fi
    return 0
}

# Refuse any home-directory path in a tracked file.
#
# `$1` is the repository root. Returns non-zero on a finding, having said which
# file and how many.
wz_home_path_scan() {
    local root="${1:-.}"
    local store="docs/.atomic/workspace.atomic.json"
    # LINES, not occurrences: `grep -c` counts lines and so must this. The two
    # differ here -- 141 occurrences sit on 137 lines -- and a ceiling in the
    # other unit would carry four lines of silent headroom.
    local ceiling=137

    # R2729 — the two preconditions moved to `wz_home_path_term_state` so the
    # three entry points share ONE definition of "is there a term, and is it a
    # developer's". Two copies would be two facts that can disagree, which is
    # the argument the ident gate already makes one file over.
    local state=0
    wz_home_path_term_state || state=$?
    if (( state == 1 )); then
        echo "  home-paths FAIL: \$HOME is unset or /, so there is no term to scan for" >&2
        return 1
    fi
    if (( state == 2 )); then
        echo "  home-paths: skipped -- \$HOME is $HOME, a shared CI home and not a developer's"
        return 0
    fi

    local tracked
    tracked="$(cd "$root" && git ls-files)" || {
        echo "  home-paths FAIL: could not list tracked files" >&2
        return 1
    }
    if [[ -z "$tracked" ]]; then
        echo "  home-paths FAIL: the tracked-file list is empty" >&2
        return 1
    fi

    local outside=0 outside_lines="" store_count=0
    local f hits
    while IFS= read -r f; do
        [[ -f "$root/$f" ]] || continue
        hits="$(grep -cF "$HOME" "$root/$f" 2>/dev/null || true)"
        [[ -n "$hits" && "$hits" != "0" ]] || continue
        if [[ "$f" == "$store" ]]; then
            store_count="$hits"
        else
            outside=$((outside + hits))
            outside_lines+="    $f:$(grep -nF "$HOME" "$root/$f" | cut -d: -f1 | head -3 | tr '\n' ' ')"$'\n'
        fi
    done <<<"$tracked"

    if (( outside > 0 )); then
        echo "  home-paths FAIL: $outside tracked line(s) name this machine's home directory"
        printf '%s' "$outside_lines"
        echo "    A home path leaks the layout AND is wrong on every other clone."
        echo "    Name the thing, not the path (CLAUDE.md's External-references"
        echo "    rule); where a LENGTH is what a measurement rests on, give the"
        echo "    length."
        return 1
    fi

    if (( store_count > ceiling )); then
        echo "  home-paths FAIL: $store names this home on $store_count line(s), ceiling $ceiling"
        echo "    A ledger entry named a home directory. That file is APPEND-ONLY"
        echo "    -- this push is the last moment it can be stopped."
        return 1
    fi

    echo "  home-paths: 0 outside the ledger; $store_count line(s) inside it (ceiling $ceiling, append-only)"
    return 0
}

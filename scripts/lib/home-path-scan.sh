#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

    # A gate that cannot read its input must not report green -- the rule this
    # repo already applies to the python3-backed schema pin.
    if [[ -z "${HOME:-}" || "$HOME" == "/" ]]; then
        echo "  home-paths FAIL: \$HOME is unset or /, so there is no term to scan for" >&2
        return 1
    fi
    # The CI runner's home is a public constant of GitHub Actions, identical for
    # every user of this repository, and the footprint comments depend on its
    # LENGTH and say so. There is no developer layout to leak there.
    if [[ "$HOME" == "/home/runner" || "$HOME" == "/root" ]]; then
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

#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Files the ledger round a commit carries as a descriptor, with the number the
# store gives it on THIS tree. The bx action `file-round` runs it on every queue
# candidate (`bx.toml`).
#
# ## Why this exists
#
# `scripts/land.sh` files a round inside its push lock: the prose comes from four
# files outside the repository and the number from the store after the rebase. A
# queue integrator (`bx --land`, bx RFC 0024) cherry-picks a commit onto the remote
# tip and runs the repository's declared actions on the result; it has no lock, no
# files outside the commit and no `--round`. So the round has to be IN the commit,
# as data without its number, and the number has to be taken after the cherry-pick,
# on the candidate, where the store already holds every round that landed before it.
# That is a descriptor (`scripts/lib/round_descriptor.py` states its form) and this
# script: read the store's last round, file the descriptor as the next one, delete
# the descriptor. A candidate with no descriptor changes nothing.
#
# The number is a function of the candidate's tree, which is what lets the
# integrator run this again on a rebased candidate and get the number that is right
# for the new base. Nothing outside the tree (an environment variable, a lock, a
# file of the author's) enters the filing.
#
# ## Usage
#
#   bash scripts/file-round.sh                    # file every pending descriptor
#   bash scripts/file-round.sh --check [<file>]   # dry run, files nothing
#
# Descriptors are `docs/rounds/pending/*.toml`, filed in name order, each with the
# next number. `--check` runs everything an append would refuse (the impact ids, the
# home-path scan, the upstream-citation gate) over the descriptor's prose, so an
# author learns it at commit time and not from a returned queue item. With no file it
# checks every pending descriptor, and it is a no-op when there is none.
#
# Exit codes: 0 done (or nothing pending); 1 a descriptor or the append refused;
# 2 usage.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

pending_dir="docs/rounds/pending"

check_only=0
files=()
while [[ $# -gt 0 ]]; do
    case "$1" in
    --check)
        check_only=1
        shift
        ;;
    -*)
        echo "file-round: unknown argument \`$1\` (see the header of scripts/file-round.sh)" >&2
        exit 2
        ;;
    *)
        files+=("$1")
        shift
        ;;
    esac
done
if [[ ${#files[@]} -gt 0 && $check_only -eq 0 ]]; then
    echo "file-round: a file is named only with --check; filing takes every pending descriptor" >&2
    exit 2
fi

if [[ ${#files[@]} -eq 0 ]]; then
    shopt -s nullglob
    files=("$pending_dir"/*.toml)
    shopt -u nullglob
fi
if [[ ${#files[@]} -eq 0 ]]; then
    echo "file-round: no pending descriptor; nothing to file"
    exit 0
fi

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    echo "file-round: FAIL mnemosyne-cli is not on PATH" >&2
    echo "  A gate that cannot read its input must not report green." >&2
    exit 1
fi
# shellcheck source=scripts/lib/ledger-round.sh
source "$repo_root/scripts/lib/ledger-round.sh"

# The prose is written outside the tree: `append-round.sh` takes files, and a file left
# in the tree would be a change of the candidate that nothing declared.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mapfile -t files < <(printf '%s\n' "${files[@]}" | LC_ALL=C sort)

for descriptor in "${files[@]}"; do
    if [[ ! -f "$descriptor" ]]; then
        echo "file-round: FAIL $descriptor is not a file" >&2
        exit 1
    fi
    out="$work/$(basename "$descriptor" .toml)"
    impact="$(python3 -I "$repo_root/scripts/lib/round_descriptor.py" emit "$descriptor" "$out")" || exit 1
    prose=(--decision-file "$out/decision.txt" --changes-file "$out/changes.txt"
        --verification-file "$out/verification.txt" --carry-file "$out/carry.txt")
    if [[ $check_only -eq 1 ]]; then
        bash scripts/append-round.sh --check-only "${prose[@]}" --impact "$impact"
        continue
    fi
    last="$(wz_last_round)"
    [[ -n "$last" ]] || { echo "file-round: the store lists no ledger round" >&2; exit 1; }
    round=$((last + 1))
    echo "file-round: filing $descriptor as ledger round $round"
    bash scripts/append-round.sh --entry-id "Round $round" "${prose[@]}" --impact "$impact"
    rm -- "$descriptor"
done

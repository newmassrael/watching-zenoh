#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The one way a commit reaches `main` from this machine: under a lock that every
# session's push takes, rebased, numbered and pushed in one breath.
#
# ## Why this exists, measured
#
# Several sessions push to `main` from worktrees of one clone, and each push
# spends about a minute in the pre-push hook. A session that fetched, rebased
# and filed ledger round N then lost the race to a session that filed round N
# during its hook: origin refused the push after the hook had passed, and the
# loser dropped its ledger commit, rebased, renumbered and ran the hook again.
# One batch of round 3744 was refused six times that way on 2026-10-26. The
# window was the hook itself, so no amount of care at the keyboard closed it.
#
# Owner decision, 2026-10-27: serialise the pushes instead of shortening the
# window. This script holds an exclusive `flock` on a file in the clone's
# common git directory (shared by every worktree) from the fetch to the end of
# the push, so nobody else's push can land between this one's rebase and its
# arrival. The pre-push hook refuses a push to `main` that does not hold the
# lock (its lock gate), so the serialisation is enforced and not a convention.
#
# ## What it does
#
#   1. refuses a dirty tree (a rebase would carry it, and the push would not);
#   2. takes the lock, waiting up to WZ_LAND_WAIT seconds (default 3600) and
#      naming the holder while it waits;
#   3. fetches `origin main` and rebases HEAD onto it;
#   4. when ledger arguments follow `--`, files the ledger round with the next
#      number the store holds NOW (inside the lock, so nobody can take it) and
#      commits the files the append changed;
#   5. pushes HEAD to `main` THROUGH the hooks;
#   6. when origin still refuses the push as stale (a push from outside this
#      clone), drops its own ledger commit and goes round once more.
#
# It never passes `--no-verify`, `--force` or anything but `HEAD:main`.
#
# ## Usage
#
#   bash scripts/land.sh                          # code commits only
#   bash scripts/land.sh --ack-red <run-id>       # WZ_ACK_RED for this push only
#   bash scripts/land.sh -- --decision-file d --changes-file c \
#       --verification-file v --carry-file k --impact <id>[,<id>...]
#   bash scripts/land.sh --status                 # who holds the lock
#
# The arguments after `--` are `scripts/append-round.sh`'s own, without
# `--entry-id`: the number is this script's to take. When a commit of the batch
# already names the round (an acknowledgement row does), `--round N` makes the
# number a precondition: the script files nothing and exits 5 when the next
# number is not N, so the text is renumbered before anything is published.
#
# Exit codes: 0 landed; 1 the hook or a step refused; 2 usage or a dirty tree;
# 3 the lock was not obtained in time; 4 the rebase conflicted (aborted);
# 5 the next round is not the one `--round` named.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

common_dir="$(git rev-parse --path-format=absolute --git-common-dir)"
lock="$common_dir/wz-push.lock"
owner="$lock.owner"
log="$(git rev-parse --path-format=absolute --git-dir)/wz-land.log"

ack_red=""
want_round=""
ledger_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
    --status)
        if flock -n "$lock" true 2>/dev/null; then
            echo "land: the push lock is free"
        else
            echo "land: the push lock is held: $(cat "$owner" 2>/dev/null || echo unknown)"
        fi
        exit 0
        ;;
    --ack-red)
        [[ $# -ge 2 ]] || { echo "land: --ack-red needs a run id" >&2; exit 2; }
        ack_red="$2"
        shift 2
        ;;
    --round)
        [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]] || { echo "land: --round needs a number" >&2; exit 2; }
        want_round="$2"
        shift 2
        ;;
    --)
        shift
        ledger_args=("$@")
        break
        ;;
    *)
        echo "land: unknown argument \`$1\` (see the header of scripts/land.sh)" >&2
        exit 2
        ;;
    esac
done
if [[ -n "$want_round" && ${#ledger_args[@]} -eq 0 ]]; then
    echo "land: --round names the ledger round, so ledger arguments must follow --" >&2
    exit 2
fi
for a in "${ledger_args[@]+"${ledger_args[@]}"}"; do
    if [[ "$a" == "--entry-id" ]]; then
        echo "land: drop --entry-id; the round number is taken inside the lock" >&2
        exit 2
    fi
done

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "land: the tree has uncommitted changes; commit or set them aside first" >&2
    exit 2
fi

exec 9>>"$lock"
if ! flock -n 9; then
    echo "land: waiting for the push lock, held by: $(cat "$owner" 2>/dev/null || echo unknown)"
    if ! flock -w "${WZ_LAND_WAIT:-3600}" 9; then
        echo "land: the push lock was not released within ${WZ_LAND_WAIT:-3600}s" >&2
        exit 3
    fi
fi
token="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
printf '%s pid=%s tree=%s since=%s\n' "$token" "$$" "$repo_root" "$(date -u +%FT%TZ)" >"$owner"
trap ': >"$owner"' EXIT

# The highest `Round N` the store holds. The store is read after the rebase, so
# this is origin's ledger plus nothing: every unpushed round is this push's own.
last_round() {
    mnemosyne-cli query --list-changelog \
        | sed -n 's/^Round \([0-9][0-9]*\)$/\1/p' \
        | sort -n | tail -n 1
}

attempt=1
while :; do
    git fetch -q origin main
    if ! git rebase -q origin/main; then
        git rebase --abort
        echo "land: the rebase onto origin/main conflicted and was aborted" >&2
        exit 4
    fi

    filed=0
    if [[ ${#ledger_args[@]} -gt 0 ]]; then
        last="$(last_round)"
        [[ -n "$last" ]] || { echo "land: the store lists no ledger round" >&2; exit 1; }
        round=$((last + 1))
        if [[ -n "$want_round" && "$round" != "$want_round" ]]; then
            echo "land: the next round is $round, not $want_round; renumber the batch" >&2
            exit 5
        fi
        echo "land: filing ledger round $round"
        bash scripts/append-round.sh --entry-id "Round $round" "${ledger_args[@]}"
        changed=()
        while IFS= read -r path; do
            changed+=("$path")
        done < <(git diff --name-only)
        [[ ${#changed[@]} -gt 0 ]] || { echo "land: the append changed no file" >&2; exit 1; }
        printf 'docs: File ledger round %s\n' "$round" | git commit -q -F - -- "${changed[@]}"
        filed=1
    fi

    rc=0
    WZ_LAND_TOKEN="$token" WZ_ACK_RED="${ack_red:-${WZ_ACK_RED:-}}" \
        git push origin HEAD:main 2>&1 | tee "$log" || rc=$?
    if [[ $rc -eq 0 ]]; then
        break
    fi
    # A stale-tip refusal comes from origin after the hook passed. Inside this
    # lock only a push from outside the clone can cause one, so one more round
    # is enough; a hook refusal is a verdict and is never retried.
    if [[ $attempt -lt 2 ]] && grep -qE '^ ! \[(rejected|remote rejected)\]' "$log"; then
        echo "land: origin moved during the push; going round once more"
        if [[ $filed -eq 1 ]]; then
            git reset -q --keep HEAD~1
        fi
        attempt=$((attempt + 1))
        continue
    fi
    echo "land: the push was refused (exit $rc); the output above says why" >&2
    exit 1
done

remote_tip="$(git ls-remote origin refs/heads/main | cut -f1)"
if [[ "$remote_tip" != "$(git rev-parse HEAD)" ]]; then
    echo "land: the push reported success but origin's main is $remote_tip" >&2
    exit 1
fi
echo "land: landed $(git rev-parse --short=9 HEAD) on origin/main"

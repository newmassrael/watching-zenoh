#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The one way a session's commits reach `main`: submitted to the branch's landing
# queue, which has one writer.
#
# ## Why a queue
#
# Several sessions land on `main` from worktrees of several clones, and the
# repository's judgement of a push (the pre-push hook) takes about a minute. Two
# sessions that each judged their own rebase raced through that minute: origin
# refused the loser after its hook had passed, and one batch went round six
# times on 2026-10-26. A lock held by this script closed the race for one clone
# only, and left a round's number to whoever held it.
#
# The queue (`bx --land`, bx RFC 0024; `[land]` in `bx.toml`) closes it for every
# clone: the submitted commit goes to the remote as an item, and the branch's one
# integrator puts it on the tip, files the ledger round its descriptor carries
# (`scripts/file-round.sh`, with the number the store gives it there), judges the
# result with this repository's own pre-push hook, and pushes exactly what it
# judged. Gate 0p of that hook refuses a push to `main` from any clone that is not
# the integrator's, so the queue is the only writer and not a convention.
#
# ## What it does
#
#   1. refuses a dirty tree (the item is a commit, and the change would not be in it);
#   2. when append-round arguments follow `--`, writes them as a round descriptor
#      (`docs/rounds/pending/`, `round_descriptor.py write`), checks it the way the
#      append would (`file-round.sh --check`) and commits it; an item the queue
#      returns keeps that commit, and `bash scripts/land.sh` alone lands it again;
#   3. with `WZ_PREPUSH_EXTENDED=1`, runs the hook's extended local sweep over
#      `origin/main..HEAD` first, as a branch push is judged; it only adds a local
#      refusal, the item's verdict is the integrator's;
#   4. submits HEAD with `bx --land` and waits for its end;
#   5. once it landed, moves the branch onto `origin/main`, which holds the
#      landed commits and the round the integrator filed.
#
# It never pushes `main`, and it passes nothing that turns a hook off.
#
# ## Usage
#
#   bash scripts/land.sh                          # commits only, or rounds already
#                                                 # committed as descriptors
#   bash scripts/land.sh -- --decision-file d --changes-file c \
#       --verification-file v --carry-file k --impact <id>[,<id>...]
#   bash scripts/land.sh --status                 # the queue (`bx --land-queue`)
#
# The arguments after `--` are `scripts/append-round.sh`'s own, without
# `--entry-id`: the number is the store's on the tree the item lands on.
#
# Acknowledging a red hosted run is a row in docs/hosted-red-acks.md in a commit of the
# item (the previous-run gate reads it from the range being pushed), not an option of
# this script, because the integrator that judges the item never sees this process's
# environment.
#
# `bx` is the one on PATH, else `~/.local/bin/bx`.
#
# Exit codes: 0 landed (or nothing to land); 1 the queue returned the item or a step
# refused; 2 usage, a dirty tree or no bx; 3 the item was not submitted, was cancelled,
# or its end is not known; 4 it landed, and moving the branch onto origin/main
# conflicted (aborted).

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

bx_bin="$(command -v bx || true)"
if [[ -z "$bx_bin" && -x "$HOME/.local/bin/bx" ]]; then
    bx_bin="$HOME/.local/bin/bx"
fi

status=0
ledger_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
    --status)
        status=1
        shift
        ;;
    --ack-red | --round)
        echo "land: $1 is gone (see the header of scripts/land.sh): acknowledge a red run with a row in docs/hosted-red-acks.md in a commit of this item" >&2
        exit 2
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

if [[ -z "$bx_bin" ]]; then
    echo "land: no bx on PATH or at ~/.local/bin/bx; the landing queue is reached through it" >&2
    exit 2
fi
if [[ $status -eq 1 ]]; then
    exec "$bx_bin" --land-queue
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "land: the tree has uncommitted changes; commit or set them aside first" >&2
    exit 2
fi

git fetch -q origin main

if [[ ${#ledger_args[@]} -gt 0 ]]; then
    shopt -s nullglob
    pending=(docs/rounds/pending/*.toml)
    shopt -u nullglob
    if [[ ${#pending[@]} -gt 0 ]]; then
        echo "land: the tree holds a round descriptor (docs/rounds/pending), so ledger arguments after -- would file a second round; land it with \`bash scripts/land.sh\` alone" >&2
        exit 2
    fi
    # Named by when and on what it was written, so two sessions' descriptors never share
    # a name and the integrator files them in the order they were made.
    descriptor="docs/rounds/pending/$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short=12 HEAD).toml"
    if ! python3 -I scripts/lib/round_descriptor.py write "$descriptor" "${ledger_args[@]}"; then
        echo "land: the ledger arguments are not a round (the line above says why)" >&2
        exit 1
    fi
    if ! bash scripts/file-round.sh --check "$descriptor"; then
        rm -f -- "$descriptor"
        echo "land: the round would be refused when it is filed (the output above says why)" >&2
        exit 1
    fi
    git add -- "$descriptor"
    if ! printf '%s\n' "docs: Carry the ledger round of this landing" \
        | git commit -q -F - -- "$descriptor"; then
        echo "land: the commit of the round descriptor was refused; $descriptor is staged" >&2
        exit 1
    fi
fi

if [[ "${WZ_PREPUSH_EXTENDED:-0}" == "1" ]]; then
    # The hook's own sweep, asked as a branch push of this range would ask it. Gate 0p
    # grades only a push to main, which is the integrator's; everything else the hook
    # grades is the same.
    precheck="$(git rev-parse --path-format=absolute --git-path "wz-land-precheck-$$")"
    trap 'rm -f -- "$precheck"' EXIT
    printf 'HEAD %s refs/heads/wz-land-precheck %s\n' \
        "$(git rev-parse HEAD)" "$(git rev-parse origin/main)" >"$precheck"
    if ! git hook run --to-stdin="$precheck" pre-push -- origin "$(git remote get-url origin)"; then
        echo "land: the extended local sweep refused this item; nothing was submitted" >&2
        exit 1
    fi
fi

submitted="$(git rev-parse HEAD)"
rc=0
"$bx_bin" --land "$submitted" || rc=$?
case "$rc" in
0) ;;
1)
    echo "land: the queue returned the item (the lines above say why); nothing landed" >&2
    exit 1
    ;;
2)
    echo "land: the item was not submitted, was cancelled, or its end is not known (the lines above say why)" >&2
    exit 3
    ;;
*)
    echo "land: bx --land ended $rc (the lines above say why)" >&2
    exit 1
    ;;
esac

git fetch -q origin main
# Every commit of the item landed, put on the tip by the integrator, so origin/main holds
# all of them and the round it filed. A branch still at the submitted commit moves there
# and loses nothing; one that gained a commit while the item waited is rebased, and git
# drops the landed commits as equal patches.
if [[ "$(git rev-parse HEAD)" == "$submitted" ]]; then
    git reset -q --keep origin/main
elif ! git rebase -q origin/main; then
    git rebase --abort
    echo "land: the item landed; moving this branch onto origin/main conflicted and was aborted" >&2
    echo "      (\`git rebase origin/main\` by hand takes up from there)" >&2
    exit 4
fi
echo "land: landed; this branch is at $(git rev-parse --short=9 HEAD), on origin/main"

#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# round-runner.sh — one debt round per SESSION, repeated until the register is
# empty or the round says stop.
#
# WHY A PROCESS LOOP AND NOT AN IN-SESSION ONE
#
# `/loop` repeats inside one conversation, so every round's transcript stacks on
# the last and eventually gets summarised. What summarising costs here is
# exactly what makes a round correct: which numbers were measured rather than
# quoted, whether the falsify probe actually reddened, whether an item was M or
# I. A fresh process per round has no such decay — and this workspace already
# carries cross-round state properly, in the atomic ledger and in agent memory,
# because its kickoff was designed to restore from them rather than from a
# conversation.
#
# WHY THIS MACHINE AND NOT A CLOUD RUNNER
#
# The gates a round has to re-measure are machine-local: the pico oracle needs
# `target/zenoh-pico-build/lib/libzenohpico.so`, the SSOT gates need
# `mnemosyne-cli` on PATH, the footprint lanes need this box's toolchain set,
# and the push gate reads `.git/wz-nda-terms.txt`, which by design exists only
# here. A cloud session has none of it and would report green on checks that
# never ran.
#
# THE STOP CONDITION IS THE FEATURE
#
# Each round writes `.round/status`, whose first line is CONTINUE / DONE /
# STOP. The runner reads it and does nothing clever with it: a missing or
# unparseable verdict STOPS, on the same rule every gate in this repo follows —
# a check that cannot read its input must not report success. The loop cannot
# talk itself into another round.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# NOT under .git/. The verdict is written by the AGENT, and the permission
# layer treats .git/ as sensitive: interactively that is a prompt, but a
# headless round has nobody to answer it, so the write is simply refused and
# the round ends with no verdict. Found by smoke-testing the plumbing rather
# than by reading it -- the interactive path had worked.
run_dir="$repo_root/.round"
status_file="$run_dir/status"
lock_file="$run_dir/runner.lock"
log_dir="$run_dir/logs"
prompt_file="scripts/round-prompt.txt"

max_rounds=10
permission_mode="acceptEdits"
round_timeout=$(( 4 * 60 * 60 ))
dry_run=0

usage() {
    cat <<'USAGE'
usage: scripts/round-runner.sh [options]

  --max-rounds N        stop after N rounds regardless of verdict (default 10)
  --timeout SECONDS     per-round wall clock ceiling (default 14400 = 4h)
  --permission-mode M   claude --permission-mode (default acceptEdits)
  --prompt FILE         round prompt (default scripts/round-prompt.txt); a
                        smoke prompt here exercises the loop without doing work
  --dry-run             print the command that would run, then exit
  -h, --help            this

Each round is a fresh `claude -p` session fed scripts/round-prompt.txt.
Transcripts land in .round/logs/ (gitignored). Ctrl-C between rounds is
safe: the loop only ever starts a round from a clean verdict.

bypassPermissions is deliberately NOT the default. This repo pushes to a
public main; a mode that answers every prompt yes covers `rm -rf` too. If a
round dies on a permission refusal, widen .claude/settings.local.json for that
one command rather than removing the question.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-rounds)      max_rounds="$2"; shift 2 ;;
        --timeout)         round_timeout="$2"; shift 2 ;;
        --permission-mode) permission_mode="$2"; shift 2 ;;
        --prompt)          prompt_file="$2"; shift 2 ;;
        --dry-run)         dry_run=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        *) echo "round-runner: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ ! -r "$prompt_file" ]]; then
    echo "round-runner: $prompt_file missing or unreadable" >&2
    exit 1
fi
if ! command -v claude >/dev/null 2>&1; then
    echo "round-runner: claude CLI not on PATH" >&2
    exit 1
fi

if [[ $dry_run -eq 1 ]]; then
    echo "round-runner: would run, once per round, from $repo_root:"
    echo "  claude -p \"\$(cat $prompt_file)\" --permission-mode $permission_mode"
    echo "  verdict file: $status_file"
    echo "  logs:         $log_dir/round-NNN.log"
    echo "  ceiling:      $max_rounds round(s), ${round_timeout}s each"
    exit 0
fi

# Single instance. Two runners would interleave commits, ledger appends and
# pushes on one branch; the ledger alone is a single JSON with a monotonic
# `Round N`, so a second writer is a corruption, not a slowdown.
mkdir -p "$run_dir"
exec 9>"$lock_file"
if ! flock -n 9; then
    echo "round-runner: another runner holds $lock_file" >&2
    exit 1
fi

mkdir -p "$log_dir"

round=0
while (( round < max_rounds )); do
    round=$(( round + 1 ))
    log="$log_dir/round-$(printf '%03d' "$round").log"

    # Clear the verdict BEFORE the round, so a round that dies without writing
    # one cannot be judged by its predecessor's answer.
    rm -f "$status_file"

    echo "round-runner: round $round/$max_rounds -> $log"
    set +e
    # </dev/null: with no stdin `claude -p` waits 3s for piped input that is
    # never coming, once per round, and says so on stderr.
    timeout "$round_timeout" \
        claude -p "$(cat "$prompt_file")" \
            --permission-mode "$permission_mode" \
        >"$log" 2>&1 </dev/null
    rc=$?
    set -e

    if [[ $rc -eq 124 ]]; then
        echo "round-runner: round $round hit the ${round_timeout}s ceiling; stopping." >&2
        exit 1
    fi
    if [[ $rc -ne 0 ]]; then
        echo "round-runner: round $round exited $rc; stopping. tail of $log:" >&2
        tail -20 "$log" >&2
        exit "$rc"
    fi

    if [[ ! -r "$status_file" ]]; then
        echo "round-runner: round $round wrote no verdict to $status_file; stopping." >&2
        echo "  A round that did not say how it ended is not a round that succeeded." >&2
        tail -20 "$log" >&2
        exit 1
    fi

    verdict="$(head -1 "$status_file")"
    echo "round-runner: round $round verdict: $verdict"
    sed -n '2,$p' "$status_file"

    case "$verdict" in
        CONTINUE) ;;
        DONE*)
            echo "round-runner: register empty; nothing left to close."
            exit 0 ;;
        STOP*)
            echo "round-runner: stopping as the round asked."
            exit 0 ;;
        *)
            echo "round-runner: unparseable verdict '$verdict'; stopping." >&2
            exit 1 ;;
    esac
done

echo "round-runner: reached the $max_rounds-round ceiling with work still open."
echo "  This is the ceiling talking, not the register. Re-run to continue."

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
stream=1
reap=1

usage() {
    cat <<'USAGE'
usage: scripts/round-runner.sh [options]

  --max-rounds N        stop after N rounds regardless of verdict (default 10)
  --timeout SECONDS     per-round wall clock ceiling (default 14400 = 4h)
  --permission-mode M   claude --permission-mode (default acceptEdits)
  --prompt FILE         round prompt (default scripts/round-prompt.txt); a
                        smoke prompt here exercises the loop without doing work
  --no-stream           final answer only, instead of a live JSONL transcript.
                        Streaming is the DEFAULT because plain -p writes the log
                        in ONE go at the end: a round that dies mid-way leaves an
                        EMPTY log, which is exactly when you want to read it.
  --no-reap             skip the build-artefact reap around each round
  --dry-run             print the command that would run, then exit
  -h, --help            this

Each round is a fresh `claude -p` session fed scripts/round-prompt.txt.
Transcripts land in .round/logs/ (gitignored), live and one JSON object per
line. Watch one with:
  tail -f .round/logs/round-001.log | grep -o '"name":"[^"]*"'
Ctrl-C between rounds is safe: the loop only ever starts a round from a clean
verdict.

WATCHING A ROUND: use the PID, never a pattern. `pgrep -f round-runner` and
`pkill -f ...` match the ROUND ITSELF and any shell quoting the same string,
because the whole prompt rides on the command line and the prompt names this
file. That misfire killed the wrong process once. Take the pid the runner
prints, or read it off `ps --forest`, and drive everything off that:
  ps -p <pid>            # still alive?
  ps --ppid <pid>        # what is it running RIGHT NOW (cargo? gh? nothing?)
To stop AFTER the current round, SIGTERM this runner's own pid: the round is a
child that outlives it, finishes its work, and writes its verdict -- but no
next round starts. Nothing prints the verdict then, so read .round/status.

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
        --no-stream)       stream=0; shift ;;
        --no-reap)         reap=0; shift ;;
        --dry-run)         dry_run=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        *) echo "round-runner: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
done

# stream-json needs --verbose in print mode; the pair is what makes the log
# land line by line instead of all at once when the round ends.
output_args=()
if [[ $stream -eq 1 ]]; then
    output_args=(--output-format stream-json --verbose)
fi

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
    echo "  claude -p \"\$(cat $prompt_file)\" --permission-mode $permission_mode ${output_args[*]}"
    echo "  verdict file: $status_file"
    echo "  logs:         $log_dir/round-NNN.log"
    echo "  ceiling:      $max_rounds round(s), ${round_timeout}s each"
    exit 0
fi

# ─── Build-artefact reap, around each round (R311y735, N26) ─────────
#
# WHY IT IS SAFE TO DO THIS UNATTENDED, which it was not before R311y734.
# `sweep-target.sh reap` requires PROOF that a full gate ran since the stamp: a
# run-ci log, newer than it, whose passed-lane count equals the number
# run-ci.sh registers. A round that ran a partial gate — which is most rounds —
# cannot satisfy that, so the reap refuses and the tree is untouched. The
# automation therefore needs no threshold of its own and carries no number
# anyone chose: rounds that happen to run the full gate get their artefacts
# reaped, and every other round pays one refusal message.
#
# IT SAYS WHY IT DECLINED. A reap that skipped in silence would read as "there
# was nothing to reap", which is the failure mode this workspace keeps
# measuring in its own gates.
sweep="$repo_root/scripts/sweep-target.sh"

reap_stamp() {
    [[ $reap -eq 1 && -x "$sweep" ]] || return 0
    bash "$sweep" stamp >/dev/null 2>&1 ||
        echo "round-runner: could not stamp for the reap; the tree is untouched."
}

reap_after() {
    [[ $reap -eq 1 && -x "$sweep" ]] || return 0
    # `|| rc=$?` and not a bare assignment: under `set -e` a command
    # substitution that exits non-zero kills the RUNNER before `$?` can be
    # read, and a declined reap exits non-zero BY DESIGN. Probed: the first
    # version of this hook ended the round loop on the ordinary case.
    local out rc=0
    out="$(bash "$sweep" reap --apply 2>&1)" || rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "round-runner: reap — $(tail -1 <<<"$out")"
    else
        # Not a failure of the round. The common case is "this round did not
        # run the full gate", which is exactly when reaping would be wrong.
        echo "round-runner: reap declined — $(grep -m1 'FAIL\|REFUSING' <<<"$out" |
            sed 's/^sweep-target: //')"
    fi
}

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
    reap_stamp
    set +e
    # </dev/null: with no stdin `claude -p` waits 3s for piped input that is
    # never coming, once per round, and says so on stderr.
    timeout "$round_timeout" \
        claude -p "$(cat "$prompt_file")" \
            --permission-mode "$permission_mode" \
            "${output_args[@]}" \
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
    reap_after
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

#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y791 (no register item) — a CI job's own time-budget margin, as a gate
# rather than a hope. The debt it closes was opened by y790 and lives outside
# the store's `debt-` register, so there is no id to cite here.
#
# WHY THIS EXISTS. `timeout-minutes` on a GitHub job does not fail the job; it
# CANCELS it. A cancel grades nothing, so a run that trips the ceiling reports
# neither pass nor fail and the commit it was grading gets no hosted verdict at
# all. That happened on run 31711867852 (Round 1819): the `ci` job was cancelled
# at 30m20s of a 30m budget, on a ledger-only commit, with every other job in
# the run green.
#
# It had been visible for a long time and only ever in prose. ci.yml:145-147
# recorded in y296 that "both ceilings were being approached at once and nothing
# reported either" and acted on the disk one; y351 wrote "Nothing reported the
# margin — exactly what ci.yml:84-86 predicted in y297 and left standing". This
# file is the part that was left standing.
#
# WHY A SCRIPT AND NOT A `run:` BLOCK. A gate whose logic lives inside a
# workflow step cannot be executed by anything except the workflow, so it cannot
# be tested and its two arms cannot be told apart -- the same objection Layer C0
# raised against `append-round.sh` in y783 ("a gate nothing runs cannot fail"),
# answered there by Layer C0i. Here the answer is the same shape: the logic is
# one script, and run-ci Layer C0b drives both arms.
#
# USAGE
#   job-budget-margin.sh <start-epoch-file> <budget-seconds> <alarm-percent>
#
# Exit 0 = inside the margin. Exit 1 = at or past the alarm fraction. Any
# malformed input is exit 2 and is NOT treated as "inside the margin": a gate
# that cannot read its input must not report green.

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "job-budget-margin: usage: $0 <start-epoch-file> <budget-seconds> <alarm-percent>" >&2
    exit 2
fi

start_file="$1"
budget_seconds="$2"
alarm_pct="$3"

if [[ ! -r "${start_file}" ]]; then
    echo "job-budget-margin: FAIL: start-epoch file '${start_file}' is unreadable." \
        "The stamp step did not run, so the margin is unknown -- and unknown is not green." >&2
    exit 2
fi

start_epoch="$(cat "${start_file}")"

for value in "${start_epoch}" "${budget_seconds}" "${alarm_pct}"; do
    if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
        echo "job-budget-margin: FAIL: '${value}' is not a non-negative integer" >&2
        exit 2
    fi
done

if [[ "${budget_seconds}" -eq 0 ]]; then
    echo "job-budget-margin: FAIL: budget-seconds must be non-zero" >&2
    exit 2
fi

# `WZ_JOB_BUDGET_NOW` exists for the test lane, which must be able to place the
# clock rather than wait 27 minutes for it. Absent -- i.e. in CI -- the real
# clock is read, so the override cannot silently soften a hosted run.
now_epoch="${WZ_JOB_BUDGET_NOW:-$(date +%s)}"
if ! [[ "${now_epoch}" =~ ^[0-9]+$ ]]; then
    echo "job-budget-margin: FAIL: WZ_JOB_BUDGET_NOW='${now_epoch}' is not an integer" >&2
    exit 2
fi

if [[ "${now_epoch}" -lt "${start_epoch}" ]]; then
    echo "job-budget-margin: FAIL: now (${now_epoch}) precedes the start stamp (${start_epoch})" >&2
    exit 2
fi

elapsed=$(( now_epoch - start_epoch ))
pct=$(( elapsed * 100 / budget_seconds ))

echo "job-budget-margin: elapsed ${elapsed}s of ${budget_seconds}s budget (${pct}%)," \
    "alarm at ${alarm_pct}%"

if [[ "${pct}" -ge "${alarm_pct}" ]]; then
    cat >&2 <<EOF
::error::job used ${pct}% of its ${budget_seconds}s budget (alarm at ${alarm_pct}%).
Every lane above this step PASSED; what failed is the MARGIN. At this fraction
runner variance alone decides whether the next run is graded or cancelled, and a
cancel grades nothing -- the commit it was grading gets no hosted verdict.
The remedy is to SPLIT a lane into its own job (see the y791 verdict-legs job),
not to raise timeout-minutes: a bigger number buys one atom's worth of time and
re-arms the same failure, because the cost grows monotonically in atom count.
EOF
    exit 1
fi

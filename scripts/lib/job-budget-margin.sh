#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
# WHICH JOBS CARRY IT, and this is a MEASUREMENT rather than a policy. Over the
# completed CI runs ending at 31750463524, successful jobs against their own
# `timeout-minutes` (max of the observed band):
#
#     feature-gate NEG lanes   2328s / 2700s   86%   <- instrumented (y792)
#     validate + verify + test 1730s / 1800s   96%   <- instrumented (y791),
#                                                       and ~62% after the
#                                                       y791 C0mut split
#     cross-compile + QEMU      687s / 2700s   25%
#     cross-impl proof lanes   1245s / 7200s   17%
#     Zephyr cooperative boot   250s / 3600s    7%
#
# The bottom three are not instrumented and should not be: a gate that cannot
# plausibly fire teaches nobody anything, and adding it everywhere would make
# the two that matter look like boilerplate. Re-measure before assuming this
# table still holds -- that is exactly how the `ci` job's "26m22s" rotted.
#
# CHECKED IN BOTH DIRECTIONS (R311y794). Too HIGH is the cancel this file was
# written for. Too LOW is a budget nothing can approach, which is a gate that
# cannot fire -- and a `timeout-minutes` that cannot fire is exactly the state
# every job here was in before y791. This workspace already applies the
# two-directional rule to its doc-link budget ("a crate whose count FALLS is
# also a failure... a stale budget is a gate that has quietly stopped
# measuring") and to the orphan ledger, which rejects a resolved-but-still-
# ledgered entry. A time budget is the same kind of number.
#
# The floor is OPTIONAL because a job may be legitimately far under its budget
# for a stated reason; passing one is the caller saying "this budget is a claim
# I want held to". It exists because R311y793 gave the new routing-adminspace
# job 45 minutes for its COLD first run and wrote down that nothing would ever
# make anyone lower it again.
#
# R2069 — THE FLOOR NEEDS THE JOB'S STATUS, AND ITS OWN MESSAGE SAID SO.
# That message opens "Nothing failed." and this script had no way to know it.
# In run 32652466813 it fired on a job that used 13% of 1800s because the job
# DIED at Layer C0 after 234 seconds -- so an early red manufactured a second,
# unrelated red underneath it, and the workflow runs this step under
# `if: always()`, which means EVERY fast failure produces that pair. Two reds
# for one cause is the misattribution this repository pays whole rounds to
# undo. The ALARM stays unconditional: a job that ran long and then failed did
# still approach its timeout, and that is worth knowing either way.
#
# The status argument is OPTIONAL and defaults to `success`, so a caller that
# passes no floor is unaffected and one that passes a floor without a status
# keeps the old behaviour rather than silently going quiet.
#
# USAGE
#   job-budget-margin.sh <start-epoch-file> <budget-seconds> <alarm-percent>
#                        [floor-percent] [job-status]
#
# Exit 0 = inside the margin. Exit 1 = at or past the alarm fraction. Any
# malformed input is exit 2 and is NOT treated as "inside the margin": a gate
# that cannot read its input must not report green.

set -euo pipefail

if [[ $# -lt 3 || $# -gt 5 ]]; then
    echo "job-budget-margin: usage: $0 <start-epoch-file> <budget-seconds>" \
        "<alarm-percent> [floor-percent] [job-status]" >&2
    exit 2
fi

start_file="$1"
budget_seconds="$2"
alarm_pct="$3"
floor_pct="${4:-}"
job_status="${5:-success}"

if [[ ! -r "${start_file}" ]]; then
    echo "job-budget-margin: FAIL: start-epoch file '${start_file}' is unreadable." \
        "The stamp step did not run, so the margin is unknown -- and unknown is not green." >&2
    exit 2
fi

start_epoch="$(cat "${start_file}")"

for value in "${start_epoch}" "${budget_seconds}" "${alarm_pct}" ${floor_pct:+"${floor_pct}"}; do
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
    "alarm at ${alarm_pct}%${floor_pct:+, floor at ${floor_pct}%}"

if [[ -n "${floor_pct}" && "${pct}" -lt "${floor_pct}" && "${job_status}" != "success" ]]; then
    echo "job-budget-margin: floor NOT applied — job status is '${job_status}'," \
        "so the short elapsed time is the failure's, not the budget's." \
        "The alarm half still applies and did not fire." >&2
fi

if [[ -n "${floor_pct}" && "${pct}" -lt "${floor_pct}" && "${job_status}" == "success" ]]; then
    cat >&2 <<EOF
::error::job used only ${pct}% of its ${budget_seconds}s budget (floor at ${floor_pct}%).
Nothing failed. What this says is that the budget is too large to be a GATE: a
timeout nothing can approach cannot fire, and a job whose ceiling cannot fire is
the state every job in this workflow was in before R311y791. Lower
timeout-minutes to something this job can actually run into, in the same commit
that reads this -- the same rule the doc-link budget applies when a count FALLS.
EOF
    exit 1
fi

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

#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y865 (no register item) — `apt-get` with a CEILING, because without one a
# mirror outage spends a whole job's time budget and reports it as the job being
# slow.
#
# The debt it closes was opened by this same round's diagnosis of run
# 32160845314 and lives outside the store's `debt-` register, so there is no id
# to cite here — the same position `job-budget-margin.sh` is in.
#
# WHAT HAPPENED. Run 32160845314: three jobs — the C0mut gate, the isolated-crate
# lanes and the feature-gate NEG lanes — were all reported `cancelled`, each at
# exactly its own `timeout-minutes`. The step timeline says what the conclusions
# do not:
#
#     16:33:40  Run sudo apt-get update
#     16:34:10  Ign:2 http://azure.archive.ubuntu.com/ubuntu jammy InRelease
#     ...       the same four Ign lines, retried, for twenty-nine minutes
#     17:02:47  the job hits timeout-minutes and is cancelled
#
# Nothing in this tree was involved. But the three jobs died in the SAME shape a
# job dies in when its lanes have genuinely outgrown their budget, and this
# session very nearly filed them under that debt (249) instead. The step
# timeline was the only thing that told them apart, and reading it costs a
# `gh api .../jobs/<id>/logs` per job.
#
# SO THE FIX IS NOT "MAKE APT FASTER", IT IS "MAKE APT FAIL BY NAME". Thirty
# minutes of silence becomes half a minute and a sentence that says the mirror
# is unreachable, which is a fact about Azure's archive and not about this
# repository's lanes.
#
# HOW IT BOUNDS. Two independent ceilings, because apt has two ways to hang:
#
#   1. Per-transfer, through apt's own knobs. `Acquire::http::Timeout` and its
#      https twin bound one connection; `Acquire::Retries` bounds how many times
#      apt re-attempts a source it could not reach. Left at their defaults, an
#      unreachable mirror is retried on a schedule that has no total.
#   2. Wall-clock, through `timeout(1)` around the whole invocation. The knobs
#      above are apt's promise; this is the one this script can keep. A mirror
#      that accepts a connection and then dribbles bytes satisfies every
#      per-transfer timeout there is and still runs forever.
#
# WHY ONE SCRIPT AND NOT A FLAG ON THIRTEEN STEPS. There are thirteen
# `apt-get update` sites in ci.yml. A knob added to each is a list that has to
# stay in agreement with itself, which is the class this workspace has paid for
# repeatedly — most recently `verdict_leg_mutation.py`'s hand-written recipe
# loop going stale against the accessor it described (R311y862). One script is
# one place.
#
# WHY IT IS TESTABLE. Logic that lives inside a workflow `run:` block cannot be
# executed by anything except the workflow, so its two arms cannot be told apart
# from logic that always passes — the objection Layer C0i raised against
# `append-round.sh` and Layer C0b against the budget gate. Same answer here: the
# bounded-wait core is a function, `WZ_APT_CMD` replaces the command it runs,
# and run-ci Layer C0g drives both arms.
#
# USAGE
#   apt-install.sh <package>...
#
# ENVIRONMENT
#   WZ_APT_DEADLINE   wall-clock ceiling per invocation, seconds (default 300)
#   WZ_APT_RETRIES    apt's own per-source retry count (default 2)
#   WZ_APT_CMD        the command to run instead of apt-get; the test lane's
#                     only entry point. Never set in CI.
#
# Exit 0 = installed. Exit 1 = apt failed or ran past the deadline, named.
# Exit 2 = called wrong.

set -euo pipefail

WZ_APT_DEADLINE="${WZ_APT_DEADLINE:-300}"
WZ_APT_RETRIES="${WZ_APT_RETRIES:-2}"

# Run one command under the wall-clock ceiling, and say which ceiling was hit.
#
# `timeout` answers 124 for its own kill, and that is the case worth naming
# separately: a non-zero from apt is apt refusing, while a 124 is apt never
# answering, and those send a reader to different places.
wz_apt_bounded() {
    local what="$1"
    shift
    local rc=0
    timeout "${WZ_APT_DEADLINE}" "$@" || rc=$?
    if [[ "${rc}" -eq 124 ]]; then
        cat >&2 <<EOF
::error::apt: ${what} did not finish within ${WZ_APT_DEADLINE}s and was killed.
This is a package-mirror outage, NOT a lane in this repository being slow. Left
unbounded it would have kept retrying until this job hit its timeout-minutes and
was reported \`cancelled\` — the shape run 32160845314 took on three jobs at
once, where an unreachable azure.archive.ubuntu.com burned twenty-nine minutes
per job. Re-run the job; if it recurs, the mirror is down.
EOF
        return 1
    fi
    if [[ "${rc}" -ne 0 ]]; then
        echo "::error::apt: ${what} failed with exit ${rc}." \
            "This is apt REFUSING rather than apt hanging — read its output above." >&2
        return 1
    fi
    return 0
}

# The one entry point. Split from `main` so the test lane can drive the ceiling
# without installing anything.
wz_apt_install() {
    if [[ $# -lt 1 ]]; then
        echo "apt-install: usage: $0 <package>..." >&2
        return 2
    fi
    # `WZ_APT_CMD` arrives as one string and must become argv; unquoted on
    # purpose, and only ever set by the test lane.
    # shellcheck disable=SC2206
    local apt=(${WZ_APT_CMD:-sudo apt-get})
    local opts=(
        -o "Acquire::Retries=${WZ_APT_RETRIES}"
        -o "Acquire::http::Timeout=15"
        -o "Acquire::https::Timeout=15"
    )
    wz_apt_bounded "update" "${apt[@]}" "${opts[@]}" update || return 1
    wz_apt_bounded "install of $*" \
        "${apt[@]}" "${opts[@]}" install -y --no-install-recommends "$@" || return 1
    return 0
}

# Sourced by the test lane, executed by CI. `${BASH_SOURCE[0]}` differs from
# `$0` only when sourced, which is exactly the distinction wanted.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    wz_apt_install "$@"
fi

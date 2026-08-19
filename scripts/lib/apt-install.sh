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
# R311y872 — THE CEILING BOUNDED NOTHING, AND SAID IT HAD.
#
# Run 32207350092 reported NINE jobs failed, every one of them at this step, and
# the log of job 95933028814 says what the conclusion does not:
#
#     02:09:11  Get:1 ... 32.4 MB of archives
#     02:11:06  Get:9 ... libclang-14-dev 25.2 MB
#     02:16:45  Fetched 32.4 MB in 7min 34s (71.4 kB/s)
#     02:16:49  Setting up cmake (3.22.1-1ubuntu1.22.04.2) ...
#     02:16:51  ##[error]apt: install ... did not finish within 300s and was killed.
#
# THE INSTALL SUCCEEDED. Every package was fetched, unpacked and configured, and
# two seconds after `Setting up cmake` this script reported it killed. That is a
# gate whose verdict is about ITSELF rather than about its subject, and it was
# red on nine jobs across two rounds.
#
# TWO INDEPENDENT REASONS, both of which produce that exact symptom:
#
#   1. `timeout` STOOD OUTSIDE THE PRIVILEGE. The invocation was
#      `timeout 300 sudo apt-get ...`, so the process `timeout` signals is a
#      SETUID root `sudo` and the signal comes from an unprivileged parent. The
#      kernel refuses it. `timeout` then waits out a command it cannot stop and
#      answers 124 on its own clock, while apt runs to completion behind it.
#   2. NO `--kill-after`. `timeout` sends TERM and nothing else. apt and dpkg
#      trap TERM during unpack precisely so a killed run does not leave a broken
#      package database, so even inside the privilege a plain TERM is a request
#      rather than a kill.
#
# So the ceiling is composed as `sudo timeout --kill-after=K D apt-get ...`:
# INSIDE the privilege, and with the second signal that makes it a kill. The
# composition is its own function because it is the property that was wrong, and
# a property that was wrong once needs something that can fail on it —
# `wz_apt_compose` prints the argv it would run and Layer C0g reads it.
#
# AND THE DEADLINE SPLITS IN TWO, because the two invocations do different
# amounts of work and one number could not be right for both. R311y865's
# 29-minute outage was an `update` retrying `Ign:` lines against an unreachable
# mirror — no bytes, no progress, and 300s is generous for it. An `install` of
# this repo's largest package set is 32.4 MB, MEASURED at 454s on a mirror that
# was answering at 71 kB/s. Holding that to the same 300s is what turned a slow
# success into a red, and raising the single number to cover it would have
# doubled the silence R311y865 bought for the case it was actually built for.
#
# WHAT THIS DOES NOT FIX: the mirror is genuinely slow. apt's own
# `Acquire::Retries` + `Acquire::*::Timeout` are the fast path for a mirror that
# does not answer at all; this wall clock is the backstop for one that answers
# and dribbles. That the knobs fail fast is NOT measured here.
#
# R311y876 — A FAILED `update` NO LONGER VETOES THE INSTALL.
#
# Run 32218773681: nine jobs, every one dead at `apt: update` on its 300s
# deadline, and not one wz lane had run. The ceiling was doing exactly what
# R311y872 built it to do; what was wrong is that a step whose PURPOSE is four
# packages was answering on behalf of a step that fetches an index.
#
# `update` is a MEANS. The runner image ships an index, and for cmake, clang,
# libclang-dev, perl and pkg-config it is very nearly always good enough. So a
# failed update is annotated and the install is ATTEMPTED, and the install's own
# verdict is the step's. R311y874's carry 6 proposed raising the deadline
# instead; that is a guess about a mirror, and it would have left this standing
# while making it fire less often.
#
# Nothing is hidden by continuing: a stale index either still names fetchable
# versions, in which case the install succeeds, or it does not, in which case the
# install fails by name with apt's own 404. There is no arm where a package is
# quietly absent. The staleness is annotated in both directions, and an install
# that fails after a failed update says so, because that is what a reader should
# suspect first.
#
# USAGE
#   apt-install.sh <package>...
#
# ENVIRONMENT
#   WZ_APT_UPDATE_DEADLINE    ceiling on `apt-get update`, seconds (default 300)
#   WZ_APT_INSTALL_DEADLINE   ceiling on `apt-get install`, seconds (default 900)
#   WZ_APT_DEADLINE           sets BOTH, for the test lane and for a caller that
#                             wants one number
#   WZ_APT_KILL_AFTER         grace between TERM and KILL, seconds (default 30)
#   WZ_APT_RETRIES            apt's own per-source retry count (default 2)
#   WZ_APT_CMD                the command to run instead of apt-get; the test
#                             lane's only entry point. Never set in CI.
#
# Exit 0 = installed, whether or not `update` succeeded first.
# Exit 1 = the INSTALL failed or ran past its deadline, named.
# Exit 2 = called wrong.

set -euo pipefail

WZ_APT_UPDATE_DEADLINE="${WZ_APT_DEADLINE:-${WZ_APT_UPDATE_DEADLINE:-300}}"
WZ_APT_INSTALL_DEADLINE="${WZ_APT_DEADLINE:-${WZ_APT_INSTALL_DEADLINE:-900}}"
WZ_APT_KILL_AFTER="${WZ_APT_KILL_AFTER:-30}"
WZ_APT_RETRIES="${WZ_APT_RETRIES:-2}"

# Compose the argv that runs `$@` under a ceiling of `$1` seconds.
#
# The whole of the R311y872 defect is in where `timeout` goes, so it is decided
# HERE, in a function that prints its answer and installs nothing — a lane can
# then fail on the composition without a package mirror, a network or a root
# password. When the command elevates, the ceiling elevates WITH it; when it
# does not (the test lane's stand-ins), there is no privilege boundary to be on
# the wrong side of.
wz_apt_compose() {
    local deadline="$1"
    shift
    local bound=(timeout "--kill-after=${WZ_APT_KILL_AFTER}" "${deadline}")
    if [[ "${1:-}" == "sudo" ]]; then
        shift
        printf '%s\n' sudo "${bound[@]}" "$@"
        return 0
    fi
    printf '%s\n' "${bound[@]}" "$@"
}

# Run one command under the wall-clock ceiling, and say which ceiling was hit.
#
# `timeout` answers 124 for its own kill, and that is the case worth naming
# separately: a non-zero from apt is apt refusing, while a 124 is apt never
# answering, and those send a reader to different places.
#
# R311y876 — `severity` is the annotation level, because the two invocations no
# longer mean the same thing to the job. A failed `install` is the step failing;
# a failed `update` is a note about the index the install then used. Emitting
# `::error::` for both would put a red annotation on a job that went green, and
# this workspace reads annotations.
wz_apt_bounded() {
    local severity="$1"
    local what="$2"
    local deadline="$3"
    shift 3
    local argv=()
    while IFS= read -r word; do
        argv+=("$word")
    done < <(wz_apt_compose "${deadline}" "$@")
    local rc=0
    "${argv[@]}" || rc=$?
    # 137 as well as 124: with `--kill-after` the second signal is what actually
    # ends a TERM-ignoring apt, and a shell reports a KILLed child as 128+9. A
    # ceiling that named only 124 would read its own successful kill as apt
    # refusing, and send the reader to apt's output to look for a reason that is
    # not there.
    if [[ "${rc}" -eq 124 || "${rc}" -eq 137 ]]; then
        cat >&2 <<EOF
::${severity}::apt: ${what} did not finish within ${deadline}s and was killed.
This is a package-mirror outage, NOT a lane in this repository being slow. Left
unbounded it would have kept retrying until this job hit its timeout-minutes and
was reported \`cancelled\` — the shape run 32160845314 took on three jobs at
once, where an unreachable azure.archive.ubuntu.com burned twenty-nine minutes
per job. Re-run the job; if it recurs, the mirror is down.
EOF
        return 1
    fi
    if [[ "${rc}" -ne 0 ]]; then
        echo "::${severity}::apt: ${what} failed with exit ${rc}." \
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
    # Two ceilings, not one. `update` fetches indices and makes no progress at
    # all against a mirror that will not answer, which is the shape R311y865
    # bounded; `install` fetches this repo's 32.4 MB and was MEASURED at 454s on
    # a mirror that was answering slowly. One number could only be wrong for one
    # of them, and it was wrong for the second on nine jobs.
    #
    # R311y876 — AND A FAILED `update` NO LONGER VETOES THE INSTALL.
    #
    # `update` is a MEANS. What this script is for is the packages; refreshing
    # the index is how it usually gets a better chance at them, and the runner
    # image ships an index that is already good enough for cmake, clang, perl and
    # pkg-config the overwhelming majority of the time. Aborting here spends the
    # mirror's bad day on a step whose actual work was never attempted — run
    # 32218773681, nine jobs, every one of them dead at `apt: update` on its
    # 300s deadline with not one wz lane having run.
    #
    # THIS IS THE SAME DEFECT THE ROUND BEFORE IT FIXED, one layer out. R311y874
    # stopped a publisher's LABEL from vetoing a rule the label's own bytes
    # refute; here a preparatory step vetoes the operation it exists to prepare,
    # on its own authority and before anything has asked the packages whether
    # they were needed. A check standing in for its subject is the shape, and it
    # is worth naming because raising the deadline — R311y874's carry 6 — would
    # have left it standing while making it fire less often.
    #
    # WHAT THIS DOES NOT HIDE, which is why it is safe. Installing against a
    # stale index has exactly two outcomes and neither is silent: the index still
    # names fetchable versions and the install SUCCEEDS, or it does not and the
    # install FAILS BY NAME with apt's own 404. There is no arm where a package
    # is quietly not installed. The staleness is annotated either way, and an
    # install that fails after a failed update says so, because that is the first
    # thing a reader should suspect.
    local stale=0
    if ! wz_apt_bounded "warning" "update" "${WZ_APT_UPDATE_DEADLINE}" \
        "${apt[@]}" "${opts[@]}" update; then
        stale=1
        echo "::warning::apt: update failed, CONTINUING with the package index this" \
            "runner image shipped. The install below is what this step is for, and" \
            "it either succeeds or fails by name; it is not being skipped." >&2
    fi
    if ! wz_apt_bounded "error" "install of $*" "${WZ_APT_INSTALL_DEADLINE}" \
        "${apt[@]}" "${opts[@]}" install -y --no-install-recommends "$@"; then
        if [[ "${stale}" -eq 1 ]]; then
            echo "::error::apt: and update had ALREADY failed above, so this install ran" \
                "against the image's shipped index. A version it names may no longer be" \
                "on the mirror. Suspect the mirror before suspecting the package list." >&2
        fi
        return 1
    fi
    if [[ "${stale}" -eq 1 ]]; then
        echo "::notice::apt: installed from the image's shipped index -- update failed" \
            "above and the packages were there anyway." >&2
    fi
    return 0
}

# Sourced by the test lane, executed by CI. `${BASH_SOURCE[0]}` differs from
# `$0` only when sourced, which is exactly the distinction wanted.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    wz_apt_install "$@"
fi

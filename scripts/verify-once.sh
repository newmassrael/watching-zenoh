#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R3353 (no register item) -- verify a change ONCE, in the build fleet, and keep each
# lane's verdict in the clone's author receipt store under the digest of what it read.
#
#   bash scripts/verify-once.sh              the lanes whose digest the branch moved from
#                                            its merge base with origin/main and that have
#                                            no pass at that digest here
#   bash scripts/verify-once.sh --only-red   only the lanes whose latest verdict at their
#                                            current digest is a failure
#   bash scripts/verify-once.sh --all --reason '<why>'
#                                            every lane; refused without a reason when the
#                                            store already judged their inputs
#   bash scripts/verify-once.sh --plan       print what would run, and why; run nothing
#   bash scripts/verify-once.sh --check      run nothing; 0 only when every lane the
#                                            branch moved has a pass at its digest
#   bash scripts/verify-once.sh --summary    one line per lane the branch moved: lane,
#                                            digest, verdict, executor (a round's verification)
#   --base <ref>                             the target of the diff (default origin/main)
#
# The lane set, each lane's class and its digest D(L, t) are scripts/lib/lane_digest.py's;
# the author receipt store and the plans are scripts/lib/gate_ledger.py's, whose docstring
# says why. The lanes run as units of `bx --checks ci`, one call for all of them; a lane
# with a pass at its digest is inherited and printed with the commit it was judged on.
# Run this once, after the work is committed: a second run with nothing changed has
# nothing to do and says so. A whole gate chained by hand (run-ci.sh lane after lane)
# is what this replaces. Receipts are the author's: they spare a run, and nothing that
# admits a candidate to main reads them.
#
# It refuses a dirty or untracked tree: bx ships the working state, and a receipt binds
# to committed bytes.
#
# Exit codes: 0 every lane the branch moved has a pass at its digest; 1 a lane failed
# or was not measured, or (--plan, --check) a lane is still to run; 2 usage, a dirty tree, no bx, or a plan that could not
# be made; 3 --all refused because the store already judged these inputs.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

ledger="scripts/lib/gate_ledger.py"
mode="changed"
base="origin/main"
reason=""
plan_only=0
check_only=0
summary_only=0

usage() {
    sed -n '5,21p' "$0" | sed 's/^# \{0,1\}//'
}
set_mode() {
    if [[ "$mode" != "changed" ]]; then
        echo "verify-once: --$mode and --$1 ask for two plans; give one" >&2
        exit 2
    fi
    mode="$1"
}
while [[ $# -gt 0 ]]; do
    case "$1" in
    --only-red)
        set_mode only-red
        shift
        ;;
    --all)
        set_mode all
        shift
        ;;
    --reason)
        [[ $# -ge 2 && -n "$2" ]] || { echo "verify-once: --reason needs a sentence" >&2; exit 2; }
        reason="$2"
        shift 2
        ;;
    --base)
        [[ $# -ge 2 && -n "$2" ]] || { echo "verify-once: --base needs a ref" >&2; exit 2; }
        base="$2"
        shift 2
        ;;
    --plan)
        plan_only=1
        shift
        ;;
    --check)
        check_only=1
        shift
        ;;
    --summary)
        summary_only=1
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        echo "verify-once: unknown argument `$1`" >&2
        usage >&2
        exit 2
        ;;
    esac
done
if [[ -n "$reason" && "$mode" != "all" ]]; then
    echo "verify-once: --reason is the reason of a whole run; give it with --all" >&2
    exit 2
fi
if [[ ($check_only -eq 1 || $summary_only -eq 1) && "$mode" != "changed" ]]; then
    echo "verify-once: --check and --summary read the lanes the branch moved; no other mode" >&2
    exit 2
fi
if [[ $summary_only -eq 1 ]]; then
    exec python3 -I "$ledger" summary --base "$base" --head HEAD
fi

if [[ -n "$(git status --porcelain)" ]]; then
    echo "verify-once: the tree is dirty or has untracked files. Commit first: the fleet is" >&2
    echo "             sent the working state, and a receipt binds to committed bytes." >&2
    git status --short >&2
    exit 2
fi
head="$(git rev-parse HEAD)"
if [[ "$base" == origin/* ]]; then
    git fetch -q origin "${base#origin/}" 2>/dev/null \
        || echo "verify-once: could not fetch $base; it is judged as it is here" >&2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

plan_args=(plan --mode "$mode" --base "$base" --head "$head" --ids-out "$work/ids")
if [[ -n "$reason" ]]; then
    plan_args+=(--reason "$reason")
fi
plan_rc=0
python3 -I "$ledger" "${plan_args[@]}" || plan_rc=$?
case "$plan_rc" in
0)
    echo "verify-once: nothing to run; every lane the branch moved has a pass at its digest"
    exit 0
    ;;
1) ;;
3)
    exit 3
    ;;
*)
    echo "verify-once: no plan was made (exit $plan_rc; the lines above say why)" >&2
    exit 2
    ;;
esac
if [[ $plan_only -eq 1 || $check_only -eq 1 ]]; then
    echo "verify-once: lanes are still to run (above); run `bash scripts/verify-once.sh`" >&2
    exit 1
fi

bx_bin="$(command -v bx || true)"
if [[ -z "$bx_bin" && -x "$HOME/.local/bin/bx" ]]; then
    bx_bin="$HOME/.local/bin/bx"
fi
if [[ -z "$bx_bin" ]]; then
    echo "verify-once: no bx on PATH or at ~/.local/bin/bx; the lanes run in the fleet through it" >&2
    exit 2
fi

ids="$(cat "$work/ids")"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "verify-once: running ${ids//,/ } in one `bx --checks ci` call"
bx_rc=0
"$bx_bin" --checks ci --results "$work/results.jsonl" -- \
    python3 -I "$ledger" units --head "$head" --ids "$ids" || bx_rc=$?
echo "verify-once: bx --checks ended $bx_rc; recording what it measured"

record_args=(record --mode "$mode" --head "$head" --started "$started"
    --results "$work/results.jsonl" --ids "$ids")
if [[ -n "$reason" ]]; then
    record_args+=(--reason "$reason")
fi
record_rc=0
python3 -I "$ledger" "${record_args[@]}" || record_rc=$?
if [[ $record_rc -ne 0 ]]; then
    echo "verify-once: a lane failed or was not measured (above); repair it and run" >&2
    echo "             `bash scripts/verify-once.sh --only-red`" >&2
    exit 1
fi
echo "verify-once: every lane the branch moved has a pass at its digest"

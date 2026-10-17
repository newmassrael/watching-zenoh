#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R3353 (no register item) -- verify a change ONCE, on the build host, and leave
# a receipt the pre-push gate 2c4 reads.
#
#   bash scripts/verify-once.sh            run every lane the push requires and has
#                                          no current receipt for, in ONE invocation
#   bash scripts/verify-once.sh --plan     print the lanes and their state, run nothing
#   bash scripts/verify-once.sh --all      run the required lanes even when current
#   --base <ref>                           the push base (default origin/main)
#   --host <name>                          the build host (default $WZ_VERIFY_HOST or pc2)
#
# Which lane a changed file requires is `scripts/lib/verify_lanes.json`, read by
# `scripts/lib/verify_plan.py`; the reasoning, and why a receipt survives a ledger
# commit and not a change to a trigger file, are in that file's docstring. Run
# this once, after the work is committed and every claim you expect is in: a
# second run with nothing changed has nothing to do and says so.
#
# It refuses a dirty or untracked tree: `bx` ships the working state, and a
# receipt binds to committed bytes. It prints failing lanes' logs' paths under
# target/verify-once/<tag>/. Run it in the background and read the result when
# the job reports, as for any build-host run: it takes as long as its lanes.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

base="origin/main"
host="${WZ_VERIFY_HOST:-pc2}"
plan_only=0
force=0
usage() {
    sed -n '4,19p' "$0" | sed 's/^# \{0,1\}//'
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base) base="${2:?--base needs a ref}"; shift 2 ;;
        --host) host="${2:?--host needs a name}"; shift 2 ;;
        --plan) plan_only=1; shift ;;
        --all) force=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "verify-once: unknown argument $1" >&2; usage >&2; exit 2 ;;
    esac
done

bx="${BX:-$HOME/.local/bin/bx}"
plan="scripts/lib/verify_plan.py"

if [[ -n "$(git status --porcelain)" ]]; then
    echo "verify-once: the tree is dirty or has untracked files. Commit first: the build" >&2
    echo "             host is sent the working state, and a receipt binds to committed bytes." >&2
    git status --short >&2
    exit 2
fi
git fetch -q origin 2>/dev/null || echo "verify-once: could not fetch origin; the base is $base as it is here" >&2
head="$(git rev-parse HEAD)"

plan_rc=0
python3 -I "$plan" plan --base "$base" --head "$head" || plan_rc=$?
if [[ $plan_only -eq 1 ]]; then
    exit "$plan_rc"
fi
if [[ $plan_rc -eq 0 && $force -eq 0 ]]; then
    echo "verify-once: every required lane already has a receipt for these bytes; nothing to run"
    exit 0
fi

tag="v$(date +%s)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
script_args=(--base "$base" --head "$head" --tag "$tag")
[[ $force -eq 1 ]] && script_args+=(--force)
if ! python3 -I "$plan" script "${script_args[@]}" >"$work/remote.sh" 2>"$work/ids.json"; then
    echo "verify-once: no lane to run" >&2
    exit 0
fi
expect="$(python3 -I -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))))' "$work/ids.json")"
echo "verify-once: running ${expect//,/ } on $host in one invocation"

remote="/home/developer/zc/verify-$tag.sh"
scp -q "$work/remote.sh" "$host:$remote"

bx_rc=0
"$bx" --host "$host" --label "verify-once" -- bash "$remote" "$tag" >"$work/bx.out" 2>&1 || bx_rc=$?
log="$(sed -n 's/.*full log: //p' "$work/bx.out" | tail -n 1)"
if [[ -z "$log" || ! -r "$log" ]]; then
    echo "verify-once: bx (rc=$bx_rc) named no readable log; its output:" >&2
    cat "$work/bx.out" >&2
    exit 1
fi

record_rc=0
python3 -I "$plan" record --base "$base" --head "$head" --log "$log" --host "$host" \
    --expect "$expect" || record_rc=$?

# A failing lane's own log, brought back where it can be read.
failed="$(sed -n 's/^LANE \([^ ]*\) rc=[1-9][0-9]*$/\1/p' "$log")"
if [[ -n "$failed" ]]; then
    mkdir -p "target/verify-once/$tag"
    while IFS= read -r lane; do
        [[ -n "$lane" ]] || continue
        safe="$(printf %s "$lane" | tr -c 'A-Za-z0-9_.-' _)"
        scp -q "$host:/home/developer/zc/$tag-$safe.log" "target/verify-once/$tag/$safe.log" \
            && echo "verify-once: $lane failed; its log: target/verify-once/$tag/$safe.log" \
            || echo "verify-once: $lane failed; its log is $host:/home/developer/zc/$tag-$safe.log" >&2
    done <<<"$failed"
fi
echo "verify-once: bx log $log"
exit "$record_rc"

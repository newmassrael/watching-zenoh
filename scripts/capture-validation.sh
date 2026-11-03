#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Capture the validation corpus of the flow zenoh test
# (docs/flow-zenoh-verdict.md §6.12) with docker, into target/validation/raw:
#
#     bash scripts/capture-validation.sh zenoh <workload>...
#     bash scripts/capture-validation.sh null <protocol>...
#
# A zenoh workload runs in one container of the image in
# scripts/capture-validation/Dockerfile, on its loopback
# (scripts/capture-validation/zenoh-workload.sh), with the pinned release's
# programs from target/validation/bin (build-bins.sh) and, where it names them,
# the zenoh-c and zenoh-pico examples from target/validation/bin-c and
# target/validation/bin-pico. A null protocol runs as its real server and
# client in containers on a docker network of its own
# (scripts/capture-validation/null-workload.sh), captured inside the server's
# network namespace. The raw captures are anonymised into captures/validation/
# by scripts/lib/capture_anonymise.py (scope `own`); the raw ones are never
# committed.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$ROOT/scripts/capture-validation"
RAW="$ROOT/target/validation/raw"
IMAGE=wz-validation:1
mkdir -p "$RAW"

docker build -q -t "$IMAGE" "$HERE" > /dev/null || exit 2

# The containers write as root; what they wrote is handed back to the caller.
give_back() {
    docker run --rm -v "$RAW:/out" "$IMAGE" chown -R "$(id -u):$(id -g)" /out
}

kind="${1:-}"
shift || true
failed=0
case "$kind" in
zenoh)
    mounts=(-v "$ROOT/target/validation/bin:/z:ro" -v "$HERE:/w:ro" -v "$RAW:/out")
    [[ -d $ROOT/target/validation/bin-c ]] && mounts+=(-v "$ROOT/target/validation/bin-c:/zc:ro")
    [[ -d $ROOT/target/validation/bin-pico ]] && mounts+=(-v "$ROOT/target/validation/bin-pico:/zp:ro")
    for w in "$@"; do
        docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
            --sysctl net.ipv6.conf.all.disable_ipv6=0 \
            "${mounts[@]}" "$IMAGE" bash /w/zenoh-workload.sh "$w" /out
        rc=$?
        echo "capture-validation: zenoh $w rc=$rc"
        [[ $rc -eq 0 ]] || failed=$((failed + 1))
    done ;;
null)
    for p in "$@"; do
        IMAGE="$IMAGE" RAW="$RAW" bash "$HERE/null-workload.sh" "$p"
        rc=$?
        echo "capture-validation: null $p rc=$rc"
        [[ $rc -eq 0 ]] || failed=$((failed + 1))
    done ;;
*)
    echo "usage: capture-validation.sh zenoh|null <name>..." >&2
    exit 2 ;;
esac
give_back
exit "$failed"

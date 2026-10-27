#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R3787 (no register item) -- run one command inside an SDK's toolchain environment
# (docs/target-build-contract.md T2): the package entry, or a lane, on the machine where the SDK is.
#
#     bash scripts/with-sdk-env.sh yocto <sdk>/environment-setup-cortexa72-poky-linux -- <command...>
#     bash scripts/with-sdk-env.sh qnx   <sdp>/qnxsdp-env.sh                          -- <command...>
#
# The two toolchain scripts are written to be SOURCED by whoever stands at the SDK, so a command run
# for them from elsewhere (a build machine's job, a lane) had to be a shell string composed for the
# occasion, the part of the procedure nothing held. This is that string, once: it sources the
# script the SDK's kind names, in this shell, and executes the command with what it exported. The
# SDK is the caller's (T2): nothing here selects one or records where one is.
#
# Exit codes: the command's own; 2 for a usage error or an environment the toolchain script refused.
set -euo pipefail

usage() {
    echo "usage: with-sdk-env.sh yocto|qnx <sdk environment script> -- <command...>" >&2
    exit 2
}

[[ $# -ge 4 ]] || usage
kind="$1" env_script="$2"
[[ "$3" == "--" ]] || usage
shift 3

case "$kind" in
    yocto) toolchain="scripts/yocto-toolchain-env.sh" ;;
    qnx) toolchain="scripts/qnx-toolchain-env.sh" ;;
    *) usage ;;
esac
[[ -f "$env_script" ]] || { echo "with-sdk-env: $env_script is not a file" >&2; exit 2; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
# The toolchain scripts use unset variables and return codes of their own; they are sourced as
# their header says, without this file's strict mode, and a refusal is theirs to name.
set +eu
# shellcheck source=/dev/null
. "$toolchain" "$env_script" || { echo "with-sdk-env: $toolchain refused $env_script" >&2; exit 2; }
set -eu
exec "$@"

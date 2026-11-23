#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zenoh-pico's own API tests and example programs against the pico C ABI library without `std`,
# on this Linux host: the run the Platform workflow's `pico-upstream-windows` job makes of the
# release DLL, made here of the same profile's POSIX library (`os-posix`, the `capi-nostd`
# profile), so a red of that job can be read on a developer's machine first.
#
#   scripts/pico-upstream-programs.sh [<profile>] [-- <runner options>]
#
# <profile> is a registered profile (configs/profiles/), `host-peer-ext` when none is given: the
# one the release package is built from. The runner options are those of
# scripts/lib/pico_upstream_programs.py (`--sets tests,c11`, `--only c11/z_sub`, `--no-control`).
#
# The router is the stock zenohd at the pin: WZ_ZENOHD_BIN when it is set, else the one
# scripts/build-zenohd.sh installs under the artifact root. zenoh-pico itself is built from the
# pinned submodule as the same build, by the runner, with cmake.
#
# Exit status: the runner's (0 every scenario passed, 1 one failed or was not measured, 2 a
# refusal).

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
profile="host-peer-ext"
if [ "$#" -gt 0 ] && [ "$1" != "--" ]; then
    profile="$1"
    shift
fi
if [ "$#" -gt 0 ] && [ "$1" = "--" ]; then
    shift
fi

# shellcheck source=scripts/lib/artifact-root.sh
source "$root/scripts/lib/artifact-root.sh"
wz_artifact_root_init "$root" || exit 2
zenohd="${WZ_ZENOHD_BIN:-$WZ_ARTIFACTS/target/zenohd/zenohd}"
if [ ! -x "$zenohd" ]; then
    echo "pico-upstream-programs: no zenohd at $zenohd; set WZ_ZENOHD_BIN or run scripts/build-zenohd.sh" >&2
    exit 2
fi
if [ ! -f vendor/zenoh-pico/CMakeLists.txt ]; then
    echo "pico-upstream-programs: vendor/zenoh-pico is empty; run git submodule update --init vendor/zenoh-pico" >&2
    exit 2
fi

exec python3 scripts/lib/pico_upstream_programs.py --host-library "$profile" --zenohd "$zenohd" "$@"

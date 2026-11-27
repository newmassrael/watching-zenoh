#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Provision the one Kconfig interpreter of the host build configuration (pinned by version and
# hash; the Zephyr build's copy must resolve the same): kconfiglib at the version and hashes
# scripts/requirements-kconfig.txt pins, in a virtual environment of this checkout
# (target/kconfig-venv), so a host whose Python is managed by its distribution (PEP 668) needs no
# system install, and every host resolves with the same copy. scripts/lib/wz_config.py finds it
# there. Idempotent: a venv that already holds the pinned version is left as it is.
#
# Linux, macOS and Windows under Git Bash. A venv's interpreter is bin/python on the first two and
# Scripts/python.exe on Windows; the hosted workflows run this through
# .github/actions/kconfig-interpreter on all three.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# A product of this checkout, under the artifact root (scripts/lib/artifact-root.sh); wz_config.py
# reads it there under the same rule.
# shellcheck source=scripts/lib/artifact-root.sh
source "$ROOT/scripts/lib/artifact-root.sh"
wz_artifact_root_init "$ROOT" || exit 2
VENV="$WZ_ARTIFACTS/target/kconfig-venv"
REQ="$ROOT/scripts/requirements-kconfig.txt"

# The venv's own interpreter, wherever this host's venv layout puts it; nothing when there is none.
venv_python() {
    if [[ -x "$VENV/bin/python" ]]; then
        printf '%s\n' "$VENV/bin/python"
    elif [[ -x "$VENV/Scripts/python.exe" ]]; then
        printf '%s\n' "$VENV/Scripts/python.exe"
    fi
}

pinned='import kconfiglib, sys; sys.exit(kconfiglib.VERSION != (14, 1, 0))'
vpy="$(venv_python)"
if [[ -n "$vpy" ]] && "$vpy" -c "$pinned" 2>/dev/null; then
    echo "provision-kconfiglib: kconfiglib 14.1.0 already in $VENV"
    exit 0
fi

# The interpreter that makes the venv. On Windows `python` first: a `python3` there may be the
# store's launcher stub, which runs nothing, so a candidate counts only once it has run.
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) candidates="python python3" ;;
    *) candidates="python3 python" ;;
esac
py=""
for candidate in $candidates; do
    if command -v "$candidate" >/dev/null 2>&1 \
        && "$candidate" -c 'import sys, venv; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
        py="$candidate"
        break
    fi
done
if [[ -z "$py" ]]; then
    echo "provision-kconfiglib: no python 3.8 or later with venv on PATH (tried: $candidates)" >&2
    exit 2
fi

"$py" -m venv "$VENV"
vpy="$(venv_python)"
if [[ -z "$vpy" ]]; then
    echo "provision-kconfiglib: $py made $VENV with no bin/python or Scripts/python.exe in it" >&2
    exit 1
fi
"$vpy" -m pip install --quiet --no-deps --require-hashes -r "$REQ"
"$vpy" -c 'import kconfiglib; assert kconfiglib.VERSION == (14, 1, 0), kconfiglib.VERSION'
echo "provision-kconfiglib: kconfiglib 14.1.0 installed in $VENV"

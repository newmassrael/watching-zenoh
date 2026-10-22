#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Provision the one Kconfig interpreter of the host build configuration (docs/build-configuration.md,
# decision C11): kconfiglib at the version and hashes scripts/requirements-kconfig.txt pins, in a
# virtual environment of this checkout (target/kconfig-venv), so a host whose Python is managed by
# its distribution (PEP 668) needs no system install, and every host resolves with the same copy.
# scripts/lib/wz_config.py finds it there. Idempotent: a venv that already holds the pinned version
# is left as it is.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$ROOT/target/kconfig-venv"
REQ="$ROOT/scripts/requirements-kconfig.txt"

if [[ -x "$VENV/bin/python" ]] \
    && "$VENV/bin/python" -c 'import kconfiglib, sys; sys.exit(kconfiglib.VERSION != (14, 1, 0))' 2>/dev/null; then
    echo "provision-kconfiglib: kconfiglib 14.1.0 already in $VENV"
    exit 0
fi
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --no-deps --require-hashes -r "$REQ"
"$VENV/bin/python" -c 'import kconfiglib; assert kconfiglib.VERSION == (14, 1, 0), kconfiglib.VERSION'
echo "provision-kconfiglib: kconfiglib 14.1.0 installed in $VENV"

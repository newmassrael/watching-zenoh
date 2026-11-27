#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-arm-gnu-toolchain.sh -- install the Arm GNU Toolchain release Layer Bc compiles
# and weighs the C11 emission with (scripts/c11-lane.sh).
#
#     bash scripts/install-arm-gnu-toolchain.sh
#
# The release and the SHA-256 of each archive are SCE's (vendor/sce/scripts/
# install_arm_gnu_toolchain.sh, ARM_GNU_TOOLCHAIN_REV), because the lane holds wz's C11
# units to the compiler SCE's own C11 gate weighs its units with (SCE ADR 0110 D4), and
# one pin moves with the SCE pin rather than beside it. This script is that installer,
# reached under the name the hosted steps and bx's tool store give a provisioning script
# of this repository; it adds nothing to it. ARM_GNU_TOOLCHAIN_ROOT, when set, is where it
# installs, as the installer reads it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT/vendor/sce/scripts/install_arm_gnu_toolchain.sh"
if [[ ! -f "$INSTALLER" ]]; then
    echo "install-arm-gnu-toolchain: $INSTALLER is absent; run: git submodule update --init vendor/sce" >&2
    exit 1
fi
exec bash "$INSTALLER"

#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-zenoh-c-shm.sh — provision the SECOND §5.27 api-compat-c ORACLE:
# zenoh-c built WITH `Z_FEATURE_SHARED_MEMORY` and `Z_FEATURE_UNSTABLE_API`
# (R311y541).
#
# ## Why a second oracle at all
#
# `install-zenoh-c.sh` installs upstream's published standalone archive, and
# R311y540 MEASURED what that archive is: the build with neither feature. Two
# consequences follow, and this script exists for both.
#
#   1. SEVEN of upstream's 29 examples do not COMPILE against that header —
#      `z_advanced_pub`, `z_advanced_sub` and the five SHM ones. Layer C1cc
#      reports them as ORACLE-ONLY and keeps them out of the denominator, which
#      is honest but permanent: no amount of wz work moves them while the only
#      installed header cannot declare their types.
#   2. The type SIZES differ. Shared-memory moves 8 of the types wz declares and
#      unstable moves 2 (additively), so a header from this build is the only
#      thing that can check wz's other arms with a C COMPILER rather than with
#      upstream's size generator.
#
# `check-capi-c-opaque-arms.sh` already covers (2) from a source checkout, and
# it needs no install. This script covers (1), which does.
#
# ## It builds from SOURCE, because upstream publishes no such archive
#
# The release archive is one configuration. Everything else has to be built,
# which pulls the whole zenoh dependency graph — minutes, and network for
# zenoh-c's git dependency on zenoh. That is why this is on-demand rather than
# part of any default lane, exactly like `build-zenohd.sh`.
#
# The source is COPIED out of the reference checkout before building. zenoh-c's
# CMake generates `Cargo.toml` from `Cargo.toml.in` IN THE SOURCE TREE, so
# building in place would dirty the reference clone that Layer C1cc reads its
# examples from — and a reference that the build mutates is not a reference.
#
# The toolchain comes from the checkout's own `rust-toolchain.toml`, for the
# reason R311y540 measured: `z_owned_task_t` is 32 bytes under the pinned 1.85.0
# and 24 under 1.97.0, so a header built with the wrong compiler describes a
# different ABI than upstream ships.
#
# Output: target/zenoh-c-shm/{include,lib}
# Consumers point WZ_ZENOH_C_PREFIX at it.

set -euo pipefail

# R311y614 — the BUILD moved to `install-zenoh-c-arm.sh`, which does the same
# thing for any one of the four arms. This file stays because the path
# `target/zenoh-c-shm` and the entry-point name are what `run-ci.sh`'s Layer
# C1ce and the CI provisioning step call, and because the "why a second oracle"
# reasoning above is about THIS arm specifically.
#
# The prefix is passed EXPLICITLY rather than left to the generic default
# (`target/zenoh-c-unstable-shm`): the historical path is owned here, so the
# generalised script keeps one rule with no special case in it.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${WZ_ZENOH_C_SHM_PREFIX:-$ROOT/target/zenoh-c-shm}"

exec bash "$ROOT/scripts/install-zenoh-c-arm.sh" unstable-shm "$PREFIX"

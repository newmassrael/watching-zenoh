#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-mnemosyne-cli.sh — install the PINNED mnemosyne-cli for CI.
#
# Single source of truth for the mnemosyne-cli install, shared by
# .github/workflows/ci.yml and release.yml (mirrors run-ci.sh being the
# single source of truth for the lane logic) so the two workflows cannot
# drift.
#
# Pinned to a known-good rev (NOT `--branch main`): the install is then
# DETERMINISTIC — a future upstream mnemosyne `main` change cannot silently
# break this repo's CI (e.g. a config-schema change that rejects the current
# mnemosyne.toml). Bump MNEMOSYNE_REV deliberately, in its own commit, when
# this repo adopts a mnemosyne feature that needs a newer CLI; keep it in
# step with the locally-installed `--path` binary so local pre-push and CI
# validate against the same mnemosyne version.
#
# `--force` always rebuilds the pinned rev, overriding any stale
# ~/.cargo/bin binary a CI cache restored (Swatinem/rust-cache caches
# ~/.cargo/bin by default; without --force a `command -v` guard would run a
# stale cached CLI — the R408 `missing field docs` failure mode).

set -euo pipefail

# github.com/newmassrael/mnemosyne @ R757 (B1b store scene_cast projection)
# — the newest PUSHED rev (origin/main), whose CLI defines
# CURRENT_SCHEMA_VERSION 41 and READS the schema-41 store. REQUIRED bump: the
# R311y401 append (this repo's own commit, with the same d9e2bee CLI locally)
# migrated the store 39 -> 41, and the prior pin (R754, 3bf4c8d) defines only
# schema <= 39, so its validate-workspace rejected the schema-41 store
# ("schema version mismatch: store=41 expected <= 39") — the Layer A red on the
# R311y400/y401 hosted CI runs. A reader whose max < store cannot lazy-migrate,
# so the pin must move UP to a reader that covers the store. Kept in step with
# the locally-installed `--path` binary (mnemosyne-cli 0.1.0 d9e2bee), which
# validated this workspace clean (orphan new=+0) all session.
MNEMOSYNE_REV="d9e2beed24dbfca9b8ffa46c180d1cfa755e8fce"

cargo install --git https://github.com/newmassrael/mnemosyne \
  --rev "$MNEMOSYNE_REV" --bin mnemosyne-cli --force mnemosyne-cli

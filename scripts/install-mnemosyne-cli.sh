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

# github.com/newmassrael/mnemosyne @ R584 (validate: exempt append-only
# caveats from prose lint) — the rev whose CLI reads the current atomic-store
# schema_version (23). The prior pin (R415, 48117d24) only handled schema <= 9,
# so Layer A hard-failed `schema version mismatch: store=23 expected <= 9` on
# every push after the store schema bumped past 9. Kept in step with the
# locally-installed `--path` binary (mnemosyne-cli 0.1.0 bb01cc6b) so local
# pre-push and CI validate against the same mnemosyne version.
MNEMOSYNE_REV="bb01cc6b9fca5f4e7a65b50a565deb5dda938413"

cargo install --git https://github.com/newmassrael/mnemosyne \
  --rev "$MNEMOSYNE_REV" --bin mnemosyne-cli --force mnemosyne-cli

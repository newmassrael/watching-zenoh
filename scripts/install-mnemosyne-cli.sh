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

# github.com/newmassrael/mnemosyne @ b95b45d0 (a PUSHED origin/main rev), whose
# CLI defines CURRENT_SCHEMA_VERSION 42 and READS the schema-42 store. REQUIRED
# bump: the R311y406 store mutations (this repo's own commits, with the same
# b95b45d0 CLI locally) migrated the store 41 -> 42, and the prior pin (R311y403,
# d9e2beed) defines only schema <= 41, so its validate-workspace rejected the
# schema-42 store ("schema version mismatch: store=42 expected <= 41") — the
# Layer A red on the R311y406 hosted CI run. A reader whose max < store cannot
# lazy-migrate, so the pin must move UP to a reader that covers the store.
# b95b45d0 is PUSHED (origin/main of the mnemosyne repo, so CI `--rev` can fetch
# it) and is the exact locally-installed `--path` binary (mnemosyne-cli 0.1.0
# b95b45d0) that validated this workspace clean (orphan new=+0) all session.
MNEMOSYNE_REV="b95b45d0a8135002cd1629cc69590739043a3893"

cargo install --git https://github.com/newmassrael/mnemosyne \
  --rev "$MNEMOSYNE_REV" --bin mnemosyne-cli --force mnemosyne-cli

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

# github.com/newmassrael/mnemosyne @ R754 (2d-projection harness follow-ons)
# — the newest PUSHED rev (origin/main), whose CLI defines
# CURRENT_SCHEMA_VERSION 39. It reads the store's schema_version (38, written by
# the R748 CLI at the R311y389 append) and migrates the store up to 39 on the
# NEXT mutation, still reading it in the meantime (reader max >= store). The
# store staying one schema behind the pin is the designed lazy-migrate path, not
# a drift. The prior pin (R748, 7ec9eec) defines only schema <= 38; the author
# pushed the R749-R754 ladder (schema 38 -> 39) upstream, so the pin moves to
# R754 in step. Kept in step with the locally-installed `--path` binary
# (mnemosyne-cli 0.1.0 3bf4c8d).
MNEMOSYNE_REV="3bf4c8da195f6e81820c333cabcb270a2f37f96c"

cargo install --git https://github.com/newmassrael/mnemosyne \
  --rev "$MNEMOSYNE_REV" --bin mnemosyne-cli --force mnemosyne-cli

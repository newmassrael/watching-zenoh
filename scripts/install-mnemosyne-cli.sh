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

# github.com/newmassrael/mnemosyne @ R732 (DEBT-M entity-kind inheritance
# tree) — the rev whose CLI reads the current atomic-store schema_version
# (34) and defines CURRENT_SCHEMA_VERSION 37, so a later mutation migrates
# the store up to 37 and this same pin still reads it (reader max >= store).
# The prior pin (R730, 6871b925) defines only schema <= 35; adopting the
# R731/R732 upstream (fact_counts multiset custody + entity-kind inheritance
# tree) moved the local --path binary to R732, so the pin moves in step to
# keep local pre-push and CI on one mnemosyne version. Kept in step with the
# locally-installed `--path` binary (mnemosyne-cli 0.1.0 5807bd5).
MNEMOSYNE_REV="5807bd5cd53d4b9dea85a6560a2dfe22b02252bc"

cargo install --git https://github.com/newmassrael/mnemosyne \
  --rev "$MNEMOSYNE_REV" --bin mnemosyne-cli --force mnemosyne-cli

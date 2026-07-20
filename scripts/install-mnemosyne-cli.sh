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

# github.com/newmassrael/mnemosyne @ R730 (DEBT-K choice gate) — the rev whose
# CLI reads the current atomic-store schema_version (34). The store bumped
# 23 -> 34 when the R730 CLI appended the wz R311y376 ledger entry; the prior
# pin (R584, bb01cc6b) reads only schema <= 23, so it would hard-fail Layer A
# `schema version mismatch: store=34 expected <= 23` (the same failure class the
# even-older R415 pin hit at schema 9). Kept in step with the locally-installed
# `--path` binary (mnemosyne-cli 0.1.0 6871b925) so local pre-push and CI
# validate against the same mnemosyne version.
MNEMOSYNE_REV="6871b9256d3b35687cdb6df7145a19cd5c717ed8"

cargo install --git https://github.com/newmassrael/mnemosyne \
  --rev "$MNEMOSYNE_REV" --bin mnemosyne-cli --force mnemosyne-cli

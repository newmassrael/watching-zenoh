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

# github.com/newmassrael/mnemosyne @ d7f048b5 (a PUSHED origin/main rev), whose
# CLI defines CURRENT_SCHEMA_VERSION 43 and READS the schema-43 store.
#
# R311y417 REQUIRED bump, and the SECOND time this exact trap has fired (the
# R311y406 account it replaces is kept below). The R311y416 ledger append
# migrated the store 42 -> 43, so the prior pin b95b45d0 (max 42) rejected it:
# "schema version mismatch: store=43 expected ≤ 42" — Layer A red on run
# 30235292100, taking A2/A3/A4/B/B2 down as skipped with it. A reader whose max
# < store cannot lazy-migrate, so the pin must move UP to a reader that covers
# the store. Verified before landing: a d7f048b5 build validates this workspace
# clean (entries 1423, orphan new=+0).
#
# HOW IT FIRED, because the mechanism is what recurs: the session verified at
# kickoff that the PATH CLI (08e71f08) and the pin were both schema 42, and
# reported no trap. Correct then, stale later — the PATH binary was replaced
# mid-session by a 376c5e10-dirty build from parallel mnemosyne work carrying
# schema 43. So check `mnemosyne-cli --version` against this pin IMMEDIATELY
# BEFORE EVERY mutate, not once per session.
#
# DOCTRINE DEVIATION, disclosed: the paragraph this replaces required the pin to
# be "the exact locally-installed binary". It is not, this time. The local
# binary is 376c5e10-dirty — an uncommitted build, so unpinnable by
# construction, since CI resolves `--rev` from github. d7f048b5 is origin/main
# and carries the same CURRENT_SCHEMA_VERSION 43, which is the property that
# actually gates CI. Reinstalling the local CLI from d7f048b5 would restore the
# stricter invariant; it was left alone to avoid clobbering in-progress work.
#
# --- the R311y406 precedent this bump follows (kept verbatim) ---
# The R311y406 store mutations (this repo's own commits, with the same
# b95b45d0 CLI locally) migrated the store 41 -> 42, and the prior pin (R311y403,
# d9e2beed) defines only schema <= 41, so its validate-workspace rejected the
# schema-42 store ("schema version mismatch: store=42 expected <= 41") — the
# Layer A red on the R311y406 hosted CI run.
MNEMOSYNE_REV="d7f048b56a734790b4a9875d53b9c7c9a579e4f9"

cargo install --git https://github.com/newmassrael/mnemosyne \
  --rev "$MNEMOSYNE_REV" --bin mnemosyne-cli --force mnemosyne-cli

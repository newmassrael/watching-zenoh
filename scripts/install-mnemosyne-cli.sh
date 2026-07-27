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
#
# READ, NOT SOURCED (R311y418): scripts/lib/schema-pin-gate.sh, used by both
# .githooks/pre-commit and .githooks/pre-push, extracts BOTH constants below
# textually from a git object, with line-anchored patterns. It deliberately
# does not source this file — that would execute an installer inside a git
# hook, which the first cut of R311y418 briefly did. So each assignment must
# stay on ONE unindented line in the literal form NAME="<value>", appearing
# exactly once; the gate hard-fails on any other count rather than guessing,
# and rejects a leading zero (bash `(( ))` reads 043 as octal).

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

# The pinned rev's CURRENT_SCHEMA_VERSION: the HIGHEST atomic-store schema this
# CLI can read. Verified at the pin, not inherited from prose —
# crates/mnemosyne-atomic/src/lib.rs:1678 at d7f048b5 defines it as 43, and
# :1924 rejects `on_disk_version > CURRENT_SCHEMA_VERSION` outright. A reader
# cannot lazy-migrate DOWN to an older store shape, so a local mutate that
# migrates the store past this number reds hosted Layer A and takes
# A2/A3/A4/B/B2 with it. That has now happened FOUR times, every time
# discovered only on hosted CI — R311y15 (store=23 expected <= 9), R311y401
# (store=41 expected <= 39, repaired at y403), R311y406 (42 vs 41) and
# R311y416 (43 vs 42, repaired at y417). R311y417's carry said "twice";
# enumerating the ledger rather than inheriting that number gives four.
#
# This constant exists so the local hooks can turn that hosted red into a local
# one: scripts/lib/schema-pin-gate.sh reads the number below out of a git
# object and refuses any commit (index) or push (pushed commits) whose store
# schema_version exceeds it. MNEMOSYNE_REV and MNEMOSYNE_MAX_SCHEMA are ONE
# fact in two forms — never move the rev without re-reading
# CURRENT_SCHEMA_VERSION at the new rev and moving this with it. That pairing
# is now gated too: pre-commit refuses a ceiling that moves while the rev
# stands still, because the ceiling is the gate's ONLY oracle and raising it
# alone merely silences the gate. What is still NOT gated, and is the honest
# next step, is that the new rev's CURRENT_SCHEMA_VERSION really equals the new
# ceiling — that needs the pinned source, so it belongs in ci.yml beside the
# `cargo install --rev` below.
# shellcheck disable=SC2034  # read by .githooks/pre-commit as text, so it has
                            # no in-script use; keep the one-line literal form.
MNEMOSYNE_MAX_SCHEMA="43"

cargo install --git https://github.com/newmassrael/mnemosyne \
  --rev "$MNEMOSYNE_REV" --bin mnemosyne-cli --force mnemosyne-cli

#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R3389 (no register item) — install the toolchain rust-toolchain.toml pins and
# leave it the ONLY one on the runner, so the build cache is keyed by the
# compiler the build uses.
#
# WHAT HAPPENED. Run 39344495779: `validate + verify + test` passed every lane
# and failed its budget margin at 1715 s of 1800 s, because its cargo cache was
# a miss ("No cache found") on the key `v0-rust-ci-Linux-x64-94b53446-...` the
# run before had restored as a full match. Swatinem/rust-cache hashes into that
# key the `rustc -vV` of EVERY toolchain `rustup toolchain list` names
# (src/config.ts, getRustVersions), and the hosted image preinstalls a floating
# `stable` this tree never builds with: 1.99.0 on image 20261012, 1.99.1 on
# image 20261018. While GitHub rolled the images out, consecutive runs landed
# on different ones, so the key alternated between two environment hashes,
# `scripts/lib/cache_prune.py` removed the other image's live generation as
# superseded, and the next run on the other image compiled from cold.
#
# SO THE FIX IS THE ENVIRONMENT, NOT THE KEY. Dropping the environment hash
# (`add-rust-environment-hash-key: false`) would also drop the manifest and
# lockfile hash that input controls; a toolchain nobody uses is the thing that
# should not be there. The pinned toolchain becomes the rustup default as well,
# so a cargo invoked outside the checkout builds with the pinned compiler too
# instead of finding no toolchain at all.
#
# A job that needs a second pinned channel (zenoh's own, for the oracles)
# installs it AFTER this step, so this never removes it.
#
# Usage, from the repository root:  bash scripts/lib/rust-toolchain-pinned.sh
set -euo pipefail

# Materialises the pinned channel with its components and targets.
rustup show

pinned="$(rustup show active-toolchain)"
pinned="${pinned%% *}"
if [ -z "$pinned" ]; then
    echo "rust-toolchain-pinned: rustup named no active toolchain here" >&2
    exit 1
fi

rustup default "$pinned"
# The first field only: an older rustup annotates a name with "(default)".
while read -r toolchain _; do
    if [ -n "$toolchain" ] && [ "$toolchain" != "$pinned" ]; then
        echo "rust-toolchain-pinned: removing $toolchain (not pinned by rust-toolchain.toml)"
        rustup toolchain uninstall "$toolchain"
    fi
done < <(rustup toolchain list --quiet)

echo "rust-toolchain-pinned: the toolchains the build cache key hashes:"
rustup toolchain list

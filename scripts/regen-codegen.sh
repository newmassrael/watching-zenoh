#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# regen-codegen.sh — regenerate the committed generated Rust under out/**
# from the SCXML sources (R311y22). This is the ONLY supported way to
# refresh out/**; manual edits there are forbidden (SSoT-downstream).
#
# After editing an SCXML under sources/** (or bumping the vendor/sce pin),
# run this and commit the resulting out/** changes. The CI Layer B2
# regen-diff gate fails any push where out/** is stale vs the SCXML.
#
# Requires the codegen toolchain (the xtask pulls sce-build -> libxml2);
# install libxml2-dev (Linux) / libxml2 (macOS brew) / libxml2 vcpkg
# (Windows). Consumers building the wz stack do NOT need this — that is
# the whole point of committing out/**.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

echo "regen-codegen: regenerating out/** via xtask (codegen SSOT)"
cargo run --manifest-path xtask/Cargo.toml --quiet -- regen

echo "regen-codegen: done. Review + commit any out/** changes:"
git status --porcelain -- out/ || true

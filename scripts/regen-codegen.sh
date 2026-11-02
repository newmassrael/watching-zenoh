#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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

# The statechart/buffer-pool regen leg shells the vendored sce-codegen binary
# (the codec leg uses sce-build in-process). Ensure it is built AT THE PIN THIS
# TREE CARRIES — an existence test was not enough: a binary left over from an
# older vendor/sce rev regenerates out/** from that rev's templates, and the
# result is committed. See scripts/lib/sce-codegen-oracle.sh.
# shellcheck source=scripts/lib/sce-codegen-oracle.sh
source scripts/lib/sce-codegen-oracle.sh
sce_codegen_ensure "regen-codegen" || {
    echo "regen-codegen: refusing to regenerate — the sce-codegen oracle is not at the pinned revision" >&2
    exit 1
}

echo "regen-codegen: regenerating out/** via xtask (codegen SSOT)"
# Two stages, in this order. Stage 1 (codecs, the codec deployment, statecharts,
# pools) builds without the switchboard generator, which compiles wz-session-core
# and so the codec tree stage 1 writes; built first, it would compile the OLD
# tree against a moved SCE runtime and never get to regenerate it. Stage 2
# (switchboards) is built once the tree it compiles is the new one.
#
# `--stage1` or `--stage2` runs one stage; no argument runs both, which is what
# the bx action `regen-codegen` and the hosted regen-diff lane do. A pin move
# needs them apart: the codec tree changes shape, wz-session-core does not
# compile until its callers follow, and stage 2 cannot be built until they do.
stage="${1:-both}"
case "$stage" in
    --stage1 | --stage2 | both) ;;
    *)
        echo "regen-codegen: unknown argument '$stage' (expected --stage1, --stage2 or none)" >&2
        exit 2
        ;;
esac
if [ "$stage" != "--stage2" ]; then
    cargo run --manifest-path xtask/Cargo.toml --quiet --no-default-features -- stage1
fi
if [ "$stage" != "--stage1" ]; then
    cargo run --manifest-path xtask/Cargo.toml --quiet -- switchboards
fi

echo "regen-codegen: done. Review + commit any out/** changes:"
git status --porcelain -- out/ || true

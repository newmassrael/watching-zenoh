#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-mnemosyne-mcp.sh — install the PINNED mnemosyne-mcp for AGENT
# SESSIONS, at the same rev scripts/install-mnemosyne-cli.sh pins for CI.
#
# WHY A SECOND SCRIPT rather than a second `--bin` on the CI installer. That
# script runs in every ci.yml and release.yml job, and CI never speaks MCP —
# adding a ~50MB binary to every lane would buy nothing. But the two binaries
# must still be ONE rev: .mcp.json starts mnemosyne-mcp against the SAME
# mnemosyne.toml the pinned CLI validates, so a server older than the pin
# rejects config the CLI accepts, and the whole config is parsed at startup.
#
# THAT IS THE FAILURE THIS SCRIPT EXISTS FOR, not a hypothetical. R311y429
# adopted the citation gate, added `scan_exclusions` to mnemosyne.toml and moved
# MNEMOSYNE_REV d7f048b5 -> b867bfe2. The CLI followed, because the installer
# installs it. The MCP binary did not, because nothing installed it — it sat at
# d7f048b5 and died at startup with `unknown field scan_exclusions`. Two rounds
# of sessions then ran with the Mnemosyne concept resources unreachable, and the
# only symptom the client surfaces is `Connection closed`, which is
# indistinguishable from a server that was never configured. A drift that
# reports as an absence gets diagnosed as one.
#
# THE REV IS READ, NEVER DUPLICATED. scripts/lib/schema-pin-gate.sh is the
# single textual parser of the pin constants (the git hooks use it), and it is
# pure function definitions by contract, so sourcing it is side-effect free.
# A second copy of the hash here would be a second thing to forget — which is
# precisely the class of bug above, one level up.
#
# WHICH TREE: `HEAD:`, a git object spec, per the doctrine that file argues at
# its own :22-28 — the pin that CI resolves is the COMMITTED one, so installing
# from an uncommitted edit would produce a local binary no gate agrees with. The
# hooks already require MNEMOSYNE_REV to move in its own commit, so a bump is
# committed before anything installs from it.

set -euo pipefail

fail() {
    echo "install-mnemosyne-mcp: $*" >&2
    exit 1
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" ||
    fail "not inside a git worktree — the pinned rev is read from a git object."
cd "$repo_root"

# shellcheck disable=SC1091  # constant path, resolved at run time
if ! source scripts/lib/schema-pin-gate.sh; then
    fail "scripts/lib/schema-pin-gate.sh missing or unreadable.
  It is the single parser of MNEMOSYNE_REV; this script will not guess."
fi

if ! rev="$(wz_pin_rev 'HEAD:')"; then
    fail "cannot read MNEMOSYNE_REV from scripts/install-mnemosyne-cli.sh at HEAD
  (the parser's own diagnostic is above). Fix the pin, not this script."
fi

echo "install-mnemosyne-mcp: installing mnemosyne-mcp @ ${rev}"

# --force for the same reason the CLI installer gives: without it a stale
# ~/.cargo/bin binary wins, which is the exact shape that produced the drift
# this script closes.
cargo install --git https://github.com/newmassrael/mnemosyne \
    --rev "$rev" --bin mnemosyne-mcp --force mnemosyne-mcp

# THE ORACLE is a real MCP `initialize` handshake against THIS workspace's
# mnemosyne.toml, because the failure mode is a startup-time CONFIG parse and
# nothing cheaper observes it: the binary answers --version perfectly well while
# being unable to serve this repo.
#
# DELIBERATELY NOT a version-string match. scripts/verify-mnemosyne-pin.sh:46-55
# reasons that out for the CLI and the reasoning transfers verbatim: --version
# embeds `git describe`, so it is a bare short hash only while no tag is
# reachable upstream, and degrades to the literal `unknown` when .git is absent.
# That is a gate whose truth depends on another project's tagging policy. Serving
# this workspace depends on neither, and it is the property actually wanted.
#
# GRADING THE PAYLOAD, not the exit code. A config parse failure was measured to
# exit 1 with an empty stdout, so an exit-code check would catch today's shape —
# but a server that starts and then cannot answer exits 0, and only the response
# distinguishes it. Grade the stronger signal.
if ! command -v mnemosyne-mcp >/dev/null 2>&1; then
    fail "mnemosyne-mcp is not on PATH after the pinned install.
  Check that \$CARGO_HOME/bin is on PATH."
fi

handshake='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"install-mnemosyne-mcp","version":"0"}}}'

# 2>&1 kept OUT of the capture: the server's diagnostics belong on the terminal
# where a maintainer reads them, while `reply` must contain only the protocol
# stream it is about to be graded on.
reply="$(printf '%s\n' "$handshake" |
    timeout 60 mnemosyne-mcp --workspace "$repo_root" 2>/dev/null || true)"

if ! printf '%s' "$reply" | grep -q '"result"'; then
    printf '%s\n' "$handshake" |
        timeout 60 mnemosyne-mcp --workspace "$repo_root" >/dev/null || true
    fail "the pinned mnemosyne-mcp did not answer \`initialize\` for this
  workspace (its own diagnostic is above, if it produced one).

  The usual cause is the one this script was written for, inverted: the pin at
  HEAD is OLDER than a mnemosyne.toml field this repo now uses. Read the parse
  error, then move MNEMOSYNE_REV in scripts/install-mnemosyne-cli.sh — with
  MNEMOSYNE_MAX_SCHEMA re-read at the new rev, in its own commit.

  Do not work around this by deleting the field from mnemosyne.toml."
fi

echo "install-mnemosyne-mcp: OK — mnemosyne-mcp @ ${rev} serves ${repo_root}."

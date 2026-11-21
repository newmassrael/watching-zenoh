#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Install the cargo-mutants that Layer Cmut runs, at the version deploy/mutation_ratchet.json pins
# (docs/mutation-testing.md).
#
# The pin is the table's and not a workflow's: the table's rows count the mutants one version
# generates, and another version mutates the same code differently, so a row is comparable only
# with a run of its own version and the gate refuses outcomes of another one. This one installer
# serves the nightly workflow, a build machine (`[tools.cargo-mutants]` in bx.toml) and a person.
#
# Usage:  bash scripts/install-cargo-mutants.sh [--force]
#         PREFIX=/somewhere/bin bash scripts/install-cargo-mutants.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
table="$repo_root/deploy/mutation_ratchet.json"
prefix="${PREFIX:-$HOME/.local/bin}"
force=0
[[ "${1:-}" == "--force" ]] && force=1

# Read with a JSON parser and not a pattern, so a version written anywhere else in the table
# cannot be taken for the pin.
version="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["cargo_mutants_version"])' "$table")"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "install-cargo-mutants: $table pins no MAJOR.MINOR.PATCH version (read '$version')" >&2
    exit 1
fi

# cargo runs a subcommand as `cargo-mutants mutants <args>`, so the binary is asked the same way.
have="$("$prefix/cargo-mutants" mutants --version 2>/dev/null || true)"
if [[ "$have" == "cargo-mutants $version" && $force -eq 0 ]]; then
    echo "install-cargo-mutants: cargo-mutants $version already at $prefix/cargo-mutants"
    exit 0
fi

# Built into a scratch root and then copied, so a failed build leaves the installed binary as it
# was; `--locked` builds against the lock file the release was published with.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "install-cargo-mutants: building cargo-mutants $version"
cargo install cargo-mutants --version "$version" --locked --root "$tmp/root"
mkdir -p "$prefix"
install -m 0755 "$tmp/root/bin/cargo-mutants" "$prefix/cargo-mutants"

# Read back off the installed file, not off PATH: an older binary ahead of the prefix would
# otherwise answer for it.
installed="$("$prefix/cargo-mutants" mutants --version)"
if [[ "$installed" != "cargo-mutants $version" ]]; then
    echo "install-cargo-mutants: installed '$installed' but the pin is $version" >&2
    exit 1
fi
echo "install-cargo-mutants: cargo-mutants $version installed at $prefix/cargo-mutants"

on_path="$(command -v cargo-mutants 2>/dev/null || true)"
if [[ "$on_path" != "$prefix/cargo-mutants" ]]; then
    echo "install-cargo-mutants: NOTE -- PATH finds '${on_path:-no cargo-mutants}' first;" \
        "put $prefix ahead of it, or Layer Cmut refuses the version it finds."
fi

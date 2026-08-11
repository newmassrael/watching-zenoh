#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y710 — install the shellcheck THIS REPO'S CI installs, on a developer's
# machine.
#
# ## Why this exists, measured
#
# R311y707 cost a round to a hosted red that had been sitting in `Layer 0` for
# four rounds: the developer's apt shellcheck is 0.9.0, the runner's is 0.11.0,
# and 0.9.0 emits SC2317 on every dispatch-invoked function in `run-ci.sh` while
# 0.11.0 does not. A lane that is permanently red locally is a lane nobody reads,
# and a real SC2043 sat inside that noise until CI found it.
#
# That round SUPPRESSED the difference with a file-scoped directive, and said in
# its own carry that suppressing is not closing: two versions will disagree again
# the next time they differ about a code this file does not name. This closes it
# instead. With the pinned binary on PATH, "local Layer 0 pass" means "hosted
# Layer 0 pass" -- which is the only thing that makes running the lane every
# round worth doing.
#
# ## Where the version comes from
#
# `.github/workflows/ci.yml`, parsed. ONE fact in ONE place: the workflow is what
# actually installs the binary CI uses, so a pin recorded anywhere else could
# drift from it silently -- and a drifted local pin is worse than none, because it
# looks like agreement. The same reasoning `install-mnemosyne-mcp.sh` follows for
# `MNEMOSYNE_REV`.
#
# Usage:  bash scripts/install-shellcheck.sh [--force]
#         PREFIX=/somewhere/bin bash scripts/install-shellcheck.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow="$repo_root/.github/workflows/ci.yml"
prefix="${PREFIX:-$HOME/.local/bin}"
force=0
[[ "${1:-}" == "--force" ]] && force=1

if [[ ! -f "$workflow" ]]; then
    echo "install-shellcheck: $workflow not found" >&2
    exit 1
fi

# The two `env:` keys the workflow's install step declares. Anchored to the key
# so a version string appearing in prose cannot be read as the pin.
version="$(grep -oE '^\s*SHELLCHECK_VERSION:\s*"[^"]+"' "$workflow" |
    head -1 | grep -oE '"[^"]+"' | tr -d '"')"
sha256="$(grep -oE '^\s*SHELLCHECK_SHA256:\s*"[^"]+"' "$workflow" |
    head -1 | grep -oE '"[^"]+"' | tr -d '"')"

# A parse that came back empty is a FAILURE, not a default. An installer that
# guessed a version would produce exactly the silent disagreement it exists to
# end.
if [[ -z "$version" || -z "$sha256" ]]; then
    echo "install-shellcheck: could not read SHELLCHECK_VERSION / SHELLCHECK_SHA256" >&2
    echo "  from $workflow -- the workflow's install step is the pin's SSOT" >&2
    exit 1
fi

have="$(shellcheck --version 2>/dev/null | awk '/^version:/ {print $2}')"
if [[ "$have" == "$version" && $force -eq 0 ]]; then
    echo "install-shellcheck: shellcheck $version already on PATH ($(command -v shellcheck))"
    exit 0
fi

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) asset="linux.x86_64" ;;
    Linux/aarch64 | Linux/arm64) asset="linux.aarch64" ;;
    Darwin/x86_64) asset="darwin.x86_64" ;;
    Darwin/arm64) asset="darwin.aarch64" ;;
    *)
        echo "install-shellcheck: no pinned asset for $(uname -s)/$(uname -m)" >&2
        exit 1
        ;;
esac

# The checksum in the workflow is for the LINUX X86_64 tarball, because that is
# the only asset CI downloads. On any other host the download is still pinned by
# VERSION and the checksum is skipped rather than checked against the wrong file
# -- stated here because a verification that silently did not happen is the
# failure mode this script is otherwise built to avoid.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
tgz="shellcheck-v${version}.${asset}.tar.gz"
url="https://github.com/koalaman/shellcheck/releases/download/v${version}/${tgz}"

echo "install-shellcheck: fetching shellcheck $version ($asset)"
curl -sSLf --retry 3 --retry-all-errors --retry-delay 2 \
    --connect-timeout 10 --max-time 180 -o "$tmp/$tgz" "$url"

if [[ "$asset" == "linux.x86_64" ]]; then
    echo "${sha256}  $tmp/$tgz" | sha256sum -c - >/dev/null
    echo "install-shellcheck: checksum matches the workflow's pin"
else
    echo "install-shellcheck: WARNING -- the workflow pins a checksum for" \
        "linux.x86_64 only, so this $asset download is version-pinned and" \
        "NOT checksum-verified"
fi

tar xzf "$tmp/$tgz" -C "$tmp" "shellcheck-v${version}/shellcheck"
mkdir -p "$prefix"
install -m 0755 "$tmp/shellcheck-v${version}/shellcheck" "$prefix/shellcheck"

# Read the version back OFF THE INSTALLED FILE rather than off PATH: an older
# binary sitting ahead of `$prefix` would otherwise let this report success while
# the lane keeps running that one.
#
# (The line above deliberately does not begin with the tool's own name. A comment
# whose first word is that name is parsed as a DIRECTIVE, and this script's first
# draft failed its own lint with SC1073 for exactly that.)
installed="$("$prefix/shellcheck" --version | awk '/^version:/ {print $2}')"
if [[ "$installed" != "$version" ]]; then
    echo "install-shellcheck: installed $installed but the pin is $version" >&2
    exit 1
fi
echo "install-shellcheck: shellcheck $version installed at $prefix/shellcheck"

on_path="$(command -v shellcheck 2>/dev/null || true)"
if [[ "$on_path" != "$prefix/shellcheck" ]]; then
    echo "install-shellcheck: NOTE -- '$on_path' still shadows it on PATH." \
        "Put $prefix ahead of it, or Layer 0 keeps running the other one."
fi

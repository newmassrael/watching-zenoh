#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y793 (no register item) — expand a set of crate names to include every
# workspace crate whose DOCS LINK INTO one of them. Prints the union, one crate
# per line, sorted. The debt it closes was opened by y792 and lives outside the
# store's `debt-` register, so there is no id to cite here.
#
# WHY. R311y792 gave the pre-push hook a doc-link gate over the crates a push
# CHANGES. That leaves the case the changed crate is the TARGET rather than the
# author: a public item renamed in `wz-session-core` breaks
# `[wz_session_core::Foo]` wherever it is written, and those files are in crates
# the push never touched, so the gate measures the one crate that is still fine.
#
# IT IS NOT HYPOTHETICAL. Measured across crates/: 98 files carry a cross-crate
# intra-doc link, ~250 sites, and `wz_session_core::` alone accounts for 149 of
# them across fifteen crates. That is the single most-linked target in the
# workspace and also the one most rounds touch.
#
# WHY GREP AND NOT THE DEPENDENCY GRAPH. Reverse cargo dependencies of
# wz-session-core are very nearly the whole workspace, and almost none of those
# edges carry a doc link. The link TEXT is the exact population that can break,
# it is cheap to find, and it over-approximates only by the handful of files
# that name a crate in a link and depend on it anyway.
#
# COST, measured: the full C1bz lane is ~112s warm and a two-crate subset ~5s,
# so a per-crate `cargo doc` is a few seconds. The worst expansion here
# (wz-session-core -> 16 crates) is therefore ~40s, which is bounded and well
# under the `cargo test -p` this hook already pays for.
#
# USAGE
#   doclink-dependents.sh <crate-name>...
#
# A name that is not a workspace member is passed through unchanged rather than
# refused: the caller (the hook) has its own crate-set discipline, and the lane
# that consumes this output refuses an unknown name for real.

set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "doclink-dependents: usage: $0 <crate-name>..." >&2
    exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

out=""
for crate in "$@"; do
    out="${out}${crate}"$'\n'
    # The module path is the crate name with dashes as underscores. Both link
    # spellings occur in this tree -- ``[`wz_x::Y`]`` and ``[wz_x::Y]`` -- and
    # the optional backtick is why this is one pattern rather than two.
    module="${crate//-/_}"
    while IFS= read -r hit; do
        [[ -n "$hit" ]] || continue
        out="${out}${hit}"$'\n'
    done < <(
        grep -rlE "\[\`?${module}::" --include='*.rs' crates/ 2>/dev/null |
            sed -nE 's#^crates/([^/]+)/.*#\1#p' |
            sort -u
    )
done

printf '%s' "$out" | sort -u | grep -v '^$' || true

#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# audit-mid-values.sh — repo-side gate that rejects any wz envelope
# codec SCXML whose `<sce:flag name="mid">` declaration is missing
# the `value="..."` attribute.
#
# Motivation (R111, post-R108a): in R108a we discovered that
# request.scxml had been authored at R90 without a `value=` attribute
# on its envelope-level mid flag. The codegen emitted `Default::default()`
# with header byte 0x40 (M flag only, no MID nibble) which would have
# produced an unparseable wire on every freshly-built Request. The
# defect went unnoticed across 5+ rounds because no Layer 3 wire-
# interop test covered REQUEST until R108b — pure round-trip on the
# wz side was self-consistent but wrong-against-pico.
#
# Rule enforced:
#   For every sources/codecs/*.scxml, every `<sce:flag name="mid" ...>`
#   declaration that appears OUTSIDE a `<sce:peek-byte>...</sce:peek-byte>`
#   block must carry a `value="..."` attribute.
#
#   `<sce:peek-byte>` blocks intentionally declare mid without
#   `value=` — they are read-only field references inside a variant's
#   tag picker, not envelope wire-MID carriers. Stripping these blocks
#   before the audit is the entire reason the script is bash + sed
#   rather than a grep one-liner.
#
# Exit codes:
#   0 — all files clean
#   1 — at least one envelope-level mid missing `value=`
#   2 — sources/codecs/ not found (likely run from wrong directory)
#
# Invocation:
#   bash scripts/audit-mid-values.sh
#
# Wired into scripts/run-ci.sh as a Layer A2 sub-gate so the rule
# runs in every local CI sweep (alongside cargo fmt / clippy / etc.).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SOURCES_DIR="$REPO_ROOT/sources/codecs"

if [ ! -d "$SOURCES_DIR" ]; then
    printf 'audit-mid-values: sources/codecs not found at %s\n' \
        "$SOURCES_DIR" >&2
    exit 2
fi

violations=0
files_scanned=0

for scxml in "$SOURCES_DIR"/*.scxml; do
    [ -f "$scxml" ] || continue
    files_scanned=$((files_scanned + 1))

    # Strip every <sce:peek-byte ...> ... </sce:peek-byte> block,
    # leaving only the envelope-level <sce:flags> declarations.
    # Then look for `name="mid"` lines that lack a `value=` attribute
    # on the same line. Preserve the original line number for the
    # diagnostic (sed's `=` command emits it before the matching line).
    bad="$(sed '/<sce:peek-byte/,/<\/sce:peek-byte>/d' "$scxml" \
        | grep -n 'name="mid"' \
        | grep -v 'value=' \
        || true)"

    if [ -n "$bad" ]; then
        printf '%s:\n' "$scxml" >&2
        printf '%s\n' "$bad" | sed 's/^/  /' >&2
        violations=$((violations + 1))
    fi
done

if [ "$violations" -ne 0 ]; then
    printf 'audit-mid-values: %d file(s) have envelope mid declarations without value=\n' \
        "$violations" >&2
    printf 'audit-mid-values: see R108a (request mid value= defect) for the precedent\n' >&2
    exit 1
fi

printf 'audit-mid-values: %d file(s) clean — every envelope mid carries value=\n' \
    "$files_scanned"
exit 0

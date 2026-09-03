#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R2326 (no register item)
#
# The PROVENANCE STAMP, as one implementation shared by every provisioner that
# builds a FOREIGN ORACLE into this tree's `target/`.
#
# The citation is `no register item` in the sense `debt_plane_census.py` uses:
# the item this answers for -- unregistered open-debt item 10 -- lives in the
# agent-memory register, which has no store id to resolve. The item is named in
# prose below.
#
# ## What item 10 said, and what re-measuring it found
#
# Item 10: "nobody measures a foreign oracle's staleness -- `zenohd_binary` /
# `zenoh_pico_cli_binary` just pick the file up if it exists; the comparison
# target is not a wz source but the VENDORED SUBMODULE's HEAD."
#
# Half of that is no longer true. R2240 built `scripts/lib/oracle_pin_gate.py`
# for the zenohd family: it derives its population from `build-zenohd.sh`'s own
# `INSTALL_DIR=` assignments, reads each binary's `--version`, and reds a binary
# that answers with anything but the pinned release. That is a STRONGER axis
# than the one item 10 prescribed -- the binary's own answer rather than a claim
# about it -- so the zenohd half is closed and this file does not touch it.
#
# The half that survived is the one whose oracles CANNOT answer. MEASURED:
# `strings target/zenoh-pico-cli/z_put | grep -E '^[0-9]+\.[0-9]+\.[0-9]+'`
# returns nothing, `readelf -d target/zenoh-pico-build/lib/libzenohpico.so`
# reports the unversioned soname `libzenohpico.so`, and the submodule those were
# built from is at `1.9.0-10-g3b3ab65c` -- a state no release number names. A
# binary that cannot state its own provenance has to be given a record of it,
# which is what a stamp is.
#
# ## Why not mtime
#
# `scripts/lib/sce-codegen-oracle.sh` argued this out for `vendor/sce` in R1994
# and the argument transfers unchanged: mtime answers *when* a file was written,
# never *what from*. Move a submodule pin BACKWARDS -- a rebase, a revert, a
# branch switch -- and a binary built yesterday is "newer" than a pin committed
# last week, so the stale binary passes; any copy that resets mtimes (rsync,
# tar, a fresh container layer) defeats it the same way. `bx` rsyncs this tree
# to build hosts without `-t`, so mtimes there are TRANSFER times, which makes
# the defeat the normal case here rather than the exotic one.
#
# ## Why this file exists rather than a second copy of that one
#
# The token construction is identical for every git checkout, and R1994 already
# wrote it twice on purpose -- once in shell and once in Rust
# (`crates/wz-codegen-build/src/lib.rs`) -- because the two languages must
# produce byte-identical strings. A THIRD copy for zenoh-pico would be the
# open-debt item 47 shape: one fact in several places with nothing measuring the
# gap. So the primitives live here, `sce-codegen-oracle.sh` delegates to them
# with its public names unchanged, and the zenoh-pico provisioner is a second
# CALLER rather than a second implementation.
#
# ## The two token kinds, and why both are here
#
# Not every foreign oracle comes from a submodule. `install-mbedtls.sh`
# provisions a PINNED RELEASE TARBALL, so its source state is a version string
# and not a git rev -- there is no checkout to ask. Both kinds answer the same
# question ("which source state produced what is installed here"), both are
# compared as STRINGS with no clock involved, and both are written by the same
# `vendored_oracle_stamp_root`, so a consumer reads one file in one shape
# whatever provisioned the root. A separate mechanism per kind would have been a
# second convention for one question.
#
# ## The stamp's LOCATION is a convention, deliberately
#
# `<oracle root>/.wz-oracle.pin`, one filename, at the root of the output
# directory a resolver names. That is what lets
# `scripts/lib/oracle_provenance_gate.py` DERIVE coverage instead of being told
# it: the gate reads the resolver layer for `target/<root>` sites, finds the
# script that assigns each root, and requires that script to stamp it. A
# per-oracle filename would have made the coverage question unanswerable without
# a hand-written table, which is the escape hatch this workspace's rule (6)
# forbids.
#
# `vendor/sce` keeps its own `.sce-codegen.pin` and is deliberately NOT migrated:
# its output lives at `vendor/sce/target/release/`, outside this tree's
# `target/`, so it is not in that gate's population, and renaming its stamp
# would invalidate every stamp already written and force a rebuild of the
# codegen oracle on every host for no gain.
#
# This file is PURE FUNCTION DEFINITIONS. Sourcing it must stay side-effect
# free -- run-ci.sh and the provisioner scripts source it, and a sourced file
# that builds is how a wrapper starts compiling before it has parsed its
# arguments. Do not add top-level statements beyond these constants.

# The one stamp filename. Read by `oracle_provenance_gate.py` (which parses it
# out of THIS assignment rather than carrying a copy) and by the Rust consumer
# in `crates/wz-integration-tests/src/lib.rs`.
WZ_ORACLE_STAMP_NAME=".wz-oracle.pin"

# vendored_oracle_git_token <checkout-dir>
#
# Print the token identifying the git source state a build from `<checkout-dir>`
# would consume, or print nothing and return 1 when it cannot be established
# (no checkout, no git).
#
# The token is `<full-rev>-<dirty-digest>`, not the rev alone, because a
# vendored submodule is a WORKING checkout: an uncommitted edit changes what the
# binary must be while HEAD stays put. When the checkout is clean the digest is
# the digest of empty input (`e69de29b…`, git's empty blob) and the token is
# stable across machines.
#
# The dirty digest folds BOTH the untracked/modified listing and the tracked
# diff, for the same reason bx's tree fingerprint does: `git status --porcelain`
# alone cannot see a change that leaves the path list identical, and `git diff`
# alone cannot see a new untracked source file.
#
# The digest is computed by `git hash-object`, deliberately, and not by md5sum
# or sha256sum. GIT IS THE ONLY DEPENDENCY THIS TOKEN HAS, which is what lets
# the Rust side recompute the identical string with two subprocess calls and no
# hashing crate. A token only one language can compute is a token the other
# language has to trust, and the whole point here is that nothing trusts the
# binary's own claim about itself.
#
# `target/` IS EXCLUDED, and that is load-bearing rather than tidiness. The
# token must describe the SOURCE state that determines the binary; a checkout's
# `target/` holds build output. Include it and, for any oracle whose stamp lands
# inside the checkout, the record changes the thing it records -- writing the
# stamp makes the checkout dirty, which moves the token, so the stamp can never
# match and every consumer rebuilds forever. That today's `vendor/zenoh-pico`
# and `vendor/sce` both gitignore `target/` is a fact about upstream's
# .gitignore, not a property of this token, and it is not something to depend
# on.
vendored_oracle_git_token() {
    local dir="$1"
    [[ -n "$dir" ]] || return 1
    [[ -e "$dir/.git" ]] || return 1
    command -v git >/dev/null 2>&1 || return 1

    local rev
    rev="$(git -C "$dir" rev-parse HEAD 2>/dev/null)" || return 1
    [[ -n "$rev" ]] || return 1

    local digest
    digest="$( { git -C "$dir" status --porcelain -- . ':(exclude)target' 2>/dev/null | LC_ALL=C sort
                 git -C "$dir" diff HEAD -- . ':(exclude)target' 2>/dev/null; } \
               | git hash-object --stdin 2>/dev/null)" || return 1
    [[ -n "$digest" ]] || return 1

    printf '%s-%s\n' "$rev" "$digest"
}

# vendored_oracle_stamp_path <oracle-root>
#
# Where the stamp for an oracle output root lives. One place computes this so
# the provisioner, the gate and the Rust consumer cannot drift.
vendored_oracle_stamp_path() {
    printf '%s/%s\n' "${1%/}" "$WZ_ORACLE_STAMP_NAME"
}

# vendored_oracle_stamped_token <stamp-path>
#
# Print the token the installed artefacts carry, or nothing and return 1 when
# the root is unstamped. An unstamped root is UNKNOWN provenance, which is not
# the same verdict as a mismatching one and is reported separately by every
# consumer here: a mismatch is a stale oracle, while unstamped is an oracle
# provisioned before this gate existed. Both are refused where the oracle is
# REQUIRED; only the mismatch is refused unconditionally, because on the day
# this lands every root in every developer tree is unstamped and turning that
# into a hard failure would red every pico lane on every host at once for a
# question the tree cannot yet answer.
vendored_oracle_stamped_token() {
    local stamp="$1"
    [[ -r "$stamp" ]] || return 1
    local token
    read -r token <"$stamp" || return 1
    [[ -n "$token" ]] || return 1
    printf '%s\n' "$token"
}

# vendored_oracle_write_stamp <stamp-path> <token>
#
# Record the source state a just-completed provisioning consumed. Callers must
# invoke this AFTER the build or install reports success -- never before, so a
# failed run cannot leave behind a stamp asserting freshness it does not have.
#
# An EMPTY token removes the stamp rather than writing a blank one: "we could
# not establish what this was built from" must read as unstamped, not as a token
# that matches nothing in a way a later reader has to guess about.
vendored_oracle_write_stamp() {
    local stamp="$1" token="$2"
    if [[ -z "$token" ]]; then
        rm -f "$stamp" 2>/dev/null || true
        return 0
    fi
    printf '%s\n' "$token" >"$stamp"
}

# vendored_oracle_stamp_root <oracle-root> <token>
#
# The convention-located form: stamp the root a resolver names. This is the
# entry point `oracle_provenance_gate.py` derives coverage from, so a
# provisioner that stamps its root any other way is not covered -- deliberately,
# because a stamp the gate cannot find is a stamp no consumer can rely on.
#
# A root that does not exist is not stamped and not an error: the provisioner
# may legitimately have produced nothing (an idempotent no-op run against an
# already-removed prefix), and inventing a directory to hold a stamp would be a
# provisioning side effect from a recording function.
vendored_oracle_stamp_root() {
    local root="$1" token="$2"
    [[ -d "$root" ]] || return 0
    vendored_oracle_write_stamp "$(vendored_oracle_stamp_path "$root")" "$token"
}

# vendored_oracle_verdict <oracle-root> <want-token>
#
# Print one of `MATCH` / `STALE <have>` / `UNSTAMPED`, and return 0 / 1 / 2.
# Shared by the shell consumers so the three states are spelled once; the Rust
# consumer carries the same trichotomy for the same reason.
vendored_oracle_verdict() {
    local root="$1" want="$2"
    local have
    if ! have="$(vendored_oracle_stamped_token "$(vendored_oracle_stamp_path "$root")")"; then
        printf 'UNSTAMPED\n'
        return 2
    fi
    if [[ "$have" == "$want" ]]; then
        printf 'MATCH\n'
        return 0
    fi
    printf 'STALE %s\n' "$have"
    return 1
}

#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R1994 (debt-sce-codegen-provenance)
#
# The sce-codegen ORACLE gate — shared by every shell consumer of
# `vendor/sce/target/release/sce-codegen`.
#
# It ANSWERS FOR that item without closing it: the sce-codegen instance is
# closed and gated here, and the item stays open for the untracked oracles that
# still carry no provenance record at all (`target/zenohd`,
# `target/zenoh-pico-cli`, the capture fixtures) and for
# `binary_freshness_lint.py`, which grades the sibling class by mtime — the same
# wrong question one layer over.
#
# ## What it grades
#
# WHICH vendor/sce revision the built binary was built FROM — not whether it
# exists, and not when it was built. Both of those were asked before, and both
# gave wrong answers:
#
#   EXISTENCE.  Layer B and Layer B2 each opened with `[[ ! -x <bin> ]] && SKIP`.
#   A lane whose oracle is an untracked build product therefore reports a
#   pass-shaped SKIP on any host that does not carry it. `bx` prunes
#   `vendor/sce/target` after every remote run, so that host is the normal case,
#   not the exotic one.
#
#   MTIME.  R114 added a real freshness gate after a green local pre-push went
#   red on hosted CI (msg_del/query/request mismatches traced to a binary built
#   against the pre-R112 pin). It compares the binary's mtime to the pin
#   commit's author time and rebuilds when the binary is older. That gate is
#   correct in the developer loop it was written for and wrong in general:
#   mtime answers *when* the binary was built, never *what from*. Move the pin
#   BACKWARDS — a rebase, a cherry-pick, a revert to an older SCE revision —
#   and a binary built yesterday is "newer" than a pin committed last week, so
#   the stale binary passes. Any copy that resets mtimes (rsync, tar, a fresh
#   container layer) defeats it the same way.
#
#   It also lived in ONE lane. Layer B2's own comment outsourced the question —
#   "In a full run-ci, Layer B builds + freshness-checks the binary before this
#   lane" — which holds for a full sweep and for nothing else. `--layer B2`
#   alone had no check at all.
#
# ## The measured failure this replaces
#
# 2026-08-22, this round. The SCE pin moved 0ac56f1a45 -> 6399fad49c, whose
# templates introduce a `host_invoker` filter. `--layer B2` ran on a build host
# carrying a binary from an older pin and failed with
#
#     unknown filter: filter host_invoker is unknown (in entry_exit_actions.rs.jinja2:462)
#
# which names a template, a filter and a line number, and not one of them is the
# defect. The tree was fine; the oracle was from a different tree. The sibling
# class is already written down at scripts/lib/binary_freshness_lint.py: R311y774
# tested a feature against a demo binary predating it and attributed the red to a
# feature-closure defect that did not exist, and R311y776 retracted the whole
# diagnosis. A stale oracle does not report "stale" — it reports a plausible
# wrong answer somewhere else.
#
# ## The provenance stamp
#
# `scripts/build-sce.sh` writes `<bin dir>/.sce-codegen.pin` after a SUCCESSFUL
# build, holding the exact source state it built from. Consumers recompute that
# same token from the tree and compare STRINGS. No clock is involved, so none of
# the mtime defeats above apply.
#
# The token is `<full-rev>-<dirty-digest>`, not the rev alone, because
# `vendor/sce` is a working checkout: an uncommitted template edit changes what
# the binary must be, while HEAD stays put. When the checkout is clean the digest
# is the digest of empty input and the token is stable across machines.
#
# ## Arming
#
# `WZ_SCE_ORACLE_REQUIRE=1` turns "cannot establish the oracle" from a SKIP into
# a hard failure. Hosted CI arms it: there the submodule and the toolchain are
# always present, so an unavailable oracle is a broken runner rather than a
# developer without libxml2. This mirrors the WZ_*_REQUIRE convention Layers D
# and F already use for python3.
#
# ## The store
#
# A build in one checkout served that checkout alone, so a new worktree, or a
# copy a build machine made of the tree, built the oracle again from nothing,
# one core for most of an hour, at a pin another tree of the same machine had
# built already. So `scripts/build-sce.sh` also keeps the build of a CLEAN
# source state in the machine's oracle store (the one
# `scripts/lib/oracle_store.py` keeps zenohd in), at
#
#     <store>/sce-codegen/<rev>-<dirty digest>-<recipe digest>-<toolchain>/
#
# whose name is everything that decides the binary: the source token below, the
# digest of `scripts/build-sce.sh` (its cargo command and features), and the
# channel of the wz toolchain it builds with. Every consumer asks
# `sce_codegen_binary`, which takes the entry for the tree's state when it holds
# a build and the checkout's build otherwise; the Rust door decides the same way
# (`wz_codegen_build::sce_codegen_build`). The entry carries the same stamp, and
# a consumer compares it with the token it computes from the tree, so the rule
# above holds in both places. The entry's files are renamed into place, the
# stamp last, so a reader never takes a half-written one, and a lock beside each
# entry lets one build of it run at a time. A source state with changes of its
# own is built in its checkout only: no other tree holds it.
#
# This file is PURE FUNCTION DEFINITIONS. Sourcing it must stay side-effect
# free — run-ci.sh and the wrapper scripts source it, and a sourced file that
# builds is how a wrapper starts compiling before it has parsed its arguments.
# Do not add top-level statements beyond these constants.
#
# R2326 (unregistered open-debt item 10) — the token construction moved to
# `scripts/lib/vendored-oracle.sh` when zenoh-pico became a second oracle
# needing the identical string. This file keeps its three public names and
# delegates: a second implementation of one token is the open-debt item 47
# shape, and the Rust side already has to reproduce it byte for byte, which is
# copy number two and the ceiling.
# shellcheck source=scripts/lib/vendored-oracle.sh
source "$(dirname "${BASH_SOURCE[0]}")/vendored-oracle.sh"
# `wz_artifact_dir`: where a product of a tree path is (the rule, scripts/lib/artifact-root.sh).
# shellcheck source=scripts/lib/artifact-root.sh
source "$(dirname "${BASH_SOURCE[0]}")/artifact-root.sh"
# `wz_build_evidence`: what a failed rebuild prints (scripts/lib/build-evidence.sh).
# shellcheck source=scripts/lib/build-evidence.sh
source "$(dirname "${BASH_SOURCE[0]}")/build-evidence.sh"

WZ_SCE_DIR="vendor/sce"
# Where the CHECKOUT's build and its stamp are is the artifact-root rule's answer for vendor/sce,
# the place scripts/build-sce.sh's cargo writes them (it runs under the root's shim) and both doors
# read them when the store holds no build of the tree's state (`sce_codegen_binary` below, and
# `wz_codegen_build::sce_codegen_build`). This was the literal
# `vendor/sce/target/release` until 2026-11-19: under a WZ_ARTIFACT_ROOT the gate read a binary
# and a stamp the build never wrote, so `sce_codegen_ensure` rebuilt on every call and refused
# after each rebuild, and verify-codegen ran whatever was left in the checkout. Absolute, so a
# caller does not prefix it with its root.
WZ_SCE_CODEGEN_BIN="$(wz_artifact_dir "$_wz_ar_checkout_l/vendor/sce")/target/release/sce-codegen"
WZ_SCE_CODEGEN_STAMP="$(wz_artifact_dir "$_wz_ar_checkout_l/vendor/sce")/target/release/.sce-codegen.pin"
# The recipe whose digest is part of a store entry's name: what build-sce.sh makes of the checkout
# (its cargo command, the features, the toolchain rule) is this file's text, so an edit to it is
# another binary. The Rust door reads the same file (`wz_codegen_build::SCE_CODEGEN_RECIPE`).
WZ_SCE_CODEGEN_RECIPE="$_wz_ar_checkout_l/scripts/build-sce.sh"
# How long a store entry no consumer took is kept: the window scripts/lib/oracle_store.py keeps a
# zenohd product of another recipe for. One entry is made per SCE pin, recipe and toolchain, so a
# store without a window grows by a binary at every move of the pin.
WZ_SCE_CODEGEN_STORE_DAYS=14
# What sce-codegen prints on stderr when it parsed a document without validating
# it. The Rust door carries the same text (XSD_NOT_VALIDATED in
# crates/wz-codegen-build/src/spawn.rs); scripts/lib/sce_codegen_spawn_lint.py
# holds the two and the generator's own wording to one another.
WZ_SCE_XSD_NOT_VALIDATED="XSD schema validation did not run"

# sce_codegen_spawn <binary> <sce-dir> <stderr-file> <arg>...
#
# THE ONE SHELL DOOR THROUGH WHICH THIS TREE RUNS sce-codegen; the Rust door is
# `SceCodegen` in crates/wz-codegen-build. sce-codegen finds its workspace, its
# Jinja2 templates and its XSD schemas by looking around the machine when it is
# not told, and each guess has missed on some build host while the tree passed
# where it was written. So all three are named here, derived from <sce-dir>, and
# scripts/lib/sce_codegen_spawn_lint.py refuses a spawn written anywhere else.
# A caller that sets SCE_TEMPLATE_DIR or SCE_SCHEMAS_DIR still points elsewhere;
# an empty value counts as unset, as it does in the Rust door.
#
# The XSD half is why this returns codes of its own. When the schema is missing,
# or the binary was built without the `xsd` feature, sce-codegen warns, emits
# from a document whose sce: attributes nobody checked, and exits 0. A warning
# in a log is not a verdict, so that run is refused here.
#
# Standard output is the caller's; standard error goes to <stderr-file>, which
# also receives the reason for a refusal.
#
#   n    sce-codegen's own exit status, when it ran and failed
#   0    it ran, succeeded and validated
#   125  refused before running: the template directory or the schema is not
#        where it is named
#   126  it exited 0 but said that XSD validation did not run
sce_codegen_spawn() {
    local bin="$1" sce="$2" errf="$3"
    shift 3
    local templates="${SCE_TEMPLATE_DIR:-$sce/tools/codegen/templates}"
    local schemas="${SCE_SCHEMAS_DIR:-$sce/schemas}"
    if [[ ! -d "$templates" ]]; then
        echo "sce_codegen_spawn: no template directory at $templates" >"$errf"
        return 125
    fi
    if [[ ! -f "$schemas/sce-forge.xsd" ]]; then
        echo "sce_codegen_spawn: no XSD schema at $schemas/sce-forge.xsd; sce-codegen would emit without validating" >"$errf"
        return 125
    fi
    local rc=0
    SCE_TEMPLATE_DIR="$templates" SCE_SCHEMAS_DIR="$schemas" \
        "$bin" --workspace-root "$sce" "$@" 2>"$errf" || rc=$?
    if [[ $rc -eq 0 ]] && grep -qF "$WZ_SCE_XSD_NOT_VALIDATED" "$errf"; then
        echo "sce_codegen_spawn: sce-codegen exited 0 without validating against the XSD" >>"$errf"
        return 126
    fi
    return "$rc"
}

# sce_codegen_source_token <sce-dir>
#
# Print the token identifying the SCE source state a build would consume, or
# print nothing and return 1 when it cannot be established (no checkout, no git).
#
# The dirty digest folds BOTH the untracked/modified listing and the tracked
# diff, for the same reason bx's tree fingerprint does: `git status --porcelain`
# alone cannot see a change that leaves the path list identical, and `git diff`
# alone cannot see a new untracked template.
#
# The digest is computed by `git hash-object`, deliberately, and not by md5sum
# or sha256sum. GIT IS THE ONLY DEPENDENCY THIS TOKEN HAS, which is what lets
# the Rust side (crates/wz-codegen-build) recompute the identical string with
# two subprocess calls and no hashing crate. A token only one language can
# compute is a token the other language has to trust, and the whole point here
# is that nothing trusts the binary's own claim about itself.
#
# `target/` IS EXCLUDED, and that is load-bearing rather than tidiness. The
# token must describe the SOURCE state that determines the binary; `target/`
# holds the binary and the stamp itself. Include it and the record changes the
# thing it records — writing the stamp makes the checkout dirty, which moves the
# token, so the stamp can never match and every consumer rebuilds or refuses
# forever. MEASURED: crates/wz-codegen-build/tests/provenance.rs caught exactly
# this, on a fixture whose `target/` was not gitignored. That today's
# vendor/sce happens to ignore `target/` is a fact about upstream's .gitignore,
# not a property of this gate, and it is not something to depend on.
sce_codegen_source_token() {
    vendored_oracle_git_token "${1:-$WZ_SCE_DIR}"
}

# sce_codegen_stamped_token [stamp-path]
#
# Print the token the built binary carries, or nothing when unstamped. An
# unstamped binary is treated as UNKNOWN provenance and therefore as stale:
# every binary this repo builds has been stamped since this file landed, so an
# unstamped one predates the gate and is exactly the case it exists to catch.
sce_codegen_stamped_token() {
    vendored_oracle_stamped_token "${1:-$WZ_SCE_CODEGEN_STAMP}"
}

# sce_codegen_write_stamp <sce-dir> <stamp-path>
#
# Record the source state a just-completed build consumed. Called by
# build-sce.sh AFTER cargo reports success — never before, so a failed build
# cannot leave behind a stamp asserting freshness it does not have.
sce_codegen_write_stamp() {
    local dir="$1" stamp="$2"
    # No git to read: leave the binary UNSTAMPED rather than stamp it with a
    # guess — which is what an empty token asks the writer to do. Unstamped
    # reads as stale, which is the safe direction.
    vendored_oracle_write_stamp "$stamp" "$(sce_codegen_source_token "$dir" || true)"
}

# sce_codegen_store_root
#
# The machine's oracle store: WZ_ORACLE_STORE, else $XDG_CACHE_HOME/watching-zenoh/oracles, else
# $HOME/.cache/watching-zenoh/oracles -- the order `store_root` in scripts/lib/oracle_store.py
# reads them in, and the Rust door's (`wz_codegen_build::oracle_store_root`). A value that is
# empty or relative is passed over, as the XDG rule says of its variables: a relative one names
# another place from every directory a consumer runs in. Nothing, and 1, when none is left.
sce_codegen_store_root() {
    if [[ "${WZ_ORACLE_STORE:-}" == /* ]]; then
        printf '%s\n' "$WZ_ORACLE_STORE"
    elif [[ "${XDG_CACHE_HOME:-}" == /* ]]; then
        printf '%s/watching-zenoh/oracles\n' "${XDG_CACHE_HOME%/}"
    elif [[ "${HOME:-}" == /* ]]; then
        printf '%s/.cache/watching-zenoh/oracles\n' "${HOME%/}"
    else
        return 1
    fi
}

# sce_codegen_toolchain [<checkout>]
#
# The toolchain the checkout's rust-toolchain.toml names, which build-sce.sh builds with: the name
# on the first line that is exactly `channel = "<name>"`. Nothing, and 1, when there is no such
# line or its name holds a character outside [A-Za-z0-9._+-], because the name is a path
# component of a store entry. The Rust door reads it the same way
# (`wz_codegen_build::toolchain_channel`).
sce_codegen_toolchain() {
    local file="${1:-$_wz_ar_checkout_l}/rust-toolchain.toml"
    local line channel line_re='^channel = "(.*)"$' name_re='^[A-Za-z0-9._+-]+$'
    [[ -r "$file" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ $line_re ]] || continue
        channel="${BASH_REMATCH[1]}"
        [[ "$channel" =~ $name_re ]] || return 1
        printf '%s\n' "$channel"
        return 0
    done <"$file"
    return 1
}

# sce_codegen_store_entry [<sce-dir>]
#
# The store entry for the sce-codegen built from <sce-dir>'s source state with this checkout's
# recipe and toolchain, <store>/sce-codegen/<rev>-<dirty digest>-<recipe digest>-<toolchain>,
# printed whether it exists or not. Nothing, and 1, when a part of the name cannot be
# established. The Rust door names the same path (`wz_codegen_build::sce_codegen_store_entry`).
sce_codegen_store_entry() {
    local dir="${1:-$WZ_SCE_DIR}" store made_from channel
    store="$(sce_codegen_store_root)" || return 1
    made_from="$(vendored_oracle_recipe_token "$dir" "$WZ_SCE_CODEGEN_RECIPE")" || return 1
    channel="$(sce_codegen_toolchain)" || return 1
    printf '%s/sce-codegen/%s-%s\n' "${store%/}" "$made_from" "$channel"
}

# sce_codegen_stamp_of <binary>
#
# The provenance stamp of a built sce-codegen: beside it, in the checkout and in the store alike.
sce_codegen_stamp_of() {
    printf '%s/.sce-codegen.pin\n' "$(dirname "$1")"
}

# sce_codegen_entry_holds <entry> <token>
#
# 0 when the store entry <entry> holds a build of the source state <token>: its binary is
# executable and the stamp beside it names <token>. The stamp is the last file a publisher
# renames into place, so an entry left half-written is not taken.
sce_codegen_entry_holds() {
    local entry="$1" want="$2" have
    [[ -n "$want" && -x "$entry/sce-codegen" ]] || return 1
    have="$(sce_codegen_stamped_token "$entry/.sce-codegen.pin" || true)"
    [[ "$have" == "$want" ]]
}

# sce_codegen_binary [<sce-dir>]
#
# THE sce-codegen a consumer of <sce-dir> runs: the store entry's when it holds a build of the
# tree's source state, else the checkout's ($WZ_SCE_CODEGEN_BIN), built or not. Its stamp is
# `sce_codegen_stamp_of` it. The Rust door decides the same way
# (`wz_codegen_build::sce_codegen_build`).
sce_codegen_binary() {
    local dir="${1:-$WZ_SCE_DIR}" entry want
    if entry="$(sce_codegen_store_entry "$dir")" \
        && want="$(sce_codegen_source_token "$dir")" \
        && sce_codegen_entry_holds "$entry" "$want"; then
        printf '%s/sce-codegen\n' "$entry"
    else
        printf '%s\n' "$WZ_SCE_CODEGEN_BIN"
    fi
}

# sce_codegen_token_is_clean <token>
#
# 0 when the source token names a checkout with no changes of its own: its dirty digest is the
# digest of empty input, taken the way the token's own is. Only such a state is put in the store;
# any other belongs to the one checkout that holds it.
sce_codegen_token_is_clean() {
    local empty
    empty="$(git hash-object --stdin </dev/null 2>/dev/null)" || return 1
    [[ -n "$empty" && "$1" == *"-$empty" ]]
}

# sce_codegen_store_publish <binary> <entry> <token>
#
# Put <binary>, built from the source state <token>, into the store entry <entry>. Each file is
# copied under a name no reader takes and renamed into place, the stamp last, so a reader finds
# the entry whole or does not take it (`sce_codegen_entry_holds`). Two publishers of one entry
# write the same bytes, so the second rename changes nothing a reader can tell. 1 when the store
# cannot be written; the caller still has the checkout's build.
sce_codegen_store_publish() {
    local bin="$1" entry="$2" token="$3" part
    mkdir -p -- "$entry" 2>/dev/null || return 1
    part="$entry/.part.$$"
    if cp -- "$bin" "$part.bin" 2>/dev/null \
        && chmod 0755 "$part.bin" \
        && mv -f -- "$part.bin" "$entry/sce-codegen" \
        && printf '%s\n' "$token" >"$part.pin" \
        && mv -f -- "$part.pin" "$entry/.sce-codegen.pin"; then
        touch -- "$entry/.used" 2>/dev/null || true
        return 0
    fi
    rm -f -- "$part.bin" "$part.pin" 2>/dev/null || true
    return 1
}

# sce_codegen_store_mark_used <binary>
#
# Record that a consumer took <binary> from the store, which keeps its entry from being pruned. A
# binary outside the store is left alone.
sce_codegen_store_mark_used() {
    local entry store
    entry="$(dirname "$1")"
    store="$(sce_codegen_store_root)" || return 0
    [[ "$entry" == "${store%/}/sce-codegen/"* ]] || return 0
    touch -- "$entry/.used" 2>/dev/null || true
}

# sce_codegen_store_prune <kept-entry>
#
# Remove the store's sce-codegen entries no consumer took for WZ_SCE_CODEGEN_STORE_DAYS days. Each
# goes under its own lock, taken without waiting, so an entry a build is writing stays, and
# <kept-entry> and a directory whose name is not an entry's are never removed. Without flock
# nothing is removed: whether a build holds an entry cannot be known there.
sce_codegen_store_prune() {
    local kept="${1%/}" base entry mark
    local name_re='^[0-9a-f]{40,64}-[0-9a-f]{40,64}-[0-9a-f]{40,64}-[A-Za-z0-9._+-]+$'
    command -v flock >/dev/null 2>&1 || return 0
    base="$(sce_codegen_store_root)" || return 0
    base="${base%/}/sce-codegen"
    for entry in "$base"/*/; do
        entry="${entry%/}"
        [[ -d "$entry" && "${entry##*/}" != "${kept##*/}" ]] || continue
        [[ "${entry##*/}" =~ $name_re ]] || continue
        mark="$entry/.used"
        [[ -e "$mark" ]] || mark="$entry"
        [[ -n "$(find "$mark" -maxdepth 0 -mtime +"$WZ_SCE_CODEGEN_STORE_DAYS" 2>/dev/null)" ]] || continue
        (
            exec 8>>"$entry.lock" || exit 0
            flock -n 8 || exit 0
            rm -rf -- "$entry" "$entry.lock"
        ) 2>/dev/null || true
    done
}

# sce_codegen_ensure <label>
#
# Bring the oracle to the revision this tree pins, rebuilding when it is absent
# or was built from anything else. A store entry holding a build of the tree's
# state counts as built (`sce_codegen_binary`). Prints what it did on the
# caller's stdout, a rebuild's own lines included.
#
#   0  the binary exists and provably matches the pinned source state
#   1  HARD FAIL — the rebuild failed, or succeeded and still does not match
#   2  UNAVAILABLE — the oracle cannot be established here (no submodule, no
#      cargo, no git). The caller may SKIP, unless WZ_SCE_ORACLE_REQUIRE=1, in
#      which case this returns 1 instead and never 2.
sce_codegen_ensure() {
    local label="${1:-sce-codegen}"
    # Spelled as an `if` and not `[[ ... ]] && x`: an AND-list whose test fails
    # returns 1, and this file is sourced by callers that run under `set -e`.
    local unavailable=2
    if [[ "${WZ_SCE_ORACLE_REQUIRE:-0}" == "1" ]]; then
        unavailable=1
    fi

    local want
    if ! want="$(sce_codegen_source_token "$WZ_SCE_DIR")"; then
        echo "$label: sce-codegen oracle UNAVAILABLE (no readable $WZ_SCE_DIR checkout; run: git submodule update --init $WZ_SCE_DIR)"
        return "$unavailable"
    fi

    local bin have=""
    bin="$(sce_codegen_binary "$WZ_SCE_DIR")"
    if [[ -x "$bin" ]]; then
        have="$(sce_codegen_stamped_token "$(sce_codegen_stamp_of "$bin")" || true)"
        if [[ "$have" == "$want" ]]; then
            sce_codegen_store_mark_used "$bin"
            return 0
        fi
    fi

    # Say WHICH of the three states we are in before rebuilding, so a log read
    # later can tell "never built here" from "built from something else" — the
    # R311y889 rule that a skip or a repair must carry its reason.
    if [[ ! -x "$bin" ]]; then
        echo "$label: sce-codegen absent; building at ${want%%-*}"
    elif [[ -z "$have" ]]; then
        echo "$label: sce-codegen carries no provenance stamp (predates the oracle gate); rebuilding at ${want%%-*}"
    else
        echo "$label: sce-codegen was built from ${have%%-*}, tree pins ${want%%-*}; rebuilding"
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        echo "$label: sce-codegen oracle UNAVAILABLE (cargo not on PATH; cannot build it)"
        return "$unavailable"
    fi

    # A log is a product: under the artifact root (scripts/lib/artifact-root.sh).
    local log
    log="${RUNCI_LOG_DIR:-$(wz_artifact_dir crates/target/run-ci-logs)}/sce-codegen-oracle-rebuild.log"
    mkdir -p "$(dirname "$log")" 2>/dev/null || true
    # The build's lines reach the caller as cargo prints them, and the log keeps
    # them for the failure path: a remote run that prints nothing for an hour is
    # ended as hung, and this build can take that long on one core.
    if ! (set -o pipefail; bash scripts/build-sce.sh 2>&1 | tee "$log"); then
        # KEEP WHAT IT SAID (R311y756 / R311y889): a build that failed silently
        # costs a second full build to learn anything.
        echo "$label: sce-codegen rebuild FAILED" >&2
        wz_build_evidence "$log" 40 >&2
        return 1
    fi

    bin="$(sce_codegen_binary "$WZ_SCE_DIR")"
    have="$(sce_codegen_stamped_token "$(sce_codegen_stamp_of "$bin")" || true)"
    if [[ "$have" != "$want" ]]; then
        # A rebuild that reports success and still does not match means the
        # stamp and the build disagree about what was built. That is a defect in
        # this gate or in build-sce.sh, and it must never degrade to a pass.
        echo "$label: sce-codegen rebuilt but provenance still does not match" >&2
        echo "  want: $want" >&2
        echo "  have: ${have:-<unstamped>}" >&2
        return 1
    fi
    return 0
}

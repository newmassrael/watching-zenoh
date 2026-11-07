#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# artifact-root.sh -- where the lanes and the oracle scripts WRITE.
#
# A consumer mounts this checkout read-only (its files are shared between
# worktrees as hard links) and still has to run lanes and build oracles from it.
# Everything those write -- cargo target directories, CMake build directories,
# installed oracles, logs, Python bytecode -- therefore needs a place outside the
# checkout, and one place, so a reader finds what a writer put there.
#
# THE RULE, one for every language that reads or writes a product:
#
#   WZ_ARTIFACT_ROOT unset  a product of the tree path <rel> is at <checkout>/<rel>,
#                           which is where every product has always been.
#   WZ_ARTIFACT_ROOT set    it is at $WZ_ARTIFACT_ROOT/<rel>, and nothing is
#                           written into the checkout.
#
# The layout under the root MIRRORS the tree, so a path a lane, a test or a
# comment names (`target/zenohd/zenohd`, `crates/target/debug/wz-ap-demo`,
# `deploy/mcu-freertos-demo/target-two-session`) names the same product in both
# modes; only the prefix moves. The other readings of this rule are
# `scripts/lib/artifact_root.py` (Python) and `wz_codegen_build::artifact_dir`
# (Rust); each takes the variable as given and the checkout from its own place.
#
# What this file sets, for the script that sources it:
#
#   wz_artifact_root_init [<checkout>]
#       Resolves the root into `WZ_ARTIFACTS` (absolute; the checkout when the
#       variable is unset) and, when it is set, refuses a root inside the
#       checkout, creates the root, puts the cargo shim
#       (`scripts/lib/artifact-root-bin/cargo`) first on PATH and points
#       Python's bytecode cache under the root. The shim gives each cargo
#       workspace of the checkout the mirrored target directory, so the
#       script's cargo calls need no edit.
#
#   wz_artifact_dir <path>
#       The product location of a path of the checkout, absolute or relative to
#       the current directory. A path outside the checkout is printed unchanged:
#       it is not the checkout's to relocate.
#
# The variable is exported unchanged in meaning, so every process a lane starts
# (a test binary, a build script, a gate) reads the same answer.

# The names below are read by the scripts that source this file.
# shellcheck disable=SC2034

# The checkout this file belongs to, physical and as the shell spells it; a
# caller's path may arrive in either form.
_wz_ar_checkout="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
_wz_ar_checkout_l="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# `$1` is inside `$2` (or is `$2`): both absolute, both normalized.
_wz_ar_within() {
    local path="$1" dir="$2"
    [[ "$path" == "$dir" || "$path" == "$dir"/* ]]
}

# Absolute and normalized WITHOUT resolving symlinks: a checkout may hold a
# directory such as `crates/target` as a link to a machine cache, and that path
# is still the checkout's own product path, to be mirrored and not followed.
_wz_ar_abs() {
    realpath -m -s -- "$1"
}

# `$1` (absolute, normalized) is inside the checkout in either spelling of it.
_wz_ar_in_checkout() {
    _wz_ar_within "$1" "$_wz_ar_checkout" || _wz_ar_within "$1" "$_wz_ar_checkout_l"
}

wz_artifact_root_init() {
    local checkout="${1:-$_wz_ar_checkout}"
    _wz_ar_checkout_l="$(cd "$checkout" && pwd)" || {
        echo "artifact-root: cannot enter the checkout '$checkout'" >&2
        return 2
    }
    _wz_ar_checkout="$(cd "$checkout" && pwd -P)"
    if [[ -z "${WZ_ARTIFACT_ROOT:-}" ]]; then
        WZ_ARTIFACTS="$_wz_ar_checkout_l"
        return 0
    fi
    if [[ "$WZ_ARTIFACT_ROOT" != /* ]]; then
        echo "artifact-root: WZ_ARTIFACT_ROOT must be an absolute path, got '$WZ_ARTIFACT_ROOT'" >&2
        echo "  a relative root would name a different place from every directory a lane enters" >&2
        return 2
    fi
    local root
    root="$(_wz_ar_abs "$WZ_ARTIFACT_ROOT")"
    # Both the spelling and what it resolves to: a root reached through a link
    # into the checkout writes into the checkout all the same.
    if _wz_ar_in_checkout "$root" || _wz_ar_in_checkout "$(realpath -m -- "$root")"; then
        echo "artifact-root: WZ_ARTIFACT_ROOT ($root) is inside the checkout ($_wz_ar_checkout)" >&2
        echo "  the root exists so that nothing is written into the checkout; name a directory outside it" >&2
        return 2
    fi
    mkdir -p -- "$root" || {
        echo "artifact-root: cannot create WZ_ARTIFACT_ROOT ($root)" >&2
        return 2
    }
    WZ_ARTIFACTS="$root"
    export WZ_ARTIFACT_ROOT="$root"
    # The shim directory goes first, once, whatever sourced this before.
    local shim="$_wz_ar_checkout/scripts/lib/artifact-root-bin"
    case ":$PATH:" in
    *":$shim:"*) ;;
    *) export PATH="$shim:$PATH" ;;
    esac
    # Python writes `__pycache__` beside every module it imports; under a root it
    # writes there instead (the interpreter's own switch, 3.8 and later).
    export PYTHONPYCACHEPREFIX="$root/.pycache"
    # `git status` refreshes the checkout's index as a side effect; git's own
    # switch turns the optional write off, and nothing a lane asks git needs it.
    export GIT_OPTIONAL_LOCKS=0
    return 0
}

wz_artifact_dir() {
    local path base
    path="$(_wz_ar_abs "$1")"
    if [[ -n "${WZ_ARTIFACT_ROOT:-}" ]]; then
        for base in "$_wz_ar_checkout" "$_wz_ar_checkout_l"; do
            if _wz_ar_within "$path" "$base"; then
                printf '%s\n' "$(_wz_ar_abs "$WZ_ARTIFACT_ROOT")${path#"$base"}"
                return 0
            fi
        done
    fi
    printf '%s\n' "$path"
}

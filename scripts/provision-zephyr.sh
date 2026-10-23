#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The Zephyr workspace and SDK a host builds the kit's images with, at the pins hosted CI builds them
# with: the checks and, where something is missing, the provisioning, so a host that loses its workspace
# (pc2 did, on 2026-10-23, and nothing said so until a build failed with "No such file") is put back by
# one command and not by hand.
#
#   scripts/provision-zephyr.sh --check      what is whole and what is not; exit 0 only if all of it is
#   scripts/provision-zephyr.sh --dry-run    the steps provisioning would take, taken by nobody
#   scripts/provision-zephyr.sh              check, provision what is missing, check again
#
# THE PINS ARE CI'S. `ZEPHYR_REF` and `ZEPHYR_SDK_VERSION` are read from the `env:` of the jobs of
# `.github/workflows/ci.yml` that carry them, and every copy must agree: two numbers for one
# workspace is a host that builds against a tree hosted CI never saw. The steps are the ones of that
# workflow's `Provision Zephyr` step; its `Verify` step is `--check`: it RUNS the venv's tools and
# does not stat them, because a venv whose interpreter is gone still has an executable `west`.
#
# Where: `ZEPHYR_HOME` (default ~/zephyrproject, holding .venv, zephyr and the modules) and
# `ZEPHYR_SDK_DIR` (default ~/zephyr-sdk-<version>), which are the places the repository's lanes look.
# `GITHUB_TOKEN` is used for the SDK's release lookup when set (unauthenticated calls are limited per
# IP and a shared one can be spent before this starts); it is never printed.
#
# Needs network for provisioning (GitHub), Python >= 3.12, git, and about 11 GB.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/ci.yml"
HOME_DIR="${ZEPHYR_HOME:-$HOME/zephyrproject}"

mode=provision
case "${1:-}" in
    "") ;;
    --check) mode=check ;;
    --dry-run) mode=dry ;;
    *)
        echo "usage: $0 [--check | --dry-run]" >&2
        exit 64
        ;;
esac

# One value for a pin, from every place the workflow states it. No copy, or two that differ, is a stop.
pin() {
    local name="$1" values
    values="$(sed -n "s/^[[:space:]]*$name:[[:space:]]*\"\{0,1\}\([^\"[:space:]]*\)\"\{0,1\}[[:space:]]*$/\1/p" "$WORKFLOW" | sort -u)"
    if [[ -z "$values" ]]; then
        echo "provision-zephyr: FAIL - $WORKFLOW states no $name" >&2
        exit 2
    fi
    if [[ "$(wc -l <<<"$values")" -ne 1 ]]; then
        echo "provision-zephyr: FAIL - $name has more than one value in $WORKFLOW: $(tr '\n' ' ' <<<"$values")" >&2
        exit 2
    fi
    printf '%s\n' "$values"
}

REF="$(pin ZEPHYR_REF)"
SDK_VERSION="$(pin ZEPHYR_SDK_VERSION)"
SDK_DIR="${ZEPHYR_SDK_DIR:-$HOME/zephyr-sdk-$SDK_VERSION}"
VENV="$HOME_DIR/.venv"
ZEPHYR="$HOME_DIR/zephyr"
failures=0

item() {
    # item <ok|FAIL> <sentence>
    if [[ "$1" == ok ]]; then
        echo "  provision-zephyr: ok   - $2"
    else
        echo "  provision-zephyr: FAIL - $2" >&2
        failures=$((failures + 1))
    fi
}

# Each check runs the thing it names; a file's existence is not what is being asked.
check() {
    failures=0
    local west version head listed missing=0 path
    if [[ -x "$VENV/bin/west" ]] && version="$("$VENV/bin/west" --version 2>&1)"; then
        item ok "the venv's west runs ($version)"
        west="$VENV/bin/west"
    else
        item FAIL "the venv's west does not run: $VENV/bin/west (the venv is missing, or its interpreter is gone)"
        west=""
    fi
    if head="$(git -C "$ZEPHYR" rev-parse HEAD 2>/dev/null)"; then
        if [[ "$head" == "$REF" ]]; then
            item ok "zephyr is at the pinned revision ${REF:0:12}"
        else
            item FAIL "zephyr is at ${head:0:12}, the pin is ${REF:0:12}"
        fi
    else
        item FAIL "$ZEPHYR is not a git checkout of zephyr"
    fi
    if [[ -n "$west" ]] && listed="$(cd "$HOME_DIR" && "$west" list -f '{abspath}' 2>&1)"; then
        while IFS= read -r path; do
            [[ -d "$path" ]] || { missing=$((missing + 1)); echo "    missing project: $path" >&2; }
        done <<<"$listed"
        if [[ "$missing" -eq 0 ]]; then
            item ok "every project of the workspace is on disk ($(wc -l <<<"$listed") listed by west)"
        else
            item FAIL "$missing project(s) of the workspace are not on disk (west update)"
        fi
    else
        item FAIL "west cannot list the workspace in $HOME_DIR"
    fi
    if [[ -f "$SDK_DIR/sdk_version" && "$(tr -d '[:space:]' <"$SDK_DIR/sdk_version")" == "$SDK_VERSION" ]]; then
        item ok "the SDK in $SDK_DIR is $SDK_VERSION"
    else
        item FAIL "no SDK $SDK_VERSION in $SDK_DIR"
    fi
    if version="$("$SDK_DIR/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc" --version 2>&1)"; then
        item ok "the SDK's arm compiler runs ($(head -n 1 <<<"$version"))"
    else
        item FAIL "the SDK's arm compiler does not run: $SDK_DIR/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc"
    fi
    # Registered FOR THIS SDK: the registry is per user and holds whichever SDK was installed last, so
    # a non-empty one says nothing about the directory the checks above looked at.
    if compgen -G "$HOME/.cmake/packages/Zephyr-sdk/*" >/dev/null \
        && grep -qsF -x "$SDK_DIR/cmake" "$HOME"/.cmake/packages/Zephyr-sdk/*; then
        item ok "the SDK is registered for cmake (~/.cmake/packages/Zephyr-sdk names $SDK_DIR/cmake)"
    else
        item FAIL "$SDK_DIR/cmake is not registered for cmake (~/.cmake/packages/Zephyr-sdk)"
    fi
    return "$failures"
}

run() {
    if [[ "$mode" == dry ]]; then
        echo "  would run: $*"
    else
        echo "  + $*"
        "$@"
    fi
}

python312() {
    local candidate
    for candidate in python3.12 python3 python; do
        if command -v "$candidate" >/dev/null \
            && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 12))' 2>/dev/null; then
            command -v "$candidate"
            return 0
        fi
    done
    echo "provision-zephyr: FAIL - no Python >= 3.12 (Zephyr main needs it)" >&2
    return 1
}

provision() {
    local py
    py="$(python312)"
    # The venv: rebuilt when its west does not run, which is also the state of a venv whose interpreter
    # moved. An existing one that works is left as it is.
    if ! { [[ -x "$VENV/bin/west" ]] && "$VENV/bin/west" --version >/dev/null 2>&1; }; then
        run rm -rf "$VENV"
        run mkdir -p "$HOME_DIR"
        run "$py" -m venv "$VENV"
        run "$VENV/bin/python" -m pip install --quiet --upgrade pip
        run "$VENV/bin/pip" install --quiet west tqdm
    fi
    if [[ ! -d "$ZEPHYR/.git" ]]; then
        run git clone --filter=blob:none https://github.com/zephyrproject-rtos/zephyr "$ZEPHYR"
    fi
    if [[ "$(git -C "$ZEPHYR" rev-parse HEAD 2>/dev/null || true)" != "$REF" ]]; then
        # Never move a tree that holds work that is not committed: that is somebody's.
        if [[ -n "$(git -C "$ZEPHYR" status --porcelain 2>/dev/null || true)" ]]; then
            echo "provision-zephyr: FAIL - $ZEPHYR has uncommitted changes and is not at the pin; not moving it" >&2
            return 1
        fi
        run git -C "$ZEPHYR" fetch --filter=blob:none origin "$REF"
        run git -C "$ZEPHYR" checkout "$REF"
    fi
    if [[ ! -d "$HOME_DIR/.west" ]]; then
        (cd "$HOME_DIR" && run "$VENV/bin/west" init -l zephyr)
    fi
    (
        cd "$HOME_DIR"
        run "$VENV/bin/west" update --narrow -o=--depth=1
        run "$VENV/bin/west" zephyr-export
        run "$VENV/bin/pip" install --quiet -r zephyr/scripts/requirements-base.txt
    )
    if ! { [[ -f "$SDK_DIR/sdk_version" && "$(tr -d '[:space:]' <"$SDK_DIR/sdk_version")" == "$SDK_VERSION" ]] \
        && "$SDK_DIR/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc" --version >/dev/null 2>&1; }; then
        local token=()
        if [[ -n "${GITHUB_TOKEN:-}" ]]; then
            token=(--personal-access-token "$GITHUB_TOKEN")
        fi
        (
            cd "$HOME_DIR/zephyr"
            run "$VENV/bin/west" sdk install --version "$SDK_VERSION" -t arm-zephyr-eabi \
                --install-dir "$SDK_DIR" "${token[@]}"
        )
    fi
}

echo "provision-zephyr: pins from ci.yml: zephyr ${REF:0:12}, SDK $SDK_VERSION; workspace $HOME_DIR, SDK $SDK_DIR"
case "$mode" in
    check)
        check && echo "provision-zephyr: the workspace and the SDK are whole" && exit 0
        echo "provision-zephyr: $failures check(s) failed; scripts/provision-zephyr.sh puts it back" >&2
        exit 1
        ;;
    dry)
        provision
        exit 0
        ;;
    provision)
        if check; then
            echo "provision-zephyr: the workspace and the SDK are whole; nothing to do"
            exit 0
        fi
        echo "provision-zephyr: provisioning what is missing"
        provision
        echo "provision-zephyr: checking what was provisioned"
        if check; then
            echo "provision-zephyr: the workspace and the SDK are whole"
            exit 0
        fi
        echo "provision-zephyr: FAIL - provisioned, and $failures check(s) still fail" >&2
        exit 1
        ;;
esac

#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The Zephyr workspace and SDK a host builds the kit's images with, at the pins hosted CI builds them
# with: the checks and, where something is missing, the provisioning, so a host that loses its workspace
# (pc2 did, on 2026-10-23, and nothing said so until a build failed with "No such file") is put back by
# one command and not by hand.
#
#   scripts/provision-zephyr.sh [PART] --check      what is whole and what is not; exit 0 only if all of it is
#   scripts/provision-zephyr.sh [PART] --dry-run    the steps provisioning would take, taken by nobody
#   scripts/provision-zephyr.sh [PART]              check, provision what is missing, check again
#
# PART is one of the two trees, each of which bx keeps as a tool of its own (`[tools.zephyr-sdk]` and
# `[tools.zephyr-venv]` in bx.toml, built into a tool-store prefix by `bx-provision`):
#
#   --workspace   the venv, the zephyr tree at the pin and its modules, in ZEPHYR_HOME
#   --sdk         the SDK, in ZEPHYR_SDK_DIR
#
# With no PART both are checked and provisioned. The SDK is fetched by zephyr's own `west sdk install`,
# as CI's step does, so `--sdk` needs a west and a zephyr tree at the pin too: it makes them in
# ZEPHYR_HOME (bx points that at the install's scratch directory, so the SDK's entry does not reach
# into the workspace's) and checks only the SDK.
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
# Needs network for provisioning (GitHub), Python >= 3.12 with venv, git, cmake and wget (the SDK's
# setup.sh fetches the toolchain with it), and about 11 GB.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/ci.yml"
HOME_DIR="${ZEPHYR_HOME:-$HOME/zephyrproject}"

usage() {
    echo "usage: $0 [--workspace | --sdk] [--check | --dry-run]" >&2
    exit 64
}

mode=provision
part=all
for arg in "$@"; do
    case "$arg" in
        --check) [[ "$mode" == provision ]] || usage; mode=check ;;
        --dry-run) [[ "$mode" == provision ]] || usage; mode=dry ;;
        --workspace) [[ "$part" == all ]] || usage; part=workspace ;;
        --sdk) [[ "$part" == all ]] || usage; part=sdk ;;
        *) usage ;;
    esac
done

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

# Whether cmake's per-user registry names THIS SDK: it holds whichever SDK was installed last, so a
# non-empty one says nothing about the directory the other checks looked at. An entry and SDK_DIR
# are compared as the directories they resolve to, because an SDK bx keeps is registered at its
# tool-store entry and found by the lanes through the link `~/zephyr-sdk-<version>` to it.
sdk_registered() {
    local want entry line
    want="$(realpath -e "$SDK_DIR/cmake" 2>/dev/null)" || return 1
    for entry in "$HOME"/.cmake/packages/Zephyr-sdk/*; do
        [[ -f "$entry" ]] || continue
        # cmake writes the entry without a final newline, and `read` reports such a last line as false.
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -n "$line" && "$(realpath -e "$line" 2>/dev/null || true)" == "$want" ]] && return 0
        done <"$entry"
    done
    return 1
}

# Each check runs the thing it names; a file's existence is not what is being asked.
check_workspace() {
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
}

check_sdk() {
    local version
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
    if sdk_registered; then
        item ok "the SDK is registered for cmake (~/.cmake/packages/Zephyr-sdk names $SDK_DIR/cmake)"
    else
        item FAIL "$SDK_DIR/cmake is not registered for cmake (~/.cmake/packages/Zephyr-sdk)"
    fi
}

check() {
    failures=0
    [[ "$part" == sdk ]] || check_workspace
    [[ "$part" == workspace ]] || check_sdk
    return "$failures"
}

# A step as it is printed: GITHUB_TOKEN, passed to `west sdk install` as an argument, is shown by name.
shown() {
    local text="$*"
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        text="${text//"$GITHUB_TOKEN"/"\$GITHUB_TOKEN"}"
    fi
    printf '%s\n' "$text"
}

run() {
    if [[ "$mode" == dry ]]; then
        echo "  would run: $(shown "$@")"
    else
        echo "  + $(shown "$@")"
        "$@"
    fi
}

# run_in <dir> <command...>: a step west takes its workspace from the working directory for. A dry
# run prints it and does not enter the directory, which an earlier step would have made.
run_in() {
    local dir="$1"
    shift
    if [[ "$mode" == dry ]]; then
        echo "  would run in $dir: $(shown "$@")"
    else
        echo "  + (in $dir) $(shown "$@")"
        (cd "$dir" && "$@")
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

# What both parts stand on: the venv with west and zephyr's Python requirements, the zephyr tree at
# the pin, and the west workspace around it.
provision_west() {
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
        run_in "$HOME_DIR" "$VENV/bin/west" init -l zephyr
    fi
    # The workspace's tools, and what zephyr's `west sdk` imports (requests, semver, patool).
    run "$VENV/bin/pip" install --quiet -r "$ZEPHYR/scripts/requirements-base.txt"
}

provision_workspace() {
    run_in "$HOME_DIR" "$VENV/bin/west" update --narrow -o=--depth=1
    run_in "$HOME_DIR" "$VENV/bin/west" zephyr-export
}

provision_sdk() {
    if ! { [[ -f "$SDK_DIR/sdk_version" && "$(tr -d '[:space:]' <"$SDK_DIR/sdk_version")" == "$SDK_VERSION" ]] \
        && "$SDK_DIR/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc" --version >/dev/null 2>&1; }; then
        local token=()
        if [[ -n "${GITHUB_TOKEN:-}" ]]; then
            token=(--personal-access-token "$GITHUB_TOKEN")
        fi
        # `west sdk install` takes an SDK of this version that cmake's per-user registry already names
        # (one made by hand, or the tool-store entry an older key built) instead of fetching one into
        # --install-dir, which would stay empty. So it runs with a home of its own, whose registry is
        # empty, and the SDK it fetched is registered in the user's home afterwards.
        #
        # It also moves the SDK it extracted TO --install-dir with `shutil.move`, which puts it INSIDE
        # a directory that already exists: bx's tool store makes {prefix} before the install runs, and
        # the first install on a build machine left prefix/zephyr-sdk-<version>/setup.sh and failed.
        # The SDK is not moved up afterwards, because its setup binds the host tools to the directory
        # it runs in; an empty SDK_DIR is removed first instead, and one that holds anything is a stop.
        if [[ -d "$SDK_DIR" ]]; then
            if [[ -n "$(ls -A "$SDK_DIR")" ]]; then
                echo "provision-zephyr: FAIL - $SDK_DIR holds something that is not SDK $SDK_VERSION; not installing into it" >&2
                return 1
            fi
            run rmdir "$SDK_DIR"
        fi
        local own_home="$HOME_DIR/.sdk-install-home"
        run mkdir -p "$own_home"
        run_in "$ZEPHYR" env HOME="$own_home" "$VENV/bin/west" sdk install --version "$SDK_VERSION" \
            -t arm-zephyr-eabi --install-dir "$SDK_DIR" "${token[@]}"
        run rm -rf "$own_home"
        run "$SDK_DIR/setup.sh" -c
    elif ! sdk_registered; then
        run "$SDK_DIR/setup.sh" -c
    fi
}

provision() {
    provision_west
    [[ "$part" == sdk ]] || provision_workspace
    [[ "$part" == workspace ]] || provision_sdk
}

case "$part" in
    all) what="the workspace and the SDK are" ;;
    workspace) what="the workspace is" ;;
    sdk) what="the SDK is" ;;
esac
echo "provision-zephyr: pins from ci.yml: zephyr ${REF:0:12}, SDK $SDK_VERSION; workspace $HOME_DIR, SDK $SDK_DIR"
case "$mode" in
    check)
        check && echo "provision-zephyr: $what whole" && exit 0
        echo "provision-zephyr: $failures check(s) failed; scripts/provision-zephyr.sh puts it back" >&2
        exit 1
        ;;
    dry)
        provision
        exit 0
        ;;
    provision)
        if check; then
            echo "provision-zephyr: $what whole; nothing to do"
            exit 0
        fi
        echo "provision-zephyr: provisioning what is missing"
        provision
        echo "provision-zephyr: checking what was provisioned"
        if check; then
            echo "provision-zephyr: $what whole"
            exit 0
        fi
        echo "provision-zephyr: FAIL - provisioned, and $failures check(s) still fail" >&2
        exit 1
        ;;
esac

#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# What a kit image's size moved by between a base revision and this tree, both built in ONE run.
#
#   scripts/kit-size-delta.sh --base <rev> [--variant compare|plain] [--symbols N] <image>...
#
# Run it on a build machine through bx, with no --host:
#
#   bx --label kit-size-delta -- bash scripts/kit-size-delta.sh --base origin/main zephyr-client-heap
#
# WHY IT EXISTS. A size change of a kit image (its text, flash, static RAM, stack objects, which
# symbols) is attributed by building the image before and after the change. Two builds compare only
# when they share a toolchain, a Zephyr workspace and the paths the link and the debug information
# see, so sessions ran Layer Qzk once per tree and pinned both runs to one machine with
# `bx --host`. The pin was chosen from memory, went stale, and one pinned run waited 50 minutes for
# its machine. Here both trees are built by one process on one machine, so they share all of that by
# construction, and bx is free to place the run on any machine with the Zephyr toolchain (bx.toml
# asks for it on a command line naming this script: `needed_by` of the two Zephyr tools).
#
# WHAT IT DOES.
#   1. Refuses, before anything is built, a base that is not a commit of this repository and an
#      image key that is not one of this tree's `scripts/kit-lane.sh images`. On a build machine the
#      refs are the ones bx sent with the tree: fetch before the run to compare with today's tip.
#   2. Checks the base out in a temporary git worktree, and in it every submodule this checkout has
#      checked out, at the commit the base records, from this checkout's own repository of it (a
#      hard-linked copy where git keeps a worktree's submodules), so no network is asked: a build
#      machine may hold no credential for a submodule's remote.
#   3. Per image, builds it in this tree and then in the base, each with that tree's own
#      `scripts/kit-lane.sh build` (the base built the way the base builds it), keeps only the ELF
#      and removes the build directory before the next build, as Layer Qzk does, so the disk holds
#      one build at a time. `--variant compare` (the default) builds as the pico ceiling of Layer Qzk
#      does (BUILD_VARIANT=compare: the memory report in, the lane's gates not run); `--variant
#      plain` builds the image the text and stack gates hold. A plain build the lane's gates refuse
#      still left an ELF, and the ELF is what is compared.
#   4. Prints, through `scripts/lib/kit_size_delta.py`, the cells the ceiling gate reads (text,
#      flash, static RAM, stack objects, the heap client's storage block) for base, head and the
#      delta, the owners that moved, and the symbols that changed, largest movers first
#      (`--symbols` of them per family, 40 by default).
#
# The head is this tree as it is, uncommitted changes included (bx sends them). The base build runs
# without WZ_ARTIFACT_ROOT, so its products stay in its temporary checkout and never land in this
# tree's mirrored directories under the root; the checkout and its git records are removed on exit.
#
# EXIT. 0 when every image was built and read on both sides (an image the base does not list is
# printed with its head figures and the reason); a growth is not a failure, this attributes and does
# not judge. 1 when a build failed, or the base could not be checked out whole (the tail of the
# build's log is printed). 2 when refused: the arguments, the base, an image key, or an ELF that
# could not be read.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/artifact-root.sh
source "$ROOT/scripts/lib/artifact-root.sh"
wz_artifact_root_init "$ROOT" || exit 2

say() { echo "kit-size-delta: $*"; }
refuse() {
    say "$*" >&2
    exit 2
}
usage() {
    sed -n '7,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit "${1:-64}"
}

BASE="" VARIANT=compare SYMBOLS=40
KEYS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base)
            [[ $# -ge 2 ]] || refuse "--base needs the revision to compare with (origin/main, a branch, a commit)"
            BASE="$2"
            shift 2
            ;;
        --variant)
            [[ $# -ge 2 && ( "$2" == compare || "$2" == plain ) ]] \
                || refuse "--variant is compare (the pico ceiling's build) or plain (the gated build)"
            VARIANT="$2"
            shift 2
            ;;
        --symbols)
            [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || refuse "--symbols is a count of one or more"
            SYMBOLS="$2"
            shift 2
            ;;
        -h | --help) usage 0 ;;
        -*) refuse "unknown option $1 (--base, --variant, --symbols)" ;;
        *)
            [[ " ${KEYS[*]} " == *" $1 "* ]] || KEYS+=("$1")
            shift
            ;;
    esac
done
[[ -n "$BASE" ]] || refuse "--base names the revision to compare with (origin/main, a branch, a commit)"
[[ ${#KEYS[@]} -gt 0 ]] || refuse "name at least one image of scripts/kit-lane.sh images"

BASE_SHA="$(git -C "$ROOT" rev-parse --verify --quiet "$BASE^{commit}")" \
    || refuse "the base '$BASE' is not a commit this repository holds (git rev-parse --verify found none); fetch it, or name a branch or commit it has"

# The run's own directory, outside every checkout: cargo and rustup look for their configuration
# upward from where they run, and this tree's would be found above a base checkout placed inside it.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kit-size-delta.XXXXXX")" || refuse "no temporary directory could be made"
BASE_TREE=""
# shellcheck disable=SC2329  # called by the EXIT trap below, which shellcheck does not follow
cleanup() {
    if [[ -n "$BASE_TREE" ]]; then
        # --force: git refuses to remove a worktree with submodules otherwise, and this one is the
        # run's own, holding nothing but what the run put there.
        git -C "$ROOT" worktree remove --force "$BASE_TREE" >/dev/null 2>&1
        git -C "$ROOT" worktree prune >/dev/null 2>&1
    fi
    rm -rf -- "$WORK"
}
trap cleanup EXIT

# Each tree's lane lists its images itself; a lane home of the run's keeps it out of the user's.
lane_images() { KIT_LANE_HOME="$WORK/list" bash "$1/scripts/kit-lane.sh" images; }

HEAD_IMAGES="$(lane_images "$ROOT")" || refuse "this tree's kit lane could not list its images (scripts/kit-lane.sh images)"
for key in "${KEYS[@]}"; do
    grep -qxF -- "$key" <<<"$HEAD_IMAGES" \
        || refuse "'$key' is not an image of this tree's kit lane; scripts/kit-lane.sh images lists: $(tr '\n' ' ' <<<"$HEAD_IMAGES")"
done

# bring_submodules <tree> <from>: in the base checkout <tree>, every submodule <from> has checked
# out, at the commit <tree> records, from <from>'s own repository of it; then the submodules inside
# each, the same way. A copy of that repository is put where git keeps a worktree's submodule
# (<gitdir>/modules/<name>), and `git submodule update` takes a repository it finds there as its
# own, so it clones nothing. `git clone --mirror` from a path hard-links the objects.
bring_submodules() {
    local tree="$1" from="$2" tree_git kv key path name src dest here
    local -a entries=()
    [[ -f "$tree/.gitmodules" ]] || return 0
    tree_git="$(git -C "$tree" rev-parse --absolute-git-dir)" || return 1
    mapfile -d '' entries < <(git config -f "$tree/.gitmodules" -z --get-regexp '^submodule\..*\.path$')
    for kv in ${entries[@]+"${entries[@]}"}; do
        key="${kv%%$'\n'*}"
        path="${kv#*$'\n'}"
        name="${key#submodule.}"
        name="${name%.path}"
        # Checked out in <from> when it is its own top level; an uninitialised one is an empty
        # directory of the superproject, whose top level is the superproject's.
        [[ -d "$from/$path" ]] || continue
        here="$(cd "$from/$path" && pwd -P)"
        [[ "$(git -C "$from/$path" rev-parse --show-toplevel 2>/dev/null)" == "$here" ]] || continue
        src="$(git -C "$from/$path" rev-parse --absolute-git-dir)" || return 1
        dest="$tree_git/modules/$name"
        if [[ ! -e "$dest" ]]; then
            if ! { git clone -q --mirror -- "$src" "$dest" \
                && cp -- "$src/config" "$dest/config" \
                && { git config -f "$dest/config" --unset core.worktree || [[ $? -eq 5 ]]; }; }; then
                say "the base's $path could not be copied from this checkout's repository of it ($src)" >&2
                return 1
            fi
        fi
        if ! GIT_TERMINAL_PROMPT=0 git -C "$tree" submodule update --init -q -- "$path" </dev/null; then
            say "the base's $path could not be checked out at the commit the base records: this checkout's repository of it ($src) may not hold that commit" >&2
            return 1
        fi
        bring_submodules "$tree/$path" "$from/$path" || return 1
    done
}

BASE_TREE="$WORK/base"
if ! git -C "$ROOT" -c core.hooksPath=/dev/null -c submodule.recurse=false \
    worktree add --detach --quiet "$BASE_TREE" "$BASE_SHA" >"$WORK/base-checkout.log" 2>&1; then
    say "the base $BASE ($BASE_SHA) could not be checked out:" >&2
    cat "$WORK/base-checkout.log" >&2
    exit 1
fi
if ! bring_submodules "$BASE_TREE" "$ROOT"; then
    say "the base $BASE could not be checked out whole: its submodules are not all there" >&2
    exit 1
fi
# A base whose lane cannot list its images builds none of them; each is then said as absent.
BASE_IMAGES="$(lane_images "$BASE_TREE")" || BASE_IMAGES=""

HEAD_LABEL="$(git -C "$ROOT" rev-parse --short=12 HEAD)"
if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]]; then
    HEAD_LABEL="$HEAD_LABEL plus its uncommitted changes"
fi
BASE_LABEL="$BASE (${BASE_SHA:0:12})"

# The name kit-lane.sh keeps a build's record under: a compare build has one of its own.
record_name() {
    if [[ "$VARIANT" == compare ]]; then echo "compare-$1"; else echo "$1"; fi
}

# build_one <tree> <side> <key>: the kit lane of <tree> builds <key> into a lane home of the side's
# own; its ELF is copied to $WORK/<side>-<key>.elf and its build directory removed. It fails when
# the lane left no record of a linked image (its build, its objcopy or its region refused it).
build_one() {
    local tree="$1" side="$2" key="$3" lane="$WORK/$2" name out log built rc=0
    # A BUILD_VARIANT of the caller's would choose the variant behind --variant's back.
    local -a env_args=(-u BUILD_VARIANT)
    name="$(record_name "$key")"
    log="$WORK/$side-$key.log"
    rm -f -- "$lane/last-out-$name"
    # The base checkout is a throwaway: its products stay in it, never in the root's mirror of this
    # tree. env reads its options before the first assignment, so the unset comes first.
    if [[ "$side" == base ]]; then
        env_args+=(-u WZ_ARTIFACT_ROOT)
    fi
    if [[ "$VARIANT" == compare ]]; then
        env_args+=(BUILD_VARIANT=compare)
    fi
    env "${env_args[@]}" KIT_LANE_HOME="$lane" \
        KIT_LANE_MIN_AVAIL_MB="${KIT_LANE_MIN_AVAIL_MB:-4000}" \
        bash "$tree/scripts/kit-lane.sh" build "$key" >"$log" 2>&1 || rc=$?
    out="$(cat "$lane/last-out-$name" 2>/dev/null)"
    if [[ -n "$out" && -f "$out/elf.path" ]] && cp -- "$(cat "$out/elf.path")" "$WORK/$side-$key.elf"; then
        rm -rf -- "$lane/build"
        if (( rc != 0 )); then
            say "$key ($side): the kit lane's gates refused the build; its ELF is compared all the same:"
            grep -a 'FAIL' "$log" | sed 's/^/    /'
        fi
        return 0
    fi
    say "$key ($side): the build failed (kit-lane.sh build, exit $rc):" >&2
    sed 's/^/    /' "$log" >&2
    for built in "$lane"/out/*-"$name"; do
        [[ -f "$built/build.log" ]] || continue
        tail -40 "$built/build.log" | sed 's/^/    build.log: /' >&2
    done
    rm -rf -- "$lane/build"
    return 1
}

# The Zephyr workspace, named the way Layer Qzk names it when WZ_ZEPHYR_BASE is the one given.
if [[ -z "${ZEPHYR_HOME:-}" && -n "${WZ_ZEPHYR_BASE:-}" ]]; then
    export ZEPHYR_HOME="${WZ_ZEPHYR_BASE%/*}"
fi

say "base $BASE_LABEL, head $HEAD_LABEL, $VARIANT builds of: ${KEYS[*]}"
build_fail=0 read_fail=0
for key in "${KEYS[@]}"; do
    if ! build_one "$ROOT" head "$key"; then
        build_fail=1
        continue
    fi
    base_args=()
    if ! grep -qxF -- "$key" <<<"$BASE_IMAGES"; then
        base_args=(--base-absent "the base's scripts/kit-lane.sh images does not list it")
    elif build_one "$BASE_TREE" base "$key"; then
        base_args=(--base-elf "$WORK/base-$key.elf")
    else
        build_fail=1
        continue
    fi
    python3 "$ROOT/scripts/lib/kit_size_delta.py" --image "$key" --head-elf "$WORK/head-$key.elf" \
        "${base_args[@]}" --base-rev "$BASE_LABEL" --head-rev "$HEAD_LABEL" --symbols "$SYMBOLS" \
        || read_fail=1
    rm -f -- "$WORK/head-$key.elf" "$WORK/base-$key.elf"
done
if (( build_fail )); then
    exit 1
fi
if (( read_fail )); then
    exit 2
fi
exit 0

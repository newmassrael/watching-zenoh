#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R4401 (no register item) -- run a command with this checkout READ-ONLY and an
# artifact root writable: the shape a consumer gives a checkout it mounts
# read-only, made on this host so a
# lane can show the artifact-root rule (scripts/lib/artifact-root.sh) holds for
# it. Any write into the checkout fails with EROFS, so a lane that passes in here
# wrote nothing there -- a measurement, where a lint can only read spellings.
#
#     source scripts/lib/read-only-tree.sh
#     ro_tree_probe <checkout>        # 0 bwrap, 1 non-interactive sudo, 2 neither (RO_TREE_WHY)
#     ro_tree_exec <checkout> <root> <command...>
#
# Two ways to hold the privilege, in the order the netns lanes use them
# (scripts/lib/netns-topology.sh): a bwrap user namespace (a build machine's
# AppArmor profile allows it), else a mount namespace made with non-interactive
# sudo (the hosted runner), whose command then runs as the caller again.
#
# What is made read-only: the checkout, and the target of every symbolic link in
# it named `target*` that points outside it. A checkout may hold `target` or
# `crates/target` as a link to a machine cache; a write through that link is a
# write to a path of the checkout all the same, and leaving its target writable
# would let exactly the defect this measures pass.

RO_TREE_WHY=""

# The link targets outside the checkout that a write through the checkout could
# reach, one per line.
_ro_tree_linked() {
    local tree="$1" link dest
    while IFS= read -r -d '' link; do
        dest="$(realpath -e -- "$link" 2>/dev/null)" || continue
        [[ -d "$dest" ]] || continue
        [[ "$dest" == "$tree" || "$dest" == "$tree"/* ]] && continue
        printf '%s\n' "$dest"
    done < <(find "$tree" -maxdepth 3 -path "$tree/vendor" -prune -o \
        -type l -name 'target*' -print0 2>/dev/null)
}

ro_tree_probe() {
    local tree="$1"
    if command -v bwrap >/dev/null 2>&1 \
        && bwrap --bind / / --dev-bind /dev /dev --unshare-user \
            --ro-bind "$tree" "$tree" -- true 2>/dev/null; then
        RO_TREE_WHY=""
        return 0
    fi
    if command -v unshare >/dev/null 2>&1 && command -v setpriv >/dev/null 2>&1 \
        && sudo -n true 2>/dev/null; then
        RO_TREE_WHY=""
        return 1
    fi
    RO_TREE_WHY="neither a bwrap user namespace nor non-interactive sudo is available to mount the checkout read-only"
    return 2
}

ro_tree_exec() {
    local tree="$1" root="$2"
    shift 2
    tree="$(cd "$tree" && pwd -P)" || return 2
    mkdir -p -- "$root" || return 2
    root="$(cd "$root" && pwd -P)"
    local -a linked=()
    mapfile -t linked < <(_ro_tree_linked "$tree")
    local mode
    ro_tree_probe "$tree"
    mode=$?
    case "$mode" in
    0)
        local -a binds=(--ro-bind "$tree" "$tree")
        local d
        for d in "${linked[@]}"; do
            binds+=(--ro-bind "$d" "$d")
        done
        bwrap --bind / / --dev-bind /dev /dev --unshare-user "${binds[@]}" \
            --bind "$root" "$root" --setenv WZ_ARTIFACT_ROOT "$root" -- "$@"
        ;;
    1)
        # The mounts need root; the command does not, and must not: it runs as the
        # caller again, with the caller's WHOLE environment and WZ_ARTIFACT_ROOT on
        # top, exactly what the bwrap branch above gives it, so what it builds is
        # owned as anything else the caller builds and a lane sees the same
        # variables whichever branch the host takes.
        #
        # sudo rewrites the environment even under `-E`: it removes the dynamic
        # linker's variables and others (PERL5LIB, PYTHONPATH), sets USER and
        # LOGNAME to root, adds SUDO_*, and replaces PATH. Carrying a chosen list
        # across lost each variable the list did not name: LD_LIBRARY_PATH first, so
        # a test binary linked to the shared RocksDB engine stopped at its start on
        # `librocksdb.so.10: cannot open shared object file` (hosted run of
        # c91572906a, Layer Ero), and USER=root after it, which a test that re-runs
        # itself in a namespace hands to runuser. So the caller's environment goes
        # across as arguments, every variable, and the command starts from it alone
        # (`env -i`); NUL-separated, so a value may hold any byte but NUL. The Rust
        # twin is NetnsPair::test_inside in crates/wz-integration-tests/src/lib.rs.
        local -a carried=()
        mapfile -d '' -t carried < <(env -0)
        sudo -n unshare --mount --propagation private -- /bin/bash -c '
            set -e
            uid="$1" gid="$2" root="$3" n="$4" m="$5"
            shift 5
            for ((i = 0; i < n; i++)); do
                mount --bind "$1" "$1"
                mount -o remount,bind,ro "$1"
                shift
            done
            carried=("${@:1:m}")
            shift "$m"
            exec setpriv --reuid="$uid" --regid="$gid" --init-groups -- \
                env -i "${carried[@]}" WZ_ARTIFACT_ROOT="$root" "$@"
        ' ro-tree "$(id -u)" "$(id -g)" "$root" "$((1 + ${#linked[@]}))" \
            "${#carried[@]}" "$tree" "${linked[@]}" "${carried[@]}" "$@"
        ;;
    *)
        echo "read-only-tree: $RO_TREE_WHY" >&2
        return 2
        ;;
    esac
}

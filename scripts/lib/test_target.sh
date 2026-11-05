#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The `cargo test` arguments that run ONE test file of a crate, wherever the crate keeps the file.
#
#   wz_test_args wz-integration-tests link_emitter_b6
#   cargo test -p wz-integration-tests "${WZ_TEST_ARGS[@]}" --quiet
#
# A crate's integration test file is `tests/<name>.rs`, an executable of its own (`--test <name>`),
# or, once `scripts/lib/merge_tests.py` has merged the crate, `tests/<target>/files/<name>.rs`, a
# module of the executable `<target>`, where the test of the file is `files::<name>::<test>`:
# `--test <target> files::<name>::`. libtest's filter is a substring, and the `files::` before the
# name is what makes it pick this file and not another whose name ends in it. A script that spelled
# `--test <name>` would hold the layout and break at every move; this sets the spelling for the
# layout the tree is in, in the array `WZ_TEST_ARGS` (two words after a merge, so an array, which a
# caller expands quoted).
#
# The caller puts `"${WZ_TEST_ARGS[@]}"` where `--test <name>` stood, BEFORE any `--`: cargo takes
# one filter before `--` and a test filter of the caller's own goes after it. An optional third
# argument names one test of the file (a filter inside it): `--test <name> <test>` before a merge,
# `--test <target> files::<name>::<test>` after it (with `--exact` after `--`, the whole path, which
# is the full name of the test in the merged executable).
#
# `scripts/lib/retarget_test_refs.py --verify` reads this spelling back (the call and the array are
# `--test <name> [<test>]`) for the lints that parse `run-ci.sh`.

# The repository root: where `crates/` is, from the caller's `repo_root` or from this file.
_wz_tt_root="${repo_root:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

WZ_TEST_ARGS=()

wz_test_args() {
    local crate="$1" name="$2" within="${3:-}"
    local dir="$_wz_tt_root/crates/$crate/tests"
    local file target
    if [[ -f "$dir/$name.rs" ]]; then
        WZ_TEST_ARGS=(--test "$name")
        [[ -n "$within" ]] && WZ_TEST_ARGS+=("$within")
        return 0
    fi
    for file in "$dir"/*/files/"$name".rs; do
        [[ -f "$file" ]] || continue
        target="$(basename "$(dirname "$(dirname "$file")")")"
        WZ_TEST_ARGS=(--test "$target" "files::${name}::${within}")
        return 0
    done
    # A name that is not a file must not widen the command to the whole crate (the argument would
    # be gone and `cargo test -p <crate>` runs every target): it names a target cargo refuses.
    echo "wz_test_args: $crate has no test file named $name" >&2
    WZ_TEST_ARGS=(--test "wz_test_args_found_no_file_${name}")
    return 1
}

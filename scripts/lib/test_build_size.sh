#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# What one crate's test build costs: the time to build every test executable into a FRESH target
# directory, the size of what it wrote, how many executables there are and how large, and the list
# of the crate's tests (for `scripts/lib/merge_tests.py --compare`).
#
#   test_build_size.sh <crate> <label> [cargo test args after --no-run, e.g. --features a,b]
#
# It exists for the measurement that decides whether a crate's integration tests are merged into
# one executable (`merge_tests.py`): run it before the move and after it, from the same host, and
# read `AB build`, `AB debug_kb` and `AB executables`. The target directory is its own
# (`crates/target-ab-<label>`), so the figures do not depend on what an earlier build
# left, and it is deleted at the end.
set -u
crate="${1:?crate}"
label="${2:?label}"
shift 2
# The cargo workspace is `crates/`, wherever the caller stands (a build host starts at the root).
cd "$(dirname "$0")/../../crates" || exit 1
T="$PWD/target-ab-$label"
rm -rf "$T"
export CARGO_TARGET_DIR="$T"
start=$(date +%s)
cargo test -p "$crate" "$@" --no-run --quiet
echo "AB build rc=$? seconds=$(($(date +%s) - start))"
du -sk "$T/debug" >"$T/size.txt"
echo "AB debug_kb $(cut -f1 "$T/size.txt")"
find "$T/debug/deps" -maxdepth 1 -type f -perm -u+x ! -name '*.*' -printf '%s\n' >"$T/exe.txt"
awk '{n++; s+=$1} END {printf "AB executables=%d bytes=%d\n", n, s}' "$T/exe.txt"
cargo test -p "$crate" "$@" --quiet -- --list >"$T/list.txt" 2>&1
echo "LISTBEGIN"
cat "$T/list.txt"
echo "LISTEND"
rm -rf "$T"

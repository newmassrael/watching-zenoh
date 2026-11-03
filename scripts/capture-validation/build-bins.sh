#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The zenoh programs the validation corpus of the flow zenoh test is captured
# with (docs/flow-zenoh-verdict.md §6.12), built from the pinned release.
#
#     bx --artifact 'target/validation/bin/*' -- bash scripts/capture-validation/build-bins.sh
#
# The pinned version is the one the reader is compared against
# (`UPSTREAM_VERSION` in scripts/lib/upstream_feature_census.py), read from
# there so it is stated once. The tag is cloned into target/validation/src (a
# shallow clone of the public repository) unless ZENOH_SRC names a checkout
# whose `git describe` is the tag. zenohd and the examples a workload needs are
# built with the release's own toolchain file and default features (every
# transport, both authentications, compression), and copied into
# target/validation/bin with the tag written beside them.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import upstream_feature_census as c; print(c.UPSTREAM_VERSION)' "$ROOT/scripts/lib")"
WORK="$ROOT/target/validation"
SRC="${ZENOH_SRC:-$WORK/src}"
OUT="$WORK/bin"

if [[ ! -f "$SRC/zenohd/Cargo.toml" ]]; then
    rm -rf "$SRC"
    git clone --quiet --depth 1 --branch "$VERSION" https://github.com/eclipse-zenoh/zenoh "$SRC"
fi
described="$(git -C "$SRC" describe --tags --always)"
if [[ "$described" != "$VERSION" ]]; then
    echo "build-bins: $SRC describes itself as $described, not the pinned $VERSION" >&2
    exit 1
fi

CORE=(z_pub z_sub z_put z_get z_queryable z_liveliness z_sub_liveliness
      z_get_liveliness z_pub_thr z_sub_thr z_ping z_pong z_scout z_querier)
EXT=(z_advanced_pub z_advanced_sub)

export CARGO_TARGET_DIR="$WORK/build"
cd "$SRC"
cargo build --release --locked -p zenohd
args=()
for ex in "${CORE[@]}"; do args+=(--example "$ex"); done
cargo build --release --locked -p zenoh-examples "${args[@]}"
args=()
for ex in "${EXT[@]}"; do args+=(--example "$ex"); done
cargo build --release --locked -p zenoh-ext-examples "${args[@]}"

rm -rf "$OUT"
mkdir -p "$OUT"
install -m 0755 "$CARGO_TARGET_DIR/release/zenohd" "$OUT/zenohd"
for ex in "${CORE[@]}" "${EXT[@]}"; do
    install -m 0755 "$CARGO_TARGET_DIR/release/examples/$ex" "$OUT/$ex"
done
printf '%s\n' "$VERSION" > "$OUT/VERSION"
"$OUT/zenohd" --version

#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# build-zenohd.sh — provision the zenoh-full REFERENCE router (zenohd v1.5.0)
# for wz <-> zenohd cross-impl interop tests (tests/wz_to_zenohd_router.rs,
# run-ci Layer Z).
#
# Every other interop test pairs wz with zenoh-PICO (the embedded C impl).
# zenohd is the canonical Rust router: dialing it as a client and completing
# the handshake + routing a Put through it is the ultimate wire-parity check.
# zenohd is NOT a wz dependency, so this script provisions it on demand.
#
# Two sources, in preference order — both produce the SAME release binary, so
# the reference oracle has ONE identity regardless of which source ran
# (R311pe fresh-clone reproducibility + R311pj source convergence, debt ③):
#   A. The cargo git checkout (~/.cargo/git/checkouts/zenoh-*/.../zenohd), when
#      present: a RELEASE build that reuses cargo's already-compiled zenoh
#      dependency graph (incremental, the developer fast path). The checkout's
#      version is asserted to equal ZENOHD_VERSION, so a cache that later resolves
#      a different zenoh fails fast instead of silently building a divergent
#      router.
#   B. Otherwise crates.io: `cargo install zenohd@<ver> --locked`, a release build
#      from the published, Cargo.lock-pinned source. This is what lets a fresh
#      `git clone` of wz provision zenohd with no manual ZENOHD step (the prior
#      script only PRINTED this command on a missing checkout and exited 1).
#      Reproducibility caveat: the pinned toolchain must already be installed —
#      the rustup check below hard-errors with the install hint if it is not.
#
# Set ZENOHD_FORCE_CRATES_IO=1 to skip the checkout glob and force source B
# (reproducibility self-test, and the path a fresh clone takes). Override the
# pinned version with ZENOHD_VERSION=x.y.z.
#
# Output: target/zenohd/zenohd
#
# Built with zenoh 1.5.0's pinned toolchain (channel 1.85.0) to avoid any
# newer-rustc incompatibility. Re-runs are idempotent: the checkout build is
# incremental, the crates.io install is a no-op when the version is already
# installed, and `install -m 0755` overwrites atomically.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="$ROOT/target/zenohd"
BUILD_DIR="$ROOT/target/zenohd-build"
TOOLCHAIN="1.85.0"
ZENOHD_VERSION="${ZENOHD_VERSION:-1.5.0}"

# R311y392 — the unixpipe-enabled variant. zenoh's `default` feature set OMITS
# transport_unixpipe (zenoh/Cargo.toml), and `cargo install` (source B) cannot add
# a dependency feature, so a unixpipe zenohd requires a SOURCE build with
# `--features zenoh/transport_unixpipe`. It is installed to a SEPARATE target so the
# default oracle's "one identity" (used by every other Layer Z test) is unchanged;
# the wz<->zenohd unixpipe interop test points WZ_ZENOHD_UNIXPIPE_BIN at it. Enable
# with ZENOHD_UNIXPIPE=1 (which also implies a source build — set
# ZENOHD_ALLOW_CLONE=1 on a machine with no cargo git checkout).
#
# R311y400 — the vsock-enabled variant, the SAME pattern: zenoh's `default` also
# OMITS transport_vsock, so a vsock zenohd needs a SOURCE build with
# `--features zenoh/transport_vsock`, installed to target/zenohd-vsock/. Enable with
# ZENOHD_VSOCK=1. Used ONLY by the host-only wz vsock ACCEPTOR interop
# (wz_vsock_acceptor_zenohd_interop) on a vsock-capable host (AF_VSOCK loopback);
# NOT provisioned in hosted CI (the runner has no vsock_loopback), so unlike the
# unixpipe oracle its Layer Z leg SKIPs rather than FAILs when absent.
#
# The two variants are mutually exclusive (one oracle identity per build); the
# shared VARIANT_FEATURE / VARIANT_NAME carry the selected transport feature so the
# build + storage-skip + source-B-reject logic below stays single-path.
VARIANT_FEATURE=""
VARIANT_NAME=""
if [[ "${ZENOHD_UNIXPIPE:-0}" -eq 1 ]]; then
    INSTALL_DIR="$ROOT/target/zenohd-unixpipe"
    BUILD_DIR="$ROOT/target/zenohd-unixpipe-build"
    VARIANT_FEATURE="--features zenoh/transport_unixpipe"
    VARIANT_NAME="transport_unixpipe"
elif [[ "${ZENOHD_VSOCK:-0}" -eq 1 ]]; then
    INSTALL_DIR="$ROOT/target/zenohd-vsock"
    BUILD_DIR="$ROOT/target/zenohd-vsock-build"
    VARIANT_FEATURE="--features zenoh/transport_vsock"
    VARIANT_NAME="transport_vsock"
# R311y505 — the SHARED-MEMORY-enabled variant, the same pattern a third time, and
# the reason it is needed is a measurement that could not be made without it.
#
# wz puts a UNIT ext at establishment id 0x2 (`extshm::SHM_ESTABLISHMENT_EXT_ID`)
# while zenoh declares `Shm = zextzbuf!(0x2, false)` (`transport/init.rs:152`), and
# the inventory called that WIRE-INCOMPATIBLE. Whether the two actually collide
# turns on zenoh's extension identity being `eid = header & !FLAG_Z` — encoding
# bits INCLUDED — which makes wz's 0x02 and zenoh's 0x42 different extensions.
# zenoh relies on that itself (`QoS = zextunit!(0x1)` beside
# `QoSLink = zextz64!(0x1)`).
#
# The STOCK oracle cannot decide it: `shared-memory` is absent from zenoh's
# `default` set (zenoh/Cargo.toml:34-46) and zenohd's default is `zenoh/default`,
# so the stock binary has no `Shm` ext compiled in AT ALL. Pointing wz at it proves
# only that an unknown UNIT is skippable — a real result, but not the collision
# question, and reading it as such would be the "a foreign CLI can hide the
# property" trap. This variant is the oracle that HAS the extension.
elif [[ "${ZENOHD_SHM:-0}" -eq 1 ]]; then
    INSTALL_DIR="$ROOT/target/zenohd-shm"
    BUILD_DIR="$ROOT/target/zenohd-shm-build"
    VARIANT_FEATURE="--features zenoh/shared-memory"
    VARIANT_NAME="shared-memory"
fi

if ! rustup toolchain list 2>/dev/null | grep -q "^$TOOLCHAIN"; then
    echo "build-zenohd: toolchain $TOOLCHAIN not installed" >&2
    echo "  run: rustup toolchain install $TOOLCHAIN" >&2
    exit 1
fi

# Source A — locate the zenoh checkout (cargo git cache) that carries the
# zenohd crate. The directory is hash-named, so glob for the one with a
# zenohd/Cargo.toml. Skipped entirely when ZENOHD_FORCE_CRATES_IO=1.
ZH=""
if [[ "${ZENOHD_FORCE_CRATES_IO:-0}" -ne 1 ]]; then
    # R311y442 — an EXPLICIT checkout override, tried before the cargo-git glob.
    # A developer who keeps a plain `git clone` of zenoh (rather than a checkout
    # cargo happened to materialise) otherwise falls silently to source B, and
    # source B yields neither the storage-manager cdylib nor the zenoh-ext
    # example oracles — so two interop families go dark on a machine that has
    # the source right there. An env var, deliberately, not a path in this file:
    # a committed absolute path is wrong on the next clone (the CLAUDE.md rule).
    if [[ -n "${ZENOHD_SRC:-}" ]]; then
        if [[ ! -f "$ZENOHD_SRC/zenohd/Cargo.toml" ]]; then
            echo "build-zenohd: ZENOHD_SRC=$ZENOHD_SRC has no zenohd/Cargo.toml" >&2
            exit 1
        fi
        ZH="$(cd "$ZENOHD_SRC" && pwd)"
    else
        for c in "$HOME"/.cargo/git/checkouts/zenoh-*/*/zenohd/Cargo.toml; do
            [[ -f "$c" ]] || continue
            ZH="$(cd "$(dirname "$c")/.." && pwd)"
            break
        done
    fi
fi

# Source A2 (R311y264) — a SOURCE TREE from a shallow clone of the pinned tag, for a
# machine that has no cargo-git checkout to reuse (a hosted CI runner).
#
# Why not just fall to source B (crates.io) there: `cargo install` yields BINARIES, not
# the storage-manager cdylib, so Layer Z's storage-replication interop test SKIPs — and a
# SKIP is green. The lane would "run in CI" while one of its proofs never executed, which
# is exactly the false-authority Layer A4 exists to stop (it reports proofs hosted CI
# actually runs as a separate population precisely because a proof that never runs is not
# a proof). Only a source tree can produce the plugin, so CI takes a source tree.
#
# Opt-in via ZENOHD_ALLOW_CLONE=1: a developer's machine keeps preferring the checkout it
# already has and never pays a clone. The version assert below validates the clone the
# same way it validates a checkout, so a mis-tagged tree fails fast rather than silently
# building a divergent reference router.
if [[ -z "$ZH" && "${ZENOHD_ALLOW_CLONE:-0}" -eq 1 ]]; then
    SRC_TREE="$BUILD_DIR/zenoh-src"
    if [[ ! -d "$SRC_TREE/.git" ]]; then
        echo "build-zenohd: no cargo git checkout; cloning zenoh $ZENOHD_VERSION" >&2
        rm -rf "$SRC_TREE"
        mkdir -p "$(dirname "$SRC_TREE")"
        git clone --depth 1 --branch "$ZENOHD_VERSION" \
            https://github.com/eclipse-zenoh/zenoh "$SRC_TREE"
    fi
    ZH="$SRC_TREE"
fi

if [[ -n "$ZH" ]]; then
    # R311pj — assert the checkout's version matches the pinned ZENOHD_VERSION so
    # a cargo cache that later resolves a different zenoh fails fast here rather
    # than silently building a divergent reference router. Build --release so
    # source A and source B yield the SAME profile (one oracle identity).
    checkout_version="$(grep -m1 '^version' "$ZH/Cargo.toml" | cut -d'"' -f2)"
    echo "build-zenohd: source = cargo git checkout $ZH (version $checkout_version)" >&2
    if [[ "$checkout_version" != "$ZENOHD_VERSION" ]]; then
        echo "build-zenohd: checkout version $checkout_version != pinned ZENOHD_VERSION=$ZENOHD_VERSION" >&2
        echo "  set ZENOHD_VERSION=$checkout_version, or ZENOHD_FORCE_CRATES_IO=1 for the crates.io path." >&2
        exit 1
    fi
    echo "build-zenohd: building zenohd (release, +$TOOLCHAIN)${VARIANT_NAME:+ [+$VARIANT_NAME]} ..." >&2
    # shellcheck disable=SC2086  # VARIANT_FEATURE is an intentional word-split flag
    CARGO_TARGET_DIR="$BUILD_DIR" cargo "+$TOOLCHAIN" build -p zenohd --release \
        $VARIANT_FEATURE --manifest-path "$ZH/Cargo.toml"
    SRC_BIN="$BUILD_DIR/release/zenohd"
    # R311wo (A10) — also build the storage-manager plugin (cdylib) from the SAME
    # checkout, so its ABI-compat hash (zenoh version + rustc) matches the zenohd
    # binary and zenohd loads it via `--plugin`. The storage replication interop
    # test (wz_zenohd_storage_replication.rs) needs it. Only source A can produce
    # the cdylib: `cargo install` (source B) yields binaries, not the plugin .so,
    # so a crates.io build leaves it absent and the interop test SKIPs.
    # A transport variant (unixpipe / vsock) is a transport-only interop oracle — it
    # does NOT need the storage-manager plugin (the A10 storage test uses the default
    # oracle), so skip the extra cdylib build for it.
    if [[ -n "$VARIANT_FEATURE" ]]; then
        SO_SRC=""
        REST_SO_SRC=""
        EXT_EXAMPLES_SRC=""
        CORE_EXAMPLES_SRC=""
    else
        echo "build-zenohd: building zenoh-plugin-storage-manager (release) ..." >&2
        CARGO_TARGET_DIR="$BUILD_DIR" cargo "+$TOOLCHAIN" build \
            -p zenoh-plugin-storage-manager --release --manifest-path "$ZH/Cargo.toml"
        SO_SRC="$BUILD_DIR/release/libzenoh_plugin_storage_manager.so"
        # R311y501 — and the REST plugin cdylib, the foreign oracle for §5.26
        # (rest-http-bridge / rest-sse-subscribe). zenohd accepts
        # `--rest-http-port` UNCONDITIONALLY — the flag is a zenohd CLI option,
        # not a capability probe — but without this `.so` it dies at startup with
        # "Plugin load failure: Library file 'libzenoh_plugin_rest.so' not found".
        # So the flag's presence in `--help` is NOT evidence the oracle exists;
        # only this build is. Same source tree as zenohd itself, so its
        # ABI-compat hash matches and the auto-load (search_dirs includes
        # `current_exe_parent`) resolves it beside the installed binary.
        echo "build-zenohd: building zenoh-plugin-rest (release) ..." >&2
        CARGO_TARGET_DIR="$BUILD_DIR" cargo "+$TOOLCHAIN" build \
            -p zenoh-plugin-rest --release --manifest-path "$ZH/Cargo.toml"
        REST_SO_SRC="$BUILD_DIR/release/libzenoh_plugin_rest.so"
        # R311y442 — also build the zenoh-ext ADVANCED-PUBSUB example binaries from
        # the SAME checkout. They are the only foreign counterparty the `@adv` legs
        # can have: zenohd is a router and holds no AdvancedCache, and zenoh-pico
        # has no advanced-pubsub plane at all, so the cache only exists inside an
        # APPLICATION built on zenoh-ext — which is what these examples are.
        # `zenoh-ext-examples` depends on zenoh-ext with `unstable`, and that is
        # load-bearing rather than incidental: `Query::_reply_sample` only honours
        # `_anyke` under `zenoh/unstable` (`zcondfeat!`), so a build without it
        # would refuse every `@adv` reply regardless of what the querier sent and
        # the oracle would "fail" identically for a conformant and a broken wz.
        # Only source A can produce them, exactly as for the plugin cdylib above.
        # R311y445 — z_view_size joins them, for the GROUP-MEMBERSHIP family. Its
        # sibling z_member is unusable as an oracle: it builds `Config::default()`
        # with no CommonArgs, so it cannot be pointed at a zenohd with `-e` and
        # would depend on multicast scouting. z_view_size takes the full CommonArgs
        # AND prints a decisive verdict ("Established view size of N with members:"
        # vs "Failed to establish view size of N"), which is what lets a leg assert
        # that a FOREIGN implementation actually decoded wz's Join/KeepAlive.
        echo "build-zenohd: building zenoh-ext examples (z_advanced_pub/sub, z_view_size) ..." >&2
        CARGO_TARGET_DIR="$BUILD_DIR" cargo "+$TOOLCHAIN" build \
            -p zenoh-ext-examples --example z_advanced_pub --example z_advanced_sub \
            --example z_view_size \
            --release --manifest-path "$ZH/Cargo.toml"
        EXT_EXAMPLES_SRC="$BUILD_DIR/release/examples"
        # R311y841 — the CORE `zenoh-examples` query pair, for the same reason
        # the ext pair above exists: the counterparty a leg needs does not exist
        # in any oracle already provisioned. zenohd is a router and declares no
        # queryable of its own, and zenoh-pico's `z_queryable` hardcodes the
        # DEFAULT `complete = false` (`_Z_QUERYABLE_COMPLETE_DEFAULT`,
        # `session/queryable.h:42`) with no flag to change it — so neither can
        # play a COMPLETE queryable, which is precisely what a `QueryTarget`
        # route selects on. `z_queryable --complete` and `z_get --target` are the
        # only foreign binaries in existence that can drive both sides of that
        # decision. Same source-A-only constraint as the ext examples.
        echo "build-zenohd: building zenoh core examples (z_queryable, z_get) ..." >&2
        CARGO_TARGET_DIR="$BUILD_DIR" cargo "+$TOOLCHAIN" build \
            -p zenoh-examples --example z_queryable --example z_get \
            --release --manifest-path "$ZH/Cargo.toml"
        CORE_EXAMPLES_SRC="$BUILD_DIR/release/examples"
    fi
else
    # A transport variant CANNOT come from source B: `cargo install` builds the
    # published binary and cannot add `zenoh/$VARIANT_NAME`, so a crates.io zenohd has
    # no such transport. Require a source build.
    if [[ -n "$VARIANT_FEATURE" ]]; then
        echo "build-zenohd: a variant build (zenoh/$VARIANT_NAME) needs a SOURCE build" >&2
        echo "  (crates.io cannot add a dependency feature). Set ZENOHD_ALLOW_CLONE=1 (or" >&2
        echo "  provide a cargo git checkout) and re-run." >&2
        exit 1
    fi
    # Source B — deterministic crates.io install (fresh-clone reproducible).
    # --locked pins to the published Cargo.lock; --root keeps the install tree
    # inside target/ so it is git-ignored and clean-able like any build output.
    echo "build-zenohd: no cargo git checkout found (or forced); installing" >&2
    echo "  zenohd@$ZENOHD_VERSION from crates.io (release, +$TOOLCHAIN, --locked) ..." >&2
    cargo "+$TOOLCHAIN" install "zenohd@$ZENOHD_VERSION" --locked \
        --root "$BUILD_DIR/cargo-install" --bin zenohd
    SRC_BIN="$BUILD_DIR/cargo-install/bin/zenohd"
    # No plugin cdylib from `cargo install`; the A10 interop test SKIPs without it.
    SO_SRC=""
    REST_SO_SRC=""
    # Nor the zenoh-ext examples: `cargo install` publishes zenohd's binaries only.
    EXT_EXAMPLES_SRC=""
    # Nor the core zenoh examples, for the same reason.
    CORE_EXAMPLES_SRC=""
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$SRC_BIN" "$INSTALL_DIR/zenohd"
echo "build-zenohd: installed -> $INSTALL_DIR/zenohd" >&2
"$INSTALL_DIR/zenohd" --version 2>&1 | tail -1 >&2
if [[ -n "$SO_SRC" && -f "$SO_SRC" ]]; then
    install -m 0755 "$SO_SRC" "$INSTALL_DIR/libzenoh_plugin_storage_manager.so"
    echo "build-zenohd: installed -> $INSTALL_DIR/libzenoh_plugin_storage_manager.so" >&2
else
    echo "build-zenohd: storage-manager plugin NOT provisioned (source B / crates.io);" >&2
    echo "  the wz<->zenohd storage replication interop test will SKIP." >&2
fi
# R311y506 — INSTALL the REST plugin cdylib. R311y501 built it and assigned
# `REST_SO_SRC`, but no install step was ever written, so the variable was dead
# (shellcheck SC2034, a Layer 0 red that had been reported as a lint) and the
# `.so` never reached the oracle directory. The copy present on this machine was
# placed there by hand, which is why the §5.26 legs passed while a FRESH clone
# would have paid for the build and then had zenohd die at startup with exactly
# the "Library file 'libzenoh_plugin_rest.so' not found" the build comment above
# warns about. The lint was pointing at the defect, not at style.
if [[ -n "$REST_SO_SRC" && -f "$REST_SO_SRC" ]]; then
    install -m 0755 "$REST_SO_SRC" "$INSTALL_DIR/libzenoh_plugin_rest.so"
    echo "build-zenohd: installed -> $INSTALL_DIR/libzenoh_plugin_rest.so" >&2
else
    echo "build-zenohd: REST plugin NOT provisioned (variant / source B);" >&2
    echo "  a zenohd started with --rest-http-port will fail to load it." >&2
fi
if [[ -n "$EXT_EXAMPLES_SRC" ]]; then
    for ex in z_advanced_pub z_advanced_sub z_view_size; do
        install -m 0755 "$EXT_EXAMPLES_SRC/$ex" "$INSTALL_DIR/$ex"
        echo "build-zenohd: installed -> $INSTALL_DIR/$ex" >&2
    done
else
    echo "build-zenohd: zenoh-ext examples NOT provisioned (variant or source B);" >&2
    echo "  the wz<->zenoh-ext advanced-pubsub interop legs cannot run." >&2
fi
if [[ -n "$CORE_EXAMPLES_SRC" ]]; then
    for ex in z_queryable z_get; do
        install -m 0755 "$CORE_EXAMPLES_SRC/$ex" "$INSTALL_DIR/zenoh_$ex"
        echo "build-zenohd: installed -> $INSTALL_DIR/zenoh_$ex" >&2
    done
else
    echo "build-zenohd: zenoh core examples NOT provisioned (variant or source B);" >&2
    echo "  the wz<->zenoh QueryTarget interop legs cannot run." >&2
fi

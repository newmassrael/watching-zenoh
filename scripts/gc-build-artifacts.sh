#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# gc-build-artifacts.sh — BUILD-AWARE garbage collection of crates/target.
#
# Wraps a build command and keeps exactly what that build TOUCHED, deleting
# everything else. The wrapper does NOT change directory, so the command must be
# spelled the way it would be run by hand:
#
#     bash scripts/gc-build-artifacts.sh -- bash scripts/run-ci.sh
#     (cd crates && bash ../scripts/gc-build-artifacts.sh -- cargo test -p wz)
#
# Sweeping after a FULL run-ci is the intended use: that run compiles the widest
# feature surface this repo has, so what survives is the union every lane needs.
# Sweeping after a single narrow `cargo test` is legal but expensive — it keeps
# only that one combination and the next lane rebuilds from scratch.
#
# ## Why not `--time N`
#
# The obvious form is `cargo sweep --time 7`, and it does not work here. This
# workspace's target is dominated by `debug/deps`, and run-ci rebuilds it under
# dozens of feature combinations, so on any day work happened almost every
# artifact has a fresh mtime. Measured 2026-07-29 with target/debug at 62G:
# `cargo sweep --dry-run -t 3` reported "Would clean: nothing", while
# `--maxsize 25` reported 65.19 GiB — i.e. the time window either keeps
# everything or, shortened until it bites, starts deleting artifacts the NEXT
# build still needs. Both failure modes are silent.
#
# The stamp/file pair replaces the mtime GUESS with a fact. `--stamp` writes a
# timestamp before the build; `--file` then deletes every artifact older than
# it. What survives is precisely what the wrapped build read or wrote, so the
# next identical build is a cache hit and nothing else is retained.
#
# ## Why a wrapper rather than two subcommands
#
# Because the failure mode of the split form is expensive and quiet: running
# `--file` without a preceding `--stamp` (or with a stale one) sweeps artifacts
# the last build DID need, turning the next build into a full rebuild. Binding
# the two halves to one invocation makes that unrepresentable rather than
# documented.
#
# ## A FAILED build does not get swept
#
# The sweep is skipped unless the build exits 0, and this is load-bearing rather
# than cautious. The stamp defines "keep what this build touched", so a build
# that touched NOTHING makes the whole target sweepable. Measured while writing
# this script: invoking it with a cargo command from the wrong directory made
# the build die instantly with "could not find Cargo.toml", and the sweep then
# reported 65.40 GiB — the entire target — as removable. A wrapper whose
# argv typo wipes the build cache is worse than no wrapper. Only a build that
# ran to completion has a trustworthy touch set.
#
# The build's exit status is always preserved.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# The cargo workspace lives in crates/, and so does its target dir.
PROJECT_DIR="$REPO_ROOT/crates"

usage() {
    cat >&2 <<'EOF'
usage: gc-build-artifacts.sh [--dry-run] --installed
       gc-build-artifacts.sh [--dry-run] -- <build command> [args...]

  --installed  TOOLCHAIN mode: keep artifacts of every rustup toolchain still
               installed, delete the rest. Cheap (~1s), safe, and REBUILD-FREE,
               so it is the form to run habitually / from a hook. It reclaims
               nothing until a toolchain is actually removed.

  -- <cmd>     BUILD mode: stamp, run the build, then delete everything that
               build did not touch. Reclaims far more, but only what the wrapped
               build needs survives — so wrap a FULL run-ci, not one lane.

  --dry-run    report what would be deleted, delete nothing
EOF
}

DRY_RUN=""
MODE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN="--dry-run"; shift ;;
        --installed) MODE="installed"; shift ;;
        --) MODE="build"; shift; break ;;
        -h|--help) usage; exit 0 ;;
        *) echo "gc-build-artifacts: unexpected argument '$1' (did you forget '--'?)" >&2
           usage; exit 2 ;;
    esac
done

if [[ -z "$MODE" ]]; then
    echo "gc-build-artifacts: pick a mode: --installed, or -- <build command>" >&2
    usage
    exit 2
fi
if [[ "$MODE" == "build" && $# -eq 0 ]]; then
    echo "gc-build-artifacts: no build command given after '--'" >&2
    usage
    exit 2
fi

# A GC that cannot read its own input must not report success — the same rule
# the schema-pin gate follows. Without cargo-sweep the wrapper would run the
# build and silently collect nothing, which reads as "the target is now tidy".
if ! cargo sweep --help >/dev/null 2>&1; then
    echo "gc-build-artifacts: cargo-sweep not available." >&2
    echo "  install with: cargo install cargo-sweep" >&2
    exit 1
fi

if [[ "$MODE" == "installed" ]]; then
    # Toolchain mode. Nothing to wrap and nothing to rebuild afterwards: every
    # artifact of a still-installed toolchain survives, so this is safe to run
    # unconditionally and cheap enough for a hook (measured 2026-07-29 on a 63G
    # target: 3.8s for a real sweep, 1.1s for --dry-run).
    #
    # It reclaims nothing until a toolchain is REMOVED — measured on this
    # machine the same day: six toolchains installed, "Would clean: nothing",
    # while target/debug/deps alone was 58G. That 58G is feature-combination
    # accumulation from run-ci's lanes, not old-rustc residue, and only BUILD
    # mode reaches it. Keep both; they collect different garbage.
    #
    # No `du` around this arm, deliberately: cargo-sweep already reports what it
    # removed, and `du -sh` on a 63G target costs MORE than the sweep it would be
    # annotating (measured: sweep 1.29s, the pair of du calls took the wrapper to
    # 4.63s). BUILD mode keeps them — there the sweep is the slow part and the
    # before/after is the point.
    # shellcheck disable=SC2086  # DRY_RUN is a deliberate optional flag word
    cargo sweep $DRY_RUN --installed "$PROJECT_DIR" >&2 || {
        echo "gc-build-artifacts: sweep failed" >&2
        exit 1
    }
    exit 0
fi

before="$(du -sh "$PROJECT_DIR/target" 2>/dev/null | cut -f1)"
echo "gc-build-artifacts: target before = ${before:-<absent>}" >&2

echo "gc-build-artifacts: stamping $PROJECT_DIR ..." >&2
if ! cargo sweep --stamp "$PROJECT_DIR" >&2; then
    echo "gc-build-artifacts: could not write the stamp; refusing to sweep" >&2
    exit 1
fi

echo "gc-build-artifacts: running: $*" >&2
"$@"
build_rc=$?
echo "gc-build-artifacts: build exited $build_rc" >&2

if [[ $build_rc -ne 0 ]]; then
    echo "gc-build-artifacts: build FAILED — skipping the sweep." >&2
    echo "  A build that did not complete has no trustworthy touch set: sweeping" >&2
    echo "  on it can mark the whole target removable (measured: a wrong-directory" >&2
    echo "  cargo invocation made 65.40 GiB sweepable). Fix the build, re-run." >&2
    exit "$build_rc"
fi

# Never let the sweep's own status mask the build's.
echo "gc-build-artifacts: sweeping artifacts the build did not touch ..." >&2
# shellcheck disable=SC2086  # DRY_RUN is a deliberate optional flag word
cargo sweep $DRY_RUN --file "$PROJECT_DIR" >&2 || {
    echo "gc-build-artifacts: sweep failed" >&2
    exit "$build_rc"
}

after="$(du -sh "$PROJECT_DIR/target" 2>/dev/null | cut -f1)"
echo "gc-build-artifacts: target after  = ${after:-<absent>} (was ${before:-<absent>})" >&2

exit "$build_rc"

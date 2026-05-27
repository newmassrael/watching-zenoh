#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# run-ci.sh — CI-equivalent local check.
#
# Single source of truth for the gate-set the GitHub Actions
# workflow runs. Both `.github/workflows/ci.yml` and the local
# `.githooks/pre-push` hook invoke this script so the two paths
# cannot drift (R64.1 retrospect: a CI yaml change without local
# verification land-then-fail pattern is exactly what this script
# prevents).
#
# Lanes (matches CI workflow):
#
#   Layer A  — mnemosyne-cli validate-workspace
#   Layer A2 — scripts/audit-mid-values.sh (envelope mid value= gate; R111)
#   Layer B  — verify-codegen.sh per codec (L1+L2+L3)
#   Layer C0 — binary-dep test #[ignore] discipline pre-flight
#              (R235-hotfix; rejects new e2e tests that would panic
#              Layer C1 on fresh CI checkouts)
#   Layer C1 — cargo test --workspace
#   Layer C1b — cargo test -p wz-runtime-core --features alloc
#              (R269; the workspace lane uses default features so the
#              alloc-gated panic_payload tests would otherwise never
#              run in CI — see crates/wz-runtime-core/Cargo.toml)
#   Layer C2 — cargo clippy --workspace --all-targets -- -D warnings
#   Layer D  — deploy/*.yaml schema validate
#   Layer E  — binary-dep e2e suite via `cargo test ... -- --ignored`
#              (auto-includes every #[ignore]-marked test in the
#              wz-integration-tests crate; wz-ap-demo + zenoh-pico CLI
#              must be built first or the lane SKIPs gracefully)
#   Layer 0  — preflight lints: cargo fmt --check (mandatory) +
#              actionlint (optional, SKIPs if not installed). The
#              fmt gate is mandatory because R285–R287 wz-ap-demo
#              decomposition merged without local fmt enforcement
#              and the workspace accumulated multi-hundred-KB drift
#              before R291 caught it; the gate here prevents that
#              recurrence by failing pre-push if rustfmt would
#              reformat any tracked file.
#   Layer F  — codec-footprint catalog truthfulness gate (R311n).
#              Opt-in via `--layer F` or `WZ_RUN_LAYER_F=1`. Runs
#              scripts/measure-codec-footprint.sh and exits non-zero
#              if any codec-* atomic feature's minus-<codec> lane
#              measures a near-zero elision delta (default threshold
#              1 KB). Catches the catalog-truthfulness regression
#              shape where a new high-level consumer feature is
#              added without listing it in the implies graph and
#              cargo's resolver silently re-enables the codec the
#              lane was trying to elide. The bench is expensive
#              (~5-10 min cold; multiple wz-ap-demo release builds)
#              so it stays off the default dispatch path; run it
#              explicitly when authoring a codec cascade.
#   Layer G  — MCU cross-compile catalog (Phase W). Opt-in via
#              `--layer G` or `WZ_RUN_LAYER_G=1`. Catalog matrix =
#              (crate × target):
#                Crates:
#                  G.1 (R311ak) wz-runtime-core — §5.P trait skeleton
#                  G.2 (R311am) wz facade no_std cfg_attr toggle
#                  G.3 (R311aq) wz-codecs no_std + alloc — codec wire
#                  G.4 (R311au) wz-runtime-lwip — sync alias #![no_std]
#                  G.4-alloc (R311av) wz-runtime-lwip --features alloc
#                                 (LwipRuntime + impl Runtime + LwipTime)
#                                 R311bb closed M0+ via portable-atomic
#                                 polyfill — thumbv6m now lands.
#                  G.5 (R311ax) wz facade --features runtime-lwip
#                                 (composes wz-runtime-lwip through the
#                                 public facade surface; M0+ lands too
#                                 post-R311bb).
#                  G.6 (R311az-3c) WZ_LWIP_PORT cross-real lane —
#                                 lwip-sys + wz-link-lwip + wz facade
#                                 with cross-test port supplied as
#                                 WZ_LWIP_PORT (real lwIP C cross-build
#                                 + lwip_real_build cfg flips on).
#                                 SKIPs riscv32imac (toolchain not
#                                 installed on the local dev machine).
#                Targets (R311ao + R311ap portability widening):
#                  thumbv7em-none-eabihf  (Cortex-M4F/M7, original R311ak)
#                  thumbv6m-none-eabi     (Cortex-M0+)
#                  thumbv7m-none-eabi     (Cortex-M3)
#                  thumbv8m.base-none-eabi    (Cortex-M23, ARMv8-M Base)
#                  thumbv8m.main-none-eabi    (Cortex-M33/M55 soft-float)
#                  thumbv8m.main-none-eabihf  (Cortex-M33/M55 hard-float)
#                  riscv32imac-unknown-none-elf (RISC-V 32-bit IMAC)
#              Per-target SKIP if the rustup target is not installed
#              (no auto-install — keeps a developer machine without
#              cross-compile interest free of the lane). Stays opt-in
#              until the wz-runtime-lwip caller lands (R311an+);
#              promotes to default lane at that point.
#              Out of scope today: zenoh-pico-sys (arm-none-eabi-gcc
#              install carry, R311ao+). R40 wz-codecs carry resolved
#              by R311aq — codec wire encode/decode now cross-compiles
#              via the alloc-prelude shim in wz-codecs/src/lib.rs;
#              hosted callers see no behavioural delta.
#   Layer Q  — QEMU mps2-an386 UDP loopback e2e demo run (R311be).
#              Opt-in via `--layer Q` or `WZ_RUN_LAYER_Q=1`. Three
#              sub-lanes:
#                Q.1 build  cargo build --release for thumbv7m-none-
#                           eabi of deploy/mcu-qemu-demo with
#                           WZ_LWIP_PORT set to the cross-test port.
#                           Requires thumbv7m-none-eabi rustup target
#                           + arm-none-eabi-gcc.
#                Q.2 run    qemu-system-arm boots the built ELF and
#                           asserts on the semihost SYS_EXIT exit
#                           code (PASS=0 / FAIL=1). Requires
#                           qemu-system-arm; SKIPs if absent.
#                Q.3 footprint (R311bl) — `arm-none-eabi-size` on
#                           the built ELF asserts text + data stay
#                           within ±256 bytes of the R311bj caveat
#                           baseline. Per target-triple (not per
#                           machine) since same-triple machines emit
#                           byte-identical binaries; deduped on the
#                           first sub-lane that built a given triple.
#                           SKIPs if `arm-none-eabi-size` is absent.
#                           Composable-framework footprint regression
#                           mechanical gate — silent ROM creep caught
#                           at the Layer Q invocation that introduced
#                           it instead of surfacing rounds later when
#                           someone reads the §6.7 caveat.
#              Each sub-lane SKIPs gracefully on toolchain absence.
#              Phase W ladder FULL closure mantissa: composable-
#              framework MCU stack RUNS on a non-host target end-to-
#              end (wz facade + runtime-lwip + LwipRuntime timer
#              queue + LwipJoinHandle::abort + wz-link-lwip UDP raw
#              API + lwip-sys cross-real C build, all in one
#              binary).
#
# Exit codes:
#   0  every required layer passed
#   1  one or more required layers failed
#   2  setup error (sce-codegen binary missing, wrong cwd, etc.)
#
# Usage:
#   scripts/run-ci.sh                  # full CI mirror
#   scripts/run-ci.sh --skip-codegen   # skip Layer B (codec emit; ~30s/codec)
#   scripts/run-ci.sh --layer A        # run only the named layer
#
# Time cost (warm cache):
#   Layer 0: <2s   A: <1s   B: ~30s   C1: ~10s   C2: ~5s   D: <1s
#   Total ~50s on incremental build, ~5min on cold compile.

set -uo pipefail

# ─── argument parsing ──────────────────────────────────────────────
SKIP_CODEGEN=0
ONLY_LAYER=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-codegen) SKIP_CODEGEN=1; shift ;;
        --layer)
            ONLY_LAYER="$2"
            shift 2
            ;;
        --help|-h)
            sed -n '1,/^set -uo pipefail/p' "$0" | sed '$d' | grep -E "^#"
            exit 0
            ;;
        *)
            echo "run-ci: unknown arg '$1'" >&2
            exit 2
            ;;
    esac
done

# ─── cwd discovery ─────────────────────────────────────────────────
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$repo_root" ]]; then
    echo "run-ci: must be invoked from within a git checkout of watching-zenoh" >&2
    exit 2
fi
cd "$repo_root"

# ─── layer runner helpers ──────────────────────────────────────────
run_layer() {
    local name="$1"
    shift
    if [[ -n "$ONLY_LAYER" && "$ONLY_LAYER" != "$name" ]]; then
        return 0
    fi
    echo "──── Layer $name ────"
    if "$@"; then
        echo "Layer $name pass"
        return 0
    else
        echo "Layer $name FAIL" >&2
        return 1
    fi
}

# ─── Layer 0 — preflight lints (fmt mandatory + actionlint optional) ──
#
# R291: cargo fmt --check is promoted into Layer 0 as a mandatory
# preflight gate. Rationale — R285→R287 wz-ap-demo decomposition
# pushed multi-hundred-KB of fmt drift onto main without local
# rejection because the prior Layer 0 only carried optional
# actionlint and no lane invoked rustfmt at all. The mandatory
# fmt gate here is exactly the R64.1 single-source-of-truth
# invariant applied to rustfmt: the same gate fires locally
# (pre-push hook) and remotely (.github/workflows/ci.yml), so a
# fmt-dirty commit cannot reach origin/main again.
#
# actionlint stays optional (SKIP if not installed) — yaml workflow
# lint is a nice-to-have, not a correctness gate.
layer_0_preflight_lints() {
    # 0.1 cargo fmt --check (mandatory)
    if ! (cd crates && cargo fmt --all -- --check); then
        echo "  fmt --check FAIL — run \`(cd crates && cargo fmt --all)\` to fix" >&2
        return 1
    fi
    echo "  fmt --check OK"

    # 0.2 actionlint (optional)
    if ! command -v actionlint >/dev/null 2>&1; then
        echo "  actionlint SKIP (not installed; install: go install github.com/rhysd/actionlint/cmd/actionlint@latest)"
        return 0
    fi
    actionlint .github/workflows/*.yml
}

# ─── Layer A — mnemosyne validate-workspace ─────────────────────────
layer_a_mnemosyne() {
    if ! command -v mnemosyne-cli >/dev/null 2>&1; then
        echo "Layer A SKIP (mnemosyne-cli not on PATH)"
        return 0
    fi
    mnemosyne-cli validate-workspace
}

# ─── Layer A2 — envelope mid value= audit gate (R111) ───────────────
# Rejects any sources/codecs/*.scxml whose envelope-level <sce:flag
# name="mid"> declaration lacks `value=`. Precedent: R108a discovered
# a latent defect (request.scxml had no mid value= since R90; wire
# first byte emitted as 0x40 instead of 0x5C) that the wz-side round-
# trip pass kept invisible until R108b's Layer 3 wire-compare against
# zenoh-pico's `_z_request_encode`. The audit script is a build-time
# preventer for that whole class of defect.
layer_a2_audit_mid_values() {
    bash scripts/audit-mid-values.sh
}

# ─── Layer B — verify-codegen.sh per codec ──────────────────────────
layer_b_verify_codegen() {
    if [[ $SKIP_CODEGEN -eq 1 ]]; then
        echo "Layer B SKIP (--skip-codegen)"
        return 0
    fi
    if [[ ! -x vendor/sce/target/release/sce-codegen ]]; then
        echo "Layer B SKIP (sce-codegen not built; run scripts/build-sce.sh)"
        return 0
    fi

    # R114 sce-codegen freshness gate. The vendor pin moves
    # whenever R<X> bumps vendor/sce; if the local sce-codegen
    # binary was built against an older pin, verify-codegen.sh
    # silently uses the stale binary and Layer 2 reports
    # spurious match/mismatch results. The R112 -> R114 GitHub
    # Actions failure (msg_del/query/request rust+cpp mismatch
    # on a green local pre-push) traced to exactly this stale-
    # binary path: timestamp 2026-05-18 00:00 (pre-R112 build)
    # against R112 vendor pin checkout. The gate below compares
    # the vendor/sce HEAD commit time to the binary mtime and
    # auto-rebuilds if the binary is older — same effect as the
    # CI's clean-build path, but no manual `bash scripts/build-
    # sce.sh` needed in the developer loop.
    local sce_head_epoch
    sce_head_epoch="$(git -C vendor/sce log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
    local bin_mtime_epoch
    bin_mtime_epoch="$(stat -c '%Y' vendor/sce/target/release/sce-codegen 2>/dev/null || echo 0)"
    if [[ "$sce_head_epoch" -gt 0 && "$bin_mtime_epoch" -gt 0 \
          && "$bin_mtime_epoch" -lt "$sce_head_epoch" ]]; then
        echo "Layer B: sce-codegen stale (built $(date -d @$bin_mtime_epoch +%F) vs pin $(date -d @$sce_head_epoch +%F)); rebuilding"
        bash scripts/build-sce.sh >/dev/null 2>&1 || {
            echo "Layer B FAIL: sce-codegen rebuild failed" >&2
            return 1
        }
    fi

    declare -A SCE_UPSTREAM=(
        ["crc16_ccitt"]="vendor/sce/tests/forge/resources/algorithm_crc16.scxml"
        ["keep_alive"]="vendor/sce/tests/forge/resources/codec_zenoh_keep_alive.scxml"
        ["close"]="vendor/sce/tests/forge/resources/codec_variant_session_close.scxml"
        ["frame"]="vendor/sce/tests/forge/resources/codec_zenoh_frame.scxml"
        ["fragment"]="vendor/sce/tests/forge/resources/codec_zenoh_fragment.scxml"
        ["locator"]="vendor/sce/tests/forge/resources/codec_zenoh_locator.scxml"
        ["timestamp"]="vendor/sce/tests/forge/resources/codec_zenoh_timestamp.scxml"
        ["encoding"]="vendor/sce/tests/forge/resources/codec_zenoh_encoding.scxml"
        ["ext_unit"]="vendor/sce/tests/forge/resources/codec_zenoh_ext_unit.scxml"
        ["ext_zint"]="vendor/sce/tests/forge/resources/codec_zenoh_ext_zint.scxml"
        ["ext_zbuf"]="vendor/sce/tests/forge/resources/codec_zenoh_ext_zbuf.scxml"
        ["ext_entry"]="vendor/sce/tests/forge/resources/codec_zenoh_ext_entry.scxml"
        ["ext_envelope"]="vendor/sce/tests/forge/resources/codec_zenoh_ext_envelope.scxml"
        ["scout"]="vendor/sce/tests/forge/resources/codec_zenoh_scout.scxml"
        ["hello"]="vendor/sce/tests/forge/resources/codec_zenoh_hello.scxml"
        ["msg_put"]="vendor/sce/tests/forge/resources/codec_zenoh_msg_put.scxml"
        ["msg_del"]="vendor/sce/tests/forge/resources/codec_zenoh_msg_del.scxml"
        ["wireexpr"]="vendor/sce/tests/forge/resources/codec_zenoh_wireexpr.scxml"
        ["query"]="vendor/sce/tests/forge/resources/codec_zenoh_query.scxml"
        ["request"]="vendor/sce/tests/forge/resources/codec_zenoh_request.scxml"
        ["open_body"]="vendor/sce/tests/forge/resources/codec_zenoh_open_body.scxml"
    )
    # Intentional divergences from SCE upstream fixtures. Each entry's
    # wz-side rationale lives in the matching sources/codecs/*.scxml
    # header comment (search for "Deliberate divergence from SCE
    # upstream"). Layer 2 reports MISMATCH for these pairs and the
    # report is correct — these are audit-traced wire-correctness
    # improvements that SCE upstream has not yet mirrored.
    #
    # R122 closure (vendor pin 122f851d → 4441431d): SCE commit
    # 71357264 "align Zenoh codec wire bytes to zenoh-pico HEAD"
    # reverse-merged five wire-shape patches upstream — init_body /
    # join (R44 endian) + msg_del / query (R88 mid value= baking) +
    # msg_put (R88 family / R114 defense-in-depth) all flipped from
    # MISMATCH to OK on the new pin. SCE root-cause: validator
    # validate_cross_codec_variant_default_arm only checked the
    # default arm; non-default arms produced silent wire-wrong bytes
    # on standalone encode. Validator renamed to
    # validate_cross_codec_variant_arm_mids (all arms iterated).
    #
    # Residual carry (R123 follow-up; R125c2 update):
    #
    #   request — R88 arm 0x03 default + R108a mid value=0x1C are
    #             still divergences (R114 → R123b follow-up). The
    #             R106 M=1 baking is RETRACTED in R125c2 because
    #             wireexpr.scxml is now a B5-ν parent-tag variant
    #             dispatcher (SCE vendor pin b35dbb66) and the M
    #             bit is derived from the selected arm rather than
    #             statically baked. SCE Q-3 cross-doc validator
    #             forbids derivation + static-value coexistence so
    #             the R106 baking had to go once the dispatcher
    #             landed.
    #
    #   wireexpr — R125c2 restructure into a parent-tag variant
    #             dispatcher (B5-ν Phase B substrate; SCE atomic
    #             b35dbb66 closed all six gaps surfaced in the
    #             R125c → R125c1 → R125c2 sequence). SCE upstream
    #             codec_zenoh_wireexpr fixture is still the pre-
    #             B5-ν flat leaf shape, so wz's wireexpr stem no
    #             longer body-matches SCE. Production-correct
    #             adoption sequence terminus for SCE's B5-ν; SCE
    #             upstream needs to lift its leaf into the same
    #             dispatch shape to clear this entry. Layer 3
    #             (crates/wz-integration-tests/tests/
    #             layer3_wireexpr_{local,nonlocal}.rs) is the real
    #             wire-interop check carried to R125e.
    local LAYER2_KNOWN_DIVERGENCE=(request wireexpr)

    local fail=0
    for scxml in sources/codecs/*.scxml sources/algorithms/*.scxml; do
        local stem
        stem="$(basename "$scxml" .scxml)"
        local upstream="${SCE_UPSTREAM[$stem]:-}"
        local extra=()
        [[ -n "$upstream" && -f "$upstream" ]] && extra=("$upstream")

        if bash scripts/verify-codegen.sh "$scxml" "${extra[@]}" >/dev/null 2>&1; then
            echo "  $stem OK"
        else
            if [[ " ${LAYER2_KNOWN_DIVERGENCE[*]} " == *" $stem "* ]]; then
                echo "  $stem L2 MISMATCH (audit-traced KNOWN_DIVERGENCE)"
                bash scripts/verify-codegen.sh "$scxml" >/dev/null 2>&1 || fail=1
            else
                echo "  $stem FAIL" >&2
                bash scripts/verify-codegen.sh "$scxml" "${extra[@]}" || true
                fail=1
            fi
        fi
    done
    return $fail
}

# ─── Layer C0 — binary-dep test discipline pre-flight ───────────────
# R235-hotfix: Layer C1 runs `cargo test --workspace` which fans
# every `#[test]` fn in `crates/wz-integration-tests/tests/`. Tests
# that spawn the wz-ap-demo binary or a zenoh-pico CLI binary panic
# with "binary not found" when those artifacts are not yet built —
# on the local developer machine the cached binaries usually exist
# so the panic stays hidden, but a fresh CI checkout has empty
# `target/` and the cargo test --workspace lane fails before the
# "Build wz-ap-demo binary (Layer E dep)" step ever runs.
#
# The discipline fix is to mark every binary-dep test with
# `#[ignore = "..."]` so Layer C1 skips them and Layer E picks them
# up via `cargo test ... -- --ignored`. Layer C0 enforces the
# discipline mechanically: any test file that calls
# `wz_ap_demo_binary()` or `zenoh_pico_cli_binary(` MUST pair every
# `#[test]` with an adjacent `#[ignore]` (next non-blank line). A
# violation fails the lane with a file:line pointer and a copy-
# pastable fix line.
#
# Runs before Layer C1 in the dispatch order so a developer who
# adds a new e2e test without #[ignore] sees a fast localised
# failure instead of waiting for the full cargo test --workspace
# panic message.
layer_c0_test_discipline() {
    local exit_code=0
    local violations_count=0
    while IFS= read -r f; do
        if ! grep -q 'wz_ap_demo_binary()\|zenoh_pico_cli_binary(' "$f"; then
            continue
        fi
        local report
        report=$(awk '
            /^#\[test\]/ {
                test_count++
                test_line = NR
                if ((getline next_line) > 0 && next_line ~ /^#\[ignore/) {
                    next
                }
                print FILENAME ":" test_line ": #[test] missing adjacent #[ignore]"
            }
        ' "$f")
        if [[ -n "$report" ]]; then
            echo "$report" >&2
            violations_count=$((violations_count + 1))
            exit_code=1
        fi
    done < <(find crates/wz-integration-tests/tests -maxdepth 1 -name '*.rs' | sort)

    if [[ $exit_code -ne 0 ]]; then
        echo "" >&2
        echo "Layer C0: $violations_count binary-dep test file(s) violate the" >&2
        echo "  #[test] + #[ignore] discipline. Layer C1 (cargo test" >&2
        echo "  --workspace) would panic on these on fresh CI checkouts" >&2
        echo "  where wz-ap-demo + zenoh-pico CLI binaries are not yet" >&2
        echo "  built (R235-hotfix root cause)." >&2
        echo "" >&2
        echo "Fix: add this line immediately after the offending #[test]:" >&2
        echo "  #[ignore = \"binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored\"]" >&2
        return 1
    fi
    return 0
}

# ─── Layer C1 — cargo test --workspace ──────────────────────────────
layer_c1_cargo_test() {
    (cd crates && cargo test --workspace --quiet)
}

# ─── Layer C1b — cargo test -p wz-runtime-core --features alloc ────
#
# wz-runtime-core's default features = [] (the crate must compile clean
# for MCU bare-metal where no heap exists). The 7 R266/R267
# panic_payload + Error-trait tests live behind `cfg(feature = "alloc")`
# because they construct `Box<dyn Any + Send>` payloads. Layer C1's
# `cargo test --workspace` runs each member crate with that member's
# OWN default features, so wz-runtime-core's test binary compiles with
# zero features and the alloc-gated mod is `cfg(false)` — i.e. the
# tests silently do not run. This lane runs them explicitly so the
# alloc-mode behaviour is gated in CI.
layer_c1b_cargo_test_alloc() {
    (cd crates && cargo test -p wz-runtime-core --features alloc --quiet)
}

# ─── Layer C2 — cargo clippy --deny warnings ────────────────────────
layer_c2_cargo_clippy() {
    (cd crates && cargo clippy --workspace --all-targets --quiet -- -D warnings)
}

# ─── Layer D — deploy yaml schema validate ──────────────────────────
layer_d_validate_deploy() {
    if ! python3 -c 'import yaml' >/dev/null 2>&1; then
        echo "Layer D SKIP (python3-yaml not installed)"
        return 0
    fi
    bash scripts/validate-deploy.sh
}

# ─── Layer E — wz-ap-demo bidirectional round-trip vs zenoh-pico ────
# R121c + R121e integration tests. Each test spawns the wz-ap-demo
# binary, points the matching zenoh-pico CLI at its TCP --listen
# endpoint, and asserts the round-trip witness line surfaces on the
# foreign side within a bounded timeout:
#
#   R121c (`ap_demo_round_trip.rs`):
#     z_put initiator → wz-ap-demo subscriber callback fires (hard
#     gate on the "SUBSCRIBER FIRED" stderr line; R121d closed the
#     four interop blockers that promoted this from optimistic
#     stretch goal to hard gate).
#
#   R121e (`wz_publisher_to_zsub.rs`):
#     wz-ap-demo publisher (`--publish demo/test --value
#     hello-from-wz`) → z_sub client receives the Push and
#     prints `>> [Subscriber] Received` on stdout. Hard gate on
#     the foreign-side stdout line plus belt-and-suspenders
#     assertions on the keyexpr + value substrings so a
#     wire-shape regression localises the failure.
#
# Both tests run in this single lane so the 8-lane CI structure
# stays intact; each is bounded to ~15s wall-clock so the lane
# total caps at ~30s on cold start (the gate fires in <500ms on
# a warm machine).
#
# Pre-requisites:
#   1. wz-ap-demo binary built (cargo build -p wz-ap-demo).
#   2. zenoh-pico CLI binaries built (scripts/build-zenoh-pico-cli.sh
#      produces target/zenoh-pico-cli/{z_put,z_sub,...}).
# Both are local-build artifacts. Layer E SKIPs gracefully when
# either is missing (developer running --layer E without prep) and
# surfaces the install hint instead of a hard failure.
layer_e_ap_demo_round_trip() {
    if [[ ! -x crates/target/debug/wz-ap-demo && ! -x crates/target/release/wz-ap-demo ]]; then
        echo "Layer E SKIP (wz-ap-demo not built; run: cd crates && cargo build -p wz-ap-demo)"
        return 0
    fi
    if [[ ! -x target/zenoh-pico-cli/z_put || ! -x target/zenoh-pico-cli/z_sub ]]; then
        echo "Layer E SKIP (zenoh-pico CLI not built; run: bash scripts/build-zenoh-pico-cli.sh)"
        return 0
    fi
    # R121e + R121f + R121f1 + R121g: bundle the integration tests
    # into a single cargo invocation so the compilation/link step
    # runs once and the lane timing stays predictable. `--test`
    # accepts multiple binary names. Five tests cover the full
    # AP MVP pubsub interop matrix:
    #   ap_demo_round_trip          — wz acceptor + sub vs z_put
    #   wz_publisher_to_zsub        — wz acceptor + pub vs z_sub
    #                                 (literal-keyexpr Push, R121e)
    #   wz_initiator_to_wz_acceptor — wz initiator + pub vs wz
    #   wz_initiator_to_zsub        — wz initiator + pub vs z_sub
    #                                 (peer-listen, R121f1 closure)
    #   wz_publisher_aliased_to_zsub — wz acceptor + pub vs z_sub
    #                                 with DECLARE-aliased Push
    #                                 (R121g — bandwidth-efficient
    #                                 repeated-keyexpr publisher
    #                                 shape; verifies DeclKexpr
    #                                 wire shape + peer keyexpr
    #                                 table population).
    # The R121g authoring round documented two wz-codec interop
    # hazards in `build_declare_kexpr`: the B5-ν derived 0x40 bit
    # for `WireexprLocal` must be suppressed (zenoh-pico's
    # DeclKexpr has no flag at bit 6), and `_Z_DECL_KEXPR_FLAG_N
    # (0x20)` must be author-set since the codec does not
    # auto-derive it from suffix presence. Both are pinned by the
    # unit-level wire-byte gate
    # (`build_declare_kexpr_emits_zenoh_pico_compatible_wire_bytes`)
    # and the integration test here.
    # R235-hotfix — every binary-dep test in
    # crates/wz-integration-tests/tests/ is marked `#[ignore = "..."]`
    # so Layer C1 (`cargo test --workspace`) skips them on fresh CI
    # checkouts where wz-ap-demo + zenoh-pico CLI are not built yet.
    # Layer C0 enforces the discipline as a pre-flight gate. Here
    # Layer E runs the ignored set via `-- --ignored`; new binary-dep
    # tests are auto-included as long as they keep the convention,
    # so the per-test `--test foo` list no longer needs hand-sync
    # with the actual fileset. The legacy R121e+R121f+R121g+R121h
    # five-test bundle is preserved in spirit — `--ignored` runs the
    # superset (every binary-dep test in the crate) which matches
    # the e2e gate intent.
    (cd crates && cargo test -p wz-integration-tests --quiet -- --ignored)
}

# ─── Layer F — codec-footprint catalog truthfulness gate (R311n) ───
#
# Opt-in. The bench rebuilds wz-ap-demo under every codec-* atomic
# feature's transitive-puller-aware exclusion lane, so a single run
# is several minutes on cold cargo cache. Skipped on the default
# dispatch path; invoked explicitly via:
#
#   scripts/run-ci.sh --layer F               # only Layer F
#   WZ_RUN_LAYER_F=1 scripts/run-ci.sh        # full CI + Layer F
#
# Catalog-truthfulness rationale (R311n): for every codec-X atomic
# feature, turning X off at the wz facade level must mechanically
# remove bytes from a real binary. Without an implies-aware lane the
# minus-codec-X measurement re-enables the codec via consumer
# features (e.g. declare-subscriber implies codec-declare); R311n
# parses the implies graph from `cargo metadata` and excludes the
# full puller set so the lane is honest. The threshold gate exits
# non-zero when any lane drops below the minimum elision delta —
# typically a sign that a new high-level consumer feature was added
# without being listed against the codec it pulls.
layer_f_codec_footprint() {
    if [[ "$ONLY_LAYER" != "F" && "${WZ_RUN_LAYER_F:-0}" -ne 1 ]]; then
        echo "Layer F SKIP (opt-in: --layer F or WZ_RUN_LAYER_F=1)"
        return 0
    fi
    bash scripts/measure-codec-footprint.sh
}

# ─── Layer G — cross-compile cortex-m wz-runtime-core lib build ────
#
# Opt-in via `--layer G` or `WZ_RUN_LAYER_G=1`. Phase W mechanical
# first gate (R311ak) — wz-runtime-core is the §5.P
# runtime-services-tier entry crate (R251) and must build for an
# MCU target so the no_std/MCU half of the composable framework
# stays mechanically truthful as concrete impls (wz-runtime-lwip +
# extern lwIP symbols) land in R311al+. SKIPs gracefully if the
# rustup target is not installed so a host-only developer machine
# is not forced to install a cross-compile toolchain just to run
# the default lanes. Promoted to default once the wz-runtime-lwip
# caller lands and the cross-compile path has a real consumer
# (concrete-impls-land-alongside-real-callers, R63 lesson).
layer_g_cross_compile_cortex_m() {
    if [[ "$ONLY_LAYER" != "G" && "${WZ_RUN_LAYER_G:-0}" -ne 1 ]]; then
        echo "Layer G SKIP (opt-in: --layer G or WZ_RUN_LAYER_G=1)"
        return 0
    fi
    local targets=(
        thumbv7em-none-eabihf
        thumbv6m-none-eabi
        thumbv7m-none-eabi
        thumbv8m.base-none-eabi
        thumbv8m.main-none-eabi
        thumbv8m.main-none-eabihf
        riscv32imac-unknown-none-elf
    )
    local installed
    installed="$(rustup target list --installed 2>/dev/null)"
    local any_ran=0
    local fail=0
    for t in "${targets[@]}"; do
        if ! grep -q "^$t$" <<< "$installed"; then
            echo "  $t SKIP (rustup target not installed; add: rustup target add $t)"
            continue
        fi
        any_ran=1
        # G.1 (R311ak) wz-runtime-core — §5.P trait skeleton.
        if (cd crates && cargo build -p wz-runtime-core \
            --target "$t" --no-default-features --quiet); then
            echo "  G.1 wz-runtime-core $t OK"
        else
            echo "  G.1 wz-runtime-core $t FAIL" >&2
            fail=1
        fi
        # G.2 (R311am) wz facade — no_std cfg_attr toggle when
        # runtime-tokio is not active in the feature set.
        if (cd crates && cargo build -p wz \
            --target "$t" --no-default-features --quiet); then
            echo "  G.2 wz facade $t OK"
        else
            echo "  G.2 wz facade $t FAIL" >&2
            fail=1
        fi
        # G.3 (R311aq) wz-codecs — no_std + alloc; codec wire
        # encode/decode MCU-readiness. Default features kept on so
        # the full codec catalog exercises the alloc-prelude shim
        # end-to-end (R40 carry resolved).
        if (cd crates && cargo build -p wz-codecs \
            --target "$t" --quiet); then
            echo "  G.3 wz-codecs $t OK"
        else
            echo "  G.3 wz-codecs $t FAIL" >&2
            fail=1
        fi
        # G.4 (R311au scope C) wz-runtime-lwip — Phase W MCU profile
        # sync primitive aliases (critical_section::Mutex<RefCell<T>>
        # binding). #![no_std] sync surface, no alloc; covers every
        # Phase W rustup target including Cortex-M0+ (thumbv6m).
        if (cd crates && cargo build -p wz-runtime-lwip \
            --target "$t" --quiet); then
            echo "  G.4 wz-runtime-lwip $t OK"
        else
            echo "  G.4 wz-runtime-lwip $t FAIL" >&2
            fail=1
        fi
        # G.4-alloc (R311av + R311bb) wz-runtime-lwip --features alloc.
        # LwipRuntime self-rolled cooperative task pool + impl Runtime
        # + LwipTime impl TimeSource. R311bb closed the M0+ gap via
        # portable-atomic{,-util}: thumbv6m no longer SKIPs because
        # the crate::atomic alias module substitutes
        # portable_atomic_util::Arc + portable_atomic::Atomic* on
        # targets without native CAS. The polyfill rides on the same
        # critical_section impl the deploy crate supplies for
        # sync::Mutex, so no extra runtime mechanism is layered on.
        if (cd crates && cargo build -p wz-runtime-lwip \
            --target "$t" --features alloc --quiet); then
            echo "  G.4-alloc wz-runtime-lwip $t OK"
        else
            echo "  G.4-alloc wz-runtime-lwip $t FAIL" >&2
            fail=1
        fi
        # G.5 (R311ax + R311bb) wz facade --features runtime-lwip.
        # Composes wz-runtime-lwip via the public facade surface so a
        # consumer enabling `runtime-lwip` finds `wz::runtime_lwip::*`
        # cross-compiled on every Phase W target. R311bb removed the
        # M0+ SKIP that inherited from G.4-alloc.
        if (cd crates && cargo build -p wz \
            --target "$t" --no-default-features \
            --features runtime-lwip --quiet); then
            echo "  G.5 wz facade runtime-lwip $t OK"
        else
            echo "  G.5 wz facade runtime-lwip $t FAIL" >&2
            fail=1
        fi
        # G.6 (R311az-3c) WZ_LWIP_PORT cross-real lane — verifies the
        # `lwip_real_build` cfg path end-to-end:
        #   1. lwip-sys cross-compiles the real lwIP NO_SYS source set
        #      against the deploy-supplied port (cross-test in-tree).
        #   2. bindgen with --target=$t emits real FFI bindings into
        #      the no_std lwip-sys crate.
        #   3. wz-link-lwip's lwip_real_build cfg flips on, exposing
        #      LwipLink + LwipUdpSocket against the real FFI symbols.
        #   4. wz facade re-exports the `wz::link_lwip` namespace.
        # SKIPs riscv32imac because the matching `riscv32-unknown-elf-
        # gcc` cross C toolchain is not installed on the developer
        # machine — the deploy is responsible for that toolchain, not
        # the lwip-sys consumer. The check still proves the cross-real
        # path on the entire ARM lineup, which is the mechanical gate
        # preset-cortex-m4-default catalog truthfulness depends on.
        if [[ "$t" == "riscv32imac-unknown-none-elf" ]]; then
            echo "  G.6 cross-real lwip-sys $t SKIP (riscv32-unknown-elf-gcc not installed on this host)"
        elif (cd crates && \
                WZ_LWIP_PORT="$(realpath lwip-sys/port/cross-test)" \
                cargo build -p wz-link-lwip \
                    --target "$t" --quiet) && \
             (cd crates && \
                WZ_LWIP_PORT="$(realpath lwip-sys/port/cross-test)" \
                cargo build -p wz \
                    --target "$t" --no-default-features \
                    --features runtime-lwip --quiet); then
            echo "  G.6 cross-real lwip-sys $t OK"
        else
            echo "  G.6 cross-real lwip-sys $t FAIL" >&2
            fail=1
        fi
    done
    if [[ $any_ran -eq 0 ]]; then
        echo "Layer G SKIP (no Phase W rustup targets installed)"
        return 0
    fi
    return $fail
}

# ─── Layer Q — QEMU mps2 multi-machine UDP loopback e2e demo run ───
#
# Opt-in via `--layer Q` or `WZ_RUN_LAYER_Q=1`. R311be introduced
# the lane; R311bf fixed the initial single-machine bug
# (mps2-an386/M4 ↔ -cpu cortex-m3 ↔ thumbv7m mismatch + DwtClock vs
# QEMU CYCCNT stub + cwd-dependent link.x). R311bg generalises the
# lane to multi-machine so the Layer Q runtime catalog reaches
# parity with Layer G's cross-compile catalog — the same
# deploy/mcu-qemu-demo source compiles and boots on three QEMU
# mps2 machines representing distinct M-class cores.
#
# Sub-lane matrix (one Q.1.<m>/Q.2.<m> pair per machine):
#
#   m=an385  cortex-m3   thumbv7m-none-eabi       mps2-an385
#   m=an386  cortex-m4   thumbv7em-none-eabihf    mps2-an386
#   m=an500  cortex-m7   thumbv7em-none-eabihf    mps2-an500
#
# (mps2-an505 / Cortex-M33 deferred to a later round — its ARMv8-M
# Secure-state boot requires TrustZone SAU/NSACR setup not covered
# by cortex-m-rt 0.7's default reset path; microbit / Cortex-M0
# deferred until the demo migrates from `core::sync::atomic::*` to
# portable-atomic AtomicU32, since ARMv6-M has no native LDREX/STREX
# and the polyfill is at the wz-runtime-lwip layer, not main.rs.)
#
# Sub-lane shape:
#
#   Q.1.<m> build   cargo build --release for the machine's target
#                   triple. Requires the rustup target + arm-none-eabi-gcc
#                   (lwip-sys cc::Build invokes the C cross-compiler).
#                   SKIPs if the target is absent so a dev host with
#                   only thumbv7m installed still gets the an385
#                   sub-lane.
#   Q.2.<m> run     qemu-system-arm -machine <m> -cpu <cpu> boots
#                   the built ELF and asserts on the semihost
#                   SYS_EXIT exit code. PASS=0 / FAIL=1; 10s timeout
#                   bounds a runaway loop. SKIPs Q.2 if qemu-system-arm
#                   is absent.
#
# Phase W ladder FULL closure mantissa: composable-framework MCU
# stack runs end-to-end on three M-class cores (wz facade +
# runtime-lwip + LwipRuntime timer queue (R311bc) +
# LwipJoinHandle::abort surface (R311bd) + wz-link-lwip UDP raw API
# (R311az-2) + lwip-sys cross-real build (R311az-1) + R311bf's
# SystickClock ClockSource composed in one binary per target).
layer_q_qemu_mcu_e2e() {
    if [[ "$ONLY_LAYER" != "Q" && "${WZ_RUN_LAYER_Q:-0}" -ne 1 ]]; then
        echo "Layer Q SKIP (opt-in: --layer Q or WZ_RUN_LAYER_Q=1)"
        return 0
    fi

    if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
        echo "  Q SKIP (arm-none-eabi-gcc not on PATH;" \
             "install gcc-arm-none-eabi)"
        return 0
    fi

    local installed
    installed="$(rustup target list --installed 2>/dev/null)"
    local has_qemu=0
    if command -v qemu-system-arm >/dev/null 2>&1; then
        has_qemu=1
    fi

    local lwip_port
    lwip_port="$(realpath crates/lwip-sys/port/cross-test)"

    # Sub-lane matrix: machine|cpu|target. Parallel arrays kept as a
    # single colon-delimited table so a new (machine, cpu, target)
    # tuple is one line of addition. Order is "increasing core
    # generation" — M3 -> M4 -> M7.
    local sub_lanes=(
        "mps2-an385:cortex-m3:thumbv7m-none-eabi"
        "mps2-an386:cortex-m4:thumbv7em-none-eabihf"
        "mps2-an500:cortex-m7:thumbv7em-none-eabihf"
    )

    local any_built=0
    local fail=0
    # Q.3 dedup — record which target-triples have already been
    # footprint-checked so two machines that share a triple
    # (mps2-an386 + mps2-an500 both thumbv7em-none-eabihf) do not
    # measure the byte-identical ELF twice.
    declare -A footprint_checked=()

    for lane in "${sub_lanes[@]}"; do
        local machine="${lane%%:*}"
        local rest="${lane#*:}"
        local cpu="${rest%%:*}"
        local target="${rest##*:}"

        if ! grep -q "^${target}$" <<< "$installed"; then
            echo "  Q.${machine} SKIP (rustup target ${target} absent;" \
                 "rustup target add ${target})"
            continue
        fi

        # Q.1.<machine> build — cross-compile the demo with the
        # cross-test lwIP port. `--target` is passed explicitly
        # because cargo's `.cargo/config.toml` lookup starts at
        # the CWD; the build.rs R311bf link-arg directive makes
        # the link script application cwd-invariant.
        if WZ_LWIP_PORT="$lwip_port" cargo build --release \
            --manifest-path deploy/mcu-qemu-demo/Cargo.toml \
            --target "$target" --bin mcu-qemu-demo --quiet; then
            echo "  Q.1.${machine} build mcu-qemu-demo ${target} OK"
        else
            echo "  Q.1.${machine} build mcu-qemu-demo ${target} FAIL" >&2
            fail=1
            continue
        fi
        any_built=1

        if [[ "$has_qemu" -ne 1 ]]; then
            echo "  Q.2.${machine} run SKIP (qemu-system-arm not on PATH;" \
                 "install qemu-system-arm)"
        else
            local bin
            bin="deploy/mcu-qemu-demo/target/${target}/release/mcu-qemu-demo"

            # Q.2.<machine> run — boot the ELF in QEMU. Semihost
            # SYS_EXIT propagates the demo's PASS/FAIL into the QEMU
            # process exit code (0 / 1); a 10s outer timeout bounds
            # a runaway loop so a hung demo does not block CI
            # indefinitely.
            if timeout 10 qemu-system-arm \
                -cpu "$cpu" -machine "$machine" \
                -nographic -semihosting-config enable=on,target=native \
                -kernel "$bin" >/dev/null 2>&1; then
                echo "  Q.2.${machine} run mcu-qemu-demo via qemu-system-arm ${machine} PASS"
            else
                echo "  Q.2.${machine} run mcu-qemu-demo via qemu-system-arm ${machine} FAIL" >&2
                fail=1
            fi
        fi

        # Q.3.<target> footprint — single check per target-triple.
        # Tolerance band gates ROM-axis silent growth; bss is
        # informational (HEAP_SIZE dominated, per R311bj caveat (c)).
        if [[ -z "${footprint_checked[$target]:-}" ]]; then
            footprint_checked[$target]=1
            if ! bash scripts/check-footprint.sh "$target"; then
                fail=1
            fi
        fi
    done

    if [[ $any_built -eq 0 ]]; then
        echo "Layer Q SKIP (no Layer Q rustup targets installed)"
        return 0
    fi
    return $fail
}

# ─── dispatch ──────────────────────────────────────────────────────
overall=0
run_layer 0 layer_0_preflight_lints || overall=1
run_layer A layer_a_mnemosyne || overall=1
run_layer A2 layer_a2_audit_mid_values || overall=1
run_layer B layer_b_verify_codegen || overall=1
run_layer C0 layer_c0_test_discipline || overall=1
run_layer C1 layer_c1_cargo_test || overall=1
run_layer C1b layer_c1b_cargo_test_alloc || overall=1
run_layer C2 layer_c2_cargo_clippy || overall=1
run_layer D layer_d_validate_deploy || overall=1
run_layer E layer_e_ap_demo_round_trip || overall=1
run_layer F layer_f_codec_footprint || overall=1
run_layer G layer_g_cross_compile_cortex_m || overall=1
run_layer Q layer_q_qemu_mcu_e2e || overall=1

if [[ $overall -eq 0 ]]; then
    echo ""
    echo "run-ci: all required layers pass"
fi
exit $overall

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
#   Layer 0  — (optional) actionlint .github/workflows/
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
#   Layer A: <1s   B: ~30s   C1: ~10s   C2: ~5s   D: <1s
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

# ─── Layer 0 — actionlint (optional, runs first to catch CI yaml regressions early) ──
layer_0_actionlint() {
    if ! command -v actionlint >/dev/null 2>&1; then
        echo "Layer 0 SKIP (actionlint not installed; install: go install github.com/rhysd/actionlint/cmd/actionlint@latest)"
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

# ─── dispatch ──────────────────────────────────────────────────────
overall=0
run_layer 0 layer_0_actionlint || overall=1
run_layer A layer_a_mnemosyne || overall=1
run_layer A2 layer_a2_audit_mid_values || overall=1
run_layer B layer_b_verify_codegen || overall=1
run_layer C0 layer_c0_test_discipline || overall=1
run_layer C1 layer_c1_cargo_test || overall=1
run_layer C1b layer_c1b_cargo_test_alloc || overall=1
run_layer C2 layer_c2_cargo_clippy || overall=1
run_layer D layer_d_validate_deploy || overall=1
run_layer E layer_e_ap_demo_round_trip || overall=1

if [[ $overall -eq 0 ]]; then
    echo ""
    echo "run-ci: all required layers pass"
fi
exit $overall

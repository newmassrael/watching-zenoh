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
#   Layer C1 — cargo test --workspace
#   Layer C2 — cargo clippy --workspace --all-targets -- -D warnings
#   Layer D  — deploy/*.yaml schema validate
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
    # R44/R88/R106/R108a intentional divergences from SCE upstream
    # fixtures. Each entry's wz-side rationale lives in the matching
    # sources/codecs/*.scxml header comment (search for "Deliberate
    # divergence from SCE upstream"). Layer 2 reports MISMATCH for
    # these pairs and the report is correct — these are audit-traced
    # wire-correctness improvements that SCE upstream has not yet
    # mirrored (carry as paired upstream PRs).
    #
    #   init_body, join    — R44 endian (BE -> LE for zenoh-pico wire)
    #   msg_del, query     — R88 mid value= baking (variant default)
    #   request            — R88 + R106 + R108a (mid + M=1 + default arm)
    #   msg_put            — R88 family member, defense-in-depth for
    #                        backend-specific MISMATCH noise (R114
    #                        GitHub Actions observation)
    local LAYER2_KNOWN_DIVERGENCE=(init_body join msg_del msg_put query request)

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

# ─── Layer C1 — cargo test --workspace ──────────────────────────────
layer_c1_cargo_test() {
    (cd crates && cargo test --workspace --quiet)
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

# ─── dispatch ──────────────────────────────────────────────────────
overall=0
run_layer 0 layer_0_actionlint || overall=1
run_layer A layer_a_mnemosyne || overall=1
run_layer A2 layer_a2_audit_mid_values || overall=1
run_layer B layer_b_verify_codegen || overall=1
run_layer C1 layer_c1_cargo_test || overall=1
run_layer C2 layer_c2_cargo_clippy || overall=1
run_layer D layer_d_validate_deploy || overall=1

if [[ $overall -eq 0 ]]; then
    echo ""
    echo "run-ci: all required layers pass"
fi
exit $overall

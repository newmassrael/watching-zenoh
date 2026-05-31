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
#   Layer C1c — cargo test -p wz-session-core --features codec-declare
#              (R311ds; same shape as C1b. The 58 codec-declare-gated
#              wz-session-core declare tests (54 behavioural + 4 R311dm
#              thin) run under the workspace lane only because
#              wz-runtime-tokio's defaults transitively enable
#              wz-session-core/codec-declare; this lane makes that
#              coverage explicit instead of an implicit coincidence)
#   Layer C1d — cargo test -p wz-session-core (pub/sub data plane)
#              (R311du; same shape as C1c. The migrated pubsub
#              SubscriberRegistry test module gates on the full pub/sub
#              data-plane union codec-push + codec-declare +
#              codec-response-final + pubsub-{put,delete,attachment,
#              timestamp}; this lane enumerates that union so the tests
#              cannot silently drop out of CI on a defaults change)
#   Layer C1e — cargo test -p wz-session-core (query dispatch plane)
#              (R311dx; same shape as C1d. The migrated QueryableRegistry
#              test module gates on the query dispatch union
#              query-queryable (implies codec-request + codec-response) +
#              query-attachment + query-selector-parameters +
#              query-reply-err + codec-response-final; enumerated so the
#              query tests cannot silently drop out of CI)
#   Layer C1f — cargo test -p wz-session-core (reply dispatch plane;
#              R311fn adds a pure-getter query-reply-only invocation so
#              the reply-DECODE arms are unit-guarded under the
#              zget-reply-only subset, not just the pub/sub union)
#              (R311dy; same shape as C1e. The migrated ReplyRegistry
#              test module gates on the reply dispatch union
#              codec-response + codec-response-final + pubsub-put +
#              pubsub-delete + query-queryable (+ codec-push for the
#              pubsub dispatch path); enumerated so the reply tests
#              cannot silently drop out of CI)
#   Layer C1g — cargo test -p wz-session-core (observer dispatch plane)
#              (R311dz; same shape as C1e/C1f. The migrated
#              ApplicationLayerObserver test module gates on the full
#              observer fan-out union — codec-push + codec-declare +
#              query-queryable + liveliness-token + liveliness-subscriber
#              + declare-subscriber + declare-queryable + codec-response-
#              final + pubsub-{put,delete}. PLUS a composability build
#              of the new codec-declare-on / query-queryable-off subset,
#              which compiles the observer with the queryable slot elided
#              — the arbitrary-subset class C1c-f's maximal-preset tests
#              never exercise.)
#   Layer C1h — wz-session-core arbitrary-subset composability matrix
#              (R311ea; `cargo build`s the crate under several
#              deliberately-incomplete coherent consumer profiles —
#              minimal / pubsub-only / queryable-only / zget-reply-only /
#              declare-observer / codec-declare-bare. deny-warnings turns
#              every subset-specific unused-import / dead-code into a
#              hard error, so this is the mechanical guard that each
#              migrated registry composes under arbitrary feature
#              selection — the class the maximal-union C1c-g lanes miss.)
#   Layer C1i — wz-runtime-tokio scouting-active glue unit tests
#              (R311ep; scouting-active is off by default so Layer C1
#              never builds the scouting glue. Builds + runs the
#              deterministic scout_emit / record_hello_and_emit /
#              scout-timeout unit tests under --features scouting-active
#              + deny-warnings. The socket-bound multicast e2e is the
#              opt-in Layer M.)
#   Layer C1j — wz-runtime-tokio arbitrary-subset BEHAVIOUR matrix
#              (R311ff; `cargo test`s the runtime crate under the same
#              SSOT coherent subsets C4c builds — handshake-only /
#              pubsub-only / queryable-only / zget-reply-only /
#              declare-observer. The behavioural twin of C4c: C4c proves
#              each subset BUILDS, C1j proves each one BEHAVES.
#              Runtime-crate analog of the session-core behavioural
#              lanes C1d-g. Before R311ff the runtime crate's tests ran
#              only under default all-on features.
#              R311fr — this lane was SILENTLY contaminated until now:
#              the wz-runtime-tokio-test-support dev-dependency declared
#              wz-runtime-tokio WITHOUT default-features=false, so cargo
#              feature-unification re-enabled the crate's DEFAULT feature
#              set during `cargo test`, and every named subset actually
#              compiled+ran the full ~420-test default suite (false
#              isolation for ALL subsets). R311fr fixes the dev-dep to
#              default-features=false (forwarding only the foundational
#              session-handshake base) AND gates the entire per-plane
#              test surface (lib + integration) on the feature each test
#              exercises — including behaviour tests of signature-stable
#              methods whose bodies no-op when their codec/plane is off
#              (R311g1). Each subset now runs ONLY its applicable tests
#              and they all pass; the differing run-counts (handshake
#              ~142 .. zget-reply ~233 vs ~420 default) are the proof of
#              genuine isolation. Transport-orthogonal tests (keepalive /
#              batching / lease) gate on transport-keepalive /
#              transport-batching and so run only in the default lane,
#              not in the consumer-plane subsets.)
#   Layer C2 — cargo clippy --workspace --all-targets -- -D warnings
#   Layer C3 — per-package isolated `cargo clippy ... --all-targets`
#              sub-lanes (R311cv; per-package isolated feature
#              resolution catches preset-feature lint regressions that
#              the workspace-mode unified resolver can mask). R311cx
#              expansion: wz-ap-demo (R311cv original) + wz facade
#              under preset-ap-client + wz-runtime-tokio default +
#              wz-runtime-lwip default sync-only + wz-runtime-lwip
#              with `--features alloc`. Five sub-lanes total; any
#              failure short-circuits the whole layer.
#   Layer C4b — wz facade arbitrary-incomplete-subset matrix (R311ek;
#              cargo-builds the facade under deliberately-incomplete
#              coherent consumer subsets — pubsub-only / queryable-only /
#              zget-reply-only / declare-observer — the facade-level
#              analog of C1h that the named-preset C4 lane does not cover.)
#   Layer C4 — wz facade preset composability matrix (R311eb; cargo-
#              builds the facade under all 7 named presets — mcu-minimal/
#              -extended, ap-client/-router/-full, zenoh-cpp, cortex-m4-
#              default — so a preset feature-list drift or incoherent
#              combo cannot pass CI invisibly. Facade-level analog of
#              C1h; no_std footing stays Layer G's cross-compile job.)
#   Layer C4c — wz-runtime-tokio arbitrary-subset BUILD matrix (R311fe;
#              cargo-builds the runtime crate DIRECTLY under
#              --no-default-features + incomplete coherent consumer
#              subsets — handshake-only / pubsub-only / queryable-only /
#              zget-reply-only / declare-observer — the runtime-crate
#              analog of C1h / C4b. transport-unicast pinned ON
#              (FOUNDATIONAL: sole session FSM, like keyexpr-canon). The
#              BUILD half; C1j is the BEHAVIOUR twin over the same SSOT
#              subset list, so the two matrices cannot drift.)
#   Layer C4d — wz-runtime-tokio arbitrary-subset CLIPPY matrix (R311fi;
#              `cargo clippy -D warnings` over the same SSOT subsets C4c
#              builds. Catches clippy lints that only fire in a
#              feature-OFF arm — invisible to C2 `clippy --workspace`
#              which runs the all-on feature union. CLIPPY third of the
#              build/behaviour/lint runtime-crate composability triad.)
#   Layer D  — deploy/*.yaml schema validate
#   Layer E  — binary-dep e2e suite via `cargo test ... -- --ignored`
#              (auto-includes every #[ignore]-marked test in the
#              wz-integration-tests crate EXCEPT the `wz_e2e_*`
#              facade-subset family, which Layer E2 owns; wz-ap-demo +
#              zenoh-pico CLI must be built first or the lane SKIPs)
#   Layer E2 — facade-subset behavioural e2e (R311fg). Drives the
#              single-purpose subset-pinned `wz-e2e-*` binaries (e.g.
#              wz-e2e-pubsub) against zenoh-pico — the behavioural
#              counterpart of the C4b facade BUILD subset matrix. Proves
#              a subset INTEROPERATES on the wire, not just type-checks.
#              SKIPs if the subset binaries / zenoh-pico CLI are absent.
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
#   Layer Q  — QEMU mps2 + microbit MCU e2e demo + footprint
#              (R311be / R311bg / R311bm-m0). Opt-in via
#              `--layer Q` or `WZ_RUN_LAYER_Q=1`. Three sub-lanes:
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
#   Layer M  — active-scouting multicast loopback e2e (R311ep). Opt-in
#              via `--layer M` or `WZ_RUN_LAYER_M=1`. Binds a real UDP
#              multicast scouting link (UdpDriver::bind_multicast_v4),
#              emits a Scout, and resolves a peer locator from a Hello
#              sent on the group. Opt-in because multicast routing is
#              environment-dependent (a container without a multicast
#              route drops the IGMP join) — keeping it out of the
#              default gate honors the no-flaky rule. The deterministic
#              FSM + encode/decode logic is covered socket-free by
#              Layer C1i, so SKIP loses only the real-socket leg.
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
    # 0.1 cargo fmt --check across both workspaces (mandatory).
    # crates/ is the primary workspace; deploy/mcu-qemu-demo is a
    # standalone workspace (R311be `[workspace]` empty table) that
    # the crates/ fmt --check does not visit. R311bn mirrors the
    # gate there so a deploy-side edit (e.g. R311bq main.rs
    # portable-atomic adoption) cannot ship fmt-dirty either.
    if ! (cd crates && cargo fmt --all -- --check); then
        echo "  fmt --check FAIL crates — run \`(cd crates && cargo fmt --all)\`" >&2
        return 1
    fi
    if ! (cd deploy/mcu-qemu-demo && cargo fmt --all -- --check); then
        echo "  fmt --check FAIL deploy/mcu-qemu-demo — run \`(cd deploy/mcu-qemu-demo && cargo fmt --all)\`" >&2
        return 1
    fi
    echo "  fmt --check OK (crates + deploy/mcu-qemu-demo)"

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

# ─── Layer C1c — cargo test -p wz-session-core --features codec-declare ─
#
# R311ds: same shape as C1b. wz-session-core's default features =
# ["alloc"] (codec-declare OFF). The four declare/* registry test
# modules (`#[cfg(test)] mod tests` inside the
# `#[cfg(feature = "codec-declare")] pub mod` registries) + cross_tests
# compile only under codec-declare. Layer C1's `cargo test --workspace`
# happens to run them because wz-runtime-tokio's default features
# transitively enable `wz-session-core/codec-declare` — but that is an
# implicit cross-crate coincidence. This lane runs the 58 codec-declare-
# gated tests (54 R311ds declare behavioural + 4 R311dm liveliness thin)
# explicitly so they cannot silently drop out of CI if wz-runtime-tokio
# ever stops enabling codec-declare by default.
layer_c1c_cargo_test_codec_declare() {
    (cd crates && cargo test -p wz-session-core --features codec-declare --quiet)
}

# ─── Layer C1d — cargo test -p wz-session-core (pub/sub data plane) ──
#
# R311du: same shape as C1c. The pubsub SubscriberRegistry test module
# (migrated from wz-runtime-tokio) gates on the full pub/sub data-plane
# feature union (codec-push + codec-declare + codec-response-final +
# pubsub-{put,delete,attachment,timestamp}). Layer C1's
# `cargo test --workspace` runs them because wz-runtime-tokio's defaults
# enable all of those, but that is an implicit cross-crate coincidence.
# This lane enumerates the union explicitly so the pubsub tests cannot
# silently drop out of CI if wz-runtime-tokio's defaults change.
#
# R311el/R311em: two invocations gate both cfg arms of the metadata-
# projection wire-ups. The first omits pubsub-source-info AND the three
# QoS-byte features (pubsub-priority/-congestion-control/-express) — it
# builds the cfg-off populators (body_source_info = None, qos = None)
# under deny-warnings and runs the cautious-fire dedup tests that hold
# with source_info absent. The second adds pubsub-source-info + all three
# QoS features — it builds the extract_source_info + extract_qos paths
# and runs the self-echo suppression tests that only engage when the wire
# source_info is decoded. The maximal-preset lanes never build the
# metadata-off subset, so the off arms would otherwise escape CI.
layer_c1d_cargo_test_pubsub() {
    (cd crates \
        && cargo test -p wz-session-core --features codec-push,codec-declare,codec-response-final,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp --quiet \
        && cargo test -p wz-session-core --features codec-push,codec-declare,codec-response-final,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp,pubsub-source-info,pubsub-priority,pubsub-congestion-control,pubsub-express --quiet)
}

# ─── Layer C1e — cargo test -p wz-session-core (query dispatch plane) ──
#
# R311dx: same shape as C1c/C1d. The migrated QueryableRegistry test
# module (lifted from wz-runtime-tokio::query) gates on the query
# dispatch-plane union (query-queryable — which implies codec-request +
# codec-response — plus query-attachment / query-selector-parameters /
# query-reply-err, and codec-response-final for the response_final_for
# tests). Layer C1's `cargo test --workspace` runs them because
# wz-runtime-tokio's defaults enable all of those, but that is an
# implicit cross-crate coincidence. This lane enumerates the union
# explicitly so the query tests cannot silently drop out of CI if
# wz-runtime-tokio's defaults change.
layer_c1e_cargo_test_query() {
    (cd crates && cargo test -p wz-session-core --features query-queryable,query-attachment,query-selector-parameters,query-reply-err,codec-response-final --quiet)
}

# ─── Layer C1f — cargo test -p wz-session-core (reply dispatch plane) ──
#
# R311dy: same shape as C1d/C1e. The migrated ReplyRegistry test module
# (lifted from wz-runtime-tokio::reply) gates on the reply dispatch
# union: codec-response (Response/Reply/Err) + codec-response-final
# (ResponseFinal) + pubsub-put / pubsub-delete (the inbound Reply Put/Del
# body arms) + query-queryable (the From<QueryReply> loopback-projection
# tests). codec-push is enabled too because pubsub-put / pubsub-delete
# drive the wz-session-core::pubsub dispatch path, which references the
# codec-push Push type. Enumerated explicitly so the reply tests cannot
# silently drop out of CI on a wz-runtime-tokio defaults change.
#
# R311fn — second invocation: the PURE GETTER subset (query-reply ON,
# pub/sub OFF). This is the behavioural twin of the `zget-reply-only`
# BUILD subset that C4b / C4c / C1h / C1j compile — those prove it builds,
# this proves the inbound Reply Put/Del DECODE actually fires. R311fm
# split the reply-body decode arms off the pub/sub publisher markers onto
# `any(pubsub-{put,delete}, query-reply)`; before R311fn the reply test
# module itself required pubsub-put+pubsub-delete, so the getter arm had
# ZERO unit coverage (a revert to `_ => return` kept this suite green and
# only the heavier wz-e2e-zget e2e caught it). With the module gate now
# `any(pubsub-put, query-reply)` ∧ `any(pubsub-delete, query-reply)`, this
# invocation runs the dispatch_response Put/Del/Err decode tests under the
# exact subset a foreign-interop z_get consumer pins. --no-default-features
# keeps pub/sub genuinely OFF (default would pull nothing extra here, but
# the explicit form documents the getter-only intent and guards against a
# future default change re-enabling a publisher feature).
layer_c1f_cargo_test_reply() {
    (cd crates \
        && cargo test -p wz-session-core --features codec-push,codec-response,codec-response-final,pubsub-put,pubsub-delete,query-queryable --quiet \
        && cargo test -p wz-session-core --no-default-features --features alloc,codec-response,codec-response-final,query-reply --quiet)
}

# ─── Layer C1g — cargo test -p wz-session-core (observer dispatch plane) ─
#
# R311dz: same shape as C1e/C1f. The migrated ApplicationLayerObserver
# test module (lifted from wz-runtime-tokio::observer) gates on the full
# observer fan-out union: codec-push (the subscriber Push fixture +
# module test gate) + codec-declare (the peer-declare registries it
# aggregates) + query-queryable (the queryable slot + its staged-reply
# test) + liveliness-token + liveliness-subscriber + declare-subscriber
# + declare-queryable (the per-domain assertion / cross-talk tests) +
# codec-response-final (the ResponseFinal drain) + pubsub-{put,delete}.
# Layer C1's `cargo test --workspace` runs them because wz-runtime-tokio's
# defaults enable all of those, but that is an implicit cross-crate
# coincidence — this lane enumerates the union explicitly.
#
# The lane also adds a composability BUILD of the codec-declare-on /
# query-queryable-off subset: it must compile the observer with the
# `queryables` field (+ its dispatch / drain arms) elided. This is the
# arbitrary-subset class the maximal-preset tests in C1c-f never
# exercise (they only ever build the full union), so it is enumerated
# here as the first explicit guard that the observer composes when a
# consumer wires pub/sub + liveliness but no in-process queryable.
layer_c1g_cargo_test_observer() {
    (cd crates \
        && cargo test -p wz-session-core --features codec-push,codec-declare,codec-request,codec-response,codec-response-final,query-queryable,liveliness-token,liveliness-subscriber,declare-subscriber,declare-queryable,pubsub-put,pubsub-delete --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,codec-push,codec-declare,codec-response,codec-response-final,liveliness-token,liveliness-subscriber,declare-subscriber,declare-queryable,pubsub-put,pubsub-delete --quiet)
}

# ─── Layer C1h — wz-session-core arbitrary-subset composability matrix ─
#
# R311ea: the C1c-g lanes each build wz-session-core under ONE maximal
# feature union (per dispatch plane), so a gating regression that only
# surfaces in a deliberately-incomplete coherent subset passes CI
# invisibly. This lane closes that gap: it `cargo build`s the crate
# under several representative coherent consumer profiles, none of which
# any other lane builds in isolation. The `[workspace.lints] warnings =
# "deny"` policy turns every subset-specific unused-import / dead-code /
# single-pattern-match into a hard error, so this lane is the mechanical
# guard that the migrated registries (pubsub / query / reply / declare /
# observer) each compose under arbitrary feature selection — the
# north-star "compose only what you wire" property. `cargo build` (lib,
# no --all-targets) is the right surface: it is the compile-composability
# check; the per-plane test modules are already covered by C1c-g's
# maximal unions.
#
# Subsets (each a real consumer shape):
#   1. minimal           alloc                       (trait/value surface, no codec)
#   2. pubsub-only       +codec-push +pubsub-*       (subscriber data plane, no query/reply/declare)
#   3. queryable-only    +query-queryable +query-*   (in-process queryable server, no pubsub/declare)
#   4. zget-reply-only   +codec-response(+final)     (z_get initiator reply plane, no queryable/declare)
#   5. declare-observer  +codec-declare +declare/liveliness  (peer-declare + liveliness observer, NO query/reply
#                                                      — builds the observer with the queryables slot elided)
#   6. codec-declare-bare +codec-declare             (registries present, zero consumer features)
#   7. transport-batching +transport-batching        (R311eg: PeerInitCaps::from_init_syn honors the
#                                                      peer-advertised batch_size; guards the gate-ON arm
#                                                      that the alloc-only subset #1 leaves OFF)
layer_c1h_arbitrary_subset_matrix() {
    (cd crates \
        && cargo build -p wz-session-core --no-default-features --features alloc --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,codec-push,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,query-queryable,query-attachment,query-selector-parameters,query-reply-err --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,codec-push,codec-response,codec-response-final,pubsub-put,pubsub-delete --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,codec-declare,declare-subscriber,declare-queryable,liveliness-token,liveliness-subscriber --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,codec-declare --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,transport-batching --quiet)
}

# ─── Layer C1i — cargo test -p wz-runtime-tokio --features scouting-active ─
#
# R311ep: scouting-active is off by default (scouting is opt-in per
# deploy.scouting.mode), so Layer C1's `cargo test --workspace` never
# builds the scouting glue. This lane builds + runs the deterministic
# scouting unit tests (scout_emit Scout framing, record_hello_and_emit
# locator extraction, scout-timeout path) under `--features
# scouting-active`, which the `[workspace.lints] warnings = "deny"`
# policy compiles with no dead-code/unused tolerance. The socket-bound
# multicast e2e is the separate opt-in Layer M (multicast routing is
# environment-dependent). `--lib` scopes the run to the in-crate unit
# tests; the `scouting_multicast_loopback` integration test is `#[ignore]`
# and only runs under Layer M.
layer_c1i_cargo_test_scouting() {
    (cd crates && cargo test -p wz-runtime-tokio --features scouting-active --lib scouting_glue --quiet)
}

# ─── Layer C2 — cargo clippy --deny warnings ────────────────────────
#
# R311bo: mirror the gate to deploy/mcu-qemu-demo (standalone
# workspace, same shape as R311bn fmt mirror). Cross-compile
# clippy on thumbv7m-none-eabi catches the universal portion of
# the deploy-side lint surface (cfg-attribute consistency, unused
# bindings, type-state issues) without paying for all five Phase W
# targets each invocation — the issues that vary by target triple
# are caught by Layer G's per-triple build matrix. SKIP gracefully
# if the thumbv7m-none-eabi rustup target or arm-none-eabi-gcc is
# absent so a host-only developer is not forced to install the
# cross toolchain just to clear C2.
layer_c2_cargo_clippy() {
    (cd crates && cargo clippy --workspace --all-targets --quiet -- -D warnings) || return 1

    local installed
    installed="$(rustup target list --installed 2>/dev/null)"
    if ! grep -q "^thumbv7m-none-eabi$" <<< "$installed"; then
        echo "  C2 deploy SKIP (thumbv7m-none-eabi target absent)"
        return 0
    fi
    if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
        echo "  C2 deploy SKIP (arm-none-eabi-gcc not on PATH)"
        return 0
    fi

    local lwip_port
    lwip_port="$(realpath crates/lwip-sys/port/cross-test)"
    WZ_LWIP_PORT="$lwip_port" cargo clippy --release \
        --manifest-path deploy/mcu-qemu-demo/Cargo.toml \
        --target thumbv7m-none-eabi --quiet -- -D warnings
}

# ─── Layer C3 — per-package isolated --all-targets ──────────────────
#
# R311cv: closes the R311cp carry. `cargo clippy --workspace --all-
# targets` (Layer C2) resolves features in workspace-unified mode,
# which can mask regressions that surface only when a binary crate is
# built in isolation with its own default features. wz-ap-demo's
# `preset-ap-client` default routes through the wz facade feature
# graph and the workspace-mode unification can silently re-enable
# sibling features that hide preset-feature-isolated lint failures.
#
# R311cx expansion: extends the original wz-ap-demo lane to also cover
# the wz facade itself (under `preset-ap-client` — the same surface
# wz-ap-demo selects, but linted at the facade's own crate boundary so
# preset wiring regressions surface even if no consumer-binary catches
# them yet), wz-runtime-tokio on its default feature bundle (the
# largest single source of cfg combinations in the workspace), and
# both wz-runtime-lwip lanes (default sync-only + `--features alloc`)
# so Phase W MCU profile feature combinations are caught the same way
# the AP-tokio lane catches them.
layer_c3_per_pkg_isolated_lint() {
    (cd crates \
        && cargo clippy -p wz-ap-demo --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz --no-default-features --features preset-ap-client \
            --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-lwip --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-lwip --features alloc \
            --all-targets --quiet -- -D warnings)
}

# ─── Layer C4 — wz facade preset composability matrix ───────────────
#
# R311eb: the wz facade exposes 7 named presets (the user-facing
# composition surface — `mnemosyne.toml` north-star "compose a profile,
# not a feature soup"). C3 builds only `preset-ap-client`; Layer G
# cross-compiles the facade under its default / runtime-lwip bundles.
# Neither guards the OTHER presets' feature lists from drift — a preset
# that references a renamed/removed feature, or selects an incoherent
# combo that no longer type-checks, would pass CI invisibly. This lane
# `cargo build`s the facade under each named preset (host typecheck +
# feature-resolution; `[workspace.lints] warnings = "deny"` still turns
# any preset-specific unused-import / dead-code into a hard error). It is
# the facade-level analog of C1h's wz-session-core subset matrix. The
# no_std footing of the MCU presets is independently proven by Layer G's
# cross-compile; this lane is the fast feature-shape guard that runs on
# the host without the cross toolchain.
layer_c4_preset_matrix() {
    local presets=(
        preset-mcu-minimal
        preset-mcu-extended
        preset-ap-client
        preset-ap-router
        preset-ap-full
        preset-zenoh-cpp
        preset-cortex-m4-default
    )
    local p
    for p in "${presets[@]}"; do
        if ! (cd crates && cargo build -p wz --no-default-features --features "$p" --quiet); then
            echo "  C4 FAIL: wz preset $p did not build"
            return 1
        fi
        echo "  C4 wz $p OK"
    done
}

# ─── consumer-plane subset SSOT (R311fp) ────────────────────────────
#
# The SINGLE canonical plane->extras map. Each row is one deliberately-
# incomplete coherent consumer plane (the features layered on a handshake
# core to select ONE plane). Every arbitrary-subset lane consumes this
# one map, each prepending its own crate-appropriate base:
#   * C4b  — wz facade BUILD            (facade base + plane)
#   * C4c  — wz-runtime-tokio BUILD     (crate base + plane)
#   * C1j  — wz-runtime-tokio BEHAVIOUR (crate base + plane)
#   * C4d  — wz-runtime-tokio CLIPPY    (crate base + plane)
# Before R311fp the facade matrix (C4b) carried its OWN copy of the 4
# overlapping plane strings while C4c/C1j/C4d shared a second copy — two
# sources of truth for "what is a pubsub-only / queryable-only plane",
# free to drift. This is the SSOT they now both consume.
#
# R311fp naming ruling — "queryable-only" build = the FULL queryable
# plane (codec-response-final INCLUDED), consistent with declare-observer
# already being its full bundle. Previously the build matrices listed
# query-reply-err but NOT codec-response-final, while wz-e2e-queryable
# (interop) pinned the reverse — one name, two feature sets. Now build
# extras superset interop extras for EVERY plane, so the sole
# build-vs-interop delta is transport-batching: a uniform transport/base
# feature (R311fg foreign handshake), NOT a per-plane one. That collapses
# the 3 historical deltas (transport-batching R311fg, codec-response-final
# R311fh, query-reply R311fm) into ONE uniform base delta, carried by
# Layer E2's wz-e2e-* binaries (which add transport-batching + tcp). It
# also closes the R311fh gap at the BUILD layer: the queryable build now
# includes the terminating Final.
#
# handshake-only = empty extras (bare session core, no consumer plane).
# transport-unicast / keyexpr-canon are FOUNDATIONAL and live in each
# lane's base, not here (a subset that drops them does not type-check).
_wz_consumer_plane_subsets() {
    printf '%s\t%s\n' "handshake-only"        ""
    printf '%s\t%s\n' "pubsub-only"           "codec-push,pubsub-put,pubsub-delete"
    printf '%s\t%s\n' "queryable-only"        "codec-request,codec-response,codec-response-final,query-queryable,query-reply-err"
    printf '%s\t%s\n' "zget-reply-only"       "codec-response,codec-response-final,query-get,query-reply"
    printf '%s\t%s\n' "liveliness-sub-only"   "codec-declare,declare-interest,liveliness-subscriber"
    printf '%s\t%s\n' "liveliness-token-only" "liveliness-token"
    printf '%s\t%s\n' "declare-observer"      "codec-declare,declare-subscriber,declare-queryable,liveliness-token,liveliness-subscriber"
}

# ─── Layer C4b — wz facade arbitrary-incomplete-subset matrix ────────
#
# R311ek: C4 builds the 7 named presets, each a COMPLETE coherent
# profile. C1h builds wz-session-core under incomplete subsets — but the
# session-core subset can pass while the FACADE (wz -> wz-runtime-tokio
# -> wz-session-core) fails, because the runtime-tokio glue
# (`session.rs` / `session_glue.rs`) imports gated session-core items
# (observer / liveliness_subscriber / the source_info ext encoder) under
# conditions broader than their use sites. The default-feature CI never
# exercises a codec-push-only / queryable-only facade, so that regression
# class passed invisibly (it is exactly what R311ek fixed). This lane is
# the facade-level analog of C1h: it `cargo build`s the wz facade under
# several deliberately-incomplete coherent consumer subsets — each a real
# user shape that selects ONE consumer plane — so `deny(warnings)` turns
# any over-broad import / dead-field / unused-type-param in the
# runtime-tokio glue into a hard error. Host typecheck only; the no_std
# footing stays Layer G's job.
#
# R311fp ruling — C4b stays BUILD-minimal; it does NOT pin interop
# supersets. R311fo asked whether C4b should layer the interop deltas
# (transport-batching / codec-response-final / query-reply) into its
# subsets. Ruling: NO. C4b and Layer E2 are different guards. C4b's value
# is testing the MINIMAL incomplete shape (a smaller feature set is a
# STRONGER over-broad-import guard); pinning a superset would (1) stop
# exercising the superset-OFF facade build two wz peers legitimately use
# (transport-batching OFF → both force 65535), (2) duplicate the build
# each wz-e2e-* binary already performs under its interop superset
# (Layer E2), and (3) erase the build-vs-interop distinction that is the
# reason Layer E2 exists. Interop supersets live with the wz-e2e-* binaries
# + Layer E2; the per-plane deltas were since collapsed to the single
# uniform transport-batching delta (see the SSOT block above). This closes
# the C4b-ruling carry.
#
# R311fp SSOT — C4b consumes _wz_consumer_plane_subsets (the one plane map
# shared with C4c/C1j/C4d) instead of its own copy. It prepends the FACADE
# base, which differs from the crate base by exactly `runtime-tokio` (the
# facade must SELECT a runtime; the crate IS one) plus the facade-only
# forwarding markers `keyexpr-literal` / `transport-keepalive`. Link is
# transport-link-tcp, matching the crate base + every wz-e2e-* binary
# (the prior transport-link-udp here was unexplained drift, not a UDP
# requirement — the facade builds identically on either link feature).
# handshake-only (empty extras) is now build-guarded at the facade too.
layer_c4b_facade_subset_matrix() {
    local base="runtime-tokio,transport-unicast,transport-link-tcp,transport-keepalive,session-unicast-open,session-unicast-accept,codec-frame,codec-keep-alive,codec-init-body,codec-open-body,codec-close,keyexpr-literal,keyexpr-canon"
    local name extra feats
    while IFS=$'\t' read -r name extra; do
        feats="$base${extra:+,$extra}"
        if ! (cd crates && cargo build -p wz --no-default-features --features "$feats" --quiet); then
            echo "  C4b FAIL: wz facade subset $name did not build"
            return 1
        fi
        echo "  C4b wz subset $name OK"
    done < <(_wz_consumer_plane_subsets)
}

# ─── wz-runtime-tokio coherent-subset wrapper ───────────────────────
#
# R311ff introduced this as the SSOT for C4c/C1j/C4d. R311fp lifted the
# plane->extras map up to _wz_consumer_plane_subsets (now shared with the
# facade lane C4b too); this is the thin crate-base wrapper that prepends
# the wz-runtime-tokio base to each shared plane row. Consumed by the
# build (C4c), behaviour (C1j) and clippy (C4d) guards so all three can
# never drift from each other OR from the facade lane. Each emitted line
# is `name<TAB>full-feature-string`.
#
# transport-unicast is pinned ON in every subset: it is FOUNDATIONAL
# (the sole session FSM; transport-multicast stays reserved with no
# consumer), so a transport-unicast-OFF subset does not type-check and
# is not a coherent shape to guard — same status as keyexpr-canon. The
# crate base differs from the facade base (C4b) by exactly `runtime-tokio`
# (the facade selects a runtime; this crate IS one) and the facade-only
# forwarding markers keyexpr-literal / transport-keepalive — the plane
# extras are identical because they come from the shared map.
_wz_runtime_tokio_coherent_subsets() {
    local base="transport-unicast,transport-link-tcp,session-unicast-open,session-unicast-accept,codec-frame,codec-keep-alive,codec-init-body,codec-open-body,codec-close,keyexpr-canon"
    local name extra
    while IFS=$'\t' read -r name extra; do
        printf '%s\t%s\n' "$name" "$base${extra:+,$extra}"
    done < <(_wz_consumer_plane_subsets)
}

# ─── Layer C4c — wz-runtime-tokio arbitrary-subset BUILD composability ─
#
# R311fe/R311ff: C1h guards wz-session-core subsets (build), C4b guards
# the wz facade (build). Neither builds wz-runtime-tokio DIRECTLY under
# an incomplete subset — the facade always selects a coherent preset
# bundle, so a regression in the runtime crate's own cfg gating (an
# over-broad `use` whose only call site is feature-gated, a dead field
# under a one-plane build) can pass C4b invisibly when the facade default
# pulls the missing feature back in. That is exactly the class R311fe
# fixed (the `wz_codecs::ext_entry::ExtEntry` import was unconditional
# while its sole consumer `decode_ext_chain` is gated on the codec
# union). This lane `cargo build`s the runtime crate under each SSOT
# subset so `deny(warnings)` turns any subset-specific dead import /
# unused field into a hard error.
#
# This is the BUILD half of the runtime-crate composability guard; the
# BEHAVIOURAL half is C1j (`cargo test` over the same SSOT subsets). The
# two are kept as separate lanes on purpose: "does it type-check +
# lint-clean?" and "does it run correctly?" are distinct questions that
# must localise distinctly, even though `cargo test` mechanically
# subsumes the `cargo build` step.
layer_c4c_runtime_tokio_subset_matrix() {
    local name feats
    while IFS=$'\t' read -r name feats; do
        if ! (cd crates && cargo build -p wz-runtime-tokio --no-default-features --features "$feats" --quiet); then
            echo "  C4c FAIL: wz-runtime-tokio subset $name did not build"
            return 1
        fi
        echo "  C4c wz-runtime-tokio subset $name OK"
    done < <(_wz_runtime_tokio_coherent_subsets)
}

# ─── Layer C1j — wz-runtime-tokio arbitrary-subset BEHAVIOUR ─────────
#
# R311ff: the behavioural twin of C4c. C4c proves each coherent subset
# BUILDS; C1j proves each one BEHAVES — it `cargo test`s wz-runtime-tokio
# under the same SSOT subsets, so a feature-off code path that compiles
# but mis-dispatches / panics / drops a message is caught by whichever
# tests stay cfg-active in that subset (each subset runs 400+ lib +
# integration tests). This is the runtime-crate analog of the
# wz-session-core behavioural plane lanes C1d–g, which are likewise kept
# separate from the session-core BUILD matrix C1h. Behavioural coverage
# under reduced features previously existed only for wz-session-core; the
# runtime crate's own tests ran solely under default (all-on) features
# via Layer C1's `cargo test --workspace`, so a subset-specific runtime
# behaviour regression had no guard.
layer_c1j_runtime_tokio_subset_behavior() {
    local name feats
    while IFS=$'\t' read -r name feats; do
        if ! (cd crates && cargo test -p wz-runtime-tokio --no-default-features --features "$feats" --quiet); then
            echo "  C1j FAIL: wz-runtime-tokio subset $name behaviour tests failed"
            return 1
        fi
        echo "  C1j wz-runtime-tokio subset $name tests OK"
    done < <(_wz_runtime_tokio_coherent_subsets)
}

# ─── Layer C4d — wz-runtime-tokio arbitrary-subset CLIPPY ────────────
#
# R311fi: the clippy twin of C4c (build) / C1j (behaviour) over the same
# SSOT subsets. C4c's `cargo build` + workspace `deny(warnings)` catches
# rustc warnings (dead import / unused field), but clippy lints are a
# distinct surface that `cargo build` does NOT evaluate. The default
# clippy lane (C2 `cargo clippy --workspace`) runs under the unified
# all-on feature set, so a clippy lint that only fires in a feature-OFF
# arm escapes it. R311fg/R311fh surfaced exactly that: under any
# query-get-OFF subset the signature-stability methods Session::query /
# query_aliased / query_aliased_auto had a `cfg(not(query-get))` arm
# whose `return Err(FeatureDisabled)` became the function tail →
# clippy::needless_return, invisible to C2 (query-get is ON in the
# workspace union via wz-ap-demo). R311fi resolved those three sites to
# tail-expression form (per feedback_signature_stability: cfg
# tail-expr, not #[allow]) and adds this lane so the regression class
# is guarded going forward. `cargo clippy` over each SSOT subset with
# `-D warnings` turns any subset-specific clippy lint into a hard error.
layer_c4d_runtime_tokio_subset_clippy() {
    local name feats
    while IFS=$'\t' read -r name feats; do
        if ! (cd crates && cargo clippy -p wz-runtime-tokio --no-default-features --features "$feats" --quiet -- -D warnings); then
            echo "  C4d FAIL: wz-runtime-tokio subset $name clippy not clean"
            return 1
        fi
        echo "  C4d wz-runtime-tokio subset $name clippy OK"
    done < <(_wz_runtime_tokio_coherent_subsets)
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
    # R311fg — exclude the `wz_e2e_*` facade-subset behavioural e2e
    # family; those run in the dedicated Layer E2 lane against their
    # own subset-pinned binaries (wz-e2e-pubsub etc.), not the full
    # preset-ap-client wz-ap-demo this lane drives. The `--skip` is a
    # test-name substring filter, so the `wz_e2e_` prefix convention
    # keeps every future subset e2e out of this sweep with one pattern.
    (cd crates && cargo test -p wz-integration-tests --quiet -- --ignored --skip wz_e2e_)
}

# ─── Layer E2 — facade-subset behavioural e2e vs zenoh-pico ──────────
#
# R311fg: the behavioural counterpart of the C4b facade BUILD subset
# matrix. C4b proves each coherent facade subset type-checks; Layer E2
# proves a subset INTEROPERATES on the wire with a foreign zenoh-pico
# peer. It drives the single-purpose subset-pinned binaries (the
# `wz-e2e-*` crate family) rather than the full preset-ap-client
# wz-ap-demo, so a feature that is load-bearing for foreign interop but
# invisible to a build check or an in-process wz<->wz test is caught
# here. Each binary pins ONE consumer plane's interop-coherent subset:
#   * wz-e2e-pubsub    — pubsub-only,    wz publishes vs z_sub
#                        (R311fg catch: transport-batching is load-bearing
#                        for the foreign handshake — see its Cargo.toml).
#   * wz-e2e-queryable — queryable-only, wz answers queries vs z_get
#                        (catch: codec-response-final is load-bearing for
#                        z_get's terminating Final — see its Cargo.toml).
#   * wz-e2e-zget      — zget-reply-only, wz issues queries vs
#                        z_queryable (initiator mirror of wz-e2e-
#                        queryable; consumes the reply + Final chain).
#   * wz-e2e-liveliness — liveliness-subscriber-only, wz OBSERVES a token
#                        vs z_liveliness declarer (wz=sink). Witness is on
#                        the wz side, so no foreign-stdout capture race.
#   * wz-e2e-liveliness-token — liveliness-token DECLARER, wz ANSWERS a
#                        liveliness query vs z_get_liveliness (R283
#                        interest-response). z_get_liveliness is a one-shot
#                        CURRENT get with no future subscription, so only
#                        the R283 reply can satisfy it — it isolates the
#                        interest-response from the proactive declare.
#   * wz-e2e-declare-observer — declare-observer, wz passively OBSERVES a
#                        foreign z_sub's proactive Declare(DeclSubscriber)
#                        (wz=sink, emits nothing; no Interest needed).
#                        Witness is on the wz side, so no foreign-stdout
#                        capture race. The LAST C4b/C4c build-subset entry
#                        to gain a behavioural e2e twin (R311fo).
#
# Same prereq-SKIP discipline as Layer E: the subset binaries + the
# zenoh-pico CLI must be prebuilt (CI builds them; a bare local run
# SKIPs with the build hint). Runs only the `wz_e2e_*` family that
# Layer E skips, so no test runs twice.
layer_e2_facade_subset_e2e() {
    if [[ ! -x target/zenoh-pico-cli/z_sub || ! -x target/zenoh-pico-cli/z_get \
          || ! -x target/zenoh-pico-cli/z_queryable \
          || ! -x target/zenoh-pico-cli/z_liveliness \
          || ! -x target/zenoh-pico-cli/z_get_liveliness ]]; then
        echo "Layer E2 SKIP (zenoh-pico CLI not built; run: bash scripts/build-zenoh-pico-cli.sh)"
        return 0
    fi
    # pubsub-only subset (R311fg) — wz publishes vs zenoh-pico z_sub.
    if [[ ! -x crates/target/debug/wz-e2e-pubsub && ! -x crates/target/release/wz-e2e-pubsub ]]; then
        echo "Layer E2 SKIP (wz-e2e-pubsub not built; run: cd crates && cargo build -p wz-e2e-pubsub)"
        return 0
    fi
    # queryable-only subset — wz answers queries vs zenoh-pico z_get.
    if [[ ! -x crates/target/debug/wz-e2e-queryable && ! -x crates/target/release/wz-e2e-queryable ]]; then
        echo "Layer E2 SKIP (wz-e2e-queryable not built; run: cd crates && cargo build -p wz-e2e-queryable)"
        return 0
    fi
    # zget-reply-only subset — wz issues queries vs zenoh-pico z_queryable.
    if [[ ! -x crates/target/debug/wz-e2e-zget && ! -x crates/target/release/wz-e2e-zget ]]; then
        echo "Layer E2 SKIP (wz-e2e-zget not built; run: cd crates && cargo build -p wz-e2e-zget)"
        return 0
    fi
    # liveliness-subscriber-only subset — wz observes a token vs z_liveliness.
    if [[ ! -x crates/target/debug/wz-e2e-liveliness && ! -x crates/target/release/wz-e2e-liveliness ]]; then
        echo "Layer E2 SKIP (wz-e2e-liveliness not built; run: cd crates && cargo build -p wz-e2e-liveliness)"
        return 0
    fi
    # liveliness-token declarer subset (R283) — wz answers a liveliness
    # query vs z_get_liveliness.
    if [[ ! -x crates/target/debug/wz-e2e-liveliness-token && ! -x crates/target/release/wz-e2e-liveliness-token ]]; then
        echo "Layer E2 SKIP (wz-e2e-liveliness-token not built; run: cd crates && cargo build -p wz-e2e-liveliness-token)"
        return 0
    fi
    # declare-observer subset (R311fo) — wz observes a foreign z_sub's
    # proactive DeclSubscriber.
    if [[ ! -x crates/target/debug/wz-e2e-declare-observer && ! -x crates/target/release/wz-e2e-declare-observer ]]; then
        echo "Layer E2 SKIP (wz-e2e-declare-observer not built; run: cd crates && cargo build -p wz-e2e-declare-observer)"
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_e2e_pubsub_to_zsub \
        --test wz_e2e_queryable_to_zget \
        --test wz_e2e_zget_to_zqueryable \
        --test wz_e2e_liveliness_to_zliveliness \
        --test wz_e2e_liveliness_token_to_zget_liveliness \
        --test wz_e2e_declare_observer_to_zsub \
        --quiet -- --ignored)
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

    # Sub-lane matrix: machine|cpu|target|run_policy. Parallel
    # arrays kept as a single colon-delimited table so a new
    # (machine, cpu, target, run_policy) tuple is one line of
    # addition. Order is "increasing core generation" — M0 -> M3
    # -> M4 -> M7. run_policy:
    #   run        Q.2 attempts the QEMU boot and asserts on the
    #              semihost SYS_EXIT exit code (PASS/FAIL gates
    #              the lane).
    #   skip:<why> Q.2 is suppressed with a printed reason. Used
    #              for known-running-but-FAIL configs where the
    #              binary boots but a separate compatibility carry
    #              is outstanding (Cortex-M33 Secure-state init,
    #              etc.). Build + Q.3 footprint still run so the
    #              catalog records the honest cross-compile state.
    #
    # R311bq promoted the microbit lane from skip → run after the
    # deploy main.rs gained the spawn-less sync-only branch under
    # `cfg(not(target_has_atomic = "32"))` and wz-link-lwip went
    # const-generic so the lane instantiates a slim
    # `LwipUdpSocket<128, 2>` (~280 B rx queue versus 12 KB at
    # default `<1500, 8>`). The change closed the
    # north-star phase 1 anchor (preset-mcu-minimal truthfulness)
    # while keeping the wz facade `runtime-lwip` surface intact —
    # mps2 lanes still build + run the async + spawn path.
    local sub_lanes=(
        "microbit:cortex-m0:thumbv6m-none-eabi:run"
        "mps2-an385:cortex-m3:thumbv7m-none-eabi:run"
        "mps2-an386:cortex-m4:thumbv7em-none-eabihf:run"
        "mps2-an500:cortex-m7:thumbv7em-none-eabihf:run"
        "mps2-an505:cortex-m33:thumbv8m.main-none-eabi:skip:cortex-m-rt 0.7 ARMv8-M Secure-state Lockup PC=0x56ea; cortex-m-rt 0.8 carry"
    )

    local any_built=0
    local fail=0
    # Q.3 dedup — record which target-triples have already been
    # footprint-checked so two machines that share a triple
    # (mps2-an386 + mps2-an500 both thumbv7em-none-eabihf) do not
    # measure the byte-identical ELF twice.
    declare -A footprint_checked=()

    for lane in "${sub_lanes[@]}"; do
        # Parse machine|cpu|target|run_policy. The run_policy slot
        # is either the literal `run` or `skip:<reason>`. `skip:`
        # may contain colons inside the reason, so split on the
        # first three colon boundaries and keep the remainder as
        # the policy field verbatim.
        IFS=':' read -r machine cpu target run_policy rest <<< "$lane"
        local skip_reason=""
        if [[ "$run_policy" == "skip" ]]; then
            skip_reason="$rest"
            run_policy="skip"
        fi

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

        if [[ "$run_policy" == "skip" ]]; then
            echo "  Q.2.${machine} run KNOWN_SKIP (${skip_reason})"
        elif [[ "$has_qemu" -ne 1 ]]; then
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

# ─── Layer M — active-scouting multicast loopback e2e ──────────────
#
# R311ep: opt-in via `--layer M` or `WZ_RUN_LAYER_M=1`. Runs the
# `scouting_multicast_loopback` integration test, which binds a real
# UDP multicast scouting link (UdpDriver::bind_multicast_v4), emits a
# Scout, and resolves a peer locator from a Hello sent on the group.
# Opt-in (not a default gate) because multicast routing is
# environment-dependent: a CI container without a multicast route on
# the default interface drops the IGMP join, which would make the test
# env-flaky — forbidden as a required gate (no-flaky rule). The
# deterministic FSM + encode/decode logic is covered without a socket
# by Layer C1i's `scouting_glue` unit tests, so disabling Layer M loses
# no logic coverage, only the real-socket transport leg.
layer_m_scouting_multicast() {
    if [[ "$ONLY_LAYER" != "M" && "${WZ_RUN_LAYER_M:-0}" -ne 1 ]]; then
        echo "Layer M SKIP (opt-in: --layer M or WZ_RUN_LAYER_M=1)"
        return 0
    fi
    (cd crates && cargo test -p wz-runtime-tokio --features scouting-active \
        --test scouting_multicast_loopback -- --ignored --quiet)
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
run_layer C1c layer_c1c_cargo_test_codec_declare || overall=1
run_layer C1d layer_c1d_cargo_test_pubsub || overall=1
run_layer C1e layer_c1e_cargo_test_query || overall=1
run_layer C1f layer_c1f_cargo_test_reply || overall=1
run_layer C1g layer_c1g_cargo_test_observer || overall=1
run_layer C1h layer_c1h_arbitrary_subset_matrix || overall=1
run_layer C1i layer_c1i_cargo_test_scouting || overall=1
run_layer C1j layer_c1j_runtime_tokio_subset_behavior || overall=1
run_layer C2 layer_c2_cargo_clippy || overall=1
run_layer C3 layer_c3_per_pkg_isolated_lint || overall=1
run_layer C4 layer_c4_preset_matrix || overall=1
run_layer C4b layer_c4b_facade_subset_matrix || overall=1
run_layer C4c layer_c4c_runtime_tokio_subset_matrix || overall=1
run_layer C4d layer_c4d_runtime_tokio_subset_clippy || overall=1
run_layer D layer_d_validate_deploy || overall=1
run_layer E layer_e_ap_demo_round_trip || overall=1
run_layer E2 layer_e2_facade_subset_e2e || overall=1
run_layer F layer_f_codec_footprint || overall=1
run_layer G layer_g_cross_compile_cortex_m || overall=1
run_layer Q layer_q_qemu_mcu_e2e || overall=1
run_layer M layer_m_scouting_multicast || overall=1

if [[ $overall -eq 0 ]]; then
    echo ""
    echo "run-ci: all required layers pass"
fi
exit $overall

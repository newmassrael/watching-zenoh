#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y420 — FILE-SCOPED, and only this file. Every lane runs through
# `run_layer <name> <fn>`, which invokes its argument as `"$@"`, so no layer
# function is reachable by static analysis and neither is any helper only they
# call. shellcheck 0.11 (the pin this round introduced; the check did not exist
# in the 0.8.0 that floated on the runner image before it) therefore reports
# SC2329 on 124 functions here (R311y449 — it read 119, drifted since R311y420
# and widened by y448; it is a MOVING count, so recompute with
# `grep -cE '^[A-Za-z_][A-Za-z0-9_]*\(\) \{' scripts/run-ci.sh` rather than
# trusting this number) — including `_runci_guarded_test`, which has 15
# call sites in this file. The dispatch is the point of the design, so the
# finding is structural rather than a defect to fix. Scoped to this file
# deliberately: SC2329 stays live for the other 17 shell files, none of which
# dispatch indirectly.
# shellcheck disable=SC2329
#
# run-ci.sh — CI-equivalent local check.
#
# Single source of truth for the gate-set the GitHub Actions
# workflow runs. R311y417 — this used to add "and the local
# `.githooks/pre-push` hook invoke this script so the two paths
# cannot drift". R311y386 removed that: pre-push runs
# validate-workspace plus a changed-crate `cargo test -p` and never
# calls this script. Hosted CI is the only caller of the full lane
# set; run it by hand for a local sweep. (R64.1 retrospect: a CI yaml change without local
# verification land-then-fail pattern is exactly what this script
# prevents).
#
# Lanes (matches CI workflow):
#
#   Layer A  — mnemosyne-cli validate-workspace
#   Layer A2 — scripts/audit-mid-values.sh (envelope mid value= gate; R111)
#   Layer A3 — scripts/audit-catalog-status.sh (inventory atom status vs
#              cargo-feature gate reality; joins the Mnemosyne catalog
#              SSOT to the source tree so a reserved-but-gated /
#              active-but-ungated drift cannot pass invisibly — the class
#              every cargo-feature CI lane and validate-workspace both
#              miss because neither knows about the other world)
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
#   Layer C1k — scouting-static synth + static-open seam
#              (R311if; scouting-static is off by default — the static-
#              mode toggle. Builds + runs the wz-session-core scout_static
#              synth unit tests + the wz-runtime-tokio static_scout_open
#              seam under --features scouting-static, which Layer C1 stops
#              building once the static tests gain the gate.)
#   Layer C1o — keyexpr matching composition gating BEHAVIOUR
#              (R311jf; runs the keyexpr_match test module three times —
#              wildcards OFF asserts `**`/`*`/`$*` degrade to a literal
#              chunk compare, wildcards ON asserts the glob + directional
#              `includes` semantics, wildcards ON no-`alloc` exercises the
#              bounded `heapless` candidate buffer + is the only host lane
#              that COMPILES the no-alloc lib tests (R311sx). The
#              behavioural composability guard that proves the per-site cfg
#              gates ACT, not just build.)
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
#              wz-runtime-coop default sync-only + wz-runtime-coop
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
#              analog of C1h / C4b. transport-unicast pinned ON (these
#              subsets exercise the unicast Session FSM; the orthogonal
#              multicast-without-unicast axis is Layer C4e — R311mk). The
#              BUILD half; C1j is the BEHAVIOUR twin over the same SSOT
#              subset list, so the two matrices cannot drift.)
#   Layer C4d — wz-runtime-tokio arbitrary-subset CLIPPY matrix (R311fi;
#              `cargo clippy -D warnings` over the same SSOT subsets C4c
#              builds. Catches clippy lints that only fire in a
#              feature-OFF arm — invisible to C2 `clippy --workspace`
#              which runs the all-on feature union. CLIPPY third of the
#              build/behaviour/lint runtime-crate composability triad.)
#   Layer C4e — transport-axis (multicast-without-unicast) BUILD+CLIPPY
#              (R311mk; the orthogonal axis the consumer-plane matrices
#              C4b/C4c/C1j/C4d cannot express. They vary the consumer plane
#              on a transport-unicast base; this lane varies the transport
#              atom — it builds the facade + clippy-checks the crate under
#              transport-multicast WITHOUT transport-unicast, guarding the
#              unicast decouple that made transport-multicast compose alone.)
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
#              before R291 caught it. R311y415 — it prevents that
#              recurrence by failing the HOSTED ci job (this lane is
#              wired there now); it used to say "failing pre-push",
#              which R311y386 had already made false. `.githooks/
#              pre-commit` Check 2 covers the crates/ half at commit
#              time; this lane's unique reach is the six deploy/*
#              workspaces. See the lane's own header for the detail.
#   Layer F  — codec-footprint catalog truthfulness gate (R311n).
#              Default gate (R311pt — opt-in axis retired). Runs
#              scripts/measure-codec-footprint.sh and exits non-zero
#              if any codec-* atomic feature's minus-<codec> lane
#              measures a near-zero elision delta (default threshold
#              1 KB). Catches the catalog-truthfulness regression
#              shape where a new high-level consumer feature is
#              added without listing it in the implies graph and
#              cargo's resolver silently re-enables the codec the
#              lane was trying to elide. Host-only (python3 + cargo
#              only), so it runs on every default sweep and SKIPs
#              gracefully only when python3 is absent. The bench is
#              expensive (~5-10 min cold; multiple wz-ap-demo release
#              builds) but that cost is no longer a reason to skip it
#              — footprint truthfulness must gate before push.
#   Layer G  — MCU cross-compile catalog (Phase W). Default gate
#              (R311pt — opt-in axis retired). Catalog matrix =
#              (crate × target):
#                Crates:
#                  G.1 (R311ak) wz-runtime-core — §5.P trait skeleton
#                  G.2 (R311am) wz facade no_std cfg_attr toggle
#                  G.3 (R311aq) wz-codecs no_std + alloc — codec wire
#                  G.4 (R311au) wz-runtime-coop — sync alias #![no_std]
#                  G.4-alloc (R311av) wz-runtime-coop --features alloc
#                                 (CoopRuntime + impl Runtime + CoopTime)
#                                 R311bb closed M0+ via portable-atomic
#                                 polyfill — thumbv6m now lands.
#                  G.5 (R311ax) wz facade --features runtime-coop
#                                 (composes wz-runtime-coop through the
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
#              cross-compile interest free of the lane). Promoted to
#              default in R311pt: the wz-runtime-coop caller landed in
#              R311av+, satisfying the promotion condition stated here.
#              Out of scope today: zenoh-pico-sys (arm-none-eabi-gcc
#              install carry, R311ao+). R40 wz-codecs carry resolved
#              by R311aq — codec wire encode/decode now cross-compiles
#              via the alloc-prelude shim in wz-codecs/src/lib.rs;
#              hosted callers see no behavioural delta.
#   Layer Q  — QEMU mps2 + microbit MCU e2e demo + footprint
#              (R311be / R311bg / R311bm-m0). Default gate (R311pt —
#              opt-in axis retired). Three sub-lanes:
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
#              end (wz facade + runtime-coop + CoopRuntime timer
#              queue + CoopJoinHandle::abort + wz-link-lwip UDP raw
#              API + lwip-sys cross-real C build, all in one
#              binary).
#   Layer M  — active-scouting multicast loopback e2e (R311ep). Opt-in
#              via `--layer M` or `WZ_RUN_LAYER_M=1` — the ONE lane that
#              stays opt-in after R311pt retired the cost-based opt-in
#              axis (F/G/Q/Z). Its opt-in is NOT a cost gate: multicast
#              route presence cannot be detected statically (the IGMP
#              join only fails at socket bind time), so a missing route
#              FAILs rather than SKIPs, which would break the no-flaky
#              rule if M were a required gate. Binds a real UDP multicast
#              scouting link (UdpDriver::bind_multicast_v4), emits a
#              Scout, and resolves a peer locator from a Hello on the
#              group. The deterministic FSM + encode/decode logic is
#              covered socket-free by Layer C1i, so opt-out loses only
#              the real-socket leg.
#
# Exit codes:
#   0  every required layer passed
#   1  one or more required layers failed
#   2  setup error (sce-codegen binary missing, wrong cwd, etc.)
#
# Usage:
#   scripts/run-ci.sh                  # full default sweep (= CI mirror)
#   scripts/run-ci.sh --skip-codegen   # skip Layer B (codec emit; ~30s/codec)
#   scripts/run-ci.sh --layer A        # run only the named layer
#   scripts/run-ci.sh --resume         # skip layers that already passed on the
#                                      # IDENTICAL tree (kill/flake re-run); a
#                                      # fingerprint over HEAD + tracked diff +
#                                      # untracked content invalidates on ANY
#                                      # source edit -> full re-run. Opt-in; the
#                                      # the default sweep runs all (R311y417:
#                                      # not the pre-push hook — see the header).
#   WZ_RUN_LAYER_M=1 scripts/run-ci.sh # add the opt-in environment-flaky M lane
#
# Time cost (warm cache):
#   Layer 0: ~20s  A: <1s   B: ~30s   C1: ~10s   C2: ~5s   D: <1s
#     (R311y417 — "<2s" predated the 7-workspace fmt sweep and actionlint;
#      measured 18-30s local, 23-29s hosted)
#   Host-only floor ~50s incremental / ~5min cold. With the cross-
#   toolchain + zenohd/pico binaries present, the default sweep also
#   runs F (codec footprint ~5-10min) + G (7-target cross-compile) +
#   Q (QEMU e2e + footprint) + Z (zenohd interop), so a full local
#   sweep is several minutes even warm. Intentional (R311pt): these
#   gates must run before push, not as opt-in.

set -uo pipefail

# ─── argument parsing ──────────────────────────────────────────────
SKIP_CODEGEN=0
ONLY_LAYER=""
RESUME=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-codegen) SKIP_CODEGEN=1; shift ;;
        --resume) RESUME=1; shift ;;
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
cd "$repo_root" || exit 2

# ─── production logging: complete, clean, leveled ──────────────────
# Force cargo/rustc to line-oriented, color-free, progress-bar-free output so a
# captured log is clean text in EVERY sink (tty / redirect / pipe): a `\r`
# progress-bar rewrite or ANSI colour escape corrupts a persisted log and
# defeats post-hoc grep.
#
# R311y412 — colour is now FORCED off rather than merely defaulted. The lane
# count-guards match `^test result: ok. N passed` at line start, which an ANSI
# escape would break, and `.github/workflows/ci.yml` exports
# CARGO_TERM_COLOR=always for the whole hosted job — so the old `:-` default let
# the one environment we cannot edit from here win over the invariant the guards
# depend on. Today cargo does not forward colour to libtest, so this is
# defence-in-depth, not a live fix; it is one line instead of an ANSI strip at
# every guarded pipeline.
export CARGO_TERM_COLOR=never
export CARGO_TERM_PROGRESS_WHEN="${CARGO_TERM_PROGRESS_WHEN:-never}"

# Self-tee ALL stdout+stderr to a persistent per-run logfile, so the FULL run is
# always on disk INDEPENDENT of how the caller captures our output — no external
# redirect/pipe buffering can drop a layer. (This is the fix for the failure mode
# where a truncated external capture lost the early layers, hiding which lane
# failed.) The EXIT trap closes our fds and waits for tee so the tail — including
# the final verdict — is flushed before we exit: zero omission. The tee also
# writes to the original stdout, so console + hook output is unchanged, and the
# real exit code is preserved. Opt out with RUNCI_NO_SELF_LOG=1.
if [[ "${RUNCI_NO_SELF_LOG:-0}" != "1" ]]; then
    RUNCI_LOG_DIR="${RUNCI_LOG_DIR:-crates/target/run-ci-logs}"
    mkdir -p "$RUNCI_LOG_DIR"
    RUNCI_LOG_FILE="${RUNCI_LOG_FILE:-$RUNCI_LOG_DIR/run-ci-$(date +%Y%m%d-%H%M%S)-$$.log}"
    exec > >(tee "$RUNCI_LOG_FILE") 2>&1
    RUNCI_TEE_PID=$!
    trap 'rc=$?; exec >&- 2>&-; wait "${RUNCI_TEE_PID:-}" 2>/dev/null || true; exit $rc' EXIT
    echo "run-ci: full log -> $RUNCI_LOG_FILE"
fi

# ─── layer runner helpers ──────────────────────────────────────────
# Every lane's start/verdict is a leveled, timestamped line (INFO / ERROR) that
# keeps the historical `Layer <name> pass` / `Layer <name> FAIL` tokens (so
# existing greps + the pre-push hook still match) while adding a wall-clock
# stamp, a duration, and — on failure — the lane name to FAILED_LAYERS for the
# unmissable end-of-run summary. The pass/fail verdict is still the exit code.
FAILED_LAYERS=()
_runci_ts() { date +'%Y-%m-%dT%H:%M:%S%z'; }

# ─── resume checkpoint (--resume) ──────────────────────────────────
# A fingerprint-gated per-layer pass ledger so a killed/failed sweep can be
# re-run with --resume and SKIP the layers that already passed on the IDENTICAL
# tree. SAFETY (the R311gf lesson — a subset run must never hide a break a source
# edit introduced): the fingerprint hashes HEAD + the full tracked diff + every
# untracked file's content, so ANY source change invalidates the checkpoint and
# forces a full re-run. Opt-in only — the default sweep passes no --resume
# (R311y417: nor does any hook; R311y386 stopped pre-push from calling this
# script at all), so it runs every layer unconditionally; it still WRITEs the
# checkpoint (a killed full sweep is then resumable). Disabled under --layer (that
# mode owns lane selection). The ledger lives in .git (untracked), like the
# pre-push run-ci.lock.
CKPT_FILE="$(git rev-parse --git-dir)/run-ci-checkpoint"
[[ -n "$ONLY_LAYER" ]] && RESUME=""   # --layer is a targeted single-lane run
_runci_fingerprint() {
    {
        git rev-parse HEAD 2>/dev/null || echo "no-head"
        git diff HEAD 2>/dev/null
        git ls-files --others --exclude-standard -z 2>/dev/null \
            | sort -z | xargs -0 -r sha256sum 2>/dev/null
    } | sha256sum | cut -d' ' -f1
}
_ckpt_passed() { [[ -f "$CKPT_FILE" ]] && grep -qxF "$1" "$CKPT_FILE"; }
_ckpt_mark()   { [[ -z "$ONLY_LAYER" ]] && printf '%s\n' "$1" >> "$CKPT_FILE"; }
if [[ -z "$ONLY_LAYER" ]]; then
    _ckpt_fp="$(_runci_fingerprint)"
    if [[ -n "$RESUME" && -f "$CKPT_FILE" \
          && "$(head -n1 "$CKPT_FILE" 2>/dev/null)" == "$_ckpt_fp" ]]; then
        echo "[$(_runci_ts)] INFO  resume: checkpoint matches tree; skipping already-passed layers"
    else
        [[ -n "$RESUME" ]] && \
            echo "[$(_runci_ts)] INFO  resume: no matching checkpoint (tree changed or none); running ALL layers"
        printf '%s\n' "$_ckpt_fp" > "$CKPT_FILE"   # fresh ledger: fingerprint header only
    fi
fi

# ─── footprint build normalisation (SSOT) ──────────────────────────
#
# The rustc flags that make a footprint-gated binary's .text/.rodata
# independent of WHERE it was built. Consumed by Layer Q (which exports them
# for every MCU build) and re-asserted per measurement by
# scripts/check-footprint.sh, which FAILs if either prefix still appears in the
# ELF — so a binary built without these cannot be silently footprint-gated.
#
# The two prefixes are the only absolute paths rustc embeds: the workspace
# (panic `Location` strings for local crates + the OUT_DIR generated sources)
# and $CARGO_HOME (registry dependency sources). rustc already canonicalises
# std/core to /rustc/<hash>. The replacement strings are arbitrary but must be
# FIXED — their length is what the baseline encodes.
footprint_remap_rustflags() {
    local cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    echo "--remap-path-prefix=${repo_root}=/wz --remap-path-prefix=${cargo_home}=/cargo"
}

run_layer() {
    local name="$1"
    shift
    if [[ -n "$ONLY_LAYER" && "$ONLY_LAYER" != "$name" ]]; then
        return 0
    fi
    # Record that the requested --layer actually exists; the end-of-run check
    # turns an unmatched name into a FAILURE instead of a silent green.
    LAYER_MATCHED=1
    if [[ -n "$RESUME" ]] && _ckpt_passed "$name"; then
        echo "[$(_runci_ts)] INFO  Layer $name SKIP (resume: already passed on this tree)"
        return 0
    fi
    echo "[$(_runci_ts)] INFO  ──── Layer $name ────"
    local start=$SECONDS
    if "$@"; then
        echo "[$(_runci_ts)] INFO  Layer $name pass ($((SECONDS - start))s)"
        _ckpt_mark "$name"
        return 0
    else
        local rc=$?
        echo "[$(_runci_ts)] ERROR Layer $name FAIL (rc=$rc, $((SECONDS - start))s)" >&2
        FAILED_LAYERS+=("$name")
        return 1
    fi
}

# ─── _runci_guarded_test — a cargo-test call plus an anchored count guard ─────
#
# `cargo test <filter>` EXITS 0 WHEN THE FILTER MATCHES ZERO TESTS, and a
# `--test <bin>` whose cases all cfg out prints `0 passed` and exits 0 too. A
# bare invocation therefore reports success BY SILENCE the moment a cfg gate, a
# rename or a feature-set edit elides its subject — this repo's #1 hazard class.
# Every guarded call asserts the libtest summary line the run must print.
#
#   _runci_guarded_test <label> <expect> <cargo> <args...>
#
#   <label>   lane tag carried into the FAIL diagnostic (e.g. C1ad)
#   <expect>  an integer -> EXACT `N passed`. For small stable sets (one e2e
#             binary, one named test) and for feature-gated filters whose COUNT
#             is itself the proof (a lower count = a gate stopped activating).
#             `+`        -> `>=1 passed`. For large module filters that grow
#             legitimately, where an exact number would only breed churn — the
#             R311y280 Layer C1bg precedent.
#
# The command runs in `crates/`. Its output is STREAMED (`tee /dev/stderr`, so a
# lane killed by the job's `timeout-minutes` still leaves its diagnostics in the
# log — R311y414 review finding) AND captured for the assert. The assert reads
# the captured copy rather than sitting in the pipe, because a `... | grep -q`
# stage races its upstream's SIGPIPE against `grep`'s early exit under this
# script's `set -o pipefail` — a false RED once the post-summary output exceeds
# the pipe buffer.
#
# <expect> is validated up front: `+` or a POSITIVE integer. `0` is rejected on
# purpose — "assert that nothing ran" is never the intent, and accepting it
# would silently re-open the hazard this helper closes.
_runci_guarded_test() {
    local label="$1" expect="$2"
    shift 2
    local out pat want
    if [[ "$expect" == "+" ]]; then
        pat='^test result: ok\. [1-9][0-9]* passed'
        want=">=1 passed"
    elif [[ "$expect" =~ ^[1-9][0-9]*$ ]]; then
        pat="^test result: ok\. ${expect} passed"
        want="exactly ${expect} passed"
    else
        echo "  ${label} FAIL: guard expectation must be '+' or a positive integer, got '${expect}'"
        return 1
    fi
    if ! out="$( (cd crates && "$@") 2>&1 | tee /dev/stderr )"; then
        echo "  ${label} FAIL: \`$*\` exited non-zero"
        return 1
    fi
    if ! grep -qE "$pat" <<< "$out"; then
        echo "  ${label} FAIL: expected ${want} from \`$*\` — no libtest summary matched, so the run either printed a DIFFERENT count or selected NO tests (which still exits 0)"
        return 1
    fi
}

# Run one QEMU MCU case, CAPTURING qemu stdout+stderr so a FAIL is diagnosable
# from a SINGLE run (no reproduction needed). On PASS the output is discarded
# (the lane stays quiet); on FAIL the captured output AND the exit-code meaning
# (124 = the outer wall-clock timeout [R311y14: 30s, was 10s] = hang / runaway
# loop, vs a non-zero semihost SYS_EXIT) are surfaced to stderr. Pre-R311q2
# every Q.0/Q.2/Q.4 qemu run
# redirected to /dev/null, so a rare emulator transient (the R311pw an385 /
# R311q1 an386 SYS_EXIT hiccup) left ZERO forensic trace and could only be
# chased by re-running — this helper records everything the first time.
# The PASS/FAIL line itself is echoed here (label + " PASS"/" FAIL (why)"), so
# callers only branch on the return code. Args: 1=label 2=cpu 3=machine 4=elf.
run_qemu_case() {
    local label="$1" cpu="$2" machine="$3" kernel="$4"
    local qlog rc
    qlog="$(mktemp)"
    # Wall-clock bound on the qemu run — a backstop against a GENUINE
    # runaway / livelock, not a flake-suppressant. R311y14 misdiagnosed
    # the mps2-an386/an500 Layer-Q failure as a load-slowdown and bumped
    # 10s -> 30s; that was wrong (a 30s bound never fixes a hang). R311y15
    # root-caused it: the mcu-qemu-demo SystickClock::now_us() was
    # non-monotonic when the SysTick exception was delayed past a wrap
    # boundary on the Cortex-M4F/M7 (FPU) lanes, which lost a SleepFuture
    # wakeup and livelocked the cooperative loop — the demo carried the
    # bug, the timeout only masked how long it ran. With the clock now
    # monotonic the demo completes in ~2s standalone on every M-class
    # lane (verified 60/60 under deterministic `-icount`, which previously
    # reproduced the hang ~1/3). The 30s bound stays as a generous runaway
    # backstop. [[feedback-no-flaky-ever]] — the fix is the clock, not the
    # timeout / retry-until-green / --no-verify.
    local timeout_s=30
    # `else rc=$?` (not a post-`fi` capture): after a false `if cond; then …;
    # fi` bash resets $? to 0, so the timeout exit code is only readable inside
    # the else branch.
    if timeout "$timeout_s" qemu-system-arm \
        -cpu "$cpu" -machine "$machine" \
        -nographic -semihosting-config enable=on,target=native \
        -kernel "$kernel" >"$qlog" 2>&1; then
        echo "  ${label} PASS"
        rm -f "$qlog"
        return 0
    else
        rc=$?
    fi
    local why="exit=${rc}"
    if [[ "$rc" -eq 124 ]]; then
        why="exit=124 (${timeout_s}s timeout — hang / runaway loop)"
    fi
    {
        echo "  ${label} FAIL (${why})"
        echo "  ── ${label}: captured qemu output (R311q2 one-shot diagnosis) ──"
        if [[ -s "$qlog" ]]; then
            sed 's/^/    | /' "$qlog"
        else
            echo "    | <qemu produced no output before exit ${rc}>"
        fi
        echo "  ── ${label}: end qemu output ──"
    } >&2
    rm -f "$qlog"
    return "$rc"
}

# ─── Layer 0 — preflight lints (fmt mandatory + actionlint optional) ──
#
# R291: cargo fmt --check is promoted into Layer 0 as a mandatory
# preflight gate. Rationale — R285→R287 wz-ap-demo decomposition
# pushed multi-hundred-KB of fmt drift onto main without local
# rejection because the prior Layer 0 only carried optional
# actionlint and no lane invoked rustfmt at all.
#
# R311y415 — WHERE the gate fires, corrected. This comment used to
# claim "the same gate fires locally (pre-push hook) and remotely
# (.github/workflows/ci.yml), so a fmt-dirty commit cannot reach
# origin/main again". Both halves were false: R311y386 cut the
# pre-push hook down to validate-workspace + changed-crate `cargo
# test -p` (its own header lists fmt among what it no longer
# covers), and Layer 0 was in NO hosted --layer set.
#
# What that did NOT mean — and a first cut of R311y415 got this
# wrong before review caught it — is that fmt was gated nowhere.
# `.githooks/pre-commit` Check 2 runs `(cd crates && cargo fmt --all
# -- --check)` whenever a `crates/**.rs` is staged, so a fmt-dirty
# commit to the crates workspace was already rejected at commit
# time. The REAL gap this lane closes is narrower and still real:
# pre-commit filters on `^crates/.+\.rs$` and runs only in `crates`,
# so the SIX auto-discovered `deploy/*` workspaces were gated by
# nothing — and the whole hook path is skipped by `--no-verify` or
# an uninstalled core.hooksPath. R311y415 wires `--layer 0` into the
# ci job, so the hosted run is the backstop for all seven. The
# pre-push hook still does not run it, by the R311y386 design — run
# `bash scripts/run-ci.sh --layer 0` by hand when you touch a
# `deploy/*` workspace, which is the half pre-commit cannot see.
#
# actionlint: optional LOCALLY, MANDATORY on the hosted ci job.
# R311y416 wired it — the job installs a pinned v1.7.12 (+sha256) and
# sets WZ_LINT_REQUIRE=1, so an absent actionlint or shellcheck is
# FATAL there, while both stay non-fatal locally so a dev without
# them is not blocked. Confirmed on run 30235292100:
# `actionlint OK (1.7.12)`. This closed the gap y414 and y415 each
# disclosed. R311y417 — the text that used to sit here still called
# it "optional", "EXPECTED to SKIP hosted" and "a deliberate
# DEFERRAL"; every clause was false the moment y416 landed, and it
# survived because the round edited this function without re-reading
# its own header. Same class y415 spent a round retracting.
layer_0_preflight_lints() {
    # 0.1 cargo fmt --check across every workspace (mandatory). crates/ is
    # the primary workspace; each deploy/*/ that carries its OWN
    # `[workspace]` table is a standalone workspace the crates/ fmt --check
    # does not visit (R311be `mcu-qemu-demo`, R311hl `mcu-noheap-probe`,
    # R311iv `mcu-session-acceptor`). R311iw — these were enumerated one
    # `if`-block per crate, and the enumeration was forgotten for
    # mcu-session-acceptor (it shipped un-gated until R311iv caught a fmt
    # FAIL on a full run). Auto-discovery replaces the manual list for the
    # layouts the globs below reach. R311y415 — it does NOT make the
    # stronger guarantee this comment used to claim ("a NEW standalone
    # deploy workspace is fmt-gated the moment it exists"): a workspace
    # nested one level deeper than `deploy/*/*/` is silently not gated,
    # reproduced at R311y415. The floor below is what converts that class
    # from a silent green into a red; the globs still need widening by hand
    # when a deeper layout lands.
    # R311y31 — also scan one level deeper (`deploy/*/*/`): the Zephyr deploy is
    # west/cmake-driven at deploy/zephyr-app/, with its Rust staticlib workspace
    # nested at deploy/zephyr-app/rust/. The extra glob keeps the auto-discovery
    # invariant ("any standalone deploy workspace is fmt-gated") for nested
    # layouts; it still only matches a dir that carries its OWN `[workspace]`.
    local fmt_dirs=(crates)
    local dpath
    for dpath in deploy/*/ deploy/*/*/; do
        [[ -f "${dpath}Cargo.toml" ]] || continue
        grep -qE '^[[:space:]]*\[[[:space:]]*workspace[[:space:]]*\]' \
            "${dpath}Cargo.toml" || continue
        fmt_dirs+=("${dpath%/}")
    done
    # R311y415 — DISCOVERY FLOOR. The loop above had no lower bound, so a
    # deploy workspace the globs miss (one nested a third level deep, which
    # R311y31 already had to widen the glob for once) was not reported as
    # ungated: the lane simply printed `fmt --check OK` over the shorter
    # list and returned 0. That was moot while Layer 0 ran nowhere; hosting
    # it (R311y415) makes the hole load-bearing, and it is the same
    # "success by silence" class y414's _runci_guarded_test closes by
    # rejecting an expect of 0. The floor turns every future discovery miss
    # into a red. Bump it in the same commit that adds a workspace.
    local -r fmt_dirs_min=7   # crates + 6 deploy workspaces @ R311y415
    if (( ${#fmt_dirs[@]} < fmt_dirs_min )); then
        echo "  Layer0 FAIL: fmt discovery found ${#fmt_dirs[@]} workspace(s), expected >= ${fmt_dirs_min}" >&2
        echo "  found: ${fmt_dirs[*]}" >&2
        return 1
    fi
    # R311y415 — accumulate rather than fail-fast. A `return 1` on the first
    # dirty workspace costs one full hosted round-trip PER dirty workspace;
    # reporting all of them is one push instead of N.
    #
    # READ THE OUTPUT AS FILES, NOT AS A WORKSPACE COUNT. These seven
    # workspaces OVERLAP: every deploy/* one path-depends on crates/, and
    # `cargo fmt --all` follows that, so ONE dirty file under crates/ makes
    # all seven report FAIL (measured at R311y415). That is not seven
    # problems — the fail-fast form simply hid the redundancy by returning
    # on the first. The `Diff in <path>` lines cargo prints above each FAIL
    # are the actual defect list. The unique reach of the six deploy lanes
    # is their OWN sources, which nothing else in the repo fmt-checks.
    local fdir fmt_rc=0
    for fdir in "${fmt_dirs[@]}"; do
        if ! (cd "$fdir" && cargo fmt --all -- --check --color=never); then
            # R311y415 — ` FAIL: ` exactly, not the older ` FAIL `: that is
            # the token y414's GitHub `::error` extractor lifts. With the
            # old spelling every Layer 0 red produced an EMPTY annotation
            # body, the same defect y414 fixed for the count guards.
            echo "  Layer0 FAIL: fmt --check ${fdir} — run \`(cd ${fdir} && cargo fmt --all)\`" >&2
            fmt_rc=1
        fi
    done
    (( fmt_rc == 0 )) || return 1
    echo "  fmt --check OK (${fmt_dirs[*]})"

    # 0.3 actionlint — optional locally, REQUIRED where WZ_LINT_REQUIRE=1.
    # (0.2 below runs first; both are gated on the same lint_required axis,
    # and the shellcheck-presence resolution they share is hoisted above 0.2.)
    #
    # R311y416 — the hosted ci job sets WZ_LINT_REQUIRE=1 and installs a
    # pinned actionlint, so a missing binary there is a provisioning
    # regression that must fail RED. Without this axis the download could
    # break and the lane would keep printing SKIP and returning 0 — the
    # "success by silence" shape this file spent R311y415 closing for fmt.
    # Same idiom as WZ_QZ_REQUIRE / WZ_A3_REQUIRE.
    # R311y417 — GITHUB_ACTIONS is a second, independent trigger for REQUIRE
    # mode. WZ_LINT_REQUIRE is a bare string contract across two files
    # (ci.yml sets it, this function reads it); drop or typo either side and
    # the gate silently reverts to SKIP-green, which is the failure this lane
    # exists to prevent. Any hosted run provisions actionlint, so asserting
    # unconditionally under GITHUB_ACTIONS costs nothing and removes the
    # single point of failure. Same belt-and-braces as y414 making an
    # unknown `--layer` a hard error instead of a silent no-op.
    local lint_required=0
    [[ "${WZ_LINT_REQUIRE:-0}" == "1" || "${GITHUB_ACTIONS:-}" == "true" ]] \
        && lint_required=1

    # Presence of shellcheck is resolved HERE, before either lint runs,
    # because BOTH depend on it and they fail differently without it. (Note
    # the phrasing: a comment starting with the word itself is a DIRECTIVE.
    # See 0.2 below.) R311y419 moved
    # this up from inside the actionlint block: it used to sit after that
    # block's `return 0`, so a developer without actionlint skipped the script
    # lint below as well, even with shellcheck installed. Two independent tools
    # must not share one another's absence.
    #
    # For actionlint the dependency is indirect: it runs its shellcheck
    # integration ONLY if shellcheck is on PATH, and silently drops those
    # checks otherwise. Its other 36 documented check categories are native and
    # DO still run — R311y417 corrects y416's "near-empty gate", which
    # undersold the tool it was justifying. The load-bearing fact is narrower
    # and measured: every finding this repo's workflows have ever produced came
    # through its shellcheck integration (swept at R311y417 across all 83
    # historical revisions of .github/workflows/ — 103 finding lines, 103 of
    # them shellcheck-backed, zero native). So on THIS repo an actionlint
    # without shellcheck would have passed the dirty tree: with the y416 fixes
    # reverted it exits 1 with shellcheck and 0 without. Under WZ_LINT_REQUIRE
    # the absence is therefore fatal to both.
    local have_shellcheck=1
    if ! command -v shellcheck >/dev/null 2>&1; then
        if [[ "$lint_required" == "1" ]]; then
            echo "  Layer0 FAIL: shellcheck REQUIRED (WZ_LINT_REQUIRE=1 or GITHUB_ACTIONS) but not on PATH — 0.2 cannot run and actionlint would silently drop its shellcheck checks" >&2
            return 1
        fi
        have_shellcheck=0
        echo "  shellcheck absent — 0.2 SKIP, and actionlint SC* checks will be skipped"
    fi

    # 0.2 shellcheck over the repo's OWN shell — the surface actionlint does
    # NOT reach. actionlint (0.3) shellchecks the `run:` blocks INSIDE
    # .github/workflows/; scripts/*.sh, scripts/lib/*.sh and .githooks/* are
    # disjoint from that, and until R311y419 they were linted by NOTHING. That
    # is what R311y418 disclosed after hand-checking ~150 new hook lines.
    #
    # Hand-checking is also precisely what missed the defect this lane found on
    # its first run, in THIS file: two prose comments began with the word
    # `shellcheck`, which shellcheck reads as a malformed DIRECTIVE
    # (SC1073/SC1072) and then abandons the enclosing brace group over
    # (SC1009). All ~13k lines of run-ci.sh — including this function, the one
    # that runs the linters — were therefore analysed by nothing, and four real
    # findings sat behind that silence: an unguarded `cd "$repo_root"`, two
    # unquoted expansions inside a `date -d @$…`, and two dead locals. A
    # comment whose first token STARTS WITH `shellcheck` is a directive, not
    # prose (the match is a prefix — `shellcheck-backed` triggers it too, which
    # is how the second one survived the sweep for the first). Keep the word
    # off the start of a comment line.
    #
    # Severity is left at shellcheck's default (style and up) rather than
    # narrowed to warnings: the whole surface is clean at that bar today, so
    # nothing is bought by grading looser, and SC2086-class quoting findings
    # are `info` — exactly the kind this lane should keep catching.
    if [[ "$have_shellcheck" == "1" ]]; then
        # No mapfile: schema-pin-gate.sh already avoids it for bash 3.2 (stock
        # macOS), and a lint lane is a poor place to reintroduce the dependency.
        # .githooks/* entries are extensionless, so they are admitted by SHEBANG
        # rather than by name — a future non-shell file dropped in that
        # directory then neither breaks the lane nor silently widens it.
        local -a sc_files=()
        local scf
        while IFS= read -r scf; do
            case "$scf" in
                *.sh) sc_files+=("$scf") ;;
                .githooks/*)
                    [[ -f "$scf" ]] \
                        && head -n1 "$scf" | grep -qE '^#!.*\b(ba)?sh\b' \
                        && sc_files+=("$scf") ;;
            esac
        done < <(git ls-files -- '*.sh' '.githooks/*')
        # DISCOVERY FLOOR, same contract as fmt_dirs_min above: without it a
        # pathspec that stops matching degrades to "linted fewer files" and
        # still prints OK. Bump it in the same commit that adds a script.
        local -r sc_files_min=18   # 15 scripts/**.sh + 3 .githooks @ R311y419
        if (( ${#sc_files[@]} < sc_files_min )); then
            echo "  Layer0 FAIL: shellcheck discovery found ${#sc_files[@]} file(s), expected >= ${sc_files_min}" >&2
            return 1
        fi
        if ! shellcheck "${sc_files[@]}"; then
            echo "  Layer0 FAIL: shellcheck reported findings (see above)" >&2
            return 1
        fi
        echo "  shellcheck OK (${#sc_files[@]} files)"
    fi

    if ! command -v actionlint >/dev/null 2>&1; then
        if [[ "$lint_required" == "1" ]]; then
            echo "  Layer0 FAIL: actionlint REQUIRED (WZ_LINT_REQUIRE=1 or GITHUB_ACTIONS) but not on PATH" >&2
            return 1
        fi
        # R311y417 — points at the PIN, not `@latest`. The install step in
        # ci.yml argues that an unpinned linter is a spontaneous-red hazard;
        # telling a developer to fetch @latest here would hand them a
        # different finding set than the gate grades against.
        echo "  actionlint SKIP (not installed; install the ci pin — see the \"Install actionlint\" step in .github/workflows/ci.yml)"
        return 0
    fi
    # R311y417 — NO path argument. y416 passed `.github/workflows/*.yml`,
    # which silently skips `.yaml` files; GitHub accepts BOTH extensions
    # (workflow-syntax docs: "must have either a `.yml` or `.yaml` file
    # extension"), so a future `deploy.yaml` would have been linted by
    # nothing while the lane stayed green — the exact success-by-silence
    # class this lane was armed to close. Bare `actionlint` auto-discovers
    # the project from cwd (run_layer cd's to the repo root), covers both
    # extensions and subdirectories, and is still LOUD on the empty cases:
    # no workflow files -> rc=3 "no YAML file was found", no .github ->
    # rc=3 "no project was found". Verified all four ways at R311y417.
    # Known limit, recorded rather than implied: composite
    # `.github/actions/*/action.yml` files are NOT linted by actionlint at
    # all. This repo has none today.
    local al_version
    al_version=$(actionlint --version 2>/dev/null | head -1) || al_version=""
    [[ -n "$al_version" ]] || al_version="version unknown"
    if ! actionlint; then
        echo "  Layer0 FAIL: actionlint reported findings (see above)" >&2
        return 1
    fi
    # Log BOTH versions. R311y420 pinned shellcheck too (its own
    # checksummed ci.yml step), so this is no longer the only record of an
    # unpinned input — but it stays, because LOCAL runs are still graded by
    # whatever shellcheck the developer has, and this line is what makes a
    # local green comparable to a hosted one.
    echo "  actionlint OK (${al_version}; $(shellcheck --version 2>/dev/null | awk '/^version:/{print "shellcheck " $2}' || true))"

    # 0.4 — the zenoh-c ORACLE-ARM resolver, driven on all four feature
    # combinations plus the refusal case.
    #
    # R311y566. `check-capi-c-opaque-arms.sh` calibrated its generator against
    # the `nounstable` table unconditionally. That matched the author's
    # `~/.local` (a plain archive) and could never match hosted CI's
    # unstable+SHM oracle, so the `capi-c-arms` job redded on a check
    # structurally unable to pass and the four-arm comparison behind it went
    # unrun from R311y542. The arm is now READ from the oracle's own
    # `zenoh_configure.h`, and this drives that resolver rather than a copy of
    # its logic — the shape of check a count guard nothing ties to its binary
    # already taught this tree to distrust.
    #
    # In Layer 0 because it needs no oracle, no toolchain and no network: it
    # synthesises its prefixes. The lane it PROTECTS (`capi-c-arms`) is
    # hosted-only and opt-in, which is precisely why its resolver has to be
    # checkable here.
    if ! bash scripts/lib/test-zenoh-c-oracle-arm.sh; then
        echo "  Layer0 FAIL: the zenoh-c oracle-arm resolver is wrong (see above)" >&2
        return 1
    fi
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

# ─── Layer A3 — catalog status truthfulness gate ────────────────────
# Asserts every Mnemosyne inventory atom's status agrees with the
# cargo-feature gate reality in crates/**. Motivation: the cargo-feature
# CI triad (build/behaviour/clippy/footprint) never inspects the
# inventory, and Layer A's validate-workspace never inspects the source
# gates, so a status that drifts from the code it describes (e.g. Phase 2
# R311fx wired pubsub-source-info to real gates but left it "reserved")
# is invisible to both. This gate is the join.
layer_a3_audit_catalog_status() {
    bash scripts/audit-catalog-status.sh
}

# ─── Layer A4 — cross-impl PROOF axis (R311y259) ────────────────────
# A3 answers "is there a knob?" and -- for every atom whose impl axis has been
# TAGGED -- "is it built?". R311y299: that second half is a LOWER BOUND, not a
# total; A3 reports its unaudited remainder rather than asserting completeness.
# A4 answers the question the north
# star actually turns on: "is it PROVEN against a real foreign implementation?" It joins
# the catalog to the interop corpus (derived from the harness call graph) and to cargo's
# feature closure (which mechanically refutes a claim for code that is not compiled in).
layer_a4_audit_crossimpl_proof() {
    bash scripts/audit-crossimpl-proof.sh
}

# ─── Layer A5 — preset-ap-full MEMBERSHIP gate (R311y496) ───────────
# A3 asks "is there a knob?", A4 asks "is it proven against a foreign impl?".
# Neither asks whether the KITCHEN-SINK ARTIFACT actually contains the atom, and
# nothing else did either: preset-ap-full's membership was hand-maintained and
# dropped a whole family in four consecutive rounds (y461 routing-token-tables,
# y488 ext-pubsub-*, y489 adminspace-*, y491 the router-hat tier), each found by
# accident, none recorded as a decision anywhere. y496 found the fifth (the
# storage manager and every backend) and, because that one left the AP-full node
# reporting a live storage it could not serve a single read from, made the case
# that four rounds of the same shape is a missing gate rather than five separate
# mistakes.
#
# The gate DERIVES membership from cargo + the Mnemosyne inventory and enforces a
# reasoned exclusion table whose entries are re-validated against the inventory
# every run, so an exclusion cannot outlive its justification. It also enforces
# the wz-ap-demo manifest's own "held back" rule, which was prose until now.
#
# mnemosyne-cli / python3 absence is a SKIP on a dev box (they may not have the
# tool) and a FAIL where WZ_A5_REQUIRE is set -- the same rule as A3/A4/Qz: a
# lane that SKIPs where the job provisions its input is a provisioning
# regression wearing a green badge.
layer_a5_apfull_membership() {
    if ! command -v mnemosyne-cli >/dev/null 2>&1; then
        if [[ -n "${WZ_A5_REQUIRE:-}" ]]; then
            echo "  Layer A5 FAIL — required (WZ_A5_REQUIRE set) but mnemosyne-cli not on PATH" >&2
            return 1
        fi
        echo "  Layer A5 SKIP (mnemosyne-cli not on PATH)"
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        if [[ -n "${WZ_A5_REQUIRE:-}" ]]; then
            echo "  Layer A5 FAIL — required (WZ_A5_REQUIRE set) but python3 not on PATH" >&2
            return 1
        fi
        echo "  Layer A5 SKIP (python3 not on PATH)"
        return 0
    fi
    python3 scripts/lib/apfull_membership.py
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
        echo "Layer B: sce-codegen stale (built $(date -d @"$bin_mtime_epoch" +%F) vs pin $(date -d @"$sce_head_epoch" +%F)); rebuilding"
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
    #
    #   msg_put, msg_del — R311y583 raised the ext-chain `max-depth` from 4
    #             to 8 across every entry-flag chain in sources/codecs/,
    #             for a measured reason: at 4, a Put carrying five
    #             extensions decoded to Ok with a payload of three bytes
    #             that were never the payload (the generated decode leaves
    #             the loop on the FOR bound with the last entry's Z still
    #             set and reads `payload_len` from the next extension's
    #             header). SCE's upstream codec_zenoh_msg_{put,del}
    #             fixtures are still at 4, so these two stems no longer
    #             body-match. They are the ONLY two of the fifteen changed
    #             that HAVE an upstream fixture, which is why the list
    #             grows by two and not by fifteen.
    #
    #             Two things clear this entry, and they are separate: SCE
    #             lifting its fixtures to the same depth, and SCE honouring
    #             `on-overflow="reject"` on the entry-flag path at all
    #             (claudedocs/sce-report-tlv-chain-entry-flag-overflow.md
    #             — until then the depth is a cliff moved, not removed).
    #
    #             R311y589 — the SECOND condition is now MET and the first
    #             is not, which is exactly why they were written as two.
    #             SCE landed the guard (ec3b032984) and wz's compensating
    #             seam is deleted; the cliff is REMOVED, not merely moved.
    #             The upstream fixtures still declare max-depth="4"
    #             (vendor/sce/tests/forge/resources/codec_zenoh_msg_put
    #             .scxml:82), so the body diff survives on its own and
    #             this entry stays. MEASURED, not assumed: Layer B was
    #             re-run against pin fbc29c4d14 and both stems still
    #             report L2 MISMATCH.
    #             Layer 3 (crates/wz-integration-tests/tests/
    #             layer3_msg_{put,del}.rs, byte-compared against
    #             zenoh-pico's own encoder) is the real wire check and is
    #             GREEN: the depth is a decoder bound and changes no
    #             emitted byte.
    #
    #             R311y598 — CLOSED, and the FIRST condition is what closed
    #             it. Vendor pin ef4c2fe4d5 lifts both upstream fixtures to
    #             max-depth="8" (codec_zenoh_msg_put.scxml:82,
    #             codec_zenoh_msg_del.scxml:68), so the two stems body-match
    #             wz again and are REMOVED from the list below. MEASURED:
    #             Layer B at this pin reports `msg_put OK` / `msg_del OK`.
    #             The removal is the point, not bookkeeping — the array is
    #             read ONLY on a failing pair, so a stale entry would excuse
    #             a FUTURE genuine divergence in these stems as
    #             audit-traced.
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
    return "$fail"
}

# ─── Layer B2 — committed-codegen regen-diff gate (R311y22) ─────────
#
# R311y22 moved the SCXML->Rust codegen out of the per-crate build.rs
# scripts and into committed files under out/** (so a plain `cargo build`
# of the wz stack needs no libxml2/SCE toolchain). This gate keeps the
# committed tree honest: regenerate it via the xtask codegen SSOT, then
# fail if it differs from what is committed. With this gate, the committed
# out/** is a VERIFIED CACHE of the SCXML SSOT (committed == regenerated),
# never a second source of truth — the standard discipline for committed
# generated code behind a heavy generator.
#
# Skips gracefully (like Layer B) when the codegen toolchain is absent:
# the xtask pulls sce-build -> libxml (native libxml2), so a dev box
# without libxml2 cannot regenerate. CI Linux has libxml2 (it builds
# sce-codegen for Layer B), so the gate runs there.
layer_b2_regen_diff() {
    if [[ $SKIP_CODEGEN -eq 1 ]]; then
        echo "Layer B2 SKIP (--skip-codegen)"
        return 0
    fi
    # The statechart/buffer-pool regen leg shells the vendored sce-codegen
    # binary (the codec leg uses sce-build in-process). Absent -> SKIP, not
    # FAIL (mirrors Layer B). In a full run-ci, Layer B builds + freshness-
    # checks the binary before this lane, so it is present here.
    if [[ ! -x vendor/sce/target/release/sce-codegen ]]; then
        echo "Layer B2 SKIP (sce-codegen not built; run scripts/build-sce.sh — needed for the statechart/pool regen)"
        return 0
    fi
    # Build the xtask first; a libxml2-absent box fails here -> SKIP, not FAIL
    # (the gate is a maintainer freshness check, not a consumer build step).
    if ! cargo build --manifest-path xtask/Cargo.toml --quiet >/dev/null 2>&1; then
        echo "Layer B2 SKIP (xtask build failed — libxml2/sce-build toolchain absent?)"
        return 0
    fi
    if ! cargo run --manifest-path xtask/Cargo.toml --quiet -- regen >/dev/null 2>&1; then
        echo "Layer B2 FAIL: xtask regen errored" >&2
        return 1
    fi
    local dirty
    dirty="$(git status --porcelain -- out/ 2>/dev/null)"
    if [[ -n "$dirty" ]]; then
        echo "Layer B2 FAIL: committed out/** is stale vs regenerated —" >&2
        echo "  run scripts/regen-codegen.sh and commit out/:" >&2
        echo "$dirty" >&2
        return 1
    fi
    # R311y517 — the regen-diff above CANNOT catch a machine-dependent emit on
    # the machine that produced it: whoever last regenerated sees
    # `committed == regenerated` by construction, and only a checkout at a
    # DIFFERENT path reds. That is exactly how the y510 SCE pin bump shipped the
    # author's home directory into 8 `// From:` headers and left hosted Layer B2
    # red for five consecutive runs while every local run was green — the gate
    # was structurally blind on the one machine that could have fixed it.
    #
    # This assertion is the machine-INDEPENDENT half, and it is cheap: no
    # committed generated file may carry an ABSOLUTE source path, because an
    # absolute path is by definition the thing that differs across checkouts.
    # (SCE 43695e572 emits the `// From:` line verbatim as the caller named it —
    # `header_source_path`, vendor/sce/sce-build/src/lib.rs:330-334 — so keeping
    # the path relative is the emitter contract, enforced here.)
    local abs_src
    abs_src="$(grep -rn '^// From: /' out/ 2>/dev/null || true)"
    if [[ -n "$abs_src" ]]; then
        echo "Layer B2 FAIL: committed out/** carries an ABSOLUTE source path —" >&2
        echo "  the emit is machine-dependent, so hosted CI reds on EVERY run" >&2
        echo "  while this box stays green. Fix the xtask path hand-off" >&2
        echo "  (xtask/src/main.rs \`repo_relative\`), regen, and commit out/:" >&2
        echo "$abs_src" >&2
        return 1
    fi
    echo "Layer B2 pass (committed out/** == regenerated, no absolute source path)"
    return 0
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
    # R311y259 — the "does this test spawn an external binary?" predicate now comes from
    # scripts/lib/crossimpl_corpus.py, which BOTH this layer and Layer A4 consume. The
    # prior inline grep (`wz_ap_demo_binary()\|zenoh_pico_cli_binary(`) missed every test
    # that reaches a binary through a wrapper helper -- concretely, pubkey_zenohd_interop
    # and usrpwd_zenohd_interop spawn zenohd and nothing else, so their #[ignore]
    # discipline was never actually gated. One predicate, two consumers, no drift.
    #
    # The list is materialised BEFORE the loop and its exit status checked. A process
    # substitution (`done < <(python3 ...)`) does NOT propagate the producer's exit
    # status, and `set -euo pipefail` does not catch it either: a python failure (no
    # python3 on the runner, a UnicodeDecodeError on a new test file) would yield an
    # empty list, zero loop iterations, zero violations -- and a GREEN "Layer C0 pass"
    # having checked nothing. The predecessor (`find ... -name '*.rs'`) could not fail
    # empty; this dependency has to be guarded to keep that property.
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Layer C0 FAIL: python3 not on PATH (needed by scripts/lib/crossimpl_corpus.py)" >&2
        return 1
    fi
    local spawn_list
    spawn_list="$(mktemp)"
    if ! python3 scripts/lib/crossimpl_corpus.py --list-spawn >"$spawn_list"; then
        rm -f "$spawn_list"
        echo "Layer C0 FAIL: crossimpl_corpus.py --list-spawn errored" >&2
        return 1
    fi
    if [[ ! -s "$spawn_list" ]]; then
        rm -f "$spawn_list"
        echo "Layer C0 FAIL: the spawn-class corpus came back EMPTY -- the predicate is" >&2
        echo "  broken, not the tree (there are binary-dep tests). Refusing to pass green." >&2
        return 1
    fi
    while IFS= read -r f; do
        local report
        # Both #[test] and #[tokio::test(...)] mark a test; the old awk matched only the
        # former, so ~20 corpus files' #[ignore] discipline rode on convention, not a gate.
        # The `^[[:space:]]*` anchor matches the shared parser's, so C0 and A4 agree on
        # what a test IS -- an indented #[test] (inside a mod / proptest! block) must not
        # be a test to one gate and invisible to the other.
        report=$(awk '
            /^[[:space:]]*#\[(test|tokio::test)/ {
                test_line = NR
                if ((getline next_line) > 0 && next_line ~ /^[[:space:]]*#\[ignore/) {
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
    done <"$spawn_list"
    rm -f "$spawn_list"

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

    # R311y455 — the SKIP-TOKEN NAMING OBLIGATION, now enforced.
    #
    # Layer E's default sweep excludes whole families with libtest `--skip <token>`
    # (see the skip block in `layer_e_ap_demo_round_trip`). libtest matches a skip
    # against the TEST NAME, which for an integration test is the FUNCTION name --
    # NOT the file name. So a fixture named `wz_peer_*.rs` whose test fns do not
    # themselves contain `wz_peer` is NOT skipped, and Layer E runs it against
    # whatever demo binary that lane happens to have built.
    #
    # This lane exists because that already happened. R311y453 added
    # wz_peer_subject_scoping_pico_interop.rs with fns named
    # `a_link_protocol_scoped_rule_...` / `an_interface_scoped_rule_...`; Layer E ran
    # both against a demo built without `routing-peer`, the demo refused `--peer`,
    # and the hosted run for 2ab214a4 went RED. run-ci.sh had ALREADY written the
    # hazard down at the E4i lane -- "The token is a NAMING OBLIGATION that no gate
    # enforces" -- and a documented-but-ungated hazard is one that recurs. It is
    # gated now: a file whose basename carries a skip token must have EVERY test fn
    # carry it too.
    local naming_violations
    naming_violations="$(python3 - <<'PY'
import pathlib, re, sys

# The tokens must stay in step with the `--skip` list in
# layer_e_ap_demo_round_trip. Deliberately duplicated rather than scraped: this
# check has to fail LOUD if the two drift, and the drift itself is caught by the
# self-check below, which requires every token to appear in that skip block.
TOKENS = ["wz_e2e_", "multicast", "zenohd", "wz_router", "wz_peer",
          "wz_storage_host", "zenoh_ext", "inert", "capi_c"]

runci = pathlib.Path("scripts/run-ci.sh").read_text()
missing = [t for t in TOKENS if f"--skip {t}" not in runci]
if missing:
    print(f"SELFCHECK this check's token list has drifted from Layer E's "
          f"--skip block; not present there: {missing}")
    sys.exit(0)

TEST_ATTR = re.compile(r"#\[(?:tokio::)?test\b")
FN_NAME = re.compile(r"^\s*(?:async\s+)?fn\s+([A-Za-z0-9_]+)")

# SCOPE: Layer E runs `cargo test -p wz-integration-tests` and nothing else
# (see the invocation in layer_e_ap_demo_round_trip). A `--skip` cannot reach a
# fixture in another crate, so checking one would be a false gate -- and a false
# gate that fails the build is worse than no gate. Calibrated against this fact
# after a first draft flagged 29 sites of which 28 were not hazards.
TESTS = sorted(pathlib.Path("crates/wz-integration-tests/tests").glob("*.rs"))
if not TESTS:
    print("SELFCHECK no wz-integration-tests fixtures found; this check "
          "asserted nothing")
    sys.exit(0)

for path in TESTS:
    # A basename carrying a token declares the fixture part of an excluded
    # family. Only then is anything owed.
    if not any(t in path.stem for t in TOKENS):
        continue
    lines = path.read_text().splitlines()
    pending = False
    for line in lines:
        if TEST_ATTR.search(line):
            pending = True
            continue
        m = FN_NAME.match(line)
        if pending and m:
            fn = m.group(1)
            # ANY token suffices: one match is enough for libtest to exclude the
            # test, and it need not be the same token the filename carries --
            # `wz_gossip_autoconnect_zenohd_interop`'s fns are excluded by their
            # `wz_peer` prefix, not by `zenohd`.
            if not any(t in fn for t in TOKENS):
                print(f"{path}::{fn} carries NO Layer E skip token while its "
                      f"filename declares the family; the token set is {TOKENS}")
            pending = False
PY
)" || {
        echo "Layer C0 FAIL: the skip-token naming check errored" >&2
        return 1
    }
    if [[ -n "$naming_violations" ]]; then
        echo "Layer C0 FAIL: skip-token NAMING OBLIGATION violated" >&2
        echo "" >&2
        echo "$naming_violations" >&2
        echo "" >&2
        echo "libtest --skip matches the FUNCTION name, not the file name. A" >&2
        echo "fixture whose basename carries a family token but whose test fns" >&2
        echo "do not is run by Layer E's default sweep against an" >&2
        echo "arbitrary-feature binary -- exactly how the hosted run for" >&2
        echo "2ab214a4 went red." >&2
        echo "" >&2
        echo "Fix: rename the test fn so it contains the token (e.g." >&2
        echo "  fn wz_peer_<what_it_asserts>()), which is how the zenohd and" >&2
        echo "  inert families already stay covered." >&2
        return 1
    fi
    # R311y606 — the PYTHON-FLOOR lint, FIRST because every check below it is
    # a python script and their answers are only as portable as the interpreter
    # that runs them. R311y605 landed `import tomllib` (stdlib from 3.11) in
    # the census two lines down; the hosted lanes run ubuntu-22.04 / python
    # 3.10, so C0 died in `import` on the first hosted run and hid the 29 steps
    # behind it, while staying green on the 3.12 workstation that verified the
    # round. Two arms: `ast.parse(feature_version=)` for grammar (no table --
    # CPython's parser knows when each construct arrived) and a short
    # self-checking table for stdlib modules newer than the floor. The floor is
    # DERIVED from `runs-on:` rather than written down, so bumping the image
    # moves it. Enforcement MEASURED on four arms: the y605 import verbatim, a
    # PEP 695 alias, an unrecorded runner image, and a misspelt table entry.
    python3 scripts/lib/python_floor_lint.py || return 1
    # R311y606 — the DISCARDED-EVIDENCE lint. Layer E failed twice in six
    # sweeps with nothing to read but `exited ExitStatus(65280)`: the harness
    # captured each foreign child's stdout, printed it in the panic, and sent
    # stderr to /dev/null — and a C program under test (zenoh-pico, openssl)
    # says WHY it refused on stderr. 53 chains had that asymmetry. The gate is
    # over the ASYMMETRY, not over `Stdio::null()`: a leg that captures neither
    # stream has made a choice, one that captures a stream and bins the other
    # has a reader and is feeding it half the story. Enforcement MEASURED by
    # re-binning one of the 53 — and the gate's FIRST run found a 54th that the
    # hand sweep had missed, because its two calls were not adjacent lines.
    python3 scripts/lib/discarded_evidence_lint.py || return 1
    # R311y608 — the DUPLICATE-MODULE lint. R311y607 declared `pub mod
    # scouting;` in a crate root that already declared `pub mod scouting { .. }`
    # (the SCE-generated FSM), behind a DISJOINT feature, so rustc raises E0428
    # only for a build that enables both -- and every build that round ran
    # enabled one. Three hosted jobs then failed at once on one cause (C1's
    # workspace feature unification, M's multicast lane, C1bf's --all-features).
    # A build-based gate would have to guess which combination unions the two
    # cfgs; the invariant does not depend on features, so it is checked by
    # reading the declarations. Enforcement MEASURED by restoring the collision.
    python3 scripts/lib/duplicate_module_lint.py || return 1
    # R311y616 (§7.13) — the LITERAL-WIRE-FLAG lint, scoped to wz-capture.
    # R311y615 named `wire_const::FLAG_N_N` for the network `N` bit and shipped
    # it with ONE consumer while four fixtures beside it kept writing `0x20`;
    # a constant with no gate is a naming exercise, and the value being
    # identical means no test can ever tell the two apart. The scan reports the
    # count OUTSIDE its scope on every run so the gate cannot be mistaken for a
    # workspace-wide claim (that sweep is §3.3, its own round). Enforcement
    # MEASURED by restoring one literal, not by observing that the script runs.
    python3 scripts/lib/literal_wire_flag_lint.py || return 1
    # R311y621 (§7.14) — the SOLO-PLANE-PAGE gate. R311y618 severed one leg of
    # `CaptureReport::is_complete` and all 229 tests stayed green: the pages
    # that should have caught it attached TWO planes, and the other plane
    # already produced the verdict, so neither leg gated anything. The remedy —
    # one plane on the page — has since been applied by hand six times across
    # y618 / y620 / y621 with nothing requiring it, so a fourth plane could ship
    # with only a multi-plane page behind it and every test would pass. The
    # plane set is READ from `CaptureReport`'s own `with_*` builders rather than
    # listed here, because a hand-kept list would be updated by the same person
    # who forgot the page. Enforcement MEASURED three ways: a new plane with no
    # page, a solo page that gains a second plane, and a builder set the scan
    # cannot read — each reds, and the revert returns OK.
    python3 scripts/lib/solo_plane_page_lint.py || return 1
    # R311y639 (§4.30) — the PAYLOAD-MEASUREMENT gate. Two rounds in a row a
    # carrier arm of `agg::classify` wrote a byte total with a bare assignment
    # and so had no way to say "unknown": R311y637's query carries its value in
    # an ext and was reported as zero bytes, R311y639's SHM descriptor stands in
    # for data that never crossed the wire and was reported as its own slot
    # length. Both fixes route the write through `KeyexprCounts::record_payload`,
    # whose parameter is an `Option`. Nothing required the door, so a THIRD
    # carrier could be added with a bare assignment and every test would pass —
    # a test cannot observe a question that was never asked. The guarded field
    # set is READ from what the door writes, not listed here. Enforcement
    # MEASURED both ways in: restoring the y639 assignment reds, and a
    # `KeyexprCounts` struct literal naming a guarded field reds.
    python3 scripts/lib/payload_measurement_lint.py || return 1
    # R311y565 — the EXPIRED-BLOCKER lint. Eight times across y561-y563 a field
    # or a family sat unimplemented behind a comment naming its own reason, and
    # the reason had already dissolved -- twice in the round that wrote it. Each
    # named its own blocker in prose and each blocker was one grep from being
    # falsified, which is what makes the class mechanical rather than editorial.
    # Enforcement MEASURED by re-introducing one of the eight verbatim, not by
    # observing that the script runs.
    python3 scripts/lib/expired_blocker_lint.py || return 1
    # R311y581 — the UNWIRED-LANE gate: a lane in run-ci.sh but not in
    # ci.yml's --layer set runs ONLY in a local full sweep. Seven were found,
    # one of them created by the round that closed the sibling debt. See the
    # script's docstring for why this is a gate and not a fourth comment.
    python3 scripts/lib/unwired_lane_lint.py || return 1
    # R311y595 — the DISSECT NAME CENSUS. `Field::name`'s doc declares that a
    # field is named after the generated codec's struct field, and nothing
    # compared the two: the prose was the specification and the walkers were
    # the implementation. A census rather than a golden JSON test on purpose --
    # a golden test reds on every legitimate walker addition and decays into a
    # reflex update, which is exactly how an accidental rename would slip past
    # (one already happened: `locator` -> `locator_entry`, R311y585). This
    # DEMANDS the name instead, and carries the linkstate gap by name.
    python3 scripts/lib/dissect_name_census.py || return 1
    # R311y605 — the DISSECT FEATURE CENSUS, the name census's sibling one level
    # up. `dissect`'s doc says it selects the whole codec-* MID space so "an
    # observer reads every message it sees", and the claim had been wrong THREE
    # times (scout/hello R311y585, linkstate R311y597, join/fragment/keep-alive
    # R311y605) — each found by accident, while someone was writing a walker.
    #
    # The existing MID gate cannot see any of them: it walks the 32 NETWORK
    # MIDs, and the three gaps live on the scouting space, inside an OAM body,
    # and on the TRANSPORT space respectively. The FEATURE space is the one
    # place every carrier appears exactly once, so that is where the gate goes.
    # Enforcement MEASURED by removing `codec-join` from the feature list.
    python3 scripts/lib/dissect_feature_census.py || return 1
    # R311y569 — the COUNT-GUARD-to-binary gate. `run-ci.sh` carries 53 bare
    # `| grep -qE '^test result: ok\. N passed'` guards, and NOTHING tied N to
    # the binary it guards: rename a test, delete one, or add one, and the guard
    # is simply wrong until some lane happens to run. The debt ledger ranked it
    # #5 on the frontier and noted the check is DERIVABLE, which is the whole
    # reason it belongs in a static lane — both sides are readable without
    # building anything, so this costs milliseconds rather than a test run.
    #
    # It reports what it CANNOT analyse (a substring filter, a feature-dependent
    # test set) rather than passing over it, and FAILS when its in-scope set is
    # empty — a version that quietly analysed nothing would exit 0 forever and
    # read as coverage. Enforcement MEASURED by renaming a guarded test fn.
    python3 scripts/lib/count_guard_lint.py || return 1
    # R311y570 — the UNSEQUENCED-PROBE lint. A C probe that passes `&x` to a
    # constructor and reads `x` through a loan accessor in the SAME full
    # expression is reading an uninitialised object: C does not order call
    # arguments and gcc evaluates them right to left. R311y568 shipped two such
    # lines and the twice-and-diff gate could not see them, because both arms
    # printed stack junk and an equality between two wrong answers is GREEN.
    # Only the hosted runner's different junk exposed it, a round later.
    #
    # Static for the same reason the count-guard gate is: both halves are in the
    # source. Enforcement MEASURED by re-introducing the y568 line verbatim.
    python3 scripts/lib/unsequenced_probe_lint.py || return 1
    return 0
}

# ─── Layer C1 — cargo test --workspace ──────────────────────────────
layer_c1_cargo_test() {
    # Stage 4b — exclude wz-session-lwip: it forces wz-session-core/no_std
    # (heapless sce-rust-runtime) through non-optional deps, which is
    # mutually exclusive with the std sce-rust-runtime (http-send) that
    # wz-runtime-tokio pulls — the two cannot coexist in one feature-
    # unified graph. The crate is tested ISOLATED in Layer C1m via `-p`.
    # Stage 5 — wz-mcu-session-acceptor (the MCU acceptor e2e SSOT) depends
    # on wz-session-lwip + the facade session-lwip funnel, so it inherits the
    # same no_std-forcing hazard; excluded here and tested ISOLATED in C1n.
    # R311mi — wz-mcu-multicast-e2e (the MCU multicast e2e SSOT) depends on the
    # same facade session-lwip funnel, so it carries the same hazard; excluded
    # here and tested ISOLATED in C1r.
    # R311mo — wz-runtime-tokio-multicast-tests reaches the multicast-only
    # Session API (gated `not(transport-unicast)`), which the workspace's
    # transport-unicast feature unification would gate out; excluded here and
    # tested ISOLATED in C1s.
    (cd crates && cargo test --workspace \
        --exclude wz-session-lwip \
        --exclude wz-mcu-session-acceptor \
        --exclude wz-mcu-multicast-e2e \
        --exclude wz-runtime-tokio-multicast-tests --quiet)
}

# ─── Layer C1b — cargo test -p wz-runtime-core --features alloc ────
#
# wz-runtime-core's default features = [] (the crate must compile clean
# for MCU bare-metal where no heap exists). The 7 R266/R267
# panic_payload + Error-trait tests live behind `cfg(feature = "alloc")`
# because they construct `Box<dyn Any + Send>` payloads.
#
# R311y415 — this block used to justify the lane with "Layer C1's
# `cargo test --workspace` runs each member crate with that member's OWN
# default features, so wz-runtime-core's test binary compiles with zero
# features and the alloc-gated mod is `cfg(false)` — i.e. the tests
# silently do not run". MEASURED FALSE, twice over. The general claim is
# false (feature pins unify onto the shared build under `--workspace` —
# see crates/wz-integration-tests/Cargo.toml for the frag/multicast
# case), and it is false for THIS crate specifically:
# wz-runtime-tokio/Cargo.toml:1463 pins `wz-runtime-core` with
# `features = ["alloc"]` as a NORMAL dependency, so C1 builds it alloc-on
# and all 7 `error::alloc_error_tests::*` DO run there. Measured: `-p
# wz-runtime-core` 0 tests, `-p wz-runtime-core --features alloc` 7, C1
# 7 (all 7 names alloc-gated).
#
# The lane still earns its place, for a DIFFERENT reason: it pins the
# alloc build to an explicit, ISOLATED invocation instead of depending
# on wz-runtime-tokio continuing to pin alloc. Drop that pin and C1's
# coverage of these 7 silently goes to 0 while C1 stays green; this lane
# goes red. That is the failure this lane actually guards, and why the
# alloc-mode behaviour stays gated in CI regardless of C1's pin graph.
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

# ─── Layer C1t — SERIAL link: wz-session-core logic + wz-runtime-tokio tty ─
#
# R311nt: same shape as C1c. The `serial_link` module (SERIAL upper
# protocol: framing + handshake + locator logic) and its byte-parity
# test module gate on `transport-link-serial`, which is OFF in
# wz-session-core's default features. Layer C1's `cargo test --workspace`
# does NOT reach it (no default-features crate enables it transitively),
# so this lane runs the serial_link tests explicitly. The second
# invocation drops the default keyexpr matcher features to prove the
# serial logic composes standalone (the feature pulls only alloc +
# codec-serial, no keyexpr dependency).
#
# R311nv: the lane now ALSO covers the host tty BACKEND
# (`wz-runtime-tokio::serial_pipeline`, the 2nd layer of the SERIAL split):
# the `serial_pipeline` lib unit tests (PTY-pair handshake + data-frame
# round-trip), the `serial_pty_e2e` integration test (wz<->wz over an
# openpty serial pair: link handshake -> zenoh transport Established ->
# Push byte-exact), and a clippy gate on the `transport-link-serial` cfg
# (NOT in default features, so the global clippy lane does not reach it).
# Both serial test files gate `#![cfg(feature = "transport-link-serial")]`,
# so Layer C1's `cargo test --workspace` skips them — this lane is where
# the runtime serial backend is exercised.
#
# R311nw: the lane gains a SECOND `serial_pty_e2e` invocation adding
# `transport-fragmentation`, which unlocks the `#[cfg(transport-fragmentation)]`
# oversize-Put test (a > SERIAL_MTU payload fragments at the transport
# layer to chunks the serial frame can carry, then reassembles byte-exact).
# The frag-OFF invocation stays — it proves the serial backend composes in
# a minimal build with no reassembly subsystem. A matching frag-ON clippy
# gate lints the otherwise cfg'd-out fragmentation test.
#
# R311y413 — HOSTED on ci.yml's feature-gates job (completes the link-kind
# e2e family: all 10 transport-link-* kinds now gate hosted). The three
# targeted runtime steps (serial_pipeline lib; serial_pty_e2e frag-off /
# frag-on) gained anchored exact-count guards (3 / 1 / 2 passed). The two
# leading `cargo test -p wz-session-core --features transport-link-serial`
# whole-crate runs stay bare (cargo-exit-gated): an exact `N passed` guard
# is impractical for a whole-crate run whose count churns with unrelated
# session-core tests; a serial regression still reddens via cargo's exit.
# openpty PTY pairs are standard on Linux runners -> pure cargo, hostable.
layer_c1t_cargo_test_serial() {
    (cd crates \
        && cargo test -p wz-session-core --features transport-link-serial --quiet \
        && cargo test -p wz-session-core --no-default-features --features transport-link-serial --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-serial --lib serial_pipeline --quiet 2>&1 | grep -qE '^test result: ok\. 3 passed' \
        && cargo test -p wz-runtime-tokio --features transport-link-serial --test serial_pty_e2e --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo test -p wz-runtime-tokio --features transport-link-serial,transport-fragmentation --test serial_pty_e2e --quiet 2>&1 | grep -qE '^test result: ok\. 2 passed' \
        && cargo test -p wz-runtime-tokio --features transport-link-serial --test link_endpoints_pairing --quiet 2>&1 | grep -qE '^test result: ok\. 2 passed' \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-link-serial --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-link-serial,transport-fragmentation --quiet -- -D warnings)
}

# ─── Layer C1u — TLS link: locator parse + wz-runtime-tokio tls backend ─
#
# R311oa: same shape as C1t (serial). The TLS backend (`tls_pipeline`:
# dial_tls/accept_tls rustls handshake + the TlsReadDriver, reusing the TCP
# StreamEnvelope framing) gates on `transport-link-tls`, OFF in the default
# set, so Layer C1's `cargo test --workspace` never reaches it. This lane:
#   1. runs the locator tests (the `Proto::Tls` parse is ungated parse-always
#      in wz-session-core, but pin it here so a parse regression is caught
#      even if the default workspace run's feature set shifts);
#   2. runs the `tls_e2e` integration test (gated
#      `all(transport-link-tls, transport-unicast)`: two nodes complete the
#      rustls handshake over a loopback TCP link, reach Established, and a Put
#      is delivered byte-exact through the TLS-wrapped stream);
#   3. clippy-gates the `transport-link-tls` cfg (`--all-targets`, defaults
#      retained so the e2e + lib both lint);
#   4. clippy-gates the LIB under `--no-default-features --features
#      transport-link-tls` to prove `tls_pipeline` composes standalone (it
#      needs only the forwarded `transport-link-tcp`, not `transport-unicast`).
#
# R311y413 — HOSTED on ci.yml's feature-gates job. The combined
# `--test tls_e2e --test session_reconnect_e2e --test tls_pem_mtls_e2e` run
# was SPLIT into three per-binary steps, each with its anchored exact-count
# guard (2 / 5 / 6 passed), so a 0-tests drift in ANY one binary reddens
# (the combined form could not — one binary going quiet was invisible).
# tls loopback uses in-process self-signed certs -> pure cargo, hostable.
layer_c1u_cargo_test_tls() {
    # R311oe — also run session_reconnect_e2e here: its `tls_reconnect` module
    # (gated all(transport-link-tls, transport-unicast)) proves a TLS session's
    # reconnect re-dials with the RETAINED DialConfig. defaults+tls already
    # carry session-reconnect + transport-unicast, so the module compiles and
    # runs; without this invocation it is empty and the retained-config re-dial
    # is unexercised (gate-skew). The clippy --all-targets line below already
    # lints the module under tls.
    #
    # R311og/oh — also run tls_pem_mtls_e2e: mutual-TLS + cert-PEM-loading e2e
    # (gated all(transport-link-tls, transport-unicast)). It drives the
    # production `tls_config` PEM loaders to build mTLS configs and asserts
    # mutual auth reaches Established, an mTLS server rejects an anonymous
    # client, and a one-way config built from PEM reaches Established; R311oh
    # adds the file-path (`read_pem_file`) and base64 (`decode_base64_pem`) cert
    # sources. R311oj adds the verify-name knob (`ServerNameVerification`): a
    # SAN-mismatched dial is rejected under `Verify`, accepted under `AnyName`.
    # All in the same tls_pem_mtls_e2e binary, so the `--test` wiring below
    # already covers it (no gate-skew). Same gate-skew reasoning: without this
    # invocation the module is empty and the cert-PEM/mTLS path is unexercised.
    #
    # R311y537 — the three count guards moved from bare `grep -q` to
    # `_runci_guarded_test`, and the `session_reconnect_e2e` count moved 5 -> 6.
    #
    # The COUNT was stale: `a_dying_link_delivers_remote_liveliness_deletes_to_
    # the_dialer` landed in that file and this guard was never updated, so the
    # lane has been red ever since — and nobody saw it, because Layer C1j in the
    # SAME hosted job failed FIRST and hid it. It surfaced only once R311y536
    # fixed C1j. Third unmasking of that round: a lane list read off a red run is
    # a LOWER BOUND on the red set, never the set.
    #
    # The SILENCE was the worse half. `| grep -qE '<pattern>'` discards the
    # child's output AND the reason: this lane failed in 3 s having printed one
    # unrelated `test result` line and then `Layer C1u FAIL`, stating neither
    # what it expected nor what it got, so diagnosing it meant running the three
    # commands by hand. `_runci_guarded_test` tees the output and names the
    # expectation on mismatch, which is what makes a count guard tolerable at
    # all — it is a citation, and a citation has to say when it is wrong.
    _runci_guarded_test C1u + cargo test -p wz-session-core --features alloc --lib locator --quiet \
        || return 1
    _runci_guarded_test C1u 3 cargo test -p wz-runtime-tokio --features transport-link-tls --test tls_e2e --quiet \
        || return 1
    _runci_guarded_test C1u 6 cargo test -p wz-runtime-tokio --features transport-link-tls --test session_reconnect_e2e --quiet \
        || return 1
    _runci_guarded_test C1u 6 cargo test -p wz-runtime-tokio --features transport-link-tls --test tls_pem_mtls_e2e --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-link-tls --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features transport-link-tls --quiet -- -D warnings)
}

# ─── Layer C1v — WS link: locator parse + wz-runtime-tokio ws backend ─
#
# R311ob: same shape as C1u (tls). The WS backend (`ws_pipeline`: dial_ws/
# accept_ws RFC6455 handshake + the datagram WsReadDriver over a tungstenite
# WebSocketStream) gates on `transport-link-ws`, OFF in the default set, so
# Layer C1's `cargo test --workspace` never reaches it. This lane:
#   1. runs the locator tests (the `Proto::Ws` parse is ungated parse-always);
#   2. runs the `ws_e2e` integration test (gated
#      `all(transport-link-ws, transport-unicast)`: two nodes complete the WS
#      handshake over loopback — the initiator via a `ws/...` LOCATOR, since WS
#      dials from dial_locator unlike tls — reach Established, and a Put is
#      delivered byte-exact through WS BINARY messages);
#   3. R311oj — also runs session_reconnect_e2e: its `ws_reconnect` module
#      (gated all(transport-link-ws, transport-unicast)) proves a WS session's
#      reconnect re-dials the `ws/...` locator and re-runs the RFC6455 upgrade.
#      Same gate-skew reasoning as C1u's tls_reconnect: defaults+ws carry
#      session-reconnect + transport-unicast, so the module compiles and runs;
#      without this invocation it is empty and the WS reconnect path is
#      unexercised. The clippy --all-targets line below already lints it.
#   4. clippy-gates the `transport-link-ws` cfg (`--all-targets`);
#   5. clippy-gates the LIB under `--no-default-features --features
#      transport-link-ws` to prove `ws_pipeline` composes standalone (it needs
#      no `transport-link-tcp` — WS is datagram-flow, not StreamEnvelope).
#
# R311y413 — HOSTED on ci.yml's feature-gates job. The combined
# `--test ws_e2e --test session_reconnect_e2e` run was SPLIT into two
# per-binary steps, each with its anchored exact-count guard (1 / 5 passed).
# ws loopback is pure cargo, hostable.
layer_c1v_cargo_test_ws() {
    # R311y537 — the SECOND instance of C1u's stale count, found by auditing
    # every bare guard in this file against reality rather than by waiting for
    # this lane to surface. Same test binary, same missed update, same 5 -> 6:
    # one commit added a test to `session_reconnect_e2e` and two lanes counted
    # it. The audit that found it ran each guarded command and compared the
    # number libtest printed to the number the guard demands, and it cleared the
    # other 53 bare guards in this file as CURRENT — so the class here is two
    # instances of one missed update, not a general rot.
    #
    # Converted to `_runci_guarded_test` for the reason C1u states at length: a
    # bare `grep -q` fails without saying what it wanted, which is why the first
    # instance survived behind another lane's failure instead of being read off
    # its own message.
    _runci_guarded_test C1v + cargo test -p wz-session-core --features alloc --lib locator --quiet \
        || return 1
    _runci_guarded_test C1v 3 cargo test -p wz-runtime-tokio --features transport-link-ws --test ws_e2e --quiet \
        || return 1
    _runci_guarded_test C1v 6 cargo test -p wz-runtime-tokio --features transport-link-ws --test session_reconnect_e2e --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-link-ws --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features transport-link-ws --quiet -- -D warnings)
}

# ─── Layer C1aa — UNIXSOCK link: locator parse + wz-runtime-tokio backend ─
#
# R311xi: same shape as C1u (tls) / C1v (ws). The unixsock backend
# (`unixsock_pipeline`: dial_unixsock/bind_unixsock/accept_unixsock_on + the
# UnixsockReadDriver reusing the TCP StreamEnvelope framing) gates on
# `transport-link-unixsock`, OFF in the default set, so Layer C1's
# `cargo test --workspace` never reaches it. (The single-letter C1[u-z] suffix
# run is exhausted; this is the next transport-link lane, grouped with C1u/C1v
# in the run loop.) This lane:
#   1. runs the locator tests (the `unixsock-stream` parse is ungated
#      parse-always, like serial — the `AnyLocator::Unixsock` leaf);
#   2. runs the `unixsock_pipeline` unit tests (dial-error, bind/accept
#      round-trip, stale-socket-file replace);
#   3. runs the `unixsock_e2e` integration test (gated
#      `all(transport-link-unixsock, transport-unicast)`: two nodes bring a
#      session up over a loopback unix socket — the initiator via a
#      `unixsock-stream/...` LOCATOR, dialed straight through dial_locator like
#      ws/udp — reach Established, and a Put is delivered byte-exact over the
#      StreamEnvelope-framed unix stream);
#   4. clippy-gates the `transport-link-unixsock` cfg (`--all-targets`);
#   5. clippy-gates the LIB under `--no-default-features --features
#      transport-link-unixsock` to prove `unixsock_pipeline` composes standalone
#      (it pulls only `transport-link-tcp`'s shared `stream_link`, no
#      `transport-unicast` session-open integration). NO reconnect e2e: a unix
#      socket is `NotReconnectable` (non-IP, outside the reconnect set), so —
#      unlike C1u/C1v — there is no reconnect module to exercise.
#
# R311y413 — HOSTED on ci.yml's feature-gates job (link-kind e2e family
# closure). The unixsock_pipeline + unixsock_e2e steps gained anchored
# `^test result: ok\. 3 passed` / `2 passed` count-guards (were bare). A unix
# socket loopback needs no kernel module -> pure cargo, hostable.
layer_c1aa_cargo_test_unixsock() {
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-unixsock --lib unixsock_pipeline --quiet 2>&1 | grep -qE '^test result: ok\. 3 passed' \
        && cargo test -p wz-runtime-tokio --features transport-link-unixsock --test unixsock_e2e --quiet 2>&1 | grep -qE '^test result: ok\. 2 passed' \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-link-unixsock --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features transport-link-unixsock --quiet -- -D warnings)
}

# ─── Layer C1ab — VSOCK link: locator parse + wz-runtime-tokio backend ─
#
# R311xj: same shape as C1aa (unixsock). The vsock backend (`vsock_pipeline`:
# dial_vsock/bind_vsock/accept_vsock_on + the VsockReadDriver reusing the TCP
# StreamEnvelope framing, split via tokio::io::split) gates on BOTH
# `transport-link-vsock` AND `target_os = "linux"` (AF_VSOCK is Linux-only, via
# the optional `tokio-vsock` dep), OFF in the default set. This lane:
#   1. runs the locator tests (the `vsock/<CID>:<PORT>` parse is ungated +
#      platform-independent — the CID/port grammar, the genuinely-new logic);
#   2. runs `--lib vsock_pipeline` + `--test vsock_e2e`: these COMPILE the
#      backend + the wz<->wz e2e and report them IGNORED. The live tests are
#      `#[ignore]` because AF_VSOCK loopback (`VMADDR_CID_LOCAL`) needs the
#      `vsock_loopback` kernel module, ABSENT in this sandbox (bind = EPERM, no
#      /dev/vsock). They run on a vsock-capable host via
#      `cargo test --features transport-link-vsock -- --ignored` (the Layer Z
#      environment-gated pattern); the data path they would exercise is already
#      proven by the TCP/TLS/unixsock lanes. The lane does NOT pass `--ignored`
#      (it would EPERM-fail here) — it proves compile + correct-ignore;
#   3. clippy-gates the `transport-link-vsock` cfg (`--all-targets`, compiling
#      the #[ignore] targets);
#   4. clippy-gates the LIB under `--no-default-features --features
#      transport-link-vsock` to prove `vsock_pipeline` composes standalone (it
#      pulls only `transport-link-tcp`'s shared `stream_link` + tokio-vsock, no
#      `transport-unicast` session-open integration). NO reconnect e2e: vsock is
#      `NotReconnectable` (non-IP), like unixsock.
#
# R311y413 — HOSTED on ci.yml's feature-gates job. NO count-guard, deliberately:
# every vsock test is `#[ignore]` (AF_VSOCK loopback needs the `vsock_loopback`
# kernel module, absent on the runner), so this lane is a COMPILE + clippy gate —
# the only lane building the vsock backend off-default. It stays robust without a
# `N passed` guard: a cfg-out reddens at COMPILE, and a dropped `#[ignore]` runs
# the test and EPERM-reddens on the module-less runner. The live data path is
# proven by the TCP/TLS/unixsock lanes.
layer_c1ab_cargo_test_vsock() {
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-vsock --lib vsock_pipeline --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-vsock --test vsock_e2e --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-link-vsock --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features transport-link-vsock --quiet -- -D warnings)
}

# ─── Layer C1ac — QUIC link: locator parse + wz-runtime-tokio backend ─
#
# R311xk: same shape as C1aa (unixsock) / C1ab (vsock), but the e2e RUNS (no
# #[ignore]) — QUIC loopback needs no special kernel support (ordinary UDP on
# 127.0.0.1 + an in-process self-signed cert), so this is the fully-verified
# link round. The QUIC backend (`quic_pipeline`: dial_quic/bind_quic/
# accept_quic_on + the VsockReadDriver... no: the QuicReadDriver reusing the TCP
# StreamEnvelope framing over a quinn SendStream/RecvStream pair) gates on
# `transport-link-quic`, OFF in the default set. This lane:
#   1. runs the locator tests (the `quic/<host>:<port>` parse is `Proto::Quic`,
#      the IP-family numeric grammar — ungated parse, like tls/ws);
#   2. runs the `quic_e2e` integration test (gated `all(transport-link-quic,
#      transport-unicast)`): two nodes complete the QUIC + TLS-1.3 handshake
#      over loopback — the initiator via a `quic/...` LOCATOR + DialConfig.quic
#      (the cert-threaded seam) — reach Established, and a Put is delivered
#      byte-exact over the StreamEnvelope-framed QUIC bidi stream;
#   3. clippy-gates the `transport-link-quic` cfg (`--all-targets`);
#   4. clippy-gates the LIB under `--no-default-features --features
#      transport-link-quic` to prove `quic_pipeline` + `quic_config` compose
#      standalone (they pull only `transport-link-tcp`'s shared `stream_link` +
#      quinn + the tls rustls cert stack, no `transport-unicast` session-open
#      integration). NO reconnect e2e yet (a QUIC reconnect would re-dial the
#      `quic/...` locator like tls/ws — a clean follow-up; deferred here).
#
# R311y413 — the `quic_e2e` step gained the anchored `^test result: ok\. 1 passed`
# count-guard (was a bare `cargo test`, so a future 0-tests cfg-out would have
# passed silently — the y412 hardening convention applied to a lane about to run
# hosted), and this whole lane is now HOSTED on ci.yml's feature-gates job (see
# that step's comment for the never-hosted-gate rationale).
layer_c1ac_cargo_test_quic() {
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-quic --test quic_e2e --quiet 2>&1 | grep -qE '^test result: ok\. 2 passed' \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-link-quic --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features transport-link-quic --quiet -- -D warnings)
}

# ─── Layer C1ad — lowlatency transport: ext codec + lean tx/rx + e2e ─
#
# R311xl: transport-lowlatency is a transport MODE (not a link kind), the wz
# mirror of zenoh's runtime-negotiated lowlatency unicast transport
# (init.rs:162 zextunit!(0x5,false)) — the functional alternative to
# transport-fragmentation. Both peers OFFER the Z_EXT_LOWLATENCY unit ext on
# Init; the `&=` merge agrees; the established session drops the Frame(sn)
# wrapper + fragmentation, serializing the bare NetworkMessage directly. NO new
# dependency. This lane:
#   1. runs the extlowlatency ext-codec unit tests (the 0x5 unit ext + the
#      peer-offer projector);
#   2. runs the lowlatency_e2e integration tests (gated all(transport-lowlatency,
#      transport-unicast, transport-link-tcp)): wz<->wz negotiate over real TCP
#      loopback + deliver a Put byte-exact over the lean wire, AND a deterministic
#      wire-form proof that the lowlatency Put rides a bare N_MID_PUSH (no Frame)
#      while the no-offer control rides a T_MID_FRAME, plus the one-sided-offer
#      `&=` leaving both sides universal;
#   3. clippy-gates the cfg under --all-targets (the lean tx/rx branches +
#      the negotiation wiring);
#   4. clippy-gates the LIB under --no-default-features --features
#      transport-lowlatency to prove the rx-capable lowlatency primitive (the
#      ext codec + lean rx + per-session state) composes standalone WITHOUT the
#      handshake codecs (the Init offer/merge is additively gated on
#      codec-init-body, so a bare build carries no dead send_wire seam).
#   5. R311y433 — clippy-gates wz-ap-demo under --features transport-lowlatency,
#      the demo's `--lowlatency` cfg site, for the reason spelled out on C1ae step 5
#      (C2 is default-features and compiles the arm out). Added in the compression
#      round because R311y433 moved BOTH modes' open arms into one
#      `open_initiator_with_offer` seam, and gating one mode's arm while leaving its
#      sibling's ungated would be an asymmetry with no rationale behind it.
#
# R311y414 — the two test steps were BARE, so an `extlowlatency` rename or a
# cfg-out of the e2e cases would have gone green by silence. Both now carry
# anchored count guards with the MEASURED counts (4 unit / 2 e2e).
layer_c1ad_cargo_test_lowlatency() {
    _runci_guarded_test C1ad 4 cargo test -p wz-session-core --features transport-lowlatency --lib extlowlatency --quiet \
        || return 1
    _runci_guarded_test C1ad 2 cargo test -p wz-runtime-tokio --features transport-lowlatency,transport-unicast,transport-link-tcp --test lowlatency_e2e --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-lowlatency,transport-unicast,transport-link-tcp --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features transport-lowlatency --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features transport-lowlatency --quiet -- -D warnings)
}

# ─── Layer C1bb — transport-qos: ext_qos wire + per-priority SN conduits ─
#
# R311y215: transport-qos builds zenoh's per-(priority,reliability) QoS
# transport as a COMPILE-TIME cargo feature — the `[AtomicTxSn; 8]` (TX) and
# `[RxSn; 8]` (RX) conduit arrays must be statically sized so the MCU no-alloc
# profile never sizes a heap array by a runtime flag; `is_qos` is the RUNTIME
# per-session negotiation WITHIN a transport-qos build (unit ext_qos on Init,
# lowlatency-exclusive). The Frame/Fragment `ext_qos` extension (id 0x1, z64,
# header 0x31) carries a non-DEFAULT priority; a DEFAULT frame stays
# byte-identical to the pre-QoS wire. This lane:
#   1. runs the qos unit suite in wz-session-core — extqos (the 0x1
#      establishment ext), the Frame/Fragment ext_qos wire round-trip
#      (frame_encode::qos_wire_tests), the per-priority RxConduits
#      gate-independence (sn::tests), and the priority-keyed reassembly chains
#      (reassembly_dispatch::tests);
#   2. clippy-gates the ON path under --all-targets across the composition
#      surface (qos + fragmentation + batching + reassembly + multicast);
#   3. clippy-gates the OFF path (fragmentation WITHOUT qos — the ext_qos=None /
#      single-conduit arms must compose with NO dead code under -D warnings);
#   4. compile-checks the pairwise composition of qos with each adjacent
#      transport mode (multilink / lowlatency / batching) — qos and lowlatency
#      are RUNTIME-exclusive (the symmetric set_qos_offer / set_lowlatency_offer
#      guards) but MUST compile together — plus the minimal --no-default-features
#      qos build (arrays cross a lean profile); R311y216 RUNS the exclusivity unit
#      test (is_qos_negotiates_by_and_and_is_lowlatency_exclusive) under BOTH
#      features so the reciprocal-guard symmetry has executed CI coverage, not just
#      a cargo-check compile;
#   5. R311y216(a): runs qos_e2e over the default feature set (transport-qos +
#      transport-unicast + transport-link-tcp, NO --no-default-features so the
#      default codec-init-body / codec-push / session-unicast-open|accept the
#      round-trip needs are present — mirroring the lowlatency_e2e lane), proving
#      the `*_with_qos` entrypoints flip `is_qos` on a real handshake and a
#      prioritized Put rides / clamps ext_qos by negotiation;
#   6. R311y217: RUNS the multilink priority-select segregation tests (two joined
#      recording-driver links, SAME reliability + DISTINCT priority bands) proving
#      `select_link(reliability, priority)` pins each conduit to one link on the
#      immediate AND batch-reopen-flush paths (the flushed frame routes by its OWN
#      conduit, not the trigger) + the narrowest-band tie-break;
#   7. proves the wz facade + wz-runtime-tokio feature forwards resolve.
#
# R311y414 — every test step in this lane was BARE. The three NAMED runs (the
# qos_e2e binary, the exclusivity unit, the multilink:: filter) now carry EXACT
# guards; the two whole-module runs (the session-core `--lib` sweep and the
# `linkstate` filter, 301 / 202 cases today) carry `>=1` guards instead, since
# an exact number there would red on every added test without catching anything
# an exact-count-of-1 case does not already catch.
layer_c1bb_cargo_test_qos() {
    _runci_guarded_test C1bb + cargo test -p wz-session-core --features transport-qos,transport-fragmentation,transport-batching,reassembly,session-multicast --lib --quiet \
        || return 1
    # R311y414 review — the `+` above is necessary (301 cases, an exact number
    # would red on every unrelated session-core test) but NOT sufficient: it
    # cannot see this lane's own subject go dark. Measured, the same feature set
    # minus transport-qos drops the sweep to 276 and the `qos` filter from 21 to
    # 12, so the qos-gated session-core cases would vanish under a still-green
    # `+`. The exact count pins them; nothing else in this lane covers the
    # session-core side (its other exact guards are all wz-runtime-tokio).
    #
    # R311y630c — 21 -> 22. `ext_admit`'s
    # `the_frame_qos_extension_is_understood_but_only_at_its_own_encoding`
    # matches this filter by NAME, which is the pin doing its job on a test
    # that has nothing to do with the transport-qos feature: the filter is a
    # substring, so the count is a claim about the whole `qos`-named
    # population rather than about this lane's subject alone. That is the
    # accepted cost of an exact pin, and the remedy is to move it deliberately
    # rather than to loosen the filter.
    _runci_guarded_test C1bb 22 cargo test -p wz-session-core --features transport-qos,transport-fragmentation,transport-batching,reassembly,session-multicast --lib qos --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-session-core --all-targets --features transport-qos,transport-fragmentation,transport-batching,reassembly,session-multicast --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features transport-fragmentation --quiet -- -D warnings \
        && cargo check -p wz-session-core --no-default-features --features transport-qos --quiet \
        && cargo clippy -p wz-session-core --all-targets --features transport-qos,transport-multilink,codec-push --quiet -- -D warnings \
        && cargo check -p wz-session-core --features transport-qos,transport-lowlatency --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-qos --quiet -- -D warnings) \
        || return 1
    _runci_guarded_test C1bb 3 cargo test -p wz-runtime-tokio --features transport-qos,transport-unicast,transport-link-tcp --test qos_e2e --quiet \
        || return 1
    _runci_guarded_test C1bb 1 cargo test -p wz-runtime-tokio --features transport-qos,transport-lowlatency,transport-unicast --lib is_qos_negotiates_by_and_and_is_lowlatency_exclusive --quiet \
        || return 1
    # R311y514 — `session-extqos` JOINED this lane's feature set and the pin moved
    # 8 -> 11. The three tests it admits are the ones that pin the negotiated
    # metadata onto the link's egress-selection inputs (zenoh's
    # `link.reconfigure` at the end of establishment). Without the key they are
    # compiled out, and the lane reports 8 green while the seam it is named for
    # goes unexercised — the R311y513 shape, one feature key over.
    _runci_guarded_test C1bb 11 cargo test -p wz-runtime-tokio --features transport-qos,session-extqos,transport-multilink,transport-batching,codec-push,codec-close,transport-unicast --lib multilink:: --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-qos,session-extqos,transport-multilink,transport-batching,codec-push,codec-close,transport-unicast --quiet -- -D warnings) \
        || return 1
    # R311y514 — the `cfg(not(transport-multilink))` twin of the write-back seam.
    # A session with no aggregation set never runs `select_link`, so there is no
    # per-link selection input to reconfigure; the arm must still COMPILE, and
    # only a build that omits multilink while keeping `session-extqos` proves it.
    (cd crates \
        && cargo clippy -p wz-session-core --all-targets --no-default-features --features session-extqos,codec-init-body,codec-push,codec-close --quiet -- -D warnings) \
        || return 1
    _runci_guarded_test C1bb + cargo test -p wz-runtime-tokio --features routing-peer,transport-qos --lib linkstate --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-peer,transport-qos --quiet -- -D warnings \
        && cargo check -p wz --features transport-qos --quiet)
}

# ─── Layer C1bc — multicast per-priority QoS conduit ACTIVATION (R311y232) ─
#
# R311y232 flips the multicast per-priority QoS conduit from DEFAULT-inert
# (built at R311y227, every ctor hard-`false`) to config-sourced: the AP
# `spawn_router_mcast_egress` / `_ingress` gain a `qos` param -> `MulticastParams.is_qos`
# (the wz seam for zenoh `transport.multicast.qos.enabled`, default FALSE, a knob
# DISTINCT from unicast `transport.unicast.qos`), driven by the demo
# `--multicast-qos` flag; and the direct multicast-Session send seam gains a
# `priority` (the WHOLE-SESSION finding — `Session::publish_qos` now stamps the
# app band onto the `MulticastTxItem` instead of the pre-y232 hard-coded DEFAULT).
# This lane drives BOTH gate arms so neither rots:
#   1. ON witness — the direct multicast `Session::publish_qos` -> tx-item band
#      hand-off (the finding fix), in the multicast+codec-push lane. This pins the
#      Session -> MulticastTxItem enqueue; the group-level is_qos CLAMP (the wire
#      half: is_qos=true -> non-DEFAULT band survives to frame ext_qos + mints on
#      the per-priority conduit; is_qos=false -> DEFAULT byte-identical) is the
#      `wz-session-core` `multicast_tx::qos_emit_tests`, RUN by (1b) below. NOTE
#      C1bb's transport-qos test lane OMITS `codec-push`, so it cfg's those two
#      tests OUT (they need `transport-qos + codec-push`); this lane is the one
#      that EXECUTES the wire-level clamp proof, not only clippy-compiles it.
#   1b. ON dispatch clamp — RUN `multicast_tx::qos_emit_tests` under
#      `transport-qos,codec-push,session-multicast,pubsub-put` (the exact combo
#      that inhabits `MulticastTxItem::Push` AND the per-priority TX conduit).
#   2. ON clippy — the per-priority multicast conduit + the `_qos` send seam under
#      `transport-qos` (the conduit-active arm), --all-targets -D warnings.
#   3. OFF clippy — multicast WITHOUT `transport-qos` (the pico-faithful 2-channel
#      arm: `effective_mcast_priority`'s not(transport-qos) clamp + the seam's
#      DEFAULT hand-off must compose with NO dead code under -D warnings).
#   4. Demo ON — `wz-ap-demo` with `router-multicast-faces,transport-qos`: the
#      `--multicast-qos` parse + `run_router_hat(multicast_qos)` + the two spawn
#      `qos` params compile+lint clean.
#   5. Demo OFF — `wz-ap-demo` with `router-multicast-faces` only: the
#      not(transport-qos) flag arm (flag ignored, non-QoS group).
#   6. item3 UNIFIED — the base `publish` (NOT publish_qos) with
#      `PublishOptions::with_priority` routes the conduit band from the SINGLE
#      `opts.qos` source. RUN `publish_with_priority_routes_multicast_conduit_band`
#      + clippy under the both-transports+`pubsub-priority` combo (the multicast
#      tx-item harness needs `transport-multicast`; `with_priority` + the
#      `publish_qos` fold-arm need `pubsub-qos`, which the `pubsub-priority`
#      alias pulls in (R311y314: this said the fold-arm "needs pubsub-priority" --
#      the alias is sufficient, never necessary; the arm is cfg(pubsub-qos));
#      multicast-only+pubsub-priority
#      is a pre-existing incompatible combo — the SessionRuntime ActionsHandle GAT
#      is `transport-unicast`-gated — so both transports are required). This is the
#      only lane that exercises `with_priority` on the multicast conduit AND the
#      `pubsub-qos` arm of the `publish_qos` fold (reached here via the
#      `pubsub-priority` alias, which this lane composes).
#
# R311y414 — the four test steps were BARE. Each is a narrow named filter
# (2 emit units, then the SAME `multicast_publish_qos_stamps` witness run twice
# — qos OFF then ON — then the priority-routing witness), which is exactly the
# shape where a rename or a feature-set edit silently matches nothing; the
# measured exact counts now pin them, including the qos-OFF/ON pair whose whole
# point is that BOTH builds run the same single case.
layer_c1bc_cargo_test_mcast_qos() {
    _runci_guarded_test C1bc 2 cargo test -p wz-session-core --features transport-qos,codec-push,session-multicast,pubsub-put --lib qos_emit_tests --quiet \
        || return 1
    _runci_guarded_test C1bc 1 cargo test -p wz-runtime-tokio --no-default-features --features transport-multicast,transport-link-udp,codec-push,pubsub-put,pubsub-allow-loop --lib multicast_publish_qos_stamps --quiet \
        || return 1
    _runci_guarded_test C1bc 1 cargo test -p wz-runtime-tokio --no-default-features --features transport-multicast,transport-link-udp,codec-push,transport-qos,pubsub-put,pubsub-allow-loop --lib multicast_publish_qos_stamps --quiet \
        || return 1
    _runci_guarded_test C1bc 1 cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,transport-multicast,transport-link-udp,codec-push,transport-qos,pubsub-put,pubsub-allow-loop,pubsub-priority --lib publish_with_priority_routes_multicast_conduit_band --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-multicast,transport-link-udp,codec-push,transport-qos --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --no-default-features --features transport-multicast,transport-link-udp,codec-push --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --no-default-features --features transport-unicast,transport-multicast,transport-link-udp,codec-push,transport-qos,pubsub-put,pubsub-allow-loop,pubsub-priority --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features router-multicast-faces,transport-qos --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features router-multicast-faces --quiet -- -D warnings)
}

# ─── Layer C1bd — locator-iface: #iface= NIC bind honor (R311y236) ─
#
# R311y236 promotes `locator-iface` reserved-INERT -> active: the `#iface=<name>`
# locator config tail (parsed always-on in wz-session-core::locator) is now
# HONORED by binding the dialing/listening socket to the named NIC
# (SO_BINDTODEVICE, Linux/Android; warn-noop off-platform) across tcp/tls/ws/udp/
# quic/quic-datagram + the listen bind. This lane clippy-gates the feature-ON
# honor path (which pulls socket2 + compiles the real SO_BINDTODEVICE bind)
# -D warnings across the TCP-family (udp+ws), TLS, and QUIC(+datagram)
# feature-arms — each transport ALONE with locator-iface, since tls+quic TOGETHER
# is a pre-existing DialConfig-literal clash unrelated to this atom. The #iface=
# PARSE tests (wz-session-core) + the Some-arm noop-connect wiring test
# (link_pipeline, gated not(locator-iface)) run in the DEFAULT lanes; this lane
# pins that the honor path itself builds clean under the feature for every
# transport that carries it.
# R311y454 — this lane was clippy+build ONLY, and it RAN NOWHERE HOSTED (absent from
# ci.yml's --layer set, so only a manual local full sweep reached it). Both are fixed:
# the lane is registered in ci.yml, and it now EXECUTES the honor path rather than
# merely compiling it. Three test legs, each owning a build variant nothing else has:
#   - the getifaddrs resolver unit tests (NotFound vs Undetermined, the carrier
#     cross-check against sysfs, both resolution directions agreeing);
#   - the quic LISTEN-side delivery A/B (`lo` accepts a loopback dial, a non-lo device
#     does not) -- DELIVERY-based on purpose: an implementation that device-binds a
#     socket and then drops it, still calling quinn's convenience constructor, passes
#     every "binding to lo works" and "absent device gives ENODEV" test;
#   - the multicast honor rides Layer M (it needs real group sockets), not here.
layer_c1bd_locator_iface() {
    (cd crates \
        && cargo test -p wz-session-core --lib locator::tests --quiet \
        && cargo test -p wz-runtime-tokio --features locator-iface,transport-link-udp --lib link_interfaces --quiet \
        && cargo test -p wz-runtime-tokio --features locator-iface,transport-link-quic --test quic_e2e --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features locator-iface,transport-link-udp,transport-link-ws --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features locator-iface,transport-link-tls --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features locator-iface,transport-link-quic,transport-link-quic-datagram --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features locator-iface,transport-multicast --quiet -- -D warnings \
        && cargo build -p wz --features locator-iface --quiet)
}

# ─── Layer C1ae — compression transport: lz4 wrap + ext 0x6 + e2e ─
#
# R311xm: transport-compression (the lz4 per-batch wrap) + session-extcompression
# (the Z_EXT_COMPRESSION 0x6 handshake), the wz mirror of zenoh's per-batch
# compression (batch.rs), using the SAME lz4_flex crate for wz<->zenohd byte
# compatibility. Both peers OFFER the 0x6 unit ext on Init; the `&=` merge agrees;
# every post-establishment batch is lz4-wrapped [BatchHeader][payload] (kept only
# when smaller). Handshake/OpenAck stay uncompressed (the is_established gate).
# This lane:
#   1. runs the compression + extcompression unit tests (the lz4 round-trip incl
#      the incompressible-stays-raw + decompression-bomb-bound cases, and the 0x6
#      unit ext codec);
#   2. runs the compression_e2e integration tests (gated all(session-extcompression,
#      transport-unicast, transport-link-tcp)): wz<->wz negotiate over real TCP +
#      deliver a compressible Put byte-exact through the lz4 wrap, AND a
#      deterministic wire-form proof that the Put batch leads with the COMPRESSION
#      BatchHeader (vs a bare T_MID_FRAME control), plus the one-sided-offer `&=`;
#   3. clippy-gates the cfg under --all-targets (the lz4 tx/rx wrap + negotiation);
#   4. clippy-gates the LIB under --no-default-features --features
#      transport-compression to prove the bare lz4 wrap primitive (no handshake
#      codecs) composes standalone (is_compression never flips, so the wrap is
#      inert-but-present, dead-code-free).
#   5. R311y433 — clippy-gates wz-ap-demo under --features session-extcompression,
#      the demo's `--compression` cfg site (the `InitiatorOffer::Compression` open
#      arm + the `compression negotiated = {}` witness the Layer Z cross-impl leg
#      greps). Layer C2 is `clippy --workspace` at DEFAULT features, which compiles
#      that arm OUT and exits 0, so without this step the atom's demo-side code is
#      lint-gated by nothing. Layer Z `cargo build`s the same feature, which catches
#      a compile error but no lint.
#
# R311y414 — both test steps were BARE; they now carry anchored count guards
# with the MEASURED counts (6 unit / 2 e2e).
layer_c1ae_cargo_test_compression() {
    _runci_guarded_test C1ae 6 cargo test -p wz-session-core --features session-extcompression --lib compression --quiet \
        || return 1
    _runci_guarded_test C1ae 2 cargo test -p wz-runtime-tokio --features session-extcompression,transport-unicast,transport-link-tcp --test compression_e2e --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features session-extcompression,transport-unicast,transport-link-tcp --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features transport-compression --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features session-extcompression --quiet -- -D warnings)
}

# ─── Layer C1ax — §5.21 routing-namespace (R311y106 unicast + R311y107 multicast) ─
#
# The per-participant keyexpr namespace decorator (the wz mirror of zenoh's
# Namespace/ENamespace Primitives pair). Its egress (the unicast
# Tp::send_network_message arm + the send_response reply seam) and ingress (the
# drive-loop FramePayload strip, BOTH the direct and the reassembled mint
# points) are routing-namespace-gated and OFF by default, so Layer C1 (default
# features) never reaches them. This lane:
#   1. runs the kernel + actions lib tests (the apply_egress / stateful
#      NamespaceIngress unit suite, incl the strip_nonwild_prefix oracle);
#   2. runs the composed pub/sub + query/reply e2e over a real loopback link
#      (same-ns delivery, cross-ns isolation, un-namespaced drop, off-path no-op,
#      and the query REPLY round-trip that proves the send_response egress seam);
#   3. runs the fragmented/reassembled e2e (transport-fragmentation forces a tiny
#      MTU so an oversize namespaced Put exercises the report_outcome_reassembling
#      strip mint-point);
#   4. clippy-gates the cfg-active surface (incl the test files) across the full
#      codec combo and a narrow no-default combo (the decorator composes
#      standalone), and builds the wz facade under the forwarded feature;
#   5. covers the reconnect declaration-replay egress seam (the
#      session-reconnect + declare-* clippy combo compiles `replay_namespace_*`,
#      and `namespace_reconnect_e2e` proves a replayed declare ships namespaced —
#      the R311y106 implementation-panel finding) and the remote-declare
#      `matching_status` e2e (the relative-remote-table DROP decision: ingress
#      strips inbound declares, so no namespace-qualify is needed).
#   6. (R311y107) the MULTICAST facet: the egress decorator at the single
#      outbound chokepoint (apply_egress_multicast_item) + the PER-PEER ingress
#      strip on the dispatcher (the `namespace_ingress_is_per_peer` proof — wz
#      applies the strip on raw per-sender ids with no router to de-collide, so
#      the blocked-id correlation is per-PeerSlot, not one per session) + the
#      in-loop `drive_loop_namespaced_strips_inbound_and_drops_out_of_namespace`
#      composed e2e. Runs the session-core unit suite (namespace + the
#      multicast_dispatch per-peer/no-op tests, caught by the `namespace` filter)
#      and the wz-runtime-tokio multicast_glue lib e2e under transport-multicast,
#      plus the ON-path and OFF-path (session-multicast WITHOUT routing-namespace)
#      clippy gates proving the seam composes and the off path is dead-code clean.
layer_c1ax_cargo_test_routing_namespace() {
    _runci_guarded_test "C1AX namespace 19" 19 \
        cargo test -p wz-session-core --features routing-namespace,session-unicast,codec-push,codec-request,codec-response,codec-response-final,codec-declare,reassembly --lib namespace --quiet || return 1
    _runci_guarded_test "C1AX namespace_e2e 4" 4 \
        cargo test -p wz-runtime-tokio --features routing-namespace --test namespace_e2e --quiet || return 1
    _runci_guarded_test "C1AX namespace_query_e2e 1" 1 \
        cargo test -p wz-runtime-tokio --features routing-namespace --test namespace_query_e2e --quiet || return 1
    _runci_guarded_test "C1AX namespace_matching_e2e 2" 2 \
        cargo test -p wz-runtime-tokio --features routing-namespace --test namespace_matching_e2e --quiet || return 1
    _runci_guarded_test "C1AX namespace_alias_e2e 1" 1 \
        cargo test -p wz-runtime-tokio --features routing-namespace --test namespace_alias_e2e --quiet || return 1
    _runci_guarded_test "C1AX namespace_reassembly_e2e 1" 1 \
        cargo test -p wz-runtime-tokio --features routing-namespace,transport-fragmentation --test namespace_reassembly_e2e --quiet || return 1
    _runci_guarded_test "C1AX namespace_reconnect_e2e 2" 2 \
        cargo test -p wz-runtime-tokio --features routing-namespace,session-reconnect --test namespace_reconnect_e2e --quiet || return 1
    _runci_guarded_test "C1AX session-multicast 25" 25 \
        cargo test -p wz-session-core --no-default-features --features routing-namespace,session-multicast,codec-join,codec-frame,codec-close,codec-push,codec-declare,codec-response,codec-response-final,liveliness-token,query-queryable,reassembly,pubsub-put --lib namespace --quiet || return 1
    _runci_guarded_test "C1AX multicast_glue 15" 15 \
        cargo test -p wz-runtime-tokio --features transport-multicast,routing-namespace --lib multicast_glue --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-session-core --features routing-namespace,session-unicast,codec-push,codec-request,codec-response,codec-response-final,codec-declare,reassembly --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features routing-namespace,session-unicast,codec-push --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --features routing-namespace,session-unicast,session-reconnect,declare-keyexpr,declare-subscriber,declare-queryable,declare-token,declare-interest --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --features routing-namespace,session-unicast,declare-keyexpr --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-namespace --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-namespace,transport-fragmentation --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-namespace,session-reconnect --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features routing-namespace,session-multicast,codec-join,codec-frame,codec-close,codec-push,codec-declare,codec-response,codec-response-final,liveliness-token,query-queryable,reassembly,pubsub-put --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features alloc,session-multicast,codec-join,codec-frame,codec-close,codec-push,codec-declare,codec-response,codec-response-final,liveliness-token,query-queryable,reassembly,pubsub-put --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-multicast,routing-namespace --quiet -- -D warnings \
        && cargo build -p wz --features routing-namespace --quiet)
}

# ─── Layer C1ay — router-hat: STATE + INGEST + COMPUTE C1-C4 unit + clippy ─
#
# R311y108 + R311y109 + R311y110: the §5.21 router forwarder (the 4th
# `impl FaceForwarder`, `router_forward`) is the wz port of zenoh `hat/router`'s
# DUAL link-state mesh (routers_net + linkstatepeers_net), gated on the off-default
# `routing-router-hat` feature, so the default Layer C1 does NOT compile it --
# this lane restores its coverage, the same triad shape C1w/C1x/C1y use for the
# other routing forwarders:
#   1. runs the `router_forward` lib units: (1a) dual-net register/deregister
#      tier classification by whatami, the TIER-SCOPED flood proof that the two
#      nets never cross-inject, OAM tier ingest, tick coalescing per net, the
#      count-only Push deferral pin; (1b) subscription dual-tier INGEST --
#      DeclareSubscriber -> inbound-tier subs table + within-tier re-flood,
#      UndeclareSubscriber withdraw, DeclKexpr alias absorb, the duplicate-declare
#      change-gate; (1c) queryable dual-tier INGEST -- DeclareQueryable ->
#      inbound-tier qabls table (VALUE = QueryableInfo, the value-diff gate incl
#      the complete-flip re-flood) + within-tier re-flood carrying the info;
#      client-face-not-ingested pins for both planes;
#   2. clippy-gates the `routing-router-hat` cfg (`--all-targets`, incl tests);
#   3. clippy-gates the LIB under `--no-default-features --features
#      routing-router-hat` to prove the forwarder composes standalone
#      (routing-router-hat pulls only routing-peer). The `--lib router_forward`
#      filter runs the WHOLE router suite: 1a-1c = dual-net STATE + declare INGEST;
#      C0 (y112) extracted the shared route/re-advertise cores; C1 (y113) =
#      within-tier data route + tick re-advertise + self-zid guard; C2 (y114) =
#      client cross-tier subscription advertisement; C3a (y115) = client data
#      delivery; C3b (y117) = client->mesh publish; C4 (y118) = router↔router
#      mesh federation bridge + master-election (HRW elect_router over shared_nodes,
#      re-gating C3a local delivery + C3b's router leg). The query route (Request/
#      Response) + source-dimensioned route cache are the later C5 slice.
#   4. §5.16 access-control (R311y131, the y113 obligation): the router now carries
#      the ingress/egress interceptor plane (parity with LinkstateForwarder). The
#      `routing-router-hat,access-acl` arm RUNS the router ACL tests (an_ingress /
#      an_egress_acl_* — fan_out_tier + admit_inbound gates); the full access combo
#      (acl+downsampling+quota) clippy-gates --all-targets so the shared
#      `InterceptorConfig { .. }` spread is non-redundant (the C1y needless_update
#      caveat).
#   5. §5.21 routing-token-tables (slice-1): the router liveliness-TOKEN dual-tier
#      ingest plane (the token twin of router_subs/router_qabls). The
#      `routing-router-hat,routing-token-tables` arm RUNS the token units
#      (router/peer/client tier landing, within-tier reflood, change-gate,
#      face-down purge) that are `#[cfg(feature="routing-token-tables")]`-gated
#      and NEVER compiled by the plain routing-router-hat arm above; the
#      `--no-default-features --features routing-token-tables` clippy arm proves
#      standalone composition (it pulls routing-router-hat), so the token cfg sites
#      are never a dead, unlinted stub.
#   6. §5.21 router-multicast-faces (slice-1/3, EGRESS plane): the router's
#      unconditional broadcast of a routed Push to attached multicast groups
#      (mcast_groups egress, McastMux-faithful) + the run-mode egress HOST. The
#      group plane is `#[cfg(feature="transport-multicast")]`-gated inside
#      router_forward and NEVER compiled by the plain routing-router-hat arm above,
#      so the `routing-router-hat,transport-multicast` arm RUNS the egress units
#      (mcast_group_receives + routed_push_broadcasts_to_attached_mcast_group) +
#      clippy-gates the mcast cfg sites (incl. the Layer M loopback e2e). Slice 3
#      (R311y188) flipped the atom ACTIVE: the `cargo build -p wz-ap-demo --features
#      router-multicast-faces` step compiles the run_router_hat mcast host
#      (spawn_router_mcast_egress + attach_mcast_group) — the atom's A3 cfg site.
#   7. §5.21 router-connect-reconcile (R311y202): the runtime dynamic connect-list
#      reconcile (zenoh `update_peers`) + peer auto-reconnect (`closed_session`) — a
#      reconcile channel on the shared face_drive_loop that dials a newly-listed
#      connect endpoint (address dedup) AND `schedule_redial` re-dials a dropped
#      still-desired peer. The reconcile state + Step::Reconcile handler + the redial
#      arms are `#[cfg(feature="router-connect-reconcile")]`-gated in accept_loop,
#      NEVER compiled by the plain routing-router-hat arm above, so the
#      `routing-router-hat,router-connect-reconcile` clippy arm lints the reconcile
#      cfg sites (+ the `--no-default-features` narrow-combo arm), and the
#      `cargo build -p wz-ap-demo --features router-connect-reconcile` step compiles
#      the `--connect-after` run-mode host (the atom's A3 cfg site). The wz<->wz E2E
#      runs in Layer E7b.
#   8. R311y224 transit QoS band: the `routing-router-hat,transport-qos` arm RUNS
#      the router band-preservation test (route_push_preserves_the_received_band_on
#      _transit, `#[cfg(feature="transport-qos")]`-gated so it is NEVER compiled by
#      the plain routing-router-hat arm above) + clippy-gates the transport-qos cfg.
#      It proves a RealTime Put driven through the full `forward` dispatch survives
#      BOTH the within-tier relay (forward_push_tier) AND the cross-mesh bridge
#      (bridge_push_cross_mesh -> self_publish_into_tier) still banded — the router
#      twin of the peer transit lane (C1bb's routing-peer,transport-qos --lib
#      linkstate). Without this arm the y224 threading would be unguarded in CI.
layer_c1ay_cargo_test_router_hat() {
    _runci_guarded_test "C1AY router_forward 136" 136 \
        cargo test -p wz-runtime-tokio --features routing-router-hat --lib router_forward --quiet || return 1
    _runci_guarded_test "C1AY router_forward 138" 138 \
        cargo test -p wz-runtime-tokio --features routing-router-hat,transport-qos --lib router_forward --quiet || return 1
    _runci_guarded_test "C1AY router_forward 139" 139 \
        cargo test -p wz-runtime-tokio --features routing-router-hat,access-acl --lib router_forward --quiet || return 1
    # R311y464 — 171 -> 173: y463 added token_current_future_interest_replies_with_a
    # _client_token and token_current_future_interest_matches_a_wildcard_target, both
    # cfg(routing-token-tables), so ONLY this arm of the six moves. The other five
    # feature sets compile them out, which is why they still read 136/138/139/142/136.
    _runci_guarded_test "C1AY router_forward 173" 173 \
        cargo test -p wz-runtime-tokio --features routing-router-hat,routing-token-tables --lib router_forward --quiet || return 1
    _runci_guarded_test "C1AY router_forward 142" 142 \
        cargo test -p wz-runtime-tokio --features routing-router-hat,transport-multicast --lib router_forward --quiet || return 1
    _runci_guarded_test "C1AY router_forward 136" 136 \
        cargo test -p wz-runtime-tokio --features routing-router-hat,adminspace-router-linkstate --lib router_forward --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features routing-router-hat --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,transport-qos --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,access-acl,access-downsampling,access-quota --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,routing-token-tables --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,transport-multicast --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features routing-token-tables --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,router-connect-reconcile --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features router-connect-reconcile --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,adminspace-router-linkstate --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features routing-router-hat,adminspace-router-linkstate --quiet -- -D warnings \
        && cargo build -p wz-ap-demo --features router-multicast-faces --quiet \
        && cargo build -p wz-ap-demo --features router-connect-reconcile --quiet \
        && cargo build -p wz-ap-demo --features adminspace-router-linkstate --quiet)
}

# ─── Layer C1az — §5.26 rest-sse-subscribe: the SSE half of the REST bridge ─
#
# R311y161: the wz-rest crate's request/response bridge (GET/PUT/DELETE) rides
# the default Layer C1 `cargo test --workspace` (wz-rest is a workspace member,
# no default features), but the SSE half is gated behind wz-rest's
# `rest-sse-subscribe` feature -- OFF in the workspace build, so its sse unit
# tests + the rest_sse_wire_e2e (Accept: text/event-stream GET -> subscriber
# stream over two TCP sessions) never compile under C1. This lane turns the
# feature ON: runs the SSE unit + wire-e2e tests and clippy-gates the SSE cfg.
layer_c1az_cargo_test_rest_sse() {
    (cd crates \
        && cargo test -p wz-rest --features rest-sse-subscribe --quiet \
        && cargo clippy -p wz-rest --all-targets --features rest-sse-subscribe --quiet -- -D warnings)
}

# ─── Layer C1af — SHM transport (R3a+R3b): provider + live swap + e2e ─
#
# R311xn (R3a) + R311xo (R3b): the scoped same-host SHM transport -- the wz mirror
# of zenoh's zero-copy SHM payload (a descriptor on the wire + an mmap'd /dev/shm
# segment). R3a: the no_std core (extshm: ShmDescriptor + VLE codec, the 0x2
# Put-body marker, the ShmResolver trait) + the AP provider (shm_provider: memmap2
# ShmBackedPayload + PosixShmResolver). R3b: the live TX swap (build_push_shm_literal
# emits the descriptor + marker), the RX un-swap (pubsub resolves via the
# registry-stored resolver), the scoped Z_EXT_SHM 0x2 establishment negotiation (a
# UNIT capability `&=`, NOT zenoh's challenge-response -- deferred), publish_shm +
# the open helpers. io_uring / zero-copy are NOT prerequisites (zenoh uses neither).
# This lane:
#   1. runs the session-core SHM unit tests (extshm descriptor/marker + the
#      build_push_shm_literal TX-swap wire-form proof: payload=descriptor + 0x2);
#   2. runs the shm_provider unit tests over REAL /dev/shm (a payload written to a
#      fresh segment is read back byte-exact by the resolver opening it by
#      descriptor; owner-drop unlinks; distinct ids) -- fully runnable, NO #[ignore]
#      (/dev/shm is present), like the QUIC lane closed vsock's gap;
#   3. runs the shm_e2e integration tests (gated all(session-extshm,
#      transport-unicast, transport-link-tcp)): wz<->wz negotiate SHM over real TCP
#      + deliver a Put ZERO-COPY (the publisher writes /dev/shm, the descriptor
#      rides the wire, the acceptor's PosixShmResolver mmaps + reads it byte-exact),
#      plus the negotiation `&=` (one-sided offer -> both off);
#   4. clippy-gates the cfg under --all-targets (the provider + the live swap);
#   5. clippy-gates BOTH bare cores standalone: --features transport-shm (the inert
#      R3a primitive) and --features session-extshm (the negotiation + swap).
#
# R311y414 — all three test steps were BARE; they now carry anchored count
# guards with the MEASURED counts (5 ext-codec unit / 3 provider unit / 2 e2e).
layer_c1af_cargo_test_shm() {
    # R311y507 — 5 -> 16. The filter `shm` now also selects the challenge-response
    # wire tests + the four-step FSM driven both ways (the forged-challenge,
    # unmappable-segment and malformed-InitSyn arms among them). Measured, not
    # inferred: `cargo test .. --lib shm` reports 16.
    _runci_guarded_test C1af 16 cargo test -p wz-session-core --features session-extshm,codec-push --lib shm --quiet \
        || return 1
    _runci_guarded_test C1af 3 cargo test -p wz-runtime-tokio --features session-extshm,transport-unicast,transport-link-tcp --lib shm_provider --quiet \
        || return 1
    # R311y507 — 2 -> 5. The target gained the challenge-response over a real
    # driven handshake plus the two half-mix arms (a ONE-SIDED authenticator must
    # leave BOTH sides without SHM — a session ending with one side believing it
    # was on would put descriptors on a wire the peer reads as payload bytes).
    # R311y516 — 5 -> 6. The target gained the RX ENFORCEMENT arm: an SHM
    # descriptor arriving from a peer that never NEGOTIATED SHM must not make
    # this node map the segment. Before y516 the un-swap consulted only the 0x2
    # body marker, so the negotiation was decorative on the receive side; zenoh
    # gates the whole un-swap on the negotiated capability
    # (io/zenoh-transport/src/unicast/universal/rx.rs:50-51).
    _runci_guarded_test C1af 6 cargo test -p wz-runtime-tokio --features session-extshm,transport-unicast,transport-link-tcp --test shm_e2e --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features session-extshm,transport-unicast,transport-link-tcp --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features transport-shm --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features session-extshm --quiet -- -D warnings)
}

# ─── Layer C1ag — transport-advanced COMPOSITION + R311xr review remediation ─
#
# R311xr: the three transport-advanced capabilities (lowlatency / compression /
# shm) COMPOSE on one session, plus the review-remediation tests. This lane:
#   1. runs the shared unit_ext SSOT test (the encode/detect mechanism the three
#      establishment negotiations delegate to);
#   2. runs the SHM unresolved-drop observability test (a marker Put with no
#      resolver drops AND increments the observable counter -- fail-observable,
#      not fail-silent) under the heavily-gated pubsub dispatch test module;
#   3. runs transport_compose_e2e -- the 3-way composition the single-mode e2e
#      could not prove. R311y434 REWROTE what it asserts: the stack is NOT
#      compression(lean(shm-descriptor)). zenoh negotiates the 0x6 ext on a lean
#      link but its lean tx never touches WBatch/BatchHeader
#      (unicast/lowlatency/link.rs:33-73), so a negotiated wrap is INERT there and
#      wz wrapping anyway emitted a wire no zenoh peer can read. The lane now runs
#      an option-atom PAIR (2 tests, hence the pin below): with lowlatency the wire
#      is the bare lean Push and `compresses_batches()` is false while
#      `is_compression()` stays true; WITHOUT it the BatchHeader is present, which
#      is what catches an over-broad suppression;
#   4. runs transport_mode_pairs_e2e -- R311y435's two option-atom PAIRS for the
#      mode pairs R311y434's carry named as unread and untested: qos x
#      compression (the wrap is OUTSIDE the ext_qos-bearing Frame, as upstream,
#      where every per-priority queue shares one BatchConfig --
#      common/pipeline.rs:719) and batching x lowlatency (an ACTIVE batching
#      window accumulates NOTHING on a lean session, because upstream's lean
#      transport has no pipeline at all -- lowlatency/tx.rs:30-51 -- and wz
#      reproduces that by ORDERING the lean early-return ahead of the batching
#      arm). 4 tests, hence the pin; all four REDs were measured separately,
#      including provoking each byte assertion on its own because the invariant
#      assertion panics first (the R311y434 discipline);
#   5. clippy-gates the combined cfg --all-targets (the only build where all the
#      composed data paths + the shared establish_capability_pair helper compile
#      together).
#
# R311y414 — all three test steps were BARE and each is a SINGLE-test target
# (1/1/1), the shape where a rename or a cfg-out is invisible; anchored count
# guards now pin them. R311y434 — the compose target became a PAIR, so its pin is
# 2. MEASURED, and the other two pins were re-checked rather than assumed
# unaffected: neither shares the compose target's filter, so this pin did not
# invalidate in a cluster (the R311y432 failure mode).
layer_c1ag_cargo_test_transport_compose() {
    # R311y506 — the pin moved 1 -> 2. R311y505 added a SECOND test to
    # `unit_ext` (`a_shared_id_with_another_encoding_is_a_different_extension`,
    # the regression guard for reading a zenoh ZBuf@0x2 as wz's UNIT@0x2) without
    # moving the count, which is precisely the drift this anchored guard exists to
    # catch -- it has been red on main since that round.
    _runci_guarded_test C1ag 2 cargo test -p wz-session-core --features transport-lowlatency,session-extcompression,session-extshm --lib unit_ext --quiet \
        || return 1
    _runci_guarded_test C1ag 1 cargo test -p wz-session-core --features transport-shm,codec-push,codec-declare,codec-response-final,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp --lib shm_put_with_no_resolver --quiet \
        || return 1
    _runci_guarded_test C1ag 2 cargo test -p wz-runtime-tokio --features transport-lowlatency,session-extcompression,session-extshm,transport-unicast,transport-link-tcp --test transport_compose_e2e --quiet \
        || return 1
    _runci_guarded_test C1ag 4 cargo test -p wz-runtime-tokio --features transport-qos,transport-lowlatency,session-extcompression,transport-batching,transport-unicast,transport-link-tcp --test transport_mode_pairs_e2e --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-lowlatency,session-extcompression,session-extshm,transport-unicast,transport-link-tcp --quiet -- -D warnings) \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-qos,transport-lowlatency,session-extcompression,transport-batching,transport-unicast,transport-link-tcp --quiet -- -D warnings)
}

# ─── Layer C1ah — time-hlc: §5.18 HLC timestamp source + storage seam ─
#
# R311xt: time-hlc is the active §5.18 atom -- the uhlc::HLC variant of the
# storage fallback stamper (wz-runtime-tokio::timestamp_source::FallbackStamp),
# the wz mirror of zenoh's Option<Arc<HLC>> on the Runtime. The HLC WRAPS wz's
# wall_clock_ntp64 physical clock (injected via HLCBuilder::with_clock) and adds
# a logical counter (the low CSIZE bits) + a drift bound, so an un-timestamped
# captured sample is stamped with a strictly-monotonic NTP64. R311xw: time-hlc
# now IMPLIES storage-backend (its only consumer), so this lane drives `time-hlc`
# ALONE (no explicit storage-backend) to prove the implication holds + no dead
# uhlc dep, the gap the prior always-paired lane missed. This lane:
#   1. runs the timestamp_source unit tests under `time-hlc` alone (the
#      counter-isolating frozen-clock proof + the observable strict-increase +
#      zid-preservation + real-magnitude checks) -- the test compiling at all
#      proves time-hlc pulled storage-backend (timestamp_source is storage-gated);
#   2. clippy-gates the ON path (--all-targets, `time-hlc` alone) -- the HLC
#      build + the stamper seam + the storage wiring + the implied storage stack;
#   3. clippy-gates the OFF path (storage-backend WITHOUT time-hlc) to prove the
#      bare wall_clock_ntp64 fallback is byte-identical + unused-free (the
#      TimestampHint import goes test-only, the HLC fns elide cleanly).
# R311y450 restructures this lane in three ways, each closing a measured gap:
#
#   (a) TWO test legs instead of one. `time-hlc = ["storage-backend", "dep:uhlc"]`
#       but the timestamp_source MODULE gate is
#       any(storage-backend, ext-pubsub-advanced-cache, time-hlc), so the two are
#       not the same axis. Driving `time-hlc,storage-backend` AND
#       `time-hlc,ext-pubsub-advanced-cache` clippy-covers the cache consumer's
#       compiled surface as well as the storage one. MEASURED: both legs select
#       the same counts today (5 / 12) because time-hlc pulls storage-backend
#       either way — the legs differ in COMPILED FEATURE SET, not in selection.
#   (b) node_clock coverage. The node-scoped HLC + the forward-path stamp landed
#       in a NEW module, so the pre-existing `--lib timestamp_source` filter did
#       not select a single one of its tests. Twelve tests, filter `node_clock::`
#       — with the `::` deliberately, because the bare substring `node_clock`
#       ALSO matches timestamp_source's `..._not_the_node_clocks` test and would
#       report 13 (pin SETS, not counts).
#   (c) a ROUTING leg. The forward-path stamp lives in `route_push`
#       (router_forward.rs) and `forward_push` (linkstate_forward.rs), which are
#       compiled only under the routing features. No lane composed
#       `time-hlc` WITH routing before this round, so the seam could have failed
#       to compile — or been cfg'd out entirely — with every lane still green.
#       C4 builds preset-ap-full (which carries both) but is build-only and
#       clippy-free. R311y480 narrows that: C4 is still library-build-only, but
#       Layer E9 now RUNS a preset-ap-full DEMO BINARY against real zenoh-pico.
#       It is not a substitute for this lane — E9 proves the composition
#       interoperates, not that `time-hlc` WITH routing composes as a clippy-clean
#       seam, which is what the combo below is for.
layer_c1ah_cargo_test_time_hlc() {
    _runci_guarded_test "C1ah timestamp_source" 5 \
        cargo test -p wz-runtime-tokio --features time-hlc --lib timestamp_source:: --quiet || return 1
    _runci_guarded_test "C1ah node_clock" 12 \
        cargo test -p wz-runtime-tokio --features time-hlc --lib node_clock:: --quiet || return 1
    _runci_guarded_test "C1ah node_clock (advanced-cache leg)" 12 \
        cargo test -p wz-runtime-tokio --features time-hlc,ext-pubsub-advanced-cache \
        --lib node_clock:: --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features time-hlc --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features time-hlc,ext-pubsub-advanced-cache --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features time-hlc,routing-router-hat,routing-peer,routing-accept --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features storage-backend --quiet -- -D warnings)
}

# ─── Layer C1ai — liveliness-history: §5.10 CURRENT-state-replay request gate ─
#
# R311xy: liveliness-history is the active §5.10 atom -- the per-call cfg gate on
# the subscriber-side CURRENT-state-replay REQUEST (the `history = true` option
# -> CURRENT bit on the outbound Interest + the history_complete snapshot signal)
# living inside `Session::declare_liveliness_subscriber{_aliased}` (R311cl's
# "per-call gate, not field gate"). The default Layer C1 builds it ON, so this
# lane pins the two ISOLATED paths the default does not exercise:
#   1. clippy the ON path (--no-default-features, liveliness-subscriber +
#      liveliness-history) -- the gate forwards options.history to the Interest
#      builder + the register/cache sites;
#   2. clippy the OFF path (liveliness-subscriber WITHOUT liveliness-history) to
#      prove the future-only build composes -- the `not(liveliness-history)` arm
#      forces history=false, so the CURRENT-bit request elides cleanly while
#      options.history / with_history() stay callable no-ops (signature-stable).
#   3. cargo TEST the OFF path's BEHAVIOR (R311y1 review remediation): the
#      effective_history gate test asserts effective_history()==false under
#      not(liveliness-history) even when history=true -- the OFF-arm
#      behavioral assertion the prior clippy-only lane (despite its
#      `cargo_test` name) never actually ran.
layer_c1ai_cargo_test_liveliness_history() {
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --no-default-features \
            --features transport-unicast,liveliness-subscriber,liveliness-history --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features \
            --features transport-unicast,liveliness-subscriber --quiet -- -D warnings)
    _runci_guarded_test "C1ai effective_history" 1 \
        cargo test -p wz-runtime-tokio --no-default-features \
        --features transport-unicast,liveliness-subscriber --lib effective_history --quiet || return 1
}

# ─── Layer C1aj — QUIC DATAGRAM link: locator parse + datagram backend e2e ─
#
# R311y8: the DATAGRAM sibling of C1ac (quic). `transport-link-quic-datagram`
# (OFF in the default set, IMPLIES `transport-link-quic`) carries each zenoh
# batch as ONE QUIC unreliable datagram (send_datagram/read_datagram, RFC9221) —
# the UDP datagram driver shape, NOT the StreamEnvelope stream of C1ac. This
# lane:
#   1. runs the locator tests (the `quic-datagram/<host>:<port>` parse is the new
#      `Proto::QuicDatagram`, the IP-family numeric grammar — ungated parse);
#   2. runs the `quic_datagram_e2e` integration test (gated
#      `all(transport-link-quic-datagram, transport-unicast)`): two nodes complete
#      the QUIC + TLS-1.3 handshake over loopback — the initiator via a
#      `quic-datagram/...` LOCATOR + DialConfig.quic (the SAME cert as quic) —
#      reach Established, and a Put is delivered byte-exact over the QUIC datagram
#      data path;
#   3. clippy-gates the `transport-link-quic-datagram` cfg (`--all-targets`);
#   4. clippy-gates the LIB under `--no-default-features --features
#      transport-link-quic-datagram` to prove `quic_datagram_pipeline` composes
#      standalone (it pulls transport-link-quic's quinn + tls stack + `bytes`).
#
# R311y413 — the `quic_datagram_e2e` step gained the anchored
# `^test result: ok\. 1 passed` count-guard (was bare, a silent-0-tests risk), and
# this whole lane is now HOSTED on ci.yml's feature-gates job (see that step's
# comment). The datagram sibling of C1ac's hosting.
layer_c1aj_cargo_test_quic_datagram() {
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-quic-datagram --test quic_datagram_e2e --quiet 2>&1 | grep -qE '^test result: ok\. 2 passed' \
        && cargo test -p wz-runtime-tokio --features transport-link-quic-datagram --test link_endpoints_pairing --quiet 2>&1 | grep -qE '^test result: ok\. 3 passed' \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-link-quic-datagram --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features transport-link-quic-datagram --quiet -- -D warnings)
}

# ─── Layer C1ak — transport-stats: per-session byte/msg counters ─
#
# R311y9: `transport-stats` (OFF in the default set) adds per-session
# tx/rx byte+message counters at the single send_wire (TX) + dispatch_link_event
# (RX) seams in wz-session-core, with a public OpenedSession::stats() snapshot.
# Zero extra deps; the adminspace consumer stays P4. This lane:
#   1. runs the wz-session-core stats unit tests (counter accumulation + report);
#   2. runs the transport_stats_e2e integration test (gated
#      all(transport-stats, transport-unicast)): two nodes handshake over a
#      loopback TCP link to Established and BOTH peers show non-zero tx/rx
#      byte+message counters — the increments fire on a real driven session;
#   3. clippy-gates the `transport-stats` cfg on both crates (`--all-targets`).
#
# R311y414 — both test steps were BARE; anchored count guards with the MEASURED
# counts (2 counter unit / 1 e2e) now pin them.
layer_c1ak_cargo_test_transport_stats() {
    _runci_guarded_test C1ak 2 cargo test -p wz-session-core --features transport-stats --lib stats --quiet \
        || return 1
    _runci_guarded_test C1ak 1 cargo test -p wz-runtime-tokio --features transport-stats --test transport_stats_e2e --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-stats --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --all-targets --features transport-stats --quiet -- -D warnings)
}

# ─── Layer C1al — unixpipe: locator + FIFO e2e + accept seam + mesh-join ─
#
# R311y10 / R311y380: the named-FIFO-pair sibling of C1aa (unixsock).
# transport-link-unixpipe (OFF in the default set, Linux-only) carries a zenoh
# batch over a uplink + downlink FIFO pair using tokio's native pipe support —
# the SAME StreamEnvelope byte-stream framing as unixsock, reused unchanged.
# This lane:
#   1. runs the locator tests (the `unixpipe/<path>` parse is `AnyLocator::Unixpipe`
#      — ungated + platform-independent, like unixsock/vsock);
#   2. runs the `unixpipe_e2e` integration test (gated all(transport-link-unixpipe,
#      target_os="linux", transport-unicast)): two nodes reach Established over a
#      loopback FIFO pair — the initiator via a `unixpipe/...` LOCATOR — and a Put
#      is delivered byte-exact. It ALSO carries the R311y380 accept-seam
#      discriminator (`bind_endpoint("unixpipe/..")` -> BoundListener::accept_raw
#      -> AcceptedLink::handshake), RED before the scheme-keyed bind arm lands;
#   3. runs the R311y392 mesh-JOIN discriminator (routing-accept +
#      transport-link-unixpipe): TWO initiators dial ONE unixpipe listener through
#      the multi-client invitation handshake and are BOTH held as ZID-keyed mesh
#      faces (peak_concurrent == 2, zero AcceptError) — RED on the retired
#      single-connection acceptor (held 0/1). Count-guarded (`grep -qE '^test result: ok. 1 passed'`)
#      so a future test-name drift reddens the lane rather than silently running
#      0 tests (the "proof that never runs" trap this lane once lacked);
#   4. clippy-gates that same combo `--all-targets -- -D warnings` — `accept_loop`
#      is `#[cfg(feature = "routing-accept")]` (NOT in the default set), so the
#      plain-unixpipe clippy in step 5 compiles the accept-loop change OUT and
#      would not lint it; this step is the one that -D-warnings-gates it;
#   5. clippy-gates the `transport-link-unixpipe` cfg (`--all-targets`);
#   6. clippy-gates the LIB under `--no-default-features --features
#      transport-link-unixpipe` to prove `unixpipe_pipeline` composes standalone
#      (it pulls transport-link-tcp's shared stream_link + libc for mkfifo).
#
# R311y410 (unixpipe bind-pin RUN + C1al hosted): step 3b RUNS the BIND-time pin
# `boundlistener_unixpipe_is_mesh_capable` (right after the step-3 mesh accept unit,
# same `routing-accept,transport-link-unixpipe` set so it reuses that test binary),
# closing the sibling asymmetry the quic/datagram pins closed in C1w (R311y408/y409):
# the unixpipe accept unit ran (step 3) but the bind predicate
# `BoundListener::Unixpipe => true` executed in NO lane, only clippy-compiled. RED+TWIN
# by falsification: flip that arm to `false` and ONLY this new step reddens — the step-3
# accept unit consults the `AcceptedLink` RUNTIME twin, not the BoundListener bind
# predicate, so it stays green (the same isolation the quic pair has). Same `1 passed`
# count-guard. R311y410 ALSO hosts this whole C1al lane on ci.yml's feature-gates job (it
# ran only in a local full sweep before — the "gate that never runs hosted reports
# success by silence" hazard, the exact reason that job exists), mirroring how y409
# hosted C1w. The vsock twin C1ab stays local-only (out of y410 scope).
layer_c1al_cargo_test_unixpipe() {
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-unixpipe --test unixpipe_e2e --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-unixpipe --test link_endpoints_pairing --quiet 2>&1 | grep -qE '^test result: ok\. 2 passed' \
        && cargo test -p wz-runtime-tokio --features routing-accept,transport-link-unixpipe --lib mesh_accept_loop_holds_two_unixpipe_peers --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo test -p wz-runtime-tokio --features routing-accept,transport-link-unixpipe --lib boundlistener_unixpipe_is_mesh_capable --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-accept,transport-link-unixpipe --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-link-unixpipe --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features transport-link-unixpipe --quiet -- -D warnings)
}

# ─── Layer C1ba — transport-multilink §5.1: N-link aggregation clippy floor ─
#
# R311y205 (transport-multilink slice-1): the §5.1 multi-link aggregation feature
# (the 0x4 Z_EXT_MULTILINK establishment ext + the shared-SessionCore link set +
# reliability-segregated send). It is AP-only (rsa/std). R311y211 REMOVED the
# former transport-multilink × session-reconnect compile_error: the
# reset_for_reopen shared-SN corruption is now a RUNTIME guard (the shared-core
# reset is skipped while a survivor link is live). The standalone §5.1 invocations
# below stay --no-default-features (they prove multilink composes WITHOUT
# session-reconnect — the runtime-tokio default set carries session-reconnect), and
# invocation 5 adds the ex-XOR coexistence proof on default + transport-multilink.
# This lane:
#   1. runs the wz<->wz slice-1 e2e (session_multilink_e2e: 2 loopback-TCP links
#      aggregated into ONE session with reliability segregation + failover, the
#      0x4 handshake + config-equality join, the INVALID/MAX_LINKS rejects, and
#      the no-0x4 regression floor + the positive-0x4 control);
#   1b. runs the DEPLOY-ACTIVE e2e (session_multilink_deploy_e2e): a real
#      `peer_loop` with `max_links = 2` aggregating two links THROUGH the
#      production accept/dial path (not direct join_link) — aggregation,
#      reliability segregation, MAX_LINKS reject, and link-death failover on the
#      loop's own handlers, plus the dial-side aggregation. This lane adds
#      `routing-peer` to the aggregation set (the accept_loop/peer_loop module is
#      `routing-accept`-gated, which `routing-peer` forwards); it stays
#      --no-default-features (routing-peer does not pull session-reconnect, so the
#      mutual-exclusion gate is not tripped);
#   2. runs the multilink lib unit tests (the 0x4 dispatch round-trip, the MF-A
#      absent-0x4 single-link fallback, the join_link reject path) on both crates;
#   3. clippy-gates the LIB + the e2e test targets under the aggregation feature
#      set (-D warnings);
#   4. clippy-gates the LIB under --no-default-features --features
#      transport-multilink ALONE (proves the feature composes standalone — the
#      transport-unicast dependency + the codec-union select_link gate);
#   5. R311y211 — runs the reconnect×multilink COEXISTENCE unit test on the FULL
#      default feature set + transport-multilink (the combo the y205 XOR forbade),
#      pinning the reset_for_reopen GUARD MECHANICS on a synthetically-populated
#      link set (SN preserved while a link is live; re-seeded once the set is
#      empty). The count is asserted (grep '1 passed') so a future default-set
#      change that cfg-outs the test reddens the lane instead of passing green.
#      Clippy floors the ex-XOR combo on BOTH crates (the guard lives in
#      wz-session-core).
#   6. R311y212 slice-2 — the per-link AUTO-RE-ADD e2e (session_multilink_readd_e2e):
#      A's production peer_loop re-dials + re-JOINs a dropped dialed link (the
#      harness kills one of B's accepted links), proving a flapped aggregated link
#      comes back onto the SAME session with no manual re-dial.
layer_c1ba_cargo_clippy_transport_multilink() {
    local ML_FEATURES="transport-multilink,transport-link-tcp,codec-push,codec-close,session-unicast-open,session-unicast-accept,pubsub-put"
    # The deploy-active e2e drives the production `peer_loop` accept/dial path, so
    # it needs the `routing-accept`/`routing-peer` loop module compiled in.
    local ML_DEPLOY_FEATURES="$ML_FEATURES,routing-peer"
    # R311y414 — every test step in this lane is now a `_runci_guarded_test`
    # call. Six were BARE; the other three carried the older inline
    # `tee /dev/stderr | grep -qE` form, which the helper's own docstring rejects
    # (a `grep -q` stage can win the race against its upstream's SIGPIPE under
    # `set -o pipefail` and turn a SATISFIED guard into a false RED). The first
    # cut of this round kept the inline form here, arguing the helper's `cd
    # crates` cannot compose inside the lane's single `(cd crates && ...)` chain
    # — review disproved that: splitting the chain into guarded calls plus
    # clippy-only subshells is exactly what C1bb/C1bc did, and it also gives
    # each step a labelled FAIL diagnostic naming WHICH of the nine missed.
    _runci_guarded_test C1ba 5 cargo test -p wz-runtime-tokio --no-default-features --features "$ML_FEATURES" --test session_multilink_e2e --quiet \
        || return 1
    # R311y218 — qos x multilink composition: the qos-gated e2e proves the
    # _with_multilink entrypoints negotiate is_qos over the 0x4 handshake
    # (both-offer -> is_qos true; qos=false control -> false). The 5 -> 6 count
    # step IS that proof: the qos build activates one more case.
    _runci_guarded_test C1ba 6 cargo test -p wz-runtime-tokio --no-default-features --features "$ML_FEATURES,transport-qos" --test session_multilink_e2e --quiet \
        || return 1
    _runci_guarded_test C1ba 2 cargo test -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES" --test session_multilink_deploy_e2e --quiet \
        || return 1
    # R311y219 — qos x multilink PRIORITY segregation over the DEPLOY path: the
    # transport-qos deploy build activates the #[cfg(transport-qos)] priority
    # test (an EXPRESS + a LOW Put ride DISTINCT physical links; the reliability
    # tests stay green with the band inert). Runs BOTH deploy tests with qos on.
    _runci_guarded_test C1ba 3 cargo test -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES,transport-qos" --test session_multilink_deploy_e2e --quiet \
        || return 1
    # R311y212 slice-2 — the per-link AUTO-RE-ADD e2e: A's production peer_loop
    # (max_links=2, dials B twice) re-dials + re-JOINs a link the harness kills
    # on B, so a dropped dialed link comes back onto the SAME session. The count
    # guard reddens the lane if a feature-set edit ever cfg-outs the
    # '#![cfg(all(...))]'-gated file to 0 tests (silent green).
    _runci_guarded_test C1ba 1 cargo test -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES" --test session_multilink_readd_e2e --quiet \
        || return 1
    _runci_guarded_test C1ba 5 cargo test -p wz-runtime-tokio --no-default-features --features "$ML_FEATURES" --lib multilink --quiet \
        || return 1
    # R311y219a — the per-face priority-band + reliability-axis POLICY unit
    # tests live in accept_loop::tests (gated transport-multilink) inside the
    # routing-accept/peer-gated module, so they need BOTH multilink AND the
    # module gate to compile+run. No prior --lib lane combined them, so they
    # were CI-invisible; ML_DEPLOY_FEATURES has both.
    _runci_guarded_test C1ba 2 cargo test -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES" --lib --quiet -- multilink_priority_range multilink_pref_for \
        || return 1
    _runci_guarded_test C1ba 3 cargo test -p wz-session-core --no-default-features --features alloc,transport-multilink,session-unicast,codec-push,codec-close --lib extmultilink --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features "$ML_FEATURES" --lib --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features "$ML_FEATURES" --test session_multilink_e2e --quiet -- -D warnings \
        `# R311y218 — clippy the qos x multilink composition (entrypoint qos param,` \
        `# the demo --qos threading) under -D warnings, incl the wz-ap-demo bridge.` \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features "$ML_FEATURES,transport-qos" --test session_multilink_e2e --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --features transport-qos,transport-multilink --quiet -- -D warnings \
        `# R311y218 scope boundary — transport-qos WITHOUT transport-multilink: the` \
        `# demo --qos wires WzConfig.qos but the single-link arms do not offer it;` \
        `# must still compile (the FaceSources.qos bridge cfg-elides cleanly).` \
        && cargo clippy -p wz-ap-demo --features transport-qos --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES" --test session_multilink_deploy_e2e --quiet -- -D warnings \
        `# R311y219 — clippy the deploy e2e with qos on (the #[cfg(transport-qos)]` \
        `# priority-segregation test compiled) under -D warnings.` \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES,transport-qos" --test session_multilink_deploy_e2e --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES" --test session_multilink_readd_e2e --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features transport-multilink --quiet -- -D warnings \
        `# R311y205 whole-session F4 — the send_wire/select_link cfg-skew net: a` \
        `# transport-multilink build carrying ONLY a control codec (codec-close)` \
        `# or ONLY transport-keepalive must NOT compile a dead send_wire/select_link` \
        `# seam (those TX paths route through send_wire_this_link). Same class the` \
        `# C1m lane caught for send_wire on a bare transport-multicast MCU build.` \
        && cargo clippy -p wz-session-core --no-default-features --features alloc,transport-multilink,session-unicast,codec-close --lib --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features alloc,transport-multilink,session-unicast,transport-keepalive --lib --quiet -- -D warnings) \
        || return 1
    # R311y211 invocation 5 — the ex-XOR coexistence proof: default features
    # (which carry session-reconnect) + transport-multilink now COMPILE and the
    # reset_for_reopen runtime guard preserves the survivor's shared SN. The
    # count guard asserts the test actually RAN (`cargo test <substring>` exits
    # 0 on ZERO matches, so a future cfg-out would otherwise pass green).
    _runci_guarded_test C1ba 1 cargo test -p wz-runtime-tokio --features transport-multilink --lib reset_for_reopen_preserves_shared_sn_while_a_link_is_live --quiet \
        || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --features transport-multilink --lib --quiet -- -D warnings \
        `# the guard lives in wz-session-core; clippy-floor the ex-XOR combo THERE` \
        `# too (invocation 5's runtime-tokio clippy would not lint the guard body).` \
        && cargo clippy -p wz-session-core --features transport-multilink,session-reconnect --lib --quiet -- -D warnings)
}

# ─── Layer C1am — adminspace §5.23: @/<zid>/<whatami> built-in admin queryable ─
#
# R311y34 (adminspace-core) + R311y35 (adminspace-metrics) + R311y36 (adminspace-read):
# Session::declare_adminspace
# registers the `@/<zid>/<whatami>/**` built-in queryable and dispatches a GET to
# every handler whose key intersects it -- the root key -> `local_data` JSON
# (application/json), `/config` -> the typed WzConfig read-at-open mirror JSON
# (R311y40, application/json), and (adminspace-metrics) `/metrics` -> the
# OpenMetrics build-info body (text/plain). The default Layer C1 carries none of
# these, so this lane is the sole coverage:
#   1. wz-session-core data-view unit tests (adminspace: JSON emitter + metrics
#      builder) + the relocated zid<->ZenohId-hex SSOT (zid_hex), plus a
#      storage-replication build proving the re-export keeps the old call site
#      intact (no regression);
#   2. wz-runtime-tokio e2e (declare_adminspace, --lib filter) on BOTH the core
#      build (root GET -> JSON; `/config` GET -> typed WzConfig JSON [R311y40];
#      no-handler sub-path -> no reply) AND the metrics build (/metrics ->
#      OpenMetrics text/plain; a `/**` wildcard fires BOTH handlers);
#   3. clippy both ON builds (-D warnings, --all-targets) so the dispatch + the
#      reply_keyed_encoded seam stay warning-clean.
# This lane composes the features ON the default set; the --no-default-features
# standalone coverage is the sibling Layer C1an (R311y38), which also locks the
# two self-sufficiency fixes that the slim build surfaced (the session/mod.rs
# unused-ResponseSink import + the test-module dead-code re-gating).
layer_c1am_cargo_test_adminspace() {
    _runci_guarded_test "C1AM adminspace 18" 18 \
        cargo test -p wz-session-core --features adminspace-metrics --lib adminspace --quiet || return 1
    _runci_guarded_test "C1AM zid_hex 3" 3 \
        cargo test -p wz-session-core --features adminspace-core --lib zid_hex --quiet || return 1
    _runci_guarded_test "C1AM zid_to_zenoh_hex 1" 1 \
        cargo test -p wz-session-core --features storage-replication --lib zid_to_zenoh_hex --quiet || return 1
    _runci_guarded_test "C1AM declare_adminspace 3" 3 \
        cargo test -p wz-runtime-tokio --features adminspace-core,query-get --lib declare_adminspace --quiet || return 1
    _runci_guarded_test "C1AM admin_write_permit 1" 1 \
        cargo test -p wz-runtime-tokio --features adminspace-core,query-get --lib admin_write_permit --quiet || return 1
    _runci_guarded_test "C1AM declare_adminspace 5" 5 \
        cargo test -p wz-runtime-tokio --features adminspace-metrics,query-get --lib declare_adminspace --quiet || return 1
    _runci_guarded_test "C1AM declare_adminspace 6" 6 \
        cargo test -p wz-runtime-tokio --features adminspace-read,adminspace-metrics,query-get --lib declare_adminspace --quiet || return 1
    _runci_guarded_test "C1AM admin_write_permit 1" 1 \
        cargo test -p wz-runtime-tokio --features adminspace-write,query-get --lib admin_write_permit --quiet || return 1
    _runci_guarded_test "C1AM adminspace 20" 20 \
        cargo test -p wz-session-core --features adminspace-introspection-handlers --lib adminspace --quiet || return 1
    _runci_guarded_test "C1AM adminspace 21" 21 \
        cargo test -p wz-session-core --features adminspace-router-linkstate --lib adminspace --quiet || return 1
    _runci_guarded_test "C1AM adminspace 25" 25 \
        cargo test -p wz-session-core --features adminspace-plugins-handlers --lib adminspace --quiet || return 1
    _runci_guarded_test "C1AM declare_adminspace 3" 3 \
        cargo test -p wz-runtime-tokio --features adminspace-plugins-handlers,query-get --lib declare_adminspace --quiet || return 1
    _runci_guarded_test "C1AM compiled_plugins 1" 1 \
        cargo test -p wz-runtime-tokio --features adminspace-plugins-handlers,query-get --lib compiled_plugins --quiet || return 1
    _runci_guarded_test "C1AM compiled_plugins 1" 1 \
        cargo test -p wz-runtime-tokio --features adminspace-plugins-handlers,storage-backend,query-get --lib compiled_plugins --quiet || return 1
    # R311y497: 22 -> 26. The storage-add payload gained client-selectable volumes,
    # and the four new legs are what hold the widening to its promises — the legacy
    # (no-@) payload still resolving to `mem`, a named volume reaching the config, an
    # `@` inside a KEYEXPR left untouched (the delimiter must not narrow the keyexpr
    # grammar), and a name that itself contains `@` splitting on the last one. This
    # pin is why the count moved visibly instead of the module quietly growing.
    _runci_guarded_test "C1AM adminspace 26" 26 \
        cargo test -p wz-session-core --features adminspace-config-hotreload --lib adminspace --quiet || return 1
    _runci_guarded_test "C1AM storage_manager_service 5" 5 \
        cargo test -p wz-runtime-tokio --features adminspace-config-hotreload --lib storage_manager_service --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets --features adminspace-core,query-get --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features adminspace-metrics,query-get --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features adminspace-read,adminspace-metrics,query-get --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features adminspace-write,query-get --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-peer,adminspace-introspection-handlers --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-peer,adminspace-plugins-handlers,storage-backend --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-peer,adminspace-plugins-handlers --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features router-hat-router,adminspace-plugins-handlers,storage-backend --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features adminspace-config-hotreload --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features routing-peer,adminspace-write,adminspace-config-hotreload --quiet -- -D warnings)
}

# ─── Layer C1an — adminspace §5.23 SELF-SUFFICIENCY under --no-default-features ─
#
# R311y38: C1am proves adminspace works on the DEFAULT feature set; this lane is
# the standalone twin — it proves adminspace-core/metrics/read COMPOSE AND WORK
# under --no-default-features, i.e. the feature genuinely declares its OWN deps
# rather than free-riding the default set. Two real deps surfaced on the slim
# build and are now pulled by adminspace-core (wz-session-core/Cargo.toml):
#   * keyexpr-wildcard-double — the `@/<zid>/<whatami>/**` queryable's wire-path
#     match (keyexpr_intersects_target); without it `**` degrades to a literal
#     chunk and a remote admin GET never reaches the handler. Locked by the unit
#     `admin_queryable_double_wildcard_routes_root_and_subpath_gets`.
#   * pubsub-encoding — the reply EncodingHint (application/json / text/plain);
#     without it gated_reply_encoding drops the content-type. Locked by the
#     runtime root e2e's encoding assertion.
# This lane:
#   1. wz-session-core adminspace unit tests under --no-default-features
#      --features adminspace-core (the `**` matcher lock + the JSON emitters);
#   2. wz-runtime-tokio declare_adminspace e2e under --no-default-features for the
#      core / metrics / read+metrics combos (each loopback GET replies correctly,
#      proving the deps compose without the default set);
#   3. clippy --all-targets -D warnings on each --no-default-features combo — the
#      lane that would have caught the session/mod.rs unused-ResponseSink import
#      (R311y38 removed it; redundant with the always-present inherent
#      send_response_final) and the make_request_query/query_frame_outcome
#      test-module dead-code (R311y38 re-gated them to their codec-response-final
#      consumers), both of which only surface WITHOUT the full default codec set.
layer_c1an_cargo_test_adminspace_nodefault() {
    _runci_guarded_test "C1AN adminspace 16" 16 \
        cargo test -p wz-session-core --no-default-features --features adminspace-core --lib adminspace --quiet || return 1
    _runci_guarded_test "C1AN adminspace 21" 21 \
        cargo test -p wz-session-core --no-default-features --features adminspace-router-linkstate --lib adminspace --quiet || return 1
    _runci_guarded_test "C1AN declare_adminspace 3" 3 \
        cargo test -p wz-runtime-tokio --no-default-features --features adminspace-core,query-get --lib declare_adminspace --quiet || return 1
    _runci_guarded_test "C1AN declare_adminspace 5" 5 \
        cargo test -p wz-runtime-tokio --no-default-features --features adminspace-metrics,query-get --lib declare_adminspace --quiet || return 1
    _runci_guarded_test "C1AN declare_adminspace 6" 6 \
        cargo test -p wz-runtime-tokio --no-default-features --features adminspace-read,adminspace-metrics,query-get --lib declare_adminspace --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-session-core --no-default-features --features adminspace-core --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features adminspace-router-linkstate --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features adminspace-core,query-get --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features adminspace-metrics,query-get --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features adminspace-read,adminspace-metrics,query-get --all-targets --quiet -- -D warnings)
}

# ─── Layer C1ao — §5.23 config-mutate-runtime: typed WzConfig live reconfigure ─
#
# R311y39: the typed WzConfig SSOT (config.rs) + the LIVE interceptor reconfigure.
# config-mutate-runtime gates the re-apply: ON re-drives the live forwarder
# (config-DRIVEN), OFF stores-but-inert (read-at-open mirror — the inert mirror the
# §5.23 design rejects). The toggle existing IS the proof the config is load-bearing.
# The default Layer C1 carries neither the feature nor the access-acl combo, so this
# lane is the sole coverage:
#   1. ON arm: the `wzconfig_` live-drive family (config-mutate-runtime,access-acl)
#      — a config mutation flips the live admit->deny verdict
#      (wzconfig_reconfigure_drives_the_live_forwarder), the same instance also
#      serves the admin read (wzconfig_one_instance_drives_forwarder_and_serves_
#      admin_read), and the R311y48 config-WRITE merge reads via the
#      `interceptors()` getter then reapplies
#      (wzconfig_interceptors_getter_backs_the_config_write_merge);
#   1b. R311y50/y53 — the `to_admin_json` named tests on the SAME ON combo (so the
#      `#[cfg(all(routing-peer, access-acl))]` `acl_default`/`acl_deny` branch runs
#      in CI — the unfiltered full-lib lanes all build routing-peer OFF, so without
#      this it was never-executed, the R311y25 class) AND on the FULL access combo
#      (access-acl,access-downsampling,access-quota) so the R311y53 `downsampling` /
#      `low_pass` interceptor-view branches + their populated-rule test run too;
#   2. OFF arm: wzconfig_reconfigure_is_inert_without_config_mutate_runtime — the
#      mutation is stored but never applied (access-acl alone);
#   3. clippy the config.rs LIB on the ON combo + the routing-peer-OFF universal
#      WzConfig base (--no-default-features) — proving config.rs composes standalone.
# LIB-scope clippy (not --all-targets): the access-acl-only test module tickles a
# pre-existing clippy::needless_update in the SHARED `InterceptorConfig { acl: ..,
# ..Default::default() }` fixture pattern (the downsampling/low_pass fields are
# cfg-elided when only access-acl is on, so the spread is redundant) — an issue of
# the an_acl_* test fixtures, not config.rs; the default C1 runs the richer access-*
# set where the spread is needed.
layer_c1ao_cargo_test_config_mutate_runtime() {
    _runci_guarded_test "C1AO wzconfig_ 4" 4 \
        cargo test -p wz-runtime-tokio --features config-mutate-runtime,access-acl --lib wzconfig_ --quiet || return 1
    _runci_guarded_test "C1AO to_admin_json 3" 3 \
        cargo test -p wz-runtime-tokio --features config-mutate-runtime,access-acl --lib to_admin_json --quiet || return 1
    _runci_guarded_test "C1AO to_admin_json 4" 4 \
        cargo test -p wz-runtime-tokio --features config-mutate-runtime,access-acl,access-downsampling,access-quota --lib to_admin_json --quiet || return 1
    _runci_guarded_test "C1AO wzconfig_reconfigure_is_inert 1" 1 \
        cargo test -p wz-runtime-tokio --features access-acl --lib wzconfig_reconfigure_is_inert --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --features config-mutate-runtime,access-acl --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features transport-unicast --quiet -- -D warnings)
}

# ─── Layer C1ap — ext-pubsub-serde-codec §5.25: Zenoh Serialization Format codec ─
#
# R311y68: ext-pubsub-serde-codec is off-default (an opt-in atom), so the default
# Layer C1 (`cargo test --workspace`) never compiles the `serde_codec` module —
# this lane is the only run-site for the codec. It runs the golden-vector +
# round-trip unit tests under the feature (byte-exact vs zenoh-ext
# serialization.rs:653-673) and clippy-gates BOTH the owning crate
# (wz-session-core::serde_codec) AND the facade forward (wz-runtime-tokio's
# re-export at crate::serde_codec), proving the 3-stage feature chain composes.
layer_c1ap_cargo_test_ext_pubsub_serde() {
    _runci_guarded_test "C1ap serde_codec" 6 \
        cargo test -p wz-session-core --features ext-pubsub-serde-codec --lib serde_codec --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-session-core --all-targets --features ext-pubsub-serde-codec --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --features ext-pubsub-serde-codec --quiet -- -D warnings \
        && cargo build -p wz --features ext-pubsub-serde-codec --quiet)
}

# ─── Layer C1aq — ext-pubsub advanced-publisher/cache §5.25: @adv ring + queryable ─
#
# R311y69: ext-pubsub-advanced-publisher (which pulls ext-pubsub-advanced-cache)
# is off-default, so the default Layer C1 never compiles the advanced_publisher /
# advanced_cache modules — this lane is their only run-site. It runs the
# selector-filter + answer_from_ring unit tests AND the WIRE-LEVEL composed e2e
# (a real loopback session.query through the declared cache queryable recovers
# the three published sequenced samples — the R311y66 composition standard, not
# a kernel-proxy), then clippy-gates the feature (incl the wz facade forward via
# wz-runtime-tokio). query-get supplies the loopback get; pubsub-allow-loop the
# loopback dispatch.
layer_c1aq_cargo_test_ext_pubsub_advanced() {
    _runci_guarded_test "C1aq advanced_" 16 \
        cargo test -p wz-runtime-tokio --features ext-pubsub-advanced-publisher,query-get,pubsub-allow-loop \
        --lib advanced_ --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features ext-pubsub-advanced-publisher,query-get,pubsub-allow-loop \
            --quiet -- -D warnings \
        && cargo build -p wz --features ext-pubsub-advanced-publisher --quiet \
        `# R311y443-review (REVIEWER 3, NIT 1) — the demo's advanced arm is` \
        `# clippy-gated HERE, not in Layer Z where R311y442 put it. That line` \
        `# sat AFTER Z's zenohd / pico presence guards, each of which returns` \
        `# 0, so on any box without the foreign binaries the only -D warnings` \
        `# gate on the demo's #[cfg(feature = "advanced")] code SKIPped green` \
        `# -- and R311y443 adds new code behind exactly that cfg. Hosted CI` \
        `# was covered (WZ_Z_REQUIRE arms the skip into a fail), so this was a` \
        `# LOCAL false green, which is the shape that reaches a push. Clippy` \
        `# needs no external binary, so it belongs in a lane that never skips.` \
        && cargo clippy -p wz-ap-demo --all-targets --features advanced \
            --quiet -- -D warnings)
}

# ─── Layer C1ar — ext-pubsub advanced-subscriber §5.25: per-source order/dedup ─
#
# R311y70: ext-pubsub-advanced-subscriber is off-default, so the default Layer C1
# never compiles advanced_subscriber — this lane is its only run-site. It runs the
# state-machine unit tests (synthetic source: 0,1,3+dup -> deliver 0,1,3 + ONE
# Miss(nb=1) + drop; distinct-sources independence), then clippy-gates the feature.
# R311y71 (session-review HIGH fix): this lane now CO-ENABLES ext-pubsub-advanced-
# publisher so the COMPOSED producer->consumer e2e runs — a REAL AdvancedPublisher
# feeds a REAL AdvancedSubscriber on one session (the two atoms are co-compiled +
# composed, not green-per-atom in isolation). pubsub-allow-loop supplies the loopback
# dispatch; inbound source_info decode rides pubsub-source-info (pulled by the
# features). The trailing `cargo build -p wz` validates the facade forward target.
layer_c1ar_cargo_test_ext_pubsub_advanced_sub() {
    _runci_guarded_test "C1ar advanced_subscriber" 3 \
        cargo test -p wz-runtime-tokio --features ext-pubsub-advanced-subscriber,ext-pubsub-advanced-publisher,pubsub-allow-loop \
        --lib advanced_subscriber --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features ext-pubsub-advanced-subscriber,ext-pubsub-advanced-publisher,pubsub-allow-loop \
            --quiet -- -D warnings \
        && cargo build -p wz --features ext-pubsub-advanced-subscriber --quiet)
}

# ─── Layer C1as — reply source_info (advanced-recovery producer seam) §5.25 ──
#
# R311y79 (session-review HIGH fix): reply-source-info is a brand-new off-default
# wz-session-core feature (R311y74-y78, the advanced-recovery reply source_info
# producer + decode seam) that NO default / C1e / C1f lane enables — so its 7
# wire-faithfulness tests (response_build emit + emit-order, query into_response +
# reply_keyed_sourced, reply dispatch_response + loopback surfacing) and the gated
# ON-branch codec (gated_reply_source_info / put_reply_source_info /
# loopback_put_source_info) were never run or compiled feature-on in CI — the
# exact recurring "feature-gated test needs a same-round lane or it is never-run"
# pattern. This lane co-enables the full surface (codec-response{,-final} +
# query-{queryable,reply,attachment,selector-parameters,reply-err} +
# pubsub-attachment for the compose-order test + reply-source-info), runs the lib
# suite, and clippy-gates the ON-branch. The subscriber-composed e2e + the
# ext-pubsub-advanced-recovery active flip stay deferred (they need the reorder
# buffer); this lane covers the producer seam NOW, not 3 rounds later.
layer_c1as_cargo_test_reply_source_info() {
    (cd crates \
        && cargo test -p wz-session-core \
            --features codec-response,codec-response-final,query-queryable,query-reply,query-attachment,query-selector-parameters,query-reply-err,pubsub-attachment,reply-source-info \
            --lib --quiet \
        && cargo clippy -p wz-session-core --all-targets \
            --features codec-response,codec-response-final,query-queryable,query-reply,query-attachment,query-selector-parameters,query-reply-err,pubsub-attachment,reply-source-info \
            --quiet -- -D warnings)
}

# ─── Layer C1be — query-value (Q_B/Q_E): the querier VALUE ext ────────────────
#
# R311y248: query-value is a brand-new off-default wz-session-core feature — the
# querier's attached VALUE ext (payload + encoding, id 0x03 ENC_ZBUF, the
# "Q_B / Q_E" wire codec slots).
#
# R311y318 — the header used to justify this lane with "No default / other lane
# enables it". FALSE since R311y250, which added query-value to
# wz-runtime-tokio's default: Layer C1's `cargo test --workspace` unifies it ON
# and runs the ON-branch. Flagged as R311y315 carry (d) and carried unpaid
# through y316/y317. (This correction's own first draft then claimed the lane
# runs `--no-default-features`. It does not — measured. Read the command, not
# the header; that is the whole lesson here.) What the lane still earns is
# NARROWER and real: `-p wz-session-core` with a PRECISE feature set, where
# Layer C1's `--workspace` unifies every member's features into session-core at
# once. A defect that needs query-value ON while some other atom is OFF is
# masked by that unification and fails here first. Its
# encode/decode SSOT (query_value_ext) unit tests + the builder -> dispatch ->
# QueryView surface test + the gated request_build / query.rs / query_sink.rs
# code would be never-run / never-compiled-on in CI (the recurring feature-gated-
# test pattern). This lane runs the lib suite + clippy-gates the ON-branch. (The
# layer3_request VALUE byte-parity vs pico runs in the integration lane, whose
# wz-session-core dev-dep enables query-value.)
layer_c1be_cargo_test_query_value() {
    (cd crates \
        && cargo test -p wz-session-core \
            --features codec-request,codec-response,alloc,query-value,query-queryable,query-attachment,query-source-info,query-selector-parameters,query-reply-err \
            --lib --quiet \
        && cargo clippy -p wz-session-core --all-targets \
            --features codec-request,codec-response,alloc,query-value,query-queryable,query-attachment,query-source-info,query-selector-parameters,query-reply-err \
            --quiet -- -D warnings)
}

# ─── Layer C1at — ext-pubsub-advanced-recovery §5.25: gap recovery (consumer) ─
#
# R311y82: ext-pubsub-advanced-recovery is the CONSUMER half of gap recovery —
# the advanced subscriber's reorder buffer + sample-driven `_sn`-range recovery
# GET. It is off-default and composes query-get + query-selector-parameters +
# wz-session-core/reply-source-info on top of ext-pubsub-advanced-subscriber, so
# no default / C1ar (recovery-OFF) / C1as (producer-seam) lane compiles the
# recovery path. This lane is its only run-site. It CO-ENABLES the PRODUCER
# answerer (ext-pubsub-advanced-publisher pulls -advanced-cache) + pubsub-allow-
# loop so the composed loopback recovery e2e runs: a real AdvancedCache holds the
# full stream, a recovering AdvancedSubscriber sees a synthetic live hole, issues
# the `_sn` GET, and the cache replies the missing sample WITH its source_info
# (reply-source-info, composed by the recovery gate) — proving the recovered
# sample came from the cache and re-keys/orders in place, plus the buffer/drain +
# flush-miss state-machine units. This is the subscriber-composed e2e the C1as
# header deferred "they need the reorder buffer"; it lands WITH the active flip.
# Then clippy-gates the recovery surface + validates the facade forward target.
layer_c1at_cargo_test_ext_pubsub_advanced_recovery() {
    _runci_guarded_test "C1at advanced_subscriber" 15 \
        cargo test -p wz-runtime-tokio --features ext-pubsub-advanced-recovery,ext-pubsub-advanced-publisher,pubsub-allow-loop \
        --lib advanced_subscriber --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features ext-pubsub-advanced-recovery,ext-pubsub-advanced-publisher,pubsub-allow-loop \
            --quiet -- -D warnings \
        && cargo build -p wz --features ext-pubsub-advanced-recovery --quiet)
}

# ─── Layer C1au — ext-pubsub-sample-miss-detection §5.25: heartbeat PRODUCER ─
#
# R311y85: ext-pubsub-sample-miss-detection is the heartbeat PRODUCER beacon (an
# AdvancedPublisher background task emitting `z_serialize::<u32>(last_sn)` on the
# @adv KE). Off-default and composing ext-pubsub-advanced-publisher + serde-codec,
# so no default / C1aq / C1at lane compiles the beacon. This lane CO-ENABLES the
# CONSUMER (ext-pubsub-advanced-recovery) + pubsub-allow-loop so the composed
# PRODUCER->CONSUMER e2e runs: a real producer's beacon drives a real late-joining
# subscriber's heartbeat recovery from the cache (a faithful in-loopback model of
# loss — the subscriber missed the pre-declaration puts), plus the beacon-
# faithfulness test (the emitted payload decodes to last_sn on the @adv KE). Then
# clippy-gates the producer surface + validates the facade forward target.
layer_c1au_cargo_test_ext_pubsub_sample_miss_detection() {
    _runci_guarded_test "C1au advanced_publisher" 10 \
        cargo test -p wz-runtime-tokio --features ext-pubsub-sample-miss-detection,ext-pubsub-advanced-recovery,pubsub-allow-loop \
        --lib advanced_publisher --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features ext-pubsub-sample-miss-detection,ext-pubsub-advanced-recovery,pubsub-allow-loop \
            --quiet -- -D warnings \
        && cargo build -p wz --features ext-pubsub-sample-miss-detection --quiet)
}

# ─── Layer C1av — ext-pubsub-advanced-history §5.25: startup history query ─
#
# R311y86: ext-pubsub-advanced-history is the startup `<ke>/@adv/**` history GET
# (a late joiner recovers the publishers' cached history on declare). Off-default
# and composing ext-pubsub-advanced-recovery (it reuses the reorder buffer +
# recovered-reply ordering), so no default / C1at lane compiles the history path.
# This lane CO-ENABLES ext-pubsub-advanced-publisher (-> the cache answerer) +
# pubsub-allow-loop so the composed late-joiner history e2e runs (cache holds
# 0,1,2 -> a history-enabled subscriber's declare GETs them -> the `history_pending`
# gate buffers, the terminal Final flushes oldest-first), plus the gating unit.
# Then clippy-gates the history surface + validates the facade forward target.
# R311y98 built the `_time` age filter + R311y100 detect_late_publishers (the
# liveliness path), so the full zenoh HistoryConfig surface runs here: the
# subscriber-side history_selector + max_age + late-publisher tests
# (--lib advanced_subscriber, which now also pulls liveliness-subscriber); the
# cache-side _time parser + filter tests run under C1aq (--lib advanced_).
#
# R311y592 25 -> 28: the TEARDOWN-CANCELLATION trio. They land on THIS lane and
# not on C1at because all three are `ext-pubsub-advanced-history`-gated — the
# startup history GET is the one GET that is reliably in flight at a chosen
# moment, so it is what the cancellation is measured through.
layer_c1av_cargo_test_ext_pubsub_advanced_history() {
    _runci_guarded_test "C1av advanced_subscriber" 28 \
        cargo test -p wz-runtime-tokio --features ext-pubsub-advanced-history,ext-pubsub-advanced-publisher,pubsub-allow-loop \
        --lib advanced_subscriber --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features ext-pubsub-advanced-history,ext-pubsub-advanced-publisher,pubsub-allow-loop \
            --quiet -- -D warnings \
        && cargo build -p wz --features ext-pubsub-advanced-history --quiet)
}

# ─── Layer C1aw — ext-pubsub-group-membership §5.25: group view + lease ─────
#
# R311y97: ext-pubsub-group-membership is the LAST §5.25 atom (zenoh-ext's group
# membership: a bincode-wire group view + per-member queryable, INDEPENDENT of
# the advanced-pubsub @adv family). Off-default + spanning two crates, so no
# default / C1aq..C1av lane compiles `group_membership` (core wire) or `group`
# (the live Group). This is their ONLY run-site (R311y99, 20th-trigger review:
# the atom shipped without a lane — its real-`bincode` faithfulness ORACLE was
# never run in CI). It runs: (1) the core bincode-1.3 wire oracle + decode-reject
# tests (the wire is pinned byte-for-byte to the real bincode crate); (2) the
# runtime Group tests incl. the two composed loopback e2e (Join propagation +
# the keepalive -> unknown-member-GET recovery, needing pubsub-allow-loop); then
# clippy-gates both crates' surface + validates the wz facade forward target.
layer_c1aw_cargo_test_ext_pubsub_group_membership() {
    _runci_guarded_test "C1aw group_membership" 6 \
        cargo test -p wz-session-core --features ext-pubsub-group-membership \
        --lib group_membership --quiet || return 1
    _runci_guarded_test "C1aw group" 6 \
        cargo test -p wz-runtime-tokio --features ext-pubsub-group-membership,pubsub-allow-loop \
        --lib group --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-session-core \
            --features ext-pubsub-group-membership --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features ext-pubsub-group-membership,pubsub-allow-loop \
            --quiet -- -D warnings \
        && cargo build -p wz --features ext-pubsub-group-membership --quiet \
        `# R311y445-review (REVIEWER 3, DEFECT 1) — the demo's` \
        `# --features group arm had NO -D warnings gate anywhere: Layer C2 is` \
        `# clippy --workspace at DEFAULT features, and the only place group` \
        `# reached wz-ap-demo was the Layer Z build, which sits past that lane's` \
        `# zenohd / pico presence guards and so does not even COMPILE it on a box` \
        `# without the foreign binaries. This is the same hole R311y443-review` \
        `# closed for --features advanced by moving its clippy into C1aq. Clippy` \
        `# needs no external binary, so it belongs in a lane that never skips.` \
        && cargo clippy -p wz-ap-demo --all-targets --features group \
            --quiet -- -D warnings)
}

# ─── Layer C1w — routing-accept: multi-peer accept_loop unit + clippy ─
#
# R311qa: the multi-peer `accept_loop` (the `routing-router` foundation) is gated
# on the off-default `routing-accept` feature, so the default Layer C1
# (`cargo test --workspace`) does NOT compile it — this lane restores the unit
# coverage, the same shape C1v uses for the off-default `transport-link-ws`:
#   1. runs the in-crate `accept_loop_holds_three_concurrent_peers` unit
#      (real 3-session handshake, peak == 3) under `--features routing-accept`;
#   2. clippy-gates the `routing-accept` cfg (`--all-targets`);
#   3. clippy-gates the LIB under `--no-default-features --features routing-accept`
#      to prove `accept_loop` composes standalone (routing-accept pulls only
#      transport-link-tcp + transport-unicast + futures-util, nothing else).
# The demo-binary multi-peer e2e is Layer E3 (separate, --features routing-router).
#
# R311y382: step 1's `--features routing-accept` keeps DEFAULTS on, so
# transport-link-udp (a default) is present and the udp-demux F2 discriminator
# `mesh_accept_loop_holds_two_udp_peers` (gated all(routing-accept,
# transport-link-udp)) already runs under `--lib accept_loop`. Step 1a re-runs it
# under an EXPLICIT `routing-accept,transport-link-udp` (independent of the
# default set, so a future `--no-default-features` edit to step 1 cannot silently
# cfg it out) with a `1 passed` count-guard that reddens on a silent 0-tests (the
# "proof that never runs" trap) — the C1al precedent for the off-default arm.
#
# Slice B (non-IP mesh): step 1b runs the ENABLEMENT discriminator
# `mesh_accept_loop_holds_two_unixsock_peers` (two unixsock clients held as
# ZID-keyed faces off one listener; RED pre-Slice-B, where every NonIp accept was
# rejected) under an EXPLICIT `routing-accept,transport-link-unixsock` with the
# same `1 passed` count-guard. transport-link-unixsock is OFF-default, so without
# this the test is cfg-compiled-OUT (the y380 trap). The added clippy step gates
# `--all-targets --features routing-accept,transport-link-unixsock`, which is the
# ONLY lane that compiles the `Step::Accepted` non-IP arm + the new tests.
#
# R311y404 (mesh-capable quic): step 1c runs the MESH-JOIN discriminator
# `mesh_accept_loop_holds_two_quic_peers` (two quic clients held as ZID-keyed faces
# off one endpoint; RED pre-y404, where quic's `supports_mesh_multi_peer == false`
# reject-throttled every accept) under an EXPLICIT `routing-accept,transport-link-quic`
# with the same `1 passed` count-guard. transport-link-quic is OFF-default, so
# without this the test is cfg-compiled-OUT (the y380 trap); the matching clippy step
# gates `--all-targets --features routing-accept,transport-link-quic`.
#
# R311y408 (mesh-capable quic-datagram): step 1d runs the MESH-JOIN discriminator
# `mesh_accept_loop_holds_two_quic_datagram_peers` (two quic-datagram clients held as
# ZID-keyed faces off one endpoint; RED if the QuicDatagram `supports_mesh_multi_peer`
# arm is reverted to `false`, which reject-throttles the second accept) under an
# EXPLICIT `routing-accept,transport-link-quic-datagram` with the same `1 passed`
# count-guard. transport-link-quic-datagram is OFF-default, so without this the test is
# cfg-compiled-OUT (the y380 trap); the matching clippy step gates `--all-targets
# --features routing-accept,transport-link-quic-datagram`. Step 1e RUNS the BIND-time
# pin `boundlistener_quic_datagram_is_mesh_capable` (same guard) so the once-only-
# compiled bind predicate `BoundListener::QuicDatagram => true` actually executes its
# assertion in CI (a wrong `false` reddens here, not just at a clippy compile).
#
# R311y409 (reliable-quic bind-pin RUN + C1w hosted): the quic slice gains the
# BIND-time pin step `boundlistener_quic_is_mesh_capable` (right after the quic accept
# unit), closing the sibling asymmetry y408 left — the datagram twin ran its bind-pin
# (step 1e above) but the reliable-quic bind predicate `BoundListener::Quic => true`
# executed in NO lane, only clippy-compiled. RED+TWIN by falsification: flip that arm
# to `false` and ONLY this new step reddens (the quic accept unit consults the
# `AcceptedLink` RUNTIME twin, not the BoundListener bind predicate, so it stays green
# — the same isolation the datagram pair has). Same `1 passed` count-guard. R311y409
# ALSO hosts this whole C1w lane on ci.yml's feature-gates job (it ran only in a local
# full sweep before — the "gate that never runs hosted reports success by silence"
# hazard, the exact reason that job exists), so both quic + datagram bind-pins and
# C1w's mesh accept units are now continuously enforced, not decorative (the unixpipe
# mesh unit lives in the still-local-only C1al, out of y409 scope).
layer_c1w_cargo_test_routing_accept() {
    (cd crates \
        && cargo test -p wz-runtime-tokio --features routing-accept --lib accept_loop --quiet \
        && cargo test -p wz-runtime-tokio --features routing-accept,transport-link-udp --lib mesh_accept_loop_holds_two_udp_peers --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo test -p wz-runtime-tokio --features routing-accept,transport-link-unixsock --lib mesh_accept_loop_holds_two_unixsock_peers --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo test -p wz-runtime-tokio --features routing-accept,transport-link-quic --lib mesh_accept_loop_holds_two_quic_peers --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo test -p wz-runtime-tokio --features routing-accept,transport-link-quic --lib boundlistener_quic_is_mesh_capable --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo test -p wz-runtime-tokio --features routing-accept,transport-link-quic-datagram --lib mesh_accept_loop_holds_two_quic_datagram_peers --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo test -p wz-runtime-tokio --features routing-accept,transport-link-quic-datagram --lib boundlistener_quic_datagram_is_mesh_capable --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-accept --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-accept,transport-link-unixsock --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-accept,transport-link-quic --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-accept,transport-link-quic-datagram --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features routing-accept --quiet -- -D warnings)
}

# ─── Layer C1bl — the mesh router admits a multi-client unixpipe --listen (R311y392) ─
#
# The demo-binary twin of C1w's library backstop. R311y390 added a BIND-time
# reject to the demo mesh router (`run_router` -> its testable inner
# `run_router_until`) for a NON-mesh-capable `--listen`; R311y392 made the
# unixpipe acceptor multi-client, so `BoundListener::supports_mesh_multi_peer`
# flipped `true` and the router now ADMITS a `--listen unixpipe/..` (binds + enters
# the accept loop). This lane's discriminator flipped with it: it now witnesses the
# router returns `Ok` for a unixpipe listen (RED if the guard's verdict is reverted
# to `false`). The bind-time guard stays as defensive code for a future non-mesh
# acceptor.
#
# `routing-router` AND `transport-link-unixpipe` are BOTH off-default (a DOUBLE
# gate). Without transport-link-unixpipe the `unixpipe/` scheme STILL PARSES (the
# locator leaf is ungated in wz-session-core), but `bind_locator` returns a
# feature-gated `Unsupported` at BIND because the accept backend is not compiled,
# so `bind_endpoint("unixpipe/..").await?` errors BEFORE the mesh-capability guard
# (the guard is dead code without the feature). Layer E3/Z also compile
# `run_router_until`'s body under `routing-router` (redundant compile coverage),
# but ONLY this lane compiles the `caller_failfast_tests` module (it needs
# transport-link-unixpipe + a test target) AND reaches a real
# `BoundListener::Unixpipe` — the BEHAVIORAL proof (removing/inverting the guard
# reddens this lane's discriminator; E3/Z stay green). Step 1 runs the
# discriminator under an EXPLICIT `routing-router,transport-link-unixpipe` with a
# `1 passed` count-guard that reddens on a silent 0-tests (the y380
# proof-that-never-runs trap). Step 2 clippy-gates the same combo `--all-targets`
# (the sole lane compiling the `caller_failfast_tests` module).
#
# R311y405 — steps 3+4 are the quic twin: the `--router quic/` cert-threading
# discriminator `run_router_admits_a_quic_listen_with_cert_at_bind` (the router now
# ADMITS a `quic/...` --listen once `--quic-cert`/`--quic-key` are threaded; RED if
# `run_router_until` reverts to the cert-free `bind_endpoint`) under an EXPLICIT
# `routing-router,quic` with the same `1 passed` count-guard, plus its clippy gate
# (the sole lane compiling `router_quic_cert_tests`, which needs the `quic` feature
# + the test-support tls-fixtures dev-dep for the self-signed cert).
#
# R311y406 — the same cert-threading extended to the other two mesh callers:
# `run_peer_admits_a_quic_listen_with_cert_at_bind` (routing-peer,quic) and
# `run_router_hat_admits_a_quic_listen_with_cert_at_bind` (router-hat-router,quic),
# each a guarded test + clippy gate. (The pico `z_open(listen=quic/)` cert twin is
# Layer C1bm's `quic_listen_cert`.)
#
# R311y413 — HOSTED on ci.yml's feature-gates job. Its 4 admit discriminators
# already carry anchored `^test result: ok\. 1 passed` count-guards (no run-ci
# change), so hosting converts an already-falsification-proven lane from local-only
# to continuously enforced.
layer_c1bl_cargo_test_router_failfast() {
    (cd crates \
        && cargo test -p wz-ap-demo --features routing-router,transport-link-unixpipe run_router_accepts_a_unixpipe_listen_at_bind --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo clippy -p wz-ap-demo --all-targets --features routing-router,transport-link-unixpipe --quiet -- -D warnings \
        && cargo test -p wz-ap-demo --features routing-router,quic run_router_admits_a_quic_listen_with_cert_at_bind --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo clippy -p wz-ap-demo --all-targets --features routing-router,quic --quiet -- -D warnings \
        && cargo test -p wz-ap-demo --features routing-peer,quic run_peer_admits_a_quic_listen_with_cert_at_bind --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo clippy -p wz-ap-demo --all-targets --features routing-peer,quic --quiet -- -D warnings \
        && cargo test -p wz-ap-demo --features router-hat-router,quic run_router_hat_admits_a_quic_listen_with_cert_at_bind --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo clippy -p wz-ap-demo --all-targets --features router-hat-router,quic --quiet -- -D warnings)
}

# ─── Layer C1bm — pico admits a multi-client unixpipe listen (R311y392) ─────
#
# The pico twin of C1bl. R311y391 made pico's `z_open(listen=unixpipe/..)` REJECT
# at bind (a single-connection acceptor cannot feed the mesh loop); R311y392 made
# the acceptor multi-client, so `BoundListener::supports_mesh_multi_peer` flipped
# `true` and `drive_listen`'s guard no longer rejects -> z_open returns Z_OK, a
# listening pico session over unixpipe. This lane's discriminator flipped with it
# (now asserts Z_OK; RED if the guard's verdict is reverted).
# `transport-link-unixpipe` is a SUPERSET feature (not a zenoh-pico-native link --
# real pico has no unixpipe; the north star is a composable superset of zenoh-full
# + zenoh-pico), off-default: without it the `unixpipe/` scheme still parses but
# bind_locator returns a feature-gated Unsupported at bind. This is the ONLY lane
# compiling the unixpipe_listen_multiclient discriminator + reaching a real
# BoundListener::Unixpipe through the pico C ABI. Step 1 runs it under an EXPLICIT
# transport-link-unixpipe with a `1 passed` count-guard that reddens on a silent
# 0-tests (the y380 proof-that-never-runs trap); step 2 clippy-gates the same
# feature `--all-targets`. R311y406 — steps 3+4 are the pico quic-listen cert twin:
# `quic_listen_cert` (z_open(listen=quic/) + the native Z_CONFIG_TLS_LISTEN_* cert keys
# binds) under transport-link-quic with the same `1 passed` guard + clippy gate.
#
# R311y413 — HOSTED on ci.yml's feature-gates job. Both discriminators already carry
# anchored `^test result: ok\. 1 passed` count-guards (no run-ci change), so hosting
# converts an already-falsification-proven lane from local-only to enforced.
layer_c1bm_cargo_test_pico_failfast() {
    (cd crates \
        && cargo test -p wz-capi-pico --features transport-link-unixpipe --test unixpipe_listen_multiclient --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo clippy -p wz-capi-pico --all-targets --features transport-link-unixpipe --quiet -- -D warnings \
        && cargo test -p wz-capi-pico --features transport-link-quic --test quic_listen_cert --quiet 2>&1 | grep -qE '^test result: ok\. 1 passed' \
        && cargo clippy -p wz-capi-pico --all-targets --features transport-link-quic --quiet -- -D warnings)
}

# ─── Layer C1x — routing-routes: forwarding kernel + forwarder unit + clippy ─
#
# R311qc: the data-plane forwarding atom (`routing::RouteTable` kernel +
# `routing_forward::RoutingForwarder`) is gated on the off-default
# `routing-routes` feature, so the default Layer C1 does NOT compile it — this
# lane restores its coverage, mirroring C1w for `routing-accept`:
#   1. clippy-gates the GENERIC kernel in wz-session-core (it compiles + lints
#      for the generic `<R, T>`). The kernel's BEHAVIOR is exercised in step 2,
#      not here: its forward path needs a concrete `SessionLinkActions`, which
#      only the tokio profile constructs (the test-support dev-dep-cycle keeps
#      actions tokio-side, see feedback-test-support-dev-dep-cycle), so the
#      kernel is tested transitively through the Tokio monomorphization.
#   2. runs the forwarder unit suite (forward / no-match / fan-out / src-skip /
#      undeclare / face-leave / wildcard / cross-talk / best-effort / Del, plus
#      R311qd aliased: drop-without-mapping / resolve-after-declare /
#      re-literalize / per-push-suffix concat / undeclare-keyexpr) under
#      `--features routing-routes`;
#   3. clippy-gates the `routing-routes` cfg (`--all-targets`);
#   4. clippy-gates the LIB under `--no-default-features --features routing-routes`
#      to prove the forwarder composes standalone (routing-routes pulls
#      routing-accept + the kernel + codec-push + declare-subscriber).
# The demo-binary forwarding e2e is Layer E5 (separate, --features routing-routes).
# R311y224: the `routing-routes,transport-qos` arm additionally RUNS the switchboard
# band-preservation test (forward_push_preserves_the_received_band_on_transit,
# `#[cfg(feature="transport-qos")]`-gated) + clippy-gates the transport-qos cfg — the
# switchboard twin of the router/linkstate transit band lanes (RouteTable::forward_push
# now routes through send_network_message_qos on the received FramePayload.priority).
layer_c1x_cargo_test_routing_routes() {
    _runci_guarded_test "C1X routing_forward 24" 24 \
        cargo test -p wz-runtime-tokio --features routing-routes --lib routing_forward --quiet || return 1
    _runci_guarded_test "C1X routing_forward 25" 25 \
        cargo test -p wz-runtime-tokio --features routing-routes,transport-qos --lib routing_forward --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-session-core --features routing-routes --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-routes --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-routes,transport-qos --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features routing-routes --quiet -- -D warnings)
}

# ─── Layer C1y — routing-peer: dial+accept mesh-node unit + clippy ──
#
# R311qg: the peer-mesh `peer_loop` (the `routing-peer` foundation = dial a
# configured peer set AND accept inbound) is gated on the off-default
# `routing-peer` feature, so the default Layer C1 does NOT compile it — this lane
# restores its coverage, the same shape C1w uses for `routing-accept`:
#   1. runs the `accept_loop` lib units under `--features routing-peer` (the 4
#      accept-and-hold units + the 2 new peer_loop dial+accept units);
#   1b. R311qv/qw: runs the linkstate-peer routing tests — the topology-graph
#      kernel crate `wz-routing-graph` (lifted out in R311qw) AND the
#      `linkstate_forward` driver units in this crate (the `--lib linkstate`
#      filter), which the `accept_loop` filter had silently excluded;
#   2. clippy-gates `wz-routing-graph` + the `routing-peer` cfg (`--all-targets`);
#   3. clippy-gates the LIB under `--no-default-features --features routing-peer`
#      to prove `peer_loop` composes standalone (routing-peer pulls only
#      routing-accept);
#   4. clippy-gates the demo `run_peer` cfg site (`--features routing-peer`).
#   5. §5.16 access knobs: routing-peer ALONE (steps 1-4) proves the interceptor
#      chain ELIDES to nothing (access control disabled) — the seam compiles and
#      the access tests vanish. The combo run then enables all three
#      (access-acl / access-downsampling / access-quota) so the enforcers + their
#      unit tests (interceptor::*) and the linkstate access tests actually
#      compile, lint, and RUN; and each knob is clippy-gated standalone
#      (--no-default-features --features access-X, each implies routing-peer) to
#      prove independent composition.
#   6. §5.16 extauth (R311wy): the wz-session-core auth atoms — the Z_EXT_AUTH
#      codec (extauth), the dispatch kernel (auth_dispatch), and the usrpwd
#      method (extauth_usrpwd) — are TESTED under `access-extauth-usrpwd` and
#      clippy-gated both there and codec-only (`--no-default-features --features
#      session-extauth`). Without this the auth unit tests ran in NO lane
#      (preset-ap-full carries the features but is build-only — still true of the
#      LIBRARY build C4 does; R311y480's Layer E9 adds a preset-ap-full BINARY
#      driven against pico, which exercises composition but runs no unit test).
#   7. §5.16 usrpwd LIVE wiring (R3b): the wz<->wz usrpwd handshake e2e
#      (`usrpwd_handshake_e2e`) drives a real initiator<->responder handshake
#      over the encode/parse/dispatch path (matching creds -> Established;
#      bad password -> AuthRejected/Closing), and the wz-runtime-tokio
#      all-targets clippy gate covers the now-active AP-layer wiring
#      (nonce_from_os_entropy + OpenError::AuthRejected + the drive-loop reject
#      arm) that the R3b feature-graph fix made compile (access-extauth-usrpwd
#      now implies the LOCAL session-extauth).
#   8. §5.16 pubkey (R4b): the PubKeyMethod (mutual RSA challenge-response, the
#      wz mirror of zenoh pubkey.rs; AP-only since `rsa` needs std) -- the
#      extauth_pubkey kernel tests + the wz<->wz real-TCP both-seams e2e
#      (pubkey_handshake_e2e) + the all-targets clippy gate under
#      access-extauth-pubkey. Plugs into the SAME dispatch + open seams as
#      usrpwd; the accept seam injects pubkey's challenge nonce.
# The demo-binary mesh e2e is Layer E6 (separate, --features routing-peer).
#
# R311y428 — the nine FILTERED / TARGET-SCOPED runs are guarded at their measured
# counts, as the precondition for hosting this lane. `cargo test <filter>` exits 0
# when the filter selects NOTHING, so a renamed module, a dropped `#[ignore]` or a
# cfg-gate slip would have kept every one of them green. The whole-crate
# `-p wz-routing-graph` run stays BARE, per the convention that an unfiltered
# whole-crate run has no meaningful count to pin.
layer_c1y_cargo_test_routing_peer() {
    local access="routing-peer,access-acl,access-downsampling,access-quota"
    _runci_guarded_test "C1y accept_loop" 11 \
        cargo test -p wz-runtime-tokio --features routing-peer --lib accept_loop --quiet || return 1
    # R311y509 — 200 -> 202: the peer's two liveliness-TOKEN tier tests. They land
    # in BOTH linkstate pins because the plane is ungated, so it compiles under bare
    # `routing-peer` as well as the access set below. Two pins for one plane is not
    # redundancy: this one proves the tests are not silently access-feature-gated.
    _runci_guarded_test "C1y linkstate" 202 \
        cargo test -p wz-runtime-tokio --features routing-peer --lib linkstate --quiet || return 1
    # R311y513 — the BARE routing peer, and the pin that would have caught the
    # defect this round fixed. Every arm above passes `--features routing-peer`
    # WITHOUT `--no-default-features`, so what they actually measure is
    # "default + routing-peer" — and the default set carries the declare-*
    # origination features. A deploy that builds a routing-only node does NOT,
    # and on that build the send seam routed every Declare a linkstate forwarder
    # originated to its no-emit catch arm: 50 of the tests below failed, for
    # months, in a configuration no lane ran. A lane named for a feature must
    # compile that feature ALONE at least once, or it is measuring the default
    # set and reporting the feature's name. 200 not 202: two access-tier tests
    # need the access set, which bare routing-peer does not pull.
    _runci_guarded_test "C1y linkstate bare" 200 \
        cargo test -p wz-runtime-tokio --no-default-features --features routing-peer \
        --lib linkstate --quiet || return 1
    # R311y451 — 10 -> 16: the six low-pass fidelity tests (attachment in the
    # budget, checked-add overflow, minimum-across-overlapping-rules, the
    # `messages` selector, the `flows` selector + no-interceptor-on-an-ungoverned-
    # flow, and the per-kind classification bound to real built messages).
    # R311y452 — 16 -> 21: the five DOWNSAMPLING fidelity tests (its own `messages`
    # selector, its own `flows` selector + the no-interceptor-on-an-ungoverned-flow
    # twin, the Hz->interval mapping, the `freq == 0.0` drop-all that drops even the
    # FIRST message, and the body-level kind classification bound to real built
    # messages).
    # R311y453 — 21 -> 23: the two SUBJECT-axis tests (a rule narrowed by
    # link_protocols governs only a face speaking one of them, including the
    # fail-closed arm for a face whose protocol is indeterminate; and a rule
    # narrowed by interfaces, which separates RESOLVED-to-a-different-NIC and
    # RESOLVED-to-no-NIC — both definite non-matches — from COULD-NOT-DETERMINE,
    # which is fail-closed and governed). Like C1ah's `node_clock::` pin this is a
    # COUNT, not a SET: it catches a test that stops being selected, not a test
    # renamed into still-23.
    # R311y457 — 23 -> 28: the five fail-OPEN-close tests. Two are the
    # discriminators (an undeclared expr-id is denied; the empty-wireexpr timeout
    # Err is denied) — they are the only two that red when `intercept`'s
    # unresolvable-keyexpr branch is put back to `return true`. The other three
    # bound what the deny means: the SAME alias admits once declared, a declared
    # alias resolving into `admin/**` is denied by the RULE (so resolution really
    # feeds the policy), and a `ResponseFinal` admits at the ACTION arm rather
    # than the keyexpr one (which is what makes folding it into the governed
    # `Response` arm red here first).
    # R311y458 — 28 -> 34: the six tests for the governed kinds this round added.
    # Four are the discriminators, each falsified by its own damage: removing the
    # undeclare / token arms reds four of them; dropping the INGRESS-only
    # condition on the undeclare admit reds only the egress one; swapping the two
    # Interest mode arms, or ignoring the body's TOKENS bit, reds only the mode
    # one. The undeclare pair also proves the enforcer reads the OPTIONAL
    # ext_wire_expr, which is the only place an undeclare's keyexpr lives.
    # R311y508 — 34 -> 36: the interceptor CACHE contract's two tests. One walks
    # six message shapes asserting the cached verdict EQUALS the direct one,
    # including the branches that do not factor through (face, keyexpr) -- an
    # ungoverned kind and an undeclared alias -- which is where a cache is easy to
    # get wrong; the other pins that a subject-less face caches nothing. Neither
    # needs the hotreload feature: they exercise the trait pair directly, so this
    # lane's feature set is unchanged.
    _runci_guarded_test "C1y interceptor" 36 \
        cargo test -p wz-runtime-tokio --features "$access" --lib interceptor --quiet || return 1
    # R311y509 — 211 -> 213: the peer's CURRENT liveliness-TOKEN dump, in its two
    # tiers. Each test is bound by a damage that reds it ALONE: disabling the client
    # ingest or the dump arm reds the client-leaf test, and disabling the mesh
    # ingest reds only the mesh-sourced one. So the pair cannot rot as a unit, and
    # a count that moves names which tier moved.
    _runci_guarded_test "C1y linkstate+access" 213 \
        cargo test -p wz-runtime-tokio --features "$access" --lib linkstate --quiet || return 1
    _runci_guarded_test "C1y extauth" 10 \
        cargo test -p wz-session-core --features access-extauth-usrpwd --lib extauth --quiet || return 1
    _runci_guarded_test "C1y auth_dispatch" 4 \
        cargo test -p wz-session-core --features access-extauth-usrpwd --lib auth_dispatch --quiet || return 1
    _runci_guarded_test "C1y usrpwd e2e" 3 \
        cargo test -p wz-runtime-tokio --features access-extauth-usrpwd \
        --test usrpwd_handshake_e2e --quiet || return 1
    # R311y581 — 7 -> 11: R311y576 added the four initiator-gate tests and left
    # the guard behind, and this lane has been RED on hosted CI ever since
    # (`5a8ad35b`, `e8af0d92`, and again on `0a0cf608` once R311y580's C1w fix
    # stopped masking it). DERIVED from `--list` under this exact feature set:
    # all 11 are `extauth_pubkey::tests::`, so the filter did not widen.
    _runci_guarded_test "C1y extauth_pubkey" 11 \
        cargo test -p wz-runtime-tokio --features access-extauth-pubkey --lib extauth_pubkey --quiet || return 1
    _runci_guarded_test "C1y pubkey e2e" 1 \
        cargo test -p wz-runtime-tokio --features access-extauth-pubkey \
        --test pubkey_handshake_e2e --quiet || return 1
    (cd crates \
        && cargo test -p wz-routing-graph --quiet \
        && cargo clippy -p wz-routing-graph --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-peer --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features routing-peer --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features routing-peer --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features routing-peer,adminspace-write --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features "$access" --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features access-acl --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features access-downsampling --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features access-quota --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --all-targets --features access-extauth-usrpwd --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features session-extauth --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features access-extauth-usrpwd --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features access-extauth-pubkey --quiet -- -D warnings)
}

# ─── Layer C1z — storage driver: backend/history/replication/aligner ─
#
# R311wl: the storage DRIVER stack — the StorageService capture+answer
# queryable, the History::All backend, the digest publisher/subscriber, and the
# aligner answer queryable + ASK pull loop + on_diff->pull wiring — is gated on
# the off-default storage-* features, so the default Layer C1
# (`cargo test --workspace`) does NOT compile it: storage was UNCOVERED in CI
# before this lane. storage-aligner is the maximal replication-side feature (it
# implies storage-replication -> storage-backend), so two configs exercise every
# storage driver module:
#   0. R311y55 — the wz-session-core storage KERNEL modules (storage_backend /
#      storage_state / storage_volume) are gated on `storage-backend` (off-default),
#      so `cargo test --workspace` never compiled their unit tests either; this lane
#      now runs `-p wz-session-core --features storage-backend --lib storage` to
#      cover them — the §5.24 Volume/Capability/MemoryVolume (storage_volume) AND
#      the previously-uncovered storage_backend/storage_state kernel tests.
#      R311y57 — a SECOND wz-session-core line runs `--features
#      storage-mgr-multi-storage-host --lib storage` (the storage_manager module is
#      gated on that feature, NOT storage-backend, so the line above does not
#      compile it) + clippy + a `wz` facade build, covering the cfg-ACTIVE manager.
#      R311y58 — likewise a `--features storage-mgr-strip-prefix --lib
#      storage_strip_prefix` line (+ clippy + facade) covers the cfg-ACTIVE
#      strip_prefix/restore key transforms (gated on their own feature). R311y59 —
#      a `--features storage-mgr-complete-flag --lib storage_service` line (+ clippy
#      + facade) covers the config-driven queryable COMPLETE gate ON; its OFF arm
#      rides the storage-aligner / storage-history `--lib storage` lines below.
#      R311y61 — the §5.24 COMPOSITION round: a
#      `--features storage-backend,storage-mgr-strip-prefix --lib storage` line
#      (+ clippy) covers the storage_state strip wiring (the new `mod strip` tests,
#      under BOTH features — strip alone composes only alloc and does not compile
#      storage_state), and a
#      `--features storage-backend,storage-mgr-strip-prefix,declare-subscriber,pubsub-allow-loop --lib storage_service`
#      line (+ clippy) runs the live composition e2e
#      (`strip_configured_storage_captures_stripped_and_restores_on_query`): a
#      Volume-created backend + a strip-configured StorageConfig drive a live
#      StorageService end to end. Both close never-run gaps the existing combos
#      missed (the e2e needs strip + declare-subscriber + pubsub-allow-loop, which
#      no prior storage lane enabled together). R311y62 — the runtime-side
#      storage MANAGER (storage_manager_service): a
#      `--features storage-mgr-multi-storage-host,declare-subscriber,pubsub-allow-loop,storage-mgr-strip-prefix --lib storage_manager_service`
#      line (+ clippy) runs the RuntimeStorageManager tests incl the
#      hosts-N-strip-storages e2e, and a bare
#      `clippy --features storage-mgr-multi-storage-host` line proves the
#      cfg(not(strip)) arm + the module compile standalone (the feature now
#      also pulls the runtime storage-backend driver). The kernel
#      create_backend rides the storage-mgr-multi-storage-host `--lib storage`
#      line above;
#      R311wt slice 2 — a `--features storage-mgr-wildcard-updates --lib storage`
#      line (+ clippy + facade build) covers the write-path wildcard override
#      engine (the `storage_state::tests::wildcard` mod: materialize + the
#      resurrection guard + the named empty-put divergence), and a
#      `storage-mgr-wildcard-updates,storage-mgr-strip-prefix` line covers the
#      full-key-register / stored-key-write strip composition (the wildcard::strip
#      sub-mod). The atom pulls the keyexpr wildcard matcher, NOT storage-aligner.
#      R311wt slice 3 — a `--features storage-aligner,storage-mgr-wildcard-updates
#      --lib storage` line (+ clippy) covers the align-receive path applying a
#      wildcard from a peer (the `aligner::wildcard_align` mod: WildcardDelete in
#      the metadata round, WildcardPut deferred to Retrieval, initial-All Retrieval
#      WildcardDelete, idempotence, and the named tlnwu-resurrection divergence).
#      This is the storage-aligner ∩ storage-mgr-wildcard-updates intersection —
#      the ONLY lane that compiles+runs wildcard_align (neither is default); the
#      existing `--features storage-aligner` lines are the wildcard-OFF combo
#      proving the align arms skip byte-identically.
#      R311wt slice 4 — a `--features storage-mgr-garbage-collection --lib storage`
#      kernel line (+ clippy) covers `collect_garbage` (the `wildcard::gc` mod:
#      the age sweep, the `>=` boundary, the saturating-sub unset-clock guard, and
#      the end-to-end registry-shrink), and a `-p wz-runtime-tokio
#      --features storage-mgr-garbage-collection --lib storage_gc_service` line
#      (+ clippy) covers the periodic `GarbageCollector` driver (a spawned sweep +
#      the RAII abort-on-drop), then a `cargo build -p wz` facade build. The GC
#      feature transitively pulls storage-mgr-wildcard-updates (the sweep touches
#      those registries), so a single-feature line proves the dep implication; no
#      strip combo (GC writes no stored keys) and no declare-subscriber (it
#      declares nothing).
#   1. runs the storage_* lib tests (storage_service / storage_replication_service
#      / storage_aligner_service) under `--features storage-aligner`, and the
#      History::All tests under `--features storage-history`;
#   2. clippy-gates both cfgs (`--all-targets`);
#   3. clippy-gates the LIB under `--no-default-features --features storage-aligner`
#      to prove the storage driver composes standalone (storage-aligner pulls its
#      full set: storage-replication + query-{queryable,consolidation,timeout,
#      attachment} + pubsub-{attachment,encoding,timestamp} + transport-unicast);
#   4. builds the wz facade under `--features storage-aligner` AND
#      `--features storage-history` (R311wp/A9) so BOTH storage facade forwards
#      stay wired: storage-aligner covers backend+replication+aligner (it
#      implies them), but storage-history is ORTHOGONAL (replication runs on a
#      Latest store, so storage-aligner does NOT imply it), so its
#      `wz-runtime-tokio?/storage-history` forward needs its own facade build.
# A11 (R311wn): the live two-replica digest->aligner convergence e2e
# (`--test storage_aligner_convergence_e2e`) is now run here — the ONE place the
# full path executes over a real link (the digest subscriber + aligner queryable
# are Locality::Remote, so no single-session loopback can drive them). `--lib`
# excludes integration tests, so the e2e needs its own `--test` invocation.
layer_c1z_cargo_test_storage_driver() {
    _runci_guarded_test "C1z storage" 27 \
        cargo test -p wz-session-core --features storage-backend --lib storage --quiet || return 1
    _runci_guarded_test "C1z storage" 35 \
        cargo test -p wz-session-core --features storage-mgr-multi-storage-host --lib storage --quiet || return 1
    _runci_guarded_test "C1z storage_manager_service" 5 \
        cargo test -p wz-runtime-tokio --features storage-mgr-multi-storage-host,declare-subscriber,pubsub-allow-loop,storage-mgr-strip-prefix --lib storage_manager_service --quiet || return 1
    _runci_guarded_test "C1z storage_strip_prefix" 6 \
        cargo test -p wz-session-core --features storage-mgr-strip-prefix --lib storage_strip_prefix --quiet || return 1
    _runci_guarded_test "C1z storage" 40 \
        cargo test -p wz-session-core --features storage-backend,storage-mgr-strip-prefix --lib storage --quiet || return 1
    _runci_guarded_test "C1z storage" 50 \
        cargo test -p wz-session-core --features storage-history,storage-mgr-strip-prefix --lib storage --quiet || return 1
    _runci_guarded_test "C1z storage" 39 \
        cargo test -p wz-session-core --features storage-mgr-wildcard-updates --lib storage --quiet || return 1
    _runci_guarded_test "C1z storage" 53 \
        cargo test -p wz-session-core --features storage-mgr-wildcard-updates,storage-mgr-strip-prefix --lib storage --quiet || return 1
    _runci_guarded_test "C1z storage" 127 \
        cargo test -p wz-session-core --features storage-aligner,storage-mgr-wildcard-updates --lib storage --quiet || return 1
    _runci_guarded_test "C1z storage_service" 9 \
        cargo test -p wz-runtime-tokio --features storage-mgr-complete-flag --lib storage_service --quiet || return 1
    _runci_guarded_test "C1z storage_service" 10 \
        cargo test -p wz-runtime-tokio --features storage-backend,storage-mgr-strip-prefix,declare-subscriber,pubsub-allow-loop --lib storage_service --quiet || return 1
    _runci_guarded_test "C1z storage" 46 \
        cargo test -p wz-session-core --features storage-mgr-garbage-collection --lib storage --quiet || return 1
    _runci_guarded_test "C1z storage_gc_service" 3 \
        cargo test -p wz-runtime-tokio --features storage-mgr-garbage-collection --lib storage_gc_service --quiet || return 1
    _runci_guarded_test "C1z storage" 38 \
        cargo test -p wz-runtime-tokio --features storage-aligner --lib storage --quiet || return 1
    _runci_guarded_test "C1z storage_aligner_convergence_e2e" 1 \
        cargo test -p wz-runtime-tokio --features storage-aligner --test storage_aligner_convergence_e2e --quiet || return 1
    _runci_guarded_test "C1z storage" 11 \
        cargo test -p wz-runtime-tokio --features storage-history --lib storage --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-session-core --features storage-mgr-multi-storage-host --all-targets --quiet -- -D warnings \
        && cargo build -p wz --features storage-mgr-multi-storage-host --quiet \
        && cargo clippy -p wz-runtime-tokio --features storage-mgr-multi-storage-host,declare-subscriber,pubsub-allow-loop,storage-mgr-strip-prefix --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --features storage-mgr-multi-storage-host --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --features storage-mgr-strip-prefix --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --features storage-backend,storage-mgr-strip-prefix --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --features storage-history,storage-mgr-strip-prefix --all-targets --quiet -- -D warnings \
        && cargo build -p wz --features storage-mgr-strip-prefix --quiet \
        && cargo clippy -p wz-session-core --features storage-mgr-wildcard-updates --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --features storage-mgr-wildcard-updates,storage-mgr-strip-prefix --all-targets --quiet -- -D warnings \
        && cargo build -p wz --features storage-mgr-wildcard-updates --quiet \
        && cargo clippy -p wz-session-core --features storage-aligner,storage-mgr-wildcard-updates --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --features storage-mgr-complete-flag --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --features storage-backend,storage-mgr-strip-prefix,declare-subscriber,pubsub-allow-loop --all-targets --quiet -- -D warnings \
        && cargo build -p wz --features storage-mgr-complete-flag --quiet \
        && cargo clippy -p wz-session-core --features storage-mgr-garbage-collection --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --features storage-mgr-garbage-collection --all-targets --quiet -- -D warnings \
        && cargo build -p wz --features storage-mgr-garbage-collection --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features storage-aligner --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features storage-history --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features storage-aligner --quiet -- -D warnings \
        && cargo build -p wz --features storage-aligner --quiet \
        && cargo build -p wz --features storage-history --quiet)
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
# projection wire-ups. The first omits pubsub-encoding, pubsub-source-info
# AND the QoS-byte feature (R311y307: `pubsub-qos`, formerly the three
# pubsub-priority/-congestion-control/-express features it merged) — it
# builds the cfg-off populators (body_encoding = None,
# body_source_info = None, qos = None) under deny-warnings and runs the
# cautious-fire dedup tests that hold with that metadata absent. The
# second adds pubsub-encoding + pubsub-source-info + the QoS
# features — it builds the encoding projection + extract_source_info +
# extract_qos paths and runs the self-echo suppression tests that only
# engage when the wire source_info is decoded. The maximal-preset lanes
# never build the metadata-off subset, so the off arms would otherwise
# escape CI.
# The two ASYMMETRIC lanes (pubsub-put XOR pubsub-delete) run the
# `pubsub::decode_isolation_tests` module: the main `mod tests` requires
# BOTH features (its Del-body POS tests assert SampleKind::Del), so the
# receive-side silent-drop of the OFF variant — dispatch_push's
# `_ => return` for the cfg'd-out arm — is only behaviourally guarded
# here. The symmetric lanes above never build a single-variant subset, so
# without these a regression that un-gated an arm (firing the OFF variant)
# would escape CI. Layer F proves the OFF feature shrinks the binary;
# these prove the OFF variant fires no subscriber callback while the ON
# variant still dispatches.
#
# R311y321 — the 5th arm is the REPLY plane's metadata-OFF subset, the twin of
# arms 3/4 for `reply::reply_timestamp_decode_isolation_tests`. Arms 1-4 are all
# pubsub-plane: NONE of them enables `codec-response`, so none compiles
# `dispatch_response` at all, and a reply-plane isolation guard placed in `mod
# tests` would never run anywhere. `query-reply` (= `codec-response`) with every
# `pubsub-*` metadata feature OFF is the profile that compiles the reply decode
# arms while their timestamp gate is off. It mirrors `zget-reply-only` in
# `_wz_consumer_plane_subsets` on the ONE axis this arm guards; it is not the
# whole row (no `codec-response-final` / `query-get` — this arm dispatches a
# Response directly and needs neither), so it is deliberately narrower rather
# than a hand-copy that can silently diverge (the C1bk mistake, R311y319).
layer_c1d_cargo_test_pubsub() {
    (cd crates \
        && cargo test -p wz-session-core --features codec-push,codec-declare,codec-response-final,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp --quiet \
        && cargo test -p wz-session-core --features codec-push,codec-declare,codec-response-final,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp,pubsub-encoding,pubsub-source-info,pubsub-priority,pubsub-congestion-control,pubsub-express --quiet \
        && cargo test -p wz-session-core --features codec-push,pubsub-put --quiet \
        && cargo test -p wz-session-core --features codec-push,pubsub-delete --quiet \
        && cargo test -p wz-session-core --features codec-response,query-reply --quiet)
}

# ─── Layer C1bi — pubsub-qos: the merged QoS-byte gate (R311y307) ───────
#
# The QoS ext (network id 0x01) packs priority / congestion / express into
# ONE byte, so R311y307 merged the three former per-field features into the
# single `pubsub-qos` compile unit and demoted them to aliases (catalog:
# reserved + FOUNDATIONAL). This lane pins the two properties that merge
# rests on — both are NEGATIVE assertions, because the defect y307 fixed
# was invisible to every build-only / clippy-only arm that already covered
# these subsets (a subset that compiles proves nothing about what the gate
# lets onto the wire).
#
#   arm 1 (gate ON, canonical knob): the qos encode/decode paths compile and
#     the build_push_outer_extensions tests RUN — raw-faithful, unmasked
#     (a decoded byte is recorded as the peer sent it; y307 deliberately
#     does NOT per-field mask, which would make wz report a QoS never sent).
#   arm 2 (gate OFF): the SAME test filter must select ONLY the ungated
#     `returns_none_without_qos` — i.e. the qos-gated tests must VANISH.
#     `--exact` on a gated-out test name would pass vacuously, so this arm
#     asserts the surviving COUNT via the filter, which is what makes the
#     OFF arm a real gate proof rather than a skip reporting green.
#   arm 3 (alias composition): `--features pubsub-express` ALONE must
#     compose pubsub-qos, so the qos tests execute. This is the arm that
#     would have caught the y307 defect: pre-merge, composing express alone
#     silently enabled the whole byte while each sibling's doc claimed its
#     sub-field "cannot ride the wire" without its own feature.
#   arm 4 (wz-runtime-tokio side): C1d is `-p wz-session-core` only and
#     never builds the crate where `PublishOptions::with_qos` and the three
#     per-field setters live, so the gate's API surface needs its own arm.
layer_c1bi_cargo_test_pubsub_qos() {
    (cd crates \
        && cargo test -p wz-session-core --no-default-features --features alloc,codec-push,pubsub-qos --lib push_build::tests::build_push_outer_extensions --quiet \
        && test "$(cargo test -p wz-session-core --no-default-features --features alloc,codec-push --lib push_build::tests::build_push_outer_extensions -- --list 2>/dev/null | grep -c ': test')" = "1" \
        && cargo test -p wz-session-core --no-default-features --features alloc,codec-push,pubsub-express --lib push_build::tests::build_push_outer_extensions --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop,pubsub-qos --lib --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop,pubsub-qos --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop --quiet -- -D warnings)
}

# ─── Layer C1bk — Query pub-field gates (R311y317) ─────────────────────
#
# The QUERY twin of C1bj, three domains and nine rounds later. Same shape,
# worse blast radius: on the push side y308's leak was loopback-only /
# process-local, but here `query-target` / `-consolidation` / `-timeout` put
# their bytes ON THE WIRE in a build that does not contain the atom — Q_T
# (0x34), Q_C (0x23), the timeout ext (0x26) — because `QueryOptions`' fields
# are `pub` and `#[non_exhaustive]` blocks only struct-literal construction,
# not assignment. y317 moved the gate onto the `effective_*` accessors.
#
# Why these three and not their four siblings: `query-value` /
# `-source-info` / `-attachment` / `-selector-parameters` forward to
# same-named wz-session-core features, so the TX SSOT
# (`build_request_query_with_meta`) gates them downstream and no pub-field
# write survives. `query-target` / `-consolidation` / `-timeout` are
# runtime-tokio TERMINAL features — session-core cannot name them — so the
# runtime accessor is the last hop that knows, and this lane is its only
# proof.
#
# The NEGs are `not(feature)`-gated, so they compile ONLY in a subset that
# omits the atom. Every hosted lane has these features ON (Layer C1's
# `--workspace` unifies them), which cfg's all three OUT — so without THIS
# lane they never build and the gate is unproven [[a skip is green]]. The
# subset MIRRORS `zget-reply-only` in `_wz_consumer_plane_subsets` but is
# HAND-COPIED, not derived from it -- so the two can silently diverge. Deriving
# it is the better shape; it is not done. (R311y319: the first draft of this
# header called it "from the SSOT", which it is not.)
#
# The `--list` assertion pins the SET, not a count: R311y315 shipped a gate
# whose CARRY pinned `len()`, so a rename kept the number equal and a real
# omission passed green. Four names, compared exactly.
#
# R311y336 — the subset carries `query-queryable` for the FOURTH guard, the
# LOOPBACK twin. R311y334 wired zenoh's `(queryable.complete || target !=
# AllComplete)` filter into the LOCAL dispatch, which handed the pub-field
# bypass a second leg: with `query-target` OFF, a raw `opts.target` write made
# the loopback select on completeness while the wire leg — gated by
# `effective_target()` — did not, so the two legs disagreed in a build without
# the atom. Proving that needs a LOCAL QUERYABLE to select among, which is why
# this subset now composes `query-queryable`; the three wire guards are
# unaffected by it (they route `Locality::Remote` and compare frames, so no
# loopback fan occurs).
layer_c1bk_cargo_test_query_pub_field_gates() {
    local base="transport-unicast,transport-link-tcp,session-unicast-open,session-unicast-accept,codec-frame,codec-keep-alive,codec-init-body,codec-open-body,codec-close,keyexpr-canon"
    local feats="$base,codec-response,codec-response-final,query-get,query-reply,query-queryable"
    local expected="loopback_target_pub_field_cannot_bypass_the_query_target_gate
query_consolidation_pub_field_cannot_bypass_the_gate
query_target_pub_field_cannot_bypass_the_query_target_gate
query_timeout_pub_field_cannot_bypass_the_query_timeout_gate"
    local got
    got=$(cd crates && cargo test -p wz-runtime-tokio --no-default-features \
        --features "$feats" --lib pub_field -- --list 2>/dev/null \
        | sed -n 's/^session::tests::\([^:]*\): test$/\1/p' | sort)
    if [ "$got" != "$(printf '%s' "$expected" | sort)" ]; then
        echo "  C1bk FAIL: the pub-field NEG set drifted (cfg elided a guard, or one was renamed)"
        echo "    expected:"; printf '%s\n' "$expected" | sort | sed 's/^/      /'
        echo "    got:";      printf '%s\n' "$got" | sed 's/^/      /'
        return 1
    fi
    (cd crates \
        && cargo test -p wz-runtime-tokio --no-default-features --features "$feats" --lib pub_field --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --no-default-features --features "$feats" --quiet -- -D warnings)
}

# ─── Layer C1bj — Push loopback metadata gates (R311y308) ──────────────
#
# `build_loopback_sample` threads PublishOptions' metadata into the loopback
# Sample. Until y308 it copied all five fields UNGATED while the wire leg
# gated each on its own feature, so a field written through the PUB FIELD
# (the gated `with_*` setter is absent in these subsets, but
# `#[non_exhaustive]` blocks only struct-literal construction, not field
# assignment) reached a loopback subscriber in a build that never composed
# the feature — falsifying the manifest's "Feature-off: nothing is set nor
# written". Loopback-only / process-local; the wire leg was always correct.
#
# The `loopback_drops_*_when_feature_off` NEGs are `not(feature)`-gated, so
# they compile ONLY in a subset that omits the feature. The default and
# maximal lanes have every metadata feature ON, which cfg's all five OUT —
# so without THIS lane they would never build and the gate would be unproven.
# Each arm below omits exactly one metadata feature while keeping
# pubsub-allow-loop (the compile precondition of build_loopback_sample), so
# each NEG runs in exactly one arm. The final arm omits all of them at once
# and also clippy-gates that subset.
layer_c1bj_cargo_test_loopback_metadata_gates() {
    (cd crates \
        && cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop,pubsub-encoding,pubsub-source-info,pubsub-attachment,pubsub-qos --lib loopback_drops_ --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop,pubsub-timestamp,pubsub-source-info,pubsub-attachment,pubsub-qos --lib loopback_drops_ --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop,pubsub-timestamp,pubsub-encoding,pubsub-attachment,pubsub-qos --lib loopback_drops_ --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop,pubsub-timestamp,pubsub-encoding,pubsub-source-info,pubsub-qos --lib loopback_drops_ --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop,pubsub-timestamp,pubsub-encoding,pubsub-source-info,pubsub-attachment --lib loopback_drops_ --quiet \
        && test "$(cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop --lib loopback_drops_ -- --list 2>/dev/null | grep -c ': test')" = "5" \
        && cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop --lib push_metadata_drops_qos --quiet \
        && test "$(cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop --lib push_metadata_drops_qos -- --list 2>/dev/null | grep -c ': test')" = "1" \
        && cargo clippy -p wz-runtime-tokio --all-targets --no-default-features --features transport-unicast,codec-push,pubsub-put,pubsub-allow-loop --quiet -- -D warnings)
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
#
# This feature set is ALSO the `reply::decode_isolation_tests` build:
# `query-queryable` pulls in `codec-response` (so `dispatch_response`
# compiles) while the reply-body consumer markers (query-reply /
# pubsub-put / pubsub-delete) stay OFF, so the inbound Reply Put/Del
# body arms are cfg'd out and fall through to `_ => return`. The
# maximal reply lane C1f keeps those markers ON (cfg'ing the module
# out), so this is the only lane that RUNS the reply decode-isolation
# NEG — the query-side mirror of pubsub's `decode_isolation_tests`.
#
# Second invocation: the metadata-OFF receive subset (query-queryable
# ON, query-attachment / query-selector-parameters OFF). It runs
# `query::request_decode_isolation_tests` — the receive-side NEG that an
# inbound Query's attachment ext / parameters slice does NOT reach the
# QueryView when those consumer features are off (extract_query_attachment
# short-circuits; parameters_view = None). The first (maximal) invocation
# keeps both markers ON, cfg'ing that module out, so only this lane RUNS
# it. (It also re-runs reply::decode_isolation_tests — harmless.)
# R311y314 — arm 2 is a bare whole-crate `cargo test`: ZERO surviving tests would
# report green, which is the construction C1bi's own comment calls "a skip
# reporting green" rather than a gate proof. R311y313 tagged query-reply COMPLETE
# citing this arm as its OFF proof, so the arm now asserts the surviving COUNT:
# reply::decode_isolation_tests is `not(pubsub-put) + not(pubsub-delete) +
# not(query-reply)`-gated, so its 2 NEGs exist ONLY in this subset. If a future
# round widens any of those three gates the module vanishes and this goes red,
# instead of the suite silently shrinking to nothing.
#
# R311y329 — y314 guarded the REPLY module and left its sibling unguarded, in the
# same arm. `query::request_decode_isolation_tests` is the OFF proof for THREE
# atoms (query-attachment / query-selector-parameters / query-source-info, the
# last already tagged COMPLETE citing this module AND this lane by name).
#
# Two DIFFERENT widening paths, both silent before this guard — measured, not
# argued (an earlier draft of this comment claimed one mechanism for all three
# and was wrong about source-info; a reviewer caught it):
#   - query-attachment / query-selector-parameters are the module's own cfg
#     (query.rs:3374-3379, two `not()`s): widening either cfg's the WHOLE module
#     out. Measured: `--features query-queryable,query-attachment` lists 0 tests,
#     rc=0 — green even under RUSTFLAGS="-D warnings", because every fixture is
#     co-located and vanishes with it.
#   - query-source-info is NOT in that cfg. Its test + fixture carry their own
#     `not(query-source-info)` (query.rs:3516 / :3542), so widening it elides
#     only THAT test. Measured: `--features query-queryable,query-source-info`
#     lists 2, rc=0.
# Either way arm 2 silently shrinks — the exact "skip reporting green" y314
# named — and a SET pin catches both; y314's `grep -c = 2` on reply catches
# neither. Sets, not counts: R311y315 shipped a len()-pinned gate that a rename
# passed green, so C1bk moved to a set comparison and this lane follows it.
# Falsifiable both ways — rename an expected name or cfg-elide a guard and the
# compare goes red.
# Print `$1`'s surviving test-name set (sorted) from the arm-2 subset build.
# Returns non-zero WITHOUT printing a set when the listing build itself fails:
# `--list` emits nothing on a compile error, so a swallowed build failure would
# otherwise read as an empty set and be reported as drift. Verified live while
# building this guard (R311y329) — eliding one NEG tripped `-D warnings`
# dead_code on its now-unused fixture, and the first draft blamed the SIBLING
# module for a compile error it never mentioned.
#
# The capture is `.*`, not `[^:]*`: a NEG added inside a SUBMODULE would be
# invisible to `[^:]*` and the compare would still MATCH, so a new guard could
# land unpinned. Neither module has submodules today (measured) — `.*` keeps it
# that way by construction rather than by luck. A submodule name simply reads as
# `nested::name` and must appear verbatim in the expected set.
_c1e_neg_set() {
    local module="$1" out rc
    out=$(cd crates && cargo test -p wz-session-core --features query-queryable \
        --lib "$module" -- --list 2>&1); rc=$?
    if [ "$rc" -ne 0 ]; then
        # The crate failed to compile. The error can originate in ANY module —
        # `--lib <module>` filters which tests RUN, not what gets built — so do
        # not read `$module` as the culprit; the dump below names the real site.
        echo "  C1e FAIL: the subset build broke while listing \`$module\` (exit $rc)." >&2
        echo "            This is NOT a drift verdict, and the fault is not necessarily" >&2
        echo "            in \`$module\` — the compiler output names the real site:" >&2
        printf '%s\n' "$out" | tail -20 | sed 's/^/      /' >&2
        return 1
    fi
    printf '%s' "$out" | sed -n "s/^${module}::\(.*\): test\$/\1/p" | sort
}

layer_c1e_cargo_test_query() {
    local reply_expected="inbound_reply_del_body_is_dropped_when_reply_consumer_off
inbound_reply_put_body_is_dropped_when_reply_consumer_off"
    local query_expected="inbound_query_attachment_is_dropped_when_query_attachment_off
inbound_query_parameters_are_dropped_when_query_selector_parameters_off
inbound_query_source_info_is_dropped_when_query_source_info_off"
    local got
    got=$(_c1e_neg_set reply::decode_isolation_tests) || return 1
    if [ "$got" != "$(printf '%s' "$reply_expected" | sort)" ]; then
        echo "  C1e FAIL: the reply decode-isolation NEG set drifted (cfg elided a guard, or one was renamed)"
        echo "    expected:"; printf '%s\n' "$reply_expected" | sort | sed 's/^/      /'
        echo "    got:";      printf '%s\n' "$got" | sed 's/^/      /'
        return 1
    fi
    got=$(_c1e_neg_set query::request_decode_isolation_tests) || return 1
    if [ "$got" != "$(printf '%s' "$query_expected" | sort)" ]; then
        echo "  C1e FAIL: the query request decode-isolation NEG set drifted (cfg elided a guard, or one was renamed)"
        echo "    expected:"; printf '%s\n' "$query_expected" | sort | sed 's/^/      /'
        echo "    got:";      printf '%s\n' "$got" | sed 's/^/      /'
        return 1
    fi
    (cd crates \
        && cargo test -p wz-session-core --features query-queryable,query-attachment,query-selector-parameters,query-reply-err,query-source-info,codec-response-final --quiet \
        && cargo test -p wz-session-core --features query-queryable --quiet)
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
# A8c session-review: the maximal invocation also enables pubsub-attachment +
# pubsub-encoding + query-reply so the A8a/A8b reply-attachment seam tests
# (dispatch_response_surfaces_*, from_query_reply_put_surfaces_*,
# from_view_is_lossless_*) run in an EXPLICIT lane, not only via the implicit
# C1 workspace union (which depended on wz-runtime-tokio's defaults forwarding
# both features — exactly the "silent drop on a defaults change" this lane
# guards against).
# R311y314 — arm 2 (the R311fn pure-getter arm) was likewise a bare `cargo test`.
# R311y313 cites it as query-reply's ON proof -- the arm showing this atom ALONE,
# with no publisher marker, enables the reply-body decode. A bare invocation
# cannot show that: it passes just as green if `mod tests` cfg's out entirely,
# which is exactly the R311fn regression (before it, the module required
# pubsub-put+pubsub-delete, so the getter arm had ZERO unit coverage and a revert
# to `_ => return` stayed green). The two asserts below are the discriminator:
# the module EXISTS under query-reply and VANISHES without it. Measured at
# R311y314: 32 vs 0. The ON side is `-gt 0`, not an exact count, so adding a reply
# test does not falsely red this lane; the load-bearing assert is the `= "0"`.
layer_c1f_cargo_test_reply() {
    (cd crates \
        && cargo test -p wz-session-core --features codec-push,codec-response,codec-response-final,pubsub-put,pubsub-delete,query-queryable,pubsub-attachment,pubsub-encoding,query-reply --quiet \
        && cargo test -p wz-session-core --no-default-features --features alloc,codec-response,codec-response-final,query-reply --quiet \
        && test "$(cargo test -p wz-session-core --no-default-features --features alloc,codec-response,codec-response-final,query-reply --lib reply::tests -- --list 2>/dev/null | grep -c ': test')" -gt 0 \
        && test "$(cargo test -p wz-session-core --no-default-features --features alloc,codec-response,codec-response-final --lib reply::tests -- --list 2>/dev/null | grep -c ': test')" = "0")
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
#   6b. seam-skew (clippy) +session-unicast +declare-interest  (R311my — the
#       send-seam gate-skew guard. session-unicast ON compiles the
#       SessionLinkActions seam; declare-interest ON pulls codec-declare + the
#       Interest arm but NO Declare-origination feature (the 6-union
#       declare-keyexpr/-subscriber/-queryable/-token/-final/liveliness-token),
#       so the seam's Declare arm is cfg'd OUT. R311mw shipped a skew where that
#       arm was codec-declare-gated while dispatch_declare is union-gated —
#       absent dispatch, hard compile error — and EVERY other codec-declare lane
#       pins a 6-union member, masking it. This is the only lane that compiles
#       the seam with codec-declare on but no Declare origination. clippy
#       -D warnings (the seam lives in lib) so a future seam-arm gate that
#       outruns its dispatch_* helper, or a dropped catch-arm param discard,
#       fails here.)
#   6c. seam-skew-degenerate (clippy) +session-unicast +codec-declare  (R311nh —
#       the codec-declare-with-NO-origination build subset 6b explicitly did NOT
#       pin. The send-seam fn-gate is any(codec-push, codec-request,
#       codec-declare, declare-interest) but each typed arm keys off a narrower
#       gate (Declare on the 6-union, not bare codec-declare), so this build
#       compiles the seam with ONLY the `_ =>` catch arm — every NetworkMessage::
#       pattern cfg'd out. Pre-R311o that left the fn's `use NetworkMessage`
#       alias unused (clippy -D warnings reject), and it was UNREACHABLE through
#       run-ci because every codec-declare lane pinned a 6-union member or
#       declare-interest. R311nh made the patterns fully-qualified (no alias), so
#       the unused-import class is now unrepresentable regardless of the
#       fn-gate/arm-gate skew; this lane is the regression guard.)
#   7. transport-batching +transport-batching        (R311kl: the gate covers ONLY the BatchTx coalescing
#                                                      machinery now — negotiation is core; guards the
#                                                      gate-ON arm that the alloc-only subset #1 leaves OFF)
#
# R311gb (Track 2) — no-alloc (MCU no-heap) subsets 8-13. Every subset
# above pins `alloc`; these drop it, so they exercise the bounded
# control-plane backing + the `all(codec-*, alloc)` wire-dispatch gating
# that an `alloc`-on build can never reach. This is the guard that caught
# the R311hf-pre / R311hk-pre gaps (codec features whose alloc-gated
# imports were left un-gated): a `<codec> && !alloc` profile that pulls an
# absent `alloc` module or leaves an unused import is a hard error here.
# Subset 13 is the full registry surface with no heap — the strongest
# statement of the north-star "single source → MCU no-heap" property.
#   8.  no-alloc bare        (control/value surface only, no codec)
#   9.  no-alloc declare     +codec-declare +declare/liveliness observers
#   10. no-alloc pubsub      +codec-push +pubsub-*
#   11. no-alloc query       +codec-request +query-queryable +query-*
#   12. no-alloc reply       +codec-response(+final) +query-reply
#   13. no-alloc FULL surface (every codec + consumer feature, zero heap)
#
# R311y516 (Track 3) — the ESTABLISHMENT-CODEC-WITHOUT-ROLE subsets 14-16.
# `codec-init-body` / `codec-open-body` name a CODEC, not an emit: the four
# senders that route INIT/OPEN through the `send_wire` seam are each
# additionally role-gated (`session-unicast-open` / `session-unicast-accept`).
# A build carrying an establishment codec and NEITHER role therefore has no
# `send_wire` / `emit_on_link` caller, and before R311y516 compiled both as
# dead code — `-D warnings` reject. It survived because no lane named the
# combination (the y513/y514 lesson, third instance). These are CLIPPY arms,
# not `cargo build`: dead code is a WARNING, so a `build` arm cannot see it.
#   14. session-extqos +codec-init-body    (the exact combination that reded)
#   15. codec-open-body bare               (the open-side twin)
#   16. codec-init-body +session-unicast-open  (POSITIVE arm — the seam MUST
#                                               still compile when a role is
#                                               present, so 14/15 cannot pass
#                                               by deleting the seam)
#
# R311y578 (G7) — the CODEC-WITHOUT-SEAM subsets 17-18, the same lesson one
# layer down. A helper's cfg must include the gate of every module that calls
# it; `frame_encode::oam_body` had `codec-linkstate + codec-push` while its
# ONLY consumer, `session_actions::dispatch_oam`, sits behind
# `session-unicast`. Every sibling body encoder has an in-module caller and so
# stays live on its own, which is why oam_body alone reded and why no lane saw
# it: the combination was named by a consumer crate OUTSIDE this workspace,
# whose feature choice owes nothing to wz's matrix. CLIPPY arms — dead code is
# a warning, so a `build` arm cannot see it.
#   17. every codec + reassembly, NO session-unicast  (the measured combination)
#   18. the same +session-unicast                     (POSITIVE arm — 17 must
#                                                      not pass by deleting the
#                                                      helper)
layer_c1h_arbitrary_subset_matrix() {
    (cd crates \
        && cargo build -p wz-session-core --no-default-features --features alloc --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,codec-push,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,query-queryable,query-attachment,query-selector-parameters,query-reply-err,query-source-info --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,codec-push,codec-response,codec-response-final,pubsub-put,pubsub-delete --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,codec-declare,declare-subscriber,declare-queryable,liveliness-token,liveliness-subscriber --quiet \
        && cargo build -p wz-session-core --no-default-features --features alloc,codec-declare --quiet \
        && cargo clippy -p wz-session-core --no-default-features --features alloc,session-unicast,declare-interest,codec-frame --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features alloc,session-unicast,codec-declare --all-targets --quiet -- -D warnings \
        && cargo build -p wz-session-core --no-default-features --features alloc,transport-batching --quiet \
        && cargo build -p wz-session-core --no-default-features --quiet \
        && cargo build -p wz-session-core --no-default-features --features codec-declare,declare-subscriber,declare-queryable,liveliness-token,liveliness-subscriber --quiet \
        && cargo build -p wz-session-core --no-default-features --features codec-push,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp --quiet \
        && cargo build -p wz-session-core --no-default-features --features codec-request,query-queryable,query-attachment,query-selector-parameters,query-reply-err,query-source-info --quiet \
        && cargo build -p wz-session-core --no-default-features --features codec-response,codec-response-final,query-reply --quiet \
        && cargo build -p wz-session-core --no-default-features --features codec-push,codec-declare,codec-request,codec-response,codec-response-final,query-queryable,query-reply,liveliness-token,liveliness-subscriber,declare-subscriber,declare-queryable,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp,pubsub-source-info,query-attachment,query-selector-parameters,query-reply-err,query-source-info --quiet \
        && cargo clippy -p wz-session-core --no-default-features --features session-extqos,codec-init-body --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features codec-open-body --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features codec-init-body,session-unicast-open --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features alloc,codec-frame,codec-push,codec-declare,codec-request,codec-response,codec-response-final,codec-init-body,codec-open-body,codec-close,codec-keep-alive,codec-fragment,reassembly,codec-linkstate --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features alloc,codec-frame,codec-push,codec-declare,codec-request,codec-response,codec-response-final,codec-init-body,codec-open-body,codec-close,codec-keep-alive,codec-fragment,reassembly,codec-linkstate,session-unicast --quiet -- -D warnings)
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

# ─── Layer C1k — cargo test ... --features scouting-static ──────────
#
# R311if: scouting-static is off by default (the static-mode toggle, the
# alternative to scouting-active per deploy.scouting.mode), so Layer C1's
# `cargo test --workspace` builds neither the wz-session-core `scout_static`
# synth module nor the wz-runtime-tokio `open_session_static` consumer. This
# lane builds + runs both under `--features scouting-static`:
#   - the synth unit tests (ScoutingMode parse, synth_static_locators
#     trim/dedup/order) in wz-session-core;
#   - the static -> session-open seam in wz-runtime-tokio
#     (static_scout_open.rs: skip-unreachable, empty, all-unreachable),
#     which Layer C1 stopped running once the static tests gained the gate.
# `--features X` adds to (does not replace) the default feature set, so the
# transport-link-tcp/udp + transport-unicast the open path needs stay on.
# R311ih: also build-gates the no-alloc backing (scout_static on the
# bounded seam composes without alloc) and the MCU runtime edge
# (wz-runtime-coop scouting-static = the facade -> runtime -> core funnel,
# no-alloc + alloc). The thumb cross-compile of the same is Layer G.5.
layer_c1k_cargo_test_scouting_static() {
    _runci_guarded_test "C1k scout_static" 7 \
        cargo test -p wz-session-core --features scouting-static --lib scout_static --quiet || return 1
    _runci_guarded_test "C1k static_scout_open" 6 \
        cargo test -p wz-runtime-tokio --features scouting-static --test static_scout_open --quiet || return 1
    (cd crates \
        && cargo build -p wz-session-core --no-default-features --features scouting-static --quiet \
        && cargo build -p wz-runtime-coop --features scouting-static --quiet \
        && cargo build -p wz-runtime-coop --features alloc,scouting-static --quiet)
}

# ─── Layer C1o — keyexpr matching composition gating BEHAVIOUR ───────
#
# R311jf — the keyexpr wildcard / DSL / includes capabilities became
# real atomic toggles (§5.6); Layer C1's `cargo test --workspace`
# unifies them ON (wz-runtime-tokio's default forwards them), so C1
# only ever exercises the wildcards-ON matcher. This lane is the
# behavioural composability guard the audit flagged as missing: it runs
# the SAME keyexpr_match test module three times and proves the gate ACTS —
#   - wildcards OFF (alloc only): the off-degrade tests assert `**`/`*`
#     lose wildcard meaning and match only the literal chunk; the
#     wildcard / includes tests are cfg'd out (not run);
#   - wildcards ON (alloc): the `**`/`*`/`$*` glob + directional `includes`
#     tests run and pass;
#   - wildcards ON, no-`alloc`: the same matcher over the bounded
#     `heapless`-backed candidate buffer. This arm runs the
#     `cfg(not(feature = "alloc"))` over-depth asserts (the bounded buffer
#     refuses to grow and conservatively NO-matches) that the two alloc
#     arms cfg out, and — because `cargo test` compiles the WHOLE no-alloc
#     lib test binary before filtering — it is the only host lane that
#     compiles wz-session-core's tests under `--no-default-features`
#     (R311sx). C1h `cargo build`s the no-alloc lib but never its tests, so
#     a test-only no-alloc break (a test struct-literal that inits an
#     `alloc`-gated field without the matching cfg) slipped past every
#     lane until the pre-push full run-ci; this arm closes that gap.
# A regression that ungated a branch (made it always-on again) would
# make the OFF arm fail (a `**` would wrongly match multi-chunk),
# catching exactly the "implemented-but-not-excludable" drift this
# round closed. The no_std MCU strip is Layer G's cross-compile job.
layer_c1o_keyexpr_gating_behavior() {
    _runci_guarded_test "C1o keyexpr alloc" 7 \
        cargo test -p wz-session-core --no-default-features --features alloc \
        --lib keyexpr_match --quiet || return 1
    _runci_guarded_test "C1o keyexpr alloc+wildcards" 17 \
        cargo test -p wz-session-core --no-default-features \
        --features alloc,keyexpr-wildcard-single,keyexpr-wildcard-double,keyexpr-dollar-star,keyexpr-includes \
        --lib keyexpr_match --quiet || return 1
    _runci_guarded_test "C1o keyexpr wildcards-no-alloc" 17 \
        cargo test -p wz-session-core --no-default-features \
        --features keyexpr-wildcard-single,keyexpr-wildcard-double,keyexpr-dollar-star,keyexpr-includes \
        --lib keyexpr_match --quiet || return 1
}

# ─── Layer C1l — reassembly subsystem (Tier B) build + AP unification ─
#
# R311im: reassembly is off by default (a Tier B transport capability),
# so Layer C1's `cargo test --workspace` never builds the wz-session-core
# reassembly slot module or the ReassemblyDispatcher. This lane:
#   - runs the dispatcher / slot-FSM unit tests under `--features
#     reassembly` (std sce-rust-runtime — the AP profile);
#   - guards the AP feature-unification fix: R311im dropped the
#     `sce-rust-runtime/no_std` force from the `reassembly` feature, so
#     building wz-runtime-tokio (std runtime, `http-send`) together with
#     `wz-session-core/reassembly` in one resolve must NOT trip the
#     runtime's no_std x http-send `compile_error!`. This is the exact
#     command that failed before the force was dropped (SCE pin 1474091c2
#     routes the bytes payload through the profile-resolving SceBytes<N>
#     alias so the single --no-std emit also builds on the std runtime).
# The MCU no_std build of the same module is Layer G.8.
#
# R311jm: the same lane also runs `--features transport-fragmentation` —
# the TX-side fragmentation half (an oversize FRAME splits into a
# `T_MID_FRAGMENT` chain). transport-fragmentation pulls `reassembly`
# (full-duplex), so these runs cover both `frame_encode::fragment_*` (the
# wire split + parse round-trip) and the `send_push_literal`
# fragment-and-reassemble e2e (session_glue `fragment_tx_tests`).
#
# R311ni: the `--features transport-fragmentation` wz-runtime-tokio run also
# picks up the new `tests/layer3_reassembly_tx.rs` integration test (gated
# `#![cfg(feature = "transport-fragmentation")]`) — the unicast TX-split
# PRODUCTION-path e2e over a real loopback TCP link: an oversize
# `Session::publish` (200 bytes past a 64-byte negotiated batch MTU) leaves
# the publisher as a fragment chain and the subscriber node's continuous
# drive loop reassembles it into one byte-exact Sample. Closes the session-
# review gap where unicast TX fragmentation had only codec + RX-ingest
# coverage, never an oversize real-socket send (multicast had its sibling in
# multicast_pubsub_loopback).
#
# R311jp: the transport-fragmentation invocation also carries the batching
# x fragmentation interplay test (session_glue `batch_tx_tests::
# oversize_publish_drains_open_frame_then_fragments`) — default features
# keep transport-batching ON, so the oversize-while-batching drain order
# is pinned here; the rest of `batch_tx_tests` rides the default Layer C1
# workspace run, and the FeatureDisabled NEG rides the C1j subsets (their
# base omits transport-batching).
#
# R311ol: the `--features transport-fragmentation` wz-runtime-tokio run also
# picks up the new `tests/udp_chaos_e2e.rs` (gated `#![cfg(all(
# transport-fragmentation, transport-link-udp))]`, transport-link-udp is a
# default feature) — the first LOSSY-link robustness e2e (P3.10 chaos): a
# deterministically-dropped UDP fragment datagram aborts its reassembly chain
# (the lossy Put is lost, ReassemblyDropped observed) and the SAME live session
# reassembles a subsequent clean oversize Put byte-exact. Closes the gap where
# the reassembly + RX-SN-gate RECOVERY path had only unit-test coverage, never
# an end-to-end lossy real-socket run (every prior e2e ran over a clean link).
# The clippy line below clippy-gates the transport-fragmentation test targets
# (udp_chaos_e2e + udp_frag_e2e + layer3_reassembly_{tx,rx}); the C2 workspace
# clippy resolves DEFAULT features only, so these transport-fragmentation-gated
# files were rustc-checked by the test build above but never clippy-linted
# (gate-skew, same shape the C1u/C1v lanes close for tls/ws).
#
# R311y414 — the four whole-crate runs stay BARE on purpose (they emit 126
# libtest summary lines between them, so neither an exact count nor a `>=1`
# says anything), but bare is exactly why this lane could go green on nothing:
# `cargo test -p wz-runtime-tokio --features reassembly` passes with hundreds of
# unrelated cases while every fragmentation-gated TARGET sits at 0. Measured on
# the unperturbed tree: under `reassembly` alone udp_chaos_e2e / udp_frag_e2e /
# layer3_reassembly_tx really are 0-test targets (they need
# transport-fragmentation), and under transport-fragmentation they carry 3 / 1 /
# 1. So the lane now ALSO runs its own subjects target-scoped with exact guards
# -- the per-target counts are what the whole-crate exit code cannot show.
layer_c1l_reassembly() {
    # R311y580 — 16 -> 27: R311y578 added the eleven `chain_boundary_marker_tests`
    # to `reassembly_dispatch`, and the guard was not moved with them. The number is
    # DERIVED, not guessed: `--list` under this exact feature set enumerates 27, all
    # of them `reassembly_dispatch::` (16 original + 11 new), so the filter did not
    # widen onto foreign tests.
    _runci_guarded_test C1l 27 cargo test -p wz-session-core --features reassembly --lib reassembly --quiet \
        || return 1
    _runci_guarded_test C1l 4 cargo test -p wz-runtime-tokio --features reassembly --test layer3_reassembly_rx --quiet \
        || return 1
    # R311y580 — the same eleven, on the sibling feature arm.
    _runci_guarded_test C1l 27 cargo test -p wz-session-core --features transport-fragmentation --lib reassembly --quiet \
        || return 1
    _runci_guarded_test C1l 1 cargo test -p wz-runtime-tokio --features transport-fragmentation --test layer3_reassembly_tx --quiet \
        || return 1
    _runci_guarded_test C1l 4 cargo test -p wz-runtime-tokio --features transport-fragmentation --test layer3_reassembly_rx --quiet \
        || return 1
    _runci_guarded_test C1l 1 cargo test -p wz-runtime-tokio --features transport-fragmentation --test udp_frag_e2e --quiet \
        || return 1
    _runci_guarded_test C1l 3 cargo test -p wz-runtime-tokio --features transport-fragmentation --test udp_chaos_e2e --quiet \
        || return 1
    # R311y474 — the udp leg of the adminspace {src,dst} pairing proof. Only ONE
    # test selects here: the file's other four legs are gated on link features this
    # set does not arm, and each is guarded in ITS OWN transport lane (C1t serial,
    # the quic-datagram lane, the unixpipe lane) rather than all in one place.
    _runci_guarded_test C1l 1 cargo test -p wz-runtime-tokio --features transport-fragmentation --test link_endpoints_pairing --quiet \
        || return 1
    # R311y511 — wz-runtime-coop is the MCU sibling of the wz-runtime-tokio
    # drive above, and it was the one reassembly consumer this lane never
    # built. Its reassembly_rx tests are `#[cfg(test)]` behind
    # `--features reassembly`, so neither Layer C1 (default features) nor a
    # `cargo build` lane compiles them; the R311kp `zid` -> `peer_key` rename
    # and the R311y215 `Fragment.priority` addition both rotted the fixture
    # undetected. `test`, not `build`, is the load-bearing verb here.
    (cd crates \
        && cargo test -p wz-session-core --features reassembly --quiet \
        && cargo test -p wz-runtime-tokio --features reassembly --quiet \
        && cargo test -p wz-runtime-coop --features reassembly --quiet \
        && cargo test -p wz-session-core --features transport-fragmentation --quiet \
        && cargo test -p wz-runtime-tokio --features transport-fragmentation --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-fragmentation --quiet -- -D warnings)
}

# ─── Layer C1p — multicast session FSM + dispatcher (Round A) ────────
#
# Round A: session-multicast is off by default (a transport-tier
# capability), so Layer C1's `cargo test --workspace` never builds the
# wz-session-core multicast FSM modules (session_fsm_multicast +
# multicast_peer) or the MulticastDispatcher Router. This lane runs the
# Router + per-peer-FSM unit tests under `--features session-multicast`
# (std sce-rust-runtime — the AP profile). Multicast is handshake-free
# (§3.3), a different shape from the unicast session FSM, so it is its own
# lane. The MCU no_std build of the same is Layer G.12. Mirrors the Layer
# C1l reassembly lane. R311kn adds the reassembly-union arm: the multicast
# fragment SN gate + the shared ingest_multicast_fragment pipeline compose
# session-multicast WITH reassembly (codec-push backs the FramePayload
# fixture); the first arm keeps the without-reassembly composition honest
# (fragment MIDs drop, nothing else regresses). R311kt widens the union
# arm with codec-join: the hoisted multicast_join module (the JOIN wire
# SSOT moved here from wz-runtime-tokio::multicast_glue) gates on
# session-multicast + codec-join + alloc; the first arm keeps the
# codec-join-less Router composition honest.
#
# R311y414 — same treatment as C1l: the two whole-crate runs stay bare (they
# pass on hundreds of unrelated session-core cases and would not move if the
# multicast module cfg'd out), so the lane now ALSO runs its OWN subject
# filtered, with the counts that make the composition visible -- `multicast`
# selects 32 cases on bare session-multicast and 48 once reassembly + codec-push
# + codec-join compose in. The 32 -> 48 step is the proof the second feature set
# is doing something.
layer_c1p_multicast() {
    _runci_guarded_test C1p 32 cargo test -p wz-session-core --features session-multicast --lib multicast --quiet \
        || return 1
    _runci_guarded_test C1p 48 cargo test -p wz-session-core --features session-multicast,reassembly,codec-push,codec-join --lib multicast --quiet \
        || return 1
    # R311y633 (§17.6 / §11.2) — the arm that BUILDS `multicast_rx` and RUNS it.
    # The two arms above omit `codec-close`, and `pub mod multicast_rx` is gated
    # on session-multicast + codec-join + codec-frame + codec-close + alloc, so
    # neither of them compiles the module at all: their 32 / 48 counts are a
    # measurement of a different population. The only other lane that selects
    # all four filters on `--lib namespace`, which compiles these tests and runs
    # none of them. Without this arm the batch walk over a multicast datagram
    # is gated by clippy alone.
    _runci_guarded_test C1p 2 cargo test -p wz-session-core \
        --features session-multicast,codec-join,codec-frame,codec-close,reassembly \
        --lib multicast_rx --quiet \
        || return 1
    (cd crates \
        && cargo test -p wz-session-core --features session-multicast --quiet) \
        && (cd crates \
            && cargo test -p wz-session-core \
                --features session-multicast,reassembly,codec-push,codec-join --quiet)
}

# ─── Layer C1q — multicast transport drive loop (Round C) ────────────
#
# Round C: transport-multicast is off by default, so Layer C1's
# `cargo test --workspace` never builds the wz-runtime-tokio multicast_glue
# drive loop. This lane runs its deterministic unit tests (JOIN
# encode/decode round-trip + the fake-driver drive-loop admit/beacon/
# link-lost paths) under `--features transport-multicast`. The real-socket
# multicast e2e is Layer M (Round D). Mirrors the Layer C1i scouting-glue
# lane. R311kn adds the reassembly-union arm: the fragment RX arm in
# drive_multicast_session (per-peer chains, frame-OOO chain abort,
# eviction abort before slot reuse); the first arm keeps the
# without-reassembly drive loop composing (fragment MIDs fall to the
# drop arm). R311ko adds the fragmentation-union arm: the TX seam
# (oversize publish re-frames as a fragment chain +
# the TX->RX round-trip through a peer loop's reassembly).
#
# R311y414 — the three runs were BARE, and here the COUNT is the proof: the
# same `multicast_glue` filter activates 12 tests on bare transport-multicast,
# 16 with reassembly and 18 with transport-fragmentation, so the measured
# counts pin that each composition step really switches its cases on. A bare
# run would stay green if a gate stopped activating (or the filter matched 0).
layer_c1q_multicast_glue() {
    _runci_guarded_test C1q 12 cargo test -p wz-runtime-tokio --features transport-multicast --lib multicast_glue --quiet \
        || return 1
    _runci_guarded_test C1q 16 cargo test -p wz-runtime-tokio --features transport-multicast,reassembly --lib multicast_glue --quiet \
        || return 1
    _runci_guarded_test C1q 18 cargo test -p wz-runtime-tokio --features transport-multicast,transport-fragmentation --lib multicast_glue --quiet \
        || return 1
}

# ─── Layer C1m — wz-session-lwip isolated host test + clippy ─────────
#
# Stage 4b. wz-session-lwip is the no_std MCU session shell: it forces
# `wz-session-core/no_std` (the heapless sce-rust-runtime engine) through
# its non-optional deps. That is mutually exclusive with the std
# sce-rust-runtime (`http-send`) that wz-runtime-tokio pulls — the
# sce-rust-runtime `compile_error!` (no_std vs http-send, RFC §5.J.2)
# fires if both land in one feature-unified graph. So this crate CANNOT
# participate in the `--workspace` unification (Layer C1 / C2 exclude it);
# it is built ISOLATED here via `-p`, where cargo resolves only this
# crate's subgraph (no tokio, no http-send) and `no_std` is correct.
# Mirrors the Layer G.11 cross-real lane but on the host (real lwIP build
# = host always has lwip_real_build). Covers the default (non-reassembly)
# drive path + the reassembly drive path + the R311lt transport-multicast
# drive loop (run_multicast_session), test + clippy each. The
# transport-multicast variant lints the no_std MCU multicast loop under
# run-ci so its code is covered (the same close-the-coverage-gap discipline
# R311ls applied to the AP multicast_glue loop). R311ly adds the
# transport-multicast,codec-push variant: the MCU multicast TX seam
# (run_multicast_session's next_tx pull -> multicast_tx_emit -> send_to_group)
# + its real-lwIP Push round-trip test, which the codec-free transport-multicast
# build (uninhabited MulticastTxItem) does not exercise. R311lz makes the TX seam
# variant-complete and adds two combos: transport-multicast,liveliness-token
# exercises a NON-codec-push TX variant (the DeclareReply round-trip) and lints
# the union TX gate WITHOUT codec-push (the case the old codec-push-only gating
# would have mis-compiled to `match item {}` on an inhabited type). R311ma/R311mb
# add the observer-staging tests: transport-multicast,liveliness-token covers the
# liveliness DeclareReplySink drain, and transport-multicast,query-queryable,
# codec-response,codec-response-final covers the queryable ResponseSink drain
# (MulticastReplyQueue with no liveliness-token, so its ResponseSink-only gate is
# exercised). The maximal build now also carries query-queryable so every
# multicast_tx_emit arm + both observer-staging sinks compile + run together.
# R311mf adds the Fragment RX/TX arms: transport-multicast,reassembly lints the
# reassembly RX path composing WITHOUT fragmentation (the honest non-fragmenting
# reassembly node), and transport-multicast,transport-fragmentation,codec-push
# runs the real-lwIP fragment round-trip (an oversize Put split by
# multicast_tx_emit, reassembled by the Fragment RX arm into one Push).
#
# R311y419 — the nine test runs are GUARDED at their measured counts, as the
# precondition for hosting this lane (R311y414's rule: hosting only helps if
# the lane can go red). `cargo test` exits 0 when a feature combo selects NO
# tests, so a cfg-gate change that silently stops compiling the arms these
# combos exist to reach would have kept every one of them green. The counts are
# a real discriminator here rather than a formality: they DIFFER per combo
# (1/1/3/4/5/4/7/3/5), so each guard pins the arms its own features add. The
# crate has no tests/ dir — all nine runs emit exactly two summaries, the lib
# one and a 0-count doc-test — which is what makes an exact count meaningful
# (contrast C1n below, where six summaries make it ambiguous).
layer_c1m_session_lwip() {
    _runci_guarded_test "C1m default" 1 \
        cargo test -p wz-session-lwip --quiet || return 1
    _runci_guarded_test "C1m reassembly" 1 \
        cargo test -p wz-session-lwip --features reassembly --quiet || return 1
    _runci_guarded_test "C1m multicast" 3 \
        cargo test -p wz-session-lwip --features transport-multicast --quiet || return 1
    _runci_guarded_test "C1m multicast+push" 4 \
        cargo test -p wz-session-lwip --features transport-multicast,codec-push --quiet || return 1
    _runci_guarded_test "C1m multicast+liveliness" 5 \
        cargo test -p wz-session-lwip --features transport-multicast,liveliness-token --quiet || return 1
    _runci_guarded_test "C1m multicast+queryable" 4 \
        cargo test -p wz-session-lwip \
        --features transport-multicast,query-queryable,codec-response,codec-response-final \
        --quiet || return 1
    _runci_guarded_test "C1m multicast maximal" 7 \
        cargo test -p wz-session-lwip \
        --features transport-multicast,codec-push,codec-response,codec-response-final,liveliness-token,query-queryable \
        --quiet || return 1
    _runci_guarded_test "C1m multicast+reassembly" 3 \
        cargo test -p wz-session-lwip --features transport-multicast,reassembly --quiet || return 1
    _runci_guarded_test "C1m multicast+fragmentation" 5 \
        cargo test -p wz-session-lwip \
        --features transport-multicast,transport-fragmentation,codec-push --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-session-lwip --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-lwip --all-targets --features reassembly --quiet -- -D warnings \
        && cargo clippy -p wz-session-lwip --all-targets --features transport-multicast --quiet -- -D warnings \
        && cargo clippy -p wz-session-lwip --all-targets --features transport-multicast,codec-push --quiet -- -D warnings \
        && cargo clippy -p wz-session-lwip --all-targets --features transport-multicast,liveliness-token --quiet -- -D warnings \
        && cargo clippy -p wz-session-lwip --all-targets \
            --features transport-multicast,query-queryable,codec-response,codec-response-final \
            --quiet -- -D warnings \
        && cargo clippy -p wz-session-lwip --all-targets \
            --features transport-multicast,codec-push,codec-response,codec-response-final,liveliness-token,query-queryable \
            --quiet -- -D warnings \
        && cargo clippy -p wz-session-lwip --all-targets --features transport-multicast,reassembly --quiet -- -D warnings \
        && cargo clippy -p wz-session-lwip --all-targets \
            --features transport-multicast,transport-fragmentation,codec-push --quiet -- -D warnings)
}

# ─── Layer C1n — wz-mcu-session-acceptor isolated host e2e + clippy ──
#
# Stage 5. wz-mcu-session-acceptor owns the MCU acceptor session e2e SSOT
# (run_acceptor_e2e<C>, shared verbatim by this host test and the
# deploy/mcu-session-acceptor QEMU bin). It composes wz-session-lwip + the
# facade session-lwip funnel, so it inherits wz-session-lwip's no_std
# forcing and CANNOT participate in the `--workspace` unification (Layer
# C1 / C2 exclude it). Built ISOLATED here via `-p`, where cargo resolves
# only this crate's subgraph (no tokio, no http-send) and `no_std` is
# correct + lwip_real_build holds (host always has a real lwIP build). The
# host integration test drives the full acceptor handshake (InitSyn ->
# InitAck -> OpenSyn with the real round-tripped cookie -> OpenAck ->
# Established) + a post-handshake Frame dispatch over a live lwIP loopback
# — the same scenario Layer Q.4 boots on QEMU.
layer_c1n_mcu_session_acceptor() {
    # Default (no reassembly) — the minimal MCU session build: the
    # WholeFrame data-plane proof (host_acceptor_e2e), reassembly slot pool
    # compiled out. Then `--features reassembly` — the Tier B build: two
    # separate binaries (lwIP's process-global NO_SYS single-init holds per
    # file) covering the three reassembly outcomes — host_acceptor_reassembly_e2e
    # drives a chain through ingest -> reassemble -> dispatch (completion);
    # host_acceptor_reassembly_timeout_e2e stalls the chain + advances the
    # OffsetClock past its deadline so the sweep evicts it (timeout); and
    # host_acceptor_reassembly_ooo_e2e sends a non-consecutive fragment so the
    # strict-in-order ingest aborts the chain (drop). The WholeFrame test still
    # passes with the pool linked in. clippy both configs so the reassembly
    # data path is lint-gated too.
    # R311jd — also gate the `buffer-pool-session-rx-slim` config (the slim
    # session-rx pool the Layer Q.4 microbit boot uses): the host e2e under
    # the slim pool + clippy on the slim-gated cfg paths in the acceptor AND
    # the wz-link-lwip link tier (rx_sockets const select + the cfg'd pool
    # module), which the default/reassembly clippy passes do not cover.
    # R311y419 — the three whole-crate runs stay BARE, and the six
    # TARGET-SCOPED runs below are what makes this lane able to go red, which
    # is the precondition for hosting it. The split is not arbitrary: this
    # crate emits SIX libtest summaries (lib + 4 e2e binaries + doc-tests) and
    # under `reassembly` four of them read `1 passed`, so neither an exact
    # count nor `>=1` over the whole-crate output asserts which binary ran —
    # three of the four e2e tests could vanish and an exact-count guard would
    # still match the survivor. Per TARGET the count is unambiguous (exactly
    # 1 each, measured), and `cargo test` exiting 0 on a selection of NOTHING
    # is precisely the hazard: the three reassembly binaries compile to zero
    # tests without the feature, so a cfg-gate slip silently empties them.
    (cd crates \
        && cargo test -p wz-mcu-session-acceptor --quiet \
        && cargo test -p wz-mcu-session-acceptor --features reassembly --quiet \
        && cargo test -p wz-mcu-session-acceptor --features buffer-pool-session-rx-slim --quiet) \
        || return 1
    _runci_guarded_test "C1n default e2e" 1 \
        cargo test -p wz-mcu-session-acceptor --test host_acceptor_e2e --quiet || return 1
    _runci_guarded_test "C1n slim e2e" 1 \
        cargo test -p wz-mcu-session-acceptor --features buffer-pool-session-rx-slim \
        --test host_acceptor_e2e --quiet || return 1
    _runci_guarded_test "C1n reassembly completion" 1 \
        cargo test -p wz-mcu-session-acceptor --features reassembly \
        --test host_acceptor_reassembly_e2e --quiet || return 1
    _runci_guarded_test "C1n reassembly timeout" 1 \
        cargo test -p wz-mcu-session-acceptor --features reassembly \
        --test host_acceptor_reassembly_timeout_e2e --quiet || return 1
    _runci_guarded_test "C1n reassembly out-of-order" 1 \
        cargo test -p wz-mcu-session-acceptor --features reassembly \
        --test host_acceptor_reassembly_ooo_e2e --quiet || return 1
    _runci_guarded_test "C1n reassembly whole-frame" 1 \
        cargo test -p wz-mcu-session-acceptor --features reassembly \
        --test host_acceptor_e2e --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-mcu-session-acceptor --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-mcu-session-acceptor --features reassembly \
            --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-mcu-session-acceptor --features buffer-pool-session-rx-slim \
            --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-link-lwip --features buffer-pool-session-rx-slim \
            --all-targets --quiet -- -D warnings)
}

# ─── Layer C1r — wz-mcu-multicast-e2e isolated host e2e + clippy ─────
#
# R311mi. wz-mcu-multicast-e2e owns the MCU multicast transport e2e SSOT
# (run_multicast_e2e<C>, shared verbatim by this host test and the
# deploy/mcu-multicast-e2e footprint bin). It composes wz-session-lwip + the
# facade session-lwip funnel, so — like wz-mcu-session-acceptor (C1n) — it
# inherits wz-session-lwip's no_std forcing and CANNOT participate in the
# `--workspace` unification (Layer C1 / C2 exclude it). Built ISOLATED here
# via `-p`, where cargo resolves only this crate's subgraph (no tokio) and
# `no_std` is correct + lwip_real_build holds (host always has a real lwIP
# build). The host integration test is the RUNTIME PROOF the footprint bin
# cannot give via QEMU (multicast self-loopback is a host-only lwIP
# affordance): it drives the full multicast profile end to end over a live
# lwIP loopback — a peer JOIN admitted (transport-multicast) + an oversize
# Put split into a T_MID_FRAGMENT chain (transport-fragmentation TX) +
# reassembled into one Push (reassembly RX + codec-push) — via
# wz_session_lwip::run_multicast_session. The crate has no feature variants
# (the multicast profile is fixed on its wz dep), so one test + one clippy
# pass cover it.
#
# R311y414 — the crate's whole-crate run legitimately prints `0 / 1 / 0` (empty
# lib + the one e2e + empty doctests), so the invariant worth asserting is that
# the e2e case itself did not vanish -- which a bare run reports as green and an
# unscoped guard would stop witnessing the moment the lib gains a test. Hence a
# target-scoped exact guard on `--test host_multicast_e2e`.
layer_c1r_mcu_multicast_e2e() {
    # R311y414 review — TARGET-SCOPED, not a whole-crate `+`. A `+` on the
    # whole-crate run asserts only that SOME target had >=1 case, so the day the
    # (today empty) lib gains its first test the guard would stop witnessing the
    # e2e at all. Scoping to the one target that carries the scenario makes the
    # assertion structural; the whole-crate run below still executes everything.
    _runci_guarded_test C1r 1 cargo test -p wz-mcu-multicast-e2e --test host_multicast_e2e --quiet \
        || return 1
    (cd crates \
        && cargo test -p wz-mcu-multicast-e2e --quiet \
        && cargo clippy -p wz-mcu-multicast-e2e --all-targets --quiet -- -D warnings)
}

# ─── Layer C1s — wz-runtime-tokio-multicast-tests isolated test + clippy ─
#
# R311mo (Level B). The multicast-only Session API (Session::new_multicast,
# gated `not(transport-unicast)`; and the R311nb-unified transport-agnostic
# Session::publish exercised against a multicast transport) is unreachable from
# wz-runtime-tokio's OWN `cargo test`: its wz-runtime-tokio-test-support
# dev-dependency forces transport-unicast ON via feature unification, gating
# the multicast-only constructor out.
# wz-runtime-tokio-multicast-tests pulls wz-runtime-tokio with ONLY
# transport-multicast,codec-push (no test-support, no unicast), so — built
# ISOLATED here via `-p`, excluded from the C1/C2 `--workspace` unification —
# the multicast Session surface is reachable. The test is the RUNTIME PROOF
# that the multicast Session::publish builds a Put and enqueues exactly one
# MulticastTxItem::Push onto the TX seam; the drive loop's framing of that
# queued item is covered by C1p/C1q (drive_loop_frames_queued_push). The crate
# has a single fixed feature config, so one test + one clippy pass cover it.
#
# R311y414 — the crate carries exactly ONE test target (src/lib.rs, 4 cases;
# the second summary line is the empty doctest target), so an exact guard is
# practical here where it is not for a multi-binary whole-crate lane: the whole
# point of the crate is that `transport-unicast` stays OUT of the feature
# unification, and a dev-dependency edit that pulls it back in cfg's
# `new_multicast` away — which a bare run would report as green.
layer_c1s_runtime_tokio_multicast_tests() {
    # R311y414 review — `--lib`-scoped for the same reason as C1r: an unscoped
    # guard is satisfied by ANY summary line in the run, so it would survive the
    # arrival of a second target printing the same count. The whole-crate run
    # below still covers everything the crate grows.
    _runci_guarded_test C1s 4 cargo test -p wz-runtime-tokio-multicast-tests --lib --quiet \
        || return 1
    (cd crates \
        && cargo test -p wz-runtime-tokio-multicast-tests --quiet \
        && cargo clippy -p wz-runtime-tokio-multicast-tests --all-targets --quiet -- -D warnings)
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

# ─── Layer C1bf — wz-runtime-tokio CROSS-FEATURE composition gate ─────
#
# R311y253. Layer C2 runs `clippy --workspace --all-targets` on the DEFAULT
# feature set, so it never composes two optional features that are individually
# exercised by their own lanes but never together. That blind spot shipped a real
# build break: `DialConfig` (session_open.rs) has TWO `#[cfg]`-gated fields
# (`tls` @transport-link-tls, `quic` @transport-link-quic), and every exhaustive
# struct literal in the tree named exactly ONE of them — so the tls-side literals
# failed E0063 the moment `transport-link-quic` was also on, and the quic-side
# ones the moment `transport-link-tls` was. Six integration-test targets did not
# compile under `--all-features`, and NO lane caught it, because the tls lane and
# the quic lane each enable their own feature alone.
#
# This lane closes that gap by clippy-gating every crate in the HAZARD CLASS with
# ALL of its features on at once, over --all-targets so the integration tests
# (separate crates, and the ones that actually broke) are included.
#
# R311y254 — the hazard class is "crates that declare a `#[cfg(feature ...)]`-gated
# `pub` struct field", because that is exactly the shape an exhaustive struct
# literal cannot survive: the literal only compiles for the one feature
# combination its author built with. R311y253 covered wz-runtime-tokio alone and
# NAMED the rest as a residual; the sweep that closed it found two more crates in
# the class (wz-session-core — whose ApplicationLayerObserver carries EIGHT
# independently-gated pub fields — and wz-ap-demo). Both already composed clean,
# so this is a gate over a latent hazard, not a second fix.
#
# The audit step below is what keeps the list HONEST: it re-derives the hazard set
# from the source on every run and fails if a crate joins the class without being
# added to COVERED. Without it, the next crate to grow a cfg-gated pub field would
# silently sit outside the gate — the exact way the DialConfig break shipped.
#
# Scoped per-crate deliberately: a WORKSPACE-wide `--all-features` is structurally
# impossible here — sce-rust-runtime declares `no_std` and `http-send` mutually
# exclusive (a compile_error! guard), so `--all-features` can never be a workspace
# gate. Per-crate is the only form this check can take. If a future crate in the
# class carries its own mutually-exclusive feature pair, NARROW its entry to an
# explicit max-compatible feature set — do not drop it from COVERED, which would
# restore the blind spot this lane exists to cover.
layer_c1bf_cargo_clippy_all_features() {
    # R311y566 — `wz-capi-c` JOINED the hazard class and the audit caught it on
    # HOSTED, where this lane runs and the local sweep does not. The trigger was
    # y565's `z_close_options_t` / `z_query_reply_del_options_t`, whose fields are
    # `#[cfg(feature = "zenoh-c-no-unstable-api")]`-gated — exactly the shape an
    # exhaustive struct literal cannot survive. Its two features are INDEPENDENT
    # axes rather than an exclusive pair, so `--all-features` is a real arm (the
    # no-unstable + shared-memory one) and no narrowing is needed.
    local covered=(wz-runtime-tokio wz-session-core wz-ap-demo wz-capi-c)

    # Drift audit: re-derive the hazard class from source. A crate qualifies when
    # a `#[cfg(feature ...)]` attribute is immediately followed by a `pub <field>:`
    # declaration. Deliberately over-inclusive (an enum or private struct can trip
    # it) — a false positive costs one line in COVERED, a false NEGATIVE costs a
    # shipped build break.
    local hazard=() c n
    for c in crates/*/; do
        n="$(grep -rn -A1 --include=*.rs '^[[:space:]]*#\[cfg(feature' "$c" 2>/dev/null \
             | grep -cE '^[^[:space:]]+[-:][0-9]+-[[:space:]]*pub [a-z_]+:' || true)"
        [ "${n:-0}" -gt 0 ] && hazard+=("$(basename "$c")")
    done

    local h uncovered=()
    for h in "${hazard[@]}"; do
        printf '%s\n' "${covered[@]}" | grep -qx "$h" || uncovered+=("$h")
    done
    if [ "${#uncovered[@]}" -gt 0 ]; then
        echo "  C1bf FAIL: crate(s) grew a cfg-gated pub struct field but are not"
        echo "  in the C1bf COVERED list, so no lane composes their features:"
        printf '    - %s\n' "${uncovered[@]}"
        echo "  Add them to COVERED (or narrow, if they have exclusive features)."
        return 1
    fi
    echo "  C1bf audit: hazard class = ${hazard[*]} — all covered"

    local pkg
    for pkg in "${covered[@]}"; do
        (cd crates && cargo clippy -p "$pkg" --all-targets --all-features \
            --quiet -- -D warnings) || return 1
    done
}
# ─── Layer C1bn — the PASSIVE-DISSECTION feature set, RUN ────────────
#
# R311y579. Five features and one whole CRATE landed across R311y578/y578a/y579
# for the G1-G10 passive-dissection track, and NO lane ran any of their tests.
# C1bf's per-crate `--all-features` clippy COMPILES them, which is a different
# claim: a decoder whose spans are one byte off, a whitelist that admits
# everything, an emitter zenoh cannot read -- all compile.
#
# The gap was REGISTERED as debt by R311y578 ("wz-capture and
# transport-link-tls-keylog are in no lane, ~2 lines each") and this closes it
# for both, plus the three R311y579 additions.
#
# Guards are AT-LEAST-ONE-PASSED (`[1-9][0-9]* passed`), not exact counts:
# R311y569 recorded that a bare `N passed` guard goes stale the moment a test is
# added or renamed, and the property this lane needs is "the filter matched
# something", which the loose form states without a number to maintain.
#
# `transport-link-tls-keylog` is clippy-only here BY NECESSITY, not by choice:
# its e2e (`tls_keylog_e2e`) drives a real loopback TLS session and lives in
# wz-runtime-tokio's own test dir, where Layer C1u already runs it under
# `transport-link-tls`. What no lane did was LINT the keylog feature's own two
# arms, which is where an un-called `#[cfg]` helper reds -- the exact shape of
# R311y578's G7 and of the four hosted reds R311y537 catalogued.
# ─── Layer C1bq — the runtime-zero-copy arena, BOTH arms ─────────────
#
# R311y589. `runtime-zero-copy` stopped being an empty Cargo.toml flag and
# became the first consumer any `sce:kind="buffer-pool"` emit has had, and a
# feature in no lane rots -- the §7 "gates that do not exist" shape this tree
# has now paid for three times.
#
# BOTH arms, because the seam's whole claim is that swapping the arena changes
# only WHERE the bytes land. The default arm alone would miss a pooled-only
# defect; the pooled arm alone would miss the arena default regressing every
# other Router in the tree, which is the wider blast radius of the two.
#
# The dims arm is not decoration either. `PooledStaging::new` asserts the
# Router's dims against the pool's, and the AP Router's are the pool's own
# constants -- so a lane that only ran the 4x64 unit dims would never construct
# the 32 MiB arena, which is exactly the configuration that stack-overflowed
# before `heap_pool` existed.
# ─── Layer C1br — runtime-tokio-uring, ARCHITECTURE §9.5 row 3 ───────
#
# R311y589. The inventory entry for this atom said it "needs an ARMING FLAG with
# a hosted hard-fail before it can be a lane", and that condition is what this
# lane implements rather than works around.
#
# io_uring is a KERNEL capability, so a box without it is a provisioning fact
# and a SKIP is the honest local answer. A SKIP is also green, which is the
# R311y265 masked-skip burn — so hosted (or `WZ_URING_REQUIRE=1`) turns the same
# absence into a FAIL. Same idiom as WZ_LINT_REQUIRE / WZ_QZ_REQUIRE / WZ_A3_-
# REQUIRE, and it is a bare string contract across two files: the token here
# must match ci.yml's `env:`.
#
# The probe is a real `io_uring_setup`, not a kernel-version comparison: the
# syscall is what the feature needs, and a container can refuse it on a kernel
# whose version string says it should work.
#
# ─── R311y593 — the probe measured the WRONG capability ──────────────────────
#
# `io_uring_setup` succeeding does not mean the lane can run. Registering fixed
# buffers PINS them, and pinned pages are charged to RLIMIT_MEMLOCK; the pool is
# 32 x 1 MiB, so the lane needs 32 MiB of lockable memory that `io_uring_setup`
# never asks for. Hosted run 31193705276 failed exactly there — ENOMEM out of
# `register_buffers` — while every local run passed on a workstation whose limit
# is 3.9 GiB. A machine-dependent baseline that only hosted could see.
#
# So the probe now exercises the LEG THE LANE NEEDS: a real
# `io_uring_register(IORING_REGISTER_BUFFERS)` of the required size. And because
# the limit is raisable, the lane PROVISIONS before it judges — soft up to hard,
# then `prlimit` if passwordless sudo is available, which on a CI runner it is.
# Only after both does an absence become a verdict, and the three exit codes keep
# "no io_uring" (provisioning) apart from "ENOMEM" (provisioning) and apart from
# any other errno (a defect, which is a FAIL everywhere and never a SKIP).
# `ulimit` speaks KIBIBYTES and the requirement is in BYTES. Converting at the
# one place that reads the limit — the first version of this lane printed a soft
# limit in bytes beside a hard limit in KiB, in the same sentence.
_c1br_soft_memlock_bytes() { _c1br_memlock_bytes -Sl; }
_c1br_hard_memlock_bytes() { _c1br_memlock_bytes -Hl; }
_c1br_memlock_bytes() {
    local s
    s="$(ulimit "$1")"
    if [[ "$s" == "unlimited" ]]; then echo "-1"; else echo "$(( s * 1024 ))"; fi
}

# Raise this shell's RLIMIT_MEMLOCK toward `$1` bytes, by the two routes an
# unprivileged process has. Best-effort throughout: every failure here is
# reported by the probe that follows, so a silent `|| true` cannot hide one.
_c1br_raise_memlock() {
    local need="$1" hard soft
    hard="$(ulimit -Hl)"
    if [[ "$hard" == "unlimited" ]]; then
        ulimit -l unlimited 2>/dev/null || true
    else
        ulimit -l "$hard" 2>/dev/null || true
    fi
    soft="$(_c1br_soft_memlock_bytes)"
    if [[ "$soft" != "-1" ]] && (( soft < need )) && sudo -n true 2>/dev/null; then
        # Raising the HARD limit needs privilege. A CI runner is precisely where
        # that is available, and `prlimit` on our own pid is the narrowest form
        # of it — no test runs as root.
        #
        # UNLIMITED, not `need`. Provisioning exactly one registration's worth is
        # what the first version did, and it produced a second failure that took
        # a bisect to read: io_uring context teardown is DEFERRED, so a binary
        # that registers the pool in several tests still holds the earlier
        # charges when the next one registers, even run single-threaded. The
        # minimum is the PROBE's business (below); what a host should grant a
        # lane that pins memory is as much as it will.
        sudo -n prlimit --memlock=unlimited:unlimited --pid $$ 2>/dev/null \
            || sudo -n prlimit "--memlock=${need}:${need}" --pid $$ 2>/dev/null || true
        ulimit -l unlimited 2>/dev/null \
            || ulimit -l "$(( (need + 1023) / 1024 ))" 2>/dev/null || true
    fi
}

layer_c1br_uring_fixed_buffers() {
    local out need rc soft hard count size pool_bytes page

    # The requirement is READ from the generated pool, never written down here.
    # The same fact reached by two paths always drifts (R311y589's own lesson),
    # and this one moves whenever `sources/network/reassembly_pool_ap.scxml`
    # does — a resized pool must not leave a stale number in a provisioning gate.
    read -r count size < <(python3 - <<'PY'
import re, sys
src = open("out/wz-runtime-tokio/reassembly_pool_ap.rs", encoding="utf-8").read()
def const(name):
    m = re.search(r"pub const %s: usize = (\d+);" % name, src)
    if not m:
        sys.exit("C1br: cannot read %s from the generated pool" % name)
    return int(m.group(1))
print(const("SLOT_COUNT"), const("SLOT_SIZE"))
PY
    ) || { echo "  C1br FAIL: could not derive the locked-byte requirement" >&2; return 1; }
    [[ -n "$count" && -n "$size" ]] || {
        echo "  C1br FAIL: the pool dims did not parse" >&2; return 1; }

    # The kernel charges WHOLE PAGES per registered region, and the pool's slots
    # are not page-aligned, so each of the `count` regions can straddle one extra
    # page. Provisioning the bare pool size is what the first version of this
    # lane did, and the kernel refused at exactly the limit. One page per region
    # plus one is the worst case, stated rather than fudged.
    pool_bytes=$(( count * size ))
    page="$(getconf PAGESIZE 2>/dev/null || echo 4096)"
    need=$(( pool_bytes + count * page + page ))

    _c1br_raise_memlock "$need"
    soft="$(_c1br_soft_memlock_bytes)"
    hard="$(_c1br_hard_memlock_bytes)"

    # The probe registers the SAME SHAPE the adapter does — `count` separate
    # regions of `size`, not one big one — because the page-straddle above is a
    # property of the shape. A single-region probe would pass while the real
    # registration of the same total failed.
    python3 - "$count" "$size" <<'PY'
import ctypes, os, sys
count, size = int(sys.argv[1]), int(sys.argv[2])
libc = ctypes.CDLL(None, use_errno=True)
class P(ctypes.Structure):
    _fields_ = [("sq_entries", ctypes.c_uint32), ("cq_entries", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("sq_thread_cpu", ctypes.c_uint32),
                ("sq_thread_idle", ctypes.c_uint32), ("features", ctypes.c_uint32),
                ("wq_fd", ctypes.c_uint32), ("resv", ctypes.c_uint32 * 3),
                ("sq_off", ctypes.c_uint64 * 10), ("cq_off", ctypes.c_uint64 * 10)]
class IoVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]
p = P()
fd = libc.syscall(425, 8, ctypes.byref(p))        # io_uring_setup
if fd < 0:
    sys.exit(2)
bufs = [ctypes.create_string_buffer(size) for _ in range(count)]
iovs = (IoVec * count)(*[IoVec(ctypes.cast(b, ctypes.c_void_p), size) for b in bufs])
rc = libc.syscall(427, fd, 0, ctypes.byref(iovs), count)  # io_uring_register, BUFFERS
err = ctypes.get_errno()
os.close(fd)
sys.exit(0 if rc >= 0 else (3 if err == 12 else 4))
PY
    rc=$?
    if (( rc != 0 )); then
        local why
        case "$rc" in
            2) why="io_uring_setup refused by this kernel" ;;
            3) why="io_uring_register refused ${count}x${size} locked bytes with ENOMEM (needed ${need} incl. page headroom; RLIMIT_MEMLOCK after raising: soft=${soft} hard=${hard} bytes, -1 = unlimited)" ;;
            *) why="the io_uring capability probe failed with an errno that is NOT ENOMEM (rc=${rc}) — that is a defect, not provisioning" ;;
        esac
        if (( rc == 4 )); then
            echo "  C1br FAIL: ${why}" >&2
            return 1
        fi
        if [[ "${WZ_URING_REQUIRE:-0}" == "1" || "${GITHUB_ACTIONS:-}" == "true" ]]; then
            echo "  C1br FAIL: ${why}, and WZ_URING_REQUIRE/GITHUB_ACTIONS is set" >&2
            return 1
        fi
        echo "  C1br SKIP (${why}; set WZ_URING_REQUIRE=1 to make it a FAIL)"
        return 0
    fi

    (cd crates && cargo clippy -p wz-runtime-tokio \
        --features runtime-tokio-uring --all-targets --quiet -- -D warnings) || return 1

    # SERIALIZED, and that is a resource fact rather than a style choice: each
    # registering test pins the WHOLE pool, so two of them in parallel ask for
    # twice the pool and the second gets ENOMEM. Invisible on a box whose limit
    # is gigabytes; it is what the lane hit the moment the limit was provisioned
    # to exactly what one registration needs.
    out="$(cd crates && cargo test -p wz-runtime-tokio --features runtime-tokio-uring \
        --lib uring:: --quiet -- --test-threads=1 2>&1)" || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1br FAIL: the uring filter matched no test"; echo "$out"; return 1; }

    # The subset that has NO transport. R311y589 found a pre-existing dead-code
    # hole exactly here: `reassembly_config`'s cfg omitted both its callers'
    # gates, and nothing selected a `reassembly`-without-transport build until
    # this feature implied one.
    (cd crates && cargo build -p wz-runtime-tokio --no-default-features \
        --features runtime-tokio-uring --quiet) || return 1
    return 0
}

# ─── Layer C1bs — live-capture, the AF_PACKET tap (R311y594 / B1) ────
#
# Two capabilities, kept apart because they fail for different reasons and a
# reader must not have to guess which one bit.
#
#   1. The FEED LOOP and the dissection wiring need no privilege at all — the
#      module carries a canned `PacketSource` precisely so the part with logic
#      in it is provable on any host. That half is a hard FAIL everywhere.
#   2. The SOCKET (`AF_PACKET`, `SO_TIMESTAMP`, the CMSG walk) needs
#      CAP_NET_RAW. That half is `#[ignore]`d and run here when the capability
#      is present, because a path that exists and never runs is the shape this
#      repo keeps paying for.
#
# The capability is PROBED by opening the socket, not by comparing uid to 0: a
# ── R311y665 (§1.2a) — Layer C1bw: the analyzer's COMMAND LINE.
#
# `wz-analyze` is the composition root R311y664 added, and it was in no lane of
# its own: `cargo test --workspace` (Layer C1) builds and runs it, and that is
# precisely the coverage this project has repeatedly found to be invisible when
# it stops. A binary target that fails to build, or an integration test that
# silently stops being compiled, does not announce itself in a workspace run's
# summary line -- it just contributes zero.
#
# So this lane does the two things a workspace run does not:
#   1. builds the BINARY (`--bins`), which `cargo test` alone does not link;
#   2. pins the SET of binary-level test names present, on the R311y634 rule
#      (pin a SET, never a COUNT), so a test that stops being compiled reds
#      instead of quietly leaving.
layer_c1bw_analyze_cli() {
    local out listing missing name
    (cd crates && cargo clippy -p wz-analyze --all-targets --quiet -- -D warnings) || return 1
    (cd crates && cargo build -p wz-analyze --bins --quiet) || {
        echo "  C1bw FAIL: the wz-analyze binary does not build"; return 1; }

    out="$(cd crates && cargo test -p wz-analyze --quiet 2>&1)" || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bw FAIL: wz-analyze ran no tests"
        echo "$out"; return 1; }

    listing="$(cd crates && cargo test -p wz-analyze --test binary -- --list 2>/dev/null)" \
        || { echo "  C1bw FAIL: the binary-level tests did not list"; return 1; }
    missing=0
    for name in \
        the_binary_decrypts_a_capture_given_a_key_log_on_the_command_line \
        the_exit_code_separates_an_incomplete_capture_from_a_failed_run \
        an_unreadable_key_log_fails_instead_of_reporting_the_capture_as_encrypted \
        the_flows_option_names_which_connection_the_summary_cannot \
        the_json_rendering_is_a_single_document_even_with_flows \
        the_messages_option_lists_what_was_read_and_not_only_how_much
    do
        grep -qF "$name: test" <<<"$listing" || {
            echo "  C1bw FAIL: $name is absent from the binary test target"
            missing=1
        }
    done
    [[ $missing -eq 0 ]] || return 1
    echo "  C1bw: the analyzer builds as a program and its command line is gated"
}

# container can grant CAP_NET_RAW to a non-root process and a root process can
# be denied it by seccomp. Same arming-flag contract as C1br — a green SKIP on
# hosted is the R311y265 masked-skip burn.
layer_c1bs_live_capture() {
    local out bin

    (cd crates && cargo clippy -p wz-runtime-tokio \
        --features live-capture --all-targets --quiet -- -D warnings) || return 1

    out="$(cd crates && cargo test -p wz-runtime-tokio --features live-capture \
        --lib live_capture:: --quiet 2>&1)" || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bs FAIL: the live_capture filter matched no test"; echo "$out"; return 1; }

    # The privileged half. Build as THIS user and run the binary under sudo, so
    # the cargo target dir never acquires root-owned artefacts.
    bin="$(cd crates && cargo test -p wz-runtime-tokio --features live-capture \
        --lib --no-run --message-format=short 2>&1 \
        | grep -oE 'target/debug/deps/wz_runtime_tokio-[a-f0-9]+' | tail -1)"
    if [[ -z "$bin" ]]; then
        echo "  C1bs FAIL: could not locate the built test binary" >&2
        return 1
    fi

    local runner=()
    if ./crates/"$bin" --list >/dev/null 2>&1 && _c1bs_has_net_raw; then
        runner=()
    elif sudo -n true 2>/dev/null; then
        runner=(sudo -n)
    else
        if [[ "${WZ_LIVECAP_REQUIRE:-0}" == "1" || "${GITHUB_ACTIONS:-}" == "true" ]]; then
            echo "  C1bs FAIL: CAP_NET_RAW is absent and no passwordless sudo, and WZ_LIVECAP_REQUIRE/GITHUB_ACTIONS is set" >&2
            return 1
        fi
        echo "  C1bs SKIP (the socket half needs CAP_NET_RAW; set WZ_LIVECAP_REQUIRE=1 to make it a FAIL)"
        return 0
    fi

    # BOTH ignored tests: the real socket read AND the flood measurement. The
    # measurement does not gate on its rate -- a throughput number on a shared
    # runner is noise -- but it RUNS, so the figure in the module docs has a
    # second run behind it instead of being a sentence someone typed once.
    # SERIALIZED, and measured: run in parallel these two failed 3 of 8 times.
    # They share the loopback interface -- the flood's 20 000 packets arrive on
    # the other test's tap and push its probe packet past the search budget --
    # so this is resource coupling, not flakiness to retry away.
    out="$("${runner[@]}" ./crates/"$bin" live_capture::tests:: \
        --ignored --nocapture --test-threads=1 2>&1)" || { echo "$out"; return 1; }
    # A filter that matches nothing reports `ok. 0 passed`, which is green and
    # says nothing -- the exact trap this lane exists to avoid.
    grep -qE '^test result: ok\. 2 passed' <<<"$out" || {
        echo "  C1bs FAIL: the privileged tap tests did not both run"; echo "$out"; return 1; }
    # Surface the measurement in the lane log; a number nobody sees is a number
    # nobody checks.
    # NOT anchored: with `--test-threads=1 --nocapture` libtest prints the test
    # NAME on the same line before the test's own stdout, so `^live tap:` never
    # matches. Measured on hosted run 31228323741, where the lane passed and
    # printed nothing -- the number this echo exists to surface was invisible in
    # exactly the way its own comment warns about.
    grep -oE 'live tap: .*' <<<"$out" || true
    return 0
}

# CAP_NET_RAW in the process's own effective set, read from /proc rather than
# inferred from uid.
_c1bs_has_net_raw() {
    local eff
    eff="$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null)" || return 1
    [[ -n "$eff" ]] || return 1
    # CAP_NET_RAW is bit 13.
    python3 -c "import sys; sys.exit(0 if (int('$eff', 16) >> 13) & 1 else 1)"
}

layer_c1bq_zero_copy_arena() {
    local out
    (cd crates && cargo clippy -p wz-runtime-tokio \
        --features runtime-zero-copy --all-targets --quiet -- -D warnings) || return 1

    out="$(cd crates && cargo test -p wz-runtime-tokio --features runtime-zero-copy \
        --lib zero_copy:: --quiet 2>&1)" || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bq FAIL: the zero_copy filter matched no test"; echo "$out"; return 1; }

    # The DEFAULT arena, which every other Router in the tree runs. The seam
    # moved `reassembly_dispatch`'s staging out from under all of them.
    out="$(cd crates && cargo test -p wz-session-core --features reassembly \
        --lib reassembly_dispatch:: --quiet 2>&1)" || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bq FAIL: the reassembly_dispatch filter matched no test"; echo "$out"; return 1; }

    # The feature must compose with the transports that actually drive a Router,
    # not only standalone: the unicast and multicast loops each thread the
    # dispatcher through their own generic paths.
    (cd crates && cargo clippy -p wz-runtime-tokio \
        --features runtime-zero-copy,transport-unicast,transport-multicast,transport-fragmentation \
        --all-targets --quiet -- -D warnings) || return 1

    # The facade arm the preset actually ships.
    (cd crates && cargo build -p wz --features preset-ap-full --quiet) || return 1
    return 0
}

layer_c1bo_dissect_c_abi() {
    # R311y587 — the dissection C ABI, driven from a REAL C translation unit.
    #
    # The Rust tests in `wz-capi-dissect` cover the functions. Only C covers
    # what is ONLY true across the boundary: that the header compiles, that the
    # symbols export under the names it declares, that the calling convention
    # agrees, and that a string allocated in Rust can be released from C.
    # R311y586 proved all four by hand, which is the shape that rots.
    #
    # `cc` absent -> SKIP, not FAIL: the Rust half still gates on every host,
    # and a box without a C compiler is a provisioning fact rather than a
    # defect. Hosted has one, so the leg runs where it matters.
    local out cc
    cc="${CC:-cc}"
    command -v "$cc" >/dev/null 2>&1 || {
        echo "  C1bo SKIP (no C compiler: $cc)"; return 0; }

    (cd crates && cargo clippy -p wz-capi-dissect --all-targets --quiet -- -D warnings) || return 1
    out="$(cd crates && cargo test -p wz-capi-dissect --quiet 2>&1)" || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bo FAIL: wz-capi-dissect ran no tests"; echo "$out"; return 1; }

    # The cdylib the C side links. `--release` on purpose: it is the artifact a
    # consumer ships against, and a debug-only link would not exercise the
    # symbol set LTO produces.
    (cd crates && cargo build -p wz-capi-dissect --release --quiet) || return 1

    local bin
    bin="$(mktemp -d)/c_abi_consumer"
    out="$("$cc" -Wall -Wextra -Werror \
        -I crates/wz-capi-dissect/include \
        crates/wz-capi-dissect/tests/c_abi_consumer.c \
        -L crates/target/release -lwz_capi_dissect -o "$bin" 2>&1)" || {
        echo "  C1bo FAIL: the C consumer did not compile or link"; echo "$out"; return 1; }
    out="$(LD_LIBRARY_PATH=crates/target/release "$bin" 2>&1)" || {
        echo "$out"; rm -rf "$(dirname "$bin")"; return 1; }
    echo "$out"
    rm -rf "$(dirname "$bin")"

    # The header must compile as C++ too: the consumer this ABI exists for is
    # [REDACTED], and a header that only works in C is found at integration time.
    command -v c++ >/dev/null 2>&1 && {
        out="$(c++ -fsyntax-only -x c++ -I crates/wz-capi-dissect/include \
            crates/wz-capi-dissect/tests/c_abi_consumer.c 2>&1)" || {
            echo "  C1bo FAIL: the header does not compile as C++"; echo "$out"; return 1; }
    }
    return 0
}

# R311y612 (§5.11) — wz-capture at `--no-default-features`, which NO lane had.
#
# The gap was not hypothetical. R311y609 found that `wz-capture` did not
# COMPILE without its default `reassembly` feature and fixed it; nothing was
# added that would notice the next time, so the fix was one edit away from
# silently regressing. C1bn above builds the crate at its DEFAULT features, and
# a `--workspace` build unifies `reassembly` back on from wz-runtime-tokio, so
# neither can see this.
#
# Two claims, and the second is the one a bare `cargo test` cannot make:
#   1. it builds and its tests RUN (count floor, not `exit 0`);
#   2. the tests that matter are PRESENT in this build. A `#[cfg]`-gated test
#      that vanishes at no-default reports `ok. N passed` with N silently
#      smaller — the shape R311y611 hit when three MID censuses had to be
#      confirmed in the no-default `--list` one by one. The SET is pinned, not
#      the count, so adding a test does not red the lane and losing one does.
layer_c1bt_capture_no_default_features() {
    local out listing missing name
    (cd crates && cargo clippy -p wz-capture --no-default-features --all-targets \
        --quiet -- -D warnings) || return 1

    out="$(cd crates && cargo test -p wz-capture --no-default-features --quiet 2>&1)" \
        || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bt FAIL: wz-capture ran no tests at --no-default-features"
        echo "$out"; return 1; }

    listing="$(cd crates && cargo test -p wz-capture --no-default-features -- --list 2>/dev/null)" \
        || { echo "  C1bt FAIL: --list did not run"; return 1; }
    missing=0
    for name in \
        ws::tests::the_ws_chain_discriminator_refuses_noise \
        ws::tests::an_announced_gap_no_longer_ends_the_flow \
        ws::tests::a_recovery_never_joins_the_two_sides_of_a_hole \
        ws::tests::a_deframer_with_no_opening_scans_to_the_first_boundary \
        ws::tests::a_ws_scan_that_confirms_nothing_drops_what_it_cannot_frame \
        ws_flow_tests::a_hole_in_the_opening_is_decided_on_the_far_side_rather_than_guessed \
        ws_flow_tests::the_other_directions_opening_settles_a_hole_in_this_one \
        ws_flow_tests::every_mid_on_a_websocket_link_is_named_rather_than_unknown \
        datagram_tests::announcing_the_hole_stops_the_reader_swallowing_the_frames_after_it \
        datagram_tests::a_link_type_this_build_cannot_read_is_named_and_arp_is_not_it \
        datagram_tests::the_skip_census_survives_the_cap_the_skipped_list_does_not \
        ws::tests::every_structural_desync_recovers_and_not_only_the_announced_one \
        ws_flow_tests::a_structural_desync_mid_segment_does_not_end_the_flow \
        datagram_tests::a_frame_carries_the_capture_instant_in_every_feature_arm \
        report::tests::every_character_json_requires_escaping_is_escaped_as_the_rfc_names_it \
        report::tests::a_keyexpr_cannot_end_the_field_it_is_printed_in \
        filter::tests::a_record_whose_keyexpr_never_resolved_is_undecided_rather_than_rejected \
        filter::tests::a_clockless_capture_cannot_decide_a_time_term \
        filter::tests::the_three_valued_connectives_follow_kleene_rather_than_infecting \
        filter::tests::a_malformed_selector_is_refused_by_name_rather_than_guessed \
        filter::tests::a_wildcard_pattern_is_refused_where_the_matcher_cannot_honour_it \
        filter::tests::each_outcome_field_reads_the_axis_it_names \
        filter::tests::an_unanswered_exchange_and_a_slow_one_are_both_expressible \
        filter::tests::a_plane_that_does_not_correlate_exchanges_cannot_decide_an_outcome_term \
        filter::tests::the_outcome_fields_refuse_what_they_do_not_admit \
        filter::tests::the_elapsed_axis_reads_the_capture_relative_clock \
        payload::tests::the_encoding_table_is_the_wire_table_and_the_index_is_the_id \
        payload::tests::an_id_outside_the_table_is_reported_rather_than_defaulted \
        payload::tests::a_payload_that_contradicts_its_declaration_is_a_finding_with_an_offset \
        payload::tests::the_json_scanner_follows_rfc_8259_rather_than_being_permissive \
        payload::tests::the_json_adjacent_encodings_are_not_judged_as_strict_json \
        datagram_tests::the_compression_offer_is_the_entry_the_ext_codec_names \
        datagram_tests::the_compressed_fixture_negotiates_compression_and_establishes \
        report::tests::an_undecompressible_capture_reaches_the_document_in_its_own_slot \
        agg::no_codec_tests::a_build_without_the_network_codecs_reports_the_traffic_as_unread \
        agg::no_codec_tests::a_frame_carrying_nothing_is_not_reported_as_unread \
        datagram_tests::the_capture_clock_is_sticky_and_an_unstamped_packet_inherits_it \
        datagram_tests::a_capture_with_no_stamp_anywhere_leaves_every_frame_timeless \
        tls_flow_tests::a_tls_flow_is_named_as_encrypted_rather_than_reported_empty \
        tls_flow_tests::a_zenoh_stream_that_opens_like_a_client_hello_is_still_a_zenoh_stream \
        tls_flow_tests::a_chain_that_stops_being_tls_stops_the_census \
        tls_flow_tests::a_plaintext_capture_carries_the_encrypted_fields_at_zero \
        tls_flow_tests::a_capture_that_began_mid_session_is_still_recognised_as_encrypted \
        tls_flow_tests::a_capture_of_only_the_servers_half_is_recognised \
        tls_flow_tests::one_record_is_a_coincidence_and_the_depth_is_what_refuses_it \
        tls_flow_tests::a_hole_while_the_chain_is_still_shallow_does_not_force_a_stream \
        tls_flow_tests::an_evicted_encrypted_flows_finding_stays_in_the_report \
        tls_flow_tests::an_evicted_flow_settles_the_verdict_it_was_still_holding \
        tls_flow_tests::a_flow_still_deciding_when_the_capture_ends_settles_too \
        tls_flow_tests::an_evicted_flow_that_was_still_held_accounts_for_its_bytes \
        datagram_tests::the_datagram_flow_table_is_bounded_by_the_same_limit \
        datagram_tests::a_scouting_only_capture_is_bounded_too \
        datagram_tests::an_evicted_datagram_flows_sequence_accounting_stays_in_the_total \
        datagram_tests::the_scouting_list_is_bounded_and_the_loss_is_counted \
        datagram_tests::the_flow_table_evicts_the_least_recently_active \
        vsock_flow_tests::the_vsock_flow_table_evicts_the_least_recently_active \
        datagram_tests::the_stream_paths_frame_cap_keeps_the_most_recent \
        datagram_tests::frames_are_capped_per_flow_and_the_loss_is_counted \
        datagram_tests::a_capture_that_abandoned_nothing_carries_the_field_at_zero \
        tls_flow_tests::the_client_hello_random_reaches_the_report \
        tls_flow_tests::a_flow_recognised_by_its_chain_has_no_random_to_offer \
        tls_flow_tests::the_kept_records_are_numbered_by_what_is_protected \
        tls_flow_tests::a_flow_whose_records_open_yields_zenoh_frames_and_says_it_was_decrypted \
        tls_flow_tests::a_decrypted_frames_offset_resolves_to_the_packet_that_carried_it \
        tls_flow_tests::a_post_handshake_message_is_opened_and_not_fed_to_the_zenoh_reader \
        tls_flow_tests::a_record_that_refuses_the_keys_stops_its_direction_and_is_named \
        tls_flow_tests::a_declined_flow_reports_the_openers_reason_and_opens_nothing \
        tls_flow_tests::a_mid_session_flow_is_announced_with_no_identity \
        tls_flow_tests::a_second_decryption_pass_does_not_decode_the_same_records_twice \
        tls_flow_tests::the_report_states_what_the_decryption_pass_actually_found \
        tls_flow_tests::a_record_after_a_hole_carries_the_offset_the_hole_put_it_at \
        tls_flow_tests::a_capture_is_not_decrypted_while_one_of_its_flows_is_not \
        tls_flow_tests::a_capture_files_own_decryption_secrets_reach_the_dissection
    do
        grep -qF "$name: test" <<<"$listing" || {
            echo "  C1bt FAIL: $name is absent from the --no-default-features build"
            missing=1; }
    done
    (( missing == 0 )) || return 1

    # R311y614 — the NETWORK half, and it needs its own arm rather than more
    # rows above. `network-codecs` is switchable (it had to become so: naming
    # those five codecs unconditionally widened every dependent's
    # wz-session-core feature set and killed Layer C1bi's negative arm), so the
    # census and aggregation tests do not EXIST at `--no-default-features` and
    # a pin listing them would be asserting the impossible.
    #
    # What is asserted instead is that the feature COMPOSES ALONE: without
    # `reassembly`, with only the network codecs, the data plane is still named.
    # That combination is built by no other lane, and it is the one a consumer
    # who wants records and not chains would ask for.
    out="$(cd crates && cargo test -p wz-capture --no-default-features \
        --features network-codecs --quiet 2>&1)" || { echo "$out"; return 1; }
    listing="$(cd crates && cargo test -p wz-capture --no-default-features \
        --features network-codecs -- --list 2>/dev/null)" \
        || { echo "  C1bt FAIL: the network-codecs --list did not run"; return 1; }
    for name in \
        datagram_tests::every_network_mid_inside_a_frame_is_named_rather_than_unknown \
        datagram_tests::every_network_mid_inside_a_frame_is_named_over_a_stream_too \
        ws_flow_tests::every_network_mid_inside_a_frame_is_named_over_websocket_too \
        agg::tests::the_mapping_bit_picks_the_space_and_the_observer_holds_both \
        agg::tests::an_unbound_alias_is_reported_rather_than_guessed \
        agg::tests::a_halted_batch_is_reported_rather_than_quietly_short \
        agg::tests::an_intact_capture_reports_no_gap_at_all \
        exchange::tests::the_fixture_puts_real_request_and_response_records_on_the_wire \
        exchange::tests::a_query_exchange_reports_its_latency_at_the_tap \
        exchange::tests::a_capture_without_timestamps_reports_no_latency_rather_than_zero \
        exchange::tests::each_direction_owns_its_request_id_space \
        report::tests::an_incomplete_capture_says_so_in_both_renderings \
        report::tests::an_unmeasured_latency_is_null_in_json_and_named_in_text \
        agg::tests::a_reference_the_capture_never_bound_is_undecided_rather_than_dropped \
        agg::tests::a_declaration_is_absorbed_even_when_the_selector_would_not_pick_it \
        agg::tests::a_filter_cannot_hide_a_gap \
        report::tests::a_filtered_report_says_what_the_selector_could_not_judge \
        payload::census_tests::the_fixture_puts_a_declared_encoding_on_the_wire \
        payload::census_tests::a_publisher_contradicting_its_own_encoding_is_named_with_its_keyexpr \
        payload::census_tests::binary_payloads_are_never_a_contradiction \
        report::tests::a_payload_contradiction_is_a_finding_and_not_an_incompleteness \
        exchange::tests::the_identity_filter_is_the_unfiltered_exchange_plane \
        exchange::tests::the_responses_to_a_rejected_request_are_not_orphans \
        exchange::tests::an_unresolvable_request_keyexpr_is_undecided_rather_than_rejected \
        payload::census_tests::an_encoding_id_the_wire_carries_and_this_build_cannot_name_is_counted \
        payload::census_tests::a_selector_narrows_what_a_finding_can_be_about \
        payload::census_tests::a_payload_carried_by_a_response_answers_kind_reply \
        report::tests::one_selector_narrows_every_plane_of_the_report \
        report::tests::one_undecided_plane_makes_the_page_a_floor_when_it_is_the_only_plane \
        agg::tests::a_batch_this_build_cannot_decompress_is_counted_rather_than_missing \
        exchange::tests::a_batch_this_build_cannot_decompress_is_unread_rather_than_absent \
        payload::census_tests::a_batch_this_build_cannot_decompress_is_a_gap_and_not_a_finding \
        payload::census_tests::the_err_term_selects_error_payloads_and_leaves_the_rest \
        payload::census_tests::a_payload_the_capture_does_not_hold_is_named_rather_than_judged \
        payload::census_tests::an_extension_sharing_the_id_field_is_not_the_shm_marker \
        agg::tests::the_parts_account_for_every_record_walked \
        exchange::tests::the_four_outcomes_fixture_really_carries_four_different_outcomes \
        exchange::tests::a_first_reply_term_picks_the_slow_exchange_out_of_four \
        exchange::tests::a_replies_term_picks_the_exchanges_nothing_answered \
        exchange::tests::the_exchange_that_never_closed_is_judged_and_not_merely_counted \
        exchange::tests::an_outcome_rejection_leaves_no_trace_in_the_totals \
        exchange::tests::moving_the_verdict_to_the_close_did_not_move_what_time_means \
        exchange::tests::the_throughput_plane_reports_an_outcome_term_as_undecided_not_empty \
        agg::tests::the_fixture_puts_a_valued_query_and_a_bare_one_on_the_wire \
        agg::tests::a_querys_value_is_measured_and_an_unresolvable_body_still_is_not \
        agg::tests::a_bytes_term_decides_a_measured_query_and_declines_an_unresolvable_one \
        report::tests::an_unsizable_payload_reaches_the_document_and_the_verdict \
        agg::tests::the_capture_origin_is_the_earliest_instant_over_every_packet \
        agg::tests::an_elapsed_window_selects_what_an_absolute_one_would_and_time_does_not \
        agg::tests::a_hand_folded_plane_cannot_decide_an_elapsed_term \
        agg::tests::a_records_offset_in_its_unit_reaches_the_selector \
        agg::tests::a_topic_split_across_keys_is_invisible_to_the_flat_ranking \
        agg::tests::a_flat_key_space_names_no_subtree \
        report::tests::the_keyexpr_hierarchy_reaches_both_renderings \
        report::tests::a_capture_under_an_unreadable_link_type_says_so_in_both_renderings \
        agg::tests::a_stamped_record_yields_a_one_way_delay_and_an_ahead_clock_declines \
        report::tests::an_offset_source_clock_is_named_in_both_renderings \
        agg::tests::each_carrier_puts_three_distinct_records_on_the_wire \
        agg::tests::a_descriptor_slot_is_unsized_on_every_carrier_and_a_plain_one_is_measured \
        agg::tests::a_body_ext_sharing_the_markers_id_field_leaves_the_payload_measured \
        agg::tests::a_bytes_term_over_a_descriptor_slot_is_undecided_rather_than_its_length \
        agg::tests::a_records_offset_is_measured_from_the_front_of_the_unit \
        agg::tests::the_three_planes_place_one_record_at_one_byte \
        agg::tests::an_absent_payload_and_an_unseparated_one_are_different_facts \
        report::tests::the_two_reasons_a_payload_is_unmeasured_reach_both_renderings \
        report::tests::a_row_says_whether_its_own_byte_total_is_whole
    do
        grep -qF "$name: test" <<<"$listing" || {
            echo "  C1bt FAIL: $name is absent from the network-codecs build"
            missing=1; }
    done
    (( missing == 0 )) || return 1

    # R311y616 — a THIRD arm, for the same reason R311y614 added the second: the
    # filter language's wildcard half exists only where `filter-wildcards` is
    # on, and its end-to-end proof needs the network codecs to have records to
    # judge. No other lane builds `network-codecs + filter-wildcards WITHOUT
    # reassembly`, and that is precisely the shape a consumer who wants records
    # and selectors but not chain tracking would ask for.
    #
    # The pin is one test on purpose: the arm exists to prove the two features
    # COMPOSE, and the language's own semantics are pinned in the first arm
    # where they run without any of this.
    out="$(cd crates && cargo test -p wz-capture --no-default-features \
        --features network-codecs,filter-wildcards --quiet 2>&1)" || { echo "$out"; return 1; }
    listing="$(cd crates && cargo test -p wz-capture --no-default-features \
        --features network-codecs,filter-wildcards -- --list 2>/dev/null)" \
        || { echo "  C1bt FAIL: the filter-wildcards --list did not run"; return 1; }
    for name in \
        agg::tests::a_selector_narrows_the_table_and_says_what_it_left_out \
        filter::tests::a_wildcard_pattern_matches_the_way_zenohs_own_matcher_does
    do
        grep -qF "$name: test" <<<"$listing" || {
            echo "  C1bt FAIL: $name is absent from the filter-wildcards build"
            missing=1; }
    done
    (( missing == 0 )) || return 1
    echo "  C1bt: wz-capture builds, tests and keeps its framing suite without default features"
}

layer_c1bn_passive_dissection_features() {
    # `name` is LOCAL on purpose: bash scopes dynamically, so a loop variable
    # left global here overwrites `run_layer`'s own `local name` and the lane
    # reports its pass under the name of the last test it pinned. C1bt beside it
    # declares the same four for the same reason.
    local out listing name
    (cd crates && cargo clippy -p wz-capture --all-targets --quiet -- -D warnings) || return 1
    out="$(cd crates && cargo test -p wz-capture --quiet 2>&1)" || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bn FAIL: wz-capture ran no tests"; echo "$out"; return 1; }

    # R311y645 — the tests that need BOTH `reassembly` and `network-codecs`, so
    # C1bt's arms cannot see them: its network arm has no reassembly and its
    # default-off arm has neither. This is the only lane that builds the pair,
    # which makes it the only place their names can be held down — and a name
    # pin is what R311y636 showed to be a gate in its own right: a test hidden
    # behind one more `#[cfg]` still leaves a green suite behind it.
    listing="$(cd crates && cargo test -p wz-capture -- --list 2>/dev/null)" \
        || { echo "  C1bn FAIL: the wz-capture --list did not run"; return 1; }
    for name in \
        agg::tests::a_reassembled_record_declines_the_offset_it_never_had \
        report::tests::a_record_with_no_offset_in_the_capture_is_named_in_both_renderings
    do
        grep -qF "$name: test" <<<"$listing" || {
            echo "  C1bn FAIL: $name is absent from the default build"; return 1; }
    done

    out="$(cd crates && cargo test -p wz-session-core --features dissect-serde dissect:: --quiet 2>&1)" \
        || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bn FAIL: the dissect filter matched no test"; echo "$out"; return 1; }

    # R311y605 — the JOIN arm of `parse_inbound`. Its own filter because the
    # `dissect::` one above cannot reach it: the tests live in `inbound`, and
    # the defect they pin was that the PASSIVE observer's parser reported every
    # multicast peer announcement as `Unknown { mid: 7 }` — a SUCCESSFUL parse,
    # which is why no coarse assertion anywhere noticed.
    out="$(cd crates && cargo test -p wz-session-core --features dissect,session-unicast inbound::join_tests:: --quiet 2>&1)" \
        || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bn FAIL: the join_tests filter matched no test"; echo "$out"; return 1; }

    out="$(cd crates && cargo test -p wz-session-core --features transport-link-raweth raweth_link:: --quiet 2>&1)" \
        || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bn FAIL: the raweth_link filter matched no test"; echo "$out"; return 1; }

    out="$(cd crates && cargo test -p wz-runtime-tokio --features transport-link-raweth raweth_socket:: --quiet 2>&1)" \
        || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bn FAIL: the raweth_socket filter matched no test"; echo "$out"; return 1; }

    out="$(cd crates && cargo test -p wz-runtime-tokio --features zenoh-config-emit zenoh_config:: --quiet 2>&1)" \
        || { echo "$out"; return 1; }
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<<"$out" || {
        echo "  C1bn FAIL: the zenoh_config filter matched no test"; echo "$out"; return 1; }

    # The keylog feature's OWN arms. Each pairs it with the link it installs the
    # sink on; a lane that never selects a feature is a lane that never lints it.
    (cd crates && cargo clippy -p wz-runtime-tokio \
        --features transport-link-tls,transport-link-tls-keylog \
        --all-targets --quiet -- -D warnings) || return 1
    (cd crates && cargo clippy -p wz-runtime-tokio \
        --features transport-link-quic,transport-link-tls-keylog \
        --all-targets --quiet -- -D warnings) || return 1

    # The no-default-features arms: each new module must compose STANDALONE, not
    # only inside the default set that happens to bring its dependencies.
    (cd crates && cargo clippy -p wz-session-core --no-default-features \
        --features dissect --all-targets --quiet -- -D warnings) || return 1
    (cd crates && cargo clippy -p wz-session-core --no-default-features \
        --features transport-link-raweth --all-targets --quiet -- -D warnings) || return 1
    # R311y605 — `codec-join`, in BOTH shapes, and the second one is the one
    # that earned its place. `codec-join` alone leaves `inbound` out (the module
    # is alloc-gated), so it proves only that `join_decode` composes;
    # `alloc,codec-join` is the ONLY shape in which no sibling codec pulls in
    # `ext_chain`, `FLAG_T_Z`, or `Vec`, and it found three separate cfg-union
    # holes that the workspace build and every richer subset unified away.
    (cd crates && cargo clippy -p wz-session-core --no-default-features \
        --features codec-join --all-targets --quiet -- -D warnings) || return 1
    (cd crates && cargo clippy -p wz-session-core --no-default-features \
        --features alloc,codec-join --all-targets --quiet -- -D warnings) || return 1
    # R311y607 — the SCOUTING pair, for exactly the reason the line above
    # exists, and it found the same class of hole a second time: `FLAG_T_Z` and
    # `decode_ext_chain` both listed every transport carrier and neither listed
    # a scouting one, so `--features alloc,codec-scout` was the only shape that
    # would not compile. Each codec gets its OWN arm rather than one arm naming
    # both, because a build carrying only HELLO (a reader that names peers but
    # not askers) is a real composition and unifying the two would stop testing
    # it.
    (cd crates && cargo clippy -p wz-session-core --no-default-features \
        --features alloc,codec-scout --all-targets --quiet -- -D warnings) || return 1
    (cd crates && cargo clippy -p wz-session-core --no-default-features \
        --features alloc,codec-hello --all-targets --quiet -- -D warnings) || return 1
}

# ─── Layer C1bg — storage-backend-filesystem: durable fs Volume/Storage ─
#
# R311y279: `storage-backend-filesystem` (OFF in the default set) is a durable,
# filesystem-backed Volume/StorageBackend (the `filesystem_storage` module in
# wz-runtime-tokio), forwarding ONLY the no_std storage seam
# (wz-session-core/storage-backend), NOT the runtime storage driver. C1bf's
# `--all-features` clippy already COMPILES the module; what no lane does is
# EXECUTE the durability tests (the atom's whole claim). This lane runs them:
#   1. cargo TEST the module's unit tests under the feature (put/get/delete, the
#      None mount-root slot, key<->filename round-trip, the DURABILITY reopen
#      test, corrupt-file quarantine, long-key regression, name sanitization),
#      with a >=1-passed guard so a future module rename cannot silently turn a
#      name-filtered `cargo test` into a green no-op ([[feedback-a-skip-is-green]]);
#   2. R311y280 — cargo TEST the COMPOSITION + DURABILITY of the fs backend
#      through the LIVE driver (RuntimeStorageManager add_storage -> StorageService
#      capture + queryable -> FilesystemStorage -> disk -> manager restart -> served),
#      with its MemoryVolume-loses-it discriminator, under the fuller feature combo
#      (storage-mgr-multi-storage-host + pubsub-allow-loop + declare-subscriber); a
#      >=1-passed guard again forbids a zero-test false-green;
#   3. clippy-gate the cfg (`--all-targets`) with the feature on;
#   4. clippy-gate the LIB under `--no-default-features --features
#      storage-backend-filesystem` — the module composes standalone over the
#      minimal seam forward.
# R311y426 — the two inline `>= 1 passed` guards are replaced by
# `_runci_guarded_test` at EXACT counts, the same substitution R311y414 made for
# three other inline forms. `>= 1` catches the empty selection but not a set that
# silently shrinks; the counts below are measured on this tree.
layer_c1bg_cargo_test_storage_backend_filesystem() {
    _runci_guarded_test "C1bg filesystem_storage" 14 \
        cargo test -p wz-runtime-tokio \
        --features storage-backend-filesystem --lib filesystem_storage --quiet || return 1
    # R311y280 — the live-driver composition + durability proof (+ its discriminator).
    _runci_guarded_test "C1bg manager_restart" 2 \
        cargo test -p wz-runtime-tokio \
        --features storage-mgr-multi-storage-host,storage-backend-filesystem,pubsub-allow-loop,declare-subscriber \
        --lib manager_restart --quiet || return 1
    (cd crates \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features storage-backend-filesystem --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features \
            --features storage-backend-filesystem --quiet -- -D warnings)
}
# ─── Layer C1bh — wz-ap-demo storage-host durable backing (--storage-host-dir) ─
#
# R311y282: `--storage-host-dir <dir>` lets the storage-host run-mode register a
# durable FilesystemVolume and map hosted storages onto it (zenoh-faithful: the
# storage VOLUME is a host/deployment concern). A wire durable-SERVE proof is
# BLOCKED by the per-client-Session "zombie storage" wall (a stock pico z_put and
# z_get are separate one-shot connections; a hosted storage does not serve data
# across the connection boundary — the same wall that walls the cross-impl A4
# frontier), so this is proven at the LEVEL that is honestly reachable + CI-safe
# (a C1-class cargo-test/clippy lane, NOT a fragile Layer E `--ignored` binary
# variant): the arg -> volume_id selection seam is unit-tested, and the fs branch
# of the live run-mode is compile + clippy gated. This lane:
#   1. cargo TEST the `storage_host_volume_id` mapping under the feature (a >=1
#      -passed guard forbids a zero-test false-green);
#   2. clippy-gate the demo with `storage-backend-filesystem` ON (the fs volume
#      registration + config-volume mapping branch);
#   3. clippy-gate the demo with only `adminspace-config-hotreload` (the
#      not(fs) inert-warning arm);
#   4. clippy-gate the demo on DEFAULT features (hotreload OFF) -- the arm where
#      `storage_host_volume_id` has NO caller, so a missing cfg gate on it would be
#      dead-code under the workspace `-D warnings` deny. This leg exists because the
#      first cut of R311y282 shipped that exact break: the fs-ON / hotreload-ON legs
#      all COMPILE the caller, so only the default arm catches an un-gated helper
#      (a green-local-gate-is-not-green / a-SKIP-is-green lesson -- the lane must
#      clippy the arm that can regress, not only the feature-ON arms).
# (It does NOT drive the demo binary, so there is no Layer-E feature-variant uplift
# hazard -- a `cargo test` binary is a different artifact from the driven bin.)
layer_c1bh_cargo_test_storage_host_dir() {
    local out
    out="$(cd crates && cargo test -p wz-ap-demo \
        --features storage-backend-filesystem --bin wz-ap-demo storage_host_volume --quiet 2>&1)" \
        || { echo "$out"; return 1; }
    echo "$out"
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<< "$out" \
        || { echo "  C1bh FAIL: 0 storage_host_volume tests ran (filter matched nothing)"; return 1; }
    (cd crates \
        && cargo clippy -p wz-ap-demo --features storage-backend-filesystem --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --features adminspace-config-hotreload --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --quiet -- -D warnings)
}
layer_c2_cargo_clippy() {
    # Stage 4b — exclude wz-session-lwip (no_std-engine crate, mutually
    # exclusive with tokio's http-send in a unified graph; isolated clippy
    # is in Layer C1m). Stage 5 — exclude wz-mcu-session-acceptor for the
    # same reason (isolated clippy in C1n). R311mi — exclude
    # wz-mcu-multicast-e2e for the same reason (isolated clippy in C1r).
    # R311mo — wz-runtime-tokio-multicast-tests for the transport-unicast
    # feature-unification reason (isolated clippy in C1s). Same rationale as
    # the C1 exclude.
    (cd crates && cargo clippy --workspace --all-targets \
        --exclude wz-session-lwip \
        --exclude wz-mcu-session-acceptor \
        --exclude wz-mcu-multicast-e2e \
        --exclude wz-runtime-tokio-multicast-tests --quiet -- -D warnings) || return 1

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
# both wz-runtime-coop lanes (default sync-only + `--features alloc`)
# so Phase W MCU profile feature combinations are caught the same way
# the AP-tokio lane catches them.
#
# R311ls expansion: adds the three `transport-multicast` clippy combos
# (base + reassembly + transport-fragmentation, mirroring the C1q test
# matrix). transport-multicast is off by default, so the default-feature
# wz-runtime-tokio lane above never lints multicast_glue's drive loop and
# its cfg-gated RX/TX arms — before R311ls that left the whole module
# clippy-uncovered in run-ci (the gap that hid drive_multicast_session's
# too_many_arguments until it was collapsed into MulticastDriveConfig).
layer_c3_per_pkg_isolated_lint() {
    (cd crates \
        && cargo clippy -p wz-ap-demo --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz --no-default-features --features preset-ap-client \
            --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --features transport-multicast \
            --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --features transport-multicast,reassembly \
            --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --features transport-multicast,transport-fragmentation \
            --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-coop --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-coop --features alloc \
            --all-targets --quiet -- -D warnings)
}

# ─── Layer C4 — wz facade preset composability matrix ───────────────
#
# R311eb: the wz facade exposes 7 named presets (the user-facing
# composition surface — `mnemosyne.toml` north-star "compose a profile,
# not a feature soup"). C3 builds only `preset-ap-client`; Layer G
# cross-compiles the facade under its default / runtime-coop bundles.
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
        preset-cortex-m0-minimal
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
# (interop) pinned the reverse — one name, two feature sets. R311fp made
# build extras superset interop extras for EVERY plane, leaving one
# uniform base delta: transport-batching (R311fg foreign handshake).
# R311kl dissolved that last delta at the root (the INIT batch_size
# negotiation is core transport now; no wz-e2e-* binary pins
# transport-batching), so build-coherent == interop-coherent and Layer
# E2's binaries add only tcp over these subsets. It also closes the
# R311fh gap at the BUILD layer: the queryable build now includes the
# terminating Final.
#
# handshake-only = empty extras (bare session core, no consumer plane).
# keyexpr-canon is FOUNDATIONAL and lives in each lane's base, not here
# (a subset dropping it does not type-check). transport-unicast is also
# pinned in each base — not as FOUNDATIONAL (R311mk made transport-
# multicast independently composable) but because these consumer-plane
# subsets exercise the unicast Session handle.
_wz_consumer_plane_subsets() {
    printf '%s\t%s\n' "handshake-only"        ""
    printf '%s\t%s\n' "pubsub-only"           "codec-push,pubsub-put,pubsub-delete"
    printf '%s\t%s\n' "queryable-only"        "codec-request,codec-response,codec-response-final,query-queryable,query-reply-err"
    # R311hu — zget-reply-only composes query-get WITHOUT query-target /
    # query-consolidation / query-timeout / query-attachment, so it is the
    # subset that carries the query send-side metadata NEG / isolation
    # guards (session.rs query_with_{target,consolidation,timeout_ms}_is_
    # silent_noop_*). Those tests assert the signature-stable setters elide
    # to the bare no-metadata wire when their feature is off — the
    # query-side analog of the pubsub C1d metadata-OFF lane. The timeout_ms
    # guard (R311hv) additionally pins that the local ReplyRegistry
    # deadline stays unarmed, since both effects share the one setter gate.
    printf '%s\t%s\n' "zget-reply-only"       "codec-response,codec-response-final,query-get,query-reply"
    printf '%s\t%s\n' "liveliness-sub-only"   "codec-declare,declare-interest,liveliness-subscriber"
    printf '%s\t%s\n' "liveliness-token-only" "liveliness-token"
    # R311lk — liveliness-get does NOT imply query-get (its wire is the
    # declaration plane, not Request/Response), yet it installs the SAME
    # deferred reply-staging sink the z_get path uses (`deferred_reply_sink`
    # + the owned `InboundReply` copy). This subset is the getter-less
    # guard that pins that sink + its `InboundReply` import composing on
    # the liveliness plane alone — without it the `any(query-get,
    # liveliness-get)` gates regress invisibly (default CI has query-get ON).
    printf '%s\t%s\n' "liveliness-get-only"   "liveliness-get"
    printf '%s\t%s\n' "declare-observer"      "codec-declare,declare-subscriber,declare-queryable,liveliness-token,liveliness-subscriber"
    # R311pb — `declare-observer` minus `liveliness-token`: the ROUTED
    # subscriber + queryable declares (`announce_subscriber` /
    # `announce_queryable`, R311ou / R311ow) name `SendDeclareError`, but the
    # import was gated on `liveliness-token` alone — so a build with
    # `declare-subscriber` / `declare-queryable` ON and `liveliness-token` OFF
    # failed E0425 (the R311ou/ow latent gate bug). No prior subset exercised
    # that combo (`declare-observer` keeps liveliness-token ON, masking it).
    # This lane pins routed-declare-without-liveliness so the import-gate union
    # cannot regress; it carries query-queryable + the request/response codecs
    # so `announce_queryable`'s `map_queryable_err` (query-queryable-gated) is
    # actually compiled.
    printf '%s\t%s\n' "routed-declare-no-liveliness" "codec-declare,declare-subscriber,declare-queryable,declare-undeclare,query-queryable,codec-request,codec-response,codec-response-final,query-reply-err"
    # R311gi gc-2c — statechart switchboard plane (keyexpr -> SCXML
    # domain-event injection). `switchboard` implies codec-push (it reacts
    # to inbound Push); it is the first subset with codec-push ON but
    # pubsub-put OFF, which guards that the data-callback projection and
    # the switchboard injection stay independently composable.
    printf '%s\t%s\n' "switchboard-only"      "switchboard"
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
# exercising the superset-OFF facade build two wz peers legitimately use,
# (2) duplicate the build each wz-e2e-* binary already performs under its
# interop superset (Layer E2), and (3) erase the build-vs-interop
# distinction that is the reason Layer E2 exists. Interop supersets live
# with the wz-e2e-* binaries + Layer E2; the per-plane deltas were since
# collapsed to the single uniform transport-batching delta, and R311kl
# then dissolved that one too (negotiation is core transport; no wz-e2e-*
# binary pins transport-batching any more — the interop superset is now
# exactly the build subset + tcp). This closes the C4b-ruling carry.
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
# transport-unicast is pinned ON in every subset HERE because this matrix
# varies the CONSUMER plane on a unicast base — each consumer plane
# (pubsub / queryable / declare / liveliness) hangs off the unicast Session
# handle. R311mk note: transport-unicast is no longer FOUNDATIONAL-as-in-
# unconditional — the unicast decouple made transport-multicast an
# independently-composable atom, so a transport-multicast-WITHOUT-
# transport-unicast build IS now a coherent shape. That orthogonal transport
# axis is guarded by Layer C4e (_wz_transport_axis_subsets), not here: these
# consumer-plane rows still pin unicast because they exercise the Session
# handle, which is the unicast API surface. The
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
#
# ─── the SSOT DISCOVERY FLOOR, shared by C4c / C4d / C1j ─────────────
#
# R311y420. All three consumers read the subset list through a process
# SUBSTITUTION, and a reading `while` loop cannot see that producer's exit
# status. So if _wz_runtime_tokio_coherent_subsets ever emitted nothing — a
# renamed feature that drops every row, an early `return`, a typo in the
# heredoc — the loop would run ZERO times and the lane would return 0. A
# matrix gate reporting success over an empty matrix is the same
# success-by-silence shape as Layer 0's fmt-workspace and shellcheck-file
# discovery, and it is closed the same way. Bump the floor in the same commit
# that adds a subset.
#
# Applied to C1j as well as to the two lanes R311y420 hosts, because C1j has
# been HOSTED since R311y318 carrying the identical hole; closing it only for
# the lanes being moved would be knowingly leaving the worse one open.
WZ_TOKIO_SUBSETS_MIN=10   # @ R311y420

# _wz_subset_floor <lane-label> <seen-count>
_wz_subset_floor() {
    local lane="$1" seen="$2"
    if (( seen < WZ_TOKIO_SUBSETS_MIN )); then
        echo "  ${lane} FAIL: subset SSOT yielded ${seen} subset(s), expected >= ${WZ_TOKIO_SUBSETS_MIN}" >&2
        echo "    _wz_runtime_tokio_coherent_subsets emitted too few rows, so this" >&2
        echo "    matrix would have passed over an empty or truncated matrix." >&2
        return 1
    fi
    return 0
}

layer_c4c_runtime_tokio_subset_matrix() {
    local name feats seen=0
    while IFS=$'\t' read -r name feats; do
        seen=$((seen + 1))
        if ! (cd crates && cargo build -p wz-runtime-tokio --no-default-features --features "$feats" --quiet); then
            echo "  C4c FAIL: wz-runtime-tokio subset $name did not build"
            return 1
        fi
        echo "  C4c wz-runtime-tokio subset $name OK"
    done < <(_wz_runtime_tokio_coherent_subsets)
    _wz_subset_floor C4c "$seen" || return 1
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
#
# R311hw / R311hx — the codec & declare behavioural NEG / isolation
# guards (session_glue.rs send_*_rejects_with_feature_disabled_when_*_off:
# codec-push / codec-request -> SendWireError; declare-keyexpr /
# -subscriber / -queryable / -token -> SendDeclareError; declare-interest
# -> SendWireError) ride these same subsets: a subset that composes the
# consumer plane with one of those gates OFF runs the matching guard,
# asserting the signature-stable emit path returns the typed
# FeatureDisabled reject (never a falsely-Ok no-op). This is the BEHAVIOUR
# complement to Layer F, which only proves the codec bytes shrink
# (footprint), not that the off path rejects correctly.
#
# R311hy — the pubsub-allow-loop NEG guards (session.rs
# publish{,_aliased}_session_local_does_not_fire_loopback_when_allow_loop_
# off) likewise ride these subsets: pubsub-allow-loop is OFF in every
# consumer-plane subset, so a SessionLocal publish there must short-circuit
# to Ok(0) and never fire the registered loopback subscriber. The POS twins
# are cfg-gated ON the feature and run only in the all-on default build.
# The feature-OFF NEG set each SSOT row is REQUIRED to execute. Rows absent from
# this table assert nothing beyond "the suite is green" — the table names only
# what a round deliberately parked here.
#
# R311y332 — why this exists at all. C1j runs `cargo test --quiet` and reads only
# the exit code, so a row that silently STOPS running a guard still reports green:
# the suite is 100+ tests and losing five of them changes no visible number. That
# is y314's "skip reporting green" one level up, and it would have eaten exactly
# the proofs R311y330/y331 wrote and R311y332 hosted. Pinned as SETS, not counts —
# R311y315 shipped a len()-pinned gate that a rename passed green, so C1bk and
# C1e's guards both compare sets and this follows them.
_c1j_required_negs() {
    case "$1" in
        # R311y330 — the query-queryable OFF arms: declare rejects typed AND
        # announces nothing. This row is the only place they compile.
        zget-reply-only)
            printf '%s\n' \
                declare_queryable_aliased_rejects_typed_and_emits_nothing_when_feature_off \
                declare_queryable_rejects_typed_and_emits_nothing_when_feature_off
            ;;
        # R311y331 — the query-get OFF arms, the atom's whole initiator surface.
        queryable-only)
            printf '%s\n' \
                query_aliased_auto_rejects_typed_and_emits_nothing_when_query_get_off \
                query_aliased_rejects_typed_and_emits_nothing_when_query_get_off \
                query_rejects_typed_and_emits_nothing_when_query_get_off
            ;;
        *) : ;;
    esac
}

layer_c1j_runtime_tokio_subset_behavior() {
    local name feats expected got rc out seen=0
    while IFS=$'\t' read -r name feats; do
        seen=$((seen + 1))
        expected=$(_c1j_required_negs "$name" | sort)
        if [ -n "$expected" ]; then
            # `--list` in its own invocation: a build break must read as a build
            # break, not as a vanished guard, so the exit code is checked before
            # the set is compared (the trap R311y329 hit writing C1e's twin).
            out=$(cd crates && cargo test -p wz-runtime-tokio --no-default-features \
                --features "$feats" --lib -- --list 2>&1); rc=$?
            if [ "$rc" -ne 0 ]; then
                echo "  C1j FAIL: subset $name did not BUILD (exit $rc) — not a drift verdict:"
                printf '%s\n' "$out" | tail -20 | sed 's/^/      /'
                return 1
            fi
            got=$(printf '%s' "$out" \
                | sed -n 's/^session::tests::\(.*rejects_typed_and_emits_nothing_when_[a-z_]*\): test$/\1/p' \
                | sort)
            if [ "$got" != "$expected" ]; then
                echo "  C1j FAIL: subset $name's required feature-OFF NEG set drifted"
                echo "            (a guard was cfg-elided, renamed, or its gate widened)"
                echo "    expected:"; printf '%s\n' "$expected" | sed 's/^/      /'
                echo "    got:";      printf '%s\n' "$got" | sed 's/^/      /'
                return 1
            fi
        fi
        if ! (cd crates && cargo test -p wz-runtime-tokio --no-default-features --features "$feats" --quiet); then
            echo "  C1j FAIL: wz-runtime-tokio subset $name behaviour tests failed"
            return 1
        fi
        echo "  C1j wz-runtime-tokio subset $name tests OK${expected:+ (NEG set pinned)}"
    done < <(_wz_runtime_tokio_coherent_subsets)
    _wz_subset_floor C1j "$seen" || return 1
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
    local name feats seen=0
    while IFS=$'\t' read -r name feats; do
        seen=$((seen + 1))
        if ! (cd crates && cargo clippy -p wz-runtime-tokio --no-default-features --features "$feats" --quiet -- -D warnings); then
            echo "  C4d FAIL: wz-runtime-tokio subset $name clippy not clean"
            return 1
        fi
        echo "  C4d wz-runtime-tokio subset $name clippy OK"
    done < <(_wz_runtime_tokio_coherent_subsets)
    _wz_subset_floor C4d "$seen" || return 1
}

# ─── transport-axis subsets (the multicast transport WITHOUT unicast) ──
#
# R311mk — the consumer-plane matrix (_wz_consumer_plane_subsets, shared by
# C4b/C4c/C1j/C4d) varies the CONSUMER plane on a transport-unicast base. The
# transport axis is orthogonal: transport-multicast is now an independently-
# composable atom (the unicast decouple lifted session_glue + the Session
# handle behind transport-unicast and relocated the shared reassembly + link
# machinery to their SSOT homes), so a transport-multicast-WITHOUT-
# transport-unicast build is a coherent shape the unicast-based matrices
# cannot express. These rows guard that surface. `name<TAB>extra-features`.
_wz_transport_axis_subsets() {
    # JOIN-only multicast (no data body codecs): the bare beacon + lease
    # transport. This is the config that exposed the conditional tx_sn
    # unused-mut (the TX-mint arm is gated on the data-plane body codecs).
    printf '%s\t%s\n' "multicast-join-only"  "transport-multicast"
    # Multicast with a Push data plane (tx_sn is minted by multicast_tx_emit).
    printf '%s\t%s\n' "multicast-data"       "transport-multicast,codec-push,pubsub-put"
    # Realistic multicast deploy shape: binds a real UDP multicast socket
    # (transport-link-udp pulls the UdpDriver + the link pipeline, which must
    # not depend on the transport-unicast-gated session_glue).
    printf '%s\t%s\n' "multicast-udp-deploy" "transport-multicast,transport-link-udp"
}

# ─── Layer C4e — transport-axis (multicast-without-unicast) BUILD+CLIPPY ─
#
# R311mk: C4b/C4c/C1j/C4d vary the CONSUMER plane on a transport-unicast base;
# this lane varies the TRANSPORT axis. Before the unicast decouple,
# transport-multicast could not build without transport-unicast (session_glue
# compiled unconditionally and named the unicast FSM types), so the facade
# `runtime-tokio,transport-multicast` profile was unbuildable — a catalog
# composability gap, since transport-multicast is an ATOMIC feature and must
# compose alone (an implication edge to transport-unicast would have welded
# two atoms and mis-stated the protocol: zenoh-pico builds multicast-only).
# This lane builds the facade (the reported-gap shape) AND clippy-checks the
# wz-runtime-tokio crate in isolation (deny-warnings, the conditional tx_sn
# unused-mut guard) under each multicast-without-unicast subset, so the
# decouple cannot silently regress. No `cargo test` twin: a multicast-only
# crate has no unicast-handshake tests to run and the multicast behaviour is
# already covered with unicast on by C1p/C1q + the MCU e2e by C1r.
layer_c4e_transport_axis_matrix() {
    local name extra
    while IFS=$'\t' read -r name extra; do
        # Facade build — the reported-gap shape (runtime-tokio + the subset).
        if ! (cd crates && cargo build -p wz --no-default-features --features "runtime-tokio,$extra" --quiet); then
            echo "  C4e FAIL: wz facade transport-axis subset $name did not build"
            return 1
        fi
        # Crate clippy in isolation — `cargo clippy` subsumes the build and
        # adds deny-warnings over the crate alone.
        if ! (cd crates && cargo clippy -p wz-runtime-tokio --no-default-features --features "$extra" --quiet -- -D warnings); then
            echo "  C4e FAIL: wz-runtime-tokio transport-axis subset $name clippy not clean"
            return 1
        fi
        echo "  C4e transport-axis subset $name OK (facade build + crate clippy)"
    done < <(_wz_transport_axis_subsets)
}

# ─── Layer D — deploy yaml schema validate ──────────────────────────
layer_d_validate_deploy() {
    if ! python3 -c 'import yaml' >/dev/null 2>&1; then
        echo "Layer D SKIP (python3-yaml not installed)"
        return 0
    fi
    bash scripts/validate-deploy.sh
}

# ─── Layer C1bp — §5.22 dynamic plugin loading, end to end ─────────────
#
# R311y492. `plugin-dynamic-loading` was the ONE §5.22 atom R311y256 kept as real
# backlog ("genuinely unbuilt and genuinely buildable ON THE AP PROFILE"); the
# other four were deprecated ON THE CONDITION that it never got built, in that
# round's own words: "if this is ever built they return with it". This lane is
# the condition being met, gated.
#
# BUILD THE `.so` FIRST, and it is not optional. `wz-plugin-example` is a
# `cdylib` that nothing depends on — no `cargo test` anywhere pulls it — so
# without this step the host unit tests SKIP (loudly, but green) and the e2e
# fails on a missing file. A lane whose subject is dynamic loading must provide
# the thing to load.
layer_c1bp_plugin_dynamic_loading() {
    (cd crates && cargo build -p wz-plugin-example --quiet) || return 1
    # The ABI contract's own gate: the compatibility check is a pure function, so
    # it is unit-testable exhaustively in a way the e2e cannot be — a mismatched
    # ABI needs a second plugin built against a different contract.
    (cd crates && cargo test -p wz-plugin-abi --quiet) || return 1
    # The host: dlopen, the gate, the lifecycle FSM, the registry. Drives the
    # REAL `.so` built above.
    (cd crates && cargo test -p wz-runtime-tokio --features plugin-dynamic-loading \
        --lib --quiet plugin:: 2>&1 | tee /dev/stderr \
        | grep -qE '^test result: ok\. [0-9]+ passed') || return 1
    (cd crates && cargo clippy -p wz-runtime-tokio --features plugin-dynamic-loading \
        --all-targets -- -D warnings) || return 1
    # The AP-full binary for the pico e2e. `preset-ap-full` carries the plugin
    # host since R311y492, so no extra key here — and the e2e asserts the demo's
    # own BUILD FEATURES line rather than trusting this invocation.
    (cd crates && cargo build -p wz-ap-demo --no-default-features \
        --features preset-ap-full --quiet) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_get ]]; then
        _pico_cli_unavailable "Layer C1bp" || return 1
        return 0
    fi
    for leg in \
        wz_plugin_dlopened_is_read_by_a_real_pico_beside_the_static_one \
        wz_plugin_non_plugin_shared_object_is_refused_and_the_node_survives; do
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_plugin_dynamic_loading_pico -- --ignored --quiet --test-threads=1 \
            --exact "$leg" 2>&1 \
            | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    done
}

# ─── Layer L — every committed Cargo.lock agrees with its manifests ────
#
# R311y490 added this lane; R311y494 fixed its PREMISE, which hosted CI refuted
# on the lane's first hosted run.
#
# This repo has EIGHT independent cargo workspaces — `crates/`, `xtask/`, and six
# under `deploy/` — and until R311y490 nothing checked that their committed locks
# still resolve. `deploy/mcu-multicast-e2e/Cargo.lock` had silently rotted, so any
# build in that directory rewrote a committed file and dirtied an untouched tree.
#
# `--locked` is the check: it resolves and FAILS rather than writing when the lock
# would have to change.
#
# THE PREMISE THAT WAS WRONG. R311y490 ran it `--offline` and split the failure
# messages two ways, treating "dependency not in the local cache" as a benign SKIP
# distinct from staleness. Hosted CI produced a THIRD message the split did not
# cover — `no matching package named `cortex-m` found` for every MCU deploy
# workspace, whose dependencies that job never builds and so never caches — and
# the catch-all correctly refused to guess, which is how the gap surfaced as a red
# rather than as a silent pass.
#
# The deeper problem is not the missing third string: OFFLINE MODE CANNOT
# CLASSIFY AT ALL. A lock that is stale BECAUSE it lacks a newly-added dependency
# produces the not-cached message, not the `--locked` one, so the R311y490 split
# would have SKIPPED exactly the drift the lane exists to catch. cargo says as
# much in its own note ("offline mode … can sometimes cause surprising resolution
# failures").
#
# So: `--offline` FIRST as a fast path, and on any failure that is not the
# unambiguous `--locked` message, RETRY ONLINE. The retry is what makes the
# verdict real — with the index available, a resolution failure means the lock is
# genuinely stale and nothing else. A network outage on a cold cache then reports
# as an unrecognised failure and FAILS, which is honest: the lane could not
# determine the answer, and a gate that cannot read its input must not report
# green.
layer_l_lockfile_freshness() {
    local rc=0 lock dir out
    while IFS= read -r lock; do
        dir="$(dirname "$lock")"
        # Fast path: no network, and conclusive when it succeeds or when it names
        # the --locked refusal.
        if out="$( (cd "$dir" && cargo metadata --locked --offline --format-version 1 2>&1 >/dev/null) )"; then
            echo "  L $lock OK (offline)"
            continue
        fi
        if grep -q "because --locked was passed" <<< "$out"; then
            echo "  L FAIL: $lock is STALE — it no longer resolves against its" >&2
            echo "     manifests. Refresh it: (cd $dir && cargo update --workspace)" >&2
            rc=1
            continue
        fi
        # Anything else offline is INCONCLUSIVE, not benign. Ask the index.
        if out="$( (cd "$dir" && cargo metadata --locked --format-version 1 2>&1 >/dev/null) )"; then
            echo "  L $lock OK (online; not in the local cache)"
            continue
        fi
        if grep -q "because --locked was passed" <<< "$out"; then
            echo "  L FAIL: $lock is STALE — it no longer resolves against its" >&2
            echo "     manifests. Refresh it: (cd $dir && cargo update --workspace)" >&2
        else
            echo "  L FAIL: $lock — could not be resolved even with the index:" >&2
            echo "$out" | head -5 >&2
        fi
        rc=1
    done < <(find . -name Cargo.lock -not -path "./vendor/*" -not -path "*/target/*" | sort)
    return "$rc"
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
# R311y266 — the shared zenoh-pico-CLI prereq guard for the hosted proof lanes.
#
# E / E2 / E6 / E8 each SKIP green when the pico CLIs are absent. On a developer's box
# that is honest: the CLIs are FOREIGN binaries built from a vendored submodule and a
# machine may legitimately not have them. In the hosted jobs it is not honest -- a step
# builds them, and Layer A4 reads "this lane is in ci.yml" as evidence its proofs
# EXECUTED. Delete that build step and every one of these lanes would go green having
# proved nothing, while A4 kept reporting them as executed. WZ_PICO_REQUIRE=1 (set in the
# workflow) turns the skip into a failure. Same rule as WZ_QZ_REQUIRE / WZ_Z_REQUIRE.
_pico_cli_unavailable() {
    if [[ -n "${WZ_PICO_REQUIRE:-}" ]]; then
        echo "  $1 FAIL — required (WZ_PICO_REQUIRE set) but the zenoh-pico CLI is not built" >&2
        return 1
    fi
    echo "$1 SKIP (zenoh-pico CLI not built; run: bash scripts/build-zenoh-pico-cli.sh)"
    return 0
}

# R311y628 (§1.1g) — the pico LIBRARY oracles: the legs whose counterparty is
# `libzenohpico.so` itself rather than a pico process on a socket.
#
# Two things land here at once and the second is why the lane exists.
#
# THE DRIVING ORACLE. `pico_transport_decode_differential` is the first test in
# this tree whose INPUT is generated rather than imagined. Every analyzer round
# so far reached its defect through a fixture someone thought of first, and the
# register carries the cost of that as §1.4a — "a fixture can make a defect
# unreachable" — with seven recorded instances. This walks the whole 8-bit
# transport header space against a body ladder and asks upstream's compiled
# decoder whether it agrees. Its first honest run found 27 disagreements in 1536
# strings, every one of them with the ext-chain `Z` bit set and in BOTH
# directions. They are PINNED with the drift check running both ways, on the
# same rule Mnemosyne's orphan ledger follows: a new divergence fails, and a
# pinned one that stops diverging fails too.
#
# AND THE TWO THAT WERE NEVER WIRED. `pico_pure_function_oracle` and
# `pico_abi_symbol_census` have run by hand since R311y568 and appear in NO
# lane — the register recorded that as §11.9 and it stayed true. A proof that
# only ever runs when someone remembers is a proof the tree cannot depend on.
layer_epico_library_oracles() {
    if [[ ! -f target/zenoh-pico-build/lib/libzenohpico.so ]]; then
        _pico_cli_unavailable "Layer Epico" || return 1
        return 0
    fi
    # R311y629 — the wz SIDE, and its absence is what this lane found on its very
    # first hosted run: `pico_pure_function_oracle` and `pico_abi_symbol_census`
    # dlopen wz's `libwz_capi_pico.so` BESIDE pico's library, and nothing in the
    # cross-impl job builds it. Seven of eight legs panicked with "run
    # `cargo build -p wz-capi-pico` first" — on a test that has existed since
    # R311y568 and, until this lane, had only ever been run by hand on a
    # developer box where the cdylib happened to be lying around.
    #
    # BUILT rather than skipped, on this file's own rule: SKIP on a FOREIGN
    # binary a machine may legitimately lack, never on a wz one we can produce.
    # A lane that skipped here would go green having compared nothing, and
    # Layer A4 reads "this lane is in ci.yml" as evidence its proofs executed.
    (cd crates && cargo build -p wz-capi-pico --quiet) || return 1
    # R311y630 — 2 -> 5. The triage of the 27 divergences added the MECHANISM
    # WITNESS for the surviving sixteen (pico's CLOSE verdict is independent of
    # the extension chain, measured rather than read off transport.c); the
    # VOCABULARY oracle added the half the blind sweep cannot reach (the seven
    # extension identities the wire spec actually names); and the SCOUTING leg
    # added the second namespace, where the id `0x01` is not `T_MID_INIT`.
    _runci_guarded_test "Epico transport-decode differential" 7 \
        cargo test -p wz-integration-tests \
        --test pico_transport_decode_differential -- --ignored --quiet --test-threads=1 \
        || return 1
    _runci_guarded_test "Epico pure-function oracle" 8 \
        cargo test -p wz-integration-tests \
        --test pico_pure_function_oracle -- --ignored --quiet --test-threads=1 \
        || return 1
    _runci_guarded_test "Epico ABI symbol census" 4 \
        cargo test -p wz-integration-tests \
        --test pico_abi_symbol_census -- --ignored --quiet --test-threads=1 \
        || return 1
    echo "  Epico: wz and the real libzenohpico agree where they are pinned to"
}

layer_e_ap_demo_round_trip() {
    # R311y478 — z_pong joins the guarded set. It is the counterparty for the
    # §5.27 drop-in round-trip leg, and it arrived AFTER the other four, so a
    # tree whose CLIs were built by the previous script would have z_put and
    # friends but not z_pong. Without it in this list Layer E would run and the
    # leg would PANIC on a missing binary instead of taking the honest
    # SKIP-or-require path every other foreign prereq takes. R311y479 adds
    # z_liveliness and z_sub_liveliness on the same grounds -- they were already
    # in the build script's TARGETS but never guarded, so a tree that had them
    # and a tree that did not were indistinguishable to this lane.
    if [[ ! -x target/zenoh-pico-cli/z_put || ! -x target/zenoh-pico-cli/z_sub || ! -x target/zenoh-pico-cli/z_sub_attachment || ! -x target/zenoh-pico-cli/z_pub_attachment || ! -x target/zenoh-pico-cli/z_pong || ! -x target/zenoh-pico-cli/z_liveliness || ! -x target/zenoh-pico-cli/z_sub_liveliness ]]; then
        _pico_cli_unavailable "Layer E" || return 1
        return 0
    fi
    # R311y265 — build the DEFAULT wz-ap-demo rather than SKIPping when it is absent,
    # the same rule E2 / E6 / E8 / Z now follow: SKIP on a FOREIGN binary (a machine may
    # legitimately lack the zenoh-pico CLI), never on a wz binary we can just build.
    # Layer A4 treats "this lane is in ci.yml" as evidence its proofs EXECUTED, so a
    # hosted lane that can SKIP green on a missing wz binary would make the number lie.
    # The workflow still builds the demo explicitly before this lane; that step is now a
    # belt to this brace rather than the only thing standing between CI and a silent SKIP.
    (cd crates && cargo build -p wz-ap-demo --quiet) || return 1
    # R311y338 — the query-timeout e2e's peer is `wz-e2e-silent-peer`, the test
    # double whose only job is to never answer (its predecessor borrowed its
    # silence from R311y337's defect and inverted when that was fixed). Built
    # here under the same rule as the demo above: never SKIP on a wz binary we
    # can build, or the lane goes green without proving anything.
    (cd crates && cargo build -p wz-e2e-silent-peer --quiet) || return 1
    # The §5.27 api-compat-pico drop-in witness needs the C-ABI `cdylib`
    # ITSELF, not a Rust dependency on it: `tests/pico_c_examples_on_wz_capi_dropin.rs`
    # compiles an upstream zenoh-pico example with `cc` and links it against
    # `libwz_capi_pico.so`. wz-capi-pico is deliberately NOT a dev-dependency of
    # wz-integration-tests — its `#[no_mangle]` `z_*` exports would collide with
    # the REAL zenoh-pico ones this crate links via zenoh-pico-sys for the layer3
    # codec-parity tests — so nothing in `cargo test -p wz-integration-tests`
    # builds it, and on a fresh checkout the helper would panic on a missing .so.
    # Built here under the same rule as the two binaries above: never SKIP (or
    # crash) on a wz artifact we can just build.
    #
    # R311y534 — with `transport-link-tls`, and that feature is what makes the
    # TLS drop-in legs POSSIBLE rather than merely nicer. `z_pub_tls.c` /
    # `z_sub_tls.c` open `tls/` endpoints; without the feature the scheme parses
    # and then fails at bind/dial with a typed `Unsupported`, so both legs would
    # red on a wz that is otherwise correct. Selecting it here rather than in the
    # crate default keeps the no-TLS build a real, tested configuration (the
    # feature-arm builds in Layer C1bm), while the ONE artifact this lane's legs
    # link carries every scheme they exercise.
    (cd crates && cargo build -p wz-capi-pico --features transport-link-tls --quiet) || return 1
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
    # R311nm — also exclude any `multicast` test: the wz->pico multicast
    # JOIN+Push interop (wz_publisher_to_pico_multicast_zsub) is real-UDP
    # multicast and environment-dependent (no multicast route → dropped
    # IGMP join → env-flaky), so it is a required-gate hazard. It runs in
    # the opt-in Layer M instead, alongside the wz<->wz multicast lanes.
    # The `multicast` substring keeps every future multicast interop test
    # out of this default sweep with one pattern (the wz_e2e_ analogue).
    # R311ou — also exclude any `zenohd` test: the wz<->zenoh-full (zenohd)
    # interop tests (wz_to_zenohd_router.rs) drive a HEAVY external reference
    # router (zenohd v1.5.0, not a wz artifact) and are load-sensitive — under
    # this default sweep's concurrent process pressure (cargo runs the whole
    # --ignored set in parallel: 3 zenohd instances + their wz-ap-demo /
    # z_pub / z_sub children alongside every other e2e), a wz-ap-demo handshake
    # to zenohd can exceed the per-test readiness budget. Same required-gate
    # hazard class as `multicast`; they run ONLY in the dedicated Layer Z
    # (where the env + external binary are explicitly provisioned), which is
    # their `#[ignore]`-declared home. The `zenohd` substring keeps every future
    # zenohd interop test out of this default sweep with one pattern.
    # R311qa / R311qc — also exclude `wz_router`: the router e2es need a SPECIFIC
    # binary VARIANT this default-binary sweep does not provide. wz_router_multi_peer
    # needs `--features routing-router` (Layer E3 builds it); wz_router_reject
    # needs the DEFAULT build to assert the exit-2 reject (Layer E4 rebuilds it);
    # wz_router_forward needs `--features routing-routes` (Layer E5 builds it).
    # Each owns its variant in its dedicated lane, so all stay out of this sweep
    # (whose binary is whichever variant a prior lane last built — not assertable
    # here). The `wz_router` substring covers all three with one pattern.
    # R311y449 — THAT PARENTHETICAL IS STALE, and it is the source R311y448
    # copied its own false rationale from. Since R311y265 this lane builds the
    # DEFAULT demo itself at :4985, so the sweep's binary IS assertable: it is the
    # default one. The EXCLUSIONS above remain correct for the reason that
    # actually holds — wz_router_multi_peer needs `--features routing-router` and
    # wz_router_forward needs `--features routing-routes`, neither of which a
    # default build has — not because the variant is unknown. Same for the
    # `wz_peer` paragraph's "indeterminate binary" below. Do not propagate the
    # indeterminacy premise into a new skip; R311y442's zenoh_ext block has the
    # correct phrasing ("On THIS sweep's default binary").
    # R311qk — same for `wz_peer`: wz_peer_mesh needs `--features routing-peer`
    # (Layer E6 builds it), wz_peer_reject_without_feature needs the DEFAULT build
    # for its exit-2 assertion (Layer E4 rebuilds it). On THIS sweep's
    # indeterminate binary, a routing-peer-enabled build turns `--peer` into a
    # peer SERVER that runs until SIGTERM — so the reject test's `.output()`
    # blocks forever (the R311qg lane-wiring gap a full run-ci surfaced). The
    # `wz_peer` substring keeps both out; they run only in E4 / E6.
    # R311y278 — same for `wz_storage_host`: wz_storage_host_config_hotreload_state_flip_via_pico
    # needs `--features adminspace-config-hotreload` (Layer E6h builds it) for the
    # `--storage-host` run-mode. On THIS sweep's default binary that flag is rejected
    # with exit 2, so the test's readiness barrier times out (the gap the y277 push's
    # pre-push full run-ci surfaced: E6h ran the right binary, but this catch-all also
    # ran it against the default one). The `wz_storage_host` substring keeps it out;
    # it runs only in E6h.
    # R311y442 — same for `zenoh_ext`: the wz<->zenoh-ext advanced-pubsub legs
    # need a wz-ap-demo built `--features advanced` (Layer Z builds it) for the
    # `--advanced-subscribe` / `--advanced-publish` CLI. On THIS sweep's default
    # binary those flags are INERT, and the legs assert that explicitly rather
    # than reading an empty sample set as success — so running them here would be
    # a red with a correct diagnosis and a wrong lane. Every one of the names
    # carries the `zenoh_ext` token FOR this skip; they run only in Z, where
    # `_runci_guarded_test Z 12` pins that all of them executed. (R311y444-review,
    # REVIEWER 3 — this documentation pin was left at 6 when the executable one
    # moved to 10; y443 had moved both together, so the convention was one round
    # old when this round broke it. Move BOTH or the skip block misinforms.)
    # R311y448 — same for `inert`: wz_ap_demo_inert_flags asserts the DEFAULT
    # build reports --advanced-* / --group-join as INERT, which is the exact
    # inverse of what the zenoh_ext legs assert. It runs only in E4i, which
    # rebuilds the default binary first and pins the count at 3.
    # R311y449 CORRECTS THE REASON y448 recorded here. y448 wrote "on a binary
    # this sweep inherited with `--features advanced` all three fail (measured)"
    # — a NECESSITY claim, and it is false. This sweep inherits nothing: the lane
    # builds the DEFAULT demo itself at :4985 (R311y265) before reaching here, so
    # the three legs would have PASSED in this sweep. y448's measurement was real
    # but describes a build this lane cannot present; it copied the stale
    # pre-R311y265 premise from the wz_router/wz_peer paragraphs above instead of
    # the correct adjacent one at the zenoh_ext block ("On THIS sweep's default
    # binary"). The skip STAYS, on honest grounds: it avoids a duplicate run and
    # keeps three process-spawning legs out of this ~49-test fully-parallel sweep.
    # Contrast `--skip zenoh_ext`, whose necessity IS real.
    # R311y443 — the token is a NAMING OBLIGATION on every future leg in that
    # file, not a property of the four it started with. The two recovery legs
    # added here were first named for what they do (`..._relay_induced_gap`),
    # which reads better and would have put them on this sweep's default binary,
    # where they fail with a correct INERT diagnosis in the wrong lane.
    # R311y480 — also exclude `apfull`: `apfull_preset_pico_interop.rs` drives the
    # `--no-default-features --features preset-ap-full` demo binary, which THIS lane
    # does not build (it builds the default preset-ap-client one at :4985). Its leg 2
    # needs `--peer`, so on this sweep's binary it would fail at spawn with exit 2 —
    # a real failure for the wrong reason. Layer E9 owns that binary. Same one-substring
    # convention as `wz_peer` / `wz_router` above; `--skip` matches the TEST FN name,
    # and both fns are named `apfull_preset_*`.
    # R311y481 — the token now covers a SECOND file, `apfull_query_plane_pico_interop.rs`
    # (fns `apfull_query_*`), on the same grounds and with the same naming obligation
    # R311y443 states: every future leg on the preset-ap-full binary must carry the
    # `apfull` substring or it lands on THIS sweep's ap-client binary, where the two
    # querier legs die at argv (no `--query-params` / `--query-attachment` key) and the
    # reply-err leg silently answers nothing. Measured, not assumed: dropping
    # `--skip apfull` takes this sweep 59 -> 64 and names exactly those five.
    # R311y500 — `capi_c`, and this one excludes for an ARTIFACT reason rather than
    # an argv one. The §5.27 zenoh-c legs run against `libwz_capi_c.so`, and WHICH
    # ABI that file holds depends on the last lane that built it: Layer C1cc picks
    # the arm by reading `Z_FEATURE_UNSTABLE_API` out of the installed header, and
    # Layer C4's preset matrix later rebuilds the same path with DEFAULT features.
    # C4 sits between C1cc and this sweep in ci.yml, so without this token Layer E
    # would compile upstream's examples against a header whose `z_owned_bytes_t` is
    # 32 bytes and link them to a cdylib built for 40 — a stack-layout mismatch,
    # reported as whatever it happened to corrupt. C1cc owns these four legs and
    # owns the arm selection with them. The token is the same NAMING OBLIGATION the
    # families above carry, and R311y500 renamed both fixtures and one test fn so
    # every fn in the family contains `capi_c`; Layer C0's naming gate lists the
    # token, so a future leg that omits it fails there rather than here.
    (cd crates && cargo test -p wz-integration-tests --quiet -- --ignored \
        --skip wz_e2e_ --skip multicast --skip zenohd --skip wz_router --skip wz_peer \
        --skip wz_storage_host --skip zenoh_ext --skip inert --skip apfull \
        --skip wz_plugin --skip capi_c)
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
        _pico_cli_unavailable "Layer E2" || return 1
        return 0
    fi
    # R311y265 — the lane BUILDS its own wz binaries instead of SKIPping when they are
    # absent, the same way E6 / E8 / Z build wz-ap-demo.
    #
    # This was a real false-green, and of exactly the kind this lane's proofs exist to
    # prevent. The six wz-e2e-* subsets used to be prereq-SKIP guards, and NOTHING built
    # them -- not run-ci.sh, not the workflow. A developer never noticed because the
    # binaries linger in target/ from an earlier session. But R311y264 wired E2 into
    # hosted CI, and Layer A4 derives "this lane runs in hosted CI" from ci.yml, so A4
    # began counting E2's pico proofs as EXECUTED while a fresh runner would have SKIPped
    # every one of them, green. A SKIP is green; that is the whole hazard.
    #
    # The distinction the guards should draw, and now do: SKIP on a FOREIGN binary (the
    # zenoh-pico CLI is genuinely external and a machine may legitimately not have it),
    # never on a wz binary we can just build.
    (cd crates && cargo build --quiet \
        -p wz-e2e-pubsub \
        -p wz-e2e-queryable \
        -p wz-e2e-zget \
        -p wz-e2e-liveliness \
        -p wz-e2e-liveliness-token \
        -p wz-e2e-declare-observer) || return 1
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
# Default gate (R311pt — opt-in axis retired). The bench rebuilds
# wz-ap-demo under every codec-* atomic feature's transitive-puller-
# aware exclusion lane, so a single run is several minutes on cold
# cargo cache — but that cost no longer keeps it off the default
# sweep. Run a single isolated lane via:
#
#   scripts/run-ci.sh --layer F               # only Layer F
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
    # Default gate (R311pt — opt-in axis retired). Host-only: no
    # cross-toolchain prereq, so it runs on every default sweep. SKIPs
    # gracefully only when python3 is absent (measure-codec-footprint.sh
    # parses cargo-metadata through python3) — the same prereq-SKIP
    # discipline the other lanes use for their toolchain deps.
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Layer F SKIP (python3 not on PATH; needed by measure-codec-footprint.sh)"
        return 0
    fi
    bash scripts/measure-codec-footprint.sh
}

# ─── Layer G — cross-compile cortex-m wz-runtime-core lib build ────
#
# Default gate (R311pt — opt-in axis retired). Phase W mechanical
# first gate (R311ak) — wz-runtime-core is the §5.P
# runtime-services-tier entry crate (R251) and must build for an
# MCU target so the no_std/MCU half of the composable framework
# stays mechanically truthful as concrete impls (wz-runtime-coop +
# extern lwIP symbols) land in R311al+. SKIPs gracefully if the
# rustup target is not installed so a host-only developer machine
# is not forced to install a cross-compile toolchain just to run
# the default lanes. Promoted to default once the wz-runtime-coop
# caller lands and the cross-compile path has a real consumer
# (concrete-impls-land-alongside-real-callers, R63 lesson).
layer_g_cross_compile_cortex_m() {
    # Default gate (R311pt — opt-in axis retired; the wz-runtime-coop
    # caller landed in R311av+, satisfying the "promote to default once a
    # real cross-compile consumer exists" condition stated below). The
    # per-target + no-targets-installed graceful SKIPs further down keep a
    # host-only machine from being forced to install the toolchain.
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
        # G.4 (R311au scope C) wz-runtime-coop — Phase W MCU profile
        # sync primitive aliases (critical_section::Mutex<RefCell<T>>
        # binding). #![no_std] sync surface, no alloc; covers every
        # Phase W rustup target including Cortex-M0+ (thumbv6m).
        if (cd crates && cargo build -p wz-runtime-coop \
            --target "$t" --quiet); then
            echo "  G.4 wz-runtime-coop $t OK"
        else
            echo "  G.4 wz-runtime-coop $t FAIL" >&2
            fail=1
        fi
        # G.4-alloc (R311av + R311bb) wz-runtime-coop --features alloc.
        # CoopRuntime self-rolled cooperative task pool + impl Runtime
        # + CoopTime impl TimeSource. R311bb closed the M0+ gap via
        # portable-atomic{,-util}: thumbv6m no longer SKIPs because
        # the crate::atomic alias module substitutes
        # portable_atomic_util::Arc + portable_atomic::Atomic* on
        # targets without native CAS. The polyfill rides on the same
        # critical_section impl the deploy crate supplies for
        # sync::Mutex, so no extra runtime mechanism is layered on.
        if (cd crates && cargo build -p wz-runtime-coop \
            --target "$t" --features alloc --quiet); then
            echo "  G.4-alloc wz-runtime-coop $t OK"
        else
            echo "  G.4-alloc wz-runtime-coop $t FAIL" >&2
            fail=1
        fi
        # G.5 (R311ax + R311bb) wz facade --features runtime-coop.
        # Composes wz-runtime-coop via the public facade surface so a
        # consumer enabling `runtime-coop` finds `wz::runtime_coop::*`
        # cross-compiled on every Phase W target. R311bb removed the
        # M0+ SKIP that inherited from G.4-alloc.
        if (cd crates && cargo build -p wz \
            --target "$t" --no-default-features \
            --features runtime-coop --quiet); then
            echo "  G.5 wz facade runtime-coop $t OK"
        else
            echo "  G.5 wz facade runtime-coop $t FAIL" >&2
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
                    --features runtime-coop --quiet); then
            echo "  G.6 cross-real lwip-sys $t OK"
        else
            echo "  G.6 cross-real lwip-sys $t FAIL" >&2
            fail=1
        fi
        # G.7 (R311ih) static-scouting synth on the MCU profile. Proves
        # the scout_static bounded-seam synth composes no-alloc on every
        # Phase W target (the §2.4.3 reason #2 claim — static mode is for
        # tiny static-only deploys), and that the facade -> wz-runtime-coop
        # -> wz-session-core funnel cross-compiles with scouting-static on.
        # No-alloc: the synth builds onto BoundedVec/BoundedString, so it
        # rides every target including thumbv6m (Cortex-M0+). (Since R311ja
        # the session-unicast subset rides thumbv6m too — G.10 — so this is
        # no longer the only session-core path that clears ARMv6-M.)
        if (cd crates && cargo build -p wz-session-core \
            --target "$t" --no-default-features --features scouting-static --quiet) \
           && (cd crates && cargo build -p wz \
            --target "$t" --no-default-features \
            --features runtime-coop,scouting-static --quiet); then
            echo "  G.7 scouting-static MCU synth $t OK"
        else
            echo "  G.7 scouting-static MCU synth $t FAIL" >&2
            fail=1
        fi
        # G.8 (R311im) reassembly slot FSM + dispatcher on the MCU profile.
        # Proves the Tier B reassembly module cross-compiles no_std on every
        # Phase W target via the `no_std` profile feature
        # (`sce-rust-runtime?/no_std` — the heapless engine variant). R311im
        # dropped the `sce-rust-runtime/no_std` force from the `reassembly`
        # capability feature, so the no_std runtime is now selected by this
        # PROFILE feature, not forced by the capability — which is what lets
        # the AP build (std runtime) host the same module (Layer C1l). The
        # one --no-std codegen emit serves both profiles (SCE pin 1474091c2
        # SceBytes<N> alias).
        if (cd crates && cargo build -p wz-session-core \
            --target "$t" --no-default-features --features reassembly,no_std --quiet); then
            echo "  G.8 reassembly MCU $t OK"
        else
            echo "  G.8 reassembly MCU $t FAIL" >&2
            fail=1
        fi
        # G.9 (R311in carry[3]) wz-runtime-coop reassembly seam on the MCU
        # profile. Proves the live MCU reassembly consumer (reassembly_rx:
        # CoopReassembly + mcu_reassembly() over the SCE buffer-pool SSOT
        # reassembly_pool_mcu.scxml) cross-compiles no_std + no-alloc on
        # every Phase W target. The bottom-up MCU consumer of the
        # ReassemblyDispatcher that G.8 only build-checked at the
        # session-core layer; the ~22 KiB no_std dispatcher (vendor/sce
        # 4ec1aa642 metadata elision + fragment.chunk payload-field
        # removal) is SRAM-resident. No alloc: the seam stages into inline
        # BoundedVec, so it rides every target including thumbv6m (M0+).
        if (cd crates && cargo build -p wz-runtime-coop \
            --target "$t" --features reassembly --quiet); then
            echo "  G.9 reassembly seam MCU $t OK"
        else
            echo "  G.9 reassembly seam MCU $t FAIL" >&2
            fail=1
        fi
        # G.10 (Stage 4a) wz-runtime-coop --features session-unicast.
        # Proves the session-tier `impl SessionRuntime for CoopRuntime`
        # link-sink binding + the `SessionLinkActions<CoopRuntime<C>,
        # CoopTime<C>>` type-check (the precondition the MCU sync drive
        # loop consumer depends on) cross-compile on the alloc-capable
        # MCU targets — INCLUDING thumbv6m (Cortex-M0/M0+) since R311ja. The
        # session_actions bundle handle was lifted from a hard-coded
        # `alloc::sync::Arc` to the per-profile `SessionRuntime::ActionsHandle`
        # GAT: tokio binds `Arc` (multi-thread), the lwIP MCU profile binds
        # `Rc` (single-task drive loop). `Rc` lowers to plain loads / stores,
        # so session-unicast no longer needs `target_has_atomic = "ptr"` and
        # cross-compiles on ARMv6-M. This IS the no-alloc M0 session reach the
        # prior rounds deferred; M3/M4/M7/M33 + RISC-V IMAC keep building too.
        if (cd crates && cargo build -p wz-runtime-coop \
            --target "$t" --features session-unicast --quiet); then
            echo "  G.10 session-unicast MCU $t OK"
        else
            echo "  G.10 session-unicast MCU $t FAIL" >&2
            fail=1
        fi
        # G.11 (Stage 4b) wz-session-lwip + facade session-lwip cross-real.
        # The tier-clean MCU session shell — run_session sync drive loop +
        # LwipUdpDriver (BoxedLinkDriver over LwipUdpSocket) — over the real
        # lwIP build. Like wz-link-lwip the crate is #![cfg(lwip_real_build)]
        # (empty without WZ_LWIP_PORT), so this mirrors G.6's cross-real
        # setup: builds the crate with `reassembly` on (exercises the
        # reassembly drive path) AND the facade `session-lwip` re-export.
        # SKIPs riscv32imac (no riscv32-unknown-elf-gcc for the lwIP C
        # cross build, same as G.6). thumbv6m (M0+) NO LONGER SKIPs since
        # R311ja: the `Rc` ActionsHandle (see G.10) lets the whole MCU
        # session shell — handshake + reassembly consumer + facade — cross-
        # compile on ARMv6-M, the no-alloc M0 session reach end to end.
        # R311mc: two more facade builds pin the multicast forward — proving
        # wz's wz-session-lwip?/ weak-forwards cfg-in the MCU multicast drive
        # loop + MulticastReplyQueue THROUGH the facade (not just at the
        # wz-session-lwip crate boundary, C1m). Build 3 is the Arc-free subset
        # (transport-multicast + TX codecs + query-queryable) on EVERY target:
        # the queryable observer-staging ResponseSink is Rc<RefCell<VecDeque>>-
        # backed, so it rides thumbv6m. Build 4 ADDS liveliness-token, which
        # now ALSO rides thumbv6m (R311me): the MCU multicast liveliness reply
        # stages through the same Rc-backed MulticastReplyQueue (the inline-
        # fire path), and collapsing the deferred_fire module gate to
        # `deferred-fire` alone stopped liveliness-token from spuriously
        # compiling that Arc-bearing module. So the full TX-codec +
        # liveliness-token subset cross-builds on EVERY non-riscv target —
        # the M0 liveliness inline-fire reach the prior rounds carried.
        # R311mf/R311mg: a final facade build pins the multicast Fragment RX/TX
        # path THROUGH the facade (session-lwip,transport-multicast,
        # transport-fragmentation,codec-push) — proving wz's
        # wz-session-lwip?/transport-fragmentation forward (R311mg) reaches the
        # MCU reassembly Router + TX splitter, which cross-compile on every
        # non-riscv target including thumbv6m (Vec-backed, no Arc), the M0
        # fragment reach. Built via the facade (not -p wz-session-lwip direct)
        # so the public composition surface is what is tested, like Build 3/4.
        if [[ "$t" == "riscv32imac-unknown-none-elf" ]]; then
            echo "  G.11 session-lwip cross-real $t SKIP (riscv32-unknown-elf-gcc not installed on this host)"
        elif (cd crates && \
                WZ_LWIP_PORT="$(realpath lwip-sys/port/cross-test)" \
                cargo build -p wz-session-lwip \
                    --target "$t" --features reassembly --quiet) && \
             (cd crates && \
                WZ_LWIP_PORT="$(realpath lwip-sys/port/cross-test)" \
                cargo build -p wz \
                    --target "$t" --no-default-features \
                    --features session-lwip --quiet) && \
             (cd crates && \
                WZ_LWIP_PORT="$(realpath lwip-sys/port/cross-test)" \
                cargo build -p wz \
                    --target "$t" --no-default-features \
                    --features session-lwip,transport-multicast,codec-push,codec-response,codec-response-final,query-queryable \
                    --quiet) && \
             (cd crates && \
                WZ_LWIP_PORT="$(realpath lwip-sys/port/cross-test)" \
                cargo build -p wz \
                    --target "$t" --no-default-features \
                    --features session-lwip,transport-multicast,codec-push,codec-response,codec-response-final,liveliness-token,query-queryable \
                    --quiet) && \
             (cd crates && \
                WZ_LWIP_PORT="$(realpath lwip-sys/port/cross-test)" \
                cargo build -p wz \
                    --target "$t" --no-default-features \
                    --features session-lwip,transport-multicast,transport-fragmentation,codec-push \
                    --quiet); then
            echo "  G.11 session-lwip cross-real $t OK"
        else
            echo "  G.11 session-lwip cross-real $t FAIL" >&2
            fail=1
        fi
        # G.12 (Round A) multicast session FSM + per-peer FSM + dispatcher
        # on the MCU profile. Proves the handshake-free multicast cluster
        # (session_fsm_multicast.scxml + multicast_peer.scxml + the
        # multicast_dispatch Router) cross-compiles no_std + no-alloc on
        # every Phase W target via the `no_std` profile feature
        # (`sce-rust-runtime?/no_std` + portable-atomic, same as G.8
        # reassembly). The Router is allocation-free (inline `[PeerSlot;
        # MAX_PEERS]` pool, fixed ZID buffers), so it rides every target
        # including thumbv6m (M0+, CAS-less via the critical-section
        # backend). The lwIP consumer + the real multicast socket land in
        # the transport-multicast round; this build-checks the session-core
        # layer, mirroring how G.8 build-checks reassembly.
        if (cd crates && cargo build -p wz-session-core \
            --target "$t" --no-default-features --features session-multicast,no_std --quiet); then
            echo "  G.12 multicast MCU $t OK"
        else
            echo "  G.12 multicast MCU $t FAIL" >&2
            fail=1
        fi
        # G.13 (R311ki) session-reconnect MCU composition. Proves the
        # reconnect module - the declaration cache, reset/replay, and the
        # LocalSwappableLink single-task swap seam (the RefCell-backed,
        # no-Send twin of SwappableLink the lwIP Rc sink requires) -
        # cross-compiles on every Phase W target. session-reconnect pulls
        # alloc; session-unicast is the reconnect module's gate; the
        # declare-keyexpr + declare-undeclare pair keeps the subset
        # COHERENT (the cache append/prune hooks live in those send
        # paths - a reconnect build with no declare emits has a dead
        # cache and fails deny-warnings, by design). The MCU reconnect
        # SUPERVISOR (re-dial loop) awaits the MCU session-open runtime;
        # this build-checks the seam layer, as G.12 does for multicast.
        if (cd crates && cargo build -p wz-session-core \
            --target "$t" --no-default-features \
            --features session-reconnect,session-unicast,declare-keyexpr,declare-undeclare,no_std --quiet); then
            echo "  G.13 session-reconnect MCU $t OK"
        else
            echo "  G.13 session-reconnect MCU $t FAIL" >&2
            fail=1
        fi
        # G.14 (R311y25) freertos-sys cross-real — compiles the vendored
        # FreeRTOS-Kernel V11.1.0 ARM_CM3 port + core + heap_4 against the
        # cooperative-profile reference config, flipping freertos-sys's
        # `freertos_real_build` path on (= the LAYER-2 RTOS foundation). Runs
        # ONLY on thumbv7m-none-eabi: the vendored ARM_CM3 port is ARMv7-M /
        # Cortex-M3-specific (thumbv6m=ARMv6-M needs ARM_CM0, thumbv8m needs
        # ARM_CM23/33, riscv has no port), and port/cross-test is the mps2-an385
        # (M3) reference config. Other triples get their own port + config in a
        # later round. Mirrors G.6's WZ_LWIP_PORT cross-real pattern but with
        # WZ_FREERTOS_CONFIG supplying the consumer config (the -sys crate bakes
        # no default — symmetry with lwip-sys).
        if [[ "$t" == "thumbv7m-none-eabi" ]]; then
            if (cd crates && \
                WZ_FREERTOS_CONFIG="$(realpath freertos-sys/port/cross-test)" \
                cargo build -p freertos-sys --target "$t" --quiet); then
                echo "  G.14 cross-real freertos-sys $t OK"
            else
                echo "  G.14 cross-real freertos-sys $t FAIL" >&2
                fail=1
            fi
            # G.15 (R311y26) wz-runtime-freertos — the FreeRTOS cooperative
            # single-task PROFILE: FreertosClock (ClockSource over
            # xTaskGetTickCount) + FreertosAllocator (heap_4 GlobalAlloc) +
            # FreertosRuntime = CoopRuntime<FreertosClock> (reuses the
            # wz-runtime-coop executor SSOT). Cross-compiles against the real
            # freertos-sys kernel build (WZ_FREERTOS_CONFIG supplied). thumbv7m
            # only — same ARM_CM3 constraint as G.14.
            if (cd crates && \
                WZ_FREERTOS_CONFIG="$(realpath freertos-sys/port/cross-test)" \
                cargo build -p wz-runtime-freertos --target "$t" --quiet); then
                echo "  G.15 wz-runtime-freertos $t OK"
            else
                echo "  G.15 wz-runtime-freertos $t FAIL" >&2
                fail=1
            fi
        fi
        # G.16 (R311y29) zephyr-sys — the Zephyr cooperative profile's hand-FFI
        # crate. PURE extern declarations (no build.rs, no vendored kernel, NO
        # bindgen); the symbols resolve at the Z2 deploy's Zephyr image link, so
        # a standalone cross build is a clean lib-check. Runs on EVERY Phase W
        # triple (unlike G.14/G.15's thumbv7m-only ARM_CM3 kernel build) because
        # it compiles no C — proving the FFI crate is no_std-portable.
        if (cd crates && cargo build -p zephyr-sys --target "$t" --quiet); then
            echo "  G.16 zephyr-sys $t OK"
        else
            echo "  G.16 zephyr-sys $t FAIL" >&2
            fail=1
        fi
        # G.17 (R311y29) wz-runtime-zephyr — the Zephyr cooperative single-task
        # PROFILE: ZephyrClock (ClockSource over sys_clock_tick_get) +
        # ZephyrAllocator (k_malloc/k_free GlobalAlloc) + ZephyrRuntime =
        # CoopRuntime<ZephyrClock> (reuses the wz-runtime-coop executor SSOT,
        # exactly like wz-runtime-freertos). Pure-cargo cross-build on every
        # Phase W triple; the kernel-symbol link is the Z2 deploy's job.
        if (cd crates && cargo build -p wz-runtime-zephyr --target "$t" --quiet); then
            echo "  G.17 wz-runtime-zephyr $t OK"
        else
            echo "  G.17 wz-runtime-zephyr $t FAIL" >&2
            fail=1
        fi
    done
    if [[ $any_ran -eq 0 ]]; then
        echo "Layer G SKIP (no Phase W rustup targets installed)"
        return 0
    fi
    return "$fail"
}

# ─── Layer Q — QEMU mps2 multi-machine UDP loopback e2e demo run ───
#
# Default gate (R311pt — opt-in axis retired). R311be introduced
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
# and the polyfill is at the wz-runtime-coop layer, not main.rs.)
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
#                   SYS_EXIT exit code. PASS=0 / FAIL=1; the run_qemu_case
#                   wall-clock timeout (30s, R311y14) bounds a runaway loop.
#                   SKIPs Q.2 if qemu-system-arm
#                   is absent.
#
# Phase W ladder FULL closure mantissa: composable-framework MCU
# stack runs end-to-end on three M-class cores (wz facade +
# runtime-coop + CoopRuntime timer queue (R311bc) +
# CoopJoinHandle::abort surface (R311bd) + wz-link-lwip UDP raw API
# (R311az-2) + lwip-sys cross-real build (R311az-1) + R311bf's
# SystickClock ClockSource composed in one binary per target).
layer_q_qemu_mcu_e2e() {
    # Default gate (R311pt — opt-in axis retired). The rustup-target /
    # qemu-system-arm / arm-none-eabi-* graceful SKIPs below keep this a
    # no-op on a host-only machine; on a machine that carries the
    # cross-toolchain it runs the MCU e2e + footprint regression gate on
    # every default sweep (closing the staleness window that opt-in left).
    #
    # ── Path-normalised builds — the footprint gate's precondition ──
    #
    # rustc embeds ABSOLUTE build paths in the binary (panic `Location`
    # strings, cargo registry source paths). They land in .rodata, and
    # `arm-none-eabi-size --format=berkeley` counts .rodata inside its `text`
    # column — so an un-normalised footprint number partly measures THE LENGTH
    # OF THE BUILD DIRECTORY PATH. Measured on mcu-multicast-e2e at one commit
    # and one rustc: 50964 built at /w, 51164 at /home/coin/watching-zenoh, and
    # 51344 at the CI runner's /home/runner/work/watching-zenoh/watching-zenoh
    # — a 380 B spread on IDENTICAL code, against a +/-256 B band. That is what
    # kept Layer Q red on hosted CI for ~20 pushes while the local pre-push
    # run-ci stayed green: two machines gating one absolute-byte baseline they
    # could never agree on.
    #
    # --remap-path-prefix rewrites those prefixes to fixed strings, so .text is
    # environment-independent and one baseline governs every machine. Verified:
    # this host and an ubuntu:22.04 container mounted at the CI runner's path
    # (different $CARGO_HOME, different target dir) now emit a byte-identical
    # 50956. check-footprint.sh re-asserts the property per measurement, so a
    # build that bypasses this export FAILs the gate instead of silently
    # measuring its own path length. The rust-toolchain.toml pin covers the
    # other half (rustc codegen drift across releases).
    #
    # Safe to export over the deploy crates' `.cargo/config.toml`
    # `target.*.rustflags` (env RUSTFLAGS replaces rather than merges them):
    # every deploy MCU build.rs already emits `-Tlink.x` via
    # `cargo:rustc-link-arg`, and those config entries are documented
    # duplicates of exactly that (see deploy/mcu-noheap-probe/.cargo/config.toml).
    local RUSTFLAGS
    RUSTFLAGS="$(footprint_remap_rustflags)"
    export RUSTFLAGS

    local installed
    installed="$(rustup target list --installed 2>/dev/null)"
    local has_qemu=0
    if command -v qemu-system-arm >/dev/null 2>&1; then
        has_qemu=1
    fi
    local fail=0

    # ── Q.0 — R311hl no-heap registry runtime probe ──
    #
    # deploy/mcu-noheap-probe declares NO `#[global_allocator]` and has NO
    # C deps (no lwip-sys), so it needs only the rustup target + qemu —
    # not arm-none-eabi-gcc. A clean LINK is a whole-program proof that the
    # wz-session-core registry control plane + no-heap fire paths are
    # allocation-free (any `alloc` reference fails with "no global memory
    # allocator found"); the semihost SYS_EXIT=0 proves they EXECUTE on the
    # emulated core. Runs BEFORE the arm-none-eabi-gcc gate below so the
    # no-heap proof is available even on a host lacking the C toolchain.
    # Mechanically distinct from Layer G (rlib cross-compile — an rlib
    # never needs an allocator, so it cannot surface a transitive
    # alloc-forcing dependency; this binary link does, and did: R311hl
    # found `wz-codecs/alloc` was hardcoded into wz-session-core).
    local probe_lanes=(
        "microbit:cortex-m0:thumbv6m-none-eabi"
        "mps2-an385:cortex-m3:thumbv7m-none-eabi"
        "mps2-an386:cortex-m4:thumbv7em-none-eabihf"
        "mps2-an500:cortex-m7:thumbv7em-none-eabihf"
    )
    local probe_built=0
    local plane pmachine pcpu ptarget pbin
    for plane in "${probe_lanes[@]}"; do
        IFS=':' read -r pmachine pcpu ptarget <<< "$plane"
        if ! grep -q "^${ptarget}$" <<< "$installed"; then
            echo "  Q.0.${pmachine} SKIP (rustup target ${ptarget} absent)"
            continue
        fi
        if cargo build --release \
            --manifest-path deploy/mcu-noheap-probe/Cargo.toml \
            --target "$ptarget" --bin mcu-noheap-probe --quiet; then
            echo "  Q.0.${pmachine} build mcu-noheap-probe ${ptarget} OK (no global allocator)"
            probe_built=1
        else
            echo "  Q.0.${pmachine} build mcu-noheap-probe ${ptarget} FAIL" >&2
            fail=1
            continue
        fi
        if [[ "$has_qemu" -ne 1 ]]; then
            echo "  Q.0.${pmachine} run SKIP (qemu-system-arm not on PATH)"
            continue
        fi
        pbin="deploy/mcu-noheap-probe/target/${ptarget}/release/mcu-noheap-probe"
        if ! run_qemu_case \
            "Q.0.${pmachine} run mcu-noheap-probe via qemu-system-arm ${pmachine}" \
            "$pcpu" "$pmachine" "$pbin"; then
            fail=1
        fi
    done

    if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
        echo "  Q.1-3 SKIP (arm-none-eabi-gcc not on PATH;" \
             "install gcc-arm-none-eabi — mcu-qemu-demo lwip-sys needs it)"
        return "$fail"
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
    # while keeping the wz facade `runtime-coop` surface intact —
    # mps2 lanes still build + run the async + spawn path.
    local sub_lanes=(
        "microbit:cortex-m0:thumbv6m-none-eabi:run"
        "mps2-an385:cortex-m3:thumbv7m-none-eabi:run"
        "mps2-an386:cortex-m4:thumbv7em-none-eabihf:run"
        "mps2-an500:cortex-m7:thumbv7em-none-eabihf:run"
        "mps2-an505:cortex-m33:thumbv8m.main-none-eabi:skip:cortex-m-rt 0.7 ARMv8-M Secure-state Lockup PC=0x56ea; cortex-m-rt 0.8 carry"
    )

    local any_built=0
    # `fail` already declared at the top of the function (shared with the
    # Q.0 probe lanes so a probe FAIL gates the layer even when the demo
    # portion SKIPs for a missing toolchain).
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
            if [[ -n "${WZ_Q_REQUIRE:-}" ]]; then
                echo "  Q.${machine} FAIL — required (WZ_Q_REQUIRE set) but rustup" \
                     "target ${target} absent (provisioning regression)" >&2
                fail=1
            else
                echo "  Q.${machine} SKIP (rustup target ${target} absent;" \
                     "rustup target add ${target})"
            fi
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
            # process exit code (0 / 1); the run_qemu_case wall-clock
            # timeout (30s, R311y14) bounds a runaway loop so a hung demo
            # does not block CI
            # indefinitely.
            if ! run_qemu_case \
                "Q.2.${machine} run mcu-qemu-demo via qemu-system-arm ${machine}" \
                "$cpu" "$machine" "$bin"; then
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

    # ── Q.frt — FreeRTOS profile e2e (deploy/mcu-freertos-demo) — R311y27 ──
    #
    # Boots the LAYER-2 FreeRTOS cooperative single-task profile on mps2-an385
    # (Cortex-M3 only — the vendored ARM_CM3 port): cortex-m-rt #[entry] ->
    # xTaskCreate(wz_task) -> vTaskStartScheduler; the wz task hosts
    # CoopRuntime<FreertosClock> (the REUSED wz-runtime-coop executor) + the
    # wz-link-lwip UDP loopback echo, yielding with vTaskDelay. SYS_EXIT=0 =>
    # the FreeRTOS scheduler booted (SysTick/PendSV/SVCall vector wiring via the
    # FreeRTOSConfig.h handler #defines works) AND the cooperative echo
    # round-tripped. Build needs BOTH WZ_FREERTOS_CONFIG (the deploy's
    # FreeRTOSConfig.h, with the cortex-m-rt direct-routing #defines) AND
    # WZ_LWIP_PORT (the lwIP cross-test port). Reaches here only with
    # arm-none-eabi-gcc present (the Q.1-3 toolchain gate returned early else).
    if grep -q "^thumbv7m-none-eabi$" <<< "$installed"; then
        local frt_cfg frt_lwip
        frt_cfg="$(realpath deploy/mcu-freertos-demo)"
        frt_lwip="$(realpath crates/lwip-sys/port/cross-test)"
        if WZ_FREERTOS_CONFIG="$frt_cfg" WZ_LWIP_PORT="$frt_lwip" cargo build --release \
            --manifest-path deploy/mcu-freertos-demo/Cargo.toml \
            --target thumbv7m-none-eabi --bin mcu-freertos-demo --quiet; then
            echo "  Q.frt build mcu-freertos-demo thumbv7m-none-eabi OK"
            any_built=1
            if [[ "$has_qemu" -ne 1 ]]; then
                echo "  Q.frt run SKIP (qemu-system-arm not on PATH)"
            elif ! run_qemu_case \
                "Q.frt run mcu-freertos-demo via qemu-system-arm mps2-an385" \
                cortex-m3 mps2-an385 \
                "deploy/mcu-freertos-demo/target/thumbv7m-none-eabi/release/mcu-freertos-demo"; then
                fail=1
            fi
        else
            echo "  Q.frt build mcu-freertos-demo thumbv7m-none-eabi FAIL" >&2
            fail=1
        fi
    fi

    # ── Q.4 — Stage 5 acceptor session e2e (deploy/mcu-session-acceptor) ──
    #
    # Boots wz_mcu_session_acceptor::run_acceptor_e2e on the native-atomic
    # mps2 machines (M3/M4/M7): the acceptor half of the unicast handshake
    # (InitSyn -> InitAck -> OpenSyn with the real round-tripped cookie ->
    # OpenAck -> Established) + a post-handshake Frame dispatch, over a live
    # lwIP loopback, driven by the Stage 4b run_session sync loop. SYS_EXIT=0
    # => the on-target handshake reached Established AND dispatched the Frame
    # (the host mirror of this exact scenario is Layer C1n). The mps2 lanes
    # (M3/M4/M7, native-atomic, MB-scale SRAM, default full-rate pool) run
    # below in the tuple loop. R311jb first added a Cortex-M0 (thumbv6m /
    # microbit) entry as BUILD-ONLY (the default ~37 KB-socket e2e cannot fit
    # nrf51's 16 KB SRAM); R311jc then makes microbit a REAL boot via the slim
    # buffer-pool profile + a trimmed lwIP port (its own block after the loop —
    # see that block's header). So the acceptor handshake + Frame dispatch now
    # run on-target across M3 / M4 / M7 AND Cortex-M0.
    # Reaches here only with arm-none-eabi-gcc present (the Q.1-3 gate above
    # returned early otherwise). No footprint gate: this bin is an e2e proof,
    # not a footprint-tracked deploy artifact.
    local acceptor_lanes=(
        "mps2-an385:cortex-m3:thumbv7m-none-eabi"
        "mps2-an386:cortex-m4:thumbv7em-none-eabihf"
        "mps2-an500:cortex-m7:thumbv7em-none-eabihf"
    )
    # Two data-plane modes per machine: the default whole-`T_MID_FRAME`
    # dispatch (Stage 5) and `--features reassembly` (Tier B), which boots
    # DataMode::FragmentChain so the acceptor reassembles a `T_MID_FRAGMENT`
    # chain through the swept slot pool + re-parses + dispatches it. One QEMU
    # boot per mode (lwIP NO_SYS is process-global single-init), built to the
    # same ELF path in sequence. The `reasm` mode is the on-target mirror of
    # the host C1n `--features reassembly` lane.
    local amachine acpu atarget abin alabel amode
    local afeat_args
    for lane in "${acceptor_lanes[@]}"; do
        IFS=':' read -r amachine acpu atarget <<< "$lane"
        if ! grep -q "^${atarget}$" <<< "$installed"; then
            echo "  Q.4.${amachine} SKIP (rustup target ${atarget} absent)"
            continue
        fi
        for amode in frame reasm; do
            alabel="$amode"
            # Array (not an unquoted string) so the empty default-mode case
            # expands to zero args and the reasm case to two, with no
            # word-splitting footgun.
            afeat_args=()
            [[ "$amode" == reasm ]] && afeat_args=(--features reassembly)
            if WZ_LWIP_PORT="$lwip_port" cargo build --release \
                --manifest-path deploy/mcu-session-acceptor/Cargo.toml \
                --target "$atarget" --bin mcu-session-acceptor "${afeat_args[@]}" --quiet; then
                echo "  Q.4.${amachine}.${alabel} build mcu-session-acceptor ${atarget} OK"
            else
                echo "  Q.4.${amachine}.${alabel} build mcu-session-acceptor ${atarget} FAIL" >&2
                fail=1
                continue
            fi
            any_built=1

            if [[ "$has_qemu" -ne 1 ]]; then
                echo "  Q.4.${amachine}.${alabel} run SKIP (qemu-system-arm not on PATH)"
                continue
            fi
            abin="deploy/mcu-session-acceptor/target/${atarget}/release/mcu-session-acceptor"
            if ! run_qemu_case \
                "Q.4.${amachine}.${alabel} run mcu-session-acceptor via qemu-system-arm ${amachine}" \
                "$acpu" "$amachine" "$abin"; then
                fail=1
            fi
        done
    done

    # ── Q.4 microbit (Cortex-M0) acceptor BOOT — the slim buffer-pool profile.
    # R311jc lifts the microbit lane from build-only (R311jb) to a real boot.
    # nrf51's 16 KB SRAM cannot hold the default ~32 KB-heap e2e, but two
    # things make it fit: (1) the `buffer-pool-session-rx-slim` feature selects
    # the 4 x 256 session-rx pool (session_rx_pool_mcu_minimal.scxml), dropping
    # the measured peak heap to ~3.15 KB; (2) the `microbit-minimal` lwIP port
    # (MEM_SIZE 2048 + trimmed pools) frees the SRAM the M0 session-runtime
    # stack needs (~6 KB; ARMv6-M codegen spills more than M3's ~1.7 KB). Frame
    # mode only: the reassembly slot pool (4 x 4096 = 16 KB) does not fit nrf51
    # (a separate slim-reassembly-pool concern, not wired here). A DIFFERENT
    # WZ_LWIP_PORT than the mps2 lanes, so it is its own block, not a tuple row.
    if grep -q "^thumbv6m-none-eabi$" <<< "$installed"; then
        local mb_port
        mb_port="$(realpath crates/lwip-sys/port/microbit-minimal)"
        if WZ_LWIP_PORT="$mb_port" cargo build --release \
            --manifest-path deploy/mcu-session-acceptor/Cargo.toml \
            --target thumbv6m-none-eabi --bin mcu-session-acceptor \
            --features buffer-pool-session-rx-slim --quiet; then
            echo "  Q.4.microbit.slim build mcu-session-acceptor thumbv6m-none-eabi OK"
            any_built=1
            if [[ "$has_qemu" -ne 1 ]]; then
                echo "  Q.4.microbit.slim run SKIP (qemu-system-arm not on PATH)"
            elif ! run_qemu_case \
                "Q.4.microbit.slim run mcu-session-acceptor via qemu-system-arm microbit" \
                cortex-m0 microbit \
                "deploy/mcu-session-acceptor/target/thumbv6m-none-eabi/release/mcu-session-acceptor"; then
                fail=1
            fi
        else
            echo "  Q.4.microbit.slim build mcu-session-acceptor thumbv6m-none-eabi FAIL" >&2
            fail=1
        fi
    else
        echo "  Q.4.microbit SKIP (rustup target thumbv6m-none-eabi absent)"
    fi

    # ── Q.5 — R311mi multicast footprint artifact (deploy/mcu-multicast-e2e).
    #
    # Cross-builds the FULL MCU multicast profile bin (session-lwip +
    # transport-multicast + transport-fragmentation + codec-push) on the
    # mps2-class triples (M3 / M4 / M7) and footprint-gates each via
    # `check-footprint.sh <target> multicast-e2e`. NO qemu boot: multicast
    # self-loopback is a host-only lwIP affordance (the cross port omits
    # LWIP_LOOPIF_MULTICAST), so run_multicast_e2e returns join_ok=false on
    # QEMU — the RUNTIME proof is the host C1r lane; this lane is build +
    # footprint-size only. mps2-class only: the 32 x 1536 multicast rx pool
    # (~49 KB, slim-toggle-independent) does not fit nrf51's 16 KB SRAM (a slim
    # multicast pool is a deferred item), so thumbv6m is not built/gated here.
    # Reaches here only with arm-none-eabi-gcc present (the Q.1 gate returned
    # early otherwise); $lwip_port is the same cross-test port the Q.2/Q.4
    # builds use.
    local mctarget
    for mctarget in thumbv7m-none-eabi thumbv7em-none-eabihf; do
        if ! grep -q "^${mctarget}$" <<< "$installed"; then
            if [[ -n "${WZ_Q_REQUIRE:-}" ]]; then
                echo "  Q.5.${mctarget} FAIL — required (WZ_Q_REQUIRE set) but" \
                     "rustup target absent (provisioning regression)" >&2
                fail=1
            else
                echo "  Q.5.${mctarget} SKIP (rustup target absent)"
            fi
            continue
        fi
        if WZ_LWIP_PORT="$lwip_port" cargo build --release \
            --manifest-path deploy/mcu-multicast-e2e/Cargo.toml \
            --target "$mctarget" --bin mcu-multicast-e2e --quiet; then
            echo "  Q.5.${mctarget} build mcu-multicast-e2e OK"
            any_built=1
        else
            echo "  Q.5.${mctarget} build mcu-multicast-e2e FAIL" >&2
            fail=1
            continue
        fi
        # Footprint gate (ROM-axis ±256 B; bss INFO). No qemu run for this bin.
        if ! bash scripts/check-footprint.sh "$mctarget" multicast-e2e; then
            fail=1
        fi
    done

    # ── Q.6 — R311y190 multicast RUNTIME proof (deploy/mcu-multicast-e2e).
    #
    # The counterpart to Q.5's build+footprint-only lane: this BOOTS the MCU
    # multicast bin on QEMU and asserts a REAL on-target IGMP-join + multicast-
    # loopback roundtrip (join_ok + peer_admitted + oversize-Put fragmented +
    # reassembled into one Push -> semihost EXIT_SUCCESS). Built with the
    # `loopback-multicast` feature (routes multicast TX over the loop netif via
    # LwipLink::route_multicast_over_loopback) against the TESTMODE
    # `cross-test-mcast` lwIP port (LWIP_LOOPIF_MULTICAST + LWIP_TESTMODE) — a
    # SEPARATE ELF + port from Q.5's footprint build, so the shared cross-test
    # port + the Q.5 baseline stay byte-identical.
    #
    # R311y269 — the ELF is separate BY CONSTRUCTION now, via a dedicated
    # CARGO_TARGET_DIR. It was not before, and the claim above was false: cargo
    # keys a binary's FINAL path on (target dir, triple, profile, bin name) only
    # — features are hashed into the intermediate deps/<bin>-<hash> artifact,
    # then the last build UPLIFTS (hard-links) over the same stable path. So
    # Q.6's loopback-multicast ELF landed exactly where Q.5's footprint artifact
    # lives, and the ELF left on disk after Layer Q was ALWAYS Q.6's (bss 287244,
    # not the footprint bin's 272268 — which is how R311y268 caught it, having
    # diffed the wrong binary). The measurement was never wrong, because Q.5
    # gates immediately after its own build and before Q.6 runs — but that made
    # the gate's correctness depend on LANE ORDERING, and a future round that
    # reorders these or footprints anything after Q.6 would have silently
    # measured the wrong binary. A separate target dir makes the collision
    # unrepresentable instead of merely unreached; it also ends the per-run
    # rebuild thrash (the two lanes flip WZ_LWIP_PORT, which lwip-sys declares
    # rerun-if-env-changed, so each invalidated the other's C build).
    # mps2-class only (M3/M4/M7):
    # the ~49 KB multicast rx pool does not fit nrf51's 16 KB SRAM (thumbv6m
    # excluded, as in Q.5); an505/M33 is omitted from the M3/M4/M7 loop below —
    # the same cortex-m-rt Secure-state carry Q.2 explicitly KNOWN_SKIPs. With
    # `loopback-multicast` the bin has no loopback-only SKIP
    # arm, so QEMU exit 0 == PASS (a failed join/roundtrip exits non-zero);
    # run_qemu_case's 30s backstop bounds a runaway. This CLOSES the "MCU
    # multicast is host-only / on-target evidence deferred" debt.
    local mcast_port mcrun_lane mcmachine mccpu mctgt mcast_target_dir
    mcast_port="$(realpath crates/lwip-sys/port/cross-test-mcast)"
    # Q.6's own target dir — see the R311y269 note above. Keeps the
    # loopback-multicast ELF off Q.5's footprint artifact path for good.
    mcast_target_dir="$repo_root/deploy/mcu-multicast-e2e/target-loopback"
    declare -A mcrun_built=()
    for mcrun_lane in \
        "mps2-an385:cortex-m3:thumbv7m-none-eabi" \
        "mps2-an386:cortex-m4:thumbv7em-none-eabihf" \
        "mps2-an500:cortex-m7:thumbv7em-none-eabihf"; do
        IFS=':' read -r mcmachine mccpu mctgt <<< "$mcrun_lane"
        if ! grep -q "^${mctgt}$" <<< "$installed"; then
            echo "  Q.6.${mcmachine} SKIP (rustup target ${mctgt} absent)"
            continue
        fi
        # Build once per triple (an386 + an500 share thumbv7em-none-eabihf).
        if [[ -z "${mcrun_built[$mctgt]:-}" ]]; then
            if CARGO_TARGET_DIR="$mcast_target_dir" \
                WZ_LWIP_PORT="$mcast_port" cargo build --release \
                --manifest-path deploy/mcu-multicast-e2e/Cargo.toml \
                --target "$mctgt" --features loopback-multicast \
                --bin mcu-multicast-e2e --quiet; then
                echo "  Q.6.${mctgt} build mcu-multicast-e2e (loopback-multicast) OK"
                mcrun_built[$mctgt]=1
                any_built=1
            else
                echo "  Q.6.${mctgt} build mcu-multicast-e2e (loopback-multicast) FAIL" >&2
                fail=1
                continue
            fi
        fi
        if [[ "$has_qemu" -ne 1 ]]; then
            echo "  Q.6.${mcmachine} run SKIP (qemu-system-arm not on PATH)"
            continue
        fi
        if ! run_qemu_case \
            "Q.6.${mcmachine} run mcu-multicast-e2e (loopback-multicast) via qemu-system-arm ${mcmachine}" \
            "$mccpu" "$mcmachine" \
            "${mcast_target_dir}/${mctgt}/release/mcu-multicast-e2e"; then
            fail=1
        fi
    done

    if [[ $any_built -eq 0 && $probe_built -eq 0 ]]; then
        # R311y274 — the nothing-built backstop. WZ_Q_REQUIRE (set on the hosted
        # mcu job, which PROVISIONS the targets) turns "measured zero bytes" into a
        # FAIL: the footprint gate is the whole subject of R311y267, so it must not
        # be the one lane that reports green having gated nothing. The per-sub-lane
        # target-absent escalations above already FAIL individually under
        # WZ_Q_REQUIRE; this catches the aggregate case a future SKIP path could
        # reintroduce. Off (a host-only dev machine) it stays a soft SKIP.
        if [[ -n "${WZ_Q_REQUIRE:-}" ]]; then
            echo "Layer Q FAIL — required (WZ_Q_REQUIRE set) but nothing built" \
                 "(no Layer Q rustup targets installed?); footprint measured 0 axes" >&2
            return 1
        fi
        echo "Layer Q SKIP (no Layer Q rustup targets installed)"
        return 0
    fi
    return "$fail"
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
# A1c adds the `multicast_pubsub_loopback` two-node pub/sub e2e (a
# publisher node's JOIN + framed Push reach a group-joined subscriber
# node's registry over a real socket); its deterministic logic twin is
# the C1q `multicast_glue` unit suite. R311ko widens that invocation
# with transport-fragmentation for the oversize-put e2e (publisher
# fragments at the group batch budget, subscriber reassembles).
layer_m_scouting_multicast() {
    # R311y421 — WZ_M_REQUIRE arms this lane the way WZ_QZ_REQUIRE / WZ_A3_REQUIRE
    # arm theirs: every SKIP path below becomes a hard FAIL, and the opt-in gate
    # itself no longer applies. Hosted CI sets it.
    #
    # WHY THIS LANE IS BEING HOSTED AT ALL, against its own opt-in rationale.
    # Layer A4 reports three atoms sitting in the headline `proven` with NO
    # hosted-CI witness of any kind — router-multicast-faces, transport-multicast
    # (and codec-join's `full` claims) — and for these two the reason is that
    # EVERY witness they have lives in this lane, which is opt-in and therefore
    # runs on no default path at all, not even the pre-push sweep. A proof that
    # runs nowhere is not a proof.
    #
    # THE FLAKINESS RATIONALE, RE-READ RATHER THAN INHERITED. The comment above
    # this function says multicast is "environment-dependent: a CI CONTAINER
    # without a multicast route on the default interface drops the IGMP join".
    # That is a claim about containers, and GitHub's hosted runners are full VMs
    # with a default route, not containers. The tests also use 224.0.0.224 — the
    # link-local control block — joined with INADDR_ANY and
    # set_multicast_loop_v4(true), so sender and receiver are the same host and
    # the datagram never needs to leave it. Measured here: 5/5 green, 0 skips,
    # 15-26s. None of that PROVES the runner can join; it only means the
    # inherited rationale does not obviously apply to this environment, and the
    # only way to settle that is to run it there. The preflight below exists so
    # the answer is diagnosable in ONE run rather than an unexplained red.
    local m_required=0
    [[ "${WZ_M_REQUIRE:-0}" == "1" ]] && m_required=1
    if (( ! m_required )) && [[ "$ONLY_LAYER" != "M" && "${WZ_RUN_LAYER_M:-0}" -ne 1 ]]; then
        echo "Layer M SKIP (opt-in environment-flaky lane; --layer M or WZ_RUN_LAYER_M=1)"
        return 0
    fi
    # PREFLIGHT — report the multicast capability of THIS host before any test
    # runs, so a failure downstream can be read as "the environment cannot join"
    # versus "the code broke". Purely diagnostic: it never decides the lane,
    # because a probe that gates would just be a second place for the same
    # question to be answered wrongly.
    echo "  M preflight: multicast environment"
    ip route show type multicast 2>/dev/null | sed 's/^/    route: /' || true
    ip -o link show up 2>/dev/null | awk -F': ' '{print "    link: " $2}' | head -5 || true
    python3 - <<'PY' 2>&1 | sed 's/^/    /' || true
import socket, struct
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 0))
    mreq = struct.pack("4s4s", socket.inet_aton("224.0.0.224"),
                       socket.inet_aton("0.0.0.0"))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print("IGMP join 224.0.0.224 via INADDR_ANY: OK")
    s.close()
except OSError as exc:
    print(f"IGMP join 224.0.0.224 via INADDR_ANY: FAILED ({exc})")
    print("  -> the lane's tests cannot pass here; this is the environment,")
    print("     not the code.")
PY
    # R311od — `transport-link-tls` is added so the `round3_tls` module
    # (active scouting -> `tls/...` open over the R311oc config-threaded seam)
    # compiles and its `#[ignore]` test runs here. Without it that module is
    # empty and the scouted-side TLS dial path is unexercised (gate-skew). The
    # default features already carry tcp+udp+unicast, so round2 (tcp) and the
    # discovery-only test are unaffected — tls is purely additive.
    (cd crates && cargo test -p wz-runtime-tokio --features scouting-active,transport-link-tls \
        --test scouting_multicast_loopback -- --ignored --quiet) || return 1
    # R311of — clippy-gate the scouting-active + transport-link-tls combo so the
    # round3_tls module (and round2) get clippy coverage, not only the rustc-deny
    # the test build above already applies (mirrors the C1u/C1v all-targets
    # clippy shape). This is the one lane that builds this feature combination.
    (cd crates && cargo clippy -p wz-runtime-tokio --all-targets \
        --features scouting-active,transport-link-tls --quiet -- -D warnings) || return 1
    (cd crates && cargo test -p wz-runtime-tokio \
        --features transport-multicast,transport-fragmentation \
        --test multicast_pubsub_loopback -- --ignored --quiet) || return 1
    # R311y232/y234 — the transport-qos ARM of the multicast e2e (BOTH qos tests, the
    # `qos` filter): the POSITIVE arm (both-is_qos group, a direct
    # TokioMulticastSession::publish_qos prioritized publish delivers -- the composed
    # real-socket path + live publish_qos driver) AND the y234 NEGATIVE DISCRIMINATOR
    # (a qos publisher meets a non-qos subscriber, which REFUSES the qos JOIN -> no
    # admit, no delivery -- the config that actually exercises the is_qos wire gate).
    # Separate invocation because the default set omits transport-qos; runs in THIS
    # isolated (opt-in) multicast lane so it never contends for the multicast route
    # under load (the --ignored no-flaky discipline). The deterministic per-priority
    # band-survival proof runs unconditionally in default CI via C1bc's qos_emit_tests.
    (cd crates && cargo test -p wz-runtime-tokio \
        --features transport-multicast,transport-qos \
        --test multicast_pubsub_loopback qos \
        -- --ignored --quiet) || return 1
    # R311y454 — the `locator-iface` MULTICAST honor arm (IP_MULTICAST_IF on the
    # sender + imr_interface on the join). Its own invocation because the multicast
    # honor needs the `locator-iface` feature, which the sets above omit: without it
    # `multicast_iface_selector_v4` takes its warn-noop arm and the test is compiled
    # out entirely. This lane therefore OWNS that build variant.
    #
    # wz-INTERNAL and that is deliberate, not a gap papered over: the interface pin is
    # NOT foreign-observable on a single host. IP_MULTICAST_ALL defaults to 1 and the
    # leaking membership is per (group, device), so any other membership for the group
    # on the delivering device makes the pin invisible -- and a foreign peer has to
    # share the group to interoperate at all. Measured, not reasoned. The test uses a
    # dedicated 239.0.0.0/8 group for exactly that reason.
    # Count-guarded (`1 passed`): this leg carries a NAME FILTER, so a renamed test
    # selects 0, `cargo test` exits 0, and a bare invocation would report green having
    # run nothing. The sibling legs above select whole binaries and do not need it.
    (cd crates && cargo test -p wz-runtime-tokio \
        --features transport-multicast,locator-iface \
        --test multicast_pubsub_loopback a_multicast_iface \
        -- --ignored --quiet 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    # R311y428 — ACTIVE SCOUTING cross-impl: a wz `--scout` discovers a
    # multicast-scouting zenohd on 224.0.0.224:7446 and opens a session on the
    # locator that router's HELLO advertised. The first cross-impl witness for
    # scouting-active + scouting-multicast (both were unproven at A4 with no
    # foreign leg at all — the demo had no way to be TOLD to scout until this
    # round's `--scout` entrypoint).
    #
    # PLACED BEFORE THE PICO GUARD, deliberately: this leg needs zenohd and NOT
    # the pico CLI, so a `--layer M` on a box with zenohd but no pico CLI still
    # runs it instead of returning at the guard below. Its own prereq is checked
    # the same way Layer Z checks its externals — SKIP on a developer box that
    # has not built zenohd, FATAL under WZ_M_REQUIRE, since the hosted interop
    # job builds zenohd for Layer Z and a SKIP there would be a provisioning
    # regression wearing a green badge.
    #
    # The demo build is SEPARATE from the router-multicast-faces one further
    # down rather than merged into a single `--features a,b` build. The cost is
    # real and named here rather than hidden: two feature sets means two demo
    # builds in this lane. It buys (a) this leg keeping its position above the
    # pico guard, and (b) the `--scout` path being proven under the MINIMAL
    # feature set that is supposed to carry it — a merged build would prove only
    # that it works alongside router-multicast-faces.
    local m_zenohd="${WZ_ZENOHD_BIN:-$PWD/target/zenohd/zenohd}"
    if [[ ! -x "$m_zenohd" ]]; then
        if (( m_required )); then
            echo "  Layer M FAIL: zenohd absent ($m_zenohd) but WZ_M_REQUIRE=1 — the" >&2
            echo "    hosted job builds it for Layer Z, so its absence here is a" >&2
            echo "    provisioning regression, not a reason to skip the only cross-impl" >&2
            echo "    witness scouting-active and scouting-multicast have." >&2
            return 1
        fi
        echo "Layer M SKIP wz scout->zenohd interop (zenohd not built; \
run: bash scripts/build-zenohd.sh)"
    else
        (cd crates && cargo build -p wz-ap-demo --features scouting-active --quiet) || return 1
        # GUARDED (R311y414's helper, and the class R311y428-y427 spent four
        # rounds closing): `cargo test --test <target> -- --ignored` prints
        # `0 passed` and EXITS 0 if the case is renamed or cfg'd away, so the one
        # leg two atoms depend on would report success by silence. The count is
        # exact at 1 — this target holds one test and a drop to 0 is the failure
        # mode being guarded.
        _runci_guarded_test "M scout->zenohd" 1 \
            cargo test -p wz-integration-tests \
            --test wz_scout_zenohd_interop -- --ignored || return 1
    fi
    # R311nm — wz->pico multicast JOIN+Push interop e2e: a wz in-library
    # multicast publisher's JOIN beacon + framed Push are admitted and
    # decoded by an external zenoh-pico `z_sub -m peer` over a real UDP
    # group. Binary-dep (needs the pico CLI built) AND environment-
    # dependent (multicast routing), so it lives here in the opt-in Layer
    # M, never the default Layer E sweep. Graceful SKIP when the pico CLI
    # is absent mirrors Layer E's prereq discipline so `--layer M` without
    # pico-CLI prep does not hard-fail.
    # R311y421 — under WZ_M_REQUIRE this is FATAL, not a skip. The pico
    # interop tests below are the ONLY witnesses router-multicast-faces and
    # transport-multicast have; a hosted job that provisions the pico CLI and
    # then skips them would restore, silently, exactly the state this round is
    # closing. Same shape as the WZ_QZ_REQUIRE / WZ_A3_REQUIRE arming.
    if [[ ! -x target/zenoh-pico-cli/z_sub ]]; then
        if (( m_required )); then
            echo "  Layer M FAIL: zenoh-pico CLI absent but WZ_M_REQUIRE=1 — this job" >&2
            echo "    provisions it, so its absence is a provisioning regression, not a" >&2
            echo "    reason to skip the only witnesses two atoms have." >&2
            return 1
        fi
        echo "Layer M SKIP wz->pico multicast interop (zenoh-pico CLI not built; \
run: bash scripts/build-zenoh-pico-cli.sh)"
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_publisher_to_pico_multicast_zsub -- --ignored --quiet) || return 1
    # R311no — pico -> wz multicast dial-in (the reverse of the lane
    # above): an external zenoh-pico `z_pub -m peer` multicast publisher's
    # JOIN beacon + framed Push are admitted (dispatcher active_peers==1,
    # a DIRECT in-process observation) and decoded byte-exact by a wz
    # in-library multicast subscriber that co-binds the group port — made
    # possible by the SO_REUSEADDR/SO_REUSEPORT bind added to
    # `UdpDriver::bind_multicast_v4` this round. Needs the pico `z_pub` CLI
    # (the z_sub check above covers it — the same build script emits both).
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_subscriber_from_pico_multicast -- --ignored --quiet) || return 1
    # R311y193 — router-multicast-faces S4: a wz `--router-hat` egresses a routed,
    # re-literalized Put over the data-plane multicast group to a foreign pico
    # `z_sub -m peer` (the LAST slice, the atom's first cross-impl egress proof).
    # Needs the DEMO built with router-multicast-faces (the mcast-attach block is
    # cfg'd on THAT feature, `runner.rs:2100`; a `router-hat-router`-only build
    # elides it). Layer M builds no demo of its own, so build it here; the build
    # is already compile-proven by Layer C1ay (`--features router-multicast-faces`
    # at line ~1220). ONE binary serves the `--router-hat` node + the
    # `--connect --publish` publisher. Reached only past the pico-CLI presence
    # guard above, so it never builds when the lane is SKIPping for a missing CLI.
    (cd crates && cargo build -p wz-ap-demo --features router-multicast-faces --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_multicast_pico_interop -- --ignored --quiet) || return 1
    # R311y195 — router-multicast-faces INGRESS I2 (the reverse of S4): a real pico
    # `z_pub -m peer` (LITERAL) publishes over the group; the wz `--router-hat`
    # RECEIVES it on its ingress group face and routes it to a wz unicast
    # subscriber. Reuses the demo built just above (--features
    # router-multicast-faces); reached only past the pico-CLI presence guard.
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_multicast_ingress_pico_interop -- --ignored --quiet) || return 1
    # R311y198 — router-multicast-faces INGRESS I3c: TWO wz `--router-hat` processes
    # share the data-plane group AND mesh-peer over TCP; a foreign pico `z_pub -m peer`
    # injects a Put; an off-group `--peer` subscriber receives the DR-federated copy.
    # Proves the per-keyexpr Designated-Router election converges cross-process (the
    # JOIN->member-relay->election chain the I3b unit tests inject past) and is
    # LOOP-SAFE (EXACTLY ONE of the two routers federates the group-ingress into the
    # mesh). Reuses the demo built above (--features router-multicast-faces); reached
    # only past the pico-CLI presence guard.
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_multicast_ingress_federation_interop -- --ignored --quiet) || return 1

    # R311y200 sub plane (S3) — cross-impl REACHABILITY: a stock pico `z_sub -m peer`
    # subscribes on the group; the wz `--router-hat` ingests its DeclareSubscriber and
    # advertises it into the unicast mesh (S1/S2); an OFF-group `--peer --publish` whose
    # publish is subscription-gated reaches the pico ONLY via that advertisement. Proves
    # cross-router reachability limit (a) against a foreign, unmodified pico subscriber.
    # Reuses the demo built above (--features router-multicast-faces); past the pico guard.
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_multicast_reach_pico_zsub -- --ignored --quiet) || return 1
}

# ─── Layer Z — wz <-> zenohd (zenoh-full reference router) interop ────
#
# R311or — the first cross-impl interop against the REFERENCE Rust router
# (zenohd v1.5.0), not zenoh-pico. Built on the SAME binary + harness SSOT as
# the pico interop suite: the wz side is the `wz-ap-demo --connect <zenohd>`
# binary (already version 0x09 + whatami Client on its initiator path), zenohd
# is the foreign router, and the wz-integration-tests `common` harness
# orchestrates. Legs span handshake wire-parity, pub/sub, query/queryable, and
# liveliness over TCP (legs 1-7); R311pk adds WebSocket-transport legs (8-9) that
# dial zenohd's `ws/` listener with wz's WS transport while pico stays on TCP
# (zenoh-pico has no native WS — emscripten-only).
#
# Default gate (R311pt — opt-in axis retired), binary-dep: zenohd is an external
# 1.5.0 build (scripts/build-zenohd.sh), not a wz artifact. The "external binary"
# boundary is now expressed by the presence checks below — graceful SKIP when
# zenohd or the pico CLI is absent (mirrors Layer M/E prereq discipline), gate
# when a developer voluntarily built zenohd to verify interop. The test
# (tests/wz_to_zenohd_router.rs) locates zenohd via WZ_ZENOHD_BIN or the build
# script's target/zenohd/zenohd default.
# R311y265 — the Layer Z twin of `_qz_unavailable` (R311y25: "a should-run lane that
# SKIPs is the burn"). Layer Z's prerequisites are EXTERNAL binaries, so a developer's
# machine may legitimately lack them and a SKIP there is honest. The hosted `interop` job
# is different: its steps GUARANTEE zenohd (source-built, so it also carries the
# storage-manager plugin) and the zenoh-pico CLIs, so a SKIP there is a provisioning
# regression masquerading as success — and it would lie twice, because Layer A4 treats
# "this lane is in ci.yml" as evidence its proofs EXECUTED. That job sets WZ_Z_REQUIRE=1.
# Returns 0 = skip-green, 1 = required-but-absent.
_z_unavailable() {
    if [[ -n "${WZ_Z_REQUIRE:-}" ]]; then
        echo "  Layer Z FAIL — required (WZ_Z_REQUIRE set) but $1" >&2
        return 1
    fi
    echo "  Layer Z SKIP ($1)"
    return 0
}

layer_z_zenohd_interop() {
    # Default gate (R311pt — opt-in axis retired). The "external binary,
    # never gates the default sweep" boundary is now expressed purely by
    # the zenohd / pico-CLI presence checks below: a machine that has not
    # built zenohd SKIPs, a machine that voluntarily built it (intending to
    # verify interop) gates on every default sweep. The harness is
    # deterministic (R311ou --test-threads=1 removed the starvation race).
    local zenohd="${WZ_ZENOHD_BIN:-$PWD/target/zenohd/zenohd}"
    if [[ ! -x "$zenohd" ]]; then
        _z_unavailable "zenohd not built ($zenohd; run: bash scripts/build-zenohd.sh)" || return 1
        return 0
    fi
    if [[ ! -x target/zenoh-pico-cli/z_sub ]]; then
        _z_unavailable "zenoh-pico z_sub not built (run: bash scripts/build-zenoh-pico-cli.sh)" || return 1
        return 0
    fi
    # R311y140 — the router-hat interop leg 2 spawns z_pub too (a pico client of
    # zenohd), which `zenoh_pico_cli_binary` panics on if absent. build-zenoh-pico-
    # cli.sh builds z_pub + z_sub together, so this is a symmetry guard, not an
    # expected split — SKIP (not FAIL) on the near-impossible z_sub-without-z_pub.
    if [[ ! -x target/zenoh-pico-cli/z_pub ]]; then
        _z_unavailable "zenoh-pico z_pub not built (run: bash scripts/build-zenoh-pico-cli.sh)" || return 1
        return 0
    fi
    # R311y147 — the router-hat interop leg 4 (QUERY plane) spawns the pico
    # z_querier (the PERSISTENT querier that installs a write-filter, unlike
    # one-shot z_get) + z_queryable. z_queryable ships with the base TARGETS;
    # z_querier was added to build-zenoh-pico-cli.sh in R311y147. Same near-
    # impossible symmetry guard as z_pub: build-zenoh-pico-cli.sh emits all CLIs
    # together, so a missing z_querier means a stale build -> SKIP, not FAIL.
    if [[ ! -x target/zenoh-pico-cli/z_querier ]]; then
        _z_unavailable "zenoh-pico z_querier not built (run: bash scripts/build-zenoh-pico-cli.sh)" || return 1
        return 0
    fi
    # R311y536 — BUILD the C-ABI cdylib here, with the same features Layer E
    # selects. This lane runs the three zenohd-named drop-in legs that Layer E's
    # `--skip zenohd` deliberately hands to it, and every one of them links
    # `libwz_capi_pico.so`. Layer E built that artifact and Z did not, which is
    # invisible locally (one checkout, one target dir, E ran first) and is the
    # whole failure on hosted CI, where E and Z are SEPARATE JOBS on separate
    # machines: Z reached `assert_capi_cdylib_is_not_stale` with whatever the
    # cache happened to restore and the lane red on a staleness check rather
    # than on anything about zenoh.
    #
    # `--features transport-link-tls` is not optional and must not drift from
    # Layer E's line: two lanes building ONE artifact path at different feature
    # sets is the misdiagnosis shape this file has paid for before — the second
    # build silently replaces the first, and the legs that needed the missing
    # feature fail as if wz were wrong.
    #
    # A build, never a SKIP: the same rule Layer E states for the demo and the
    # silent peer. Skipping green on a wz artifact we can produce would let the
    # lane report success having linked nothing.
    (cd crates && cargo build -p wz-capi-pico --features transport-link-tls --quiet) || return 1
    # §5.21 token cross-impl leg — the router-hat token lifecycle leg spawns the
    # pico z_sub_liveliness (the liveliness SUBSCRIBER that prints "New alive
    # token" on the future push + "Dropped token" on the undeclare; z_get_liveliness
    # is a one-shot GET that can witness neither). z_sub_liveliness was added to
    # build-zenoh-pico-cli.sh alongside z_liveliness; same near-impossible symmetry
    # guard as z_querier -> SKIP (not FAIL) on a stale build missing it.
    if [[ ! -x target/zenoh-pico-cli/z_sub_liveliness ]]; then
        _z_unavailable "zenoh-pico z_sub_liveliness not built (run: bash scripts/build-zenoh-pico-cli.sh)" || return 1
        return 0
    fi
    # R311y443-review (REVIEWER 3, NIT 2) — the R311y442 advanced-pubsub
    # DISCRIMINATOR leg (zenoh_ext_cache_refuses_a_get_without_anyke) spawns the
    # pico z_get, which `zenoh_pico_cli_binary` PANICS on if absent while the
    # four guards above SKIP. So a partial pico build reddened this lane as a
    # test failure instead of skipping it cleanly — the reviewer hit exactly
    # that on a fresh worktree. Same near-impossible symmetry guard as the rest:
    # build-zenoh-pico-cli.sh emits every CLI together, so a missing z_get means
    # a stale build -> SKIP, not FAIL.
    if [[ ! -x target/zenoh-pico-cli/z_get ]]; then
        _z_unavailable "zenoh-pico z_get not built (run: bash scripts/build-zenoh-pico-cli.sh)" || return 1
        return 0
    fi
    # wz-ap-demo is the wz client (--connect zenohd) for the client-tier legs
    # AND the `--router-hat` node for the R311y140 router-tier federation leg
    # (wz_router_hat_zenohd_interop). Build it with BOTH the `ws` feature
    # (R311pk; renamed from `connect-ws` in R311pp — the WS legs 8/9 dial
    # `ws/...`) and `router-hat-router` (the run-mode presenting wire
    # WhatAmI::Router). Both are additive — the TCP client legs 1-7 dial through
    # the same binary unchanged; pico dials TCP (zenoh-pico has no native WS).
    # `routing-token-tables` (R311y170-175) is additive: it compiles the router
    # liveliness-TOKEN plane + the `pushed a future token` witness into the SAME
    # binary so the token cross-impl leg exercises it; the non-token legs 1-8 dial
    # through the unchanged binary. router-hat-router is redundant under the
    # passthrough but kept explicit to match this line's documenting comment.
    # `unixsock` (R311y364) is additive too: it compiles the `unixsock-stream/`
    # DIAL transport so the unixsock cross-impl legs 10/11 dial
    # `--connect unixsock-stream/<path>` against zenohd's unixsock listener; every
    # TCP/WS leg dials through the unchanged binary (pico has no unixsock link).
    # `tls` (R311y365) is additive too: it compiles the `tls/` DIAL transport +
    # the `--tls-ca <path>` cert affordance so the TLS cross-impl legs 12/13 dial
    # `--connect tls/127.0.0.1:port --tls-ca <cert>` against zenohd's `tls/`
    # listener; every TCP/WS/unixsock leg dials through the unchanged binary.
    # `quic` (R311y366) is additive too: it compiles the `quic/` DIAL transport +
    # the `--quic-ca <path>` cert affordance so the QUIC cross-impl legs 14/15 dial
    # `--connect quic/127.0.0.1:port --quic-ca <cert>` against zenohd's `quic/`
    # listener; every TCP/WS/unixsock/tls leg dials through the unchanged binary.
    # `namespace` (R311y369) is additive too: it compiles the `--namespace <prefix>`
    # CLI (routing-namespace) so leg 18 publishes a bare key under a namespace and
    # a pico `<prefix>/**` z_sub receives the wire-prefixed keyexpr; every other leg
    # (no --namespace) dials through the unchanged binary.
    # `transport-lowlatency` (R311y372) is additive too: it compiles the
    # `--lowlatency` CLI so the lowlatency cross-impl leg dials `--connect ...
    # --lowlatency` and NEGOTIATES zenoh's lean (Frame-less) transport against a
    # zenohd whose `transport/unicast/lowlatency` is on; every other leg (no
    # --lowlatency) dials through the unchanged binary on the universal transport.
    # R311y376 — `routing-router` added so the Layer Z binary carries the `--router`
    # accept-and-hold mode (the multi-peer accept loop) for the ws-router-acceptor
    # leg below; a superset over the acceptor legs, inert for them (it adds a mode,
    # not a wire change), per the routing-routes-is-a-superset rationale.
    # R311y392 — `transport-link-unixpipe` added so the Layer Z binary carries the
    # `unixpipe/` DIAL + `--listen unixpipe/` ACCEPT transports for the wz<->zenohd
    # unixpipe cross-impl legs below (both directions). Additive: every TCP/WS/../..
    # leg dials through the unchanged binary (real zenoh-pico has no unixpipe link).
    # R311y400 — `vsock` added so the Layer Z binary carries the `--listen vsock/`
    # AF_VSOCK ACCEPT transport for the host-only vsock cross-impl leg below. Additive
    # (a new locator arm, inert for every other leg). This COMPILE-gates the demo's
    # vsock acceptor arm on EVERY CI run even though the leg itself runs only on a
    # vsock-capable host (the runner has no vsock_loopback) — the same compile-on-CI /
    # run-on-host split as the C1ab vsock lane.
    # R311y408 — `quic-datagram` added so the Layer Z binary carries the `--listen
    # quic-datagram/` RFC9221 unreliable-DATAGRAM ACCEPT transport for the
    # quic-datagram acceptor cross-impl leg below. Additive (a new locator arm, inert
    # for every other leg); it IMPLIES `quic` (shared cert plumbing), already present.
    # quic-datagram is in zenoh's DEFAULT features and zenohd enables `zenoh/default`,
    # so the DEFAULT oracle dials it -- NO special oracle (unlike vsock/unixpipe).
    # R311y433 — `session-extcompression` added so the Layer Z binary carries the
    # `--compression` CLI for the per-batch lz4 cross-impl leg below. It pulls
    # `transport-compression` through the wz facade, so ONE feature brings both the
    # 0x6 handshake and the lz4 wrap. Additive in the same sense as
    # transport-lowlatency: the wrap is behind `is_compression() &&
    # is_established()`, and no other leg passes `--compression`, so every other
    # leg dials through the unchanged binary. compression is in zenoh's DEFAULT
    # features and zenohd enables `zenoh/default`, so the DEFAULT oracle speaks it
    # once configured -- NO special oracle (unlike vsock/unixpipe).
    # R311y442 — `advanced` added so the Layer Z binary carries the
    # `--advanced-subscribe` / `--advanced-publish` CLI for the advanced-pubsub
    # cross-impl legs below. It forwards BOTH halves of the plane through the wz
    # facade (`ext-pubsub-advanced-history` for the asking side,
    # `-advanced-publisher` for the answering side), because the two legs witness
    # opposite directions and neither alone covers the other. Additive like the
    # rest of this list: the advanced subscriber / publisher are declared only when
    # their flags are passed, so every other leg dials through the unchanged binary.
    # R311y454 adds `locator-iface` (the `#iface=` HONOR). Two reasons, and the
    # second is the load-bearing one: the new `wz_quic_acceptor_iface_zenohd_interop`
    # leg needs a demo that actually honours the tail, AND the A4 cross-impl gate
    # requires every `active` atom a proof CLAIMS to sit inside the feature closure
    # of a crate the proof builds (`crossimpl_audit.py` containment). `locator-iface`
    # was in NEITHER closure, so the claim would have failed containment regardless
    # of the test. KEEP THIS ON ONE LINE: `feature_closure.py`'s scraper is
    # `cargo build -p wz-ap-demo[^\n|)]*?--features ([A-Za-z0-9_,-]+)`, whose class
    # cannot cross a newline — a `\`-continued build silently drops the WHOLE feature
    # set from the closure and reds A4-5.
    # R311y471 adds `routing-peer`: the new `wz_advertised_locator_zenohd_dial` leg
    # drives `--peer`, whose `run_peer` path is this crate's only ADVERTISE seam
    # (`BoundListener::advertised_locator` -> `set_self_locators`), and that path is
    # `routing-peer`-gated. Additive like the rest: no other leg passes `--peer`, so
    # they all dial through the unchanged binary.
    # R311y472 adds `transport-multilink` for the same two reasons: the new
    # `wz_multilink_aggregation_zenohd_interop` leg drives `--max-links`, which is
    # parsed only under that feature, AND its `transport-multilink` claim must sit
    # inside this build's feature closure or A4-5 containment reds. Additive: the
    # knob defaults to 1 (single-link), so every other leg dials unchanged.
    # R311y473 adds NOTHING here, and that is a measured result rather than an
    # assumption. Its new leg drives `--config-queryable`, whose handler block is
    # `adminspace-core`-gated, and its claim needs that feature inside this closure
    # for A4-5 containment. `adminspace-core` is absent from preset-ap-client -- but
    # checking only the preset is checking the wrong set: `routing-peer` (added here
    # by R311y471) pulls `wz/adminspace-core` (wz-ap-demo/Cargo.toml), so the FULL
    # build line already carries it. Resolved from wz-ap-demo's own feature table,
    # not read off one preset.
    (cd crates && cargo build -p wz-ap-demo --features ws,unixsock,tls,quic,quic-datagram,routing-router,router-hat-router,routing-token-tables,namespace,transport-lowlatency,session-extcompression,transport-link-unixpipe,vsock,advanced,group,locator-iface,routing-peer,transport-multilink --quiet) || return 1
    # R311y442 review (REVIEWER 3, finding 3) added a clippy of the demo's
    # `advanced` arm right here, closing the `-D warnings` hole R311y433 closed
    # for transport-lowlatency and session-extcompression. R311y443-review
    # (REVIEWER 3, NIT 1) MOVED it to Layer C1aq: this point is past Z's zenohd
    # and pico presence guards, each of which `return 0`, so on a box without the
    # foreign binaries the gate SKIPped green — measured. C1aq needs no external
    # binary and cannot skip.
    # R311ou — `--test-threads=1`: serialize the zenohd interop tests. Each
    # spawns a full external zenohd router + its wz-ap-demo / z_pub / z_sub
    # children; run concurrently (cargo's default), 3 zenohd instances + clients
    # contend for CPU during the wz<->zenohd handshake, and a per-test 10s
    # readiness wait occasionally starves (observed ~1/10 as
    # `wz_client_reaches_established` / `wz_routed_subscribe` "did not log ...
    # within 10s"). Serializing removes the contention at the ROOT (each test
    # runs in isolation, the same condition as the 20/20-stable standalone) — a
    # structural fix, not a load-mitigation timeout bump. These are heavy
    # e2e tests, so serial execution costs only wall-clock, not coverage.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_to_zenohd_router -- --ignored --quiet --test-threads=1) || return 1
    # R311y372 — wz LOWLATENCY transport cross-impl: wz dials zenohd with
    # `--lowlatency`, negotiates the Z_EXT_LOWLATENCY unit ext (asserted true via
    # the demo log), and its lean (4-byte-prefixed, Frame-less) Put routes through
    # a lowlatency-configured zenohd to a pico z_sub. zenoh-pico has NO lowlatency
    # transport, so zenohd is the only foreign witness. Same --test-threads=1
    # per-zenohd isolation as the client legs above.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_lowlatency_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y433 — wz per-batch lz4 COMPRESSION cross-impl: wz dials zenohd with
    # `--compression`, negotiates Z_EXT_COMPRESSION 0x6 (asserted true via the demo
    # log), and a COMPRESSIBLE Put — sized so `compress_batch` provably keeps the
    # compressed form rather than shipping raw with the bit clear — routes through a
    # compression-configured zenohd to a pico z_sub. zenoh-pico has NO compression,
    # so zenohd is the only foreign witness. TWO legs in the one target: the proof
    # plus its calibration twin against a STOCK zenohd (negotiated = false, delivery
    # still works over the un-wrapped wire), which is what forbids reading the
    # proof's `negotiated = true` as a hardcoded constant. No `--features` on this
    # invocation: the interop target drives EXTERNAL binaries, so the atom is
    # compiled into the wz-ap-demo build above, not into the test.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_compression_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y505 — the SHM ESTABLISHMENT interop, and it needs its OWN oracle: zenoh's
    # `default` feature set omits `shared-memory` (zenoh/Cargo.toml:34-46) and
    # zenohd's default is `zenoh/default`, so the stock binary above has no
    # `init::ext::Shm` compiled in and can neither send the challenge nor react to
    # wz's offer. Built by `ZENOHD_SHM=1 scripts/build-zenohd.sh` into
    # target/zenohd-shm/; ABSENT is a SKIP inside the test (the vsock precedent —
    # hosted CI does not provision a source build for this).
    #
    # The demo is rebuilt with `session-extshm` for these two legs alone, and the
    # test asserts the BUILD FEATURES line rather than trusting this invocation
    # (the one-shared-artifact-path discipline).
    #
    # Leg 2 is the one that earned the lane: it caught wz reading a real zenoh
    # `Shm` ZBuf (header 0x42) as its own UNIT offer at the same 4-bit id, which
    # negotiated SHM with a peer that had issued a challenge wz cannot answer.
    # R311y506 — the `init::ext::QoSLink` interop (the z64 half of zenoh's dual QoS
    # establishment ext: the link's priority band + reliability class, and the
    # DIRECTIONAL containment that negotiates it). Four legs against the STOCK
    # oracle above — `QoSLink` is not feature-gated in zenoh and its default config
    # has `transport.unicast.qos.enabled = true`, so no variant build is needed.
    #
    # Three legs have zenohd DIAL wz, which is not a stylistic choice: zenoh seeds
    # its QoS state from an ENDPOINT's `prio=`/`rel=` metadata, and on the ACCEPT
    # side that endpoint is the accepted link's src locator, which zenoh-link-tcp
    # builds with a hard-coded EMPTY metadata string (unicast.rs:103). A listening
    # zenohd therefore has no band at all, and pointing wz at one witnesses nothing
    # — measured first, and it accepted a deliberately non-subset band.
    #
    # The demo is rebuilt with `session-extqos` for these legs alone (the same
    # one-shared-artifact-path treatment as the SHM lane above), and the test
    # asserts the BUILD FEATURES line rather than trusting this invocation.
    (cd crates && cargo build -p wz-ap-demo --features session-extqos --quiet) || return 1
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_qos_link_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    (cd crates && cargo build -p wz-ap-demo --features session-extshm --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_shm_establishment_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # Restore the lane's OWN demo build: the `session-extshm` build above wrote over
    # the same `--bin` path (R311y269 — cargo uplifts every feature variant of one
    # bin to one path), and every leg after this point expects the big feature set
    # this lane opened with. Restated verbatim rather than referenced, because a
    # drift between the two lines would be silent.
    (cd crates && cargo build -p wz-ap-demo --features ws,unixsock,tls,quic,quic-datagram,routing-router,router-hat-router,routing-token-tables,namespace,transport-lowlatency,session-extcompression,transport-link-unixpipe,vsock,advanced,group,locator-iface,routing-peer,transport-multilink --quiet) || return 1
    # R311y435 — wz COMPOSED lowlatency x compression cross-impl: the measurement
    # R311y434 explicitly did NOT claim ("no leg dials zenohd with both modes,
    # because the demo cannot stage both offers"). The offer-SET widening of
    # session_open removes that blocker, so wz now dials `--lowlatency
    # --compression` against a zenohd configured for BOTH (a configuration
    # upstream permits: the exclusivity at unicast/manager.rs:264 names qos, not
    # compression). TWO legs: the proof asserts both exts negotiate, that the lz4
    # wrap is nonetheless reported INACTIVE (`batch compression active = false`,
    # the R311y434 negotiated-vs-applied split made externally observable), and
    # that the lean Put routes through to a pico z_sub; the option-atom TWIN drops
    # ONLY the --lowlatency offer against the SAME router and reads `active =
    # true`, which is what attributes the suppression to that offer. This is the
    # first FOREIGN witness for the R311y434 fix — until now it had a wz<->wz byte
    # assertion only. No `--features` here: the interop target drives EXTERNAL
    # binaries, so both atoms are compiled into the wz-ap-demo build above.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_compose_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y438 — wz TX FRAGMENTATION cross-impl (transport-fragmentation
    # wz->zenohd). `transport-fragmentation` had witnesses in both PICO
    # directions and none against zenohd, because wz negotiates batch_size 65535
    # with a router by default and nothing in the corpus lowered it. This leg
    # dials IN-PROCESS with batch_size 64, so zenohd min-negotiates to 64 and a
    # 200-byte Put is forced through the split; zenohd reassembles the chain and
    # a pico z_sub on the far side prints it byte-exact. TWO legs: the proof plus
    # its option-atom TWIN at the default batch (same publish, MTU far above the
    # payload, ZERO fragments on the wire, still delivered), which is what makes
    # the fragment count a discriminator rather than a constant. Unlike the pico
    # frag leg this one is `full`, not `partial`: wz dials through an in-test
    # counting relay that observes the T_MID_FRAGMENT chain on the wire, so
    # "wz actually fragmented" is measured here rather than deferred to the
    # wz<->wz host lane. No `--features`: the test opens the session in-process,
    # and this crate's dev-dep already pins transport-fragmentation.
    # R311y439 — GUARDED (`_runci_guarded_test`, 2 = proof + calibration twin).
    # The bare form this leg used until now is the "success by silence" class
    # documented at the helper: `--ignored` selecting ZERO tests still exits 0,
    # and because both names carry the `zenohd` token that Layer E skips by
    # substring, an elided test would then run in NO lane with every lane green.
    _runci_guarded_test Z 2 env WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_fragment_tx_zenohd_interop -- --ignored --quiet --test-threads=1 || return 1
    # R311y439 — wz RX FRAGMENTATION cross-impl (transport-fragmentation
    # zenohd->wz), the direction R311y438 explicitly left open ("the tiny MTU
    # binds BOTH ways ... but nothing asserts it, so no claim is made"). wz
    # dials IN-PROCESS with batch_size 64 and declares a ROUTED subscriber; a
    # pico z_pub publishes a 200-byte value into zenohd, which must SPLIT the
    # routed Put to reach wz, and wz reassembles it into one byte-exact Sample.
    # The pico->wz leg (wz_reassembles_pico_fragment_tx) proves a different
    # fragmenter: pico splits at a compiled constant with no router in the path,
    # zenohd's is the full Rust pipeline splitting a message it is ROUTING. TWO
    # legs: the proof plus its option-atom TWIN at the default batch (same
    # route, MTU far above the payload, ZERO fragments on the wire AND zero RX
    # reassembly, still delivered). Two independent halves: the shared counting
    # relay observes ZENOHD's chain on the wire (here the tag is produced by the
    # FOREIGN side, not merely recognised by wz), and wz's own drive loop
    # reports the reassembly branch plus a chain terminator. No `--features`:
    # the test opens the session in-process, and this crate's dev-dep already
    # pins transport-fragmentation.
    _runci_guarded_test Z 2 env WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_fragment_rx_zenohd_interop -- --ignored --quiet --test-threads=1 || return 1
    # R311y528 — §5.27 api-compat-pico LEG 9: upstream's own `z_info.c`, linked
    # against wz's cdylib, must report a REAL zenohd's zid under "Routers IDs".
    #
    # It lives in the DROP-IN test file, whose other eleven legs run in Layer E,
    # and it is registered HERE by exact test name for one reason: Layer E's
    # sweep carries `--skip zenohd` because Layer E does not provision the
    # router. The leg was written, registered, and NOT RUN — measured, by reading
    # the lane's own log and finding "11 passed; 1 filtered out" against a
    # twelve-leg file. Renaming the test to dodge the skip token would have made
    # Layer E red on any machine without zenohd; naming it in the lane that DOES
    # provision one is the fix. The whatami split it pins needs both halves, and
    # its peer-side twin (LEG 10) runs in Layer E.
    _runci_guarded_test Z 1 env WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test pico_c_examples_on_wz_capi_dropin \
        pico_zinfo_source_on_wz_capi_reports_a_real_zenohd_as_a_router \
        -- --ignored --quiet --test-threads=1 || return 1
    # LEG 9z — the same program with zenohd's zid PINNED to one whose leading
    # nibble is zero. Registered here rather than in Layer E for the identical
    # reason as the leg above (its name carries the `zenohd` skip token, and it
    # provisions a router), and it exists because LEG 9 was a 1-in-16 FLAKE from
    # the day it was written: it asserted its oracle was 32 hex characters, and
    # `uhlc::ID` renders through `{:x}` over a `u128`, so a zid whose top nibble
    # is zero logs 31. The C side never trims. LEG 9 cannot discriminate that
    # rule — measured, by a damage probe: making `z_id_to_string` trim leaves
    # LEG 9 GREEN and reds this one with the two spellings side by side.
    _runci_guarded_test Z 1 env WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test pico_c_examples_on_wz_capi_dropin \
        pico_zinfo_source_on_wz_capi_pads_a_short_zenohd_zid_to_32 \
        -- --ignored --quiet --test-threads=1 || return 1
    # R311y530 — the SCOUTING plane's witness, and the second leg of the drop-in
    # file that needs a router. Upstream's `z_scout.c` is compiled TWICE against
    # the same pico headers -- once linked to wz's cdylib, once to the real
    # `libzenohpico.so` -- and the two must print the SAME `Hello { ... }` line
    # for the same zenohd. Registered here for exactly the reason the leg above
    # is: Layer E's sweep carries `--skip zenohd`, and this test's name carries
    # that token ON PURPOSE so the sweep skips it rather than reding on a machine
    # with no router. It ALSO needs the CMake-built `libzenohpico.so`, which is
    # the same artifact Layer E's pico legs depend on, so no new prereq.
    _runci_guarded_test Z 1 env WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test pico_c_examples_on_wz_capi_dropin \
        pico_zscout_source_on_wz_capi_matches_the_real_pico_against_a_zenohd \
        -- --ignored --quiet --test-threads=1 || return 1
    # R311y533 -- the LIVELINESS SNAPSHOT leg, moved here from Layer E because
    # its old topology was one the REFERENCE cannot serve. Measured: the real
    # zenoh-pico z_get_liveliness against the real zenoh-pico z_liveliness, wired
    # peer-to-client with no router, reports ZERO tokens and hangs, 6 runs of 6;
    # with a zenohd between them the same foreign pair answers at once. The leg
    # was passing about one run in three on wz for that reason, not because wz
    # was at fault -- wz was being MORE permissive than pico. It now uses the
    # topology the oracle actually serves, which needs a router, which is this
    # lane. The flakiness also exposed a real wz defect, fixed separately:
    # `Session::sweep_expired_liveliness_gets` (the C ABI armed a liveliness-get
    # deadline that no host ever swept, so an unanswered snapshot blocked the C
    # caller in `z_recv` forever).
    _runci_guarded_test Z 1 env WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test pico_c_examples_on_wz_capi_dropin \
        pico_zgetliveliness_source_on_wz_capi_sees_a_real_pico_token_through_zenohd \
        -- --ignored --quiet --test-threads=1 || return 1
    # R311y442 — wz<->zenoh-ext ADVANCED-PUBSUB cross-impl, the FIRST foreign
    # witness the `@adv` plane has ever had. Every advanced-pubsub test before
    # this was wz<->wz, which cannot see a selector-dialect divergence: the same
    # wrong spelling sits on both ends and they agree. Two such divergences were
    # live (a `&` list separator where zenoh and pico both use `;`, and a missing
    # `_anyke` without which zenoh's responder refuses every `@adv` reply), and
    # they COMPOUND — under `&` the whole selector reads as one `_max` value and
    # swallows `_anyke` with it.
    #
    # The oracle is NOT zenohd: a router holds no AdvancedCache, and zenoh-pico
    # has no advanced-pubsub plane at all, so the counterparty must be an
    # application built on zenoh-ext. build-zenohd.sh provisions upstream's own
    # `z_advanced_pub` / `z_advanced_sub` examples from the same pinned checkout.
    #
    # FOUR legs. Two go RED on the pre-fix wire (wz's history GET draining a real
    # cache, and the same with a `_max` cap) and two stay green in both arms (a
    # non-`_anyke` GET refused by the same cache, proving the gate is live rather
    # than the fixture permissive; and the reverse direction, upstream's own
    # advanced subscriber draining a wz cache, which exercises wz as RESPONDER and
    # so binds the cache / publisher atoms rather than the subscriber-side ones).
    #
    # R311y443 adds a FIFTH and SIXTH: the retransmission path, which unlike
    # every leg above cannot be witnessed by two healthy peers because it engages
    # only on LOSS. A relay between zenohd and wz deletes one of the oracle's
    # samples from the wire; leg 5 (recovery armed) shows wz refilling it from the
    # foreign publisher's `@adv` cache via an `_sn=` GET, and leg 6 — same
    # fixture, same removed sample, flag omitted — shows the hole persisting.
    # Leg 6 is what binds leg 5's result to the recovery path rather than to a
    # fixture that quietly repaired itself.
    #
    # R311y444 adds a SEVENTH and EIGHTH, in the OTHER direction. Legs 5/6 witness
    # the subscriber-side recovery trigger; the publisher-side heartbeat BEACON is
    # a separate atom (`ext-pubsub-sample-miss-detection`, whose 19 cfg sites are
    # all in advanced_publisher.rs), so a leg where wz CONSUMES a foreign beacon
    # would compile none of it. Here wz PRODUCES the beacon: the relay removes the
    # burst's LAST sample, wz then stops publishing, and no later sequence number
    # can ever expose the hole — leaving the beacon as the only path by which
    # upstream's `z_advanced_sub` can learn the sample exists. Leg 8 is the same
    # fixture with the beacon unarmed, where it stays missing.
    #
    # A NINTH and TENTH close the recovery atom's third trigger. They cannot be
    # judged the way legs 5/6 are: wz's sample-driven trigger is implied by
    # recovering at all and cannot be switched off, and the oracle publishes at
    # 1 Hz forever, so BOTH arms end with the gap filled. The observable is the
    # SELECTOR instead — heartbeat asks for a BOUNDED `_sn=a..b`, sample-driven
    # for an OPEN `_sn=a..` — read out of the oracle's own `zenoh_ext=trace` log,
    # i.e. reported by the peer that received it. Leg 10 also calibrates the
    # parser: it asserts the open range PRESENT, so a parser matching nothing
    # fails there instead of satisfying leg 9's negative vacuously.
    #
    # R311y447 adds an ELEVENTH and TWELFTH for the recovery atom's LAST trigger,
    # periodic. The selector trick above does not transfer: periodic emits the
    # same OPEN `_sn=last+1..` sample-driven does, so shape cannot separate them.
    # What does is that `periodic_requests` consults no gap — it asks on every
    # tick for every known source — while sample-driven fires only from the gap
    # branch. So this fixture has NO relay: on a clean stream the periodic arm
    # keeps asking (measured 15 GETs over 8 s at a 500 ms period) and the control
    # asks nothing at all. The control is load-bearing beyond attribution: it is
    # what rules out a REPAIRED loss, which delivery contiguity cannot see, since
    # recovery refills a dropped sample into a contiguous run. Leg 11 also pins
    # that the ask ADVANCES (distinct `_sn` lower bounds), which is what a timer
    # tracking `last_delivered` produces and a sample-driven retry on one stuck
    # gap never can.
    #
    # The two REDs are not independent, and the first version of this comment said
    # they were. Measured across all three revert arms (separator only, `_anyke`
    # only, both): the failure shape is the SAME empty recovery in both legs,
    # because `&` swallows `_anyke` before the cap can matter. What the capped leg
    # adds is a positive conformance observation — a foreign cache honouring the
    # SECOND parameter of a list — not a second discriminator.
    #
    # R311y442 review (REVIEWER 3, finding 2) — GUARDED on the oracles' presence,
    # like the storage-manager plugin leg below and unlike the first draft. Both
    # binaries come from the SAME build-zenohd.sh run as zenohd itself, so a
    # missing one means a stale `target/zenohd/` (a developer who has not re-run
    # the script since this round), not a broken build. That is the lane's
    # documented SKIP case; hard-failing it made an out-of-date checkout look like
    # a regression, 20s into the lane and after the other legs had already run.
    # WZ_Z_REQUIRE still turns the SKIP into a FAIL on hosted CI, where ci.yml
    # asserts both binaries exist before any lane starts.
    local ext_examples_dir="${WZ_ZENOH_EXT_EXAMPLES_DIR:-$PWD/target/zenohd}"
    local missing_ext_example=""
    # R311y445 — z_view_size joins the guard for the GROUP-MEMBERSHIP legs. Same
    # provisioning run, same SKIP semantics: a stale target/zenohd/ means a
    # developer has not re-run build-zenohd.sh since this round, not a regression.
    for ex in z_advanced_pub z_advanced_sub z_view_size; do
        [[ -x "$ext_examples_dir/$ex" ]] || missing_ext_example="$ex"
    done
    if [[ -n "$missing_ext_example" ]]; then
        _z_unavailable "zenoh-ext example oracle not built \
($ext_examples_dir/$missing_ext_example; run: bash scripts/build-zenohd.sh)" || return 1
    else
        # R311y550 — 13, not 12. R311y544 added leg 9b (`..._on_a_double_star_base`)
        # to this binary and left the count at 12, so the lane redded on HOSTED
        # CI with "no libtest summary matched". This is the debt class the
        # ledger names: nothing ties a guard's number to its binary, and both
        # sides are readable without running the tests
        # (`cargo test --test X -- --list`).
        _runci_guarded_test Z 13 env WZ_ZENOHD_BIN="$zenohd" \
            WZ_ZENOH_EXT_EXAMPLES_DIR="$ext_examples_dir" cargo test -p wz-integration-tests \
            --test wz_advanced_pubsub_zenoh_ext_interop -- --ignored --quiet --test-threads=1 \
            || return 1
        # R311y445 — the GROUP-MEMBERSHIP family, a separate file because it is a
        # separate atom on a separate wire (bincode under
        # `zenoh/ext/net/group/...`, independent of `@adv`). Three legs: wz's
        # KEEP-ALIVE plus the per-member queryable that answers the unknown-member
        # GET it provokes (R311y445-review corrected this — upstream issues no
        # "view query" on join; its only client-side get is the one at
        # zenoh-ext/src/group.rs:307), the Join BROADCAST a foreign peer decodes,
        # and a wrong-group control. Oracle = z_view_size, which prints its own
        # verdict, so the pass/fail judgement is the FOREIGN implementation's
        # rather than an inference from wz's logs.
        _runci_guarded_test Zgroup 3 env WZ_ZENOHD_BIN="$zenohd" \
            WZ_ZENOH_EXT_EXAMPLES_DIR="$ext_examples_dir" cargo test -p wz-integration-tests \
            --test wz_group_membership_zenoh_ext_interop -- --ignored --quiet --test-threads=1 \
            || return 1
    fi
    # R311y374 — wz WebSocket ACCEPTOR cross-impl (transport-link-ws zenohd->wz):
    # a real zenohd DIALS the wz `--listen ws/...` acceptor over ws (the RFC6455
    # server upgrade wired in bind_locator/accept_locator), and a pico z_put routes
    # through zenohd ACROSS the ws link into the wz acceptor's subscriber. The
    # existing wz_to_zenohd_router legs prove only the wz ws DIALER (wz->zenohd);
    # this is the reverse (acceptor) direction. zenoh-pico has no ws client, so
    # zenohd is the only foreign ws dialer. Same --test-threads=1 per-zenohd
    # isolation; the demo is already built with `ws` above.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_ws_acceptor_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y375 — wz TLS ACCEPTOR cross-impl (transport-link-tls zenohd->wz): the tls
    # twin of the ws-acceptor leg above. A real zenohd DIALS the wz `--listen
    # tls/...` acceptor over tls (the rustls server handshake wired as the
    # BoundListener::Tls arm), trusting wz's self-signed cert; a pico z_put routes
    # through zenohd ACROSS the tls link into the wz acceptor's subscriber. The
    # existing wz_to_zenohd_router legs prove only the wz tls DIALER (wz->zenohd);
    # this is the reverse (acceptor) direction. zenoh-pico's CLI has no tls, so
    # zenohd is the only foreign tls dialer. The demo is already built with `tls`.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_tls_acceptor_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y398 — wz UNIXSOCK ACCEPTOR cross-impl (transport-link-unixsock zenohd->wz):
    # the AF_UNIX-stream sibling of the ws/tls acceptor legs above. A real zenohd
    # DIALS the wz `--listen unixsock-stream/<path>` acceptor (the
    # BoundListener::Unixsock arm wired in R311y378, proven wz<->wz by unixsock_e2e),
    # and a pico z_put routes through zenohd ACROSS the unixsock link into the wz
    # acceptor's subscriber. The existing wz_to_zenohd_router unixsock leg proves only
    # the wz unixsock DIALER (wz->zenohd); this is the reverse (acceptor) direction.
    # zenoh-pico's CLI has no unixsock client, so zenohd is the only foreign unixsock
    # dialer. The unixsock link is in STOCK zenohd (no special oracle, unlike the
    # unixpipe legs); the demo is already built with `unixsock` above. Same
    # --test-threads=1 per-zenohd isolation.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_unixsock_acceptor_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y471 — the ADVERTISE-path sibling of the leg above, and deliberately NOT a
    # duplicate of it. That leg writes `unixsock-stream/<path>` into BOTH wz's
    # `--listen` and zenohd's `-e`, so the two sides agree by construction and wz's
    # own advertised string is never consulted; it passes identically before and
    # after R311y470. This leg reads the locator wz LOGGED for itself and hands that
    # verbatim to zenohd, so it fails when wz advertises a scheme no foreign stack
    # can dial. Under the pre-R311y470 rendering zenohd EXITS 255 on the
    # `unixsock/<path>` endpoint (measured), which is what makes it a real gate.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_advertised_locator_zenohd_dial -- --ignored --quiet --test-threads=1) || return 1
    # R311y472 — wz MULTILINK AGGREGATION cross-impl (transport-multilink wz->zenohd),
    # the S4 gap the atom's own reason named: the whole C1ba behavioural lane is
    # wz<->wz, so nothing had ever put a foreign stack on the other end of the 0x4
    # MultiLink establishment ext. A `--max-links 2` wz peer dials ONE zenohd twice
    # and the verdict is read off zenohd's OWN adminspace (`@/*/router` -> one session
    # object carrying two links), never off wz's "link AGGREGATED" log. Ships with its
    # calibration twin in the same file: the SAME argv against a STOCK zenohd
    # (max_links defaults to 1) must report ONE link, so the count is reading the
    # router's budget rather than restating wz's. `transport_multilink` rides zenoh's
    # DEFAULT features, so the STOCK oracle speaks it once configured -- no variant
    # build. Same --test-threads=1 per-zenohd isolation.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_multilink_aggregation_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y473 — the READ side of the same atom: R311y472 had to ask ZENOH how many
    # links it had bound because wz's own adminspace reported none (the `sessions[]`
    # array was hard-coded empty at both admin hosts, and `to_admin_json` rendered
    # neither `max_links` nor the link set). That was transport-multilink's named S5
    # residual. Now a `--max-links 2 --config-queryable` wz peer is asked the same
    # question about ITSELF, and answers ONE router session carrying TWO links plus
    # the budget in its config body. Its calibration twin ships in the same file: the
    # SAME argv against a STOCK zenohd must report ONE link, so the number wz renders
    # follows a FOREIGN process's config and cannot be a wz-side constant. The
    # `sessions[]` body is parsed with the parser built for ZENOH's adminspace, so
    # reusing it is also the wire-shape fidelity assertion.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_own_adminspace_reports_aggregated_links -- --ignored --quiet --test-threads=1) || return 1
    # R311y399 — wz UDP-DEMUX ACCEPTOR cross-impl (transport-link-udp zenohd->wz):
    # the DATAGRAM sibling of the ws/tls/unixsock acceptor legs above, and the first
    # cross-impl proof of a structurally-datagram wz acceptor. A real zenohd DIALS
    # the wz `--listen udp/127.0.0.1:0` acceptor (bind_udp_demux -> BoundListener::Udp
    # wired in R311y382, proven wz<->wz by udp_seam_e2e), and a pico z_put routes
    # through zenohd ACROSS the udp link into the wz acceptor's subscriber. The
    # existing wz_to_zenohd_router udp leg proves only the wz udp DIALER (wz->zenohd);
    # this is the reverse (acceptor) direction. wz binds ONLY udp (no TCP listener),
    # so udp is the sole wz<->zenohd transport. udp is in STOCK zenohd + the demo
    # DEFAULT preset (no build-line change, unlike ws/tls/unixsock). Same
    # --test-threads=1 per-zenohd isolation.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_udp_acceptor_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y401 — wz QUIC ACCEPTOR cross-impl (transport-link-quic zenohd->wz): the
    # cert-transport sibling of the tls acceptor leg above. A real zenohd DIALS the wz
    # `--listen quic/...` acceptor (BoundListener::Quic / bind_quic + accept_quic_on,
    # the accept SEAM wired in R311y401 on top of the pre-existing quic pipeline
    # primitives proven wz<->wz by quic_e2e), trusting wz's self-signed localhost cert
    # (zenoh's quic link reads the SAME transport.link.tls config block as tls), and a
    # pico z_put routes through zenohd ACROSS the quic link into the wz acceptor's
    # subscriber. The existing wz_to_zenohd_router quic legs prove only the wz quic
    # DIALER (wz->zenohd); this is the reverse (acceptor) direction, closing the
    # accept-direction cross-impl set. zenoh-pico's CLI has no quic, so zenohd is the
    # only foreign quic dialer. QUIC is in STOCK zenohd + the demo carries `quic`
    # (built above) -- NO build-line change (like udp/unixsock, unlike the
    # vsock/unixpipe oracles); it RUNS on hosted CI (UDP loopback needs no kernel
    # module, unlike vsock). Same --test-threads=1 per-zenohd isolation. Count-guarded
    # (`1 passed`, the y400 vsock-leg precedent) so a dropped `#[ignore]` (0 selected
    # -> exit 0) reddens instead of silently passing.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_quic_acceptor_zenohd_interop -- --ignored --quiet --test-threads=1 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    # R311y454 — the `locator-iface` LISTEN-side HONOR, cross-impl (§5.2 x the quic
    # accept seam x zenohd->wz). A real zenohd dials the SAME wz quic acceptor twice,
    # differing only in the device the listen locator names: `#iface=lo` establishes,
    # `#iface=<a non-lo NIC>` does not, because SO_BINDTODEVICE delivers only packets
    # that ARRIVED on the named device and a datagram to 127.0.0.1 arrives on `lo`.
    # A SEPARATE FILE, not a second #[test] in the leg above: that leg's count guard
    # is `1 passed`, so adding a test there would red it. This leg carries its own
    # `1 passed` guard for the same dropped-#[ignore] reason. No pico hop -- the
    # Established/not-Established pair IS the discriminator, and a routed Put would
    # add a second foreign binary without adding discrimination. The demo build above
    # gained `locator-iface`, which is also what puts the atom in the A4 closure.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_quic_acceptor_iface_zenohd_interop -- --ignored --quiet --test-threads=1 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    # R311y407 — wz MESH QUIC acceptor cross-impl (transport-link-quic x mesh accept
    # loop x zenohd->wz): a real zenohd DIALS a wz `--peer quic/...` / `--router-hat
    # quic/...` MESH listen and both FEDERATES over it AND routes real pub/sub DATA
    # across it BOTH ways. The uncovered intersection the y401 one-shot quic acceptor
    # leg above does NOT reach: y401 dials the ONE-SHOT `--listen quic/` (single
    # observe face, no federation); y376 is the ws (not quic) mesh acceptor, hold-only;
    # the y404 mesh_accept_loop_holds_two_quic_peers unit is wz<->wz only; the y406
    # run_peer/run_router_hat quic-cert units are bind-only (no peer connects); and
    # the wz_peer/router_hat_zenohd_interop legs federate over TCP with wz as the
    # DIALER. This is the first proof a FOREIGN impl JOINS wz's MESH (peer_loop /
    # router-hat) over an encrypted QUIC listen wz ACCEPTS, exercising the y404
    # deferred-handshake quic accept split inside the mesh loop + the y406 cert
    # threading. FIVE legs: (1) --router-hat routers_net converges + wz decodes the
    # LinkStateList OAM; (2) --peer forms a MUTUAL linkstate edge; (3) a gossip-dialer
    # NEUTER proves leg-2's reciprocal witness is load-bearing (no edge); (4) a pico
    # z_pub behind zenohd's Put crosses the quic mesh INTO wz's subscriber; (5) wz's
    # Put crosses the quic mesh OUT to a pico z_sub behind zenohd; (6) a REGRESSION
    # leg pinning a peer whose zid ends in a ZERO BYTE (R311y413 — the reliable-quic
    # twin of the datagram lane's leg, since the Zid canonicalisation it guards is a
    # ROUTING fix that every mesh lane depends on). All over a quic-ONLY
    # listen (no tcp fallback path). STOCK zenohd (quic is a zenoh default) + the pico
    # z_pub/z_sub CLIs (checked at the top of this lane); the demo carries `quic` +
    # `router-hat-router` (pulls routing-peer for --peer), built above -- NO build-line
    # change. Count-guarded (`5 passed`, the y401 precedent) so a dropped `#[ignore]`
    # on any leg (fewer selected -> exit 0) reddens instead of silently passing. Same
    # --test-threads=1 per-zenohd isolation.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_mesh_quic_acceptor_zenohd_interop -- --ignored --quiet --test-threads=1 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 6 passed') || return 1
    # R311y408 — wz QUIC-DATAGRAM ACCEPTOR cross-impl (transport-link-quic-datagram
    # zenohd->wz): the RFC9221 unreliable-datagram twin of the y401 one-shot quic
    # acceptor leg above. A real zenohd DIALS the wz `--listen quic-datagram/...`
    # acceptor (BoundListener::QuicDatagram / bind_quic_datagram + the deferred
    # accept_quic_incoming / complete_quic_datagram_accept split wired in R311y408 on
    # top of the quic_datagram_pipeline primitives proven wz<->wz by quic_datagram_e2e),
    # trusting wz's self-signed localhost cert (datagrams reuse the SAME
    # transport.link.tls cert as reliable quic). zenoh gives the datagram link NO
    # distinct scheme -- its prefix is `quic` and the datagram link is selected by the
    # reliability metadata, so zenohd dials `quic/<wz>?rel=0` while wz names its acceptor
    # `quic-datagram/...`; on the wire it is one QUIC handshake then RFC9221 datagram
    # frames (no stream). A pico z_put routes through zenohd ACROSS the datagram link
    # into the wz acceptor's subscriber. quic-datagram is in STOCK zenoh's DEFAULT
    # features (the DEFAULT oracle carries it, verified identical footprint to a
    # `zenoh/transport_quic_datagram` build) + the demo carries `quic-datagram` (built
    # above) -- NO special oracle, like udp/quic and unlike vsock/unixpipe; it RUNS on
    # hosted CI (UDP loopback needs no kernel module). Same --test-threads=1 per-zenohd
    # isolation. Count-guarded (`1 passed`, the y401 precedent) so a dropped `#[ignore]`
    # (0 selected -> exit 0) reddens instead of silently passing.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_quic_datagram_acceptor_zenohd_interop -- --ignored --quiet --test-threads=1 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    # R311y411 — wz MESH QUIC-DATAGRAM ACCEPTOR cross-impl: the y407 mesh-quic leg's
    # UNRELIABLE twin. A real zenohd JOINS wz's MESH (`--peer` / `--router-hat
    # quic-datagram/...`, the accept LOOP -- not the y408 one-shot `--listen` above)
    # over RFC9221 datagram frames, and real pub/sub data crosses that mesh link BOTH
    # ways. zenoh gives the datagram link no distinct scheme, so zenohd dials
    # `quic/<wz>?rel=0` while wz names its listen `quic-datagram/...`. SIX legs:
    # (1) --router-hat routers_net converges + wz decodes the LinkStateList OAM;
    # (2) --peer forms a MUTUAL linkstate edge; (3) a gossip-dialer ROUTING neuter
    # proves leg-2's reciprocal witness is load-bearing (0 edges); (4) a pico z_pub
    # behind zenohd's Put crosses the datagram mesh INTO wz; (5) wz's Put crosses OUT
    # to a pico z_sub; (6) a TRANSPORT neuter -- the SAME endpoint/cert dialed WITHOUT
    # `?rel=0` (reliable quic) never brings a face up (`served 0 peer(s)`), which is
    # what pins legs 1-5 to the DATAGRAM data plane (the mesh listen line carries no
    # transport tag); (7) a REGRESSION leg pinning a peer whose zid ends in a ZERO
    # BYTE -- the deterministic form of a Zid-canonicalisation bug this lane exposed
    # (a self zid arriving back wire-trimmed became a phantom node and silently broke
    # spanning-tree forwarding; 6 failures in 250 runs, every one a zero-low-byte
    # port). STOCK zenohd (transport_quic_datagram is a zenoh default) + the pico
    # z_pub/z_sub CLIs; the demo carries `quic-datagram` + `router-hat-router`
    # (pulls routing-peer for --peer), built above -- NO build-line change.
    # Count-guarded and ANCHORED (`^test result: ok. 7 passed`) so a dropped
    # `#[ignore]` (fewer selected) AND a FAILED result line both redden -- the
    # unanchored sibling form matches `FAILED. N passed; 1 failed`. Same
    # --test-threads=1 per-zenohd isolation.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_mesh_quic_datagram_acceptor_zenohd_interop -- --ignored --quiet --test-threads=1 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 7 passed') || return 1
    # R311y376 — wz ROUTER ws ACCEPTOR cross-impl (accept-symmetry Stage 3): the
    # MULTI-PEER accept loop (`--router` / peer_loop, not just one-shot `--listen`)
    # now accepts a foreign non-tcp face. A real zenohd DIALS the wz `--router
    # --listen ws/...` over ws; the loop accepts the ws connection, completes the
    # RFC6455 upgrade + zenoh handshake, and HOLDS it (face 0 UP). The R311y374 ws
    # acceptor leg proves only the ONE-SHOT `--listen` acceptor; this proves the
    # loop (was TCP-only via bind_endpoint->into_tcp). zenoh-pico has no ws client,
    # so zenohd is the only foreign ws dialer. Same --test-threads=1 isolation; the
    # demo is built with `ws,routing-router` above.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_router_ws_acceptor_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y140 — wz-ROUTER-HAT <-> zenohd ROUTER-TIER federation interop, the
    # FIRST cross-impl test on wz's `routers_net` link-state wire (every other
    # zenohd leg pairs wz as a CLIENT, never on the router tier). Leg 1 converges
    # the router tier with the reference router (routers-net -> 2, proving the
    # cross-impl LinkStateList OAM exchange); leg 2 routes a pico Put across the
    # MIXED-VENDOR router backbone (pico -> zenohd -> linkstate -> wz-router ->
    # pico); leg 3 the reverse Put; leg 4 (R311y147) the QUERY plane (pico
    # z_querier behind wz -> zenohd -> pico z_queryable, reply in reverse); leg 5
    # the FUTURE-mode pub-before-sub proactive-push closure; leg 6 (R311y149) the
    # FORWARD query (pico z_querier behind zenohd -> wz -> pico z_queryable behind
    # wz, wz advertising its client qabl cross-tier); leg 7 (R311y156) the
    # querier-before-queryable FUTURE-mode qabl push (the query twin of leg 5); leg 8
    # the undeclare-RE-ARM of the pico querier's write-filter (z_querier -a matching
    # listener). Needs zenohd + the pico
    # z_pub/z_sub/z_querier/z_queryable CLIs (checked above) + the
    # `router-hat-router` binary (built above). Same --test-threads=1 per-zenohd
    # isolation as the client legs.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_router_hat_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # wz-PEER <-> zenohd-PEER linkstate FEDERATION interop, the peer-tier twin of
    # the router-hat leg above (the last cross-impl router gap): a wz `--peer`
    # LinkstateForwarder meshes with a real zenohd in mode=peer +
    # routing/peer/mode=linkstate and DECODES its linkstatepeers_net LinkStateList
    # flood. Leg 1 (positive) converges a MUTUAL edge (the full-linkstate
    # discriminator: zenohd's self-entry advertises a reciprocal link back to wz);
    # leg 2 (neuter) points wz at a DEFAULT gossip (peer_to_peer) zenohd, which
    # floods the SAME OAM_LINKSTATE self-announcement (so wz still "learned mesh
    # topology") but carries no reciprocal link, so NO edge forms — proving the
    # edge witness is load-bearing, not an ingested-only green-but-meaningless
    # pass. Needs zenohd + the `router-hat-router` binary (built above; pulls
    # routing-peer for --peer). Same --test-threads=1 per-zenohd isolation.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_peer_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y430 — `scouting-autoconnect`, the last unproven scouting atom, on a
    # THREE-node topology the peer-tier leg above cannot host: a zenohd ROUTER, a
    # THIRD-PARTY zenohd PEER listening beside it, and a wz `--peer --autoconnect`
    # whose argv names ONLY the router. wz learns the third party's listen port
    # from the router's LinkStateList and DIALS it, so the face-UP assertion names
    # a port the demo was never given. R311y423 recorded this as blocked on a
    # topology fact; the fact was a NON-UNIFORM subsystem (zenoh's
    # routing.peer.mode "needs to be set to the same value in all peers and routers"
    # — DEFAULT_CONFIG.json5), so the fixture, not wz, was what had to change.
    # SEVEN legs in three pairs plus a control. (1) positive + the option-atom
    # pair with --autoconnect removed (same flood, same mesh — the foreign peer
    # dials wz instead, so `accepted 1` — but wz initiates nothing), plus a
    # no-third-party control separating "the flag dials" from "a DISCOVERED PEER
    # dials". (2) R311y431's --autoconnect-strategy pair: on a fixture where wz's
    # zid is the LOWER, `always` (zenoh's default, and newly reachable) dials what
    # `greater-zid` declines. (3) R311y431's --peer-mode pair against a STOCK
    # subsystem — no routing/peer/mode anywhere, so both zenohd run zenoh's own
    # peer_to_peer default: `peer-to-peer` autoconnects, `linkstate` discovers
    # nothing because the reachability GC eats the links-less announcement. Leg 1
    # and the stock-subsystem leg also assert the ROUTER logged no
    # `unknown link mapping`, the two halves of R311y431's psid-introduction fix.
    # Spawns 2 zenohd per leg, hence the shared --test-threads=1. Same
    # `router-hat-router` binary (pulls routing-peer).
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_gossip_autoconnect_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y353 — liveliness-get's cross-impl witness rides THIS lane and could not
    # ride Layer E, for a reason measured rather than assumed: zenoh-pico NEVER
    # answers an Interest on a unicast transport (interest.c:533-535, "Nothing to
    # do on unicast"), so a wz<->pico snapshot get returns empty no matter the
    # timing. zenohd IS an interest responder, so the topology is pico(token) ->
    # zenohd(responder) <- wz(get), and all three are load-bearing. Needs the pico
    # z_liveliness CLI on top of zenohd; the presence gates at the top of this
    # lane cover z_sub/z_pub/z_querier, so this one is checked here.
    if [[ ! -x target/zenoh-pico-cli/z_liveliness ]]; then
        _z_unavailable "zenoh-pico z_liveliness not built (run: bash scripts/build-zenoh-pico-cli.sh)" || return 1
        return 0
    fi
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_liveliness_get_zenohd_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y354 — liveliness-history, same topology and same reason as the get above:
    # a history replay IS an Interest answer, and pico never answers one on unicast.
    # This file is a PAIR (history on / history off against an identical fixture) and
    # the twin is load-bearing: `LIVELINESS SAMPLE PUT` is what any token logs, so the
    # positive arm alone would not show the replay was caused by `history`. Both arms
    # must run for either to mean anything -- do not filter one out.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_liveliness_history_zenohd_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y355 — session-reconnect, against a foreign router RESTARTED underneath a
    # live wz session: wz subscribes to zenohd#1, zenohd#1 is killed, a fresh
    # zenohd#2 respawns on the same port, and a pico put on a NEW keyexpr reaches wz
    # only if the supervisor re-dialled and REPLAYED the subscription to that fresh
    # router. This is the cross-impl half the wz-only session_reconnect_e2e cannot
    # reach (it re-handshakes against a wz acceptor). A PAIR: the --reconnect arm
    # resumes, the twin (no --reconnect) exits on link loss and never delivers the
    # post-respawn put -- both must run or neither means anything. ~28s, verified
    # stable across repeated local runs (zenohd restart on the same port).
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test wz_reconnect_zenohd_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    # R3b-2 — wz<->zenohd usrpwd AUTH interop. Needs ONLY zenohd (no
    # storage-manager plugin, no pico CLI): wz authenticates to a
    # mandatory-usrpwd zenohd (correct creds -> Established) and is rejected
    # with a wrong password. --test-threads=1 for the same per-zenohd isolation
    # as the router leg.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test usrpwd_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R4c — wz<->zenohd PUBKEY WIRE interop, BOTH directions (needs zenohd +
    # openssl, no plugin). Leg a (R4c): wz DIALS. Stock zenohd cannot admit a
    # pubkey client (known_keys_file is an unimplemented upstream TODO ->
    # Some(empty) lookup rejects all), so that leg proves the achievable interop:
    # zenohd DECODES wz's pubkey InitSyn and rejects only at the lookup. Leg b
    # (R311y576): zenohd DIALS, and this one reaches ESTABLISHED — the same
    # Some(empty) lookup that rejects every initiator EXEMPTS the empty set on the
    # responder-key side (pubkey.rs:414-418), so the success path was always on
    # this side. Leg b is also the foreign anchor for wz's own initiator gate.
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test pubkey_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
    # R311y392 — wz <-> zenohd UNIXPIPE cross-impl, BOTH directions (leg a: wz
    # dials zenohd's UnicastPipeListener; leg b: zenohd's UnicastPipeClient dials
    # wz's multi-client acceptor). Needs a UNIXPIPE-ENABLED zenohd — a SEPARATE
    # source-only oracle (stock zenohd omits transport_unixpipe; crates.io cannot
    # add it), built via `ZENOHD_UNIXPIPE=1 scripts/build-zenohd.sh` to
    # target/zenohd-unixpipe/. Gated on its presence: a job that provisioned it runs
    # the legs; absent + WZ_Z_REQUIRE => FAIL (the proof must run in the required
    # job, ci.yml provisions it), absent otherwise => skip. The demo carries
    # transport-link-unixpipe (built above). Same --test-threads=1 per-zenohd
    # isolation. MUST precede the storage-replication leg below (whose plugin-absent
    # skip returns from the lane early).
    local zenohd_uxp="${WZ_ZENOHD_UNIXPIPE_BIN:-$PWD/target/zenohd-unixpipe/zenohd}"
    if [[ -x "$zenohd_uxp" ]]; then
        # Count-guard (`2 passed`) so a future edit that drops `#[ignore]` from the
        # two legs — making `-- --ignored` select 0 tests and exit 0 — reddens the
        # lane instead of silently passing; `tee /dev/stderr` keeps the output
        # visible on failure. Extends the C1al/C1bl/C1bm count-guard discipline.
        (cd crates && WZ_ZENOHD_UNIXPIPE_BIN="$zenohd_uxp" cargo test -p wz-integration-tests \
            --test wz_unixpipe_zenohd_interop -- --ignored --quiet --test-threads=1 2>&1 \
            | tee /dev/stderr | grep -qE '^test result: ok\. 2 passed') || return 1
        # R311y393/y394 — the wz<->zenohd unixpipe DATA-PLANE cross-impl (4 legs:
        # forward wz-pub->pico-sub over the DIALED link, reverse pico-pub->wz-sub over
        # the dialed link, the ACCEPTOR-direction pico-pub->wz-sub across the link
        # zenohd DIALED into wz's multi-client acceptor, and R311y394's MULTI-CLIENT
        # leg -- TWO concurrent wz clients on ONE zenohd unixpipe listener, a Put
        # routed between them across zenohd's two dedicated sub-pipe pairs). The
        # interop test above proves only the handshake; these prove a Put SAMPLE
        # crosses the unixpipe link both ways, across both the dialed + accepted link,
        # AND between two concurrent clients. Same unixpipe-zenohd oracle + the pico
        # z_sub/z_pub checked at the lane top; same `--test-threads=1` isolation.
        # Count-guarded (`4 passed`) so a dropped `#[ignore]` (0 selected -> exit 0)
        # reddens instead of silently passing.
        (cd crates && WZ_ZENOHD_UNIXPIPE_BIN="$zenohd_uxp" cargo test -p wz-integration-tests \
            --test wz_unixpipe_zenohd_dataplane -- --ignored --quiet --test-threads=1 2>&1 \
            | tee /dev/stderr | grep -qE '^test result: ok\. 4 passed') || return 1
    elif [[ -n "${WZ_Z_REQUIRE:-}" ]]; then
        echo "  Layer Z FAIL — required (WZ_Z_REQUIRE set) but unixpipe zenohd absent" >&2
        echo "  ($zenohd_uxp; run: ZENOHD_UNIXPIPE=1 ZENOHD_ALLOW_CLONE=1 scripts/build-zenohd.sh)" >&2
        return 1
    fi
    # R311y400 — wz VSOCK ACCEPTOR cross-impl (transport-link-vsock zenohd->wz): the
    # AF_VSOCK sibling of the ws/tls/unixsock/udp acceptor legs, closing the LAST
    # accept-direction cross-impl gap. A real zenohd DIALS the wz
    # `--listen vsock/VMADDR_CID_LOCAL:<port>` acceptor (BoundListener::Vsock /
    # bind_vsock — direct wrap, proven wz<->wz by vsock_e2e), and a pico z_put routes
    # through zenohd ACROSS the AF_VSOCK loopback link into the wz acceptor's
    # subscriber. wz binds ONLY vsock (no TCP listener), so vsock is the sole
    # wz<->zenohd transport. zenoh-pico has no vsock client, so zenohd is the only
    # foreign vsock dialer; the demo carries `vsock` (built above).
    #
    # HOST-ONLY, unlike every other Layer Z leg: AF_VSOCK loopback needs the
    # `vsock_loopback` kernel module AND a VSOCK-enabled zenohd (target/zenohd-vsock/ —
    # a SEPARATE source build; zenoh's default omits transport_vsock). The hosted CI
    # runner has neither and ci.yml does NOT provision them, so this leg SKIPs when the
    # vsock oracle is absent — even under WZ_Z_REQUIRE (this is the same kernel-gated
    # host-only treatment as vsock_e2e / the C1ab lane; the demo still COMPILES with
    # vsock on every CI run above). A vsock-capable host builds the oracle with
    # `ZENOHD_VSOCK=1 ZENOHD_ALLOW_CLONE=1 scripts/build-zenohd.sh` to run it.
    # Count-guarded (`1 passed`) so a dropped `#[ignore]` (0 selected -> exit 0)
    # reddens instead of silently passing. Same --test-threads=1 per-zenohd isolation.
    # MUST precede the storage-replication leg below (whose plugin-absent skip returns
    # from the lane early).
    local zenohd_vsock="${WZ_ZENOHD_VSOCK_BIN:-$PWD/target/zenohd-vsock/zenohd}"
    if [[ -x "$zenohd_vsock" ]]; then
        (cd crates && WZ_ZENOHD_VSOCK_BIN="$zenohd_vsock" cargo test -p wz-integration-tests \
            --test wz_vsock_acceptor_zenohd_interop -- --ignored --quiet --test-threads=1 2>&1 \
            | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    else
        # R311y422 — NO LONGER WZ_Z_REQUIRE-EXEMPT. The exemption existed because the
        # hosted runner was believed to have neither the vsock_loopback module nor a
        # vsock zenohd, so requiring the leg would have failed for the environment
        # rather than for the code. Run 30251723895 MEASURED the first half false:
        # `modprobe vsock_loopback` succeeds on the runner (6.8.0-1062-azure) and a
        # bind on VMADDR_CID_LOCAL returns a port. ci.yml now loads the module and
        # builds the oracle, so on the hosted job an absent oracle is a provisioning
        # regression — the same rule every other leg here follows, and the reason
        # transport-link-vsock could sit in `proven` with no hosted witness at all.
        _z_unavailable "vsock zenohd absent ($zenohd_vsock; build it with \
ZENOHD_VSOCK=1 ZENOHD_ALLOW_CLONE=1 scripts/build-zenohd.sh)" || return 1
    fi
    # R311y501 (§5.26) — wz's REST bridge vs the REAL zenoh-plugin-rest. Needs
    # the REST plugin cdylib, which only a SOURCE build produces (as for the
    # storage-manager plugin below). MUST precede that leg: its plugin-absent
    # branch `return 0`s out of the whole lane, so anything after it is dead on
    # a crates.io-only zenohd.
    #
    # Count-guarded (`2 passed`) rather than bare exit-0: both legs are
    # `#[ignore]`d, so a dropped attribute would select 0 tests and STILL exit
    # 0 — the lane would report green having proven nothing
    # ([[feedback-a-skip-is-green]]). --test-threads=1 for per-zenohd isolation,
    # as every other leg in this lane.
    local rest_plugin="${WZ_REST_PLUGIN_SO:-$PWD/target/zenohd/libzenoh_plugin_rest.so}"
    if [[ -f "$rest_plugin" ]]; then
        (cd crates && WZ_ZENOHD_BIN="$zenohd" WZ_REST_PLUGIN_SO="$rest_plugin" \
            cargo test -p wz-integration-tests \
            --test wz_rest_zenohd_interop -- --ignored --quiet --test-threads=1 2>&1 \
            | tee /dev/stderr | grep -qE '^test result: ok\. 2 passed') || return 1
    else
        _z_unavailable "REST plugin not built ($rest_plugin; build it with \
scripts/build-zenohd.sh from a source checkout)" || return 1
    fi
    # R311wo (A10) — wz<->zenohd storage-manager REPLICATION interop. Needs the
    # storage-manager plugin cdylib (built + installed by build-zenohd.sh from a
    # checkout); SKIP if absent (a crates.io-only zenohd has no plugin .so).
    local plugin="${WZ_STORAGE_MANAGER_SO:-$PWD/target/zenohd/libzenoh_plugin_storage_manager.so}"
    if [[ ! -f "$plugin" ]]; then
        _z_unavailable "storage-manager plugin not built ($plugin)" || return 1
        return 0
    fi
    (cd crates && WZ_ZENOHD_BIN="$zenohd" WZ_STORAGE_MANAGER_SO="$plugin" \
        cargo test -p wz-integration-tests \
        --test wz_zenohd_storage_replication -- --ignored --quiet --test-threads=1) || return 1
}

# ─── Layer E3 — multi-peer ROUTER e2e (R311qa) ─────────────────────
# wz-ap-demo `--router` binds ONCE and HOLDS N concurrent peer faces (the
# `routing-router` catalog atom's foundation), vs the one-shot `--listen`
# acceptor that serves a single peer. Built with `--features routing-router`
# (additive — the `--router` arg is opt-in behind it; the TCP `--listen` /
# `--connect` paths are unchanged, so the binary is a superset). The lane is
# self-contained wz<->wz (one router + two initiators, no external zenohd /
# pico CLI), so unlike Layer E / Z there is no prereq to SKIP on — it always
# builds + gates. `wz_router_multi_peer` asserts the router holds both peers at
# once (summary `peak 2 concurrent`), the property a one-shot acceptor cannot
# produce.
layer_e3_router_multi_peer() {
    (cd crates && cargo build -p wz-ap-demo --features routing-router --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_multi_peer -- --ignored --quiet) || return 1
}

# ─── Layer E4 — routing-router catalog-truthfulness reject gate (R311qa) ─
#
# The NEGATIVE counterpart to Layer E3/E6: a DEFAULT `wz-ap-demo` (no
# `routing-router`, no `routing-peer`) must reject `--router` AND `--peer` with
# exit 2, proving the feature claims and the binary stay in lockstep. Self-
# contained — it builds the DEFAULT binary once, then runs both reject tests
# against it (no `--features`), so it never shares a binary build with the
# feature-gated positive lanes; the feature binaries are supersets, so neither
# clobbers the others.
layer_e4_router_reject() {
    (cd crates && cargo build -p wz-ap-demo --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_reject_without_feature -- --ignored --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_reject_without_feature -- --ignored --quiet) || return 1
}

# ─── Layer E4i — the INERT-reporting gate for the advanced / group flags ──
#
# R311y448. The sibling of E4 and its opposite contract. E4 asserts that a
# DEFAULT build REJECTS `--router` / `--peer` with exit 2; this lane asserts that
# the same build accepts `--advanced-subscribe` / `--advanced-publish` /
# `--group-join`, drops the capability, and SAYS SO naming the missing feature.
# The demo keeps that CLI feature-uniform on purpose, so the INERT report is the
# whole of what a caller gets.
#
# Nothing exercised those `#[cfg(not(feature = ...))]` arms until now. 14 of the
# 15 advanced/group legs build the feature ON and assert the NEGATIVE
# `!contains("is INERT")` (the 15th, zenoh_ext_cache_refuses_a_get_without_anyke,
# spawns no wz binary at all), and the Layer E catch-all skips that whole family
# by fn-name substring -- so the arms compiled everywhere and ran nowhere, while
# FOUR fixtures' failure messages depended on their exact wording.
# R311y447-review named the gap after R311y447 widened it by a field
# (`recovery_periodic_ms`, which reached no gate at all).
#
# R311y449 corrected three claims R311y448 made in this block: "every leg" (14 of
# 15), "three fixtures" (four -- the group one is in this round's own scope), and
# the `--skip inert` NECESSITY rationale (corrected in the skip block inside
# `layer_e_ap_demo_round_trip`; see also the note below on what the count pin
# does and does not enforce).
#
# Needs the DEFAULT binary, hence its own lane immediately after E4's rebuild --
# on an `advanced` build all three tests fail (measured). Self-contained wz<->wz
# (a second wz-ap-demo --listen is the peer), so there is no external prereq to
# SKIP on and this is a hard gate.
#
# WHAT THE `3` PIN DOES NOT ENFORCE (R311y449). Adding a 4th leg without updating
# the pin reds this lane. RENAMING one of the three test fns to drop its `inert`
# token does NOT: E4i still sees `3 passed` and stays green, while Layer E's
# `--skip inert` silently stops covering it. The token is a NAMING OBLIGATION
# that no gate enforces -- the same structural hole the `zenoh_ext` family
# carries, and an instance of this project's "pin SETS, not counts". Layer E
# itself has no count guard at all, so an over-matching `--skip` there would
# delete coverage with nothing going red.
layer_e4i_demo_inert_flags() {
    (cd crates && cargo build -p wz-ap-demo --quiet) || return 1
    _runci_guarded_test E4i 3 cargo test -p wz-integration-tests \
        --test wz_ap_demo_inert_flags -- --ignored --quiet --test-threads=1 \
        || return 1
}

# ─── Layer E5 — router data-plane FORWARDING e2e (R311qc) ───────────
#
# The data-plane counterpart to Layer E3's accept-and-hold: a `wz-ap-demo
# --router` built with `--features routing-routes` forwards a Put received on
# one peer face to another peer face that declared a matching subscriber.
# Topology is one router + a `--key` consumer + a `--publish` producer, all
# distinct processes — neither peer can hear the other directly, so the
# consumer firing its subscriber callback is a definitive witness that the
# ROUTER forwarded the Put across faces (a property `routing-router` alone, which
# holds faces but routes nothing, cannot produce). Self-contained wz<->wz (no
# external zenohd / pico CLI), so like E3/E4 there is no prereq to SKIP on. The
# `routing-routes` binary is a superset of the `routing-router` one, so building
# it here does not invalidate E3's assertions.
layer_e5_router_forward() {
    (cd crates && cargo build -p wz-ap-demo --features routing-routes --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_forward -- --ignored --quiet) || return 1
    # R311y373 — the CROSS-IMPL half of routing-routes forwarding: real pico
    # z_pub / z_put -> wz --router (RoutingForwarder) -> real pico z_sub, the
    # §5.15 forwarding atom's foreign<->foreign witness (incl the pico publisher's
    # write-filter Interest release, which the wz RouteTable now answers). Needs
    # the FOREIGN pico CLI, so SKIP green when it is absent (WZ_PICO_REQUIRE
    # escalates to FAIL, per the E/E2/E6/E8 rule); the self-contained wz<->wz
    # wz_router_forward leg above stays a hard gate. Rides the SAME routing-routes
    # demo binary (built above), so no extra build. --test-threads=1 keeps the
    # per-router pico spawns from contending.
    if [[ ! -x target/zenoh-pico-cli/z_pub || ! -x target/zenoh-pico-cli/z_put \
          || ! -x target/zenoh-pico-cli/z_sub ]]; then
        _pico_cli_unavailable "Layer E5 (routing-routes pico interop)" || return 1
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_routes_pico_interop -- --ignored --test-threads=1 --quiet) || return 1
}

# ─── Layer E5u — router data-plane FORWARDING e2e OVER UNIXPIPE (R311y395) ──
#
# The ACCEPTOR-concurrency counterpart of R311y394 (the Layer Z dialer-concurrency
# leg where two wz clients dialed ONE zenohd unixpipe listener): here WZ is the
# multi-client routing LISTENER over IPC. A `wz-ap-demo --router unixpipe/<base>`
# built with `--features routing-routes,transport-link-unixpipe` holds TWO
# concurrent `--connect unixpipe/<base>` clients and forwards a Put across their
# faces to a matching subscriber — the exact transport-mirror of Layer E5's TCP
# `wz_router_forward`. Self-contained wz<->wz (NO external zenohd / pico oracle),
# so it lives in the primary `ci` job beside E5, NOT the zenohd Layer Z. The
# `routing-routes,transport-link-unixpipe` build is NOT produced by any other lane
# (E5 lacks unixpipe; Layer Z's demo build lacks routing-routes), so this lane
# builds its own binary. The test fn is `#![cfg(target_os = "linux")]` (unixpipe is
# Linux-only) and starts `wz_router_`, so the default Layer E sweep's `--skip
# wz_router` already excludes it from the oracle-less arbitrary-feature run. The
# `grep -qE '^test result: ok. 1 passed'` count-guard reddens on a dropped #[ignore] (0 selected ->
# exit 0) the same way the Layer Z dataplane guard does.
layer_e5u_router_unixpipe_forward() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "Layer E5u SKIP (unixpipe is Linux-only; host is $(uname -s))"
        return 0
    fi
    (cd crates && cargo build -p wz-ap-demo \
        --features routing-routes,transport-link-unixpipe --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_unixpipe_forward -- --ignored --test-threads=1 --quiet 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
}

# ─── Layer E6 — peer-MESH e2e (R311qg) ─────────────────────────────
#
# The dial+accept counterpart to Layer E3's accept-only hold: a `wz-ap-demo
# --peer` built with `--features routing-peer` DIALS a configured peer AND
# accepts inbound, holding both directions' faces at once. Topology is peer-B
# (a pure acceptor, `--peer` with no `--connect`) + peer-A (`--peer --connect B`,
# the witness) + a `--connect` client, all distinct processes. Peer-A's summary
# reporting `dialed 1, accepted 1` and `peak 2 concurrent` is the definitive
# "held a dialed AND an accepted face at once" witness — the mesh property a
# one-sided acceptor (`--router`) could never produce. Self-contained wz<->wz (no
# external zenohd / pico CLI), so like E3/E5 there is no prereq to SKIP on. The
# `routing-peer` binary is a superset of the default one (its `--connect`
# single-session path is unchanged), so building it does not invalidate other
# Layer E assertions.
layer_e6_peer_mesh() {
    # R311y51 — the E6 binary is built with `adminspace-write` so the §5.23
    # config-write GATE (permissions.write) is compiled in: the config-write e2es
    # grant it with `--config-write-permit`, and the deny e2e omits it to witness
    # the gate rejecting a write. The gate-OFF arm stays covered by C1y clippy
    # (`--features routing-peer`, no adminspace-write).
    # R311y508 — `routing-interceptor-hotreload` joins the SAME binary so the
    # config-write legs below exercise the VERSION-KEYED per-(face, keyexpr)
    # interceptor cache rather than the uncached path. It is additive: the cache
    # only serves verdicts the direct path would have produced, so no other E6 leg
    # changes behaviour. Naming it here is also what puts the atom in wz-ap-demo's
    # feature closure, which A4-5 containment requires before any test may claim
    # it — an unnamed feature is compiled OUT and the claim would be vacuous.
    # R311y512 — `routing-interest-pending-gc` joins the SAME binary so the peer's
    # p2p_peer-shaped INTEREST BROKER (and the GC on its pending table) is compiled
    # in, which A4-5 containment requires before the new leg below may claim the
    # atom — an unnamed feature is compiled OUT and the claim would be vacuous.
    # Additive to every OTHER E6 leg by construction: the broker fires only on a
    # CLIENT face's CURRENT interest that carries the TOKEN bit AND finds an
    # upstream face (`is_client && body.to() && propagate.. > 0`), so the sub /
    # queryable / adminspace legs never reach it. The one family that DOES reach it
    # is the liveliness-token pair, and both its client-leaf and mesh arms were
    # re-run under this feature set before it was added here.
    (cd crates && cargo build -p wz-ap-demo \
        --features routing-peer,adminspace-write,routing-interceptor-hotreload,routing-interest-pending-gc --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_mesh -- --ignored --quiet) || return 1
    # R311rs — the subscription-filtered data-forward e2e (c3c-3) rides the
    # SAME routing-peer demo binary; gate it in E6 alongside the topology
    # exchange e2e. (It was added in R311ri but never wired into a CI lane —
    # Layer E `--skip wz_peer` excludes it and E6 ran only wz_peer_mesh.)
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_data_forward -- --ignored --quiet) || return 1
    # R311y45 (§5.23 Phase 2b) — the routing-peer adminspace config GET e2e:
    # peer A (--config-queryable) hosts its adminspace on the forwarder; client B
    # z_gets @/<A_zid>/peer/config and receives A's LIVE shared WzConfig JSON over
    # the wire. Rides the SAME routing-peer demo binary (which now pulls
    # adminspace-core), so no extra build.
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_adminspace_config -- --ignored --quiet) || return 1
    # R311y48 (§5.23 Phase 3b) — the adminspace config-WRITE e2e: peer B PUTs A's
    # @/<A_zid>/peer/config/acl-deny carrying a keyexpr; A's --config-writable
    # subscriber reconfigures A's LIVE forwarder to deny it, and the data plane
    # FLIPS admit -> drop over the wire (closing the y45 read-at-open caveat). Rides
    # the SAME routing-peer demo binary (which now pulls config-mutate-runtime so
    # the reconfigure actually drives), so no extra build.
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_adminspace_config_write -- --ignored --quiet) || return 1
    # R311y272 — the CROSS-IMPL half of the config write, on the SAME binary, and the
    # first §5.23 leg where pico is the ENCODER (y270/y271 had pico decoding wz's admin
    # replies). A pico z_put reconfigures A's live forwarder when the write permission is
    # GRANTED, and is REJECTED by the permissions.write gate when it is not — both arms
    # deterministic POSITIVE edges, never a wait-for-absence. The gate IS the atom: with
    # adminspace-write compiled out, the apply arm still passes (the write plumbing is
    # unguarded) while the deny arm fails, which is why the claim rests on the deny arm.
    # Guarded on the FOREIGN binary only (R311y265); WZ_PICO_REQUIRE escalates the skip.
    # R311y503 — `z_pub` joins the guard because the config-mutate-runtime leg
    # added to this file drives a LIVE foreign publisher (the verdict has to flip
    # under traffic, not between two one-shots). `zenoh_pico_cli_binary` PANICS on
    # a missing binary while this guard SKIPs, so a partial pico build would red
    # the lane as a test failure instead of skipping it — the same shape the
    # R311y443 review hit on Layer Z.
    if [[ -x target/zenoh-pico-cli/z_put && -x target/zenoh-pico-cli/z_pub ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_adminspace_write_from_pico_zput -- --ignored --quiet) || return 1
    else
        _pico_cli_unavailable "Layer E6 (pico adminspace config-write z_put/z_pub)" || return 1
    fi
    # R311y368 — pico ACCESS-CONTROL cross-impl (§5.16): a pico z_put to a wz
    # peer's DENIED keyexpr (secret/**, via --acl-deny) is dropped by the ACL
    # interceptor while a z_put to an allowed keyexpr is admitted (the positive
    # control in the SAME leg — proves the ACL, not a dead session). pico is the
    # ENCODER; the wz peer adjudicates by subject + keyexpr. Guarded on the
    # FOREIGN z_put binary (like the adminspace leg above); rides the same E6
    # binary (routing-peer pulls access-acl). The atom binds to the AclInterceptor
    # decision (RED: always-admit -> secret leaks as a 2nd admitted push).
    if [[ -x target/zenoh-pico-cli/z_put ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_acl_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    else
        _pico_cli_unavailable "E6 leg wz_peer_acl_pico_interop" || return 1
    fi
    # R311y459 — pico ACCESS-CONTROL cross-impl, LIVELINESS plane (§5.16): the
    # foreign witness for the three kinds R311y458 added arms for. z_liveliness
    # emits a DeclareToken AND, one second later, its UndeclareToken carrying the
    # keyexpr in the OPTIONAL ext_wire_expr (vendor/zenoh-pico src/net/
    # liveliness.c:32-50), so a denied token costs TWO drops and the second one
    # is what exercises the undeclare arm; z_get_liveliness emits EXACTLY ONE
    # message, a token-carrying CURRENT Interest (:314-362), so its drop is
    # attributable to the LivelinessQuery arm alone. Every ALLOWED message runs
    # FIRST and must leave the counter at zero, which is a stronger positive
    # control than a per-message one: it rules out the ACL dropping the whole
    # liveliness plane. Needs BOTH foreign binaries, so both are guarded. Rides
    # the same E6 binary (routing-peer pulls access-acl). RED: before y458 none
    # of these kinds was governed and every drop barrier times out.
    if [[ -x target/zenoh-pico-cli/z_liveliness && -x target/zenoh-pico-cli/z_get_liveliness ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_acl_liveliness_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    else
        _pico_cli_unavailable "E6 leg wz_peer_acl_liveliness_pico_interop" || return 1
    fi
    # R311y509 — the PEER's liveliness-TOKEN plane, foreign-witnessed on both ends.
    # Four legs: the client-leaf tier and the mesh tier, each with its `-h`-off twin
    # that isolates the CURRENT bit. Rides the SAME E6 binary; the plane is UNGATED
    # under routing-peer, so unlike the router-hat liveliness file this needs no
    # routing-token-tables and cannot pass vacuously on a build that omits it.
    # --test-threads=1 because the mesh legs bind two demo listeners plus two pico
    # processes each, and the twins hold an 8s absence window.
    if [[ -x target/zenoh-pico-cli/z_liveliness && -x target/zenoh-pico-cli/z_sub_liveliness ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_liveliness_token_pico_interop -- --ignored --quiet --test-threads=1) \
            || return 1
    else
        _pico_cli_unavailable "E6 leg wz_peer_liveliness_token_pico_interop" || return 1
    fi
    # R311y512 — §5.21 routing-interest-pending-gc, on the SAME E6 binary. A real
    # pico `z_get_liveliness` against a wz peer whose upstream is SIGSTOPped: pico
    # carries NO timeout for a CURRENT interest (`net/liveliness.c:348`), so its
    # return IS the GC's DeclareFinal arriving. Three arms — frozen upstream (the
    # atom), live upstream (0 reaped, so the atom arm is not "the broker always
    # reaps"), and no upstream (inline, so the delay is the pending table). One
    # arm holds a 2.5s GC window inside an 8s budget, so --test-threads=1 keeps
    # the three fixtures' ports and frozen processes from overlapping.
    if [[ -x target/zenoh-pico-cli/z_get_liveliness ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_interest_pending_gc_pico_interop -- --ignored --quiet --test-threads=1) \
            || return 1
    else
        _pico_cli_unavailable "E6 leg wz_peer_interest_pending_gc_pico_interop" || return 1
    fi
    # R311y451 — pico LOW-PASS cross-impl (§5.16 access-quota), the size-budget
    # sibling of the ACL leg above and on the SAME E6 binary (routing-peer pulls
    # access-quota). A pico z_pub_attachment Put whose PAYLOAD ALONE exactly fills
    # the peer's --max-payload budget is dropped anyway, because zenoh budgets
    # payload + attachment (low_pass.rs:358-361); a plain under-budget z_put in the
    # same leg is admitted (the positive control — proves the budget, not a dead
    # session). The calibration is what makes it discriminate: an over-sized
    # payload would have been dropped by the pre-y451 code too. Needs BOTH foreign
    # binaries, so both are guarded (RED: payload-only accounting admits the
    # attachment put as a 2nd data push and the drop barrier times out).
    if [[ -x target/zenoh-pico-cli/z_put && -x target/zenoh-pico-cli/z_pub_attachment ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_low_pass_attachment_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    else
        _pico_cli_unavailable "E6 leg wz_peer_low_pass_attachment_pico_interop" || return 1
    fi
    # R311y452 — pico DOWNSAMPLING cross-impl (§5.16 access-downsampling), the
    # rate-limit sibling of the two legs above and on the SAME E6 binary
    # (routing-peer pulls access-downsampling). A pico z_pub BURST of 3 Puts at its
    # own 1 Hz cadence on a governed keyexpr is admitted exactly ONCE, because the
    # rule's interval (derived from that cadence, via --downsample-freq in zenoh's
    # Hertz unit) spans the whole burst; an ungoverned z_put in the same leg is
    # admitted (the positive control). The COUNT is the discriminator: 0 admitted
    # is a dead session, 3 is no throttling, 1 is the rule timer. Needs BOTH
    # foreign binaries, so both are guarded (RED, measured: with the interval back
    # at the pre-y452 500ms hardcode — FASTER than pico's cadence — all 4 pushes
    # are admitted, 0 dropped, and the drop barrier times out while the control
    # leg still passes).
    if [[ -x target/zenoh-pico-cli/z_put && -x target/zenoh-pico-cli/z_pub ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_downsampling_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    else
        _pico_cli_unavailable "E6 leg wz_peer_downsampling_pico_interop" || return 1
    fi
    # R311y453 — pico §5.16 SUBJECT-SCOPING cross-impl, the axis that decides
    # whether a rule governs a face at all. Two A/B arms on the SAME pico burst
    # and the SAME E6 binary: a rule narrowed to the link protocol pico actually
    # dials (tcp) throttles it to 1 of 3, the identical rule narrowed to vsock is
    # inert at 3 of 3; likewise a rule narrowed to `lo` throttles the accepted
    # loopback link while one narrowed to an absent NIC is inert. The interface
    # arm is ALSO the live-getifaddrs witness: it only throttles if the peer
    # resolved 127.0.0.1 to `lo` at link open. Guarded on the one foreign binary
    # it drives (RED, measured: with both subject matchers made inert, BOTH
    # negative arms throttle and both tests fail).
    if [[ -x target/zenoh-pico-cli/z_pub ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_subject_scoping_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    else
        _pico_cli_unavailable "E6 leg wz_peer_subject_scoping_pico_interop" || return 1
    fi
    # R311y165 — the STRONG peer-mode future-push CROSS-IMPL e2e (the leg-5 peer analog,
    # now that D4 gave the peer a client data plane): a pico z_pub CLIENT of peer-A
    # (pub-before-sub) + a pico z_sub CLIENT of peer-B; A pushes the future
    # DeclareSubscriber to z_pub (deactivating its write-filter) and re-injects its Put
    # across the wz peer mesh (D4b/C3b) to B, which delivers it to z_sub (D4a/C3a). This
    # is the FIRST E6 leg with a pico-CLI dependency, so — like Layer E/Z — SKIP it when
    # the zenoh-pico CLI is absent (the other E6 legs are wz<->wz and need no guard).
    if [[ -x target/zenoh-pico-cli/z_pub && -x target/zenoh-pico-cli/z_sub ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_future_push_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    else
        _pico_cli_unavailable "E6 leg wz_peer_future_push_pico_interop" || return 1
    fi
    # The client-QUERYABLE hosting CROSS-IMPL e2e (the query-plane twin of the
    # future-push leg above): a pico z_queryable CLIENT of peer-A hosts demo/**; a pico
    # z_querier CLIENT of peer-B queries demo/key; the Query crosses the wz peer mesh to
    # peer-A's co-attached client queryable (the R311y177 hosting plane) and the reply
    # returns in reverse. Same pico-CLI guard as the future-push leg (z_queryable +
    # z_querier are already in build-zenoh-pico-cli.sh TARGETS).
    if [[ -x target/zenoh-pico-cli/z_queryable && -x target/zenoh-pico-cli/z_querier ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_qabl_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    else
        _pico_cli_unavailable "E6 leg wz_peer_qabl_pico_interop" || return 1
    fi
    # The TRANSIT-source client-delivery cross-impl e2e (3-peer line A->B->C, pico z_sub
    # on the terminal C): proves peer-C delivers a multi-hop (non-zero-routing-source)
    # mesh Push to a foreign pico client sub without the pico rejecting the ext_nodeid
    # and closing (the DATA twin of the R311y179 query-source fix).
    if [[ -x target/zenoh-pico-cli/z_sub ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_transit_push_pico_interop -- --ignored --quiet --test-threads=1) || return 1
    else
        _pico_cli_unavailable "E6 leg wz_peer_transit_push_pico_interop" || return 1
    fi
}

# ─── Layer E6b — §5.23 adminspace-introspection-handlers E2E ───────────────────
#
# The per-entity admin introspection (R311y203) driven over the wire: a routing peer
# A (--config-queryable --subscribe demo/data) answers a client B's
# `@/<A_zid>/peer/subscriber/**` GET with the LIVE keyexpr of its declared subscriber
# (the wz analogue of zenoh's `subscribers_data`). Needs its OWN demo binary built
# with `--features routing-peer,adminspace-introspection-handlers` (a superset of the
# E6 `adminspace-write` binary, but a distinct feature), so it rides its own lane
# rather than clobbering E6's binary mid-lane. The e2e asserts the reply key carries
# the ACTUAL declared keyexpr + the live Sources body, so a green reply cannot be a
# static echo — it proves the live `forwarder.subscriptions()` enumeration. wz<->wz
# loopback (the
# introspection adds no wire format, so no cross-impl leg is needed). The
# `wz_peer_` fn prefix keeps the default Layer E sweep's `--skip wz_peer` from
# double-running it on an arbitrary-feature binary.
layer_e6b_adminspace_introspection() {
    (cd crates && cargo build -p wz-ap-demo --features routing-peer,adminspace-introspection-handlers --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_adminspace_introspection -- --ignored --quiet) || return 1
    # R311y270 — the CROSS-IMPL half, on the SAME binary: a real zenoh-pico z_get
    # CLI reads wz's admin bodies (the adminspace-core node record + the
    # introspection subscriber leg). §5.23 was wz<->wz only until now, which is why
    # every adminspace atom sat `unproven` on the cross-impl proof axis: an admin GET
    # adds no new wire FORMAT, but "no new format" is a claim about the envelope, not
    # about the KEYS and BODIES a foreign client must agree with.
    #
    # SKIPs on the FOREIGN binary only (the pico CLI a machine may legitimately lack),
    # never on a wz one — the R311y265 rule. WZ_PICO_REQUIRE escalates that skip to a
    # FAIL wherever the job provisions pico, so a hosted lane cannot go green having
    # run nothing.
    if [[ ! -x target/zenoh-pico-cli/z_get ]]; then
        _pico_cli_unavailable "Layer E6b (pico adminspace z_get)" || return 1
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_adminspace_to_pico_zget -- --ignored --quiet) || return 1
    # R311y350 — locator-tcp's cross-impl witness rides THIS lane, not Layer E: it
    # needs the same routing-peer + adminspace binary built above (Layer E builds the
    # demo with default features, which reject `--peer`). The atom is the canonical
    # `tcp/...` string wz RENDERS into `@/<zid>/peer` from a BARE addr -- a foreign
    # peer reads it, which is what killed R311y348's proposal to exclude the 8
    # locator-* atoms from the A4 denominator as non-observable.
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_locator_render_to_pico_zget -- --ignored --quiet) || return 1
}

# ─── Layer E6c — transport-multilink: demo-binary N-link aggregation E2E ───────
#
# R311y213 (S2 slice-3) — the §5.1 multilink aggregation driven from a REAL binary
# for the first time (the library `session_multilink_deploy_e2e`/`_readd_e2e` drive
# `peer_loop` directly with a test forwarder; Layer C1ba is library-only and never
# builds wz-ap-demo). A `wz-ap-demo --peer --max-links 2` built `--features
# transport-multilink` dials a peer TWICE (`--connect B,B`) and aggregates its two
# outbound links into ONE logical session, while the accept-side peer aggregates the
# two inbound links; both log the demo-owned `link AGGREGATED ... (live links now 2)`
# witness (the R311y213 AcceptEvent::LinkAggregated, rendered by log_face_event), and
# the subscriber receives the published data over the aggregated session. The
# `cargo clippy --features transport-multilink -D warnings` step is the genuinely-new
# demo-cfg-site gate (the atom active <=> its run_peer/main.rs cfg sites compile
# clean). NAMED BOUND: this proves aggregation reachability+observability, NOT per-link
# auto-re-add (wired by the same knob, proven at library level by
# session_multilink_readd_e2e; a 2-process black-box demo cannot sever a single link).
# The `wz_peer_` fn prefix keeps the default Layer E sweep's `--skip wz_peer` from
# double-running it on an arbitrary-feature binary. wz<->wz loopback (no pico/zenohd
# prereq), so no SKIP guard.
#
# R311y414 — the `--ignored` step was BARE, and an `--ignored` run is the most
# silent shape of all: strip the `#[ignore]` (or rename the case) and the run
# selects NOTHING, prints `0 passed` and exits 0. The measured `1 passed` guard
# closes it.
layer_e6c_peer_multilink() {
    (cd crates && cargo build -p wz-ap-demo --features transport-multilink --quiet) || return 1
    (cd crates && cargo clippy -p wz-ap-demo --features transport-multilink --quiet -- -D warnings) || return 1
    _runci_guarded_test E6c 1 cargo test -p wz-integration-tests \
        --test wz_peer_multilink_aggregate -- --ignored --quiet || return 1
}

# ─── Layer E6d — qos demo reachability: prioritized publish over aggregated multilink ─
#
# R311y220 — the demo-binary prioritized-publish proof. A `--peer` node built `--features
# transport-qos,transport-multilink` and driven `--max-links 2 --qos --express-high`
# ORIGINATES its `--publish` data at a non-DEFAULT QoS band (RealTime, the HIGH band)
# through the new `LinkstateForwarder::publish_qos` app path, and the `--subscribe` peer
# RECEIVES it over the aggregated qos session — making the y217 `select_link` band routing
# + y219a per-face band assignment reachable from a real binary (pre-y220 the forwarder
# publish API hard-clamped `Priority::DEFAULT`, so an application could never originate a
# banded Put). The `clippy --features transport-qos,transport-multilink -D warnings` step
# gates the new demo cfg sites (the `--express-high` / `--low` flag + `PublishBand`).
# NAMED BOUND: proves publish_qos send-PATH reachability from the binary (a --express-high
# Put is originated via publish_qos and delivered); it does NOT prove band SELECTION was
# observed (a black-box subscriber cannot see which link carried the Put, and a green result
# does not distinguish qos-on from qos-off), NOR the y219b joined-secondary DELIVERY fix
# (`data_seen` is upstream of the drop gate; guarded deterministically by the
# linkstate_forward library unit test), NOR band-selection correctness (the y219a in-process
# `session_multilink_deploy_e2e`). wz<->wz loopback (no
# pico/zenohd prereq), so no SKIP guard; the `wz_peer_` prefix keeps the default Layer E
# sweep's `--skip wz_peer` from double-running it.
#
# R311y414 — same `--ignored` silence as E6c above; the measured `1 passed`
# guard closes it.
layer_e6d_peer_multilink_qos() {
    (cd crates && cargo build -p wz-ap-demo --features transport-qos,transport-multilink --quiet) || return 1
    (cd crates && cargo clippy -p wz-ap-demo --features transport-qos,transport-multilink --quiet -- -D warnings) || return 1
    _runci_guarded_test E6d 1 cargo test -p wz-integration-tests \
        --test wz_peer_multilink_qos_reach -- --ignored --quiet || return 1
}

# ─── Layer E6e — §5.23 adminspace-plugins-handlers E2E ─────────────────────────
#
# The wz-native plugins admin surface (R311y237) driven over the wire: a routing peer
# A (--config-queryable) answers a client B's `@/<A_zid>/peer/plugins/**` GET with its
# compiled-in plugin registry, the wz superset of zenoh's `plugins_data` handler. Needs
# its OWN demo binary built with
# `--features routing-peer,adminspace-plugins-handlers,storage-backend` — the
# storage-backend opt-in compiles the `storage_manager` subsystem so `compiled_plugins`
# reports it (state=Loaded, the wz mirror of zenoh-plugin-storage-manager). The e2e
# asserts the reply key carries the ACTUAL plugin id AND the body is the zenoh
# PluginStatusRec (id/state/path), so a green reply cannot be a static echo — it proves
# the live `compiled_plugins()` enumeration. wz<->wz loopback (the plugins legs add no
# wire format, so no cross-impl leg is needed). The `wz_peer_` fn prefix keeps the
# default Layer E sweep's `--skip wz_peer` from double-running it.
layer_e6e_adminspace_plugins() {
    (cd crates && cargo build -p wz-ap-demo --features routing-peer,adminspace-plugins-handlers,storage-backend --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_adminspace_plugins -- --ignored --quiet) || return 1
    # R311y271 — the CROSS-IMPL half, on the SAME binary this lane already builds:
    # pico's z_get reads the `plugins/**` leg and decodes wz's compiled-subsystem
    # record. PARTIAL and graded so — the atom's other two surfaces
    # (`status/plugins/**` + the node record's `plugins` field) report STARTED
    # plugins, and nothing starts storage_manager here, so they are faithfully empty.
    #
    # SKIPs on the FOREIGN binary only (the pico CLI a machine may legitimately lack),
    # never on a wz one — the R311y265 rule; WZ_PICO_REQUIRE escalates that skip to a
    # FAIL wherever the job provisions pico.
    if [[ ! -x target/zenoh-pico-cli/z_get ]]; then
        _pico_cli_unavailable "Layer E6e (pico adminspace plugins z_get)" || return 1
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_adminspace_plugins_to_pico_zget -- --ignored --quiet) || return 1
}

# ─── Layer E6f — §5.23 adminspace-metrics E2E (vs zenoh-pico) ──────────────────
#
# The `@/<zid>/<whatami>/metrics` OpenMetrics build-info leg (R311y35) read over the
# wire by a FOREIGN decoder for the first time. Needs its OWN demo binary built with
# `--features routing-peer,adminspace-metrics` — DISTINCT from E6b's binary, whose
# wz_peer_adminspace_to_pico_zget asserts the metrics leg is ABSENT; folding metrics
# into that binary would break y270's counterfactual. A pico z_get on
# `@/<A_zid>/peer/metrics` decodes the `zenoh_build` gauge (metrics_text, byte-faithful
# to zenoh adminspace.rs:714-720). No wz<->wz e2e is added — the leg is unit-proven
# (declare_adminspace_metrics_get_returns_openmetrics_text); this lane supplies the
# cross-impl witness. The `wz_peer_` fn prefix keeps the default Layer E sweep's
# `--skip wz_peer` from double-running it on an arbitrary-feature binary.
#
# SKIPs on the FOREIGN binary only (the pico CLI a machine may legitimately lack),
# never on a wz one — the R311y265 rule; WZ_PICO_REQUIRE escalates that skip to a
# FAIL wherever the job provisions pico.
layer_e6f_adminspace_metrics() {
    (cd crates && cargo build -p wz-ap-demo --features routing-peer,adminspace-metrics --quiet) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_get ]]; then
        _pico_cli_unavailable "Layer E6f (pico adminspace metrics z_get)" || return 1
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_adminspace_metrics_to_pico_zget -- --ignored --quiet) || return 1
}

# ─── Layer E6g — §5.23 adminspace-read GET-gate E2E (vs zenoh-pico) ─────────────
#
# The `permissions.read` GET gate (R311y36) driven from a FOREIGN client for the
# first time. Needs its OWN demo binary built with
# `--features routing-peer,adminspace-read` and run `--no-admin-read`: the admin
# queryable then answers NOTHING and a pico z_get receives only the terminating
# Final. The gate resolves through the library admin_read_permit (a
# cfg(feature="adminspace-read") site, the read-side mirror of adminspace-write).
# Distinct from E6b's binary (whose y270 test needs the record SERVED), so its own
# lane. wz-unit-proven by admin_read_permit_tests + the y270 positive complement
# (record served without the flag); this lane supplies the denied-path foreign
# witness. The `wz_peer_` fn prefix keeps the default Layer E sweep's `--skip
# wz_peer` from double-running it on an arbitrary-feature binary.
#
# SKIPs on the FOREIGN binary only (the pico CLI a machine may legitimately lack),
# never on a wz one — the R311y265 rule; WZ_PICO_REQUIRE escalates that SKIP to a FAIL.
layer_e6g_adminspace_read() {
    (cd crates && cargo build -p wz-ap-demo --features routing-peer,adminspace-read --quiet) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_get ]]; then
        _pico_cli_unavailable "Layer E6g (pico adminspace read-deny z_get)" || return 1
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_adminspace_read_deny_to_pico_zget -- --ignored --quiet) || return 1
}

# ─── Layer E6h — §5.23 adminspace-config-hotreload E2E (vs zenoh-pico) ──────────
#
# The config-diff-driven storage lifecycle (R311y239 mechanism, R311y277 ACTIVATION)
# driven END-TO-END over the wire by a stock zenoh-pico client. Needs its OWN demo
# binary built with `--features adminspace-config-hotreload` — the ONLY build that
# compiles the `--storage-host` run-mode (a bare-Session admin host that multi-accepts
# per-client Sessions and applies storage-add/-del via RuntimeStorageManager). A pico
# z_put `.../config/storage-add demo:demo/**` live-spawns a storage; a pico z_get on
# `.../plugins/**` then decodes storage_manager state Started (Loaded before), and a
# z_put `.../config/storage-del demo` reverses it. The Started state binds to a REAL
# add_storage (storage_started tracks !manager.is_empty(), never a bool flip), so a
# green reply proves the compiled_plugins_dyn + RuntimeStorageManager wiring. clippy is
# run on the feature build because it is the ONLY lane compiling the run-mode. The
# `wz_storage_host_` fn prefix is in the default Layer E sweep's `--skip` list (added
# R311y278 alongside wz_peer / wz_router), so that catch-all does NOT run this test
# against the default binary (where `--storage-host` is rejected exit-2 → the readiness
# barrier would time out); it runs ONLY here on the feature build.
#
# SKIPs on the FOREIGN binaries only (the pico CLIs a machine may legitimately lack),
# never on a wz one — the R311y265 rule; WZ_PICO_REQUIRE escalates that SKIP to a FAIL
# wherever the job provisions pico.
layer_e6h_adminspace_config_hotreload() {
    (cd crates && cargo build -p wz-ap-demo --features adminspace-config-hotreload --quiet) || return 1
    (cd crates && cargo clippy -p wz-ap-demo --features adminspace-config-hotreload -- -D warnings) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_put || ! -x target/zenoh-pico-cli/z_get ]]; then
        _pico_cli_unavailable "Layer E6h (pico config-hotreload z_put/z_get)" || return 1
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_storage_host_config_hotreload_pico -- --ignored --quiet --test-threads=1) || return 1
}

# ─── Layer E7 — router-hat: RouterForwarder driven E2E (P4 §5.21 ACTIVATION) ───
#
# The dual-mesh RouterForwarder (the zenoh hat/router port) composed over real
# transport for the first time — a `--router-hat` node presenting wire
# WhatAmI::Router through accept_loop, with `--peer` nodes dialing it. ONE binary
# built with `--features router-hat-router` (the run-mode ACTIVE atom, R311y132;
# pulls the routing-router-hat foundation -> routing-peer) serves both kinds. The
# six tests are STAGED (topology before forwarding, single router before
# federation, data plane before query plane): a 2-node floor, a 3-node star
# data-forward, a 2-router convergence floor, a 2-router peer-native data
# federation E2E, a single-router query-plane E2E, and a 2-router query-plane
# federation E2E. The test fns carry the `wz_router_hat_` prefix so the default
# Layer E sweep's `--skip wz_router` excludes them from the arbitrary-feature run.
layer_e7_router_hat() {
    # R311y273 — the binary now also carries adminspace-router-linkstate (a superset
    # of the prior router-hat-router; the router admin legs are additive, so the
    # existing wz<->wz router mesh tests are unaffected) so the pico router-adminspace
    # witness rides the same binary.
    # R311y463 — plus routing-token-tables, so this lane OWNS the build the router
    # liveliness-TOKEN plane needs. It is NOT reachable any other way: `routing-peer`
    # does not pull it (crates/wz/Cargo.toml:473 vs :857), so the Layer E6 demo has
    # the whole plane — ingest_client_token / dump_interest_tokens /
    # push_future_token — compiled OUT, and a proof placed there passes vacuously.
    # Additive like the y273 adminspace superset above: it adds the token plane and
    # touches neither the data nor the query forwarding the mesh tests assert.
    (cd crates && cargo build -p wz-ap-demo \
        --features router-hat-router,adminspace-router-linkstate,routing-token-tables --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_mesh -- --ignored --quiet) || return 1
    # R311y463 — liveliness-historical-samples, the RESPONDER half of liveliness
    # history: pico A declares a token, THEN pico B subscribes with `-h`, and wz
    # replays the token B never saw declared. The pair differs in that ONE pico flag,
    # which is exactly the CURRENT bit on the wire (vendor/zenoh-pico
    # src/net/liveliness.c:196-205), so the twin is what makes the sample the atom's.
    # Guarded on BOTH foreign binaries; rides the token-tables build above.
    if [[ -x target/zenoh-pico-cli/z_liveliness && -x target/zenoh-pico-cli/z_sub_liveliness ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_router_hat_liveliness_history_pico_interop \
            -- --ignored --quiet --test-threads=1) || return 1
    else
        _pico_cli_unavailable "Layer E7 (pico liveliness history z_liveliness/z_sub_liveliness)" || return 1
    fi
    # R311y273 — the CROSS-IMPL half: a pico z_get reads the router's link-state DOT +
    # the computed route-successor table across a two-router federation. FULL (all three
    # legs carry content once a second router exists; probed before the round). Guarded
    # on the FOREIGN binary only (R311y265); WZ_PICO_REQUIRE escalates the skip.
    if [[ -x target/zenoh-pico-cli/z_get ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_router_hat_adminspace_to_pico_zget -- --ignored --quiet) || return 1
    else
        _pico_cli_unavailable "Layer E7 (pico router adminspace z_get)" || return 1
    fi
}

# ─── Layer E7b — router-connect-reconcile: runtime connect-list reconcile E2E ───
#
# The §5.21 `router-connect-reconcile` atom (R311y202) driven END TO END over real
# transport: a router-hat learns a NEW connect endpoint at RUNTIME (via the
# `--connect-after` operator affordance) and dials it, federating with a peer it
# never had on its startup `--connect` list — the wz port of zenoh's `update_peers`
# (orchestrator.rs:413). TWO binaries: the positive tests run first against the
# feature-on build, THEN the feature-off binary is rebuilt (over the same
# target/debug/wz-ap-demo path) for the negative test — the ORDERING, not any
# non-clobber property, is what keeps each test on the binary it needs:
#   - POSITIVE (feature ON): `router-hat-router,router-connect-reconcile` — R1 with
#     no `--connect` reconcile-dials R2 at runtime, converging its router tier to 2.
#   - NEGATIVE (feature OFF): the `router-hat-router`-only binary treats
#     `--connect-after` as inert (warns + ignores), the feature-gate lockstep.
# Cross-impl is not needed (the reconcile adds no new wire format — the dial reuses
# the cross-impl-proven session handshake), so a wz<->wz loopback covers the whole
# new control path. The `wz_router_hat_` fn prefix keeps the default Layer E sweep's
# `--skip wz_router` from double-running these on an arbitrary-feature binary.
layer_e7b_router_connect_reconcile() {
    # POSITIVE (feature ON): both the connect-added reconcile (slice 1) and the peer
    # auto-reconnect redial-on-drop (slice 2) against the reconcile binary; skip the
    # feature-off negative (it needs the no-reconcile binary below).
    (cd crates && cargo build -p wz-ap-demo --features router-hat-router,router-connect-reconcile --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_connect_reconcile -- --ignored --skip requires_feature --quiet) || return 1
    # NEGATIVE (feature OFF): --connect-after inert on the router-hat-router-only
    # binary (rebuilt here so it never shares the reconcile build).
    (cd crates && cargo build -p wz-ap-demo --features router-hat-router --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_connect_reconcile wz_router_hat_reconcile_requires_feature -- --ignored --quiet) || return 1
}

# ─── Layer E7c — adminspace-router-linkstate: router admin legs CROSS-NODE E2E ───
#
# The §5.23 `adminspace-router-linkstate` atom (R311y204) driven END TO END: a
# querier behind R1 GETs R2's `@/<R2_zid>/router/**` admin subtree, routed
# issuer -> R1 -> [router mesh] -> R2, self-dispatched at R2, with the replies
# returning back down both hops. This proves the self-sourced-queryable mesh routing
# the §5.21 router lacked: R2 registers its admin queryable at STARTUP (before R1
# connects), so R1 can only route the GET after the re-advertise fold
# (`re_advertise_self_cross_tier` picking up the `local_queryables` fold in
# `derived_cross_tier_qabls_into`) federates it on join. The test asserts the LIVE
# `linkstate/routers` DOT body names BOTH routers' zenoh-hex zids + a
# `route/successor/src/<x>/dst/<y>` entry. wz<->wz only — the legs add no new wire
# format (a standard reply GET, cross-impl-proven by adminspace-core), so no Layer Z
# cross-impl arm is needed (a byte-parity wz<->zenohd DOT test could only assert
# well-formedness — the DOT node labels are petgraph-Debug of wz `Node` vs zenoh
# `Node` — a named verification-leg deferral, not a build). The `wz_router_hat_` fn
# prefix keeps the default Layer E sweep's `--skip wz_router` from double-running it.
layer_e7c_router_adminspace_linkstate() {
    (cd crates && cargo build -p wz-ap-demo --features router-hat-router,adminspace-router-linkstate --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_adminspace_linkstate_interop -- --ignored --quiet) || return 1
}

# ─── Layer E7u — router-hat (TRUE Router) forwarding OVER UNIXPIPE (R311y396) ──
#
# The PRODUCT-CODE counterpart of Layer E5u (which proved the star --router over
# unixpipe test-only): R311y396 makes run_router_hat's addressing seam non-IP safe
# (the log + admin locator render from local_addr_display; the zid uses an explicit
# --zid for any transport, IP keeps the port-derived fallback, a non-IP listen
# REQUIRES --zid), so a wz --router-hat (a true wire WhatAmI::Router) binds a
# unixpipe listener and forwards a Put between two DISTINCT-zid --connect unixpipe
# clients. Two guarded steps: (1) the fast product-code fail-fast UNIT
# (run_router_hat on a unixpipe listen WITHOUT --zid returns an Err naming --zid,
# binding to the R311y396 seam vs the pre-fix "no IP SocketAddr"); (2) the e2e
# forward. Self-contained wz<->wz (NO external oracle), so it lives in the primary
# `ci` job beside E5u (NOT beside E7, which is in the oracle-required interop job),
# NOT the zenohd Layer Z. No pre-existing lane builds
# router-hat-router,transport-link-unixpipe together, so this lane builds its own
# binary. The test fns start `wz_router_hat_` / `run_router_hat_`, so the default
# Layer E sweep's `--skip wz_router` excludes the e2e from the oracle-less run.
# Linux-only (unixpipe); the count-guards redden on a dropped test.
layer_e7u_router_hat_unixpipe_forward() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "Layer E7u SKIP (unixpipe is Linux-only; host is $(uname -s))"
        return 0
    fi
    # (1) the R311y396 product-code fail-fast unit (non-IP router-hat REQUIRES --zid).
    (cd crates && cargo test -p wz-ap-demo \
        --features router-hat-router,transport-link-unixpipe \
        run_router_hat_without_zid_on_a_unixpipe_listen_fails_fast \
        -- --test-threads=1 --quiet 2>&1 | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    # (2) the e2e: build the router-hat+unixpipe binary, then route a Put between two
    #     distinct-zid --connect unixpipe clients through the true-Router.
    (cd crates && cargo build -p wz-ap-demo \
        --features router-hat-router,transport-link-unixpipe --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_unixpipe_forward -- --ignored --test-threads=1 --quiet 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
}

# ─── Layer E6u — peer (WhatAmI::Peer) forwarding OVER UNIXPIPE (R311y397) ──
#
# The peer run-mode counterpart of Layer E5u (star --router, test-only) and E7u
# (--router-hat, a true Router): R311y397 adds a --zid override to run_peer and makes
# its addressing seam non-IP safe (the log + self locator render from
# local_addr_display; the zid uses an explicit --zid for any transport, IP keeps the
# port-derived fallback, a non-IP listen REQUIRES --zid), so a wz --peer binds a
# unixpipe listener and forwards a Put between two DISTINCT-zid --connect unixpipe
# clients (deliver_to_client_subscribers routes among the peer's co-attached client
# faces). Two guarded steps: (1) the fast product-code fail-fast UNIT (run_peer on a
# unixpipe listen WITHOUT --zid returns an Err naming --zid, binding to the R311y397
# seam vs the pre-fix "no IP SocketAddr"); (2) the e2e forward. Self-contained
# wz<->wz (NO external oracle), so it lives in the primary `ci` job beside E5u/E7u,
# NOT the oracle-required interop job. No pre-existing lane builds
# routing-peer,transport-link-unixpipe together, so this lane builds its own binary.
# The test fns start `wz_peer_` / `run_peer_`, so the default Layer E sweep's `--skip
# wz_peer` excludes the e2e from the oracle-less run. Linux-only (unixpipe); the
# count-guards redden on a dropped test.
layer_e6u_peer_unixpipe_forward() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "Layer E6u SKIP (unixpipe is Linux-only; host is $(uname -s))"
        return 0
    fi
    # (1) the R311y397 product-code fail-fast unit (non-IP peer REQUIRES --zid).
    (cd crates && cargo test -p wz-ap-demo \
        --features routing-peer,transport-link-unixpipe \
        run_peer_without_zid_on_a_unixpipe_listen_fails_fast \
        -- --test-threads=1 --quiet 2>&1 | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    # (2) the e2e: build the peer+unixpipe binary, then route a Put between two
    #     distinct-zid --connect unixpipe clients through the peer.
    (cd crates && cargo build -p wz-ap-demo \
        --features routing-peer,transport-link-unixpipe --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_unixpipe_forward -- --ignored --test-threads=1 --quiet 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
}

# ─── Layer E8 — router-hat CROSS-IMPL vs zenoh-pico (P4 §5.21) ───
#
# The dual-mesh RouterForwarder proven against a FOREIGN zenoh client: a wz
# --connect --publish routes wz-client -> [wz router-hat] -> pico z_sub -- the pico
# analog of Layer Z leg 2 (wz -> zenohd -> pico), with wz's OWN router replacing
# zenohd. This is the router daemon's first cross-impl (non-wz) data-plane proof.
# Needs wz-ap-demo built with --features router-hat-router AND the zenoh-pico CLI;
# SKIPs if the pico CLI is absent (like Layer E), FAILs on a real routing break. The
# test fn's `wz_router_hat_` prefix keeps the default Layer E sweep's `--skip
# wz_router` from double-running it on an arbitrary-feature binary.
layer_e8_router_hat_pico() {
    if [[ ! -x target/zenoh-pico-cli/z_sub ]]; then
        _pico_cli_unavailable "Layer E8" || return 1
        return 0
    fi
    (cd crates && cargo build -p wz-ap-demo --features router-hat-router --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_pico_interop -- --ignored --quiet) || return 1
}

# ─── Layer E8t — time-hlc FORWARD-PATH STAMP cross-impl vs zenoh-pico ───
#
# R311y450. The §5.18 forward-path stamp proven against a FOREIGN client: a wz
# --connect --publish emits a Put with NO timestamp, the wz --router-hat relays it
# and its node HLC ADDS one, and a real zenoh-pico z_sub_attachment decodes it
# (`with timestamp: <ntp64>`). zenoh's counterpart is the `treat_timestamp!` macro
# at zenoh/src/net/routing/dispatcher/pubsub.rs:328.
#
# TWO BUILDS, one test each, and the second build is the point. A contract about a
# build VARIANT needs a lane that OWNS that build:
#   leg 1 (router-hat-router,time-hlc) — the positive: pico MUST print the line.
#   leg 2 (router-hat-router, NO time-hlc) — the negative twin: the Put must still
#          ROUTE and pico must print NO timestamp line. Without leg 2, leg 1's
#          `with timestamp:` is not attributable to the HLC — anything in the path
#          could in principle be stamping. MEASURED at authoring time: leg 1's
#          assertion FAILS against leg 2's binary ("relayed the sample WITHOUT
#          adding a node-HLC timestamp"), which is the RED that makes the pair a
#          discriminator rather than two independent greens.
# They cannot share a build, so they cannot share a `cargo test` invocation — that
# is why this is its own lane rather than two more legs bolted onto E8.
#
# The `--features ...,time-hlc` build line here is ALSO what makes the A4 claim
# legal: A4-5 containment derives wz-ap-demo's feature closure by unioning every
# `cargo build -p wz-ap-demo --features` set in THIS file
# (scripts/lib/feature_closure.py::ap_demo_lane_features), so a `time-hlc` claim is
# rejected until a lane really builds the demo with it. Deleting this lane
# therefore reds A4 rather than silently orphaning the proof.
#
# Needs the zenoh-pico CLI; SKIPs if absent (like Layer E8), FAILs on a real break.
# Count-guarded and ANCHORED (`^test result: ok. 1 passed`) so a dropped `#[ignore]`
# (0 selected -> exit 0) and a FAILED result line both redden.
layer_e8t_router_hat_hlc_stamp_pico() {
    if [[ ! -x target/zenoh-pico-cli/z_sub_attachment ]]; then
        _pico_cli_unavailable "Layer E8t" || return 1
        return 0
    fi
    (cd crates && cargo build -p wz-ap-demo --features router-hat-router,time-hlc --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hlc_stamp_to_pico_zsub -- --ignored --quiet --test-threads=1 \
        --exact wz_router_hat_hlc_stamps_a_bare_put_for_pico_zsub_attachment 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    # The negative twin, on its OWN build (no time-hlc).
    (cd crates && cargo build -p wz-ap-demo --features router-hat-router --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hlc_stamp_to_pico_zsub -- --ignored --quiet --test-threads=1 \
        --exact wz_router_hat_without_time_hlc_relays_a_bare_put_unstamped 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
}

# ─── Layer E9 — the preset-ap-full COMPOSITION, driven against pico ──
#
# R311y480. Until this round `preset-ap-full` had NO executable: Layer C4
# ran `cargo build -p wz --no-default-features --features preset-ap-full`,
# a LIBRARY typecheck, and `wz-ap-demo` had no `preset-ap-full` key at all
# (`cargo build -p wz-ap-demo --features preset-ap-full` answered "the
# package 'wz-ap-demo' does not contain this feature"). So the kitchen-sink
# preset had never been RUN and no foreign peer had ever spoken to it.
#
# Every other pico lane in this file drives a NARROW binary — E6 builds
# `--features routing-peer`, E8t `--features router-hat-router,time-hlc`,
# E6e `--features storage-backend`. Composition is the one axis none of
# them reaches, and it is not a formality: preset-ap-full drags in
# `session-extqos`, `session-extshm` (recorded WIRE-INCOMPATIBLE) and
# `transport-shm` alongside the live handshake. They are reserved (declared
# cargo key, no cfg site) so the expectation is that they change no wire
# byte — an expectation no lane could observe before this one.
#
# The two tests are named EXPLICITLY rather than swept, so a rename or a
# silently-dropped test fails the lane instead of shrinking it quietly
# (the `--exact` + `1 passed` pin E8t uses). Leg 2 is also the build
# discriminator: `--peer` is cfg(routing-peer), so a binary built from the
# wrong feature set exits 2 at spawn and this lane reds.
# ─── Layer E10 — who sends a session Close at teardown (R311y487) ───────────
#
# A MEASUREMENT lane, and it is registered precisely because a measurement that
# nobody re-runs decays into a quoted number. It counts DIALER -> ACCEPTOR
# batches opening with T_MID_CLOSE through the harness's own counting relay, for
# three closers against one wz-ap-demo acceptor: the demo itself on SIGTERM (the
# positive control, without which every zero is unreadable), a real zenoh-pico
# z_put, and the exported C ABI's z_close.
#
# What it established: a bare TCP FIN at z_close is INSIDE real pico's envelope.
# pico emitted a Close in 3 of 20 runs and none in the other 17, so it is not a
# usable equality oracle; wz-capi-pico emitted none in 20 of 20. The R311y486
# carry calling that silence a fidelity gap is retracted by this lane.
#
# Only the control and the capi count are asserted (both stable across 20 runs).
# The pico count is printed and deliberately NOT gated -- asserting it is a
# 15%-red lane, which is the trap this comment exists to keep shut.
layer_e10_close_frame_on_teardown() {
    (cd crates && cargo build -p wz-ap-demo --quiet) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_put ]]; then
        _pico_cli_unavailable "Layer E10" || return 1
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test close_frame_on_teardown -- --ignored --nocapture --test-threads=1 \
        --exact who_sends_a_session_close_at_teardown 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
}

layer_e9_apfull_preset_pico() {
    # BUILD FIRST, GUARD SECOND — deliberately in this order. The pico guard below
    # can SKIP-green on a machine without the foreign CLI, and a SKIP is green: if
    # the build sat behind it, the `preset-ap-full` demo key would get NO gate at
    # all on those machines, which is precisely how a feature-list drift (a renamed
    # or removed atom in the preset) would reach main invisibly. wz artifacts are
    # never a reason to skip (the R311y265 rule Layer E states); only the FOREIGN
    # binary is.
    (cd crates && cargo build -p wz-ap-demo --no-default-features \
        --features preset-ap-full --quiet) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_put || ! -x target/zenoh-pico-cli/z_sub \
        || ! -x target/zenoh-pico-cli/z_pub || ! -x target/zenoh-pico-cli/z_get \
        || ! -x target/zenoh-pico-cli/z_queryable \
        || ! -x target/zenoh-pico-cli/z_queryable_attachment ]]; then
        _pico_cli_unavailable "Layer E9" || return 1
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test apfull_preset_pico_interop -- --ignored --quiet --test-threads=1 \
        --exact apfull_preset_acceptor_round_trips_with_a_real_pico_z_put 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test apfull_preset_pico_interop -- --ignored --quiet --test-threads=1 \
        --exact apfull_preset_peer_forwards_between_two_real_pico_clients 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    # R311y481 — the QUERY PLANE legs, on the SAME preset build above. Each is the
    # first live-foreign witness for an atom whose only prior claim was
    # `codec-parity` (query-selector-parameters / query-attachment /
    # query-reply-err), so before this they had never faced a real process at all.
    #
    # Named `--exact` one per invocation, like the two legs above and for the same
    # reason: a rename or a silently-dropped test then fails the lane instead of
    # shrinking it quietly. They must run on the preset-ap-full binary this
    # function built at the top — all three atoms are absent from
    # `preset-ap-client`, so an ap-client binary rejects the two querier flags at
    # spawn and answers NOTHING on the reply-err leg. That is not hypothetical: the
    # reply-err leg was first authored against a default-features binary that a
    # later `cargo build -p wz-ap-demo` had written over the same target path, and
    # the missing Err frame read exactly like a wz defect (see the test file's
    # module doc). The legs each assert a build-discriminating marker for it.
    (cd crates && cargo test -p wz-integration-tests \
        --test apfull_query_plane_pico_interop -- --ignored --quiet --test-threads=1 \
        --exact apfull_query_selector_parameters_decoded_by_a_real_pico_queryable 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test apfull_query_plane_pico_interop -- --ignored --quiet --test-threads=1 \
        --exact apfull_query_attachment_decoded_by_a_real_pico_queryable 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test apfull_query_plane_pico_interop -- --ignored --quiet --test-threads=1 \
        --exact apfull_query_reply_err_decoded_by_a_real_pico_z_get 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
}

# ─── Layer E11 — AP-full ADVANCED-PUBSUB against a real zenoh-pico ─────
#
# R311y488. The `ext-pubsub-*` plane's FIRST zenoh-pico witness, in both
# directions: wz's cache answers a real `z_advanced_sub`'s history GET, and wz's
# AdvancedSubscriber recovers a real `z_advanced_pub`'s cache. Both cross the
# AP-full `--peer` between two of its clients, so the lane also covers the peer
# routing the `@adv` QUERY plane rather than only pushes.
#
# The pico guard names z_advanced_sub / z_advanced_pub SPECIFICALLY, and that is
# the point: those two binaries are NEW to the curated CLI set and a machine with
# a pre-y488 `target/zenoh-pico-cli/` has every OTHER pico binary present. A guard
# that checked only `z_put` would SKIP-green here while reporting a full pico
# provisioning — which is the R311y265 masked-skip burn wearing the opposite mask.
# A pre-y488 build that HAS the binaries but built them without the cmake flags
# cannot slip through either: those are stub `main`s and the test asserts against
# their stub message.
#
# BUILD FIRST, GUARD SECOND, for the same reason Layer E9 states: a SKIP is green,
# so a build sitting behind the guard would leave the preset's advanced membership
# ungated on machines without the foreign CLI.
layer_e11_apfull_advanced_pubsub_pico() {
    (cd crates && cargo build -p wz-ap-demo --no-default-features \
        --features preset-ap-full --quiet) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_advanced_sub \
        || ! -x target/zenoh-pico-cli/z_advanced_pub ]]; then
        _pico_cli_unavailable "Layer E11" || return 1
        return 0
    fi
    (cd crates && cargo test -p wz-integration-tests \
        --test apfull_advanced_pubsub_pico_interop -- --ignored --quiet --test-threads=1 \
        --exact apfull_cache_history_recovered_by_a_real_pico_advanced_subscriber 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test apfull_advanced_pubsub_pico_interop -- --ignored --quiet --test-threads=1 \
        --exact apfull_advanced_subscriber_recovers_history_from_a_real_pico_cache 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
}

# ─── Layer E12 — AP-full ADMINSPACE plane against a real zenoh-pico ────
#
# R311y489. The `adminspace-*` plane COMPOSED on one binary, in both directions:
# a real `z_get` reads every leg wz serves in ONE query (node record +
# introspection + metrics + plugins), and a real `z_put` reconfigures the node and
# then observes its own write through a second `z_get`.
#
# WHY THIS IS NOT COVERED BY E6b/E6e/E6f/E6g/E6. Each of those builds its OWN
# narrow feature set — cargo uplifts every variant of the same `--bin` to one path
# — and they assert the OTHER legs are absent (E6b's test ends by requiring
# `.../metrics` to be missing, which is what makes its cfg-gate argument work). So
# the plane had six proofs of six parts and none of the whole. That whole is what
# `preset-ap-full` is for, and until y489 it could not be asked: the preset omitted
# seven of the eight atoms while `routing-peer` pulled the eighth, so an AP-full
# node answered its own identity and nothing else.
#
# The pico guard names `z_put` BESIDE `z_get`: the write legs need both, and a
# guard on the reader alone would SKIP-green on a machine that has it — the
# R311y265 masked-skip shape E11's comment describes, and the reason its own guard
# names the advanced binaries specifically.
#
# BUILD FIRST, GUARD SECOND, for the reason Layers E9 and E11 both state: a SKIP is
# green, so a build sitting behind the guard would leave the preset's adminspace
# membership ungated on every machine without the foreign CLI — which is exactly
# how the membership drift this lane exists to catch would reach main invisibly.
layer_e12_apfull_adminspace_pico() {
    (cd crates && cargo build -p wz-ap-demo --no-default-features \
        --features preset-ap-full --quiet) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_get || ! -x target/zenoh-pico-cli/z_put ]]; then
        _pico_cli_unavailable "Layer E12" || return 1
        return 0
    fi
    # Named `--exact` one per invocation, like E9 and E11 and for the same reason:
    # a rename or a silently-dropped test then fails the lane instead of shrinking
    # it quietly.
    for leg in \
        apfull_adminspace_plane_decoded_by_a_real_pico_z_get \
        apfull_adminspace_read_gate_denies_every_leg_to_a_real_pico_z_get \
        apfull_adminspace_write_applied_and_observed_by_a_real_pico \
        apfull_adminspace_write_gate_refuses_an_unpermitted_pico_put \
        apfull_router_hat_linkstate_decoded_by_a_real_pico_z_get \
        apfull_storage_host_hotreload_state_flip_seen_by_a_real_pico; do
        (cd crates && cargo test -p wz-integration-tests \
            --test apfull_adminspace_pico_interop -- --ignored --quiet --test-threads=1 \
            --exact "$leg" 2>&1 \
            | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    done
}

# ─── Layer E13 — AP-full STORAGE plane against a real zenoh-pico ───────
#
# R311y496. The §5.24 storage plane COMPOSED on one AP-full binary and driven
# entirely by foreign processes: a real pico CONFIGURES a storage over the admin
# write plane, a real pico WRITES a sample into it, and a LATER real pico READS
# that sample back. Three one-shot clients, three separate sessions, one wz node.
#
# WHY E6h AND y362's LANE DO NOT COVER IT. Each proves a part on its own narrow
# build — E6h the `storage-add` STATE flip (`storage_manager` reports Started),
# y362 an in-process manager serving two storages. Neither crosses the session
# boundary on the kitchen-sink binary, which is where this plane was broken: the
# storage's capture subscriber and queryable were bound to whichever transient
# client session had created the storage, so the admin plane reported a live
# storage that the storage plane could not serve one foreign read from. Leg 1 is
# the guard for the fix (`RuntimeStorageManager::rebind_all`) and FAILED before
# it, with no reply at all for the key pico had just written.
#
# Legs 2 and 3 are a PAIR and neither is droppable: leg 2 restarts the host on
# the same `--storage-host-dir` and requires the value back (the
# `storage-backend-filesystem` claim, and the atom this preset held back until
# y496), leg 3 runs the same script WITHOUT the flag and requires it gone. Alone,
# leg 2 passes just as well if the value never left memory.
#
# BUILD FIRST, GUARD SECOND, as E9/E11/E12 all do and for the reason they state:
# a SKIP is green, so a build behind the guard would leave the preset's storage
# membership ungated on every machine without the foreign CLI.
# ─── Layer C1bv — §5.24 dynamic storage-VOLUME loading (unit + ABI) ───
#
# R311y497. Deliberately split from Layer E14 rather than bundled the way C1bp
# bundles its own unit and pico legs, and the split IS the R311y495 lesson applied
# rather than re-learned: C1bp did 86s of real work and then SKIP-passed the one
# leg that made it a cross-impl proof, because it was wired into a job that does
# not provision the pico CLI. This lane touches no foreign binary at all, so it
# cannot skip anywhere, and every leg that needs pico lives in E14.
# ─── Layer C1cc — §5.27 api-compat-c: the zenoh-c drop-in ───────────
#
# R311y498. The ORACLE (zenoh-c's headers, libzenohc.so, and a clone of its
# examples) is machine-local and is NOT in this repo, so the lane SKIPs when it is
# absent — and `WZ_C1BC_REQUIRE=1` turns that skip into a hard failure on any job
# that provisions it. The arming flag exists because a skip is green, which is the
# R311y265 masked-skip burn and what R311y495 caught C1bp doing for two rounds.
#
# Named C1cc, not C1bc: C1bc is `layer_c1bc_cargo_test_mcast_qos`. The first draft
# reused it and `--layer C1bc` ran BOTH lanes, which is how the collision showed.
#
# Three things run, and they are bound to different properties (each shown by its
# own damage): the LAYOUT gate compares wz's footprints against what a C compiler
# measures from the installed header — the in-file const assertions cannot see the
# header move, because they only check that file against itself; the DROP-IN leg
# compiles upstream's own z_put.c against upstream's own header and links it BOTH
# ways, requiring the same wz subscriber to observe both; and the COVERAGE report
# prints how many of upstream's examples link, so a slice stays a measured
# fraction rather than a declared milestone.
# Build the `wz-capi-c` cdylib for the ABI arm THIS MACHINE's oracle actually is.
#
# zenoh-c's own `Z_FEATURE_UNSTABLE_API` changes type SIZES (`z_owned_bytes_t` is
# 40 with it, 32 without), so "wz is a zenoh-c drop-in" is incomplete until the
# build is named. Reading the INSTALLED header beats making every developer know
# which oracle they have — and C1cc's layout leg still checks the result, so a
# wrong selection here is caught rather than trusted.
#
# A FUNCTION rather than a copy in each lane: R311y500 added a second consumer
# (C1cd, on the job that has zenohd), and two copies of an arm selection is two
# places for the cdylib to be built for the wrong header. `$1` is the lane name,
# for the message only.
_runci_build_capi_c_for_oracle() {
    local lane="$1"
    local capi_c_features=()
    local zc_configure="${WZ_ZENOH_C_PREFIX:-$HOME/.local}/include/zenoh_configure.h"
    # TWO axes, not one (R311y540 measured the second). `Z_FEATURE_UNSTABLE_API`
    # moves 2 of the types wz declares and `Z_FEATURE_SHARED_MEMORY` moves 8, so
    # reading only the first would build the wrong cdylib the moment a lane is
    # pointed at an SHM oracle — and the failure would be a SIZE mismatch, which
    # is a corrupted caller frame rather than a link error.
    #
    # Absent header => no features, i.e. the default arm. That is unchanged, and
    # it is fine: the layout leg SKIPs when the oracle is absent, so nothing
    # compares the build against anything.
    if [[ -f "$zc_configure" ]]; then
        if ! grep -q '^#define Z_FEATURE_UNSTABLE_API' "$zc_configure"; then
            capi_c_features+=(--features zenoh-c-no-unstable-api)
        fi
        if grep -q '^#define Z_FEATURE_SHARED_MEMORY' "$zc_configure"; then
            capi_c_features+=(--features zenoh-c-shared-memory)
        fi
    fi
    if [[ ${#capi_c_features[@]} -gt 0 ]]; then
        echo "  Layer $lane: oracle selects wz-capi-c ${capi_c_features[*]}"
    else
        echo "  Layer $lane: oracle selects wz-capi-c default features (unstable, no shm)"
    fi
    (cd crates && cargo build -p wz-capi-c "${capi_c_features[@]}" --quiet)
}

layer_c1cc_api_compat_c() {
    _runci_build_capi_c_for_oracle C1cc || return 1
    (cd crates && cargo build -p wz-ap-demo --quiet) || return 1
    (cd crates && cargo clippy -p wz-capi-core --all-targets --quiet -- -D warnings) || return 1
    # BOTH ABI arms are clippy-gated, not just the one this oracle selects: the
    # other arm is still shipped code and a `#[cfg]` that stops compiling is
    # invisible until someone with the other oracle tries it.
    # R311y543 — all FOUR arms, not the two this loop used to cover. The crate's
    # `#[cfg]` surface is now two independent axes (`zenoh-c-no-unstable-api` and
    # `zenoh-c-shared-memory`), and the `ze_advanced_*` / `z_shm_*` modules sit
    # behind different combinations of them — so an arm nobody compiles is an arm
    # whose `cfg` can stop building unnoticed, which is exactly the shape that
    # redded hosted CI at R311y536.
    for capi_c_arm in \
        "" \
        "zenoh-c-no-unstable-api" \
        "zenoh-c-shared-memory" \
        "zenoh-c-no-unstable-api,zenoh-c-shared-memory"; do
        if [[ -z "$capi_c_arm" ]]; then
            (cd crates && cargo clippy -p wz-capi-c --all-targets --quiet -- -D warnings) || return 1
        else
            (cd crates && cargo clippy -p wz-capi-c --features "$capi_c_arm" \
                --all-targets --quiet -- -D warnings) || return 1
        fi
    done
    # Via the guarded helper, NOT a bare `| grep -q`: this script sets
    # `set -o pipefail`, so grep's early exit races its upstream's SIGPIPE and
    # reds the lane. The first draft here did exactly that and the lane failed
    # with every one of its assertions passing — the hazard this helper exists to
    # close, documented at its own definition.
    _runci_guarded_test "C1cc wz-capi-c unit" + \
        cargo test -p wz-capi-c --quiet || return 1
    # R311y543 — the SHM arm carries unit tests the other three do not (the
    # segment allocator's), so running only the default arm would leave them
    # ungated. Same argument as the clippy loop above.
    _runci_guarded_test "C1cc wz-capi-c unit (shared-memory arm)" + \
        cargo test -p wz-capi-c --features zenoh-c-shared-memory --quiet || return 1
    if [[ ! -f "${WZ_ZENOH_C_PREFIX:-$HOME/.local}/include/zenoh.h" \
       || ! -f "${WZ_ZENOH_C_EXAMPLES:-$HOME/zenoh-c-ref/examples}/z_put.c" ]]; then
        if [[ -n "${WZ_C1CC_REQUIRE:-}" ]]; then
            echo "  Layer C1cc FAIL — required (WZ_C1CC_REQUIRE set) but the zenoh-c oracle is absent" >&2
            return 1
        fi
        echo "  Layer C1cc SKIP (zenoh-c oracle absent: headers + examples clone)"
        return 0
    fi
    # Named --exact one per invocation, like the E lanes: a rename or a silently
    # dropped test then fails the lane instead of shrinking it.
    for leg in \
        the_wz_capi_c_type_footprints_equal_upstreams_on_this_installation \
        upstream_option_defaults_on_wz_capi_c_match_real_libzenohc \
        upstream_z_put_links_against_wz_capi_c_and_a_real_wz_subscriber_receives_it; do
        _runci_guarded_test "C1cc $leg" 1 \
            cargo test -p wz-integration-tests \
            --test zenoh_c_examples_on_wz_capi_c_dropin -- --ignored --quiet --test-threads=1 \
            --exact "$leg" || return 1
    done
    # R311y564 — the PURE-FUNCTION twice-and-diff, a separate binary. It reaches
    # the part of the ABI no session ever touches (the encoding constant table,
    # keyexpr canonization and the set relations), which is where a wrong answer
    # is invisible to every interop leg: `z_keyexpr_canonize` runs before a
    # session exists. It found two wire-affecting defects on its first run.
    _runci_guarded_test "C1cc upstream_pure_functions_on_wz_capi_c_match_real_libzenohc" 1 \
        cargo test -p wz-integration-tests \
        --test zenoh_c_pure_function_oracle -- --ignored --quiet --test-threads=1 \
        --exact upstream_pure_functions_on_wz_capi_c_match_real_libzenohc || return 1
    # R311y564 — the DROP-IN CENSUS, the question the corpus report cannot ask.
    # `capi_c_coverage.py` above counts upstream EXAMPLES that link (29 of 29);
    # this counts SYMBOLS the real library defines and wz does not (180 of 568 at
    # this round). Both are true and they measure different things — a symbol no
    # example calls is invisible to the corpus and is still a program that cannot
    # be written. A RATCHET, not a zero: it fails when the gap grows, and equally
    # when it shrinks without its committed baseline moving.
    # R311y568 — `wz_exports_nothing_the_reference_does_not` is the OTHER
    # direction, and it is a separate leg rather than a widening of the first:
    # the ratchet above measures reference-minus-wz and is blind by construction
    # to wz-minus-reference, which is where an ungated unstable export or an
    # invented `z_`-named symbol lives. Both were present when it was written.
    for leg in \
        the_wz_capi_c_drop_in_surface_gap_does_not_grow \
        wz_exports_nothing_the_reference_does_not \
        the_census_reads_both_libraries_rather_than_nothing; do
        _runci_guarded_test "C1cc $leg" 1 \
            cargo test -p wz-integration-tests \
            --test zenoh_c_abi_symbol_census -- --ignored --quiet --test-threads=1 \
            --exact "$leg" || return 1
    done
    # R311y566 — the `source_info` FOREIGN ADJUDICATOR, the gap the debt ledger
    # named as the largest on this axis. Everything y561-y563 built on this plane
    # was wz-driven with damage probes, because no stock example on either side
    # sets the field. This is the y548 remedy applied: an upstream program
    # PATCHED to set it, compiled once and linked twice.
    _runci_guarded_test \
        "C1cc a_patched_upstream_put_carries_source_info_identically_on_wz_and_libzenohc" 1 \
        cargo test -p wz-integration-tests \
        --test zenoh_c_source_info_twice_and_diff -- --ignored --quiet --test-threads=1 \
        --exact a_patched_upstream_put_carries_source_info_identically_on_wz_and_libzenohc \
        || return 1
    # R311y500 — the CROSS-IMPL half, and it is a different question from the
    # three legs above. Those establish that upstream's program LINKS wz and that
    # wz's answers match the real `libzenohc.so`; every byte on their wire was
    # still produced and consumed by wz, which is why Layer A4 refused a proof
    # annotation on that file and `api-compat-c` sat UNPROVEN. These two put a
    # REAL zenoh-pico CLI on the far side, so the counterparty is a foreign
    # implementation that shares no code with either end.
    #
    # They need the pico CLIs as well as the zenoh-c oracle; ci.yml builds them
    # ahead of this lane (moved there in this same commit for exactly that
    # reason). The oracle guard above covers the zenoh-c half and returns before
    # reaching here when it is absent.
    for leg in \
        upstream_z_sub_on_wz_capi_c_receives_from_a_real_pico_zput \
        upstream_z_put_on_wz_capi_c_reaches_a_real_pico_zsub \
        upstream_z_delete_on_wz_capi_c_is_decoded_by_a_real_pico_zsub \
        upstream_z_pub_on_wz_capi_c_reaches_a_real_pico_zsub_and_sees_it_match \
        upstream_z_liveliness_on_wz_capi_c_is_seen_alive_by_real_pico \
        upstream_z_sub_liveliness_on_wz_capi_c_sees_a_real_pico_token_come_and_go \
        upstream_z_queryable_on_wz_capi_c_answers_a_real_pico_zget \
        upstream_z_get_on_wz_capi_c_is_answered_by_a_real_pico_queryable \
        upstream_z_queryable_with_channels_on_wz_capi_c_answers_from_its_own_thread \
        upstream_z_pull_on_wz_capi_c_pulls_a_real_pico_sample_out_of_a_ring \
        upstream_z_ping_on_wz_capi_c_round_trips_against_a_real_pico_pong \
        upstream_z_bytes_on_wz_capi_c_prints_identically_to_real_libzenohc \
        upstream_z_pub_on_wz_capi_c_carries_its_put_encoding_to_a_real_pico \
        upstream_z_pub_thr_on_wz_capi_c_carries_its_publisher_qos_to_a_real_pico \
        a_wz_capi_c_queryable_reply_encoding_reaches_a_real_pico_as_it_does_on_libzenohc \
        a_wz_capi_c_get_encoding_reaches_a_real_pico_queryable_as_it_does_on_libzenohc; do
        _runci_guarded_test "C1cc $leg" 1 \
            cargo test -p wz-integration-tests \
            --test zenoh_c_capi_c_pico_interop -- --ignored --quiet --test-threads=1 \
            --exact "$leg" || return 1
    done
    # REPORTED, never enforced — see the script's own header for why a ratchet
    # needs a committed baseline and is a separate decision.
    python3 scripts/lib/capi_c_coverage.py || return 1
    # R311y540 — the OTHER ABI arm. Everything above measures wz against the
    # INSTALLED header, which exists for exactly one `Z_FEATURE_*` set, so the
    # arm this machine did NOT provision is measured by nothing at all. That is
    # where a 40-byte `z_owned_bytes_t` survived from R311y498 to R311y540.
    #
    # Behind a flag because a COLD run builds the zenoh dependency graph twice
    # (minutes, and it needs network for zenoh-c's git dependency on zenoh) — the
    # same on-demand shape `build-zenohd.sh` has. Re-runs are incremental. The
    # script SKIPs loudly without zenoh-c's SOURCE checkout, and
    # WZ_CAPI_C_ARMS_REQUIRE=1 turns that skip into a failure on a job that
    # provisions it.
    if [[ -n "${WZ_C1CC_OPAQUE_ARMS:-}" ]]; then
        bash scripts/check-capi-c-opaque-arms.sh || return 1
    fi
}

# ─── Layer C1ce — §5.27 api-compat-c against the SHARED-MEMORY oracle ───
#
# R311y541. Layer C1cc measures wz against whatever zenoh-c is INSTALLED, and
# `install-zenoh-c.sh` installs upstream's published archive — the build with
# neither `Z_FEATURE_SHARED_MEMORY` nor `Z_FEATURE_UNSTABLE_API`. Against that
# header SEVEN of upstream's 29 examples do not COMPILE at all, so C1cc reports
# them ORACLE-ONLY and keeps them out of its denominator. That is honest and it
# is also permanent: no amount of wz work moves a number whose denominator
# excludes them.
#
# `install-zenoh-c-shm.sh` builds the other oracle from source, and against it
# the denominator becomes the whole corpus. The measured effect of turning it on
# is the point of this lane: 22 of 22 becomes 21 of 29, which is NOT a
# regression — it is the same library measured against a corpus that no longer
# hides the part it does not implement. `z_sub_shm` moving from LINKS to
# MISSING(3) is the same thing at one example's scale: against an SHM header it
# needs three symbols it did not need before.
#
# SKIPs when that oracle is absent, because building it takes minutes and pulls
# the whole zenoh graph; WZ_C1CE_REQUIRE=1 turns the skip into a failure on a
# job that provisions it.
layer_c1ce_api_compat_c_shm_oracle() {
    local shm="${WZ_ZENOH_C_SHM_PREFIX:-$repo_root/target/zenoh-c-shm}"
    if [[ ! -f "$shm/include/zenoh.h" || ! -f "$shm/lib/libzenohc.so" ]]; then
        if [[ -n "${WZ_C1CE_REQUIRE:-}" ]]; then
            echo "  Layer C1ce FAIL — required (WZ_C1CE_REQUIRE set) but the" >&2
            echo "  shared-memory zenoh-c oracle is absent at $shm." >&2
            echo "  Provision it with: bash scripts/install-zenoh-c-shm.sh" >&2
            return 1
        fi
        echo "  Layer C1ce SKIP (no shared-memory zenoh-c oracle at $shm;"
        echo "  provision with: bash scripts/install-zenoh-c-shm.sh)"
        return 0
    fi
    # The examples corpus still comes from the reference clone; only the headers
    # and the reference library change.
    if [[ ! -f "${WZ_ZENOH_C_EXAMPLES:-$HOME/zenoh-c-ref/examples}/z_put.c" ]]; then
        echo "  Layer C1ce SKIP (the zenoh-c examples clone is absent)"
        return 0
    fi

    local rc=0
    # Build the arm THIS oracle selects — which is the default plus
    # `zenoh-c-shared-memory`, resolved by reading both defines rather than one.
    WZ_ZENOH_C_PREFIX="$shm" _runci_build_capi_c_for_oracle C1ce || return 1
    # The OBSERVER the publishing legs adjudicate with. Built here rather than
    # inherited from Layer C1cc, because `--layer C1ce` on its own is a supported
    # invocation and because a STALE observer is not a missing one: this lane's
    # `@adv`-namespace assertion is about wz's keyexpr matcher, so an observer
    # binary predating a change to it reds the lane for a reason that is no
    # longer true. That happened while these legs were being written.
    (cd crates && cargo build -p wz-ap-demo --quiet) || return 1
    # The C-compiler footprint check, now against the OTHER header. It is a
    # different mechanism from `check-capi-c-opaque-arms.sh`'s generator: one
    # asks a C compiler for `sizeof` on an installed header, the other asks
    # upstream's own build to print the sizes. Agreement between two independent
    # mechanisms is what makes the SHM arm's numbers trustworthy.
    WZ_ZENOH_C_PREFIX="$shm" _runci_guarded_test "C1ce layout" 1 \
        cargo test -p wz-integration-tests \
        --test zenoh_c_examples_on_wz_capi_c_dropin -- --ignored --quiet --test-threads=1 \
        --exact the_wz_capi_c_type_footprints_equal_upstreams_on_this_installation || rc=1
    # R311y545 — the option-DEFAULTS differential, and this oracle is the only
    # place it can measure the unstable half. `z_publisher_options_t.reliability`
    # and `z_put_options_t.source_info` exist ONLY under Z_FEATURE_UNSTABLE_API,
    # which the installed header C1cc runs against does not define — so the
    # `Z_RELIABILITY_RELIABLE` value R311y545 corrected from 0 to 1 is invisible
    # on that lane. This is the arm nobody was measuring, which is the shape
    # R311y540 paid for.
    WZ_ZENOH_C_PREFIX="$shm" _runci_guarded_test "C1ce option defaults" 1 \
        cargo test -p wz-integration-tests \
        --test zenoh_c_examples_on_wz_capi_c_dropin -- --ignored --quiet --test-threads=1 \
        --exact upstream_option_defaults_on_wz_capi_c_match_real_libzenohc || rc=1
    # R311y566 — the `source_info` FOREIGN ADJUDICATOR, and THIS is the lane
    # where it means something. The whole source-info half of that probe sits
    # behind the header's own `#if defined(Z_FEATURE_UNSTABLE_API)`, so on the
    # installed no-unstable oracle Layer C1cc runs it and measures only the
    # delivery half. Here it measures the field: that a publisher's
    # `z_entity_global_id_t` round-trips through `z_source_info_new`, reaches the
    # wire, and comes back off `z_sample_source_info` with the same eid and sn.
    #
    # It is the gap the debt ledger named as the largest on this axis: every
    # witness R311y561-y563 produced for this plane was wz driving wz, because no
    # stock example sets the field. Damage-probed by dropping the put-side fold,
    # which prints five differing lines.
    WZ_ZENOH_C_PREFIX="$shm" _runci_guarded_test "C1ce source_info adjudicator" 1 \
        cargo test -p wz-integration-tests \
        --test zenoh_c_source_info_twice_and_diff -- --ignored --quiet --test-threads=1 \
        --exact a_patched_upstream_put_carries_source_info_identically_on_wz_and_libzenohc \
        || rc=1
    # R311y543 — the RUN legs for the two planes this oracle is what makes
    # reachable. Layer C1cc cannot host them: against the INSTALLED header
    # (neither Z_FEATURE_SHARED_MEMORY nor Z_FEATURE_UNSTABLE_API) these six
    # examples do not COMPILE, which is why they sat ORACLE-ONLY for so long.
    #
    # Named --exact one per invocation, as C1cc does: a rename or a silently
    # dropped test then fails the lane instead of shrinking it.
    #
    # Two of them additionally need the zenoh-pico CLIs as the foreign
    # counterparty; ci.yml's capi-c-arms job builds them ahead of this lane.
    for leg in \
        upstream_z_pub_shm_on_wz_capi_c_publishes_the_same_shm_chunk_on_both_arms \
        upstream_z_advanced_pub_on_wz_capi_c_puts_the_same_sample_and_no_adv_leak \
        upstream_z_sub_shm_on_wz_capi_c_reports_the_same_buffer_type_on_both_arms \
        upstream_z_advanced_sub_on_wz_capi_c_receives_the_same_samples_from_real_pico \
        upstream_z_get_shm_on_wz_capi_c_is_answered_identically_by_a_real_pico_queryable; do
        WZ_ZENOH_C_PREFIX="$shm" _runci_guarded_test "C1ce $leg" 1 \
            cargo test -p wz-integration-tests \
            --test zenoh_c_shm_and_advanced_on_wz_capi_c -- --ignored --quiet --test-threads=1 \
            --exact "$leg" || rc=1
    done
    # R311y573 — the zenoh-ext families (`ze_publication_cache` /
    # `ze_querying_subscriber`), the 18 symbols that were the smaller of the two
    # planes the census had left on this arm. They sit behind
    # `Z_FEATURE_UNSTABLE_API`, so THIS oracle is the only one that can declare
    # them and this lane is the only place the leg can run. A link census says
    # the symbols exist; this says they behave as upstream's do.
    WZ_ZENOH_C_PREFIX="$shm" _runci_guarded_test "C1ce zenoh-ext families" 1 \
        cargo test -p wz-integration-tests \
        --test zenoh_c_ext_families_twice_and_diff -- --ignored --quiet --test-threads=1 \
        --exact the_zenoh_ext_families_behave_identically_on_wz_and_libzenohc || rc=1
    # REPORTED, never enforced, exactly as C1cc's is.
    WZ_ZENOH_C_PREFIX="$shm" python3 scripts/lib/capi_c_coverage.py || rc=1

    # Leave the cdylib as the DEFAULT oracle wants it. Layers that run after this
    # one read the same artifact path, and a lane that hands the next one a
    # cdylib built for a different header is the one-shared-artifact hazard this
    # tree has already been bitten by.
    _runci_build_capi_c_for_oracle "C1ce restore" || rc=1
    # QUOTED, and the quotes are the whole point (R311y543). The pinned 0.11.0
    # linter hosted CI installs reports SC2086 on a bare `return $rc` and the
    # 0.8.0 that floats on a dev machine does not, so R311y541 shipped this line
    # and hosted CI red on Layer 0 while every local run was green. Same class
    # R311y419 fixed five of.
    #
    # (This comment deliberately does not open a line with the linter's own
    # name: a comment that does is parsed as a DIRECTIVE, which is SC1073.)
    return "$rc"
}

# ─── Layer C1cd — §5.27 api-compat-c ATTACHMENT, pico + zenohd ──────
#
# R311y500. A SEPARATE lane from C1cc, and the split is about PROVISIONING, not
# about tidiness: this leg needs a real zenohd as well as the zenoh-c oracle and
# the pico CLIs, and ci.yml builds zenohd on the `interop` job only. Putting it in
# C1cc — which runs on `ci` — would make it skip there forever, and a skip is
# green.
#
# WHY THE ROUTER IS IN THE TOPOLOGY AT ALL. `z_sample_attachment`'s PRESENT arm
# needs a foreign publisher that attaches, and the only pico example that does is
# `z_pub_attachment`, which publishes through a DECLARED PUBLISHER. That path
# delivers nothing in the client-to-listening-peer topology C1cc's legs use — not
# to wz, and not pico-to-pico either. Measuring all four arms with a real zenohd
# in the middle is what settled why: pico `z_pub` reaches a pico subscriber
# through zenohd (3 of 3) AND through wz's own `--router-hat` (3 of 3), so the
# declared-publisher path works and wz forwards it as the reference router does.
# The earlier failures were the ABSENT ROUTER — a fact about the harness, not
# about either implementation.
#
# The leg gains what C1cc's cannot have: TWO foreign implementations on the path.
# pico encodes the attachment, zenohd routes it, and only the rendering is wz's.
layer_c1cd_api_compat_c_attachment() {
    if [[ ! -f "${WZ_ZENOH_C_PREFIX:-$HOME/.local}/include/zenoh.h" \
       || ! -f "${WZ_ZENOH_C_EXAMPLES:-$HOME/zenoh-c-ref/examples}/z_sub.c" \
       || ! -x target/zenohd/zenohd \
       || ! -x target/zenoh-pico-cli/z_pub_attachment ]]; then
        if [[ -n "${WZ_C1CD_REQUIRE:-}" ]]; then
            echo "  Layer C1cd FAIL — required (WZ_C1CD_REQUIRE set) but an oracle is absent (zenoh-c headers+examples / zenohd / pico z_pub_attachment)" >&2
            return 1
        fi
        echo "  Layer C1cd SKIP (needs the zenoh-c oracle AND zenohd AND the pico CLIs)"
        return 0
    fi
    _runci_build_capi_c_for_oracle C1cd || return 1
    # R311y519 — the lane's OWN dependency, and it is not the subject under test.
    # `spawn_zenohd` gates readiness by driving a real wz open against the router
    # (`wait_for_zenohd_handshake_ready`), and that probe is the wz-ap-demo
    # binary. Nothing else in this leg touches the demo — the subject is the C
    # ABI — which is exactly why the lane never learned to build it: every OTHER
    # zenohd lane drives the demo directly and so provisions it as its subject.
    #
    # Absent, the probe panics "wz-ap-demo binary not found" before a single
    # attachment byte moves. That was invisible on any developer machine, where
    # some earlier lane has always left the binary in `target/debug`, and red on
    # every hosted run: the `interop` job builds zenohd, the pico CLIs and the
    # zenoh-c oracle, but never the demo. Provisioned HERE rather than as a
    # workflow step so the lane behaves identically hosted and locally, and so a
    # clean checkout cannot reintroduce it.
    (cd crates && cargo build -p wz-ap-demo --quiet) || return 1
    _runci_guarded_test "C1cd attachment through zenohd" 1 \
        cargo test -p wz-integration-tests \
        --test zenoh_c_capi_c_pico_interop -- --ignored --quiet --test-threads=1 \
        --exact upstream_z_sub_on_wz_capi_c_renders_a_pico_attachment_through_zenohd \
        || return 1
}

layer_c1bv_dynamic_volume_loading() {
    # The two cdylibs. wz-volume-example is what the host loads; wz-plugin-example
    # is the honest NEGATIVE — a real loadable shared object that exports
    # `wz_plugin_entry` and no `wz_volume_entry`, which is the leg that justifies
    # the two ABIs having distinct entry symbols.
    (cd crates && cargo build -p wz-volume-example -p wz-plugin-example --quiet) || return 1
    # The ABI contract's own gate: the compatibility check is a pure function, so
    # it is unit-testable exhaustively in a way the e2e cannot be — a mismatched
    # ABI needs a volume built against a different contract. It checks TWO layout
    # fingerprints (vtable AND StoredEntry), unlike the plugin ABI, because this
    # one passes a struct BY POINTER.
    (cd crates && cargo test -p wz-volume-abi --quiet) || return 1
    # The host: dlopen, the gate, the mirror rebuild, put/delete/entries across the
    # boundary, and the out-of-band counters that establish the host really called
    # THROUGH the vtable. Drives the REAL `.so` built above.
    (cd crates && cargo test -p wz-runtime-tokio --no-default-features \
        --features storage-mgr-dynamic-volume-loading --lib --quiet dynamic_volume:: 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. [0-9]+ passed') || return 1
    # The WIRE half: the storage-add payload's volume selection, which is what
    # makes a loaded volume reachable from a foreign client at all.
    (cd crates && cargo test -p wz-session-core --features adminspace-config-hotreload \
        --lib --quiet adminspace::tests::config_hotreload:: 2>&1 \
        | tee /dev/stderr | grep -qE '^test result: ok\. [0-9]+ passed') || return 1
    (cd crates && cargo clippy -p wz-runtime-tokio --no-default-features \
        --features storage-mgr-dynamic-volume-loading --all-targets -- -D warnings) || return 1
    (cd crates && cargo clippy -p wz-volume-abi -p wz-volume-example --all-targets \
        -- -D warnings) || return 1
}

# ─── Layer E14 — §5.24 dynamic storage volume against a real zenoh-pico ───
#
# R311y497. The four legs are a set: 1 proves the WIRE selection reaches the loaded
# volume, 2 proves DURABILITY through the `.so` across a host restart (the
# load-bearing one — within one process the host's read mirror answers every read,
# so only a value the previous process wrote can distinguish the volume from the
# host answering itself), 3 is the calibration that the same payload mounts NOTHING
# without the volume, and 4 is the refusal path with the node surviving.
layer_e14_apfull_dynamic_volume_pico() {
    (cd crates && cargo build -p wz-volume-example -p wz-plugin-example --quiet) || return 1
    (cd crates && cargo build -p wz-ap-demo --no-default-features \
        --features preset-ap-full --quiet) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_get || ! -x target/zenoh-pico-cli/z_put ]]; then
        _pico_cli_unavailable "Layer E14" || return 1
        return 0
    fi
    # Named `--exact` one per invocation, like E9/E11/E12/E13: a rename or a
    # silently dropped test then fails the lane instead of shrinking it quietly.
    for leg in \
        apfull_dynamic_volume_selected_over_the_wire_serves_a_pico_write \
        apfull_dynamic_volume_survives_a_host_restart_through_the_loaded_so \
        apfull_without_the_loaded_volume_the_same_payload_mounts_nothing \
        apfull_a_non_volume_shared_object_is_refused_and_the_node_survives; do
        (cd crates && cargo test -p wz-integration-tests \
            --test apfull_dynamic_volume_pico_interop -- --ignored --quiet --test-threads=1 \
            --exact "$leg" 2>&1 \
            | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    done
}

layer_e13_apfull_storage_plane_pico() {
    (cd crates && cargo build -p wz-ap-demo --no-default-features \
        --features preset-ap-full --quiet) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_get || ! -x target/zenoh-pico-cli/z_put ]]; then
        _pico_cli_unavailable "Layer E13" || return 1
        return 0
    fi
    # Named `--exact` one per invocation, like E9/E11/E12: a rename or a silently
    # dropped test then fails the lane instead of shrinking it quietly.
    for leg in \
        apfull_storage_plane_serves_a_pico_write_to_a_later_pico_read \
        apfull_storage_plane_survives_a_host_restart_on_a_durable_volume \
        apfull_storage_plane_is_volatile_across_a_restart_without_the_durable_volume \
        apfull_storage_del_stops_serving_a_real_pico_get \
        apfull_storage_gc_sweeps_a_wildcard_update_a_real_pico_registered; do
        (cd crates && cargo test -p wz-integration-tests \
            --test apfull_storage_plane_pico_interop -- --ignored --quiet --test-threads=1 \
            --exact "$leg" 2>&1 \
            | tee /dev/stderr | grep -qE '^test result: ok\. 1 passed') || return 1
    done
}

# ─── Layer E15 — §5.21 router-connect-reconcile federation to a real zenoh-pico ───
#
# The reconcile's FOUR existing proofs (wz_router_hat_connect_reconcile.rs) are all
# wz<->wz and all assert a LINK-STATE COUNT; none asks whether the face the reconcile
# dialed carries application data. This lane is the pair that does, with both endpoints
# foreign: leg 1 sends a real pico z_pub's sample across a federation face that did not
# exist at startup to a real pico z_sub on the far router, and leg 2 is the calibration
# that removes ONLY `--connect-after` and shows the same AP-full binary (multicast
# faces compiled in, group live) forwards zero pushes. Without leg 2 a green leg 1
# would not distinguish the reconcile from the multicast plane.
#
# Damage-established (R311y499): suppressing the reconcile channel send while LEAVING
# its log line intact reds leg 1 and leaves BOTH Layer E9 legs green on the same
# binary — so the claim binds to the reconcile path, and the existing AP-full
# composition proof demonstrably survives a dead reconcile.
layer_e15_apfull_reconcile_federation_pico() {
    (cd crates && cargo build -p wz-ap-demo --no-default-features \
        --features preset-ap-full --quiet) || return 1
    if [[ ! -x target/zenoh-pico-cli/z_sub || ! -x target/zenoh-pico-cli/z_pub ]]; then
        _pico_cli_unavailable "Layer E15" || return 1
        return 0
    fi
    # Named `--exact` one per invocation, like E9/E11/E12/E13/E14: a rename or a
    # silently dropped test then fails the lane instead of shrinking it quietly.
    for leg in \
        apfull_reconcile_federation_carries_data_between_two_real_picos \
        apfull_without_the_reconcile_the_two_picos_cannot_reach_each_other; do
        _runci_guarded_test "Layer E15 ($leg)" 1 \
            cargo test -p wz-integration-tests \
            --test apfull_router_reconcile_pico_interop -- --ignored --quiet \
            --test-threads=1 --exact "$leg" || return 1
    done
}

# ─── Layer Qz — Zephyr cooperative profile west build + QEMU boot e2e ───
#
# The REAL Zephyr link + boot proof (R311y31 / Z2). UNLIKE the FreeRTOS lane
# (Q.frt, pure-cargo: cargo IS the build + link), the Zephyr port is
# west/cmake/kconfig-driven: this lane drives `west build -b qemu_cortex_m3
# deploy/zephyr-app`, which compiles the Zephyr kernel AND links the wz cargo
# staticlib into the image via the CMakeLists.txt `--undefined` kernel-symbol
# contract (libkernel.a is scanned before librustlib.a). It then boots the image
# on qemu_cortex_m3 (= ti_lm3s6965 = machine lm3s6965evb, per the board.cmake)
# and asserts the `ZEPHYR-WZ PASS` CONSOLE sentinel — Zephyr's idiomatic
# console-regex verdict (twister-style), since this board's qemu launch has no
# semihosting SYS_EXIT channel (so run_qemu_case's exit-code verdict does not
# apply here). This is the executed boot that ends the G.16/G.17 pure-cargo
# lib-check staging.
#
# The Zephyr toolchain (Python 3.12 venv + ZEPHYR_BASE + SDK + west) is
# host/CI-provisioned, NOT vendored, so every prerequisite SKIPs (does not FAIL)
# when absent — host-only dev boxes and non-Zephyr CI legs stay green, exactly
# like Q.frt SKIPs without qemu. Override the default ~/zephyrproject paths with
# WZ_ZEPHYR_VENV / WZ_ZEPHYR_BASE.
# Qz prerequisite outcome: SKIP (green) on a dev host / non-Zephyr CI leg where
# the toolchain is absent, but FAIL (red) on the dedicated GitHub `zephyr-mcu`
# job, which sets WZ_QZ_REQUIRE=1. On that job the provisioning steps GUARANTEE
# every prerequisite, so a SKIP there is a provisioning regression masquerading
# as success — the project's anti-masked-failure stance (R311y25: a should-run
# lane that SKIPs is the burn). Returns 0 = skip-green, 1 = required-but-absent.
_qz_unavailable() {
    if [[ -n "${WZ_QZ_REQUIRE:-}" ]]; then
        echo "  Qz FAIL — required (WZ_QZ_REQUIRE set) but $1" >&2
        return 1
    fi
    echo "  Qz SKIP ($1)"
    return 0
}

layer_qz_zephyr_boot() {
    local venv="${WZ_ZEPHYR_VENV:-$HOME/zephyrproject/.venv}"
    local zbase="${WZ_ZEPHYR_BASE:-$HOME/zephyrproject/zephyr}"
    local installed
    installed="$(rustup target list --installed 2>/dev/null)"

    if ! grep -q "^thumbv7m-none-eabi$" <<< "$installed"; then
        _qz_unavailable "rustup target thumbv7m-none-eabi absent"; return $?
    fi
    if ! command -v qemu-system-arm >/dev/null 2>&1; then
        _qz_unavailable "qemu-system-arm not on PATH"; return $?
    fi
    if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
        _qz_unavailable "arm-none-eabi-gcc not on PATH — lwip-sys cross cc"; return $?
    fi
    if [[ ! -f "$venv/bin/activate" ]]; then
        _qz_unavailable "Zephyr venv absent: $venv — set WZ_ZEPHYR_VENV"; return $?
    fi
    if [[ ! -d "$zbase" ]]; then
        _qz_unavailable "ZEPHYR_BASE absent: $zbase — set WZ_ZEPHYR_BASE"; return $?
    fi
    if ! command -v west >/dev/null 2>&1 && [[ ! -x "$venv/bin/west" ]]; then
        _qz_unavailable "west not on PATH nor in the venv"; return $?
    fi

    local build_dir elf qlog qpid fail=0
    build_dir="$(mktemp -d)/zbuild"
    elf="$build_dir/zephyr/zephyr.elf"

    # west build in a subshell so the venv activate + ZEPHYR_BASE export do not
    # leak into the rest of run-ci. cargo (invoked by the CMakeLists.txt) pins
    # CC_thumbv7m_none_eabi=arm-none-eabi-gcc + WZ_LWIP_PORT itself.
    if (
        # shellcheck disable=SC1091
        source "$venv/bin/activate" 2>/dev/null
        export ZEPHYR_BASE="$zbase"
        west build -b qemu_cortex_m3 -d "$build_dir" deploy/zephyr-app >/dev/null 2>&1
    ); then
        echo "  Qz build deploy/zephyr-app (west, qemu_cortex_m3) OK"
    else
        echo "  Qz build deploy/zephyr-app (west) FAIL" >&2
        rm -rf "$(dirname "$build_dir")"
        return 1
    fi

    # Boot + console-sentinel verdict. The -icount/-rtc flags mirror west's own
    # run invocation; kill qemu as soon as the verdict line appears (the image
    # idles after, no semihosting exit) with a 40s wall-clock backstop.
    #
    # The early-break pattern `^ZEPHYR-WZ ` is a deliberate line-anchored PREFIX
    # of BOTH the C main's outcome lines (`ZEPHYR-WZ PASS` / `ZEPHYR-WZ FAIL …`,
    # main.c) — it only ENDS the wait once either verdict is fully printed; the
    # narrow anchored grep below is what DECIDES. Both greps are `-E '^…'`
    # start-anchored so a mid-write partial line or an interleaved log line cannot
    # produce a false verdict; the verdict grep ends with `[[:space:]]*$` (NOT a
    # bare `$`) because the QEMU serial console emits CRLF — the line is
    # `ZEPHYR-WZ PASS\r`, so a bare `$` would FALSE-FAIL on the trailing \r. If
    # the C sentinel prefix is ever renamed, update BOTH patterns in lockstep.
    # The 350×0.1s (35s) poll stays inside the 40s
    # qemu backstop; the loopback echo completes in well under a second of guest
    # time, so the margin is large even on a slow/loaded runner.
    qlog="$(mktemp)"
    timeout 40 qemu-system-arm -cpu cortex-m3 -machine lm3s6965evb -nographic \
        -icount shift=6,align=off,sleep=off -rtc clock=vm -net none \
        -kernel "$elf" >"$qlog" 2>&1 &
    qpid=$!
    for _ in $(seq 1 350); do
        grep -qE '^ZEPHYR-WZ ' "$qlog" 2>/dev/null && break
        kill -0 "$qpid" 2>/dev/null || break
        sleep 0.1
    done
    kill "$qpid" 2>/dev/null
    wait "$qpid" 2>/dev/null

    if grep -qE '^ZEPHYR-WZ PASS[[:space:]]*$' "$qlog"; then
        echo "  Qz run deploy/zephyr-app via qemu_cortex_m3 (lm3s6965evb) PASS"
    else
        echo "  Qz run deploy/zephyr-app FAIL (no 'ZEPHYR-WZ PASS' console sentinel)" >&2
        echo "  ── Qz: captured qemu output ──" >&2
        sed 's/^/    | /' "$qlog" >&2
        fail=1
    fi
    rm -f "$qlog"
    rm -rf "$(dirname "$build_dir")"
    return "$fail"
}

# ─── dispatch ──────────────────────────────────────────────────────
overall=0
run_layer 0 layer_0_preflight_lints || overall=1
run_layer A layer_a_mnemosyne || overall=1
run_layer A2 layer_a2_audit_mid_values || overall=1
run_layer A3 layer_a3_audit_catalog_status || overall=1
run_layer A4 layer_a4_audit_crossimpl_proof || overall=1
run_layer A5 layer_a5_apfull_membership || overall=1
run_layer B layer_b_verify_codegen || overall=1
run_layer B2 layer_b2_regen_diff || overall=1
run_layer C0 layer_c0_test_discipline || overall=1
run_layer C1 layer_c1_cargo_test || overall=1
run_layer C1b layer_c1b_cargo_test_alloc || overall=1
run_layer C1c layer_c1c_cargo_test_codec_declare || overall=1
run_layer C1t layer_c1t_cargo_test_serial || overall=1
run_layer C1u layer_c1u_cargo_test_tls || overall=1
run_layer C1v layer_c1v_cargo_test_ws || overall=1
run_layer C1aa layer_c1aa_cargo_test_unixsock || overall=1
run_layer C1ab layer_c1ab_cargo_test_vsock || overall=1
run_layer C1ac layer_c1ac_cargo_test_quic || overall=1
run_layer C1ad layer_c1ad_cargo_test_lowlatency || overall=1
run_layer C1ae layer_c1ae_cargo_test_compression || overall=1
run_layer C1af layer_c1af_cargo_test_shm || overall=1
run_layer C1ag layer_c1ag_cargo_test_transport_compose || overall=1
run_layer C1ah layer_c1ah_cargo_test_time_hlc || overall=1
run_layer C1ai layer_c1ai_cargo_test_liveliness_history || overall=1
run_layer C1aj layer_c1aj_cargo_test_quic_datagram || overall=1
run_layer C1ak layer_c1ak_cargo_test_transport_stats || overall=1
run_layer C1al layer_c1al_cargo_test_unixpipe || overall=1
run_layer C1am layer_c1am_cargo_test_adminspace || overall=1
run_layer C1an layer_c1an_cargo_test_adminspace_nodefault || overall=1
run_layer C1ao layer_c1ao_cargo_test_config_mutate_runtime || overall=1
run_layer C1ap layer_c1ap_cargo_test_ext_pubsub_serde || overall=1
run_layer C1aq layer_c1aq_cargo_test_ext_pubsub_advanced || overall=1
run_layer C1ar layer_c1ar_cargo_test_ext_pubsub_advanced_sub || overall=1
run_layer C1as layer_c1as_cargo_test_reply_source_info || overall=1
run_layer C1at layer_c1at_cargo_test_ext_pubsub_advanced_recovery || overall=1
run_layer C1au layer_c1au_cargo_test_ext_pubsub_sample_miss_detection || overall=1
run_layer C1av layer_c1av_cargo_test_ext_pubsub_advanced_history || overall=1
run_layer C1aw layer_c1aw_cargo_test_ext_pubsub_group_membership || overall=1
run_layer C1ax layer_c1ax_cargo_test_routing_namespace || overall=1
run_layer C1ay layer_c1ay_cargo_test_router_hat || overall=1
run_layer C1az layer_c1az_cargo_test_rest_sse || overall=1
run_layer C1ba layer_c1ba_cargo_clippy_transport_multilink || overall=1
run_layer C1bb layer_c1bb_cargo_test_qos || overall=1
run_layer C1bc layer_c1bc_cargo_test_mcast_qos || overall=1
run_layer C1bd layer_c1bd_locator_iface || overall=1
run_layer C1be layer_c1be_cargo_test_query_value || overall=1
run_layer C1bf layer_c1bf_cargo_clippy_all_features || overall=1
run_layer C1bn layer_c1bn_passive_dissection_features || overall=1
run_layer C1bo layer_c1bo_dissect_c_abi || overall=1
run_layer C1bt layer_c1bt_capture_no_default_features || overall=1
run_layer C1bq layer_c1bq_zero_copy_arena || overall=1
run_layer C1br layer_c1br_uring_fixed_buffers || overall=1
run_layer C1bs layer_c1bs_live_capture || overall=1
run_layer C1bw layer_c1bw_analyze_cli || overall=1
run_layer C1w layer_c1w_cargo_test_routing_accept || overall=1
run_layer C1bl layer_c1bl_cargo_test_router_failfast || overall=1
run_layer C1bm layer_c1bm_cargo_test_pico_failfast || overall=1
run_layer C1x layer_c1x_cargo_test_routing_routes || overall=1
run_layer C1y layer_c1y_cargo_test_routing_peer || overall=1
run_layer C1z layer_c1z_cargo_test_storage_driver || overall=1
run_layer C1d layer_c1d_cargo_test_pubsub || overall=1
run_layer C1e layer_c1e_cargo_test_query || overall=1
run_layer C1f layer_c1f_cargo_test_reply || overall=1
run_layer C1g layer_c1g_cargo_test_observer || overall=1
run_layer C1h layer_c1h_arbitrary_subset_matrix || overall=1
run_layer C1i layer_c1i_cargo_test_scouting || overall=1
run_layer C1k layer_c1k_cargo_test_scouting_static || overall=1
run_layer C1l layer_c1l_reassembly || overall=1
run_layer C1m layer_c1m_session_lwip || overall=1
run_layer C1n layer_c1n_mcu_session_acceptor || overall=1
run_layer C1r layer_c1r_mcu_multicast_e2e || overall=1
run_layer C1s layer_c1s_runtime_tokio_multicast_tests || overall=1
run_layer C1o layer_c1o_keyexpr_gating_behavior || overall=1
run_layer C1p layer_c1p_multicast || overall=1
run_layer C1q layer_c1q_multicast_glue || overall=1
run_layer C1j layer_c1j_runtime_tokio_subset_behavior || overall=1
run_layer C1bg layer_c1bg_cargo_test_storage_backend_filesystem || overall=1
run_layer C1bh layer_c1bh_cargo_test_storage_host_dir || overall=1
run_layer C1bi layer_c1bi_cargo_test_pubsub_qos || overall=1
run_layer C1bj layer_c1bj_cargo_test_loopback_metadata_gates || overall=1
run_layer C1bk layer_c1bk_cargo_test_query_pub_field_gates || overall=1
run_layer C2 layer_c2_cargo_clippy || overall=1
run_layer C3 layer_c3_per_pkg_isolated_lint || overall=1
run_layer C4 layer_c4_preset_matrix || overall=1
run_layer C4b layer_c4b_facade_subset_matrix || overall=1
run_layer C4c layer_c4c_runtime_tokio_subset_matrix || overall=1
run_layer C4d layer_c4d_runtime_tokio_subset_clippy || overall=1
run_layer C4e layer_c4e_transport_axis_matrix || overall=1
run_layer D layer_d_validate_deploy || overall=1
run_layer L layer_l_lockfile_freshness || overall=1
run_layer C1bp layer_c1bp_plugin_dynamic_loading || overall=1
run_layer C1bv layer_c1bv_dynamic_volume_loading || overall=1
run_layer C1cc layer_c1cc_api_compat_c || overall=1
run_layer C1ce layer_c1ce_api_compat_c_shm_oracle || overall=1
run_layer C1cd layer_c1cd_api_compat_c_attachment || overall=1
run_layer Epico layer_epico_library_oracles || overall=1
run_layer E layer_e_ap_demo_round_trip || overall=1
run_layer E2 layer_e2_facade_subset_e2e || overall=1
run_layer E3 layer_e3_router_multi_peer || overall=1
run_layer E4 layer_e4_router_reject || overall=1
run_layer E4i layer_e4i_demo_inert_flags || overall=1
run_layer E5 layer_e5_router_forward || overall=1
run_layer E5u layer_e5u_router_unixpipe_forward || overall=1
run_layer E6u layer_e6u_peer_unixpipe_forward || overall=1
run_layer E6 layer_e6_peer_mesh || overall=1
run_layer E6b layer_e6b_adminspace_introspection || overall=1
run_layer E6c layer_e6c_peer_multilink || overall=1
run_layer E6d layer_e6d_peer_multilink_qos || overall=1
run_layer E6e layer_e6e_adminspace_plugins || overall=1
run_layer E6f layer_e6f_adminspace_metrics || overall=1
run_layer E6g layer_e6g_adminspace_read || overall=1
run_layer E6h layer_e6h_adminspace_config_hotreload || overall=1
run_layer E7 layer_e7_router_hat || overall=1
run_layer E7b layer_e7b_router_connect_reconcile || overall=1
run_layer E7c layer_e7c_router_adminspace_linkstate || overall=1
run_layer E7u layer_e7u_router_hat_unixpipe_forward || overall=1
run_layer E8 layer_e8_router_hat_pico || overall=1
run_layer E8t layer_e8t_router_hat_hlc_stamp_pico || overall=1
run_layer E9 layer_e9_apfull_preset_pico || overall=1
run_layer E10 layer_e10_close_frame_on_teardown || overall=1
run_layer E11 layer_e11_apfull_advanced_pubsub_pico || overall=1
run_layer E12 layer_e12_apfull_adminspace_pico || overall=1
run_layer E13 layer_e13_apfull_storage_plane_pico || overall=1
run_layer E14 layer_e14_apfull_dynamic_volume_pico || overall=1
run_layer E15 layer_e15_apfull_reconcile_federation_pico || overall=1
run_layer F layer_f_codec_footprint || overall=1
run_layer G layer_g_cross_compile_cortex_m || overall=1
run_layer Q layer_q_qemu_mcu_e2e || overall=1
run_layer Qz layer_qz_zephyr_boot || overall=1
run_layer M layer_m_scouting_multicast || overall=1
run_layer Z layer_z_zenohd_interop || overall=1

echo ""
# R311y414 — a `--layer <name>` that matches NO lane used to run nothing and
# exit 0: `run_layer` returns 0 for every non-matching name and no one asked
# afterwards whether ANY name had matched. That is the same "a gate reports
# success by silence" class this round exists to close, and the exposure grew
# with it (the new transport-modes job alone names 16 layer strings that must
# stay in sync across two files). An unmatched --layer is now a hard failure.
if [[ -n "$ONLY_LAYER" && "${LAYER_MATCHED:-0}" -ne 1 ]]; then
    echo "[$(_runci_ts)] ERROR run-ci: --layer '$ONLY_LAYER' matched no lane — nothing ran (typo, or the lane was renamed/removed)" >&2
    FAILED_LAYERS+=("--layer $ONLY_LAYER (no such lane)")
    overall=1
fi
if [[ $overall -eq 0 ]]; then
    echo "[$(_runci_ts)] INFO  run-ci: all required layers pass"
else
    # Name every failed lane so the verdict is unmissable regardless of how large
    # the log is or how it was captured — no hunting for a buried FAIL line.
    echo "[$(_runci_ts)] ERROR run-ci: ${#FAILED_LAYERS[@]} layer(s) FAILED: ${FAILED_LAYERS[*]}" >&2
    # Under GitHub Actions, ALSO surface the verdict + the actual failing lines as
    # a `::error` annotation. Annotations render in the run summary and the
    # `gh run view` ANNOTATIONS section even when `gh run view --log-failed`
    # returns EMPTY — a gh-CLI log-archive parsing gap that (R311y377) hid the
    # R311y376 Layer Z panic behind a bare "Process completed with exit code 1".
    # The body lifts the panic location + message (`-A1`), the per-test /
    # per-suite FAILED verdict lines, (R311y414) any lane's own
    # `  <LANE> FAIL: ...` diagnostic, AND (R311y417) actionlint's own
    # `.github/workflows/<f>:<line>:<col>: ...` finding lines — without that
    # last alternative a Layer 0 lint red produced a body reading only
    # "actionlint reported findings (see above)", i.e. it told the reader to
    # go do the very thing this annotation exists to spare them. ANSI-stripped and
    # %/newline-encoded for the annotation wire, so the reason is visible without
    # downloading the log. Gated on GITHUB_ACTIONS so a local pre-push run stays
    # plain text.
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
        _annot="see the full run log (gh api .../actions/jobs/<id>/logs)"
        if [[ -n "${RUNCI_LOG_FILE:-}" && -f "$RUNCI_LOG_FILE" ]]; then
            # Strip ANSI FIRST so the greps match uncolored text (robust even
            # under a non-default CARGO_TERM_COLOR=always), then lift the panic
            # location + its message (`-A1`), the per-test / per-suite FAILED
            # verdicts, AND cargo/clippy `error:` / `error[EXXXX]` lines so a
            # build/lint failure (no panic) is not left body-less. %/CR-encoded
            # for the wire. Keep the fallback body if extraction is empty.
            _extracted="$(sed 's/\x1b\[[0-9;]*m//g' "$RUNCI_LOG_FILE" \
                | grep -aE -A1 'panicked at|(--- |result: )FAILED|^error(\[|:)| FAIL: |^\.github/workflows/[^ ]+:[0-9]+:[0-9]+: ' \
                | sed 's/%/%25/g; s/\r//g; /^--$/d' \
                | tail -n 40 | awk 'BEGIN{ORS="%0A"}{print}')"
            [[ -n "$_extracted" ]] && _annot="$_extracted"
        fi
        echo "::error title=run-ci FAILED: ${FAILED_LAYERS[*]}::${_annot}"
    fi
fi
[[ -n "${RUNCI_LOG_FILE:-}" ]] && echo "run-ci: full log -> $RUNCI_LOG_FILE"
exit $overall

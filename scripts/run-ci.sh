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
#              before R291 caught it; the gate here prevents that
#              recurrence by failing pre-push if rustfmt would
#              reformat any tracked file.
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
#   WZ_RUN_LAYER_M=1 scripts/run-ci.sh # add the opt-in environment-flaky M lane
#
# Time cost (warm cache):
#   Layer 0: <2s   A: <1s   B: ~30s   C1: ~10s   C2: ~5s   D: <1s
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

# ─── production logging: complete, clean, leveled ──────────────────
# Force cargo/rustc to line-oriented, color-free, progress-bar-free output so a
# captured log is clean text in EVERY sink (tty / redirect / pipe): a `\r`
# progress-bar rewrite or ANSI colour escape corrupts a persisted log and
# defeats post-hoc grep. A caller's explicit value wins (the `:-` override).
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
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
    echo "[$(_runci_ts)] INFO  ──── Layer $name ────"
    local start=$SECONDS
    if "$@"; then
        echo "[$(_runci_ts)] INFO  Layer $name pass ($((SECONDS - start))s)"
        return 0
    else
        local rc=$?
        echo "[$(_runci_ts)] ERROR Layer $name FAIL (rc=$rc, $((SECONDS - start))s)" >&2
        FAILED_LAYERS+=("$name")
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
# actionlint and no lane invoked rustfmt at all. The mandatory
# fmt gate here is exactly the R64.1 single-source-of-truth
# invariant applied to rustfmt: the same gate fires locally
# (pre-push hook) and remotely (.github/workflows/ci.yml), so a
# fmt-dirty commit cannot reach origin/main again.
#
# actionlint stays optional (SKIP if not installed) — yaml workflow
# lint is a nice-to-have, not a correctness gate.
layer_0_preflight_lints() {
    # 0.1 cargo fmt --check across every workspace (mandatory). crates/ is
    # the primary workspace; each deploy/*/ that carries its OWN
    # `[workspace]` table is a standalone workspace the crates/ fmt --check
    # does not visit (R311be `mcu-qemu-demo`, R311hl `mcu-noheap-probe`,
    # R311iv `mcu-session-acceptor`). R311iw — these were enumerated one
    # `if`-block per crate, and the enumeration was forgotten for
    # mcu-session-acceptor (it shipped un-gated until R311iv caught a fmt
    # FAIL on a full run). Auto-discovery replaces the manual list so a NEW
    # standalone deploy workspace is fmt-gated the moment it exists — no
    # manual gate edit, no recurrence of the forgotten-enumeration gap.
    # R311y31 — also scan one level deeper (`deploy/*/*/`): the Zephyr deploy is
    # west/cmake-driven at deploy/zephyr-app/, with its Rust staticlib workspace
    # nested at deploy/zephyr-app/rust/. The extra glob keeps the auto-discovery
    # invariant ("any standalone deploy workspace is fmt-gated") for nested
    # layouts; it still only matches a dir that carries its OWN `[workspace]`.
    local fmt_dirs=(crates)
    local dpath
    for dpath in deploy/*/ deploy/*/*/; do
        [[ -f "${dpath}Cargo.toml" ]] || continue
        grep -q '^\[workspace\]' "${dpath}Cargo.toml" || continue
        fmt_dirs+=("${dpath%/}")
    done
    local fdir
    for fdir in "${fmt_dirs[@]}"; do
        if ! (cd "$fdir" && cargo fmt --all -- --check); then
            echo "  fmt --check FAIL ${fdir} — run \`(cd ${fdir} && cargo fmt --all)\`" >&2
            return 1
        fi
    done
    echo "  fmt --check OK (${fmt_dirs[*]})"

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
    echo "Layer B2 pass (committed out/** == regenerated)"
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
layer_c1t_cargo_test_serial() {
    (cd crates \
        && cargo test -p wz-session-core --features transport-link-serial --quiet \
        && cargo test -p wz-session-core --no-default-features --features transport-link-serial --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-serial --lib serial_pipeline --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-serial --test serial_pty_e2e --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-serial,transport-fragmentation --test serial_pty_e2e --quiet \
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
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-tls --test tls_e2e --test session_reconnect_e2e --test tls_pem_mtls_e2e --quiet \
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
layer_c1v_cargo_test_ws() {
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-ws --test ws_e2e --test session_reconnect_e2e --quiet \
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
layer_c1aa_cargo_test_unixsock() {
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-unixsock --lib unixsock_pipeline --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-unixsock --test unixsock_e2e --quiet \
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
layer_c1ac_cargo_test_quic() {
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-quic --test quic_e2e --quiet \
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
layer_c1ad_cargo_test_lowlatency() {
    (cd crates \
        && cargo test -p wz-session-core --features transport-lowlatency --lib extlowlatency --quiet \
        && cargo test -p wz-runtime-tokio --features transport-lowlatency,transport-unicast,transport-link-tcp --test lowlatency_e2e --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-lowlatency,transport-unicast,transport-link-tcp --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features transport-lowlatency --quiet -- -D warnings)
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
layer_c1bb_cargo_test_qos() {
    (cd crates \
        && cargo test -p wz-session-core --features transport-qos,transport-fragmentation,transport-batching,reassembly,session-multicast --lib --quiet \
        && cargo clippy -p wz-session-core --all-targets --features transport-qos,transport-fragmentation,transport-batching,reassembly,session-multicast --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features transport-fragmentation --quiet -- -D warnings \
        && cargo check -p wz-session-core --no-default-features --features transport-qos --quiet \
        && cargo clippy -p wz-session-core --all-targets --features transport-qos,transport-multilink,codec-push --quiet -- -D warnings \
        && cargo check -p wz-session-core --features transport-qos,transport-lowlatency --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-qos --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features transport-qos,transport-unicast,transport-link-tcp --test qos_e2e --quiet \
        && cargo test -p wz-runtime-tokio --features transport-qos,transport-lowlatency,transport-unicast --lib is_qos_negotiates_by_and_and_is_lowlatency_exclusive --quiet \
        && cargo test -p wz-runtime-tokio --features transport-qos,transport-multilink,transport-batching,codec-push,codec-close,transport-unicast --lib multilink:: --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-qos,transport-multilink,transport-batching,codec-push,codec-close,transport-unicast --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features routing-peer,transport-qos --lib linkstate --quiet \
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
layer_c1bc_cargo_test_mcast_qos() {
    (cd crates \
        && cargo test -p wz-session-core --features transport-qos,codec-push,session-multicast,pubsub-put --lib qos_emit_tests --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features transport-multicast,transport-link-udp,codec-push,pubsub-put,pubsub-allow-loop --lib multicast_publish_qos_stamps --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features transport-multicast,transport-link-udp,codec-push,transport-qos,pubsub-put,pubsub-allow-loop --lib multicast_publish_qos_stamps --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features transport-unicast,transport-multicast,transport-link-udp,codec-push,transport-qos,pubsub-put,pubsub-allow-loop,pubsub-priority --lib publish_with_priority_routes_multicast_conduit_band --quiet \
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
layer_c1bd_locator_iface() {
    (cd crates \
        && cargo test -p wz-session-core --lib locator::tests --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features locator-iface,transport-link-udp,transport-link-ws --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features locator-iface,transport-link-tls --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features locator-iface,transport-link-quic,transport-link-quic-datagram --quiet -- -D warnings \
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
layer_c1ae_cargo_test_compression() {
    (cd crates \
        && cargo test -p wz-session-core --features session-extcompression --lib compression --quiet \
        && cargo test -p wz-runtime-tokio --features session-extcompression,transport-unicast,transport-link-tcp --test compression_e2e --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features session-extcompression,transport-unicast,transport-link-tcp --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features transport-compression --quiet -- -D warnings)
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
    (cd crates \
        && cargo test -p wz-session-core --features routing-namespace,session-unicast,codec-push,codec-request,codec-response,codec-response-final,codec-declare,reassembly --lib namespace --quiet \
        && cargo clippy -p wz-session-core --features routing-namespace,session-unicast,codec-push,codec-request,codec-response,codec-response-final,codec-declare,reassembly --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features routing-namespace,session-unicast,codec-push --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --features routing-namespace,session-unicast,session-reconnect,declare-keyexpr,declare-subscriber,declare-queryable,declare-token,declare-interest --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --features routing-namespace,session-unicast,declare-keyexpr --all-targets --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features routing-namespace --test namespace_e2e --test namespace_query_e2e --test namespace_matching_e2e --test namespace_alias_e2e --quiet \
        && cargo test -p wz-runtime-tokio --features routing-namespace,transport-fragmentation --test namespace_reassembly_e2e --quiet \
        && cargo test -p wz-runtime-tokio --features routing-namespace,session-reconnect --test namespace_reconnect_e2e --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-namespace --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-namespace,transport-fragmentation --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-namespace,session-reconnect --quiet -- -D warnings \
        && cargo test -p wz-session-core --no-default-features --features routing-namespace,session-multicast,codec-join,codec-frame,codec-close,codec-push,codec-declare,codec-response,codec-response-final,liveliness-token,query-queryable,reassembly,pubsub-put --lib namespace --quiet \
        && cargo clippy -p wz-session-core --no-default-features --features routing-namespace,session-multicast,codec-join,codec-frame,codec-close,codec-push,codec-declare,codec-response,codec-response-final,liveliness-token,query-queryable,reassembly,pubsub-put --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features alloc,session-multicast,codec-join,codec-frame,codec-close,codec-push,codec-declare,codec-response,codec-response-final,liveliness-token,query-queryable,reassembly,pubsub-put --all-targets --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features transport-multicast,routing-namespace --lib multicast_glue --quiet \
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
    (cd crates \
        && cargo test -p wz-runtime-tokio --features routing-router-hat --lib router_forward --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features routing-router-hat --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features routing-router-hat,transport-qos --lib router_forward --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,transport-qos --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features routing-router-hat,access-acl --lib router_forward --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,access-acl,access-downsampling,access-quota --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features routing-router-hat,routing-token-tables --lib router_forward --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,routing-token-tables --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features routing-router-hat,transport-multicast --lib router_forward --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,transport-multicast --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features routing-token-tables --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-router-hat,router-connect-reconcile --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features router-connect-reconcile --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features routing-router-hat,adminspace-router-linkstate --lib router_forward --quiet \
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
layer_c1af_cargo_test_shm() {
    (cd crates \
        && cargo test -p wz-session-core --features session-extshm,codec-push --lib shm --quiet \
        && cargo test -p wz-runtime-tokio --features session-extshm,transport-unicast,transport-link-tcp --lib shm_provider --quiet \
        && cargo test -p wz-runtime-tokio --features session-extshm,transport-unicast,transport-link-tcp --test shm_e2e --quiet \
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
#   3. runs transport_compose_e2e (all three negotiated on one session; an SHM Put
#      shows the wire LAYERING compression(lean(shm-descriptor)) -- the 3-way
#      composition the single-mode e2e could not prove);
#   4. clippy-gates the combined three-feature cfg --all-targets (the only build
#      where all three data paths + the shared establish_capability_pair helper
#      compile together).
layer_c1ag_cargo_test_transport_compose() {
    (cd crates \
        && cargo test -p wz-session-core --features transport-lowlatency,session-extcompression,session-extshm --lib unit_ext --quiet \
        && cargo test -p wz-session-core --features transport-shm,codec-push,codec-declare,codec-response-final,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp --lib shm_put_with_no_resolver --quiet \
        && cargo test -p wz-runtime-tokio --features transport-lowlatency,session-extcompression,session-extshm,transport-unicast,transport-link-tcp --test transport_compose_e2e --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-lowlatency,session-extcompression,session-extshm,transport-unicast,transport-link-tcp --quiet -- -D warnings)
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
layer_c1ah_cargo_test_time_hlc() {
    (cd crates \
        && cargo test -p wz-runtime-tokio --features time-hlc --lib timestamp_source --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features time-hlc --quiet -- -D warnings \
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
            --features transport-unicast,liveliness-subscriber --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --no-default-features \
            --features transport-unicast,liveliness-subscriber --lib effective_history --quiet)
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
layer_c1aj_cargo_test_quic_datagram() {
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-quic-datagram --test quic_datagram_e2e --quiet \
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
layer_c1ak_cargo_test_transport_stats() {
    (cd crates \
        && cargo test -p wz-session-core --features transport-stats --lib stats --quiet \
        && cargo test -p wz-runtime-tokio --features transport-stats --test transport_stats_e2e --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features transport-stats --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --all-targets --features transport-stats --quiet -- -D warnings)
}

# ─── Layer C1al — unixpipe link: locator parse + FIFO-pair backend e2e ─
#
# R311y10: the named-FIFO-pair sibling of C1aa (unixsock). transport-link-unixpipe
# (OFF in the default set, Linux-only) carries a zenoh batch over a uplink +
# downlink FIFO pair using tokio's native pipe support — the SAME StreamEnvelope
# byte-stream framing as unixsock, reused unchanged. This lane:
#   1. runs the locator tests (the `unixpipe/<path>` parse is `AnyLocator::Unixpipe`
#      — ungated + platform-independent, like unixsock/vsock);
#   2. runs the `unixpipe_e2e` integration test (gated all(transport-link-unixpipe,
#      target_os="linux", transport-unicast)): two nodes reach Established over a
#      loopback FIFO pair — the initiator via a `unixpipe/...` LOCATOR — and a Put
#      is delivered byte-exact over the FIFO byte stream;
#   3. clippy-gates the `transport-link-unixpipe` cfg (`--all-targets`);
#   4. clippy-gates the LIB under `--no-default-features --features
#      transport-link-unixpipe` to prove `unixpipe_pipeline` composes standalone
#      (it pulls transport-link-tcp's shared stream_link + libc for mkfifo).
layer_c1al_cargo_test_unixpipe() {
    (cd crates \
        && cargo test -p wz-session-core --features alloc --lib locator --quiet \
        && cargo test -p wz-runtime-tokio --features transport-link-unixpipe --test unixpipe_e2e --quiet \
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
    (cd crates \
        && cargo test -p wz-runtime-tokio --no-default-features --features "$ML_FEATURES" --test session_multilink_e2e --quiet \
        `# R311y218 — qos x multilink composition: the qos-gated e2e proves the` \
        `# _with_multilink entrypoints negotiate is_qos over the 0x4 handshake` \
        `# (both-offer -> is_qos true; qos=false control -> false).` \
        && cargo test -p wz-runtime-tokio --no-default-features --features "$ML_FEATURES,transport-qos" --test session_multilink_e2e --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES" --test session_multilink_deploy_e2e --quiet \
        `# R311y219 — qos x multilink PRIORITY segregation over the DEPLOY path: the` \
        `# transport-qos deploy build activates the #[cfg(transport-qos)] priority` \
        `# test (an EXPRESS + a LOW Put ride DISTINCT physical links; the reliability` \
        `# tests stay green with the band inert). Runs BOTH deploy tests with qos on.` \
        && cargo test -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES,transport-qos" --test session_multilink_deploy_e2e --quiet \
        `# R311y212 slice-2 — the per-link AUTO-RE-ADD e2e: A's production peer_loop` \
        `# (max_links=2, dials B twice) re-dials + re-JOINs a link the harness kills` \
        `# on B, so a dropped dialed link comes back onto the SAME session. The count` \
        `# guard (grep ' 1 passed') reddens the lane if a feature-set edit ever` \
        `# cfg-outs the '#![cfg(all(...))]'-gated file to 0 tests (silent green).` \
        && cargo test -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES" --test session_multilink_readd_e2e --quiet 2>&1 | tee /dev/stderr | grep -q ' 1 passed' \
        && cargo test -p wz-runtime-tokio --no-default-features --features "$ML_FEATURES" --lib multilink --quiet \
        `# R311y219a — the per-face priority-band + reliability-axis POLICY unit` \
        `# tests live in accept_loop::tests (gated transport-multilink) inside the` \
        `# routing-accept/peer-gated module, so they need BOTH multilink AND the` \
        `# module gate to compile+run. No prior --lib lane combined them, so they` \
        `# were CI-invisible; ML_DEPLOY_FEATURES has both. The ' 2 passed' guard` \
        `# reddens the lane if a feature-set edit ever cfg-outs them to a silent 0.` \
        && cargo test -p wz-runtime-tokio --no-default-features --features "$ML_DEPLOY_FEATURES" --lib --quiet -- multilink_priority_range multilink_pref_for 2>&1 | tee /dev/stderr | grep -q ' 2 passed' \
        && cargo test -p wz-session-core --no-default-features --features alloc,transport-multilink,session-unicast,codec-push,codec-close --lib extmultilink --quiet \
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
        && cargo clippy -p wz-session-core --no-default-features --features alloc,transport-multilink,session-unicast,transport-keepalive --lib --quiet -- -D warnings \
        `# R311y211 invocation 5 — the ex-XOR coexistence proof: default features` \
        `# (which carry session-reconnect) + transport-multilink now COMPILE and the` \
        `# reset_for_reopen runtime guard preserves the survivor's shared SN. The` \
        `# 'grep 1 passed' asserts the test actually RAN ('cargo test <substring>'` \
        `# exits 0 on ZERO matches, so a future cfg-out would otherwise pass green);` \
        `# 'tee /dev/stderr' keeps the full cargo output in the CI log.` \
        && cargo test -p wz-runtime-tokio --features transport-multilink --lib reset_for_reopen_preserves_shared_sn_while_a_link_is_live --quiet 2>&1 | tee /dev/stderr | grep -q ' 1 passed' \
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
    (cd crates \
        && cargo test -p wz-session-core --features adminspace-metrics --lib adminspace --quiet \
        && cargo test -p wz-session-core --features adminspace-core --lib zid_hex --quiet \
        && cargo test -p wz-session-core --features storage-replication --lib zid_to_zenoh_hex --quiet \
        && cargo test -p wz-runtime-tokio --features adminspace-core,query-get --lib declare_adminspace --quiet \
        && cargo test -p wz-runtime-tokio --features adminspace-core,query-get --lib admin_write_permit --quiet \
        && cargo test -p wz-runtime-tokio --features adminspace-metrics,query-get --lib declare_adminspace --quiet \
        && cargo test -p wz-runtime-tokio --features adminspace-read,adminspace-metrics,query-get --lib declare_adminspace --quiet \
        && cargo test -p wz-runtime-tokio --features adminspace-write,query-get --lib admin_write_permit --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features adminspace-core,query-get --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features adminspace-metrics,query-get --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features adminspace-read,adminspace-metrics,query-get --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features adminspace-write,query-get --quiet -- -D warnings \
        && cargo test -p wz-session-core --features adminspace-introspection-handlers --lib adminspace --quiet \
        && cargo test -p wz-session-core --features adminspace-router-linkstate --lib adminspace --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-peer,adminspace-introspection-handlers --quiet -- -D warnings \
        && cargo test -p wz-session-core --features adminspace-plugins-handlers --lib adminspace --quiet \
        && cargo test -p wz-runtime-tokio --features adminspace-plugins-handlers,query-get --lib declare_adminspace --quiet \
        && cargo test -p wz-runtime-tokio --features adminspace-plugins-handlers,query-get --lib compiled_plugins --quiet \
        && cargo test -p wz-runtime-tokio --features adminspace-plugins-handlers,storage-backend,query-get --lib compiled_plugins --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-peer,adminspace-plugins-handlers,storage-backend --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-peer,adminspace-plugins-handlers --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features router-hat-router,adminspace-plugins-handlers,storage-backend --quiet -- -D warnings \
        && cargo test -p wz-session-core --features adminspace-config-hotreload --lib adminspace --quiet \
        && cargo test -p wz-runtime-tokio --features adminspace-config-hotreload --lib storage_manager_service --quiet \
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
    (cd crates \
        && cargo test -p wz-session-core --no-default-features --features adminspace-core --lib adminspace --quiet \
        && cargo clippy -p wz-session-core --no-default-features --features adminspace-core --all-targets --quiet -- -D warnings \
        && cargo test -p wz-session-core --no-default-features --features adminspace-router-linkstate --lib adminspace --quiet \
        && cargo clippy -p wz-session-core --no-default-features --features adminspace-router-linkstate --all-targets --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --no-default-features --features adminspace-core,query-get --lib declare_adminspace --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features adminspace-metrics,query-get --lib declare_adminspace --quiet \
        && cargo test -p wz-runtime-tokio --no-default-features --features adminspace-read,adminspace-metrics,query-get --lib declare_adminspace --quiet \
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
    (cd crates \
        && cargo test -p wz-runtime-tokio --features config-mutate-runtime,access-acl --lib wzconfig_ --quiet \
        && cargo test -p wz-runtime-tokio --features config-mutate-runtime,access-acl --lib to_admin_json --quiet \
        && cargo test -p wz-runtime-tokio --features config-mutate-runtime,access-acl,access-downsampling,access-quota --lib to_admin_json --quiet \
        && cargo test -p wz-runtime-tokio --features access-acl --lib wzconfig_reconfigure_is_inert --quiet \
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
    (cd crates \
        && cargo test -p wz-session-core --features ext-pubsub-serde-codec --lib serde_codec --quiet \
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
    (cd crates \
        && cargo test -p wz-runtime-tokio \
            --features ext-pubsub-advanced-publisher,query-get,pubsub-allow-loop \
            --lib advanced_ --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features ext-pubsub-advanced-publisher,query-get,pubsub-allow-loop \
            --quiet -- -D warnings \
        && cargo build -p wz --features ext-pubsub-advanced-publisher --quiet)
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
    (cd crates \
        && cargo test -p wz-runtime-tokio \
            --features ext-pubsub-advanced-subscriber,ext-pubsub-advanced-publisher,pubsub-allow-loop \
            --lib advanced_subscriber --quiet \
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
    (cd crates \
        && cargo test -p wz-runtime-tokio \
            --features ext-pubsub-advanced-recovery,ext-pubsub-advanced-publisher,pubsub-allow-loop \
            --lib advanced_subscriber --quiet \
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
    (cd crates \
        && cargo test -p wz-runtime-tokio \
            --features ext-pubsub-sample-miss-detection,ext-pubsub-advanced-recovery,pubsub-allow-loop \
            --lib advanced_publisher --quiet \
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
layer_c1av_cargo_test_ext_pubsub_advanced_history() {
    (cd crates \
        && cargo test -p wz-runtime-tokio \
            --features ext-pubsub-advanced-history,ext-pubsub-advanced-publisher,pubsub-allow-loop \
            --lib advanced_subscriber --quiet \
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
    (cd crates \
        && cargo test -p wz-session-core \
            --features ext-pubsub-group-membership \
            --lib group_membership --quiet \
        && cargo test -p wz-runtime-tokio \
            --features ext-pubsub-group-membership,pubsub-allow-loop \
            --lib group --quiet \
        && cargo clippy -p wz-session-core \
            --features ext-pubsub-group-membership --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets \
            --features ext-pubsub-group-membership,pubsub-allow-loop \
            --quiet -- -D warnings \
        && cargo build -p wz --features ext-pubsub-group-membership --quiet)
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
layer_c1w_cargo_test_routing_accept() {
    (cd crates \
        && cargo test -p wz-runtime-tokio --features routing-accept --lib accept_loop --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-accept --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features routing-accept --quiet -- -D warnings)
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
    (cd crates \
        && cargo clippy -p wz-session-core --features routing-routes --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features routing-routes --lib routing_forward --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-routes --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features routing-routes,transport-qos --lib routing_forward --quiet \
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
#      (preset-ap-full carries the features but is build-only).
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
layer_c1y_cargo_test_routing_peer() {
    local access="routing-peer,access-acl,access-downsampling,access-quota"
    (cd crates \
        && cargo test -p wz-runtime-tokio --features routing-peer --lib accept_loop --quiet \
        && cargo test -p wz-routing-graph --quiet \
        && cargo test -p wz-runtime-tokio --features routing-peer --lib linkstate --quiet \
        && cargo clippy -p wz-routing-graph --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --all-targets --features routing-peer --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features routing-peer --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features routing-peer --quiet -- -D warnings \
        && cargo clippy -p wz-ap-demo --all-targets --features routing-peer,adminspace-write --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features "$access" --lib interceptor --quiet \
        && cargo test -p wz-runtime-tokio --features "$access" --lib linkstate --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features "$access" --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features access-acl --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features access-downsampling --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --no-default-features --features access-quota --quiet -- -D warnings \
        && cargo test -p wz-session-core --features access-extauth-usrpwd --lib extauth --quiet \
        && cargo test -p wz-session-core --features access-extauth-usrpwd --lib auth_dispatch --quiet \
        && cargo clippy -p wz-session-core --all-targets --features access-extauth-usrpwd --quiet -- -D warnings \
        && cargo clippy -p wz-session-core --no-default-features --features session-extauth --all-targets --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features access-extauth-usrpwd --test usrpwd_handshake_e2e --quiet \
        && cargo clippy -p wz-runtime-tokio --all-targets --features access-extauth-usrpwd --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features access-extauth-pubkey --lib extauth_pubkey --quiet \
        && cargo test -p wz-runtime-tokio --features access-extauth-pubkey --test pubkey_handshake_e2e --quiet \
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
    (cd crates \
        && cargo test -p wz-session-core --features storage-backend --lib storage --quiet \
        && cargo test -p wz-session-core --features storage-mgr-multi-storage-host --lib storage --quiet \
        && cargo clippy -p wz-session-core --features storage-mgr-multi-storage-host --all-targets --quiet -- -D warnings \
        && cargo build -p wz --features storage-mgr-multi-storage-host --quiet \
        && cargo test -p wz-runtime-tokio --features storage-mgr-multi-storage-host,declare-subscriber,pubsub-allow-loop,storage-mgr-strip-prefix --lib storage_manager_service --quiet \
        && cargo clippy -p wz-runtime-tokio --features storage-mgr-multi-storage-host,declare-subscriber,pubsub-allow-loop,storage-mgr-strip-prefix --all-targets --quiet -- -D warnings \
        && cargo clippy -p wz-runtime-tokio --features storage-mgr-multi-storage-host --all-targets --quiet -- -D warnings \
        && cargo test -p wz-session-core --features storage-mgr-strip-prefix --lib storage_strip_prefix --quiet \
        && cargo clippy -p wz-session-core --features storage-mgr-strip-prefix --all-targets --quiet -- -D warnings \
        && cargo test -p wz-session-core --features storage-backend,storage-mgr-strip-prefix --lib storage --quiet \
        && cargo clippy -p wz-session-core --features storage-backend,storage-mgr-strip-prefix --all-targets --quiet -- -D warnings \
        && cargo test -p wz-session-core --features storage-history,storage-mgr-strip-prefix --lib storage --quiet \
        && cargo clippy -p wz-session-core --features storage-history,storage-mgr-strip-prefix --all-targets --quiet -- -D warnings \
        && cargo build -p wz --features storage-mgr-strip-prefix --quiet \
        && cargo test -p wz-session-core --features storage-mgr-wildcard-updates --lib storage --quiet \
        && cargo clippy -p wz-session-core --features storage-mgr-wildcard-updates --all-targets --quiet -- -D warnings \
        && cargo test -p wz-session-core --features storage-mgr-wildcard-updates,storage-mgr-strip-prefix --lib storage --quiet \
        && cargo clippy -p wz-session-core --features storage-mgr-wildcard-updates,storage-mgr-strip-prefix --all-targets --quiet -- -D warnings \
        && cargo build -p wz --features storage-mgr-wildcard-updates --quiet \
        && cargo test -p wz-session-core --features storage-aligner,storage-mgr-wildcard-updates --lib storage --quiet \
        && cargo clippy -p wz-session-core --features storage-aligner,storage-mgr-wildcard-updates --all-targets --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features storage-mgr-complete-flag --lib storage_service --quiet \
        && cargo clippy -p wz-runtime-tokio --features storage-mgr-complete-flag --all-targets --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features storage-backend,storage-mgr-strip-prefix,declare-subscriber,pubsub-allow-loop --lib storage_service --quiet \
        && cargo clippy -p wz-runtime-tokio --features storage-backend,storage-mgr-strip-prefix,declare-subscriber,pubsub-allow-loop --all-targets --quiet -- -D warnings \
        && cargo build -p wz --features storage-mgr-complete-flag --quiet \
        && cargo test -p wz-session-core --features storage-mgr-garbage-collection --lib storage --quiet \
        && cargo clippy -p wz-session-core --features storage-mgr-garbage-collection --all-targets --quiet -- -D warnings \
        && cargo test -p wz-runtime-tokio --features storage-mgr-garbage-collection --lib storage_gc_service --quiet \
        && cargo clippy -p wz-runtime-tokio --features storage-mgr-garbage-collection --all-targets --quiet -- -D warnings \
        && cargo build -p wz --features storage-mgr-garbage-collection --quiet \
        && cargo test -p wz-runtime-tokio --features storage-aligner --lib storage --quiet \
        && cargo test -p wz-runtime-tokio --features storage-aligner --test storage_aligner_convergence_e2e --quiet \
        && cargo test -p wz-runtime-tokio --features storage-history --lib storage --quiet \
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
        && cargo build -p wz-session-core --no-default-features --features codec-push,codec-declare,codec-request,codec-response,codec-response-final,query-queryable,query-reply,liveliness-token,liveliness-subscriber,declare-subscriber,declare-queryable,pubsub-put,pubsub-delete,pubsub-attachment,pubsub-timestamp,pubsub-source-info,query-attachment,query-selector-parameters,query-reply-err,query-source-info --quiet)
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
    (cd crates \
        && cargo test -p wz-session-core --features scouting-static --lib scout_static --quiet \
        && cargo test -p wz-runtime-tokio --features scouting-static --test static_scout_open --quiet \
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
    (cd crates \
        && cargo test -p wz-session-core --no-default-features --features alloc \
            --lib keyexpr_match --quiet \
        && cargo test -p wz-session-core --no-default-features \
            --features alloc,keyexpr-wildcard-single,keyexpr-wildcard-double,keyexpr-dollar-star,keyexpr-includes \
            --lib keyexpr_match --quiet \
        && cargo test -p wz-session-core --no-default-features \
            --features keyexpr-wildcard-single,keyexpr-wildcard-double,keyexpr-dollar-star,keyexpr-includes \
            --lib keyexpr_match --quiet)
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
layer_c1l_reassembly() {
    (cd crates \
        && cargo test -p wz-session-core --features reassembly --quiet \
        && cargo test -p wz-runtime-tokio --features reassembly --quiet \
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
layer_c1p_multicast() {
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
layer_c1q_multicast_glue() {
    (cd crates \
        && cargo test -p wz-runtime-tokio --features transport-multicast --lib multicast_glue --quiet) \
        && (cd crates \
            && cargo test -p wz-runtime-tokio \
                --features transport-multicast,reassembly --lib multicast_glue --quiet) \
        && (cd crates \
            && cargo test -p wz-runtime-tokio \
                --features transport-multicast,transport-fragmentation --lib multicast_glue --quiet)
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
layer_c1m_session_lwip() {
    (cd crates \
        && cargo test -p wz-session-lwip --quiet \
        && cargo test -p wz-session-lwip --features reassembly --quiet \
        && cargo test -p wz-session-lwip --features transport-multicast --quiet \
        && cargo test -p wz-session-lwip --features transport-multicast,codec-push --quiet \
        && cargo test -p wz-session-lwip --features transport-multicast,liveliness-token --quiet \
        && cargo test -p wz-session-lwip \
            --features transport-multicast,query-queryable,codec-response,codec-response-final \
            --quiet \
        && cargo test -p wz-session-lwip \
            --features transport-multicast,codec-push,codec-response,codec-response-final,liveliness-token,query-queryable \
            --quiet \
        && cargo test -p wz-session-lwip --features transport-multicast,reassembly --quiet \
        && cargo test -p wz-session-lwip \
            --features transport-multicast,transport-fragmentation,codec-push --quiet \
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
    (cd crates \
        && cargo test -p wz-mcu-session-acceptor --quiet \
        && cargo test -p wz-mcu-session-acceptor --features reassembly --quiet \
        && cargo test -p wz-mcu-session-acceptor --features buffer-pool-session-rx-slim --quiet \
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
layer_c1r_mcu_multicast_e2e() {
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
layer_c1s_runtime_tokio_multicast_tests() {
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
    local covered=(wz-runtime-tokio wz-session-core wz-ap-demo)

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
layer_c1bg_cargo_test_storage_backend_filesystem() {
    local out
    out="$(cd crates && cargo test -p wz-runtime-tokio \
        --features storage-backend-filesystem --lib filesystem_storage --quiet 2>&1)" \
        || { echo "$out"; return 1; }
    echo "$out"
    grep -qE 'test result: ok\. [1-9][0-9]* passed' <<< "$out" \
        || { echo "  C1bg FAIL: 0 filesystem_storage tests ran (filter matched nothing)"; return 1; }
    # R311y280 — the live-driver composition + durability proof (+ its discriminator).
    local comp
    comp="$(cd crates && cargo test -p wz-runtime-tokio \
        --features storage-mgr-multi-storage-host,storage-backend-filesystem,pubsub-allow-loop,declare-subscriber \
        --lib manager_restart --quiet 2>&1)" \
        || { echo "$comp"; return 1; }
    echo "$comp"
    grep -qE 'test result: ok\. [1-9][0-9]* passed' <<< "$comp" \
        || { echo "  C1bg FAIL: 0 manager_restart composition tests ran (filter matched nothing)"; return 1; }
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
    grep -qE 'test result: ok\. [1-9][0-9]* passed' <<< "$out" \
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
    local name feats expected got rc out
    while IFS=$'\t' read -r name feats; do
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

layer_e_ap_demo_round_trip() {
    if [[ ! -x target/zenoh-pico-cli/z_put || ! -x target/zenoh-pico-cli/z_sub || ! -x target/zenoh-pico-cli/z_sub_attachment || ! -x target/zenoh-pico-cli/z_pub_attachment ]]; then
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
    (cd crates && cargo test -p wz-integration-tests --quiet -- --ignored \
        --skip wz_e2e_ --skip multicast --skip zenohd --skip wz_router --skip wz_peer \
        --skip wz_storage_host)
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
    return $fail
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
        return $fail
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
        local mb_port mb_bin
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
# A1c adds the `multicast_pubsub_loopback` two-node pub/sub e2e (a
# publisher node's JOIN + framed Push reach a group-joined subscriber
# node's registry over a real socket); its deterministic logic twin is
# the C1q `multicast_glue` unit suite. R311ko widens that invocation
# with transport-fragmentation for the oversize-put e2e (publisher
# fragments at the group batch budget, subscriber reassembles).
layer_m_scouting_multicast() {
    if [[ "$ONLY_LAYER" != "M" && "${WZ_RUN_LAYER_M:-0}" -ne 1 ]]; then
        echo "Layer M SKIP (opt-in environment-flaky lane; --layer M or WZ_RUN_LAYER_M=1)"
        return 0
    fi
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
    # R311nm — wz->pico multicast JOIN+Push interop e2e: a wz in-library
    # multicast publisher's JOIN beacon + framed Push are admitted and
    # decoded by an external zenoh-pico `z_sub -m peer` over a real UDP
    # group. Binary-dep (needs the pico CLI built) AND environment-
    # dependent (multicast routing), so it lives here in the opt-in Layer
    # M, never the default Layer E sweep. Graceful SKIP when the pico CLI
    # is absent mirrors Layer E's prereq discipline so `--layer M` without
    # pico-CLI prep does not hard-fail.
    if [[ ! -x target/zenoh-pico-cli/z_sub ]]; then
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
    _z_unavailable "$1" || return 1
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
    (cd crates && cargo build -p wz-ap-demo --features ws,router-hat-router,routing-token-tables --quiet) || return 1
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
    # R4c — wz<->zenohd PUBKEY WIRE interop (needs zenohd + openssl, no plugin).
    # Stock zenohd cannot admit a pubkey client (known_keys_file is an
    # unimplemented upstream TODO -> Some(empty) lookup rejects all), so this
    # proves the achievable interop: zenohd DECODES wz's pubkey InitSyn and
    # rejects only at the lookup (wz's wire is canonical-router decodable).
    (cd crates && WZ_ZENOHD_BIN="$zenohd" cargo test -p wz-integration-tests \
        --test pubkey_zenohd_interop -- --ignored --quiet --test-threads=1) || return 1
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
    (cd crates && cargo build -p wz-ap-demo --features routing-peer,adminspace-write --quiet) || return 1
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
    if [[ -x target/zenoh-pico-cli/z_put ]]; then
        (cd crates && cargo test -p wz-integration-tests \
            --test wz_peer_adminspace_write_from_pico_zput -- --ignored --quiet) || return 1
    else
        _pico_cli_unavailable "Layer E6 (pico adminspace config-write z_put)" || return 1
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
layer_e6c_peer_multilink() {
    (cd crates && cargo build -p wz-ap-demo --features transport-multilink --quiet) || return 1
    (cd crates && cargo clippy -p wz-ap-demo --features transport-multilink --quiet -- -D warnings) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_multilink_aggregate -- --ignored --quiet) || return 1
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
layer_e6d_peer_multilink_qos() {
    (cd crates && cargo build -p wz-ap-demo --features transport-qos,transport-multilink --quiet) || return 1
    (cd crates && cargo clippy -p wz-ap-demo --features transport-qos,transport-multilink --quiet -- -D warnings) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_peer_multilink_qos_reach -- --ignored --quiet) || return 1
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
    (cd crates && cargo build -p wz-ap-demo --features router-hat-router,adminspace-router-linkstate --quiet) || return 1
    (cd crates && cargo test -p wz-integration-tests \
        --test wz_router_hat_mesh -- --ignored --quiet) || return 1
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

    local build_dir elf qlog qpid i fail=0
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
    for i in $(seq 1 350); do
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
    return $fail
}

# ─── dispatch ──────────────────────────────────────────────────────
overall=0
run_layer 0 layer_0_preflight_lints || overall=1
run_layer A layer_a_mnemosyne || overall=1
run_layer A2 layer_a2_audit_mid_values || overall=1
run_layer A3 layer_a3_audit_catalog_status || overall=1
run_layer A4 layer_a4_audit_crossimpl_proof || overall=1
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
run_layer C1w layer_c1w_cargo_test_routing_accept || overall=1
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
run_layer E layer_e_ap_demo_round_trip || overall=1
run_layer E2 layer_e2_facade_subset_e2e || overall=1
run_layer E3 layer_e3_router_multi_peer || overall=1
run_layer E4 layer_e4_router_reject || overall=1
run_layer E5 layer_e5_router_forward || overall=1
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
run_layer E8 layer_e8_router_hat_pico || overall=1
run_layer F layer_f_codec_footprint || overall=1
run_layer G layer_g_cross_compile_cortex_m || overall=1
run_layer Q layer_q_qemu_mcu_e2e || overall=1
run_layer Qz layer_qz_zephyr_boot || overall=1
run_layer M layer_m_scouting_multicast || overall=1
run_layer Z layer_z_zenohd_interop || overall=1

echo ""
if [[ $overall -eq 0 ]]; then
    echo "[$(_runci_ts)] INFO  run-ci: all required layers pass"
else
    # Name every failed lane so the verdict is unmissable regardless of how large
    # the log is or how it was captured — no hunting for a buried FAIL line.
    echo "[$(_runci_ts)] ERROR run-ci: ${#FAILED_LAYERS[@]} layer(s) FAILED: ${FAILED_LAYERS[*]}" >&2
fi
[[ -n "${RUNCI_LOG_FILE:-}" ]] && echo "run-ci: full log -> $RUNCI_LOG_FILE"
exit $overall

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Test-only fixtures + helpers for `wz-runtime-tokio`.
//!
//! R71 entry — replaces the `_test_support` Cargo feature that
//! previously gated these helpers inside the production crate. The
//! sibling-crate boundary is the encapsulation contract: production
//! consumers of `wz-runtime-tokio` cannot reach `fixture_session_init_params`
//! / `install_session_actions_for_test` / `dispatch_script` without
//! explicitly adding `wz-runtime-tokio-test-support` as a dev-dep,
//! and `wz-runtime-tokio`'s own production compile units no longer
//! carry the test-only code paths at all.
//!
//! R79 entry — SCE upstream commits `09906015` / `489e1922` deleted
//! `lua_engine_singleton` / `sce_rust_lua::register` and reshaped
//! every generated `Policy::new` to accept a per-instance
//! `Arc<dyn IScriptEngine>`. `install_session_actions_for_test`
//! now constructs a fresh `LuaEngine` per call, wires the 17
//! closures onto it, and returns the typed engine handle for the
//! caller to pass into `SessionFsmUnicastPolicy::new`. Each test
//! owns an independent engine — the cross-test namespace race
//! the R71b carry pointed at is gone by design.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sce_rust_lua::LuaEngine;
use sce_rust_runtime::scripting::{IScriptEngine, ScriptResult, ScriptValue};
use sce_rust_runtime::Hal;

use wz_runtime_tokio::session_glue::{
    install_session_actions, SessionInitParams, SessionLinkActions, SigningKey,
    REGISTERED_SCRIPT_NAMES, SESSION_ID,
};

/// Deterministic `SessionInitParams` matching the Layer 3 wire-interop
/// fixture inputs, so wire-byte assertions cross-reference cleanly
/// against the `layer3_init_body` fixture.
///
/// Production callers MUST source every field from `deploy.yaml` (or
/// another configured source); `SessionInitParams` intentionally does
/// not implement `Default` so a zero-filled construct cannot reach
/// the wire-encode path silently. This fixture lives in the
/// test-support crate so that production builds cannot accidentally
/// link against it.
pub fn fixture_session_init_params() -> SessionInitParams {
    SessionInitParams {
        version: 0x05,
        whatami: 0x02, // Peer
        zid: vec![0x01; 4],
        seq_num_res: 0,
        req_id_res: 0,
        batch_size: 0,
        lease: 10_000,
        lease_in_seconds: false,
        initial_sn: 0,
        cookie: Vec::new(),
        // Deterministic 32-byte test key. Production callers MUST
        // supply real per-process entropy via `SigningKey::new_random`.
        cookie_signing_key: SigningKey::new(vec![0xAB; 32])
            .expect("32-byte test key satisfies >= 32 invariant"),
    }
}

/// Build a fresh `LuaEngine`, wire `actions`'s 17 closures onto it
/// via the production `install_session_actions` path, and return the
/// typed engine handle.
///
/// The caller passes the returned handle into
/// `SessionFsmUnicastPolicy::new` so the same engine drives both the
/// SCE-generated state machine and the script-action dispatch — every
/// `execute_script` from the Policy resolves the 17 closures from the
/// engine's `global_functions` map (auto-injected into every session
/// the engine creates, including the Policy-side `session_N` id).
///
/// Each call yields an independent engine, so two concurrent
/// `#[test]` fns in the same binary cannot collide on a shared
/// namespace — the R71b cross-test race carry is resolved by SCE
/// upstream's per-instance DI rather than a watching-zenoh-side
/// workaround.
pub fn install_session_actions_for_test(
    actions: Arc<SessionLinkActions>,
) -> Arc<dyn IScriptEngine> {
    let engine: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
    install_session_actions(actions, &engine);
    engine
}

/// Direct dispatch shim — invoke a script-action by name on the
/// supplied engine without driving the generated state machine. The
/// `name` argument is debug-asserted to be a member of
/// `REGISTERED_SCRIPT_NAMES` so a typo fires loud at test time rather
/// than reaching the Lua engine as arbitrary source (which would be a
/// Lua injection surface in production, hence the test-support-only
/// placement).
///
/// Production callers MUST drive script-actions via
/// `Engine::process_event` — that path validates the action against
/// the generated SCXML's transition guards before invoking the Lua
/// closure, whereas this shim bypasses all of that for direct
/// codec-output / trace-counter assertions.
///
/// R79 — `script_engine` is now an explicit parameter (was implicit
/// via the retired `lua_engine_singleton`). Callers pass the same
/// engine they handed to `install_session_actions_for_test`.
pub fn dispatch_script(
    script_engine: &dyn IScriptEngine,
    name: &str,
) -> ScriptResult<ScriptValue> {
    debug_assert!(
        REGISTERED_SCRIPT_NAMES.contains(&name),
        "dispatch_script: '{name}' is not a registered script-action name; \
         production scripts must be drive via Engine::process_event"
    );
    script_engine.execute_script(SESSION_ID, &format!("{name}()"))
}

/// Process-global synthetic tick state backing [`TestHal`].
///
/// The atomic is `static` because `Hal` methods are associated (no
/// `&self`), so the impl can only reach this state via process-global
/// storage. Test code that needs isolated tick streams across
/// concurrently-running test binaries must put each test in its own
/// binary (`#[test]` fns in the same test binary share this state
/// and should run sequentially — `cargo test` defaults to multi-thread
/// per binary, so use `--test-threads=1` if a test asserts on the
/// initial tick value).
static TEST_HAL_TICK_MS: AtomicU64 = AtomicU64::new(0);

/// Zero-sized [`Hal`] impl whose `now_ticks_ms` reads from a
/// process-global `AtomicU64` the test advances by hand.
///
/// R116 entry — became viable when SCE upstream commit `fa3a2fda`
/// ("fix: route scheduler clock through Hal trait under std builds")
/// unified `SchedTimePoint` to `u64` ms and routed `sched_now()` /
/// `sched_now_plus()` through `<P::Hal as Hal>::now_ticks_ms()` on
/// both std and no_std profiles. Before that fix, a `TestHal` on the
/// std build was decorative: the SCE Engine's std path read
/// `Instant::now()` directly and the consumer's `Hal` impl had no
/// causal effect on scheduler resolution.
///
/// Usage pattern matches SCE's own regression test
/// (`sce-rust-runtime/tests/hal_clock_routing.rs`):
///
/// 1. Anchor the synthetic clock to a known epoch via [`test_hal_set_ticks`]
///    at test entry so the assertion baseline is independent of any
///    prior mutation in the same test binary.
/// 2. Construct an `Engine<P, TestHal>` (the policy's `type Hal`
///    associated type must resolve to `TestHal` — see
///    [`hal_timer_routing.rs`](../tests/hal_timer_routing.rs) for the
///    test-policy shape needed to opt in; the production session-FSM
///    policy emits `type Hal = StdHal` from the codegen template and
///    is not Hal-swappable today).
/// 3. Call `engine.schedule_event(Ev, Duration::from_secs(N), …)`
///    and assert `!engine.has_ready_events()` immediately (clock
///    hasn't advanced).
/// 4. Call [`test_hal_set_ticks`] / [`test_hal_advance_ticks`] to push
///    the synthetic clock past `ready_at`, then assert
///    `engine.has_ready_events()` — the scheduler's `pop_ready_event_at`
///    now sees the synthetic clock via `sched_now()`.
///
/// `wake()` is a no-op (matches `StdHal`'s single-threaded contract);
/// `irq_save` direct-passes the closure (matches `StdHal`'s `!Sync`
/// engine model — no critical section needed under std).
#[derive(Debug, Clone, Copy, Default)]
pub struct TestHal;

impl Hal for TestHal {
    fn now_ticks_ms() -> u64 {
        TEST_HAL_TICK_MS.load(Ordering::SeqCst)
    }
    fn wake() {}
    fn irq_save<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        f()
    }
}

/// Set the synthetic tick value backing [`TestHal::now_ticks_ms`].
///
/// Mirrors the `mock_set_ticks` helper in SCE's
/// `hal_clock_routing.rs`. Anchoring tests to a non-zero epoch at
/// entry (e.g. `test_hal_set_ticks(1_000_000)`) makes the assertion
/// baseline independent of any prior `test_hal_advance_ticks` call
/// in the same test binary — important because `cargo test` runs
/// `#[test]` fns multi-threaded by default and they share the
/// process-global atomic.
pub fn test_hal_set_ticks(ms: u64) {
    TEST_HAL_TICK_MS.store(ms, Ordering::SeqCst);
}

/// Advance the synthetic tick by `delta_ms` (relative to the current
/// value). Returns the new tick value.
///
/// Convenience over [`test_hal_set_ticks`] for the common "schedule
/// a 5s delay, advance 5_001 ms, assert ready" pattern.
pub fn test_hal_advance_ticks(delta_ms: u64) -> u64 {
    TEST_HAL_TICK_MS.fetch_add(delta_ms, Ordering::SeqCst) + delta_ms
}

/// Read the current synthetic tick. Mainly useful in assertions that
/// surface "advance_ticks went the wrong way" via the returned value
/// rather than via the indirect `has_ready_events` boolean.
pub fn test_hal_now_ticks() -> u64 {
    TEST_HAL_TICK_MS.load(Ordering::SeqCst)
}

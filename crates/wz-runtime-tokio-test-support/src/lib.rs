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

use std::sync::Arc;

use sce_rust_lua::LuaEngine;
use sce_rust_runtime::scripting::{IScriptEngine, ScriptResult, ScriptValue};

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

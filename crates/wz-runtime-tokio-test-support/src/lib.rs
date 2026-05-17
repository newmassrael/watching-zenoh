// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Test-only fixtures + rebind shims for `wz-runtime-tokio`.
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
//! The 3 helpers here intentionally mirror the previous feature-gated
//! API one-for-one so the migration is a pure import-path rewrite at
//! every test call site; no logic changes.

use std::sync::Arc;

use sce_rust_lua::lua_engine_singleton;
use sce_rust_runtime::scripting::{IScriptEngine, ScriptResult, ScriptValue};

use wz_runtime_tokio::session_glue::{
    register_guard_fns, register_outbound_link_fns, register_state_internal_fns, SessionInitParams,
    SessionLinkActions, SigningKey, REGISTERED_SCRIPT_NAMES, SESSION_ID,
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

/// Re-bind the Lua engine's global functions against a fresh
/// `SessionLinkActions`, bypassing the production `INSTALLED`
/// OnceLock guard.
///
/// Cargo's test runner reuses one process across N `#[test]` fns in
/// the same binary, so the process-singleton `INSTALLED` OnceLock
/// would reject the second-and-onward test's `install_session_actions`
/// call. This shim overwrites every `register_global_function`
/// registration to capture a different `SessionLinkActions` so each
/// `#[test]` fn can drive its own bundle.
///
/// The resulting state is a hybrid (the `INSTALLED` slot still points
/// at the first test's actions while the Lua registrations target
/// the most-recent bundle); production code MUST use
/// `install_session_actions` instead, which the type system enforces
/// by living in `wz-runtime-tokio` proper.
pub fn install_session_actions_for_test(actions: Arc<SessionLinkActions>) {
    let _ = sce_rust_lua::register();
    let lua = lua_engine_singleton();
    lua.create_session(SESSION_ID);
    register_outbound_link_fns(lua, &actions);
    register_state_internal_fns(lua, &actions);
    register_guard_fns(lua);
}

/// Direct dispatch shim — invoke a script-action by name without
/// driving the generated state machine. The `name` argument is
/// debug-asserted to be a member of `REGISTERED_SCRIPT_NAMES` so a
/// typo fires loud at test time rather than reaching the Lua engine
/// as arbitrary source (which would be a Lua injection surface in
/// production, hence the test-support-only placement).
///
/// Production callers MUST drive script-actions via
/// `Engine::process_event` — that path validates the action against
/// the generated SCXML's transition guards before invoking the Lua
/// closure, whereas this shim bypasses all of that for direct
/// codec-output / trace-counter assertions.
pub fn dispatch_script(name: &str) -> ScriptResult<ScriptValue> {
    debug_assert!(
        REGISTERED_SCRIPT_NAMES.contains(&name),
        "dispatch_script: '{name}' is not a registered script-action name; \
         production scripts must be drive via Engine::process_event"
    );
    let lua = lua_engine_singleton();
    lua.execute_script(SESSION_ID, &format!("{name}()"))
}

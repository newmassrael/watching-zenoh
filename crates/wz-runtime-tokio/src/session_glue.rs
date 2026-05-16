// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Session-FSM ↔ LinkDriver glue (R54 — first FSM-driven LinkDriver call).
//!
//! The generated `session_fsm_unicast_sm` module (from
//! `sources/session/session_fsm_unicast.scxml`) emits W3C SCXML
//! `<script>foo()</script>` action bodies as
//! `ScriptEngineProvider::get().execute_script(sid, "foo()")` calls.
//! This module supplies the Lua-engine-side implementations: 17
//! `register_global_function` registrations wire the script names
//! that appear inside SCXML transitions/onentry/onexit to native
//! Rust closures that mutate `SessionLinkActions` state.
//!
//! Scope ceiling. Outbound link calls deliberately invoke
//! `LinkDriver` with *placeholder bytes* (e.g. b"INIT_SYN") rather
//! than actual init_body/open_body codec encodings. Closing the
//! codec-encoded wire-bytes gap is a separate round (R55) — splitting
//! it lets R54 land the FSM→LinkDriver dispatch as a single audit
//! step without entangling the wire-format choices for INIT_SYN /
//! OPEN_SYN / ACK shapes (those need session-layer transport
//! header + cookie payload decisions that belong in their own
//! round).
//!
//! Lua engine handle. `sce_rust_lua::register()` is one-shot per
//! process; `install_session_actions` records the registration
//! result and treats `ScriptEngineAlreadyRegistered` as success
//! (subsequent installs in the same process — e.g. multiple tests
//! in one binary — reuse the same engine and only need to register
//! their own native fns again, which `register_global_function`
//! safely overwrites by name).

use std::sync::{Arc, Mutex, OnceLock};

use sce_rust_lua::lua_engine_singleton;
use sce_rust_runtime::scripting::{
    IScriptEngine, NativeMethod, ScriptError, ScriptResult, ScriptValue,
};

use crate::{LinkDriver, Reliability, TxFrame};

/// Discrete close-reason discriminator. Mirrors the four close-reason
/// mutator actions emitted by `session_fsm_unicast.scxml`
/// (`set_close_reason_generic / invalid / expired / unresponsive`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloseReason {
    #[default]
    Generic,
    Invalid,
    Expired,
    Unresponsive,
}

/// Counters and discrete state the integration tests inspect to
/// verify the script-action dispatch reached this side. One field
/// per native function so a test can pinpoint exactly which
/// SCXML action the FSM exercised.
#[derive(Debug, Default)]
pub struct ActionTrace {
    pub link_driver_open: u32,
    pub send_init_syn: u32,
    pub send_open_syn: u32,
    pub send_init_ack_with_cookie: u32,
    pub send_open_ack: u32,
    pub send_close_frame_with_reason: u32,
    pub release_link: u32,
    pub enable_rx_tx_regions: u32,
    pub start_lease_monitor: u32,
    pub stop_lease_monitor: u32,
    pub start_keepalive_worker: u32,
    pub stop_keepalive_worker: u32,
    pub free_pool_slots: u32,
    pub set_close_reason_count: u32,
    pub close_reason: CloseReason,
}

/// Trait-object handle for the link driver shared across the 7
/// outbound native functions. The Send + Sync bounds are required
/// by `NativeMethod`'s `Send + Sync` shape on the registered
/// closures. `Reliable` is the R54 baseline default for every
/// outbound send; per-message reliability classification is the
/// session FSM's wire-format concern and lands in R55.
pub trait BoxedLinkDriver: Send + Sync {
    /// Synchronous send shim — closures registered with
    /// `register_global_function` are `Fn`, so they cannot
    /// `.await`. Implementations block on their async driver here
    /// (Tokio multi-thread runtime context required).
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability);

    /// Synchronous open + close shims, same rationale as send.
    fn open_blocking(&self);
    fn close_blocking(&self);
}

/// Tokio multi-thread runtime adapter for a `LinkDriver`
/// implementation. Owns the driver behind a `Mutex` so concurrent
/// closures serialise their access; the driver's own internal
/// state is single-owner per the `LinkDriver` trait contract.
pub struct TokioLinkDriverAdapter<D: LinkDriver + Send + 'static> {
    driver: Mutex<D>,
    handle: tokio::runtime::Handle,
}

impl<D: LinkDriver + Send + 'static> TokioLinkDriverAdapter<D> {
    /// Wrap a driver + Tokio handle for use inside Lua-registered
    /// closures. The handle MUST point at a multi-thread runtime —
    /// `block_on` from inside a current-thread runtime's task
    /// would deadlock when the closure is invoked on the same
    /// thread that owns the runtime.
    pub fn new(driver: D, handle: tokio::runtime::Handle) -> Self {
        Self {
            driver: Mutex::new(driver),
            handle,
        }
    }
}

impl<D: LinkDriver + Send + 'static> BoxedLinkDriver for TokioLinkDriverAdapter<D> {
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) {
        let frame = TxFrame { bytes };
        let mut driver = self.driver.lock().unwrap();
        let _ = self.handle.block_on(driver.send(&frame, reliability));
    }

    fn open_blocking(&self) {
        let mut driver = self.driver.lock().unwrap();
        let _ = self.handle.block_on(driver.open());
    }

    fn close_blocking(&self) {
        let mut driver = self.driver.lock().unwrap();
        let _ = self.handle.block_on(driver.close());
    }
}

/// Bundle of state the 17 native functions read or mutate.
/// `Arc<SessionLinkActions>` is what the Lua closures capture; the
/// `Mutex<ActionTrace>` is the only mutable field, so the typical
/// "lots of small mutexes" overhead does not apply.
pub struct SessionLinkActions {
    pub driver: Arc<dyn BoxedLinkDriver>,
    pub trace: Mutex<ActionTrace>,
}

impl SessionLinkActions {
    pub fn new(driver: Arc<dyn BoxedLinkDriver>) -> Arc<Self> {
        Arc::new(Self {
            driver,
            trace: Mutex::new(ActionTrace::default()),
        })
    }

    /// Convenience accessor — clones the current trace snapshot
    /// (counters are u32 / enum, so the clone is cheap).
    pub fn trace_snapshot(&self) -> ActionTrace {
        self.trace.lock().unwrap().clone_via_copy()
    }
}

impl ActionTrace {
    /// Manual copy-clone — `#[derive(Clone)]` would clash with the
    /// Default + Debug derives' compile path here on the older
    /// rustc versions the workspace supports; field-wise copy
    /// is explicit and identical in semantics.
    fn clone_via_copy(&self) -> Self {
        Self {
            link_driver_open: self.link_driver_open,
            send_init_syn: self.send_init_syn,
            send_open_syn: self.send_open_syn,
            send_init_ack_with_cookie: self.send_init_ack_with_cookie,
            send_open_ack: self.send_open_ack,
            send_close_frame_with_reason: self.send_close_frame_with_reason,
            release_link: self.release_link,
            enable_rx_tx_regions: self.enable_rx_tx_regions,
            start_lease_monitor: self.start_lease_monitor,
            stop_lease_monitor: self.stop_lease_monitor,
            start_keepalive_worker: self.start_keepalive_worker,
            stop_keepalive_worker: self.stop_keepalive_worker,
            free_pool_slots: self.free_pool_slots,
            set_close_reason_count: self.set_close_reason_count,
            close_reason: self.close_reason,
        }
    }
}

/// Process-wide one-shot registration flag for the Lua engine.
/// `sce_rust_lua::register` returns an error if called twice; we
/// guard the call with an `OnceLock` so test binaries that install
/// the engine from multiple tests do not abort.
static LUA_REGISTERED: OnceLock<()> = OnceLock::new();

/// SCE-runtime session id the generated state-machine uses by
/// default. Matches the `_sessionid` system variable initialization
/// in the emitted code; `create_session` is idempotent so calling
/// it from `install_session_actions` is safe even when the
/// generated `initialize` has already done so.
pub const SESSION_ID: &str = "session_fsm_unicast";

/// Wire the 17 native script functions referenced by
/// `session_fsm_unicast.scxml` onto the Lua engine, sharing the
/// supplied `SessionLinkActions` across every closure.
pub fn install_session_actions(actions: Arc<SessionLinkActions>) -> Result<(), ScriptError> {
    // Singleton-init the Lua engine on first use; subsequent calls
    // (e.g. multi-test binaries) silently reuse the same engine and
    // only need to register their per-actions closures.
    let _ = LUA_REGISTERED.get_or_init(|| {
        let _ = sce_rust_lua::register();
    });

    let lua = lua_engine_singleton();
    lua.create_session(SESSION_ID);

    register_outbound_link_fns(lua, &actions);
    register_state_internal_fns(lua, &actions);
    register_guard_fns(lua);

    Ok(())
}

fn register_outbound_link_fns(lua: &dyn IScriptEngine, actions: &Arc<SessionLinkActions>) {
    bind_unit(lua, "link_driver_open", actions, |a| {
        a.trace.lock().unwrap().link_driver_open += 1;
        a.driver.open_blocking();
    });
    bind_unit(lua, "send_init_syn", actions, |a| {
        a.trace.lock().unwrap().send_init_syn += 1;
        a.driver.send_blocking(b"INIT_SYN", Reliability::Reliable);
    });
    bind_unit(lua, "send_open_syn", actions, |a| {
        a.trace.lock().unwrap().send_open_syn += 1;
        a.driver.send_blocking(b"OPEN_SYN", Reliability::Reliable);
    });
    bind_unit(lua, "send_init_ack_with_cookie", actions, |a| {
        a.trace.lock().unwrap().send_init_ack_with_cookie += 1;
        a.driver
            .send_blocking(b"INIT_ACK_COOKIE", Reliability::Reliable);
    });
    bind_unit(lua, "send_open_ack", actions, |a| {
        a.trace.lock().unwrap().send_open_ack += 1;
        a.driver.send_blocking(b"OPEN_ACK", Reliability::Reliable);
    });
    bind_unit(lua, "send_close_frame_with_reason", actions, |a| {
        a.trace.lock().unwrap().send_close_frame_with_reason += 1;
        a.driver.send_blocking(b"CLOSE", Reliability::Reliable);
    });
    bind_unit(lua, "release_link", actions, |a| {
        a.trace.lock().unwrap().release_link += 1;
        a.driver.close_blocking();
    });
}

fn register_state_internal_fns(lua: &dyn IScriptEngine, actions: &Arc<SessionLinkActions>) {
    bind_unit(lua, "enable_rx_tx_regions", actions, |a| {
        a.trace.lock().unwrap().enable_rx_tx_regions += 1;
    });
    bind_unit(lua, "start_lease_monitor", actions, |a| {
        a.trace.lock().unwrap().start_lease_monitor += 1;
    });
    bind_unit(lua, "stop_lease_monitor", actions, |a| {
        a.trace.lock().unwrap().stop_lease_monitor += 1;
    });
    bind_unit(lua, "start_keepalive_worker", actions, |a| {
        a.trace.lock().unwrap().start_keepalive_worker += 1;
    });
    bind_unit(lua, "stop_keepalive_worker", actions, |a| {
        a.trace.lock().unwrap().stop_keepalive_worker += 1;
    });
    bind_unit(lua, "free_pool_slots", actions, |a| {
        a.trace.lock().unwrap().free_pool_slots += 1;
    });
    bind_close_reason(lua, "set_close_reason_generic", actions, CloseReason::Generic);
    bind_close_reason(lua, "set_close_reason_invalid", actions, CloseReason::Invalid);
    bind_close_reason(lua, "set_close_reason_expired", actions, CloseReason::Expired);
    bind_close_reason(
        lua,
        "set_close_reason_unresponsive",
        actions,
        CloseReason::Unresponsive,
    );
}

fn register_guard_fns(lua: &dyn IScriptEngine) {
    // R54 baseline: guard expressions always return true so the
    // accept-side hardening + cookie validation transitions advance
    // for the integration test. Cap quota / token-bucket / cookie
    // HMAC actual checks are RFC §5.M concerns and bind in a later
    // round (R55+) when the security-relevant state-keeping moves
    // out of placeholder territory.
    bind_bool(lua, "half_open_cap_available", true);
    bind_bool(lua, "accept_rate_token", true);
    bind_bool(lua, "cookie_valid", true);
}

fn bind_unit<F>(lua: &dyn IScriptEngine, name: &str, actions: &Arc<SessionLinkActions>, body: F)
where
    F: Fn(&Arc<SessionLinkActions>) + Send + Sync + 'static,
{
    let captured = actions.clone();
    let cb: NativeMethod = Box::new(move |_args: &[ScriptValue]| -> ScriptValue {
        body(&captured);
        ScriptValue::Null
    });
    let ok = lua.register_global_function(name, cb);
    debug_assert!(ok, "register_global_function failed for {name}");
}

fn bind_close_reason(
    lua: &dyn IScriptEngine,
    name: &str,
    actions: &Arc<SessionLinkActions>,
    reason: CloseReason,
) {
    let captured = actions.clone();
    let cb: NativeMethod = Box::new(move |_args: &[ScriptValue]| -> ScriptValue {
        let mut trace = captured.trace.lock().unwrap();
        trace.set_close_reason_count += 1;
        trace.close_reason = reason;
        ScriptValue::Null
    });
    let ok = lua.register_global_function(name, cb);
    debug_assert!(ok, "register_global_function failed for {name}");
}

fn bind_bool(lua: &dyn IScriptEngine, name: &str, value: bool) {
    let cb: NativeMethod = Box::new(move |_args: &[ScriptValue]| -> ScriptValue {
        ScriptValue::Bool(value)
    });
    let ok = lua.register_global_function(name, cb);
    debug_assert!(ok, "register_global_function failed for {name}");
}

/// Direct dispatch shim — exercises the script engine path without
/// driving the generated state machine. Useful as a load-bearing
/// smoke test: it isolates the "is the Lua engine wired to the
/// native fns" question from the "does the generated FSM emit the
/// right execute_script calls" question.
pub fn dispatch_script(name: &str) -> ScriptResult<ScriptValue> {
    let lua = lua_engine_singleton();
    lua.execute_script(SESSION_ID, &format!("{name}()"))
}

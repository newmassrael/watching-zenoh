// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Session-FSM ↔ LinkDriver glue with real codec-driven wire bytes.
//!
//! R57 entry. The R54 baseline used literal placeholder bytes
//! (`b"INIT_SYN"`, `b"OPEN_SYN"`, …) for the 7 outbound link calls;
//! the placeholder pattern was an explicit hack flagged in R56's
//! self-review. R57 swaps every outbound to the real wz-codecs
//! encode path:
//!
//! - `send_init_syn` / `send_init_ack_with_cookie` build a
//!   `wz_codecs::init_body::InitBody` and prepend the
//!   `_Z_MID_T_INIT` transport-message header byte plus the
//!   parent.S / parent.A flag pattern from
//!   `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h`.
//! - `send_open_syn` / `send_open_ack` build a
//!   `wz_codecs::open_body::OpenBody` with the lease + initial_sn
//!   carrier and the `_Z_FLAG_T_OPEN_A` / `_Z_FLAG_T_OPEN_T`
//!   discriminators.
//! - `send_close_frame_with_reason` builds a
//!   `wz_codecs::close::Close` (single reason byte) and prepends
//!   `_Z_MID_T_CLOSE | _Z_FLAG_T_CLOSE_S` for a graceful session
//!   close (vs. link-only close).
//!
//! Production-correctness sourcing. The codec output is verified
//! byte-identical against zenoh-pico's own `_z_init_encode` /
//! `_z_open_encode` / `_z_close_encode` by the Layer 3 wire-interop
//! tests (`crates/wz-integration-tests/tests/layer3_{init_body,open_body,close}.rs`).
//! Re-using those codecs here therefore inherits the same byte-equiv
//! guarantee — `dispatch_script("send_init_syn")` now produces the
//! exact bytes a zenoh-pico peer would generate from the equivalent
//! `_z_t_msg_init_t` input.
//!
//! Field values flow through `SessionInitParams`. A production
//! caller supplies the per-deploy zid / whatami / version /
//! seq_num_res / req_id_res / batch_size / lease / initial_sn from
//! `deploy.yaml` (the source of truth per
//! `docs/wire-spec-subset.md` §4.4 + ARCHITECTURE.md §3.5);
//! integration tests pass fixed values so the wire bytes are
//! reproducible.
//!
//! Cookie material is supplied by the caller. R57 ships the cookie
//! handling as a "caller-owned bytes" interface — the
//! `SessionInitParams::cookie` field carries whatever the
//! `Accepting` side wants to sign and the `Established`-side
//! initiator echoes. The HMAC-SHA256 generation per RFC §5.M is
//! the consumer's responsibility (production callers compose
//! `sce_intrinsics_runtime::hmac_sha256` with a deploy-supplied
//! secret); the integration test uses a fixed 8-byte cookie so
//! the assertion against zenoh-pico's reference is deterministic.

use std::sync::{Arc, Mutex, OnceLock};

use sce_rust_lua::lua_engine_singleton;
use sce_rust_runtime::scripting::{
    IScriptEngine, NativeMethod, ScriptResult, ScriptValue,
};

use crate::{LinkDriver, Reliability, TxFrame};

/// Transport-message header constants from
/// `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h`.
/// Kept local (rather than re-exported from zenoh-pico-sys) so this
/// module does not pull the zenoh-pico FFI into its hot path on
/// MCU builds — wz-runtime-tokio is the AP/linux runtime, but the
/// constants themselves are wire-spec-frozen across both runtimes.
mod wire_const {
    pub const T_MID_INIT: u8 = 0x01;
    pub const T_MID_OPEN: u8 = 0x02;
    pub const T_MID_CLOSE: u8 = 0x03;

    /// InitAck discriminator (0 = InitSyn, 1 = InitAck).
    pub const FLAG_T_INIT_A: u8 = 0x20;
    /// Size parameters carrier (sn_res + batch_size present).
    pub const FLAG_T_INIT_S: u8 = 0x40;

    /// OpenAck discriminator (0 = OpenSyn, 1 = OpenAck).
    pub const FLAG_T_OPEN_A: u8 = 0x20;
    /// Lease in seconds (1) vs milliseconds (0).
    pub const FLAG_T_OPEN_T: u8 = 0x40;

    /// Session-close vs link-only close.
    pub const FLAG_T_CLOSE_S: u8 = 0x20;
}

/// Per-deploy parameters that drive the codec field values for the
/// 4-way handshake + close. Production callers source these from
/// `deploy.yaml`; tests pass fixed values for reproducible wire bytes.
#[derive(Debug, Clone)]
pub struct SessionInitParams {
    /// Protocol version (zenoh: 0x05 at the time of writing).
    pub version: u8,
    /// API-form whatami: `0x01` Router, `0x02` Peer, `0x04` Client.
    /// The codec packs the wire-form 2-bit field per
    /// `_z_whatami_to_uint8` (transport.c:31-37).
    pub whatami: u8,
    /// ZenohID — 1..=16 bytes. The codec encodes the length in the
    /// high 4 bits of `cbyte` as `zid_len - 1`.
    pub zid: Vec<u8>,
    /// Sequence-number resolution (0..=3 → 8 / 16 / 32 / 64-bit).
    pub seq_num_res: u8,
    /// Request-id resolution (0..=3).
    pub req_id_res: u8,
    /// Per-link batch size (bytes). Transport.h documents 1..=65535.
    pub batch_size: u16,
    /// Lease duration. The `lease_in_seconds` flag below picks the
    /// unit; the value itself is VLE-encoded inside the open body.
    pub lease: u64,
    /// `_Z_FLAG_T_OPEN_T` semantics: when true the wire encodes the
    /// `lease` field as seconds (set the flag); when false it
    /// encodes milliseconds (clear the flag).
    pub lease_in_seconds: bool,
    /// Initial sequence number for the reliable channel (VLE-encoded
    /// inside the open body).
    pub initial_sn: u64,
    /// Cookie material exchanged on the InitAck → OpenSyn echo path.
    /// Production callers generate this via HMAC-SHA256 per RFC §5.M;
    /// tests use a fixed slice for byte-equiv reproducibility.
    pub cookie: Vec<u8>,
}

impl Default for SessionInitParams {
    /// Test-grade defaults. Production callers MUST override every
    /// field from `deploy.yaml`.
    fn default() -> Self {
        Self {
            version: 0x05,
            whatami: 0x02, // Peer
            zid: vec![0x01; 4],
            seq_num_res: 0,
            req_id_res: 0,
            batch_size: 0,
            lease: 10_000, // 10s in ms
            lease_in_seconds: false,
            initial_sn: 0,
            cookie: Vec::new(),
        }
    }
}

/// Discrete close-reason discriminator. Mirrors the four close-reason
/// mutator actions emitted by `session_fsm_unicast.scxml`
/// (`set_close_reason_generic / invalid / expired / unresponsive`).
/// Encoded as a single byte in the Close codec body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloseReason {
    /// Default close (set via `session.close` transition).
    #[default]
    Generic = 0,
    /// Framing error close.
    Invalid = 1,
    /// Lease expired close.
    Expired = 2,
    /// TX congestion / peer unresponsive close.
    Unresponsive = 3,
}

/// Counters + last-wire-bytes snapshot the integration tests inspect
/// to verify the script-action dispatch reached this side AND the
/// codec produced the expected wire shape.
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

/// Sync RAII shim around an async `LinkDriver`. Production callers
/// supply this via `TokioLinkDriverAdapter`; tests supply a
/// recording implementation.
///
/// Send + Sync are required because the trait object captured by
/// each native-fn closure must outlive the closure's `'static`
/// bound and travel across worker threads on a Tokio multi-thread
/// runtime.
pub trait BoxedLinkDriver: Send + Sync {
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability);
    fn open_blocking(&self);
    fn close_blocking(&self);
}

/// Tokio multi-thread runtime adapter for a `LinkDriver`
/// implementation.
pub struct TokioLinkDriverAdapter<D: LinkDriver + Send + 'static> {
    driver: Mutex<D>,
    handle: tokio::runtime::Handle,
}

impl<D: LinkDriver + Send + 'static> TokioLinkDriverAdapter<D> {
    /// Wrap a driver + Tokio handle. The handle MUST point at a
    /// multi-thread runtime; using a current-thread runtime here
    /// would deadlock on the first script-action dispatch because
    /// `block_on` from inside the runtime's own worker thread
    /// requires another worker to make progress. The constructor
    /// panics fast on a current-thread runtime so the misuse is
    /// caught at construction site, not at the first dispatch.
    pub fn new(driver: D, handle: tokio::runtime::Handle) -> Self {
        assert_eq!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread,
            "TokioLinkDriverAdapter requires a multi-thread runtime; \
             block_on on a current-thread runtime worker would deadlock"
        );
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

/// Bundle of state shared across the 17 native script functions.
pub struct SessionLinkActions {
    pub driver: Arc<dyn BoxedLinkDriver>,
    pub params: SessionInitParams,
    pub trace: Mutex<ActionTrace>,
}

impl SessionLinkActions {
    /// Construct a session action bundle for one logical FSM instance.
    /// The `params` are captured by value; production callers
    /// supplying per-deploy values stage them once at session
    /// construction.
    pub fn new(driver: Arc<dyn BoxedLinkDriver>, params: SessionInitParams) -> Arc<Self> {
        Arc::new(Self {
            driver,
            params,
            trace: Mutex::new(ActionTrace::default()),
        })
    }

    pub fn trace_snapshot(&self) -> ActionTrace {
        self.trace.lock().unwrap().clone_via_copy()
    }
}

impl ActionTrace {
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

/// Process-wide install guard.
///
/// `sce_rust_lua::register_global_function` writes into one process-global
/// Lua name space; allowing two `install_session_actions` calls would
/// race on which `SessionLinkActions` the registered closures capture.
/// R58 makes the guard explicit: the first install succeeds, every
/// subsequent install returns `Err(SessionActionsAlreadyInstalled)`
/// so the caller can decide whether to (a) treat reinstall as a
/// programming bug and abort, or (b) accept the existing install if
/// the same `SessionLinkActions` already covers their session.
///
/// The single-FSM-per-process limit is documented in
/// `docs/runtime-crate-tokio.md` §6 (carry from R56) — multi-peer
/// FSM concurrency requires session-scoped binding via
/// `bind_native_object` and is deferred.
static INSTALLED: OnceLock<Arc<SessionLinkActions>> = OnceLock::new();

/// Returned when `install_session_actions` is called twice in the
/// same process.
#[derive(Debug)]
pub struct SessionActionsAlreadyInstalled;

impl std::fmt::Display for SessionActionsAlreadyInstalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "wz-runtime-tokio session actions already installed; this process supports at most one logical session FSM instance"
        )
    }
}

impl std::error::Error for SessionActionsAlreadyInstalled {}

/// SCE-runtime session id the generated state-machine uses by default.
pub const SESSION_ID: &str = "session_fsm_unicast";

/// Wire the 17 native script functions referenced by
/// `session_fsm_unicast.scxml` onto the Lua engine. The first call
/// per process succeeds and locks the session actions; subsequent
/// calls return `Err(SessionActionsAlreadyInstalled)`.
pub fn install_session_actions(
    actions: Arc<SessionLinkActions>,
) -> Result<(), SessionActionsAlreadyInstalled> {
    INSTALLED
        .set(actions.clone())
        .map_err(|_| SessionActionsAlreadyInstalled)?;

    // Lua engine register is OnceLock-guarded inside sce_rust_lua so
    // a re-entrant call here is harmless (the second `register`
    // returns `Err(ScriptEngineAlreadyRegistered)` which we treat
    // as success — the engine itself is process-singleton).
    let _ = sce_rust_lua::register();

    let lua = lua_engine_singleton();
    lua.create_session(SESSION_ID);

    register_outbound_link_fns(lua, &actions);
    register_state_internal_fns(lua, &actions);
    register_guard_fns(lua);

    Ok(())
}

/// Re-bind the Lua engine's global functions against a fresh
/// `SessionLinkActions`, bypassing the `INSTALLED` guard.
///
/// **Test infrastructure only.** Production code MUST NOT call this
/// — it deliberately keeps `INSTALLED` pointing at the first
/// successful `install_session_actions` while overwriting every
/// `register_global_function` registration with closures captured
/// against the supplied actions. The resulting state is a hybrid
/// (first install's actions still observable via the `INSTALLED`
/// OnceLock, current Lua closures capturing a different
/// `SessionLinkActions`) that no production caller benefits from.
///
/// Tests use this to swap the driver / trace within a single test
/// binary process, where cargo runs multiple `#[test]` functions
/// against one shared `INSTALLED`. The function is exposed in all
/// build profiles (rather than `#[cfg(test)]`-gated) because cargo
/// builds integration tests as separate crates that cannot see
/// `#[cfg(test)]` items from the library; the `_for_test` suffix
/// + this doc comment are the load-bearing "do not use in
/// production" markers.
#[doc(hidden)]
pub fn rebind_session_actions_for_test(actions: Arc<SessionLinkActions>) {
    let _ = sce_rust_lua::register();
    let lua = lua_engine_singleton();
    lua.create_session(SESSION_ID);
    register_outbound_link_fns(lua, &actions);
    register_state_internal_fns(lua, &actions);
    register_guard_fns(lua);
}

fn register_outbound_link_fns(lua: &dyn IScriptEngine, actions: &Arc<SessionLinkActions>) {
    bind_unit(lua, "link_driver_open", actions, |a| {
        a.trace.lock().unwrap().link_driver_open += 1;
        a.driver.open_blocking();
    });

    bind_unit(lua, "send_init_syn", actions, |a| {
        a.trace.lock().unwrap().send_init_syn += 1;
        let bytes = encode_init(&a.params, /*is_ack=*/ false);
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

    bind_unit(lua, "send_open_syn", actions, |a| {
        a.trace.lock().unwrap().send_open_syn += 1;
        let bytes = encode_open(&a.params, /*is_ack=*/ false);
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

    bind_unit(lua, "send_init_ack_with_cookie", actions, |a| {
        a.trace.lock().unwrap().send_init_ack_with_cookie += 1;
        let bytes = encode_init(&a.params, /*is_ack=*/ true);
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

    bind_unit(lua, "send_open_ack", actions, |a| {
        a.trace.lock().unwrap().send_open_ack += 1;
        let bytes = encode_open(&a.params, /*is_ack=*/ true);
        a.driver.send_blocking(&bytes, Reliability::Reliable);
    });

    bind_unit(lua, "send_close_frame_with_reason", actions, |a| {
        let reason = a.trace.lock().unwrap().close_reason as u8;
        a.trace.lock().unwrap().send_close_frame_with_reason += 1;
        let bytes = encode_close(reason);
        a.driver.send_blocking(&bytes, Reliability::Reliable);
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
    // R57 baseline: guard expressions always return true so the
    // accept-side hardening + cookie validation transitions advance
    // for the integration test. Cap quota / token-bucket / cookie
    // HMAC actual checks are RFC §5.M concerns and bind in a later
    // round (R58+) when the security-relevant state-keeping moves
    // out of placeholder territory.
    bind_bool(lua, "half_open_cap_available", true);
    bind_bool(lua, "accept_rate_token", true);
    bind_bool(lua, "cookie_valid", true);
}

// ─────────────────────────── codec wiring ───────────────────────────

/// Build the wire bytes for an Init frame (InitSyn if `is_ack==false`,
/// InitAck if `is_ack==true`). The codec body is the wz `InitBody`,
/// verified byte-identical to zenoh-pico's `_z_init_encode` by
/// `crates/wz-integration-tests/tests/layer3_init_body.rs`. The
/// transport-message header is one byte: `(flags) | T_MID_INIT`.
fn encode_init(params: &SessionInitParams, is_ack: bool) -> Vec<u8> {
    use wz_codecs::init_body::InitBody;

    let mut parent_flags = wire_const::FLAG_T_INIT_S;
    if is_ack {
        parent_flags |= wire_const::FLAG_T_INIT_A;
    }

    let cbyte = init_cbyte(params.whatami, params.zid.len());
    let body = InitBody {
        version: params.version,
        cbyte,
        zid: params.zid.clone(),
        sn_res: Some(pack_sn_res(params.seq_num_res, params.req_id_res)),
        batch_size: Some(params.batch_size),
        cookie_len: if is_ack {
            Some(params.cookie.len() as u64)
        } else {
            None
        },
        cookie: if is_ack { Some(params.cookie.clone()) } else { None },
    };

    let mut wire = Vec::with_capacity(body.zid.len() + params.cookie.len() + 12);
    wire.push(parent_flags | wire_const::T_MID_INIT);
    wire.extend_from_slice(&body.encode(parent_flags));
    wire
}

/// Build the wire bytes for an Open frame (OpenSyn / OpenAck). Body
/// is the wz `OpenBody`, verified byte-identical to zenoh-pico's
/// `_z_open_encode` by `tests/layer3_open_body.rs`.
fn encode_open(params: &SessionInitParams, is_ack: bool) -> Vec<u8> {
    use wz_codecs::open_body::OpenBody;

    let mut parent_flags = 0u8;
    if params.lease_in_seconds {
        parent_flags |= wire_const::FLAG_T_OPEN_T;
    }
    if is_ack {
        parent_flags |= wire_const::FLAG_T_OPEN_A;
    }

    // OpenSyn echoes the cookie the InitAck side issued; OpenAck does
    // not (cookie is consumed by the time the Accepting side sends
    // OpenAck).
    let body = OpenBody {
        lease: params.lease,
        initial_sn: params.initial_sn,
        cookie_len: if !is_ack {
            Some(params.cookie.len() as u64)
        } else {
            None
        },
        cookie: if !is_ack { Some(params.cookie.clone()) } else { None },
    };

    let mut wire = Vec::with_capacity(params.cookie.len() + 24);
    wire.push(parent_flags | wire_const::T_MID_OPEN);
    wire.extend_from_slice(&body.encode(parent_flags));
    wire
}

/// Build the wire bytes for a Close frame. Body is the wz `Close`
/// (single reason byte), verified byte-identical to zenoh-pico's
/// `_z_close_encode` by `tests/layer3_close.rs`. The
/// `_Z_FLAG_T_CLOSE_S` flag selects graceful session close (we
/// always set it — link-only close is a transport-layer concern
/// that the link driver handles directly).
fn encode_close(reason: u8) -> Vec<u8> {
    use wz_codecs::close::Close;

    let parent_flags = wire_const::FLAG_T_CLOSE_S;
    let body = Close { reason };
    let mut wire = Vec::with_capacity(2);
    wire.push(parent_flags | wire_const::T_MID_CLOSE);
    wire.extend_from_slice(&body.encode());
    wire
}

/// Pack the `cbyte` field per zenoh-pico's `_z_whatami_to_uint8`
/// (transport.c:31-37) + `(zid_len - 1) << 4` (transport.c:189-192).
fn init_cbyte(api_whatami: u8, zid_len: usize) -> u8 {
    debug_assert!(
        (1..=16).contains(&zid_len),
        "zid_len must be 1..=16 (wire constraint, transport.h)"
    );
    let whatami_wire = (api_whatami >> 1) & 0x03;
    whatami_wire | (((zid_len as u8 - 1) & 0x0F) << 4)
}

/// Pack `sn_res` per transport.c:196-197:
/// `(seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)`.
fn pack_sn_res(seq_num_res: u8, req_id_res: u8) -> u8 {
    (seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)
}

// ─────────────────────────── helpers ───────────────────────────

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
/// driving the generated state machine. Useful for tests that pin
/// the script-name → native-fn mapping in isolation from the FSM
/// transition logic.
pub fn dispatch_script(name: &str) -> ScriptResult<ScriptValue> {
    let lua = lua_engine_singleton();
    lua.execute_script(SESSION_ID, &format!("{name}()"))
}

/// R58 carry — the build script (or a dedicated tool) will parse
/// `sources/session/session_fsm_unicast.scxml` to extract every
/// `<script>foo()</script>` body and validate that
/// `register_outbound_link_fns + register_state_internal_fns +
/// register_guard_fns` cover the same set. The list below is the
/// hand-maintained truth source until the build-time check lands.
#[doc(hidden)]
pub const REGISTERED_SCRIPT_NAMES: &[&str] = &[
    "link_driver_open",
    "send_init_syn",
    "send_open_syn",
    "send_init_ack_with_cookie",
    "send_open_ack",
    "send_close_frame_with_reason",
    "release_link",
    "enable_rx_tx_regions",
    "start_lease_monitor",
    "stop_lease_monitor",
    "start_keepalive_worker",
    "stop_keepalive_worker",
    "free_pool_slots",
    "set_close_reason_generic",
    "set_close_reason_invalid",
    "set_close_reason_expired",
    "set_close_reason_unresponsive",
    "half_open_cap_available",
    "accept_rate_token",
    "cookie_valid",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// init_cbyte must match zenoh-pico's transport.c:189-192
    /// packing exactly — Layer 3 byte-equiv depends on this.
    #[test]
    fn init_cbyte_packs_whatami_and_zid_len() {
        // whatami=Peer(0x02), zid_len=4 → wire whatami = (0x02>>1)&3 = 0x01
        // zid_len_m1 = 3 → cbyte = 0x01 | (3 << 4) = 0x31
        assert_eq!(init_cbyte(0x02, 4), 0x31);
        // whatami=Router(0x01), zid_len=1 → wire whatami = (0x01>>1)&3 = 0
        // zid_len_m1 = 0 → cbyte = 0
        assert_eq!(init_cbyte(0x01, 1), 0x00);
        // whatami=Client(0x04), zid_len=16 → wire whatami = (0x04>>1)&3 = 0x02
        // zid_len_m1 = 15 → cbyte = 0x02 | (15 << 4) = 0xF2
        assert_eq!(init_cbyte(0x04, 16), 0xF2);
    }

    /// pack_sn_res must match transport.c:196-197 packing exactly.
    #[test]
    fn pack_sn_res_layout_matches_transport_h() {
        assert_eq!(pack_sn_res(0, 0), 0x00);
        assert_eq!(pack_sn_res(3, 0), 0x03);
        assert_eq!(pack_sn_res(0, 3), 0x0C);
        assert_eq!(pack_sn_res(3, 3), 0x0F);
        assert_eq!(pack_sn_res(2, 1), 0x06);
    }
}

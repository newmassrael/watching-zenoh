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
//! R311il entry — the engine-free session FSM migration retired the Lua
//! test helpers (`install_session_actions_for_test` / `dispatch_script`)
//! and the `sce-rust-lua` dependency. Tests build the engine-free engine
//! directly via `wz_runtime_tokio::session_glue::new_session_engine`
//! (`SessionFsmUnicastPolicy<SessionActionsBinding>`); this crate retains
//! the fixtures + link drivers + `TestHal` that the integration tests
//! consume.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use sce_rust_runtime::Hal;

use wz_runtime_tokio::session_glue::{BoxedLinkDriver, SessionInitParams, SigningKey};
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, TxFrame};

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
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        // Deterministic 32-byte test key. Production callers MUST
        // supply real per-process entropy via `SigningKey::new_random`.
        cookie_signing_key: SigningKey::new(vec![0xAB; 32])
            .expect("32-byte test key satisfies >= 32 invariant"),
    }
}

// The frame-recording `RecordingLinkDriver` + `recording_actions`
// builders that used to live here moved to `wz-runtime-tokio`'s
// crate-local `#[cfg(test)] mod test_fixtures`: they are consumed ONLY
// by that crate's own unit tests, and sourcing them across the
// dev-dependency cycle handed those tests a second `wz-runtime-tokio`
// copy whose `SessionLinkActions` `Session::new` rejects (and whose
// private methods are out of scope). This sibling now holds only the
// fixtures the INTEGRATION tests (`tests/*.rs`) consume:
// `fixture_session_init_params` (a shared `wz-session-core` return type,
// safe across the cycle), `LifecycleRecordingDriver`,
// `install_session_actions_for_test`, `dispatch_script`, and `TestHal`.

/// Test [`BoxedLinkDriver`] that counts `open_blocking` / `close_blocking`
/// calls *in addition to* recording every outbound frame. This is the
/// second driver shape the runtime tests need — handshake / lifecycle
/// tests assert the FSM drove the link through open → sends → close in
/// the right order, which the no-op-open/close [`RecordingLinkDriver`]
/// cannot observe.
///
/// SSOT home for the `RecordingDriver { opens, closes, sends }` shape
/// that was copy-pasted byte-identically across
/// `tests/session_fsm_engine_drive.rs`, `tests/session_fsm_full_path.rs`,
/// and `tests/session_glue_dispatch.rs` (plus a send-count-only variant
/// in `tests/session_fsm_coverage.rs`). Consolidating it here removes
/// the four duplicates.
#[derive(Default)]
pub struct LifecycleRecordingDriver {
    inner: Mutex<LifecycleState>,
}

#[derive(Default)]
struct LifecycleState {
    opens: u32,
    closes: u32,
    sends: Vec<(Vec<u8>, Reliability)>,
}

/// Immutable snapshot of a [`LifecycleRecordingDriver`]'s observed state.
/// A test binds this once via [`LifecycleRecordingDriver::snapshot`] and
/// reads multiple fields without re-locking — the field names/types mirror
/// the inline `RecordingState` the tests/ files previously defined, so the
/// assertion bodies (`snap.opens`, `snap.sends[i].0`, …) are unchanged.
pub struct LifecycleSnapshot {
    /// `open_blocking` call count.
    pub opens: u32,
    /// `close_blocking` call count.
    pub closes: u32,
    /// Every `send_blocking` frame in emission order: (bytes, reliability).
    pub sends: Vec<(Vec<u8>, Reliability)>,
}

impl LifecycleRecordingDriver {
    /// Take an immutable snapshot of the observed open/close/send state.
    pub fn snapshot(&self) -> LifecycleSnapshot {
        let s = self.inner.lock().expect("lifecycle driver poisoned");
        LifecycleSnapshot {
            opens: s.opens,
            closes: s.closes,
            sends: s.sends.clone(),
        }
    }
}

impl BoxedLinkDriver for LifecycleRecordingDriver {
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) {
        self.inner
            .lock()
            .expect("lifecycle driver poisoned")
            .sends
            .push((bytes.to_vec(), reliability));
    }
    fn open_blocking(&self) {
        self.inner.lock().expect("lifecycle driver poisoned").opens += 1;
    }
    fn close_blocking(&self) {
        self.inner.lock().expect("lifecycle driver poisoned").closes += 1;
    }
}

/// Inert no-op outbound [`BoxedLinkDriver`]. `SessionLinkActions::new`
/// requires an outbound driver for the Lua-closure capture path, but
/// scenarios that drive the inbound side independently (or assert only
/// on lifecycle / FSM state) never inspect its output. Callers
/// construct it via `NoopOutboundDriver::default()`.
///
/// SSOT home for the byte-identical no-op driver previously copy-pasted
/// across five `tests/session_fsm_*.rs` files (lease_deadline,
/// accepting_path, handshake_timeout, driver_loop, drive_session).
#[derive(Default)]
pub struct NoopOutboundDriver {
    _state: Mutex<()>,
}

impl BoxedLinkDriver for NoopOutboundDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) {}
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

/// Scripted async [`LinkDriver`] that replays a fixed `LinkEvent` queue
/// from `poll_event`, returning `Lost { PeerClosed }` once the queue
/// drains. `open` / `send` / `close` are inert `Ok(())`.
///
/// SSOT home for the byte-identical queue driver previously copy-pasted
/// across three `tests/session_fsm_*.rs` files (accepting_path,
/// driver_loop, drive_session).
pub struct QueueDriver {
    events: VecDeque<LinkEvent>,
}

impl QueueDriver {
    /// Build a driver that yields `events` in order from `poll_event`.
    pub fn with(events: Vec<LinkEvent>) -> Self {
        Self {
            events: events.into(),
        }
    }
}

impl LinkDriver for QueueDriver {
    async fn open(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        Ok(())
    }
    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn poll_event(&mut self) -> LinkEvent {
        self.events.pop_front().unwrap_or(LinkEvent::Lost {
            cause: LostCause::PeerClosed,
        })
    }
}

// R311il — `install_session_actions_for_test` and the `dispatch_script`
// shim were retired with the engine-free session FSM migration. Tests now
// build the engine directly via the production
// `wz_runtime_tokio::session_glue::new_session_engine(&actions)` (the
// engine-free `SessionFsmUnicastPolicy<SessionActionsBinding>` — no
// `LuaEngine` / `IScriptEngine`), and exercise individual actions by
// calling the native `SessionFsmUnicastActions` trait methods on a
// `SessionActionsBinding` rather than dispatching Lua by name.

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

/// R311of — the loopback TLS config pair: one self-signed `localhost` cert the
/// server presents and the client trusts (added to a fresh root store). The
/// SSOT for every wz-runtime-tokio TLS e2e — `tls_e2e`, the scouting
/// `round3_tls` module, and the `session_reconnect_e2e` `tls_reconnect` module
/// — which previously copy-pasted this 26-line cert-generation block. Both
/// configs pin the `ring` crypto provider explicitly so the test does not
/// depend on a process-default provider being installed. Returns pure rustls
/// types and touches no wz type, so it carries no wz-runtime-tokio feature;
/// the `tls-fixtures` gate keeps rustls/rcgen out of the other 6 consumers of
/// this crate. The caller builds its own `ServerName` for the dial side.
#[cfg(feature = "tls-fixtures")]
pub fn loopback_tls_configs() -> (
    std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
    std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
) {
    use std::sync::Arc;
    use tokio_rustls::rustls::crypto::ring;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_der: CertificateDer<'static> = issued.cert.der().clone();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.key_pair.serialize_der()));

    let provider = Arc::new(ring::default_provider());

    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("server default protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server single cert");

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).expect("trust the self-signed cert");
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

    (Arc::new(server_config), Arc::new(client_config))
}

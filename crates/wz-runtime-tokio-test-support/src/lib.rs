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

use wz_runtime_tokio::session_glue::{BoxedLinkDriver, SessionInitParams, SigningKey, WhatAmI};
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};

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
        whatami: WhatAmI::Peer,
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

/// The zenoh-1.5.0 INTEROP wire-negotiation profile, parameterized on the two
/// fields that legitimately vary per caller: `whatami` (the role the opener
/// presents) and `zid` (its identity). The remaining eight fields are the
/// negotiation shape a STRICT zenoh peer accepts at InitSyn — `version: 0x09`,
/// a real `batch_size: 65535`, and `seq_num_res`/`req_id_res = 2` — the shape
/// `wz-ap-demo`'s initiator path uses. This differs from
/// [`fixture_session_init_params`], whose `version: 0x05` / `batch_size: 0` are
/// wz<->wz internal-test values a strict zenohd rejects at InitSyn.
///
/// This is the SSOT for that profile: the in-process zenohd storage-replication
/// interop e2e (a `Client` dialing a router — [`zenohd_interop_session_init_params`])
/// and the `wz-e2e-*` acceptor scaffolding (a `Peer` accepting one peer) both
/// derive their `SessionInitParams` from this ONE builder rather than each
/// re-declaring the eight shared negotiation fields inline. (`wz-ap-demo`'s
/// `demo_session_init_params` is `pub(crate)` to that binary, so it cannot be
/// the shared source for an in-process or cross-crate test.)
pub fn zenoh_interop_session_init_params(whatami: WhatAmI, zid: Vec<u8>) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami,
        zid,
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        // Deterministic 32-byte test key (same discipline as the fixture).
        cookie_signing_key: SigningKey::new(vec![0xAB; 32])
            .expect("32-byte test key satisfies >= 32 invariant"),
    }
}

/// Session-open params for dialing a REAL zenoh 1.5.0 router (zenohd or any
/// foreign zenoh peer) in-process — the `Client`-role projection of
/// [`zenoh_interop_session_init_params`]. Used by the in-process zenohd
/// storage-replication interop e2e (and any future cross-impl test that opens a
/// `Session` in-process against a foreign peer).
pub fn zenohd_interop_session_init_params() -> SessionInitParams {
    zenoh_interop_session_init_params(WhatAmI::Client, vec![0x0c, 0x0a, 0x10, 0x00])
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

/// Which deterministic perturbation a [`ChaosReadDriver`] applies to the
/// targeted (Nth-matching) inbound frame.
enum ChaosAction {
    /// Swallow the targeted frame (a single-datagram loss / gap).
    Drop,
    /// Re-emit the targeted frame once, immediately after the original — a
    /// duplicate-delivery (the lossy-link / malicious-peer hazard the R311oo
    /// reassembly fix defends against).
    Duplicate,
    /// Delay the targeted frame by one position — emit the frame that follows
    /// it first, then the held target (an adjacent swap, the out-of-order
    /// delivery a multi-path / racing link produces).
    Reorder,
}

/// A [`LinkDriver`] decorator applying a DETERMINISTIC perturbation to one
/// frame of the inbound stream: it targets the `ordinal`-th (1-based) frame
/// for which the caller's predicate returns true and either DROPS it
/// ([`ChaosReadDriver::drop_nth_matching`]), DUPLICATES it
/// ([`ChaosReadDriver::duplicate_nth_matching`]), or REORDERS it past its
/// successor ([`ChaosReadDriver::reorder_nth_matching`]), passing every other
/// event through. The schedule is a fixed counter — NO RNG — so a chaos
/// scenario reproduces byte-for-byte every run (the no-flaky contract).
///
/// MECHANISM vs POLICY split: the decorator owns only the count + perturb
/// mechanism; the caller's predicate decides which frame is the candidate.
/// So transport-specific wire knowledge (e.g. decoding a UDP datagram's
/// transport MID to recognise a fragment) stays in the test, never baked into
/// this reusable mechanism — the same decorator perturbs frames on a stream
/// (length-prefixed) and a datagram link alike. Wrap a link AFTER its
/// handshake so only the steady-state stream is perturbed.
///
/// `dropped` / `duplicated` / `reordered` are `pub` so a test reads them after
/// the drive completes to assert the perturbation was actually injected, not
/// merely inferred from a delivery outcome.
pub struct ChaosReadDriver<D, P> {
    inner: D,
    predicate: P,
    ordinal: usize,
    action: ChaosAction,
    matched: usize,
    /// A held event re-emitted on a subsequent `poll_event`: the duplicate
    /// copy (Duplicate), or the delayed target / the event that overtook it
    /// (Reorder). Held as a `LinkEvent` (not an `RxFrame`) so the Reorder edge
    /// case — a terminal event following the target — can be stashed too.
    pending: Option<LinkEvent>,
    /// Count of frames actually swallowed (0 or 1 for a single-ordinal plan).
    pub dropped: usize,
    /// Count of frames re-emitted as a duplicate (0 or 1 for a single ordinal).
    pub duplicated: usize,
    /// Count of frames delayed past their successor (0 or 1 for a single ordinal).
    pub reordered: usize,
}

impl<D, P> ChaosReadDriver<D, P>
where
    D: LinkDriver,
    P: FnMut(&RxFrame) -> bool,
{
    fn new(inner: D, ordinal: usize, predicate: P, action: ChaosAction) -> Self {
        Self {
            inner,
            predicate,
            ordinal,
            action,
            matched: 0,
            pending: None,
            dropped: 0,
            duplicated: 0,
            reordered: 0,
        }
    }

    /// Drop the `drop_ordinal`-th (1-based) inbound frame matching
    /// `should_drop`. `drop_ordinal == 0` is a pass-through (no 1-based
    /// ordinal equals 0), useful as a chaos-disabled control.
    pub fn drop_nth_matching(inner: D, drop_ordinal: usize, should_drop: P) -> Self {
        Self::new(inner, drop_ordinal, should_drop, ChaosAction::Drop)
    }

    /// Re-emit the `dup_ordinal`-th (1-based) inbound frame matching
    /// `should_duplicate` once more, immediately after the original — modelling
    /// a link that delivers a frame twice. `dup_ordinal == 0` is a pass-through.
    pub fn duplicate_nth_matching(inner: D, dup_ordinal: usize, should_duplicate: P) -> Self {
        Self::new(inner, dup_ordinal, should_duplicate, ChaosAction::Duplicate)
    }

    /// Delay the `reorder_ordinal`-th (1-based) inbound frame matching
    /// `should_reorder` past the single frame that follows it — an adjacent
    /// swap (`.. T S ..` -> `.. S T ..`), modelling out-of-order delivery. If a
    /// terminal event (`Lost`) follows the target, it cannot be reordered past
    /// it and the target emits in place. `reorder_ordinal == 0` is a
    /// pass-through.
    pub fn reorder_nth_matching(inner: D, reorder_ordinal: usize, should_reorder: P) -> Self {
        Self::new(inner, reorder_ordinal, should_reorder, ChaosAction::Reorder)
    }
}

impl<D, P> LinkDriver for ChaosReadDriver<D, P>
where
    D: LinkDriver,
    P: FnMut(&RxFrame) -> bool,
{
    async fn open(&mut self) -> io::Result<()> {
        self.inner.open().await
    }

    async fn send(&mut self, frame: &TxFrame<'_>, reliability: Reliability) -> io::Result<()> {
        self.inner.send(frame, reliability).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }

    async fn poll_event(&mut self) -> LinkEvent {
        // Re-emit a held event (a duplicate copy, or a reorder's delayed
        // target / overtaking event) before polling the inner driver, so it
        // lands in the right relative position. Cancel-safe — `pending` is
        // owned state set without an intervening await, so a `select!` cancel
        // here loses only the wake.
        if let Some(event) = self.pending.take() {
            return event;
        }
        loop {
            let event = self.inner.poll_event().await;
            if let LinkEvent::Rx(frame) = &event {
                if (self.predicate)(frame) {
                    self.matched += 1;
                    if self.matched == self.ordinal {
                        match self.action {
                            ChaosAction::Drop => {
                                // Deterministic single drop: swallow this frame
                                // and poll for the next. Cancel-safe — the inner
                                // driver owns any partial-read state, and a
                                // datagram recv is atomic, so a `select!` cancel
                                // here loses only the wake, never wire bytes.
                                self.dropped += 1;
                                continue;
                            }
                            ChaosAction::Duplicate => {
                                // Stash an owned copy to re-emit on the next
                                // poll, then return this one now. `reclone_rx`
                                // avoids requiring `RxFrame: Clone` on the
                                // production type (keeping the owned ->
                                // borrowed `RxFrame<'pool>` migration note in
                                // `link.rs` unconstrained).
                                self.duplicated += 1;
                                self.pending = Some(LinkEvent::Rx(reclone_rx(frame)));
                                return event;
                            }
                            ChaosAction::Reorder => {
                                // Delay the target by one: hold it, emit the
                                // event that follows it first, then the held
                                // target on the next poll. If a terminal event
                                // (Lost) follows, the target cannot be reordered
                                // past it — emit the target now and stash the
                                // terminal. The single inner poll below adds no
                                // await between holding and returning beyond the
                                // recv itself, so a cancel loses only a wake.
                                self.reordered += 1;
                                let held = LinkEvent::Rx(reclone_rx(frame));
                                let next = self.inner.poll_event().await;
                                if matches!(next, LinkEvent::Rx(_)) {
                                    self.pending = Some(held);
                                    return next;
                                }
                                self.pending = Some(next);
                                return held;
                            }
                        }
                    }
                }
            }
            return event;
        }
    }
}

/// Reconstruct an owned copy of an [`RxFrame`] from its public fields. The
/// [`ChaosReadDriver`] duplicate path holds and re-emits a copy of a matched
/// frame; doing it through the `RxFrame` constructors (rather than a `Clone`
/// derive) keeps the production type free of a `Clone` capability that the
/// planned owned -> borrowed `RxFrame<'pool>` zero-copy migration would have to
/// preserve or break.
fn reclone_rx(frame: &RxFrame) -> RxFrame {
    match frame.src {
        Some(src) => RxFrame::with_src(frame.bytes.clone(), src),
        None => RxFrame::new(frame.bytes.clone()),
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

/// R311og — the loopback mutual-TLS (mTLS) PEM material, returned as PEM
/// strings so a test feeds them through the PRODUCTION
/// `wz_runtime_tokio::tls_config::{server_config_from_pem, client_config_from_pem}`
/// loaders — exercising the real cert-PEM path AND mutual auth in one shot. A
/// single self-signed CA issues both a server leaf (SAN `localhost`, EKU
/// serverAuth) and a client leaf (EKU clientAuth); that one CA is the trust
/// anchor for BOTH directions (the client trusts it to verify the server leaf,
/// the server's client-cert verifier trusts it to verify the client leaf). This
/// is a richer cert topology than the self-signed-leaf [`loopback_tls_configs`]
/// because mTLS needs a CA the verifier can chain the peer's leaf to.
///
/// Behind `tls-fixtures` (pulls rcgen) like [`loopback_tls_configs`]; returns
/// only owned `String`s — no rustls or wz type — so it leaks no feature into
/// the non-TLS consumers of this crate (the R311fr default-features=false
/// contract is untouched). The caller loads the PEMs via the production module.
#[cfg(feature = "tls-fixtures")]
pub struct MtlsPems {
    /// The CA cert (PEM) — trust anchor for both leaves, in both directions.
    pub ca_pem: String,
    /// Server leaf cert (PEM), SAN `localhost`, signed by the CA.
    pub server_cert_pem: String,
    /// Server leaf private key (PEM).
    pub server_key_pem: String,
    /// Client leaf cert (PEM), signed by the CA, EKU clientAuth.
    pub client_cert_pem: String,
    /// Client leaf private key (PEM).
    pub client_key_pem: String,
}

/// Generate a fresh [`MtlsPems`] bundle (one CA, one server leaf, one client
/// leaf) for a mutual-TLS loopback e2e. See the type docs for the trust model.
#[cfg(feature = "tls-fixtures")]
pub fn loopback_mtls_pems() -> MtlsPems {
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};

    // ── Self-signed CA that issues both leaves. `is_ca` marks it a CA so
    //    webpki accepts it as a trust anchor a leaf can chain to.
    let ca_key = KeyPair::generate().expect("ca keypair");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-signed");

    // ── Server leaf: SAN `localhost` (the dial server-name), serverAuth EKU.
    let server_key = KeyPair::generate().expect("server keypair");
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("server cert signed by ca");

    // ── Client leaf: clientAuth EKU. No SAN match is needed for client auth —
    //    the server's verifier checks the chain to the CA, not a name.
    let client_key = KeyPair::generate().expect("client keypair");
    let mut client_params =
        CertificateParams::new(vec!["wz-client".to_string()]).expect("client params");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("client cert signed by ca");

    MtlsPems {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rx(byte: u8) -> LinkEvent {
        LinkEvent::Rx(RxFrame::new(vec![byte]))
    }

    /// The decorator swallows exactly the Nth frame matching the predicate and
    /// passes every other frame (matching or not) through unchanged — the
    /// deterministic single-loss mechanism, transport-free.
    #[tokio::test]
    async fn drops_only_the_nth_matching_frame() {
        // Marker 0xAA = a drop candidate, 0x00 = a pass-through frame.
        // Sequence: match, non-match, match(<- 2nd match, dropped), match.
        let inner = QueueDriver::with(vec![rx(0xAA), rx(0x00), rx(0xAA), rx(0xAA)]);
        let mut chaos =
            ChaosReadDriver::drop_nth_matching(inner, 2, |f| f.bytes.first() == Some(&0xAA));

        // 1st matching frame passes.
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xAA]),
            other => panic!("expected 1st match Rx, got {other:?}"),
        }
        // Non-matching frame passes (not counted toward the ordinal).
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0x00]),
            other => panic!("expected non-match Rx, got {other:?}"),
        }
        // 2nd matching frame is SWALLOWED, so the next poll yields the 3rd.
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xAA]),
            other => panic!("expected 3rd match Rx (2nd dropped), got {other:?}"),
        }
        // Inner queue drained -> Lost.
        assert!(matches!(chaos.poll_event().await, LinkEvent::Lost { .. }));
        assert_eq!(chaos.dropped, 1, "exactly one frame dropped");
    }

    /// `drop_ordinal == 0` is a pass-through: nothing is ever swallowed.
    #[tokio::test]
    async fn drop_ordinal_zero_passes_everything() {
        let inner = QueueDriver::with(vec![rx(0xAA), rx(0xAA)]);
        let mut chaos =
            ChaosReadDriver::drop_nth_matching(inner, 0, |f| f.bytes.first() == Some(&0xAA));
        for _ in 0..2 {
            match chaos.poll_event().await {
                LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xAA]),
                other => panic!("expected pass-through Rx, got {other:?}"),
            }
        }
        assert_eq!(chaos.dropped, 0);
    }

    /// Duplicate mode re-emits exactly the Nth matching frame once, immediately
    /// after the original, leaving every other frame untouched — the
    /// deterministic single-duplicate mechanism, transport-free.
    #[tokio::test]
    async fn duplicates_only_the_nth_matching_frame() {
        // Markers 0xAA / 0xBB are drop candidates, 0x00 is a pass-through.
        // Sequence: match(0xAA), non-match, match(0xBB <- 2nd match, DUPLICATED).
        let inner = QueueDriver::with(vec![rx(0xAA), rx(0x00), rx(0xBB)]);
        let mut chaos = ChaosReadDriver::duplicate_nth_matching(inner, 2, |f| {
            matches!(f.bytes.first(), Some(0xAA | 0xBB))
        });

        // 1st matching frame passes once.
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xAA]),
            other => panic!("expected 1st match Rx, got {other:?}"),
        }
        // Non-matching frame passes (not counted toward the ordinal).
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0x00]),
            other => panic!("expected non-match Rx, got {other:?}"),
        }
        // 2nd matching frame is emitted ...
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xBB]),
            other => panic!("expected 2nd match Rx, got {other:?}"),
        }
        // ... then re-emitted as a duplicate BEFORE the inner queue is polled.
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xBB]),
            other => panic!("expected duplicated Rx, got {other:?}"),
        }
        // Inner queue drained -> Lost.
        assert!(matches!(chaos.poll_event().await, LinkEvent::Lost { .. }));
        assert_eq!(chaos.duplicated, 1, "exactly one frame duplicated");
        assert_eq!(chaos.dropped, 0);
    }

    /// `dup_ordinal == 0` is a pass-through: nothing is ever duplicated.
    #[tokio::test]
    async fn dup_ordinal_zero_passes_everything() {
        let inner = QueueDriver::with(vec![rx(0xAA), rx(0xAA)]);
        let mut chaos =
            ChaosReadDriver::duplicate_nth_matching(inner, 0, |f| f.bytes.first() == Some(&0xAA));
        for _ in 0..2 {
            match chaos.poll_event().await {
                LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xAA]),
                other => panic!("expected pass-through Rx, got {other:?}"),
            }
        }
        assert!(matches!(chaos.poll_event().await, LinkEvent::Lost { .. }));
        assert_eq!(chaos.duplicated, 0);
    }

    /// Reorder mode delays the Nth matching frame past the single frame that
    /// follows it (an adjacent swap), leaving the rest in order — the
    /// deterministic single-reorder mechanism, transport-free.
    #[tokio::test]
    async fn reorders_the_nth_matching_frame_past_its_successor() {
        // Target the 1st match (0xAA); it should be delayed past 0xBB.
        // Sequence in: 0xAA, 0xBB, 0xCC -> out: 0xBB, 0xAA, 0xCC.
        let inner = QueueDriver::with(vec![rx(0xAA), rx(0xBB), rx(0xCC)]);
        let mut chaos =
            ChaosReadDriver::reorder_nth_matching(inner, 1, |f| f.bytes.first() == Some(&0xAA));

        // The successor overtakes the target ...
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xBB]),
            other => panic!("expected successor Rx first, got {other:?}"),
        }
        // ... then the held target ...
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xAA]),
            other => panic!("expected held target Rx, got {other:?}"),
        }
        // ... then the rest, in order.
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xCC]),
            other => panic!("expected tail Rx in order, got {other:?}"),
        }
        assert!(matches!(chaos.poll_event().await, LinkEvent::Lost { .. }));
        assert_eq!(chaos.reordered, 1, "exactly one frame reordered");
        assert_eq!(chaos.dropped, 0);
        assert_eq!(chaos.duplicated, 0);
    }

    /// When the reorder target is the last frame before a terminal event, it
    /// cannot be swapped past it: the target emits in place, then the terminal.
    #[tokio::test]
    async fn reorder_target_before_terminal_emits_target_then_terminal() {
        // Target 0xAA is the last frame; 0xBB precedes it, then the queue drains.
        let inner = QueueDriver::with(vec![rx(0xBB), rx(0xAA)]);
        let mut chaos =
            ChaosReadDriver::reorder_nth_matching(inner, 1, |f| f.bytes.first() == Some(&0xAA));

        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xBB]),
            other => panic!("expected 0xBB Rx, got {other:?}"),
        }
        // Nothing follows the target (the next inner event is Lost), so the
        // target emits in place rather than being reordered past the terminal.
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xAA]),
            other => panic!("expected target Rx in place, got {other:?}"),
        }
        assert!(matches!(chaos.poll_event().await, LinkEvent::Lost { .. }));
        assert_eq!(chaos.reordered, 1);
    }

    /// `reorder_ordinal == 0` is a pass-through: nothing is ever reordered.
    #[tokio::test]
    async fn reorder_ordinal_zero_passes_everything() {
        let inner = QueueDriver::with(vec![rx(0xAA), rx(0xBB)]);
        let mut chaos =
            ChaosReadDriver::reorder_nth_matching(inner, 0, |f| f.bytes.first() == Some(&0xAA));
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xAA]),
            other => panic!("expected pass-through Rx, got {other:?}"),
        }
        match chaos.poll_event().await {
            LinkEvent::Rx(f) => assert_eq!(f.bytes, [0xBB]),
            other => panic!("expected pass-through Rx, got {other:?}"),
        }
        assert!(matches!(chaos.poll_event().await, LinkEvent::Lost { .. }));
        assert_eq!(chaos.reordered, 0);
    }
}

// ── R311xr — shared establishment-handshake driver for the capability e2e tests
//    (lowlatency / compression / shm). Extracted from the three byte-identical
//    `establish_pair` helpers (one differing line: which `set_*_offer` was
//    called) per the project's "test fixtures -> sibling crate" rule. The one
//    differing line becomes the `apply_offer` closure the caller supplies, so the
//    feature-gated setter stays in the (feature-on) e2e crate and test-support
//    carries none of it.

use std::sync::Arc;

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastEvent as FsmEvent;
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, SessionLinkActions,
};

/// `SessionInitParams` with a distinct 4-byte zid (the accept-side cookie binds
/// to the peer zid, so the two sides of a handshake must differ).
pub fn fixture_params_with_zid(zid_byte: u8) -> SessionInitParams {
    let mut p = fixture_session_init_params();
    p.zid = vec![zid_byte; 4];
    p
}

/// The two actions bundles + their recording drivers from a completed
/// recording-driver handshake.
pub struct EstablishedPair {
    pub init_actions: Arc<SessionLinkActions>,
    pub resp_actions: Arc<SessionLinkActions>,
    pub init_driver: Arc<LifecycleRecordingDriver>,
    pub resp_driver: Arc<LifecycleRecordingDriver>,
}

/// Drive a complete wz<->wz unicast handshake over recording drivers to
/// Established (no socket -- a deterministic feed of each side's captured bytes
/// into the other). `apply_offer` stages a capability on a side that offers
/// (e.g. `|a| { a.set_lowlatency_offer(true); }`) before the drive -- the one
/// line the per-capability e2e helpers differed on.
pub async fn establish_capability_pair(
    init_offer: bool,
    resp_offer: bool,
    apply_offer: impl Fn(&Arc<SessionLinkActions>),
) -> EstablishedPair {
    let init_driver = Arc::new(LifecycleRecordingDriver::default());
    let resp_driver = Arc::new(LifecycleRecordingDriver::default());

    let init_actions = {
        let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = init_driver.clone();
        let a = new_session_actions(outbound, fixture_params_with_zid(0x01), TokioTime::new());
        if init_offer {
            apply_offer(&a);
        }
        a
    };
    let resp_actions = {
        let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = resp_driver.clone();
        let a = new_session_actions(outbound, fixture_params_with_zid(0x02), TokioTime::new());
        if resp_offer {
            apply_offer(&a);
        }
        a
    };

    let mut init_engine = new_session_engine(&init_actions);
    init_engine.initialize();
    let mut resp_engine = new_session_engine(&resp_actions);
    resp_engine.initialize();

    let last_send =
        |d: &LifecycleRecordingDriver| d.snapshot().sends.last().expect("a send").0.clone();

    resp_engine.process_event(FsmEvent::InboundStart);
    init_engine.process_event(FsmEvent::OutboundStart);
    init_engine.process_event(FsmEvent::LinkOpened);
    let init_syn = last_send(&init_driver);

    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn))]);
    poll_and_dispatch_one(&mut d, &resp_actions, &mut resp_engine).await;
    let init_ack = last_send(&resp_driver);

    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_ack))]);
    poll_and_dispatch_one(&mut d, &init_actions, &mut init_engine).await;
    let open_syn = last_send(&init_driver);

    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(open_syn))]);
    poll_and_dispatch_one(&mut d, &resp_actions, &mut resp_engine).await;
    let open_ack = last_send(&resp_driver);

    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(open_ack))]);
    poll_and_dispatch_one(&mut d, &init_actions, &mut init_engine).await;

    EstablishedPair {
        init_actions,
        resp_actions,
        init_driver,
        resp_driver,
    }
}

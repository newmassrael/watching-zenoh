// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use wz_runtime_tokio::session_glue::{
    BoxedLinkDriver, LinkSendOutcome, SessionInitParams, SigningKey, WhatAmI,
};
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
        tx_queue: wz_runtime_tokio::session_glue::TxQueueConf::default(),
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
        tx_queue: wz_runtime_tokio::session_glue::TxQueueConf::default(),
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
/// the right order, which the no-op-open/close `RecordingLinkDriver`
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
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        self.inner
            .lock()
            .expect("lifecycle driver poisoned")
            .sends
            .push((bytes.to_vec(), reliability));
        LinkSendOutcome::Sent
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
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        LinkSendOutcome::Sent
    }
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

/// Ports this process has already handed out. See [`free_port`].
static HANDED_OUT_PORTS: Mutex<Vec<u16>> = Mutex::new(Vec::new());

/// Record `port` as handed out by this process, in ONE step with asking whether it
/// already was: `false` means this process gave the number to someone before.
///
/// This is what keeps two THREADS of a process from drawing the same number, on every
/// host. The cross-process claim (`claim_file_in`) is a `flock`, which exists on unix
/// only, and on unix it also keeps two threads apart because two descriptors of one file
/// conflict. Elsewhere the claim is absent, and a pick checked only against the kernel's
/// socket table cannot tell a number another thread has drawn and not yet bound from a
/// free one: both threads see it free, both go on to bind it, and where a listener sets
/// `SO_REUSEADDR` (every wz listener does, as upstream's does) Windows lets both
/// succeed. A dial then reaches the other round's listener. A hosted run counted that as
/// 1 of 1200 dials; eight rounds live at once drawing from about 8192 numbers meet about
/// once in that many, which is the whole of that count.
fn record_in_process(port: u16) -> bool {
    let mut seen = HANDED_OUT_PORTS.lock().expect("port ledger");
    if seen.contains(&port) {
        return false;
    }
    seen.push(port);
    true
}

/// How many candidates [`free_port`] will reject before giving up. A bound
/// rather than a loop, for the reason every other limit in this workspace has
/// one: the number of attempts must not be decided by the kernel.
const FREE_PORT_ATTEMPTS: usize = 64;

/// A loopback TCP port no caller IN THIS PROCESS has been given before.
///
/// R311y867 (unregistered debt 264). Sixteen test files each carried their own
/// copy of this, and every copy was the same three lines: bind `127.0.0.1:0`,
/// read the port, DROP THE LISTENER, hand the number to something that will
/// bind it later. That gap is a time-of-check-to-time-of-use race, and it is
/// not theoretical — it took Layer C1cc red on hosted run 32198505957, where
/// `a_put_on_a_session_with_no_peer_still_reaches_its_own_subscriber` got
/// `z_open` = -4 (`locality_roundtrip.rs:92`) with the other eight tests in the
/// same binary green.
///
/// WHY THE PROCESS IS THE RIGHT SCOPE FOR THE LEDGER. `cargo test` runs one
/// binary's `#[test]` fns on many threads and the binaries themselves one after
/// another, so two callers of THIS function can only collide as two THREADS.
/// Remembering what has been handed out closes that case.
///
/// WHY THE NUMBER IS NEVER THE KERNEL'S TO OFFER, which the ledger could not
/// close and the first version of this function left open. The caller is a test
/// that hands the number to a session it has not opened yet, and every session
/// opened as a peer binds a `tcp/[::]:0` listener of its own: a `bind(:0)` from
/// another test of the same binary. A number this function took from the kernel
/// and released is in the pool that `bind(:0)` draws from, and measured on a
/// 2-core host with 8 threads opening and closing peer sessions beside a
/// late-listener leg, the draw landed on the leg's number (3 times in 1050
/// legs; 22 of 960 whole-binary runs failed with 24 copies on the same cores).
/// The consequences were not one failure but four: the late listener could not
/// bind (`z_open` = -4), a client that must wait for a listener 400 ms late
/// dialled the other session's listener and opened after 105 ms, a peer's start
/// window ended early because its dial was answered, and a dial that must have
/// been refused succeeded. None of them is a wz fault and a ledger cannot see
/// any of them, because the other caller never asked this function for anything.
///
/// So the number comes from a range the kernel does not autoselect from
/// ([`autoselect_range`]): `bind(:0)` anywhere in this process, or in a child it
/// spawns, cannot be given it, whatever the load. A candidate is probed by an
/// explicit bind, which is also what refuses a number a running service holds.
///
/// WHAT IS NOT CLOSED, stated rather than implied: a process that binds this
/// very number EXPLICITLY between this call and the caller's bind — another
/// test binary if a runner ever parallelises them with a picker that also
/// chooses explicitly, or a service that starts on a fixed port — can still take
/// it. Candidates are drawn at random from a range of thousands, so two
/// pickers meet rarely, and nothing a function returning a `u16` can do closes
/// it: that needs the caller to hold the listener until it hands the socket
/// over, which the C ABI under test cannot accept.
///
/// CAPACITY, because the claim that keeps two processes apart has a price. A
/// number handed out is claimed (see `claim_across_processes`) for as long as the
/// process lives: this function cannot know when its caller has finished with
/// the number, so it never lets one go. The numbers come from one range of at
/// most 8192 (the span below the kernel's autoselect range), so the processes
/// that pick through this crate AT THE SAME TIME share 8192 numbers between
/// them, and a process that has been handed N of them leaves 8192 - N to the
/// rest. `cargo test` runs one binary at a time and a binary asks for a few dozen
/// at most, so the sequential case never comes near it. A runner that runs many
/// binaries at once, or one binary in many copies, is bounded by the sum of what
/// they ask for: when the range runs out the pick panics and says that the claim
/// registry refused the draws, which is a different message from a number that
/// something else holds.
///
/// AND NO SOCKET IS HELD for any moment while the number is chosen
/// ([`unbound_unautoselected`]): a probe that binds and closes at once leaves the
/// number bound in every child another thread forks while the probe is open, which
/// kept a program started for it from binding it (see `pick_in`).
pub fn free_port() -> u16 {
    // The ledger entry is made by the pick itself, atomically with the check.
    unbound_unautoselected()
}

/// Raise this process's soft limit on open files to `wanted`, or to the hard limit when that
/// is lower, and answer the soft limit the process has afterwards.
///
/// A test that opens many sessions at once (each is a runtime, an I/O reactor and its sockets)
/// holds hundreds of descriptors, and the soft limit of a shell on a build host is commonly
/// 1024 where a developer's machine and a hosted runner allow far more. Past it the open fails
/// with `Too many open files`, which the code under test reports as a failed open: the test then
/// fails on the host's setting and says nothing of the code (measured: a 1,200-dial test failed
/// on both build hosts at 1024, at the commit before any change of this round, and passed in
/// under two seconds at 65,536). Raising the soft limit to what the hard limit permits is what
/// every long-lived server does on start, and is a change to this process alone. Not unix: no
/// such limit is modelled, and the answer is `wanted`.
pub fn raise_open_file_limit(wanted: u64) -> u64 {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes the struct it is handed, which is fully initialised and
        // lives for the call.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return 0;
        }
        let target = (wanted as libc::rlim_t).min(limit.rlim_max);
        if target > limit.rlim_cur {
            let raised = libc::rlimit {
                rlim_cur: target,
                rlim_max: limit.rlim_max,
            };
            // SAFETY: `setrlimit` reads the struct it is handed, which is fully initialised
            // and lives for the call; it changes this process's limit alone.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
                return target as u64;
            }
        }
        limit.rlim_cur as u64
    }
    #[cfg(not(unix))]
    {
        wanted
    }
}

/// The ledger half of the older, socket-holding [`free_port`], with the source of
/// candidates passed in so a test can feed it a candidate that was handed out
/// before. A candidate that is in the ledger is rejected with its listener held, and
/// the next one is taken. Kept for the tests that pin that shape.
#[cfg(test)]
fn hand_out(mut candidate: impl FnMut() -> (std::net::TcpListener, u16)) -> u16 {
    let mut rejected = Vec::new();
    for _ in 0..FREE_PORT_ATTEMPTS {
        let (listener, port) = candidate();
        let mut seen = HANDED_OUT_PORTS.lock().expect("port ledger");
        if seen.contains(&port) {
            // HELD, not dropped: releasing it here would let the very next
            // attempt draw the same number again.
            rejected.push(listener);
            continue;
        }
        seen.push(port);
        return port;
    }
    panic!(
        "free_port: {FREE_PORT_ATTEMPTS} consecutive candidates had already been \
         handed out in this process. Either a test is leaking ports faster than \
         the range can supply them, or the ledger is never cleared and this \
         binary has run for a very long time"
    );
}

/// The files that hold this process's claims, kept open for the process's life.
#[cfg(unix)]
static CLAIMS: Mutex<Vec<std::fs::File>> = Mutex::new(Vec::new());

/// Claim `port` against every OTHER process that picks through this crate,
/// for as long as this process lives. `false` means a live process holds it.
///
/// Two processes that each draw from the same few thousand numbers meet more
/// often than a reader expects: 24 copies of one test binary, each holding about
/// a dozen numbers, met 8 times in 960 runs on the first version of this picker
/// (a late listener that could not bind, a peer whose dial was answered by the
/// other copy's listener). A probe bind cannot see it, because the number is
/// handed out BEFORE its owner binds. So each handed-out number is also an
/// exclusive `flock` on a file named by the number, and a picker skips a number
/// whose file is locked.
///
/// `flock` and not a marker file: the kernel drops the lock when the descriptor
/// closes, including on `SIGKILL`, so a killed test cannot strand a number for
/// every later run. The files themselves are left behind and are harmless: an
/// unlocked file claims nothing. A host where the directory cannot be made or
/// the file cannot be opened has no registry, and the pick proceeds without one
/// -- the same as before this existed. Non-unix hosts have none either, and no
/// leg in this tree can run a Windows implementation to test one.
///
/// This form claims and KEEPS the answer, which is what the tests of the claim
/// need. The picker itself goes through [`draw_in`], which claims BEFORE it binds.
#[cfg(all(unix, test))]
fn claim_across_processes(port: u16) -> bool {
    claim_in(&claims_dir(), port)
}

/// [`claim_across_processes`] against the registry in `dir`. The directory is a
/// parameter so that a test of the claim itself can use one no picker touches:
/// a test that kills a holder and expects to claim its number is, in the shared
/// directory, a race against every other process that is drawing numbers.
#[cfg(all(unix, test))]
fn claim_in(dir: &std::path::Path, port: u16) -> bool {
    match claim_file_in(dir, port) {
        Claim::Held(file) => {
            CLAIMS.lock().expect("claim registry").push(file);
            true
        }
        Claim::Unrecorded => true,
        Claim::Taken => false,
    }
}

/// What asking the registry about a number came to.
#[cfg_attr(not(unix), allow(dead_code))]
enum Claim {
    /// The number is ours: the `flock` on its file, held for as long as the file is.
    Held(std::fs::File),
    /// There is no registry to ask (the directory cannot be made, the file cannot
    /// be opened, the host has none), and the pick goes on without one.
    Unrecorded,
    /// A live holder has it.
    Taken,
}

/// Ask the registry in `dir` for `port` WITHOUT keeping the answer anywhere but in
/// the returned [`Claim`], so a caller that then fails to bind drops the file and
/// the number is free again.
#[cfg(unix)]
fn claim_file_in(dir: &std::path::Path, port: u16) -> Claim {
    use std::os::unix::io::AsRawFd;

    if std::fs::create_dir_all(dir).is_err() {
        return Claim::Unrecorded;
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(port.to_string()))
    else {
        return Claim::Unrecorded;
    };
    // SAFETY: `file` owns a valid open descriptor for the whole call, and
    // `LOCK_EX | LOCK_NB` has no memory effects.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Claim::Held(file);
    }
    if std::io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
        Claim::Taken
    } else {
        Claim::Unrecorded
    }
}

/// No registry on a host that is not unix: see the unix form.
#[cfg(not(unix))]
fn claim_file_in(_dir: &std::path::Path, _port: u16) -> Claim {
    Claim::Unrecorded
}

/// What one draw of a number came to.
enum Draw {
    /// Another claim holds the number and nothing was bound.
    Taken,
    /// Nobody claims it, but something is bound to it.
    Unbindable,
    /// The number is bound here and claimed.
    Bound(std::net::TcpListener),
}

/// Draw `port`: CLAIM IT FIRST, and bind only a number that is ours.
///
/// THE ORDER MATTERS. A number is handed out BEFORE its owner binds: a foreign
/// program is started with it, and binds a moment later. Binding a candidate first and
/// consulting the registry after (what this did) means every draw that lands on a number
/// somebody else has claimed and not yet bound takes that number for as long as the probe
/// lives, in the middle of the other process's window. zenoh-pico does not retry a failed
/// bind. A claimed number is therefore never bound by a draw, in any process that picks
/// through this crate and in this one.
///
/// This is the form for a caller that WANTS the socket (a refusing port holds one on
/// purpose). A caller that is about to hand the number to a program uses
/// [`unbound_unautoselected`], which holds no socket at all: see [`pick_in`] for why
/// even a probe that is closed at once is not harmless.
fn draw_in(dir: &std::path::Path, port: u16) -> Draw {
    let claim = claim_file_in(dir, port);
    if matches!(claim, Claim::Taken) {
        return Draw::Taken;
    }
    match std::net::TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => {
            #[cfg(unix)]
            if let Claim::Held(file) = claim {
                CLAIMS.lock().expect("claim registry").push(file);
            }
            Draw::Bound(listener)
        }
        // `claim` is dropped here, and with it the `flock`: a number that cannot
        // be bound is not ours.
        Err(_) => Draw::Unbindable,
    }
}

/// What one look at a number came to, for a pick that holds NO socket.
enum Pick {
    /// Another claim holds the number.
    Taken,
    /// Something is bound or connected on it.
    InUse,
    /// Nobody holds it, and it is claimed here.
    Free,
}

/// Whether anything at all uses `port` as its local port. On Linux this is the kernel's
/// own socket table, read without creating a socket; elsewhere it is a bind that is
/// dropped at once, which is the best a host without such a table can do.
fn port_in_use(port: u16) -> bool {
    #[cfg(target_os = "linux")]
    {
        let wanted = format!(":{port:04X}");
        let mut read_any = false;
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(text) = std::fs::read_to_string(table) else {
                continue;
            };
            read_any = true;
            let used = text.lines().skip(1).any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .is_some_and(|local| local.ends_with(&wanted))
            });
            if used {
                return true;
            }
        }
        if read_any {
            return false;
        }
    }
    std::net::TcpListener::bind(("127.0.0.1", port)).is_err()
}

/// Look at `port` for a pick that must leave NO SOCKET behind: claim it, then ask the
/// kernel's table whether anything uses it.
///
/// WHY NOT BIND IT AND CLOSE IT, which is what a pick did for years. A socket that exists
/// is a file descriptor, and a descriptor is inherited by every `fork` another thread of
/// the process makes while it is open: the child holds a copy of the LISTENING socket
/// until its `exec` closes it, and the number stays bound for as long as that takes. A test
/// binary runs dozens of tests on threads, each starting programs, so the window between a
/// pick's bind and its close is crossed by somebody else's `fork` often enough to matter, and
/// on a machine short of CPUs the forked child waits milliseconds for its `exec`. The program
/// the number was picked for then binds it inside that wait and fails. Measured on the
/// zenoh-pico drop-in legs: the real library's `bind() failed for address 127.0.0.1: Address
/// already in use` with no socket on the number when anyone looked, the failed bind 1.3 to
/// 1.7 ms after the pick's own bind where a good one follows by about 5. A pick that creates
/// no socket has nothing to inherit.
fn pick_in(dir: &std::path::Path, port: u16) -> Pick {
    let claim = claim_file_in(dir, port);
    if matches!(claim, Claim::Taken) {
        return Pick::Taken;
    }
    if port_in_use(port) {
        // `claim` is dropped here, and with it the `flock`: a number in use is not ours.
        return Pick::InUse;
    }
    #[cfg(unix)]
    if let Claim::Held(file) = claim {
        CLAIMS.lock().expect("claim registry").push(file);
    }
    Pick::Free
}

/// A number the kernel does not autoselect, claimed by this process and used by nothing,
/// WITHOUT a socket held on it for any moment: see `pick_in`. The reservation of a number
/// for a program that is started a moment later, and the number a test hands to a session of
/// its own, are this.
pub fn unbound_unautoselected() -> u16 {
    let (first, last) = pick_range();
    let span = u64::from(last - first) + 1;
    let claims = claims_dir();
    let (mut in_use, mut claimed) = (0usize, 0usize);
    for _ in 0..FREE_PORT_ATTEMPTS {
        let port = first + (random_draw() % span) as u16;
        match pick_in(&claims, port) {
            // Free by the kernel's table and the claim registry: also not a number this
            // process gave out, which no table can show for one that is not bound yet.
            Pick::Free if record_in_process(port) => return port,
            Pick::Free | Pick::Taken => claimed += 1,
            Pick::InUse => in_use += 1,
        }
    }
    panic!(
        "unbound_unautoselected: {FREE_PORT_ATTEMPTS} draws from {first}..={last} found no \
         number. {in_use} were in use (something else on this host uses the number) and \
         {claimed} were refused by the claim registry (a live process picking through this \
         crate holds the number: claims last until the process exits, so the {span} numbers \
         of this range are shared by every such process at once)"
    );
}

/// The registry every picker of this user shares.
fn claims_dir() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        // SAFETY: `getuid` has no arguments and no memory effects.
        let uid = unsafe { libc::getuid() };
        std::env::temp_dir().join(format!("wz-free-port-claims-{uid}"))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("wz-free-port-claims")
    }
}

/// The smallest span of ports the picker will draw from. A narrower range makes
/// two pickers meet often, which is the thing the range exists to avoid.
const MIN_PICK_SPAN: u32 = 1024;

/// How far below the autoselect range the picker's own range reaches.
const PICK_SPAN: u32 = 8192;

/// The first number a non-privileged process may bind explicitly.
const FIRST_UNPRIVILEGED_PORT: u32 = 1024;

/// The closed range `(first, last)` the kernel draws a `bind(:0)` number and an
/// outgoing connection's source number from on this host.
///
/// Linux states it in `/proc/sys/net/ipv4/ip_local_port_range`, 32768 to 60999
/// unless an administrator moved it; the BSD stack under macOS and Windows use
/// the IANA range, 49152 to 65535. The Linux file is read because a container or
/// a CI image does move it, and a hard-coded number would then be a claim about
/// a different host. An unreadable file is the Linux default: the range can only
/// be wrong that way on a host whose administrator moved it AND hid the file.
pub fn autoselect_range() -> (u16, u16) {
    #[cfg(target_os = "linux")]
    {
        let stated = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .ok()
            .and_then(|text| {
                let mut numbers = text.split_whitespace().map(str::parse::<u16>);
                match (numbers.next(), numbers.next()) {
                    (Some(Ok(first)), Some(Ok(last))) if first <= last => Some((first, last)),
                    _ => None,
                }
            });
        stated.unwrap_or((32768, 60999))
    }
    #[cfg(not(target_os = "linux"))]
    {
        (49152, 65535)
    }
}

/// The closed range `(first, last)` the picker draws from: the ports just below
/// [`autoselect_range`], or, when that leaves too little room, the ports above it.
///
/// Below first, because nothing assigns a number there on its own and it keeps
/// clear of the top of the range where a high port is more likely to be one a
/// service chose. Panics when neither side has [`MIN_PICK_SPAN`] numbers, which
/// is a host whose autoselect range covers nearly all of the unprivileged ports:
/// there is then no number a test can be handed that the kernel will not also
/// offer to someone else, and saying so beats a pick that quietly can be stolen.
fn pick_range() -> (u16, u16) {
    let (first, last) = autoselect_range();
    // A host shared with other test runs can give a run a range of its own:
    // `WZ_TEST_PORT_RANGE=20000-21999`. Pickers that bind a candidate before they
    // claim it (every build of this crate before the claim moved ahead of the bind)
    // take, for the moment of a probe, a number a run of this crate has claimed
    // and not yet bound, and a range nobody else draws from is the one way to tell
    // that cause from a cause inside the run. It must lie outside the kernel's
    // autoselect range, for the reason the default does.
    if let Some((low, high)) = std::env::var("WZ_TEST_PORT_RANGE").ok().and_then(|text| {
        let (low, high) = text.split_once('-')?;
        Some((
            low.trim().parse::<u16>().ok()?,
            high.trim().parse::<u16>().ok()?,
        ))
    }) {
        assert!(
            u32::from(low) >= FIRST_UNPRIVILEGED_PORT
                && low <= high
                && (high < first || low > last),
            "WZ_TEST_PORT_RANGE={low}-{high} must be unprivileged, ordered, and outside the \
             kernel's autoselect range {first}..={last}"
        );
        return (low, high);
    }
    let below_end = u32::from(first).saturating_sub(1);
    let below_start = below_end
        .saturating_sub(PICK_SPAN - 1)
        .max(FIRST_UNPRIVILEGED_PORT);
    if below_end >= below_start && below_end - below_start + 1 >= MIN_PICK_SPAN {
        return (below_start as u16, below_end as u16);
    }
    let above_start = u32::from(last) + 1;
    let above_end = (above_start + PICK_SPAN - 1).min(u32::from(u16::MAX));
    if above_end >= above_start && above_end - above_start + 1 >= MIN_PICK_SPAN {
        return (above_start as u16, above_end as u16);
    }
    panic!(
        "the kernel's autoselect range {first}..={last} leaves no {MIN_PICK_SPAN}-port span \
         of unprivileged ports outside it, so no number can be handed to a test that a \
         bind(:0) elsewhere in the process could not also be given"
    );
}

/// A uniformly drawn value, from the standard library's per-instance random keys.
fn random_draw() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    hasher.finish()
}

/// Bind `127.0.0.1` on a port the kernel does not autoselect, and return the
/// listener with its number. The caller holds the listener for as long as the
/// number must stay its own: [`free_port`] drops it at once, a reservation that
/// wraps a child process holds it until the child has bound.
///
/// Reads no address back from the socket and takes none from the kernel: the
/// number is the one this function asked for, and a bind that fails (a number
/// something already holds, or a live process has claimed) is drawn again, at
/// most `FREE_PORT_ATTEMPTS` times (a private constant, so a code span).
///
/// Capacity: every number returned stays claimed until the process exits, and
/// the range is shared by every process that picks through this crate at the
/// same time; see [`free_port`].
pub fn bind_unautoselected() -> (std::net::TcpListener, u16) {
    let (first, last) = pick_range();
    let span = u64::from(last - first) + 1;
    let (mut unbindable, mut claimed) = (0usize, 0usize);
    let claims = claims_dir();
    for _ in 0..FREE_PORT_ATTEMPTS {
        let port = first + (random_draw() % span) as u16;
        match draw_in(&claims, port) {
            Draw::Bound(listener) => return (listener, port),
            Draw::Taken => claimed += 1,
            Draw::Unbindable => unbindable += 1,
        }
    }
    panic!(
        "bind_unautoselected: {FREE_PORT_ATTEMPTS} draws from {first}..={last} found no \
         number. {unbindable} could not be bound (something else on this host holds the \
         number) and {claimed} were refused by the claim registry (a live process picking \
         through this crate holds the number: claims last until the process exits, so \
         the {span} numbers of this range are shared by every such process at once)"
    );
}

/// A loopback TCP address that REFUSES connections for as long as the
/// returned socket is held.
///
/// R2778 (open-debt item 806) — the socket is BOUND and never `listen()`ed.
/// While it is held the kernel answers a connect to that port with a reset
/// (`ECONNREFUSED`), and no other bind on the host can take the number, so a
/// dial that is meant to fail cannot be answered by anyone.
///
/// ⚠ WHY NOT BIND AND RELEASE, which is what five tests in this tree did and
/// what one of them was red for. A released number belongs to nobody, and the
/// kernel hands it to the next `bind(:0)` it sees — the listener of the node
/// under test included. Hosted run `35579977073` shows the cost exactly: a
/// node told to exit when its one peer was unreachable was given, as that
/// peer, the number its own `tcp/127.0.0.1:0` listener then received, so it
/// connected to ITSELF, reported its connect phase satisfied and never
/// exited. The helper that picked the number said in its own doc that a
/// stolen number could only make the dial succeed "and no arm here reads
/// that"; the exit arms read exactly that.
///
/// And why not a held std listener: `TcpListener::bind` always `listen()`s,
/// so a held listener ACCEPTS the connect into its backlog — the dial
/// succeeds and the failure arm under test never runs.
///
/// The guard is the value the caller keeps: the address is read OFF it, so
/// the natural use — `let dead = refusing_port();` then `dead.addr()` where
/// it is needed — holds the socket for the whole scope. Dropping it returns
/// the number to the pool and reopens the window this closes.
///
/// The one shared form of a shape two files had already written correctly
/// for themselves (`wz-integration-tests`' `closed_port`, whose own
/// discriminating test moved here with it, and `static_scout_open.rs`'
/// `refused_locator`) and five had written the other way.
///
/// R2781 (open-debt item 810) — the socket also sets `SO_REUSEPORT`, which
/// is what lets [`RefusingPort::listen`] put a LISTENER on the same number
/// while this socket keeps holding it. A plain bind still fails (std's
/// `TcpListener::bind` does not set the option, and the kernel admits a
/// second socket to a port only when both did), so the reservation above is
/// unchanged; and a `bind(:0)` never picks a port another socket holds, with
/// or without the option, so nothing else on the host can be handed it.
///
/// R2782 — UNIX ONLY, that option and the `listen` it enables. `SO_REUSEPORT`
/// is a unix socket option and socket2 has no setter for it elsewhere; hosted
/// run 35620636972's Windows portability leg failed to COMPILE this crate on
/// exactly that call. Windows has a different sharing model (`SO_REUSEADDR`
/// there lets a second socket take a port another holds, and
/// `SO_EXCLUSIVEADDRUSE` forbids it), and no leg in this tree can run a
/// Windows implementation, so none is written: on a non-unix host this is the
/// R2778 guard exactly -- bound, never listening, refusing -- and `listen`
/// does not exist, which is a compile error rather than an untested guess.
///
/// ⚠ "Refusing" is a LINUX property of this socket. A bound socket that is not
/// listening is not a destination there, and a SYN to it is answered with a reset, as
/// to a closed port. The BSD stack under macOS drops the SYN of a bound socket in the
/// closed state without answering, so a connect to this number does not fail: it waits
/// out the kernel's connect timeout (75 s on macOS), which is what the hosted macOS
/// leg of run 37915005371 measured in `link_pipeline::tests::dial_tcp_surfaces_connect_error`
/// (running over 60 s, then passing). A caller that needs the refusal gates on
/// `target_os = "linux"` and bounds its connect; a caller that needs an error from the
/// dial itself on every host dials a destination the kernel validates before it sends
/// (port 0).
pub fn refusing_port() -> RefusingPort {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
        .expect("a TCP socket");
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .expect("SO_REUSEPORT, so a listener can share the held number");
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
    socket.bind(&bind.into()).expect("bind without listen");
    let addr = socket
        .local_addr()
        .expect("the bound address is readable")
        .as_socket()
        .expect("an IPv4 socket address");
    RefusingPort {
        _socket: socket,
        addr,
    }
}

/// A held, refusing loopback port — see [`refusing_port`].
#[must_use = "the port refuses only while this is held; dropping it frees the number"]
pub struct RefusingPort {
    /// Held, never read: its whole job is to keep the number bound.
    _socket: socket2::Socket,
    addr: std::net::SocketAddr,
}

impl RefusingPort {
    /// The address that refuses, for as long as `self` lives.
    pub fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    /// A LISTENER on this same number, for as long as it is held; dropping it
    /// returns the number to refusing, and it is never free in between.
    ///
    /// R2781 (open-debt item 810) — for a test whose peer must go AWAY and,
    /// in some tests, come back on the same address. The shape this replaces
    /// dropped a listener to make the address dead and bound a new one to
    /// bring it back; the drop freed the number, so another test's `bind(:0)`
    /// could take it -- answering the dial that was meant to be refused, or
    /// making the rebind fail. Here the number stays with `self` throughout.
    ///
    /// The listener is NON-BLOCKING, ready for tokio's `from_std`, because
    /// every caller in this tree drives it from a tokio test.
    ///
    /// Unix only, for the reason [`refusing_port`] gives.
    #[cfg(unix)]
    pub fn listen(&self) -> std::net::TcpListener {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
            .expect("a TCP socket");
        socket
            .set_reuse_port(true)
            .expect("SO_REUSEPORT, to share the number the guard holds");
        socket
            .bind(&self.addr.into())
            .expect("bind the held number beside its guard");
        socket.listen(128).expect("listen on the held number");
        socket
            .set_nonblocking(true)
            .expect("non-blocking, for tokio's from_std");
        socket.into()
    }
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

/// R311y365 — a fresh self-signed `localhost` cert + private key as PEM strings
/// `(cert_pem, key_pem)` — the file-material twin of [`loopback_tls_configs`]
/// for a caller that must hand cert/key to an EXTERNAL process by PATH (a
/// zenohd `--config` TLS listener cannot take a rustls `ServerConfig`, only PEM
/// files). Same rcgen `localhost` self-signed leaf; for a self-signed cert the
/// leaf IS its own root, so the SAME `cert_pem` doubles as the client's
/// `root_ca_pem` (`wz_runtime_tokio::session_open::TlsDialConfig::from_ca_pem`).
/// The caller writes the two PEMs to files and cleans them up.
#[cfg(feature = "tls-fixtures")]
pub fn localhost_cert_key_pem() -> (String, String) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    (issued.cert.pem(), issued.key_pair.serialize_pem())
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

#[cfg(test)]
mod port_tests {
    use super::{
        autoselect_range, free_port, hand_out, record_in_process, refusing_port,
        unbound_unautoselected,
    };
    #[cfg(unix)]
    use super::{claim_across_processes, claim_in};
    use std::collections::BTreeSet;

    /// Held by a test that drops a listener and expects the number to refuse, for
    /// the whole test, and by every test that starts a child process, around the
    /// start only.
    ///
    /// Why: `fork` gives the child a copy of every descriptor the process has
    /// open, and `exec` closes them again; between the two, a listener that
    /// another thread has just dropped is still open in the child, so the
    /// number still ANSWERS. `Command::spawn` returns after the `exec`, so the
    /// window is the call. Measured on a 22-core host with the tests of this
    /// module running together: the refusing-port test failed in 87 of 100 runs
    /// beside the test that starts a holder process and 58 of 100 beside the
    /// probe process, and in none beside the tests that start no process.
    static SPAWN_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// R2778 — the discriminator for `refusing_port`, moved here with the
    /// helper from `wz-integration-tests`, where it guarded that crate's local
    /// copy (R311y383): the socket RESERVES the port (a concurrent bind to it
    /// fails) AND keeps it CLOSED (a connect is refused), for as long as it is
    /// held.
    ///
    /// Both halves, because each catches a different wrong helper. A helper
    /// that binds and releases reds the first — the number is free to rebind,
    /// which is item 806's defect. A helper that holds a LISTENING socket reds
    /// the second — the connect is accepted into the backlog.
    ///
    /// Linux only, and every connect bounded: the refusal is a Linux property of a bound,
    /// non-listening socket (see [`refusing_port`]), and an unbounded `connect` on a
    /// stack that drops the SYN waits out the kernel's schedule.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refusing_port_is_reserved_and_refuses_connect() {
        use std::net::{TcpListener, TcpStream};
        let dead = refusing_port();
        assert!(
            TcpListener::bind(dead.addr()).is_err(),
            "the held socket must reserve the port against a concurrent bind"
        );
        assert!(
            TcpStream::connect_timeout(&dead.addr(), std::time::Duration::from_secs(10)).is_err(),
            "a bound-not-listening port must refuse connects (ECONNREFUSED)"
        );
    }

    /// R2781 — the discriminator for `RefusingPort::listen`: the held number
    /// ANSWERS while a listener is held on it, REFUSES again once that
    /// listener is dropped, answers again on a second listen, and a plain
    /// bind fails in every one of those phases.
    ///
    /// Each phase catches a different wrong helper. A `listen` that bound a
    /// fresh port answers somewhere else, and the first connect is refused. A
    /// guard without the shared option cannot be joined at all, and `listen`
    /// panics. A guard that let go of the number while a listener held it
    /// would leave nothing refusing after the drop.
    ///
    /// Linux only, for the reason of the test above: the "refuses again" half is a
    /// Linux property of a bound, non-listening socket.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refusing_port_listens_and_refuses_again_on_the_same_number() {
        use std::net::{TcpListener, TcpStream};
        // No other test of this module may start a process while a listener
        // here is dropped: see `SPAWN_GATE`.
        let _gate = SPAWN_GATE.lock().unwrap_or_else(|held| held.into_inner());
        let port = refusing_port();
        let connect_within =
            |addr| TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10));
        for phase in ["first", "second"] {
            let listener = port.listen();
            assert_eq!(
                listener.local_addr().expect("the listener's address"),
                port.addr(),
                "the {phase} listener is on the held number"
            );
            assert!(
                connect_within(port.addr()).is_ok(),
                "the held number must answer while the {phase} listener is held"
            );
            assert!(
                TcpListener::bind(port.addr()).is_err(),
                "a plain bind must still fail while the {phase} listener is held"
            );
            drop(listener);
            assert!(
                connect_within(port.addr()).is_err(),
                "the number must refuse again once the {phase} listener is dropped"
            );
            assert!(
                TcpListener::bind(port.addr()).is_err(),
                "and stay reserved after the {phase} listener is dropped"
            );
        }
    }

    /// A number another LIVE process was handed is not handed out here, and is
    /// again once that process is gone.
    ///
    /// The test runs itself twice. With `WZ_PORT_CLAIM_HOLDER` set (to a
    /// directory) it is the holder: it claims a number in that registry, prints
    /// it and holds it until its stdin closes. Without it, it starts that holder,
    /// reads the number, and asks for a claim on the same number: that must be
    /// refused while the holder lives and granted after the holder is killed (the
    /// kernel drops an `flock` with its process, so a killed test strands
    /// nothing).
    ///
    /// The registry is a directory of this test's own. In the shared one, "the
    /// number is claimable again" is a race against every other process drawing
    /// numbers, and 24 copies of this binary on two cores lost it in 16 runs of
    /// 960: another copy drew the number in the moments between the kill and the
    /// claim.
    #[cfg(unix)]
    #[test]
    fn a_number_held_by_another_process_is_not_handed_out() {
        use std::io::{BufRead, Read, Write};
        use std::process::{Command, Stdio};

        const HELD: u16 = 40_000;
        if let Some(dir) = std::env::var_os("WZ_PORT_CLAIM_HOLDER") {
            assert!(
                claim_in(std::path::Path::new(&dir), HELD),
                "the holder claims"
            );
            std::println!("CLAIMED {HELD}");
            let _ = std::io::stdout().flush();
            let mut sink = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut sink);
            return;
        }
        let dir = std::env::temp_dir().join(format!("wz-claim-test-{}", std::process::id()));
        // The gate covers the start only: see `SPAWN_GATE`.
        let gate = SPAWN_GATE.lock().unwrap_or_else(|held| held.into_inner());
        let mut holder = Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                "port_tests::a_number_held_by_another_process_is_not_handed_out",
                "--nocapture",
            ])
            .env("WZ_PORT_CLAIM_HOLDER", &dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start the holder");
        drop(gate);
        // Kept alive to the end of the test: dropping the read end early would make
        // the holder's own harness lines fail with a broken pipe.
        let mut lines = std::io::BufReader::new(holder.stdout.take().expect("holder stdout"))
            .lines()
            .map_while(Result::ok);
        let held: u16 = lines
            .find_map(|line| line.strip_prefix("CLAIMED ")?.parse().ok())
            .expect("the holder prints the number it holds");
        assert!(
            !claim_in(&dir, held),
            "{held} is held by a live process and must not be claimable here"
        );
        holder.kill().expect("kill the holder");
        holder.wait().expect("reap the holder");
        assert!(
            claim_in(&dir, held),
            "{held} must be claimable again once its holder is gone"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A number somebody else has claimed is NEVER bound by a draw. The claim is
    /// asked for first, so a number that is both claimed and bound elsewhere
    /// comes back `Taken`; asked second (the order this used to have) the same
    /// number comes back `Unbindable`, and the bind that found it out has held it
    /// for the moment it took, which is the moment the other process's child
    /// needed it.
    #[cfg(unix)]
    #[test]
    fn a_claimed_number_is_never_bound_by_a_draw() {
        use super::{draw_in, unbound_unautoselected, Draw};
        let dir = std::env::temp_dir().join(format!("wz-draw-test-{}", std::process::id()));
        // Bound by something else AND claimed: the draw must stop at the claim.
        let other = std::net::TcpListener::bind("127.0.0.1:0").expect("a bound number");
        let held = other.local_addr().expect("local_addr").port();
        assert!(
            claim_in(&dir, held),
            "the number is claimed before the draw"
        );
        match draw_in(&dir, held) {
            Draw::Taken => {}
            Draw::Unbindable => panic!(
                "{held} is claimed, yet the draw tried to bind it before looking at the claim"
            ),
            Draw::Bound(_) => panic!("{held} is claimed and bound elsewhere"),
        }
        // A number nobody holds is bound AND claimed by the draw.
        drop(other);
        let free = unbound_unautoselected();
        match draw_in(&dir, free) {
            Draw::Bound(listener) => {
                assert_eq!(listener.local_addr().expect("local_addr").port(), free);
            }
            Draw::Taken => panic!("{free} was nobody's and is reported claimed"),
            Draw::Unbindable => panic!("{free} was nobody's and could not be bound"),
        }
        assert!(
            !claim_in(&dir, free),
            "{free} is bound by the draw and must stay claimed by this process"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pick holds NO socket, so there is nothing for a `fork` in another thread
    /// to copy: the number it returns is claimed by this process, absent from the
    /// kernel's table, and bindable the next moment.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unbound_pick_leaves_no_socket_and_the_number_is_claimed() {
        let port = super::unbound_unautoselected();
        assert!(
            !super::port_in_use(port),
            "{port} was picked, so nothing may use it yet"
        );
        assert!(
            !claim_across_processes(port),
            "{port} was picked and must stay claimed by this process"
        );
        drop(std::net::TcpListener::bind(("127.0.0.1", port)).expect("the picked number binds"));
    }

    /// A number something uses is not picked, and the claim taken to look at it is
    /// let go, so the number is not lost to every later pick.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unbound_pick_refuses_a_number_in_use_and_lets_its_claim_go() {
        use super::{pick_in, Pick};
        let dir = std::env::temp_dir().join(format!("wz-pick-test-{}", std::process::id()));
        let holder = std::net::TcpListener::bind("127.0.0.1:0").expect("a number in use");
        let used = holder.local_addr().expect("local_addr").port();
        assert!(
            matches!(pick_in(&dir, used), Pick::InUse),
            "{used} is bound by a listener and must not be picked"
        );
        assert!(
            claim_in(&dir, used),
            "{used} was refused as in use, so the look at it must not leave it claimed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A number another picker has claimed is not picked, whatever the table says.
    #[cfg(unix)]
    #[test]
    fn an_unbound_pick_refuses_a_claimed_number() {
        use super::{pick_in, Pick};
        let dir = std::env::temp_dir().join(format!("wz-pick-claim-test-{}", std::process::id()));
        const CLAIMED: u16 = 40_001;
        assert!(claim_in(&dir, CLAIMED), "the number is claimed first");
        assert!(
            matches!(pick_in(&dir, CLAIMED), Pick::Taken),
            "a claimed number must not be picked"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `free_port` claims what it hands out: the number it returns is refused to
    /// a second claim, which is what keeps another process from being handed it.
    /// This process holds the claim, so no other process can disturb the answer.
    #[cfg(unix)]
    #[test]
    fn free_port_claims_the_number_it_hands_out() {
        let port = free_port();
        assert!(
            !claim_across_processes(port),
            "{port} was handed out and must stay claimed by this process"
        );
    }

    /// The structural half of the claim below, with no draw in it: no number
    /// `free_port` hands out lies in the range the kernel autoselects from, and
    /// the range that is read is a real one.
    #[test]
    fn a_handed_out_port_lies_outside_the_autoselect_range() {
        let (first, last) = autoselect_range();
        assert!(
            first <= last,
            "the autoselect range {first}..={last} is empty"
        );
        // 32 numbers, not more: every number handed out is claimed until this
        // process exits (see `free_port`), and copies of this binary running at
        // once share one range. Thirty-two is what the claim needs: a pick that
        // drew from the kernel's pool lands inside the range on its FIRST draw,
        // and one that overlapped the range by half misses all 32 with odds of
        // one in four billion.
        for _ in 0..32 {
            let port = free_port();
            assert!(
                port < first || port > last,
                "free_port handed out {port}, inside the autoselect range {first}..={last}"
            );
            assert!(port >= 1024, "{port} is a privileged port");
        }
    }

    /// A port `free_port` has handed out and its owner has not bound yet is
    /// never what a `bind(:0)` anywhere in the process returns.
    ///
    /// The race this closes, as measured on a 2-core host: a wz session opened
    /// as a peer binds `tcp/[::]:0` of its own, and the kernel chose that number
    /// from the same pool `free_port` had just released a number into, so a test
    /// that was about to dial or bind its handed-out port met another test's
    /// session instead (the open returned after 105 ms where a listener 400 ms
    /// late was expected). The ledger of [`free_port`] cannot see that caller;
    /// only a number the kernel never offers to `bind(:0)` is safe from it.
    ///
    /// The probe is the kernel's own: many threads bind `:0` on the two address
    /// families a session uses and the numbers they are given are compared with
    /// the handed-out set. It is a draw, so the claim it carries is bounded: with
    /// the old shape the draw hits within a fraction of a second on every host
    /// measured, and a number outside the autoselect range cannot be hit at all.
    ///
    /// It runs in a CHILD process of this test binary (`WZ_AUTOSELECT_PROBE`),
    /// so that eight threads binding and releasing listeners without pause do
    /// not compete with its siblings for the cores. That process is also what
    /// fails the refusing-port test beside it, and not through its binds: it
    /// is started with `fork`, and a listener dropped in the window before
    /// the `exec` is still open in the child. The start is therefore made
    /// under `SPAWN_GATE`.
    #[test]
    fn a_handed_out_port_is_never_an_autoselect_result() {
        use std::process::{Command, Stdio};

        if std::env::var_os("WZ_AUTOSELECT_PROBE").is_some() {
            let (binds, hits, handed) = hammer_autoselect();
            std::println!("PROBE binds={binds} hits={hits} handed={handed}");
            return;
        }
        // The gate covers the start only: see `SPAWN_GATE`.
        let gate = SPAWN_GATE.lock().unwrap_or_else(|held| held.into_inner());
        let child = Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                "port_tests::a_handed_out_port_is_never_an_autoselect_result",
                "--nocapture",
            ])
            .env("WZ_AUTOSELECT_PROBE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the probe process");
        drop(gate);
        let output = child.wait_with_output().expect("run the probe process");
        let text = String::from_utf8_lossy(&output.stdout);
        let line = text
            .lines()
            .find(|line| line.starts_with("PROBE "))
            .unwrap_or_else(|| panic!("the probe process printed no result: {text}"));
        std::println!("{line}");
        assert!(
            line.contains(" hits=0 "),
            "a bind(:0) was given a port free_port had handed out and nobody had bound yet: {line}"
        );
    }

    /// Bind `:0` on both address families from eight threads, for up to four
    /// seconds or until the first hit, against 64 numbers `free_port` handed out
    /// and nobody has bound. Returns `(binds, hits, handed)`.
    fn hammer_autoselect() -> (u64, u64, usize) {
        use std::collections::HashSet;
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let handed: Arc<HashSet<u16>> = Arc::new((0..64).map(|_| free_port()).collect());
        let stop = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicU64::new(0));
        let binds = Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (0..8)
            .map(|n| {
                let (handed, stop, hits, binds) =
                    (handed.clone(), stop.clone(), hits.clone(), binds.clone());
                std::thread::spawn(move || {
                    let wildcard = if n % 2 == 0 { "[::]:0" } else { "127.0.0.1:0" };
                    while !stop.load(Ordering::SeqCst) {
                        let Ok(l) = std::net::TcpListener::bind(wildcard) else {
                            continue;
                        };
                        binds.fetch_add(1, Ordering::SeqCst);
                        if let Ok(a) = l.local_addr() {
                            if handed.contains(&a.port()) {
                                hits.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                })
            })
            .collect();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(4) && hits.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(Duration::from_millis(50));
        }
        stop.store(true, Ordering::SeqCst);
        for t in threads {
            t.join().expect("autoselect thread");
        }
        (
            binds.load(Ordering::SeqCst),
            hits.load(Ordering::SeqCst),
            handed.len(),
        )
    }

    /// The old three-line helper: bind, read, drop. Reproduced here so the
    /// control below is a COMPARISON rather than an assertion about the new one
    /// alone.
    ///
    /// R311y889 — `Option` and not `unwrap`. This runs 256 times inside a test
    /// that deliberately asserts NOTHING about the kernel, so a bind that fails
    /// under load must not be the one thing in it that can still panic. A draw
    /// that did not happen is not a draw.
    fn old_shape() -> Option<u16> {
        Some(
            std::net::TcpListener::bind("127.0.0.1:0")
                .ok()?
                .local_addr()
                .ok()?
                .port(),
        )
    }

    /// Repeats and distinct ports across 256 attempted draws, plus how many of
    /// those draws actually bound.
    fn old_shape_repeats() -> (usize, usize, usize) {
        let mut seen = BTreeSet::new();
        let (mut repeats, mut drawn) = (0usize, 0usize);
        for _ in 0..256 {
            let Some(port) = old_shape() else { continue };
            drawn += 1;
            if !seen.insert(port) {
                repeats += 1;
            }
        }
        (repeats, seen.len(), drawn)
    }

    /// R311y867 — the property the sixteen hand-copied helpers did not have.
    ///
    /// R311y889 — SPLIT FROM ITS CONTROL, because the control was hiding it.
    ///
    /// The two were one test, control first, and on 2026-08-20 the hosted
    /// runner drew 256 DISTINCT ports through the old shape — a fact about that
    /// kernel — so the control asserted, the run went red, and the property
    /// below never executed at all. A failing step hides the ones after it,
    /// which this workspace has measured before; the arrangement meant the
    /// claim that matters was untested on exactly the host where the build runs.
    ///
    /// This arm asserts nothing about the kernel and runs everywhere.
    #[test]
    fn free_port_never_repeats() {
        let mut fresh = BTreeSet::new();
        // 32 numbers: each stays claimed until the process exits (see
        // `free_port`), and the witness for the ledger itself is
        // `a_candidate_handed_out_before_is_rejected`, which claims nothing.
        for _ in 0..32 {
            assert!(
                fresh.insert(free_port()),
                "free_port handed out a port twice in one process"
            );
        }
    }

    /// The ledger of `free_port`, with the repeat supplied instead of waited for.
    ///
    /// Three candidates: a number, the same number again, and a third. The
    /// first call takes the first. The second call must reject the repeat and
    /// take the third. A draw from a range of thousands would repeat once in
    /// many thousand tries, so waiting for one costs a claim per try; feeding
    /// the repeat costs none, and a ledger without its `contains` check hands
    /// the repeat out and fails here at once.
    #[test]
    fn a_candidate_handed_out_before_is_rejected() {
        let bound = || {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a probe bind");
            let port = listener.local_addr().expect("probe address").port();
            (listener, port)
        };
        let (one, first) = bound();
        let (two, _) = bound();
        let (three, third) = bound();
        // The repeat is the first number again, held by the second listener: the
        // function never reads the listener's own address.
        let mut script = vec![(one, first), (two, first), (three, third)].into_iter();
        let handed_first = hand_out(|| script.next().expect("a scripted candidate"));
        let handed_next = hand_out(|| script.next().expect("a scripted candidate"));
        assert_eq!(handed_first, first);
        assert_eq!(
            handed_next, third,
            "the repeat of {first} was handed out instead of being rejected"
        );
    }

    /// A number the pick hands out is in the ledger when it returns, and the ledger
    /// answers a second record of it with `false`.
    ///
    /// The cross-process claim is a `flock` and exists on unix only; on a host without
    /// it the ledger is what keeps two threads of the process from drawing one number
    /// before either has bound it. The pick used to hand a number out WITHOUT recording
    /// it (only `free_port` recorded, after the fact, and nothing consulted the ledger),
    /// so a unix host's `flock` hid the gap and Windows showed it: a dial accepted by
    /// another round's listener, 1 of 1200 on a hosted run. This reads the ledger directly,
    /// so it is red wherever the claim is, which no outcome of a bind could be.
    #[test]
    fn a_pick_records_its_number_and_a_second_record_is_refused() {
        let port = unbound_unautoselected();
        assert!(
            !record_in_process(port),
            "{port} was handed out by the pick and was not in the ledger: another thread \
             could be given it before this one binds"
        );
        // The ledger itself: a number is recorded once.
        assert!(record_in_process(1), "a number not handed out was refused");
        assert!(!record_in_process(1), "a number recorded twice");
    }

    /// Threads picking at once are never given one number, wherever the claim file is.
    #[test]
    fn threads_picking_at_once_are_given_distinct_numbers() {
        let pickers: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    (0..50)
                        .map(|_| unbound_unautoselected())
                        .collect::<Vec<u16>>()
                })
            })
            .collect();
        let all: Vec<u16> = pickers
            .into_iter()
            .flat_map(|picker| picker.join().expect("a picker thread"))
            .collect();
        let mut distinct = all.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            all.len(),
            "{} numbers were handed out to threads and {} of them were repeats",
            all.len(),
            all.len() - distinct.len()
        );
    }

    /// R311y889 — THE CONTROL, as a statement about the HOST rather than a
    /// verdict on the code.
    ///
    /// # Why this is not an assertion any more, and not a silent pass either
    ///
    /// Whether a kernel re-hands a just-released ephemeral port is a property
    /// of the kernel and its current port pressure. On a host that does, this
    /// number is what makes `free_port_never_repeats` a claim about a real
    /// race; on a host that does not, the race cannot be provoked and there is
    /// nothing here to fail — asserting turns "this runner behaves differently"
    /// into a broken build, which is what happened.
    ///
    /// So it PRINTS, and it asserts nothing.
    ///
    /// # Why there is no arming flag here, which is not the usual answer
    ///
    /// R311y889 gave this an env handle, on the model of the `WZ_..._REQUIRE`
    /// flags Layer Qz uses: green-with-a-reason where a precondition is
    /// genuinely absent, red where a lane has guaranteed it. R2254 (open-debt
    /// item 599) measured that no lane script and no workflow ever set it, and
    /// found that none COULD:
    ///
    ///   * the precondition is a kernel behaviour, not a file and not a
    ///     program, so it is outside the closed set of oracle kinds
    ///     `armed_oracle_census.py` can probe on a machine;
    ///   * and a lane that established it first would be arming on the result
    ///     of the very draw this test then judges, which can never disagree
    ///     with itself. Arming is vacuous BY CONSTRUCTION here, not merely
    ///     unwired.
    ///
    /// A handle no job can turn on is a verdict nobody can reach, so the
    /// branch is gone rather than left as a promise. What the anti-masking
    /// stance actually needs is served by `free_port_never_repeats`, which
    /// stands on its own; this test's job is to say how sharp the race is on
    /// the host reading it.
    #[test]
    fn the_old_shape_repeats_where_the_kernel_lets_it() {
        let (repeats, distinct, drawn) = old_shape_repeats();
        // Printed, not only judged: the number is how sharp the race is on this
        // host, and a reader comparing two runs wants it. `drawn` is printed
        // beside it because a low repeat count over few draws says nothing.
        std::println!(
            "old bind-read-drop shape: {repeats} repeat(s) in {drawn} draw(s) \
             ({distinct} distinct)"
        );
        if repeats == 0 {
            std::println!(
                "  this host does not reuse a released ephemeral port, so the \
                 race is unprovokable here. That is a fact about the kernel, \
                 and `free_port_never_repeats` stands on its own"
            );
        }
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

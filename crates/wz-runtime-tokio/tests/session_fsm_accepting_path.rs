// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R78 — Accepting-side path integration test.
//!
//! Walks the listener half of the 4-way handshake through the
//! production-shaped `poll_and_dispatch_one` driver so two crafted
//! inbound wires (InitSyn + OpenSyn) terminate at `Established`
//! without the test hand-routing
//! `parse_inbound + inbound_to_fsm_event + Engine::process_event`.
//!
//! Path under test:
//!   `Init -(inbound.start)-> AwaitingInitSyn
//!         -(Rx InitSyn via poll_and_dispatch_one)-> SentInitAck
//!         -(Rx OpenSyn via poll_and_dispatch_one)-> Established`
//!
//! The Initiator-side `Rx(InitAck)` scenario was already covered by
//! `session_fsm_driver_loop.rs::scenario_1` at R76; this complement
//! confirms `poll_and_dispatch_one` handles both halves of the
//! handshake symmetrically (it must, since the helper does not
//! discriminate Initiator vs Accepting — the FSM does).
//!
//! Single `#[test]` fn because the two phases (Rx InitSyn then Rx
//! OpenSyn) form one continuous handshake walk — phase 2 depends on
//! phase 1's resulting FSM state. R79 closed the cross-test race
//! carry that previously forced the mega-test pattern here, but
//! splitting this particular path-dependent flow gains no granularity.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use sce_rust_runtime::Engine;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    poll_and_dispatch_one, BoxedLinkDriver, PeerInitCaps, SessionLinkActions,
};
// R311fr — DriverLoopOutcome is referenced only by the
// transport-keepalive-gated r78 handshake test; gate the import to match
// so a transport-keepalive-off subset does not see an unused import.
#[cfg(feature = "transport-keepalive")]
use wz_runtime_tokio::session_glue::DriverLoopOutcome;
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, install_session_actions_for_test,
};

/// Inert outbound driver — the listener path triggers
/// `send_init_ack_with_cookie` and `send_open_ack` outbound;
/// `NoopOutboundDriver` swallows the bytes so the test focuses on
/// the FSM transitions, not the wire shape (Layer 3 interop tests
/// already cover the outbound wire bytes against zenoh-pico).
#[derive(Default)]
struct NoopOutboundDriver {
    _state: Mutex<()>,
}

impl BoxedLinkDriver for NoopOutboundDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) {}
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

/// Staged-event `LinkDriver`. Each `poll_event` call returns the
/// next `LinkEvent` from the queue; an empty queue yields
/// `Lost { PeerClosed }` so a forgotten staging step does not hang.
struct QueueDriver {
    events: VecDeque<LinkEvent>,
}

impl QueueDriver {
    fn with(events: Vec<LinkEvent>) -> Self {
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

// ─── Transport-header constants (mirror session_glue::wire_const) ──

const T_MID_INIT: u8 = 0x01;
const T_MID_OPEN: u8 = 0x02;
const FLAG_T_INIT_S: u8 = 0x40;

/// Hand-craft a minimal InitSyn wire frame matching the InitBody
/// decoder under `parent_flags = FLAG_T_INIT_S`:
///   - version (1)
///   - cbyte: whatami(Peer=0x01 wire) | (zid_len-1)<<4  (1)
///   - zid (4 bytes — `zid_len-1 = 3` in the cbyte high nibble)
///   - sn_res (1)
///   - batch_size LE u16 (2)
///
/// Cookie fields are gated by `FLAG_T_INIT_A` per zenoh-pico
/// transport.h §5.M; InitSyn omits the A bit so no cookie payload.
fn craft_initsyn_wire() -> Vec<u8> {
    vec![
        FLAG_T_INIT_S | T_MID_INIT,
        0x05, // version
        0x31, // cbyte: whatami=Peer wire(0x01), zid_len=4 (high nibble = 3)
        0xB0,
        0xB1,
        0xB2,
        0xB3, // peer zid (4 bytes)
        0x00, // sn_res (seq=0, req=0)
        0x00,
        0x00, // batch_size LE u16 = 0
    ]
}

/// Hand-craft an OpenSyn wire frame echoing a cookie. `parent_flags
/// = 0x00` (no FLAG_T_OPEN_A, no FLAG_T_OPEN_T) so the cookie
/// carrier is present (gated by `(parent_flags & 0x20) == 0` per
/// OpenBody decode) and the lease is interpreted in milliseconds:
///   - lease VLE = 0     (single byte 0x00)
///   - initial_sn VLE = 0 (single byte 0x00)
///   - cookie_len VLE = `cookie.len()` (assumed < 0x80 for single-byte VLE)
///   - cookie bytes
///
/// R89 — cookie payload is now required by the `cookie_valid()`
/// guard's HMAC verification (closes the R86 outbound mint loop).
/// Pre-R89 this function ignored `cookie` and emitted a zero-length
/// carrier; the guard was an unconditional `true` placeholder.
fn craft_opensyn_wire(cookie: &[u8]) -> Vec<u8> {
    assert!(cookie.len() < 0x80, "fixture: single-byte VLE only");
    let mut wire = vec![
        T_MID_OPEN,
        0x00,               // lease VLE = 0
        0x00,               // initial_sn VLE = 0
        cookie.len() as u8, // cookie_len VLE
    ];
    wire.extend_from_slice(cookie);
    wire
}

fn fresh_setup() -> (Arc<SessionLinkActions>, Engine<SessionFsmUnicastPolicy>) {
    let outbound: Arc<dyn BoxedLinkDriver> = Arc::new(NoopOutboundDriver::default());
    let actions =
        SessionLinkActions::new(outbound, fixture_session_init_params(), TokioTime::new());
    let lua = install_session_actions_for_test(actions.clone());
    let mut engine = Engine::new(SessionFsmUnicastPolicy::new(lua));
    engine.initialize();
    (actions, engine)
}

// R311fr — Established.onentry starts the keepalive worker only under
// `transport-keepalive`; the SSOT consumer-plane subsets omit it, so this
// handshake-termination test asserts that behaviour only where it exists.
#[cfg(feature = "transport-keepalive")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r78_accepting_path_handshake_terminates_at_established() {
    let (actions, mut engine) = fresh_setup();
    assert_eq!(engine.get_current_state(), S::Init);

    // Init -> AwaitingInitSyn via inbound.start (listener role
    // activation; the driver loop does not synthesize this — the
    // production caller dispatches it on socket-accept).
    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    // ── Rx InitSyn via poll_and_dispatch_one ───────────────────────
    {
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
            bytes: craft_initsyn_wire(),
        })]);
        let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
        assert!(
            matches!(outcome, DriverLoopOutcome::AdvancedFsm),
            "InitSyn Rx must AdvanceFsm; got {outcome:?}"
        );
        assert_eq!(
            engine.get_current_state(),
            S::SentInitAck,
            "Rx(InitSyn) must advance AwaitingInitSyn -> SentInitAck"
        );
        let trace = actions.trace_snapshot();
        assert_eq!(
            trace.send_init_ack_with_cookie, 1,
            "SentInitAck.onentry must dispatch send_init_ack_with_cookie"
        );
    }

    // ── Rx OpenSyn via poll_and_dispatch_one ───────────────────────
    {
        // R89 — the OpenSyn must echo the HMAC-bound cookie the
        // Accepting side minted on InitAck (R86) for the
        // `cookie_valid()` guard to pass. peer_zid was captured by
        // R86 on InitSyn arrival (= [0xB0..0xB3] from craft_initsyn_wire).
        let expected_cookie = wz_runtime_tokio::session_glue::generate_cookie_hmac_sha256(
            &fixture_session_init_params().cookie_signing_key,
            &[0xB0, 0xB1, 0xB2, 0xB3],
        );
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
            bytes: craft_opensyn_wire(&expected_cookie),
        })]);
        let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
        assert!(
            matches!(outcome, DriverLoopOutcome::AdvancedFsm),
            "OpenSyn Rx must AdvanceFsm; got {outcome:?}"
        );
        // SentOpenAck has an eventless transition to Established;
        // the SCXML macrostep traverses both states in one
        // process_event so the observable state is Established.
        assert_eq!(
            engine.get_current_state(),
            S::Established,
            "Rx(OpenSyn) must drive SentInitAck -> SentOpenAck -> Established"
        );

        let trace = actions.trace_snapshot();
        assert_eq!(
            trace.send_open_ack, 1,
            "SentOpenAck.onentry must dispatch send_open_ack"
        );
        // Established.onentry side effects (matches
        // session_fsm_coverage.rs::r61 listener-path assertions).
        assert_eq!(
            trace.enable_rx_tx_regions, 1,
            "Established.onentry must enable rx/tx regions"
        );
        assert_eq!(
            trace.start_lease_monitor, 1,
            "Established.onentry must start the lease monitor"
        );
        assert_eq!(
            trace.start_keepalive_worker, 1,
            "Established.onentry must start the keepalive worker"
        );
        // R89 — the cookie_valid() guard MUST have fired exactly
        // once on the SentInitAck -> SentOpenAck transition. The
        // happy-path OpenSyn arrival was the only candidate.
        assert_eq!(
            trace.cookie_valid_check, 1,
            "R89 dynamic guard must fire exactly once on the valid \
             OpenSyn cookie echo path; got count={}",
            trace.cookie_valid_check
        );
    }
}

// ───────────── R89 cookie verification negative paths ──────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r89_invalid_cookie_blocks_transition_to_sentopen_ack() {
    // Setup mirrors r78 happy path up through SentInitAck, then
    // stages an OpenSyn whose cookie is byte-mismatched against the
    // R86-minted HMAC. The cookie_valid() guard must reject the
    // transition and the FSM must stay at SentInitAck.
    let recording_driver = Arc::new(NoopOutboundDriver::default());
    let driver_arc: Arc<dyn BoxedLinkDriver> = recording_driver;
    let actions =
        SessionLinkActions::new(driver_arc, fixture_session_init_params(), TokioTime::new());
    let lua = install_session_actions_for_test(actions.clone());
    let mut engine = Engine::new(SessionFsmUnicastPolicy::new(lua));
    engine.initialize();

    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: craft_initsyn_wire(),
    })]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    // Forged cookie: 16 bytes of 0xFF — guaranteed to mismatch any
    // valid HMAC(cookie_signing_key, peer_zid) output.
    let forged = vec![0xFFu8; 16];
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: craft_opensyn_wire(&forged),
    })]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;

    assert_eq!(
        engine.get_current_state(),
        S::SentInitAck,
        "forged cookie must NOT advance the FSM past SentInitAck \
         (cookie_valid guard rejects); state={:?}",
        engine.get_current_state()
    );
    let trace = actions.trace_snapshot();
    assert!(
        trace.cookie_valid_check >= 1,
        "cookie_valid guard must have fired (and rejected); got count={}",
        trace.cookie_valid_check
    );
    assert_eq!(
        trace.send_open_ack, 0,
        "send_open_ack must NOT fire when cookie verification fails"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r89_missing_cookie_blocks_transition_to_sentopen_ack() {
    let recording_driver = Arc::new(NoopOutboundDriver::default());
    let driver_arc: Arc<dyn BoxedLinkDriver> = recording_driver;
    let actions =
        SessionLinkActions::new(driver_arc, fixture_session_init_params(), TokioTime::new());
    let lua = install_session_actions_for_test(actions.clone());
    let mut engine = Engine::new(SessionFsmUnicastPolicy::new(lua));
    engine.initialize();

    engine.process_event(E::InboundStart);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: craft_initsyn_wire(),
    })]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    // Zero-length cookie carrier: cookie_len VLE = 0, no cookie
    // bytes. OpenBody.cookie decodes as Some(Vec::new()) per the
    // present-if gating; the R89 guard sees an empty Vec which
    // never matches a non-empty HMAC output.
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: craft_opensyn_wire(&[]),
    })]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;

    assert_eq!(
        engine.get_current_state(),
        S::SentInitAck,
        "missing/empty cookie must NOT advance past SentInitAck"
    );
    let trace = actions.trace_snapshot();
    assert!(trace.cookie_valid_check >= 1);
    assert_eq!(trace.send_open_ack, 0);
}

// ────── R86 cookie HMAC binding (Accepting-side InitAck wire) ──────

/// Recording outbound driver that captures every send_blocking call
/// so R86's HMAC-bound cookie can be inspected post-dispatch. The
/// inert NoopOutboundDriver above discards bytes — fine for the R78
/// FSM-shape walk, but R86 needs the InitAck wire bytes.
#[derive(Default)]
struct RecordingOutboundDriver {
    sent: Mutex<Vec<Vec<u8>>>,
}

impl BoxedLinkDriver for RecordingOutboundDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        self.sent.lock().unwrap().push(bytes.to_vec());
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r86_send_init_ack_with_cookie_binds_to_inbound_peer_zid() {
    use wz_runtime_tokio::session_glue::{
        generate_cookie_hmac_sha256, parse_inbound, InboundFrame,
    };

    // Setup with a RecordingOutboundDriver so the InitAck wire bytes
    // are captured for cookie inspection.
    let recording_driver = Arc::new(RecordingOutboundDriver::default());
    let driver_arc: Arc<dyn BoxedLinkDriver> = recording_driver.clone();
    let params = fixture_session_init_params();
    let actions = SessionLinkActions::new(driver_arc, params, TokioTime::new());
    let lua = install_session_actions_for_test(actions.clone());
    let mut engine = Engine::new(SessionFsmUnicastPolicy::new(lua));
    engine.initialize();

    // Init -> AwaitingInitSyn (listener role activation)
    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    // Rx InitSyn (zid = [0xB0..0xB3] per craft_initsyn_wire) routes
    // through poll_and_dispatch_one -> handle_inbound captures
    // peer_zid -> FSM transitions to SentInitAck -> SentInitAck.onentry
    // fires send_init_ack_with_cookie which (per R86) HMAC-binds the
    // cookie against the captured peer_zid.
    let mut queue_driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: craft_initsyn_wire(),
    })]);
    let _ = poll_and_dispatch_one(&mut queue_driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);
    assert_eq!(
        actions.inbound_peer_zid.lock().unwrap().as_deref(),
        Some(&[0xB0, 0xB1, 0xB2, 0xB3][..]),
        "InitSyn dispatch must capture peer_zid before SentInitAck.onentry fires"
    );

    // The InitAck wire was just sent through the recording driver.
    let sends = recording_driver.sent.lock().unwrap().clone();
    assert_eq!(sends.len(), 1, "exactly one outbound frame (the InitAck)");
    let initack_wire = &sends[0];

    // Re-parse the wire and pull out the cookie field. The InitAck
    // re-encode path is verified byte-identical against zenoh-pico by
    // layer3_init_body.rs; here we just need the cookie value.
    let frame = parse_inbound(initack_wire).expect("outbound InitAck wire re-parses");
    let cookie = match frame {
        InboundFrame::Init {
            is_ack: true, body, ..
        } => body.cookie.expect("InitAck carries cookie payload"),
        other => panic!(
            "expected InitAck variant, got {other:?}",
            other = std::any::type_name_of_val(&other)
        ),
    };

    // The expected cookie is HMAC-SHA256(cookie_signing_key, peer_zid)
    // truncated to 16 bytes per RFC §5.M. Recompute it inline using
    // the same fixture key so the test is independent of the cookie
    // module's internal constants.
    let expected_cookie = generate_cookie_hmac_sha256(
        &fixture_session_init_params().cookie_signing_key,
        &[0xB0, 0xB1, 0xB2, 0xB3],
    );
    assert_eq!(
        cookie, expected_cookie,
        "R86: outbound InitAck cookie MUST be HMAC(cookie_signing_key, \
         inbound_peer_zid)[..16] — pre-R86 this was params.cookie verbatim \
         which violated RFC §5.M anti-amplification (deploy-static cookie \
         offers no per-peer replay defense)"
    );
}

// ── R311fb staleness guard: once the accept handshake reaches Established,
//    a stale accepting.inactivity_timeout (armed on AwaitingInitSyn entry,
//    delivered after Established) must be discarded. Established is outside
//    the Accepting state that handles the event, so the single armed timer
//    has no handler in scope and cannot kill a healthy session. The
//    single-arm parent-scoped design needs no per-phase child-scoping (unlike
//    R311fa's init_ack/open_ack timers) precisely because there is only ever
//    one timer of this event name in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311fb_stale_accept_inactivity_timeout_after_established_is_discarded() {
    let (actions, mut engine) = fresh_setup();
    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    // Walk the crafted handshake to Established (same wires as r78).
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: craft_initsyn_wire(),
    })]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    let cookie = wz_runtime_tokio::session_glue::generate_cookie_hmac_sha256(
        &fixture_session_init_params().cookie_signing_key,
        &[0xB0, 0xB1, 0xB2, 0xB3],
    );
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: craft_opensyn_wire(&cookie),
    })]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::Established);

    // Deliver the now-stale accept inactivity timer.
    engine.process_event(E::AcceptingInactivityTimeout);

    assert_eq!(
        engine.get_current_state(),
        S::Established,
        "a stale accepting.inactivity_timeout after Established must be \
         discarded (no handler in scope), leaving the session healthy"
    );
    assert_eq!(
        actions.trace_snapshot().set_close_reason_count,
        0,
        "the discarded stale timer must not run any close-reason action"
    );
}

// ───────────── R121d peer-caps negotiation unit tests ──────────────

#[test]
fn r121d_peer_init_caps_from_init_syn_uses_defaults_when_s_bit_clear() {
    // When the peer's InitSyn carries `_Z_FLAG_T_INIT_S=0`, the
    // `sn_res` byte and `batch_size` are absent on the wire; the
    // decoder must substitute the Zenoh defaults
    // (`_Z_DEFAULT_RESOLUTION_SIZE=2`, `_Z_DEFAULT_UNICAST_BATCH_SIZE
    // =65535`) so the downstream `min(own, peer)` cap in
    // `init_ack_params` keeps the own params verbatim (peer's stated
    // ceiling is the maximum).
    let caps = PeerInitCaps::from_init_syn(None, None);
    assert_eq!(caps.seq_num_res, 2);
    assert_eq!(caps.req_id_res, 2);
    assert_eq!(caps.batch_size, 65535);
}

// R311fr — PeerInitCaps decode is `transport-batching`-gated; the SSOT
// consumer-plane subsets omit transport-batching, so this caps-behaviour
// test runs only where the caps decoder is compiled in.
#[cfg(feature = "transport-batching")]
#[test]
fn r121d_peer_init_caps_decodes_packed_sn_res_byte() {
    // The InitSyn `sn_res` byte is packed
    // `(seq & 0x03) | ((req & 0x03) << 2)` per zenoh-pico
    // transport.c:196-197. Encoder shape: seq=1, req=2 →
    // 0x01 | (0x02 << 2) = 0x09. Decoder must invert that
    // composition exactly.
    let caps = PeerInitCaps::from_init_syn(Some(0x09), Some(1024));
    assert_eq!(caps.seq_num_res, 1, "low 2 bits are seq_num_res");
    assert_eq!(caps.req_id_res, 2, "next 2 bits are req_id_res");
    assert_eq!(caps.batch_size, 1024);
}

// R311fr — InitAck caps negotiation is `transport-batching` behaviour.
#[cfg(feature = "transport-batching")]
#[test]
fn r121d_init_ack_params_caps_to_peer_when_peer_lower() {
    // The wire-spec invariant `InitAck.size <= InitSyn.size`
    // (zenoh-pico unicast/transport.c:123-140) requires the
    // Accepting side to cap each sizing field to `min(own, peer)`.
    // Construct an actions instance whose own params announce
    // permissive ceilings, capture a peer with stricter caps via
    // the inbound slot, and verify `init_ack_params` flattens the
    // three fields to the peer's stricter values.
    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopOutboundDriver::default());
    let mut params = fixture_session_init_params();
    params.seq_num_res = 3;
    params.req_id_res = 3;
    params.batch_size = 65535;
    let actions = SessionLinkActions::new(driver, params, TokioTime::new());

    // No peer InitSyn parsed yet → init_ack_params returns own
    // params verbatim (the slot is `None`).
    let p = actions.init_ack_params();
    assert_eq!(p.seq_num_res, 3);
    assert_eq!(p.req_id_res, 3);
    assert_eq!(p.batch_size, 65535);

    // Capture peer caps with stricter values across the board.
    *actions.inbound_peer_init_caps.lock().unwrap() = Some(PeerInitCaps {
        seq_num_res: 2,
        req_id_res: 1,
        batch_size: 2048,
    });
    let p = actions.init_ack_params();
    assert_eq!(p.seq_num_res, 2, "seq_num_res capped to peer");
    assert_eq!(p.req_id_res, 1, "req_id_res capped to peer");
    assert_eq!(p.batch_size, 2048, "batch_size capped to peer");
}

#[test]
fn r121d_init_ack_params_keeps_own_when_own_lower() {
    // Symmetric case — when our own announced caps are stricter
    // than the peer's, `min(own, peer) = own`. Verifies the cap
    // never accidentally promotes a value upward.
    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopOutboundDriver::default());
    let mut params = fixture_session_init_params();
    params.seq_num_res = 1;
    params.req_id_res = 1;
    params.batch_size = 512;
    let actions = SessionLinkActions::new(driver, params, TokioTime::new());

    *actions.inbound_peer_init_caps.lock().unwrap() = Some(PeerInitCaps {
        seq_num_res: 3,
        req_id_res: 3,
        batch_size: 65535,
    });
    let p = actions.init_ack_params();
    assert_eq!(p.seq_num_res, 1, "own seq_num_res preserved (1 < 3)");
    assert_eq!(p.req_id_res, 1, "own req_id_res preserved (1 < 3)");
    assert_eq!(p.batch_size, 512, "own batch_size preserved (512 < 65535)");
}

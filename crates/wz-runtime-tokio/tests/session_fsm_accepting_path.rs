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
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    poll_and_dispatch_one, BoxedLinkDriver, DriverLoopOutcome,
    SessionLinkActions,
};
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
    async fn send(
        &mut self,
        _frame: &TxFrame<'_>,
        _reliability: Reliability,
    ) -> io::Result<()> {
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
        0xB0, 0xB1, 0xB2, 0xB3, // peer zid (4 bytes)
        0x00, // sn_res (seq=0, req=0)
        0x00, 0x00, // batch_size LE u16 = 0
    ]
}

/// Hand-craft a minimal OpenSyn wire frame. `parent_flags = 0x00`
/// (no FLAG_T_OPEN_A, no FLAG_T_OPEN_T) so the cookie carrier is
/// present (gated by `(parent_flags & 0x20) == 0` per OpenBody
/// decode) and the lease is interpreted in milliseconds:
///   - lease VLE = 0     (single byte 0x00)
///   - initial_sn VLE = 0 (single byte 0x00)
///   - cookie_len VLE = 0 (single byte 0x00) — empty cookie carrier
fn craft_opensyn_wire() -> Vec<u8> {
    vec![
        T_MID_OPEN,
        0x00, // lease VLE = 0
        0x00, // initial_sn VLE = 0
        0x00, // cookie_len VLE = 0
    ]
}

fn fresh_setup() -> (Arc<SessionLinkActions>, Engine<SessionFsmUnicastPolicy>) {
    let outbound: Arc<dyn BoxedLinkDriver> = Arc::new(NoopOutboundDriver::default());
    let actions = SessionLinkActions::new(outbound, fixture_session_init_params());
    let lua = install_session_actions_for_test(actions.clone());
    let mut engine = Engine::new(SessionFsmUnicastPolicy::new(lua));
    engine.initialize();
    (actions, engine)
}

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
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
            bytes: craft_opensyn_wire(),
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
    }
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
    use wz_runtime_tokio::session_glue::{generate_cookie_hmac_sha256, parse_inbound, InboundFrame};

    // Setup with a RecordingOutboundDriver so the InitAck wire bytes
    // are captured for cookie inspection.
    let recording_driver = Arc::new(RecordingOutboundDriver::default());
    let driver_arc: Arc<dyn BoxedLinkDriver> = recording_driver.clone();
    let params = fixture_session_init_params();
    let actions = SessionLinkActions::new(driver_arc, params);
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
        InboundFrame::Init { is_ack: true, body, .. } => {
            body.cookie.expect("InitAck carries cookie payload")
        }
        other => panic!("expected InitAck variant, got {other:?}", other = std::any::type_name_of_val(&other)),
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

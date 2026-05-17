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
//! Single mega-test on purpose (R71b singleton-race carry — Lua
//! engine + INSTALLED OnceLock are process-global).

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

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R76 — production driver-loop wiring tests.
//!
//! Exercises `poll_and_dispatch_one`, the production-shaped helper
//! that pulls a `LinkEvent` from a `LinkDriver` and routes it through
//! `handle_inbound` + `inbound_to_fsm_event` + `Engine::process_event`
//! so the session FSM advances without the caller hand-wiring the
//! chain.
//!
//! This is the consumer wiring for the R68/R68a/R68c/R69b/R72/R73
//! inbound work — without it, those 8 commits would land as
//! production-unreachable helpers.
//!
//! Single mega-test on purpose. The Lua engine + INSTALLED OnceLock
//! are process-global; splitting scenarios into per-`#[test]`
//! functions causes cargo's thread-parallel runner to race on
//! `install_session_actions_for_test` (carry from R71b — fixed in a
//! later round once the SCE `bind_native_object` upstream lands).

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use sce_rust_runtime::Engine;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    install_session_actions, poll_and_dispatch_one, BoxedLinkDriver, DriverLoopOutcome,
    SessionLinkActions,
};
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, install_session_actions_for_test,
};

/// Inert outbound driver — `SessionLinkActions::new` requires one
/// for the Lua-closure capture path, but `poll_and_dispatch_one`
/// drives the inbound `LinkDriver` independently, so the outbound
/// trace counters from this driver are unused in these scenarios.
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

// ─── Wire-bytes helpers (mirror session_fsm_inbound_dispatch.rs) ──

const T_MID_INIT: u8 = 0x01;
const T_MID_KEEP_ALIVE: u8 = 0x04;
const FLAG_T_INIT_S: u8 = 0x40;
const FLAG_T_INIT_A: u8 = 0x20;

fn craft_initack_wire(cookie: &[u8]) -> Vec<u8> {
    let parent_flags = FLAG_T_INIT_S | FLAG_T_INIT_A;
    let mut wire = vec![
        parent_flags | T_MID_INIT,
        0x05, // version
        0x31, // cbyte: whatami=Peer, zid_len=4
        0xA0, 0xA1, 0xA2, 0xA3, // zid (4 bytes)
        0x00, // sn_res
        0x00, 0x00, // batch_size LE u16
        cookie.len() as u8, // VLE cookie_len < 0x80
    ];
    wire.extend_from_slice(cookie);
    wire
}

fn fresh_setup() -> (Arc<SessionLinkActions>, Engine<SessionFsmUnicastPolicy>) {
    let outbound: Arc<dyn BoxedLinkDriver> =
        Arc::new(NoopOutboundDriver::default());
    let actions = SessionLinkActions::new(outbound, fixture_session_init_params());
    if install_session_actions(actions.clone()).is_err() {
        install_session_actions_for_test(actions.clone());
    }
    let mut engine = Engine::new(SessionFsmUnicastPolicy::new());
    engine.initialize();
    (actions, engine)
}

fn drive_to_sent_init_syn(engine: &mut Engine<SessionFsmUnicastPolicy>) {
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    assert_eq!(engine.get_current_state(), S::SentInitSyn);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r76_poll_and_dispatch_one_covers_link_event_to_fsm_paths() {
    // ── Scenario 1: Rx(InitAck) → AdvancedFsm + state=GotInitAck ─
    {
        let (actions, mut engine) = fresh_setup();
        drive_to_sent_init_syn(&mut engine);

        let cookie = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let wire = craft_initack_wire(&cookie);
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
            bytes: wire,
        })]);

        let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
        assert!(
            matches!(outcome, DriverLoopOutcome::AdvancedFsm),
            "InitAck Rx must AdvanceFsm; got {outcome:?}"
        );
        assert_eq!(
            engine.get_current_state(),
            S::GotInitAck,
            "Rx(InitAck) must advance SentInitSyn -> GotInitAck"
        );
        // R68a cookie capture invariant still applies through the
        // helper (handle_inbound runs inside poll_and_dispatch_one).
        let captured = actions.inbound_cookie.lock().unwrap().clone();
        assert_eq!(captured.as_deref(), Some(cookie.as_slice()));
    }

    // ── Scenario 2: Rx(KeepAlive) → SideEffectOnly, state unchanged
    {
        let (actions, mut engine) = fresh_setup();
        drive_to_sent_init_syn(&mut engine);
        let pre_state = engine.get_current_state();
        assert!(
            actions.last_inbound_keepalive_at.lock().unwrap().is_none(),
            "keepalive slot empty before Rx"
        );

        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
            bytes: vec![T_MID_KEEP_ALIVE],
        })]);

        let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
        assert!(
            matches!(outcome, DriverLoopOutcome::SideEffectOnly),
            "KeepAlive Rx must SideEffectOnly; got {outcome:?}"
        );
        assert_eq!(
            engine.get_current_state(),
            pre_state,
            "KeepAlive must not advance FSM"
        );
        assert!(
            actions.last_inbound_keepalive_at.lock().unwrap().is_some(),
            "KeepAlive must populate lease-timestamp slot via handle_inbound"
        );
    }

    // ── Scenario 3: Rx(malformed) → ParseError + FSM moves via
    //                framing.error to Closing
    {
        let (_actions, mut engine) = fresh_setup();
        drive_to_sent_init_syn(&mut engine);

        // 2-byte truncated InitAck — header says "InitAck present"
        // but the body cuts off before the version byte. parse_inbound
        // returns NeedMoreBytes, the helper raises FramingError.
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
            bytes: vec![FLAG_T_INIT_S | FLAG_T_INIT_A | T_MID_INIT],
        })]);

        let outcome = poll_and_dispatch_one(&mut driver, &_actions, &mut engine).await;
        assert!(
            matches!(outcome, DriverLoopOutcome::ParseError(_)),
            "truncated wire must surface ParseError; got {outcome:?}"
        );
        assert_eq!(
            engine.get_current_state(),
            S::Closing,
            "FramingError event must transition SentInitSyn -> Closing"
        );
    }

    // ── Scenario 4: Lost{PeerClosed} → LinkLost outcome + FSM
    //                advances via link.lost transition
    {
        let (_actions, mut engine) = fresh_setup();
        drive_to_sent_init_syn(&mut engine);

        let mut driver = QueueDriver::with(vec![LinkEvent::Lost {
            cause: LostCause::PeerClosed,
        }]);

        let outcome = poll_and_dispatch_one(&mut driver, &_actions, &mut engine).await;
        match outcome {
            DriverLoopOutcome::LinkLost(LostCause::PeerClosed) => (),
            other => panic!("Lost must surface LinkLost(PeerClosed); got {other:?}"),
        }
        // session-fsm: SentInitSyn + link.lost -> Closing (or Closed
        // direct depending on the SCXML edge; both are valid
        // terminations). The assertion accepts either.
        let st = engine.get_current_state();
        assert!(
            matches!(st, S::Closing | S::Closed),
            "link.lost must drive toward terminal; got {st:?}"
        );
    }

    // ── Scenario 5: Ready → LinkOpened mapping; engine advances
    //                LinkOpening -> SentInitSyn via the helper
    {
        let (_actions, mut engine) = fresh_setup();
        engine.process_event(E::OutboundStart);
        assert_eq!(engine.get_current_state(), S::LinkOpening);

        let mut driver = QueueDriver::with(vec![LinkEvent::Ready]);
        let outcome = poll_and_dispatch_one(&mut driver, &_actions, &mut engine).await;
        assert!(
            matches!(outcome, DriverLoopOutcome::AdvancedFsm),
            "Ready must AdvanceFsm; got {outcome:?}"
        );
        assert_eq!(
            engine.get_current_state(),
            S::SentInitSyn,
            "Ready -> LinkOpened must advance LinkOpening -> SentInitSyn"
        );
    }
}

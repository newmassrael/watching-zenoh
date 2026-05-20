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
//! R80 — each LinkEvent → outcome mapping is now an independent
//! `#[tokio::test]` fn (was bundled into a single mega-test before
//! R79 closed the cross-test race carry by retiring the process-global
//! `INSTALLED` OnceLock + Lua singleton). Each test owns its own
//! `LuaEngine` via `install_session_actions_for_test`.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use sce_rust_runtime::Engine;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    poll_and_dispatch_one, BoxedLinkDriver, DriverLoopOutcome, NetworkMessage,
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
    let lua = install_session_actions_for_test(actions.clone());
    let mut engine = Engine::new(SessionFsmUnicastPolicy::new(lua));
    engine.initialize();
    (actions, engine)
}

fn drive_to_sent_init_syn(engine: &mut Engine<SessionFsmUnicastPolicy>) {
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    assert_eq!(engine.get_current_state(), S::SentInitSyn);
}

// ── Scenario 1: Rx(InitAck) → AdvancedFsm + state=GotInitAck ─
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r76_rx_init_ack_advances_to_got_init_ack() {
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r76_rx_keepalive_side_effect_only_populates_lease_slot() {
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r76_rx_malformed_surfaces_parse_error_and_framing_close() {
    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    // 2-byte truncated InitAck — header says "InitAck present"
    // but the body cuts off before the version byte. parse_inbound
    // returns NeedMoreBytes, the helper raises FramingError.
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: vec![FLAG_T_INIT_S | FLAG_T_INIT_A | T_MID_INIT],
    })]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r76_link_lost_peer_closed_drives_toward_terminal() {
    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    let mut driver = QueueDriver::with(vec![LinkEvent::Lost {
        cause: LostCause::PeerClosed,
    }]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
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

// ── R74 Scenario A: Rx(Frame) with empty payload → FramePayload
//                    with messages=[]; FSM unchanged
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r74_rx_frame_with_empty_payload_surfaces_framepayload() {
    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);
    let pre_state = engine.get_current_state();

    // T_MID_FRAME (0x05) without R flag, sn=0 VLE single byte, empty
    // tail payload. R74 dispatch must surface this as FramePayload
    // (not SideEffectOnly) so the application layer sees the Frame.
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: vec![0x05, 0x00],
    })]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    match outcome {
        DriverLoopOutcome::FramePayload {
            reliable,
            sn,
            ref messages,
            has_ext,
            ref extensions,
        } => {
            assert!(!reliable, "no R flag → best-effort");
            assert_eq!(sn, 0);
            assert!(messages.is_empty(), "empty tail → empty batch");
            assert!(!has_ext);
            assert!(extensions.is_empty());
        }
        _ => panic!("expected FramePayload outcome, got {outcome:?}"),
    }
    assert_eq!(
        engine.get_current_state(),
        pre_state,
        "Frame receipt is not a session-state trigger"
    );
}

// ── R74 Scenario B: Rx(Frame) with payload carrying a single
//                    Unknown MID → FramePayload with Unknown record
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r74_rx_frame_unknown_network_mid_absorbs_as_unknown() {
    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    // T_MID_FRAME | R flag = 0x25, sn=1 VLE (0x01), tail payload
    // = [0x00, 0xAA, 0xBB] — 0x00 is a synthetic network MID outside
    // the {0x19..0x1F} authored set (INTEREST / RESPONSE_FINAL /
    // RESPONSE / REQUEST / PUSH / DECLARE / OAM are the 7 wz-typed
    // network MIDs as of R115's DECLARE inbound dispatch land). The
    // R74 Unknown-MID dispatch path used 0x1E (DECLARE) historically
    // because that was the last un-typed MID; the R97 + R110 + R115
    // catalog completion forced a refactor to a synthetic out-of-range
    // value so the Unknown coverage stays meaningful.
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: vec![0x25, 0x01, 0x00, 0xAA, 0xBB],
    })]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    match outcome {
        DriverLoopOutcome::FramePayload {
            reliable,
            sn,
            messages,
            ..
        } => {
            assert!(reliable, "R flag set → reliable=true");
            assert_eq!(sn, 1);
            assert_eq!(messages.len(), 1);
            match &messages[0] {
                NetworkMessage::Unknown { mid, body } => {
                    assert_eq!(*mid, 0x00);
                    assert_eq!(body.as_slice(), &[0x00, 0xAA, 0xBB]);
                }
                NetworkMessage::Request(_)
                | NetworkMessage::Push(_)
                | NetworkMessage::ResponseFinal(_)
                | NetworkMessage::Oam(_)
                | NetworkMessage::Interest(_)
                | NetworkMessage::Response(_)
                | NetworkMessage::Declare(_) => {
                    panic!(
                        "synthetic MID 0x00 must NOT dispatch to any typed decoder"
                    )
                }
            }
        }
        other => panic!("expected FramePayload, got {other:?}"),
    }
}

// ── R90 Scenario: Rx(Frame) with PUSH payload → FramePayload
//                  containing Push variant decoded via wz_codecs::push
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r90_rx_frame_push_payload_decodes_via_push_codec() {
    use wz_codecs::push::Push;

    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    // Build a round-trip-safe Push (header = N_MID_PUSH = 0x1D,
    // other fields default). After R88 variant-default-uniformity:
    // Push::default().body = CodecZenohMsgPut(MsgPut::default())
    // with MsgPut.header = 0x01 baked in → byte-exact roundtrip.
    let push = Push {
        header: 0x1D,
        ..Push::default()
    };
    let push_bytes = push.encode_to_vec();

    // Frame envelope: T_MID_FRAME | R flag = 0x25, sn=2 VLE = 0x02,
    // tail = push_bytes.
    let mut frame_wire = vec![0x25, 0x02];
    frame_wire.extend_from_slice(&push_bytes);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: frame_wire,
    })]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    match outcome {
        DriverLoopOutcome::FramePayload {
            reliable,
            sn,
            messages,
            ..
        } => {
            assert!(reliable);
            assert_eq!(sn, 2);
            assert_eq!(messages.len(), 1, "exactly one Push record; got {messages:?}");
            assert!(
                matches!(messages[0], NetworkMessage::Push(_)),
                "PUSH MID 0x1D dispatches to wz_codecs::push decoder"
            );
        }
        other => panic!("expected FramePayload, got {other:?}"),
    }
}

// ── R74 Scenario C: Rx(Frame) with malformed payload (Request MID
//                    but truncated body) → ParseError + FramingError
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r74_rx_frame_malformed_request_payload_surfaces_parse_error() {
    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    // Frame envelope OK (header + sn=0), but payload = [0x1C] alone
    // — Request::decode consumes the header then needs rid VLE bytes
    // that don't exist. parse_frame_payload returns CodecError;
    // poll_and_dispatch_one must surface ParseError AND fire
    // FramingError into the FSM (SentInitSyn -> Closing edge).
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame {
        bytes: vec![0x05, 0x00, 0x1C],
    })]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::ParseError(_)),
        "malformed application-layer payload must surface ParseError; \
         got {outcome:?}"
    );
    assert_eq!(
        engine.get_current_state(),
        S::Closing,
        "framing.error event from R74 path must transition \
         SentInitSyn -> Closing (consistent with R76 transport-layer \
         malformed-wire policy)"
    );
}

// ── Scenario 5: Ready → LinkOpened mapping; engine advances
//                LinkOpening -> SentInitSyn via the helper
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r76_ready_maps_to_link_opened_event() {
    let (actions, mut engine) = fresh_setup();
    engine.process_event(E::OutboundStart);
    assert_eq!(engine.get_current_state(), S::LinkOpening);

    let mut driver = QueueDriver::with(vec![LinkEvent::Ready]);
    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
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

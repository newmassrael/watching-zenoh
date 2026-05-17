// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R69b integration test — drives the Initiator path through a real
//! `Engine<SessionFsmUnicastPolicy>`, then routes a wire-equivalent
//! InitAck through `parse_inbound + inbound_to_fsm_event` to advance
//! the FSM from `Opening` to `GotInitAck`. Closes the loop opened
//! by R68a (inbound parse) + R68c (ext decode): the parsed inbound
//! event now actually advances the session FSM, not just the
//! `inbound_cookie` slot.
//!
//! Path under test:
//!   `Init ─(outbound.start)→ LinkOpening
//!         ─(link.opened)→ Opening (SentInitSyn substate)
//!         ─(init_ack.received)→ GotInitAck`
//!
//! The InitAck event is NOT raised directly — it flows through:
//!   1. `parse_inbound(wire_bytes)` decodes the transport header +
//!      InitBody.
//!   2. `SessionLinkActions::handle_inbound` populates
//!      `inbound_cookie` with the InitAck cookie field.
//!   3. `inbound_to_fsm_event(&frame)` projects the typed event
//!      variant.
//!   4. `engine.process_event(event)` advances the FSM.

use std::sync::{Arc, Mutex};

use sce_rust_runtime::Engine;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent, SessionFsmUnicastPolicy, SessionFsmUnicastState,
};
use wz_runtime_tokio::session_glue::{
    inbound_to_fsm_event, install_session_actions, rebind_session_actions_for_test,
    BoxedLinkDriver, SessionInitParams, SessionLinkActions,
};
use wz_runtime_tokio::Reliability;

#[derive(Default)]
struct NoopDriver {
    _state: Mutex<()>,
}

impl BoxedLinkDriver for NoopDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) {}
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

// Transport header + body bits — mirrors session_glue::wire_const
// (private). Test stays self-contained.
const T_MID_INIT: u8 = 0x01;
const FLAG_T_INIT_S: u8 = 0x40;
const FLAG_T_INIT_A: u8 = 0x20;

/// Hand-craft a minimal InitAck wire frame matching what
/// `parse_inbound` expects. Avoids pulling zenoh-pico-sys into
/// `wz-runtime-tokio`'s test dep set — the byte layout is identical
/// to the pico-encoded fixtures already verified by
/// `wz-integration-tests/tests/layer3_inbound_init.rs`.
fn craft_initack_wire(cookie: &[u8]) -> Vec<u8> {
    let parent_flags = FLAG_T_INIT_S | FLAG_T_INIT_A;
    // cbyte = whatami_wire (Peer=0x02 >> 1 = 0x01) | (zid_len_m1=3 << 4) = 0x31.
    let mut wire = vec![
        parent_flags | T_MID_INIT,
        0x05, // version
        0x31, // cbyte: whatami=Peer, zid_len=4
        0xA0, 0xA1, 0xA2, 0xA3, // zid (4 bytes)
        0x00, // sn_res (seq=0, req=0)
        0x00, 0x00, // batch_size = 0 (LE u16)
        cookie.len() as u8, // VLE cookie_len (< 0x80 so single byte)
    ];
    wire.extend_from_slice(cookie);
    wire
}

#[test]
fn inbound_initack_routes_through_parser_to_fsm_advancing_state() {
    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopDriver::default());
    let actions = SessionLinkActions::new(driver, SessionInitParams::for_test());
    if install_session_actions(actions.clone()).is_err() {
        rebind_session_actions_for_test(actions.clone());
    }

    let mut engine: Engine<SessionFsmUnicastPolicy> =
        Engine::new(SessionFsmUnicastPolicy::new());
    engine.initialize();
    assert_eq!(engine.get_current_state(), SessionFsmUnicastState::Init);

    // Init → LinkOpening (outbound start).
    engine.process_event(SessionFsmUnicastEvent::OutboundStart);
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::LinkOpening
    );

    // LinkOpening → Opening / SentInitSyn (link opened by driver).
    engine.process_event(SessionFsmUnicastEvent::LinkOpened);
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::SentInitSyn,
        "link.opened must compound-enter Opening → SentInitSyn"
    );

    // Stage the peer-supplied cookie inside the wire bytes. R68a's
    // handle_inbound capture path populates inbound_cookie with this.
    let peer_cookie = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x11, 0x22, 0x33, 0x44];
    let wire = craft_initack_wire(&peer_cookie);

    // R69b — route the inbound bytes through the parser + projector.
    let frame = actions
        .handle_inbound(&wire)
        .expect("handle_inbound on synthetic InitAck");
    let event = inbound_to_fsm_event(&frame)
        .expect("InitAck must project to a typed FSM event (non-KeepAlive)");
    assert_eq!(
        event,
        SessionFsmUnicastEvent::InitAckReceived,
        "InitAck frame must project to InitAckReceived"
    );

    engine.process_event(event);
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::GotInitAck,
        "init_ack.received from inbound parser must advance FSM to GotInitAck"
    );

    // R68a cookie capture invariant — the cookie bytes from the
    // synthetic wire surface in `inbound_cookie` for the next
    // OpenSyn outbound to echo per RFC §5.M.
    let captured = actions.inbound_cookie.lock().unwrap().clone();
    assert_eq!(
        captured.as_deref(),
        Some(peer_cookie.as_slice()),
        "inbound parser must populate inbound_cookie with peer's bytes"
    );
}

#[test]
fn inbound_to_fsm_event_covers_every_inbound_variant() {
    use wz_codecs::close::Close;
    use wz_codecs::init_body::InitBody;
    use wz_codecs::open_body::OpenBody;
    use wz_runtime_tokio::session_glue::InboundFrame;

    let init_syn = InboundFrame::Init {
        is_ack: false,
        has_ext: false,
        body: InitBody::default(),
        extensions: Vec::new(),
    };
    assert_eq!(
        inbound_to_fsm_event(&init_syn),
        Some(SessionFsmUnicastEvent::InitSynReceived)
    );

    let init_ack = InboundFrame::Init {
        is_ack: true,
        has_ext: false,
        body: InitBody::default(),
        extensions: Vec::new(),
    };
    assert_eq!(
        inbound_to_fsm_event(&init_ack),
        Some(SessionFsmUnicastEvent::InitAckReceived)
    );

    let open_syn = InboundFrame::Open {
        is_ack: false,
        lease_in_seconds: false,
        has_ext: false,
        body: OpenBody::default(),
        extensions: Vec::new(),
    };
    assert_eq!(
        inbound_to_fsm_event(&open_syn),
        Some(SessionFsmUnicastEvent::OpenSynReceived)
    );

    let open_ack = InboundFrame::Open {
        is_ack: true,
        lease_in_seconds: false,
        has_ext: false,
        body: OpenBody::default(),
        extensions: Vec::new(),
    };
    assert_eq!(
        inbound_to_fsm_event(&open_ack),
        Some(SessionFsmUnicastEvent::OpenAckReceived)
    );

    let close = InboundFrame::Close {
        reason: Close::default().reason,
        has_ext: false,
        extensions: Vec::new(),
    };
    assert_eq!(
        inbound_to_fsm_event(&close),
        Some(SessionFsmUnicastEvent::PeerClose)
    );

    let keep_alive = InboundFrame::KeepAlive {
        has_ext: false,
        extensions: Vec::new(),
    };
    assert_eq!(
        inbound_to_fsm_event(&keep_alive),
        None,
        "KeepAlive is a side-effect signal, not an FSM transition"
    );

    let unknown = InboundFrame::Unknown { mid: 0x1F };
    assert_eq!(
        inbound_to_fsm_event(&unknown),
        Some(SessionFsmUnicastEvent::FramingError)
    );
}

#[test]
fn parse_inbound_decodes_keep_alive_frame() {
    use wz_runtime_tokio::session_glue::{parse_inbound, InboundFrame};

    // MID=0x04 (T_MID_KEEP_ALIVE), no flags set, body is zero bytes.
    let wire = [0x04u8];
    let frame = parse_inbound(&wire).expect("parse_inbound on KeepAlive wire");
    match frame {
        InboundFrame::KeepAlive { has_ext, extensions } => {
            assert!(!has_ext);
            assert!(extensions.is_empty());
        }
        _ => panic!("expected KeepAlive variant"),
    }
}

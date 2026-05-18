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
    inbound_to_fsm_event, BoxedLinkDriver, SessionLinkActions,
};
use wz_runtime_tokio::Reliability;
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, install_session_actions_for_test,
};

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
    let actions = SessionLinkActions::new(driver, fixture_session_init_params());
    let lua = install_session_actions_for_test(actions.clone());

    let mut engine: Engine<SessionFsmUnicastPolicy> =
        Engine::new(SessionFsmUnicastPolicy::new(lua));
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

    let frame = InboundFrame::Frame {
        reliable: true,
        sn: 0,
        payload: Vec::new(),
        has_ext: false,
        extensions: Vec::new(),
    };
    assert_eq!(
        inbound_to_fsm_event(&frame),
        None,
        "Frame payload routes to application dispatch, not FSM transition"
    );

    let unknown = InboundFrame::Unknown { mid: 0x1F };
    assert_eq!(
        inbound_to_fsm_event(&unknown),
        Some(SessionFsmUnicastEvent::FramingError)
    );
}

#[test]
fn parse_inbound_decodes_frame_with_sn_and_payload() {
    use wz_runtime_tokio::session_glue::{parse_inbound, InboundFrame};

    // MID=0x05 (T_MID_FRAME) | R flag (0x20) = 0x25.
    // sn=1 (VLE single byte: 0x01), payload=[0xCA, 0xFE].
    let wire = [0x25u8, 0x01, 0xCA, 0xFE];
    let frame = parse_inbound(&wire).expect("Frame wire parses");
    match frame {
        InboundFrame::Frame {
            reliable,
            sn,
            payload,
            has_ext,
            extensions,
        } => {
            assert!(reliable, "FLAG_T_FRAME_R must surface as reliable=true");
            assert_eq!(sn, 1);
            assert_eq!(payload, vec![0xCA, 0xFE]);
            assert!(!has_ext);
            assert!(extensions.is_empty());
        }
        _ => panic!("expected Frame variant"),
    }
}

#[test]
fn parse_inbound_decodes_best_effort_frame_with_large_sn() {
    use wz_runtime_tokio::session_glue::{parse_inbound, InboundFrame};

    // MID=0x05, no R flag → best-effort. sn=128 (VLE 2 bytes:
    // 0x80, 0x01), payload empty.
    let wire = [0x05u8, 0x80, 0x01];
    let frame = parse_inbound(&wire).expect("best-effort Frame parses");
    match frame {
        InboundFrame::Frame {
            reliable,
            sn,
            payload,
            ..
        } => {
            assert!(!reliable);
            assert_eq!(sn, 128, "2-byte VLE boundary value");
            assert!(payload.is_empty());
        }
        _ => panic!("expected Frame variant"),
    }
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

#[test]
fn handle_inbound_keepalive_updates_last_inbound_keepalive_at() {
    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopDriver::default());
    let actions = SessionLinkActions::new(driver, fixture_session_init_params());

    assert!(
        actions.last_inbound_keepalive_at.lock().unwrap().is_none(),
        "slot starts empty"
    );

    let pre = std::time::Instant::now();
    let _ = actions
        .handle_inbound(&[0x04])
        .expect("KeepAlive wire parses");
    let post = std::time::Instant::now();

    let stamp = actions
        .last_inbound_keepalive_at
        .lock()
        .unwrap()
        .expect("KeepAlive must populate the timestamp slot");
    assert!(
        stamp >= pre && stamp <= post,
        "captured timestamp must lie within the handle_inbound call window"
    );
}

#[test]
fn handle_inbound_non_keepalive_does_not_touch_keepalive_slot() {
    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopDriver::default());
    let actions = SessionLinkActions::new(driver, fixture_session_init_params());

    // Seed the slot to verify a non-KeepAlive frame leaves it
    // untouched (no spurious overwrite).
    let seeded = std::time::Instant::now();
    *actions.last_inbound_keepalive_at.lock().unwrap() = Some(seeded);

    // Drive an InitAck wire through handle_inbound (R68a path).
    let cookie = vec![0xAB, 0xCD];
    let wire = craft_initack_wire(&cookie);
    let _ = actions.handle_inbound(&wire).expect("InitAck parses");

    let after = *actions.last_inbound_keepalive_at.lock().unwrap();
    assert_eq!(
        after,
        Some(seeded),
        "non-KeepAlive frames must NOT mutate the keepalive slot"
    );
}

// ─────────────── R74 parse_frame_payload application-layer batch ──────────

#[test]
fn parse_frame_payload_empty_returns_empty_batch() {
    use wz_runtime_tokio::session_glue::parse_frame_payload;

    let parsed = parse_frame_payload(&[]).expect("empty payload parses");
    assert!(
        parsed.is_empty(),
        "empty payload yields an empty batch (no records)"
    );
}

#[test]
fn parse_frame_payload_unknown_mid_absorbs_remainder() {
    use wz_runtime_tokio::session_glue::{parse_frame_payload, NetworkMessage};

    // 0x1B = N_MID_RESPONSE — no codec authored yet (was 0x1D=PUSH
    // pre-R90; PUSH is now codec'd, so use a still-uncodec'd MID
    // here to exercise the Unknown absorb path).
    let bytes = [0x1B, 0xAB, 0xCD, 0xEF];
    let parsed = parse_frame_payload(&bytes).expect("unknown MID absorbs as Unknown");
    assert_eq!(parsed.len(), 1, "single Unknown record");
    match &parsed[0] {
        NetworkMessage::Unknown { mid, body } => {
            assert_eq!(*mid, 0x1B, "header low 5 bits = network MID");
            assert_eq!(
                body.as_slice(),
                &bytes,
                "Unknown.body absorbs the entire remaining payload including header"
            );
        }
        NetworkMessage::Request(_)
        | NetworkMessage::Push(_)
        | NetworkMessage::ResponseFinal(_)
        | NetworkMessage::Oam(_)
        | NetworkMessage::Interest(_) => {
            panic!("expected Unknown, got typed variant")
        }
    }
}

#[test]
fn parse_frame_payload_dispatches_request_mid_to_request_decoder() {
    use wz_codecs::request::Request;
    use wz_runtime_tokio::session_glue::{parse_frame_payload, NetworkMessage};

    // R88 — exact byte-count round-trip Request envelope using plain
    // `Request::default()`. Pre-R88 this test required explicit
    // construction with `RequestVariant::Default { tag: 0, body:
    // Query::default() }` to work around a codegen Default-arm
    // self-inconsistency (R82 carry / R87 documentation). The SCE
    // vendor pin bump to 189bf7f4 landed RFC variant-default-uniformity:
    //   - `<sce:arm value="0x03" type="codec_zenoh_query" default="true"/>`
    //     in request.scxml marks Query as the declared default arm
    //   - `<sce:flag name="mid" bit="0" width="5" value="0x03"/>` in
    //     query.scxml bakes the wire-MID into Query::default()'s header
    //   - Codegen now emits `RequestVariant::default() -> CodecZenohQuery(Query::default())`
    //     with Query.header = 0x03 → encode writes Query bytes →
    //     decode peeks 0x03 → CodecZenohQuery arm → byte-exact roundtrip.
    let req = Request {
        header: 0x1C,
        ..Request::default()
    };
    let bytes = req.encode();
    assert_eq!(
        bytes.len(),
        4,
        "round-trip-safe Request: header + rid + wireexpr + query_default = 4 bytes"
    );

    let parsed = parse_frame_payload(&bytes).expect("Request envelope parses");
    assert_eq!(
        parsed.len(),
        1,
        "round-trip-safe Request yields exactly one record; got {parsed:?}"
    );
    assert!(
        matches!(parsed[0], NetworkMessage::Request(_)),
        "Request MID 0x1C dispatches to wz_codecs::request decoder"
    );
}

#[test]
fn parse_frame_payload_decodes_request_then_unknown_chain() {
    use wz_codecs::request::Request;
    use wz_runtime_tokio::session_glue::{parse_frame_payload, NetworkMessage};

    // R88 — chain test simplified alongside the Request roundtrip.
    // The default-state mismatch that previously polluted this test's
    // residual is gone after the SCE variant-default-uniformity fix.
    let req = Request {
        header: 0x1C,
        ..Request::default()
    };
    let mut bytes = req.encode();
    let request_len = bytes.len();
    // Append an Unknown MID (0x1B = N_MID_RESPONSE — still uncodec'd
    // post-R90; was 0x1D=PUSH pre-R90).
    bytes.extend_from_slice(&[0x1B, 0x42, 0x43]);

    let parsed = parse_frame_payload(&bytes).expect("Request + Unknown batch parses");
    assert_eq!(
        parsed.len(),
        2,
        "two records: Request envelope then Unknown absorbing the tail; got {parsed:?}"
    );
    assert!(matches!(parsed[0], NetworkMessage::Request(_)));
    match &parsed[1] {
        NetworkMessage::Unknown { mid, body } => {
            assert_eq!(*mid, 0x1B);
            assert_eq!(
                body.as_slice(),
                &bytes[request_len..],
                "Unknown.body absorbs from its header byte to end of payload"
            );
        }
        NetworkMessage::Request(_)
        | NetworkMessage::Push(_)
        | NetworkMessage::ResponseFinal(_)
        | NetworkMessage::Oam(_)
        | NetworkMessage::Interest(_) => {
            panic!("expected Unknown second record")
        }
    }
}

#[test]
fn parse_frame_payload_dispatches_push_mid_to_push_decoder() {
    use wz_codecs::push::Push;
    use wz_runtime_tokio::session_glue::{parse_frame_payload, NetworkMessage};

    // R90 — round-trip-safe Push using plain `Push::default()`.
    // After R88 variant-default-uniformity + R90 push.scxml's
    // `<sce:arm value="0x01" default="true"/>` on msg_put:
    //   - Push::default().body = CodecZenohMsgPut(MsgPut::default())
    //   - MsgPut::default().header = 0x01 (R88 baked MID)
    //   - encode writes msg_put bytes; decode peeks 0x01 → msg_put arm
    //   - byte-exact roundtrip.
    let push = Push {
        header: 0x1D,
        ..Push::default()
    };
    let bytes = push.encode();

    let parsed = parse_frame_payload(&bytes).expect("Push envelope parses");
    assert_eq!(
        parsed.len(),
        1,
        "round-trip-safe Push yields exactly one record; got {parsed:?}"
    );
    assert!(
        matches!(parsed[0], NetworkMessage::Push(_)),
        "PUSH MID 0x1D dispatches to wz_codecs::push decoder"
    );
}

#[test]
fn parse_frame_payload_decodes_push_then_request_chain() {
    use wz_codecs::push::Push;
    use wz_codecs::request::Request;
    use wz_runtime_tokio::session_glue::{parse_frame_payload, NetworkMessage};

    // R90 — multi-codec batch: PUSH + REQUEST in one Frame.payload.
    // Both round-trip-safe constructions via R88's Default-uniformity.
    let push = Push {
        header: 0x1D,
        ..Push::default()
    };
    let req = Request {
        header: 0x1C,
        ..Request::default()
    };
    let mut bytes = push.encode();
    bytes.extend_from_slice(&req.encode());

    let parsed = parse_frame_payload(&bytes).expect("Push+Request batch parses");
    assert_eq!(parsed.len(), 2, "two records: Push then Request");
    assert!(matches!(parsed[0], NetworkMessage::Push(_)));
    assert!(matches!(parsed[1], NetworkMessage::Request(_)));
}

#[test]
fn parse_frame_payload_dispatches_response_final_mid_to_response_final_decoder() {
    use wz_codecs::response_final::ResponseFinal;
    use wz_runtime_tokio::session_glue::{parse_frame_payload, NetworkMessage};

    // R91 — round-trip-safe ResponseFinal using plain
    // `ResponseFinal::default()`. After R88 variant-default-uniformity
    // the inner default state is byte-exact (no inner body to worry
    // about — ResponseFinal is header + request_id VLE only).
    let rf = ResponseFinal {
        header: 0x1A,
        ..ResponseFinal::default()
    };
    let bytes = rf.encode();
    assert_eq!(
        bytes.len(),
        2,
        "round-trip-safe ResponseFinal: header(1) + request_id VLE(1) = 2 bytes"
    );

    let parsed = parse_frame_payload(&bytes).expect("ResponseFinal envelope parses");
    assert_eq!(
        parsed.len(),
        1,
        "round-trip-safe ResponseFinal yields exactly one record; got {parsed:?}"
    );
    assert!(
        matches!(parsed[0], NetworkMessage::ResponseFinal(_)),
        "RESPONSE_FINAL MID 0x1A dispatches to wz_codecs::response_final decoder"
    );
}

#[test]
fn parse_frame_payload_dispatches_oam_mid_to_oam_decoder() {
    use wz_codecs::oam::Oam;
    use wz_runtime_tokio::session_glue::{parse_frame_payload, NetworkMessage};

    // R92 — round-trip-safe OAM with default header.enc=00 (UNIT)
    // selecting the empty ext_unit body via the declared default arm.
    let oam = Oam {
        header: 0x1F,
        ..Oam::default()
    };
    let bytes = oam.encode();

    let parsed = parse_frame_payload(&bytes).expect("OAM envelope parses");
    assert_eq!(
        parsed.len(),
        1,
        "round-trip-safe OAM yields exactly one record; got {parsed:?}"
    );
    assert!(
        matches!(parsed[0], NetworkMessage::Oam(_)),
        "OAM MID 0x1F dispatches to wz_codecs::oam decoder"
    );
}

#[test]
fn parse_frame_payload_dispatches_interest_mid_to_interest_decoder() {
    use wz_codecs::interest::Interest;
    use wz_runtime_tokio::session_glue::{parse_frame_payload, NetworkMessage};

    // R93 — round-trip-safe Interest envelope with default header
    // (mid=0x19, C/F/Z bits clear): wire form is header byte + VLE id (1
    // byte for id=0) = 2 bytes, structurally identical to a default
    // ResponseFinal aside from the MID. The envelope-only scope of
    // interest.scxml maps to upstream's is_final path; flipping C or F
    // would invite the inner-body extension deferred to a future round.
    let interest = Interest {
        header: 0x19,
        ..Interest::default()
    };
    let bytes = interest.encode();
    assert_eq!(
        bytes.len(),
        2,
        "round-trip-safe Interest: header(1) + interest_id VLE(1) = 2 bytes"
    );

    let parsed = parse_frame_payload(&bytes).expect("Interest envelope parses");
    assert_eq!(
        parsed.len(),
        1,
        "round-trip-safe Interest yields exactly one record; got {parsed:?}"
    );
    assert!(
        matches!(parsed[0], NetworkMessage::Interest(_)),
        "INTEREST MID 0x19 dispatches to wz_codecs::interest decoder"
    );
}

#[test]
fn parse_frame_payload_truncated_request_returns_codec_error() {
    use wz_runtime_tokio::session_glue::parse_frame_payload;

    // Header only — Request::decode consumes 1 byte and then tries to
    // read the rid VLE, hitting NeedMoreBytes.
    let bytes = [0x1Cu8];
    parse_frame_payload(&bytes).expect_err("truncated Request body rejects");
}

// ─────────── R86 handle_inbound InitSyn peer_zid capture ───────────

#[test]
fn r86_handle_inbound_initsyn_captures_peer_zid() {
    use wz_runtime_tokio::session_glue::InboundFrame;

    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopDriver::default());
    let actions = SessionLinkActions::new(driver, fixture_session_init_params());
    assert!(
        actions.inbound_peer_zid.lock().unwrap().is_none(),
        "slot starts empty"
    );

    // Hand-crafted InitSyn wire — FLAG_T_INIT_S (0x40) | T_MID_INIT
    // (0x01) header, 4-byte peer zid [0xB0..0xB3]. Mirrors
    // session_fsm_accepting_path::craft_initsyn_wire() shape so the
    // R78 integration test and this R86 unit test inspect the same
    // wire across the dispatch layers.
    let wire = vec![
        0x40 | 0x01, // FLAG_T_INIT_S | T_MID_INIT
        0x05, // version
        0x31, // cbyte: whatami=Peer wire(0x01), zid_len=4 (high nibble = 3)
        0xB0, 0xB1, 0xB2, 0xB3, // zid (4 bytes)
        0x00, // sn_res
        0x00, 0x00, // batch_size LE u16
    ];

    let frame = actions.handle_inbound(&wire).expect("InitSyn parses");
    assert!(
        matches!(frame, InboundFrame::Init { is_ack: false, .. }),
        "wire decodes to InitSyn (is_ack=false)"
    );

    let captured = actions.inbound_peer_zid.lock().unwrap().clone();
    assert_eq!(
        captured,
        Some(vec![0xB0, 0xB1, 0xB2, 0xB3]),
        "InitSyn arrival must capture peer_zid into inbound_peer_zid slot \
         (R86 wiring for RFC §5.M cookie binding)"
    );
}

#[test]
fn r86_handle_inbound_init_ack_does_not_overwrite_peer_zid() {
    use wz_runtime_tokio::session_glue::InboundFrame;

    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopDriver::default());
    let actions = SessionLinkActions::new(driver, fixture_session_init_params());

    // Seed the slot to verify InitAck doesn't overwrite it (InitAck
    // is the Initiator side observing the listener; the listener's
    // zid is in body.zid but the SLOT is for inbound peer's zid in
    // the Accepting-side capture path, so semantic-wise InitAck
    // should NOT touch this slot to avoid cross-role confusion).
    let seeded = vec![0xAA, 0xBB, 0xCC, 0xDD];
    *actions.inbound_peer_zid.lock().unwrap() = Some(seeded.clone());

    // Hand-crafted InitAck wire — has different zid bytes
    // [0xC0..0xC3] AND a 4-byte cookie at the end, with both
    // FLAG_T_INIT_S (0x40) and FLAG_T_INIT_A (0x20) parent flags.
    let wire = vec![
        0x40 | 0x20 | 0x01, // FLAG_T_INIT_S | FLAG_T_INIT_A | T_MID_INIT
        0x05, 0x31,
        0xC0, 0xC1, 0xC2, 0xC3, // different zid (would be the responder's)
        0x00, 0x00, 0x00,
        0x04, // cookie_len VLE = 4
        0xDE, 0xAD, 0xBE, 0xEF, // cookie
    ];

    let frame = actions.handle_inbound(&wire).expect("InitAck parses");
    assert!(matches!(frame, InboundFrame::Init { is_ack: true, .. }));

    let after = actions.inbound_peer_zid.lock().unwrap().clone();
    assert_eq!(
        after,
        Some(seeded),
        "InitAck arrival must NOT overwrite inbound_peer_zid \
         (R86 capture is Accepting-side InitSyn only)"
    );
}

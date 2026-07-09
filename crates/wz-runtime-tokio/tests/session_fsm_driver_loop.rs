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

use std::sync::Arc;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, BoxedLinkDriver,
    DriverLoopOutcome, SessionActionsBinding, SessionLinkActions,
};
// `NetworkMessage` is referenced only by the two codec-decode tests
// below: `r74_rx_frame_unknown_network_mid_absorbs_as_unknown`
// (all five typed-codec features) and
// `r90_rx_frame_push_payload_decodes_via_push_codec` (codec-push).
// Both require codec-push, so this import follows codec-push.
#[cfg(feature = "codec-push")]
use wz_runtime_tokio::session_glue::NetworkMessage;
use wz_runtime_tokio::{LinkEvent, LostCause, RxFrame};
use wz_runtime_tokio_test_support::{fixture_session_init_params, NoopOutboundDriver, QueueDriver};
// R311it — craft_initack_wire + the transport constants come from the
// shared no_std SSOT (was copy-pasted across the session_fsm_* test files).
// T_MID_INIT / FLAG_T_INIT_S / FLAG_T_INIT_A / T_MID_KEEP_ALIVE stay imported
// because the malformed-wire + KeepAlive tests below build one-off frames.
use wz_session_wire_fixtures::{
    craft_initack_wire, FLAG_T_INIT_A, FLAG_T_INIT_S, T_MID_INIT, T_MID_KEEP_ALIVE,
};

fn fresh_setup() -> (
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
) {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    (actions, engine)
}

fn drive_to_sent_init_syn(engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>) {
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
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

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
        actions.link.last_inbound_at.lock().unwrap().is_none(),
        "keepalive slot empty before Rx"
    );

    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(vec![T_MID_KEEP_ALIVE]))]);

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
        actions.link.last_inbound_at.lock().unwrap().is_some(),
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
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(vec![
        FLAG_T_INIT_S | FLAG_T_INIT_A | T_MID_INIT,
    ]))]);

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
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(vec![0x05, 0x00]))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    match outcome {
        DriverLoopOutcome::FramePayload {
            reliable,
            sn,
            ref messages,
            has_ext,
            ref extensions,
            ..
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
#[cfg(all(
    feature = "codec-request",
    feature = "codec-push",
    feature = "codec-response-final",
    feature = "codec-response",
    feature = "codec-declare"
))]
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
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(vec![
        0x25, 0x01, 0x00, 0xAA, 0xBB,
    ]))]);

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
                    panic!("synthetic MID 0x00 must NOT dispatch to any typed decoder")
                }
            }
        }
        other => panic!("expected FramePayload, got {other:?}"),
    }
}

// ── R90 Scenario: Rx(Frame) with PUSH payload → FramePayload
//                  containing Push variant decoded via wz_codecs::push
#[cfg(feature = "codec-push")]
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
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(frame_wire))]);

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
            assert_eq!(
                messages.len(),
                1,
                "exactly one Push record; got {messages:?}"
            );
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
// R311fr — surfaces a ParseError only when the Request codec rejects the
// truncated body; with codec-request off the MID decodes as Unknown and
// no ParseError is raised. Gate on codec-request.
#[cfg(feature = "codec-request")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r74_rx_frame_malformed_request_payload_surfaces_parse_error() {
    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    // Frame envelope OK (header + sn=0), but payload = [0x1C] alone
    // — Request::decode consumes the header then needs rid VLE bytes
    // that don't exist. parse_frame_payload returns CodecError;
    // poll_and_dispatch_one must surface ParseError AND fire
    // FramingError into the FSM (SentInitSyn -> Closing edge).
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(vec![0x05, 0x00, 0x1C]))]);

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

// ── R311kc Scenario: Rx(InitAck enlarging a size param) →
//                    InitAckCapsRejected + framing.error teardown
//
// pico parity (`_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION`,
// unicast/transport.c:123-140): the fixture initiator advertises
// seq/req/batch = 0/0/0 (fixture_session_init_params), so an InitAck
// claiming seq_num_res=1 ENLARGES the advertisement and must reject the
// session — Closing with CloseReason::Invalid, not a silent min()
// adoption (the F-b carry this closes). The conforming-caps positive
// arm is Scenario 1 above (all-zero InitAck caps == the advertisement).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311kc_rx_init_ack_enlarged_caps_rejects_session() {
    use wz_runtime_tokio::session_glue::CloseReason;
    use wz_session_wire_fixtures::craft_initack_wire_with_caps;

    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    let cookie = vec![0xC0, 0x01];
    // sn_res byte 0x01 = seq_num_res 1 (> advertised 0), req 0; batch 0.
    let wire = craft_initack_wire_with_caps(&cookie, 0x01, 0);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::InitAckCapsRejected),
        "enlarged InitAck caps must surface InitAckCapsRejected; got {outcome:?}"
    );
    assert_eq!(
        engine.get_current_state(),
        S::Closing,
        "params rejection must drive the framing.error arm to Closing"
    );
    let trace = actions.trace_snapshot();
    assert!(
        trace.set_close_reason_count >= 1,
        "Closing entry must record a close reason"
    );
    assert_eq!(
        trace.close_reason,
        CloseReason::Invalid,
        "params rejection closes with INVALID (wire 'invalid parameters')"
    );
}

// ── R311kc NEG: an InitAck whose batch_size enlarges the advertisement
//               rejects even though seq/req conform — pico validates the
//               three parameters independently. R311kj — the own side is
//               a CONFIGURED 512 (the fixture's unset 0 advertises the
//               65535 ceiling on the wire since R311kj, so an unset own
//               side can no longer be "enlarged" by any u16 peer value).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311kc_rx_init_ack_enlarged_batch_size_rejects_session() {
    use wz_session_wire_fixtures::craft_initack_wire_with_caps;

    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let mut params = fixture_session_init_params();
    params.batch_size = 512;
    let actions = new_session_actions(outbound, params, TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    drive_to_sent_init_syn(&mut engine);

    // seq/req = 0/0 conform; batch_size 1024 > advertised 512.
    let wire = craft_initack_wire_with_caps(&[0xC0, 0x01], 0x00, 1024);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::InitAckCapsRejected),
        "enlarged batch_size must reject independently; got {outcome:?}"
    );
    assert_eq!(engine.get_current_state(), S::Closing);
}

// ── R311ke Scenario: per-channel RX SN gate — a duplicate/stale Frame
//                    SN drops typed (pico `_z_sn_precedes`, rx.c:108-131)
//                    while the other channel gates independently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311ke_rx_duplicate_frame_sn_rejected_per_channel() {
    use wz_session_wire_fixtures::craft_frame_wire;

    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    let mut driver = QueueDriver::with(vec![
        LinkEvent::Rx(RxFrame::new(craft_frame_wire(2, true))),
        LinkEvent::Rx(RxFrame::new(craft_frame_wire(2, true))), // duplicate
        LinkEvent::Rx(RxFrame::new(craft_frame_wire(1, true))), // backward
        LinkEvent::Rx(RxFrame::new(craft_frame_wire(2, false))), // other channel
    ]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::FramePayload { sn: 2, .. }),
        "first frame at sn=2 admits (unseeded channel tracks from it); got {outcome:?}"
    );
    let pre_state = engine.get_current_state();

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(
            outcome,
            DriverLoopOutcome::RxSnRejected {
                reliable: true,
                sn: 2,
                ..
            }
        ),
        "duplicate sn=2 must drop typed; got {outcome:?}"
    );
    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(
            outcome,
            DriverLoopOutcome::RxSnRejected {
                reliable: true,
                sn: 1,
                ..
            }
        ),
        "backward sn=1 must drop typed; got {outcome:?}"
    );
    assert_eq!(
        engine.get_current_state(),
        pre_state,
        "SN-gate drops must not advance the FSM (pico silent drop)"
    );

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(
            outcome,
            DriverLoopOutcome::FramePayload {
                reliable: false,
                sn: 2,
                ..
            }
        ),
        "best-effort channel gates independently of reliable; got {outcome:?}"
    );
}

// ── R311kj review fix: the InitAck params gate is SCOPED to
//    SentInitSyn — an ACCEPTOR mid-handshake receiving a bogus
//    enlarging InitAck must NOT tear down (the FSM ignores the
//    no-transition event, pico drops it). The R311kc !is_established()
//    scope was role-blind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311kj_acceptor_ignores_enlarging_init_ack() {
    use wz_session_wire_fixtures::craft_initack_wire_with_caps;

    let (actions, mut engine) = fresh_setup();
    // Accepting role: InboundStart -> AwaitingInitSyn.
    engine.process_event(E::InboundStart);
    let pre_state = engine.get_current_state();

    // Enlarging InitAck (seq_num_res 1 > advertised 0) aimed at the
    // acceptor — outside SentInitSyn the gate must not fire.
    let wire = craft_initack_wire_with_caps(&[0xC0, 0x01], 0x01, 0);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        !matches!(outcome, DriverLoopOutcome::InitAckCapsRejected),
        "acceptor-side InitAck must not trigger the params gate; got {outcome:?}"
    );
    assert_eq!(
        engine.get_current_state(),
        pre_state,
        "the FSM ignores the no-transition event (no teardown)"
    );
    assert!(
        !engine.is_in_final_state(),
        "acceptor session survives a bogus InitAck"
    );
}

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
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, NoopOutboundDriver, QueueDriver,
};
// R311it — craft_initack_wire + the transport constants come from the
// shared no_std SSOT (was copy-pasted across the session_fsm_* test files).
// T_MID_INIT / FLAG_T_INIT_S / FLAG_T_INIT_A / T_MID_KEEP_ALIVE stay imported
// because the malformed-wire + KeepAlive tests below build one-off frames.
use wz_session_wire_fixtures::{
    craft_initack_wire, FLAG_T_INIT_A, FLAG_T_INIT_S, T_MID_INIT, T_MID_KEEP_ALIVE,
};
// R311y823 — the Close header's MID, for reading the reason byte a reject
// actually put on the wire rather than only the FSM action that chose it.
use wz_codecs::wire_const::T_MID_CLOSE;

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

// ── R311y817 Scenario: Rx(InitAck announcing a PATCH level above ours) →
//                      InitAckPatchRejected + framing.error teardown.
//
// The ext-chain member of the same "less or equal than the one in the
// InitSyn" family the R311kc tests above cover for the body's three size
// parameters. zenoh `bail!`s out of `PatchFsm::recv_init_ack`
// (`unicast/establishment/ext/patch.rs:78-84`) and zenoh-pico returns
// `_Z_ERR_GENERIC` before it builds the OpenSyn
// (`unicast/transport.c:142-148`); wz silently `min()`ed the level down and
// continued the handshake, which is the clause this closes.
//
// DISCRIMINATING against the R311kc gate: the fixture's caps are the
// all-zero conforming advertisement, so nothing the size rule looks at has
// moved and the rejection can only be the patch's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311y817_rx_init_ack_future_patch_rejects_session() {
    use wz_runtime_tokio::session_glue::CloseReason;
    use wz_session_wire_fixtures::craft_initack_wire_with_patch;

    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    // wz advertises CURRENT_PATCH = 1; the acceptor claims 2.
    let wire = craft_initack_wire_with_patch(&[0xC0, 0x01], 2);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::InitAckPatchRejected),
        "an InitAck patch above our InitSyn's must surface \
         InitAckPatchRejected; got {outcome:?}"
    );
    assert_eq!(
        engine.get_current_state(),
        S::Closing,
        "patch rejection must drive the establishment.ext_rejected arm to Closing"
    );
    let trace = actions.trace_snapshot();
    // R311y823 REVERSED THIS ASSERTION IN PLACE rather than deleting it. It
    // read `CloseReason::Invalid` ("wire 'invalid parameters'") because
    // R311y817 routed the patch reject through `framing.error` like every
    // other ext reject. zenoh closes GENERIC for extension failures and
    // reserves INVALID for the body's size parameters, so the same builder
    // shape now asserts the opposite outcome and the reversal is visible at
    // the site. The wire-byte half lives in
    // `r311y823_init_ack_patch_reject_closes_generic_on_the_wire`.
    assert_eq!(
        trace.close_reason,
        CloseReason::Generic,
        "an ext-chain rejection closes with GENERIC, not the body family's INVALID"
    );
    // The refused level must NOT have reached the min(): a torn-down
    // session that still recorded a negotiated patch would mean the
    // rejection ran after the state it was supposed to protect.
    assert!(
        !actions.patch_was_negotiated(),
        "a refused InitAck must not seed the negotiated patch level"
    );
}

// ── R311y817 POSITIVE: an InitAck at OUR OWN level is admitted, and the
//    level it announced is what the session negotiates. Without this arm
//    the rejection above is satisfied by a gate that refuses everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311y817_rx_init_ack_at_our_own_patch_level_is_admitted() {
    use wz_session_wire_fixtures::craft_initack_wire_with_patch;

    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    let wire = craft_initack_wire_with_patch(&[0xC0, 0x01], 1);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::AdvancedFsm),
        "an InitAck at our own patch level must advance; got {outcome:?}"
    );
    assert_eq!(
        engine.get_current_state(),
        S::GotInitAck,
        "the conforming InitAck still advances SentInitSyn -> GotInitAck"
    );
    assert_eq!(
        actions.negotiated_patch(),
        1,
        "the admitted level is what the session negotiates"
    );
}

// ── R311y817 POSITIVE: a PRE-PATCH acceptor — an InitAck with no `0x7`
//    entry at all — must be admitted. The extension is non-mandatory in
//    both references, so absence is a peer to negotiate DOWN to level 0,
//    never one to refuse. This is the arm that breaks if the comparison is
//    written as an equality or inverted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311y817_rx_init_ack_without_a_patch_ext_is_admitted() {
    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    // `craft_initack_wire` carries NO ext chain at all.
    let wire = craft_initack_wire(&[0xC0, 0x01]);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        !matches!(outcome, DriverLoopOutcome::InitAckPatchRejected),
        "a pre-patch acceptor must not be refused; got {outcome:?}"
    );
    assert_eq!(
        actions.negotiated_patch(),
        0,
        "an absent patch ext negotiates to NO_PATCH, markers off"
    );
}

// ── R311y817 ASYMMETRY: the rule is INITIATOR-ONLY. An InitSyn announcing
//    a level above ours is a newer peer to be negotiated DOWN, and neither
//    reference refuses it — zenoh's `AcceptFsm::recv_init_syn` stores it
//    unexamined (`ext/patch.rs:168-175`) and answers `min(CURRENT, peer)`;
//    pico caps with the same `min` (`unicast/transport.c:237-241`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311y817_acceptor_does_not_refuse_an_init_syn_announcing_a_future_patch() {
    use wz_session_wire_fixtures::craft_initsyn_wire_with_patch;

    let (actions, mut engine) = fresh_setup();
    // Accepting role: InboundStart -> AwaitingInitSyn.
    engine.process_event(E::InboundStart);

    let wire = craft_initsyn_wire_with_patch(9);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        !matches!(outcome, DriverLoopOutcome::InitAckPatchRejected),
        "an acceptor must never apply the InitAck patch rule; got {outcome:?}"
    );
    assert!(
        !engine.is_in_final_state(),
        "the acceptor session survives an initiator announcing a future patch"
    );
    assert_eq!(
        actions.negotiated_patch(),
        1,
        "the future level is capped at ours by the min(), not refused"
    );
}

// ── R311y817 DISCRIMINATOR: the ceiling is the chain wz ACTUALLY STAGED on
//    its InitSyn, not the `CURRENT_PATCH` constant.
//
//    pico compares against `ism._body._init._patch` — the InitSyn it built
//    — and that form is the one wz takes, so a build whose AP layer stages
//    an InitSyn chain WITHOUT a patch entry holds its peer to NO_PATCH.
//    An InitAck at level 1 is conforming against the default chain (the
//    positive arm above proves it) and REFUSED against an empty one; only
//    a ceiling read back from the slot can tell those two apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311y817_the_patch_ceiling_is_the_staged_init_syn_chain() {
    use wz_runtime_tokio::session_glue::ExtChainRole;
    use wz_session_wire_fixtures::craft_initack_wire_with_patch;

    let (actions, mut engine) = fresh_setup();
    assert_eq!(
        actions.advertised_patch(),
        1,
        "the default InitSyn chain advertises CURRENT_PATCH"
    );

    // This node now announces NO patch level at all.
    actions.set_ext_chain(ExtChainRole::InitSyn, Vec::new());
    assert_eq!(
        actions.advertised_patch(),
        0,
        "the ceiling follows the staged chain"
    );

    drive_to_sent_init_syn(&mut engine);
    let wire = craft_initack_wire_with_patch(&[0xC0, 0x01], 1);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::InitAckPatchRejected),
        "level 1 exceeds an advertisement of none and must be refused; \
         got {outcome:?}"
    );
}

/// R311y632 (§17) — a framing unit holding TWO transport messages delivers
/// BOTH, and the second arrives WITHOUT the peer sending again.
///
/// # What was wrong
///
/// `handle_inbound` read the message at the front of a unit and nothing read
/// the rest. That is not a stricter dialect than the wire's — zenoh holds a
/// batch open instead of flushing per message
/// (`zenoh-transport-1.5.0/src/common/pipeline.rs:318`, batching on by default)
/// and both reference receivers walk a received unit to its end
/// (`.../multicast/rx.rs:287`, `.../unicast/universal/rx.rs:220`,
/// `vendor/zenoh-pico/src/transport/multicast/rx.c:68-77`). So a peer's data
/// frame batched behind a keepalive was simply dropped by this participant.
///
/// # Why the empty driver queue is the discriminator
///
/// `QueueDriver` yields `LinkEvent::Lost { PeerClosed }` once its queue drains,
/// so the second call CANNOT get a Frame from the link. If the Frame arrives,
/// it came from the parked remainder of the first unit — which is exactly the
/// claim. A drive loop that reached for the link first would answer `LinkLost`
/// here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batched_unit_delivers_every_message_it_carried() {
    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    // [KeepAlive][Frame(best-effort, sn=0, empty payload)] — the smallest batch
    // that can exist. A Frame consumes the remainder of its unit by
    // construction, so a real batch ends with one and never begins with one.
    let unit = vec![0x04, 0x05, 0x00];
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(unit))]);

    let first = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(first, DriverLoopOutcome::SideEffectOnly),
        "the KeepAlive at the front of the batch; got {first:?}"
    );

    let second = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    match second {
        DriverLoopOutcome::FramePayload {
            reliable,
            sn,
            ref messages,
            ..
        } => {
            assert!(!reliable, "no R flag -> best-effort");
            assert_eq!(sn, 0);
            assert!(messages.is_empty(), "empty tail -> empty batch");
        }
        other => panic!(
            "the batched Frame must be delivered without the peer speaking \
             again; got {other:?}"
        ),
    }

    // And the unit is then EXHAUSTED rather than replayed: the next turn
    // reaches the link, which has nothing left.
    let third = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(third, DriverLoopOutcome::LinkLost(LostCause::PeerClosed)),
        "a drained unit must not keep answering; got {third:?}"
    );
}

// ── R311y823: the CLOSE REASON BYTE an establishment-EXTENSION reject puts
//              on the wire.
//
// zenoh splits the establishment reject family in two, and the split is a
// wire fact rather than a log level. The BODY's size parameters close
// INVALID (`recv_init_ack`'s FrameSN / RequestID arms,
// `unicast/establishment/open.rs:288,304`), and every EXTENSION handler
// failure closes GENERIC -- QoS, Shm, Auth, MultiLink, LowLatency,
// Compression and Patch all reach `link.close(Some(GENERIC))` through the
// same `map_err` (`open.rs:321-364`, mirrored on the accept side at
// `accept.rs:234-356`). The reason is what a peer READS: `link.close`
// encodes `Close { reason, session: false }` and sends it before dropping
// the link (`unicast/link.rs:103-114`).
//
// wz routed the whole ext-reject family through the FSM's `framing.error`
// arm, which closes INVALID -- so a wz initiator refusing an over-claiming
// PATCH told the peer "invalid parameters" where zenoh says "generic".
// zenoh-pico cannot arbitrate: it returns `_Z_ERR_GENERIC` and drops the
// link WITHOUT sending any Close at all (`unicast/transport.c:141-152`),
// so zenoh is the only upstream that puts a byte there.
//
// The three tests below are ONE discriminator, not three assertions. A and
// B take the same path to `Closing` from the same state and differ only in
// the family, so a change that moved both would be moving the FSM's
// close-reason default rather than splitting the family; C holds the other
// direction, where a teardown that never was an establishment reject at all
// must keep INVALID.
fn fresh_recording_setup() -> (
    Arc<LifecycleRecordingDriver>,
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
) {
    let recorder = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = recorder.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    (recorder, actions, engine)
}

/// The reason byte of the sole Close frame this session put on the wire.
/// Panics when there is not exactly one: a silent teardown is a different
/// defect from a wrong reason, and folding them together would let either
/// pass as the other.
fn sole_close_reason_byte(recorder: &LifecycleRecordingDriver) -> u8 {
    let snap = recorder.snapshot();
    let closes: Vec<&(Vec<u8>, wz_runtime_tokio::Reliability)> = snap
        .sends
        .iter()
        .filter(|(bytes, _)| bytes.first().map(|h| h & 0x1f) == Some(T_MID_CLOSE))
        .collect();
    assert_eq!(
        closes.len(),
        1,
        "expected exactly one Close frame on the wire; sends were {:?}",
        snap.sends
    );
    let bytes = &closes[0].0;
    assert_eq!(bytes.len(), 2, "Close is a header plus one reason byte");
    bytes[1]
}

// ── R311y823 A: an InitAck announcing a PATCH level above ours closes
//                GENERIC, because the patch rides the EXTENSION chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311y823_init_ack_patch_reject_closes_generic_on_the_wire() {
    use wz_runtime_tokio::session_glue::CloseReason;
    use wz_session_wire_fixtures::craft_initack_wire_with_patch;

    let (recorder, actions, mut engine) = fresh_recording_setup();
    drive_to_sent_init_syn(&mut engine);

    // wz advertises CURRENT_PATCH = 1; the acceptor claims 2.
    let wire = craft_initack_wire_with_patch(&[0xC0, 0x01], 2);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::InitAckPatchRejected),
        "an InitAck patch above our InitSyn's must surface \
         InitAckPatchRejected; got {outcome:?}"
    );
    assert_eq!(engine.get_current_state(), S::Closing);
    assert_eq!(
        actions.trace_snapshot().close_reason,
        CloseReason::Generic,
        "an EXTENSION reject closes GENERIC (zenoh routes every ext \
         handler's error through the GENERIC map_err, not the body's \
         INVALID arm)"
    );
    assert_eq!(
        sole_close_reason_byte(&recorder),
        CloseReason::Generic as u8,
        "the byte the peer reads must be GENERIC(0), not INVALID(1)"
    );
}

// ── R311y823 B (the NEGATIVE half of the pair): an InitAck enlarging a BODY
//               size parameter still closes INVALID. Same state, same
//               teardown arm, same wire assertion -- only the family differs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311y823_init_ack_caps_reject_still_closes_invalid_on_the_wire() {
    use wz_runtime_tokio::session_glue::CloseReason;
    use wz_session_wire_fixtures::craft_initack_wire_with_caps;

    let (recorder, actions, mut engine) = fresh_recording_setup();
    drive_to_sent_init_syn(&mut engine);

    // sn_res byte 0x01 = seq_num_res 1, above the fixture's advertised 0.
    let wire = craft_initack_wire_with_caps(&[0xC0, 0x01], 0x01, 0);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::InitAckCapsRejected),
        "enlarged InitAck caps must surface InitAckCapsRejected; got {outcome:?}"
    );
    assert_eq!(engine.get_current_state(), S::Closing);
    assert_eq!(
        actions.trace_snapshot().close_reason,
        CloseReason::Invalid,
        "a BODY size-parameter reject keeps INVALID (zenoh reserves it \
         for exactly these fields)"
    );
    assert_eq!(
        sole_close_reason_byte(&recorder),
        CloseReason::Invalid as u8,
        "the byte the peer reads must stay INVALID(1)"
    );
}

// ── R311y823 C: a PAYLOAD framing error is not an establishment reject and
//               must keep INVALID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311y823_malformed_frame_still_closes_invalid_on_the_wire() {
    use wz_runtime_tokio::session_glue::CloseReason;

    let (recorder, actions, mut engine) = fresh_recording_setup();
    drive_to_sent_init_syn(&mut engine);

    // A truncated InitAck: the header claims a body the bytes do not carry.
    let wire = vec![T_MID_INIT | FLAG_T_INIT_A | FLAG_T_INIT_S, 0x00];
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);

    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::ParseError(_)),
        "a truncated frame is a parse error; got {outcome:?}"
    );
    assert_eq!(engine.get_current_state(), S::Closing);
    assert_eq!(
        actions.trace_snapshot().close_reason,
        CloseReason::Invalid,
        "a framing error is not an establishment-extension reject"
    );
    assert_eq!(
        sole_close_reason_byte(&recorder),
        CloseReason::Invalid as u8
    );
}

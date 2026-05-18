// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// R61 strict-audit coverage pass. Walks every transition edge in
// `sources/session/session_fsm_unicast.scxml` that R59's happy-path
// test did not exercise:
//
//   1. Listener path (Accepting branch):
//        Init -> inbound.start -> AwaitingInitSyn
//        AwaitingInitSyn -> init_syn.received -> SentInitAck
//        SentInitAck -> open_syn.received -> SentOpenAck
//        SentOpenAck -> Established
//
//   2. Failure / timeout paths (all converge on Closing or Closed):
//        LinkOpening -> link.open_timeout -> Closing (reason=Generic)
//        LinkOpening -> link.lost -> Closed (direct)
//        Opening -> init_ack.timeout -> Closing (reason=Generic)
//        Opening -> open_ack.timeout -> Closing (reason=Generic)
//        Opening -> framing.error -> Closing (reason=Invalid)
//        Established -> lease.expired -> Closing (reason=Expired)
//        Established -> framing.error -> Closing (reason=Invalid)
//        Established -> tx.congestion.exhaust -> Closing
//        Established -> peer.close -> Closed (direct)
//        Accepting -> framing.error -> Closing (reason=Invalid)
//
// R80 — each transition edge is now a separate `#[test]` fn (was a
// single mega-test fn pre-R80 because of the R71b cross-test race
// carry on the process-global `INSTALLED` OnceLock + Lua singleton).
// SCE upstream's per-instance ScriptEngine DI (vendor pin bump
// 085268d1 in R79) eliminated the shared state, so each `#[test]`
// now owns an independent `LuaEngine` via
// `install_session_actions_for_test` and cargo's thread-parallel
// runner can execute them concurrently without collision.

use std::sync::Arc;
use std::sync::Mutex;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    BoxedLinkDriver, CloseReason, SessionLinkActions,
};
use wz_runtime_tokio::Reliability;
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, install_session_actions_for_test,
};

#[derive(Default)]
struct RecordingDriver {
    inner: Mutex<RecordingState>,
}

#[derive(Default)]
struct RecordingState {
    sends: u32,
}

impl BoxedLinkDriver for RecordingDriver {
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
    fn send_blocking(&self, _b: &[u8], _r: Reliability) {
        self.inner.lock().unwrap().sends += 1;
    }
}

/// Build a driver + actions + Engine triple for one scenario. Each
/// call yields an independent `LuaEngine` (R79 per-instance DI), so
/// concurrent test scenarios cannot contend on shared state.
fn fresh_engine() -> (
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy>,
) {
    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(RecordingDriver::default());
    let actions = SessionLinkActions::new(driver, fixture_session_init_params());
    let lua = install_session_actions_for_test(actions.clone());
    let mut engine = Engine::new(SessionFsmUnicastPolicy::new(lua));
    engine.initialize();
    (actions, engine)
}

fn drive_to_established(engine: &mut Engine<SessionFsmUnicastPolicy>) {
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    engine.process_event(E::InitAckReceived);
    engine.process_event(E::OpenAckReceived);
    assert_eq!(engine.get_current_state(), S::Established);
}

// ── 1. Listener path: Init → AwaitingInitSyn → SentInitAck
//                     → SentOpenAck → Established
#[test]
fn r61_listener_path_inbound_to_established() {
    use wz_runtime_tokio::session_glue::generate_cookie_hmac_sha256;

    let (actions, mut engine) = fresh_engine();
    assert_eq!(engine.get_current_state(), S::Init);

    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    // R89 — raw-event-injection bypasses handle_inbound, so the
    // R86 peer_zid + R89 OpenSyn cookie slots must be seeded
    // manually to satisfy the dynamic cookie_valid() guard. r61
    // verifies FSM transition shape, not wire-bytes; the seed
    // mirrors what handle_inbound would populate on a real
    // InitSyn + OpenSyn arrival.
    let fixture_peer_zid = vec![0xB0, 0xB1, 0xB2, 0xB3];
    *actions.inbound_peer_zid.lock().unwrap() = Some(fixture_peer_zid.clone());
    let expected_cookie = generate_cookie_hmac_sha256(
        &actions.params.cookie_signing_key,
        &fixture_peer_zid,
    );
    *actions.inbound_opensyn_cookie.lock().unwrap() = Some(expected_cookie);

    engine.process_event(E::InitSynReceived);
    assert_eq!(engine.get_current_state(), S::SentInitAck);
    let t = actions.trace_snapshot();
    assert_eq!(t.send_init_ack_with_cookie, 1);

    engine.process_event(E::OpenSynReceived);
    // SentOpenAck has an eventless transition to Established —
    // the macrostep traverses both states in one process_event.
    assert_eq!(engine.get_current_state(), S::Established);
    let t = actions.trace_snapshot();
    assert_eq!(t.send_open_ack, 1);
    assert_eq!(t.enable_rx_tx_regions, 1);
    assert_eq!(t.start_lease_monitor, 1);
    assert_eq!(t.start_keepalive_worker, 1);
    assert!(
        t.cookie_valid_check >= 1,
        "R89 dynamic guard must have fired at least once on the \
         SentInitAck -> SentOpenAck transition; got count={}",
        t.cookie_valid_check
    );
}

// ── 2. LinkOpening -> link.open_timeout -> Closing (Generic)
#[test]
fn r61_link_opening_open_timeout_to_closing_generic() {
    let (actions, mut engine) = fresh_engine();
    engine.process_event(E::OutboundStart);
    assert_eq!(engine.get_current_state(), S::LinkOpening);

    engine.process_event(E::LinkOpenTimeout);
    assert_eq!(engine.get_current_state(), S::Closing);
    let t = actions.trace_snapshot();
    assert_eq!(t.set_close_reason_count, 1);
    assert_eq!(t.close_reason, CloseReason::Generic);
    assert_eq!(t.send_close_frame_with_reason, 1);
}

// ── 3. LinkOpening -> link.lost -> Closed (direct)
#[test]
fn r61_link_opening_link_lost_to_closed_direct() {
    let (actions, mut engine) = fresh_engine();
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkLost);
    assert_eq!(engine.get_current_state(), S::Closed);
    assert!(engine.is_in_final_state());
    let t = actions.trace_snapshot();
    assert_eq!(t.release_link, 1);
    assert_eq!(t.free_pool_slots, 1);
    // link.lost bypasses Closing: no CLOSE frame, no
    // set_close_reason call.
    assert_eq!(t.send_close_frame_with_reason, 0);
    assert_eq!(t.set_close_reason_count, 0);
}

// ── 4. Opening (SentInitSyn) -> init_ack.timeout -> Closing
#[test]
fn r61_opening_init_ack_timeout_to_closing() {
    let (actions, mut engine) = fresh_engine();
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    assert_eq!(engine.get_current_state(), S::SentInitSyn);

    engine.process_event(E::InitAckTimeout);
    assert_eq!(engine.get_current_state(), S::Closing);
    let t = actions.trace_snapshot();
    assert_eq!(t.close_reason, CloseReason::Generic);
    assert_eq!(t.send_close_frame_with_reason, 1);
}

// ── 5. Opening -> framing.error -> Closing (Invalid)
#[test]
fn r61_opening_framing_error_to_closing_invalid() {
    let (actions, mut engine) = fresh_engine();
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    engine.process_event(E::FramingError);
    assert_eq!(engine.get_current_state(), S::Closing);
    let t = actions.trace_snapshot();
    assert_eq!(t.close_reason, CloseReason::Invalid);
}

// ── 6. Opening (GotInitAck) -> open_ack.timeout -> Closing
#[test]
fn r61_opening_open_ack_timeout_to_closing() {
    let (actions, mut engine) = fresh_engine();
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    engine.process_event(E::InitAckReceived);
    assert_eq!(engine.get_current_state(), S::GotInitAck);

    engine.process_event(E::OpenAckTimeout);
    assert_eq!(engine.get_current_state(), S::Closing);
    let t = actions.trace_snapshot();
    assert_eq!(t.close_reason, CloseReason::Generic);
}

// ── 7. Established -> lease.expired -> Closing (Expired)
#[test]
fn r61_established_lease_expired_to_closing_expired() {
    let (actions, mut engine) = fresh_engine();
    drive_to_established(&mut engine);
    engine.process_event(E::LeaseExpired);
    assert_eq!(engine.get_current_state(), S::Closing);
    let t = actions.trace_snapshot();
    assert_eq!(t.close_reason, CloseReason::Expired);
    assert_eq!(t.send_close_frame_with_reason, 1);
    // Established.onexit ran.
    assert_eq!(t.stop_keepalive_worker, 1);
    assert_eq!(t.stop_lease_monitor, 1);
}

// ── 8. Established -> framing.error -> Closing (Invalid)
#[test]
fn r61_established_framing_error_to_closing_invalid() {
    let (actions, mut engine) = fresh_engine();
    drive_to_established(&mut engine);
    engine.process_event(E::FramingError);
    assert_eq!(engine.get_current_state(), S::Closing);
    assert_eq!(actions.trace_snapshot().close_reason, CloseReason::Invalid);
}

// ── 9. Established -> tx.congestion.exhaust -> Closing
#[test]
fn r61_established_tx_congestion_exhaust_to_closing() {
    let (actions, mut engine) = fresh_engine();
    drive_to_established(&mut engine);
    engine.process_event(E::TxCongestionExhaust);
    assert_eq!(engine.get_current_state(), S::Closing);
    assert_eq!(
        actions.trace_snapshot().close_reason,
        CloseReason::Unresponsive
    );
}

// ── 10. Established -> peer.close -> Closed (skips Closing)
#[test]
fn r61_established_peer_close_to_closed_direct() {
    let (actions, mut engine) = fresh_engine();
    drive_to_established(&mut engine);
    engine.process_event(E::PeerClose);
    assert_eq!(engine.get_current_state(), S::Closed);
    let t = actions.trace_snapshot();
    assert_eq!(t.release_link, 1);
    assert_eq!(t.send_close_frame_with_reason, 0);
}

// ── 11. Accepting -> framing.error -> Closing (Invalid)
#[test]
fn r61_accepting_framing_error_to_closing_invalid() {
    let (actions, mut engine) = fresh_engine();
    engine.process_event(E::InboundStart);
    engine.process_event(E::InitSynReceived);
    engine.process_event(E::FramingError);
    assert_eq!(engine.get_current_state(), S::Closing);
    assert_eq!(actions.trace_snapshot().close_reason, CloseReason::Invalid);
}

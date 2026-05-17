// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R59 integration test — drives the generated `SessionFsmUnicastPolicy`
//! through every state on the outbound-initiator happy path and
//! asserts each onentry script reached the LinkDriver side via the
//! real codec encode path established in R57.
//!
//! State walk:
//!
//!   Init                   (initial; no onentry script)
//!     │ outbound.start
//!     ▼
//!   LinkOpening            (onentry: link_driver_open)
//!     │ link.opened
//!     ▼
//!   Opening.SentInitSyn    (onentry: send_init_syn)
//!     │ init_ack.received
//!     ▼
//!   Opening.GotInitAck     (onentry: send_open_syn)
//!     │ open_ack.received
//!     ▼
//!   Established            (onentry: enable_rx_tx_regions,
//!                                    start_lease_monitor,
//!                                    start_keepalive_worker)
//!     │ session.close
//!     ▼
//!   Closing                (onexit:  stop_keepalive_worker,
//!                                    stop_lease_monitor;
//!                           onentry: send_close_frame_with_reason)
//!     │ closing.timeout
//!     ▼
//!   Closed (final)         (onentry: release_link, free_pool_slots)
//!
//! The 5s `link.open_timeout` and 100ms `closing.timeout` delayed
//! sends scheduled inside LinkOpening / Closing onentry are NOT
//! advanced by `Engine::tick` in this test — the success path is
//! driven by external `link.opened` / `closing.timeout` events. The
//! tick-based time-mock harness is its own carry (Hal time
//! injection in `sce_rust_runtime` is documented at
//! `sce_rust_runtime::StdHal`).

use std::sync::Arc;
use std::sync::Mutex;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent, SessionFsmUnicastPolicy, SessionFsmUnicastState,
};
use wz_runtime_tokio::session_glue::{
    install_session_actions, BoxedLinkDriver, SessionLinkActions,
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
    opens: u32,
    closes: u32,
    sends: Vec<(Vec<u8>, Reliability)>,
}

impl BoxedLinkDriver for RecordingDriver {
    fn open_blocking(&self) {
        self.inner.lock().unwrap().opens += 1;
    }
    fn close_blocking(&self) {
        self.inner.lock().unwrap().closes += 1;
    }
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) {
        self.inner
            .lock()
            .unwrap()
            .sends
            .push((bytes.to_vec(), reliability));
    }
}

#[test]
fn r59_engine_drives_full_outbound_initiator_happy_path() {
    let driver = Arc::new(RecordingDriver::default());
    let actions = SessionLinkActions::new(driver.clone(), fixture_session_init_params());
    if install_session_actions(actions.clone()).is_err() {
        install_session_actions_for_test(actions.clone());
    }

    let mut engine: Engine<SessionFsmUnicastPolicy> =
        Engine::new(SessionFsmUnicastPolicy::new());
    engine.initialize();
    assert_eq!(engine.get_current_state(), SessionFsmUnicastState::Init);

    // ─── outbound.start ─→ LinkOpening ──────────────────────────
    engine.process_event(SessionFsmUnicastEvent::OutboundStart);
    assert_eq!(engine.get_current_state(), SessionFsmUnicastState::LinkOpening);
    {
        let t = actions.trace_snapshot();
        assert_eq!(t.link_driver_open, 1);
        let snap = driver.inner.lock().unwrap();
        assert_eq!(snap.opens, 1, "driver.open after LinkOpening onentry");
    }

    // ─── link.opened ─→ Opening.SentInitSyn ─────────────────────
    engine.process_event(SessionFsmUnicastEvent::LinkOpened);
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::SentInitSyn
    );
    {
        let t = actions.trace_snapshot();
        assert_eq!(t.send_init_syn, 1);
        let snap = driver.inner.lock().unwrap();
        assert_eq!(
            snap.sends.len(),
            1,
            "one send (INIT_SYN) after SentInitSyn onentry"
        );
        assert_eq!(snap.sends[0].1, Reliability::Reliable);
    }

    // ─── init_ack.received ─→ Opening.GotInitAck ────────────────
    engine.process_event(SessionFsmUnicastEvent::InitAckReceived);
    assert_eq!(engine.get_current_state(), SessionFsmUnicastState::GotInitAck);
    {
        let t = actions.trace_snapshot();
        assert_eq!(t.send_open_syn, 1);
        let snap = driver.inner.lock().unwrap();
        assert_eq!(
            snap.sends.len(),
            2,
            "two sends (INIT_SYN, OPEN_SYN) after GotInitAck onentry"
        );
    }

    // ─── open_ack.received ─→ Established ───────────────────────
    engine.process_event(SessionFsmUnicastEvent::OpenAckReceived);
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established
    );
    {
        let t = actions.trace_snapshot();
        assert_eq!(t.enable_rx_tx_regions, 1);
        assert_eq!(t.start_lease_monitor, 1);
        assert_eq!(t.start_keepalive_worker, 1);
    }

    // ─── session.close ─→ Closing ───────────────────────────────
    // The transition runs the set_close_reason_generic action; the
    // exit from Established runs stop_keepalive_worker +
    // stop_lease_monitor; the Closing onentry runs
    // send_close_frame_with_reason.
    engine.process_event(SessionFsmUnicastEvent::SessionClose);
    assert_eq!(engine.get_current_state(), SessionFsmUnicastState::Closing);
    {
        let t = actions.trace_snapshot();
        assert_eq!(t.set_close_reason_count, 1);
        assert_eq!(t.stop_keepalive_worker, 1);
        assert_eq!(t.stop_lease_monitor, 1);
        assert_eq!(t.send_close_frame_with_reason, 1);
        let snap = driver.inner.lock().unwrap();
        assert_eq!(
            snap.sends.len(),
            3,
            "three sends (INIT_SYN, OPEN_SYN, CLOSE) after Closing onentry"
        );
        // Verify the last send is the Close codec output (2 bytes:
        // [FLAG_T_CLOSE_S | T_MID_CLOSE, reason_byte]).
        let close_wire = &snap.sends[2].0;
        assert_eq!(close_wire.len(), 2, "Close wire is 2 bytes");
        assert_eq!(close_wire[0], 0x20 | 0x03, "Close header byte");
        assert_eq!(close_wire[1], 0x00, "Close reason byte = Generic");
    }

    // ─── closing.timeout ─→ Closed (final) ──────────────────────
    engine.process_event(SessionFsmUnicastEvent::ClosingTimeout);
    assert_eq!(engine.get_current_state(), SessionFsmUnicastState::Closed);
    assert!(engine.is_in_final_state());
    {
        let t = actions.trace_snapshot();
        assert_eq!(t.release_link, 1);
        assert_eq!(t.free_pool_slots, 1);
        let snap = driver.inner.lock().unwrap();
        assert_eq!(snap.closes, 1, "driver.close after release_link");
    }
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R54 integration test — exercises the Lua script engine path that
//! the generated `session_fsm_unicast_sm.rs` emits for each
//! `<script>foo()</script>` action body. Bypasses the full Engine
//! driving (lands with codec wiring in R55+) and calls
//! `execute_script` directly to isolate the
//! "is the FSM-action surface wired to LinkDriver" question from
//! the "does the FSM transition correctly" question.
//!
//! Single integration test on purpose. The Lua engine singleton at
//! `sce_rust_lua::lua_engine_singleton()` is process-global, and
//! `register_global_function` writes into one shared name space.
//! Splitting into per-action `#[test]` functions makes cargo's
//! thread-parallel test runner reinstall the actions concurrently
//! and the registered closures' captured `Arc<RecordingDriver>`
//! values race across tests. The sequential single-test shape
//! pins one set of registrations and walks the full script-action
//! surface in a deterministic order, which is what the R55 Engine
//! integration will diff its emit ordering against.

use std::sync::Arc;
use std::sync::Mutex;

use wz_runtime_tokio::session_glue::{
    dispatch_script, install_session_actions, BoxedLinkDriver, CloseReason, SessionLinkActions,
};
use wz_runtime_tokio::Reliability;

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
fn r54_session_script_actions_route_to_link_driver() {
    let driver = Arc::new(RecordingDriver::default());
    let actions = SessionLinkActions::new(driver.clone());
    install_session_actions(actions.clone()).expect("install");

    // Step 1 — initiator-path script actions, in the order the
    // `session_fsm_unicast.scxml` SCXML would invoke them on the
    // happy outbound-handshake path.
    dispatch_script("link_driver_open").expect("LinkOpening onentry");
    dispatch_script("send_init_syn").expect("Opening/SentInitSyn onentry");
    dispatch_script("send_open_syn").expect("Opening/GotInitAck onentry");
    dispatch_script("enable_rx_tx_regions").expect("Established onentry");
    dispatch_script("start_lease_monitor").expect("Established onentry");
    dispatch_script("start_keepalive_worker").expect("Established onentry");

    // Step 2 — session-close walk.
    dispatch_script("set_close_reason_generic").expect("session.close transition action");
    dispatch_script("stop_keepalive_worker").expect("Established onexit");
    dispatch_script("stop_lease_monitor").expect("Established onexit");
    dispatch_script("send_close_frame_with_reason").expect("Closing onentry");
    dispatch_script("release_link").expect("Closed onentry");
    dispatch_script("free_pool_slots").expect("Closed onentry");

    // Step 3 — listener-path actions covered separately (these were
    // not invoked above because the script set above walked the
    // initiator path).
    dispatch_script("send_init_ack_with_cookie").expect("Accepting/SentInitAck onentry");
    dispatch_script("send_open_ack").expect("Accepting/SentOpenAck onentry");

    // Step 4 — close-reason discriminator coverage. The single
    // `set_close_reason_generic` in step 2 only proved one variant;
    // the other three set their own discriminator + bump the
    // counter.
    dispatch_script("set_close_reason_invalid").expect("framing.error path");
    dispatch_script("set_close_reason_expired").expect("lease.expired path");
    dispatch_script("set_close_reason_unresponsive").expect("tx.congestion.exhaust path");

    let trace = actions.trace_snapshot();

    // Each outbound link action increments its counter exactly once
    // per dispatch.
    assert_eq!(trace.link_driver_open, 1, "link_driver_open trace");
    assert_eq!(trace.send_init_syn, 1, "send_init_syn trace");
    assert_eq!(trace.send_open_syn, 1, "send_open_syn trace");
    assert_eq!(
        trace.send_init_ack_with_cookie, 1,
        "send_init_ack_with_cookie trace"
    );
    assert_eq!(trace.send_open_ack, 1, "send_open_ack trace");
    assert_eq!(
        trace.send_close_frame_with_reason, 1,
        "send_close_frame_with_reason trace"
    );
    assert_eq!(trace.release_link, 1, "release_link trace");
    assert_eq!(trace.enable_rx_tx_regions, 1, "enable_rx_tx_regions trace");
    assert_eq!(trace.start_lease_monitor, 1, "start_lease_monitor trace");
    assert_eq!(trace.stop_lease_monitor, 1, "stop_lease_monitor trace");
    assert_eq!(
        trace.start_keepalive_worker, 1,
        "start_keepalive_worker trace"
    );
    assert_eq!(
        trace.stop_keepalive_worker, 1,
        "stop_keepalive_worker trace"
    );
    assert_eq!(trace.free_pool_slots, 1, "free_pool_slots trace");

    // Close-reason setters bumped the counter four times (one per
    // variant). The last variant set wins on the discriminator.
    assert_eq!(trace.set_close_reason_count, 4);
    assert_eq!(trace.close_reason, CloseReason::Unresponsive);

    // Driver side received the expected open / close / 5 sends. The
    // sends in order are the five outbound payloads from steps 1-3.
    let snap = driver.inner.lock().unwrap();
    assert_eq!(snap.opens, 1, "driver.open call count");
    assert_eq!(snap.closes, 1, "driver.close call count");
    assert_eq!(snap.sends.len(), 5, "driver.send call count");

    let expected: &[(&[u8], Reliability)] = &[
        (b"INIT_SYN", Reliability::Reliable),
        (b"OPEN_SYN", Reliability::Reliable),
        (b"CLOSE", Reliability::Reliable),
        (b"INIT_ACK_COOKIE", Reliability::Reliable),
        (b"OPEN_ACK", Reliability::Reliable),
    ];
    for (i, (want_bytes, want_rel)) in expected.iter().enumerate() {
        let (got_bytes, got_rel) = &snap.sends[i];
        assert_eq!(got_bytes, want_bytes, "send[{i}] bytes");
        assert_eq!(got_rel, want_rel, "send[{i}] reliability");
    }
}

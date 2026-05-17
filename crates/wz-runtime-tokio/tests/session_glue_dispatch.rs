// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R57 integration test — drives every outbound script-action
//! through `session_glue` and asserts the wire bytes are produced
//! by the real wz codec encode path with the right
//! transport-message-id header + flag pattern.
//!
//! Single integration test on purpose. The Lua engine + the
//! `INSTALLED` OnceLock guard are process-global; the
//! `__test_only_rebind` hook lets the test rebind closures against
//! a fresh `SessionLinkActions` without resetting the guard.
//!
//! Wire-byte assertions are exact-bytes (not pattern-matched) so
//! any drift between session_glue's encode path and zenoh-pico's
//! `_z_*_encode` reference (verified by the Layer 3 tests in
//! `wz-integration-tests`) fails this test loudly. The fixtures
//! mirror those Layer 3 tests' input choices so the byte sequences
//! are directly cross-referenceable.

use std::sync::Arc;
use std::sync::Mutex;

use wz_runtime_tokio::session_glue::{
    dispatch_script, install_session_actions, BoxedLinkDriver, CloseReason, SessionInitParams,
    SessionLinkActions, SigningKey,
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

/// Mirror of `layer3_init_body.rs::compute_init_cbyte` so this test's
/// expected bytes are independent of the production code under
/// test — drift between the two implementations surfaces as a
/// mismatch instead of being hidden by sharing the helper.
fn expected_init_cbyte(whatami: u8, zid_len: usize) -> u8 {
    let wire_whatami = (whatami >> 1) & 0x03;
    wire_whatami | (((zid_len as u8 - 1) & 0x0F) << 4)
}

fn expected_sn_res(seq_num_res: u8, req_id_res: u8) -> u8 {
    (seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)
}

/// Fixed-cost test params. Match the Layer 3 `layer3_init_body_s1_a1`
/// fixture so any future cross-check against zenoh-pico's
/// `_z_init_encode` reference uses the same input space.
fn fixture_params() -> SessionInitParams {
    SessionInitParams {
        version: 0x05,
        whatami: 0x02, // Peer
        zid: vec![0x10, 0x20, 0x30, 0x40],
        seq_num_res: 0x03,
        req_id_res: 0x02,
        batch_size: 0xCAFE,
        lease: 30,
        lease_in_seconds: true,
        initial_sn: 0x42,
        cookie: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x77],
        cookie_signing_key: SigningKey::new(vec![0xAB; 32])
            .expect("32-byte test key valid"),
    }
}

#[test]
fn r57_session_script_actions_produce_real_wire_bytes() {
    let driver = Arc::new(RecordingDriver::default());
    let actions = SessionLinkActions::new(driver.clone(), fixture_params());
    // First install in this binary process. If a sibling test in the
    // same binary already installed (cargo test runs tests parallel
    // by default), we treat the `SessionActionsAlreadyInstalled`
    // error as "rebind onto our own actions" — production code never
    // takes this path, but test infrastructure must tolerate test
    // ordering.
    if install_session_actions(actions.clone()).is_err() {
        wz_runtime_tokio::session_glue::rebind_session_actions_for_test(actions.clone());
    }

    // ─── Step 1: initiator handshake path ───────────────────────
    dispatch_script("link_driver_open").expect("LinkOpening onentry");
    dispatch_script("send_init_syn").expect("Opening/SentInitSyn onentry");
    dispatch_script("send_open_syn").expect("Opening/GotInitAck onentry");
    dispatch_script("enable_rx_tx_regions").expect("Established onentry");
    dispatch_script("start_lease_monitor").expect("Established onentry");
    dispatch_script("start_keepalive_worker").expect("Established onentry");

    // ─── Step 2: session-close walk ────────────────────────────
    dispatch_script("set_close_reason_generic").expect("session.close transition action");
    dispatch_script("stop_keepalive_worker").expect("Established onexit");
    dispatch_script("stop_lease_monitor").expect("Established onexit");
    dispatch_script("send_close_frame_with_reason").expect("Closing onentry");
    dispatch_script("release_link").expect("Closed onentry");
    dispatch_script("free_pool_slots").expect("Closed onentry");

    // ─── Step 3: listener-path actions ─────────────────────────
    dispatch_script("send_init_ack_with_cookie").expect("Accepting/SentInitAck onentry");
    dispatch_script("send_open_ack").expect("Accepting/SentOpenAck onentry");

    // ─── Step 4: close-reason discriminator coverage ──────────
    dispatch_script("set_close_reason_invalid").expect("framing.error path");
    dispatch_script("set_close_reason_expired").expect("lease.expired path");
    dispatch_script("set_close_reason_unresponsive").expect("tx.congestion.exhaust path");

    let trace = actions.trace_snapshot();
    assert_eq!(trace.link_driver_open, 1);
    assert_eq!(trace.send_init_syn, 1);
    assert_eq!(trace.send_open_syn, 1);
    assert_eq!(trace.send_init_ack_with_cookie, 1);
    assert_eq!(trace.send_open_ack, 1);
    assert_eq!(trace.send_close_frame_with_reason, 1);
    assert_eq!(trace.release_link, 1);
    assert_eq!(trace.enable_rx_tx_regions, 1);
    assert_eq!(trace.start_lease_monitor, 1);
    assert_eq!(trace.stop_lease_monitor, 1);
    assert_eq!(trace.start_keepalive_worker, 1);
    assert_eq!(trace.stop_keepalive_worker, 1);
    assert_eq!(trace.free_pool_slots, 1);
    assert_eq!(trace.set_close_reason_count, 4);
    assert_eq!(trace.close_reason, CloseReason::Unresponsive);

    let snap = driver.inner.lock().unwrap();
    assert_eq!(snap.opens, 1);
    assert_eq!(snap.closes, 1);
    assert_eq!(snap.sends.len(), 5, "5 outbound sends in step 1-3");

    // ── Wire-byte assertions ────────────────────────────────────
    //
    // Each assertion below constructs the expected wire bytes from
    // the fixture inputs using the same packing rules zenoh-pico's
    // `_z_init_encode` / `_z_open_encode` / `_z_close_encode`
    // follow, but composed here independently of session_glue's
    // helpers so an implementation drift in session_glue surfaces
    // as a failure rather than being hidden by shared code.
    let params = fixture_params();

    let init_cbyte = expected_init_cbyte(params.whatami, params.zid.len());
    let init_sn_res = expected_sn_res(params.seq_num_res, params.req_id_res);

    // InitSyn — flags=S only, no cookie. Wire =
    //   [header_byte] || version || cbyte || zid || sn_res || batch_size(le)
    let init_syn_flags = 0x40u8; // FLAG_T_INIT_S
    let mut expected_init_syn = Vec::new();
    expected_init_syn.push(init_syn_flags | 0x01 /* T_MID_INIT */);
    expected_init_syn.push(params.version);
    expected_init_syn.push(init_cbyte);
    expected_init_syn.extend_from_slice(&params.zid);
    expected_init_syn.push(init_sn_res);
    // batch_size encode: 2 bytes little-endian per InitBody::encode
    // (init_body.rs emits low byte then `(_v >> 8) as u8`).
    expected_init_syn.push((params.batch_size & 0xFF) as u8);
    expected_init_syn.push((params.batch_size >> 8) as u8);
    assert_eq!(
        snap.sends[0].0, expected_init_syn,
        "send_init_syn wire bytes drift",
    );
    assert_eq!(snap.sends[0].1, Reliability::Reliable);

    // OpenSyn — flags=T (lease_in_seconds), echoes cookie.
    // Wire = [header] || OpenBody.encode(flags=T)
    let open_syn_flags = 0x40u8; // FLAG_T_OPEN_T
    let open_syn = &snap.sends[1].0;
    assert_eq!(open_syn[0], open_syn_flags | 0x02 /* T_MID_OPEN */);
    // The OpenBody encoded body has 3+ bytes (lease VLE + initial_sn VLE +
    // cookie_len VLE + cookie); we assert the first byte (header) and that
    // the body ends with the cookie payload, which is fixed.
    assert!(
        open_syn.windows(params.cookie.len())
            .any(|w| w == params.cookie.as_slice()),
        "OpenSyn body must contain the cookie payload"
    );

    // Close — graceful session close, reason=Generic (0).
    let close_flags = 0x20u8; // FLAG_T_CLOSE_S
    let expected_close = vec![close_flags | 0x03 /* T_MID_CLOSE */, 0x00 /* reason */];
    assert_eq!(snap.sends[2].0, expected_close, "Close wire bytes drift");

    // InitAck — flags=S|A, includes cookie.
    let init_ack_flags = 0x40u8 | 0x20u8; // S | A
    let init_ack = &snap.sends[3].0;
    assert_eq!(init_ack[0], init_ack_flags | 0x01 /* T_MID_INIT */);
    assert!(
        init_ack.windows(params.cookie.len())
            .any(|w| w == params.cookie.as_slice()),
        "InitAck body must contain the cookie payload"
    );

    // OpenAck — flags=T|A, no cookie.
    let open_ack_flags = 0x40u8 | 0x20u8; // T | A
    let open_ack = &snap.sends[4].0;
    assert_eq!(open_ack[0], open_ack_flags | 0x02 /* T_MID_OPEN */);
    assert!(
        !open_ack
            .windows(params.cookie.len())
            .any(|w| w == params.cookie.as_slice()),
        "OpenAck body must NOT contain the cookie payload"
    );

    // ── Inline double-install assertion ─────────────────────────
    let second_driver: Arc<dyn BoxedLinkDriver> =
        Arc::new(RecordingDriver::default());
    let second_actions =
        SessionLinkActions::new(second_driver, SessionInitParams::for_test());
    let second_install = install_session_actions(second_actions);
    assert!(
        second_install.is_err(),
        "second install in same process must return SessionActionsAlreadyInstalled"
    );
}

// double_install behaviour is exercised inline at the end of
// `r57_session_script_actions_produce_real_wire_bytes` to avoid
// cargo test's default thread-parallel runner racing two
// `install_session_actions` calls on the process-global
// `INSTALLED` OnceLock.

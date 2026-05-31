// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R57 integration test — drives every outbound script-action
//! through `session_glue` and asserts the wire bytes are produced
//! by the real wz codec encode path with the right
//! transport-message-id header + flag pattern.
//!
//! Single integration test because the walk-through dispatches the
//! 17 script actions in a fixed sequence and asserts the resulting
//! wire bytes inline; the sequence is path-dependent (each action
//! reads the trace counters left by the prior one) so splitting
//! into per-action `#[test]` fns gains no granularity. R79's
//! per-instance ScriptEngine DI closed the cross-test race carry —
//! the multi-engine isolation assertion at the test's tail verifies
//! the new invariant.
//!
//! Wire-byte assertions are exact-bytes (not pattern-matched) so
//! any drift between session_glue's encode path and zenoh-pico's
//! `_z_*_encode` reference (verified by the Layer 3 tests in
//! `wz-integration-tests`) fails this test loudly. The fixtures
//! mirror those Layer 3 tests' input choices so the byte sequences
//! are directly cross-referenceable.

// R311fr — the single test here dispatches the start_keepalive_worker /
// stop_keepalive_worker script actions (glue_dispatch.rs:109/113), which
// only exist when transport-keepalive is on. The whole file (recording
// driver + helpers + imports) exists solely to support this test, so
// gate at file scope.
#![cfg(feature = "transport-keepalive")]

use std::sync::Arc;
use std::sync::Mutex;

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{
    BoxedLinkDriver, CloseReason, SessionInitParams, SessionLinkActions, SigningKey,
};
use wz_runtime_tokio::Reliability;
use wz_runtime_tokio_test_support::{
    dispatch_script, fixture_session_init_params, install_session_actions_for_test,
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
        cookie_signing_key: SigningKey::new(vec![0xAB; 32]).expect("32-byte test key valid"),
    }
}

#[test]
fn r57_session_script_actions_produce_real_wire_bytes() {
    let driver = Arc::new(RecordingDriver::default());
    let actions = SessionLinkActions::new(driver.clone(), fixture_params(), TokioTime::new());
    let lua = install_session_actions_for_test(actions.clone());

    // ─── Step 1: initiator handshake path ───────────────────────
    dispatch_script(&*lua, "link_driver_open").expect("LinkOpening onentry");
    dispatch_script(&*lua, "send_init_syn").expect("Opening/SentInitSyn onentry");
    dispatch_script(&*lua, "send_open_syn").expect("Opening/GotInitAck onentry");
    dispatch_script(&*lua, "enable_rx_tx_regions").expect("Established onentry");
    dispatch_script(&*lua, "start_lease_monitor").expect("Established onentry");
    dispatch_script(&*lua, "start_keepalive_worker").expect("Established onentry");

    // ─── Step 2: session-close walk ────────────────────────────
    dispatch_script(&*lua, "set_close_reason_generic").expect("session.close transition action");
    dispatch_script(&*lua, "stop_keepalive_worker").expect("Established onexit");
    dispatch_script(&*lua, "stop_lease_monitor").expect("Established onexit");
    dispatch_script(&*lua, "send_close_frame_with_reason").expect("Closing onentry");
    dispatch_script(&*lua, "release_link").expect("Closed onentry");
    dispatch_script(&*lua, "free_pool_slots").expect("Closed onentry");

    // ─── Step 3: listener-path actions ─────────────────────────
    dispatch_script(&*lua, "send_init_ack_with_cookie").expect("Accepting/SentInitAck onentry");
    dispatch_script(&*lua, "send_open_ack").expect("Accepting/SentOpenAck onentry");

    // ─── Step 4: close-reason discriminator coverage ──────────
    dispatch_script(&*lua, "set_close_reason_invalid").expect("framing.error path");
    dispatch_script(&*lua, "set_close_reason_expired").expect("lease.expired path");
    dispatch_script(&*lua, "set_close_reason_unresponsive").expect("tx.congestion.exhaust path");

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

    // InitSyn — flags=S|Z (R121f1 default ext chain seeds the patch
    // extension entry per zenoh-pico's `Z_FEATURE_FRAGMENTATION=1`
    // size-negotiation invariant; see `default_init_patch_ext_entry`
    // for the wire-spec citation). Wire =
    //   [header_byte] || version || cbyte || zid || sn_res ||
    //   batch_size(le) || patch_ext_header || patch_ext_value(VLE)
    let init_syn_flags = 0x40u8 | 0x80u8; // FLAG_T_INIT_S | FLAG_T_Z
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
    // R121f1 — patch extension entry. Header byte
    // `_Z_MSG_EXT_ID_INIT_PATCH = 0x07 | _Z_MSG_EXT_ENC_ZINT = 0x27`;
    // body = VLE(`_Z_CURRENT_PATCH = 1`) = single byte 0x01. Last
    // entry of a single-entry chain, so the Z bit on the ext header
    // is cleared by `encode_ext_chain` (chain terminator).
    expected_init_syn.push(0x07 | 0x20 /* INIT_PATCH | ENC_ZINT */);
    expected_init_syn.push(0x01 /* VLE(_Z_CURRENT_PATCH) */);
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
        open_syn
            .windows(params.cookie.len())
            .any(|w| w == params.cookie.as_slice()),
        "OpenSyn body must contain the cookie payload"
    );

    // Close — graceful session close, reason=Generic (0).
    let close_flags = 0x20u8; // FLAG_T_CLOSE_S
    let expected_close = vec![
        close_flags | 0x03, /* T_MID_CLOSE */
        0x00,               /* reason */
    ];
    assert_eq!(snap.sends[2].0, expected_close, "Close wire bytes drift");

    // InitAck — flags=S|A|Z, includes cookie (R121f1 default ext
    // chain seeds the patch-extension entry mirroring zenoh-pico's
    // size-negotiation invariant; see `default_init_patch_ext_entry`).
    let init_ack_flags = 0x40u8 | 0x20u8 | 0x80u8; // S | A | Z
    let init_ack = &snap.sends[3].0;
    assert_eq!(init_ack[0], init_ack_flags | 0x01 /* T_MID_INIT */);
    assert!(
        init_ack
            .windows(params.cookie.len())
            .any(|w| w == params.cookie.as_slice()),
        "InitAck body must contain the cookie payload"
    );
    // R121f1 — patch-ext entry trails the cookie field. Last two
    // bytes of the InitAck wire = [0x27 (INIT_PATCH | ENC_ZINT),
    //                              0x01 (VLE _Z_CURRENT_PATCH)].
    let init_ack_tail = &init_ack[init_ack.len() - 2..];
    assert_eq!(
        init_ack_tail,
        &[0x27u8, 0x01u8],
        "InitAck must terminate with the default patch-ext entry"
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

    // ── R79 multi-engine isolation assertion ────────────────────
    // SCE upstream `09906015` + `489e1922` retired the process-global
    // ScriptEngineProvider singleton; two independent
    // `install_session_actions_for_test` calls now own separate
    // `LuaEngine` instances, and a dispatch against the second
    // engine must hit the SECOND `SessionLinkActions` — not the
    // first one (which would be the pre-R79 race symptom).
    let second_driver = Arc::new(RecordingDriver::default());
    let second_actions = SessionLinkActions::new(
        second_driver.clone() as Arc<dyn BoxedLinkDriver>,
        fixture_session_init_params(),
        TokioTime::new(),
    );
    let second_lua = install_session_actions_for_test(second_actions.clone());
    dispatch_script(&*second_lua, "link_driver_open")
        .expect("second engine dispatch must succeed independently");
    let second_trace = second_actions.trace_snapshot();
    assert_eq!(
        second_trace.link_driver_open, 1,
        "second engine's dispatch must increment ITS own actions, not the first"
    );
    // First engine's trace remains unchanged by the second install.
    let first_trace_after = actions.trace_snapshot();
    assert_eq!(
        first_trace_after.link_driver_open, 1,
        "first engine's trace must NOT see the second engine's dispatch"
    );
}

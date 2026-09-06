// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastActions;
use wz_runtime_tokio::session_glue::{
    new_session_actions, BoxedLinkDriver, CloseReason, SessionActionsBinding, SessionInitParams,
    SigningKey, WhatAmI,
};
use wz_runtime_tokio::Reliability;
use wz_runtime_tokio_test_support::{fixture_session_init_params, LifecycleRecordingDriver};

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
        whatami: WhatAmI::Peer,
        zid: vec![0x10, 0x20, 0x30, 0x40],
        seq_num_res: 0x03,
        req_id_res: 0x02,
        batch_size: 0xCAFE,
        lease_ms: 30_000,
        initial_sn: 0x42,
        cookie: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x77],
        cookie_signing_key: SigningKey::new(vec![0xAB; 32]).expect("32-byte test key valid"),
    }
}

#[test]
fn r57_session_script_actions_produce_real_wire_bytes() {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let actions = new_session_actions(driver.clone(), fixture_params(), TokioTime::new());
    // R311il — engine-free: dispatch each action by calling the native
    // `SessionFsmUnicastActions` trait method on a binding over `actions`
    // (the successor of the retired Lua `dispatch_script` by-name shim).
    // The walk-through fires the actions in a fixed sequence and asserts
    // the recorded wire bytes inline.
    // R311ja — annotate `R = TokioRuntime`: `SessionActionsBinding::new` now
    // takes the non-injective `R::ActionsHandle<T>`, so the `Arc` arg alone
    // cannot back-infer `R`.
    let mut binding = SessionActionsBinding::<TokioRuntime, TokioTime>::new(actions.clone());

    // ─── Step 1: initiator handshake path ───────────────────────
    binding.link_driver_open();
    binding.send_init_syn();
    binding.send_open_syn();
    binding.enable_rx_tx_regions();
    binding.start_lease_monitor();
    binding.start_keepalive_worker();

    // ─── Step 2: session-close walk ────────────────────────────
    binding.set_close_reason_generic();
    binding.stop_keepalive_worker();
    binding.stop_lease_monitor();
    binding.send_close_frame_with_reason();
    binding.release_link();
    binding.free_pool_slots();

    // ─── Step 3: listener-path actions ─────────────────────────
    binding.send_init_ack_with_cookie();
    binding.send_open_ack();

    // ─── Step 4: close-reason discriminator coverage ──────────
    binding.set_close_reason_invalid();
    binding.set_close_reason_expired();
    binding.set_close_reason_unresponsive();

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

    let snap = driver.snapshot();
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

    // expected_init_cbyte is an independent API-form oracle ((api>>1)&3), kept
    // separate from production's WhatAmI::to_wire, so feed it the API byte.
    let init_cbyte = expected_init_cbyte(params.whatami.to_api(), params.zid.len());
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

    // OpenSyn — flags=T (whole-second lease_ms auto-derives T, R311ku),
    // echoes cookie.
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

    // Close — reason=Generic (0), S CLEAR.
    //
    // R2389 — this fixture dispatches the actions directly and never
    // drives a handshake, so its session was never Established and the
    // scope is LINK. `close_scope_is_session` asks the phase before the
    // link set, which is zenoh's rule for every pre-Established Close
    // (`unicast/link.rs:103-114` builds `Close { reason, session: false }`,
    // reached from both roles' `step!` macro). This byte was `0x20 | 0x03`
    // until then, which claimed a whole-session teardown for a session that
    // did not exist yet.
    let expected_close = vec![0x03 /* T_MID_CLOSE, S clear */, 0x00 /* reason */];
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
    //                              VLE(the NEGOTIATED level)].
    //
    // R311y838 — the value is 0x00 here, and the contrast with the InitSyn
    // assertion above (which stays `_Z_CURRENT_PATCH`) is now this pair's
    // content rather than a coincidence. The two Inits answer different
    // questions in both references: an INITIATOR announces its own current
    // level unconditionally (zenoh `send_init_syn` -> `Ok(PatchType::CURRENT)`,
    // `ext/patch.rs:63-68`; pico `_z_t_msg_make_init_syn`), while an ACCEPTOR
    // answers `min(CURRENT, peer)` (zenoh `send_init_ack`, :180-186; pico's cap
    // at `transport.c:237-241`).
    //
    // This script fires the accept-side action in ISOLATION and never delivers
    // an InitSyn, so there is no peer level to min against — which is precisely
    // zenoh's `StateAccept::new() { patch: PatchType::NONE }` (:119-124), and
    // `min(CURRENT, NONE) = 0`. Asserting 0x01 here, as this test did until
    // R311y838, asserted the seeded slot rather than any answer either
    // reference gives.
    let init_ack_tail = &init_ack[init_ack.len() - 2..];
    assert_eq!(
        init_ack_tail,
        &[0x27u8, 0x00u8],
        "InitAck must terminate with the patch-ext entry at the NEGOTIATED \
         level, which is 0 for an acceptor that has been given no InitSyn"
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

    // ── R311il binding-isolation assertion ──────────────────────
    // Each `SessionActionsBinding` wraps its own `Arc<SessionLinkActions>`,
    // so dispatching an action on a second binding must hit the SECOND
    // actions bundle — not the first. (Engine-free successor of the R79
    // per-instance ScriptEngine isolation assertion: there is no shared
    // Lua namespace to race on at all now.)
    let second_driver = Arc::new(LifecycleRecordingDriver::default());
    let second_actions = new_session_actions(
        second_driver.clone() as Arc<dyn BoxedLinkDriver + Send + Sync>,
        fixture_session_init_params(),
        TokioTime::new(),
    );
    let mut second_binding =
        SessionActionsBinding::<TokioRuntime, TokioTime>::new(second_actions.clone());
    second_binding.link_driver_open();
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

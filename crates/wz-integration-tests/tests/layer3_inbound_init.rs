// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop — reverse direction (Initiator inbound parser).
//!
//! Existing `layer3_init_body.rs` validates wz encode == zenoh-pico
//! encode (forward direction). R68a closes the loop: zenoh-pico
//! encodes an InitAck wire, wz's `parse_inbound` decodes it, and
//! the cookie payload populated into `SessionLinkActions::
//! inbound_cookie` matches the cookie zenoh-pico originally serialised.
//!
//! Wire path:
//! ```text
//!   pico _z_init_encode (body)
//!     ↓ prepend transport-header byte (MID_INIT | FLAG_S | FLAG_A)
//!   bytes ─→ wz parse_inbound ─→ InboundFrame::Init { body.cookie }
//!     ↓ handle_inbound side-effect
//!   inbound_cookie slot populated with the same bytes
//! ```
//!
//! `_z_init_encode` writes ONLY the body (version + cbyte + zid +
//! sn_res/batch_size + cookie); the transport-header byte is added by
//! the higher-layer `_z_t_msg_encode` dispatch — we mirror that here
//! by prepending the header byte ourselves so the wire matches what
//! a peer would observe end-to-end.

use std::sync::Arc;

use wz_runtime_tokio::session_glue::{
    parse_inbound, BoxedLinkDriver, InboundFrame, InboundParseError, SessionInitParams,
    SessionLinkActions,
};
use wz_runtime_tokio::Reliability;
use zenoh_pico_sys::{
    _z_delete_context_t, _z_id_t, _z_init_encode, _z_slice_t, _z_t_msg_init_t, _z_wbuf_clear,
    _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

// Transport-message header bits (mirrors session_glue::wire_const,
// kept local so this test stays self-contained without exposing the
// `wire_const` module).
const T_MID_INIT: u8 = 0x01;
const FLAG_T_INIT_S: u8 = 0x40;
const FLAG_T_INIT_A: u8 = 0x20;

const WHATAMI_PEER: u8 = 0x02;

fn make_cookie_slice(payload: &[u8]) -> _z_slice_t {
    if payload.is_empty() {
        _z_slice_t {
            len: 0,
            start: std::ptr::null(),
            _delete_context: _z_delete_context_t {
                deleter: None,
                context: std::ptr::null_mut(),
            },
        }
    } else {
        _z_slice_t {
            len: payload.len(),
            start: payload.as_ptr(),
            _delete_context: _z_delete_context_t {
                deleter: None,
                context: std::ptr::null_mut(),
            },
        }
    }
}

fn pack_zid(payload: &[u8]) -> [u8; 16] {
    assert!(payload.len() <= 16);
    let mut id = [0u8; 16];
    id[..payload.len()].copy_from_slice(payload);
    id
}

/// Encode a full InitAck transport-message frame using zenoh-pico:
/// header byte + body. Returns the same bytes a wz peer would
/// observe on the wire.
fn pico_encode_initack_frame(
    version: u8,
    whatami: u8,
    zid: &[u8],
    seq_num_res: u8,
    req_id_res: u8,
    batch_size: u16,
    cookie: &[u8],
) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(256, false);
        let msg = _z_t_msg_init_t {
            _zid: _z_id_t { id: pack_zid(zid) },
            _cookie: make_cookie_slice(cookie),
            _batch_size: batch_size,
            _whatami: whatami as u32,
            _req_id_res: req_id_res,
            _seq_num_res: seq_num_res,
            _version: version,
            _patch: 0,
        };
        let parent_flags = FLAG_T_INIT_S | FLAG_T_INIT_A;
        let ret = _z_init_encode(&mut wbf, parent_flags, &msg);
        assert_eq!(ret, 0, "_z_init_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let body = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);

        let mut frame = Vec::with_capacity(1 + body.len());
        frame.push(parent_flags | T_MID_INIT);
        frame.extend_from_slice(&body);
        frame
    }
}

/// Inert link driver: every send/open/close call is a no-op. The
/// R68a test path drives `SessionLinkActions::handle_inbound`
/// directly without exercising the outbound side.
struct NoopDriver;
impl BoxedLinkDriver for NoopDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) {}
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

#[test]
fn parse_inbound_decodes_pico_initack_frame() {
    let cookie = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let wire = pico_encode_initack_frame(
        0x05,
        WHATAMI_PEER,
        &[0x01, 0x02, 0x03, 0x04],
        /*seq_num_res=*/ 2,
        /*req_id_res=*/ 1,
        /*batch_size=*/ 0xCAFE,
        &cookie,
    );

    let frame = parse_inbound(&wire).expect("parse_inbound on pico-encoded InitAck");
    match frame {
        InboundFrame::Init {
            is_ack,
            has_ext,
            body,
            extensions,
        } => {
            assert!(is_ack, "InitAck discriminator must be flagged");
            assert!(!has_ext, "no ext chain expected in R68a baseline");
            assert!(extensions.is_empty(), "no-Z-flag frame must yield empty extensions");
            assert_eq!(body.version, 0x05);
            assert_eq!(body.zid, vec![0x01, 0x02, 0x03, 0x04]);
            assert_eq!(body.sn_res, Some(0x06)); // (seq=2 & 0x03) | ((req=1 & 0x03) << 2)
            assert_eq!(body.batch_size, Some(0xCAFE));
            assert_eq!(body.cookie.as_deref(), Some(cookie.as_slice()));
        }
        other => panic!("expected Init variant, got {:?}", std::mem::discriminant(&other)),
    }
}

#[test]
fn handle_inbound_populates_cookie_slot_from_initack() {
    let cookie = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let wire = pico_encode_initack_frame(
        0x05,
        WHATAMI_PEER,
        &[0xA0, 0xA1, 0xA2, 0xA3],
        0,
        0,
        0x1000,
        &cookie,
    );

    let driver: Arc<dyn BoxedLinkDriver> = Arc::new(NoopDriver);
    let actions = SessionLinkActions::new(driver, SessionInitParams::for_test());

    let pre = actions.inbound_cookie.lock().unwrap().clone();
    assert!(pre.is_none(), "cookie slot starts empty");

    let frame = actions
        .handle_inbound(&wire)
        .expect("handle_inbound on pico InitAck");
    assert!(matches!(frame, InboundFrame::Init { is_ack: true, .. }));

    let post = actions.inbound_cookie.lock().unwrap().clone();
    assert_eq!(
        post.as_deref(),
        Some(cookie.as_slice()),
        "handle_inbound must capture the InitAck cookie verbatim"
    );
}

#[test]
fn parse_inbound_rejects_empty_wire() {
    match parse_inbound(&[]) {
        Err(InboundParseError::Empty) => {}
        Err(other) => panic!("expected Empty, got {other:?}"),
        Ok(_) => panic!("expected Empty error, got Ok frame"),
    }
}

#[test]
fn parse_inbound_surfaces_unknown_mid() {
    // MID=0x1F is outside the {INIT, OPEN, CLOSE} triad — the parser
    // surfaces it as Unknown rather than constructing a body.
    let wire = [0x1Fu8];
    let frame = parse_inbound(&wire).expect("unknown MID is not an error");
    match frame {
        InboundFrame::Unknown { mid } => assert_eq!(mid, 0x1F),
        _ => panic!("expected Unknown variant"),
    }
}

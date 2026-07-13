// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `response` codec (§5 RESPONSE network
//! envelope; R97 wz-side authoring, R105 Layer 3 byte-compare).
//!
//! Closes the post-R90 catalog's Layer 3 wire-interop debt: the
//! response envelope is the largest unproven codec, spanning header
//! flags + VLE request_id + wireexpr embed + Z-gated ext-chain +
//! peek-byte variant body (reply / err arms; reply itself wraps a
//! put / del peek-byte body). R88 RFC variant-default-uniformity
//! applies a three-level chain (response → reply → msg_put) of
//! declared default arms, so wz `Response::default().encode_to_vec()`
//! reaches the same wire bytes as zenoh-pico after a three-patch
//! fixture matches the upstream defaults: (1) `_ext_qos._val = 5`
//! is the Z_N_QOS_DEFAULT sentinel; (2)
//! `_body._reply._consolidation = -1` is Z_CONSOLIDATION_MODE_DEFAULT
//! which clears the reply.C bit; (3) `_body._reply._body._is_put =
//! true` selects the PUT branch inside the reply body union,
//! mirroring R88's msg_put default-arm declaration. R106 dropped
//! the `_key._mapping = 1` patch: M=1 is now baked into wz
//! Response::default()'s header, and the pico encoder's
//! `_z_wireexpr_is_local` check sets the same bit when `_mapping`
//! stays at its zero-init value of 0 (LOCAL).
//!
//! Wire shape: `[0x5B, 0x00, 0x00, 0x04, 0x01, 0x00]` = 6 bytes =
//! response_header (MID 0x1B | M flag) + rid VLE + wireexpr.id VLE +
//! reply_header + msg_put_header + payload_len VLE.

use wz_codecs::response::Response;
use zenoh_pico_sys::{
    _z_bytes_from_buf, _z_bytes_t, _z_n_msg_response_t, _z_response_encode, _z_slice_t,
    _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

fn zenoh_pico_encode_response_default() -> Vec<u8> {
    // SAFETY: bindgen surfaces `_z_n_msg_response_t._body` as a
    // `__bindgen_ty_3` union with `_reply` / `_err` members. The
    // accesses below dereference the union as `_reply` (selected by
    // `_tag = 0 = REPLY` left at zero-init) which is sound under
    // the C-side memory layout. All other field patches are plain
    // struct member writes.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let mut msg = _z_n_msg_response_t::default();
        // (1) qos default — see layer3_push.rs comment.
        msg._ext_qos._val = 5;
        // (2) consolidation default = -1 (Z_CONSOLIDATION_MODE_DEFAULT
        //     per api/constants.h:188 == Z_CONSOLIDATION_MODE_AUTO).
        //     The encoder treats any other value as "has_consolidation"
        //     and emits the C flag + byte. wz Reply::default().header
        //     keeps C=0, so we set the mode to the upstream default
        //     to keep both sides quiet.
        msg._body._reply._consolidation = -1;
        // (3) PUT branch inside reply._body. Zero-init `_is_put=false`
        //     would select the DEL branch (header MID 0x02) but wz
        //     reply's body variant defaults to MsgPut (declared default
        //     arm per R88).
        msg._body._reply._body._is_put = true;
        // R106: `_key._mapping` left at zero-init = 0 (LOCAL). The
        //       encoder's `_z_wireexpr_is_local` check sets M=1 to
        //       match the R106-baked wz default header.
        let ret = _z_response_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_response_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

// wz-proves: codec-response codec-parity partial
#[test]
fn layer3_response_default_byte_equivalent() {
    let wz = Response::default().encode_to_vec();
    let pico = zenoh_pico_encode_response_default();
    assert_eq!(
        wz, pico,
        "default RESPONSE must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    assert_eq!(
        wz,
        &[0x5B, 0x00, 0x00, 0x04, 0x01, 0x00],
        "default wire form: response_hdr (MID 0x1B | M flag) + rid + ke.id + reply_hdr + put_hdr + payload_len"
    );
}

// ── R311y261 — the RESPONSE(Err) arm, byte-compared against zenoh-pico ────────
//
// The response envelope's peek-byte variant has TWO arms; every existing Layer 3
// compare in this file drives the REPLY arm. The ERR arm (`query-reply-err`) had never
// been checked against a foreign encoder, so wz's error path -- the one a queryable
// takes when it cannot answer -- was structurally unproven against zenoh-pico. A
// disagreement there would be worst-case invisible: the happy path interoperates and
// only failures mis-decode.

/// zenoh-pico `_z_n_msg_response_t` on the ERR arm (`_tag = _Z_RESPONSE_BODY_ERR`).
///
/// Zero-init leaves `_encoding` unset (so `_z_err_encode` clears E) and the source-info
/// ext zeroed (so it clears Z) — exactly the shape wz's `build_response_err_empty`
/// emits, which is why no fixture patch is needed on the err body itself.
fn zenoh_pico_encode_response_err(
    payload: &[u8],
    encoding_id: Option<u16>,
    keyexpr_suffix: Option<&str>,
) -> Vec<u8> {
    // SAFETY: same wbuf-extract path as `zenoh_pico_encode_response_default`. Here the
    // `_body` union is dereferenced as `_err`, which is the arm selected by the explicit
    // `_tag = _Z_RESPONSE_BODY_ERR` written below — sound under the C-side layout.
    // `_z_bytes_from_buf` initialises the zeroed `_z_bytes_t` in place and copies.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let mut msg = _z_n_msg_response_t::default();
        msg._ext_qos._val = 5;
        msg._tag = zenoh_pico_sys::_z_n_msg_response_t__Z_RESPONSE_BODY_ERR;
        let mut payload_bytes: _z_bytes_t = core::mem::zeroed();
        let rc = _z_bytes_from_buf(&mut payload_bytes, payload.as_ptr(), payload.len());
        assert_eq!(rc, 0, "_z_bytes_from_buf failed");
        msg._body._err._payload = payload_bytes;
        if let Some(suffix) = keyexpr_suffix {
            // The LITERAL keyexpr arm (N flag + inline suffix) -- the shape the production
            // `ResponseErrBuilder` requires (mapping_id = 0 panics without a suffix). The
            // `_z_string_t` wraps a borrowed `_z_slice_t`; the encoder only READS it and
            // the zeroed delete-context is pico's own "not owned" sentinel.
            msg._key._suffix._slice = _z_slice_t {
                len: suffix.len(),
                start: suffix.as_ptr(),
                _delete_context: core::mem::zeroed(),
            };
        }
        if let Some(id) = encoding_id {
            // `_z_encoding_check` is true for a non-default id, which makes
            // `_z_err_encode` set _Z_FLAG_Z_E_E and emit the encoding bytes
            // (message.c:550-563) -- the branch the production reply_err path takes.
            msg._body._err._encoding.id = id;
        }
        let ret = _z_response_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_response_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

/// wz's `build_response_err_empty` must emit the RESPONSE(Err) arm byte-for-byte as
/// zenoh-pico's `_z_response_encode` with `_tag = _Z_RESPONSE_BODY_ERR` — proving the
/// peek-byte variant discriminator (Err MID 0x05 vs Reply MID 0x04) and the err body's
/// length-prefixed payload agree on the wire.
// wz-proves: query-reply-err codec-parity partial
// wz-proves: codec-response codec-parity partial
#[test]
fn layer3_response_err_byte_equivalent() {
    use wz_session_core::response_build::build_response_err_empty;

    for payload in [&b"unauthorized"[..], b"", b"a-longer-error-payload-from-wz"] {
        let owned = build_response_err_empty(0, payload).expect("wz err response builds");
        let wz = owned
            .try_as_borrowed()
            .expect("borrow the owned response")
            .encode_to_vec();
        let pico = zenoh_pico_encode_response_err(payload, None, None);
        assert_ne!(
            pico,
            zenoh_pico_encode_response_default(),
            "anti-vacuity: the ERR arm must differ from the REPLY arm on the wire, else \
             both sides could agree by encoding the same default"
        );
        assert_eq!(
            wz, pico,
            "RESPONSE(Err) must match zenoh-pico byte-for-byte; \
             wz={wz:02x?} pico={pico:02x?}"
        );
    }
}

/// The ERR arm as PRODUCTION emits it: with an ENCODING (the E flag + encoding bytes).
///
/// `build_response_err_empty` above is the minimal shape. The real `reply_err` path
/// (`QueryResponder::reply_err` -> `send_err` -> `ResponseErrBuilder::encoding(...)`)
/// always stamps an encoding, so `_z_err_encode`'s E-flag branch (message.c:550-563) is
/// the one that actually crosses the wire in production — and it was unproven against
/// zenoh-pico. Without this, the only err branch checked would have been the one
/// production never emits.
///
/// Still NOT covered here, and named rather than claimed: the production err response
/// also carries a `responder` envelope ext (`ResponseErrBuilder::responder`). That is the
/// residual, which is why `query-reply-err` stays graded `partial`.
// wz-proves: query-reply-err codec-parity partial
// wz-proves: codec-response codec-parity partial
#[test]
fn layer3_response_err_with_encoding_byte_equivalent() {
    use wz_session_core::response_build::ResponseErrBuilder;

    const PAYLOAD: &[u8] = b"queryable-refused";
    // zenoh encoding id 4 = text/plain; wz packs it as `id << 1 | has_schema` at build().
    const ENCODING_ID: u32 = 4;

    // The production literal path: mapping_id = 0 REQUIRES an inline keyexpr suffix
    // (response_build.rs:994-1001 panics otherwise), so the shape production emits is
    // N-flag + suffix + E-flag encoding — not the bare envelope the sibling test drives.
    const KEYEXPR: &str = "demo/err";
    let owned = ResponseErrBuilder::new(0, 0, Some(KEYEXPR), PAYLOAD)
        .encoding(ENCODING_ID, None)
        .build()
        .expect("wz err response with encoding builds");
    let wz = owned
        .try_as_borrowed()
        .expect("borrow the owned response")
        .encode_to_vec();
    let pico = zenoh_pico_encode_response_err(PAYLOAD, Some(ENCODING_ID as u16), Some(KEYEXPR));
    assert_ne!(
        pico,
        zenoh_pico_encode_response_err(PAYLOAD, None, None),
        "anti-vacuity: the N-flag keyexpr and the E-flag encoding must actually reach the wire"
    );
    assert_eq!(
        wz, pico,
        "RESPONSE(Err) WITH an encoding must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
}

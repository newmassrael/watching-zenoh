// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `request` codec (§5 REQUEST network
//! envelope; R90 wz-side authoring, R108a mid-defect fix, R108b
//! Layer 3 byte-compare).
//!
//! Closes the application-layer envelope wire-interop debt at 6/6
//! MIDs. REQUEST is the most-ext-rich envelope in the post-R90 set
//! (5 ext slots in `_z_n_msg_request_t`: qos / timestamp / target /
//! budget / timeout) plus an inner-body variant whose declared
//! default arm (R88 variant-default-uniformity) selects `Query` —
//! a separate codec with its own header, gates, and ext chain.
//!
//! Three reasons the wire matches on default state with only two
//! fixture patches:
//!
//! 1. zenoh-pico's `_z_n_msg_request_needed_exts` only marks
//!    `ext_qos` as needed by default (it compares `_val` against
//!    the `_Z_N_QOS_DEFAULT` sentinel of 5; zero-init's val of 0
//!    differs from 5, so qos is on). The other 4 ext checks all
//!    evaluate false for the zero-init message. Patch `_ext_qos._val
//!    = 5` and `exts.n` drops to 0 → the envelope's Z flag stays
//!    clear and no ext slot is emitted.
//! 2. `_z_query_encode` (message.c:394) sets the inner Q_C flag from
//!    `_consolidation != Z_CONSOLIDATION_MODE_DEFAULT`. Zero-init's
//!    `_consolidation = 0 = Z_CONSOLIDATION_MODE_NONE` differs from
//!    the AUTO sentinel (-1). Patch `_consolidation = -1` to keep
//!    Q_C clear.
//! 3. `_tag = _Z_REQUEST_QUERY` (= 0, first enum variant) is the
//!    zero-init default, which routes the encoder into
//!    `_z_query_encode(wbf, &msg->_body._query)` — exactly the
//!    branch wz Request's R88 default arm picks.
//!
//! Wire shape: `[0x5C, 0x00, 0x00, 0x03]` = 4 bytes =
//! request_header (MID 0x1C | M flag, R106 baking; M=1 set by pico
//! encoder via `_z_wireexpr_is_local` when `_key._mapping = 0`) +
//! rid VLE 0 + wireexpr.id VLE 0 (no suffix) + query inner header
//! (MID 0x03, all Q_C/Q_P/Z flags clear).

use wz_codecs::request::Request;
use zenoh_pico_sys::{
    _z_bytes_from_buf, _z_bytes_t, _z_n_msg_request_t, _z_request_encode, _z_wbuf_clear,
    _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

fn zenoh_pico_encode_request_default() -> Vec<u8> {
    // SAFETY: standard wbuf-extract path. The two field writes
    // (`_ext_qos._val` and `_body._query._consolidation`) target
    // primitive members exposed by bindgen as plain struct fields;
    // no union-discriminant invariant is touched. The `_body`
    // member is a `__bindgen_ty_*` union, but we only access the
    // `_query` arm — which is also the arm selected by the
    // zero-init `_tag = 0 = _Z_REQUEST_QUERY`, so this access is
    // sound under the C-side memory layout.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let mut msg = _z_n_msg_request_t::default();
        // (1) qos default sentinel — see layer3_push.rs comment.
        //     `_Z_N_QOS_DEFAULT._val = 5` in definitions/network.c
        //     L22; zero-init's `_val = 0` triggers
        //     `needed_exts.ext_qos = true` → wire emits the qos ext
        //     slot. Patching to 5 keeps the envelope ext chain
        //     empty (envelope Z stays clear).
        msg._ext_qos._val = 5;
        // (2) query inner consolidation default — same shape as
        //     R105 reply consolidation. Z_CONSOLIDATION_MODE_DEFAULT
        //     equals AUTO (-1); zero-init's NONE (0) differs, so
        //     `_z_query_encode` sets Q_C and emits an extra byte.
        //     Patch to -1 keeps the inner header at bare 0x03.
        msg._body._query._consolidation = -1;
        let ret = _z_request_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_request_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

// wz-proves: codec-request codec-parity partial
#[test]
fn layer3_request_default_byte_equivalent() {
    let wz = Request::default().encode_to_vec();
    let pico = zenoh_pico_encode_request_default();
    assert_eq!(
        wz, pico,
        "default REQUEST must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    assert_eq!(
        wz,
        &[0x5C, 0x00, 0x00, 0x03],
        "default wire form: request_hdr (MID 0x1C | M flag) + rid + ke.id + query_hdr (MID 0x03)"
    );
}

// R311y248 — encode a default REQUEST(Query) carrying a VALUE ext (id 0x03) via
// zenoh-pico. Identical to the default builder above except `_ext_value.payload`
// is set from `payload`: `_z_msg_query_required_extensions.body` then flips true
// (`_z_bytes_check(payload)`), so `_z_query_encode` sets the inner Q_Z (0x80)
// flag and emits the `ENC_ZBUF | 0x03` value ext = `_z_value_encode` =
// `zsize(total) || encoding || payload`. The encoding stays zero-init (id 0, no
// schema) so `_z_encoding_encode` writes a single `0x00`.
fn zenoh_pico_encode_request_query_value(payload: &[u8]) -> Vec<u8> {
    // SAFETY: same wbuf-extract path as `zenoh_pico_encode_request_default`.
    // `_z_bytes_from_buf` initialises the zeroed `_z_bytes_t` in place and
    // copies `payload`; `_ext_value.payload` is a plain struct member on the
    // `_query` union arm selected by the zero-init `_tag = _Z_REQUEST_QUERY`.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let mut msg = _z_n_msg_request_t::default();
        msg._ext_qos._val = 5;
        msg._body._query._consolidation = -1;
        let mut payload_bytes: _z_bytes_t = core::mem::zeroed();
        let rc = _z_bytes_from_buf(&mut payload_bytes, payload.as_ptr(), payload.len());
        assert_eq!(rc, 0, "_z_bytes_from_buf failed");
        msg._body._query._ext_value.payload = payload_bytes;
        let ret = _z_request_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_request_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

/// Layer 3 byte-parity for the Query VALUE ext (Q_B / Q_E, R311y248): wz's
/// production `RequestQueryBuilder::query_value(payload, default-encoding)` must
/// emit the same bytes as zenoh-pico's `_z_request_encode` with
/// `_ext_value.payload` set — proving the value ext (header `0x43`, the
/// ExtZbuf/pico-`zsize` length prefix, `encoding || payload` body) and the inner
/// Q_Z (0x80) flag compose byte-for-byte on the wire.
// wz-proves: codec-request codec-parity partial
// wz-proves: query-value codec-parity partial
#[test]
fn layer3_request_query_value_byte_equivalent() {
    use wz_session_core::request_build::RequestQueryBuilder;
    use wz_session_core::sample::EncodingHint;

    const PAYLOAD: &[u8] = b"the-query-value";
    let owned = RequestQueryBuilder::new(0, 0, None)
        .query_value(
            PAYLOAD,
            EncodingHint {
                packed_id: 0,
                schema: None,
            },
        )
        .build()
        .expect("wz query-value request builds");
    let wz = owned
        .try_as_borrowed()
        .expect("borrow the owned request")
        .encode_to_vec();
    let pico = zenoh_pico_encode_request_query_value(PAYLOAD);
    assert_eq!(
        wz, pico,
        "REQUEST(Query) with a VALUE ext must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    // Explicit wire lock (secondary to the live-FFI compare): base
    // [0x5C, 0x00, 0x00] + query_hdr 0x83 (MID 0x03 | Q_Z 0x80) + value ext
    // [0x43 (ENC_ZBUF|0x03), 0x10 (zsize = 1 enc byte + 15 payload), 0x00
    // (default encoding), then the 15 payload bytes].
    let mut expected = std::vec![0x5C_u8, 0x00, 0x00, 0x83, 0x43, 0x10, 0x00];
    expected.extend_from_slice(PAYLOAD);
    assert_eq!(wz, expected, "value-ext wire layout locked");
}

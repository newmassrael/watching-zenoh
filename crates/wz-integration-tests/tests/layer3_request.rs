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
    _z_n_msg_request_t, _z_request_encode, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf,
    _z_zbuf_clear,
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

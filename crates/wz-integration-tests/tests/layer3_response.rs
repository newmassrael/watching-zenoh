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
    _z_n_msg_response_t, _z_response_encode, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf,
    _z_zbuf_clear,
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

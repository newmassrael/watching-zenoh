// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `push` codec (§5 PUSH network
//! envelope; R90 wz-side authoring, R102 Layer 3 byte-compare).
//!
//! First Layer 3 fixture in the R101 rollout that spans a composite
//! envelope shape:
//!
//!   - header byte (MID + N + M + Z flags)
//!   - wireexpr embed (id VLE + parent.N-gated suffix)
//!   - Z-gated ext-chain (qos / timestamp slots — upstream encoder)
//!   - peek-byte variant body (msg_put / msg_del)
//!
//! Scope (R102 first cut, R106 M-flag baking): default state — no
//! extensions, no keyexpr suffix, msg_put inner body with empty
//! payload, mapping=LOCAL ⇒ M flag set in header. Wire shape is
//! [0x5D, 0x00 (wireexpr.id VLE 0), 0x01 (msg_put header MID 0x01),
//! 0x00 (msg_put.payload_len VLE 0)] = 4 bytes (header byte 0x5D =
//! MID 0x1D | M flag at bit 6).
//!
//! Why this matters: wz `Push::default()` defaults the inner-body
//! variant to `CodecZenohMsgPut(MsgPut::default())` per R88 variant-
//! default-uniformity; R106 additionally bakes `M=1` into the header
//! default so a freshly-built Push carries the same M flag that
//! zenoh-pico's `_z_push_encode` derives from
//! `_z_wireexpr_is_local(&_key)` when `_key._mapping = 0` (LOCAL,
//! the natural default). zenoh-pico's `_z_push_encode` reaches the
//! same wire bytes when the fixture sets
//! `_body._is_put = true` (so the encoder picks the PUT branch) AND
//! `_qos._val = 5` (so `has_qos_ext = (val != _Z_N_QOS_DEFAULT._val)`
//! evaluates to false — the extern const lives in zenoh-pico's
//! definitions/network.c L22 with `._val = 5`). The `_key._mapping`
//! field stays at its zero-init default of 0 (LOCAL); the encoder's
//! `is_local` check then sets M=1, matching the R106-baked wz
//! default.

use wz_codecs::push::Push;
use zenoh_pico_sys::{
    _z_n_msg_push_t, _z_push_encode, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

fn zenoh_pico_encode_push_default() -> Vec<u8> {
    // SAFETY: bindgen surfaces `_z_n_msg_push_t` as a struct whose
    // union member `_body._body` (the put / del variant) is opaque
    // bytes. Zero-init via `Default` produces a `_z_n_msg_push_t`
    // where `_qos._val = 0` (NOT the upstream default of 5) and
    // `_body._is_put = false` (would select the del branch). Both
    // must be patched. `_key._mapping = 0 = _Z_KEYEXPR_MAPPING_LOCAL`
    // is now the natural default that matches wz: the encoder's
    // `_z_wireexpr_is_local(&_key)` check sets M=1, and R106 bakes
    // the same M=1 into wz Push::default()'s header.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let mut msg = _z_n_msg_push_t::default();
        // Match _Z_N_QOS_DEFAULT._val = 5 (definitions/network.c
        // L22) so the encoder's
        // `has_qos_ext = (qos._val != _Z_N_QOS_DEFAULT._val)` check
        // evaluates false and no qos extension is emitted.
        msg._qos._val = 5;
        // Default zenoh-pico zero-init has `_is_put = false` which
        // would route to the DEL branch (header MID 0x02). wz
        // Push::default()'s body defaults to MsgPut so we patch
        // here to match.
        msg._body._is_put = true;
        let ret = _z_push_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_push_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_push_default_byte_equivalent() {
    let wz = Push::default().encode_to_vec();
    let pico = zenoh_pico_encode_push_default();
    assert_eq!(
        wz, pico,
        "default Push must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    assert_eq!(
        wz,
        &[0x5D, 0x00, 0x01, 0x00],
        "default wire form: [push_header (MID 0x1D | M flag), wireexpr.id_vle, msg_put_header, payload_len_vle]"
    );
}

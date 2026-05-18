// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `oam` codec (§5 OAM network envelope;
//! R92 wz-side authoring, R103 Layer 3 byte-compare).
//!
//! First Layer 3 fixture exercising a self-flag-dispatch variant
//! (header.enc bits 5..6 select the inner body codec — UNIT 00 /
//! ZINT 01 / ZBUF 10). R88 RFC variant-default-uniformity declares
//! UNIT as the default arm; zenoh-pico's `_z_oam_encode` defaults
//! the `_enc` enum value to 0 (`_Z_OAM_BODY_UNIT`, the first
//! variant). Both sides therefore reach the same default-state
//! wire bytes when the `_ext_qos` field is patched to match the
//! upstream `_Z_N_QOS_DEFAULT` sentinel.
//!
//! Default wire: `[0x1F, 0x00]` = 2 bytes (header with no flags,
//! id VLE 0). No qos / timestamp ext, no body (UNIT is empty per
//! the protocol §5 OAM definition).

use wz_codecs::oam::Oam;
use zenoh_pico_sys::{
    _z_n_msg_oam_t, _z_oam_encode, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

fn zenoh_pico_encode_oam_default() -> Vec<u8> {
    // SAFETY: same wbuf-extract pattern as layer3_response_final.rs.
    // The `_z_n_msg_oam_t` zero-init produces `_enc = 0` which
    // corresponds to `_Z_OAM_BODY_UNIT` (first enum variant); the
    // wz default arm declaration matches, so the only field that
    // must be patched is `_ext_qos._val = 5` to align with the
    // `_Z_N_QOS_DEFAULT` sentinel and elide the qos extension.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let mut msg = _z_n_msg_oam_t::default();
        msg._ext_qos._val = 5;
        let ret = _z_oam_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_oam_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_oam_default_byte_equivalent() {
    let wz = Oam::default().encode();
    let pico = zenoh_pico_encode_oam_default();
    assert_eq!(
        wz, pico,
        "default OAM must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    assert_eq!(wz, &[0x1F, 0x00], "default wire form: [MID, id VLE 0]");
}

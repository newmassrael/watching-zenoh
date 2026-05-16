// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `keep_alive` codec (§4.1 transport
//! KeepAlive body, empty).
//!
//! Pins the empty-body contract: both wz `KeepAlive::encode()` and
//! zenoh-pico `_z_keep_alive_encode` produce zero bytes. The
//! enclosing transport-message envelope writes the MID byte
//! separately; the body codec scope is exactly 0 bytes.
//!
//! Smallest Layer 3 test in the catalog. Validates that the empty-
//! datamodel codec emit shape (= no fields, no bytes) is consistent
//! across wz and zenoh-pico — caught if either side accidentally
//! emits a sentinel or version-prefix.

use wz_codecs::keep_alive::KeepAlive;
use zenoh_pico_sys::{
    _z_keep_alive_encode, _z_t_msg_keep_alive_t, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf,
    _z_zbuf_clear,
};

fn zenoh_pico_encode_keep_alive() -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let msg = _z_t_msg_keep_alive_t::default();
        let header = 0u8; // ignored by _z_keep_alive_encode
        let ret = _z_keep_alive_encode(&mut wbf, header, &msg);
        assert_eq!(ret, 0, "_z_keep_alive_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_keep_alive_zero_bytes() {
    let wz = KeepAlive::default().encode();
    let pico = zenoh_pico_encode_keep_alive();
    assert_eq!(wz, pico);
    assert!(wz.is_empty(), "KeepAlive body must be zero bytes");
}

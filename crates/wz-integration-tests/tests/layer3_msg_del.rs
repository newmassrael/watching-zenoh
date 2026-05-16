// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `msg_del` codec (§6.1 PushBody DEL body).
//!
//! Sibling to msg_put — distinct only by MID (0x02 vs 0x01) and the
//! absence of a payload field. Scope: simple DEL with no header
//! flags (no timestamp, no source_info, no attachment) → body
//! reduces to a SINGLE header byte (MID 0x02).
//!
//! Wire shape (per `_z_push_body_encode` with `_is_put=false` and
//! all check fields cleared, message.c:257-303): just `[0x02]`.
//!
//! This is the minimum-bytes Layer 3 codec test in the catalog
//! (1-byte output). Pins the DEL contract: an empty DEL is a
//! single header byte with no trailing data.

use wz_codecs::msg_del::MsgDel;
use zenoh_pico_sys::{
    _z_del_encode, _z_msg_del_t, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

const MID_Z_DEL: u8 = 0x02;

fn zenoh_pico_encode_del_no_flags() -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let msg = _z_msg_del_t::default(); // all-zero → no flags set
        let ret = _z_del_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_del_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_msg_del_no_flags_single_byte() {
    let wz = MsgDel {
        header: MID_Z_DEL,
        timestamp: None,
        extensions: None,
    }
    .encode();
    let pico = zenoh_pico_encode_del_no_flags();
    assert_eq!(wz, pico);
    assert_eq!(wz, vec![MID_Z_DEL], "no-flags DEL is a single MID byte");
}

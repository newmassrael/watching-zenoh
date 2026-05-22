// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `interest` codec (§5 INTEREST network
//! envelope; R93/R94 wz-side authoring, R104 Layer 3 byte-compare).
//!
//! Default-state INTEREST is the is_final form: the upstream
//! `_z_n_interest_encode` writes only [header, id VLE] when
//! `_interest.flags` has neither CURRENT (0x20) nor FUTURE (0x40)
//! set. The wz Interest::default()'s header is 0x19 (no flags), so
//! R94's disjunction present-if `header.C || header.F` evaluates
//! false and the body sub-codec is skipped. Both sides reach the
//! same `[0x19, 0x00]` 2-byte wire.
//!
//! Non-final state (header.C=1 or F=1) involves the interest_body
//! sub-codec landed in R94, which carries its own wireexpr embed.
//! That state is the next Layer 3 extension; for R104 first contact
//! we pin the is_final byte-equivalence.

use wz_codecs::interest::Interest;
use zenoh_pico_sys::{
    _z_n_interest_encode, _z_n_msg_interest_t, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf,
    _z_zbuf_clear,
};

fn zenoh_pico_encode_interest_default() -> Vec<u8> {
    // SAFETY: standard wbuf-extract path; the zero-init
    // `_z_n_msg_interest_t` has `_interest.flags = 0` (no CURRENT,
    // no FUTURE) → encoder takes the is_final branch and writes
    // only [header MID, id VLE]. No qos field on the n_msg shape
    // (INTEREST does not carry the qos / timestamp ext slots that
    // PUSH / OAM / RESPONSE attach), so no `_ext_qos` patch is
    // needed.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let msg = _z_n_msg_interest_t::default();
        let ret = _z_n_interest_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_n_interest_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_interest_default_byte_equivalent() {
    let wz = Interest::default().encode_to_vec();
    let pico = zenoh_pico_encode_interest_default();
    assert_eq!(
        wz, pico,
        "default INTEREST must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    assert_eq!(
        wz,
        &[0x19, 0x00],
        "default is_final wire form: [MID, id VLE 0]"
    );
}

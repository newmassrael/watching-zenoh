// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `scout` codec (§3 scouting layer body).
//!
//! Validates the cbyte multi-bit packing primitive (3-bit + 1-bit +
//! 4-bit fields in a single byte) AND the local-flag `present-if`
//! gate (cbyte.I gates zid emission). Scout has no parent-flag
//! dependency, so this test exercises the simplest non-trivial
//! handshake-shape codec; init/open/join (R44 layer3_*) layer
//! parent.S / parent.A gates on top.
//!
//! Wire shape (per vendor/zenoh-pico/src/protocol/codec/message.c:605-623):
//!   - byte 0  : version (uint8)
//!   - byte 1  : cbyte (low 3 bits = what; bit 3 = I; high 4 bits = zid_len_m1)
//!   - bytes 2+: zid (only when cbyte.I=1; length = cbyte.zid_len_m1+1)
//!
//! Test asymmetry: zenoh-pico takes msg._what + msg._zid as semantic
//! inputs and COMPUTES cbyte internally; wz takes Scout.cbyte as a
//! pre-packed raw u8 input. The test pre-computes cbyte from the
//! same (what, zid) inputs, sets wz.cbyte = pre-computed, and
//! verifies byte equivalence. Any divergence in cbyte packing
//! semantics between wz and zenoh-pico would surface here.

use wz_codecs::scout::Scout;
use zenoh_pico_sys::{
    _z_id_t, _z_s_msg_scout_t, _z_scout_encode, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf,
    _z_zbuf_clear,
};

/// Pack a 16-byte zenoh-id ([u8; 16]) from a variable-length Rust slice.
/// Trailing zeros encode "shorter id" per zenoh-pico's _z_id_len
/// strip-trailing-zeros convention.
fn pack_zid(payload: &[u8]) -> [u8; 16] {
    assert!(payload.len() <= 16);
    let mut id = [0u8; 16];
    id[..payload.len()].copy_from_slice(payload);
    id
}

/// Mirror zenoh-pico's cbyte construction logic from
/// `_z_scout_encode` (message.c:611-616) so the wz-side Scout.cbyte
/// input matches what zenoh-pico computes internally from
/// (what, zid).
fn compute_scout_cbyte(what: u8, zid_len: u8) -> u8 {
    let mut cbyte = what & 0x07;
    if zid_len > 0 {
        cbyte |= 0x08; // _Z_FLAG_T_SCOUT_I (bit 3)
        cbyte |= ((zid_len - 1) & 0x0F) << 4;
    }
    cbyte
}

fn zenoh_pico_encode_scout(version: u8, what: u8, zid_bytes: &[u8]) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let zid = _z_id_t {
            id: pack_zid(zid_bytes),
        };
        let msg = _z_s_msg_scout_t {
            _zid: zid,
            _what: what as u32, // z_what_t is uint32_t on the C side
            _version: version,
        };
        let header = 0u8; // scout encoder ignores header per upstream
        let ret = _z_scout_encode(&mut wbf, header, &msg);
        assert_eq!(
            ret, 0,
            "_z_scout_encode returned non-zero for version={version} what={what}"
        );
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_scout_no_zid() {
    // cbyte.I=0 → no zid bytes on the wire. Body = [version, cbyte].
    let version = 0x02u8;
    let what = 0x05u8; // ROUTER | CLIENT bitmask
    let zid_bytes: &[u8] = &[];

    let cbyte = compute_scout_cbyte(what, zid_bytes.len() as u8);
    let wz_bytes = Scout {
        version,
        cbyte,
        zid: None,
    }
    .encode();

    let pico_bytes = zenoh_pico_encode_scout(version, what, zid_bytes);
    assert_eq!(wz_bytes, pico_bytes);
}

#[test]
fn layer3_scout_with_zid() {
    // cbyte.I=1 + zid_len_m1=2 → zid is 3 bytes.
    let version = 0x02u8;
    let what = 0x01u8; // ROUTER
    let zid_bytes: Vec<u8> = vec![0x11, 0x22, 0x33];

    let cbyte = compute_scout_cbyte(what, zid_bytes.len() as u8);
    let wz_bytes = Scout {
        version,
        cbyte,
        zid: Some(zid_bytes.clone()),
    }
    .encode();

    let pico_bytes = zenoh_pico_encode_scout(version, what, &zid_bytes);
    assert_eq!(wz_bytes, pico_bytes);
}

#[test]
fn layer3_scout_max_zid_16_bytes() {
    // Boundary: zid_len_m1=15 (max 4-bit value) → 16-byte zid.
    let version = 0x02u8;
    let what = 0x07u8; // all-on (ROUTER | PEER | CLIENT)
    let zid_bytes: Vec<u8> = (0x10..0x20).collect();

    let cbyte = compute_scout_cbyte(what, zid_bytes.len() as u8);
    let wz_bytes = Scout {
        version,
        cbyte,
        zid: Some(zid_bytes.clone()),
    }
    .encode();

    let pico_bytes = zenoh_pico_encode_scout(version, what, &zid_bytes);
    assert_eq!(wz_bytes, pico_bytes);
}

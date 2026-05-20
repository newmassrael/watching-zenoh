// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `response_final` codec (§5 RESPONSE_FINAL
//! network envelope; R91 wz-side authoring, R101 first-contact Layer 3
//! byte-compare).
//!
//! Pins the textbook contract: wz `ResponseFinal::default().encode_to_vec()`
//! produces byte-for-byte identical output to zenoh-pico's
//! `_z_response_final_encode` invoked against
//! `_z_n_msg_response_final_t { _request_id = 0 }`. Default state is
//! the minimum-cardinality wire shape:
//!
//!   byte 0   : header byte (MID Z_RESPONSE_FINAL = 0x1A; no flags
//!              set because zenoh-pico's encoder never sets Z and our
//!              codegen leaves Z=0 in the default).
//!   byte 1+  : `_request_id` VLE u64 (= 0 → 1-byte 0x00 encoding).
//!
//! Why this matters:
//!   The codec catalog post-R90 (PUSH / RESPONSE_FINAL / OAM /
//!   INTEREST envelope+body / RESPONSE) accumulated wire-interop
//!   debt — wz round-trips were self-consistent but never validated
//!   against zenoh-pico's actual bytes. R101 closes the smallest
//!   first contact (ResponseFinal: simplest envelope with the
//!   smallest data surface) and seeds the per-codec rollout pattern
//!   for the rest of the post-R90 catalog.

use wz_codecs::response_final::ResponseFinal;
use zenoh_pico_sys::{
    _z_n_msg_response_final_t, _z_response_final_encode, _z_wbuf_clear, _z_wbuf_make,
    _z_wbuf_to_zbuf, _z_zbuf_clear,
};

fn zenoh_pico_encode_response_final(request_id: u64) -> Vec<u8> {
    // SAFETY: `_z_wbuf_make(64, false)` allocates a heap-backed
    // growable buffer with capacity 64 bytes and `is_expandable=false`
    // (no realloc — a 2-byte ResponseFinal fits with margin). The
    // `_z_n_msg_response_final_t` POD has a single `_z_zint_t` field
    // (bindgen surfaces it as `usize` on x86_64-linux because the
    // upstream typedef resolves to `size_t`); we widen via `as _` so
    // the test's u64 input stays the natural integer type at the
    // call site. After encode, `_z_wbuf_to_zbuf` produces a read-
    // side view we slice into a Rust Vec, then `_z_wbuf_clear`
    // releases the buffer.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let msg = _z_n_msg_response_final_t {
            _request_id: request_id as _,
        };
        let ret = _z_response_final_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_response_final_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_response_final_default_byte_equivalent() {
    let wz = ResponseFinal::default().encode_to_vec();
    let pico = zenoh_pico_encode_response_final(0);
    assert_eq!(
        wz, pico,
        "default ResponseFinal must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    assert_eq!(wz, &[0x1A, 0x00], "default wire form is [MID, rid VLE 0]");
}

#[test]
fn layer3_response_final_nonzero_rid_byte_equivalent() {
    // Single-byte VLE: any rid in [0, 127] encodes as a single byte
    // equal to the value. Pick 0x42 for the visual distinctness.
    let rid = 0x42_u64;
    let wz = ResponseFinal {
        header: 0x1A,
        request_id: rid,
        ..ResponseFinal::default()
    }
    .encode_to_vec();
    let pico = zenoh_pico_encode_response_final(rid);
    assert_eq!(
        wz, pico,
        "ResponseFinal {{ request_id: 0x42 }} must match zenoh-pico"
    );
    assert_eq!(wz, &[0x1A, 0x42]);
}

#[test]
fn layer3_response_final_multibyte_vle_rid_byte_equivalent() {
    // rid = 200 (= 0xC8) crosses the 7-bit VLE boundary, producing a
    // 2-byte VLE: 0xC8 = 1100_1000; low 7 bits 0x48 with continuation
    // bit set = 0xC8; high bits = 0x01 → emitted as [0xC8, 0x01].
    let rid = 200_u64;
    let wz = ResponseFinal {
        header: 0x1A,
        request_id: rid,
        ..ResponseFinal::default()
    }
    .encode_to_vec();
    let pico = zenoh_pico_encode_response_final(rid);
    assert_eq!(
        wz, pico,
        "multi-byte VLE rid must match zenoh-pico byte-for-byte"
    );
    assert_eq!(wz, &[0x1A, 0xC8, 0x01], "multi-byte VLE wire form");
}

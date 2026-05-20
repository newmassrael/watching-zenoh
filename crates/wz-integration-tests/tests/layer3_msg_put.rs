// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `msg_put` codec (§6.1 PushBody PUT body).
//!
//! Validates the payload-layer data path: 1-byte header (MID + T/E/Z
//! flags) + optional embeds (timestamp / encoding) + optional tlv-chain
//! (ext_entry) + ALWAYS-present payload (VLE u64 length + bytes).
//!
//! Scope (R46 first cut): simple PUT with NO header flags set
//! (T=0, E=0, Z=0). zenoh-pico's `_z_put_encode` (message.c:369-379)
//! routes to `_z_push_body_encode` which computes header byte
//! internally from the msg state — for a zero-init msg with only
//! `_payload` populated, the encoder skips the timestamp / encoding /
//! ext-chain branches and writes header byte 0x01 (Z_PUT MID) + VLE
//! payload_len + payload bytes.
//!
//! The wz path takes `header` as an explicit field — for byte
//! equivalence the test pre-computes the same header value
//! (0x01 for no-flags PUT) and leaves the optional sub-codecs as
//! None.
//!
//! Test corpus picks payload size variants that exercise the VLE
//! width boundary on `payload_len`: empty (VLE=0), 1-byte, 127-byte
//! (1-byte VLE boundary), 128-byte (2-byte VLE), 256-byte.
//!
//! Larger payloads + flag-set scenarios (T/E/Z) land in subsequent
//! R46-extension rounds — each new flag exercises a different
//! primitive class (timestamp embed, encoding embed, ext_entry
//! variant + tlv-chain).

use wz_codecs::msg_put::MsgPut;
use zenoh_pico_sys::{
    _z_bytes_from_buf, _z_msg_put_t, _z_put_encode, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf,
    _z_zbuf_clear,
};

// Note: `_z_bytes_drop` is `static inline` in zenoh-pico's
// `collections/bytes.h` and bindgen does not emit bindings for inline
// helpers by default. Each test invocation leaks the per-test
// payload _z_bytes_t (a single arc_slice_svec) — the leak is bounded
// by the test corpus size + Rust's process-exit cleanup, and is
// acceptable in the test harness scope. Production consumers of the
// FFI must wrap a non-inline drop helper if they hold _z_bytes_t
// long-term (R46b carry).

const MID_Z_PUT: u8 = 0x01;

fn zenoh_pico_encode_put_no_flags(payload: &[u8]) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(2048, false);

        // Zero-init msg_put. With all sub-fields zeroed,
        // _z_push_body_encode's has_timestamp / has_encoding /
        // has_source_info / has_attachment checks all return false →
        // header = MID_Z_PUT (no flags) → encoder writes only [0x01,
        // VLE(payload_len), payload].
        let mut msg = _z_msg_put_t::default();
        if !payload.is_empty() {
            let r = _z_bytes_from_buf(&mut msg._payload, payload.as_ptr(), payload.len());
            assert_eq!(r, 0, "_z_bytes_from_buf failed for {} bytes", payload.len());
        }

        let ret = _z_put_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_put_encode failed");

        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();

        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        // See comment at the use statement above re: _z_bytes_drop
        // omission. msg._payload leaks per test invocation.
        bytes
    }
}

#[test]
fn layer3_msg_put_no_flags_payload_variants() {
    // VLE width boundary corpus on payload_len.
    let corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xAA],
        (0..127u8).collect(),        // VLE 1-byte boundary (len=127)
        (0..128u8).collect(),        // VLE 2-byte boundary (len=128)
        (0..255u8).collect(), // 255 bytes (2-byte VLE)
    ];
    for payload in corpus {
        let wz_bytes = MsgPut {
            header: MID_Z_PUT,
            timestamp: None,
            encoding: None,
            extensions: None,
            payload_len: payload.len() as u64,
            payload: payload.clone(),
        }
        .encode_to_vec();
        let pico_bytes = zenoh_pico_encode_put_no_flags(&payload);
        assert_eq!(
            wz_bytes, pico_bytes,
            "Layer 3 byte mismatch for msg_put payload.len={}",
            payload.len()
        );
    }
}

#[test]
fn layer3_msg_put_empty_payload_yields_header_and_zero_vle() {
    // Pin the canonical empty-PUT wire form: [0x01, 0x00] = MID + VLE(0).
    let wz = MsgPut {
        header: MID_Z_PUT,
        timestamp: None,
        encoding: None,
        extensions: None,
        payload_len: 0,
        payload: vec![],
    }
    .encode_to_vec();
    let pico = zenoh_pico_encode_put_no_flags(&[]);
    assert_eq!(wz, pico);
    assert_eq!(wz, vec![MID_Z_PUT, 0x00], "empty-PUT canonical form");
}

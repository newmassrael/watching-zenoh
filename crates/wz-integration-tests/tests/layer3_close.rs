// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `close` codec (session-close frame body).
//!
//! This is the FIRST objective evidence in the project that a
//! watching-zenoh codec SCXML matches zenoh-pico 1.9.0's wire format
//! byte-for-byte. Prior Layers (1 = emit success, 2 = sce-codegen
//! body-golden) were internal consistency checks; only Layer 3
//! actually compares against a reference implementation of the wire.
//!
//! Test shape:
//!
//!   1. Construct `wz_codecs::close::Close { reason }` for each
//!      reason byte in the corpus.
//!   2. Encode via `Close::encode()` → `Vec<u8>` (wz path).
//!   3. Construct `_z_t_msg_close_t { _reason: reason }` for the
//!      same input.
//!   4. Encode via `_z_close_encode(wbf, header, &msg)` → bytes
//!      extracted from the wbuf → zbuf → `_z_iosli_t._buf[.._w_pos]`
//!      path (zenoh-pico path).
//!   5. Assert byte-equality.
//!
//! Per `vendor/zenoh-pico/src/protocol/codec/transport.c:335-343`,
//! `_z_close_encode` writes exactly `msg->_reason` (1 byte) and
//! ignores the `header` argument. The wz-side `close.scxml` declares
//! a single `<data id="reason" sce:type="uint8" sce:byte="0"
//! sce:bit-size="8"/>` field. Both paths should produce a single byte
//! equal to the reason — this is the simplest non-trivial Layer 3
//! gate.
//!
//! The corpus deliberately includes 0x00 (canonical Generic close
//! reason), 0x05 (Expired per `_z_close_reason_t` in
//! `transport.h`), 0xFF (out-of-defined-range — still a valid uint8
//! on the wire; both encoders should emit it unchanged), plus
//! mid-range arbitrary values.

use wz_codecs::close::Close;
use zenoh_pico_sys::{
    _z_close_encode, _z_t_msg_close_t, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

/// Encode a session-close body via zenoh-pico's FFI path. Returns the
/// raw bytes the encoder wrote, with all C-side resources cleaned up
/// before return.
fn zenoh_pico_encode_close(reason: u8) -> Vec<u8> {
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let msg = _z_t_msg_close_t { _reason: reason };
        let header = 0u8; // ignored by _z_close_encode per upstream
        let ret = _z_close_encode(&mut wbf, header, &msg);
        assert_eq!(
            ret, 0,
            "_z_close_encode returned non-zero z_result_t for reason=0x{:02X}",
            reason
        );

        // Extract the bytes the encoder wrote. The wbuf→zbuf
        // conversion yields a read view of the same underlying iosli;
        // `_w_pos` is the count of bytes written into the buffer and
        // `_buf` is the pointer to the first byte.
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let len = zbf._ios._w_pos;
        let ptr = zbf._ios._buf;
        let bytes = std::slice::from_raw_parts(ptr, len).to_vec();

        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

#[test]
fn layer3_close_byte_compare_canonical_reasons() {
    // Reasons sourced from zenoh-pico's `_z_close_reason_t` enum at
    // include/zenoh-pico/protocol/definitions/transport.h. The wire
    // format encodes any uint8 verbatim, so we sample both defined
    // codes and arbitrary off-range values to ensure the encoder
    // does no implicit validation / sentinel mapping.
    let corpus = [
        0x00u8, // GENERIC
        0x01,   // UNSUPPORTED
        0x02,   // INVALID
        0x03,   // MAX_SESSIONS
        0x04,   // MAX_LINKS
        0x05,   // EXPIRED
        0x06,   // WRITE_ERROR
        0x07,   // READ_ERROR
        0x42,   // arbitrary mid-range
        0xFF,   // out-of-defined-range — both encoders must pass through
    ];

    for reason in corpus {
        let wz_bytes = Close { reason }.encode();
        let pico_bytes = zenoh_pico_encode_close(reason);
        assert_eq!(
            wz_bytes, pico_bytes,
            "Layer 3 byte mismatch for close.reason=0x{reason:02X}: \
             wz={wz_bytes:?}, zenoh-pico={pico_bytes:?}"
        );
    }
}

#[test]
fn layer3_close_emits_exactly_one_byte() {
    // Pin the wire shape contract: a session-close body is exactly
    // one byte (the reason). If either encoder ever drifts to a
    // multi-byte body (e.g., a future zenoh-pico patch adds an
    // implicit version prefix), this test catches it and forces an
    // explicit decision rather than a silent divergence.
    let bytes = Close { reason: 0x01 }.encode();
    assert_eq!(
        bytes.len(),
        1,
        "wz Close.encode produced {} bytes; close body must be 1 byte",
        bytes.len()
    );
    let bytes = zenoh_pico_encode_close(0x01);
    assert_eq!(
        bytes.len(),
        1,
        "zenoh-pico _z_close_encode produced {} bytes; close body must be 1 byte",
        bytes.len()
    );
}

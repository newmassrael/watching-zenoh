// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Byte-parity gate for the zenoh-pico SERIAL-link framing codecs:
//! `crc32`, `serial_envelope`, and `cobs_encode` / `cobs_decode`. Each
//! is pinned against zenoh-pico's exact reference implementation on the
//! `Z_FEATURE_LINK_SERIAL` path:
//!
//!   - CRC32 oracle: `_z_crc32`
//!     (vendor/zenoh-pico/src/utils/checksum.c:19-28). This is a
//!     NON-standard CRC-32 — forward polynomial 0x04C11DB7 with a
//!     right-shift (reflected-style) reduction — so the reference
//!     values below are computed from `_z_crc32` itself, NOT from a
//!     canonical CRC-32/ISO-HDLC table (which would give 0xCBF43926
//!     for "123456789" instead of pico's 0xFC4F2BE9).
//!
//!   - Frame assembly oracle: `_z_serial_msg_serialize`
//!     (vendor/zenoh-pico/src/protocol/codec/serial.c:28-68) lays out
//!     `[header(1)][len(2 LE)][payload(N)][crc32(4 LE)]` (= N + 7
//!     bytes) before COBS-stuffing. The crc32 field carries the
//!     `_z_crc32` of the payload only.
//!
//!   - COBS oracle: `_z_cobs_encode` / `_z_cobs_decode`
//!     (vendor/zenoh-pico/src/utils/encoding.c:19-76). Expressed in
//!     SCXML via SCE's algorithm-kind byte-buffer-build primitives
//!     (SCE 9c0356a41). The on-wire 0x00 EOP delimiter is appended /
//!     stripped by the serial link driver, not by the COBS codec, so
//!     it is exercised here only as decode EOP tolerance.

#![cfg(feature = "codec-serial")]

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::cobs_decode::cobs_decode;
use wz_codecs::cobs_encode::cobs_encode;
use wz_codecs::crc32::crc32;
use wz_codecs::serial_envelope::SerialEnvelope;

/// CRC32 vectors taken directly from zenoh-pico's `_z_crc32`.
///
/// Each pair is `(payload, expected_crc32)`. The empty case exercises
/// the `~0xFFFFFFFF == 0` identity (no bytes folded). The 257-byte
/// case mirrors the project's recurring "just over the legacy 256
/// bound" payload theme.
#[test]
fn crc32_matches_zenoh_pico_reference() {
    // (label, payload, expected) — payload built inline because slice
    // literals cannot embed a repeat-count macro.
    let abcdef: &[u8] = &[0xAB, 0xCD, 0xEF];
    let a256: Vec<u8> = vec![0x41; 256];
    let x257: Vec<u8> = vec![0x42; 257];

    let cases: [(&str, &[u8], u32); 5] = [
        ("empty", &[], 0x0000_0000),
        ("abcdef", abcdef, 0xFBA7_2077),
        ("123456789", b"123456789", 0xFC4F_2BE9),
        ("0x41*256", &a256, 0xFDCD_51B9),
        ("0x42*257", &x257, 0xF992_A3A6),
    ];

    for (label, payload, expected) in cases {
        let got = crc32(payload);
        assert_eq!(
            got, expected,
            "crc32({label}) = 0x{got:08X}, expected pico 0x{expected:08X}"
        );
    }
}

/// The non-standard property regression-pinned explicitly: pico's
/// serial CRC32 must NOT equal the canonical CRC-32/ISO-HDLC value.
/// If a future SCXML edit accidentally flips to a reflected-poly /
/// table form, this catches it even though the round-trip would still
/// "look like a CRC".
#[test]
fn crc32_is_pico_variant_not_iso_hdlc() {
    let standard_iso_hdlc = 0xCBF4_3926u32; // CRC-32 of "123456789"
    assert_ne!(
        crc32(b"123456789"),
        standard_iso_hdlc,
        "pico serial CRC32 is the 0x04C11DB7 right-shift variant, \
         not canonical CRC-32/ISO-HDLC"
    );
}

/// `serial_envelope` assembles `[header][len(2 LE)][payload][crc32(4 LE)]`
/// exactly like zenoh-pico's `_z_serial_msg_serialize` pre-COBS buffer
/// (serial.c:28-68). This is the codec shape (fixed crc32 after a
/// length-ref payload) that required SCE's positional-validity path
/// selection; the encode order and decode offsets are pinned here.
#[test]
fn serial_envelope_matches_pico_pre_cobs_frame() {
    let abcdef: &[u8] = &[0xAB, 0xCD, 0xEF];
    let cases: [(u8, &[u8], &[u8]); 2] = [
        (
            0x00,
            abcdef,
            // header, len=0x0003 LE, payload, crc 0xFBA72077 LE
            &[0x00, 0x03, 0x00, 0xAB, 0xCD, 0xEF, 0x77, 0x20, 0xA7, 0xFB],
        ),
        // INIT frame (header 0x01), empty payload, crc 0x00000000
        (0x01, &[], &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    ];

    for (header, payload, expected) in cases {
        let env = SerialEnvelope {
            header,
            payload_len: payload.len() as u16,
            payload,
            crc32: crc32(payload),
        };
        let wire = env.encode_to_vec();
        assert_eq!(
            &wire[..],
            expected,
            "serial_envelope encode mismatch for header 0x{header:02X}"
        );

        let mut cursor = SceCursor::new(&wire);
        let decoded = SerialEnvelope::decode(&mut cursor).expect("serial_envelope decode");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.payload_len as usize, payload.len());
        assert_eq!(decoded.payload, payload, "decoded payload mismatch");
        assert_eq!(decoded.crc32, crc32(payload), "decoded crc32 mismatch");
    }
}

/// `cobs_encode` matches canonical COBS (byte-equal to zenoh-pico
/// `_z_cobs_encode`, encoding.c:19-47). The 0x00 EOP delimiter is the
/// link driver's responsibility and is NOT part of this output.
#[test]
fn cobs_encode_matches_canonical() {
    let v: &[u8] = &[0x11, 0x22, 0x00, 0x33];
    let cases: [(&[u8], &[u8]); 5] = [
        (&[], &[0x01]),
        (&[0x00], &[0x01, 0x01]),
        (v, &[0x03, 0x11, 0x22, 0x02, 0x33]),
        (&[0x11, 0x00, 0x00], &[0x02, 0x11, 0x01, 0x01]),
        (&[0x11, 0x22, 0x33], &[0x04, 0x11, 0x22, 0x33]),
    ];
    for (inp, exp) in cases {
        let enc = cobs_encode(inp).expect("cobs_encode within capacity");
        assert_eq!(enc.as_slice(), exp, "cobs_encode mismatch for {inp:02X?}");
    }
}

/// `cobs_decode` is the exact inverse of `cobs_encode` (mirrors pico
/// `_z_cobs_decode`, encoding.c:49-76), and tolerates an optional
/// trailing 0x00 EOP (it breaks on a 0x00 code byte).
#[test]
fn cobs_decode_inverts_encode() {
    let frame: &[u8] = &[0x00, 0x03, 0x00, 0xAB, 0xCD, 0xEF, 0x77, 0x20, 0xA7, 0xFB];
    let originals: [&[u8]; 6] = [
        &[],
        &[0x00],
        &[0x11, 0x22, 0x00, 0x33],
        &[0x11, 0x00, 0x00],
        &[0x11, 0x22, 0x33],
        frame, // a real serial frame (contains 0x00 bytes)
    ];
    for orig in originals {
        let enc = cobs_encode(orig).expect("encode");
        let dec = cobs_decode(enc.as_slice()).expect("decode");
        assert_eq!(
            dec.as_slice(),
            orig,
            "cobs round-trip mismatch for {orig:02X?}"
        );
    }

    // Explicit decode vectors, and EOP tolerance.
    assert_eq!(cobs_decode(&[0x01]).unwrap().as_slice(), b"");
    assert_eq!(cobs_decode(&[0x01, 0x01]).unwrap().as_slice(), &[0x00]);
    assert_eq!(
        cobs_decode(&[0x03, 0x11, 0x22, 0x02, 0x33])
            .unwrap()
            .as_slice(),
        &[0x11, 0x22, 0x00, 0x33]
    );
    // trailing 0x00 EOP is consumed/stopped-on, same output:
    assert_eq!(
        cobs_decode(&[0x03, 0x11, 0x22, 0x02, 0x33, 0x00])
            .unwrap()
            .as_slice(),
        &[0x11, 0x22, 0x00, 0x33]
    );
}

/// Full pico `_z_serial_msg_serialize` on-wire pipeline (minus the
/// final 0x00 EOP append, a link-driver concern): crc32 -> serial_envelope
/// assemble -> cobs_encode. Pins the COBS bytes and proves the inverse
/// pipeline (cobs_decode -> serial_envelope::decode) recovers the frame.
#[test]
fn serial_frame_full_pipeline_round_trip() {
    let payload: &[u8] = &[0xAB, 0xCD, 0xEF];
    let env = SerialEnvelope {
        header: 0x00,
        payload_len: payload.len() as u16,
        payload,
        crc32: crc32(payload),
    };
    let frame = env.encode_to_vec();
    assert_eq!(
        &frame[..],
        &[0x00, 0x03, 0x00, 0xAB, 0xCD, 0xEF, 0x77, 0x20, 0xA7, 0xFB]
    );

    // COBS-stuff the frame; pico on-wire bytes (pre-EOP):
    let cobs = cobs_encode(&frame).expect("cobs_encode frame");
    assert_eq!(
        cobs.as_slice(),
        &[0x01, 0x02, 0x03, 0x08, 0xAB, 0xCD, 0xEF, 0x77, 0x20, 0xA7, 0xFB]
    );

    // Inverse: destuff -> decode frame -> recover header/payload/crc.
    let destuffed = cobs_decode(cobs.as_slice()).expect("cobs_decode");
    assert_eq!(destuffed.as_slice(), &frame[..]);

    let mut cursor = SceCursor::new(destuffed.as_slice());
    let decoded = SerialEnvelope::decode(&mut cursor).expect("decode recovered frame");
    assert_eq!(decoded.header, 0x00);
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.crc32, crc32(payload));
}

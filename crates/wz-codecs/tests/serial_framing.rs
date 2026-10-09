// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

// ─── cobs_decode is total (open-debt: COBS decoder index panic) ───
//
// A COBS code byte promises that many bytes follow it. Line noise on a serial
// link can promise more than the frame holds; the generated decoder used to
// index `data[i]` for the promise with no bound against the input length and
// panicked. zenoh-pico's `_z_cobs_decode` tests `byte < input_end_ptr` before
// every byte, so a truncated group just ends decoding. These tests pin the
// wz decoder to that behaviour; the comparison against the compiled pico C
// function is `wz-integration-tests/tests/layer3_serial_framing.rs`.

/// The outcome of the pico `_z_cobs_decode` loop, transcribed from
/// encoding.c:49-76 (a pointer walk with a `block` down-counter), plus the
/// one thing the wz decoder deliberately does not copy: a 0x00 CODE byte
/// removes the last written byte (`pos = pos - 1`), which is the implicit
/// zero unless the previous group was a full 0xFF group (it wrote none) or
/// there is no previous group (`pos` moves before the output: SIZE_MAX).
struct PicoModel {
    out: Vec<u8>,
    /// The real data byte a 0x00 code removed (only after a full 0xFF group).
    dropped_data_byte: Option<u8>,
    /// A 0x00 FIRST byte: pico's `pos` moves before the output start.
    underflow: bool,
}

fn pico_model(input: &[u8]) -> PicoModel {
    let mut out = Vec::new();
    let mut code: u8 = 0xFF;
    let mut block: u8 = 0;
    let mut at = 0usize;
    let mut dropped_data_byte = None;
    let mut underflow = false;
    while at < input.len() {
        if block != 0 {
            out.push(input[at]);
            at += 1;
        } else {
            let previous_code = code;
            if previous_code != 0xFF {
                out.push(0);
            }
            code = input[at];
            block = input[at];
            at += 1;
            if code == 0 {
                match out.pop() {
                    // The byte popped is the implicit zero just written,
                    // unless the previous group was a full 0xFF one.
                    Some(b) if previous_code == 0xFF => dropped_data_byte = Some(b),
                    Some(_) => {}
                    None => underflow = true,
                }
                break;
            }
        }
        block = block.wrapping_sub(1);
    }
    PicoModel {
        out,
        dropped_data_byte,
        underflow,
    }
}

/// Every wz result equals the pico model, except where the model's 0x00 code
/// dropped a real data byte, where wz keeps it (the documented difference).
fn assert_wz_matches_pico_model(input: &[u8]) {
    let wz = cobs_decode(input)
        .unwrap_or_else(|_| panic!("capacity exceeded on a short input {input:02X?}"));
    let model = pico_model(input);
    let mut expected = model.out;
    // pico's SIZE_MAX (underflow) has no output at all; wz returns nothing.
    assert!(!model.underflow || expected.is_empty());
    if let Some(b) = model.dropped_data_byte {
        expected.push(b);
    }
    assert_eq!(wz.as_slice(), &expected[..], "input {input:02X?}");
}

#[test]
fn cobs_decode_truncated_group_vectors_match_pico() {
    let cases: [(&[u8], &[u8]); 9] = [
        // promised 2 bytes, 1 left: the available byte is copied
        (&[0x03, 0x11], &[0x11]),
        // promised 4 bytes, none left
        (&[0x05], &[]),
        // the zero closing group 1 is emitted once group 2's code is read
        (&[0x02, 0x11, 0x03], &[0x11, 0x00]),
        (&[0x02, 0x11, 0x03, 0x22], &[0x11, 0x00, 0x22]),
        // a full group cut short
        (&[0xFF, 0x01, 0x02], &[0x01, 0x02]),
        // the EOP is consumed as data when a group promises more than is left
        (&[0x11, 0x22, 0x33, 0x00], &[0x22, 0x33, 0x00]),
        // a promise that ends exactly at the input end is not truncated
        (&[0x03, 0xAA, 0xBB], &[0xAA, 0xBB]),
        (&[0x03, 0xAA, 0xBB, 0x00], &[0xAA, 0xBB]),
        // empty input decodes to nothing
        (&[], &[]),
    ];
    for (input, expected) in cases {
        let got = cobs_decode(input).expect("within capacity");
        assert_eq!(got.as_slice(), expected, "input {input:02X?}");
        assert_wz_matches_pico_model(input);
    }
}

/// Totality: every input of up to two bytes, and every input of three to six
/// bytes over an alphabet that holds each boundary code (0x00, small codes,
/// 0x7F, 0xFE, 0xFF), returns without panicking and agrees with the model.
#[test]
fn cobs_decode_is_total_over_short_inputs() {
    let mut count = 0usize;
    assert_wz_matches_pico_model(&[]);
    for a in 0..=255u8 {
        assert_wz_matches_pico_model(&[a]);
        for b in 0..=255u8 {
            assert_wz_matches_pico_model(&[a, b]);
            count += 1;
        }
    }
    let wide: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x7F, 0xFE, 0xFF];
    let mut input = Vec::new();
    for len in 3..=5usize {
        for mut n in 0..wide.len().pow(len as u32) {
            input.clear();
            for _ in 0..len {
                input.push(wide[n % wide.len()]);
                n /= wide.len();
            }
            assert_wz_matches_pico_model(&input);
            count += 1;
        }
    }
    let narrow: [u8; 5] = [0x00, 0x01, 0x02, 0x05, 0xFF];
    for mut n in 0..narrow.len().pow(6) {
        input.clear();
        for _ in 0..6 {
            input.push(narrow[n % narrow.len()]);
            n /= narrow.len();
        }
        assert_wz_matches_pico_model(&input);
        count += 1;
    }
    assert!(count > 100_000, "the sweep shrank: {count} inputs");
}

/// The input length is not clipped to 16 bits: an input past 65535 bytes is
/// processed whole (or refused for capacity), never cut to `len % 65536`, and
/// neither direction panics. The two `SceBytes` profiles differ here: the
/// no-alloc profile reports `CapacityExceeded` past its bound, the alloc
/// profile grows, so the assertion is the profile-independent one -- an `Ok`
/// result is longer than the clipped length it would have had.
#[test]
fn cobs_codec_does_not_clip_the_input_length_to_16_bits() {
    let long = vec![0x11u8; 65_536 + 3];
    if let Ok(encoded) = cobs_encode(&long) {
        // A clipped input (3 bytes) would encode to 4 bytes.
        assert!(encoded.as_slice().len() > long.len());
        let decoded = cobs_decode(encoded.as_slice()).expect("decode of an encode");
        assert_eq!(decoded.as_slice(), &long[..]);
    }
    // 0x11 codes promise 16 bytes each: a clipped decode would see 3 bytes.
    if let Ok(decoded) = cobs_decode(&long) {
        assert!(decoded.as_slice().len() > 1000);
    }
    // A 3-byte tail after 64 KiB must not decode as if it were the whole input.
    let mut tail = vec![0x01u8; 65_536];
    tail.extend_from_slice(&[0x03, 0xAA, 0xBB]);
    if let Ok(decoded) = cobs_decode(&tail) {
        assert!(decoded.as_slice().len() > 1000);
    }
}

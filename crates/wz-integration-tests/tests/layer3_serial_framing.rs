// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nx — Layer 3 wire-interop: SERIAL-link framing codec vs the REAL
//! zenoh-pico C serial codec.
//!
//! The serial complement of `layer3_fragment.rs` (and the rest of the
//! `layer3_*` byte-compare family): it pairs wz's serial framing
//! (`wz_session_core::serial_link::{encode_frame, decode_frame,
//! SerialFrameReader}`, built on the `wz_codecs` serial primitives) against
//! the compiled zenoh-pico functions (`_z_serial_msg_serialize` /
//! `_z_serial_msg_deserialize` / `_z_cobs_encode` / `_z_cobs_decode` /
//! `_z_crc32`, via `zenoh_pico_sys` FFI) and BYTE-COMPARES.
//!
//! ## Why this exists alongside `wz-codecs/tests/serial_framing.rs`
//!
//! R311ns already pins the wz serial codec against HAND-DERIVED vectors
//! (my transcription of pico's algorithm). Those vectors are a SECONDARY
//! source: a transcription error would pass the vector test yet diverge
//! from real pico. This test compares against the PRIMARY source — pico's
//! actual compiled C — closing the transcription gap, exactly as
//! `layer3_fragment.rs` links `_z_fragment_encode` rather than trusting a
//! hand-built fragment vector. Serial was the one link-codec family still
//! verified only by transcription; this brings it in line with the rest.
//!
//! ## Why FFI (not a live pico process)
//!
//! CORRECTION — the paragraph below is FALSE at the current vendor pin, and
//! is kept because its conclusion ("a live pico serial process is
//! impossible") was quoted and believed. zenoh-pico DOES have a host serial
//! backend: `src/link/transport/serial/tty_posix.c` (Copyright 2026), added
//! to the Linux build by `cmake/platforms/linux.cmake:9`. The link moved
//! OUT of `src/system/<plat>/` — the directory the paragraph checks — into
//! `src/link/transport/serial/`, so looking where it says to look still
//! finds nothing. `tests/pico_serial_link_to_wz_acceptor.rs` now runs the
//! live shape this text calls impossible. What remains true is the
//! sentence AFTER it: the codec functions are platform-independent, which
//! is why this byte-compare needs no link at all and stays the right
//! vehicle for FORMAT parity.
//!
//! zenoh-pico has NO unix serial LINK backend — `_z_open_serial_*` exists
//! only for MCU targets (RPi Pico / esp-idf / zephyr; `src/system/unix/`
//! has no serial). So a live external pico unix process cannot open a
//! serial link, and the live-socket interop shape used for TCP
//! (`wz_reassembles_pico_fragment_tx.rs`) is impossible for serial. The
//! serial CODEC functions, however, are platform-independent
//! (`protocol/codec/serial.c` + `utils/encoding.c` + `utils/checksum.c`
//! carry no `Z_FEATURE_LINK_SERIAL` guard and are compiled into
//! `libzenohpico.a`), so the wire FORMAT is verifiable against real pico
//! C even though the serial TRANSPORT is not host-runnable. The transport
//! handshake interop itself is already proven cross-impl over TCP; serial
//! only swaps the link framing, which is exactly what this verifies.
//!
//! ## Frame shape (identical both sides)
//!
//! `_z_serial_msg_serialize` (serial.c:28) builds
//! `[header(1) | len(2 LE) | payload(N) | crc32(4 LE)]`, COBS-encodes it,
//! and appends a `0x00` EOP — byte-for-byte what `encode_frame` emits.
//! `_z_serial_msg_deserialize` (serial.c:70) COBS-decodes, checks the
//! declared length against the decoded size (trailing-garbage reject) and
//! verifies the CRC32 — the same contract as `decode_frame`. pico's read
//! path (`_z_read_serial_internal`, serial_protocol.c:160-174) accumulates
//! bytes up to AND INCLUDING the `0x00` EOP into `rb`, then deserializes
//! that span — so feeding the full EOP-terminated frame to
//! `_z_serial_msg_deserialize` here mirrors production exactly.
//!
//! Ungated (like the rest of the `layer3_*` byte-compare family): the wz
//! serial surface is always present in this crate's build because
//! `transport-link-serial` / `codec-serial` are pinned on the dev-deps
//! (see Cargo.toml), so this runs under the Layer C1 `cargo test
//! --workspace` lane with its sibling byte-parity tests.

use wz_codecs::cobs_decode::cobs_decode;
use wz_codecs::cobs_encode::cobs_encode;
use wz_codecs::crc32::crc32;
use wz_session_core::serial_link::{decode_frame, encode_frame, SerialFrameReader};
use zenoh_pico_sys::{
    _z_cobs_decode, _z_cobs_encode, _z_crc32, _z_serial_msg_deserialize, _z_serial_msg_serialize,
};

/// (header, payload) cases spanning: empty payload, single byte, embedded
/// `0x00` runs (the case COBS exists for), the full 0..=255 byte range, a
/// COBS block boundary (254), and an MTU-sized payload. Headers cover the
/// data byte (0x00) and the R311nt control flags (INIT 0x01, INIT|ACK 0x03,
/// RESET 0x04) plus 0xFF — the header is opaque to the codec, so every
/// value must round-trip.
fn corpus() -> Vec<(u8, Vec<u8>)> {
    vec![
        (0x00, Vec::new()),
        (0x01, vec![0x42]),
        (0x03, vec![0x00, 0x00, 0x00]),
        (0x04, vec![0xFF; 5]),
        (0xFF, b"hello-serial-frame".to_vec()),
        (0x00, (0..=255u32).map(|i| i as u8).collect()),
        (0x00, vec![0x00; 300]),
        (0x00, vec![0xAB; 254]),
        (0x00, vec![0x5Au8; 1500]),
    ]
}

/// Serialize one frame via the real pico C codec. Buffers sized as pico's
/// own read/send path does (`_Z_SERIAL_MFS_SIZE` tmp, COBS-grown dest),
/// here generous over the payload so every corpus case fits.
fn pico_serialize(header: u8, payload: &[u8]) -> Vec<u8> {
    let mut tmp = vec![0u8; payload.len() + 64];
    let mut dest = vec![0u8; payload.len() + 64 + payload.len() / 254];
    let ret = unsafe {
        _z_serial_msg_serialize(
            dest.as_mut_ptr(),
            dest.len(),
            payload.as_ptr(),
            payload.len(),
            header,
            tmp.as_mut_ptr(),
            tmp.len(),
        )
    };
    assert_ne!(ret, usize::MAX, "pico _z_serial_msg_serialize failed");
    dest.truncate(ret);
    dest
}

/// Deserialize one EOP-terminated frame via the real pico C codec,
/// returning `(header, payload)`. Mirrors `_z_read_serial_internal`'s call
/// (`src` spans the COBS body up to and including the `0x00` EOP).
fn pico_deserialize(wire: &[u8]) -> (u8, Vec<u8>) {
    let mut dst = vec![0u8; wire.len() + 64];
    let mut tmp = vec![0u8; wire.len() + 64];
    let mut header_out: u8 = 0;
    let ret = unsafe {
        _z_serial_msg_deserialize(
            wire.as_ptr(),
            wire.len(),
            dst.as_mut_ptr(),
            dst.len(),
            &mut header_out,
            tmp.as_mut_ptr(),
            tmp.len(),
        )
    };
    assert_ne!(ret, usize::MAX, "pico _z_serial_msg_deserialize failed");
    dst.truncate(ret);
    (header_out, dst)
}

fn pico_cobs_encode(input: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; input.len() + 64 + input.len() / 254];
    let ret = unsafe { _z_cobs_encode(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    out.truncate(ret);
    out
}

fn pico_cobs_decode(input: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; input.len() + 64];
    let ret = unsafe { _z_cobs_decode(input.as_ptr(), input.len(), out.as_mut_ptr()) };
    out.truncate(ret);
    out
}

/// The strongest single assertion: the COMPLETE on-wire serial frame wz
/// emits is byte-for-byte identical to what pico emits, EOP included. If
/// this holds for the whole corpus, the header / length / payload / CRC32
/// layout, the COBS stuffing, and the EOP all agree with real pico.
// wz-proves: transport-link-serial codec-parity partial
#[test]
fn wz_serial_frame_is_byte_identical_to_pico() {
    for (header, payload) in corpus() {
        let wz = encode_frame(header, &payload).expect("wz encode_frame");
        let pico = pico_serialize(header, &payload);
        assert_eq!(
            wz,
            pico,
            "serial frame bytes diverge for header={header:#04x} payload_len={}",
            payload.len()
        );
    }
}

/// pico's serialized frame decodes in wz — both the one-shot `decode_frame`
/// and the streaming `SerialFrameReader` (fed byte-by-byte exactly as the
/// `serial_pipeline` read driver does, yielding the frame at the `0x00`
/// EOP). Proves wz consumes a real pico-emitted serial frame.
// wz-proves: transport-link-serial pico->wz partial
#[test]
fn pico_serialized_frame_decodes_in_wz() {
    for (header, payload) in corpus() {
        let pico = pico_serialize(header, &payload);

        let decoded = decode_frame(&pico).expect("wz decode_frame of a pico frame");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.payload, payload);

        let mut reader = SerialFrameReader::new();
        let mut yielded = None;
        for &b in &pico {
            if let Some(frame) = reader.push(b).expect("SerialFrameReader::push") {
                assert!(yielded.is_none(), "reader yielded more than one frame");
                yielded = Some(frame);
            }
        }
        let frame = yielded.expect("SerialFrameReader yields the frame at the 0x00 EOP");
        assert_eq!(frame.header, header);
        assert_eq!(frame.payload, payload);
    }
}

/// wz's serialized frame deserializes in pico — fed exactly as pico's read
/// path feeds it (`rb` includes the EOP). Proves real pico consumes a
/// wz-emitted serial frame: header, length-vs-decoded-size, and CRC32 all
/// pass pico's own checks.
// wz-proves: transport-link-serial wz->pico partial
#[test]
fn wz_serialized_frame_deserializes_in_pico() {
    for (header, payload) in corpus() {
        let wz = encode_frame(header, &payload).expect("wz encode_frame");
        let (h, p) = pico_deserialize(&wz);
        assert_eq!(h, header, "header mismatch (payload_len={})", payload.len());
        assert_eq!(
            p,
            payload,
            "payload mismatch (payload_len={})",
            payload.len()
        );
    }
}

/// Primitive-level parity for the two foundations the frame is built from:
/// COBS (round-trip both ways) and CRC32. Localizes a divergence to the
/// exact primitive rather than only surfacing it at the full-frame level.
// wz-proves: transport-link-serial codec-parity partial
#[test]
fn cobs_and_crc32_byte_parity_with_pico() {
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x00],
        vec![0x11, 0x00, 0x22],
        vec![0x01; 254],
        vec![0x00; 300],
        (0..=255u32).map(|i| i as u8).collect(),
    ];
    for input in inputs {
        // CRC32 over the raw input.
        let wz_crc = crc32(&input);
        let pico_crc = unsafe { _z_crc32(input.as_ptr(), input.len()) };
        assert_eq!(wz_crc, pico_crc, "crc32 mismatch for len={}", input.len());

        // COBS encode: the pure stuffed body (no EOP) must match byte-exact.
        let wz_enc = cobs_encode(&input).expect("wz cobs_encode");
        let pico_enc = pico_cobs_encode(&input);
        assert_eq!(
            wz_enc.as_slice(),
            &pico_enc[..],
            "cobs_encode mismatch for len={}",
            input.len()
        );

        // COBS decode: feed the stuffed body + a 0x00 EOP (the real frame
        // shape pico's reader produces). Both decoders recover the input.
        let mut framed = pico_enc.clone();
        framed.push(0x00);
        assert_eq!(
            cobs_decode(&framed).expect("wz cobs_decode").as_slice(),
            &input[..],
            "wz cobs_decode mismatch for len={}",
            input.len()
        );
        assert_eq!(
            &pico_cobs_decode(&framed)[..],
            &input[..],
            "pico cobs_decode mismatch for len={}",
            input.len()
        );
    }
}

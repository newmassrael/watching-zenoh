// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y698 (§1.2a) — QUIC packets, BUILT, so a reader of them can be gated.
//!
//! ## Why an analyzer carries a sender
//!
//! A passive reader can only be tested against traffic, and traffic whose
//! plaintext is known is traffic somebody built. rustls is this crate's oracle
//! and it protects exactly one thing — an Initial packet, from a connection ID —
//! because that is the only key schedule its public surface exposes without a
//! live handshake. Every later space needs a packet built here.
//!
//! So this module exists to make FIXTURES and is compiled only for tests and for
//! a consumer that asks for the `fixtures` feature. It is not part of the
//! analyzer: nothing outside a test builds a QUIC packet, and the crate's own
//! reader never calls anything here.
//!
//! ## What a fixture built here can and cannot prove
//!
//! It CANNOT prove the cryptography: sealing with the same key schedule that
//! opens it would agree with itself under a shared mistake. That claim is made
//! one module over, where rustls seals an Initial packet and this crate opens
//! it, and it is why `initial` and `derive` are gated there rather than here.
//!
//! It CAN prove everything above the cipher, which is the whole of what
//! R311y698 added: which space a packet belongs to, which key that selects,
//! where a short header's packet number begins, how a truncated number is
//! reconstructed, which sequence a piece is filed under, and whether a caller
//! wired any of it up.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::{LongHeader, QuicKeys, NONCE_LEN, SAMPLE_LEN, SAMPLE_OFFSET};
use crate::keylog::KeyLog;

/// The connection ID RFC 9001's own worked example uses, shared with the
/// packet-protection tests so both sides derive from one number.
pub const ICID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// The connection ID the server advertises, and therefore the length of the one
/// a client's SHORT header carries.
pub const SCID: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];

/// Bytes as lowercase hex, which is the only shape a key log line accepts.
pub fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A CRYPTO frame at `offset` carrying `body`.
pub fn crypto_frame(offset: u8, body: &[u8]) -> Vec<u8> {
    let mut f = alloc::vec![0x06u8, offset, body.len() as u8];
    f.extend_from_slice(body);
    f
}

/// A STREAM frame with both the OFF and LEN bits present.
pub fn stream_frame(id: u8, offset: u8, body: &[u8]) -> Vec<u8> {
    let mut f = alloc::vec![0x08u8 | 0x04 | 0x02, id, offset, body.len() as u8];
    f.extend_from_slice(body);
    f
}

/// An RFC 9221 DATAGRAM frame with a length, which is how zenoh's
/// `transport-link-quic-datagram` sends a batch.
pub fn datagram_frame(body: &[u8]) -> Vec<u8> {
    let mut f = alloc::vec![0x31u8, body.len() as u8];
    f.extend_from_slice(body);
    f
}

/// A TLS 1.3 ClientHello as QUIC carries it: a bare handshake message with NO
/// record layer in front of it (RFC 9001 §4).
pub fn client_hello(random: &[u8; 32]) -> Vec<u8> {
    let mut body = alloc::vec![0x03u8, 0x03]; // legacy_version
    body.extend_from_slice(random);
    body.push(0); // empty legacy_session_id
    let mut msg = alloc::vec![0x01u8]; // handshake type: client_hello
    msg.extend_from_slice(&[0, 0, body.len() as u8]); // 24-bit length
    msg.extend_from_slice(&body);
    msg
}

/// A long header with the packet number written IN THE CLEAR, and the offset it
/// begins at. [`protect`] masks it.
pub fn long_header(
    packet_type: u8,
    dcid: &[u8],
    scid: &[u8],
    body_len: usize,
    number: u32,
) -> (Vec<u8>, usize) {
    // Form bit, FIXED BIT, type, and a four-byte packet number.
    //
    // The fixed bit (0x40) is not decoration: RFC 9000 requires it set on every
    // versioned long header, and `wz_capture::quic::recognise_long` refuses a
    // packet without it. MEASURED -- the first version of this helper omitted
    // it, every test in `quic::connection` passed because `LongHeader::parse`
    // is a lower-level primitive that only checks the form bit, and the
    // capture-level test then found the whole connection decoded as zenoh. A
    // fixture that no recogniser would accept cannot gate a recogniser.
    let mut h = alloc::vec![0xc0 | (packet_type << 4) | 0x03];
    h.extend_from_slice(&1u32.to_be_bytes());
    h.push(dcid.len() as u8);
    h.extend_from_slice(dcid);
    h.push(scid.len() as u8);
    h.extend_from_slice(scid);
    if packet_type == LongHeader::INITIAL {
        h.push(0); // empty token
    }
    let length = 4 + body_len + 16;
    h.push(0x40 | (length >> 8) as u8);
    h.push((length & 0xff) as u8);
    let pn_offset = h.len();
    h.extend_from_slice(&number.to_be_bytes());
    (h, pn_offset)
}

/// A short header addressed to `dcid`, its packet number in the clear.
pub fn short_header(dcid: &[u8], number: u32) -> (Vec<u8>, usize) {
    let mut h = alloc::vec![0x43u8]; // fixed bit set, four-byte number, phase 0
    h.extend_from_slice(dcid);
    let pn_offset = h.len();
    h.extend_from_slice(&number.to_be_bytes());
    (h, pn_offset)
}

/// Protect one packet: seal the payload under the AEAD, then mask the header.
///
/// The inverse of what this crate's reader does, written out rather than
/// borrowed from it — a fixture that called the reader's own helpers would
/// agree with the reader by construction.
pub fn protect(
    keys: &QuicKeys,
    number: u64,
    header: &[u8],
    pn_offset: usize,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut packet = header.to_vec();
    let mut body = plaintext.to_vec();
    let algorithm = keys.suite.aead_algorithm();
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(algorithm, &keys.key).expect("a usable key"),
    );
    let mut nonce = keys.iv;
    let counter = number.to_be_bytes();
    for (i, b) in counter.iter().enumerate() {
        nonce[NONCE_LEN - counter.len() + i] ^= *b;
    }
    let tag = key
        .seal_in_place_separate_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(header),
            &mut body,
        )
        .expect("the seal");
    packet.extend_from_slice(&body);
    packet.extend_from_slice(tag.as_ref());

    let sample_at = pn_offset + SAMPLE_OFFSET;
    let sample = packet[sample_at..sample_at + SAMPLE_LEN].to_vec();
    let hp = ring::aead::quic::HeaderProtectionKey::new(keys.suite.quic_hp_algorithm(), &keys.hp)
        .expect("a usable header key");
    let mask = hp.new_mask(&sample).expect("a mask");
    let long = packet[0] & 0x80 != 0;
    // The LENGTH is read BEFORE the byte carrying it is masked. Measured:
    // reading it after produced a packet whose own reader refused it, because
    // the masked low bits name a different width.
    let pn_len = usize::from(packet[0] & 0x03) + 1;
    packet[0] ^= mask[0] & if long { 0x0f } else { 0x1f };
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    packet
}

/// A key log holding one connection's handshake secrets and `generations`
/// application secrets per direction.
pub fn log_for(random: &[u8; 32], generations: usize) -> KeyLog {
    KeyLog::parse(log_text(random, generations).as_bytes())
}

/// The same log as the text a caller would write to a file.
pub fn log_text(random: &[u8; 32], generations: usize) -> String {
    let mut text = String::new();
    let r = hex(random);
    for (label, seed) in [
        ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", 11u8),
        ("SERVER_HANDSHAKE_TRAFFIC_SECRET", 13),
    ] {
        let secret: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(seed).wrapping_add(1))
            .collect();
        text.push_str(&alloc::format!("{label} {r} {}\n", hex(&secret)));
    }
    for generation in 0..generations {
        for (label, server) in [
            ("CLIENT_TRAFFIC_SECRET", false),
            ("SERVER_TRAFFIC_SECRET", true),
        ] {
            text.push_str(&alloc::format!(
                "{label}_{generation} {r} {}\n",
                hex(&application_secret(server, generation))
            ));
        }
    }
    text
}

/// The application secret [`log_text`] wrote, so a fixture can seal with it.
pub fn application_secret(server: bool, generation: usize) -> Vec<u8> {
    let seed: u8 = if server { 19 } else { 17 };
    (0..32u8)
        .map(|i| i.wrapping_mul(seed).wrapping_add(generation as u8 + 1))
        .collect()
}

/// The handshake secret [`log_text`] wrote.
pub fn handshake_secret(server: bool) -> Vec<u8> {
    let seed: u8 = if server { 13 } else { 11 };
    (0..32u8)
        .map(|i| i.wrapping_mul(seed).wrapping_add(1))
        .collect()
}

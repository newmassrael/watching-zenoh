// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y694 (§1.2a) — QUIC PACKET PROTECTION, the first slice of the track.
//!
//! ## Where this sits, and why it is here and not in `wz-capture`
//!
//! `wz-capture` recognises a QUIC flow and counts it (R311y669) and opens no
//! byte of it: it carries zero third-party dependencies because its decode path
//! builds for the MCU profiles. The cipher lives on this side of that seam,
//! which is the same split `capture::CaptureOpener` already occupies for TLS
//! records.
//!
//! ## What one packet needs, in order
//!
//! 1. **Keys.** An Initial packet's are derived from the connection ID on the
//!    wire (RFC 9001 §5.2) and need no key log at all -- the one QUIC packet
//!    space anybody can open. Every later space needs a traffic secret, which
//!    is what a key log carries.
//! 2. **Header protection off** (§5.4). The packet number's length is inside
//!    the byte that protection covers, so nothing can be parsed until the mask
//!    is removed -- this is why a QUIC packet cannot be read the way a TLS
//!    record can.
//! 3. **AEAD** (§5.3), whose nonce is the IV xor the packet number and whose
//!    additional data is the header including that number.
//!
//! Step 4 -- reassembling CRYPTO and STREAM frames into a byte stream, which is
//! where this workspace's own framing finally applies -- is NOT here. It is the
//! next slice, and saying so is the difference between a track with one part
//! done and a claim that QUIC is readable.
//!
//! ## The oracle
//!
//! `rustls::quic` derives the same keys and applies the same protection, and it
//! is already this crate's dev-dependency for exactly this purpose. It protects
//! a packet in the tests below and this module opens it: two independent
//! implementations agreeing, which is the only form of agreement this crate
//! accepts (see the crate manifest's own note).

use crate::{expand_label, Suite};

/// RFC 9001 §5.2 — the version-1 Initial salt.
///
/// Read from `rustls-0.23.43/src/quic.rs::Version::initial_salt`, which cites
/// the RFC section beside it, rather than from memory: a constant this module
/// cannot check by any other means is a constant that has to come from a source
/// that can be opened.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The AEAD nonce width, which is the IV's width. Fixed for every TLS 1.3 AEAD.
const NONCE_LEN: usize = 12;

/// The header-protection sample width, and the offset it is taken from past the
/// packet number field. RFC 9001 §5.4.2: the sample starts four bytes into the
/// packet number field regardless of how long that field turns out to be, which
/// is what makes the sample readable BEFORE the length is known.
const SAMPLE_LEN: usize = 16;
const SAMPLE_OFFSET: usize = 4;

/// Why a packet could not be opened.
///
/// Separate variants for the two halves because they send a reader to different
/// places: a header this reader could not unmask is a packet whose shape it
/// misread, and a payload that failed authentication is the wrong key or the
/// wrong packet number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicOpenError {
    /// The packet is shorter than the sample the protection needs.
    TooShortForSample,
    /// The packet number field runs off the end of the packet.
    TruncatedPacketNumber,
    /// The AEAD refused the payload.
    NotAuthenticated,
    /// There is no room in the packet for an authentication tag.
    NoTag,
}

/// One direction's QUIC packet-protection keys, for one packet space.
///
/// A DIRECTION and a SPACE, not a connection: QUIC derives Initial, 0-RTT,
/// Handshake and 1-RTT keys separately and each direction of each has its own,
/// so "the connection's key" is not a thing that exists here any more than it
/// does for a TLS record.
#[derive(Clone)]
pub struct QuicKeys {
    suite: Suite,
    key: Vec<u8>,
    iv: [u8; NONCE_LEN],
    hp: Vec<u8>,
}

impl core::fmt::Debug for QuicKeys {
    /// The suite and nothing else, for the reason `TrafficKeys` gives: a
    /// `Debug` that spilled key material into a log would undo the reason a
    /// capture tool is trusted with it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuicKeys")
            .field("suite", &self.suite)
            .field("key", &"<redacted>")
            .field("iv", &"<redacted>")
            .field("hp", &"<redacted>")
            .finish()
    }
}

/// What the header carried once its protection was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnprotectedHeader {
    /// The first byte, unmasked. Its low bits are the packet number length and,
    /// for a short header, the key phase.
    pub first: u8,
    /// How many bytes the packet number field occupies: 1 to 4.
    pub packet_number_len: usize,
    /// The packet number as it appeared on the wire — TRUNCATED, and not yet
    /// the full number the AEAD nonce needs.
    ///
    /// RFC 9000 §17.1 sends only the low bits and expects the receiver to
    /// reconstruct the rest from the largest number it has already
    /// acknowledged. A passive reader has no such state on the first packet it
    /// sees, so the reconstruction belongs to the caller that tracks a flow —
    /// and handing back the truncated value rather than a guess is what keeps
    /// this function from inventing one.
    pub truncated_packet_number: u64,
    /// Where the payload begins: past the packet number field.
    pub payload_offset: usize,
}

impl QuicKeys {
    /// RFC 9001 §5.1 — derive one direction's keys from its traffic secret.
    ///
    /// The three labels are the QUIC ones (`quic key` / `quic iv` / `quic hp`)
    /// and not TLS's (`key` / `iv`), which is the whole difference between this
    /// and [`crate::TrafficKeys::derive`]: same HKDF, same secret shape,
    /// different labels, and a third key TLS has no equivalent of.
    pub fn derive(suite: Suite, traffic_secret: &[u8]) -> Self {
        let mut key = vec![0u8; suite.key_len()];
        expand_label(suite, traffic_secret, b"quic key", &[], &mut key);
        let mut iv = [0u8; NONCE_LEN];
        expand_label(suite, traffic_secret, b"quic iv", &[], &mut iv);
        let mut hp = vec![0u8; suite.key_len()];
        expand_label(suite, traffic_secret, b"quic hp", &[], &mut hp);
        Self { suite, key, iv, hp }
    }

    /// RFC 9001 §5.2 — the INITIAL keys of both directions, from the client's
    /// destination connection ID.
    ///
    /// # Why this one needs no key log
    ///
    /// The Initial secret is extracted from a fixed salt and a connection ID
    /// that is ON THE WIRE, in the clear, in the packet being read. So an
    /// Initial packet is the one QUIC packet space a passive reader can open
    /// with nothing but the capture — which is exactly the property that makes
    /// it the first slice of this track and the reason a handshake can be
    /// followed at all.
    ///
    /// Returned as `(client, server)` because the labels differ and nothing
    /// else does; a caller holding one of the two would have to remember which.
    pub fn initial(client_destination_connection_id: &[u8]) -> (Self, Self) {
        // Initial packets are protected with AES-128-GCM-SHA256 in every QUIC
        // version this reader knows: RFC 9001 §5.2 names the suite rather than
        // negotiating it, because the negotiation has not happened yet.
        let suite = Suite::Aes128GcmSha256;
        let initial_secret = ring_extract(&INITIAL_SALT_V1, client_destination_connection_id);
        let mut client = vec![0u8; suite.hash_len()];
        expand_label(suite, &initial_secret, b"client in", &[], &mut client);
        let mut server = vec![0u8; suite.hash_len()];
        expand_label(suite, &initial_secret, b"server in", &[], &mut server);
        (Self::derive(suite, &client), Self::derive(suite, &server))
    }

    /// RFC 9001 §5.4 — remove header protection, in place.
    ///
    /// # Why this cannot be done after parsing
    ///
    /// The packet number's LENGTH lives in the two low bits of the first byte,
    /// and those bits are themselves protected. A reader that parsed the header
    /// first would be reading a length the sender never wrote. So the sample is
    /// taken at a FIXED offset — four bytes past where the packet number
    /// starts, whatever its length turns out to be — and the mask is applied
    /// before anything is believed.
    ///
    /// `pn_offset` is where the packet number field begins, which the caller
    /// knows from the header it has already walked: for a long header, past the
    /// version, the two connection IDs, the token and the length; for a short
    /// header, past the destination connection ID.
    pub fn unprotect_header(
        &self,
        packet: &mut [u8],
        pn_offset: usize,
    ) -> Result<UnprotectedHeader, QuicOpenError> {
        let sample_at = pn_offset + SAMPLE_OFFSET;
        let sample = packet
            .get(sample_at..sample_at + SAMPLE_LEN)
            .ok_or(QuicOpenError::TooShortForSample)?;
        let mask = self.mask(sample)?;

        // The long-header form keeps four reserved bits the short form uses for
        // the key phase and spin, so the two mask different widths of the first
        // byte. The bit that says which form this is (0x80) is NOT protected,
        // which is what makes this readable before anything else.
        let long = packet[0] & 0x80 != 0;
        let first = packet[0] ^ (mask[0] & if long { 0x0f } else { 0x1f });
        packet[0] = first;

        let pn_len = usize::from(first & 0x03) + 1;
        let pn = packet
            .get_mut(pn_offset..pn_offset + pn_len)
            .ok_or(QuicOpenError::TruncatedPacketNumber)?;
        let mut truncated = 0u64;
        for (i, byte) in pn.iter_mut().enumerate() {
            *byte ^= mask[1 + i];
            truncated = (truncated << 8) | u64::from(*byte);
        }
        Ok(UnprotectedHeader {
            first,
            packet_number_len: pn_len,
            truncated_packet_number: truncated,
            payload_offset: pn_offset + pn_len,
        })
    }

    /// RFC 9001 §5.3 — open the payload of one packet.
    ///
    /// `header` is the packet's bytes up to the payload, packet number
    /// INCLUDED and already unmasked: QUIC authenticates the header it sent,
    /// which is the unprotected one. `packet_number` is the FULL number, not
    /// the truncated field — reconstructing it is the caller's, for the reason
    /// [`UnprotectedHeader::truncated_packet_number`] gives.
    ///
    /// Returns the plaintext, which is shorter than the input by the tag.
    pub fn open<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], QuicOpenError> {
        let key = ring::aead::UnboundKey::new(self.suite.aead_algorithm(), &self.key)
            .map_err(|_| QuicOpenError::NotAuthenticated)?;
        let key = ring::aead::LessSafeKey::new(key);
        // The nonce is the IV with the packet number xored into its RIGHT end
        // (RFC 9001 §5.3), which is the same construction TLS uses for its
        // sequence number and the reason a 12-byte IV can carry a 62-bit
        // number.
        let mut nonce = self.iv;
        let counter = packet_number.to_be_bytes();
        for (i, b) in counter.iter().enumerate() {
            nonce[NONCE_LEN - counter.len() + i] ^= *b;
        }
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce);
        if payload.len() < self.suite.aead_algorithm().tag_len() {
            return Err(QuicOpenError::NoTag);
        }
        key.open_in_place(nonce, ring::aead::Aad::from(header), payload)
            .map_err(|_| QuicOpenError::NotAuthenticated)
            .map(|plain| &*plain)
    }

    /// The five-byte header-protection mask for one sample.
    fn mask(&self, sample: &[u8]) -> Result<[u8; 5], QuicOpenError> {
        let hp =
            ring::aead::quic::HeaderProtectionKey::new(self.suite.quic_hp_algorithm(), &self.hp)
                .map_err(|_| QuicOpenError::NotAuthenticated)?;
        hp.new_mask(sample)
            .map_err(|_| QuicOpenError::TooShortForSample)
    }
}

/// HKDF-Extract, as a byte vector.
///
/// `ring` models a PRK as an opaque type, so the extracted secret cannot be
/// read back out of it -- and this module needs it as BYTES, because the two
/// `client in` / `server in` expansions both start from it. Extract is one
/// HMAC, so it is done here rather than borrowed.
fn ring_extract(salt: &[u8], secret: &[u8]) -> Vec<u8> {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    hmac::sign(&key, secret).as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use rustls::quic::{Keys, Version};
    use rustls::{Side, SupportedCipherSuite};

    /// The connection ID RFC 9001's own worked example uses, which is also what
    /// rustls's `initial_test_vector` tests derive from.
    const ICID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    /// rustls's Initial keys for one side of that connection.
    fn oracle(side: Side) -> Keys {
        let SupportedCipherSuite::Tls13(suite) = TLS13_AES_128_GCM_SHA256;
        Keys::initial(
            Version::V1,
            suite,
            suite.quic.expect("the ring provider offers QUIC keys"),
            &ICID,
            side,
        )
    }

    /// One Initial packet, protected BY THE ORACLE, and where its packet number
    /// begins.
    ///
    /// Built by hand rather than captured: what is under test is whether this
    /// module can undo what a conforming sender did, and a hand-built packet is
    /// the only way to know what the plaintext was.
    fn protected_initial(pn: u32, plaintext: &[u8]) -> (Vec<u8>, usize) {
        let mut packet = Vec::new();
        // Long header, Initial, four-byte packet number.
        packet.push(0xC3);
        packet.extend_from_slice(&1u32.to_be_bytes());
        packet.push(ICID.len() as u8);
        packet.extend_from_slice(&ICID);
        packet.push(0); // no source connection ID
        packet.push(0); // no token
        let length = 4 + plaintext.len() + 16;
        packet.push(0x40 | (length >> 8) as u8);
        packet.push((length & 0xff) as u8);
        let pn_offset = packet.len();
        packet.extend_from_slice(&pn.to_be_bytes());
        let header_end = packet.len();
        packet.extend_from_slice(plaintext);
        packet.extend_from_slice(&[0u8; 16]);

        let keys = oracle(Side::Client);
        let (header, payload) = packet.split_at_mut(header_end);
        let tag = keys
            .local
            .packet
            .encrypt_in_place(u64::from(pn), header, &mut payload[..plaintext.len()])
            .expect("the oracle seals");
        payload[plaintext.len()..].copy_from_slice(tag.as_ref());

        let sample_at = pn_offset + SAMPLE_OFFSET;
        let sample = packet[sample_at..sample_at + SAMPLE_LEN].to_vec();
        let (first, rest) = packet.split_at_mut(1);
        keys.local
            .header
            .encrypt_in_place(
                &sample,
                &mut first[0],
                &mut rest[pn_offset - 1..pn_offset + 3],
            )
            .expect("the oracle masks");
        (packet, pn_offset)
    }

    /// R311y694 (§1.2a) — an INITIAL packet a conforming sender protected is
    /// opened by keys this module derived from the connection ID alone.
    ///
    /// ## What this proves and what it does not
    ///
    /// Proves: the key schedule (§5.1/§5.2), the header protection (§5.4) and
    /// the AEAD (§5.3) all agree with an INDEPENDENT implementation, on a
    /// packet that implementation protected. The oracle is rustls, this
    /// crate's dev-dependency for exactly this purpose and never a dependency
    /// -- one implementation agreeing with itself is not the claim.
    ///
    /// Does not prove anything about frames: the plaintext here is arbitrary
    /// bytes, and turning a real payload into a byte stream is the CRYPTO and
    /// STREAM reassembly this track has not reached.
    #[test]
    fn an_initial_packet_is_opened_from_the_connection_id_alone() {
        let plaintext = b"a zenoh session begins somewhere in here";
        let (mut packet, pn_offset) = protected_initial(7, plaintext);

        // ANTI-VACUITY, both halves: the packet must actually be protected, or
        // "this module opened it" is a statement about a plaintext buffer.
        assert_ne!(
            packet[0], 0xC3,
            "the first byte must carry the header mask, or nothing was protected"
        );
        assert!(
            !packet.windows(plaintext.len()).any(|w| w == &plaintext[..]),
            "the plaintext must not be lying in the packet in the clear"
        );

        let (client, _server) = QuicKeys::initial(&ICID);
        let header = client
            .unprotect_header(&mut packet, pn_offset)
            .expect("the header unmasks");
        assert_eq!(header.first, 0xC3, "the first byte is recovered exactly");
        assert_eq!(header.packet_number_len, 4);
        assert_eq!(
            header.truncated_packet_number, 7,
            "and the packet number the sender wrote is read back"
        );

        let (aad, payload) = packet.split_at_mut(header.payload_offset);
        let opened = client.open(7, aad, payload).expect("the payload opens");
        assert_eq!(
            opened,
            &plaintext[..],
            "and the plaintext is what the sender sealed"
        );
    }

    /// R311y694 (§1.2a) — the WRONG connection ID derives keys that open
    /// nothing, and fails at the AEAD rather than quietly producing bytes.
    ///
    /// An Initial key is derived from a value read OFF THE WIRE, so a reader
    /// that took the wrong connection ID would hold a key that is wrong in a
    /// way no other check catches. The 128-bit tag is what catches it, and this
    /// is what says the tag is being consulted.
    #[test]
    fn a_connection_id_that_is_not_the_senders_opens_nothing() {
        let plaintext = b"a zenoh session begins somewhere in here";
        let (mut packet, pn_offset) = protected_initial(7, plaintext);

        let mut wrong = ICID;
        wrong[0] ^= 0x01;
        let (client, _server) = QuicKeys::initial(&wrong);
        // A mask is not authenticated, so the header may unmask into something
        // plausible; the assertion is on the AEAD, which is.
        let opened = match client.unprotect_header(&mut packet, pn_offset) {
            Err(_) => return,
            Ok(h) => {
                let end = h.payload_offset.min(packet.len());
                let (aad, payload) = packet.split_at_mut(end);
                client.open(7, aad, payload)
            }
        };
        assert_eq!(
            opened.err(),
            Some(QuicOpenError::NotAuthenticated),
            "a key derived from the wrong connection ID must be refused by the \
             tag, not produce bytes"
        );
    }

    /// R311y694 (§1.2a) — the SERVER's Initial keys are a different derivation
    /// and must not open the client's packet.
    ///
    /// Both directions come from one secret and differ only by a label, which
    /// is exactly the pair a reader can wire up backwards -- and the failure
    /// would look like a wrong key log rather than a swapped label.
    #[test]
    fn the_server_keys_do_not_open_a_client_packet() {
        let plaintext = b"a zenoh session begins somewhere in here";
        let (mut packet, pn_offset) = protected_initial(7, plaintext);

        let (client, server) = QuicKeys::initial(&ICID);
        // The client's keys open it, asserted FIRST so a build where neither
        // works cannot pass this test.
        let mut copy = packet.clone();
        let h = client
            .unprotect_header(&mut copy, pn_offset)
            .expect("the header unmasks");
        let (aad, payload) = copy.split_at_mut(h.payload_offset);
        assert!(
            client.open(7, aad, payload).is_ok(),
            "the client's keys open it"
        );

        let opened = match server.unprotect_header(&mut packet, pn_offset) {
            Err(_) => return,
            Ok(h) => {
                let end = h.payload_offset.min(packet.len());
                let (aad, payload) = packet.split_at_mut(end);
                server.open(7, aad, payload)
            }
        };
        assert_eq!(
            opened.err(),
            Some(QuicOpenError::NotAuthenticated),
            "the other direction's keys must not open this packet"
        );
    }
}

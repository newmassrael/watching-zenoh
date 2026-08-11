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

/// R311y695 (§1.2a) — the QUIC version a packet declares, as far as this
/// reader can act on it.
///
/// # Why an unknown version is a REFUSAL and not a default
///
/// Every version has its own Initial salt and its own key labels, so a reader
/// that assumed version 1 for a version-2 packet would derive keys that open
/// nothing -- and the failure would be indistinguishable from a wrong
/// connection ID or a corrupt capture. Naming the version it could not act on
/// is the difference between a diagnosis and a shrug.
///
/// The numbers are read from `quinn-proto-0.11.16/src/crypto/rustls.rs::
/// interpret_version` and the salts from
/// `rustls-0.23.43/src/quic.rs::Version::initial_salt`, both of which cite
/// their sources. Version 2 is deliberately ABSENT: rustls carries its salt and
/// labels, and neither of the two crates on this machine states its wire
/// number, so it would have to be remembered -- and a constant this module
/// cannot check is one it must not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicVersion {
    /// The first stable RFC: 0x00000001, and the two `ff00002x` drafts that
    /// share its salt.
    V1,
    /// Drafts 29 through 32, which have their own salt.
    V1Draft,
}

impl QuicVersion {
    /// The version a wire number names, or `None` for one this reader cannot
    /// derive keys for.
    pub fn from_wire(version: u32) -> Option<Self> {
        match version {
            0x0000_0001 | 0xff00_0021..=0xff00_0022 => Some(Self::V1),
            0xff00_001d..=0xff00_0020 => Some(Self::V1Draft),
            _ => None,
        }
    }

    /// RFC 9001 §5.2 — this version's Initial salt.
    fn initial_salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1 => &INITIAL_SALT_V1,
            Self::V1Draft => &INITIAL_SALT_V1_DRAFT,
        }
    }
}

/// The salt of drafts 29-32, read from the same rustls table as
/// [`INITIAL_SALT_V1`].
const INITIAL_SALT_V1_DRAFT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

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
    /// R311y695 — the packet's header ran off the end of the bytes.
    TruncatedHeader,
    /// R311y695 — the version this packet declares is one this reader has no
    /// salt for, and it says which rather than deriving the wrong keys.
    UnsupportedVersion(u32),
    /// R311y696 — a frame type this walk does not know, NAMED. QUIC frames are
    /// not length-prefixed as a genre, so a reader that does not know a type
    /// does not know where it ends: the walk stops rather than producing
    /// pieces at offsets nobody sent.
    UnknownFrame(u64),
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

/// R311y695 (§1.2a) — a QUIC long header, walked far enough to protect it.
///
/// # What the caller had to do before this
///
/// [`QuicKeys::unprotect_header`] takes the offset the packet number begins at,
/// and R311y694 left finding it entirely to the caller: past the version, both
/// connection IDs, the token and the length, each of which is a variable-length
/// field and two of which are QUIC varints. That is not an offset a reader can
/// be asked to compute by hand, and `wz-capture::quic` -- which already walks
/// these fields to RECOGNISE the packet -- does not report it.
///
/// So the walk is here, beside the thing that needs it, and it stops exactly
/// where protection begins. Nothing past the packet number can be read before
/// the mask comes off, which is why this type has no payload and no frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeader {
    /// The version the packet declares, unmapped: a caller may want to report
    /// the number even where this reader has no salt for it.
    pub version: u32,
    /// The DESTINATION connection ID, which for a client Initial is what the
    /// Initial keys are derived from.
    pub destination_connection_id: Vec<u8>,
    /// The SOURCE connection ID.
    pub source_connection_id: Vec<u8>,
    /// Where the packet number field begins.
    pub packet_number_offset: usize,
    /// The length the header declared: the packet number plus the payload,
    /// tag included.
    pub remainder_len: usize,
    /// The packet type from the first byte's two type bits, unmasked only
    /// insofar as those bits are NOT protected.
    pub packet_type: u8,
}

impl LongHeader {
    /// The long-header packet types of version 1 (RFC 9000 §17.2).
    pub const INITIAL: u8 = 0;
    pub const ZERO_RTT: u8 = 1;
    pub const HANDSHAKE: u8 = 2;
    pub const RETRY: u8 = 3;

    /// Walk one long header. `packet` is the whole UDP payload.
    ///
    /// Refuses rather than guesses on every truncation, because a header this
    /// reader mis-walks produces a packet number offset that is wrong, and a
    /// wrong offset produces a mask taken from the wrong bytes -- which fails
    /// as an authentication error, blaming the key for a parse.
    pub fn parse(packet: &[u8]) -> Result<Self, QuicOpenError> {
        let first = *packet.first().ok_or(QuicOpenError::TruncatedHeader)?;
        if first & 0x80 == 0 {
            return Err(QuicOpenError::TruncatedHeader);
        }
        let packet_type = (first >> 4) & 0x03;
        let version = u32::from_be_bytes(
            packet
                .get(1..5)
                .ok_or(QuicOpenError::TruncatedHeader)?
                .try_into()
                .expect("four bytes"),
        );
        let mut at = 5usize;
        let dcid = take_cid(packet, &mut at)?;
        let scid = take_cid(packet, &mut at)?;
        // A Retry packet has neither a length nor a packet number: its tail is
        // a token and an integrity tag. Refused here rather than half-walked,
        // because there is no packet number offset to report.
        if packet_type == Self::RETRY {
            return Err(QuicOpenError::TruncatedHeader);
        }
        if packet_type == Self::INITIAL {
            let token_len = take_varint(packet, &mut at)? as usize;
            at = at
                .checked_add(token_len)
                .ok_or(QuicOpenError::TruncatedHeader)?;
            if at > packet.len() {
                return Err(QuicOpenError::TruncatedHeader);
            }
        }
        let remainder_len = take_varint(packet, &mut at)? as usize;
        Ok(Self {
            version,
            destination_connection_id: dcid,
            source_connection_id: scid,
            packet_number_offset: at,
            remainder_len,
            packet_type,
        })
    }
}

/// One length-prefixed connection ID, advancing `at` past it.
fn take_cid(packet: &[u8], at: &mut usize) -> Result<Vec<u8>, QuicOpenError> {
    let len = usize::from(*packet.get(*at).ok_or(QuicOpenError::TruncatedHeader)?);
    let start = *at + 1;
    let end = start
        .checked_add(len)
        .ok_or(QuicOpenError::TruncatedHeader)?;
    let cid = packet
        .get(start..end)
        .ok_or(QuicOpenError::TruncatedHeader)?
        .to_vec();
    *at = end;
    Ok(cid)
}

/// One QUIC variable-length integer (RFC 9000 §16), advancing `at` past it.
///
/// The two high bits of the first byte give the encoding's length, and the
/// remaining six are the value's most significant bits -- which is why the
/// prefix cannot simply be skipped.
fn take_varint(packet: &[u8], at: &mut usize) -> Result<u64, QuicOpenError> {
    let first = *packet.get(*at).ok_or(QuicOpenError::TruncatedHeader)?;
    let len = 1usize << (first >> 6);
    let bytes = packet
        .get(*at..*at + len)
        .ok_or(QuicOpenError::TruncatedHeader)?;
    let mut value = u64::from(first & 0x3f);
    for b in &bytes[1..] {
        value = (value << 8) | u64::from(*b);
    }
    *at += len;
    Ok(value)
}

/// R311y695 (§1.2a) — RFC 9000 §A.3: the full packet number, from the
/// truncated one on the wire.
///
/// # Why this is not the reader's guess
///
/// A sender writes only the low bits and expects the receiver to pick the
/// candidate nearest the number it expects next. A passive reader's "expected"
/// is the largest it has already opened on this direction, which is state it
/// keeps rather than state on the wire -- so this takes it as an argument and
/// invents nothing. The first packet of a flow has no such state and its
/// truncated number IS the number, which is what passing `None` means.
pub fn reconstruct_packet_number(
    largest_opened: Option<u64>,
    truncated: u64,
    packet_number_len: usize,
) -> u64 {
    let Some(largest) = largest_opened else {
        return truncated;
    };
    let bits = packet_number_len * 8;
    let window = 1u64 << bits;
    let half = window / 2;
    let expected = largest + 1;
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate + half <= expected && candidate + window < (1u64 << 62) {
        candidate + window
    } else if candidate > expected + half && candidate >= window {
        candidate - window
    } else {
        candidate
    }
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
    pub fn initial(version: QuicVersion, client_destination_connection_id: &[u8]) -> (Self, Self) {
        // Initial packets are protected with AES-128-GCM-SHA256 in every QUIC
        // version this reader knows: RFC 9001 §5.2 names the suite rather than
        // negotiating it, because the negotiation has not happened yet.
        let suite = Suite::Aes128GcmSha256;
        let initial_secret = ring_extract(version.initial_salt(), client_destination_connection_id);
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
    pub(super) const ICID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

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
    pub(super) fn protected_initial(pn: u32, plaintext: &[u8]) -> (Vec<u8>, usize) {
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

        let (client, _server) = QuicKeys::initial(QuicVersion::V1, &ICID);
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
        let (client, _server) = QuicKeys::initial(QuicVersion::V1, &wrong);
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

        let (client, server) = QuicKeys::initial(QuicVersion::V1, &ICID);
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

#[cfg(test)]
mod header_tests {
    use super::*;

    /// R311y695 (§1.2a) — the long header is WALKED to the packet number, and
    /// R311y694 left that offset entirely to the caller.
    ///
    /// The fixture is the same packet the protection tests use, so the offset
    /// this walk reports is checked against the one that packet was BUILT with
    /// — two ways of knowing the same number, which is what makes this more
    /// than a restatement of the parser.
    #[test]
    fn a_long_header_is_walked_to_where_protection_begins() {
        let plaintext = b"a zenoh session begins somewhere in here";
        let (packet, built_at) = super::tests::protected_initial(7, plaintext);
        let header = LongHeader::parse(&packet).expect("the header walks");

        assert_eq!(header.version, 1, "the version is read, not assumed");
        assert_eq!(header.packet_type, LongHeader::INITIAL);
        assert_eq!(
            header.destination_connection_id,
            super::tests::ICID.to_vec(),
            "the connection ID the Initial keys come from is the one on the wire"
        );
        assert!(header.source_connection_id.is_empty());
        assert_eq!(
            header.packet_number_offset, built_at,
            "the walked offset must be the offset the packet was built with"
        );
        assert_eq!(
            header.remainder_len,
            4 + plaintext.len() + 16,
            "the declared length covers the packet number, the payload and the tag"
        );

        // AND THE WALK IS ENOUGH TO OPEN THE PACKET, which is the point: keys
        // from the walked connection ID, offset from the walked header.
        let mut packet = packet;
        let (client, _) = QuicKeys::initial(QuicVersion::V1, &header.destination_connection_id);
        let h = client
            .unprotect_header(&mut packet, header.packet_number_offset)
            .expect("unmasks");
        let (aad, payload) = packet.split_at_mut(h.payload_offset);
        assert_eq!(
            client.open(7, aad, payload).expect("opens"),
            &plaintext[..],
            "a caller now needs nothing but the packet"
        );
    }

    /// R311y695 (§1.2a) — every truncation refuses instead of reporting an
    /// offset it guessed.
    ///
    /// A header this reader mis-walks yields a packet number offset that is
    /// wrong, and a wrong offset takes the mask from the wrong bytes -- which
    /// surfaces as an authentication error, blaming the key for a parse.
    #[test]
    fn a_truncated_long_header_is_refused_at_every_field() {
        let plaintext = b"a zenoh session begins somewhere in here";
        let (packet, _) = super::tests::protected_initial(7, plaintext);
        // ANTI-VACUITY: the whole packet walks, so a refusal below is about the
        // truncation and not about the fixture.
        assert!(LongHeader::parse(&packet).is_ok());
        // Up to the header's own length: a slice that ENDS exactly where the
        // packet number begins is a complete header and walks correctly, which
        // is what the assertion above already says. Measured -- the first
        // version of this loop ran to 24 and failed at 18, which is this
        // header's length.
        let header_len = LongHeader::parse(&packet)
            .expect("walks")
            .packet_number_offset;
        for cut in 1..header_len {
            assert_eq!(
                LongHeader::parse(&packet[..cut]).err(),
                Some(QuicOpenError::TruncatedHeader),
                "a header cut at {cut} must be refused"
            );
        }
    }

    /// R311y695 (§1.2a) — a version this reader has no salt for is NAMED.
    #[test]
    fn an_unknown_version_is_named_rather_than_treated_as_version_one() {
        assert_eq!(QuicVersion::from_wire(0x0000_0001), Some(QuicVersion::V1));
        assert_eq!(
            QuicVersion::from_wire(0xff00_001d),
            Some(QuicVersion::V1Draft)
        );
        assert_eq!(
            QuicVersion::from_wire(0x6b33_43cf),
            None,
            "a version this reader carries no salt for must not be read as V1"
        );
        // AND THE TWO SALTS DIFFER, which is what makes the distinction worth
        // drawing: the same connection ID under the two versions must not
        // produce the same keys.
        let (v1, _) = QuicKeys::initial(QuicVersion::V1, &super::tests::ICID);
        let (draft, _) = QuicKeys::initial(QuicVersion::V1Draft, &super::tests::ICID);
        assert_ne!(
            v1.key, draft.key,
            "two versions with different salts derive different keys"
        );
    }

    /// R311y695 (§1.2a) — RFC 9000 §A.3, including the wrap the naive
    /// arithmetic gets wrong.
    ///
    /// The interesting cases are the ones where the truncated number is on the
    /// other side of a rollover from the expected one: a reader that simply
    /// pasted the low bits onto the high ones would be a whole window out, and
    /// the AEAD would refuse a packet that was perfectly good.
    #[test]
    fn a_truncated_packet_number_is_reconstructed_across_a_rollover() {
        // No state: the first packet of a flow IS its number.
        assert_eq!(reconstruct_packet_number(None, 7, 4), 7);
        // Ordinary: the next number, one byte on the wire.
        // RFC 9000 §A.3's own worked example: largest 0xa82f30ea, two bytes
        // reading 0x9b32.
        assert_eq!(
            reconstruct_packet_number(Some(0xa82f_30ea), 0x9b32, 2),
            0xa82f_9b32
        );
        // FORWARD across a rollover: expected is just past a window boundary
        // and the truncated value is just below it.
        assert_eq!(reconstruct_packet_number(Some(0xff), 0x01, 1), 0x101);
        // BACKWARD: a reordered packet from just before the boundary.
        assert_eq!(reconstruct_packet_number(Some(0x101), 0xff, 1), 0xff);
    }
}

/// R311y696 (§1.2a) — the FRAMES inside an opened packet, and the byte stream
/// they carry.
///
/// # Why this is where the track stops being about cryptography
///
/// R311y694 and R311y695 turn a protected packet into plaintext. That plaintext
/// is not a byte stream: it is a sequence of QUIC frames, most of which carry
/// no application data at all, and the two that do -- `CRYPTO` during the
/// handshake and `STREAM` after it -- each carry an OFFSET, because QUIC
/// delivers a stream in whatever order the packets arrive. Only once those are
/// ordered does anything this workspace already owns apply.
pub mod frames {
    use super::QuicOpenError;
    use std::collections::BTreeMap;

    /// One piece of a byte stream, as a frame delivered it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StreamPiece<'a> {
        /// `None` for a `CRYPTO` frame, which has no stream identity: the
        /// handshake is its own space.
        pub stream_id: Option<u64>,
        /// Where these bytes belong in that stream.
        pub offset: u64,
        /// The bytes.
        pub data: &'a [u8],
        /// Whether this frame closed its stream.
        pub fin: bool,
    }

    /// Walk one packet's plaintext into the stream pieces it carries.
    ///
    /// Frames that carry no stream bytes are SKIPPED and not reported: padding,
    /// pings and acknowledgements are the majority of a real capture and a
    /// reader of a byte stream has nothing to do with them. A frame type this
    /// walk does not know ENDS the walk rather than being stepped over --
    /// QUIC frames are not length-prefixed as a genre, so a reader that does
    /// not know a type does not know where it ends, and guessing produces
    /// pieces at offsets nobody sent.
    pub fn walk(plaintext: &[u8]) -> Result<Vec<StreamPiece<'_>>, QuicOpenError> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < plaintext.len() {
            let ty = super::take_varint(plaintext, &mut at)?;
            match ty {
                // PADDING and PING carry nothing and are one byte each.
                0x00 | 0x01 => {}
                // ACK, with and without ECN counts.
                0x02 | 0x03 => {
                    let _largest = super::take_varint(plaintext, &mut at)?;
                    let _delay = super::take_varint(plaintext, &mut at)?;
                    let ranges = super::take_varint(plaintext, &mut at)?;
                    let _first = super::take_varint(plaintext, &mut at)?;
                    for _ in 0..ranges {
                        let _gap = super::take_varint(plaintext, &mut at)?;
                        let _len = super::take_varint(plaintext, &mut at)?;
                    }
                    if ty == 0x03 {
                        for _ in 0..3 {
                            let _ecn = super::take_varint(plaintext, &mut at)?;
                        }
                    }
                }
                // CRYPTO: the handshake's own stream, which has no identity.
                0x06 => {
                    let offset = super::take_varint(plaintext, &mut at)?;
                    let len = super::take_varint(plaintext, &mut at)? as usize;
                    let data = slice(plaintext, at, len)?;
                    at += len;
                    out.push(StreamPiece {
                        stream_id: None,
                        offset,
                        data,
                        fin: false,
                    });
                }
                // STREAM, whose three low bits say which of its fields are
                // present. A reader that assumed all three would walk into the
                // next frame's bytes.
                0x08..=0x0f => {
                    let stream_id = super::take_varint(plaintext, &mut at)?;
                    let offset = if ty & 0x04 != 0 {
                        super::take_varint(plaintext, &mut at)?
                    } else {
                        0
                    };
                    let len = if ty & 0x02 != 0 {
                        super::take_varint(plaintext, &mut at)? as usize
                    } else {
                        // No length means "to the end of the packet", which is
                        // legal and is why this walk cannot be a simple loop
                        // over sized frames.
                        plaintext.len() - at
                    };
                    let data = slice(plaintext, at, len)?;
                    at += len;
                    out.push(StreamPiece {
                        stream_id: Some(stream_id),
                        offset,
                        data,
                        fin: ty & 0x01 != 0,
                    });
                }
                _ => return Err(QuicOpenError::UnknownFrame(ty)),
            }
        }
        Ok(out)
    }

    fn slice(bytes: &[u8], at: usize, len: usize) -> Result<&[u8], QuicOpenError> {
        bytes
            .get(at..at + len)
            .ok_or(QuicOpenError::TruncatedHeader)
    }

    /// R311y696 — one stream's bytes, put back in order.
    ///
    /// # The bound, and why it has a counter
    ///
    /// A piece that arrives ahead of a hole cannot be delivered and has to be
    /// held, which is an accumulation that grows with the input -- the shape
    /// this workspace bounds everywhere. `max_buffered` is that bound and
    /// [`Self::dropped`] is what it cost, because a reassembler that silently
    /// discards is a reader that reports a stream shorter than the one that was
    /// sent.
    #[derive(Debug, Default)]
    pub struct StreamReassembler {
        /// Bytes delivered so far, in order.
        ready: Vec<u8>,
        /// Pieces held for a hole ahead of them, keyed by their offset.
        held: BTreeMap<u64, Vec<u8>>,
        /// How many bytes are held.
        held_bytes: usize,
        /// The ceiling on held bytes; `None` is unbounded.
        max_buffered: Option<usize>,
        /// Bytes the bound refused, which is what the bound cost.
        dropped: usize,
        /// Whether a frame said the stream ended.
        finished: bool,
    }

    impl StreamReassembler {
        /// A reassembler holding at most `max_buffered` out-of-order bytes.
        pub fn new(max_buffered: Option<usize>) -> Self {
            Self {
                max_buffered,
                ..Default::default()
            }
        }

        /// Offer one piece. Returns how many bytes became deliverable.
        pub fn push(&mut self, piece: &StreamPiece<'_>) -> usize {
            if piece.fin {
                self.finished = true;
            }
            let before = self.ready.len();
            let start = piece.offset;
            let end = start + piece.data.len() as u64;
            if end <= self.ready.len() as u64 {
                // Wholly retransmitted: QUIC may resend, and a reader that
                // appended it again would invent bytes nobody sent.
                return 0;
            }
            if start <= self.ready.len() as u64 {
                let skip = (self.ready.len() as u64 - start) as usize;
                self.ready.extend_from_slice(&piece.data[skip..]);
                self.drain_held();
            } else if self
                .max_buffered
                .is_none_or(|cap| self.held_bytes + piece.data.len() <= cap)
            {
                self.held_bytes += piece.data.len();
                self.held.insert(start, piece.data.to_vec());
            } else {
                self.dropped += piece.data.len();
            }
            self.ready.len() - before
        }

        /// Move whatever the new bytes unblocked out of the hold.
        fn drain_held(&mut self) {
            while let Some((&offset, _)) = self.held.iter().next() {
                if offset > self.ready.len() as u64 {
                    break;
                }
                let piece = self.held.remove(&offset).expect("just seen");
                self.held_bytes -= piece.len();
                let end = offset + piece.len() as u64;
                if end > self.ready.len() as u64 {
                    let skip = (self.ready.len() as u64 - offset) as usize;
                    self.ready.extend_from_slice(&piece[skip..]);
                }
            }
        }

        /// The contiguous bytes delivered so far.
        pub fn stream(&self) -> &[u8] {
            &self.ready
        }

        /// Bytes held for a hole ahead of them.
        pub fn buffered(&self) -> usize {
            self.held_bytes
        }

        /// Bytes the bound refused.
        pub fn dropped(&self) -> usize {
            self.dropped
        }

        /// Whether a frame said this stream ended.
        pub fn finished(&self) -> bool {
            self.finished
        }
    }
}

#[cfg(test)]
mod frame_tests {
    use super::frames::{walk, StreamReassembler};
    use super::QuicOpenError;

    /// One STREAM frame: type bits for OFF and LEN, the id, the offset, the
    /// length, then the bytes.
    fn stream_frame(id: u8, offset: u8, data: &[u8], fin: bool) -> Vec<u8> {
        let mut f = vec![0x08 | 0x04 | 0x02 | u8::from(fin)];
        f.push(id);
        f.push(offset);
        f.push(data.len() as u8);
        f.extend_from_slice(data);
        f
    }

    /// R311y696 (§1.2a) — an opened packet's plaintext is walked into the
    /// stream pieces it carries, and the frames that carry nothing are stepped
    /// over rather than reported.
    #[test]
    fn a_packets_plaintext_is_walked_into_the_stream_it_carries() {
        let mut plaintext = vec![0x00, 0x00, 0x01]; // two PADDING and a PING
        plaintext.extend_from_slice(&[0x06, 0x00, 0x04]); // CRYPTO at offset 0
        plaintext.extend_from_slice(b"hi\x00\x01");
        plaintext.extend_from_slice(&stream_frame(4, 0, b"zenoh", true));

        let pieces = walk(&plaintext).expect("the walk reads every frame");
        // ANTI-VACUITY: the padding and the ping must have been walked past,
        // not stopped at -- a walk that gave up at the first frame would also
        // produce "only the ones that carry bytes".
        assert_eq!(pieces.len(), 2, "two frames carry stream bytes: {pieces:?}");
        assert_eq!(pieces[0].stream_id, None, "CRYPTO has no stream identity");
        assert_eq!(pieces[0].data, b"hi\x00\x01");
        assert_eq!(pieces[1].stream_id, Some(4));
        assert_eq!(pieces[1].data, b"zenoh");
        assert!(pieces[1].fin, "the FIN bit is read from the type");
    }

    /// R311y696 (§1.2a) — a STREAM frame WITHOUT the OFF bit begins at zero,
    /// and its absence is read from the type rather than assumed.
    ///
    /// ## Why this test exists
    ///
    /// Measured: a probe that read an offset varint unconditionally -- ignoring
    /// the type bit that says whether one is present -- passed every test in
    /// this module, because every fixture set the bit. A build with that defect
    /// consumes the first byte of the DATA as an offset and reports a stream
    /// that is shifted by one and short by one, which is a scrambled stream
    /// reported as a whole one.
    #[test]
    fn a_stream_frame_without_an_offset_field_begins_at_zero() {
        // 0x08 | LEN, and no OFF: id, length, bytes.
        let plaintext = vec![0x0a, 0x04, 0x05, b'z', b'e', b'n', b'o', b'h'];
        let pieces = walk(&plaintext).expect("the walk reads it");
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0].stream_id, Some(4), "the id is the first varint");
        assert_eq!(
            pieces[0].offset, 0,
            "a frame with no OFF bit starts at zero, and the byte after the id \
             is the LENGTH rather than an offset"
        );
        assert_eq!(
            pieces[0].data, b"zenoh",
            "so the data begins where the length says and not one byte later"
        );
    }

    /// R311y696 (§1.2a) — a frame type this walk does not know STOPS it.
    ///
    /// QUIC frames are not length-prefixed as a genre, so a reader that does
    /// not know a type does not know where it ends. Stepping over it by a
    /// guessed width would produce pieces at offsets nobody sent -- bytes that
    /// look like a stream and are not one.
    #[test]
    fn an_unknown_frame_type_stops_the_walk_by_name() {
        // 0x1e is HANDSHAKE_DONE in RFC 9000 and this walk does not carry it.
        let plaintext = vec![0x1e, 0x00];
        assert_eq!(
            walk(&plaintext).err(),
            Some(QuicOpenError::UnknownFrame(0x1e))
        );
    }

    /// R311y696 (§1.2a) — pieces are put back in ORDER, and a hole holds the
    /// bytes behind it rather than delivering them early.
    ///
    /// This is the property the whole module exists for: QUIC delivers a stream
    /// in whatever order the packets arrive, so a reader that appended in
    /// arrival order would hand this workspace's framing a stream that is
    /// scrambled -- and every message in it would decode as garbage with no
    /// indication why.
    #[test]
    fn pieces_are_reassembled_in_order_and_a_hole_holds_the_rest() {
        let mut r = StreamReassembler::new(None);
        let tail = super::frames::StreamPiece {
            stream_id: Some(0),
            offset: 5,
            data: b" world",
            fin: false,
        };
        let head = super::frames::StreamPiece {
            stream_id: Some(0),
            offset: 0,
            data: b"hello",
            fin: true,
        };

        assert_eq!(r.push(&tail), 0, "a piece behind a hole delivers nothing");
        assert_eq!(r.buffered(), 6, "and is held, counted");
        assert_eq!(r.stream(), b"", "nothing is delivered early");

        assert_eq!(r.push(&head), 11, "the hole filling releases both");
        assert_eq!(r.stream(), b"hello world");
        assert_eq!(r.buffered(), 0, "and the hold is empty again");
        assert!(
            r.finished(),
            "the FIN is remembered whichever order it came in"
        );

        // A RETRANSMISSION adds nothing: QUIC may resend, and a reader that
        // appended it again would invent bytes nobody sent.
        assert_eq!(r.push(&head), 0);
        assert_eq!(r.stream(), b"hello world");
    }

    /// R311y696 (§1.2a) — the hold is BOUNDED and what the bound cost is
    /// counted.
    ///
    /// An out-of-order piece is an accumulation that grows with the input,
    /// which this workspace bounds everywhere; a reassembler that silently
    /// discarded would report a stream shorter than the one that was sent.
    #[test]
    fn the_hold_is_bounded_and_says_what_it_refused() {
        let mut r = StreamReassembler::new(Some(4));
        let far = super::frames::StreamPiece {
            stream_id: Some(0),
            offset: 100,
            data: b"12345",
            fin: false,
        };
        assert_eq!(r.push(&far), 0);
        // ANTI-VACUITY: nothing was held, so the drop is the bound biting and
        // not an empty hold reporting itself.
        assert_eq!(r.buffered(), 0, "the piece did not fit");
        assert_eq!(r.dropped(), 5, "and what did not fit is counted");
    }
}

#[cfg(test)]
mod keylog_tests {
    use super::*;
    use crate::keylog::KeyLog;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// R311y697 (§1.2a) — a 1-RTT secret reaches QUIC keys through an ORDINARY
    /// key log line, and R311y694's carry said it could not.
    ///
    /// ## The claim that was wrong, and how it was checked
    ///
    /// That round recorded: "Handshake and 1-RTT keys need `QUIC_*_TRAFFIC_
    /// SECRET` entries, which `keylog::KeyLog` does not parse: it knows the TLS
    /// label set." Measured against the sources on this machine: rustls emits
    /// `CLIENT_TRAFFIC_SECRET_0` and `CLIENT_HANDSHAKE_TRAFFIC_SECRET` for QUIC
    /// exactly as for TLS (`rustls-0.23.43/src/tls13/key_schedule.rs`:1026-1028)
    /// and neither it nor `quinn-proto` mentions a `QUIC_` label anywhere. The
    /// NSS key log format has ONE label set and QUIC uses it.
    ///
    /// So nothing had to be added. What was missing was a test saying so —
    /// the fourth time this session a carry's "blocked" turned out to be a
    /// claim nobody had measured.
    ///
    /// ## What this gates, and what it leans on
    ///
    /// Gates: the log parses both label kinds, the secret comes out verbatim,
    /// and the keys derived from it are NOT the Initial ones. Leans on: the
    /// AEAD and header protection are already oracle-gated against rustls for
    /// Initial keys, and `initial` reaches them through this same `derive` —
    /// so what is unproven here is not the cryptography but only that a 1-RTT
    /// packet in a real capture is found and its short header walked, which is
    /// this track's remaining item and is stated as such.
    #[test]
    fn a_one_rtt_secret_reaches_quic_keys_through_an_ordinary_key_log_line() {
        let secret: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        let handshake: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(11).wrapping_add(5))
            .collect();
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1));
        let log = KeyLog::parse(
            format!(
                "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
                hex(&random),
                hex(&secret),
                hex(&random),
                hex(&handshake)
            )
            .as_bytes(),
        );

        let entry = log.get(&random).expect("the log holds this connection");
        // BOTH label kinds, because the carry named both spaces.
        assert_eq!(
            entry.get(crate::keylog::SecretLabel::ClientApplication(0)),
            Some(&secret[..]),
            "a QUIC 1-RTT secret is written under the TLS application label"
        );
        assert_eq!(
            entry.get(crate::keylog::SecretLabel::ClientHandshake),
            Some(&handshake[..]),
            "and the handshake secret under the TLS handshake label"
        );

        let one_rtt = QuicKeys::derive(Suite::Aes128GcmSha256, &secret);
        let hs = QuicKeys::derive(Suite::Aes128GcmSha256, &handshake);
        // ANTI-VACUITY: two different secrets must give two different keys, or
        // "derive works" would hold for a function that returned a constant.
        assert_ne!(one_rtt.key, hs.key, "different secrets, different keys");
        // AND NEITHER IS THE INITIAL KEY of the same connection: the spaces are
        // separate derivations and a reader that reused one would open nothing.
        let (initial, _) = QuicKeys::initial(QuicVersion::V1, &random[..8]);
        assert_ne!(one_rtt.key, initial.key);
        assert_ne!(hs.key, initial.key);
    }
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y669 (§1.2a) — QUIC RECOGNITION, and only recognition.
//!
//! # Why this module exists, measured
//!
//! Before it, a QUIC capture was not un-read — it was MISREAD. Driven through
//! `wz-analyze`, a three-packet QUIC exchange on port 7447 reported:
//!
//! ```text
//! messages decoded: 4
//!   A @2 #0  Init
//!   A @2 #1  Fragment
//! ```
//!
//! There are no zenoh messages in that capture. A QUIC short header's first
//! byte has the high bit clear and the next bit set (`0x40..=0x7F`), which in
//! the zenoh transport envelope is a MID in the low five bits under two flag
//! bits — so `0x41` is a perfectly good `T_MID_INIT` with a flag on it. The
//! reader produced a confident wrong answer, complete with a message count, and
//! nothing in the report said the bytes might not have been zenoh at all. That
//! is the failure this whole crate exists to end, and QUIC was the one transport
//! where it was still happening.
//!
//! # Why the byte cannot be the discriminator, and what is
//!
//! The collision above is not incidental. zenoh's transport MID space occupies
//! the same first byte QUIC's short header does, so no first-byte rule separates
//! them: a rule that called `0x41` QUIC would silence real zenoh INIT traffic,
//! and one that called it zenoh keeps the misread. This is the SCOUT-vs-INIT
//! collision (`wz_session_core::scouting_message`) a second time, and it takes
//! the same answer — **the discriminator is the flow, not the byte.**
//!
//! A QUIC LONG header, on the other hand, is soundly recognisable: the high bit
//! and the fixed bit are both set, a known 32-bit version follows, and the two
//! connection-id lengths are bounded (≤ 20, RFC 9000 §17.2) and must fit inside
//! the datagram. A zenoh transport message cannot satisfy all of that — `0x80`
//! is not a MID flag zenoh sets on a datagram, and the version word would have
//! to be one of a handful of exact values by accident.
//!
//! So: a flow becomes QUIC when a long header is seen on it, and every datagram
//! after that — short headers included — belongs to QUIC and is counted rather
//! than decoded. That requires having seen part of the handshake, which is the
//! same precondition [`crate::tls::NotDecrypted::NoSessionIdentity`] already
//! records for a mid-session TLS capture, and it fails in the same honest
//! direction: a capture that begins mid-connection is not recognised, and this
//! module says nothing about it rather than guessing.
//!
//! # What this module deliberately does NOT do
//!
//! It does not decrypt. QUIC packet protection is two layers — header
//! protection removes the packet-number mask before the AEAD can be applied, and
//! the keys come off the TLS traffic secret through a QUIC-specific
//! HKDF-Expand-Label schedule (`quic key` / `quic iv` / `quic hp`, RFC 9001
//! §5.1) — and the zenoh bytes then live inside QUIC STREAM frames that must be
//! reassembled before any of this crate's framing applies. That is a track, not
//! a function. What matters here is that a reader is told the difference between
//! "this capture carried no zenoh" and "this capture carried QUIC that I did not
//! open", and until this module those were the same output.

/// One QUIC packet, as much as an unkeyed reader can say about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicPacket {
    /// What the header says it is.
    pub kind: QuicPacketKind,
    /// The version word, for a long header. `None` for a short header, whose
    /// header carries no version — the connection's version was established by
    /// the long-header packets that came before it.
    pub version: Option<u32>,
    /// Datagram bytes this packet accounts for. The whole datagram: this reader
    /// does not walk a coalesced packet's length fields, and claiming a smaller
    /// number would under-report what it could not read.
    pub bytes: usize,
}

/// The packet types an unkeyed reader can name.
///
/// Long-header types come from the two type bits (RFC 9000 §17.2); the short
/// header has no type field, which is why it is one variant and not several.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPacketKind {
    /// Carries the CRYPTO frames of the TLS ClientHello / ServerHello. Its keys
    /// are derivable from the version and the original destination connection id
    /// alone, which is why a real dissector reads it without a key log — and
    /// also why reading it is a track of its own rather than a line here.
    Initial,
    /// Early data, under the 0-RTT key.
    ZeroRtt,
    /// The rest of the encrypted handshake.
    Handshake,
    /// A server refusing to accept the client's connection id.
    Retry,
    /// Version 0: the server listing versions it does support.
    VersionNegotiation,
    /// 1-RTT application data. Recognised ONLY on a flow already established as
    /// QUIC — see the module note on why its first byte cannot decide.
    OneRtt,
}

/// The most a connection id may be, RFC 9000 §17.2.
const MAX_CID_LEN: usize = 20;

/// The versions this reader will accept as establishing a QUIC flow.
///
/// An explicit list and not "any nonzero word", because the version field is
/// the load-bearing half of the long-header rule: accepting anything would
/// reduce the test to two header bits, which a zenoh datagram can satisfy.
///
/// `0` is Version Negotiation (RFC 9000 §17.2.1) and is accepted separately in
/// [`recognise_long`], since it is the one long-header packet with no version to
/// match.
const KNOWN_VERSIONS: &[u32] = &[
    // RFC 9000.
    0x0000_0001,
    // RFC 9369, QUIC v2.
    0x6b33_43cf,
];

/// Is this word one of the IETF draft versions (`0xff00_00xx`)?
///
/// Kept separate from [`KNOWN_VERSIONS`] because it is a RANGE and because a
/// draft version is a fact about a capture's age rather than about the
/// protocol: a reader that refused them would fail to recognise older captures
/// while reporting them as zenoh, which is the misread this module removes.
fn is_draft_version(v: u32) -> bool {
    v & 0xffff_ff00 == 0xff00_0000
}

/// Recognise a LONG-header QUIC packet, or answer `None`.
///
/// Sound on its own — this is the function that may establish a flow as QUIC —
/// so every field it reads is bounds-checked against the datagram it came from.
pub fn recognise_long(payload: &[u8]) -> Option<QuicPacket> {
    let first = *payload.first()?;
    // Header form (0x80) and the fixed bit (0x40). The fixed bit is what a
    // version-negotiation packet may clear, and it is checked below rather than
    // here for exactly that case.
    if first & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(payload.get(1..5)?.try_into().ok()?);

    // Connection ids: a length byte then that many bytes, both halves inside
    // the datagram. This is the second half of the rule and it is what makes a
    // coincidental first byte insufficient.
    let dcid_len = *payload.get(5)? as usize;
    if dcid_len > MAX_CID_LEN {
        return None;
    }
    let after_dcid = 6 + dcid_len;
    let scid_len = *payload.get(after_dcid)? as usize;
    if scid_len > MAX_CID_LEN {
        return None;
    }
    // The source connection id must fit; a datagram that ends inside it is not
    // a QUIC long header this reader will act on.
    if payload.len() < after_dcid + 1 + scid_len {
        return None;
    }

    // Version 0 is Version Negotiation, whose type bits carry no meaning.
    if version == 0 {
        return Some(QuicPacket {
            kind: QuicPacketKind::VersionNegotiation,
            version: Some(0),
            bytes: payload.len(),
        });
    }
    if first & 0x40 == 0 {
        // The fixed bit is clear on a versioned long header. RFC 9000 requires
        // it set; something else produced these bytes.
        return None;
    }
    if !KNOWN_VERSIONS.contains(&version) && !is_draft_version(version) {
        return None;
    }
    let kind = match (first >> 4) & 0x03 {
        0 => QuicPacketKind::Initial,
        1 => QuicPacketKind::ZeroRtt,
        2 => QuicPacketKind::Handshake,
        _ => QuicPacketKind::Retry,
    };
    Some(QuicPacket {
        kind,
        version: Some(version),
        bytes: payload.len(),
    })
}

/// Read one datagram of a flow ALREADY established as QUIC.
///
/// Answers a short-header packet where [`recognise_long`] would not, and that
/// is the whole difference between the two functions: this one is only sound
/// because its caller has already decided the flow, so the first byte no longer
/// has to carry the decision.
///
/// `None` means the datagram is not a QUIC packet at all — the fixed bit is
/// clear and no long header matched. Reported rather than folded into the count:
/// a QUIC flow carrying something else is a fact, and a census that absorbed it
/// would be claiming to have seen a packet it could not name.
pub fn recognise_on_quic_flow(payload: &[u8]) -> Option<QuicPacket> {
    if let Some(p) = recognise_long(payload) {
        return Some(p);
    }
    let first = *payload.first()?;
    // Short header: form clear, fixed set. On an established flow that is the
    // whole test, because the alternative — a zenoh message on a flow whose
    // handshake was QUIC — is not a thing either endpoint can produce.
    if first & 0x80 == 0 && first & 0x40 != 0 {
        return Some(QuicPacket {
            kind: QuicPacketKind::OneRtt,
            version: None,
            bytes: payload.len(),
        });
    }
    None
}

/// What a QUIC flow was seen to carry.
///
/// Counts and not kept packets, deliberately: every byte of it is protected and
/// this reader holds no key, so keeping the bytes would grow memory in exchange
/// for nothing it can later say. The same reasoning
/// [`crate::tls::MAX_KEPT_RECORDS_PER_DIRECTION`] inverts for TLS, where the
/// records ARE openable given a key log and so are worth keeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuicCensus {
    /// Packets recognised, of every kind.
    pub packets: usize,
    /// Datagram bytes they accounted for.
    pub bytes: u64,
    /// Long-header packets by kind: Initial, 0-RTT, Handshake, Retry,
    /// Version Negotiation, and 1-RTT last.
    pub initial: usize,
    /// 0-RTT (early data) packets.
    pub zero_rtt: usize,
    /// Handshake packets.
    pub handshake: usize,
    /// Retry packets.
    pub retry: usize,
    /// Version Negotiation packets.
    pub version_negotiation: usize,
    /// 1-RTT (application data) packets — where the zenoh session would be.
    pub one_rtt: usize,
    /// Datagrams on this flow that were NOT a QUIC packet. Counted rather than
    /// ignored, so "a QUIC flow" never silently absorbs bytes it could not name.
    pub unrecognised: usize,
    /// The version the flow's long headers carried, or `None` before one was
    /// seen. First one wins: a flow whose version changes mid-connection is a
    /// version negotiation, whose own packet carries `0` and does not overwrite.
    pub version: Option<u32>,
    /// R311y670 (§1.2a) — this flow was DECLARED QUIC by the caller rather than
    /// RECOGNISED from a long header.
    ///
    /// Carried because the two are different claims and a reader must be able to
    /// tell which one it is reading. "I saw an Initial packet with version 1 on
    /// this flow" is evidence; "someone told me port 4433 is QUIC" is a premise,
    /// and a premise that is wrong makes every count below wrong with it — a
    /// declared port carrying real zenoh would report that zenoh as unopened
    /// QUIC, which is this round's own mirror-image hazard.
    pub declared: bool,
}

impl QuicCensus {
    /// Fold one recognised packet in.
    pub fn add(&mut self, p: QuicPacket) {
        self.packets += 1;
        self.bytes += p.bytes as u64;
        match p.kind {
            QuicPacketKind::Initial => self.initial += 1,
            QuicPacketKind::ZeroRtt => self.zero_rtt += 1,
            QuicPacketKind::Handshake => self.handshake += 1,
            QuicPacketKind::Retry => self.retry += 1,
            QuicPacketKind::VersionNegotiation => self.version_negotiation += 1,
            QuicPacketKind::OneRtt => self.one_rtt += 1,
        }
        // A real version only. Version Negotiation carries `0`, which is not
        // the connection's version and must not be recorded as one.
        if self.version.is_none() {
            if let Some(v) = p.version.filter(|v| *v != 0) {
                self.version = Some(v);
            }
        }
    }

    /// Fold one datagram this reader could not name.
    pub fn add_unrecognised(&mut self, bytes: usize) {
        self.packets += 1;
        self.bytes += bytes as u64;
        self.unrecognised += 1;
    }

    /// R311y671 (§1.2a) — does this flow CONTRADICT the declaration it rests on?
    ///
    /// A flow classified by [`Self::declared`] and carrying not one packet this
    /// reader can name as QUIC is a flow whose premise is probably wrong — and
    /// the cost of a wrong premise is the worst this reader can inflict: the
    /// datagrams were withheld from the zenoh decoder, so REAL zenoh traffic was
    /// silenced and the report said the bytes were protected.
    ///
    /// MEASURED before this existed: declaring a port that carried three ordinary
    /// zenoh datagrams produced `unrecognised: 3`, `one_rtt: 0`, `initial: 0` in
    /// the JSON -- the signal was already there and complete -- while the text
    /// rendering said `NOT DECRYPTED (this reader recognises QUIC and opens none
    /// of it)`. Nothing read the signal, and the sentence a person actually sees
    /// was a confident wrong statement.
    ///
    /// # What this does NOT catch, and why it is still worth having
    ///
    /// A zenoh message whose first byte happens to carry bit `0x40` -- a
    /// `Fragment` with its M flag, say -- IS accepted as a 1-RTT packet by
    /// [`recognise_on_quic_flow`], because on a flow the caller has declared
    /// there is nothing left to check. So a wrong declaration over
    /// fragment-heavy traffic looks supported. This answers about the case a
    /// wrong flag usually produces (handshake and keepalive bytes, whose MIDs sit
    /// below `0x20` with no `0x40` flag) and it does not answer about every case.
    /// A partial witness that fires on the common shape beats no witness on a
    /// premise whose failure is silent.
    pub fn declaration_unsupported(&self) -> bool {
        self.declared && self.packets > 0 && self.unrecognised == self.packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// A QUIC long header of the given type bits and version.
    fn long(type_bits: u8, version: u32, body: &[u8]) -> Vec<u8> {
        let dcid = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let scid = [8u8, 9, 10, 11];
        let mut out = alloc::vec![0xC0 | (type_bits << 4)];
        out.extend_from_slice(&version.to_be_bytes());
        out.push(dcid.len() as u8);
        out.extend_from_slice(&dcid);
        out.push(scid.len() as u8);
        out.extend_from_slice(&scid);
        out.extend_from_slice(body);
        out
    }

    /// THE ROUND, as one assertion: every long-header type is named.
    #[test]
    fn each_long_header_type_is_named() {
        for (bits, kind) in [
            (0u8, QuicPacketKind::Initial),
            (1, QuicPacketKind::ZeroRtt),
            (2, QuicPacketKind::Handshake),
            (3, QuicPacketKind::Retry),
        ] {
            let wire = long(bits, 1, &[0xAA; 20]);
            let got = recognise_long(&wire).expect("a v1 long header is recognised");
            assert_eq!(got.kind, kind, "type bits {bits}");
            assert_eq!(got.version, Some(1));
            assert_eq!(got.bytes, wire.len(), "the whole datagram is accounted for");
        }
    }

    /// THE DISCRIMINATING NEGATIVE, and it is the reason this module is
    /// flow-scoped: a zenoh transport message whose first byte looks like a
    /// QUIC short header must NOT be recognised by the sound function.
    ///
    /// `T_MID_INIT | 0x40` is `0x41`, which is `0x40..=0x7F` — form clear, fixed
    /// set — i.e. exactly a short header's first byte. A rule that decided on
    /// that byte would silence real zenoh INIT traffic.
    #[test]
    fn a_zenoh_message_that_looks_like_a_short_header_is_not_recognised() {
        // A plausible zenoh INIT: mid 0x01 with a flag bit set, version, cbyte,
        // a one-byte zid.
        let zenoh = [0x41u8, 0x09, 0x01, 0xAA];
        assert_eq!(
            recognise_long(&zenoh),
            None,
            "the sound rule must not claim a zenoh message"
        );
        // And on an ESTABLISHED QUIC flow the same bytes ARE a packet, which is
        // the whole point of there being two functions: the flow carries the
        // decision the byte cannot.
        assert!(recognise_on_quic_flow(&zenoh).is_some());
    }

    /// An unknown version is refused. The version word is the load-bearing half
    /// of the rule; without it the test is two header bits, which a zenoh
    /// datagram can satisfy.
    #[test]
    fn an_unknown_version_does_not_establish_a_quic_flow() {
        assert_eq!(recognise_long(&long(0, 0xDEAD_BEEF, &[0xAA; 8])), None);
        // v2 and the draft range are accepted.
        assert!(recognise_long(&long(0, 0x6b33_43cf, &[0xAA; 8])).is_some());
        assert!(recognise_long(&long(0, 0xff00_001d, &[0xAA; 8])).is_some());
    }

    /// Version 0 is Version Negotiation and is named as such — including with
    /// the fixed bit clear, which that packet alone is allowed to do.
    #[test]
    fn version_zero_is_version_negotiation_whatever_the_fixed_bit_says() {
        let mut wire = long(0, 0, &[0xAA; 8]);
        let got = recognise_long(&wire).expect("recognised");
        assert_eq!(got.kind, QuicPacketKind::VersionNegotiation);
        wire[0] &= !0x40;
        assert_eq!(
            recognise_long(&wire).map(|p| p.kind),
            Some(QuicPacketKind::VersionNegotiation),
            "a version-negotiation packet may clear the fixed bit"
        );
        // A VERSIONED long header may not.
        let mut versioned = long(0, 1, &[0xAA; 8]);
        versioned[0] &= !0x40;
        assert_eq!(recognise_long(&versioned), None);
    }

    /// A connection id longer than RFC 9000 allows, and a datagram that ends
    /// inside one, are both refused — the bounds are what stop a coincidental
    /// first byte and version from carrying a parse off the end.
    #[test]
    fn an_oversize_or_truncated_connection_id_is_refused() {
        let mut over = long(0, 1, &[0xAA; 8]);
        over[5] = (MAX_CID_LEN + 1) as u8;
        assert_eq!(recognise_long(&over), None, "dcid longer than 20");

        // Truncated: the header claims an 8-byte dcid and a 4-byte scid and the
        // datagram stops in the middle of the second.
        let full = long(0, 1, &[]);
        for cut in 1..=4usize {
            assert_eq!(
                recognise_long(&full[..full.len() - cut]),
                None,
                "a datagram ending inside the scid is not a header to act on"
            );
        }
    }

    /// The census names each kind and never records `0` as the connection's
    /// version. A flow that reported version 0 would be describing a
    /// version-negotiation exchange as if it had negotiated version zero.
    #[test]
    fn the_census_counts_by_kind_and_never_calls_zero_a_version() {
        let mut c = QuicCensus::default();
        c.add(QuicPacket {
            kind: QuicPacketKind::VersionNegotiation,
            version: Some(0),
            bytes: 40,
        });
        assert_eq!(c.version, None, "0 is not a version");
        c.add(QuicPacket {
            kind: QuicPacketKind::Initial,
            version: Some(1),
            bytes: 1200,
        });
        c.add(QuicPacket {
            kind: QuicPacketKind::OneRtt,
            version: None,
            bytes: 100,
        });
        c.add_unrecognised(7);
        assert_eq!(
            (c.packets, c.bytes, c.initial, c.one_rtt, c.unrecognised),
            (4, 1347, 1, 1, 1)
        );
        assert_eq!(c.version, Some(1), "the first REAL version wins");
    }
}

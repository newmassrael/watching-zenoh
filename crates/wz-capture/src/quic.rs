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
const KNOWN_VERSIONS: &[(u32, VersionSource)] = &[
    // RFC 9000, and named by an implementation this tree resolves:
    // `quinn_proto::DEFAULT_SUPPORTED_VERSIONS[0]`
    // (quinn-proto-0.11.16/src/lib.rs:161).
    (0x0000_0001, VersionSource::Implementation),
    // RFC 9369, QUIC v2. NO implementation on this machine names this word --
    // see [`VersionSource::Document`] for what was searched.
    (0x6b33_43cf, VersionSource::Document),
];

/// R311y708 (§1.2a) — WHERE the number a version field was matched against came
/// from.
///
/// Carried because this crate has a rule about constants — one it cannot check
/// must not be carried as though it could (R311y695) — and because the flat list
/// this replaced was in breach of it while looking exactly like compliance. A
/// reader of `KNOWN_VERSIONS` could not tell which of its entries this tree can
/// verify and which is a remembered reading of an RFC, and that is precisely the
/// laundering the rule names.
///
/// The alternative considered and REJECTED was to delete the unverifiable entry.
/// That trades a stated weakness for a silent one: without `0x6b33_43cf` a QUIC
/// v2 flow is not recognised, so its datagrams go to the zenoh decoder and come
/// back as the confident wrong answer in this module's own header comment. The
/// asymmetry decides it — a wrong number here can only silence traffic that
/// deliberately carries that exact word in the version field behind both header
/// bits and two valid connection-id lengths, while a missing number silences
/// every v2 flow there is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSource {
    /// An implementation in this tree's own dependency graph names this word,
    /// so a build here is wrong about it only if that implementation is.
    Implementation,
    /// Only a specification document names it.
    ///
    /// MEASURED for `0x6b33_43cf` (R311y708): absent from every `.rs` and
    /// `.toml` in this machine's cargo registry cache;
    /// `quinn_proto::DEFAULT_SUPPORTED_VERSIONS` lists v1 and six drafts and not
    /// this (quinn-proto-0.11.16/src/lib.rs:160-168); `rustls::quic::Version::V2`
    /// carries the salt and the `quicv2 key` / `iv` / `hp` labels and no wire
    /// number at all (rustls-0.23.40/src/quic.rs:1003,1015,1023,1031).
    Document,
}

/// Which authority names this word as a QUIC version, if any.
///
/// `None` is the answer for a word that is not a version this reader accepts —
/// the same answer [`recognise_long`] acts on, exposed so a caller can ask about
/// provenance without re-deriving the table.
pub fn version_source(v: u32) -> Option<VersionSource> {
    if let Some((_, src)) = KNOWN_VERSIONS.iter().find(|(known, _)| *known == v) {
        return Some(*src);
    }
    draft_version_source(v)
}

/// Is this word one of the IETF draft versions (`0xff00_00xx`), and who names it?
///
/// Kept separate from [`KNOWN_VERSIONS`] because it is a RANGE and because a
/// draft version is a fact about a capture's age rather than about the
/// protocol: a reader that refused them would fail to recognise older captures
/// while reporting them as zenoh, which is the misread this module removes.
///
/// R311y708 — the range is split by the same authority question, because the
/// answer genuinely differs across it: `quinn_proto::DEFAULT_SUPPORTED_VERSIONS`
/// names `0xff00_001d` through `0xff00_0022` and nothing else in the range, so
/// the other 250 words are accepted on the shape of the space rather than on any
/// implementation agreeing.
fn draft_version_source(v: u32) -> Option<VersionSource> {
    if v & 0xffff_ff00 != 0xff00_0000 {
        return None;
    }
    Some(if (0xff00_001d..=0xff00_0022).contains(&v) {
        VersionSource::Implementation
    } else {
        VersionSource::Document
    })
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
    version_source(version)?;
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

/// R311y698 (§1.2a) — what a DECRYPTOR did with this capture's QUIC flows.
///
/// # Why this type is in the crate that opens nothing
///
/// This crate recognises QUIC and carries no cipher, by the same rule that put
/// TLS record decryption behind `wz_capture::tls::RecordOpener`: the decode path
/// builds for the MCU profiles and may not gain a third-party dependency. Until
/// this round that meant the report's QUIC sentence ended `NOT DECRYPTED (this
/// reader recognises QUIC and opens none of it)` and its JSON carried a
/// hard-coded `"decrypted":false` -- statements that were true of this crate and
/// became false the moment a caller existed.
///
/// So the RESULT comes back as plain counts. Nothing here is a key, a cipher or
/// a plaintext; a decryptor fills it in and the report renders it, which is the
/// same inversion `RecordOpener` uses in the other direction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QuicDecryption {
    /// Flows a decryptor was given.
    pub flows_offered: usize,
    /// Flows whose every packet opened. The figure
    /// [`crate::report::CaptureReport::is_complete`] consults, on exactly the
    /// rule an undecrypted TLS flow reaches that verdict by.
    pub flows_opened: usize,
    /// Packets offered.
    pub packets: usize,
    /// Packets whose AEAD authenticated.
    pub packets_opened: usize,
    /// Packets refused for want of a key for their space -- a key log question.
    pub packets_no_keys: usize,
    /// Packets refused for any other reason -- a capture question.
    pub packets_refused: usize,
    /// Handshake bytes recovered in order.
    pub crypto_bytes: usize,
    /// Application stream bytes recovered in order.
    pub stream_bytes: usize,
    /// RFC 9221 datagram bytes recovered, which carry no order at all.
    pub datagram_bytes: usize,
    /// Frame walks that stopped at a type the walker does not know. Nonzero
    /// means some packet's later frames went unread and a stream is short by an
    /// unknown amount -- a floor reported as a total is exactly what this
    /// crate's gap counters exist to prevent.
    pub walks_stopped: usize,
    /// R311y710 (Y2) — flows whose identity was ADOPTED from a key log holding
    /// exactly one connection, rather than read from a ClientHello.
    ///
    /// Carried at the capture level and not only per flow, because the per-flow
    /// listing is behind `--flows` and this line is the one a person reads
    /// first. The same reason `declared_flows` sits beside it: a summary that
    /// reports the consequence of a premise without reporting the premise
    /// invites the reader to treat it as evidence.
    pub flows_identity_adopted: usize,
    /// R311y718 (§1.2a) — what became of the recovered bytes once a zenoh
    /// framer saw them.
    ///
    /// Beside the byte counters rather than replacing them, because they answer
    /// different questions and the gap between the two is the finding:
    /// [`Self::stream_bytes`] is how much QUIC gave back, and this is how much
    /// of it turned into messages. A round that recovered 25 bytes and decoded
    /// nothing from them looks identical to a working one in the byte counter
    /// alone -- which is the state this field ends.
    pub framing: QuicStreamFeed,
}

/// R311y718 (§1.2a) — what [`crate::Dissection::feed_quic_stream`] did with one
/// offer of recovered stream bytes.
///
/// Counts and not a bool, because the four ways an offer can end are four
/// different findings and only one of them is "nothing happened": bytes may be
/// refused by the per-flow stream bound, offered to a flow this dissection does
/// not hold, framed into messages, or framed into none because the recovered
/// prefix stops mid-message. A caller that could only see success would report
/// the last two identically.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QuicStreamFeed {
    /// Bytes handed to a zenoh framer.
    pub bytes_fed: usize,
    /// Transport messages that came out of them.
    pub messages: usize,
    /// Offers whose flow this dissection does not hold — an evicted flow, or a
    /// caller feeding a key that was never in the datagram table.
    pub flow_absent: usize,
    /// Offers refused because the flow already holds
    /// [`crate::DissectionLimits::quic_streams_per_flow`] streams.
    ///
    /// A REFUSAL and not an eviction: the streams already being framed hold
    /// session state (the zenoh handshake is on one of them), so dropping the
    /// oldest to admit a new one would throw away the decoded half of the
    /// connection to make room for its tail. The bound therefore stops
    /// admitting rather than starts discarding, and this counter is what keeps
    /// that from being silent.
    pub streams_refused: usize,
    /// Offers whose bytes were CRYPTO rather than an application stream, and so
    /// were never zenoh to begin with.
    ///
    /// Nonzero is not an error — it is a caller handing on the TLS handshake,
    /// which belongs to the key schedule and not to a zenoh framer. Counted so
    /// that "no messages" can be told apart from "no application bytes".
    pub handshake_offers: usize,
    /// Bytes a framer was given and decoded no message out of, over every
    /// stream, once the pass has finished.
    ///
    /// NOT a sum of per-offer leftovers — a stream fed twice has one leftover,
    /// not two — so a caller computes this from the FINAL state
    /// ([`crate::QuicStreamDissection::undecoded_bytes`]) and sets it once.
    /// [`Self::absorb`] therefore takes the larger rather than adding, which
    /// keeps a per-offer fold from double counting a stream it saw twice.
    ///
    /// Load-bearing for the verdict: feeding a framer is not reading, and a
    /// capture whose recovered bytes were pushed into a stall is short by them
    /// exactly as one nobody offered at all is.
    pub bytes_undecoded: usize,
    /// Offers that APPENDED to a stream and whose messages were therefore
    /// framed but not offered to the field sink.
    ///
    /// Zero for the analyzer's own pass, which offers each direction of each
    /// stream exactly once. Nonzero says a `--fields` listing is short by those
    /// messages, and it is a count rather than a silence because the
    /// alternative — walking a tail at an offset into the whole — names the
    /// wrong bytes as a message's fields. See
    /// [`crate::Dissection::feed_quic_stream_with_sink`].
    pub appends_not_walked: usize,
}

impl QuicStreamFeed {
    /// Fold another offer's counts into this one.
    pub fn absorb(&mut self, other: QuicStreamFeed) {
        self.bytes_fed += other.bytes_fed;
        self.messages += other.messages;
        self.flow_absent += other.flow_absent;
        self.streams_refused += other.streams_refused;
        self.handshake_offers += other.handshake_offers;
        self.appends_not_walked += other.appends_not_walked;
        // See the field: a stream's leftover is a property of its final state,
        // so folding it must not accumulate. `max` keeps a fold over offers
        // agreeing with a single set from the finished dissection.
        self.bytes_undecoded = self.bytes_undecoded.max(other.bytes_undecoded);
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

    /// R311y708 — EVERY ACCEPTED VERSION, PAIRED WITH WHO SAYS SO.
    ///
    /// The SET and not a count (R311y634), and stated in both directions,
    /// because the two halves fail differently: an entry that quietly moved to
    /// `Implementation` would launder exactly the constant this round un-
    /// laundered, and one that moved to `Document` would put a caveat on a
    /// number `quinn_proto::DEFAULT_SUPPORTED_VERSIONS` names out loud.
    ///
    /// The negative arm matters just as much. `0x0000_0002` is not a QUIC
    /// version and must answer `None` rather than any authority — the whole
    /// point of an explicit list is that "any nonzero word" reduces recognition
    /// to two header bits, which a zenoh datagram satisfies.
    #[test]
    fn each_accepted_version_names_the_authority_that_names_it() {
        for (word, want) in [
            // Named by quinn-proto: v1 and the six drafts it lists.
            (0x0000_0001u32, Some(VersionSource::Implementation)),
            (0xff00_001d, Some(VersionSource::Implementation)),
            (0xff00_001e, Some(VersionSource::Implementation)),
            (0xff00_001f, Some(VersionSource::Implementation)),
            (0xff00_0020, Some(VersionSource::Implementation)),
            (0xff00_0021, Some(VersionSource::Implementation)),
            (0xff00_0022, Some(VersionSource::Implementation)),
            // Accepted from a document alone: v2, and the rest of the draft
            // space either side of the six above.
            (0x6b33_43cf, Some(VersionSource::Document)),
            (0xff00_0000, Some(VersionSource::Document)),
            (0xff00_001c, Some(VersionSource::Document)),
            (0xff00_0023, Some(VersionSource::Document)),
            (0xff00_00ff, Some(VersionSource::Document)),
            // Not a version this reader accepts at all.
            (0x0000_0002, None),
            (0x6b33_43ce, None),
            (0xfe00_0001, None),
            (0xff00_0100, None),
        ] {
            assert_eq!(
                version_source(word),
                want,
                "the authority for {word:#010x} is not what this tree measured"
            );
        }
    }

    /// R311y708 — AND THE RECOGNITION IS UNCHANGED BY SAYING SO.
    ///
    /// This is what deleting the unverifiable entry would have cost, made
    /// concrete: a v2 long header is a QUIC packet, and a reader that dropped it
    /// would hand these bytes to the zenoh decoder, which is the misread in this
    /// module's own header comment. The caveat rides ALONGSIDE the recognition,
    /// it does not replace it.
    #[test]
    fn a_version_only_a_document_names_is_still_recognised() {
        let wire = long(0, 0x6b33_43cf, &[0xAA; 20]);
        let got = recognise_long(&wire).expect("a v2 long header is a QUIC packet");
        assert_eq!(got.kind, QuicPacketKind::Initial);
        assert_eq!(got.version, Some(0x6b33_43cf));
        assert_eq!(
            version_source(0x6b33_43cf),
            Some(VersionSource::Document),
            "and the fact that nothing here can check it survives recognition"
        );
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

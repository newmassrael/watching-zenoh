// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y648 (§1.2a) — RECOGNISING a TLS record stream, and nothing else.
//!
//! ## What this is for
//!
//! zenoh's `tls/...` and `quic/...` locators are the ordinary production shape,
//! and a capture of one was this crate's worst possible output: the TCP flow was
//! created, the stream reader read a length prefix out of the record header,
//! waited for bytes that never satisfied it, and reported a flow with **zero
//! frames, zero desyncs, zero skips and zero gaps**. Every health counter said
//! the capture was clean. That is indistinguishable from a connection that
//! carried no zenoh traffic at all — a wrong statement about a working
//! deployment, made confidently.
//!
//! Naming the flow as encrypted is worth more than decrypting it, and it comes
//! first: a reader who is told "this is TLS and no keys were supplied" knows
//! what to do next, and a reader shown an empty flow does not know there is
//! anything to do.
//!
//! ## What this deliberately is NOT
//!
//! There is no cryptography here and there will not be. This module reads the
//! 5-byte record header — a content type, a legacy version and a big-endian
//! length — and walks the chain. Decryption is a separate crate on the far side
//! of the seam this crate already draws (`lib.rs`'s module doc: the boundary is
//! a byte stream plus a direction), because a cipher is not a zenoh fact and
//! `wz-capture` keeps its zero third-party dependencies.
//!
//! ## Why the discriminator is what it is
//!
//! A zenoh stream frames every unit with a 2-byte LITTLE-endian length, so its
//! first bytes are `[len_lo, len_hi, mid, ..]`. A TLS record opens
//! `[0x16, 0x03, 0x01, len_hi, len_lo, ..]`. Those overlap: a 790-byte zenoh
//! unit beginning with an `INIT` is `[0x16, 0x03, 0x01, ..]` byte for byte, so
//! a detector that matched the first three bytes would classify a real zenoh
//! flow as encrypted and produce exactly the silence it exists to end, in the
//! other direction.
//!
//! Two independent structural facts are therefore required, and neither is a
//! heuristic:
//!
//! 1. **The ClientHello is internally consistent.** A handshake record carries
//!    a 1-byte message type and a 3-byte length, and that length must be
//!    exactly the record's length minus its own 4-byte header. A zenoh unit
//!    would have to agree with a number derived from two different byte orders.
//! 2. **The records CHAIN.** The byte after the first record must open another
//!    plausible record, or the direction must end exactly on the record
//!    boundary. This is the `ws::carries_ws_frames` rule: the answer comes from
//!    walking the structure, not from recognising a prefix.

use alloc::vec::Vec;

/// TLS content types (RFC 8446 §5.1, RFC 5246 §6.2.1).
pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

/// The handshake message type of a ClientHello (RFC 8446 §4.1.2).
const HS_CLIENT_HELLO: u8 = 1;

/// A record's fixed header width: type, version major/minor, length.
const RECORD_HEADER: usize = 5;

/// The largest a record's fragment may be. RFC 8446 §5.1 caps plaintext at
/// 2^14 and lets a ciphertext record carry up to 256 bytes more; RFC 5246
/// allowed 2048 for compression, so the wider legacy bound is used — a
/// recogniser that refused a legal record would answer `No` about real TLS.
const MAX_FRAGMENT: usize = (1 << 14) + 2048;

/// What a direction's opening bytes say about whether it carries TLS.
///
/// Three answers for the reason [`crate::ws::UpgradeVerdict`] has three: a
/// caller forced to choose on too few bytes either stalls a short flow forever
/// or decides it wrongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVerdict {
    /// A TLS record stream, opened by a self-consistent ClientHello.
    Yes,
    /// Not one — settled, however few bytes there are.
    No,
    /// Still consistent with a ClientHello and shorter than the evidence
    /// needs. Wait.
    NeedMore,
}

/// Does this direction open with a TLS ClientHello?
///
/// Answers `No` the moment the bytes diverge, never on a byte count, so a
/// direction whose whole first message is shorter than a record header is
/// settled rather than held — the defect `ws::http_upgrade_verdict`'s own
/// comment records having been written once already.
///
/// Only the CLIENT's direction is recognised here. The server's flight opens
/// with a ServerHello that is equally well-formed, and admitting it would mean
/// answering `Yes` for any handshake-shaped record — including the one a
/// mid-session capture starts on, where the internal length check has nothing
/// to disagree with.
///
/// R311y649 — that cost is no longer paid by the FLOW. This question stayed
/// exactly as narrow as it was and [`record_chain_verdict`] was added beside it:
/// a capture with no ClientHello in it is now recognised by the chain instead,
/// which is evidence of a different kind rather than a loosening of this one.
pub fn client_hello_verdict(bytes: &[u8]) -> TlsVerdict {
    // Byte 0 decides against every stream whose first byte is not a handshake
    // record, which is almost all of them.
    match bytes.first() {
        None => return TlsVerdict::NeedMore,
        Some(&ct) if ct != CT_HANDSHAKE => return TlsVerdict::No,
        Some(_) => {}
    }
    // The legacy record version of a ClientHello is `TLS 1.0` on the wire even
    // for TLS 1.3 (RFC 8446 §5.1 keeps it for middlebox compatibility), but
    // `1.1` and `1.2` are both seen from older stacks. The major must be 3.
    match (bytes.get(1), bytes.get(2)) {
        (None, _) | (Some(_), None) => return TlsVerdict::NeedMore,
        (Some(&3), Some(&minor)) if minor <= 3 => {}
        _ => return TlsVerdict::No,
    }
    let Some(record_len) = read_len(bytes, 3) else {
        return TlsVerdict::NeedMore;
    };
    if record_len == 0 || record_len > MAX_FRAGMENT {
        return TlsVerdict::No;
    }
    // The handshake header: type, then a 3-byte length that must account for
    // the whole record. THIS is the leg a zenoh unit cannot satisfy by
    // coincidence -- it would have to agree with a number this reader derived
    // from a different byte order in a different field.
    match bytes.get(RECORD_HEADER) {
        None => return TlsVerdict::NeedMore,
        Some(&HS_CLIENT_HELLO) => {}
        Some(_) => return TlsVerdict::No,
    }
    let Some(hs_len) = bytes
        .get(RECORD_HEADER + 1..RECORD_HEADER + 4)
        .map(|b| (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]))
    else {
        return TlsVerdict::NeedMore;
    };
    // A ClientHello may be fragmented across records, in which case the
    // handshake length EXCEEDS this record's payload. Accepting only equality
    // would answer `No` about a legal (if unusual) flow, so the rule is that
    // the handshake must not claim LESS than the record carries: a record with
    // trailing bytes the handshake does not account for is not a ClientHello.
    if (hs_len as usize) + 4 < record_len {
        return TlsVerdict::No;
    }
    TlsVerdict::Yes
}

/// R311y659 (§1.2a) — the ClientHello's 32-byte `Random`, if this direction's
/// opening carries a whole one.
///
/// A SEPARATE question from [`client_hello_verdict`] and not a widening of it.
/// That function's narrowness is load-bearing (R311y649: admitting any
/// handshake-shaped record is what leaves the internal length check with
/// nothing to disagree with), so this one does not decide anything -- it reads
/// a field out of bytes the caller has already decided about.
///
/// The random is what a key log line is keyed by, so it is the ONLY thing that
/// ties a flow in a capture to the secrets in that capture's own Decryption
/// Secrets Block. Without it R311y658's parsed secrets have no way to be
/// selected for a connection.
///
/// ## The offset, and why it is a constant rather than a walk
///
/// RFC 8446 §4.1.2 fixes everything in front of it: a 5-byte record header, a
/// 4-byte handshake header (type + 3-byte length), and the 2-byte
/// `legacy_version`. The random is the next 32 bytes. Nothing before it is
/// variable-length, which is why this is arithmetic and not a parser.
///
/// `None` when the bytes are not all here yet. A ClientHello may be split
/// across records -- rare and legal -- and a capture may simply have stopped;
/// both are "not yet", and returning a partial random would key a connection
/// under something no key log contains.
pub fn client_hello_random(bytes: &[u8]) -> Option<[u8; 32]> {
    const RANDOM_AT: usize = RECORD_HEADER + 4 + 2;
    bytes.get(RANDOM_AT..RANDOM_AT + 32)?.try_into().ok()
}

/// Does this run of bytes walk as a chain of TLS records?
///
/// The second, independent question, and the one that separates a record header
/// from three bytes that happen to look like one: a prefix can be coincidence,
/// a chain of self-declared lengths that lands exactly on the end of the data
/// cannot. `None` when the walk runs out mid-record — which is not `false`,
/// because a captured direction ends wherever the capture stopped.
pub fn carries_tls_records(bytes: &[u8]) -> Option<RecordCensus> {
    let mut census = RecordCensus::default();
    let mut at = 0usize;
    while at < bytes.len() {
        let rest = &bytes[at..];
        if rest.len() < RECORD_HEADER {
            // A partial header at the very end is the ordinary shape of a
            // capture that stopped mid-record.
            census.trailing_bytes = rest.len();
            return Some(census);
        }
        // R311y649 — the SAME rule the flow-level verdict applies, called
        // rather than restated. `rest` is at least a full header here, so the
        // only answers reachable are `Yes` and `No`.
        if prelude_verdict(rest) != TlsVerdict::Yes {
            return None;
        }
        let len = read_len(rest, 3)?;
        if len == 0 || len > MAX_FRAGMENT {
            return None;
        }
        census.records += 1;
        if rest[0] == CT_APPLICATION_DATA {
            census.application_records += 1;
            census.application_bytes += len as u64;
        }
        match rest.len().checked_sub(RECORD_HEADER + len) {
            // The record's payload is not all here yet: the capture stopped
            // inside it. Counted, and the shortfall named.
            None => {
                census.trailing_bytes = rest.len() - RECORD_HEADER;
                return Some(census);
            }
            Some(_) => at += RECORD_HEADER + len,
        }
    }
    Some(census)
}

/// What a walked direction turned out to hold.
///
/// Counted rather than merely recognised, for the reason every other census in
/// this crate is counted: "this flow is encrypted" and "this flow is encrypted
/// and carried 4 MiB of application data in 3000 records" are different
/// findings, and only the second tells a reader what they are missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecordCensus {
    /// Records of every content type.
    pub records: usize,
    /// Records carrying `application_data` — the ones whose plaintext is the
    /// zenoh session.
    pub application_records: usize,
    /// Ciphertext bytes those records carried. NOT the plaintext size: a TLS
    /// 1.3 record's fragment includes the AEAD tag and the inner content type,
    /// so this is an upper bound on the zenoh bytes inside.
    pub application_bytes: u64,
    /// Bytes at the end of the direction that do not complete a record —
    /// where the capture stopped, not a decode failure.
    pub trailing_bytes: usize,
}

impl RecordCensus {
    pub(crate) fn add(&mut self, other: &RecordCensus) {
        self.records += other.records;
        self.application_records += other.application_records;
        self.application_bytes += other.application_bytes;
        self.trailing_bytes += other.trailing_bytes;
    }
}

/// Why a flow this reader recognised as encrypted was not read.
///
/// One variant today and an enum rather than a bool on purpose: the whole point
/// of R311y648 is that "not decrypted" is a statement with a REASON, and the
/// reasons a decryption layer will add — keys for the wrong session, one
/// direction only, a capture that began mid-handshake — are facts a reader acts
/// on differently. A `bool` here would have to be widened by whoever adds them,
/// which is how the reason gets dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotDecrypted {
    /// No key material was supplied to this dissection at all.
    NoKeysSupplied,
}

/// An encrypted flow, as the report shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedFlow {
    /// Per-direction record census, `[A, B]`.
    pub per_direction: [RecordCensus; 2],
    /// Why its plaintext is absent from this report.
    pub not_decrypted: NotDecrypted,
    /// R311y659 (§1.2a) — the ClientHello `Random` this flow opened with, which
    /// is the key a capture's own key log is indexed by.
    ///
    /// `None` where the flow was recognised by its record CHAIN rather than by
    /// a ClientHello -- a mid-session capture or a server-half one -- because
    /// there is no ClientHello in those to read one from.
    pub client_random: Option<[u8; 32]>,
}

impl EncryptedFlow {
    /// Every record both directions carried.
    pub fn totals(&self) -> RecordCensus {
        let mut t = self.per_direction[0];
        t.add(&self.per_direction[1]);
        t
    }
}

/// R311y650 (§1.2a) — every encrypted flow a capture HELD, live or evicted.
///
/// [`crate::Dissection::encrypted_flows`] lists the flows still in the table,
/// which is the right answer for a reader who wants to look at one and the
/// wrong answer for "was any of this capture unreadable": a flow-cap eviction
/// removes the flow and, until this type existed, removed the finding with it.
/// The report then said a flow had been dropped and never said it was
/// ENCRYPTED — R311y648's silence reached through a different door, and the
/// same door R311y605 and R311y610 had already had to close on two other
/// counters.
///
/// A flow is either live or counted here, never both — the invariant
/// [`crate::Dissection::evicted_streams`] states for the stream tally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EncryptedTotals {
    /// How many flows were recognised as carrying zenoh inside TLS.
    pub flows: usize,
    /// Their combined record census, both directions of every flow.
    pub census: RecordCensus,
}

impl EncryptedTotals {
    /// Fold one flow's per-direction census in.
    pub(crate) fn add_flow(&mut self, per_direction: &[RecordCensus; 2]) {
        self.flows += 1;
        self.census.add(&per_direction[0]);
        self.census.add(&per_direction[1]);
    }
}

/// How many chained records [`record_chain_verdict`] needs before it will call
/// a direction encrypted.
///
/// A READING and not a preference, and the falsification is pinned by a test:
/// at depth 1 this module's own control shape — a zenoh unit whose little-endian
/// length prefix reads `[0x16, 0x03]` — answers `Yes`, because ONE record header
/// is exactly the coincidence this module's doc says it is. The second record
/// has to land where the first one's self-declared BIG-endian length puts it,
/// and a stream framed by a different byte order in a different field does not
/// oblige twice.
pub const TLS_CHAIN_DEPTH: usize = 2;

/// What a record header's first three bytes say — answered the moment each byte
/// is PRESENT, never on a byte count.
///
/// The single place the "could this be a record header" rule lives, so the
/// census walk and the flow-level verdict cannot drift into different ideas of
/// what a record looks like.
fn prelude_verdict(rest: &[u8]) -> TlsVerdict {
    match rest.first() {
        None => return TlsVerdict::NeedMore,
        Some(&ct)
            if !matches!(
                ct,
                CT_CHANGE_CIPHER_SPEC | CT_ALERT | CT_HANDSHAKE | CT_APPLICATION_DATA
            ) =>
        {
            return TlsVerdict::No
        }
        Some(_) => {}
    }
    match rest.get(1) {
        None => return TlsVerdict::NeedMore,
        Some(&3) => {}
        Some(_) => return TlsVerdict::No,
    }
    match rest.get(2) {
        None => TlsVerdict::NeedMore,
        Some(&minor) if minor <= 4 => TlsVerdict::Yes,
        Some(_) => TlsVerdict::No,
    }
}

/// R311y649 (§1.2a) — does this direction carry a chain of `depth` TLS records?
///
/// The SECOND, independent route to the same finding, and the one that reaches
/// the captures [`client_hello_verdict`] cannot. A ClientHello is the client's
/// FIRST record: a capture that began mid-session has none, and one taken from a
/// SPAN port on the wrong side of the link has only the server's half. R311y648
/// recognised neither, so both fell through to a zenoh byte-stream reader that
/// read the record header's first two bytes as a little-endian length prefix —
/// measured, on a mid-session fixture, as a decoded `Close` no peer sent, with a
/// `FlowContext` claiming a negotiated session that never happened.
///
/// Three-valued for the reason everything else here is: `NeedMore` is a chain
/// that is consistent so far and shorter than `depth`, and collapsing it into
/// either answer is a decision taken without the evidence. The caller holds.
pub fn record_chain_verdict(bytes: &[u8], depth: usize) -> TlsVerdict {
    let mut at = 0usize;
    let mut records = 0usize;
    loop {
        if records >= depth {
            return TlsVerdict::Yes;
        }
        let rest = &bytes[at.min(bytes.len())..];
        match prelude_verdict(rest) {
            TlsVerdict::Yes => {}
            // Ran out of bytes mid-header — including exactly ON a record
            // boundary, which is a direction that ended where a record ended
            // and is not evidence against the next one.
            TlsVerdict::NeedMore => return TlsVerdict::NeedMore,
            TlsVerdict::No => return TlsVerdict::No,
        }
        let Some(len) = read_len(rest, 3) else {
            return TlsVerdict::NeedMore;
        };
        if len == 0 || len > MAX_FRAGMENT {
            return TlsVerdict::No;
        }
        // The record's own payload is not all here yet: the capture stopped
        // inside it. That is not a broken chain.
        if rest.len() < RECORD_HEADER + len {
            return TlsVerdict::NeedMore;
        }
        records += 1;
        at += RECORD_HEADER + len;
    }
}

/// A big-endian `u16` at `at`, or `None` when the bytes are not there.
fn read_len(bytes: &[u8], at: usize) -> Option<usize> {
    let hi = *bytes.get(at)?;
    let lo = *bytes.get(at + 1)?;
    Some(((hi as usize) << 8) | lo as usize)
}

/// The running record census of one encrypted flow.
///
/// `pub` because [`crate::Framing::Encrypted`] carries it and that enum is the
/// flow's own public shape; its fields stay crate-private, so a consumer reads
/// [`Self::census`] rather than the walk's intermediate state.
#[derive(Debug, Default)]
pub struct TlsFlowState {
    pub(crate) per_direction: [RecordCensus; 2],
    /// Bytes held for a direction whose last record was incomplete.
    pub(crate) pending: [Vec<u8>; 2],
    /// R311y659 (§1.2a) — the ClientHello `Random`, where this flow was
    /// recognised BY its ClientHello.
    ///
    /// `None` for the two capture shapes R311y649 added: a mid-session capture
    /// and a server-half one are recognised by the record chain, and neither
    /// has a ClientHello in it to read. That is a real limit on which flows a
    /// key log can be matched to, and carrying `Option` rather than a sentinel
    /// is what makes a caller say so instead of matching on 32 zero bytes.
    pub(crate) client_random: Option<[u8; 32]>,
}

impl TlsFlowState {
    /// Fold one run of a direction's bytes, keeping whatever tail did not
    /// complete a record so the next run continues the chain rather than
    /// restarting it.
    ///
    /// R311y648 — the tail is HELD and not counted twice: a record split across
    /// two TCP segments is one record, and a census that walked each segment
    /// from its own start would report it as two partial ones.
    pub(crate) fn push(&mut self, index: usize, bytes: &[u8]) {
        let mut run = core::mem::take(&mut self.pending[index]);
        run.extend_from_slice(bytes);
        let Some(census) = carries_tls_records(&run) else {
            // The chain broke. Nothing is counted for this run, and the state
            // keeps no tail -- a direction that stopped being TLS is not a
            // direction whose next bytes continue a record.
            return;
        };
        let consumed = run.len() - census.trailing_bytes;
        let mut counted = census;
        counted.trailing_bytes = 0;
        self.per_direction[index].add(&counted);
        self.pending[index] = run[consumed..].to_vec();
    }

    /// The per-direction census, `[A, B]`, with each direction's unwalked tail
    /// reported as its trailing bytes.
    pub fn census(&self) -> [RecordCensus; 2] {
        let mut out = self.per_direction;
        // The unwalked tail is reported as trailing bytes of the direction it
        // belongs to, so a reader summing the census against the capture's own
        // byte count is not short by a partial record.
        out[0].trailing_bytes = self.pending[0].len();
        out[1].trailing_bytes = self.pending[1].len();
        out
    }
}

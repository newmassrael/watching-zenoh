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

/// R311y661 (§1.2a) — re-exported because [`RecordOpener`] is implemented
/// OUTSIDE this crate, and an implementor should not have to depend on a third
/// crate to name a parameter of the trait it is implementing.
pub use wz_session_core::passive::Direction;

/// TLS content types (RFC 8446 §5.1, RFC 5246 §6.2.1).
pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

/// The handshake message type of a ClientHello (RFC 8446 §4.1.2).
const HS_CLIENT_HELLO: u8 = 1;

/// The handshake message type of a ServerHello (RFC 8446 §4.1.3).
const HS_SERVER_HELLO: u8 = 2;

/// R311y725 (N4) — the NEGOTIATED cipher suite, read out of a ServerHello.
///
/// # Why this is read at all
///
/// [`RecordCensus::application_bytes_at_least`] subtracts each record's AEAD
/// overhead to turn a ciphertext count into a plaintext floor, and until this
/// round it subtracted the LARGEST tag any RFC 8446 suite uses, because the
/// suite was not read. That is a valid floor and a loose one: it understates the
/// plaintext of a `TLS_AES_128_CCM_8_SHA256` connection by 8 bytes per record.
/// The suite is on the wire, in the clear, in the ServerHello — the one
/// handshake message TLS 1.3 leaves unprotected — so this is a measurement
/// rather than an assumption, which is the whole distinction the register
/// carried N4 for.
///
/// # What it deliberately does not do
///
/// It does not decide anything about the flow, on the rule
/// [`client_hello_random`] states for the same reason: recognition is
/// [`client_hello_verdict`]'s job and stays narrow. This reads a field out of a
/// record the caller has already walked.
///
/// `None` for any record that is not a plaintext ServerHello, and for one that
/// is truncated before the field. A ServerHello split across records is legal
/// and rare, and a partial read would report a suite assembled from the wrong
/// bytes — worse than not knowing, because the floor would then be tightened on
/// a guess.
pub fn server_hello_suite(record: &[u8]) -> Option<u16> {
    if *record.first()? != CT_HANDSHAKE {
        return None;
    }
    if *record.get(RECORD_HEADER)? != HS_SERVER_HELLO {
        return None;
    }
    // Everything before the session id is fixed-width (RFC 8446 §4.1.3): the
    // record header, the 4-byte handshake header, `legacy_version`, and the
    // 32-byte random. The session id is the first variable-length field, so
    // this is the last offset that can be arithmetic.
    const SESSION_ID_LEN_AT: usize = RECORD_HEADER + 4 + 2 + 32;
    let session_id_len = usize::from(*record.get(SESSION_ID_LEN_AT)?);
    // RFC 8446 §4.1.3 caps `legacy_session_id_echo` at 32 bytes. A longer one
    // is not a ServerHello this reader can walk, and reading past it would take
    // two bytes of something else as a suite.
    if session_id_len > 32 {
        return None;
    }
    let at = SESSION_ID_LEN_AT + 1 + session_id_len;
    let hi = *record.get(at)?;
    let lo = *record.get(at + 1)?;
    Some((u16::from(hi) << 8) | u16::from(lo))
}

/// R311y725 (N4) — how many bytes of AEAD tag a negotiated suite spends per
/// record.
///
/// 16 for every suite RFC 8446 §B.4 defines except
/// `TLS_AES_128_CCM_8_SHA256`, whose whole point is the truncated tag. An
/// UNKNOWN value also answers 16, and that direction is deliberate: this number
/// is SUBTRACTED to produce a floor, so over-stating it understates the
/// plaintext, which is what a floor must do. Answering 8 for a suite this reader
/// does not know would tighten the floor on a guess.
pub fn aead_tag_bytes(suite: u16) -> u64 {
    match suite {
        // `TLS_AES_128_CCM_8_SHA256`.
        0x1305 => 8,
        _ => 16,
    }
}

/// R311y725 (N4) — what to subtract per record when the suite is NOT known.
///
/// The value [`RecordCensus::application_bytes_at_least`] used unconditionally
/// before the suite was read, kept as a named constant so the two states — a
/// measured suite and no ServerHello in the capture — are the same expression
/// with a different input rather than two formulas.
pub const AEAD_TAG_UNKNOWN: u64 = 16;

/// R311y725 (N4) — the suite's registry name, for a report that shows what the
/// floor was measured against.
///
/// Spelled out rather than derived, and unknown values render as their hex:
/// a suite this build does not know is a finding about the capture, and a name
/// invented for it would be the confident-zero shape this crate refuses
/// elsewhere.
pub fn suite_name(suite: u16) -> Option<&'static str> {
    Some(match suite {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        _ => return None,
    })
}

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
    // R311y725 (N4) — a suite this run learns for itself and then discards. The
    // FLOW keeps one across pushes (`TlsFlowState::suite`); this entry point
    // answers about one buffer and has nowhere to keep it, which is the honest
    // shape: a run holding no ServerHello measures its overhead against the
    // widest tag, exactly as this function always did.
    walk_records(bytes, &mut None, &mut |_, _| {})
}

/// R311y660 (§1.2a) — the walk itself, with each COMPLETE record handed to
/// `on_record` as `(whole_record_including_header, content_type)`.
///
/// One walk and not two. [`carries_tls_records`] is this function with an empty
/// observer, so a census and a decryptor can never come to disagree about where
/// a record starts — the failure `prelude_verdict` was extracted in R311y649 to
/// prevent, one layer up.
///
/// The record is handed on WHOLE, header included, because the header is the
/// AEAD's additional data: a consumer given the fragment alone would have to
/// rebuild five bytes it already had, and a rebuild that disagrees with the
/// wire authenticates nothing.
/// R311y725 (N4) — `suite` is READ AND WRITTEN: the walk learns the negotiated
/// cipher suite from a ServerHello it passes and charges every application
/// record after it the tag that suite actually spends. In and out rather than
/// out alone, because a flow's ServerHello is in one direction and its records
/// are in both, so the caller holds the fact across pushes.
fn walk_records(
    bytes: &[u8],
    suite: &mut Option<u16>,
    on_record: &mut impl FnMut(&[u8], u8),
) -> Option<RecordCensus> {
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
            // R311y725 (N4) — charged HERE, against whatever the walk knows by
            // now, and not recomputed from the record count at read time: a
            // capture whose ServerHello sits in the middle of a direction has
            // records on both sides of it, and only a running total can charge
            // each one what it actually spent. The `+ 1` is the inner content
            // type, which every TLS 1.3 record carries inside the protection.
            let tag = suite.map_or(AEAD_TAG_UNKNOWN, aead_tag_bytes);
            census.aead_overhead_bytes += tag + 1;
        }
        match rest.len().checked_sub(RECORD_HEADER + len) {
            // The record's payload is not all here yet: the capture stopped
            // inside it. Counted, and the shortfall named. NOT handed to the
            // observer: half a record cannot be opened, and handing it on would
            // make a decryptor's failure look like a wrong key.
            None => {
                census.trailing_bytes = rest.len() - RECORD_HEADER;
                return Some(census);
            }
            Some(_) => {
                let record = &rest[..RECORD_HEADER + len];
                // R311y725 (N4) — only a WHOLE record can be read for a suite,
                // which is why this sits in the complete arm. First one wins: a
                // HelloRetryRequest carries the selected suite and the
                // ServerHello that follows carries the same one, so a later
                // read cannot correct an earlier one and could only be a second
                // connection's answer applied to this one.
                if suite.is_none() {
                    *suite = server_hello_suite(record);
                }
                on_record(record, rest[0]);
                at += RECORD_HEADER + len;
            }
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
    /// R311y716 (§E 8.14) — bytes a GAP took out of this direction: what the
    /// hole swallowed, plus the partial record this reader was holding when it
    /// arrived, which goes with it.
    ///
    /// Recorded since R311y666 and, until this round, reaching nothing: the
    /// number was carried onto the next kept record and never left this
    /// module, so the census silently became a floor and every figure beside
    /// it read as a total. A reader summing `application_bytes` against the
    /// capture's own byte count has to be told when the sum cannot add up.
    pub lost_bytes: u64,
    /// R311y725 (N4) — the AEAD overhead this direction's application records
    /// carry, MEASURED against the negotiated suite where the capture holds a
    /// ServerHello and against the widest tag where it does not.
    ///
    /// Accumulated per record rather than derived from
    /// [`Self::application_records`] at read time, because the two cannot be
    /// derived from one another once censuses are FOLDED: two flows in one
    /// capture may negotiate different suites, and a single tag width applied
    /// to the sum would be wrong for at least one of them. A running total of
    /// what each record actually spent adds correctly across any mix.
    pub aead_overhead_bytes: u64,
}

impl RecordCensus {
    /// R311y716 (§E 8.13) — the FLOOR under [`Self::application_bytes`].
    ///
    /// That figure is ciphertext: every TLS 1.3 record's fragment carries an
    /// AEAD tag and the true inner content type inside the protected bytes, so
    /// the zenoh underneath is smaller by both. The report said "N byte(s) of
    /// application data" and meant "at most N", which is a different claim.
    ///
    /// R311y725 (N4) — the tag is now MEASURED where the capture says what it
    /// is. [`AEAD_TAG_UNKNOWN`] (16) is the largest tag among the TLS 1.3
    /// suites, so a capture with no ServerHello in it subtracts the same amount
    /// this function always did — but a capture that carries one subtracts what
    /// that connection actually spends, which for `TLS_AES_128_CCM_8_SHA256` is
    /// 8 bytes per record less. See [`server_hello_suite`].
    ///
    /// Saturating: a direction whose records are all shorter than their own
    /// overhead is a capture this reader misparsed, and a floor of zero is the
    /// honest answer there rather than a wrap.
    pub fn application_bytes_at_least(&self) -> u64 {
        self.application_bytes
            .saturating_sub(self.aead_overhead_bytes)
    }

    pub(crate) fn add(&mut self, other: &RecordCensus) {
        self.records += other.records;
        self.application_records += other.application_records;
        self.application_bytes += other.application_bytes;
        self.trailing_bytes += other.trailing_bytes;
        self.lost_bytes += other.lost_bytes;
        self.aead_overhead_bytes += other.aead_overhead_bytes;
    }
}

/// Why a flow this reader recognised as encrypted was not read.
///
/// An enum rather than a bool on purpose: the whole point of R311y648 is that
/// "not decrypted" is a statement with a REASON, and the reasons a decryption
/// layer adds — keys for the wrong session, a capture that began mid-handshake,
/// a record that refused the keys it was given — are facts a reader acts on
/// differently. A `bool` here would have to be widened by whoever adds them,
/// which is how the reason gets dropped.
///
/// R311y661 (§1.2a) — the four reasons are now DISTINGUISHED rather than
/// collapsed. Until this round every flow reported [`Self::NoKeysSupplied`]
/// unconditionally, including for a capture file that carried a key log in its
/// own Decryption Secrets Block: the report said "no keys supplied" about a file
/// whose keys this reader had parsed and thrown away. Each variant below sends a
/// reader somewhere different — find the keys, recapture from the handshake,
/// find the RIGHT keys, or look at the epoch — and one string for all four sends
/// them to the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotDecrypted {
    /// No key material was supplied to this dissection at all.
    NoKeysSupplied,
    /// R311y661 — keys were supplied and this flow has no identity to select
    /// them by: it was recognised by its record CHAIN, so there is no
    /// ClientHello in the capture and hence no `Random` for a key log to be
    /// indexed by. The mid-session and server-half shapes R311y649 added.
    ///
    /// Distinct from [`Self::NoKeyForSession`] because the remedies differ: this
    /// one is fixed by capturing from the handshake, that one by finding the
    /// right key log.
    NoSessionIdentity,
    /// R311y661 — keys were supplied, this flow has a `Random`, and nothing in
    /// the supplied material is for that session.
    NoKeyForSession,
    /// R311y661 — keys for this session were found and a record did not open
    /// under them, naming the first index that refused.
    ///
    /// The known cause is the epoch: TLS 1.3 restarts the AEAD sequence at zero
    /// on every key change, so a record numbered by its position in the
    /// direction is opened at the wrong sequence once the keys have rotated.
    /// Reporting the index a reader can act on is the honest form; claiming the
    /// keys were wrong would not be.
    RecordRefusedKeys {
        /// The direction the refusing record travelled.
        direction: Direction,
        /// Its [`EncryptedRecord::index`].
        index: u64,
    },
    /// R311y668 (§1.2a) — keys for this session were found and they cover only
    /// ONE of its two directions, so the other's records were never attempted.
    ///
    /// The ordinary cause is a HALF key log: `SSLKEYLOGFILE` written by one of
    /// the two peers gives `CLIENT_TRAFFIC_SECRET_0` and not
    /// `SERVER_TRAFFIC_SECRET_0`, or the reverse, and each secret opens exactly
    /// one direction ([`Direction`]).
    ///
    /// MEASURED before it existed, which is the reason it does: such a flow
    /// reported `RecordRefusedKeys { direction: B, index: 0 }` — a reason whose
    /// documented cause is the EPOCH. It sent a reader to look at key rotation
    /// for a flow whose key was never in the log at all. Every other variant here
    /// names a remedy and this one names a different remedy from the variant it
    /// was folded into: get the other peer's log, not recapture the rotation.
    NoKeyForDirection {
        /// The direction no key material covered.
        direction: Direction,
    },
}

/// An encrypted flow, as the report shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedFlow {
    /// Per-direction record census, `[A, B]`.
    pub per_direction: [RecordCensus; 2],
    /// Why its plaintext is absent from this report, or `None` where it is
    /// PRESENT — every kept record opened and its zenoh frames are in
    /// [`crate::FlowDissection::frames`] like any other flow's.
    ///
    /// R311y661 — an `Option` and not a bare reason, because until this round
    /// the type could not say "decrypted" at all: the field was infallible, so
    /// the report's `"decrypted"` was a hard-coded `false` that no amount of key
    /// material could move.
    pub not_decrypted: Option<NotDecrypted>,
    /// R311y669 (§1.2a) — why each direction's plaintext is absent, `[A, B]`.
    ///
    /// [`Self::not_decrypted`] is the flow's one-word summary and it is the FIRST
    /// refusal met, which for a flow whose two halves fail differently names one
    /// of two remedies. This field is both. `None` for a direction that opened,
    /// and also for one that was never asked — a flow declined at `begin_flow`
    /// has no per-direction answer, and inventing one would claim a record
    /// attempt that never happened.
    pub not_decrypted_per_direction: [Option<NotDecrypted>; 2],
    /// R311y661 — records opened per direction, `[A, B]`.
    ///
    /// Carried beside the reason rather than implied by it: a flow whose keys
    /// rotate opens the records of its first epoch and refuses the rest, so
    /// "some plaintext" is a real state and a reader that inferred zero from a
    /// non-`None` reason would be short by exactly what it did get.
    pub decrypted_records: [usize; 2],
    /// R311y661 — which direction carried the ClientHello, where one did.
    ///
    /// A decryptor needs it and cannot derive it: the client's records open
    /// under `CLIENT_TRAFFIC_SECRET` and the server's under `SERVER_`, so a
    /// consumer without this field is choosing between two secrets by a coin
    /// flip that fails half the time with an authentication error indisting-
    /// uishable from a wrong key log.
    pub client_direction: Option<Direction>,
    /// R311y660 (§1.2a) — the encrypted records this flow kept, `[A, B]`, each
    /// numbered within its direction. What a decryptor opens.
    pub kept_records: [Vec<EncryptedRecord>; 2],
    /// R311y660 — encrypted records dropped per direction to stay inside
    /// [`MAX_KEPT_RECORDS_PER_DIRECTION`]. A decryptor handed this flow cannot
    /// produce the plaintext of a record that is not here, and a report that
    /// did not say so would be short by exactly the traffic a bound consumed.
    pub records_dropped: [usize; 2],
    /// R311y659 (§1.2a) — the ClientHello `Random` this flow opened with, which
    /// is the key a capture's own key log is indexed by.
    ///
    /// `None` where the flow was recognised by its record CHAIN rather than by
    /// a ClientHello -- a mid-session capture or a server-half one -- because
    /// there is no ClientHello in those to read one from.
    pub client_random: Option<[u8; 32]>,
    /// R311y725 (N4) — the cipher suite this flow's ServerHello negotiated, as
    /// the 2-byte registry value on the wire.
    ///
    /// Carried beside the census rather than folded into it, because the two
    /// answer different questions: the census says how tight the plaintext floor
    /// is and this says WHY it is that tight. A reader shown a floor 8 bytes per
    /// record above the old one, with nothing saying which suite bought that,
    /// has a number they cannot check.
    ///
    /// `None` where the capture holds no plaintext ServerHello — the same two
    /// shapes [`Self::client_random`] is `None` for, and for the same reason.
    /// See [`server_hello_suite`] and [`suite_name`].
    pub negotiated_suite: Option<u16>,
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
/// `crate::Dissection::evicted_streams` states for the stream tally.
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

/// R311y660 (§1.2a) — one ENCRYPTED record, kept so it can be opened later.
///
/// Only `application_data` records are kept, and in TLS 1.3 that is every
/// record that carries ciphertext: the true content type moves inside the
/// protected payload and the outer type reads `application_data` even for the
/// handshake messages after the ServerHello.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedRecord {
    /// This record's index among the encrypted records of its direction,
    /// counting from zero.
    ///
    /// ## What this is NOT, stated because the number is easy to misuse
    ///
    /// It is not, by itself, the AEAD sequence number. TLS 1.3 restarts that
    /// sequence at zero every time the keys change, and the boundary is not
    /// visible on the wire: the `Finished` that ends the handshake epoch is
    /// itself encrypted, so a reader without keys cannot see where one epoch
    /// stops. A consumer holding handshake AND application secrets finds the
    /// boundary by TRIAL — the first index that refuses the handshake keys and
    /// accepts the application ones — and the base for each epoch is that
    /// index. Reporting the index and naming the gap is honest; inventing an
    /// epoch boundary this reader cannot see would not be.
    ///
    /// A `ChangeCipherSpec` record never consumes one, which is why the count
    /// is over `application_data` records and not over all of them: CCS is
    /// plaintext middlebox compatibility (RFC 8446 §5) and is not protected.
    pub index: u64,
    /// R311y661 (§1.2a) — where this record's first byte sits in its
    /// direction's REASSEMBLED BYTE STREAM, counted from the first byte the
    /// flow was given.
    ///
    /// ## Why a decryptor needs a second coordinate
    ///
    /// Opening a record produces plaintext, and the zenoh frames decoded out of
    /// that plaintext are offset within the PLAINTEXT stream — a different space
    /// from the TCP one, shorter by every record header and AEAD tag along the
    /// way. [`crate::FlowDissection::packet_for`] resolves an offset against the
    /// TCP-space run map, so a decrypted frame carrying its plaintext offset
    /// would resolve to a packet that is merely nearby, and would do it
    /// silently.
    ///
    /// That is R311y645's defect exactly — a coordinate named for one space and
    /// measured in another — and it is avoided by carrying the record's own
    /// stream offset here, so a frame can be attributed to the record that
    /// carried it and through it to a real packet.
    pub stream_offset: usize,
    /// R311y666 (§1.2a) — bytes this direction LOST between the previous kept
    /// record and this one, from segments the capture never saw.
    ///
    /// ## Why a decryptor cannot do without it
    ///
    /// [`Self::index`] counts records this reader WALKED. The AEAD sequence
    /// number counts records the SENDER protected. A record swallowed by a
    /// dropped segment is never walked, so after a hole the two disagree by
    /// exactly the number of lost records — and every later record is opened at
    /// a nonce that was never used. Measured: a capture missing ONE record of
    /// four opens the two before the hole and refuses everything after it, and
    /// reports `RecordRefusedKeys`, which reads as "wrong key log" about a key
    /// log that is perfect.
    ///
    /// How many records were lost cannot be read off the wire — their boundaries
    /// went with them. But this number BOUNDS it: a TLS 1.3 protected record is
    /// at least [`MIN_PROTECTED_RECORD`] bytes, so at most
    /// `lost_before / MIN_PROTECTED_RECORD` of them fitted in the hole. A
    /// decryptor can therefore search a bounded window and let the AEAD tag say
    /// which offset is right, which is a 128-bit answer rather than a guess.
    ///
    /// `0` on every record of a direction the capture saw whole.
    pub lost_before: u64,
    /// The record, header included, exactly as the wire carried it. The header
    /// is the AEAD's additional data.
    pub bytes: Vec<u8>,
}

/// R311y666 (§1.2a) — the smallest a TLS 1.3 protected record can be.
///
/// A 5-byte header, and a payload that must hold at least the inner content
/// type (1 byte) and the AEAD tag (16 bytes for every suite RFC 8446 defines).
/// Used to bound how many records a hole of a given size could have swallowed.
pub const MIN_PROTECTED_RECORD: u64 = 5 + 1 + 16;

/// R311y661 (§1.2a) — the plaintext of one opened record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedRecord {
    /// The record's INNER content type (RFC 8446 §5.2), recovered from the end
    /// of the protected payload.
    ///
    /// Load bearing and not informational. A TLS 1.3 record's outer type reads
    /// `application_data` for everything after the ServerHello, so a
    /// post-handshake `NewSessionTicket` — which servers send routinely, on the
    /// same connection, at any time — is indistinguishable from session traffic
    /// until it is opened. Feeding its bytes to the zenoh reader would inject a
    /// handshake message into the middle of a length-prefixed stream and desync
    /// everything after it. [`crate::Dissection::decrypt_with`] therefore feeds
    /// only [`CT_APPLICATION_DATA`] onward.
    pub content_type: u8,
    /// The plaintext, with the content type and any padding removed.
    pub plaintext: Vec<u8>,
}

/// R311y661 (§1.2a) — the seam a decryptor is plugged into.
///
/// ## Why this is a trait and not a dependency
///
/// `wz-capture` has zero third-party dependencies by design — its decode path
/// builds for a Cortex-M — and an AEAD is not something this crate will grow or
/// hand-roll. The alternative to inverting the dependency is for this crate to
/// call a cipher crate, which would put ring in every build of the dissector.
///
/// So the flow of control inverts instead: this crate finds the records,
/// numbers them and knows which direction is the client's; the caller supplies
/// something that can open one. `wz-tls-record` implements it over `ring`, and
/// a consumer with a hardware keystore or a different record layer implements
/// the same two methods without this crate learning anything about either.
pub trait RecordOpener {
    /// Announce the flow about to be opened, and answer whether it CAN be.
    ///
    /// Asked once per flow rather than once per record, so a caller holding no
    /// key for the session pays a lookup and not a decryption attempt per
    /// record — and, more importantly, so the reason is stated ONCE and as a
    /// property of the flow, which is what it is.
    ///
    /// `client_direction` is `None` for a flow recognised by its record chain;
    /// an implementation that needs to pick between the client's and the
    /// server's traffic secret cannot serve such a flow and should say so with
    /// [`NotDecrypted::NoSessionIdentity`].
    fn begin_flow(
        &mut self,
        client_random: Option<&[u8; 32]>,
        client_direction: Option<Direction>,
    ) -> Result<(), NotDecrypted>;

    /// Open one record of the flow most recently announced.
    ///
    /// R311y666 — the whole [`EncryptedRecord`] rather than an index and a
    /// slice. It carries the bytes (header included, because the header is the
    /// AEAD's additional data), the index, and — the reason the signature
    /// changed — [`EncryptedRecord::lost_before`], without which a decryptor
    /// cannot tell a record whose sequence jumped from one whose key changed.
    ///
    /// `None` means this record did not open. It is not "no more records": the
    /// caller stops the direction and reports
    /// [`NotDecrypted::RecordRefusedKeys`] naming this index, because a gap in
    /// the middle of a byte stream cannot be skipped over — the bytes after it
    /// no longer begin where the reader thinks they do.
    fn open(&mut self, direction: Direction, record: &EncryptedRecord) -> Option<OpenedRecord>;

    /// R311y668 (§1.2a) — does this opener hold key material for `direction` of
    /// the flow most recently announced?
    ///
    /// A SEPARATE question from [`Self::open`] because the two answers a caller
    /// needs are not the same fact, and folding them cost a reason. `open`
    /// returning `None` means "this record did not authenticate", whose
    /// documented cause is the epoch; a direction with no secret at all also
    /// returns `None` from the first record it is handed, and until this method
    /// existed the caller reported the second as the first — sending a reader to
    /// look at key rotation for a flow whose key was never supplied.
    ///
    /// NO default implementation, deliberately. A `true` default would let an
    /// opener that cannot answer be read as "keys for everything", which is the
    /// silent degradation this project treats as worse than a compile error:
    /// every implementor states its own answer or does not build.
    fn has_keys(&self, direction: Direction) -> bool;
}

impl core::fmt::Debug for EncryptedRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedRecord")
            .field("index", &self.index)
            .field("bytes", &format_args!("<{} byte(s)>", self.bytes.len()))
            .finish()
    }
}

/// R311y660 — the most encrypted records kept per DIRECTION of a flow.
///
/// A bound because everything in this crate is bounded, and this one holds
/// CIPHERTEXT: a busy TLS flow produces records for as long as it runs, and
/// keeping them all would make the memory a capture uses depend on how much of
/// it this reader cannot read. What the bound drops is counted, in the same
/// direction every other loss counter in this crate moves.
pub const MAX_KEPT_RECORDS_PER_DIRECTION: usize = 4096;

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
    /// R311y660 (§1.2a) — the encrypted records this flow kept, per direction,
    /// numbered as they were walked.
    pub(crate) kept: [Vec<EncryptedRecord>; 2],
    /// How many encrypted records each direction has walked, which is what the
    /// NEXT one is numbered with — a counter and not `kept.len()`, because the
    /// bound below drops records and the numbering must not shift when it does.
    pub(crate) next_index: [u64; 2],
    /// Records dropped per direction to stay inside
    /// [`MAX_KEPT_RECORDS_PER_DIRECTION`].
    pub(crate) dropped: [usize; 2],
    /// R311y659 (§1.2a) — the ClientHello `Random`, where this flow was
    /// recognised BY its ClientHello.
    ///
    /// `None` for the two capture shapes R311y649 added: a mid-session capture
    /// and a server-half one are recognised by the record chain, and neither
    /// has a ClientHello in it to read. That is a real limit on which flows a
    /// key log can be matched to, and carrying `Option` rather than a sentinel
    /// is what makes a caller say so instead of matching on 32 zero bytes.
    pub(crate) client_random: Option<[u8; 32]>,
    /// R311y661 (§1.2a) — which direction the ClientHello arrived on, recorded
    /// at the same instant [`Self::client_random`] is.
    ///
    /// The client's records open under a different traffic secret from the
    /// server's, so a decryptor that does not know which side is which has a
    /// coin flip's chance of an authentication failure that looks exactly like
    /// a wrong key log. The flow is the only layer that knows which direction
    /// the hello came in on, and it knew all along — it simply was not writing
    /// it down.
    pub(crate) client_direction: Option<usize>,
    /// R311y661 — where the NEXT byte handed to [`Self::push`] sits in its
    /// direction's reassembled stream, so each kept record can carry its own
    /// [`EncryptedRecord::stream_offset`].
    ///
    /// Advanced by what the walk CONSUMED and by what a hole swallowed, which
    /// is the only way it stays true across one: the bytes after a lost segment
    /// begin further along the stream than the bytes before it ended.
    pub(crate) stream_at: [usize; 2],
    /// R311y661 — what [`crate::Dissection::decrypt_with`] found, or `None`
    /// where no decryption pass has run over this flow.
    ///
    /// `Some(None)` is the fully-opened state and is deliberately distinct from
    /// the outer `None`: "a pass ran and everything opened" and "no pass ran"
    /// are the two findings a report must not merge, because merging them is
    /// how a dissection with no keys at all comes to claim plaintext.
    #[allow(clippy::option_option)]
    pub(crate) outcome: Option<Option<NotDecrypted>>,
    /// R311y669 (§1.2a) — the reason PER DIRECTION, `[A, B]`.
    ///
    /// `outcome` above is one value for a flow with two halves, and it keeps the
    /// FIRST refusal a pass met (`Option::get_or_insert`). R311y668 recorded that
    /// as a narrowing and it is a real one: a flow whose direction A refuses a
    /// record at an epoch boundary and whose direction B has no key at all
    /// reported only A's, so the remedy a reader was given was one of the two it
    /// needed. Nothing is lost now — the summary still answers in one word, and
    /// the two halves are both readable beside it.
    pub(crate) outcome_per_direction: [Option<NotDecrypted>; 2],
    /// R311y661 — records opened per direction by that pass.
    pub(crate) opened: [usize; 2],
    /// R311y666 (§1.2a) — bytes lost since the last KEPT record of each
    /// direction, waiting to be charged to the next one.
    ///
    /// Held here rather than applied at the gap because a hole is announced
    /// between records: what it costs a decryptor is a jump in the sequence of
    /// the NEXT record, and that record is where the fact has to arrive.
    pub(crate) pending_gap_bytes: [u64; 2],
    /// R311y725 (N4) — the cipher suite this flow's ServerHello negotiated.
    ///
    /// One per FLOW and not per direction, which is the only place it can live:
    /// the ServerHello travels in the server's direction and the tag it names is
    /// spent by the records of both. `None` for a capture that holds no
    /// ServerHello — a mid-session capture, or one whose handshake was in a
    /// segment nobody saw — and the census then measures its overhead against
    /// the widest tag, which is what it always did.
    pub(crate) suite: Option<u16>,
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
        // R311y661 — the run begins where the HELD TAIL began, not where this
        // push's bytes did: a record split across two segments starts in the
        // earlier one, and that is the offset it must carry. `stream_at` is
        // maintained as exactly that — the offset of `pending`'s first byte,
        // which is this run's first byte.
        let run_base = self.stream_at[index];
        let mut kept = Vec::new();
        let mut walked = 0usize;
        let Some(census) = walk_records(&run, &mut self.suite, &mut |record, content_type| {
            // Only the protected ones. A `ChangeCipherSpec` is plaintext and
            // consumes no sequence number, so keeping it would put every later
            // record one place too far along.
            if content_type == CT_APPLICATION_DATA {
                kept.push((run_base + walked, record.to_vec()));
            }
            walked += record.len();
        }) else {
            // The chain broke. Nothing is counted for this run, and the state
            // keeps no tail -- a direction that stopped being TLS is not a
            // direction whose next bytes continue a record.
            //
            // R311y661 — the stream position still moves. These bytes were
            // delivered, so the next ones sit after them, and a coordinate that
            // stopped advancing here would put every later record earlier in
            // the stream than it is.
            self.stream_at[index] = run_base + run.len();
            return;
        };
        let consumed = run.len() - census.trailing_bytes;
        let mut counted = census;
        counted.trailing_bytes = 0;
        // R311y716 (§E 8.14) — the gap loss is accumulated HERE, before the
        // line below hands it to one record. `pending_gap_bytes` is `take`n
        // when the first record after the hole is kept, so a census that read
        // only the pending amount reported ZERO for every capture whose gap was
        // followed by anything -- which is every capture where it matters.
        counted.lost_bytes = self.pending_gap_bytes[index];
        self.per_direction[index].add(&counted);
        for (stream_offset, bytes) in kept {
            // The bound is made room for FIRST, and that ordering is what makes
            // the numbering testable rather than merely stated: with the drop
            // taken afterwards, `next_index` and `kept.len()` agree in every
            // reachable state and a numbering read off the LIST would pass
            // every test. Here they diverge the moment the bound bites, and the
            // survivors' numbers are what a decryptor opens them at.
            //
            // The OLDEST goes, on the rule `frames_per_flow` states: a reader
            // looking at a live flow is looking at what just happened.
            if self.kept[index].len() >= MAX_KEPT_RECORDS_PER_DIRECTION {
                self.kept[index].remove(0);
                self.dropped[index] += 1;
            }
            self.kept[index].push(EncryptedRecord {
                index: self.next_index[index],
                stream_offset,
                // R311y666 — charged to the FIRST record after the hole and to
                // no other, which is where the sequence jump actually is.
                lost_before: core::mem::take(&mut self.pending_gap_bytes[index]),
                bytes,
            });
            self.next_index[index] += 1;
        }
        self.pending[index] = run[consumed..].to_vec();
        // The tail that did not complete a record begins `consumed` bytes into
        // this run, and that is where the NEXT run begins.
        self.stream_at[index] = run_base + consumed;
    }

    /// R311y661 (§1.2a) — a hole was announced for one direction: drop the held
    /// tail and step the stream coordinate over what was lost.
    ///
    /// The drop is R311y648's rule (a record is not joined across a gap). The
    /// STEP is this round's: the bytes after a lost segment sit further along
    /// the stream than the bytes before it, so a coordinate that ignored the
    /// hole would name, for every later record, a position occupied by
    /// something else — and `packet_for` would resolve it without complaint.
    pub(crate) fn note_gap(&mut self, index: usize, bytes_missing: u64) {
        let held = core::mem::take(&mut self.pending[index]).len();
        self.stream_at[index] = self.stream_at[index]
            .saturating_add(held)
            .saturating_add(bytes_missing as usize);
        // R311y666 — and the loss is REMEMBERED for the next kept record. The
        // held tail goes with it: those bytes were part of a record this reader
        // will never complete, so whatever the hole did not swallow of it is
        // lost the same way.
        self.pending_gap_bytes[index] = self.pending_gap_bytes[index]
            .saturating_add(bytes_missing)
            .saturating_add(held as u64);
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
        // R311y716 (§E 8.14) — and what a gap took. `pending_gap_bytes` is the
        // amount still WAITING to be attached to a kept record; anything
        // already attached is in `per_direction`, so the two are added rather
        // than one replacing the other.
        out[0].lost_bytes += self.pending_gap_bytes[0];
        out[1].lost_bytes += self.pending_gap_bytes[1];
        out
    }
}

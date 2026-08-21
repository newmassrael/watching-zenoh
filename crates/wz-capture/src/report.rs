// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y615 (§1.1f) — the EXPORT plane: what the analysis planes found, in a
//! form something other than a Rust caller can read.
//!
//! Every plane below this one hands back a typed table. That is the right shape
//! for a consumer inside this workspace and no shape at all for the reader the
//! analyzer exists for: a person comparing two captures, a script watching a
//! number across a fleet, a diff against a stock-zenoh run. Both had to be
//! written by hand at every call site, and a hand-written summary is exactly
//! where a gap counter gets left out.
//!
//! ## The rule this module exists to enforce
//!
//! **A report carries its gaps or it is not a report.**
//!
//! [`crate::agg::ThroughputGaps`] and [`crate::exchange::ExchangeGaps`] were
//! built because a total that is quietly short reads exactly like a total that
//! is right. Serialising the rows and dropping the gaps would undo both in one
//! line — so the gap objects are STRUCTURAL here (always emitted, never
//! conditional on being non-zero), and [`crate::report::CaptureReport::is_complete`] is a
//! single field a consumer can branch on without knowing which planes ran.
//!
//! ## Format
//!
//! JSON, hand-written, because this crate has zero third-party dependencies and
//! a serialiser is thirty lines. The escaping is the part that has to be right
//! rather than short: a keyexpr is attacker-influenced text on the wire, and a
//! writer that emitted it raw would let a publisher choose the shape of this
//! tool's output. `escape_into` handles every character RFC 8259 requires and
//! is pinned character by character in this module's tests.
//!
//! A text rendering sits beside it for the human case. It is deliberately NOT
//! the JSON reformatted: a person wants the heavy keyexprs and whether anything
//! is missing, and a machine wants every field.

use alloc::format;
use alloc::string::{String, ToString};

use crate::agg::{ThroughputGaps, ThroughputTable};

/// R311y708 (§1.2a) — the versions these QUIC flows settled on that NO
/// implementation in this build names, sorted and deduplicated.
///
/// One function rather than a computation inlined into each rendering, because
/// the two renderings must agree about the SET and not merely about whether it
/// is empty — a text line that says `0x6b3343cf` beside a JSON array that says
/// something else is worse than either alone. Both call this.
fn document_only_versions(q: &[crate::quic::QuicCensus]) -> alloc::vec::Vec<u32> {
    let mut v: alloc::vec::Vec<u32> = q
        .iter()
        .filter_map(|c| c.version)
        .filter(|ver| {
            crate::quic::version_source(*ver) == Some(crate::quic::VersionSource::Document)
        })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// R311y718 (§1.2a) — application bytes a decryptor recovered that no zenoh
/// message came out of.
///
/// # Why one function for two callers
///
/// The verdict decides WHETHER to report a shortfall and the rendering says HOW
/// BIG it is, and until this round each computed it: both read
/// `stream_bytes + datagram_bytes`, which agreed only because nothing subtracted
/// anything. The moment a seam exists that reads some of those bytes, two copies
/// of the subtraction is two chances to forget a term — and a verdict that says
/// "whole" over a rendering that names 25 unread bytes is worse than either
/// alone. R311y715 measured that shape five times over in one round: the same
/// fact rendered twice, agreeing by luck.
///
/// # The two terms
///
/// `bytes_fed` is what reached a framer. Everything recovered and not fed is
/// unread because nothing offered it: an RFC 9221 DATAGRAM frame (which carries
/// a batch, not a stream, and has no seam yet), a stream the per-flow bound
/// refused, or a flow the datagram table had already evicted. `bytes_undecoded`
/// is what was fed and stalled — offered is not read, and a capture whose bytes
/// went into a framer that produced nothing is short by them just the same.
fn quic_application_unread(k: &crate::quic::QuicDecryption) -> usize {
    (k.stream_bytes + k.datagram_bytes).saturating_sub(k.framing.bytes_fed)
        + k.framing.bytes_undecoded
}

/// One capture's findings, ready to render.
///
/// Planes are OPTIONAL and named individually rather than recomputed here: a
/// caller that only ran the throughput plane must be able to say so, and a
/// report that silently re-derived a plane would report on data the caller
/// never inspected.
#[derive(Debug, Clone, Copy)]
pub struct CaptureReport<'a> {
    /// R311y714 — the node plane, when the caller built one.
    nodes: Option<&'a crate::node::NodeCensus>,
    /// R311y869 — the interest plane, and its coverage, when the caller built
    /// them.
    ///
    /// The two travel TOGETHER rather than the report re-joining them, because
    /// a coverage is only meaningful against the table it was computed from: a
    /// report that re-derived one could answer "this subscriber covers nothing"
    /// about traffic a selector had removed.
    #[cfg(feature = "network-codecs")]
    interests: Option<(
        &'a crate::interest::InterestCensus,
        &'a crate::interest::Coverage,
    )>,
    dissection: &'a crate::Dissection,
    throughput: Option<&'a ThroughputTable>,
    #[cfg(feature = "network-codecs")]
    exchanges: Option<&'a crate::exchange::ExchangeTable>,
    #[cfg(feature = "network-codecs")]
    payloads: Option<&'a crate::payload::PayloadCensus>,
    /// R311y698 — what a decryptor did with the QUIC flows, if one ran.
    quic: Option<&'a crate::quic::QuicDecryption>,
}

/// R311y870 — what an `Interest` asked for, as the words a reader acts on.
///
/// The kinds and the keyexpr in one phrase because they are one statement:
/// "subscribers under demo/**" is the ask, and a rendering that printed the
/// flag letters and the keyexpr in separate columns would make the reader
/// reassemble it. An UNRESTRICTED interest says so rather than printing an
/// empty keyexpr, which would read as one.
#[cfg(feature = "network-codecs")]
fn interest_scope_words(r: &crate::interest::InterestRequest) -> String {
    let Some(scope) = r.scope else {
        // A Final carries no body. Saying "nothing" would be a claim about
        // what it asked for; it asked for nothing because it is a cancellation.
        return "a cancellation".to_string();
    };
    let mut kinds: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    if scope.keyexprs {
        kinds.push("keyexprs");
    }
    if scope.subscribers {
        kinds.push("subscribers");
    }
    if scope.queryables {
        kinds.push("queryables");
    }
    if scope.tokens {
        kinds.push("tokens");
    }
    if kinds.is_empty() {
        kinds.push("nothing this reader names");
    }
    let what = kinds.join("+");
    let where_ = match (&r.keyexpr, scope.restricted, r.unresolved) {
        (Some(k), _, _) => format!(" under {k}"),
        // R==1 with no resolved keyexpr is an alias this capture never saw
        // bound, which is a different statement from an unrestricted ask.
        (None, true, Some((_, id))) => format!(" under an unresolved alias {id}"),
        (None, true, None) => " under a keyexpr this reader could not read".to_string(),
        (None, false, _) => " (all key expressions)".to_string(),
    };
    let aggregate = if scope.aggregate { ", aggregated" } else { "" };
    format!("{what}{where_}{aggregate}")
}

/// R311y714 — a zid as the hex a reader can match against a config file.
///
/// zenoh prints zids as lowercase hex with no separators and so does this.
fn hex_zid(zid: &[u8]) -> String {
    let mut out = String::with_capacity(zid.len() * 2);
    for b in zid {
        out.push_str(&alloc::format!("{b:02x}"));
    }
    out
}

/// R311y725 (N4) — the cipher suite a capture's encrypted flows negotiated, as
/// one word.
///
/// Three answers and not two, on the rule `reason` states beside its own caller:
/// a capture whose flows agree names the suite, a capture whose flows disagree
/// says `mixed` rather than naming one of them as the capture's, and a capture
/// that holds no ServerHello says `unknown`. A suite this build does not have a
/// registry name for renders as its hex value — a finding about the capture,
/// where an invented name would be a confident zero.
///
/// A flow with no suite does not make the answer `mixed`: not knowing is not
/// disagreeing, and folding the two would say "these flows negotiated different
/// suites" about a capture that simply started mid-session.
fn encrypted_suites(flows: &[crate::tls::EncryptedFlow]) -> String {
    let seen: alloc::collections::BTreeSet<u16> =
        flows.iter().filter_map(|f| f.negotiated_suite).collect();
    let mut it = seen.iter();
    match (it.next(), it.next()) {
        (None, _) => String::from("unknown"),
        (Some(&one), None) => crate::tls::suite_name(one)
            .map(String::from)
            .unwrap_or_else(|| alloc::format!("0x{one:04x}")),
        (Some(_), Some(_)) => String::from("mixed"),
    }
}

/// The handshake's 2-bit role, named.
///
/// Unknown values are printed as themselves rather than mapped to a default:
/// a role this build does not know is a finding about the capture, and
/// "peer" is what an invented default would have said.
fn role_name(w: u8) -> &'static str {
    match w {
        0 => "router",
        1 => "peer",
        2 => "client",
        _ => "unknown",
    }
}

/// R311y716 (§C G1) — one reason a capture's totals are a floor.
///
/// The SSOT for what `complete: false` means. Every leg of the verdict is a
/// variant here, so a leg cannot be added, removed or silently absorbed by a
/// neighbour without this enumeration saying so — which is exactly what
/// R311y715 measured going wrong: nine of the twenty-four guards bound nothing,
/// and a severed one left every test green.
///
/// The names are a WIRE FORMAT: they go out in the export and, through
/// `wz-replay --alert`, onto a live deployment's own bus. Renaming one is a
/// consumer-visible change, not a tidy-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerdictReason {
    /// Packets the reader walked past: traffic in the file and in no row.
    PacketsSkipped,
    /// A bound discarded something rather than the wire losing it.
    BoundsDiscarded,
    /// An encrypted flow this reader could not open.
    EncryptedFlowsUnopened,
    /// A QUIC flow this reader could not open.
    QuicFlowsUnopened,
    /// A QUIC walk that stopped mid-packet, so the frames behind it went
    /// unread.
    QuicWalkStopped,
    /// Application bytes a QUIC decryption pass recovered and nothing decodes.
    QuicBytesNobodyDecodes,
    /// A reassembly chain given up on at this reader's own deadline.
    ExpiredChains,
    /// A chain still open when the capture ended.
    AbandonedChains,
    /// A hole the assembler stepped over rather than waiting on forever.
    GapsForced,
    /// The zenoh framing lost and found again.
    Desyncs,
    /// The WebSocket framing lost and found again.
    WsDesyncs,
    /// Frames the SENDER numbered that this capture does not hold. The wire's
    /// own accounting, which survives a capture with no holes of its own.
    SnMissing,
    /// Bytes of a framing unit that reached no message.
    UnaccountedBatchBytes,
    /// Traffic the throughput plane could not READ.
    ThroughputGaps,
    /// Records read under a keyexpr this capture never saw declared.
    UnresolvedRecords,
    /// Records whose payload this build cannot size.
    UnsizedPayloads,
    /// Records a selector could not judge either way.
    ThroughputUndecided,
    /// Exchanges the query plane could not read.
    ExchangeGaps,
    /// Messages the query plane reached and did not read.
    ExchangeUnread,
    /// Queries this capture never saw answered.
    ExchangesUnclosed,
    /// Exchanges a selector could not judge either way.
    ExchangeUndecided,
    /// Payloads the payload plane could not read.
    PayloadGaps,
    /// Payloads a selector could not judge either way.
    PayloadUndecided,
    /// IP fragment chains that never became a datagram.
    UnfinishedFragmentChains,
    /// Every checksum this reader could verify on a layer FAILED, so nothing
    /// corroborates the headers the rows were built from.
    ChecksumsUncorroborated,
}

impl VerdictReason {
    /// The name this reason is rendered and exported under.
    ///
    /// Spelled out rather than derived from the variant, so a rename of the
    /// Rust identifier does not silently become a rename of the wire name a
    /// consumer matches on.
    pub fn name(self) -> &'static str {
        match self {
            Self::PacketsSkipped => "packets_skipped",
            Self::ChecksumsUncorroborated => "checksums_uncorroborated",
            Self::BoundsDiscarded => "bounds_discarded",
            Self::EncryptedFlowsUnopened => "encrypted_flows_unopened",
            Self::QuicFlowsUnopened => "quic_flows_unopened",
            Self::QuicWalkStopped => "quic_walk_stopped",
            Self::QuicBytesNobodyDecodes => "quic_bytes_nobody_decodes",
            Self::ExpiredChains => "expired_chains",
            Self::AbandonedChains => "abandoned_chains",
            Self::GapsForced => "gaps_forced",
            Self::Desyncs => "desyncs",
            Self::WsDesyncs => "ws_desyncs",
            Self::SnMissing => "sn_missing",
            Self::UnaccountedBatchBytes => "unaccounted_batch_bytes",
            Self::ThroughputGaps => "throughput_gaps",
            Self::UnresolvedRecords => "unresolved_records",
            Self::UnsizedPayloads => "unsized_payloads",
            Self::ThroughputUndecided => "throughput_undecided",
            Self::ExchangeGaps => "exchange_gaps",
            Self::ExchangeUnread => "exchange_unread",
            Self::ExchangesUnclosed => "exchanges_unclosed",
            Self::ExchangeUndecided => "exchange_undecided",
            Self::PayloadGaps => "payload_gaps",
            Self::PayloadUndecided => "payload_undecided",
            Self::UnfinishedFragmentChains => "unfinished_fragment_chains",
        }
    }
}

impl<'a> CaptureReport<'a> {
    /// A report over the dissection alone.
    pub fn of(dissection: &'a crate::Dissection) -> Self {
        Self {
            dissection,
            throughput: None,
            #[cfg(feature = "network-codecs")]
            exchanges: None,
            #[cfg(feature = "network-codecs")]
            payloads: None,
            nodes: None,
            #[cfg(feature = "network-codecs")]
            interests: None,
            quic: None,
        }
    }

    /// R311y698 — include what a QUIC decryptor found.
    ///
    /// Without it this report says the QUIC in the capture was not opened,
    /// which is what happens when nothing opened it. With it the sentence and
    /// the verdict both follow the result — the same shape `with_throughput`
    /// has, and for the same reason: a report must not re-derive a plane the
    /// caller never ran.
    pub fn with_quic_decryption(mut self, quic: &'a crate::quic::QuicDecryption) -> Self {
        self.quic = Some(quic);
        self
    }

    /// Include a throughput table.
    pub fn with_throughput(mut self, table: &'a ThroughputTable) -> Self {
        self.throughput = Some(table);
        self
    }

    /// Include an exchange table.
    #[cfg(feature = "network-codecs")]
    pub fn with_exchanges(mut self, table: &'a crate::exchange::ExchangeTable) -> Self {
        self.exchanges = Some(table);
        self
    }

    /// R311y617 — include a payload census.
    #[cfg(feature = "network-codecs")]
    pub fn with_payloads(mut self, census: &'a crate::payload::PayloadCensus) -> Self {
        self.payloads = Some(census);
        self
    }

    /// R311y714 (§1.1f) — attach the NODE plane: the capture keyed by zid.
    pub fn with_nodes(mut self, census: &'a crate::node::NodeCensus) -> Self {
        self.nodes = Some(census);
        self
    }

    /// R311y869 (§1.1f) — attach the INTEREST plane: who declared what, joined
    /// against the traffic the caller measured.
    ///
    /// Both halves at once, on the rule the field states: the coverage must be
    /// the one computed from the table this report's other planes describe.
    #[cfg(feature = "network-codecs")]
    pub fn with_interests(
        mut self,
        census: &'a crate::interest::InterestCensus,
        coverage: &'a crate::interest::Coverage,
    ) -> Self {
        self.interests = Some((census, coverage));
        self
    }

    /// `true` when nothing anywhere in this report is known to be missing.
    ///
    /// The conjunction of every loss counter the included planes carry, plus
    /// the dissection's own skipped packets. A consumer that treats a total as
    /// the capture's total must consult this first — which is why it is one
    /// field rather than a walk over three structs the caller would have to
    /// know about.
    pub fn is_complete(&self) -> bool {
        self.reasons().is_empty()
    }

    /// R311y716 (§C G1) — EVERY reason this capture's totals are a floor, not
    /// just whether there is one.
    ///
    /// # Why an enumeration replaced the conjunction
    ///
    /// `is_complete` was 24 `return false` guards, and R311y715 severed each in
    /// turn: NINE bound nothing. Two were payable and seven were not, for one
    /// structural reason — the legs are COUPLED. A forced gap desynchronises
    /// the framing behind it, so no fixture trips `gaps_forced` alone, and a
    /// test whose fixture trips two legs proves neither: sever one and the
    /// other still fails the assertion.
    ///
    /// Answering with the SET dissolves that. A fixture that trips two legs
    /// asserts both are named, and severing either one reds — no fixture has to
    /// be surgically isolated, which is what made seven of them unpayable.
    ///
    /// It is also the content an ALERT needs. `false` tells an operator
    /// something is wrong and not what, and a notification that says only
    /// "incomplete" sends them back to the tool they were trying not to run.
    ///
    /// Collected rather than short-circuited: the first reason is not the only
    /// one worth telling, and the cost is a walk over counters already in hand.
    pub fn reasons(&self) -> alloc::vec::Vec<VerdictReason> {
        let mut out = alloc::vec::Vec::new();
        // R311y860 — the BYTES-ABSENT class and not every skip. An Ethernet
        // segment carries ARP, so `packets_skipped > 0` was true of every
        // capture ever taken on one, and a verdict true of everything is not a
        // verdict: it took the exit code with it, since `wz-analyze` returns 1
        // for an incomplete capture. What this leg means, and what the reason's
        // name has always claimed, is that traffic the capture holds is in no
        // row. ARP is not that; a truncated packet is.
        //
        // The furniture is still COUNTED and still RENDERED by
        // `skips_text` / `skips_json` (R311y859). It is not judged.
        if self.dissection.skip_census().bytes_absent() > 0 {
            out.push(VerdictReason::PacketsSkipped);
        }
        // R311y861 — the HELD class is judged HERE and not by the census, and
        // the split is what makes either half honest. R311y860 put
        // `ip_fragment_pending` in `bytes_absent`, which made this verdict fire
        // on ordinary fragmentation: a datagram split in two and reassembled
        // perfectly leaves one held piece behind at the door, every byte of it
        // in a row, and the capture was called a floor for it. The other
        // direction was carried unverified in that round's own carry 3 — a
        // chain that expired out of the table reached no leg at all.
        //
        // One number answers both, because the question is about CHAINS and the
        // census counts PIECES: a chain that completed is not here, and a chain
        // that expired, was evicted, or was still open when the file ended is.
        if self.dissection.unfinished_fragment_chains() > 0 {
            out.push(VerdictReason::UnfinishedFragmentChains);
        }
        // R311y884 (open-debt item 233) — THE CHECKSUM COUNTERS, WHICH WERE
        // RENDERED AND NEVER JUDGED.
        //
        // `valid` / `invalid` / `absent` reach both surfaces and `health` prints
        // all six, but no leg of this verdict read one, so a capture whose every
        // checksum failed reported itself complete. `DissectionHealth` even
        // carries `any_checksum_invalid()`, which nothing called.
        //
        // WHY NOT `invalid > 0`, which is what the helper answers. Checksum
        // OFFLOAD: a host capturing its own transmit path sees the field before
        // the NIC fills it, and those packets are present-and-wrong through no
        // fault of the wire. A verdict on `> 0` would fire on ordinary local
        // captures, which is exactly the defect R311y860 removed from
        // `packets_skipped` — a reason true of almost everything took the exit
        // code with it.
        //
        // The rule is therefore: this reader verified at least one checksum on
        // this layer and NOT ONE of them passed. That is a floor claim rather
        // than a corruption claim, which is what this enumeration is for: with
        // nothing corroborating the headers, the rows built from them cannot be
        // trusted to be all the rows. `absent` is deliberately not counted on
        // either side — IPv6 has no header checksum and a zero UDP checksum is
        // the sender declining (RFC 768), and a capture of either is not
        // uncorroborated, it is unchecked.
        //
        // WHY THE TRANSPORT LAYER AND NOT THE IP HEADER. The IPv4 header
        // checksum covers the HEADER only, is recomputed at every hop, and does
        // not exist in IPv6 — it was removed as redundant. It says nothing about
        // the bytes the rows are built from. The TCP/UDP checksum covers the
        // payload, which is exactly the claim this leg makes, so asking the IP
        // axis would add noise on the layer with the weaker evidence.
        //
        // Reachable only because R311y884 also fixed the fixtures: the packet
        // builders wrote a ZERO checksum, so the corpus sat entirely in the
        // invalid bucket and no rule about it could be written at all.
        let h = self.dissection.health();
        if h.transport_checksum_invalid > 0 && h.transport_checksum_valid == 0 {
            out.push(VerdictReason::ChecksumsUncorroborated);
        }
        if self.dissection.drops().any() {
            out.push(VerdictReason::BoundsDiscarded);
        }
        // R311y648 (§1.2a) — an encrypted flow this reader could not decrypt is
        // a shortfall in the ROWS, on exactly the rule `unsized_payloads`
        // reaches this verdict by: the traffic was there, it is not in the
        // totals, and a reader summing them would otherwise be told the sum is
        // the whole capture. The strongest form of the defect this closes: the
        // flow used to be silent AND the verdict used to say `complete`.
        //
        // R311y650 — asked of the CENSUS and not of the live table. A flow the
        // cap evicted is a flow this reader could not decrypt just the same, and
        // reading the verdict off `encrypted_flows()` made the answer depend on
        // whether the flow was still in the table when the caller asked.
        //
        // R311y664 (§1.2a) — and it asks whether they were OPENED. Until this
        // round any encrypted flow made the capture incomplete, which was right
        // while nothing could decrypt one: the rows were a floor because the
        // session was unreadable. A flow whose every kept record opened is not a
        // shortfall in the rows — its messages ARE the rows — and reporting the
        // capture as incomplete would tell a reader to go looking for traffic
        // that is already in front of them.
        //
        // The census stays the population (R311y650: an evicted flow is one this
        // reader could not open, and reading the verdict off the live table made
        // the answer depend on whether the flow was still in it). What is
        // subtracted is the live flows a decryption pass fully opened, which are
        // by construction still in the table -- a flow that left it took its
        // plaintext with it.
        let enc = self.dissection.encrypted_census().flows;
        let opened = self
            .dissection
            .encrypted_flows()
            .iter()
            .filter(|f| f.not_decrypted.is_none())
            .count();
        if enc > opened {
            out.push(VerdictReason::EncryptedFlowsUnopened);
        }
        // R311y669 (§1.2a) — a QUIC flow reaches the verdict on the same rule an
        // undecrypted TLS flow does: the traffic was there, its zenoh is not in
        // the totals, and this reader opens none of it.
        //
        // R311y698 — and "unless opened" is now reachable, which it was not when
        // that rule was written: the disjunct was unconditional because there was
        // no key path for QUIC at all, and the round that built one has to move
        // this or the verdict says a fully opened capture is incomplete. This is
        // R311y664's change to the TLS half, arriving here for the same reason.
        //
        // The population is the LIVE flows and that is airtight rather than
        // approximate: a QUIC flow the cap evicted took its packets with it, and
        // every eviction increments `drops.flows`, which the first line of this
        // function already reads.
        let quic_flows = self
            .dissection
            .datagram_flows()
            .iter()
            .filter(|f| f.quic.is_some())
            .count();
        if quic_flows > self.quic.map_or(0, |q| q.flows_opened) {
            out.push(VerdictReason::QuicFlowsUnopened);
        }
        // A walk that stopped mid-packet is a shortfall in the rows even where
        // every packet opened: the frames after the stop were not read, so a
        // stream cut short there is reported as one that ended.
        if self.quic.is_some_and(|q| q.walks_stopped > 0) {
            out.push(VerdictReason::QuicWalkStopped);
        }
        // R311y705 (§1.2a) — AND THE APPLICATION BYTES A DECRYPTOR RECOVERED AND
        // NOBODY READ.
        //
        // THE DEFECT THIS CLOSES, and it was asserted as correct behaviour.
        // R311y698 moved this verdict on the argument that "a flow whose every
        // packet opened IS the rows -- its messages ARE the rows". That is true
        // of the TLS half, where `PlaintextSink` hands the recovered plaintext
        // to the session and the rows exist. It is FALSE of QUIC: the pass
        // reassembles the streams, records their LENGTHS, and drops the bytes.
        // Nothing in this workspace decodes zenoh out of them. So the round
        // transplanted a rule to a half that had not earned it, and its own
        // test asserted `complete` over a capture holding 25 recovered
        // application bytes and zero decoded messages.
        //
        // `crypto_bytes` is deliberately NOT here. Those are the TLS handshake
        // inside QUIC -- they carry no zenoh, they are what the key schedule
        // was derived from, and a capture whose handshake was read is not
        // short by them.
        //
        // This is a FLOOR, and it lifts when a decoder exists rather than when
        // someone edits this line: the fix is the seam the TLS half already has
        // (`Dissection::decrypt_with` + `PlaintextSink`), never a second walk of
        // the zenoh stream framing here -- R311y678 measured what a third
        // opinion about where the messages are costs.
        //
        // R311y718 — THE SEAM ARRIVED, exactly where the paragraph above said it
        // would have to (`Dissection::feed_quic_stream`, the QUIC twin of
        // `decrypt_with`), so this now measures what is STILL unread instead of
        // assuming everything is. Two subtractions and not one: bytes nobody
        // offered a framer, plus bytes a framer took and decoded nothing out of.
        // Dropping the second would let this verdict call a capture whole
        // because its bytes reached a stall -- offering is not reading, and a
        // rule that cannot tell those apart is the one this line has already
        // been wrong under once.
        if self.quic.is_some_and(|q| quic_application_unread(q) > 0) {
            out.push(VerdictReason::QuicBytesNobodyDecodes);
        }
        // R311y624 (§1.1m) — the FRAMING witnesses reach the verdict, and until
        // now none of them did. A capture whose assembler gave up on a gap, or
        // whose direction lost the zenoh or WebSocket framing, or whose peer
        // numbered frames this reader never saw, is a capture whose totals are
        // a floor — by exactly the definition the halt counters already answer
        // to. `sn_missing` is the sharpest of the four: it is the only witness
        // that survives a capture with no holes of its own, because it is the
        // WIRE's own accounting of what the sender sent.
        //
        // `reserved_headers` is deliberately NOT here. It counts what ARRIVED
        // and should not have — a peer on a different wire-spec vintage — which
        // is a fact about the sender, not a shortfall in the rows.
        // R311y654 (§1.1f) — a chain this reader ABANDONED on its own deadline
        // is a message the capture carried and the totals do not, which is the
        // definition every witness above reaches this verdict by. The counter
        // was written in R311y594 with the words "COUNTED rather than silent"
        // and then reached no surface at all: not this verdict, not the export,
        // not one test. A capture holding an abandoned chain reported
        // `complete: true` and did not mention it.
        //
        // R311y656 — `evicted_chains` is deliberately NOT a third disjunct here,
        // and that is a measurement rather than an oversight: a chain can only
        // be counted there by an eviction, and every eviction increments
        // `drops.flows`, which the first line of this function already reads. A
        // disjunct nothing can reach is a claim no test can hold, so the number
        // reaches the reader through the export and the page instead.
        if self.dissection.expired_chains() > 0 {
            out.push(VerdictReason::ExpiredChains);
        }
        if self.dissection.abandoned_chains() > 0 {
            out.push(VerdictReason::AbandonedChains);
        }
        let framing = self.dissection.framing_health();
        //
        // R311y631 (§1.2b) — `unaccounted_batch_bytes` DOES reach the verdict,
        // on the same rule that keeps `reserved_headers` out of it: it counts
        // bytes of a framing unit this reader could not attribute to any
        // message, which is a shortfall in the rows and not a fact about the
        // sender. A capture whose batches were walked only part way is a
        // capture whose totals are a floor.
        if framing.gaps_forced > 0 {
            out.push(VerdictReason::GapsForced);
        }
        if framing.desyncs > 0 {
            out.push(VerdictReason::Desyncs);
        }
        if framing.ws_desyncs > 0 {
            out.push(VerdictReason::WsDesyncs);
        }
        if framing.sn_missing > 0 {
            out.push(VerdictReason::SnMissing);
        }
        if framing.unaccounted_batch_bytes > 0 {
            out.push(VerdictReason::UnaccountedBatchBytes);
        }
        if let Some(t) = self.throughput {
            if !t.gaps().is_clean() {
                out.push(VerdictReason::ThroughputGaps);
            }
            if t.unresolved_records() > 0 {
                out.push(VerdictReason::UnresolvedRecords);
            }
            // R311y637 (§1.1w) — a record whose payload this build cannot size
            // makes `total_payload_bytes` a floor, so it reaches the verdict on
            // the same rule as an unread batch. It is NOT a `gaps()` member:
            // the record was read and attributed, and only its byte
            // contribution is unknown. A reader who sums the table still has
            // to be told the sum is short.
            if t.unsized_payloads() > 0 {
                out.push(VerdictReason::UnsizedPayloads);
            }
            // R311y616 — a selector that could not judge part of the capture
            // makes the rows under it a floor, exactly as an unread batch does.
            // The two shortfalls have different causes and the same
            // consequence for a reader summing the table, so they reach the
            // same verdict. An unfiltered report is unaffected: the identity
            // filter leaves nothing undecided.
            if !t.selection().is_decisive() {
                out.push(VerdictReason::ThroughputUndecided);
            }
        }
        #[cfg(feature = "network-codecs")]
        if let Some(e) = self.exchanges {
            if !e.gaps().is_clean() {
                out.push(VerdictReason::ExchangeGaps);
            }
            if !e.unread().is_clean() {
                out.push(VerdictReason::ExchangeUnread);
            }
            if e.unclosed() > 0 {
                out.push(VerdictReason::ExchangesUnclosed);
            }
            // R311y618 — the same rule the throughput plane got in R311y616,
            // reached one plane later: an exchange the selector could not judge
            // is an exchange missing from the rows, and a reader summing them
            // has to be told.
            if !e.selection().is_decisive() {
                out.push(VerdictReason::ExchangeUndecided);
            }
        }
        // R311y617 — the payload plane's own unread counters. A CONTRADICTION
        // is deliberately NOT one of them: a payload that disagrees with its
        // declaration was read perfectly, and calling the capture incomplete
        // because it contains a finding would conflate "I could not see" with
        // "I saw something wrong".
        #[cfg(feature = "network-codecs")]
        if let Some(p) = self.payloads {
            if !p.gaps().is_clean() {
                out.push(VerdictReason::PayloadGaps);
            }
            if !p.selection().is_decisive() {
                out.push(VerdictReason::PayloadUndecided);
            }
        }
        out
    }

    /// Render as JSON.
    ///
    /// Every included plane emits its `gaps` object unconditionally, and the
    /// top level always carries `complete`. A consumer therefore cannot read a
    /// total out of this document without the document also telling it whether
    /// the total is whole.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push('{');
        self.json_fields(&mut s);
        s.push('}');
        s
    }

    /// R311y668 (§1.2a) — the report's top-level keys, WITHOUT the braces that
    /// close the object around them.
    ///
    /// # Why this seam exists
    ///
    /// R311y667 put the analyzer's flow list INSIDE the report object, and did
    /// it by string surgery: pop the rendering's final `}`, append a key, push
    /// `}` back. That was correct for the renderer as it stands and it was not
    /// composition — a report that grew a trailing newline, or a second
    /// top-level form, would fail the `ends_with('}')` guard and take a
    /// fallback that silently produces the TWO-DOCUMENT shape R311y667 existed
    /// to remove. A consumer parsing that stream as one value reads the report
    /// and ignores the flows: this track's own failure mode, arriving through
    /// the output format.
    ///
    /// So the object's inside is nameable, and a caller with more keys to add
    /// writes `{`, this, `,`, its own, `}`. Nothing pops anything, there is no
    /// guard to be wrong about, and there is no fallback to regress into.
    ///
    /// Emits NO leading or trailing comma — the caller owns the separator,
    /// which is the only arrangement in which appending nothing is also valid.
    pub fn json_fields(&self, s: &mut String) {
        self.capture_json(s);
        if let Some(t) = self.throughput {
            s.push(',');
            throughput_json(t, s);
        }
        #[cfg(feature = "network-codecs")]
        if let Some(e) = self.exchanges {
            s.push(',');
            exchanges_json(e, s);
        }
        #[cfg(feature = "network-codecs")]
        if let Some(p) = self.payloads {
            s.push(',');
            payloads_json(p, s);
        }
        // R311y716 (§C G1) — the verdict AND its reasons, computed once and
        // rendered from the one value. `complete` alone tells a consumer that
        // something is wrong and not what, which is the question it goes on to
        // ask; and reading the bool from one call and the list from another
        // would let the two disagree about one capture.
        let reasons = self.reasons();
        s.push_str(",\"complete\":");
        s.push_str(if reasons.is_empty() { "true" } else { "false" });
        s.push_str(",\"reasons\":[");
        for (i, r) in reasons.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            s.push_str(r.name());
            s.push('"');
        }
        s.push(']');
    }

    fn capture_json(&self, s: &mut String) {
        let d = self.dissection;
        let health = d.health();
        let drops = d.drops();
        s.push_str("\"capture\":{");
        s.push_str(&format!(
            "\"stream_flows\":{},\"datagram_flows\":{},\"packets_skipped\":{}",
            d.flows().len(),
            d.datagram_flows().len(),
            health.packets_skipped
        ));
        s.push_str(&format!(
            ",\"retransmits\":{},\"out_of_order\":{},\"partial_overlaps\":{}",
            health.retransmits, health.out_of_order, health.partial_overlaps
        ));
        // R311y665 (§1.2a) — see `decoded_messages`. STRUCTURAL, so a consumer
        // never has to test for the field.
        s.push_str(&format!(",\"messages_decoded\":{}", decoded_messages(d)));
        s.push_str(&format!(
            ",\"ip_checksum_invalid\":{},\"transport_checksum_invalid\":{}",
            health.ip_checksum_invalid, health.transport_checksum_invalid
        ));
        // R311y648 (§1.2a) — STRUCTURAL, like `skips` below: present with zeroes
        // on a plaintext capture, so a consumer never has to test for the key to
        // learn whether part of this capture was unreadable by design. The
        // reason is a STRING and not a flag, because the decryption layer will
        // add reasons a reader acts on differently (wrong session, one
        // direction, mid-handshake start) and a boolean would have to be
        // widened by whoever adds them.
        //
        // R311y650 — over every flow the capture HELD. Summing the live table
        // made these four numbers walk backwards when the flow cap recycled a
        // slot, which is the one direction a census of what a reader COULD NOT
        // see must never move.
        //
        // R311y661 (§1.2a) — `decrypted` and `reason` are now FACTS. Both were
        // constants: `false` was written into the format string, and the reason
        // resolved to `no_keys_supplied` for every flow including one whose keys
        // the capture file itself carried. A decryption pass having run is the
        // only thing that moves either.
        //
        // The census is capture-wide and a reason belongs to a FLOW, so the two
        // are reconciled explicitly rather than by reading the first flow and
        // presenting its reason as the capture's — which is what this did, and
        // is wrong the moment two flows differ. `flows_decrypted` counts, and
        // `reason` is reported only where every undecrypted flow agrees on one.
        let enc = d.encrypted_census();
        let flows = d.encrypted_flows();
        let decrypted = flows.iter().filter(|e| e.not_decrypted.is_none()).count();
        let reasons: alloc::collections::BTreeSet<&'static str> = flows
            .iter()
            .filter_map(|e| e.not_decrypted.map(decryption_reason))
            .collect();
        let reason = match reasons.len() {
            0 => "none",
            1 => reasons.iter().next().copied().unwrap_or("none"),
            // Genuinely differing reasons across flows. A single string here
            // would name one flow's problem as the capture's.
            _ => "mixed",
        };
        // R311y725 (N4) — the suite the plaintext floor was measured against,
        // reconciled to one string by exactly the rule `reason` above uses: it
        // belongs to a FLOW, the census is capture-wide, and presenting the
        // first flow's suite as the capture's is wrong the moment two differ.
        // "unknown" is the honest word for a capture with no ServerHello in it,
        // and it is the state in which the floor stays at its widest.
        let suites = encrypted_suites(&flows);
        s.push_str(&format!(
            ",\"encrypted\":{{\"flows\":{},\"records\":{},\"application_records\":{},\
             \"application_bytes\":{},\"application_bytes_at_least\":{},\
             \"aead_overhead_bytes\":{},\"cipher_suite\":\"{}\",\
             \"lost_bytes\":{},\"decrypted\":{},\"flows_decrypted\":{},\
             \"records_decrypted\":{},\"reason\":\"{}\"}}",
            enc.flows,
            enc.census.records,
            enc.census.application_records,
            // R311y716 (§E 8.13 / 8.14) — the key keeps its name and its
            // meaning: it always was the ceiling. What it gains is a FLOOR
            // beside it and the gap loss that makes both of them short,
            // UNCONDITIONALLY, on the rule this document already follows for
            // `unsized_payloads` -- a consumer that has to test for a key to
            // learn whether a total is whole will not.
            enc.census.application_bytes,
            enc.census.application_bytes_at_least(),
            enc.census.aead_overhead_bytes,
            suites,
            enc.census.lost_bytes,
            // The capture-wide claim, and it is deliberately the STRONG one:
            // "this capture was decrypted" must not be true while part of it
            // was not. `flows_decrypted` beside it carries the partial state.
            decrypted > 0 && decrypted == flows.len(),
            decrypted,
            flows
                .iter()
                .map(|e| e.decrypted_records[0] + e.decrypted_records[1])
                .sum::<usize>(),
            reason
        ));
        // R311y643 (§1.1e) — the skip count above is a number; this is what it
        // MEANS. Structural like `gaps`: present with zeroes on a clean capture,
        // so a consumer's field lookup never depends on this particular file
        // having had that kind of trouble.
        s.push_str(",\"skips\":");
        skips_json(d.skip_census(), s);
        // R311y624 (§1.1m) — the FRAMING witnesses. Every figure below was
        // already computed by the dissection and none of it reached the
        // document, so a reader of the export could not see that a peer had
        // numbered frames this capture never received, that a direction had
        // lost the zenoh framing, or that a WebSocket boundary had gone. The
        // object is STRUCTURAL like `gaps`: present with zeroes on a clean
        // capture, so a consumer's field lookup never depends on whether this
        // particular file happened to have that kind of damage.
        let f = d.framing_health();
        s.push_str(&format!(
            ",\"framing\":{{\"gaps_forced\":{},\"gap_bytes_missing\":{},\
             \"desyncs\":{},\"recoveries\":{},\"resync_skipped_bytes\":{},\
             \"ws_desyncs\":{},\"ws_recoveries\":{},\"ws_resync_skipped_bytes\":{},\
             \"reserved_headers\":{},\"undefined_mandatory_exts\":{},\
             \"unaccounted_batch_bytes\":{}}}",
            f.gaps_forced,
            f.gap_bytes_missing,
            f.desyncs,
            f.recoveries,
            f.resync_skipped_bytes,
            f.ws_desyncs,
            f.ws_recoveries,
            f.ws_resync_skipped_bytes,
            f.reserved_headers,
            f.undefined_mandatory_exts,
            f.unaccounted_batch_bytes
        ));
        s.push_str(&format!(
            ",\"sequence\":{{\"frames\":{},\"missing\":{},\"gaps\":{},\
             \"duplicates\":{},\"out_of_window\":{},\"without_resolution\":{}}}",
            f.sn_frames,
            f.sn_missing,
            f.sn_gaps,
            f.sn_duplicates,
            f.sn_out_of_window,
            f.sn_without_resolution
        ));
        // R311y624 — the pre-session namespace. Counted rather than listed: a
        // scouting message advances no session, so it belongs beside the flow
        // counts and not in any plane.
        s.push_str(&format!(
            ",\"scouting_messages\":{}",
            d.datagram_flows()
                .iter()
                .map(|fl| fl.scouting.len())
                .sum::<usize>()
        ));
        // R311y720 (§D M3) — STRUCTURAL, with a `null` when no serial link type
        // was declared: a consumer branches on the key's VALUE rather than on
        // its presence, which is the rule the `quic` block above follows.
        match d.serial_census() {
            None => s.push_str(",\"serial\":null"),
            Some(k) => s.push_str(&format!(
                ",\"serial\":{{\"interfaces\":{},\"bytes\":{},\"frames\":{},\
                 \"messages\":{},\"crc_failures\":{},\"framing_errors\":{},\
                 \"handshake_frames\":{},\"roles_witnessed\":{},\
                 \"direction_unattributed\":{},\"committed_positionally\":{}}}",
                k.interfaces,
                k.bytes,
                k.frames,
                d.serial_frames().len(),
                k.crc_failures,
                k.framing_errors,
                k.handshake_frames,
                k.roles_witnessed,
                k.direction_unattributed,
                k.committed_positionally,
            )),
        }
        // R311y669 (§1.2a) — QUIC. STRUCTURAL, present with zeroes on a capture
        // that carried none, for the reason `encrypted` is: a consumer must be
        // able to learn that part of a capture was unreadable BY DESIGN without
        // testing for a key. And the reason it is here at all is a measurement —
        // before this round a QUIC capture reported four decoded zenoh messages
        // that did not exist, so the alternative to this block is not silence,
        // it is a wrong answer.
        {
            let q: alloc::vec::Vec<crate::quic::QuicCensus> =
                d.datagram_flows().iter().filter_map(|fl| fl.quic).collect();
            s.push_str(&format!(
                ",\"quic\":{{\"flows\":{},\"packets\":{},\"bytes\":{},\"initial\":{},\
                 \"handshake\":{},\"zero_rtt\":{},\"one_rtt\":{},\"retry\":{},\
                 \"version_negotiation\":{},\"unrecognised\":{},\"declared_flows\":{},\
                 \"declarations_unsupported\":{},\"versions_document_only\":[{}],{}}}",
                q.len(),
                q.iter().map(|c| c.packets).sum::<usize>(),
                q.iter().map(|c| c.bytes).sum::<u64>(),
                q.iter().map(|c| c.initial).sum::<usize>(),
                q.iter().map(|c| c.handshake).sum::<usize>(),
                q.iter().map(|c| c.zero_rtt).sum::<usize>(),
                q.iter().map(|c| c.one_rtt).sum::<usize>(),
                q.iter().map(|c| c.retry).sum::<usize>(),
                q.iter().map(|c| c.version_negotiation).sum::<usize>(),
                q.iter().map(|c| c.unrecognised).sum::<usize>(),
                // R311y670 — how many of those flows are a PREMISE rather than
                // evidence. A consumer that treats a declared flow as a
                // recognised one is treating someone's flag as a measurement.
                q.iter().filter(|c| c.declared).count(),
                // R311y671 — declared flows that carried NOTHING this reader can
                // name as QUIC. The signal for a wrong `--quic` port, and the
                // cost of one is the worst this reader inflicts: real zenoh
                // withheld from the decoder and reported as protected bytes.
                q.iter().filter(|c| c.declaration_unsupported()).count(),
                // R311y708 — the versions among these flows that NO
                // implementation in this build names. Emitted as the SET rather
                // than a count so a consumer can see WHICH word it is: the count
                // says a caveat applies and the word says what to go check.
                document_only_versions(&q)
                    .iter()
                    .map(|v| alloc::format!("\"{v:#010x}\""))
                    .collect::<alloc::vec::Vec<_>>()
                    .join(","),
                // R311y698 — the DECRYPTION result, which was a hard-coded
                // `"decrypted":false` until a caller existed. A literal that
                // cannot change is a field a consumer cannot branch on, and it
                // became a wrong answer the moment this workspace could open a
                // QUIC packet.
                match self.quic {
                    None => alloc::string::String::from("\"decrypted\":false"),
                    Some(k) => format!(
                        "\"decrypted\":{},\"decryption\":{{\"flows_offered\":{},\
                         \"flows_opened\":{},\"packets\":{},\"packets_opened\":{},\
                         \"packets_no_keys\":{},\"packets_refused\":{},\
                         \"crypto_bytes\":{},\"stream_bytes\":{},\
                         \"datagram_bytes\":{},\"walks_stopped\":{},\
                         \"flows_identity_adopted\":{},\
                         \"framing\":{{\"bytes_fed\":{},\"messages\":{},\
                         \"bytes_undecoded\":{},\"streams_refused\":{},\
                         \"flow_absent\":{},\"handshake_offers\":{},\
                         \"appends_not_walked\":{},\
                         \"messages_straddling_offers\":{}}},\
                         \"application_unread\":{}}}",
                        k.flows_opened > 0 && k.flows_opened == k.flows_offered,
                        k.flows_offered,
                        k.flows_opened,
                        k.packets,
                        k.packets_opened,
                        k.packets_no_keys,
                        k.packets_refused,
                        k.crypto_bytes,
                        k.stream_bytes,
                        k.datagram_bytes,
                        k.walks_stopped,
                        k.flows_identity_adopted,
                        // R311y718 — what happened to the recovered bytes once a
                        // framer had them. Emitted rather than left inside the
                        // verdict, because "25 bytes recovered" and "25 bytes
                        // recovered, read, and yielding nothing" are different
                        // findings with different remedies and the byte counter
                        // above cannot tell them apart.
                        k.framing.bytes_fed,
                        k.framing.messages,
                        k.framing.bytes_undecoded,
                        k.framing.streams_refused,
                        k.framing.flow_absent,
                        k.framing.handshake_offers,
                        // R311y749 (N6) — MEASURED MISSING: six of this
                        // struct's fields were emitted and `appends_not_walked`
                        // was not, so the one counter that says a `--fields`
                        // listing is short could not be read by a consumer of
                        // this export at all. `messages_straddling_offers`
                        // lands beside it rather than behind the same silence.
                        k.framing.appends_not_walked,
                        k.framing.messages_straddling_offers,
                        // The number the verdict itself consults, emitted so a
                        // consumer branching on `complete` can see WHY without
                        // re-deriving a subtraction this file owns.
                        quic_application_unread(k),
                    ),
                },
            ));
        }
        // R311y709 (§1.2a) — bytes recovered against bytes handed to a decoder.
        // Emitted UNCONDITIONALLY, and as two numbers plus their difference
        // rather than the difference alone: a consumer given only the difference
        // cannot recover the scale it happened on, and 300 unfed bytes out of
        // 320 is a different report from 300 out of 3 000 000.
        {
            let r = d.byte_residue();
            s.push_str(&alloc::format!(
                ",\"residue\":{{\"recovered\":{},\"fed\":{},\"unfed\":{}}}",
                r.recovered,
                r.fed,
                r.unfed()
            ));
        }
        s.push_str(&format!(
            ",\"drops\":{{\"frames\":{},\"stream_bytes\":{},\"skipped\":{},\"flows\":{},\
             \"scouting\":{},\"scout_askers\":{}}}",
            drops.frames,
            drops.stream_bytes,
            drops.skipped,
            drops.flows,
            // R311y651 (§4.4) — a bound that bites and does not reach the export
            // is a bound that reports itself as the wire, which is the one thing
            // this object exists to prevent.
            drops.scouting,
            drops.scout_askers
        ));
        // R311y714 (§1.1f) — the node plane, in the export. Absent rather
        // than empty when the plane was not built: `"nodes":[]` would say the
        // capture named none, which is a different statement from not asking.
        if let Some(n) = self.nodes {
            s.push_str(",\"nodes\":[");
            for (i, node) in n.nodes().iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                let e = node.evidence;
                s.push_str(&alloc::format!(
                    "{{\"zid\":\"{}\",\"whatami\":{},\"wire_bytes\":{},\
                     \"share_bp\":{},\"init\":{},\"join\":{},\
                     \"hello\":{},\"scout\":{},\"inadmissible\":{},\"flows\":{},\
                     \"locators\":[{}]}}",
                    hex_zid(&node.zid),
                    match node.whatami {
                        Some(w) => alloc::format!("\"{}\"", role_name(w)),
                        None => "null".into(),
                    },
                    node.wire_bytes,
                    match n.share_bp(i) {
                        Some(bp) => alloc::format!("{bp}"),
                        // NULL and not zero: a capture that attributed nothing
                        // has no share to state, and `0` would be a claim.
                        None => "null".into(),
                    },
                    e.init,
                    e.join,
                    e.hello,
                    e.scout,
                    e.inadmissible,
                    node.flows.len(),
                    // A locator is a string a PEER chose and this reader
                    // printed, so it goes through the escaper like every other
                    // wire-sourced field in this module. R311y891.
                    node.locators
                        .iter()
                        .map(|l| quoted(l))
                        .collect::<alloc::vec::Vec<_>>()
                        .join(",")
                ));
            }
            s.push_str(&alloc::format!(
                "],\"node_bytes\":{{\"attributed\":{},\"unattributed\":{}}},\
                 \"node_links\":[",
                n.attributed_bytes(),
                n.unattributed_bytes()
            ));
            for (i, link) in n.links().iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&alloc::format!(
                    "{{\"a\":\"{}\",\"b\":\"{}\"}}",
                    hex_zid(&n.nodes()[link.a].zid),
                    hex_zid(&n.nodes()[link.b].zid)
                ));
            }
            s.push(']');
        }
        // R311y869 (§1.1f) — the interest plane, in the export. Absent rather
        // than empty when the plane was not built, on the node plane's rule
        // above: `"interests":[]` would say the capture carried no declaration.
        #[cfg(feature = "network-codecs")]
        if let Some((census, coverage)) = self.interests {
            s.push_str(",\"interests\":[");
            for (i, interest) in census.interests().iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&alloc::format!(
                    "{{\"kind\":\"{}\",\"declarer\":\"{}\",\"id\":{},\"keyexpr\":{},\
                     \"open\":{},\"covers\":{},\"solicited_by\":{}}}",
                    interest.kind.name(),
                    match interest.declarer {
                        wz_session_core::passive::Direction::A => "a",
                        wz_session_core::passive::Direction::B => "b",
                    },
                    interest.id,
                    match &interest.keyexpr {
                        // ESCAPED: a keyexpr is the attacker-influenced text
                        // this module's own doc names, and it reached this
                        // field raw until R311y891.
                        Some(k) => quoted(k),
                        // NULL and not "": a declaration this reader could not
                        // name is a finding, and the empty string is a keyexpr.
                        None => "null".into(),
                    },
                    interest.is_open(),
                    coverage
                        .matched
                        .iter()
                        .find(|m| m.interest == i)
                        .map(|m| m.keys.len())
                        .unwrap_or(0),
                    // NULL and not 0: id 0 is a legal interest id, and an
                    // UNSOLICITED declaration is a contract state rather than
                    // an absent field.
                    match interest.solicited_by {
                        Some(id) => alloc::format!("{id}"),
                        None => "null".into(),
                    },
                ));
            }
            s.push_str(&alloc::format!(
                "],\"interest_coverage\":{{\"judged\":{},\"silent\":{},\
                 \"undecidable\":{},\"unresolved\":{},\"unclaimed\":{},\
                 \"unclaimed_exact\":{},\"orphan_withdrawals\":{}}}",
                coverage.judged(),
                coverage.silent.len(),
                coverage.undecidable.len(),
                coverage.unresolved.len(),
                coverage.unclaimed.len(),
                coverage.unclaimed_exact,
                census.orphan_withdrawals(),
            ));
            // R311y870 — the QUESTION half. STRUCTURAL: present with an empty
            // array whenever the plane was built, so a consumer's field lookup
            // does not depend on whether this capture happened to carry an
            // Interest.
            s.push_str(",\"interest_requests\":[");
            for (i, r) in census.requests().iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&alloc::format!(
                    "{{\"asker\":\"{}\",\"id\":{},\"mode\":\"{}\",\"answers\":{},\
                     \"mismatched\":{},\"unjudged_answers\":{},\
                     \"answers_in_scope\":{},\
                     \"closed\":{},\"cancelled\":{},\"keyexpr\":{},\
                     \"asks\":{{\"keyexprs\":{},\"subscribers\":{},\
                     \"queryables\":{},\"tokens\":{},\"restricted\":{},\
                     \"aggregate\":{}}}}}",
                    match r.asker {
                        wz_session_core::passive::Direction::A => "a",
                        wz_session_core::passive::Direction::B => "b",
                    },
                    r.id,
                    r.mode.name(),
                    r.answers,
                    r.mismatched.len(),
                    r.unjudged_answers,
                    r.answers_in_scope(),
                    r.closed_at.is_some(),
                    r.cancelled_at.is_some(),
                    match &r.keyexpr {
                        // ESCAPED, for the reason the declaration plane above
                        // states. R311y891.
                        Some(k) => quoted(k),
                        None => "null".into(),
                    },
                    r.scope.is_some_and(|s| s.keyexprs),
                    r.scope.is_some_and(|s| s.subscribers),
                    r.scope.is_some_and(|s| s.queryables),
                    r.scope.is_some_and(|s| s.tokens),
                    r.scope.is_some_and(|s| s.restricted),
                    r.scope.is_some_and(|s| s.aggregate),
                ));
            }
            s.push_str(&alloc::format!(
                "],\"interest_exchange\":{{\"unanswered\":{},\"unclosed\":{},\
                 \"mismatched\":{},\"unjudged_answers\":{},\
                 \"orphan_answers\":{}}}",
                census.unanswered().len(),
                census.unclosed().len(),
                census.mismatched().len(),
                census.unjudged_answers(),
                census.orphan_answers(),
            ));
        }
        // R311y713 (§B10) — the same census the text renders, in the export.
        // One fact rendered in two places is one fact that can drift, so the
        // test asserts BOTH in one run.
        {
            let c = d.dropped_frame_census();
            s.push_str(&alloc::format!(
                ",\"dropped_frames\":{{\"total\":{},\"init\":{},\"open\":{},\
                 \"close\":{},\"keep_alive\":{},\"frame\":{},\"fragment\":{},\
                 \"join\":{},\"unknown\":{},\"undecodable\":{}}}",
                c.total(),
                c.init(),
                c.open(),
                c.close(),
                c.keep_alive(),
                c.frame(),
                c.fragment(),
                c.join(),
                c.unknown(),
                c.undecodable()
            ));
        }
        // The figure the CAPTURE FILE reports about itself, which is a
        // different claim from anything this reader counted: `null` when the
        // format carried none, never 0.
        // R311y654 (§1.1f) — STRUCTURAL like `skips` and `encrypted`: present
        // with a zero on a build that reassembles nothing, so a consumer's
        // field lookup never depends on which features this binary carries.
        s.push_str(&format!(
            ",\"reassembly\":{{\"expired_chains\":{},\"abandoned_at_end\":{},\
             \"abandoned_on_eviction\":{}}}",
            d.expired_chains(),
            d.abandoned_chains(),
            d.evicted_chains()
        ));
        s.push_str(",\"capture_reported_drops\":");
        s.push_str(&opt_u64(d.capture_reported_drops()));
        s.push('}');
    }

    /// Render for a human.
    ///
    /// Leads with the completeness verdict rather than burying it: the first
    /// line a reader sees says whether the numbers under it are the whole
    /// capture.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        let d = self.dissection;
        let health = d.health();
        // R311y716 (§C G1) — the reasons ride on the same line as the verdict.
        // A reader told only "INCOMPLETE" has to walk every plane below to find
        // out which one is short, and the walk is the work this line exists to
        // save them.
        let reasons = self.reasons();
        if reasons.is_empty() {
            s.push_str("capture: complete\n");
        } else {
            s.push_str(&format!(
                "capture: INCOMPLETE -- totals below are a floor, not the whole \
                 capture ({})\n",
                reasons
                    .iter()
                    .map(|r| r.name())
                    .collect::<alloc::vec::Vec<_>>()
                    .join(", ")
            ));
        }
        s.push_str(&format!(
            "  flows: {} stream, {} datagram; packets skipped: {}\n",
            d.flows().len(),
            d.datagram_flows().len(),
            health.packets_skipped
        ));
        // R311y665 (§1.2a) — HOW MANY MESSAGES THIS READER DECODED, which no
        // line of this report said. `sequence` below counts frames that carry a
        // sequence NUMBER, and a KeepAlive does not carry one -- so a capture
        // whose whole session is KeepAlives reported zero everywhere while
        // holding three decoded messages. That is R311y648's silence in the one
        // place it had not been closed: the summary of what WAS read.
        s.push_str(&format!("  messages decoded: {}\n", decoded_messages(d)));
        // R311y714 (§1.1f) — the capture's NODES, when the caller built the
        // plane. Printed as an inventory rather than a drawing: the shipped
        // artifact draws it, and what this reader owes is the evidence behind
        // each vertex and edge.
        if let Some(n) = self.nodes {
            s.push_str(&format!(
                "  nodes: {} (links {}); unit bytes attributed {}, \
                 unattributed {}\n",
                n.nodes().len(),
                n.links().len(),
                n.attributed_bytes(),
                n.unattributed_bytes()
            ));
            for (i, node) in n.nodes().iter().enumerate() {
                let e = node.evidence;
                s.push_str(&format!(
                    "    {} role {} -- share {}.{:02}%, init {}, join {}, \
                     hello {}, scout {}, inadmissible {}, flows {}\n",
                    hex_zid(&node.zid),
                    match node.whatami {
                        Some(w) => role_name(w),
                        None => "unstated",
                    },
                    n.share_bp(i).unwrap_or(0) / 100,
                    n.share_bp(i).unwrap_or(0) % 100,
                    e.init,
                    e.join,
                    e.hello,
                    e.scout,
                    e.inadmissible,
                    node.flows.len()
                ));
                // R311y714 — where it said it can be reached, when it said so.
                // Absent rather than an empty bracket for a node that never
                // advertised: the two are different facts.
                if !node.locators.is_empty() {
                    s.push_str(&format!("      at {}\n", node.locators.join(", ")));
                }
            }
            for link in n.links() {
                s.push_str(&format!(
                    "    link {} <-> {}\n",
                    hex_zid(&n.nodes()[link.a].zid),
                    hex_zid(&n.nodes()[link.b].zid)
                ));
            }
        }
        // R311y869 (§1.1f) — WHO ASKED FOR THE TRAFFIC. Printed when the
        // caller built the plane, whatever it found: a capture with no
        // declaration at all is itself the answer to "is anything subscribed
        // here", and suppressing the block on an empty census would make the
        // one deployment a reader most needs told about look like the one they
        // did not ask about.
        #[cfg(feature = "network-codecs")]
        if let Some((census, coverage)) = self.interests {
            let by = census.by_kind();
            s.push_str(&format!(
                "  declared interest: {} (subscriber {}, queryable {}, \
                 liveliness {}); judged {}, silent {}\n",
                census.interests().len(),
                by[0],
                by[1],
                by[2],
                coverage.judged(),
                coverage.silent.len(),
            ));
            for m in &coverage.matched {
                let i = &census.interests()[m.interest];
                s.push_str(&format!(
                    "    {} {} covers {} key(s), {} message(s), {} byte(s){}\n",
                    i.kind.name(),
                    i.keyexpr.as_deref().unwrap_or("<unresolved>"),
                    m.keys.len(),
                    m.totals.messages(),
                    m.totals.payload_bytes,
                    if i.is_open() { "" } else { "  [withdrawn]" },
                ));
            }
            // THE FINDING, and it leads with the word a reader acts on. A
            // declaration nobody published under is a deployment that believes
            // it is receiving something.
            for at in &coverage.silent {
                let i = &census.interests()[*at];
                s.push_str(&format!(
                    "    FINDING: {} {} matched NO traffic in this capture\n",
                    i.kind.name(),
                    i.keyexpr.as_deref().unwrap_or("<unresolved>"),
                ));
            }
            // The mirror finding, and it is stated as a FLOOR whenever any
            // declaration could not be judged — see `Coverage::unclaimed`.
            if !coverage.unclaimed.is_empty() {
                s.push_str(&format!(
                    "    {} keyexpr(s) carried traffic no declaration here \
                     matches{}\n",
                    coverage.unclaimed.len(),
                    if coverage.unclaimed_exact {
                        ""
                    } else {
                        " (AT MOST -- some declaration could not be judged)"
                    },
                ));
            }
            // Held apart from `silent` in the rendering as well as in the
            // type: "this build cannot tell" must never read as "nobody
            // subscribed".
            if !coverage.undecidable.is_empty() {
                s.push_str(&format!(
                    "    {} declaration(s) carry a wildcard this build's \
                     matcher cannot evaluate (feature `filter-wildcards`)\n",
                    coverage.undecidable.len()
                ));
            }
            if !coverage.unresolved.is_empty() {
                s.push_str(&format!(
                    "    {} declaration(s) name a keyexpr alias this capture \
                     never saw bound\n",
                    coverage.unresolved.len()
                ));
            }
            if census.orphan_withdrawals() > 0 {
                s.push_str(&format!(
                    "    {} undeclare(s) for a declaration this capture never \
                     saw -- the list above is a floor\n",
                    census.orphan_withdrawals()
                ));
            }
            // R311y870 — the QUESTION half. Printed under the same heading
            // because a reader asking "who wanted this" is asking one question,
            // and splitting the ask from the answer across two blocks is how a
            // reader concludes the two are unrelated.
            if !census.requests().is_empty() {
                s.push_str(&format!(
                    "  interest requests: {}\n",
                    census.requests().len()
                ));
                for r in census.requests() {
                    s.push_str(&format!(
                        "    {} interest {} for {} -- {} answer(s), {}{}\n",
                        r.mode.name(),
                        r.id,
                        interest_scope_words(r),
                        r.answers,
                        if r.closed_at.is_some() {
                            "closed"
                        } else {
                            "not closed"
                        },
                        if r.cancelled_at.is_some() {
                            ", cancelled by the asker"
                        } else {
                            ""
                        },
                    ));
                }
                for at in census.unanswered() {
                    let r = &census.requests()[at];
                    s.push_str(&format!(
                        "    FINDING: interest {} for {} got NO answer at all\n",
                        r.id,
                        interest_scope_words(r),
                    ));
                }
                for at in census.unclosed() {
                    let r = &census.requests()[at];
                    s.push_str(&format!(
                        "    FINDING: interest {}'s current dump never closed -- \
                         its {} answer(s) are a floor\n",
                        r.id, r.answers,
                    ));
                }
                // R311y871 — the answer that was not an answer. Upstream sends
                // neither an out-of-scope keyexpr nor an unasked kind, so this
                // line is about the PEER and not about this reader's limits --
                // which is why the unjudged floor below is a separate sentence
                // rather than a qualifier on this one.
                for at in census.mismatched() {
                    let r = &census.requests()[at];
                    s.push_str(&format!(
                        "    FINDING: interest {} for {} was answered with {} \
                         declaration(s) it did not ask for\n",
                        r.id,
                        interest_scope_words(r),
                        r.mismatched.len(),
                    ));
                    for d in &r.mismatched {
                        let i = &census.interests()[*d];
                        s.push_str(&format!(
                            "      {} {}\n",
                            i.kind.name(),
                            i.keyexpr.as_deref().unwrap_or("<unresolved>"),
                        ));
                    }
                }
                if census.unjudged_answers() > 0 {
                    s.push_str(&format!(
                        "    {} answer(s) could not be judged against what was \
                         asked -- the findings above are a floor\n",
                        census.unjudged_answers()
                    ));
                }
                if census.orphan_answers() > 0 {
                    s.push_str(&format!(
                        "    {} declaration(s) answer an interest this capture \
                         never saw asked -- the list above is a floor\n",
                        census.orphan_answers()
                    ));
                }
            }
        }
        // R311y713 (§B10) — and WHAT the per-flow bound discarded, when it
        // discarded anything. A count alone leaves a reader unable to tell a
        // trim of a hundred keepalives from one that took the `Close` the
        // capture is being read to explain. Printed only when the bound bit,
        // for the reason the skip line above is: a zero here is furniture.
        {
            let c = d.dropped_frame_census();
            if c.total() > 0 {
                s.push_str(&format!(
                    "  frames discarded by frames_per_flow: {} \
                     (init {}, open {}, close {}, keepalive {}, frame {}, \
                     fragment {}, join {}, unknown {}, undecodable {})\n",
                    c.total(),
                    c.init(),
                    c.open(),
                    c.close(),
                    c.keep_alive(),
                    c.frame(),
                    c.fragment(),
                    c.join(),
                    c.unknown(),
                    c.undecodable()
                ));
            }
        }
        // R311y643 (§1.1e) — the line that turns a skip COUNT into a
        // diagnosis, and it leads with the link types because that is the
        // reason with the loudest consequence: it means the file was never
        // read. Printed only when this build refused a link type at all.
        //
        // R311y859 CORRECTS what this comment used to assert — that "every
        // other skip is furniture in an otherwise-readable capture". Three of
        // the remaining eight are. The other five (`truncated`, both fragment
        // counters, `ip_fragment_pending`, `ipv6_extension_chain`) each mean
        // BYTES THE CAPTURE HOLDS ARE ABSENT from this dissection, and folding
        // them into an unnamed total is how a reader concludes a short capture
        // was whole. The breakdown below is printed whenever anything was
        // skipped at all, which is the same qualifier every other line here
        // uses; the belief that it was not needed is why it took this long.
        let sk = d.skip_census();
        if !sk.is_empty() {
            skips_text(sk, &mut s);
        }
        // The link types and their count are named by `skips_text` above; what
        // stays here is the CONSEQUENCE, which is a judgement about this
        // capture rather than a counter, and which the health document has no
        // place for. Printing the identity a third time would be three
        // spellings of one fact in one document.
        if !sk.unsupported_link_types.is_empty() {
            s.push_str(
                "  this capture was not dissected: its link type is not \
                 decapsulated by this build\n",
            );
        }
        // R311y648 (§1.2a) — the line that stops an encrypted capture reading
        // as an idle one. Printed only when there IS such a flow, like every
        // other qualifier here; a plaintext capture is not told about a hazard
        // it does not have.
        //
        // R311y650 — the census, for the reason the JSON beside it uses one: a
        // person reading a capture whose encrypted flow was evicted was shown a
        // dropped-flow count and no hint that the traffic was TLS, which is the
        // idle-looking capture this line exists to prevent.
        //
        // R311y664 (§1.2a) — and it says WHICH of the two happened. R311y661
        // made the JSON's `decrypted` a fact and left this line stating
        // "NOT DECRYPTED (no keys supplied)" unconditionally, so the two
        // renderings of one report disagreed about the same capture — and this
        // is the one a person reads. Found by running the binary R311y664 added:
        // the JSON said `"decrypted":true` and the text said the session could
        // not be seen into, about the same file, in the same run.
        let enc = d.encrypted_census();
        if enc.flows > 0 {
            let live = d.encrypted_flows();
            let opened = live.iter().filter(|f| f.not_decrypted.is_none()).count();
            let records: usize = live
                .iter()
                .map(|f| f.decrypted_records[0] + f.decrypted_records[1])
                .sum();
            // R311y716 (§E 8.13) — a RANGE, not a figure. `application_bytes`
            // is ciphertext: the AEAD tag and the inner content type are inside
            // it, so stating it alone told a reader they were missing more
            // zenoh than they are. The floor is what remains once this reader
            // subtracts the per-record overhead.
            //
            // R311y725 (N4) — and the sentence now says WHAT that overhead was
            // measured against. It used to end "without knowing the suite",
            // which was true and is no longer: a capture holding a plaintext
            // ServerHello has the suite on the wire, and a reader shown a
            // tightened floor with nothing naming its basis has a number they
            // cannot check.
            s.push_str(&format!(
                "  {} flow(s) carry zenoh inside TLS: {} record(s), {}-{} byte(s) \
                 of application data (the upper figure is ciphertext; the lower \
                 subtracts {} byte(s) of AEAD overhead, suite {}).",
                enc.flows,
                enc.census.records,
                enc.census.application_bytes_at_least(),
                enc.census.application_bytes,
                enc.census.aead_overhead_bytes,
                encrypted_suites(&live),
            ));
            // R311y716 (§E 8.14) — and what a gap took, printed only when it
            // happened: a census short by a hole is a floor, and until this
            // round it said so nowhere.
            if enc.census.lost_bytes > 0 {
                s.push_str(&format!(
                    " {} byte(s) of it went with a gap and are not in those \
                     figures.",
                    enc.census.lost_bytes
                ));
            }
            if opened == 0 {
                s.push_str(
                    " NOT DECRYPTED -- the session is there and this report \
                     cannot see into it",
                );
            } else {
                s.push_str(&format!(
                    " DECRYPTED: {opened} flow(s), {records} record(s) opened; \
                     their messages are in the rows above"
                ));
                if opened < live.len() {
                    s.push_str(&format!(" ({} flow(s) were not)", live.len() - opened));
                }
            }
            if let Some(reason) = live.iter().find_map(|f| f.not_decrypted) {
                s.push_str(&format!(" [{}]", decryption_reason(reason)));
            }
            s.push('\n');
        }
        // R311y654 (§1.1f) — and the bound this reader applied to ITSELF, which
        // no other line here reports. Every other qualifier names something the
        // wire or the capture tool did; this one names a message the analyzer
        // gave up on, and a reader who is not told cannot distinguish it from a
        // message that was never sent.
        if d.evicted_chains() > 0 {
            s.push_str(&format!(
                "  {} reassembly chain(s) went with a flow the flow cap evicted; \
                 raising max_flows_per_table is what would have kept them\n",
                d.evicted_chains()
            ));
        }
        if d.abandoned_chains() > 0 {
            s.push_str(&format!(
                "  {} reassembly chain(s) still OPEN when the capture ended; the \
                 messages they carried are absent from the totals below and no \
                 deadline would have changed that\n",
                d.abandoned_chains()
            ));
        }
        if d.expired_chains() > 0 {
            s.push_str(&format!(
                "  {} reassembly chain(s) ABANDONED on this reader's own \
                 deadline; the messages they carried are absent from the totals \
                 below\n",
                d.expired_chains()
            ));
        }
        // R311y861 — the IP-FRAGMENT chains, which the three lines above are
        // NOT about: those count zenoh's own fragmentation inside a session,
        // and these count datagrams IP split on the way. The verdict fires on
        // this family, and until this round no line of this document carried
        // the number it fires on — a reader told `unfinished_fragment_chains`
        // had nowhere to go and look at it.
        //
        // ONE LINE PER END, printed only when non-zero, because the three are
        // three different things for an operator to do: widen the window, raise
        // the cap, or capture for longer. The verdict sums them; this is where
        // the sum is taken apart.
        let frag = d.fragment_stats();
        if frag.expired > 0 {
            s.push_str(&format!(
                "  {} IP datagram(s) ABANDONED on this reader's reassembly \
                 deadline; raising reassembly_window_ms is what would have \
                 kept them\n",
                frag.expired
            ));
        }
        if frag.evicted > 0 {
            s.push_str(&format!(
                "  {} IP datagram(s) dropped to stay inside \
                 max_pending_fragments; raising it is what would have kept \
                 them\n",
                frag.evicted
            ));
        }
        if d.open_fragment_chains() > 0 {
            s.push_str(&format!(
                "  {} IP datagram(s) still half-assembled when the capture \
                 ended; the rest of their pieces is not in this file and no \
                 bound of this reader's would have changed that\n",
                d.open_fragment_chains()
            ));
        }
        // R311y624 (§1.1m) — printed ONLY when non-zero, unlike the JSON object
        // beside it. The two formats answer different readers: a consumer
        // parses fields and needs them present unconditionally, a person reads
        // lines and a row of zeroes on every clean capture is noise that trains
        // the eye to skip the section.
        let f = d.framing_health();
        if f.desyncs > 0
            || f.gaps_forced > 0
            || f.reserved_headers > 0
            || f.undefined_mandatory_exts > 0
            || f.unaccounted_batch_bytes > 0
        {
            s.push_str(&format!(
                "  framing: {} desync(s), {} recovered ({} bytes stepped over); \
                 {} forced gap(s) ({} bytes); {} reserved-flag header(s); \
                 {} undefined-mandatory-extension frame(s); \
                 {} byte(s) of a batch left unaccounted for\n",
                f.desyncs,
                f.recoveries,
                f.resync_skipped_bytes,
                f.gaps_forced,
                f.gap_bytes_missing,
                f.reserved_headers,
                f.undefined_mandatory_exts,
                f.unaccounted_batch_bytes
            ));
        }
        if f.ws_desyncs > 0 {
            s.push_str(&format!(
                "  websocket framing: {} desync(s), {} recovered ({} bytes)\n",
                f.ws_desyncs, f.ws_recoveries, f.ws_resync_skipped_bytes
            ));
        }
        if f.sn_missing > 0 || f.sn_duplicates > 0 || f.sn_out_of_window > 0 {
            s.push_str(&format!(
                "  sequence: {} of {} frame(s) never seen across {} gap(s); \
                 {} duplicate(s), {} out of window, {} unjudgeable\n",
                f.sn_missing,
                f.sn_frames,
                f.sn_gaps,
                f.sn_duplicates,
                f.sn_out_of_window,
                f.sn_without_resolution
            ));
        }
        let scouting: usize = d.datagram_flows().iter().map(|fl| fl.scouting.len()).sum();
        if scouting > 0 {
            s.push_str(&format!("  scouting: {scouting} message(s)\n"));
        }
        // R311y720 (§D M3) — the declared SERIAL line. Printed only when one
        // was declared AND something arrived on it, which is the distinction
        // `serial_census`'s `Option` carries: a capture with no serial in it
        // and a declaration nothing matched must not render alike.
        if let Some(k) = d.serial_census() {
            s.push_str(&format!(
                "  serial: {} frame(s) on {} interface(s), {} byte(s); \
                 {} message(s) decoded",
                k.frames,
                k.interfaces,
                k.bytes,
                d.serial_frames().len()
            ));
            if k.crc_failures > 0 || k.framing_errors > 0 {
                s.push_str(&format!(
                    " -- {} CRC failure(s), {} framing error(s)",
                    k.crc_failures, k.framing_errors
                ));
            }
            // THE SENTENCE A READER MUST NOT MISS. Everything above is a
            // count; this says whether the direction column beside those
            // messages is a measurement or a convention, and a reader who
            // takes a positional attribution for a measured one will read a
            // reply as a request.
            s.push_str(if k.committed_positionally {
                // FIRST, because it overrides `roles_witnessed`: a line that
                // committed before its handshake arrived ignored that
                // handshake, so a rendering that read the witness flag would
                // call a convention a measurement.
                "\n    direction POSITIONAL and COMMITTED: no handshake arrived \
                 within the frame bound, so A is the first interface seen and \
                 a later handshake was ignored to keep one capture on one \
                 mapping\n"
            } else if k.direction_unattributed {
                "\n    direction UNATTRIBUTED: one interface holds both wires of \
                 the line, and no rule over the zenoh bytes recovers which \
                 frame came off which\n"
            } else if k.roles_witnessed {
                "\n    direction measured: a handshake frame named which \
                 interface is the initiator\n"
            } else {
                "\n    direction POSITIONAL: no handshake frame was captured, \
                 so A is the first interface seen rather than the initiator\n"
            });
        }
        // R311y669 (§1.2a) — QUIC, and the sentence says what a reader must do
        // with it: the zenoh is inside and this reader does not open it. Printed
        // only when non-zero, like every other qualifier here.
        {
            let q: alloc::vec::Vec<crate::quic::QuicCensus> =
                d.datagram_flows().iter().filter_map(|fl| fl.quic).collect();
            if !q.is_empty() {
                // R311y698 — the TAIL of this sentence follows what happened.
                // "this reader recognises QUIC and opens none of it" was true of
                // this crate on its own and false of a run whose caller opened
                // it, and a person reads this line rather than the JSON.
                let mut undecoded = alloc::string::String::new();
                let verdict = match self.quic {
                    None => alloc::string::String::from(
                        "NOT DECRYPTED (this reader recognises QUIC and opens \
                         none of it; supply --keylog to open one)",
                    ),
                    Some(k) if k.packets_opened == 0 => format!(
                        "NOT DECRYPTED ({} packet(s) offered, {} had no key for \
                         their space, {} were refused)",
                        k.packets, k.packets_no_keys, k.packets_refused
                    ),
                    Some(k) => format!(
                        "{} of {} packet(s) opened, {} flow(s) whole -- {} \
                         handshake byte(s), {} stream byte(s), {} datagram byte(s)",
                        k.packets_opened,
                        k.packets,
                        k.flows_opened,
                        k.crypto_bytes,
                        k.stream_bytes,
                        k.datagram_bytes
                    ),
                };
                // R311y705 — and the sentence a reader ACTS on: bytes this
                // workspace recovered and did not decode. Printed after the
                // line above rather than folded into it, because that line is
                // about the DECRYPTION and this is about what happened next --
                // and the answer is nothing.
                if let Some(k) = self.quic {
                    let unread = quic_application_unread(k);
                    if unread > 0 {
                        // R311y718 — the sentence now names WHICH of the two
                        // ways bytes go unread, because the remedies are
                        // opposite. Bytes nothing was offered are a seam
                        // question (a DATAGRAM frame, a refused stream, an
                        // evicted flow); bytes a framer took and decoded
                        // nothing from are a CONTENT question -- the stream was
                        // not zenoh, or it is cut short. Until this round only
                        // the first existed, so the sentence could state its
                        // cause as a fact.
                        let (offered, stalled) = (k.framing.bytes_fed, k.framing.bytes_undecoded);
                        let cause = if stalled >= unread {
                            "a zenoh framer read them and decoded no message out \
                             of them -- the stream is not zenoh, or it is cut short"
                        } else if offered == 0 {
                            "nothing in this run offered them to a zenoh framer"
                        } else {
                            "part of them reached a zenoh framer and the rest \
                             reached none"
                        };
                        undecoded = alloc::format!(
                            "\n  QUIC: {unread} application byte(s) were recovered \
                             and NOT decoded -- {cause}, so the zenoh inside them \
                             is not in any total above"
                        );
                    }
                }
                s.push_str(&format!(
                    "  QUIC: {} flow(s){}, {} packet(s), {} byte(s) -- {verdict}{undecoded}\n",
                    q.len(),
                    // Named in the rendering and not only in the JSON: a person
                    // reading this must know whether the classification came from
                    // a header or from their own flag, because a wrong flag turns
                    // real zenoh into an unopened QUIC flow.
                    match q.iter().filter(|c| c.declared).count() {
                        0 => alloc::string::String::new(),
                        n => alloc::format!(" ({n} declared, not recognised)"),
                    },
                    q.iter().map(|c| c.packets).sum::<usize>(),
                    q.iter().map(|c| c.bytes).sum::<u64>(),
                ));
                // R311y671 — and the sentence for a premise its own flow
                // CONTRADICTS, which the line above cannot carry: that line says
                // this reader recognised QUIC, and for such a flow it recognised
                // nothing at all. MEASURED before this existed — a `--quic` port
                // that really carried three ordinary zenoh datagrams printed
                // exactly the sentence above, with the traffic silenced and the
                // `unrecognised: 3` evidence visible only in the JSON.
                // R311y710 (Y2) — a flow whose KEYS rest on a premise, said in
                // the summary rather than only in `--flows`. The verdict line
                // above reports packets opened, which is the CONSEQUENCE of the
                // assumption and reads exactly like the consequence of evidence.
                // `declared` below is the same shape one question earlier -- that
                // one is about whether the flow is QUIC, this one about whether
                // these are its keys -- and both are premises a wrong answer to
                // makes every number above wrong with it.
                if let Some(k) = self.quic {
                    if k.flows_identity_adopted > 0 {
                        s.push_str(&format!(
                            "  QUIC: {} flow(s) opened on an ASSUMED identity -- no \
                             ClientHello was seen and the key log held exactly one \
                             connection, taken to be theirs\n",
                            k.flows_identity_adopted
                        ));
                    }
                }
                let unsupported = q.iter().filter(|c| c.declaration_unsupported()).count();
                if unsupported > 0 {
                    s.push_str(&format!(
                        "  QUIC: {unsupported} DECLARED flow(s) carried no packet this \
                         reader can name as QUIC -- the --quic port is probably wrong, \
                         and that traffic was withheld from the zenoh decoder\n"
                    ));
                }
                // R311y708 — and the sentence for a flow this reader accepted on
                // a number NOTHING it links against knows. The recognition is
                // still the right call (the note on `VersionSource` says why
                // deleting the entry is the worse trade), but a person reading
                // "QUIC: 1 flow" is entitled to know that this particular flow
                // rests on a reading of an RFC rather than on agreement with an
                // implementation, because that is the one line above that could
                // be wrong for a reason no test here can find.
                let doc_only = document_only_versions(&q);
                if !doc_only.is_empty() {
                    let words = doc_only
                        .iter()
                        .map(|v| alloc::format!("{v:#010x}"))
                        .collect::<alloc::vec::Vec<_>>()
                        .join(", ");
                    s.push_str(&format!(
                        "  QUIC: recognised at version(s) {words}, which no \
                         implementation in this build names -- accepted from the \
                         specification alone, and nothing here can check it\n"
                    ));
                }
            }
        }

        // R311y709 (§1.2a) — the same two numbers for a person, printed only
        // when the difference is non-zero.
        //
        // The conditional is the R311y707 lesson applied before it can bite: a
        // line that appears on every capture, carrying a number that is
        // non-zero on every capture, is a line readers learn to skip — which is
        // how a real SC2043 sat inside a permanently red lane for four rounds.
        // The differences this reader EXPECTS are documented on `ByteResidue`;
        // what is worth a person's attention is that there IS one.
        {
            let r = d.byte_residue();
            if r.unfed() > 0 {
                s.push_str(&format!(
                    "residue: {} of {} recovered byte(s) reached no decoder \
                     -- this is a MEASUREMENT and moves no verdict above\n",
                    r.unfed(),
                    r.recovered
                ));
            }
        }

        if let Some(t) = self.throughput {
            let g = t.gaps();
            s.push_str(&format!(
                "throughput: {} of {} record(s) attributed, {} bytes, \
                 {} unresolved reference(s)\n",
                t.records(),
                t.walked_records(),
                t.total_payload_bytes(),
                t.unresolved_records()
            ));
            // R311y637 (§1.1w) — printed only when non-zero, like every other
            // qualifier in this rendering: a reader of an ordinary capture is
            // not told about a hazard it does not have.
            if t.unsized_payloads() > 0 {
                // R311y646 (§4.28 / §4.34) — the two reasons are named
                // separately and the ceiling is stated in BYTES, because they
                // are what a reader does something different about: bytes that
                // went through shared memory are not in this file at any
                // resolution, while unseparated ones are here and bounded.
                let u = t.unmeasured_payloads();
                s.push_str(&format!(
                    "  UNSIZED: {} record(s) carry a payload this build cannot \
                     measure ({} elsewhere, {} unresolved); application bytes \
                     are between {} and {}\n",
                    t.unsized_payloads(),
                    u.elsewhere,
                    u.unresolved,
                    t.total_payload_bytes(),
                    t.payload_bytes_ceiling()
                ));
            }
            if !g.is_clean() {
                s.push_str(&format!(
                    "  UNREAD: {} halted batch(es) ({} bytes), {} undecompressible, {} unresolvable fragment(s)\n",
                    g.halted_batches, g.unparsed_bytes, g.undecompressible_batches, g.unresolvable_fragments
                ));
            }
            // Only where a selector was actually applied: an unfiltered report
            // would otherwise carry a line saying every record matched, which
            // is true and tells the reader nothing.
            let sel = t.selection();
            if sel.rejected > 0 || sel.undecided > 0 {
                s.push_str(&format!(
                    "  selection: {} matched, {} rejected, {} UNDECIDED\n",
                    sel.matched, sel.rejected, sel.undecided
                ));
            }
            if t.source_ahead_of_observer() > 0 {
                s.push_str(&format!(
                    "  {} record(s) stamped by their source AFTER this capture \
                     saw them: the two clocks are offset and no delay figure \
                     here is trustworthy\n",
                    t.source_ahead_of_observer()
                ));
            }
            // R311y645 (§4.38) — printed only when it happened, like the line
            // above: a capture read straight off the wire has nothing to say
            // here, and a permanent "0 records could not be located" would be
            // noise on every ordinary report.
            if t.unlocatable_records() > 0 {
                s.push_str(&format!(
                    "  {} record(s) were reassembled or decompressed and have \
                     no offset in this capture: they cannot be pointed at in \
                     the file\n",
                    t.unlocatable_records()
                ));
            }
            for row in t.rows() {
                let totals = row.totals();
                // R311y714 ([REDACTED-REQ]) — the share beside the count. Printed as
                // a dash where the plane has no denominator rather than as
                // 0.00%, which would say this topic carried none of a total
                // that does not exist.
                let share = match t.share_bp(&row.keyexpr) {
                    Some(bp) => alloc::format!("{:>3}.{:02}%", bp / 100, bp % 100),
                    None => "     -".into(),
                };
                s.push_str(&format!(
                    "  {:>12} B  {} {:>6} msg  {}\n",
                    totals.payload_bytes,
                    share,
                    totals.messages(),
                    row.keyexpr
                ));
            }
            // R311y642 (§1.1t) — the line the ranking above cannot produce. A
            // topic split across a key per entity is N small rows here and one
            // heavy subtree there, and only the second is a statement about
            // where the capture's traffic is. Printed only when a shared prefix
            // exists at all, so a flat key space says nothing rather than
            // repeating its own root.
            if let Some(sub) = t.subtrees().heaviest_shared() {
                s.push_str(&format!(
                    "  {:>12} B  {:>6} msg  {}/** ({} keys)\n",
                    sub.totals.payload_bytes,
                    sub.totals.messages(),
                    sub.prefix,
                    sub.rows
                ));
            }
        }

        #[cfg(feature = "network-codecs")]
        if let Some(e) = self.exchanges {
            let (first, completion) = e.totals();
            s.push_str(&format!(
                "exchanges: {} request(s), {} completed, {} unclosed\n",
                e.requests(),
                e.completed(),
                e.unclosed()
            ));
            s.push_str(&format!(
                "  latency at the tap: first reply {}, completion {}\n",
                describe(&first),
                describe(&completion)
            ));
            let g = e.gaps();
            if !g.is_clean() {
                s.push_str(&format!(
                    "  UNMEASURED: {} orphan response(s), {} unstamped, {} non-monotonic, {} unattributed\n",
                    g.orphan_responses, g.unstamped, g.non_monotonic, g.unattributed_requests
                ));
            }
            // R311y618 — exchanges, not records: the unit this plane judged is
            // named on the line so the figure is not mistaken for the
            // throughput plane's, which counts something else over the same
            // capture.
            let sel = e.selection();
            if sel.rejected > 0 || sel.undecided > 0 {
                s.push_str(&format!(
                    "  selection: {} exchange(s) matched, {} rejected, {} UNDECIDED\n",
                    sel.matched, sel.rejected, sel.undecided
                ));
            }
            for row in e.rows() {
                s.push_str(&format!(
                    "  {:>8}  {:>4} req  {}\n",
                    describe(&row.completion),
                    row.requests,
                    row.keyexpr
                ));
            }
        }

        #[cfg(feature = "network-codecs")]
        if let Some(p) = self.payloads {
            s.push_str(&format!(
                "payloads: {} judged, {} contradicted their declaration, \
                 {} unknown encoding id(s), {} not on the wire\n",
                p.payloads(),
                p.contradictions().len(),
                p.unknown_ids(),
                p.descriptors()
            ));
            // Beside the finding count, and deliberately: a narrowed census
            // reports findings about the payloads it kept and says nothing
            // about the rest, so "0 contradicted" under a selector is not the
            // same claim as "0 contradicted" over the capture.
            let sel = p.selection();
            if sel.rejected > 0 || sel.undecided > 0 {
                s.push_str(&format!(
                    "  selection: {} matched, {} rejected, {} UNDECIDED\n",
                    sel.matched, sel.rejected, sel.undecided
                ));
            }
            for row in p.rows() {
                s.push_str(&format!(
                    "  {:>6} msg  {:>10} B  {}{}\n",
                    row.payloads,
                    row.bytes,
                    row.declared,
                    if row.not_as_declared > 0 {
                        format!("  [{} NOT AS DECLARED]", row.not_as_declared)
                    } else {
                        String::new()
                    }
                ));
            }
            // The findings themselves, named with where they broke -- the
            // reason this plane exists, so it leads rather than being a footnote
            // under the totals.
            for c in p.contradictions() {
                s.push_str(&format!(
                    "  FINDING: {} declared {} and {}\n",
                    c.keyexpr.as_deref().unwrap_or("<unresolved keyexpr>"),
                    c.declared,
                    describe_mismatch(&c.reason)
                ));
            }
        }
        s
    }
}

/// R311y665 (§1.2a) — transport messages this reader DECODED, over every flow
/// still in the table.
///
/// The number the whole analyzer exists to produce, and the report did not carry
/// it: `sequence.frames` counts frames whose message type carries a sequence
/// number, so a session of KeepAlives -- which is what an idle zenoh link is,
/// and what a decrypted TLS flow in this workspace's own tests is -- reported
/// zero while three messages sat in the rows.
///
/// R311y666 — over every flow the capture HELD, not every flow it still holds.
/// R311y665 shipped this reading the live tables and named the consequence in
/// its own carry: on a live tap the number walked BACKWARDS every time the flow
/// cap recycled a slot. `Dissection::decoded_messages` carries the evicted
/// flows' share, which is the same repair R311y650 made to the encrypted
/// census and R311y605/y610 made to the stream and session tallies.
fn decoded_messages(d: &crate::Dissection) -> usize {
    d.decoded_messages()
}

/// R311y661 (§1.2a) — the wire name of one undecrypted-flow reason.
///
/// A total match and not a `_ =>` fallback: a variant added later must be given
/// a name here rather than silently reported as whichever string happened to be
/// the default, which is the shape of the constant this round replaced.
///
/// UNCONDITIONAL, because its caller is: the `encrypted` block of the report is
/// structural and present with zeroes on a plaintext capture, so a reason
/// function behind a feature would leave that block unbuildable in exactly the
/// configurations the dissector ships to smallest.
fn decryption_reason(reason: crate::tls::NotDecrypted) -> &'static str {
    match reason {
        crate::tls::NotDecrypted::NoKeysSupplied => "no_keys_supplied",
        crate::tls::NotDecrypted::NoSessionIdentity => "no_session_identity",
        crate::tls::NotDecrypted::NoKeyForSession => "no_key_for_session",
        crate::tls::NotDecrypted::RecordRefusedKeys { .. } => "record_refused_keys",
        crate::tls::NotDecrypted::NoKeyForDirection { .. } => "no_key_for_direction",
    }
}

/// A latency in the one phrasing that stays honest when nothing was measured.
#[cfg(feature = "network-codecs")]
fn describe(l: &crate::exchange::LatencySamples) -> String {
    match l.mean_ms() {
        // "unmeasured" and not "0 ms", for the reason `LatencySamples` keeps
        // its min as an `Option`.
        None => "unmeasured".to_string(),
        Some(mean) => format!(
            "{}ms mean over {} (min {}, max {})",
            mean,
            l.count(),
            l.min_ms().unwrap_or(mean),
            l.max_ms().unwrap_or(mean)
        ),
    }
}

/// R311y642 (§1.1t) — one subtree node and everything under it.
///
/// Recursive, and the recursion is bounded by the deepest keyexpr in the
/// capture rather than by anything this function chooses: a document that
/// truncated the tree would be a different claim about the capture than the
/// rows beside it.
fn subtree_json(node: &crate::agg::KeyexprSubtree, s: &mut String) {
    s.push_str("{\"prefix\":");
    quote_into(&node.prefix, s);
    s.push_str(&format!(
        ",\"rows\":{},\"messages\":{},\"payload_bytes\":{},\"unsized_payloads\":{},\
         \"payload_bytes_ceiling\":{}",
        node.rows,
        node.totals.messages(),
        node.totals.payload_bytes,
        node.totals.unsized_payloads,
        // R311y647 (§4.50) — the same ceiling the rows and the capture carry.
        // A node's totals are INCLUSIVE of its descendants, so this is the
        // ceiling for that whole subtree and a reader moving between the three
        // renderings never meets a number qualified in two different ways.
        node.totals.payload_bytes + node.totals.unresolved_at_most_bytes
    ));
    s.push_str(",\"children\":[");
    for (i, c) in node.children.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        subtree_json(c, s);
    }
    s.push_str("]}");
}

fn throughput_json(t: &ThroughputTable, s: &mut String) {
    let (declared, undeclared) = t.declarations();
    s.push_str("\"throughput\":{");
    s.push_str(&format!(
        "\"records\":{},\"unattributed_records\":{},\"walked_records\":{},\
         \"unresolved_records\":{},\"total_payload_bytes\":{},\
         \"unsized_payloads\":{}",
        t.records(),
        // R311y622 (§1.4h) — the denominator rides BESIDE the numerator rather
        // than being left for the consumer to add up from four fields, which is
        // the arithmetic nobody does.
        t.unattributed_records(),
        t.walked_records(),
        t.unresolved_records(),
        t.total_payload_bytes(),
        // UNCONDITIONAL in JSON, conditional in text: a machine consumer that
        // has to test for a key's presence to learn whether the total is whole
        // will not, and the field is the only thing qualifying the number
        // beside it.
        t.unsized_payloads()
    ));
    // R311y646 (§4.28 / §4.34) — the breakdown and the CEILING, unconditional
    // for the reason the count above is: a consumer reading `total_payload_bytes`
    // holds a floor, and the number that says how far from whole it might be
    // must not be something they have to test for.
    {
        let u = t.unmeasured_payloads();
        s.push_str(&format!(
            ",\"payloads_elsewhere\":{},\"payloads_unresolved\":{},\
             \"payload_bytes_ceiling\":{}",
            u.elsewhere,
            u.unresolved,
            t.payload_bytes_ceiling()
        ));
    }
    // R311y644 (§1.1p) — UNCONDITIONAL, like `unsized_payloads` above and for
    // the same reason: it is the field that qualifies every `delay` figure in
    // the capture, and a consumer that must test for a key's presence to learn
    // the axis is untrustworthy will not.
    s.push_str(&format!(
        ",\"source_ahead_of_observer\":{}",
        t.source_ahead_of_observer()
    ));
    // R311y645 (§4.38) — UNCONDITIONAL for the same reason as the two above: it
    // says how much of this report cannot be pointed at in the capture file,
    // and a consumer that has to test for the key to learn that will not.
    s.push_str(&format!(
        ",\"unlocatable_records\":{}",
        t.unlocatable_records()
    ));
    s.push_str(&format!(
        ",\"declarations\":{declared},\"undeclarations\":{undeclared}"
    ));
    s.push_str(",\"gaps\":");
    gaps_json(t.gaps(), s);
    s.push_str(",\"selection\":");
    selection_json(t.selection(), s);
    // R311y642 (§1.1t) — the hierarchy beside the flat list, not instead of it.
    // The two answer different questions and a consumer that wants "which key"
    // must not have to walk a tree to get it back.
    s.push_str(",\"tree\":");
    subtree_json(&t.subtrees(), s);
    s.push_str(",\"rows\":[");
    for (i, row) in t.rows().iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let totals = row.totals();
        s.push_str("{\"keyexpr\":");
        quote_into(&row.keyexpr, s);
        s.push_str(&format!(
            ",\"messages\":{},\"payload_bytes\":{},\"puts\":{},\"dels\":{},\"queries\":{},\"replies\":{},\"errs\":{}",
            totals.messages(),
            totals.payload_bytes,
            totals.puts,
            totals.dels,
            totals.queries,
            totals.replies,
            totals.errs
        ));
        // R311y647 (§4.50) — the ROW's own qualifier, which it did not have.
        // The capture-wide count says SOME total is a floor and never which, so
        // a consumer reading one row got a bare number and no way to learn it
        // was short. The tree beside these rows has carried `unsized_payloads`
        // since R311y642 and was folded from exactly this data, so the document
        // was qualifying one rendering of a number and not the other.
        s.push_str(&format!(
            ",\"unsized_payloads\":{},\"payloads_elsewhere\":{},\
             \"payloads_unresolved\":{},\"payload_bytes_ceiling\":{}",
            totals.unsized_payloads,
            totals.payloads_elsewhere,
            totals.payloads_unresolved,
            totals.payload_bytes + totals.unresolved_at_most_bytes
        ));
        // R311y715 (§C G6, [REDACTED-REQ]) — the row's OCCUPANCY, which the text
        // rendering has printed since R311y714 and the export did not carry at
        // all. The consumer that has to draw the figure reads this document,
        // so a share only a person can see is a share the requirement's
        // audience never gets. `null` and not `0` where the plane has no
        // denominator, matching both the node plane's export and the dash the
        // text prints there.
        s.push_str(&match t.share_bp(&row.keyexpr) {
            Some(bp) => format!(",\"share_bp\":{bp}"),
            None => ",\"share_bp\":null".to_string(),
        });
        // R311y918 — see `census_json::push_row`: the pair is an interval in one
        // coordinate space and `anchors_exact` says whether every record in the
        // row is in it. Both surfaces carry the same three, because a reader
        // moving between them must not find the pair qualified on one and bare
        // on the other.
        s.push_str(&format!(
            ",\"offset_space\":\"{}\",\"first_anchor\":{},\"last_anchor\":{},\
             \"anchors_exact\":{}}}",
            row.anchors.name(),
            row.first_anchor,
            row.last_anchor,
            row.anchors_exact
        ));
    }
    s.push_str("],\"unresolved\":[");
    for (i, u) in t.unresolved().iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"space\":\"{}\",\"id\":{},\"references\":{}}}",
            match u.space {
                wz_session_core::passive::Direction::A => "A",
                wz_session_core::passive::Direction::B => "B",
            },
            u.id,
            u.references
        ));
    }
    s.push_str("]}");
}

/// R311y616 (§7.12) — the gap object, read by DESTRUCTURING.
///
/// The binding shape is the gate. The planes match `Carried` by name so a new
/// variant fails to compile rather than joining the silent set (R311y614), and
/// the serialiser had no equivalent: a field added to [`ThroughputGaps`] would
/// have kept compiling here and this document would have kept omitting it —
/// silently, in the one place whose whole purpose is that losses are never
/// silent. A struct field can go unread; a destructuring pattern cannot.
///
/// So: do not replace this with `g.halted_batches` field access. The
/// exhaustive pattern is load bearing.
fn gaps_json(g: ThroughputGaps, s: &mut String) {
    let ThroughputGaps {
        halted_batches,
        unparsed_bytes,
        undecompressible_batches,
        unresolvable_fragments,
    } = g;
    s.push_str(&format!(
        "{{\"halted_batches\":{halted_batches},\"unparsed_bytes\":{unparsed_bytes},\"undecompressible_batches\":{undecompressible_batches},\"unresolvable_fragments\":{unresolvable_fragments}}}"
    ));
}

/// The exchange plane's gap object, on the same rule as [`gaps_json`]: an
/// exhaustive pattern, so a new [`ExchangeGaps`](crate::exchange::ExchangeGaps)
/// field cannot be added without this document learning about it.
#[cfg(feature = "network-codecs")]
fn exchange_gaps_json(g: crate::exchange::ExchangeGaps, s: &mut String) {
    let crate::exchange::ExchangeGaps {
        orphan_responses,
        unstamped,
        non_monotonic,
        unattributed_requests,
    } = g;
    s.push_str(&format!(
        "{{\"orphan_responses\":{orphan_responses},\"unstamped\":{unstamped},\"non_monotonic\":{non_monotonic},\"unattributed_requests\":{unattributed_requests}}}"
    ));
}

/// R311y616 (§1.1f) — what the selector did, as JSON.
///
/// Emitted whenever the table was built under a filter, and structurally
/// (every field, whatever its value) for the reason the gap objects are
/// structural: a consumer's field lookup must not depend on whether this
/// capture happened to have that kind of shortfall.
fn selection_json(sel: crate::filter::Selection, s: &mut String) {
    let crate::filter::Selection {
        matched,
        rejected,
        undecided,
    } = sel;
    s.push_str(&format!(
        "{{\"matched\":{matched},\"rejected\":{rejected},\"undecided\":{undecided}}}"
    ));
}

#[cfg(feature = "network-codecs")]
fn exchanges_json(e: &crate::exchange::ExchangeTable, s: &mut String) {
    let (replies, errs) = e.responses();
    let (first, completion) = e.totals();
    let g = e.gaps();
    s.push_str("\"exchanges\":{");
    s.push_str(&format!(
        "\"requests\":{},\"completed\":{},\"unclosed\":{},\"replies\":{},\"errs\":{}",
        e.requests(),
        e.completed(),
        e.unclosed(),
        replies,
        errs
    ));
    s.push_str(",\"first_reply\":");
    latency_json(&first, s);
    s.push_str(",\"completion\":");
    latency_json(&completion, s);
    s.push_str(",\"selection\":");
    selection_json(e.selection(), s);
    s.push_str(",\"gaps\":");
    exchange_gaps_json(g, s);
    s.push_str(",\"unread\":");
    gaps_json(e.unread(), s);
    s.push_str(",\"rows\":[");
    for (i, row) in e.rows().iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"keyexpr\":");
        quote_into(&row.keyexpr, s);
        s.push_str(&format!(
            ",\"requests\":{},\"completed\":{},\"unclosed\":{},\"replies\":{},\"errs\":{}",
            row.requests,
            row.completed,
            row.unclosed(),
            row.replies,
            row.errs
        ));
        s.push_str(",\"first_reply\":");
        latency_json(&row.first_reply, s);
        s.push_str(",\"completion\":");
        latency_json(&row.completion, s);
        s.push('}');
    }
    s.push_str("]}");
}

/// A latency distribution as JSON, with `null` where there is no measurement.
///
/// `null` rather than `0`, and rather than omitting the key: an absent key
/// makes a consumer guess, and a zero makes it wrong.
#[cfg(feature = "network-codecs")]
fn latency_json(l: &crate::exchange::LatencySamples, s: &mut String) {
    s.push_str(&format!(
        "{{\"count\":{},\"min_ms\":{},\"max_ms\":{},\"mean_ms\":{},\"total_ms\":{}}}",
        l.count(),
        opt_u64(l.min_ms()),
        opt_u64(l.max_ms()),
        opt_u64(l.mean_ms()),
        l.total_ms()
    ));
}

/// R311y617 — the payload census as JSON, gap object structural like the rest.
#[cfg(feature = "network-codecs")]
fn payloads_json(p: &crate::payload::PayloadCensus, s: &mut String) {
    s.push_str("\"payloads\":{");
    s.push_str(&format!(
        "\"judged\":{},\"not_as_declared\":{},\"unknown_ids\":{},\
         \"descriptors_not_on_the_wire\":{}",
        p.payloads(),
        p.contradictions().len(),
        p.unknown_ids(),
        // R311y622 (§1.1o) — beside the finding count, never inside it: a
        // descriptor is data this capture could never have held, not a
        // publisher's mistake.
        p.descriptors()
    ));
    s.push_str(",\"selection\":");
    selection_json(p.selection(), s);
    s.push_str(",\"gaps\":");
    gaps_json(p.gaps(), s);
    s.push_str(",\"encodings\":[");
    for (i, row) in p.rows().iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"declared\":");
        quote_into(&row.declared, s);
        s.push_str(&format!(
            ",\"payloads\":{},\"consistent\":{},\"not_as_declared\":{},\
             \"descriptors\":{},\"bytes\":{}}}",
            row.payloads, row.consistent, row.not_as_declared, row.descriptors, row.bytes
        ));
    }
    s.push_str("],\"findings\":[");
    for (i, c) in p.contradictions().iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"keyexpr\":");
        match &c.keyexpr {
            Some(k) => quote_into(k, s),
            None => s.push_str("null"),
        }
        s.push_str(",\"declared\":");
        quote_into(&c.declared, s);
        s.push_str(",\"reason\":");
        quote_into(&describe_mismatch(&c.reason), s);
        s.push_str(&format!(",\"at\":{}}}", mismatch_offset(&c.reason)));
    }
    s.push_str("]}");
}

/// One mismatch in a phrase a person can read.
#[cfg(feature = "network-codecs")]
fn describe_mismatch(m: &crate::payload::Mismatch) -> String {
    use crate::payload::Mismatch;
    match m {
        Mismatch::NotUtf8 { at } => format!("is not valid UTF-8 at byte {at}"),
        Mismatch::NotJson { at, reason } => format!("is not JSON at byte {at}: {reason}"),
        Mismatch::NotCbor { at, reason } => format!("is not CBOR at byte {at}: {reason}"),
    }
}

#[cfg(feature = "network-codecs")]
fn mismatch_offset(m: &crate::payload::Mismatch) -> usize {
    use crate::payload::Mismatch;
    match m {
        Mismatch::NotUtf8 { at } | Mismatch::NotJson { at, .. } | Mismatch::NotCbor { at, .. } => {
            *at
        }
    }
}

fn opt_u64(v: Option<u64>) -> String {
    match v {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    }
}

/// `value` as a quoted, escaped JSON string.
///
/// R311y891 — the allocating form, for the emitters that build a field inside
/// a `format!` and so have no `&mut String` to write into. Its absence is why
/// three wire-sourced fields were spelled `format!("\"{k}\"")` instead: the
/// escaping path took a cursor and the surrounding code had a value, and the
/// short spelling was one character away.
fn quoted(value: &str) -> String {
    let mut out = String::new();
    quote_into(value, &mut out);
    out
}

/// Write `s` as a quoted JSON string.
///
/// R311y921 (open-debt item 379) — THE ESCAPER IS THE WORKSPACE'S, not this
/// module's. This file carried its own for long enough to drift from it in two
/// characters (`\b` and `\f` against `` and ``), and both spellings
/// are correct JSON, so nothing that judges the DOCUMENT could ever have seen
/// the difference. What is left here is the one thing that is this module's own
/// business: the fact that a value is being written as a string at all.
///
/// A keyexpr arrives from the wire and this tool prints it, so the escaping is
/// a correctness boundary rather than a formatting nicety: a publisher that
/// chooses a name containing a quote would otherwise choose where this
/// document's fields end.
fn quote_into(value: &str, out: &mut String) {
    wz_session_core::json::escape_into(value, out);
}

/// R311y859 — the skip census as JSON, written ONCE.
///
/// Two documents carry it — the capture report and [`health_json`] — and they
/// carry the same object rather than two selections of one census, which is the
/// distinction `debt-census-emit-two-renderings` is about. The alternative was
/// on the table and is what this round refused: a second `format!` in
/// `health_json` naming the fields it happened to think mattered, which is
/// exactly how the health surface came to omit all nine in the first place.
///
/// `total` is emitted rather than left to the consumer to sum. A reader adding
/// nine fields is a reader who will be short by one the next time a reason is
/// added, and [`crate::SkipCensus::total`] is the figure the dissection already
/// cross-checks against `packets_skipped`.
fn skips_json(sk: &crate::SkipCensus, s: &mut String) {
    s.push_str(&format!(
        "{{\"total\":{},\"bytes_absent\":{},\"not_this_protocol\":{},\"held\":{},\
         \"unsupported_link_type\":{},\"truncated\":{},\
         \"not_ip\":{},\"not_transport\":{},\"ipv4_fragment\":{},\
         \"ip_fragment_pending\":{},\"vsock_non_payload\":{},\
         \"ipv6_extension_chain\":{},\"ipv6_fragment\":{},\
         \"unwalked_encapsulation\":{},\"gre_payload\":{},\"link_types\":[",
        sk.total(),
        sk.bytes_absent(),
        sk.not_this_protocol(),
        sk.held(),
        sk.unsupported_link_type,
        sk.truncated,
        sk.not_ip,
        sk.not_transport,
        sk.ipv4_fragment,
        sk.ip_fragment_pending,
        sk.vsock_non_payload,
        sk.ipv6_extension_chain,
        sk.ipv6_fragment,
        sk.unwalked_encapsulation,
        sk.gre_payload
    ));
    for (i, dlt) in sk.unsupported_link_types.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{dlt}"));
    }
    // R311y862 — the two protocol SETS beside the link-type one, on the same
    // reasoning: the actionable fact is WHICH number, and `not_transport_protos`
    // in particular is how a reader checks the furniture claim rather than
    // taking it. A tunnel absent from `is_encapsulation`'s list shows up here as
    // a number nobody expected.
    s.push_str("],\"encapsulations\":[");
    for (i, p) in sk.unwalked_encapsulations.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{p}"));
    }
    s.push_str("],\"not_transport_protos\":[");
    for (i, p) in sk.not_transport_protos.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{p}"));
    }
    // R311y864 — the GRE payload ethertypes, on the same reasoning as the two
    // sets above and for a reader who needs to tell "no GRE support" from "GRE
    // read, and it was carrying Ethernet".
    s.push_str("],\"gre_payloads\":[");
    for (i, e) in sk.gre_payloads.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{e}"));
    }
    s.push_str("]}");
}

/// R311y859 — the skip census for a person at a terminal, SPLIT BY WHAT IT
/// COSTS the reader rather than printed as nine equal numbers.
///
/// The split is the finding, not the formatting. Six of the nine reasons mean
/// BYTES THE CAPTURE HOLDS ARE ABSENT from this dissection — a snaplen cut the
/// packet short, a fragment other than the first was walked past by a consumer
/// that does not reassemble, a chain was still waiting for its rest, an IPv6
/// header this build may not walk past (ESP among them) ended the chain, or the
/// link type was never decapsulated at all. The other three are ordinary
/// furniture in a readable capture: ARP and its neighbours, IP that is neither
/// TCP nor UDP, and a vsock control op that carries no payload.
///
/// Until this round the text surface named ONE of the nine and a comment beside
/// it called the other eight furniture. That is true of three of them. Reading
/// it as true of `truncated` or of either fragment counter is how a reader
/// concludes a short capture was whole.
fn skips_text(sk: &crate::SkipCensus, s: &mut String) {
    s.push_str(&format!("  reader skipped: {} packet(s)\n", sk.total()));
    s.push_str(&format!(
        "    bytes this dissection does not hold ({}): {} truncated, \
         {} IPv4 fragment, {} IPv6 fragment, \
         {} IPv6 extension chain, {} link type not read, \
         {} tunnel not opened, {} GRE payload not walked\n",
        sk.bytes_absent(),
        sk.truncated,
        sk.ipv4_fragment,
        sk.ipv6_fragment,
        sk.ipv6_extension_chain,
        sk.unsupported_link_type,
        sk.unwalked_encapsulation,
        sk.gre_payload
    ));
    if !sk.gre_payloads.is_empty() {
        let mut types = String::new();
        for (i, e) in sk.gre_payloads.iter().enumerate() {
            if i > 0 {
                types.push_str(", ");
            }
            types.push_str(&format!("0x{e:04x}"));
        }
        s.push_str(&format!(
            "      GRE payload ethertype(s) not walked: {types}\n"
        ));
    }
    if !sk.unwalked_encapsulations.is_empty() {
        let mut protos = String::new();
        for (i, p) in sk.unwalked_encapsulations.iter().enumerate() {
            if i > 0 {
                protos.push_str(", ");
            }
            protos.push_str(&format!("{p}"));
        }
        s.push_str(&format!(
            "      tunnel IP protocol(s) not opened: {protos}\n"
        ));
    }
    s.push_str(&format!(
        "    not this protocol ({}), counted and not judged: {} not IP, \
         {} terminate at the host, {} vsock control\n",
        sk.not_this_protocol(),
        sk.not_ip,
        sk.not_transport,
        sk.vsock_non_payload
    ));
    // R311y862 — the numbers behind the furniture count, so the claim "none of
    // these could have carried zenoh" is one a reader can check. An
    // encapsulation missing from `is_encapsulation`'s list appears here rather
    // than nowhere.
    if !sk.not_transport_protos.is_empty() {
        let mut protos = String::new();
        for (i, p) in sk.not_transport_protos.iter().enumerate() {
            if i > 0 {
                protos.push_str(", ");
            }
            protos.push_str(&format!("{p}"));
        }
        s.push_str(&format!(
            "      IP protocol(s) held to terminate at the host: {protos}\n"
        ));
    }
    // R311y861 — the third line, and it names WHERE its verdict comes from.
    // A reader who saw `IP fragment pending` on the bytes-absent line above
    // read a completed reassembly as a loss, which is the misreading this
    // split exists to stop. Pieces here; chains in `fragments:`.
    s.push_str(&format!(
        "    held for reassembly ({}): {} IP fragment piece(s), \
         judged as CHAINS and not as pieces\n",
        sk.held(),
        sk.ip_fragment_pending
    ));
    if !sk.unsupported_link_types.is_empty() {
        let mut dlts = String::new();
        for (i, dlt) in sk.unsupported_link_types.iter().enumerate() {
            if i > 0 {
                dlts.push_str(", ");
            }
            dlts.push_str(&format!("{dlt}"));
        }
        s.push_str(&format!(
            "    link type(s) not read by this build: {dlts}\n"
        ));
    }
}

/// R311y885 — what THIS DISSECTION's caps cost, as one JSON object, rendered
/// in ONE place because two documents now carry it.
///
/// # Why it is extracted rather than written a second time
///
/// [`health_json`] held this group inline and was its only consumer until the
/// CENSUS document needed it. A census is a fold over a dissection that may
/// have been read under [`crate::DissectionLimits`], and planes computed over a
/// walk that lost rows have to be able to say so; copying the five-field format
/// string into `census_json` would have made the group a fact with no owner —
/// the same class the doc below names when it says a `--health` flag must be a
/// second CONSUMER of one rendering rather than a second rendering
/// (`debt-census-emit-two-renderings`).
///
/// # The zeros mean "no cap", not "no loss"
///
/// Unchanged from where this lived: every field is zero for a dissection built
/// without caps, and STRUCTURALLY so, because no cap exists to bite. The group
/// is emitted anyway so a consumer can tell "no caps" from "caps that did not
/// bite" — and behind the bounded doors the numbers are a measurement.
pub fn dropped_by_limits_json(d: &crate::Dissection) -> String {
    let drops = d.health().drops;
    format!(
        "{{\"frames\":{},\"stream_bytes\":{},\"skipped\":{},\"flows\":{},\
         \"scout_askers\":{}}}",
        drops.frames, drops.stream_bytes, drops.skipped, drops.flows, drops.scout_askers
    )
}

/// R311y885 — the same group for a person, one indented line, and the same
/// argument for extracting it: [`health_text`] owned the only copy until a
/// bounded run needed to print it on its own.
///
/// One trailing newline, so a caller appends it wherever the line belongs.
pub fn dropped_by_limits_text(d: &crate::Dissection) -> String {
    let drops = d.health().drops;
    format!(
        "  dissection caps: {} frame(s), {} stream byte(s), {} skipped, \
         {} flow(s), {} scout asker(s)\n",
        drops.frames, drops.stream_bytes, drops.skipped, drops.flows, drops.scout_askers
    )
}

/// R311y857 — WHAT THE DISSECTION LOST, AND WHO LOST IT, as one document.
///
/// # Why this is here rather than in the C ABI, where it was written
///
/// R311y608 built this inside `wz-capi-dissect` because that was the surface
/// asking, and the counters then had exactly one consumer. `wz-analyze` grew
/// its own smaller selection — `CaptureReport::capture_json` reports
/// `packets_skipped`, the three stream-health figures and the two INVALID
/// checksum counts, and nothing else — so the command line could not see the
/// capture tool's own admission, the caps that bit, the fragment chains, the
/// framing desyncs or the sequence gaps at all. That asymmetry is the last
/// `debt-analysis-surface-parity` row, and it is the one direction where the
/// ABI was the richer surface.
///
/// The order of operations matters and is the same one R311y856 used: the emit
/// moves here FIRST, so a `--health` flag on the command line is a second
/// consumer of one rendering rather than a second rendering
/// (`debt-census-emit-two-renderings`).
///
/// # Grouped by WHO lost the packet
///
/// Because that is the only thing a consumer can act on, and the answers are
/// genuinely different:
///
/// - `capture_reported_drops` — the CAPTURE TOOL's own admission. Its ring
///   overflowed and the file has a hole. Nothing wz does recovers it; the
///   correct response is to re-capture with a bigger buffer.
/// - `dropped_by_limits` — THIS DISSECTION's caps biting. The data was present;
///   raise [`crate::DissectionLimits`] and it comes back.
/// - `fragments` / `streams` / `framing` / `sequence` — what the WIRE did:
///   reordering, retransmission, chains that never completed, framing this
///   reader had to resynchronise, sequence numbers that never arrived.
/// - `skips` (R311y859) — THIS BUILD's own reach. A packet the decapsulator
///   walked past is a packet the capture holds and no row does, and the owner
///   of that loss is neither the tool, nor the caps, nor the wire: it is the
///   reader. Its absence here is what this round repaired — a document titled
///   "what the dissection lost" carried every loss except the one class whose
///   remedy is to fix this program.
///
/// `capture_reported_drops` is `null` and not `0` when the file made no
/// statement, and the difference IS the field's value: a classic pcap has
/// nowhere to record the figure, so "no ISB" is silence and not a clean bill of
/// health. A reader shown `0` for both cannot tell a quiet capture from a
/// format that cannot answer.
///
/// # One honest limitation, stated rather than left to be discovered
///
/// `dropped_by_limits` is all zeros for any dissection built without caps, and
/// STRUCTURALLY so — no cap exists to bite. The zeros are true and they are not
/// evidence that a bounded dissection would report none. The group is reported
/// anyway, because the alternative is a consumer unable to tell "no caps" from
/// "caps that did not bite".
pub fn health_json(d: &crate::Dissection) -> String {
    let h = d.health();
    let f = d.fragment_stats();
    let fr = d.framing_health();
    let dropped = dropped_by_limits_json(d);
    let reported = match d.capture_reported_drops() {
        Some(n) => n.to_string(),
        None => String::from("null"),
    };
    let mut out = format!(
        "{{\
         \"capture_reported_drops\":{reported},\
         \"dropped_by_limits\":{dropped},\
         \"fragments\":{{\"pieces\":{},\"completed\":{},\"expired\":{},\"evicted\":{},\
         \"open\":{},\"unfinished\":{},\
         \"malformed\":{},\"overlapping\":{}}},\
         \"streams\":{{\"retransmits\":{},\"out_of_order\":{},\"partial_overlaps\":{},\
         \"ip_checksum_valid\":{},\"ip_checksum_invalid\":{},\"ip_checksum_absent\":{},\
         \"transport_checksum_valid\":{},\"transport_checksum_invalid\":{},\
         \"transport_checksum_absent\":{}}},\
         \"framing\":{{\"gaps_forced\":{},\"gap_bytes_missing\":{},\
         \"desyncs\":{},\"recoveries\":{},\"resync_skipped_bytes\":{},\
         \"reserved_headers\":{},\
         \"ws_desyncs\":{},\"ws_recoveries\":{},\"ws_resync_skipped_bytes\":{}}},\
         \"sequence\":{{\"frames\":{},\"missing\":{},\"gaps\":{},\
         \"duplicates\":{},\"out_of_window\":{},\"without_resolution\":{}}},\
         \"skips\":",
        f.pieces,
        f.completed,
        f.expired,
        f.evicted,
        // R311y861 — the two figures the completeness verdict actually reads.
        // Neither appeared in either document before this round, so a consumer
        // could not reproduce `unfinished_fragment_chains` from the health
        // surface at all: `expired` and `evicted` were here, the residue was
        // nowhere, and the sum was a number only the verdict knew.
        d.open_fragment_chains(),
        d.unfinished_fragment_chains(),
        f.malformed,
        f.overlapping,
        h.retransmits,
        h.out_of_order,
        h.partial_overlaps,
        h.ip_checksum_valid,
        h.ip_checksum_invalid,
        h.ip_checksum_absent,
        h.transport_checksum_valid,
        h.transport_checksum_invalid,
        h.transport_checksum_absent,
        fr.gaps_forced,
        fr.gap_bytes_missing,
        fr.desyncs,
        fr.recoveries,
        fr.resync_skipped_bytes,
        fr.reserved_headers,
        fr.ws_desyncs,
        fr.ws_recoveries,
        fr.ws_resync_skipped_bytes,
        fr.sn_frames,
        fr.sn_missing,
        fr.sn_gaps,
        fr.sn_duplicates,
        fr.sn_out_of_window,
        fr.sn_without_resolution,
    );
    skips_json(d.skip_census(), &mut out);
    out.push('}');
    out
}

/// R311y857 — the same counters for a person at a terminal.
///
/// A SECOND rendering of one value and not a second selection of the counters,
/// which is the distinction this workspace's two-renderings debt is about: both
/// this and [`health_json`] read the same four accessors in the same order, and
/// neither is free to report a figure the other omits. What differs is only
/// what a terminal needs — a heading per owner, and `not reported` where the
/// document says `null`.
pub fn health_text(d: &crate::Dissection) -> String {
    let h = d.health();
    let f = d.fragment_stats();
    let fr = d.framing_health();
    let mut s = String::from("health:\n");
    s.push_str(&format!(
        "  capture tool: {}\n",
        match d.capture_reported_drops() {
            // Never "0": a classic pcap cannot record the figure, and a reader
            // shown a zero would read silence as a clean bill of health.
            None => String::from("not reported (this capture format has nowhere to say)"),
            Some(n) => format!("{n} packet(s) dropped by the capture tool"),
        }
    ));
    s.push_str(&dropped_by_limits_text(d));
    s.push_str(&format!(
        "  fragments: {} piece(s), {} completed, {} expired, {} evicted, \
         {} still open, {} unfinished, {} malformed, {} overlapping\n",
        f.pieces,
        f.completed,
        f.expired,
        f.evicted,
        d.open_fragment_chains(),
        d.unfinished_fragment_chains(),
        f.malformed,
        f.overlapping
    ));
    s.push_str(&format!(
        "  streams: {} retransmit(s), {} out of order, {} partial overlap(s)\n",
        h.retransmits, h.out_of_order, h.partial_overlaps
    ));
    s.push_str(&format!(
        "  checksums: ip {} valid / {} invalid / {} absent, \
         transport {} valid / {} invalid / {} absent\n",
        h.ip_checksum_valid,
        h.ip_checksum_invalid,
        h.ip_checksum_absent,
        h.transport_checksum_valid,
        h.transport_checksum_invalid,
        h.transport_checksum_absent
    ));
    s.push_str(&format!(
        "  framing: {} gap(s) forced, {} byte(s) missing, {} desync(s), \
         {} recovery(ies), {} byte(s) skipped resynchronising, \
         {} reserved header(s)\n",
        fr.gaps_forced,
        fr.gap_bytes_missing,
        fr.desyncs,
        fr.recoveries,
        fr.resync_skipped_bytes,
        fr.reserved_headers
    ));
    s.push_str(&format!(
        "  websocket framing: {} desync(s), {} recovery(ies), \
         {} byte(s) skipped resynchronising\n",
        fr.ws_desyncs, fr.ws_recoveries, fr.ws_resync_skipped_bytes
    ));
    s.push_str(&format!(
        "  sequence: {} frame(s), {} missing, {} gap(s), {} duplicate(s), \
         {} out of window, {} without resolution\n",
        fr.sn_frames,
        fr.sn_missing,
        fr.sn_gaps,
        fr.sn_duplicates,
        fr.sn_out_of_window,
        fr.sn_without_resolution
    ));
    skips_text(d.skip_census(), &mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R311y921 (open-debt item 379) — THIS WORKSPACE HAS ONE JSON ESCAPER.
    ///
    /// # Why a second one is invisible to every guard that exists
    ///
    /// R311y920 made the emitted documents provably JSON, and that guard cannot
    /// see this: `\b` and `` are both correct, both parse, and both mean
    /// the same character. So the two writers this crate carried could disagree
    /// on the BYTES of the same string forever while every test stayed green —
    /// which is `debt-census-emit-two-renderings` one layer down, in the layer
    /// that turns a wire string into a document.
    ///
    /// Asserted as EQUIVALENCE rather than against a table, because a table
    /// would be a third statement of the same fact and the failure this guards
    /// is exactly two statements drifting. The RFC's own character table lives
    /// with the implementation, in `wz_session_core::json`.
    #[test]
    fn this_crate_has_one_json_escaper() {
        for s in [
            "plain",
            "with\"quote",
            "back\\slash",
            "new\nline",
            "carriage\rreturn",
            "tab\there",
            "bs\u{08}",
            "ff\u{0C}",
            "nul\u{0}",
            "esc\u{1b}",
            "unit\u{1f}",
            "공간/온도",
        ] {
            let mut mine = String::new();
            quote_into(s, &mut mine);
            let mut shared = String::new();
            wz_session_core::json::escape_into(s, &mut shared);
            assert_eq!(
                mine, shared,
                "this crate's writer and the workspace's escaper disagree on {s:?}"
            );
        }
    }

    // R311y921 (item 379) — the RFC's own character table MOVED to
    // `wz_session_core::json`, which is where the escaper now lives. A pin
    // travels with the code it pins; left here it would have been a third
    // statement of the fact `this_crate_has_one_json_escaper` above already
    // makes, and the drift it exists to catch is statements multiplying.

    /// A keyexpr that ends its own JSON string cannot. The one attacker-facing
    /// leg of this module, driven through the public renderer rather than the
    /// private helper.
    #[test]
    fn a_keyexpr_cannot_end_the_field_it_is_printed_in() {
        let mut out = String::new();
        quote_into(r#"a","injected":"x"#, &mut out);
        assert_eq!(out, r#""a\",\"injected\":\"x""#);
    }

    /// An empty dissection is COMPLETE and says so, so the incomplete leg below
    /// is a difference rather than a constant.
    #[test]
    fn an_untouched_capture_reports_itself_complete() {
        let d = crate::Dissection::new();
        let r = CaptureReport::of(&d);
        assert!(r.is_complete());
        assert!(r.to_json().contains("\"complete\":true"), "{}", r.to_json());
        assert!(r.to_text().starts_with("capture: complete"));
    }

    /// THE RULE, end to end: a capture the planes could not fully read renders
    /// as INCOMPLETE in both formats, and the gap figures are IN the document
    /// rather than left for the caller to fetch separately.
    ///
    /// The capture is a real one — a query whose close never arrived, so the
    /// exchange plane holds an unclosed request and the reader must not read
    /// `completed` as the whole story.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn an_incomplete_capture_says_so_in_both_renderings() {
        use crate::exchange::tests as fx;

        let d = fx::dissect(&[
            (
                true,
                Some(10),
                fx::request_query(1, fx::sender_space(0, Some("q/unclosed"))),
            ),
            (
                false,
                Some(30),
                fx::response_reply(1, fx::sender_space(0, Some("q/unclosed")), b"partial"),
            ),
        ]);
        let throughput = crate::agg::aggregate(&d);
        let exchanges = crate::exchange::exchanges(&d);
        assert_eq!(
            exchanges.unclosed(),
            1,
            "the fixture must actually be short"
        );

        let r = CaptureReport::of(&d)
            .with_throughput(&throughput)
            .with_exchanges(&exchanges);
        assert!(!r.is_complete());

        let json = r.to_json();
        assert!(json.contains("\"complete\":false"), "{json}");
        assert!(json.contains("\"unclosed\":1"), "{json}");
        // Structural, not conditional: both gap objects are present even where
        // their counters are zero, so a consumer's field lookup never depends
        // on whether this capture happened to have that kind of loss.
        assert!(json.contains("\"gaps\":{\"halted_batches\":0"), "{json}");
        assert!(json.contains("\"orphan_responses\":0"), "{json}");
        assert!(json.contains("\"q/unclosed\""), "{json}");

        let text = r.to_text();
        assert!(
            text.starts_with("capture: INCOMPLETE"),
            "the verdict must lead: {text}"
        );
        assert!(text.contains("1 unclosed"), "{text}");
    }

    /// R311y624 (§1.1m) — a capture whose framing broke SAYS SO in the
    /// document, and the verdict follows.
    ///
    /// The dissection has counted desyncs, recoveries and skipped bytes since
    /// R311y609 and the report rendered none of it, so an export could show a
    /// clean bill of health for a stream this reader had demonstrably lost and
    /// re-found. The rows under it are a floor whenever that happens, which is
    /// the same claim the halt counters make and had the same right to reach
    /// `complete`.
    ///
    /// Only the framing plane is on this page. No analysis plane is attached at
    /// all, so `complete: false` here can only have come from the framing
    /// witnesses — the rule R311y618 measured and R311y621 reused.
    #[test]
    fn a_capture_that_lost_its_framing_says_so_and_is_not_complete() {
        let mut d = crate::Dissection::new();
        // A byte stream of small frames with one segment missing, which is how
        // a capture loses one: the splice lands mid-frame and the observer has
        // to find the framing again.
        let stream: alloc::vec::Vec<u8> = (0..600u32)
            .map(|i| (i % 0x80) as u8)
            .flat_map(crate::datagram_tests::framed_frame)
            .collect();
        const SEG: usize = 37;
        for (i, seg) in stream.chunks(SEG).enumerate() {
            if i == 5 {
                continue;
            }
            d.push_packet(
                crate::link::LINKTYPE_ETHERNET,
                i,
                &crate::datagram_tests::tcp_packet(1000 + (i * SEG) as u32, seg),
            );
        }
        let framing = d.framing_health();
        assert!(
            framing.desyncs > 0 && framing.recoveries > 0,
            "the fixture must actually lose and regain the framing: {framing:?}"
        );

        let r = CaptureReport::of(&d);
        assert!(
            !r.is_complete(),
            "a stream this reader lost is not a complete capture"
        );

        let json = r.to_json();
        assert!(json.contains("\"complete\":false"), "{json}");
        // The OBJECT KEY is pinned beside the numbers, on the rule R311y621
        // wrote for the `UNREAD:` line: a probe that renamed the wrapper left
        // every field-name assertion passing, so the numbers alone do not say
        // where a consumer must look for them.
        assert!(
            json.contains(&alloc::format!(
                "\"framing\":{{\"gaps_forced\":{},\"gap_bytes_missing\":{},\"desyncs\":{},\"recoveries\":{},\"resync_skipped_bytes\":{}",
                framing.gaps_forced,
                framing.gap_bytes_missing,
                framing.desyncs,
                framing.recoveries,
                framing.resync_skipped_bytes
            )),
            "{json}"
        );

        let text = r.to_text();
        assert!(text.starts_with("capture: INCOMPLETE"), "{text}");
        assert!(text.contains("  framing: "), "{text}");
    }

    /// THE CONTROL, and the reason the framing object is STRUCTURAL in JSON but
    /// CONDITIONAL in text: an intact capture carries the fields with zeroes
    /// and prints no framing line at all.
    ///
    /// A consumer parsing `framing.desyncs` must never have to ask whether this
    /// particular file had damage; a person reading lines must never be shown a
    /// row of zeroes on every clean capture, which trains the eye to skip the
    /// section that matters.
    #[test]
    fn an_intact_capture_carries_the_framing_fields_and_prints_no_line() {
        let mut d = crate::Dissection::new();
        let stream: alloc::vec::Vec<u8> = (0..8u32)
            .map(|i| (i % 0x80) as u8)
            .flat_map(crate::datagram_tests::framed_frame)
            .collect();
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::tcp_packet(1000, &stream),
        );

        let r = CaptureReport::of(&d);
        assert!(r.is_complete(), "{}", r.to_text());
        let json = r.to_json();
        assert!(
            json.contains("\"framing\":{\"gaps_forced\":0,\"gap_bytes_missing\":0,\"desyncs\":0"),
            "the object is STRUCTURAL: present with zeroes on a clean capture: {json}"
        );
        assert!(
            json.contains("\"sequence\":{\"frames\":"),
            "and so is the wire's own accounting: {json}"
        );
        assert!(json.contains("\"scouting_messages\":0"), "{json}");
        assert!(
            !r.to_text().contains("  framing: "),
            "no damage, no line: {}",
            r.to_text()
        );
    }

    /// R311y621 (§1.4i) — an UNDECOMPRESSIBLE capture reaches the document, in
    /// its own slot, in both renderings.
    ///
    /// The whole `UNREAD:` line is pinned rather than the one number, because
    /// the four counters are rendered by ONE `format!` and a plane that
    /// incremented the wrong field would still put a `1` on the page. Pinning
    /// the line is what makes the SLOT part of the assertion.
    ///
    /// Ungated on purpose: the throughput plane and the compression fixture both
    /// exist without `network-codecs`, so this is one of the few end-to-end
    /// report pages a `--no-default-features` build can run.
    #[test]
    fn an_undecompressible_capture_reaches_the_document_in_its_own_slot() {
        let d = crate::datagram_tests::compressed_session_dissection();
        let throughput = crate::agg::aggregate(&d);
        let r = CaptureReport::of(&d).with_throughput(&throughput);

        assert!(
            !r.is_complete(),
            "a capture whose only frame was unreadable is not complete"
        );
        let json = r.to_json();
        assert!(json.contains("\"complete\":false"), "{json}");
        assert!(
            json.contains(
                "\"halted_batches\":0,\"unparsed_bytes\":0,\
                 \"undecompressible_batches\":1,\"unresolvable_fragments\":0"
            ),
            "{json}"
        );

        let text = r.to_text();
        assert!(text.starts_with("capture: INCOMPLETE"), "{text}");
        assert!(
            text.contains(
                "  UNREAD: 0 halted batch(es) (0 bytes), 1 undecompressible, \
                 0 unresolvable fragment(s)\n"
            ),
            "{text}"
        );
    }

    /// R311y621 (§1.4i) — the same for a capture that began mid-session, and
    /// the SECOND slot on the same line.
    ///
    /// Two pages rather than one for the reason the planes get two: a single
    /// capture exercising both counters would pass on a renderer that printed
    /// the same number twice.
    #[cfg(feature = "reassembly")]
    #[test]
    fn an_unresolvable_fragment_reaches_the_document_in_its_own_slot() {
        let d = crate::datagram_tests::midsession_fragment_dissection();
        let throughput = crate::agg::aggregate(&d);
        let r = CaptureReport::of(&d).with_throughput(&throughput);

        assert!(!r.is_complete());
        let json = r.to_json();
        assert!(
            json.contains(
                "\"halted_batches\":0,\"unparsed_bytes\":0,\
                 \"undecompressible_batches\":0,\"unresolvable_fragments\":1"
            ),
            "{json}"
        );

        let text = r.to_text();
        assert!(
            text.contains(
                "  UNREAD: 0 halted batch(es) (0 bytes), 0 undecompressible, \
                 1 unresolvable fragment(s)\n"
            ),
            "{text}"
        );
    }

    /// R311y637 (§1.1w) — a byte total that is a FLOOR says so, in both
    /// renderings and in the verdict.
    ///
    /// The failure this refuses: a reader sums `total_payload_bytes` over a
    /// capture full of queries carrying values and gets a number that is not
    /// short by a little but short by everything those queries carried, with
    /// nothing anywhere saying so.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn an_unsizable_payload_reaches_the_document_and_the_verdict() {
        use crate::exchange::tests as fx;

        // R311y640 — the record that carries an unsizable payload is now the
        // TRUNCATED query body, not merely a valued one: a query's value became
        // measurable this round, so a fixture that still used it would assert
        // an incompleteness the capture no longer has. The floor and the way the
        // document reports it are unchanged; only the record that produces one
        // moved.
        let valued = fx::dissect(&[(
            true,
            Some(10),
            crate::agg::tests::request_query_truncated(1, fx::sender_space(0, Some("demo/q"))),
        )]);
        let throughput = crate::agg::aggregate(&valued);
        assert_eq!(
            throughput.unsized_payloads(),
            1,
            "the fixture must actually hold an unsizable record"
        );

        let r = CaptureReport::of(&valued).with_throughput(&throughput);
        assert!(
            !r.is_complete(),
            "a byte total that is a floor is not a complete capture: {}",
            r.to_text()
        );
        // R311y725 (N2) — BY NAME, which `!is_complete()` cannot say.
        assert_eq!(
            r.reasons(),
            alloc::vec![VerdictReason::UnsizedPayloads],
            "the unsizable payload is the only leg here: {}",
            r.to_text()
        );
        assert!(
            r.to_json().contains("\"unsized_payloads\":1"),
            "the JSON must qualify the total beside it: {}",
            r.to_json()
        );
        assert!(
            r.to_text().contains("UNSIZED"),
            "the text must say the total is a floor: {}",
            r.to_text()
        );

        // THE CONTROL, and it is the half that makes the three assertions above
        // a decision rather than a counter that is always on: the same query
        // WITHOUT a value produces a complete report, a zero in the JSON, and
        // no UNSIZED line at all.
        let bare = fx::dissect(&[(
            true,
            Some(10),
            crate::agg::tests::request_query_valued(1, fx::sender_space(0, Some("demo/q")), None),
        )]);
        let bare_throughput = crate::agg::aggregate(&bare);
        let br = CaptureReport::of(&bare).with_throughput(&bare_throughput);
        assert_eq!(bare_throughput.unsized_payloads(), 0);
        assert!(br.is_complete(), "{}", br.to_text());
        assert!(br.to_json().contains("\"unsized_payloads\":0"));
        assert!(!br.to_text().contains("UNSIZED"));
    }

    /// R311y646 (§4.28 / §4.34) — the document says WHY a payload went
    /// unmeasured and states the answer as a RANGE.
    ///
    /// A reader of the previous document got a floor and a count of records
    /// standing between it and any ceiling at all — a count in records, which is
    /// not the unit the answer is in. Two records here, one of each reason, so
    /// the rendering has to carry both rather than one number that could be
    /// either.
    ///
    /// The control is a capture with nothing unmeasured: no text line, the JSON
    /// fields still present at zero, and a ceiling that equals the floor.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_two_reasons_a_payload_is_unmeasured_reach_both_renderings() {
        use crate::exchange::tests as fx;

        let d = fx::dissect(&[
            (
                true,
                Some(10),
                crate::agg::tests::request_query_truncated(1, fx::sender_space(0, Some("demo/q"))),
            ),
            (
                true,
                Some(11),
                crate::agg::tests::record_with_body_ext(
                    crate::agg::tests::Carrier::Push,
                    "demo/shm",
                    b"descriptor",
                    crate::agg::tests::BodyExt::ShmMarker,
                ),
            ),
        ]);
        let t = crate::agg::aggregate(&d);
        // ANTI-VACUITY: one record of each reason really did reach the table.
        assert_eq!(t.unsized_payloads(), 2);
        assert_eq!(t.unmeasured_payloads().elsewhere, 1);
        assert_eq!(t.unmeasured_payloads().unresolved, 1);

        let r = CaptureReport::of(&d).with_throughput(&t);
        let text = r.to_text();
        assert!(
            text.contains("1 elsewhere, 1 unresolved"),
            "the text must name both reasons: {text}"
        );
        assert!(
            text.contains("application bytes are between 0 and 3"),
            "and state the answer as a range, in bytes: {text}"
        );
        let json = r.to_json();
        assert!(
            json.contains("\"payloads_elsewhere\":1")
                && json.contains("\"payloads_unresolved\":1")
                && json.contains("\"payload_bytes_ceiling\":3"),
            "the export must carry the breakdown and the ceiling: {json}"
        );

        // THE CONTROL. A measured capture prints no line, and its ceiling is
        // its floor rather than an absent key.
        let plain = fx::dissect(&[(
            true,
            Some(10),
            crate::agg::tests::record_with_body_ext(
                crate::agg::tests::Carrier::Push,
                "demo/plain",
                b"descriptor",
                crate::agg::tests::BodyExt::None,
            ),
        )]);
        let pt = crate::agg::aggregate(&plain);
        let pr = CaptureReport::of(&plain).with_throughput(&pt);
        assert!(!pr.to_text().contains("UNSIZED"), "{}", pr.to_text());
        let pj = pr.to_json();
        assert!(
            pj.contains("\"payloads_elsewhere\":0")
                && pj.contains("\"payloads_unresolved\":0")
                && pj.contains("\"payload_bytes_ceiling\":10"),
            "the fields are structural, and the ceiling is the measured total: {pj}"
        );
    }

    /// R311y647 (§4.50) — a ROW says whether its own byte total is whole.
    ///
    /// THE DEFECT, and it is a disagreement inside one document rather than a
    /// missing field: the tree has carried `unsized_payloads` per node since
    /// R311y642, and the flat rows it is folded FROM carried a bare
    /// `payload_bytes`. So the same quantity was qualified in one rendering and
    /// presented as whole in the other, and a consumer reading rows — the
    /// obvious thing to read — got a confident number for a keyexpr whose bytes
    /// this build could not size.
    ///
    /// TWO KEYEXPRS, one of each kind, because the capture-wide count cannot
    /// tell them apart and a per-row field must. The measured row is the control
    /// and it is the half that matters: a build that stamped the capture's
    /// qualifier onto every row would satisfy every assertion about the unsized
    /// one and fail here.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_row_says_whether_its_own_byte_total_is_whole() {
        use crate::exchange::tests as fx;

        let d = fx::dissect(&[
            (
                true,
                Some(10),
                crate::agg::tests::record_with_body_ext(
                    crate::agg::tests::Carrier::Push,
                    "demo/measured",
                    b"abcd",
                    crate::agg::tests::BodyExt::None,
                ),
            ),
            (
                true,
                Some(11),
                crate::agg::tests::record_with_body_ext(
                    crate::agg::tests::Carrier::Push,
                    "demo/descriptor",
                    b"descriptor",
                    crate::agg::tests::BodyExt::ShmMarker,
                ),
            ),
        ]);
        let t = crate::agg::aggregate(&d);
        // ANTI-VACUITY: two rows, one of each kind.
        assert_eq!(t.rows().len(), 2, "{:?}", t.rows());
        assert_eq!(t.unsized_payloads(), 1);

        let json = CaptureReport::of(&d).with_throughput(&t).to_json();
        // The rows are emitted in `rows()` order and each carries its OWN
        // qualifier. Sliced by keyexpr so the assertion cannot be satisfied by
        // the other row's fields.
        let row_of = |key: &str| {
            let at = json
                .find(&alloc::format!("\"keyexpr\":\"{key}\""))
                .expect(key);
            let end = json[at..].find('}').expect("the row closes") + at;
            json[at..end].to_string()
        };
        let unsized_row = row_of("demo/descriptor");
        assert!(
            unsized_row.contains("\"unsized_payloads\":1")
                && unsized_row.contains("\"payloads_elsewhere\":1")
                && unsized_row.contains("\"payload_bytes\":0")
                && unsized_row.contains("\"payload_bytes_ceiling\":0"),
            "the row whose bytes are elsewhere must say so: {unsized_row}"
        );

        // THE CONTROL. The measured row is complete, and its ceiling is its
        // total rather than the capture's.
        let measured_row = row_of("demo/measured");
        assert!(
            measured_row.contains("\"unsized_payloads\":0")
                && measured_row.contains("\"payload_bytes\":4")
                && measured_row.contains("\"payload_bytes_ceiling\":4"),
            "the measured row must not inherit the capture's qualifier: {measured_row}"
        );
    }

    /// R311y884 (open-debt item 233) — a capture NOTHING corroborates is not
    /// complete, and one with checksum offload still is.
    ///
    /// The six checksum counters were rendered by `health` on both surfaces and
    /// read by no leg of the verdict, so a capture whose every checksum failed
    /// called itself complete. Both arms are here because the rule is a PAIR:
    /// the leg has to fire when nothing verified, and it must NOT fire on the
    /// ordinary local capture where the transmit path's checksums are filled by
    /// the NIC after the tap. A `> 0` rule passes the first and fails the
    /// second, which is the shape R311y860 took out of `packets_skipped`.
    #[test]
    fn a_capture_no_checksum_corroborates_is_not_complete_but_offload_is() {
        use crate::datagram_tests::{framed_keepalive, tcp_packet};
        use crate::link::LINKTYPE_ETHERNET;
        use crate::Dissection;

        // EVERY transport checksum fails: the fixture's own is correct, so one
        // flipped byte is the whole difference between the two arms.
        let mut corrupt = tcp_packet(1000, &framed_keepalive());
        corrupt[14 + 20 + 16] ^= 0xFF;
        let mut all_bad = Dissection::new();
        all_bad.push_packet(LINKTYPE_ETHERNET, 0, &corrupt);
        let h = all_bad.health();
        assert_eq!(h.transport_checksum_invalid, 1, "{h:?}");
        assert_eq!(h.transport_checksum_valid, 0, "{h:?}");
        // The WHOLE list, not a containment claim: a set that also names other
        // legs would satisfy `contains` while proving nothing about this one.
        let r = CaptureReport::of(&all_bad);
        assert_eq!(
            r.reasons(),
            alloc::vec![VerdictReason::ChecksumsUncorroborated],
            "nothing verified, so nothing corroborates the rows: {}",
            r.to_text()
        );

        // THE CONTROL, and the reason the rule is not `invalid > 0`: the same
        // corrupt packet beside a good one is a capture whose reader demonstrably
        // verifies checksums, which is what a transmit-offload capture looks like.
        let mut offload = Dissection::new();
        offload.push_packet(LINKTYPE_ETHERNET, 0, &corrupt);
        offload.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(1000 + framed_keepalive().len() as u32, &framed_keepalive()),
        );
        let h = offload.health();
        assert!(
            h.transport_checksum_invalid > 0 && h.transport_checksum_valid > 0,
            "the control must hold BOTH: {h:?}"
        );
        let control = CaptureReport::of(&offload);
        assert_eq!(
            control.reasons(),
            alloc::vec![],
            "one bad checksum among good ones is offload, not a floor: {}",
            control.to_text()
        );
    }

    /// R311y715 (§C G1) — a WIRE-ACCOUNTED loss reaches the verdict.
    ///
    /// `is_complete` is a conjunction of 24 terms and R311y618 measured what
    /// that costs: one leg was severed and 229 tests stayed green, because
    /// every fixture that reached the verdict reached it through some OTHER
    /// leg. This round severed all 24 one at a time and NINE bound nothing.
    /// These tests are the payment, and each carries the same two parts: a
    /// fixture that trips exactly one term, and an ISOLATION block asserting
    /// that no other term is tripped — without which the test would pass for a
    /// reason that has nothing to do with the leg it names.
    ///
    /// A record whose keyexpr this capture never saw declared is traffic read
    /// and not attributed: it is in no row, so a reader summing the rows is
    /// summing less than the capture holds.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_reference_to_an_undeclared_keyexpr_makes_the_capture_a_floor() {
        use crate::datagram_tests::{push, sender_space};
        use crate::exchange::tests as fx;

        // id 9 was never declared by anyone, so the record is seen and lands in
        // no row.
        let d = fx::dissect(&[(true, Some(10), push(sender_space(9, None), &[0u8; 50]))]);
        let t = crate::agg::aggregate(&d);
        assert_eq!(t.unresolved_records(), 1, "the fixture must fail to bind");
        // ISOLATION on this plane's OWN legs as well as the dissection's: an
        // unresolved record must be the only thing wrong here.
        assert!(t.gaps().is_clean(), "gaps: {:?}", t.gaps());
        assert_eq!(t.unsized_payloads(), 0);
        assert!(t.selection().is_decisive());
        assert_verdict_rests_on(&d, VerdictLeg::None);

        let r = CaptureReport::of(&d).with_throughput(&t);
        assert!(
            !r.is_complete(),
            "a record in no row is a row total that is short"
        );
        // R311y725 (N2) — and WHICH leg. The isolation above already proves no
        // other counter moved; this makes the test say so.
        assert_eq!(
            r.reasons(),
            alloc::vec![VerdictReason::UnresolvedRecords],
            "{}",
            r.to_text()
        );
    }

    /// R311y716 (§C G1) — the reasons reach BOTH renderings, from one
    /// computation.
    ///
    /// The rule this workspace measured at R311y664: a fact rendered in two
    /// places must be asserted in both IN ONE RUN, or the two drift. Here the
    /// hazard is sharper than drift -- `complete` and `reasons` are the same
    /// judgement, and a page saying INCOMPLETE beside an empty reason list
    /// would send a reader looking for a fault the document declines to name.
    #[test]
    fn the_verdicts_reasons_reach_the_page_and_the_export_together() {
        // R311y860 — the fixture MOVED from an ARP frame to a truncated one.
        // What this test is about is that one judgement reaches two renderings,
        // and it needs a fixture that trips the leg; ARP stopped tripping it
        // when the verdict learned that furniture is not a shortfall. The
        // fixture follows the leg rather than the leg being widened back to
        // keep the fixture.
        let mut d = crate::Dissection::new();
        let mut short = alloc::vec![0u8; 12];
        short.extend_from_slice(&[0x08, 0x00]);
        short.extend_from_slice(&[0x45, 0, 0, 40, 0]);
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &short);
        d.finish();

        let report = CaptureReport::of(&d);
        let reasons = report.reasons();
        assert_eq!(
            reasons,
            alloc::vec![VerdictReason::PacketsSkipped],
            "the fixture must state exactly one reason, or neither assertion \
             below distinguishes the list from a substring of it"
        );
        let text = report.to_text();
        let json = report.to_json();
        assert!(
            text.contains("(packets_skipped)"),
            "the page names what is short: {text}"
        );
        assert!(
            json.contains("\"complete\":false,\"reasons\":[\"packets_skipped\"]"),
            "and the export carries the same name beside the same verdict: \
             {json}"
        );

        // THE CLEAN CASE, in the same run: an empty list and `true` must agree
        // too, and an export whose key vanished when there was nothing to say
        // would make a consumer test for presence to learn absence.
        let clean = crate::Dissection::new();
        let clean = CaptureReport::of(&clean);
        assert!(clean.reasons().is_empty() && clean.is_complete());
        assert!(clean.to_json().contains("\"complete\":true,\"reasons\":[]"));
        assert!(clean.to_text().contains("capture: complete"));
    }

    /// R311y716 (§C G1) — the three PLANE legs that bound nothing, and the
    /// point at which isolation stopped being required.
    ///
    /// R311y715 could not pay these: a capture whose batch will not decompress
    /// is short on the exchange plane AND the payload plane AND the throughput
    /// plane at once, so no fixture trips one alone. The verdict answering with
    /// a SET is what makes them individually bindable -- each leg is asserted
    /// by NAME, and severing any one of them reds this test on that name while
    /// the others still hold.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_batch_that_will_not_decompress_names_every_plane_it_shortens() {
        let d = crate::datagram_tests::compressed_session_dissection();
        let exchanges = crate::exchange::exchanges(&d);
        let payloads = crate::payload::payloads(&d);
        let throughput = crate::agg::aggregate(&d);
        let reasons = CaptureReport::of(&d)
            .with_exchanges(&exchanges)
            .with_payloads(&payloads)
            .with_throughput(&throughput)
            .reasons();

        for leg in [
            VerdictReason::ExchangeUnread,
            VerdictReason::PayloadGaps,
            VerdictReason::ThroughputGaps,
        ] {
            assert!(
                reasons.contains(&leg),
                "{} must be named: {reasons:?}",
                leg.name()
            );
        }
        // R311y727 (N19) — AND THE WHOLE LIST, which the containment claims
        // above cannot say. They hold while every other leg fires too, so a
        // guard that widened would pass under them; this is the sentence that
        // says what is NOT in the verdict.
        assert_eq!(
            reasons,
            alloc::vec![
                VerdictReason::ThroughputGaps,
                VerdictReason::ExchangeUnread,
                VerdictReason::PayloadGaps,
            ],
            "the undecompressible batch shortens these three planes and \
             nothing else"
        );
    }

    /// R311y730 (N22) — A HALTED BATCH, AT EXACTLY ONE, ON EVERY PLANE THAT
    /// COUNTS ONE.
    ///
    /// `halted_batches` and `unparsed_bytes` move TOGETHER -- all three
    /// producers raise them in one `if` -- so relaxing either alone leaves the
    /// other holding the plane unclean, and the sweep asks about the PAIR. This
    /// is the capture that answers it: one FRAME carrying a one-byte record
    /// under a network MID this build cannot decode, which halts the walk with
    /// exactly one byte behind it.
    ///
    /// Measured, and it is why the earlier fixtures could not serve: the
    /// undecompressible-batch capture raises neither counter at all, and a
    /// two-byte unknown record gives `unparsed_bytes` 2.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_halted_batch_reaches_every_plane_at_exactly_one() {
        let wire = crate::datagram_tests::frame_carrying(&[0x1F]);
        let mut d = crate::Dissection::new();
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire),
        );
        let t = crate::agg::aggregate(&d);
        let e = crate::exchange::exchanges(&d);
        let pl = crate::payload::payloads(&d);
        assert_eq!(
            (
                t.gaps().halted_batches,
                t.gaps().unparsed_bytes,
                e.unread().halted_batches,
                e.unread().unparsed_bytes,
                pl.gaps().halted_batches,
                pl.gaps().unparsed_bytes,
            ),
            (1, 1, 1, 1, 1, 1),
            "one halt and one unparsed byte, on all three planes that count them"
        );
        assert_eq!(
            CaptureReport::of(&d)
                .with_throughput(&t)
                .with_exchanges(&e)
                .with_payloads(&pl)
                .reasons(),
            alloc::vec![
                VerdictReason::ThroughputGaps,
                VerdictReason::ExchangeUnread,
                VerdictReason::PayloadGaps,
            ],
            "the halt shortens exactly these three planes"
        );
    }

    /// R311y729 (N20) — EVERY EXCHANGE GAP COUNTER, AT EXACTLY ONE.
    ///
    /// The mutation sweep's predicate layer relaxes `ExchangeGaps::is_clean` by
    /// one per field and requires a test to redden. Three fields survived it:
    /// every fixture in this tree trips them TWO or more at a time -- the
    /// orphan test below feeds a reply AND its close, so `orphan_responses` is
    /// never 1 anywhere -- and a reader that stopped counting the FIRST of each
    /// would have passed the whole suite.
    ///
    /// Each arm is its own dissection, because the counter has to be one and
    /// not one-of-several for the boundary to be pinned.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn each_exchange_gap_counter_is_witnessed_at_exactly_one() {
        use crate::exchange::tests as fx;

        // ORPHAN, alone: the reply without its close. The pair is what makes
        // every other fixture here count two.
        let d = fx::dissect(&[(
            false,
            Some(10),
            fx::response_reply(9, fx::sender_space(0, Some("mid/session")), b"x"),
        )]);
        let ex = crate::exchange::exchanges(&d);
        assert_eq!(
            ex.gaps().orphan_responses,
            1,
            "exactly one, or this arm measures nothing the existing test does not"
        );
        assert_eq!(
            CaptureReport::of(&d).with_exchanges(&ex).reasons(),
            alloc::vec![VerdictReason::ExchangeGaps],
            "and it is the whole of the verdict"
        );

        // UNSTAMPED, alone: one exchange that completes, carrying no clock.
        let d = fx::dissect(&[
            (true, None, fx::request_query(1, fx::sender_space(0, None))),
            (
                false,
                None,
                fx::response_reply(1, fx::sender_space(0, None), b"x"),
            ),
            (false, None, fx::response_final(1)),
        ]);
        let ex = crate::exchange::exchanges(&d);
        assert_eq!(ex.gaps().unstamped, 1, "one exchange, and it has no clock");
        assert_eq!(ex.gaps().orphan_responses, 0, "and nothing is orphaned");
        assert_eq!(
            CaptureReport::of(&d).with_exchanges(&ex).reasons(),
            alloc::vec![VerdictReason::ExchangeGaps],
            "an unstamped exchange is the whole of this verdict"
        );

        // NON-MONOTONIC, alone: one exchange whose reply precedes its request.
        let d = fx::dissect(&[
            (
                true,
                Some(20),
                fx::request_query(1, fx::sender_space(0, None)),
            ),
            (
                false,
                Some(10),
                fx::response_reply(1, fx::sender_space(0, None), b"x"),
            ),
            (false, Some(30), fx::response_final(1)),
        ]);
        let ex = crate::exchange::exchanges(&d);
        assert_eq!(ex.gaps().non_monotonic, 1, "one exchange, and it runs back");
        assert_eq!(ex.gaps().unstamped, 0, "and it is stamped throughout");
        assert_eq!(
            CaptureReport::of(&d).with_exchanges(&ex).reasons(),
            alloc::vec![VerdictReason::ExchangeGaps],
            "a backwards exchange is the whole of this verdict"
        );
    }

    /// R311y716 (§C G1) — a reply whose request this capture never saw.
    ///
    /// The exchange plane's own GAPS leg, distinct from its `unread` above: the
    /// message was read perfectly and there is nothing to attribute it to.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn an_orphan_reply_names_the_exchange_planes_gap() {
        use crate::exchange::tests as fx;

        let d = fx::dissect(&[
            (
                false,
                Some(10),
                fx::response_reply(9, fx::sender_space(0, Some("mid/session")), b"x"),
            ),
            (false, Some(20), fx::response_final(9)),
        ]);
        let exchanges = crate::exchange::exchanges(&d);
        assert_eq!(
            exchanges.gaps().orphan_responses,
            2,
            "the fixture must orphan the reply AND its close"
        );
        let reasons = CaptureReport::of(&d).with_exchanges(&exchanges).reasons();
        assert!(
            reasons.contains(&VerdictReason::ExchangeGaps),
            "a reply attributable to nothing is a row this page does not hold: \
             {reasons:?}"
        );
        // R311y727 (N19) — and it is the ONLY leg here, which is what makes
        // the claim above load-bearing against a widened guard as well as a
        // severed one.
        assert_eq!(
            reasons,
            alloc::vec![VerdictReason::ExchangeGaps],
            "the orphan is the whole of this verdict"
        );
    }

    /// R311y715 (§C G1) — a packet this reader SKIPPED reaches the verdict.
    ///
    /// The first line of `is_complete` and one of the nine that bound nothing.
    /// A skipped packet is traffic the capture holds and the rows do not, which
    /// is the definition every other leg answers to.
    ///
    /// R311y860 NARROWED which skip that is, and the fixture moved with it. The
    /// original was an ARP frame, and ARP is on every Ethernet segment — so the
    /// leg it bound was true of every capture ever taken, which is a leg that
    /// distinguishes nothing. It now holds a TRUNCATED packet: bytes that were
    /// on the wire, were captured short, and are in no row. The property this
    /// test defends is unchanged and is now falsifiable.
    #[test]
    fn a_skipped_packet_makes_the_capture_a_floor() {
        let mut d = crate::Dissection::new();
        // An ethertype that promises IPv4 and five bytes of it: the header this
        // frame declares is longer than the frame, so it is skipped rather than
        // misread, and the bytes it declared are absent.
        let mut short = alloc::vec![0u8; 12];
        short.extend_from_slice(&[0x08, 0x00]);
        short.extend_from_slice(&[0x45, 0, 0, 40, 0]);
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &short);
        d.finish();

        assert_eq!(
            d.health().packets_skipped,
            1,
            "the fixture must skip exactly one packet"
        );
        assert_eq!(
            d.skip_census().bytes_absent(),
            1,
            "and it must be the class the verdict reads"
        );
        assert_verdict_rests_on(&d, VerdictLeg::PacketsSkipped);
        assert!(
            !CaptureReport::of(&d).is_complete(),
            "a packet the reader walked past is not in any row"
        );
    }

    /// Which leg of the verdict a §C G1 fixture is allowed to trip.
    #[derive(PartialEq, Eq, Debug)]
    enum VerdictLeg {
        /// The fixture trips no dissection-level leg at all — its shortfall is
        /// on a PLANE, and the plane's own legs are asserted by the caller.
        ///
        /// Gated to match its only constructor: the plane-level fixtures need
        /// the network codecs, and a variant nothing builds is what `-D
        /// dead-code` refuses in the arm a default build never compiles.
        #[cfg(feature = "network-codecs")]
        None,
        PacketsSkipped,
    }

    /// The ISOLATION half of a §C G1 witness: every dissection-level leg of
    /// `is_complete` EXCEPT the named one must be quiet.
    ///
    /// Without this a fixture that trips two legs proves neither — severing the
    /// one under test leaves the other to fail the assertion, and the test
    /// reports a pass that belongs to its neighbour. This is the shape that let
    /// nine legs go unbound in the first place.
    fn assert_verdict_rests_on(d: &crate::Dissection, leg: VerdictLeg) {
        let fh = d.framing_health();
        if leg != VerdictLeg::PacketsSkipped {
            assert_eq!(d.health().packets_skipped, 0, "packets_skipped: {fh:?}");
        }
        assert_eq!(fh.sn_missing, 0, "sn_missing: {fh:?}");
        assert!(!d.drops().any(), "drops: {:?}", d.drops());
        assert_eq!(fh.gaps_forced, 0, "gaps_forced: {fh:?}");
        assert_eq!(fh.desyncs, 0, "desyncs: {fh:?}");
        assert_eq!(fh.ws_desyncs, 0, "ws_desyncs: {fh:?}");
        assert_eq!(
            fh.unaccounted_batch_bytes, 0,
            "unaccounted_batch_bytes: {fh:?}"
        );
        assert_eq!(d.expired_chains(), 0);
        assert_eq!(d.abandoned_chains(), 0);
        assert_eq!(
            d.encrypted_census().flows,
            0,
            "an encrypted flow reaches the verdict on its own leg"
        );
    }

    /// R311y715 (§C G6, [REDACTED-REQ]) — the TOPIC occupancy, in both renderings at
    /// once, and the export half is new here.
    ///
    /// Two defects met at this line. The percentage the text prints was bound
    /// by nothing — `bp / 1000` in place of `bp / 100` left 393 crate tests and
    /// 62 CLI tests green, a figure ten times wrong on the page. And the JSON
    /// row did not carry the share AT ALL, so the reader who has to draw the
    /// occupancy this requirement asks for could not read it: the figure
    /// existed only in the rendering a person looks at.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_topics_occupancy_reaches_both_renderings_as_one_figure() {
        use crate::exchange::tests as fx;

        let d = fx::dissect(&[
            (
                true,
                Some(10),
                crate::agg::tests::record_with_body_ext(
                    crate::agg::tests::Carrier::Push,
                    "demo/heavy",
                    &[0u8; 30],
                    crate::agg::tests::BodyExt::None,
                ),
            ),
            (
                true,
                Some(11),
                crate::agg::tests::record_with_body_ext(
                    crate::agg::tests::Carrier::Push,
                    "demo/light",
                    &[0u8; 10],
                    crate::agg::tests::BodyExt::None,
                ),
            ),
        ]);
        let t = crate::agg::aggregate(&d);
        // ANTI-VACUITY: a share of zero is zero under any divisor.
        assert_eq!(t.total_payload_bytes(), 40, "the denominator");
        assert_eq!(t.share_bp("demo/heavy"), Some(7_500));

        let report = CaptureReport::of(&d).with_throughput(&t);
        let text = report.to_text();
        let json = report.to_json();

        assert!(
            text.contains("75.00%") && text.contains("25.00%"),
            "the page states the occupancy as a percentage: {text}"
        );
        let row_of = |key: &str| {
            let at = json
                .find(&alloc::format!("\"keyexpr\":\"{key}\""))
                .expect(key);
            let end = json[at..].find('}').expect("the row closes") + at;
            json[at..end].to_string()
        };
        // Sliced per row, so neither assertion can be satisfied by the other's
        // figure.
        assert!(
            row_of("demo/heavy").contains("\"share_bp\":7500"),
            "and the export states the SAME figure in basis points: {json}"
        );
        assert!(
            row_of("demo/light").contains("\"share_bp\":2500"),
            "for every row and not just the heaviest: {json}"
        );
    }

    /// R311y616 — a filtered report carries what the selector could NOT judge,
    /// and that shortfall reaches the completeness verdict.
    ///
    /// The failure this refuses: a reader narrows a capture to `demo/**`, gets
    /// a total, and never learns that three records carried a keyexpr the
    /// capture never bound. The rows would be right and the total would be a
    /// floor, which is the difference `complete` exists to carry.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_filtered_report_says_what_the_selector_could_not_judge() {
        use crate::exchange::tests as fx;

        // Two records: one under a resolvable literal keyexpr, one referencing
        // an alias whose declaration this capture never saw.
        let d = fx::dissect(&[
            (
                true,
                Some(10),
                fx::request_query(1, fx::sender_space(0, Some("demo/known"))),
            ),
            (
                true,
                Some(20),
                fx::request_query(2, fx::sender_space(9, None)),
            ),
        ]);

        let filter = crate::filter::Filter::parse("key == demo/known").expect("compiles");
        let throughput = crate::agg::aggregate_where(&d, &filter);
        assert_eq!(throughput.selection().matched, 1);
        assert_eq!(
            throughput.selection().undecided,
            1,
            "the fixture must actually hold an unjudgeable record"
        );

        let r = CaptureReport::of(&d).with_throughput(&throughput);
        let json = r.to_json();
        assert!(
            json.contains("\"selection\":{\"matched\":1,\"rejected\":0,\"undecided\":1}"),
            "{json}"
        );
        assert!(
            json.contains("\"complete\":false"),
            "an undecided record makes the total a floor: {json}"
        );
        let text = r.to_text();
        assert!(text.starts_with("capture: INCOMPLETE"), "{text}");
        assert!(text.contains("1 UNDECIDED"), "{text}");

        // The control: the same capture unfiltered decides everything, so the
        // selection line is absent from the text and the JSON says so.
        let all = crate::agg::aggregate(&d);
        assert!(all.selection().is_decisive());
        let unfiltered = CaptureReport::of(&d).with_throughput(&all).to_text();
        assert!(
            !unfiltered.contains("selection:"),
            "an unfiltered report must not carry a line that says nothing: {unfiltered}"
        );
    }

    /// R311y644 (§1.1p) — an offset source clock reaches BOTH renderings, and
    /// the field that qualifies the delay axis is present even when it is zero.
    ///
    /// The control is a capture whose stamps precede their arrivals: the text
    /// must say nothing and the JSON must still carry the zero, so a consumer
    /// never has to test for a key's presence to learn the axis is sound.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn an_offset_source_clock_is_named_in_both_renderings() {
        use crate::datagram_tests::{push_stamped, sender_space};
        let seen = 1_700_000_005_000u64;

        let ahead = crate::exchange::tests::dissect(&[(
            true,
            Some(seen),
            push_stamped(sender_space(0, Some("demo/p")), b"x", seen + 500),
        )]);
        let at = crate::agg::aggregate(&ahead);
        let r = CaptureReport::of(&ahead).with_throughput(&at);
        assert!(
            r.to_text().contains("the two clocks are offset"),
            "the text must say the axis cannot be trusted: {}",
            r.to_text()
        );
        assert!(
            r.to_json().contains("\"source_ahead_of_observer\":1"),
            "and the export must carry the count: {}",
            r.to_json()
        );

        let sound = crate::exchange::tests::dissect(&[(
            true,
            Some(seen),
            push_stamped(sender_space(0, Some("demo/p")), b"x", seen - 250),
        )]);
        let st = crate::agg::aggregate(&sound);
        let sr = CaptureReport::of(&sound).with_throughput(&st);
        assert!(
            !sr.to_text().contains("clocks are offset"),
            "a sound capture must not print the warning: {}",
            sr.to_text()
        );
        assert!(
            sr.to_json().contains("\"source_ahead_of_observer\":0"),
            "but must still carry the field: {}",
            sr.to_json()
        );
    }

    /// R311y645 (§4.38) — a record with no offset into the capture is NAMED as
    /// such in both renderings.
    ///
    /// The failure this ends is quieter than a wrong number: the record is in
    /// the rows, its keyexpr resolved and its bytes counted, so every total in
    /// the report is right — and a reader who then goes looking for it in the
    /// file has nowhere to look, because its bytes arrived in pieces at two
    /// unrelated places. Until R311y645 the report said the record was at
    /// offset zero of its unit, which is a place in a packet that never carried
    /// it.
    ///
    /// The control is the SAME record read straight off the wire: the text must
    /// print no such line and the JSON must still carry the zero, so a consumer
    /// never has to test for a key's presence to learn its rows are locatable.
    #[cfg(all(feature = "network-codecs", feature = "reassembly"))]
    #[test]
    fn a_record_with_no_offset_in_the_capture_is_named_in_both_renderings() {
        use crate::datagram_tests::{push, sender_space};
        let record = push(sender_space(0, Some("demo/split")), &[0u8; 8]);

        let joined = crate::datagram_tests::reassembled_record_dissection(&record);
        let jt = crate::agg::aggregate(&joined);
        // ANTI-VACUITY: the chain completed, so the report is describing a
        // record it really did read.
        assert_eq!(jt.records(), 1);
        let r = CaptureReport::of(&joined).with_throughput(&jt);
        assert!(
            r.to_text().contains("cannot be pointed at in the file"),
            "the text must say the rows cannot be located: {}",
            r.to_text()
        );
        assert!(
            r.to_json().contains("\"unlocatable_records\":1"),
            "and the export must carry the count: {}",
            r.to_json()
        );

        let plain = crate::exchange::tests::dissect(&[(true, Some(1), record)]);
        let pt = crate::agg::aggregate(&plain);
        assert_eq!(pt.records(), 1, "the control read the same record");
        let pr = CaptureReport::of(&plain).with_throughput(&pt);
        assert!(
            !pr.to_text().contains("cannot be pointed at"),
            "a capture read off the wire must not print the warning: {}",
            pr.to_text()
        );
        assert!(
            pr.to_json().contains("\"unlocatable_records\":0"),
            "but must still carry the field: {}",
            pr.to_json()
        );
    }

    /// R311y643 (§1.1e) — a capture this build cannot decapsulate SAYS SO, in
    /// both renderings, and names the link type.
    ///
    /// The document is the whole point of the census: a reader holding a serial
    /// or unix-socket capture previously got "0 flows, N packets skipped" and no
    /// way to tell that from a deployment with no traffic in it.
    ///
    /// The control is a clean Ethernet capture, which must print no such line
    /// and carry an empty link-type list — so the line is a decision about this
    /// file and not a banner.
    #[test]
    fn a_capture_under_an_unreadable_link_type_says_so_in_both_renderings() {
        let mut d = crate::Dissection::new();
        for i in 0..3 {
            d.push_packet(250, i, &[0xAA; 20]);
        }
        let r = CaptureReport::of(&d);
        let text = r.to_text();
        // R311y859 — the identity moved into the skip breakdown, which is where
        // every other reason is named and where the health surface reads it
        // from. The PIN follows it rather than being dropped: what it defends is
        // that the text says WHICH link type, and that is as true after the move.
        assert!(
            text.contains("link type(s) not read by this build: 250"),
            "the text must name what it refused: {text}"
        );
        // R311y859 — and the CONSEQUENCE is a second fact, pinned separately.
        // A capture whose link type this build cannot read is not a quiet
        // deployment, and that judgement is the one thing the counters cannot
        // carry.
        assert!(
            text.contains("this capture was not dissected"),
            "the text must say what the refusal cost: {text}"
        );
        let json = r.to_json();
        assert!(
            json.contains("\"unsupported_link_type\":3"),
            "the export must carry the count: {json}"
        );
        assert!(
            json.contains("\"link_types\":[250]"),
            "and the SET behind it: {json}"
        );

        let clean = crate::Dissection::new();
        let cr = CaptureReport::of(&clean);
        assert!(
            !cr.to_text().contains("link type not read"),
            "a capture with no refusal must not print one: {}",
            cr.to_text()
        );
        assert!(
            cr.to_json().contains("\"link_types\":[]"),
            "the field is structural, present and empty: {}",
            cr.to_json()
        );
    }

    /// R311y642 (§1.1t) — the hierarchy reaches BOTH renderings, and it says
    /// something the flat list beside it does not.
    ///
    /// The text leg is the sharper one: the ranking there names `logs`, the
    /// heaviest single key, and the rollup line names `robot/**`, which is
    /// heavier and appears nowhere else in the document. A reader of the text
    /// alone was previously being pointed at the wrong topic.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_keyexpr_hierarchy_reaches_both_renderings() {
        use crate::datagram_tests::{push, sender_space};

        let mut records = alloc::vec::Vec::new();
        for key in ["robot/1/pose", "robot/2/pose", "robot/3/pose"] {
            records.push((
                true,
                Some(1u64),
                push(sender_space(0, Some(key)), &[0u8; 10]),
            ));
        }
        records.push((
            true,
            Some(1u64),
            push(sender_space(0, Some("logs")), &[0u8; 25]),
        ));
        let d = crate::exchange::tests::dissect(&records);
        let t = crate::agg::aggregate(&d);
        let r = CaptureReport::of(&d).with_throughput(&t);

        let text = r.to_text();
        assert!(
            text.contains("robot/** (3 keys)"),
            "the rollup line must name the subtree and how many keys it stands for: {text}"
        );
        assert!(
            text.contains("logs"),
            "and the flat ranking must still be there: {text}"
        );

        let json = r.to_json();
        assert!(
            json.contains("\"tree\":"),
            "the hierarchy must reach the export: {json}"
        );
        assert!(
            json.contains("\"prefix\":\"robot\",\"rows\":3,\"messages\":3,\"payload_bytes\":30"),
            "with inclusive totals for the node the text names: {json}"
        );

        // THE CONTROL: a flat key space emits a tree with no shared node, and
        // NO rollup line — so the line above is a decision about this capture
        // and not a banner the renderer always prints.
        let flat = crate::exchange::tests::dissect(&[
            (
                true,
                Some(1u64),
                push(sender_space(0, Some("alpha")), &[0u8; 4]),
            ),
            (
                true,
                Some(1u64),
                push(sender_space(0, Some("beta")), &[0u8; 4]),
            ),
        ]);
        let ft = crate::agg::aggregate(&flat);
        let ftext = CaptureReport::of(&flat).with_throughput(&ft).to_text();
        assert!(
            !ftext.contains("/**"),
            "a flat key space has no subtree to report: {ftext}"
        );
    }

    /// R311y617 — the payload plane reaches the document, and a FINDING leads
    /// with its keyexpr and its offset in both renderings.
    ///
    /// Also pins the distinction the verdict rests on: a contradiction does
    /// NOT make the capture incomplete. The bytes were read perfectly; what is
    /// wrong is the publisher's claim about them.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_payload_contradiction_is_a_finding_and_not_an_incompleteness() {
        use crate::payload::tests_support as fx;

        let d = fx::dissect_pushes(&[
            ("app/good", 5, b"{\"ok\":1}".to_vec()),
            ("app/bad", 5, b"nope".to_vec()),
        ]);
        let census = crate::payload::payloads(&d);
        assert_eq!(
            census.contradictions().len(),
            1,
            "the fixture must be short"
        );

        let r = CaptureReport::of(&d).with_payloads(&census);
        assert!(r.is_complete(), "a finding is not a hole: {}", r.to_json());

        let json = r.to_json();
        assert!(json.contains("\"not_as_declared\":1"), "{json}");
        assert!(json.contains("\"app/bad\""), "{json}");
        assert!(
            json.contains("\"gaps\":{\"halted_batches\":0"),
            "structural: {json}"
        );

        let text = r.to_text();
        assert!(
            text.contains("FINDING: app/bad declared application/json"),
            "{text}"
        );
        assert!(text.contains("is not JSON at byte 0"), "{text}");
    }

    /// R311y618 (§1.1q) — ONE selector, THREE planes, and each plane's document
    /// says what that selector could not judge about IT.
    ///
    /// The failure this refuses is the one R311y616 shipped with: a reader
    /// narrowed a report to a topic, the throughput table honestly reported its
    /// undecided count, and the exchange and payload tables beside it silently
    /// answered about the WHOLE capture. Two of the three numbers on the page
    /// were about a different question than the one asked.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn one_selector_narrows_every_plane_of_the_report() {
        use crate::exchange::tests as fx;

        // A capture with an exchange and a payload on each of two topics, plus
        // one record whose alias this capture never bound.
        let d = fx::dissect(&[
            (
                true,
                Some(10),
                fx::request_query(1, fx::sender_space(0, Some("demo/keep"))),
            ),
            (
                false,
                Some(20),
                fx::response_reply(1, fx::sender_space(0, Some("demo/keep")), b"kept"),
            ),
            (false, Some(40), fx::response_final(1)),
            (
                true,
                Some(50),
                fx::request_query(2, fx::sender_space(0, Some("other/drop"))),
            ),
            (
                false,
                Some(55),
                fx::response_reply(2, fx::sender_space(0, Some("other/drop")), b"dropped!"),
            ),
            (false, Some(60), fx::response_final(2)),
            (
                true,
                Some(90),
                fx::request_query(3, fx::sender_space(42, None)),
            ),
        ]);

        let filter = crate::filter::Filter::parse("key == demo/keep").expect("compiles");
        let throughput = crate::agg::aggregate_where(&d, &filter);
        let exchanges = crate::exchange::exchanges_where(&d, &filter);
        let payloads = crate::payload::payloads_where(&d, &filter);

        // The control FIRST: unfiltered, every plane answers about everything.
        let all_throughput = crate::agg::aggregate(&d);
        let all_exchanges = crate::exchange::exchanges(&d);
        let all_payloads = crate::payload::payloads(&d);
        let all = CaptureReport::of(&d)
            .with_throughput(&all_throughput)
            .with_exchanges(&all_exchanges)
            .with_payloads(&all_payloads);
        assert_eq!(all_exchanges.requests(), 3, "the fixture must be wide");
        assert_eq!(all_exchanges.unclosed(), 1);
        // R311y725 (N2) — the unanswered query is a leg of the verdict, and it
        // is named here because nothing else named it. The exchange plane is
        // attached ALONE so the reason cannot be another plane's.
        let exchanges_alone = CaptureReport::of(&d)
            .with_exchanges(&all_exchanges)
            .reasons();
        assert!(
            exchanges_alone.contains(&VerdictReason::ExchangesUnclosed),
            "{exchanges_alone:?}"
        );
        // R311y727 (N19) — the whole list, so this witness also holds the
        // other exchange legs QUIET rather than only naming its own.
        assert_eq!(
            exchanges_alone,
            alloc::vec![
                VerdictReason::ExchangeGaps,
                VerdictReason::ExchangesUnclosed,
            ],
            "MEASURED, not assumed: this fixture also orphans a response, so \
             the plane is short two ways and the pin has to name both"
        );
        assert_eq!(all_payloads.payloads(), 2);
        assert!(all.to_text().contains("other/drop"));

        assert_eq!(exchanges.requests(), 1, "one exchange survived");
        assert_eq!(payloads.payloads(), 1, "one payload survived");
        assert_eq!(
            exchanges.selection().undecided,
            1,
            "the unbound alias is undecidable for the exchange plane too"
        );
        assert_eq!(
            exchanges.unclosed(),
            0,
            "the unclosed exchange was the undecided one, and a suppressed \
             exchange is not reported as a loss of this table"
        );

        let r = CaptureReport::of(&d)
            .with_throughput(&throughput)
            .with_exchanges(&exchanges)
            .with_payloads(&payloads);

        let json = r.to_json();
        // Three selection objects, structurally, one per plane.
        assert_eq!(
            json.matches("\"selection\":").count(),
            3,
            "every plane carries its own selection: {json}"
        );
        assert!(
            json.contains("\"complete\":false"),
            "an undecided exchange makes the page a floor: {json}"
        );
        assert!(
            !json.contains("\"other/drop\""),
            "a rejected topic must not appear in any plane's rows: {json}"
        );

        let text = r.to_text();
        assert!(text.contains("1 exchange(s) matched"), "{text}");
        assert!(text.contains("payloads: 1 judged"), "{text}");
        assert!(
            text.contains("selection: 1 matched, 1 rejected, 0 UNDECIDED"),
            "the payload plane's own line, in records: {text}"
        );
    }

    /// R311y618 — each plane's undecided count reaches the verdict ON ITS OWN.
    ///
    /// The test above cannot see this and a falsification proved it: its
    /// throughput plane is undecided too, so deleting the exchange leg from
    /// [`crate::report::CaptureReport::is_complete`] changed nothing and the suite stayed
    /// green. Here each plane is the ONLY one on the page, so the leg under
    /// test is the only thing that can produce the verdict — the shape §7.14
    /// names, reached by putting one plane on a page rather than by trusting a
    /// page that has three.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn one_undecided_plane_makes_the_page_a_floor_when_it_is_the_only_plane() {
        use crate::exchange::tests as fx;

        // Every record travels under an alias this capture never bound, so a
        // `key` term is undecidable for all of them — and NOTHING else about
        // the capture is short.
        let d = fx::dissect(&[
            (
                true,
                Some(10),
                fx::request_query(1, fx::sender_space(42, None)),
            ),
            (
                false,
                Some(20),
                fx::response_reply(1, fx::sender_space(42, None), b"x"),
            ),
            (false, Some(30), fx::response_final(1)),
        ]);
        let filter = crate::filter::Filter::parse("key == demo/keep").expect("compiles");

        let exchanges = crate::exchange::exchanges_where(&d, &filter);
        assert_eq!(exchanges.selection().undecided, 1);
        assert!(
            exchanges.gaps().is_clean() && exchanges.unread().is_clean(),
            "the selection must be the ONLY shortfall: {:?}",
            exchanges.gaps()
        );
        assert_eq!(exchanges.unclosed(), 0);
        let r = CaptureReport::of(&d).with_exchanges(&exchanges);
        assert!(
            !r.is_complete(),
            "an exchange the selector could not judge is missing from the rows"
        );
        // R311y725 (N2) — named. The assertions above establish that the
        // selection is the plane's ONLY shortfall, so the list is exactly one.
        assert_eq!(
            r.reasons(),
            alloc::vec![VerdictReason::ExchangeUndecided],
            "{}",
            r.to_text()
        );

        let payloads = crate::payload::payloads_where(&d, &filter);
        assert_eq!(payloads.selection().undecided, 1);
        assert!(payloads.gaps().is_clean());
        let r = CaptureReport::of(&d).with_payloads(&payloads);
        assert!(
            !r.is_complete(),
            "a payload the selector could not judge is missing from the census"
        );
        assert_eq!(
            r.reasons(),
            alloc::vec![VerdictReason::PayloadUndecided],
            "{}",
            r.to_text()
        );

        // The control: unfiltered, NOTHING is undecided on either plane — the
        // identity filter has no question it cannot answer. The page is still
        // not complete, and deliberately so: unfiltered, the unbound alias
        // becomes an `unattributed_requests` gap instead. Asserting
        // completeness here would have been asserting the wrong fact, which is
        // what a falsification run surfaced.
        let all_exchanges = crate::exchange::exchanges(&d);
        let all_payloads = crate::payload::payloads(&d);
        assert!(all_exchanges.selection().is_decisive());
        assert!(all_payloads.selection().is_decisive());
        assert_eq!(
            all_exchanges.gaps().unattributed_requests,
            1,
            "unfiltered, the same shortfall is reported as a GAP rather than as \
             an undecided selection"
        );
    }

    /// A latency nobody could measure prints as `unmeasured` and serialises as
    /// `null` — never as `0`, in either rendering. The export half of the
    /// anti-fabrication rule `LatencySamples` exists for.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn an_unmeasured_latency_is_null_in_json_and_named_in_text() {
        use crate::exchange::tests as fx;

        let d = fx::dissect(&[
            (
                true,
                None,
                fx::request_query(2, fx::sender_space(0, Some("q/untimed"))),
            ),
            (false, None, fx::response_final(2)),
        ]);
        let exchanges = crate::exchange::exchanges(&d);
        assert_eq!(exchanges.completed(), 1, "it correlated");

        let r = CaptureReport::of(&d).with_exchanges(&exchanges);
        let json = r.to_json();
        assert!(
            json.contains("\"completion\":{\"count\":0,\"min_ms\":null,\"max_ms\":null,\"mean_ms\":null,\"total_ms\":0}"),
            "{json}"
        );
        assert!(
            !json.contains("\"mean_ms\":0"),
            "no fabricated zero: {json}"
        );
        assert!(r.to_text().contains("unmeasured"), "{}", r.to_text());
    }

    /// R311y715 (§C G6) — and its MEASURED counterpart, which is where the
    /// denominator lives.
    ///
    /// A mean is a ratio, and the test above pins only the case where there is
    /// none. The population it was taken over is printed beside it ("over N")
    /// for exactly the reason this workspace states denominators at all — and
    /// nothing bound that N: rendering `l.count() + 1` left all 394 tests
    /// green, so the page could tell a reader a two-sample mean was taken over
    /// three while the JSON beside it said two.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_measured_latency_states_the_population_it_was_taken_over() {
        use crate::exchange::tests as fx;

        // Two exchanges, 20ms and 40ms: a mean of 30 over a count of 2, and
        // every figure distinct from every other so no assertion can be
        // satisfied by the wrong one.
        let d = fx::dissect(&[
            (
                true,
                Some(1_000),
                fx::request_query(1, fx::sender_space(0, Some("q/one"))),
            ),
            (false, Some(1_020), fx::response_final(1)),
            (
                true,
                Some(2_000),
                fx::request_query(2, fx::sender_space(0, Some("q/two"))),
            ),
            (false, Some(2_040), fx::response_final(2)),
        ]);
        let exchanges = crate::exchange::exchanges(&d);
        assert_eq!(exchanges.completed(), 2, "both correlated");

        let r = CaptureReport::of(&d).with_exchanges(&exchanges);
        let text = r.to_text();
        let json = r.to_json();
        assert!(
            text.contains("30ms mean over 2 (min 20, max 40)"),
            "the page states the mean WITH the population it is of: {text}"
        );
        assert!(
            json.contains("\"completion\":{\"count\":2,\"min_ms\":20,\"max_ms\":40,\"mean_ms\":30,\"total_ms\":60}"),
            "and the export states the same five figures: {json}"
        );
    }

    /// R311y668 (§1.2a) — THE COMPOSITION SEAM. `to_json` is exactly its own
    /// body inside one pair of braces, and the body carries neither of them.
    ///
    /// This is what a caller with more keys to add depends on. R311y667's
    /// analyzer added its flow list by popping the rendering's final `}` and
    /// pushing one back, guarded by `ends_with('}')` — correct for this renderer
    /// and not composition: a report that grew a trailing newline would fail the
    /// guard, take the fallback, and silently emit the TWO-DOCUMENT shape that
    /// round existed to remove. The pin makes the seam a contract rather than an
    /// observation, so a `to_json` that later wrapped its body differently fails
    /// HERE instead of downstream in a consumer's parser.
    #[test]
    fn the_json_body_is_exactly_the_document_without_its_braces() {
        let d = crate::Dissection::new();
        let r = CaptureReport::of(&d);

        let mut body = String::new();
        r.json_fields(&mut body);
        assert_eq!(
            r.to_json(),
            alloc::format!("{{{body}}}"),
            "the document must be the body braced once and nothing else"
        );
        // Neither end, and neither a separator: a body that opened or closed an
        // object, or that carried a leading / trailing comma, would compose into
        // malformed JSON at every caller rather than at one.
        assert!(
            !body.starts_with('{') && !body.ends_with('}'),
            "the body must not brace itself: {body}"
        );
        assert!(
            !body.starts_with(',') && !body.ends_with(','),
            "and the caller owns the separator, which is the only arrangement \
             in which appending nothing is also valid: {body}"
        );
    }

    /// R311y869 (§1.1f) — THE INTEREST PLANE, ON A PAGE BY ITSELF.
    ///
    /// `solo_plane_page_lint` demanded this and was right to: a page carrying a
    /// second plane would let the other one produce every line asserted here,
    /// and this plane's whole output could be severed with the suite still
    /// green. So `with_interests` is the ONLY attachment.
    ///
    /// What it pins is the pair of FINDINGS, which is the part of this plane a
    /// listing could not deliver: a declaration nothing was published under,
    /// and traffic no declaration matched. Both renderings, because one fact
    /// rendered in two places is one fact that can drift.
    ///
    /// Gated on the wildcard feature for the reason `interest`'s own tests are:
    /// without a matcher this fixture's `demo/**` is UNDECIDABLE, which is a
    /// different page and is asserted there.
    #[cfg(all(feature = "network-codecs", feature = "filter-wildcards"))]
    #[test]
    fn an_interest_plane_alone_names_both_findings_in_both_renderings() {
        let declare = |ke: &str| {
            let d = wz_session_core::declare_build::build_declare_subscriber(1, 0, Some(ke))
                .expect("the production builder")
                .try_as_borrowed()
                .expect("re-borrow")
                .encode_to_vec();
            let mut w = alloc::vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
            w.extend_from_slice(&d);
            w
        };
        let mut d = crate::Dissection::new();
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::udp_packet(
                [10, 0, 0, 1],
                50000,
                [10, 0, 0, 2],
                7447,
                &declare("nothing/**"),
            ),
        );
        let mut unit = alloc::vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
        unit.extend_from_slice(&crate::datagram_tests::push(
            crate::datagram_tests::sender_space(0, Some("demo/temp")),
            b"hello",
        ));
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            1,
            &crate::datagram_tests::udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 50000, &unit),
        );
        // R311y870 — the QUESTION, on the same page: A asks B for its
        // QUERYABLES and B says nothing at all.
        let mut unit = alloc::vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
        unit.extend_from_slice(
            &wz_session_core::interest_build::build_interest_queryables(
                4,
                true,
                false,
                0,
                Some("svc/**"),
            )
            .expect("the production interest builder")
            .try_as_borrowed()
            .expect("re-borrow")
            .encode_to_vec(),
        );
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            2,
            &crate::datagram_tests::udp_packet([10, 0, 0, 1], 50000, [10, 0, 0, 2], 7447, &unit),
        );

        // THE POPULATION, before anything is asked of it: one declaration read,
        // one request read and one row measured. A capture that carried none of
        // them would satisfy every "the finding is printed" claim below by
        // printing a zero.
        let census = crate::interest::interests(&d);
        let table = crate::agg::aggregate(&d);
        assert_eq!(census.interests().len(), 1, "one declaration was read");
        assert_eq!(census.requests().len(), 1, "and one request");
        assert_eq!(table.rows().len(), 1, "and one keyexpr carried traffic");
        let coverage = census.coverage(&table);

        let page = CaptureReport::of(&d).with_interests(&census, &coverage);

        let text = page.to_text();
        assert!(
            text.contains("declared interest: 1 (subscriber 1, queryable 0, liveliness 0)"),
            "the plane's own header is missing: {text}"
        );
        assert!(
            text.contains("FINDING: subscriber nothing/** matched NO traffic in this capture"),
            "a declaration nobody published under is THE finding: {text}"
        );
        assert!(
            text.contains("1 keyexpr(s) carried traffic no declaration here matches"),
            "and the mirror finding is the other half: {text}"
        );
        assert!(
            !text.contains("AT MOST"),
            "every declaration here was judged, so neither count is a floor: \
             {text}"
        );

        let json = page.to_json();
        assert!(
            json.contains("\"keyexpr\":\"nothing/**\",\"open\":true,\"covers\":0"),
            "the export carries the same declaration: {json}"
        );
        assert!(
            json.contains("\"silent\":1") && json.contains("\"unclaimed\":1"),
            "and the same two findings: {json}"
        );
        assert!(
            json.contains("\"unclaimed_exact\":true"),
            "stated as exact rather than as a floor: {json}"
        );

        // R311y870 — the QUESTION half in both renderings, and the phrase a
        // reader acts on rather than the flag letters: "queryables under
        // svc/**" is the ask, and a rendering that printed `Q=1 R=1` beside a
        // keyexpr column would make them reassemble it.
        // `keyexprs+queryables` and not `queryables`: every builder in
        // `interest_build` composes `KE | <kinds> | R | N | M`, so a wz-emitted
        // interest ALWAYS carries the K bit. Asserted as it is rather than as
        // it reads more nicely, because the alternative is a test that pins
        // this reader's idea of the message instead of the sender's.
        assert!(
            text.contains(
                "current interest 4 for keyexprs+queryables under svc/** -- \
                 0 answer(s), not closed"
            ),
            "the request line is missing: {text}"
        );
        assert!(
            text.contains(
                "FINDING: interest 4 for keyexprs+queryables under svc/** got \
                 NO answer at all"
            ),
            "and the finding with it: {text}"
        );
        assert!(
            json.contains(
                "\"asker\":\"a\",\"id\":4,\"mode\":\"current\",\"answers\":0,\
                 \"mismatched\":0,\"unjudged_answers\":0,\"answers_in_scope\":0,\
                 \"closed\":false,\"cancelled\":false,\"keyexpr\":\"svc/**\""
            ),
            "the export carries the same request: {json}"
        );
        assert!(
            json.contains(
                "\"unanswered\":1,\"unclosed\":0,\"mismatched\":0,\
                 \"unjudged_answers\":0,\"orphan_answers\":0"
            ),
            "and the same verdict: {json}"
        );
        assert!(
            json.contains("\"solicited_by\":null"),
            "the declaration here was spontaneous, and null says so rather than \
             the field being absent: {json}"
        );
    }

    /// R311y871 (§1.1f) — THE ANSWER THAT WAS NOT AN ANSWER, ON A PAGE BY
    /// ITSELF.
    ///
    /// A peer answers interest 4 -- restricted to `svc/**` -- with a
    /// subscriber for `other/thing`, then closes the dump. Every count on the
    /// page agrees the exchange completed: one answer, dump closed, nothing
    /// unanswered. The finding is that the answer was to a different question,
    /// and before this round no rendering said so.
    ///
    /// BOTH renderings, on this file's own rule, and the same page pins the
    /// CONTROL: `answers` stays 1 while `answers_in_scope` is 0, so a change
    /// that "fixed" this by not counting the reply would fail here rather than
    /// quietly turning a divergence into a silence.
    ///
    /// `with_interests` is the only attachment, per `solo_plane_page_lint`.
    #[cfg(all(feature = "network-codecs", feature = "filter-wildcards"))]
    #[test]
    fn an_answer_to_a_different_question_is_named_in_both_renderings() {
        let framed = |body: alloc::vec::Vec<u8>| {
            let mut w = alloc::vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
            w.extend_from_slice(&body);
            w
        };
        let mut d = crate::Dissection::new();
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::udp_packet(
                [10, 0, 0, 1],
                50000,
                [10, 0, 0, 2],
                7447,
                &framed(
                    wz_session_core::interest_build::build_interest_subscribers(
                        4,
                        true,
                        false,
                        0,
                        Some("svc/**"),
                    )
                    .expect("the production interest builder")
                    .try_as_borrowed()
                    .expect("re-borrow")
                    .encode_to_vec(),
                ),
            ),
        );
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            1,
            &crate::datagram_tests::udp_packet(
                [10, 0, 0, 2],
                7447,
                [10, 0, 0, 1],
                50000,
                &framed(
                    wz_session_core::declare_build::build_declare_subscriber_reply(
                        4,
                        "other/thing",
                    )
                    .expect("the production reply builder")
                    .try_as_borrowed()
                    .expect("re-borrow")
                    .encode_to_vec(),
                ),
            ),
        );
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            2,
            &crate::datagram_tests::udp_packet(
                [10, 0, 0, 2],
                7447,
                [10, 0, 0, 1],
                50000,
                &framed(
                    wz_session_core::declare_build::build_declare_final_reply(4)
                        .try_as_borrowed()
                        .expect("re-borrow")
                        .encode_to_vec(),
                ),
            ),
        );

        // THE POPULATION FIRST: one question, one answer, and the answer read.
        // Without this the assertions below could all be satisfied by a page
        // built over a capture that carried nothing.
        let census = crate::interest::interests(&d);
        assert_eq!(census.requests().len(), 1);
        assert_eq!(census.interests().len(), 1);
        assert_eq!(census.requests()[0].answers, 1);
        let table = crate::agg::aggregate(&d);
        let coverage = census.coverage(&table);

        let page = CaptureReport::of(&d).with_interests(&census, &coverage);
        let text = page.to_text();
        assert!(
            text.contains(
                "FINDING: interest 4 for keyexprs+subscribers under svc/** was \
                 answered with 1 declaration(s) it did not ask for"
            ),
            "the finding is missing: {text}"
        );
        assert!(
            text.contains("      subscriber other/thing"),
            "and WHICH declaration it was: {text}"
        );
        // THE CONTROL, on the same page: the exchange otherwise looks served,
        // which is precisely why the finding had to be its own line.
        assert!(
            !text.contains("got NO answer at all"),
            "this peer answered; it answered the wrong question: {text}"
        );
        assert!(
            !text.contains("never closed"),
            "and the dump WAS terminated: {text}"
        );
        assert!(
            !text.contains("could not be judged"),
            "the pattern was decidable, so nothing here is a floor: {text}"
        );

        let json = page.to_json();
        assert!(
            json.contains(
                "\"answers\":1,\"mismatched\":1,\"unjudged_answers\":0,\"answers_in_scope\":0"
            ),
            "the export carries the split rather than the raw count alone: {json}"
        );
        assert!(
            json.contains(
                "\"unanswered\":0,\"unclosed\":0,\"mismatched\":1,\
                 \"unjudged_answers\":0,\"orphan_answers\":0"
            ),
            "and the verdict names the finding beside the two it is not: {json}"
        );
    }

    /// R311y701 (§1.1f) — THE QUIC DECRYPTION PLANE, ON A PAGE BY ITSELF.
    ///
    /// R311y698 attached this plane and gave it two legs of the completeness
    /// verdict, and put neither on a page of its own. `solo_plane_page_lint`
    /// said so on hosted CI and nowhere else, which is exactly the gate's
    /// purpose: a page carrying a second plane produces the verdict from the
    /// other one, and either leg could be severed with every test still green.
    ///
    /// So the ONLY plane here is `with_quic_decryption`, and each leg is moved
    /// on its own: a flow nobody opened, the same flow opened, and a walk that
    /// stopped inside a flow that DID open — the last being the one a
    /// `flows_opened`-only verdict would call whole.
    #[test]
    fn a_quic_decryption_plane_alone_moves_the_verdict_and_both_renderings() {
        // A v1 Initial: a long header is EVIDENCE, so this flow needs no
        // `--quic` declaration and the population below is a measurement.
        let mut initial = alloc::vec![0xC0u8];
        initial.extend_from_slice(&1u32.to_be_bytes());
        initial.push(8);
        initial.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        initial.push(4);
        initial.extend_from_slice(&[8, 9, 10, 11]);
        initial.extend_from_slice(&[0x00, 0x29, 0x01]);
        initial.extend_from_slice(&[0xAA; 40]);

        let mut d = crate::Dissection::new();
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::udp_packet([10, 0, 0, 1], 50000, [10, 0, 0, 2], 7447, &initial),
        );

        // THE POPULATION, asserted before anything is asked of it. A capture
        // holding no QUIC flow would satisfy every `is_complete` claim below
        // vacuously — the "population of zero is green" shape this workspace
        // has measured more than once.
        assert_eq!(
            d.datagram_flows()
                .iter()
                .filter(|f| f.quic.is_some())
                .count(),
            1,
            "the long header must have established exactly one QUIC flow"
        );
        assert!(
            d.health().packets_skipped == 0 && !d.drops().any(),
            "and NOTHING else about this capture may be short, or the verdict \
             below would be produced by a cause this page is not about"
        );

        // No decryptor ran: the flow's zenoh is not in the totals.
        let bare = CaptureReport::of(&d);
        assert!(!bare.is_complete());
        assert!(
            bare.to_json().contains("\"decrypted\":false"),
            "{}",
            bare.to_json()
        );
        assert!(
            bare.to_text().contains("NOT DECRYPTED"),
            "{}",
            bare.to_text()
        );

        // A decryptor ran and opened nothing — same verdict, different sentence.
        let shut = crate::quic::QuicDecryption {
            flows_offered: 1,
            flows_opened: 0,
            packets: 1,
            packets_opened: 0,
            packets_no_keys: 1,
            packets_refused: 0,
            crypto_bytes: 0,
            stream_bytes: 0,
            datagram_bytes: 0,
            walks_stopped: 0,
            flows_identity_adopted: 0,
            framing: crate::quic::QuicStreamFeed::default(),
        };
        let r = CaptureReport::of(&d).with_quic_decryption(&shut);
        assert!(!r.is_complete(), "a flow offered and not opened is a floor");
        // R311y725 (N2) — BY NAME. `!is_complete()` is satisfied by any leg, so
        // a witness that only asserts it cannot tell its own reason from a
        // neighbour's, which is the state `verdict_reason_lint` measured this
        // enum into: thirteen of twenty-three legs were exercised and none of
        // them named.
        assert_eq!(
            r.reasons(),
            alloc::vec![VerdictReason::QuicFlowsUnopened],
            "the flow's own leg, and no other: {}",
            r.to_text()
        );
        assert!(
            r.to_text().contains("1 had no key for their space"),
            "and the reason a person acts on is the key log, not the capture: {}",
            r.to_text()
        );

        // Opened. THE LEG R311y698 ADDED: before it, this said incomplete.
        let open = crate::quic::QuicDecryption {
            flows_opened: 1,
            packets_opened: 1,
            packets_no_keys: 0,
            crypto_bytes: 41,
            ..shut
        };
        let r = CaptureReport::of(&d).with_quic_decryption(&open);
        assert!(
            r.is_complete(),
            "a flow whose every packet opened IS the rows: {}",
            r.to_text()
        );
        assert!(
            r.to_json().contains("\"decrypted\":true")
                && r.to_json().contains("\"flows_opened\":1"),
            "{}",
            r.to_json()
        );
        assert!(
            r.to_text().contains("1 of 1 packet(s) opened"),
            "{}",
            r.to_text()
        );

        // R311y705 — THE THIRD LEG, and the one this page existed to make
        // gateable: the flow opened, the walk finished, and the application
        // bytes it recovered were never decoded. `open` above carries only
        // `crypto_bytes` -- the TLS handshake inside QUIC, which carries no
        // zenoh -- which is exactly why it is still whole; add ONE application
        // byte and it is not.
        let unread = crate::quic::QuicDecryption {
            stream_bytes: 25,
            ..open
        };
        let r = CaptureReport::of(&d).with_quic_decryption(&unread);
        assert!(
            !r.is_complete(),
            "bytes a decryptor recovered and nothing read are a floor: {}",
            r.to_text()
        );
        assert!(
            r.to_text()
                .contains("25 application byte(s) were recovered and NOT decoded"),
            "and the reader is told in the rendering: {}",
            r.to_text()
        );
        // R311y728 (N18) — AND LITERALLY ONE BYTE, which the paragraph above
        // CLAIMS ("add ONE application byte and it is not") and no arm here
        // did: every one of them recovers 25 or 7. A guard reading `> 1` where
        // `> 0` was meant fires on all of them identically, so the boundary
        // sweep found this leg with nothing holding its threshold -- a reader
        // that quietly stopped reporting the single-byte shortfall would have
        // passed the whole suite.
        let single = crate::quic::QuicDecryption {
            stream_bytes: 1,
            ..open
        };
        let r = CaptureReport::of(&d).with_quic_decryption(&single);
        assert_eq!(
            r.reasons(),
            alloc::vec![VerdictReason::QuicBytesNobodyDecodes],
            "one recovered byte nobody read is a floor, and it is the whole of \
             this verdict: {}",
            r.to_text()
        );

        // The RFC 9221 half reaches the same verdict by the same rule -- zenoh's
        // quic-datagram link puts application bytes there and no reader takes
        // them out either.
        let unread = crate::quic::QuicDecryption {
            datagram_bytes: 7,
            ..open
        };
        assert!(!CaptureReport::of(&d)
            .with_quic_decryption(&unread)
            .is_complete());

        // And the SECOND leg, which `flows_opened` alone cannot carry: the flow
        // opened, and the walk stopped at a frame type this reader does not
        // know, so the stream is short by an unknown amount.
        let stopped = crate::quic::QuicDecryption {
            walks_stopped: 1,
            ..open
        };
        let r = CaptureReport::of(&d).with_quic_decryption(&stopped);
        assert!(
            !r.is_complete(),
            "a walk that stopped mid-packet is a shortfall in the rows even \
             where every flow opened: {}",
            r.to_text()
        );
        assert!(
            r.to_json().contains("\"walks_stopped\":1"),
            "{}",
            r.to_json()
        );
        // R311y725 (N2) — named, and ALONE: `open` opened every flow and
        // decoded every byte it recovered, so the walk is the only shortfall.
        assert_eq!(
            r.reasons(),
            alloc::vec![VerdictReason::QuicWalkStopped],
            "a stopped walk is its own leg: {}",
            r.to_text()
        );
    }

    /// R311y709 (§1.2a) — RECOVERED AGAINST FED, ON THE TWO SHAPES THAT ANSWER
    /// THE REGISTER'S QUESTION.
    ///
    /// The open question was "R311y705 established the value is non-zero for
    /// QUIC by construction; what nobody has measured is whether it is non-zero
    /// anywhere else". So both arms are here and the second is not decoration:
    /// a capture where every recovered byte IS fed is what makes the QUIC number
    /// a difference rather than a property of the counter.
    ///
    /// The QUIC arm pins EXACT numbers because they are this reader's own
    /// arithmetic — the payload length it recovered, and the zero it fed — and
    /// an inequality there would pass on an instrument that counted nothing.
    #[test]
    fn a_quic_flow_feeds_nothing_and_a_zenoh_one_feeds_everything() {
        // A v1 Initial: recognised, counted, and handed to no decoder.
        let mut initial = alloc::vec![0xC0u8];
        initial.extend_from_slice(&1u32.to_be_bytes());
        initial.push(8);
        initial.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        initial.push(4);
        initial.extend_from_slice(&[8, 9, 10, 11]);
        initial.extend_from_slice(&[0xAA; 40]);

        let mut quic = crate::Dissection::new();
        quic.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::udp_packet([10, 0, 0, 1], 50000, [10, 0, 0, 2], 7447, &initial),
        );
        assert_eq!(
            quic.datagram_flows()
                .iter()
                .filter(|f| f.quic.is_some())
                .count(),
            1,
            "the population: without a QUIC flow the numbers below are about nothing"
        );
        let r = quic.byte_residue();
        assert_eq!(
            r.recovered,
            initial.len() as u64,
            "every byte of the datagram was recovered"
        );
        assert_eq!(
            r.fed, 0,
            "and none of them reached a decoder -- R311y705's finding as a number"
        );
        assert_eq!(r.unfed(), initial.len() as u64);
        assert!(
            CaptureReport::of(&quic)
                .to_text()
                .contains("reached no decoder"),
            "and a person is told: {}",
            CaptureReport::of(&quic).to_text()
        );

        // THE OTHER AXIS. A zenoh datagram on a flow nothing has classified as
        // QUIC goes to the observer whole.
        let mut zenoh = crate::Dissection::new();
        let payload = [0x01u8, 0x05, 0x00, 0x01, 0x02];
        zenoh.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::udp_packet([10, 0, 0, 1], 50000, [10, 0, 0, 2], 7447, &payload),
        );
        assert_eq!(
            zenoh.datagram_flows().len(),
            1,
            "the population on this arm too"
        );
        assert!(
            zenoh.datagram_flows()[0].quic.is_none(),
            "this flow must NOT be QUIC or the two arms are the same test"
        );
        let r = zenoh.byte_residue();
        assert_eq!(r.recovered, payload.len() as u64);
        assert_eq!(
            r.fed,
            payload.len() as u64,
            "a decoder saw all of it, so the difference is zero"
        );
        assert_eq!(r.unfed(), 0);
        assert!(
            !CaptureReport::of(&zenoh)
                .to_text()
                .contains("reached no decoder"),
            "and no sentence is printed: {}",
            CaptureReport::of(&zenoh).to_text()
        );
        assert!(
            CaptureReport::of(&zenoh)
                .to_json()
                .contains("\"residue\":{\"recovered\":5,\"fed\":5,\"unfed\":0}"),
            "the JSON carries the key even at zero -- absent cannot say 'none': {}",
            CaptureReport::of(&zenoh).to_json()
        );
    }

    /// R311y708 (§1.2a) — A VERSION NOTHING HERE CAN CHECK, SAID OUT LOUD IN
    /// BOTH RENDERINGS.
    ///
    /// The two captures differ in FOUR BYTES — the version word — and in nothing
    /// else, which is what makes this a difference rather than a description.
    /// Both axes are asserted because either alone is satisfiable by a wrong
    /// implementation: a reader that printed the caveat unconditionally passes
    /// the v2 arm, and one that never printed it passes the v1 arm.
    ///
    /// The population assertion in the middle is the point of the round. The
    /// alternative this design rejected was DELETING `0x6b33_43cf`, and its cost
    /// is exactly the line that asserts the v2 capture still holds a QUIC flow:
    /// without the entry that count is zero, the datagram goes to the zenoh
    /// decoder, and the caveat is moot because there is nothing left to caveat.
    #[test]
    fn a_version_only_a_document_names_is_said_in_both_renderings() {
        fn capture_at(version: u32) -> crate::Dissection {
            let mut initial = alloc::vec![0xC0u8];
            initial.extend_from_slice(&version.to_be_bytes());
            initial.push(8);
            initial.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
            initial.push(4);
            initial.extend_from_slice(&[8, 9, 10, 11]);
            initial.extend_from_slice(&[0xAA; 40]);

            let mut d = crate::Dissection::new();
            d.push_packet(
                crate::link::LINKTYPE_ETHERNET,
                0,
                &crate::datagram_tests::udp_packet(
                    [10, 0, 0, 1],
                    50000,
                    [10, 0, 0, 2],
                    7447,
                    &initial,
                ),
            );
            d
        }

        let checked = capture_at(0x0000_0001);
        let unchecked = capture_at(0x6b33_43cf);

        // THE POPULATION, on both arms. A capture holding no QUIC flow renders
        // no QUIC line at all, and every `!contains` below would then pass for
        // the wrong reason.
        for (name, d) in [("v1", &checked), ("v2", &unchecked)] {
            let flows: alloc::vec::Vec<_> =
                d.datagram_flows().iter().filter_map(|f| f.quic).collect();
            assert_eq!(
                flows.len(),
                1,
                "{name}: the long header must have established exactly one QUIC flow"
            );
            assert!(
                flows[0].version.is_some(),
                "{name}: and that flow must have settled on a version"
            );
        }

        let (t_unchecked, j_unchecked) = (
            CaptureReport::of(&unchecked).to_text(),
            CaptureReport::of(&unchecked).to_json(),
        );
        assert!(
            t_unchecked.contains(
                "recognised at version(s) 0x6b3343cf, which no implementation in \
                 this build names"
            ),
            "the person-facing rendering must carry the caveat and the word: \
             {t_unchecked}"
        );
        assert!(
            j_unchecked.contains("\"versions_document_only\":[\"0x6b3343cf\"]"),
            "and the machine-facing one must carry the SET, not a flag: {j_unchecked}"
        );

        let (t_checked, j_checked) = (
            CaptureReport::of(&checked).to_text(),
            CaptureReport::of(&checked).to_json(),
        );
        assert!(
            t_checked.contains("QUIC: 1 flow(s)"),
            "the v1 arm must still report its flow: {t_checked}"
        );
        assert!(
            !t_checked.contains("no implementation in this build names"),
            "and must NOT caveat a version quinn-proto names: {t_checked}"
        );
        assert!(
            j_checked.contains("\"versions_document_only\":[]"),
            "the JSON says empty rather than omitting the key -- a consumer must \
             be able to tell 'checked' from 'this build has no such field': \
             {j_checked}"
        );
    }

    /// R311y749 (debt-carry-N6) — EVERY `QuicStreamFeed` FIELD REACHES THE
    /// EXPORT, and a new one cannot be added without deciding.
    ///
    /// MEASURED: six of the seven were emitted and `appends_not_walked` was
    /// not, so the single counter that says a `--fields` listing is SHORT could
    /// not be read by a consumer of this export at all. That is the failure the
    /// emit's own comment argues against one line above it — "25 bytes
    /// recovered" and "25 bytes recovered, read, and yielding nothing" are
    /// different findings — applied to the field it forgot.
    ///
    /// Two mechanisms, because either alone is weak. The exhaustive
    /// destructuring makes a NEW field a COMPILE error rather than a silent
    /// omission (the shape `every_quic_stream_field_is_classified` already uses
    /// one module over). The DISTINCT VALUES make the assertion about the
    /// pairing rather than about presence: a render that emitted the right keys
    /// with each other's values would satisfy a key-only check.
    #[test]
    fn every_quic_stream_feed_field_reaches_the_export() {
        let feed = crate::quic::QuicStreamFeed {
            bytes_fed: 11,
            messages: 22,
            flow_absent: 33,
            streams_refused: 44,
            handshake_offers: 55,
            bytes_undecoded: 66,
            appends_not_walked: 77,
            messages_straddling_offers: 88,
        };
        // The compile-time half: a field added to `QuicStreamFeed` and not
        // named here does not compile, so the author adding it is the one who
        // decides whether the export carries it.
        let crate::quic::QuicStreamFeed {
            bytes_fed,
            messages,
            flow_absent,
            streams_refused,
            handshake_offers,
            bytes_undecoded,
            appends_not_walked,
            messages_straddling_offers,
        } = feed;

        let d = crate::Dissection::default();
        let quic = crate::quic::QuicDecryption {
            framing: feed,
            ..crate::quic::QuicDecryption::default()
        };
        let json = CaptureReport::of(&d).with_quic_decryption(&quic).to_json();

        for (key, value) in [
            ("bytes_fed", bytes_fed),
            ("messages", messages),
            ("flow_absent", flow_absent),
            ("streams_refused", streams_refused),
            ("handshake_offers", handshake_offers),
            ("bytes_undecoded", bytes_undecoded),
            ("appends_not_walked", appends_not_walked),
            ("messages_straddling_offers", messages_straddling_offers),
        ] {
            assert!(
                json.contains(&alloc::format!("\"{key}\":{value}")),
                "the export must carry {key} with ITS OWN value {value}: {json}"
            );
        }
    }

    /// Ethernet + IPv4 carrying an arbitrary protocol number.
    fn eth_ipv4_proto(proto: u8, body: &[u8]) -> alloc::vec::Vec<u8> {
        let mut ip = alloc::vec::Vec::new();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&((20 + body.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.push(64);
        ip.push(proto);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(body);

        let mut eth = alloc::vec![0u8; 12];
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// Ethernet + IPv6 whose next header is the one asked for.
    fn eth_ipv6_next(next_header: u8) -> alloc::vec::Vec<u8> {
        let mut ip = alloc::vec::Vec::new();
        ip.extend_from_slice(&0x6000_0000u32.to_be_bytes());
        ip.extend_from_slice(&8u16.to_be_bytes());
        ip.push(next_header);
        ip.push(64);
        ip.extend_from_slice(&[0u8; 16]);
        ip.extend_from_slice(&[0u8; 16]);
        ip.extend_from_slice(&[0u8; 8]);

        let mut eth = alloc::vec![0x02u8; 12];
        eth.extend_from_slice(&0x86ddu16.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    /// PROBE — every skip this reader COUNTS must reach the surface that claims
    /// to hold every loss counter.
    #[test]
    fn every_skip_reason_the_reader_counts_reaches_the_health_surface() {
        let mut d = crate::Dissection::new();
        let mut arp = alloc::vec![0u8; 12];
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.extend_from_slice(&[0u8; 46]);
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &arp);
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            1,
            &eth_ipv4_proto(1, &[0u8; 8]),
        );
        let mut short = alloc::vec![0u8; 12];
        short.extend_from_slice(&[0x08, 0x00]);
        short.extend_from_slice(&[0x45, 0, 0, 40, 0]);
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 2, &short);
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 3, &eth_ipv6_next(50));
        // R311y862 — the fixture grows with the census it is measuring. A
        // rendering leg that only ever sees the reasons that existed when it
        // was written is the shape this test exists to refuse.
        //
        // R311y864 MOVED this leg rather than dropping it, which is the point
        // of a pin: 47 used to be a tunnel with no parser and is now walked, so
        // the packet that stands for "no parser" had to become one that still
        // is — 50, ESP, whose remainder is encrypted. GRE gets its own packet
        // below, under the counter it now reaches.
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            4,
            &eth_ipv4_proto(50, &[0u8; 8]),
        );
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            5,
            &eth_ipv4_proto(47, &gre(0x0000, 0x6558, &[], &[0u8; 8])),
        );
        d.finish();

        let sk = d.skip_census();
        assert_eq!(
            (
                sk.not_ip,
                sk.not_transport,
                sk.truncated,
                sk.ipv6_extension_chain,
                sk.unwalked_encapsulation,
                sk.gre_payload
            ),
            (1, 1, 1, 1, 1, 1),
            "the fixture must reach six DIFFERENT reasons: {sk:?}"
        );

        // CONTROL: the counters exist and the capture document already carries
        // them, so what the legs below measure is a RENDERING that omits what
        // the reader already knows.
        let json = CaptureReport::of(&d).to_json();
        for key in [
            "not_ip",
            "not_transport",
            "truncated",
            "ipv6_extension_chain",
            "unwalked_encapsulation",
            "gre_payload",
        ] {
            assert!(
                json.contains(&alloc::format!("\"{key}\":1")),
                "the capture document already carries {key}: {json}"
            );
        }

        // The COUNT is asserted beside the NAME. A rendering that printed the
        // nine labels with a total under them would satisfy a name-only leg
        // while telling a reader nothing about which reason fired.
        let health = health_text(&d);
        for label in [
            "1 not IP",
            "1 terminate at the host",
            "1 truncated",
            "1 IPv6 extension chain",
            "1 tunnel not opened",
            "tunnel IP protocol(s) not opened: 50",
            "1 GRE payload not walked",
            "GRE payload ethertype(s) not walked: 0x6558",
            "terminate at the host: 1",
            "reader skipped: 6 packet(s)",
        ] {
            assert!(
                health.contains(label),
                "health text must name `{label}` rather than fold it into one total: {health}"
            );
        }

        let hjson = health_json(&d);
        for key in [
            "\"total\":6",
            "\"not_ip\":1",
            "\"not_transport\":1",
            "\"truncated\":1",
            "\"ipv6_extension_chain\":1",
            "\"unwalked_encapsulation\":1",
            "\"gre_payload\":1",
            "\"encapsulations\":[50]",
            "\"not_transport_protos\":[1]",
            "\"gre_payloads\":[25944]",
        ] {
            assert!(
                hjson.contains(key),
                "the health document must carry {key}: {hjson}"
            );
        }

        // The capture SUMMARY names them too -- the surface an operator reads
        // without asking for `--health`, and the one that used to print a bare
        // total plus a line about link types.
        let text = CaptureReport::of(&d).to_text();
        assert!(
            text.contains("1 truncated")
                && text.contains("1 terminate at the host")
                && text.contains("1 tunnel not opened"),
            "the capture summary must name the reasons it skipped for: {text}"
        );
    }

    /// PROBE — the two classes must reach the VERDICT differently, because they
    /// answer different questions about the same capture.
    ///
    /// An Ethernet segment carries ARP. Every capture taken on one therefore
    /// skips packets, and a verdict that fires on `packets_skipped > 0` calls
    /// every real capture a floor — which is the same as having no verdict, and
    /// it takes the exit code with it. A capture whose packets were TRUNCATED
    /// is the case the verdict exists for: the bytes were on the wire, the
    /// snaplen cut them, and no row holds them.
    #[test]
    fn furniture_and_missing_bytes_are_not_the_same_verdict() {
        let mut arp_only = crate::Dissection::new();
        let mut arp = alloc::vec![0u8; 12];
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.extend_from_slice(&[0u8; 46]);
        arp_only.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &arp);
        arp_only.finish();
        assert_eq!(
            arp_only.skip_census().not_this_protocol(),
            1,
            "the fixture must skip for a furniture reason"
        );
        assert_eq!(arp_only.skip_census().bytes_absent(), 0, "and for no other");
        assert!(
            CaptureReport::of(&arp_only).is_complete(),
            "ARP on a segment is not a shortfall in the rows: {:?}",
            CaptureReport::of(&arp_only).reasons()
        );

        let mut cut = crate::Dissection::new();
        let mut short = alloc::vec![0u8; 12];
        short.extend_from_slice(&[0x08, 0x00]);
        short.extend_from_slice(&[0x45, 0, 0, 40, 0]);
        cut.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &short);
        cut.finish();
        assert_eq!(
            cut.skip_census().bytes_absent(),
            1,
            "the fixture must skip for a bytes-absent reason"
        );
        assert!(
            !CaptureReport::of(&cut).is_complete(),
            "bytes the capture holds and no row does ARE a floor"
        );
        // The WHOLE list, not a containment claim. A `contains` leg holds while
        // every other guard fires too, so it cannot see one that became too
        // wide -- which is the direction this round moved in and therefore the
        // direction the assertion has to watch.
        assert_eq!(
            CaptureReport::of(&cut).reasons(),
            alloc::vec![VerdictReason::PacketsSkipped],
            "the fixture must state exactly this reason: {}",
            CaptureReport::of(&cut).to_text()
        );
    }

    /// Ethernet + IPv4 carrying ONE PIECE of a fragmented UDP datagram.
    fn eth_ipv4_piece(
        ident: u16,
        offset_bytes: u16,
        more: bool,
        body: &[u8],
    ) -> alloc::vec::Vec<u8> {
        let mut ip = alloc::vec::Vec::new();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&((20 + body.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&ident.to_be_bytes());
        let flags_and_offset = (offset_bytes / 8) | if more { 0x2000 } else { 0 };
        ip.extend_from_slice(&flags_and_offset.to_be_bytes());
        ip.push(64);
        ip.push(17);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(body);

        let mut eth = alloc::vec![0u8; 12];
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    /// R311y860 — a fragment chain that NEVER COMPLETES is a shortfall, and
    /// the verdict says so.
    ///
    /// The counter had no fixture anywhere in this tree, which the mutation
    /// gate found by forgiving it and watching every test pass. It is the
    /// sharpest member of its class: the piece is not furniture and it is not
    /// noise, it is the front of a datagram whose rest this capture does not
    /// hold, and a reader summing the rows would otherwise be told the sum is
    /// the whole capture.
    ///
    /// R311y861 — THE PIN MOVED WITH ITS SUBJECT rather than being deleted.
    /// What this fixture demonstrates is unchanged and is still true; where the
    /// tree answers it moved, from the door's census to the reassembly table,
    /// because the census cannot tell this chain from one that completed a
    /// packet later. The assertion follows it: `held` at the door,
    /// `unfinished_fragment_chains` at the verdict, and `bytes_absent` now
    /// explicitly ZERO — which is the leg that used to carry this case and must
    /// not still be carrying it, or the sibling witness below proves nothing.
    #[test]
    fn a_fragment_chain_that_never_completes_is_a_shortfall() {
        let mut d = crate::Dissection::new();
        let mut udp = alloc::vec::Vec::new();
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&7446u16.to_be_bytes());
        udp.extend_from_slice(&64u16.to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&[0u8; 16]);
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &eth_ipv4_piece(0x4242, 0, true, &udp),
        );
        d.finish();

        let sk = d.skip_census();
        assert_eq!(
            sk.ip_fragment_pending, 1,
            "the fixture must leave exactly one piece held: {sk:?}"
        );
        assert_eq!(sk.held(), 1, "a held piece is held, at the door: {sk:?}");
        assert_eq!(
            sk.bytes_absent(),
            0,
            "and the door does not get to call it absent -- it cannot yet know: {sk:?}"
        );
        assert_eq!(sk.not_this_protocol(), 0, "nor is it furniture: {sk:?}");
        assert_eq!(
            d.open_fragment_chains(),
            1,
            "the chain is still half-assembled when the file ends"
        );
        assert_eq!(
            d.unfinished_fragment_chains(),
            1,
            "which is one datagram this capture carried pieces of and no row holds"
        );
        assert_eq!(
            CaptureReport::of(&d).reasons(),
            alloc::vec![VerdictReason::UnfinishedFragmentChains],
            "a datagram whose rest never arrived makes the totals a floor, \
             and says which floor: {}",
            CaptureReport::of(&d).to_text()
        );
        // R311y861 — and the DOCUMENT carries the number the verdict fired on.
        // A reader told `unfinished_fragment_chains` and shown no such figure
        // anywhere is the y859 shape: a verdict naming a fact the page omits.
        let text = CaptureReport::of(&d).to_text();
        assert!(
            text.contains("1 IP datagram(s) still half-assembled"),
            "the page must name the chain, not only the verdict: {text}"
        );
    }

    /// R311y861 — THE SIBLING, and the one that was wrong before this round: a
    /// chain that DID complete is not a shortfall.
    ///
    /// The discriminator is a pair, not a single capture. R311y860 placed
    /// `ip_fragment_pending` in `bytes_absent`, and a piece is counted there the
    /// moment it is held — before anything can know whether the rest arrives.
    /// So a datagram split in two and reassembled perfectly left one held piece
    /// at the door, every byte of it decoded into a row, and the verdict called
    /// the capture a floor for it. Measured, not argued: this test failed with
    /// `reasons=[PacketsSkipped]` against the previous build.
    ///
    /// It is the same shape as the ARP finding that round fixed — a leg firing
    /// on traffic that is not missing — in the one place that round introduced
    /// it, which is why the two witnesses sit together.
    #[test]
    fn a_reassembled_datagram_is_not_a_shortfall() {
        // Whole zenoh messages and no padding: a padded datagram leaves bytes
        // no message claims, which is `unaccounted_batch_bytes` -- a real and
        // different shortfall, and one that would make this fixture prove the
        // wrong thing. Measured on the first draft, which used padding.
        let msg = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE; 48];
        let mut udp = alloc::vec::Vec::new();
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&7446u16.to_be_bytes());
        udp.extend_from_slice(&((8 + msg.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&msg);

        // A multiple of 8, as IP requires, and past the UDP header so the first
        // piece cannot be read as a whole datagram on its own.
        let cut = 24usize;
        let mut d = crate::Dissection::new();
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &eth_ipv4_piece(0x4242, 0, true, &udp[..cut]),
        );
        // THE HALF-WAY STATE IS ASSERTED, so the fixture cannot silently stop
        // fragmenting: with one piece in, the capture IS a floor.
        assert_eq!(d.skip_census().held(), 1, "the first piece must be held");
        assert!(
            !CaptureReport::of(&d).is_complete(),
            "and a capture holding it is short until the rest arrives"
        );

        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            1,
            &eth_ipv4_piece(0x4242, cut as u16, false, &udp[cut..]),
        );
        d.finish();

        assert_eq!(d.fragment_stats().completed, 1, "the chain must close");
        assert_eq!(
            d.skip_census().held(),
            1,
            "the piece stays counted at the door -- the census is a tally of \
             what happened, not a running state"
        );
        assert_eq!(
            d.datagram_flows()[0].frames.len(),
            msg.len(),
            "and every byte must reach a row"
        );
        assert_eq!(
            d.unfinished_fragment_chains(),
            0,
            "no chain is unfinished once the rest arrives"
        );
        let r = CaptureReport::of(&d);
        assert!(
            r.is_complete(),
            "a datagram that was reassembled is in the rows: reasons={:?} {}",
            r.reasons(),
            r.to_text()
        );
    }

    /// A datagram of whole zenoh messages, split at `cut`, as two pieces.
    ///
    /// Whole messages and no padding, for the reason
    /// `a_reassembled_datagram_is_not_a_shortfall` states at its own fixture.
    fn two_piece_datagram(ident: u16) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
        let msg = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE; 48];
        let mut udp = alloc::vec::Vec::new();
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&7446u16.to_be_bytes());
        udp.extend_from_slice(&((8 + msg.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&msg);
        let cut = 24usize;
        (
            eth_ipv4_piece(ident, 0, true, &udp[..cut]),
            eth_ipv4_piece(ident, cut as u16, false, &udp[cut..]),
        )
    }

    /// R311y861 — a chain the DEADLINE took reaches the verdict.
    ///
    /// This is R311y860's carry 3, and it was carried as unverified rather than
    /// as absent. It is the sharpest of the three ends because the pieces leave
    /// no trace where a reader would look: the chain is gone from the table, so
    /// `open` is zero, and the census counts it under `held` beside pieces that
    /// completed perfectly. `expired` is the only witness there is, and until
    /// this round nothing read it.
    #[test]
    fn a_chain_the_deadline_took_reaches_the_verdict() {
        let mut d = crate::Dissection::with_limits(crate::DissectionLimits {
            reassembly_window_ms: Some(1_000),
            ..crate::DissectionLimits::default()
        });
        let (lost_head, _lost_tail) = two_piece_datagram(0x4242);
        let (head, tail) = two_piece_datagram(0x5151);

        d.push_packet_at(crate::link::LINKTYPE_ETHERNET, 0, Some(0), &lost_head);
        // The sweep runs on the next PUSH into the table, so the second chain
        // is what advances the clock past the first one's deadline. A packet
        // that is not a fragment would not reach it at all.
        d.push_packet_at(crate::link::LINKTYPE_ETHERNET, 1, Some(5_000), &head);
        d.push_packet_at(crate::link::LINKTYPE_ETHERNET, 2, Some(5_000), &tail);
        d.finish();

        let f = d.fragment_stats();
        assert_eq!(
            f.expired, 1,
            "the first chain must miss its deadline: {f:?}"
        );
        assert_eq!(f.completed, 1, "and the second must complete: {f:?}");
        assert_eq!(
            d.open_fragment_chains(),
            0,
            "nothing is left half-assembled, which is what makes this the \
             end no other counter can see"
        );
        assert_eq!(
            d.unfinished_fragment_chains(),
            1,
            "one datagram was carried and is in no row: {f:?}"
        );
        assert_eq!(
            CaptureReport::of(&d).reasons(),
            alloc::vec![VerdictReason::UnfinishedFragmentChains],
            "and the verdict says exactly that: {}",
            CaptureReport::of(&d).to_text()
        );
        // The page names the END, which is the actionable half: this one is
        // fixed by widening the window and the eviction below is not.
        let text = CaptureReport::of(&d).to_text();
        assert!(
            text.contains("reassembly_window_ms"),
            "the page must name the knob that would have kept it: {text}"
        );
    }

    /// R311y861 — a chain the CAP dropped reaches the verdict.
    ///
    /// The third end, and the one an operator acts on differently: the deadline
    /// says widen the window, this says raise `max_pending_fragments`. It is
    /// one number at the verdict and three at [`crate::Dissection::fragment_stats`]
    /// for exactly that reason.
    #[test]
    fn a_chain_the_cap_dropped_reaches_the_verdict() {
        let mut d = crate::Dissection::with_limits(crate::DissectionLimits {
            max_pending_fragments: Some(1),
            ..crate::DissectionLimits::default()
        });
        let (evicted_head, _evicted_tail) = two_piece_datagram(0x4242);
        let (head, tail) = two_piece_datagram(0x5151);

        d.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &evicted_head);
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 1, &head);
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 2, &tail);
        d.finish();

        let f = d.fragment_stats();
        assert_eq!(f.evicted, 1, "the cap must bite exactly once: {f:?}");
        assert_eq!(f.completed, 1, "and the survivor must complete: {f:?}");
        assert_eq!(d.open_fragment_chains(), 0, "with nothing left open");
        assert_eq!(
            d.unfinished_fragment_chains(),
            1,
            "the evicted chain is a datagram in no row: {f:?}"
        );
        assert_eq!(
            CaptureReport::of(&d).reasons(),
            alloc::vec![VerdictReason::UnfinishedFragmentChains],
            "and the verdict says exactly that -- the WHOLE list, because a \
             containment claim holds while every other leg fires too: {}",
            CaptureReport::of(&d).to_text()
        );
        let text = CaptureReport::of(&d).to_text();
        assert!(
            text.contains("max_pending_fragments"),
            "and the page names THIS knob rather than the deadline's: {text}"
        );
        assert!(
            !text.contains("reassembly_window_ms"),
            "an eviction is not a deadline, and a page that names both sends \
             the operator to the wrong one: {text}"
        );
    }

    /// A bare IPv4 packet (no link header) carrying `body` under `proto`.
    fn ipv4_packet(proto: u8, src: [u8; 4], dst: [u8; 4], body: &[u8]) -> alloc::vec::Vec<u8> {
        let mut ip = alloc::vec::Vec::new();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&((20 + body.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.push(64);
        ip.push(proto);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(body);
        ip
    }

    /// A UDP datagram of whole zenoh KeepAlives, `n` of them.
    fn zenoh_udp(n: usize) -> alloc::vec::Vec<u8> {
        let msg = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE; n];
        let mut udp = alloc::vec::Vec::new();
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&7446u16.to_be_bytes());
        udp.extend_from_slice(&((8 + msg.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&msg);
        udp
    }

    /// A bare IPv4 packet that is ONE PIECE of a fragmented datagram.
    fn ipv4_frag_packet(
        proto: u8,
        src: [u8; 4],
        dst: [u8; 4],
        ident: u16,
        offset_bytes: usize,
        more: bool,
        body: &[u8],
    ) -> alloc::vec::Vec<u8> {
        assert_eq!(
            offset_bytes % 8,
            0,
            "an IP fragment offset is in 8-byte units"
        );
        let mut ip = alloc::vec::Vec::new();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&((20 + body.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&ident.to_be_bytes());
        let flags_off = (offset_bytes as u16 / 8) | if more { 0x2000 } else { 0 };
        ip.extend_from_slice(&flags_off.to_be_bytes());
        ip.push(64);
        ip.push(proto);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(body);
        ip
    }

    /// Ethernet framing around one already-built IP packet.
    fn eth(ip: &[u8]) -> alloc::vec::Vec<u8> {
        let mut frame = alloc::vec![0u8; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(ip);
        while frame.len() < 60 {
            frame.push(0);
        }
        frame
    }

    /// Feed `packet` to a fresh dissection as TWO fragments of one carrier.
    ///
    /// The carrier's endpoints are `10.0.0.x`, distinct from every inner
    /// address these tests use, so a flow keyed by the wrong header is visible
    /// as a wrong address rather than only as a wrong count.
    fn push_fragmented_carrier(
        d: &mut crate::Dissection,
        proto: u8,
        ident: u16,
        first_index: usize,
        packet: &[u8],
    ) {
        let cut = (packet.len() / 2) / 8 * 8;
        assert!(
            cut > 0 && cut < packet.len(),
            "the split must produce two pieces"
        );
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            first_index,
            &eth(&ipv4_frag_packet(
                proto,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                ident,
                0,
                true,
                &packet[..cut],
            )),
        );
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            first_index + 1,
            &eth(&ipv4_frag_packet(
                proto,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                ident,
                cut,
                false,
                &packet[cut..],
            )),
        );
    }

    /// A GRE header with the flags asked for, wrapping `body`.
    fn gre(flags: u16, protocol_type: u16, optional: &[u8], body: &[u8]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&protocol_type.to_be_bytes());
        out.extend_from_slice(optional);
        out.extend_from_slice(body);
        out
    }

    /// R311y864 — zenoh inside a GRE tunnel is READ, at every optional-field
    /// combination.
    ///
    /// THE DEFECT THIS REPLACES: `capture: INCOMPLETE`, `messages decoded: 0`,
    /// `tunnel IP protocol(s) not opened: 47`. Honest, and useless to the person
    /// holding a capture off a VPN concentrator — which is where GRE comes from,
    /// and why R311y863's carry called this the largest unread class left.
    ///
    /// THE TABLE IS THE TEST. GRE's header has no fixed length: RFC 2784 gives
    /// four bytes and makes everything after them optional and keyed by a flag
    /// bit. A reader that summed the flags wrongly would find the inner IP
    /// header at the wrong offset, and the failure is not a refusal — it is a
    /// plausible-looking parse of the wrong bytes. Driving all three deployed
    /// combinations is what makes a wrong length visible rather than lucky.
    #[test]
    fn zenoh_inside_a_gre_tunnel_is_read() {
        let inner = ipv4_packet(17, [192, 168, 0, 1], [192, 168, 0, 2], &zenoh_udp(48));
        for (name, flags, optional) in [
            ("no optional fields", 0x0000u16, &[][..]),
            ("key + sequence (RFC 2890)", 0x3000u16, &[0u8; 8][..]),
            ("checksum + reserved1", 0x8000u16, &[0u8; 4][..]),
        ] {
            let mut d = crate::Dissection::new();
            d.push_packet(
                crate::link::LINKTYPE_ETHERNET,
                0,
                &eth_ipv4_proto(47, &gre(flags, 0x0800, optional, &inner)),
            );
            d.finish();

            let sk = d.skip_census();
            assert_eq!(
                d.datagram_flows().len(),
                1,
                "GRE with {name}: the session must reach a row: {sk:?}"
            );
            assert_eq!(
                d.datagram_flows()[0].frames.len(),
                48,
                "GRE with {name}: and every message must decode"
            );
            let flow = &d.datagram_flows()[0].flow;
            assert_eq!(
                (flow.low.addr(), flow.high.addr()),
                (&[192, 168, 0, 1][..], &[192, 168, 0, 2][..]),
                "GRE with {name}: keyed by the inner header, not the carrier's"
            );
            assert!(sk.is_empty(), "GRE with {name}: nothing skipped: {sk:?}");
        }
    }

    /// R311y864 — a GRE payload this reader does not walk is named BY ITS
    /// ETHERTYPE, not as protocol 47.
    ///
    /// The distinction is the whole reason `GrePayload` is its own variant.
    /// `tunnel IP protocol(s) not opened: 47` would tell a reader to add GRE
    /// support that is now present — the misdirection R311y863 measured on
    /// protocol 4, one carrier later. Transparent Ethernet Bridging is a whole
    /// Ethernet frame, so what is actually missing is a link strip, and the
    /// number on the page is what says so.
    #[test]
    fn a_gre_payload_this_reader_does_not_walk_is_named_by_its_ethertype() {
        let mut d = crate::Dissection::new();
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &eth_ipv4_proto(47, &gre(0x0000, 0x6558, &[], &[0u8; 32])),
        );
        d.finish();

        let sk = d.skip_census();
        assert_eq!(sk.gre_payload, 1, "counted under its own reason: {sk:?}");
        assert!(
            sk.gre_payloads.contains(&0x6558),
            "and by the ethertype, which is what names the next thing to \
             build: {sk:?}"
        );
        assert_eq!(
            sk.unwalked_encapsulation, 0,
            "NOT as a tunnel this build cannot open — it opened it: {sk:?}"
        );
        assert_eq!(sk.not_transport, 0, "and not as furniture: {sk:?}");
        assert_eq!(sk.bytes_absent(), 1, "which is bytes absent: {sk:?}");
        let text = CaptureReport::of(&d).to_text();
        assert!(
            text.contains("GRE payload ethertype(s) not walked: 0x6558"),
            "the page names the ethertype: {text}"
        );
        assert!(
            !text.contains("tunnel IP protocol(s) not opened"),
            "and does not also blame protocol 47: {text}"
        );
    }

    /// R311y864 — CONTROL. A GRE header this reader cannot SIZE is still a
    /// tunnel not opened.
    ///
    /// The other side of the same split, and the leg that keeps `GrePayload`
    /// from swallowing everything: version 1 is PPTP's Enhanced GRE, whose word
    /// at the Protocol Type offset is not a protocol type at all. The payload
    /// cannot be named, so "protocol 47, not opened" is the whole of what is
    /// known — and reporting an ethertype read out of that header would be
    /// inventing one.
    #[test]
    fn a_gre_header_this_reader_cannot_size_is_a_tunnel_not_opened() {
        for (name, flags) in [
            ("version 1 (PPTP Enhanced GRE)", 0x3001u16),
            ("routing present, whose field is variable-length", 0x4000u16),
            (
                "a non-zero Reserved0, which RFC 2784 says to discard",
                0x0008u16,
            ),
        ] {
            let mut d = crate::Dissection::new();
            d.push_packet(
                crate::link::LINKTYPE_ETHERNET,
                0,
                &eth_ipv4_proto(47, &gre(flags, 0x0800, &[0u8; 8], &[0u8; 32])),
            );
            d.finish();

            let sk = d.skip_census();
            assert_eq!(
                sk.unwalked_encapsulation, 1,
                "GRE with {name}: a tunnel not opened: {sk:?}"
            );
            assert!(
                sk.unwalked_encapsulations.contains(&47),
                "GRE with {name}: and 47 is the honest number here, because \
                 the payload type could not be read: {sk:?}"
            );
            assert_eq!(
                sk.gre_payload, 0,
                "GRE with {name}: no ethertype is invented: {sk:?}"
            );
        }
    }

    /// R311y864 — a FRAGMENTED GRE carrier is read, which is R311y863's door
    /// asked about the carrier this round added.
    ///
    /// The two rounds compose or they do not, and "or they do not" is the
    /// default: R311y863 fixed the reassembly door for protocols 4 and 41 by
    /// naming them, so a new carrier reaches it only if it is added there too.
    /// This is the leg that would have caught leaving it out — and the capture
    /// it stands for is ordinary, because a GRE header is what pushes a
    /// full-MTU packet over the path MTU in the first place.
    #[test]
    fn a_fragmented_gre_carrier_is_read() {
        let inner = ipv4_packet(17, [192, 168, 0, 1], [192, 168, 0, 2], &zenoh_udp(48));
        let carrier = gre(0x0000, 0x0800, &[], &inner);

        let mut d = crate::Dissection::new();
        push_fragmented_carrier(&mut d, 47, 0x7777, 0, &carrier);
        d.finish();

        let sk = d.skip_census();
        assert_eq!(
            d.datagram_flows().len(),
            1,
            "the session inside the fragmented GRE carrier must read: {sk:?}"
        );
        assert_eq!(d.datagram_flows()[0].frames.len(), 48);
        assert_eq!(
            sk.unwalked_encapsulation, 0,
            "and 47 is not reported as unopened: {sk:?}"
        );
        assert_eq!(sk.bytes_absent(), 0, "no bytes absent: {sk:?}");
        assert_eq!(
            CaptureReport::of(&d).reasons(),
            alloc::vec![],
            "so the capture is complete: {}",
            CaptureReport::of(&d).to_text()
        );
    }

    /// R311y863 — a carrier the sender FRAGMENTED is walked like one that
    /// arrived whole.
    ///
    /// THE DEFECT THIS REPLACES, measured on R311y862's build as a pair whose
    /// only variable is the number of packets: one IPIP packet carrying
    /// `IPv4 / UDP:7447 / 48 KeepAlives` read `datagram_flows=1, 48 messages`;
    /// the SAME session split across two fragments of the same carrier read
    /// `datagram_flows=0, messages decoded: 0`, with the census naming
    /// `unwalked_encapsulation: {4}` — protocol 4 reported as a tunnel this
    /// build cannot open, one packet after it opened one.
    ///
    /// The reassembly was never the problem: the chain completed and the whole
    /// inner packet was in hand. R311y862 put the tunnel walk inside
    /// `decapsulate`, and a reassembled datagram does not come through that
    /// door — it comes through `transport_from_ip`, which refused what the
    /// other door walks. A tunnel adds header bytes to packets that are already
    /// at the path MTU, so the fragmented carrier is the ORDINARY case and the
    /// unfragmented one is the small-packet exception.
    #[test]
    fn a_fragmented_carrier_is_walked_like_an_unfragmented_one() {
        let inner = ipv4_packet(17, [192, 168, 0, 1], [192, 168, 0, 2], &zenoh_udp(48));

        let mut d = crate::Dissection::new();
        push_fragmented_carrier(&mut d, 4, 0x1234, 0, &inner);
        d.finish();

        assert_eq!(
            d.datagram_flows().len(),
            1,
            "the session inside the fragmented carrier must reach a row: {:?}",
            d.skip_census()
        );
        assert_eq!(
            d.datagram_flows()[0].frames.len(),
            48,
            "and every message in it must decode"
        );
        let flow = &d.datagram_flows()[0].flow;
        assert_eq!(
            (flow.low.addr(), flow.high.addr()),
            (&[192, 168, 0, 1][..], &[192, 168, 0, 2][..]),
            "keyed by the innermost header, not by the carrier's 10.0.0.x ends"
        );
        let sk = d.skip_census();
        assert_eq!(
            sk.unwalked_encapsulation, 0,
            "and protocol 4 is NOT reported as a tunnel this build cannot \
             open, because it opened it: {sk:?}"
        );
        assert!(
            sk.unwalked_encapsulations.is_empty(),
            "so no protocol number is named on that line: {sk:?}"
        );
        assert_eq!(sk.bytes_absent(), 0, "no bytes are absent: {sk:?}");
        let r = CaptureReport::of(&d);
        assert_eq!(
            r.reasons(),
            alloc::vec![],
            "and the capture is complete because it was READ: {}",
            r.to_text()
        );

        // THE OTHER HALF OF THE PAIR, and the reason this is a discriminator
        // rather than an assertion: the same bytes through ONE packet already
        // read, so the fragmentation is the only variable in the comparison.
        let mut whole = crate::Dissection::new();
        whole.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &eth_ipv4_proto(4, &inner),
        );
        whole.finish();
        assert_eq!(
            whole.datagram_flows()[0].frames.len(),
            d.datagram_flows()[0].frames.len(),
            "one carrier packet and two must yield the same session"
        );
    }

    /// R311y863 — a fragment found INSIDE a reassembled carrier goes back to
    /// the table, not to the furniture class.
    ///
    /// The arm this replaces called `Ok(Transport::IpFragment(_))` from the
    /// reassembly door impossible and booked it as `NotTransport(4)` — the
    /// exact mislabelling R311y862 fixed, regenerated one layer down by the
    /// fix for it. A tunnel ingress that fragments a packet which was already a
    /// fragment produces this shape, and there is no other path on which those
    /// bytes reach a row.
    #[test]
    fn a_fragment_inside_a_reassembled_carrier_is_reassembled_too() {
        let udp = zenoh_udp(48);
        let inner_a = ipv4_frag_packet(
            17,
            [192, 168, 0, 1],
            [192, 168, 0, 2],
            0x5678,
            0,
            true,
            &udp[..24],
        );
        let inner_b = ipv4_frag_packet(
            17,
            [192, 168, 0, 1],
            [192, 168, 0, 2],
            0x5678,
            24,
            false,
            &udp[24..],
        );

        let mut d = crate::Dissection::new();
        push_fragmented_carrier(&mut d, 4, 0xA000, 0, &inner_a);
        push_fragmented_carrier(&mut d, 4, 0xB000, 2, &inner_b);
        d.finish();

        let sk = d.skip_census();
        assert_eq!(
            d.datagram_flows().len(),
            1,
            "a fragmented session inside a fragmented carrier still reads: {sk:?}"
        );
        assert_eq!(d.datagram_flows()[0].frames.len(), 48);
        assert_eq!(
            sk.not_transport, 0,
            "and no piece of it is filed as a protocol that terminates at the \
             host: {sk:?}"
        );
        assert_eq!(
            sk.unwalked_encapsulation, 0,
            "nor as an unopened tunnel: {sk:?}"
        );
        assert_eq!(sk.bytes_absent(), 0, "no bytes absent: {sk:?}");
        assert_eq!(
            d.unfinished_fragment_chains(),
            0,
            "and both chains closed: {:?}",
            d.fragment_stats()
        );
    }

    /// R311y863 — CONTROL. Walking a reassembled IPIP carrier does not make
    /// every reassembled carrier walkable.
    ///
    /// Without this leg the round reads as "make the verdict fire less often",
    /// which is the regression in the other direction: a capture whose tunnel
    /// this build cannot open must still say so, whether the tunnel arrived in
    /// one packet or in two.
    ///
    /// R311y864 moved the fixture from 47 to 50 for the same reason its
    /// unfragmented twin moved: GRE stopped being an instance of the thing this
    /// leg is about. `a_fragmented_gre_carrier_is_read` is where 47 went.
    #[test]
    fn a_reassembled_carrier_this_build_cannot_open_is_still_a_shortfall() {
        let mut d = crate::Dissection::new();
        // 50 = ESP. The body is never walked, so its contents do not matter.
        push_fragmented_carrier(&mut d, 50, 0x2222, 0, &[0u8; 64]);
        d.finish();

        let sk = d.skip_census();
        assert_eq!(sk.unwalked_encapsulation, 1, "counted as a tunnel: {sk:?}");
        assert!(
            sk.unwalked_encapsulations.contains(&50),
            "and by its number: {sk:?}"
        );
        assert_eq!(sk.not_transport, 0, "not as furniture: {sk:?}");
        assert_eq!(sk.gre_payload, 0, "and not under GRE's counter: {sk:?}");
        assert_eq!(
            CaptureReport::of(&d).reasons(),
            alloc::vec![VerdictReason::PacketsSkipped],
            "so the capture is a floor and says so: {}",
            CaptureReport::of(&d).to_text()
        );
    }

    /// R311y863 — CONTROL. A reassembled protocol that TERMINATES at the host
    /// is still furniture.
    ///
    /// The other half of the same guard: R311y860 paid for widening the
    /// bytes-absent class until ARP made every capture incomplete, and the
    /// split R311y862 drew has to survive the reassembly door too.
    #[test]
    fn a_reassembled_protocol_that_terminates_at_the_host_is_still_furniture() {
        let mut d = crate::Dissection::new();
        // 1 = ICMP: it carries no session, whether fragmented or not.
        push_fragmented_carrier(&mut d, 1, 0x3333, 0, &[0u8; 64]);
        d.finish();

        let sk = d.skip_census();
        assert_eq!(sk.not_transport, 1, "furniture: {sk:?}");
        assert!(
            sk.not_transport_protos.contains(&1),
            "and the number is printed so a reader can check the claim: {sk:?}"
        );
        assert_eq!(sk.unwalked_encapsulation, 0, "not a tunnel: {sk:?}");
        assert_eq!(sk.bytes_absent(), 0, "and no bytes are absent: {sk:?}");
        assert_eq!(
            CaptureReport::of(&d).reasons(),
            alloc::vec![],
            "so the capture stays complete: {}",
            CaptureReport::of(&d).to_text()
        );
    }

    /// R311y863 — the reassembled carrier COUNTS toward the chain's bound.
    ///
    /// This is what pins `start_depth = 1` at the reassembly door. The header
    /// that declared the reassembled body was itself a carrier and the
    /// reassembler already consumed it, so a door that started counting at zero
    /// would walk five headers on the fragmented path and four on the
    /// unfragmented one — the same chain, two limits, decided by whether the
    /// sender happened to fragment.
    ///
    /// The claim is about ONE datagram's chain. A capture in which several
    /// carriers are each separately fragmented re-enters the walk once per
    /// reassembly and is bounded by `push_fragment`'s own counter instead; that
    /// second bound is not this test's subject and is not the same number.
    #[test]
    fn a_reassembled_carrier_counts_toward_the_chain_bound() {
        fn nest(carriers: usize) -> alloc::vec::Vec<u8> {
            let mut packet = ipv4_packet(17, [192, 168, 0, 1], [192, 168, 0, 2], &zenoh_udp(4));
            for i in 0..carriers {
                packet = ipv4_packet(4, [172, 16, i as u8, 1], [172, 16, i as u8, 2], &packet);
            }
            packet
        }

        // Three more carriers inside the reassembled one is four in the chain,
        // which is the bound, so it WALKS — the leg that makes this a bound
        // rather than a refusal.
        let mut ok = crate::Dissection::new();
        push_fragmented_carrier(&mut ok, 4, 0x4444, 0, &nest(3));
        ok.finish();
        assert_eq!(
            ok.datagram_flows().len(),
            1,
            "four carriers deep still reads: {:?}",
            ok.skip_census()
        );

        // One more is five, and it is reported rather than walked.
        let mut over = crate::Dissection::new();
        push_fragmented_carrier(&mut over, 4, 0x5555, 0, &nest(4));
        over.finish();
        let sk = over.skip_census();
        assert_eq!(
            over.datagram_flows().len(),
            0,
            "five is past the bound: {sk:?}"
        );
        assert_eq!(
            sk.unwalked_encapsulation, 1,
            "and is reported as a chain this reader did not walk: {sk:?}"
        );
        assert_eq!(sk.bytes_absent(), 1, "which is bytes absent: {sk:?}");
    }

    /// R311y862 — zenoh inside an IPIP tunnel is READ, not called furniture.
    ///
    /// THE DEFECT THIS REPLACES, measured on the previous build: one packet,
    /// `IPv4(proto 4) / IPv4 / UDP:7447 / 48 KeepAlives`, produced
    /// `complete=true reasons=[] datagram_flows=0` with `not_transport: 1`. A
    /// capture holding a whole zenoh session reported itself WHOLE having read
    /// none of it — the worst shape available to a tool whose job is to say
    /// what a capture contains, and it came from the furniture class being
    /// argued from what wz SENDS rather than from what a capture may CONTAIN.
    #[test]
    fn zenoh_inside_a_tunnel_is_read_rather_than_filed_as_furniture() {
        let inner = ipv4_packet(17, [192, 168, 0, 1], [192, 168, 0, 2], &zenoh_udp(48));
        let mut d = crate::Dissection::new();
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &eth_ipv4_proto(4, &inner),
        );
        d.finish();

        assert_eq!(
            d.datagram_flows().len(),
            1,
            "the inner datagram must reach the datagram path: {:?}",
            d.skip_census()
        );
        assert_eq!(
            d.datagram_flows()[0].frames.len(),
            48,
            "and every message inside the tunnel must decode"
        );
        // THE ADDRESSES ARE THE INNER ONES, which is not a detail: a flow keyed
        // by the tunnel endpoints would merge every session riding that tunnel
        // into a single flow, and the report would name the carrier's addresses
        // for traffic that never used them.
        let flow = &d.datagram_flows()[0].flow;
        assert_eq!(
            (flow.low.addr(), flow.high.addr()),
            (&[192, 168, 0, 1][..], &[192, 168, 0, 2][..]),
            "the flow is keyed by the inner header, not by the carrier's \
             10.0.0.x endpoints"
        );
        let sk = d.skip_census();
        assert!(sk.is_empty(), "nothing was skipped at all: {sk:?}");
        let r = CaptureReport::of(&d);
        assert_eq!(
            r.reasons(),
            alloc::vec![],
            "and the capture is complete because it was READ: {}",
            r.to_text()
        );
    }

    /// R311y862 — a tunnel this build cannot open is a SHORTFALL, not furniture.
    ///
    /// The other half of the pair, and the half that has to be got right for
    /// the first one to mean anything: walking IPIP does not make GRE readable,
    /// and the honest report for a tunnel with no parser is that bytes the
    /// capture holds are in no row. Filing it beside ARP is what let the case
    /// above go unnoticed.
    #[test]
    fn a_tunnel_this_build_cannot_open_is_a_shortfall() {
        let mut d = crate::Dissection::new();
        // R311y864 MOVED this fixture from 47 to 50, and moving it is the
        // correct response rather than deleting the leg: GRE is walked now, so
        // it is no longer an instance of "a tunnel with no parser", and the
        // claim this test makes still needs one. 50 = ESP, whose remainder is
        // encrypted — the case that cannot become walkable by writing a parser.
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &eth_ipv4_proto(50, &[0u8; 32]),
        );
        d.finish();

        let sk = d.skip_census();
        assert_eq!(sk.unwalked_encapsulation, 1, "counted as a tunnel: {sk:?}");
        assert_eq!(
            sk.not_transport, 0,
            "and NOT as a protocol that terminates at the host: {sk:?}"
        );
        assert_eq!(
            sk.gre_payload, 0,
            "nor under the counter for a GRE that WAS opened: {sk:?}"
        );
        assert!(
            sk.unwalked_encapsulations.contains(&50),
            "the number is kept, because 'a tunnel' is not actionable and \
             'ESP' is: {sk:?}"
        );
        assert_eq!(sk.bytes_absent(), 1, "which is bytes absent: {sk:?}");
        assert_eq!(sk.not_this_protocol(), 0, "and is not furniture: {sk:?}");
        assert_eq!(
            CaptureReport::of(&d).reasons(),
            alloc::vec![VerdictReason::PacketsSkipped],
            "so the capture is a floor and says so: {}",
            CaptureReport::of(&d).to_text()
        );
        assert!(
            CaptureReport::of(&d)
                .to_text()
                .contains("tunnel not opened"),
            "and the page names the class: {}",
            CaptureReport::of(&d).to_text()
        );
    }

    /// R311y862 — a protocol that TERMINATES at the host is still furniture.
    ///
    /// The control arm of the pair above. Splitting the encapsulations out
    /// would be worthless if it had also dragged ICMP with them: a capture is
    /// not a floor because the segment it was taken on had pings on it, and
    /// that is exactly the regression R311y860 paid for with ARP.
    #[test]
    fn a_protocol_that_terminates_at_the_host_is_still_furniture() {
        let mut d = crate::Dissection::new();
        // 1 = ICMP, 132 = SCTP. Neither carries a zenoh session: zenoh has no
        // SCTP link, and ICMP terminates.
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &eth_ipv4_proto(1, &[0u8; 8]),
        );
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            1,
            &eth_ipv4_proto(132, &[0u8; 8]),
        );
        d.finish();

        let sk = d.skip_census();
        assert_eq!(sk.not_transport, 2, "both are furniture: {sk:?}");
        assert_eq!(sk.unwalked_encapsulation, 0, "and neither is a tunnel");
        assert_eq!(sk.bytes_absent(), 0, "so nothing is absent: {sk:?}");
        assert!(
            CaptureReport::of(&d).is_complete(),
            "a segment with pings on it is not a floor: {:?}",
            CaptureReport::of(&d).reasons()
        );
        // The NUMBERS are on the page, which is what makes the furniture claim
        // checkable instead of asserted -- a tunnel missing from the list would
        // show up here as a number a reader did not expect.
        let text = CaptureReport::of(&d).to_text();
        assert!(
            text.contains("terminate at the host: 1, 132"),
            "the page must name which protocols it held to terminate: {text}"
        );
    }

    /// R311y862 — the nesting bound is a bound, and beyond it the answer is the
    /// same one GRE gets.
    ///
    /// The depth comes out of the packet, so without this a crafted chain
    /// decides how much work the walk does. Reported rather than dropped: the
    /// bytes are as absent as any other unopened tunnel's.
    #[test]
    fn a_tunnel_chain_past_the_bound_is_reported_not_walked() {
        // Six nested IPv4 headers around the datagram; the bound is four.
        let mut pkt = ipv4_packet(17, [192, 168, 0, 1], [192, 168, 0, 2], &zenoh_udp(4));
        for _ in 0..6 {
            pkt = ipv4_packet(4, [10, 0, 0, 1], [10, 0, 0, 2], &pkt);
        }
        let mut eth = alloc::vec![0u8; 12];
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&pkt);

        let mut d = crate::Dissection::new();
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &eth);
        d.finish();

        let sk = d.skip_census();
        assert_eq!(
            sk.unwalked_encapsulation, 1,
            "a chain past the bound is an unopened tunnel: {sk:?}"
        );
        assert_eq!(sk.bytes_absent(), 1, "and is bytes absent: {sk:?}");
        assert_eq!(
            d.datagram_flows().len(),
            0,
            "the walk must stop rather than recurse"
        );
        // AND THE BOUND IS NOT ZERO: four levels are walked, so this is a bound
        // rather than a refusal to walk at all.
        let mut ok = ipv4_packet(17, [192, 168, 0, 1], [192, 168, 0, 2], &zenoh_udp(4));
        for _ in 0..4 {
            ok = ipv4_packet(4, [10, 0, 0, 1], [10, 0, 0, 2], &ok);
        }
        let mut eth_ok = alloc::vec![0u8; 12];
        eth_ok.extend_from_slice(&0x0800u16.to_be_bytes());
        eth_ok.extend_from_slice(&ok);
        let mut d2 = crate::Dissection::new();
        d2.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &eth_ok);
        d2.finish();
        assert_eq!(
            d2.datagram_flows().len(),
            1,
            "four levels are inside the bound: {:?}",
            d2.skip_census()
        );
    }

    /// PROBE — the classification is EXHAUSTIVE, so a tenth reason cannot be
    /// added to neither class.
    ///
    /// `total` is the sum of the two classes, and a separate test already pins
    /// `total` against `DissectionHealth::packets_skipped`. Together those are
    /// the gate: a field added at the door and placed in no class makes the two
    /// figures disagree, which is a red rather than a silently unjudged reason.
    #[test]
    fn every_skip_reason_belongs_to_exactly_one_class() {
        let mut d = crate::Dissection::new();
        let mut arp = alloc::vec![0u8; 12];
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.extend_from_slice(&[0u8; 46]);
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &arp);
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            1,
            &eth_ipv4_proto(1, &[0u8; 8]),
        );
        let mut short = alloc::vec![0u8; 12];
        short.extend_from_slice(&[0x08, 0x00]);
        short.extend_from_slice(&[0x45, 0, 0, 40, 0]);
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 2, &short);
        d.push_packet(crate::link::LINKTYPE_ETHERNET, 3, &eth_ipv6_next(50));
        // R311y861 — a HELD packet too, so the third class is non-zero in the
        // fixture. A partition assertion whose third term is 0 holds just as
        // well with that term dropped from `total`, which is the mistake this
        // test exists to catch.
        let mut udp = alloc::vec::Vec::new();
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&7446u16.to_be_bytes());
        udp.extend_from_slice(&64u16.to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&[0u8; 16]);
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            4,
            &eth_ipv4_piece(0x5151, 0, true, &udp),
        );
        d.finish();

        let sk = d.skip_census();
        assert!(
            sk.bytes_absent() > 0 && sk.not_this_protocol() > 0 && sk.held() > 0,
            "every class must be non-zero or the partition proves nothing: {sk:?}"
        );
        assert_eq!(
            sk.bytes_absent() + sk.not_this_protocol() + sk.held(),
            sk.total(),
            "the three classes must partition the census: {sk:?}"
        );
        assert_eq!(
            sk.total(),
            d.health().packets_skipped,
            "and the census must still agree with the counter it shadows"
        );
    }

    /// The other half of the leg above: a capture that skipped NOTHING must not
    /// grow a block about skipping, and the health document must carry the
    /// group anyway.
    ///
    /// Without this, a rendering that printed the breakdown unconditionally
    /// would pass every assertion above while making every clean capture report
    /// look like it had trouble -- and a structural group that vanished on a
    /// clean capture would make a consumer's field lookup depend on the file.
    #[test]
    fn a_capture_that_skipped_nothing_says_so_only_where_the_document_is_structural() {
        let d = crate::Dissection::new();
        assert!(d.skip_census().is_empty(), "the control must skip nothing");

        let text = CaptureReport::of(&d).to_text();
        assert!(
            !text.contains("reader skipped"),
            "a clean capture is not told about a hazard it does not have: {text}"
        );

        let health = health_text(&d);
        assert!(
            health.contains("reader skipped: 0 packet(s)"),
            "the health document is structural, so the group is present with zeroes: {health}"
        );
        assert!(
            health_json(&d).contains("\"skips\":{\"total\":0"),
            "and so is its JSON: {}",
            health_json(&d)
        );
    }

    // ── R311y891: the wire chooses the text, not the document's shape ─────
    //
    // `debt-census-emit-two-renderings` says the CLI report and
    // `census_json` render the same tables twice and nothing measures the
    // difference. Measuring it found one that is not a matter of taste:
    // `census_json` puts every wire-sourced string through
    // `wz_session_core::json::escape_into` and the report put THREE of them
    // through `format!("\"{x}\"")` -- the node plane's locators and the
    // interest plane's two keyexprs.
    //
    // Both tests below judge the WHOLE document with this crate's own JSON
    // scanner rather than looking for an escaped substring. A substring check
    // is a claim about a spelling; a publisher choosing where this document's
    // fields end is a claim about the document, and only one of them is what
    // this module's doc says the escaping is for.

    /// A keyexpr that closes the string and opens a field of its own does not
    /// get one.
    ///
    /// The keyexpr is the exact byte string `escape_into`'s own unit test uses
    /// (`a","injected":"x`), so the two agree about what a hostile name is. The
    /// control character is the second half and it is not decoration: RFC 8259
    /// forbids a raw byte below 0x20 INSIDE a string even though it is legal
    /// whitespace outside one, so a writer that escaped the quote and passed
    /// the tab through would still emit a document this scanner refuses.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_keyexpr_that_closes_its_own_string_does_not_reshape_the_report() {
        let hostile = "a\",\"injected\":\"x\u{9}y";
        let declare = wz_session_core::declare_build::build_declare_subscriber(1, 0, Some(hostile))
            .expect("the production builder")
            .try_as_borrowed()
            .expect("re-borrow")
            .encode_to_vec();
        let mut w = alloc::vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
        w.extend_from_slice(&declare);

        let mut d = crate::Dissection::new();
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::udp_packet([10, 0, 0, 1], 50000, [10, 0, 0, 2], 7447, &w),
        );
        let census = crate::interest::interests(&d);
        // THE POPULATION. Without this the assertions below are satisfied by a
        // report that carries no interest plane at all.
        assert_eq!(
            census.interests().len(),
            1,
            "the hostile declaration must have been READ, or nothing renders it",
        );
        assert_eq!(
            census.interests()[0].keyexpr.as_deref(),
            Some(hostile),
            "and read whole -- a truncated keyexpr would defuse the fixture",
        );
        let table = crate::agg::aggregate(&d);
        let coverage = census.coverage(&table);

        let json = CaptureReport::of(&d)
            .with_interests(&census, &coverage)
            .to_json();
        crate::payload::json_wellformed(json.as_bytes()).unwrap_or_else(|(at, why)| {
            panic!("the report is not JSON at byte {at}: {why}\n{json}")
        });
        assert!(
            !json.contains("\"injected\":"),
            "the keyexpr opened a field of its own: {json}",
        );
    }

    /// The same rule one plane over: a LOCATOR is a string a peer chose too.
    ///
    /// Held apart from the test above rather than folded into it, because the
    /// two fields are rendered by different code and the escaping was missing
    /// from both independently. A single test covering one of them would have
    /// left the other exactly as it was.
    #[test]
    fn a_locator_that_closes_its_own_string_does_not_reshape_the_report() {
        use wz_session_core::codec_owned::{owned_bytes, owned_string};
        let hostile = "tcp/a\",\"injected\":\"x";
        let zid = [0x55u8, 0x66, 0x77, 0x88];
        let owned: wz_codecs::hello::HelloOwned = wz_codecs::hello::HelloOwned {
            version: 0x09,
            cbyte: (((zid.len() as u8) - 1) << 4) | 0x01,
            zid: owned_bytes(&zid).expect("zid"),
            num_locators: Some(1),
            locators: Some(alloc::vec![wz_codecs::locator::LocatorOwned {
                locator_len: hostile.len() as u64,
                locator: owned_string(hostile).expect("locator"),
            }]),
        };
        let body = owned
            .try_as_borrowed()
            .expect("borrowed projection")
            .encode_to_vec(1);
        let mut wire = alloc::vec![
            wz_session_core::wire_const::S_MID_HELLO | wz_session_core::wire_const::FLAG_S_HELLO_L
        ];
        wire.extend_from_slice(&body);

        let mut d = crate::Dissection::new();
        // The SCOUT first: a HELLO is read as an ANSWER, so a capture that
        // carries only the answer names no node at all. `node`'s own fixture
        // states the same ordering.
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::udp_packet(
                [192, 168, 1, 5],
                43210,
                crate::datagram_tests::SCOUT_GROUP,
                7446,
                &crate::datagram_tests::scout_message(),
            ),
        );
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            1,
            &crate::datagram_tests::udp_packet(
                [192, 168, 1, 9],
                7447,
                [192, 168, 1, 5],
                43210,
                &wire,
            ),
        );
        d.finish();
        let census = crate::node::nodes(&d);
        assert_eq!(
            census
                .nodes()
                .iter()
                .filter(|n| n.locators.iter().any(|l| l == hostile))
                .count(),
            1,
            "the hostile locator must have been READ: {:?}",
            census.nodes(),
        );

        let json = CaptureReport::of(&d).with_nodes(&census).to_json();
        crate::payload::json_wellformed(json.as_bytes()).unwrap_or_else(|(at, why)| {
            panic!("the report is not JSON at byte {at}: {why}\n{json}")
        });
        assert!(
            !json.contains("\"injected\":"),
            "the locator opened a field of its own: {json}",
        );
    }
}

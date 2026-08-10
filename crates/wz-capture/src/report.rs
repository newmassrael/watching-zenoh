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
//! conditional on being non-zero), and [`CaptureReport::is_complete`] is a
//! single field a consumer can branch on without knowing which planes ran.
//!
//! ## Format
//!
//! JSON, hand-written, because this crate has zero third-party dependencies and
//! a serialiser is thirty lines. The escaping is the part that has to be right
//! rather than short: a keyexpr is attacker-influenced text on the wire, and a
//! writer that emitted it raw would let a publisher choose the shape of this
//! tool's output. [`escape_into`] handles every character RFC 8259 requires and
//! is pinned character by character in this module's tests.
//!
//! A text rendering sits beside it for the human case. It is deliberately NOT
//! the JSON reformatted: a person wants the heavy keyexprs and whether anything
//! is missing, and a machine wants every field.

use alloc::format;
use alloc::string::{String, ToString};

use crate::agg::{ThroughputGaps, ThroughputTable};

/// One capture's findings, ready to render.
///
/// Planes are OPTIONAL and named individually rather than recomputed here: a
/// caller that only ran the throughput plane must be able to say so, and a
/// report that silently re-derived a plane would report on data the caller
/// never inspected.
#[derive(Debug, Clone, Copy)]
pub struct CaptureReport<'a> {
    dissection: &'a crate::Dissection,
    throughput: Option<&'a ThroughputTable>,
    #[cfg(feature = "network-codecs")]
    exchanges: Option<&'a crate::exchange::ExchangeTable>,
    #[cfg(feature = "network-codecs")]
    payloads: Option<&'a crate::payload::PayloadCensus>,
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
        }
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

    /// `true` when nothing anywhere in this report is known to be missing.
    ///
    /// The conjunction of every loss counter the included planes carry, plus
    /// the dissection's own skipped packets. A consumer that treats a total as
    /// the capture's total must consult this first — which is why it is one
    /// field rather than a walk over three structs the caller would have to
    /// know about.
    pub fn is_complete(&self) -> bool {
        if self.dissection.health().packets_skipped > 0 || self.dissection.drops().any() {
            return false;
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
        if self.dissection.encrypted_census().flows > 0 {
            return false;
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
        if self.dissection.expired_chains() > 0 {
            return false;
        }
        let framing = self.dissection.framing_health();
        //
        // R311y631 (§1.2b) — `unaccounted_batch_bytes` DOES reach the verdict,
        // on the same rule that keeps `reserved_headers` out of it: it counts
        // bytes of a framing unit this reader could not attribute to any
        // message, which is a shortfall in the rows and not a fact about the
        // sender. A capture whose batches were walked only part way is a
        // capture whose totals are a floor.
        if framing.gaps_forced > 0
            || framing.desyncs > 0
            || framing.ws_desyncs > 0
            || framing.sn_missing > 0
            || framing.unaccounted_batch_bytes > 0
        {
            return false;
        }
        if let Some(t) = self.throughput {
            if !t.gaps().is_clean() || t.unresolved_records() > 0 {
                return false;
            }
            // R311y637 (§1.1w) — a record whose payload this build cannot size
            // makes `total_payload_bytes` a floor, so it reaches the verdict on
            // the same rule as an unread batch. It is NOT a `gaps()` member:
            // the record was read and attributed, and only its byte
            // contribution is unknown. A reader who sums the table still has
            // to be told the sum is short.
            if t.unsized_payloads() > 0 {
                return false;
            }
            // R311y616 — a selector that could not judge part of the capture
            // makes the rows under it a floor, exactly as an unread batch does.
            // The two shortfalls have different causes and the same
            // consequence for a reader summing the table, so they reach the
            // same verdict. An unfiltered report is unaffected: the identity
            // filter leaves nothing undecided.
            if !t.selection().is_decisive() {
                return false;
            }
        }
        #[cfg(feature = "network-codecs")]
        if let Some(e) = self.exchanges {
            if !e.gaps().is_clean() || !e.unread().is_clean() || e.unclosed() > 0 {
                return false;
            }
            // R311y618 — the same rule the throughput plane got in R311y616,
            // reached one plane later: an exchange the selector could not judge
            // is an exchange missing from the rows, and a reader summing them
            // has to be told.
            if !e.selection().is_decisive() {
                return false;
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
                return false;
            }
            if !p.selection().is_decisive() {
                return false;
            }
        }
        true
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
        self.capture_json(&mut s);
        if let Some(t) = self.throughput {
            s.push(',');
            throughput_json(t, &mut s);
        }
        #[cfg(feature = "network-codecs")]
        if let Some(e) = self.exchanges {
            s.push(',');
            exchanges_json(e, &mut s);
        }
        #[cfg(feature = "network-codecs")]
        if let Some(p) = self.payloads {
            s.push(',');
            payloads_json(p, &mut s);
        }
        s.push_str(",\"complete\":");
        s.push_str(if self.is_complete() { "true" } else { "false" });
        s.push('}');
        s
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
        let enc = d.encrypted_census();
        s.push_str(&format!(
            ",\"encrypted\":{{\"flows\":{},\"records\":{},\"application_records\":{},\
             \"application_bytes\":{},\"decrypted\":false,\"reason\":\"{}\"}}",
            enc.flows,
            enc.census.records,
            enc.census.application_records,
            enc.census.application_bytes,
            match d.encrypted_flows().first().map(|e| e.not_decrypted) {
                None | Some(crate::tls::NotDecrypted::NoKeysSupplied) => "no_keys_supplied",
            }
        ));
        // R311y643 (§1.1e) — the skip count above is a number; this is what it
        // MEANS. Structural like `gaps`: present with zeroes on a clean capture,
        // so a consumer's field lookup never depends on this particular file
        // having had that kind of trouble.
        let sk = d.skip_census();
        s.push_str(&format!(
            ",\"skips\":{{\"unsupported_link_type\":{},\"truncated\":{},\
             \"not_ip\":{},\"not_transport\":{},\"ipv4_fragment\":{},\
             \"ip_fragment_pending\":{},\"vsock_non_payload\":{},\
             \"ipv6_extension_chain\":{},\"ipv6_fragment\":{},\"link_types\":[",
            sk.unsupported_link_type,
            sk.truncated,
            sk.not_ip,
            sk.not_transport,
            sk.ipv4_fragment,
            sk.ip_fragment_pending,
            sk.vsock_non_payload,
            sk.ipv6_extension_chain,
            sk.ipv6_fragment
        ));
        for (i, dlt) in sk.unsupported_link_types.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("{dlt}"));
        }
        s.push_str("]}");
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
        // The figure the CAPTURE FILE reports about itself, which is a
        // different claim from anything this reader counted: `null` when the
        // format carried none, never 0.
        // R311y654 (§1.1f) — STRUCTURAL like `skips` and `encrypted`: present
        // with a zero on a build that reassembles nothing, so a consumer's
        // field lookup never depends on which features this binary carries.
        s.push_str(&format!(
            ",\"reassembly\":{{\"expired_chains\":{}}}",
            d.expired_chains()
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
        if self.is_complete() {
            s.push_str("capture: complete\n");
        } else {
            s.push_str("capture: INCOMPLETE -- totals below are a floor, not the whole capture\n");
        }
        s.push_str(&format!(
            "  flows: {} stream, {} datagram; packets skipped: {}\n",
            d.flows().len(),
            d.datagram_flows().len(),
            health.packets_skipped
        ));
        // R311y643 (§1.1e) — the line that turns a skip COUNT into a
        // diagnosis, and it leads with the link types because that is the one
        // reason a reader can act on: every other skip is furniture in an
        // otherwise-readable capture, while this one means the file was never
        // read. Printed only when this build refused a link type at all.
        let sk = d.skip_census();
        if !sk.unsupported_link_types.is_empty() {
            let mut dlts = String::new();
            for (i, dlt) in sk.unsupported_link_types.iter().enumerate() {
                if i > 0 {
                    dlts.push_str(", ");
                }
                dlts.push_str(&format!("{dlt}"));
            }
            s.push_str(&format!(
                "  link type not read by this build: {} ({} packet(s)); \
                 this capture was not dissected\n",
                dlts, sk.unsupported_link_type
            ));
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
        let enc = d.encrypted_census();
        if enc.flows > 0 {
            s.push_str(&format!(
                "  {} flow(s) carry zenoh inside TLS: {} record(s), {} byte(s) of \
                 application data. NOT DECRYPTED (no keys supplied) -- the \
                 session is there and this report cannot see into it\n",
                enc.flows, enc.census.records, enc.census.application_bytes
            ));
        }
        // R311y654 (§1.1f) — and the bound this reader applied to ITSELF, which
        // no other line here reports. Every other qualifier names something the
        // wire or the capture tool did; this one names a message the analyzer
        // gave up on, and a reader who is not told cannot distinguish it from a
        // message that was never sent.
        if d.expired_chains() > 0 {
            s.push_str(&format!(
                "  {} reassembly chain(s) ABANDONED on this reader's own \
                 deadline; the messages they carried are absent from the totals \
                 below\n",
                d.expired_chains()
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
                s.push_str(&format!(
                    "  {:>12} B  {:>6} msg  {}\n",
                    totals.payload_bytes,
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
        s.push_str(&format!(
            ",\"first_anchor\":{},\"last_anchor\":{}}}",
            row.first_anchor, row.last_anchor
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
    }
}

#[cfg(feature = "network-codecs")]
fn mismatch_offset(m: &crate::payload::Mismatch) -> usize {
    use crate::payload::Mismatch;
    match m {
        Mismatch::NotUtf8 { at } | Mismatch::NotJson { at, .. } => *at,
    }
}

fn opt_u64(v: Option<u64>) -> String {
    match v {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    }
}

/// Write `s` as a quoted JSON string.
fn quote_into(value: &str, out: &mut String) {
    out.push('"');
    escape_into(value, out);
    out.push('"');
}

/// Escape one string's contents per RFC 8259 §7.
///
/// A keyexpr arrives from the wire and this tool prints it, so the escaping is
/// a correctness boundary rather than a formatting nicety: a publisher that
/// chooses a name containing a quote would otherwise choose where this
/// document's fields end. Every character the RFC requires is handled —
/// quote, reverse solidus, and every control character below 0x20 — with the
/// five short forms it defines and `\u00XX` for the rest.
fn escape_into(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every escape RFC 8259 §7 requires, checked one character at a time
    /// against the form the RFC names — not against this writer's own output.
    #[test]
    fn every_character_json_requires_escaping_is_escaped_as_the_rfc_names_it() {
        for (input, expected) in [
            ("plain", "plain"),
            ("with\"quote", "with\\\"quote"),
            ("back\\slash", "back\\\\slash"),
            ("new\nline", "new\\nline"),
            ("carriage\rreturn", "carriage\\rreturn"),
            ("tab\there", "tab\\there"),
            ("bs\u{08}", "bs\\b"),
            ("ff\u{0C}", "ff\\f"),
            ("nul\u{00}", "nul\\u0000"),
            ("esc\u{1B}", "esc\\u001b"),
            ("unit\u{1F}", "unit\\u001f"),
            // Above 0x1F nothing is required, including non-ASCII: valid UTF-8
            // is valid JSON, and escaping it would be a second encoding of the
            // same bytes.
            ("공간/온도", "공간/온도"),
            ("space here", "space here"),
        ] {
            let mut got = String::new();
            escape_into(input, &mut got);
            assert_eq!(got, expected, "escaping {input:?}");
        }
    }

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
        assert!(
            text.contains("link type not read by this build: 250"),
            "the text must name what it refused: {text}"
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
    /// [`CaptureReport::is_complete`] changed nothing and the suite stayed
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
        assert!(
            !CaptureReport::of(&d)
                .with_exchanges(&exchanges)
                .is_complete(),
            "an exchange the selector could not judge is missing from the rows"
        );

        let payloads = crate::payload::payloads_where(&d, &filter);
        assert_eq!(payloads.selection().undecided, 1);
        assert!(payloads.gaps().is_clean());
        assert!(
            !CaptureReport::of(&d).with_payloads(&payloads).is_complete(),
            "a payload the selector could not judge is missing from the census"
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
}

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
        if let Some(t) = self.throughput {
            if !t.gaps().is_clean() || t.unresolved_records() > 0 {
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
        s.push_str(&format!(
            ",\"drops\":{{\"frames\":{},\"stream_bytes\":{},\"skipped\":{},\"flows\":{},\"scout_askers\":{}}}",
            drops.frames, drops.stream_bytes, drops.skipped, drops.flows, drops.scout_askers
        ));
        // The figure the CAPTURE FILE reports about itself, which is a
        // different claim from anything this reader counted: `null` when the
        // format carried none, never 0.
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
            for row in t.rows() {
                let totals = row.totals();
                s.push_str(&format!(
                    "  {:>12} B  {:>6} msg  {}\n",
                    totals.payload_bytes,
                    totals.messages(),
                    row.keyexpr
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

fn throughput_json(t: &ThroughputTable, s: &mut String) {
    let (declared, undeclared) = t.declarations();
    s.push_str("\"throughput\":{");
    s.push_str(&format!(
        "\"records\":{},\"unattributed_records\":{},\"walked_records\":{},\
         \"unresolved_records\":{},\"total_payload_bytes\":{}",
        t.records(),
        // R311y622 (§1.4h) — the denominator rides BESIDE the numerator rather
        // than being left for the consumer to add up from four fields, which is
        // the arithmetic nobody does.
        t.unattributed_records(),
        t.walked_records(),
        t.unresolved_records(),
        t.total_payload_bytes()
    ));
    s.push_str(&format!(
        ",\"declarations\":{declared},\"undeclarations\":{undeclared}"
    ));
    s.push_str(",\"gaps\":");
    gaps_json(t.gaps(), s);
    s.push_str(",\"selection\":");
    selection_json(t.selection(), s);
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

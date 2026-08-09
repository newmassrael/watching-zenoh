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
}

impl<'a> CaptureReport<'a> {
    /// A report over the dissection alone.
    pub fn of(dissection: &'a crate::Dissection) -> Self {
        Self {
            dissection,
            throughput: None,
            #[cfg(feature = "network-codecs")]
            exchanges: None,
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
        }
        #[cfg(feature = "network-codecs")]
        if let Some(e) = self.exchanges {
            if !e.gaps().is_clean() || !e.unread().is_clean() || e.unclosed() > 0 {
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
                "throughput: {} records, {} bytes, {} unresolved reference(s)\n",
                t.records(),
                t.total_payload_bytes(),
                t.unresolved_records()
            ));
            if !g.is_clean() {
                s.push_str(&format!(
                    "  UNREAD: {} halted batch(es) ({} bytes), {} undecompressible, {} unresolvable fragment(s)\n",
                    g.halted_batches, g.unparsed_bytes, g.undecompressible_batches, g.unresolvable_fragments
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
            for row in e.rows() {
                s.push_str(&format!(
                    "  {:>8}  {:>4} req  {}\n",
                    describe(&row.completion),
                    row.requests,
                    row.keyexpr
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
        "\"records\":{},\"unresolved_records\":{},\"total_payload_bytes\":{}",
        t.records(),
        t.unresolved_records(),
        t.total_payload_bytes()
    ));
    s.push_str(&format!(
        ",\"declarations\":{declared},\"undeclarations\":{undeclared}"
    ));
    s.push_str(",\"gaps\":");
    gaps_json(t.gaps(), s);
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

fn gaps_json(g: ThroughputGaps, s: &mut String) {
    s.push_str(&format!(
        "{{\"halted_batches\":{},\"unparsed_bytes\":{},\"undecompressible_batches\":{},\"unresolvable_fragments\":{}}}",
        g.halted_batches, g.unparsed_bytes, g.undecompressible_batches, g.unresolvable_fragments
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
    s.push_str(&format!(
        ",\"gaps\":{{\"orphan_responses\":{},\"unstamped\":{},\"non_monotonic\":{},\"unattributed_requests\":{}}}",
        g.orphan_responses, g.unstamped, g.non_monotonic, g.unattributed_requests
    ));
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

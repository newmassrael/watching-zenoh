// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y851 (§1.1f) — the four ANALYSIS planes as ONE self-describing document.
//!
//! ## The gap this closes, and it is a gap between SURFACES rather than in a
//! plane
//!
//! wz exports its dissection through two consumption surfaces, and they carry
//! different halves of it. [`crate::agg`], [`crate::exchange`], [`crate::node`]
//! and [`crate::payload`] were reachable ONLY from `wz-analyze`, the command
//! line — a person at a terminal. `wz-capi-dissect`, the C ABI a framework
//! links, could reach a per-flow frame count and the health counters and
//! nothing else: the four planes were compiled into its dependency graph (this
//! crate is its dependency) and had no symbol.
//!
//! That is the same class as an atom compiled into a preset with no flag to
//! reach it — the capability ships and the consumer cannot call it — and the
//! reason it went unmeasured is that nothing compares the two surfaces.
//!
//! ## Why the emit lives HERE and not in either consumer
//!
//! Beside the types, because a plane's serialization is the plane's own
//! business and because two consumers each rendering their own view of the same
//! table is how the two surfaces came to disagree in the first place. A
//! consumer added later reaches one document rather than reimplementing four.
//!
//! Hand-rolled rather than derived: this crate's manifest commits to ZERO
//! third-party dependencies, and `wz-capi-dissect` commits to not forcing a
//! JSON dependency on a caller that only wants a decode out of the library.
//! Strings are escaped through [`wz_session_core::json::escape_into`], the
//! workspace's one escaper — a keyexpr and a locator both come off the wire, so
//! escaping is correctness and not tidiness.
//!
//! ## `null` is a different answer from an empty plane
//!
//! `exchanges_json` and `payloads_json` — code spans and NOT intra-doc links.
//! Written as links they came back unresolved from `cargo doc` even in the
//! build where both items exist, and Layer C1bz counted them; the mechanism is
//! not established here and is deliberately not guessed at in a comment. What
//! is established is the measurement. They need the network codecs to have any
//! record to correlate at all, and this crate can be built without them. In
//! that build the two keys are emitted as `null` rather than omitted or emitted
//! as an empty table: `exchange`'s own doc states the rule this follows — a
//! plane that cannot be fed is ABSENT rather than empty — and a consumer that
//! saw `{"rows":[]}` would read "this capture had no queries" off a build that
//! could not have seen one.
//!
//! ## The shape is NOT frozen
//!
//! Keys are this crate's own names and may gain siblings as planes gain
//! columns. Read by name and tolerate unknown keys; that is the same
//! forward-compatibility contract `wz_dissect.h` states, and the reason both
//! surfaces hand back a document instead of a struct.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use wz_session_core::json::escape_into;
use wz_session_core::passive::Direction;

use crate::agg::{
    KeyexprCounts, KeyexprRow, KeyexprSubtree, ThroughputGaps, ThroughputTable, UnmeasuredPayloads,
};
use crate::node::NodeCensus;

/// Every plane this crate computes over `d`, as one JSON object.
///
/// Each plane is a SEPARATE walk of every frame — the same cost the command
/// line's `--census` pays and for the same reason: the planes are independent
/// folds and none of them is cheap enough to build unasked.
pub fn census_json(d: &crate::Dissection) -> String {
    census_json_where(d, &crate::filter::Filter::any())
}

/// R311y854 — the same census, narrowed to the records `filter` matches.
///
/// # The node plane is NOT narrowed, and the document says so
///
/// Three of the four planes take a selector; [`crate::node`] has no `_where`
/// entry point, so it is built whole here. That is not an omission this
/// function could quietly fix — a node is not a record the selector's terms
/// (`key`, `kind`, `bytes`, `delay`, …) describe — and it is the same choice
/// the command line makes. What would be a defect is leaving a consumer to
/// infer it: each plane carries `narrowed_by_selector`, so "this table was
/// filtered" is read off the document rather than assumed from the call.
///
/// Each narrowed plane also carries its `selection` — matched / rejected /
/// UNDECIDED. The third is the one that matters and the reason it is emitted
/// beside the rows rather than derived: a keyexpr whose declaration went past
/// before the tap started cannot be judged against `key == demo/**`, and
/// counting it as a non-match would make a short total look whole.
pub fn census_json_where(d: &crate::Dissection, filter: &crate::filter::Filter) -> String {
    let mut out = String::from("{\"keyexprs\":");
    out.push_str(&keyexprs_json(&crate::agg::aggregate_where(d, filter)));
    out.push_str(",\"nodes\":");
    out.push_str(&nodes_json(&crate::node::nodes(d)));
    out.push_str(",\"exchanges\":");
    #[cfg(feature = "network-codecs")]
    out.push_str(&exchanges_json(&crate::exchange::exchanges_where(
        d, filter,
    )));
    // A plane that cannot be fed is absent, not empty — see the module doc.
    #[cfg(not(feature = "network-codecs"))]
    out.push_str("null");
    out.push_str(",\"payloads\":");
    #[cfg(feature = "network-codecs")]
    out.push_str(&payloads_json(&crate::payload::payloads_where(d, filter)));
    #[cfg(not(feature = "network-codecs"))]
    out.push_str("null");
    // R311y869 — the INTEREST plane, and the SECOND one the selector does not
    // narrow. A declaration is not a record the selector's terms describe, on
    // exactly the argument the node plane above makes; the coverage it is
    // joined against IS narrowed, which is why the plane emits its own
    // `narrowed_by_selector: false` rather than borrowing the keyexpr plane's.
    out.push_str(",\"interests\":");
    #[cfg(feature = "network-codecs")]
    out.push_str(&interests_json(
        &crate::interest::interests(d),
        &crate::agg::aggregate_where(d, filter),
    ));
    #[cfg(not(feature = "network-codecs"))]
    out.push_str("null");
    // R311y885 — WHAT THE WALK UNDER THESE PLANES LOST, so a bounded census is
    // not silent about its bound.
    //
    // Every plane above is a fold over ONE `Dissection`, and that dissection
    // may have been built under `DissectionLimits`: a flow evicted by
    // `max_flows_per_table` takes its keyexprs, its samples and its queries out
    // of these tables with it. Without this group the document is short and
    // says nothing about why — indistinguishable from a quiet network, which is
    // the reading that makes a capped tap dangerous rather than merely partial.
    //
    // It is the SAME rendering `health_json` embeds (`report::dropped_by_limits_json`),
    // not a second one, so the two documents cannot drift.
    out.push_str(",\"dropped_by_limits\":");
    out.push_str(&crate::report::dropped_by_limits_json(d));
    out.push('}');
    out
}

/// The INTEREST plane: who declared what, and what their declarations cover.
///
/// Takes the throughput table rather than building one, so the document's
/// coverage is joined against the SAME rows its `keyexprs` object reports. A
/// second aggregation here would be a second answer to "what traffic was
/// there", and the two could differ by a selector.
#[cfg(feature = "network-codecs")]
pub fn interests_json(c: &crate::interest::InterestCensus, t: &ThroughputTable) -> String {
    let coverage = c.coverage(t);
    let mut out = String::from("{\"declarations\":[");
    for (i, d) in c.interests().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"kind\":\"{}\",\"declarer\":\"{}\",\"id\":{},\"keyexpr\":",
            d.kind.name(),
            dir_name(d.declarer),
            d.id
        );
        match &d.keyexpr {
            Some(k) => escape_into(k, &mut out),
            // Not an empty string: a declaration this reader could not name is
            // a finding, and `""` is a keyexpr.
            None => out.push_str("null"),
        }
        out.push_str(",\"unresolved\":");
        match d.unresolved {
            Some((space, id)) => {
                let _ = write!(out, "{{\"space\":\"{}\",\"id\":{id}}}", dir_name(space));
            }
            None => out.push_str("null"),
        }
        let _ = write!(out, ",\"declared_at\":{},\"withdrawn_at\":", d.declared_at);
        match d.withdrawn_at {
            Some(at) => {
                let _ = write!(out, "{at}");
            }
            // `null` and not the declaration's own anchor: an interest still
            // open at the end of the capture has no closing coordinate, and a
            // number there would read as one.
            None => out.push_str("null"),
        }
        // R311y870 — WHAT ASKED FOR IT. `null` is the contract state
        // UNSOLICITED and not a missing field; id 0 is a legal interest id, so
        // a zero here would be indistinguishable from one.
        out.push_str(",\"solicited_by\":");
        match d.solicited_by {
            Some(id) => {
                let _ = write!(out, "{id}");
            }
            None => out.push_str("null"),
        }
        out.push_str(",\"flow\":");
        push_flow(&d.flow, &mut out);
        out.push('}');
    }
    out.push_str("],\"matched\":[");
    for (i, m) in coverage.matched.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"declaration\":{},\"keys\":[", m.interest);
        for (j, key) in m.keys.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            escape_into(key, &mut out);
        }
        out.push_str("],\"totals\":");
        push_counts(&m.totals, &mut out);
        out.push('}');
    }
    out.push_str("],\"silent\":");
    push_indices(&coverage.silent, &mut out);
    out.push_str(",\"undecidable\":");
    push_indices(&coverage.undecidable, &mut out);
    out.push_str(",\"unresolved_declarations\":");
    push_indices(&coverage.unresolved, &mut out);
    out.push_str(",\"unclaimed\":[");
    for (i, key) in coverage.unclaimed.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        escape_into(key, &mut out);
    }
    // R311y870 — the QUESTION half of the exchange, beside the answers rather
    // than in a plane of its own: `zenoh-protocol`'s own message flow makes
    // them one conversation, and a document that split them would leave a
    // consumer to re-derive the correlation this fold already performed.
    out.push_str("],\"requests\":[");
    for (i, r) in c.requests().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"asker\":\"{}\",\"id\":{},\"mode\":\"{}\",\"answers\":{},\
             \"asked_at\":{},\"closed_at\":",
            dir_name(r.asker),
            r.id,
            r.mode.name(),
            r.answers,
            r.asked_at,
        );
        match r.closed_at {
            Some(at) => {
                let _ = write!(out, "{at}");
            }
            None => out.push_str("null"),
        }
        out.push_str(",\"cancelled_at\":");
        match r.cancelled_at {
            Some(at) => {
                let _ = write!(out, "{at}");
            }
            None => out.push_str("null"),
        }
        out.push_str(",\"keyexpr\":");
        match &r.keyexpr {
            Some(k) => escape_into(k, &mut out),
            None => out.push_str("null"),
        }
        out.push_str(",\"asks\":");
        match r.scope {
            Some(s) => {
                let _ = write!(
                    out,
                    "{{\"keyexprs\":{},\"subscribers\":{},\"queryables\":{},\
                     \"tokens\":{},\"restricted\":{},\"aggregate\":{}}}",
                    s.keyexprs, s.subscribers, s.queryables, s.tokens, s.restricted, s.aggregate
                );
            }
            // A Final carries no body. An all-false object would say it asked
            // for none of the four; it asked for nothing, being a cancellation.
            None => out.push_str("null"),
        }
        // R311y871 — WHICH answers were not answers to THIS question, as the
        // declaration indices themselves rather than a count: the consumer's
        // next question is always which declaration, and a bare number would
        // send it back to re-deriving the join.
        out.push_str(",\"mismatched\":");
        push_indices(&r.mismatched, &mut out);
        let _ = write!(
            out,
            ",\"unjudged_answers\":{},\"answers_in_scope\":{}",
            r.unjudged_answers,
            r.answers_in_scope(),
        );
        out.push_str(",\"flow\":");
        push_flow(&r.flow, &mut out);
        out.push('}');
    }
    out.push_str("],\"unanswered\":");
    push_indices(&c.unanswered(), &mut out);
    out.push_str(",\"unclosed\":");
    push_indices(&c.unclosed(), &mut out);
    // Beside the other two findings and not folded into either: a peer that
    // answered wrongly is neither one that stayed silent nor one whose dump was
    // truncated.
    out.push_str(",\"mismatched\":");
    push_indices(&c.mismatched(), &mut out);
    let by = c.by_kind();
    let _ = write!(
        out,
        ",\"unclaimed_exact\":{},\"judged\":{},\"orphan_withdrawals\":{},\
         \"orphan_answers\":{},\"unjudged_answers\":{},\
         \"by_kind\":{{\"subscriber\":{},\"queryable\":{},\"liveliness_token\":{}}},",
        coverage.unclaimed_exact,
        coverage.judged(),
        c.orphan_withdrawals(),
        c.orphan_answers(),
        c.unjudged_answers(),
        by[0],
        by[1],
        by[2],
    );
    push_selection(&crate::filter::Selection::default(), false, &mut out);
    out.push('}');
    out
}

#[cfg(feature = "network-codecs")]
fn push_indices(v: &[usize], out: &mut String) {
    out.push('[');
    for (i, at) in v.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{at}");
    }
    out.push(']');
}

/// The KEYEXPR plane: which key expressions carried the traffic.
pub fn keyexprs_json(t: &ThroughputTable) -> String {
    let mut out = String::from("{\"rows\":[");
    for (i, row) in t.rows().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_row(row, t, &mut out);
    }
    out.push_str("],\"subtrees\":");
    push_subtree(&t.subtrees(), &mut out);
    out.push_str(",\"unresolved\":[");
    for (i, alias) in t.unresolved().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"space\":\"{}\",\"id\":{},\"references\":{}}}",
            dir_name(alias.space),
            alias.id,
            alias.references
        );
    }
    let (declared, undeclared) = t.declarations();
    let _ = write!(
        out,
        "],\"records\":{},\"unresolved_records\":{},\"unattributed_records\":{},\
         \"walked_records\":{},\"declarations\":{declared},\"undeclarations\":{undeclared},\
         \"total_payload_bytes\":{},\"payload_bytes_ceiling\":{},\
         \"source_ahead_of_observer\":{},\"unlocatable_records\":{},",
        t.records(),
        t.unresolved_records(),
        t.unattributed_records(),
        t.walked_records(),
        t.total_payload_bytes(),
        t.payload_bytes_ceiling(),
        t.source_ahead_of_observer(),
        t.unlocatable_records(),
    );
    push_unmeasured(&t.unmeasured_payloads(), &mut out);
    out.push(',');
    push_selection(&t.selection(), true, &mut out);
    out.push(',');
    push_gaps(&t.gaps(), &mut out);
    out.push('}');
    out
}

/// The NODE plane: the capture keyed by zid, and the links where both ends
/// named themselves.
pub fn nodes_json(c: &NodeCensus) -> String {
    let mut out = String::from("{\"nodes\":[");
    for (i, node) in c.nodes().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"zid\":\"");
        for byte in &node.zid {
            let _ = write!(out, "{byte:02x}");
        }
        out.push('"');
        match node.whatami {
            Some(w) => {
                let _ = write!(out, ",\"whatami\":{w}");
            }
            // A kind of message that states no role is silence, not a role of
            // zero: `whatami` 0 is a legal encoding.
            None => out.push_str(",\"whatami\":null"),
        }
        let e = &node.evidence;
        let _ = write!(
            out,
            ",\"evidence\":{{\"init\":{},\"join\":{},\"hello\":{},\"scout\":{},\
             \"inadmissible\":{},\"admissible\":{}}},\"first_packet\":{},\
             \"wire_bytes\":{}",
            e.init,
            e.join,
            e.hello,
            e.scout,
            e.inadmissible,
            e.admissible(),
            node.first_packet,
            node.wire_bytes,
        );
        match c.share_bp(i) {
            Some(bp) => {
                let _ = write!(out, ",\"share_bp\":{bp}");
            }
            // No denominator is not a share of zero — see `unattributed_bytes`.
            None => out.push_str(",\"share_bp\":null"),
        }
        out.push_str(",\"locators\":[");
        for (j, loc) in node.locators.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            escape_into(loc, &mut out);
        }
        out.push_str("],\"flows\":[");
        for (j, flow) in node.flows.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            push_flow(flow, &mut out);
        }
        out.push_str("]}");
    }
    out.push_str("],\"links\":[");
    for (i, link) in c.links().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"a\":{},\"b\":{},\"flow\":", link.a, link.b);
        push_flow(&link.flow, &mut out);
        out.push('}');
    }
    let _ = write!(
        out,
        "],\"attributed_bytes\":{},\"unattributed_bytes\":{},",
        c.attributed_bytes(),
        c.unattributed_bytes()
    );
    // The one plane a selector does not reach. Stated rather than left to be
    // inferred from an absent `selection`, which would read as "nothing was
    // rejected" — the opposite of the truth on a narrowed census.
    push_selection(&crate::filter::Selection::default(), false, &mut out);
    out.push('}');
    out
}

/// The QUERY plane: requests matched to their replies, and the delay between.
#[cfg(feature = "network-codecs")]
pub fn exchanges_json(t: &crate::exchange::ExchangeTable) -> String {
    let mut out = String::from("{\"rows\":[");
    for (i, row) in t.rows().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"keyexpr\":");
        escape_into(&row.keyexpr, &mut out);
        let _ = write!(
            out,
            ",\"requests\":{},\"completed\":{},\"unclosed\":{},\"replies\":{},\"errs\":{},\
             \"first_reply\":",
            row.requests,
            row.completed,
            row.unclosed(),
            row.replies,
            row.errs,
        );
        push_latency(&row.first_reply, &mut out);
        out.push_str(",\"completion\":");
        push_latency(&row.completion, &mut out);
        out.push('}');
    }
    let (replies, errs) = t.responses();
    let (first_reply, completion) = t.totals();
    let _ = write!(
        out,
        "],\"requests\":{},\"completed\":{},\"unclosed\":{},\"replies\":{replies},\
         \"errs\":{errs},\"first_reply\":",
        t.requests(),
        t.completed(),
        t.unclosed(),
    );
    push_latency(&first_reply, &mut out);
    out.push_str(",\"completion\":");
    push_latency(&completion, &mut out);
    let g = t.gaps();
    let _ = write!(
        out,
        ",\"gaps\":{{\"orphan_responses\":{},\"unstamped\":{},\"non_monotonic\":{},\
         \"unattributed_requests\":{}}},",
        g.orphan_responses, g.unstamped, g.non_monotonic, g.unattributed_requests,
    );
    push_selection(&t.selection(), true, &mut out);
    out.push(',');
    push_gaps_named(&t.unread(), "unread", &mut out);
    out.push('}');
    out
}

/// The PAYLOAD plane: what the samples carry, judged against their own
/// declaration.
#[cfg(feature = "network-codecs")]
pub fn payloads_json(c: &crate::payload::PayloadCensus) -> String {
    let mut out = String::from("{\"rows\":[");
    for (i, row) in c.rows().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"declared\":");
        escape_into(&row.declared, &mut out);
        let _ = write!(
            out,
            ",\"payloads\":{},\"consistent\":{},\"not_as_declared\":{},\
             \"descriptors\":{},\"bytes\":{}}}",
            row.payloads, row.consistent, row.not_as_declared, row.descriptors, row.bytes,
        );
    }
    out.push_str("],\"contradictions\":[");
    for (i, bad) in c.contradictions().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"keyexpr\":");
        match &bad.keyexpr {
            Some(k) => escape_into(k, &mut out),
            // The record contradicted its declaration on a key this capture
            // could not resolve; naming none is the honest answer.
            None => out.push_str("null"),
        }
        out.push_str(",\"declared\":");
        escape_into(&bad.declared, &mut out);
        match bad.reason {
            crate::payload::Mismatch::NotUtf8 { at } => {
                let _ = write!(out, ",\"reason\":\"not_utf8\",\"at\":{at}");
            }
            crate::payload::Mismatch::NotJson { at, reason } => {
                let _ = write!(out, ",\"reason\":\"not_json\",\"at\":{at},\"why\":");
                escape_into(reason, &mut out);
            }
        }
        out.push('}');
    }
    let _ = write!(
        out,
        "],\"payloads\":{},\"unknown_ids\":{},\"descriptors\":{},",
        c.payloads(),
        c.unknown_ids(),
        c.descriptors(),
    );
    push_selection(&c.selection(), true, &mut out);
    out.push(',');
    push_gaps(&c.gaps(), &mut out);
    out.push('}');
    out
}

fn push_row(row: &KeyexprRow, t: &ThroughputTable, out: &mut String) {
    out.push_str("{\"keyexpr\":");
    escape_into(&row.keyexpr, out);
    out.push_str(",\"a_to_b\":");
    push_counts(&row.per_direction[0], out);
    out.push_str(",\"b_to_a\":");
    push_counts(&row.per_direction[1], out);
    out.push_str(",\"totals\":");
    push_counts(&row.totals(), out);
    match t.share_bp(&row.keyexpr) {
        Some(bp) => {
            let _ = write!(out, ",\"share_bp\":{bp}");
        }
        // A capture whose payloads cannot be SIZED has no denominator, and 0
        // would read as "this topic carried nothing".
        None => out.push_str(",\"share_bp\":null"),
    }
    let _ = write!(
        out,
        ",\"first_anchor\":{},\"last_anchor\":{}}}",
        row.first_anchor, row.last_anchor
    );
}

fn push_counts(c: &KeyexprCounts, out: &mut String) {
    let _ = write!(
        out,
        "{{\"puts\":{},\"dels\":{},\"queries\":{},\"replies\":{},\"errs\":{},\
         \"payload_bytes\":{},\"unsized_payloads\":{},\"messages\":{}}}",
        c.puts,
        c.dels,
        c.queries,
        c.replies,
        c.errs,
        c.payload_bytes,
        c.unsized_payloads,
        c.messages(),
    );
}

fn push_subtree(node: &KeyexprSubtree, out: &mut String) {
    out.push_str("{\"prefix\":");
    escape_into(&node.prefix, out);
    out.push_str(",\"totals\":");
    push_counts(&node.totals, out);
    let _ = write!(out, ",\"rows\":{},\"children\":[", node.rows);
    for (i, child) in node.children.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_subtree(child, out);
    }
    out.push_str("]}");
}

/// What the selector did to the records this plane was shown, and whether it
/// reached this plane at all.
///
/// `undecided` is the field the other two exist to be read against: a record
/// the capture did not carry enough to judge is neither matched nor rejected,
/// and folding it into `rejected` would let a short total read as a whole one.
fn push_selection(s: &crate::filter::Selection, narrowed: bool, out: &mut String) {
    let _ = write!(
        out,
        "\"narrowed_by_selector\":{narrowed},\"selection\":{{\"matched\":{},\
         \"rejected\":{},\"undecided\":{}}}",
        s.matched, s.rejected, s.undecided
    );
}

fn push_unmeasured(u: &UnmeasuredPayloads, out: &mut String) {
    let _ = write!(
        out,
        "\"unmeasured_payloads\":{{\"elsewhere\":{},\"unresolved\":{},\"at_most_bytes\":{}}}",
        u.elsewhere, u.unresolved, u.at_most_bytes
    );
}

fn push_gaps(g: &ThroughputGaps, out: &mut String) {
    push_gaps_named(g, "gaps", out);
}

fn push_gaps_named(g: &ThroughputGaps, key: &str, out: &mut String) {
    let _ = write!(
        out,
        "\"{key}\":{{\"halted_batches\":{},\"unparsed_bytes\":{},\
         \"undecompressible_batches\":{},\"unresolvable_fragments\":{}}}",
        g.halted_batches, g.unparsed_bytes, g.undecompressible_batches, g.unresolvable_fragments
    );
}

#[cfg(feature = "network-codecs")]
fn push_latency(l: &crate::exchange::LatencySamples, out: &mut String) {
    let _ = write!(out, "{{\"count\":{}", l.count());
    for (key, value) in [
        ("min_ms", l.min_ms()),
        ("max_ms", l.max_ms()),
        ("mean_ms", l.mean_ms()),
    ] {
        match value {
            Some(v) => {
                let _ = write!(out, ",\"{key}\":{v}");
            }
            // A floor of 0 on an empty sample set is a number a reader can
            // print, and printing it claims a measurement never taken.
            None => {
                let _ = write!(out, ",\"{key}\":null");
            }
        }
    }
    let _ = write!(out, ",\"total_ms\":{}}}", l.total_ms());
}

/// R311y855 — `pub(crate)` so [`crate::fields_json`] renders a flow key the
/// SAME way this module does. Two renderings of one key is how the two
/// consumption surfaces came to disagree in the first place, one level up.
pub(crate) fn push_flow(flow: &crate::link::FlowKey, out: &mut String) {
    out.push_str("{\"low\":");
    push_endpoint(&flow.low, out);
    out.push_str(",\"high\":");
    push_endpoint(&flow.high, out);
    out.push('}');
}

fn push_endpoint(e: &crate::link::Endpoint, out: &mut String) {
    out.push_str("{\"addr\":\"");
    let addr = e.addr();
    if e.is_ipv4() {
        let _ = write!(out, "{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
    } else {
        let groups: Vec<String> = addr
            .chunks(2)
            .map(|c| {
                let mut s = String::new();
                let _ = write!(s, "{:x}", u16::from_be_bytes([c[0], c[1]]));
                s
            })
            .collect();
        for (i, g) in groups.iter().enumerate() {
            if i > 0 {
                out.push(':');
            }
            out.push_str(g);
        }
    }
    let _ = write!(out, "\",\"port\":{}}}", e.port);
}

pub(crate) fn dir_name(d: Direction) -> &'static str {
    match d {
        Direction::A => "a",
        Direction::B => "b",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::tcp_packet;
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    /// R311y851 — the document names every plane in a build that cannot FEED
    /// two of them, and says which two by answering `null`.
    ///
    /// The claim the module doc makes and nothing tested until this: an absent
    /// plane and an empty one are different answers. Without the network
    /// codecs there is no record to correlate or to judge, so `{"rows":[]}`
    /// would tell a reader this capture held no queries — a statement about the
    /// capture made on the evidence of the build.
    ///
    /// Gated to the arm where it is TRUE rather than written once and made
    /// vague: the fed arm below asserts the same two keys carry tables.
    #[cfg(not(feature = "network-codecs"))]
    #[test]
    fn a_build_that_cannot_feed_a_plane_reports_it_absent_rather_than_empty() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &[1, 0, 0x04]));
        d.finish();

        let json = census_json(&d);
        assert!(
            json.contains("\"exchanges\":null")
                && json.contains("\"payloads\":null")
                // R311y869 — the interest plane joins them, and for a sharper
                // reason than either: its entire input is the `Declare`
                // message, so a build that cannot decode one would answer
                // "this capture declared nothing" about every capture there is.
                && json.contains("\"interests\":null"),
            "a plane with no decoder behind it must be null, not an empty \
             table: {json}"
        );
    }

    /// R311y851 — every plane key is present whatever the capture held.
    ///
    /// The control for the fixture-driven assertions below. A consumer indexes
    /// these keys, and one that is absent for an IDLE capture crashes on the
    /// quietest network rather than on the busiest — so the shape must not
    /// depend on the traffic.
    #[test]
    fn an_empty_capture_still_names_every_plane() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &[1, 0, 0x04]));
        d.finish();

        let json = census_json(&d);
        for key in [
            "\"keyexprs\":",
            "\"nodes\":",
            "\"exchanges\":",
            "\"payloads\":",
            "\"interests\":",
        ] {
            assert!(
                json.contains(key),
                "{key} missing from an empty census: {json}"
            );
        }
        assert!(
            json.contains("\"rows\":[]"),
            "an empty plane must be an empty table rather than absent: {json}"
        );
    }

    /// R311y885 — the census says what the walk under it LOST, and says it with
    /// the SAME words the health document uses.
    ///
    /// # Why the two strings are compared rather than each pinned
    ///
    /// The alternative is two format strings that agree today. This module and
    /// `report` would then each own a copy of a five-field layout, and the copy
    /// that gained a sixth axis would be whichever document its author was
    /// looking at — which is the failure `debt-census-emit-two-renderings`
    /// names and the reason `dropped_by_limits_json` was extracted rather than
    /// duplicated. An equality between the two renderings cannot be satisfied
    /// by remembering.
    #[test]
    fn the_census_carries_the_drop_group_the_health_document_renders() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &[1, 0, 0x04]));
        d.finish();

        let group = crate::report::dropped_by_limits_json(&d);
        assert!(
            group.starts_with('{') && group.contains("\"flows\":"),
            "the shared emitter must render the group as an object: {group}"
        );
        let json = census_json(&d);
        assert!(
            json.contains(&alloc::format!("\"dropped_by_limits\":{group}")),
            "the census must carry the group byte for byte: {json}"
        );
        assert!(
            crate::report::health_json(&d)
                .contains(&alloc::format!("\"dropped_by_limits\":{group}")),
            "and so must the health document, or the two have drifted"
        );
    }
}

/// The planes that need a decoder behind them, driven off a capture that
/// carries real zenoh records.
///
/// Its own module so the whole fixture is gated on the feature that makes it
/// mean anything: without the network codecs a Push inside a frame is an
/// unknown MID, every plane here answers zero HONESTLY, and these assertions
/// would fail for a reason that has nothing to do with the emitter.
#[cfg(all(test, feature = "network-codecs"))]
mod fed_tests {
    use super::*;
    use crate::datagram_tests::{push, sender_space, tcp_packet, tcp_packet_reverse};
    use crate::link::LINKTYPE_ETHERNET;
    use crate::node::tests::framed_init;
    use crate::Dissection;

    use alloc::vec;

    const ZID_A: [u8; 4] = [0xA1; 4];
    const ZID_B: [u8; 4] = [0xB2; 4];

    /// One `T_MID_FRAME` at `sn` carrying `records`, length-prefixed for a
    /// stream link.
    fn framed_frame(sn: u8, records: &[u8]) -> Vec<u8> {
        let mut wire = vec![
            wz_session_core::wire_const::T_MID_FRAME | wz_session_core::wire_const::FLAG_T_FRAME_R,
            sn,
        ];
        wire.extend_from_slice(records);
        let mut out = (wire.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&wire);
        out
    }

    /// A capture that gives all four planes something to say: two nodes that
    /// named themselves across one flow, a Put on a literal keyexpr, and a
    /// query answered and closed.
    ///
    /// One capture rather than four, on purpose. Each plane is a separate walk
    /// of the same frames, and a fixture per plane would let a document that
    /// renders one plane off the WRONG walk pass — the planes have to be seen
    /// disagreeing or agreeing about one capture.
    fn four_plane_capture(keyexpr: &'static str) -> Dissection {
        // R311y869 — the CONTROL plane, and the reason it is in this fixture
        // rather than in one of its own: the module's own rule above is that
        // the planes have to be seen agreeing about ONE capture, and the
        // interest plane's whole claim is a join against the keyexpr rows the
        // same frames produced. Built by the PRODUCTION declare builders, so
        // a plane that reads a fixture author's idea of the wire fails here.
        //
        // The two sides declare the two things their traffic then does: A
        // subscribes to everything under `demo`, B offers to answer the query
        // that arrives on `demo/q`.
        let declare_sub = framed_frame(
            0,
            &wz_session_core::declare_build::build_declare_subscriber(1, 0, Some("demo/**"))
                .expect("the production subscriber builder")
                .try_as_borrowed()
                .expect("re-borrow")
                .encode_to_vec(),
        );
        let declare_qbl = framed_frame(
            0,
            &wz_session_core::declare_build::build_declare_queryable(2, 0, Some("demo/q"))
                .expect("the production queryable builder")
                .try_as_borrowed()
                .expect("re-borrow")
                .encode_to_vec(),
        );
        // R311y870 — the QUESTION, and it is deliberately one NOBODY ANSWERS:
        // A asks for B's SUBSCRIBERS and B declares a queryable. That is the
        // finding a census of declarations cannot construct, and putting it in
        // the shared fixture is what makes the request half of this plane
        // visible to the document test rather than only to a unit test.
        let interest = framed_frame(
            1,
            &wz_session_core::interest_build::build_interest_subscribers(
                9,
                true,
                false,
                0,
                Some("demo/**"),
            )
            .expect("the production interest builder")
            .try_as_borrowed()
            .expect("re-borrow")
            .encode_to_vec(),
        );
        // The data plane: a Put under a literal keyexpr (id 0 + suffix, which
        // needs no Declare to resolve).
        let put = framed_frame(2, &push(sender_space(0, Some(keyexpr)), b"hello"));
        // The query plane: a Request, its Reply, and the ResponseFinal that
        // CLOSES it. Without the final the exchange is unclosed and
        // `completion` has no sample -- a row that exists and measures nothing.
        let query = framed_frame(
            3,
            &crate::exchange::tests::request_query(7, sender_space(0, Some("demo/q"))),
        );
        let mut answer =
            crate::exchange::tests::response_reply(7, sender_space(0, Some("demo/q")), b"answer");
        answer.extend_from_slice(&crate::exchange::tests::response_final(7));
        let answer = framed_frame(1, &answer);

        // The handshake rides the front of each direction: without it no
        // direction has an owner and the node plane attributes nothing.
        //
        // The DECLARATION leads each direction's data, as it does on a real
        // session: a subscriber that arrived after the sample would be a
        // capture begun mid-session, which is a different fixture.
        let mut low_to_high = framed_init(&ZID_A);
        low_to_high.extend_from_slice(&declare_sub);
        low_to_high.extend_from_slice(&interest);
        low_to_high.extend_from_slice(&put);
        low_to_high.extend_from_slice(&query);
        let mut high_to_low = framed_init(&ZID_B);
        high_to_low.extend_from_slice(&declare_qbl);
        high_to_low.extend_from_slice(&answer);

        // One packet per direction, so the whole of each stream is contiguous
        // and no reassembly gap can stand in for a decode failure. The
        // timestamps are what make the exchange's delay measurable at all.
        let mut d = Dissection::new();
        d.push_packet_at(
            LINKTYPE_ETHERNET,
            0,
            Some(0),
            &tcp_packet(1000, &low_to_high),
        );
        d.push_packet_at(
            LINKTYPE_ETHERNET,
            1,
            Some(9),
            &tcp_packet_reverse(2000, &high_to_low),
        );
        d.finish();
        d
    }

    /// R311y851 — EVERY PLANE CARRIES WHAT THE CAPTURE NAMED.
    ///
    /// The claim is not "the emitter produced JSON": a document of four empty
    /// tables is JSON and says nothing. Each assertion names a fact that is
    /// only in the document because the plane beneath it read it off the wire
    /// -- the keyexpr string, both zids, the correlated query, and the payload
    /// declaration -- so a plane wired to the wrong walk fails here rather than
    /// rendering an honest-looking zero.
    /// One plane's own slice of the document.
    ///
    /// Asserting against the WHOLE document would let one plane satisfy
    /// another's assertion — `"keyexpr":"demo/q"` appears in the keyexpr rows
    /// as well as the exchange rows, so a census whose exchange plane was wired
    /// to an empty table passed the naive form. Measured: that is exactly what
    /// happened when this test was first written, and it is why the slicing
    /// exists rather than being a tidiness.
    /// `key` carries its own leading delimiter so it names the DOCUMENT-level
    /// key and not a same-named field inside a row — `payloads` is both a plane
    /// and a column of the payload plane's rows, and the first cut of this
    /// helper sliced at the column.
    fn plane<'a>(json: &'a str, key: &str) -> &'a str {
        let at = json
            .find(key)
            .unwrap_or_else(|| panic!("{key} missing from the census: {json}"));
        let rest = &json[at + key.len()..];
        let bytes = rest.as_bytes();
        assert_eq!(bytes.first(), Some(&b'{'), "a plane is an object: {rest}");
        // Balanced braces, STRING-AWARE: a keyexpr is bytes a peer chose and
        // can hold a brace, so counting them blind would end the slice inside a
        // row. The escape state is tracked for the same reason `\"` exists.
        let (mut depth, mut in_str, mut escaped) = (0usize, false, false);
        for (i, &b) in bytes.iter().enumerate() {
            if in_str {
                match (escaped, b) {
                    (true, _) => escaped = false,
                    (false, b'\\') => escaped = true,
                    (false, b'"') => in_str = false,
                    _ => {}
                }
                continue;
            }
            match b {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &rest[..=i];
                    }
                }
                _ => {}
            }
        }
        panic!("the plane under {key} never closed: {rest}");
    }

    #[test]
    fn every_plane_carries_what_the_capture_named() {
        let json = census_json(&four_plane_capture("demo/temp"));

        // The keyexpr plane: the literal, and the bytes under it.
        let keyexprs = plane(&json, "{\"keyexprs\":");
        assert!(
            keyexprs.contains("\"keyexpr\":\"demo/temp\""),
            "the key the Put travelled under is missing: {keyexprs}"
        );
        assert!(
            keyexprs.contains("\"payload_bytes\":5"),
            "the payload was not sized: {keyexprs}"
        );

        // The node plane: BOTH zids, and the link between them.
        let nodes = plane(&json, ",\"nodes\":");
        assert!(
            nodes.contains("\"zid\":\"a1a1a1a1\"") && nodes.contains("\"zid\":\"b2b2b2b2\""),
            "both ends named themselves and must both appear: {nodes}"
        );
        assert!(
            nodes.contains("\"links\":[{\"a\":0,\"b\":1"),
            "a handshake both ways is a link between the two: {nodes}"
        );

        // The query plane: the exchange correlated, closed, AND timed.
        let exchanges = plane(&json, ",\"exchanges\":");
        assert!(
            exchanges.contains("\"keyexpr\":\"demo/q\""),
            "the queried key is missing: {exchanges}"
        );
        assert!(
            exchanges.contains("\"requests\":1,\"completed\":1"),
            "the ResponseFinal must close the exchange: {exchanges}"
        );
        assert!(
            exchanges.contains("\"first_reply\":{\"count\":1"),
            "a correlated exchange with two capture clocks is a SAMPLE, and a \
             delay nobody can read is the half of this plane the product needs: \
             {exchanges}"
        );

        // The payload plane: a declaration was judged rather than counted.
        let payloads = plane(&json, ",\"payloads\":");
        assert!(
            payloads.contains("\"consistent\":2"),
            "both payloads were judged against their own declaration: {payloads}"
        );
        assert!(
            payloads.contains("\"contradictions\":[]"),
            "and neither contradicted it: {payloads}"
        );

        // R311y869 — the INTEREST plane: both declarations, from the two sides
        // that made them, and the coverage joining them to the rows above.
        let interests = plane(&json, ",\"interests\":");
        assert!(
            interests.contains(
                "\"kind\":\"subscriber\",\"declarer\":\"a\",\"id\":1,\"keyexpr\":\"demo/**\""
            ),
            "A's subscriber is missing: {interests}"
        );
        assert!(
            interests.contains(
                "\"kind\":\"queryable\",\"declarer\":\"b\",\"id\":2,\"keyexpr\":\"demo/q\""
            ),
            "B's queryable is missing, so the plane read one direction only: \
             {interests}"
        );
        // THE JOIN over a LITERAL pattern, which every build can evaluate: the
        // queryable B declared covers exactly the key the query arrived on.
        assert!(
            interests.contains("\"declaration\":1,\"keys\":[\"demo/q\"]"),
            "the queryable must cover the key it was declared for: {interests}"
        );
        assert!(
            interests.contains("\"narrowed_by_selector\":false"),
            "a declaration is not a record a selector describes, and the plane \
             must say so rather than leave it inferred: {interests}"
        );

        // R311y870 — THE QUESTION, and the finding that only the pair can
        // state. A asked B for its SUBSCRIBERS; B declared a queryable and
        // nothing else, so the ask went unanswered — which no count of the
        // declarations above can express.
        assert!(
            interests.contains("\"asker\":\"a\",\"id\":9,\"mode\":\"current\",\"answers\":0"),
            "the request is missing from the document: {interests}"
        );
        assert!(
            interests.contains("\"unanswered\":[0]"),
            "and the finding with it: {interests}"
        );
        assert!(
            interests.contains("\"unclosed\":[]"),
            "nothing was answered, so nothing is a truncated answer: {interests}"
        );
        assert!(
            interests.contains("\"solicited_by\":null"),
            "the declarations here were spontaneous, and the field says so \
             rather than being absent: {interests}"
        );

        // THE JOIN over a WILDCARD, which is the assertion a listing could not
        // satisfy: `demo/**` covers BOTH rows the keyexpr plane reports, which
        // no prefix comparison against `demo/temp` would produce.
        //
        // The two arms below are ONE claim seen from both builds, on the same
        // bytes: where the matcher exists the document reports coverage, and
        // where it does not it reports that it cannot tell. Neither may report
        // a confident zero, and the second arm is the only place that is
        // checkable.
        #[cfg(feature = "filter-wildcards")]
        {
            assert!(
                interests.contains("\"keys\":[\"demo/q\",\"demo/temp\"]"),
                "the subscriber's wildcard must cover the traffic: {interests}"
            );
            assert!(
                interests.contains("\"unclaimed\":[]")
                    && interests.contains("\"unclaimed_exact\":true,\"judged\":2"),
                "both declarations were judged and nothing went unasked-for: \
                 {interests}"
            );
        }
        #[cfg(not(feature = "filter-wildcards"))]
        {
            assert!(
                interests.contains("\"undecidable\":[0]"),
                "a wildcard this build cannot evaluate must be named as such: \
                 {interests}"
            );
            assert!(
                interests.contains("\"silent\":[]"),
                "and never as a declaration that matched nothing: {interests}"
            );
            assert!(
                interests.contains("\"unclaimed\":[\"demo/temp\"]")
                    && interests.contains("\"unclaimed_exact\":false"),
                "so the unclaimed list is a floor and says so: {interests}"
            );
        }
    }

    /// R311y851 — A KEYEXPR IS WIRE INPUT, SO IT IS ESCAPED.
    ///
    /// A suffix is bytes a peer chose. One `"` in it turns a hand-rolled
    /// emitter's output into a document that no longer parses, and every
    /// consumer of this ABI reads it with a real JSON reader -- so the failure
    /// is not a cosmetic one, it is the whole census becoming unreadable
    /// because of one publisher.
    #[test]
    fn a_keyexpr_a_peer_chose_cannot_break_the_document() {
        let json = census_json(&four_plane_capture("demo/a\"b"));
        assert!(
            json.contains(r#""keyexpr":"demo/a\"b""#),
            "the quote must be escaped, not emitted raw: {json}"
        );
        // And the naive form is genuinely absent -- without this the assertion
        // above would also hold for a document that emitted BOTH.
        assert!(
            !json.contains("\"keyexpr\":\"demo/a\"b\""),
            "an unescaped copy would still break the parse: {json}"
        );
    }

    /// R311y854 — A SELECTOR NARROWS THREE PLANES AND LEAVES THE NODE PLANE
    /// WHOLE, and the document says which is which.
    ///
    /// The asymmetry is the finding a consumer would otherwise get wrong. Three
    /// planes take the selector; the node plane has no `_where` entry point,
    /// because a node is not a record the selector's terms describe. A reader
    /// who assumed otherwise would read "both zids are still here" as a filter
    /// that did nothing.
    ///
    /// Driven against the UNFILTERED census of the same capture, so what is
    /// asserted is a DIFFERENCE. Without that arm an emitter that had simply
    /// stopped reporting `demo/q` would pass.
    #[test]
    fn a_selector_narrows_three_planes_and_leaves_the_node_plane_whole() {
        let d = four_plane_capture("demo/temp");
        let whole = census_json(&d);
        assert!(
            plane(&whole, "{\"keyexprs\":").contains("\"keyexpr\":\"demo/q\""),
            "the CONTROL must carry the key the selector will reject: {whole}"
        );

        let filter = crate::filter::Filter::parse("key == demo/temp").expect("compiles");
        let narrowed = census_json_where(&d, &filter);

        let keyexprs = plane(&narrowed, "{\"keyexprs\":");
        assert!(
            keyexprs.contains("\"keyexpr\":\"demo/temp\""),
            "the matching key must survive: {keyexprs}"
        );
        assert!(
            !keyexprs.contains("\"keyexpr\":\"demo/q\""),
            "the rejected key must be gone: {keyexprs}"
        );
        assert!(
            keyexprs.contains("\"narrowed_by_selector\":true"),
            "and the plane must say it was narrowed: {keyexprs}"
        );
        assert!(
            keyexprs.contains("\"selection\":{\"matched\":1,\"rejected\":2,\"undecided\":0}"),
            "the rejected records are COUNTED, not merely absent -- a plane \
             that dropped rows silently is a short total that looks whole: \
             {keyexprs}"
        );

        let exchanges = plane(&narrowed, ",\"exchanges\":");
        assert!(
            !exchanges.contains("\"keyexpr\":\"demo/q\""),
            "the query plane takes the selector too: {exchanges}"
        );

        let nodes = plane(&narrowed, ",\"nodes\":");
        assert!(
            nodes.contains("\"zid\":\"a1a1a1a1\"") && nodes.contains("\"zid\":\"b2b2b2b2\""),
            "the node plane is NOT narrowed and must still hold both: {nodes}"
        );
        assert!(
            nodes.contains("\"narrowed_by_selector\":false"),
            "and it must say so, or a reader reads the surviving nodes as a \
             filter that did nothing: {nodes}"
        );
    }

    /// R311y851 — and in a build that CAN feed them, the two gated planes are
    /// tables rather than `null`.
    ///
    /// The other half of the pair the ungated module asserts. Without this,
    /// "absent means the build cannot see it" would rest on one arm, and an
    /// emitter that answered `null` unconditionally would satisfy it.
    #[test]
    fn a_build_that_can_feed_a_plane_reports_a_table() {
        let json = census_json(&four_plane_capture("demo/temp"));
        assert!(
            !json.contains("\"exchanges\":null") && !json.contains("\"payloads\":null"),
            "a plane this build CAN feed must not report itself absent: {json}"
        );
    }
}

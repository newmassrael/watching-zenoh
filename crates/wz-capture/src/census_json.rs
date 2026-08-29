// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y851 (§1.1f) — the ANALYSIS planes as ONE self-describing document.
//!
//! ⚠ R2180 — THE CARDINAL IS GONE FROM THIS LINE ON PURPOSE, and from the two
//! paragraphs below it. It read "the four ANALYSIS planes" and was true when
//! R311y851 wrote it; R311y869 added the interest plane and left every sentence
//! that counted them. R2176 struck a cardinal in `doc_revision` for this exact
//! reason one axis over — a number written beside the list it counts is a
//! second copy with nothing joining it to the first — and open-debt item 554
//! is the bill for the same defect here. The DECLARATION is the count:
//! `doc_revision::CENSUS_R5_PLANES`, which the document itself carries and
//! which `the_declared_planes_are_the_planes_the_document_emits` derives from
//! an emitted census rather than reading back.
//!
//! ## The gap this closes, and it is a gap between SURFACES rather than in a
//! plane
//!
//! wz exports its dissection through two consumption surfaces, and they carry
//! different halves of it. [`crate::agg`], [`crate::exchange`], [`crate::node`]
//! and [`crate::payload`] were reachable ONLY from `wz-analyze`, the command
//! line — a person at a terminal. `wz-capi-dissect`, the C ABI a framework
//! links, could reach a per-flow frame count and the health counters and
//! nothing else: the four NAMED ABOVE were compiled into its dependency graph
//! (this crate is its dependency) and had no symbol. Four is what there were
//! THEN — `crate::interest` joined at R311y869 — and the cardinal is kept here
//! only because this paragraph is an account of R311y851 and names its own
//! four. Nowhere below does it describe today.
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
//! Some of the planes below need the network codecs to have any record to
//! correlate at all, and this crate can be built without them. In that build
//! their keys are emitted as `null` rather than omitted or emitted as an empty
//! table: `exchange`'s own doc states the rule this follows — a plane that
//! cannot be fed is ABSENT rather than empty — and a consumer that saw
//! `{"rows":[]}` would read "this capture had no queries" off a build that
//! could not have seen one.
//!
//! WHICH keys those are is not said here, and that is the repair rather than an
//! omission. This paragraph used to name two of them and call them "the two
//! keys" while three were emitted that way, which is open-debt item 554's own
//! evidence: a list kept in prose is a copy, and this one was stale for as long
//! as the third had existed. The document says it instead — `document.planes`
//! — and the emitters below are gated on the same feature the plane list is
//! checked against.
//!
//! ⚠ `exchanges_json` and the emitters beside it are written as CODE SPANS and
//! NOT as intra-doc links. Written as links they came back unresolved from
//! `cargo doc` even in the build where the items exist, and Layer C1bz counted
//! them; the mechanism is not established here and is deliberately not guessed
//! at in a comment. What is established is the measurement.
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
/// # Two planes are NOT narrowed, and the document says so
///
/// [`crate::node`] and `interest` have no `_where` entry point, so they are
/// built whole here. That is not an omission this function could quietly fix —
/// neither a node nor a declaration is a record the selector's terms (`key`,
/// `kind`, `bytes`, `delay`, …) describe — and it is the same choice the
/// command line makes. What would be a defect is leaving a consumer to infer
/// it: each plane carries `narrowed_by_selector`, so "this table was filtered"
/// is read off the document rather than assumed from the call.
///
/// ⚠ R2180 — this heading read "The node plane is NOT narrowed" over "Three of
/// the four planes take a selector", and BOTH halves had gone stale: R311y869
/// added a fifth plane and a second unnarrowed one, and said so in this
/// function's body while its doc kept counting. `interest` is a code span and
/// not a link on this module's own measured rule — the gated modules come back
/// unresolved from `cargo doc` and Layer C1bz counts them.
///
/// # WHICH top-level keys are planes, and why that needed saying
///
/// R2180 (open-debt item 554). The sentence above put `narrowed_by_selector` to
/// a second use it could not carry: a consumer read it as the MARK OF A PLANE,
/// so a top-level object holding it was one. That works for every plane this
/// build can feed and fails for the rest — a plane with no decoder behind it is
/// emitted as `null`, and a `null` holds no keys at all. The consumer was
/// therefore reading "a top-level `null` is an absent plane", which was true of
/// this library and was promised by nothing.
///
/// So the envelope carries `planes`: the top-level keys that ARE planes, from
/// `doc_revision::DocumentShape::planes`, travelling with the document rather
/// than answerable only by a second door. A key in that list and `null` is an
/// absent plane; a key not in it is not a plane, whatever its value.
///
/// Each narrowed plane also carries its `selection` — matched / rejected /
/// UNDECIDED. The third is the one that matters and the reason it is emitted
/// beside the rows rather than derived: a keyexpr whose declaration went past
/// before the tap started cannot be judged against `key == demo/**`, and
/// counting it as a non-match would make a short total look whole.
pub fn census_json_where(d: &crate::Dissection, filter: &crate::filter::Filter) -> String {
    // R2100 (open-debt item 509) — the document's OWN revision, first key, so
    // a consumer reads it without walking the body. Until this round a key
    // rename here was a break that nothing in the document could express: the
    // ABI revision is defined not to move for a JSON change, and the JSON
    // carried no revision.
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::CENSUS, &mut out);
    out.push_str(",\"keyexprs\":");
    out.push_str(&keyexprs_json(&crate::agg::aggregate_where(d, filter)));
    // Round 2016 (item 268) — built ONCE and lent to both planes that read it.
    // The interest plane names the zid that declared each row, and a second
    // census built for that would be a second answer to "who is in this
    // capture".
    let nodes = crate::node::nodes(d);
    out.push_str(",\"nodes\":");
    out.push_str(&nodes_json(&nodes));
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
        &nodes,
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
pub fn interests_json(
    c: &crate::interest::InterestCensus,
    t: &ThroughputTable,
    // Round 2016 (item 268) — the node plane, so a declaration can name WHO
    // made it. A parameter and not a second census built here: this document
    // already renders `nodes` from one the caller composed, and building a
    // second would let the two disagree about how many nodes the capture held.
    nodes: &NodeCensus,
) -> String {
    let coverage = c.coverage(t);
    let mut out = String::from("{\"declarations\":[");
    for (i, d) in c.interests().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"kind\":\"{}\",\"declarer\":\"{}\",\"declarer_zid\":",
            d.kind.name(),
            dir_name(d.declarer),
        );
        // Item 268 — NULL for a flow whose handshake this capture missed, on
        // this document's rule that an empty string is a value. See
        // `NodeCensus::zid_on` for why a guess is worse than a null here.
        match nodes.zid_on(&d.flow, d.declarer) {
            Some(zid) => {
                out.push('"');
                for b in zid {
                    let _ = write!(out, "{b:02x}");
                }
                out.push('"');
            }
            None => out.push_str("null"),
        }
        let _ = write!(out, ",\"id\":{},\"keyexpr\":", d.id);
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
        // R311y919 (item 452) — the SPACE before the numbers, in the field
        // layer's own vocabulary (`AnchorSpace::name`). A reader handed
        // `declared_at: 9` cannot tell a ninth packet from a ninth byte, and
        // this plane's numbers are compared against the traffic rows' by
        // anyone answering "what did this declaration actually cover".
        let _ = write!(
            out,
            ",\"offset_space\":\"{}\",\"declared_at\":{},\"withdrawn_at\":",
            d.anchors.name(),
            d.declared_at
        );
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
            // R311y919 (item 452) — one `offset_space` for the THREE anchors
            // this row carries (`asked_at`, `closed_at`, `cancelled_at`), which
            // share a space because they are all this request's own flow.
            "{{\"asker\":\"{}\",\"id\":{},\"mode\":\"{}\",\"answers\":{},\
             \"offset_space\":\"{}\",\"asked_at\":{},\"closed_at\":",
            dir_name(r.asker),
            r.id,
            r.mode.name(),
            r.answers,
            r.anchors.name(),
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
            // R311y919 (item 452) — `offset_space` BEFORE the anchor keys,
            // because over a stream the OLD name is wrong and this is the only
            // thing that says so.
            //
            // R2119 (open-debt item 455) emitted BOTH keys for one value:
            // `first_anchor` is the name and `first_packet` was what a
            // consumer written against census revision 1 still read. R2123
            // IS THE NEXT REVISION, and this is it dropping the old one —
            // the second step of the dance, taken on the schedule the field's
            // own doc states ("going away in the next revision") rather than
            // left to linger, which is what open-debt item 534 records nothing
            // enforces.
            //
            // Two keys for one fact is exactly the smell this tree distrusts,
            // and it was bounded on purpose: one revision wide, with the
            // expiry written into the table rather than into a comment.
            //
            // R311y920 — AND THIS COMMENT WAS INSIDE THE FORMAT STRING. A
            // line-continuation `\` at the end of a string literal swallows the
            // next line, comment and all, so these five lines were emitted into
            // every census document for a whole round. Every gate passed:
            // `cargo test` because the round's own assertion looked for
            // `"offset_space":"…","first_packet"` and that substring still
            // occurred further along the same literal, Layer C1bo because the C
            // consumer greps for keys, clippy and the doc build because a string
            // is a string. Nothing judged the DOCUMENT, which is open-debt item
            // 380 stated as an accident instead of a sentence.
            ",\"evidence\":{{\"init\":{},\"join\":{},\"hello\":{},\"scout\":{},\
             \"inadmissible\":{},\"admissible\":{}}},\"offset_space\":\"{}\",\
             \"first_anchor\":{},\"wire_bytes\":{}",
            e.init,
            e.join,
            e.hello,
            e.scout,
            e.inadmissible,
            e.admissible(),
            node.anchors.name(),
            node.first_anchor,
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
            // R311y914 — its own reason word rather than folded into
            // `not_json`: a consumer filtering this stream is asking which
            // FORMAT the publisher contradicted, and two formats sharing one
            // word would make that question unanswerable downstream.
            crate::payload::Mismatch::NotCbor { at, reason } => {
                let _ = write!(out, ",\"reason\":\"not_cbor\",\"at\":{at},\"why\":");
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
    // R311y918 — the pair, and whether it covers the whole row. An anchor is a
    // coordinate in ONE space (`crate::AnchorSpace`) and a row folds every flow
    // and both directions, so `anchors_exact` is what separates an interval
    // over all of this row's records from one over the first space's. Emitted
    // structurally, like `unclaimed_exact` beside it: a consumer that had to
    // test for the key's absence would read it as "exact".
    let _ = write!(
        out,
        ",\"offset_space\":\"{}\",\"first_anchor\":{},\"last_anchor\":{},\
         \"anchors_exact\":{}",
        row.anchors.name(),
        row.first_anchor,
        row.last_anchor,
        row.anchors_exact
    );
    // R2123 (open-debt item 453) — and one extent PER SPACE, so `false` above
    // stops being the whole answer. `anchors_exact` says the pair covers part
    // of the row; this says which parts there are, how far each reaches and
    // how many records are in it, and the counts sum to the row's own message
    // total. A reader who could not tell one stray record from a thousand can
    // now decide what to do about it.
    //
    // STRUCTURAL, like `anchors_exact` beside it: always present, one entry on
    // the ordinary single-space row, so a consumer never reads an absent key
    // as "there was only one".
    out.push_str(",\"anchor_intervals\":[");
    for (i, interval) in row.anchor_intervals.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"offset_space\":\"{}\",\"first\":{},\"last\":{},\"records\":{}}}",
            interval.anchors.name(),
            interval.first,
            interval.last,
            interval.records
        );
    }
    out.push_str("]}");
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

/// Every word `dir_name` can return, WALKED rather than written down.
///
/// ⚠ R2176 — `dir_name` IS NAMED WITHOUT BEING LINKED, and that is the fix
/// rather than the omission it looks like. It is `pub(crate)`, so a link from
/// this PUBLIC item's documentation is `rustdoc::private_intra_doc_links`,
/// which Layer C1bz spends a zero budget on for this crate — R2175 wrote the
/// link, every crate test passed, and the push was refused by the doc lane.
/// The two repairs this workspace refuses are also worth naming: an
/// `#[allow(..)]` here would be an escape hatch disabling the lane at exactly
/// the site it fired on, and making `dir_name` public would widen the API for
/// the benefit of a hyperlink. The word stays crate-private; the vocabulary is
/// public through this function, which is the whole point of it existing.
///
/// R2175 (open-debt item 552) — `asker`, `declarer`, `direction` and `space`
/// all carry this vocabulary, and the documents that emit them now DECLARE it
/// per revision. The declaration is joined to a walk over the enum so it cannot
/// be a second opinion about what a direction is called.
///
/// ⚠ THE WORDS ARE ONE CHARACTER LONG, which is why the header gate that holds
/// each word to a mention searches for the BACKTICKED spelling: `HEADER
/// .contains("a")` is true of any English prose, so the plain form would be a
/// check that cannot fail.
pub fn direction_names() -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut cur = Some(Direction::A);
    while let Some(d) = cur {
        out.push(dir_name(d));
        cur = match d {
            Direction::A => Some(Direction::B),
            Direction::B => None,
        };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::tcp_packet;
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    /// R311y851 — the document reports a plane it cannot FEED by answering
    /// `null`, and it reports EVERY such plane that way.
    ///
    /// The claim the module doc makes and nothing tested until this: an absent
    /// plane and an empty one are different answers. Without the network
    /// codecs there is no record to correlate or to judge, so `{"rows":[]}`
    /// would tell a reader this capture held no queries — a statement about the
    /// capture made on the evidence of the build.
    ///
    /// # R2180 (open-debt item 554) — the names are DERIVED, not listed
    ///
    /// This test used to spell three keys out. That literal was a copy of the
    /// plane list, it sat one screen from the module doc that called the same
    /// set "the two keys", and a fourth undecodable plane could have joined
    /// them without either moving. So the population comes from the DOCUMENT:
    /// every top-level key that arrives as `null`, checked against the declared
    /// plane set. A plane that stops being null and a null that is not a plane
    /// are both red, and neither needs a name written here.
    ///
    /// Gated to the arm where it is TRUE rather than written once and made
    /// vague: the fed arm below asserts those same keys carry tables.
    #[cfg(not(feature = "network-codecs"))]
    #[test]
    fn a_build_that_cannot_feed_a_plane_reports_it_absent_rather_than_empty() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &[1, 0, 0x04]));
        d.finish();

        let json = census_json(&d);
        let absent: Vec<&str> = crate::doc_revision::top_level_entries(&json)
            .into_iter()
            .filter(|(_, v)| *v == "null")
            .map(|(k, _)| k)
            .collect();
        // A build with no codecs that reported no absent plane would pass every
        // assertion below by having nothing to assert about, which is the
        // population-of-zero failure this workspace keeps paying for.
        assert!(
            !absent.is_empty(),
            "a build without the network codecs cannot feed every plane, so at \
             least one must be null: {json}"
        );
        let declared = crate::doc_revision::newest(crate::doc_revision::CENSUS)
            .expect("the census document has a revision")
            .planes;
        for key in &absent {
            assert!(
                declared.contains(key),
                "{key:?} is emitted as null, so a consumer cannot tell an absent \
                 plane from a key that is not one. Declare it in \
                 `doc_revision::CENSUS_R5_PLANES` — or stop emitting null for it: \
                 {json}"
            );
        }
    }

    /// R311y851 — every plane key is present whatever the capture held.
    ///
    /// The control for the fixture-driven assertions below. A consumer indexes
    /// these keys, and one that is absent for an IDLE capture crashes on the
    /// quietest network rather than on the busiest — so the shape must not
    /// depend on the traffic.
    ///
    /// R2180 (open-debt item 554) — the five names it spelled out were the
    /// SECOND copy of the plane list in this module and the third in this
    /// crate. Read from the declaration now, which the document itself carries.
    #[test]
    fn an_empty_capture_still_names_every_plane() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &[1, 0, 0x04]));
        d.finish();

        let json = census_json(&d);
        let declared = crate::doc_revision::newest(crate::doc_revision::CENSUS)
            .expect("the census document has a revision")
            .planes;
        assert!(
            !declared.is_empty(),
            "the census declares no plane, so this test asserts nothing"
        );
        let top: Vec<&str> = crate::doc_revision::top_level_entries(&json)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        for key in declared {
            assert!(
                top.contains(key),
                "{key} missing from an empty census: {json}"
            );
        }
        assert!(
            json.contains("\"rows\":[]"),
            "an empty plane must be an empty table rather than absent: {json}"
        );
    }

    /// R2180 (open-debt item 554) — THE DECLARED PLANES ARE THE PLANES THE
    /// DOCUMENT EMITS, in a build that feeds them all and in a build that feeds
    /// none.
    ///
    /// # What a consumer could not do, and why the obvious fix is not one
    ///
    /// The consumption surface that filed this reads the census and has to
    /// partition its top-level keys into planes and everything else. It
    /// deliberately keeps no list of plane names of its own — such a list is a
    /// copy of this library's, and this library's grew from four to five when
    /// the interest plane landed. What it used instead was the structural rule
    /// `census_json_where`'s doc states: a plane carries `narrowed_by_selector`.
    /// That rule is exactly right for a plane this build can feed, and a plane
    /// it cannot is `null` — which holds no keys, so there is nothing in it to
    /// recognise. The consumer was left reading "a top-level null is an absent
    /// plane": true here, promised by nothing, and it wrote that distinction
    /// down itself rather than pretend otherwise.
    ///
    /// # Why the population is DERIVED
    ///
    /// A test comparing the declaration against a list written in this file
    /// would be checking a copy against a copy. So the plane set is taken from
    /// an EMITTED census: a top-level key is a plane when it carries the
    /// marker, or when it is `null`. Those two rules cover the same set from
    /// opposite sides of the feature flag — five marked and none null with the
    /// codecs, two marked and three null without — so the SAME assertion runs
    /// in both builds and neither can pass by having nothing to look at.
    ///
    /// Item 554's own filing recorded that a regex over this crate's source had
    /// miscounted the population three times. This reads the document.
    ///
    /// # The direction that closes the item
    ///
    /// The last assertion is the one a consumer acts on: a top-level key that
    /// is NOT declared a plane is never `null`. With it, "no `planes` key here
    /// and a null there" stops being a state a consumer has to guess about,
    /// because it cannot be reached.
    #[test]
    fn the_declared_planes_are_the_planes_the_document_emits() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &[1, 0, 0x04]));
        d.finish();
        let json = census_json(&d);

        let entries = crate::doc_revision::top_level_entries(&json);
        assert!(
            !entries.is_empty(),
            "the census document has no top-level key, so nothing below is \
             measuring anything: {json}"
        );
        let mut derived: Vec<&str> = entries
            .iter()
            .filter(|(_, v)| {
                *v == "null"
                    || crate::doc_revision::top_level_entries(v)
                        .iter()
                        .any(|(ik, _)| *ik == "narrowed_by_selector")
            })
            .map(|(k, _)| *k)
            .collect();
        derived.sort_unstable();
        assert!(
            !derived.is_empty(),
            "no top-level key of the census looks like a plane, so the \
             comparison below would hold over an empty set: {json}"
        );

        let declared = crate::doc_revision::newest(crate::doc_revision::CENSUS)
            .expect("the census document has a revision")
            .planes;
        assert_eq!(
            derived,
            declared.to_vec(),
            "the census document's PLANES moved. The document carries this list \
             in its envelope, so a consumer reads it rather than inferring one; \
             if the change is deliberate, APPEND a revision to \
             `doc_revision::DOCUMENT_HISTORY` carrying the new plane set.\n{json}"
        );

        // The half a consumer acts on: an undeclared top-level key is never
        // null, so `null` and "not a plane" cannot arrive together.
        for (key, value) in &entries {
            if declared.contains(key) {
                continue;
            }
            assert_ne!(
                *value, "null",
                "{key:?} is not a declared plane and arrived as null, which \
                 leaves a consumer unable to tell an absent plane from a key \
                 that never was one — the state open-debt item 554 was filed \
                 about: {json}"
            );
        }

        // And the declaration actually REACHES the document. A list a consumer
        // cannot read is the state before this round, spelled differently.
        let mut rendered = String::from("\"planes\":[");
        for (i, plane) in declared.iter().enumerate() {
            if i > 0 {
                rendered.push(',');
            }
            let _ = write!(rendered, "\"{plane}\"");
        }
        rendered.push(']');
        assert!(
            json.contains(&rendered),
            "the census document does not carry its own plane list \
             ({rendered} not found): {json}"
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
// R2100 (open-debt item 509) — `pub(crate)` so `fields_json`'s revision pin can
// build its document over the SAME four-plane capture this module's census pin
// uses. A second fixture over there would be a second opinion about what a rich
// capture contains, and a key-set pin taken over a THIN one silently stops
// covering the keys that capture never reaches. The pattern is already here:
// this module reads `crate::exchange::tests` and `crate::node::tests`.
#[cfg(all(test, feature = "network-codecs"))]
pub(crate) mod fed_tests {
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

    /// A capture that gives EVERY plane something to say: two nodes that named
    /// themselves across one flow, a Put on a literal keyexpr, a query answered
    /// and closed, and a declaration for the interest plane to fold.
    ///
    /// ONE capture rather than one per plane, on purpose. Each plane is a
    /// separate walk of the same frames, and a fixture per plane would let a
    /// document that renders one plane off the WRONG walk pass — the planes
    /// have to be seen disagreeing or agreeing about one capture.
    ///
    /// ⚠ R2180 (open-debt item 554) — this was `four_plane_capture` and gave
    /// five planes something to say. A cardinal in an IDENTIFIER is the same
    /// stale copy as one in prose and is read by every author who writes a test
    /// against it, so the name says the property (`every`) rather than the
    /// count. The plane set itself is declared once, in
    /// `doc_revision::CENSUS_R5_PLANES`, and derived from the document by
    /// `the_declared_planes_are_the_planes_the_document_emits`.
    /// R311y927 (item 456) — the fixture above, plus the CAPTURE FILE those
    /// same packets make and an optional scouting pair carrying `locator`.
    ///
    /// Two things item 456 named needed this. The field document
    /// ([`crate::fields_json`]) takes the capture bytes and the fixture handed
    /// back only a `Dissection`, so no test could ask it to render at all. And
    /// the node plane's `locators` is a second wire-sourced string that the
    /// census writes; the report's own guard covers the REPORT document and
    /// says nothing about this one, which a probe confirmed by deleting the
    /// census locator escaper and watching the well-formedness guard pass.
    ///
    /// `locator` is an Option so every caller of [`every_plane_capture`] sees a
    /// byte-identical capture: passing `None` adds no packets, and the key-set
    /// pin and the plane assertions are measuring what they were. (R2180 struck
    /// "the six callers" from that sentence — there were more than six, and a
    /// count of callers is a copy nothing joins to the callers.)
    pub(crate) fn every_plane_capture_with_file(
        keyexpr: &'static str,
        locator: Option<&str>,
        contradicting: bool,
    ) -> (Dissection, alloc::vec::Vec<u8>) {
        let mut packets: alloc::vec::Vec<(u32, u32, alloc::vec::Vec<u8>)> = alloc::vec::Vec::new();
        let mut d = Dissection::new();
        if let Some(locator) = locator {
            // The SCOUT leads: a HELLO is read as an ANSWER, so a capture that
            // carries only the answer names no node at all. `node`'s own
            // fixture states the same ordering, and so does the report's
            // locator guard this mirrors.
            let scout = crate::datagram_tests::udp_packet(
                [192, 168, 1, 5],
                43210,
                crate::datagram_tests::SCOUT_GROUP,
                7446,
                &crate::datagram_tests::scout_message(),
            );
            let hello = crate::datagram_tests::udp_packet(
                [192, 168, 1, 9],
                7447,
                [192, 168, 1, 5],
                43210,
                &hello_wire_with_locator(locator),
            );
            d.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &scout);
            d.push_packet(crate::link::LINKTYPE_ETHERNET, 1, &hello);
            packets.push((0, 0, scout));
            packets.push((1, 0, hello));
        }
        let (mut low, high) = four_plane_streams(keyexpr);
        if contradicting {
            low.extend_from_slice(&framed_frame(4, &contradicting_records(keyexpr)));
            low.extend_from_slice(&framed_frame(5, &unresolved_records()));
        }
        let low_packet = tcp_packet(1000, &low);
        let high_packet = tcp_packet_reverse(2000, &high);
        d.push_packet_at(LINKTYPE_ETHERNET, 0, Some(0), &low_packet);
        d.push_packet_at(LINKTYPE_ETHERNET, 1, Some(9), &high_packet);
        d.finish();
        packets.push((0, 0, low_packet));
        packets.push((1, 0, high_packet));
        let refs: alloc::vec::Vec<(u32, u32, &[u8])> = packets
            .iter()
            .map(|(s, u, b)| (*s, *u, b.as_slice()))
            .collect();
        let file = crate::pcap::write(crate::link::LINKTYPE_ETHERNET, &refs);
        (d, file)
    }

    /// A HELLO answer whose single locator is `locator`, on the wire.
    fn hello_wire_with_locator(locator: &str) -> alloc::vec::Vec<u8> {
        use wz_session_core::codec_owned::{owned_bytes, owned_string};
        let zid = [0x55u8, 0x66, 0x77, 0x88];
        let owned: wz_codecs::hello::HelloOwned = wz_codecs::hello::HelloOwned {
            version: 0x09,
            cbyte: (((zid.len() as u8) - 1) << 4) | 0x01,
            zid: owned_bytes(&zid).expect("zid"),
            num_locators: Some(1),
            locators: Some(alloc::vec![wz_codecs::locator::LocatorOwned {
                locator_len: locator.len() as u64,
                locator: owned_string(locator).expect("locator"),
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
        wire
    }

    fn every_plane_capture(keyexpr: &'static str) -> Dissection {
        every_plane_capture_with_file(keyexpr, None, false).0
    }

    /// Round 2001 (item 473) — THE THIRD RENDERING IS THE SAME ROWS.
    ///
    /// `crate::census_csv` exists so a plane can reach a table tool, and the
    /// danger it brings is a third opinion about what a row IS — the family
    /// open-debt item 253 names. This is where that is refused: ONE table, both
    /// renderings, and the CSV's lines must be the JSON's rows in the JSON's
    /// order.
    ///
    /// It lives here rather than in `census_csv` because the fixture does. A
    /// second fixture over there would be a second opinion about what a plane
    /// CONTAINS, which is the same defect one level up.
    ///
    /// Asserted on the keyexpr IN EACH POSITION rather than on a count: a
    /// renderer emitting the right number of wrong rows would satisfy a count,
    /// and reordering is exactly what a second sort would introduce.
    #[test]
    fn the_csv_rendering_is_the_json_rendering_row_for_row() {
        let d = every_plane_capture("demo/a");
        let table = crate::agg::aggregate(&d);
        let csv = crate::census_csv::keyexprs_csv(&table);
        let lines: Vec<&str> = csv.lines().collect();

        assert_eq!(
            lines[0],
            crate::census_csv::KEYEXPR_COLUMNS,
            "the header must be the constant a consumer reads, not a copy"
        );
        // The population is non-zero, asserted rather than assumed: an empty
        // table would make every comparison below vacuously true.
        assert!(
            !table.rows().is_empty(),
            "the fixture must attribute at least one keyexpr"
        );
        assert_eq!(
            lines.len() - 1,
            table.rows().len(),
            "one line per row and no more: {csv}"
        );
        for (line, row) in lines[1..].iter().zip(table.rows()) {
            assert!(
                line.starts_with(&row.keyexpr) || line.starts_with('"'),
                "row order must follow the table's: {line} vs {}",
                row.keyexpr
            );
        }
        // And the JSON is over the SAME table, so every keyexpr the CSV names
        // is a keyexpr that document names. This is the join that makes the two
        // renderings one plane rather than two.
        let json = keyexprs_json(&table);
        for row in table.rows() {
            assert!(
                json.contains(&row.keyexpr),
                "keyexpr {} is in the CSV and not in the JSON: {json}",
                row.keyexpr
            );
        }
    }

    /// The two directions' framed streams, so the fixture above can build both
    /// a dissection and the capture file over the same bytes.
    /// R311y930 (item 465) — a Put DECLARING an encoding its bytes refute, so
    /// the payload census has a CONTRADICTION and the finding clause runs.
    ///
    /// Encoding 6 is `application/json` in the wire table and `[0xff]` is not
    /// UTF-8, so the verdict is `NotUtf8` and the clause writes `reason` and
    /// `at`. `why` needs a body that IS UTF-8 and is not JSON, which the
    /// second record supplies.
    ///
    /// Appended as an Option so the six callers that pass `None` see a
    /// byte-identical capture, which is the property item 456 bought the same
    /// way: a shared fixture widened unconditionally moves what every other
    /// test measures.
    fn contradicting_records(keyexpr: &'static str) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        // NotUtf8: declared JSON, bytes are a lone 0xff.
        out.extend_from_slice(&crate::payload::tests_support::push_declaring(
            keyexpr,
            6,
            &[0xff],
        ));
        // NotJson: declared JSON, bytes are valid UTF-8 that is not JSON.
        out.extend_from_slice(&crate::payload::tests_support::push_declaring(
            keyexpr,
            6,
            b"not json at all",
        ));
        out
    }

    /// R311y931 (item 465, the half R311y930 left) — a Put addressed to a
    /// keyexpr ID THIS CAPTURE NEVER DECLARES.
    ///
    /// The fixture's own records use id 0 with a suffix, which resolves
    /// without a Declare and so leaves the keyexpr table's `unresolved` list
    /// empty. An id with no suffix and no declaration is what fills it, and
    /// that list is the only writer of `space` and `references`.
    ///
    /// Two records under the same id, because `references` is a COUNT: one
    /// would let a renderer that always wrote `1` pass.
    fn unresolved_records() -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        out.extend_from_slice(&push(sender_space(77, None), b"a"));
        out.extend_from_slice(&push(sender_space(77, None), b"bb"));
        out
    }

    fn four_plane_streams(keyexpr: &'static str) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
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
        (low_to_high, high_to_low)
    }

    /// R311y923 (open-debt item 288) — THE CENSUS DOCUMENT'S KEY SET IS PINNED,
    /// SO A ROUND THAT CHANGES THE SHAPE HAS TO SAY SO.
    ///
    /// # The judgement nothing was making
    ///
    /// `wz_dissect.h` states the rule in prose: the ABI revision moves when a
    /// SYMBOL or the memory rule changes, "never when the JSON gains fields".
    /// Which side of that line a given key change falls on was decided by
    /// reading, every time, and nothing checked the reading — item 288.
    ///
    /// The last four rounds are the evidence. R311y917 added
    /// `dropped_by_limits` to a document, R311y919 added `offset_space` six
    /// times, and each round argued in a comment that an ADDED key is the
    /// widening the read-by-name contract permits. That argument is correct.
    /// What it does not cover is a key REMOVED or RENAMED, which is a break —
    /// and R311y919 came within one edit of renaming `first_packet` on exactly
    /// that prose reading.
    ///
    /// # Why the whole set and not a rule about additions
    ///
    /// A gate that only refused removals would let the shape grow unremarked,
    /// and the growth is what a consumer pinned to a revision has to be told
    /// about. Pinning the SET means both directions land on this table, in the
    /// commit that changes the document, where the author states which side of
    /// the header's line the change is on. It is `capi_abi_pin.py`'s shape one
    /// layer in: that pins the symbol set against the revision, this pins the
    /// document the symbols hand back.
    #[test]
    fn the_census_documents_key_set_is_pinned() {
        let doc = census_json_where(
            &every_plane_capture("demo/temp"),
            &crate::filter::Filter::any(),
        );
        let mut seen = json_keys(&doc);
        seen.sort_unstable();
        seen.dedup();
        // R2100 (open-debt item 509) — the set MOVED to
        // `doc_revision::CENSUS_R1_KEYS`, beside the revision it belongs to.
        // R311y923 wrote it as a literal here, which pinned the shape for the
        // AUTHOR and told the CONSUMER nothing; the revision is what the
        // consumer reads, and a key set pinned in one file with a revision
        // declared in another is two facts that can disagree.
        //
        // MEASURED, not transcribed, at both addresses: this test printed the
        // set it saw and the table was filled from that printout.
        //
        // R2123 (open-debt item 453) — against the NEWEST revision rather than
        // `CENSUS_R1_KEYS` by name. That name was right while revision 2 was
        // an alias of revision 1, and it silently became a pin on a shape the
        // library had stopped emitting the moment a revision changed the set.
        // `newest` is what the four documents in `wz-capi-dissect` already
        // compare against, and the reason is the same: the consumer reads the
        // revision the document declares, not the first one that ever existed.
        let expected: Vec<&str> = crate::doc_revision::newest(crate::doc_revision::CENSUS)
            .expect("the census document has a revision")
            .keys
            .to_vec();
        assert_eq!(
            seen, expected,
            "the census document's key set moved; if that is deliberate, APPEND a \
             revision to `doc_revision::DOCUMENT_HISTORY` carrying the new set — and \
             if a key is going away, announce it in the previous revision's \
             `retiring` first, which is what makes a rename an edit a consumer can \
             follow instead of a break"
        );
    }

    // R2100 (open-debt item 509) — `json_keys` MOVED to
    // `crate::doc_revision`, and is `pub` there. Two crates now take key-set
    // pins (`wz-capi-dissect` owns four of the six documents), and a second
    // copy of the extractor over there would be a second opinion about what a
    // KEY is — the same argument this function's own doc makes about parsers.
    use crate::doc_revision::json_keys;

    /// R311y920 (open-debt item 380) — A WIRE STRING FULL OF JSON
    /// METACHARACTERS LEAVES EVERY DOCUMENT WELL-FORMED.
    ///
    /// # Why a property test and not a lint
    ///
    /// Item 380 is the residue of three real leaks (the node plane's
    /// `locators` and two interest keyexprs) and it says why the obvious guard
    /// does not work: a static rule for "a wire string reaches JSON without
    /// `escape_into`" would need an exemption per SAFE site, and today's safe
    /// sites — enum names, hex zids, fixed strings — outnumber the unsafe ones,
    /// so the exemption table would be longer than the findings. R311y889's own
    /// rule refuses a lint in that shape.
    ///
    /// So the guard is the harm instead of its cause: push a hostile string
    /// through the wire and require the DOCUMENT to still parse. That covers
    /// the fourth site, and the fifth, without naming any of them.
    ///
    /// # What is hostile, and why each character is here
    ///
    /// `"` and `\` are the two a naive writer breaks on. U+0001 is the one a
    /// writer that handles those two still breaks on, because JSON forbids raw
    /// control characters below U+0020 rather than merely discouraging them.
    /// The newline is the same class and the one a human notices. U+00FC is
    /// legal raw and is here as the control arm: a "writer" that escaped
    /// everything non-ASCII would still pass, so the assertion below also
    /// requires the string to arrive.
    #[test]
    fn a_wire_string_of_json_metacharacters_leaves_every_document_well_formed() {
        const HOSTILE: &str = "de\"mo/a\\b\u{1}c\nd/\u{fc}";
        // R311y927 (item 456) — the hostile string now rides a SECOND wire
        // field. The keyexpr alone left the node plane's `locators` unmeasured
        // here, and a probe proved it: deleting this module's locator escaper
        // outright left this test passing, because no locator in the fixture
        // carried anything that needed escaping. The report has a guard of its
        // own for locators; it judges the REPORT document and says nothing
        // about the census, which is written by different code.
        const HOSTILE_LOCATOR: &str = "tcp/a\"b\\c\u{1}d";
        // `file` is read only by the field-document arm below, which is behind
        // `dissect`; underscored rather than cfg'd so the fixture call reads
        // the same in both builds.
        let (d, _file) = every_plane_capture_with_file(HOSTILE, Some(HOSTILE_LOCATOR), false);

        let census = census_json_where(&d, &crate::filter::Filter::any());
        crate::payload::json_wellformed(census.as_bytes()).unwrap_or_else(|e| {
            panic!("the CENSUS document is not JSON: {e:?}\n{census}");
        });

        // The wire string must actually REACH the document. Without this a
        // plane that dropped the keyexpr entirely would pass -- the same
        // "population of zero is green" this workspace keeps paying for.
        assert!(
            census.contains("de\\\"mo/a\\\\b"),
            "the hostile keyexpr never reached the census: {census}"
        );

        // The REPORT is a second writer over the same tables (open-debt item
        // 379 is that this crate has two escapers), so a document that only
        // asserted the census would say nothing about it.
        let table = crate::agg::aggregate(&d);
        let report = crate::report::CaptureReport::of(&d)
            .with_throughput(&table)
            .to_json();
        crate::payload::json_wellformed(report.as_bytes()).unwrap_or_else(|e| {
            panic!("the REPORT document is not JSON: {e:?}\n{report}");
        });
        assert!(
            report.contains("de\\\"mo/a\\\\b"),
            "the hostile keyexpr never reached the report: {report}"
        );

        // The LOCATOR, on the plane this module writes. Asserted arriving
        // before the parse below is judged, because a census that dropped the
        // node would parse perfectly and measure nothing.
        assert!(
            census.contains("tcp/a\\\"b\\\\c"),
            "the hostile locator never reached the census: {census}"
        );

        // The FIELD document, which no test could reach before the fixture
        // handed back the capture file. It carries walked field NAMES and
        // VALUES, and the keyexpr arrives as one of those values, so the same
        // class lives in it.
        //
        // Behind `dissect` because the module is: that feature is default-off
        // so an MCU build is not charged for a desktop reader's walker, and
        // Layer C1bt builds this crate with default features to say so. The
        // capture file above is built either way -- it is the fixture's own
        // packets and costs nothing to keep honest.
        #[cfg(feature = "dissect")]
        {
            let fields = crate::fields_json::fields_json(&d, &_file, None, None);
            crate::payload::json_wellformed(fields.as_bytes()).unwrap_or_else(|e| {
                panic!("the FIELD document is not JSON: {e:?}\n{fields}");
            });
            assert!(
                fields.contains("de\\\"mo/a\\\\b"),
                "the hostile keyexpr never reached the field document: {fields}"
            );

            // R311y929 (item 464) — the same document with RULES DECLARED, so
            // the payload block's own writers run at all.
            //
            // Without a declaration `push_decoding` answers `NoRules` and
            // returns, which item 464 measured: the escaper in the `NoRule`
            // arm could be deleted with this guard still green, because no
            // capture in the suite ever reached that arm. A rule whose pattern
            // matches nothing here takes it, and the keyexpr it reports is the
            // hostile one.
            let mut map = crate::payload::formats::FormatMap::new();
            map.declare("other/topic=protobuf")
                .expect("a literal pattern and a built-in format");
            let declared = crate::payload_decode::Declarations::new(&map);
            let ruled = crate::fields_json::fields_json(&d, &_file, None, Some(&declared));
            crate::payload::json_wellformed(ruled.as_bytes()).unwrap_or_else(|e| {
                panic!("the RULED field document is not JSON: {e:?}\n{ruled}");
            });
            // The needle is split across a `concat!` on purpose. The key-set
            // sweep further down reads THIS FILE for `"key":` literals, and
            // `state` is `payload_decode`'s key rather than one this module
            // writes -- declaring it unreached here would be false, and
            // weakening the assertion to drop the key would measure less. So
            // the literal is spelled in two pieces, which the sweep does not
            // join. R311y928 hit the same class with an example in a comment.
            assert!(
                ruled.contains(concat!("\"state", "\":\"no_rule\"")),
                "the payload block must have taken the no_rule arm, or this \
                 measures the same thing the block above already did: {ruled}"
            );
            assert!(
                ruled.contains("de\\\"mo/a\\\\b"),
                "the hostile keyexpr never reached the ruled field document: {ruled}"
            );
        }
    }

    /// R311y919 (open-debt item 452) — EVERY ANCHOR THIS DOCUMENT EMITS NAMES
    /// ITS COORDINATE SPACE.
    ///
    /// # The defect, and why the node plane is the sharp end
    ///
    /// `PassiveFrame::stream_offset` carries two different kinds of number: a
    /// byte offset absolute within ONE DIRECTION of a stream, and the INDEX of
    /// the packet on a datagram link. R311y918 gave `AnchorSpace` to the
    /// enumeration that knows, and fixed the throughput row's pair, but the
    /// SURFACES still print bare numbers.
    ///
    /// The node plane is worse than unlabelled: its field is called
    /// `first_packet`, and over a TCP flow the value is a byte offset. The name
    /// is not missing, it is WRONG — which is the failure a reader cannot
    /// detect, because a plausible small integer under a plausible name reads
    /// as an answer.
    ///
    /// # Both values, so the label cannot be hardwired
    ///
    /// The stream capture must say `stream_byte` and the datagram capture must
    /// say `packet`. A build that emitted one constant would pass either half
    /// alone.
    #[test]
    fn every_anchor_this_document_emits_names_its_coordinate_space() {
        let over_tcp = census_json_where(
            &every_plane_capture("demo/temp"),
            &crate::filter::Filter::any(),
        );
        // PER PLANE, by adjacency. Asserting only that the word appears
        // somewhere would let ONE labelled plane stand for four, which is the
        // failure this whole item is about -- a number that reads as answered
        // because its neighbour was.
        // R2123 (open-debt item 453) — and the rename is DONE. R2119 spelled
        // the node plane's needle as the pair `first_anchor:0,first_packet:0`
        // specifically so the round that drops the old key would have to come
        // back and delete half of a literal, which is a smaller and louder
        // edit than relaxing an assertion. This is that edit.
        for anchor in [
            "\"first_anchor\"",                  // the throughput rows
            "\"first_anchor\":0,\"wire_bytes\"", // the node census, renamed
            "\"declared_at\"",                   // the interest declarations
            "\"asked_at\"",                      // the interest requests
        ] {
            assert!(
                over_tcp.contains(anchor),
                "the fixture must actually reach the plane carrying {anchor}: {over_tcp}"
            );
            let labelled = alloc::format!("\"offset_space\":\"stream_byte\",{anchor}");
            assert!(
                over_tcp.contains(&labelled),
                "the anchor {anchor} is emitted with no space beside it, so a \
                 reader cannot tell a byte offset from a packet index: {over_tcp}"
            );
        }
        // And the retired key is GONE, not merely unmentioned. Asserting its
        // absence is what makes the second step of the dance a checked event
        // rather than an edit someone believes they made.
        assert!(
            !over_tcp.contains("first_packet"),
            "`first_packet` was announced as retiring in census revision 2 and \
             this revision drops it; it is still in the document: {over_tcp}"
        );
        assert!(
            !over_tcp.contains("\"offset_space\":\"packet\""),
            "and over TCP none of them is a packet index: {over_tcp}"
        );

        let over_udp = census_json_where(&datagram_capture(), &crate::filter::Filter::any());
        assert!(
            over_udp.contains("\"offset_space\":\"packet\",\"first_anchor\""),
            "a datagram capture's anchors ARE packet indices and the label must \
             follow the wire rather than being a constant: {over_udp}"
        );
    }

    /// A one-flow DATAGRAM capture, the control arm for the label above.
    fn datagram_capture() -> Dissection {
        let mut d = Dissection::new();
        let wire = crate::datagram_tests::frame_carrying(&push(
            sender_space(0, Some("demo/temp")),
            &[0u8; 8],
        ));
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire),
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
        let json = census_json(&every_plane_capture("demo/temp"));

        // The keyexpr plane: the literal, and the bytes under it.
        let keyexprs = plane(&json, ",\"keyexprs\":");
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
                "\"kind\":\"subscriber\",\"declarer\":\"a\",\
                 \"declarer_zid\":\"a1a1a1a1\",\"id\":1,\"keyexpr\":\"demo/**\""
            ),
            "A's subscriber is missing: {interests}"
        );
        // Round 2016 (item 268) — and the two declarations name DIFFERENT
        // zids, which is the half a join reading one end would fail. This
        // fixture had both ends' handshakes all along; nothing was asking.
        assert!(
            interests.contains("\"declarer\":\"b\",\"declarer_zid\":\"b2b2b2b2\""),
            "B's queryable must name B: {interests}"
        );
        assert!(
            interests.contains(
                "\"kind\":\"queryable\",\"declarer\":\"b\",\
                 \"declarer_zid\":\"b2b2b2b2\",\"id\":2,\"keyexpr\":\"demo/q\""
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
        let json = census_json(&every_plane_capture("demo/a\"b"));
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
        let d = every_plane_capture("demo/temp");
        let whole = census_json(&d);
        assert!(
            plane(&whole, ",\"keyexprs\":").contains("\"keyexpr\":\"demo/q\""),
            "the CONTROL must carry the key the selector will reject: {whole}"
        );

        let filter = crate::filter::Filter::parse("key == demo/temp").expect("compiles");
        let narrowed = census_json_where(&d, &filter);

        let keyexprs = plane(&narrowed, ",\"keyexprs\":");
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
        let json = census_json(&every_plane_capture("demo/temp"));
        assert!(
            !json.contains("\"exchanges\":null") && !json.contains("\"payloads\":null"),
            "a plane this build CAN feed must not report itself absent: {json}"
        );
    }

    /// This module's own source, so the key set can be read from the WRITER
    /// rather than only from what one capture happened to produce.
    const SOURCE: &str = include_str!("census_json.rs");

    /// Every `"key":` literal this module can write.
    ///
    /// Deliberately over-inclusive and with NO exclusion list: it sweeps the
    /// whole file, tests included, so a literal cannot escape by living in a
    /// place the sweep was told to skip. Item 400's warning is about filters
    /// that carry exemptions; this one carries none, and every literal it finds
    /// must be accounted for below in one list or the other.
    fn emitter_key_literals() -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut rest = SOURCE;
        // The literals appear inside Rust string literals as an escaped quote,
        // the key, an escaped quote and a colon -- so on disk: backslash,
        // quote, key, backslash, quote, colon. Spelled in words rather than
        // shown, because the sweep below reads THIS FILE and an example would
        // be picked up as a key of its own. It was: the first run reported
        // `name`, which was the example this comment used to carry.
        while let Some(at) = rest.find("\\\"") {
            let after = &rest[at + 2..];
            let Some(end) = after.find("\\\"") else { break };
            let name = &after[..end];
            let tail = &after[end + 2..];
            if tail.starts_with(':')
                && !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            {
                out.push(name);
            }
            rest = after;
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// R311y928 (open-debt item 458) — EVERY KEY THIS MODULE CAN WRITE IS
    /// EITHER OBSERVED BY THE PIN OR DECLARED UNREACHED.
    ///
    /// # The direction the pin could not see
    ///
    /// `the_census_documents_key_set_is_pinned` reads the keys one capture
    /// produced. That is the wire truth and it is worth pinning, but its
    /// population is a FIXTURE: a key emitted only under a condition that
    /// capture never reaches is in neither direction of the assertion, because
    /// the set it compares against is built from the same document. A probe
    /// measured it -- a `probe_conditional` key added to the node plane behind
    /// an unreachable byte count left that test at 1 passed.
    ///
    /// # Why this is a second test and not a wider fixture
    ///
    /// Item 458's own candidate was a second capture, and R311y927's locator
    /// capture was tried first: the union of the two key sets is IDENTICAL to
    /// the first alone, measured rather than assumed. A capture that reaches
    /// every conditional branch does not exist, which item 458 says outright.
    ///
    /// So the writer is the denominator instead. What a fixture cannot reach is
    /// named here, in a list that is itself pinned, and a NEW conditional key
    /// lands in neither list until its author puts it in one.
    #[test]
    fn every_key_this_module_can_write_is_observed_or_declared_unreached() {
        let doc = census_json_where(
            &every_plane_capture("demo/temp"),
            &crate::filter::Filter::any(),
        );
        // R311y930 (item 465) — a SECOND capture that carries contradictions,
        // so the payload finding clause runs at all. Its keys join the observed
        // set rather than replacing it: the plain capture is what every other
        // assertion in this module measures and it stays untouched.
        let (contradicting, _) = every_plane_capture_with_file("demo/temp", None, true);
        let finding = census_json_where(&contradicting, &crate::filter::Filter::any());
        // MEASURED: both records report `not_json`. The bytes that are not
        // UTF-8 do NOT reach `Mismatch::NotUtf8` here -- the JSON scanner
        // answers first and says so in `why` ("not UTF-8, which RFC 8259
        // requires of a JSON text"). The first draft of this assertion looked
        // for `not_utf8` and the dump is what corrected it.
        assert!(
            finding.contains(concat!("\"reason", "\":\"not_json\"")),
            "the contradicting capture must have produced a finding, or the \
             union below is the plain capture's set again: {finding}"
        );
        // R311y931 (item 465) — the same capture also carries a keyexpr id it
        // never declares, which is the ONLY writer of `space` and
        // `references`. Asserted here for the same reason as the line above:
        // a clause that did not run cannot widen the set.
        assert!(
            finding.contains(concat!("\"references", "\":2")),
            "the unresolved alias must have been counted twice, or the \
             `references` key below is unmeasured: {finding}"
        );
        let mut observed = json_keys(&doc);
        observed.extend(json_keys(&finding));
        observed.sort_unstable();
        observed.dedup();

        // MEASURED, not transcribed: written first as an empty table so the
        // failure printed the real difference.
        // R311y930 took this list from five to three and R311y931 emptied it,
        // and BOTH times the list's own stale-exemption arm is what reported
        // the change rather than a reader noticing. That arm is the reason an
        // empty list is safe to keep: it is not a place a key can hide, it is
        // a place a key is named while nothing produces it.
        //
        // Empty is not the goal and is not a milestone. Item 465 says so and
        // it is right: a clause no capture can reach belongs here with the
        // reason it cannot, and the next such clause should be ADDED rather
        // than chased. What emptied it was two fixtures, not one -- a
        // contradicting payload for the finding clause and an undeclared
        // keyexpr id for the alias clause.
        const UNREACHED: [&str; 0] = [];

        let literals = emitter_key_literals();
        assert!(
            !literals.is_empty(),
            "no key literal was read out of this module's source, so this test \
             measured nothing"
        );
        let missing: Vec<&str> = literals
            .iter()
            .copied()
            .filter(|k| !observed.contains(k) && !UNREACHED.contains(k))
            .collect();
        assert!(
            missing.is_empty(),
            "this module can write {missing:?}, and no capture in the suite \
             produces them -- either give a fixture that reaches the condition, \
             or add them to UNREACHED with the round that decided so"
        );

        // And the other direction: a name in UNREACHED that the fixture now
        // DOES produce is a stale exemption, which is how a list like this
        // rots into a place to hide a key.
        let stale: Vec<&str> = UNREACHED
            .iter()
            .copied()
            .filter(|k| observed.contains(k))
            .collect();
        assert!(
            stale.is_empty(),
            "{stale:?} are declared unreached but the capture emits them -- \
             delete them from UNREACHED"
        );
    }
}

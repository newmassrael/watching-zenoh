// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ZA-3509 — the VERDICT of a selector over the rows of the field document, and
//! nothing else.
//!
//! # What was missing, in the consumer's numbers
//!
//! A consumer narrowing a message list with a selector needs, per row, only
//! the four coordinates that join the row to a record and the word the
//! selector said about it. The only door that gave it was the field document,
//! which renders every row's whole tree, carried state and session verdicts
//! beside those five values. Measured by the consumer on a synthetic capture
//! of 25,360 rows: the door took 171 ms, the document was 58 MB, and reading
//! it took the consumer 1.5 s — paid on every chip toggle, against the 0.1 to
//! 0.2 s its own evaluator had taken before it was retired in favour of this
//! library's.
//!
//! This document is those five values per row. The verdict is the SAME one
//! (`row_verdict_of` in `fields_json` is called by both renderers), the
//! coordinates are the SAME ones, and the rows are the field document's rows in
//! the same order, with the two differences stated below.
//!
//! # Where its rows differ from the field document's
//!
//! Both are the field document's limitation and not this one's.
//!
//! * The field document renders a datagram row only when it can re-read the
//!   packet from the capture container and the second read agrees with the
//!   first. This document does not need the packet at all — the verdict is
//!   decided by the record plane, not by a re-walk of the bytes — so it has a
//!   row for every frame the dissection framed, and takes no container. A
//!   handle fed by `push`, which has no container, therefore gets datagram
//!   verdicts here that it cannot get from the field document.
//! * Neither renders a recovered QUIC stream or a serial line: those lists have
//!   no row in the field document, and this one is the field document's rows.
//!
//! # An empty selector is the identity, here as everywhere
//!
//! It asks nothing, so it says nothing: rows carry their coordinates and no
//! `selected` key. That is the field document's rule for the same argument,
//! and the rule a consumer already holds for every census plane; a verdict
//! document that answered `yes` to everything under an empty selector would be
//! the one door in the family where "no selector" and "the selector that
//! matches all" differ.
//!
//! # The ceilings
//!
//! `dropped_by_limits` is the SAME group the field document and the census
//! carry, for the reason the field document gives: a row the walk never reached
//! is ABSENT rather than unmatched, and a consumer counting "three matched"
//! needs to be told the list it counted in was made short.

use alloc::string::String;
use core::fmt::Write as _;

use crate::census_json::dir_name;
use crate::fields_json::{row_verdict_of, RenderedLists, RowCoordinates, RowVerdict};

/// One row: the coordinates a record joins on, and the selector's word when a
/// selector was asked.
///
/// `list_id` is `None` for a list the caller does not number, and then the row
/// carries no coordinate keys at all, on the field document's own rule that a
/// key is never invented. `verdict` is `None` when no selector was asked.
fn push_row(
    direction: &str,
    list_id: Option<u64>,
    anchor: u64,
    batch_index: u64,
    verdict: Option<RowVerdict>,
    first: &mut bool,
    out: &mut String,
) {
    if !*first {
        out.push(',');
    }
    *first = false;
    let _ = write!(out, "{{\"direction\":\"{direction}\"");
    if let Some(list_id) = list_id {
        let _ = write!(
            out,
            ",\"list_id\":{list_id},\"anchor\":{anchor},\"batch_index\":{batch_index}"
        );
    }
    if let Some(verdict) = verdict {
        let _ = write!(out, ",\"selected\":\"{}\"", verdict.word());
    }
    out.push('}');
}

/// The selector's verdict over every row of the field document, with each row
/// carrying the coordinates of a record door that shares this dissection.
///
/// `coordinates` is the caller's numbering, exactly as
/// `fields_json_where_coordinated` takes it: this crate renders rows and does
/// not mint the ids a handle in another crate publishes.
pub fn selection_json_where_coordinated(
    d: &crate::Dissection,
    filter: &crate::filter::Filter,
    coordinates: &dyn RowCoordinates,
) -> String {
    let grouping = crate::node::session_grouping(d);
    // No question, no walk: an empty selector is the identity and judges nothing,
    // so it pays nothing either.
    let verdicts =
        (!filter.is_any()).then(|| crate::payload::payloads_grouped(d, filter, &grouping));
    let lists = RenderedLists::of(d);
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::SELECTION, &mut out);
    out.push_str(",\"rows\":[");
    let mut first = true;

    for (i, flow) in d.flows().iter().enumerate() {
        let list = lists.stream.get(i).copied();
        let list_id = list.and_then(|l| coordinates.list_id(l));
        for frame in &flow.frames {
            let verdict = match (verdicts.as_ref(), list) {
                (Some(census), Some(list)) => Some(row_verdict_of(census, list, frame)),
                _ => None,
            };
            push_row(
                dir_name(frame.direction),
                list_id,
                frame.stream_offset as u64,
                frame.batch_index as u64,
                verdict,
                &mut first,
                &mut out,
            );
        }
    }

    for (i, flow) in d.datagram_flows().iter().enumerate() {
        let list = lists.datagram.get(i).copied();
        let list_id = list.and_then(|l| coordinates.list_id(l));
        for frame in &flow.frames {
            let verdict = match (verdicts.as_ref(), list) {
                (Some(census), Some(list)) => Some(row_verdict_of(census, list, frame)),
                _ => None,
            };
            // `stream_offset` names the PACKET on a datagram link, the only anchor
            // there is, as the field document's own row says.
            push_row(
                dir_name(frame.direction),
                list_id,
                frame.stream_offset as u64,
                frame.batch_index as u64,
                verdict,
                &mut first,
                &mut out,
            );
        }
        // The scouting list, after the transport rows exactly as the field
        // document orders them. A scouting message carries no payload for the
        // record plane to judge, so under a selector it is unjudged BY
        // CONSTRUCTION and says so directly, on the field document's argument.
        let scouting_id = coordinates.scouting_list_id(&flow.flow);
        for datagram in &flow.scouting {
            let verdict = match (verdicts.as_ref(), list) {
                (Some(_), Some(_)) => Some(RowVerdict::Unjudged),
                _ => None,
            };
            push_row(
                dir_name(datagram.direction),
                scouting_id,
                datagram.packet_index as u64,
                0,
                verdict,
                &mut first,
                &mut out,
            );
        }
    }

    out.push_str("],\"dropped_by_limits\":");
    out.push_str(&crate::report::dropped_by_limits_json(d));
    out.push('}');
    out
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y855 — the FIELD layer over a whole capture: every message dissected
//! into the byte ranges it was decoded from.
//!
//! ## The walk this makes possible, which was documented and impossible
//!
//! `wz_dissect.h` has told a C consumer since R311y586 to "walk the flows, then
//! expand the messages you want with `wz_dissect_transport_message`". That walk
//! could not be performed. The summary reports per-flow frame COUNTS, so there
//! is nothing to enumerate messages by — and even holding a coordinate, a
//! caller could not slice the bytes out: a stream message lives in the
//! REASSEMBLED per-direction stream, which exists only inside this library. The
//! capture file a caller passed in does not contain the message contiguously.
//!
//! So the fix could not be "report offsets and let the caller slice". The walk
//! has to happen here, where the reassembly is, and hand back the trees.
//!
//! ## One coordinate space, and the row says which one
//!
//! Every span inside a tree is MESSAGE-RELATIVE — the walk is driven at base 0.
//! Where the message sits is on the row, once, because the three row producers
//! put three different kinds of number there:
//!
//! - a stream message carries `message_at`, a BYTE OFFSET into the direction's
//!   retained stream, so a span added to it is a capture coordinate;
//! - a datagram message carries `packet`, the INDEX of the packet in the file,
//!   which is not a byte offset and must not be added to anything.
//!
//! `offset_space` names which, so a reader never has to tell them apart by
//! inspection — they are small numbers all round.
//!
//! ## The walk is CHECKED against the session that framed it
//!
//! A tree is emitted only when the field walker's name for a message agrees
//! with the name the passive session gave it. A disagreement means the
//! coordinate this row was sliced at does not name the message the session
//! framed, and it is reported as a `declined` row with the reason rather than
//! dropped: R311y687 found a live misread this way (a batched unit's second
//! message walked as its first). Dropping the check to save work here would
//! give this surface a weaker guarantee than the command line's, which is the
//! divergence the two-renderings debt is about.
//!
//! ## Both halves, and the datagram half needs the file again
//!
//! A datagram flow retains no stream — its messages' bytes are packet payloads
//! — so the capture is parsed a SECOND time and each packet re-decapsulated.
//! That second read can disagree with the first, and every way it can is
//! counted rather than skipped: a `continue` there would drop rows and leave
//! the listing looking whole, which is the failure this whole layer exists to
//! end.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use wz_session_core::dissect::to_json;
use wz_session_core::json::escape_into;
use wz_session_core::passive::{Direction, PassiveFrame};

use crate::census_json::{dir_name, push_flow};
use crate::payload_decode::{decode_payload, push_decoding, Declarations, KeyexprAt};

/// Every message in `capture`, dissected into fields.
///
/// `capture` is the same bytes `d` was built from; the datagram half needs them
/// again (see the module doc). `max_messages_shown_per_flow` bounds each flow's
/// listing — `None` is unbounded, which is the shape that works for a test and
/// fails for a session, so a caller with a screen to fill should pass a bound.
///
/// R311y856 — `declarations` is the payload format mapping in force, or `None`
/// for a caller that declared nothing. A row gets a `payload_decode` object
/// only when a mapping exists, which is the rule the command line has followed
/// since R311y699: a reader who declared no format is not told about payloads
/// they did not ask about.
///
/// R2440 (open-debt item 691) — the RESOLVED KEYEXPR does not ride on that rule
/// and never should have. It is emitted on every `carried` entry of every walked
/// row whatever this argument is; `push_carried` in this module is where.
///
/// R2441 — that reference is deliberately NOT an intra-doc link. `push_carried`
/// is private, and a public item linking a private one is refused by
/// `rustdoc::private-intra-doc-links` under `-D warnings`. Widening the
/// function to satisfy a doc link would export a helper for a sentence's sake;
/// naming it in prose points the reader who has the source, which is the only
/// reader who can follow it either way.
pub fn fields_json(
    d: &crate::Dissection,
    capture: &[u8],
    max_messages_shown_per_flow: Option<usize>,
    declarations: Option<&Declarations<'_>>,
) -> String {
    fields_json_grouped(
        d,
        capture,
        max_messages_shown_per_flow,
        declarations,
        &crate::node::session_grouping(d),
    )
}

/// R2765 (open debt 788) — the same document, with each row told whether a
/// SELECTOR picked it.
///
/// # What was missing, in the consumer's words
///
/// There is a census door that takes a selector and a field door that does
/// not, so a reader wanting "the messages matching this" could only take the
/// rows and apply the selector again on its own side. That is a second
/// implementation of one language, and the verdicts of two implementations
/// disagree eventually — which is the cost this door removes.
///
/// # Where the answer comes from
///
/// NOT from here. [`crate::payload`] walks the records, builds each
/// `RecordView` to its own plane's rules, and asks the filter once; this
/// function renders what that walk already decided. Evaluating the selector
/// again at render time would build a second `RecordView` from a different
/// walk, which is the same defect one layer down.
///
/// # The verdict is per ROW
///
/// A row may carry several records. Any match makes the row a match, all
/// misses make it a miss, and anything else is undecided — the consumer's
/// rule, adopted because a record's reassembled coordinates live only inside
/// a reader, so a row per record would have to invent one for each.
///
/// # An EMPTY selector is the identity, and asks nothing
///
/// ZA-3517. It selects everything, so it is the document [`fields_json`]
/// makes, byte for byte: no walk to judge the rows and no `selected` key on
/// any of them, because a verdict is an answer to a question and none was
/// asked. It used to render `yes` on every judged row and `unjudged` on the
/// rest, which contradicted the header's own sentence that a document asked
/// for without a selector carries no such key, and made the field family the
/// one place where the empty selector was not the identity — the reading the
/// census planes had taught every consumer.
pub fn fields_json_where(
    d: &crate::Dissection,
    capture: &[u8],
    max_messages_shown_per_flow: Option<usize>,
    declarations: Option<&Declarations<'_>>,
    filter: &crate::filter::Filter,
) -> String {
    let grouping = crate::node::session_grouping(d);
    let verdicts = judged_by(d, filter, &grouping);
    fields_json_selected(
        d,
        capture,
        max_messages_shown_per_flow,
        declarations,
        &grouping,
        verdicts.as_ref(),
        None,
    )
}

/// ZA-3517 — the walk that judges the rows, or nothing when no question was
/// asked.
///
/// One function for both renderers that take a selector, so the rule that an
/// empty selector is the identity is written in one place and cannot be kept
/// by one of them and forgotten by the other.
fn judged_by(
    d: &crate::Dissection,
    filter: &crate::filter::Filter,
    grouping: &crate::node::SessionGrouping,
) -> Option<crate::payload::PayloadCensus> {
    (!filter.is_any()).then(|| crate::payload::payloads_grouped(d, filter, grouping))
}

/// ZA-3214 ① — the selector's document, with each row carrying the
/// COORDINATES of a record door that shares this dissection.
///
/// # The join this makes possible
///
/// A consumer whose message list stands on drained records and whose detail
/// comes from this document had to line the two up itself, and it could only
/// do that by direction and anchor order on a capture with one flow: the
/// document named flows by their 5-tuple and the records by numbers the handle
/// minted, and nothing published said which was which. So on a capture with
/// several flows, or with datagram rows, the detail simply did not attach.
///
/// With coordinates, every row carries `list_id`, `anchor` and `batch_index` —
/// the three fields that identify a record within its handle — so a record
/// and its row are joined on equal values rather than on a guess. The
/// coordinates come from `coordinates`, which is the handle's own numbering; a
/// list it has no id for gets no coordinate keys rather than an invented one.
///
/// Everything else is [`fields_json_where`], by the same function.
pub fn fields_json_where_coordinated(
    d: &crate::Dissection,
    capture: &[u8],
    max_messages_shown_per_flow: Option<usize>,
    declarations: Option<&Declarations<'_>>,
    filter: &crate::filter::Filter,
    coordinates: &dyn RowCoordinates,
) -> String {
    let grouping = crate::node::session_grouping(d);
    let verdicts = judged_by(d, filter, &grouping);
    fields_json_selected(
        d,
        capture,
        max_messages_shown_per_flow,
        declarations,
        &grouping,
        verdicts.as_ref(),
        Some(coordinates),
    )
}

/// ZA-3214 ① — the numbering a record door gave the lists of one dissection.
///
/// A trait rather than a map handed in, because the numbering is the CALLER's:
/// this crate renders rows and has no business minting the ids a handle in
/// another crate publishes. The two questions are the two kinds of list a row
/// can come from.
pub trait RowCoordinates {
    /// The id for the list at `list` in `Dissection::message_lists_with_origin`
    /// order, or `None` for a list the caller does not number.
    fn list_id(&self, list: usize) -> Option<u64>;
    /// The id for `flow`'s SCOUTING list, which is not in that enumeration.
    fn scouting_list_id(&self, flow: &crate::link::FlowKey) -> Option<u64>;
}

/// R2458 (open-debt item 703) — the same document, against a grouping the
/// caller already has.
///
/// The shape `crate::agg::aggregate_grouped` and `crate::payload::payloads_grouped`
/// set at R2457 and for their reason: the node census must be complete before
/// the first keyexpr fold, and a consumer rendering several planes has already
/// paid for it. Handed in, the second walk is not made at all.
///
/// See `crate::node::session_grouping` for the ordering cost this imposes, and
/// [`crate::agg::KeyexprSpaces`] for what the grouping buys — a declaration on
/// one link of a `max_links: 2` session reaching a reference on the other.
pub fn fields_json_grouped(
    d: &crate::Dissection,
    capture: &[u8],
    max_messages_shown_per_flow: Option<usize>,
    declarations: Option<&Declarations<'_>>,
    grouping: &crate::node::SessionGrouping,
) -> String {
    fields_json_selected(
        d,
        capture,
        max_messages_shown_per_flow,
        declarations,
        grouping,
        None,
        None,
    )
}

/// R2765 (open debt 788) — ONE implementation under both doors.
///
/// A document with no selector is the `None` case of a document with one, not
/// a separate renderer: two copies of this walk would be two chances for the
/// unselected document to drift from the selected one, and a reader comparing
/// them would be comparing two programs.
fn fields_json_selected(
    d: &crate::Dissection,
    capture: &[u8],
    max_messages_shown_per_flow: Option<usize>,
    declarations: Option<&Declarations<'_>>,
    grouping: &crate::node::SessionGrouping,
    verdicts: Option<&crate::payload::PayloadCensus>,
    coordinates: Option<&dyn RowCoordinates>,
) -> String {
    // A map with no rules answers `NoRules` for every message, so it renders
    // nothing either way -- folded here so the row renderers ask one question
    // rather than two.
    let declarations = declarations.filter(|d| !d.is_empty());
    // R2458 (open-debt item 703) — which lists this document renders, DERIVED.
    // See `RenderedLists`.
    let lists = RenderedLists::of(d);
    // R2458 — ONE instance for the capture, exactly as the census planes hold
    // one. Per-folder it was the defect: two flows of one session each built
    // their own tables, so a `DeclKexpr` that went out on the first link left
    // every reference on the second unresolved.
    let mut spaces = crate::agg::KeyexprSpaces::new();
    // R2513 (open-debt item 713) — EVERY declaration of the capture, absorbed
    // in capture order and stamped with the packet it went past at, before any
    // row is rendered. See `absorb_every_declaration`.
    absorb_every_declaration(d, grouping, &mut spaces);
    // R2100 (open-debt item 509) — the document's own revision, first key. See
    // `doc_revision`; the census document opens the same way.
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::FIELDS, &mut out);
    out.push_str(",\"stream_flows\":[");
    // ZA-3215 — re-read ONCE, ahead of both flow tables: a stream row now
    // names the packet holding its first byte and that packet's link
    // addresses, which only the capture's own bytes can say.
    let reread = Reread::of(capture);
    for (i, flow) in d.flows().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let mut own = None;
        let spaces = enter(
            &mut spaces,
            &mut own,
            grouping,
            lists.stream.get(i).copied(),
        );
        push_stream_flow(
            flow,
            spaces,
            reread.as_ref(),
            max_messages_shown_per_flow,
            declarations,
            // R2765 (open debt 788) — the LIST index, not the flow. The
            // caller already resolved it one line up for the keyexpr owner,
            // and it is what the verdict map is keyed by: a TCP flow and a UDP
            // flow may carry the identical 5-tuple, so a flow key would read
            // one list's verdicts onto the other's rows.
            RowTags {
                selection: RowSelection::of(verdicts, lists.stream.get(i).copied()),
                // ZA-3214 ① — keyed by the SAME list index, for the same
                // reason: the index is what names this list unambiguously.
                list_id: coordinates.and_then(|c| c.list_id(*lists.stream.get(i)?)),
                scouting_list_id: None,
            },
            &mut out,
        );
    }
    out.push_str("],\"datagram_flows\":[");
    for (i, flow) in d.datagram_flows().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let mut own = None;
        let spaces = enter(
            &mut spaces,
            &mut own,
            grouping,
            lists.datagram.get(i).copied(),
        );
        push_datagram_flow(
            flow,
            spaces,
            reread.as_ref(),
            max_messages_shown_per_flow,
            declarations,
            // R2765 (open debt 788) — this flow's CLEARTEXT list, which is the
            // one whose rows this producer renders. The sub-lists folded after
            // this call are the ones the header says the document does not
            // show, so they have no rows here to carry a verdict.
            RowTags {
                selection: RowSelection::of(verdicts, lists.datagram.get(i).copied()),
                list_id: coordinates.and_then(|c| c.list_id(*lists.datagram.get(i)?)),
                scouting_list_id: coordinates.and_then(|c| c.scouting_list_id(&flow.flow)),
            },
            &mut out,
        );
        // R2460 (open-debt item 705) — the flow's QUIC sub-lists, folded after
        // its cleartext one and before the next flow, which is where the census
        // folds them. This document renders no recovered QUIC row (see
        // `RenderedLists`), so nothing of THIS flow changes; what changes is
        // that a `DeclKexpr` carried on a QUIC stream now reaches the lists that
        // come after it, exactly as it always did on the census plane.
        if let Some(row) = lists.sub.get(i) {
            crate::node::absorb_datagram_sublists(flow, row, grouping, spaces);
        }
    }
    // Said rather than left to be inferred from empty datagram listings: a
    // capture this reader cannot parse a second time yields no datagram rows
    // for a reason that has nothing to do with the traffic.
    let _ = write!(out, "],\"capture_reread\":{},", reread.is_some());
    // R311y917 (open-debt item 366) — WHAT A CEILING COST, in the document the
    // ceiling made short.
    //
    // The field layer was the one read plane with no way to be bounded, and
    // adding the door without this would have made it silent in the way
    // R311y885 measured for the census: a plane made short by an evicted flow
    // reads exactly like a quiet network. The group is the SAME rendering the
    // summary's health object and the census document carry
    // (`report::dropped_by_limits_json`), a second consumer rather than a
    // second rendering.
    //
    // Emitted STRUCTURALLY, for the reason that rendering's own doc gives:
    // every counter is zero for a dissection built without caps, and a
    // consumer that can only see the group when it is non-zero cannot tell
    // "no caps" from "caps that did not bite".
    out.push_str("\"dropped_by_limits\":");
    out.push_str(&crate::report::dropped_by_limits_json(d));
    // ZA-3215 — THE CHAINS NO ROW ENDED, beside the rows that begin them.
    //
    // A reader indexing `chain.chain_id` finds some chains with a `begun` row
    // and no closing one, and the rows cannot say why: the router gave those up
    // with no fragment in hand — past their deadline, still open when the
    // capture stopped, or on a flow the cap evicted. Those three counts are
    // this group, and it is the SAME rendering the command line's capture
    // report carries (`report::reassembly_json`), a second consumer rather
    // than a second spelling. Capture-wide because that is the grain the
    // dissection books them at.
    out.push_str(",\"reassembly\":");
    out.push_str(&crate::report::reassembly_json(d));
    out.push(',');
    // R311y875 — the run's misbound rules, AFTER every row producer, for the
    // reason `wz-analyze` places its unbound-declaration note there: this is a
    // fact about what the capture turned out to hold, and both producers above
    // decide it while they walk. Emitted even for a caller that declared
    // nothing, so the key is structural rather than conditional.
    crate::payload_decode::push_misbindings(declarations, &mut out);
    out.push('}');
    out
}

/// R2458 (open-debt item 703) — the `Dissection::message_lists` index of every
/// list THIS DOCUMENT renders.
///
/// # Why this is derived and not arithmetic
///
/// `crate::node::SessionGrouping` is keyed by list index, and the four census
/// planes get theirs for free because they ARE
/// `Dissection::message_lists().enumerate()`. This document is not: it renders
/// `stream_flows` and `datagram_flows` as two arrays keyed to the two tables,
/// so it has to say which enumeration position each row stands at. Computing
/// that from table lengths would be a second copy of the enumeration's order —
/// the exact shape `Dissection::message_lists` exists to end — and it would be
/// WRONG today, because a datagram flow contributes one list plus one per QUIC
/// stream plus one for its RFC 9221 datagrams.
///
/// So the origins are READ. Every list whose origin is `Stream` is one row of
/// `d.flows()` in order, and every list whose origin is `Datagram` is one row
/// of `d.datagram_flows()` in order, because those are the only two producers
/// of those origins — see `Dissection::message_lists_with_origin`.
///
/// # The set, and what is NOT in it
///
/// Named arms and no catch-all, so a producer added to that enumeration has to
/// be decided here rather than falling into a default:
///
/// * `Stream` and `Datagram` — RENDERED, one row each.
/// * `QuicStream(_)` and `QuicDatagram` — NOT rendered, and structurally so.
///   This document walks a message's own BYTES, and
///   `Dissection::message_bytes_at` answers `NoByteSource` for both: a
///   recovered QUIC stream's plaintext was never on the wire in that form and
///   is not retained, and the RFC 9221 list anchors to a packet index whose
///   re-read yields the PROTECTED bytes, not the ones the message was framed
///   out of. `Reread` below has nothing to open them with.
/// * `Serial` — NOT rendered. This document has two flow arrays and a serial
///   line stands in neither table; `FlowKey::serial_line` is the empty key.
///
/// The lists left out are the subject of a separate report — they are absent
/// from this document's ROWS, which is a rendering question, and this type only
/// records which indices the rows it does render stand at.
///
/// ZA-3509 — crate-visible, because the verdict-only document renders exactly
/// these lists and a second copy of "which lists are rows" is the enumeration
/// this type exists to keep single. It reads `stream` and `datagram` and folds
/// nothing, so `sub` stays this document's own.
pub(crate) struct RenderedLists {
    /// One index per `d.flows()` row, in order.
    pub(crate) stream: alloc::vec::Vec<usize>,
    /// One index per `d.datagram_flows()` row, in order — its cleartext list.
    pub(crate) datagram: alloc::vec::Vec<usize>,
    /// R2460 (open-debt item 705) — one ROW per `d.datagram_flows()` entry,
    /// holding EVERY list that flow contributes in
    /// `DatagramDissection::frame_lists_with_origin` order.
    ///
    /// Not a rendering fact and deliberately so: the lists past the first are
    /// the ones the header above says this document does not render. They are
    /// here because a list this document cannot SHOW still mints ids the lists
    /// after it USE, and folding them is what keeps this document's answer to
    /// "does this id resolve" the same as the census plane's.
    sub: alloc::vec::Vec<alloc::vec::Vec<usize>>,
}

impl RenderedLists {
    /// R2459 (open-debt item 704) — the two doors on `Dissection`, not a walk
    /// of its own.
    ///
    /// The origin match lived here until `wz-analyze`'s listing needed the same
    /// answer. Leaving a copy behind would have made this the second
    /// enumeration of one fact — and the two would not even have agreed for
    /// long, because that listing RENDERS the recovered QUIC rows this document
    /// cannot. What is shared is the INDEX; which origins a document renders
    /// stays each document's own decision, and this type is where this
    /// document's is written down.
    pub(crate) fn of(d: &crate::Dissection) -> Self {
        Self {
            stream: crate::node::stream_list_indices(d),
            datagram: crate::node::datagram_list_indices(d),
            sub: crate::node::datagram_flow_list_indices(d),
        }
    }
}

/// R2515 — the pass itself moved to [`crate::agg::absorb_every_declaration`],
/// which is where the table it fills lives. It was private here for one round,
/// and `wz-analyze`'s two listings need the same pass for the same reason: a
/// second copy of it is the second spelling of one rule, which is the shape this
/// crate has paid for more than once.
use crate::agg::absorb_every_declaration;

/// Begin one list, on the spaces it writes into.
///
/// `Some(list)` is the ordinary path: the capture-wide instance, told whose
/// tables this list's two directions belong to. `None` is a list
/// [`RenderedLists`] did not name, which cannot happen for a row this document
/// renders and is answered anyway rather than left to leak the PREVIOUS list's
/// owners into it — that would resolve one flow's ids against another's, which
/// is the one failure `KeyexprSpaces` documents as never happening. A private
/// instance is the pre-R2458 reach exactly: per-flow tables, and
/// `crate::agg::UnresolvedCause::NoSession` on what they miss.
fn enter<'a>(
    shared: &'a mut crate::agg::KeyexprSpaces,
    own: &'a mut Option<crate::agg::KeyexprSpaces>,
    grouping: &crate::node::SessionGrouping,
    list: Option<usize>,
) -> &'a mut crate::agg::KeyexprSpaces {
    match list {
        Some(list) => {
            shared.enter_flow(grouping.owners(list));
            shared
        }
        None => own.insert(crate::agg::KeyexprSpaces::new()),
    }
}

fn push_stream_flow(
    flow: &crate::FlowDissection,
    spaces: &mut crate::agg::KeyexprSpaces,
    reread: Option<&Reread>,
    cap: Option<usize>,
    declarations: Option<&Declarations<'_>>,
    tags: RowTags<'_>,
    out: &mut String,
) {
    out.push_str("{\"flow\":");
    push_flow(&flow.flow, out);
    push_context(&flow.session.context(), out);
    out.push_str(",\"messages\":[");
    let (mut shown, mut omitted, mut emitted) = (0usize, 0usize, 0usize);
    let mut chains = ChainIds::default();
    // R311y856 — folded in FRAME ORDER and before the cap bites, which is the
    // rule R311y701 settled for the same table: a keyexpr id resolves through
    // the bindings that were live when the message travelled, and a listing
    // that stopped absorbing where it stopped PRINTING would resolve later ids
    // against a table missing the declarations a held-back row carried.
    //
    // R2513 (open-debt item 713) — the absorbing itself moved OUT, to a
    // capture-ordered pre-pass over every list (`absorb_every_declaration`).
    // This loop now only says WHERE each frame is, and the rule above is kept by
    // the anchor rather than by the order this loop happens to run in: a
    // declaration that went out on the session's OTHER link is in the table, and
    // one that went out LATER than this frame is still not applied to it. That
    // is the half a renderer could not have by walking, because its rows have to
    // come out grouped by flow.
    let mut last_packet = 0usize;
    for frame in &flow.frames {
        last_packet = flow
            .packet_for(frame.direction, frame.stream_offset)
            .unwrap_or(last_packet);
        spaces.at_packet(last_packet);
        // ZA-3215 — folded ahead of the cap, for the reason `ChainIds` gives.
        let session_row = chains.observe(frame);
        if cap.is_some_and(|c| shown >= c) {
            omitted += 1;
            // Round 2029 (item 298) — TELL THE RULE RUN. The misbinding verdict
            // is reached inside `push_walk` below, so a message held back here
            // is one no rule was applied to: the tally beside the findings is
            // a floor from this point on. Both surfaces already emitted their
            // own `omitted` and nothing joined them, which is the item.
            if let Some(d) = declarations {
                d.note_unwalked();
            }
            continue;
        }
        shown += 1;
        if emitted > 0 {
            out.push(',');
        }
        emitted += 1;
        let at = message_at(frame);
        let _ = write!(
            out,
            // R311y919 — the word comes from `AnchorSpace` now, so this row and
            // the census planes cannot drift into two vocabularies for one fact.
            // R2206 (open-debt item 561) — and it comes off the FRAME, not from
            // a literal named here. A literal per producer is exactly what the
            // message-list enumeration used to carry, and the serial line is
            // what it cost: two places deciding one fact, with nothing joining
            // either to the caller that chose the coordinate.
            "{{\"direction\":\"{}\",\"offset_space\":\"{}\",\"message_at\":{at},",
            dir_name(frame.direction),
            crate::anchor_space_of(frame).name()
        );
        push_coordinates(
            tags.list_id,
            frame.stream_offset as u64,
            frame.batch_index as u64,
            out,
        );
        push_selected(tags.selection, frame, out);
        match flow.message_bytes(frame) {
            Err(why) => push_declined(&why, out),
            Ok(bytes) => push_walk(
                RowWalk {
                    bytes,
                    space: MidSpace::of_frame(frame),
                    direction: frame.direction,
                    framed: &message_name(frame),
                    spaces,
                    declarations,
                    carried: Some(&frame.carried),
                },
                out,
            ),
        }
        push_session_row(&session_row, out);
        push_first_byte(
            // A decompressed message's coordinate indexes the reader's own
            // buffer, not the stream, so it names no packet byte.
            flow.byte_origin(frame.direction, at)
                .filter(|_| frame.decompressed.is_none())
                .map(|(packet, payload_offset)| FirstByte {
                    packet,
                    payload_offset,
                }),
            reread,
            out,
        );
        out.push('}');
    }
    let _ = write!(out, "],\"shown\":{shown},\"omitted\":{omitted}}}");
}

fn push_datagram_flow(
    flow: &crate::DatagramDissection,
    spaces: &mut crate::agg::KeyexprSpaces,
    reread: Option<&Reread>,
    cap: Option<usize>,
    declarations: Option<&Declarations<'_>>,
    tags: RowTags<'_>,
    out: &mut String,
) {
    out.push_str("{\"flow\":");
    push_flow(&flow.flow, out);
    push_context(&flow.session.context(), out);
    out.push_str(",\"messages\":[");
    let (mut shown, mut omitted, mut emitted) = (0usize, 0usize, 0usize);
    let mut chains = ChainIds::default();
    let mut disagreed = 0usize;
    let mut named: Vec<(usize, &'static str)> = Vec::new();
    // The stream half's rule, unchanged: anchored for every frame, ahead of
    // every reason this loop has for skipping one. R2513 (open-debt item 713) —
    // the absorb moved to the capture-ordered pre-pass, exactly as in the stream
    // half; see `absorb_every_declaration`.
    for frame in &flow.frames {
        // `stream_offset` names the PACKET here: a datagram link has no stream
        // for an offset to be into, so the field carries the only anchor there
        // is.
        let index = frame.stream_offset;
        spaces.at_packet(index);
        // ZA-3215 — ahead of every reason this loop has for skipping a row, so
        // a datagram the second read disagrees about still advances the chain
        // fold exactly as the router was advanced by it.
        let session_row = chains.observe(frame);
        let Some(file) = reread else {
            continue;
        };
        let datagram = match reread_datagram(file, flow, frame.direction, index) {
            Ok(datagram) => datagram,
            Err(why) => {
                note(&mut named, &mut disagreed, cap, index, why);
                continue;
            }
        };
        // ZA-3215 ⑤ — a message decompressed out of an lz4 batch is not in the
        // packet; its own bytes travel with it.
        let message = match &frame.decompressed {
            Some(own) => Some(own.as_slice()),
            None => datagram.payload.get(frame.unit_offset..),
        };
        let Some(message) = message else {
            note(&mut named, &mut disagreed, cap, index, "short_payload");
            continue;
        };
        if cap.is_some_and(|c| shown >= c) {
            omitted += 1;
            // Item 298 — the datagram half of the same join. Both listings cap,
            // so a fix on one of them would leave a capture of a UDP
            // deployment reporting exact counts it does not have.
            if let Some(d) = declarations {
                d.note_unwalked();
            }
            continue;
        }
        shown += 1;
        if emitted > 0 {
            out.push(',');
        }
        emitted += 1;
        let _ = write!(
            out,
            // R2206 (open-debt item 561) — off the FRAME, on the argument the
            // stream producer above makes.
            "{{\"direction\":\"{}\",\"offset_space\":\"{}\",\"packet\":{index},",
            dir_name(frame.direction),
            crate::anchor_space_of(frame).name()
        );
        push_coordinates(tags.list_id, index as u64, frame.batch_index as u64, out);
        push_selected(tags.selection, frame, out);
        push_walk(
            RowWalk {
                bytes: message,
                space: MidSpace::Transport,
                direction: frame.direction,
                framed: &message_name(frame),
                spaces,
                declarations,
                carried: Some(&frame.carried),
            },
            out,
        );
        push_session_row(&session_row, out);
        push_first_byte(
            // A decompressed message has no byte in the packet to point at.
            frame.decompressed.is_none().then_some(FirstByte {
                packet: index,
                payload_offset: frame.unit_offset,
            }),
            reread,
            out,
        );
        out.push('}');
    }
    // R2629 (open-debt item 744) — AND THE SCOUTING LIST, which this document
    // never read.
    //
    // The first pass puts a datagram in `scouting` rather than `frames` when it
    // belongs to the scouting MID space. The summary has counted that list since
    // R311y608 and the census folds it, while this loop walked `frames` alone —
    // so a discovery capture went out as `"messages":[]` with no disagreement
    // named, and the listing that most needed a row was the one with none.
    //
    // AFTER the transport rows rather than interleaved: `wz-analyze`'s listing
    // orders the two the same way, and every row's `packet` is the coordinate a
    // consumer merges on. NOT stamped into the id spaces: a scouting message
    // references no keyexpr, and its packet may precede the last frame's, which
    // would move a cursor that only moves forward.
    for datagram in &flow.scouting {
        let index = datagram.packet_index;
        let Some(file) = reread else {
            continue;
        };
        let read = match reread_datagram(file, flow, datagram.direction, index) {
            Ok(read) => read,
            Err(why) => {
                note(&mut named, &mut disagreed, cap, index, why);
                continue;
            }
        };
        if cap.is_some_and(|c| shown >= c) {
            // No `note_unwalked` here: that counter says a PAYLOAD went
            // unexamined, and a scouting message carries none.
            omitted += 1;
            continue;
        }
        shown += 1;
        if emitted > 0 {
            out.push(',');
        }
        emitted += 1;
        let _ = write!(
            out,
            "{{\"direction\":\"{}\",\"offset_space\":\"{}\",\"packet\":{index},",
            dir_name(datagram.direction),
            crate::AnchorSpace::PacketIndex.name()
        );
        // R2765 (open debt 788) — a SCOUTING row is unjudged BY CONSTRUCTION,
        // and it says so directly rather than through a lookup. The payload
        // plane never sees these: the comment above this loop's cap says a
        // scouting message carries no payload, so a key built here would miss
        // the map and answer `unjudged` by accident. Writing the word is the
        // same answer with its reason attached, and it cannot become wrong if
        // the map's keying changes.
        // ZA-3214 ① — the scouting list's own id: this row joins a record the
        // record door drains with ORIGIN_SCOUTING, whose batch index is 0
        // because a scouting message is never batched.
        push_coordinates(tags.scouting_list_id, index as u64, 0, out);
        if tags.selection.is_some() {
            RowVerdict::Unjudged.push(out);
        }
        push_walk(
            RowWalk {
                bytes: &read.payload,
                space: MidSpace::Scouting,
                direction: datagram.direction,
                framed: &scouting_name(datagram),
                spaces,
                declarations,
                // A scouting datagram is not a session frame: there is no
                // `Carried` to report, and `null` says so rather than leaving
                // the key absent.
                carried: None,
            },
            out,
        );
        // ZA-3215 — no SN and no chain on a scouting message, said as `null`
        // like `above_transport` above; the datagram IS the message, so its
        // first byte is the payload's first.
        push_session_row(
            &SessionRow {
                sn: None,
                chain: None,
            },
            out,
        );
        push_first_byte(
            Some(FirstByte {
                packet: index,
                payload_offset: 0,
            }),
            reread,
            out,
        );
        out.push('}');
    }
    let _ = write!(
        out,
        "],\"shown\":{shown},\"omitted\":{omitted},\
         \"disagreements\":{{\"count\":{disagreed},\"named\":["
    );
    for (i, (at, why)) in named.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"at\":{at},\"why\":\"{why}\"}}");
    }
    out.push_str("]}}");
}

/// R2629 (open-debt item 744) — the SECOND read of one datagram, judged against
/// the first, for both of a datagram flow's lists.
///
/// Hoisted out of the transport loop when the scouting list joined it. The same
/// re-read written twice is the shape Round 2443 paid for, where widening one
/// copy to raweth and not the other would have left a flow answering differently
/// depending on which list asked.
///
/// `Err` is the disagreement's word, exactly as `note` records it.
fn reread_datagram(
    file: &Reread,
    flow: &crate::DatagramDissection,
    direction: Direction,
    index: usize,
) -> Result<crate::link::Datagram, &'static str> {
    let Some(packet) = file.packet(index) else {
        return Err("absent");
    };
    // Round 2443 (open-debt item 694) — BOTH DATAGRAM ARMS, not one.
    //
    // This read `Transport::Udp(..)` alone, so every raweth (L2) frame fell
    // through to the refusal below and the flow went out with `"messages":[]`
    // — while `summary` counted the same frames and `census` read the node's
    // zid off them. A downstream consumer measured exactly that split and
    // reported it.
    //
    // The first pass tells the two apart deliberately (`Dissection`'s own
    // `Transport::Udp` / `Transport::RawEth` arms, whose comment calls that
    // site "the last place that knows which one it was") because a raweth
    // flow is keyed by MAC with no ports. That distinction is about how a
    // flow is NAMED. It is not a reason to refuse to read the payload back,
    // and `Transport::RawEth` carries the same `Datagram` this arm binds —
    // which is why `Dissection::push_tunnelled` already spells the pattern
    // this way.
    let Ok(crate::link::Transport::Udp(datagram) | crate::link::Transport::RawEth(datagram)) =
        crate::link::decapsulate(packet.link_type, packet.index, packet.data)
    else {
        // RENAMED with the widening, because the old word became false in
        // the useful direction: with raweth accepted, a frame reaching here
        // is TCP, vsock or undecodable on a flow the first pass called a
        // datagram flow. "not_udp" named a UDP-shaped expectation that was
        // never what this loop wanted, and it read as a defect in the
        // CAPTURE when the fact was that the reader declined a link kind it
        // knows.
        return Err("not_datagram");
    };
    // The second read's own coordinates, against the first read's. Three
    // axes rather than one boolean, because they fail for different reasons
    // and a reader chasing one of them needs to know which.
    let travels = if datagram.from_low {
        Direction::A
    } else {
        Direction::B
    };
    if datagram.flow != flow.flow {
        return Err("flow");
    }
    if travels != direction {
        return Err("direction");
    }
    if datagram.packet_index != index {
        return Err("index");
    }
    Ok(datagram)
}

/// Walk `bytes` and emit either the tree or the reason it was declined.
///
/// The walk is driven at base 0 so every span is message-relative; the row's
/// own coordinate says where the message sits (see the module doc).
///
/// `spaces` is the id table this flow has declared so far and `declarations` is
/// the payload format mapping in force, or `None` for a caller that declared no
/// format. TWO arguments, and R2440 (open-debt item 691) is what separated them.
///
/// R311y856 rode them as one `lens`, on the argument that they are one fact: a
/// mapping with nothing to resolve against would silently miss every message a
/// running capture names by id. That is true of the MAPPING and it was made to
/// hold in the other direction too, where it is false. A resolved keyexpr is a
/// property of the message; a payload format is the reader's own input; and
/// pairing them meant the only door to the first was a declaration about the
/// second. A consumer building a republisher reported the consequence — with no
/// format declared it got `state: "no_rules"` and NO key, and with any format at
/// all, even one matching nothing, it got a key — so whether a sample could be
/// replayed turned on whether its reader had opinions about payloads. See
/// [`push_carried`], which now resolves for every walked row.
///
/// The payload block hangs off a WALKED tree and never off a declined row: a
/// decline means the bytes are not the message the session framed, and decoding
/// a payload out of them would be a confident statement about bytes nobody
/// asked for -- the failure the decline itself exists to avoid.
///
/// R2629 (open-debt item 744) — `space` is which MID space the first pass read
/// these bytes in, and `framed` is the name it gave them. Both are handed in
/// rather than recovered here, because the bytes cannot answer either: `0x01`
/// is `Init` on a session and `Scout` on the scouting group, and a walker
/// choosing by byte is the confident wrong answer.
/// One row's inputs, grouped.
///
/// R2706 — a STRUCT rather than an eighth parameter, and the boundary is not
/// arbitrary: clippy's ceiling is seven and this row needed one more. The
/// grouping is the whole of what a row is walked FROM, which is why `out` stays
/// a parameter — it is where the walk goes, not part of its subject.
struct RowWalk<'a> {
    /// The message bytes this row was sliced at.
    bytes: &'a [u8],
    /// Which MID space to read the first byte in.
    space: MidSpace,
    direction: Direction,
    /// What the SESSION named this message, for the agreement check.
    framed: &'a str,
    spaces: &'a crate::agg::KeyexprSpaces,
    declarations: Option<&'a Declarations<'a>>,
    /// What the SESSION made of this frame, for the two facts a second walk
    /// over these bytes structurally cannot reach. `None` for a scouting row,
    /// which has no session frame. See [`push_above_transport`].
    carried: Option<&'a wz_session_core::passive::Carried>,
}

fn push_walk(row: RowWalk<'_>, out: &mut String) {
    let RowWalk {
        bytes,
        space,
        direction,
        framed,
        spaces,
        declarations,
        carried,
    } = row;
    match space.walk(bytes) {
        Err(err) => {
            let mut why = String::from("the field walker refused these bytes: ");
            why.push_str(&err);
            push_declined(&why, out);
        }
        // Only the scouting walker gives this answer, and only for a byte
        // outside its space — which the first pass, having put these bytes in
        // the scouting list, said they were not. A disagreement between the two
        // readers, so it is declined the way the arm below declines one.
        Ok(None) => {
            let mut why = String::from("the session read these bytes as ");
            why.push_str(framed);
            why.push_str(" and the field walker names no message in their MID space");
            push_declined(&why, out);
        }
        Ok(Some(field)) => {
            if walk_agrees(&field.name, framed) {
                let at = KeyexprAt::new(direction, spaces);
                out.push_str("\"name\":");
                escape_into(&field.name, out);
                out.push_str(",\"fields\":");
                out.push_str(&to_json(&field));
                push_carried(bytes, &field, space, at, out);
                if let Some(declarations) = declarations {
                    out.push_str(",\"payload_decode\":");
                    push_decoding(&decode_payload(&field, declarations, at), out);
                } else if let Some(decoding) = crate::payload_decode::shm_decoding(&field) {
                    // R2209 (open-debt item 563) — THE ONE STATE A READER WHO
                    // DECLARED NOTHING IS STILL TOLD.
                    //
                    // Every other `payload_decode` state answers a question
                    // about the reader's own declarations, and the rule above
                    // is right for those: somebody who asked about no formats
                    // is not lectured about payloads. `not_on_the_wire` is not
                    // one of them. It says the data this record names never
                    // crossed the wire being read -- a fact about the CAPTURE,
                    // true whether or not anybody declared a format, and the
                    // reason `Verdict::NotOnTheWire` was built as a NAMED
                    // ABSENCE rather than left as a silent `no_payload`.
                    //
                    // R2170 made that argument inside `decode_payload` and the
                    // emitter did not inherit it, so the fact stayed behind the
                    // declarations one level up: a consuming surface counting
                    // `payloads.descriptors` could see HOW MANY records were
                    // SHM and could not say WHICH. That is item 563, and the
                    // consuming surface's own sufficient condition is exactly
                    // this marker -- it does not ask for the descriptor bytes,
                    // which were never on the wire either.
                    out.push_str(",\"payload_decode\":");
                    push_decoding(&decoding, out);
                }
            } else {
                let mut why = String::from("the session read these bytes as ");
                why.push_str(framed);
                why.push_str(" and the field walker reads them as ");
                why.push_str(&field.name);
                why.push_str(
                    ", so the coordinate this row was sliced at does not name \
                     the message the session framed",
                );
                push_declined(&why, out);
            }
        }
    }
    // R2706 — AFTER THE MATCH, so every arm carries it. A row whose second walk
    // was DECLINED still had a session verdict, and that is the case where this
    // matters most: the reader is being told these bytes could not be walked
    // here, and `above_transport` is the only thing on the row that can say
    // whether the session nonetheless read what they carried.
    push_above_transport(carried, KeyexprAt::new(direction, spaces), out);
}

fn push_declined(why: &str, out: &mut String) {
    out.push_str("\"declined\":");
    escape_into(why, out);
}

/// R2223 (open-debt item 573) — WHICH MESSAGES THIS ROW CARRIES, by name and by
/// span, from a CLOSED vocabulary.
///
/// # The key `name` could not be
///
/// A consumer of this document splits traffic by message — `Push` here,
/// `Declare` there — and the only word it had to do that with was `name`, which
/// `DocumentShape::keys`' own rule makes the UNION of every field name at every
/// depth of the tree. That is an open set by construction, so no revision could
/// ever declare it, and a message name added upstream reached a consumer as a
/// `switch` fallthrough. `message` is the closed half of that fact, given its
/// own key so it can be declared.
///
/// # Read off the WIRE, through the vocabulary
///
/// The word comes from the MID BYTE — `bytes[0]` for the row's own message,
/// read in the row's [`MidSpace`] (R2629, open-debt item 744: `0x01` is `Init`
/// on a session and `Scout` on the scouting group), and the first byte of each
/// batched record's span for the network ones —
/// resolved through [`MessageName`]. Not from the tree's node names: those are
/// the walker's own strings, and asking the walker to confirm the walker is the
/// tautology this whole axis exists to avoid. `dissect_transport_message` is
/// driven at base 0 here (see [`push_walk`]), so a record's `span.start` indexes
/// `bytes` directly.
///
/// # An UNNAMED transport MID emits no entry, and that is a statement
///
/// A byte this build does not name walks as the `Unknown` group, which the row
/// already reports under `name`. Adding `Unknown` to this family would make the
/// vocabulary something other than the message set the wire constants define,
/// so the entry is omitted instead — and what makes the omission a statement
/// rather than a silence is
/// `the_message_vocabulary_is_the_one_the_dispatchers_produce`, which holds
/// "the dispatcher named it `Unknown`" and "the vocabulary does not claim this
/// MID" to be the same set over all thirty-two MIDs.
///
/// A BATCHED record is a different case and is never dropped: those bytes were
/// accepted by `walk_network_record`, so a vocabulary with no answer for one is
/// a disagreement and not a gap. It arrives under its walked name, where the
/// declared-values gate reports it as a word no revision declares — the rule
/// this workspace states as "unclassified is RED, not a pass".
///
/// # R2440 (open-debt item 691) — AND THE KEY EACH ONE TRAVELLED UNDER
///
/// Every entry carries `keyexpr`, RESOLVED through
/// [`crate::payload_decode::subtree_keyexpr_outcome`] — the same
/// `KeyexprSpaces::resolve_parts` the payload plane uses, never a second copy of
/// the rule. It is emitted for every walked row whatever the caller declared,
/// and that is the item: the value was already computed on every frame (the
/// table is folded in frame order above, ahead of the display cap) and the only
/// door to it was `payload_decode.keyexpr`, which exists only when a payload
/// FORMAT was declared. A consumer building a republisher out of a capture needs
/// the key and does not care about payload formats; it was having to declare one
/// it would never read, purely as a side channel. Emitting the key here couples
/// nothing: a keyexpr is a property of the message, which is what this listing
/// is about.
///
/// # `null` rather than an absent key, and why the ENTRY is the home
///
/// Emitted STRUCTURALLY on every entry, `null` where there is no key to name.
/// That is [`crate::doc_revision::CarriesShape::Passenger`]'s own rule — an
/// inapplicable companion arrives as `null` rather than absent — and here it is
/// load-bearing twice over: a consumer cannot tell "this build stopped emitting
/// it" from "this message has no key" out of an absence, and `message` would
/// stop being a passenger the moment the word decided whether the key arrived.
///
/// The ENTRY and not the row, which is the placement the reporting consumer left
/// to this tree. A row is one transport message and a `Frame` batches several
/// network messages that need not share a key, so a row-level key would have to
/// pick one of them — the pairing defect
/// [`crate::payload_decode::keyexpr_and_payload`] measured one level down, where
/// taking the first keyexpr under a batch paired it with another record's bytes.
/// The entry is the smallest object that names ONE network message, so it is the
/// only place where the key is a property of its subject.
///
/// A transport message that BATCHES records names no key of its own for the same
/// reason: every keyexpr under it belongs to a record that has its own entry
/// below. One that batches nothing is searched, so a transport MID that ever
/// carries a `WireExpr` is answered by the structure rather than by a list of
/// which MIDs do.
///
/// # R2458 (open-debt item 703) — AND WHY, when the key is `null`
///
/// `keyexpr_cause` beside it, from
/// [`crate::payload_decode::subtree_keyexpr_outcome`]. A `null` key has two
/// meanings that send a reader to opposite places, and this document could not
/// tell them apart: the message referenced an id nothing in its session ever
/// declared (`no_declaration`), or this capture never saw the flow's handshake
/// so the declaration may be one link over (`no_session`). That split is the
/// acceptance the consumer who filed item 702 derived; the census document has
/// carried it since R2457 and this is the document a consumer walking MESSAGES
/// reads.
///
/// The third state stays a `null` cause, and it is not the same fact: a message
/// that references no keyexpr at all — a `KeepAlive`, or a `WireExpr` naming
/// `id 0` with an empty suffix — has nothing to explain. A word for it would
/// declare a failure where there was no reference.
fn push_carried(
    bytes: &[u8],
    field: &wz_session_core::dissect::Field,
    space: MidSpace,
    at: KeyexprAt<'_>,
    out: &mut String,
) {
    use wz_session_core::dissect::MessageName;
    out.push_str(",\"carried\":[");
    let mut first = true;
    let mut entry = |word: &str,
                     span: &wz_session_core::dissect::Span,
                     keyexpr: Option<Result<String, crate::agg::UnresolvedCause>>,
                     out: &mut String| {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str("{\"message\":");
        escape_into(word, out);
        let _ = write!(
            out,
            ",\"start\":{},\"end\":{},\"keyexpr\":",
            span.start, span.end
        );
        match &keyexpr {
            Some(Ok(keyexpr)) => escape_into(keyexpr, out),
            Some(Err(_)) | None => out.push_str("null"),
        }
        out.push_str(",\"keyexpr_cause\":");
        match &keyexpr {
            Some(Err(cause)) => escape_into(cause.name(), out),
            Some(Ok(_)) | None => out.push_str("null"),
        }
        out.push('}');
    };
    // The first listing entry is the row itself; subsequent entries are its
    // network records. A lean row and its sole record share the same span.
    let records = if matches!(space, MidSpace::Network) {
        alloc::vec![field]
    } else {
        batched_records(field)
    };
    if let Some(message) = bytes.first().and_then(|b| space.head(b & 0x1F)) {
        let keyexpr = if records.is_empty() {
            crate::payload_decode::subtree_keyexpr_outcome(field, at)
        } else {
            None
        };
        entry(message.name(), &field.span, keyexpr, out);
    }
    for record in records {
        let word = bytes
            .get(record.span.start)
            .and_then(|b| MessageName::of_network(b & 0x1F))
            .map_or(record.name.as_ref(), |m| m.name());
        entry(
            word,
            &record.span,
            crate::payload_decode::subtree_keyexpr_outcome(record, at),
            out,
        );
    }
    out.push(']');
}

/// The network records a `Frame` batched, or nothing for every other message.
///
/// STRUCTURAL rather than by name: `dissect_transport_message`'s Frame arm is
/// the only one that builds a NESTED `payload` group, and it fills it with
/// `dissect_batch`'s records plus — when the walk halted — one `unparsed`
/// remainder that is a byte range and not a message. Every other MID either
/// carries no payload or carries it as a leaf, so this returns empty for them
/// without needing to know which they are.
fn batched_records(
    field: &wz_session_core::dissect::Field,
) -> Vec<&wz_session_core::dissect::Field> {
    use wz_session_core::dissect::FieldValue;
    let FieldValue::Nested(children) = &field.value else {
        return Vec::new();
    };
    children
        .iter()
        .find(|c| c.name == "payload")
        .and_then(|payload| match &payload.value {
            FieldValue::Nested(records) => Some(records),
            _ => None,
        })
        .map(|records| records.iter().filter(|r| r.name != "unparsed").collect())
        .unwrap_or_default()
}

/// R2706 — WHAT THE SESSION MADE OF THIS FRAME'S PAYLOAD, which this row's own
/// bytes cannot show.
///
/// # The gap this closes
///
/// Every other key on a row comes from walking the row's bytes a second time
/// ([`push_walk`] → `dissect_transport_message`). That walk is complete for a
/// message whose bytes were contiguous on the wire and it is STRUCTURALLY blind
/// to two cases the session already decided:
///
/// * a `Fragment` that COMPLETED a chain carries records whose bytes were never
///   contiguous, so no second walk over this row can reach them. A reporting
///   consumer measured the cost on its own frozen capture: 85 of 99 rows were
///   `Fragment`s, the census attributed the 5 `Push`es those chains carried, and
///   this document had no row saying any of them happened. Silence there is not
///   "nothing travelled" — it is indistinguishable from it.
/// * a `Frame` whose body the session could not decompress. `dissect_batch` has
///   no lz4 and never has (`grep -ci decompress` over `dissect.rs` answers 0),
///   so it walks the compressed bytes and halts wherever a record first fails —
///   reporting `UnknownMid`, a word that cannot be told apart from a MID this
///   build's wire vintage genuinely does not know.
///
/// Both facts are already on the frame, in [`Carried`], and were already read by
/// every census plane. This document simply never asked.
///
/// # Why the word rather than an absence
///
/// Emitted on every row that has a session frame, whatever it says, on the
/// `keyexpr_cause` rule this document already follows: a consumer cannot tell
/// "this build stopped emitting it" from "this frame carried nothing" out of an
/// absence. A scouting row has no session frame and no `Carried` to report, and
/// answers `null` for the same reason.
///
/// # ⚠ The spans under `reassembled` are NOT capture offsets
///
/// They index the buffer the chain was joined in, which exists only inside the
/// reader. `PassiveFrame::batch_offset` states the rule this obeys — "handing
/// out the buffer's offset is how a fabricated coordinate gets read as a
/// measured one" — and it is why the coordinate is named by the WORD here
/// rather than left for a reader to infer from the row's `offset_space`, which
/// keeps its own meaning: where the FRAGMENT stands in the capture, a fact that
/// remains true and measured.
///
/// Matched exhaustively and by name, on the rule `agg::absorb_frame` states: a
/// new `Carried` variant must fail to compile here rather than fall into a
/// catch-all that reports it as something it is not.
fn carried_state(carried: &wz_session_core::passive::Carried) -> CarriedState {
    use wz_session_core::passive::Carried;
    match carried {
        Carried::Nothing => CarriedState::Nothing,
        Carried::Batch(_) => CarriedState::Batch,
        Carried::Undecompressible => CarriedState::Undecompressible,
        #[cfg(feature = "reassembly")]
        Carried::Fragment(_) => CarriedState::Fragment,
        #[cfg(feature = "reassembly")]
        Carried::Reassembled { .. } => CarriedState::Reassembled,
        #[cfg(feature = "reassembly")]
        Carried::FragmentWithoutResolution => CarriedState::FragmentWithoutResolution,
    }
}

/// The word `above_transport.carried_state` carries, as a closed type.
///
/// A type rather than a `&'static str` return, on `AnchorSpace`'s rule: a
/// vocabulary a consumer SWITCHES on is declared per revision and that
/// declaration is joined to a WALK, and a walk needs something to walk. The
/// chain below visits every word without a written list, so a state added here
/// fails at `cargo build` rather than at review.
///
/// ⚠ NOT `#[cfg]`-gated, while [`carried_state`]'s match arms are. The six
/// words are what this DOCUMENT can ever report, and a consumer switching on
/// one must handle all six however the producer was built — a vocabulary that
/// shrank with the emitter's feature set would make "this build cannot say
/// `reassembled`" and "this capture had no chains" the same answer, which is
/// the class this whole object exists to separate.
#[cfg_attr(not(feature = "reassembly"), allow(dead_code))]
#[derive(Clone, Copy)]
enum CarriedState {
    Batch,
    Fragment,
    FragmentWithoutResolution,
    Nothing,
    Reassembled,
    Undecompressible,
}

impl CarriedState {
    const fn name(self) -> &'static str {
        match self {
            Self::Batch => "batch",
            Self::Fragment => "fragment",
            Self::FragmentWithoutResolution => "fragment_without_resolution",
            Self::Nothing => "nothing",
            Self::Reassembled => "reassembled",
            Self::Undecompressible => "undecompressible",
        }
    }

    /// The next state, so the walk visits every arm without a list.
    ///
    /// `#[cfg(test)]` with its caller rather than one condition wider: the
    /// vocabulary gate is the only consumer, and a helper gated more widely
    /// than what uses it is dead code in exactly the build nobody runs locally.
    /// `name` above is NOT gated — the emitter calls it.
    #[cfg(test)]
    fn next(self) -> Option<Self> {
        Some(match self {
            Self::Batch => Self::Fragment,
            Self::Fragment => Self::FragmentWithoutResolution,
            Self::FragmentWithoutResolution => Self::Nothing,
            Self::Nothing => Self::Reassembled,
            Self::Reassembled => Self::Undecompressible,
            Self::Undecompressible => return None,
        })
    }

    /// Every word [`Self::name`] can return, WALKED rather than written down.
    #[cfg(test)]
    pub(crate) fn names() -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut cur = Some(Self::Batch);
        while let Some(v) = cur {
            out.push(v.name());
            cur = v.next();
        }
        out
    }
}

/// Render `above_transport` for one row.
///
/// The `reassembled` arm dissects the JOINED buffer with the same
/// `dissect_batch` every other batch goes through, and resolves each record's
/// key through the same `subtree_keyexpr_outcome` [`push_carried`] uses. Two
/// walkers over one shape, or two keyexpr rules, is the drift this document has
/// paid for elsewhere; there is one of each.
// `at` resolves the keys of a reassembled batch's records, which exist only
// with `reassembly`.
#[cfg_attr(not(feature = "reassembly"), allow(unused_variables))]
fn push_above_transport(
    carried: Option<&wz_session_core::passive::Carried>,
    at: KeyexprAt<'_>,
    out: &mut String,
) {
    out.push_str(",\"above_transport\":");
    let Some(carried) = carried else {
        out.push_str("null");
        return;
    };
    out.push_str("{\"carried_state\":");
    escape_into(carried_state(carried).name(), out);
    #[cfg(feature = "reassembly")]
    if let wz_session_core::passive::Carried::Reassembled { joined, .. } = carried {
        let walked = wz_session_core::dissect::dissect_batch(joined, 0);
        out.push_str(",\"fields\":[");
        for (i, record) in walked.records.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&to_json(record));
        }
        out.push_str("],\"carried\":[");
        for (i, record) in walked.records.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let word = joined
                .get(record.span.start)
                .and_then(|b| wz_session_core::dissect::MessageName::of_network(b & 0x1F))
                .map_or(record.name.as_ref(), |m| m.name());
            out.push_str("{\"message\":");
            escape_into(word, out);
            let _ = write!(
                out,
                ",\"start\":{},\"end\":{},\"keyexpr\":",
                record.span.start, record.span.end
            );
            match crate::payload_decode::subtree_keyexpr_outcome(record, at) {
                Some(Ok(keyexpr)) => escape_into(&keyexpr, out),
                _ => out.push_str("null"),
            }
            out.push_str(",\"keyexpr_cause\":");
            match crate::payload_decode::subtree_keyexpr_outcome(record, at) {
                Some(Err(cause)) => escape_into(cause.name(), out),
                _ => out.push_str("null"),
            }
            out.push('}');
        }
        out.push(']');
    }
    out.push('}');
}

/// ZA-3215 — what the session decided about ONE row that this document had
/// never said: the SN verdict with the conduit it was judged on, and the chain
/// router's outcome with the identity of the chain it touched.
///
/// # Why these belong on the row and not in a plane
///
/// Both verdicts are per FRAME and both are already computed — `sn_verdict` by
/// `PassiveSession::track_sn`, the outcome by the reassembly router, each
/// carried on the `PassiveFrame` this row is rendered from. A consumer that
/// wanted either had to rebuild it: re-read the SN, re-derive the conduit, and
/// re-run a chain router of its own over the `Fragment` rows, which is a
/// second implementation of a rule this library already enforces, holding it
/// to the same answer by hope.
///
/// Emitted STRUCTURALLY on every row — `null` when the row carries no SN or
/// touched no chain — so a reader's field lookup never depends on which
/// message a row happens to be.
struct SessionRow {
    /// `None` for every message that carries no SN.
    sn: Option<SnRow>,
    /// `None` for every row the chain router did not see.
    chain: Option<ChainRow>,
}

/// The SN half of [`SessionRow`].
struct SnRow {
    verdict: SnVerdictWord,
    /// `Some` only for [`SnVerdictWord::Gap`].
    missing: Option<u64>,
    direction: Direction,
    priority: wz_session_core::qos::Priority,
    reliable: bool,
}

/// The chain half of [`SessionRow`].
struct ChainRow {
    outcome: ChainOutcome,
    /// `Some` only for an abort or a refusal.
    reason: Option<ChainReason>,
    /// `None` for a refusal: the router refused the fragment BEFORE allocating
    /// a chain, so there is nothing for an identity to name.
    chain_id: Option<u64>,
}

/// ZA-3215 — the one word per `SnVerdict` variant this document writes under
/// `sn.verdict`.
///
/// A type rather than a `&'static str`, on [`CarriedState`]'s rule: a word a
/// consumer switches on is declared per revision and that declaration is held
/// to a WALK, which needs something to walk.
#[derive(Clone, Copy)]
enum SnVerdictWord {
    Baseline,
    Continuous,
    Duplicate,
    Gap,
    OutOfWindow,
    WithoutResolution,
}

impl SnVerdictWord {
    /// Exhaustive over the session's enum, so a verdict added there fails to
    /// compile here rather than reaching a consumer under no word.
    fn of(verdict: &wz_session_core::passive::SnVerdict) -> (Self, Option<u64>) {
        use wz_session_core::passive::SnVerdict;
        match *verdict {
            SnVerdict::WithoutResolution => (Self::WithoutResolution, None),
            SnVerdict::Baseline => (Self::Baseline, None),
            SnVerdict::Continuous => (Self::Continuous, None),
            SnVerdict::Gap { missing } => (Self::Gap, Some(missing)),
            SnVerdict::Duplicate => (Self::Duplicate, None),
            SnVerdict::OutOfWindow => (Self::OutOfWindow, None),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Continuous => "continuous",
            Self::Duplicate => "duplicate",
            Self::Gap => "gap",
            Self::OutOfWindow => "out_of_window",
            Self::WithoutResolution => "without_resolution",
        }
    }

    #[cfg(test)]
    fn next(self) -> Option<Self> {
        Some(match self {
            Self::Baseline => Self::Continuous,
            Self::Continuous => Self::Duplicate,
            Self::Duplicate => Self::Gap,
            Self::Gap => Self::OutOfWindow,
            Self::OutOfWindow => Self::WithoutResolution,
            Self::WithoutResolution => return None,
        })
    }

    /// Every word, WALKED.
    #[cfg(test)]
    pub(crate) fn names() -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut cur = Some(Self::Baseline);
        while let Some(v) = cur {
            out.push(v.name());
            cur = v.next();
        }
        out
    }
}

/// ZA-3215 — the chain router's outcome for one fragment, as the word
/// `chain.outcome` carries.
///
/// A joined payload is never decompressed on its own (compression wraps the
/// whole batch, before any fragment is read), so `reassembled` always sits
/// beside `carried_state: reassembled`.
// The words are the document's in every build, as `CarriedState`'s are; only
// the router that produces them is feature-gated.
#[cfg_attr(not(feature = "reassembly"), allow(dead_code))]
#[derive(Clone, Copy)]
enum ChainOutcome {
    Aborted,
    Begun,
    Continued,
    Reassembled,
    Refused,
}

impl ChainOutcome {
    const fn name(self) -> &'static str {
        match self {
            Self::Aborted => "aborted",
            Self::Begun => "begun",
            Self::Continued => "continued",
            Self::Reassembled => "reassembled",
            Self::Refused => "refused",
        }
    }

    #[cfg(test)]
    fn next(self) -> Option<Self> {
        Some(match self {
            Self::Aborted => Self::Begun,
            Self::Begun => Self::Continued,
            Self::Continued => Self::Reassembled,
            Self::Reassembled => Self::Refused,
            Self::Refused => return None,
        })
    }

    #[cfg(test)]
    pub(crate) fn names() -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut cur = Some(Self::Aborted);
        while let Some(v) = cur {
            out.push(v.name());
            cur = v.next();
        }
        out
    }
}

/// ZA-3215 — why the router aborted or refused, as the word `chain.reason`
/// carries. One vocabulary over the router's two reason enums, because a
/// consumer reads it beside `outcome`, which already says which of the two it
/// is.
///
/// `superseded` is declared although no row carries it today: the router
/// reports a restart as `Begun` for the NEW chain and the stranded one ends
/// without a row of its own. The word is the router's, and a router that one
/// day returns it must not reach a consumer under an undeclared word.
#[cfg_attr(not(feature = "reassembly"), allow(dead_code))]
#[derive(Clone, Copy)]
enum ChainReason {
    CapacityOverflow,
    MissingStartMarker,
    OutOfOrder,
    PeerQuota,
    PoolExhausted,
    SenderDropped,
    Superseded,
}

impl ChainReason {
    #[cfg(feature = "reassembly")]
    fn of_abort(reason: wz_session_core::reassembly_dispatch::AbortReason) -> Self {
        use wz_session_core::reassembly_dispatch::AbortReason;
        match reason {
            AbortReason::OutOfOrder => Self::OutOfOrder,
            AbortReason::CapacityOverflow => Self::CapacityOverflow,
            AbortReason::SenderDropped => Self::SenderDropped,
            AbortReason::Superseded => Self::Superseded,
        }
    }

    #[cfg(feature = "reassembly")]
    fn of_refusal(reason: wz_session_core::reassembly_dispatch::RefuseReason) -> Self {
        use wz_session_core::reassembly_dispatch::RefuseReason;
        match reason {
            RefuseReason::PeerQuota => Self::PeerQuota,
            RefuseReason::PoolExhausted => Self::PoolExhausted,
            RefuseReason::MissingStartMarker => Self::MissingStartMarker,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::CapacityOverflow => "capacity_overflow",
            Self::MissingStartMarker => "missing_start_marker",
            Self::OutOfOrder => "out_of_order",
            Self::PeerQuota => "peer_quota",
            Self::PoolExhausted => "pool_exhausted",
            Self::SenderDropped => "sender_dropped",
            Self::Superseded => "superseded",
        }
    }

    #[cfg(test)]
    fn next(self) -> Option<Self> {
        Some(match self {
            Self::CapacityOverflow => Self::MissingStartMarker,
            Self::MissingStartMarker => Self::OutOfOrder,
            Self::OutOfOrder => Self::PeerQuota,
            Self::PeerQuota => Self::PoolExhausted,
            Self::PoolExhausted => Self::SenderDropped,
            Self::SenderDropped => Self::Superseded,
            Self::Superseded => return None,
        })
    }

    #[cfg(test)]
    pub(crate) fn names() -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut cur = Some(Self::CapacityOverflow);
        while let Some(v) = cur {
            out.push(v.name());
            cur = v.next();
        }
        out
    }
}

/// ZA-3215 — chain IDENTITY, one per flow, assigned in frame order.
///
/// # What the identity is, and what it is not
///
/// A number shared by every row that touched ONE chain, unique within its flow
/// and counted from 0 in the order chains began. It is an identity for ROWS:
/// it says which fragments belong together. It is NOT a coordinate into the
/// buffer the chain was joined in — R2706 keeps that buffer's offsets off the
/// document, and nothing here changes that.
///
/// # Why it is folded here and cannot drift from the router
///
/// The router keys a chain by `(peer, reliable, priority)` and an observer
/// holds one router per direction, so the key is `(direction, reliable,
/// priority)` — read off the SAME `Fragment` fields the router was handed. The
/// fold then follows the router's OWN outcome rather than re-judging anything:
///
/// * `Begun` opens a new identity. A chain already open on the key was ended
///   by the router without a row (a `First` restart, or a deadline sweep), so
///   minting unconditionally is what keeps the two in step.
/// * `Continued` takes the key's open identity.
/// * `Reassembled` and `Aborted` take it and close it — or mint one, for a
///   chain that began and ended on this very fragment.
/// * `Refused` has none: no chain was allocated.
///
/// Folded for EVERY frame, including rows the listing cap holds back, for the
/// reason the keyexpr anchor is: an identity assigned only to printed rows
/// would renumber when the cap moved.
#[cfg_attr(not(feature = "reassembly"), allow(dead_code))]
#[derive(Default)]
struct ChainIds {
    next: u64,
    open: Vec<((Direction, bool, wz_session_core::qos::Priority), u64)>,
}

impl ChainIds {
    /// The row's two session verdicts, advancing the chain fold by one frame.
    fn observe(&mut self, frame: &PassiveFrame) -> SessionRow {
        SessionRow {
            sn: sn_row(frame),
            chain: self.chain_row(frame),
        }
    }

    #[cfg(feature = "reassembly")]
    fn chain_row(&mut self, frame: &PassiveFrame) -> Option<ChainRow> {
        use wz_session_core::inbound::InboundFrame;
        use wz_session_core::passive::Carried;
        use wz_session_core::reassembly_dispatch::IngestOutcome;
        let Ok(InboundFrame::Fragment {
            reliable, priority, ..
        }) = &frame.frame
        else {
            return None;
        };
        let key = (frame.direction, *reliable, *priority);
        let outcome = match &frame.carried {
            Carried::Fragment(outcome) => *outcome,
            // The joiner handed a payload back on this fragment.
            Carried::Reassembled { .. } => IngestOutcome::Reassembled,
            // No SN resolution, so no router ran: there is no outcome to name.
            // `Undecompressible` is a whole lz4 batch no message was read out
            // of, so no fragment reached the router either.
            Carried::FragmentWithoutResolution
            | Carried::Undecompressible
            | Carried::Nothing
            | Carried::Batch(_) => return None,
        };
        Some(match outcome {
            IngestOutcome::Begun => ChainRow {
                outcome: ChainOutcome::Begun,
                reason: None,
                chain_id: Some(self.open(key)),
            },
            IngestOutcome::Continued => ChainRow {
                outcome: ChainOutcome::Continued,
                reason: None,
                chain_id: self.current(key),
            },
            IngestOutcome::Reassembled => ChainRow {
                outcome: ChainOutcome::Reassembled,
                reason: None,
                chain_id: Some(self.close(key)),
            },
            IngestOutcome::Aborted(why) => ChainRow {
                outcome: ChainOutcome::Aborted,
                reason: Some(ChainReason::of_abort(why)),
                chain_id: Some(self.close(key)),
            },
            IngestOutcome::Refused(why) => ChainRow {
                outcome: ChainOutcome::Refused,
                reason: Some(ChainReason::of_refusal(why)),
                chain_id: None,
            },
        })
    }

    /// A build without `reassembly` routes no fragment, so no row touched a
    /// chain — the true answer, not a stub.
    #[cfg(not(feature = "reassembly"))]
    fn chain_row(&mut self, _frame: &PassiveFrame) -> Option<ChainRow> {
        None
    }

    #[cfg(feature = "reassembly")]
    fn open(&mut self, key: (Direction, bool, wz_session_core::qos::Priority)) -> u64 {
        let id = self.next;
        self.next += 1;
        match self.open.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = id,
            None => self.open.push((key, id)),
        }
        id
    }

    #[cfg(feature = "reassembly")]
    fn current(&self, key: (Direction, bool, wz_session_core::qos::Priority)) -> Option<u64> {
        self.open.iter().find(|(k, _)| *k == key).map(|(_, id)| *id)
    }

    #[cfg(feature = "reassembly")]
    fn close(&mut self, key: (Direction, bool, wz_session_core::qos::Priority)) -> u64 {
        match self.open.iter().position(|(k, _)| *k == key) {
            Some(i) => self.open.swap_remove(i).1,
            None => {
                let id = self.next;
                self.next += 1;
                id
            }
        }
    }
}

/// The SN half of a row, off the frame's own verdict and the conduit fields
/// `track_sn` judged it on.
fn sn_row(frame: &PassiveFrame) -> Option<SnRow> {
    use wz_session_core::inbound::InboundFrame;
    let verdict = frame.sn_verdict.as_ref()?;
    let (reliable, priority) = match &frame.frame {
        Ok(InboundFrame::Frame {
            reliable, priority, ..
        }) => (*reliable, *priority),
        #[cfg(feature = "reassembly")]
        Ok(InboundFrame::Fragment {
            reliable, priority, ..
        }) => (*reliable, *priority),
        // `track_sn` answers `None` for every other message, so a verdict here
        // would be one this function cannot place on a conduit. Said as an
        // absence rather than guessed.
        _ => return None,
    };
    let (word, missing) = SnVerdictWord::of(verdict);
    Some(SnRow {
        verdict: word,
        missing,
        direction: frame.direction,
        priority,
        reliable,
    })
}

/// Render the row's `sn` and `chain` keys.
fn push_session_row(row: &SessionRow, out: &mut String) {
    out.push_str(",\"sn\":");
    match &row.sn {
        None => out.push_str("null"),
        Some(sn) => {
            out.push_str("{\"verdict\":");
            escape_into(sn.verdict.name(), out);
            out.push_str(",\"missing\":");
            match sn.missing {
                Some(n) => {
                    let _ = write!(out, "{n}");
                }
                None => out.push_str("null"),
            }
            let _ = write!(
                out,
                ",\"conduit\":{{\"direction\":\"{}\",\"priority\":",
                dir_name(sn.direction)
            );
            escape_into(sn.priority.name(), out);
            let _ = write!(out, ",\"reliable\":{}}}}}", sn.reliable);
        }
    }
    out.push_str(",\"chain\":");
    match &row.chain {
        None => out.push_str("null"),
        Some(chain) => {
            out.push_str("{\"outcome\":");
            escape_into(chain.outcome.name(), out);
            out.push_str(",\"reason\":");
            match chain.reason {
                Some(reason) => escape_into(reason.name(), out),
                None => out.push_str("null"),
            }
            out.push_str(",\"chain_id\":");
            match chain.chain_id {
                Some(id) => {
                    let _ = write!(out, "{id}");
                }
                None => out.push_str("null"),
            }
            out.push('}');
        }
    }
}

/// ZA-3215 — the captured packet holding a row's FIRST BYTE, and the link
/// addresses it travelled between.
///
/// * `packet` — the capture's packet index.
/// * `payload_offset` — where that byte sits inside the packet's transport
///   payload (the TCP segment body, the UDP datagram body, the raweth or vsock
///   payload).
/// * `frame_offset` — where it sits inside the CAPTURED FRAME, link header
///   included, or `null` where `link::transport_payload_at` cannot place the
///   payload in one packet's bytes. A reader highlighting the byte in a packet
///   view reads this and parses no header.
///
/// `l2` is the packet's Ethernet II source and destination, `null` on any
/// other link — including a cooked capture, which records one address, and
/// every packet this document could not re-read.
struct FirstByte {
    packet: usize,
    payload_offset: usize,
}

fn push_first_byte(at: Option<FirstByte>, reread: Option<&Reread>, out: &mut String) {
    let packet = at
        .as_ref()
        .and_then(|a| reread.and_then(|file| file.packet(a.packet)));
    out.push_str(",\"first_byte\":");
    match &at {
        None => out.push_str("null"),
        Some(a) => {
            let _ = write!(
                out,
                "{{\"packet\":{},\"payload_offset\":{},\"frame_offset\":",
                a.packet, a.payload_offset
            );
            match packet
                .as_ref()
                .and_then(|p| crate::link::transport_payload_at(p.link_type, p.index, p.data))
            {
                Some(base) => {
                    let _ = write!(out, "{}", base + a.payload_offset);
                }
                None => out.push_str("null"),
            }
            out.push('}');
        }
    }
    push_l2(
        packet
            .as_ref()
            .and_then(|p| crate::link::ethernet_endpoints(p.link_type, p.data)),
        out,
    );
}

/// The row's `l2` key: `(source, destination)` or `null`.
fn push_l2(endpoints: Option<([u8; 6], [u8; 6])>, out: &mut String) {
    out.push_str(",\"l2\":");
    match endpoints {
        None => out.push_str("null"),
        Some((src, dst)) => {
            out.push_str("{\"src\":\"");
            push_mac(&src, out);
            out.push_str("\",\"dst\":\"");
            push_mac(&dst, out);
            out.push_str("\"}");
        }
    }
}

fn push_mac(mac: &[u8; 6], out: &mut String) {
    for (i, b) in mac.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(out, "{b:02x}");
    }
}

/// ZA-3215 — the flow's observation CONTEXT: what the handshake it watched
/// negotiated, as of the end of the flow.
///
/// A consumer re-read the `InitAck` tree for these, which is a second decode
/// of a negotiation the session already folded — and folded correctly, which
/// the re-read need not: every capability starts TRUE and is ANDed down per
/// Init, so reading one before both Inits were seen reads the identity element
/// of an `&=`. That is why `lowlatency`, `compression` and `qos` are `null`
/// until `negotiated` is `true` rather than a `true` nobody agreed to.
///
/// `sn_mask` is the ring the SN verdicts on this flow were judged at, `null`
/// until an `InitAck` (or `Join`) was observed — and `null` is then why every
/// `sn.verdict` on the flow is `without_resolution`. ⚠ It can reach
/// `2^63 - 1`, past what an IEEE double holds exactly: read it as an integer.
fn push_context(context: &wz_session_core::passive::FlowContext, out: &mut String) {
    let negotiated = context.negotiated();
    let agreed = |v: bool| {
        if negotiated {
            if v {
                "true"
            } else {
                "false"
            }
        } else {
            "null"
        }
    };
    out.push_str(",\"context\":{\"phase\":");
    escape_into(phase_word(context.phase).name(), out);
    let _ = write!(
        out,
        ",\"negotiated\":{negotiated},\"lowlatency\":{},\"compression\":{},\"qos\":{},\
         \"patch\":",
        agreed(context.lowlatency),
        agreed(context.compression),
        agreed(context.qos),
    );
    match context.patch {
        Some(p) => {
            let _ = write!(out, "{p}");
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"sn_mask\":");
    match context.sn_mask() {
        Some(m) => {
            let _ = write!(out, "{m}");
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"batch_size\":");
    match context.batch_size() {
        Some(b) => {
            let _ = write!(out, "{b}");
        }
        None => out.push_str("null"),
    }
    out.push('}');
}

/// The word `context.phase` carries, one per `SessionPhase` variant.
#[derive(Clone, Copy)]
enum PhaseWord {
    Closed,
    Established,
    HalfInit,
    InitComplete,
    Unseen,
}

fn phase_word(phase: wz_session_core::passive::SessionPhase) -> PhaseWord {
    use wz_session_core::passive::SessionPhase;
    match phase {
        SessionPhase::Unseen => PhaseWord::Unseen,
        SessionPhase::HalfInit => PhaseWord::HalfInit,
        SessionPhase::InitComplete => PhaseWord::InitComplete,
        SessionPhase::Established => PhaseWord::Established,
        SessionPhase::Closed => PhaseWord::Closed,
    }
}

impl PhaseWord {
    const fn name(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Established => "established",
            Self::HalfInit => "half_init",
            Self::InitComplete => "init_complete",
            Self::Unseen => "unseen",
        }
    }

    #[cfg(test)]
    fn next(self) -> Option<Self> {
        Some(match self {
            Self::Closed => Self::Established,
            Self::Established => Self::HalfInit,
            Self::HalfInit => Self::InitComplete,
            Self::InitComplete => Self::Unseen,
            Self::Unseen => return None,
        })
    }

    #[cfg(test)]
    pub(crate) fn names() -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut cur = Some(Self::Closed);
        while let Some(v) = cur {
            out.push(v.name());
            cur = v.next();
        }
        out
    }
}

fn note(
    named: &mut Vec<(usize, &'static str)>,
    count: &mut usize,
    cap: Option<usize>,
    at: usize,
    why: &'static str,
) {
    *count += 1;
    // The COUNT is exact and never approximate; the per-message detail is a
    // listing like any other here and takes the same ceiling.
    if cap.is_none_or(|c| named.len() < c) {
        named.push((at, why));
    }
}

/// Where a stream message begins, through the crate's one accessor.
///
/// R311y900 — the arithmetic and the slice that reads it used to live here,
/// private, and item 406 needed the slice from OUTSIDE the crate: a witness
/// asserting on a foreign implementation's field values cannot go through
/// this renderer's JSON without re-deriving what it is trying to judge. Both
/// moved to [`crate::FlowDissection`] and this file kept the two call sites.
fn message_at(frame: &PassiveFrame) -> usize {
    crate::FlowDissection::message_at(frame)
}

/// R2765 (open debt 788) — what a row producer needs to report selection: the
/// list it is rendering, and the walk that judged it.
///
/// # Why one value and not two arguments
///
/// They are one fact. A verdict map without a list index cannot be looked up
/// in, and a list index without a map has nothing to look up — but as two
/// `Option`s those impossible pairs are representable, and the renderer had to
/// check for them at a point where the only honest response was to say
/// nothing. As one `Option` the impossible pairs do not exist, and the absence
/// means the one thing it should: no selector was given.
///
/// ⚠ AND IT KEPT AN ARITY HONEST. Splitting this into two arguments pushed
/// `push_datagram_flow` past clippy's bound, and the reflex there is an
/// `#[allow]`. The bound was right: the two arguments that broke it were the
/// two that should never have been separate.
#[derive(Clone, Copy)]
struct RowSelection<'a> {
    list: usize,
    census: &'a crate::payload::PayloadCensus,
}

impl<'a> RowSelection<'a> {
    /// Both halves, or neither.
    ///
    /// The list is an `Option` at the CALLER because a flow this document
    /// renders may have no list index to resolve — the header's own note on
    /// which lists it shows. Such a flow's rows cannot be looked up, so the
    /// honest answer is the same one a document with no selector gives, and
    /// this is the one place that decision is made.
    fn of(census: Option<&'a crate::payload::PayloadCensus>, list: Option<usize>) -> Option<Self> {
        Some(Self {
            list: list?,
            census: census?,
        })
    }
}

/// ZA-3214 ① — everything a row producer writes about a row BESIDES its walk:
/// the selector's verdict and the record coordinates.
///
/// One value, for the reason [`RowSelection`] is one value: a producer's
/// arguments were at clippy's bound, and each thing that joins a row to
/// something outside this document is the same kind of input. `list_id` is the
/// flow's own list; `scouting_list_id` is its scouting list, which only a
/// datagram flow has.
#[derive(Clone, Copy)]
struct RowTags<'a> {
    selection: Option<RowSelection<'a>>,
    list_id: Option<u64>,
    scouting_list_id: Option<u64>,
}

/// ZA-3214 ① — `"list_id":L,"anchor":A,"batch_index":B,` for a row whose list
/// the caller numbered, and nothing for one it did not.
///
/// The three fields are the record's (`list_id`, `anchor`, `batch_index`) with
/// the record's meanings, so a consumer joins on equal values. `anchor` is
/// written even where the row already carries `message_at` or `packet`: it is
/// the record's coordinate, which for a stream is the framing unit's LENGTH
/// PREFIX and not the message's first byte, so it is not the same number.
fn push_coordinates(list_id: Option<u64>, anchor: u64, batch_index: u64, out: &mut String) {
    if let Some(list_id) = list_id {
        let _ = write!(
            out,
            "\"list_id\":{list_id},\"anchor\":{anchor},\"batch_index\":{batch_index},"
        );
    }
}

/// R2765 (open debt 788) — what a selector said about ONE row, or nothing at
/// all on a document that was not given one.
///
/// # Four answers, and none of them is a nullable version of another
///
/// The consumer's own rule for its half-rows is that "we could not tell" and
/// "there is nothing to tell" must not render alike, and the same rule applies
/// coming the other way. So:
///
/// - **absent key** — no selector was given. The document says nothing about
///   selection and a reader must not infer a verdict from silence.
/// - **`"yes"` / `"no"`** — the fold decided, from records that were judged.
/// - **`"undecided"`** — records were judged and the capture does not carry
///   what deciding needs.
/// - **`"unjudged"`** — this row carried nothing the record plane judges: a
///   handshake, a keepalive, a frame whose batch it could not read. Rendering
///   that as `"undecided"` would claim a question was asked here.
///
/// ⚠ THE LAST TWO ARE THE POINT. Folding them into one null is what lets a
/// reader mistake a gap in the capture for a measured exclusion, which is the
/// failure this axis was asked for in the first place.
#[cfg(feature = "network-codecs")]
fn push_selected(selection: Option<RowSelection<'_>>, frame: &PassiveFrame, out: &mut String) {
    let Some(RowSelection { list, census }) = selection else {
        return;
    };
    row_verdict_of(census, list, frame).push(out);
}

/// ZA-3509 — the verdict for ONE row, asked of the walk that judged it.
///
/// Hoisted out of `push_selected` when the verdict-only document arrived, and
/// for the reason that document exists at all: two renderers reading the same
/// map are two places for the mapping from a fold to one of four words to
/// drift, and a row whose word differs between the document with trees and the
/// document without is the one disagreement neither consumer could debug from
/// its own half.
#[cfg(feature = "network-codecs")]
pub(crate) fn row_verdict_of(
    census: &crate::payload::PayloadCensus,
    list: usize,
    frame: &PassiveFrame,
) -> RowVerdict {
    use crate::filter::Truth;
    let key = crate::payload::RowKey::of(list, frame);
    match census.row_verdict(&key).and_then(|v| v.folded()) {
        Some(Truth::Yes) => RowVerdict::Yes,
        Some(Truth::No) => RowVerdict::No,
        Some(Truth::Unknown) => RowVerdict::Undecided,
        None => RowVerdict::Unjudged,
    }
}

/// ZA-3214 ④ — the four words a row's `selected` key carries, as ONE type.
///
/// R2766 wrote them as literals in two places — the arm above and the scouting
/// arm, which writes `unjudged` directly — and declared neither the key nor
/// the set, so a consumer switching on the word had no revision to pin and no
/// `@values` marker to read, against R2175's contract that a closed set a
/// consumer switches on is declared. This enum is the walk the declaration in
/// [`crate::doc_revision::SELECTED_R13`] is held to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowVerdict {
    /// The row's records were judged and at least one matched.
    Yes,
    /// The row's records were judged and none matched.
    No,
    /// Records were judged and the capture does not carry what deciding needs.
    Undecided,
    /// The row carries nothing the record plane judges.
    Unjudged,
}

impl RowVerdict {
    /// The word this verdict is written as.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Undecided => "undecided",
            Self::Unjudged => "unjudged",
        }
    }

    /// Every word, by walking the variants — what the declared family is held to.
    pub fn names() -> alloc::vec::Vec<&'static str> {
        [Self::Yes, Self::No, Self::Undecided, Self::Unjudged]
            .into_iter()
            .map(|v| match v {
                // Exhaustive on purpose: a variant added later fails to compile
                // here rather than missing from the declaration.
                Self::Yes | Self::No | Self::Undecided | Self::Unjudged => v.word(),
            })
            .collect()
    }

    fn push(self, out: &mut String) {
        let _ = write!(out, "\"selected\":\"{}\",", self.word());
    }
}

/// The same, where the record plane is not compiled in at all.
///
/// A build without `network-codecs` has no `RecordView` to judge, so it has no
/// verdict to report and says nothing rather than saying "unjudged" about
/// every row — which would be this document claiming a walk it never made.
#[cfg(not(feature = "network-codecs"))]
fn push_selected(_selection: Option<RowSelection<'_>>, _frame: &PassiveFrame, _out: &mut String) {}

fn message_name(frame: &PassiveFrame) -> String {
    if let Ok(wz_session_core::inbound::InboundFrame::Network { payload }) = &frame.frame {
        return payload
            .first()
            .and_then(|b| MidSpace::Network.head(b & 0x1f))
            .map_or("Unknown", |m| m.name())
            .to_string();
    }
    framed_name(frame.frame.as_ref().map(|f| f.kind_name()))
}

/// R2629 (open-debt item 744) — the first pass's name for a scouting datagram,
/// on the rule [`message_name`] follows.
fn scouting_name(datagram: &crate::ScoutingDatagram) -> String {
    framed_name(datagram.frame.as_ref().map(|f| f.kind_name()))
}

fn framed_name<E: core::fmt::Debug>(frame: Result<&'static str, &E>) -> String {
    match frame {
        Ok(name) => name.to_string(),
        // A message this reader could NOT decode is named as such rather than
        // omitted: a listing that shows only the successes is the silence this
        // layer exists to end.
        Err(e) => {
            let mut s = String::from("undecodable(");
            let _ = write!(s, "{e:?}");
            s.push(')');
            s
        }
    }
}

/// R2629 (open-debt item 744) — WHICH MID SPACE a row's bytes are read in.
///
/// Two spaces reach this document and they reuse each other's numbers: `0x01`
/// is `Init` on a session and `Scout` on the scouting group. The first pass
/// already decided which list a datagram belongs to, so a row carries that
/// decision here rather than letting the walker or the vocabulary guess it from
/// the byte.
#[derive(Clone, Copy)]
enum MidSpace {
    /// A session message: walked by `dissect_transport_message`, named through
    /// `MessageName::of_transport`.
    Transport,
    /// A bare network message on a negotiated lowlatency session.
    Network,
    /// A scouting datagram: walked by `dissect_scouting_message`, named through
    /// `MessageName::of_scouting`.
    Scouting,
}

impl MidSpace {
    fn of_frame(frame: &PassiveFrame) -> Self {
        if matches!(
            frame.frame,
            Ok(wz_session_core::inbound::InboundFrame::Network { .. })
        ) {
            Self::Network
        } else {
            Self::Transport
        }
    }

    /// Walk `bytes` at base 0 in this space.
    ///
    /// `Ok(None)` is the scouting walker's "not a MID of mine"; the transport
    /// walker has no such answer and names what it does not know `Unknown`.
    /// The error is rendered rather than named: its type is
    /// `sce_forge_runtime`'s and is not re-exported here, and this crate has no
    /// reason to take that dependency on for one message string.
    fn walk(self, bytes: &[u8]) -> Result<Option<wz_session_core::dissect::Field>, String> {
        fn rendered<E: core::fmt::Debug>(err: E) -> String {
            let mut s = String::new();
            let _ = write!(s, "{err:?}");
            s
        }
        match self {
            Self::Transport => wz_session_core::dissect::dissect_transport_message(bytes, 0)
                .map(Some)
                .map_err(rendered),
            Self::Network => {
                let mut cursor = wz_session_core::dissect::SpanCursor::new(bytes);
                let field =
                    wz_session_core::dissect::walk_network_record(&mut cursor).map_err(rendered)?;
                if field.is_some() && cursor.remaining() != 0 {
                    return Err("trailing bytes after a lowlatency network message".to_string());
                }
                Ok(field)
            }
            Self::Scouting => {
                wz_session_core::dissect::dissect_scouting_message(bytes, 0).map_err(rendered)
            }
        }
    }

    /// The message this space's MID byte names, through the one vocabulary.
    fn head(self, mid: u8) -> Option<wz_session_core::dissect::MessageName> {
        use wz_session_core::dissect::MessageName;
        match self {
            Self::Transport => MessageName::of_transport(mid),
            Self::Network => MessageName::of_network(mid),
            Self::Scouting => MessageName::of_scouting(mid),
        }
    }
}

/// `Unknown` on either side is not a disagreement — neither reader claimed to
/// have named the message — and an undecodable frame has no name to compare.
fn walk_agrees(walked: &str, framed: &str) -> bool {
    walked == "Unknown"
        || framed == "Unknown"
        || framed.starts_with("undecodable(")
        || walked == framed
}

/// The capture, parsed a second time, in EITHER format.
///
/// Both, and that is not a convenience: reading only pcapng would tell a
/// classic `.pcap` holding datagram traffic that its packets could not be
/// re-read — a notice true about the code and false about the file.
enum Reread {
    Ng(crate::pcapng::PcapngFile),
    Classic(crate::pcap::PcapFile),
}

struct RereadPacket<'a> {
    link_type: u32,
    index: usize,
    data: &'a [u8],
}

impl Reread {
    fn of(capture: &[u8]) -> Option<Self> {
        if crate::pcapng::looks_like_pcapng(capture) {
            crate::pcapng::parse(capture).ok().map(Self::Ng)
        } else {
            crate::pcap::parse(capture).ok().map(Self::Classic)
        }
    }

    fn packet(&self, index: usize) -> Option<RereadPacket<'_>> {
        match self {
            Self::Ng(file) => file.packets.get(index).map(|p| RereadPacket {
                link_type: p.link_type,
                index: p.index,
                data: &p.data,
            }),
            Self::Classic(file) => file.packets.get(index).map(|p| RereadPacket {
                // One link type for the whole file, which is what a classic
                // pcap's header says and the reason it is not on the packet.
                link_type: file.link_type,
                index: p.index,
                data: &p.data,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::{tcp_packet, udp_packet};
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    use alloc::vec;

    /// R2460 (open-debt item 705) — ACCEPTANCE: THIS DOCUMENT RESOLVES A KEY
    /// DECLARED ON THE PREVIOUS FLOW'S QUIC SUB-LIST.
    ///
    /// # What was wrong
    ///
    /// `push_datagram_flow` folded `flow.frames` — the cleartext list — and
    /// nothing else, so a `DeclKexpr` carried on a recovered QUIC stream went
    /// into no table at all. `crate::agg`'s census planes walk
    /// `Dissection::message_lists`, which is EVERY list, and resolved the same
    /// id from the same bytes. One capture, two answers.
    ///
    /// # Why the declaration is on flow ONE and the reference on flow TWO
    ///
    /// Within a flow the enumeration folds the cleartext list BEFORE that
    /// flow's QUIC sub-lists, so a declaration on the stream is legitimately
    /// not yet in the table when the flow's own rows are read. What diverges is
    /// the lists that come AFTER, which a one-flow capture cannot show.
    ///
    /// # Why the handshake is on the QUIC stream too
    ///
    /// `node::SessionGrouping` is keyed by LIST, not by flow — a link is
    /// recorded only where both ends sent an INIT on that list. With the
    /// handshake only on the cleartext list, the sub-list would fall to the
    /// `agg::SpaceOwner::Flow` fallback, its declaration would be private, and
    /// this test would pass with the fold removed. Fed as a length-prefixed
    /// pair, which is what a stream carries.
    #[test]
    fn a_key_declared_on_a_quic_sublist_reaches_the_next_flow() {
        use crate::node::tests::{framed_init, init_wire};
        use wz_session_core::passive::Direction;
        use wz_session_core::wire_const::T_MID_KEEP_ALIVE;

        const ZID_A: &[u8] = &[0xA1, 0xA1, 0xA1, 0xA1];
        const ZID_B: &[u8] = &[0xB2, 0xB2, 0xB2, 0xB2];
        const ID: u64 = 7;

        let declare = wz_codecs::declare::Declare {
            body: wz_codecs::declare::DeclareVariant::CodecZenohDeclKexpr(
                wz_codecs::decl_kexpr::DeclKexpr {
                    header: wz_session_core::wire_const::D_MID_KEXPR
                        | wz_session_core::wire_const::FLAG_D_N,
                    id: ID,
                    keyexpr: crate::datagram_tests::sender_space(0, Some("demo/temp")),
                    extensions: None,
                },
            ),
            ..Default::default()
        }
        .encode_to_vec();

        // A REAL capture file, because this document renders a row only by
        // RE-READING the bytes a message was framed out of: handed an empty
        // slice it reports `capture_reread: false` and every flow comes out
        // with no messages, which would make the claim below unfalsifiable.
        let packets: Vec<Vec<u8>> = alloc::vec![
            // FLOW ONE, in the clear: only a keepalive, so its cleartext list
            // declares nothing and names nobody. Everything this flow
            // contributes is on the sub-list fed below.
            udp_packet(
                [10, 0, 0, 1],
                43210,
                [10, 0, 0, 2],
                7447,
                &[T_MID_KEEP_ALIVE]
            ),
            // FLOW TWO, and it comes after: the same session's other link,
            // whose handshake and whose REFERENCE are both in the clear.
            udp_packet([10, 0, 0, 3], 43211, [10, 0, 0, 2], 7447, &init_wire(ZID_A)),
            udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 3], 43211, &init_wire(ZID_B)),
            udp_packet(
                [10, 0, 0, 3],
                43211,
                [10, 0, 0, 2],
                7447,
                &crate::datagram_tests::frame_carrying(&crate::datagram_tests::push(
                    crate::datagram_tests::sender_space(ID, None),
                    &[7u8; 5],
                )),
            ),
        ];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = crate::pcapng::write(&[(LINKTYPE_ETHERNET, 6)], &refs);
        let mut d = Dissection::from_capture(&capture).expect("the capture reads");

        // THE SUB-LIST. Fed rather than pushed because this crate carries no
        // cipher: what a caller hands in is the plaintext it decrypted. Both
        // directions on ONE stream id, which is what records the link at THIS
        // list's index and puts the declaration in the session's table.
        let first = d.datagram_flows()[0].flow;
        let mut opening = framed_init(ZID_A);
        opening.extend_from_slice(&{
            let framed = crate::datagram_tests::frame_carrying(&declare);
            let mut unit = (framed.len() as u16).to_le_bytes().to_vec();
            unit.extend_from_slice(&framed);
            unit
        });
        d.feed_quic_stream(first, Direction::A, 0, false, &opening);
        d.feed_quic_stream(first, Direction::B, 0, false, &framed_init(ZID_B));
        d.finish();

        // THE FIXTURE'S OWN ANCHOR: one session over two links, one of which is
        // the QUIC sub-list. Without it the declaration is private and the
        // claim below could not fail.
        let grouping = crate::node::session_grouping(&d);
        let inventory: Vec<(usize, String, usize)> = d
            .message_lists_with_origin()
            .enumerate()
            .map(|(i, (_, origin, list))| {
                (
                    i,
                    alloc::format!("{origin:?}"),
                    wz_session_core::passive_messages::MessageList::as_slice(list).len(),
                )
            })
            .collect();
        assert_eq!(
            (grouping.sessions(), grouping.grouped_lists()),
            (1, 2),
            "one session, and its two links are the QUIC SUB-LIST of flow one \
             and the cleartext list of flow two.\n  lists: {inventory:?}\n  \
             links: {:?}",
            crate::node::nodes(&d).links()
        );

        let json = fields_json(&d, &capture, None, None);
        assert!(
            json.contains("\"keyexpr\":\"demo/temp\""),
            "the reference on flow two must resolve against the declaration \
             carried on flow one's QUIC stream: {json}"
        );
        assert!(
            !json.contains("\"keyexpr_cause\":\"no_declaration\""),
            "and nothing may still report that the session declared nothing, \
             which is the cause a walk of `flow.frames` alone produced: {json}"
        );
    }

    /// R2458 (open-debt item 703) — a capture whose datagram table carries QUIC
    /// SUB-LISTS, so the enumeration position of a row and its position in its
    /// own table are different numbers.
    ///
    /// TWO datagram flows and the QUIC lists on the FIRST, because that is what
    /// makes the second flow's list index disagree with its table index. One
    /// flow would leave the two the same and the derivation would be graded by
    /// a capture that cannot tell it from the arithmetic it replaced.
    ///
    /// Its own fixture rather than `tls_flow_tests::every_producer_corpus`,
    /// which reaches the same producers: that one lives in a module named for
    /// another subject and is private to it, and widening a fixture across
    /// modules to reach one number is how a fixture acquires callers whose
    /// needs pull against each other.
    fn quic_bearing_dissection() -> Dissection {
        use wz_session_core::passive::Direction;
        use wz_session_core::wire_const::T_MID_KEEP_ALIVE;

        const BATCH: usize = 4;
        let keepalive = alloc::vec![T_MID_KEEP_ALIVE];
        // One framing unit: a two-byte little-endian length prefix, then that
        // many one-byte messages. The stream half needs a whole unit or the
        // flow decodes nothing.
        let mut unit = (BATCH as u16).to_le_bytes().to_vec();
        unit.extend(core::iter::repeat_n(T_MID_KEEP_ALIVE, BATCH));

        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &unit));
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &crate::datagram_tests::tcp_packet_reverse(2000, &unit),
        );
        for (i, (low, port)) in [([10u8, 0, 0, 1], 43210u16), ([10, 0, 0, 3], 43211)]
            .into_iter()
            .enumerate()
        {
            d.push_packet(
                LINKTYPE_ETHERNET,
                2 + i,
                &udp_packet(low, port, [10, 0, 0, 2], 7447, &keepalive),
            );
        }
        let flow = d.datagram_flows()[0].flow;
        // Fed rather than pushed: this crate carries no cipher, so what a
        // caller hands in is the plaintext it decrypted — which is exactly why
        // those bytes are not retained and why this document cannot render
        // them.
        d.feed_quic_stream(flow, Direction::A, 7, false, &unit);
        d.feed_quic_datagram(flow, Direction::A, 2, &keepalive);
        d.finish();
        d
    }

    /// R2458 (open-debt item 703) — THE LIST SET THIS DOCUMENT RENDERS, DERIVED
    /// FROM THE ENUMERATION AND NOT FROM TABLE ARITHMETIC.
    ///
    /// [`RenderedLists`] exists because `SessionGrouping` is keyed by the
    /// `Dissection::message_lists` position and this document is not that walk.
    /// What is graded here is that the derivation LANDS: one index per rendered
    /// row, and each index naming the list that row's frames actually are.
    ///
    /// The population is a QUIC-carrying capture on purpose. A datagram flow
    /// contributes one list plus one per QUIC stream plus one for its RFC 9221
    /// datagrams, so `datagram_flows[i]` is `flows.len() + i` only while no
    /// capture holds a QUIC flow — an assumption that is true of most fixtures
    /// here and false of the reader. This is the fixture where positional
    /// arithmetic and the derivation disagree, which is what makes the
    /// assertion mean something.
    #[test]
    fn the_field_document_names_a_list_index_for_every_row_it_renders() {
        for (what, d) in [
            ("multilink", crate::agg::tests::multilink_session()),
            ("quic", quic_bearing_dissection()),
        ] {
            let lists = RenderedLists::of(&d);
            assert_eq!(
                lists.stream.len(),
                d.flows().len(),
                "{what}: one list index per stream row"
            );
            assert_eq!(
                lists.datagram.len(),
                d.datagram_flows().len(),
                "{what}: one list index per datagram row"
            );
            // The index NAMES the row's own list, checked against the
            // enumeration rather than against a second computation of it.
            let all: Vec<(crate::link::FlowKey, crate::MessageListOrigin)> = d
                .message_lists_with_origin()
                .map(|(flow, origin, _)| (flow, origin))
                .collect();
            for (i, flow) in d.flows().iter().enumerate() {
                assert_eq!(
                    all[lists.stream[i]],
                    (flow.flow, crate::MessageListOrigin::Stream),
                    "{what}: stream row {i}"
                );
            }
            for (i, flow) in d.datagram_flows().iter().enumerate() {
                assert_eq!(
                    all[lists.datagram[i]],
                    (flow.flow, crate::MessageListOrigin::Datagram),
                    "{what}: datagram row {i}"
                );
            }
        }
    }

    /// THE ANTI-VACUITY HALF of the derivation: the QUIC fixture really does
    /// hold lists this document does not render, so the test above is not
    /// asserting that a positional guess happens to be right.
    ///
    /// Without it, a capture with no QUIC sub-list would satisfy every
    /// assertion above under `datagram_flows[i] == flows.len() + i`, and the
    /// derivation would be graded by a population that cannot tell it from the
    /// arithmetic it replaced.
    #[test]
    fn the_quic_fixture_holds_lists_the_field_document_does_not_render() {
        let d = quic_bearing_dissection();
        let lists = RenderedLists::of(&d);
        let total = d.message_lists_with_origin().count();
        let rendered = lists.stream.len() + lists.datagram.len();
        assert!(
            rendered < total,
            "the fixture must hold lists this document leaves out, or the \
             derivation is graded against a capture where position and \
             enumeration agree: {rendered} rendered of {total}"
        );
        let last = *lists.datagram.last().expect("a datagram row");
        assert_ne!(
            last,
            lists.stream.len() + lists.datagram.len() - 1,
            "and the LAST datagram row must not sit where the arithmetic would \
             put it, or the disagreement is behind the rows this test reads"
        );
    }

    /// Every `(keyexpr, keyexpr_cause)` pair the document carries, as the raw
    /// JSON values so `null` and `"null"` cannot be confused.
    #[cfg(feature = "network-codecs")]
    fn carried_keys(doc: &str) -> Vec<(&str, &str)> {
        crate::doc_revision::object_scopes(doc)
            .into_iter()
            .filter_map(|scope| {
                let key = scope.iter().find(|(k, _)| *k == "keyexpr")?.1;
                let cause = scope.iter().find(|(k, _)| *k == "keyexpr_cause")?.1;
                Some((key, cause))
            })
            .collect()
    }

    /// A document with every row's `selected` key taken out — what a selector
    /// ADDS, so that the rest can be compared against a document made without
    /// one. `RowVerdict::push` writes the key with its trailing comma, and the
    /// four words are the whole vocabulary, so this removes exactly what the
    /// selector put there.
    #[cfg(feature = "network-codecs")]
    fn without_selected(doc: &str) -> String {
        let mut out = String::from(doc);
        for word in RowVerdict::names() {
            out = out.replace(&alloc::format!("\"selected\":\"{word}\","), "");
        }
        out
    }

    /// ZA-3517 — THE EMPTY SELECTOR IS THE IDENTITY, for the field document as
    /// it is for every census plane: it asks no question, so it writes no answer.
    ///
    /// # What this holds, and where it was false
    ///
    /// `wz_dissect.h` says a document asked for without a selector carries no
    /// `selected` key, and says three times that an empty selector selects
    /// everything so that the door taking one is the door that does not. For the
    /// census that is true byte for byte. For this document it was not: the
    /// empty selector parsed to `Filter::any`, every row was judged against it,
    /// and each carried a `selected` word — `yes` for a judged row, `unjudged`
    /// for the rest. A consumer reading the SUBSUMED mark as "same answer"
    /// swapped the older door for the newer one and its golden moved on every
    /// row.
    ///
    /// Three arms, and the second is what keeps the first from being satisfied
    /// by a door that never writes the key: a narrowing selector DOES write it,
    /// and what it adds is that key and nothing else — so the two documents are
    /// one document, differing by exactly the question asked.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn an_empty_selector_asks_no_question_and_writes_no_verdict() {
        let (d, file) = crate::agg::tests::multilink_session_with_file();
        let plain = fields_json(&d, &file, None, None);
        assert!(
            !plain.contains("\"selected\""),
            "the document made with no selector must carry no verdict: {plain}"
        );

        let picky = crate::filter::Filter::parse("bytes > 6").expect("parses");
        let narrowed = fields_json_where(&d, &file, None, None, &picky);
        assert!(
            narrowed.contains("\"selected\":\"yes\"") && narrowed.contains("\"selected\":\"no\""),
            "anti-vacuity: a narrowing selector must write the key and divide the \
             rows, or the identity below is satisfied by a door that never does: \
             {narrowed}"
        );

        for source in ["", "   ", "\t\n"] {
            let any = crate::filter::Filter::parse(source).expect("parses");
            assert_eq!(
                fields_json_where(&d, &file, None, None, &any),
                plain,
                "selector {source:?} selects everything, so it must be the document \
                 that asks nothing, byte for byte"
            );
        }

        assert_eq!(
            without_selected(&narrowed),
            plain,
            "a selector adds the verdict key and nothing else"
        );
    }

    /// ZA-3517 — the same identity through the door that also carries the
    /// record coordinates, which is the one a live handle calls and the one a
    /// consumer passes an empty selector to when it is not narrowing.
    ///
    /// The coordinates are a separate axis from the verdict and stay when the
    /// verdict goes: an empty selector must not cost a consumer its join key.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn an_empty_selector_keeps_the_coordinates_and_drops_only_the_verdict() {
        let (d, file) = crate::agg::tests::multilink_session_with_file();
        let any = crate::filter::Filter::parse("").expect("parses");
        let picky = crate::filter::Filter::parse("bytes > 6").expect("parses");

        let every = fields_json_where_coordinated(&d, &file, None, None, &any, &EveryListNumbered);
        assert!(
            every.contains("\"list_id\":") && every.contains("\"anchor\":"),
            "an empty selector must not cost a consumer its join key: {every}"
        );
        assert!(
            !every.contains("\"selected\""),
            "and it must not write a verdict either: {every}"
        );

        let narrowed =
            fields_json_where_coordinated(&d, &file, None, None, &picky, &EveryListNumbered);
        assert!(
            narrowed.contains("\"selected\":"),
            "anti-vacuity: {narrowed}"
        );
        assert_eq!(
            without_selected(&narrowed),
            every,
            "a selector adds the verdict key and nothing else, coordinates included"
        );
    }

    /// One row of a document that carries the record coordinates, as the raw
    /// JSON values `(direction, list_id, anchor, batch_index, selected)` — the
    /// last empty when the row has no verdict. Rows are found by the key only a
    /// row carries, so the objects nested inside a row's tree never join them.
    #[cfg(feature = "network-codecs")]
    fn coordinate_rows(doc: &str) -> Vec<(String, String, String, String, String)> {
        crate::doc_revision::object_scopes(doc)
            .into_iter()
            .filter(|scope| scope.iter().any(|(key, _)| *key == "list_id"))
            .map(|scope| {
                let get = |key: &str| {
                    scope
                        .iter()
                        .find(|(k, _)| *k == key)
                        .map_or_else(String::new, |(_, value)| String::from(*value))
                };
                (
                    get("direction"),
                    get("list_id"),
                    get("anchor"),
                    get("batch_index"),
                    get("selected"),
                )
            })
            .collect()
    }

    /// A numbering that numbers nothing — a caller whose handle minted no ids.
    #[cfg(feature = "network-codecs")]
    struct NoListNumbered;

    #[cfg(feature = "network-codecs")]
    impl RowCoordinates for NoListNumbered {
        fn list_id(&self, _list: usize) -> Option<u64> {
            None
        }

        fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
            None
        }
    }

    /// The captures the verdict document is held against: a session over two
    /// links with a datagram flow, a flow with no handshake, a compressed
    /// session, and — where the build reassembles — a capture that starts
    /// mid-chain. Each carries rows the others do not.
    #[cfg(feature = "network-codecs")]
    fn verdict_fixtures() -> Vec<(&'static str, crate::Dissection, Vec<u8>)> {
        let mut out = Vec::new();
        let (d, file) = crate::agg::tests::multilink_session_with_file();
        out.push(("multilink", d, file));
        let (d, file) = crate::agg::tests::orphan_flow_session_with_file();
        out.push(("orphan flow", d, file));
        let (d, file) = crate::datagram_tests::compressed_session_dissection_with_file();
        out.push(("compressed", d, file));
        #[cfg(feature = "reassembly")]
        {
            let (d, file) = crate::datagram_tests::midsession_fragment_dissection_with_file();
            out.push(("midsession", d, file));
        }
        out
    }

    /// ZA-3509 — THE VERDICT DOCUMENT IS THE FIELD DOCUMENT'S ROWS AND THE SAME
    /// WORD ON EACH, without the trees.
    ///
    /// # The claim, and why it is the whole of the contract
    ///
    /// A consumer that narrows a list from this document and shows a detail from
    /// the field document is reading two documents about one row, and the only
    /// thing that makes that safe is that they agree about which rows there are
    /// and what the selector said of each. So every row the field document
    /// renders must be here, in its order, with its coordinates and its word —
    /// over every capture the fixtures hold and every selector a consumer types
    /// a chip for.
    ///
    /// Equality where the field document lost nothing, and the field document's
    /// rows as an ORDERED SUBSET where it did: a datagram row is dropped there
    /// when its second read disagrees, and this document has no second read to
    /// disagree.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_verdict_document_is_the_field_documents_rows_without_the_trees() {
        let mut compared = 0usize;
        let mut exact = 0usize;
        for (name, d, file) in verdict_fixtures() {
            for source in ["bytes > 6", "bytes >= 0", "key == demo/temp", "kind == put"] {
                let filter = crate::filter::Filter::parse(source).expect("parses");
                let full = fields_json_where_coordinated(
                    &d,
                    &file,
                    None,
                    None,
                    &filter,
                    &EveryListNumbered,
                );
                let light = crate::selection_json::selection_json_where_coordinated(
                    &d,
                    &filter,
                    &EveryListNumbered,
                );
                let (in_full, in_light) = (coordinate_rows(&full), coordinate_rows(&light));
                assert!(
                    !in_full.is_empty(),
                    "{name}/{source}: anti-vacuity, the field document must render rows: {full}"
                );
                assert!(
                    in_full.iter().all(|row| !row.4.is_empty()),
                    "{name}/{source}: every field row must carry a verdict under a selector"
                );

                let mut from = 0usize;
                for row in &in_full {
                    let at = in_light[from..]
                        .iter()
                        .position(|candidate| candidate == row)
                        .unwrap_or_else(|| {
                            panic!(
                                "{name}/{source}: the field document's row {row:?} is missing \
                                 from, or out of order in, the verdict document: {light}"
                            )
                        });
                    from += at + 1;
                }
                // Every datagram flow says how many rows its second read cost it; the
                // documents must agree exactly only where every flow says none.
                let lost_none = full.matches("\"disagreements\":{\"count\":0,").count()
                    == full.matches("\"disagreements\":").count();
                if lost_none && full.contains("\"capture_reread\":true") {
                    assert_eq!(
                        in_light, in_full,
                        "{name}/{source}: where the field document lost no row the two \
                         documents must list the same rows"
                    );
                    exact += 1;
                }
                assert!(
                    light.len() < full.len(),
                    "{name}/{source}: the verdict document must be the smaller one"
                );
                compared += 1;
            }
        }
        assert!(
            compared >= 12,
            "the population shrank: {compared} comparisons"
        );
        assert!(
            exact > 0,
            "anti-vacuity: at least one capture must have lost no row, or the equality arm \
             never ran"
        );
    }

    /// ZA-3509 — AND IT NEEDS NO CAPTURE CONTAINER, which is what lets a handle
    /// fed by `push` have datagram verdicts at all.
    ///
    /// The field document re-reads each datagram from the container to walk its
    /// tree, so given none it renders no datagram row and says so with
    /// `capture_reread: false`. The verdict is decided by the record plane, not
    /// by that walk, so this document has the row anyway. The three counts are
    /// the argument: the container-less field document has fewer rows than the
    /// one with a container, and the verdict document has at least as many as
    /// the latter.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_verdict_document_has_datagram_rows_a_container_less_field_document_cannot() {
        let (d, file) = crate::agg::tests::multilink_session_with_file();
        let filter = crate::filter::Filter::parse("bytes > 6").expect("parses");

        let blind = fields_json_where_coordinated(&d, &[], None, None, &filter, &EveryListNumbered);
        assert!(
            blind.contains("\"capture_reread\":false"),
            "anti-vacuity: with no container the field document must say it re-read nothing: \
             {blind}"
        );
        let with =
            fields_json_where_coordinated(&d, &file, None, None, &filter, &EveryListNumbered);
        let light = crate::selection_json::selection_json_where_coordinated(
            &d,
            &filter,
            &EveryListNumbered,
        );

        let (blind_rows, with_rows, light_rows) = (
            coordinate_rows(&blind),
            coordinate_rows(&with),
            coordinate_rows(&light),
        );
        assert!(
            blind_rows.len() < with_rows.len(),
            "anti-vacuity: the fixture must hold a datagram row the container-less document \
             loses: {} against {}",
            blind_rows.len(),
            with_rows.len()
        );
        assert!(
            light_rows.len() >= with_rows.len(),
            "the verdict document must not lose what the container-less field document does: \
             {} against {}",
            light_rows.len(),
            with_rows.len()
        );
    }

    /// ZA-3509 — AN EMPTY SELECTOR IS THE IDENTITY HERE TOO: the rows and their
    /// coordinates, and no verdict on any of them.
    ///
    /// The verdict document is the one place an empty selector could have been
    /// read as "everything matches" and answered `yes` throughout. It does not:
    /// that would be the census-and-field family's one exception again, and a
    /// consumer that passed an empty selector because it was not narrowing would
    /// read a verdict nobody asked for.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_verdict_document_under_an_empty_selector_lists_rows_and_says_nothing_of_them() {
        let (d, _file) = crate::agg::tests::multilink_session_with_file();
        let any = crate::filter::Filter::parse("  ").expect("parses");
        let picky = crate::filter::Filter::parse("bytes > 6").expect("parses");

        let asked_nothing =
            crate::selection_json::selection_json_where_coordinated(&d, &any, &EveryListNumbered);
        let asked =
            crate::selection_json::selection_json_where_coordinated(&d, &picky, &EveryListNumbered);
        assert!(
            !asked_nothing.contains("\"selected\""),
            "an empty selector asks nothing and must write no verdict: {asked_nothing}"
        );
        assert!(
            asked.contains("\"selected\":\"yes\"") && asked.contains("\"selected\":\"no\""),
            "anti-vacuity: a selector must divide the rows, or the arm above proves nothing: \
             {asked}"
        );
        let coordinates = |doc: &str| -> Vec<(String, String, String, String)> {
            coordinate_rows(doc)
                .into_iter()
                .map(|r| (r.0, r.1, r.2, r.3))
                .collect()
        };
        assert!(
            !coordinates(&asked_nothing).is_empty(),
            "an empty selector must not cost a consumer its rows: {asked_nothing}"
        );
        assert_eq!(
            coordinates(&asked_nothing),
            coordinates(&asked),
            "the selector adds the verdict and changes neither the rows nor their order"
        );
    }

    /// ZA-3509 — a list the caller does not number gets no coordinate keys and
    /// no invented ones, on the field document's own rule, and the verdict still
    /// arrives: a consumer that cannot join a row can still count it.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_row_of_a_list_nobody_numbered_carries_no_coordinates_and_still_a_verdict() {
        let (d, _file) = crate::agg::tests::multilink_session_with_file();
        let picky = crate::filter::Filter::parse("bytes > 6").expect("parses");
        let doc =
            crate::selection_json::selection_json_where_coordinated(&d, &picky, &NoListNumbered);
        assert!(
            !doc.contains("\"list_id\"")
                && !doc.contains("\"anchor\"")
                && !doc.contains("\"batch_index\""),
            "no coordinate may be invented for a list nobody numbered: {doc}"
        );
        assert!(
            doc.contains("{\"direction\":\"a\",\"selected\":")
                || doc.contains("{\"direction\":\"b\",\"selected\":"),
            "and the verdict must still be there: {doc}"
        );
    }

    /// R2458 (open-debt item 703) — ACCEPTANCE, inherited from item 702 word for
    /// word and asked of the document R2457 did not reach.
    ///
    /// NOT "the multilink capture resolves", which a build that folded every
    /// table into one would satisfy while cross-resolving two unrelated
    /// sessions. The claim is the PAIR, on this document:
    ///
    /// 1. a reference on the SECOND link of a session resolves against the
    ///    declaration that went out on the first;
    /// 2. a reference that does NOT resolve says which of the two failures it
    ///    was — `no_declaration` (the session is named and nobody declared this
    ///    id) or `no_session` (this flow showed no handshake, so the
    ///    declaration may be one link over).
    ///
    /// R2765 (open debt 788) — A SELECTOR REACHES THE ROWS, and the document
    /// says which rows it picked rather than only how many.
    ///
    /// The consumer has a census door that takes a selector and a field door
    /// that does not, so the only way it could show "the messages matching
    /// this" was to re-implement the selector over the rows it got back. That
    /// is a second reading of one language, which is the failure both sides
    /// named independently.
    ///
    /// ⚠ THE VERDICT IS FOLDED PER ROW, NOT PER RECORD, and that is the
    /// consumer's decision rather than a convenience: a row may carry several
    /// records, and their reassembled coordinates exist only inside a reader,
    /// so a row-per-record rendering would have to invent a coordinate for
    /// each. Any Yes makes the row Yes; all No makes it No; anything else is
    /// the third value.
    ///
    /// ⚠ AND THE THIRD VALUE IS NOT `null`-FOR-EVERYTHING. "The capture did
    /// not carry what deciding needs" and "no record on this row could be
    /// judged at all" are different facts, and a reader that cannot separate
    /// them reads a silent gap as a measured exclusion.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_selector_picks_rows_in_the_field_document_and_says_which() {
        let (d, file) = crate::agg::tests::multilink_session_with_file();

        let unfiltered = fields_json(&d, &file, None, None);
        assert!(
            !carried_keys(&unfiltered).is_empty(),
            "anti-vacuity: the fixture must render carried rows at all, or \
             every count below is 0 and proves nothing: {unfiltered}"
        );

        // ⚠ THE AXIS IS PAYLOAD SIZE AND NOT THE KEYEXPR, measured rather than
        // chosen for taste. This fixture carries exactly one keyexpr that
        // resolves, so `key == ..` cannot produce a miss: every row is either
        // that key or undecided, and the arm below would fail for a reason
        // about the fixture rather than about the join. Its payloads are 3, 5
        // and 11 bytes, so a size question divides them — and it divides them
        // on an axis that does not depend on resolution, which keeps this test
        // about selection rather than about keyexpr binding.
        let picky = crate::filter::Filter::parse("bytes > 6")
            .expect("the fixture's own payload sizes must parse as a selector");
        let doc = fields_json_where(&d, &file, None, None, &picky);

        let yes = doc.matches("\"selected\":\"yes\"").count();
        let no = doc.matches("\"selected\":\"no\"").count();
        assert!(
            yes > 0,
            "the selector must pick something in a capture that carries it: {doc}"
        );
        assert!(
            no > 0,
            "and it must DIVIDE the rows -- a verdict that says yes to every \
             row is not a selection: {doc}"
        );
    }

    /// R2765 (open debt 788) — THE FOUR ANSWERS ARE FOUR, and the two that
    /// look alike are the reason this test exists.
    ///
    /// `undecided` and `unjudged` both mean "no verdict", and a renderer that
    /// folded them into one null would be defensible right up until a reader
    /// acted on it. They are different facts: one says the selector was
    /// applied and the capture does not carry what deciding needs, the other
    /// says this row carries nothing the record plane judges at all — a
    /// handshake, a declaration. A reader chasing "why did my filter miss
    /// this" needs to know which, because only the first is about the filter.
    ///
    /// ⚠ THE FIXTURE PRODUCES ALL FOUR WITHOUT BEING ASKED TO, which is what
    /// makes this gradeable rather than staged: its Inits and its Declare are
    /// unjudged, its Pushes with an unresolved keyexpr are undecided under a
    /// `key` selector, and its three payload sizes split yes from no under a
    /// `bytes` one.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_field_documents_selection_words_do_not_collapse_into_one_absence() {
        let (d, file) = crate::agg::tests::multilink_session_with_file();
        let count = |doc: &str, word: &str| {
            doc.matches(&alloc::format!("\"selected\":\"{word}\""))
                .count()
        };

        // A `key` selector: the resolved row answers, the unresolved ones
        // cannot, and the transport-only rows were never asked.
        let by_key = fields_json_where(
            &d,
            &file,
            None,
            None,
            &crate::filter::Filter::parse("key == demo/temp").expect("parses"),
        );
        assert!(
            count(&by_key, "yes") > 0,
            "the resolved row must answer: {by_key}"
        );
        assert!(
            count(&by_key, "undecided") > 0,
            "a row whose keyexpr never bound was ASKED and could not answer: \
             {by_key}"
        );
        assert!(
            count(&by_key, "unjudged") > 0,
            "and a row the record plane never walked was not asked at all -- \
             folding this into `undecided` is the collapse this test forbids: \
             {by_key}"
        );

        // A `bytes` selector reaches the same rows on an axis that does not
        // depend on resolution, so the misses here are misses and not gaps.
        let by_size = fields_json_where(
            &d,
            &file,
            None,
            None,
            &crate::filter::Filter::parse("bytes > 6").expect("parses"),
        );
        assert!(
            count(&by_size, "no") > 0,
            "a row that was asked and did not match: {by_size}"
        );

        // AND THE ABSENT KEY IS THE FOURTH ANSWER. A document rendered with no
        // selector must not say `unjudged` about every row -- that would be a
        // verdict where none was sought.
        let plain = fields_json(&d, &file, None, None);
        assert_eq!(
            count(&plain, "yes")
                + count(&plain, "no")
                + count(&plain, "undecided")
                + count(&plain, "unjudged"),
            0,
            "a document given no selector says NOTHING about selection: {plain}"
        );
    }

    /// R2765 (open debt 788) — TWO STREAM FLOWS, WHOSE FIRST MESSAGES SIT AT
    /// THE SAME OFFSET, get their OWN verdicts.
    ///
    /// # Why this fixture exists, and it is a finding rather than a flourish
    ///
    /// The round's first damage probe on this axis CAME BACK GREEN: removing
    /// the list index from the join key reddened nothing. The reason is
    /// structural and was invisible until it was measured — the other fixture
    /// is all datagram, and a datagram row's anchor is built from a PACKET
    /// INDEX, which is unique across the whole capture. The list index adds
    /// nothing there, so no datagram capture can grade it.
    ///
    /// A STREAM anchor is a byte offset within its own direction's stream, so
    /// the first message of flow one and the first message of flow two both
    /// sit at zero. That collision is the whole hazard, and it takes two
    /// stream flows to build.
    ///
    /// ⚠ THE TWO PAYLOADS DIFFER IN SIZE ON PURPOSE. Same-size payloads would
    /// make both rows answer alike, and a key that merged them would be
    /// indistinguishable from one that did not.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn two_stream_flows_at_the_same_offset_do_not_share_a_verdict() {
        use crate::census_json::fed_tests::framed_frame;
        use crate::datagram_tests::{push, sender_space, tcp_packet_on};

        let small = push(sender_space(1, Some("demo/a")), b"xx");
        let big = push(sender_space(1, Some("demo/b")), b"xxxxxxxxxxxx");

        let mut d = Dissection::new();
        // Two flows, each carrying ONE message, each at stream offset 0 of
        // direction A. Different source ports make them two flows; the
        // identical offset is what the key has to survive.
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &tcp_packet_on(40001, 0, &framed_frame(0, &small)),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet_on(40002, 0, &framed_frame(0, &big)),
        );
        d.finish();
        let file = crate::pcap::write(LINKTYPE_ETHERNET, &[]);

        let doc = fields_json_where(
            &d,
            &file,
            None,
            None,
            &crate::filter::Filter::parse("bytes > 6").expect("parses"),
        );

        let yes = doc.matches("\"selected\":\"yes\"").count();
        let no = doc.matches("\"selected\":\"no\"").count();
        assert_eq!(
            (yes, no),
            (1, 1),
            "one flow's message is over the bound and the other's is under, so \
             the two rows must answer DIFFERENTLY -- a key that merged them \
             would give both the same word: {doc}"
        );
    }

    /// Folded into one `"keyexpr":null`, a reader cannot tell a capture that
    /// started late from a genuine gap and searches the wrong thing. That is
    /// the consumer's own sentence, and it is why the second half is asserted
    /// as hard as the first.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_session_resolves_across_its_links_in_the_field_document() {
        let (d, file) = crate::agg::tests::multilink_session_with_file();
        let doc = fields_json(&d, &file, None, None);
        let pairs = carried_keys(&doc);
        assert!(
            !pairs.is_empty(),
            "the document rendered no carried entry at all, so nothing below \
             could have failed: {doc}"
        );

        // (1) THE SECOND LINK'S REFERENCE RESOLVED. The declaration went out on
        // port 43210 and the `Push` that names id 7 went out on 43211, so a
        // per-flow space cannot produce this literal on the second flow.
        let resolved = pairs
            .iter()
            .filter(|(key, _)| *key == "\"demo/temp\"")
            .count();
        assert!(
            resolved >= 2,
            "the declaration on link 1 names `demo/temp` and the reference on \
             link 2 must resolve to it as well, so the literal stands on TWO \
             entries; it stands on {resolved}: {pairs:?}"
        );

        // (2) AND THE REST SAY WHY, each arm with a population that is not
        // empty. id 9 was referenced on a link of a KNOWN session that declared
        // nothing for it; id 7 was referenced again on a third flow that never
        // handshook — the SAME id the session bound, which is exactly the
        // reference a grouping leaking across sessions would have resolved.
        let no_declaration = pairs
            .iter()
            .filter(|(key, cause)| *key == "null" && *cause == "\"no_declaration\"")
            .count();
        let no_session = pairs
            .iter()
            .filter(|(key, cause)| *key == "null" && *cause == "\"no_session\"")
            .count();
        assert_eq!(
            (no_declaration, no_session),
            (1, 1),
            "one reference of each kind, and DISTINGUISHED: {pairs:?}"
        );

        // The two columns never contradict: an entry that names a key does not
        // also carry a reason it has none. `(null, null)` is NOT in that class
        // and is the ordinary majority — a `KeepAlive` or an `Init` references
        // no keyexpr, so there is nothing to resolve and nothing to explain.
        let contradictory: Vec<&(&str, &str)> = pairs
            .iter()
            .filter(|(key, cause)| *key != "null" && *cause != "null")
            .collect();
        assert!(
            contradictory.is_empty(),
            "an entry names a key AND a reason it has none: {contradictory:?}"
        );
        // AND the quiet majority is not the whole document: without this the
        // assertion above holds over a population where every pair is
        // `(null, null)`, which is what a build that emitted the key and never
        // filled it would produce.
        assert!(
            pairs
                .iter()
                .any(|(key, cause)| *key != "null" || *cause != "null"),
            "every entry is (null, null), so nothing above was measured: {pairs:?}"
        );
    }

    /// R2513 (open-debt item 713) — the acceptance above on the axis it cannot
    /// reach: WHEN the id resolves, not merely WHERE.
    ///
    /// Its capture declares on the link this crate walks FIRST, so it is
    /// satisfied by a walk in list order and by one in capture order alike. This
    /// one declares on the link walked SECOND, two packets BEFORE the reference
    /// -- so `demo/temp` is what the session's own bytes say, and
    /// `"keyexpr_cause":"no_declaration"` is a statement about the session that
    /// the session contradicts.
    ///
    /// The document is GROUPED BY FLOW, which is why this is not the same fix
    /// the folds took: `crate::agg`, `crate::payload`, `crate::interest` and
    /// `crate::exchange` simply changed the order they walk in, and a renderer
    /// cannot -- its rows have to come out per flow. So resolution is separated
    /// from rendering instead.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_reference_resolves_against_the_later_links_declaration_in_the_field_document() {
        let (d, file) =
            crate::agg::tests::multilink_session_declaring_on_the_later_link_carrying_with_file(
                crate::agg::tests::push_for_item_713(),
            );
        let doc = fields_json(&d, &file, None, None);
        let pairs = carried_keys(&doc);
        assert!(
            !pairs.is_empty(),
            "the document rendered no carried entry at all, so nothing below \
             could have failed: {doc}"
        );
        // TWO, not "at least one". MEASURED: with the defect present the
        // literal already stands on ONE entry -- the `DeclKexpr` itself, which
        // carries `demo/temp` inline and resolves through no table at all. An
        // `any()` here passes on that entry alone and grades nothing, which is
        // what the first draft of this guard did. The SECOND is the reference.
        assert_eq!(
            pairs
                .iter()
                .filter(|(key, _)| *key == "\"demo/temp\"")
                .count(),
            2,
            "the declaration names the topic inline and the reference must \
             resolve to the same literal, so it stands on TWO entries: {pairs:?}"
        );
        assert_eq!(
            pairs
                .iter()
                .filter(|(_, cause)| *cause == "\"no_declaration\"")
                .count(),
            0,
            "and nothing is left claiming the session declared nothing: {pairs:?}"
        );
    }

    /// R2513 (open-debt item 713) — THE OTHER HALF, and the one that makes the
    /// guard above safe: a declaration that went out AFTER a reference must
    /// still not name it.
    ///
    /// This document now absorbs the whole capture before rendering a row,
    /// because a flow-grouped document cannot get `crate::agg`'s "one pass, in
    /// capture order" rule from its walk. Absorbing everything up front is
    /// precisely the retroactive naming that module weighed and refused — unless
    /// each binding carries the packet it went past at and each row resolves at
    /// its own. That is the whole content of
    /// `crate::agg::KeyexprSpaces::at_packet`, and this is where it is graded:
    /// with it, `id 7` is unbound when this reference travels; without it, the
    /// pre-pass has already bound it and the row would name `demo/temp`.
    ///
    /// A pair, then, not a single claim. The guard above says a reader now sees
    /// a declaration the OTHER LINK carried; this one says it still does not see
    /// one from the FUTURE.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_declaration_that_followed_a_reference_still_does_not_name_it() {
        let (d, file) =
            crate::agg::tests::multilink_session_declaring_after_the_reference_with_file();
        let doc = fields_json(&d, &file, None, None);
        let pairs = carried_keys(&doc);
        assert!(
            !pairs.is_empty(),
            "the document rendered no carried entry at all: {doc}"
        );
        // ONE `demo/temp`: the declaration's own inline literal, which consults
        // no table. The reference must NOT have become a second one.
        assert_eq!(
            pairs
                .iter()
                .filter(|(key, _)| *key == "\"demo/temp\"")
                .count(),
            1,
            "the declaration names the topic inline; the reference that PRECEDED \
             it must not be named by it: {pairs:?}"
        );
        assert_eq!(
            pairs
                .iter()
                .filter(|(key, cause)| *key == "null" && *cause == "\"no_declaration\"")
                .count(),
            1,
            "and the reference says why, on the session's own terms: {pairs:?}"
        );
    }

    /// THE PROPERTY THE PER-FLOW RULE PROTECTED, kept in this document: a flow
    /// whose session is unknown still resolves its OWN declarations.
    ///
    /// The fallback is not "give up", it is "the pre-R2458 reach". Without this
    /// the `no_session` arm above would be satisfied by a build that had simply
    /// stopped resolving on unattributed flows — a regression wearing the new
    /// word as a costume.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_field_row_on_a_handshakeless_flow_still_resolves_its_own_declaration() {
        let (d, file) = crate::agg::tests::orphan_flow_session_with_file();
        let doc = fields_json(&d, &file, None, None);
        let pairs = carried_keys(&doc);
        let resolved = pairs
            .iter()
            .filter(|(key, _)| *key == "\"orphan/topic\"")
            .count();
        assert!(
            resolved >= 2,
            "the flow declared `orphan/topic` and referenced it, and both \
             entries must name it: {pairs:?} in {doc}"
        );
        assert!(
            pairs.iter().all(|(_, cause)| *cause == "null"),
            "nothing on this flow is unresolved, so no entry says why: {pairs:?}"
        );
    }

    /// R2100 (open-debt item 509) — THE FIELD DOCUMENT'S KEY SET IS PINNED
    /// AGAINST ITS REVISION.
    ///
    /// The census document got this at R311y923 and this one did not, which is
    /// half of what item 509 measured: `fields_json.rs` was named in the same
    /// breath as `census_json.rs` and had neither a revision nor a pin. A
    /// consumer of `wz_dissect_pcap_fields` had no way to be told a key had
    /// moved and the author had nothing that would notice.
    ///
    /// # The fixture is the RICH one, on purpose
    ///
    /// `census_json::tests::every_plane_capture_with_file` carries declares,
    /// interests, a Put, a Query and its closing Reply — so the document it
    /// produces reaches the row renderers rather than one KeepAlive's worth of
    /// them. A pin taken over a thin capture silently stops covering every key
    /// that capture never reaches, which is a gate that reads green while the
    /// keys it was written for go unwatched.
    ///
    /// ⚠ R2175 (open-debt item 552) — THE `declarations: None` READING WAS
    /// WRONG, and it is corrected here rather than argued with.
    ///
    /// This test used to drive the mapping argument as `None`, on the note that
    /// "a payload map is the operator's input, not the capture's, and the keys
    /// it adds belong to a revision that declares them". The first half is
    /// true; the second described something that had not happened. MEASURED:
    /// with a mapping supplied the document gains fifteen keys —
    /// `payload_decode`, `state`, `descriptor_bytes`, `under`, `wrong` and the
    /// rest — and revision 1 declared not one of them. So the subtree was
    /// emitted to consumers, pinned by nothing, and two rounds (R2025 item 285,
    /// R2170 item 546) added keys to it with no number moving. The pin's own
    /// paragraph above — "a pin taken over a thin capture silently stops
    /// covering every key that capture never reaches" — was true of this test.
    ///
    /// Both branches now, which is `wz-capi-dissect`'s ruling for the two
    /// verdict documents applied here: a pin over one branch leaves the other's
    /// keys unwatched, and that is a gate reading green over half a contract.
    /// The union is compared against `newest`, not against `FIELDS_R1_KEYS` by
    /// name — R2123's correction on the census, which this test had not had.
    ///
    /// Gated on `network-codecs` because the fixture is: without the decoders a
    /// Push inside a frame is an unknown MID, so the document would be pinned
    /// over a capture whose rows never rendered — a pin taken on a shape that
    /// only exists in that build.
    #[cfg(feature = "network-codecs")]
    /// R2211 (open-debt item 565) — THE MARKER NAMES REACH THE FIELD DOCUMENT,
    /// and this is the half of that item that was already true.
    ///
    /// # Why nobody could see it
    ///
    /// Item 565 was filed as "the `First` / `Drop` markers do not go out to the
    /// consumption surface", on a sweep that read `fields_json.rs`,
    /// `census_json.rs` and `doc_revision.rs` for the words. Neither emitter
    /// spells them and no document key is named for them, so the sweep found an
    /// absence — and the names were arriving all along, from
    /// `ext_name::FRAGMENT`'s rows (`0x2 -> "first"`, `0x3 -> "drop"`) through
    /// `dissect::walk_ext_entry`, which pushes the row's name as an `ext_name`
    /// FIELD. A value, in a tree, produced by a table one crate over: the one
    /// shape a grep for the word cannot reach.
    ///
    /// So this test exists to make the fact ASKABLE rather than re-derivable.
    /// The half that genuinely had no surface — what the markers CAUSED — is
    /// the census's `fragment_chains` object, added the same round.
    ///
    /// # The control
    ///
    /// The same fixture with no ext chain at all. It must render neither name,
    /// or this test would pass on a document that names every extension it has
    /// ever heard of regardless of what the capture carried.
    /// R2706 — A COMPLETED CHAIN'S RECORDS REACH THIS DOCUMENT, WITH NO OFFSET.
    ///
    /// The reporting consumer measured the gap this closes: 85 of 99 rows in
    /// its frozen capture were `Fragment`s, the census attributed the 5 `Push`es
    /// those chains carried (`unlocatable_records = 5`), and the field document
    /// had no row from which a reader could learn that any of them happened.
    /// Not an empty answer — an absent one, which a consumer cannot tell from
    /// "this traffic carried nothing".
    ///
    /// # What is asserted, and what deliberately is not
    ///
    /// That the record arrives NAMED, with its key, and with its location
    /// declared absent rather than fabricated. The span is NOT asserted to be
    /// anything, because there is nothing in the capture for it to be: the
    /// buffer those bytes were joined in exists only inside the reader, and
    /// `PassiveFrame::batch_offset`'s own doc gives the rule this follows —
    /// "handing out the buffer's offset is how a fabricated coordinate gets
    /// read as a measured one". `a_reassembled_record_declines_the_offset it
    /// never had` is the same verdict one plane over, where the selector
    /// answers `undecided`.
    ///
    /// # The control
    ///
    /// The same record contiguous on the wire. It must name the `Push` too, or
    /// this test would pass on an emitter that prints the word for every
    /// capture; and its entry must carry a span, or "the location is absent"
    /// would be this document's answer everywhere and say nothing here.
    #[cfg(all(feature = "reassembly", feature = "network-codecs"))]
    #[test]
    fn a_completed_chains_records_are_named_in_the_field_document() {
        use crate::datagram_tests::{push, sender_space};
        let record = push(sender_space(0, Some("split/across")), &[0u8; 8]);
        let (d, file) = crate::datagram_tests::reassembled_record_dissection_with_file(&record);

        // ANTI-VACUITY: the chain really completed, measured by the plane that
        // already answers for it. Without this, a capture whose fragments never
        // joined would leave the assertion below with no subject.
        let census = crate::agg::aggregate(&d);
        assert_eq!(
            census.records(),
            1,
            "the fragment chain must complete, or this fixture is not the subject"
        );

        // `(message, keyexpr)` off the same `object_scopes` walk `carried_keys`
        // uses, rather than a `doc.contains`: a substring would be satisfied by
        // the word appearing anywhere in the document, including inside the
        // `fields` tree of a row that carried nothing.
        // `top_level_entries` hands back the RAW value slice, quotes included,
        // so the words are unquoted here rather than compared against quoted
        // literals -- which would read as a typo the first time one was wrong.
        let named = |doc: &str| -> Vec<(String, String)> {
            let unquote = |v: &str| v.trim_matches('"').to_string();
            crate::doc_revision::object_scopes(doc)
                .into_iter()
                .filter_map(|scope| {
                    let message = scope.iter().find(|(k, _)| *k == "message")?.1;
                    let key = scope.iter().find(|(k, _)| *k == "keyexpr")?.1;
                    Some((unquote(message), unquote(key)))
                })
                .collect()
        };

        let doc = fields_json(&d, &file, None, None);
        let pairs = named(&doc);
        assert!(
            pairs.iter().any(|(m, _)| m == "Push"),
            "the record a completed chain carried must be NAMED in the field \
             document; the census attributes it and this document did not \
             mention it: {doc}"
        );
        assert!(
            pairs
                .iter()
                .any(|(m, k)| m == "Push" && k == "split/across"),
            "and it must carry the key it travelled under: {doc}"
        );

        // THE CONTROL: the same session and the same record, carried in ONE
        // frame. It must name the Push under the ORDINARY `carried` of a walked
        // row -- so the claim above is about a chain rather than about an
        // emitter that prints the word for every capture -- and its row must
        // report `carried_state: batch`, which is what makes `reassembled` a
        // measured verdict rather than this document's only answer.
        let (contiguous, control_file) =
            crate::datagram_tests::contiguous_record_dissection_with_file(&record);
        let control = fields_json(&contiguous, &control_file, None, None);
        assert!(
            named(&control).iter().any(|(m, _)| m == "Push"),
            "the control must name the Push: {control}"
        );
        assert!(
            control.contains("\"carried_state\":\"batch\""),
            "the control's frame must report the ordinary batch state: {control}"
        );
        assert!(
            !control.contains("\"carried_state\":\"reassembled\""),
            "and nothing in it was reassembled: {control}"
        );
    }

    /// R2706 — A BODY THE SESSION COULD NOT DECOMPRESS SAYS SO.
    ///
    /// The reporting consumer asked what this document does with a `Frame` on a
    /// session that negotiated compression, and said it could not produce such
    /// a capture to find out. This tree has had one since R311y621; what it did
    /// not have was this document rendered over it.
    ///
    /// The answer WAS: `dissect_batch` carries no lz4 (`grep -ci decompress`
    /// over `dissect.rs` answers 0), so it walked the compressed bytes and
    /// halted at whatever record first failed — reporting a MID word that a
    /// reader cannot tell apart from one this build's wire vintage genuinely
    /// does not know. The bytes were there and unreadable, and the document
    /// said something else.
    ///
    /// The answer IS `undecompressible`, from the session that negotiated the
    /// compression and knows.
    ///
    /// # The control
    ///
    /// The same shape of session WITHOUT the compression offer. Its frame must
    /// report `batch`, or this test would pass on a document that says
    /// `undecompressible` about every frame it cannot walk.
    #[test]
    fn a_body_the_session_could_not_decompress_says_so_in_the_field_document() {
        let (d, file) = crate::datagram_tests::compressed_session_dissection_with_file();
        let doc = fields_json(&d, &file, None, None);
        assert!(
            doc.contains("\"carried_state\":\"undecompressible\""),
            "a frame whose body the session could not open must say so: {doc}"
        );
        // AND THE WALK FABRICATED NOTHING, which is the half of the consumer's
        // question that was about damage rather than absence: "it walks the
        // compressed bytes and reports whatever records fall out of them" would
        // be worse than silence.
        //
        // ZA-3215 ⑤ — the batch is now in upstream's shape, header byte first,
        // and the session stands ONE record for the whole unopened batch. The
        // second walk over those wire bytes must DECLINE rather than name a
        // tree: they are a header and lz4, not a message.
        assert!(
            doc.contains("\"declined\":"),
            "the row over an unopened lz4 batch must be declined: {doc}"
        );
        assert!(
            !doc.contains("\"message\":\"Push\"") && !doc.contains("\"message\":\"Declare\""),
            "and it must invent no network record out of compressed bytes: {doc}"
        );

        // THE CONTROL: the same handshake without the offer, carrying a record
        // this build CAN read.
        let record = crate::datagram_tests::push(
            crate::datagram_tests::sender_space(0, Some("plain/text")),
            &[0u8; 8],
        );
        let (plain_d, plain_file) =
            crate::datagram_tests::contiguous_record_dissection_with_file(&record);
        let control = fields_json(&plain_d, &plain_file, None, None);
        assert!(
            control.contains("\"carried_state\":\"batch\""),
            "the control's frame must read as an ordinary batch: {control}"
        );
        assert!(
            !control.contains("\"carried_state\":\"undecompressible\""),
            "and nothing in it was undecompressible: {control}"
        );
    }

    /// An lz4 BLOCK holding `bytes` as one literal run, and nothing else.
    ///
    /// Written from the block format rather than produced by `lz4_flex`, so the
    /// input these tests hand the reader does not come from the library that
    /// reads it: a token whose high nibble is the literal length (15 meaning
    /// "more follows, in 255-steps"), then the literals. A block that ends in a
    /// literal run is the format's own required tail, so this is a complete and
    /// valid block — larger than its input, which upstream would never SEND
    /// (it keeps the raw form then) and which a receiver decodes all the same.
    fn lz4_literal_block(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let n = bytes.len();
        if n < 15 {
            out.push((n as u8) << 4);
        } else {
            out.push(0xF0);
            let mut rest = n - 15;
            while rest >= 255 {
                out.push(255);
                rest -= 255;
            }
            out.push(rest as u8);
        }
        out.extend_from_slice(bytes);
        out
    }

    /// ZA-3215 ⑤ — A COMPRESSION-NEGOTIATED LINK PUTS A BATCH HEADER IN FRONT
    /// OF EVERY BATCH, and the reader must strip it before it reads a message.
    ///
    /// Upstream: once a side has sent its `Open`, every batch it sends on a
    /// link that negotiated compression is `[BatchHeader][payload]`, and bit 0
    /// of the header says whether the WHOLE payload is lz4:
    ///
    /// `io/zenoh-transport/src/common/batch.rs` @ `let zslice = self.decompress(p, buff)?;`
    ///
    /// This is the bit-CLEAR arm: the payload is the batch as it would otherwise be,
    /// so the record must be read with no lz4 in the build at all. Reading the
    /// header byte as a transport MID is the failure this names.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_raw_batch_behind_a_clear_batch_header_is_read_as_the_batch() {
        let record = crate::datagram_tests::push(
            crate::datagram_tests::sender_space(0, Some("zip/raw")),
            &[1u8; 8],
        );
        let mut unit = alloc::vec![0x00u8];
        unit.extend_from_slice(&crate::datagram_tests::frame_datagram(&record));
        let (d, file) = crate::datagram_tests::compressed_session_with_unit(unit);
        let doc = fields_json(&d, &file, None, None);
        assert_eq!(
            scoped(&doc, "message", &["message", "keyexpr"])
                .iter()
                .filter(|e| e[..] == ["Push", "zip/raw"])
                .count(),
            1,
            "the Push behind a clear batch header must be read: {doc}"
        );
    }

    /// ZA-3215 ⑤ — AND THE BIT-SET ARM: the whole batch is lz4, and a build
    /// with `compression` reads the records inside it, while a build without
    /// says `undecompressible` and invents nothing.
    ///
    /// The body is a literal-only lz4 block built from the format, see
    /// [`lz4_literal_block`].
    #[cfg(feature = "network-codecs")]
    #[test]
    fn an_lz4_batch_is_read_when_this_build_has_lz4_and_named_when_it_does_not() {
        let record = crate::datagram_tests::push(
            crate::datagram_tests::sender_space(0, Some("zip/ped")),
            &[2u8; 8],
        );
        let mut unit = alloc::vec![0x01u8];
        unit.extend_from_slice(&lz4_literal_block(&crate::datagram_tests::frame_datagram(
            &record,
        )));
        let (d, file) = crate::datagram_tests::compressed_session_with_unit(unit);
        let doc = fields_json(&d, &file, None, None);
        let pushes = scoped(&doc, "message", &["message", "keyexpr"])
            .iter()
            .filter(|e| e[..] == ["Push", "zip/ped"])
            .count();
        if cfg!(feature = "compression") {
            assert_eq!(
                pushes, 1,
                "lz4 is in this build, so the Push is read: {doc}"
            );
            assert!(
                !doc.contains("\"carried_state\":\"undecompressible\""),
                "{doc}"
            );
        } else {
            assert_eq!(pushes, 0, "no lz4 here, so nothing is read: {doc}");
            assert!(
                doc.contains("\"carried_state\":\"undecompressible\""),
                "and the row says why: {doc}"
            );
        }
    }

    #[cfg(feature = "reassembly")]
    #[test]
    fn a_fragments_chain_boundary_markers_are_named_in_the_field_document() {
        let (d, file) =
            crate::datagram_tests::marked_fragment_dissection_with_file(&[(0, true, true, true)]);
        let doc = fields_json(&d, &file, None, None);
        assert!(
            doc.contains("\"first\""),
            "the `0x2 First` marker must reach the field document by NAME: {doc}"
        );
        assert!(doc.contains("\"drop\""), "and so must `0x3 Drop`: {doc}");

        let (plain, plain_file) =
            crate::datagram_tests::marked_fragment_dissection_with_file(&[(0, true, false, false)]);
        let control = fields_json(&plain, &plain_file, None, None);
        assert!(
            !control.contains("\"first\"") && !control.contains("\"drop\""),
            "a Fragment carrying no ext chain must name neither, or the \
             assertion above is about the emitter's vocabulary rather than \
             about this capture: {control}"
        );
    }

    /// ZA-3215 — the row and flow objects revision 14 added, RENDERED FROM
    /// THEIR OWN TYPES, one per word.
    ///
    /// The rule `the_field_documents_payload_plane_is_pinned_over_every_arm`
    /// states, applied to five new families: no one capture reaches every SN
    /// verdict, every router outcome and reason, every band and every phase,
    /// and a fixture that stopped reaching one would take that word out of the
    /// pinned population in silence. Each walk is bound to an exhaustive
    /// match, so a variant added later joins here at `cargo build`.
    fn session_arms() -> Vec<String> {
        use wz_session_core::passive::{FlowContext, SessionPhase};
        use wz_session_core::qos::Priority;
        let mut arms = Vec::new();
        let mut verdict = Some(SnVerdictWord::Baseline);
        let mut band = 0u8;
        while let Some(word) = verdict {
            // Every band too, cycled across the verdicts and then finished off
            // below, so both walks are rendered in full.
            let row = SessionRow {
                sn: Some(SnRow {
                    verdict: word,
                    missing: matches!(word, SnVerdictWord::Gap).then_some(1),
                    direction: Direction::A,
                    priority: Priority::from_wire(band),
                    reliable: true,
                }),
                chain: None,
            };
            let mut out = String::new();
            push_session_row(&row, &mut out);
            arms.push(out);
            band += 1;
            verdict = word.next();
        }
        while usize::from(band) < Priority::NUM {
            let mut out = String::new();
            push_session_row(
                &SessionRow {
                    sn: Some(SnRow {
                        verdict: SnVerdictWord::Continuous,
                        missing: None,
                        direction: Direction::B,
                        priority: Priority::from_wire(band),
                        reliable: false,
                    }),
                    chain: None,
                },
                &mut out,
            );
            arms.push(out);
            band += 1;
        }
        let mut outcome = Some(ChainOutcome::Aborted);
        while let Some(word) = outcome {
            let mut out = String::new();
            push_session_row(
                &SessionRow {
                    sn: None,
                    chain: Some(ChainRow {
                        outcome: word,
                        reason: None,
                        chain_id: Some(0),
                    }),
                },
                &mut out,
            );
            arms.push(out);
            outcome = word.next();
        }
        let mut reason = Some(ChainReason::CapacityOverflow);
        while let Some(word) = reason {
            let mut out = String::new();
            push_session_row(
                &SessionRow {
                    sn: None,
                    chain: Some(ChainRow {
                        outcome: ChainOutcome::Aborted,
                        reason: Some(word),
                        chain_id: None,
                    }),
                },
                &mut out,
            );
            arms.push(out);
            reason = word.next();
        }
        // The phases are the session's own enum, so they are listed here and
        // held to the word walk by COUNT: a sixth `SessionPhase` fails
        // `phase_word`'s match, and a sixth word fails this assertion.
        let phases = [
            SessionPhase::Unseen,
            SessionPhase::HalfInit,
            SessionPhase::InitComplete,
            SessionPhase::Established,
            SessionPhase::Closed,
        ];
        assert_eq!(phases.len(), PhaseWord::names().len());
        for phase in phases {
            let mut out = String::new();
            push_context(
                &FlowContext {
                    phase,
                    ..FlowContext::default()
                },
                &mut out,
            );
            arms.push(out);
        }
        let mut out = String::new();
        push_first_byte(
            Some(FirstByte {
                packet: 0,
                payload_offset: 0,
            }),
            None,
            &mut out,
        );
        push_l2(Some(([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])), &mut out);
        arms.push(out);
        arms
    }

    /// Every object in `doc` carrying `key`, each read as the values of
    /// `fields` in that order, quotes stripped. `object_scopes` reads each
    /// object at its OWN depth, so a key is never credited to the object it is
    /// nested in.
    fn scoped<'a>(doc: &'a str, key: &str, fields: &[&str]) -> Vec<Vec<&'a str>> {
        crate::doc_revision::object_scopes(doc)
            .into_iter()
            .filter(|scope| scope.iter().any(|(k, _)| *k == key))
            .map(|scope| {
                fields
                    .iter()
                    .map(|f| {
                        scope
                            .iter()
                            .find(|(k, _)| k == f)
                            .map_or("<absent>", |(_, v)| v.trim_matches('"'))
                    })
                    .collect()
            })
            .collect()
    }

    /// ZA-3215 ① — EVERY FRAGMENT ROW NAMES WHAT THE ROUTER DID WITH IT, and
    /// the rows of one chain share one identity.
    ///
    /// The sequence is chosen so each outcome the router reaches on a live
    /// chain arrives once, and so the identity is exercised across the one
    /// transition that makes it non-trivial: a `First` restart ends chain 0
    /// WITHOUT a row of its own, so an identity that followed rows rather than
    /// the router's key would run the two chains together.
    ///
    /// The SN half rides the same capture: the refused fragment is still
    /// numbered by its sender, so skipping sn 4 is a gap of one on the SAME
    /// conduit the others were judged on — the router refusing a fragment and
    /// the SN tracker counting it are two verdicts about one frame.
    #[cfg(feature = "reassembly")]
    #[test]
    fn each_fragment_row_names_its_chains_outcome_and_identity() {
        let (d, file) = crate::datagram_tests::marked_fragment_dissection_with_file(&[
            // (sn, more, first, drop)
            (0, true, true, false),
            (1, true, false, false),
            (2, true, true, false),
            (3, true, false, true),
            (5, true, false, false),
        ]);
        let doc = fields_json(&d, &file, None, None);
        assert_eq!(
            scoped(&doc, "outcome", &["outcome", "reason", "chain_id"]),
            alloc::vec![
                alloc::vec!["begun", "null", "0"],
                alloc::vec!["continued", "null", "0"],
                alloc::vec!["begun", "null", "1"],
                alloc::vec!["aborted", "sender_dropped", "1"],
                alloc::vec!["refused", "missing_start_marker", "null"],
            ],
            "{doc}"
        );
        assert_eq!(
            scoped(&doc, "verdict", &["verdict", "missing"]),
            alloc::vec![
                alloc::vec!["baseline", "null"],
                alloc::vec!["continuous", "null"],
                alloc::vec!["continuous", "null"],
                alloc::vec!["continuous", "null"],
                alloc::vec!["gap", "1"],
            ],
            "{doc}"
        );
        // The conduit is the one the fixture's fragments were sent on: the `R`
        // flag set, no `ext_qos` (so the upstream default band), from the low
        // endpoint.
        let conduits = scoped(&doc, "reliable", &["direction", "priority", "reliable"]);
        assert_eq!(conduits.len(), 5, "{doc}");
        for conduit in &conduits {
            assert_eq!(
                conduit,
                &alloc::vec!["a", wz_session_core::qos::Priority::DEFAULT.name(), "true"],
                "{doc}"
            );
        }
        // And the handshake rows, which carry no SN and touched no chain, say
        // so as `null` rather than by omitting the key.
        assert!(
            doc.matches("\"sn\":null,\"chain\":null").count() >= 4,
            "the four handshake rows must carry both keys as null: {doc}"
        );
    }

    /// ZA-3215 ① — AND A COMPLETED CHAIN CLOSES UNDER THE IDENTITY IT BEGAN
    /// WITH, while a chain the capture stopped inside is counted by the
    /// top-level `reassembly` group, which is the only place a chain with no
    /// closing row can be accounted for.
    #[cfg(all(feature = "reassembly", feature = "network-codecs"))]
    #[test]
    fn a_completed_chain_closes_under_its_identity_and_an_open_one_is_counted() {
        use crate::datagram_tests::{push, sender_space};
        let record = push(sender_space(0, Some("split/across")), &[0u8; 8]);
        let (d, file) = crate::datagram_tests::reassembled_record_dissection_with_file(&record);
        let doc = fields_json(&d, &file, None, None);
        assert_eq!(
            scoped(&doc, "outcome", &["outcome", "chain_id"]),
            alloc::vec![alloc::vec!["begun", "0"], alloc::vec!["reassembled", "0"]],
            "{doc}"
        );
        assert_eq!(
            scoped(&doc, "abandoned_at_end", &["abandoned_at_end"]),
            alloc::vec![alloc::vec!["0"]],
            "{doc}"
        );

        let (mut open, open_file) =
            crate::datagram_tests::marked_fragment_dissection_with_file(&[(0, true, true, false)]);
        // The fixture feeds packets and stops; ending the capture is the
        // caller's verb, and it is where a still-open chain is booked. Every
        // door that reads a whole file calls it.
        open.finish();
        assert!(
            open.abandoned_chains() >= 1,
            "the fixture must leave a chain open at the end, or the count below \
             has no subject"
        );
        let open_doc = fields_json(&open, &open_file, None, None);
        assert_eq!(
            scoped(&open_doc, "abandoned_at_end", &["abandoned_at_end"]),
            alloc::vec![alloc::vec![
                alloc::format!("{}", open.abandoned_chains()).as_str()
            ]],
            "{open_doc}"
        );
    }

    /// ZA-3215 ③ — THE FLOW SAYS WHAT ITS HANDSHAKE NEGOTIATED, and a flow
    /// whose handshake this capture never saw says THAT rather than reporting
    /// the `&=` fold's starting `true` as an agreement.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_flows_context_is_its_negotiation_and_null_where_none_was_seen() {
        let (d, file) =
            crate::datagram_tests::marked_fragment_dissection_with_file(&[(0, true, true, false)]);
        let doc = fields_json(&d, &file, None, None);
        let fields = [
            "phase",
            "negotiated",
            "lowlatency",
            "compression",
            "qos",
            "sn_mask",
        ];
        let context = scoped(&doc, "phase", &fields);
        assert_eq!(context.len(), 1, "one flow, one context: {doc}");
        let mask = d.datagram_flows()[0]
            .session
            .context()
            .sn_mask()
            .expect("the fixture's InitAck names a resolution");
        assert_eq!(context[0][0], "established", "{doc}");
        assert_eq!(context[0][1], "true", "{doc}");
        assert_eq!(context[0][5], alloc::format!("{mask}"), "{doc}");
        for capability in &context[0][2..5] {
            assert!(
                *capability == "true" || *capability == "false",
                "a negotiated capability is a boolean: {doc}"
            );
        }

        let (unseen, unseen_file) =
            crate::datagram_tests::midsession_fragment_dissection_with_file();
        let unseen_doc = fields_json(&unseen, &unseen_file, None, None);
        let context = scoped(&unseen_doc, "phase", &fields);
        assert!(!context.is_empty(), "{unseen_doc}");
        for flow in &context {
            assert_eq!(
                flow,
                &alloc::vec!["unseen", "false", "null", "null", "null", "null"],
                "no Init was seen, so nothing was agreed: {unseen_doc}"
            );
        }
    }

    /// ZA-3215 ④ — A STREAM ROW NAMES THE PACKET HOLDING ITS FIRST BYTE, and
    /// the offset it gives is the byte, read back out of the capture file.
    ///
    /// Judged against the FILE and not against this module's own arithmetic:
    /// `frame_offset` is only worth publishing if a reader holding the packet
    /// finds the message's first byte there without parsing a header. Every
    /// stream row is checked, and a length-prefixed stream puts every message
    /// at least two bytes into its segment, so a locator that ignored the
    /// prefix or the segment boundary would miss on every row.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_stream_rows_first_byte_is_the_byte_the_capture_holds_there() {
        let (d, file) =
            crate::census_json::fed_tests::every_plane_capture_with_file("demo/temp", None, false);
        let doc = fields_json(&d, &file, None, None);
        let pcap = crate::pcap::parse(&file).expect("the fixture writes a readable capture");
        let rows = scoped(
            &doc,
            "payload_offset",
            &["packet", "payload_offset", "frame_offset"],
        );
        let frames: Vec<(&crate::FlowDissection, &PassiveFrame)> = d
            .flows()
            .iter()
            .flat_map(|flow| flow.frames.iter().map(move |frame| (flow, frame)))
            .collect();
        assert!(
            frames.len() >= 2 && rows.len() >= frames.len(),
            "the stream rows lead the document, one first_byte each: {doc}"
        );
        // `l2` is the Ethernet header of the SAME packet, both addresses, row
        // by row: every stream row here carries one, so the two lists align.
        let l2 = scoped(&doc, "src", &["src", "dst"]);
        let mac = |b: &[u8]| {
            b.iter()
                .map(|x| alloc::format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        };
        for (((flow, frame), row), link) in frames.iter().zip(&rows).zip(&l2) {
            let message = flow
                .message_bytes(frame)
                .expect("every fixture message is sliceable");
            let packet: usize = row[0].parse().expect("a packet index");
            let payload_offset: usize = row[1].parse().expect("a payload offset");
            let frame_offset: usize = row[2]
                .parse()
                .expect("an Ethernet/IPv4/TCP frame is locatable");
            assert!(
                payload_offset >= frame.prefix_width,
                "a message follows its length prefix: {row:?}"
            );
            let data = &pcap.packets[packet].data;
            assert_eq!(
                data.get(frame_offset),
                message.first(),
                "row {row:?} does not point at its message's first byte"
            );
            assert_eq!(
                link,
                &alloc::vec![mac(&data[6..12]).as_str(), mac(&data[0..6]).as_str()],
                "row {row:?} names the wrong link addresses"
            );
        }
        assert_eq!(
            l2.len(),
            rows.len(),
            "every row read off Ethernet names both: {doc}"
        );
    }

    /// ZA-3601 — THE JOIN: the packet number a row names is a number the door
    /// hands a frame out for, and `frame_offset` is the message's first byte IN
    /// THAT FRAME.
    ///
    /// The two halves each have a test of their own (a row's coordinates against
    /// the capture file above, the door against the whole-file parsers in
    /// `captured_frame_tests`); this is the seam between them, and it is the
    /// only claim the consumer's bytes column stands on: it draws the frame the
    /// door returns and highlights at the offset the row gave. A door that
    /// numbered packets one way and a row that anchored another would pass both
    /// halves and fail here.
    ///
    /// Every stream row is checked, and every packet of the capture is handed
    /// out and compared with what `pcap::parse` holds for it, link header
    /// included.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_rows_packet_number_names_the_frame_the_door_hands_out() {
        let (d, file) =
            crate::census_json::fed_tests::every_plane_capture_with_file("demo/temp", None, false);
        let doc = fields_json(&d, &file, None, None);
        let pcap = crate::pcap::parse(&file).expect("the fixture writes a readable capture");
        let rows = scoped(
            &doc,
            "payload_offset",
            &["packet", "payload_offset", "frame_offset"],
        );
        let frames: Vec<(&crate::FlowDissection, &PassiveFrame)> = d
            .flows()
            .iter()
            .flat_map(|flow| flow.frames.iter().map(move |frame| (flow, frame)))
            .collect();
        assert!(
            frames.len() >= 2 && rows.len() >= frames.len(),
            "the stream rows lead the document, one first_byte each: {doc}"
        );

        for (i, packet) in pcap.packets.iter().enumerate() {
            let handed = crate::captured_frame(&file, i).expect("every packet of the capture");
            assert_eq!(handed.index, i);
            assert_eq!(
                handed.data,
                packet.data.as_slice(),
                "packet {i}: the door hands out other bytes than the capture holds"
            );
        }

        for ((flow, frame), row) in frames.iter().zip(&rows) {
            let message = flow
                .message_bytes(frame)
                .expect("every fixture message is sliceable");
            let packet: usize = row[0].parse().expect("a packet index");
            let frame_offset: usize = row[2]
                .parse()
                .expect("an Ethernet/IPv4/TCP frame is locatable");
            let handed = crate::captured_frame(&file, packet)
                .expect("the number a row names resolves against the container that made it");
            assert_eq!(
                handed.data.get(frame_offset),
                message.first(),
                "row {row:?}: the byte at frame_offset in the frame the door hands \
                 out is not the message's first byte"
            );
        }
    }

    #[test]
    fn the_field_documents_key_set_is_pinned() {
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::Declarations;
        let (d, file) =
            crate::census_json::fed_tests::every_plane_capture_with_file("demo/temp", None, false);
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let run = Declarations::new(&map);

        let mut seen: Vec<&str> = Vec::new();
        let with = fields_json(&d, &file, None, Some(&run));
        let without = fields_json(&d, &file, None, None);
        for doc in [&with, &without] {
            seen.extend(crate::doc_revision::key_set(doc));
        }
        seen.sort_unstable();
        seen.dedup();
        // A SUBSET, and the sibling test is what makes that sound: this fixture
        // reaches two of the eight decode states, so the arms it does not take
        // are pinned by `the_field_documents_payload_plane_is_pinned_over_every_arm`
        // instead. Asserting equality here would force this capture to produce
        // every arm, which is the fixture nobody can keep whole.
        let pinned: Vec<&str> = crate::doc_revision::newest(crate::doc_revision::FIELDS)
            .expect("the field document has a revision")
            .keys
            .to_vec();
        let stray: Vec<&&str> = seen.iter().filter(|k| !pinned.contains(k)).collect();
        assert!(
            stray.is_empty(),
            "the field document emits {stray:?}, which no revision declares; if that \
             is deliberate, APPEND a revision to `doc_revision::DOCUMENT_HISTORY` \
             carrying the new set — and if a key is going away, announce it in the \
             previous revision's `retiring` first"
        );
        assert!(
            seen.len() >= crate::doc_revision::FIELDS_R1_KEYS.len(),
            "this fixture reached {} keys, fewer than revision 1's own set; a pin \
             over a capture that stopped rendering is a gate measuring nothing",
            seen.len()
        );
    }

    /// ZA-3214 ① — a numbering that numbers every list, standing in for a live
    /// handle's in a test that only needs the coordinate keys to appear.
    struct EveryListNumbered;

    impl RowCoordinates for EveryListNumbered {
        fn list_id(&self, list: usize) -> Option<u64> {
            Some(list as u64)
        }

        fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
            Some(u64::MAX)
        }
    }

    /// R2175 (open-debt item 552) — THE PAYLOAD PLANE OF THIS DOCUMENT,
    /// RENDERED FROM ITS OWN TYPES RATHER THAN FROM WHATEVER A CAPTURE REACHED.
    ///
    /// # What the pin above could not see, measured
    ///
    /// `the_field_documents_key_set_is_pinned` drives `declarations: None`, on
    /// the reading that "a payload map is the operator's input, not the
    /// capture's". The consequence was not stated and is this: with a mapping
    /// supplied the document gains FIFTEEN keys — `payload_decode`, `state`,
    /// `descriptor_bytes` and the rest — and revision 1 pins none of them. So
    /// R2170 added `descriptor_bytes` to a shipped document and no revision
    /// moved, because no revision had ever covered the subtree it landed in.
    ///
    /// # Why the renderers and not a richer capture
    ///
    /// Eight `PayloadDecoding` states, three `RefusedUnder` and two `Misbound`
    /// are reachable by rendering the TYPE; making one capture produce all
    /// thirteen would be a fixture nobody can keep whole, and a fixture that
    /// stopped reaching an arm would take the arm's keys out of the pin
    /// silently — which is the failure this test exists to end. The walks
    /// (`PayloadDecoding::all`, `RefusedUnder::names`, `Misbound::names`) are
    /// each bound to an exhaustive match, so a variant added later joins this
    /// population at `cargo build` rather than when someone remembers.
    ///
    /// The union of the document AND the renderings, because neither alone is
    /// the document a consumer reads: the capture supplies the surrounding
    /// rows, the renderings supply the arms it did not take.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_field_documents_payload_plane_is_pinned_over_every_arm() {
        use crate::doc_revision as rev;
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::{
            push_decoding, push_misbinding, push_refusal, Declarations, Misbinding, Misbound,
            PayloadDecoding, RefusedUnder,
        };

        let (d, file) =
            crate::census_json::fed_tests::every_plane_capture_with_file("demo/temp", None, false);
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let run = Declarations::new(&map);

        let mut rendered = alloc::vec![fields_json(&d, &file, None, Some(&run))];
        // ZA-3215 — AND THE SAME CAPTURE THROUGH THE SELECTOR DOOR. Revision 13
        // declared `selected` and this population never rendered a row that
        // carries it, so the equality below failed from the round that
        // declared it; a selector is the only input that emits the key.
        let selector = crate::filter::Filter::parse("bytes > 6").expect("a selector");
        rendered.push(fields_json_where(&d, &file, None, Some(&run), &selector));
        // ZA-3214 ① — and through the live door's coordinated rendering, the
        // only one that writes `list_id`, `anchor` and `batch_index` (revision
        // 15). Without it those keys would be declared and pinned by nothing.
        rendered.push(fields_json_where_coordinated(
            &d,
            &file,
            None,
            Some(&run),
            &selector,
            &EveryListNumbered,
        ));
        let states = PayloadDecoding::all();
        assert_eq!(
            states.len(),
            PayloadDecoding::STATES.len(),
            "the variant walk and the word list must stay the same length, or this \
             population is short by however many arms the walk stopped at"
        );
        for state in &states {
            let mut out = String::new();
            push_decoding(state, &mut out);
            rendered.push(out);
        }
        // THE ONE SHAPE THE WALK CANNOT SUPPLY, and it is a discriminant walk's
        // structural limit rather than an omission. `PayloadDecoding::next`
        // builds each variant with EMPTY payloads — its own doc says the data
        // is furniture there — so the `Decoded` arm it yields carries no
        // decoded field, and `fields[]`'s own object never opens. `path` is
        // emitted only from inside it. Measured: without this the union is 51
        // keys and `path` is not one of them, so a key a consumer receives
        // would have been pinned by nothing for the second time in one
        // document.
        rendered.push({
            let mut out = String::new();
            push_decoding(
                &PayloadDecoding::Decoded {
                    keyexpr: String::from("demo/**"),
                    format: String::from("json"),
                    fields: alloc::vec![crate::payload::formats::PayloadField {
                        path: String::from("$.a"),
                        name: None,
                        value: String::from("1"),
                        start: 0,
                        end: 1,
                    }],
                    despite_encoding: None,
                },
                &mut out,
            );
            out
        });

        // Constructed rather than captured, for the reason the doc gives: the
        // WALK is the population, and each variant only has to be RENDERED for
        // its keys and its word to join the pin.
        for under in [
            RefusedUnder::Corroborated,
            RefusedUnder::Unclaimed,
            RefusedUnder::Refuted,
        ] {
            let mut out = String::new();
            push_refusal(
                &crate::payload_decode::Refusal {
                    keyexpr: String::from("demo/**"),
                    format: String::from("json"),
                    under,
                    samples: 1,
                    example: String::from("byte 0"),
                },
                &mut out,
            );
            rendered.push(out);
        }
        for wrong in [Misbound::Rule, Misbound::Publisher] {
            let mut out = String::new();
            push_misbinding(
                &Misbinding {
                    keyexpr: String::from("demo/**"),
                    format: String::from("json"),
                    declared: String::from("text/plain"),
                    wrong,
                    publisher: None,
                    samples: 1,
                },
                &mut out,
            );
            rendered.push(out);
        }
        // The two arms above are written out, so the count is asserted against
        // the walks that ARE compiler-bound: a fourth `RefusedUnder` or a third
        // `Misbound` fails here rather than quietly leaving its word unpinned.
        assert_eq!(
            RefusedUnder::names().len(),
            3,
            "a RefusedUnder arm was added"
        );
        assert_eq!(Misbound::names().len(), 2, "a Misbound arm was added");
        // ZA-3215 — the row and flow objects revision 14 added.
        rendered.extend(session_arms());

        let mut seen: Vec<&str> = Vec::new();
        for doc in &rendered {
            seen.extend(rev::key_set(doc));
        }
        seen.sort_unstable();
        seen.dedup();
        let expected: Vec<&str> = rev::newest(rev::FIELDS)
            .expect("the field document has a revision")
            .keys
            .to_vec();
        assert_eq!(
            seen, expected,
            "the field document's key set moved once the payload plane is counted; \
             if that is deliberate, APPEND a revision to \
             `doc_revision::DOCUMENT_HISTORY` carrying the new set"
        );
    }

    /// R2175 (open-debt item 552) — A DECLARED VOCABULARY IS THE LIBRARY'S OWN,
    /// AND WIDENING ONE COSTS A REVISION.
    ///
    /// # The defect, restated as the thing this asserts
    ///
    /// R2170 added `not_on_the_wire` as an eighth `payload_decode.state` and
    /// the header says it REPLACES what used to be reported as `no_payload`.
    /// Same key, same document revision, a different answer about the same
    /// record. Nothing moved, and nothing could have: the key-set pin sees keys,
    /// and a consumer's `switch` reads the string inside one. The consuming
    /// surface that reported this found it while moving its own pin, not from
    /// any signal wz sent.
    ///
    /// # Why this compares against the WALK and not against a second list
    ///
    /// `PayloadDecoding::STATES`, `RefusedUnder::names` and `Misbound::names`
    /// are each bound to an exhaustive match, so they are what the library
    /// actually emits. The `DOCUMENT_HISTORY` row is a SNAPSHOT of that, written
    /// out per revision — see [`crate::doc_revision::ValueFamily::values`] for
    /// why it must not simply point at the constant. This test is the joint: a
    /// word added to a walk fails here, and the only way to pass is to append a
    /// revision that carries it, which is exactly the notice a consumer needs.
    ///
    /// The three arms are COLLECTED rather than asserted where they are read: an
    /// arm that panics leaves the later ones unmeasured, and unmeasured must not
    /// read as passed.
    #[test]
    fn the_declared_value_families_match_the_librarys_own_vocabularies() {
        use crate::doc_revision as rev;
        use crate::payload_decode::{Misbound, PayloadDecoding, RefusedUnder};

        let vocabulary = |document: &str, key: &str| -> (u32, Vec<&'static str>) {
            let newest = rev::newest(document).expect("the document has a revision");
            let family = newest
                .families
                .iter()
                .find(|f| f.key == key)
                .unwrap_or_else(|| {
                    panic!(
                        "the {document} document declares no family for {key:?}; a key \
                         a consumer switches on with no declared vocabulary is the \
                         whole of item 552"
                    )
                });
            (newest.revision, family.values.to_vec())
        };
        let sorted = |mut v: Vec<&'static str>| {
            v.sort_unstable();
            v
        };

        // Every family in the table, against the walk that produces its words.
        // BOTH documents, because a gate over one document would leave the
        // other's unwatched — the half-a-contract shape `wz-capi-dissect`'s
        // verdict pins already name.
        //
        // R2182 (open-debt item 555) — `fields.kind` joins as the first row,
        // and it is the row that made this table's population question real:
        // the walk behind it, `FieldValue::kind_words`, did not exist in the
        // library at all until this round. It was a successor chain inside
        // `wz-session-core`'s own `mod tests`, so the eight words were held
        // against a rename and against each other and against NOTHING a
        // consumer could read.
        let mut failures: Vec<String> = Vec::new();
        let live: [(&str, &str, Vec<&'static str>); 24] = [
            // ZA-3215 — the session's per-frame verdicts, each held to the
            // walk its emitter's exhaustive match is bound to.
            (rev::FIELDS, "verdict", SnVerdictWord::names()),
            (rev::FIELDS, "outcome", ChainOutcome::names()),
            (rev::FIELDS, "reason", ChainReason::names()),
            (rev::FIELDS, "phase", PhaseWord::names()),
            // The band's NAME is `Priority::name`, an exhaustive match over the
            // eight variants; `from_wire` is total over the 3-bit field, so the
            // walk over `0..NUM` reaches each exactly once.
            (
                rev::FIELDS,
                "priority",
                (0..wz_session_core::qos::Priority::NUM as u8)
                    .map(|b| wz_session_core::qos::Priority::from_wire(b).name())
                    .collect(),
            ),
            // R2457 (open-debt item 702) — WHY a keyexpr reference did not
            // resolve. A key a consumer switches on precisely because the two
            // words send it to different places: `no_session` says the
            // declaration may be one flow over, `no_declaration` says it is not
            // in this capture at all.
            (rev::CENSUS, "cause", crate::agg::UnresolvedCause::names()),
            // R2458 (open-debt item 703) — the SAME enum on the field document,
            // under the key that names its subject there. Two declarations of
            // one vocabulary, each at its own document's revision, and both
            // held to the one walk: that is the joint the `link` pair below
            // makes the argument for.
            (
                rev::FIELDS,
                "keyexpr_cause",
                crate::agg::UnresolvedCause::names(),
            ),
            (
                rev::FIELDS,
                "kind",
                wz_session_core::dissect::FieldValue::kind_words(),
            ),
            // Round 2447 (open-debt item 696) — `link` on BOTH documents, and
            // both rows take the same walk. That is the point rather than a
            // duplicate: the two documents declare the vocabulary separately,
            // at their own revisions, and holding each declaration to the ONE
            // walk is what keeps them from drifting into two answers about one
            // enum.
            (rev::FIELDS, "link", crate::link::LinkKind::names()),
            (rev::CENSUS, "link", crate::link::LinkKind::names()),
            // R2223 (open-debt item 573) — the message vocabulary, and the row
            // whose walk is held to something outside itself. The others here
            // are successor chains checked against a derive or against each
            // other; `MessageName::names` is checked against what the two
            // DISPATCHERS produce over all thirty-two values a MID can take,
            // because the defect this row closes was a list that drifted from
            // the walkers and stayed drifted until traffic revealed it.
            (
                rev::FIELDS,
                "message",
                wz_session_core::dissect::MessageName::names(),
            ),
            (rev::FIELDS, "state", PayloadDecoding::STATES.to_vec()),
            // R2706 — the session's verdict words. The walk is the successor
            // chain on `CarriedState`; what holds it to `Carried` itself is
            // `carried_state`'s exhaustive match, which a new variant breaks.
            (rev::FIELDS, "carried_state", CarriedState::names()),
            (rev::FIELDS, "under", RefusedUnder::names()),
            (rev::FIELDS, "wrong", Misbound::names()),
            (rev::FIELDS, "offset_space", crate::AnchorSpace::names()),
            // ZA-3214 ④ — the selector door's per-row verdict. It wrote these
            // four words from R2766 on with no family declaring them, so a
            // consumer's switch had no revision to pin and nothing here to
            // break when a fifth word arrived.
            (
                rev::FIELDS,
                "selected",
                crate::fields_json::RowVerdict::names(),
            ),
            (
                rev::FIELDS,
                "direction",
                crate::census_json::direction_names(),
            ),
            (rev::CENSUS, "kind", crate::interest::InterestKind::names()),
            (rev::CENSUS, "mode", crate::interest::InterestMode::names()),
            (rev::CENSUS, "offset_space", crate::AnchorSpace::names()),
            // ZA-3214 ③ — the lexer's token classes, the first family on the
            // selector verdict. Its walk is `TokenClass::names`, held to the
            // lexer by the exhaustive `TokenClass::of`.
            (
                rev::SELECTOR_DIAGNOSE,
                "kind",
                crate::filter::TokenClass::names(),
            ),
            // ZA-3509 — the verdict document's two families, each held to the
            // SAME walk the field document's is. Two declarations of one
            // vocabulary at their own documents' revisions, and one walk behind
            // both: that is what keeps the verdict document from drifting into a
            // second answer about the four words.
            (
                rev::SELECTION,
                "selected",
                crate::fields_json::RowVerdict::names(),
            ),
            (
                rev::SELECTION,
                "direction",
                crate::census_json::direction_names(),
            ),
        ];
        // R2185 — what this table ACTUALLY held, collected as it is walked
        // rather than counted afterwards, so the closing comparison cannot
        // disagree with the loop that fed it.
        let mut names_checked: Vec<(&str, &str)> = Vec::new();
        for (document, key, words) in live {
            names_checked.push((document, key));
            // A walk that came back empty would make the comparison below
            // trivially true, which is this workspace's most expensive
            // recurring defect in its smallest form.
            assert!(
                !words.is_empty(),
                "the walk for {document}.{key:?} produced no words"
            );
            let (revision, declared) = vocabulary(document, key);
            if declared != sorted(words.clone()) {
                failures.push(alloc::format!(
                    "{document}.{key}: the library emits {:?} and revision {revision} \
                     declares {declared:?}. A value vocabulary that widened without a \
                     revision is item 552 happening again: APPEND a revision to \
                     `doc_revision::DOCUMENT_HISTORY` carrying the new set, so a \
                     consumer pinned to the old one is told its switch is no longer \
                     exhaustive.",
                    sorted(words),
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n\n"));

        // The `asker` / `declarer` pair carries the endpoint vocabulary too and
        // is checked here rather than in the table above, because listing one
        // walk under three keys would make the count read as three
        // independent facts.
        let endpoints = sorted(crate::census_json::direction_names());
        for key in ["asker", "declarer"] {
            let (_, declared) = vocabulary(rev::CENSUS, key);
            assert_eq!(declared, endpoints, "census.{key}");
        }

        // AND NO FAMILY ESCAPED THIS GATE — the population DERIVED rather than
        // counted.
        //
        // ⚠ R2185 — this was `census.families.len() + fields.families.len() ==
        // 11`, which is two defects in one line and both are recorded classes.
        // It is a CARDINAL beside the list it counts (R2176 struck one of these
        // in `doc_revision` for the same reason), and it names the two
        // documents by hand, so a family on a THIRD was invisible to it.
        // PROBED on 2026-08-30: a family declared on the SUMMARY document
        // passed this whole crate at exit 0, and three hand-written lines in
        // `wz_dissect.h` then satisfied the two gates that had caught it — a
        // vocabulary joined to no walk, shipped.
        //
        // The set is compared, not its size, and the declared side comes from
        // `declared_families`, which reads the newest revision of EVERY
        // document. A family anywhere that this test does not name fails here.
        let mut held: Vec<(&str, &str)> = names_checked;
        for key in ["asker", "declarer"] {
            held.push((rev::CENSUS, key));
        }
        held.sort_unstable();
        held.dedup();
        assert_eq!(
            held,
            rev::declared_families(),
            "a family was declared without joining this gate. Every family this \
             library emits today must be held to a WALK, whichever document it \
             is on; the one that is not is a vocabulary that can widen in \
             silence again, which is item 552 happening a second time"
        );
    }

    /// R2223 (open-debt item 573) — AND THE MESSAGE WORDS REACH THE DOCUMENT,
    /// read back off one this library actually emitted.
    ///
    /// The `kind` sibling below makes the argument for both: the vocabulary
    /// gate holds two Rust constants against each other and neither has been
    /// near a capture, so a walk could report a word `push_carried` never
    /// writes, or write it under a key no document carries.
    ///
    /// A SUBSET with a floor, for the reason that sibling gives. This fixture
    /// is one capture and the vocabulary is every message the wire defines;
    /// `Join` is the standing example of a word no unicast capture can reach,
    /// and the exact reason the family comes from a walk and not from an
    /// artifact. What is asserted here is that the words which DO arrive are
    /// declared, that enough of them arrive for the comparison to mean
    /// something, and that a word this capture cannot produce is nevertheless
    /// declared — the last being the check that would fail if anyone ever
    /// derived this family from observation.
    #[test]
    fn the_field_documents_message_words_are_all_declared() {
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::Declarations;

        let (d, file) =
            crate::census_json::fed_tests::every_plane_capture_with_file("demo/temp", None, false);
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let run = Declarations::new(&map);

        let declared = crate::doc_revision::newest(crate::doc_revision::FIELDS)
            .expect("the field document has a revision")
            .families
            .iter()
            .find(|f| f.key == "message")
            .expect("revision 5 declares the message family")
            .values;

        let mut seen: Vec<&str> = Vec::new();
        let with = fields_json(&d, &file, None, Some(&run));
        let without = fields_json(&d, &file, None, None);
        for doc in [&with, &without] {
            seen.extend(
                crate::doc_revision::json_string_values(doc)
                    .into_iter()
                    .filter(|(k, _)| *k == "message")
                    .map(|(_, v)| v),
            );
        }
        seen.sort_unstable();
        seen.dedup();

        let stray: Vec<&&str> = seen.iter().filter(|w| !declared.contains(w)).collect();
        assert!(
            stray.is_empty(),
            "the field document emits the `message` word(s) {stray:?}, which no \
             revision declares. A value that ARRIVES is the break — see \
             `ValueFamily` for the asymmetry — so APPEND a revision to \
             `doc_revision::DOCUMENT_HISTORY` carrying the widened set"
        );
        assert_eq!(
            seen.len(),
            8,
            "this fixture reached {} of the declared message words ({seen:?}); it \
             reached eight of fourteen when the family was written — `Declare`, \
             `Frame`, `Init`, `Interest`, `Push`, `Request`, `Response`, \
             `ResponseFinal` — and a capture that stopped producing rows would \
             make the subset above true by having nothing to compare",
            seen.len()
        );
        assert!(
            !seen.contains(&"Join") && declared.contains(&"Join"),
            "`Join` is declared and this capture does not produce it, which is the \
             measurement that decides where this vocabulary comes from. It is also \
             the exact word R2050 shipped a list without, for exactly this reason: \
             a Join is a MULTICAST announcement and every witness read a unicast \
             capture. If a fixture now DOES reach it, that is good news and this \
             assertion is what should change — but the family must keep coming \
             from `MessageName`, never from what a capture happened to show"
        );
    }

    /// R2182 (open-debt item 555) — AND THE WORDS REACH THE DOCUMENT, read back
    /// off one this library actually emitted.
    ///
    /// # Why the sibling above is not enough on its own
    ///
    /// `the_declared_value_families_match_the_librarys_own_vocabularies` holds
    /// the declaration against the WALK. Both halves of that are Rust constants
    /// this crate compiles, and neither has been near a capture: a walk could
    /// report a word `push_json` never writes, or write it under a key the
    /// document does not carry, and that gate would agree with itself. What a
    /// consumer receives is the document.
    ///
    /// # And why the walk is still the population, which this test MEASURES
    ///
    /// The check here is a SUBSET, and the number below is why it must be. The
    /// every-plane fixture — the richest capture this crate can build — reaches
    /// SEVEN of the eight words. The eighth is `opaque`, and it is the one the
    /// consuming surface that filed item 555 was missing. So a vocabulary
    /// derived from an artifact alone would have been derived with the very hole
    /// it was meant to close, which is the population-from-observation failure
    /// this workspace pays for repeatedly, in its exact shape.
    ///
    /// The floor is asserted so this cannot decay into a gate over an empty
    /// listing: a fixture that stopped rendering rows would otherwise make the
    /// subset trivially true.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_field_documents_kind_words_are_all_declared() {
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::Declarations;

        let (d, file) =
            crate::census_json::fed_tests::every_plane_capture_with_file("demo/temp", None, false);
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let run = Declarations::new(&map);

        let declared = crate::doc_revision::newest(crate::doc_revision::FIELDS)
            .expect("the field document has a revision")
            .families
            .iter()
            .find(|f| f.key == "kind")
            .expect("revision 3 declares the kind family")
            .values;

        let mut seen: Vec<&str> = Vec::new();
        let with = fields_json(&d, &file, None, Some(&run));
        let without = fields_json(&d, &file, None, None);
        for doc in [&with, &without] {
            seen.extend(
                crate::doc_revision::json_string_values(doc)
                    .into_iter()
                    .filter(|(k, _)| *k == "kind")
                    .map(|(_, v)| v),
            );
        }
        seen.sort_unstable();
        seen.dedup();

        let stray: Vec<&&str> = seen.iter().filter(|w| !declared.contains(w)).collect();
        assert!(
            stray.is_empty(),
            "the field document emits the `kind` word(s) {stray:?}, which no \
             revision declares. A value that ARRIVES is the break — see \
             `ValueFamily` for the asymmetry — so APPEND a revision to \
             `doc_revision::DOCUMENT_HISTORY` carrying the widened set, which is \
             the notice a consumer's switch needs"
        );
        // ZA-3687 — EIGHT now. The fixture's two Init frames each carry a `zid`,
        // and that field is `kind: "zid"` since revision 17, so the word joined
        // the ones this capture reaches without the capture changing. It
        // reached seven when the family was written; the extra word is a
        // consequence of the family widening by exactly the word the fixture
        // already exercised.
        assert_eq!(
            seen.len(),
            8,
            "this fixture reached {} of the declared kind words ({seen:?}); it \
             reached eight when `zid` joined the family, and a capture that \
             stopped producing rows would make the subset above true by having \
             nothing to compare",
            seen.len()
        );
        assert!(
            seen.contains(&"zid"),
            "the fixture's handshakes carry a zid, so the new word must be one \
             this capture reaches: {seen:?}"
        );
        assert!(
            !seen.contains(&"opaque") && declared.contains(&"opaque"),
            "`opaque` is declared and this capture does not produce it, which is \
             the measurement that decides where this vocabulary comes from. If a \
             fixture now DOES reach it, that is good news and this assertion is \
             what should change — but the family must keep coming from \
             `FieldValue::kind_words`, never from what a capture happened to show"
        );
    }

    /// R2184 (open-debt item 556) — WHICH KEYS ARRIVE BESIDE A VALUE, DERIVED
    /// FROM WHAT THE EMITTERS RENDER AND HELD AGAINST WHAT THE REVISION
    /// DECLARES.
    ///
    /// # The hole, and why neither sibling gate could see it
    ///
    /// `the_field_documents_key_set_is_pinned` pins a UNION over the whole
    /// document, so it cannot express "sometimes absent" at all.
    /// `the_declared_value_families_match_the_librarys_own_vocabularies` sees
    /// the WORD and stops. The sentence a consumer needs — *if `kind` is
    /// `opaque`, do not look for `value`* — was expressible in neither, so it
    /// was read off today's rendering. That is item 556.
    ///
    /// # The classification is DERIVED, and it is a total function
    ///
    /// `doc_revision::companions` reports one entry per OCCURRENCE. Group them
    /// by word and there are exactly three answers:
    ///
    /// * every word in ONE shape, two or more shapes overall → DISCRIMINANT;
    /// * some word in TWO shapes, or every word in one common shape →
    ///   PASSENGER;
    /// * one word, one shape → UNMEASURED, which is a FAILURE and not a pass.
    ///   Nothing in such a population could have contradicted either verdict,
    ///   and a claim nothing could falsify is not a measurement.
    ///
    /// The third case is why `interest_pair_capture` exists: `census.asker` and
    /// `census.mode` are reached by the every-plane capture with a single word
    /// each.
    ///
    /// # Why per-occurrence and not per-word
    ///
    /// MEASURED while deriving this: a union per word reports
    /// `fields[].direction == "a"` carrying both `packet` and `message_at`,
    /// because `a` occurs in a datagram row and in a stream row. A union
    /// therefore makes a PASSENGER look like a discriminant, and it destroys
    /// the very observation — one word in two shapes — that proves passage.
    ///
    /// # What the population is
    ///
    /// The captures for the surrounding rows, and the TYPES' own arms for
    /// everything a capture cannot reach: eight payload states, three
    /// `RefusedUnder`, two `Misbound` and eight `FieldValue` kinds, each walk
    /// bound to an exhaustive match. `opaque` is the word no capture in this
    /// tree produces — item 555's measurement — and it is the one whose object
    /// carries nothing at all, so a population taken from captures alone would
    /// have been derived with exactly the hole this axis exists to close.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_declared_carries_axis_is_the_one_the_emitters_render() {
        use crate::doc_revision as rev;
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::{
            push_decoding, push_misbinding, push_refusal, Declarations, Misbinding, Misbound,
            PayloadDecoding, RefusedUnder,
        };
        let (d, file) =
            crate::census_json::fed_tests::every_plane_capture_with_file("demo/temp", None, true);
        let (dl, filel) = crate::census_json::fed_tests::every_plane_capture_with_file(
            "demo/temp",
            Some("tcp/127.0.0.1:7447"),
            true,
        );
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let run = Declarations::new(&map);
        let with = fields_json(&d, &file, None, Some(&run));
        let without = fields_json(&d, &file, None, None);
        let withl = fields_json(&dl, &filel, None, Some(&run));
        let dgram_packet = udp_packet(
            [10, 0, 0, 1],
            43210,
            [10, 0, 0, 2],
            7447,
            &[wz_session_core::wire_const::T_MID_KEEP_ALIVE],
        );
        let mut dg = Dissection::new();
        dg.push_packet(LINKTYPE_ETHERNET, 0, &dgram_packet);
        dg.finish();
        let dgfile = crate::pcap::write(1, &[(0, 0, dgram_packet.as_slice())]);
        let dgram = fields_json(&dg, &dgfile, None, None);
        // ZA-3214 ④ — the selector's document, so `selected` is measured and
        // not only declared: a selector that matches the capture's key and one
        // that does not, which between them reach `yes`, `no` and `unjudged`.
        let hit = crate::filter::Filter::parse("key == demo/temp").expect("parses");
        let miss = crate::filter::Filter::parse("key == elsewhere/x").expect("parses");
        let where_hit = fields_json_where(&d, &file, None, None, &hit);
        let where_miss = fields_json_where(&d, &file, None, None, &miss);
        let census = crate::census_json::census_json(&d);
        let censusl = crate::census_json::census_json(&dl);
        let censusdg = crate::census_json::census_json(&dg);
        // THE ARMS THE CAPTURES CANNOT REACH, rendered from their own types on
        // the rule `the_field_documents_payload_plane_is_pinned_over_every_arm`
        // states: making one capture produce all thirteen payload states would
        // be a fixture nobody can keep whole, and a fixture that stopped
        // reaching an arm would take that arm's answer out of the population in
        // silence. Each walk is bound to an exhaustive match, so an arm added
        // later joins this population at `cargo build`.
        let mut arms: Vec<String> = Vec::new();
        for state in &PayloadDecoding::all() {
            let mut out = String::new();
            push_decoding(state, &mut out);
            arms.push(out);
        }
        for under in [
            RefusedUnder::Corroborated,
            RefusedUnder::Unclaimed,
            RefusedUnder::Refuted,
        ] {
            let mut out = String::new();
            push_refusal(
                &crate::payload_decode::Refusal {
                    keyexpr: String::from("demo/**"),
                    format: String::from("json"),
                    under,
                    samples: 1,
                    example: String::from("byte 0"),
                },
                &mut out,
            );
            arms.push(out);
        }
        for wrong in [Misbound::Rule, Misbound::Publisher] {
            let mut out = String::new();
            push_misbinding(
                &Misbinding {
                    keyexpr: String::from("demo/**"),
                    format: String::from("json"),
                    declared: String::from("text/plain"),
                    wrong,
                    publisher: None,
                    samples: 1,
                },
                &mut out,
            );
            arms.push(out);
        }
        // `opaque` is the word no capture in this tree produces, which is the
        // measurement item 555 recorded and the reason the population is the
        // WALK. `kind_representatives` is that walk carrying values rather than
        // words, so each arm can be RENDERED and its object read.
        for value in wz_session_core::dissect::FieldValue::kind_representatives() {
            arms.push(wz_session_core::dissect::to_json(
                &wz_session_core::dissect::Field {
                    name: "m".into(),
                    span: wz_session_core::dissect::Span { start: 0, end: 1 },
                    value,
                },
            ));
        }
        let interests = crate::census_json::census_json(
            &crate::census_json::fed_tests::interest_pair_capture(),
        );
        // R2457 (open-debt item 702) — the capture that renders BOTH words of
        // `cause`, which nothing else here does.
        //
        // This axis refused the family on the round it landed, and correctly:
        // the four census documents above hold no unattributed flow, so every
        // `unresolved[]` row they carry says `no_declaration` and the verdict
        // would have been reached over a population of one word. The multilink
        // fixture holds a NAMED session and a handshake-less flow in one
        // capture, so it renders `no_declaration` and `no_session` together —
        // which is the only shape that can grade the boundary between them.
        let multilink = crate::census_json::census_json(&crate::agg::tests::multilink_session());
        // R2458 (open-debt item 703) — the SAME capture through THIS document,
        // for the same reason one line up. `keyexpr_cause` arrives on the field
        // document at revision 9 and nothing else rendered here holds an
        // unattributable flow, so without this the family would be measured
        // over `no_declaration` alone — the population-of-one verdict this axis
        // refused at R2457, one document over.
        let (multilink_d, multilink_file) = crate::agg::tests::multilink_session_with_file();
        let multilink_fields = fields_json(&multilink_d, &multilink_file, None, None);
        // R2706 — the capture that renders `carried_state = reassembled`, and
        // the same argument the two entries above make: every other document
        // here carries `batch`, `nothing` and `fragment`, all of which arrive
        // with an EMPTY companion set, so the family would be judged a
        // PASSENGER over a population that holds no discriminating word. This
        // one completes a chain, which is the only shape whose object brings
        // `carried` and `fields`.
        #[cfg(all(feature = "reassembly", feature = "network-codecs"))]
        let (chain_d, chain_file) = crate::datagram_tests::reassembled_record_dissection_with_file(
            &crate::datagram_tests::push(
                crate::datagram_tests::sender_space(0, Some("split/across")),
                &[0u8; 8],
            ),
        );
        #[cfg(all(feature = "reassembly", feature = "network-codecs"))]
        let chain_fields = fields_json(&chain_d, &chain_file, None, None);
        // R2706 — and the two states no other fixture reaches. Every word this
        // family declares must be RENDERED by something here, which is the rule
        // that found both of these: a shape asserted by nobody is a declaration
        // a consumer parses by and nothing checks.
        #[cfg(feature = "reassembly")]
        let (midsession_d, midsession_file) =
            crate::datagram_tests::midsession_fragment_dissection_with_file();
        #[cfg(feature = "reassembly")]
        let midsession_fields = fields_json(&midsession_d, &midsession_file, None, None);
        let (compressed_d, compressed_file) =
            crate::datagram_tests::compressed_session_dissection_with_file();
        let compressed_fields = fields_json(&compressed_d, &compressed_file, None, None);
        // ZA-3215 — the five families revision 14 added, each word rendered
        // from its own type; see `session_arms`.
        arms.extend(session_arms());

        let mut fields_docs: Vec<&String> = alloc::vec![
            &with,
            &without,
            &withl,
            &dgram,
            &multilink_fields,
            &compressed_fields,
            &where_hit,
            &where_miss
        ];
        // ZA-3214 ① — EVERY capture above through the two other doors as well:
        // the selector's (rows gain `selected`) and the live door's (rows gain
        // `selected` and the record coordinates). The optional keys compose
        // with a word's own shapes independently, so the population has to be
        // the same product the declaration states — a door rendered over only
        // some captures would leave some products unmeasured and declared.
        //
        // ZA-3517 — A NON-EMPTY selector, and that is the point of the line. This
        // used to be the empty one, which judged every row and so put a `selected`
        // word on each; the empty selector now asks nothing and writes none, so
        // the population that measures the verdict's products has to ask a
        // question. `bytes >= 0` is the weakest one the language has: it drops no
        // row, and it still makes every row say which of the four words it is.
        let every = crate::filter::Filter::parse("bytes >= 0").expect("a selector that asks");
        let mut through: Vec<(&Dissection, &[u8], Option<&Declarations<'_>>)> = alloc::vec![
            (&d, &file[..], Some(&run)),
            (&d, &file[..], None),
            (&dl, &filel[..], Some(&run)),
            (&dg, &dgfile[..], None),
            (&multilink_d, &multilink_file[..], None),
            (&compressed_d, &compressed_file[..], None),
        ];
        #[cfg(all(feature = "reassembly", feature = "network-codecs"))]
        through.push((&chain_d, &chain_file[..], None));
        #[cfg(feature = "reassembly")]
        through.push((&midsession_d, &midsession_file[..], None));
        let mut widened: Vec<String> = Vec::new();
        for &(dissection, capture, decl) in &through {
            widened.push(fields_json_where(dissection, capture, None, decl, &every));
            widened.push(fields_json_where_coordinated(
                dissection,
                capture,
                None,
                decl,
                &every,
                &EveryListNumbered,
            ));
        }
        fields_docs.extend(widened.iter());
        // ZA-3509 — THE VERDICT DOCUMENT, over every capture the field document
        // is rendered over and under the selectors that between them reach the
        // words: one that keeps every row, one that matches this capture's key
        // and one that does not. Plus the empty selector, which is the shape the
        // other three never write — rows with their coordinates and no verdict
        // at all — so a declaration that forgot the key can be absent is
        // measured against a document where it is.
        let asked_nothing = crate::filter::Filter::parse("").expect("parses");
        let mut verdict_docs: Vec<String> = Vec::new();
        for &(dissection, _, _) in &through {
            for selector in [&every, &hit, &miss, &asked_nothing] {
                verdict_docs.push(crate::selection_json::selection_json_where_coordinated(
                    dissection,
                    selector,
                    &EveryListNumbered,
                ));
            }
        }
        // ZA-3214 ③ — the selector verdict, over selectors that between them
        // reach every token class, on both branches.
        let diagnoses: Vec<String> = [
            "(key == 'a b') && not size >= 3",
            "x != 1 || !y < 2 and z > 3 or w <= 4",
            "key == \"unclosed",
        ]
        .into_iter()
        .map(crate::filter::diagnose_json)
        .collect();
        #[cfg(all(feature = "reassembly", feature = "network-codecs"))]
        fields_docs.push(&chain_fields);
        #[cfg(feature = "reassembly")]
        fields_docs.push(&midsession_fields);
        fields_docs.extend(arms.iter());
        let docs: [(&str, Vec<&String>); 4] = [
            (rev::FIELDS, fields_docs),
            (
                rev::CENSUS,
                alloc::vec![&census, &censusl, &censusdg, &interests, &multilink],
            ),
            (rev::SELECTOR_DIAGNOSE, diagnoses.iter().collect()),
            (rev::SELECTION, verdict_docs.iter().collect()),
        ];

        // ⚠ R2185 — THE DOCUMENTS THIS GATE RENDERS ARE THE DOCUMENTS THAT
        // DECLARE FAMILIES, and that is asserted rather than assumed.
        //
        // The table above names two documents by hand. PROBED on 2026-08-30: a
        // family plus a `carries` row added to the SUMMARY document passed this
        // whole crate at exit 0 — this loop never looked at it, because it
        // iterates the table and not the declaration. `wz_dissect.h`'s two
        // marker gates did catch it, and three hand-written header lines then
        // silenced them, so the verdict shipped derived from no document at
        // all. That is `DocumentShape::planes`' own history one axis over, and
        // the repair is R2181's: derive the population.
        let rendered: Vec<&str> = docs.iter().map(|(name, _)| *name).collect();
        let mut sorted_rendered = rendered.clone();
        sorted_rendered.sort_unstable();
        assert_eq!(
            sorted_rendered,
            rev::documents_declaring_families(),
            "this gate renders {rendered:?} and the library declares families on \
             {:?}. A document whose families this gate does not render has a \
             carries verdict nothing derives; render it here, or it is a claim \
             with no measurement behind it",
            rev::documents_declaring_families()
        );

        let mut failures: Vec<String> = Vec::new();
        // The two verdicts, counted SEPARATELY. R2181's lesson, and it bites
        // exactly here: three families are discriminants and eight are
        // passengers, so a single total stays at eleven while either arm could
        // be holding over an empty set.
        let (mut discriminants, mut passengers) = (0usize, 0usize);
        // R2185 — and every family CLASSIFIED, collected as the loop runs, so
        // the closing comparison is over what actually happened.
        let mut classified: Vec<(&str, &str)> = Vec::new();
        for (name, rendered) in docs {
            let shape = rev::newest(name).expect("a revision");
            for family in shape.families {
                // word -> the DISTINCT companion sets it was seen with, one
                // entry per shape and not a union. See `rev::companions`: a
                // union per word makes a passenger look like a discriminant,
                // measured on `fields.direction`.
                let mut seen: Vec<(String, Vec<Vec<String>>)> = Vec::new();
                for doc in &rendered {
                    for (word, beside) in rev::companions(doc, family.key) {
                        let beside: Vec<String> = beside.iter().map(|s| s.to_string()).collect();
                        let row = match seen.iter_mut().find(|(w, _)| w == word) {
                            Some(row) => row,
                            None => {
                                seen.push((word.to_string(), Vec::new()));
                                seen.last_mut().expect("just pushed")
                            }
                        };
                        if !row.1.contains(&beside) {
                            row.1.push(beside);
                        }
                    }
                }
                seen.sort();
                let stray: Vec<&String> = seen
                    .iter()
                    .map(|(w, _)| w)
                    .filter(|w| !family.values.contains(&w.as_str()))
                    .collect();
                if !stray.is_empty() {
                    failures.push(alloc::format!(
                        "{name}.{}: the documents carry the word(s) {stray:?} that no \
                         revision declares",
                        family.key
                    ));
                    continue;
                }
                // UNMEASURED IS A FAILURE, NOT A PASS. With fewer than two
                // distinct words nothing observed here could have contradicted
                // either verdict — the family would be classified on the
                // strength of having looked at one thing. That is the
                // population-of-one pass this axis exists to refuse, and it is
                // why `interest_pair_capture` was built.
                if seen.len() < 2 {
                    failures.push(alloc::format!(
                        "{name}.{} is UNMEASURED by this population: {seen:?}. Fewer \
                         than two words arrived, so no observation here could have \
                         contradicted either verdict. Widen the population",
                        family.key
                    ));
                    continue;
                }
                // The SAME predicate the table is audited by, applied to what
                // the emitters actually rendered. Two rules would let the
                // declaration and the document be judged differently.
                let derived_discriminant = seen.iter().any(|(w1, shapes1)| {
                    let always: Vec<&String> = match shapes1.first() {
                        Some(first) => first
                            .iter()
                            .filter(|k| shapes1.iter().all(|s| s.contains(k)))
                            .collect(),
                        None => Vec::new(),
                    };
                    seen.iter().any(|(w2, shapes2)| {
                        w2 != w1
                            && always
                                .iter()
                                .any(|k| !shapes2.iter().any(|s| s.contains(k)))
                    })
                });
                let declared = shape
                    .carries
                    .iter()
                    .find(|c| c.key == family.key)
                    .map(|c| &c.shape);
                let Some(declared) = declared else {
                    failures.push(alloc::format!(
                        "{name}.{}: the newest revision declares no carries row, which \
                         `audit` should have refused before this test ran",
                        family.key
                    ));
                    continue;
                };
                match (declared, derived_discriminant) {
                    (rev::CarriesShape::Discriminant(rows), true) => {
                        discriminants += 1;
                        classified.push((name, family.key));
                        // EVERY declared word rendered, each with exactly the
                        // shapes the table names. A word the population never
                        // reached is not a pass: it is a row of the declaration
                        // that nothing measured.
                        for row in *rows {
                            let Some((_, shapes)) = seen.iter().find(|(w, _)| w == row.word) else {
                                failures.push(alloc::format!(
                                    "{name}.{} declares the word {:?} and nothing in this \
                                     population rendered it, so the shapes it declares are \
                                     asserted by nobody",
                                    family.key,
                                    row.word
                                ));
                                continue;
                            };
                            let mut got: Vec<Vec<String>> = shapes.clone();
                            got.sort();
                            let mut want: Vec<Vec<String>> = row
                                .shapes
                                .iter()
                                .map(|s| s.iter().map(|k| k.to_string()).collect())
                                .collect();
                            want.sort();
                            if got != want {
                                failures.push(alloc::format!(
                                    "{name}.{} = {:?} arrives in the shape(s) {got:?} and \
                                     the revision declares {want:?}. The keys a word \
                                     brings are a parse contract a consumer writes by \
                                     hand; APPEND a revision to \
                                     `doc_revision::DOCUMENT_HISTORY` carrying the new map",
                                    family.key,
                                    row.word
                                ));
                            }
                        }
                    }
                    (rev::CarriesShape::Passenger, false) => {
                        passengers += 1;
                        classified.push((name, family.key));
                    }
                    (declared, _) => failures.push(alloc::format!(
                        "{name}.{} is declared {} and these emitters render {}: {seen:?}. \
                         A key one word ALWAYS brings and another NEVER does is what makes \
                         a DISCRIMINANT; anything else is a PASSENGER, and the declaration \
                         is what a consumer parses by",
                        family.key,
                        match declared {
                            rev::CarriesShape::Passenger => "a PASSENGER",
                            rev::CarriesShape::Discriminant(_) => "a DISCRIMINANT",
                        },
                        if derived_discriminant {
                            "a discriminant"
                        } else {
                            "a passenger"
                        }
                    )),
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n\n"));
        assert!(
            discriminants >= 1 && passengers >= 1,
            "the carries axis classified {discriminants} discriminant(s) and \
             {passengers} passenger(s); an axis where every family answers the same \
             way says nothing the key set did not already say, and a count of zero \
             on either arm means that arm held over an empty set"
        );
        // R2185 — AND EVERY DECLARED FAMILY REACHED A VERDICT HERE. The
        // document-level assertion above cannot say this on its own: a document
        // may be rendered and a family on it still slip past, because the loop
        // walks `shape.families` and the verdict arms are not the only exits.
        classified.sort_unstable();
        assert_eq!(
            classified,
            rev::declared_families(),
            "the carries axis classified {classified:?} and the library declares \
             {:?}. A declared verdict that no rendering reached is a claim with \
             nothing behind it, which is the state this axis was added to abolish",
            rev::declared_families()
        );
    }

    /// One framed KeepAlive: a two-byte length prefix and the message.
    fn framed_keepalive() -> Vec<u8> {
        vec![1, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE]
    }

    /// R311y855 — A STREAM MESSAGE CROSSES AS A TREE PLUS THE OFFSET IT WAS
    /// TAKEN AT, which is the pair that makes a span usable.
    ///
    /// A tree alone is not enough to highlight bytes in a capture: every span
    /// inside it is message-relative, so a reader needs the message's own
    /// coordinate AND to know which space that coordinate is in. Both are
    /// asserted here, and the `offset_space` is what stops a packet index and a
    /// byte offset being told apart by inspection.
    #[test]
    fn a_stream_message_carries_its_tree_and_the_offset_it_was_taken_at() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &framed_keepalive()));
        d.finish();

        let file = crate::pcap::write(
            1,
            &[(0, 0, tcp_packet(1000, &framed_keepalive()).as_slice())],
        );
        let json = fields_json(&d, &file, None, None);

        assert!(
            json.contains("\"offset_space\":\"stream_byte\""),
            "a stream row's number is a BYTE OFFSET and must say so: {json}"
        );
        assert!(
            json.contains("\"name\":\"KeepAlive\""),
            "the walker named the message: {json}"
        );
        assert!(
            json.contains("\"fields\":{\"name\":\"KeepAlive\""),
            "and handed back the TREE, which is what a span comes from: {json}"
        );
        // The framing prefix is 2 bytes, so the message begins at 2 -- not at
        // the unit's own offset. A `message_at` that pointed at the prefix
        // would put every span two bytes early, which is exactly the class of
        // error a coordinate is for.
        assert!(
            json.contains("\"message_at\":2"),
            "the offset must skip the framing prefix: {json}"
        );
        assert!(
            json.contains("\"shown\":1,\"omitted\":0"),
            "one message, none held back: {json}"
        );
    }

    /// One framed `Frame` whose extension chain carries the mandatory transport
    /// QoS — `transport::frame::ext::QoS`, `zextz64!(0x1, true)`, so the header
    /// byte is the id, the MANDATORY flag and the `Z64` encoding.
    fn framed_frame_with_qos() -> Vec<u8> {
        let msg = vec![
            wz_session_core::wire_const::T_MID_FRAME | 0x80,
            0x01, // sn
            0x01 | 0x10 | 0x20,
            0x03, // the z64 body
        ];
        let mut out = vec![msg.len() as u8, 0];
        out.extend_from_slice(&msg);
        out
    }

    /// THE EXTENSION'S NAME REACHES THE CONSUMED SURFACE, not just the tree.
    ///
    /// `ext_name` is resolved down in the field walker, and a name that stopped
    /// there would be a finding with no plane: the analyzer's readers consume
    /// this JSON, so the label has to survive `to_json`'s rendering to be worth
    /// anything. That is what this asserts, and it also exercises the TRANSPORT
    /// carrier mapping, which the walker's own tests do not reach.
    ///
    /// The value matters as much as the presence: `0x1` is `qos` on a `Frame`
    /// and `qos` on an `Init` too, but a `Frame` declares it MANDATORY where
    /// `Init` does not, so a table that dropped that bit would name this nothing.
    #[test]
    fn an_extensions_name_reaches_the_json_a_reader_consumes() {
        let packet = tcp_packet(1000, &framed_frame_with_qos());
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
        d.finish();

        let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);
        let json = fields_json(&d, &file, None, None);

        assert!(
            json.contains("\"name\":\"Frame\""),
            "the row must be a walked Frame, not a decline: {json}"
        );
        assert!(
            json.contains(
                "\"name\":\"ext_name\",\"start\":2,\"end\":3,\
                           \"kind\":\"label\",\"value\":\"qos\""
            ),
            "the extension must reach the reader NAMED, aliasing its header \
             byte's own span: {json}"
        );
        assert!(
            json.contains(
                "\"name\":\"ext_id\",\"start\":2,\"end\":3,\
                           \"kind\":\"bits\",\"value\":1"
            ),
            "and its id must be the four bits zenoh gives it, not five: {json}"
        );
        assert!(
            json.contains(
                "\"name\":\"m\",\"start\":2,\"end\":3,\
                           \"kind\":\"flag\",\"value\":true"
            ),
            "and the mandatory bit must be its own field: {json}"
        );
    }

    /// R2756 (open debt 789) — THE EXTENSION'S DECODED VALUE REACHES THE
    /// CONSUMED SURFACE, and not merely its name.
    ///
    /// The sibling above pins the NAME. A document that named `qos` and then
    /// dropped what its z64 body says would satisfy that test while telling a
    /// reader nothing about the message's priority — and a consumer reported
    /// exactly that absence, on a claim this witness is what refutes.
    ///
    /// ⚠ THE DECODE HAD NO WITNESS AT THIS CARRIER, which is why the claim
    /// stood. `walk_ext_z64_body`'s `(Frame | Fragment | TransportOam, "qos")`
    /// arm reaches `read_transport_qos_z64`, and the two tests that did assert
    /// on a decoded qos both sit at OTHER carriers (a `Join`'s per-priority sn
    /// table, a `Push`'s priority/congestion/express). Nothing ran the transport
    /// arm, so "the document does not carry priority" could not be contradicted
    /// by anything but a reading.
    ///
    /// BOTH HALVES ARE PINNED BECAUSE THE SPAN IS THE CLAIM: the label ALIASES
    /// the `value` field's own span rather than replacing it, which is
    /// `walk_ext_entry`'s stated rule for a Z64 body (R311y898). A reading that
    /// consumed the span would leave the raw number invisible, and a test that
    /// checked only the label would not notice.
    #[test]
    fn a_frames_qos_extension_carries_its_decoded_priority_into_the_document() {
        let packet = tcp_packet(1000, &framed_frame_with_qos());
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
        d.finish();

        let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);
        let json = fields_json(&d, &file, None, None);

        assert!(
            json.contains(
                "\"name\":\"value\",\"start\":3,\"end\":4,\
                 \"kind\":\"uint\",\"value\":3"
            ),
            "the z64 body must stay visible as the number it is: {json}"
        );
        assert!(
            json.contains(
                "\"name\":\"priority\",\"start\":3,\"end\":4,\
                 \"kind\":\"label\",\"value\":\"InteractiveLow\""
            ),
            "and its decoding must reach the reader, aliasing that same \
             span: {json}"
        );
    }

    /// R311y855 — THE BOUND HOLDS BACK ROWS AND SAYS HOW MANY.
    ///
    /// An unbounded listing over a session-sized capture is the shape the
    /// summary's own doc refuses. What matters is that the held-back rows are
    /// COUNTED: a listing that silently stopped would read as a capture that
    /// ended.
    #[test]
    fn the_bound_holds_rows_back_and_counts_them() {
        let mut stream = Vec::new();
        for _ in 0..5 {
            stream.extend_from_slice(&framed_keepalive());
        }
        let packet = tcp_packet(1000, &stream);
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
        d.finish();
        let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);

        let all = fields_json(&d, &file, None, None);
        assert!(
            all.contains("\"shown\":5,\"omitted\":0"),
            "the unbounded arm must show every message, or the bound below \
             proves nothing: {all}"
        );

        let bounded = fields_json(&d, &file, Some(2), None);
        assert!(
            bounded.contains("\"shown\":2,\"omitted\":3"),
            "the bound must hold rows back AND count them: {bounded}"
        );
    }

    /// R311y855 — A DATAGRAM MESSAGE IS WALKED TOO, AND ITS NUMBER IS A PACKET
    /// INDEX RATHER THAN AN OFFSET.
    ///
    /// The datagram half is the one that needs the capture a second time, and
    /// it is the half a listing quietly omits when nobody looks: a flows() walk
    /// that names only the stream side is this crate's own recorded failure
    /// (R311y679, and three rounds after it).
    #[test]
    fn a_datagram_message_is_walked_and_its_number_is_a_packet_index() {
        let packet = udp_packet(
            [10, 0, 0, 1],
            43210,
            [10, 0, 0, 2],
            7447,
            &[wz_session_core::wire_const::T_MID_KEEP_ALIVE],
        );
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
        d.finish();
        let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);

        let json = fields_json(&d, &file, None, None);
        assert!(
            json.contains("\"capture_reread\":true"),
            "the second read is what the datagram half runs on: {json}"
        );
        assert!(
            json.contains("\"offset_space\":\"packet\",\"packet\":0"),
            "a datagram row's number is a packet INDEX, and adding a span to it \
             would be meaningless: {json}"
        );
        assert!(
            json.contains("\"name\":\"KeepAlive\""),
            "the datagram half walks its messages, it does not merely count \
             them: {json}"
        );
        assert!(
            json.contains("\"disagreements\":{\"count\":0"),
            "and the two reads agreed about every one: {json}"
        );
    }

    /// R311y855 — A CAPTURE THIS READER CANNOT PARSE A SECOND TIME SAYS SO.
    ///
    /// The honesty valve on the row above. Handing back an empty datagram
    /// listing would read as "this capture had no datagram traffic", which is a
    /// statement about the capture made on the evidence of the reader.
    #[test]
    fn a_capture_that_cannot_be_reread_is_reported_rather_than_left_empty() {
        let packet = udp_packet(
            [10, 0, 0, 1],
            43210,
            [10, 0, 0, 2],
            7447,
            &[wz_session_core::wire_const::T_MID_KEEP_ALIVE],
        );
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
        d.finish();

        // The dissection is real and the BYTES handed to the walker are not a
        // capture at all, which is the only way to reach this arm.
        let json = fields_json(&d, b"not a capture file", None, None);
        assert!(
            json.contains("\"capture_reread\":false"),
            "the reader must admit it could not re-read the file: {json}"
        );
        assert!(
            json.contains("\"shown\":0"),
            "and show nothing rather than inventing rows: {json}"
        );
    }

    /// R311y855 — THE WALK IS CHECKED AGAINST THE SESSION, AND A DISAGREEMENT
    /// IS A NAMED DECLINE RATHER THAN A CONFIDENT TREE.
    ///
    /// This is the guarantee that must not be dropped in porting the field
    /// layer to a second surface. R311y687 found a live misread with it -- a
    /// batched unit's second message walked as its first -- and a tree emitted
    /// from a coordinate that names the wrong message is worse than no tree:
    /// it is a confident answer about bytes nobody asked about.
    ///
    /// Reached through the RETENTION cap, which is the shape that actually
    /// occurs: a bounded reader trims the stream behind it, so a message the
    /// session framed early has bytes nobody kept.
    ///
    /// The first cut used a truncated framing prefix instead and PASSED ON ZERO
    /// ROWS -- the session never framed that unit at all, so there was nothing
    /// to decline and the negative assertion held vacuously. Measured rather
    /// than reasoned: the fixture was dumped and its message list was empty.
    /// The assertions below are positive for that reason.
    #[test]
    fn a_row_the_stream_cannot_supply_is_declined_with_the_reason() {
        let mut stream = Vec::new();
        for _ in 0..40 {
            stream.extend_from_slice(&framed_keepalive());
        }
        let packet = tcp_packet(1000, &stream);
        let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);

        // Keep far fewer bytes than the stream holds, so the early messages'
        // bytes are gone while their frames remain.
        let limits = crate::DissectionLimits {
            stream_bytes_per_direction: Some(16),
            ..Default::default()
        };
        let d = crate::Dissection::from_capture_bounded(&file, limits).expect("the capture reads");

        let json = fields_json(&d, &file, None, None);
        assert!(
            json.contains("\"declined\":\"bytes discarded to stay inside the retained stream"),
            "a message whose bytes were trimmed must be DECLINED with the \
             reason -- not dropped, and not walked from whatever happens to sit \
             at that offset now: {json}"
        );
        // And the listing is not ALL declines: messages still inside the window
        // walk. Without this the test would pass against an emitter that
        // declined everything, which is the same vacuity in the other
        // direction.
        assert!(
            json.contains("\"fields\":{\"name\":\"KeepAlive\""),
            "the messages still inside the retained window must still walk: {json}"
        );
    }

    /// R311y856 — A DECLARED FORMAT DECODES THE PAYLOAD IN *THIS* EMIT, which
    /// is what the C ABI links and could not do.
    ///
    /// # What makes this a discriminator rather than an observation
    ///
    /// Three arms over ONE capture, and the assertion is the DIFFERENCE between
    /// them, not that any single one printed something:
    ///
    /// - no declarations -> no `payload_decode` key at all. Without this arm a
    ///   renderer that always emitted a block would pass;
    /// - a rule that does not cover this topic -> `no_rule`, carrying the
    ///   keyexpr that WAS tested. Without this arm a renderer that decoded
    ///   every payload regardless of the mapping would pass, which is the
    ///   failure a schemaless decoder makes silently: run over the wrong topic
    ///   it does not fail, it produces fields;
    /// - the covering rule -> `decoded`, with the DECLARED name and spans in
    ///   the MESSAGE's coordinates.
    ///
    /// The span is the sharpest of the four claims. `Protobuf` hands back
    /// payload-relative offsets, so a walker that forgot to rebase would report
    /// `start: 0` -- a number that is in range, looks plausible beside every
    /// other span in the row, and points at the message header.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_misbinding_counts_say_they_are_a_floor_when_a_cap_bit() {
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::Declarations;

        // THREE samples on one topic, all under a rule that is wrong for them:
        // declared JSON, and the rule says protobuf. Three so a cap of one has
        // two messages to hold back.
        let payload = br#"{"a":1}"#;
        let mut framed = Vec::new();
        for _ in 0..3 {
            let push = crate::datagram_tests::frame_carrying(
                &crate::payload::tests_support::push_declaring("demo/sensor", 5, payload),
            );
            framed.push(push.len() as u8);
            framed.push(0);
            framed.extend_from_slice(&push);
        }
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &framed));
        d.finish();
        let file = crate::pcap::write(1, &[(0, 0, tcp_packet(1000, &framed).as_slice())]);

        let mut map = FormatMap::new();
        map.declare("demo/**=protobuf").expect("a keyexpr pattern");

        // UNCAPPED: every message walked, so the count beside the finding is
        // the whole answer.
        let whole = Declarations::new(&map);
        let out = fields_json(&d, &file, None, Some(&whole));
        assert_eq!(whole.unwalked(), 0, "nothing was held back: {out}");
        assert!(whole.counts_are_exact(), "so the counts are exact: {out}");
        assert!(
            out.contains("\"payload_mapping_counts_exact\":true"),
            "and the document says so: {out}"
        );
        // THE POPULATION. Without a finding to qualify, everything above and
        // below is true of an empty array.
        let found = whole.misbindings();
        assert_eq!(found.len(), 1, "one rule is misbound: {found:?}");
        assert_eq!(found[0].samples, 3, "over all three samples: {found:?}");

        // CAPPED AT ONE: two messages are never walked, so no rule is applied
        // to them and the count is a floor.
        let capped = Declarations::new(&map);
        let out = fields_json(&d, &file, Some(1), Some(&capped));
        assert_eq!(
            capped.unwalked(),
            2,
            "the cap held two messages back: {out}"
        );
        assert!(!capped.counts_are_exact());
        assert!(
            out.contains("\"payload_mapping_counts_exact\":false"),
            "and the document must SAY the counts are a floor -- this is item \
             298: {out}"
        );
        // ⚠ THE FINDING SURVIVES AND THE NUMBER DOES NOT. That asymmetry is
        // the whole reason the flag is worth having: a reader who saw
        // `samples: 1` with nothing beside it would take a three-sample
        // misbinding for a one-off.
        let found = capped.misbindings();
        assert_eq!(found.len(), 1, "the rule is still named: {found:?}");
        assert_eq!(found[0].samples, 1, "but the count is short: {found:?}");
    }

    /// R2209 (open-debt item 563) — A READER WHO DECLARED NOTHING IS STILL TOLD
    /// WHICH RECORD WAS NOT ON THE WIRE.
    ///
    /// # The gap, as the tree itself had already written it down
    ///
    /// `payload::tests`'s `the_descriptor_count_is_a_row_total_and_cannot_name_\
    /// which_record` asserts the census row is consistent with either record
    /// having been the descriptor, and says in as many words that attributing
    /// it needs the per-message plane. That plane existed and its answer could
    /// not be reached: `push_walk` asked for a decoding only when a caller
    /// supplied a mapping, so a consuming surface that declared no format got
    /// `payloads.descriptors` -- how many -- and never WHICH.
    ///
    /// R2170 had already made the argument one level down, moving the SHM
    /// question ahead of the declaration check inside `decode_payload` because
    /// "whether a record's data crossed this wire has nothing to do with what
    /// formats the reader declared". The emitter did not inherit it.
    ///
    /// # Why the CONTROL is the half that matters
    ///
    /// The rule this changes is a real one and is still in force: a reader who
    /// declared nothing is not lectured about payloads they did not ask about.
    /// So the same document, from the same call, must carry NO `payload_decode`
    /// for the ordinary record beside the SHM one. Without that arm this test
    /// is satisfied by an emitter that reverted to a block on every row, which
    /// is the change item 563 does NOT ask for.
    ///
    /// ⚠ `network-codecs`, because `payload::tests_support` is -- the Put
    /// builders this fixture needs live there. MEASURED the hard way: without
    /// the gate the test does not compile into the default `--lib` target at
    /// all, and `cargo test … an_shm_record_names_itself` printed
    /// `running 0 tests … ok`, which is this workspace's most-repeated way of
    /// reading a green over nothing.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn an_shm_record_names_itself_to_a_reader_that_declared_no_format() {
        // TWO records in one capture on one topic: one whose payload slot holds
        // an SHM descriptor, one ordinary. Same topic on purpose -- the census
        // folds both onto one row, which is exactly why the row cannot name
        // either of them.
        let mut framed = Vec::new();
        for push in [
            crate::payload::tests_support::push_with_shm_descriptor(
                "shm/topic",
                5,
                &[0x01, 0x00, 0x2A],
            ),
            crate::payload::tests_support::push_declaring("shm/topic", 5, br#"{"a":1}"#),
        ] {
            let wire = crate::datagram_tests::frame_carrying(&push);
            framed.push(wire.len() as u8);
            framed.push(0);
            framed.extend_from_slice(&wire);
        }
        let packet = tcp_packet(1000, &framed);
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
        d.finish();
        let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);

        // NO DECLARATIONS. This is the door a consuming surface reaches for
        // when it has no format to declare, and the one item 563 is about.
        let out = fields_json(&d, &file, None, None);

        let blocks = out.matches("\"payload_decode\"").count();
        assert_eq!(
            blocks, 1,
            "exactly one of the two records may carry a payload_decode block \
             with no declarations -- the SHM one. {blocks} did: {out}"
        );
        assert!(
            out.contains("\"payload_decode\":{\"state\":\"not_on_the_wire\""),
            "and the block must carry the state that names the fact, since a \
             consuming surface counting `payloads.descriptors` can already see \
             HOW MANY and needs WHICH: {out}"
        );
        // THE CONTROL, on the number rather than on a second string: the
        // ordinary record shares this document and this call, and it is the
        // record that must still be told nothing.
        //
        // R2440 (open-debt item 691) — COUNTED OVER `carried`, which is emitted
        // once per WALKED row, and it used to be `out.contains("\"keyexpr\"")`.
        // That string was reached only through the SHM block when this was
        // written, and item 691 put a resolved `keyexpr` on every carried entry
        // of every row: the old control would now hold over a document whose
        // payload plane emitted nothing at all. A witness whose subject moves
        // under it is a green that read nothing.
        let rows = out.matches("\"carried\":[").count();
        assert_eq!(
            rows, 2,
            "both records must reach the walked rows, or the count above is \
             over a document holding one of them: {out}"
        );
    }

    /// ITEM 298, THE DATAGRAM DOOR — both listings cap, so both must say so.
    ///
    /// # Why this leg exists, as what happened rather than as a principle
    ///
    /// The stream witness above landed green, and removing the datagram
    /// listing's `note_unwalked` SURVIVED the whole suite. Four rounds running
    /// now, the first witness has been written against whichever door was
    /// convenient and the other has gone unasked — 2013 at `push_fragment`,
    /// 2014 at the reassembly door, 2019 at the space check, and this.
    ///
    /// A UDP deployment is not the exotic case here: multicast scouting and
    /// every `udp/...` link land in this listing, so a capture of one would
    /// have reported exact counts it did not have.
    #[test]
    fn the_datagram_listing_says_its_counts_are_a_floor_too() {
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::Declarations;

        // Three samples on one topic, each its own datagram, all declared JSON
        // under a protobuf rule.
        let payload = br#"{"a":1}"#;
        let mut packets = Vec::new();
        for _ in 0..3 {
            packets.push(udp_packet(
                [10, 0, 0, 1],
                43210,
                [10, 0, 0, 2],
                7447,
                &crate::datagram_tests::frame_carrying(
                    &crate::payload::tests_support::push_declaring("demo/sensor", 5, payload),
                ),
            ));
        }
        let mut d = Dissection::new();
        for (i, p) in packets.iter().enumerate() {
            d.push_packet(LINKTYPE_ETHERNET, i, p);
        }
        d.finish();
        let refs: Vec<(u32, u32, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u32, 0u32, p.as_slice()))
            .collect();
        let file = crate::pcap::write(1, &refs);

        let mut map = FormatMap::new();
        map.declare("demo/**=protobuf").expect("a keyexpr pattern");

        // THE POPULATION FIRST, on the uncapped run: without three misbound
        // samples in the DATAGRAM listing this leg is about nothing.
        let whole = Declarations::new(&map);
        let out = fields_json(&d, &file, None, Some(&whole));
        let found = whole.misbindings();
        assert_eq!(found.len(), 1, "one rule is misbound: {found:?}\n{out}");
        assert_eq!(found[0].samples, 3, "over all three: {found:?}");
        assert_eq!(whole.unwalked(), 0);

        let capped = Declarations::new(&map);
        let out = fields_json(&d, &file, Some(1), Some(&capped));
        assert_eq!(capped.unwalked(), 2, "the cap held two back: {out}");
        assert!(
            out.contains("\"payload_mapping_counts_exact\":false"),
            "the datagram listing must say its counts are a floor too: {out}"
        );
    }

    #[test]
    fn a_declared_format_decodes_the_payload_and_the_spans_are_the_messages() {
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::Declarations;

        // `{ 1: 150 }`, which the walker reads as one varint field spanning
        // three bytes of the PAYLOAD.
        let payload = [0x08u8, 0x96, 0x01];
        // A `Push` is a NETWORK message and rides inside a transport `Frame`;
        // the length prefix is the stream link's framing on top of that.
        let push = crate::datagram_tests::frame_carrying(
            &crate::payload::tests_support::push_declaring("demo/sensor", 0, &payload),
        );
        let mut framed = vec![push.len() as u8, 0];
        framed.extend_from_slice(&push);

        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &framed));
        d.finish();
        let file = crate::pcap::write(1, &[(0, 0, tcp_packet(1000, &framed).as_slice())]);

        let undeclared = fields_json(&d, &file, None, None);
        assert!(
            !undeclared.contains("payload_decode"),
            "a caller that declared nothing is told nothing about payloads: \
             {undeclared}"
        );

        let miss = FormatMap::new();
        let mut miss = miss;
        miss.declare("other/topic=protobuf")
            .expect("a literal pattern and a built-in format");
        let missed = fields_json(&d, &file, None, Some(&Declarations::new(&miss)));
        assert!(
            missed.contains(
                "\"payload_decode\":{\"state\":\"no_rule\",\
                             \"keyexpr\":\"demo/sensor\"}"
            ),
            "a rule that covers no topic here must say so AND name the keyexpr \
             it was tested against: {missed}"
        );

        let mut map = FormatMap::new();
        map.declare("demo/sensor=protobuf")
            .expect("a literal pattern and a built-in format");
        map.declare("demo/sensor:1=temperature")
            .expect("a field-name declaration");
        let declarations = Declarations::new(&map);
        let decoded = fields_json(&d, &file, None, Some(&declarations));

        let at = decoded
            .find("\"payload_decode\":")
            .unwrap_or_else(|| panic!("the row must carry a payload block: {decoded}"));
        let block = &decoded[at..];
        assert!(
            block.starts_with(
                "\"payload_decode\":{\"state\":\"decoded\",\"keyexpr\":\"demo/sensor\",\
                 \"despite_encoding\":null,\"format\":\"protobuf\",\"fields\":["
            ),
            "the covering rule must DECODE, naming the topic and the decoder: {block}"
        );
        assert!(
            block.contains("\"path\":\"1\",\"name\":\"temperature\",\"value\":\"varint 150\""),
            "the DECLARED name must be attached -- protobuf's wire format \
             carries none, so this is the only place one can come from: {block}"
        );

        // The rebase. The payload's three bytes are the LAST three of the
        // message, so a message-relative span ends where the message does and
        // begins three bytes earlier; `start: 0` is what a missing rebase
        // prints and it is in range.
        let end = push.len();
        let start = end - payload.len();
        assert!(
            block.contains(&alloc::format!("\"start\":{start},\"end\":{end}")),
            "the span must be in the MESSAGE's coordinates ({start}..{end}), \
             not the payload's (0..{}): {block}",
            payload.len()
        );

        // And the ledger saw both declarations apply, which is the half a
        // reader acts on when a rule binds nothing.
        assert!(
            declarations.unused().is_empty(),
            "both declarations applied: {:?}",
            declarations.unused()
        );
    }

    /// R2440 (open-debt item 691) — THE RESOLVED KEYEXPR REACHES A READER THAT
    /// DECLARED NO PAYLOAD FORMAT.
    ///
    /// # The coupling, as the consumer reported it
    ///
    /// The value was already computed for every frame — the id table is folded
    /// in frame order, ahead of the display cap — and the only place it left the
    /// library was `payload_decode.keyexpr`, a block emitted only when the
    /// caller declared a payload FORMAT. So a reader that declared nothing got
    /// `state: "no_rules"` and no key, and a reader that declared anything at
    /// all — even a rule matching nothing — got a key. Whether a captured sample
    /// could be REPUBLISHED therefore turned on whether its reader had opinions
    /// about payload encodings, and a replay tool had to hand over a decoder
    /// mapping it would never read purely as a side channel. That is the item,
    /// and it is a coupling rather than a defect: the resolver, the
    /// refuse-rather-than-guess rule and the payload block are each right about
    /// their own subject.
    ///
    /// ⚠ The "just pass an empty mapping" answer is not even available, which is
    /// worth stating because it is the first thing a reader tries:
    /// [`fields_json`] folds an empty [`Declarations`] to `None` on its first
    /// line, so the side channel demanded a mapping with a real rule in it.
    ///
    /// # The population is DERIVED from the document
    ///
    /// Not from a list of rows this test knows about: every JSON object in the
    /// document that carries a `message` key IS a carried entry — that key is
    /// emitted nowhere else — so the population comes from the shape of what was
    /// rendered. A floor refuses to grade an empty one: a claim that every entry
    /// carries a key is free when there are no entries.
    ///
    /// # And the value is one NEITHER shortcut produces
    ///
    /// The fixture's sample names its key by id against an inline declaration,
    /// so the answer is `demo/sensor/temp`. Reading the suffix alone gives
    /// `/temp` — asserted absent, because that is a WRONG key rather than a
    /// missing one and a republisher would send live traffic to it — and the
    /// `id == 0` literal path is not taken at all. A gate over the every-plane
    /// capture, whose records are `id 0` plus a suffix, would pass on a build
    /// holding no table.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn every_carried_entry_names_its_key_without_a_payload_format() {
        use crate::doc_revision::object_scopes;

        let (d, file) = crate::census_json::fed_tests::id_named_keyexpr_capture();

        // NO DECLARATIONS. This is the door the reporting consumer reaches for,
        // and the one the key used to be behind.
        let out = fields_json(&d, &file, None, None);

        assert!(
            !out.contains("\"payload_decode\""),
            "this reader declared no format, so no payload plane may be emitted \
             -- otherwise the key below could be arriving through the very side \
             channel this witness is about: {out}"
        );

        // THE POPULATION, derived: every object carrying `message` is a carried
        // entry, and `message` is emitted in no other object.
        let entries: Vec<Vec<(&str, &str)>> = object_scopes(&out)
            .into_iter()
            .filter(|scope| scope.iter().any(|(k, _)| *k == "message"))
            .collect();
        assert!(
            entries.len() >= 3,
            "the fixture must render the Init, the Declare's frame and the \
             Push's -- {} carried entr(ies) reached this gate, and a claim over \
             an empty population is free: {out}",
            entries.len()
        );

        let missing: Vec<&str> = entries
            .iter()
            .filter(|scope| !scope.iter().any(|(k, _)| *k == "keyexpr"))
            .filter_map(|scope| scope.iter().find(|(k, _)| *k == "message").map(|(_, v)| *v))
            .collect();
        assert!(
            missing.is_empty(),
            "every carried entry names its key or says `null`; {missing:?} \
             carried neither, so a consumer cannot tell a message with no key \
             from a build that stopped emitting one: {out}"
        );

        let keys: Vec<&str> = entries
            .iter()
            .filter_map(|scope| scope.iter().find(|(k, _)| *k == "keyexpr").map(|(_, v)| *v))
            .collect();
        assert!(
            keys.contains(&"\"demo/sensor/temp\""),
            "the sample's key is named by id against the inline declaration, so \
             the resolved answer is `demo/sensor/temp`: {keys:?} in {out}"
        );
        assert!(
            !keys.contains(&"\"/temp\""),
            "`/temp` is what reading the suffix alone reports for a record \
             published under `demo/sensor/temp` -- a WRONG key rather than a \
             missing one, and live traffic sent to the wrong topic for anybody \
             replaying it: {keys:?} in {out}"
        );
        assert!(
            keys.contains(&"null"),
            "the Init names no key at all and must say so as `null` rather than \
             by omission, which is what keeps `message` a passenger: {keys:?} \
             in {out}"
        );
    }

    /// Round 2443 (open-debt item 694) — A RAWETH FLOW RENDERS ITS MESSAGES,
    /// BESIDE A UDP ONE.
    ///
    /// # The fixture MIXES the two link kinds, and that is the whole design
    ///
    /// The word `raweth` occurred ZERO times in this file before this round, so
    /// the edit that widens the re-read had nothing here to grade it. The item
    /// that reported this said so and named the trap by name: a population that
    /// never mixes two conditions cannot grade the rule governing their
    /// boundary — R2441 paid for that lesson one crate over, where a rule
    /// written down since R311y703 turned out to be graded by nothing because
    /// every fixture held capture times that were all present or all absent.
    ///
    /// So this capture carries BOTH: a UDP scout and a raweth INIT, in one
    /// file, read by one call. A raweth-only fixture would pass just as well
    /// against a build that had stopped reading UDP.
    ///
    /// # What it would have caught
    ///
    /// Before the widening the raweth flow went out as `"messages":[]` with a
    /// `not_udp` disagreement, while `summary` counted the same frame and
    /// `census` read the node's zid off it. One capture, three doors, two
    /// answers.
    #[test]
    fn a_raweth_flow_renders_its_messages_beside_a_udp_flow() {
        use crate::datagram_tests::{init_message, raweth_packet};

        // THE SAME MESSAGE ON BOTH LINKS, so the only thing that differs is the
        // link kind. A first cut put a SCOUT on the UDP side, and until R2629
        // (open-debt item 744) that rendered no message row at all, which would
        // have made the UDP half of this fixture prove nothing. It renders one
        // now, but out of a different list and MID space than the raweth INIT,
        // so it still could not grade the link-kind boundary this test is for.
        let udp = udp_packet(
            [192, 168, 1, 5],
            43210,
            [192, 168, 1, 9],
            7447,
            &init_message(),
        );
        let eth = raweth_packet(&init_message());

        let mut d = Dissection::new();
        d.push_packet_at(LINKTYPE_ETHERNET, 0, Some(0), &udp);
        d.push_packet_at(LINKTYPE_ETHERNET, 1, Some(1), &eth);
        d.finish();

        assert_eq!(
            d.datagram_flows().len(),
            2,
            "the fixture must MIX the two link kinds; one of them alone cannot \
             grade the boundary this test exists for"
        );

        let file = crate::pcap::write(
            LINKTYPE_ETHERNET,
            &[(0, 0, udp.as_slice()), (1, 0, eth.as_slice())],
        );
        let out = fields_json(&d, &file, None, None);

        assert!(
            !out.contains("not_datagram"),
            "both frames ARE datagrams -- one UDP, one raweth -- so neither may \
             be refused by the second read: {out}"
        );
        assert!(
            !out.contains("\"messages\":[]"),
            "every datagram flow here carries a message, so an empty listing is \
             the defect this test was written for: {out}"
        );
    }

    /// R2629 (open-debt item 744) — A SCOUTING DATAGRAM IS A ROW, NAMED IN ITS
    /// OWN MID SPACE.
    ///
    /// # The defect
    ///
    /// The first pass keeps a datagram flow's scouting messages in
    /// `DatagramDissection::scouting`, apart from `frames`, because the two MID
    /// spaces collide: `S_MID_SCOUT` and `T_MID_INIT` are both `0x01`. The
    /// summary has counted that list since R311y608 and the census folds it,
    /// while this document walked `frames` alone — so a discovery capture
    /// crossed the C ABI as `"messages":[]` with no disagreement named, beside a
    /// summary reporting `"scouting":1`. One capture, two doors, two answers:
    /// item 694's shape, on a list this document did not read at all.
    ///
    /// # The misread it has to refuse, not only the absence
    ///
    /// The two bytes are `0x01` and `0x02`, so a row that reused the transport
    /// lookup would carry `Init` and `Open` with every key in place. A test
    /// asserting only that SOME row exists would pass against that renderer,
    /// which is why the transport words are named below.
    #[test]
    fn a_scouting_datagram_is_a_row_named_in_its_own_mid_space() {
        use crate::datagram_tests::{hello_with_locators, scout_message, SCOUT_GROUP};

        let asker = [192, 168, 1, 5];
        let asker_port = 43210;
        let scout = udp_packet(asker, asker_port, SCOUT_GROUP, 7446, &scout_message());
        let hello = udp_packet(
            [192, 168, 1, 9],
            7447,
            asker,
            asker_port,
            &hello_with_locators(),
        );

        let mut d = Dissection::new();
        d.push_packet_at(LINKTYPE_ETHERNET, 0, Some(0), &scout);
        d.push_packet_at(LINKTYPE_ETHERNET, 1, Some(1), &hello);
        d.finish();

        // The population this test grades: both messages in the SCOUTING list
        // and nothing in `frames`, so every row below can only have come from
        // the list the defect left unread.
        let lists: Vec<(usize, usize)> = d
            .datagram_flows()
            .iter()
            .map(|f| (f.frames.len(), f.scouting.len()))
            .collect();
        assert_eq!(
            lists,
            [(0, 1), (0, 1)],
            "the fixture must hold one scouting message per flow and no transport \
             frame, or the rows below are graded against something else"
        );

        let file = crate::pcap::write(
            LINKTYPE_ETHERNET,
            &[(0, 0, scout.as_slice()), (1, 0, hello.as_slice())],
        );
        let out = fields_json(&d, &file, None, None);

        for word in ["Scout", "Hello"] {
            let row = alloc::format!("\"name\":\"{word}\",\"fields\":");
            let entry = alloc::format!("\"carried\":[{{\"message\":\"{word}\",\"start\":0,");
            assert_eq!(
                (out.matches(&row).count(), out.matches(&entry).count()),
                (1, 1),
                "the {word} datagram must render exactly one walked row whose \
                 `carried` word is read in the scouting MID space: {out}"
            );
        }
        for misread in ["\"message\":\"Init\"", "\"message\":\"Open\""] {
            assert!(
                !out.contains(misread),
                "{misread} is `0x01`/`0x02` read in the TRANSPORT space, which is \
                 the confident wrong answer the scouting list exists to prevent: {out}"
            );
        }
        assert!(
            !out.contains("\"declined\":"),
            "both readers agree on both messages, so no row may be declined: {out}"
        );
        assert_eq!(
            out.matches("\"disagreements\":{\"count\":0,").count(),
            2,
            "both second reads agree with the first, on both flows: {out}"
        );
    }

    /// Round 2447 (open-debt item 696) — A FLOW ROW SAYS WHICH LINK IT WAS READ
    /// OFF, AND ITS ENDPOINTS ARE SPELLED THE WAY THAT LINK SPELLS ADDRESSES.
    ///
    /// # The defect, which is the ZA-1039 report's second claim
    ///
    /// The reader knew the answer and threw it away. `DatagramLink::RawEth` is
    /// chosen in `Dissection::push_packet_at`, whose own comment calls that the
    /// last place that knows, and it reached exactly one question — whether the
    /// link has a handshake. Nothing downstream carried it, so the document
    /// emitted a flow whose two endpoints are 6-byte MACs and whose only
    /// discriminator was `Endpoint::is_ipv4`. The `false` that answers sent
    /// them down the IPv6 branch, and pico's source MAC `30:03:c8:37:25:a1`
    /// went out as `"addr":"3003:c837:25a1","port":0` — three hex groups that
    /// read as a truncated address, beside no key saying otherwise.
    ///
    /// # Why the fixture MIXES, and what each half grades
    ///
    /// R2443 wrote the mixing rule for the sibling above and this test needs it
    /// twice over. A raweth-only capture cannot tell "the row says raweth" from
    /// "the row says raweth for everything", and it cannot tell a MAC spelled
    /// correctly from an address renderer that has stopped spelling IPv4. Both
    /// halves are asserted here, on ONE document, so the repair cannot be a
    /// widening that lost the other kind.
    ///
    /// # The discriminator is NOT the endpoint shape, and this is where that is
    /// checked
    ///
    /// The report asked for that in its own words, and the reason is in this
    /// crate one layer up: `link_handshake` exists precisely because pico's
    /// default DMAC has a clear I/G bit, so an address rule reads its whole
    /// deployment as a unicast link and is wrong about every frame. The same
    /// mistake in a renderer is what this closes. What the document carries is
    /// `crate::link::LinkKind`, written by the strip that decapsulated the
    /// frame — so a MAC that happened to be four bytes long, or an IPv4 address
    /// that happened to be six, would still be named correctly.
    #[test]
    fn a_datagram_flow_row_says_which_link_it_was_read_off() {
        use crate::datagram_tests::{init_message, raweth_packet};

        let udp = udp_packet(
            [192, 168, 1, 5],
            43210,
            [192, 168, 1, 9],
            7447,
            &init_message(),
        );
        let eth = raweth_packet(&init_message());

        let mut d = Dissection::new();
        d.push_packet_at(LINKTYPE_ETHERNET, 0, Some(0), &udp);
        d.push_packet_at(LINKTYPE_ETHERNET, 1, Some(1), &eth);
        d.finish();
        assert_eq!(
            d.datagram_flows().len(),
            2,
            "the fixture must MIX the two link kinds, or neither half below \
             grades anything"
        );

        let file = crate::pcap::write(
            LINKTYPE_ETHERNET,
            &[(0, 0, udp.as_slice()), (1, 0, eth.as_slice())],
        );
        let out = fields_json(&d, &file, None, None);

        // THE KEY, both words, from one document.
        assert!(
            out.contains("\"link\":\"raweth\""),
            "the raweth flow's row must say which link it is: {out}"
        );
        assert!(
            out.contains("\"link\":\"udp\""),
            "and the UDP flow's row must still say udp -- a repair that named \
             every flow raweth would satisfy the assertion above: {out}"
        );

        // THE SPELLING, both families. The MACs are `raweth_packet`'s own:
        // pico's default destination mapping and the source it lays.
        for mac in [
            "\"addr\":\"30:03:c8:37:25:a1\"",
            "\"addr\":\"aa:bb:cc:dd:ee:ff\"",
        ] {
            assert!(
                out.contains(mac),
                "a raweth endpoint is a MAC and must be spelled as one ({mac}): \
                 {out}"
            );
        }
        assert!(
            !out.contains("3003:c837:25a1"),
            "and the three-group reading the consumer reported must be gone, \
             not merely joined by a second one: {out}"
        );
        for ip in ["\"addr\":\"192.168.1.5\"", "\"addr\":\"192.168.1.9\""] {
            assert!(
                out.contains(ip),
                "the UDP flow's endpoints are IPv4 and must still read as \
                 dotted quads ({ip}) -- this is the arm a MAC-shaped repair \
                 would break: {out}"
            );
        }
    }

    /// ZA-3695 — an IPv6 flow's `addr` in the field document is RFC 5952 text.
    ///
    /// The sibling above grades the LINK-dependent spelling, and this one grades
    /// what the IP arm itself writes for sixteen bytes. The two endpoints are
    /// chosen for the two rules a renderer that merely dropped leading zeros
    /// gets wrong: `fe80::1` needs a run compressed, and `2001:db8:0:0:1:0:0:1`
    /// is a TIE between two runs of two, where the FIRST is the one that
    /// compresses. The old reading of them was eight groups each, with no `::`.
    ///
    /// The fixture MIXES an IPv4 datagram in, as its siblings do, because a
    /// repair that spelled every four-byte address through `Ipv6Addr` would
    /// satisfy the IPv6 half of this test and still be wrong.
    #[test]
    fn an_ipv6_flow_reaches_the_field_document_in_rfc_5952_text() {
        use crate::datagram_tests::{init_message, udp_packet, udp_packet_v6};

        let a = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let b = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0x01,
        ];
        let v6 = udp_packet_v6(a, 43210, b, 7447, &init_message());
        let v4 = udp_packet(
            [192, 168, 1, 5],
            43210,
            [192, 168, 1, 9],
            7447,
            &init_message(),
        );

        let mut d = Dissection::new();
        d.push_packet_at(LINKTYPE_ETHERNET, 0, Some(0), &v6);
        d.push_packet_at(LINKTYPE_ETHERNET, 1, Some(1), &v4);
        d.finish();
        assert_eq!(
            d.datagram_flows().len(),
            2,
            "the IPv6 and the IPv4 datagram must each be a flow, or the half \
             below that reads them grades nothing"
        );

        let file = crate::pcap::write(
            LINKTYPE_ETHERNET,
            &[(0, 0, v6.as_slice()), (1, 0, v4.as_slice())],
        );
        let out = fields_json(&d, &file, None, None);

        for ip in [
            "\"addr\":\"fe80::1\",\"port\":43210",
            "\"addr\":\"2001:db8::1:0:0:1\",\"port\":7447",
        ] {
            assert!(
                out.contains(ip),
                "an IPv6 endpoint is spelled the way RFC 5952 spells it ({ip}): \
                 {out}"
            );
        }
        for old in ["fe80:0:0:0:0:0:0:1", "2001:db8:0:0:1:0:0:1"] {
            assert!(
                !out.contains(old),
                "and the eight-group reading ({old}) is GONE, not merely joined \
                 by a second one: {out}"
            );
        }
        for ip in ["\"addr\":\"192.168.1.5\"", "\"addr\":\"192.168.1.9\""] {
            assert!(
                out.contains(ip),
                "the IPv4 datagram keeps its dotted quads ({ip}) -- the arm a \
                 repair that spelled every address as IPv6 would break: {out}"
            );
        }
    }

    /// R2454 (open-debt item 698) — the sibling above, one family over: a
    /// VSOCK endpoint's `addr` is the context id the operator's locator names,
    /// not four hex groups of its little-endian bytes.
    ///
    /// # What was wrong, measured before the repair
    ///
    /// Item 696 gave every flow object `link`, so a consumer could tell a MAC
    /// from an address — and it left the vsock SPELLING alone and said so. The
    /// row for a `vsock/2:7447` session read
    /// `{"addr":"200:0:0:0","port":7447}`: `Endpoint::vsock_cid` had the
    /// answer, `Endpoint::is_ipv4` said `false` for an 8-byte address, and the
    /// IPv6 branch read the cid's little-endian bytes as four `u16` groups.
    /// `2` came out as `200:0:0:0`, which is a well-formed IPv6 address and
    /// therefore the kind of wrong a consumer cannot detect.
    ///
    /// # Why this fixture MIXES, exactly as the raweth one does
    ///
    /// A vsock-only capture cannot separate "the vsock row spells a cid" from
    /// "every row spells the first eight bytes as a decimal", and the second
    /// would be a worse defect than the one being repaired. The UDP flow in
    /// this same document is the arm that refuses it.
    ///
    /// # `2` and `3` are the CIDs, and the row reassembles into the locator
    ///
    /// `wz_session_core::locator::parse_vsock_locator` reads `vsock/<CID>:<PORT>`
    /// with the cid as a decimal `u32`, so `"addr":"2","port":7447` is exactly
    /// the string an operator typed, split into the two fields this document
    /// has for it. That is the whole spelling rule, and it is why the assertion
    /// pins the pair rather than the address alone.
    #[test]
    fn a_vsock_flow_row_spells_its_context_id_beside_a_udp_one() {
        use crate::datagram_tests::init_message;
        use crate::link::LINKTYPE_VSOCK;

        /// One `vsockmon` record with no transport header: a 32-byte
        /// transport-independent header (`linux/vsockmon.h`) then the payload.
        /// `op` is 4, `AF_VSOCK_OP_PAYLOAD`, the only op that carries bytes.
        fn vsockmon(
            src_cid: u64,
            src_port: u32,
            dst_cid: u64,
            dst_port: u32,
            body: &[u8],
        ) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&src_cid.to_le_bytes());
            out.extend_from_slice(&dst_cid.to_le_bytes());
            out.extend_from_slice(&src_port.to_le_bytes());
            out.extend_from_slice(&dst_port.to_le_bytes());
            out.extend_from_slice(&4u16.to_le_bytes());
            out.extend_from_slice(&2u16.to_le_bytes()); // AF_VSOCK_TRANSPORT_VIRTIO
            out.extend_from_slice(&0u16.to_le_bytes()); // no transport header
            out.extend_from_slice(&[0u8, 0]); // reserved
            out.extend_from_slice(body);
            out
        }

        // A vsock link is SOCK_STREAM and carries the same length-prefixed
        // envelope tcp does, so the INIT goes on with its 16-bit prefix.
        let init = init_message();
        let mut framed = alloc::vec![init.len() as u8, 0];
        framed.extend_from_slice(&init);
        let vsock = vsockmon(3, 40000, 2, 7447, &framed);
        let udp = udp_packet(
            [192, 168, 1, 5],
            43210,
            [192, 168, 1, 9],
            7447,
            &init_message(),
        );

        // ONE capture, two interfaces of two link types — the mixing this
        // test's doc requires, expressed in the file rather than assembled by
        // hand, so the dissection and the byte offsets come from one read.
        let file = crate::pcapng::write(
            &[(LINKTYPE_ETHERNET, 6), (LINKTYPE_VSOCK, 6)],
            &[
                (0, 1_000_000, udp.as_slice()),
                (1, 2_000_000, vsock.as_slice()),
            ],
        );
        let d = Dissection::from_capture(&file).expect("the capture reads");
        assert_eq!(
            d.flows().len(),
            1,
            "the vsock session must be a stream flow, or the vsock half grades \
             nothing: {:?}",
            d.skipped()
        );
        assert_eq!(
            d.datagram_flows().len(),
            1,
            "and the UDP datagram must be beside it, or the negative arm does"
        );

        let out = fields_json(&d, &file, None, None);

        assert!(
            out.contains("\"addr\":\"2\",\"port\":7447")
                && out.contains("\"addr\":\"3\",\"port\":40000"),
            "both vsock endpoints must read as their decimal context ids, \
             paired with the 32-bit vsock port: {out}"
        );
        assert!(
            !out.contains("200:0:0:0") && !out.contains("300:0:0:0"),
            "and the four-hex-group reading of the little-endian cid must be \
             GONE, not merely joined by a correct one: {out}"
        );
        assert!(
            out.contains("\"link\":\"vsock\""),
            "the row still names the link -- item 696's key is what makes the \
             spelling above readable: {out}"
        );
        for ip in ["\"addr\":\"192.168.1.5\"", "\"addr\":\"192.168.1.9\""] {
            assert!(
                out.contains(ip),
                "the UDP flow keeps its dotted quads ({ip}) -- the arm a \
                 repair that spelled every address as a number would break: \
                 {out}"
            );
        }
    }

    /// THE NEGATIVE ARM: a link kind that genuinely is NOT a datagram is still
    /// refused, and now says so under the honest name.
    ///
    /// Without this, "accept everything" would satisfy the test above. A TCP
    /// segment found where the first pass recorded a datagram flow is a real
    /// disagreement between two reads of one file, and widening the arm must
    /// not have widened it to that.
    #[test]
    fn a_non_datagram_packet_is_still_refused_by_the_second_read() {
        use crate::datagram_tests::init_message;

        // A UDP datagram carrying a real message, so the flow HAS a frame for
        // the second read to disagree about. A first cut used a SCOUT here and
        // the flow had no frames at all, so the loop this test is about ran
        // zero times and the assertion below failed on an empty document —
        // a vacuous control, caught by the assertion rather than by review.
        let udp = udp_packet(
            [192, 168, 1, 5],
            43210,
            [192, 168, 1, 9],
            7447,
            &init_message(),
        );
        let mut d = Dissection::new();
        d.push_packet_at(LINKTYPE_ETHERNET, 0, Some(0), &udp);
        d.finish();

        // The FILE disagrees with the dissection: index 0 holds a TCP segment,
        // which is neither UDP nor raweth. The coordinates were inherited from
        // the first read, so this is exactly the "two reads of one file" case.
        let tcp = tcp_packet(1000, b"not a datagram at all");
        let file = crate::pcap::write(LINKTYPE_ETHERNET, &[(0, 0, tcp.as_slice())]);
        let out = fields_json(&d, &file, None, None);

        assert!(
            out.contains("not_datagram"),
            "a TCP segment where the first read recorded a datagram flow must \
             still be refused, under the name that says what happened: {out}"
        );
    }
}

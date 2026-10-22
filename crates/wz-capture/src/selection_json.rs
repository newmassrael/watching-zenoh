// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The VERDICT of a selector over the rows of the field document, and
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
//! # The order of the rows
//!
//! Rows are grouped by flow, stream flows first and then datagram flows, each
//! flow's scouting rows after its transport rows. Within a stream flow they are
//! in CAPTURE order since revision 3: the packet that carried the row's first
//! byte, then its place in that packet, which is
//! [`crate::FlowDissection::capture_order`] and is the order the field document
//! writes the same flow's `messages` in. It was the order the session decoded
//! the messages in before, which is the order their last bytes arrived in, and
//! the two parted whenever a message completed after one that began later. A
//! datagram flow's rows were always in capture order: a datagram is one packet.
//!
//! The key is total, so the order is deterministic and never depends on how many
//! `drain` calls the rows' records arrived in or on any hashing: no two rows of
//! a flow share a packet and a place.
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
//! # What a row says under a selector, and which rows say nothing
//!
//! A row's `kind` is the kind of what it carries, from the classifier every
//! plane shares: a `Push` is `put` or `del`; a `Request` is its body's kind
//! (`query` for every request upstream sends, because its request body has the
//! one variant `Query`:
//! `commons/zenoh-protocol/src/zenoh/mod.rs` @ `pub enum RequestBody`
//! and its reader refuses any other message id:
//! `commons/zenoh-codec/src/zenoh/mod.rs` @ `id::QUERY => RequestBody::Query`
//! while a request this reader decodes with a put or a del body takes that
//! kind); a `Response` is `reply` whatever the reply carries, or `err`.
//!
//! A `ResponseFinal` has no kind of its own. It FOLLOWS ITS EXCHANGE: it closes
//! the `Request` with the same request id, and it answers every selector as that
//! request does, so `kind == query` is `yes` on it and `kind == put` is `no`
//! when the request was a query. A `Request` and its `ResponseFinal` are one
//! exchange judged once, so the outcome terms (`replies`, `closed`,
//! `completion`) decide on those two rows and on no other.
//!
//! A `ResponseFinal` whose request the capture does not hold (it began
//! mid-exchange) is `unjudged`, not `no`: nothing was asked of it. So are `Init`,
//! `Open`, `Close`, `KeepAlive`, `Declare` and `Interest`, which carry no kind,
//! keyexpr or payload, under every selector.
//!
//! These rows used to read `unjudged` under every selector, because the verdict
//! was a by-product of the walk that inspects payloads and a `Query`, a `Del`
//! and a `ResponseFinal` have none. The exchange plane counted seven queries in
//! a capture whose seven request rows said `unjudged`; the two planes now agree
//! for any selector, on a capture where each row carries one record: the `yes`
//! request rows are the exchange plane's `requests` and the `yes` closes its
//! `completed`. See [`crate::fields_json`]'s `RowJudgement` for who judges which
//! record.
//!
//! # A selector whose `zid` prefix is AMBIGUOUS in this capture
//!
//! A `zid` term may be written as a prefix of eight digits or more
//! ([`crate::filter`] has the rules), and which zid it names is a fact about the
//! capture it is judged in. When the prefix begins TWO OR MORE of the zids this
//! capture names, the selector has no meaning here and `no` would be false, so
//! it judges nothing: every row reads `unjudged`, and the document says why in
//! `ambiguous_zid_prefixes`, one object per ambiguous term in the order the
//! selector writes them:
//!
//! ```text
//! "ambiguous_zid_prefixes":[{"start":7,"end":15,"prefix":"cbf383be",
//!                            "candidates":["cbf383be…","cbf383be…"]}]
//! ```
//!
//! `start` and `end` are the byte span of the value in the selector (a quoted
//! value's includes its quotes), the unit the selector verdict's `at` and token
//! spans use. `prefix` is the digits typed, in lower case. `candidates` are the
//! zids it begins, in the spelling the documents print and the order the
//! capture first named them. The key is ABSENT for a selector that was judged,
//! and the unit of the judgement is the CAPTURE: the same selector can be
//! ambiguous in one and unique in another.
//!
//! # The ceilings
//!
//! `dropped_by_limits` is the SAME group the field document and the census
//! carry, for the reason the field document gives: a row the walk never reached
//! is ABSENT rather than unmatched, and a consumer counting "three matched"
//! needs to be told the list it counted in was made short.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::census_json::dir_name;
use crate::fields_json::{
    judged_by, row_verdict_of, RenderedLists, RowCoordinates, RowJudgement, RowVerdict,
};

/// One row of the selection, before it is written: the coordinates a record
/// joins on, the number the handle gave the row when it numbers rows, and the
/// selector's word when a selector was asked.
///
/// `list_id` is `None` for a list the caller does not number, and then the row
/// carries no coordinate keys at all, on the field document's own rule that a
/// key is never invented. `verdict` is `None` when no selector was asked. `seq`
/// is `None` for a row the caller numbers no rows of.
///
/// `source` is where the row's bytes came from, which the documents here do not
/// write and [`crate::selected_packets`] reads to name the packets that carried
/// them.
pub(crate) struct Row<'a> {
    pub(crate) seq: Option<u64>,
    pub(crate) direction: &'static str,
    pub(crate) list_id: Option<u64>,
    pub(crate) anchor: u64,
    pub(crate) batch_index: u64,
    pub(crate) verdict: Option<RowVerdict>,
    pub(crate) source: RowSource<'a>,
}

/// Where one row's bytes came from.
#[derive(Clone, Copy)]
pub(crate) enum RowSource<'a> {
    /// A message of the TCP flow at `index` in `Dissection::flows`, at
    /// `position` in its list: its bytes are a range of the flow's stream.
    Stream {
        index: usize,
        flow: &'a crate::FlowDissection,
        position: usize,
    },
    /// A message of the datagram flow at `index` in
    /// `Dissection::datagram_flows`, at `position` in its cleartext list: one
    /// packet carried it whole.
    Datagram {
        index: usize,
        flow: &'a crate::DatagramDissection,
        position: usize,
    },
    /// A scouting message, carried whole by the packet `packet`.
    Scouting { packet: usize },
}

/// The coordinate keys of a row, without its braces and without its verdict.
fn push_coordinates(row: &Row, out: &mut String) {
    let _ = write!(out, "\"direction\":\"{}\"", row.direction);
    if let Some(list_id) = row.list_id {
        let _ = write!(
            out,
            ",\"list_id\":{list_id},\"anchor\":{},\"batch_index\":{}",
            row.anchor, row.batch_index
        );
    }
}

/// One row of the selection document.
fn push_row(row: &Row, first: &mut bool, out: &mut String) {
    if !*first {
        out.push(',');
    }
    *first = false;
    out.push('{');
    push_coordinates(row, out);
    if let Some(verdict) = row.verdict {
        let _ = write!(out, ",\"selected\":\"{}\"", verdict.word());
    }
    out.push('}');
}

/// Every row of the field document, in its order, each with the word the selector
/// said of it.
///
/// ONE enumeration behind both documents this file writes, so that "the same rows
/// in the same order, with the same numbers" is a property of the code and not of
/// two walks agreeing. [`crate::selected_packets`] walks it too, for the same
/// reason: the packets it names are those of these rows and of no others.
pub(crate) fn for_each_row<'d>(
    d: &'d crate::Dissection,
    verdicts: Option<&RowJudgement>,
    coordinates: &dyn RowCoordinates,
    each: &mut dyn FnMut(Row<'d>),
) {
    let lists = RenderedLists::of(d);

    for (i, flow) in d.flows().iter().enumerate() {
        let list = lists.stream.get(i).copied();
        let list_id = list.and_then(|l| coordinates.list_id(l));
        // The produced-index of the OLDEST message still held, so a row's number
        // is looked up by an index a front trim does not move: the field
        // document's own.
        let first_produced = flow.frames.produced() - flow.frames.len() as u64;
        // CAPTURE order, the field document's own: see
        // `FlowDissection::capture_order`. One function orders the rows of both
        // documents, so "the same rows in the same order" is a property of the
        // code and not of two walks agreeing.
        for position in flow.capture_order() {
            let frame = &flow.frames[position];
            let verdict = match (verdicts, list) {
                (Some(census), Some(list)) => Some(row_verdict_of(census, list, frame)),
                _ => None,
            };
            each(Row {
                seq: list.and_then(|l| coordinates.row_seq(l, first_produced + position as u64)),
                direction: dir_name(frame.direction),
                list_id,
                anchor: frame.stream_offset as u64,
                batch_index: frame.batch_index as u64,
                verdict,
                source: RowSource::Stream {
                    index: i,
                    flow,
                    position,
                },
            });
        }
    }

    for (i, flow) in d.datagram_flows().iter().enumerate() {
        let list = lists.datagram.get(i).copied();
        let list_id = list.and_then(|l| coordinates.list_id(l));
        let first_produced = flow.frames.produced() - flow.frames.len() as u64;
        for (position, frame) in flow.frames.iter().enumerate() {
            let verdict = match (verdicts, list) {
                (Some(census), Some(list)) => Some(row_verdict_of(census, list, frame)),
                _ => None,
            };
            // `stream_offset` names the PACKET on a datagram link, the only anchor
            // there is, as the field document's own row says.
            each(Row {
                seq: list.and_then(|l| coordinates.row_seq(l, first_produced + position as u64)),
                direction: dir_name(frame.direction),
                list_id,
                anchor: frame.stream_offset as u64,
                batch_index: frame.batch_index as u64,
                verdict,
                source: RowSource::Datagram {
                    index: i,
                    flow,
                    position,
                },
            });
        }
        // The scouting list, after the transport rows exactly as the field
        // document orders them. A scouting message carries no payload for the
        // record plane to judge, so under a selector it is unjudged BY
        // CONSTRUCTION and says so directly, on the field document's argument.
        let scouting_id = coordinates.scouting_list_id(&flow.flow);
        let scouting_first = flow.scouting.produced() - flow.scouting.len() as u64;
        for (position, datagram) in flow.scouting.iter().enumerate() {
            let verdict = match (verdicts, list) {
                (Some(_), Some(_)) => Some(RowVerdict::Unjudged),
                _ => None,
            };
            each(Row {
                seq: coordinates.scouting_row_seq(&flow.flow, scouting_first + position as u64),
                direction: dir_name(datagram.direction),
                list_id: scouting_id,
                anchor: datagram.packet_index as u64,
                batch_index: 0,
                verdict,
                source: RowSource::Scouting {
                    packet: datagram.packet_index,
                },
            });
        }
    }
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
    // so it pays nothing either. The rule lives in `judged_by`, which the field
    // document asks too.
    let verdicts = judged_by(d, filter, &grouping, Some(coordinates));
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::SELECTION, &mut out);
    out.push_str(",\"rows\":[");
    let mut first = true;
    for_each_row(d, verdicts.as_ref(), coordinates, &mut |row| {
        push_row(&row, &mut first, &mut out);
    });

    out.push(']');
    // WHY every row above reads `unjudged`, when it does: a `zid` prefix of the
    // selector began more than one zid of THIS capture. The key is absent for a
    // selector that was judged, and for a document with no selector.
    crate::filter::push_ambiguous_zid_prefixes(
        verdicts.as_ref().map_or(&[], |v| v.ambiguities()),
        &mut out,
    );
    out.push_str(",\"dropped_by_limits\":");
    out.push_str(&crate::report::dropped_by_limits_json(d));
    out.push('}');
    out
}

/// The word a selector said of each row the LAST call of
/// [`selection_since_json_coordinated`] judged, by the row's number.
///
/// The memory that makes a revision reportable. A verdict is not final when it
/// is given: it is the capture's reading of the row at that state, and it moves
/// when the state does (see the document's own paragraph), so a door that judged
/// only the new rows would hold every earlier row at the word it was first given.
/// Remembering what was said is what lets the next call say what changed, and it
/// costs a word per row the handle still holds, not a copy of any row.
#[derive(Debug, Default, Clone)]
pub struct SelectionMemory {
    said: BTreeMap<u64, RowVerdict>,
    /// Whether a call of [`selection_since_json_coordinated`] has written this
    /// memory. A memory is made empty when a selector has none, and a selector
    /// whose memory was given up to make room is made empty again, so this is
    /// the one fact that tells a caller which of the two the call found: the
    /// document says it as `window.continued`.
    written: bool,
}

impl SelectionMemory {
    /// How many rows' words are remembered.
    pub fn len(&self) -> usize {
        self.said.len()
    }

    /// Whether nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.said.is_empty()
    }
}

/// The [`SelectionMemory`] of each selector a handle has been asked under, up to
/// a count, the most recently used kept.
///
/// A selection memory is for ONE selector: it holds the words that selector said.
/// A caller that alternates between selectors therefore needs one per selector,
/// or every change of selector empties the memory and the next call writes every
/// row as new. With one memory, which is the default, a change of selector does
/// exactly that. A selector is told apart by its text, as it always was.
#[derive(Debug, Clone, Default)]
pub struct SelectionMemories {
    slots: crate::bounded_slots::BoundedSlots<String, SelectionMemory>,
}

impl SelectionMemories {
    /// How many selectors' memories are kept at once.
    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    /// Keep up to `n` selectors' memories, `n` held to
    /// `1..=`[`crate::MAX_SELECTOR_MEMORIES`], and return the number in effect.
    /// Lowering it gives up the least recently used first.
    pub fn set_capacity(&mut self, n: usize) -> usize {
        self.slots.set_capacity(n)
    }

    /// The memory of `selector`, made empty if it has none, and marked the most
    /// recently used.
    pub fn for_selector(&mut self, selector: &str) -> &mut SelectionMemory {
        self.slots
            .touch(&String::from(selector), SelectionMemory::default)
    }

    /// How many selectors have a memory now.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether no selector has a memory.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// How many selectors' memories have been given up to make room.
    pub fn evictions(&self) -> u64 {
        self.slots.evicted()
    }
}

/// The cursor window of a since document: the number the caller gave, and the
/// highest number the handle had issued when the document was made.
#[derive(Debug, Clone, Copy)]
pub struct SelectionWindow {
    /// The cursor the caller gave: rows numbered above it are NEW.
    pub after_seq: u64,
    /// The highest row number issued, and the cursor to give next.
    pub through_seq: u64,
}

/// A revised row also says what it read before.
fn push_revised_row(row: &Row, was: RowVerdict, first: &mut bool, out: &mut String) {
    if !*first {
        out.push(',');
    }
    *first = false;
    out.push('{');
    if let Some(seq) = row.seq {
        let _ = write!(out, "\"seq\":{seq},");
    }
    push_coordinates(row, out);
    if let Some(verdict) = row.verdict {
        let _ = write!(out, ",\"selected\":\"{}\"", verdict.word());
    }
    let _ = write!(out, ",\"was\":\"{}\"}}", was.word());
}

/// The selector's verdict over the rows issued AFTER a cursor, and the rows
/// BEFORE it whose word has changed since the last time it was asked.
///
/// # What a consumer narrowing a list that grows was paying for
///
/// [`selection_json_where_coordinated`] writes a word for every row, so a list
/// refreshed once per feed step received and parsed every row again at every step.
/// This writes the rows numbered above `since.after_seq` and nothing else, so the
/// cost of the DOCUMENT follows what is new. The cost of the WALK does not move:
/// the verdict is decided over the whole capture, as it is for the other door,
/// because a verdict is a fact about the capture and not about a row.
///
/// # A verdict can change after it is given, and this says which
///
/// It can, and a cursor alone would have missed it. TESTED here: a request and
/// its final are judged as ONE exchange at its close, so under `closed == no` the
/// request reads `yes` while nothing has closed it and `no` once the close is in
/// the capture, and the request row is one the cursor has already passed. NAMED by
/// the verdict document: a selector's `zid` prefix that began one zid and now
/// begins two makes the selector ambiguous, and every row reads `unjudged`. TESTED
/// NOT to move a row, in the construction a datagram link gives: a keyexpr
/// declaration that arrives after the reference to it is not applied to the
/// reference (the anchor rule), so that row's word stays; whether a decode that
/// happens later than its packet can move one is not claimed.
///
/// `revised` does not depend on the reason, which is why it is the answer: the rows
/// numbered at or below the cursor that this handle said a word about the last
/// time, and now says another. Each carries the new word in `selected` and the old
/// one in `was`. A consumer applies `revised` to the words it holds and appends
/// `rows`; it never has to ask for the whole walk, and a verdict it holds is as
/// true as the last document it read.
///
/// # What it remembers, and what a changed selector does
///
/// The words said last time, per row ([`SelectionMemory`]), for ONE selector. A
/// call under a different selector starts the memory again, so nothing is
/// reported revised and every row from the cursor on is new: ask from 0 after a
/// selector change, as the rows before the cursor are never written again. With
/// no selector there are no words, the memory is emptied, and nothing is revised.
///
/// # `window.continued`: whether the call found the selector's memory
///
/// `window.after_seq` is the cursor the caller GAVE, so it cannot say whether the
/// words that cursor is about were still held. `window.continued` does: `true`
/// when an earlier call under this selector wrote the memory this call used, and
/// `false` when the call began it, which is the first call under the selector or
/// the first after the handle gave its memory up to make room for another
/// selector's (the memories are a least-recently-used set, see
/// [`SelectionMemories`]). A `false` with a cursor above 0 is the one case a
/// consumer must act on: no row at or below the cursor is compared and none
/// is written again, so a word the consumer holds for such a row may be stale, and
/// the way to be right is to ask that selector again from 0.
pub fn selection_since_json_coordinated(
    d: &crate::Dissection,
    filter: &crate::filter::Filter,
    coordinates: &dyn RowCoordinates,
    since: SelectionWindow,
    memory: &mut SelectionMemory,
) -> String {
    let grouping = crate::node::session_grouping(d);
    let verdicts = judged_by(d, filter, &grouping, Some(coordinates));
    let mut said_now: BTreeMap<u64, RowVerdict> = BTreeMap::new();
    let mut fresh: Vec<Row> = Vec::new();
    let mut revised: Vec<(Row, RowVerdict)> = Vec::new();
    for_each_row(d, verdicts.as_ref(), coordinates, &mut |row| {
        let Some(seq) = row.seq else {
            // A row with NO number is never passed over: with a cursor set it
            // cannot be compared, and writing a row twice is a recoverable
            // answer where dropping one is not. The field document's rule.
            fresh.push(row);
            return;
        };
        if let Some(verdict) = row.verdict {
            said_now.insert(seq, verdict);
        }
        if seq > since.after_seq {
            fresh.push(row);
        } else if let (Some(now), Some(&was)) = (row.verdict, memory.said.get(&seq)) {
            if now != was {
                revised.push((row, was));
            }
        }
    });
    memory.said = said_now;
    // Read BEFORE it is set: whether this call found a memory an earlier call
    // had written, which is the only answer the caller cannot get anywhere else.
    let continued = core::mem::replace(&mut memory.written, true);

    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::SELECTION_SINCE, &mut out);
    let _ = write!(
        out,
        ",\"window\":{{\"after_seq\":{},\"through_seq\":{},\"continued\":{continued}}},\"rows\":[",
        since.after_seq, since.through_seq
    );
    let mut first = true;
    for row in &fresh {
        push_seq_row(row, &mut first, &mut out);
    }
    out.push_str("],\"revised\":[");
    let mut first = true;
    for (row, was) in &revised {
        push_revised_row(row, *was, &mut first, &mut out);
    }
    out.push(']');
    crate::filter::push_ambiguous_zid_prefixes(
        verdicts.as_ref().map_or(&[], |v| v.ambiguities()),
        &mut out,
    );
    out.push_str(",\"dropped_by_limits\":");
    out.push_str(&crate::report::dropped_by_limits_json(d));
    out.push('}');
    out
}

/// One row of the since document: the selection row, with its number first.
fn push_seq_row(row: &Row, first: &mut bool, out: &mut String) {
    if !*first {
        out.push(',');
    }
    *first = false;
    out.push('{');
    if let Some(seq) = row.seq {
        let _ = write!(out, "\"seq\":{seq},");
    }
    push_coordinates(row, out);
    if let Some(verdict) = row.verdict {
        let _ = write!(out, ",\"selected\":\"{}\"", verdict.word());
    }
    out.push('}');
}

/// The captures and the reading of them that the rows below are held to.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::datagram_tests::{
        frame_carrying, init_datagram, open_datagram, sender_space, udp_packet,
    };
    use crate::exchange::tests::{
        declare_kexpr, has_suffix, request_put, request_query, response_final, response_reply,
    };
    use crate::fields_json::RowCoordinates;
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    use alloc::vec::Vec;
    use wz_codecs::wire_const::FLAG_N_N;
    use wz_codecs::wireexpr::Wireexpr;

    const LOW: [u8; 4] = [10, 0, 0, 1];
    const HIGH: [u8; 4] = [10, 0, 0, 2];

    /// A numbering that numbers every list, standing in for a handle's.
    struct EveryListNumbered;

    impl RowCoordinates for EveryListNumbered {
        fn list_id(&self, list: usize) -> Option<u64> {
            Some(list as u64)
        }

        fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
            None
        }
    }

    fn key(literal: &'static str) -> Wireexpr<'static> {
        sender_space(0, Some(literal))
    }

    /// A `Push` carrying a `MsgDel` under `keyexpr`.
    fn push_del(keyexpr: Wireexpr<'static>) -> Vec<u8> {
        let n = if has_suffix(&keyexpr) { FLAG_N_N } else { 0 };
        wz_codecs::push::Push {
            header: wz_codecs::push::Push::default().header | n,
            keyexpr,
            body: wz_codecs::push::PushVariant::CodecZenohMsgDel(
                wz_codecs::msg_del::MsgDel::default(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// A `Response` whose `Reply` carries a `MsgDel` rather than a put.
    fn response_reply_del(request_id: u64, keyexpr: Wireexpr<'static>) -> Vec<u8> {
        let n = if has_suffix(&keyexpr) { FLAG_N_N } else { 0 };
        wz_codecs::response::Response {
            header: wz_codecs::response::Response::default().header | n,
            request_id,
            keyexpr,
            body: wz_codecs::response::ResponseVariant::CodecZenohReply(wz_codecs::reply::Reply {
                body: wz_codecs::reply::ReplyVariant::CodecZenohMsgDel(
                    wz_codecs::msg_del::MsgDel::default(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// The transport `Close`, bare.
    fn close_wire() -> Vec<u8> {
        let mut wire = alloc::vec![wz_session_core::wire_const::T_MID_CLOSE];
        wire.extend_from_slice(&wz_codecs::close::Close { reason: 0x01 }.encode_to_vec());
        wire
    }

    /// One packet of the contract capture, in capture order: what it is called
    /// here, who sent it (`true` is the low address, direction A), and the record
    /// or transport message it carries.
    ///
    /// Every network record is framed in its OWN transport frame, so a row and a
    /// record are the same thing in this capture and a row's word is that one
    /// record's. The fold over several records in one row is a different
    /// claim, tested where a row is built to carry several.
    fn packets() -> Vec<(&'static str, bool, Vec<u8>)> {
        let framed = |record: Vec<u8>| frame_carrying(&record);
        alloc::vec![
            ("init-syn", true, init_datagram(false, &[])),
            ("init-ack", false, init_datagram(true, &[])),
            ("open-syn", true, open_datagram(false)),
            ("open-ack", false, open_datagram(true)),
            (
                "keepalive",
                true,
                alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE]
            ),
            ("declare", true, framed(declare_kexpr(1, "demo/declared"))),
            ("query-7", true, framed(request_query(7, key("demo/q")))),
            (
                "reply-7",
                false,
                framed(response_reply(7, key("demo/q"), b"answer"))
            ),
            ("final-7", false, framed(response_final(7))),
            (
                "push-put",
                true,
                framed(crate::datagram_tests::push(key("demo/p"), b"v"))
            ),
            ("push-del", true, framed(push_del(key("demo/p")))),
            (
                "request-put-8",
                true,
                framed(request_put(8, key("demo/p"), b"v"))
            ),
            ("final-8", false, framed(response_final(8))),
            // Two exchanges of DIFFERENT kinds open together and close in the
            // opposite order, then two more close in the order they opened: a
            // close that took its kind from the oldest exchange open, or from
            // the latest, would swap one of the pairs.
            ("query-9", true, framed(request_query(9, key("demo/q")))),
            (
                "request-put-10",
                true,
                framed(request_put(10, key("demo/p"), b"v"))
            ),
            ("final-10", false, framed(response_final(10))),
            ("final-9", false, framed(response_final(9))),
            ("query-12", true, framed(request_query(12, key("demo/q")))),
            (
                "request-put-13",
                true,
                framed(request_put(13, key("demo/p"), b"v"))
            ),
            ("final-12", false, framed(response_final(12))),
            ("final-13", false, framed(response_final(13))),
            // The request this final answers is not in the capture.
            ("final-99", false, framed(response_final(99))),
            // A query nothing closes, answered by a reply that carries a del.
            ("query-11", true, framed(request_query(11, key("demo/q")))),
            (
                "reply-del-11",
                false,
                framed(response_reply_del(11, key("demo/q")))
            ),
            ("close", true, close_wire()),
        ]
    }

    /// The names of [`packets`], in order.
    pub(crate) fn labels() -> Vec<&'static str> {
        packets().into_iter().map(|(label, _, _)| label).collect()
    }

    /// The capture: one UDP conversation, a packet every 10 ms, and the file
    /// those packets make (the field document re-reads it).
    pub(crate) fn mixed_session_with_file() -> (Dissection, Vec<u8>) {
        let wires: Vec<Vec<u8>> = packets()
            .into_iter()
            .map(|(_, from_low, wire)| {
                if from_low {
                    udp_packet(LOW, 43210, HIGH, 7447, &wire)
                } else {
                    udp_packet(HIGH, 7447, LOW, 43210, &wire)
                }
            })
            .collect();
        let rows: Vec<(u32, u32, &[u8])> = wires
            .iter()
            .enumerate()
            .map(|(i, wire)| (1, i as u32 * 10_000, wire.as_slice()))
            .collect();
        let file = crate::pcap::write(LINKTYPE_ETHERNET, &rows);
        let d = Dissection::from_capture(&file).expect("the capture reads");
        (d, file)
    }

    /// A numbering that numbers every list AND every row, as a handle's does: a
    /// row's number is its produced-index plus one, so a capture and any prefix of
    /// it number the rows they share the same way, which is what lets one memory
    /// follow a capture as it grows.
    struct EveryRowNumbered;

    impl RowCoordinates for EveryRowNumbered {
        fn list_id(&self, list: usize) -> Option<u64> {
            Some(list as u64)
        }

        fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
            None
        }

        fn row_seq(&self, _list: usize, produced: u64) -> Option<u64> {
            Some(produced + 1)
        }
    }

    /// The first `n` packets of the contract capture, read as the capture of a
    /// tap that has seen no more of them yet.
    fn contract_capture_prefix(n: usize) -> Dissection {
        let wires: Vec<Vec<u8>> = packets()
            .into_iter()
            .take(n)
            .map(|(_, from_low, wire)| {
                if from_low {
                    udp_packet(LOW, 43210, HIGH, 7447, &wire)
                } else {
                    udp_packet(HIGH, 7447, LOW, 43210, &wire)
                }
            })
            .collect();
        let rows: Vec<(u32, u32, &[u8])> = wires
            .iter()
            .enumerate()
            .map(|(i, wire)| (1, i as u32 * 10_000, wire.as_slice()))
            .collect();
        let file = crate::pcap::write(LINKTYPE_ETHERNET, &rows);
        Dissection::from_capture(&file).expect("the capture reads")
    }

    /// The since document for `d` under `selector` after `after`, with `n` rows
    /// issued (each packet of the contract capture is one row, numbered from 1).
    fn since(
        d: &Dissection,
        n: u64,
        selector: &str,
        after: u64,
        memory: &mut SelectionMemory,
    ) -> String {
        let filter = crate::filter::Filter::parse(selector).expect("the selector parses");
        selection_since_json_coordinated(
            d,
            &filter,
            &EveryRowNumbered,
            SelectionWindow {
                after_seq: after,
                through_seq: n,
            },
            memory,
        )
    }

    /// The text of the array under `key` in a since document, brackets included.
    fn array_of<'a>(doc: &'a str, key: &str) -> &'a str {
        let at = doc
            .find(&alloc::format!("\"{key}\":["))
            .unwrap_or_else(|| panic!("no {key} in {doc}"))
            + key.len()
            + 3;
        // `at` is the opening bracket itself, so the walk starts one level in.
        let mut depth = 0usize;
        for (i, c) in doc[at..].char_indices() {
            match c {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        return &doc[at..at + i + 1];
                    }
                }
                _ => {}
            }
        }
        panic!("{key} is not closed in {doc}");
    }

    /// The since documents the registry gates are held to: every word and every
    /// shape the document writes without an ambiguous prefix (the handle-level
    /// gates add that one, which needs a capture with two zids that share eight
    /// digits).
    ///
    /// One asked nothing, one that keeps every row, and the two states of one
    /// capture asked twice under `closed == no` and again under `closed == yes`,
    /// so each second document carries a revised row with its own `was`.
    pub(crate) fn since_documents_for_the_gates() -> Vec<String> {
        let (whole, _) = mixed_session_with_file();
        let n = labels().len() as u64;
        let mut docs = Vec::new();
        for selector in ["", "kind == query"] {
            docs.push(since(
                &whole,
                n,
                selector,
                0,
                &mut SelectionMemory::default(),
            ));
        }
        // Both directions of the move, so `was` arrives as two different words:
        // an exchange still open reads `yes` under `closed == no` and `no` under
        // `closed == yes`, and its close turns each into the other.
        for selector in ["closed == no", "closed == yes"] {
            let mut memory = SelectionMemory::default();
            docs.push(since(
                &contract_capture_prefix(7),
                7,
                selector,
                0,
                &mut memory,
            ));
            docs.push(since(
                &contract_capture_prefix(9),
                9,
                selector,
                7,
                &mut memory,
            ));
        }
        docs
    }

    /// FROM CURSOR ZERO IT IS THE VERDICT DOCUMENT'S ROWS, each with its number,
    /// the same words in the same order.
    #[test]
    fn from_zero_the_since_document_holds_every_row_the_verdict_document_does() {
        let (d, _) = mixed_session_with_file();
        let n = labels().len() as u64;
        for selector in ["kind == query", "replies == 0", "closed == no"] {
            let mut memory = SelectionMemory::default();
            let doc = since(&d, n, selector, 0, &mut memory);
            let said: String = array_of(&doc, "rows")
                .split("\"selected\":\"")
                .skip(1)
                .map(|rest| match rest.split('"').next() {
                    Some("yes") => 'Y',
                    Some("no") => 'N',
                    Some("undecided") => '?',
                    Some("unjudged") => 'U',
                    other => panic!("an unknown word {other:?} in {doc}"),
                })
                .collect();
            assert_eq!(said, letters(&d, selector), "{selector}: {doc}");
            assert_eq!(
                array_of(&doc, "revised"),
                "[]",
                "{selector}: nothing was said before"
            );
            assert!(
                array_of(&doc, "rows").starts_with("[{\"seq\":1,\"direction\":\"a\""),
                "{doc}"
            );
            assert!(
                doc.contains(&alloc::format!(
                    "\"window\":{{\"after_seq\":0,\"through_seq\":{n},\"continued\":false}}"
                )),
                "{doc}"
            );
        }
    }

    /// WHETHER A CALL FOUND THE SELECTOR'S MEMORY is said in the window, and it is
    /// the only way a caller holding a cursor can tell.
    ///
    /// The first call under a selector begins its memory (`false`); the next
    /// finds it (`true`). Under ONE memory slot a second selector gives the first
    /// one's up, so asking the first again begins it anew (`false`) while the
    /// cursor the caller holds is still above 0: the case the field exists for. With
    /// two slots the first selector is still held and the same call continues.
    #[test]
    fn the_window_says_whether_the_selectors_memory_was_continued_or_began() {
        let (d, _) = mixed_session_with_file();
        let n = labels().len() as u64;
        let continued = |doc: &str| {
            if doc.contains("\"continued\":true") {
                true
            } else if doc.contains("\"continued\":false") {
                false
            } else {
                panic!("no continued in the window of {doc}")
            }
        };
        let ask = |memories: &mut SelectionMemories, selector: &str, after: u64| {
            since(&d, n, selector, after, memories.for_selector(selector))
        };

        let mut one = SelectionMemories::default();
        assert_eq!(one.capacity(), 1);
        assert!(
            !continued(&ask(&mut one, "kind == query", 0)),
            "a first call begins"
        );
        assert!(
            continued(&ask(&mut one, "kind == query", n)),
            "the next call under the same selector finds its memory"
        );
        assert!(
            !continued(&ask(&mut one, "closed == no", 0)),
            "another selector begins its own"
        );
        assert!(
            !continued(&ask(&mut one, "kind == query", n)),
            "the first selector's memory was given up for the second's, and the \
             call says so although the caller's cursor is above 0"
        );
        assert_eq!(one.evictions(), 2);

        let mut two = SelectionMemories::default();
        assert_eq!(two.set_capacity(2), 2);
        ask(&mut two, "kind == query", 0);
        ask(&mut two, "closed == no", 0);
        assert!(
            continued(&ask(&mut two, "kind == query", n)),
            "with room for both, alternating selectors continue"
        );
        assert!(continued(&ask(&mut two, "closed == no", n)));
        assert_eq!(two.evictions(), 0);
    }

    /// A CURSOR LEAVES OUT THE ROWS IT PASSES, and only those.
    #[test]
    fn a_cursor_leaves_out_the_rows_it_passes() {
        let (d, _) = mixed_session_with_file();
        let n = labels().len() as u64;
        let mut memory = SelectionMemory::default();
        let doc = since(&d, n, "kind == query", 20, &mut memory);
        let rows = array_of(&doc, "rows");
        assert_eq!(rows.matches("\"seq\":").count() as u64, n - 20, "{doc}");
        assert!(rows.starts_with("[{\"seq\":21,"), "{doc}");
        assert!(!rows.contains("\"seq\":20,"), "{doc}");
        // The rows it passed were still judged, and remembered.
        assert_eq!(memory.len() as u64, n);
        // Past the end there is nothing, and that is not an error.
        let past = since(&d, n, "kind == query", n + 5, &mut memory);
        assert_eq!(array_of(&past, "rows"), "[]", "{past}");
    }

    /// AN EXCHANGE IS JUDGED AT ITS CLOSE, so the request row a cursor has passed
    /// reads a different word once the close is in the capture, and the since
    /// document says so.
    ///
    /// `closed == no` is `yes` on a request nothing has closed and `no` on one
    /// something has. The first document is taken when the capture ends at the
    /// request; the second when it also holds the reply and the close. The
    /// request row is numbered 7 in both; the second document writes the two
    /// rows after it as new, and the request again as REVISED, with the word it
    /// read before beside the one it reads now.
    #[test]
    fn the_close_of_an_exchange_revises_the_request_row_the_cursor_passed() {
        let mut memory = SelectionMemory::default();
        let before = contract_capture_prefix(7);
        let first = since(&before, 7, "closed == no", 0, &mut memory);
        assert!(
            array_of(&first, "rows").contains(
                "{\"seq\":7,\"direction\":\"a\",\"list_id\":0,\"anchor\":6,\"batch_index\":0,\
                 \"selected\":\"yes\"}"
            ),
            "the request is unclosed, so it is open: {first}"
        );
        assert_eq!(array_of(&first, "revised"), "[]", "{first}");

        let after = contract_capture_prefix(9);
        let second = since(&after, 9, "closed == no", 7, &mut memory);
        assert_eq!(
            array_of(&second, "rows"),
            "[{\"seq\":8,\"direction\":\"b\",\"list_id\":0,\"anchor\":7,\"batch_index\":0,\
             \"selected\":\"undecided\"},\
             {\"seq\":9,\"direction\":\"b\",\"list_id\":0,\"anchor\":8,\"batch_index\":0,\
             \"selected\":\"no\"}]",
            "{second}"
        );
        assert_eq!(
            array_of(&second, "revised"),
            "[{\"seq\":7,\"direction\":\"a\",\"list_id\":0,\"anchor\":6,\"batch_index\":0,\
             \"selected\":\"no\",\"was\":\"yes\"}]",
            "{second}"
        );
    }

    /// NOTHING IS REVISED THAT DID NOT CHANGE: the same capture asked twice says
    /// the same words, and the second answer names no row.
    #[test]
    fn a_row_whose_word_did_not_move_is_not_revised() {
        let (d, _) = mixed_session_with_file();
        let n = labels().len() as u64;
        let mut memory = SelectionMemory::default();
        let _ = since(&d, n, "closed == no", 0, &mut memory);
        let again = since(&d, n, "closed == no", n, &mut memory);
        assert_eq!(array_of(&again, "rows"), "[]", "{again}");
        assert_eq!(array_of(&again, "revised"), "[]", "{again}");
        // And a cursor BEHIND the memory is no revision either: the rows it lists
        // are new to the caller and are written with their words.
        let behind = since(&d, n, "closed == no", 20, &mut memory);
        assert_eq!(array_of(&behind, "revised"), "[]", "{behind}");
    }

    /// A DECLARATION THAT ARRIVES AFTER THE REFERENCE TO IT DOES NOT MOVE THE
    /// REFERENCE'S ROW, in the construction a datagram link gives.
    ///
    /// The question a consumer asked: can a verdict already given change when a
    /// keyexpr declaration is resolved late? Here a `Push` names key id 1, which
    /// nothing has declared, and the declaration of id 1 follows in a later packet.
    /// The row reads `undecided` under a key term in the first document and the
    /// same in the second, and nothing is revised: a declaration is applied to the
    /// frames at or after the packet it went past at, and not to the ones before
    /// it (`crate::fields_json`'s anchor rule). That is a fact of THIS
    /// construction; the cases where a decode happens later than its packet (a
    /// held stream segment) are not claimed, and `revised` reports whatever moved
    /// whichever way it did.
    #[test]
    fn a_declaration_after_the_reference_does_not_move_the_reference_row() {
        let capture_of = |with_declaration: bool| {
            let mut wires: Vec<(bool, Vec<u8>)> = alloc::vec![
                (true, init_datagram(false, &[])),
                (false, init_datagram(true, &[])),
                (true, open_datagram(false)),
                (false, open_datagram(true)),
                (
                    true,
                    frame_carrying(&crate::datagram_tests::push(sender_space(1, None), b"v")),
                ),
            ];
            if with_declaration {
                wires.push((true, frame_carrying(&declare_kexpr(1, "demo/declared"))));
            }
            let packets: Vec<Vec<u8>> = wires
                .into_iter()
                .map(|(from_low, wire)| {
                    if from_low {
                        udp_packet(LOW, 43210, HIGH, 7447, &wire)
                    } else {
                        udp_packet(HIGH, 7447, LOW, 43210, &wire)
                    }
                })
                .collect();
            let rows: Vec<(u32, u32, &[u8])> = packets
                .iter()
                .enumerate()
                .map(|(i, wire)| (1, i as u32 * 10_000, wire.as_slice()))
                .collect();
            let file = crate::pcap::write(LINKTYPE_ETHERNET, &rows);
            Dissection::from_capture(&file).expect("the capture reads")
        };
        let mut memory = SelectionMemory::default();
        let before = since(
            &capture_of(false),
            5,
            "key == demo/declared",
            0,
            &mut memory,
        );
        let word_of_the_push = |doc: &str| {
            array_of(doc, "rows")
                .split("{\"seq\":5,")
                .nth(1)
                .and_then(|rest| rest.split("\"selected\":\"").nth(1))
                .and_then(|rest| rest.split('"').next())
                .map(String::from)
        };
        let first = word_of_the_push(&before).expect("the push is row 5");
        let after = since(&capture_of(true), 6, "key == demo/declared", 5, &mut memory);
        assert_eq!(
            array_of(&after, "revised"),
            "[]",
            "the reference row was \"{first}\" and a later declaration moved it: {after}"
        );
    }

    /// With no selector there are no words: the rows carry their coordinates and
    /// no `selected`, nothing is revised and nothing is remembered.
    #[test]
    fn an_empty_selector_says_no_word_and_remembers_none() {
        let (d, _) = mixed_session_with_file();
        let n = labels().len() as u64;
        let mut memory = SelectionMemory::default();
        let _ = since(&d, n, "closed == no", 0, &mut memory);
        assert!(!memory.is_empty());
        let doc = since(&d, n, "", 0, &mut memory);
        assert!(!doc.contains("\"selected\""), "{doc}");
        assert!(!doc.contains("\"was\""), "{doc}");
        assert!(memory.is_empty(), "no selector, no words to remember");
    }

    /// The selection document's word for every row of `d`, one letter each:
    /// `Y` yes, `N` no, `?` undecided, `U` unjudged.
    pub(crate) fn letters(d: &Dissection, selector: &str) -> String {
        let filter = crate::filter::Filter::parse(selector).expect("the selector parses");
        let doc = selection_json_where_coordinated(d, &filter, &EveryListNumbered);
        doc.split("\"selected\":\"")
            .skip(1)
            .map(|rest| match rest.split('"').next() {
                Some("yes") => 'Y',
                Some("no") => 'N',
                Some("undecided") => '?',
                Some("unjudged") => 'U',
                other => panic!("{selector}: an unknown word {other:?} in {doc}"),
            })
            .collect()
    }

    /// Say which packets differ, by name, rather than leaving two strings of
    /// letters to be lined up by eye.
    fn assert_rows(selector: &str, expected: &str, got: &str) {
        let names = labels();
        assert_eq!(
            expected.chars().count(),
            names.len(),
            "{selector}: the table must have one letter per packet"
        );
        assert_eq!(
            got.chars().count(),
            names.len(),
            "{selector}: one row per packet, or the capture is not the one the table describes: {got}"
        );
        let wrong: Vec<String> = names
            .iter()
            .zip(expected.chars().zip(got.chars()))
            .filter(|(_, (want, have))| want != have)
            .map(|(name, (want, have))| alloc::format!("{name}: wanted {want}, got {have}"))
            .collect();
        assert!(
            wrong.is_empty(),
            "{selector}: {wrong:#?}\n  wanted {expected}\n  got    {got}"
        );
    }

    /// THE REPRODUCTION, AND THE KIND CONTRACT ROW BY ROW.
    ///
    /// Each line is one selector over the one capture above, and each letter is
    /// the packet of the same position in [`packets`]: the first six are the
    /// transport and the declaration and the last is the `Close`, which carry
    /// no record and so answer every term about one as an absent field (`N`,
    /// and `Y` under its negation), and `final-99` is a close whose request the
    /// capture does not hold, so every record term over it is `?`.
    ///
    /// The consumer's defect is the `Y` at `query-7`: the row was `U`, with every
    /// request and every close of a query, a `Push` carrying a del, and a `Reply`
    /// carrying one. The `N` at `final-8` is the other half of the contract: a
    /// close FOLLOWS ITS EXCHANGE, so under `kind == query` the close of a put
    /// exchange is `no`, not unjudged.
    #[test]
    fn a_request_a_response_final_and_every_reply_are_judged_by_the_kind_they_carry() {
        let (d, _) = mixed_session_with_file();
        for (selector, expected) in [
            ("kind == query", "NNNNNNYNYNNNNYNNYYNYN?YNN"),
            ("kind == put", "NNNNNNNNNYNYYNYYNNYNY?NNN"),
            ("kind == del", "NNNNNNNNNNYNNNNNNNNNN?NNN"),
            ("not kind == put", "YYYYYYYYYNYNNYNNYYNYN?YYY"),
            ("kind == reply", "NNNNNNNYNNNNNNNNNNNNN?NYN"),
        ] {
            assert_rows(selector, expected, &letters(&d, selector));
        }
    }

    /// A CLOSE ANSWERS EVERY FIELD AS THE EXCHANGE IT TERMINATES DOES, not only
    /// `kind`.
    ///
    /// A `ResponseFinal` names no keyexpr and no kind, so under `key ==` it could
    /// only ever have been unjudged or wrongly `no`; it carries the exchange's
    /// verdict instead, and the exchange's `dir` is its requester's, as it is on
    /// the exchange plane (`crate::exchange::OpenExchange::direction`). The
    /// replies are records and answer for themselves: `reply-7` is `N` under
    /// `dir == a` because B sent it, while `final-7`, B's close of A's query, is
    /// `Y`.
    #[test]
    fn a_response_final_answers_every_field_as_the_exchange_it_terminates() {
        let (d, _) = mixed_session_with_file();
        for (selector, expected) in [
            ("key == demo/p", "NNNNNNNNNYYYYNYYNNYNY?NNN"),
            ("dir == a", "YNYNYYYNYYYYYYYYYYYYYYYNY"),
            ("kind == query or kind == del", "NNNNNNYNYNYNNYNNYYNYN?YNN"),
            (
                "kind == query and key == demo/p",
                "NNNNNNNNNNNNNNNNNNNNN?NNN",
            ),
        ] {
            assert_rows(selector, expected, &letters(&d, selector));
        }
    }

    /// THE OUTCOME TERMS DECIDE ON THE ROWS OF AN EXCHANGE AND ONLY THERE.
    ///
    /// `replies`, `closed` and `completion` are properties of how an exchange
    /// turned out, so the two rows that are its ends can answer them and a
    /// record cannot: a `Push` and a `Reply` read `?` under `replies == 0`, the
    /// word for "the capture does not carry what deciding needs", and not `N`.
    /// `query-11` is unclosed and `final-99` is an orphan: the first is `Y`
    /// under `closed == no`, and the second has no exchange to be an end of.
    #[test]
    fn the_outcome_terms_decide_on_the_rows_of_an_exchange_and_nowhere_else() {
        let (d, _) = mixed_session_with_file();
        for (selector, expected) in [
            ("replies == 0", "NNNNNNN?N??YYYYYYYYYY?N?N"),
            ("closed == no", "NNNNNNN?N??NNNNNNNNNN?Y?N"),
            (
                "kind == query and replies == 0",
                "NNNNNNNNNNNNNYNNYYNYN?NNN",
            ),
        ] {
            assert_rows(selector, expected, &letters(&d, selector));
        }
    }

    /// A `Request` with a `Del` body, which no zenoh peer sends (upstream's
    /// request body is a query and nothing else) and this reader's codec
    /// decodes, so the dissection classifies it by its body.
    fn request_del(rid: u64, keyexpr: Wireexpr<'static>) -> Vec<u8> {
        let n = if has_suffix(&keyexpr) { FLAG_N_N } else { 0 };
        wz_codecs::request::Request {
            header: wz_codecs::request::Request::default().header | n,
            rid,
            keyexpr,
            body: wz_codecs::request::RequestVariant::CodecZenohMsgDel(
                wz_codecs::msg_del::MsgDel::default(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// What a generated packet is to the exchange plane.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Role {
        /// The `Request` that opens an exchange.
        Request,
        /// A `ResponseFinal` that closes an exchange the capture opened.
        Close,
        /// A `ResponseFinal` whose request the capture never carried.
        Orphan,
        /// A record that is no end of an exchange: a push or a reply.
        Other,
    }

    /// A small deterministic generator, so a failing capture is rebuilt by its
    /// seed.
    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % n
        }
    }

    /// What `crate::exchange::tests::dissect` takes: for each record, who sent
    /// it, when, and its bytes.
    type Records = Vec<(bool, Option<u64>, Vec<u8>)>;

    /// A capture of forty network records chosen by `seed`, with what each one is
    /// to the exchange plane.
    ///
    /// Requests of the three kinds on a few keys, request ids drawn from a
    /// small range so one is sometimes opened again before it closed (the first
    /// exchange is then judged unclosed), replies and closes for open exchanges,
    /// closes of exchanges that were never opened, and pushes. Some exchanges are
    /// left open when the capture ends.
    fn generated(seed: u64) -> (Records, Vec<Role>) {
        let keys = ["demo/a", "demo/b", "other/c"];
        let mut rng = Lcg(seed);
        // Which of the request ids 1..=6 an exchange is open under.
        let mut is_open = [false; 7];
        let mut records = Vec::new();
        let mut roles = Vec::new();
        for step in 0..40u64 {
            let at = Some(1_000 + step * 7);
            let pick = rng.below(10);
            let open: Vec<u64> = (1..=6).filter(|rid| is_open[*rid as usize]).collect();
            if pick <= 3 {
                let rid = 1 + rng.below(6);
                let at_key = key(keys[rng.below(3) as usize]);
                let wire = match rng.below(3) {
                    0 => request_query(rid, at_key),
                    1 => request_put(rid, at_key, b"v"),
                    _ => request_del(rid, at_key),
                };
                is_open[rid as usize] = true;
                records.push((true, at, wire));
                roles.push(Role::Request);
            } else if pick <= 5 && !open.is_empty() {
                let rid = open[rng.below(open.len() as u64) as usize];
                let at_key = key(keys[rng.below(3) as usize]);
                records.push((false, at, response_reply(rid, at_key, b"r")));
                roles.push(Role::Other);
            } else if pick <= 7 && !open.is_empty() {
                let rid = open[rng.below(open.len() as u64) as usize];
                is_open[rid as usize] = false;
                records.push((false, at, response_final(rid)));
                roles.push(Role::Close);
            } else if pick == 8 {
                records.push((false, at, response_final(90 + rng.below(5))));
                roles.push(Role::Orphan);
            } else {
                let at_key = key(keys[rng.below(3) as usize]);
                let wire = if rng.below(2) == 0 {
                    crate::datagram_tests::push(at_key, b"p")
                } else {
                    push_del(at_key)
                };
                records.push((true, at, wire));
                roles.push(Role::Other);
            }
        }
        (records, roles)
    }

    /// THE TWO PLANES COUNT THE SAME EXCHANGES, FOR ANY SELECTOR, ON ANY CAPTURE.
    ///
    /// The invariant that was broken: the exchange plane counted seven queries in
    /// a capture whose seven request rows the row plane left unjudged. Held on the
    /// capture the contract tests read and on forty generated ones, against
    /// selectors on the kind, the key, the direction and the outcome:
    ///
    /// * the `yes` rows of `Request` records are `ExchangeTable::requests`, and
    ///   their `no` and `undecided` rows are `Selection::rejected` and
    ///   `Selection::undecided`;
    /// * the `yes` rows of closing `ResponseFinal` records are
    ///   `ExchangeTable::completed`;
    /// * a `ResponseFinal` the capture never opened is `unjudged`, not `no`.
    ///
    /// The count of ROWS and the count of EXCHANGES agree here because each
    /// packet carries one record. A row built to carry several folds them, and
    /// `a_row_carrying_a_push_and_a_request_folds_what_both_planes_said` holds
    /// that.
    #[test]
    fn the_row_plane_and_the_exchange_plane_count_the_same_exchanges_for_any_selector() {
        let selectors = [
            "kind == query",
            "kind == put",
            "kind == del",
            "not kind == put",
            "kind == reply",
            "key == demo/a",
            "key == demo/**",
            "dir == a",
            "dir == b",
            "kind == query and key == demo/b",
            "kind == query or kind == del",
            "replies == 0",
            "replies >= 1",
            "closed == no",
            "closed == yes",
            "kind == put and completion >= 14",
            "bytes > 0",
            "first_reply >= 0",
        ];
        let mut captures: Vec<(Dissection, Vec<Role>)> = Vec::new();
        for seed in 0..40 {
            let (records, roles) = generated(seed);
            captures.push((crate::exchange::tests::dissect(&records), roles));
        }
        let mut closes_counted = 0usize;
        let mut unclosed_counted = 0usize;
        let mut orphans_seen = 0usize;
        let mut undecided_counted = 0usize;
        for (seed, (d, roles)) in captures.iter().enumerate() {
            for selector in selectors {
                let filter = crate::filter::Filter::parse(selector).expect("parses");
                let table = crate::exchange::exchanges_where(d, &filter);
                let rows: Vec<char> = letters(d, selector).chars().collect();
                assert_eq!(rows.len(), roles.len(), "seed {seed}: one row per record");

                let count = |role: Role, word: char| {
                    rows.iter()
                        .zip(roles)
                        .filter(|(have, is)| **is == role && **have == word)
                        .count()
                };
                assert_eq!(
                    count(Role::Request, 'Y'),
                    table.requests(),
                    "seed {seed}, {selector}: yes request rows against exchanges counted"
                );
                assert_eq!(
                    count(Role::Request, 'N'),
                    table.selection().rejected,
                    "seed {seed}, {selector}: no request rows against exchanges rejected"
                );
                assert_eq!(
                    count(Role::Request, '?'),
                    table.selection().undecided,
                    "seed {seed}, {selector}: undecided request rows against exchanges undecided"
                );
                assert_eq!(
                    count(Role::Close, 'Y'),
                    table.completed(),
                    "seed {seed}, {selector}: yes close rows against exchanges completed"
                );
                // An orphan close is JUDGED, and every term about its record is
                // undecided: it answers as the request it closes, which the
                // capture does not hold. `dir` is the one record fact it names
                // (the requester is the end it travels back to), so a `dir`
                // selector decides it.
                let orphans = roles.iter().filter(|r| **r == Role::Orphan).count();
                assert_eq!(
                    count(Role::Orphan, 'U'),
                    0,
                    "seed {seed}, {selector}: an orphan close is judged"
                );
                if !selector.starts_with("dir") {
                    assert_eq!(
                        count(Role::Orphan, '?'),
                        orphans,
                        "seed {seed}, {selector}: an orphan close's record terms are undecided"
                    );
                }
                closes_counted += table.completed();
                unclosed_counted += table.unclosed();
                undecided_counted += table.selection().undecided;
                orphans_seen += orphans;
            }
        }
        // Anti-vacuity: the population exercised closed exchanges, exchanges the
        // capture never closed, orphans, and a selector the exchange plane could
        // not decide; the equalities above were not satisfied by zeros.
        assert!(
            closes_counted > 100,
            "closed exchanges counted: {closes_counted}"
        );
        assert!(
            unclosed_counted > 50,
            "unclosed exchanges counted: {unclosed_counted}"
        );
        assert!(orphans_seen > 100, "orphan closes judged: {orphans_seen}");
        assert!(
            undecided_counted > 0,
            "undecided exchanges: {undecided_counted}"
        );
    }

    /// The same equalities on the capture the contract tests read, which has the
    /// shapes a generator draws only by chance: a close that follows another
    /// exchange's close, two exchanges of different kinds open together, and a
    /// `Reply` that carries a `Del`.
    #[test]
    fn the_two_planes_agree_on_the_contract_capture_too() {
        let (d, _) = mixed_session_with_file();
        let roles: Vec<Role> = labels()
            .into_iter()
            .map(|label| match label {
                l if l.starts_with("query-") || l.starts_with("request-put-") => Role::Request,
                "final-99" => Role::Orphan,
                l if l.starts_with("final-") => Role::Close,
                _ => Role::Other,
            })
            .collect();
        for selector in [
            "kind == query",
            "kind == put",
            "kind == del",
            "key == demo/p",
            "dir == a",
            "replies == 0",
            "closed == no",
        ] {
            let filter = crate::filter::Filter::parse(selector).expect("parses");
            let table = crate::exchange::exchanges_where(&d, &filter);
            let rows: Vec<char> = letters(&d, selector).chars().collect();
            let count = |role: Role| {
                rows.iter()
                    .zip(&roles)
                    .filter(|(have, is)| **is == role && **have == 'Y')
                    .count()
            };
            assert_eq!(count(Role::Request), table.requests(), "{selector}");
            assert_eq!(count(Role::Close), table.completed(), "{selector}");
        }
    }

    /// A ROW THAT CARRIES RECORDS OF BOTH PLANES FOLDS WHAT BOTH SAID.
    ///
    /// One frame holding a `Push` (judged as a record) and a `Request` (judged as
    /// an exchange), so the row has a verdict from each plane. Any yes makes the
    /// row yes, all no makes it no, and anything else is undecided: the rule the
    /// consumer set, applied across the two planes as it is within one.
    ///
    /// The last two lines are the ones that need both: `replies == 1` is `no` for
    /// the request and unknown for the push, and a fold that dropped the
    /// exchange's `no` (or the push's unknown) would call the row `N` (or `Y`).
    #[test]
    fn a_row_carrying_a_push_and_a_request_folds_what_both_planes_said() {
        let mut record = crate::datagram_tests::push(key("demo/p"), b"v");
        record.extend_from_slice(&request_query(5, key("demo/q")));
        let d = crate::exchange::tests::dissect(&[(true, Some(1_000), record)]);
        for (selector, expected) in [
            ("kind == put", "Y"),
            ("kind == query", "Y"),
            ("kind == del", "N"),
            ("key == nothing/here", "N"),
            ("replies == 0", "Y"),
            ("replies == 1", "?"),
            ("closed == yes", "?"),
        ] {
            assert_eq!(letters(&d, selector), expected, "{selector}");
        }
    }
}

/// What the per-selector memories keep and give up.
#[cfg(test)]
mod memories_tests {
    use super::*;
    use crate::fields_json::RowVerdict;

    fn said(memories: &mut SelectionMemories, selector: &str, row: u64) {
        memories
            .for_selector(selector)
            .said
            .insert(row, RowVerdict::Yes);
    }

    fn held(memories: &mut SelectionMemories, selector: &str) -> usize {
        memories.for_selector(selector).len()
    }

    /// One memory is the default and a second selector empties it, which is how a
    /// handle behaved before there were several.
    #[test]
    fn one_memory_is_emptied_by_another_selector() {
        let mut m = SelectionMemories::default();
        assert_eq!(m.capacity(), 1);
        said(&mut m, "key == demo/a", 1);
        assert_eq!(held(&mut m, "key == demo/a"), 1);
        assert_eq!(held(&mut m, "key == demo/b"), 0);
        assert_eq!(held(&mut m, "key == demo/a"), 0, "a was given up");
        assert_eq!(m.len(), 1);
    }

    /// With two, each selector keeps what it said, and a third gives up the least
    /// recently used one.
    #[test]
    fn two_memories_each_keep_their_words_and_the_oldest_goes() {
        let mut m = SelectionMemories::default();
        assert_eq!(m.set_capacity(2), 2);
        said(&mut m, "a", 1);
        said(&mut m, "b", 2);
        said(&mut m, "a", 3);
        assert_eq!(held(&mut m, "a"), 2);
        assert_eq!(held(&mut m, "b"), 1);
        // `b` was asked last, so `a` is the oldest and `c` takes its place.
        assert_eq!(held(&mut m, "c"), 0);
        assert_eq!(m.len(), 2);
        assert_eq!(held(&mut m, "b"), 1, "b was kept");
        assert_eq!(held(&mut m, "a"), 0, "a was given up");
    }

    /// The count is held to its bounds, and lowering it drops the oldest.
    #[test]
    fn the_capacity_is_bounded_and_lowering_drops_the_oldest() {
        let mut m = SelectionMemories::default();
        assert_eq!(m.set_capacity(0), 1);
        assert_eq!(m.set_capacity(usize::MAX), crate::MAX_SELECTOR_MEMORIES);
        m.set_capacity(3);
        said(&mut m, "a", 1);
        said(&mut m, "b", 2);
        said(&mut m, "c", 3);
        assert_eq!(
            m.evictions(),
            0,
            "nothing was given up while there was room"
        );
        assert_eq!(m.set_capacity(1), 1);
        assert_eq!(m.len(), 1);
        assert_eq!(m.evictions(), 2, "lowering the count gave up two");
        assert_eq!(held(&mut m, "c"), 1, "the newest is the one kept");
    }
}

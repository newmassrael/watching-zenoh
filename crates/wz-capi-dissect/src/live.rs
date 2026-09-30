// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2102 (open-debt item 524) — the LIVE half of the dissection ABI: a handle
//! that keeps a dissection alive across calls, is fed packet by packet, and
//! hands decoded messages back as FIXED-LAYOUT BINARY RECORDS.
//!
//! # The gap this closes
//!
//! Every other door in this library takes a whole capture and returns a JSON
//! document. That is the right shape for a file — it ends, so one call can read
//! all of it — and it is the wrong shape for a link, which does not. A consumer
//! watching a running system had two options and neither is a live tap: hand
//! the same growing buffer in again and pay a full re-dissection per call, or
//! cut the stream into windows and lose every message that straddles a cut.
//!
//! Nothing was missing from the engine. `wz_capture::Dissection` has been fed
//! packet at a time since R311y594 (`push_packet_at`), and
//! `DissectionLimits::for_live_tap` is the configuration that makes an endless
//! feed safe. What was missing is the door.
//!
//! # Why the records are BINARY, alone among this ABI's outputs
//!
//! The crate doc argues at length for handing back a self-describing document
//! rather than a struct tree, and that argument is about SHAPE STABILITY: a
//! walker added to the field tree must not be an ABI break. It does not reach
//! here, because these records carry no walker output. They are the handful of
//! scalars that say a message arrived — when, on which flow, which way, how
//! long, what kind — and that set is the transport's, not the dissector's.
//!
//! What does reach here is cost. A live tap renders per message, at line rate;
//! serialising each one to JSON and parsing it back is work proportional to the
//! traffic, paid twice, for facts that are eight fixed fields. A consumer that
//! wants the field tree of one message still asks for it by name
//! ([`crate::wz_dissect_transport_message`]) and pays for that one.
//!
//! # The identity problem this module is really about
//!
//! Draining incrementally means remembering what has already been taken, and
//! the naive bookmark — an index into a flow's message list — is WRONG here in
//! a way that is silent. A bounded dissection trims from the FRONT
//! (`MessageList::discard_oldest`) and evicts whole flows, so an index means
//! something different after every trim.
//!
//! Two facts fix it, and both were added for this:
//!
//! * `MessageList::produced` — messages EVER appended to a list, which no trim
//!   moves. A watermark stated against it survives everything a bound does.
//! * `wz_capture::MessageListOrigin` — which list, said in the wire's own terms
//!   rather than by position, so a name survives a flow being evicted from the
//!   middle of its table or a QUIC stream being appended to its.
//!
//! With those, `produced - len` is the produced-index of the oldest message
//! still held, and a watermark below it is EXACTLY the count that was discarded
//! before this consumer reached it. That number is reported
//! ([`LiveDissection::lost`]) rather than swallowed, on this workspace's
//! standing rule: a bound that takes something away and does not say so reports
//! a floor as a total.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use wz_capture::link::FlowKey;
use wz_capture::{
    AnchorSpace, CaptureCursor, CaptureError, Dissection, DissectionLimits, FollowError,
    MessageListOrigin, ScoutingDatagram,
};
use wz_session_core::passive::{Direction, PassiveFrame};

/// The `origin` a SCOUTING record carries.
///
/// Not a `MessageListOrigin` code, because the scouting list is not one of that
/// enumeration's lists: it is a flow's pre-session list, walked by nothing that
/// walks `Dissection::message_lists_with_origin`, and adding it there would
/// hand Scout and Hello to every census plane that folds transport messages.
/// So this door names it itself, as the next number after the five that
/// [`origin_code`] assigns.
pub const ORIGIN_SCOUTING: u8 = 6;

/// R2102 — a message this reader could not decode. Not a variant of
/// `InboundFrame` at all — the failure lives in the `Result` around it — so its
/// code is assigned here, at the one place that holds both halves.
pub const KIND_UNDECODABLE: u8 = 0;

/// The frame's own header declared a length past what the session's InitAck
/// agreed to. A protocol violation by the sender; the message still decoded.
pub const FLAG_EXCEEDS_NEGOTIATED_BATCH: u32 = 1 << 0;
/// This message cannot occur on the link that carried it, so it was reported
/// and NOT folded into the session context.
pub const FLAG_INADMISSIBLE_ON_LINK: u32 = 1 << 1;
/// The first message after the reader recovered its framing. Everything between
/// the loss and here was skipped.
pub const FLAG_AFTER_RESYNC: u32 = 1 << 2;

/// The sentinel a record carries when the caller supplied no clock reading.
///
/// Not zero: zero is a legal instant, and a live tap whose clock genuinely
/// starts at zero must not be reported as having no clock at all.
pub const NO_TIMESTAMP: u64 = u64::MAX;

/// R2102 (open-debt item 524) — ONE decoded transport message, as the bytes a C
/// consumer receives.
///
/// 56 bytes, 8-aligned. `#[repr(C)]` with explicitly sized fields and the
/// widest first, so the
/// layout is the one the header declares on every ABI this library is built
/// for. Its size is pinned on both sides of the boundary — see
/// `the_record_layout_is_the_one_the_header_declares` here and the matching
/// `sizeof` assertion in `tests/c_abi_consumer.c`.
///
/// The name carries a VERSION and that is the whole compatibility story for
/// this type: field names are read from a header, not by name at runtime, so a
/// layout change is a new struct and a new door rather than a silently
/// different meaning for the same one.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WzDissectRecord {
    /// The reader's clock AS OF this message, in nanoseconds, or
    /// [`NO_TIMESTAMP`] if it was never set.
    ///
    /// Two things a consumer has to know, and they look alike:
    ///
    /// * the clock is in MILLISECONDS, so the value is the nanosecond reading
    ///   that was pushed, truncated to the millisecond it fell in and widened
    ///   back. Narrowing at the boundary rather than in the caller keeps ONE
    ///   rounding rule in the system;
    /// * a push carrying [`NO_TIMESTAMP`] leaves the clock WHERE IT STOOD, so a
    ///   record can carry the instant of an earlier packet. That is a different
    ///   fact from having no clock at all, and only the second reports the
    ///   sentinel — see
    ///   `a_clock_that_never_moved_is_told_apart_from_one_that_stopped`.
    pub ts_ns: u64,
    /// The CONVERSATION: a number this handle assigns each flow it sees,
    /// counting from zero in order of first appearance. Stable for the life of
    /// the handle and meaningless outside it.
    ///
    /// Everything one UDP conversation carries shares this — the cleartext
    /// messages and whatever was recovered from inside QUIC alike — because
    /// that is what a reader grouping by "connection" means.
    pub flow_id: u64,
    /// The COORDINATE SPACE: a number per message LIST, on the same counter.
    ///
    /// # Why this is not [`Self::flow_id`]
    ///
    /// Two records' anchors are comparable exactly when this matches. A flow
    /// can carry several lists at once, and for the QUIC-stream ones the
    /// anchors are byte offsets that each start at zero — so a consumer
    /// grouping by `(flow_id, origin)` would put two streams' byte 0 in one
    /// space and read two distinct messages as one. That is the same silent
    /// wrongness [`Self::anchor_space`] exists to prevent, one level down, and
    /// [`origin_code`] cannot express it because the stream's identity is a
    /// number the wire chose.
    ///
    /// It also moves when a list is REPLACED: a flow evicted and reopened under
    /// the same 5-tuple starts a new stream whose offsets restart, so it gets a
    /// new id rather than inheriting coordinates that no longer mean anything.
    pub list_id: u64,
    /// Where the message sits, read according to [`Self::anchor_space`], and
    /// comparable only against another record with the same [`Self::list_id`].
    pub anchor: u64,
    /// The length the framing unit DECLARED, in bytes.
    pub unit_len: u64,
    /// Which message of its framing unit this is, counting from zero. A batch
    /// puts several messages at one anchor and this is what keeps them apart.
    pub batch_index: u32,
    /// Byte offset of this message within its framing unit.
    pub unit_offset: u32,
    /// 0 = direction A (conventionally the initiator), 1 = B.
    pub direction: u8,
    /// 0 = [`Self::anchor`] is a packet index, 1 = a byte offset within one
    /// direction of this list's stream. They are small numbers either way and
    /// cannot be told apart by looking, which is why the record says.
    pub anchor_space: u8,
    /// Which list of this flow the message came out of — see
    /// [`origin_code`].
    pub origin: u8,
    /// The message kind: [`KIND_UNDECODABLE`], or
    /// `wz_session_core::inbound::InboundFrame::kind_code`.
    pub kind: u8,
    /// `FLAG_*` bits. Zero for an ordinary message.
    pub flags: u32,
}

/// R2102 — the number a record's `origin` field carries.
///
/// A function beside the enum's consumer rather than a method on it: the codes
/// are this ABI's, and `wz-capture` must not grow a field whose only meaning is
/// what a C header says about it.
pub fn origin_code(origin: MessageListOrigin) -> u8 {
    match origin {
        MessageListOrigin::Stream => 1,
        MessageListOrigin::Datagram => 2,
        MessageListOrigin::QuicStream(_) => 3,
        MessageListOrigin::QuicDatagram => 4,
        MessageListOrigin::Serial => 5,
    }
}

/// Which FLOW a list belongs to, for the purpose of handing out
/// [`WzDissectRecord::flow_id`].
///
/// The QUIC lists fold into the datagram flow they were recovered from, because
/// that is what a consumer means by "the flow": one UDP conversation, whatever
/// this reader managed to open inside it. The record's `origin` is what says
/// which half of it a message came from.
fn flow_table(origin: MessageListOrigin) -> u8 {
    match origin {
        MessageListOrigin::Stream => 0,
        MessageListOrigin::Datagram
        | MessageListOrigin::QuicStream(_)
        | MessageListOrigin::QuicDatagram => 1,
        MessageListOrigin::Serial => 2,
    }
}

/// What this consumer has taken from one list, and what it last saw there.
#[derive(Debug, Clone)]
struct Mark {
    /// The produced-index up to which records have been handed out. Everything
    /// below this has been delivered or accounted as lost.
    drained: u64,
    /// `MessageList::produced` as of the last walk. Held so that a list which
    /// DISAPPEARS can still be accounted: the difference against `drained` is
    /// what went with it.
    seen: u64,
    /// The id this list's records carry as [`WzDissectRecord::list_id`].
    ///
    /// Kept on the mark rather than in a map of its own because it is born and
    /// dies with the watermark: a slot whose `produced` went backwards is a
    /// different list, and the round that resets the watermark is exactly the
    /// round that must hand out a new coordinate space.
    list_id: u64,
    /// The produced-index up to which this handle has given messages a row
    /// sequence number. A different watermark from `drained`, and it has to be:
    /// a drain into a small buffer leaves `drained` behind while the rows of
    /// those messages are already being issued by the field document.
    numbered: u64,
    /// The sequence numbers given to the messages still held, as runs. See
    /// [`SeqRun`].
    runs: VecDeque<SeqRun>,
}

/// A stretch of one list's messages that were given CONSECUTIVE row sequence
/// numbers, because one walk saw them all for the first time.
///
/// # Why runs and not one offset per list
///
/// Sequence numbers are handed out in the order the handle first sees rows, and
/// two lists grow in interleaved order: a message of list A, then two of list B,
/// then another of A. A list's numbers are therefore NOT `produced + constant`,
/// and a single offset would give the second message of A the number of the
/// first message of B. One run per walk that found something new keeps the map
/// exact, and adjacent runs that continue each other are joined, so a handle
/// with one busy list holds one run.
///
/// A run is dropped, or cut from the front, as its messages are trimmed away, so
/// the map is never larger than the number of messages still held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeqRun {
    /// Produced-index of the run's first message.
    first_produced: u64,
    /// The sequence number of that message; the run's others follow by one.
    first_seq: u64,
    /// How many messages.
    len: u64,
}

impl SeqRun {
    /// The sequence number of the message at `produced`, if the run holds it.
    fn seq_of(&self, produced: u64) -> Option<u64> {
        let offset = produced.checked_sub(self.first_produced)?;
        (offset < self.len).then(|| self.first_seq + offset)
    }
}

/// The sequence number of the message at `produced`, among `runs`.
///
/// `runs` is in produced order and disjoint, so a binary search on the run whose
/// first index is at or below `produced` finds the only candidate.
fn seq_in_runs(runs: &[SeqRun], produced: u64) -> Option<u64> {
    let after = runs.partition_point(|run| run.first_produced <= produced);
    runs.get(after.checked_sub(1)?)?.seq_of(produced)
}

/// What [`LiveDissection::reassembled_bytes`] answers.
///
/// Three answers and not [`wz_capture::MessageBytes`]'s three, because the
/// question is narrower: the record either completed a chain or it did not, and
/// only a record that DID can have lost its buffer since.
pub enum ReassembledBytes<'a> {
    /// The buffer the chain was joined in — the referent of the row's
    /// `above_transport.fields` and `above_transport.carried` spans.
    Joined(&'a [u8]),
    /// The record names no message this handle still holds.
    Retired,
    /// The record's message did not complete a fragment chain, so there is no
    /// joined buffer to hand back — structurally, for this record.
    NotReassembled,
}

/// R2102 (open-debt item 524) — a dissection that outlives the call that made
/// it, fed incrementally and drained into the caller's buffer.
///
/// This is the type behind the opaque `wz_dissect_live *` the header declares.
/// See the module doc for why it exists and what makes its bookmarks sound.
pub struct LiveDissection {
    dissection: Dissection,
    marks: BTreeMap<(FlowKey, MessageListOrigin), Mark>,
    /// The same watermarks, for each datagram flow's SCOUTING
    /// list. A map of its own because that list is not in the enumeration the
    /// map above is keyed by (see [`ORIGIN_SCOUTING`]); the bookkeeping is the
    /// same function, [`advance`].
    scouting_marks: BTreeMap<FlowKey, Mark>,
    flow_ids: BTreeMap<(FlowKey, u8), u64>,
    /// ONE counter behind BOTH [`WzDissectRecord::flow_id`] and
    /// [`WzDissectRecord::list_id`], so the two are never the same number by
    /// accident. Two counters would each start at zero, and a consumer that
    /// read the wrong field would get a plausible answer for a while — which is
    /// the failure mode worth spending a few integers to remove.
    next_id: u64,
    /// The next row sequence number to hand out, starting at 1 so that a cursor
    /// of 0 means "before the first row" and needs no second spelling. Its own
    /// counter and NOT `next_id`: list and flow ids are coordinate spaces a
    /// consumer must not confuse with each other, and a row number is a count of
    /// rows issued, which no other id is.
    next_seq: u64,
    lost: u64,
    /// R2373 (open-debt item 661) — how far into a capture CONTAINER this
    /// handle has read, for [`Self::follow`].
    ///
    /// On the handle rather than beside it because it is the only thing that
    /// knows what it has already consumed, and it is the thing that must know:
    /// a follower hands over the whole prefix every call, so a cursor the
    /// CALLER held would be a second place the same fact lived, and the two
    /// would part the first time a call returned an error.
    ///
    /// [`Self::from_capture`] leaves it at the end of the file it read, which
    /// is what lets a replayed handle be followed as the writer appends more.
    cursor: CaptureCursor,
}

impl LiveDissection {
    /// A handle reading under `limits`.
    pub fn new(limits: DissectionLimits) -> Self {
        Self::over(Dissection::with_limits(limits))
    }

    /// R2171 (open-debt item 547) — a handle over a capture FILE already read.
    ///
    /// # Why this reads the file through `Dissection` rather than per packet
    ///
    /// The obvious shape is to open the container here and call [`Self::push`]
    /// per packet, and it is wrong in a way that is silent. `from_capture_*`
    /// dispatches on the magic and carries what only the FILE knows: a pcapng's
    /// per-interface link types (`push_packet_on`, which this type's `push` has
    /// no way to reach), its Decryption Secrets Blocks, its Interface
    /// Statistics, and the `finish()` that spends the gap patience a file's end
    /// makes final. A loop here would drop all four, so a frozen capture would
    /// read one way through the document doors and another way through this
    /// one — which is the second reader of the same bytes that this crate keeps
    /// removing, arriving inside it.
    ///
    /// So the file is read by the reader every other door uses, and this type
    /// wraps the result. What it inherits with it is the packet coordinate:
    /// `Dissection::next_packet_index` is where a later [`Self::push`] resumes,
    /// so a live source continuing after the file cannot land on a coordinate
    /// the file already spent.
    ///
    /// R2373 (open-debt item 661) — it now reads the file through
    /// [`Self::follow`], which is the same walk a GROWING container gets, and
    /// then requires the container to have ENDED on a block boundary. Two
    /// things come of that. The handle's cursor is left at the file's end, so a
    /// replay may be followed as the writer appends — the two doors compose
    /// rather than excluding each other. And "the frozen door and the growing
    /// door read these bytes the same way" stops being a claim in a comment: it
    /// is one function calling the other.
    pub fn from_capture(bytes: &[u8], limits: DissectionLimits) -> Result<Self, CaptureError> {
        let mut me = Self::over(Dissection::with_limits(limits));
        me.follow(bytes).map_err(|e| match e {
            FollowError::Capture(c) => c,
            // Unreachable from a fresh cursor: nothing has been consumed, so
            // no prefix can be shorter than it. Mapped rather than unwrapped
            // because a panic here would be this door's answer to a caller's
            // capture, and it has a better one.
            FollowError::Shrank { .. } => {
                CaptureError::Pcapng(wz_capture::pcapng::PcapngError::Truncated { offset: 0 })
            }
        })?;
        if me.followed() != bytes.len() {
            // A FILE does not grow, so the tail a follower would wait for is a
            // truncation here. Reported through the format the container turned
            // out to be, which is what the whole-file readers did.
            return Err(if wz_capture::pcapng::looks_like_pcapng(bytes) {
                CaptureError::Pcapng(wz_capture::pcapng::PcapngError::Truncated {
                    offset: me.followed(),
                })
            } else {
                CaptureError::Pcap(wz_capture::pcap::PcapError::TruncatedRecordHeader {
                    index: me.dissection.next_packet_index(),
                })
            });
        }
        // R311y610 — a FILE has a last packet, so the patience an open gap is
        // waiting on will never be spent. This is the caller that knows it, and
        // it is the one thing `follow` deliberately does not do.
        //
        // R2453 (open-debt item 700) — through [`Self::end`], which is that act
        // given a name so a LIVE feed can perform it too. One call site rather
        // than two: a door that ended a feed differently from the way a file
        // ends one is exactly the divergence this round is closing.
        me.end();
        Ok(me)
    }

    /// R2373 (open-debt item 661) — FEED A GROWING CAPTURE CONTAINER into this
    /// handle. Returns how many packets became readable.
    ///
    /// `bytes` is the whole container prefix the caller holds, from offset
    /// zero, on every call. The handle remembers how far into it has been
    /// parsed and consumes only the blocks that completed since the last call,
    /// so a message whose bytes span two calls is decoded exactly ONCE and
    /// every coordinate, count and budget continues.
    ///
    /// See [`wz_capture::Dissection::follow_container`] for why the whole
    /// prefix rather than the new tail, and why re-reading the prefix each
    /// window fails on correctness rather than on speed.
    ///
    /// A prefix that ends in the middle of a block is LEGAL and consumes
    /// nothing extra; the next call with more bytes decodes that block. It does
    /// not call `finish`, because a container still being written has no last
    /// packet.
    pub fn follow(&mut self, bytes: &[u8]) -> Result<usize, FollowError> {
        self.dissection.follow_container(&mut self.cursor, bytes)
    }

    /// How many bytes of the container [`Self::follow`] has consumed.
    ///
    /// A consumer that already knows how far its writer's cursor reached does
    /// not need this. It exists for the one thing the caller cannot otherwise
    /// see: whether a prefix ended mid-block, which is the difference between
    /// "nothing new was written" and "a block is half here".
    pub fn followed(&self) -> usize {
        self.cursor.consumed()
    }

    /// The one constructor both of the above go through.
    fn over(dissection: Dissection) -> Self {
        Self {
            dissection,
            marks: BTreeMap::new(),
            scouting_marks: BTreeMap::new(),
            flow_ids: BTreeMap::new(),
            next_id: 0,
            next_seq: 1,
            lost: 0,
            cursor: CaptureCursor::new(),
        }
    }

    /// Feed one captured packet.
    ///
    /// `ts_ns` is [`NO_TIMESTAMP`] for a source with no clock, which leaves the
    /// observer's clock where it is — the honest answer, and the behaviour
    /// `push_packet` has always had for a caller with nothing to say about
    /// time.
    pub fn push(&mut self, link_type: u32, ts_ns: u64, bytes: &[u8]) {
        let ts_millis = if ts_ns == NO_TIMESTAMP {
            None
        } else {
            Some(ts_ns / 1_000_000)
        };
        let at = self.dissection.next_packet_index();
        self.dissection
            .push_packet_at(link_type, at, ts_millis, bytes);
    }

    /// The packet index the NEXT push will anchor its messages to, which on a
    /// handle fed only by [`Self::push`] is also the number of pushes.
    ///
    /// R2171 — read off the dissection rather than counted here. A second
    /// counter beside the engine's own was the same fact in two places, and
    /// [`Self::from_capture`] is where the two would have parted: the file
    /// reader advances the engine's coordinate and could not touch a private
    /// field of this type.
    pub fn pushes(&self) -> usize {
        self.dissection.next_packet_index()
    }

    /// Messages that were decoded and then discarded — by a ceiling trimming a
    /// list, or by a flow being evicted — before this consumer drained them.
    ///
    /// Cumulative and monotone. A live tap renders it beside its own counts: a
    /// non-zero value is the one thing that separates "the link went quiet"
    /// from "this reader could not keep up".
    pub fn lost(&self) -> u64 {
        self.lost
    }

    /// Fill `out` with the messages decoded since the last drain, and return
    /// how many were written.
    ///
    /// # The walk always completes, and the WRITING may not
    ///
    /// Every list is visited on every call even after `out` is full. That is
    /// deliberate and it is what makes [`Self::lost`] sound: a list is known to
    /// have been evicted only by its ABSENCE from a complete walk, and a drain
    /// that stopped early would have to treat "not reached" and "gone" the
    /// same. Visiting a list costs a lookup, not a walk of its messages, so a
    /// small buffer does not turn into a large cost.
    ///
    /// # Order
    ///
    /// Records come out grouped by list, and each list in produced order. They
    /// are NOT globally sorted by time — a consumer wanting that sorts by
    /// [`WzDissectRecord::ts_ns`], which is on every record for that reason.
    /// Sorting here would mean holding messages back until it was known that
    /// nothing older could still arrive, which on a live link is never.
    pub fn drain(&mut self, out: &mut [WzDissectRecord]) -> usize {
        // Destructured so the walk over `dissection` and the bookkeeping in the
        // three maps are disjoint borrows rather than one borrow of `self`.
        let Self {
            dissection,
            marks,
            scouting_marks,
            flow_ids,
            next_id,
            next_seq,
            lost,
            ..
        } = self;

        let mut written = 0usize;
        let mut present: BTreeSet<(FlowKey, MessageListOrigin)> = BTreeSet::new();

        for (flow, origin, list) in dissection.message_lists_with_origin() {
            let key = (flow, origin);
            present.insert(key);

            let produced = list.produced();
            let mark = marks.entry(key).or_insert_with(|| fresh_mark(next_id));
            let first_held = advance(mark, produced, list.len() as u64, next_id, next_seq, lost);

            let list_id = mark.list_id;
            let flow_id = *flow_ids
                .entry((flow, flow_table(origin)))
                .or_insert_with(|| {
                    let id = *next_id;
                    *next_id += 1;
                    id
                });

            while mark.drained < produced && written < out.len() {
                let idx = (mark.drained - first_held) as usize;
                out[written] = record_of(&list[idx], flow_id, list_id, origin);
                written += 1;
                mark.drained += 1;
            }
        }

        // A list this walk did NOT see is gone, and so is whatever it still
        // held for this consumer. Retiring the mark with it keeps the map the
        // size of the live table rather than of every flow ever seen.
        marks.retain(|key, mark| {
            if present.contains(key) {
                return true;
            }
            *lost += mark.seen - mark.drained;
            false
        });

        // THE SCOUTING LISTS, after every message list, under the
        // same watermark rule. Before this a discovery capture drained to
        // nothing: R2629 put Scout and Hello on the field document's rows, and
        // a consumer whose message list stands on these records had no row to
        // stand them on.
        //
        // A flow whose scouting list has never produced anything mints no id —
        // most datagram flows are sessions and would otherwise burn a
        // coordinate space each on a list that stays empty. A flow that HAS a
        // mark is always walked, so a list emptied by eviction is still
        // reconciled.
        let mut scouting_present: BTreeSet<FlowKey> = BTreeSet::new();
        for flow in dissection.datagram_flows() {
            let list = &flow.scouting;
            let produced = list.produced();
            if produced == 0 && !scouting_marks.contains_key(&flow.flow) {
                continue;
            }
            scouting_present.insert(flow.flow);
            let mark = scouting_marks
                .entry(flow.flow)
                .or_insert_with(|| fresh_mark(next_id));
            let first_held = advance(mark, produced, list.len() as u64, next_id, next_seq, lost);
            let list_id = mark.list_id;
            // The datagram table's flow id: a scouting list is one more list
            // of the same UDP conversation, as the QUIC lists are.
            let flow_id = *flow_ids
                .entry((flow.flow, flow_table(MessageListOrigin::Datagram)))
                .or_insert_with(|| {
                    let id = *next_id;
                    *next_id += 1;
                    id
                });
            while mark.drained < produced && written < out.len() {
                let idx = (mark.drained - first_held) as usize;
                out[written] = record_of_scouting(&list[idx], flow_id, list_id);
                written += 1;
                mark.drained += 1;
            }
        }
        scouting_marks.retain(|key, mark| {
            if scouting_present.contains(key) {
                return true;
            }
            *lost += mark.seen - mark.drained;
            false
        });

        written
    }

    /// R2205 (open-debt item 560) — THE BYTES one drained record was decoded
    /// from, found by the coordinates that record already carries.
    ///
    /// The walk from record to frame moved to `Self::resolve`,
    /// which [`Self::reassembled_bytes`] shares.
    ///
    /// # Why the RECORD is the key and not a span
    ///
    /// The obvious door takes `(list_id, direction, start, end)` and hands back
    /// that range. It cannot be written, and the reason is a measurement rather
    /// than a preference: locating a message inside its framing unit needs
    /// `PassiveFrame::prefix_width`, and [`WzDissectRecord`] does not carry it —
    /// `anchor` names the unit's LENGTH PREFIX, not its body. A consumer asked
    /// for a span would therefore be asked to re-derive this crate's framing
    /// rule from coordinates that cannot express it, which is the second reader
    /// of the same bytes `wz-capture` keeps removing.
    ///
    /// Handing back the record instead costs the consumer nothing — it is the
    /// value it just drained — and it makes an unanswerable question
    /// unaskable: there is no way to name a range that is not a message.
    ///
    /// # How a record is resolved back to a frame
    ///
    /// `list_id` names the list through the same watermark map that issued it,
    /// so a list that has been REPLACED cannot be reached by an old record's id
    /// — the successor got a new one, which is `Mark::list_id`'s whole
    /// purpose. Inside the list, `(direction, anchor, batch_index)` is exact:
    /// two messages of one list in one direction share an anchor only when they
    /// are in the same framing unit, and `batch_index` is what tells those
    /// apart.
    ///
    /// A record whose message has since been trimmed away resolves to nothing
    /// and is answered `Retired` — the same word `wz-capture` uses for bytes a
    /// ceiling took, because from the consumer's side it is the same fact.
    pub fn message_bytes(&self, record: &WzDissectRecord) -> wz_capture::MessageBytes<'_> {
        match self.resolve(record) {
            Ok((flow, origin, index, _)) => self.dissection.message_bytes_at(flow, origin, index),
            Err(answer) => answer,
        }
    }

    /// THE JOINED BUFFER of the record that completed a fragment
    /// chain: the bytes `above_transport.fields` and `above_transport.carried`
    /// index, for exactly the row whose `carried_state` is `reassembled`.
    ///
    /// Resolved through the same record-to-frame walk as [`Self::message_bytes`],
    /// so the two doors cannot disagree about which message a record names.
    /// They differ in WHICH bytes of that message they hand back, and that is
    /// the whole reason there are two: `message_bytes` answers with the bytes
    /// the row's own `fields` were walked from — for a completing `Fragment`,
    /// the fragment as it crossed the wire — and this answers with the buffer
    /// the chain was joined in, which never crossed the wire in one piece.
    pub fn reassembled_bytes(&self, record: &WzDissectRecord) -> ReassembledBytes<'_> {
        let frame = match self.resolve(record) {
            Ok((_, _, _, frame)) => frame,
            Err(wz_capture::MessageBytes::NoSource(_)) => return ReassembledBytes::NotReassembled,
            Err(_) => return ReassembledBytes::Retired,
        };
        match &frame.carried {
            wz_session_core::passive::Carried::Reassembled { joined, .. } => {
                ReassembledBytes::Joined(joined)
            }
            _ => ReassembledBytes::NotReassembled,
        }
    }

    /// The record-to-frame walk both byte doors share: which list the record
    /// came out of, where in it, and the frame itself — or the answer to give
    /// when there is no such frame.
    #[allow(clippy::type_complexity)]
    fn resolve(
        &self,
        record: &WzDissectRecord,
    ) -> Result<
        (
            wz_capture::link::FlowKey,
            wz_capture::MessageListOrigin,
            usize,
            &wz_session_core::passive::PassiveFrame,
        ),
        wz_capture::MessageBytes<'_>,
    > {
        let direction = match record.direction {
            0 => Direction::A,
            1 => Direction::B,
            // Not a direction this ABI has, so it names no message. Answered as
            // a miss rather than as a panic: the record crossed a C boundary
            // and this library does not get to assume what is on the other side
            // of it.
            _ => {
                return Err(wz_capture::MessageBytes::Retired(String::from(
                    "no such direction on any message of this reader",
                )))
            }
        };
        // A SCOUTING record's bytes are a whole datagram the
        // caller pushed, which is exactly the answer a transport datagram's
        // record gets: this reader keeps no copy of a pushed packet. Said as
        // that, rather than as "no list carries this id", which would read as
        // a stale record.
        if self
            .scouting_marks
            .values()
            .any(|mark| mark.list_id == record.list_id)
        {
            return Err(wz_capture::MessageBytes::NoSource(
                wz_capture::NoByteSource::CallerHoldsThePacket,
            ));
        }
        let Some((&(flow, origin), _)) = self
            .marks
            .iter()
            .find(|(_, mark)| mark.list_id == record.list_id)
        else {
            return Err(wz_capture::MessageBytes::Retired(String::from(
                "no list of this handle carries that list_id",
            )));
        };
        let Some((_, _, list)) = self
            .dissection
            .message_lists_with_origin()
            .find(|(f, o, _)| *f == flow && *o == origin)
        else {
            return Err(wz_capture::MessageBytes::Retired(String::from(
                "the list this record came out of is no longer held",
            )));
        };
        let Some((index, frame)) = list.iter().enumerate().find(|(_, f)| {
            f.direction == direction
                && f.stream_offset as u64 == record.anchor
                && f.batch_index as u32 == record.batch_index
        }) else {
            return Err(wz_capture::MessageBytes::Retired(String::from(
                "this message is no longer in its list",
            )));
        };
        Ok((flow, origin, index, frame))
    }

    /// R2453 (open-debt item 700) — THE ANALYSIS PLANES OF WHAT THIS HANDLE HAS
    /// SEEN, as the same document the capture doors emit.
    ///
    /// `filter` narrows exactly as it does through
    /// [`crate::wz_dissect_pcap_census_where`], and an EMPTY one selects
    /// everything — which is why one method answers both the narrowed question
    /// and the plain one.
    ///
    /// # Nothing here is new aggregation, and that is the point
    ///
    /// The planes were never missing from this half. `wz-capture` computes them
    /// from a `&Dissection`, and this type has held one since R2102, so what
    /// this returns is the SAME emitter the capture doors call rather than a
    /// second one. That matters because the alternative a consumer reaches for
    /// when a library has no door is to aggregate the drained records itself,
    /// which puts a second counter of the same facts in the system — and a
    /// second counter does not fail, it DIVERGES.
    ///
    /// # `&self`, and why that is load-bearing
    ///
    /// Rendering the planes must not change what the tap decodes. Exactly one
    /// act would, and it is not here: giving up on an unfilled reassembly gap.
    /// That is [`Self::end`], and it is a separate call so that a consumer
    /// drawing a window cannot spend it by accident.
    pub fn census(&self, filter: &wz_capture::filter::Filter) -> String {
        wz_capture::census_json::census_json_where(&self.dissection, filter)
    }

    /// THE FIELD DOCUMENT OF WHAT THIS HANDLE HAS SEEN, each row
    /// carrying the coordinates its record carries.
    ///
    /// # Why this is the join and a second dissection is not
    ///
    /// A consumer that drains records here and reads rows off a capture door
    /// holds TWO dissections of one file, and nothing published joins them:
    /// the records name lists by ids this handle minted, the document names
    /// flows by 5-tuple. On one flow they line up by order; on several, or on
    /// datagram rows, they do not line up at all. Rendered over THIS handle's
    /// dissection with THIS handle's ids, a row and its record share
    /// `(list_id, direction, anchor, batch_index)` by construction — the same
    /// fact R2453 made true of the census.
    ///
    /// # `&mut`, and what that does and does not change
    ///
    /// A list this handle has not drained yet has no id, and a row with no id
    /// cannot join the record a later drain hands out. So the ids are settled
    /// FIRST, by a drain into an empty buffer: every list is reconciled
    /// exactly as a drain reconciles it — minted, replaced, trimmed and
    /// counted — and no record is handed out, so the next real drain returns
    /// what it would have returned anyway, under the same ids. It changes no
    /// decoded message; [`Self::end`] is still the one act that would.
    ///
    /// `capture` is the container this handle was read from, for the datagram
    /// rows: this reader keeps no copy of a pushed packet, so those rows are
    /// re-read from it exactly as the capture doors re-read theirs. An empty
    /// slice renders none of them and says so with `capture_reread: false`.
    pub fn fields_where(
        &mut self,
        capture: &[u8],
        max_messages_shown_per_flow: Option<usize>,
        declarations: Option<&wz_capture::payload_decode::Declarations<'_>>,
        filter: &wz_capture::filter::Filter,
    ) -> String {
        self.drain(&mut []);
        let ids = HandleIds::of(self);
        wz_capture::fields_json::fields_json_where_coordinated(
            &self.dissection,
            capture,
            max_messages_shown_per_flow,
            declarations,
            filter,
            &ids,
        )
    }

    /// THE FIELD DOCUMENT'S ROWS AFTER A CURSOR, and only those: the rows whose
    /// sequence number is greater than `after_seq`.
    ///
    /// # What it is for
    ///
    /// A consumer that holds the rows it has already been given should not be
    /// handed them again. Every row carries a `seq` (see [`Self::fields_where`],
    /// which writes it too), so a caller keeps the `window.through_seq` of the
    /// last answer and passes it back; what comes out is the rows that were
    /// issued since. `0` asks for every row.
    ///
    /// # Nothing is decided differently
    ///
    /// The ids and the row numbers are settled first by the reconciliation a
    /// drain performs, into an empty buffer, exactly as the whole-document door
    /// does, so the next [`Self::drain`] returns what it would have and the
    /// coordinates a row carries are the ones its record carries. The document
    /// is `wz_capture::fields_json::fields_json_since_coordinated`'s, and it is
    /// the whole-document renderer with the rows before the cursor not written;
    /// see that function for the two things it does not take (a selector, a row
    /// cap) and why.
    ///
    /// # Take it at the state the drain was taken at
    ///
    /// [`Self::end`] releases the messages a reassembly gap was holding, so a
    /// document taken before it and records drained after it disagree by
    /// exactly those messages. The rows themselves are not changed by `end`; the
    /// join fails only because the document and the records are two states.
    /// Call this and [`Self::drain`] on the same side of it.
    pub fn fields_since(
        &mut self,
        capture: &[u8],
        declarations: Option<&wz_capture::payload_decode::Declarations<'_>>,
        after_seq: u64,
    ) -> String {
        self.drain(&mut []);
        let ids = HandleIds::of(self);
        // The highest number the handle has issued, and NOT the highest row that
        // was written: a datagram row whose second read was declined has a
        // number and no row, and the cursor has to pass it.
        let through_seq = self.next_seq - 1;
        wz_capture::fields_json::fields_json_since_coordinated(
            &self.dissection,
            capture,
            declarations,
            &ids,
            wz_capture::fields_json::Since {
                after_seq,
                through_seq,
            },
        )
    }

    /// THE SELECTOR'S VERDICT OVER THE ROWS OF THE FIELD DOCUMENT, and
    /// nothing beside it: each row's four coordinates and the word the selector
    /// said, with the ceilings that made the list short.
    ///
    /// # Why this is a method of its own and not a flag on the one above
    ///
    /// The field document renders every row's whole tree, carried state and
    /// session verdicts, and a consumer narrowing a list needs none of them —
    /// measured by that consumer at 58 MB and 1.5 s to read, per chip toggle, on
    /// 25,360 rows. A "no tree" argument would make one document with two
    /// shapes; this is two documents, each with its own revision, which is how
    /// this library already tells a reader which shape it holds.
    ///
    /// # `&mut`, for the reason [`Self::fields_where`] is
    ///
    /// A list not drained yet has no id, and a row without one cannot join the
    /// record a later drain hands out. The ids are settled first, by a drain into
    /// an empty buffer: no record is handed out and no decoded message changes.
    ///
    /// # No capture container
    ///
    /// The field document re-reads each datagram from the container to walk its
    /// tree. The verdict is decided by the record plane and needs no such walk,
    /// so this takes no container and a handle fed by `push` gets datagram
    /// verdicts it cannot get from the field document.
    pub fn selection(&mut self, filter: &wz_capture::filter::Filter) -> String {
        self.drain(&mut []);
        let ids = HandleIds::of(self);
        wz_capture::selection_json::selection_json_where_coordinated(&self.dissection, filter, &ids)
    }

    /// R2453 (open-debt item 700) — THE FEED ENDED: spend the patience that a
    /// capture's last packet spends.
    ///
    /// # Why a live handle needs this at all
    ///
    /// A file ends, so the reader that opens one knows when to stop waiting for
    /// a segment that never came; `Dissection::finish` is where every capture
    /// door spends that. A tap does not end, so this handle never spends it,
    /// and until this round there was no way to say the feed was over.
    ///
    /// MEASURED, on a capture whose last act is an unfilled gap: the census of
    /// the same bytes reports 32 walked records before this call and 94 after
    /// it. The bytes BEHIND a hole decode only once the hole is given up on, so
    /// a consumer replaying a finite capture through the live door read a SHORT
    /// document and had no way to reach the one the capture doors give for the
    /// same bytes. That is the seam item 700 is about, in the one case a
    /// regression can hold still.
    ///
    /// # It does not close the handle, and feeding may continue
    ///
    /// [`Self::from_capture`] has called this since R2373 and then leaves the
    /// handle followable, so "ended" here means the patience is spent and not
    /// that the handle is done. A tap that goes quiet and then speaks again is
    /// the ordinary case, and the cost of having said so is that a gap which a
    /// late retransmission would have filled is already a discontinuity —
    /// which is the same trade a file's end makes, made deliberately.
    ///
    /// Releasing the handle is still [`crate::wz_dissect_live_close`]'s job.
    pub fn end(&mut self) {
        self.dissection.finish();
    }

    /// The lists this handle is currently tracking a watermark for. Used by the
    /// tests that assert the map does not grow without bound.
    #[cfg(test)]
    pub fn tracked_lists(&self) -> usize {
        self.marks.len()
    }

    /// The dissection itself, for a test that wants to assert against the
    /// engine rather than against the records.
    #[cfg(test)]
    pub fn dissection(&self) -> &Dissection {
        &self.dissection
    }
}

/// One `PassiveFrame`, projected into the record a C consumer receives.
fn record_of(
    frame: &PassiveFrame,
    flow_id: u64,
    list_id: u64,
    origin: MessageListOrigin,
) -> WzDissectRecord {
    let mut flags = 0u32;
    if frame.exceeds_negotiated_batch {
        flags |= FLAG_EXCEEDS_NEGOTIATED_BATCH;
    }
    if frame.inadmissible_on_link {
        flags |= FLAG_INADMISSIBLE_ON_LINK;
    }
    if frame.resync.is_some() {
        flags |= FLAG_AFTER_RESYNC;
    }
    WzDissectRecord {
        ts_ns: match frame.observed_at_ms {
            // Widened back from the millisecond clock this reader keeps. The
            // caller's sub-millisecond digits are gone and the record says so
            // by carrying a whole number of milliseconds, which is a better
            // answer than a precision this reader never had.
            Some(ms) => ms.saturating_mul(1_000_000),
            None => NO_TIMESTAMP,
        },
        flow_id,
        list_id,
        anchor: frame.stream_offset as u64,
        unit_len: frame.unit_len as u64,
        batch_index: frame.batch_index as u32,
        unit_offset: frame.unit_offset as u32,
        direction: match frame.direction {
            Direction::A => 0,
            Direction::B => 1,
        },
        // R2206 (open-debt item 561) — off the FRAME. It used to be handed in
        // from the enumeration that walks the message lists, which decided the
        // space by a hand-written match with nothing joining it to the caller
        // that chose the coordinate. That is what published a capture packet
        // index under WZ_DISSECT_ANCHOR_STREAM_BYTES for a serial line: the
        // header's own argument for this field is that the two cannot be told
        // apart by looking, so a consumer switching on it was told to add byte
        // spans to a packet index.
        anchor_space: match wz_capture::anchor_space_of(frame) {
            AnchorSpace::PacketIndex => 0,
            AnchorSpace::StreamBytes => 1,
        },
        origin: origin_code(origin),
        // The kind lives on the variant (`kind_code`) so that a message kind
        // added upstream fails that match rather than silently taking a
        // default here; the UNDECODABLE case is the one this side owns,
        // because the failure is in the `Result` and not in the enum.
        kind: match &frame.frame {
            Ok(f) => f.kind_code(),
            Err(_) => KIND_UNDECODABLE,
        },
        flags,
    }
}

/// This handle's list ids, in the shape the field renderer asks for them.
///
/// A snapshot taken after the ids were settled, keyed the way the renderer
/// keys lists: by position in `Dissection::message_lists_with_origin`, which is
/// the enumeration the marks were minted from, and by flow for a scouting list.
///
/// The row sequence numbers ride in the same snapshot, so the id a row is joined
/// on and the sequence number it carries are read from ONE state of the handle.
struct HandleIds {
    lists: Vec<Option<ListNumbers>>,
    scouting: BTreeMap<FlowKey, ListNumbers>,
}

/// One list's id and the row sequence numbers of the messages it still holds.
struct ListNumbers {
    list_id: u64,
    runs: Vec<SeqRun>,
}

impl ListNumbers {
    fn of(mark: &Mark) -> Self {
        Self {
            list_id: mark.list_id,
            runs: mark.runs.iter().copied().collect(),
        }
    }
}

impl HandleIds {
    fn of(handle: &LiveDissection) -> Self {
        Self {
            lists: handle
                .dissection
                .message_lists_with_origin()
                .map(|(flow, origin, _)| handle.marks.get(&(flow, origin)).map(ListNumbers::of))
                .collect(),
            scouting: handle
                .scouting_marks
                .iter()
                .map(|(flow, mark)| (*flow, ListNumbers::of(mark)))
                .collect(),
        }
    }
}

impl wz_capture::fields_json::RowCoordinates for HandleIds {
    fn list_id(&self, list: usize) -> Option<u64> {
        self.lists.get(list)?.as_ref().map(|n| n.list_id)
    }

    fn scouting_list_id(&self, flow: &FlowKey) -> Option<u64> {
        self.scouting.get(flow).map(|n| n.list_id)
    }

    fn row_seq(&self, list: usize, produced: u64) -> Option<u64> {
        seq_in_runs(&self.lists.get(list)?.as_ref()?.runs, produced)
    }

    fn scouting_row_seq(&self, flow: &FlowKey, produced: u64) -> Option<u64> {
        seq_in_runs(&self.scouting.get(flow)?.runs, produced)
    }
}

/// A watermark for a list this handle has not tracked before, on the shared
/// id counter.
fn fresh_mark(next_id: &mut u64) -> Mark {
    let id = *next_id;
    *next_id += 1;
    Mark {
        drained: 0,
        seen: 0,
        list_id: id,
        numbered: 0,
        runs: VecDeque::new(),
    }
}

/// Give the messages of one list that this handle has not numbered yet their row
/// sequence numbers, and forget the numbers of messages that are gone.
///
/// Called from [`advance`], so every walk that settles a list's ids settles its
/// row numbers with the same call: the field document, the selection document
/// and a drain all reconcile first, and none of them can render a row this
/// handle has not numbered.
///
/// A message trimmed away BEFORE it was ever numbered is skipped and takes no
/// number: it was never issued, and it is already counted as lost. That leaves a
/// gap in the numbers, which a cursor passes without harm — the numbers are
/// unique and increasing, not dense.
fn number_new_rows(mark: &mut Mark, produced: u64, first_held: u64, next_seq: &mut u64) {
    // Forget what a front trim took, cutting a run that straddles the edge.
    while let Some(front) = mark.runs.front_mut() {
        let end = front.first_produced + front.len;
        if end <= first_held {
            mark.runs.pop_front();
        } else {
            if front.first_produced < first_held {
                let cut = first_held - front.first_produced;
                front.first_produced += cut;
                front.first_seq += cut;
                front.len -= cut;
            }
            break;
        }
    }

    let from = mark.numbered.max(first_held);
    if produced > from {
        let len = produced - from;
        let first_seq = *next_seq;
        *next_seq += len;
        match mark.runs.back_mut() {
            // The new stretch continues the last run in BOTH spaces, so it is the
            // same run and not one more.
            Some(back)
                if back.first_produced + back.len == from
                    && back.first_seq + back.len == first_seq =>
            {
                back.len += len;
            }
            _ => mark.runs.push_back(SeqRun {
                first_produced: from,
                first_seq,
                len,
            }),
        }
    }
    mark.numbered = mark.numbered.max(produced);
}

/// Bring one list's watermark up to what the list now holds, and return the
/// produced-index of the OLDEST message still in it.
///
/// ONE function for both kinds of list. It was the body of the
/// message-list loop in [`LiveDissection::drain`]; the scouting lists need the
/// same three rules, and a second copy of them is the copy that drifts.
fn advance(
    mark: &mut Mark,
    produced: u64,
    held: u64,
    next_id: &mut u64,
    next_seq: &mut u64,
    lost: &mut u64,
) -> u64 {
    // Everything below this produced-index has been trimmed away.
    let first_held = produced - held;

    // A `produced` that went BACKWARDS is not this list any more: the flow was
    // evicted and another opened under the same key, so the successor's
    // counter starts again. What the predecessor still owed is owed by nobody
    // now.
    //
    // The COORDINATE SPACE restarts with it, so the successor gets a fresh
    // `list_id`. Inheriting the predecessor's would tell a consumer that byte 0
    // of a new stream is comparable with byte 0 of one that has gone, which is
    // the merge this field exists to stop.
    if produced < mark.seen {
        *lost += mark.seen - mark.drained;
        mark.drained = 0;
        mark.seen = 0;
        mark.list_id = *next_id;
        *next_id += 1;
        // The successor's messages are new rows: the predecessor's numbers name
        // messages that are gone, and its produced-indices mean nothing in the
        // successor's counter. The NUMBERS already issued are not reused —
        // `next_seq` only ever moves forward.
        mark.numbered = 0;
        mark.runs.clear();
    }

    // Messages a ceiling discarded before this consumer reached them. Counted,
    // then stepped over -- they are not in the list to hand out, and pretending
    // the watermark is still valid would make the NEXT record come out under
    // the wrong produced-index.
    if mark.drained < first_held {
        *lost += first_held - mark.drained;
        mark.drained = first_held;
    }
    mark.seen = produced;
    number_new_rows(mark, produced, first_held, next_seq);
    first_held
}

/// One scouting message, projected into the SAME record.
///
/// Every field keeps the meaning it has for a transport datagram, because a
/// consumer reads them by one rule: the anchor is the packet index
/// (`WZ_DISSECT_ANCHOR_PACKET`), the unit is the whole datagram — a scouting
/// message is never batched, so `batch_index` and `unit_offset` are zero — and
/// the kind is `ScoutingFrame::kind_code`, in the one kind space. `flags` is
/// zero: each flag is a verdict about a SESSION (a negotiated batch, a link's
/// admissible messages, a resync of framing), and a scouting message has none.
fn record_of_scouting(datagram: &ScoutingDatagram, flow_id: u64, list_id: u64) -> WzDissectRecord {
    WzDissectRecord {
        ts_ns: match datagram.observed_at_ms {
            Some(ms) => ms.saturating_mul(1_000_000),
            None => NO_TIMESTAMP,
        },
        flow_id,
        list_id,
        anchor: datagram.packet_index as u64,
        unit_len: datagram.unit_len as u64,
        batch_index: 0,
        unit_offset: 0,
        direction: match datagram.direction {
            Direction::A => 0,
            Direction::B => 1,
        },
        anchor_space: 0,
        origin: ORIGIN_SCOUTING,
        kind: match &datagram.frame {
            Ok(f) => f.kind_code(),
            Err(_) => KIND_UNDECODABLE,
        },
        flags: 0,
    }
}

/// The row sequence numbering, graded on its own bookkeeping.
///
/// These take `number_new_rows` and `advance` directly, with no capture, because
/// the properties are arithmetic on two counters and a fixture that reached them
/// through a dissection would only add the ways a dissection can be wrong.
#[cfg(test)]
mod numbering_tests {
    use super::*;

    fn a_mark() -> Mark {
        fresh_mark(&mut 0)
    }

    fn runs_of(mark: &Mark) -> Vec<SeqRun> {
        mark.runs.iter().copied().collect()
    }

    /// The number of each produced-index in `range`, as a consumer's row lookup
    /// would ask for them.
    fn numbers(mark: &Mark, range: core::ops::Range<u64>) -> Vec<Option<u64>> {
        let runs = runs_of(mark);
        range.map(|p| seq_in_runs(&runs, p)).collect()
    }

    #[test]
    fn a_first_walk_numbers_from_the_counter_as_one_run() {
        let mut mark = a_mark();
        let mut next = 1;
        number_new_rows(&mut mark, 3, 0, &mut next);
        assert_eq!(
            runs_of(&mark),
            vec![SeqRun {
                first_produced: 0,
                first_seq: 1,
                len: 3
            }]
        );
        assert_eq!(next, 4, "the counter moved by exactly the rows numbered");
        assert_eq!(numbers(&mark, 0..4), vec![Some(1), Some(2), Some(3), None]);
    }

    /// Two lists share one counter, so a list's numbers are NOT its produced-index
    /// plus a constant. A single offset per list would give the fourth message of
    /// A the number of the first message of B.
    #[test]
    fn interleaved_lists_each_keep_their_own_exact_numbers() {
        let (mut a, mut b) = (a_mark(), a_mark());
        let mut next = 1;
        number_new_rows(&mut a, 3, 0, &mut next); // A: 1,2,3
        number_new_rows(&mut b, 2, 0, &mut next); // B: 4,5
        number_new_rows(&mut a, 5, 0, &mut next); // A: 6,7
        assert_eq!(
            numbers(&a, 0..5),
            vec![Some(1), Some(2), Some(3), Some(6), Some(7)]
        );
        assert_eq!(numbers(&b, 0..2), vec![Some(4), Some(5)]);
        assert_eq!(
            runs_of(&a).len(),
            2,
            "a stretch that does not continue the last run in the NUMBERS is a run of its own"
        );
        // A stretch that does continue it joins it, so one busy list is one run.
        number_new_rows(&mut a, 6, 0, &mut next); // A: 8
        assert_eq!(
            runs_of(&a).len(),
            2,
            "8 continues 6 and 7: still two runs, not three"
        );
        assert_eq!(numbers(&a, 3..6), vec![Some(6), Some(7), Some(8)]);
    }

    #[test]
    fn walking_twice_numbers_nothing_twice() {
        let mut mark = a_mark();
        let mut next = 1;
        number_new_rows(&mut mark, 4, 0, &mut next);
        let before = (runs_of(&mark), next);
        number_new_rows(&mut mark, 4, 0, &mut next);
        assert_eq!((runs_of(&mark), next), before);
    }

    #[test]
    fn a_front_trim_cuts_the_run_and_keeps_the_numbers_of_what_is_left() {
        let mut mark = a_mark();
        let mut next = 1;
        number_new_rows(&mut mark, 5, 0, &mut next); // 1..=5
        number_new_rows(&mut mark, 5, 2, &mut next); // the two oldest are trimmed
        assert_eq!(
            numbers(&mark, 0..5),
            vec![None, None, Some(3), Some(4), Some(5)],
            "what is left keeps the number it was issued under"
        );
        number_new_rows(&mut mark, 5, 5, &mut next);
        assert!(
            runs_of(&mark).is_empty(),
            "nothing held, nothing remembered"
        );
        assert_eq!(next, 6, "and a trim issues no number");
    }

    /// A message the ceiling took before this handle ever looked was never issued,
    /// so it takes no number: the numbers are unique and increasing, not dense.
    #[test]
    fn a_message_trimmed_before_it_was_numbered_takes_no_number() {
        let mut mark = a_mark();
        let mut next = 1;
        number_new_rows(&mut mark, 5, 3, &mut next);
        assert_eq!(
            numbers(&mark, 0..5),
            vec![None, None, None, Some(1), Some(2)]
        );
        assert_eq!(next, 3);
    }

    /// A list replaced under the same key restarts its produced counter, and its
    /// messages are new rows. The numbers already issued are not reused.
    #[test]
    fn a_replaced_list_is_numbered_afresh_and_no_number_is_reused() {
        let (mut next_id, mut next_seq, mut lost) = (0, 1, 0);
        let mut mark = fresh_mark(&mut next_id);
        advance(&mut mark, 5, 5, &mut next_id, &mut next_seq, &mut lost);
        let first_id = mark.list_id;
        assert_eq!(numbers(&mark, 0..5), (1..=5).map(Some).collect::<Vec<_>>());

        // The counter went BACKWARDS: another list opened under the same key.
        advance(&mut mark, 2, 2, &mut next_id, &mut next_seq, &mut lost);
        assert_ne!(mark.list_id, first_id, "a new coordinate space");
        assert_eq!(
            numbers(&mark, 0..2),
            vec![Some(6), Some(7)],
            "the successor's rows continue the counter; 1 and 2 are not handed out again"
        );
        assert_eq!(numbers(&mark, 2..5), vec![None, None, None]);
        // And the predecessor's runs are GONE, not shadowed. A lookup asks only
        // the last run that starts at or below an index, so a stale run left
        // behind answers every question correctly by accident while it holds
        // memory for messages that no longer exist and breaks the ordering the
        // lookup relies on; the list of runs is what has to be asserted.
        assert_eq!(
            runs_of(&mark),
            vec![SeqRun {
                first_produced: 0,
                first_seq: 6,
                len: 2
            }],
            "only the successor's run remains"
        );
    }
}

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

use std::collections::{BTreeMap, BTreeSet};

use wz_capture::link::FlowKey;
use wz_capture::{
    AnchorSpace, CaptureCursor, CaptureError, Dissection, DissectionLimits, FollowError,
    MessageListOrigin,
};
use wz_session_core::passive::{Direction, PassiveFrame};

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
#[derive(Debug, Clone, Copy)]
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
}

/// R2102 (open-debt item 524) — a dissection that outlives the call that made
/// it, fed incrementally and drained into the caller's buffer.
///
/// This is the type behind the opaque `wz_dissect_live *` the header declares.
/// See the module doc for why it exists and what makes its bookmarks sound.
pub struct LiveDissection {
    dissection: Dissection,
    marks: BTreeMap<(FlowKey, MessageListOrigin), Mark>,
    flow_ids: BTreeMap<(FlowKey, u8), u64>,
    /// ONE counter behind BOTH [`WzDissectRecord::flow_id`] and
    /// [`WzDissectRecord::list_id`], so the two are never the same number by
    /// accident. Two counters would each start at zero, and a consumer that
    /// read the wrong field would get a plausible answer for a while — which is
    /// the failure mode worth spending a few integers to remove.
    next_id: u64,
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
        me.dissection.finish();
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
            flow_ids: BTreeMap::new(),
            next_id: 0,
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
            flow_ids,
            next_id,
            lost,
            ..
        } = self;

        let mut written = 0usize;
        let mut present: BTreeSet<(FlowKey, MessageListOrigin)> = BTreeSet::new();

        for (flow, origin, list) in dissection.message_lists_with_origin() {
            let key = (flow, origin);
            present.insert(key);

            let produced = list.produced();
            let held = list.len() as u64;
            // The produced-index of the OLDEST message still in the list.
            // Everything below it has been trimmed away.
            let first_held = produced - held;

            let mark = marks.entry(key).or_insert_with(|| {
                let id = *next_id;
                *next_id += 1;
                Mark {
                    drained: 0,
                    seen: 0,
                    list_id: id,
                }
            });

            // A `produced` that went BACKWARDS is not this list any more: the
            // flow was evicted and another opened under the same key, so the
            // successor's counter starts again. What the predecessor still
            // owed is owed by nobody now.
            //
            // The COORDINATE SPACE restarts with it, so the successor gets a
            // fresh `list_id`. Inheriting the predecessor's would tell a
            // consumer that byte 0 of a new stream is comparable with byte 0 of
            // one that has gone, which is the merge this field exists to stop.
            if produced < mark.seen {
                *lost += mark.seen - mark.drained;
                mark.drained = 0;
                mark.seen = 0;
                mark.list_id = *next_id;
                *next_id += 1;
            }

            // Messages a ceiling discarded before this consumer reached them.
            // Counted, then stepped over -- they are not in the list to hand
            // out, and pretending the watermark is still valid would make the
            // NEXT record come out under the wrong produced-index.
            if mark.drained < first_held {
                *lost += first_held - mark.drained;
                mark.drained = first_held;
            }
            mark.seen = produced;

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

        written
    }

    /// R2205 (open-debt item 560) — THE BYTES one drained record was decoded
    /// from, found by the coordinates that record already carries.
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
        let direction = match record.direction {
            0 => Direction::A,
            1 => Direction::B,
            // Not a direction this ABI has, so it names no message. Answered as
            // a miss rather than as a panic: the record crossed a C boundary
            // and this library does not get to assume what is on the other side
            // of it.
            _ => {
                return wz_capture::MessageBytes::Retired(String::from(
                    "no such direction on any message of this reader",
                ))
            }
        };
        let Some((&(flow, origin), _)) = self
            .marks
            .iter()
            .find(|(_, mark)| mark.list_id == record.list_id)
        else {
            return wz_capture::MessageBytes::Retired(String::from(
                "no list of this handle carries that list_id",
            ));
        };
        let Some((_, _, list)) = self
            .dissection
            .message_lists_with_origin()
            .find(|(f, o, _)| *f == flow && *o == origin)
        else {
            return wz_capture::MessageBytes::Retired(String::from(
                "the list this record came out of is no longer held",
            ));
        };
        let Some(index) = list.iter().position(|f| {
            f.direction == direction
                && f.stream_offset as u64 == record.anchor
                && f.batch_index as u32 == record.batch_index
        }) else {
            return wz_capture::MessageBytes::Retired(String::from(
                "this message is no longer in its list",
            ));
        };
        self.dissection.message_bytes_at(flow, origin, index)
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

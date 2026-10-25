// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! TCP flow reassembly: segments in, a per-direction byte stream out, plus
//! the map from a stream offset back to the packet that carried it.
//!
//! ## What this must get right, and why
//!
//! A byte stream handed to a decoder has to be the bytes the peer's socket
//! delivered, in order, exactly once. Three things on a capture conspire
//! against that, and each is handled explicitly rather than hoped away:
//!
//! - **Retransmissions.** The same bytes arrive twice. Appending them both
//!   inserts a duplicate run into the middle of the stream, which downstream
//!   reads as a corrupt frame at a plausible-looking offset.
//! - **Reordering.** A segment arrives before its predecessor. Appending in
//!   arrival order transposes the stream.
//! - **Partial overlap.** A retransmission that begins before `next_seq` but
//!   extends past it carries some new bytes. Dropping it whole loses them;
//!   appending it whole duplicates the prefix. Only the tail is new.
//!
//! ## The offset map
//!
//! Every emitted run records `(stream_offset, len, packet_index)`, so a
//! decoded message at stream offset N can be attributed to the packet that
//! carried it — the thing that makes a dissection point at a capture rather
//! than at an abstraction. Runs are appended in stream order, so the lookup
//! is a binary search.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use wz_session_core::byte_log::ByteLog;
use wz_session_core::column_log::{ColumnLog, Row};

use crate::link::Segment;

/// A contiguous run of stream bytes contributed by one packet, as the run map
/// keeps it.
///
/// Open-debt item 924 (`docs/dissect-row-index.md`, step 3 and D10): one of these
/// is kept for every payload-carrying segment of a capture, so what is held is
/// not this value but its columns, in a [`RunMap`] (20 bytes a run). This is the
/// run as a reader sees it. The fields are read through [`StreamAssembler`]'s
/// lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    /// Offset of the run's first byte within the direction's stream.
    stream_offset: u64,
    /// Where the run's bytes are: an offset in the assembler's own kept bytes,
    /// or, with [`IN_CONTAINER`] set, an offset in the capture container its
    /// holder lends (see [`StreamAssembler::push_located`]).
    place: u64,
    /// Index of the capture packet that carried it.
    packet_index: u64,
    /// The capture instant of that packet, in nanoseconds, as the caller stated
    /// it ([`StreamAssembler::push_at`]); [`NO_INSTANT`] when it stated none.
    ///
    /// Recorded here, with the packet, because this map is the one place that
    /// still knows which packet a byte came from once the bytes are a stream:
    /// a record read out of the stream asks it for the instant of its first
    /// byte, and the answer is the same packet [`StreamAssembler::origin_of_offset`]
    /// names for that byte, by construction.
    at_ns: u64,
    /// Run length in bytes.
    len: u32,
    /// Where the run's first byte sits within that packet's
    /// transport PAYLOAD (the segment body, header excluded).
    ///
    /// Zero for an ordinary segment; the number of bytes skipped for one that
    /// partially overlapped what the stream already held, because only its
    /// fresh tail became this run. Without it a byte's packet is known and its
    /// position inside the packet is not, and a reader highlighting it would
    /// have to re-derive the overlap this assembler already resolved.
    segment_offset: u32,
}

/// [`Run::at_ns`] of a packet the caller stated no instant for. A nanosecond
/// clock reaches it in the year 2554, so it is never a real instant.
const NO_INSTANT: u64 = u64::MAX;

/// [`Run::place`] names an offset in the lent capture container, not in the
/// assembler's kept bytes. No container or kept buffer reaches 2^63 bytes.
const IN_CONTAINER: u64 = 1 << 63;

impl Run {
    /// One past the run's last byte.
    fn end(&self) -> usize {
        self.stream_offset as usize + self.len as usize
    }

    fn at_ns(&self) -> Option<u64> {
        (self.at_ns != NO_INSTANT).then_some(self.at_ns)
    }

    /// Where the run's bytes are.
    fn place(&self) -> Place {
        if self.place & IN_CONTAINER != 0 {
            Place::Container((self.place & !IN_CONTAINER) as usize)
        } else {
            Place::Kept(self.place as usize)
        }
    }
}

/// The run map: every run of a direction's stream, in stream order, kept as the
/// columns a reader cannot recompute and nothing else (open-debt item 924, D10).
///
/// [`Run`] is the value a reader works with, 40 bytes of words; this is what is
/// held, 20 bytes a run. Four of its fields are columns of a [`ColumnLog`]: the
/// offset, the place and the packet rise from one run to the next, so each is a
/// 32-bit distance from its chunk's first, and the instant, which moves a
/// billion a second, is kept whole. The two fields it leaves out are not stored:
///
/// - `len` is the distance to the next run's offset, since the runs tile the
///   stream (a forced gap included: the stream stays contiguous across it), and
///   to [`Self::end`] for the last;
/// - `segment_offset` is zero except for a run that began inside its packet's
///   payload because the bytes before it were already delivered, which is a
///   partial overlap, so those few are kept apart by stream offset.
#[derive(Debug, Default)]
struct RunMap {
    /// `[stream_offset, place, packet_index]` rebased, and `[at_ns]` raw, of
    /// every run.
    log: ColumnLog<3, 1>,
    /// One past the last run's last byte.
    end: u64,
    /// `(stream_offset, segment_offset)` of the runs whose `segment_offset` is not
    /// zero, in stream order.
    skipped: VecDeque<(u64, u32)>,
}

impl RunMap {
    /// The run `row` is, given the offset the next run begins at.
    fn run(&self, row: Row<3, 1>, next: u64) -> Run {
        let [stream_offset, place, packet_index] = row.rebased;
        let [at_ns] = row.raw;
        Run {
            stream_offset,
            place,
            packet_index,
            at_ns,
            len: u32::try_from(next - stream_offset).unwrap_or(u32::MAX),
            segment_offset: self
                .skipped
                .binary_search_by_key(&stream_offset, |(offset, _)| *offset)
                .map_or(0, |at| self.skipped[at].1),
        }
    }

    /// Bytes the map holds on the heap.
    fn allocated_bytes(&self) -> usize {
        self.log.allocated_bytes() + wz_session_core::heap_account::vec_deque_bytes(&self.skipped)
    }

    /// Append the run that begins where the last one ended.
    fn push_back(&mut self, run: Run) {
        debug_assert!(
            self.log.is_empty() || run.stream_offset == self.end,
            "runs tile the stream"
        );
        self.log.push_back(Row {
            rebased: [run.stream_offset, run.place, run.packet_index],
            raw: [run.at_ns],
        });
        self.end = run.stream_offset + u64::from(run.len);
        if run.segment_offset != 0 {
            self.skipped
                .push_back((run.stream_offset, run.segment_offset));
        }
    }

    /// The run at `index`, oldest first.
    fn get(&self, index: usize) -> Option<Run> {
        let row = self.log.get(index)?;
        let next = self
            .log
            .get(index + 1)
            .map_or(self.end, |next| next.rebased[0]);
        Some(self.run(row, next))
    }

    /// The oldest run.
    fn front(&self) -> Option<Run> {
        self.get(0)
    }

    /// Release the oldest run.
    fn pop_front(&mut self) -> Option<Run> {
        let run = self.get(0)?;
        let _ = self.log.pop_front();
        if self
            .skipped
            .front()
            .is_some_and(|(offset, _)| *offset == run.stream_offset)
        {
            let _ = self.skipped.pop_front();
        }
        Some(run)
    }

    /// The position of the first run for which `pred` is `false`, the map being
    /// partitioned by it.
    fn partition_point(&self, mut pred: impl FnMut(&Run) -> bool) -> usize {
        let (mut low, mut high) = (0usize, self.log.len());
        while low < high {
            let mid = low + (high - low) / 2;
            match self.get(mid) {
                Some(run) if pred(&run) => low = mid + 1,
                _ => high = mid,
            }
        }
        low
    }

    /// The runs from position `from`, oldest first.
    fn iter_from(&self, from: usize) -> impl Iterator<Item = Run> + '_ {
        let mut rows = self.log.iter_from(from).peekable();
        core::iter::from_fn(move || {
            let row = rows.next()?;
            let next = rows.peek().map_or(self.end, |next| next.rebased[0]);
            Some(self.run(row, next))
        })
    }
}

/// Where a run's bytes are, read off [`Run::place`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// At this absolute offset of the assembler's kept bytes.
    Kept(usize),
    /// At this offset of the capture container the holder lends.
    Container(usize),
}

/// Where a segment's payload is, as the caller of
/// [`StreamAssembler::push_located`] knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadAt {
    /// Only in the segment: the assembler keeps a copy of the bytes it uses.
    Here,
    /// Also at this offset of the capture container the holder lends and keeps
    /// unchanged for as long as the assembler is read: the assembler keeps no
    /// copy, and reads the bytes there.
    Container(usize),
}

/// A segment held ahead of the stream, waiting for the bytes before it.
#[derive(Debug)]
struct HeldSegment {
    seq: u32,
    packet_index: usize,
    /// Its payload: a copy, or where the lent container holds it.
    payload: HeldBytes,
    /// [`StreamAssembler::segments_pushed`] at the moment it was held — the
    /// clock the gap's patience is measured on.
    held_at: usize,
    /// The capture instant of its packet, kept for the run it will become: a
    /// segment released by a hole being filled, or stepped over, is stamped with
    /// the instant it was captured at and not the instant it was released.
    at_ns: Option<u64>,
}

/// The payload of a [`HeldSegment`].
#[derive(Debug)]
enum HeldBytes {
    /// A copy, for a payload only the segment held.
    Copy(Vec<u8>),
    /// Its place in the lent container, and its length.
    Container { at: usize, len: usize },
}

impl HeldBytes {
    fn len(&self) -> usize {
        match self {
            HeldBytes::Copy(bytes) => bytes.len(),
            HeldBytes::Container { len, .. } => *len,
        }
    }

    fn payload(&self) -> Payload<'_> {
        match self {
            HeldBytes::Copy(bytes) => Payload::Here(bytes),
            HeldBytes::Container { at, len } => Payload::Container { at: *at, len: *len },
        }
    }
}

/// A payload as the assembler takes it in: the bytes, or where the lent
/// container holds them.
#[derive(Debug, Clone, Copy)]
enum Payload<'a> {
    Here(&'a [u8]),
    Container { at: usize, len: usize },
}

impl Payload<'_> {
    fn len(&self) -> usize {
        match self {
            Payload::Here(bytes) => bytes.len(),
            Payload::Container { len, .. } => *len,
        }
    }

    fn hold(&self) -> HeldBytes {
        match *self {
            Payload::Here(bytes) => HeldBytes::Copy(bytes.to_vec()),
            Payload::Container { at, len } => HeldBytes::Container { at, len },
        }
    }
}

/// What a reassembler did with one segment. Reported rather than swallowed:
/// a dissection that cannot say why a byte is missing is not evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentOutcome {
    /// Bytes were appended to the stream.
    Appended {
        /// How many.
        len: usize,
        /// At what stream offset.
        stream_offset: usize,
    },
    /// Every byte had already been delivered — a pure retransmission.
    Duplicate,
    /// The segment is ahead of `next_seq`; it is held until the gap fills.
    /// A capture that never fills the gap leaves it held, which
    /// [`StreamAssembler::held_segments`] surfaces.
    HeldOutOfOrder,
    /// The segment carried no payload (a bare ACK, or a SYN / FIN whose
    /// sequence space is one byte but whose stream contribution is none).
    NoPayload,
}

/// R311y609 — payload-carrying segments that may arrive with a gap still open
/// before the assembler judges it permanent and steps over it.
///
/// Measured in SEGMENTS on this direction rather than in packets of the
/// capture or in time: a retransmission is prompted by the peer's ACKs, so the
/// natural unit is how much this sender got through while the missing bytes
/// did not arrive. 64 is comfortably more than one congestion window's worth
/// of 1460-byte segments at a 64 KiB window, so a fast retransmit and an
/// ordinary RTO both land well inside it.
///
/// The cost of being wrong is bounded and reported either way: too patient
/// delays recovery, too eager splices a gap that would have filled and counts
/// the bytes as missing when they were merely late. Both are visible in
/// [`StreamAssembler::bytes_missing`].
pub const DEFAULT_GAP_PATIENCE: usize = 64;

/// One DIRECTION of one TCP connection, reassembled.
#[derive(Debug)]
pub struct StreamAssembler {
    /// The sequence number of the next byte the stream expects.
    next_seq: Option<u32>,
    /// Whether `next_seq` came from an observed SYN. A stream synchronised
    /// off the first DATA segment instead is missing however much preceded
    /// the capture, and that is a materially different claim.
    synced_from_syn: bool,
    /// The bytes of the runs whose bytes the assembler keeps itself: every run's,
    /// unless its holder lends the capture container the run's packet sits in
    /// (open-debt item 924, step 3), in stream order.
    ///
    /// A log of chunks and not one buffer: a buffer that grows doubles, holding up
    /// to half of what it has unused (1.4 times the stream at 4 KiB segments) and
    /// copying every byte at each doubling, and releasing its front moves every
    /// byte behind it. A run is one segment's bytes and lies in one chunk, so a
    /// read of a run is a slice, and [`Run::place`] is the position the log gave
    /// it, which does not change while it is held.
    kept: ByteLog,
    /// One past the stream's last byte: bytes reassembled so far, trimmed or
    /// not.
    end: usize,
    /// R311y594b — absolute offset of the first byte still RETAINED.
    ///
    /// A file dissection keeps the whole stream because the file ends. A live
    /// tap does not end, so the reassembled bytes of every connection would
    /// grow without bound — the single largest of the five accumulations in
    /// this crate. [`StreamAssembler::trim`] drops the oldest bytes and this
    /// records where the retained region now starts, so the ABSOLUTE offset
    /// space that `PassiveFrame::stream_offset` and the run map live in is
    /// unchanged by trimming. Rebasing to zero instead would silently
    /// re-point every offset a consumer already holds.
    discarded: usize,
    /// The run map, in stream order.
    runs: RunMap,
    /// Segments ahead of `next_seq`, kept until the gap before them fills.
    ///
    /// Each carries [`Self::segments_pushed`] AT THE MOMENT IT WAS HELD — the
    /// clock the gap's patience is measured on (R311y609). A wall clock would
    /// not do: a capture is replayed, not lived, and a file read at 100x must
    /// reach the same verdict.
    pending: Vec<HeldSegment>,
    fin_seen: bool,
    rst_seen: bool,
    /// R311y597 — segments carrying ONLY bytes already delivered.
    ///
    /// [`SegmentOutcome::Duplicate`] decided this from the first commit and
    /// nothing counted it: `push` returned the verdict and every caller
    /// discarded it, so a health summary could report a flow without the one
    /// number that says the link is retransmitting. The judgement existed; the
    /// measurement did not.
    retransmits: usize,
    /// Segments that arrived AHEAD of the expected sequence and were held.
    out_of_order: usize,
    /// Segments carrying some bytes already delivered AND some new ones.
    ///
    /// Kept apart from [`Self::retransmits`] because they are different
    /// events: one wasted a whole segment, the other made progress alongside a
    /// repeat, and a reader diagnosing a link wants to tell them apart.
    partial_overlaps: usize,
    /// R311y609 — payload-carrying segments pushed at this assembler, the
    /// clock an open gap's patience is measured against.
    segments_pushed: usize,
    /// R311y609 — gaps this assembler gave up on and stepped over.
    gaps_forced: usize,
    /// R311y609 — sequence-space bytes those gaps skipped: what the sender
    /// sent and this capture does not contain.
    ///
    /// A DIFFERENT number from the reassembled stream length, which stays
    /// contiguous across a forced gap. Splicing without counting is what makes
    /// a hole indistinguishable from data.
    bytes_missing: u64,
    /// R311y609 — how many payload-carrying segments may arrive with a gap
    /// still open before it is judged permanent. `None` disables forcing,
    /// which is the pre-R311y609 behaviour exactly.
    gap_patience: Option<usize>,
    /// R311y610 — splices not yet reported to the consumer of [`Self::stream`],
    /// in stream order. Drained by [`Self::take_splices`].
    ///
    /// [`Self::bytes_missing`] says a hole exists somewhere; this says WHERE,
    /// and the difference is the whole of R311y610. A consumer handed a
    /// contiguous byte slice cannot place the discontinuity inside it, so it
    /// reads across the splice as if the sender had written those two runs
    /// adjacently — which is exactly what it did NOT do.
    splices: Vec<Splice>,
}

/// What one direction's assembler holds on the heap (open-debt item 924, D7),
/// by structure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StreamMemory {
    /// The reassembled bytes kept for rows that read them again: what the owned
    /// door copies, and nothing of a payload a lent container holds.
    pub(crate) kept: usize,
    /// The run map, one entry per run of bytes and where each came from.
    pub(crate) runs: usize,
    /// Segments held behind a gap, with the copies they hold, and the splices
    /// not yet reported.
    pub(crate) pending: usize,
}

impl StreamAssembler {
    /// What this assembler holds on the heap.
    pub(crate) fn memory(&self) -> StreamMemory {
        StreamMemory {
            kept: self.kept.allocated(),
            runs: self.runs.allocated_bytes(),
            pending: wz_session_core::heap_account::vec_bytes(&self.pending)
                + self
                    .pending
                    .iter()
                    .map(|segment| match &segment.payload {
                        HeldBytes::Copy(bytes) => bytes.capacity(),
                        HeldBytes::Container { .. } => 0,
                    })
                    .sum::<usize>()
                + wz_session_core::heap_account::vec_bytes(&self.splices),
        }
    }
}

/// R311y610 — one discontinuity in the reassembled stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Splice {
    /// Absolute stream offset of the first byte AFTER the hole — the same
    /// offset space [`StreamAssembler::len`] and `PassiveFrame::stream_offset`
    /// live in, so a consumer can split a delivered slice at it.
    pub at_offset: usize,
    /// Sequence-space bytes the hole swallowed.
    pub bytes_missing: u64,
}

/// Hand-written for ONE field: `gap_patience` defaults to
/// [`DEFAULT_GAP_PATIENCE`] rather than to `None`, and a derive would have
/// silently shipped the disabled arm as the default.
impl Default for StreamAssembler {
    fn default() -> Self {
        Self {
            next_seq: None,
            synced_from_syn: false,
            kept: ByteLog::default(),
            end: 0,
            discarded: 0,
            runs: RunMap::default(),
            pending: Vec::new(),
            fin_seen: false,
            rst_seen: false,
            retransmits: 0,
            out_of_order: 0,
            partial_overlaps: 0,
            segments_pushed: 0,
            gaps_forced: 0,
            bytes_missing: 0,
            gap_patience: Some(DEFAULT_GAP_PATIENCE),
            splices: Vec::new(),
        }
    }
}

impl StreamAssembler {
    /// A fresh, unsynchronised assembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// R311y609 — how long this assembler waits on a gap before stepping over
    /// it. `None` never steps over one, which is the pre-R311y609 behaviour
    /// and the arm that proves the forcing is what acts.
    pub fn with_gap_patience(mut self, patience: Option<usize>) -> Self {
        self.gap_patience = patience;
        self
    }

    /// R311y609 — gaps this assembler gave up on.
    pub fn gaps_forced(&self) -> usize {
        self.gaps_forced
    }

    /// R311y609 — sequence-space bytes those gaps skipped.
    ///
    /// The reassembled stream is CONTIGUOUS across a forced gap, so this is
    /// the only place the discontinuity is stated. A consumer reading
    /// [`Self::len`] alone cannot tell a spliced stream from an intact one.
    pub fn bytes_missing(&self) -> u64 {
        self.bytes_missing
    }

    /// R311y609 — give up on the oldest open gap NOW, whatever the patience.
    ///
    /// For the end of a capture, where no further segment will arrive to run
    /// the patience down: a file that stops one segment after a hole would
    /// otherwise hold the rest of the flow forever. Returns the bytes stepped
    /// over, or `None` when no gap is open.
    pub fn force_oldest_gap(&mut self) -> Option<u64> {
        let next = self.next_seq?;
        let target = self.lowest_pending(next)?;
        let missing = target.wrapping_sub(next) as u64;
        self.next_seq = Some(target);
        self.gaps_forced += 1;
        self.bytes_missing += missing;
        // R311y610 — recorded BEFORE the drain, because `len()` is the far side
        // of the hole only until the held segments land on it.
        self.splices.push(Splice {
            at_offset: self.len(),
            bytes_missing: missing,
        });
        self.drain_pending();
        Some(missing)
    }

    /// R311y610 — take the splices recorded since the last call, in stream
    /// order.
    ///
    /// Draining rather than accumulating: the consumer's obligation is to
    /// announce each discontinuity to whatever reads the bytes across it, and
    /// an obligation that has been met should not be met twice.
    /// [`Self::gaps_forced`] and [`Self::bytes_missing`] remain the cumulative
    /// record for a health view.
    pub fn take_splices(&mut self) -> Vec<Splice> {
        core::mem::take(&mut self.splices)
    }

    /// The held segment nearest AHEAD of `next` in sequence space — the far
    /// side of the oldest gap.
    fn lowest_pending(&self, next: u32) -> Option<u32> {
        self.pending
            .iter()
            .map(|held| held.seq)
            .filter(|seq| seq.wrapping_sub(next) as i32 > 0)
            .min_by_key(|seq| seq.wrapping_sub(next))
    }

    /// The reassembled bytes from absolute offset `from` up to `to`, or `None`
    /// when any of them is not retained (trimmed, or not arrived).
    ///
    /// `container` is the capture container the assembler's holder lends, which
    /// a run pushed with [`PayloadAt::Container`] is read from; `None` answers
    /// `None` for a range touching such a run. A range held in one place is
    /// lent; one that spans places (it crosses packets) is gathered into a copy.
    ///
    /// Open-debt item 924, step 3: this replaced the slice of a contiguous
    /// retained stream, which a holder that lends its container does not have.
    pub fn bytes<'a>(
        &'a self,
        from: usize,
        to: usize,
        container: Option<&'a [u8]>,
    ) -> Option<alloc::borrow::Cow<'a, [u8]>> {
        if from < self.discarded || to > self.end || from > to {
            return None;
        }
        if from == to {
            return Some(alloc::borrow::Cow::Borrowed(&[]));
        }
        let first = self.runs.partition_point(|r| r.end() <= from);
        let mut gathered: Option<Vec<u8>> = None;
        let mut at = from;
        for run in self.runs.iter_from(first) {
            // Runs tile the stream: each begins where the one before it ends.
            let start = at.checked_sub(run.stream_offset as usize)?;
            let stop = run.end().min(to) - run.stream_offset as usize;
            let piece = self.run_bytes(&run, start, stop, container)?;
            at = run.stream_offset as usize + stop;
            match gathered.as_mut() {
                None if at == to => return Some(alloc::borrow::Cow::Borrowed(piece)),
                None => {
                    let mut out = Vec::with_capacity(to - from);
                    out.extend_from_slice(piece);
                    gathered = Some(out);
                }
                Some(out) => out.extend_from_slice(piece),
            }
            if at == to {
                break;
            }
        }
        (at == to)
            .then_some(gathered)
            .flatten()
            .map(alloc::borrow::Cow::Owned)
    }

    /// Bytes `start..stop` of `run`, counted from its first byte.
    fn run_bytes<'a>(
        &'a self,
        run: &Run,
        start: usize,
        stop: usize,
        container: Option<&'a [u8]>,
    ) -> Option<&'a [u8]> {
        match run.place() {
            // The run that straddles a trim keeps its whole chunk, and one wholly
            // behind it has none: a read of released bytes answers `None`.
            Place::Kept(place) => self.kept.get((place + start) as u64, stop - start),
            Place::Container(place) => container?.get(place + start..place + stop),
        }
    }

    /// Whether the stream still holds the bytes `from..to`: they have arrived and
    /// have not been trimmed. A cheap answer to what [`Self::bytes`] answers by
    /// reading them, for a caller that is about to remember where they stand.
    pub fn holds(&self, from: usize, to: usize) -> bool {
        from >= self.discarded && from <= to && to <= self.end
    }

    /// Absolute offset of the first retained byte.
    pub fn retained_from(&self) -> usize {
        self.discarded
    }

    /// Bytes reassembled so far, INCLUDING any since trimmed — an absolute
    /// count, so it never goes backwards when a live reader reclaims memory.
    pub fn len(&self) -> usize {
        self.end
    }

    /// Bytes retained: reassembled and not trimmed, from
    /// [`Self::retained_from`] to [`Self::len`].
    pub fn retained_len(&self) -> usize {
        self.end - self.discarded
    }

    /// Bytes the assembler holds a copy of itself, rather than remembering where
    /// they are in a lent container: what its log of chunks has allocated, which
    /// is none for a stream that lends every run.
    #[cfg(test)]
    pub(crate) fn bytes_kept(&self) -> usize {
        self.kept.allocated()
    }

    /// `true` when no bytes have been reassembled.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// R311y594b — drop the oldest bytes until at most `keep` remain.
    /// Returns how many were discarded by THIS call.
    ///
    /// Run map entries entirely inside the discarded region go with them; a
    /// run straddling the new base is kept, because it still answers for the
    /// bytes that survive. What a consumer loses is the ability to attribute
    /// an offset it did not read in time, and [`Self::packet_for_offset`]
    /// answers `None` there rather than pointing at the wrong packet.
    pub fn trim(&mut self, keep: usize) -> usize {
        let retained = self.retained_len();
        if retained <= keep {
            return 0;
        }
        let cut = retained - keep;
        self.discarded += cut;
        let base = self.discarded;
        // Runs are in stream order, so the ones wholly behind the new base are
        // at the front.
        while self.runs.front().is_some_and(|r| r.end() <= base) {
            let _ = self.runs.pop_front();
        }
        // The kept bytes still read: from the first retained run the assembler
        // keeps the bytes of (kept places rise with the stream), from the base
        // where that run straddles it. None: every kept byte goes.
        //
        // R3358 — the log gives back every chunk wholly behind that position, so
        // a stream that once held a lot does not keep the allocation after the
        // trim (what the buffer this replaced did, until it was told to shrink),
        // and what stays is at most the chunk the position falls in.
        let kept_base = self
            .runs
            .iter_from(0)
            .find_map(|r| match r.place() {
                Place::Kept(place) => Some(place + base.saturating_sub(r.stream_offset as usize)),
                Place::Container(_) => None,
            })
            .map_or(u64::MAX, |place| place as u64);
        self.kept.release_before(kept_base);
        cut
    }

    /// R3357 — drop the retained bytes that stand before absolute `offset`.
    /// Returns how many were discarded by THIS call: `0` when `offset` is at or
    /// before [`Self::retained_from`].
    ///
    /// The same trim as [`Self::trim`], asked by position instead of by how much
    /// to keep, because a caller that knows which bytes nothing reads any more
    /// (the ones before its oldest held message) has the offset and not the
    /// length. An offset past the end empties the retained bytes.
    pub fn trim_before(&mut self, offset: usize) -> usize {
        if offset <= self.discarded {
            return 0;
        }
        self.trim(self.len().saturating_sub(offset))
    }

    /// Whether the stream's origin was established from an observed SYN. When
    /// `false`, offset 0 is where the CAPTURE started, not where the stream
    /// did — an observer must not report the two the same way.
    pub fn synced_from_syn(&self) -> bool {
        self.synced_from_syn
    }

    /// Segments still held for a gap that has not filled. A non-zero count at
    /// the end of a capture means bytes are genuinely missing, not merely
    /// late.
    pub fn held_segments(&self) -> usize {
        self.pending.len()
    }

    /// Whether a FIN was observed on this direction.
    pub fn fin_seen(&self) -> bool {
        self.fin_seen
    }

    /// Whether an RST was observed on this direction.
    pub fn rst_seen(&self) -> bool {
        self.rst_seen
    }

    /// The run holding the byte at `stream_offset`, when one does and the byte
    /// was not trimmed.
    fn run_at(&self, stream_offset: usize) -> Option<Run> {
        // An offset whose bytes were trimmed is UNANSWERABLE, not answerable
        // by the nearest surviving run: a live reader that reclaimed memory
        // must not thereby start misattributing old messages to new packets.
        if stream_offset < self.discarded {
            return None;
        }
        let idx = self.runs.partition_point(|r| r.end() <= stream_offset);
        self.runs
            .get(idx)
            .filter(|r| stream_offset >= r.stream_offset as usize)
    }

    /// Which capture packet carried the byte at `stream_offset`.
    pub fn packet_for_offset(&self, stream_offset: usize) -> Option<usize> {
        self.origin_of_offset(stream_offset)
            .map(|(packet, _)| packet)
    }

    /// Every capture packet that carried a byte of `start..end`, in stream
    /// order (a retransmission that filled a gap can make that differ from
    /// packet order), with adjacent runs of one packet named once. A caller
    /// that needs a set sorts and dedups.
    ///
    /// `None` when the range is not answerable as a whole: its first byte was
    /// trimmed (see [`Self::origin_of_offset`] on why the nearest surviving run
    /// is not an answer), or no run holds any byte of it. A range whose middle
    /// fell in a gap answers with the packets that did carry its bytes.
    pub fn packets_in(&self, start: usize, end: usize) -> Option<Vec<usize>> {
        if start < self.discarded || end <= start {
            return None;
        }
        let first = self.runs.partition_point(|r| r.end() <= start);
        let mut packets: Vec<usize> = Vec::new();
        for run in self.runs.iter_from(first) {
            if run.stream_offset as usize >= end {
                break;
            }
            let packet = run.packet_index as usize;
            if packets.last() != Some(&packet) {
                packets.push(packet);
            }
        }
        (!packets.is_empty()).then_some(packets)
    }

    /// Which capture packet carried the byte at `stream_offset`, and
    /// where inside that packet's transport payload it sat.
    ///
    /// One lookup for both halves, so the packet and the position can never
    /// come from two different runs.
    pub fn origin_of_offset(&self, stream_offset: usize) -> Option<(usize, usize)> {
        self.run_at(stream_offset).map(|r| {
            (
                r.packet_index as usize,
                r.segment_offset as usize + (stream_offset - r.stream_offset as usize),
            )
        })
    }

    /// The capture instant, in nanoseconds, of the packet that carried the byte
    /// at `stream_offset` -- the instant [`Self::push_at`] was given with it.
    ///
    /// `None` where [`Self::origin_of_offset`] has no packet to name (the byte
    /// was trimmed, or is not in the stream) and where the caller stated no
    /// instant. It reads the SAME run the packet lookup reads, so the packet a
    /// row names and the instant its record carries cannot come from two
    /// different runs.
    pub fn instant_of_offset(&self, stream_offset: usize) -> Option<u64> {
        self.run_at(stream_offset).and_then(|run| run.at_ns())
    }

    /// Feed one segment belonging to THIS direction, stating no instant for it.
    pub fn push(&mut self, seg: &Segment) -> SegmentOutcome {
        self.push_at(seg, None)
    }

    /// Feed one segment belonging to THIS direction, with the capture instant of
    /// its packet in nanoseconds.
    ///
    /// The instant travels with the segment's bytes wherever they wait: a
    /// segment held ahead of a hole keeps it, and the run it becomes -- when the
    /// hole fills, or is stepped over on patience or at the end of the capture --
    /// carries the instant it was CAPTURED at, however much later it is
    /// delivered. See [`Self::instant_of_offset`].
    pub fn push_at(&mut self, seg: &Segment, at_ns: Option<u64>) -> SegmentOutcome {
        self.push_located(seg, at_ns, PayloadAt::Here)
    }

    /// [`Self::push_at`], saying where else the segment's payload is.
    ///
    /// Open-debt item 924, step 3 (`docs/dissect-row-index.md`): a holder that
    /// lends the capture container the segment's packet sits in names the
    /// payload's offset there, and the assembler then keeps no copy of it; it
    /// reads the bytes from the container through [`Self::bytes`]. The stream,
    /// its offsets and every answer are the ones a copy gives.
    pub fn push_located(
        &mut self,
        seg: &Segment,
        at_ns: Option<u64>,
        at: PayloadAt,
    ) -> SegmentOutcome {
        if seg.rst {
            self.rst_seen = true;
        }
        if seg.syn {
            // The SYN consumes one sequence number; the first data byte is
            // seq + 1. Only an unsynchronised stream adopts it — a
            // retransmitted SYN mid-capture must not rewind an established
            // origin.
            if self.next_seq.is_none() {
                self.next_seq = Some(seg.seq.wrapping_add(1));
                self.synced_from_syn = true;
            }
        }
        if seg.fin {
            self.fin_seen = true;
        }
        if seg.payload.is_empty() {
            return SegmentOutcome::NoPayload;
        }
        self.segments_pushed += 1;
        let next = match self.next_seq {
            Some(n) => n,
            None => {
                // No SYN observed: synchronise on the first data byte seen.
                // Offset 0 then means "where the capture started".
                self.next_seq = Some(seg.seq);
                seg.seq
            }
        };

        let payload = match at {
            PayloadAt::Here => Payload::Here(seg.payload),
            PayloadAt::Container(at) => Payload::Container {
                at,
                len: seg.payload.len(),
            },
        };
        let outcome = self.absorb(next, seg.seq, payload, seg.packet_index, at_ns);
        match outcome {
            SegmentOutcome::Duplicate => self.retransmits += 1,
            SegmentOutcome::HeldOutOfOrder => self.out_of_order += 1,
            _ => {}
        }
        // Absorbing may have completed the gap a held segment waited on.
        self.drain_pending();
        // R311y609 — and if it did not, the gap may have been open long enough
        // to call it permanent. WITHOUT THIS the zenoh layer's own
        // resynchronisation is unreachable in the case that motivates it: a
        // capture that lost a segment holds every later segment here forever,
        // so no byte after the hole ever reaches `PassiveSession` to
        // desynchronise it in the first place. Two layers, one defect.
        self.force_stale_gap();
        outcome
    }

    /// R311y609 — step over a gap that has stayed open past its patience.
    fn force_stale_gap(&mut self) {
        let Some(patience) = self.gap_patience else {
            return;
        };
        let Some(next) = self.next_seq else {
            return;
        };
        // Only segments AHEAD of the stream are waiting on this gap; one
        // behind it is a duplicate the drain will discard.
        let oldest_wait = self
            .pending
            .iter()
            .filter(|held| held.seq.wrapping_sub(next) as i32 > 0)
            .map(|held| held.held_at)
            .min();
        let Some(held_at) = oldest_wait else {
            return;
        };
        if self.segments_pushed.saturating_sub(held_at) < patience {
            return;
        }
        self.force_oldest_gap();
    }

    /// Segments that carried only bytes already delivered — pure
    /// retransmissions.
    ///
    /// ⚠ The three anomaly counters count EVENTS, not a partition of the
    /// segments pushed. A segment held out of order and later absorbed with an
    /// overlap contributes to [`Self::out_of_order`] once and to
    /// [`Self::partial_overlaps`] once, because both happened to it. Summing
    /// them and comparing against a packet count is the misuse this note
    /// exists to prevent.
    pub fn retransmits(&self) -> usize {
        self.retransmits
    }

    /// Segments that arrived ahead of the expected sequence and were held.
    /// See the caveat on [`Self::retransmits`].
    pub fn out_of_order(&self) -> usize {
        self.out_of_order
    }

    /// Segments that repeated some bytes and delivered others. See the caveat
    /// on [`Self::retransmits`].
    pub fn partial_overlaps(&self) -> usize {
        self.partial_overlaps
    }

    /// Absorb one payload against the current `next_seq`, handling the
    /// duplicate / partial-overlap / ahead cases.
    fn absorb(
        &mut self,
        next: u32,
        seq: u32,
        payload: Payload<'_>,
        packet_index: usize,
        at_ns: Option<u64>,
    ) -> SegmentOutcome {
        // Sequence-space distance, wrapping: how far this segment starts
        // AHEAD of what the stream expects. Read as a signed delta so a
        // retransmission (which starts behind) is distinguishable from a
        // segment 4 GiB ahead, which cannot occur on a real flow.
        let delta = seq.wrapping_sub(next) as i32;
        if delta > 0 {
            self.pending.push(HeldSegment {
                seq,
                packet_index,
                payload: payload.hold(),
                held_at: self.segments_pushed,
                at_ns,
            });
            return SegmentOutcome::HeldOutOfOrder;
        }
        // delta <= 0: the segment starts at or before what we expect.
        // `unsigned_abs`, not `-delta`: `i32::MIN` has no positive twin, and
        // negating it overflowed. That segment starts half the sequence space
        // behind, which is far past any payload, so it is a duplicate.
        let already = delta.unsigned_abs() as usize;
        if already >= payload.len() {
            return SegmentOutcome::Duplicate;
        }
        // Only the tail past `next` is new — the partial-overlap case.
        if already > 0 {
            self.partial_overlaps += 1;
        }
        let fresh = payload.len() - already;
        // R311y594b — ABSOLUTE, not an index into the retained bytes. Trimming
        // drops bytes off the front, so the retained length stops being the
        // stream position the moment it happens; runs recorded relatively
        // would all point one trim-length too early, and the run map went
        // EMPTY in the first version of this because `retain` compared those
        // relative offsets against an absolute base.
        let stream_offset = self.end;
        // Only the fresh tail is the run's, wherever the payload is.
        let place = match payload {
            Payload::Here(bytes) => self.kept.append(&bytes[already..]),
            Payload::Container { at, .. } => (at + already) as u64 | IN_CONTAINER,
        };
        self.end += fresh;
        self.runs.push_back(Run {
            stream_offset: stream_offset as u64,
            place,
            packet_index: packet_index as u64,
            at_ns: at_ns.unwrap_or(NO_INSTANT),
            len: u32::try_from(fresh).unwrap_or(u32::MAX),
            segment_offset: u32::try_from(already).unwrap_or(u32::MAX),
        });
        self.next_seq = Some(next.wrapping_add(fresh as u32));
        SegmentOutcome::Appended {
            len: fresh,
            stream_offset,
        }
    }

    /// Repeatedly absorb any held segment that is now contiguous.
    fn drain_pending(&mut self) {
        loop {
            let next = match self.next_seq {
                Some(n) => n,
                None => return,
            };
            let found = self.pending.iter().position(|held| {
                let delta = held.seq.wrapping_sub(next) as i32;
                // Contiguous or overlapping-from-behind, and carrying at
                // least one byte the stream has not seen.
                delta <= 0 && ((-delta) as usize) < held.payload.len()
            });
            match found {
                Some(i) => {
                    let held = self.pending.remove(i);
                    self.absorb(
                        next,
                        held.seq,
                        held.payload.payload(),
                        held.packet_index,
                        held.at_ns,
                    );
                }
                None => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{decapsulate, LINKTYPE_IPV4};
    use alloc::vec;

    /// The bytes `s` retains, as one run.
    fn stream(s: &StreamAssembler) -> Vec<u8> {
        s.bytes(s.retained_from(), s.len(), None)
            .expect("an assembler that lends nothing holds every byte it retains")
            .into_owned()
    }

    /// Build a bare IPv4 + TCP packet and decapsulate it, so the fixtures go
    /// through the REAL parser rather than constructing `Segment` by hand —
    /// a hand-built `Segment` would test the assembler against the author's
    /// idea of what the parser produces.
    fn seg(seq: u32, flags: u8, payload: &[u8], packet_index: usize) -> Segment<'static> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&1000u16.to_be_bytes());
        tcp.extend_from_slice(&2000u16.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(flags);
        tcp.extend_from_slice(&0xFFFFu16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(payload);
        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&tcp);
        // A segment borrows its payload from the packet it was lifted out of,
        // and a fixture's packet has no capture to live in: it is kept for the
        // rest of the test process, a few bytes per call.
        let ip: &'static [u8] = ip.leak();
        match decapsulate(LINKTYPE_IPV4, packet_index, ip).expect("fixture decapsulates") {
            crate::link::Transport::Tcp(s) => s,
            other => panic!("the TCP fixture decapsulated as {other:?}"),
        }
    }

    /// A segment exactly half the sequence space BEHIND what the stream expects
    /// is a duplicate, and not an arithmetic fault.
    ///
    /// The distance is read as an `i32`, and the one value of it that has no
    /// positive twin is `i32::MIN`: negating it overflowed, so a capture with
    /// such a segment (a damaged one, or one a person built) panicked a debug
    /// build inside the reader instead of being read. Found by feeding damaged
    /// containers to the session table door, which must answer every input.
    #[test]
    fn a_segment_half_the_sequence_space_behind_is_a_duplicate() {
        let mut s = StreamAssembler::new();
        assert_eq!(
            s.push(&seg(1000, 0x18, b"hello", 0)),
            SegmentOutcome::Appended {
                len: 5,
                stream_offset: 0
            }
        );
        // next_seq is 1005; 1005 - 2^31 wrapping is the segment's start.
        let behind = 1005u32.wrapping_add(0x8000_0000);
        assert_eq!(
            s.push(&seg(behind, 0x18, b"x", 1)),
            SegmentOutcome::Duplicate
        );
        assert_eq!(stream(&s), b"hello", "nothing was added");
    }

    /// `trim_before` drops the bytes ahead of an offset, leaves the rest at its
    /// absolute positions, and gives the memory back: a vector that held 64 KiB and
    /// holds 1 KiB after the trim does not keep the 64 KiB allocation.
    #[test]
    fn trimming_before_an_offset_keeps_the_rest_and_frees_the_memory() {
        let mut s = StreamAssembler::new();
        let chunk = [7u8; 1000];
        for i in 0..64u32 {
            s.push(&seg(1000 + i * 1000, 0x18, &chunk, i as usize));
        }
        assert_eq!(s.len(), 64_000);
        let held_before = s.kept.allocated();
        assert!(held_before >= 64_000);

        assert_eq!(s.trim_before(0), 0, "an offset at the start trims nothing");
        assert_eq!(s.trim_before(63_000), 63_000);
        assert_eq!(s.retained_from(), 63_000);
        assert_eq!(stream(&s).len(), 1_000);
        assert_eq!(s.len(), 64_000, "the absolute count never goes backwards");
        // The log gives back whole chunks: what stays is the chunk the last
        // kept run lies in (here the largest, a half of all that was held), and
        // every chunk wholly behind it is gone.
        assert!(
            s.kept.allocated() <= held_before / 2 + 1024,
            "the allocation follows what is held, to within a chunk, and not what \
             once was: {} of {held_before}",
            s.kept.allocated()
        );
        assert_eq!(
            s.trim_before(62_000),
            0,
            "an offset already trimmed is a no-op"
        );
        assert_eq!(
            s.trim_before(70_000),
            1_000,
            "past the end empties the stream"
        );
        assert!(stream(&s).is_empty());
    }

    /// The ordinary case: a SYN establishes the origin, then contiguous data.
    #[test]
    fn a_syn_establishes_the_origin_and_data_follows() {
        let mut s = StreamAssembler::new();
        assert_eq!(s.push(&seg(100, 0x02, b"", 0)), SegmentOutcome::NoPayload);
        assert!(s.synced_from_syn(), "the SYN was observed");
        assert_eq!(
            s.push(&seg(101, 0x18, b"hello ", 1)),
            SegmentOutcome::Appended {
                len: 6,
                stream_offset: 0
            }
        );
        assert_eq!(
            s.push(&seg(107, 0x18, b"world", 2)),
            SegmentOutcome::Appended {
                len: 5,
                stream_offset: 6
            }
        );
        assert_eq!(stream(&s), b"hello world");
    }

    /// A capture that started mid-connection has no SYN. The stream still
    /// assembles, but it must NOT claim its offset 0 is the connection's
    /// origin — the distinction an observer has to report honestly.
    #[test]
    fn a_capture_without_a_syn_synchronises_but_says_so() {
        let mut s = StreamAssembler::new();
        s.push(&seg(5000, 0x18, b"midstream", 0));
        assert_eq!(stream(&s), b"midstream");
        assert!(
            !s.synced_from_syn(),
            "offset 0 is where the CAPTURE began, not the stream"
        );
    }

    /// A pure retransmission is dropped. Appending it would insert a
    /// duplicate run mid-stream, which downstream reads as corruption at a
    /// plausible offset — the failure mode that is hardest to attribute.
    #[test]
    fn a_retransmission_is_dropped_not_appended() {
        let mut s = StreamAssembler::new();
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"abcd", 1));
        assert_eq!(
            s.push(&seg(101, 0x18, b"abcd", 2)),
            SegmentOutcome::Duplicate
        );
        assert_eq!(stream(&s), b"abcd", "exactly once");
    }

    /// A PARTIAL overlap contributes only its tail. Dropping it whole would
    /// lose real bytes; appending it whole would duplicate the prefix.
    /// R311y597 — the anomaly counters. The verdicts existed from the first
    /// commit and nothing counted them.
    ///
    /// The CONTROL is the half that makes this a measurement: a clean stream
    /// must leave all three at zero. A counter that only ever goes up reads as
    /// working no matter what it counts.
    #[test]
    fn tcp_anomalies_are_counted_and_a_clean_stream_counts_none() {
        let mut clean = StreamAssembler::new();
        clean.push(&seg(100, 0x02, b"", 0));
        clean.push(&seg(101, 0x18, b"abcd", 1));
        clean.push(&seg(105, 0x18, b"efgh", 2));
        assert_eq!(
            (
                clean.retransmits(),
                clean.out_of_order(),
                clean.partial_overlaps()
            ),
            (0, 0, 0),
            "an in-order stream has no anomalies to report",
        );

        let mut s = StreamAssembler::new();
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"abcd", 1));
        // A pure retransmission of bytes already delivered.
        s.push(&seg(101, 0x18, b"abcd", 2));
        // Ahead of what the stream expects, so held.
        s.push(&seg(111, 0x18, b"jjjj", 3));
        // Overlaps: `cd` was delivered, `ef` is new.
        s.push(&seg(103, 0x18, b"cdef", 4));

        assert_eq!(s.retransmits(), 1, "one whole segment was wasted");
        assert_eq!(s.out_of_order(), 1, "one segment arrived early");
        assert_eq!(
            s.partial_overlaps(),
            1,
            "one segment repeated and progressed"
        );
        assert_eq!(
            stream(&s),
            b"abcdef",
            "the counters must not have changed what was reassembled",
        );
    }

    #[test]
    fn a_partial_overlap_contributes_only_its_new_tail() {
        let mut s = StreamAssembler::new();
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"abcd", 1));
        // Retransmit from 103: "cd" is old, "ef" is new.
        assert_eq!(
            s.push(&seg(103, 0x18, b"cdef", 2)),
            SegmentOutcome::Appended {
                len: 2,
                stream_offset: 4
            }
        );
        assert_eq!(stream(&s), b"abcdef");
    }

    /// Reordering is repaired, not accepted. The out-of-order segment is held
    /// and released the moment the gap fills — including a CHAIN of them, so
    /// the drain is a loop rather than a single step.
    #[test]
    fn reordered_segments_are_held_then_released_in_order() {
        let mut s = StreamAssembler::new();
        s.push(&seg(100, 0x02, b"", 0));
        // Arrival order 3, 2, 1.
        assert_eq!(
            s.push(&seg(107, 0x18, b"CCC", 1)),
            SegmentOutcome::HeldOutOfOrder
        );
        assert_eq!(
            s.push(&seg(104, 0x18, b"BBB", 2)),
            SegmentOutcome::HeldOutOfOrder
        );
        assert_eq!(s.held_segments(), 2);
        assert!(s.is_empty(), "nothing is delivered while the gap is open");
        s.push(&seg(101, 0x18, b"AAA", 3));
        assert_eq!(
            stream(&s),
            b"AAABBBCCC",
            "the whole held chain drains in SEQUENCE order, not arrival order"
        );
        assert_eq!(s.held_segments(), 0);
    }

    /// A gap that never fills leaves the segments held and SAYS SO, rather
    /// than emitting a stream with a silent hole in it.
    #[test]
    fn an_unfilled_gap_is_reported_not_papered_over() {
        let mut s = StreamAssembler::new();
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"AAA", 1));
        s.push(&seg(200, 0x18, b"ZZZ", 2)); // far ahead; the gap never fills
        assert_eq!(
            stream(&s),
            b"AAA",
            "the hole is not closed by concatenation"
        );
        assert_eq!(s.held_segments(), 1);
    }

    /// R311y609 — a gap that stays open past its patience is STEPPED OVER,
    /// and the bytes it skipped are counted.
    ///
    /// Before this, a capture that lost one segment held every later segment
    /// of that direction forever. Nothing downstream ever saw those bytes, so
    /// the zenoh layer's own resynchronisation could not have run: the frames
    /// it would resynchronise on had not been delivered to it.
    #[test]
    fn a_gap_open_past_its_patience_is_stepped_over_and_counted() {
        // Patience 3: the segment held at push 2 is given up on at push 5.
        let mut s = StreamAssembler::new().with_gap_patience(Some(3));
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"AAA", 1));
        // Sequence 104..=199 never arrives. Segments beyond it keep coming.
        for (i, seq) in [200u32, 203, 206].iter().enumerate() {
            s.push(&seg(*seq, 0x18, b"ZZZ", 2 + i));
            assert_eq!(stream(&s), b"AAA", "still waiting at push {}", i + 1);
        }
        s.push(&seg(209, 0x18, b"ZZZ", 5));
        assert_eq!(
            stream(&s),
            b"AAAZZZZZZZZZZZZ",
            "the far side of the gap is delivered once the gap is judged permanent"
        );
        assert_eq!(s.gaps_forced(), 1);
        assert_eq!(
            s.bytes_missing(),
            96,
            "sequence 104..200 is what the capture does not contain"
        );
        assert_eq!(s.held_segments(), 0);
    }

    /// The disabled arm, which is the pre-R311y609 behaviour exactly. Without
    /// it the test above would pass on an assembler that simply concatenated
    /// whatever it held.
    #[test]
    fn patience_none_holds_the_gap_however_long_it_stays_open() {
        let mut s = StreamAssembler::new().with_gap_patience(None);
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"AAA", 1));
        for i in 0..64u32 {
            s.push(&seg(200 + i * 3, 0x18, b"ZZZ", 2 + i as usize));
        }
        assert_eq!(stream(&s), b"AAA", "nothing is stepped over");
        assert_eq!(s.gaps_forced(), 0);
        assert_eq!(s.bytes_missing(), 0);
        assert_eq!(s.held_segments(), 64);
    }

    /// A gap that FILLS is not forced, however many segments passed while it
    /// was open — patience is spent on absence, not on delay.
    #[test]
    fn a_gap_that_fills_is_not_counted_as_missing() {
        let mut s = StreamAssembler::new().with_gap_patience(Some(2));
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"AAA", 1));
        s.push(&seg(107, 0x18, b"CCC", 2)); // ahead: 104..=106 missing
        s.push(&seg(104, 0x18, b"BBB", 3)); // it arrives, late
        assert_eq!(stream(&s), b"AAABBBCCC");
        assert_eq!(s.gaps_forced(), 0);
        assert_eq!(s.bytes_missing(), 0);
    }

    /// The END-OF-CAPTURE arm: a file that stops right after a hole never
    /// spends the patience, so the caller says when to give up.
    #[test]
    fn the_end_of_a_capture_can_force_the_last_gap_by_hand() {
        let mut s = StreamAssembler::new();
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"AAA", 1));
        s.push(&seg(200, 0x18, b"ZZZ", 2));
        assert_eq!(stream(&s), b"AAA", "the patience is nowhere near spent");
        assert_eq!(s.force_oldest_gap(), Some(96));
        assert_eq!(stream(&s), b"AAAZZZ");
        assert_eq!(s.force_oldest_gap(), None, "no gap is open now");
    }

    /// The offset map attributes each byte to the packet that carried it —
    /// including across a run boundary, which is exactly where an off-by-one
    /// in the search would hide.
    #[test]
    fn the_offset_map_attributes_bytes_to_their_packets() {
        let mut s = StreamAssembler::new();
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"AAA", 11));
        s.push(&seg(104, 0x18, b"BB", 22));
        assert_eq!(s.packet_for_offset(0), Some(11));
        assert_eq!(s.packet_for_offset(2), Some(11), "last byte of run 0");
        assert_eq!(s.packet_for_offset(3), Some(22), "first byte of run 1");
        assert_eq!(s.packet_for_offset(4), Some(22));
        assert_eq!(s.packet_for_offset(5), None, "past the end");
    }

    /// Sequence numbers WRAP at 2^32. A comparison that used `<` on the raw
    /// u32 would read the post-wrap segment as a 4 GiB-old retransmission and
    /// silently drop the rest of the stream.
    #[test]
    fn a_sequence_wrap_is_not_read_as_a_retransmission() {
        let mut s = StreamAssembler::new();
        // SYN at 0xFFFF_FFFD -> first data byte at 0xFFFF_FFFE.
        s.push(&seg(0xFFFF_FFFD, 0x02, b"", 0));
        s.push(&seg(0xFFFF_FFFE, 0x18, b"AB", 1));
        // next_seq has wrapped to 0.
        assert_eq!(
            s.push(&seg(0, 0x18, b"CD", 2)),
            SegmentOutcome::Appended {
                len: 2,
                stream_offset: 2
            },
            "the segment across the wrap is the NEXT one, not an old one"
        );
        assert_eq!(stream(&s), b"ABCD");
    }

    /// A retransmitted SYN mid-capture must not rewind an established origin
    /// — it would reset `next_seq` and turn every subsequent byte into an
    /// out-of-order hold.
    #[test]
    fn a_repeated_syn_does_not_rewind_the_origin() {
        let mut s = StreamAssembler::new();
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"AAA", 1));
        s.push(&seg(100, 0x02, b"", 2));
        assert_eq!(
            s.push(&seg(104, 0x18, b"BBB", 3)),
            SegmentOutcome::Appended {
                len: 3,
                stream_offset: 3
            }
        );
        assert_eq!(stream(&s), b"AAABBB");
        assert_eq!(s.held_segments(), 0);
    }

    /// FIN and RST are recorded. A stream that ended with an RST is a
    /// different fact from one that ended with a FIN, and both differ from a
    /// capture that simply stopped.
    #[test]
    fn fin_and_rst_are_recorded() {
        let mut s = StreamAssembler::new();
        s.push(&seg(100, 0x02, b"", 0));
        s.push(&seg(101, 0x18, b"x", 1));
        assert!(!s.fin_seen() && !s.rst_seen());
        s.push(&seg(102, 0x11, b"", 2));
        assert!(s.fin_seen());
        s.push(&seg(103, 0x04, b"", 3));
        assert!(s.rst_seen());
    }

    /// A run costs 20 bytes in the map, with the instant stated or not (open-debt
    /// item 924, D10): three columns of 32-bit distances and the instant whole, and
    /// neither the length nor the common zero of `segment_offset` held.
    #[test]
    fn a_run_costs_twenty_bytes_in_the_map() {
        for stated in [false, true] {
            let mut s = StreamAssembler::new();
            s.push(&seg(100, 0x02, b"", 0));
            let n = 8 * wz_session_core::chunk_log::CHUNK_ITEMS;
            for k in 0..n {
                let segment = seg(101 + 4 * k as u32, 0x18, b"abcd", 1 + k);
                let at = stated.then_some(1_000_000_000 + 25_000 * k as u64);
                s.push_at(&segment, at);
            }
            let per_run = s.memory().runs as f64 / n as f64;
            assert!(
                (20.0..20.2).contains(&per_run),
                "stated {stated}: {per_run}"
            );
            assert_eq!(s.memory().pending, 0);
        }
    }

    /// The map answers what the runs it replaced did, across chunk edges, a
    /// partial overlap (the one run whose segment offset is not zero), a
    /// retransmission, and a trim in the middle of a run.
    #[test]
    fn the_run_map_reads_back_what_was_pushed_after_a_trim() {
        let mut s = StreamAssembler::new();
        s.push(&seg(100, 0x02, b"", 0));
        let mut expected = Vec::new();
        let mut next = 101u32;
        let n = 3 * wz_session_core::chunk_log::CHUNK_ITEMS + 11;
        for k in 0..n {
            let body = [b'a' + (k % 26) as u8; 5];
            // Every 500th segment repeats its first two bytes: a partial overlap.
            let (seq, bytes) = if k % 500 == 499 {
                (
                    next - 2,
                    [&expected[expected.len() - 2..], &body[..]].concat(),
                )
            } else {
                (next, body.to_vec())
            };
            s.push_at(&seg(seq, 0x18, &bytes, 10 + k), Some(7 + 3 * k as u64));
            expected.extend_from_slice(&body);
            next += 5;
        }
        assert_eq!(stream(&s), expected);
        for probe in [0usize, 4, 5, 2_499, 2_500, 5_000, expected.len() - 1] {
            let (packet, within) = s.origin_of_offset(probe).expect("held");
            let run = probe / 5;
            let overlapped = run % 500 == 499;
            assert_eq!(packet, 10 + run, "offset {probe}");
            assert_eq!(
                within,
                (probe % 5) + if overlapped { 2 } else { 0 },
                "offset {probe}"
            );
            assert_eq!(s.instant_of_offset(probe), Some(7 + 3 * run as u64));
        }
        let before = s.memory().runs;
        let cut = s.trim(expected.len() - 7_503);
        assert_eq!(cut, 7_503);
        assert!(s.memory().runs < before);
        assert_eq!(s.origin_of_offset(cut - 1), None);
        let (packet, _) = s.origin_of_offset(cut).expect("the straddled run answers");
        assert_eq!(packet, 10 + cut / 5);
        assert_eq!(
            s.bytes(cut, expected.len(), None)
                .expect("held")
                .into_owned(),
            expected[cut..].to_vec()
        );
        assert_eq!(
            s.packets_in(cut, cut + 12).expect("held"),
            alloc::vec![10 + cut / 5, 11 + cut / 5, 12 + cut / 5]
        );
    }
}

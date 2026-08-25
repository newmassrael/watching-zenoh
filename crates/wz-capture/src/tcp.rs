// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use alloc::vec::Vec;

use crate::link::Segment;

/// A contiguous run of stream bytes contributed by one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetRun {
    /// Offset of the run's first byte within the direction's stream.
    pub stream_offset: usize,
    /// Run length in bytes.
    pub len: usize,
    /// Index of the capture packet that carried it.
    pub packet_index: usize,
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
    stream: Vec<u8>,
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
    runs: Vec<OffsetRun>,
    /// Segments ahead of `next_seq`, kept until the gap before them fills.
    ///
    /// The trailing `usize` is [`Self::segments_pushed`] AT THE MOMENT THE
    /// SEGMENT WAS HELD — the clock the gap's patience is measured on
    /// (R311y609). A wall clock would not do: a capture is replayed, not
    /// lived, and a file read at 100x must reach the same verdict.
    pending: Vec<(u32, usize, Vec<u8>, usize)>,
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
            stream: Vec::new(),
            discarded: 0,
            runs: Vec::new(),
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
            .map(|(seq, ..)| *seq)
            .filter(|seq| seq.wrapping_sub(next) as i32 > 0)
            .min_by_key(|seq| seq.wrapping_sub(next))
    }

    /// The reassembled bytes still RETAINED. Starts at absolute offset
    /// [`Self::retained_from`], which is `0` until something is trimmed.
    pub fn stream(&self) -> &[u8] {
        &self.stream
    }

    /// Absolute offset of the first retained byte.
    pub fn retained_from(&self) -> usize {
        self.discarded
    }

    /// Bytes reassembled so far, INCLUDING any since trimmed — an absolute
    /// count, so it never goes backwards when a live reader reclaims memory.
    pub fn len(&self) -> usize {
        self.discarded + self.stream.len()
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
        if self.stream.len() <= keep {
            return 0;
        }
        let cut = self.stream.len() - keep;
        self.stream.drain(..cut);
        self.discarded += cut;
        let base = self.discarded;
        self.runs.retain(|r| r.stream_offset + r.len > base);
        cut
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

    /// The per-run offset map, in stream order.
    pub fn runs(&self) -> &[OffsetRun] {
        &self.runs
    }

    /// Which capture packet carried the byte at `stream_offset`.
    pub fn packet_for_offset(&self, stream_offset: usize) -> Option<usize> {
        // An offset whose bytes were trimmed is UNANSWERABLE, not answerable
        // by the nearest surviving run: a live reader that reclaimed memory
        // must not thereby start misattributing old messages to new packets.
        if stream_offset < self.discarded {
            return None;
        }
        let idx = self
            .runs
            .partition_point(|r| r.stream_offset + r.len <= stream_offset);
        self.runs
            .get(idx)
            .filter(|r| stream_offset >= r.stream_offset)
            .map(|r| r.packet_index)
    }

    /// Feed one segment belonging to THIS direction.
    pub fn push(&mut self, seg: &Segment) -> SegmentOutcome {
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

        let outcome = self.absorb(next, seg.seq, &seg.payload, seg.packet_index);
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
            .filter(|(seq, ..)| seq.wrapping_sub(next) as i32 > 0)
            .map(|(.., held_at)| *held_at)
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
        payload: &[u8],
        packet_index: usize,
    ) -> SegmentOutcome {
        // Sequence-space distance, wrapping: how far this segment starts
        // AHEAD of what the stream expects. Read as a signed delta so a
        // retransmission (which starts behind) is distinguishable from a
        // segment 4 GiB ahead, which cannot occur on a real flow.
        let delta = seq.wrapping_sub(next) as i32;
        if delta > 0 {
            self.pending
                .push((seq, packet_index, payload.to_vec(), self.segments_pushed));
            return SegmentOutcome::HeldOutOfOrder;
        }
        // delta <= 0: the segment starts at or before what we expect.
        let already = (-delta) as usize;
        if already >= payload.len() {
            return SegmentOutcome::Duplicate;
        }
        // Only the tail past `next` is new — the partial-overlap case.
        if already > 0 {
            self.partial_overlaps += 1;
        }
        let fresh = &payload[already..];
        // R311y594b — ABSOLUTE, not an index into the retained Vec. Trimming
        // drops bytes off the front, so `self.stream.len()` stops being the
        // stream position the moment it happens; runs recorded relatively
        // would all point one trim-length too early, and the run map went
        // EMPTY in the first version of this because `retain` compared those
        // relative offsets against an absolute base.
        let stream_offset = self.discarded + self.stream.len();
        self.stream.extend_from_slice(fresh);
        self.runs.push(OffsetRun {
            stream_offset,
            len: fresh.len(),
            packet_index,
        });
        self.next_seq = Some(next.wrapping_add(fresh.len() as u32));
        SegmentOutcome::Appended {
            len: fresh.len(),
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
            let found = self.pending.iter().position(|(seq, _, payload, _)| {
                let delta = seq.wrapping_sub(next) as i32;
                // Contiguous or overlapping-from-behind, and carrying at
                // least one byte the stream has not seen.
                delta <= 0 && ((-delta) as usize) < payload.len()
            });
            match found {
                Some(i) => {
                    let (seq, packet_index, payload, _) = self.pending.remove(i);
                    self.absorb(next, seq, &payload, packet_index);
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

    /// Build a bare IPv4 + TCP packet and decapsulate it, so the fixtures go
    /// through the REAL parser rather than constructing `Segment` by hand —
    /// a hand-built `Segment` would test the assembler against the author's
    /// idea of what the parser produces.
    fn seg(seq: u32, flags: u8, payload: &[u8], packet_index: usize) -> Segment {
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
        match decapsulate(LINKTYPE_IPV4, packet_index, &ip).expect("fixture decapsulates") {
            crate::link::Transport::Tcp(s) => s,
            other => panic!("the TCP fixture decapsulated as {other:?}"),
        }
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
        assert_eq!(s.stream(), b"hello world");
    }

    /// A capture that started mid-connection has no SYN. The stream still
    /// assembles, but it must NOT claim its offset 0 is the connection's
    /// origin — the distinction an observer has to report honestly.
    #[test]
    fn a_capture_without_a_syn_synchronises_but_says_so() {
        let mut s = StreamAssembler::new();
        s.push(&seg(5000, 0x18, b"midstream", 0));
        assert_eq!(s.stream(), b"midstream");
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
        assert_eq!(s.stream(), b"abcd", "exactly once");
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
            s.stream(),
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
        assert_eq!(s.stream(), b"abcdef");
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
            s.stream(),
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
            s.stream(),
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
            assert_eq!(s.stream(), b"AAA", "still waiting at push {}", i + 1);
        }
        s.push(&seg(209, 0x18, b"ZZZ", 5));
        assert_eq!(
            s.stream(),
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
        assert_eq!(s.stream(), b"AAA", "nothing is stepped over");
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
        assert_eq!(s.stream(), b"AAABBBCCC");
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
        assert_eq!(s.stream(), b"AAA", "the patience is nowhere near spent");
        assert_eq!(s.force_oldest_gap(), Some(96));
        assert_eq!(s.stream(), b"AAAZZZ");
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
        assert_eq!(s.stream(), b"ABCD");
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
        assert_eq!(s.stream(), b"AAABBB");
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
}

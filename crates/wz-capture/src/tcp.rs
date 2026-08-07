// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// One DIRECTION of one TCP connection, reassembled.
#[derive(Debug, Default)]
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
    pending: Vec<(u32, usize, Vec<u8>)>,
    fin_seen: bool,
    rst_seen: bool,
}

impl StreamAssembler {
    /// A fresh, unsynchronised assembler.
    pub fn new() -> Self {
        Self::default()
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
        // Absorbing may have completed the gap a held segment waited on.
        self.drain_pending();
        outcome
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
            self.pending.push((seq, packet_index, payload.to_vec()));
            return SegmentOutcome::HeldOutOfOrder;
        }
        // delta <= 0: the segment starts at or before what we expect.
        let already = (-delta) as usize;
        if already >= payload.len() {
            return SegmentOutcome::Duplicate;
        }
        // Only the tail past `next` is new — the partial-overlap case.
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
            let found = self.pending.iter().position(|(seq, _, payload)| {
                let delta = seq.wrapping_sub(next) as i32;
                // Contiguous or overlapping-from-behind, and carrying at
                // least one byte the stream has not seen.
                delta <= 0 && ((-delta) as usize) < payload.len()
            });
            match found {
                Some(i) => {
                    let (seq, packet_index, payload) = self.pending.remove(i);
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

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y606 — IP fragment reassembly, v4 and v6 through one table.
//!
//! ## What was wrong before this
//!
//! `link.rs` named a non-first fragment and skipped it, which read as a
//! reachability gap and was recorded as one. It was worse than that. A FIRST
//! fragment has offset zero, so the offset test called it a whole datagram and
//! handed its prefix to the transport layer:
//!
//! - **UDP** — `strip_udp` reads the header's own `length`, finds the captured
//!   bytes short of it, and returns `Truncated`. The datagram is lost and the
//!   reason blames the capture's snaplen for the network's MTU.
//! - **TCP** — nothing catches it. The segment is delivered with fewer bytes
//!   than the sender sent, the stream advances by that much, and every later
//!   segment is off by the difference. Desynchronisation is TERMINAL
//!   (`passive.rs:394`), so one fragmented segment kills the flow for the rest
//!   of the capture.
//!
//! So this is not only reach; it is a silent wrong answer on the path that had
//! no assertion.
//!
//! ## The key
//!
//! RFC 791 §3.2 and RFC 8200 §4.5 agree on the shape: a datagram is identified
//! by (source, destination, protocol, identification). IPv6 drops protocol from
//! the tuple — its identification is 32 bits and per-source — but including it
//! is harmless there and lets one table serve both. The two families cannot
//! collide because [`Endpoint`](crate::link::Endpoint) distinguishes them by
//! address LENGTH.
//!
//! ## Overlap
//!
//! Fragments may overlap, and what to do about it is the oldest evasion
//! question in the book: hosts disagree (BSD keeps the first, some Windows
//! stacks the last), and an attacker who knows which one an analyser picked can
//! show it a different datagram than the target assembles.
//!
//! This keeps the FIRST bytes written and COUNTS the overlap. Picking one is
//! unavoidable; hiding it is not. A capture with a nonzero
//! [`crate::frag::FragmentStats::overlapping`] is telling the analyst that the reassembly
//! here may not be the reassembly the receiving host performed, which is the
//! actionable fact — and it is why this is a counter rather than a log line.
//!
//! ## Bounds
//!
//! A capture is adversarial input: fragments that never complete would
//! accumulate forever, and a single datagram claiming a 64 KiB tail would
//! allocate that much on the first piece. So the table caps concurrent
//! datagrams, drops the OLDEST when full, and enforces the protocol's own
//! 65 535-byte ceiling. Every one of those is counted — a bound that is silent
//! reports itself as the wire's, which is the rule
//! [`DissectionDrops`](crate::DissectionDrops) exists for one layer up.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::link::{Endpoint, FragmentInfo, IpFragment};

/// The identity of a datagram being reassembled.
///
/// `Ord` rather than `Hash`: this crate is `no_std` + `alloc` with no
/// third-party dependencies, so the map behind it is a `BTreeMap` and the key
/// has to order. The ordering itself carries no meaning — `Endpoint` already
/// orders for [`FlowKey`](crate::link::FlowKey)'s canonicalisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FragmentKey {
    /// Source address, port zero.
    pub src: Endpoint,
    /// Destination address, port zero.
    pub dst: Endpoint,
    /// Upper-layer protocol.
    pub proto: u8,
    /// The identification field, widened from IPv4's 16 bits.
    pub ident: u32,
}

/// The largest datagram IP can express: a 16-bit total length.
///
/// Enforced rather than trusted. A piece claiming an offset past this is
/// malformed, and without the check it would size an allocation.
pub const MAX_DATAGRAM: usize = 65_535;

/// A datagram every piece of which has arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reassembled {
    /// Which datagram this was.
    pub key: FragmentKey,
    /// The whole upper-layer payload.
    pub payload: Vec<u8>,
    /// The capture index of the piece that COMPLETED it — the packet at which
    /// a reader could first have seen the whole datagram, which is the honest
    /// position for it in the capture's order.
    pub packet_index: usize,
    /// How many pieces it took.
    pub pieces: usize,
    /// Whether any piece overlapped another with different bytes. Carried on
    /// the result and not only in the totals, so a consumer can mark the ONE
    /// datagram rather than the whole capture.
    pub overlapped: bool,
}

/// What reassembly has cost and what it has seen.
///
/// Every field is a count of something the analyst would otherwise not know
/// happened. None of them is an error on its own — a capture that starts
/// mid-datagram legitimately produces `incomplete`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FragmentStats {
    /// Pieces accepted into the table.
    pub pieces: usize,
    /// Datagrams completed.
    pub completed: usize,
    /// Datagrams abandoned because their deadline passed.
    pub expired: usize,
    /// Datagrams evicted to stay inside the concurrency cap.
    pub evicted: usize,
    /// Pieces refused as malformed: past the 65 535-byte ceiling, or a last
    /// piece that contradicts a length already established.
    pub malformed: usize,
    /// Datagrams in which two pieces claimed the same bytes with different
    /// contents. See the module docs — this is an evasion signal, not damage.
    pub overlapping: usize,
}

impl FragmentStats {
    /// `true` when the capture carried any fragmentation at all.
    ///
    /// Deliberately not "anything went wrong": fragmentation is ordinary, and
    /// an `any_*` that reported it as trouble would be true for every capture
    /// crossing a tunnel. The trouble question is `malformed > 0` or
    /// `overlapping > 0`, and those are asked by name.
    pub fn any(&self) -> bool {
        self.pieces > 0 || self.malformed > 0
    }
}

/// One datagram under construction.
#[derive(Debug)]
struct Pending {
    /// Bytes placed so far. Grown to fit each piece; never pre-allocated to
    /// the ceiling, because a first piece at a high offset would otherwise
    /// reserve 64 KiB on the strength of one packet.
    bytes: Vec<u8>,
    /// Which byte positions have been written, as (start, end) runs kept
    /// sorted and merged. A bitmap would be 8 KiB per datagram; the run list
    /// is a handful of entries for any real fragmentation, which is a handful
    /// of pieces by construction.
    runs: Vec<(usize, usize)>,
    /// Total length, known only once the last piece (`more == false`) lands.
    total: Option<usize>,
    /// Pieces accepted.
    pieces: usize,
    /// Whether an overlap with differing bytes was seen.
    overlapped: bool,
    /// The observer clock when the FIRST piece arrived, for the deadline.
    opened_at: Option<u64>,
    /// Monotonic insertion order, for the eviction choice when no clock exists.
    seq: u64,
}

impl Pending {
    fn place(&mut self, offset: usize, payload: &[u8]) -> bool {
        let end = offset + payload.len();
        if end > MAX_DATAGRAM {
            return false;
        }
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
        }
        // First-writer-wins: only the gaps this piece is the first to cover are
        // written, and a byte already covered whose value differs is an
        // overlap. Doing it run by run keeps the comparison to the bytes that
        // actually collide.
        let mut at = offset;
        for &(rs, re) in &self.runs {
            if re <= at {
                continue;
            }
            if rs >= end {
                break;
            }
            if at < rs {
                let gap = rs.min(end);
                self.bytes[at..gap].copy_from_slice(&payload[at - offset..gap - offset]);
                at = gap;
            }
            let seen = re.min(end);
            if at < seen {
                if self.bytes[at..seen] != payload[at - offset..seen - offset] {
                    self.overlapped = true;
                }
                at = seen;
            }
            if at >= end {
                break;
            }
        }
        if at < end {
            self.bytes[at..end].copy_from_slice(&payload[at - offset..]);
        }
        self.add_run(offset, end);
        self.pieces += 1;
        true
    }

    fn add_run(&mut self, start: usize, end: usize) {
        self.runs.push((start, end));
        self.runs.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.runs.len());
        for &(s, e) in &self.runs {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.runs = merged;
    }

    /// Complete exactly when the total is known and one run covers all of it.
    fn complete(&self) -> bool {
        matches!((self.total, self.runs.as_slice()), (Some(t), [(0, e)]) if *e == t)
    }
}

/// Reassembles IP fragments into whole datagrams.
///
/// Holds no reference to the packets it was fed: a piece is copied in and the
/// capture buffer is free to move on, which is what lets a live tap use the
/// same table a file replay does.
#[derive(Debug)]
pub struct FragmentTable {
    pending: BTreeMap<FragmentKey, Pending>,
    stats: FragmentStats,
    /// Concurrent datagrams held. `None` is unbounded, which is what a FILE
    /// replay wants; a live tap sets it.
    max_pending: Option<usize>,
    /// How long an incomplete datagram may sit, in the capture's own
    /// milliseconds. `None` never expires one.
    window_ms: Option<u64>,
    /// Insertion counter, so eviction has an order even for a capture with no
    /// timestamps at all.
    next_seq: u64,
}

impl Default for FragmentTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentTable {
    /// An unbounded table: nothing expires and nothing is evicted.
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            stats: FragmentStats::default(),
            max_pending: None,
            window_ms: None,
            next_seq: 0,
        }
    }

    /// A table bounded by concurrency and by a deadline.
    pub fn bounded(max_pending: Option<usize>, window_ms: Option<u64>) -> Self {
        Self {
            max_pending,
            window_ms,
            ..Self::new()
        }
    }

    /// What reassembly has cost and seen.
    pub fn stats(&self) -> FragmentStats {
        self.stats
    }

    /// Datagrams currently half-assembled.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Place one piece; `Some` when it completed a datagram.
    ///
    /// `now_millis` is the capture's clock, not the wall clock — the same one
    /// [`Dissection`](crate::Dissection) advances per flow, so a replay and a
    /// live tap of the same traffic expire the same datagrams.
    pub fn push(&mut self, piece: IpFragment, now_millis: Option<u64>) -> Option<Reassembled> {
        let IpFragment {
            src,
            dst,
            proto,
            info,
            payload,
            packet_index,
            ..
        } = piece;
        let key = FragmentKey {
            src,
            dst,
            proto,
            ident: info.ident,
        };
        self.expire(now_millis);

        if !self.pending.contains_key(&key) {
            self.make_room();
            let seq = self.next_seq;
            self.next_seq += 1;
            self.pending.insert(
                key,
                Pending {
                    bytes: Vec::new(),
                    runs: Vec::new(),
                    total: None,
                    pieces: 0,
                    overlapped: false,
                    opened_at: now_millis,
                    seq,
                },
            );
        }
        let entry = self.pending.get_mut(&key).expect("just inserted");

        if let Some(total) = declared_total(&info, payload.len()) {
            match entry.total {
                // A second last-piece that disagrees is malformed, and taking
                // the new value would let a forged tail truncate the datagram.
                Some(prev) if prev != total => {
                    self.stats.malformed += 1;
                    return None;
                }
                // A last piece that ends BEFORE bytes already placed is the
                // same contradiction from the other side, and it is the one a
                // test found: the datagram would then never complete, because
                // the run past the end can never be covered.
                _ if entry.runs.last().is_some_and(|&(_, e)| e > total) => {
                    self.stats.malformed += 1;
                    return None;
                }
                _ => entry.total = Some(total),
            }
        }
        // A piece past a total already declared is data after the end of the
        // datagram. Refused rather than placed, for the same reason: placing it
        // leaves a run that nothing can ever cover, and the datagram wedges.
        if entry
            .total
            .is_some_and(|total| info.offset + payload.len() > total)
        {
            self.stats.malformed += 1;
            return None;
        }
        if !entry.place(info.offset, &payload) {
            self.stats.malformed += 1;
            return None;
        }
        self.stats.pieces += 1;

        if !entry.complete() {
            return None;
        }
        let done = self.pending.remove(&key).expect("present");
        self.stats.completed += 1;
        if done.overlapped {
            self.stats.overlapping += 1;
        }
        Some(Reassembled {
            key,
            payload: done.bytes,
            packet_index,
            pieces: done.pieces,
            overlapped: done.overlapped,
        })
    }

    /// Abandon every datagram whose deadline has passed. Returns how many.
    ///
    /// Called on every push, so a consumer never has to remember to; exposed
    /// anyway because a live tap that goes quiet still wants its memory back.
    pub fn expire(&mut self, now_millis: Option<u64>) -> usize {
        let (Some(window), Some(now)) = (self.window_ms, now_millis) else {
            return 0;
        };
        let before = self.pending.len();
        self.pending
            .retain(|_, p| p.opened_at.is_none_or(|t| now.saturating_sub(t) <= window));
        let dropped = before - self.pending.len();
        self.stats.expired += dropped;
        dropped
    }

    /// Evict the oldest-STARTED datagram if inserting one more would exceed
    /// the cap.
    ///
    /// R311y713 (§B5) — oldest-STARTED, by the insertion sequence, and NOT the
    /// least recently active: a chain that has been open longest is the one
    /// least likely ever to complete, which is the opposite of the rule
    /// `max_flows_per_table` uses for flows and the reason the two are stated
    /// apart. `the_cap_evicts_by_when_a_chain_started_not_by_when_it_last_grew`
    /// is the witness; before it, the policy was a `min_by_key` and no
    /// sentence anywhere.
    fn make_room(&mut self) {
        let Some(cap) = self.max_pending else { return };
        if cap == 0 {
            // A cap of zero means reassembly is off; the insert that follows is
            // removed immediately rather than special-cased at every call site.
            return;
        }
        while self.pending.len() >= cap {
            let Some(&victim) = self
                .pending
                .iter()
                .min_by_key(|(_, p)| p.seq)
                .map(|(k, _)| k)
            else {
                return;
            };
            self.pending.remove(&victim);
            self.stats.evicted += 1;
        }
    }
}

/// The datagram's total length, if this piece is the one that declares it.
///
/// Only the LAST piece can: it is the only one whose end is the datagram's
/// end. Every other piece knows its own extent and nothing more.
fn declared_total(info: &FragmentInfo, len: usize) -> Option<usize> {
    (!info.more).then_some(info.offset + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8) -> Endpoint {
        Endpoint::new(&[10, 0, 0, a], 0)
    }

    fn piece(ident: u32, offset: usize, more: bool, payload: &[u8], index: usize) -> IpFragment {
        IpFragment {
            src: v4(1),
            dst: v4(2),
            proto: 17,
            info: FragmentInfo {
                ident,
                offset,
                more,
            },
            payload: payload.to_vec(),
            packet_index: index,
            checksums: crate::link::Checksums {
                ip: None,
                transport: None,
            },
        }
    }

    /// Two pieces in order make one datagram, and the result is positioned at
    /// the packet that COMPLETED it.
    #[test]
    fn two_pieces_in_order_reassemble() {
        let mut t = FragmentTable::new();
        assert_eq!(t.push(piece(7, 0, true, b"hello ", 1), None), None);
        assert_eq!(t.pending(), 1);
        let done = t
            .push(piece(7, 6, false, b"world", 2), None)
            .expect("the last piece completes it");
        assert_eq!(done.payload, b"hello world");
        assert_eq!(done.packet_index, 2);
        assert_eq!(done.pieces, 2);
        assert!(!done.overlapped);
        assert_eq!(t.pending(), 0);
        assert_eq!(t.stats().completed, 1);
    }

    /// Out of order is the normal case on a real network, and the last piece
    /// arriving FIRST is what makes the total known before the hole is filled.
    #[test]
    fn pieces_out_of_order_reassemble() {
        let mut t = FragmentTable::new();
        assert_eq!(t.push(piece(9, 6, false, b"world", 2), None), None);
        assert_eq!(t.push(piece(9, 3, true, b"lo ", 3), None), None);
        let done = t
            .push(piece(9, 0, true, b"hel", 1), None)
            .expect("the last hole is filled");
        assert_eq!(done.payload, b"hello world");
        assert_eq!(done.pieces, 3);
    }

    /// A piece claiming bytes PAST a total already declared is refused.
    ///
    /// Found by a test rather than reasoned into existence: placing it leaves
    /// a run beyond the end that nothing can ever cover, so the datagram never
    /// completes and sits in the table until its deadline. A silently wedged
    /// entry is the worst of the three outcomes — worse than dropping the
    /// piece and worse than believing it.
    #[test]
    fn a_piece_past_a_declared_total_is_refused() {
        let mut t = FragmentTable::new();
        assert_eq!(t.push(piece(14, 6, false, b"world", 2), None), None);
        assert_eq!(t.push(piece(14, 12, true, b"!", 3), None), None);
        assert_eq!(t.stats().malformed, 1);
        let done = t
            .push(piece(14, 0, true, b"hello ", 1), None)
            .expect("the refusal must not have wedged the datagram");
        assert_eq!(done.payload, b"hello world");
    }

    /// The same contradiction from the other side: a last piece that ends
    /// before bytes already placed.
    #[test]
    fn a_last_piece_shorter_than_what_is_placed_is_refused() {
        let mut t = FragmentTable::new();
        assert_eq!(t.push(piece(15, 8, true, b"tail", 1), None), None);
        assert_eq!(t.push(piece(15, 0, false, b"short", 2), None), None);
        assert_eq!(t.stats().malformed, 1);
    }

    /// Two datagrams interleaved by identification do not mix.
    #[test]
    fn distinct_identifications_do_not_mix() {
        let mut t = FragmentTable::new();
        assert_eq!(t.push(piece(1, 0, true, b"aaaa", 1), None), None);
        assert_eq!(t.push(piece(2, 0, true, b"bbbb", 2), None), None);
        let a = t
            .push(piece(1, 4, false, b"AAAA", 3), None)
            .expect("a completes");
        assert_eq!(a.payload, b"aaaaAAAA");
        let b = t.push(piece(2, 4, false, b"BBBB", 4), None).expect("b");
        assert_eq!(b.payload, b"bbbbBBBB");
    }

    /// An overlap with DIFFERENT bytes keeps the first writer and is counted.
    ///
    /// The negative arm of the module's overlap policy: without the count, an
    /// analyst reading this capture would see one datagram and no sign that the
    /// receiving host may have assembled a different one.
    #[test]
    fn a_conflicting_overlap_keeps_the_first_and_is_counted() {
        let mut t = FragmentTable::new();
        assert_eq!(t.push(piece(3, 0, true, b"AAAAAAAA", 1), None), None);
        // Overlaps bytes 4..8 with different contents, then extends.
        let done = t
            .push(piece(3, 4, false, b"BBBBBBBB", 2), None)
            .expect("completes");
        assert_eq!(done.payload, b"AAAAAAAABBBB");
        assert!(done.overlapped);
        assert_eq!(t.stats().overlapping, 1);
    }

    /// An overlap with the SAME bytes is a plain retransmission and is not an
    /// evasion signal. Distinguishing them is the reason `place` compares
    /// contents instead of just noticing the ranges intersect.
    #[test]
    fn an_identical_overlap_is_not_counted() {
        let mut t = FragmentTable::new();
        assert_eq!(t.push(piece(4, 0, true, b"AAAAAAAA", 1), None), None);
        assert_eq!(t.push(piece(4, 0, true, b"AAAAAAAA", 2), None), None);
        let done = t
            .push(piece(4, 8, false, b"ZZ", 3), None)
            .expect("completes");
        assert_eq!(done.payload, b"AAAAAAAAZZ");
        assert!(!done.overlapped);
        assert_eq!(t.stats().overlapping, 0);
    }

    /// A piece past IP's own 65 535-byte ceiling is refused, and refusing it
    /// does not allocate to it.
    #[test]
    fn a_piece_past_the_ceiling_is_refused() {
        let mut t = FragmentTable::new();
        assert_eq!(t.push(piece(5, MAX_DATAGRAM, false, b"x", 1), None), None);
        assert_eq!(t.stats().malformed, 1);
        assert_eq!(t.stats().pieces, 0);
    }

    /// A second last-piece that contradicts the first is refused rather than
    /// believed — otherwise a forged tail truncates a datagram already sized.
    #[test]
    fn a_contradicting_total_is_refused() {
        let mut t = FragmentTable::new();
        assert_eq!(t.push(piece(6, 8, false, b"tail", 1), None), None);
        assert_eq!(t.push(piece(6, 4, false, b"no", 2), None), None);
        assert_eq!(t.stats().malformed, 1);
    }

    /// The deadline abandons a half-assembled datagram, and says so.
    #[test]
    fn an_abandoned_datagram_expires_and_is_counted() {
        let mut t = FragmentTable::bounded(None, Some(1_000));
        assert_eq!(t.push(piece(8, 0, true, b"head", 1), Some(0)), None);
        assert_eq!(t.pending(), 1);
        // A piece for a DIFFERENT datagram, far enough later to expire the
        // first: expiry runs on push, so it needs no separate tick.
        assert_eq!(t.push(piece(9, 0, true, b"other", 2), Some(2_000)), None);
        assert_eq!(t.stats().expired, 1);
        assert_eq!(t.pending(), 1);
    }

    /// The concurrency cap evicts the OLDEST, and says so.
    #[test]
    fn the_cap_evicts_the_oldest_and_is_counted() {
        let mut t = FragmentTable::bounded(Some(2), None);
        assert_eq!(t.push(piece(10, 0, true, b"a", 1), None), None);
        assert_eq!(t.push(piece(11, 0, true, b"b", 2), None), None);
        assert_eq!(t.push(piece(12, 0, true, b"c", 3), None), None);
        assert_eq!(t.stats().evicted, 1);
        assert_eq!(t.pending(), 2);
        // The evicted one was the first inserted, so its tail no longer
        // completes anything.
        assert_eq!(t.push(piece(10, 1, false, b"z", 4), None), None);
    }

    /// R311y713 (§B5) — and it evicts by WHEN A CHAIN STARTED, not by when it
    /// last grew.
    ///
    /// The distinction the test above cannot see: there, the first-inserted
    /// chain is also the least recently active, so both readings of "oldest"
    /// name the same victim. Here chain 10 keeps receiving and is still the
    /// one thrown away, which pins the policy rather than the coincidence —
    /// and it is the OPPOSITE of what `max_flows_per_table` does to flows.
    #[test]
    fn the_cap_evicts_by_when_a_chain_started_not_by_when_it_last_grew() {
        let mut t = FragmentTable::bounded(Some(2), None);
        assert_eq!(t.push(piece(10, 0, true, b"a", 1), None), None);
        assert_eq!(t.push(piece(11, 0, true, b"b", 2), None), None);
        // Chain 10 grows AGAIN: it is now the most recently active of the two
        // and still the oldest-started.
        assert_eq!(t.push(piece(10, 1, true, b"a2", 3), None), None);
        assert_eq!(t.pending(), 2, "the fixture must not have completed one");
        // A third chain forces a victim.
        assert_eq!(t.push(piece(12, 0, true, b"c", 4), None), None);
        assert_eq!(t.stats().evicted, 1);
        // Chain 11 first, and the ORDER matters: each push that opens a new
        // chain runs `make_room` again, so probing the evicted chain first
        // would evict the survivor and the second assertion would be reading
        // its own probe.
        assert!(
            t.push(piece(11, 1, false, b"y", 5), None).is_some(),
            "the chain that started later must have survived"
        );
        // And chain 10 is gone, though it moved most recently: its tail
        // completes nothing.
        assert_eq!(
            t.push(piece(10, 3, false, b"z", 6), None),
            None,
            "the oldest-STARTED chain must be the evicted one"
        );
    }

    /// A single unfragmented-looking piece that is both first and last still
    /// completes — the degenerate chain a middlebox can produce.
    #[test]
    fn a_lone_piece_that_is_also_the_last_completes() {
        let mut t = FragmentTable::new();
        let done = t
            .push(piece(13, 0, false, b"whole", 1), None)
            .expect("one piece is enough when it is the last");
        assert_eq!(done.payload, b"whole");
        assert_eq!(done.pieces, 1);
    }
}

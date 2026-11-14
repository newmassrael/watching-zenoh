// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The JOINING STATE of a capture's application-level pieces: one transfer
//! per stream, a verdict per piece.
//!
//! [`crate::segment_profile`] reads one payload as a piece. Which pieces make
//! one message is decided here, from what a receiver of such a sender keeps:
//!
//! * a STREAM is the sender (the list the sample travelled and its direction
//!   there), the key it was published on (the resolved key expression, or the
//!   id and suffix of a reference this capture cannot resolve), what carried
//!   it ([`Carrier`]: a published sample, or the replies to one query) and the
//!   values of the profile's `stream` fields;
//! * a TRANSFER is one message of a stream, numbered by the profile's
//!   `transfer` field. A piece with a new number ends the stream's previous
//!   transfer, whether or not it was joined, and starts the next.
//!
//! # A verdict per piece
//!
//! Every piece is answered, whether or not it joins anything ([`Verdict`]): its
//! CRC, why it cannot be placed (when it cannot), its place in its transfer
//! (the first this capture saw, one in between, the one that completed it, one
//! that alone was the whole, or one that came after the transfer completed),
//! the byte ranges of the whole still missing below the furthest byte
//! received, whether it arrived behind a piece that lies after it, whether it
//! overlaps bytes already received, and the transfers it ended unjoined. A
//! piece whose CRC is wrong or that cannot be placed joins nothing and moves
//! no state: what it claims cannot be trusted.
//!
//! # The joined message
//!
//! The piece that completes a transfer carries the whole message, joined in
//! the order of the offsets the pieces state; where two pieces overlap, the
//! first to arrive wins, because a later copy of bytes already held proves
//! nothing a reader can check. A transfer that never completes yields no
//! message: a partial whole is not a message, and a reader that wants its
//! pieces has them, each on its own row.
//!
//! # What is held, and the bound on it
//!
//! A transfer being joined holds its whole message (at most the profile's
//! `total_max`). The bytes every open transfer holds together are bounded by
//! [`MAX_OPEN_BYTES`]: a transfer that would cross it first ends the least
//! recently fed open transfers, each counted in [`SegmentLedger::evicted`] and
//! named on the piece that caused it, so a capture with many abandoned
//! transfers cannot make the reader hold them all.
//!
//! # Order, and a walk that goes on between calls
//!
//! Pieces are joined in the order they are handed in, which is the order the
//! document walks the rows: one list at a time, in capture order within it.
//! The sender is per list, so one stream never spans two lists. A verdict is
//! kept by the row it came in and its place among that row's pieces, the way
//! [`crate::e2e_slots::SlotLedger`] keeps a frame's, and under that ledger's
//! frontier: a row read again behind it is answered from what was kept and
//! joins nothing a second time.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::segment_profile::{CrcReading, Misplaced, Piece, SegmentProfile};

/// The most bytes every open transfer together may hold.
pub const MAX_OPEN_BYTES: usize = 256 * 1024 * 1024;

/// The key a stream was published on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyRef {
    /// The key expression, resolved.
    Resolved(String),
    /// A reference this capture cannot resolve: the id, and the suffix the
    /// reference wrote after it.
    Unresolved {
        /// The numeric id.
        id: u64,
        /// The suffix, verbatim.
        suffix: Option<Box<str>>,
    },
}

/// What carried a piece: a sample published on its key, or a reply to one
/// query.
///
/// Part of the stream and not a detail of it, because the two are not one
/// sequence. A responder that answers a query with pieces numbers those
/// transfers apart from the ones it publishes live, so a reply's transfer can
/// carry the number of a live one on the same key without being the same
/// message, and the replies to two queries are two streams for the same
/// reason. Joined into one, a reply piece would end the live transfer it
/// interleaves with, or be joined into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Carrier {
    /// A `Push` carrying a `put`: a sample published on its key.
    Push,
    /// A `Reply` carrying a `put`, inside a `Response`.
    Reply {
        /// The request id the `Response` echoes, which names the query it
        /// answers on the direction it travelled.
        request: u64,
    },
}

/// Which stream of transfers a piece belongs to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamKey {
    /// The list the piece travelled.
    pub list: usize,
    /// Its direction on that list (`true` from the low end), when known.
    pub from_low: Option<bool>,
    /// The key it was published on.
    pub key: KeyRef,
    /// What carried it: the live stream of the key, or the replies to one
    /// query.
    pub carrier: Carrier,
    /// The values of the profile's `stream` fields, in the profile's order.
    pub stream: Vec<u64>,
}

/// Where a piece sits in its transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The first piece of the transfer this capture saw, and not the last.
    First,
    /// Neither the first seen nor the one that completed the transfer.
    Continuing,
    /// The piece that completed the transfer.
    Closing,
    /// The first piece seen, and it completed the transfer by itself.
    Whole,
    /// A piece of a transfer that had already completed.
    AfterClosing,
}

impl Place {
    /// Every place, so a document's vocabulary and a test's walk are one list.
    pub const ALL: [Self; 5] = [
        Self::First,
        Self::Continuing,
        Self::Closing,
        Self::Whole,
        Self::AfterClosing,
    ];

    /// The word a machine reads for this place.
    pub const fn word(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Continuing => "continuing",
            Self::Closing => "closing",
            Self::Whole => "whole",
            Self::AfterClosing => "after_closing",
        }
    }
}

/// Why a piece is not part of any transfer, though it is a piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unjoined {
    /// Its CRC does not match.
    CrcMismatch,
    /// It cannot be placed in the whole it claims.
    Misplaced(Misplaced),
    /// It names the transfer being joined and a different total from the one
    /// that transfer began with.
    TotalDisagrees,
}

impl Unjoined {
    /// Every reason, so a document's vocabulary and a test's walk are one list.
    pub const ALL: [Self; 6] = [
        Self::CrcMismatch,
        Self::Misplaced(Misplaced::EmptyTotal),
        Self::Misplaced(Misplaced::TotalPastMax),
        Self::Misplaced(Misplaced::EmptyChunk),
        Self::Misplaced(Misplaced::PastTotal),
        Self::TotalDisagrees,
    ];

    /// The word a machine reads for this reason.
    pub const fn word(self) -> &'static str {
        match self {
            Self::CrcMismatch => "crc_mismatch",
            Self::Misplaced(m) => m.word(),
            Self::TotalDisagrees => "total_disagrees",
        }
    }
}

/// A transfer a piece ended before it completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ended {
    /// Its number.
    pub transfer: u64,
    /// The whole it was joining.
    pub total: u64,
    /// How many of those bytes had arrived.
    pub received: u64,
    /// Whether the bound on held bytes ended it (`true`), rather than its
    /// stream beginning another transfer (`false`).
    pub evicted: bool,
}

/// What the ledger made of one piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The value of every header field, in the profile's order.
    pub values: Vec<u64>,
    /// How many bytes the chunk has.
    pub chunk_bytes: usize,
    /// What the CRC said, when the profile has one.
    pub crc: Option<CrcReading>,
    /// Why the piece joins no transfer, or `None` when it joins one.
    pub unjoined: Option<Unjoined>,
    /// Its place in its transfer, when it joins one.
    pub place: Option<Place>,
    /// The ranges `[from, to)` of the whole still missing below the furthest
    /// byte the transfer has received, after this piece; empty when it joins
    /// none.
    pub missing: Vec<(u64, u64)>,
    /// Whether it starts before the furthest byte already received, without
    /// overlapping what was received.
    pub out_of_order: bool,
    /// Whether it overlaps bytes the transfer had already received.
    pub overlap: bool,
    /// The transfers this piece ended before they completed: its stream's
    /// previous one, and any the bound on held bytes ended to make room.
    pub ended: Vec<Ended>,
    /// The whole message, on the piece that completed its transfer. Shared,
    /// not copied, between the verdict a walk writes and the one the ledger
    /// keeps for the row, and `Arc` because a live handle that holds the
    /// ledger is sent between threads.
    pub joined: Option<Arc<[u8]>>,
}

/// One transfer of a stream.
#[derive(Debug, Clone)]
struct Transfer {
    number: u64,
    total: u64,
    /// The whole being joined; empty once completed (the message went out on
    /// the completing piece).
    buffer: Vec<u8>,
    /// The ranges received, sorted and disjoint.
    have: Vec<(u64, u64)>,
    /// The furthest byte received.
    high: u64,
    completed: bool,
    /// When it was last fed, by the ledger's own count, for eviction.
    touched: u64,
}

impl Transfer {
    fn received(&self) -> u64 {
        self.have.iter().map(|(a, b)| b - a).sum()
    }

    /// The gaps of `[0, high)` not yet received.
    fn missing(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut at = 0u64;
        for &(a, b) in &self.have {
            if a > at {
                out.push((at, a));
            }
            at = at.max(b);
        }
        if at < self.high {
            out.push((at, self.high));
        }
        out
    }

    /// Take `chunk` at `from`, copying only into bytes not yet received, and
    /// answer whether any of it had been.
    fn take(&mut self, from: u64, chunk: &[u8]) -> bool {
        let to = from + chunk.len() as u64;
        let mut overlap = false;
        let mut at = from;
        let mut fresh: Vec<(u64, u64)> = Vec::new();
        for &(a, b) in &self.have {
            if b <= at || a >= to {
                continue;
            }
            overlap = true;
            if a > at {
                fresh.push((at, a));
            }
            at = at.max(b);
        }
        if at < to {
            fresh.push((at, to));
        }
        for &(a, b) in &fresh {
            let (sa, sb) = ((a - from) as usize, (b - from) as usize);
            self.buffer[a as usize..b as usize].copy_from_slice(&chunk[sa..sb]);
        }
        self.have.extend(fresh);
        self.have.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.have.len());
        for &(a, b) in &self.have {
            match merged.last_mut() {
                Some(last) if a <= last.1 => last.1 = last.1.max(b),
                _ => merged.push((a, b)),
            }
        }
        self.have = merged;
        self.high = self.high.max(to);
        overlap
    }

    fn complete(&self) -> bool {
        self.have.as_slice() == [(0, self.total)]
    }

    fn ended(&self, evicted: bool) -> Ended {
        Ended {
            transfer: self.number,
            total: self.total,
            received: self.received(),
            evicted,
        }
    }
}

/// The joining state of a run: a transfer per stream seen, and the verdicts
/// kept by row.
///
/// `Clone` because a fold kept between calls is (the values door keeps one in
/// its fold, beside the payloads that fold already holds by value).
#[derive(Debug, Clone)]
pub struct SegmentLedger {
    streams: BTreeMap<StreamKey, Transfer>,
    /// The most bytes the open transfers may hold together.
    bound: usize,
    /// The bytes every open transfer holds together.
    held: usize,
    /// How many open transfers the bound on held bytes ended.
    evicted: usize,
    /// The ledger's own clock, one tick per piece.
    clock: u64,
    /// The verdict of each piece joined, by its list, its row's produced-index
    /// and its place among the pieces of that row. Kept for the field walker,
    /// so built with it, as [`crate::e2e_slots::SlotLedger`]'s is.
    #[cfg(feature = "dissect")]
    judged: BTreeMap<(usize, u64, u32), Verdict>,
}

impl Default for SegmentLedger {
    fn default() -> Self {
        Self::with_bound(MAX_OPEN_BYTES)
    }
}

impl SegmentLedger {
    /// A ledger that has seen nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// A ledger whose open transfers may hold at most `bound` bytes together,
    /// instead of [`MAX_OPEN_BYTES`].
    pub fn with_bound(bound: usize) -> Self {
        Self {
            streams: BTreeMap::new(),
            bound,
            held: 0,
            evicted: 0,
            clock: 0,
            #[cfg(feature = "dissect")]
            judged: BTreeMap::new(),
        }
    }

    /// How many open transfers the bound on held bytes ended.
    pub fn evicted(&self) -> usize {
        self.evicted
    }

    /// The bytes the open transfers hold.
    pub fn held(&self) -> usize {
        self.held
    }

    /// What was kept for the piece at `ordinal` of the row `produced` of
    /// `list`.
    #[cfg(feature = "dissect")]
    pub(crate) fn recall(&self, list: usize, produced: u64, ordinal: u32) -> Option<Verdict> {
        self.judged.get(&(list, produced, ordinal)).cloned()
    }

    /// Keep `verdict` for the piece at `ordinal` of the row `produced` of
    /// `list`.
    #[cfg(feature = "dissect")]
    pub(crate) fn remember(&mut self, list: usize, produced: u64, ordinal: u32, verdict: &Verdict) {
        self.judged
            .insert((list, produced, ordinal), verdict.clone());
    }

    /// Let go of what was kept for the rows of `list` older than `first_held`,
    /// joined messages included.
    #[cfg(feature = "dissect")]
    pub(crate) fn forget_before(&mut self, list: usize, first_held: u64) {
        let gone: Vec<(usize, u64, u32)> = self
            .judged
            .range((list, 0, 0)..(list, first_held, 0))
            .map(|(key, _)| *key)
            .collect();
        for key in gone {
            let _ = self.judged.remove(&key);
        }
    }

    /// Join one payload `profile` recognised as a piece, published on `key`,
    /// carried by `carrier` and travelling `list` in the direction `from_low`
    /// says.
    pub fn receive(
        &mut self,
        profile: &SegmentProfile,
        piece: &Piece<'_>,
        list: usize,
        from_low: Option<bool>,
        key: KeyRef,
        carrier: Carrier,
    ) -> Verdict {
        self.clock += 1;
        let mut verdict = Verdict {
            values: piece.values.clone(),
            chunk_bytes: piece.chunk.len(),
            crc: piece.crc,
            unjoined: None,
            place: None,
            missing: Vec::new(),
            out_of_order: false,
            overlap: false,
            ended: Vec::new(),
            joined: None,
        };
        if piece.crc.is_some_and(|c| !c.matches()) {
            verdict.unjoined = Some(Unjoined::CrcMismatch);
            return verdict;
        }
        let (total, offset) = match profile.place(piece) {
            Ok(placed) => placed,
            Err(why) => {
                verdict.unjoined = Some(Unjoined::Misplaced(why));
                return verdict;
            }
        };
        let number = piece.values[profile.transfer()];
        let stream = StreamKey {
            list,
            from_low,
            key,
            carrier,
            stream: profile.stream().iter().map(|&i| piece.values[i]).collect(),
        };

        match self.streams.get(&stream) {
            Some(current) if current.number == number => {
                if current.total != total {
                    verdict.unjoined = Some(Unjoined::TotalDisagrees);
                    return verdict;
                }
            }
            _ => {
                // A new transfer: the stream's previous one ends here.
                if let Some(previous) = self.streams.remove(&stream) {
                    self.held -= previous.buffer.len();
                    if !previous.completed {
                        verdict.ended.push(previous.ended(false));
                    }
                }
                // `place` held `total` to the profile's maximum, which the
                // profile held to `MAX_TOTAL_BYTES`, so it fits a `usize`.
                let need = total as usize;
                self.make_room(need, &mut verdict.ended);
                self.held += need;
                self.streams.insert(
                    stream.clone(),
                    Transfer {
                        number,
                        total,
                        buffer: vec![0u8; need],
                        have: Vec::new(),
                        high: 0,
                        completed: false,
                        touched: self.clock,
                    },
                );
            }
        }
        let clock = self.clock;
        let Some(transfer) = self.streams.get_mut(&stream) else {
            // Found or made just above; a ledger that lost it joins nothing.
            return verdict;
        };
        transfer.touched = clock;
        if transfer.completed {
            verdict.place = Some(Place::AfterClosing);
            verdict.overlap = true;
            return verdict;
        }
        let first = transfer.have.is_empty();
        // Behind the furthest byte already received: a piece a later one
        // overtook. Measured before this piece moves it.
        let behind = offset < transfer.high;
        verdict.overlap = transfer.take(offset, piece.chunk);
        verdict.out_of_order = behind && !verdict.overlap;
        verdict.missing = transfer.missing();
        if transfer.complete() {
            let joined: Arc<[u8]> = Arc::from(core::mem::take(&mut transfer.buffer));
            transfer.completed = true;
            self.held -= joined.len();
            verdict.joined = Some(joined);
            verdict.place = Some(if first { Place::Whole } else { Place::Closing });
        } else {
            verdict.place = Some(if first {
                Place::First
            } else {
                Place::Continuing
            });
        }
        verdict
    }

    /// End the least recently fed open transfers until `need` more bytes fit
    /// under the bound. A transfer larger than the bound by itself is still
    /// joined once every other has been ended: the profile's `total_max`
    /// admitted it, and refusing it would make a large message unjoinable on a
    /// reader with a small bound rather than merely alone.
    fn make_room(&mut self, need: usize, ended: &mut Vec<Ended>) {
        while self.held + need > self.bound {
            let oldest = self
                .streams
                .iter()
                .filter(|(_, t)| !t.completed)
                .min_by_key(|(_, t)| t.touched)
                .map(|(k, _)| k.clone());
            let Some(oldest) = oldest else {
                return;
            };
            if let Some(gone) = self.streams.remove(&oldest) {
                self.held -= gone.buffer.len();
                self.evicted += 1;
                ended.push(gone.ended(true));
            }
        }
    }
}

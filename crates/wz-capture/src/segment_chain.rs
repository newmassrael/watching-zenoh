// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The JOINING STATE of a capture's application-level pieces: one transfer
//! per stream, a verdict per piece.
//!
//! The state itself is `wz-app-frame`'s ([`wz_app_frame::segment_chain`],
//! re-exported here at the path it has always had), so a node that receives
//! such pieces joins them with the same rules a capture is read by. What stays
//! here is the field walker's: the verdict of each piece kept by the row it
//! came in and its place among that row's pieces, under the frontier of a
//! `PieceLedger`, so that a row read again behind it is answered from what was
//! kept and joins nothing a second time.
//!
//! # Order, and a walk that goes on between calls
//!
//! Pieces are joined in the order they are handed in, which is the order the
//! document walks the rows: one list at a time, in capture order within it.
//! The sender is per list, so one stream never spans two lists.

pub use wz_app_frame::segment_chain::*;

#[cfg(feature = "dissect")]
use alloc::collections::BTreeMap;
#[cfg(feature = "dissect")]
use alloc::vec::Vec;

/// The joining state of the field walker: a [`SegmentLedger`], and the verdicts
/// kept by row. It reads as the ledger it holds (`Deref`), so a walker joins a
/// piece through it as through the ledger.
#[cfg(feature = "dissect")]
#[derive(Debug, Clone, Default)]
pub struct JudgedSegments {
    ledger: SegmentLedger,
    /// The verdict of each piece joined, by its list, its row's produced-index
    /// and its place among the pieces of that row.
    judged: BTreeMap<(usize, u64, u32), Verdict>,
    /// What each `ResponseFinal` closed, kept by the same key as a piece's
    /// verdict: a final read again behind the frontier is answered from here
    /// and ends nothing a second time.
    closed: BTreeMap<(usize, u64, u32), Vec<Ended>>,
}

#[cfg(feature = "dissect")]
impl core::ops::Deref for JudgedSegments {
    type Target = SegmentLedger;

    fn deref(&self) -> &SegmentLedger {
        &self.ledger
    }
}

#[cfg(feature = "dissect")]
impl core::ops::DerefMut for JudgedSegments {
    fn deref_mut(&mut self) -> &mut SegmentLedger {
        &mut self.ledger
    }
}

#[cfg(feature = "dissect")]
impl JudgedSegments {
    /// A ledger that has joined nothing and kept nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// What was kept for the piece at `ordinal` of the row `produced` of
    /// `list`.
    pub(crate) fn recall(&self, list: usize, produced: u64, ordinal: u32) -> Option<Verdict> {
        self.judged.get(&(list, produced, ordinal)).cloned()
    }

    /// Keep `verdict` for the piece at `ordinal` of the row `produced` of
    /// `list`.
    pub(crate) fn remember(&mut self, list: usize, produced: u64, ordinal: u32, verdict: &Verdict) {
        self.judged
            .insert((list, produced, ordinal), verdict.clone());
    }

    /// Let go of what was kept for the rows of `list` older than `first_held`,
    /// joined messages included.
    pub(crate) fn forget_before(&mut self, list: usize, first_held: u64) {
        let gone: Vec<(usize, u64, u32)> = self
            .judged
            .range((list, 0, 0)..(list, first_held, 0))
            .map(|(key, _)| *key)
            .collect();
        for key in gone {
            let _ = self.judged.remove(&key);
        }
        let gone: Vec<(usize, u64, u32)> = self
            .closed
            .range((list, 0, 0)..(list, first_held, 0))
            .map(|(key, _)| *key)
            .collect();
        for key in gone {
            let _ = self.closed.remove(&key);
        }
    }

    /// What was kept for the final at `ordinal` of the row `produced` of
    /// `list`.
    pub(crate) fn recall_close(
        &self,
        list: usize,
        produced: u64,
        ordinal: u32,
    ) -> Option<Vec<Ended>> {
        self.closed.get(&(list, produced, ordinal)).cloned()
    }

    /// Keep what the final at `ordinal` of the row `produced` of `list` ended.
    pub(crate) fn remember_close(
        &mut self,
        list: usize,
        produced: u64,
        ordinal: u32,
        ended: &[Ended],
    ) {
        self.closed
            .insert((list, produced, ordinal), ended.to_vec());
    }
}

/// How far one list has been walked in the order a walk over the whole capture
/// walks it: every row before `produced` was walked, and the largest
/// capture-order key among them is `last_key` (`None` for a list walked in its
/// own order, a datagram list).
#[cfg(feature = "dissect")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Frontier {
    /// The produced-index of the first row not walked.
    pub produced: u64,
    /// The largest key walked, for a list walked in capture order.
    pub last_key: Option<(usize, u64)>,
}

/// The pieces the field walker joins, and how far it has joined each list.
///
/// A piece's verdict is a fact about the pieces of its stream before it, so a
/// walk that reads a row again behind the frontier answers from what was kept
/// and joins nothing a second time, and a walk that goes on from where the last
/// one stopped joins against the streams it left. The end-to-end counters are
/// not here: the payload plane judges them (`crate::e2e_plane`) and the walker
/// reads what it judged.
#[cfg(feature = "dissect")]
#[derive(Debug, Default, Clone)]
pub struct PieceLedger {
    segments: JudgedSegments,
    frontiers: BTreeMap<usize, Frontier>,
}

#[cfg(feature = "dissect")]
impl PieceLedger {
    /// A ledger that has joined nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// How far the list at `list` has been walked in order.
    pub(crate) fn frontier(&self, list: usize) -> Frontier {
        self.frontiers.get(&list).copied().unwrap_or_default()
    }

    /// The list at `list` has been walked in order up to `frontier`; a frontier
    /// behind the one held moves nothing.
    pub(crate) fn walked_up_to(&mut self, list: usize, frontier: Frontier) {
        let held = self.frontiers.entry(list).or_default();
        if frontier.produced > held.produced {
            *held = frontier;
        }
    }

    /// Let go of what was kept of the rows of `list` older than `first_held`,
    /// the produced-index of the oldest row it holds.
    pub(crate) fn forget_before(&mut self, list: usize, first_held: u64) {
        self.segments.forget_before(list, first_held);
    }

    /// The joining state.
    pub(crate) fn segments(&self) -> &JudgedSegments {
        &self.segments
    }

    /// The joining state, to join one piece.
    pub(crate) fn segments_mut(&mut self) -> &mut JudgedSegments {
        &mut self.segments
    }
}

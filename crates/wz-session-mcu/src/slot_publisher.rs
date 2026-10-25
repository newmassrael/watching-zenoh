// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A publisher of the client node: a fixed document put on a key every period, for as long as a
//! session is established.
//!
//! What is here is what a publisher IS and what is counted of it: the [`Publication`] (a key, a
//! period, a document), the counts of the puts that went out and that were refused
//! ([`PublishCounts`], one `static` of the image's whose initial value is all zero bytes, so it is
//! `.bss`), and the watch the program's loop says them with ([`PublishWatch`]). The puts themselves
//! are sent by the session's application layer, inside its event, on the cadence of
//! [`crate::slot_schedule::Schedule`] (`crate::slot_active::Active`): nothing runs on the program's
//! main loop and nothing is left in a mailbox, so the cadence is the session's.
//!
//! This module does not link `alloc`.

use core::cell::Cell;

use crate::slot_schedule::Periodic;

/// One publisher: the document it puts on its key, and how often.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publication {
    /// The key it puts on, a literal key expression.
    pub key: &'static str,
    /// The time between two puts, in milliseconds (at least 1).
    pub period_ms: u32,
    /// What it puts.
    pub body: &'static str,
}

impl Publication {
    /// A publication that puts nothing, to fill an array with.
    pub const NONE: Self = Self {
        key: "",
        period_ms: 1,
        body: "",
    };
}

impl Periodic for Publication {
    fn period_ms(&self) -> u32 {
        self.period_ms
    }
}

/// How many puts each publication sent and had refused, in storage the image declares.
pub struct PublishCounts<const P: usize> {
    sent: [Cell<u32>; P],
    refused: [Cell<u32>; P],
}

// SAFETY: the profile's rule: one thread drives the node, and both the session's layer (which
// writes) and the program's loop (which reads) run on it, never at the same moment.
unsafe impl<const P: usize> Sync for PublishCounts<P> {}

impl<const P: usize> PublishCounts<P> {
    /// Every count zero; all zero bytes.
    pub const fn new() -> Self {
        Self {
            sent: [const { Cell::new(0) }; P],
            refused: [const { Cell::new(0) }; P],
        }
    }

    fn bump(cells: &[Cell<u32>; P], at: usize) {
        if let Some(cell) = cells.get(at) {
            cell.set(cell.get().wrapping_add(1));
        }
    }

    /// The put of publication `at` went out.
    pub fn record_sent(&self, at: usize) {
        Self::bump(&self.sent, at);
    }

    /// The put of publication `at` was refused.
    pub fn record_refused(&self, at: usize) {
        Self::bump(&self.refused, at);
    }

    /// Puts of publication `at` that went out.
    pub fn sent(&self, at: usize) -> u32 {
        self.sent.get(at).map_or(0, Cell::get)
    }

    /// Puts of publication `at` that were refused.
    pub fn refused(&self, at: usize) -> u32 {
        self.refused.get(at).map_or(0, Cell::get)
    }
}

impl<const P: usize> Default for PublishCounts<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// What the program's loop remembers of the counts between two rounds, to say each change once.
///
/// A round that finds a publication's counts moved calls `say` with the counts NOW: puts that went
/// out between two rounds are one report with a count that jumps, so nothing is hidden by it.
pub struct PublishWatch<const P: usize> {
    seen: [(u32, u32); P],
}

impl<const P: usize> PublishWatch<P> {
    /// A watch that has seen nothing.
    pub const fn new() -> Self {
        Self { seen: [(0, 0); P] }
    }

    /// Call `say(index, sent, refused)` for each publication whose counts moved since the last call.
    pub fn poll(&mut self, counts: &PublishCounts<P>, mut say: impl FnMut(usize, u32, u32)) {
        for (at, seen) in self.seen.iter_mut().enumerate() {
            let now = (counts.sent(at), counts.refused(at));
            if now != *seen {
                *seen = now;
                say(at, now.0, now.1);
            }
        }
    }
}

impl<const P: usize> Default for PublishWatch<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn the_counts_are_kept_by_publication_and_an_index_outside_them_is_nothing() {
        let counts = PublishCounts::<2>::new();
        counts.record_sent(1);
        counts.record_sent(1);
        counts.record_refused(0);
        counts.record_sent(7);
        assert_eq!(
            (
                counts.sent(0),
                counts.sent(1),
                counts.refused(0),
                counts.refused(1)
            ),
            (0, 2, 1, 0)
        );
        assert_eq!((counts.sent(7), counts.refused(7)), (0, 0));
    }

    #[test]
    fn the_watch_says_a_change_once_with_the_counts_of_everything_since() {
        let counts = PublishCounts::<1>::new();
        let mut watch = PublishWatch::<1>::new();
        let mut said = Vec::new();
        watch.poll(&counts, |at, sent, refused| said.push((at, sent, refused)));
        assert!(said.is_empty(), "nothing happened");
        counts.record_sent(0);
        counts.record_sent(0);
        counts.record_refused(0);
        watch.poll(&counts, |at, sent, refused| said.push((at, sent, refused)));
        watch.poll(&counts, |at, sent, refused| said.push((at, sent, refused)));
        assert_eq!(said, [(0, 2, 1)], "one report for three events, said once");
    }

    #[test]
    fn a_publication_is_as_periodic_as_its_period() {
        assert_eq!(
            Periodic::period_ms(&Publication {
                key: "k",
                period_ms: 250,
                body: ""
            }),
            250
        );
    }
}

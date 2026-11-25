// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! When the session's bookkeeping is owed: the sweeps of its Router's chains and of its gets, the
//! move of its links and the read of its matching listeners (`CoopEngine::service`).
//! Each of those has a deadline or a count of changes of its own; the ledger keeps the earliest
//! deadline and the counts as the last service left them, so a step that finds neither passed nor
//! moved runs none of it, at the cost of one comparison of each.

/// The counts of the changes the bookkeeping follows, kept where the changes are made: the moves
/// of the faces' table and the writes of the faces' declaration tables.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Seen {
    pub(super) moves: u32,
    pub(super) written: u64,
}

/// The bookkeeping's due time and what it last saw.
pub(super) struct Ledger {
    /// The earliest instant, in microseconds of the session's clock, at which something of the
    /// bookkeeping falls due by time; `u64::MAX` when nothing does.
    next_due_us: u64,
    /// The counts as the last service left them.
    seen: Seen,
    /// Owed whatever the time and the counts: something that no deadline or count says came,
    /// or the last service left something that moves on by what each step reads.
    owed: bool,
}

impl Ledger {
    /// A ledger owed at once: nothing was serviced yet.
    pub(super) const fn new() -> Self {
        Self {
            next_due_us: u64::MAX,
            seen: Seen {
                moves: 0,
                written: 0,
            },
            owed: true,
        }
    }

    /// Whether the bookkeeping is owed at `now_us`, the counts standing at `seen`.
    #[inline]
    pub(super) fn owes(&self, now_us: u64, seen: Seen) -> bool {
        self.owed || now_us >= self.next_due_us || seen != self.seen
    }

    /// The bookkeeping is owed at the next step, whatever the time and the counts.
    #[inline]
    pub(super) fn owe(&mut self) {
        self.owed = true;
    }

    /// A service ran, leaving the bookkeeping due at `next_due_us` and the counts at `seen`.
    pub(super) fn settle(&mut self, next_due_us: u64, seen: Seen) {
        self.next_due_us = next_due_us;
        self.seen = seen;
        self.owed = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEEN: Seen = Seen {
        moves: 3,
        written: 7,
    };

    /// A ledger nothing serviced is owed, at any time. Turned red by a new ledger that waits for
    /// a deadline or a change before the first service.
    #[test]
    fn a_new_ledger_is_owed() {
        let ledger = Ledger::new();
        assert!(ledger.owes(0, SEEN));
        assert!(ledger.owes(
            0,
            Seen {
                moves: 0,
                written: 0
            }
        ));
    }

    /// A settled ledger owes nothing before its due time and owes it from then on. Turned red by
    /// a comparison that is late by one instant or early.
    #[test]
    fn a_settled_ledger_is_owed_from_its_due_time() {
        let mut ledger = Ledger::new();
        ledger.settle(1_000, SEEN);
        assert!(!ledger.owes(0, SEEN), "owed before anything was due");
        assert!(
            !ledger.owes(999, SEEN),
            "owed one instant before the due time"
        );
        assert!(ledger.owes(1_000, SEEN), "not owed at the due time");
        assert!(ledger.owes(5_000, SEEN), "not owed past the due time");
    }

    /// A ledger settled with nothing due owes nothing at any time while the counts stand.
    #[test]
    fn a_ledger_with_nothing_due_waits_for_a_change() {
        let mut ledger = Ledger::new();
        ledger.settle(u64::MAX, SEEN);
        assert!(!ledger.owes(u64::MAX - 1, SEEN));
    }

    /// A move of the faces' table or a write of their tables since the service owes it, before
    /// any due time. Turned red by a ledger that reads only its deadline.
    #[test]
    fn a_change_counted_elsewhere_owes_the_bookkeeping() {
        let mut ledger = Ledger::new();
        ledger.settle(u64::MAX, SEEN);
        let moved = Seen {
            moves: SEEN.moves + 1,
            ..SEEN
        };
        let written = Seen {
            written: SEEN.written + 1,
            ..SEEN
        };
        assert!(
            ledger.owes(0, moved),
            "a move of the faces' table was missed"
        );
        assert!(
            ledger.owes(0, written),
            "a write of the faces' tables was missed"
        );
    }

    /// A ledger told it is owed stays owed until the next service settles it. Turned red by an
    /// owing that a reading of the ledger spends, or that a settling leaves standing.
    #[test]
    fn an_owed_ledger_stays_owed_until_it_is_settled() {
        let mut ledger = Ledger::new();
        ledger.settle(u64::MAX, SEEN);
        ledger.owe();
        assert!(ledger.owes(0, SEEN));
        assert!(
            ledger.owes(0, SEEN),
            "reading the ledger spent what it owed"
        );
        ledger.settle(u64::MAX, SEEN);
        assert!(!ledger.owes(0, SEEN), "a settled ledger is still owed");
    }
}

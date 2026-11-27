// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! When the session's bookkeeping is owed: the sweeps of its Router's chains and of its gets, the
//! move of its links and the read of its matching listeners (`CoopEngine::service`).
//! Each of those has a deadline or a count of changes of its own; the ledger keeps the earliest
//! deadline and the counts as the last service left them, so a step that finds neither passed nor
//! moved runs none of it, at the cost of one comparison of each.
//!
//! The gets' deadlines are the index the registry keeps (`Registry::dues`), which a read's wait
//! reads; the ledger is only due by them: each leg held lowers its due time
//! (`Ledger::owe_leg_due`), and each service settles it from the index.

/// The counts of the changes the bookkeeping follows, kept where the changes are made: the moves
/// of the faces' table and the writes of the faces' declaration tables.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Seen {
    pub(super) moves: u32,
    pub(super) written: u64,
}

/// What a service leaves the bookkeeping due by ([`Ledger::settle`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Due {
    /// When the links are next due, in microseconds of the session's clock; `u64::MAX` when never.
    pub(super) links_us: u64,
    /// The earliest deadline of a pending get, in milliseconds of the session's clock, as the
    /// index of the gets' deadlines answers it; `u64::MAX` when none has one.
    #[cfg(feature = "query")]
    pub(super) gets_ms: u64,
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

    /// A leg of a get was held, with its deadline at `deadline_ms` when it has one: the
    /// bookkeeping that sweeps the get falls due by then, never later than it was.
    #[cfg(feature = "query")]
    #[inline]
    pub(super) fn owe_leg_due(&mut self, deadline_ms: Option<u64>) {
        if let Some(due_ms) = deadline_ms {
            self.next_due_us = self.next_due_us.min(due_ms.saturating_mul(1000));
        }
    }

    /// The earliest instant, in microseconds of the session's clock, at which something of the
    /// bookkeeping falls due by time: what a quiet read of a face ends by (`direct`).
    #[cfg(all(
        not(wz_round),
        feature = "threads",
        any(feature = "listen", feature = "group")
    ))]
    #[inline]
    pub(super) fn next_due_us(&self) -> u64 {
        self.next_due_us
    }

    /// A service ran, leaving the bookkeeping due by `due` and the counts at `seen`.
    pub(super) fn settle(&mut self, due: Due, seen: Seen) {
        #[cfg(feature = "query")]
        {
            self.next_due_us = due.links_us.min(due.gets_ms.saturating_mul(1000));
        }
        #[cfg(not(feature = "query"))]
        {
            self.next_due_us = due.links_us;
        }
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

    /// Due by the links at `links_us` alone, with no get pending.
    fn links(links_us: u64) -> Due {
        Due {
            links_us,
            #[cfg(feature = "query")]
            gets_ms: u64::MAX,
        }
    }

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
        ledger.settle(links(1_000), SEEN);
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
        ledger.settle(links(u64::MAX), SEEN);
        assert!(!ledger.owes(u64::MAX - 1, SEEN));
    }

    /// A move of the faces' table or a write of their tables since the service owes it, before
    /// any due time. Turned red by a ledger that reads only its deadline.
    #[test]
    fn a_change_counted_elsewhere_owes_the_bookkeeping() {
        let mut ledger = Ledger::new();
        ledger.settle(links(u64::MAX), SEEN);
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
        ledger.settle(links(u64::MAX), SEEN);
        ledger.owe();
        assert!(ledger.owes(0, SEEN));
        assert!(
            ledger.owes(0, SEEN),
            "reading the ledger spent what it owed"
        );
        ledger.settle(links(u64::MAX), SEEN);
        assert!(!ledger.owes(0, SEEN), "a settled ledger is still owed");
    }

    /// A leg held with a deadline makes the bookkeeping due by it at once, before any service; a
    /// later deadline or a leg with none moves it not. Turned red by a leg that leaves the ledger
    /// as the last service settled it, or by a lowering that raises what an earlier leg lowered.
    #[cfg(feature = "query")]
    #[test]
    fn a_held_leg_lowers_the_due_time_and_never_raises_it() {
        let mut ledger = Ledger::new();
        ledger.settle(links(u64::MAX), SEEN);
        assert!(!ledger.owes(u64::MAX - 1, SEEN), "CONTROL: nothing is due");
        ledger.owe_leg_due(Some(5));
        assert!(!ledger.owes(4_999, SEEN), "owed before the leg's deadline");
        assert!(ledger.owes(5_000, SEEN), "not owed at the leg's deadline");
        ledger.owe_leg_due(Some(9));
        assert!(ledger.owes(5_000, SEEN), "a later deadline raised it");
        ledger.owe_leg_due(None);
        assert!(ledger.owes(5_000, SEEN), "a leg with no deadline raised it");
        assert!(!ledger.owes(4_999, SEEN));
    }

    /// A service settles the due time to what the index of the gets' deadlines holds, so a get
    /// that ended before its deadline makes nothing due after it; the bookkeeping is due at the
    /// earlier of the links' time and that deadline. Turned red by a settling that keeps the
    /// lowered deadline, or that reads the links' time alone.
    #[cfg(feature = "query")]
    #[test]
    fn a_service_settles_the_due_time_from_the_gets() {
        let mut ledger = Ledger::new();
        ledger.owe_leg_due(Some(5));
        ledger.settle(
            Due {
                links_us: u64::MAX,
                gets_ms: 40,
            },
            SEEN,
        );
        assert!(!ledger.owes(39_999, SEEN), "the ended get still bounds it");
        assert!(ledger.owes(40_000, SEEN), "the get left is not due");
        ledger.settle(
            Due {
                links_us: 2_000,
                gets_ms: 40,
            },
            SEEN,
        );
        assert!(
            ledger.owes(2_000, SEEN),
            "the links' earlier time was missed"
        );
        ledger.settle(links(u64::MAX), SEEN);
        assert!(!ledger.owes(u64::MAX - 1, SEEN), "no get is left");
    }
}

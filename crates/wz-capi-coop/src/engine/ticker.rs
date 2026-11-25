// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The periodic jobs of a session: what [`wz_capi_port::SessionEngine::start_ticker`] hands the
//! cooperative engine.
//!
//! The engine has no task to run them in. A job is due when the session is stepped after its
//! time, and the wait a step makes is cut short to its time ([`Tickers::next_due_ms`]), as it is
//! for a get's deadline and a replay's next turn. A job runs OUTSIDE the session's lock, because
//! what it does (publish a beacon, say) takes that lock: [`Tickers::take_due`] hands the due ones
//! out under it one at a time, and [`Tickers::rearm`] puts each back after its run.

use wz_capi_port::{Tick, TickerId};
use wz_session_core::bounded::{BoundedVec, Static};
use wz_session_core::caps::MAX_TICKERS;

#[allow(unused_imports)]
use crate::prelude::*;

/// One periodic job.
struct Entry {
    id: TickerId,
    period_ms: u64,
    /// When it is next due; [`u64::MAX`] while it runs, so it is never run alongside itself.
    due_ms: u64,
    tick: Tick,
}

/// The session's periodic jobs, in a table of the build's rows (`MAX_TICKERS`) that lies in the
/// session itself: no start takes memory.
pub(super) struct Tickers {
    entries: BoundedVec<Entry, MAX_TICKERS, Static>,
    /// The jobs the table holds at once, at most the build's.
    rows: usize,
}

impl Tickers {
    /// A table that holds `rows` jobs, at most the build's: no start takes memory.
    pub(super) fn reserved(rows: usize) -> Self {
        Self {
            entries: BoundedVec::new_static(),
            rows: rows.min(MAX_TICKERS),
        }
    }

    /// Hold a job `id`, first due `period_ms` after `now_ms`. A period under a millisecond is
    /// raised to one. `false`, holding nothing, when every row of the table holds a job: a start
    /// past them is refused, as an engine with no periodic jobs refuses one.
    #[must_use]
    pub(super) fn start(&mut self, id: TickerId, period_ms: u64, tick: Tick, now_ms: u64) -> bool {
        if self.entries.len() >= self.rows {
            return false;
        }
        let period_ms = period_ms.max(1);
        self.entries
            .push(Entry {
                id,
                period_ms,
                due_ms: now_ms.saturating_add(period_ms),
                tick,
            })
            .is_ok()
    }

    /// Let go of job `id`; one that is not held (ended, or never started) is left alone.
    pub(super) fn stop(&mut self, id: TickerId) {
        self.entries.retain(|entry| entry.id != id);
    }

    /// Every job, handed out for its taker to let go of where it chooses: what a job holds may
    /// take the session's lock as it goes, so a close lets go of them after letting go of the
    /// lock. The table holds none after.
    pub(super) fn take_all(&mut self) -> Self {
        Self {
            entries: core::mem::take(&mut self.entries),
            rows: 0,
        }
    }

    /// When the earliest job is next due, if any is waiting. A job that is running has no time.
    pub(super) fn next_due_ms(&self) -> Option<u64> {
        self.entries
            .iter()
            .map(|entry| entry.due_ms)
            .filter(|due| *due != u64::MAX)
            .min()
    }

    /// The job that has been due the longest at `now_ms`, now marked as running. One at a time and
    /// not all that are due: a job that stops another must find it not yet started.
    pub(super) fn take_next_due(&mut self, now_ms: u64) -> Option<(TickerId, Tick)> {
        let entry = self
            .entries
            .iter_mut()
            .filter(|entry| entry.due_ms <= now_ms)
            .min_by_key(|entry| entry.due_ms)?;
        entry.due_ms = u64::MAX;
        Some((entry.id, entry.tick.clone()))
    }

    /// A job's run ended at `now_ms`: it is due again one period on when it `goes_on`, and gone
    /// when it does not. A job stopped while it ran is not in the table, and stays gone.
    pub(super) fn rearm(&mut self, id: TickerId, goes_on: bool, now_ms: u64) {
        if !goes_on {
            self.stop(id);
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.id == id) {
            entry.due_ms = now_ms.saturating_add(entry.period_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A job that goes on.
    fn job() -> Tick {
        alloc::sync::Arc::new(|| true)
    }

    /// Every job is handed out at once and the table holds none after; what a job holds goes
    /// with the jobs handed out, when their taker lets go of them. Turned red by a close that
    /// leaves a job, and what it holds, in the table of a session that runs none again.
    #[test]
    fn every_job_is_handed_out_and_goes_with_its_taker() {
        let mut tickers = Tickers::reserved(2);
        let held = alloc::sync::Arc::new(());
        let kept = alloc::sync::Arc::clone(&held);
        assert!(tickers.start(
            1,
            10,
            alloc::sync::Arc::new(move || {
                let _ = &kept;
                true
            }),
            0
        ));
        assert!(tickers.start(2, 20, job(), 0));
        let taken = tickers.take_all();
        assert_eq!(tickers.next_due_ms(), None, "the table holds no job");
        assert_eq!(
            alloc::sync::Arc::strong_count(&held),
            2,
            "a job handed out still holds what it holds"
        );
        drop(taken);
        assert_eq!(
            alloc::sync::Arc::strong_count(&held),
            1,
            "letting the jobs go lets it go"
        );
    }

    /// A start past the rows is refused and holds nothing; a row let go of takes a job again.
    #[test]
    fn a_start_past_the_tables_rows_is_refused_and_a_row_let_go_is_taken_again() {
        let mut tickers = Tickers::reserved(2);
        assert!(tickers.start(1, 10, job(), 0));
        assert!(tickers.start(2, 20, job(), 0));
        assert!(!tickers.start(3, 5, job(), 0), "both rows hold a job");
        assert_eq!(
            tickers.next_due_ms(),
            Some(10),
            "the refused job holds no row"
        );
        tickers.stop(1);
        assert!(
            tickers.start(3, 5, job(), 0),
            "the row let go of is taken again"
        );
        assert_eq!(tickers.next_due_ms(), Some(5));
    }

    /// A table asked for more rows than the build holds takes the build's and refuses the start
    /// past them, holding nothing for it. Turned red by a start the full table could not hold that
    /// still answers `true`.
    #[test]
    fn a_start_past_the_builds_rows_is_refused() {
        let mut tickers = Tickers::reserved(MAX_TICKERS + 1);
        for id in 0..MAX_TICKERS as u64 {
            assert!(tickers.start(id, 10, job(), 0));
        }
        assert!(!tickers.start(MAX_TICKERS as u64, 5, job(), 0));
        assert_eq!(
            tickers.next_due_ms(),
            Some(10),
            "the refused job holds no row"
        );
    }

    /// A table of no rows refuses every start.
    #[test]
    fn a_table_of_no_rows_refuses_every_start() {
        let mut tickers = Tickers::reserved(0);
        assert!(!tickers.start(1, 10, job(), 0));
        assert_eq!(tickers.next_due_ms(), None);
    }
}

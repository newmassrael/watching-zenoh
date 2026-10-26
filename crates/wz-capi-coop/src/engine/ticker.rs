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

/// The session's periodic jobs.
#[derive(Default)]
pub(super) struct Tickers {
    entries: Vec<Entry>,
}

impl Tickers {
    /// Hold a job `id`, first due `period_ms` after `now_ms`. A period under a millisecond is
    /// raised to one.
    pub(super) fn start(&mut self, id: TickerId, period_ms: u64, tick: Tick, now_ms: u64) {
        let period_ms = period_ms.max(1);
        self.entries.push(Entry {
            id,
            period_ms,
            due_ms: now_ms.saturating_add(period_ms),
            tick,
        });
    }

    /// Let go of job `id`; one that is not held (ended, or never started) is left alone.
    pub(super) fn stop(&mut self, id: TickerId) {
        self.entries.retain(|entry| entry.id != id);
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

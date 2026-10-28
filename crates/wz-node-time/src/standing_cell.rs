// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The standing of a clock where several threads read it and the host reports it
//! (`docs/observation-plane.md` M1).
//!
//! [`ClockStanding`] is the machine and is moved through `&mut`. This is the cell a node shares it
//! through: the machine under a lock the host's reports take, and beside it one atomic that says
//! whether the clock is trusted, so the stamping path reads a single load and never the lock.

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use wz_session_core::clock_quality::ClockQualityState;
use wz_session_core::clock_standing::ClockStanding;

/// A clock's standing, shared.
pub struct StandingCell {
    standing: Mutex<ClockStanding>,
    /// `standing.is_trusted()` as of the last report.
    trusted: AtomicBool,
}

impl Default for StandingCell {
    fn default() -> Self {
        Self::new()
    }
}

impl StandingCell {
    /// A clock no reference has been reported for.
    pub fn new() -> Self {
        Self {
            standing: Mutex::new(ClockStanding::new()),
            trusted: AtomicBool::new(false),
        }
    }

    /// The host reports that the clock follows a reference. Whether the standing changed.
    pub fn report_sync_acquired(&self) -> bool {
        self.report(ClockStanding::sync_acquired)
    }

    /// The host reports that the reference is gone. Whether the standing changed.
    pub fn report_sync_lost(&self) -> bool {
        self.report(ClockStanding::sync_lost)
    }

    /// The host reports that its bound on running without a reference has passed.
    #[cfg(feature = "clock-source")]
    pub fn report_holdover_expired(&self) -> bool {
        self.report(ClockStanding::holdover_expired)
    }

    fn report(&self, event: impl FnOnce(&mut ClockStanding) -> bool) -> bool {
        let mut standing = self.standing.lock().unwrap_or_else(PoisonError::into_inner);
        let changed = event(&mut standing);
        self.trusted.store(standing.is_trusted(), Ordering::Release);
        changed
    }

    /// The standing now.
    pub fn state(&self) -> ClockQualityState {
        self.standing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .state()
    }

    /// Whether the clock is trusted, as of the last report.
    pub fn is_trusted(&self) -> bool {
        self.trusted.load(Ordering::Acquire)
    }

    /// How many times the standing has changed.
    pub fn changes(&self) -> u32 {
        self.standing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .changes()
    }
}

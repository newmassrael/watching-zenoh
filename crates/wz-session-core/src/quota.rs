// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A bound on how many of one kind of resource a session holds live at once.
//!
//! # What it is
//!
//! A counting semaphore whose acquire never waits: the holder either takes a place or is told
//! the bound is reached. A resource that is acquired and later released (a query in flight is
//! one: it is asked, pending, and ended) is bounded by a quota; a table of rows that never move
//! is bounded by its capacity (`caps`). The two are different facts and are kept apart: a
//! capacity sizes memory the image carries, a quota refuses the holder that asks for one more.
//!
//! # Why a plain state machine
//!
//! This type does no synchronisation, on purpose. A session core is a set of sequential state
//! machines, and each runtime composes them with its own exclusion: a runtime that shares the
//! quota across threads holds it in its `Mutex` (`SessionRuntime::Mutex`), and one that runs a
//! single task holds it as it is. Putting an atomic here would fix one answer for both, and
//! would not even compile-link on a target without compare-and-swap. The rule (what is refused,
//! and when a place comes back) lives here once, and every engine that creates the resource
//! asks it.
//!
//! # The bound
//!
//! The bound is the value of a limit, a [`crate::limit_binding::Quota`], so a quota here means
//! what a limit's quota means everywhere: [`crate::limit_binding::Quota::UNBOUNDED`] is no bound
//! and a number is the most it admits, `0` admitting nothing. No bound is upstream's behaviour,
//! which has no such bound, so it is the default of every quota-limited resource. An interface
//! that writes no bound as `0` (a field of a C struct) converts the number at that interface,
//! once, and never hands the `0` on.

use crate::limit_binding;

/// The bound is reached: the holder asked for one more place than the quota allows. Only a quota
/// with a number refuses, so the bound reached is always that number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaExceeded {
    /// The bound that was reached.
    pub limit: usize,
}

/// A bound on live holders, and how many there are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    limit: limit_binding::Quota,
    live: usize,
}

impl Quota {
    /// A quota of `limit` live holders.
    pub const fn new(limit: limit_binding::Quota) -> Self {
        Self { limit, live: 0 }
    }

    /// No bound: every acquire is granted.
    pub const fn unlimited() -> Self {
        Self::new(limit_binding::Quota::UNBOUNDED)
    }

    /// The bound.
    pub const fn limit(&self) -> limit_binding::Quota {
        self.limit
    }

    /// How many places are taken now.
    pub const fn live(&self) -> usize {
        self.live
    }

    /// Change the bound. Places already taken stay taken: a bound lowered under the live count
    /// refuses every acquire until enough places are released, and takes none back from the
    /// holders.
    pub fn set_limit(&mut self, limit: limit_binding::Quota) {
        self.limit = limit;
    }

    /// Take one place, or say the bound is reached. A refusal changes nothing.
    pub fn try_acquire(&mut self) -> Result<(), QuotaExceeded> {
        match self.limit.most() {
            Some(most) if !self.limit.admits(self.live.saturating_add(1)) => {
                Err(QuotaExceeded { limit: most })
            }
            _ => {
                self.live += 1;
                Ok(())
            }
        }
    }

    /// Give one place back. Giving back a place that was never taken is a defect of the
    /// caller, so it stops a debug build; a release build leaves the count at zero rather
    /// than wrapping it, so one defect cannot become a quota that grants everything.
    pub fn release(&mut self) {
        debug_assert!(
            self.live > 0,
            "a quota place was released that was never taken"
        );
        self.live = self.live.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at_most(most: usize) -> Quota {
        Quota::new(limit_binding::Quota::at_most(most))
    }

    #[test]
    fn a_quota_grants_up_to_its_limit_and_refuses_the_next() {
        let mut quota = at_most(3);
        for taken in 1..=3 {
            assert_eq!(quota.try_acquire(), Ok(()));
            assert_eq!(quota.live(), taken);
        }
        assert_eq!(quota.try_acquire(), Err(QuotaExceeded { limit: 3 }));
        assert_eq!(quota.live(), 3, "a refusal takes no place");
    }

    #[test]
    fn a_released_place_can_be_taken_again() {
        let mut quota = at_most(1);
        assert_eq!(quota.try_acquire(), Ok(()));
        assert!(quota.try_acquire().is_err());
        quota.release();
        assert_eq!(quota.live(), 0);
        assert_eq!(quota.try_acquire(), Ok(()));
    }

    #[test]
    fn a_bound_lowered_under_the_live_count_takes_no_place_back() {
        let mut quota = at_most(3);
        for _ in 0..3 {
            assert_eq!(quota.try_acquire(), Ok(()));
        }
        quota.set_limit(limit_binding::Quota::at_most(1));
        assert_eq!(quota.live(), 3, "the holders keep their places");
        assert_eq!(quota.try_acquire(), Err(QuotaExceeded { limit: 1 }));
        quota.release();
        quota.release();
        assert_eq!(
            quota.try_acquire(),
            Err(QuotaExceeded { limit: 1 }),
            "1 live of 1"
        );
        quota.release();
        assert_eq!(quota.try_acquire(), Ok(()));
    }

    #[test]
    fn an_unbounded_quota_grants_every_acquire() {
        let mut quota = Quota::unlimited();
        assert_eq!(quota, Quota::new(limit_binding::Quota::UNBOUNDED));
        for _ in 0..10_000 {
            assert_eq!(quota.try_acquire(), Ok(()));
        }
        assert_eq!(quota.live(), 10_000);
        assert_eq!(quota.limit(), limit_binding::Quota::UNBOUNDED);
    }

    #[test]
    fn a_quota_of_zero_admits_nothing() {
        let mut quota = at_most(0);
        assert_eq!(quota.try_acquire(), Err(QuotaExceeded { limit: 0 }));
        assert_eq!(quota.live(), 0, "a refusal takes no place");
    }

    #[test]
    fn a_bound_raised_to_none_grants_what_the_number_refused() {
        let mut quota = at_most(1);
        assert_eq!(quota.try_acquire(), Ok(()));
        assert!(quota.try_acquire().is_err());
        quota.set_limit(limit_binding::Quota::UNBOUNDED);
        assert_eq!(quota.try_acquire(), Ok(()));
        assert_eq!(quota.live(), 2);
    }

    #[test]
    fn the_places_of_one_quota_are_not_another_quotas() {
        let mut first = at_most(1);
        let mut second = at_most(1);
        assert_eq!(first.try_acquire(), Ok(()));
        assert_eq!(second.try_acquire(), Ok(()));
    }

    #[test]
    #[should_panic(expected = "released that was never taken")]
    #[cfg(debug_assertions)]
    fn releasing_a_place_that_was_never_taken_stops_a_debug_build() {
        at_most(2).release();
    }
}

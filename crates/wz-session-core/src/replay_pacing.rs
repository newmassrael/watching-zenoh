// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pace of a paced declaration replay (`declaration-sync-pacing`): how many declarations a
//! turn sends and how long to wait between turns, and the pace a session's snapshot states.
//!
//! The pace is a value and not a clock: it holds two numbers, reads no time and does no I/O, so
//! every host that replays in turns (the heap runtime's supervisor, the slot node) holds the same
//! type and keeps its own time. It sits beside [`crate::replay_cursor::ReplayCursor`], which says
//! which entries a turn sends, and this says how many and how often.

/// A pace of `burst` declarations a turn and `interval_ms` between turns. A host holds it as an
/// `Option`, so a test, or a caller that wants pacing on whatever its snapshot says, can state it,
/// and the snapshot of the session that replays states it through [`Self::of_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayPacing {
    burst: usize,
    interval_ms: u64,
    retry_interval_ms: u64,
    no_progress_ms: u64,
}

/// What a paced replay does after the link refused a turn it had room to try again
/// ([`ReplayPacing::after_refusal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalStep {
    /// Try the refused turn again this many milliseconds from now, from the declaration the link
    /// refused.
    RetryIn(u64),
    /// Give the replay up: the refusal ends the replay and, with it, the link, and a reconnecting
    /// session begins the replay again on the next one.
    EndsLink,
}

impl ReplayPacing {
    /// A pace of `burst` declarations a turn and `interval_ms` between turns. Both must be at least
    /// 1: a turn that sends nothing would never finish, and no wait would run the turns together.
    /// A refused turn ends the replay ([`Self::with_refusal`] states otherwise).
    pub const fn new(burst: usize, interval_ms: u64) -> Option<Self> {
        if burst == 0 || interval_ms == 0 {
            None
        } else {
            Some(Self {
                burst,
                interval_ms,
                retry_interval_ms: 0,
                no_progress_ms: 0,
            })
        }
    }

    /// This pace, with a turn the link refused for want of room tried again after
    /// `retry_interval_ms` (`DECLARATION_SYNC_RETRY_INTERVAL_MS`), its own wait and not the turn
    /// interval, and the replay given up when no declaration has gone out for `no_progress_ms`
    /// (`DECLARATION_SYNC_TX_NO_PROGRESS_MS`). A retry interval of `0` tries nothing again, as
    /// upstream's one call does not; a no-progress bound of `0` gives up only when the link does.
    pub const fn with_refusal(self, retry_interval_ms: u64, no_progress_ms: u64) -> Self {
        Self {
            retry_interval_ms,
            no_progress_ms,
            ..self
        }
    }

    /// What follows a turn the link refused for want of room, `last_progress_ms` being when the
    /// replay last sent a declaration (or began) and `now_ms` now, on one clock.
    pub const fn after_refusal(&self, last_progress_ms: u64, now_ms: u64) -> RefusalStep {
        if self.retry_interval_ms == 0 {
            return RefusalStep::EndsLink;
        }
        if self.no_progress_ms != 0
            && now_ms.saturating_sub(last_progress_ms) >= self.no_progress_ms
        {
            return RefusalStep::EndsLink;
        }
        RefusalStep::RetryIn(self.retry_interval_ms)
    }

    /// The pace `policy` states, the snapshot of the session that replays: `None`, upstream's one
    /// call, unless its `declaration-sync-pacing` policy is on, in which case the pace is the
    /// burst and interval limits. The limits are checked where they are used, at compile time,
    /// so a build that sets one to zero does not build.
    pub const fn of_policy(policy: &crate::policy::SessionPolicy) -> Option<Self> {
        const _: () = assert!(
            crate::caps::DECLARATION_SYNC_BURST_MESSAGES >= 1
                && crate::caps::DECLARATION_SYNC_INTERVAL_MS >= 1,
            "DECLARATION_SYNC_BURST_MESSAGES and DECLARATION_SYNC_INTERVAL_MS must be at least 1"
        );
        if !policy.declaration_sync_pacing() {
            return None;
        }
        // `?` and `Option::map` are not `const`, so the two steps are written out.
        let Some(pace) = Self::new(
            crate::caps::DECLARATION_SYNC_BURST_MESSAGES,
            crate::caps::DECLARATION_SYNC_INTERVAL_MS as u64,
        ) else {
            return None;
        };
        Some(pace.with_refusal(
            crate::caps::DECLARATION_SYNC_RETRY_INTERVAL_MS as u64,
            crate::caps::DECLARATION_SYNC_TX_NO_PROGRESS_MS as u64,
        ))
    }

    /// Declarations sent in one turn.
    pub const fn burst(&self) -> usize {
        self.burst
    }

    /// Milliseconds between two turns.
    pub const fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// Milliseconds before a turn the link refused is tried again; `0` tries none again.
    pub const fn retry_interval_ms(&self) -> u64 {
        self.retry_interval_ms
    }

    /// Milliseconds with no declaration out after which a retrying replay gives up; `0` never.
    pub const fn no_progress_ms(&self) -> u64 {
        self.no_progress_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pace of nothing is refused: a turn that sends nothing never finishes, and no wait would
    /// run the turns together.
    #[test]
    fn a_pace_needs_a_burst_and_a_wait_of_at_least_one() {
        assert_eq!(ReplayPacing::new(0, 10), None);
        assert_eq!(ReplayPacing::new(8, 0), None);
        let pace = ReplayPacing::new(8, 10).expect("a real pace");
        assert_eq!((pace.burst(), pace.interval_ms()), (8, 10));
    }

    /// The build defaults state the pace through the policy: off is upstream's one call, on is the
    /// two limits. The test build states nothing, so this asserts the default.
    #[test]
    fn the_build_defaults_state_a_pace_exactly_when_the_policy_is_on() {
        let defaults = crate::policy::SessionPolicy::defaults();
        let pace = ReplayPacing::of_policy(&defaults);
        assert_eq!(pace.is_some(), defaults.declaration_sync_pacing());
        if let Some(pace) = pace {
            assert_eq!(pace.burst(), crate::caps::DECLARATION_SYNC_BURST_MESSAGES);
            assert_eq!(
                pace.interval_ms(),
                crate::caps::DECLARATION_SYNC_INTERVAL_MS as u64
            );
        }
    }

    /// The snapshot a session replays under decides its pace, not the build: on is the two
    /// limits, off is upstream's one call.
    #[test]
    fn a_session_is_paced_by_the_snapshot_it_holds() {
        use crate::policy::{DeclarationSyncPacing, SessionPolicy};
        use crate::policy_binding::PolicyValue;
        if DeclarationSyncPacing::DOMAIN.is_singleton() {
            return;
        }
        let mut on = SessionPolicy::defaults();
        on.select_declaration_sync_pacing(DeclarationSyncPacing::On)
            .expect("the domain holds both values");
        let mut off = on;
        off.select_declaration_sync_pacing(DeclarationSyncPacing::Off)
            .expect("the domain holds both values");
        assert_eq!(
            ReplayPacing::of_policy(&on),
            ReplayPacing::new(
                crate::caps::DECLARATION_SYNC_BURST_MESSAGES,
                crate::caps::DECLARATION_SYNC_INTERVAL_MS as u64
            )
            .map(|pace| pace.with_refusal(
                crate::caps::DECLARATION_SYNC_RETRY_INTERVAL_MS as u64,
                crate::caps::DECLARATION_SYNC_TX_NO_PROGRESS_MS as u64
            ))
        );
        assert_eq!(ReplayPacing::of_policy(&off), None);
    }

    /// With no retry interval a refused turn ends the replay, as it always did; with one, the
    /// turn is tried again after its own wait and not the turn interval, until no declaration
    /// has gone out for the no-progress bound, and a bound of 0 never gives up.
    #[test]
    fn a_refused_turn_is_retried_at_its_own_interval_until_no_progress_ends_the_link() {
        let pace = ReplayPacing::new(8, 10).expect("a pace");
        assert_eq!(pace.after_refusal(0, 1_000_000), RefusalStep::EndsLink);

        let retrying = pace.with_refusal(3, 50);
        assert_eq!(retrying.interval_ms(), 10, "the turn interval is untouched");
        assert_eq!(retrying.after_refusal(100, 100), RefusalStep::RetryIn(3));
        assert_eq!(retrying.after_refusal(100, 149), RefusalStep::RetryIn(3));
        assert_eq!(retrying.after_refusal(100, 150), RefusalStep::EndsLink);
        assert_eq!(
            retrying.after_refusal(200, 100),
            RefusalStep::RetryIn(3),
            "a clock read before the progress stamp is no stall"
        );

        let patient = pace.with_refusal(3, 0);
        assert_eq!(patient.after_refusal(0, u64::MAX), RefusalStep::RetryIn(3));
    }
}

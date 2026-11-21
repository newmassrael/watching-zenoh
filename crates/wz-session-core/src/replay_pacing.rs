// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pace of a paced declaration replay (`declaration-sync-pacing`): how many declarations a
//! turn sends, how long to wait between turns and how a turn the link refused is answered, and the
//! pace a session's snapshot states.
//!
//! The pace is a value and not a clock: it reads no time and does no I/O, so every host that
//! replays in turns (the heap runtime's supervisor, the slot node) holds the same type and keeps
//! its own time. It sits beside [`crate::replay_cursor::ReplayCursor`], which says which entries a
//! turn sends, and this says how many and how often.
//!
//! The answer to a refused turn is two limits, `DECLARATION_SYNC_RETRY_INTERVAL_MS` and
//! `DECLARATION_SYNC_TX_NO_PROGRESS_MS`, each held as a
//! [`Limited`](crate::limit_binding::Limited) of its domain: a build that fixes them (an image with
//! no operating system keeps the build's value alone) holds no byte of either in a pace, and keeps
//! no stamp of a replay's progress ([`ProgressStamp`]) where no pace of the build can read one.

use core::cell::Cell;

use crate::limit_binding::{LimitDomain, LimitSpec, OutsideLimitDomain};
use crate::limits::{
    DeclarationSyncRetryIntervalMs, DeclarationSyncRetryIntervalMsHeld,
    DeclarationSyncTxNoProgressMs, DeclarationSyncTxNoProgressMsHeld, SessionLimits,
};
use crate::policy::SessionPolicy;

/// A pace of `burst` declarations a turn and `interval_ms` between turns, and the answer to a turn
/// the link refused. A host holds it as an `Option`, so a test, or a caller that wants pacing on
/// whatever its snapshot says, can state it, and the snapshots of the session that replays state
/// it through [`Self::of_snapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayPacing {
    burst: usize,
    interval_ms: u64,
    /// `DECLARATION_SYNC_RETRY_INTERVAL_MS` of this pace: no byte where the build's domain of the
    /// limit is one value, which is then the value read.
    retry_interval_ms: DeclarationSyncRetryIntervalMsHeld,
    /// `DECLARATION_SYNC_TX_NO_PROGRESS_MS` of this pace, held as the retry interval is.
    no_progress_ms: DeclarationSyncTxNoProgressMsHeld,
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
    /// A refused turn is answered as the build's two limits state
    /// (`DECLARATION_SYNC_RETRY_INTERVAL_MS`, `DECLARATION_SYNC_TX_NO_PROGRESS_MS`): at their
    /// default of 0 it ends the replay, as upstream's one call does, and [`Self::with_refusal`]
    /// states other values inside their domains.
    pub const fn new(burst: usize, interval_ms: u64) -> Option<Self> {
        if burst == 0 || interval_ms == 0 {
            None
        } else {
            Some(Self {
                burst,
                interval_ms,
                retry_interval_ms: DeclarationSyncRetryIntervalMsHeld::build_default(),
                no_progress_ms: DeclarationSyncTxNoProgressMsHeld::build_default(),
            })
        }
    }

    /// This pace, with a turn the link refused for want of room tried again after
    /// `retry_interval_ms` (`DECLARATION_SYNC_RETRY_INTERVAL_MS`), its own wait and not the turn
    /// interval, and the replay given up when no declaration has gone out for `no_progress_ms`
    /// (`DECLARATION_SYNC_TX_NO_PROGRESS_MS`). A retry interval of `0` tries nothing again, as
    /// upstream's one call does not; a no-progress bound of `0` gives up only when the link does.
    ///
    /// Each value must lie in the domain the build allows its limit, the way a document's value
    /// must: a build that fixes a limit (an image keeps the build's value alone) holds no other
    /// value of it, so any other is refused and no pace is made.
    pub fn with_refusal(
        self,
        retry_interval_ms: usize,
        no_progress_ms: usize,
    ) -> Result<Self, OutsideLimitDomain> {
        Ok(Self {
            retry_interval_ms: DeclarationSyncRetryIntervalMsHeld::select(retry_interval_ms)?,
            no_progress_ms: DeclarationSyncTxNoProgressMsHeld::select(no_progress_ms)?,
            ..self
        })
    }

    /// What follows a turn the link refused for want of room, `last_progress_ms` being when the
    /// replay last sent a declaration (or began) and `now_ms` now, on one clock.
    pub const fn after_refusal(&self, last_progress_ms: u64, now_ms: u64) -> RefusalStep {
        let retry_ms = self.retry_interval_ms();
        if retry_ms == 0 {
            return RefusalStep::EndsLink;
        }
        let bound_ms = self.no_progress_ms();
        if bound_ms != 0 && now_ms.saturating_sub(last_progress_ms) >= bound_ms {
            return RefusalStep::EndsLink;
        }
        RefusalStep::RetryIn(retry_ms)
    }

    /// The pace the two snapshots of the session that replays state: `None`, upstream's one
    /// call, unless the `declaration-sync-pacing` policy of `policy` is on, in which case the
    /// pace is the burst and the interval `limits` holds, and its answer to a refused turn the
    /// two retry limits `limits` holds. The declaration's ranges hold the burst and the interval
    /// to at least 1, so every snapshot's values make a pace ([`Self::new`]).
    pub const fn of_snapshot(policy: &SessionPolicy, limits: &SessionLimits) -> Option<Self> {
        if !policy.declaration_sync_pacing() {
            return None;
        }
        match Self::new(
            limits.declaration_sync_burst_messages(),
            limits.declaration_sync_interval_ms() as u64,
        ) {
            Some(pace) => Some(Self {
                retry_interval_ms: limits.declaration_sync_retry_interval_ms_held(),
                no_progress_ms: limits.declaration_sync_tx_no_progress_ms_held(),
                ..pace
            }),
            None => None,
        }
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
        self.retry_interval_ms.get() as u64
    }

    /// Milliseconds with no declaration out after which a retrying replay gives up; `0` never.
    pub const fn no_progress_ms(&self) -> u64 {
        self.no_progress_ms.get() as u64
    }
}

/// Whether a parameter the build allows `domain` of, `value` being the build's own, can be other
/// than 0: the domain holds more than one value, or its one value is not 0.
const fn may_be_nonzero(domain: LimitDomain, value: usize) -> bool {
    !(domain.is_singleton() && value == 0)
}

/// How many stamps of a replay's progress a host keeps for each session ([`ProgressStamp`]): one
/// where a pace of this build can read it, that is where the build's domains let a refused turn be
/// retried and the retries be bounded (`DECLARATION_SYNC_RETRY_INTERVAL_MS` and
/// `DECLARATION_SYNC_TX_NO_PROGRESS_MS` may each be other than 0), and none where either is fixed
/// at 0, since [`ReplayPacing::after_refusal`] then never reads the stamp.
pub const PROGRESS_STAMPS: usize = if may_be_nonzero(
    DeclarationSyncRetryIntervalMs::DOMAIN,
    DeclarationSyncRetryIntervalMs::DEFAULT,
) && may_be_nonzero(
    DeclarationSyncTxNoProgressMs::DOMAIN,
    DeclarationSyncTxNoProgressMs::DEFAULT,
) {
    1
} else {
    0
};

/// When a replay last told its peer a declaration, or began, in the host's milliseconds: what the
/// no-progress bound of a pace counts from ([`ReplayPacing::after_refusal`]). Kept in
/// [`PROGRESS_STAMPS`] cells, so a build whose paces never read it holds no byte of it in the
/// sessions of its node.
#[derive(Debug)]
pub struct ProgressStamp {
    at_ms: [Cell<u64>; PROGRESS_STAMPS],
}

impl ProgressStamp {
    /// A stamp that reads `0`, as a replay that has not begun.
    pub const fn new() -> Self {
        Self {
            at_ms: [const { Cell::new(0u64) }; PROGRESS_STAMPS],
        }
    }

    /// The replay told the peer a declaration, or began, at `now_ms`.
    pub fn note(&self, now_ms: u64) {
        if let Some(at_ms) = self.at_ms.first() {
            at_ms.set(now_ms);
        }
    }

    /// When the replay last told the peer a declaration, or began: `0` in a build that keeps no
    /// stamp, whose paces read none.
    pub fn get(&self) -> u64 {
        self.at_ms.first().map_or(0, Cell::get)
    }
}

impl Default for ProgressStamp {
    fn default() -> Self {
        Self::new()
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

    /// A pace a caller states answers a refused turn as the build's two retry limits say, the
    /// values every pace of the build holds unless it states others.
    #[test]
    fn a_stated_pace_answers_a_refusal_by_the_builds_retry_limits() {
        let pace = ReplayPacing::new(8, 10).expect("a real pace");
        assert_eq!(
            pace.retry_interval_ms(),
            crate::caps::DECLARATION_SYNC_RETRY_INTERVAL_MS as u64
        );
        assert_eq!(
            pace.no_progress_ms(),
            crate::caps::DECLARATION_SYNC_TX_NO_PROGRESS_MS as u64
        );
    }

    /// The build defaults state the pace through the policy: off is upstream's one call, on is the
    /// limits. The test build states nothing, so this asserts the default.
    #[test]
    fn the_build_defaults_state_a_pace_exactly_when_the_policy_is_on() {
        let defaults = crate::policy::SessionPolicy::defaults();
        let pace = ReplayPacing::of_snapshot(&defaults, &SessionLimits::defaults());
        assert_eq!(pace.is_some(), defaults.declaration_sync_pacing());
        if let Some(pace) = pace {
            assert_eq!(pace.burst(), crate::caps::DECLARATION_SYNC_BURST_MESSAGES);
            assert_eq!(
                pace.interval_ms(),
                crate::caps::DECLARATION_SYNC_INTERVAL_MS as u64
            );
            assert_eq!(
                pace.retry_interval_ms(),
                crate::caps::DECLARATION_SYNC_RETRY_INTERVAL_MS as u64
            );
            assert_eq!(
                pace.no_progress_ms(),
                crate::caps::DECLARATION_SYNC_TX_NO_PROGRESS_MS as u64
            );
        }
    }

    /// The snapshot a session replays under decides its pace, not the build: on is the limits,
    /// off is upstream's one call.
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
        let limits = SessionLimits::defaults();
        assert_eq!(
            ReplayPacing::of_snapshot(&on, &limits),
            ReplayPacing::new(
                crate::caps::DECLARATION_SYNC_BURST_MESSAGES,
                crate::caps::DECLARATION_SYNC_INTERVAL_MS as u64
            )
        );
        assert_eq!(ReplayPacing::of_snapshot(&off, &limits), None);
    }

    /// With no retry interval a refused turn ends the replay, as it always did; with one, the
    /// turn is tried again after its own wait and not the turn interval, until no declaration
    /// has gone out for the no-progress bound, and a bound of 0 never gives up.
    #[test]
    fn a_refused_turn_is_retried_at_its_own_interval_until_no_progress_ends_the_link() {
        let pace = ReplayPacing::new(8, 10)
            .expect("a pace")
            .with_refusal(0, 0)
            .expect("a host's domains hold 0");
        assert_eq!(pace.after_refusal(0, 1_000_000), RefusalStep::EndsLink);

        let retrying = pace
            .with_refusal(3, 50)
            .expect("a host's domains hold a retry");
        assert_eq!(retrying.interval_ms(), 10, "the turn interval is untouched");
        assert_eq!(retrying.after_refusal(100, 100), RefusalStep::RetryIn(3));
        assert_eq!(retrying.after_refusal(100, 149), RefusalStep::RetryIn(3));
        assert_eq!(retrying.after_refusal(100, 150), RefusalStep::EndsLink);
        assert_eq!(
            retrying.after_refusal(200, 100),
            RefusalStep::RetryIn(3),
            "a clock read before the progress stamp is no stall"
        );

        let patient = pace
            .with_refusal(3, 0)
            .expect("a host's domains hold a retry");
        assert_eq!(patient.after_refusal(0, u64::MAX), RefusalStep::RetryIn(3));
    }

    /// A retry value past the limit's declared range (`0..=4294967295`) is refused by the domain of
    /// the limit, which the refusal names.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_retry_value_outside_its_limits_domain_is_refused() {
        let pace = ReplayPacing::new(8, 10).expect("a pace");
        let past = 1usize << 32;
        let refused = pace
            .with_refusal(past, 0)
            .expect_err("past the declared range");
        assert_eq!(refused.limit, "DECLARATION_SYNC_RETRY_INTERVAL_MS");
        let refused = pace
            .with_refusal(0, past)
            .expect_err("past the declared range");
        assert_eq!(refused.limit, "DECLARATION_SYNC_TX_NO_PROGRESS_MS");
    }

    /// A pace holds the burst, the interval and a word of each retry limit whose domain has more
    /// than one value, and nothing else: a limit the build fixes takes no byte of it.
    #[test]
    fn a_pace_holds_a_retry_limit_only_where_its_domain_has_two_values() {
        let held = (DeclarationSyncRetryIntervalMs::HELD + DeclarationSyncTxNoProgressMs::HELD)
            * core::mem::size_of::<usize>();
        let fields = core::mem::size_of::<usize>() + core::mem::size_of::<u64>() + held;
        assert_eq!(
            core::mem::size_of::<ReplayPacing>(),
            fields.next_multiple_of(core::mem::align_of::<u64>())
        );
    }

    /// Only a parameter fixed at 0 can never be other than 0: one fixed elsewhere, or one a later
    /// stage may select inside a range, can.
    #[test]
    fn only_a_parameter_fixed_at_zero_is_never_other_than_zero() {
        let fixed = |value| LimitDomain::of_parameter(0, 100, None, value, true);
        let open = LimitDomain::of_parameter(0, 100, None, 0, false);
        assert!(!may_be_nonzero(fixed(0), 0));
        assert!(may_be_nonzero(fixed(5), 5));
        assert!(may_be_nonzero(open, 0));
    }

    /// The stamp is kept exactly where both retry limits may be other than 0, and is then a word
    /// of the session; where it is not kept it takes no byte.
    #[test]
    fn a_progress_stamp_is_kept_only_where_both_retry_limits_may_be_set() {
        let kept = may_be_nonzero(
            DeclarationSyncRetryIntervalMs::DOMAIN,
            DeclarationSyncRetryIntervalMs::DEFAULT,
        ) && may_be_nonzero(
            DeclarationSyncTxNoProgressMs::DOMAIN,
            DeclarationSyncTxNoProgressMs::DEFAULT,
        );
        assert_eq!(PROGRESS_STAMPS, usize::from(kept));
        assert_eq!(
            core::mem::size_of::<ProgressStamp>(),
            PROGRESS_STAMPS * core::mem::size_of::<u64>()
        );
    }

    /// A stamp reads `0` until a replay notes progress, then the time noted, where the build keeps
    /// one; where it keeps none it reads `0` throughout.
    #[test]
    fn a_progress_stamp_reads_the_time_noted_where_the_build_keeps_one() {
        let stamp = ProgressStamp::new();
        assert_eq!(stamp.get(), 0);
        stamp.note(1_234);
        let expected = if PROGRESS_STAMPS == 0 { 0 } else { 1_234 };
        assert_eq!(stamp.get(), expected);
        stamp.note(5_678);
        let expected = if PROGRESS_STAMPS == 0 { 0 } else { 5_678 };
        assert_eq!(stamp.get(), expected);
    }
}

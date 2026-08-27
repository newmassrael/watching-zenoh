// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The two STARTUP PHASES a node runs before it is up — bind, and dial — and
//! what a host does when one of them fails.
//!
//! ONE transcription of zenoh's `connect.{timeout_ms,exit_on_failure}` /
//! `listen.{timeout_ms,exit_on_failure}` (`commons/zenoh-config/src/lib.rs:453-472`,
//! defaults at `defaults.rs:35-58`), and the deliberate other half of
//! [`RetryPolicy`](crate::retry_period::RetryPolicy).
//!
//! `retry_period`'s module doc drew the line this module stands on: upstream's
//! `ConnectionRetryConf` carries FOUR fields and wz's `RetryPolicy` takes
//! three, because `exit_on_failure` "is a process-lifecycle decision belonging
//! to the host that owns the retry loop, not to the schedule". That sentence
//! named a home for the fourth field and there was none, so an operator could
//! write the key and nothing read it (open-debt item 229). This module is that
//! home, and it carries `timeout_ms` with it for the reason upstream reads them
//! together: the budget decides whether there is a give-up MOMENT at all, and
//! `exit_on_failure` decides what happens AT it. Either alone is unanswerable.
//!
//! # The shape upstream has, and why it is one shape for two phases
//!
//! `bind_listeners` and `connect_peers` are the same function with a different
//! verb (`net/runtime/orchestrator.rs:497-541` and `:318-400`): wrap the whole
//! phase in the phase's `timeout_ms`, and fork per endpoint on
//! `(does this retry, does a failure end startup)`. That fork is
//! [`PhaseArm`], and it is why [`PhasePolicy`] is not two types.
//!
//! # What the DEFAULTS are, and why they are not symmetric
//!
//! Measured at the pinned checkout, not remembered:
//!
//! | key | router | peer | client |
//! |---|---|---|---|
//! | `connect/timeout_ms` | `-1` | `-1` | `0` |
//! | `connect/exit_on_failure` | `false` | `false` | `true` |
//! | `listen/timeout_ms` | `0` | `0` | `0` |
//! | `listen/exit_on_failure` | `true` | `true` | `true` |
//!
//! A node that DIALS as part of a mesh has somewhere else to be — its own
//! listener — so a refused peer is not fatal and the dial runs unbounded in the
//! background. A CLIENT has nothing else, so its dial is one attempt and its
//! failure is the end of the process. A listener that cannot bind is fatal
//! everywhere, because the address is the node's identity to everyone else.
//!
//! wz already ran the peer column of that table and could not be told any
//! other. The defaults were therefore never the debt; the NON-defaults were.

use std::time::Duration;

use wz_codecs::whatami::WhatAmI;

use crate::retry_period::RetryPolicy;

/// zenoh's `{connect,listen}.timeout_ms` — the budget the WHOLE phase gets,
/// with upstream's three-way reading of one integer.
///
/// A newtype over the `i64` upstream stores rather than a three-variant enum,
/// and the field is PRIVATE, which is the whole of the design here. The three
/// readings are `< 0` (no bound), `== 0` (do not retry at all) and `> 0` (this
/// many milliseconds), so a `Bounded(0)` variant would be a fourth state that
/// means one of the other two depending on who asks — exactly the degenerate
/// value `RetryPolicy` types its periods `u64` to make unrepresentable.
/// [`Self::from_ms`] is the only way in, and it maps a zero onto
/// [`Self::NO_RETRY`] by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseBudget(i64);

impl PhaseBudget {
    /// Upstream's `-1` — the phase is never cut off. The router and peer
    /// default for `connect`.
    pub const UNBOUNDED: Self = Self(-1);

    /// Upstream's `0` — ONE attempt per endpoint, never re-tried. The client
    /// default for `connect`, and every mode's default for `listen`.
    ///
    /// Not "a budget of zero milliseconds": upstream does not arm the
    /// `tokio::time::timeout` wrap at all for this value
    /// (`orchestrator.rs:319`, `:503`), so a phase configured this way is not
    /// one that instantly elapses — it is one that never retries.
    pub const NO_RETRY: Self = Self(0);

    /// Read the key's value. Every negative collapses onto [`Self::UNBOUNDED`],
    /// which is upstream's own reading (`ms_to_duration` answers
    /// `Duration::MAX` for any `ms < 0`, not for `-1` alone).
    pub fn from_ms(ms: i64) -> Self {
        if ms < 0 {
            Self::UNBOUNDED
        } else {
            Self(ms)
        }
    }

    /// The value as the file would spell it, so a round-trip through this type
    /// is lossless for every input a document can carry.
    pub fn as_ms(self) -> i64 {
        self.0
    }

    /// Does this budget permit a SECOND attempt at all?
    ///
    /// Upstream asks it as `get_global_{connect,listener}_timeout().is_zero()`,
    /// one half of the disjunction that selects the no-retry arm
    /// (`orchestrator.rs:355`, `:525`). The other half is the SCHEDULE's, which
    /// is why [`PhasePolicy::arm`] takes one.
    pub fn permits_retry(self) -> bool {
        self.0 != 0
    }

    /// The wall-clock the phase may run for, or `None` when it runs untimed.
    ///
    /// `None` for BOTH [`Self::UNBOUNDED`] and [`Self::NO_RETRY`], and that is
    /// not a collapse of the two: neither arms upstream's timeout wrap. They
    /// differ in [`Self::permits_retry`], which is the question that separates
    /// them.
    pub fn deadline(self) -> Option<Duration> {
        (self.0 > 0).then(|| Duration::from_millis(self.0 as u64))
    }
}

/// zenoh's `{connect,listen}` failure policy: the budget, and what the HOST
/// does when the phase spends it without succeeding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhasePolicy {
    /// `{connect,listen}.timeout_ms`.
    pub budget: PhaseBudget,
    /// `{connect,listen}.exit_on_failure` — whether a failed phase ENDS the
    /// process rather than being logged and stepped over.
    pub exit_on_failure: bool,
}

/// HAND-WRITTEN, not derived, and the distinction is the one
/// [`RetryPolicy`]'s own `Default` makes: [`PhaseBudget`] has no `Default` to
/// derive from, so a value here has to be argued for.
///
/// The argument is that this type's identity element is the policy that can
/// neither cut a phase short nor end a process — an unbounded budget and no
/// exit — which is what every wz host did before this module existed. A struct
/// field nobody set therefore keeps the pre-existing behaviour rather than
/// silently acquiring a deadline. It coincides with
/// [`Self::CONNECT_MESH_DEFAULT`] because upstream's mesh column IS that
/// policy; the coincidence is not the reason.
///
/// ⚠ It is NOT [`Self::LISTEN_DEFAULT`], so a `listen_phase` left at `Default`
/// is more permissive than a real zenohd's. Every production path resolves both
/// phases explicitly against their own column, which is what
/// `wz-ap-demo`'s `resolve_phase` is for.
impl Default for PhasePolicy {
    fn default() -> Self {
        Self::CONNECT_MESH_DEFAULT
    }
}

impl PhasePolicy {
    /// `listen`'s defaults, which upstream declares `Unique` — the same answer
    /// for all three modes (`defaults.rs:53-58`).
    pub const LISTEN_DEFAULT: Self = Self {
        budget: PhaseBudget::NO_RETRY,
        exit_on_failure: true,
    };

    /// `connect`'s defaults for a node that has a listener of its own — the
    /// router and peer column (`defaults.rs:38-48`).
    pub const CONNECT_MESH_DEFAULT: Self = Self {
        budget: PhaseBudget::UNBOUNDED,
        exit_on_failure: false,
    };

    /// `connect`'s defaults for a CLIENT, which has nowhere else to be.
    pub const CONNECT_CLIENT_DEFAULT: Self = Self {
        budget: PhaseBudget::NO_RETRY,
        exit_on_failure: true,
    };

    /// `connect`'s defaults resolved for one node's mode — upstream's
    /// `ModeDependentValue::get(whatami)` over the table in the module doc.
    pub fn connect_default_for(mode: WhatAmI) -> Self {
        match mode {
            WhatAmI::Router | WhatAmI::Peer => Self::CONNECT_MESH_DEFAULT,
            WhatAmI::Client => Self::CONNECT_CLIENT_DEFAULT,
        }
    }

    /// Which of upstream's four arms this phase runs, given the schedule that
    /// paces it.
    ///
    /// The schedule is a parameter and not a field because it is a DIFFERENT
    /// config key (`{connect,listen}.retry`), read and defaulted on its own;
    /// folding it in here would give this type two owners. What the two decide
    /// together is upstream's disjunction: a phase retries only when the budget
    /// permits it AND the schedule has a wait to apply
    /// (`retry_config.timeout().is_zero() || global.is_zero()`,
    /// `orchestrator.rs:355`). A `period_init_ms` of `0` is a re-dial hot loop
    /// otherwise, which is the same reason `StaticConnectRetry::retries` spells
    /// the disjunction rather than either half.
    pub fn arm(self, schedule: RetryPolicy) -> PhaseArm {
        match (
            self.budget.permits_retry() && schedule.period_init_ms > 0,
            self.exit_on_failure,
        ) {
            (false, true) => PhaseArm::OnceThenFail,
            (false, false) => PhaseArm::OnceThenSkip,
            (true, true) => PhaseArm::RetryThenFail,
            (true, false) => PhaseArm::RetryInBackground,
        }
    }
}

/// The four ways a startup phase can treat one endpoint — upstream's own fork,
/// which both `bind_listeners_impl` and `connect_peers_multiply_links` take
/// (`orchestrator.rs:369-397`, `:520-541`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseArm {
    /// One attempt; a failure ENDS startup.
    OnceThenFail,
    /// One attempt; a failure is reported and the node comes up without this
    /// endpoint.
    OnceThenSkip,
    /// Re-attempt on the schedule until the budget is spent, THEN end startup.
    RetryThenFail,
    /// Re-attempt without holding startup up at all — upstream's
    /// `spawn_peer_connector` / `spawn_add_listener`.
    RetryInBackground,
}

impl PhaseArm {
    /// Does this arm re-attempt a failed endpoint?
    pub fn retries(self) -> bool {
        matches!(self, Self::RetryThenFail | Self::RetryInBackground)
    }

    /// Does a failure on this arm end the process?
    ///
    /// The question a HOST asks, and the one open-debt item 229 was filed for:
    /// until this module there was no value to ask it of, so every wz host
    /// answered it the same way forever.
    pub fn ends_startup(self) -> bool {
        matches!(self, Self::OnceThenFail | Self::RetryThenFail)
    }
}

/// Why a startup phase did not bring an endpoint up.
///
/// Carries the LAST error rather than only the count, because the diagnostic an
/// operator needs is why the final attempt failed, and `tokio::time::timeout`
/// over a whole loop would have dropped it — see [`drive_phase`].
#[derive(Debug)]
pub struct PhaseFailed<E> {
    /// The error the last COMPLETED attempt returned. `None` when the budget
    /// cut the first attempt off before it answered.
    pub last: Option<E>,
    /// How many attempts ran, completed or cut off.
    pub attempts: u32,
    /// [`PhaseArm::ends_startup`] for the arm that ran, carried so the host
    /// decides from the failure rather than re-deriving the policy.
    pub ends_startup: bool,
}

impl<E: std::fmt::Display> std::fmt::Display for PhaseFailed<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.last {
            Some(e) => write!(f, "{} attempt(s), last: {e}", self.attempts),
            None => write!(
                f,
                "{} attempt(s), none completed within the budget",
                self.attempts
            ),
        }
    }
}

/// Run ONE endpoint of a startup phase to its policy — upstream's
/// `add_listener` / `add_listener_retry` pair behind one call.
///
/// # Why the budget bounds each ATTEMPT rather than wrapping the loop
///
/// Upstream wraps the whole phase in `tokio::time::timeout`
/// (`orchestrator.rs:322`, `:505`), which cuts an in-flight attempt off at the
/// deadline — the behaviour a bounded budget has to have, since a dial that
/// hangs is precisely what the budget is for. It also DROPS the future, and
/// with it the error the last attempt was about to return, so upstream's own
/// give-up message names the endpoint list and no cause.
///
/// This applies the deadline to each attempt as the REMAINING budget instead.
/// The cut-off is the same wall-clock and the same drop, and the error of every
/// attempt that did complete survives to be reported. A `timeout` around the
/// loop with the error stashed in a cell would have been the other way to keep
/// it, at the price of a `!Send` future for every caller.
///
/// `attempt` is called with the 1-based attempt number so a host can log the
/// retry it is watching without counting in two places.
pub async fn drive_phase<T, E, F, Fut>(
    policy: PhasePolicy,
    schedule: RetryPolicy,
    mut attempt: F,
) -> Result<T, PhaseFailed<E>>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let arm = policy.arm(schedule);
    let deadline = policy
        .budget
        .deadline()
        .map(|d| tokio::time::Instant::now() + d);
    let mut period = schedule.period();
    let mut last: Option<E> = None;
    let mut attempts: u32 = 0;
    loop {
        attempts += 1;
        // The remaining budget, or `None` for an untimed phase. A deadline
        // already in the past yields an elapsed timer, which `timeout_at`
        // resolves WITHOUT letting the future run to completion — so a spent
        // budget cannot smuggle one more attempt through.
        let outcome = match deadline {
            Some(at) => tokio::time::timeout_at(at, attempt(attempts))
                .await
                .map_err(|_| ()),
            None => Ok(attempt(attempts).await),
        };
        match outcome {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(e)) => last = Some(e),
            // The budget cut this attempt off; there is nothing left to wait for.
            Err(()) => break,
        }
        if !arm.retries() {
            break;
        }
        let wait = Duration::from_millis(period.next_ms());
        match deadline {
            // Sleeping PAST the deadline would report the give-up late by
            // however long the last wait was, which is the number an operator
            // reads back as "my timeout_ms did not work".
            Some(at) if tokio::time::Instant::now() + wait >= at => {
                tokio::time::sleep_until(at).await;
                break;
            }
            _ => tokio::time::sleep(wait).await,
        }
    }
    Err(PhaseFailed {
        last,
        attempts,
        ends_startup: arm.ends_startup(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three readings of one integer, including the two that both answer
    /// `None` to [`PhaseBudget::deadline`] and must still be told apart.
    #[test]
    fn the_budget_reads_upstreams_three_cases() {
        assert_eq!(PhaseBudget::from_ms(-1), PhaseBudget::UNBOUNDED);
        assert_eq!(
            PhaseBudget::from_ms(-7),
            PhaseBudget::UNBOUNDED,
            "every negative is upstream's Duration::MAX arm, not -1 alone"
        );
        assert_eq!(PhaseBudget::from_ms(0), PhaseBudget::NO_RETRY);
        assert_eq!(PhaseBudget::from_ms(5000).as_ms(), 5000);

        assert!(PhaseBudget::UNBOUNDED.permits_retry());
        assert!(!PhaseBudget::NO_RETRY.permits_retry());
        assert!(PhaseBudget::from_ms(5000).permits_retry());

        assert_eq!(PhaseBudget::UNBOUNDED.deadline(), None);
        assert_eq!(
            PhaseBudget::NO_RETRY.deadline(),
            None,
            "a zero does not arm the timeout wrap; it disables the retry"
        );
        assert_eq!(
            PhaseBudget::from_ms(5000).deadline(),
            Some(Duration::from_millis(5000))
        );
    }

    /// The defaults are the MEASURED upstream table, pinned per mode. This is
    /// the assertion open-debt item 229's "the default axis is already parity"
    /// claim rests on, so it is code rather than the sentence it was.
    #[test]
    fn the_defaults_are_upstreams_mode_table() {
        for mesh in [WhatAmI::Router, WhatAmI::Peer] {
            let p = PhasePolicy::connect_default_for(mesh);
            assert_eq!(p.budget, PhaseBudget::UNBOUNDED, "{mesh:?} connect budget");
            assert!(!p.exit_on_failure, "{mesh:?} connect exit_on_failure");
        }
        let client = PhasePolicy::connect_default_for(WhatAmI::Client);
        assert_eq!(client.budget, PhaseBudget::NO_RETRY);
        assert!(client.exit_on_failure);

        // The whole struct rather than field-by-field, so `listen`'s column is
        // pinned as a VALUE. Field asserts would also read as a constant
        // expression to `clippy::assertions_on_constants`, which is how this
        // pair was written first and what Layer C1ay refused.
        assert_eq!(
            PhasePolicy::LISTEN_DEFAULT,
            PhasePolicy {
                budget: PhaseBudget::NO_RETRY,
                exit_on_failure: true,
            }
        );
    }

    /// `Default` is the policy that can neither cut a phase short nor end a
    /// process — the pre-R2159 behaviour of every wz host. Pinned as a
    /// PROPERTY and not only as an equality: a future round that repointed it
    /// at `LISTEN_DEFAULT` would satisfy "it equals one of the constants" and
    /// would give an unset field a deadline and a kill switch.
    #[test]
    fn the_default_policy_can_neither_give_up_nor_exit() {
        let d = PhasePolicy::default();
        assert_eq!(
            d.budget.deadline(),
            None,
            "a default must not bound a phase"
        );
        assert!(!d.exit_on_failure, "a default must not end a process");
        assert_eq!(d, PhasePolicy::CONNECT_MESH_DEFAULT);
    }

    /// The fork is upstream's DISJUNCTION, so a schedule with no wait forces
    /// the no-retry arm however generous the budget is.
    #[test]
    fn the_arm_needs_both_a_budget_and_a_schedule_to_retry() {
        let hot = RetryPolicy {
            period_init_ms: 0,
            period_max_ms: 0,
            period_increase_factor: 2.0,
        };
        let paced = RetryPolicy::ZENOH_DEFAULT;
        let generous = PhasePolicy {
            budget: PhaseBudget::from_ms(5000),
            exit_on_failure: true,
        };
        assert_eq!(
            generous.arm(hot),
            PhaseArm::OnceThenFail,
            "a zero period_init_ms would be a re-dial hot loop, so it is no retry at all"
        );
        assert_eq!(generous.arm(paced), PhaseArm::RetryThenFail);

        let carry_on = PhasePolicy {
            exit_on_failure: false,
            ..generous
        };
        assert_eq!(carry_on.arm(paced), PhaseArm::RetryInBackground);
        assert_eq!(carry_on.arm(hot), PhaseArm::OnceThenSkip);

        assert_eq!(
            PhasePolicy::LISTEN_DEFAULT.arm(paced),
            PhaseArm::OnceThenFail,
            "listen's shipped default binds once and a failure is fatal"
        );
        assert_eq!(
            PhasePolicy::CONNECT_MESH_DEFAULT.arm(paced),
            PhaseArm::RetryInBackground,
            "a peer's shipped default dials forever and never dies of it"
        );
    }

    /// The two predicates a host reads off the arm, over every arm — a table
    /// rather than four asserts, so a fifth arm cannot be added un-graded.
    #[test]
    fn every_arm_says_whether_it_retries_and_whether_it_is_fatal() {
        for (arm, retries, fatal) in [
            (PhaseArm::OnceThenFail, false, true),
            (PhaseArm::OnceThenSkip, false, false),
            (PhaseArm::RetryThenFail, true, true),
            (PhaseArm::RetryInBackground, true, false),
        ] {
            assert_eq!(arm.retries(), retries, "{arm:?}.retries()");
            assert_eq!(arm.ends_startup(), fatal, "{arm:?}.ends_startup()");
        }
    }

    /// A no-retry arm runs its attempt EXACTLY once and reports the cause.
    #[tokio::test]
    async fn a_no_retry_phase_attempts_once_and_keeps_the_cause() {
        let out: Result<(), _> = drive_phase(
            PhasePolicy::LISTEN_DEFAULT,
            RetryPolicy::ZENOH_DEFAULT,
            |n| async move { Err::<(), String>(format!("refused #{n}")) },
        )
        .await;
        let failed = out.expect_err("a phase whose attempt always fails cannot succeed");
        assert_eq!(failed.attempts, 1);
        assert_eq!(failed.last.as_deref(), Some("refused #1"));
        assert!(failed.ends_startup);
    }

    /// A bounded budget with a paced schedule retries, gives up INSIDE the
    /// budget, and still carries the last cause.
    #[tokio::test(start_paused = true)]
    async fn a_bounded_phase_retries_until_the_budget_is_spent() {
        let policy = PhasePolicy {
            budget: PhaseBudget::from_ms(1000),
            exit_on_failure: true,
        };
        let schedule = RetryPolicy::constant(200);
        let started = tokio::time::Instant::now();
        let out: Result<(), _> = drive_phase(policy, schedule, |n| async move {
            Err::<(), String>(format!("refused #{n}"))
        })
        .await;
        let failed = out.expect_err("nothing ever succeeds here");
        assert!(
            failed.attempts >= 4,
            "1000ms at a 200ms cadence is at least four attempts, got {}",
            failed.attempts
        );
        assert!(failed.last.is_some(), "the last cause must survive");
        assert!(failed.ends_startup);
        let spent = started.elapsed();
        assert!(
            spent >= Duration::from_millis(1000) && spent < Duration::from_millis(1200),
            "the phase must end AT its budget, not before or a whole wait after it: {spent:?}"
        );
    }

    /// An attempt that hangs is CUT OFF by the budget rather than outliving it.
    /// The behaviour upstream's `timeout` wrap has, and the reason the budget
    /// is applied per attempt here rather than only between them.
    #[tokio::test(start_paused = true)]
    async fn the_budget_cuts_off_an_attempt_that_never_answers() {
        let policy = PhasePolicy {
            budget: PhaseBudget::from_ms(500),
            exit_on_failure: false,
        };
        let started = tokio::time::Instant::now();
        let out: Result<(), PhaseFailed<String>> =
            drive_phase(policy, RetryPolicy::constant(100), |_| async {
                std::future::pending::<Result<(), String>>().await
            })
            .await;
        let failed = out.expect_err("a phase whose attempt never answers cannot succeed");
        assert_eq!(failed.attempts, 1);
        assert!(
            failed.last.is_none(),
            "no attempt completed, so there is no cause to report"
        );
        assert!(!failed.ends_startup);
        assert!(started.elapsed() < Duration::from_millis(600));
    }

    /// A later attempt succeeding ends the phase, and the schedule is what
    /// paced the ones before it.
    #[tokio::test(start_paused = true)]
    async fn a_retrying_phase_stops_at_the_first_success() {
        let policy = PhasePolicy {
            budget: PhaseBudget::UNBOUNDED,
            exit_on_failure: true,
        };
        let got = drive_phase(policy, RetryPolicy::constant(100), |n| async move {
            if n == 3 {
                Ok(n)
            } else {
                Err("not yet")
            }
        })
        .await;
        assert_eq!(got.expect("the third attempt succeeds"), 3);
    }
}

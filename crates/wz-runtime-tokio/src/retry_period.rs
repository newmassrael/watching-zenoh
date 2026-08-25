// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The connection-retry period: how long a failed dial waits before the next
//! attempt, and how that wait grows.
//!
//! ONE transcription of zenoh's `ConnectionRetryConf` / `ConnectionRetryPeriod`
//! (`commons/zenoh-config/src/connection_retry.rs:31-107`), shared by both
//! substrates in this crate that re-dial a lost link:
//!
//! - the CLIENT reconnect supervisor ([`crate::reconnect::ReconnectPolicy`]),
//!   whose parity target is pico's `_z_client_reopen_task_fn` and therefore
//!   defaults to a CONSTANT delay; and
//! - the ROUTER peer auto-reconnect (`router-connect-reconcile`, in
//!   `crate::accept_loop` — a code span rather than an intra-doc link because
//!   that module is `routing-accept`-gated and so does not exist in the
//!   default-feature rustdoc run Layer C1bz measures), whose parity target is
//!   zenoh's
//!   `peer_connector_retry` and therefore defaults to zenoh's own
//!   exponential-with-ceiling.
//!
//! The two DEFAULTS differ because the two atoms' declared parity sources
//! differ; the SCHEDULE is one implementation, so a fix to the growth arithmetic
//! cannot land on one substrate and miss the other.
//!
//! # Where this diverges from upstream, and why
//!
//! Upstream's three fields are `i64` / `i64` / `f64`, and `duration()` special-
//! cases a NEGATIVE `period_init_ms` (`Duration::MAX` — never retry) and a ZERO
//! one (retry immediately, forever, regardless of the factor). wz types the two
//! periods `u64`, which makes the negative case unrepresentable rather than
//! silently degenerate, and collapses the zero case WITHOUT a special arm: a
//! `delay_ms` of `0` multiplied by any factor is still `0`, so "init 0 means
//! always 0" falls out of the arithmetic instead of being asserted next to it.
//! A caller that genuinely means "never re-dial" says so by not scheduling one.

/// The three period knobs of zenoh's `ConnectionRetryConf`
/// (`connection_retry.rs:31-37`), minus `exit_on_failure` — that is a
/// process-lifecycle decision belonging to the host that owns the retry loop,
/// not to the schedule.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryPolicy {
    /// Wait before the FIRST retry, milliseconds — zenoh's `period_init_ms`.
    pub period_init_ms: u64,
    /// Ceiling the growing wait is clamped to, milliseconds; `0` = NO ceiling.
    /// zenoh's `period_max_ms`, including its `> 0` guard
    /// (`connection_retry.rs:101`) — the sentinel is upstream's, not one this
    /// port invented.
    pub period_max_ms: u64,
    /// Multiplier applied AFTER each retry — zenoh's `period_increase_factor`.
    /// `1.0` reproduces a fixed delay exactly.
    pub period_increase_factor: f64,
}

/// HAND-WRITTEN, not derived, and the distinction is load-bearing: the derived
/// impl would be `0 / 0 / 0.0` — no wait, no ceiling, no growth — which is a
/// re-dial hot loop, the one value of this struct that is a defect rather than a
/// policy. [`RetryPolicy::ZENOH_DEFAULT`] is also what upstream resolves for a
/// config that omits the section (`ConnectionRetryModeDependentConf::default`),
/// so "the default" means the same thing on both sides of the port.
impl Default for RetryPolicy {
    fn default() -> Self {
        Self::ZENOH_DEFAULT
    }
}

impl RetryPolicy {
    /// zenoh's own shipped defaults — `1000` / `4000` / `2.0`
    /// (`DEFAULT_CONFIG.json5:63-67`, and identically
    /// `ConnectionRetryModeDependentConf::default()` at
    /// `zenoh-config/src/defaults.rs:347-355`, which is what a config that
    /// omits the section actually resolves to).
    pub const ZENOH_DEFAULT: Self = Self {
        period_init_ms: 1000,
        period_max_ms: 4000,
        period_increase_factor: 2.0,
    };

    /// A CONSTANT `ms` wait, forever: factor `1.0`, no ceiling. pico's shape —
    /// `_z_client_reopen_task_fn` re-arms with a literal
    /// `_z_fut_fn_result_wake_up_after(1000)` and never grows it.
    pub const fn constant(ms: u64) -> Self {
        Self {
            period_init_ms: ms,
            period_max_ms: 0,
            period_increase_factor: 1.0,
        }
    }

    /// Fresh growth state for one outage — zenoh's `ConnectionRetryConf::period`
    /// (`connection_retry.rs:67-69`).
    pub fn period(&self) -> RetryPeriod {
        RetryPeriod::new(*self)
    }

    /// Whether this policy ever grows its wait. Not used by the schedule
    /// itself; it is the predicate a caller (or a test) asks when the question
    /// is "is this deploy on the constant shape or the exponential one",
    /// which is otherwise a two-field conjunction each site would re-derive.
    pub fn grows(&self) -> bool {
        self.period_increase_factor > 1.0 && self.period_init_ms > 0
    }
}

/// The growing wait for ONE outage — zenoh's `ConnectionRetryPeriod`
/// (`connection_retry.rs:72-107`). Owns its policy exactly as upstream's state
/// clones its `conf`, so a caller holding a map of these per peer does not have
/// to thread the policy back in at every call (and cannot pair a state with the
/// wrong policy).
///
/// Per-OUTAGE, not per-process: a fresh one is built each time a link that had
/// been ESTABLISHED goes down, so a peer that flaps once an hour retries from
/// `period_init_ms` every time rather than from wherever the last outage left
/// off. That is upstream's lifetime too — `peer_connector_retry` builds its
/// `period` on entry and drops it when the connect succeeds
/// (`net/runtime/orchestrator.rs:787-788`).
#[derive(Debug, Clone, Copy)]
pub struct RetryPeriod {
    policy: RetryPolicy,
    delay_ms: u64,
}

impl RetryPeriod {
    /// Start at `period_init_ms`.
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            delay_ms: policy.period_init_ms,
            policy,
        }
    }

    /// The wait the NEXT [`Self::next_ms`] will return, WITHOUT growing —
    /// zenoh's `duration()` (`connection_retry.rs:85-95`). For logging a
    /// cadence without disturbing it.
    pub fn peek_ms(&self) -> u64 {
        self.delay_ms
    }

    /// The wait to apply NOW, then grow the stored value for the retry after
    /// it — zenoh's `next_duration()` (`connection_retry.rs:97-106`).
    ///
    /// The ORDER is the load-bearing part: the current delay is returned
    /// BEFORE the multiply, so the first retry of an outage waits
    /// `period_init_ms` itself rather than an already-multiplied value. Every
    /// caller that used to sleep a fixed `period_init_ms` therefore sees an
    /// unchanged FIRST wait, which is what makes adopting the growth safe for
    /// tests and timing assumptions that observe only the first re-dial.
    pub fn next_ms(&mut self) -> u64 {
        let now = self.delay_ms;
        // `as u64` saturates to 0 for a negative or NaN product — the same
        // degenerate answer upstream's `as i64` cast collapses to — so a
        // hostile config file cannot panic or wrap the schedule.
        let grown = (self.delay_ms as f64 * self.policy.period_increase_factor) as u64;
        self.delay_ms = if self.policy.period_max_ms > 0 {
            grown.min(self.policy.period_max_ms)
        } else {
            grown
        };
        now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The growth transcribes zenoh's `next_duration`: return the CURRENT
    /// delay, THEN multiply. Pins the SEQUENCE, not just that it rises — an
    /// off-by-one that multiplied first would still "grow".
    #[test]
    fn next_ms_returns_the_current_wait_before_multiplying() {
        let mut p = RetryPolicy {
            period_init_ms: 100,
            period_max_ms: 0,
            period_increase_factor: 2.0,
        }
        .period();
        assert_eq!(
            (0..4).map(|_| p.next_ms()).collect::<Vec<_>>(),
            vec![100, 200, 400, 800],
            "the first wait must be period_init_ms itself"
        );
    }

    /// `period_max_ms` clamps and `0` means UNBOUNDED — upstream's `> 0` guard.
    /// A port that read `0` as "clamp to zero" would busy-loop a re-dial.
    #[test]
    fn the_ceiling_clamps_and_zero_means_unbounded() {
        let capped = RetryPolicy {
            period_init_ms: 100,
            period_max_ms: 350,
            period_increase_factor: 2.0,
        };
        let mut p = capped.period();
        assert_eq!(
            (0..5).map(|_| p.next_ms()).collect::<Vec<_>>(),
            vec![100, 200, 350, 350, 350]
        );

        let mut p = RetryPolicy {
            period_max_ms: 0,
            ..capped
        }
        .period();
        assert_eq!(
            (0..4).map(|_| p.next_ms()).collect::<Vec<_>>(),
            vec![100, 200, 400, 800],
            "0 must mean unbounded, not an immediate clamp to zero"
        );
    }

    /// zenoh's shipped default resolves to 1s -> 2s -> 4s -> 4s. This is the
    /// schedule a wz router now runs by default, so it is pinned as a SEQUENCE
    /// against the upstream config it claims to mirror.
    #[test]
    fn the_zenoh_default_is_one_two_four_capped() {
        let mut p = RetryPolicy::ZENOH_DEFAULT.period();
        assert_eq!(
            (0..5).map(|_| p.next_ms()).collect::<Vec<_>>(),
            vec![1000, 2000, 4000, 4000, 4000]
        );
        assert!(RetryPolicy::ZENOH_DEFAULT.grows());
    }

    /// `Default` must be zenoh's schedule and NOT the derived all-zero one. The
    /// derived impl compiles, satisfies every `#[derive(Default)]` that embeds
    /// this type, and produces a re-dial hot loop: a zero wait, no ceiling, and
    /// no growth to ever lift it off zero.
    #[test]
    fn the_default_is_zenohs_schedule_not_a_zero_hot_loop() {
        assert_eq!(RetryPolicy::default(), RetryPolicy::ZENOH_DEFAULT);
        let mut p = RetryPolicy::default().period();
        assert!(p.next_ms() > 0, "a default re-dial must wait at all");
        assert!(RetryPolicy::default().grows());
    }

    /// [`RetryPolicy::constant`] is pico's shape, and it must NOT grow — the
    /// discriminator against a future round "unifying" the two defaults.
    #[test]
    fn a_constant_policy_never_grows() {
        let policy = RetryPolicy::constant(1000);
        let mut p = policy.period();
        assert_eq!(
            (0..5).map(|_| p.next_ms()).collect::<Vec<_>>(),
            vec![1000, 1000, 1000, 1000, 1000]
        );
        assert!(!policy.grows());
    }

    /// `peek_ms` reports the next wait WITHOUT consuming it — a log line must
    /// not be able to alter the cadence it reports.
    #[test]
    fn peek_ms_does_not_advance_the_schedule() {
        let mut p = RetryPolicy::ZENOH_DEFAULT.period();
        assert_eq!(p.peek_ms(), 1000);
        assert_eq!(p.peek_ms(), 1000, "peeking twice must not grow");
        assert_eq!(p.next_ms(), 1000);
        assert_eq!(p.peek_ms(), 2000, "and now it reports the grown value");
    }

    /// A degenerate factor collapses to zero rather than panicking or wrapping.
    /// The field is an `f64` a deploy config can set, and `as u64` on a
    /// negative or NaN value is the one piece of arithmetic here with a
    /// surprising answer.
    #[test]
    fn a_degenerate_factor_does_not_panic_or_wrap() {
        for factor in [0.0, -1.0, f64::NAN] {
            let policy = RetryPolicy {
                period_init_ms: 100,
                period_max_ms: 0,
                period_increase_factor: factor,
            };
            assert!(!policy.grows(), "factor {factor} is not growth");
            let mut p = policy.period();
            assert_eq!(p.next_ms(), 100, "the first wait is always init");
            assert_eq!(p.next_ms(), 0, "factor {factor} collapses to 0");
        }
    }

    /// A `period_init_ms` of `0` stays `0` under ANY factor — upstream's
    /// `period_init_ms == 0` arm, reproduced by the arithmetic rather than by a
    /// special case (see the module doc).
    #[test]
    fn a_zero_init_stays_zero_under_growth() {
        let mut p = RetryPolicy {
            period_init_ms: 0,
            period_max_ms: 4000,
            period_increase_factor: 2.0,
        }
        .period();
        assert_eq!((0..4).map(|_| p.next_ms()).collect::<Vec<_>>(), vec![0; 4]);
    }
}

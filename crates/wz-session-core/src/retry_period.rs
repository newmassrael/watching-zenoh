// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The connection-retry period: how long a failed dial waits before the next
//! attempt, and how that wait grows.
//!
//! ONE transcription of zenoh's `ConnectionRetryConf` / `ConnectionRetryPeriod`
//! (`commons/zenoh-config/src/connection_retry.rs:31-107`), shared by every
//! substrate in the workspace that re-dials a lost link:
//!
//! - the AP CLIENT reconnect supervisor (`wz_runtime_tokio::reconnect`),
//!   whose parity target is pico's `_z_client_reopen_task_fn` and therefore
//!   defaults to a CONSTANT delay;
//! - the AP ROUTER peer auto-reconnect (`router-connect-reconcile`, in
//!   `wz_runtime_tokio::accept_loop`), whose parity target is zenoh's
//!   `peer_connector_retry` and therefore defaults to zenoh's own
//!   exponential-with-ceiling; and
//! - R2830 — the MCU connection manager (`wz_session_lwip::connect_manager`),
//!   which re-dials the endpoints a host wrote to `connect/endpoints`.
//!
//! The DEFAULTS differ because the atoms' declared parity sources differ; the
//! SCHEDULE is one implementation, so a fix to the growth arithmetic cannot
//! land on one substrate and miss the others. R2830 moved it here from
//! `wz_runtime_tokio::retry_period` (which re-exports it, so every existing
//! path still names the same type) because the MCU needed the same schedule
//! and a second copy is what that sentence exists to prevent.
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

    /// R2496 (`router-connect-reconcile`) — this policy with a single
    /// endpoint's overrides laid over it, field by field.
    ///
    /// zenoh resolves retry exactly this way: the global `connect.retry` block
    /// first, then the endpoint's own config span on top —
    /// `commons/zenoh-config/src/connection_retry.rs` @ `pub fn get_retry_config(`,
    /// where each `if let Some(val) = config.get(..)` replaces one field and
    /// leaves the rest. A field the tail is silent about keeps the global
    /// value, which is why this takes `Option`s rather than a whole policy: an
    /// endpoint that names only `retry_period_max_ms` must not also inherit a
    /// default `period_init_ms` from nowhere.
    /// R2496b — `None` is an endpoint whose `#` tail named no override at all,
    /// which the locator parser records as an absent set rather than an empty
    /// one (see `crate::locator::LocatorRetry`'s size note). It
    /// returns the global policy untouched, which is the same answer an
    /// all-`None` set would have produced field by field.
    ///
    /// `alloc` only, because the locator parser that produces the overrides is.
    #[cfg(feature = "alloc")]
    pub fn layered(self, overrides: Option<&crate::locator::LocatorRetry>) -> Self {
        let Some(overrides) = overrides else {
            return self;
        };
        Self {
            period_init_ms: overrides.period_init_ms.unwrap_or(self.period_init_ms),
            period_max_ms: overrides.period_max_ms.unwrap_or(self.period_max_ms),
            period_increase_factor: overrides
                .period_increase_factor()
                .unwrap_or(self.period_increase_factor),
        }
    }

    /// Whether this policy ever grows its wait. Not used by the schedule
    /// itself; it is the predicate a caller (or a test) asks when the question
    /// is "is this deploy on the constant shape or the exponential one",
    /// which is otherwise a two-field conjunction each site would re-derive.
    pub fn grows(&self) -> bool {
        self.period_increase_factor > 1.0 && self.period_init_ms > 0
    }
}

/// `(delay_ms as f64 * factor) as u64`, in integer arithmetic, for every input.
///
/// The expression is upstream's (`connection_retry.rs`: `(self.delay as f64 * factor) as i64`),
/// and on a target with no double-precision unit it is a call to the compiler's soft-float
/// multiply, two conversions and two comparisons: 1.2 KB of text in the Zephyr client, whose
/// growth is the one product of a number of milliseconds by a constant. This returns what the
/// expression returns, bit for bit, with the two roundings the expression makes and no
/// floating-point operation: the delay is rounded to the nearest `f64` (it is exact below 2^53),
/// multiplied by the factor's mantissa as an integer, the product rounded to 53 significant bits
/// (nearest, ties to even), and the result truncated and saturated as `as u64` does. A negative or
/// NaN factor, an infinite one and a delay of 0 are the cases the expression resolves by the rules
/// of IEEE 754 and `as`, resolved here by the same rules. The tests hold it equal to the expression
/// over a grid of the edges and over a quarter of a million random pairs of bit patterns.
fn grown_ms(delay_ms: u64, factor: f64) -> u64 {
    const FRACTION_BITS: u32 = 52;
    const SIGNIFICANT_BITS: u32 = 53;

    let bits = factor.to_bits();
    let negative = bits >> 63 != 0;
    let biased = ((bits >> FRACTION_BITS) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << FRACTION_BITS) - 1);
    if biased == 0x7ff {
        // NaN, or an infinity: `delay * inf` is inf (saturates) unless the delay is 0 (NaN) or the
        // infinity is negative (-inf), and both of those cast to 0.
        return if fraction != 0 || negative || delay_ms == 0 {
            0
        } else {
            u64::MAX
        };
    }
    // A negative factor makes a negative or -0.0 product, a zero or subnormal one a product below
    // 1 (a subnormal is under 2^-1022 and a delay under 2^64), a delay of 0 a product of 0.
    if negative || biased == 0 || delay_ms == 0 {
        return 0;
    }
    // factor = mantissa * 2^exponent, with 2^52 <= mantissa < 2^53.
    let mantissa = u128::from(fraction | (1u64 << FRACTION_BITS));
    let exponent = biased - 1075;

    // The delay as an `f64` holds it: rounded to 53 significant bits when it needs more.
    let delay = {
        let length = 64 - delay_ms.leading_zeros();
        if length <= SIGNIFICANT_BITS {
            u128::from(delay_ms)
        } else {
            u128::from(round_to_significant(
                u128::from(delay_ms),
                length - SIGNIFICANT_BITS,
            )) << (length - SIGNIFICANT_BITS)
        }
    };

    // The product, exact: under 2^64 * 2^53.
    let product = delay * mantissa;
    let length = 128 - product.leading_zeros();
    let (kept, dropped) = if length <= SIGNIFICANT_BITS {
        (product as u64, 0)
    } else {
        let dropped = length - SIGNIFICANT_BITS;
        (round_to_significant(product, dropped), dropped)
    };

    // value = kept * 2^(dropped + exponent), and `as u64` truncates it and saturates.
    let shift = dropped as i32 + exponent;
    if shift >= 0 {
        if shift >= 64 {
            return u64::MAX;
        }
        let value = u128::from(kept) << shift;
        u64::try_from(value).unwrap_or(u64::MAX)
    } else if shift <= -64 {
        0
    } else {
        kept >> -shift
    }
}

/// `value >> dropped`, rounded to nearest with ties to even: the 53 significant bits an `f64`
/// keeps of a number that has `dropped` more.
fn round_to_significant(value: u128, dropped: u32) -> u64 {
    let mut kept = value >> dropped;
    let remainder = value & ((1u128 << dropped) - 1);
    let half = 1u128 << (dropped - 1);
    if remainder > half || (remainder == half && kept & 1 == 1) {
        kept += 1;
    }
    // At most 2^53.
    kept as u64
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
        let grown = grown_ms(self.delay_ms, self.policy.period_increase_factor);
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
    // `std`, not `alloc`: this module compiles without an allocator, and the
    // crate links `std` for tests only (lib.rs).
    use std::vec;
    use std::vec::Vec;

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

    /// The expression `grown_ms` stands for.
    fn by_float(delay_ms: u64, factor: f64) -> u64 {
        (delay_ms as f64 * factor) as u64
    }

    fn assert_same(delay_ms: u64, factor: f64) {
        assert_eq!(
            grown_ms(delay_ms, factor),
            by_float(delay_ms, factor),
            "delay {delay_ms} factor {factor:?} (bits {:#018x})",
            factor.to_bits()
        );
    }

    /// The edges: the delays around the 53 bits an `f64` holds and the 64 a `u64` does, and the
    /// factors that are exact, inexact (1.1 and 1.7 are the two that round the product across
    /// an integer), tiny, huge, subnormal, infinite, NaN and negative.
    #[test]
    fn grown_ms_is_the_float_expression_on_the_edges() {
        let delays = [
            0,
            1,
            2,
            3,
            7,
            10,
            999,
            1000,
            1001,
            4000,
            123_456_789,
            u64::from(u32::MAX),
            (1 << 52) - 1,
            1 << 52,
            (1 << 53) - 1,
            1 << 53,
            (1 << 53) + 1,
            (1 << 53) + 2,
            (1 << 53) + 3,
            (1 << 60) + 12_345,
            (1 << 63) - 1,
            1 << 63,
            u64::MAX - 1,
            u64::MAX,
        ];
        let factors = [
            0.0,
            -0.0,
            0.5,
            0.9999999999999999,
            1.0,
            1.0000000000000002,
            1.1,
            1.5,
            1.7,
            2.0,
            2.0000000000000004,
            3.0,
            4.0,
            10.0,
            1e-300,
            f64::MIN_POSITIVE,
            5e-324,
            1e19,
            1.8446744073709552e19,
            1e300,
            f64::MAX,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            -1.0,
            -2.0,
            -1e300,
        ];
        for &delay in &delays {
            for &factor in &factors {
                assert_same(delay, factor);
            }
        }
    }

    /// Random bit patterns for both: any delay of any length and any `f64`, the NaNs and the
    /// subnormals among them (xorshift64*, a fixed seed, so a failure repeats).
    #[test]
    fn grown_ms_is_the_float_expression_on_random_bit_patterns() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for _ in 0..250_000 {
            // A delay of random length: the mask keeps the top bits off.
            let delay = next() >> (next() % 64);
            let factor = f64::from_bits(next());
            assert_same(delay, factor);
            // The factors that matter in a schedule: near 1 and small integers and halves, which
            // hit the rounding of the product most often.
            let near = 1.0 + (next() % 4096) as f64 / 1024.0;
            assert_same(delay, near);
            assert_same(delay % 100_000, near);
        }
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE SN STEPS AS A MIXTURE, in integers (`docs/flow-zenoh-verdict.md` §6.6).
//!
//! A flow whose link breaks SN steps at a rate of its own, drawn from a Beta
//! distribution `Beta(a, g)`, has its `follows` followed steps and `breaks` broken
//! ones with probability
//!
//! ```text
//!   B(a + breaks, g + follows) / B(a, g)  =  (a)_breaks * (g)_follows / (a + g)_n
//! ```
//!
//! where `(x)_k` is the rising factorial and `n = follows + breaks`. This module
//! computes the log of it, against the null's, as the millibits the model weighs
//! with, with no floating point: the crate is `no_std`, has no third-party
//! dependency, and the shipped weights are integers the C header pins to the unit.
//!
//! * The Beta parameters are fractions of one denominator, `a = a_num / den` and
//!   `g = g_num / den`, so that every factor of a rising factorial is an INTEGER
//!   over `den` and its logarithm is the logarithm of an integer.
//! * [`log2_q64`](crate::zenoh_mixture::log2_q64) is the logarithm of an integer to 64 fractional bits, found by
//!   squaring a 128-bit mantissa and reading off a bit a time, which is exact in
//!   integer arithmetic and the same on every target.
//! * A rising factorial of many factors is a ratio of gamma functions, and
//!   [`log2_gamma_q64`](crate::zenoh_mixture::log2_gamma_q64) takes it: the argument is shifted up to 16 by the few
//!   factors it lacks, and Stirling's series finishes it, so the cost does not
//!   grow with the number of steps a flow holds.
//!
//! Model 3 reads the same mixture one step at a time
//! ([`crate::zenoh_eprocess::Prior`]), which is what a latched word needs; this
//! module computes it from the counts in one step, and the two are held to each
//! other (`the_predictive_walk_is_the_mixture_of_the_counts`). Its logarithm is
//! the one `zenoh_eprocess` stands on.

/// The counts above which a flow's steps are counted as this many: `2^36`, about
/// 7 * 10^10 steps, which no capture holds. It keeps the arguments of the logarithm
/// in a `u64` and every product of the series in an `i128`.
pub const MAX_STEPS: u64 = 1 << 36;

/// `log2(e)` to 64 fractional bits.
const LOG2_E_Q64: i128 = 26_613_026_195_688_644_983;

/// `log2(sqrt(2 pi))` to 64 fractional bits.
const HALF_LOG2_2PI_Q64: i128 = 24_455_735_256_403_655_384;

/// `log2(255 / 256)` to 64 fractional bits: the null's weight of a step that breaks
/// is the chance of a varint that is not the last plus one.
pub(crate) const LOG2_BREAK_NULL_Q64: i128 = -104_160_705_160_689_130;

/// One in Q64.
const ONE_Q64: i128 = 1 << 64;

/// The product of two 128-bit integers, as `(high, low)` halves of 256 bits.
pub(crate) fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    const LOW: u128 = (1 << 64) - 1;
    let (a0, a1) = (a & LOW, a >> 64);
    let (b0, b1) = (b & LOW, b >> 64);
    let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
    let mid = (p00 >> 64) + (p01 & LOW) + (p10 & LOW);
    let low = (p00 & LOW) | ((mid & LOW) << 64);
    let high = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (high, low)
}

/// `log2(x)` of a positive integer, to 64 fractional bits (`log2(x) * 2^64`).
///
/// The integer part is the position of the top bit. The fraction is read from the
/// mantissa `z` in `[1, 2)`: squaring it gives a number in `[1, 4)`, and it is at
/// least 2 exactly when the next bit of the logarithm is 1, in which case it is
/// halved. The mantissa has 127 fractional bits, which the 64 squarings spend at
/// one bit of precision each, so the result is right to better than 2^-60.
pub fn log2_q64(x: u64) -> u128 {
    let x = x.max(1);
    let lead = x.leading_zeros();
    let int = u128::from(63 - lead);
    // The mantissa with its top bit at bit 127: `z * 2^127`.
    let mut m = u128::from(x) << (64 + lead);
    let mut frac: u128 = 0;
    for _ in 0..64 {
        let (high, low) = mul_wide(m, m);
        frac <<= 1;
        if high >> 127 == 1 {
            frac |= 1;
            m = high;
        } else {
            m = (high << 1) | (low >> 127);
        }
    }
    (int << 64) | frac
}

/// `log2(num / den)` in Q64, signed.
fn log2_ratio_q64(num: u128, den: u64) -> i128 {
    let n = u64::try_from(num).unwrap_or(u64::MAX);
    log2_q64(n) as i128 - log2_q64(den) as i128
}

/// `log2(Gamma(num / den))` in Q64, for `num >= 1`.
///
/// The argument is raised to at least 16 by `Gamma(x) = Gamma(x + 1) / x`, and the
/// rest is Stirling's series, `(x - 1/2) ln x - x + ln(sqrt(2 pi)) + 1/(12 x) -
/// 1/(360 x^3)`, whose next term is under 10^-9 bits there.
pub fn log2_gamma_q64(num: u128, den: u64) -> i128 {
    let d = u128::from(den);
    let mut n = num.max(1);
    let mut shifted: i128 = 0;
    while n < 16 * d {
        shifted += log2_ratio_q64(n, den);
        n += d;
    }
    let (ni, di) = (n as i128, d as i128);
    let lx = log2_ratio_q64(n, den);
    // (x - 1/2) log2 x, with x = n / den.
    let t1 = (2 * ni - di) * lx / (2 * di);
    // -x log2 e.
    let t2 = -(ni * LOG2_E_Q64 / di);
    // log2(sqrt(2 pi)).
    let t3 = HALF_LOG2_2PI_Q64;
    // log2(e) / (12 x), and -log2(e) / (360 x^3), as a chain of divisions so that no
    // power of a large `n` is formed.
    let t4 = LOG2_E_Q64 * di / (12 * ni);
    let t5 = -(LOG2_E_Q64 * di / ni * di / ni * di / ni / 360);
    t1 + t2 + t3 + t4 + t5 - shifted
}

/// The mixture over a link's break rate: `Beta(a_num / den, g_num / den)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnMixture {
    a_num: u64,
    g_num: u64,
    den: u64,
    /// `log2 Gamma(a)`, `log2 Gamma(g)` and `log2 Gamma(a + g)`, in Q64.
    lg_a: i128,
    lg_g: i128,
    lg_ag: i128,
}

impl SnMixture {
    /// The mixture of `Beta(a_num / den, g_num / den)`. All three are at least 1,
    /// `den` is at most `2^16` and the numerators at most `2^32`; anything outside
    /// that is clamped into it.
    pub fn new(a_num: u64, g_num: u64, den: u64) -> Self {
        let den = den.clamp(1, 1 << 16);
        let a_num = a_num.clamp(1, 1 << 32);
        let g_num = g_num.clamp(1, 1 << 32);
        Self {
            a_num,
            g_num,
            den,
            lg_a: log2_gamma_q64(u128::from(a_num), den),
            lg_g: log2_gamma_q64(u128::from(g_num), den),
            lg_ag: log2_gamma_q64(u128::from(a_num) + u128::from(g_num), den),
        }
    }

    /// `log2` of the probability of a flow's steps under the mixture, in Q64.
    fn log2_probability_q64(&self, follows: u64, breaks: u64) -> i128 {
        let d = u128::from(self.den);
        let (f, b) = (u128::from(follows), u128::from(breaks));
        let a = u128::from(self.a_num);
        let g = u128::from(self.g_num);
        // (a)_b (g)_f / (a + g)_n, each a ratio of gamma functions.
        (log2_gamma_q64(a + b * d, self.den) - self.lg_a)
            + (log2_gamma_q64(g + f * d, self.den) - self.lg_g)
            - (log2_gamma_q64(a + g + (f + b) * d, self.den) - self.lg_ag)
    }

    /// What a flow's SN steps weigh, in millibits on both sums: the log of their
    /// probability under the mixture against the null's, a step that follows
    /// having chance `2^-8` and one that breaks `255/256`. The counts are
    /// clamped to [`MAX_STEPS`].
    pub fn millibits(&self, follows: u64, breaks: u64) -> i64 {
        let (f, b) = (follows.min(MAX_STEPS), breaks.min(MAX_STEPS));
        if f + b == 0 {
            return 0;
        }
        let null = -8 * i128::from(f) * ONE_Q64 + i128::from(b) * LOG2_BREAK_NULL_Q64;
        let bits = self.log2_probability_q64(f, b) - null;
        // Round half away from zero to millibits, as the model's weights are.
        let scaled = bits * 1000;
        let half = ONE_Q64 / 2;
        let rounded = if scaled >= 0 {
            (scaled + half) >> 64
        } else {
            -((-scaled + half) >> 64)
        };
        i64::try_from(rounded).unwrap_or(if rounded < 0 { i64::MIN } else { i64::MAX })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: f64 = 18_446_744_073_709_551_616.0;

    fn bits(q64: i128) -> f64 {
        q64 as f64 / Q
    }

    /// The logarithm is the logarithm, and exact where it can be.
    #[test]
    fn log2_q64_is_the_logarithm() {
        assert_eq!(log2_q64(1), 0);
        for k in 0..64u32 {
            assert_eq!(log2_q64(1u64 << k), u128::from(k) << 64, "2^{k}");
        }
        for x in [
            3u64,
            5,
            7,
            10,
            255,
            256,
            257,
            1000,
            65_535,
            1_000_003,
            (1 << 32) + 1,
            (1 << 40) + 12_345,
            u64::MAX,
        ] {
            let want = (x as f64).log2();
            let got = bits(log2_q64(x) as i128);
            assert!(
                (got - want).abs() < 1e-12,
                "log2({x}): {got} against {want}"
            );
        }
        // Monotone, over a run of neighbours.
        let mut last = 0;
        for x in 1..2_000u64 {
            let l = log2_q64(x);
            assert!(l >= last, "log2 fell at {x}");
            last = l;
        }
    }

    /// The sum of `log2(num/den + i)` for `i < count`, by direct addition.
    fn rising_log2(num: u64, den: u64, count: u64) -> f64 {
        (0..count)
            .map(|i| (num as f64 / den as f64 + i as f64).log2())
            .sum()
    }

    /// The weights of the report's prior, `Beta(88/10000, 19912/10000)` (mean
    /// 0.0044, concentration 2), to the unit. They were computed apart from this
    /// code, by floating-point addition in another language, and none is within
    /// 0.07 of a rounding boundary. The integer arithmetic is the same on every
    /// target, so a change of any of these is a change of the algorithm.
    #[test]
    fn the_mixture_weighs_to_the_unit_what_an_independent_sum_does() {
        let m = SnMixture::new(88, 19_912, 10_000);
        for (follows, breaks, want) in [
            (100u64, 0u64, 799_947i64),
            (100, 6, 759_845),
            (50, 50, 290_488),
            (10, 10, 51_488),
            (0, 20, -15_385),
            (588, 1_756, 2_795_260),
            (0, 29, -16_380),
            (1, 0, 7_994),
            (0, 1, -7_823),
            (2_400, 3, 19_160_422),
            (5_000, 0, 39_999_897),
        ] {
            assert_eq!(
                m.millibits(follows, breaks),
                want,
                "{follows} followed, {breaks} broke"
            );
        }
    }

    /// `Gamma(x + count) / Gamma(x)` is the rising factorial, for arguments below
    /// and above the point where Stirling's series takes over, and for many factors.
    #[test]
    fn the_gamma_ratio_is_the_rising_factorial() {
        for (num, den) in [
            (88u64, 10_000u64),
            (19_912, 10_000),
            (20_000, 10_000),
            (3, 2),
            (1, 1),
            (1, 3),
            (7, 5),
        ] {
            for count in [0u64, 1, 2, 5, 15, 16, 17, 100, 1_000, 100_000] {
                let got = bits(
                    log2_gamma_q64(u128::from(num + count * den), den)
                        - log2_gamma_q64(u128::from(num), den),
                );
                let want = rising_log2(num, den, count);
                let tolerance = 3e-9 + 1e-12 * want.abs();
                assert!(
                    (got - want).abs() < tolerance,
                    "{num}/{den} + {count}: {got} against {want}"
                );
            }
        }
    }

    /// The oracle: the same weight by floating point and direct addition.
    fn oracle_millibits(a: f64, g: f64, follows: u64, breaks: u64) -> f64 {
        let n = follows + breaks;
        let sum =
            |start: f64, count: u64| -> f64 { (0..count).map(|i| (start + i as f64).log2()).sum() };
        let p1 = sum(a, breaks) + sum(g, follows) - sum(a + g, n);
        let null = -8.0 * follows as f64 + breaks as f64 * (255.0f64 / 256.0).log2();
        1000.0 * (p1 - null)
    }

    /// The weight of a flow's steps agrees with the floating-point sum to the
    /// rounding, over steps from none to thousands.
    #[test]
    fn the_mixture_weighs_steps_as_the_floating_point_sum_does() {
        for (a_num, g_num, den) in [(88u64, 19_912u64, 10_000u64), (1, 1, 1), (3, 17, 10)] {
            let m = SnMixture::new(a_num, g_num, den);
            let (a, g) = (a_num as f64 / den as f64, g_num as f64 / den as f64);
            for f in [0u64, 1, 2, 10, 50, 100, 588, 5_000] {
                for b in [0u64, 1, 2, 10, 29, 100, 1_756, 5_000] {
                    let got = m.millibits(f, b);
                    let want = oracle_millibits(a, g, f, b);
                    assert!(
                        (got as f64 - want).abs() <= 0.5 + 1e-3,
                        "Beta({a_num}/{den}, {g_num}/{den}), {f} followed {b} broke: {got} against {want}"
                    );
                }
            }
        }
    }

    #[test]
    fn no_steps_weigh_nothing_and_a_count_beyond_the_cap_does_not_overflow() {
        let m = SnMixture::new(88, 19_912, 10_000);
        assert_eq!(m.millibits(0, 0), 0);
        // Beyond the cap a count is the cap, and nothing overflows.
        assert_eq!(m.millibits(u64::MAX, 0), m.millibits(MAX_STEPS, 0));
        assert_eq!(m.millibits(0, u64::MAX), m.millibits(0, MAX_STEPS));
        let _ = m.millibits(u64::MAX, u64::MAX);
    }

    /// A step that follows weighs about 8 bits whatever the break rate, and a flow of
    /// breaks alone costs far less than the shipped four bits each: the properties
    /// the report of section 6.6 rests on.
    #[test]
    fn the_mixture_has_the_shape_the_report_reads() {
        let m = SnMixture::new(88, 19_912, 10_000);
        assert!(
            m.millibits(100, 0) > 790_000,
            "100 followed: {}",
            m.millibits(100, 0)
        );
        assert!(
            m.millibits(0, 29) > -115_826,
            "29 broke: {}",
            m.millibits(0, 29)
        );
        assert!(
            m.millibits(588, 1_756) > 0,
            "the jitter flow: {}",
            m.millibits(588, 1_756)
        );
        // More followed steps never weigh less.
        let mut last = i64::MIN;
        for f in 0..300u64 {
            let w = m.millibits(f, 10);
            assert!(w >= last, "a followed step lowered the weight at {f}");
            last = w;
        }
    }
}

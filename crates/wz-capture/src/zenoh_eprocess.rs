// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE TERMS OF MODEL 3, in integers (`docs/flow-zenoh-verdict.md` §6.7, §6.8).
//!
//! Each of the test's two sums is the logarithm of an e-process against the
//! hypothesis it rejects: the `yes` sum against "not zenoh", the `no` sum against
//! "zenoh". Each step multiplies it by the chance the OTHER hypothesis gives the
//! outcome, read off a prior fixed in advance ([`Prior`]), over a bound on the
//! largest chance any member of the REJECTED hypothesis gives it, given what the
//! flow showed before ([`log2_null_sup`], [`Region::log2_sup_failure`],
//! [`log2_sn_sup`]). For every member `p` of the rejected hypothesis the product
//! is at most the ratio against `p`, a martingale under `p`, so Ville's
//! inequality bounds the chance that the sum EVER crosses its threshold.
//!
//! Every value is a logarithm in base 2 to 64 fractional bits (`Q64`), from
//! [`crate::zenoh_mixture::log2_q64`], whose error is below `2^-60`. A value
//! carries a bound on its error, [`LOG_ERR_Q64`] for each ratio of logarithms
//! that went into it, and [`floor_millibits`] and [`ceil_millibits`] round it
//! toward the hypothesis its sum rejects past that bound: the integer e-process
//! is never above the real one. A check counts at most [`MAX_COUNT`] outcomes, so
//! the bound stays below a tenth of a millibit.

use crate::zenoh_mixture::{log2_q64, mul_wide};

/// One bit in Q64.
pub const ONE_Q64: i128 = 1 << 64;

/// The fractional bits of a generated rate or concentration.
pub const Q32_BITS: u32 = 32;

/// One in the fixed point of [`Q32_BITS`].
pub const ONE_Q32: u64 = 1 << Q32_BITS;

/// The outcomes a check counts at most: `2^36`, about 7 * 10^10, which no capture
/// holds. Past it the check stops counting, which stops its process, and a
/// stopped e-process is one.
pub const MAX_COUNT: u64 = 1 << 36;

/// What one ratio of two logarithms can be off by, in Q64: `2^-50` bits, far
/// above the `2^-59` the two logarithms can be off by together.
pub const LOG_ERR_Q64: i128 = 1 << 14;

/// `log2(x)` of a positive integer of up to 128 bits, in Q64. Bits below the top
/// 64 are dropped, which moves the logarithm by under `2^-62`.
pub fn log2_wide(x: u128) -> i128 {
    let x = x.max(1);
    let width = 128 - x.leading_zeros();
    if width <= 64 {
        return log2_q64(x as u64) as i128;
    }
    let shift = width - 64;
    log2_q64((x >> shift) as u64) as i128 + (i128::from(shift) << 64)
}

/// `log2(num / den)` in Q64, both positive.
pub fn log2_ratio(num: u128, den: u128) -> i128 {
    log2_wide(num) - log2_wide(den)
}

/// Whether `a_num / a_den > b_num / b_den`, exactly.
fn greater(a_num: u128, a_den: u128, b_num: u128, b_den: u128) -> bool {
    mul_wide(a_num, b_den) > mul_wide(b_num, a_den)
}

/// A Dirichlet prior over the `K` outcomes of a check (a Beta prior when `K` is
/// two), its parameters fractions of one denominator: `alpha_o = num[o] / den`.
/// The chance of a flow's outcomes under it is the product of its predictive
/// chances in turn, `(c_o + alpha_o) / (t + sum alpha)` after `t` outcomes `c_o`
/// of which were `o`, whatever the order: the mixture is exchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prior<const K: usize> {
    /// The numerators, each at least one.
    pub num: [u64; K],
    /// The denominator.
    pub den: u64,
}

impl<const K: usize> Prior<K> {
    /// `log2` of the predictive chance of outcome `o` after `counts`, in Q64.
    pub fn log2_predictive(&self, counts: &[u64; K], o: usize) -> i128 {
        let den = u128::from(self.den);
        let t: u128 = counts.iter().map(|&c| u128::from(c)).sum();
        let total: u128 = self.num.iter().map(|&n| u128::from(n)).sum();
        log2_ratio(
            u128::from(counts[o]) * den + u128::from(self.num[o]),
            t * den + total,
        )
    }
}

/// The largest predictive chance a null member of a measured check gives
/// outcome `o`, after `t` outcomes `count` of which were `o`, in Q64.
///
/// A member's flows have a share of `o` of their own, spread around the member's
/// share `s` with a concentration `kappa` the corpus does not bound; its
/// predictive chance `(count + kappa s) / (t + kappa)` is an average of the flow's
/// own share and `s`, so its largest over every `kappa` and every `s` up to the
/// bound `q` is the larger of `count / t` and `q`. `log2_q` is `log2 q`, the
/// largest bound over the members, rounded up.
pub fn log2_null_sup(log2_q: i128, count: u64, t: u64) -> i128 {
    if count == 0 || t == 0 {
        return log2_q;
    }
    log2_q.max(log2_ratio(u128::from(count), u128::from(t)))
}

/// What the zenoh groups of the corpus allow of one check's failure rate: at
/// each concentration `kappa`, the top `mu(kappa)` of the one-sided 95% region of
/// a group's mean failure rate. `mu` falls as `kappa` grows (a more concentrated
/// Beta of one mean is lower in the convex order, and a clean group is likelier
/// under a wider one), from the bound on groups (`kappa` to zero, groups that
/// fail everything or nothing) to the bound on outcomes (`kappa` to infinity).
///
/// Generated (`zenoh_calibration_tests`), in the fixed point of [`Q32_BITS`],
/// each number rounded the way that raises the chance it bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// `mu` as `kappa` goes to zero: the bound on groups.
    pub groups_bound: u64,
    /// The concentrations `kappa_i` of the grid, rounded down.
    pub kappas: &'static [u64],
    /// Per cell `[kappa_i, kappa_{i+1}]`, `kappa_{i+1} * mu(kappa_i)`, rounded up:
    /// at least `kappa * mu(kappa)` anywhere in the cell. One fewer than
    /// [`Self::kappas`].
    pub cells: &'static [u64],
    /// `mu` at the last concentration of the grid, rounded up.
    pub top: u64,
}

impl Region {
    /// `log2` of a bound on the largest chance a zenoh flow of this region fails
    /// once more, after `t` outcomes `k` of which failed, in Q64.
    ///
    /// A flow's own rate is drawn from a Beta of mean `mu` and concentration
    /// `kappa`, and its predictive chance of a failure is
    /// `(k + kappa mu) / (t + kappa)`. Over the region it is largest at
    /// `mu(kappa)`, and on a cell `kappa mu(kappa)` is at most the cell's bound
    /// while `t + kappa` is at least `t + kappa_i`. Below the grid the chance is at
    /// most `(k + kappa_0 G) / t` with `G` the bound on groups, above it the
    /// average of `k / t` and a rate at most `top`; with nothing seen it is `G`.
    /// A chance is at most one, and the bound is held there.
    pub fn log2_sup_failure(&self, k: u64, t: u64) -> i128 {
        let one = u128::from(ONE_Q32);
        if t == 0 {
            return log2_ratio(u128::from(self.groups_bound), one);
        }
        let (k, t) = (u128::from(k), u128::from(t));
        let below = u128::from(self.kappas.first().copied().unwrap_or(0))
            * u128::from(self.groups_bound)
            / one
            + 1;
        let (mut best_num, mut best_den) = (k * one + below, t * one);
        for (cell, kappa) in self.cells.iter().zip(self.kappas) {
            let (num, den) = (k * one + u128::from(*cell), t * one + u128::from(*kappa));
            if greater(num, den, best_num, best_den) {
                (best_num, best_den) = (num, den);
            }
        }
        if greater(u128::from(self.top), one, best_num, best_den) {
            (best_num, best_den) = (u128::from(self.top), one);
        }
        log2_ratio(best_num, best_den).min(0)
    }
}

/// `log2` of the largest chance any break rate gives a link's SN steps, `follows`
/// that followed and `breaks` that broke, in Q64: the rate is the link's and the
/// zenoh hypothesis leaves it free, so the likeliest is the flow's own share,
/// `f log2(f / n) + b log2(b / n)`.
pub fn log2_sn_sup(follows: u64, breaks: u64) -> i128 {
    let n = u128::from(follows) + u128::from(breaks);
    let log_n = log2_wide(n);
    let part = |c: u64| -> i128 {
        if c == 0 {
            0
        } else {
            i128::from(c) * (log2_wide(u128::from(c)) - log_n)
        }
    };
    part(follows) + part(breaks)
}

/// A value in Q64 bits, off by at most `err`, as whole millibits rounded DOWN
/// past the error: the rounding of a term of the `yes` sum.
pub fn floor_millibits(q64: i128, err: i128) -> i64 {
    let scaled = (q64 - err).saturating_mul(1000) >> 64;
    i64::try_from(scaled).unwrap_or(if scaled < 0 { i64::MIN } else { i64::MAX })
}

/// A value in Q64 bits, off by at most `err`, as whole millibits rounded UP past
/// the error: the rounding of a term of the `no` sum.
pub fn ceil_millibits(q64: i128, err: i128) -> i64 {
    let scaled = -((-(q64 + err)).saturating_mul(1000) >> 64);
    i64::try_from(scaled).unwrap_or(if scaled < 0 { i64::MIN } else { i64::MAX })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const Q: f64 = 18_446_744_073_709_551_616.0;

    fn bits(q64: i128) -> f64 {
        q64 as f64 / Q
    }

    #[test]
    fn the_wide_logarithm_is_the_logarithm() {
        for x in [
            1u128,
            2,
            3,
            1000,
            u128::from(u64::MAX),
            u128::from(u64::MAX) + 1,
            (1u128 << 100) + 12_345,
            u128::MAX,
        ] {
            let want = (x as f64).log2();
            let got = bits(log2_wide(x));
            assert!(
                (got - want).abs() < 1e-12,
                "log2({x}): {got} against {want}"
            );
        }
        assert_eq!(log2_wide(1 << 70), 70 << 64);
    }

    /// The predictive chances of a prior add to one, and their product over a
    /// sequence is the Dirichlet-multinomial chance of it, whatever the order.
    #[test]
    fn a_priors_predictive_chances_are_a_distribution_and_exchangeable() {
        let prior = Prior {
            num: [7, 3, 2],
            den: 10,
        };
        for counts in [[0u64, 0, 0], [5, 0, 1], [100, 7, 0]] {
            let total: f64 = (0..3)
                .map(|o| 2f64.powf(bits(prior.log2_predictive(&counts, o))))
                .sum();
            assert!((total - 1.0).abs() < 1e-12, "{counts:?}: {total}");
        }
        let walk = |order: &[usize]| -> i128 {
            let mut counts = [0u64; 3];
            let mut sum = 0i128;
            for &o in order {
                sum += prior.log2_predictive(&counts, o);
                counts[o] += 1;
            }
            sum
        };
        let a = walk(&[0, 0, 1, 2, 0, 1]);
        let b = walk(&[2, 1, 1, 0, 0, 0]);
        assert!((bits(a) - bits(b)).abs() < 1e-15, "{} {}", bits(a), bits(b));
    }

    /// The SN prior's predictive chances, in turn, come to the mixture
    /// `zenoh_mixture` computes in one step from the counts.
    #[test]
    fn the_predictive_walk_is_the_mixture_of_the_counts() {
        let prior = Prior {
            num: [19_912, 88],
            den: 10_000,
        };
        let mixture = crate::zenoh_mixture::SnMixture::new(88, 19_912, 10_000);
        for (follows, breaks) in [(100u64, 6u64), (588, 1_756), (2_400, 3)] {
            let mut counts = [0u64; 2];
            let mut sum = 0i128;
            // Breaks first, then follows: the order does not matter.
            for o in core::iter::repeat_n(1, breaks as usize)
                .chain(core::iter::repeat_n(0, follows as usize))
            {
                sum += prior.log2_predictive(&counts, o);
                counts[o] += 1;
            }
            let null = -8.0 * follows as f64 + breaks as f64 * (255.0f64 / 256.0).log2();
            let walked = 1000.0 * (bits(sum) - null);
            let joint = mixture.millibits(follows, breaks) as f64;
            assert!(
                (walked - joint).abs() <= 0.5 + 1e-6,
                "{follows}/{breaks}: {walked} against {joint}"
            );
        }
    }

    #[test]
    fn a_null_members_sup_is_the_larger_of_its_bound_and_the_flows_own_share() {
        let q = log2_ratio(1, 4);
        assert_eq!(log2_null_sup(q, 0, 10), q);
        assert_eq!(log2_null_sup(q, 3, 0), q);
        assert_eq!(log2_null_sup(q, 1, 10), q);
        assert_eq!(log2_null_sup(q, 9, 10), log2_ratio(9, 10));
        assert_eq!(log2_null_sup(q, 10, 10), 0);
    }

    /// `mu(kappa)` of a made-up region: falling from `g` at small `kappa` to `i` at
    /// large, as the real ones do.
    fn mu(kappa: f64, g: f64, i: f64) -> f64 {
        i + (g - i) / (1.0 + kappa / 50.0)
    }

    /// A region built from `mu` the way the generator builds one, on a grid of
    /// eight concentrations a decade.
    fn region(g: f64, i: f64) -> Region {
        let kappas: Vec<f64> = (0..=80)
            .map(|j| 10f64.powf(-3.0 + j as f64 / 8.0))
            .collect();
        let q = ONE_Q32 as f64;
        let fixed_down: Vec<u64> = kappas.iter().map(|k| (k * q).floor() as u64).collect();
        let cells: Vec<u64> = kappas
            .windows(2)
            .map(|w| (w[1] * mu(w[0], g, i) * q).ceil() as u64)
            .collect();
        Region {
            groups_bound: (g * q).ceil() as u64,
            kappas: Vec::leak(fixed_down),
            cells: Vec::leak(cells),
            top: (mu(kappas[80], g, i) * q).ceil() as u64,
        }
    }

    /// The bound is never below the predictive chance at any concentration of
    /// a fine grid, and not far above the largest of them.
    #[test]
    fn the_regions_bound_is_above_every_member_and_close_to_the_largest() {
        let (g, i) = (0.127, 6.05e-5);
        let r = region(g, i);
        for (k, t) in [
            (0u64, 0u64),
            (0, 1),
            (0, 10),
            (0, 1_000),
            (1, 1),
            (1, 50),
            (3, 4),
            (5, 5_000),
        ] {
            let got = bits(r.log2_sup_failure(k, t));
            let mut best = f64::NEG_INFINITY;
            for j in 0..=4_000 {
                let kappa = 10f64.powf(-4.0 + j as f64 / 400.0);
                let p = if t == 0 {
                    mu(kappa, g, i)
                } else {
                    (k as f64 + kappa * mu(kappa, g, i)) / (t as f64 + kappa)
                };
                best = best.max(p.log2());
            }
            assert!(got >= best - 1e-12, "{k}/{t}: {got} below {best}");
            assert!(got <= best + 0.45, "{k}/{t}: {got} far above {best}");
            assert!(got <= 0.0);
        }
    }

    #[test]
    fn the_sn_sup_is_the_flows_own_share() {
        for (f, b) in [(0u64, 0u64), (10, 0), (0, 7), (588, 1_756), (2_400, 3)] {
            let n = (f + b) as f64;
            let part = |c: u64| {
                if c == 0 {
                    0.0
                } else {
                    c as f64 * (c as f64 / n).log2()
                }
            };
            let want = part(f) + part(b);
            let got = bits(log2_sn_sup(f, b));
            assert!((got - want).abs() < 1e-9 * (1.0 + want.abs()), "{f}/{b}");
        }
    }

    /// The rounding goes the way it says, past the error, and only by it: a
    /// value known exactly rounds to itself when it is whole.
    #[test]
    fn the_roundings_go_toward_the_rejected_side() {
        assert_eq!(floor_millibits(0, 0), 0);
        assert_eq!(ceil_millibits(0, 0), 0);
        assert_eq!(floor_millibits(-8 * ONE_Q64, 0), -8_000);
        assert_eq!(ceil_millibits(-8 * ONE_Q64, 0), -8_000);
        assert_eq!(floor_millibits(0, 1), -1);
        assert_eq!(ceil_millibits(0, 1), 1);
        for millibits in [-20_000i64, -1, 1, 7_993, 20_000] {
            let half = ONE_Q64 / 2000;
            let mid = i128::from(millibits) * ONE_Q64 / 1000 + half;
            assert_eq!(floor_millibits(mid, half / 2), millibits, "{millibits}");
            assert_eq!(ceil_millibits(mid, half / 2), millibits + 1, "{millibits}");
            assert_eq!(floor_millibits(mid, 2 * half), millibits - 1, "{millibits}");
            assert_eq!(ceil_millibits(mid, 2 * half), millibits + 2, "{millibits}");
        }
    }
}

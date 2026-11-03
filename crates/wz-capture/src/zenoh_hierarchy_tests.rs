// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE ORACLE OF MODEL 3: the floating-point arithmetic the generator computes
//! the model's parameters with (`zenoh_calibration_tests`), and the tests that
//! hold the integer terms of `zenoh_eprocess` to it
//! (`docs/flow-zenoh-verdict.md` §6.5 to §6.8).
//!
//! A zenoh failure rate is a property of a GROUP of captures (a release line, a
//! link, a workload), so a flow's outcomes share a rate drawn from a Beta
//! distribution of mean `mu` and concentration `kappa`: a Beta-binomial. The
//! corpus does not identify `kappa`, so the `no` sum takes the rate at its
//! likeliest over the region the groups leave at 95%, at every `kappa`
//! ([`mean_bound`]). The SN steps' break rate is the link's, a Beta prior fitted
//! on the corpus's links ([`fit_sn`]).
//!
//! The reports that led to the rule (a candidate per concentration, a
//! hierarchical null side, the SN mixture, the corpus read by the rule) compared
//! it with model 2 and were removed when model 3 shipped; what they measured is
//! in the design note.
#![cfg(all(
    feature = "network-codecs",
    feature = "reassembly",
    feature = "compression"
))]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::zenoh_calibration_tests::{read_corpus, Counts, File};

/// `ln Gamma(x)` for `x > 0`: Lanczos (g = 7, nine terms), and the reflection
/// formula below one half, where the Beta function of a tiny rate needs it.
pub(crate) fn ln_gamma(x: f64) -> f64 {
    const G: f64 = 7.0;
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        (core::f64::consts::PI / (core::f64::consts::PI * x).sin()).ln() - ln_gamma(1.0 - x)
    } else {
        let x = x - 1.0;
        let t = x + G + 0.5;
        let mut a = C[0];
        for (i, c) in C.iter().enumerate().skip(1) {
            a += c / (x + i as f64);
        }
        0.5 * (2.0 * core::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
    }
}

fn ln_beta(a: f64, b: f64) -> f64 {
    ln_gamma(a) + ln_gamma(b) - ln_gamma(a + b)
}

/// `P(X <= k)` for `X ~ Binomial(n, p)`, `0 < p < 1`.
fn binomial_cdf(k: u64, n: u64, p: f64) -> f64 {
    let ln_choose = |n: u64, i: u64| {
        ln_gamma(n as f64 + 1.0) - ln_gamma(i as f64 + 1.0) - ln_gamma((n - i) as f64 + 1.0)
    };
    (0..=k)
        .map(|i| (ln_choose(n, i) + i as f64 * p.ln() + (n - i) as f64 * (-p).ln_1p()).exp())
        .sum()
}

/// The exact (Clopper-Pearson) two-sided 95% interval on a share of `k` in `n`:
/// the `p` below which seeing `k` or more has chance at most 2.5%, and the `p`
/// above which seeing `k` or fewer has chance at most 2.5%.
pub(crate) fn exact_interval(k: u64, n: u64) -> (f64, f64) {
    let solve = |below: &dyn Fn(f64) -> bool| {
        let (mut lo, mut hi) = (0.0f64, 1.0f64);
        for _ in 0..200 {
            let mid = (lo + hi) / 2.0;
            if below(mid) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        (lo + hi) / 2.0
    };
    let lower = if k == 0 {
        0.0
    } else {
        solve(&|p| 1.0 - binomial_cdf(k - 1, n, p) < 0.025)
    };
    let upper = if k >= n {
        1.0
    } else {
        solve(&|p| binomial_cdf(k, n, p) > 0.025)
    };
    (lower, upper)
}

/// The one-sided 95% Clopper-Pearson upper bound on a share of `k` in `n`: the
/// `p` at which seeing `k` or fewer has chance 5%.
pub(crate) fn upper_bound(k: u64, n: u64) -> f64 {
    if k >= n {
        return 1.0;
    }
    if k == 0 {
        // The root of `(1 - p)^n = 0.05`; the bisection finds the same number.
        return 1.0 - 0.05f64.powf(1.0 / n as f64);
    }
    let (mut lo, mut hi) = (k as f64 / n as f64, 1.0f64);
    for _ in 0..200 {
        let mid = (lo + hi) / 2.0;
        if binomial_cdf(k, n, mid) > 0.05 {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi
}

/// `ln P` of one sequence of `n` outcomes, `k` of which failed, with a failure
/// `share`: independent outcomes without a `kappa`, a Beta-binomial with one.
pub(crate) fn ln_member(share: f64, kappa: Option<f64>, k: u64, n: u64) -> f64 {
    let share = share.clamp(1e-12, 1.0 - 1e-12);
    match kappa {
        None => k as f64 * share.ln() + (n - k) as f64 * (1.0 - share).ln(),
        Some(c) => {
            let (a, b) = (c * share, c * (1.0 - share));
            ln_beta(a + k as f64, b + (n - k) as f64) - ln_beta(a, b)
        }
    }
}

/// One group of the corpus: its outcomes of a check, and how many failed.
pub(crate) type GroupOutcomes = (u64, u64);

/// One check's outcomes in a flow's or a file's counts: how many, how many failed.
pub(crate) type Kind = fn(&Counts) -> (u64, u64);

fn kind_units(c: &Counts) -> (u64, u64) {
    (c.units.iter().sum(), c.units[1] + c.units[2])
}

fn kind_framing(c: &Counts) -> (u64, u64) {
    (c.framing[0] + c.framing[1], c.framing[1])
}

fn kind_cookie(c: &Counts) -> (u64, u64) {
    (c.cookie[0] + c.cookie[1], c.cookie[1])
}

fn kind_roles(c: &Counts) -> (u64, u64) {
    (c.roles[0] + c.roles[1], c.roles[1])
}

/// The checks whose zenoh failure rate is a property of zenoh (of its release,
/// implementation and workload), and so of the group. The SN steps are not here,
/// since how often they break is the link's, nor the wire's front and the
/// version header, whose zenoh side is derived from the wire (models 4 and 5).
pub(crate) const KINDS: [(&str, Kind); 4] = [
    ("units", kind_units),
    ("framing", kind_framing),
    ("cookie", kind_cookie),
    ("roles", kind_roles),
];

/// The zenoh groups' outcomes of one check, the groups that saw none left out.
pub(crate) fn kind_groups<'a>(
    files: impl Iterator<Item = &'a File>,
    kind: Kind,
) -> Vec<GroupOutcomes> {
    let mut groups: BTreeMap<&str, GroupOutcomes> = BTreeMap::new();
    for f in files.filter(|f| f.zenoh) {
        let (n, k) = kind(&f.counts);
        let slot = groups.entry(f.group.as_str()).or_default();
        slot.0 += n;
        slot.1 += k;
    }
    groups.into_values().filter(|g| g.0 > 0).collect()
}

/// The concentrations of the region's grid: `10^(-3 + i/8)` for `i` from 0 to
/// 80, from groups that fail every outcome or none to independent outcomes.
pub(crate) fn grid_kappas() -> Vec<f64> {
    (0..=80)
        .map(|i| 10f64.powf(-3.0 + i as f64 / 8.0))
        .collect()
}

/// The top of the one-sided 95% region of the mean failure rate of a zenoh group
/// at a concentration, when no group failed: the mean at which the chance that
/// every group reads clean falls to 5%, the upper end of the bisection. It is
/// the Clopper-Pearson bound of a Beta-binomial, and both of its ends are known:
/// the bound on groups when the groups are all-or-nothing, and the bound on
/// outcomes when they are independent.
pub(crate) fn mean_bound(kappa: f64, groups: &[GroupOutcomes]) -> f64 {
    assert!(
        groups.iter().all(|g| g.1 == 0),
        "a zenoh group failed this check: the region needs the general form"
    );
    let ln_clean = |m: f64| -> f64 {
        groups
            .iter()
            .map(|&(n, _)| ln_member(m, Some(kappa), 0, n))
            .sum()
    };
    let target = 0.05f64.ln();
    let (mut lo, mut hi) = (1e-15f64.ln(), (1.0f64 - 1e-12).ln());
    if ln_clean(hi.exp()) >= target {
        return 1.0;
    }
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if ln_clean(mid.exp()) > target {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi.exp()
}

/// The concentrations the SN prior is looked for among.
const SN_KAPPAS: [f64; 15] = [
    0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1_000.0, 10_000.0,
];

/// The break rate of a zenoh link's SN steps as a distribution over links: the
/// Beta prior, as its mean and concentration, that the links' `(followed, broke)`
/// counts make likeliest over a grid of means and of concentrations. Unlike the
/// failure rates this one is measured: the corpus holds links that break no step,
/// 8%, 10%, 37.5% and 75% of them.
pub(crate) fn fit_sn(flows: &[(u64, u64)]) -> (f64, f64) {
    let mut counted: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    for &(f, b) in flows.iter().filter(|&&(f, b)| f + b > 0) {
        *counted.entry((f, b)).or_default() += 1;
    }
    let mut best: Option<(f64, f64, f64)> = None;
    for i in 0..40 {
        let mean = 0.9 * 10f64.powf(-3.0 + 3.0 * i as f64 / 39.0);
        for &kappa in &SN_KAPPAS {
            let ll: f64 = counted
                .iter()
                .map(|(&(f, b), &times)| times as f64 * ln_member(mean, Some(kappa), b, f + b))
                .sum();
            if best.is_none_or(|(top, _, _)| ll > top) {
                best = Some((ll, mean, kappa));
            }
        }
    }
    let (_, mean, kappa) = best.expect("a zenoh flow stepped");
    (mean, kappa)
}

/// The function the model stands on is right, and what it makes of a flow is a
/// distribution: over the `k` failures of `n` outcomes the probabilities add to
/// one.
#[test]
fn a_beta_binomial_is_a_distribution_and_ln_gamma_is_right() {
    for n in 1..=12u64 {
        let want: f64 = (2..n).map(|i| (i as f64).ln()).sum();
        assert!((ln_gamma(n as f64) - want).abs() < 1e-9, "ln Gamma({n})");
    }
    assert!((ln_gamma(0.5) - 0.5 * core::f64::consts::PI.ln()).abs() < 1e-9);
    let ln_choose = |n: u64, k: u64| {
        ln_gamma(n as f64 + 1.0) - ln_gamma(k as f64 + 1.0) - ln_gamma((n - k) as f64 + 1.0)
    };
    for kappa in [None, Some(0.1), Some(2.0), Some(500.0)] {
        let n = 20;
        let total: f64 = (0..=n)
            .map(|k| (ln_choose(n, k) + ln_member(0.3, kappa, k, n)).exp())
            .sum();
        assert!((total - 1.0).abs() < 1e-9, "{kappa:?}: {total}");
    }
}

/// The Clopper-Pearson bound is the closed form where one exists, and the root
/// of its definition where not.
#[test]
fn the_upper_bound_is_the_clopper_pearson_bound() {
    let n = 346;
    let closed = 1.0 - 0.05f64.powf(1.0 / n as f64);
    assert!((upper_bound(0, n) - closed).abs() < 1e-12);
    assert_eq!(upper_bound(5, 5), 1.0);
    let p = upper_bound(3, 40);
    assert!((binomial_cdf(3, 40, p) - 0.05).abs() < 1e-9, "{p}");
}

/// The region's two ends are the bounds the corpus already states: on groups when
/// they are all-or-nothing, on outcomes when they are independent.
#[test]
fn the_region_of_a_zenoh_failure_rate_ends_at_the_two_known_bounds() {
    let files = read_corpus();
    for (name, kind) in KINDS {
        let groups = kind_groups(files.iter(), kind);
        let outcomes: u64 = groups.iter().map(|g| g.0).sum();
        let (small, large) = (mean_bound(1e-3, &groups), mean_bound(1e7, &groups));
        let by_groups = 1.0 - 0.05f64.powf(1.0 / groups.len() as f64);
        let by_outcomes = upper_bound(0, outcomes);
        std::println!(
            "{name}: {} groups, {outcomes} outcomes; bound {small:.4e} at kappa 1e-3 (groups: {by_groups:.4e}), {large:.4e} at 1e7 (outcomes: {by_outcomes:.4e})",
            groups.len()
        );
        assert!(
            (small / by_groups - 1.0).abs() < 0.01,
            "{name}: all-or-nothing end"
        );
        assert!(
            (large / by_outcomes - 1.0).abs() < 0.05,
            "{name}: independent end"
        );
        // The top falls as the concentration grows (a Beta of one mean is lower
        // in the convex order the more concentrated it is), which the cells of
        // the integer region rest on.
        let tops: Vec<f64> = grid_kappas()
            .iter()
            .map(|&c| mean_bound(c, &groups))
            .collect();
        for (i, w) in tops.windows(2).enumerate() {
            assert!(w[1] <= w[0] * (1.0 + 1e-9), "{name}: rises at cell {i}");
        }
    }
}

/// THE GENERATED REGIONS BOUND WHAT THEY CLAIM TO. For each group-rate check
/// and several flows, the integer bound on a failure's largest predictive chance
/// is at least the largest over a fine grid of concentrations, computed in
/// floating point from the corpus's groups, and not far above it.
#[test]
fn the_generated_regions_bound_every_concentration() {
    use crate::zenoh_evidence::model::PARAMS;
    let files = read_corpus();
    let regions = [
        PARAMS.units.region,
        PARAMS.framing.region,
        PARAMS.cookie.region,
        PARAMS.roles.region,
    ];
    let fine: Vec<f64> = (0..=1_000)
        .map(|j| 10f64.powf(-3.5 + j as f64 / 90.0))
        .collect();
    for ((name, kind), region) in KINDS.iter().zip(regions) {
        let groups = kind_groups(files.iter(), *kind);
        let tops: Vec<(f64, f64)> = fine.iter().map(|&c| (c, mean_bound(c, &groups))).collect();
        for (k, t) in [
            (0u64, 0u64),
            (0, 1),
            (0, 30),
            (0, 5_000),
            (1, 1),
            (1, 40),
            (2, 3),
        ] {
            let got = region.log2_sup_failure(k, t) as f64 / 18_446_744_073_709_551_616.0;
            let best = tops
                .iter()
                .map(|&(c, mu)| {
                    if t == 0 {
                        mu
                    } else {
                        (k as f64 + c * mu) / (t as f64 + c)
                    }
                })
                .fold(0.0f64, f64::max)
                .min(1.0)
                .log2();
            assert!(got >= best - 1e-9, "{name} {k}/{t}: {got} below {best}");
            assert!(got <= best + 0.45, "{name} {k}/{t}: {got} far above {best}");
        }
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A CANDIDATE MODEL FOR THE ZENOH UNIT READING, beside the shipped one
//! (`docs/flow-zenoh-verdict.md` §6.5). It ships nothing: `model::MODEL` stays 2.
//!
//! The shipped model gives every unit of a zenoh flow the same chance of failing,
//! the bound the corpus allows, and adds the units up. A flow of `n` units that
//! all read whole therefore weighs `n` times one unit, and a failure always costs
//! the same. That is a model of one population of units. What the corpus has is
//! 22 groups of captures (a release line, a link, a workload), and units of a
//! group share what makes them read well or badly. A workload this reader reads
//! badly fails most of its units, not one in a hundred thousand, and the shipped
//! model prices that as a run of independent rare events: two residual units weigh
//! -25188 on the `no` sum and the flow reads `no`.
//!
//! The candidate gives each GROUP its own failure rate `theta`, drawn from a Beta
//! distribution whose mean `mu` is learned from the groups and whose spread is a
//! concentration `kappa`: a Beta-binomial over the units of a group. A new group's
//! `mu` has the Jeffreys prior and the posterior the 22 groups give it (none of
//! them failed a unit). The weight of a flow of `n` units, `k` of which failed, is
//! the log of its probability under that predictive against its probability under
//! the null, which is the shipped null side (the largest bound for the `yes` sum,
//! the members' average for the `no` sum), so that only the zenoh side moves.
//!
//! `kappa` is the one number the corpus cannot give: with no group failing,
//! how unlike each other the groups' rates are is not measured. The report
//! therefore prints the candidate at several, and the question it answers is how
//! much of the shipped verdict rests on the choice.
//!
//! The null side is NOT made hierarchical here, and that is a gap and not a
//! virtue: a null protocol's units cluster as well, and a null flow whose units
//! read whole in a run is likelier than independent units say.
#![cfg(all(
    feature = "network-codecs",
    feature = "reassembly",
    feature = "compression"
))]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::zenoh_calibration_tests::{read_corpus, File};
use crate::zenoh_evidence::model;
use crate::zenoh_evidence::tests as fit;

/// `ln Gamma(x)` for `x > 0`: Lanczos (g = 7, nine terms), and the reflection
/// formula below one half, where the Beta function of a tiny rate needs it.
fn ln_gamma(x: f64) -> f64 {
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

fn log_sum_exp(xs: &[f64]) -> f64 {
    let top = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    top + xs.iter().map(|x| (x - top).exp()).sum::<f64>().ln()
}

/// Points of the grid the mean rate `mu` is integrated over. `mu = sin^2(phi)` with
/// `phi` uniform is the Jeffreys prior, and a grid in `phi` resolves rates down to
/// about 1e-8.
const GRID: usize = 6_000;

/// One group of the corpus: its units, and how many of them failed.
type GroupUnits = (u64, u64);

/// The posterior of the mean failure rate given the zenoh groups, at a
/// concentration.
struct Hierarchy {
    kappa: f64,
    mu: Vec<f64>,
    /// Log of the normalised posterior weight of each grid point.
    logw: Vec<f64>,
}

impl Hierarchy {
    fn fit(kappa: f64, groups: &[GroupUnits]) -> Hierarchy {
        let mut mu = Vec::with_capacity(GRID);
        let mut logw = Vec::with_capacity(GRID);
        for i in 0..GRID {
            let phi = (i as f64 + 0.5) * core::f64::consts::FRAC_PI_2 / GRID as f64;
            let m = phi.sin().powi(2);
            let (a, b) = (kappa * m, kappa * (1.0 - m));
            let ll: f64 = groups
                .iter()
                .map(|&(n, f)| ln_beta(a + f as f64, b + (n - f) as f64) - ln_beta(a, b))
                .sum();
            mu.push(m);
            logw.push(ll);
        }
        let norm = log_sum_exp(&logw);
        for w in &mut logw {
            *w -= norm;
        }
        Hierarchy { kappa, mu, logw }
    }

    /// The mean failure rate of a new group.
    fn mean_rate(&self) -> f64 {
        self.mu
            .iter()
            .zip(&self.logw)
            .map(|(m, w)| m * w.exp())
            .sum()
    }

    /// `ln P` of one sequence of `n` units of a new group, `k` of which failed.
    fn ln_predictive(&self, k: u64, n: u64) -> f64 {
        let terms: Vec<f64> = self
            .mu
            .iter()
            .zip(&self.logw)
            .map(|(&m, &w)| {
                let (a, b) = (self.kappa * m, self.kappa * (1.0 - m));
                w + ln_beta(a + k as f64, b + (n - k) as f64) - ln_beta(a, b)
            })
            .collect();
        log_sum_exp(&terms)
    }
}

/// The null side of the unit reading, as the shipped model has it, read as two
/// outcomes: a unit read whole, and a unit that did not.
struct Null {
    /// The largest bound of a null member's share read whole, and not read whole.
    explained_yes: f64,
    failed_yes: f64,
    /// The members' average Jeffreys share read whole.
    explained_no: f64,
}

fn null_side(files: &[File]) -> Null {
    let seen: Vec<[u64; 3]> = files
        .iter()
        .filter(|f| !f.zenoh)
        .map(|f| f.counts.units)
        .filter(|u| u.iter().sum::<u64>() > 0)
        .collect();
    let total = |u: &[u64; 3]| u.iter().sum::<u64>();
    Null {
        explained_yes: seen
            .iter()
            .map(|u| fit::upper_bound(u[0], total(u)))
            .fold(0.0, f64::max),
        failed_yes: seen
            .iter()
            .map(|u| fit::upper_bound(u[1] + u[2], total(u)))
            .fold(0.0, f64::max),
        explained_no: seen
            .iter()
            .map(|u| (u[0] as f64 + 0.5) / (total(u) as f64 + 1.5))
            .sum::<f64>()
            / seen.len() as f64,
    }
}

/// The zenoh groups' units: how many each holds, and how many failed.
fn zenoh_groups(files: &[File]) -> Vec<GroupUnits> {
    let mut groups: BTreeMap<&str, GroupUnits> = BTreeMap::new();
    for f in files.iter().filter(|f| f.zenoh) {
        let slot = groups.entry(f.group.as_str()).or_default();
        slot.0 += f.counts.units.iter().sum::<u64>();
        slot.1 += f.counts.units[1] + f.counts.units[2];
    }
    groups.into_values().collect()
}

fn millibits(bits: f64) -> i64 {
    (1000.0 * bits).round() as i64
}

/// A flow of `n` units, `k` of which failed, under the candidate: the `yes` and
/// the `no` sum in millibits.
fn candidate(h: &Hierarchy, null: &Null, k: u64, n: u64) -> (i64, i64) {
    let p1 = h.ln_predictive(k, n) / core::f64::consts::LN_2;
    let (whole, failed) = ((n - k) as f64, k as f64);
    let yes = p1 - whole * null.explained_yes.log2() - failed * null.failed_yes.log2();
    let no = p1 - whole * null.explained_no.log2() - failed * (1.0 - null.explained_no).log2();
    (millibits(yes), millibits(no))
}

/// The same flow under the shipped model, a failure read as a residual unit.
fn shipped(k: u64, n: u64) -> (i64, i64) {
    let (whole, failed) = ((n - k) as i64, k as i64);
    (
        whole * model::UNIT_EXPLAINED.yes + failed * model::UNIT_RESIDUAL.yes,
        whole * model::UNIT_EXPLAINED.no + failed * model::UNIT_RESIDUAL.no,
    )
}

fn word(yes: i64, no: i64) -> &'static str {
    match (yes >= model::YES_AT, no <= model::NO_AT) {
        (true, false) => "yes",
        (false, true) => "no",
        _ => "undecided",
    }
}

/// The concentrations a null member's spread is looked for among.
const KAPPAS: [f64; 15] = [
    0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1_000.0, 10_000.0,
];

/// The fewest flows with units a null member needs for its spread to be
/// estimated from them. Fewer, and it has none: the `yes` sum takes a spread of
/// 1, the widest the grid's middle allows and the cautious side for a false
/// `yes`, and the `no` sum takes independent units, the cautious side for a
/// false `no`.
const FLOWS_TO_ESTIMATE: usize = 5;

/// One null protocol as a Beta-binomial over the units of its flows: the share of
/// its units that fail, and how much its flows differ in it.
struct NullMember {
    file: alloc::string::String,
    /// Flows that framed at least one unit.
    flows: usize,
    units: u64,
    /// The share failing, for the `no` sum (Jeffreys) and for the `yes` sum (the
    /// least the explained share's upper bound leaves).
    no_share: f64,
    yes_share: f64,
    /// The spread estimated from the member's flows.
    kappa: Option<f64>,
}

/// `ln P` of one sequence of `n` units, `k` of which failed, in a flow of a
/// member with a failure `share`: independent units without a `kappa`, a
/// Beta-binomial with one.
fn ln_member(share: f64, kappa: Option<f64>, k: u64, n: u64) -> f64 {
    let share = share.clamp(1e-12, 1.0 - 1e-12);
    match kappa {
        None => k as f64 * share.ln() + (n - k) as f64 * (1.0 - share).ln(),
        Some(c) => {
            let (a, b) = (c * share, c * (1.0 - share));
            ln_beta(a + k as f64, b + (n - k) as f64) - ln_beta(a, b)
        }
    }
}

/// The null members of the corpus: those that framed a unit, with the spread of
/// each estimated from its flows by the concentration of the grid that makes
/// them likeliest.
fn null_members(files: &[File]) -> Vec<NullMember> {
    let mut members = Vec::new();
    for f in files.iter().filter(|f| !f.zenoh) {
        let flows: Vec<(u64, u64)> = f
            .flows
            .iter()
            .map(|flow| {
                let u = flow.counts.units;
                (u[1] + u[2], u.iter().sum::<u64>())
            })
            .filter(|&(_, n)| n > 0)
            .collect();
        let units: u64 = flows.iter().map(|&(_, n)| n).sum();
        if units == 0 {
            continue;
        }
        let failed: u64 = flows.iter().map(|&(k, _)| k).sum();
        let no_share = (failed as f64 + 0.5) / (units as f64 + 1.0);
        let yes_share = 1.0 - fit::upper_bound(units - failed, units);
        let kappa = if flows.len() < FLOWS_TO_ESTIMATE {
            None
        } else {
            let likelihood = |c: f64| -> f64 {
                flows
                    .iter()
                    .map(|&(k, n)| ln_member(no_share, Some(c), k, n))
                    .sum()
            };
            KAPPAS
                .iter()
                .copied()
                .fold(None::<(f64, f64)>, |best, c| {
                    let l = likelihood(c);
                    match best {
                        Some((_, bl)) if bl >= l => best,
                        _ => Some((c, l)),
                    }
                })
                .map(|(c, _)| c)
        };
        members.push(NullMember {
            file: f.name.clone(),
            flows: flows.len(),
            units,
            no_share,
            yes_share,
            kappa,
        });
    }
    members
}

/// A flow of `n` units, `k` of which failed, with the zenoh side of `h` and the
/// null side a rate per protocol: the `yes` sum against the likeliest member, the
/// `no` sum against the members' average, in millibits.
fn candidate_both(h: &Hierarchy, members: &[NullMember], k: u64, n: u64) -> (i64, i64) {
    let p1 = h.ln_predictive(k, n);
    let yes_null = members
        .iter()
        .map(|m| ln_member(m.yes_share, Some(m.kappa.unwrap_or(1.0)), k, n))
        .fold(f64::NEG_INFINITY, f64::max);
    let each: Vec<f64> = members
        .iter()
        .map(|m| ln_member(m.no_share, m.kappa, k, n))
        .collect();
    let no_null = log_sum_exp(&each) - (members.len() as f64).ln();
    (
        millibits((p1 - yes_null) / core::f64::consts::LN_2),
        millibits((p1 - no_null) / core::f64::consts::LN_2),
    )
}

/// A null member's flow is a distribution too: over the failures of `n` units its
/// probabilities add to one, with a spread and without.
#[test]
fn a_null_members_flow_is_a_distribution() {
    let ln_choose = |n: u64, k: u64| {
        ln_gamma(n as f64 + 1.0) - ln_gamma(k as f64 + 1.0) - ln_gamma((n - k) as f64 + 1.0)
    };
    for kappa in [None, Some(0.3), Some(3.0), Some(300.0)] {
        for share in [0.05, 0.5, 0.9] {
            let n = 15;
            let total: f64 = (0..=n)
                .map(|k| (ln_choose(n, k) + ln_member(share, kappa, k, n)).exp())
                .sum();
            assert!(
                (total - 1.0).abs() < 1e-9,
                "share {share}, kappa {kappa:?}: adds to {total}"
            );
        }
    }
}

/// THE REPORT WITH A HIERARCHICAL NULL SIDE: each null protocol has its own spread,
/// estimated from its flows, and the zenoh side is the candidate of the report
/// above at several concentrations. The question is whether the `no` that the
/// candidate lost with an independent null comes back. Printed; the words are not
/// asserted.
#[test]
fn the_corpus_read_with_a_hierarchical_null_side_too() {
    let files = read_corpus();
    let members = null_members(&files);
    let groups = zenoh_groups(&files);
    std::println!("null member | flows with units | units | failing share | spread");
    for m in &members {
        std::println!(
            "{} | {} | {} | {:.3} | {}",
            m.file,
            m.flows,
            m.units,
            m.no_share,
            m.kappa
                .map_or_else(|| String::from("not estimated"), |c| alloc::format!("{c}"))
        );
    }
    for kappa in [1.0, 16.0, 1.0e6] {
        let h = Hierarchy::fit(kappa, &groups);
        let mut cache: BTreeMap<(u64, u64), (i64, i64)> = BTreeMap::new();
        let mut moved: BTreeMap<(String, &str, &str), u64> = BTreeMap::new();
        let mut tally = [[0u64; 3]; 4];
        for f in &files {
            for flow in &f.flows {
                let u = flow.counts.units;
                let (k, n) = (u[1] + u[2], u.iter().sum::<u64>());
                let (cy, cn) = *cache
                    .entry((k, n))
                    .or_insert_with(|| candidate_both(&h, &members, k, n));
                let (sy, sn) = shipped_unit_part(&u);
                let (y, no) = (flow.yes - sy + cy, flow.no - sn + cn);
                let (was, now) = (word(flow.yes, flow.no), word(y, no));
                let slot = |w: &str| match w {
                    "yes" => 0,
                    "no" => 1,
                    _ => 2,
                };
                let side = if f.zenoh { 0 } else { 2 };
                tally[side][slot(was)] += 1;
                tally[side + 1][slot(now)] += 1;
                if was != now {
                    *moved.entry((f.group.clone(), was, now)).or_default() += 1;
                }
                if f.zenoh && now == "no" {
                    // A zenoh flow read `no`: what it holds, and what its sums were.
                    std::println!(
                        "  ZENOH FLOW READ NO in {}: units {:?}, SN steps followed/broke {:?}; sums shipped {} / {}, now {y} / {no}; its unit part shipped {sy} / {sn}, now {cy} / {cn}",
                        f.name, u, flow.counts.sn, flow.yes, flow.no
                    );
                }
            }
        }
        std::println!(
            "kappa {kappa}: zenoh flows shipped {:?} both-hierarchical {:?} | null flows shipped {:?} both-hierarchical {:?}  (yes, no, undecided)",
            tally[0], tally[1], tally[2], tally[3]
        );
        for ((group, was, now), flows) in &moved {
            std::println!("    {group}: {was} -> {now} in {flows} flow(s)");
        }
        for n in [2u64, 10, 40, 531] {
            let (y, no) = candidate_both(&h, &members, n, n);
            std::println!(
                "  every one of {n} units failed: {y} / {no} {}",
                word(y, no)
            );
        }
    }
}

/// The break rate of a zenoh flow's SN steps as a distribution over links: a flow
/// has a rate of its own, drawn from a Beta distribution of this mean and
/// concentration. Unlike the units' failure rate this one is measured: the corpus
/// holds links that break no step, 8%, 10%, 37.5% and 75% of them.
struct SnPrior {
    mean: f64,
    kappa: f64,
}

/// The prior the flows' `(followed, broke)` counts make likeliest, over a grid of
/// means and of concentrations.
fn fit_sn(flows: &[(u64, u64)]) -> SnPrior {
    let mut counted: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    for &(f, b) in flows.iter().filter(|&&(f, b)| f + b > 0) {
        *counted.entry((f, b)).or_default() += 1;
    }
    let mut best: Option<(f64, f64, f64)> = None;
    for i in 0..40 {
        let mean = 0.9 * 10f64.powf(-3.0 + 3.0 * i as f64 / 39.0);
        for &kappa in &KAPPAS {
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
    SnPrior { mean, kappa }
}

/// What a flow's SN steps weigh under the mixture, in millibits, on both sums: the
/// probability of the steps under the prior against the null's, which is the
/// shipped one (a step follows with chance at most 2^-8, as a varint).
fn sn_mixture(p: &SnPrior, follows: u64, breaks: u64) -> i64 {
    let n = follows + breaks;
    if n == 0 {
        return 0;
    }
    let p1 = ln_member(p.mean, Some(p.kappa), breaks, n) / core::f64::consts::LN_2;
    let null = -8.0 * follows as f64 + breaks as f64 * (1.0 - 2f64.powi(-8)).log2();
    millibits(p1 - null)
}

/// The same steps under the shipped weights.
fn sn_shipped(follows: u64, breaks: u64) -> i64 {
    follows as i64 * model::SN_FOLLOWS.yes + breaks as i64 * model::SN_BREAKS.yes
}

/// THE SN STEPS AS A MIXTURE, with the units of the report above or the shipped
/// ones. Every zenoh flow is read with the prior fitted WITHOUT its own group, so
/// that a link is not judged by a prior that has seen it. Printed; the words are
/// not asserted.
#[test]
fn the_sn_steps_as_a_mixture_over_the_links_break_rate() {
    let files = read_corpus();
    let members = null_members(&files);
    let groups = zenoh_groups(&files);
    let steps_of = |skip: Option<&str>| -> Vec<(u64, u64)> {
        files
            .iter()
            .filter(|f| f.zenoh && skip.is_none_or(|g| f.group != g))
            .flat_map(|f| f.flows.iter().map(|fl| (fl.counts.sn[0], fl.counts.sn[1])))
            .collect()
    };
    let all = fit_sn(&steps_of(None));
    let no_jitter = fit_sn(&steps_of(Some("jitter")));
    std::println!(
        "SN break rate prior from every zenoh flow: mean {:.4}, kappa {}; without the jitter group: mean {:.4}, kappa {}",
        all.mean, all.kappa, no_jitter.mean, no_jitter.kappa
    );
    for (f, b) in [
        (100u64, 0u64),
        (100, 6),
        (50, 50),
        (10, 10),
        (0, 20),
        (588, 1756),
        (0, 29),
    ] {
        std::println!(
            "  SN {f} followed, {b} broke: shipped {} | mixture {} (jitter left out of the fit: {})",
            sn_shipped(f, b),
            sn_mixture(&all, f, b),
            sn_mixture(&no_jitter, f, b)
        );
    }
    // One prior per zenoh group, fitted without it.
    let zenoh_groups_named: alloc::collections::BTreeSet<&str> = files
        .iter()
        .filter(|f| f.zenoh)
        .map(|f| f.group.as_str())
        .collect();
    let mut left_out: BTreeMap<&str, SnPrior> = BTreeMap::new();
    for g in &zenoh_groups_named {
        left_out.insert(g, fit_sn(&steps_of(Some(g))));
    }
    for kappa in [1.0, 16.0, 1.0e6] {
        let h = Hierarchy::fit(kappa, &groups);
        let mut cache: BTreeMap<(u64, u64), (i64, i64)> = BTreeMap::new();
        for with_units in [false, true] {
            let mut moved: BTreeMap<(String, &str, &str), u64> = BTreeMap::new();
            let mut tally = [[0u64; 3]; 4];
            for f in &files {
                for flow in &f.flows {
                    let u = flow.counts.units;
                    let (k, n) = (u[1] + u[2], u.iter().sum::<u64>());
                    let prior = if f.zenoh {
                        &left_out[f.group.as_str()]
                    } else {
                        &all
                    };
                    let (fol, brk) = (flow.counts.sn[0], flow.counts.sn[1]);
                    let (mut y, mut no) = (flow.yes, flow.no);
                    let sn = sn_mixture(prior, fol, brk) - sn_shipped(fol, brk);
                    y += sn;
                    no += sn;
                    if with_units {
                        let (cy, cn) = *cache
                            .entry((k, n))
                            .or_insert_with(|| candidate_both(&h, &members, k, n));
                        let (sy, sn_units) = shipped_unit_part(&u);
                        y += cy - sy;
                        no += cn - sn_units;
                    }
                    let (was, now) = (word(flow.yes, flow.no), word(y, no));
                    let slot = |w: &str| match w {
                        "yes" => 0,
                        "no" => 1,
                        _ => 2,
                    };
                    let side = if f.zenoh { 0 } else { 2 };
                    tally[side][slot(was)] += 1;
                    tally[side + 1][slot(now)] += 1;
                    if was != now {
                        *moved.entry((f.group.clone(), was, now)).or_default() += 1;
                    }
                    if f.zenoh && now != "yes" {
                        std::println!(
                            "  ZENOH FLOW READ {now} in {}: units {u:?}, SN {fol} followed {brk} broke; sums shipped {} / {}, now {y} / {no}",
                            f.name, flow.yes, flow.no
                        );
                    }
                }
            }
            std::println!(
                "kappa {kappa}, {}: zenoh flows shipped {:?} now {:?} | null flows shipped {:?} now {:?}  (yes, no, undecided)",
                if with_units { "SN mixture and units" } else { "SN mixture, shipped units" },
                tally[0], tally[1], tally[2], tally[3]
            );
            for ((group, was, now), flows) in &moved {
                std::println!("    {group}: {was} -> {now} in {flows} flow(s)");
            }
        }
    }
}

/// The function the model stands on is right, and what it makes of a flow is a
/// distribution: over the `k` failures of `n` units the probabilities add to one.
#[test]
fn the_predictive_is_a_distribution_and_ln_gamma_is_right() {
    for n in 1..=12u64 {
        let want: f64 = (2..n).map(|i| (i as f64).ln()).sum();
        assert!((ln_gamma(n as f64) - want).abs() < 1e-9, "ln Gamma({n})");
    }
    assert!((ln_gamma(0.5) - 0.5 * core::f64::consts::PI.ln()).abs() < 1e-9);
    let ln_choose = |n: u64, k: u64| {
        ln_gamma(n as f64 + 1.0) - ln_gamma(k as f64 + 1.0) - ln_gamma((n - k) as f64 + 1.0)
    };
    // Groups that DO fail, so that the posterior is not at the edge of its range.
    let groups = [(100, 0), (50, 1), (30, 6), (200, 0)];
    for kappa in [1.0, 4.0, 64.0] {
        let h = Hierarchy::fit(kappa, &groups);
        let n = 20;
        let total: f64 = (0..=n)
            .map(|k| (ln_choose(n, k) + h.ln_predictive(k, n)).exp())
            .sum();
        assert!(
            (total - 1.0).abs() < 1e-3,
            "kappa {kappa}: the predictive adds to {total}"
        );
    }
}

/// THE REPORT: the candidate at several concentrations against the shipped model,
/// on a flow of `n` units with `k` failures. Printed (`--nocapture`); what it
/// holds are the properties that need no judgement: a failure never raises a sum,
/// and a flow with no failure never weighs less than one with some.
#[test]
fn the_hierarchical_unit_model_against_the_shipped_one() {
    let files = read_corpus();
    let null = null_side(&files);
    let groups = zenoh_groups(&files);
    let units: u64 = groups.iter().map(|g| g.0).sum();
    let failed: u64 = groups.iter().map(|g| g.1).sum();
    std::println!(
        "zenoh groups {}, units {units}, failed {failed}; null: explained yes {:.3}, failed yes {:.3}, explained no {:.3}",
        groups.len(),
        null.explained_yes,
        null.failed_yes,
        null.explained_no
    );
    std::println!(
        "shipped: a unit read whole {} / {}, a failure {} / {}",
        model::UNIT_EXPLAINED.yes,
        model::UNIT_EXPLAINED.no,
        model::UNIT_RESIDUAL.yes,
        model::UNIT_RESIDUAL.no
    );
    for kappa in [1.0, 4.0, 16.0, 64.0, 1.0e6] {
        let h = Hierarchy::fit(kappa, &groups);
        let to_yes = (1..=400u64)
            .find(|&n| candidate(&h, &null, 0, n).0 >= model::YES_AT)
            .map_or_else(|| String::from(">400"), |n| alloc::format!("{n}"));
        let shipped_to_yes = (1..=400u64)
            .find(|&n| shipped(0, n).0 >= model::YES_AT)
            .map_or_else(|| String::from(">400"), |n| alloc::format!("{n}"));
        std::println!(
            "kappa {kappa}: a new group's mean failure rate {:.2e}; units to yes with none failing {to_yes} (shipped {shipped_to_yes})",
            h.mean_rate()
        );
        for n in [40u64, 200] {
            let mut last = (i64::MAX, i64::MAX);
            for k in 0..=4u64 {
                let (y, no) = candidate(&h, &null, k, n);
                let (sy, sn) = shipped(k, n);
                std::println!(
                    "  n={n} k={k}: candidate {y} / {no} {} | shipped {sy} / {sn} {}",
                    word(y, no),
                    word(sy, sn)
                );
                assert!(y <= last.0 && no <= last.1, "a failure raised a sum");
                last = (y, no);
            }
        }
        // Flows in which every unit failed: what the `no` word rests on.
        for n in [2u64, 10, 40, 531] {
            let (y, no) = candidate(&h, &null, n, n);
            let (sy, sn) = shipped(n, n);
            std::println!(
                "  every one of {n} units failed: candidate {y} / {no} {} | shipped {sy} / {sn} {}",
                word(y, no),
                word(sy, sn)
            );
        }
    }
}

/// The shipped model's contribution of a flow's units to its two sums.
fn shipped_unit_part(units: &[u64; 3]) -> (i64, i64) {
    let weights = [
        model::UNIT_EXPLAINED,
        model::UNIT_RESIDUAL,
        model::UNIT_UNDECODED,
    ];
    units
        .iter()
        .zip(weights)
        .fold((0, 0), |(y, n), (&count, w)| {
            let count = count as i64;
            (y + count * w.yes, n + count * w.no)
        })
}

/// THE CORPUS READ WITH THE CANDIDATE: every flow's sums with its unit part
/// replaced by the candidate's (the other checks are the shipped ones), at several
/// concentrations, against the words the shipped model gives. Printed, and it
/// asserts nothing about the words: whether a different word is wrong is for the
/// reader of the report to say.
#[test]
fn the_corpus_read_with_the_candidate_against_the_shipped_words() {
    let files = read_corpus();
    let null = null_side(&files);
    let groups = zenoh_groups(&files);
    for kappa in [1.0, 16.0, 1.0e6] {
        let h = Hierarchy::fit(kappa, &groups);
        let mut cache: BTreeMap<(u64, u64), (i64, i64)> = BTreeMap::new();
        // (group, shipped word, candidate word) -> flows
        let mut moved: BTreeMap<(String, &str, &str), u64> = BTreeMap::new();
        let mut tally = [[0u64; 3]; 4];
        let mut unfailed_moved = 0u64;
        for f in &files {
            for flow in &f.flows {
                let u = flow.counts.units;
                let (k, n) = (u[1] + u[2], u.iter().sum::<u64>());
                let (cy, cn) = *cache
                    .entry((k, n))
                    .or_insert_with(|| candidate(&h, &null, k, n));
                let (sy, sn) = shipped_unit_part(&u);
                let (y, no) = (flow.yes - sy + cy, flow.no - sn + cn);
                let (was, now) = (word(flow.yes, flow.no), word(y, no));
                let slot = |w: &str| match w {
                    "yes" => 0,
                    "no" => 1,
                    _ => 2,
                };
                let side = if f.zenoh { 0 } else { 2 };
                tally[side][slot(was)] += 1;
                tally[side + 1][slot(now)] += 1;
                if was != now {
                    *moved.entry((f.group.clone(), was, now)).or_default() += 1;
                }
                if k == 0 && was != now {
                    // A flow on the edge of a threshold, which a few millibits move.
                    unfailed_moved += 1;
                }
            }
        }
        std::println!("  flows with no failed unit whose word moved: {unfailed_moved}");
        std::println!(
            "kappa {kappa}: zenoh flows shipped {:?} candidate {:?} | null flows shipped {:?} candidate {:?}  (yes, no, undecided)",
            tally[0], tally[1], tally[2], tally[3]
        );
        for ((group, was, now), flows) in &moved {
            std::println!("    {group}: {was} -> {now} in {flows} flow(s)");
        }
    }
}

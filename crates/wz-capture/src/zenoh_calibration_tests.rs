// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE CALIBRATION: model 3's parameters computed from `captures/corpus/`, the
//! file they are written to, and how far they hold on captures that were left
//! out of them (`docs/flow-zenoh-verdict.md` §6.3, §6.8).
//!
//! The corpus test (`zenoh_corpus_tests`) reads every file with parameters that
//! were computed from every file. That is a fit, not a validation: a protocol
//! that is in the null family sets the family's largest chance of an outcome,
//! so its own flows are weighed against a bound it helped to make. This module
//! leaves one GROUP out at a time, computes the parameters again from the rest,
//! and reads the left-out flows with them, observation by observation as the
//! reader made them ([`ZenohEvidence::replayed_with`]).
//!
//! The group is the unit that is independent of the others, which a flow is
//! not: the units of one session share a stack, a traffic generator and a
//! link. A null protocol is a group of its own. A zenoh file is in the group
//! of its release line, of its link (loss, reordering, jitter, a tunnel, a
//! real Wi-Fi), or of what it exercises (compression, handshakes); the `groups`
//! of `captures/corpus/corpus.json5` says which, and the manifest reader refuses
//! a file in no group or in two.
//!
//! The tests are of the build that opens lz4 (`--features compression`). A build
//! that cannot counts the one batch it cannot open as a unit and does not weigh
//! it, so its counts are not the calibration's: they are not compiled in it.
#![cfg(all(
    feature = "network-codecs",
    feature = "reassembly",
    feature = "compression"
))]

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::zenoh_corpus_tests::{corpus_dir, manifest};
use crate::zenoh_eprocess::{Prior, Region, ONE_Q32};
use crate::zenoh_evidence::model::{self, Derived, Front, Measured, Params};
use crate::zenoh_evidence::{Check, ZenohEvidence};
use crate::zenoh_hierarchy_tests::{
    fit_sn, grid_kappas, kind_groups, mean_bound, upper_bound, GroupOutcomes, KINDS,
};
use crate::Dissection;

/// The outcomes of a flow, or of a file.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Counts {
    /// Framing units read whole, residual, undecoded.
    pub(crate) units: [u64; 3],
    /// Stream directions whose framing held, or was lost first.
    pub(crate) framing: [u64; 2],
    /// Cookie echoes matched, differing.
    pub(crate) cookie: [u64; 2],
    /// Init pairs of opposite kinds, of one kind.
    pub(crate) roles: [u64; 2],
    /// Version headers of this reader's version, of another.
    pub(crate) versions: [u64; 2],
    /// SN steps that followed, that broke.
    pub(crate) sn: [u64; 2],
    /// Datagram fronts of this wire, foreign.
    pub(crate) front: [u64; 2],
}

impl Counts {
    fn and(&mut self, other: &Counts) {
        let add = |a: &mut [u64], b: &[u64]| {
            for (x, y) in a.iter_mut().zip(b) {
                *x += y;
            }
        };
        add(&mut self.units, &other.units);
        add(&mut self.framing, &other.framing);
        add(&mut self.cookie, &other.cookie);
        add(&mut self.roles, &other.roles);
        add(&mut self.versions, &other.versions);
        add(&mut self.sn, &other.sn);
        add(&mut self.front, &other.front);
    }
}

/// One flow: its outcomes and the evidence the library gave it.
pub(crate) struct Flow {
    pub(crate) counts: Counts,
    pub(crate) evidence: ZenohEvidence,
    /// It is a stream flow, not a datagram one.
    pub(crate) stream: bool,
}

/// One file of the corpus, read.
pub(crate) struct File {
    pub(crate) name: String,
    pub(crate) zenoh: bool,
    pub(crate) group: String,
    pub(crate) flows: Vec<Flow>,
    pub(crate) counts: Counts,
}

fn flows_of(d: &Dissection) -> Vec<Flow> {
    let mut out = Vec::new();
    // The unit readings are the ones the test weighed: a datagram whose front
    // was foreign is weighed by its front, and its reading is not (model 4).
    let mut push = |e: ZenohEvidence, stream: bool| {
        let t = |check| e.tally(check);
        let pair = |check| [t(check).confirmed, t(check).violated];
        out.push(Flow {
            counts: Counts {
                units: e.unit_outcomes(),
                framing: pair(Check::StreamFraming),
                cookie: pair(Check::CookieEcho),
                roles: pair(Check::InitRoles),
                versions: pair(Check::VersionHeader),
                sn: pair(Check::SnFollows),
                front: pair(Check::WireFront),
            },
            evidence: e,
            stream,
        });
    };
    for f in d.flows() {
        push(f.zenoh_evidence(), true);
    }
    for f in d.datagram_flows() {
        push(f.zenoh_evidence(), false);
    }
    out
}

pub(crate) fn read_corpus() -> Vec<File> {
    manifest()
        .into_iter()
        .map(|entry| {
            let bytes = std::fs::read(corpus_dir().join(&entry.file))
                .unwrap_or_else(|e| panic!("{}: {e}", entry.file));
            // Every observation kept, so that a flow can be read again with
            // other parameters.
            let d = crate::zenoh_evidence::recording(|| Dissection::from_capture(&bytes))
                .unwrap_or_else(|e| panic!("{}: the capture reads: {e:?}", entry.file));
            let flows = flows_of(&d);
            let mut counts = Counts::default();
            for f in &flows {
                counts.and(&f.counts);
            }
            let zenoh = entry.hypothesis == "zenoh";
            File {
                group: entry.group,
                name: entry.file,
                zenoh,
                flows,
                counts,
            }
        })
        .collect()
}

/// The denominator of the zenoh priors of the group-rate checks.
const PRIOR_DEN: u64 = 1_000_000_000;

/// The denominator of the SN prior.
const SN_DEN: u64 = 10_000;

/// `2^-40` bits in Q64, the margin a logarithm computed in floating point is
/// moved by, far above its error.
const FLOAT_MARGIN_Q64: i128 = 1 << 24;

/// `log2 x` in Q64, rounded up past the margin.
fn log2_up(x: f64) -> i128 {
    (x.log2() * 18_446_744_073_709_551_616.0) as i128 + FLOAT_MARGIN_Q64
}

/// `log2 x` in Q64, rounded down past the margin.
fn log2_down(x: f64) -> i128 {
    (x.log2() * 18_446_744_073_709_551_616.0) as i128 - FLOAT_MARGIN_Q64
}

/// A prior of weight one outcome centred on the Jeffreys estimate of the zenoh
/// files' shares, `(c + 1/2) / (n + K/2)`: what the `yes` sum mixes a zenoh flow's
/// own shares over.
fn zenoh_prior<const K: usize>(counts: [u64; K]) -> Prior<K> {
    let n: u64 = counts.iter().sum();
    let mut num = [0u64; K];
    for o in 1..K {
        let share = (counts[o] as f64 + 0.5) / (n as f64 + K as f64 / 2.0);
        num[o] = ((share * PRIOR_DEN as f64).round() as u64).max(1);
    }
    num[0] = PRIOR_DEN - num[1..].iter().sum::<u64>();
    Prior {
        num,
        den: PRIOR_DEN,
    }
}

/// A prior of weight one outcome centred on the null members' average Jeffreys
/// share of the failure, over the members that observed the check: what the
/// `no` sum mixes a flow's own share of foreign fronts over.
fn null_prior(members: &[[u64; 2]]) -> Prior<2> {
    let seen: Vec<&[u64; 2]> = members
        .iter()
        .filter(|m| m.iter().sum::<u64>() > 0)
        .collect();
    let share = seen
        .iter()
        .map(|m| (m[1] as f64 + 0.5) / (m.iter().sum::<u64>() as f64 + 1.0))
        .sum::<f64>()
        / seen.len() as f64;
    let failed = ((share * PRIOR_DEN as f64).round() as u64).clamp(1, PRIOR_DEN - 1);
    Prior {
        num: [PRIOR_DEN - failed, failed],
        den: PRIOR_DEN,
    }
}

/// The null side of a measured check from the members that observed it: per
/// outcome, the largest Clopper-Pearson bound (the `yes` sum's) and the average
/// Jeffreys share (the `no` sum's), as logarithms.
fn null_side<const K: usize>(members: &[[u64; K]]) -> ([i128; K], [i128; K]) {
    let seen: Vec<&[u64; K]> = members
        .iter()
        .filter(|m| m.iter().sum::<u64>() > 0)
        .collect();
    let mut bound = [0i128; K];
    let mut mean = [0i128; K];
    for o in 0..K {
        let top = seen
            .iter()
            .map(|m| upper_bound(m[o], m.iter().sum()))
            .fold(0.0f64, f64::max);
        let average = seen
            .iter()
            .map(|m| (m[o] as f64 + 0.5) / (m.iter().sum::<u64>() as f64 + K as f64 / 2.0))
            .sum::<f64>()
            / seen.len() as f64;
        bound[o] = log2_up(top);
        mean[o] = log2_down(average);
    }
    (bound, mean)
}

/// The grid's concentrations in fixed point, rounded down.
fn fixed_kappas() -> Vec<u64> {
    grid_kappas()
        .iter()
        .map(|k| (k * ONE_Q32 as f64).floor() as u64)
        .collect()
}

/// What the zenoh groups allow of one check's failure rate, rounded the way
/// that raises the chance it bounds. A check no group observed allows anything.
fn region_of(groups: &[GroupOutcomes], kappas: &'static [u64]) -> Region {
    let one = ONE_Q32 as f64;
    let grid = grid_kappas();
    let up = |x: f64| ((x * (1.0 + 1e-9)) * one).ceil() as u64;
    if groups.is_empty() {
        let cells: Vec<u64> = grid[1..].iter().map(|k| up(*k)).collect();
        return Region {
            groups_bound: ONE_Q32,
            kappas,
            cells: Vec::leak(cells),
            top: ONE_Q32,
        };
    }
    let mut tops: Vec<f64> = grid.iter().map(|&k| mean_bound(k, groups)).collect();
    // Held falling: each top at least every one after it.
    for i in (0..tops.len() - 1).rev() {
        tops[i] = tops[i].max(tops[i + 1]);
    }
    let groups_bound = 1.0 - 0.05f64.powf(1.0 / groups.len() as f64);
    let cells: Vec<u64> = grid
        .windows(2)
        .zip(&tops)
        .map(|(w, mu)| up(w[1] * mu))
        .collect();
    Region {
        groups_bound: up(groups_bound),
        kappas,
        cells: Vec::leak(cells),
        top: up(tops[tops.len() - 1]),
    }
}

/// The calibration the corpus gives: the counts, and the parameters computed
/// from them.
struct Calibration {
    zenoh: Counts,
    /// Each null file, in the manifest's order, with its counts.
    null: Vec<(String, Counts)>,
    params: Params,
    /// The SN prior's mean and concentration, as the fit found them.
    sn_fit: (f64, f64),
    zenoh_files: usize,
    zenoh_groups: usize,
    null_groups: usize,
}

/// The parameters `files` give.
fn calibrate<'a>(files: impl Iterator<Item = &'a File> + Clone) -> Calibration {
    let kappas: &'static [u64] = Vec::leak(fixed_kappas());
    let mut zenoh = Counts::default();
    let mut null = Vec::new();
    let mut steps = Vec::new();
    for f in files.clone() {
        if f.zenoh {
            zenoh.and(&f.counts);
            steps.extend(f.flows.iter().map(|fl| (fl.counts.sn[0], fl.counts.sn[1])));
        } else {
            null.push((f.name.clone(), f.counts));
        }
    }
    let region = |i: usize| region_of(&kind_groups(files.clone(), KINDS[i].1), kappas);
    let units: Vec<[u64; 3]> = null.iter().map(|(_, c)| c.units).collect();
    let framing: Vec<[u64; 2]> = null.iter().map(|(_, c)| c.framing).collect();
    let (units_bound, units_mean) = null_side(&units);
    let (framing_bound, framing_mean) = null_side(&framing);
    let front: Vec<[u64; 2]> = null.iter().map(|(_, c)| c.front).collect();
    let (front_bound, _) = null_side(&front);
    let (mean, kappa) = fit_sn(&steps);
    let a = ((kappa * mean * SN_DEN as f64).round() as u64).max(1);
    let g = ((kappa * (1.0 - mean) * SN_DEN as f64).round() as u64).max(1);
    let params = Params {
        units: Measured {
            zenoh: zenoh_prior(zenoh.units),
            region: region(0),
            log2_null_bound: units_bound,
            log2_null_mean: units_mean,
        },
        framing: Measured {
            zenoh: zenoh_prior(zenoh.framing),
            region: region(1),
            log2_null_bound: framing_bound,
            log2_null_mean: framing_mean,
        },
        cookie: Derived {
            zenoh: zenoh_prior(zenoh.cookie),
            region: region(2),
        },
        roles: Derived {
            zenoh: zenoh_prior(zenoh.roles),
            region: region(3),
        },
        sn: Prior {
            num: [g, a],
            den: SN_DEN,
        },
        front: Front {
            log2_null_bound: front_bound,
            null: null_prior(&front),
        },
    };
    let groups = |zenoh: bool| {
        files
            .clone()
            .filter(|f| f.zenoh == zenoh)
            .map(|f| f.group.as_str())
            .collect::<alloc::collections::BTreeSet<_>>()
            .len()
    };
    Calibration {
        params,
        sn_fit: (mean, kappa),
        zenoh_files: files.clone().filter(|f| f.zenoh).count(),
        zenoh_groups: groups(true),
        null_groups: groups(false),
        zenoh,
        null,
    }
}

/// `1234567` as Rust writes it in the model: `1_234_567`.
fn lit(n: i128) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push('_');
        }
        out.push(c);
    }
    if n < 0 {
        out.insert(0, '-');
    }
    out
}

/// An array literal as rustfmt lays it out at `indent` spaces, after `lead` on
/// its first line and followed by `tail`: on that line when it is at most 60
/// wide and the line fits in 100, one element a line otherwise.
fn array_lit(items: &[i128], indent: usize, lead: &str, tail: &str) -> String {
    let each: Vec<String> = items.iter().map(|&n| lit(n)).collect();
    let inline = alloc::format!("[{}]", each.join(", "));
    let pad = " ".repeat(indent);
    if inline.len() <= 60 && indent + lead.len() + inline.len() + tail.len() <= 100 {
        return alloc::format!("{pad}{lead}{inline}{tail}\n");
    }
    let mut out = alloc::format!("{pad}{lead}[\n");
    for e in each {
        out.push_str(&alloc::format!("{pad}    {e},\n"));
    }
    out.push_str(&alloc::format!("{pad}]{tail}\n"));
    out
}

fn prior_lit<const K: usize>(p: &Prior<K>, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let num: Vec<i128> = p.num.iter().map(|&n| i128::from(n)).collect();
    alloc::format!(
        "Prior {{\n{}{pad}    den: {},\n{pad}}}",
        array_lit(&num, indent + 4, "num: ", ","),
        lit(i128::from(p.den))
    )
}

fn region_lit(r: &Region, cells: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    alloc::format!(
        "Region {{\n{pad}    groups_bound: {},\n{pad}    kappas: &KAPPAS,\n{pad}    cells: &{cells},\n{pad}    top: {},\n{pad}}}",
        lit(i128::from(r.groups_bound)),
        lit(i128::from(r.top))
    )
}

fn measured_lit<const K: usize>(m: &Measured<K>, cells: &str) -> String {
    alloc::format!(
        "Measured {{\n        zenoh: {},\n        region: {},\n{}{}    }}",
        prior_lit(&m.zenoh, 8),
        region_lit(&m.region, cells, 8),
        array_lit(&m.log2_null_bound, 8, "log2_null_bound: ", ","),
        array_lit(&m.log2_null_mean, 8, "log2_null_mean: ", ","),
    )
}

fn derived_lit(d: &Derived, cells: &str) -> String {
    alloc::format!(
        "Derived {{\n        zenoh: {},\n        region: {},\n    }}",
        prior_lit(&d.zenoh, 8),
        region_lit(&d.region, cells, 8),
    )
}

fn front_lit(f: &Front) -> String {
    alloc::format!(
        "Front {{\n{}        null: {},\n    }}",
        array_lit(&f.log2_null_bound, 8, "log2_null_bound: ", ","),
        prior_lit(&f.null, 8),
    )
}

fn counts_literal(counts: &[u64]) -> String {
    let each: Vec<String> = counts.iter().map(|&n| lit(i128::from(n))).collect();
    alloc::format!("[{}]", each.join(", "))
}

/// The text of `zenoh_calibration_generated.rs` for this calibration. Laid out
/// as rustfmt lays it out, so that formatting the file changes nothing.
fn render(c: &Calibration) -> String {
    use core::fmt::Write as _;
    let mut out = String::new();
    let p = &c.params;
    out.push_str(
        "// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial\n\
         // SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael\n\n\
         //! GENERATED FROM `captures/corpus/` -- DO NOT EDIT.\n\
         //!\n\
         //! The counts of the corpus and model 5's parameters computed from them\n\
         //! (`docs/flow-zenoh-verdict.md` sections 6.8 to 6.10), written by\n\
         //! `zenoh_calibration_tests::the_generated_calibration_is_current`, which\n\
         //! fails when this file is not what the corpus gives. Regenerate with\n\
         //! `scripts/regen-calibration.sh` and commit the result with the capture\n\
         //! that moved it. The counts are those of a build that opens lz4.\n",
    );
    let _ = writeln!(
        out,
        "//!\n//! The corpus: {} zenoh files in {} groups, {} null files in {} groups.\n",
        c.zenoh_files,
        c.zenoh_groups,
        c.null.len(),
        c.null_groups
    );
    out.push_str(
        "use crate::zenoh_eprocess::{Prior, Region};\n\
         use crate::zenoh_evidence::model::measured::Member;\n\
         use crate::zenoh_evidence::model::{Derived, Front, Measured, Params};\n\n",
    );
    let kappas: Vec<i128> = p
        .units
        .region
        .kappas
        .iter()
        .map(|&k| i128::from(k))
        .collect();
    let _ = writeln!(
        out,
        "/// The concentrations of the regions' grid, `10^(-3 + i/8)`, in the fixed point\n\
         /// of `zenoh_eprocess::Q32_BITS`, rounded down."
    );
    out.push_str(&array_lit(
        &kappas,
        0,
        &alloc::format!("pub const KAPPAS: [u64; {}] = ", kappas.len()),
        ";",
    ));
    let regions: [(&str, &str, &Region); 4] = [
        ("UNITS_CELLS", "the unit readings", &p.units.region),
        ("FRAMING_CELLS", "the stream framing", &p.framing.region),
        ("COOKIE_CELLS", "the cookie echo", &p.cookie.region),
        ("ROLES_CELLS", "the Init roles", &p.roles.region),
    ];
    for (name, what, region) in regions {
        let cells: Vec<i128> = region.cells.iter().map(|&k| i128::from(k)).collect();
        let _ = writeln!(
            out,
            "\n/// The cells of the region of the failure rate of {what}."
        );
        out.push_str(&array_lit(
            &cells,
            0,
            &alloc::format!("pub const {name}: [u64; {}] = ", cells.len()),
            ";",
        ));
    }
    let _ = writeln!(
        out,
        "\n/// Model 5's parameters.\npub const PARAMS: Params = Params {{\n    units: {},\n    framing: {},\n    cookie: {},\n    roles: {},\n    sn: {},\n    front: {},\n}};",
        measured_lit(&p.units, "UNITS_CELLS"),
        measured_lit(&p.framing, "FRAMING_CELLS"),
        derived_lit(&p.cookie, "COOKIE_CELLS"),
        derived_lit(&p.roles, "ROLES_CELLS"),
        prior_lit(&p.sn, 4),
        front_lit(&p.front),
    );
    let _ = writeln!(
        out,
        "\n/// The null protocols, in the manifest's order.\npub const NULL: [Member; {}] = [",
        c.null.len()
    );
    for (file, counts) in &c.null {
        let _ = writeln!(
            out,
            "    Member {{\n        file: \"{file}\",\n        units: {},\n        framing: {},\n        front: {},\n    }},",
            counts_literal(&counts.units),
            counts_literal(&counts.framing),
            counts_literal(&counts.front)
        );
    }
    out.push_str("];\n\n");
    let _ = writeln!(
        out,
        "/// The zenoh files' framing units: read whole, residual, undecoded.\npub const ZENOH_UNITS: [u64; 3] = {};\n\n\
         /// The zenoh files' stream directions captured from their start: framing held, lost.\npub const ZENOH_FRAMING: [u64; 2] = {};\n\n\
         /// The zenoh files' cookie echoes: matched, differing.\npub const ZENOH_COOKIE: [u64; 2] = {};\n\n\
         /// The zenoh files' Init pairs: of opposite kinds, of one kind.\npub const ZENOH_ROLES: [u64; 2] = {};\n\n\
         /// The zenoh files' version headers: this reader's, another.\npub const ZENOH_VERSIONS: [u64; 2] = {};\n\n\
         /// The zenoh files' batch fronts, of datagrams and of stream chains: of this wire, foreign.\npub const ZENOH_FRONT: [u64; 2] = {};",
        counts_literal(&c.zenoh.units),
        counts_literal(&c.zenoh.framing),
        counts_literal(&c.zenoh.cookie),
        counts_literal(&c.zenoh.roles),
        counts_literal(&c.zenoh.versions),
        counts_literal(&c.zenoh.front)
    );
    out
}

fn generated_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/zenoh_calibration_generated.rs")
}

/// A probability as the design note's parameter table writes it.
fn prob(log2_q64: i128) -> String {
    alloc::format!(
        "{:.4e}",
        2f64.powf(log2_q64 as f64 / 18_446_744_073_709_551_616.0)
    )
}

/// The rows of the design note's parameter table (§6.8) this calibration gives.
fn doc_rows(c: &Calibration) -> Vec<String> {
    let p = &c.params;
    let q32 = |x: u64| alloc::format!("{:.4e}", x as f64 / ONE_Q32 as f64);
    let share = |num: u64, den: u64| alloc::format!("{:.4e}", num as f64 / den as f64);
    let mut rows = Vec::new();
    let measured = [
        (
            "unit readings",
            &p.units.log2_null_bound[..],
            &p.units.log2_null_mean[..],
        ),
        (
            "stream framing",
            &p.framing.log2_null_bound[..],
            &p.framing.log2_null_mean[..],
        ),
    ];
    for (name, bound, mean) in measured {
        let b: Vec<String> = bound.iter().map(|&x| prob(x)).collect();
        let m: Vec<String> = mean.iter().map(|&x| prob(x)).collect();
        rows.push(alloc::format!(
            "| {name} | {} | {} |",
            b.join(", "),
            m.join(", ")
        ));
    }
    let regions = [
        (
            "unit readings",
            &p.units.zenoh.num[1..],
            p.units.zenoh.den,
            &p.units.region,
        ),
        (
            "stream framing",
            &p.framing.zenoh.num[1..],
            p.framing.zenoh.den,
            &p.framing.region,
        ),
        (
            "cookie echo",
            &p.cookie.zenoh.num[1..],
            p.cookie.zenoh.den,
            &p.cookie.region,
        ),
        (
            "Init roles",
            &p.roles.zenoh.num[1..],
            p.roles.zenoh.den,
            &p.roles.region,
        ),
    ];
    for (name, failures, den, region) in regions {
        let f: u64 = failures.iter().sum();
        rows.push(alloc::format!(
            "| {name} | {} | {} | {} |",
            share(f, den),
            q32(region.groups_bound),
            q32(region.top)
        ));
    }
    rows.push(alloc::format!(
        "| wire front | {} | {} |",
        p.front
            .log2_null_bound
            .iter()
            .map(|&x| prob(x))
            .collect::<Vec<_>>()
            .join(", "),
        share(p.front.null.num[1], p.front.null.den)
    ));
    rows.push(alloc::format!(
        "SN prior: Beta({}/{}, {}/{})",
        p.sn.num[1],
        p.sn.den,
        p.sn.num[0],
        p.sn.den
    ));
    rows
}

/// THE GENERATED FILE IS WHAT THE CORPUS GIVES. `zenoh_calibration_generated.rs`
/// holds the counts and the parameters, and nobody writes it: this test renders
/// it from the corpus and fails with the first line that differs when the file
/// is not that. With `WZ_BLESS_CALIBRATION` set it writes the file instead, which
/// is what `scripts/regen-calibration.sh` does, so a capture added to the corpus
/// moves the model by one command.
///
/// The design note's numbers are held to the same calibration: its parameter
/// table and the counts it states are not generated, and drifting from the file
/// is what this fails on.
#[test]
fn the_generated_calibration_is_current() {
    let files = read_corpus();
    let calibration = calibrate(files.iter());
    let want = render(&calibration);
    let path = generated_path();
    if std::env::var_os("WZ_BLESS_CALIBRATION").is_some() {
        std::fs::write(&path, &want).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
    let have = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    if have != want {
        let at = have
            .lines()
            .zip(want.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| have.lines().count().min(want.lines().count()));
        panic!(
            "zenoh_calibration_generated.rs is not what the corpus gives (first difference at \
             line {}):\n  file: {:?}\n  corpus: {:?}\nregenerate with scripts/regen-calibration.sh \
             and commit it with the capture that moved it. On a machine that cannot build it, \
             the file the corpus gives follows.\n=====\n{want}=====",
            at + 1,
            have.lines().nth(at),
            want.lines().nth(at)
        );
    }
    assert_eq!(calibration.params, model::PARAMS);
    std::println!(
        "SN prior fitted: mean {}, concentration {}",
        calibration.sn_fit.0,
        calibration.sn_fit.1
    );

    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/flow-zenoh-verdict.md"),
    )
    .expect("docs/flow-zenoh-verdict.md reads");
    let mut stale: Vec<String> = doc_rows(&calibration)
        .into_iter()
        .filter(|row| !doc.contains(row.as_str()))
        .collect();
    let prose = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    let z = &calibration.zenoh;
    let counts = alloc::format!(
        "and 0 undecoded in {} units; 0 framings lost in {} directions held from their start; \
         0 differing cookies in {} echoes; 0 Init pairs of one kind in {}; 0 other versions in {} \
         version headers",
        z.units[0],
        z.framing[0],
        z.cookie[0],
        z.roles[0],
        z.versions[0]
    );
    if !prose.contains(&counts) {
        stale.push(counts);
    }
    assert!(
        stale.is_empty(),
        "docs/flow-zenoh-verdict.md does not say what the corpus gives; it should hold:\n{}",
        stale.join("\n")
    );
}

/// THE DERIVATIONS, put to the corpus: the zenoh side of [`Check::WireFront`]
/// and of [`Check::VersionHeader`] is not measured, it says a zenoh batch's
/// front is of the wire and its version this reader's unless the bytes were
/// altered on the way, and a foreign front or another version in a zenoh file
/// would refute it. Every zenoh file is read, with its bytes of every
/// integrity the checks weigh, and fronts of both kinds are among them:
/// datagrams' and stream chains'.
#[test]
fn no_zenoh_file_refutes_a_derived_check() {
    let files = read_corpus();
    let mut fronts = [0u64; 2];
    let mut versions = [0u64; 2];
    let mut by_kind = [0u64; 2];
    let mut refuting = Vec::new();
    for f in files.iter().filter(|f| f.zenoh) {
        for (i, fl) in f.flows.iter().enumerate() {
            let c = &fl.counts;
            fronts[0] += c.front[0];
            fronts[1] += c.front[1];
            versions[0] += c.versions[0];
            versions[1] += c.versions[1];
            by_kind[usize::from(!fl.stream)] += c.front[0];
            if c.front[1] > 0 || c.versions[1] > 0 {
                refuting.push(alloc::format!(
                    "{} flow {i}: fronts {:?}, versions {:?}",
                    f.name,
                    c.front,
                    c.versions
                ));
            }
        }
    }
    assert!(refuting.is_empty(), "{}", refuting.join("\n"));
    assert!(by_kind[0] > 0, "the zenoh files weigh stream fronts");
    assert!(by_kind[1] > 0, "the zenoh files weigh datagram fronts");
    std::println!("fronts of the wire: {by_kind:?} (stream, datagram)");
    assert_eq!(fronts, model::measured::ZENOH_FRONT);
    assert_eq!(versions, model::measured::ZENOH_VERSIONS);
}

/// Every flow read again from its observations, with the parameters the reader
/// ships, is the evidence the reader gave it: the replay below reads the
/// library, not a look-alike.
#[test]
fn every_flow_read_again_from_its_observations_is_its_own_evidence() {
    let mut flows = 0usize;
    for file in read_corpus() {
        for (i, f) in file.flows.iter().enumerate() {
            flows += 1;
            assert_eq!(
                crate::zenoh_evidence::recording(|| f.evidence.replayed_with(&model::PARAMS)),
                f.evidence,
                "{} flow {i}",
                file.name
            );
        }
    }
    assert!(flows > 0, "the corpus has flows");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Word {
    Yes,
    No,
    Undecided,
}

/// The word a body of evidence latched, `undecided` while it has not crossed.
fn word(e: &ZenohEvidence) -> Word {
    match e.crossing() {
        Some(c) if c.yes && !c.no => Word::Yes,
        Some(c) if c.no && !c.yes => Word::No,
        _ => Word::Undecided,
    }
}

/// Counts of the three words.
#[derive(Debug, Default, Clone, Copy)]
struct Tally {
    yes: u64,
    no: u64,
    undecided: u64,
}

impl Tally {
    fn add(&mut self, w: Word) {
        match w {
            Word::Yes => self.yes += 1,
            Word::No => self.no += 1,
            Word::Undecided => self.undecided += 1,
        }
    }
}

/// THE MEASUREMENT: each group left out, the parameters computed from the rest,
/// the left-out flows read with them. Printed (`-- --nocapture`); what it holds
/// is that every flow is read in exactly one group, and that leaving a zenoh
/// group out turns none of its flows to `no` (the error a false `no` would be).
#[test]
fn leaving_a_group_out_of_the_parameters_moves_its_own_flows_by_this_much() {
    let files = read_corpus();
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, f) in files.iter().enumerate() {
        groups.entry(f.group.clone()).or_default().push(i);
    }
    std::println!("group | files | flows | shipped yes/no/und | left out yes/no/und");
    let mut flows_read = 0usize;
    let mut false_no = Vec::new();
    for (group, idx) in &groups {
        let zenoh_group = files[idx[0]].zenoh;
        let rest = files
            .iter()
            .enumerate()
            .filter(|(i, _)| !idx.contains(i))
            .map(|(_, f)| f);
        let left_out = calibrate(rest).params;
        let (mut own, mut other) = (Tally::default(), Tally::default());
        let mut nflows = 0usize;
        for &i in idx {
            for f in &files[i].flows {
                nflows += 1;
                own.add(word(&f.evidence));
                let again = word(&f.evidence.replayed_with(&left_out));
                other.add(again);
                if zenoh_group && again == Word::No {
                    false_no.push(alloc::format!(
                        "{}: a flow reads `no` left out",
                        files[i].name
                    ));
                }
            }
        }
        flows_read += nflows;
        std::println!(
            "{}{} | {} | {} | {}/{}/{} | {}/{}/{}",
            if zenoh_group { "zenoh " } else { "null " },
            group,
            idx.len(),
            nflows,
            own.yes,
            own.no,
            own.undecided,
            other.yes,
            other.no,
            other.undecided,
        );
    }
    let total: usize = files.iter().map(|f| f.flows.len()).sum();
    assert_eq!(flows_read, total, "every flow is read in exactly one group");
    assert!(false_no.is_empty(), "{}", false_no.join("\n"));
}

/// The independent groups a claim needs: with no failure seen in `g` groups the
/// one-sided 95% bound on a group failing is `1 - 0.05^(1/g)`
/// (`docs/flow-zenoh-verdict.md` section 6.4), so the least `g` that brings it to
/// `target`.
fn groups_needed(target: f64) -> u64 {
    let mut g = 1u64;
    while 1.0 - 0.05f64.powf(1.0 / g as f64) > target {
        g += 1;
    }
    g
}

/// The numbers of the acceptance table are the zero-failure bound inverted, and
/// the report says how far the corpus is from each row. It asserts the table and
/// not the corpus: whether the corpus must reach a row is the owner's to state.
#[test]
fn the_groups_a_claim_needs_are_the_zero_failure_bound_inverted() {
    for (target, needed) in [(0.10, 29u64), (0.05, 59), (0.01, 299)] {
        assert_eq!(groups_needed(target), needed, "target {target}");
        // The bound at `needed` is within the target, and at one fewer it is not.
        assert!(upper_bound(0, needed) <= target);
        assert!(upper_bound(0, needed - 1) > target);
    }
    let files = read_corpus();
    let groups = |zenoh: bool| {
        files
            .iter()
            .filter(|f| f.zenoh == zenoh)
            .map(|f| f.group.as_str())
            .collect::<alloc::collections::BTreeSet<_>>()
            .len() as u64
    };
    let (zenoh, null) = (groups(true), groups(false));
    std::println!("claim | needs | zenoh groups held | null groups held");
    for (name, target) in [("10%", 0.10), ("5%", 0.05), ("1%", 0.01)] {
        let needed = groups_needed(target);
        std::println!(
            "{name} | {needed} | {zenoh} ({} short) | {null} ({} short)",
            needed.saturating_sub(zenoh),
            needed.saturating_sub(null)
        );
    }
    // A group is a trial of one side: a file is in exactly one group.
    assert_eq!(
        files
            .iter()
            .map(|f| f.group.as_str())
            .collect::<alloc::collections::BTreeSet<_>>()
            .len() as u64,
        zenoh + null
    );
}

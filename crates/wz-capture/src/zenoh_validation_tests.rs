// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The validation corpus of the flow zenoh test (`captures/validation/`), read
//! the one time `docs/flow-zenoh-verdict.md` §6.12 registered: against model 6
//! as frozen there, by group, into the report that section specifies.
//!
//! The report is the test's output. The reading the section names is the first
//! run of this test on the corpus as collected; what it printed is
//! `captures/validation/report.txt` ([`REPORTED`]), and from then on the test
//! holds the reader to having read the corpus that way. It reads in the build
//! that opens lz4, the reader the model was frozen for and the build the
//! calibration is computed in; a build without lz4 reads a compressed
//! workload's batches as undecodable.
#![cfg(all(
    feature = "network-codecs",
    feature = "reassembly",
    feature = "compression"
))]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::session_table::ZenohVerdict;
use crate::zenoh_corpus_tests::{manifest_in, Entry};
use crate::zenoh_evidence::{recording, ZenohEvidence};
use crate::zenoh_hierarchy_tests::exact_interval;
use crate::Dissection;

fn validation_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../captures/validation")
}

/// What the report needs of one flow.
struct Read {
    word: ZenohVerdict,
    /// The largest `yes` sum and the smallest `no` sum it reached, millibits.
    yes_max: i64,
    no_min: i64,
    /// The observations it took to its word, when it has one.
    to_word: Option<usize>,
}

fn read_flow(e: &ZenohEvidence) -> Read {
    let to_word = e.crossing().map(|_| {
        let mut again = ZenohEvidence::default();
        e.log
            .iter()
            .position(|&(o, packet)| {
                again.observe(o, packet);
                again.crossing().is_some()
            })
            .map_or(e.log.len(), |i| i + 1)
    });
    Read {
        word: ZenohVerdict::of(e),
        yes_max: e.log2_lr_max_millibits(),
        no_min: e.log2_lr_no_min_millibits(),
        to_word,
    }
}

fn read_file(entry: &Entry) -> Vec<Read> {
    let bytes = std::fs::read(validation_dir().join(&entry.file))
        .unwrap_or_else(|e| panic!("{}: {e}", entry.file));
    let d = recording(|| Dissection::from_capture(&bytes))
        .unwrap_or_else(|e| panic!("{}: the capture reads: {e:?}", entry.file));
    let mut out: Vec<Read> = d
        .flows()
        .iter()
        .map(|f| read_flow(&f.zenoh_evidence()))
        .chain(
            d.datagram_flows()
                .iter()
                .map(|f| read_flow(&f.zenoh_evidence())),
        )
        .collect();
    if d.serial_census().is_some() {
        out.push(read_flow(&d.serial_zenoh_evidence()));
    }
    out
}

/// The 95th percentile of `xs`, the smallest value at least 95% are at or below.
fn p95(xs: &mut [usize]) -> usize {
    xs.sort_unstable();
    xs[((xs.len() * 95).div_ceil(100)).saturating_sub(1)]
}

/// The report of section 6.12, as text: the errors per group, the crossing
/// shares by level with their exact 95% intervals, and the observations to a
/// word per group.
fn report(groups: &BTreeMap<String, (bool, Vec<Read>)>) -> String {
    use core::fmt::Write as _;
    let mut out = String::new();
    let side = |zenoh: bool| groups.values().filter(move |(z, _)| *z == zenoh);
    let (nz, nn) = (side(true).count() as u64, side(false).count() as u64);
    let _ = writeln!(out, "groups: {nz} zenoh, {nn} null");
    let _ = writeln!(out, "1. errors");
    let mut errors = 0;
    for (name, (zenoh, reads)) in groups {
        let wrong = if *zenoh {
            ZenohVerdict::No
        } else {
            ZenohVerdict::Yes
        };
        let n = reads.iter().filter(|r| r.word == wrong).count();
        if n > 0 {
            errors += 1;
            let _ = writeln!(
                out,
                "   {name}: {n} of {} flows read {wrong:?}",
                reads.len()
            );
        }
    }
    let _ = writeln!(out, "   groups with an error: {errors}");
    let _ = writeln!(out, "2. groups crossing a level (exact 95% interval)");
    for k in 1..=10i64 {
        let crossed = |zenoh: bool| {
            side(zenoh)
                .filter(|(_, reads)| {
                    reads.iter().any(|r| {
                        if zenoh {
                            r.no_min <= -k * 1000
                        } else {
                            r.yes_max >= k * 1000
                        }
                    })
                })
                .count() as u64
        };
        let (cz, cn) = (crossed(true), crossed(false));
        let (zl, zu) = exact_interval(cz, nz);
        let (nl, nu) = exact_interval(cn, nn);
        let _ = writeln!(
            out,
            "   {k:>2} bits (level {:.4}): zenoh -{k}: {cz}/{nz} [{zl:.4}, {zu:.4}]; null +{k}: {cn}/{nn} [{nl:.4}, {nu:.4}]",
            0.5f64.powi(k as i32)
        );
    }
    let _ = writeln!(
        out,
        "3. observations to a word, per group (flows with one: mean, 95th percentile)"
    );
    for (name, (_, reads)) in groups {
        let mut to: Vec<usize> = reads.iter().filter_map(|r| r.to_word).collect();
        let words = |w: ZenohVerdict| reads.iter().filter(|r| r.word == w).count();
        if to.is_empty() {
            let _ = writeln!(out, "   {name}: {} flows, none with a word", reads.len());
            continue;
        }
        let mean = to.iter().sum::<usize>() as f64 / to.len() as f64;
        let _ = writeln!(
            out,
            "   {name}: {} flows, yes {} no {} undecided {}; {} with a word: mean {mean:.1}, p95 {}",
            reads.len(),
            words(ZenohVerdict::Yes),
            words(ZenohVerdict::No),
            words(ZenohVerdict::Undecided),
            to.len(),
            p95(&mut to)
        );
    }
    out
}

/// What the one reading of the validation corpus printed (§6.12, §6.13).
const REPORTED: &str = include_str!("../../../captures/validation/report.txt");

/// THE VALIDATION CORPUS, READ ONCE against the frozen model (§6.12): the
/// report is what this prints, and it is held to what it printed the first
/// time ([`REPORTED`]).
#[test]
fn the_validation_corpus_read_against_the_frozen_model() {
    let entries = manifest_in(&validation_dir(), "corpus.json5");
    let mut groups: BTreeMap<String, (bool, Vec<Read>)> = BTreeMap::new();
    for e in &entries {
        let zenoh = e.hypothesis == "zenoh";
        let slot = groups
            .entry(e.group.clone())
            .or_insert_with(|| (zenoh, Vec::new()));
        slot.1.extend(read_file(e));
    }
    let text = report(&groups);
    std::println!("{text}");
    assert_eq!(text, REPORTED, "the report of the one reading:\n{text}");
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE CALIBRATION, JUDGED BY GROUP: how far the measured weights of
//! `zenoh_evidence::model` hold on captures that were left out of the counts
//! they rest on (`docs/flow-zenoh-verdict.md` §6.3).
//!
//! The corpus test (`zenoh_corpus_tests`) reads every file with weights that
//! were counted from every file. That is a fit, not a validation: a protocol
//! that is in the null family sets the family's largest chance of an outcome,
//! so its own flows are weighed against a bound it helped to make. This module
//! leaves one GROUP out at a time, counts the weights again from the rest, and
//! reads the left-out flows with them.
//!
//! The group is the unit that is independent of the others, which a flow is
//! not: the units of one session share a stack, a traffic generator and a
//! link. A null protocol is a group of its own. A zenoh file is in the group
//! of its release line, of its link (loss, reordering, jitter, a tunnel, a
//! real Wi-Fi), or of what it exercises (compression, handshakes); [`group_of`]
//! says which, from the file's name, until the manifest names it.
//!
//! A flow's two sums are linear in its outcome counts ([`Counts`]), so a flow
//! is read again from them with any table of weights ([`Table`]). That the
//! shipped table, applied to the counts, gives back every flow's own sums is
//! the first test here, and the reason the others can be trusted.
//!
//! The tests are of the build that opens lz4 (`--features compression`). A build
//! that cannot counts the one batch it cannot open as a unit and does not weigh
//! it, so its counts are not its sums, and a test that returned early there
//! would pass over nothing: they are not compiled in it.
#![cfg(all(
    feature = "network-codecs",
    feature = "reassembly",
    feature = "compression"
))]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::passive::ReadingEvidence;

use crate::zenoh_corpus_tests::{corpus_dir, manifest};
use crate::zenoh_evidence::tests as fit;
use crate::zenoh_evidence::{cookie_echo_weight, model, Check, Weight, ZenohEvidence};
use crate::Dissection;

/// The outcomes a flow's sums are made of.
#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    /// Framing units read whole, residual, undecoded.
    units: [u64; 3],
    /// Stream directions whose framing held, or was lost first.
    framing: [u64; 2],
    /// Cookie echoes matched, differing.
    cookie: [u64; 2],
    /// Init pairs of opposite kinds, of one kind.
    roles: [u64; 2],
    /// Version headers of this reader's version, of another.
    versions: [u64; 2],
    /// SN steps that followed, that broke.
    sn: [u64; 2],
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
    }

    /// Whether the counts hold an outcome the zenoh side calls a failure.
    fn failures(&self) -> [u64; 5] {
        [
            self.units[1] + self.units[2],
            self.framing[1],
            self.cookie[1],
            self.roles[1],
            self.versions[1],
        ]
    }
}

/// One flow: its outcomes and the sums the library gave it.
struct Flow {
    counts: Counts,
    yes: i64,
    no: i64,
}

/// One file of the corpus, read.
struct File {
    name: String,
    zenoh: bool,
    group: String,
    flows: Vec<Flow>,
    counts: Counts,
}

fn flows_of(d: &Dissection) -> Vec<Flow> {
    let mut out = Vec::new();
    let mut push = |r: ReadingEvidence, e: ZenohEvidence| {
        let t = |check| e.tally(check);
        out.push(Flow {
            counts: Counts {
                units: [r.explained.units, r.residual.units, r.undecoded.units],
                framing: [
                    t(Check::StreamFraming).confirmed,
                    t(Check::StreamFraming).violated,
                ],
                cookie: [
                    t(Check::CookieEcho).confirmed,
                    t(Check::CookieEcho).violated,
                ],
                roles: [t(Check::InitRoles).confirmed, t(Check::InitRoles).violated],
                versions: [
                    t(Check::VersionHeader).confirmed,
                    t(Check::VersionHeader).violated,
                ],
                sn: [t(Check::SnFollows).confirmed, t(Check::SnFollows).violated],
            },
            yes: e.log2_lr_millibits(),
            no: e.log2_lr_no_millibits(),
        });
    };
    for f in d.flows() {
        push(f.ingest.readings(), f.zenoh_evidence());
    }
    for f in d.datagram_flows() {
        push(f.ingest.readings(), f.zenoh_evidence());
    }
    out
}

/// The group of independent evidence a file belongs to. A null protocol is its
/// own; a zenoh file is in the group of the thing that makes it unlike the
/// others, read from its name.
fn group_of(file: &str, zenoh: bool) -> String {
    let stem = file.trim_end_matches(".pcap");
    if !zenoh {
        return String::from(stem);
    }
    let parts: Vec<&str> = stem.split('-').collect();
    let release = |minor: &str| alloc::format!("release 1.{minor}");
    let has = |needle: &str| stem.contains(needle);
    if stem.starts_with("zenoh-pico") || stem.starts_with("link-pico") {
        String::from("pico")
    } else if stem.starts_with("link-") {
        String::from("real Wi-Fi")
    } else if stem.starts_with("zenoh-tunnel") {
        String::from("tunnel")
    } else if stem.starts_with("zenoh-jitter") {
        String::from("jitter")
    } else if stem.starts_with("zenoh-mixed") {
        String::from("version skew")
    } else if stem.starts_with("zenoh-matched") {
        release(parts[3])
    } else if stem.starts_with("zenoh-v1") {
        release(parts[2])
    } else if stem.starts_with("zenoh15") {
        release("5")
    } else if has("loss") {
        String::from("loss")
    } else if has("reorder") {
        String::from("reorder")
    } else if has("-dup") {
        String::from("duplicates")
    } else if has("handshakes") {
        String::from("handshakes")
    } else if has("lz4") {
        String::from("lz4")
    } else {
        String::from("loopback 1.10.1")
    }
}

fn read_corpus() -> Vec<File> {
    manifest()
        .into_iter()
        .map(|entry| {
            let bytes = std::fs::read(corpus_dir().join(&entry.file))
                .unwrap_or_else(|e| panic!("{}: {e}", entry.file));
            let d = Dissection::from_capture(&bytes)
                .unwrap_or_else(|e| panic!("{}: the capture reads: {e:?}", entry.file));
            let flows = flows_of(&d);
            let mut counts = Counts::default();
            for f in &flows {
                counts.and(&f.counts);
            }
            let zenoh = entry.hypothesis == "zenoh";
            File {
                group: group_of(&entry.file, zenoh),
                name: entry.file,
                zenoh,
                flows,
                counts,
            }
        })
        .collect()
}

/// Every weight a flow's sums are made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Table {
    unit: [Weight; 3],
    framing: [Weight; 2],
    /// A cookie of the longest length the model weighs, matched; and differing.
    cookie: [Weight; 2],
    roles: [Weight; 2],
    versions: [Weight; 2],
    sn: [Weight; 2],
}

impl Table {
    /// The table the library ships.
    fn shipped() -> Table {
        Table {
            unit: [
                model::UNIT_EXPLAINED,
                model::UNIT_RESIDUAL,
                model::UNIT_UNDECODED,
            ],
            framing: [model::FRAMING_HELD, model::FRAMING_LOST],
            cookie: [
                cookie_echo_weight(usize::try_from(model::COOKIE_ECHO_MAX_BYTES).unwrap_or(0)),
                model::COOKIE_ECHO_VIOLATED,
            ],
            roles: [model::INIT_ROLES_CONFIRMED, model::INIT_ROLES_VIOLATED],
            versions: [model::VERSION_HEADER, model::VERSION_FOREIGN],
            sn: [model::SN_FOLLOWS, model::SN_BREAKS],
        }
    }

    /// The table counted from `zenoh`'s outcomes and the null `members`', by the
    /// rule `model_weights_are_their_stated_probabilities` states. The SN steps
    /// stay the assumed ones.
    fn fitted(zenoh: &Counts, members: &[&Counts]) -> Table {
        let unit_members: Vec<&[u64]> = members.iter().map(|m| &m.units[..]).collect();
        let framing_members: Vec<&[u64]> = members.iter().map(|m| &m.framing[..]).collect();
        let units = fit::measured_weights(&zenoh.units, &unit_members);
        let framing = fit::measured_weights(&zenoh.framing, &framing_members);
        let eps = |[ok, failed]: [u64; 2]| fit::upper_bound(failed, ok + failed);
        let (e_cookie, e_roles, e_version) =
            (eps(zenoh.cookie), eps(zenoh.roles), eps(zenoh.versions));
        let byte = 1.0 / 256.0;
        Table {
            unit: [units[0], units[1], units[2]],
            framing: [framing[0], framing[1]],
            cookie: [
                Weight::both(
                    model::COOKIE_ECHO_MAX_BYTES * model::COOKIE_ECHO_PER_BYTE
                        + fit::millibits(1.0 - e_cookie),
                ),
                Weight::both(fit::millibits(e_cookie)),
            ],
            roles: [
                Weight::both(fit::millibits((1.0 - e_roles) / 0.5)),
                Weight::both(fit::millibits(e_roles / 0.5)),
            ],
            versions: [
                Weight::both(fit::millibits((1.0 - e_version) / byte)),
                Weight::both(fit::millibits(e_version / (1.0 - byte))),
            ],
            sn: Table::shipped().sn,
        }
    }

    /// A flow's `yes` and `no` sums under this table.
    fn score(&self, c: &Counts) -> (i64, i64) {
        let mut w = Weight::default();
        let mut add = |counts: &[u64], weights: &[Weight]| {
            for (n, weight) in counts.iter().zip(weights) {
                w = w.plus(weight.times(*n));
            }
        };
        add(&c.units, &self.unit);
        add(&c.framing, &self.framing);
        add(&c.cookie, &self.cookie);
        add(&c.roles, &self.roles);
        add(&c.versions, &self.versions);
        add(&c.sn, &self.sn);
        (w.yes, w.no)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Word {
    Yes,
    No,
    Undecided,
}

/// The word two sums come to: the rule of `ZenohVerdict::of`.
fn word(yes: i64, no: i64) -> Word {
    match (yes >= model::YES_AT, no <= model::NO_AT) {
        (true, false) => Word::Yes,
        (false, true) => Word::No,
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

/// Every flow's own sums are the shipped table applied to its outcome counts.
/// Without this nothing below says anything about the library.
#[test]
fn the_shipped_table_applied_to_a_flows_counts_gives_the_flows_own_sums() {
    let table = Table::shipped();
    let mut wrong = Vec::new();
    let mut flows = 0usize;
    for file in read_corpus() {
        for (i, f) in file.flows.iter().enumerate() {
            flows += 1;
            let got = table.score(&f.counts);
            if got != (f.yes, f.no) {
                wrong.push(alloc::format!(
                    "{} flow {i}: counts give {got:?}, the flow's own sums are {:?} ({:?})",
                    file.name,
                    (f.yes, f.no),
                    f.counts
                ));
            }
        }
    }
    assert!(flows > 0, "the corpus has flows");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The fit this module applies to a part of the corpus, applied to all of it,
/// is the table the library ships: the same rule, not a look-alike.
#[test]
fn counting_the_weights_again_from_the_whole_corpus_gives_the_shipped_table() {
    let files = read_corpus();
    let mut zenoh = Counts::default();
    for f in files.iter().filter(|f| f.zenoh) {
        zenoh.and(&f.counts);
    }
    let members: Vec<&Counts> = files
        .iter()
        .filter(|f| !f.zenoh)
        .map(|f| &f.counts)
        .collect();
    assert_eq!(Table::fitted(&zenoh, &members), Table::shipped());
}

/// THE MEASUREMENT: each group left out, the weights counted from the rest,
/// the left-out flows read with them. Nothing is asserted about the rates yet:
/// the owner has not stated what the corpus must show. The report is printed
/// (`cargo test -p wz-capture --features dissect,reassembly leave_one_group_out
/// -- --nocapture`), and the structure of it is held.
#[test]
fn leaving_a_group_out_of_the_counts_moves_its_own_flows_by_this_much() {
    let files = read_corpus();
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, f) in files.iter().enumerate() {
        groups.entry(f.group.clone()).or_default().push(i);
    }
    std::println!(
        "group | files | flows | shipped yes/no/und | left out yes/no/und | extreme sum (shipped -> left out)"
    );
    let mut flows_read = 0usize;
    for (group, idx) in &groups {
        let zenoh_group = files[idx[0]].zenoh;
        let mut train_zenoh = Counts::default();
        for (i, f) in files.iter().enumerate() {
            if f.zenoh && !idx.contains(&i) {
                train_zenoh.and(&f.counts);
            }
        }
        let members: Vec<&Counts> = files
            .iter()
            .enumerate()
            .filter(|(i, f)| !f.zenoh && !idx.contains(i))
            .map(|(_, f)| &f.counts)
            .collect();
        let left_out = Table::fitted(&train_zenoh, &members);
        let (mut own, mut other) = (Tally::default(), Tally::default());
        // The sum that matters for the group: the lowest `yes` of a zenoh group
        // (a false `no` or `undecided` is how it fails), the highest of a null one.
        let (mut extreme_shipped, mut extreme_left_out) = (None::<i64>, None::<i64>);
        let mut nflows = 0usize;
        for &i in idx {
            for f in &files[i].flows {
                nflows += 1;
                own.add(word(f.yes, f.no));
                let (y, n) = left_out.score(&f.counts);
                other.add(word(y, n));
                let pick = |cur: Option<i64>, v: i64| match cur {
                    None => Some(v),
                    Some(c) if zenoh_group => Some(c.min(v)),
                    Some(c) => Some(c.max(v)),
                };
                extreme_shipped = pick(extreme_shipped, f.yes);
                extreme_left_out = pick(extreme_left_out, y);
            }
        }
        flows_read += nflows;
        std::println!(
            "{}{} | {} | {} | {}/{}/{} | {}/{}/{} | {:?} -> {:?}",
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
            extreme_shipped,
            extreme_left_out
        );
    }
    let total: usize = files.iter().map(|f| f.flows.len()).sum();
    assert_eq!(flows_read, total, "every flow is read in exactly one group");
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
        assert!(fit::upper_bound(0, needed) <= target);
        assert!(fit::upper_bound(0, needed - 1) > target);
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

/// What the zenoh failure chances are bounded by, with the count the bound
/// stands on: units, files, groups. The units are not independent of each
/// other, and the files of one group are not independent of each other.
#[test]
fn the_zenoh_failure_bound_stands_on_how_many_independent_things() {
    let files = read_corpus();
    let zenoh: Vec<&File> = files.iter().filter(|f| f.zenoh).collect();
    let mut groups: BTreeMap<&str, [u64; 5]> = BTreeMap::new();
    for f in &zenoh {
        let slot = groups.entry(f.group.as_str()).or_default();
        for (s, v) in slot.iter_mut().zip(f.counts.failures()) {
            *s += v;
        }
    }
    let mut all = Counts::default();
    for f in &zenoh {
        all.and(&f.counts);
    }
    let sizes = [
        all.units.iter().sum::<u64>(),
        all.framing.iter().sum::<u64>(),
        all.cookie.iter().sum::<u64>(),
        all.roles.iter().sum::<u64>(),
        all.versions.iter().sum::<u64>(),
    ];
    let names = [
        "unit with bytes left over or undecoded",
        "stream direction that lost its framing",
        "cookie that differs",
        "Init pair of one kind",
        "version header of another version",
    ];
    std::println!("failure | bound on units | on files | on groups (95% one-sided)");
    for (i, name) in names.iter().enumerate() {
        let file_failed = zenoh.iter().filter(|f| f.counts.failures()[i] > 0).count() as u64;
        let group_failed = groups.values().filter(|g| g[i] > 0).count() as u64;
        // A file or a group is a trial that fails if any of its units does.
        let on_files = fit::upper_bound(file_failed, zenoh.len() as u64);
        let on_groups = fit::upper_bound(group_failed, groups.len() as u64);
        let on_units = fit::upper_bound(all.failures()[i], sizes[i]);
        std::println!(
            "{name} | {on_units:.6} ({} of {}) | {on_files:.4} ({file_failed} of {}) | {on_groups:.4} ({group_failed} of {})",
            all.failures()[i],
            sizes[i],
            zenoh.len(),
            groups.len()
        );
    }
}

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
//! real Wi-Fi), or of what it exercises (compression, handshakes); the `groups`
//! of `captures/corpus/corpus.json5` says which, and the manifest reader refuses
//! a file in no group or in two.
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
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wz_session_core::passive::ReadingEvidence;

use crate::zenoh_corpus_tests::{corpus_dir, manifest};
use crate::zenoh_evidence::tests as fit;
use crate::zenoh_evidence::{cookie_echo_weight, model, Check, Weight, ZenohEvidence};
use crate::Dissection;

/// The outcomes a flow's sums are made of.
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
pub(crate) struct Flow {
    pub(crate) counts: Counts,
    pub(crate) yes: i64,
    pub(crate) no: i64,
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

pub(crate) fn read_corpus() -> Vec<File> {
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
                group: entry.group,
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

/// The calibration the corpus gives: the zenoh files' counts, each null file's,
/// and the table of weights counted from them.
struct Calibration {
    zenoh: Counts,
    /// Each null file, in the manifest's order, with its counts.
    null: Vec<(String, Counts)>,
    table: Table,
    /// `log2(1 - e)` of the cookie echo, which the table holds added to the
    /// bytes it counts.
    cookie_fidelity: i64,
    zenoh_files: usize,
    zenoh_groups: usize,
    null_groups: usize,
}

fn calibrate(files: &[File]) -> Calibration {
    let mut zenoh = Counts::default();
    let mut null = Vec::new();
    for f in files {
        if f.zenoh {
            zenoh.and(&f.counts);
        } else {
            null.push((f.name.clone(), f.counts));
        }
    }
    let members: Vec<&Counts> = null.iter().map(|(_, c)| c).collect();
    let table = Table::fitted(&zenoh, &members);
    let groups = |zenoh: bool| {
        files
            .iter()
            .filter(|f| f.zenoh == zenoh)
            .map(|f| f.group.as_str())
            .collect::<alloc::collections::BTreeSet<_>>()
            .len()
    };
    Calibration {
        cookie_fidelity: table.cookie[0].yes
            - model::COOKIE_ECHO_MAX_BYTES * model::COOKIE_ECHO_PER_BYTE,
        table,
        zenoh_files: files.iter().filter(|f| f.zenoh).count(),
        zenoh_groups: groups(true),
        null_groups: groups(false),
        zenoh,
        null,
    }
}

/// `1234567` as Rust writes it in the model: `1_234_567`.
fn lit(n: i64) -> String {
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

fn weight_literal(w: Weight) -> String {
    if w.yes == w.no {
        alloc::format!("Weight::both({})", lit(w.yes))
    } else {
        alloc::format!("Weight::pair({}, {})", lit(w.yes), lit(w.no))
    }
}

fn counts_literal(counts: &[u64]) -> String {
    let each: Vec<String> = counts.iter().map(|&n| lit(n as i64)).collect();
    alloc::format!("[{}]", each.join(", "))
}

/// The text of `zenoh_calibration_generated.rs` for this calibration. Laid out
/// as rustfmt lays it out, so that formatting the file changes nothing.
fn render(c: &Calibration) -> String {
    use core::fmt::Write as _;
    let mut out = String::new();
    let t = &c.table;
    out.push_str(
        "// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial\n\
         // SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael\n\n\
         //! GENERATED FROM `captures/corpus/` -- DO NOT EDIT.\n\
         //!\n\
         //! The counts of the corpus and the weights computed from them\n\
         //! (`docs/flow-zenoh-verdict.md` section 6.2), written by\n\
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
        "use crate::zenoh_evidence::model::measured::Member;\nuse crate::zenoh_evidence::Weight;\n\n",
    );
    let weights: [(&str, &str, Weight); 10] = [
        ("COOKIE_ECHO_VIOLATED", "a cookie that differs", t.cookie[1]),
        (
            "INIT_ROLES_CONFIRMED",
            "two Inits of opposite kinds",
            t.roles[0],
        ),
        (
            "INIT_ROLES_VIOLATED",
            "two Inits of the same kind",
            t.roles[1],
        ),
        (
            "VERSION_HEADER",
            "a version byte that is this reader's",
            t.versions[0],
        ),
        (
            "VERSION_FOREIGN",
            "a version byte that names another version",
            t.versions[1],
        ),
        ("UNIT_EXPLAINED", "a unit read whole", t.unit[0]),
        ("UNIT_RESIDUAL", "a unit with bytes left over", t.unit[1]),
        ("UNIT_UNDECODED", "a unit that did not decode", t.unit[2]),
        (
            "FRAMING_HELD",
            "a stream direction that framed a unit",
            t.framing[0],
        ),
        (
            "FRAMING_LOST",
            "a stream direction that lost its framing",
            t.framing[1],
        ),
    ];
    let _ = writeln!(
        out,
        "/// `log2(1 - e)` of the cookie echo, in millibits.\npub const COOKIE_ECHO_FIDELITY: i64 = {};\n",
        lit(c.cookie_fidelity)
    );
    for (name, what, weight) in weights {
        let _ = writeln!(
            out,
            "/// The weight of {what}.\npub const {name}: Weight = {};",
            weight_literal(weight)
        );
    }
    let _ = writeln!(
        out,
        "\n/// The null protocols, in the manifest's order.\npub const NULL: [Member; {}] = [",
        c.null.len()
    );
    for (file, counts) in &c.null {
        let _ = writeln!(
            out,
            "    Member {{\n        file: \"{file}\",\n        units: {},\n        framing: {},\n    }},",
            counts_literal(&counts.units),
            counts_literal(&counts.framing)
        );
    }
    out.push_str("];\n\n");
    let _ = writeln!(
        out,
        "/// The zenoh files' framing units: read whole, residual, undecoded.\npub const ZENOH_UNITS: [u64; 3] = {};\n\n\
         /// The zenoh files' stream directions captured from their start: framing held, lost.\npub const ZENOH_FRAMING: [u64; 2] = {};\n\n\
         /// The zenoh files' cookie echoes: matched, differing.\npub const ZENOH_COOKIE: [u64; 2] = {};\n\n\
         /// The zenoh files' Init pairs: of opposite kinds, of one kind.\npub const ZENOH_ROLES: [u64; 2] = {};\n\n\
         /// The zenoh files' version headers: this reader's, another.\npub const ZENOH_VERSIONS: [u64; 2] = {};",
        counts_literal(&c.zenoh.units),
        counts_literal(&c.zenoh.framing),
        counts_literal(&c.zenoh.cookie),
        counts_literal(&c.zenoh.roles),
        counts_literal(&c.zenoh.versions)
    );
    out
}

fn generated_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/zenoh_calibration_generated.rs")
}

/// `1234` as the design note's table writes it: signed, no separators.
fn signed(n: i64) -> String {
    if n > 0 {
        alloc::format!("+{n}")
    } else {
        alloc::format!("{n}")
    }
}

/// THE GENERATED FILE IS WHAT THE CORPUS GIVES. `zenoh_calibration_generated.rs`
/// holds the counts and the weights, and nobody writes it: this test renders it
/// from the corpus and fails with the first line that differs when the file is
/// not that. With `WZ_BLESS_CALIBRATION` set it writes the file instead, which is
/// what `scripts/regen-calibration.sh` does, so a capture added to the corpus
/// moves the model by one command and not by twelve edits.
///
/// The design note's numbers are held to the same calibration: its weight table
/// and the counts it states are not generated, and drifting from the file is
/// what this fails on.
#[test]
fn the_generated_calibration_is_current() {
    let files = read_corpus();
    let calibration = calibrate(&files);
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

    // The design note: its weight table and its counts are the generated ones.
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/flow-zenoh-verdict.md"),
    )
    .expect("docs/flow-zenoh-verdict.md reads");
    let t = &calibration.table;
    let rows = [
        ("unit read whole", t.unit[0]),
        ("unit residual", t.unit[1]),
        ("unit undecoded", t.unit[2]),
        ("stream framing held", t.framing[0]),
        ("stream framing lost", t.framing[1]),
        ("cookie matched (8 bytes)", t.cookie[0]),
        ("cookie differing", t.cookie[1]),
        ("Inits of opposite kinds", t.roles[0]),
        ("Inits of one kind", t.roles[1]),
        ("version of this reader", t.versions[0]),
        ("another version", t.versions[1]),
    ];
    let mut stale = Vec::new();
    for (name, w) in rows {
        let row = alloc::format!("| {name} | {} | {} |", signed(w.yes), signed(w.no));
        if !doc.contains(&row) {
            stale.push(row);
        }
    }
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
        "docs/flow-zenoh-verdict.md section 6.2 does not say what the corpus gives; it should \
         hold:\n{}",
        stale.join("\n")
    );
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

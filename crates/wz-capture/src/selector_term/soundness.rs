// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE SOUNDNESS PROPERTY of the sentences a node offers, as one oracle that
//! every population is held to: the library's own tests, and the fuzz target
//! that reads the fuzzers' evolving capture corpus through the C doors.
//!
//! # The property
//!
//! For every record `r` and every node `n` of `r`'s tree whose `selector_path`
//! is not `null`:
//!
//! * (S1) the node's FILTER sentence `t` is `yes` over `r`;
//! * (S2) its EXCLUDE sentence is `no` over `r`.
//!
//! And of the nodes themselves:
//!
//! * (N1) every node a document writes carries `selector_path`, a path or
//!   `null`, and nothing else;
//! * (N2) a node offers a sentence exactly when its path is not `null` and its
//!   row is judged; a refusal of any other word is a defect of the library and
//!   not of the node.
//!
//! # How each part is decided: three levels, each exhaustive where it is cheap
//!
//! 1. THE RECORD LEVEL ([`hold_records`]) decides S1 for EVERY node of EVERY
//!    record of a capture. The record's tree is built by the functions the
//!    selector's planes build it with (`field_path`'s `FrameEnvelope::of`
//!    and `record_tree`, which are the crate's own, over the bytes
//!    `CaptureOrder::held_message_bytes` holds), so the verdict is the one a
//!    plane reaches. What it proves is kept ([`Proven`]): per row ([`RowAt`],
//!    the row's flow, direction and anchor as the document writes them), the
//!    sentences some record of that row answers `yes`. The tree of a record
//!    joined out of `Fragment`s is read with the `Fragment` beside it, whose
//!    nodes the row shows too.
//! 2. THE BRIDGE ([`hold_document`]) holds the consumer's path to that proof,
//!    for EVERY node of EVERY row: the field document is rendered once, each
//!    node object is handed back to the `selector_term` door as a consumer
//!    hands it, and the sentence the door offers must be one the record level
//!    proved for that row. A sentence the door offers and no record answers is
//!    an S1 violation found without rendering anything more.
//! 3. THE FOLD is what is left between a record's verdict and the row's word,
//!    a row's word being its records' verdicts folded (any `yes` makes it
//!    `yes`). It is confirmed under the rendered document itself, once per row
//!    and word: a greedy set cover picks the fewest sentences whose wants reach
//!    every row, and each picked sentence is rendered and read at EVERY row it
//!    wants a word on. Rendering a document per sentence instead costs a whole
//!    capture per node, which is what the first form of this oracle did and why
//!    it did not finish.
//!
//! S2 is a consequence of S1 and of the exclusion's FORM, and the form is what
//! is decided: the exclusion parses to exactly the negation of `t`
//! ([`Filter::negated`]), and under the selector's three-valued `not` the
//! negation of `yes` is `no`. That decides S2 for every record without asking
//! which of a row's records said what, which the row's fold does not keep. The
//! fold confirms it where the fold does decide it: a row that is one record,
//! and a node of a `Frame` outside the records it carries, which every record
//! of the row holds.
//!
//! # Why the document level takes its doors as a trait
//!
//! The same oracle runs over the library's renderer in a test and over the
//! `extern "C"` doors in the fuzz target, which is the path a consumer takes. A
//! second copy of the property for the second caller would be the failure the
//! sentences exist to end, one level up.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use super::{term_for, ShownValue, TermRefusal, Verb};
use crate::filter::{Content, Filter, Record, RecordView, Truth};
use wz_session_core::json5::{self, Json5Value};

/// The selector the first document is rendered under: one every judged row
/// answers, so every row carries its `selected` word and a row the selector
/// does not judge says so (`unjudged`).
pub const PROBE: &str = "dir == a or dir == b";

/// How many violations of one class a report keeps word for word; the rest
/// are counted, so one cause does not hide the others.
const KEPT_PER_CLASS: usize = 3;

/// The doors the document level is held through.
pub trait Doors {
    /// The field document of the capture, every row judged under `selector`,
    /// or `None` where the capture is not one the door reads.
    fn document(&mut self, selector: &str) -> Option<String>;
    /// The `selector_term` document for the field object `node` and `verb`,
    /// nothing typed.
    fn term(&mut self, node: &str, verb: Verb) -> String;
}

/// What the oracle walked, and every way the property failed.
#[derive(Debug, Default, Clone)]
pub struct Soundness {
    /// Documents rendered.
    pub documents: usize,
    /// Rows read: of the document, and of the capture at the record level.
    pub rows: usize,
    /// Records whose tree was built at the record level.
    pub records: usize,
    /// Nodes walked.
    pub nodes: usize,
    /// Nodes whose path is `null`.
    pub unnamed: usize,
    /// Nodes of a row the selector does not judge.
    pub unjudged: usize,
    /// Sentences judged.
    pub sentences: usize,
    /// The message kinds walked: a root, and under a `Frame` each record's.
    pub kinds: BTreeSet<String>,
    /// How many violations there were.
    pub violation_count: usize,
    /// How many there were of each class: the rule broken and the message
    /// kind it was broken on, so a report of thousands reads as a few causes.
    pub classes: BTreeMap<String, usize>,
    /// The first few of each class, word for word.
    pub violations: BTreeMap<String, Vec<String>>,
}

impl Soundness {
    fn violate(&mut self, class: String, what: String) {
        self.violation_count += 1;
        *self.classes.entry(class.clone()).or_default() += 1;
        self.keep(class, what);
    }

    fn keep(&mut self, class: String, what: String) {
        let kept = self.violations.entry(class).or_default();
        if kept.len() < KEPT_PER_CLASS {
            kept.push(what);
        }
    }

    /// Add `other`'s counts and violations to this one's.
    pub fn absorb(&mut self, other: Self) {
        self.documents += other.documents;
        self.rows += other.rows;
        self.records += other.records;
        self.nodes += other.nodes;
        self.unnamed += other.unnamed;
        self.unjudged += other.unjudged;
        self.sentences += other.sentences;
        self.kinds.extend(other.kinds);
        self.violation_count += other.violation_count;
        for (class, n) in other.classes {
            *self.classes.entry(class).or_default() += n;
        }
        for (class, kept) in other.violations {
            for v in kept {
                self.keep(class.clone(), v);
            }
        }
    }

    /// Whether the property held over everything walked.
    pub fn holds(&self) -> bool {
        self.violation_count == 0
    }
}

impl fmt::Display for Soundness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} documents, {} rows, {} records, {} nodes ({} with no path, {} on rows \
             not judged), {} sentences judged, {} message kinds {:?}, {} violations",
            self.documents,
            self.rows,
            self.records,
            self.nodes,
            self.unnamed,
            self.unjudged,
            self.sentences,
            self.kinds.len(),
            self.kinds,
            self.violation_count,
        )?;
        let mut classes: Vec<(&String, &usize)> = self.classes.iter().collect();
        classes.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (class, n) in classes {
            write!(f, "\n  {n:>7}  {class}")?;
            for v in self.violations.get(class).into_iter().flatten() {
                write!(f, "\n             {v}")?;
            }
        }
        Ok(())
    }
}

/// WHERE A ROW STANDS, as the field document writes it and as the record level
/// computes it with the functions the document is written by: the flow object
/// the row is listed under, the direction, the anchor's space, and the anchor
/// in it (the packet index, or the message's byte in its direction's stream).
///
/// Two lists of one flow in one space (the RFC 9221 streams of one QUIC flow)
/// can share an anchor; a proof there is a proof of one of them, and the fold
/// still reads every row by itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RowAt {
    flow: String,
    direction: String,
    space: String,
    anchor: u64,
}

impl RowAt {
    /// The row a field document's row object `row` is, listed under the flow
    /// object `flow`; `None` for a row that names no anchor.
    fn of_document(flow: &Json5Value, row: &Json5Value) -> Option<Self> {
        let word = |key: &str| match row.get(key) {
            Some(Json5Value::String(w)) => Some(w.clone()),
            _ => None,
        };
        let space = word("offset_space")?;
        let anchor_key = if space == crate::AnchorSpace::PacketIndex.name() {
            "packet"
        } else {
            "message_at"
        };
        let anchor = match row.get(anchor_key) {
            Some(Json5Value::Number(n)) => n.parse::<u64>().ok()?,
            _ => return None,
        };
        Some(Self {
            flow: serialise(flow),
            direction: word("direction")?,
            space,
            anchor,
        })
    }

    /// The row the record level reads `frame` as, of `flow`: its anchor as the
    /// document writes it, the packet a packet-anchored frame names and the
    /// byte a stream message begins at.
    fn of_frame(
        flow: &crate::link::FlowKey,
        frame: &wz_session_core::passive::PassiveFrame,
    ) -> Self {
        let mut written = String::new();
        crate::census_json::push_flow(flow, &mut written);
        // Read back and written again, as the document's flow object is.
        let flow = json5::parse(&written).map_or(written, |v| serialise(&v));
        let space = crate::anchor_space_of(frame);
        Self {
            flow,
            direction: String::from(crate::census_json::dir_name(frame.direction)),
            space: String::from(space.name()),
            anchor: match space {
                crate::AnchorSpace::PacketIndex => frame.stream_offset as u64,
                crate::AnchorSpace::StreamBytes => crate::FlowDissection::message_at(frame) as u64,
            },
        }
    }
}

impl fmt::Display for RowAt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.flow, self.direction, self.space, self.anchor
        )
    }
}

/// What the record level proved: for each row, every Filter sentence some
/// record of that row answers `yes`.
#[derive(Debug, Default, Clone)]
pub struct Proven {
    by_row: BTreeMap<RowAt, BTreeSet<String>>,
}

impl Proven {
    fn prove(&mut self, row: &RowAt, sentence: String) {
        self.by_row.entry(row.clone()).or_default().insert(sentence);
    }

    /// Whether a record of `row` answers `sentence` `yes`.
    pub fn holds(&self, row: &RowAt, sentence: &str) -> bool {
        self.by_row
            .get(row)
            .is_some_and(|proved| proved.contains(sentence))
    }

    /// The first row some record of which answers `sentence` `yes`.
    pub fn first_row_of(&self, sentence: &str) -> Option<&RowAt> {
        self.by_row
            .iter()
            .find_map(|(row, proved)| proved.contains(sentence).then_some(row))
    }
}

/// Both levels over one capture.
#[derive(Debug, Default, Clone)]
pub struct Held {
    /// The record level: every node of every record.
    pub records: Soundness,
    /// The bridge and the fold, over the document a consumer reads.
    pub document: Soundness,
}

impl Held {
    /// Whether the property held at both levels.
    pub fn holds(&self) -> bool {
        self.records.holds() && self.document.holds()
    }

    /// Add `other`'s two reports to this one's.
    pub fn absorb(&mut self, other: Self) {
        self.records.absorb(other.records);
        self.document.absorb(other.document);
    }
}

impl fmt::Display for Held {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "record level: {}\ndocument level: {}",
            self.records, self.document
        )
    }
}

/// THE PROPERTY over one capture: the record level over `d`, then the document
/// `doors` renders of the same capture held to what it proved.
pub fn hold(doors: &mut dyn Doors, d: &crate::Dissection) -> Held {
    let (records, proven) = hold_records(d);
    let document = hold_document(doors, &proven);
    Held { records, document }
}

/// The fewest sentences (greedily) whose wants reach every `(row, word)` some
/// sentence wants, in the order picked. Ties go to the first sentence in
/// order, so the pick is the same every run.
fn cover<'w>(wants: &'w BTreeMap<String, Vec<(usize, &'static str)>>) -> Vec<&'w str> {
    let mut open: BTreeSet<(usize, &'static str)> = wants.values().flatten().copied().collect();
    let mut picked = Vec::new();
    while !open.is_empty() {
        let mut best: Option<(&str, usize)> = None;
        for (sentence, rows) in wants {
            let reach = rows.iter().filter(|w| open.contains(*w)).count();
            if reach > best.map_or(0, |(_, r)| r) {
                best = Some((sentence, reach));
            }
        }
        let Some((sentence, _)) = best else {
            break;
        };
        for w in &wants[sentence] {
            open.remove(w);
        }
        picked.push(sentence);
    }
    picked
}

/// S2's form: `exclusion` is exactly the negation of `term`.
fn excludes_by_negation(term: &str, exclusion: &str) -> Result<(), String> {
    let term = Filter::parse(term).map_err(|e| alloc::format!("`{term}` does not compile: {e}"))?;
    let exclusion = Filter::parse(exclusion)
        .map_err(|e| alloc::format!("`{exclusion}` does not compile: {e}"))?;
    if exclusion == term.negated() {
        Ok(())
    } else {
        Err(String::from("the exclusion is not the sentence's negation"))
    }
}

/// THE BRIDGE AND THE FOLD: the field document `doors` renders, each node
/// object handed back as a consumer hands it and its sentence held to what the
/// record level `proven`, and the document under a cover of the sentences.
pub fn hold_document(doors: &mut dyn Doors, proven: &Proven) -> Soundness {
    let mut report = Soundness::default();
    let Some(doc) = doors.document(PROBE) else {
        return report;
    };
    report.documents += 1;
    let parsed = match json5::parse(&doc) {
        Ok(p) => p,
        Err(e) => {
            report.violate(
                String::from("document unreadable"),
                alloc::format!("the field document is not JSON: {e}"),
            );
            return report;
        }
    };
    let rows = rows_of(&parsed);
    let probed = selected_words(&doc);
    if rows.len() != probed.len() {
        report.violate(
            String::from("document rows miscounted"),
            alloc::format!(
                "{} rows carry `selected` and {} `selected` words were read",
                rows.len(),
                probed.len()
            ),
        );
        return report;
    }
    report.rows += rows.len();
    // sentence -> the rows it must say a word on.
    let mut wants: BTreeMap<String, Vec<(usize, &'static str)>> = BTreeMap::new();
    // Each row's class: its message kind and how many records it carried.
    let mut row_class: Vec<String> = alloc::vec![String::new(); rows.len()];
    for (k, (flow, row)) in rows.iter().enumerate() {
        let Some(root) = row.get("fields") else {
            continue;
        };
        let records = match row.get("carried") {
            Some(Json5Value::Array(c)) => c.len(),
            _ => 0,
        };
        let judged = probed[k] != "unjudged";
        // Where the row stands, which the record level keys what it proved by.
        let at = flow.and_then(|flow| RowAt::of_document(flow, row));
        let root_name = match root.get("name") {
            Some(Json5Value::String(n)) => n.clone(),
            _ => String::new(),
        };
        report.kinds.insert(root_name.clone());
        row_class[k] = alloc::format!(
            "{root_name}, {} record{}, probed `{}`",
            records,
            if records == 1 { "" } else { "s" },
            probed[k]
        );
        let class = |rule: &str| alloc::format!("{rule}: {}", row_class[k]);
        let framed = root_name == wz_session_core::dissect_schema::BATCH_CARRIER;
        // A node of the transport message every record of the row stands in
        // or beside: a `Frame` outside its records, and all of a `Fragment`.
        let carrier = framed || root_name == wz_session_core::dissect_schema::PIECE_CARRIER;
        // A batch whose walk stopped part way holds a record no reader read
        // in the fold (the bytes after the stop): it decides a node of the
        // transport message as every record does, and leaves a node of a
        // record undecided, so an exclusion of such a node does not fold to
        // `no` on its row. The document shows the stop as an `unparsed`
        // remainder.
        let halted = framed && batch_halted(root);
        // (node, inside one of the records a `Frame` carries)
        let mut stack: Vec<(&Json5Value, bool, usize)> = alloc::vec![(root, false, 0)];
        while let Some((node, in_record, depth)) = stack.pop() {
            let name = match node.get("name") {
                Some(Json5Value::String(n)) => n.as_str(),
                _ => "",
            };
            if let Some(Json5Value::Array(children)) = node.get("fields") {
                // A `Frame`'s records are the children of its payload group.
                let holds_records =
                    framed && depth == 1 && name == wz_session_core::dissect_schema::BATCH_LEVEL;
                for child in children {
                    if holds_records {
                        if let Some(Json5Value::String(n)) = child.get("name") {
                            report.kinds.insert(alloc::format!("{root_name}.{n}"));
                        }
                    }
                    stack.push((child, in_record || holds_records, depth + 1));
                }
            }
            report.nodes += 1;
            let path = match node.get("selector_path") {
                Some(Json5Value::String(p)) => Some(p.clone()),
                Some(Json5Value::Null) => None,
                other => {
                    report.violate(
                        class("N1 not a path"),
                        alloc::format!(
                            "row {k}: node `{name}` carries selector_path {other:?}, neither a \
                             path nor null (N1)"
                        ),
                    );
                    continue;
                }
            };
            let text = serialise(node);
            let filter = doors.term(&text, Verb::Filter);
            let filter = match verdict(&filter) {
                Verdict::Sentence { term, selector } => (term, selector),
                Verdict::Refused(word) => {
                    match (word.as_str(), &path, judged) {
                        ("unnamed", None, _) => report.unnamed += 1,
                        ("unjudged", Some(_), false) => report.unjudged += 1,
                        _ => report.violate(
                            class(&alloc::format!("N2 refused `{word}`")),
                            alloc::format!("row {k}: {path:?} is refused `{word}` (N2): {filter}"),
                        ),
                    }
                    continue;
                }
                Verdict::Unreadable => {
                    report.violate(
                        class("N2 unreadable verdict"),
                        alloc::format!("row {k}: {path:?}: an unreadable verdict: {filter}"),
                    );
                    continue;
                }
            };
            if path.is_none() || !judged {
                report.violate(
                    class(if judged {
                        "N2 a node with no path offers a sentence"
                    } else {
                        "N2 a row not judged offers a sentence"
                    }),
                    alloc::format!(
                        "row {k}: node `{name}` with path {path:?} on a row {} offers `{}` (N2)",
                        if judged { "judged" } else { "not judged" },
                        filter.1
                    ),
                );
                continue;
            }
            let exclude = doors.term(&text, Verb::Exclude);
            match verdict(&exclude) {
                Verdict::Sentence { term, selector } if term == filter.0 => {
                    if let Err(why) = excludes_by_negation(&term, &selector) {
                        report.violate(
                            class("S2 form"),
                            alloc::format!("row {k}: `{selector}`: {why} (S2)"),
                        );
                    }
                    report.sentences += 1;
                    match &at {
                        Some(at) if proven.holds(at, &filter.1) => {}
                        _ => {
                            let elsewhere = proven.first_row_of(&filter.1);
                            report.violate(
                                class(if elsewhere.is_some() {
                                    "S1 proved on another row only"
                                } else {
                                    "S1 proved on no row"
                                }),
                                alloc::format!(
                                    "row {k} ({}): `{}` is offered for `{name}` and no record of \
                                     that row answers it `yes`; first proved on {} (S1)",
                                    at.as_ref().map_or(String::from("no anchor"), |a| {
                                        alloc::format!("{a}")
                                    }),
                                    filter.1,
                                    elsewhere
                                        .map_or(String::from("none"), |a| alloc::format!("{a}")),
                                ),
                            )
                        }
                    }
                    wants.entry(filter.1.clone()).or_default().push((k, "yes"));
                    if (!halted && records <= 1) || (carrier && !in_record) {
                        wants.entry(selector).or_default().push((k, "no"));
                    }
                }
                _ => report.violate(
                    class("S2 no exclusion"),
                    alloc::format!(
                        "row {k}: {path:?} filters by `{}` and excludes by {exclude}",
                        filter.0
                    ),
                ),
            }
        }
    }
    for sentence in cover(&wants) {
        let rows = &wants[sentence];
        let Some(doc) = doors.document(sentence) else {
            report.violate(
                String::from("a sentence renders no document"),
                alloc::format!("`{sentence}` renders no document"),
            );
            continue;
        };
        report.documents += 1;
        let words = selected_words(&doc);
        if words.len() != probed.len() {
            report.violate(
                String::from("a sentence renders other rows"),
                alloc::format!(
                    "`{sentence}` renders {} rows, the probe {}",
                    words.len(),
                    probed.len()
                ),
            );
            continue;
        }
        for &(k, want) in rows {
            if words[k] != want {
                let rule = if want == "yes" { "S1" } else { "S2" };
                report.violate(
                    alloc::format!("{rule} fold reads `{}`: {}", words[k], row_class[k]),
                    alloc::format!(
                        "row {k}: `{sentence}` reads `{}`, not `{want}` ({rule})",
                        words[k]
                    ),
                );
            }
        }
    }
    report
}

/// Whether the `Frame` node object `root` shows its batch's walk stopped: an
/// `unparsed` remainder under its `payload`.
fn batch_halted(root: &Json5Value) -> bool {
    let Some(Json5Value::Array(children)) = root.get("fields") else {
        return false;
    };
    children
        .iter()
        .filter(|c| {
            matches!(c.get("name"), Some(Json5Value::String(n))
                if n == wz_session_core::dissect_schema::BATCH_LEVEL)
        })
        .filter_map(|payload| match payload.get("fields") {
            Some(Json5Value::Array(records)) => Some(records),
            _ => None,
        })
        .flatten()
        .any(|r| {
            matches!(r.get("name"), Some(Json5Value::String(n))
                if n == wz_session_core::dissect_schema::BATCH_REMAINDER)
        })
}

/// A `selector_term` document, read.
enum Verdict {
    Sentence { term: String, selector: String },
    Refused(String),
    Unreadable,
}

fn verdict(doc: &str) -> Verdict {
    let Ok(parsed) = json5::parse(doc) else {
        return Verdict::Unreadable;
    };
    match (
        parsed.get("term"),
        parsed.get("selector"),
        parsed.get("refusal"),
    ) {
        (Some(Json5Value::String(term)), Some(Json5Value::String(selector)), None) => {
            Verdict::Sentence {
                term: term.clone(),
                selector: selector.clone(),
            }
        }
        (None, None, Some(Json5Value::String(word))) => Verdict::Refused(word.clone()),
        _ => Verdict::Unreadable,
    }
}

/// The `selected` word of every row of a field document, in document order.
fn selected_words(doc: &str) -> Vec<String> {
    let needle = "\"selected\":\"";
    let mut out = Vec::new();
    let mut rest = doc;
    while let Some(at) = rest.find(needle) {
        rest = &rest[at + needle.len()..];
        let Some(end) = rest.find('"') else {
            break;
        };
        out.push(rest[..end].to_string());
        rest = &rest[end..];
    }
    out
}

/// The row objects of a field document: every object carrying a `selected`
/// word, in document order, each with the `flow` object of the list it is
/// listed under (`None` for one listed under none).
fn rows_of(value: &Json5Value) -> Vec<(Option<&Json5Value>, &Json5Value)> {
    type Rows<'v> = Vec<(Option<&'v Json5Value>, &'v Json5Value)>;
    fn walk<'v>(value: &'v Json5Value, flow: Option<&'v Json5Value>, out: &mut Rows<'v>) {
        match value {
            Json5Value::Object(entries) => {
                if entries
                    .iter()
                    .any(|(k, v)| k == "selected" && matches!(v, Json5Value::String(_)))
                {
                    out.push((flow, value));
                }
                // A list object names its flow beside its `messages`.
                let flow = match (value.get("flow"), value.get("messages")) {
                    (Some(f @ Json5Value::Object(_)), Some(_)) => Some(f),
                    _ => flow,
                };
                for (_, v) in entries {
                    walk(v, flow, out);
                }
            }
            Json5Value::Array(items) => items.iter().for_each(|i| walk(i, flow, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, None, &mut out);
    out
}

/// A JSON value written back out, as a consumer hands back the object it read.
pub fn serialise(value: &Json5Value) -> String {
    let mut out = String::new();
    serialise_into(value, &mut out);
    out
}

fn serialise_into(value: &Json5Value, out: &mut String) {
    match value {
        Json5Value::Null => out.push_str("null"),
        Json5Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json5Value::Number(n) => out.push_str(n),
        Json5Value::String(s) => wz_session_core::json::escape_into(s, out),
        Json5Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialise_into(item, out);
            }
            out.push(']');
        }
        Json5Value::Object(entries) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                wz_session_core::json::escape_into(k, out);
                out.push(':');
                serialise_into(v, out);
            }
            out.push('}');
        }
    }
}

/// The record a path's view stands for: every axis but the tree at a value no
/// path term reads.
fn view(tree: &crate::field_path::RecordTree) -> RecordView<'_> {
    RecordView {
        direction: wz_session_core::passive::Direction::A,
        keyexpr: None,
        kind: Record::None,
        payload_bytes: None,
        value: Content::Unavailable,
        observed_at_ms: None,
        elapsed_ms: None,
        unit_offset: None,
        source_delay_ms: None,
        outcome: None,
        zid: None,
        tree: Some(tree),
        row: None,
    }
}

/// THE RECORD LEVEL: every record of every row of `d`, its tree built as the
/// selector's planes build it, and every node of that tree; and what it proved,
/// for the document level to hold the consumer's path to.
pub fn hold_records(d: &crate::Dissection) -> (Soundness, Proven) {
    use crate::field_path::RecordTree;
    use wz_session_core::dissect::FieldValue;
    use wz_session_core::passive::Carried;

    let mut report = Soundness::default();
    let mut proven = Proven::default();
    let order = d.message_frames_in_capture_order();
    for (flow, list, _, row) in order.iter() {
        report.rows += 1;
        let at = RowAt::of_frame(&flow, &row);
        let held = order.held_message_bytes(d, list, &row);
        // The records of a batch, and the part past where its walk stopped,
        // read as the row plane reads it ([`crate::field_path::remainder_tree`]).
        let trees: Vec<RecordTree> = match &row.carried {
            Carried::Batch(batch) => batch_trees(&mut report, &row, held.as_deref(), batch, &at),
            #[cfg(feature = "reassembly")]
            Carried::Reassembled { batch, .. } => {
                batch_trees(&mut report, &row, held.as_deref(), batch, &at)
            }
            // A row that is its message, decoded or not: the field document
            // and the row plane both read it from the bytes the capture keeps.
            _ => match held
                .as_deref()
                .map(|b| wz_session_core::dissect::dissect_transport_message(b, 0))
            {
                Some(Ok(root)) => alloc::vec![RecordTree::transport(root)],
                Some(Err(_)) => Vec::new(),
                None => {
                    report.violate(
                        alloc::format!(
                            "a row's bytes are not held: {}",
                            row.frame.as_ref().map_or("undecodable", |f| f.kind_name())
                        ),
                        alloc::format!("{at}: the capture keeps no bytes of this row's message"),
                    );
                    Vec::new()
                }
            },
        };
        for tree in trees {
            report.records += 1;
            let root = tree.root();
            report.kinds.insert(root.name.to_string());
            if let FieldValue::Nested(children) = &root.value {
                for group in children
                    .iter()
                    .filter(|c| c.name == wz_session_core::dissect_schema::BATCH_LEVEL)
                {
                    if let FieldValue::Nested(records) = &group.value {
                        for r in records {
                            report
                                .kinds
                                .insert(alloc::format!("{}.{}", root.name, r.name));
                        }
                    }
                }
            }
            // The record's tree, and the tree beside it where one stands (the
            // `Fragment` it was joined in): every node of both is one a row
            // shows.
            let beside = tree.beside_tree().map(crate::field_path::RecordTree::root);
            for part in core::iter::once(root).chain(beside) {
                hold_nodes(&mut report, &mut proven, &tree, part, &at);
            }
        }
    }
    (report, proven)
}

/// The trees of the records of `batch`, which `row` carried, and of the part
/// past where its walk stopped, read as the planes read them from `held`, the
/// bytes of the row's transport message. A record whose tree fails to build
/// is no record the oracle read, and is reported with why rather than passed
/// over.
fn batch_trees(
    report: &mut Soundness,
    row: &wz_session_core::passive::PassiveFrame,
    held: Option<&[u8]>,
    batch: &wz_session_core::network_message::BatchParse,
    at: &RowAt,
) -> Vec<crate::field_path::RecordTree> {
    use crate::field_path::{record_tree, FrameEnvelope};
    let envelope = FrameEnvelope::of(row, held);
    let mut trees = Vec::new();
    for (message, span) in batch.records() {
        // A MID no codec knows is where the session's walk stopped: its bytes
        // are the remainder, read once below as the row plane reads them.
        if matches!(
            message,
            wz_session_core::network_message::NetworkMessage::Unknown { .. }
        ) {
            continue;
        }
        match record_tree(row, &envelope, span) {
            Some(tree) => trees.push(tree),
            None => report.violate(
                alloc::format!(
                    "a record's tree is not built: {} {}",
                    message.name(),
                    if span.is_none() {
                        "with no span"
                    } else {
                        "that does not walk"
                    }
                ),
                alloc::format!(
                    "{at}: the {} record at {span:?} has no tree a plane reads",
                    message.name()
                ),
            ),
        }
    }
    if crate::field_path::has_an_unread_remainder(Some(&envelope), batch) {
        trees.extend(crate::field_path::remainder_tree(row, &envelope, batch));
    } else if batch.records().next().is_none() {
        // A batch read to its end that held no record: the row is its
        // transport message, as the row plane reads it.
        trees.extend(crate::field_path::empty_batch_tree(&envelope));
    }
    trees
}

/// S1 and S2's form for every node of `part`, a tree the record `tree` is read
/// over (its root, or the transport message beside it), what is proved kept
/// for the row `at`.
fn hold_nodes(
    report: &mut Soundness,
    proven: &mut Proven,
    tree: &crate::field_path::RecordTree,
    part: &wz_session_core::dissect::Field,
    at: &RowAt,
) {
    use wz_session_core::dissect::{Field, FieldValue};
    let paths = wz_session_core::dissect_schema::node_paths(part);
    let mut stack: Vec<&Field> = alloc::vec![part];
    while let Some(node) = stack.pop() {
        if let FieldValue::Nested(children) = &node.value {
            stack.extend(children.iter());
        }
        report.nodes += 1;
        let path = paths.of(node);
        let value = ShownValue::of(&node.value);
        let filter = match term_for(path, &value, Verb::Filter, "") {
            Ok(s) => s.selector,
            Err(TermRefusal::Unnamed) => {
                report.unnamed += 1;
                continue;
            }
            Err(e) => {
                report.violate(
                    alloc::format!("N2 refused `{}`: {}", e.word(), part.name),
                    alloc::format!("{path:?}: refused: {e} (N2)"),
                );
                continue;
            }
        };
        report.sentences += 1;
        let got = Filter::parse(&filter)
            .map(|f| f.matches(&view(tree)))
            .map_err(|e| e.to_string());
        if got == Ok(Truth::Yes) {
            proven.prove(at, filter);
        } else {
            report.violate(
                alloc::format!("S1 record reads {got:?}: {}", part.name),
                alloc::format!(
                    "`{filter}` is {got:?} over the {} record whose tree holds the node (S1)",
                    tree.root().name
                ),
            );
        }
        match term_for(path, &value, Verb::Exclude, "") {
            Ok(s) => {
                if let Err(why) = excludes_by_negation(&s.term, &s.selector) {
                    report.violate(
                        alloc::format!("S2 form: {}", part.name),
                        alloc::format!("`{}`: {why} (S2)", s.selector),
                    );
                }
            }
            Err(e) => report.violate(
                alloc::format!("S2 no exclusion: {}", part.name),
                alloc::format!("{path:?}: excludes by nothing: {e}"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wants(
        rows: &[(&str, &[(usize, &'static str)])],
    ) -> BTreeMap<String, Vec<(usize, &'static str)>> {
        rows.iter()
            .map(|(s, w)| (String::from(*s), w.to_vec()))
            .collect()
    }

    #[test]
    fn the_cover_reaches_every_row_and_word_with_the_fewest_it_finds() {
        let w = wants(&[
            ("a", &[(0, "yes")]),
            ("b", &[(0, "yes"), (1, "yes"), (2, "yes")]),
            ("c", &[(2, "no")]),
            ("d", &[(1, "yes"), (2, "yes")]),
        ]);
        let picked = cover(&w);
        // `b` reaches three, `c` the one left; `a` and `d` add nothing.
        assert_eq!(picked, ["b", "c"]);
        let reached: BTreeSet<(usize, &str)> =
            picked.iter().flat_map(|s| w[*s].iter().copied()).collect();
        let wanted: BTreeSet<(usize, &str)> = w.values().flatten().copied().collect();
        assert_eq!(reached, wanted);
        // The same wants pick the same sentences.
        assert_eq!(cover(&w), picked);
        assert!(cover(&BTreeMap::new()).is_empty());
    }

    fn row(direction: &str, space: &str, anchor: u64) -> RowAt {
        RowAt {
            flow: String::from("{\"low\":1,\"high\":2}"),
            direction: String::from(direction),
            space: String::from(space),
            anchor,
        }
    }

    #[test]
    fn a_proof_is_kept_at_its_row_and_nowhere_else() {
        let mut proven = Proven::default();
        let at = row("a", "stream_byte", 40);
        proven.prove(&at, String::from("Frame.sn == 9"));
        assert!(proven.holds(&at, "Frame.sn == 9"));
        assert!(!proven.holds(&at, "Frame.sn == 8"));
        // The same anchor in the other direction, or in the other space, is
        // another row.
        assert!(!proven.holds(&row("b", "stream_byte", 40), "Frame.sn == 9"));
        assert!(!proven.holds(&row("a", "packet", 40), "Frame.sn == 9"));
        assert_eq!(proven.first_row_of("Frame.sn == 9"), Some(&at));
    }

    /// A document row names its anchor by the key its space reads it at, and a
    /// row whose anchor is missing is no row.
    #[test]
    fn a_document_row_is_read_at_the_anchor_its_space_names() {
        let flow = json5::parse("{\"low\":1,\"high\":2}").expect("json");
        let read = |text: &str| RowAt::of_document(&flow, &json5::parse(text).expect("json"));
        assert_eq!(
            read("{\"direction\":\"a\",\"offset_space\":\"stream_byte\",\"message_at\":40}"),
            Some(row("a", "stream_byte", 40))
        );
        assert_eq!(
            read("{\"direction\":\"b\",\"offset_space\":\"packet\",\"packet\":7}"),
            Some(row("b", "packet", 7))
        );
        assert_eq!(
            read("{\"direction\":\"a\",\"offset_space\":\"stream_byte\",\"packet\":7}"),
            None
        );
    }
}

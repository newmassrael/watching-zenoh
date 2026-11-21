// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The conformance corpus of the fixed records of a protected frame
//! (`conformance/fixed_records.json5`, its format in `conformance/README.md`): the bytes a
//! layout builds from its values, the record a receiver opens from them (`e2e_opened`), the
//! values a layout refuses, and the policy a receiver judges by (`e2e_policy`).
//!
//! Every vector runs through the hand-written builder and opener of `crate::e2e_frame` and the
//! receiver of `crate::e2e_receiver`, and, behind `sce-generated-codec`, through the codecs SCE
//! generates from the same layouts. The runner and the records are written once against `Codec`,
//! so a generated codec is held to the corpus unchanged.
//!
//! The profile language states a split word part by part, so a value over several runs of a word
//! is cut here into the parts that hold its runs, and the refusal of one of those parts is
//! reported at the value.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::e2e_crc::width_mask;
use crate::e2e_frame::{self, BuildError, OpenError, Values};
use crate::e2e_profile::{
    array, at, check_distinct, check_keys, child, object, optional, read_bool, read_string,
    read_uint, required, CounterErrors, DocError, Entries, Profile,
};
use crate::e2e_receiver::{Keying, Receiver, FAILED_IDENT};

const CORPUS: &str = include_str!("../conformance/fixed_records.json5");

/// The format this runner reads. A corpus of another is refused, not read in part.
const FORMAT: &str = "wz-fixed-records/1";

/// The vectors of each kind the corpus holds, in the order frame, open, build, policy. The README
/// lists them; a vector lost to a reading mistake shows here.
const KINDS: [usize; 4] = [7, 11, 8, 12];

/// A header field as a record carries it: a plain field's value, or a split field's values by
/// name, a value over several runs under its own name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reading {
    Whole(u64),
    Parts(BTreeMap<String, u64>),
}

/// The message cell of an `e2e_opened` record: the parts the layout's cell names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cell {
    kind: Option<u64>,
    result: Option<u64>,
    sender: Option<u64>,
}

/// The `e2e_opened` record: what a receiver reads from a frame, every defect a fact in it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Opened {
    crc_found: u64,
    crc_computed: u64,
    crc_ok: bool,
    length_found: u64,
    length_expected: u64,
    length_matches_frame: bool,
    counter: u64,
    payload_offset: usize,
    payload_bytes: usize,
    /// Every field but the CRC, the length and the counter, by name.
    fields: BTreeMap<String, Reading>,
    /// `None` when the layout names no cell.
    cell: Option<Cell>,
    /// `None` when the layout judges no identifier.
    ident_matches: Option<bool>,
}

/// The `e2e_policy` record: the rules a receiver judges the counter and the length by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Policy {
    max_gap: u64,
    timeout_ms: u64,
    max_gap_ceiling: Option<u64>,
    counter_errors: CounterErrors,
    out_of_range_moves_baseline: bool,
    length: bool,
}

/// Why a codec refused, as the corpus names it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    /// A value the layout cannot write, at a JSON pointer into the vector's `values`.
    Values(String),
    /// A body longer than the length field can count.
    PayloadTooLong,
    /// Fewer bytes than the header.
    ShortFrame,
    /// A policy member, at a JSON pointer into the vector's `stated` policy.
    Policy(String),
}

/// One value over several runs of a split word: the parts that hold its runs, the most
/// significant first.
#[derive(Debug, Clone)]
struct Run {
    name: String,
    field: String,
    parts: Vec<String>,
}

/// A layout of the corpus: the profile that defines it, the values that lie over several runs,
/// and the values a receiver expects of the identifier it judges.
#[derive(Debug, Clone)]
struct Layout {
    name: String,
    profile: Json5Value,
    runs: Vec<Run>,
    expected: Json5Value,
}

#[derive(Debug, Clone)]
enum Check {
    /// Build `values` and `payload` into `wire`, then open `wire` into `opened`.
    Frame {
        values: Json5Value,
        payload: Vec<u8>,
        wire: Vec<u8>,
        opened: Opened,
    },
    /// Open `wire`, which no build of the layout makes.
    Open {
        wire: Vec<u8>,
        outcome: Result<Opened, Refusal>,
    },
    /// Build `values` and `payload`, which the layout refuses.
    Build {
        values: Json5Value,
        payload: Vec<u8>,
        refused: Refusal,
    },
    /// Read the policy `stated` for a receiver of the layout.
    Policy {
        stated: Json5Value,
        outcome: Result<Policy, Refusal>,
    },
}

#[derive(Debug, Clone)]
struct Vector {
    name: String,
    layout: usize,
    check: Check,
}

struct Corpus {
    layouts: Vec<Layout>,
    vectors: Vec<Vector>,
}

/// What a codec of the corpus's layouts does, whoever wrote it.
trait Codec {
    /// The frame `values` and `payload` make under `layout`.
    fn build(
        &self,
        layout: &Layout,
        values: &Json5Value,
        payload: &[u8],
    ) -> Result<Vec<u8>, Refusal>;
    /// The record `wire` opens to under `layout`.
    fn open(&self, layout: &Layout, wire: &[u8]) -> Result<Opened, Refusal>;
    /// The policy `stated` gives a receiver of `layout`.
    fn policy(&self, layout: &Layout, stated: &Json5Value) -> Result<Policy, Refusal>;
}

/// Hold `codec` to every vector, and answer how many of each kind it met, in the order of
/// `KINDS`. A mismatch fails at the vector's name.
fn run(corpus: &Corpus, codec: &dyn Codec) -> [usize; 4] {
    let mut ran = [0; 4];
    for vector in &corpus.vectors {
        let layout = &corpus.layouts[vector.layout];
        let name = &vector.name;
        match &vector.check {
            Check::Frame {
                values,
                payload,
                wire,
                opened,
            } => {
                let built = codec.build(layout, values, payload);
                assert_eq!(built.as_ref(), Ok(wire), "{name}: the bytes built");
                let read = codec.open(layout, wire);
                assert_eq!(read.as_ref(), Ok(opened), "{name}: the record opened");
                ran[0] += 1;
            }
            Check::Open { wire, outcome } => {
                let read = codec.open(layout, wire);
                assert_eq!(&read, outcome, "{name}: the record opened");
                ran[1] += 1;
            }
            Check::Build {
                values,
                payload,
                refused,
            } => {
                let built = codec.build(layout, values, payload);
                assert_eq!(built, Err(refused.clone()), "{name}: the refusal");
                ran[2] += 1;
            }
            Check::Policy { stated, outcome } => {
                let read = codec.policy(layout, stated);
                assert_eq!(&read, outcome, "{name}: the policy read");
                ran[3] += 1;
            }
        }
    }
    ran
}

// ---------------------------------------------------------------- the hand-written codec

/// The builder and opener of `crate::e2e_frame` and the receiver of `crate::e2e_receiver`,
/// under the layout's profile.
struct HandWritten;

impl Codec for HandWritten {
    fn build(
        &self,
        layout: &Layout,
        values: &Json5Value,
        payload: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        let profile = layout.parsed();
        let tree = layout.cut_runs(&profile, values)?;
        let values = match Values::from_tree(&tree, &[]) {
            Ok(values) => values,
            Err(e) => return Err(layout.refusal(e)),
        };
        match e2e_frame::build(&profile, &values, payload) {
            Ok(built) => Ok(built.bytes),
            Err(BuildError::Values(e)) => Err(layout.refusal(e)),
            Err(BuildError::PayloadTooLong { .. }) => Err(Refusal::PayloadTooLong),
        }
    }

    fn open(&self, layout: &Layout, wire: &[u8]) -> Result<Opened, Refusal> {
        let profile = layout.parsed();
        let opened = match e2e_frame::open(&profile, wire) {
            Ok(opened) => opened,
            Err(OpenError::ShortFrame { .. }) => return Err(Refusal::ShortFrame),
        };
        let mechanism = [
            profile.crc().field,
            profile.length().field,
            profile.counter().field,
        ];
        let mut fields = BTreeMap::new();
        for (index, field) in profile.fields().iter().enumerate() {
            if mechanism.contains(&index) {
                continue;
            }
            let report = &opened.fields[index];
            if field.parts.is_empty() {
                fields.insert(field.name.clone(), Reading::Whole(report.value));
                continue;
            }
            let mut parts = BTreeMap::new();
            for (part, value) in field.parts.iter().zip(&report.parts) {
                if layout.run_holding(&field.name, &part.name).is_none() {
                    parts.insert(part.name.clone(), *value);
                }
            }
            for run in layout.runs.iter().filter(|r| r.field == field.name) {
                let mut joined = 0u64;
                for name in &run.parts {
                    let place = field
                        .parts
                        .iter()
                        .position(|p| &p.name == name)
                        .expect("a run's part is a part of its word");
                    let width = u32::from(field.parts[place].width);
                    joined = joined.checked_shl(width).unwrap_or(0) | report.parts[place];
                }
                parts.insert(run.name.clone(), joined);
            }
            fields.insert(field.name.clone(), Reading::Parts(parts));
        }

        let name = &layout.name;
        let judges_ident = profile.rules().ident.is_some();
        let has_cell = profile.cell().is_some();
        let expected = match Values::from_tree(&layout.expected, &[]) {
            Ok(expected) => expected,
            Err(e) => panic!("layout `{name}`: the expected values: {e}"),
        };
        let keying = Keying::Indexed { streams: 1 };
        let mut receiver = match Receiver::new(profile, &expected, keying, None, 1) {
            Ok(receiver) => receiver,
            Err(e) => panic!("layout `{name}`: no receiver: {e}"),
        };
        let verdict = match receiver.receive(0, wire, 0) {
            Ok(verdict) => verdict,
            Err(e) => panic!("layout `{name}`: not judged: {e}"),
        };

        Ok(Opened {
            crc_found: opened.crc_found,
            crc_computed: opened.crc_computed,
            crc_ok: opened.crc_ok,
            length_found: opened.length_found,
            length_expected: opened.length_expected,
            length_matches_frame: opened.length_matches_frame,
            counter: verdict.counter.expect("a header has a counter"),
            payload_offset: opened.payload_offset,
            payload_bytes: opened.payload_bytes,
            fields,
            cell: has_cell.then_some(Cell {
                kind: verdict.kind,
                result: verdict.result,
                sender: verdict.sender,
            }),
            ident_matches: judges_ident.then_some((verdict.failed & FAILED_IDENT) == 0),
        })
    }

    fn policy(&self, layout: &Layout, stated: &Json5Value) -> Result<Policy, Refusal> {
        let document = layout.with_policy(stated).to_json5_text();
        let profile = match Profile::parse(&document) {
            Ok(profile) => profile,
            Err(e) => return Err(Refusal::Policy(policy_pointer(e))),
        };
        let counter = profile.counter();
        let rules = profile.rules();
        Ok(Policy {
            max_gap: counter.max_gap,
            timeout_ms: counter.timeout_ms,
            max_gap_ceiling: counter.max_gap_ceiling,
            counter_errors: rules.counter_errors,
            out_of_range_moves_baseline: rules.out_of_range_moves_baseline,
            length: rules.length,
        })
    }
}

impl Layout {
    fn parsed(&self) -> Profile {
        match Profile::parse(&self.profile.to_json5_text()) {
            Ok(profile) => profile,
            Err(e) => panic!("layout `{}`: the profile is refused: {e}", self.name),
        }
    }

    /// The run of the word `field` called `name`, if any.
    fn run_named(&self, field: &str, name: &str) -> Option<&Run> {
        self.runs
            .iter()
            .find(|r| r.field == field && r.name == name)
    }

    /// The run of the word `field` that `part` holds, if any.
    fn run_holding(&self, field: &str, part: &str) -> Option<&Run> {
        self.runs
            .iter()
            .find(|r| r.field == field && r.parts.iter().any(|p| p == part))
    }

    /// `values` with every value over runs cut into the parts that hold them, the least
    /// significant first. The most significant part takes what is left, so a value too wide for
    /// its runs is refused by the builder at that part.
    fn cut_runs(&self, profile: &Profile, values: &Json5Value) -> Result<Json5Value, Refusal> {
        let Json5Value::Object(entries) = values else {
            return Ok(values.clone());
        };
        let mut out = Vec::with_capacity(entries.len());
        for (name, value) in entries {
            let value = match value {
                Json5Value::Object(members) if self.runs.iter().any(|r| &r.field == name) => {
                    Json5Value::Object(self.cut(profile, name, members)?)
                }
                other => other.clone(),
            };
            out.push((name.clone(), value));
        }
        Ok(Json5Value::Object(out))
    }

    fn cut(
        &self,
        profile: &Profile,
        field: &str,
        members: &Entries,
    ) -> Result<Vec<(String, Json5Value)>, Refusal> {
        let index = profile
            .field_index(field)
            .expect("a run's word is a field of the profile");
        let parts = &profile.fields()[index].parts;
        let mut out = Vec::with_capacity(members.len() + 1);
        for (member, value) in members {
            let Some(run) = self.run_named(field, member) else {
                out.push((member.clone(), value.clone()));
                continue;
            };
            let path = child(&child("", field), member);
            let mut rest = read_uint(value, &path).map_err(|e| self.refusal(e))?;
            for (i, name) in run.parts.iter().enumerate().rev() {
                let width = parts
                    .iter()
                    .find(|p| &p.name == name)
                    .expect("a run's part is a part of its word")
                    .width;
                let held = if i == 0 {
                    rest
                } else {
                    rest & width_mask(width)
                };
                rest = rest.checked_shr(u32::from(width)).unwrap_or(0);
                out.push((name.clone(), Json5Value::Number(held.to_string())));
            }
        }
        Ok(out)
    }

    /// A refusal of the builder, at the value it names: a part that holds a run is reported at
    /// the value over the runs.
    fn refusal(&self, e: DocError) -> Refusal {
        let path = match e {
            DocError::Invalid { path, .. } => path,
            DocError::Syntax { offset, .. } => panic!("a values tree read as text, at {offset}"),
        };
        for run in &self.runs {
            let word = child("", &run.field);
            if run.parts.iter().any(|part| path == child(&word, part)) {
                return Refusal::Values(child(&word, &run.name));
            }
        }
        Refusal::Values(path)
    }

    /// The layout's profile with its policy (the counter's limits and the judge's rules) replaced
    /// by `stated`, the counter field and the judged identifier kept.
    fn with_policy(&self, stated: &Json5Value) -> Json5Value {
        let Json5Value::Object(profile) = &self.profile else {
            panic!("layout `{}`: a profile is an object", self.name);
        };
        let Json5Value::Object(members) = stated else {
            panic!("layout `{}`: a stated policy is an object", self.name);
        };
        let kept = |member: &str, key: &str| -> Vec<(String, Json5Value)> {
            let Some(Json5Value::Object(entries)) = optional(profile, member) else {
                return Vec::new();
            };
            entries.iter().filter(|(k, _)| k == key).cloned().collect()
        };
        let mut counter = kept("counter", "field");
        let mut judge = kept("judge", "ident");
        for (key, value) in members {
            match key.as_str() {
                "max_gap" | "timeout_ms" | "max_gap_ceiling" => {
                    counter.push((key.clone(), value.clone()))
                }
                "counter_errors" | "out_of_range" | "length" => {
                    judge.push((key.clone(), value.clone()))
                }
                other => panic!("layout `{}`: no policy member `{other}`", self.name),
            }
        }
        let mut out: Vec<(String, Json5Value)> = profile
            .iter()
            .filter(|(k, _)| k != "counter" && k != "judge")
            .cloned()
            .collect();
        out.push((String::from("counter"), Json5Value::Object(counter)));
        out.push((String::from("judge"), Json5Value::Object(judge)));
        Json5Value::Object(out)
    }
}

/// A refusal of the profile reader, at the policy member it names: the members of `counter` and
/// `judge` are the policy's own.
fn policy_pointer(e: DocError) -> String {
    let path = match e {
        DocError::Invalid { path, .. } => path,
        DocError::Syntax { offset, .. } => panic!("a profile tree read as text, at {offset}"),
    };
    for member in ["/counter", "/judge"] {
        if let Some(rest) = path.strip_prefix(member) {
            if rest.is_empty() || rest.starts_with('/') {
                return String::from(rest);
            }
        }
    }
    path
}

// ---------------------------------------------------------------- reading the corpus

fn ok<T>(read: Result<T, DocError>) -> T {
    match read {
        Ok(value) => value,
        Err(e) => panic!("the corpus is malformed: {e}"),
    }
}

fn member<'a>(entries: &'a Entries, key: &str, path: &str) -> &'a Json5Value {
    ok(required(entries, key, path))
}

fn text<'a>(entries: &'a Entries, key: &str, path: &str) -> &'a str {
    ok(read_string(member(entries, key, path), &child(path, key)))
}

fn uint(entries: &Entries, key: &str, path: &str) -> u64 {
    ok(read_uint(member(entries, key, path), &child(path, key)))
}

fn flag(entries: &Entries, key: &str, path: &str) -> bool {
    ok(read_bool(member(entries, key, path), &child(path, key)))
}

fn size(entries: &Entries, key: &str, path: &str) -> usize {
    let value = uint(entries, key, path);
    usize::try_from(value).expect("a size fits a usize")
}

fn optional_uint(entries: &Entries, key: &str, path: &str) -> Option<u64> {
    optional(entries, key)?;
    Some(uint(entries, key, path))
}

fn optional_flag(entries: &Entries, key: &str, path: &str) -> Option<bool> {
    optional(entries, key)?;
    Some(flag(entries, key, path))
}

fn optional_text<'a>(entries: &'a Entries, key: &str, path: &str) -> Option<&'a str> {
    optional(entries, key)?;
    Some(text(entries, key, path))
}

fn corpus() -> Corpus {
    let root = match json5::parse(CORPUS) {
        Ok(root) => root,
        Err(e) => panic!("the corpus is not JSON5: {e}"),
    };
    let entries = ok(object(&root, ""));
    ok(check_keys(entries, &["format", "layouts", "vectors"], ""));
    assert_eq!(text(entries, "format", ""), FORMAT, "the corpus's format");

    let listed = ok(object(member(entries, "layouts", ""), "/layouts"));
    ok(check_distinct(listed, "/layouts"));
    let mut layouts = Vec::with_capacity(listed.len());
    for (name, value) in listed {
        layouts.push(read_layout(name, value, &child("/layouts", name)));
    }

    let items = ok(array(member(entries, "vectors", ""), "/vectors"));
    let mut vectors: Vec<Vector> = Vec::with_capacity(items.len());
    for (i, value) in items.iter().enumerate() {
        let vector = read_vector(value, &at("/vectors", i), &layouts);
        assert!(
            vectors.iter().all(|v| v.name != vector.name),
            "two vectors are called `{}`",
            vector.name
        );
        vectors.push(vector);
    }
    Corpus { layouts, vectors }
}

fn read_layout(name: &str, value: &Json5Value, path: &str) -> Layout {
    let entries = ok(object(value, path));
    ok(check_keys(entries, &["profile", "runs", "expected"], path));
    let mut runs = Vec::new();
    if let Some(value) = optional(entries, "runs") {
        let here = child(path, "runs");
        let listed = ok(object(value, &here));
        ok(check_distinct(listed, &here));
        for (run, spec) in listed {
            let at_run = child(&here, run);
            let spec = ok(object(spec, &at_run));
            ok(check_keys(spec, &["field", "parts"], &at_run));
            let at_parts = child(&at_run, "parts");
            let items = ok(array(member(spec, "parts", &at_run), &at_parts));
            let mut parts = Vec::with_capacity(items.len());
            for (i, part) in items.iter().enumerate() {
                parts.push(String::from(ok(read_string(part, &at(&at_parts, i)))));
            }
            runs.push(Run {
                name: run.clone(),
                field: String::from(text(spec, "field", &at_run)),
                parts,
            });
        }
    }
    let expected = match optional(entries, "expected") {
        Some(expected) => expected.clone(),
        None => Json5Value::Object(Vec::new()),
    };
    let layout = Layout {
        name: String::from(name),
        profile: member(entries, "profile", path).clone(),
        runs,
        expected,
    };
    // A run names a split word of the profile and at least two of its parts, each part in one
    // run, and a name no part of the word has.
    let profile = layout.parsed();
    for run in &layout.runs {
        let index = profile.field_index(&run.field).expect("a run's word");
        let parts = &profile.fields()[index].parts;
        assert!(run.parts.len() >= 2, "{path}: a run of one part");
        for part in &run.parts {
            assert!(parts.iter().any(|p| &p.name == part), "{path}: no `{part}`");
            let holders = layout.runs.iter().filter(|r| r.parts.contains(part));
            assert_eq!(holders.count(), 1, "{path}: `{part}` in two runs");
        }
        let named = parts.iter().any(|p| p.name == run.name);
        assert!(!named, "{path}: the run `{}` is a part", run.name);
    }
    layout
}

fn read_vector(value: &Json5Value, path: &str, layouts: &[Layout]) -> Vector {
    let entries = ok(object(value, path));
    let layout_name = text(entries, "layout", path);
    let layout = layouts
        .iter()
        .position(|l| l.name == layout_name)
        .unwrap_or_else(|| panic!("{path}: no layout `{layout_name}`"));
    let bytes = |key: &str| read_bytes(member(entries, key, path), &child(path, key));
    let check = match text(entries, "kind", path) {
        "frame" => {
            let keys = vector_keys(&["values", "payload", "wire", "opened"]);
            ok(check_keys(entries, &keys, path));
            Check::Frame {
                values: member(entries, "values", path).clone(),
                payload: bytes("payload"),
                wire: bytes("wire"),
                opened: read_opened(member(entries, "opened", path), &child(path, "opened")),
            }
        }
        "open" => {
            let keys = vector_keys(&["wire", "opened", "refused"]);
            ok(check_keys(entries, &keys, path));
            Check::Open {
                wire: bytes("wire"),
                outcome: outcome(entries, path, "opened", read_opened),
            }
        }
        "build" => {
            let keys = vector_keys(&["values", "payload", "refused"]);
            ok(check_keys(entries, &keys, path));
            Check::Build {
                values: member(entries, "values", path).clone(),
                payload: bytes("payload"),
                refused: read_refusal(member(entries, "refused", path), &child(path, "refused")),
            }
        }
        "policy" => {
            let keys = vector_keys(&["stated", "policy", "refused"]);
            ok(check_keys(entries, &keys, path));
            let stated = member(entries, "stated", path);
            let at_stated = child(path, "stated");
            ok(check_distinct(ok(object(stated, &at_stated)), &at_stated));
            Check::Policy {
                stated: stated.clone(),
                outcome: outcome(entries, path, "policy", read_policy),
            }
        }
        other => panic!("{path}: no vector is of the kind `{other}`"),
    };
    Vector {
        name: String::from(text(entries, "name", path)),
        layout,
        check,
    }
}

/// The members of a vector of a kind whose own members are `own`.
fn vector_keys<'a>(own: &[&'a str]) -> Vec<&'a str> {
    let mut keys = Vec::from(["name", "kind", "layout"]);
    keys.extend_from_slice(own);
    keys
}

/// What a vector expects of a call that may be refused: the record under `key` or the refusal
/// under `refused`, never both.
fn outcome<T>(
    entries: &Entries,
    path: &str,
    key: &str,
    read: fn(&Json5Value, &str) -> T,
) -> Result<T, Refusal> {
    match (optional(entries, key), optional(entries, "refused")) {
        (Some(value), None) => Ok(read(value, &child(path, key))),
        (None, Some(value)) => Err(read_refusal(value, &child(path, "refused"))),
        _ => panic!("{path}: one of `{key}` and `refused`"),
    }
}

/// Bytes as hex pairs apart by white space, in one string or an array of strings joined.
fn read_bytes(value: &Json5Value, path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut take = |line: &str, here: &str| {
        for pair in line.split_ascii_whitespace() {
            let hex = pair.len() == 2 && pair.bytes().all(|b| b.is_ascii_hexdigit());
            let byte = match u8::from_str_radix(pair, 16) {
                Ok(byte) if hex => byte,
                _ => panic!("{here}: `{pair}` is not two hex digits"),
            };
            out.push(byte);
        }
    };
    match value {
        Json5Value::Array(lines) => {
            for (i, line) in lines.iter().enumerate() {
                let here = at(path, i);
                take(ok(read_string(line, &here)), &here);
            }
        }
        other => take(ok(read_string(other, path)), path),
    }
    out
}

fn read_reading(value: &Json5Value, path: &str) -> Reading {
    let Json5Value::Object(named) = value else {
        return Reading::Whole(ok(read_uint(value, path)));
    };
    ok(check_distinct(named, path));
    let mut parts = BTreeMap::new();
    for (name, part) in named {
        parts.insert(name.clone(), ok(read_uint(part, &child(path, name))));
    }
    Reading::Parts(parts)
}

fn read_opened(value: &Json5Value, path: &str) -> Opened {
    let entries = ok(object(value, path));
    let keys = [
        "crc_found",
        "crc_computed",
        "crc_ok",
        "length_found",
        "length_expected",
        "length_matches_frame",
        "counter",
        "payload_offset",
        "payload_bytes",
        "fields",
        "cell",
        "ident_matches",
    ];
    ok(check_keys(entries, &keys, path));
    let at_fields = child(path, "fields");
    let listed = ok(object(member(entries, "fields", path), &at_fields));
    ok(check_distinct(listed, &at_fields));
    let mut fields = BTreeMap::new();
    for (name, reading) in listed {
        let reading = read_reading(reading, &child(&at_fields, name));
        fields.insert(name.clone(), reading);
    }
    Opened {
        crc_found: uint(entries, "crc_found", path),
        crc_computed: uint(entries, "crc_computed", path),
        crc_ok: flag(entries, "crc_ok", path),
        length_found: uint(entries, "length_found", path),
        length_expected: uint(entries, "length_expected", path),
        length_matches_frame: flag(entries, "length_matches_frame", path),
        counter: uint(entries, "counter", path),
        payload_offset: size(entries, "payload_offset", path),
        payload_bytes: size(entries, "payload_bytes", path),
        fields,
        cell: optional_cell(entries, path),
        ident_matches: optional_flag(entries, "ident_matches", path),
    }
}

/// The cell of an `opened` record, when it states one.
fn optional_cell(entries: &Entries, path: &str) -> Option<Cell> {
    let value = optional(entries, "cell")?;
    let here = child(path, "cell");
    let named = ok(object(value, &here));
    ok(check_keys(named, &["kind", "result", "sender"], &here));
    Some(Cell {
        kind: optional_uint(named, "kind", &here),
        result: optional_uint(named, "result", &here),
        sender: optional_uint(named, "sender", &here),
    })
}

fn read_policy(value: &Json5Value, path: &str) -> Policy {
    let entries = ok(object(value, path));
    let keys = [
        "max_gap",
        "timeout_ms",
        "max_gap_ceiling",
        "counter_errors",
        "out_of_range",
        "length",
    ];
    ok(check_keys(entries, &keys, path));
    let max_gap_ceiling = match member(entries, "max_gap_ceiling", path) {
        Json5Value::Null => None,
        _ => Some(uint(entries, "max_gap_ceiling", path)),
    };
    let counter_errors = match text(entries, "counter_errors", path) {
        "apart" => CounterErrors::Apart,
        "joined" => CounterErrors::Joined,
        other => panic!("{path}: no counter error rule `{other}`"),
    };
    let out_of_range_moves_baseline = match text(entries, "out_of_range", path) {
        "moves_baseline" => true,
        "keeps_baseline" => false,
        other => panic!("{path}: no out of range rule `{other}`"),
    };
    Policy {
        max_gap: uint(entries, "max_gap", path),
        timeout_ms: uint(entries, "timeout_ms", path),
        max_gap_ceiling,
        counter_errors,
        out_of_range_moves_baseline,
        length: flag(entries, "length", path),
    }
}

fn read_refusal(value: &Json5Value, path: &str) -> Refusal {
    let entries = ok(object(value, path));
    ok(check_keys(entries, &["kind", "at"], path));
    let pointer = optional_text(entries, "at", path);
    match (text(entries, "kind", path), pointer) {
        ("values", Some(pointer)) => Refusal::Values(String::from(pointer)),
        ("policy", Some(pointer)) => Refusal::Policy(String::from(pointer)),
        ("payload_too_long", None) => Refusal::PayloadTooLong,
        ("short_frame", None) => Refusal::ShortFrame,
        (kind, pointer) => panic!("{path}: no refusal `{kind}` at {pointer:?}"),
    }
}

/// The bytes of the vector called `name`.
fn wire_of<'a>(corpus: &'a Corpus, name: &str) -> &'a [u8] {
    let vector = corpus.vectors.iter().find(|v| v.name == name);
    match vector.map(|v| &v.check) {
        Some(Check::Frame { wire, .. } | Check::Open { wire, .. }) => wire,
        other => panic!("no vector `{name}` with bytes: {other:?}"),
    }
}

// ---------------------------------------------------------------- the arms

#[test]
fn the_hand_written_codec_meets_every_vector() {
    let corpus = corpus();
    assert_eq!(run(&corpus, &HandWritten), KINDS);
}

#[test]
fn the_corpus_holds_the_word_sent_for_review_and_the_same_word_written_otherwise() {
    let corpus = corpus();
    let layout = corpus
        .layouts
        .iter()
        .find(|l| l.name == "mask-word")
        .expect("the layout of the word");
    let profile = layout.parsed();
    let index = profile.field_index("ident").expect("the word");
    let word = &profile.fields()[index];
    assert_eq!((word.offset, word.bytes), (0, 4));
    assert_eq!((word.xor, word.owned_bits()), (0xFF0F_0F0F, 0x0FFF_FFFF));

    let sent = wire_of(&corpus, "mask-word/the-word-sent-for-review");
    assert_eq!(sent[..4], [0xFC, 0x06, 0x05, 0x1E]);
    // Bits 28 to 31 are the high nibble of the first byte, and the CRC is the last header byte:
    // the two frames written otherwise differ from the sent one there and nowhere else.
    let crc_at = profile.fields()[profile.crc().field].offset;
    for name in [
        "mask-word/unowned-bits-written-otherwise",
        "mask-word/unowned-bits-written-otherwise-again",
    ] {
        let other = wire_of(&corpus, name);
        let differ: Vec<usize> = (0..sent.len()).filter(|&i| sent[i] != other[i]).collect();
        assert_eq!(differ, [0, crc_at], "{name}");
        assert_eq!(sent[0] & 0x0F, other[0] & 0x0F, "{name}");
    }
}

/// The codecs generated from the corpus's layouts, by layout name: the list a build that links
/// them states. The layouts need SCE's word mask, multi-run fields and derived checksum, length
/// and address fields; with none of them listed the arm below fails naming each layout.
#[cfg(feature = "sce-generated-codec")]
const GENERATED: &[(&str, &dyn Codec)] = &[];

/// Every layout's generated codec, as one codec.
#[cfg(feature = "sce-generated-codec")]
struct Generated;

#[cfg(feature = "sce-generated-codec")]
impl Generated {
    fn of(layout: &Layout) -> &'static dyn Codec {
        let found = GENERATED.iter().find(|(name, _)| *name == layout.name);
        let Some((_, codec)) = found else {
            panic!("no generated codec of the layout `{}`", layout.name);
        };
        *codec
    }
}

#[cfg(feature = "sce-generated-codec")]
impl Codec for Generated {
    fn build(
        &self,
        layout: &Layout,
        values: &Json5Value,
        payload: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        Self::of(layout).build(layout, values, payload)
    }

    fn open(&self, layout: &Layout, wire: &[u8]) -> Result<Opened, Refusal> {
        Self::of(layout).open(layout, wire)
    }

    fn policy(&self, layout: &Layout, stated: &Json5Value) -> Result<Policy, Refusal> {
        Self::of(layout).policy(layout, stated)
    }
}

#[cfg(feature = "sce-generated-codec")]
#[test]
fn generated_codec_matches_the_corpus() {
    let corpus = corpus();
    let mut missing = Vec::new();
    for layout in &corpus.layouts {
        if GENERATED.iter().all(|(name, _)| *name != layout.name) {
            missing.push(layout.name.as_str());
        }
    }
    assert!(missing.is_empty(), "no generated codec of {missing:?}");
    assert_eq!(run(&corpus, &Generated), KINDS);
}

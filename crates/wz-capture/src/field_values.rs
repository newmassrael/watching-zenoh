// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE VALUES OF A FEW PAYLOAD FIELDS, for the records after a cursor that a
//! selector picks: the narrow document a consumer that plots one field over
//! time reads instead of the field document.
//!
//! # Why a document of its own
//!
//! The field document writes every row whole: its tree, its carried state, its
//! session verdicts, and the decoded payload with every field. A consumer that
//! draws `x` against time keeps one number of it. Measured by
//! `benches/fields_row_cost.rs` over ten thousand pushes of one schema: the row
//! is 5,094 bytes a push and the two values a plot keeps are 75 at their
//! narrowest, 67.5 times less; and of a 168 ms call, 109 ms is writing the rows
//! with no payload in them at all. A flag on that document would make one
//! document with two shapes; this is a second document with its own revision,
//! which is how this library tells a reader which shape it holds.
//!
//! # A record and not a row
//!
//! A value belongs to a SAMPLE, and a row (a transport message) may carry
//! several: a `Frame` batches records. So an entry here is one record: the
//! `seq` of the row that carried it, as every document of a live handle
//! numbers rows, and `record`, its place in that row's batch. The time is the
//! capture's instant for the row.
//!
//! # The walk is the payload plane's
//!
//! The records are found, their keyexpr resolved and the selector judged by
//! the payload plane's own walk
//! ([`crate::payload::PayloadCensus`]'s record observation), handed the
//! payloads it says `yes` to; so the records one selector picks here are the
//! ones it counts in the census. Each payload is read by the declarations as a
//! row of the field document reads it
//! ([`crate::payload_decode::decode_payload_parts`]), so a value here is the
//! `typed_value` that document writes for the same field.
//!
//! # What a call costs, and what it keeps
//!
//! The walk is a fold in capture order kept between calls
//! (the census planes' `ordered_fold`): a call folds the messages that arrived since the
//! last. What the fold keeps of a record is its payload's bytes and declared
//! encoding, not a reading of them, and the reading is made when the record is
//! written, by the declarations of the call that writes it. So the walk is for
//! a SELECTOR: another declaration text or path list reads the same kept
//! payloads, and only another selector, a cursor below the one the memory was
//! last asked at, or a capture the fold cannot continue in begins the walk
//! again, which costs a first call and is never a wrong answer. The records at
//! or below the cursor a call is asked at are given up: the caller has moved
//! past them.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use wz_session_core::json::escape_into;

use crate::fields_json::RowCoordinates;
use crate::payload::formats::FormatMap;
use crate::payload::Encoding;
use crate::payload_decode::{decode_payload_parts, Declarations, PayloadDecoding, PayloadParts};

/// The longest path list a call takes, in paths. A plot draws a few fields;
/// the bound keeps a mistaken list (a whole schema's paths) from making every
/// record a full listing again, which is the document this one exists to avoid.
pub const MAX_PATHS: usize = 64;

/// Why a call's arguments were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValuesRefusal {
    /// The path list names no path.
    NoPaths,
    /// The path list names more than [`MAX_PATHS`].
    TooManyPaths(usize),
    /// A path is empty or carries a character no decoded path has.
    BadPath(String),
}

impl core::fmt::Display for ValuesRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoPaths => f.write_str("the path list names no path"),
            Self::TooManyPaths(n) => write!(
                f,
                "the path list names {n} paths and a call takes at most {MAX_PATHS}"
            ),
            Self::BadPath(path) => write!(
                f,
                "`{path}` is not a payload field path (one per line, as a decoded field's \
                 `path` writes it)"
            ),
        }
    }
}

/// Read a path list: one path per line, as a decoded field's `path` is written
/// (`1`, `4.1`, `$.pose.x`). Blank lines are skipped; a path written twice is
/// kept once, in the order first written.
pub fn read_paths(text: &str) -> Result<Vec<String>, ValuesRefusal> {
    let mut paths: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if line.chars().any(|c| c.is_control()) || line.trim() != line {
            return Err(ValuesRefusal::BadPath(String::from(line)));
        }
        if !paths.iter().any(|p| p == line) {
            paths.push(String::from(line));
        }
    }
    if paths.is_empty() {
        return Err(ValuesRefusal::NoPaths);
    }
    if paths.len() > MAX_PATHS {
        return Err(ValuesRefusal::TooManyPaths(paths.len()));
    }
    Ok(paths)
}

/// A declared encoding held past the walk that read it.
#[derive(Debug, Clone)]
enum HeldEncoding {
    Known {
        id: u16,
        name: &'static str,
        schema: Option<String>,
    },
    Unknown(u16),
    Absent,
}

impl HeldEncoding {
    fn of(encoding: Encoding<'_>) -> Self {
        match encoding {
            Encoding::Known { id, name, schema } => Self::Known {
                id,
                name,
                schema: schema.map(String::from),
            },
            Encoding::Unknown { id } => Self::Unknown(id),
            Encoding::Absent => Self::Absent,
        }
    }

    fn get(&self) -> Encoding<'_> {
        match self {
            Self::Known { id, name, schema } => Encoding::Known {
                id: *id,
                name,
                schema: schema.as_deref(),
            },
            Self::Unknown(id) => Encoding::Unknown { id: *id },
            Self::Absent => Encoding::Absent,
        }
    }
}

/// One payload the selector picked, as the fold keeps it until it is written.
#[derive(Debug, Clone)]
struct Held {
    list: usize,
    produced: u64,
    record: usize,
    observed_at_ns: Option<u64>,
    keyexpr: Option<String>,
    declared: HeldEncoding,
    bytes: Vec<u8>,
    elsewhere: bool,
}

/// The fold: the payload plane's walk ([`crate::payload::PayloadFold`]),
/// keeping the payloads its selector picks.
#[derive(Debug, Clone)]
pub(crate) struct ValuesFold {
    plane: crate::payload::PayloadFold,
    held: Vec<Held>,
}

impl crate::ordered_fold::OrderedFold for ValuesFold {
    fn reads_flow_word(&self) -> bool {
        self.plane.reads_flow_word()
    }

    fn reads_tree(&self) -> bool {
        self.plane.reads_tree()
    }

    fn feed(
        &mut self,
        flow: &crate::link::FlowKey,
        list: usize,
        packet: usize,
        frame: &crate::messages::Row<'_>,
        message: Option<&[u8]>,
        grouping: &crate::node::SessionGrouping,
    ) {
        let held = &mut self.held;
        let mut sink = |payload: crate::payload::SelectedPayload<'_>| {
            let (list, _, produced) = payload.row.parts();
            held.push(Held {
                list,
                produced: produced as u64,
                record: payload.record,
                observed_at_ns: payload.observed_at_ns,
                keyexpr: payload.keyexpr.map(String::from),
                declared: HeldEncoding::of(payload.declared),
                bytes: payload.bytes.to_vec(),
                elsewhere: payload.elsewhere,
            });
        };
        self.plane.feed_selecting(
            flow,
            list,
            packet,
            frame,
            message,
            grouping,
            Some(&mut sink),
        );
    }
}

/// One kept value: a decoded field at one of the asked paths.
struct Picked {
    path: String,
    typed: Option<crate::payload::formats::TypedValue>,
}

/// What reading a record's payload came to, in the words of the field
/// document's `payload_decode.state`.
enum Outcome {
    Decoded {
        schema: Option<String>,
        typed: bool,
        values: Vec<Picked>,
    },
    Refused {
        why: String,
    },
    EncodingMismatch {
        declared: String,
    },
    NotOnTheWire,
    KeyexprUnresolved,
}

/// Every word a record's `state` can say: the walk the document's value family
/// is held to, by the families gate.
#[cfg(test)]
pub(crate) fn state_names() -> Vec<&'static str> {
    [
        Outcome::Decoded {
            schema: None,
            typed: false,
            values: Vec::new(),
        },
        Outcome::Refused { why: String::new() },
        Outcome::EncodingMismatch {
            declared: String::new(),
        },
        Outcome::NotOnTheWire,
        Outcome::KeyexprUnresolved,
    ]
    .iter()
    .map(Outcome::word)
    .collect()
}

impl Outcome {
    const fn word(&self) -> &'static str {
        match self {
            Self::Decoded { .. } => "decoded",
            Self::Refused { .. } => "refused",
            Self::EncodingMismatch { .. } => "encoding_mismatch",
            Self::NotOnTheWire => "not_on_the_wire",
            Self::KeyexprUnresolved => "keyexpr_unresolved",
        }
    }
}

/// Read one held payload by `map`, keeping the fields at `paths`; `None` when
/// no rule covers its key, which is a record nobody asked about.
fn read(map: &FormatMap<'_>, paths: &[String], held: &Held) -> Option<Outcome> {
    let Some(keyexpr) = &held.keyexpr else {
        // An id no binding resolves cannot be matched against a rule, and a
        // plot asked about some key is told a record of an unknown one came.
        return Some(Outcome::KeyexprUnresolved);
    };
    // A payload that rides shared memory is a descriptor here, and no rule's
    // decoder reads it; the field document says the same.
    if held.elsewhere {
        return map.matching_rule(keyexpr).map(|_| Outcome::NotOnTheWire);
    }
    // A run of the declarations for this one payload: what the field
    // document's ledger would record of it is that document's to report.
    let run = Declarations::new(map);
    let decoding = decode_payload_parts(
        PayloadParts {
            keyexpr: keyexpr.clone(),
            bytes: &held.bytes,
            declared: held.declared.get(),
            base: 0,
            publisher: None,
        },
        &run,
    );
    Some(match decoding {
        PayloadDecoding::Decoded {
            fields,
            typed,
            schema,
            ..
        } => Outcome::Decoded {
            schema,
            typed,
            values: fields
                .into_iter()
                .filter(|f| paths.contains(&f.path))
                .map(|f| Picked {
                    path: f.path,
                    typed: f.typed,
                })
                .collect(),
        },
        PayloadDecoding::Refused { why, .. } => Outcome::Refused { why },
        PayloadDecoding::EncodingMismatch { declared, .. } => {
            Outcome::EncodingMismatch { declared }
        }
        PayloadDecoding::NotOnTheWire { .. } => Outcome::NotOnTheWire,
        PayloadDecoding::KeyexprUnresolved => Outcome::KeyexprUnresolved,
        // Not covered by any rule, or no payload to read: not asked about. A
        // piece of a split message is neither the message nor a refusal of it,
        // so it has no value to give and is not asked about either; the
        // message's values are read where it is joined, on the field
        // document's `segment.joined`, which this door does not yet walk.
        PayloadDecoding::NoRule(_)
        | PayloadDecoding::NoRules
        | PayloadDecoding::NoPayload
        | PayloadDecoding::SegmentPiece { .. } => return None,
    })
}

/// What a live handle keeps between calls of the values door.
#[derive(Debug, Default)]
pub struct ValuesMemory {
    fold: crate::ordered_fold::Resumable<ValuesFold>,
    /// The selector the fold is for.
    selector: Option<String>,
    /// The cursor the memory was last asked at: the payloads held are the ones
    /// after it, so a lower cursor cannot be answered from them.
    asked_from: u64,
    stats: crate::FoldStats,
}

impl ValuesMemory {
    /// A memory that has folded nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// The messages folded and the times the walk began again.
    pub fn stats(&self) -> crate::FoldStats {
        self.stats
    }

    /// The payloads held, waiting to be written or passed by a cursor.
    pub fn held(&self) -> usize {
        self.fold.fold().map_or(0, |fold| fold.held.len())
    }
}

/// The inputs of one call.
pub struct ValuesAsk<'a> {
    /// The declaration text, as every door that reads payloads takes it.
    pub declarations: &'a str,
    /// The selector's text, which the memory is kept for.
    pub selector: &'a str,
    /// The selector, parsed.
    pub filter: &'a crate::filter::Filter,
    /// The path list's text, one path per line.
    pub paths: &'a str,
    /// The cursor: the records of rows numbered above it are written.
    pub after_seq: u64,
    /// The highest number the handle has issued, the cursor to give next.
    pub through_seq: u64,
}

/// Why a call wrote no document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValuesError {
    /// The declaration text was refused: its line and error.
    Declarations(crate::payload::formats::DeclarationError),
    /// The path list was refused.
    Paths(ValuesRefusal),
    /// The progress hook stopped the walk.
    Cancelled,
}

/// The values document over `dissection` for one call: the records after the
/// cursor, each row numbered by `ids`.
///
/// # Errors
///
/// The declarations or the path list refused, both before any walk, or the
/// walk stopped by `progress`.
pub fn field_values_since(
    dissection: &crate::Dissection,
    ids: &dyn RowCoordinates,
    ask: ValuesAsk<'_>,
    memory: &mut ValuesMemory,
    progress: Option<&crate::Progress<'_>>,
) -> Result<String, ValuesError> {
    let paths = read_paths(ask.paths).map_err(ValuesError::Paths)?;
    let mut map = FormatMap::new();
    map.declare_all(ask.declarations)
        .map_err(ValuesError::Declarations)?;
    if memory.selector.as_deref() != Some(ask.selector) || ask.after_seq < memory.asked_from {
        memory.fold = crate::ordered_fold::Resumable::default();
    }
    let grouping = crate::node::session_grouping(dissection);
    memory
        .fold
        .advance(dissection, &grouping, &mut memory.stats, progress, || {
            ValuesFold {
                plane: crate::payload::PayloadFold::begin(dissection, ask.filter, &grouping),
                held: Vec::new(),
            }
        })
        .ok_or(ValuesError::Cancelled)?;
    memory.selector = Some(String::from(ask.selector));
    memory.asked_from = ask.after_seq;
    let Some(fold) = memory.fold.fold_mut() else {
        return Err(ValuesError::Cancelled);
    };
    // The payloads the cursor has passed are the caller's now.
    let after = ask.after_seq;
    fold.held.retain(|h| {
        ids.row_seq(h.list, h.produced)
            .is_none_or(|seq| seq > after)
    });
    Ok(render(&map, &paths, ids, &ask, &fold.held))
}

/// The document: the held payloads in the window, read by `map`, in row order
/// and in batch order within a row.
fn render(
    map: &FormatMap<'_>,
    paths: &[String],
    ids: &dyn RowCoordinates,
    ask: &ValuesAsk<'_>,
    held: &[Held],
) -> String {
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::FIELD_VALUES, &mut out);
    let _ = write!(
        out,
        ",\"window\":{{\"after_seq\":{},\"through_seq\":{}}},\"paths\":[",
        ask.after_seq, ask.through_seq
    );
    for (i, path) in paths.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        escape_into(path, &mut out);
    }
    out.push_str("],\"records\":[");
    let mut rows: Vec<(u64, &Held)> = held
        .iter()
        .filter_map(|h| {
            let seq = ids.row_seq(h.list, h.produced)?;
            (seq > ask.after_seq && seq <= ask.through_seq).then_some((seq, h))
        })
        .collect();
    rows.sort_by_key(|(seq, h)| (*seq, h.record));
    let mut written = 0usize;
    for (seq, held) in rows {
        let Some(outcome) = read(map, paths, held) else {
            continue;
        };
        if written > 0 {
            out.push(',');
        }
        written += 1;
        push_record(seq, held, &outcome, &mut out);
    }
    out.push_str("]}");
    out
}

fn push_record(seq: u64, held: &Held, outcome: &Outcome, out: &mut String) {
    let _ = write!(
        out,
        "{{\"seq\":{seq},\"record\":{},\"time_ns\":",
        held.record
    );
    match held.observed_at_ns {
        Some(ns) => crate::proto_decode_json::push_integer(i128::from(ns), out),
        None => out.push_str("null"),
    }
    out.push_str(",\"keyexpr\":");
    match &held.keyexpr {
        Some(k) => escape_into(k, out),
        None => out.push_str("null"),
    }
    out.push_str(",\"state\":\"");
    out.push_str(outcome.word());
    out.push('"');
    match outcome {
        Outcome::Decoded {
            schema,
            typed,
            values,
        } => {
            out.push_str(",\"typed\":");
            out.push_str(if *typed { "true" } else { "false" });
            out.push_str(",\"schema\":");
            match schema {
                Some(s) => escape_into(s, out),
                None => out.push_str("null"),
            }
            out.push_str(",\"values\":[");
            for (i, v) in values.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_value(v, out);
            }
            out.push(']');
        }
        Outcome::Refused { why } => {
            out.push_str(",\"why\":");
            escape_into(why, out);
        }
        Outcome::EncodingMismatch { declared } => {
            out.push_str(",\"declared\":");
            escape_into(declared, out);
        }
        Outcome::NotOnTheWire | Outcome::KeyexprUnresolved => {}
    }
    out.push('}');
}

fn push_value(v: &Picked, out: &mut String) {
    out.push_str("{\"path\":");
    escape_into(&v.path, out);
    let typed = v.typed.as_ref();
    out.push_str(",\"type\":");
    match typed.and_then(|t| t.ty.as_deref()) {
        Some(ty) => escape_into(ty, out),
        None => out.push_str("null"),
    }
    out.push_str(",\"typed_value\":");
    out.push_str(typed.and_then(|t| t.json.as_deref()).unwrap_or("null"));
    out.push_str(",\"enum_number\":");
    match typed.and_then(|t| t.enum_number) {
        Some(n) => {
            let _ = write!(out, "{n}");
        }
        None => out.push_str("null"),
    }
    out.push('}');
}

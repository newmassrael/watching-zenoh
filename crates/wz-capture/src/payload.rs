// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y617 (§1.1f) — the PAYLOAD sub-decoder: the last of the five analysis
//! planes, and the first that reads ABOVE zenoh.
//!
//! Every layer under this one stops at the keyexpr. The payload was a byte
//! count and nothing else — [`crate::agg`] sums it, [`crate::report`] prints
//! the sum, and no reader could ask what is IN it. A capture of a fleet
//! publishing JSON was, to this tool, a capture of some bytes.
//!
//! ## The rule this module exists to enforce
//!
//! **The encoding is the SENDER'S CLAIM, and a claim is checked before it is
//! believed.**
//!
//! A zenoh `Put` carries an encoding id: the publisher's statement about what
//! it put on the wire. Nothing validates it — not the router, not the peer, not
//! the protocol. A sub-decoder that renders bytes as JSON because the header
//! said `application/json` produces a CONFIDENT MISREAD on exactly the traffic
//! worth looking at, and this crate's whole reason to exist is that a confident
//! misread is worse than no answer (R311y607).
//!
//! So every rendering here is earned. [`crate::payload::Verdict::Text`] means the bytes ARE
//! valid UTF-8; [`crate::payload::Verdict::Json`] means they parsed; and a payload that does
//! not match its own declaration is [`crate::payload::Verdict::NotAsDeclared`], carrying the
//! byte offset where the claim broke. That verdict is not a failure of this
//! module — it is a FINDING, and the most interesting one it can produce,
//! because a publisher whose payload disagrees with its own encoding is a bug
//! the differential oracle exists to catch.
//!
//! ## Where the encoding names come from
//!
//! [`wz_codecs::encoding_ids::ENCODING_ID_TO_STR`] — the wire table, hoisted
//! down to `wz-codecs` in this round precisely so this module can reach it
//! without a second transcription. The table index IS the wire id, and the
//! `zenoh-pico` oracle pins it entry for entry against the real library, so a
//! name printed here is the name the publisher's own stack would print.
//!
//! An id the table does not have is [`crate::payload::Encoding::Unknown`]. Not "probably
//! bytes": unknown, counted, and rendered opaque.
//!
//! ## No allocation to decide, no dependency to parse
//!
//! The JSON check is a hand-written scanner over the byte slice — this crate
//! has zero third-party dependencies by charter, and a validator is a hundred
//! lines. It answers WELL-FORMED or the offset where it stopped; it does not
//! build a tree, because nothing here needs one and a tree would be the first
//! allocation in a hot path over every payload in a capture.

// Both are the CENSUS half's, and the census needs a record to judge -- so
// they are gated exactly as it is. The decision half above (naming an encoding,
// validating bytes) allocates nothing and composes in a build with no network
// codecs at all, which is the arm Layer C1bt pins it in.
#[cfg(feature = "network-codecs")]
use alloc::string::String;
#[cfg(feature = "network-codecs")]
use alloc::vec::Vec;

use wz_codecs::encoding_ids::ENCODING_ID_TO_STR;

/// What a payload's declared encoding says about its BYTES.
///
/// Derived from the table name rather than from a second list of ids, so a
/// table entry added upstream lands in the right shape without an edit here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// The bytes should be valid UTF-8 (`text/*`, `zenoh/string`, and the
    /// text-shaped `application/*` entries).
    Utf8Text,
    /// The bytes should be one well-formed JSON value.
    Json,
    /// The bytes are not text and nothing is claimed about their structure.
    Binary,
    /// The declared id is not in the table, so nothing is claimed at all.
    Unclaimed,
}

/// A declared encoding, named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding<'a> {
    /// A table entry, plus the optional schema suffix the wire word carries.
    Known {
        /// The wire id — the table index.
        id: u16,
        /// The table name, e.g. `application/json`.
        name: &'static str,
        /// The schema after the `;`, when the packed word said one is present.
        schema: Option<&'a str>,
    },
    /// An id no table entry answers to.
    ///
    /// Reported rather than folded into the default: a publisher using an id
    /// this build does not know is a fact about the capture, and calling it
    /// `zenoh/bytes` would erase it.
    Unknown {
        /// The wire id, as read.
        id: u16,
    },
    /// The record carried no encoding field at all, which on the wire means
    /// the default (`zenoh/bytes`, id 0).
    Absent,
}

impl<'a> Encoding<'a> {
    /// Read the WIRE WORD — `(id << 1) | has_schema`, the packing
    /// `wz_capi_core::encoding_ids` documents — plus the schema it points at.
    pub fn from_packed(packed_id: u32, schema: Option<&'a str>) -> Self {
        let id = (packed_id >> 1) as u16;
        match ENCODING_ID_TO_STR.get(id as usize) {
            Some(name) => Encoding::Known {
                id,
                name,
                // The schema is taken from the STORED field rather than
                // synthesised from the flag: the low bit says one should be
                // there, and a record whose flag and field disagree must not
                // be made to look consistent here.
                schema,
            },
            None => Encoding::Unknown { id },
        }
    }

    /// The table name, or `None` for an unknown id.
    pub fn name(&self) -> Option<&'static str> {
        match self {
            Encoding::Known { name, .. } => Some(name),
            Encoding::Absent => ENCODING_ID_TO_STR.first().copied(),
            Encoding::Unknown { .. } => None,
        }
    }

    /// What this declaration claims about the bytes.
    pub fn shape(&self) -> Shape {
        let Some(name) = self.name() else {
            return Shape::Unclaimed;
        };
        shape_of(name)
    }
}

/// The name-to-shape rule, in one place.
///
/// Conservative on purpose. `application/json5` and `application/json-seq` are
/// NOT [`Shape::Json`]: json5 admits comments and trailing commas that a strict
/// scanner rejects, and a json-seq body is several values with a separator
/// between them. Judging either with a strict validator would manufacture a
/// [`crate::payload::Verdict::NotAsDeclared`] against a publisher that did nothing wrong — a
/// false finding, which is worse here than a missing one because this plane
/// exists to produce findings.
pub(crate) fn shape_of(name: &str) -> Shape {
    match name {
        "application/json" | "text/json" => Shape::Json,
        "zenoh/string" => Shape::Utf8Text,
        // Everything the table spells `text/*` is text by definition, and these
        // `application/*` entries are text formats whose bytes a reader can
        // legitimately be shown as characters.
        "application/yaml"
        | "application/xml"
        | "application/x-www-form-urlencoded"
        | "application/sql"
        | "application/json-patch+json"
        | "application/json-seq"
        | "application/jsonpath"
        | "application/jwt"
        | "application/yang"
        | "application/soap+xml"
        | "application/openmetrics-text" => Shape::Utf8Text,
        other if other.starts_with("text/") => Shape::Utf8Text,
        _ => Shape::Binary,
    }
}

/// Why a payload does not match what it declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mismatch {
    /// Declared as text, and the bytes are not valid UTF-8.
    NotUtf8 {
        /// Byte offset of the first invalid sequence.
        at: usize,
    },
    /// Declared as JSON, and the scan stopped.
    NotJson {
        /// Byte offset where the scan stopped.
        at: usize,
        /// What was wrong there, in one phrase.
        reason: &'static str,
    },
}

/// What one JSON payload turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonSummary {
    /// The kind of the top-level value.
    pub top_level: JsonKind,
    /// Deepest nesting reached.
    pub depth: usize,
}

/// The six JSON value kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonKind {
    Object,
    Array,
    String,
    Number,
    Bool,
    Null,
}

/// What this module concluded about one payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// Nothing to look at.
    Empty,
    /// Valid UTF-8, and here it is.
    Text(&'a str),
    /// One well-formed JSON value.
    Json(JsonSummary),
    /// Declared binary (or unknown): the bytes are shown as bytes and nothing
    /// is claimed about them.
    Opaque {
        /// How many bytes.
        bytes: usize,
    },
    /// R311y622 (§1.1o) — the payload slot holds an SHM DESCRIPTOR and the
    /// data it stands for never traversed the network
    /// (`body_ext_id::SHM`, `zextunit!(0x2, true)`).
    ///
    /// A NAMED ABSENCE, and the reason it must exist rather than the bytes
    /// being judged: a descriptor is a handle into a segment on the sender's
    /// host, so inspecting it against a declared `application/json` produces a
    /// CONTRADICTION against a publisher that did nothing wrong. Reading an
    /// observer's own reach limit as a sender's defect is the worst answer
    /// available here -- worse than silence, because it is confident.
    NotOnTheWire {
        /// The name the sender declared for data this capture does not hold.
        declared: &'static str,
        /// Bytes of DESCRIPTOR in the payload slot -- not bytes of data.
        descriptor_bytes: usize,
    },
    /// The payload does not match its own declaration.
    ///
    /// The FINDING this plane exists to produce.
    NotAsDeclared {
        /// The name the sender declared.
        declared: &'static str,
        /// Where the claim broke.
        reason: Mismatch,
    },
}

impl Verdict<'_> {
    /// `true` when the bytes matched what the record said they were.
    ///
    /// An [`Verdict::Opaque`] payload counts as consistent: nothing was claimed
    /// beyond "bytes", so nothing can contradict it.
    ///
    /// R311y622 — [`Verdict::NotOnTheWire`] does NOT. A descriptor agreed with
    /// nothing, and answering `true` here would let a caller checking "did
    /// everything verify" get a yes for traffic it never saw.
    pub fn is_consistent(&self) -> bool {
        matches!(
            self,
            Verdict::Empty | Verdict::Text(_) | Verdict::Json(_) | Verdict::Opaque { .. }
        )
    }
}

/// Judge one payload against one declaration.
///
/// The entry point. Never renders a payload as its declared type without
/// checking it first, and never falls back to a looser rendering when the check
/// fails — a fallback would turn a finding into a shrug.
pub fn inspect<'a>(encoding: Encoding<'_>, bytes: &'a [u8]) -> Verdict<'a> {
    if bytes.is_empty() {
        return Verdict::Empty;
    }
    match encoding.shape() {
        Shape::Utf8Text => match core::str::from_utf8(bytes) {
            Ok(text) => Verdict::Text(text),
            Err(e) => Verdict::NotAsDeclared {
                declared: encoding.name().unwrap_or("text"),
                reason: Mismatch::NotUtf8 {
                    at: e.valid_up_to(),
                },
            },
        },
        Shape::Json => match scan_json(bytes) {
            Ok(summary) => Verdict::Json(summary),
            Err((at, reason)) => Verdict::NotAsDeclared {
                declared: encoding.name().unwrap_or("application/json"),
                reason: Mismatch::NotJson { at, reason },
            },
        },
        Shape::Binary | Shape::Unclaimed => Verdict::Opaque { bytes: bytes.len() },
    }
}

// ── the JSON scanner ────────────────────────────────────────────────────────
//
// Hand-written because this crate carries no third-party dependencies, and a
// validator is the small half of a parser: it answers well-formed-or-where, and
// builds nothing. RFC 8259 grammar, with the two rules a naive scanner gets
// wrong -- a leading zero is not a number prefix (`01` is two tokens, so the
// document has trailing input), and a control character below 0x20 is illegal
// INSIDE a string even though it is legal whitespace outside one.

struct Scanner<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
    max_depth: usize,
    /// R311y909 — the rows this walk is BUILDING, or `None` when it is only
    /// validating.
    ///
    /// One grammar with two outputs rather than two grammars: [`scan_json`]
    /// answers well-formed-or-where for [`inspect`], and [`walk_json`] answers
    /// the same question and hands back the fields. A second reader would be a
    /// second opinion about what JSON is, and this crate has measured what a
    /// second notion of a boundary costs (`crate::agg`'s framing, three times).
    emit: Option<Emit>,
}

/// R311y909 — the emitting half of [`Scanner`]: the rows so far, the path of
/// the value being walked, and the member count of the container just closed.
struct Emit {
    fields: Vec<formats::PayloadField>,
    /// The path of the value currently being walked — `$`, `$.sensor.temp`,
    /// `$.readings.0`.
    path: String,
    /// How many members or elements the container that just returned held.
    /// Read by [`Scanner::fill`] the moment that container's row is written,
    /// which is the only point at which it is about that container.
    members: usize,
}

/// R311y909 — the root of a JSON field path.
///
/// JSONPath's own root symbol, so a reader who has seen one anywhere else
/// already knows what it means, and — the reason it is a symbol at all — so
/// that every row is ROOTED. An unrooted scheme makes the document's own row
/// pathless and collides a top-level member named `$` with it; rooted, the
/// document is `$`, that member is `$.$`, and the two are told apart.
pub(crate) const JSON_ROOT_PATH: &str = "$";

/// The separator between path segments. Shared with the protobuf decoder's
/// `2.1` form on purpose: `--payload-name` keys on one path syntax, and a
/// second one would be a second thing for a reader to hold.
const JSON_PATH_SEP: char = '.';

/// What a member whose key is not UTF-8 is called.
///
/// A key this reader cannot print is not a name it may invent one for: putting
/// a plausible name on a real row is the failure mode this whole plane exists
/// to avoid. RFC 8259 requires a JSON text to be UTF-8, so a key that reaches
/// this is already outside the format — see the caveat on [`walk_json`].
const JSON_UNNAMEABLE_KEY: &str = "<not-utf8>";

/// Guard against a document whose nesting would recurse this scanner off the
/// stack. 128 is deeper than any zenoh payload observed and shallow enough to
/// be safe on the MCU profile this crate also builds for; a document deeper
/// than that is REPORTED, not silently accepted.
pub(crate) const MAX_JSON_DEPTH: usize = 128;

/// R311y909 — the word a row leads with, one per [`JsonKind`].
///
/// A TOTAL match rather than a `_ =>` fallback, on this crate's own rule for
/// wire-name functions: a seventh kind must be named here rather than silently
/// rendered as whichever string happened to be the default.
const fn json_kind_word(kind: JsonKind) -> &'static str {
    match kind {
        JsonKind::Object => "object",
        JsonKind::Array => "array",
        JsonKind::String => "string",
        JsonKind::Number => "number",
        JsonKind::Bool => "bool",
        JsonKind::Null => "null",
    }
}

type ScanErr = (usize, &'static str);

/// R311y891 — is `bytes` a well-formed JSON document, by THIS crate's scanner?
///
/// Exposed crate-internally so [`crate::report`]'s emitter can be judged by the
/// validator this crate already ships instead of by a second reading of RFC
/// 8259 typed into a test. That matters here for one reason: a test that
/// asserted "the escaped form appears in the output" is a test about a
/// SPELLING, and it passes over a document whose next field is malformed for
/// some other reason. This answers the property.
///
/// The offset and the reason ride the error because a bare `false` about a
/// 4 KB document is not diagnosable.
///
/// `cfg(test)` because the only caller that should ever exist is a test: a
/// PRODUCTION consumer validating this crate's own emit would be asking the
/// writer whether the writer was right.
#[cfg(test)]
pub(crate) fn json_wellformed(bytes: &[u8]) -> Result<(), ScanErr> {
    scan_json(bytes).map(|_| ())
}

/// The one walk, with or without an emitter.
fn scan(bytes: &[u8], emit: Option<Emit>) -> Result<(JsonSummary, Option<Emit>), ScanErr> {
    let mut s = Scanner {
        b: bytes,
        i: 0,
        depth: 0,
        max_depth: 0,
        emit,
    };
    s.ws();
    let top = s.value()?;
    s.ws();
    if s.i != s.b.len() {
        return Err((s.i, "trailing input after the top-level value"));
    }
    Ok((
        JsonSummary {
            top_level: top,
            depth: s.max_depth,
        },
        s.emit,
    ))
}

fn scan_json(bytes: &[u8]) -> Result<JsonSummary, ScanErr> {
    scan(bytes, None).map(|(summary, _)| summary)
}

/// R311y909 — the same walk, EMITTING: one row per JSON value, in reading
/// order, each with the byte range it was decoded from.
///
/// # What the rows are, and what a path means
///
/// Every value gets a row, containers included, so a reader sees the shape
/// before the leaves: `$` names the document, `$.sensor` the member under it,
/// `$.readings.0` the first element of an array under `readings`. A container's
/// row carries how many members it holds and its children follow it, which is
/// the order [`crate::payload_builtin::Protobuf`] already emits in.
///
/// # The span is the VALUE, not the member
///
/// A member's row spans its value's bytes and not the `"key": ` in front of
/// them. Two reasons, and the first is the one that decides it: an array
/// element has no key, so a member-wide span would make the same field mean
/// two different byte ranges depending on what contained it. The second is that
/// the key is not lost — it IS the last segment of the path.
///
/// # Names come from the path, never from [`formats::PayloadField::name`]
///
/// JSON carries its own names, which protobuf does not, and it would be easy to
/// read that as licence to fill `name` in. It is not: that field's contract is
/// "the DECLARED name, from `FormatMap::field_name`", and a decoder writing it
/// would make one field mean two provenances. A JSON name is on the wire, so it
/// belongs where the wire put it — in the path.
///
/// # The caveat, stated rather than hidden
///
/// A member key containing a `.` produces a path that reads as nesting:
/// `{"a.b": 1}` yields `$.a.b`, which is also what `{"a":{"b":1}}` yields. The
/// spans differ and the container rows above them differ, so a reader has the
/// evidence, but a `--payload-name` declaration keyed on that path cannot tell
/// the two apart. Registered rather than papered over.
pub(crate) fn walk_json(bytes: &[u8]) -> Result<Vec<formats::PayloadField>, ScanErr> {
    let emit = Emit {
        fields: Vec::new(),
        path: String::from(JSON_ROOT_PATH),
        members: 0,
    };
    let (_, emit) = scan(bytes, Some(emit))?;
    Ok(emit.expect("the walk was handed an emitter").fields)
}

impl<'a> Scanner<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, c: u8, what: &'static str) -> Result<(), ScanErr> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err((self.i, what))
        }
    }

    fn literal(&mut self, word: &[u8], kind: JsonKind) -> Result<JsonKind, ScanErr> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(kind)
        } else {
            Err((self.i, "not a JSON value"))
        }
    }

    /// R311y909 — reserve this value's row BEFORE walking it, so a container
    /// lands above its children rather than below them.
    ///
    /// The placeholder is overwritten by [`Self::fill`]. A walk that errors
    /// leaves it behind, which costs nothing: an error abandons the whole
    /// document, and [`walk_json`] returns the error rather than the rows.
    fn reserve(&mut self) -> Option<usize> {
        let e = self.emit.as_mut()?;
        let at = e.fields.len();
        e.fields.push(formats::PayloadField {
            path: String::new(),
            name: None,
            value: String::new(),
            start: 0,
            end: 0,
        });
        Some(at)
    }

    /// Write the reserved row, now that the value's extent and kind are known.
    fn fill(&mut self, slot: Option<usize>, start: usize, kind: JsonKind) {
        let Some(slot) = slot else { return };
        let end = self.i;
        let b: &'a [u8] = self.b;
        let raw = &b[start..end];
        let Some(e) = self.emit.as_mut() else { return };
        let value = match kind {
            JsonKind::Object => alloc::format!("object {} member(s)", e.members),
            JsonKind::Array => alloc::format!("array {} element(s)", e.members),
            JsonKind::Null => String::from("null"),
            // A string, a number or a bool IS its source text, so the row shows
            // it verbatim -- escapes included, because what the publisher wrote
            // is what a reader comparing against the capture will see.
            _ => match core::str::from_utf8(raw) {
                Ok(text) => alloc::format!("{} {text}", json_kind_word(kind)),
                // RFC 8259 requires UTF-8 and this scanner does not enforce it
                // inside a string (see `walk_json`), so the row says what it
                // has rather than lossily inventing characters.
                Err(_) => {
                    alloc::format!("{} {} byte(s), not UTF-8", json_kind_word(kind), raw.len())
                }
            },
        };
        let path = e.path.clone();
        e.fields[slot] = formats::PayloadField {
            path,
            name: None,
            value,
            start,
            end,
        };
    }

    /// Record how many members the container that just closed held.
    fn closed(&mut self, members: usize) {
        if let Some(e) = self.emit.as_mut() {
            e.members = members;
        }
    }

    /// Extend the path by one object key, whose string began at `key_at` and
    /// which the cursor has just walked past. `None` when not emitting.
    fn push_key(&mut self, key_at: usize) -> Option<usize> {
        let b: &'a [u8] = self.b;
        // `string()` has consumed both quotes, so the key's own bytes are the
        // range between them.
        let raw = &b[key_at + 1..self.i - 1];
        let e = self.emit.as_mut()?;
        let mark = e.path.len();
        e.path.push(JSON_PATH_SEP);
        match core::str::from_utf8(raw) {
            Ok(text) => e.path.push_str(text),
            Err(_) => e.path.push_str(JSON_UNNAMEABLE_KEY),
        }
        Some(mark)
    }

    /// Extend the path by one array index. `None` when not emitting.
    fn push_index(&mut self, index: usize) -> Option<usize> {
        let e = self.emit.as_mut()?;
        let mark = e.path.len();
        e.path.push(JSON_PATH_SEP);
        e.path.push_str(&alloc::format!("{index}"));
        Some(mark)
    }

    /// Undo a [`Self::push_key`] / [`Self::push_index`].
    fn pop_segment(&mut self, mark: Option<usize>) {
        if let (Some(e), Some(mark)) = (self.emit.as_mut(), mark) {
            e.path.truncate(mark);
        }
    }

    fn value(&mut self) -> Result<JsonKind, ScanErr> {
        let start = self.i;
        let slot = self.reserve();
        let kind = self.value_inner()?;
        self.fill(slot, start, kind);
        Ok(kind)
    }

    fn value_inner(&mut self) -> Result<JsonKind, ScanErr> {
        match self.peek() {
            None => Err((self.i, "expected a value, found end of input")),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => {
                self.string()?;
                Ok(JsonKind::String)
            }
            Some(b't') => self.literal(b"true", JsonKind::Bool),
            Some(b'f') => self.literal(b"false", JsonKind::Bool),
            Some(b'n') => self.literal(b"null", JsonKind::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => Err((self.i, "not a JSON value")),
        }
    }

    fn enter(&mut self) -> Result<(), ScanErr> {
        self.depth += 1;
        if self.depth > MAX_JSON_DEPTH {
            return Err((self.i, "nesting deeper than this scanner accepts"));
        }
        if self.depth > self.max_depth {
            self.max_depth = self.depth;
        }
        Ok(())
    }

    fn object(&mut self) -> Result<JsonKind, ScanErr> {
        self.enter()?;
        self.i += 1; // '{'
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            self.depth -= 1;
            self.closed(0);
            return Ok(JsonKind::Object);
        }
        let mut members = 0usize;
        loop {
            self.ws();
            let key_at = self.i;
            self.string()?;
            let mark = self.push_key(key_at);
            self.ws();
            self.expect(b':', "expected ':' after an object key")?;
            self.ws();
            self.value()?;
            self.pop_segment(mark);
            members += 1;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    self.depth -= 1;
                    self.closed(members);
                    return Ok(JsonKind::Object);
                }
                _ => return Err((self.i, "expected ',' or '}' in an object")),
            }
        }
    }

    fn array(&mut self) -> Result<JsonKind, ScanErr> {
        self.enter()?;
        self.i += 1; // '['
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            self.depth -= 1;
            self.closed(0);
            return Ok(JsonKind::Array);
        }
        let mut elements = 0usize;
        loop {
            self.ws();
            let mark = self.push_index(elements);
            self.value()?;
            self.pop_segment(mark);
            elements += 1;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    self.depth -= 1;
                    self.closed(elements);
                    return Ok(JsonKind::Array);
                }
                _ => return Err((self.i, "expected ',' or ']' in an array")),
            }
        }
    }

    fn string(&mut self) -> Result<(), ScanErr> {
        self.expect(b'"', "expected a string")?;
        loop {
            match self.peek() {
                None => return Err((self.i, "unterminated string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(());
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.peek() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.i += 1,
                        Some(b'u') => {
                            self.i += 1;
                            for _ in 0..4 {
                                match self.peek() {
                                    Some(c) if c.is_ascii_hexdigit() => self.i += 1,
                                    _ => return Err((self.i, "\\u needs four hex digits")),
                                }
                            }
                        }
                        _ => return Err((self.i, "unknown escape")),
                    }
                }
                // RFC 8259 §7: the characters that must be escaped are the
                // quote, the reverse solidus, and everything below 0x20. A
                // literal newline inside a string is the common producer bug
                // this catches.
                Some(c) if c < 0x20 => {
                    return Err((self.i, "unescaped control character in a string"))
                }
                Some(_) => self.i += 1,
            }
        }
    }

    fn number(&mut self) -> Result<JsonKind, ScanErr> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            // A leading zero admits no more digits: `01` is not a JSON number,
            // and a scanner that accepted it would then report the document as
            // valid rather than as having trailing input.
            Some(b'0') => self.i += 1,
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            _ => return Err((self.i, "expected a digit")),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            let before = self.i;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
            if self.i == before {
                return Err((self.i, "a fraction needs at least one digit"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            let before = self.i;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
            if self.i == before {
                return Err((self.i, "an exponent needs at least one digit"));
            }
        }
        debug_assert!(self.i > start);
        Ok(JsonKind::Number)
    }
}

// ── the census plane ────────────────────────────────────────────────────────

/// What one declared encoding carried across a capture.
#[cfg(feature = "network-codecs")]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EncodingRow {
    /// The declared name, or `id <n>` for an id the table does not answer to.
    pub declared: String,
    /// Payloads carrying this declaration.
    pub payloads: usize,
    /// Of those, how many the bytes agreed with.
    pub consistent: usize,
    /// Of those, how many CONTRADICTED the declaration.
    pub not_as_declared: usize,
    /// R311y622 (§1.1o) — of those, how many carried an SHM DESCRIPTOR instead
    /// of the data. Its own column because it is neither: nothing agreed and
    /// nothing contradicted, because there was nothing here to read.
    pub descriptors: usize,
    /// Payload bytes under this declaration.
    pub bytes: u64,
}

/// One payload that contradicted its own declaration, kept rather than counted.
///
/// Carried individually for the reason [`crate::agg::UnresolvedAlias`] is: "9
/// payloads did not match" is not actionable, and the keyexpr plus the offset
/// says whether one publisher is broken or a whole topic is.
#[cfg(feature = "network-codecs")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contradiction {
    /// The keyexpr it travelled under, when the capture could resolve one.
    pub keyexpr: Option<String>,
    /// What the record declared.
    pub declared: String,
    /// Where the claim broke.
    pub reason: Mismatch,
}

/// Every payload in a capture, judged against its own declaration.
#[cfg(feature = "network-codecs")]
#[derive(Debug, Default, Clone)]
pub struct PayloadCensus {
    rows: alloc::collections::BTreeMap<String, EncodingRow>,
    contradictions: Vec<Contradiction>,
    payloads: usize,
    unknown_ids: usize,
    descriptors: usize,
    gaps: crate::agg::ThroughputGaps,
    selection: crate::filter::Selection,
    /// R311y638 (§1.1r) — where the capture began, for the `elapsed` term. Set
    /// only by [`payloads_where`], the entry point that has the whole capture.
    capture_origin_ms: Option<u64>,
}

#[cfg(feature = "network-codecs")]
impl PayloadCensus {
    /// An empty census.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every declaration seen, most payloads first.
    pub fn rows(&self) -> Vec<&EncodingRow> {
        let mut rows: Vec<&EncodingRow> = self.rows.values().collect();
        rows.sort_by(|a, b| {
            b.payloads
                .cmp(&a.payloads)
                .then_with(|| b.bytes.cmp(&a.bytes))
                .then_with(|| a.declared.cmp(&b.declared))
        });
        rows
    }

    /// The payloads that contradicted their own declaration.
    ///
    /// A NON-EMPTY answer is the point of this plane, not a failure of it.
    pub fn contradictions(&self) -> &[Contradiction] {
        &self.contradictions
    }

    /// Payloads judged.
    pub fn payloads(&self) -> usize {
        self.payloads
    }

    /// Payloads whose declared id is not in this build's table.
    pub fn unknown_ids(&self) -> usize {
        self.unknown_ids
    }

    /// R311y622 (§1.1o) — payloads whose slot held an SHM DESCRIPTOR, so the
    /// data never traversed the network and this plane could not judge it.
    ///
    /// A NAMED absence rather than a gap or a finding. Not a gap, because
    /// nothing was lost in transit and no reader could ever have seen it from a
    /// capture; not a finding, because the publisher did nothing wrong. It is
    /// the honest third answer, and without it an SHM capture reads as either
    /// clean or broken, both of which are false.
    pub fn descriptors(&self) -> usize {
        self.descriptors
    }

    /// Traffic this plane could not read at all — the same shape
    /// [`crate::agg::ThroughputTable::gaps`] carries, for the same reason.
    pub fn gaps(&self) -> crate::agg::ThroughputGaps {
        self.gaps
    }

    /// R311y618 (§1.1q) — what the selector did to the PAYLOADS it was shown.
    ///
    /// One verdict per payload, so this is directly comparable with
    /// [`Self::payloads`]: the unit here is the record, as in the throughput
    /// plane, and NOT the exchange as in [`crate::exchange`]. A payload is
    /// judged on its own because it is complete on its own — everything a
    /// predicate can ask about it travels in the same record.
    pub fn selection(&self) -> crate::filter::Selection {
        self.selection
    }

    /// R311y618 (§1.1q) — the same census, over the payloads a selector picks.
    ///
    /// A rejected payload is not inspected, not counted and not a finding. That
    /// last one is the consequence worth stating: a selector NARROWS what this
    /// plane will report a contradiction about, so a reader who asks
    /// `key == app/**` and sees no findings has learned nothing about the rest
    /// of the capture. [`Self::selection`] is what makes that legible, and it is
    /// why the report renders it beside the finding count rather than under it.
    pub fn observe_flow_where(
        &mut self,
        frames: &[wz_session_core::passive::PassiveFrame],
        filter: &crate::filter::Filter,
    ) {
        use wz_session_core::passive::Carried;

        let mut spaces = crate::agg::KeyexprSpaces::new();
        for frame in frames {
            match &frame.carried {
                Carried::Batch(batch) => self.observe_batch(&mut spaces, frame, batch, filter),
                #[cfg(feature = "reassembly")]
                Carried::Reassembled(batch) => {
                    self.observe_batch(&mut spaces, frame, batch, filter)
                }
                // Matched by name for the reason R311y614 matched them by name
                // in the throughput plane: a new `Carried` variant must fail to
                // compile here rather than join the silent set.
                Carried::Undecompressible => self.gaps.undecompressible_batches += 1,
                #[cfg(feature = "reassembly")]
                Carried::FragmentWithoutResolution => self.gaps.unresolvable_fragments += 1,
                Carried::Nothing => {}
                #[cfg(feature = "reassembly")]
                Carried::Fragment(_) => {}
            }
        }
    }

    fn observe_batch(
        &mut self,
        spaces: &mut crate::agg::KeyexprSpaces,
        frame: &wz_session_core::passive::PassiveFrame,
        batch: &wz_session_core::network_message::BatchParse,
        filter: &crate::filter::Filter,
    ) {
        if batch.halt.is_some() {
            self.gaps.halted_batches += 1;
            self.gaps.unparsed_bytes += batch.unparsed_bytes;
        }
        // R311y641 (§1.1n) — paired with the bytes each record came from, so
        // this plane can say WHERE a record was and not only that it was.
        for (message, span) in batch.records() {
            self.observe_message(spaces, frame, message, span, filter);
        }
    }

    fn observe_message(
        &mut self,
        spaces: &mut crate::agg::KeyexprSpaces,
        frame: &wz_session_core::passive::PassiveFrame,
        message: &wz_session_core::network_message::NetworkMessage,
        span: Option<(usize, usize)>,
        filter: &crate::filter::Filter,
    ) {
        use wz_session_core::network_message::NetworkMessage;

        let direction = frame.direction;
        if let NetworkMessage::Declare(d) = message {
            spaces.absorb(direction, d);
            return;
        }
        let Some((keyexpr_body, declared, bytes, shm)) = carried_payload(message) else {
            return;
        };
        let keyexpr = spaces.resolve(direction, keyexpr_body).ok();
        // R311y618 — asked after resolution and before the bytes are inspected.
        // The kind comes from the throughput plane's classifier, so a payload
        // that arrived inside a `Response` answers `kind == reply` here exactly
        // as it does there; deriving it locally is the second spelling that
        // would let the two planes disagree about one record.
        let (kind, payload_bytes) = match crate::agg::classify(message) {
            Some((_, counts, kind)) => (kind, crate::agg::sized_payload(&counts)),
            None => (crate::filter::RecordKind::Put, Some(0)),
        };
        let truth = filter.matches(&crate::filter::RecordView {
            direction,
            keyexpr: keyexpr.as_deref(),
            kind,
            payload_bytes,
            unit_offset: crate::agg::record_unit_offset(frame, span),
            // R311y644 (§1.1p) — the census of clock-offset witnesses belongs
            // to the throughput plane, so this one reads the axis and does not
            // count what it cannot own.
            source_delay_ms: crate::agg::source_delay_ms(
                frame.observed_at_ms,
                crate::agg::source_timestamp(message),
            )
            .unwrap_or(None),
            observed_at_ms: frame.observed_at_ms,
            elapsed_ms: crate::agg::elapsed_since(self.capture_origin_ms, frame.observed_at_ms),
            // R311y636 (§1.1v) — as in `agg`: this plane inspects one payload
            // and correlates nothing, so an outcome term over it is undecidable
            // rather than false.
            outcome: None,
        });
        self.selection.record(truth);
        if truth != crate::filter::Truth::Yes {
            return;
        }
        let encoding = match declared {
            Some(e) => Encoding::from_packed(e.packed_id, e.schema.as_deref()),
            None => Encoding::Absent,
        };
        // R311y622 (§1.1o) — the marker is read BEFORE the bytes are, because
        // the bytes are not the data. `inspect` would judge a descriptor
        // against the declaration and manufacture a finding against a publisher
        // that did nothing wrong.
        let verdict = if shm {
            Verdict::NotOnTheWire {
                declared: encoding.name().unwrap_or("zenoh/bytes"),
                descriptor_bytes: bytes.len(),
            }
        } else {
            inspect(encoding, bytes)
        };
        self.record(encoding, keyexpr, bytes.len() as u64, verdict);
    }

    fn record(
        &mut self,
        encoding: Encoding<'_>,
        keyexpr: Option<String>,
        bytes: u64,
        verdict: Verdict<'_>,
    ) {
        use alloc::string::ToString;

        self.payloads += 1;
        let declared = match encoding {
            Encoding::Known { name, .. } => name.to_string(),
            Encoding::Absent => "zenoh/bytes (undeclared)".to_string(),
            Encoding::Unknown { id } => {
                self.unknown_ids += 1;
                alloc::format!("id {id} (unknown to this build)")
            }
        };
        let row = self
            .rows
            .entry(declared.clone())
            .or_insert_with(|| EncodingRow {
                declared: declared.clone(),
                ..Default::default()
            });
        row.payloads += 1;
        row.bytes += bytes;
        match verdict {
            Verdict::NotAsDeclared { reason, .. } => {
                row.not_as_declared += 1;
                self.contradictions.push(Contradiction {
                    keyexpr,
                    declared,
                    reason,
                });
            }
            // R311y622 (§1.1o) — NOT `consistent`. A descriptor agreed with
            // nothing: this plane never saw the data, and counting it as
            // verified would let an SHM-heavy capture report a clean bill of
            // health for traffic nobody inspected.
            Verdict::NotOnTheWire { .. } => {
                row.descriptors += 1;
                self.descriptors += 1;
            }
            _ => row.consistent += 1,
        }
    }
}

/// R311y639 (§4.30) — the SHM-marker predicate moved to [`crate::agg`], which
/// is where the classification it shares a rule with lives. It was private here
/// while the throughput plane read the same four carriers and never asked, so
/// this plane refused to judge a descriptor as data and that one reported the
/// descriptor slot's length as a byte total. One function, one answer.
#[cfg(feature = "network-codecs")]
use crate::agg::carries_shm_marker;

/// The declared encoding and the bytes a record carries, with its keyexpr.
///
/// R311y622 (§1.1s) — `Err` bodies ARE folded in now, and the note that used to
/// stand here justified excluding them by saying it "would put a row on a topic
/// that published nothing". That reason does not describe this plane: its rows
/// are keyed by the DECLARED ENCODING NAME, never by a keyexpr, so an error
/// body adds to `text/plain` and puts a row on no topic at all. The exclusion
/// rested on a description of a data structure this plane does not have.
///
/// What DOES describe it: an `Err` carries `encoding` and `payload` — the same
/// two fields a `MsgPut` does (`out/wz-codecs/err.rs:34-40`) — so a responder
/// can declare `application/json` on an error and send bytes that are not JSON,
/// which is a contradiction of exactly the kind this plane exists to name. It
/// was unreachable here, and so was the `err` term of the filter language: the
/// vocabulary had [`RecordKind::Err`](crate::filter::RecordKind) all along and
/// this plane could never produce one, so `kind == err` was a question with a
/// permanent answer.
#[cfg(feature = "network-codecs")]
#[allow(clippy::type_complexity)]
fn carried_payload(
    message: &wz_session_core::network_message::NetworkMessage,
) -> Option<(
    &wz_codecs::wireexpr::WireexprOwnedVariant,
    Option<&wz_codecs::encoding::EncodingOwned>,
    &[u8],
    bool,
)> {
    use wz_codecs::push::PushOwnedVariant;
    use wz_codecs::reply::ReplyOwnedVariant;
    use wz_codecs::request::RequestOwnedVariant;
    use wz_codecs::response::ResponseOwnedVariant;
    use wz_session_core::network_message::NetworkMessage;

    // A free fn rather than a closure: the two borrows must carry the CALLER's
    // lifetime, and a closure's inferred one is tied to the call.
    fn put<'a>(
        k: &'a wz_codecs::wireexpr::WireexprOwnedVariant,
        p: &'a wz_codecs::msg_put::MsgPutOwned,
    ) -> (
        &'a wz_codecs::wireexpr::WireexprOwnedVariant,
        Option<&'a wz_codecs::encoding::EncodingOwned>,
        &'a [u8],
        bool,
    ) {
        (
            k,
            p.encoding.as_ref(),
            p.payload.as_slice(),
            carries_shm_marker(p.extensions.as_deref()),
        )
    }
    match message {
        NetworkMessage::Push(p) => match &p.body {
            PushOwnedVariant::CodecZenohMsgPut(m) | PushOwnedVariant::Default { body: m, .. } => {
                Some(put(&p.keyexpr.body, m))
            }
            PushOwnedVariant::CodecZenohMsgDel(_) => None,
        },
        NetworkMessage::Request(r) => match &r.body {
            RequestOwnedVariant::CodecZenohMsgPut(m) => Some(put(&r.keyexpr.body, m)),
            _ => None,
        },
        NetworkMessage::Response(r) => match &r.body {
            ResponseOwnedVariant::CodecZenohReply(reply)
            | ResponseOwnedVariant::Default { body: reply, .. } => match &reply.body {
                ReplyOwnedVariant::CodecZenohMsgPut(m)
                | ReplyOwnedVariant::Default { body: m, .. } => Some(put(&r.keyexpr.body, m)),
                // A reply carrying a Del has no payload to judge.
                ReplyOwnedVariant::CodecZenohMsgDel(_) => None,
            },
            ResponseOwnedVariant::CodecZenohErr(e) => Some((
                &r.keyexpr.body,
                e.encoding.as_ref(),
                e.payload.as_slice(),
                carries_shm_marker(e.extensions.as_deref()),
            )),
        },
        _ => None,
    }
}

/// Judge every payload in a dissection.
///
/// The production entry point, shaped like [`crate::agg::aggregate`] and
/// [`crate::exchange::exchanges`]: one walk per plane, each resolving keyexprs
/// against its own per-flow id spaces.
#[cfg(feature = "network-codecs")]
pub fn payloads(dissection: &crate::Dissection) -> PayloadCensus {
    payloads_where(dissection, &crate::filter::Filter::any())
}

/// R311y618 (§1.1q) — the same census, over the payloads a selector picks.
///
/// The third and last plane to take a [`crate::filter::Filter`], which closes
/// the gap R311y616 left: one compiled selector now narrows every plane of a
/// report, and [`crate::filter::Selection`] rides on each so no plane's totals
/// can be read without the count of what the selector could not judge.
#[cfg(feature = "network-codecs")]
pub fn payloads_where(
    dissection: &crate::Dissection,
    filter: &crate::filter::Filter,
) -> PayloadCensus {
    let mut census = PayloadCensus::new();
    census.capture_origin_ms = dissection.capture_origin_ms();
    // R311y721 — see `agg::aggregate_where`: the dissection's enumeration.
    for (_, frames) in dissection.message_lists() {
        census.observe_flow_where(frames, filter);
    }
    census
}

// R311y617 -- the census half needs the network codecs to have a record to
// judge, so the fixtures below are gated while the language tests above are not.
// R311y617 -- the fixture builders, `pub(crate)` for the same reason
// `exchange::tests` is: `report::tests` needs a capture that CARRIES declared
// payloads, and a second Put-with-encoding builder there is the copy that
// drifts. The cost is `cfg(test)` visibility widening to the crate
// -> [[feedback_cfg_test_is_a_widener_not_a_gate]].
#[cfg(all(test, feature = "network-codecs"))]
pub(crate) mod tests_support {
    use super::*;
    use crate::exchange::tests as fx;

    /// A `Push` under `keyexpr` carrying `payload` DECLARED as `encoding_id`.
    pub(crate) fn push_declaring(
        keyexpr: &'static str,
        encoding_id: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        wz_codecs::push::Push {
            header: wz_codecs::push::Push::default().header | wz_codecs::wire_const::FLAG_N_N,
            keyexpr: fx::sender_space(0, Some(keyexpr)),
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                // The `E` bit, which the codec's own `Default` does not set
                // because a bare Put carries no encoding. NAMED rather than
                // spelled: this fixture's first draft wrote `0x02` -- the wrong
                // one of the three PUT flags -- and the record stopped decoding
                // rather than merely losing its encoding (R311y617 added
                // `FLAG_Z_PUT_E` on the strength of exactly that).
                header: wz_codecs::msg_put::MsgPut::default().header
                    | wz_codecs::wire_const::FLAG_Z_PUT_E,
                encoding: Some(wz_codecs::encoding::Encoding {
                    packed_id: (encoding_id as u32) << 1,
                    schema_len: None,
                    schema: None,
                }),
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// R311y622 (§1.1s) — a `Response` carrying an `Err` whose payload is
    /// DECLARED as `encoding_id`.
    ///
    /// The sibling of [`push_declaring`] on the other half of the plane's
    /// reach. `exchange::tests::response_err` exists and is deliberately not
    /// reused: it carries no encoding, and an error body with no declaration is
    /// the one shape this plane could never have a finding about.
    pub(crate) fn err_declaring(
        keyexpr: &'static str,
        encoding_id: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        wz_codecs::response::Response {
            header: wz_codecs::response::Response::default().header
                | wz_codecs::wire_const::FLAG_N_N,
            request_id: 7,
            keyexpr: fx::sender_space(0, Some(keyexpr)),
            body: wz_codecs::response::ResponseVariant::CodecZenohErr(wz_codecs::err::Err {
                header: wz_codecs::err::Err::default().header | wz_codecs::wire_const::FLAG_Z_ERR_E,
                encoding: Some(wz_codecs::encoding::Encoding {
                    packed_id: (encoding_id as u32) << 1,
                    schema_len: None,
                    schema: None,
                }),
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// R311y622 (§1.1o) — a `Push` whose payload slot holds an SHM DESCRIPTOR:
    /// the body ext chain carries `zextunit!(0x2, true)`.
    ///
    /// The bytes handed in are deliberately NOT the declared type, because that
    /// is the shape that made the plane dangerous: judged as data they
    /// contradict the declaration, and the finding names a publisher that did
    /// nothing wrong.
    pub(crate) fn push_with_shm_descriptor(
        keyexpr: &'static str,
        encoding_id: u16,
        descriptor: &[u8],
    ) -> Vec<u8> {
        // Borrowed form directly: the encoder takes `ExtEntry<'_>` and an
        // owned local would not outlive the struct literal it is placed in.
        let marker = wz_codecs::ext_entry::ExtEntry {
            header: wz_session_core::ext_header::body_ext_id::SHM
                | wz_session_core::ext_header::EXT_FLAG_M,
            body: wz_codecs::ext_entry::ExtEntryVariant::CodecZenohExtUnit(
                wz_codecs::ext_unit::ExtUnit::default(),
            ),
        };
        push_with_body_ext(keyexpr, encoding_id, descriptor, marker)
    }

    /// R311y622 (§1.1o) — THE DISCRIMINATOR'S fixture: a body ext that shares
    /// the SHM marker's 4-BIT ID FIELD and is a DIFFERENT extension, told apart
    /// by its encoding bits exactly as zenoh tells `QoS` from `QoSLink`.
    ///
    /// A ZBuf at id `0x2` with no mandatory bit. Nothing in this fixture is an
    /// SHM descriptor, and a matcher that read the id column alone would call
    /// it one — silencing a payload this plane could have judged, which is the
    /// R311y505 defect pointed the other way.
    pub(crate) fn push_with_foreign_body_ext(
        keyexpr: &'static str,
        encoding_id: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let foreign = wz_codecs::ext_entry::ExtEntry {
            header: wz_session_core::ext_header::body_ext_id::SHM
                | wz_session_core::ext_header::EXT_ENC_ZBUF,
            body: wz_codecs::ext_entry::ExtEntryVariant::CodecZenohExtZbuf(
                wz_codecs::ext_zbuf::ExtZbuf {
                    value_len: 1,
                    value: &[0xAB],
                },
            ),
        };
        push_with_body_ext(keyexpr, encoding_id, payload, foreign)
    }

    /// A `Push` carrying `payload` under a declared encoding, with one entry on
    /// its zenoh-body ext chain. ONE builder for both fixtures above, so the two
    /// captures the discriminator compares differ by that entry and nothing
    /// else.
    fn push_with_body_ext(
        keyexpr: &'static str,
        encoding_id: u16,
        payload: &[u8],
        entry: wz_codecs::ext_entry::ExtEntry<'_>,
    ) -> Vec<u8> {
        wz_codecs::push::Push {
            header: wz_codecs::push::Push::default().header | wz_codecs::wire_const::FLAG_N_N,
            keyexpr: fx::sender_space(0, Some(keyexpr)),
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                header: wz_codecs::msg_put::MsgPut::default().header
                    | wz_codecs::wire_const::FLAG_Z_PUT_E
                    | wz_codecs::wire_const::FLAG_Z_PUT_Z,
                encoding: Some(wz_codecs::encoding::Encoding {
                    packed_id: (encoding_id as u32) << 1,
                    schema_len: None,
                    schema: None,
                }),
                extensions: Some(core::iter::once(entry).collect()),
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// A dissection carrying one A-to-B `Push` per entry.
    pub(crate) fn dissect_pushes(records: &[(&'static str, u16, Vec<u8>)]) -> crate::Dissection {
        let stamped: Vec<(bool, Option<u64>, Vec<u8>)> = records
            .iter()
            .map(|(k, id, p)| (true, Some(1), push_declaring(k, *id, p)))
            .collect();
        fx::dissect(&stamped)
    }
}

/// R311y699 ([REDACTED-REQ]) — a payload format this crate does not know, decoded by
/// somebody who does, selected BY KEY EXPRESSION.
///
/// # Why the mapping is the requirement and the format is the example
///
/// The requirement reads "decode a user-defined format (nanopb / e2e) by key
/// expression mapping". The format list is parenthetical and the deployments
/// differ; what is not optional is that the SELECTION is by keyexpr, because a
/// capture carries many topics and one payload shape per topic is the only
/// thing that makes a schema-less decoder safe to apply at all. A decoder run
/// over the wrong topic does not fail — it produces fields.
///
/// So this crate owns the MAP, and the seam stays open: a consumer with a
/// proprietary format implements [`formats::PayloadFormat`] and never patches
/// a binary here.
///
/// # R311y856 — and the BUILT-IN moved here, which reverses half of a rule
///
/// This doc used to end "so this crate owns the map and never a format",
/// arguing that a decoder is exactly the kind of thing that grows a third-party
/// dependency an MCU profile cannot carry. The rule is right and it did not
/// cover the decoder it was excluding: `formats::Protobuf` is a schemaless walk
/// over base-128 varints written by hand, and it takes NO dependency at all.
///
/// What the misplacement cost was measured by `analysis_surface_parity.py`. The
/// built-ins sat in `wz-analyze`, the command line, so the C ABI -- the surface
/// a product LINKS -- could not decode a payload at all, and the seam it was
/// told to reach (`FormatMap`) was public with nothing on that side able to
/// take one. Moving the decoder beside the map is what R311y851 did for the
/// census emit, for the same reason and in the same words: one implementation
/// beside the type, and neither consumer owning it.
///
/// It is UNGATED, deliberately. A `dissect`-gated built-in would be the tidier
/// dependency story and would move these tests into a lane that `cargo test -p
/// wz-capture` does not run, which is this workspace's most-paid-for failure
/// shape -- and it would buy nothing an MCU build does not already get from the
/// linker dropping a decoder no call site names.
pub mod formats {
    use alloc::borrow::ToOwned;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// One field a format decoder recovered, with the bytes it came from.
    ///
    /// The span is relative to the PAYLOAD, not to the message: a decoder is
    /// handed a payload slice and knows nothing about where that slice sat. The
    /// caller that sliced it is the one that can add its base, and it is the
    /// only one that can — the same rule R311y677 settled for the field layer's
    /// three coordinate spaces.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PayloadField {
        /// A path a reader can key on, e.g. `1` or `3.2` for a nested field.
        pub path: String,
        /// R311y720 (PF4) — the DECLARED name for this path, where a
        /// deployment gave one.
        ///
        /// Always `None` as a decoder returns it, and that is the invariant
        /// worth stating: protobuf's wire format carries no names, so a decoder
        /// filling this in would be inventing one. It is set afterwards, and
        /// only from [`FormatMap::field_name`] -- see that method for why the
        /// declaration is the only honest source.
        pub name: Option<String>,
        /// What the decoder made of it, rendered.
        pub value: String,
        /// First byte of the field, within the payload.
        pub start: usize,
        /// One past the last.
        pub end: usize,
    }

    /// Why a payload did not decode.
    ///
    /// Three answers and not one, because a reader acts differently on each: a
    /// format that says "these are not my bytes" is a mapping question, a
    /// truncation is a capture question, and a malformed field is a sender
    /// question.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PayloadFormatError {
        /// The bytes ran out mid-field, at this offset.
        Truncated(usize),
        /// A field this decoder could not read, and why.
        Malformed { at: usize, why: String },
        /// These bytes are not this format at all. Distinct from a malformed
        /// field: it means the MAPPING is wrong, not the traffic.
        NotThisFormat,
    }

    impl core::fmt::Display for PayloadFormatError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Truncated(at) => write!(f, "the payload ends inside a field at byte {at}"),
                Self::Malformed { at, why } => write!(f, "byte {at}: {why}"),
                Self::NotThisFormat => {
                    write!(f, "these bytes are not this format -- check the mapping")
                }
            }
        }
    }

    /// A decoder for one payload format.
    ///
    /// R311y856 — the built-in ones are [`Protobuf`] and live here, beside the
    /// map, so both consumption surfaces reach them (see the module doc). The
    /// trait stays public for the reason it always was: a consumer with a
    /// proprietary format implements this and never patches a binary here.
    pub trait PayloadFormat {
        /// The name a reader types on the command line.
        fn name(&self) -> &str;
        /// Decode `payload`, or say why not.
        fn decode(&self, payload: &[u8]) -> Result<Vec<PayloadField>, PayloadFormatError>;

        /// R311y873 — the ENCODINGS this format is for, by their table name in
        /// [`wz_codecs::encoding_ids::ENCODING_ID_TO_STR`], or `None` when this
        /// format declines to say.
        ///
        /// # Why a format is asked at all
        ///
        /// A rule is keyed on a key expression and an encoding travels on the
        /// SAMPLE, so one keyexpr legitimately carries two of them. Without
        /// this, `payload_decode::decode_payload` walked a JSON body
        /// with a varint reader because a rule said `demo/**=protobuf` — and
        /// what came back blamed the bytes, which were exactly what their
        /// publisher said they were.
        ///
        /// # Why NAMES and not ids
        ///
        /// `shape_of` settled this for the plane above: derived from the
        /// table name rather than from a second list of ids, so an entry added
        /// upstream lands correctly without an edit here.
        ///
        /// # Why a default, and what declining means
        ///
        /// This trait is an extension point a consumer implements for a
        /// proprietary format without patching this crate, so a required method
        /// would break every such implementation on a version bump. `None` is
        /// therefore the behaviour that was there before: the format is applied
        /// to whatever the rule covers. It is an opt-out that is stated rather
        /// than one taken by omission — a format that names its encodings is
        /// asking to be protected from a mapping that contradicts the wire.
        fn encodings(&self) -> Option<&[&str]> {
            None
        }
    }

    /// Why a mapping rule was refused.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FormatMapError {
        /// The pattern carries a wildcard and this build's keyexpr matcher has
        /// none.
        ///
        /// REFUSED rather than matched literally, which is the rule
        /// [`crate::filter`] settled for the same matcher and the same reason:
        /// with the wildcard features off a `**` token degrades to a literal
        /// chunk, so `demo/**` quietly stops matching `demo/a`. For a filter
        /// that silently empties an answer; here it would silently leave a
        /// payload undecoded while the reader believes their rule is live.
        WildcardUnsupported(String),
        /// The pattern is not a key expression.
        NotAKeyexpr(String),
        /// R311y720 (PF4) — a field-name declaration with an empty path or an
        /// empty name.
        ///
        /// Refused rather than stored: a declaration naming nothing, or naming
        /// a field the empty string, would render as a blank beside a field
        /// number and read as "this reader knows the name and it is nothing".
        EmptyFieldName(String),
        /// R311y856 — the line is not a declaration in either spelling.
        ///
        /// Carried as a variant of its own rather than reported as an empty
        /// pattern, because the two send a reader to different places: an empty
        /// pattern is a declaration with a hole in it, and this is text that is
        /// not a declaration at all.
        NotADeclaration(String),
        /// R311y856 — a format name this build carries no decoder for.
        ///
        /// The refusal `--payload-format` has made since R311y699, moved onto
        /// the map so that EVERY surface makes it. A fallback to "render the
        /// bytes" would leave a reader who typed `protobufff` believing their
        /// rule was live.
        NoSuchFormat(String),
    }

    impl core::fmt::Display for FormatMapError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::EmptyFieldName(p) => write!(
                    f,
                    "the field-name declaration for `{p}` has an empty path or \
                     an empty name"
                ),
                Self::WildcardUnsupported(p) => write!(
                    f,
                    "this build's keyexpr matcher has no wildcards, so the \
                     pattern `{p}` cannot be answered (feature `filter-wildcards`)"
                ),
                Self::NotAKeyexpr(p) => write!(f, "`{p}` is not a key expression"),
                Self::NotADeclaration(line) => write!(
                    f,
                    "`{line}` is not a declaration -- expected \
                     `<keyexpr>=<format>` or `<keyexpr>:<path>=<name>`"
                ),
                Self::NoSuchFormat(name) => write!(
                    f,
                    "this build has no decoder named `{name}` (it has: {})",
                    BUILTIN_NAMES.join(", ")
                ),
            }
        }
    }

    /// Which format decodes the payloads of which key expressions.
    ///
    /// Rules are tried IN INSERTION ORDER and the first match wins, so a
    /// reader can put a specific topic ahead of a wildcard covering its
    /// subtree. Stated because the alternative — longest-pattern-wins — is the
    /// other reasonable rule and a reader must not have to guess which one this
    /// is.
    #[derive(Default)]
    pub struct FormatMap<'a> {
        rules: Vec<(String, &'a dyn PayloadFormat)>,
        /// R311y720 (PF4) — declared field names: (keyexpr pattern, field
        /// path, name). See [`FormatMap::name_field`] for why they are
        /// declared rather than derived.
        names: Vec<(String, String, String)>,
    }

    /// R311y726 — a handle to ONE declaration installed in a [`FormatMap`].
    ///
    /// # Why a handle and not an index
    ///
    /// R311y725 needed to answer "which declarations applied to this capture"
    /// and recorded it INSIDE the map, as a `Cell<bool>` beside each rule. That
    /// made a type which is pure configuration carry state belonging to one RUN
    /// — two analyses sharing a map would have seen each other's marks, and a
    /// map consulted once could never be consulted again as if it were fresh.
    ///
    /// The fix is not to move the flags somewhere else and keep the arithmetic:
    /// a bare `usize` handed out here would be a positional index into a private
    /// `Vec`, which a caller can compute with, compare against `patterns()`, or
    /// hold past a mutation that shifts it. This is opaque — it can be stored,
    /// compared and looked up, and nothing else — so the ONE thing a caller may
    /// do with it is remember it and hand it back.
    ///
    /// Ordered, because the natural ledger of "which of these were used" is a
    /// set, and a set wants an order.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct DeclarationId(usize);

    /// R311y726 — which flag a declaration was installed through.
    ///
    /// Named here rather than in the reader, because the DISTINCTION is a
    /// property of the map: a rule says which decoder reads a topic's payload
    /// and a name says what one path inside it is called, and the two fail to
    /// apply for different reasons. What each one is SPELLED as on a command
    /// line belongs to the reader, and stays there.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum DeclarationKind {
        /// A keyexpr pattern mapped to a payload format.
        FormatRule,
        /// A field path under a keyexpr pattern given a name.
        FieldName,
    }

    /// R311y726 — one installed declaration, as a reader would have to see it
    /// to be told anything about it.
    ///
    /// `text` is the declaration in the syntax it was DECLARED in, rendered by
    /// the map rather than rebuilt by every caller that wants to name one. A
    /// caller that assembled `"{pattern}:{path}={name}"` for itself would be a
    /// second opinion about how a declaration is spelled, which drifts from the
    /// parser that accepted it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Declaration {
        /// The handle, for a ledger of what was used.
        pub id: DeclarationId,
        /// Which flag installed it.
        pub kind: DeclarationKind,
        /// How the reader wrote it.
        pub text: String,
    }

    impl<'a> FormatMap<'a> {
        /// An empty map, which decodes nothing.
        pub fn new() -> Self {
            Self {
                rules: Vec::new(),
                names: Vec::new(),
            }
        }

        /// R311y726 — every declaration installed, rules first, each with the
        /// handle it answers to.
        ///
        /// The population a caller's own "which of these applied" ledger is
        /// diffed against. Rules and names share ONE id space so that ledger is
        /// one set rather than two that can disagree about which is which.
        pub fn declarations(&self) -> Vec<Declaration> {
            let mut out = Vec::with_capacity(self.rules.len() + self.names.len());
            // R311y884 — both halves spelled by `declaration_text`, the mirror of
            // `parse_declaration`. The rule half used to be the bare `pattern`,
            // which carries no `=` and so is not a declaration by the reader's
            // own grammar; `Declaration::text` says "How the reader wrote it"
            // and it now is.
            for (at, (pattern, format)) in self.rules.iter().enumerate() {
                out.push(Declaration {
                    id: DeclarationId(at),
                    kind: DeclarationKind::FormatRule,
                    text: declaration_text(&DeclarationText::Rule {
                        pattern,
                        format: format.name(),
                    }),
                });
            }
            for (at, (pattern, path, name)) in self.names.iter().enumerate() {
                out.push(Declaration {
                    id: DeclarationId(self.rules.len() + at),
                    kind: DeclarationKind::FieldName,
                    text: declaration_text(&DeclarationText::Name {
                        pattern,
                        path,
                        name,
                    }),
                });
            }
            out
        }

        /// Map every keyexpr matching `pattern` to `format`.
        pub fn insert(
            &mut self,
            pattern: &str,
            format: &'a dyn PayloadFormat,
        ) -> Result<(), FormatMapError> {
            if pattern.is_empty() || pattern.starts_with('/') || pattern.ends_with('/') {
                return Err(FormatMapError::NotAKeyexpr(pattern.to_owned()));
            }
            if pattern.contains('*') && !cfg!(feature = "filter-wildcards") {
                return Err(FormatMapError::WildcardUnsupported(pattern.to_owned()));
            }
            self.rules.push((pattern.to_owned(), format));
            Ok(())
        }

        /// The format for this key expression, if a rule covers it.
        ///
        /// Matching is ZENOH'S OWN (`keyexpr_pattern_matches`), not a glob
        /// written here — a second dialect would disagree with the router about
        /// `**` at exactly the interesting cases, which is the argument
        /// [`crate::filter`] already makes for the selector language.
        /// R311y726 — the handle rides along, so a caller that wants to know
        /// which rules applied records it instead of asking a second time.
        pub fn for_keyexpr(&self, keyexpr: &str) -> Option<(DeclarationId, &'a dyn PayloadFormat)> {
            let at = self.rules.iter().position(|(pattern, _)| {
                // The matcher takes CHUNKS, which is the same split
                // `filter::compile_pattern` performs for the same function.
                let chunks: Vec<&str> = pattern.split('/').collect();
                wz_session_core::keyexpr_match::keyexpr_pattern_matches(&chunks, keyexpr)
            })?;
            Some((DeclarationId(at), self.rules[at].1))
        }

        /// Whether any rule was installed. A caller renders nothing for an
        /// empty map rather than a heading with no rows under it.
        pub fn is_empty(&self) -> bool {
            self.rules.is_empty()
        }

        /// The patterns, in the order they are tried.
        pub fn patterns(&self) -> impl Iterator<Item = &str> {
            self.rules.iter().map(|(pattern, _)| pattern.as_str())
        }

        /// R311y720 (PF4) — DECLARE a name for one field path under one
        /// keyexpr pattern.
        ///
        /// # Why the names come from the caller and never from the decoder
        ///
        /// A schemaless walk recovers `1`, `3.2` and their spans, and that is
        /// the whole of what the bytes carry: protobuf's wire format has no
        /// names in it. The register carried this as PF4 -- "field 3 is 3, not
        /// `temperature`" -- and every way of closing it that ENDS in the
        /// analyzer is a way of inventing names, which on a plane whose whole
        /// output is findings is the worst kind of wrong.
        ///
        /// So the name arrives the way `--quic-port` arrives: DECLARED. The
        /// deployment that owns the schema says `demo/**:1=temperature`, this
        /// map carries it, and a reader sees `1 temperature` where a
        /// declaration covers the path and a bare `1` where none does. Nothing
        /// is guessed and nothing is silently renamed.
        ///
        /// Keyed by (pattern, path) rather than by path alone, because a field
        /// number means different things under different topics -- one
        /// deployment's `1` is a temperature and another's is a sequence
        /// number, and a global table would rename both.
        pub fn name_field(
            &mut self,
            pattern: &str,
            path: &str,
            name: &str,
        ) -> Result<(), FormatMapError> {
            if pattern.is_empty() || pattern.starts_with('/') || pattern.ends_with('/') {
                return Err(FormatMapError::NotAKeyexpr(pattern.to_owned()));
            }
            if pattern.contains('*') && !cfg!(feature = "filter-wildcards") {
                return Err(FormatMapError::WildcardUnsupported(pattern.to_owned()));
            }
            if path.is_empty() || name.is_empty() {
                return Err(FormatMapError::EmptyFieldName(pattern.to_owned()));
            }
            self.names
                .push((pattern.to_owned(), path.to_owned(), name.to_owned()));
            Ok(())
        }

        /// The declared name for `path` under `keyexpr`, if one was given.
        ///
        /// First match wins, on the same rule [`Self::for_keyexpr`] states: a
        /// later, more specific declaration cannot quietly override an earlier
        /// one, so the order a reader typed is the order that applies.
        /// R311y726 — the handle rides along, for the reason
        /// [`Self::for_keyexpr`] states.
        pub fn field_name(&self, keyexpr: &str, path: &str) -> Option<(DeclarationId, &str)> {
            let at = self.names.iter().position(|(pattern, p, _)| {
                p == path && {
                    let chunks: Vec<&str> = pattern.split('/').collect();
                    wz_session_core::keyexpr_match::keyexpr_pattern_matches(&chunks, keyexpr)
                }
            })?;
            Some((
                DeclarationId(self.rules.len() + at),
                self.names[at].2.as_str(),
            ))
        }

        /// Whether any field name was declared. A caller that renders the
        /// declaration inventory needs this separately from [`Self::is_empty`]:
        /// names can be declared for a format the built-ins already cover.
        pub fn has_names(&self) -> bool {
            !self.names.is_empty()
        }
    }

    // R311y856 — the SHIPPED decoders, re-exported from the file that holds
    // them so a caller reads one module. See `crate::payload_builtin` for why
    // they moved out of `wz-analyze`.
    pub use crate::payload_builtin::{builtin, Json, Protobuf, BUILTIN_NAMES};

    /// R311y856 — ONE SPELLING for a declaration, read here rather than by each
    /// surface that accepts one.
    ///
    /// # The failure this ends
    ///
    /// The two declarations a reader writes -- `demo/**=protobuf` and
    /// `demo/**:1=temperature` -- were parsed by `wz-analyze`'s argument reader
    /// and by nothing else. A SECOND consumption surface could therefore reach
    /// the format seam only by inventing a second dialect, and two dialects for
    /// one declaration disagree exactly where a deployment moves a rule out of
    /// a terminal and into a config file. [`FormatMap::declarations`] already
    /// RENDERS a name declaration as `{pattern}:{path}={name}`, so the
    /// canonical spelling existed and nothing could read it back.
    ///
    /// # How the two kinds are told apart
    ///
    /// A name declaration carries a `:` ahead of its `=`. That is the rule the
    /// command line committed to when it accepted
    /// `--payload-name demo/**:1=temperature`: a key expression is a `/`-joined
    /// run of chunks, and one carrying a `:` is not a key expression this
    /// workspace resolves. Stated because it is the whole of the
    /// discrimination, and a reader must not have to rediscover it from the
    /// parser.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DeclarationText<'a> {
        /// `<keyexpr>=<format>` -- which decoder reads a topic's payload.
        Rule {
            /// The key expression pattern the rule covers.
            pattern: &'a str,
            /// The format name, which still has to name a decoder this build
            /// carries.
            format: &'a str,
        },
        /// `<keyexpr>:<path>=<name>` -- what one path inside it is called.
        Name {
            /// The key expression pattern the declaration covers.
            pattern: &'a str,
            /// The field path, e.g. `1` or `3.2`.
            path: &'a str,
            /// The name to render for that path.
            name: &'a str,
        },
    }

    impl DeclarationText<'_> {
        /// Which kind this is, in the vocabulary [`Declaration`] reports.
        pub fn kind(&self) -> DeclarationKind {
            match self {
                Self::Rule { .. } => DeclarationKind::FormatRule,
                Self::Name { .. } => DeclarationKind::FieldName,
            }
        }
    }

    /// R311y884 — how a declaration is WRITTEN, once.
    ///
    /// [`parse_declaration`] is the reader and this is its mirror, so the
    /// spelling has one definition instead of one per writer. Open-debt item
    /// 235 is what it closes: the same declaration was spelled in three places
    /// -- the parser above, [`FormatMap::declarations`], and `wz-analyze`'s
    /// refusal note -- and nothing compared them, so `FormatMap::declarations`
    /// reported a `FormatRule` as the bare pattern. That is documented as "How
    /// the reader wrote it" and it is not: it carries no `=`, so the reader's
    /// own grammar rejects it.
    ///
    /// Not a `Display` impl, because the round trip is the contract and a
    /// `Display` invites a `{:?}`-shaped near-miss to be used instead. The
    /// contract is asserted rather than described:
    /// `parse_declaration(&declaration_text(d)) == d`.
    pub fn declaration_text(d: &DeclarationText<'_>) -> String {
        match *d {
            DeclarationText::Rule { pattern, format } => alloc::format!("{pattern}={format}"),
            DeclarationText::Name {
                pattern,
                path,
                name,
            } => alloc::format!("{pattern}:{path}={name}"),
        }
    }

    /// Read one declaration line.
    ///
    /// The line is taken WHOLE and never trimmed: a pattern with a trailing
    /// space matches nothing, and silently trimming it would hide that from the
    /// reader who typed it.
    pub fn parse_declaration(line: &str) -> Result<DeclarationText<'_>, FormatMapError> {
        let bad = || FormatMapError::NotADeclaration(line.to_owned());
        let (scope, value) = line.rsplit_once('=').ok_or_else(bad)?;
        match scope.rsplit_once(':') {
            Some((pattern, path)) => {
                if pattern.is_empty() || path.is_empty() || value.is_empty() {
                    return Err(bad());
                }
                Ok(DeclarationText::Name {
                    pattern,
                    path,
                    name: value,
                })
            }
            None => {
                if scope.is_empty() || value.is_empty() {
                    return Err(bad());
                }
                Ok(DeclarationText::Rule {
                    pattern: scope,
                    format: value,
                })
            }
        }
    }

    /// R311y856 — one declaration that could not be installed, and WHERE.
    ///
    /// The line index rides along because a caller that hands over a whole
    /// declaration TEXT has no other way to point at the offending line, and
    /// making it bisect its own configuration is the failure R311y854 named
    /// when it gave the selector a diagnostic of its own.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeclarationError {
        /// Which line, counting every line of the text from 0 -- blank ones
        /// included, so the number indexes what the caller sent.
        pub line: usize,
        /// The line itself, quoted back.
        pub text: String,
        /// Why it was refused.
        pub error: FormatMapError,
    }

    impl core::fmt::Display for DeclarationError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "line {}: {}", self.line, self.error)
        }
    }

    impl<'a> FormatMap<'a> {
        /// R311y856 — install ONE declaration written in the canonical
        /// spelling.
        ///
        /// The format name is resolved against this build's [`builtin`]
        /// registry, and an unknown one is REFUSED rather than skipped: a rule
        /// silently dropped leaves the reader believing their decoder is live
        /// while every payload still renders as bytes. That is the refusal
        /// `--payload-format` has made since R311y699, moved here so both
        /// surfaces make it.
        pub fn declare(&mut self, line: &str) -> Result<DeclarationKind, FormatMapError> {
            match parse_declaration(line)? {
                DeclarationText::Rule { pattern, format } => {
                    let decoder = builtin(format)
                        .ok_or_else(|| FormatMapError::NoSuchFormat(format.to_owned()))?;
                    self.insert(pattern, decoder)?;
                    Ok(DeclarationKind::FormatRule)
                }
                DeclarationText::Name {
                    pattern,
                    path,
                    name,
                } => {
                    self.name_field(pattern, path, name)?;
                    Ok(DeclarationKind::FieldName)
                }
            }
        }

        /// R311y856 — install a whole declaration TEXT, one per line, and
        /// answer how many were installed.
        ///
        /// Blank lines are skipped and nothing else is: a line this reader does
        /// not understand STOPS the install and names itself, because the
        /// alternative is a map quietly smaller than the text that built it --
        /// which is the same silence [`FormatMap::declare`] refuses one
        /// declaration at a time.
        pub fn declare_all(&mut self, text: &str) -> Result<usize, DeclarationError> {
            let mut installed = 0usize;
            for (at, line) in text.lines().enumerate() {
                if line.is_empty() {
                    continue;
                }
                self.declare(line).map_err(|error| DeclarationError {
                    line: at,
                    text: line.to_owned(),
                    error,
                })?;
                installed += 1;
            }
            Ok(installed)
        }
    }
}

#[cfg(test)]
mod format_map_tests {
    use super::formats::*;

    /// A format that claims every byte, so a test can tell WHICH rule fired
    /// without depending on any real decoder.
    struct Marker(&'static str);

    impl PayloadFormat for Marker {
        fn name(&self) -> &str {
            self.0
        }
        fn decode(
            &self,
            payload: &[u8],
        ) -> Result<alloc::vec::Vec<PayloadField>, PayloadFormatError> {
            Ok(alloc::vec![PayloadField {
                path: alloc::string::String::from(self.0),
                name: None,
                value: alloc::format!("{} byte(s)", payload.len()),
                start: 0,
                end: payload.len(),
            }])
        }
    }

    /// R311y699 ([REDACTED-REQ]) — the mapping is ZENOH'S keyexpr dialect, and the
    /// first matching rule wins.
    ///
    /// Both halves matter and a test of either alone would pass on a wrong
    /// build: a map that matched literally would answer `None` for `demo/a`
    /// under `demo/**`, and one that took the LAST match would hand a specific
    /// topic to the subtree's decoder.
    ///
    /// ⚠ Gated on the wildcard feature because in a build without it `insert`
    /// REFUSES `demo/**` — which is this module's own rule, measured: the first
    /// version of this test panicked in the `--no-default-features` lane, which
    /// is exactly the signal that the refusal is real rather than decorative.
    /// The insertion-order half runs in every build below.
    #[test]
    #[cfg(feature = "filter-wildcards")]
    fn a_rule_is_matched_by_zenohs_own_keyexpr_dialect_in_insertion_order() {
        let specific = Marker("specific");
        let subtree = Marker("subtree");
        let mut map = FormatMap::new();
        map.insert("demo/temperature", &specific)
            .expect("a literal");
        map.insert("demo/**", &subtree).expect("a wildcard");

        assert_eq!(
            map.for_keyexpr("demo/temperature").map(|(_, f)| f.name()),
            Some("specific"),
            "the specific rule is ahead of the subtree that also covers it"
        );
        assert_eq!(
            map.for_keyexpr("demo/pressure").map(|(_, f)| f.name()),
            Some("subtree"),
            "and `**` matches a sibling, which a literal comparison would not"
        );
        assert_eq!(
            map.for_keyexpr("other/thing").map(|(_, f)| f.name()),
            None,
            "a keyexpr no rule covers has no format"
        );
    }

    /// R311y884 — every declaration this map REPORTS must be one the reader can
    /// read back, and the two halves must be spelled by the same code.
    ///
    /// `Declaration::text` is documented as "How the reader wrote it", and for a
    /// `FieldName` it was: `{pattern}:{path}={name}`, the spelling
    /// `parse_declaration` accepts. For a `FormatRule` it was the bare pattern —
    /// no `=`, no format, and therefore not a declaration at all by the reader's
    /// own grammar. Three places spelled one thing (open-debt item 235): the
    /// parser, this render, and `wz-analyze`'s refusal note, and nothing
    /// compared them.
    ///
    /// A ROUND TRIP is the comparison, and it is stronger than any census of
    /// spellings: it asks the writer and the reader to agree on the same string
    /// without either being told what the string should look like.
    #[test]
    fn every_declaration_reported_can_be_read_back_by_the_parser() {
        let proto = Marker("protobuf");
        let mut map = FormatMap::new();
        map.insert("demo/temperature", &proto).expect("a literal");
        map.name_field("demo/temperature", "1", "celsius")
            .expect("a name");

        let declared = map.declarations();
        assert_eq!(declared.len(), 2, "one rule and one name: {declared:?}");
        for d in &declared {
            let back = parse_declaration(&d.text)
                .unwrap_or_else(|e| panic!("`{}` does not read back: {e:?}", d.text));
            assert_eq!(
                back.kind(),
                d.kind,
                "`{}` read back as a different kind",
                d.text
            );
        }
        // And the rule half spells what the reader typed, not half of it.
        let rule = declared
            .iter()
            .find(|d| d.kind == DeclarationKind::FormatRule)
            .expect("a rule");
        assert_eq!(rule.text, "demo/temperature=protobuf");
    }

    /// R311y699 ([REDACTED-REQ]) — the FIRST matching rule wins, in a build of any
    /// feature set.
    ///
    /// Literal patterns only, so this runs where the wildcard test cannot. The
    /// ordering rule is the half a reader depends on when they put a specific
    /// topic ahead of a broader one, and leaving it gated would have meant the
    /// `--no-default-features` lane checked nothing about it.
    #[test]
    fn the_first_matching_rule_wins_whatever_the_matcher_can_do() {
        let first = Marker("first");
        let second = Marker("second");
        let mut map = FormatMap::new();
        map.insert("demo/temperature", &first).expect("a literal");
        map.insert("demo/temperature", &second).expect("a literal");
        assert_eq!(
            map.for_keyexpr("demo/temperature").map(|(_, f)| f.name()),
            Some("first"),
            "two rules covering one keyexpr resolve to the earlier"
        );
        assert_eq!(map.patterns().count(), 2, "and both are still installed");
    }

    /// R311y699 ([REDACTED-REQ]) — a payload with no rule is left ALONE, which is what
    /// makes a schema-less decoder safe to offer at all.
    ///
    /// A decoder run over the wrong topic does not fail: protobuf's wire format
    /// will read almost any bytes as fields. So the map is the safety, and an
    /// empty map decoding nothing is the property that says so.
    #[test]
    fn an_empty_map_decodes_nothing_and_says_it_is_empty() {
        let map = FormatMap::new();
        assert!(map.is_empty());
        assert!(map.for_keyexpr("demo/a").is_none());
    }

    /// R311y699 ([REDACTED-REQ]) — a pattern this build's matcher cannot answer is
    /// REFUSED, not matched literally.
    ///
    /// The same rule and the same reason as the selector language: with the
    /// wildcard features off, `demo/**` degrades to a literal chunk and the
    /// reader's rule silently covers nothing while they believe it is live.
    #[test]
    #[cfg_attr(
        feature = "filter-wildcards",
        ignore = "this build's matcher HAS wildcards; the refusal is unreachable"
    )]
    fn a_wildcard_pattern_is_refused_where_the_matcher_has_none() {
        let marker = Marker("m");
        let mut map = FormatMap::new();
        assert!(matches!(
            map.insert("demo/**", &marker),
            Err(FormatMapError::WildcardUnsupported(_))
        ));
    }

    /// R311y699 — a pattern that is not a key expression is refused by name.
    #[test]
    fn a_pattern_that_is_not_a_keyexpr_is_refused() {
        let marker = Marker("m");
        let mut map = FormatMap::new();
        for bad in ["", "/demo", "demo/"] {
            assert!(
                matches!(
                    map.insert(bad, &marker),
                    Err(FormatMapError::NotAKeyexpr(_))
                ),
                "{bad:?} must be refused"
            );
        }
    }
}

#[cfg(all(test, feature = "network-codecs"))]
mod census_tests {
    use super::*;
    use crate::exchange::tests as fx;

    use super::tests_support::{err_declaring, push_declaring};

    fn census(records: &[(bool, Vec<u8>)]) -> PayloadCensus {
        let stamped: Vec<(bool, Option<u64>, Vec<u8>)> = records
            .iter()
            .map(|(d, r)| (*d, Some(1), r.clone()))
            .collect();
        payloads(&fx::dissect(&stamped))
    }

    const ID_JSON: u16 = 5;
    const ID_TEXT: u16 = 4;
    const ID_OCTETS: u16 = 3;

    /// ANTI-VACUITY: the fixture really does put a DECLARED encoding on the
    /// wire and the decoder really reads it back. Without this leg every
    /// assertion below would pass on a capture whose encodings all decoded as
    /// absent -- the shape R311y613 found in the network census.
    #[test]
    fn the_fixture_puts_a_declared_encoding_on_the_wire() {
        let c = census(&[(true, push_declaring("t/json", ID_JSON, b"{\"a\":1}"))]);
        assert_eq!(c.payloads(), 1, "the record decoded and carried a payload");
        let rows = c.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].declared, "application/json",
            "the declaration survived the wire round trip"
        );
        assert_eq!(rows[0].bytes, 7);
        assert!(c.gaps().is_clean(), "{:?}", c.gaps());
    }

    /// THE FINDING, end to end through real packets: a publisher whose bytes
    /// contradict its own encoding is named, with the keyexpr and the offset.
    #[test]
    fn a_publisher_contradicting_its_own_encoding_is_named_with_its_keyexpr() {
        let c = census(&[
            (true, push_declaring("app/good", ID_JSON, b"{\"ok\":true}")),
            (true, push_declaring("app/bad", ID_JSON, b"not json at all")),
            (true, push_declaring("app/text", ID_TEXT, b"plain words")),
        ]);
        assert_eq!(c.payloads(), 3);

        let bad = c.contradictions();
        assert_eq!(bad.len(), 1, "exactly one payload contradicted itself");
        assert_eq!(bad[0].keyexpr.as_deref(), Some("app/bad"));
        assert_eq!(bad[0].declared, "application/json");
        assert!(matches!(bad[0].reason, Mismatch::NotJson { at: 0, .. }));

        let json_row = c
            .rows()
            .into_iter()
            .find(|r| r.declared == "application/json")
            .expect("a json row");
        assert_eq!(json_row.payloads, 2);
        assert_eq!(json_row.consistent, 1);
        assert_eq!(json_row.not_as_declared, 1);
    }

    /// R311y622 (§1.1o) — a payload the capture does not HOLD is named, not
    /// judged. The failure this refuses is a FALSE FINDING against an innocent
    /// publisher.
    ///
    /// With SHM negotiated, zenoh puts a DESCRIPTOR in the payload slot and
    /// marks the body `zextunit!(0x2, true)`; the data stays in a segment on the
    /// sender's host and never traverses the network. Judged as data, that
    /// descriptor disagrees with whatever the record declared — so the one
    /// plane built to catch a lying publisher would have accused a correct one,
    /// on every SHM capture, confidently.
    ///
    /// `contradictions()` empty is therefore the load-bearing assertion, and
    /// `descriptors()` is the answer that replaces it. The row's `consistent`
    /// column is asserted at zero for the same reason from the other side:
    /// nothing was verified either.
    #[test]
    fn a_payload_the_capture_does_not_hold_is_named_rather_than_judged() {
        let c = census(&[(
            true,
            tests_support::push_with_shm_descriptor("shm/topic", ID_JSON, &[0x01, 0x00, 0x2A]),
        )]);

        assert_eq!(c.payloads(), 1, "the record was read");
        assert_eq!(c.descriptors(), 1, "and its data was not on the wire");
        assert!(
            c.contradictions().is_empty(),
            "a descriptor is not a publisher's mistake: {:?}",
            c.contradictions()
        );
        let row = c.rows()[0];
        assert_eq!(row.declared, "application/json");
        assert_eq!(row.descriptors, 1);
        assert_eq!(row.consistent, 0, "nothing was verified either");
        assert_eq!(row.not_as_declared, 0);
    }

    /// THE SECOND DISCRIMINATOR, and it gates the half a probe found ungated:
    /// an extension sharing the marker's 4-BIT ID FIELD but carrying a
    /// DIFFERENT ENCODING is a DIFFERENT extension, and the payload under it is
    /// still judged.
    ///
    /// The R311y505 defect pointed the other way. That round measured a real
    /// `zenohd --features shared-memory` whose `Shm` ZBuf was read as wz's UNIT
    /// offer because the match looked at the id column; here the same slip
    /// would make an observer call an ordinary payload a descriptor and stop
    /// judging it, which silences findings rather than fabricating them — the
    /// quieter failure, and the harder one to notice.
    ///
    /// Written because a falsify probe replacing `ext_eid` with `ext_id`
    /// left every test passing. The doc on `carries_shm_marker` claimed the
    /// match was on identity; nothing was checking that it was.
    #[test]
    fn an_extension_sharing_the_id_field_is_not_the_shm_marker() {
        let c = census(&[(
            true,
            tests_support::push_with_foreign_body_ext("shm/topic", ID_JSON, &[0x01, 0x00, 0x2A]),
        )]);

        assert_eq!(
            c.descriptors(),
            0,
            "a ZBuf at id 0x2 is not the mandatory UNIT marker"
        );
        assert_eq!(
            c.contradictions().len(),
            1,
            "so the payload under it is still judged, and it does contradict"
        );
    }

    /// THE DISCRIMINATOR, and the reason the page above is about the MARKER and
    /// not about SHM-looking bytes: the SAME payload with NO marker on it IS a
    /// contradiction.
    ///
    /// Without this leg a plane that had simply stopped judging short binary
    /// payloads would satisfy the assertions above. The two captures differ by
    /// one extension entry and nothing else.
    #[test]
    fn the_same_bytes_without_the_marker_are_still_a_contradiction() {
        let c = census(&[(
            true,
            push_declaring("shm/topic", ID_JSON, &[0x01, 0x00, 0x2A]),
        )]);

        assert_eq!(c.descriptors(), 0, "no marker, no descriptor");
        assert_eq!(
            c.contradictions().len(),
            1,
            "the same bytes, judged, do contradict `application/json`"
        );
    }

    /// R311y622 (§1.1s) — an ERROR body that contradicts its own declared
    /// encoding is a finding, with the keyexpr it answered for.
    ///
    /// Unreachable before this round. The plane read `Push`, `Request` and the
    /// `Reply` half of `Response`, and skipped `Err` on the strength of a note
    /// saying a row would land "on a topic that published nothing" — which the
    /// rows cannot do, being keyed by the declared ENCODING NAME. So a
    /// responder could declare `application/json` on an error and send bytes
    /// that are not JSON, and the one plane built to catch that never looked.
    ///
    /// The keyexpr is asserted beside the reason because an error's keyexpr is
    /// what makes the finding actionable: it names WHICH query the responder
    /// answered badly.
    #[test]
    fn an_error_body_that_contradicts_its_declaration_is_a_finding() {
        let d = fx::dissect(&[(
            false,
            Some(1),
            err_declaring("q/answered/badly", ID_JSON, b"not json at all"),
        )]);
        let c = payloads(&d);

        assert_eq!(c.payloads(), 1, "the error body IS a payload to judge");
        let finding = match c.contradictions() {
            [one] => one,
            other => panic!("exactly one finding, got {other:?}"),
        };
        assert_eq!(finding.declared, "application/json");
        assert_eq!(finding.keyexpr.as_deref(), Some("q/answered/badly"));
    }

    /// THE CONTROL, and the reason the page above is about the CLAIM rather
    /// than about errors: an error body whose bytes match what it declared is
    /// not a finding. Without this, a plane that reported every error as a
    /// contradiction would satisfy the assertion above.
    #[test]
    fn an_error_body_that_keeps_its_declaration_is_not_a_finding() {
        let d = fx::dissect(&[(
            false,
            Some(1),
            err_declaring("q/answered/well", ID_JSON, b"{\"code\":404}"),
        )]);
        let c = payloads(&d);

        assert_eq!(c.payloads(), 1);
        assert!(
            c.contradictions().is_empty(),
            "the bytes ARE json: {:?}",
            c.contradictions()
        );
    }

    /// R311y622 (§1.1s) — `kind == err` was a question this plane could never
    /// answer yes to, and now it can.
    ///
    /// The filter vocabulary carried [`crate::filter::RecordKind::Err`] all
    /// along; the payload plane simply never produced a record of that kind, so
    /// the term was permanently false here. A selector language with a word
    /// that cannot match is worse than one without it — a reader who asks for
    /// error payloads and gets none learns the wrong thing.
    ///
    /// One capture with BOTH kinds on it, because a selector that admitted
    /// everything would satisfy a single-kind fixture just as well.
    #[test]
    fn the_err_term_selects_error_payloads_and_leaves_the_rest() {
        let records = &[
            (
                true,
                Some(1),
                push_declaring("app/data", ID_JSON, b"{\"ok\":true}"),
            ),
            (
                false,
                Some(2),
                err_declaring("app/data", ID_JSON, b"{\"code\":500}"),
            ),
        ];
        let d = fx::dissect(records);

        let errs = payloads_where(&d, &crate::filter::Filter::parse("kind == err").unwrap());
        assert_eq!(errs.payloads(), 1, "the error body, and only it");
        assert_eq!(errs.selection().rejected, 1, "the push was rejected");
        assert_eq!(errs.selection().undecided, 0);

        let rest = payloads_where(&d, &crate::filter::Filter::parse("kind == put").unwrap());
        assert_eq!(rest.payloads(), 1, "and the put is still reachable");
    }

    /// R311y621 (§1.4i) — a body this build cannot decompress is counted, and
    /// is NOT a contradiction.
    ///
    /// The two are the sharpest pair on this plane and the reason it carries
    /// both counters. A CONTRADICTION is a payload this census read perfectly
    /// and found to disagree with its own declaration — a finding about the
    /// SENDER. An undecompressible batch is a payload it never saw — a fact
    /// about the READER. Folding the second into the first would let a build
    /// missing a feature publish findings against a publisher that did nothing
    /// wrong.
    #[test]
    fn a_batch_this_build_cannot_decompress_is_a_gap_and_not_a_finding() {
        let c = payloads(&crate::datagram_tests::compressed_session_dissection());

        let gaps = c.gaps();
        assert_eq!(gaps.undecompressible_batches, 1);
        assert_eq!(gaps.halted_batches, 0);
        assert_eq!(gaps.unparsed_bytes, 0);
        assert_eq!(gaps.unresolvable_fragments, 0);
        assert!(!gaps.is_clean(), "the shortfall must be visible at all");
        assert_eq!(c.payloads(), 0, "no payload was readable");
        assert!(
            c.contradictions().is_empty(),
            "a payload this plane never read cannot disagree with anything: {:?}",
            c.contradictions()
        );
    }

    /// R311y621 (§1.4i) — the same plane, for a capture that began mid-session.
    ///
    /// `unknown_ids` is pinned at zero beside the counter and means what it
    /// says: an encoding id this build cannot NAME is a different shortfall
    /// from a payload it never received, and a capture that started mid-chain
    /// must not be reported as one carrying unfamiliar encodings.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_fragment_with_no_resolution_is_a_gap_and_not_an_unknown_encoding() {
        let c = payloads(&crate::datagram_tests::midsession_fragment_dissection());

        let gaps = c.gaps();
        assert_eq!(gaps.unresolvable_fragments, 1);
        assert_eq!(gaps.undecompressible_batches, 0);
        assert_eq!(gaps.halted_batches, 0);
        assert_eq!(gaps.unparsed_bytes, 0);
        assert!(!gaps.is_clean(), "the shortfall must be visible at all");
        assert_eq!(c.payloads(), 0);
        assert_eq!(
            c.unknown_ids(),
            0,
            "an unnameable encoding is not the same shortfall as an unread one"
        );
    }

    /// Bytes declared as bytes are never a finding, however unreadable they
    /// are -- the plane reports contradictions, not opinions about content.
    #[test]
    fn binary_payloads_are_never_a_contradiction() {
        let c = census(&[(
            true,
            push_declaring("bin/blob", ID_OCTETS, &[0xFF, 0x00, 0xFE, 0x01]),
        )]);
        assert_eq!(c.payloads(), 1);
        assert!(c.contradictions().is_empty());
        assert_eq!(c.rows()[0].declared, "application/octet-stream");
        assert_eq!(c.rows()[0].consistent, 1);
    }

    /// A record with NO encoding field is the wire default, and it is labelled
    /// as undeclared rather than silently merged with publishers that really
    /// did declare `zenoh/bytes`.
    #[test]
    fn an_absent_encoding_is_labelled_undeclared_rather_than_merged() {
        let c = census(&[(
            true,
            fx::request_query(1, fx::sender_space(0, Some("q/nothing"))),
        )]);
        // A Query carries no payload at all, so nothing is judged.
        assert_eq!(c.payloads(), 0, "a query is not a payload");

        let c = census(&[(true, push_no_encoding("bare/topic", b"raw"))]);
        assert_eq!(c.payloads(), 1);
        assert_eq!(c.rows()[0].declared, "zenoh/bytes (undeclared)");
        assert!(c.contradictions().is_empty());
    }

    fn push_no_encoding(keyexpr: &'static str, payload: &[u8]) -> Vec<u8> {
        wz_codecs::push::Push {
            header: wz_codecs::push::Push::default().header | wz_codecs::wire_const::FLAG_N_N,
            keyexpr: fx::sender_space(0, Some(keyexpr)),
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// R311y618 (§1.4j) — an id NOT in this build's table, arriving off the
    /// WIRE rather than through `Encoding::from_packed`.
    ///
    /// The unit tests above already build an unknown id by hand, which proves
    /// the constructor and nothing about the census: until this test there was
    /// no capture in the suite that DROVE `unknown_ids`, so the counter was a
    /// claim -> [[feedback_negative_arm_makes_the_positive_a_claim]]. The id is
    /// picked from ABOVE the table's 53 entries rather than from a gap inside
    /// it, on the R311y605 rule that a fixture reaching for a small spare id
    /// tends to collide with a real one later.
    #[test]
    fn an_encoding_id_the_wire_carries_and_this_build_cannot_name_is_counted() {
        const ID_ABOVE_THE_TABLE: u16 = 200;
        assert!(
            ENCODING_ID_TO_STR.len() < ID_ABOVE_THE_TABLE as usize,
            "the fixture's id must be outside the table for this test to mean anything"
        );
        let c = census(&[
            (
                true,
                push_declaring("odd/topic", ID_ABOVE_THE_TABLE, b"\x01\x02"),
            ),
            (true, push_declaring("known/topic", ID_JSON, b"{}")),
        ]);
        assert_eq!(c.payloads(), 2);
        assert_eq!(c.unknown_ids(), 1);
        let unknown = c
            .rows()
            .into_iter()
            .find(|r| r.declared.starts_with("id 200"))
            .expect("the unknown id gets its own row rather than joining another");
        assert_eq!(unknown.payloads, 1);
        assert_eq!(unknown.bytes, 2);
        assert_eq!(
            unknown.not_as_declared, 0,
            "a claim this build cannot read is not a claim it can refute"
        );
        assert!(
            c.rows()
                .iter()
                .any(|r| r.declared == "application/json" && r.consistent == 1),
            "the control: a known id in the same capture is still named"
        );
    }

    // R311y618 (§1.1q) — the selector reaches the payload plane too.

    fn census_where(records: &[(bool, Vec<u8>)], selector: &str) -> (PayloadCensus, PayloadCensus) {
        let stamped: Vec<(bool, Option<u64>, Vec<u8>)> = records
            .iter()
            .map(|(d, r)| (*d, Some(1), r.clone()))
            .collect();
        let d = fx::dissect(&stamped);
        let filter = crate::filter::Filter::parse(selector).expect("the selector must compile");
        (payloads_where(&d, &filter), payloads(&d))
    }

    /// The same, with the instant each record was CAPTURED at.
    ///
    /// [`census_where`] stamps everything `Some(1)`, which is enough for a
    /// plane that never asks the time and useless for one that does. The
    /// observer's clock is sticky (`passive.rs:984`), so a capture that must
    /// reach the filter with no time at all is unstamped THROUGHOUT.
    fn census_where_at(
        records: &[(bool, Option<u64>, Vec<u8>)],
        selector: &str,
    ) -> (PayloadCensus, PayloadCensus) {
        let d = fx::dissect(records);
        let filter = crate::filter::Filter::parse(selector).expect("the selector must compile");
        (payloads_where(&d, &filter), payloads(&d))
    }

    /// A capture with one good payload, one that contradicts itself, and one on
    /// a different topic.
    fn three_payloads() -> Vec<(bool, Vec<u8>)> {
        alloc::vec![
            (true, push_declaring("app/good", ID_JSON, b"{\"ok\":1}")),
            (true, push_declaring("app/bad", ID_JSON, b"not json")),
            (true, push_declaring("other/x", ID_TEXT, b"words")),
        ]
    }

    /// ANTI-VACUITY: the identity filter IS the unfiltered census.
    #[test]
    fn the_identity_filter_is_the_unfiltered_census() {
        let (filtered, plain) = census_where(&three_payloads(), "");
        assert_eq!(filtered.payloads(), plain.payloads());
        assert_eq!(
            filtered.contradictions().len(),
            plain.contradictions().len()
        );
        assert_eq!(filtered.rows().len(), plain.rows().len());
        assert_eq!(filtered.selection().matched, 3);
        assert!(filtered.selection().is_decisive());
    }

    /// The consequence worth naming: a selector narrows what this plane can
    /// report a FINDING about. The contradiction is real and unfiltered it is
    /// reported; under a selector that excludes its topic the census is silent
    /// about it, and `selection` is the only thing that says so.
    #[test]
    fn a_selector_narrows_what_a_finding_can_be_about() {
        let (t, plain) = census_where(&three_payloads(), "key == other/x");
        assert_eq!(
            plain.contradictions().len(),
            1,
            "the control: the capture really does contain one contradiction"
        );
        assert_eq!(t.payloads(), 1);
        assert_eq!(t.rows().len(), 1);
        assert_eq!(t.rows()[0].declared, "text/plain");
        assert!(
            t.contradictions().is_empty(),
            "the finding is outside the selection and is not reported"
        );
        assert_eq!(
            t.selection(),
            crate::filter::Selection {
                matched: 1,
                rejected: 2,
                undecided: 0
            }
        );
    }

    /// The `kind` a payload answers to comes from the THROUGHPUT plane's
    /// classifier, so a payload carried by a `Response` is a `reply` here
    /// exactly as it is there — one classification, asked from two planes.
    #[test]
    fn a_payload_carried_by_a_response_answers_kind_reply() {
        let capture = alloc::vec![
            (true, push_declaring("t/push", ID_TEXT, b"pushed")),
            (
                false,
                fx::response_reply(1, fx::sender_space(0, Some("t/reply")), b"replied"),
            ),
        ];
        let (replies, plain) = census_where(&capture, "kind == reply");
        assert_eq!(plain.payloads(), 2, "the control: both carry a payload");
        assert_eq!(replies.payloads(), 1);
        assert_eq!(replies.rows()[0].bytes, 7);
        let (puts, _) = census_where(&capture, "kind == put");
        assert_eq!(puts.payloads(), 1);
        assert_eq!(puts.rows()[0].bytes, 6);
    }

    /// A payload whose keyexpr the capture never bound leaves a `key` term
    /// UNDECIDED, so the census under that selector is a floor and says so.
    #[test]
    fn an_unresolvable_payload_keyexpr_is_undecided() {
        let unnamed = wz_codecs::push::Push {
            keyexpr: fx::sender_space(77, None),
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                header: wz_codecs::msg_put::MsgPut::default().header
                    | wz_codecs::wire_const::FLAG_Z_PUT_E,
                encoding: Some(wz_codecs::encoding::Encoding {
                    packed_id: (ID_TEXT as u32) << 1,
                    schema_len: None,
                    schema: None,
                }),
                payload_len: 2,
                payload: b"hi",
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec();
        let (t, plain) = census_where(&alloc::vec![(true, unnamed)], "key == app/topic");
        assert_eq!(plain.payloads(), 1, "the control: the record decoded");
        assert_eq!(t.payloads(), 0);
        assert_eq!(t.selection().undecided, 1);
        assert!(!t.selection().is_decisive());
    }

    // R311y620 (§1.4k) — the three fields R311y618 left undriven on this
    // plane. One field per page, for the reason the other two planes now spell
    // out: a page carrying several terms is satisfied by any one of them.

    /// A `dir` term, against one topic and one encoding flowing both ways.
    ///
    /// Same key, same encoding, same size on each side is deliberate — the
    /// only thing left that can separate them is the direction.
    #[test]
    fn the_payload_view_answers_a_direction_term_off_the_wire() {
        let records = alloc::vec![
            (true, push_declaring("both/ways", ID_TEXT, b"aaaa")),
            (false, push_declaring("both/ways", ID_TEXT, b"bbbb")),
        ];

        let (from_b, plain) = census_where(&records, "dir == b");
        assert_eq!(plain.payloads(), 2, "the control: both were seen");
        assert_eq!(from_b.payloads(), 1);
        assert_eq!(from_b.selection().rejected, 1);

        let (from_a, _) = census_where(&records, "dir == a");
        assert_eq!(from_a.payloads(), 1);
        assert_eq!(from_a.selection().rejected, 1);
    }

    /// A `bytes` term, against payloads of different sizes under one encoding.
    ///
    /// The surviving row's `bytes` names which record survived, so a term that
    /// admitted the wrong one cannot read as a pass on the count alone.
    #[test]
    fn the_payload_view_answers_a_bytes_term_off_the_wire() {
        let records = alloc::vec![
            (true, push_declaring("sized/topic", ID_TEXT, b"ab")),
            (true, push_declaring("sized/topic", ID_TEXT, b"abcdefghij")),
        ];

        let (heavy, plain) = census_where(&records, "bytes > 5");
        assert_eq!(plain.payloads(), 2, "the control: both were seen");
        assert_eq!(heavy.payloads(), 1);
        assert_eq!(heavy.rows()[0].bytes, 10, "the ten-byte one, not the two");
        assert_eq!(heavy.selection().rejected, 1);

        let (light, _) = census_where(&records, "bytes <= 5");
        assert_eq!(light.rows()[0].bytes, 2);
    }

    /// A `time` term, against payloads carrying capture instants.
    #[test]
    fn the_payload_view_answers_a_time_term_off_the_wire() {
        let records = alloc::vec![
            (
                true,
                Some(1_000),
                push_declaring("clocked/topic", ID_TEXT, b"early")
            ),
            (
                true,
                Some(3_000),
                push_declaring("clocked/topic", ID_TEXT, b"late!!!!")
            ),
        ];

        let (late, plain) = census_where_at(&records, "time >= 2000");
        assert_eq!(plain.payloads(), 2, "the control: both were seen");
        assert_eq!(late.payloads(), 1);
        assert_eq!(late.rows()[0].bytes, 8, "the one stamped 3000");
        assert_eq!(late.selection().rejected, 1);
        assert_eq!(late.selection().undecided, 0);

        let (early, _) = census_where_at(&records, "time < 2000");
        assert_eq!(early.rows()[0].bytes, 5);
    }

    /// A capture with no clock leaves a `time` term undecided here too.
    ///
    /// The arm that keeps the one above from being free: a plane substituting a
    /// plausible instant would answer `time > 0` with a confident No for every
    /// payload, and a reader would take "nothing was published" off a capture
    /// that merely never said when.
    #[test]
    fn an_unclocked_payload_leaves_a_time_term_undecided() {
        let records = alloc::vec![
            (true, None, push_declaring("dark/topic", ID_TEXT, b"one")),
            (true, None, push_declaring("dark/topic", ID_TEXT, b"two")),
        ];

        let (asked, plain) = census_where_at(&records, "time > 0");
        assert_eq!(plain.payloads(), 2, "the control: the records decoded");
        assert_eq!(
            asked.selection(),
            crate::filter::Selection {
                matched: 0,
                rejected: 0,
                undecided: 2
            },
            "a question the capture cannot answer is not a No"
        );
        assert_eq!(asked.payloads(), 0);
        assert!(asked.rows().is_empty(), "and no row was invented");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(name: &'static str) -> Encoding<'static> {
        let id = ENCODING_ID_TO_STR
            .iter()
            .position(|e| *e == name)
            .expect("the table must carry this name") as u16;
        Encoding::Known {
            id,
            name,
            schema: None,
        }
    }

    /// The table this module reads is the WIRE table, reached without a second
    /// transcription. Anchored on the two entries whose ids the protocol pins
    /// rather than on the length alone, so a reordering fails here.
    #[test]
    fn the_encoding_table_is_the_wire_table_and_the_index_is_the_id() {
        assert_eq!(ENCODING_ID_TO_STR[0], "zenoh/bytes");
        assert_eq!(ENCODING_ID_TO_STR[4], "text/plain");
        assert_eq!(ENCODING_ID_TO_STR[5], "application/json");
        // The packed word is `(id << 1) | has_schema`, so the id must survive
        // the shift rather than being read raw.
        assert_eq!(
            Encoding::from_packed(5 << 1, None).name(),
            Some("application/json")
        );
        assert_eq!(
            Encoding::from_packed((5 << 1) | 1, Some("v2")),
            Encoding::Known {
                id: 5,
                name: "application/json",
                schema: Some("v2")
            }
        );
    }

    /// An id past the table is UNKNOWN and stays unknown — never quietly the
    /// default. A publisher using an id this build does not know is a fact
    /// about the capture.
    #[test]
    fn an_id_outside_the_table_is_reported_rather_than_defaulted() {
        let e = Encoding::from_packed(9999 << 1, None);
        assert_eq!(e, Encoding::Unknown { id: 9999 });
        assert_eq!(e.name(), None);
        assert_eq!(e.shape(), Shape::Unclaimed);
        // And it renders opaque rather than being guessed at.
        assert_eq!(inspect(e, b"{}"), Verdict::Opaque { bytes: 2 });
    }

    /// THE RULE: a payload that contradicts its own declaration is a NAMED
    /// finding with an offset — not a fallback rendering, and not silence.
    #[test]
    fn a_payload_that_contradicts_its_declaration_is_a_finding_with_an_offset() {
        // Declared JSON, is not JSON.
        let v = inspect(known("application/json"), b"{\"a\": }");
        match v {
            Verdict::NotAsDeclared {
                declared,
                reason: Mismatch::NotJson { at, .. },
            } => {
                assert_eq!(declared, "application/json");
                assert_eq!(at, 6, "the offset points at the offending byte");
            }
            other => panic!("expected a finding, got {other:?}"),
        }
        assert!(!v.is_consistent());

        // Declared text, is not UTF-8.
        let v = inspect(known("text/plain"), &[b'o', b'k', 0xFF, 0xFE]);
        assert_eq!(
            v,
            Verdict::NotAsDeclared {
                declared: "text/plain",
                reason: Mismatch::NotUtf8 { at: 2 }
            }
        );

        // And the same bytes under a BINARY declaration are not a finding:
        // nothing was claimed, so nothing is contradicted.
        let v = inspect(known("application/octet-stream"), &[0xFF, 0xFE]);
        assert_eq!(v, Verdict::Opaque { bytes: 2 });
        assert!(v.is_consistent());
    }

    /// A rendering is EARNED: text comes back only when the bytes really are
    /// UTF-8, JSON only when it really parses.
    #[test]
    fn a_rendering_is_only_produced_after_the_claim_is_checked() {
        assert_eq!(
            inspect(known("text/plain"), b"hello"),
            Verdict::Text("hello")
        );
        assert_eq!(
            inspect(known("zenoh/string"), "온도".as_bytes()),
            Verdict::Text("온도")
        );
        assert_eq!(
            inspect(known("application/json"), b"{\"a\":[1,2,{\"b\":null}]}"),
            Verdict::Json(JsonSummary {
                top_level: JsonKind::Object,
                depth: 3
            })
        );
        assert_eq!(inspect(known("text/plain"), b""), Verdict::Empty);
    }

    /// The JSON scanner, against the grammar rather than against itself. Each
    /// row names what RFC 8259 says, and the rejects carry an offset.
    #[test]
    fn the_json_scanner_follows_rfc_8259_rather_than_being_permissive() {
        for (ok, kind) in [
            (&b"null"[..], JsonKind::Null),
            (b"true", JsonKind::Bool),
            (b"-0.5e+10", JsonKind::Number),
            (b"0", JsonKind::Number),
            (b"\"a\\u00e9b\"", JsonKind::String),
            (b"[]", JsonKind::Array),
            (b"{}", JsonKind::Object),
            (b"  { \"k\" : [ 1 , 2 ] } ", JsonKind::Object),
        ] {
            let got = scan_json(ok).unwrap_or_else(|e| panic!("{:?} rejected: {e:?}", ok));
            assert_eq!(got.top_level, kind, "{ok:?}");
        }

        for (bad, why) in [
            (&b"01"[..], "a leading zero admits no more digits"),
            (b"{\"a\":1,}", "no trailing comma"),
            (b"[1 2]", "a separator is required"),
            (b"\"unterminated", "a string must close"),
            (b"{'a':1}", "single quotes are not JSON"),
            (b"1.", "a fraction needs a digit"),
            (b"1e", "an exponent needs a digit"),
            (b"nul", "a literal must be complete"),
            (b"", "an empty document is not a value"),
            (b"{\"a\":\"b\nc\"}", "a raw control character in a string"),
        ] {
            let e = scan_json(bad);
            assert!(e.is_err(), "{why}: {bad:?} was accepted");
            let (at, _) = e.unwrap_err();
            assert!(at <= bad.len(), "{why}: offset out of range");
        }
    }

    /// Nesting deeper than the scanner accepts is REPORTED, not accepted and
    /// not a stack overflow. The guard exists because this crate also builds
    /// for the MCU profile.
    #[test]
    fn a_document_deeper_than_the_scanner_accepts_is_refused_by_name() {
        let over = MAX_JSON_DEPTH + 5;
        let mut deep = alloc::vec![b'['; over];
        deep.push(b'1');
        deep.extend(core::iter::repeat_n(b']', over));
        let (_, reason) = scan_json(&deep).expect_err("must refuse");
        assert!(reason.contains("nesting"), "{reason}");

        // And a document AT the limit still parses, so the guard is a ceiling
        // rather than a blanket refusal.
        let mut ok = alloc::vec![b'['; MAX_JSON_DEPTH];
        ok.push(b'1');
        ok.extend(core::iter::repeat_n(b']', MAX_JSON_DEPTH));
        assert_eq!(scan_json(&ok).expect("at the limit").depth, MAX_JSON_DEPTH);
    }

    /// The shapes that must NOT be judged by a strict JSON scanner, because a
    /// false finding is worse than a missing one on a plane whose output IS
    /// findings.
    #[test]
    fn the_json_adjacent_encodings_are_not_judged_as_strict_json() {
        // `text/json5` is what the table spells it -- a name this test got
        // wrong first, which is why it reads the table rather than a literal.
        for name in ["text/json5", "application/json-seq", "application/jsonpath"] {
            assert_eq!(known(name).shape(), Shape::Utf8Text, "{name}");
            // json5 with a trailing comma is a legitimate json5 document; it
            // must come back as text, not as a contradiction.
            assert!(
                inspect(known(name), b"{a: 1,}").is_consistent(),
                "{name} produced a false finding"
            );
        }
        assert_eq!(known("application/json").shape(), Shape::Json);
        assert_eq!(known("text/json").shape(), Shape::Json);
    }
}

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
//! So every rendering here is earned. [`Verdict::Text`] means the bytes ARE
//! valid UTF-8; [`Verdict::Json`] means they parsed; and a payload that does
//! not match its own declaration is [`Verdict::NotAsDeclared`], carrying the
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
//! An id the table does not have is [`Encoding::Unknown`]. Not "probably
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
/// [`Verdict::NotAsDeclared`] against a publisher that did nothing wrong — a
/// false finding, which is worse here than a missing one because this plane
/// exists to produce findings.
fn shape_of(name: &str) -> Shape {
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
    pub fn is_consistent(&self) -> bool {
        !matches!(self, Verdict::NotAsDeclared { .. })
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
}

/// Guard against a document whose nesting would recurse this scanner off the
/// stack. 128 is deeper than any zenoh payload observed and shallow enough to
/// be safe on the MCU profile this crate also builds for; a document deeper
/// than that is REPORTED, not silently accepted.
const MAX_JSON_DEPTH: usize = 128;

type ScanErr = (usize, &'static str);

fn scan_json(bytes: &[u8]) -> Result<JsonSummary, ScanErr> {
    let mut s = Scanner {
        b: bytes,
        i: 0,
        depth: 0,
        max_depth: 0,
    };
    s.ws();
    let top = s.value()?;
    s.ws();
    if s.i != s.b.len() {
        return Err((s.i, "trailing input after the top-level value"));
    }
    Ok(JsonSummary {
        top_level: top,
        depth: s.max_depth,
    })
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

    fn value(&mut self) -> Result<JsonKind, ScanErr> {
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
            return Ok(JsonKind::Object);
        }
        loop {
            self.ws();
            self.string()?;
            self.ws();
            self.expect(b':', "expected ':' after an object key")?;
            self.ws();
            self.value()?;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    self.depth -= 1;
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
            return Ok(JsonKind::Array);
        }
        loop {
            self.ws();
            self.value()?;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    self.depth -= 1;
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
    gaps: crate::agg::ThroughputGaps,
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

    /// Traffic this plane could not read at all — the same shape
    /// [`crate::agg::ThroughputTable::gaps`] carries, for the same reason.
    pub fn gaps(&self) -> crate::agg::ThroughputGaps {
        self.gaps
    }

    /// Fold one flow's frames in.
    pub fn observe_flow(&mut self, frames: &[wz_session_core::passive::PassiveFrame]) {
        use wz_session_core::passive::Carried;

        let mut spaces = crate::agg::KeyexprSpaces::new();
        for frame in frames {
            match &frame.carried {
                Carried::Batch(batch) => self.observe_batch(&mut spaces, frame, batch),
                #[cfg(feature = "reassembly")]
                Carried::Reassembled(batch) => self.observe_batch(&mut spaces, frame, batch),
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
    ) {
        if batch.halt.is_some() {
            self.gaps.halted_batches += 1;
            self.gaps.unparsed_bytes += batch.unparsed_bytes;
        }
        for message in &batch.messages {
            self.observe_message(spaces, frame, message);
        }
    }

    fn observe_message(
        &mut self,
        spaces: &mut crate::agg::KeyexprSpaces,
        frame: &wz_session_core::passive::PassiveFrame,
        message: &wz_session_core::network_message::NetworkMessage,
    ) {
        use wz_session_core::network_message::NetworkMessage;

        let direction = frame.direction;
        if let NetworkMessage::Declare(d) = message {
            spaces.absorb(direction, d);
            return;
        }
        let Some((keyexpr_body, put)) = carried_put(message) else {
            return;
        };
        let keyexpr = spaces.resolve(direction, keyexpr_body).ok();
        let encoding = match &put.encoding {
            Some(e) => Encoding::from_packed(e.packed_id, e.schema.as_deref()),
            None => Encoding::Absent,
        };
        let bytes = put.payload.as_slice();
        let verdict = inspect(encoding, bytes);
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
        if let Verdict::NotAsDeclared { reason, .. } = verdict {
            row.not_as_declared += 1;
            self.contradictions.push(Contradiction {
                keyexpr,
                declared,
                reason,
            });
        } else {
            row.consistent += 1;
        }
    }
}

/// The `MsgPut` a record carries, if it carries one, with its keyexpr.
///
/// `Err` bodies are deliberately NOT folded in here: an error payload is an
/// error string chosen by the responder, not application data under a declared
/// encoding, and counting it would put a row on a topic that published nothing.
#[cfg(feature = "network-codecs")]
#[allow(clippy::type_complexity)]
fn carried_put(
    message: &wz_session_core::network_message::NetworkMessage,
) -> Option<(
    &wz_codecs::wireexpr::WireexprOwnedVariant,
    &wz_codecs::msg_put::MsgPutOwned,
)> {
    use wz_codecs::push::PushOwnedVariant;
    use wz_codecs::reply::ReplyOwnedVariant;
    use wz_codecs::request::RequestOwnedVariant;
    use wz_codecs::response::ResponseOwnedVariant;
    use wz_session_core::network_message::NetworkMessage;

    match message {
        NetworkMessage::Push(p) => match &p.body {
            PushOwnedVariant::CodecZenohMsgPut(put)
            | PushOwnedVariant::Default { body: put, .. } => Some((&p.keyexpr.body, put)),
            PushOwnedVariant::CodecZenohMsgDel(_) => None,
        },
        NetworkMessage::Request(r) => match &r.body {
            RequestOwnedVariant::CodecZenohMsgPut(put) => Some((&r.keyexpr.body, put)),
            _ => None,
        },
        NetworkMessage::Response(r) => match &r.body {
            ResponseOwnedVariant::CodecZenohReply(reply)
            | ResponseOwnedVariant::Default { body: reply, .. } => match &reply.body {
                ReplyOwnedVariant::CodecZenohMsgPut(put)
                | ReplyOwnedVariant::Default { body: put, .. } => Some((&r.keyexpr.body, put)),
                // A reply carrying a Del has no payload to judge.
                ReplyOwnedVariant::CodecZenohMsgDel(_) => None,
            },
            ResponseOwnedVariant::CodecZenohErr(_) => None,
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
    let mut census = PayloadCensus::new();
    for flow in dissection.flows() {
        census.observe_flow(&flow.frames);
    }
    for flow in dissection.datagram_flows() {
        census.observe_flow(&flow.frames);
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

    /// A dissection carrying one A-to-B `Push` per entry.
    pub(crate) fn dissect_pushes(records: &[(&'static str, u16, Vec<u8>)]) -> crate::Dissection {
        let stamped: Vec<(bool, Option<u64>, Vec<u8>)> = records
            .iter()
            .map(|(k, id, p)| (true, Some(1), push_declaring(k, *id, p)))
            .collect();
        fx::dissect(&stamped)
    }
}

#[cfg(all(test, feature = "network-codecs"))]
mod census_tests {
    use super::*;
    use crate::exchange::tests as fx;

    use super::tests_support::push_declaring;

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

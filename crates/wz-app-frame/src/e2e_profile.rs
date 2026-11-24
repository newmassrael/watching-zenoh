// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A PROFILE: the description of an end-to-end protection header that the
//! CALLER hands over, so that this library owns the mechanism and the caller
//! owns the constants.
//!
//! # What kind of header this is
//!
//! A protected frame is a fixed run of header fields followed by a body (a
//! serialized message). The header carries a length, an identifier, a CRC, a
//! message cell and a counter, in an order and at widths that differ from one
//! profile to the next; the CRC is taken over some of those fields and the
//! body in an order that is FIXED by the profile and is generally not the wire
//! order. A receiver judges each frame: CRC, then counter, then timeout
//! ([`crate::e2e_judge`]). [`crate::e2e_frame`] builds and opens such frames.
//!
//! # Why nothing is hard-coded
//!
//! This repository is public and the masks, bit meanings and header shapes of
//! a deployed protocol are that deployment's. So a profile is DATA, passed on
//! every call, and the workspace's tests run on synthetic profiles whose
//! widths, orders, masks and names are deliberately unlike any real one. The
//! only fixed constants are the published CRC definitions in
//! [`crate::e2e_crc`]'s tests.
//!
//! # The description
//!
//! ```text
//! {
//!   "name": "demo-a",
//!   "fields": [                     // wire order, no gaps; each a big-endian unsigned integer
//!     {"name": "crc",     "bytes": 4},
//!     {"name": "length",  "bytes": 2},
//!     {"name": "counter", "bytes": 2},
//!     {"name": "ident",   "bytes": 4, "xor": "0x0F0F0F0F",
//!        "split": [{"name": "domain",  "lsb": 24, "width": 8},
//!                  {"name": "version", "lsb": 16, "width": 8},
//!                  {"name": "msg",     "lsb": 0,  "width": 16}]}
//!   ],
//!   "crc": {"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF",
//!           "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
//!           "cover": ["length", "ident", "@payload", "counter"]},
//!   "length": {"field": "length", "counts": "frame"},
//!   "counter": {"field": "counter", "max_gap": 10, "timeout_ms": 1000},
//!   "slot": {"message": ["ident"], "by_zid": true}
//! }
//! ```
//!
//! * `fields[].bytes` is 1 to 8. `xor` (optional) is XORed into the field on
//!   the wire; `split` (optional) names bit ranges of the field's logical
//!   value, `lsb` counting from the least significant bit. On BUILD the parts
//!   are OR-ed at their `lsb`, then XORed with `xor`, then written; on OPEN the
//!   field is read, XORed, then split. The order matters and is the whole
//!   point of keeping the two apart. A bit no part owns is written as the
//!   `xor`'s bit and read by nothing: no part holds it, and a receiver judges
//!   a split identifier in the bits its parts own ([`Field::owned_bits`]).
//! * `crc.cover` is the FEEDING ORDER: field names, and `"@payload"` for the
//!   body. The CRC field itself is never covered, and there is no zero-fill
//!   step. Each covered field is fed as it stands ON THE WIRE (after `xor`), big
//!   endian, at its own width.
//! * `length.counts` is `"frame"` (the value is header plus body) or
//!   `"frame_minus"` with `"fields": [...]` (header plus body less the widths
//!   of the listed fields). Which of them a sender used is not on the wire, so
//!   opening reports the length as INFORMATION beside the CRC verdict.
//! * `counter` names the field the judge reads, the largest forward step it
//!   accepts and the silence it tolerates. A `timeout_ms` of 0 states no limit
//!   on the silence: a receiver never reports a timeout on a stream of the
//!   profile, which is what a message sent on an event, with no period, needs.
//!   A periodic message's profile states its limit (see [`crate::e2e_judge`]).
//! * `slot` (optional) says which frames of a CAPTURE share one counter, for
//!   the pipeline that keeps a judge per slot (`e2e_slots`, in the capture
//!   crate); the stateless doors ignore it. A slot is the key expression the
//!   frame was published under, the sender, and the logical values of the
//!   `message` fields (none by default, so one key carries one message). `by_zid`
//!   (default true) keeps two senders' counters apart; a deployment whose
//!   receiver keeps one counter per message regardless of sender says `false`.
//!   A `message` field may not be the crc, length or counter field: each of
//!   those varies from frame to frame, and a slot that moved with the counter
//!   would judge nothing.
//!
//! # What a receiver judges by, and what a sender derives
//!
//! ```text
//!   "fields": [ ...
//!     {"name": "cell", "bytes": 4,
//!      "split": [{"name": "kind",   "lsb": 29, "width": 3},
//!                {"name": "result", "lsb": 26, "width": 3},
//!                {"name": "sender", "lsb": 0,  "width": 26,
//!                 "derive": {"from": "address", "mask": "0x3FFFF00", "xor": "0x15"}}]} ],
//!   "counter": {"field": "counter", "max_gap": 6, "timeout_ms": 1000, "max_gap_ceiling": 20},
//!   "judge": {"ident": "ident", "length": true, "counter_errors": "joined",
//!             "out_of_range": "keeps_baseline"},
//!   "cell": {"field": "cell", "kind": "kind", "result": "result", "sender": "sender"}
//! ```
//!
//! * `derive` (optional, on a plain field or on a part) takes the value from
//!   the node's address instead of from the caller: `(address & mask) ^ xor`,
//!   the mask and the xor fitting the field's or the part's own bits. The
//!   sender writes it and a receiver expecting the field computes it the same
//!   way. A split field has no `derive` of its own; a field the mechanism gives
//!   its value (crc, length, counter) has none at all. A value COMPOSED of
//!   several catalogue values and XORed with a constant needs no new word: it
//!   is a `split` with an `xor`.
//! * `counter.max_gap_ceiling` (optional) bounds the `max_gap` a receiver may
//!   be given in place of the profile's own, and the profile's own as well.
//! * `judge` (optional) states the rules a receiver applies beyond the CRC.
//!   `ident` names a field whose logical value must equal the receiver's
//!   expected one, and `length: true` makes the length field's agreement with
//!   the frame part of integrity too: a frame that fails either is an
//!   integrity error, as a CRC mismatch is, and moves no state.
//!   `counter_errors` is `apart` (a repetition and a step out of range are
//!   reported as themselves) or `joined` (both as one counter error).
//!   `out_of_range` is `moves_baseline` (a step above the gap moves the
//!   baseline to the frame) or `keeps_baseline`. Each default is the judge's
//!   behaviour with no `judge` object: CRC only, apart, moves. The first intact
//!   frame of a stream is always the baseline; it is not a rule.
//! * `cell` (optional) names the parts of one split field that carry the
//!   frame's kind, its result and its sender identity, at least one of them. A
//!   receiver reads the sender for demultiplexing and reports the other two.
//!
//! Integers are JSON numbers (plain decimal) or strings (decimal, or `0x` and
//! hex digits), so a 64-bit value survives a reader that holds numbers as
//! doubles. The text is read by the workspace's one JSON reader,
//! [`wz_session_core::json5`], which reads JSON5 and so admits what JSON5
//! admits (comments, trailing commas, single-quoted strings, unquoted keys);
//! the document is then checked strictly. Nesting deeper than
//! [`MAX_JSON_DEPTH`] levels is refused before the reader sees it, because that
//! reader recurses once per level and a document a person chose must not be
//! able to exhaust the stack of the program that linked this library. An
//! unknown key, a key that
//! appears twice, a width that does not fit, overlapping parts, a `cover` that
//! names no field, an unsupported CRC width, a CRC field narrower than the CRC
//! and every other malformed shape is REFUSED with a JSON pointer to the place
//! ([`DocError::Invalid`]) or, when the text is not JSON at all, the byte
//! offset ([`DocError::Syntax`]).
//!
//! # What a profile deliberately cannot say
//!
//! Computed fields (CRC, length) and judged fields (counter) carry no `xor` and
//! no `split`: the mechanism gives them a meaning, and a transformation on top
//! of that meaning would be a second, unchecked one. A rule that depends on a
//! value (for instance "a result is forced to zero when the kind is a query")
//! is the caller's: it decides the part values it passes.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};
use wz_session_core::json5_lex::{Json5Error, Lexer};

use crate::e2e_crc::{width_mask, Crc, CrcParams, CrcParamsError, SUPPORTED_WIDTHS};
use crate::e2e_judge::{CounterRules, Judge, JudgeConfig};

/// Most fields a profile may declare.
pub const MAX_FIELDS: usize = 32;
/// Most parts one field may be split into (a part is at least one bit).
pub const MAX_PARTS: usize = 64;
/// Longest profile, field and part name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;
/// The `cover` entry that stands for the body.
pub const PAYLOAD: &str = "@payload";
/// Deepest nesting a profile or a values text may have. The deepest legitimate
/// profile has five levels (the document, `fields`, a field, `split`, a part);
/// a values text has three.
pub const MAX_JSON_DEPTH: usize = 8;

/// Why a document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocError {
    /// The text is not JSON, and this is the byte where reading stopped.
    Syntax {
        /// Offset into the text.
        offset: usize,
        /// What the reader expected there.
        expected: &'static str,
    },
    /// The text is JSON and not what was asked for.
    Invalid {
        /// An RFC 6901 JSON pointer to the place: empty for the document
        /// itself, `/fields/2/split/0/lsb` for a value inside it.
        path: String,
        /// The reason, as a sentence.
        reason: String,
    },
}

impl DocError {
    pub fn invalid(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invalid {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

impl core::fmt::Display for DocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Syntax { offset, expected } => {
                write!(f, "not JSON at byte {offset}: expected {expected}")
            }
            Self::Invalid { path, reason } if path.is_empty() => f.write_str(reason),
            Self::Invalid { path, reason } => write!(f, "{path}: {reason}"),
        }
    }
}

/// The source a derived value is taken from. The node's address is the only one
/// today; the profile names it, so that a later source is a new word and not a
/// new reading of an old one.
pub const ADDRESS_SOURCE: &str = "address";

/// A value the profile derives from the node's address instead of taking it
/// from the caller: `(address & mask) ^ xor`. The sender writes it and the
/// receiver expects it; the address is runtime data and the rule is the
/// profile's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Derive {
    /// The bits of the address the value keeps.
    pub mask: u64,
    /// XORed into the kept bits.
    pub xor: u64,
}

impl Derive {
    /// The value for `address`. It fits the field or part the rule is on,
    /// because the mask and the xor were refused when they did not.
    pub fn apply(&self, address: u64) -> u64 {
        (address & self.mask) ^ self.xor
    }
}

/// One named bit range of a field's logical value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// The part's name, unique within its field.
    pub name: String,
    /// Bit position of the part's least significant bit.
    pub lsb: u8,
    /// How many bits the part spans.
    pub width: u8,
    /// The rule the part's value is derived by; `None` when the caller
    /// supplies it.
    pub derive: Option<Derive>,
}

impl Part {
    /// The largest value the part holds.
    pub fn max_value(&self) -> u64 {
        width_mask(self.width)
    }
}

/// One header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The field's name, unique within the profile.
    pub name: String,
    /// Width on the wire, 1 to 8 bytes.
    pub bytes: usize,
    /// Offset from the start of the frame.
    pub offset: usize,
    /// XORed into the logical value to give the wire value; 0 for none.
    pub xor: u64,
    /// The named bit ranges of the logical value; empty for a plain integer.
    pub parts: Vec<Part>,
    /// The rule a plain field's value is derived by; `None` when the caller
    /// supplies it. A split field derives part by part instead.
    pub derive: Option<Derive>,
}

impl Field {
    /// The largest value the field holds.
    pub fn max_value(&self) -> u64 {
        width_mask((self.bytes * 8) as u8)
    }

    /// The bits of the logical value that mean something: every bit of a plain
    /// field, and the bits the parts own of a split one. A sender writes the
    /// others as the `xor` gives them and another sender may write them
    /// otherwise, so nothing that judges the field reads them.
    pub fn owned_bits(&self) -> u64 {
        if self.parts.is_empty() {
            return self.max_value();
        }
        self.parts
            .iter()
            .fold(0, |owned, part| owned | (part.max_value() << part.lsb))
    }
}

/// What the CRC is taken over, in feeding order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cover {
    /// The wire bytes of the field at this index of [`Profile::fields`].
    Field(usize),
    /// The body.
    Payload,
}

/// The CRC of a profile.
#[derive(Debug, Clone)]
pub struct CrcSpec {
    /// Index of the field the CRC is written to.
    pub field: usize,
    /// The engine, built from the profile's parameters.
    pub engine: Crc,
    /// What is fed, in this order.
    pub cover: Vec<Cover>,
}

/// What the length field counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LengthCounts {
    /// Header plus body.
    Frame,
    /// Header plus body less the widths of these fields (indices).
    FrameMinus(Vec<usize>),
}

/// The length field of a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthSpec {
    /// Index of the field.
    pub field: usize,
    /// What it counts.
    pub counts: LengthCounts,
}

/// The counter field of a profile, with the rules a receiver applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterSpec {
    /// Index of the field.
    pub field: usize,
    /// The largest forward step that is not an error.
    pub max_gap: u64,
    /// The longest silence between valid receptions that is not an error; 0
    /// ([`JudgeConfig::NO_TIMEOUT`]) when no silence is.
    pub timeout_ms: u64,
    /// The largest `max_gap` a receiver may be given in place of the profile's
    /// own; `None` for the largest step the counter field can make.
    pub max_gap_ceiling: Option<u64>,
}

/// Whether a repetition and a step out of range are reported as two kinds of
/// counter error or as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterErrors {
    /// Each is reported as itself. The default.
    Apart,
    /// Both are reported as one counter error.
    Joined,
}

/// The rules a receiver judges a frame by, beyond the CRC and the counter step,
/// as the profile states them. [`Default`] is the judge's behaviour when a
/// profile states none of them.
///
/// The first intact frame of a stream is always accepted as the baseline, with
/// no counter judgement: there is nothing before it to step from, so it is not
/// a rule a profile can change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JudgeRules {
    /// The field whose logical value must equal the receiver's expected one for
    /// a frame to be intact; `None` when the identifier is not judged.
    pub ident: Option<usize>,
    /// Whether the length field must equal what the profile's length rule gives
    /// for the frame for it to be intact.
    pub length: bool,
    /// How the two counter errors are reported.
    pub counter_errors: CounterErrors,
    /// Whether a step above the largest gap moves the baseline and the instant
    /// of the last valid reception to the frame.
    pub out_of_range_moves_baseline: bool,
}

impl Default for JudgeRules {
    fn default() -> Self {
        Self {
            ident: None,
            length: false,
            counter_errors: CounterErrors::Apart,
            out_of_range_moves_baseline: true,
        }
    }
}

/// The message cell: a split header field whose parts carry the frame's kind,
/// its result and the identity of its sender. A receiver reads the sender for
/// demultiplexing and reports the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellSpec {
    /// Index of the field.
    pub field: usize,
    /// Index, in the field's parts, of the kind; `None` when the cell has none.
    pub kind: Option<usize>,
    /// Index, in the field's parts, of the result; `None` when the cell has none.
    pub result: Option<usize>,
    /// Index, in the field's parts, of the sender identity; `None` when the cell
    /// has none.
    pub sender: Option<usize>,
}

/// Which frames of a capture share one counter: the part of the slot the
/// profile decides. The rest of a slot (the key expression and, unless
/// [`Self::by_zid`] is off, the sender) is the capture's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotSpec {
    /// Indices of the fields whose logical values tell one message from
    /// another on a shared key. Empty when a key carries one message.
    pub message: Vec<usize>,
    /// Whether two senders of one message keep separate counters.
    pub by_zid: bool,
}

impl Default for SlotSpec {
    /// One message per key, one counter per sender: the reading that cannot
    /// charge one sender with another's counter.
    fn default() -> Self {
        Self {
            message: Vec::new(),
            by_zid: true,
        }
    }
}

/// A validated profile.
#[derive(Debug, Clone)]
pub struct Profile {
    name: String,
    fields: Vec<Field>,
    header_bytes: usize,
    crc: CrcSpec,
    length: LengthSpec,
    counter: CounterSpec,
    slot: SlotSpec,
    rules: JudgeRules,
    cell: Option<CellSpec>,
}

impl Profile {
    /// Read and validate a profile from JSON text.
    pub fn parse(text: &str) -> Result<Self, DocError> {
        let root = read_json(text)?;
        let doc = Pointer::text("");
        let entries = doc.object(&root)?;
        doc.check_keys(
            entries,
            &[
                "name", "fields", "crc", "length", "counter", "slot", "judge", "cell",
            ],
        )?;

        let name = doc.key("name").read_name(doc.required(entries, "name")?)?;
        let fields = read_fields(doc.required(entries, "fields")?)?;
        let header_bytes = fields.iter().map(|f| f.bytes).sum();

        let crc = read_crc(doc.required(entries, "crc")?, &fields)?;
        let length = read_length(doc.required(entries, "length")?, &fields)?;
        let counter = read_counter(doc.required(entries, "counter")?, &fields)?;
        let slot = match optional(entries, "slot") {
            Some(value) => read_slot(value, &fields, [crc.field, length.field, counter.field])?,
            None => SlotSpec::default(),
        };

        for (a, b, what) in [
            (crc.field, length.field, "crc and length"),
            (crc.field, counter.field, "crc and counter"),
            (length.field, counter.field, "length and counter"),
        ] {
            if a == b {
                return Err(doc.refuse(format!(
                    "the {what} are the same field `{}`: each of them gives a field \
                     its own meaning",
                    fields[a].name
                )));
            }
        }

        let judged = [crc.field, length.field, counter.field];
        let rules = match optional(entries, "judge") {
            Some(value) => read_rules(value, &fields, judged)?,
            None => JudgeRules::default(),
        };
        let cell = match optional(entries, "cell") {
            Some(value) => Some(read_cell(value, &fields)?),
            None => None,
        };

        Ok(Self {
            name,
            fields,
            header_bytes,
            crc,
            length,
            counter,
            slot,
            rules,
            cell,
        })
    }

    /// The profile's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The header fields in wire order.
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// The index of the field called `name`.
    pub fn field_index(&self, name: &str) -> Option<usize> {
        self.fields.iter().position(|f| f.name == name)
    }

    /// The header's size; the body starts at this offset.
    pub fn header_bytes(&self) -> usize {
        self.header_bytes
    }

    /// The CRC rules.
    pub fn crc(&self) -> &CrcSpec {
        &self.crc
    }

    /// The length rules.
    pub fn length(&self) -> &LengthSpec {
        &self.length
    }

    /// The counter rules.
    pub fn counter(&self) -> &CounterSpec {
        &self.counter
    }

    /// What the profile says about which frames share a counter.
    pub fn slot(&self) -> &SlotSpec {
        &self.slot
    }

    /// The rules a receiver judges a frame by beyond the CRC and the step.
    pub fn rules(&self) -> &JudgeRules {
        &self.rules
    }

    /// The message cell, when the profile names one.
    pub fn cell(&self) -> Option<&CellSpec> {
        self.cell.as_ref()
    }

    /// The largest `max_gap` a receiver may be given: the profile's ceiling, or
    /// the largest step the counter field can make when it states none.
    pub fn max_gap_limit(&self) -> u64 {
        self.counter
            .max_gap_ceiling
            .unwrap_or_else(|| self.fields[self.counter.field].max_value())
    }

    /// What a judge of this profile's frames is configured with.
    pub fn judge_config(&self) -> JudgeConfig {
        let counter = &self.counter;
        JudgeConfig {
            counter_bytes: self.fields[counter.field].bytes,
            max_gap: counter.max_gap,
            timeout_ms: counter.timeout_ms,
        }
    }

    /// What a judge of this profile's frames does to its state.
    pub fn counter_rules(&self) -> CounterRules {
        CounterRules {
            out_of_range_moves_baseline: self.rules.out_of_range_moves_baseline,
        }
    }

    /// A judge for one stream of this profile's frames, configured from its
    /// counter rules. A stream is the caller's to define, so the caller keeps
    /// one judge per stream; see [`crate::e2e_judge`].
    pub fn judge(&self) -> Judge {
        Judge::with_rules(self.judge_config(), self.counter_rules())
    }

    /// The value the length field carries for a body of `payload_bytes`.
    ///
    /// It may be larger than the length field can hold; the builder checks
    /// that and refuses with the numbers.
    pub fn length_for(&self, payload_bytes: usize) -> u64 {
        let total = (self.header_bytes + payload_bytes) as u64;
        match &self.length.counts {
            LengthCounts::Frame => total,
            LengthCounts::FrameMinus(skipped) => {
                let skipped: usize = skipped.iter().map(|&i| self.fields[i].bytes).sum();
                total - skipped as u64
            }
        }
    }
}

/// The workspace's JSON reader, with its refusal in this module's terms.
///
/// The document is first walked by the lexer's bounded skip, which checks the
/// whole grammar and refuses nesting past [`MAX_JSON_DEPTH`] without recursing
/// beyond it; only then is the tree built, by a parser that has no bound of its
/// own. Both refusals carry the byte they stopped at.
pub fn read_json(text: &str) -> Result<Json5Value, DocError> {
    let syntax = |e: Json5Error| DocError::Syntax {
        offset: e.offset,
        expected: e.expected,
    };
    let mut lexer = Lexer::new(text);
    lexer.skip_trivia().map_err(syntax)?;
    lexer.skip_value(MAX_JSON_DEPTH).map_err(syntax)?;
    json5::parse(text).map_err(syntax)
}

/// Where a reader stands in a document: an RFC 6901 JSON pointer that is
/// written out only when a refusal names it. A reader descends by borrowing
/// the step above, so a document that is accepted builds no path at all.
#[derive(Debug, Clone, Copy)]
pub struct Pointer<'a> {
    parent: Option<&'a Pointer<'a>>,
    step: Step<'a>,
}

#[derive(Debug, Clone, Copy)]
enum Step<'a> {
    /// A pointer already written out.
    Text(&'a str),
    /// A member of an object, by its key.
    Key(&'a str),
    /// An item of an array, by its index.
    Index(usize),
}

impl<'a> Pointer<'a> {
    /// A pointer already written out: `""` is the document itself.
    pub const fn text(text: &'a str) -> Self {
        Self {
            parent: None,
            step: Step::Text(text),
        }
    }

    /// The member `key` of the object this points at.
    pub fn key<'b>(&'b self, key: &'b str) -> Pointer<'b> {
        Pointer {
            parent: Some(self),
            step: Step::Key(key),
        }
    }

    /// The item `index` of the array this points at.
    pub fn index(&self, index: usize) -> Pointer<'_> {
        Pointer {
            parent: Some(self),
            step: Step::Index(index),
        }
    }

    /// The pointer written out, a key's `~` and `/` escaped as RFC 6901 says.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write_into(&mut out);
        out
    }

    fn write_into(&self, out: &mut String) {
        use core::fmt::Write as _;
        if let Some(parent) = self.parent {
            parent.write_into(out);
        }
        match self.step {
            Step::Text(text) => out.push_str(text),
            Step::Key(key) => {
                out.push('/');
                for c in key.chars() {
                    match c {
                        '~' => out.push_str("~0"),
                        '/' => out.push_str("~1"),
                        c => out.push(c),
                    }
                }
            }
            // Writing into a `String` does not fail.
            Step::Index(index) => {
                let _ = write!(out, "/{index}");
            }
        }
    }

    /// The refusal of what stands here, for `reason`.
    pub fn refuse(&self, reason: impl Into<String>) -> DocError {
        DocError::Invalid {
            path: self.render(),
            reason: reason.into(),
        }
    }

    /// The object this points at.
    pub fn object<'v>(&self, value: &'v Json5Value) -> Result<&'v Entries, DocError> {
        match value {
            Json5Value::Object(entries) => Ok(entries),
            other => Err(self.refuse(format!("expected an object, found {}", describe(other)))),
        }
    }

    /// The array this points at.
    pub fn array<'v>(&self, value: &'v Json5Value) -> Result<&'v [Json5Value], DocError> {
        match value {
            Json5Value::Array(items) => Ok(items),
            other => Err(self.refuse(format!("expected an array, found {}", describe(other)))),
        }
    }

    /// Refuse a key outside `allowed` and a key that appears twice. The reader
    /// keeps every member, and resolving a repeat silently (last one wins) would
    /// make a typo in a profile read as a choice.
    pub fn check_keys(&self, entries: &Entries, allowed: &[&str]) -> Result<(), DocError> {
        for (key, _) in entries {
            if !allowed.contains(&key.as_str()) {
                return Err(self.key(key).refuse(format!(
                    "unknown key `{key}` (allowed here: {})",
                    allowed.join(", ")
                )));
            }
        }
        self.check_distinct(entries)
    }

    /// Refuse a key that appears twice, for an object whose keys are the
    /// caller's own names rather than a fixed list.
    pub fn check_distinct(&self, entries: &Entries) -> Result<(), DocError> {
        for (i, (key, _)) in entries.iter().enumerate() {
            if entries[..i].iter().any(|(earlier, _)| earlier == key) {
                return Err(self
                    .key(key)
                    .refuse(format!("the key `{key}` appears twice")));
            }
        }
        Ok(())
    }

    /// The member `key` of `entries`, which this points at, refused here when
    /// it is missing.
    pub fn required<'v>(
        &self,
        entries: &'v Entries,
        key: &str,
    ) -> Result<&'v Json5Value, DocError> {
        optional(entries, key).ok_or_else(|| self.refuse(format!("the key `{key}` is required")))
    }

    /// An unsigned integer as a profile or a values document writes one: a
    /// plain decimal JSON number, or a string of decimal or `0x` hex digits.
    pub fn read_uint(&self, value: &Json5Value) -> Result<u64, DocError> {
        let result = match value {
            Json5Value::Number(text) => {
                if is_plain_decimal(text) {
                    uint_from_text(text)
                } else {
                    Err(format!(
                        "`{text}` is not a plain unsigned decimal number: write hexadecimal \
                         as a string such as \"0x1f\""
                    ))
                }
            }
            Json5Value::String(text) => uint_from_text(text),
            other => Err(format!(
                "expected an unsigned integer (a number, or a string of decimal or 0x hex \
                 digits), found {}",
                describe(other)
            )),
        };
        result.map_err(|reason| self.refuse(reason))
    }

    /// The boolean this points at.
    pub fn read_bool(&self, value: &Json5Value) -> Result<bool, DocError> {
        match value {
            Json5Value::Bool(b) => Ok(*b),
            other => Err(self.refuse(format!("expected true or false, found {}", describe(other)))),
        }
    }

    /// The string this points at.
    pub fn read_string<'v>(&self, value: &'v Json5Value) -> Result<&'v str, DocError> {
        match value {
            Json5Value::String(s) => Ok(s),
            other => Err(self.refuse(format!("expected a string, found {}", describe(other)))),
        }
    }

    /// The name this points at: a profile's, a field's or a part's.
    pub(crate) fn read_name(&self, value: &Json5Value) -> Result<String, DocError> {
        let name = self.read_string(value)?;
        check_name(name, self)?;
        Ok(String::from(name))
    }
}

/// `path` with the member `key` below it, written out. A reader holds a
/// [`Pointer`] instead, which is written out only for a refusal.
pub fn child(path: &str, key: &str) -> String {
    Pointer::text(path).key(key).render()
}

/// `path` with the item `index` below it, written out.
pub fn at(path: &str, index: usize) -> String {
    Pointer::text(path).index(index).render()
}

pub(crate) fn describe(value: &Json5Value) -> &'static str {
    match value {
        Json5Value::Null => "null",
        Json5Value::Bool(_) => "a boolean",
        Json5Value::Number(_) => "a number",
        Json5Value::String(_) => "a string",
        Json5Value::Array(_) => "an array",
        Json5Value::Object(_) => "an object",
    }
}

pub type Entries = [(String, Json5Value)];

pub fn object<'a>(value: &'a Json5Value, path: &str) -> Result<&'a Entries, DocError> {
    Pointer::text(path).object(value)
}

pub fn array<'a>(value: &'a Json5Value, path: &str) -> Result<&'a [Json5Value], DocError> {
    Pointer::text(path).array(value)
}

/// [`Pointer::check_keys`] at a pointer already written out.
pub fn check_keys(entries: &Entries, allowed: &[&str], path: &str) -> Result<(), DocError> {
    Pointer::text(path).check_keys(entries, allowed)
}

/// [`Pointer::check_distinct`] at a pointer already written out.
pub fn check_distinct(entries: &Entries, path: &str) -> Result<(), DocError> {
    Pointer::text(path).check_distinct(entries)
}

pub fn optional<'a>(entries: &'a Entries, key: &str) -> Option<&'a Json5Value> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

pub fn required<'a>(
    entries: &'a Entries,
    key: &str,
    path: &str,
) -> Result<&'a Json5Value, DocError> {
    Pointer::text(path).required(entries, key)
}

/// Whether `text` is `0` or digits with no leading zero.
fn is_plain_decimal(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text.len() == 1 || !text.starts_with('0'))
}

fn uint_from_text(text: &str) -> Result<u64, String> {
    let does_not_fit = || format!("`{text}` does not fit in 64 bits");
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("`{text}` is not hexadecimal digits after `0x`"));
        }
        return u64::from_str_radix(hex, 16).map_err(|_| does_not_fit());
    }
    if !is_plain_decimal(text) {
        return Err(format!(
            "`{text}` is not an unsigned integer: write decimal digits with no sign or \
             leading zero, or `0x` and hex digits"
        ));
    }
    text.parse().map_err(|_| does_not_fit())
}

/// [`Pointer::read_uint`] at a pointer already written out.
pub fn read_uint(value: &Json5Value, path: &str) -> Result<u64, DocError> {
    Pointer::text(path).read_uint(value)
}

pub fn read_bool(value: &Json5Value, path: &str) -> Result<bool, DocError> {
    Pointer::text(path).read_bool(value)
}

pub fn read_string<'a>(value: &'a Json5Value, path: &str) -> Result<&'a str, DocError> {
    Pointer::text(path).read_string(value)
}

fn check_name(name: &str, path: &Pointer<'_>) -> Result<(), DocError> {
    let bad = |reason: String| Err(path.refuse(reason));
    if name.is_empty() {
        return bad(String::from("a name cannot be empty"));
    }
    if name.len() > MAX_NAME_BYTES {
        return bad(format!(
            "a name is at most {MAX_NAME_BYTES} bytes, this one is {}",
            name.len()
        ));
    }
    if let Some(c) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
    {
        return bad(format!(
            "`{name}` has the character {c:?}: a name is letters, digits, `_`, `-` and `.`"
        ));
    }
    Ok(())
}

fn read_fields(value: &Json5Value) -> Result<Vec<Field>, DocError> {
    let path = Pointer::text("/fields");
    let items = path.array(value)?;
    if items.is_empty() || items.len() > MAX_FIELDS {
        return Err(path.refuse(format!(
            "a profile has 1 to {MAX_FIELDS} fields, this one has {}",
            items.len()
        )));
    }
    let mut fields: Vec<Field> = Vec::with_capacity(items.len());
    let mut offset = 0usize;
    for (i, item) in items.iter().enumerate() {
        let here = path.index(i);
        let entries = here.object(item)?;
        here.check_keys(entries, &["name", "bytes", "xor", "split", "derive"])?;

        let name_at = here.key("name");
        let name = name_at.read_name(here.required(entries, "name")?)?;
        if fields.iter().any(|f| f.name == name) {
            return Err(name_at.refuse(format!("two fields are called `{name}`")));
        }
        let bytes_at = here.key("bytes");
        let bytes = bytes_at.read_uint(here.required(entries, "bytes")?)?;
        if !(1..=8).contains(&bytes) {
            return Err(
                bytes_at.refuse(format!("a field is 1 to 8 bytes wide, this one is {bytes}"))
            );
        }
        let bytes = bytes as usize;
        let bits = (bytes * 8) as u8;

        let xor = match optional(entries, "xor") {
            None => 0,
            Some(v) => {
                let xor_at = here.key("xor");
                let xor = xor_at.read_uint(v)?;
                if xor & !width_mask(bits) != 0 {
                    return Err(xor_at.refuse(format!(
                        "the xor {xor:#x} does not fit the field's {bits} bits"
                    )));
                }
                xor
            }
        };
        let parts = match optional(entries, "split") {
            None => Vec::new(),
            Some(v) => read_split(v, &here.key("split"), bits)?,
        };
        let derive = match optional(entries, "derive") {
            None => None,
            Some(_) if !parts.is_empty() => {
                return Err(here.key("derive").refuse(format!(
                    "the field `{name}` is split: a split field derives a value part by \
                     part, in the part's own `derive`"
                )))
            }
            Some(v) => Some(read_derive(v, &here.key("derive"), bits)?),
        };

        fields.push(Field {
            name,
            bytes,
            offset,
            xor,
            parts,
            derive,
        });
        offset += bytes;
    }
    Ok(fields)
}

fn read_split(value: &Json5Value, path: &Pointer<'_>, bits: u8) -> Result<Vec<Part>, DocError> {
    let items = path.array(value)?;
    if items.is_empty() || items.len() > MAX_PARTS {
        return Err(path.refuse(format!(
            "a split has 1 to {MAX_PARTS} parts, this one has {}",
            items.len()
        )));
    }
    let mut parts: Vec<Part> = Vec::with_capacity(items.len());
    let mut claimed = 0u64;
    for (i, item) in items.iter().enumerate() {
        let here = path.index(i);
        let entries = here.object(item)?;
        here.check_keys(entries, &["name", "lsb", "width", "derive"])?;

        let name_at = here.key("name");
        let name = name_at.read_name(here.required(entries, "name")?)?;
        if parts.iter().any(|p| p.name == name) {
            return Err(name_at.refuse(format!("two parts of one field are called `{name}`")));
        }
        let width_at = here.key("width");
        let lsb = here.key("lsb").read_uint(here.required(entries, "lsb")?)?;
        let width = width_at.read_uint(here.required(entries, "width")?)?;
        if width == 0 {
            return Err(width_at.refuse("a part is at least 1 bit wide"));
        }
        if lsb >= u64::from(bits) || width > u64::from(bits) - lsb {
            return Err(here.refuse(format!(
                "the part `{name}` (lsb {lsb}, width {width}) does not fit the field's \
                 {bits} bits"
            )));
        }
        let (lsb, width) = (lsb as u8, width as u8);
        let span = width_mask(width) << lsb;
        if claimed & span != 0 {
            return Err(here.refuse(format!(
                "the part `{name}` overlaps an earlier part of the same field"
            )));
        }
        claimed |= span;
        let derive = match optional(entries, "derive") {
            None => None,
            Some(v) => Some(read_derive(v, &here.key("derive"), width)?),
        };
        parts.push(Part {
            name,
            lsb,
            width,
            derive,
        });
    }
    Ok(parts)
}

/// A derivation rule, `{"from": "address", "mask": ..., "xor": ...}`, for a
/// value `bits` wide. The mask and the xor must fit those bits, so the derived
/// value always fits; a mask of zero would take nothing from the address and is
/// refused, since a constant is the caller's to state.
fn read_derive(value: &Json5Value, path: &Pointer<'_>, bits: u8) -> Result<Derive, DocError> {
    let entries = path.object(value)?;
    path.check_keys(entries, &["from", "mask", "xor"])?;
    let from_at = path.key("from");
    let from = from_at.read_string(path.required(entries, "from")?)?;
    if from != ADDRESS_SOURCE {
        return Err(from_at.refuse(format!(
            "`{from}` is not a source a value is derived from (expected `{ADDRESS_SOURCE}`)"
        )));
    }
    let fits = |key: &str, number: u64| -> Result<u64, DocError> {
        if number & !width_mask(bits) != 0 {
            return Err(path.key(key).refuse(format!(
                "the {key} {number:#x} does not fit the {bits} bits it derives"
            )));
        }
        Ok(number)
    };
    let mask_at = path.key("mask");
    let mask = fits("mask", mask_at.read_uint(path.required(entries, "mask")?)?)?;
    if mask == 0 {
        return Err(
            mask_at.refuse("a mask of 0 takes nothing from the address: state the value itself")
        );
    }
    let xor = match optional(entries, "xor") {
        None => 0,
        Some(v) => fits("xor", path.key("xor").read_uint(v)?)?,
    };
    Ok(Derive { mask, xor })
}

fn field_named(fields: &[Field], name: &str, path: &Pointer<'_>) -> Result<usize, DocError> {
    fields
        .iter()
        .position(|f| f.name == name)
        .ok_or_else(|| path.refuse(format!("no field is called `{name}`")))
}

/// A field the mechanism gives a meaning to (CRC, length, counter) carries no
/// transformation of its own.
fn plain(field: &Field, role: &str, path: &Pointer<'_>) -> Result<(), DocError> {
    if field.xor != 0 || !field.parts.is_empty() {
        return Err(path.refuse(format!(
            "the {role} field `{}` carries an xor or a split: a {role} field is read \
             as a plain integer",
            field.name
        )));
    }
    if field.derive.is_some() {
        return Err(path.refuse(format!(
            "the {role} field `{}` is derived from the address: a {role} field is given \
             its value by the mechanism",
            field.name
        )));
    }
    Ok(())
}

/// The engine a CRC object describes: its `width`, `poly`, `init`, `refin`,
/// `refout` and `xorout`, each refused at its own place. [`read_crc_object`]
/// checks the keys of the object and reads the rest of it (which field, what
/// is covered).
fn read_crc_engine(entries: &Entries, path: &Pointer<'_>) -> Result<Crc, DocError> {
    let width_at = path.key("width");
    let width = width_at.read_uint(path.required(entries, "width")?)?;
    if !u8::try_from(width).is_ok_and(|w| SUPPORTED_WIDTHS.contains(&w)) {
        return Err(width_at.refuse(format!(
            "a CRC width of {width} bits is not supported (the engine implements 8, 16, 32 and 64)"
        )));
    }
    let number = |key: &str| -> Result<u64, DocError> {
        path.key(key).read_uint(path.required(entries, key)?)
    };
    let flag = |key: &str| -> Result<bool, DocError> {
        path.key(key).read_bool(path.required(entries, key)?)
    };
    let params = CrcParams {
        width: width as u8,
        poly: number("poly")?,
        init: number("init")?,
        refin: flag("refin")?,
        refout: flag("refout")?,
        xorout: number("xorout")?,
    };
    Crc::new(params).map_err(|e| match e {
        CrcParamsError::UnsupportedWidth(_) => path.key("width").refuse(e.to_string()),
        CrcParamsError::DoesNotFit { what, .. } => path.key(what).refuse(e.to_string()),
    })
}

/// A profile kind's header fields as its CRC object reads them.
pub(crate) trait CrcFields {
    /// The index of the field called `name`.
    fn index_of(&self, name: &str) -> Option<usize>;
    /// How many bytes the field at `index` spans.
    fn bytes_of(&self, index: usize) -> usize;
    /// Refuse, at `path`, the field at `index` as the one the CRC is
    /// written to, by the kind's own rule.
    fn may_hold_crc(&self, index: usize, path: &Pointer<'_>) -> Result<(), DocError>;
    /// The `cover` entry that stands for the bytes after the header.
    fn body(&self) -> &'static str;
}

impl CrcFields for &[Field] {
    fn index_of(&self, name: &str) -> Option<usize> {
        self.iter().position(|f| f.name == name)
    }

    fn bytes_of(&self, index: usize) -> usize {
        self[index].bytes
    }

    fn may_hold_crc(&self, index: usize, path: &Pointer<'_>) -> Result<(), DocError> {
        plain(&self[index], "crc", path)
    }

    fn body(&self) -> &'static str {
        PAYLOAD
    }
}

/// A CRC object once read: the field the CRC is written to, the engine, and
/// what is fed in that order, `None` standing for the bytes after the header.
pub(crate) struct CrcObject {
    pub(crate) field: usize,
    pub(crate) engine: Crc,
    pub(crate) cover: Vec<Option<usize>>,
}

/// The index of the field `name` names, for a CRC object.
fn crc_field_named(
    fields: &dyn CrcFields,
    name: &str,
    path: &Pointer<'_>,
) -> Result<usize, DocError> {
    fields
        .index_of(name)
        .ok_or_else(|| path.refuse(format!("no field is called `{name}`")))
}

/// The CRC object of every profile kind that carries one, read and refused
/// one way: the kinds differ only in their fields, the rule for the field
/// that holds the CRC, and the word for the body ([`CrcFields`]). Not
/// generic, so one body serves every kind.
pub(crate) fn read_crc_object(
    value: &Json5Value,
    path: &Pointer<'_>,
    fields: &dyn CrcFields,
) -> Result<CrcObject, DocError> {
    let entries = path.object(value)?;
    path.check_keys(
        entries,
        &[
            "field", "width", "poly", "init", "refin", "refout", "xorout", "cover",
        ],
    )?;

    let field_at = path.key("field");
    let field_name = field_at.read_string(path.required(entries, "field")?)?;
    let field = crc_field_named(fields, field_name, &field_at)?;
    fields.may_hold_crc(field, &field_at)?;

    let engine = read_crc_engine(entries, path)?;
    let width = engine.params().width;
    let bits = fields.bytes_of(field) * 8;
    if usize::from(width) > bits {
        return Err(field_at.refuse(format!(
            "the crc field `{field_name}` is {bits} bits wide, narrower than the {width}-bit CRC"
        )));
    }

    let cover_at = path.key("cover");
    let items = cover_at.array(path.required(entries, "cover")?)?;
    if items.is_empty() {
        return Err(cover_at.refuse("the cover list is empty: the CRC would take no input"));
    }
    let body = fields.body();
    let mut cover: Vec<Option<usize>> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let here = cover_at.index(i);
        let name = here.read_string(item)?;
        let entry = if name == body {
            None
        } else {
            Some(crc_field_named(fields, name, &here)?)
        };
        if entry == Some(field) {
            return Err(here.refuse(format!(
                "the crc field `{name}` is never covered: it holds the result"
            )));
        }
        if cover.contains(&entry) {
            return Err(here.refuse(format!("`{name}` is covered twice")));
        }
        cover.push(entry);
    }
    Ok(CrcObject {
        field,
        engine,
        cover,
    })
}

fn read_crc(value: &Json5Value, fields: &[Field]) -> Result<CrcSpec, DocError> {
    let crc = read_crc_object(value, &Pointer::text("/crc"), &fields)?;
    Ok(CrcSpec {
        field: crc.field,
        engine: crc.engine,
        cover: crc
            .cover
            .into_iter()
            .map(|c| c.map_or(Cover::Payload, Cover::Field))
            .collect(),
    })
}

fn read_length(value: &Json5Value, fields: &[Field]) -> Result<LengthSpec, DocError> {
    let path = Pointer::text("/length");
    let entries = path.object(value)?;
    path.check_keys(entries, &["field", "counts", "fields"])?;

    let field_at = path.key("field");
    let field_name = field_at.read_string(path.required(entries, "field")?)?;
    let field = field_named(fields, field_name, &field_at)?;
    plain(&fields[field], "length", &field_at)?;

    let counts_at = path.key("counts");
    let counts = counts_at.read_string(path.required(entries, "counts")?)?;
    let listed = optional(entries, "fields");
    let counts = match (counts, listed) {
        ("frame", None) => LengthCounts::Frame,
        ("frame", Some(_)) => return Err(path.key("fields").refuse(
            "`fields` belongs to `frame_minus`: a length that counts the frame subtracts nothing",
        )),
        ("frame_minus", None) => {
            return Err(path
                .refuse("`frame_minus` needs `fields`: the fields whose widths are not counted"))
        }
        ("frame_minus", Some(v)) => {
            let list_at = path.key("fields");
            let items = list_at.array(v)?;
            if items.is_empty() {
                return Err(list_at
                    .refuse("the list is empty: use `frame` for a length that subtracts nothing"));
            }
            let mut skipped: Vec<usize> = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let here = list_at.index(i);
                let name = here.read_string(item)?;
                let index = field_named(fields, name, &here)?;
                if skipped.contains(&index) {
                    return Err(here.refuse(format!("`{name}` is listed twice")));
                }
                skipped.push(index);
            }
            LengthCounts::FrameMinus(skipped)
        }
        (other, _) => {
            return Err(counts_at.refuse(format!(
                "`{other}` is not a length rule (expected `frame` or `frame_minus`)"
            )))
        }
    };
    Ok(LengthSpec { field, counts })
}

fn read_slot(
    value: &Json5Value,
    fields: &[Field],
    judged: [usize; 3],
) -> Result<SlotSpec, DocError> {
    let path = Pointer::text("/slot");
    let entries = path.object(value)?;
    path.check_keys(entries, &["message", "by_zid"])?;

    let by_zid = match optional(entries, "by_zid") {
        Some(v) => path.key("by_zid").read_bool(v)?,
        None => true,
    };
    let mut message: Vec<usize> = Vec::new();
    if let Some(v) = optional(entries, "message") {
        let list_at = path.key("message");
        for (i, item) in list_at.array(v)?.iter().enumerate() {
            let here = list_at.index(i);
            let name = here.read_string(item)?;
            let index = field_named(fields, name, &here)?;
            if judged.contains(&index) {
                return Err(here.refuse(format!(
                    "`{name}` is the crc, length or counter field: it changes from \
                     frame to frame, so a slot keyed on it would never see a second \
                     frame"
                )));
            }
            if message.contains(&index) {
                return Err(here.refuse(format!("`{name}` is listed twice")));
            }
            message.push(index);
        }
    }
    Ok(SlotSpec { message, by_zid })
}

fn read_counter(value: &Json5Value, fields: &[Field]) -> Result<CounterSpec, DocError> {
    let path = Pointer::text("/counter");
    let entries = path.object(value)?;
    path.check_keys(
        entries,
        &["field", "max_gap", "timeout_ms", "max_gap_ceiling"],
    )?;

    let field_at = path.key("field");
    let field_name = field_at.read_string(path.required(entries, "field")?)?;
    let field = field_named(fields, field_name, &field_at)?;
    plain(&fields[field], "counter", &field_at)?;

    let gap_at = path.key("max_gap");
    let max_gap = gap_at.read_uint(path.required(entries, "max_gap")?)?;
    // The forward step between two counters is 1 to 2^bits - 1, so a bound
    // outside that range could not mean what it says.
    if max_gap == 0 || max_gap > fields[field].max_value() {
        return Err(gap_at.refuse(format!(
            "max_gap is 1 to {} for the {}-byte counter `{}`, this one is {max_gap}",
            fields[field].max_value(),
            fields[field].bytes,
            fields[field].name
        )));
    }
    // Required, 0 included: a stream with no limit states it, so a profile that
    // forgot the key is still refused rather than read as never timing out.
    let timeout_ms = path
        .key("timeout_ms")
        .read_uint(path.required(entries, "timeout_ms")?)?;
    let max_gap_ceiling = match optional(entries, "max_gap_ceiling") {
        None => None,
        Some(v) => {
            let ceiling_at = path.key("max_gap_ceiling");
            let ceiling = ceiling_at.read_uint(v)?;
            if ceiling == 0 || ceiling > fields[field].max_value() {
                return Err(ceiling_at.refuse(format!(
                    "max_gap_ceiling is 1 to {} for the {}-byte counter `{}`, this one is \
                     {ceiling}",
                    fields[field].max_value(),
                    fields[field].bytes,
                    fields[field].name
                )));
            }
            if max_gap > ceiling {
                return Err(gap_at.refuse(format!(
                    "max_gap {max_gap} is above the profile's max_gap_ceiling {ceiling}"
                )));
            }
            Some(ceiling)
        }
    };
    Ok(CounterSpec {
        field,
        max_gap,
        timeout_ms,
        max_gap_ceiling,
    })
}

/// The `judge` object: which header fields, besides the CRC, make a frame
/// intact, and how the counter errors are reported and what they move.
fn read_rules(
    value: &Json5Value,
    fields: &[Field],
    judged: [usize; 3],
) -> Result<JudgeRules, DocError> {
    let path = Pointer::text("/judge");
    let entries = path.object(value)?;
    path.check_keys(
        entries,
        &["ident", "length", "counter_errors", "out_of_range"],
    )?;
    let mut rules = JudgeRules::default();
    if let Some(v) = optional(entries, "ident") {
        let here = path.key("ident");
        let name = here.read_string(v)?;
        let index = field_named(fields, name, &here)?;
        if judged.contains(&index) {
            return Err(here.refuse(format!(
                "`{name}` is the crc, length or counter field, each judged by a rule of \
                 its own: the identifier is another field"
            )));
        }
        rules.ident = Some(index);
    }
    if let Some(v) = optional(entries, "length") {
        rules.length = path.key("length").read_bool(v)?;
    }
    if let Some(v) = optional(entries, "counter_errors") {
        let here = path.key("counter_errors");
        rules.counter_errors = match here.read_string(v)? {
            "apart" => CounterErrors::Apart,
            "joined" => CounterErrors::Joined,
            other => {
                return Err(here.refuse(format!(
                    "`{other}` is not a way to report counter errors (expected `apart` or `joined`)"
                )))
            }
        };
    }
    if let Some(v) = optional(entries, "out_of_range") {
        let here = path.key("out_of_range");
        rules.out_of_range_moves_baseline = match here.read_string(v)? {
            "moves_baseline" => true,
            "keeps_baseline" => false,
            other => {
                return Err(here.refuse(format!(
                    "`{other}` is not what a step out of range does (expected \
                     `moves_baseline` or `keeps_baseline`)"
                )))
            }
        };
    }
    Ok(rules)
}

/// The `cell` object: a split field and which of its parts are the kind, the
/// result and the sender identity.
fn read_cell(value: &Json5Value, fields: &[Field]) -> Result<CellSpec, DocError> {
    let path = Pointer::text("/cell");
    let entries = path.object(value)?;
    path.check_keys(entries, &["field", "kind", "result", "sender"])?;
    let field_at = path.key("field");
    let field_name = field_at.read_string(path.required(entries, "field")?)?;
    let field = field_named(fields, field_name, &field_at)?;
    let parts = &fields[field].parts;
    if parts.is_empty() {
        return Err(field_at.refuse(format!(
            "the cell field `{field_name}` is not split: a cell names parts of a split field"
        )));
    }
    let mut taken: Vec<usize> = Vec::with_capacity(3);
    let mut part = |key: &str| -> Result<Option<usize>, DocError> {
        let Some(v) = optional(entries, key) else {
            return Ok(None);
        };
        let here = path.key(key);
        let name = here.read_string(v)?;
        let Some(index) = parts.iter().position(|p| p.name == name) else {
            return Err(here.refuse(format!(
                "the field `{field_name}` has no part called `{name}`"
            )));
        };
        if taken.contains(&index) {
            return Err(here.refuse(format!("the part `{name}` is named twice in the cell")));
        }
        taken.push(index);
        Ok(Some(index))
    };
    let kind = part("kind")?;
    let result = part("result")?;
    let sender = part("sender")?;
    if kind.is_none() && result.is_none() && sender.is_none() {
        return Err(path.refuse("a cell names at least one of `kind`, `result` and `sender`"));
    }
    Ok(CellSpec {
        field,
        kind,
        result,
        sender,
    })
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::{at, child, Pointer};

    #[test]
    fn a_pointer_is_written_out_as_the_eager_path_was() {
        let fields = Pointer::text("/fields");
        let here = fields.index(2);
        let split = here.key("split");
        let part = split.index(0);
        assert_eq!(part.key("lsb").render(), "/fields/2/split/0/lsb");
        assert_eq!(
            part.key("lsb").render(),
            child(&at(&child(&at("/fields", 2), "split"), 0), "lsb")
        );

        let doc = Pointer::text("");
        assert_eq!(doc.render(), "");
        assert_eq!(doc.key("name").render(), "/name");
        // RFC 6901: `~` is written `~0` and `/` is written `~1`, in that order.
        assert_eq!(doc.key("a~/b").render(), "/a~0~1b");
        assert_eq!(doc.key("a~/b").render(), child("", "a~/b"));
        assert_eq!(doc.key("").render(), "/");
        assert_eq!(doc.index(10).render(), "/10");

        let refused = doc.key("x").index(1).refuse("why");
        assert_eq!(
            refused,
            super::DocError::Invalid {
                path: String::from("/x/1"),
                reason: String::from("why"),
            }
        );
    }
}

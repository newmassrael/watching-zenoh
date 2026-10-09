// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! every call, and this crate's own tests run on synthetic profiles whose
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
//!   point of keeping the two apart.
//! * `crc.cover` is the FEEDING ORDER: field names, and `"@payload"` for the
//!   body. The CRC field itself is never covered, and there is no zero-fill
//!   step. Each covered field is fed as it stands ON THE WIRE (after `xor`), big
//!   endian, at its own width.
//! * `length.counts` is `"frame"` (the value is header plus body) or
//!   `"frame_minus"` with `"fields": [...]` (header plus body less the widths
//!   of the listed fields). Which of them a sender used is not on the wire, so
//!   opening reports the length as INFORMATION beside the CRC verdict.
//! * `counter` names the field the judge reads, the largest forward step it
//!   accepts and the silence it tolerates.
//! * `slot` (optional) says which frames of a CAPTURE share one counter, for
//!   the pipeline that keeps a judge per slot (`crate::e2e_slots`); the
//!   stateless doors ignore it. A slot is the key expression the frame was
//!   published under, the sender, and the logical values of the `message`
//!   fields (none by default, so one key carries one message). `by_zid`
//!   (default true) keeps two senders' counters apart; a deployment whose
//!   receiver keeps one counter per message regardless of sender says `false`.
//!   A `message` field may not be the crc, length or counter field: each of
//!   those varies from frame to frame, and a slot that moved with the counter
//!   would judge nothing.
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
use crate::e2e_judge::{Judge, JudgeConfig};

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
    pub(crate) fn invalid(path: impl Into<String>, reason: impl Into<String>) -> Self {
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

/// One named bit range of a field's logical value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// The part's name, unique within its field.
    pub name: String,
    /// Bit position of the part's least significant bit.
    pub lsb: u8,
    /// How many bits the part spans.
    pub width: u8,
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
}

impl Field {
    /// The largest value the field holds.
    pub fn max_value(&self) -> u64 {
        width_mask((self.bytes * 8) as u8)
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
    /// The longest silence between valid receptions that is not an error.
    pub timeout_ms: u64,
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
}

impl Profile {
    /// Read and validate a profile from JSON text.
    pub fn parse(text: &str) -> Result<Self, DocError> {
        let root = read_json(text)?;
        let entries = object(&root, "")?;
        check_keys(
            entries,
            &["name", "fields", "crc", "length", "counter", "slot"],
            "",
        )?;

        let name = read_name(required(entries, "name", "")?, "/name")?;
        let fields = read_fields(required(entries, "fields", "")?)?;
        let header_bytes = fields.iter().map(|f| f.bytes).sum();

        let crc = read_crc(required(entries, "crc", "")?, &fields)?;
        let length = read_length(required(entries, "length", "")?, &fields)?;
        let counter = read_counter(required(entries, "counter", "")?, &fields)?;
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
                return Err(DocError::invalid(
                    "",
                    format!(
                        "the {what} are the same field `{}`: each of them gives a field \
                         its own meaning",
                        fields[a].name
                    ),
                ));
            }
        }

        Ok(Self {
            name,
            fields,
            header_bytes,
            crc,
            length,
            counter,
            slot,
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

    /// A judge for one stream of this profile's frames, configured from its
    /// counter rules. A stream is the caller's to define, so the caller keeps
    /// one judge per stream; see [`crate::e2e_judge`].
    pub fn judge(&self) -> Judge {
        let counter = &self.counter;
        Judge::new(JudgeConfig {
            counter_bytes: self.fields[counter.field].bytes,
            max_gap: counter.max_gap,
            timeout_ms: counter.timeout_ms,
        })
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
pub(crate) fn read_json(text: &str) -> Result<Json5Value, DocError> {
    let syntax = |e: Json5Error| DocError::Syntax {
        offset: e.offset,
        expected: e.expected,
    };
    let mut lexer = Lexer::new(text);
    lexer.skip_trivia().map_err(syntax)?;
    lexer.skip_value(MAX_JSON_DEPTH).map_err(syntax)?;
    json5::parse(text).map_err(syntax)
}

/// Everything below reads one part of the document. A path is built as the
/// reader descends, so every refusal names where it stands.
pub(crate) fn child(path: &str, key: &str) -> String {
    let mut out = String::from(path);
    out.push('/');
    for c in key.chars() {
        match c {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            c => out.push(c),
        }
    }
    out
}

fn at(path: &str, index: usize) -> String {
    format!("{path}/{index}")
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

pub(crate) type Entries = [(String, Json5Value)];

pub(crate) fn object<'a>(value: &'a Json5Value, path: &str) -> Result<&'a Entries, DocError> {
    match value {
        Json5Value::Object(entries) => Ok(entries),
        other => Err(DocError::invalid(
            path,
            format!("expected an object, found {}", describe(other)),
        )),
    }
}

fn array<'a>(value: &'a Json5Value, path: &str) -> Result<&'a [Json5Value], DocError> {
    match value {
        Json5Value::Array(items) => Ok(items),
        other => Err(DocError::invalid(
            path,
            format!("expected an array, found {}", describe(other)),
        )),
    }
}

/// Refuse a key outside `allowed` and a key that appears twice. The reader
/// keeps every member, and resolving a repeat silently (last one wins) would
/// make a typo in a profile read as a choice.
pub(crate) fn check_keys(entries: &Entries, allowed: &[&str], path: &str) -> Result<(), DocError> {
    for (key, _) in entries {
        if !allowed.contains(&key.as_str()) {
            return Err(DocError::invalid(
                child(path, key),
                format!("unknown key `{key}` (allowed here: {})", allowed.join(", ")),
            ));
        }
    }
    check_distinct(entries, path)
}

/// Refuse a key that appears twice, for an object whose keys are the caller's
/// own names rather than a fixed list.
pub(crate) fn check_distinct(entries: &Entries, path: &str) -> Result<(), DocError> {
    for (i, (key, _)) in entries.iter().enumerate() {
        if entries[..i].iter().any(|(earlier, _)| earlier == key) {
            return Err(DocError::invalid(
                child(path, key),
                format!("the key `{key}` appears twice"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn optional<'a>(entries: &'a Entries, key: &str) -> Option<&'a Json5Value> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn required<'a>(entries: &'a Entries, key: &str, path: &str) -> Result<&'a Json5Value, DocError> {
    optional(entries, key)
        .ok_or_else(|| DocError::invalid(path, format!("the key `{key}` is required")))
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

/// An unsigned integer as a profile or a values document writes one: a plain
/// decimal JSON number, or a string of decimal or `0x` hex digits.
pub(crate) fn read_uint(value: &Json5Value, path: &str) -> Result<u64, DocError> {
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
    result.map_err(|reason| DocError::invalid(path, reason))
}

fn read_bool(value: &Json5Value, path: &str) -> Result<bool, DocError> {
    match value {
        Json5Value::Bool(b) => Ok(*b),
        other => Err(DocError::invalid(
            path,
            format!("expected true or false, found {}", describe(other)),
        )),
    }
}

fn read_string<'a>(value: &'a Json5Value, path: &str) -> Result<&'a str, DocError> {
    match value {
        Json5Value::String(s) => Ok(s),
        other => Err(DocError::invalid(
            path,
            format!("expected a string, found {}", describe(other)),
        )),
    }
}

fn check_name(name: &str, path: &str) -> Result<(), DocError> {
    let bad = |reason: String| Err(DocError::invalid(path, reason));
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

fn read_name(value: &Json5Value, path: &str) -> Result<String, DocError> {
    let name = read_string(value, path)?;
    check_name(name, path)?;
    Ok(String::from(name))
}

fn read_fields(value: &Json5Value) -> Result<Vec<Field>, DocError> {
    let path = "/fields";
    let items = array(value, path)?;
    if items.is_empty() || items.len() > MAX_FIELDS {
        return Err(DocError::invalid(
            path,
            format!(
                "a profile has 1 to {MAX_FIELDS} fields, this one has {}",
                items.len()
            ),
        ));
    }
    let mut fields: Vec<Field> = Vec::with_capacity(items.len());
    let mut offset = 0usize;
    for (i, item) in items.iter().enumerate() {
        let here = at(path, i);
        let entries = object(item, &here)?;
        check_keys(entries, &["name", "bytes", "xor", "split"], &here)?;

        let name = read_name(required(entries, "name", &here)?, &child(&here, "name"))?;
        if fields.iter().any(|f| f.name == name) {
            return Err(DocError::invalid(
                child(&here, "name"),
                format!("two fields are called `{name}`"),
            ));
        }
        let bytes_path = child(&here, "bytes");
        let bytes = read_uint(required(entries, "bytes", &here)?, &bytes_path)?;
        if !(1..=8).contains(&bytes) {
            return Err(DocError::invalid(
                bytes_path,
                format!("a field is 1 to 8 bytes wide, this one is {bytes}"),
            ));
        }
        let bytes = bytes as usize;
        let bits = (bytes * 8) as u8;

        let xor = match optional(entries, "xor") {
            None => 0,
            Some(v) => {
                let xor_path = child(&here, "xor");
                let xor = read_uint(v, &xor_path)?;
                if xor & !width_mask(bits) != 0 {
                    return Err(DocError::invalid(
                        xor_path,
                        format!("the xor {xor:#x} does not fit the field's {bits} bits"),
                    ));
                }
                xor
            }
        };
        let parts = match optional(entries, "split") {
            None => Vec::new(),
            Some(v) => read_split(v, &child(&here, "split"), bits)?,
        };

        fields.push(Field {
            name,
            bytes,
            offset,
            xor,
            parts,
        });
        offset += bytes;
    }
    Ok(fields)
}

fn read_split(value: &Json5Value, path: &str, bits: u8) -> Result<Vec<Part>, DocError> {
    let items = array(value, path)?;
    if items.is_empty() || items.len() > MAX_PARTS {
        return Err(DocError::invalid(
            path,
            format!(
                "a split has 1 to {MAX_PARTS} parts, this one has {}",
                items.len()
            ),
        ));
    }
    let mut parts: Vec<Part> = Vec::with_capacity(items.len());
    let mut claimed = 0u64;
    for (i, item) in items.iter().enumerate() {
        let here = at(path, i);
        let entries = object(item, &here)?;
        check_keys(entries, &["name", "lsb", "width"], &here)?;

        let name = read_name(required(entries, "name", &here)?, &child(&here, "name"))?;
        if parts.iter().any(|p| p.name == name) {
            return Err(DocError::invalid(
                child(&here, "name"),
                format!("two parts of one field are called `{name}`"),
            ));
        }
        let lsb_path = child(&here, "lsb");
        let width_path = child(&here, "width");
        let lsb = read_uint(required(entries, "lsb", &here)?, &lsb_path)?;
        let width = read_uint(required(entries, "width", &here)?, &width_path)?;
        if width == 0 {
            return Err(DocError::invalid(
                width_path,
                "a part is at least 1 bit wide",
            ));
        }
        if lsb >= u64::from(bits) || width > u64::from(bits) - lsb {
            return Err(DocError::invalid(
                &here,
                format!(
                    "the part `{name}` (lsb {lsb}, width {width}) does not fit the field's \
                     {bits} bits"
                ),
            ));
        }
        let (lsb, width) = (lsb as u8, width as u8);
        let span = width_mask(width) << lsb;
        if claimed & span != 0 {
            return Err(DocError::invalid(
                &here,
                format!("the part `{name}` overlaps an earlier part of the same field"),
            ));
        }
        claimed |= span;
        parts.push(Part { name, lsb, width });
    }
    Ok(parts)
}

fn field_named(fields: &[Field], name: &str, path: &str) -> Result<usize, DocError> {
    fields
        .iter()
        .position(|f| f.name == name)
        .ok_or_else(|| DocError::invalid(path, format!("no field is called `{name}`")))
}

/// A field the mechanism gives a meaning to (CRC, length, counter) carries no
/// transformation of its own.
fn plain(field: &Field, role: &str, path: &str) -> Result<(), DocError> {
    if field.xor != 0 || !field.parts.is_empty() {
        return Err(DocError::invalid(
            path,
            format!(
                "the {role} field `{}` carries an xor or a split: a {role} field is read \
                 as a plain integer",
                field.name
            ),
        ));
    }
    Ok(())
}

fn read_crc(value: &Json5Value, fields: &[Field]) -> Result<CrcSpec, DocError> {
    let path = "/crc";
    let entries = object(value, path)?;
    check_keys(
        entries,
        &[
            "field", "width", "poly", "init", "refin", "refout", "xorout", "cover",
        ],
        path,
    )?;

    let field_path = child(path, "field");
    let field_name = read_string(required(entries, "field", path)?, &field_path)?;
    let field = field_named(fields, field_name, &field_path)?;
    plain(&fields[field], "crc", &field_path)?;

    let width_path = child(path, "width");
    let width = read_uint(required(entries, "width", path)?, &width_path)?;
    if !u8::try_from(width).is_ok_and(|w| SUPPORTED_WIDTHS.contains(&w)) {
        return Err(DocError::invalid(
            width_path,
            format!("a CRC width of {width} bits is not supported (the engine implements 8, 16, 32 and 64)"),
        ));
    }
    let width = width as u8;
    if usize::from(width) > fields[field].bytes * 8 {
        return Err(DocError::invalid(
            field_path,
            format!(
                "the crc field `{}` is {} bits wide, narrower than the {width}-bit CRC",
                fields[field].name,
                fields[field].bytes * 8
            ),
        ));
    }

    let number = |key: &str| -> Result<u64, DocError> {
        read_uint(required(entries, key, path)?, &child(path, key))
    };
    let flag = |key: &str| -> Result<bool, DocError> {
        read_bool(required(entries, key, path)?, &child(path, key))
    };
    let params = CrcParams {
        width,
        poly: number("poly")?,
        init: number("init")?,
        refin: flag("refin")?,
        refout: flag("refout")?,
        xorout: number("xorout")?,
    };
    let engine = Crc::new(params).map_err(|e| match e {
        CrcParamsError::UnsupportedWidth(_) => {
            DocError::invalid(child(path, "width"), e.to_string())
        }
        CrcParamsError::DoesNotFit { what, .. } => {
            DocError::invalid(child(path, what), e.to_string())
        }
    })?;

    let cover_path = child(path, "cover");
    let items = array(required(entries, "cover", path)?, &cover_path)?;
    if items.is_empty() {
        return Err(DocError::invalid(
            cover_path,
            "the cover list is empty: the CRC would take no input",
        ));
    }
    let mut cover: Vec<Cover> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let here = at(&cover_path, i);
        let name = read_string(item, &here)?;
        let entry = if name == PAYLOAD {
            Cover::Payload
        } else {
            Cover::Field(field_named(fields, name, &here)?)
        };
        if entry == Cover::Field(field) {
            return Err(DocError::invalid(
                here,
                format!("the crc field `{name}` is never covered: it holds the result"),
            ));
        }
        if cover.contains(&entry) {
            return Err(DocError::invalid(
                here,
                format!("`{name}` is covered twice"),
            ));
        }
        cover.push(entry);
    }

    Ok(CrcSpec {
        field,
        engine,
        cover,
    })
}

fn read_length(value: &Json5Value, fields: &[Field]) -> Result<LengthSpec, DocError> {
    let path = "/length";
    let entries = object(value, path)?;
    check_keys(entries, &["field", "counts", "fields"], path)?;

    let field_path = child(path, "field");
    let field_name = read_string(required(entries, "field", path)?, &field_path)?;
    let field = field_named(fields, field_name, &field_path)?;
    plain(&fields[field], "length", &field_path)?;

    let counts_path = child(path, "counts");
    let counts = read_string(required(entries, "counts", path)?, &counts_path)?;
    let listed = optional(entries, "fields");
    let counts = match (counts, listed) {
        ("frame", None) => LengthCounts::Frame,
        ("frame", Some(_)) => return Err(DocError::invalid(
            child(path, "fields"),
            "`fields` belongs to `frame_minus`: a length that counts the frame subtracts nothing",
        )),
        ("frame_minus", None) => {
            return Err(DocError::invalid(
                path,
                "`frame_minus` needs `fields`: the fields whose widths are not counted",
            ))
        }
        ("frame_minus", Some(v)) => {
            let list_path = child(path, "fields");
            let items = array(v, &list_path)?;
            if items.is_empty() {
                return Err(DocError::invalid(
                    list_path,
                    "the list is empty: use `frame` for a length that subtracts nothing",
                ));
            }
            let mut skipped: Vec<usize> = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let here = at(&list_path, i);
                let name = read_string(item, &here)?;
                let index = field_named(fields, name, &here)?;
                if skipped.contains(&index) {
                    return Err(DocError::invalid(here, format!("`{name}` is listed twice")));
                }
                skipped.push(index);
            }
            LengthCounts::FrameMinus(skipped)
        }
        (other, _) => {
            return Err(DocError::invalid(
                counts_path,
                format!("`{other}` is not a length rule (expected `frame` or `frame_minus`)"),
            ))
        }
    };
    Ok(LengthSpec { field, counts })
}

fn read_slot(
    value: &Json5Value,
    fields: &[Field],
    judged: [usize; 3],
) -> Result<SlotSpec, DocError> {
    let path = "/slot";
    let entries = object(value, path)?;
    check_keys(entries, &["message", "by_zid"], path)?;

    let by_zid = match optional(entries, "by_zid") {
        Some(v) => read_bool(v, &child(path, "by_zid"))?,
        None => true,
    };
    let mut message: Vec<usize> = Vec::new();
    if let Some(v) = optional(entries, "message") {
        let list_path = child(path, "message");
        for (i, item) in array(v, &list_path)?.iter().enumerate() {
            let here = at(&list_path, i);
            let name = read_string(item, &here)?;
            let index = field_named(fields, name, &here)?;
            if judged.contains(&index) {
                return Err(DocError::invalid(
                    here,
                    format!(
                        "`{name}` is the crc, length or counter field: it changes from \
                         frame to frame, so a slot keyed on it would never see a second \
                         frame"
                    ),
                ));
            }
            if message.contains(&index) {
                return Err(DocError::invalid(here, format!("`{name}` is listed twice")));
            }
            message.push(index);
        }
    }
    Ok(SlotSpec { message, by_zid })
}

fn read_counter(value: &Json5Value, fields: &[Field]) -> Result<CounterSpec, DocError> {
    let path = "/counter";
    let entries = object(value, path)?;
    check_keys(entries, &["field", "max_gap", "timeout_ms"], path)?;

    let field_path = child(path, "field");
    let field_name = read_string(required(entries, "field", path)?, &field_path)?;
    let field = field_named(fields, field_name, &field_path)?;
    plain(&fields[field], "counter", &field_path)?;

    let gap_path = child(path, "max_gap");
    let max_gap = read_uint(required(entries, "max_gap", path)?, &gap_path)?;
    // The forward step between two counters is 1 to 2^bits - 1, so a bound
    // outside that range could not mean what it says.
    if max_gap == 0 || max_gap > fields[field].max_value() {
        return Err(DocError::invalid(
            gap_path,
            format!(
                "max_gap is 1 to {} for the {}-byte counter `{}`, this one is {max_gap}",
                fields[field].max_value(),
                fields[field].bytes,
                fields[field].name
            ),
        ));
    }
    let timeout_path = child(path, "timeout_ms");
    let timeout_ms = read_uint(required(entries, "timeout_ms", path)?, &timeout_path)?;
    if timeout_ms == 0 {
        return Err(DocError::invalid(
            timeout_path,
            "timeout_ms is at least 1: a limit of zero would time out every gap",
        ));
    }
    Ok(CounterSpec {
        field,
        max_gap,
        timeout_ms,
    })
}

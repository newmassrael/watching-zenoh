// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Protobuf wire bytes READ by the types a `.proto` schema gives them: the
//! reading half of [`crate::proto_encode`].
//!
//! ## What this is for
//!
//! The wire format carries a field's number and one of four wire types, and
//! nothing else. The schema-less walk ([`crate::payload::formats::Protobuf`])
//! reads what that much allows: a `sint32` of `-3` shows as `varint 5`, a
//! `double` as eight bytes of hex, a packed run of integers as a blob, and a
//! string and a nested message are told apart by guessing. A reader that HOLDS
//! the schema has no reason to guess, and a consumer that holds it and reads
//! the bytes itself is a second reader of the wire format beside this
//! library's one writer -- the two disagree exactly where the format is
//! unusual. This is the one typed reader, and it reads with the same schema
//! reader ([`crate::proto_schema`]), from the same list of files, under the
//! same rules as the writer.
//!
//! ## What comes out
//!
//! A listing of the fields in the order they are on the wire, ONE ENTRY PER
//! OCCURRENCE ([`DecodedField`]): the field number, the name and the type as the
//! schema writes them, the span of bytes, and the value as the type reads it.
//!
//! * A message field holds the listing of its own fields. A `map` field is, on
//!   the wire, a repeated field of entry messages whose key is field 1 and whose
//!   value is field 2 (`google/protobuf/descriptor.proto`, the comment on
//!   `MessageOptions.map_entry`), and it is listed as exactly that: one entry
//!   per map entry, holding a `key` and a `value`, which are the names `protoc`
//!   gives them and the paths [`crate::proto_schema`] declares (`5.1`, `5.2`).
//! * A packed run is one entry PER ELEMENT, each with the span of its own bytes
//!   inside the run, so a repeated field reads the same packed or not. Both
//!   forms are accepted for every repeated numeric, `bool` and enum field,
//!   whatever the schema says about packing, as every protobuf parser must.
//! * A field written twice is two entries. A parser keeps the last one (and
//!   merges a message), and so does a member of a oneof another member
//!   follows; this listing does not resolve them, because what the sender
//!   wrote is what a reader of a capture is asking about.
//! * A field the schema does not know -- a number no field has, or a known
//!   number under a wire type its type is never written with, which is what a
//!   protobuf parser treats as unknown too -- is an entry with no name and no
//!   type, holding the raw value of its wire type ([`Value::Unknown`]).
//! * An enum value is its number and the name the enum gives it, or no name
//!   when the enum has none for that number. A proto2 parser files such a value
//!   with the unknown fields; here it stays on the field it arrived in, so a
//!   reader sees which field it was.
//!
//! ## What is refused
//!
//! A wire that is not a message, with the byte offset and, when it happened
//! inside a field the schema knows, that field's full name ([`WireError`]): the
//! bytes end inside a tag, a value or a length; a varint longer than ten bytes,
//! or whose tenth byte carries more than the one bit 64 bits leave for it;
//! field number zero, or one above `2^29 - 1`; the wire types `3` and `4` (the
//! deprecated group markers, which the writer never writes and this reader does
//! not walk) and `6` and `7`, which are none; a packed run that does not end on
//! an element; a `string` that is not UTF-8 (a proto3 parser refuses it, and a
//! proto2 one keeps bytes that a JSON string could not carry); and messages
//! nested deeper than [`MAX_DECODE_DEPTH`]. The first problem is the only one
//! reported, and nothing decoded before it is returned with it: a partial
//! listing reads as the whole message.
//!
//! The schema is refused as [`crate::proto_encode`] refuses it, with the same
//! diagnostic: the reader is the same, and so is the order (an argument, the
//! files, the root message).
//!
//! ## Bounds
//!
//! The work is linear in the bytes. The recursion is one level per message
//! inside a message and stops at [`MAX_DECODE_DEPTH`], because the bytes are
//! the sender's and a run of nested length prefixes would otherwise choose how
//! deep this library's stack goes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::proto_parse::{Label, ScalarKind, MAX_FIELD_NUMBER};
use crate::proto_schema::{FieldKind, Linker, MapValueKind, ProtoDiagnostic, ProtoFile};

/// How many messages deep the reader walks: a message inside a message is one
/// level. The writer's values may nest about thirty messages
/// ([`crate::proto_encode::MAX_VALUES_DEPTH`] counts an array or a map as a
/// level too), so every message it can build reads back.
pub const MAX_DECODE_DEPTH: usize = 64;

/// One field as it occurs on the wire.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedField {
    /// The field number.
    pub number: u64,
    /// The field's name as the schema writes it, or `None` for a field the
    /// schema does not know. A map entry's two fields are `key` and `value`.
    pub name: Option<String>,
    /// The field's type as the schema writes it: a scalar keyword (`sint32`), a
    /// message's or an enum's full name, or `map<K, V>` for an entry of a map
    /// field. `None` for a field the schema does not know.
    pub ty: Option<String>,
    /// The first byte of the field: its tag, or for an element of a packed run
    /// the element's first byte. Offsets count from the start of the bytes the
    /// reader was handed.
    pub start: usize,
    /// One past the last byte.
    pub end: usize,
    /// The value.
    pub value: Value,
}

/// What a field holds, as its type reads it.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `int32`, `int64`, `sint32`, `sint64`, `sfixed32` and `sfixed64`.
    Signed(i64),
    /// `uint32`, `uint64`, `fixed32` and `fixed64`.
    Unsigned(u64),
    /// `float`.
    Float(f32),
    /// `double`.
    Double(f64),
    /// `bool`.
    Bool(bool),
    /// `string`.
    Text(String),
    /// `bytes`.
    Bytes(Vec<u8>),
    /// An enum value: its number, and the name the enum gives that number.
    Enum {
        /// The value on the wire, read as an `int32`.
        number: i32,
        /// The enum's name for it, if it has one.
        name: Option<String>,
    },
    /// A message, a map entry included: its fields, on [`DecodedField`]'s rules.
    Message(Vec<DecodedField>),
    /// A field the schema does not know, as its wire type carries it.
    Unknown(Unknown),
}

/// The raw value of a field the schema does not know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unknown {
    /// Wire type 0.
    Varint(u64),
    /// Wire type 1, read little-endian.
    Fixed64(u64),
    /// Wire type 2: the bytes the length covers.
    Len(Vec<u8>),
    /// Wire type 5, read little-endian.
    Fixed32(u32),
}

impl Unknown {
    /// The wire type's name, in the words the schema-less walk uses.
    pub fn wire_type(&self) -> &'static str {
        match self {
            Self::Varint(_) => "varint",
            Self::Fixed64(_) => "i64",
            Self::Len(_) => "len",
            Self::Fixed32(_) => "i32",
        }
    }

    /// Every word [`Self::wire_type`] can give, one per variant: the vocabulary
    /// a document declares for the key it writes the word under.
    pub fn wire_type_names() -> Vec<&'static str> {
        [
            Self::Varint(0),
            Self::Fixed64(0),
            Self::Len(Vec::new()),
            Self::Fixed32(0),
        ]
        .iter()
        .map(Self::wire_type)
        .collect()
    }
}

/// Why bytes are not a message of the schema, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireError {
    /// The byte the reader stopped at, counted from the start of the bytes it
    /// was handed.
    pub offset: usize,
    /// The full name of the schema field being read (`pkg.Pose.label`), when
    /// the problem is inside one the schema knows.
    pub field: Option<String>,
    /// What is wrong, in a sentence.
    pub reason: String,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.field {
            Some(field) => write!(f, "byte {} ({field}): {}", self.offset, self.reason),
            None => write!(f, "byte {}: {}", self.offset, self.reason),
        }
    }
}

/// Why a decoding could not be made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The schema, or an argument about it, was refused: the diagnostic
    /// [`crate::proto_encode`] gives for the same schema.
    Schema(ProtoDiagnostic),
    /// The schema is sound and the bytes are not a message of it.
    Wire(WireError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(d) => write!(f, "{d}"),
            Self::Wire(w) => write!(f, "{w}"),
        }
    }
}

/// A schema read and its root message found: what reading any number of
/// messages of one type needs, built once.
pub struct LinkedSchema<'f, 'a> {
    linker: Linker<'f, 'a>,
    root: usize,
}

impl<'f, 'a> LinkedSchema<'f, 'a> {
    /// Read `files` and find `root_message` in them, by full name including the
    /// package, looked up from the file `root_file` indexes.
    ///
    /// # Errors
    ///
    /// The diagnostic [`crate::proto_encode::encode_message`] gives for the same
    /// schema and name.
    pub fn link(
        files: &'f [ProtoFile<'a>],
        root_file: usize,
        root_message: &str,
    ) -> Result<Self, ProtoDiagnostic> {
        let linker = Linker::read(files, root_file)?;
        let root = linker.root_message(root_message, root_file)?;
        Ok(Self { linker, root })
    }

    /// The full name of the root message.
    pub fn message(&self) -> &str {
        &self.linker.msgs[self.root].full_name
    }

    /// Read `bytes` as one root message.
    ///
    /// # Errors
    ///
    /// A [`WireError`] for the first problem found; see the module
    /// documentation.
    pub fn decode(&self, bytes: &[u8]) -> Result<Vec<DecodedField>, WireError> {
        Reader {
            schema: &self.linker,
        }
        .message(Owner::Message(self.root), bytes, 0, 0)
    }
}

/// Read `bytes` as the message `root_message` of the schema in `files`.
///
/// # Errors
///
/// A [`DecodeError`] for the first problem found: the schema's, then the
/// bytes'.
pub fn decode_message(
    root_message: &str,
    files: &[ProtoFile<'_>],
    root_file: usize,
    bytes: &[u8],
) -> Result<Vec<DecodedField>, DecodeError> {
    let schema = LinkedSchema::link(files, root_file, root_message).map_err(DecodeError::Schema)?;
    schema.decode(bytes).map_err(DecodeError::Wire)
}

// ---- the wire ------------------------------------------------------------

const WIRE_VARINT: u64 = 0;
const WIRE_I64: u64 = 1;
const WIRE_LEN: u64 = 2;
const WIRE_I32: u64 = 5;

/// One value as the wire carries it, before its type reads it.
#[derive(Clone, Copy)]
enum Raw {
    Varint(u64),
    Fixed64(u64),
    /// The covered bytes, as a range of the message being read.
    Len(usize, usize),
    Fixed32(u32),
}

impl Raw {
    const fn wire_type(self) -> u64 {
        match self {
            Self::Varint(_) => WIRE_VARINT,
            Self::Fixed64(_) => WIRE_I64,
            Self::Len(..) => WIRE_LEN,
            Self::Fixed32(_) => WIRE_I32,
        }
    }
}

/// A problem at `offset` of the message being read, before the field is known.
fn wire_error(offset: usize, reason: impl Into<String>) -> WireError {
    WireError {
        offset,
        field: None,
        reason: reason.into(),
    }
}

/// One base-128 varint at `*at`, advancing it.
fn varint(bytes: &[u8], at: &mut usize, base: usize, what: &str) -> Result<u64, WireError> {
    let start = *at;
    let mut value = 0u64;
    for i in 0..10 {
        let Some(&byte) = bytes.get(*at) else {
            return Err(wire_error(
                base + start,
                format!("the bytes end inside {what}"),
            ));
        };
        *at += 1;
        // The tenth byte may carry only the one bit left of a u64.
        if i == 9 && byte > 1 {
            return Err(wire_error(
                base + start,
                format!("{what} does not fit 64 bits"),
            ));
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(wire_error(
        base + start,
        format!("{what} is longer than ten bytes"),
    ))
}

/// `width` bytes at `*at`, little-endian, advancing it.
fn fixed(bytes: &[u8], at: &mut usize, width: usize, base: usize) -> Result<u64, WireError> {
    let start = *at;
    let Some(raw) = start
        .checked_add(width)
        .and_then(|end| bytes.get(start..end))
    else {
        return Err(wire_error(
            base + start,
            format!(
                "the bytes end inside a {width}-byte value ({} left)",
                bytes.len() - start
            ),
        ));
    };
    *at = start + width;
    Ok(raw
        .iter()
        .rev()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

/// The value after a tag of wire type `wire`, at `*at`, advancing it.
fn raw_value(bytes: &[u8], at: &mut usize, wire: u64, base: usize) -> Result<Raw, WireError> {
    match wire {
        WIRE_VARINT => varint(bytes, at, base, "a varint").map(Raw::Varint),
        WIRE_I64 => fixed(bytes, at, 8, base).map(Raw::Fixed64),
        WIRE_I32 => fixed(bytes, at, 4, base).map(|v| Raw::Fixed32(v as u32)),
        WIRE_LEN => {
            let length_at = *at;
            let len = varint(bytes, at, base, "a length")?;
            let left = bytes.len() - *at;
            match usize::try_from(len) {
                Ok(len) if len <= left => {
                    let start = *at;
                    *at += len;
                    Ok(Raw::Len(start, start + len))
                }
                _ => Err(wire_error(
                    base + length_at,
                    format!(
                        "a length of {len} byte(s) runs past the end of the message ({left} left)"
                    ),
                )),
            }
        }
        3 | 4 => Err(wire_error(
            base + *at,
            format!(
                "wire type {wire} is a group marker: groups are written with the deprecated \
                 group markers, which this reader does not walk"
            ),
        )),
        _ => Err(wire_error(
            base + *at,
            format!("wire type {wire} is not a wire type"),
        )),
    }
}

/// The wire type a value of this scalar kind is written with, alone.
fn scalar_wire(kind: ScalarKind) -> u64 {
    match kind {
        ScalarKind::Int32
        | ScalarKind::Int64
        | ScalarKind::Uint32
        | ScalarKind::Uint64
        | ScalarKind::Sint32
        | ScalarKind::Sint64
        | ScalarKind::Bool => WIRE_VARINT,
        ScalarKind::Fixed64 | ScalarKind::Sfixed64 | ScalarKind::Double => WIRE_I64,
        ScalarKind::Fixed32 | ScalarKind::Sfixed32 | ScalarKind::Float => WIRE_I32,
        ScalarKind::String | ScalarKind::Bytes => WIRE_LEN,
    }
}

/// A scalar read from a varint or a fixed-width value already known to be of
/// the kind's wire type.
fn scalar_number(kind: ScalarKind, v: u64) -> Value {
    match kind {
        // An `int32` is written sign-extended and read back truncated, as
        // protobuf's own parsers read it.
        ScalarKind::Int32 | ScalarKind::Sfixed32 => Value::Signed(i64::from(v as u32 as i32)),
        ScalarKind::Int64 | ScalarKind::Sfixed64 => Value::Signed(v as i64),
        ScalarKind::Uint32 | ScalarKind::Fixed32 => Value::Unsigned(u64::from(v as u32)),
        ScalarKind::Uint64 | ScalarKind::Fixed64 => Value::Unsigned(v),
        ScalarKind::Sint32 => {
            let n = v as u32;
            Value::Signed(i64::from((n >> 1) as i32 ^ -((n & 1) as i32)))
        }
        ScalarKind::Sint64 => Value::Signed((v >> 1) as i64 ^ -((v & 1) as i64)),
        ScalarKind::Bool => Value::Bool(v != 0),
        ScalarKind::Float => Value::Float(f32::from_bits(v as u32)),
        ScalarKind::Double => Value::Double(f64::from_bits(v)),
        // Never reached: a string or bytes is a length-delimited value, which
        // `Reader::field` reads before it asks for a number.
        ScalarKind::String | ScalarKind::Bytes => Value::Bytes(Vec::new()),
    }
}

// ---- the reader ----------------------------------------------------------

/// What a field holds, as far as reading it goes: [`FieldKind`] with a map's
/// value folded into the same three cases.
#[derive(Clone, Copy)]
enum Holds {
    Scalar(ScalarKind),
    Enum(usize),
    Message(usize),
    Map { key: ScalarKind, value: MapHolds },
    Group,
}

/// A map's value: a scalar, an enum or a message.
#[derive(Clone, Copy)]
enum MapHolds {
    Scalar(ScalarKind),
    Enum(usize),
    Message(usize),
}

impl From<MapHolds> for Holds {
    fn from(h: MapHolds) -> Self {
        match h {
            MapHolds::Scalar(k) => Self::Scalar(k),
            MapHolds::Enum(e) => Self::Enum(e),
            MapHolds::Message(m) => Self::Message(m),
        }
    }
}

/// One field of the message being read, as the reader needs it.
struct Spec<'s> {
    name: &'s str,
    holds: Holds,
    repeated: bool,
    /// The full name a problem inside the field is blamed on.
    full_name: String,
}

/// The message whose fields are being read: a message of the schema, or the
/// entry message of a map field, which the schema does not hold as a message.
#[derive(Clone, Copy)]
enum Owner<'s> {
    Message(usize),
    Entry {
        key: ScalarKind,
        value: MapHolds,
        /// The map field's full name.
        field: &'s str,
    },
}

struct Reader<'s, 'f, 'a> {
    schema: &'s Linker<'f, 'a>,
}

impl<'s> Reader<'s, '_, '_> {
    /// The type of a value as the schema writes it.
    fn type_name(&self, holds: Holds) -> String {
        match holds {
            Holds::Scalar(k) => String::from(k.keyword()),
            Holds::Enum(e) => self.schema.enums[e].full_name.clone(),
            Holds::Message(m) => self.schema.msgs[m].full_name.clone(),
            Holds::Map { key, value } => {
                format!("map<{}, {}>", key.keyword(), self.type_name(value.into()))
            }
            Holds::Group => String::from("group"),
        }
    }

    /// The field numbered `number` of `owner`, if it has one.
    fn spec(&self, owner: Owner<'s>, number: u64) -> Option<Spec<'s>> {
        match owner {
            Owner::Message(m) => {
                let msg = &self.schema.msgs[m];
                let f = msg.fields.iter().find(|f| f.number == number)?;
                let holds = match f.kind {
                    FieldKind::Scalar(k) => Holds::Scalar(k),
                    FieldKind::Enum(e) => Holds::Enum(e),
                    FieldKind::Message(m) => Holds::Message(m),
                    FieldKind::Group => Holds::Group,
                    FieldKind::Map { key, value } => Holds::Map {
                        key,
                        value: match value {
                            MapValueKind::Scalar(k) => MapHolds::Scalar(k),
                            MapValueKind::Enum(e) => MapHolds::Enum(e),
                            MapValueKind::Message(m) => MapHolds::Message(m),
                        },
                    },
                };
                Some(Spec {
                    name: &f.name,
                    holds,
                    repeated: f.label == Label::Repeated,
                    full_name: format!("{}.{}", msg.full_name, f.name),
                })
            }
            Owner::Entry { key, value, field } => match number {
                1 => Some(Spec {
                    name: "key",
                    holds: Holds::Scalar(key),
                    repeated: false,
                    full_name: format!("{field}.key"),
                }),
                2 => Some(Spec {
                    name: "value",
                    holds: value.into(),
                    repeated: false,
                    full_name: format!("{field}.value"),
                }),
                _ => None,
            },
        }
    }

    /// The fields of one message of `owner`'s type, in `bytes`, which sit at
    /// `base` in the bytes the reader was handed.
    fn message(
        &self,
        owner: Owner<'s>,
        bytes: &[u8],
        base: usize,
        depth: usize,
    ) -> Result<Vec<DecodedField>, WireError> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < bytes.len() {
            let start = at;
            let tag = varint(bytes, &mut at, base, "a tag")?;
            let number = tag >> 3;
            let wire = tag & 0x07;
            if number == 0 {
                return Err(wire_error(
                    base + start,
                    "field number 0 is no field: a tag must name a field from 1",
                ));
            }
            if number > MAX_FIELD_NUMBER {
                return Err(wire_error(
                    base + start,
                    format!("field number {number} is above the largest, 2^29 - 1"),
                ));
            }
            let raw = raw_value(bytes, &mut at, wire, base)?;
            let span = (base + start, base + at);
            match self.spec(owner, number) {
                Some(spec) => self.field(&spec, number, raw, bytes, base, span, depth, &mut out)?,
                None => out.push(unknown(number, raw, bytes, span)),
            }
        }
        Ok(out)
    }

    /// One occurrence of a field the schema knows: one entry, or one per element
    /// of a packed run, or an unknown entry when the wire type is not one the
    /// field's type is written with.
    #[allow(clippy::too_many_arguments)]
    fn field(
        &self,
        spec: &Spec<'s>,
        number: u64,
        raw: Raw,
        bytes: &[u8],
        base: usize,
        span: (usize, usize),
        depth: usize,
        out: &mut Vec<DecodedField>,
    ) -> Result<(), WireError> {
        let blame = |mut e: WireError| {
            e.field.get_or_insert_with(|| spec.full_name.clone());
            e
        };
        let entry = |value: Value, span: (usize, usize)| DecodedField {
            number,
            name: Some(String::from(spec.name)),
            ty: Some(self.type_name(spec.holds)),
            start: span.0,
            end: span.1,
            value,
        };
        match (spec.holds, raw) {
            (Holds::Scalar(ScalarKind::String), Raw::Len(a, b)) => {
                let text = core::str::from_utf8(&bytes[a..b]).map_err(|e| WireError {
                    offset: base + a + e.valid_up_to(),
                    field: Some(spec.full_name.clone()),
                    reason: String::from("a `string` field holds bytes that are not UTF-8"),
                })?;
                out.push(entry(Value::Text(String::from(text)), span));
            }
            (Holds::Scalar(ScalarKind::Bytes), Raw::Len(a, b)) => {
                out.push(entry(Value::Bytes(bytes[a..b].to_vec()), span));
            }
            (Holds::Scalar(kind), Raw::Len(a, b))
                if spec.repeated && scalar_wire(kind) != WIRE_LEN =>
            {
                let run = &bytes[a..b];
                let mut at = 0usize;
                while at < run.len() {
                    let element = at;
                    let v = match scalar_wire(kind) {
                        WIRE_VARINT => varint(run, &mut at, base + a, "a packed varint"),
                        WIRE_I64 => fixed(run, &mut at, 8, base + a),
                        _ => fixed(run, &mut at, 4, base + a),
                    }
                    .map_err(blame)?;
                    out.push(entry(
                        scalar_number(kind, v),
                        (base + a + element, base + a + at),
                    ));
                }
            }
            (Holds::Enum(e), Raw::Len(a, b)) if spec.repeated => {
                let run = &bytes[a..b];
                let mut at = 0usize;
                while at < run.len() {
                    let element = at;
                    let v = varint(run, &mut at, base + a, "a packed varint").map_err(blame)?;
                    out.push(entry(
                        self.enum_value(e, v),
                        (base + a + element, base + a + at),
                    ));
                }
            }
            (Holds::Scalar(kind), raw) if raw.wire_type() == scalar_wire(kind) => {
                let v = match raw {
                    Raw::Varint(v) | Raw::Fixed64(v) => v,
                    Raw::Fixed32(v) => u64::from(v),
                    // A length-delimited scalar is a string or bytes, read above.
                    Raw::Len(..) => 0,
                };
                out.push(entry(scalar_number(kind, v), span));
            }
            (Holds::Enum(e), Raw::Varint(v)) => out.push(entry(self.enum_value(e, v), span)),
            (Holds::Message(m), Raw::Len(a, b)) => {
                let fields = self
                    .nested(Owner::Message(m), &bytes[a..b], base + a, depth)
                    .map_err(blame)?;
                out.push(entry(Value::Message(fields), span));
            }
            (Holds::Map { key, value }, Raw::Len(a, b)) => {
                let owner = Owner::Entry {
                    key,
                    value,
                    field: &spec.full_name,
                };
                let fields = self
                    .nested(owner, &bytes[a..b], base + a, depth)
                    .map_err(blame)?;
                out.push(entry(Value::Message(fields), span));
            }
            // A known number under a wire type its type is never written with:
            // a protobuf parser files it with the unknown fields, and so does
            // this listing.
            _ => out.push(unknown(number, raw, bytes, span)),
        }
        Ok(())
    }

    /// One level down, or the refusal that the bytes nest too deep.
    fn nested(
        &self,
        owner: Owner<'s>,
        bytes: &[u8],
        base: usize,
        depth: usize,
    ) -> Result<Vec<DecodedField>, WireError> {
        if depth + 1 >= MAX_DECODE_DEPTH {
            return Err(wire_error(
                base,
                format!("messages nest deeper than {MAX_DECODE_DEPTH} levels"),
            ));
        }
        self.message(owner, bytes, base, depth + 1)
    }

    fn enum_value(&self, e: usize, v: u64) -> Value {
        let number = v as u32 as i32;
        let name = self.schema.enums[e]
            .values
            .iter()
            .find(|(_, n)| *n == i128::from(number))
            .map(|(name, _)| name.clone());
        Value::Enum { number, name }
    }
}

/// The entry of a field the schema does not know.
fn unknown(number: u64, raw: Raw, bytes: &[u8], span: (usize, usize)) -> DecodedField {
    DecodedField {
        number,
        name: None,
        ty: None,
        start: span.0,
        end: span.1,
        value: Value::Unknown(match raw {
            Raw::Varint(v) => Unknown::Varint(v),
            Raw::Fixed64(v) => Unknown::Fixed64(v),
            Raw::Fixed32(v) => Unknown::Fixed32(v),
            Raw::Len(a, b) => Unknown::Len(bytes[a..b].to_vec()),
        }),
    }
}

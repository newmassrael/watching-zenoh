// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Protobuf wire bytes READ by the types a `.proto` schema gives them: the
//! reading half of the capture crate's writer (`proto_encode`).
//!
//! ## What this is for
//!
//! The wire format carries a field's number and one of four wire types, and
//! nothing else. The schema-less walk (the capture crate's `Protobuf` format)
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
//! The schema is refused as the writer refuses it, with the same
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

use crate::proto_parse::{FieldOption, Label, ScalarKind, MAX_FIELD_NUMBER};
use crate::proto_schema::{
    EnumInfo, FieldKind, FileOptions, Linker, MapValueKind, Msg, ProtoDiagnostic, ProtoFile,
};

/// How many messages deep the reader walks: a message inside a message is one
/// level. The writer's values may nest about thirty messages
/// (the writer's `MAX_VALUES_DEPTH` counts an array or a map as a
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
    /// the writer gives for the same schema.
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
    /// The diagnostic the writer's `encode_message` gives for the same
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
            msgs: &self.linker.msgs,
            enums: &self.linker.enums,
        }
        .message(Owner::Message(self.root), bytes, 0, 0)
    }
}

/// A schema read from EVERY file given and held without borrowing them: what a
/// declaration text that carries `.proto` files keeps for as long as the map it
/// built is consulted (the capture crate's `FormatMap`).
///
/// [`LinkedSchema`] borrows its files and names one root, which is right for a
/// door that reads one frame. A map is consulted for every message of a capture
/// and names a message per rule, so it reads the files ONCE, into this, and each
/// rule holds the [`SchemaMessage`] it names. Every file is read, as
/// `proto_message_list` reads them, because a rule may name a message of any
/// of them; a problem in any file is therefore a problem of the set.
pub struct SchemaSet {
    msgs: Vec<Msg>,
    enums: Vec<EnumInfo>,
    /// Each file's own `option` statements, by the index a message's `file`
    /// holds: what a writer that narrows by the nanopb options merges first.
    file_options: Vec<Vec<FieldOption>>,
}

/// One message of a [`SchemaSet`], as [`SchemaSet::message`] found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaMessage(usize);

impl fmt::Debug for SchemaSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaSet")
            .field("messages", &self.msgs.len())
            .field("enums", &self.enums.len())
            .finish()
    }
}

impl FileOptions for SchemaSet {
    fn options_of_file(&self, file: usize) -> &[FieldOption] {
        self.file_options.get(file).map_or(&[][..], Vec::as_slice)
    }
}

impl SchemaSet {
    /// Read every file of `files`, each with what it imports.
    ///
    /// # Errors
    ///
    /// The first problem found, in the order the files are listed, with the
    /// diagnostic the writer gives for the same file.
    pub fn read(files: &[ProtoFile<'_>]) -> Result<Self, ProtoDiagnostic> {
        let (msgs, enums, file_options) = Linker::read_all(files)?.into_types();
        Ok(Self {
            msgs,
            enums,
            file_options,
        })
    }

    /// The message whose full name, package included, is `full_name`.
    ///
    /// # Errors
    ///
    /// A sentence saying the name is an enum's, or that no file of the set
    /// defines it.
    pub fn message(&self, full_name: &str) -> Result<SchemaMessage, String> {
        if let Some(at) = self.msgs.iter().position(|m| m.full_name == full_name) {
            return Ok(SchemaMessage(at));
        }
        if self.enums.iter().any(|e| e.full_name == full_name) {
            return Err(format!("`{full_name}` is an enum, not a message"));
        }
        Err(format!(
            "no declared schema file defines the message `{full_name}` (the name is the full \
             name, package included)"
        ))
    }

    /// The full name of `message`.
    pub fn message_name(&self, message: SchemaMessage) -> &str {
        &self.msgs[message.0].full_name
    }

    /// The linked message `message` names: its fields, their types and labels,
    /// for a reader that picks fields out of a decoding by number.
    pub fn linked(&self, message: SchemaMessage) -> &Msg {
        &self.msgs[message.0]
    }

    /// The linked message at `index`, as a field of message type names it
    /// ([`FieldKind::Message`]); `None` for an index the set has not.
    pub fn linked_at(&self, index: usize) -> Option<&Msg> {
        self.msgs.get(index)
    }

    /// The enum at `index`, as a field of enum type names it
    /// ([`FieldKind::Enum`]): its values' names and numbers, and whether it is
    /// closed; `None` for an index the set has not.
    pub fn enum_at(&self, index: usize) -> Option<&EnumInfo> {
        self.enums.get(index)
    }

    /// Read `bytes` as one `message`, on [`LinkedSchema::decode`]'s rules.
    ///
    /// # Errors
    ///
    /// A [`WireError`] for the first problem found; see the module
    /// documentation.
    pub fn decode(
        &self,
        message: SchemaMessage,
        bytes: &[u8],
    ) -> Result<Vec<DecodedField>, WireError> {
        Reader {
            msgs: &self.msgs,
            enums: &self.enums,
        }
        .message(Owner::Message(message.0), bytes, 0, 0)
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
fn scalar_item(kind: ScalarKind, v: u64) -> Item<'static> {
    match kind {
        // An `int32` is written sign-extended and read back truncated, as
        // protobuf's own parsers read it.
        ScalarKind::Int32 | ScalarKind::Sfixed32 => Item::Signed(i64::from(v as u32 as i32)),
        ScalarKind::Int64 | ScalarKind::Sfixed64 => Item::Signed(v as i64),
        ScalarKind::Uint32 | ScalarKind::Fixed32 => Item::Unsigned(u64::from(v as u32)),
        ScalarKind::Uint64 | ScalarKind::Fixed64 => Item::Unsigned(v),
        ScalarKind::Sint32 => {
            let n = v as u32;
            Item::Signed(i64::from((n >> 1) as i32 ^ -((n & 1) as i32)))
        }
        ScalarKind::Sint64 => Item::Signed((v >> 1) as i64 ^ -((v & 1) as i64)),
        ScalarKind::Bool => Item::Bool(v != 0),
        ScalarKind::Float => Item::Float(f32::from_bits(v as u32)),
        ScalarKind::Double => Item::Double(f64::from_bits(v)),
        // Never reached: a string or bytes is a length-delimited value, which
        // `Reader::field` reads before it asks for a number.
        ScalarKind::String | ScalarKind::Bytes => Item::Bytes(&[]),
    }
}

/// One value of a field the schema knows, as the walk reads it: [`Value`]'s scalars, borrowing a
/// string or bytes from the bytes read and naming an enum value by its number alone.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Item<'b> {
    Signed(i64),
    Unsigned(u64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Text(&'b str),
    Bytes(&'b [u8]),
    /// The value on the wire, read as an `int32`.
    Enum(i32),
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
    /// What the field's full name is made of before its own name: the message's full name, and,
    /// for a field of a map's entry, the map field's name. The full name is written only when a
    /// problem inside the field is reported.
    prefix: (&'s str, Option<&'s str>),
}

impl Spec<'_> {
    /// The full name a problem inside the field is blamed on.
    fn full_name(&self) -> String {
        match self.prefix {
            (message, None) => format!("{message}.{}", self.name),
            (message, Some(map)) => format!("{message}.{map}.{}", self.name),
        }
    }
}

/// The message whose fields are being read: a message of the schema, or the
/// entry message of a map field, which the schema does not hold as a message.
#[derive(Clone, Copy)]
enum Owner<'s> {
    Message(usize),
    Entry {
        key: ScalarKind,
        value: MapHolds,
        /// The full name of the message the map field is declared in.
        holder: &'s str,
        /// The map field's name.
        map: &'s str,
    },
}

/// What a walk of a message's wire meets, in the order the bytes hold it. The walk reads and
/// refuses the bytes the one way the module documentation states; what is kept of them is the
/// visitor's, so a listing and a reading of one field take the same walk.
trait Visit<'b> {
    /// A value of a field the schema knows, at `span`: one per occurrence, and one per element of
    /// a packed run.
    fn known(&mut self, number: u64, spec: &Spec<'_>, item: Item<'b>, span: (usize, usize));
    /// A field the schema does not know, or a known number under a wire type its type is never
    /// written with; `raw` indexes `bytes`, the message it was read in.
    fn unknown(&mut self, number: u64, raw: Raw, bytes: &'b [u8], span: (usize, usize));
    /// A message field, or a map's entry, begins: what follows until its [`Self::leave`] is in it.
    fn enter(&mut self, number: u64, spec: &Spec<'_>);
    /// The message field `enter` began was read whole, at `span`.
    fn leave(&mut self, number: u64, spec: &Spec<'_>, span: (usize, usize));
}

/// The reader borrows the schema's TYPE TABLES and nothing else: the messages
/// and the enums a link produced. That is what lets [`SchemaSet`] hold a schema
/// without borrowing the files it was read from.
struct Reader<'s> {
    msgs: &'s [Msg],
    enums: &'s [EnumInfo],
}

impl<'s> Reader<'s> {
    /// The type of a value as the schema writes it.
    fn type_name(&self, holds: Holds) -> String {
        match holds {
            Holds::Scalar(k) => String::from(k.keyword()),
            Holds::Enum(e) => self.enums[e].full_name.clone(),
            Holds::Message(m) => self.msgs[m].full_name.clone(),
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
                let msg = &self.msgs[m];
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
                    prefix: (&msg.full_name, None),
                })
            }
            Owner::Entry {
                key,
                value,
                holder,
                map,
            } => match number {
                1 => Some(Spec {
                    name: "key",
                    holds: Holds::Scalar(key),
                    repeated: false,
                    prefix: (holder, Some(map)),
                }),
                2 => Some(Spec {
                    name: "value",
                    holds: value.into(),
                    repeated: false,
                    prefix: (holder, Some(map)),
                }),
                _ => None,
            },
        }
    }

    /// The fields of one message of `owner`'s type, in `bytes`, which sit at `base` in the bytes
    /// the reader was handed, as a listing ([`DecodedField`]).
    fn message(
        &self,
        owner: Owner<'s>,
        bytes: &[u8],
        base: usize,
        depth: usize,
    ) -> Result<Vec<DecodedField>, WireError> {
        let mut listing = Listing {
            reader: self,
            open: alloc::vec![Vec::new()],
        };
        self.walk(owner, bytes, base, depth, &mut listing)?;
        Ok(listing.open.pop().unwrap_or_default())
    }

    /// Walk one message of `owner`'s type, in `bytes`, which sit at `base` in the bytes the
    /// reader was handed, telling `visit` what it meets.
    fn walk<'b, V: Visit<'b>>(
        &self,
        owner: Owner<'s>,
        bytes: &'b [u8],
        base: usize,
        depth: usize,
        visit: &mut V,
    ) -> Result<(), WireError> {
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
                Some(spec) => self.field(&spec, number, raw, bytes, base, span, depth, visit)?,
                None => visit.unknown(number, raw, bytes, span),
            }
        }
        Ok(())
    }

    /// One occurrence of a field the schema knows: one value, or one per element
    /// of a packed run, or an unknown field when the wire type is not one the
    /// field's type is written with.
    #[allow(clippy::too_many_arguments)]
    fn field<'b, V: Visit<'b>>(
        &self,
        spec: &Spec<'s>,
        number: u64,
        raw: Raw,
        bytes: &'b [u8],
        base: usize,
        span: (usize, usize),
        depth: usize,
        visit: &mut V,
    ) -> Result<(), WireError> {
        let blame = |mut e: WireError| {
            e.field.get_or_insert_with(|| spec.full_name());
            e
        };
        match (spec.holds, raw) {
            (Holds::Scalar(ScalarKind::String), Raw::Len(a, b)) => {
                let text = core::str::from_utf8(&bytes[a..b]).map_err(|e| WireError {
                    offset: base + a + e.valid_up_to(),
                    field: Some(spec.full_name()),
                    reason: String::from("a `string` field holds bytes that are not UTF-8"),
                })?;
                visit.known(number, spec, Item::Text(text), span);
            }
            (Holds::Scalar(ScalarKind::Bytes), Raw::Len(a, b)) => {
                visit.known(number, spec, Item::Bytes(&bytes[a..b]), span);
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
                    visit.known(
                        number,
                        spec,
                        scalar_item(kind, v),
                        (base + a + element, base + a + at),
                    );
                }
            }
            (Holds::Enum(_), Raw::Len(a, b)) if spec.repeated => {
                let run = &bytes[a..b];
                let mut at = 0usize;
                while at < run.len() {
                    let element = at;
                    let v = varint(run, &mut at, base + a, "a packed varint").map_err(blame)?;
                    visit.known(
                        number,
                        spec,
                        Item::Enum(v as u32 as i32),
                        (base + a + element, base + a + at),
                    );
                }
            }
            (Holds::Scalar(kind), raw) if raw.wire_type() == scalar_wire(kind) => {
                let v = match raw {
                    Raw::Varint(v) | Raw::Fixed64(v) => v,
                    Raw::Fixed32(v) => u64::from(v),
                    // A length-delimited scalar is a string or bytes, read above.
                    Raw::Len(..) => 0,
                };
                visit.known(number, spec, scalar_item(kind, v), span);
            }
            (Holds::Enum(_), Raw::Varint(v)) => {
                visit.known(number, spec, Item::Enum(v as u32 as i32), span);
            }
            (Holds::Message(m), Raw::Len(a, b)) => {
                visit.enter(number, spec);
                self.nested(Owner::Message(m), &bytes[a..b], base + a, depth, visit)
                    .map_err(blame)?;
                visit.leave(number, spec, span);
            }
            (Holds::Map { key, value }, Raw::Len(a, b)) => {
                // A map field is declared in a message, whose full name its prefix holds.
                let owner = Owner::Entry {
                    key,
                    value,
                    holder: spec.prefix.0,
                    map: spec.name,
                };
                visit.enter(number, spec);
                self.nested(owner, &bytes[a..b], base + a, depth, visit)
                    .map_err(blame)?;
                visit.leave(number, spec, span);
            }
            // A known number under a wire type its type is never written with:
            // a protobuf parser files it with the unknown fields, and so does
            // this reader.
            _ => visit.unknown(number, raw, bytes, span),
        }
        Ok(())
    }

    /// One level down, or the refusal that the bytes nest too deep.
    fn nested<'b, V: Visit<'b>>(
        &self,
        owner: Owner<'s>,
        bytes: &'b [u8],
        base: usize,
        depth: usize,
        visit: &mut V,
    ) -> Result<(), WireError> {
        if depth + 1 >= MAX_DECODE_DEPTH {
            return Err(wire_error(
                base,
                format!("messages nest deeper than {MAX_DECODE_DEPTH} levels"),
            ));
        }
        self.walk(owner, bytes, base, depth + 1, visit)
    }

    /// The value `item` of a field that holds `holds`, as a listing holds it.
    fn value_of(&self, holds: Holds, item: Item<'_>) -> Value {
        match item {
            Item::Signed(v) => Value::Signed(v),
            Item::Unsigned(v) => Value::Unsigned(v),
            Item::Float(v) => Value::Float(v),
            Item::Double(v) => Value::Double(v),
            Item::Bool(v) => Value::Bool(v),
            Item::Text(text) => Value::Text(String::from(text)),
            Item::Bytes(bytes) => Value::Bytes(bytes.to_vec()),
            Item::Enum(number) => {
                let name = match holds {
                    Holds::Enum(e) => self.enums[e]
                        .values
                        .iter()
                        .find(|(_, n)| *n == i128::from(number))
                        .map(|(name, _)| name.clone()),
                    _ => None,
                };
                Value::Enum { number, name }
            }
        }
    }
}

/// The walk that lists every field ([`DecodedField`]): the listing of each message the walk is
/// inside, the outermost first.
struct Listing<'r, 's> {
    reader: &'r Reader<'s>,
    open: Vec<Vec<DecodedField>>,
}

impl Listing<'_, '_> {
    fn push(&mut self, field: DecodedField) {
        if let Some(listing) = self.open.last_mut() {
            listing.push(field);
        }
    }
}

impl<'b> Visit<'b> for Listing<'_, '_> {
    fn known(&mut self, number: u64, spec: &Spec<'_>, item: Item<'b>, span: (usize, usize)) {
        let field = DecodedField {
            number,
            name: Some(String::from(spec.name)),
            ty: Some(self.reader.type_name(spec.holds)),
            start: span.0,
            end: span.1,
            value: self.reader.value_of(spec.holds, item),
        };
        self.push(field);
    }

    fn unknown(&mut self, number: u64, raw: Raw, bytes: &'b [u8], span: (usize, usize)) {
        self.push(unknown(number, raw, bytes, span));
    }

    fn enter(&mut self, _number: u64, _spec: &Spec<'_>) {
        self.open.push(Vec::new());
    }

    fn leave(&mut self, number: u64, spec: &Spec<'_>, span: (usize, usize)) {
        let fields = self.open.pop().unwrap_or_default();
        let field = DecodedField {
            number,
            name: Some(String::from(spec.name)),
            ty: Some(self.reader.type_name(spec.holds)),
            start: span.0,
            end: span.1,
            value: Value::Message(fields),
        };
        self.push(field);
    }
}

/// Where one field path of a message stands in its bytes, as a protobuf parser reads it: the last
/// occurrence of the field wins, and the occurrences of a message field are one message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum AtPath<'b> {
    /// The field is there, with this value.
    Found(Item<'b>),
    /// Every message along the path is there, and the field is not.
    LeafMissing,
    /// A message field along the path is not there.
    HolderMissing,
}

/// The walk that reads one field path ([`SchemaSet::read_path`]) and keeps nothing else.
struct PathRead<'p, 'b> {
    /// The field numbers along the path, the outermost first.
    path: &'p [u64],
    /// How many messages deep the walk is.
    depth: usize,
    /// How many of the messages the walk is inside are the path's holders, from the outermost.
    matched: usize,
    /// Whether every holder of the path was met.
    holders_met: bool,
    found: Option<Item<'b>>,
}

impl<'b> Visit<'b> for PathRead<'_, 'b> {
    fn known(&mut self, number: u64, _spec: &Spec<'_>, item: Item<'b>, _span: (usize, usize)) {
        if self.matched == self.depth
            && self.depth + 1 == self.path.len()
            && self.path.get(self.depth) == Some(&number)
        {
            self.found = Some(item);
        }
    }

    fn unknown(&mut self, _number: u64, _raw: Raw, _bytes: &'b [u8], _span: (usize, usize)) {}

    fn enter(&mut self, number: u64, _spec: &Spec<'_>) {
        if self.matched == self.depth
            && self.depth + 1 < self.path.len()
            && self.path.get(self.depth) == Some(&number)
        {
            self.matched = self.depth + 1;
            if self.matched + 1 == self.path.len() {
                self.holders_met = true;
            }
        }
        self.depth += 1;
    }

    fn leave(&mut self, _number: u64, _spec: &Spec<'_>, _span: (usize, usize)) {
        self.depth = self.depth.saturating_sub(1);
        self.matched = self.matched.min(self.depth);
    }
}

impl SchemaSet {
    /// The value at the field path `numbers` (the outermost field's number first) of `bytes` read
    /// as `message`, as [`AtPath`] says a parser reads it. The bytes are read and refused as
    /// [`Self::decode`] reads and refuses them, and nothing is allocated unless they are refused:
    /// a string or bytes value borrows `bytes`.
    ///
    /// # Errors
    ///
    /// The [`WireError`] [`Self::decode`] gives for the same bytes.
    pub(crate) fn read_path<'b>(
        &self,
        message: SchemaMessage,
        bytes: &'b [u8],
        numbers: &[u64],
    ) -> Result<AtPath<'b>, WireError> {
        let mut read = PathRead {
            path: numbers,
            depth: 0,
            matched: 0,
            // The message read is the one holder of a field of its own.
            holders_met: numbers.len() <= 1,
            found: None,
        };
        Reader {
            msgs: &self.msgs,
            enums: &self.enums,
        }
        .walk(Owner::Message(message.0), bytes, 0, 0, &mut read)?;
        Ok(match read.found {
            Some(item) => AtPath::Found(item),
            None if read.holders_met => AtPath::LeafMissing,
            None => AtPath::HolderMissing,
        })
    }
}

/// What a walk of a message's bytes tells a reader that keeps values of its own
/// ([`SchemaSet::walk_fields`]), in the order the bytes hold them.
pub(crate) trait FieldEvents<'b> {
    /// A value of field `number`, which the schema knows: one per occurrence, and one per element
    /// of a packed run.
    fn value(&mut self, number: u64, item: Item<'b>);
    /// Bytes a reader keeps as the wire wrote them, at `span` of the bytes walked: a field the
    /// schema does not know, a known number under a wire type its type is never written with, a
    /// group, and each entry of a map, whole.
    fn kept(&mut self, span: (usize, usize));
    /// A message field `number` begins: the values that follow until [`Self::leave`] are its.
    fn enter(&mut self, number: u64);
    /// The message field [`Self::enter`] began was read whole.
    fn leave(&mut self);
}

/// The walk as [`FieldEvents`] see it: a map's entries are kept whole, and nothing inside one is
/// told.
struct Events<'e, F> {
    events: &'e mut F,
    /// How many map entries the walk is inside.
    in_map: usize,
}

impl<'b, F: FieldEvents<'b>> Visit<'b> for Events<'_, F> {
    fn known(&mut self, number: u64, _spec: &Spec<'_>, item: Item<'b>, _span: (usize, usize)) {
        if self.in_map == 0 {
            self.events.value(number, item);
        }
    }

    fn unknown(&mut self, _number: u64, _raw: Raw, _bytes: &'b [u8], span: (usize, usize)) {
        if self.in_map == 0 {
            self.events.kept(span);
        }
    }

    fn enter(&mut self, number: u64, spec: &Spec<'_>) {
        if matches!(spec.holds, Holds::Map { .. }) || self.in_map > 0 {
            self.in_map += 1;
        } else {
            self.events.enter(number);
        }
    }

    fn leave(&mut self, _number: u64, _spec: &Spec<'_>, span: (usize, usize)) {
        match self.in_map {
            0 => self.events.leave(),
            1 => {
                self.in_map = 0;
                self.events.kept(span);
            }
            _ => self.in_map -= 1,
        }
    }
}

impl SchemaSet {
    /// Walk `bytes` read as `message`, telling `events` what they hold. The bytes are read and
    /// refused as [`Self::decode`] reads and refuses them, and the walk allocates nothing unless
    /// they are refused; what is kept of them is `events`'s.
    ///
    /// # Errors
    ///
    /// The [`WireError`] [`Self::decode`] gives for the same bytes. What `events` was told before
    /// it is all it is told.
    pub(crate) fn walk_fields<'b, F: FieldEvents<'b>>(
        &self,
        message: SchemaMessage,
        bytes: &'b [u8],
        events: &mut F,
    ) -> Result<(), WireError> {
        let mut walk = Events { events, in_map: 0 };
        Reader {
            msgs: &self.msgs,
            enums: &self.enums,
        }
        .walk(Owner::Message(message.0), bytes, 0, 0, &mut walk)
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

// The reading of one field path against the listing it must agree with: every payload is read
// both ways, and the field the old lookup over the listing finds is the one the walk finds. The
// schema and every byte are synthetic, laid by hand.
#[cfg(test)]
mod read_path_tests {
    use alloc::vec::Vec;

    use super::{AtPath, DecodedField, Item, SchemaSet, Value};
    use crate::proto_schema::ProtoFile;

    const SCHEMA: &str = r#"
syntax = "proto3";
package syn.path;
message Leaf {
  sint32 tilt = 1;
  string tag = 2;
}
message Holder {
  Leaf leaf = 1;
  uint32 bay = 2;
}
message Root {
  Holder holder = 1;
  optional uint32 serial = 2;
  map<string, uint32> table = 3;
  repeated uint32 many = 4;
}
"#;

    /// Where a path stands, as either reading tells it, the found value compared as the listing
    /// holds it.
    #[derive(Debug, PartialEq)]
    enum Seen {
        Refused,
        Found(Value),
        LeafMissing,
        HolderMissing,
    }

    /// The lookup a listing was read by before the walk: the last occurrence of the field, and the
    /// occurrences of a message field read as one.
    fn listed(fields: &[DecodedField], numbers: &[u64]) -> Seen {
        let Some((&first, rest)) = numbers.split_first() else {
            return Seen::LeafMissing;
        };
        if rest.is_empty() {
            return fields
                .iter()
                .rev()
                .find(|f| f.number == first && !matches!(f.value, Value::Unknown(_)))
                .map_or(Seen::LeafMissing, |f| Seen::Found(f.value.clone()));
        }
        let mut found = None;
        let mut leaf_missing = false;
        for f in fields.iter().filter(|f| f.number == first) {
            if let Value::Message(inner) = &f.value {
                match listed(inner, rest) {
                    Seen::Found(value) => found = Some(value),
                    Seen::LeafMissing => leaf_missing = true,
                    Seen::HolderMissing | Seen::Refused => {}
                }
            }
        }
        match found {
            Some(value) => Seen::Found(value),
            None if leaf_missing => Seen::LeafMissing,
            None => Seen::HolderMissing,
        }
    }

    /// A value the walk read, as the listing holds it (an enum's name aside, which no path here
    /// reads).
    fn as_listed(item: Item<'_>) -> Value {
        match item {
            Item::Signed(v) => Value::Signed(v),
            Item::Unsigned(v) => Value::Unsigned(v),
            Item::Float(v) => Value::Float(v),
            Item::Double(v) => Value::Double(v),
            Item::Bool(v) => Value::Bool(v),
            Item::Text(text) => Value::Text(text.into()),
            Item::Bytes(bytes) => Value::Bytes(bytes.to_vec()),
            Item::Enum(number) => Value::Enum { number, name: None },
        }
    }

    fn walked(schema: &SchemaSet, bytes: &[u8], numbers: &[u64]) -> Seen {
        let root = schema.message("syn.path.Root").expect("the root");
        match schema.read_path(root, bytes, numbers) {
            Err(_) => Seen::Refused,
            Ok(AtPath::Found(item)) => Seen::Found(as_listed(item)),
            Ok(AtPath::LeafMissing) => Seen::LeafMissing,
            Ok(AtPath::HolderMissing) => Seen::HolderMissing,
        }
    }

    fn by_listing(schema: &SchemaSet, bytes: &[u8], numbers: &[u64]) -> Seen {
        let root = schema.message("syn.path.Root").expect("the root");
        match schema.decode(root, bytes) {
            Err(_) => Seen::Refused,
            Ok(fields) => listed(&fields, numbers),
        }
    }

    fn schema() -> SchemaSet {
        let files = [ProtoFile {
            name: "syn/path.proto",
            text: SCHEMA.as_bytes(),
        }];
        SchemaSet::read(&files).expect("the synthetic schema reads")
    }

    /// Payloads laid by hand: a tag is `number << 3 | wire type`.
    fn payloads() -> Vec<(&'static str, Vec<u8>)> {
        alloc::vec![
            ("empty", alloc::vec![]),
            ("serial 150", alloc::vec![0x10, 0x96, 0x01]),
            ("tilt -3", alloc::vec![0x0A, 0x04, 0x0A, 0x02, 0x08, 0x05]),
            (
                "two holders, the second's tilt 5",
                alloc::vec![0x0A, 0x04, 0x0A, 0x02, 0x08, 0x05, 0x0A, 0x04, 0x0A, 0x02, 0x08, 0x0A],
            ),
            (
                "a later holder without the leaf",
                alloc::vec![0x0A, 0x04, 0x0A, 0x02, 0x08, 0x05, 0x0A, 0x02, 0x10, 0x07],
            ),
            ("a holder with no leaf", alloc::vec![0x0A, 0x02, 0x10, 0x07]),
            ("an empty leaf", alloc::vec![0x0A, 0x02, 0x0A, 0x00]),
            (
                "the tag x",
                alloc::vec![0x0A, 0x05, 0x0A, 0x03, 0x12, 0x01, 0x78]
            ),
            (
                "serial under a fixed32",
                alloc::vec![0x15, 0x01, 0x00, 0x00, 0x00]
            ),
            (
                "a map entry, then serial 2",
                alloc::vec![0x1A, 0x05, 0x0A, 0x01, 0x61, 0x10, 0x09, 0x10, 0x02],
            ),
            ("a packed run", alloc::vec![0x22, 0x02, 0x01, 0x02]),
            ("an unknown field", alloc::vec![0x48, 0x01, 0x10, 0x03]),
            ("cut inside a varint", alloc::vec![0x10]),
            (
                "a tag that is no UTF-8",
                alloc::vec![0x0A, 0x05, 0x0A, 0x03, 0x12, 0x01, 0xFF],
            ),
            ("field number zero", alloc::vec![0x00, 0x01]),
        ]
    }

    #[test]
    fn a_path_reads_as_the_listing_of_the_same_bytes_does() {
        let schema = schema();
        let paths: [&[u64]; 5] = [&[], &[2], &[1, 2], &[1, 1, 1], &[1, 1, 2]];
        for (what, bytes) in payloads() {
            for path in paths {
                assert_eq!(
                    walked(&schema, &bytes, path),
                    by_listing(&schema, &bytes, path),
                    "{what}, the path {path:?}"
                );
            }
        }
    }

    #[test]
    fn the_last_occurrence_is_found_and_a_missing_holder_is_told_apart() {
        let schema = schema();
        let all = payloads();
        let bytes = |what: &str| {
            all.iter()
                .find(|(name, _)| *name == what)
                .map(|(_, bytes)| bytes.clone())
                .expect("a payload of the list")
        };
        assert_eq!(
            walked(
                &schema,
                &bytes("two holders, the second's tilt 5"),
                &[1, 1, 1]
            ),
            Seen::Found(Value::Signed(5))
        );
        assert_eq!(
            walked(
                &schema,
                &bytes("a later holder without the leaf"),
                &[1, 1, 1]
            ),
            Seen::Found(Value::Signed(-3))
        );
        assert_eq!(
            walked(&schema, &bytes("a holder with no leaf"), &[1, 1, 1]),
            Seen::HolderMissing
        );
        assert_eq!(
            walked(&schema, &bytes("an empty leaf"), &[1, 1, 1]),
            Seen::LeafMissing
        );
        assert_eq!(
            walked(&schema, &bytes("serial under a fixed32"), &[2]),
            Seen::LeafMissing
        );
        assert_eq!(
            walked(&schema, &bytes("the tag x"), &[1, 1, 2]),
            Seen::Found(Value::Text("x".into()))
        );
        assert_eq!(
            walked(&schema, &bytes("a tag that is no UTF-8"), &[2]),
            Seen::Refused,
            "a payload the listing refuses is refused whatever path is read"
        );
    }
}

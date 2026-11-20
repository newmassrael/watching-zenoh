// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The protobuf WIRE WRITER: values a `.proto` schema has typed, turned into
//! the bytes of a message.
//!
//! ## Why there is one
//!
//! Two writers of one format disagree exactly where the format is unusual: a
//! `sint32` is zigzagged and an `int32` is not, a negative `int32` is ten
//! bytes, a proto3 field at its default is absent, a packed field is one
//! length-delimited run. So every writer of protobuf bytes in the workspace
//! writes through this module: the payload a program sets field by field
//! (`message_payload`, behind `message-payload`) and the capture crate's
//! writer of values given as JSON. What each of them adds is how its
//! values arrive and how a value that does not fit is refused; how a value
//! becomes bytes is decided here.
//!
//! ## What it writes
//!
//! * A field is its tag, `number << 3 | wire type`, then its value
//!   ([`put_field`]).
//! * `int32`, `int64` and an enum are a varint of the value sign-extended to 64
//!   bits, so a negative one is ten bytes; `uint32` and `uint64` a varint;
//!   `sint32` and `sint64` zigzagged; `fixed32`, `sfixed32` and `float` four
//!   bytes little-endian, `fixed64`, `sfixed64` and `double` eight; `bool` a
//!   varint; `string`, `bytes` and a message length-delimited ([`Wire`]).
//! * A singular field without presence (a proto3 field that is not `optional`,
//!   not in a oneof and not a message) is left out at its default: zero, empty,
//!   or a `float` or `double` whose bits are all zero, so `-0.0` IS written
//!   ([`put_singular`], [`has_presence`]).
//! * A repeated numeric, `bool` or enum field is one length-delimited run of its
//!   elements in proto3 unless it says `[packed = false]`, and one tag per
//!   element in proto2 unless it says `[packed = true]`; a repeated string,
//!   bytes or message field is one tag per element; an empty one writes nothing
//!   ([`packed`], [`put_repeated`]).
//! * A map entry is a message whose key is field 1 and whose value is field 2,
//!   both written whatever their value ([`map_entry`]).
//!
//! The caller writes the fields of a message in ascending number and nests a
//! message by writing its bytes first and handing them over as one
//! length-delimited value.
//!
//! ## Narrowing: which integers a field takes
//!
//! A protobuf integer type has a range of its own, and every protobuf library
//! accepts it. A receiver that links nanopb stores a varint field in the C
//! integer the `(nanopb).int_size` option chooses, and its decoder refuses a
//! value that integer cannot hold. Which of the two a writer holds a value to
//! is the writer's choice, [`Narrowing`]: the type's range, or the narrower
//! one nanopb takes ([`crate::proto_range`]), so a sender that writes for a
//! nanopb receiver is told at the value it sets and not by a receiver that
//! drops the message.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use crate::proto_parse::{FieldOption, Label, OptionValue, ScalarKind, Syntax};
use crate::proto_range::{
    field_range, map_entry_range, type_field_range, RangeRefusal, ValueRange,
};
use crate::proto_schema::{FieldKind, FileOptions, Fld, Msg};

const WIRE_VARINT: u64 = 0;
const WIRE_I64: u64 = 1;
const WIRE_LEN: u64 = 2;
const WIRE_I32: u64 = 5;

/// One value as the wire carries it, before its tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wire<'b> {
    /// A varint: the integer kinds that are not fixed-width, an enum, a `bool`.
    Varint(u64),
    /// Four bytes little-endian: `fixed32`, `sfixed32`, `float`.
    Fixed32(u32),
    /// Eight bytes little-endian: `fixed64`, `sfixed64`, `double`.
    Fixed64(u64),
    /// A length, then the bytes: `string`, `bytes`, a message, a packed run.
    Len(Cow<'b, [u8]>),
}

impl<'b> Wire<'b> {
    /// A length-delimited value, borrowed or owned.
    pub fn delimited(bytes: impl Into<Cow<'b, [u8]>>) -> Self {
        Self::Len(bytes.into())
    }

    /// The wire type the tag of this value carries.
    pub const fn wire_type(&self) -> u64 {
        match self {
            Self::Varint(_) => WIRE_VARINT,
            Self::Fixed64(_) => WIRE_I64,
            Self::Len(_) => WIRE_LEN,
            Self::Fixed32(_) => WIRE_I32,
        }
    }

    /// Whether this is the default of its type: zero, all bits clear, or empty.
    /// For a float this is a test on the BITS, so `-0.0` is not the default.
    pub fn is_default(&self) -> bool {
        match self {
            Self::Varint(v) | Self::Fixed64(v) => *v == 0,
            Self::Fixed32(v) => *v == 0,
            Self::Len(bytes) => bytes.is_empty(),
        }
    }

    /// Append the value without its tag.
    pub fn put(&self, out: &mut Vec<u8>) {
        match self {
            Self::Varint(v) => put_varint(out, *v),
            Self::Fixed32(v) => out.extend_from_slice(&v.to_le_bytes()),
            Self::Fixed64(v) => out.extend_from_slice(&v.to_le_bytes()),
            Self::Len(bytes) => {
                put_varint(out, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
        }
    }
}

impl Wire<'static> {
    /// An integer of `kind` already known to fit it, by the type's own range or
    /// a narrower one.
    pub fn integer(kind: ScalarKind, v: i128) -> Self {
        match kind {
            // Sign-extended to 64 bits: a negative int32 is ten bytes.
            ScalarKind::Int32 | ScalarKind::Int64 => Self::Varint(v as i64 as u64),
            ScalarKind::Uint32 | ScalarKind::Uint64 => Self::Varint(v as u64),
            ScalarKind::Sint32 => {
                let n = v as i32;
                Self::Varint(u64::from(((n << 1) ^ (n >> 31)) as u32))
            }
            ScalarKind::Sint64 => {
                let n = v as i64;
                Self::Varint(((n << 1) ^ (n >> 63)) as u64)
            }
            ScalarKind::Fixed32 => Self::Fixed32(v as u32),
            ScalarKind::Sfixed32 => Self::Fixed32(v as i32 as u32),
            ScalarKind::Fixed64 => Self::Fixed64(v as u64),
            ScalarKind::Sfixed64 => Self::Fixed64(v as i64 as u64),
            // Not integers: a caller sends only the kinds that have a type range
            // ([`ValueRange::of_type`]).
            ScalarKind::Double
            | ScalarKind::Float
            | ScalarKind::Bool
            | ScalarKind::String
            | ScalarKind::Bytes => Self::Varint(0),
        }
    }

    /// An enum's number, sign-extended as an `int32` is.
    pub fn enum_number(number: i32) -> Self {
        Self::Varint(i64::from(number) as u64)
    }
}

/// Append `v` as a varint: seven bits a byte, the low bits first.
pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Append the tag of field `number` for a value of `wire_type`.
pub fn put_tag(out: &mut Vec<u8>, number: u64, wire_type: u64) {
    put_varint(out, (number << 3) | wire_type);
}

/// Append field `number` holding `value`: its tag and the value, whatever the
/// value is.
pub fn put_field(out: &mut Vec<u8>, number: u64, value: &Wire<'_>) {
    put_tag(out, number, value.wire_type());
    value.put(out);
}

/// Append a singular field: written when it has presence ([`has_presence`]),
/// and otherwise only when its value is not its type's default.
pub fn put_singular(out: &mut Vec<u8>, number: u64, presence: bool, value: &Wire<'_>) {
    if presence || !value.is_default() {
        put_field(out, number, value);
    }
}

/// Append the elements of a repeated field: one length-delimited run of them
/// when `packed` ([`packed`] decides it), else each under its own tag. No
/// element writes nothing.
pub fn put_repeated(out: &mut Vec<u8>, number: u64, packed: bool, elements: &[Wire<'_>]) {
    if elements.is_empty() {
        return;
    }
    if packed {
        let mut run = Vec::new();
        for element in elements {
            element.put(&mut run);
        }
        put_field(out, number, &Wire::delimited(run));
    } else {
        for element in elements {
            put_field(out, number, element);
        }
    }
}

/// The bytes of one entry of a map field: the key as field 1 and the value as
/// field 2, both written whatever their value. The entry is written into its
/// map's field as a length-delimited value ([`put_field`]).
pub fn map_entry(key: &Wire<'_>, value: &Wire<'_>) -> Vec<u8> {
    let mut entry = Vec::new();
    put_field(&mut entry, 1, key);
    put_field(&mut entry, 2, value);
    entry
}

/// Whether `field` of `holder` has presence: whether "not set" is a state of
/// its own, so that its value is written even at its default. A message field,
/// a member of a oneof and a labelled field have it; a proto3 singular field
/// with no label does not. (A proto2 field always has a label, a map and a
/// oneof member aside, and the reader refuses one without.)
pub fn has_presence(holder: &Msg, field: &Fld) -> bool {
    field.label != Label::Implicit
        || field.oneof.is_some()
        || holder.syntax == Syntax::Proto2
        || matches!(field.kind, FieldKind::Message(_))
}

/// Whether a repeated field of this kind may be packed: a numeric, `bool` or
/// enum one.
pub fn packable(kind: FieldKind) -> bool {
    match kind {
        FieldKind::Enum(_) => true,
        FieldKind::Scalar(scalar) => !matches!(scalar, ScalarKind::String | ScalarKind::Bytes),
        FieldKind::Message(_) | FieldKind::Map { .. } | FieldKind::Group => false,
    }
}

/// Why a repeated field's `packed` option cannot be acted on, with the option,
/// whose position a diagnostic blames.
#[derive(Clone, Copy, Debug)]
pub enum PackedRefusal<'f> {
    /// `[packed = true]` on a field that is not numeric, `bool` or an enum.
    NotPackable(&'f FieldOption),
    /// A `packed` that is not `true` or `false`.
    NotABool(&'f FieldOption),
}

/// Whether the repeated `field` of `holder` is written packed: the syntax of
/// the file gives the default (proto3 packs what can be packed) and
/// `[packed = ...]` overrides it.
///
/// # Errors
///
/// A [`PackedRefusal`] for a `packed` option the writer cannot act on.
pub fn packed<'f>(holder: &Msg, field: &'f Fld) -> Result<bool, PackedRefusal<'f>> {
    let packable = packable(field.kind);
    let default = holder.syntax == Syntax::Proto3 && packable;
    let Some(option) = field.options.iter().find(|o| o.name == "packed") else {
        return Ok(default);
    };
    match &option.value {
        OptionValue::Ident(word) if word == "false" => Ok(false),
        OptionValue::Ident(word) if word == "true" => {
            if packable {
                Ok(true)
            } else {
                Err(PackedRefusal::NotPackable(option))
            }
        }
        _ => Err(PackedRefusal::NotABool(option)),
    }
}

/// Which integers a writer holds a value of a varint field to: the writer's
/// choice of receiver. See the module documentation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Narrowing {
    /// The protobuf type's own range, which every protobuf library accepts.
    #[default]
    Type,
    /// The range of the C integer nanopb stores the field in under the
    /// `(nanopb).int_size` in force, intersected with the type's; a field whose
    /// nanopb options leave that unknown (an unreadable `int_size`, a
    /// `type_override`) takes no value.
    NanopbIntSize,
}

impl Narrowing {
    /// The integers `field` of `holder` takes under this choice, or why it has
    /// no integer range. `schema` is the linked schema `holder` belongs to.
    ///
    /// # Errors
    ///
    /// The [`RangeRefusal`] for a field that holds no integer, and under
    /// [`Narrowing::NanopbIntSize`] for one whose nanopb options leave the
    /// range unknown.
    pub fn field_range<S: FileOptions + ?Sized>(
        self,
        schema: &S,
        holder: &Msg,
        field: &Fld,
    ) -> Result<ValueRange, RangeRefusal> {
        match self {
            Self::Type => type_field_range(field),
            Self::NanopbIntSize => field_range(schema, holder, field),
        }
    }

    /// The integers the key or the value, of scalar `kind`, of an entry of a map
    /// written in file `file` takes under this choice.
    ///
    /// # Errors
    ///
    /// The [`RangeRefusal`] for a kind that holds no integer, and under
    /// [`Narrowing::NanopbIntSize`] for a file whose options leave the range
    /// unknown.
    pub fn map_entry_range<S: FileOptions + ?Sized>(
        self,
        schema: &S,
        file: usize,
        kind: ScalarKind,
    ) -> Result<ValueRange, RangeRefusal> {
        match self {
            Self::Type => ValueRange::of_type(kind).ok_or(RangeRefusal::NotAnInteger),
            Self::NanopbIntSize => map_entry_range(schema, file, kind),
        }
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A MESSAGE PAYLOAD set and read field by field, at paths, under a `.proto`
//! schema read at run time: values set, the protobuf bytes of the message
//! encoded, bytes decoded, and values read back.
//!
//! ## What this is for
//!
//! A program that reads its deployment's message catalog and `.proto` files
//! when it starts has no code generated for its messages: it knows a message by
//! its full name and a field by its path. [`Payload`] is that program's message:
//! one message of a [`SchemaSet`], whose fields are set and read by path and
//! whose bytes are what the schema says they are. The schema is read by the
//! one schema reader ([`crate::proto_schema`]) and bytes are read by the one
//! typed reader ([`crate::proto_decode`]), so this module adds the values and
//! the writing of them, and no second reading of either.
//!
//! ## Paths
//!
//! A path names a field by its name as the `.proto` file spells it, a field
//! inside a message field by the holder's name, a dot and its own
//! (`origin.x`), and an element of a repeated field by its index in brackets
//! (`path[2].x`, `tags[0]`), the index decimal digits with no leading zero. A
//! repeated field is named with an index wherever a value is set or read, and
//! without one where its elements are counted or all cleared. A `map` field and
//! a `group` are not addressed: a map's entries and a group's body are not
//! fields of the message that holds them, and a decoded map is carried as its
//! wire bytes. A path is at most [`MAX_DECODE_DEPTH`] names long.
//!
//! ## Setting a value
//!
//! The value is given as the program holds it ([`Given`]) and is held as the
//! field's type, never converted by guessing: an integer goes into an integer
//! or enum field it fits, a real number into a `float` or `double` (a finite one
//! a `float` cannot hold is refused rather than made infinite), a bool into a
//! `bool`, a string into a `string` or into an enum by the name of a value, and
//! bytes into `bytes`. A closed (proto2) enum takes only the numbers its values
//! have; an open (proto3) one takes any `int32`. A message field is set by its
//! fields' paths: setting one makes every message along the path that is not
//! there yet. An element is replaced at an index the list has and appended at
//! the index one past its end; a farther index is refused, and so is anything a
//! call is refused for before it changes the payload, so a refused call leaves
//! it as it was. Setting a member of a oneof clears the other members.
//!
//! ## Reading a value
//!
//! A value is read as the program asks for it ([`Wanted`]) when the field's
//! value fits: a signed integer from any integer or enum field whose value fits
//! `i64`, an unsigned one from any whose value fits `u64`, a real number from a
//! `float` or a `double`, a string from a `string` or from an enum by its
//! value's name. A field that is not set reads as protobuf reads it: a field
//! without presence (a proto3 singular field that is not `optional`, not in a
//! oneof and not a message) as its default, `0`, `false`, empty or the enum's
//! first value; a field WITH presence, or any field of a message that is not
//! there, is refused as absent ([`Refusal::Absent`]), which is how a program
//! asks whether it was set.
//!
//! ## The bytes
//!
//! Written as the capture crate's writer (`proto_encode`) writes the same
//! message: fields in ascending number; a field without presence left out at
//! its default (a `float` or `double` whose bits are all zero, so `-0.0` is
//! written); a repeated numeric, `bool` or enum field packed in proto3 unless it
//! says `[packed = false]` and unpacked in proto2 unless it says
//! `[packed = true]`; `int32` and an enum sign-extended (a negative one is ten
//! bytes), `sint32` and `sint64` zigzagged. A proto2 `required` field that is not
//! set refuses the encoding. Unlike that writer, this one takes no values from
//! JSON and so no `(nanopb).int_size` narrowing: the values are the program's,
//! held to the field's own type.
//!
//! Decoding replaces the payload's values with those of the bytes, read as a
//! protobuf parser reads them: the last occurrence of a singular field wins,
//! occurrences of a message field are merged, a repeated field takes its
//! elements packed or not, and a oneof keeps its last member. A field the
//! schema does not know and every entry of a map field are KEPT as their wire
//! bytes and written back after the known fields, so a payload decoded and
//! encoded again loses nothing. Bytes that are not a message of the schema are
//! refused with the typed reader's diagnostic, and the payload is left as it
//! was.
//!
//! ## Refusals
//!
//! Each is a [`Refusal`]: the path names no field the payload addresses, the
//! value's type is not the field's, the value does not fit the field or an index
//! is past the end of its list, a field is not set, the schema states an option
//! the writer cannot act on, or the bytes are not a message.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;

use crate::proto_decode::{
    DecodedField, SchemaMessage, SchemaSet, Value, WireError, MAX_DECODE_DEPTH,
};
use crate::proto_parse::{Label, OptionValue, ScalarKind, Syntax};
use crate::proto_schema::{FieldKind, Fld, Msg};

const WIRE_VARINT: u64 = 0;
const WIRE_I64: u64 = 1;
const WIRE_LEN: u64 = 2;
const WIRE_I32: u64 = 5;

/// A value as the program gives it to a field.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Given<'v> {
    /// A signed integer: for an integer or an enum field it fits.
    Signed(i64),
    /// An unsigned integer: for an integer or an enum field it fits.
    Unsigned(u64),
    /// A real number: for a `float` or a `double`.
    Real(f64),
    /// For a `bool`.
    Bool(bool),
    /// For a `string`, or an enum by the name of one of its values.
    Text(&'v str),
    /// For `bytes`.
    Bytes(&'v [u8]),
}

impl Given<'_> {
    fn word(self) -> &'static str {
        match self {
            Self::Signed(_) => "a signed integer",
            Self::Unsigned(_) => "an unsigned integer",
            Self::Real(_) => "a real number",
            Self::Bool(_) => "a bool",
            Self::Text(_) => "a string",
            Self::Bytes(_) => "bytes",
        }
    }
}

/// What the program asks a field's value to be read as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wanted {
    /// An `i64`, from an integer or an enum field.
    Signed,
    /// A `u64`, from an integer or an enum field.
    Unsigned,
    /// An `f64`, from a `float` or a `double`.
    Real,
    /// From a `bool`.
    Bool,
    /// From a `string`, or an enum's value by its name.
    Text,
    /// From `bytes`.
    Bytes,
}

impl Wanted {
    fn word(self) -> &'static str {
        match self {
            Self::Signed => "a signed integer",
            Self::Unsigned => "an unsigned integer",
            Self::Real => "a real number",
            Self::Bool => "a bool",
            Self::Text => "a string",
            Self::Bytes => "bytes",
        }
    }
}

/// A value read from a field, as the program asked for it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Got<'p> {
    Signed(i64),
    Unsigned(u64),
    Real(f64),
    Bool(bool),
    Text(&'p str),
    Bytes(&'p [u8]),
}

/// Why a call on a payload was refused. A refused call changes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The path names no field the payload addresses: not a path, a name the
    /// message has not, an index on a field that is not repeated, a repeated
    /// field where an element is needed (or the other way round), a field that
    /// holds no fields followed by a dot, a map or a group.
    Path { path: String, reason: String },
    /// The value's type is not the field's, or the field's value cannot be
    /// read as what was asked for.
    Type { path: String, reason: String },
    /// The value does not fit the field (an integer past its width, a real a
    /// `float` cannot hold, a number or a name a closed enum has not), a value
    /// does not fit what it is read as, or an index is past the end of its list.
    Range { path: String, reason: String },
    /// The field `path` names is not set: a field with presence, a required
    /// field of an encoding, or a field of a message that is not there; `at` is
    /// the first part of the path that is absent.
    Absent { path: String, at: String },
    /// The schema states an option of a field the writer cannot act on.
    Schema { path: String, reason: String },
    /// The bytes are not a message of the schema.
    Wire(WireError),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path { path, reason } => write!(f, "path `{path}`: {reason}"),
            Self::Type { path, reason } => write!(f, "type mismatch at `{path}`: {reason}"),
            Self::Range { path, reason } => write!(f, "out of range at `{path}`: {reason}"),
            Self::Absent { path, at } if path == at => write!(f, "`{path}` is not set"),
            Self::Absent { path, at } => write!(f, "`{path}` is not set: `{at}` is absent"),
            Self::Schema { path, reason } => write!(f, "schema at `{path}`: {reason}"),
            Self::Wire(w) => write!(f, "the bytes are not a message of the schema: {w}"),
        }
    }
}

/// One value of a field, held as the field's type holds it.
#[derive(Clone, Debug)]
enum Held {
    /// `int32`, `int64`, `sint32`, `sint64`, `sfixed32`, `sfixed64`, and an
    /// enum's number.
    Int(i64),
    /// `uint32`, `uint64`, `fixed32`, `fixed64`.
    Uint(u64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Text(String),
    Bytes(Vec<u8>),
    Message(Fields),
}

/// The values of one message: each known field's by number (one value for a
/// singular field, the elements of a repeated one), and the wire bytes of the
/// fields it carries without addressing them.
#[derive(Clone, Debug, Default)]
struct Fields {
    known: BTreeMap<u64, Vec<Held>>,
    kept: Vec<u8>,
}

impl Fields {
    /// How many values field `number` holds.
    fn len(&self, number: u64) -> usize {
        self.known.get(&number).map_or(0, Vec::len)
    }

    /// The value at `index` of field `number`.
    fn value(&self, number: u64, index: usize) -> Option<&Held> {
        self.known.get(&number).and_then(|list| list.get(index))
    }

    /// Clear the other members of the oneof `field` is in.
    fn clear_oneof(&mut self, holder: &Msg, field: &Fld) {
        if let Some(oneof) = field.oneof {
            for other in holder
                .fields
                .iter()
                .filter(|f| f.oneof == Some(oneof) && f.number != field.number)
            {
                self.known.remove(&other.number);
            }
        }
    }
}

/// The message a held value is, made one when it is not.
fn message_mut(held: &mut Held) -> &mut Fields {
    if !matches!(held, Held::Message(_)) {
        *held = Held::Message(Fields::default());
    }
    match held {
        Held::Message(fields) => fields,
        _ => unreachable!("the value was made a message above"),
    }
}

/// One step of a path: the field, the message that holds it, its index, and
/// where the step ends in the path's text.
struct Step<'s> {
    holder: &'s Msg,
    field: &'s Fld,
    index: Option<usize>,
    end: usize,
}

impl Step<'_> {
    fn repeated(&self) -> bool {
        self.field.label == Label::Repeated
    }
}

/// A part of a path: a name, and an index when it has one.
fn segment(part: &str) -> Option<(&str, Option<usize>)> {
    let (name, index) = match part.find('[') {
        None => (part, None),
        Some(open) => {
            let digits = part[open + 1..].strip_suffix(']')?;
            let plain = !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
                && (digits.len() == 1 || !digits.starts_with('0'));
            if !plain {
                return None;
            }
            (&part[..open], Some(digits.parse::<usize>().ok()?))
        }
    };
    let first = name.bytes().next()?;
    let word =
        !first.is_ascii_digit() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    word.then_some((name, index))
}

/// The steps `path` takes from the message `root`.
fn steps<'s>(schema: &'s SchemaSet, root: &'s Msg, path: &str) -> Result<Vec<Step<'s>>, Refusal> {
    let refused = |reason: String| Refusal::Path {
        path: String::from(path),
        reason,
    };
    let parts = path.split('.').count();
    if parts > MAX_DECODE_DEPTH {
        return Err(refused(format!(
            "it goes {parts} names deep, past the {MAX_DECODE_DEPTH} a payload is read to"
        )));
    }
    let mut holder = root;
    let mut out = Vec::with_capacity(parts);
    let mut end = 0usize;
    for (at, part) in path.split('.').enumerate() {
        end += part.len() + usize::from(at > 0);
        let Some((name, index)) = segment(part) else {
            return Err(refused(format!(
                "`{part}` is not a field name, or a field name and an index in brackets"
            )));
        };
        let Some(field) = holder.fields.iter().find(|f| f.name == name) else {
            return Err(refused(format!(
                "the message `{}` has no field `{name}`",
                holder.full_name
            )));
        };
        match field.kind {
            FieldKind::Map { .. } => {
                return Err(refused(format!(
                    "`{name}` is a map, whose entries a path does not address"
                )))
            }
            FieldKind::Group => {
                return Err(refused(format!(
                    "`{name}` is a group, which this library does not write"
                )))
            }
            _ => {}
        }
        let repeated = field.label == Label::Repeated;
        if index.is_some() && !repeated {
            return Err(refused(format!(
                "`{name}` is not repeated, so it has no element to index"
            )));
        }
        out.push(Step {
            holder,
            field,
            index,
            end,
        });
        if at + 1 == parts {
            break;
        }
        if repeated && index.is_none() {
            return Err(refused(format!(
                "`{name}` is repeated: name one of its elements, as `{name}[0]`"
            )));
        }
        let inner = match field.kind {
            FieldKind::Message(inner) => schema.linked_at(inner),
            _ => None,
        };
        let Some(inner) = inner else {
            return Err(refused(format!(
                "`{name}` is not a message field, so no field is inside it"
            )));
        };
        holder = inner;
    }
    Ok(out)
}

/// The type of a field as the schema writes it.
fn type_name(schema: &SchemaSet, field: &Fld) -> String {
    match field.kind {
        FieldKind::Scalar(kind) => String::from(kind.keyword()),
        FieldKind::Enum(e) => schema
            .enum_at(e)
            .map_or_else(|| String::from("an enum"), |info| info.full_name.clone()),
        FieldKind::Message(m) => schema
            .linked_at(m)
            .map_or_else(|| String::from("a message"), |msg| msg.full_name.clone()),
        FieldKind::Map { .. } => String::from("a map"),
        FieldKind::Group => String::from("a group"),
    }
}

/// Whether a field has presence: whether "not set" is a state of its own.
fn has_presence(holder: &Msg, field: &Fld) -> bool {
    field.label != Label::Implicit
        || field.oneof.is_some()
        || holder.syntax == Syntax::Proto2
        || matches!(field.kind, FieldKind::Message(_))
}

/// The integers a scalar kind holds.
fn bounds(kind: ScalarKind) -> Option<(i128, i128)> {
    match kind {
        ScalarKind::Int32 | ScalarKind::Sint32 | ScalarKind::Sfixed32 => {
            Some((i128::from(i32::MIN), i128::from(i32::MAX)))
        }
        ScalarKind::Int64 | ScalarKind::Sint64 | ScalarKind::Sfixed64 => {
            Some((i128::from(i64::MIN), i128::from(i64::MAX)))
        }
        ScalarKind::Uint32 | ScalarKind::Fixed32 => Some((0, i128::from(u32::MAX))),
        ScalarKind::Uint64 | ScalarKind::Fixed64 => Some((0, i128::from(u64::MAX))),
        _ => None,
    }
}

fn unsigned(kind: ScalarKind) -> bool {
    matches!(
        kind,
        ScalarKind::Uint32 | ScalarKind::Uint64 | ScalarKind::Fixed32 | ScalarKind::Fixed64
    )
}

/// The value `given` as field `field` holds it.
fn held_of(schema: &SchemaSet, field: &Fld, given: Given<'_>, path: &str) -> Result<Held, Refusal> {
    let mismatch = || Refusal::Type {
        path: String::from(path),
        reason: format!(
            "the field is {}, and {} was given",
            type_name(schema, field),
            given.word()
        ),
    };
    let range = |reason: String| Refusal::Range {
        path: String::from(path),
        reason,
    };
    let integer = match given {
        Given::Signed(v) => Some(i128::from(v)),
        Given::Unsigned(v) => Some(i128::from(v)),
        _ => None,
    };
    match field.kind {
        FieldKind::Scalar(kind) => {
            if let Some((low, high)) = bounds(kind) {
                let Some(v) = integer else {
                    return Err(mismatch());
                };
                if !(low..=high).contains(&v) {
                    return Err(range(format!(
                        "{v} does not fit a {}, whose values are {low} to {high}",
                        kind.keyword()
                    )));
                }
                return Ok(if unsigned(kind) {
                    Held::Uint(v as u64)
                } else {
                    Held::Int(v as i64)
                });
            }
            match (kind, given) {
                (ScalarKind::Double, Given::Real(v)) => Ok(Held::Double(v)),
                (ScalarKind::Float, Given::Real(v)) => {
                    let narrow = v as f32;
                    if v.is_finite() && narrow.is_infinite() {
                        return Err(range(format!("{v} is finite and past what a float holds")));
                    }
                    Ok(Held::Float(narrow))
                }
                (ScalarKind::Bool, Given::Bool(v)) => Ok(Held::Bool(v)),
                (ScalarKind::String, Given::Text(v)) => Ok(Held::Text(String::from(v))),
                (ScalarKind::Bytes, Given::Bytes(v)) => Ok(Held::Bytes(v.to_vec())),
                _ => Err(mismatch()),
            }
        }
        FieldKind::Enum(e) => {
            let Some(info) = schema.enum_at(e) else {
                return Err(mismatch());
            };
            let number = match (given, integer) {
                (_, Some(v)) => i32::try_from(v).map_err(|_| {
                    range(format!("{v} does not fit an enum, whose values are int32"))
                })?,
                (Given::Text(name), None) => {
                    let found = info.values.iter().find(|(n, _)| n == name);
                    let Some(number) = found.and_then(|(_, v)| i32::try_from(*v).ok()) else {
                        return Err(range(format!(
                            "the enum `{}` has no value named `{name}`",
                            info.full_name
                        )));
                    };
                    number
                }
                _ => return Err(mismatch()),
            };
            let listed = info.values.iter().any(|(_, v)| *v == i128::from(number));
            if info.syntax == Syntax::Proto2 && !listed {
                return Err(range(format!(
                    "the enum `{}` is closed and has no value {number}",
                    info.full_name
                )));
            }
            Ok(Held::Int(i64::from(number)))
        }
        FieldKind::Message(_) => Err(Refusal::Type {
            path: String::from(path),
            reason: format!(
                "the field is the message {}: set its fields by their paths",
                type_name(schema, field)
            ),
        }),
        FieldKind::Map { .. } | FieldKind::Group => Err(mismatch()),
    }
}

/// A value as it is read: borrowed from the payload, or a default.
#[derive(Clone, Copy)]
enum View<'p> {
    Int(i64),
    Uint(u64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Text(&'p str),
    Bytes(&'p [u8]),
    Message,
}

fn view(held: &Held) -> View<'_> {
    match held {
        Held::Int(v) => View::Int(*v),
        Held::Uint(v) => View::Uint(*v),
        Held::Float(v) => View::Float(*v),
        Held::Double(v) => View::Double(*v),
        Held::Bool(v) => View::Bool(*v),
        Held::Text(v) => View::Text(v),
        Held::Bytes(v) => View::Bytes(v),
        Held::Message(_) => View::Message,
    }
}

/// The value a field without presence reads as when it is not set.
fn default_view<'p>(schema: &'p SchemaSet, field: &Fld) -> View<'p> {
    match field.kind {
        FieldKind::Scalar(ScalarKind::Double) => View::Double(0.0),
        FieldKind::Scalar(ScalarKind::Float) => View::Float(0.0),
        FieldKind::Scalar(ScalarKind::Bool) => View::Bool(false),
        FieldKind::Scalar(ScalarKind::String) => View::Text(""),
        FieldKind::Scalar(ScalarKind::Bytes) => View::Bytes(&[]),
        FieldKind::Scalar(kind) if unsigned(kind) => View::Uint(0),
        FieldKind::Scalar(_) => View::Int(0),
        FieldKind::Enum(e) => View::Int(
            schema
                .enum_at(e)
                .and_then(|info| info.values.first())
                .and_then(|(_, v)| i64::try_from(*v).ok())
                .unwrap_or(0),
        ),
        FieldKind::Message(_) | FieldKind::Map { .. } | FieldKind::Group => View::Message,
    }
}

/// `value` of `field` as the program asked for it.
fn got<'p>(
    schema: &'p SchemaSet,
    field: &Fld,
    value: View<'p>,
    wanted: Wanted,
    path: &str,
) -> Result<Got<'p>, Refusal> {
    let range = |reason: String| Refusal::Range {
        path: String::from(path),
        reason,
    };
    let mismatch = || Refusal::Type {
        path: String::from(path),
        reason: format!(
            "the field is {}, and {} was asked for",
            type_name(schema, field),
            wanted.word()
        ),
    };
    match (wanted, value) {
        (Wanted::Signed, View::Int(v)) => Ok(Got::Signed(v)),
        (Wanted::Signed, View::Uint(v)) => i64::try_from(v)
            .map(Got::Signed)
            .map_err(|_| range(format!("{v} does not fit a signed 64-bit integer"))),
        (Wanted::Unsigned, View::Uint(v)) => Ok(Got::Unsigned(v)),
        (Wanted::Unsigned, View::Int(v)) => u64::try_from(v).map(Got::Unsigned).map_err(|_| {
            range(format!(
                "{v} is negative, and an unsigned integer was asked for"
            ))
        }),
        (Wanted::Real, View::Float(v)) => Ok(Got::Real(f64::from(v))),
        (Wanted::Real, View::Double(v)) => Ok(Got::Real(v)),
        (Wanted::Bool, View::Bool(v)) => Ok(Got::Bool(v)),
        (Wanted::Text, View::Text(v)) => Ok(Got::Text(v)),
        (Wanted::Bytes, View::Bytes(v)) => Ok(Got::Bytes(v)),
        (Wanted::Text, View::Int(v)) => {
            let FieldKind::Enum(e) = field.kind else {
                return Err(mismatch());
            };
            let name = schema.enum_at(e).and_then(|info| {
                info.values
                    .iter()
                    .find(|(_, n)| *n == i128::from(v))
                    .map(|(name, _)| name.as_str())
            });
            name.map(Got::Text)
                .ok_or_else(|| range(format!("the enum has no name for the value {v}")))
        }
        _ => Err(mismatch()),
    }
}

/// One message of a schema set, its fields set and read by path.
///
/// `S` holds the schema: a `&SchemaSet`, or a shared owner of one for a
/// payload that outlives the borrow (an `Arc<SchemaSet>`). The message must be
/// one the same set found.
pub struct Payload<S> {
    schema: S,
    message: SchemaMessage,
    fields: Fields,
}

impl<S> fmt::Debug for Payload<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Payload")
            .field("message", &self.message)
            .field("fields", &self.fields.known.len())
            .finish()
    }
}

impl<S: Borrow<SchemaSet>> Payload<S> {
    /// An empty payload of `message`, which `schema` found
    /// ([`SchemaSet::message`]).
    pub fn new(schema: S, message: SchemaMessage) -> Self {
        Self {
            schema,
            message,
            fields: Fields::default(),
        }
    }

    /// The full name of the payload's message.
    pub fn message_name(&self) -> &str {
        let schema: &SchemaSet = self.schema.borrow();
        schema.message_name(self.message)
    }

    /// Set the field `path` names to `value`; see the module documentation.
    ///
    /// # Errors
    ///
    /// [`Refusal::Path`], [`Refusal::Type`] or [`Refusal::Range`]; the payload
    /// is then as it was.
    pub fn set(&mut self, path: &str, value: Given<'_>) -> Result<(), Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let steps = steps(schema, schema.linked(self.message), path)?;
        let Some((last, inner)) = steps.split_last() else {
            return Err(empty_path(path));
        };
        if last.repeated() && last.index.is_none() {
            return Err(list_named(path, last));
        }
        let held = held_of(schema, last.field, value, path)?;
        reach(&self.fields, &steps, path)?;
        let mut fields = &mut self.fields;
        for step in inner {
            fields = descend(fields, step);
        }
        fields.clear_oneof(last.holder, last.field);
        let list = fields.known.entry(last.field.number).or_default();
        match last.index {
            Some(index) if index < list.len() => list[index] = held,
            Some(_) => list.push(held),
            None => {
                list.clear();
                list.push(held);
            }
        }
        Ok(())
    }

    /// The value of the field `path` names, read as `wanted`; see the module
    /// documentation.
    ///
    /// # Errors
    ///
    /// [`Refusal::Path`], [`Refusal::Type`], [`Refusal::Range`] or
    /// [`Refusal::Absent`].
    pub fn get(&self, path: &str, wanted: Wanted) -> Result<Got<'_>, Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let steps = steps(schema, schema.linked(self.message), path)?;
        let Some((last, inner)) = steps.split_last() else {
            return Err(empty_path(path));
        };
        if last.repeated() && last.index.is_none() {
            return Err(list_named(path, last));
        }
        let Some(fields) = holder_of(&self.fields, inner, path)? else {
            return Err(absent(path, inner, &self.fields));
        };
        let index = last.index.unwrap_or(0);
        if let Some(held) = fields.value(last.field.number, index) {
            return got(schema, last.field, view(held), wanted, path);
        }
        if last.index.is_some() {
            return Err(past_end(path, last, fields.len(last.field.number)));
        }
        if has_presence(last.holder, last.field) {
            return Err(Refusal::Absent {
                path: String::from(path),
                at: String::from(path),
            });
        }
        got(
            schema,
            last.field,
            default_view(schema, last.field),
            wanted,
            path,
        )
    }

    /// How many elements the repeated field `path` names holds; 0 when a
    /// message along the path is not there.
    ///
    /// # Errors
    ///
    /// [`Refusal::Path`] when the path names no repeated field, or names an
    /// element of one; [`Refusal::Range`] for an index along the path past the
    /// end of its list.
    pub fn count(&self, path: &str) -> Result<usize, Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let steps = steps(schema, schema.linked(self.message), path)?;
        let Some((last, inner)) = steps.split_last() else {
            return Err(empty_path(path));
        };
        if !last.repeated() {
            return Err(Refusal::Path {
                path: String::from(path),
                reason: format!("`{}` is not repeated: it has no count", last.field.name),
            });
        }
        if last.index.is_some() {
            return Err(Refusal::Path {
                path: String::from(path),
                reason: format!(
                    "this names one element; the count is of `{}`",
                    last.field.name
                ),
            });
        }
        Ok(holder_of(&self.fields, inner, path)?.map_or(0, |f| f.len(last.field.number)))
    }

    /// Clear the field `path` names (every element of a repeated one), or the
    /// one element it names, the elements after it moving down. Nothing to
    /// clear, where a message along the path is not there, is not refused.
    ///
    /// # Errors
    ///
    /// [`Refusal::Path`]; [`Refusal::Range`] for an index past the end of its
    /// list.
    pub fn clear(&mut self, path: &str) -> Result<(), Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let steps = steps(schema, schema.linked(self.message), path)?;
        let Some((last, inner)) = steps.split_last() else {
            return Err(empty_path(path));
        };
        let Some(holder) = holder_of(&self.fields, inner, path)? else {
            return Ok(());
        };
        let len = holder.len(last.field.number);
        if let Some(index) = last.index {
            if index >= len {
                return Err(past_end(path, last, len));
            }
        }
        let mut fields = &mut self.fields;
        for step in inner {
            fields = descend(fields, step);
        }
        let number = last.field.number;
        match last.index {
            None => {
                fields.known.remove(&number);
            }
            Some(index) => {
                let now_empty = fields.known.get_mut(&number).is_some_and(|list| {
                    list.remove(index);
                    list.is_empty()
                });
                if now_empty {
                    fields.known.remove(&number);
                }
            }
        }
        Ok(())
    }

    /// Clear every field: the payload is as [`Payload::new`] made it.
    pub fn reset(&mut self) {
        self.fields = Fields::default();
    }

    /// The protobuf bytes of the payload; see the module documentation.
    ///
    /// # Errors
    ///
    /// [`Refusal::Absent`] for a required field that is not set;
    /// [`Refusal::Schema`] for a `packed` option the writer cannot act on.
    pub fn encode(&self) -> Result<Vec<u8>, Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let mut out = Vec::new();
        write_message(
            schema,
            schema.linked(self.message),
            &self.fields,
            "",
            &mut out,
        )?;
        Ok(out)
    }

    /// Replace the payload's values with those `bytes` carry; see the module
    /// documentation.
    ///
    /// # Errors
    ///
    /// [`Refusal::Wire`] for bytes that are not a message of the schema; the
    /// payload is then as it was.
    pub fn decode(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let listing = schema.decode(self.message, bytes).map_err(Refusal::Wire)?;
        self.fields = fields_of(schema, schema.linked(self.message), &listing, bytes);
        Ok(())
    }
}

fn empty_path(path: &str) -> Refusal {
    Refusal::Path {
        path: String::from(path),
        reason: String::from("the path is empty"),
    }
}

fn list_named(path: &str, last: &Step<'_>) -> Refusal {
    let name = &last.field.name;
    Refusal::Path {
        path: String::from(path),
        reason: format!("`{name}` is repeated: name one of its elements, as `{name}[0]`"),
    }
}

fn past_end(path: &str, step: &Step<'_>, len: usize) -> Refusal {
    Refusal::Range {
        path: String::from(path),
        reason: format!(
            "`{}` has {len} element(s), so the index {} is past its end",
            step.field.name,
            step.index.unwrap_or(0)
        ),
    }
}

/// The message that holds the last step's field, `None` when one along the
/// way is not there.
fn holder_of<'f>(
    fields: &'f Fields,
    inner: &[Step<'_>],
    path: &str,
) -> Result<Option<&'f Fields>, Refusal> {
    let mut at = fields;
    for step in inner {
        let index = step.index.unwrap_or(0);
        match at.value(step.field.number, index) {
            Some(Held::Message(next)) => at = next,
            Some(_) => return Ok(None),
            None if step.index.is_some() => {
                return Err(past_end(path, step, at.len(step.field.number)))
            }
            None => return Ok(None),
        }
    }
    Ok(Some(at))
}

/// The refusal of a read whose holder is not there, naming the first part of
/// the path that is absent.
fn absent(path: &str, inner: &[Step<'_>], fields: &Fields) -> Refusal {
    let mut at = fields;
    for step in inner {
        match at.value(step.field.number, step.index.unwrap_or(0)) {
            Some(Held::Message(next)) => at = next,
            _ => {
                return Refusal::Absent {
                    path: String::from(path),
                    at: String::from(&path[..step.end]),
                }
            }
        }
    }
    Refusal::Absent {
        path: String::from(path),
        at: String::from(path),
    }
}

/// Whether a set of `steps` can be made: every index at most the length of its
/// list, a list that is not there yet being empty.
fn reach(fields: &Fields, steps: &[Step<'_>], path: &str) -> Result<(), Refusal> {
    let mut at = Some(fields);
    for step in steps {
        let number = step.field.number;
        let len = at.map_or(0, |f| f.len(number));
        if let Some(index) = step.index {
            if index > len {
                return Err(Refusal::Range {
                    path: String::from(path),
                    reason: format!(
                        "`{}` has {len} element(s): an element is replaced below {len} and \
                         appended at {len}, and {index} is past that",
                        step.field.name
                    ),
                });
            }
        }
        at = at
            .and_then(|f| f.value(number, step.index.unwrap_or(0)))
            .and_then(|held| match held {
                Held::Message(next) => Some(next),
                _ => None,
            });
    }
    Ok(())
}

/// The message a step of a set goes into, made when it is not there; the
/// index was judged by `reach`.
fn descend<'f>(fields: &'f mut Fields, step: &Step<'_>) -> &'f mut Fields {
    let number = step.field.number;
    let index = step.index.unwrap_or(0);
    if step.index.is_none() && fields.len(number) == 0 {
        fields.clear_oneof(step.holder, step.field);
    }
    let list = fields.known.entry(number).or_default();
    if index >= list.len() {
        list.push(Held::Message(Fields::default()));
    }
    let last = list.len() - 1;
    message_mut(&mut list[index.min(last)])
}

// ---- the bytes ------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_len(out: &mut Vec<u8>, bytes: &[u8]) {
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// The wire type a value of a field of this kind is written with, alone.
fn wire_of(kind: FieldKind) -> u64 {
    match kind {
        FieldKind::Scalar(ScalarKind::Fixed64 | ScalarKind::Sfixed64 | ScalarKind::Double) => {
            WIRE_I64
        }
        FieldKind::Scalar(ScalarKind::Fixed32 | ScalarKind::Sfixed32 | ScalarKind::Float) => {
            WIRE_I32
        }
        FieldKind::Scalar(ScalarKind::String | ScalarKind::Bytes)
        | FieldKind::Message(_)
        | FieldKind::Map { .. }
        | FieldKind::Group => WIRE_LEN,
        FieldKind::Scalar(_) | FieldKind::Enum(_) => WIRE_VARINT,
    }
}

/// Whether the value is its type's default: zero, all bits clear, or empty.
fn is_default(held: &Held) -> bool {
    match held {
        Held::Int(v) => *v == 0,
        Held::Uint(v) => *v == 0,
        Held::Float(v) => v.to_bits() == 0,
        Held::Double(v) => v.to_bits() == 0,
        Held::Bool(v) => !*v,
        Held::Text(v) => v.is_empty(),
        Held::Bytes(v) => v.is_empty(),
        Held::Message(_) => false,
    }
}

/// Whether the repeated field is written packed: the message's syntax gives
/// the default and `[packed = ...]` overrides it.
fn packed(holder: &Msg, field: &Fld, path: &str) -> Result<bool, Refusal> {
    let packable = match field.kind {
        FieldKind::Enum(_) => true,
        FieldKind::Scalar(kind) => !matches!(kind, ScalarKind::String | ScalarKind::Bytes),
        FieldKind::Message(_) | FieldKind::Map { .. } | FieldKind::Group => false,
    };
    let default = holder.syntax == Syntax::Proto3 && packable;
    let Some(option) = field.options.iter().find(|o| o.name == "packed") else {
        return Ok(default);
    };
    match &option.value {
        OptionValue::Ident(word) if word == "false" => Ok(false),
        OptionValue::Ident(word) if word == "true" && packable => Ok(true),
        _ => Err(Refusal::Schema {
            path: String::from(path),
            reason: format!(
                "`{}` states `packed`, which takes `true` or `false`, and `true` only on a \
                 repeated numeric, bool or enum field",
                field.name
            ),
        }),
    }
}

/// The value without its tag.
fn put_value(
    schema: &SchemaSet,
    field: &Fld,
    held: &Held,
    out: &mut Vec<u8>,
    path: &str,
) -> Result<(), Refusal> {
    match (field.kind, held) {
        (FieldKind::Scalar(ScalarKind::Sint32), Held::Int(v)) => {
            let n = *v as i32;
            put_varint(out, u64::from(((n << 1) ^ (n >> 31)) as u32));
        }
        (FieldKind::Scalar(ScalarKind::Sint64), Held::Int(v)) => {
            put_varint(out, ((*v << 1) ^ (*v >> 63)) as u64);
        }
        (FieldKind::Scalar(ScalarKind::Sfixed32), Held::Int(v)) => {
            out.extend_from_slice(&(*v as i32).to_le_bytes());
        }
        (FieldKind::Scalar(ScalarKind::Sfixed64), Held::Int(v)) => {
            out.extend_from_slice(&v.to_le_bytes());
        }
        (FieldKind::Scalar(ScalarKind::Fixed32), Held::Uint(v)) => {
            out.extend_from_slice(&(*v as u32).to_le_bytes());
        }
        (FieldKind::Scalar(ScalarKind::Fixed64), Held::Uint(v)) => {
            out.extend_from_slice(&v.to_le_bytes());
        }
        // `int32`, `int64` and an enum: the value sign-extended to 64 bits.
        (FieldKind::Scalar(_) | FieldKind::Enum(_), Held::Int(v)) => put_varint(out, *v as u64),
        (FieldKind::Scalar(_), Held::Uint(v)) => put_varint(out, *v),
        (FieldKind::Scalar(_), Held::Float(v)) => out.extend_from_slice(&v.to_bits().to_le_bytes()),
        (FieldKind::Scalar(_), Held::Double(v)) => {
            out.extend_from_slice(&v.to_bits().to_le_bytes());
        }
        (FieldKind::Scalar(_), Held::Bool(v)) => put_varint(out, u64::from(*v)),
        (FieldKind::Scalar(_), Held::Text(v)) => put_len(out, v.as_bytes()),
        (FieldKind::Scalar(_), Held::Bytes(v)) => put_len(out, v),
        (FieldKind::Message(m), Held::Message(inner)) => {
            let Some(msg) = schema.linked_at(m) else {
                return Err(Refusal::Schema {
                    path: String::from(path),
                    reason: String::from("the field's message is not in the schema set"),
                });
            };
            let mut body = Vec::new();
            write_message(schema, msg, inner, path, &mut body)?;
            put_len(out, &body);
        }
        _ => {
            return Err(Refusal::Type {
                path: String::from(path),
                reason: format!("the field is {}", type_name(schema, field)),
            })
        }
    }
    Ok(())
}

/// The path of field `name` inside the message at `prefix`.
fn child(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        String::from(name)
    } else {
        format!("{prefix}.{name}")
    }
}

/// The fields of one message, then what it keeps as wire bytes.
fn write_message(
    schema: &SchemaSet,
    msg: &Msg,
    fields: &Fields,
    prefix: &str,
    out: &mut Vec<u8>,
) -> Result<(), Refusal> {
    for field in &msg.fields {
        if field.label == Label::Required && fields.len(field.number) == 0 {
            let path = child(prefix, &field.name);
            return Err(Refusal::Absent {
                at: path.clone(),
                path,
            });
        }
    }
    for (&number, list) in &fields.known {
        let Some(field) = msg.fields.iter().find(|f| f.number == number) else {
            continue;
        };
        let here = child(prefix, &field.name);
        let tag = (number << 3) | wire_of(field.kind);
        if field.label == Label::Repeated {
            if list.is_empty() {
                continue;
            }
            if packed(msg, field, &here)? {
                let mut run = Vec::new();
                for (i, held) in list.iter().enumerate() {
                    put_value(schema, field, held, &mut run, &format!("{here}[{i}]"))?;
                }
                put_varint(out, (number << 3) | WIRE_LEN);
                put_len(out, &run);
            } else {
                for (i, held) in list.iter().enumerate() {
                    put_varint(out, tag);
                    put_value(schema, field, held, out, &format!("{here}[{i}]"))?;
                }
            }
        } else if let Some(held) = list.last() {
            if has_presence(msg, field) || !is_default(held) {
                put_varint(out, tag);
                put_value(schema, field, held, out, &here)?;
            }
        }
    }
    out.extend_from_slice(&fields.kept);
    Ok(())
}

// ---- decoding -------------------------------------------------------------

/// The values of a decoded message, as a parser keeps them.
fn fields_of(schema: &SchemaSet, msg: &Msg, listing: &[DecodedField], bytes: &[u8]) -> Fields {
    let mut fields = Fields::default();
    for entry in listing {
        let field = msg.fields.iter().find(|f| f.number == entry.number);
        let held = field.and_then(|f| held_from(schema, f, &entry.value, bytes));
        let (Some(field), Some(held)) = (field, held) else {
            fields
                .kept
                .extend_from_slice(bytes.get(entry.start..entry.end).unwrap_or_default());
            continue;
        };
        put_decoded(schema, msg, &mut fields, field, held);
    }
    fields
}

/// A decoded value as its field holds it; `None` for a value the payload
/// keeps as its wire bytes (an unknown field, a map entry).
fn held_from(schema: &SchemaSet, field: &Fld, value: &Value, bytes: &[u8]) -> Option<Held> {
    if matches!(field.kind, FieldKind::Map { .. } | FieldKind::Group) {
        return None;
    }
    Some(match value {
        Value::Signed(v) => Held::Int(*v),
        Value::Unsigned(v) => Held::Uint(*v),
        Value::Float(v) => Held::Float(*v),
        Value::Double(v) => Held::Double(*v),
        Value::Bool(v) => Held::Bool(*v),
        Value::Text(v) => Held::Text(v.clone()),
        Value::Bytes(v) => Held::Bytes(v.clone()),
        Value::Enum { number, .. } => Held::Int(i64::from(*number)),
        Value::Message(inner) => {
            let FieldKind::Message(m) = field.kind else {
                return None;
            };
            Held::Message(fields_of(schema, schema.linked_at(m)?, inner, bytes))
        }
        Value::Unknown(_) => return None,
    })
}

/// One decoded occurrence into the message: an element appended to a repeated
/// field, a message merged into the one there, any other value replacing it.
fn put_decoded(schema: &SchemaSet, msg: &Msg, fields: &mut Fields, field: &Fld, held: Held) {
    if field.label == Label::Repeated {
        fields.known.entry(field.number).or_default().push(held);
        return;
    }
    fields.clear_oneof(msg, field);
    let list = fields.known.entry(field.number).or_default();
    let inner = match field.kind {
        FieldKind::Message(m) => schema.linked_at(m),
        _ => None,
    };
    match (inner, held) {
        (Some(inner), Held::Message(more)) => {
            if let Some(Held::Message(there)) = list.last_mut() {
                merge(schema, inner, there, more);
            } else {
                list.clear();
                list.push(Held::Message(more));
            }
        }
        (_, held) => {
            list.clear();
            list.push(held);
        }
    }
}

/// `more` merged into `there`, as a parser merges a message field that occurs
/// twice.
fn merge(schema: &SchemaSet, msg: &Msg, there: &mut Fields, more: Fields) {
    for (number, list) in more.known {
        let Some(field) = msg.fields.iter().find(|f| f.number == number) else {
            continue;
        };
        for held in list {
            put_decoded(schema, msg, there, field, held);
        }
    }
    there.kept.extend_from_slice(&more.kept);
}

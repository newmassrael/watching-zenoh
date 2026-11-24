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
//! Written by the workspace's one protobuf writer ([`crate::proto_write`]), the
//! one the capture crate's writer of values given as JSON writes through too:
//! fields in ascending number; a field without presence left out at its default
//! (a `float` or `double` whose bits are all zero, so `-0.0` is written); a
//! repeated numeric, `bool` or enum field packed in proto3 unless it says
//! `[packed = false]` and unpacked in proto2 unless it says `[packed = true]`;
//! `int32` and an enum sign-extended (a negative one is ten bytes), `sint32` and
//! `sint64` zigzagged. A proto2 `required` field that is not set refuses the
//! encoding.
//!
//! ## Narrowing
//!
//! An integer is held to its field's type unless the payload was made for a
//! receiver that links nanopb ([`Payload::narrowed`] with
//! [`Narrowing::NanopbIntSize`]): then a varint field takes only what the C
//! integer its `(nanopb).int_size` chooses can hold, and a field whose nanopb
//! options leave that unknown (an `int_size` the reader cannot read, a
//! `type_override`) takes no integer at all. The range is judged where the value
//! is set, so a value the receiver would refuse is refused to the program.
//! Bytes a payload decodes are taken as they are.
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
use crate::proto_parse::{Label, ScalarKind, Syntax};
use crate::proto_range::{RangeRefusal, RangeSource, ValueRange};
use crate::proto_schema::{FieldKind, Fld, Msg};
use crate::proto_write::{self, has_presence, Narrowing, Wire};

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
    /// The schema states an option of a field the writer cannot act on: a
    /// `packed` it cannot follow, or, for a payload that narrows by nanopb, an
    /// integer field whose nanopb options leave its range unknown.
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
#[derive(Clone, Copy)]
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

/// The steps a path takes from a message, judged whole when it is made ([`route`]) and walked
/// again from its text as often as a call needs, so that no list of them is kept.
#[derive(Clone, Copy)]
struct Route<'s, 'p> {
    schema: &'s SchemaSet,
    root: &'s Msg,
    path: &'p str,
    /// How many steps the path takes.
    parts: usize,
    /// The last step: the field the path names.
    last: Step<'s>,
}

impl<'s, 'p> Route<'s, 'p> {
    /// Every step but the last, from the root: the messages that hold the field.
    fn inner(&self) -> Inner<'s, 'p> {
        Inner {
            schema: self.schema,
            holder: self.root,
            parts: self.path.split('.'),
            end: 0,
            first: true,
            left: self.parts.saturating_sub(1),
        }
    }

    /// Every step, the last included.
    fn all(&self) -> core::iter::Chain<Inner<'s, 'p>, core::iter::Once<Step<'s>>> {
        self.inner().chain(core::iter::once(self.last))
    }
}

/// The steps of a [`Route`] before its last, read again from the path's text, which [`route`]
/// judged: a part that does not read is never met, and ends the walk where it would be.
struct Inner<'s, 'p> {
    schema: &'s SchemaSet,
    holder: &'s Msg,
    parts: core::str::Split<'p, char>,
    end: usize,
    first: bool,
    left: usize,
}

impl<'s> Iterator for Inner<'s, '_> {
    type Item = Step<'s>;

    fn next(&mut self) -> Option<Step<'s>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let part = self.parts.next()?;
        self.end += part.len() + usize::from(!self.first);
        self.first = false;
        let (name, index) = segment(part)?;
        let field = self.holder.fields.iter().find(|f| f.name == name)?;
        let step = Step {
            holder: self.holder,
            field,
            index,
            end: self.end,
        };
        self.holder = match field.kind {
            FieldKind::Message(inner) => self.schema.linked_at(inner)?,
            _ => return None,
        };
        Some(step)
    }
}

/// The route `path` takes from the message `root`, every part of it judged.
fn route<'s, 'p>(
    schema: &'s SchemaSet,
    root: &'s Msg,
    path: &'p str,
) -> Result<Route<'s, 'p>, Refusal> {
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
    let mut last = None;
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
        last = Some(Step {
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
    // `split` yields at least one part, and an empty one is refused above.
    let Some(last) = last else {
        return Err(refused(String::from("the path is empty")));
    };
    Ok(Route {
        schema,
        root,
        path,
        parts,
        last,
    })
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

fn unsigned(kind: ScalarKind) -> bool {
    matches!(
        kind,
        ScalarKind::Uint32 | ScalarKind::Uint64 | ScalarKind::Fixed32 | ScalarKind::Fixed64
    )
}

/// The integers field `field` of `holder` takes under `narrowing`, for an
/// integer kind; the refusal when its nanopb options leave the range unknown.
fn integer_range(
    schema: &SchemaSet,
    holder: &Msg,
    field: &Fld,
    kind: ScalarKind,
    narrowing: Narrowing,
    path: &str,
) -> Result<ValueRange, Refusal> {
    match narrowing.field_range(schema, holder, field) {
        Ok(range) => Ok(range),
        Err(RangeRefusal::UnmodelledOption) => Err(Refusal::Schema {
            path: String::from(path),
            reason: format!(
                "the field's nanopb options (an int_size this reader cannot read, or a \
                 type_override) leave unknown the range of the values nanopb takes for this {}, \
                 so no value is set",
                kind.keyword()
            ),
        }),
        // An integer kind always has its type's range; the type is the honest
        // bound should the judgement ever say otherwise.
        Err(RangeRefusal::NotAnInteger | RangeRefusal::Enum | RangeRefusal::Map) => {
            ValueRange::of_type(kind).ok_or_else(|| Refusal::Type {
                path: String::from(path),
                reason: format!("the field is {}, which holds no integer", kind.keyword()),
            })
        }
    }
}

/// The value `given` as field `field` of `holder` holds it, an integer held to
/// the range `narrowing` chooses.
fn held_of(
    schema: &SchemaSet,
    holder: &Msg,
    field: &Fld,
    given: Given<'_>,
    narrowing: Narrowing,
    path: &str,
) -> Result<Held, Refusal> {
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
            if ValueRange::of_type(kind).is_some() {
                let Some(v) = integer else {
                    return Err(mismatch());
                };
                let ValueRange { low, high, source } =
                    integer_range(schema, holder, field, kind, narrowing, path)?;
                if !(low..=high).contains(&v) {
                    return Err(range(match source {
                        RangeSource::Type => format!(
                            "{v} does not fit a {}, whose values are {low} to {high}",
                            kind.keyword()
                        ),
                        RangeSource::NanopbIntSize { bits } => format!(
                            "{v} does not fit a {} with (nanopb).int_size = IS_{bits}, whose \
                             values are {low} to {high}",
                            kind.keyword()
                        ),
                    }));
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
    narrowing: Narrowing,
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
    /// ([`SchemaSet::message`]), whose integers are held to their fields' types.
    pub fn new(schema: S, message: SchemaMessage) -> Self {
        Self::narrowed(schema, message, Narrowing::Type)
    }

    /// An empty payload of `message` whose integers are held to the range
    /// `narrowing` chooses: [`Narrowing::NanopbIntSize`] for a receiver that
    /// links nanopb. See the module documentation.
    pub fn narrowed(schema: S, message: SchemaMessage, narrowing: Narrowing) -> Self {
        Self {
            schema,
            message,
            fields: Fields::default(),
            narrowing,
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
    /// [`Refusal::Path`], [`Refusal::Type`] or [`Refusal::Range`], and
    /// [`Refusal::Schema`] for an integer field whose range the payload's
    /// narrowing cannot know; the payload is then as it was.
    pub fn set(&mut self, path: &str, value: Given<'_>) -> Result<(), Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let route = route(schema, schema.linked(self.message), path)?;
        let last = route.last;
        if last.repeated() && last.index.is_none() {
            return Err(list_named(path, &last));
        }
        let held = held_of(schema, last.holder, last.field, value, self.narrowing, path)?;
        reach(&self.fields, route.all(), path)?;
        let mut fields = &mut self.fields;
        for step in route.inner() {
            fields = descend(fields, &step);
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
        let route = route(schema, schema.linked(self.message), path)?;
        let last = route.last;
        if last.repeated() && last.index.is_none() {
            return Err(list_named(path, &last));
        }
        let Some(fields) = holder_of(&self.fields, route.inner(), path)? else {
            return Err(absent(path, route.inner(), &self.fields));
        };
        let index = last.index.unwrap_or(0);
        if let Some(held) = fields.value(last.field.number, index) {
            return got(schema, last.field, view(held), wanted, path);
        }
        if last.index.is_some() {
            return Err(past_end(path, &last, fields.len(last.field.number)));
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
        let route = route(schema, schema.linked(self.message), path)?;
        let last = route.last;
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
        Ok(holder_of(&self.fields, route.inner(), path)?.map_or(0, |f| f.len(last.field.number)))
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
        let route = route(schema, schema.linked(self.message), path)?;
        let last = route.last;
        let Some(holder) = holder_of(&self.fields, route.inner(), path)? else {
            return Ok(());
        };
        let len = holder.len(last.field.number);
        if let Some(index) = last.index {
            if index >= len {
                return Err(past_end(path, &last, len));
            }
        }
        let mut fields = &mut self.fields;
        for step in route.inner() {
            fields = descend(fields, &step);
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

    /// Clear every field: the payload is as [`Payload::new`] or
    /// [`Payload::narrowed`] made it, its narrowing kept.
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
fn holder_of<'f, 's>(
    fields: &'f Fields,
    inner: impl Iterator<Item = Step<'s>>,
    path: &str,
) -> Result<Option<&'f Fields>, Refusal> {
    let mut at = fields;
    for step in inner {
        let index = step.index.unwrap_or(0);
        match at.value(step.field.number, index) {
            Some(Held::Message(next)) => at = next,
            Some(_) => return Ok(None),
            None if step.index.is_some() => {
                return Err(past_end(path, &step, at.len(step.field.number)))
            }
            None => return Ok(None),
        }
    }
    Ok(Some(at))
}

/// The refusal of a read whose holder is not there, naming the first part of
/// the path that is absent.
fn absent<'s>(path: &str, inner: impl Iterator<Item = Step<'s>>, fields: &Fields) -> Refusal {
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
fn reach<'s>(
    fields: &Fields,
    steps: impl Iterator<Item = Step<'s>>,
    path: &str,
) -> Result<(), Refusal> {
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

/// The wire form of one value of `field`, from the one writer.
fn wire_of<'h>(
    schema: &SchemaSet,
    field: &Fld,
    held: &'h Held,
    path: &str,
) -> Result<Wire<'h>, Refusal> {
    let integer =
        |kind: ScalarKind, v: i128| ValueRange::of_type(kind).map(|_| Wire::integer(kind, v));
    let wire = match (field.kind, held) {
        (FieldKind::Scalar(kind), Held::Int(v)) => integer(kind, i128::from(*v)),
        (FieldKind::Scalar(kind), Held::Uint(v)) => integer(kind, i128::from(*v)),
        (FieldKind::Enum(_), Held::Int(v)) => i32::try_from(*v).ok().map(Wire::enum_number),
        (FieldKind::Scalar(ScalarKind::Float), Held::Float(v)) => Some(Wire::Fixed32(v.to_bits())),
        (FieldKind::Scalar(ScalarKind::Double), Held::Double(v)) => {
            Some(Wire::Fixed64(v.to_bits()))
        }
        (FieldKind::Scalar(ScalarKind::Bool), Held::Bool(v)) => Some(Wire::Varint(u64::from(*v))),
        (FieldKind::Scalar(ScalarKind::String), Held::Text(v)) => {
            Some(Wire::delimited(v.as_bytes()))
        }
        (FieldKind::Scalar(ScalarKind::Bytes), Held::Bytes(v)) => {
            Some(Wire::delimited(v.as_slice()))
        }
        (FieldKind::Message(m), Held::Message(inner)) => {
            let Some(msg) = schema.linked_at(m) else {
                return Err(Refusal::Schema {
                    path: String::from(path),
                    reason: String::from("the field's message is not in the schema set"),
                });
            };
            let mut body = Vec::new();
            write_message(schema, msg, inner, path, &mut body)?;
            Some(Wire::delimited(body))
        }
        _ => None,
    };
    wire.ok_or_else(|| Refusal::Type {
        path: String::from(path),
        reason: format!("the field is {}", type_name(schema, field)),
    })
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
        if field.label == Label::Repeated {
            if list.is_empty() {
                continue;
            }
            let packed = proto_write::packed(msg, field).map_err(|_| Refusal::Schema {
                path: here.clone(),
                reason: format!(
                    "`{}` states `packed`, which takes `true` or `false`, and `true` only on a \
                     repeated numeric, bool or enum field",
                    field.name
                ),
            })?;
            let mut elements = Vec::with_capacity(list.len());
            for (i, held) in list.iter().enumerate() {
                elements.push(wire_of(schema, field, held, &format!("{here}[{i}]"))?);
            }
            proto_write::put_repeated(out, number, packed, &elements);
        } else if let Some(held) = list.last() {
            let wire = wire_of(schema, field, held, &here)?;
            proto_write::put_singular(out, number, has_presence(msg, field), &wire);
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

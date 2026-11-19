// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! INSTANCE KEYS: which instance of a message a sample is, read from fields of
//! its payload.
//!
//! A message is published on one key expression whatever its instance, so the
//! key expression cannot say which instance a sample is: fields of the payload
//! do. A [`Keyer`] names up to the build's `INSTANCE_KEY_FIELDS` such fields of
//! one message (an integer, an enumeration or a string, read by the schema
//! through [`crate::proto_decode`]) and the values each may take. The INSTANCE
//! INDEX of a sample is the position of its field values in the product of
//! those lists, row-major: with lists of lengths `n0, n1, ...` and positions
//! `p0, p1, ...`, the index is `((p0 * n1) + p1) * n2 + ...`, so the last field
//! varies fastest. It is never on the wire.
//!
//! The lists are a node's own, per direction: a publisher states the values it
//! sends, a subscriber the values it receives, and each makes its own keyer, so
//! the same sample may have one index at its publisher and another at a
//! subscriber. Which values each node lists is the deployment's catalogue, not
//! this module's.
//!
//! # What is not an instance
//!
//! A sample is DROPPED, counted by reason ([`Counts`]) and never judged when
//!
//! * its payload is not a message of the schema ([`Refusal::Undecodable`]);
//! * a key field that has presence (a proto2 field, a proto3 `optional`, a
//!   member of a oneof, a field of a message field that is absent) is not in it
//!   ([`Refusal::Absent`]). A field without presence that is not on the wire
//!   reads as its default, 0 or the empty string, as every protobuf reader reads
//!   it;
//! * a value is in no list ([`Refusal::NotListed`]).
//!
//! The drops are reported at a bounded rate: the first drop after a quiet
//! interval carries a [`Report`] of how many were dropped since the last one,
//! and [`Keyer::flush`] gives the report of drops still held once the interval
//! has passed. Where the report goes (an event of the node's log, a counter the
//! program reads) is the caller's.
//!
//! # Per-instance state
//!
//! The index is the STREAM of the end-to-end protection: the receiver's stream
//! ([`judge`]) and the sender's counter stream ([`protect`]), so each instance
//! is judged and counted apart. A receiver that keeps its streams per sender is
//! refused: an instance and a sender are two ways to name one stream, and a
//! message has one of them. The last value of each instance is kept in storage
//! the caller gives ([`LastValues`]).
//!
//! # The description
//!
//! A JSON document, read by the workspace's reader as a frame profile is:
//!
//! ```text
//! {
//!   "message": "pkg.Reading",
//!   "fields": [
//!     {"path": "zone", "values": [3, 7, {"range": [20, 22]}]},
//!     {"path": "place.side", "values": [1, 2]},
//!   ],
//!   "report_interval_ms": 1000
//! }
//! ```
//!
//! `message` is the full name of the payload's message. A `path` names a field
//! by its name, and a field inside a message field by the holder's name, a
//! dot and its own. An integer or enumeration field's values are integers
//! (decimal or `0x` hex, an enumeration by its number) or inclusive ranges, and
//! each must fit the field's type; a string field's values are strings. A value
//! listed twice is refused. `report_interval_ms` is how long the reports of
//! drops are apart, [`DEFAULT_REPORT_INTERVAL_MS`] when it is not stated and
//! every drop when it is 0.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use wz_session_core::json5::Json5Value;

use crate::e2e_profile::{
    array, at, check_keys, child, describe, object, optional, read_json, required, DocError,
};
use crate::e2e_receiver::{ReceiveError, Receiver, Status, Verdict};
use crate::e2e_stream_sender::{Protected, SendError, StreamSender};
use crate::proto_decode::{DecodedField, SchemaMessage, SchemaSet, Value, MAX_DECODE_DEPTH};
use crate::proto_parse::{Label, ScalarKind, Syntax};
use crate::proto_schema::{FieldKind, Msg, ProtoDiagnostic, ProtoFile};

/// How long the reports of drops are apart when the description does not say.
pub const DEFAULT_REPORT_INTERVAL_MS: u64 = 1_000;

/// What the build allows one keyer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most key fields a message names: the build's `INSTANCE_KEY_FIELDS`.
    pub fields: usize,
    /// The most instances, the product of the lists' lengths: the build's
    /// `INSTANCES_PER_MESSAGE`.
    pub instances: usize,
}

/// One value a key field may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyValue {
    /// The value of an integer field, or the number of an enumeration value.
    Integer(i128),
    /// The value of a string field, compared byte for byte.
    Text(String),
}

impl fmt::Display for KeyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(v) => write!(f, "{v}"),
            Self::Text(s) => write!(f, "{s:?}"),
        }
    }
}

/// What a key field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// An integer, or an enumeration by its number, within these bounds.
    Integer { min: i128, max: i128 },
    /// A string.
    Text,
}

/// One key field, resolved against the schema.
#[derive(Debug, Clone)]
struct KeyField {
    /// The field numbers along the path, the holder's first.
    numbers: Vec<u64>,
    kind: Kind,
    /// Whether an absent field is a fact (see the module documentation) rather
    /// than its default value.
    presence: bool,
    /// The list, in the order given: a value's position is its index here.
    values: Vec<KeyValue>,
}

impl KeyField {
    /// The position of a decoded value in the list.
    fn position(&self, value: &Value) -> Option<usize> {
        let wanted = match value {
            Value::Signed(v) => Wanted::Integer(i128::from(*v)),
            Value::Unsigned(v) => Wanted::Integer(i128::from(*v)),
            Value::Enum { number, .. } => Wanted::Integer(i128::from(*number)),
            Value::Text(s) => Wanted::Text(s),
            _ => return None,
        };
        self.find(wanted)
    }

    /// The position of the value a field without presence reads as when it is
    /// not on the wire.
    fn default_position(&self) -> Option<usize> {
        match self.kind {
            Kind::Integer { .. } => self.find(Wanted::Integer(0)),
            Kind::Text => self.find(Wanted::Text("")),
        }
    }

    fn find(&self, wanted: Wanted<'_>) -> Option<usize> {
        self.values.iter().position(|v| match (v, wanted) {
            (KeyValue::Integer(a), Wanted::Integer(b)) => *a == b,
            (KeyValue::Text(a), Wanted::Text(b)) => a == b,
            _ => false,
        })
    }
}

/// A decoded value as the lists are searched for it, without a copy.
#[derive(Clone, Copy)]
enum Wanted<'v> {
    Integer(i128),
    Text(&'v str),
}

/// Why a sample has no instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The payload is not a message of the schema, or the frame is shorter
    /// than the header in front of it.
    Undecodable,
    /// The key field at this position of the description has presence and is
    /// not in the payload.
    Absent {
        /// The key field, in the order the description lists them.
        field: usize,
    },
    /// The value of the key field at this position is in no list.
    NotListed {
        /// The key field, in the order the description lists them.
        field: usize,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undecodable => f.write_str("the payload is not a message of the schema"),
            Self::Absent { field } => write!(f, "key field {field} is not in the payload"),
            Self::NotListed { field } => write!(f, "the value of key field {field} is not listed"),
        }
    }
}

/// How many drops a report covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// The drops since the last report, the one that carries it included.
    pub dropped: u64,
}

/// A sample that was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dropped {
    /// Why.
    pub refusal: Refusal,
    /// The report this drop is the one to carry, when one is due.
    pub report: Option<Report>,
}

/// How many samples were dropped, by reason. Each saturates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Payloads that are not a message of the schema.
    pub undecodable: u64,
    /// Payloads without a key field that has presence.
    pub absent: u64,
    /// Payloads whose values are in no list.
    pub not_listed: u64,
}

/// Why a keyer was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewError {
    /// The schema files are refused.
    Schema(ProtoDiagnostic),
    /// The description is refused, at the place its path names.
    Description(DocError),
    /// More key fields than the build allows.
    TooManyFields {
        /// The fields the description names.
        fields: usize,
        /// The most the build allows.
        limit: usize,
    },
    /// The lists make more instances than the build allows.
    TooManyInstances {
        /// The most the build allows.
        limit: usize,
    },
}

impl fmt::Display for NewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(d) => write!(f, "schema: {d}"),
            Self::Description(e) => write!(f, "description: {e}"),
            Self::TooManyFields { fields, limit } => write!(
                f,
                "{fields} key fields are named, and the build allows at most {limit}"
            ),
            Self::TooManyInstances { limit } => write!(
                f,
                "the lists make more than the {limit} instances the build allows"
            ),
        }
    }
}

/// The instance index of one message's samples, read from fields of the
/// payload.
#[derive(Debug)]
pub struct Keyer {
    schema: SchemaSet,
    message: SchemaMessage,
    fields: Vec<KeyField>,
    instances: usize,
    report_interval_ms: u64,
    counts: Counts,
    /// The drops since the last report.
    pending: u64,
    /// When the last report was given; `None` before the first.
    last_report_ms: Option<u64>,
}

impl Keyer {
    /// A keyer of the message the description names, over the schema in
    /// `files` (every file is read, each with what it imports), within the
    /// build's `limits`.
    ///
    /// # Errors
    ///
    /// The schema's diagnostic, the description's refusal at its path, or a
    /// limit the description exceeds.
    pub fn new(
        files: &[ProtoFile<'_>],
        description: &str,
        limits: Limits,
    ) -> Result<Self, NewError> {
        let schema = SchemaSet::read(files).map_err(NewError::Schema)?;
        let doc = read_json(description).map_err(NewError::Description)?;
        let entries = object(&doc, "").map_err(NewError::Description)?;
        check_keys(entries, &["message", "fields", "report_interval_ms"], "")
            .map_err(NewError::Description)?;
        let name = text(
            required(entries, "message", "").map_err(NewError::Description)?,
            "/message",
        )?;
        let message = schema
            .message(name)
            .map_err(|why| NewError::Description(DocError::invalid("/message", why)))?;
        let report_interval_ms = match optional(entries, "report_interval_ms") {
            None => DEFAULT_REPORT_INTERVAL_MS,
            Some(value) => interval(value, "/report_interval_ms")?,
        };
        let listed = array(
            required(entries, "fields", "").map_err(NewError::Description)?,
            "/fields",
        )
        .map_err(NewError::Description)?;
        if listed.is_empty() {
            return Err(NewError::Description(DocError::invalid(
                "/fields",
                "a keyer names at least one key field",
            )));
        }
        if listed.len() > limits.fields {
            return Err(NewError::TooManyFields {
                fields: listed.len(),
                limit: limits.fields,
            });
        }
        let mut fields = Vec::with_capacity(listed.len());
        let mut instances: usize = 1;
        for (i, entry) in listed.iter().enumerate() {
            let field = key_field(&schema, message, entry, &at("/fields", i), limits)?;
            instances = instances
                .checked_mul(field.values.len())
                .filter(|&n| n <= limits.instances)
                .ok_or(NewError::TooManyInstances {
                    limit: limits.instances,
                })?;
            fields.push(field);
        }
        Ok(Self {
            schema,
            message,
            fields,
            instances,
            report_interval_ms,
            counts: Counts::default(),
            pending: 0,
            last_report_ms: None,
        })
    }

    /// How many instances the lists make.
    pub fn instances(&self) -> usize {
        self.instances
    }

    /// How many key fields it reads.
    pub fn fields(&self) -> usize {
        self.fields.len()
    }

    /// The full name of the message it reads.
    pub fn message_name(&self) -> &str {
        self.schema.message_name(self.message)
    }

    /// How long its reports of drops are apart.
    pub fn report_interval_ms(&self) -> u64 {
        self.report_interval_ms
    }

    /// The samples dropped so far.
    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// The values of the key fields an instance stands for, in the order the
    /// description lists the fields; `None` for an index past the last.
    pub fn values_of(&self, instance: usize) -> Option<Vec<&KeyValue>> {
        if instance >= self.instances {
            return None;
        }
        let mut rest = instance;
        let mut out: Vec<&KeyValue> = Vec::with_capacity(self.fields.len());
        for field in self.fields.iter().rev() {
            let n = field.values.len();
            out.push(&field.values[rest % n]);
            rest /= n;
        }
        out.reverse();
        Some(out)
    }

    /// The instance `payload` is, without counting anything.
    ///
    /// # Errors
    ///
    /// Why it is none.
    pub fn instance_of(&self, payload: &[u8]) -> Result<usize, Refusal> {
        let decoded = self
            .schema
            .decode(self.message, payload)
            .map_err(|_| Refusal::Undecodable)?;
        let mut index = 0usize;
        for (i, field) in self.fields.iter().enumerate() {
            let position = match lookup(&decoded, &field.numbers) {
                Lookup::Found(value) => field.position(value),
                Lookup::LeafMissing if !field.presence => field.default_position(),
                Lookup::LeafMissing | Lookup::HolderMissing => {
                    return Err(Refusal::Absent { field: i })
                }
            };
            let Some(position) = position else {
                return Err(Refusal::NotListed { field: i });
            };
            index = index * field.values.len() + position;
        }
        Ok(index)
    }

    /// The instance `payload` is, received or about to be sent at `now_ms`; a
    /// payload that is none is counted, and carries the report when one is due.
    ///
    /// # Errors
    ///
    /// The drop.
    pub fn index(&mut self, payload: &[u8], now_ms: u64) -> Result<usize, Dropped> {
        self.instance_of(payload)
            .map_err(|refusal| self.refuse(refusal, now_ms))
    }

    /// The report of the drops held since the last one, when the interval has
    /// passed at `now_ms`; `None` when there are none or it has not.
    pub fn flush(&mut self, now_ms: u64) -> Option<Report> {
        self.report_due(now_ms)
    }

    fn refuse(&mut self, refusal: Refusal, now_ms: u64) -> Dropped {
        let counter = match refusal {
            Refusal::Undecodable => &mut self.counts.undecodable,
            Refusal::Absent { .. } => &mut self.counts.absent,
            Refusal::NotListed { .. } => &mut self.counts.not_listed,
        };
        *counter = counter.saturating_add(1);
        self.pending = self.pending.saturating_add(1);
        Dropped {
            refusal,
            report: self.report_due(now_ms),
        }
    }

    fn report_due(&mut self, now_ms: u64) -> Option<Report> {
        if self.pending == 0 {
            return None;
        }
        if let Some(last) = self.last_report_ms {
            // A clock that steps back starts the interval again from where it
            // now reads, rather than holding every report until it catches up.
            if now_ms < last {
                self.last_report_ms = Some(now_ms);
                return None;
            }
            if now_ms - last < self.report_interval_ms {
                return None;
            }
        }
        let report = Report {
            dropped: self.pending,
        };
        self.pending = 0;
        self.last_report_ms = Some(now_ms);
        Some(report)
    }
}

/// The text of a string member, or the refusal at `path`.
fn text<'v>(value: &'v Json5Value, path: &str) -> Result<&'v str, NewError> {
    match value {
        Json5Value::String(s) => Ok(s),
        other => Err(NewError::Description(DocError::invalid(
            path,
            format!("expected a string, found {}", describe(other)),
        ))),
    }
}

/// An integer written as JSON number text: decimal or `0x` hex, with a sign.
fn integer_of(text: &str) -> Option<i128> {
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let magnitude: u64 = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
            u64::from_str_radix(hex, 16).ok()?
        }
        Some(_) => return None,
        None if !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()) => {
            body.parse().ok()?
        }
        None => return None,
    };
    let magnitude = i128::from(magnitude);
    Some(if negative { -magnitude } else { magnitude })
}

/// The integer a member holds, or the refusal at `path`.
fn integer(value: &Json5Value, path: &str) -> Result<i128, NewError> {
    let refused = |reason: String| NewError::Description(DocError::invalid(path, reason));
    match value {
        Json5Value::Number(text) => integer_of(text)
            .ok_or_else(|| refused(format!("`{text}` is not an integer of at most 64 bits"))),
        other => Err(refused(format!(
            "expected a number, found {}",
            describe(other)
        ))),
    }
}

fn interval(value: &Json5Value, path: &str) -> Result<u64, NewError> {
    let n = integer(value, path)?;
    u64::try_from(n).map_err(|_| {
        NewError::Description(DocError::invalid(
            path,
            format!("{n} is not a number of milliseconds"),
        ))
    })
}

/// The bounds of an integer scalar, or `None` for a scalar that is not one.
fn integer_bounds(kind: ScalarKind) -> Option<(i128, i128)> {
    Some(match kind {
        ScalarKind::Int32 | ScalarKind::Sint32 | ScalarKind::Sfixed32 => {
            (i128::from(i32::MIN), i128::from(i32::MAX))
        }
        ScalarKind::Int64 | ScalarKind::Sint64 | ScalarKind::Sfixed64 => {
            (i128::from(i64::MIN), i128::from(i64::MAX))
        }
        ScalarKind::Uint32 | ScalarKind::Fixed32 => (0, i128::from(u32::MAX)),
        ScalarKind::Uint64 | ScalarKind::Fixed64 => (0, i128::from(u64::MAX)),
        _ => return None,
    })
}

/// One key field of the description, resolved against the message.
fn key_field(
    schema: &SchemaSet,
    message: SchemaMessage,
    entry: &Json5Value,
    path: &str,
    limits: Limits,
) -> Result<KeyField, NewError> {
    let entries = object(entry, path).map_err(NewError::Description)?;
    check_keys(entries, &["path", "values"], path).map_err(NewError::Description)?;
    let at_path = child(path, "path");
    let field_path = text(
        required(entries, "path", path).map_err(NewError::Description)?,
        &at_path,
    )?;
    let (numbers, kind, presence) = resolve(schema, message, field_path, &at_path)?;
    let values_path = child(path, "values");
    let listed = array(
        required(entries, "values", path).map_err(NewError::Description)?,
        &values_path,
    )
    .map_err(NewError::Description)?;
    if listed.is_empty() {
        return Err(NewError::Description(DocError::invalid(
            values_path,
            "a key field lists at least one value",
        )));
    }
    let mut values: Vec<KeyValue> = Vec::new();
    for (i, item) in listed.iter().enumerate() {
        let item_path = at(&values_path, i);
        for value in values_of_item(item, &item_path, kind, limits)? {
            if values.contains(&value) {
                return Err(NewError::Description(DocError::invalid(
                    item_path,
                    format!("the value {value} is listed twice"),
                )));
            }
            if values.len() == limits.instances {
                return Err(NewError::TooManyInstances {
                    limit: limits.instances,
                });
            }
            values.push(value);
        }
    }
    Ok(KeyField {
        numbers,
        kind,
        presence,
        values,
    })
}

/// The values one item of a list stands for: one value, or the values of a
/// range.
fn values_of_item(
    item: &Json5Value,
    path: &str,
    kind: Kind,
    limits: Limits,
) -> Result<Vec<KeyValue>, NewError> {
    let refused = |reason: String| NewError::Description(DocError::invalid(path, reason));
    match (kind, item) {
        (Kind::Text, Json5Value::String(s)) => Ok(alloc::vec![KeyValue::Text(s.clone())]),
        (Kind::Text, other) => Err(refused(format!(
            "a string field's value is a string, found {}",
            describe(other)
        ))),
        (Kind::Integer { min, max }, Json5Value::Number(_)) => {
            let v = integer(item, path)?;
            in_bounds(v, min, max, path)?;
            Ok(alloc::vec![KeyValue::Integer(v)])
        }
        (Kind::Integer { min, max }, Json5Value::Object(entries)) => {
            check_keys(entries, &["range"], path).map_err(NewError::Description)?;
            let range_path = child(path, "range");
            let ends = array(
                required(entries, "range", path).map_err(NewError::Description)?,
                &range_path,
            )
            .map_err(NewError::Description)?;
            let [low, high] = ends else {
                return Err(NewError::Description(DocError::invalid(
                    range_path,
                    "a range is two integers, the lowest and the highest value",
                )));
            };
            let low = integer(low, &at(&range_path, 0))?;
            let high = integer(high, &at(&range_path, 1))?;
            in_bounds(low, min, max, &at(&range_path, 0))?;
            in_bounds(high, min, max, &at(&range_path, 1))?;
            if low > high {
                return Err(NewError::Description(DocError::invalid(
                    range_path,
                    format!("the range starts at {low}, above where it ends, {high}"),
                )));
            }
            // Refused before it is written out, so a wide range costs nothing.
            if high - low >= limits.instances as i128 {
                return Err(NewError::TooManyInstances {
                    limit: limits.instances,
                });
            }
            Ok((low..=high).map(KeyValue::Integer).collect())
        }
        (Kind::Integer { .. }, other) => Err(refused(format!(
            "an integer field's value is a number or {{\"range\": [low, high]}}, found {}",
            describe(other)
        ))),
    }
}

fn in_bounds(v: i128, min: i128, max: i128, path: &str) -> Result<(), NewError> {
    if !(min..=max).contains(&v) {
        return Err(NewError::Description(DocError::invalid(
            path,
            format!("{v} does not fit the field, whose values are {min} to {max}"),
        )));
    }
    Ok(())
}

/// The field numbers along `path` in `message`, what the last field holds and
/// whether it has presence.
fn resolve(
    schema: &SchemaSet,
    message: SchemaMessage,
    path: &str,
    at_path: &str,
) -> Result<(Vec<u64>, Kind, bool), NewError> {
    let refused = |reason: String| NewError::Description(DocError::invalid(at_path, reason));
    let names: Vec<&str> = path.split('.').collect();
    if names.iter().any(|n| n.is_empty()) {
        return Err(refused(format!(
            "`{path}` is not a field path: names joined by single dots"
        )));
    }
    if names.len() > MAX_DECODE_DEPTH {
        return Err(refused(format!(
            "`{path}` goes more than {MAX_DECODE_DEPTH} messages deep, past what a payload is read to"
        )));
    }
    let mut holder: &Msg = schema.linked(message);
    let mut numbers = Vec::with_capacity(names.len());
    for (depth, name) in names.iter().enumerate() {
        let Some(field) = holder.fields.iter().find(|f| f.name == *name) else {
            return Err(refused(format!(
                "the message `{}` has no field `{name}`",
                holder.full_name
            )));
        };
        if field.label == Label::Repeated {
            return Err(refused(format!(
                "`{name}` is repeated: a key field holds one value"
            )));
        }
        numbers.push(field.number);
        let last = depth + 1 == names.len();
        if !last {
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
            continue;
        }
        let kind = match field.kind {
            FieldKind::Enum(_) => Kind::Integer {
                min: i128::from(i32::MIN),
                max: i128::from(i32::MAX),
            },
            FieldKind::Scalar(ScalarKind::String) => Kind::Text,
            FieldKind::Scalar(scalar) => match integer_bounds(scalar) {
                Some((min, max)) => Kind::Integer { min, max },
                None => {
                    return Err(refused(format!(
                        "`{name}` is a {}: a key field is an integer, an enumeration or a string",
                        scalar.keyword()
                    )))
                }
            },
            _ => {
                return Err(refused(format!(
                    "`{name}` is a message, a map or a group: a key field is an integer, an \
                     enumeration or a string"
                )))
            }
        };
        let presence = field.label != Label::Implicit
            || field.oneof.is_some()
            || holder.syntax == Syntax::Proto2;
        return Ok((numbers, kind, presence));
    }
    // `split` yields at least one name, and the loop returns at the last.
    Err(refused(format!("`{path}` names no field")))
}

/// Where a field of a decoding is.
enum Lookup<'d> {
    Found(&'d Value),
    /// Its holder is there and the field is not.
    LeafMissing,
    /// A message field along the path is not there.
    HolderMissing,
}

/// The value at `numbers` in a decoding, as a protobuf reader merges it: the
/// last occurrence of a field wins, and the occurrences of a message field are
/// one message.
fn lookup<'d>(fields: &'d [DecodedField], numbers: &[u64]) -> Lookup<'d> {
    let Some((&first, rest)) = numbers.split_first() else {
        return Lookup::LeafMissing;
    };
    if rest.is_empty() {
        return fields
            .iter()
            .rev()
            .find(|f| f.number == first && !matches!(f.value, Value::Unknown(_)))
            .map_or(Lookup::LeafMissing, |f| Lookup::Found(&f.value));
    }
    let mut found = None;
    let mut leaf_missing = false;
    for f in fields.iter().filter(|f| f.number == first) {
        if let Value::Message(inner) = &f.value {
            match lookup(inner, rest) {
                Lookup::Found(value) => found = Some(value),
                Lookup::LeafMissing => leaf_missing = true,
                Lookup::HolderMissing => {}
            }
        }
    }
    match found {
        Some(value) => Lookup::Found(value),
        None if leaf_missing => Lookup::LeafMissing,
        None => Lookup::HolderMissing,
    }
}

/// Why the last values were not given their storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageTooSmall {
    /// The bytes the instances need, `None` when the product overflows.
    pub needed: Option<usize>,
    /// The bytes given.
    pub given: usize,
}

impl fmt::Display for StorageTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.needed {
            Some(needed) => write!(
                f,
                "the storage is {} bytes and the last values need {needed}",
                self.given
            ),
            None => f.write_str("the last values need more bytes than an address can count"),
        }
    }
}

/// Why a value was not kept as an instance's last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// An instance the storage has no room for.
    NoSuchInstance {
        /// The instance given.
        instance: usize,
        /// How many the storage holds.
        instances: usize,
    },
    /// A value longer than an instance's room.
    TooLong {
        /// The value's length.
        len: usize,
        /// The room each instance has.
        capacity: usize,
    },
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchInstance {
                instance,
                instances,
            } => write!(
                f,
                "instance {instance} is not one of the {instances} the storage holds"
            ),
            Self::TooLong { len, capacity } => write!(
                f,
                "a value of {len} bytes does not fit the {capacity} each instance has"
            ),
        }
    }
}

/// The last value of each instance, in storage the caller gives: `capacity`
/// bytes for each, the first instance's first.
#[derive(Debug)]
pub struct LastValues<S> {
    storage: S,
    capacity: usize,
    /// The length of each instance's value; `None` before its first.
    lens: Vec<Option<usize>>,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> LastValues<S> {
    /// Last values of `instances` instances, `capacity` bytes each, kept in
    /// `storage`.
    ///
    /// # Errors
    ///
    /// Storage of fewer than `instances * capacity` bytes.
    pub fn new(storage: S, instances: usize, capacity: usize) -> Result<Self, StorageTooSmall> {
        let given = storage.as_ref().len();
        let needed = instances.checked_mul(capacity);
        if !matches!(needed, Some(n) if n <= given) {
            return Err(StorageTooSmall { needed, given });
        }
        Ok(Self {
            storage,
            capacity,
            lens: alloc::vec![None; instances],
        })
    }

    /// How many instances it holds a value for.
    pub fn instances(&self) -> usize {
        self.lens.len()
    }

    /// The room each instance has.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Keep `value` as the last of `instance`.
    ///
    /// # Errors
    ///
    /// An instance it has no room for, or a value longer than the room; the
    /// value it held is kept.
    pub fn record(&mut self, instance: usize, value: &[u8]) -> Result<(), RecordError> {
        if instance >= self.lens.len() {
            return Err(RecordError::NoSuchInstance {
                instance,
                instances: self.lens.len(),
            });
        }
        if value.len() > self.capacity {
            return Err(RecordError::TooLong {
                len: value.len(),
                capacity: self.capacity,
            });
        }
        let start = instance * self.capacity;
        self.storage.as_mut()[start..start + value.len()].copy_from_slice(value);
        self.lens[instance] = Some(value.len());
        Ok(())
    }

    /// The last value of `instance`; `None` before its first, and for an
    /// instance it has no room for.
    pub fn last(&self, instance: usize) -> Option<&[u8]> {
        let len = (*self.lens.get(instance)?)?;
        let start = instance * self.capacity;
        Some(&self.storage.as_ref()[start..start + len])
    }
}

/// What became of the last value of the instance a frame was judged in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastOutcome {
    /// The payload is now the instance's last value.
    Recorded,
    /// The frame is not intact, so it changed no state of its instance.
    NotIntact,
    /// The payload is longer than an instance's room; the value before it is
    /// kept.
    TooLong {
        /// The payload's length.
        len: usize,
        /// The room each instance has.
        capacity: usize,
    },
    /// No last values are kept.
    NotKept,
}

/// A frame judged in its instance's stream, or dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judged {
    /// The frame's payload is an instance, and its stream judged it.
    Instance {
        /// The instance, which is the stream.
        instance: usize,
        /// The stream's verdict.
        verdict: Verdict,
        /// What became of the instance's last value.
        last: LastOutcome,
    },
    /// The payload is no instance: the frame was not judged and moved nothing.
    Dropped(Dropped),
}

/// Why a frame was not judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JudgeError {
    /// The receiver chooses its streams by sender. An instance and a sender
    /// are two ways to name one stream, and a message has one of them.
    SenderKeyed,
    /// The receiver keeps fewer streams than the keyer has instances.
    TooFewStreams {
        /// The receiver's streams.
        streams: usize,
        /// The keyer's instances.
        instances: usize,
    },
    /// The last values hold fewer instances than the keyer has.
    TooFewLastValues {
        /// The instances the last values hold.
        kept: usize,
        /// The keyer's instances.
        instances: usize,
    },
    /// The receiver refused the frame.
    Receive(ReceiveError),
}

impl fmt::Display for JudgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SenderKeyed => f.write_str(
                "the receiver keeps its streams per sender, and instance keys and sender slots \
                 are exclusive on one message",
            ),
            Self::TooFewStreams { streams, instances } => write!(
                f,
                "the receiver keeps {streams} streams and the keyer has {instances} instances"
            ),
            Self::TooFewLastValues { kept, instances } => write!(
                f,
                "the last values hold {kept} instances and the keyer has {instances}"
            ),
            Self::Receive(e) => write!(f, "{e}"),
        }
    }
}

/// Judge `frame`, received at `now_ms`, in the stream of the instance its
/// payload is, and keep the payload of an intact frame as that instance's last
/// value when `last` is given. A payload that is no instance is dropped and
/// counted by the keyer, and the receiver does not see it.
///
/// # Errors
///
/// A receiver keyed by sender, or one, or last values, with fewer instances
/// than the keyer; the receiver's refusal of the frame.
pub fn judge<S: AsRef<[u8]> + AsMut<[u8]>>(
    keyer: &mut Keyer,
    receiver: &mut Receiver,
    last: Option<&mut LastValues<S>>,
    frame: &[u8],
    now_ms: u64,
) -> Result<Judged, JudgeError> {
    if receiver.keyed_by_sender() {
        return Err(JudgeError::SenderKeyed);
    }
    if receiver.streams() < keyer.instances() {
        return Err(JudgeError::TooFewStreams {
            streams: receiver.streams(),
            instances: keyer.instances(),
        });
    }
    if let Some(kept) = last.as_ref().map(|l| l.instances()) {
        if kept < keyer.instances() {
            return Err(JudgeError::TooFewLastValues {
                kept,
                instances: keyer.instances(),
            });
        }
    }
    let Some(payload) = frame.get(receiver.profile().header_bytes()..) else {
        return Ok(Judged::Dropped(keyer.refuse(Refusal::Undecodable, now_ms)));
    };
    let instance = match keyer.index(payload, now_ms) {
        Ok(instance) => instance,
        Err(dropped) => return Ok(Judged::Dropped(dropped)),
    };
    let verdict = receiver
        .receive(instance, frame, now_ms)
        .map_err(JudgeError::Receive)?;
    let last = match last {
        None => LastOutcome::NotKept,
        Some(_) if verdict.status == Status::Integrity => LastOutcome::NotIntact,
        Some(store) => match store.record(instance, payload) {
            Ok(()) => LastOutcome::Recorded,
            Err(RecordError::TooLong { len, capacity }) => LastOutcome::TooLong { len, capacity },
            Err(RecordError::NoSuchInstance { .. }) => LastOutcome::NotKept,
        },
    };
    Ok(Judged::Instance {
        instance,
        verdict,
        last,
    })
}

/// A payload protected on its instance's counter stream, or dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyedFrame {
    /// The payload is an instance, and its stream's sender built the frame.
    Built {
        /// The instance, which is the stream.
        instance: usize,
        /// The frame.
        frame: Protected,
    },
    /// The payload is no instance this node sends: no frame was built, and no
    /// counter value was consumed.
    Dropped(Dropped),
}

/// Why a payload was not protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectError {
    /// The sender keeps fewer streams than the keyer has instances.
    TooFewStreams {
        /// The sender's streams.
        streams: usize,
        /// The keyer's instances.
        instances: usize,
    },
    /// The sender refused the frame.
    Send(SendError),
}

impl fmt::Display for ProtectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewStreams { streams, instances } => write!(
                f,
                "the sender keeps {streams} streams and the keyer has {instances} instances"
            ),
            Self::Send(e) => write!(f, "{e}"),
        }
    }
}

/// Protect `payload`, about to be sent at `now_ms`, on the counter stream of
/// the instance it is.
///
/// # Errors
///
/// A sender with fewer streams than the keyer has instances; the sender's
/// refusal of the frame.
pub fn protect(
    keyer: &mut Keyer,
    sender: &mut StreamSender,
    payload: &[u8],
    now_ms: u64,
) -> Result<KeyedFrame, ProtectError> {
    if sender.streams() < keyer.instances() {
        return Err(ProtectError::TooFewStreams {
            streams: sender.streams(),
            instances: keyer.instances(),
        });
    }
    match keyer.index(payload, now_ms) {
        Err(dropped) => Ok(KeyedFrame::Dropped(dropped)),
        Ok(instance) => sender
            .protect(instance, payload)
            .map(|frame| KeyedFrame::Built { instance, frame })
            .map_err(ProtectError::Send),
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A payload read by the TYPES its `.proto` schema gives it, as a payload
//! format: the typed reader ([`crate::proto_decode`]) reached from a
//! declaration text, so every door that takes one reads a payload as its
//! schema says.
//!
//! # The two lines
//!
//! ```text
//! #@pose.proto="syntax = \"proto3\"; package pkg; message Pose { sint32 x = 1; }"
//! demo/pose/**=protobuf@pkg.Pose
//! ```
//!
//! The first line is a SCHEMA FILE: `#@`, the name other files import it by,
//! and the file's text as one JSON string (so the line stays a line). The
//! second is a rule whose format token is `protobuf` and a BODY SCHEMA, the
//! message the payload is an instance of, written as an end-to-end profile
//! rule writes one (`demo-a@pkg.Pose`, [`crate::e2e_rule`]); a profile rule
//! reads its body by the same files.
//!
//! # When the schema is read and when it is only named
//!
//! The files are read once, together, when the first rule that names a
//! message is installed, and a problem in any of them refuses that rule with
//! the schema reader's own diagnostic. A rule whose message no file defines is
//! refused too. A declaration text that carries NO schema file and a rule that
//! names a message is what a profile rule has always been: the name is
//! carried, the payload is walked by the wire alone, and the row says so
//! (`typed: false`, `schema` the name). The difference is the operator's: a
//! text with no file has not given a schema, and a text with files whose
//! message is missing has given the wrong one.
//!
//! # What a field becomes
//!
//! The typed listing is a tree ([`crate::proto_decode::DecodedField`]); a
//! payload decoding is a flat list whose paths say the nesting, so the tree is
//! listed depth first with each field's number appended to its parent's path
//! (`4`, `4.1`). A repeated field and a packed run give one row per element
//! under the same path, in wire order. A map entry is a row holding its `key`
//! and `value` rows (`5.1`, `5.2`), the paths [`crate::proto_schema`] declares.
//! Each row carries the schema's name for the field and its
//! [`TypedValue`]; `value` is the text a person reads.

use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::payload::formats::{
    BodySchema, MessagePaths, PayloadField, PayloadFormat, PayloadFormatError, Protobuf, TypedValue,
};
use crate::proto_decode::{DecodedField, SchemaMessage, SchemaSet, Unknown, Value};

/// The schema a rule reads with: the files read together, and the message the
/// rule names in them.
#[derive(Debug, Clone)]
pub struct LinkedBody {
    /// The files, read once and shared by every rule of the map.
    pub set: Rc<SchemaSet>,
    /// The message the rule names.
    pub message: SchemaMessage,
}

impl LinkedBody {
    /// Read `body` as one message, with spans counted from the start of
    /// `body`.
    pub fn read(&self, body: &[u8]) -> Result<Vec<PayloadField>, PayloadFormatError> {
        let decoded =
            self.set
                .decode(self.message, body)
                .map_err(|e| PayloadFormatError::Malformed {
                    at: e.offset,
                    why: match e.field {
                        Some(field) => format!("{field}: {}", e.reason),
                        None => e.reason,
                    },
                })?;
        let mut out = Vec::new();
        list(&decoded, "", &mut out);
        Ok(out)
    }
}

/// The `protobuf` format with a body schema: the format a `protobuf@pkg.Msg`
/// rule installs.
#[derive(Debug, Clone)]
pub struct SchemaProtobuf {
    /// The message's full name as the rule wrote it.
    message: String,
    /// The schema it was found in, or `None` when the declarations carry no
    /// schema file and the name is only carried.
    linked: Option<LinkedBody>,
}

impl SchemaProtobuf {
    /// A rule's format: the message it names and, when the declarations carry
    /// the files, where it was found.
    pub fn new(message: String, linked: Option<LinkedBody>) -> Self {
        Self { message, linked }
    }

    /// The rule's format token as it is written after `=`.
    pub fn token(&self) -> String {
        format!(
            "{}{}{}",
            Protobuf.name(),
            crate::e2e_rule::SCHEMA_MARK,
            self.message
        )
    }
}

impl PayloadFormat for SchemaProtobuf {
    /// The format's name is `protobuf`: a row reports the decoder that read it,
    /// and `schema` beside it names the message.
    fn name(&self) -> &str {
        Protobuf.name()
    }

    fn encodings(&self) -> Option<&[&str]> {
        Protobuf.encodings()
    }

    fn decode(&self, payload: &[u8]) -> Result<Vec<PayloadField>, PayloadFormatError> {
        self.decode_declared(payload, &MessagePaths::none())
    }

    /// Read by the schema when it was found; otherwise the wire walk, with the
    /// paths the declarations say hold a message, exactly as a bare `protobuf`
    /// rule reads.
    ///
    /// An empty payload is a message whose every field is absent, which a
    /// schema can say and the wire walk cannot: it reads as no fields.
    fn decode_declared(
        &self,
        payload: &[u8],
        messages: &MessagePaths<'_>,
    ) -> Result<Vec<PayloadField>, PayloadFormatError> {
        match &self.linked {
            Some(linked) => linked.read(payload),
            None => Protobuf.decode_declared(payload, messages),
        }
    }

    fn body_schema(&self) -> Option<BodySchema<'_>> {
        Some(BodySchema {
            message: &self.message,
            read: self.linked.is_some(),
        })
    }
}

/// List a typed message's fields depth first, each under `parent`'s path.
fn list(fields: &[DecodedField], parent: &str, out: &mut Vec<PayloadField>) {
    for field in fields {
        let path = if parent.is_empty() {
            format!("{}", field.number)
        } else {
            format!("{parent}.{}", field.number)
        };
        let (value, typed) = shown(field);
        out.push(PayloadField {
            path: path.clone(),
            name: field.name.clone(),
            value,
            start: field.start,
            end: field.end,
            typed: Some(typed),
        });
        if let Value::Message(children) = &field.value {
            list(children, &path, out);
        }
    }
}

/// The text a person reads for one field, and its [`TypedValue`].
///
/// The text is the JSON value where there is one, an enum value with its
/// number beside its name, the field count of a message, and, for a field the
/// schema does not know, the wire walk's own spelling of the wire value.
fn shown(field: &DecodedField) -> (String, TypedValue) {
    let json = crate::proto_decode_json::value_json(&field.value);
    let (text, enum_number) = match &field.value {
        Value::Enum { number, name } => (
            match name {
                Some(name) => format!("{name} ({number})"),
                None => format!("{number}"),
            },
            Some(*number),
        ),
        Value::Message(children) => (format!("{} field(s)", children.len()), None),
        Value::Bytes(bytes) => (format!("{} byte(s)", bytes.len()), None),
        Value::Unknown(raw) => (
            match raw {
                Unknown::Varint(v) | Unknown::Fixed64(v) => format!("{} {v}", raw.wire_type()),
                Unknown::Fixed32(v) => format!("{} {v}", raw.wire_type()),
                Unknown::Len(bytes) => format!("{} {} byte(s)", raw.wire_type(), bytes.len()),
            },
            None,
        ),
        _ => (json.clone().unwrap_or_default(), None),
    };
    // `json` is `None` for a message and for a field the schema does not know,
    // which has a wire value and no typed one: see `TypedValue::json`.
    let typed = TypedValue {
        ty: field.ty.clone(),
        json,
        enum_number,
    };
    (text, typed)
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The document of the description door: a root message of a `.proto` schema,
//! field by field, or why the schema was refused.
//!
//! It lives beside the reader ([`crate::proto_describe`]) and not in the C ABI
//! crate, for the reason the other documents do: one rendering.
//!
//! # `proto_message`
//!
//! ```text
//! {"document":{"name":"proto_message","revision":1},"ok":true,
//!  "root":"pkg.Reading",
//!  "messages":[{"full_name":"pkg.Reading","file":"reading.proto","syntax":"proto3",
//!    "oneofs":[],
//!    "fields":[{"name":"sensor_id","json_name":"sensorId","number":1,
//!      "type":"uint32","label":"singular","oneof":null,"packed":null,
//!      "enum":null,"message_type":null,"map":null}]}]}
//! ```
//!
//! `messages` is the root message first, then every message it reaches, each
//! once; a field whose type is a message names it by full name in
//! `message_type`, and that name is the `full_name` of one of the entries. Every
//! key of a field row is always present and one that does not apply is `null`:
//!
//! * `oneof` is the oneof's name, or `null` for a field that is in none;
//! * `packed` is a boolean for a repeated field of a packable type (whether it
//!   is written as one run) and `null` for every other field;
//! * `enum` is `{"name":"pkg.Mode","values":[{"name":"A","number":0},...]}` for
//!   a field of type `enum` and `null` otherwise;
//! * `message_type` is the full name for a field of type `message` and `null`
//!   otherwise;
//! * `map` is `{"key":"string","value":{"type":"...","enum":...,
//!   "message_type":...}}` for a field of type `map` and `null` otherwise. The
//!   `key` is the scalar keyword the map is keyed by and the `type` of its value
//!   is a scalar keyword, `enum` or `message`, with `enum` and `message_type`
//!   as in a field row.
//!
//! The vocabularies are closed and are the ones [`crate::proto_describe`] lists:
//! `type` (the scalar keywords, `enum`, `message` and `map`; a map value's `type`
//! is one of them), `key` (the scalar keywords a map may be keyed by), `label`
//! and `syntax`. An enum value's number is a bare number up to 2^53 - 1 in either
//! direction and the digits in a string beyond, the integer rule the decoded
//! values follow; a legal enum number is an `i32`, but this reader does not judge
//! one.
//!
//! # A refusal
//!
//! `{"document":{...},"ok":false,"file":"a.proto","line":3,"column":9,
//! "reason":"...","message":"a.proto: line 3: ..."}`, with `file`, `line` and
//! `column` present together for a place in a file, `file` alone for a problem
//! with a file as a whole, and none of them for a problem with an argument,
//! exactly as the `declarations_from_proto` document says it, and for the same
//! reason a key that does not apply is ABSENT and never `null`.

use alloc::format;
use alloc::string::{String, ToString};

use wz_session_core::json::escape_into;

use crate::doc_revision::{envelope, PROTO_MESSAGE};
use crate::proto_decode_json::push_integer;
use crate::proto_describe::{
    describe_proto, FieldDescription, MapDescription, MessageDescription, Target,
};
use crate::proto_schema::{ProtoDiagnostic, ProtoFile};

/// The `proto_message` document for `root_message` of the schema in `files`.
pub fn proto_message_json(root_message: &str, files: &[ProtoFile<'_>], root_file: usize) -> String {
    let head = envelope(PROTO_MESSAGE);
    match describe_proto(root_message, files, root_file) {
        Ok(description) => {
            let mut out = format!("{{{head},\"ok\":true,\"root\":");
            escape_into(&description.root, &mut out);
            out.push_str(",\"messages\":[");
            for (i, message) in description.messages.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_message(message, &mut out);
            }
            out.push_str("]}");
            out
        }
        Err(bad) => {
            let mut out = format!("{{{head},\"ok\":false");
            push_diagnostic(&bad, &mut out);
            out.push('}');
            out
        }
    }
}

/// The place keys, `reason` and `message` of a refused schema, after `"ok":false`.
///
/// Written once for the two documents that carry a schema's refusal
/// (`declarations_from_proto` and `proto_message`), so a consumer that joins them
/// by equality is joining one spelling.
pub fn push_diagnostic(bad: &ProtoDiagnostic, out: &mut String) {
    if let Some(file) = &bad.file {
        out.push_str(",\"file\":");
        escape_into(file, out);
    }
    for (position, at) in [("line", bad.line), ("column", bad.column)] {
        if let Some(n) = at {
            out.push_str(&format!(",\"{position}\":{n}"));
        }
    }
    out.push_str(",\"reason\":");
    escape_into(&bad.reason, out);
    out.push_str(",\"message\":");
    escape_into(&bad.to_string(), out);
}

fn push_message(message: &MessageDescription, out: &mut String) {
    out.push_str("{\"full_name\":");
    escape_into(&message.full_name, out);
    out.push_str(",\"file\":");
    escape_into(&message.file, out);
    out.push_str(&format!(",\"syntax\":\"{}\",\"oneofs\":[", message.syntax));
    for (i, name) in message.oneofs.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        escape_into(name, out);
    }
    out.push_str("],\"fields\":[");
    for (i, field) in message.fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_field(field, out);
    }
    out.push_str("]}");
}

fn push_field(field: &FieldDescription, out: &mut String) {
    out.push_str("{\"name\":");
    escape_into(&field.name, out);
    out.push_str(",\"json_name\":");
    escape_into(&field.json_name, out);
    out.push_str(&format!(
        ",\"number\":{},\"type\":\"{}\",\"label\":\"{}\",\"oneof\":",
        field.number, field.ty, field.label
    ));
    match &field.oneof {
        Some(name) => escape_into(name, out),
        None => out.push_str("null"),
    }
    out.push_str(",\"packed\":");
    match field.packed {
        Some(packed) => out.push_str(if packed { "true" } else { "false" }),
        None => out.push_str("null"),
    }
    push_target(&field.target, out);
    out.push_str(",\"map\":");
    match &field.map {
        Some(map) => push_map(map, out),
        None => out.push_str("null"),
    }
    out.push('}');
}

/// The `enum` and `message_type` keys of a row, in that order, each `null` where
/// it does not apply.
fn push_target(target: &Target, out: &mut String) {
    out.push_str(",\"enum\":");
    match target {
        Target::Enum(e) => {
            out.push_str("{\"name\":");
            escape_into(&e.name, out);
            out.push_str(",\"values\":[");
            for (i, (name, number)) in e.values.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str("{\"name\":");
                escape_into(name, out);
                out.push_str(",\"number\":");
                push_integer(*number, out);
                out.push('}');
            }
            out.push_str("]}");
        }
        Target::None | Target::Message(_) => out.push_str("null"),
    }
    out.push_str(",\"message_type\":");
    match target {
        Target::Message(name) => escape_into(name, out),
        Target::None | Target::Enum(_) => out.push_str("null"),
    }
}

fn push_map(map: &MapDescription, out: &mut String) {
    out.push_str(&format!(
        "{{\"key\":\"{}\",\"value\":{{\"type\":\"{}\"",
        map.key, map.value_type
    ));
    push_target(&map.value, out);
    out.push_str("}}");
}

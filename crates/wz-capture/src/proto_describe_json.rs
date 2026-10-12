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
//! {"document":{"name":"proto_message","revision":3},"ok":true,
//!  "root":"pkg.Reading",
//!  "messages":[{"full_name":"pkg.Reading","file":"reading.proto","syntax":"proto3",
//!    "oneofs":[],"comment":" One reading.\n","trailing_comment":null,
//!    "options":[{"name":"(ext).id","kind":"integer","value":7}],
//!    "max_encoded_size":6,"max_encoded_size_reason":null,
//!    "fields":[{"name":"sensor_id","json_name":"sensorId","number":1,
//!      "type":"uint32","label":"singular","oneof":null,"packed":null,
//!      "enum":null,"message_type":null,"map":null,
//!      "comment":null,"trailing_comment":" the sensor\n",
//!      "options":[{"name":"(ext).int_size","kind":"identifier",
//!                  "value":"IS_16"}]}]}]}
//! ```
//!
//! `messages` is the root message first, then every message it reaches, each
//! once; a field whose type is a message names it by full name in
//! `message_type`, and that name is the `full_name` of one of the entries. Every
//! key of a field row is always present and one that does not apply is `null`:
//!
//! * `comment` and `trailing_comment`, on a message row as on a field row, are
//!   the comments `protoc` itself attaches to the declaration, as it stores
//!   them in its `SourceCodeInfo` (the leading and the trailing comment), and
//!   `null` when there is none. The text is the text after the comment marker,
//!   its line breaks included, so a `//` comment keeps the space after the
//!   slashes and ends with a newline, and a `/** ... */` comment begins with the
//!   `*` and a newline, a continuation line losing its leading white space and
//!   one `*`. A message's trailing comment is the one after its `{`. The rule
//!   for which comment belongs to which declaration is `protoc`'s and is stated
//!   on [`crate::proto_lex::Gap`]: a comment on the line of the declaration
//!   before trails that one; a comment on the lines before a declaration, with
//!   no blank line between, leads it; a blank line detaches a comment from both;
//! * `options` is an array, empty for none, of the options written on the field
//!   (its `[...]` list) or the message (its `option` statements), each in the
//!   order written and none dropped: `{"name":N,"kind":K,"value":V}`. `name` is
//!   the name as the file spelled it: a plain word (`packed`), a dotted path, or
//!   an extension in parentheses and the path after it (`(ext).field`). `kind`
//!   is how the value was written, one of `identifier` (a bare word: `true`, an
//!   enum value's name; `value` is the word), `integer` (`value` a number by the
//!   integer rule below), `float` (`value` the literal as written, sign
//!   included, as a string), `string` (`value` the decoded text) and
//!   `aggregate` (`value` the text between the braces of a `{ ... }` value, as
//!   written). An option is not judged: a value no consumer of that option could
//!   read is still listed;
//! * `max_encoded_size` and `max_encoded_size_reason`, on a message row only: the
//!   most bytes the message takes encoded, in nanopb's own arithmetic from the
//!   nanopb options written in the schema (the number the generated `Message_size`
//!   macro holds), by the integer rule below; or `null` and then the reason there
//!   is none, one of `unbounded_field`, `recursive_message`,
//!   `message_not_generated`, `unmodelled_option`, `too_large` and `too_deep`
//!   (see [`crate::proto_nanopb`]). Exactly one of the two keys is `null`;
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
    describe_proto, FieldDescription, MapDescription, MessageDescription, OptionDescription,
    OptionValueDescription, Target,
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
    out.push(']');
    push_comments(&message.comment, &message.trailing_comment, out);
    push_options(&message.options, out);
    // A number, or `null` and the reason there is none: never one without the
    // other, so a consumer reads either key alone.
    match message.max_encoded_size {
        Ok(bytes) => {
            out.push_str(",\"max_encoded_size\":");
            push_integer(i128::from(bytes), out);
            out.push_str(",\"max_encoded_size_reason\":null");
        }
        Err(why) => out.push_str(&format!(
            ",\"max_encoded_size\":null,\"max_encoded_size_reason\":\"{}\"",
            why.word()
        )),
    }
    out.push_str(",\"fields\":[");
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
    push_comments(&field.comment, &field.trailing_comment, out);
    push_options(&field.options, out);
    out.push('}');
}

/// The `comment` and `trailing_comment` keys of a message or a field row, each
/// the text as `protoc` stores it or `null`.
fn push_comments(comment: &Option<String>, trailing: &Option<String>, out: &mut String) {
    for (key, text) in [("comment", comment), ("trailing_comment", trailing)] {
        out.push_str(&format!(",\"{key}\":"));
        match text {
            Some(text) => escape_into(text, out),
            None => out.push_str("null"),
        }
    }
}

/// The `options` key of a message or a field row: an array, empty for none.
fn push_options(options: &[OptionDescription], out: &mut String) {
    out.push_str(",\"options\":[");
    for (i, option) in options.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        escape_into(&option.name, out);
        out.push_str(&format!(",\"kind\":\"{}\",\"value\":", option.value.kind()));
        match &option.value {
            OptionValueDescription::Integer(n) => push_integer(*n, out),
            OptionValueDescription::Identifier(text)
            | OptionValueDescription::Float(text)
            | OptionValueDescription::String(text)
            | OptionValueDescription::Aggregate(text) => escape_into(text, out),
        }
        out.push('}');
    }
    out.push(']');
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

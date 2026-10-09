// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The VERDICT document of the value door: the protobuf bytes a set of field
//! values comes to, or why they could not be built.
//!
//! It lives beside the writer ([`crate::proto_encode`]) and not in the C ABI
//! crate, for the reason the other documents do: one rendering, so a second
//! consumer of the writer does not get to invent another.
//!
//! # `proto_encode`
//!
//! ```text
//! {"document":{"name":"proto_encode","revision":1},"ok":true,
//!  "payload":"089601","payload_bytes":3}
//! ```
//!
//! `payload` is the message's wire bytes as lowercase hex and `payload_bytes`
//! how many bytes that is. An empty message is `"payload":""` with `0`.
//!
//! # A refusal
//!
//! ```text
//! {"document":{...},"ok":false,"values_path":"/readings/2/celsius",
//!  "field":"pkg.Reading.celsius","expected":"float: a JSON number, ...",
//!  "reason":"`x` is not a decimal number: ...",
//!  "message":"values /readings/2/celsius: `x` is not a decimal number: ..."}
//! ```
//!
//! Which keys name the place depends on what was refused, and a key that does
//! not apply is ABSENT and never `null`: a top-level `null` is what this ABI
//! reserves for a plane it cannot feed.
//!
//! * the SCHEMA (or an argument about it) was refused: `file`, `line` and
//!   `column` together for a place in a file, `file` alone for a problem with a
//!   file as a whole, none of the three for an argument, exactly as the
//!   `declarations_from_proto` document says it;
//! * the values text is not JSON: `values_offset`, the byte reading stopped at;
//! * the values are JSON and do not fit the schema: `values_path`, an RFC 6901
//!   JSON pointer to the place (empty for the whole text), and, when the value
//!   was for a particular field, `field`, its full name, and `expected`, what
//!   would have been accepted there. A problem that is about no single field (a
//!   key that is no field, a missing required field's message) carries `field`
//!   or `expected` only when they say something.
//!
//! `reason` is the sentence and `message` the one-line form
//! ([`crate::proto_encode::EncodeError`]'s `Display`). No integer in this
//! document can reach 2^53: `payload_bytes` counts bytes this library holds and
//! is bounded by [`crate::proto_encode::MAX_ENCODED_BYTES`].

use alloc::format;
use alloc::string::{String, ToString};

use wz_session_core::json::escape_into;

use crate::doc_revision::{envelope, PROTO_ENCODE};
use crate::proto_encode::{encode_message, EncodeError};
use crate::proto_schema::ProtoFile;

/// The `proto_encode` document for building `root_message` from `values`.
///
/// See [`encode_message`] for what the arguments mean and the order in which a
/// problem is found.
pub fn encode_document(
    root_message: &str,
    files: &[ProtoFile<'_>],
    root_file: usize,
    values: &str,
) -> String {
    let head = envelope(PROTO_ENCODE);
    match encode_message(root_message, files, root_file, values) {
        Ok(bytes) => {
            let mut out = format!("{{{head},\"ok\":true,\"payload\":\"");
            for b in &bytes {
                out.push_str(&format!("{b:02x}"));
            }
            out.push_str(&format!("\",\"payload_bytes\":{}}}", bytes.len()));
            out
        }
        Err(e) => refusal(&head, &e),
    }
}

fn refusal(head: &str, error: &EncodeError) -> String {
    let mut out = format!("{{{head},\"ok\":false");
    let reason = match error {
        EncodeError::Schema(d) => {
            if let Some(file) = &d.file {
                out.push_str(",\"file\":");
                escape_into(file, &mut out);
            }
            for (key, at) in [("line", d.line), ("column", d.column)] {
                if let Some(n) = at {
                    out.push_str(&format!(",\"{key}\":{n}"));
                }
            }
            d.reason.clone()
        }
        EncodeError::Syntax { offset, expected } => {
            out.push_str(&format!(",\"values_offset\":{offset}"));
            format!("the text is not JSON: expected {expected}")
        }
        EncodeError::Value(v) => {
            out.push_str(",\"values_path\":");
            escape_into(&v.path, &mut out);
            if let Some(field) = &v.field {
                out.push_str(",\"field\":");
                escape_into(field, &mut out);
            }
            if let Some(expected) = &v.expected {
                out.push_str(",\"expected\":");
                escape_into(expected, &mut out);
            }
            v.reason.clone()
        }
    };
    out.push_str(",\"reason\":");
    escape_into(&reason, &mut out);
    out.push_str(",\"message\":");
    escape_into(&error.to_string(), &mut out);
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "syntax = \"proto3\";\nmessage M { int32 a = 1; repeated float f = 2; }";

    fn document(schema: &str, values: &str) -> String {
        let files = [ProtoFile {
            name: "a.proto",
            text: schema.as_bytes(),
        }];
        encode_document("M", &files, 0, values)
    }

    #[test]
    fn a_built_message_is_hex_and_a_count_under_the_envelope() {
        assert_eq!(
            document(SCHEMA, r#"{"a":150}"#),
            "{\"document\":{\"name\":\"proto_encode\",\"revision\":1},\"ok\":true,\
             \"payload\":\"089601\",\"payload_bytes\":3}"
        );
    }

    #[test]
    fn the_hex_is_lowercase_and_two_digits_a_byte() {
        // -1 as an int32 is ten bytes, nine of them 0xff, and a byte below 0x10
        // keeps its leading zero (the float 1.0 is 00 00 80 3f).
        let doc = document(SCHEMA, r#"{"a":-1,"f":[1]}"#);
        assert!(
            doc.contains("\"payload\":\"08ffffffffffffffffff0112040000803f\""),
            "{doc}"
        );
        assert!(doc.ends_with("\"payload_bytes\":17}"), "{doc}");
    }

    #[test]
    fn an_empty_message_is_an_empty_payload_and_not_an_absent_one() {
        let doc = document(SCHEMA, "{}");
        assert!(
            doc.ends_with("\"payload\":\"\",\"payload_bytes\":0}"),
            "{doc}"
        );
    }

    #[test]
    fn a_value_refusal_names_the_pointer_the_field_and_the_type() {
        let doc = document(SCHEMA, r#"{"f":[1,"x"]}"#);
        assert!(
            doc.contains("\"ok\":false,\"values_path\":\"/f/1\""),
            "{doc}"
        );
        assert!(doc.contains("\"field\":\"M.f\""), "{doc}");
        assert!(doc.contains("\"expected\":\"float: "), "{doc}");
        assert!(doc.contains("\"message\":\"values /f/1: "), "{doc}");
        assert!(!doc.contains("\"file\""), "{doc}");
        assert!(!doc.contains("null"), "{doc}");
    }

    #[test]
    fn a_text_that_is_not_json_is_blamed_at_its_byte_and_nothing_else() {
        let doc = document(SCHEMA, r#"{"a":"#);
        assert!(doc.contains("\"ok\":false,\"values_offset\":"), "{doc}");
        assert!(
            doc.contains("\"reason\":\"the text is not JSON: expected "),
            "{doc}"
        );
        for absent in ["values_path", "\"file\"", "\"line\"", "\"field\"", "null"] {
            assert!(!doc.contains(absent), "{absent} in {doc}");
        }
    }

    #[test]
    fn a_schema_refusal_names_file_line_and_column_and_an_argument_none() {
        let doc = document("message M { int32 a = 1 }", "{}");
        assert!(
            doc.contains("\"ok\":false,\"file\":\"a.proto\",\"line\":1,\"column\":"),
            "{doc}"
        );
        assert!(!doc.contains("values_"), "{doc}");

        let files = [ProtoFile {
            name: "a.proto",
            text: SCHEMA.as_bytes(),
        }];
        let argument = encode_document("M", &files, 9, "{}");
        assert!(
            argument.contains("\"ok\":false,\"reason\":\"the root file index 9"),
            "{argument}"
        );
        for absent in ["\"file\"", "\"line\"", "\"column\"", "values_"] {
            assert!(!argument.contains(absent), "{absent} in {argument}");
        }
    }

    #[test]
    fn the_document_uses_exactly_the_keys_the_registry_pins() {
        use crate::doc_revision::{key_set, PROTO_ENCODE_R1_KEYS};
        let files = [ProtoFile {
            name: "a.proto",
            text: SCHEMA.as_bytes(),
        }];
        // Every branch: built, a value refused (with a field), a key that is no
        // field (without one), text that is not JSON, a schema place, a whole
        // file, and an argument.
        let docs = [
            document(SCHEMA, r#"{"a":1}"#),
            document(SCHEMA, r#"{"a":"x"}"#),
            document(SCHEMA, r#"{"zz":1}"#),
            document(SCHEMA, "{"),
            document("message M { int32 a = 1 }", "{}"),
            document("message N {}", "{}"),
            encode_document("M", &files, 9, "{}"),
        ];
        let mut keys: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
        for doc in &docs {
            keys.extend(key_set(doc));
        }
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys, PROTO_ENCODE_R1_KEYS);
    }
}

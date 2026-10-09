// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The two VERDICT documents of the end-to-end protection doors: what building
//! a frame did, and what opening one found.
//!
//! They live beside the types that make the facts ([`crate::e2e_frame`]) rather
//! than in the C ABI crate, for the reason the other documents do: one
//! rendering, and a second consumer would not get to invent another.
//!
//! # `e2e_wrap`
//!
//! ```text
//! {"document":{"name":"e2e_wrap","revision":2},"ok":true,
//!  "profile":"demo-a","frame":"c2bf56b4...","payload_offset":16,"payload_bytes":4,
//!  "fields":[{"name":"crc","offset":0,"bytes":4,"raw":N,"value":N},
//!            {"name":"ident","offset":8,"bytes":4,"raw":N,"value":N,
//!             "parts":[{"name":"domain","value":3},...]}, ...],
//!  "crc_computed":N,
//!  "crc_fed":[{"item":"length","bytes":2,"hex":"0014"},{"item":"@payload","bytes":4},...],
//!  "length_field":20}
//! ```
//!
//! `raw` is the integer on the wire and `value` the logical value the parts are
//! cut from (`raw` with the `xor` undone). `crc_fed` lists, in feeding order,
//! exactly what went into the CRC, with the bytes of every header field so a
//! caller can check the arithmetic one step at a time; the body is counted and
//! not repeated.
//!
//! The body is the caller's bytes or, when the values text has an `@body` member
//! ([`crate::e2e_body`]), the bytes the protobuf writer builds from the schema
//! and field values that member describes. In that case the document also has
//! `body_message`, the message the body is an instance of; it is ABSENT when the
//! body was bytes, so a frame built from bytes reads exactly as it did at
//! revision 1 but for the revision number.
//!
//! # `e2e_open`
//!
//! The same `profile`, `payload_offset`, `payload_bytes`, `fields` and
//! `crc_fed`, and in place of `frame` and the written values the facts a
//! receiver needs: `crc_ok`, `crc_computed`, and three about the length that
//! are INFORMATION and not part of the CRC verdict: `length_field` (what the
//! field holds), `length_expected` (what the profile's rule gives for this
//! frame) and `length_matches_frame`.
//!
//! # A refusal
//!
//! `{"document":{...},"ok":false,"profile_path":"/fields/0/bytes","reason":"...",
//! "message":"profile /fields/0/bytes: ..."}`. The input that was refused is
//! named by the key that locates the place: `profile_path` or `profile_offset`
//! for the profile text, `values_path` or `values_offset` for the values text
//! (`_offset` when the text is not JSON, `_path` otherwise), and neither for a
//! refusal that is about no text (a body too long for the length field, a frame
//! shorter than the header). The key is ABSENT where it does not apply and never
//! `null`: a top-level `null` is what this ABI reserves for a plane it cannot
//! feed. `message` is the one-line form.
//!
//! A refusal that is about the BODY of an `e2e_wrap` carries `"stage":"body"`
//! (absent on every other): the `@body` member is not what it should be
//! (`values_path` is then a pointer into it, `/@body/files/0/name`), the body
//! is also given as bytes, or the protobuf writer refused it. The writer's
//! refusal is its own diagnostic in its own keys ([`crate::proto_encode_json`]):
//! `file`, `line` and `column` for the schema, `values_path` for a value that
//! does not fit, with `field` and `expected` when the value was for a
//! particular field. The pointer is a place in the text the caller passed, so
//! it starts with `/@body/values`; no frame is built around a body that was
//! not.
//!
//! # Integers
//!
//! A value that can reach 2^53 is a decimal string beyond it and a number
//! below, by the same rule every document here keeps
//! ([`wz_session_core::json::u64_into`]): a 7- or 8-byte field is therefore a
//! number or a string depending on its VALUE, and a consumer asks which before it
//! reads. Offsets and byte counts are always numbers.

use alloc::string::String;
use core::fmt::Write as _;

use wz_session_core::json::{escape_into, u64_into};
use wz_session_core::json5::Json5Value;

use crate::doc_revision::{envelope, E2E_OPEN, E2E_WRAP};
use crate::e2e_body::{self, Description, Scan, BODY_KEY, BODY_VALUES_PATH};
use crate::e2e_frame::{self, BuildError, FieldReport, OpenError, Values};
use crate::e2e_profile::{Cover, DocError, Profile, PAYLOAD};
use crate::proto_encode::EncodeError;
use crate::proto_encode_json::push_refusal;

/// Which text a refusal is about.
#[derive(Clone, Copy)]
enum Source {
    Profile,
    Values,
}

impl Source {
    fn word(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Values => "values",
        }
    }
}

fn push_hex(bytes: &[u8], out: &mut String) {
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

/// The key a refusal that is about the body carries, so a reader can tell it
/// from one about the header: present on those only, absent on every other.
const BODY_STAGE: &str = ",\"stage\":\"body\"";

/// A refusal of text, with the place it is at.
fn refuse_text(head: &str, source: Source, error: &DocError) -> String {
    refuse_text_at(head, "", source, error)
}

/// [`refuse_text`] with `stage` written between `ok` and the place, which is
/// empty for the header and [`BODY_STAGE`] for the body.
fn refuse_text_at(head: &str, stage: &str, source: Source, error: &DocError) -> String {
    let word = source.word();
    let (position, reason, message) = match error {
        DocError::Syntax { offset, expected } => {
            let reason = alloc::format!("the text is not JSON: expected {expected}");
            let message = alloc::format!("{word} at byte {offset}: {reason}");
            (
                alloc::format!(",\"{word}_offset\":{offset}"),
                reason,
                message,
            )
        }
        DocError::Invalid { path, reason } => {
            let mut position = alloc::format!(",\"{word}_path\":");
            escape_into(path, &mut position);
            let message = if path.is_empty() {
                alloc::format!("{word}: {reason}")
            } else {
                alloc::format!("{word} {path}: {reason}")
            };
            (position, reason.clone(), message)
        }
    };
    let mut out = alloc::format!("{{{head},\"ok\":false{stage}{position},\"reason\":");
    escape_into(&reason, &mut out);
    out.push_str(",\"message\":");
    escape_into(&message, &mut out);
    out.push('}');
    out
}

/// A refusal of the body's writer, with the place in the values text it is at.
///
/// The writer's own diagnostic, in its own words and keys (`proto_encode_json`
/// keeps the one rendering), with the pointer moved to where the body's values
/// sit in the text the caller passed.
fn refuse_writer(head: &str, error: &EncodeError) -> String {
    let mut out = alloc::format!("{{{head},\"ok\":false{BODY_STAGE}");
    push_refusal(error, BODY_VALUES_PATH, &mut out);
    out.push('}');
    out
}

/// A refusal that is about no text.
fn refuse_plain(head: &str, reason: &str) -> String {
    let mut out = alloc::format!("{{{head},\"ok\":false,\"reason\":");
    escape_into(reason, &mut out);
    out.push_str(",\"message\":");
    escape_into(reason, &mut out);
    out.push('}');
    out
}

/// The header's fields as a JSON array under `key`, shared by the two verdict
/// documents here (`"fields"`) and by the capture row's block (`"header"`).
pub(crate) fn push_fields(profile: &Profile, reports: &[FieldReport], key: &str, out: &mut String) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":[");
    for (i, report) in reports.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let field = &profile.fields()[report.index];
        out.push_str("{\"name\":");
        escape_into(&field.name, out);
        let _ = write!(
            out,
            ",\"offset\":{},\"bytes\":{},\"raw\":",
            field.offset, field.bytes
        );
        u64_into(report.raw, out);
        out.push_str(",\"value\":");
        u64_into(report.value, out);
        if !field.parts.is_empty() {
            out.push_str(",\"parts\":[");
            for (j, part) in field.parts.iter().enumerate() {
                if j > 0 {
                    out.push(',');
                }
                out.push_str("{\"name\":");
                escape_into(&part.name, out);
                out.push_str(",\"value\":");
                u64_into(report.parts[j], out);
                out.push('}');
            }
            out.push(']');
        }
        out.push('}');
    }
    out.push(']');
}

fn push_fed(profile: &Profile, frame: &[u8], payload_bytes: usize, out: &mut String) {
    out.push_str("\"crc_fed\":[");
    for (i, item) in profile.crc().cover.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        match *item {
            Cover::Field(index) => {
                let field = &profile.fields()[index];
                out.push_str("{\"item\":");
                escape_into(&field.name, out);
                let _ = write!(out, ",\"bytes\":{},\"hex\":\"", field.bytes);
                push_hex(&frame[field.offset..field.offset + field.bytes], out);
                out.push_str("\"}");
            }
            Cover::Payload => {
                out.push_str("{\"item\":");
                escape_into(PAYLOAD, out);
                let _ = write!(out, ",\"bytes\":{payload_bytes}}}");
            }
        }
    }
    out.push(']');
}

/// The `e2e_wrap` document for building a frame from `profile_text`,
/// `values_text` and the body: `payload` as it is, or, when `values_text` has an
/// `@body` member ([`crate::e2e_body`]), the bytes the protobuf writer builds
/// from the schema and values it describes (and `payload` then empty).
///
/// The first problem found is the one reported, in this order: the profile, the
/// values text (its shape, then the body's description, then the body's writer),
/// then the header values against the profile. The body is therefore built, or
/// refused, before a header value that names no field is, because the header
/// cannot be finished until the body's bytes are known.
pub fn wrap_document(profile_text: &str, values_text: &str, payload: &[u8]) -> String {
    let head = envelope(E2E_WRAP);
    let profile = match Profile::parse(profile_text) {
        Ok(p) => p,
        Err(e) => return refuse_text(&head, Source::Profile, &e),
    };
    match e2e_body::scan(values_text) {
        Scan::Plain => match Values::parse(values_text) {
            Ok(values) => wrap_frame(&head, &profile, &values, payload, None),
            Err(e) => refuse_text(&head, Source::Values, &e),
        },
        Scan::Refused(e) => refuse_text_at(&head, BODY_STAGE, Source::Values, &e),
        Scan::Body(tree) => wrap_described(&head, &profile, &tree, payload),
    }
}

/// The wrap of a values text that carries an `@body` member: the header values
/// are its other members, and the body is built from what the member describes.
fn wrap_described(head: &str, profile: &Profile, tree: &Json5Value, payload: &[u8]) -> String {
    let values = match Values::from_tree(tree, &[BODY_KEY]) {
        Ok(v) => v,
        Err(e) => return refuse_text(head, Source::Values, &e),
    };
    let description = match Description::read(tree) {
        Ok(d) => d,
        Err(e) => return refuse_text_at(head, BODY_STAGE, Source::Values, &e),
    };
    if !payload.is_empty() {
        return refuse_text_at(head, BODY_STAGE, Source::Values, &e2e_body::given_twice());
    }
    // The writer's refusal ends the call: there is no path on which a frame is
    // finished around a body the writer refused.
    let body = match description.encode() {
        Ok(bytes) => bytes,
        Err(e) => return refuse_writer(head, &e),
    };
    wrap_frame(head, profile, &values, &body, Some(description.message()))
}

/// Build the frame around `payload` and render the success, or the refusal of
/// the header values. `body_message` is the schema message the body was built
/// from, when it was built here.
fn wrap_frame(
    head: &str,
    profile: &Profile,
    values: &Values,
    payload: &[u8],
    body_message: Option<&str>,
) -> String {
    let built = match e2e_frame::build(profile, values, payload) {
        Ok(b) => b,
        Err(BuildError::Values(e)) => return refuse_text(head, Source::Values, &e),
        Err(e @ BuildError::PayloadTooLong { .. }) => {
            return refuse_plain(head, &alloc::format!("{e}"))
        }
    };

    let mut out = alloc::format!("{{{head},\"ok\":true,\"profile\":");
    escape_into(profile.name(), &mut out);
    if let Some(message) = body_message {
        out.push_str(",\"body_message\":");
        escape_into(message, &mut out);
    }
    out.push_str(",\"frame\":\"");
    push_hex(&built.bytes, &mut out);
    let _ = write!(
        out,
        "\",\"payload_offset\":{},\"payload_bytes\":{},",
        built.payload_offset, built.payload_bytes
    );
    push_fields(profile, &built.fields, "fields", &mut out);
    out.push_str(",\"crc_computed\":");
    u64_into(built.crc, &mut out);
    out.push(',');
    push_fed(profile, &built.bytes, built.payload_bytes, &mut out);
    out.push_str(",\"length_field\":");
    u64_into(built.length, &mut out);
    out.push('}');
    out
}

/// The `e2e_open` document for reading `frame` under `profile_text`.
pub fn open_document(profile_text: &str, frame: &[u8]) -> String {
    let head = envelope(E2E_OPEN);
    let profile = match Profile::parse(profile_text) {
        Ok(p) => p,
        Err(e) => return refuse_text(&head, Source::Profile, &e),
    };
    let opened = match e2e_frame::open(&profile, frame) {
        Ok(o) => o,
        Err(e @ OpenError::ShortFrame { .. }) => {
            return refuse_plain(&head, &alloc::format!("{e}"))
        }
    };

    let mut out = alloc::format!("{{{head},\"ok\":true,\"profile\":");
    escape_into(profile.name(), &mut out);
    let _ = write!(
        out,
        ",\"payload_offset\":{},\"payload_bytes\":{},",
        opened.payload_offset, opened.payload_bytes
    );
    push_fields(&profile, &opened.fields, "fields", &mut out);
    let _ = write!(out, ",\"crc_ok\":{},\"crc_computed\":", opened.crc_ok);
    u64_into(opened.crc_computed, &mut out);
    out.push(',');
    push_fed(&profile, frame, opened.payload_bytes, &mut out);
    out.push_str(",\"length_field\":");
    u64_into(opened.length_found, &mut out);
    out.push_str(",\"length_expected\":");
    u64_into(opened.length_expected, &mut out);
    let _ = write!(
        out,
        ",\"length_matches_frame\":{}}}",
        opened.length_matches_frame
    );
    out
}

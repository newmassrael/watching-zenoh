// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `transport_build` document: a transport message built from a
//! description, the unit and the body as hex, and the structural report of the
//! bytes — or the place the description was refused.
//!
//! It lives beside the builder, for the reason `e2e_json` gives: one rendering,
//! and a second consumer would not get to invent another.
//!
//! ```text
//! {"document":{"name":"transport_build","revision":1},"ok":true,
//!  "prefix_bytes":2,"unit":"0c00...","body":"...",
//!  "layout":[{"name":"unit_length","kind":"length","offset":0,"width":2,
//!             "relative_to":"unit","encoding":"fixed","value":N,"min":0,"max":65535,
//!             "bit_mask":null,"carrier":null,"stored":null,"measures":"body",
//!             "ring_max":null,"ring_max_width":null}, ...]}
//! ```
//!
//! # One shape for every row
//!
//! Every row carries EVERY key. A key that does not apply to the row is `null`
//! inside the row, and the row keeps its shape: a consumer reads `bit_mask` of
//! a length or of a flag without asking which it has, and a revision that adds
//! a key adds it to all of them. (The `null` is a cell of a row and not a
//! top-level plane, the case `every_top_level_null_is_a_declared_plane`
//! reserves `null` for.)
//!
//! # A refusal
//!
//! `{"document":{...},"ok":false,"description_path":"/sn","reason":"...",
//! "message":"description /sn: ..."}`. The place is named by `description_path`
//! (an RFC 6901 pointer) or, for text that is not JSON, `description_offset`;
//! the key is ABSENT for a refusal that is about no text (a body too long for
//! the framing, or a report that could not be derived). `message` is the
//! one-line form.
//!
//! # Integers
//!
//! A value that can reach 2^53 is a decimal string beyond it and a number below,
//! by the rule every document here keeps ([`wz_session_core::json::u64_into`]):
//! the `value`, `min`, `max`, `stored` and `ring_max` cells. Offsets, widths,
//! `bit_mask` and `ring_max_width` are always numbers.

use alloc::string::String;
use core::fmt::Write as _;

use wz_session_core::json::{escape_into, u64_into};
use wz_session_core::transport_compose::Framing;

use crate::doc_revision::{envelope, TRANSPORT_BUILD};
use crate::e2e_profile::DocError;
use crate::transport_build::{build, BuildError, Built};
use crate::transport_layout::{LayoutError, Row};

fn push_hex(bytes: &[u8], out: &mut String) {
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

/// One integer cell: the number, a string past 2^53, or `null`.
fn push_cell(key: &str, cell: Option<u64>, out: &mut String) {
    let _ = write!(out, ",\"{key}\":");
    match cell {
        Some(v) => u64_into(v, out),
        None => out.push_str("null"),
    }
}

fn push_text_cell(key: &str, cell: Option<&str>, out: &mut String) {
    let _ = write!(out, ",\"{key}\":");
    match cell {
        Some(text) => escape_into(text, out),
        None => out.push_str("null"),
    }
}

fn push_row(row: &Row, out: &mut String) {
    out.push_str("{\"name\":");
    escape_into(&row.name, out);
    let _ = write!(
        out,
        ",\"kind\":\"{}\",\"offset\":{},\"width\":{},\"relative_to\":\"{}\",\"encoding\":\"{}\"",
        row.kind.word(),
        row.offset,
        row.width,
        row.relative_to.word(),
        row.encoding.word(),
    );
    push_cell("value", row.value, out);
    push_cell("min", row.min, out);
    push_cell("max", row.max, out);
    match row.bit_mask {
        Some(mask) => {
            let _ = write!(out, ",\"bit_mask\":{mask}");
        }
        None => out.push_str(",\"bit_mask\":null"),
    }
    push_text_cell("carrier", row.carrier.as_deref(), out);
    push_cell("stored", row.stored, out);
    push_text_cell("measures", row.measures.as_deref(), out);
    push_cell("ring_max", row.ring_max, out);
    match row.ring_max_width {
        Some(width) => {
            let _ = write!(out, ",\"ring_max_width\":{width}");
        }
        None => out.push_str(",\"ring_max_width\":null"),
    }
    out.push('}');
}

fn refuse_text(head: &str, error: &DocError) -> String {
    let (position, reason, message) = match error {
        DocError::Syntax { offset, expected } => {
            let reason = alloc::format!("the text is not JSON: expected {expected}");
            let message = alloc::format!("description at byte {offset}: {reason}");
            (
                alloc::format!(",\"description_offset\":{offset}"),
                reason,
                message,
            )
        }
        DocError::Invalid { path, reason } => {
            let mut position = String::from(",\"description_path\":");
            escape_into(path, &mut position);
            let message = if path.is_empty() {
                alloc::format!("description: {reason}")
            } else {
                alloc::format!("description {path}: {reason}")
            };
            (position, reason.clone(), message)
        }
    };
    let mut out = alloc::format!("{{{head},\"ok\":false{position},\"reason\":");
    escape_into(&reason, &mut out);
    out.push_str(",\"message\":");
    escape_into(&message, &mut out);
    out.push('}');
    out
}

fn refuse_plain(head: &str, reason: &str) -> String {
    let mut out = alloc::format!("{{{head},\"ok\":false,\"reason\":");
    escape_into(reason, &mut out);
    out.push_str(",\"message\":");
    escape_into(reason, &mut out);
    out.push('}');
    out
}

fn layout_reason(error: &LayoutError) -> String {
    match error {
        LayoutError::Unreadable(why) => {
            alloc::format!("the bytes built could not be read back for the layout: {why}")
        }
        LayoutError::Unclassified { name } => alloc::format!(
            "the layout has a field `{name}` this build does not classify; the bytes are \
             built but their report cannot be given"
        ),
        LayoutError::Untiled { at } => {
            alloc::format!("the layout does not cover the body: byte {at} belongs to no field")
        }
        LayoutError::NonCanonicalVle {
            name,
            width,
            canonical,
        } => alloc::format!(
            "the field `{name}` is a VLE of {width} bytes and its value needs {canonical}"
        ),
    }
}

fn success(head: &str, built: &Built) -> String {
    let mut out = alloc::format!(
        "{{{head},\"ok\":true,\"prefix_bytes\":{},\"unit\":\"",
        built.prefix_bytes
    );
    push_hex(&built.unit, &mut out);
    out.push_str("\",\"body\":\"");
    push_hex(&built.body, &mut out);
    out.push_str("\",\"layout\":[");
    for (i, row) in built.layout.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_row(row, &mut out);
    }
    out.push_str("]}");
    out
}

/// The `transport_build` document for building `description` as `framing`.
pub fn build_document(description: &str, framing: Framing) -> String {
    let head = envelope(TRANSPORT_BUILD);
    match build(description, framing) {
        Ok(built) => success(&head, &built),
        Err(BuildError::Description(e)) => refuse_text(&head, &e),
        Err(BuildError::Unit(reason)) => refuse_plain(&head, &reason),
        Err(BuildError::Layout(e)) => refuse_plain(&head, &layout_reason(&e)),
    }
}

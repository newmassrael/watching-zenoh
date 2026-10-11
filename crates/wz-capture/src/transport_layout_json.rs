// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `transport_layout` document: the structural report of a transport
//! message's bytes that ALREADY EXIST (a captured frame), in the row shape the
//! `transport_build` document gives the bytes it built, or the reason the bytes
//! could not be reported.
//!
//! It is the second door onto one function. `transport_build` composes bytes and
//! reports them with [`crate::transport_layout::layout`]; this document hands
//! `layout` bytes someone else wrote. The rows are rendered by `push_layout`,
//! which both documents call, so a key or a cell added to a row arrives in both
//! and a consumer that reads one reads the other.
//!
//! ```text
//! {"document":{"name":"transport_layout","revision":1},"ok":true,
//!  "prefix_bytes":2,"body_bytes":4,
//!  "layout":[{"name":"unit_length","kind":"length","offset":0,"width":2,
//!             "relative_to":"unit","encoding":"fixed","value":4,"min":0,"max":65535,
//!             "bit_mask":null,"carrier":null,"stored":null,"measures":"body",
//!             "ring_max":null,"ring_max_width":null}, ...]}
//! ```
//!
//! # A refusal is a value
//!
//! `{"document":{...},"ok":false,"reason":"...","message":"..."}`, for bytes the
//! report cannot be given for: they do not read as a transport message, they read
//! as one the report does not cover, a stream prefix disagrees with the bytes
//! behind it, bytes follow the message, or a VLE is not the shortest encoding of
//! its value. There is no position key, because the refusal is about the bytes as
//! a whole and the dissector does not name where a read gave out. Nothing is
//! truncated and no row is guessed: a document either reports every byte of the
//! body or refuses.
//!
//! # What is and is not refused
//!
//! * A stream framing's prefix must announce exactly the bytes that follow it.
//!   The report says `unit_length` MEASURES `body`, and a prefix that does not
//!   would make that a lie. A capture cut short, or one that holds the start of
//!   the next unit, is refused with both numbers; the caller who wants the layout
//!   of the message alone passes it as a datagram.
//! * A Frame or a Fragment keeps its tail as ONE `payload` row, so a datagram cut
//!   inside the payload is a shorter message and reports as one. Every other
//!   message ends where its fields end, and bytes after them are refused.
//! * A sequence number outside the ring the caller named is reported as it
//!   stands: `value` above `ring_max` is a fact about the session, not about the
//!   bytes, and the caller compares the two.
//!
//! # Integers
//!
//! The cells that can reach 2^53 follow the rule every document here keeps, as
//! `transport_build`'s do: a number below it and a decimal string beyond.

use alloc::string::String;
use core::fmt::Write as _;

use wz_session_core::json::{escape_into, u64_into};
use wz_session_core::transport_compose::{sn_ring_max, Framing};

use crate::doc_revision::{envelope, TRANSPORT_LAYOUT};
use crate::transport_build::RESOLUTION_WORDS;
use crate::transport_layout::{layout, LayoutError, Row, COVERED_MESSAGES};

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

/// The `"layout":[...]` member, rows in wire order, with no comma before it.
///
/// THE ONE RENDERING of a row: the `transport_build` document and this one both
/// write their rows here, so the two doors cannot answer the same bytes in two
/// shapes.
pub(crate) fn push_layout(rows: &[Row], out: &mut String) {
    out.push_str("\"layout\":[");
    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_row(row, out);
    }
    out.push(']');
}

/// The largest sequence number the ring `word` names holds, or `None` for a
/// word that is not one of [`RESOLUTION_WORDS`].
///
/// The same four words `transport_build` reads an `sn_resolution` by and the
/// dissector prints `sn_res_frame_sn` with, so a caller that read the
/// resolution off a handshake passes it through unchanged.
pub fn ring_max_of(word: &str) -> Option<u64> {
    RESOLUTION_WORDS
        .iter()
        .position(|w| *w == word)
        .map(|code| sn_ring_max(code as u8))
}

fn refuse(head: &str, reason: &str) -> String {
    let mut out = alloc::format!("{{{head},\"ok\":false,\"reason\":");
    escape_into(reason, &mut out);
    out.push_str(",\"message\":");
    escape_into(reason, &mut out);
    out.push('}');
    out
}

fn read_reason(error: &LayoutError, body_bytes: usize) -> String {
    match error {
        LayoutError::Unreadable(why) if why == "NeedMoreBytes" => String::from(
            "the bytes end inside a field of the message (NeedMoreBytes), so no report can be given",
        ),
        LayoutError::Unreadable(why) => {
            alloc::format!("the bytes do not read as a transport message: {why}")
        }
        LayoutError::NotCovered { name, mid } => {
            let covered = COVERED_MESSAGES.join(", ");
            if name == "Unknown" {
                alloc::format!(
                    "message id {mid} is not one the transport space names; the report covers {covered}"
                )
            } else {
                alloc::format!(
                    "message id {mid} is `{name}`, which the report does not cover; it covers {covered}"
                )
            }
        }
        LayoutError::Unclassified { name } => alloc::format!(
            "the message has a field `{name}` this build does not classify, so its report \
             cannot be given"
        ),
        LayoutError::Untiled { at } => alloc::format!(
            "the message ends at byte {at} of the {body_bytes}-byte body and the rest belongs to \
             no field of it: bytes follow the message"
        ),
        LayoutError::NonCanonicalVle {
            name,
            width,
            canonical,
        } => alloc::format!(
            "the field `{name}` is a VLE of {width} bytes and its value needs {canonical}: the \
             format reads it, and the report's min and max would be wrong about its width"
        ),
    }
}

/// The refusal document for a report that could not be derived from a body of
/// `body_bytes` bytes.
pub(crate) fn refusal_for(error: &LayoutError, body_bytes: usize) -> String {
    refuse(&envelope(TRANSPORT_LAYOUT), &read_reason(error, body_bytes))
}

/// The `transport_layout` document for `unit`, the bytes of ONE unit as
/// `framing` writes it: the framing's length prefix, if it has one, then the
/// transport message.
///
/// `ring_max` is the largest sequence number the session's ring holds, when the
/// caller knows the ring ([`ring_max_of`]): the sequence-number rows then carry
/// it and the widest their VLE can become, and otherwise carry `null`.
pub fn layout_document(unit: &[u8], framing: Framing, ring_max: Option<u64>) -> String {
    let head = envelope(TRANSPORT_LAYOUT);
    let prefix = framing.prefix_bytes();
    if unit.len() < prefix {
        return refuse(
            &head,
            &alloc::format!(
                "a unit of {} bytes has no room for the {prefix}-byte length prefix of the {} \
                 framing",
                unit.len(),
                framing.name()
            ),
        );
    }
    let body_bytes = unit.len() - prefix;
    if prefix > 0 {
        let announced = unit[..prefix]
            .iter()
            .rev()
            .fold(0u64, |acc, byte| acc << 8 | u64::from(*byte));
        if announced != body_bytes as u64 {
            return refuse(
                &head,
                &alloc::format!(
                    "the {} framing's length prefix announces {announced} bytes and {body_bytes} \
                     follow it: the unit is cut short or holds more than one message",
                    framing.name()
                ),
            );
        }
    }
    match layout(unit, framing, ring_max) {
        Ok(rows) => {
            let mut out = alloc::format!(
                "{{{head},\"ok\":true,\"prefix_bytes\":{prefix},\"body_bytes\":{body_bytes},"
            );
            push_layout(&rows, &mut out);
            out.push('}');
            out
        }
        Err(error) => refusal_for(&error, body_bytes),
    }
}

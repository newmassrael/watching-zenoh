// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y856 — the payload format decoders this workspace SHIPS, beside the map
//! that selects them.
//!
//! ## Why they are here and not in the command line
//!
//! R311y699 put them in `wz-analyze`, the composition root, on the rule that
//! this crate has zero third-party dependencies because its decode path builds
//! for the MCU profiles and "a format decoder is exactly the kind of thing that
//! grows one". The rule is right; it did not describe the decoder it excluded.
//! [`Protobuf`] is a hand-written walk over base-128 varints and takes no
//! dependency at all.
//!
//! What the misplacement cost was MEASURED by `analysis_surface_parity.py`: the
//! C ABI — the surface a product LINKS — could not decode a payload, because
//! the registry it would have to name lived in a binary it must not depend on
//! (`wz-analyze` pulls `wz-tls-record`, and through it `ring`). The seam it was
//! told to reach, [`crate::payload::formats::FormatMap`], was public with
//! nothing on that side able to build one. Moving the decoder beside the map is
//! what R311y851 did for the census emit, for the same reason: one
//! implementation beside the type, and neither consumer owning it.
//!
//! ## Private module, public through `formats`
//!
//! Nothing outside names `crate::payload_builtin`; the items are re-exported by
//! [`crate::payload::formats`], where the trait and the map are. A caller reads
//! one module and the file boundary stays an authoring convenience rather than
//! a second place to look.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::payload::formats::{PayloadField, PayloadFormat, PayloadFormatError};

/// The protobuf WIRE FORMAT, walked without a schema.
///
/// # Why this one is the built-in, and what it can honestly claim
///
/// nanopb emits protobuf's wire format, and that format is
/// self-describing enough to walk with no `.proto` at all: every field
/// carries its number and one of four wire types, and each wire type
/// determines its own length. So a reader gets field numbers, wire types,
/// values and BYTE SPANS — the structure — without anyone shipping a
/// schema.
///
/// What it cannot give is NAMES: field 3 is field 3, not `temperature`.
/// Said plainly rather than papered over, because a decoder that invented
/// names would be the worst kind of wrong on a plane whose whole output is
/// findings.
///
/// # Why not an `e2e` built-in beside it
///
/// An AUTOSAR E2E profile is a CRC, a counter and a data id at offsets the
/// PROFILE fixes, and this machine's sources carry neither the profile
/// table nor the CRC polynomial — a grep for `0x1021` / `crc16` across
/// every crate returns nothing. This workspace's own rule (R311y695) is
/// that a constant a module cannot check is one it must not carry, so `e2e`
/// is a format a deployment supplies through the seam rather than one
/// invented here from memory.
pub struct Protobuf;

/// The four wire types of protobuf, and what each one's length is.
fn wire_type_name(ty: u64) -> Option<&'static str> {
    match ty {
        0 => Some("varint"),
        1 => Some("i64"),
        2 => Some("len"),
        5 => Some("i32"),
        _ => None,
    }
}

/// One base-128 varint, advancing `at`.
fn varint(bytes: &[u8], at: &mut usize) -> Result<u64, PayloadFormatError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let start = *at;
    loop {
        let byte = *bytes.get(*at).ok_or(PayloadFormatError::Truncated(start))?;
        *at += 1;
        // Ten groups of seven bits is 70, so the tenth byte may only carry
        // the one bit left of a u64. A longer run is malformed rather than
        // silently truncated -- the shift would panic in debug and wrap the
        // value in release, which is the pair of behaviours a decoder over
        // adversarial bytes must not have.
        if shift >= 64 {
            return Err(PayloadFormatError::Malformed {
                at: start,
                why: String::from("a varint longer than ten bytes"),
            });
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// R311y701 (PF3) — how deep a nested walk goes before it stops walking.
///
/// A payload is attacker-influenced bytes and a length-delimited field can
/// name another one forever, so the recursion is bounded like every other
/// walk in this workspace. Eight is past any hand-written schema this
/// analyzer is pointed at, and what sits below it is not silently dropped —
/// the field says the nesting went further than this reader walks.
const MAX_NESTING: usize = 8;

/// Is this run of bytes TEXT rather than a nested message?
///
/// # Why the question is asked this way, and what it cannot settle
///
/// Protobuf's wire format does not distinguish a string, a nested message
/// and a blob: all three are wire type 2, and the ambiguity is IN THE
/// FORMAT rather than in this reader. So there is no rule that is right
/// every time and the choice is which mistake to make.
///
/// Valid UTF-8 with no control characters is a strong signal for a string
/// and a weak one for a message: a nested message begins with a tag byte,
/// and the overwhelming majority of tags (any field with a varint under a
/// small number, any 64-bit or 32-bit field) put a control byte or a
/// non-UTF-8 byte in the first two positions. "Parses as protobuf" is by
/// contrast very permissive — two bytes like `"Px"` parse cleanly as field
/// 10 varint 120 — so trying the parse first would rename short strings as
/// messages far more often than this rule hides a message.
fn text_like(raw: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(raw).ok()?;
    if text.is_empty() {
        return None;
    }
    text.chars()
        .all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r')
        .then_some(text)
}

/// Walk `payload`, whose first byte sits at `base` in the message this
/// decoding will be rendered against, appending to `out` under `prefix`.
///
/// R311y701 — `base` and `prefix` are what make the recursion honest. A
/// nested field's span must be in the SAME coordinate space as its parent's
/// or a reader cannot line the two up, and its path must name the route to
/// it (`2.1`) rather than restart at `1` — a listing with two fields called
/// `1` says nothing about where either lives.
fn walk(
    payload: &[u8],
    base: usize,
    depth: usize,
    prefix: &str,
    out: &mut Vec<PayloadField>,
) -> Result<(), PayloadFormatError> {
    let mut at = 0usize;
    while at < payload.len() {
        let start = at;
        let tag = varint(payload, &mut at).map_err(|e| rebase(e, base))?;
        let number = tag >> 3;
        let wire = tag & 0x07;
        let Some(kind) = wire_type_name(wire) else {
            // Wire types 3 and 4 are the deprecated group markers and 6
            // and 7 are unassigned. A reader that stepped over one
            // would not know where it ends, so this stops -- the same
            // rule the QUIC frame walk follows for an unknown type.
            return Err(PayloadFormatError::Malformed {
                at: base + start,
                why: format!("wire type {wire} has no length rule"),
            });
        };
        if number == 0 {
            // Field number zero is invalid in every protobuf version,
            // and it is what a run of zero bytes decodes to -- which is
            // the single most likely thing to be under a WRONG mapping.
            return Err(PayloadFormatError::NotThisFormat);
        }
        let path = if prefix.is_empty() {
            format!("{number}")
        } else {
            format!("{prefix}.{number}")
        };
        // The children of a nested field are collected into their own
        // vector so the PARENT row can be pushed before them: a listing
        // reads top-down, and a walk that pushed as it went would put
        // `2.1` above `2`.
        let mut children = Vec::new();
        let value = match wire {
            0 => {
                let v = varint(payload, &mut at).map_err(|e| rebase(e, base))?;
                format!("{v}")
            }
            1 | 5 => {
                let width = if wire == 1 { 8 } else { 4 };
                let end = at
                    .checked_add(width)
                    .ok_or(PayloadFormatError::Truncated(base + at))?;
                let raw = payload
                    .get(at..end)
                    .ok_or(PayloadFormatError::Truncated(base + at))?;
                at = end;
                format!(
                    "0x{}",
                    raw.iter()
                        .rev()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                )
            }
            _ => {
                let len = varint(payload, &mut at).map_err(|e| rebase(e, base))? as usize;
                let body = at;
                let end = at
                    .checked_add(len)
                    .ok_or(PayloadFormatError::Truncated(base + at))?;
                let raw = payload
                    .get(at..end)
                    .ok_or(PayloadFormatError::Truncated(base + at))?;
                at = end;
                // Rendered as text when it IS text, because a
                // length-delimited field is a string as often as it is
                // a nested message and a reader should not have to
                // decode hex to find out.
                match text_like(raw) {
                    Some(text) => format!("{text:?}"),
                    // R311y701 (PF3) — otherwise it may be a NESTED
                    // MESSAGE, which nesting is common enough in real
                    // schemas that stopping here showed a reader one
                    // layer of their own data.
                    None if depth >= MAX_NESTING => {
                        format!("{len} byte(s), nested deeper than this reader walks")
                    }
                    None => {
                        // A TRY, and a failure falls back rather than
                        // rejecting the message: these bytes may simply be
                        // a blob, and a blob is not a malformed message.
                        // The whole sub-buffer must be consumed and yield
                        // at least one field, or "it parsed" would be a
                        // statement about a prefix.
                        match walk(raw, base + body, depth + 1, &path, &mut children) {
                            Ok(()) if !children.is_empty() => {
                                format!("{} field(s)", children.len())
                            }
                            _ => {
                                children.clear();
                                format!("{len} byte(s)")
                            }
                        }
                    }
                }
            }
        };
        out.push(PayloadField {
            path,
            // R311y720 (PF4) — ALWAYS `None` here, and it is a statement
            // rather than a placeholder: protobuf's wire format carries no
            // names, so this decoder has none to give. The declaration
            // fills it in, in `decode_payload`.
            name: None,
            value: format!("{kind} {value}"),
            start: base + start,
            end: base + at,
        });
        out.append(&mut children);
    }
    Ok(())
}

/// Move an error's offset into the outer payload's coordinates.
fn rebase(err: PayloadFormatError, base: usize) -> PayloadFormatError {
    match err {
        PayloadFormatError::Truncated(at) => PayloadFormatError::Truncated(base + at),
        other => other,
    }
}

impl PayloadFormat for Protobuf {
    fn name(&self) -> &str {
        "protobuf"
    }

    fn decode(&self, payload: &[u8]) -> Result<Vec<PayloadField>, PayloadFormatError> {
        if payload.is_empty() {
            // An empty payload is not a protobuf message this reader can
            // vouch for; it is also not malformed. Saying NotThisFormat
            // sends the reader to their mapping, which is where an empty
            // payload under a protobuf rule usually comes from.
            return Err(PayloadFormatError::NotThisFormat);
        }
        let mut out = Vec::new();
        walk(payload, 0, 0, "", &mut out)?;
        Ok(out)
    }
}

/// The format a name selects, or `None` for a name this build has no
/// decoder for.
///
/// A refusal rather than a fallback: a reader who typed `--payload-format
/// 'demo/**=protobufff'` and got the bytes rendered as hex would think
/// their rule was live.
pub fn builtin(name: &str) -> Option<&'static dyn PayloadFormat> {
    match name {
        "protobuf" => Some(&Protobuf),
        _ => None,
    }
}

/// Every built-in name, for the usage text and for a refusal that can say
/// what IS available.
pub const BUILTIN_NAMES: &[&str] = &["protobuf"];

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// R311y701 (PF3) — A NESTED MESSAGE IS WALKED, and its fields carry
    /// the ROUTE to them and spans in the OUTER payload's coordinates.
    ///
    /// Before this round wire type 2 was rendered as text or as a byte
    /// count, so a reader whose schema nests — which real schemas do — saw
    /// exactly one layer of their own data and no sign there was more.
    #[test]
    fn a_nested_message_is_walked_and_its_paths_name_the_route() {
        // { 1: 150, 2: { 1: 7, 2: "in" } }
        let inner = [0x08u8, 0x07, 0x12, 0x02, b'i', b'n'];
        let mut outer = vec![0x08u8, 0x96, 0x01, 0x12, inner.len() as u8];
        outer.extend_from_slice(&inner);

        let fields = Protobuf.decode(&outer).expect("a protobuf message");
        let seen: Vec<(&str, &str, usize, usize)> = fields
            .iter()
            .map(|f| (f.path.as_str(), f.value.as_str(), f.start, f.end))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("1", "varint 150", 0, 3),
                // The parent is rendered as a COUNT of what is under it and
                // stands ABOVE its children, so the listing reads top-down.
                ("2", "len 2 field(s)", 3, 11),
                // R311y677's rule, one layer in: the inner spans are in the
                // outer payload's space, so a reader can line them up
                // against the bytes. `5` is where the nested body begins.
                ("2.1", "varint 7", 5, 7),
                ("2.2", "len \"in\"", 7, 11),
            ],
            "the walk must reach the nested fields and name the route to them"
        );
    }

    /// R311y701 (PF3) — TWO layers, because one does not test the rebase.
    ///
    /// MEASURED: dropping the accumulated `base` from the recursive call
    /// left the one-layer test above GREEN, and it has to — at the top
    /// level `base` is zero, so `base + body` and `body` are the same
    /// number. The offset only diverges from the second layer down, which
    /// is where a probe put it and where this witness now sits.
    #[test]
    fn a_span_two_layers_in_is_still_in_the_outer_payloads_coordinates() {
        // { 1: { 1: { 1: 7 } } }
        let innermost = [0x08u8, 0x07];
        let mid = [0x0Au8, innermost.len() as u8, innermost[0], innermost[1]];
        let mut outer = vec![0x0Au8, mid.len() as u8];
        outer.extend_from_slice(&mid);

        let fields = Protobuf.decode(&outer).expect("a protobuf message");
        let seen: Vec<(&str, usize, usize)> = fields
            .iter()
            .map(|f| (f.path.as_str(), f.start, f.end))
            .collect();
        assert_eq!(
            seen,
            vec![("1", 0, 6), ("1.1", 2, 6), ("1.1.1", 4, 6)],
            "each layer's body begins two bytes past its parent's, and the \
             offsets ACCUMULATE"
        );
    }

    /// R311y701 (PF3) — bytes that are NOT a message fall back rather than
    /// rejecting the whole payload.
    ///
    /// A length-delimited field is a string, a message OR a blob, and the
    /// wire format does not say which. A recursion that treated "does not
    /// parse" as malformed would refuse every payload carrying a JPEG.
    #[test]
    fn a_length_field_that_is_not_a_message_falls_back_to_its_byte_count() {
        // Field 1, four bytes that start with a valid-looking tag and then
        // run out: `0x08` says field 1 varint and nothing follows it.
        let blob = [0xFFu8, 0xD8, 0xFF, 0x08];
        let mut outer = vec![0x0Au8, blob.len() as u8];
        outer.extend_from_slice(&blob);

        let fields = Protobuf.decode(&outer).expect("still a protobuf message");
        assert_eq!(
            fields.len(),
            1,
            "the blob contributes no children: {fields:?}"
        );
        assert_eq!(fields[0].value, "len 4 byte(s)");
    }

    /// R311y701 (PF3) — text still wins over a nested parse, and the rule
    /// that makes that safe is stated on [`text_like`].
    ///
    /// `"Px"` parses cleanly as field 10 varint 120. It is a string, and a
    /// walker that tried the parse first would rename it.
    #[test]
    fn printable_bytes_are_text_even_when_they_would_parse_as_a_message() {
        let mut outer = vec![0x0Au8, 2];
        outer.extend_from_slice(b"Px");
        let fields = Protobuf.decode(&outer).expect("a protobuf message");
        assert_eq!(fields[0].value, "len \"Px\"");
        assert_eq!(fields.len(), 1, "and nothing was walked into it");

        // The control-character half of the rule, which is what lets a
        // nested message through: the same two bytes with a control byte in
        // front are not text.
        assert!(text_like(b"Px").is_some());
        assert!(text_like(&[0x08, 0x07]).is_none());
    }

    /// R311y701 (PF3) — the depth bound is REPORTED rather than silently
    /// stopping, the rule every bound in this workspace answers to.
    #[test]
    fn nesting_past_the_bound_says_so_rather_than_going_quiet() {
        // MAX_NESTING + 1 layers, each one field 1 wrapping the next, with
        // a two-byte non-text leaf so no layer is mistaken for a string.
        let mut body = vec![0x08u8, 0x07];
        for _ in 0..=MAX_NESTING {
            let mut wrapped = vec![0x0Au8, body.len() as u8];
            wrapped.extend_from_slice(&body);
            body = wrapped;
        }
        let fields = Protobuf.decode(&body).expect("a protobuf message");
        let deepest = fields.last().expect("at least one field");
        assert!(
            deepest
                .value
                .contains("nested deeper than this reader walks"),
            "the bottom of the walk says the bound bit: {fields:?}"
        );
        // And the bound is the one declared, counted by path depth.
        assert_eq!(
            deepest.path.matches('.').count(),
            MAX_NESTING,
            "the walk went exactly as deep as it says it does: {fields:?}"
        );
    }
}

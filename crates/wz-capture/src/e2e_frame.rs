// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Building and opening a protected frame under a [`Profile`].
//!
//! Both directions are stateless functions of the profile and their input. The
//! only state a protected link has, the counter, is an input of [`build`] and
//! an output of [`open`]; what a receiver does with a SEQUENCE of counters is
//! [`crate::e2e_judge`]'s.
//!
//! # Build
//!
//! [`build`] takes the values of every field the mechanism does not compute
//! ([`Values`]: a number for a plain field, one number per part for a split
//! one, and the counter) and the body. It lays the fields out in wire order as
//! big-endian integers, computes the length from the body, feeds the CRC the
//! covered pieces in the profile's order, and writes the CRC. A value that does
//! not fit is REFUSED, never truncated: a field that silently lost its high
//! bits would be a frame about some other message.
//!
//! # Open
//!
//! [`open`] reads every field, undoes the `xor`, splits, and recomputes the CRC
//! over the received bytes. It reports three facts about the length, none of
//! which is a verdict: the value in the field, the value a sender using the
//! profile's rule would have written for this frame, and whether they agree.
//! The CRC takes the length field as it stands on the wire, never a length
//! recomputed from the frame. That is what keeps the two questions apart: a
//! sender that counts the length by another rule than the profile's still
//! produces frames whose CRC verifies, and shows only as
//! `length_matches_frame == false`; damage shows as `crc_ok == false`, with the
//! length facts clean unless the length field itself was hit. A consumer reads
//! the pair and can tell "the sender counts differently" from "bytes were
//! damaged" instead of reading both as damage.
//!
//! A frame shorter than the header is the only thing [`open`] refuses; every
//! other defect is a fact in the result. The body is whatever follows the
//! header: its extent is never taken from the length field.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use wz_session_core::json5::Json5Value;

use crate::e2e_profile::{
    check_distinct, child, object, read_json, read_uint, Cover, DocError, Profile,
};

/// What the caller supplies for one field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Supplied {
    /// The value of a plain field.
    Whole(u64),
    /// The value of each part of a split field, by part name.
    Parts(Vec<(String, u64)>),
}

/// The values of the fields a frame is built from.
///
/// Everything the mechanism does not compute: the CRC and the length are left
/// out, and giving one is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Values {
    entries: Vec<(String, Supplied)>,
}

impl Values {
    /// No values yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Supply a plain field.
    pub fn whole(mut self, field: &str, value: u64) -> Self {
        self.entries.push((field.into(), Supplied::Whole(value)));
        self
    }

    /// Supply the parts of a split field.
    pub fn parts(mut self, field: &str, parts: &[(&str, u64)]) -> Self {
        let parts = parts.iter().map(|&(n, v)| (n.into(), v)).collect();
        self.entries.push((field.into(), Supplied::Parts(parts)));
        self
    }

    /// Read the values from JSON: an object whose keys are field names, each
    /// either an unsigned integer or, for a split field, an object of
    /// integers keyed by part name.
    ///
    /// ```text
    /// {"counter": 258,
    ///  "ident": {"domain": 3, "version": 7, "msg": 4660},
    ///  "cell": {"kind": 1, "result": 0, "sender": "0x0ABCDEF"}}
    /// ```
    ///
    /// Whether the names exist, and whether each value fits, is judged against
    /// a profile by [`build`].
    pub fn parse(text: &str) -> Result<Self, DocError> {
        let root = read_json(text)?;
        let entries = object(&root, "")?;
        check_distinct(entries, "")?;
        let mut out = Vec::with_capacity(entries.len());
        for (name, value) in entries {
            let here = child("", name);
            let supplied = match value {
                Json5Value::Object(parts) => {
                    check_distinct(parts, &here)?;
                    let mut list = Vec::with_capacity(parts.len());
                    for (part, v) in parts {
                        list.push((part.clone(), read_uint(v, &child(&here, part))?));
                    }
                    Supplied::Parts(list)
                }
                other => Supplied::Whole(read_uint(other, &here)?),
            };
            out.push((name.clone(), supplied));
        }
        Ok(Self { entries: out })
    }

    fn get(&self, field: &str) -> Option<&Supplied> {
        self.entries
            .iter()
            .find(|(n, _)| n == field)
            .map(|(_, s)| s)
    }
}

/// Why a frame could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// A value is missing, unknown, of the wrong shape, or does not fit; the
    /// path points into the values document.
    Values(DocError),
    /// The body is longer than the length field can describe.
    PayloadTooLong {
        /// The body's size.
        payload_bytes: usize,
        /// The length value that body would need.
        length: u64,
        /// The length field.
        field: String,
        /// The field's width in bytes.
        field_bytes: usize,
        /// The largest value the field holds.
        max: u64,
    },
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Values(e) => write!(f, "{e}"),
            Self::PayloadTooLong {
                payload_bytes,
                length,
                field,
                field_bytes,
                max,
            } => write!(
                f,
                "a body of {payload_bytes} bytes makes the length {length}, which does not \
                 fit the {field_bytes}-byte length field `{field}` (largest {max})"
            ),
        }
    }
}

/// Why a frame could not be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// There is not even a whole header.
    ShortFrame {
        /// The frame's size.
        have: usize,
        /// The header's size.
        need: usize,
    },
}

impl core::fmt::Display for OpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ShortFrame { have, need } => write!(
                f,
                "the frame is {have} bytes and the header alone is {need}"
            ),
        }
    }
}

/// One field of a built or opened frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldReport {
    /// Index into [`Profile::fields`].
    pub index: usize,
    /// The integer on the wire.
    pub raw: u64,
    /// The logical value: `raw` with the `xor` undone, which is what the parts
    /// are cut from.
    pub value: u64,
    /// The value of each part, in the order the profile declares them; empty
    /// for a plain field.
    pub parts: Vec<u64>,
}

/// A frame [`build`] made, with every step it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltFrame {
    /// The frame: header, then body.
    pub bytes: Vec<u8>,
    /// Every header field, in wire order.
    pub fields: Vec<FieldReport>,
    /// The CRC that was written.
    pub crc: u64,
    /// The length that was written.
    pub length: u64,
    /// Where the body starts.
    pub payload_offset: usize,
    /// The body's size.
    pub payload_bytes: usize,
}

/// A frame [`open`] read: its fields and the facts about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedFrame {
    /// Every header field, in wire order.
    pub fields: Vec<FieldReport>,
    /// The CRC field as received.
    pub crc_found: u64,
    /// The CRC recomputed over the received bytes.
    pub crc_computed: u64,
    /// Whether they agree.
    pub crc_ok: bool,
    /// The length field as received.
    pub length_found: u64,
    /// What the profile's length rule gives for this frame's body.
    pub length_expected: u64,
    /// Whether they agree. Information, not a verdict.
    pub length_matches_frame: bool,
    /// Where the body starts.
    pub payload_offset: usize,
    /// The body's size: the frame less the header.
    pub payload_bytes: usize,
}

impl OpenedFrame {
    /// The counter, as the judge reads it.
    pub fn counter(&self, profile: &Profile) -> u64 {
        self.fields[profile.counter().field].value
    }
}

fn read_be(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |acc, &b| (acc << 8) | u64::from(b))
}

fn write_be(out: &mut [u8], value: u64) {
    let n = out.len();
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = (value >> (8 * (n - 1 - i))) as u8;
    }
}

/// The CRC of `frame` as the profile feeds it: the covered pieces, in the
/// profile's order, each as it stands on the wire.
fn crc_over(profile: &Profile, frame: &[u8]) -> u64 {
    let mut digest = profile.crc().engine.start();
    for item in &profile.crc().cover {
        match *item {
            Cover::Field(index) => {
                let field = &profile.fields()[index];
                digest.update(&frame[field.offset..field.offset + field.bytes]);
            }
            Cover::Payload => digest.update(&frame[profile.header_bytes()..]),
        }
    }
    digest.finish()
}

fn invalid(path: String, reason: String) -> BuildError {
    BuildError::Values(DocError::invalid(path, reason))
}

/// Resolve what was supplied for one field to its logical value and parts.
fn resolve(
    profile: &Profile,
    index: usize,
    supplied: Option<&Supplied>,
) -> Result<(u64, Vec<u64>), BuildError> {
    let field = &profile.fields()[index];
    let path = child("", &field.name);
    let Some(supplied) = supplied else {
        return Err(invalid(
            String::new(),
            format!("no value for the field `{}`", field.name),
        ));
    };
    match supplied {
        Supplied::Whole(value) => {
            if !field.parts.is_empty() {
                let names: Vec<&str> = field.parts.iter().map(|p| p.name.as_str()).collect();
                return Err(invalid(
                    path,
                    format!(
                        "the field `{}` is split into parts: supply an object with {}",
                        field.name,
                        names.join(", ")
                    ),
                ));
            }
            if *value > field.max_value() {
                return Err(invalid(
                    path,
                    format!(
                        "{value} does not fit the {}-byte field `{}`",
                        field.bytes, field.name
                    ),
                ));
            }
            Ok((*value, Vec::new()))
        }
        Supplied::Parts(given) => {
            if field.parts.is_empty() {
                return Err(invalid(
                    path,
                    format!("the field `{}` is not split: supply a number", field.name),
                ));
            }
            for (i, (name, _)) in given.iter().enumerate() {
                if !field.parts.iter().any(|p| &p.name == name) {
                    return Err(invalid(
                        child(&path, name),
                        format!("the field `{}` has no part called `{name}`", field.name),
                    ));
                }
                if given[..i].iter().any(|(earlier, _)| earlier == name) {
                    return Err(invalid(
                        child(&path, name),
                        format!("the part `{name}` is supplied twice"),
                    ));
                }
            }
            let mut value = 0u64;
            let mut out = Vec::with_capacity(field.parts.len());
            for part in &field.parts {
                let Some((_, v)) = given.iter().find(|(n, _)| n == &part.name) else {
                    return Err(invalid(
                        path,
                        format!("no value for the part `{}` of `{}`", part.name, field.name),
                    ));
                };
                if *v > part.max_value() {
                    return Err(invalid(
                        child(&path, &part.name),
                        format!(
                            "{v} does not fit the {}-bit part `{}` of `{}`",
                            part.width, part.name, field.name
                        ),
                    ));
                }
                value |= *v << part.lsb;
                out.push(*v);
            }
            Ok((value, out))
        }
    }
}

/// Build the frame for `values` and `payload` under `profile`.
pub fn build(profile: &Profile, values: &Values, payload: &[u8]) -> Result<BuiltFrame, BuildError> {
    let fields = profile.fields();
    let (crc_at, length_at) = (profile.crc().field, profile.length().field);

    for (i, (name, _)) in values.entries.iter().enumerate() {
        let path = child("", name);
        let Some(index) = profile.field_index(name) else {
            return Err(invalid(path, format!("no field is called `{name}`")));
        };
        if index == crc_at || index == length_at {
            let role = if index == crc_at { "crc" } else { "length" };
            return Err(invalid(
                path,
                format!("the {role} field `{name}` is computed: leave it out"),
            ));
        }
        if values.entries[..i]
            .iter()
            .any(|(earlier, _)| earlier == name)
        {
            return Err(invalid(
                path,
                format!("the field `{name}` is supplied twice"),
            ));
        }
    }

    let length = profile.length_for(payload.len());
    let length_field = &fields[length_at];
    if length > length_field.max_value() {
        return Err(BuildError::PayloadTooLong {
            payload_bytes: payload.len(),
            length,
            field: length_field.name.clone(),
            field_bytes: length_field.bytes,
            max: length_field.max_value(),
        });
    }

    let header = profile.header_bytes();
    let mut bytes = vec![0u8; header + payload.len()];
    bytes[header..].copy_from_slice(payload);

    let mut reports: Vec<FieldReport> = Vec::with_capacity(fields.len());
    for (index, field) in fields.iter().enumerate() {
        let (value, parts) = if index == crc_at {
            (0, Vec::new())
        } else if index == length_at {
            (length, Vec::new())
        } else {
            resolve(profile, index, values.get(&field.name))?
        };
        let raw = value ^ field.xor;
        write_be(&mut bytes[field.offset..field.offset + field.bytes], raw);
        reports.push(FieldReport {
            index,
            raw,
            value,
            parts,
        });
    }

    let crc = crc_over(profile, &bytes);
    let crc_field = &fields[crc_at];
    write_be(
        &mut bytes[crc_field.offset..crc_field.offset + crc_field.bytes],
        crc,
    );
    reports[crc_at].raw = crc;
    reports[crc_at].value = crc;

    Ok(BuiltFrame {
        bytes,
        fields: reports,
        crc,
        length,
        payload_offset: header,
        payload_bytes: payload.len(),
    })
}

/// Read `frame` under `profile`.
pub fn open(profile: &Profile, frame: &[u8]) -> Result<OpenedFrame, OpenError> {
    let header = profile.header_bytes();
    if frame.len() < header {
        return Err(OpenError::ShortFrame {
            have: frame.len(),
            need: header,
        });
    }
    let fields: Vec<FieldReport> = profile
        .fields()
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let raw = read_be(&frame[field.offset..field.offset + field.bytes]);
            let value = raw ^ field.xor;
            let parts = field
                .parts
                .iter()
                .map(|p| (value >> p.lsb) & p.max_value())
                .collect();
            FieldReport {
                index,
                raw,
                value,
                parts,
            }
        })
        .collect();

    let crc_found = fields[profile.crc().field].raw;
    let crc_computed = crc_over(profile, frame);
    let payload_bytes = frame.len() - header;
    let length_found = fields[profile.length().field].raw;
    let length_expected = profile.length_for(payload_bytes);
    Ok(OpenedFrame {
        fields,
        crc_found,
        crc_computed,
        crc_ok: crc_found == crc_computed,
        length_found,
        length_expected,
        length_matches_frame: length_found == length_expected,
        payload_offset: header,
        payload_bytes,
    })
}

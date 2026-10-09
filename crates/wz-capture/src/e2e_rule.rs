// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The DECLARATION that ties a key expression pattern to an end-to-end
//! protection profile.
//!
//! # The two lines
//!
//! A deployment registers its profiles once and then says which keys carry
//! which, in the dialect every payload declaration already uses
//! ([`crate::payload::formats::FormatMap`]):
//!
//! ```text
//! #demo-a={"name":"demo-a","fields":[...],"crc":{...},"length":{...},"counter":{...}}
//! demo/sensor/**=demo-a
//! demo/pose/**=demo-a@pkg.Pose
//! ```
//!
//! The first line DEFINES a profile under a name; the profile description is
//! [`crate::e2e_profile`]'s, on ONE line, and its own `name` must be the name
//! the line gives it, so a description read from a file cannot be registered
//! under a second name that nothing else knows it by. The other lines are
//! RULES: the first whose pattern covers a key wins, exactly as for any other
//! format. `@pkg.Pose` is the BODY SCHEMA the rule names: the message type the
//! bytes after the header are an instance of. It is carried and reported, and
//! nothing reads it yet; the door that turns a schema into field names is a
//! later step, and the seam it will read is [`E2eFormat::schema`]. The sending
//! half uses the same name: the `message` of the wrap door's `@body` member
//! ([`crate::e2e_body`]) is this string, so a caller that registered the rule
//! passes its schema to the one door and to the other unchanged.
//!
//! # Why a format and not a second kind of rule
//!
//! A profile rule competes with the other rules for a key: `demo/**=json` ahead
//! of `demo/a=demo-a` means `demo/a` is JSON, and a second list of rules held
//! beside the first would let one key be both. So the rule is an ordinary one
//! whose format is an [`E2eFormat`], and the map's single first-match-wins
//! decides.
//!
//! # What the format decodes
//!
//! The payload walk ([`crate::payload::formats::PayloadFormat::decode`]) reads
//! the BODY: the bytes after the header, as the schema-less protobuf walk reads
//! them, with spans in payload coordinates. The header, its CRC and the
//! counter are not a decode: they are judged, with state, by
//! [`crate::e2e_slots`], and reported beside the decode under the entry's
//! `e2e` key.

use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::e2e_profile::Profile;
use crate::payload::formats::{PayloadField, PayloadFormat, PayloadFormatError, Protobuf};

/// The character that separates a profile name from a body schema in a rule's
/// format token.
///
/// Not one of the characters the declaration dialect quotes, and not a
/// character a profile name may hold (a name is letters, digits, `_`, `-` and
/// `.`), so `name@schema` is read the same way wherever it is written.
pub const SCHEMA_MARK: char = '@';

/// The longest schema reference a rule carries, in bytes.
pub const MAX_SCHEMA_BYTES: usize = 128;

/// Why a body schema reference was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaRefusal(pub String);

impl core::fmt::Display for SchemaRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Check a body schema reference: a protobuf message's full name, which is
/// identifiers joined by single dots.
pub fn check_schema(schema: &str) -> Result<(), SchemaRefusal> {
    let refuse = |why: String| Err(SchemaRefusal(why));
    if schema.is_empty() {
        return refuse(String::from("the schema after `@` is empty"));
    }
    if schema.len() > MAX_SCHEMA_BYTES {
        return refuse(format!(
            "a schema reference is at most {MAX_SCHEMA_BYTES} bytes, this one is {}",
            schema.len()
        ));
    }
    for segment in schema.split('.') {
        let mut chars = segment.chars();
        let starts = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if !starts || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return refuse(format!(
                "`{schema}` is not a message name: expected identifiers joined by single \
                 dots (`pkg.Message`)"
            ));
        }
    }
    Ok(())
}

/// A profile bound to a rule: the thing a key expression pattern maps to.
///
/// Cheap to clone and to share between rules, because the profile it names is
/// registered once and read by as many rules as the deployment writes.
#[derive(Debug, Clone)]
pub struct E2eFormat {
    profile: Rc<Profile>,
    schema: Option<String>,
}

impl E2eFormat {
    /// A rule's format: `profile`, and the body schema the rule names, if any.
    ///
    /// The schema is checked here, so a format that exists names a schema the
    /// later step can look up. The profile's name is not checked again; a
    /// profile is only registered under a name it can be written in.
    pub fn new(profile: Rc<Profile>, schema: Option<String>) -> Result<Self, SchemaRefusal> {
        if let Some(schema) = &schema {
            check_schema(schema)?;
        }
        Ok(Self { profile, schema })
    }

    /// The profile.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The body schema the rule names: the seam the later step reads.
    pub fn schema(&self) -> Option<&str> {
        self.schema.as_deref()
    }

    /// The rule's format token as it is written after `=`.
    pub fn token(&self) -> String {
        match &self.schema {
            Some(schema) => format!("{}{SCHEMA_MARK}{schema}", self.profile.name()),
            None => String::from(self.profile.name()),
        }
    }
}

/// Move a decoder's offset from body coordinates to payload coordinates.
fn rebase_error(error: PayloadFormatError, header: usize) -> PayloadFormatError {
    match error {
        PayloadFormatError::Truncated(at) => PayloadFormatError::Truncated(at + header),
        PayloadFormatError::Malformed { at, why } => PayloadFormatError::Malformed {
            at: at + header,
            why,
        },
        PayloadFormatError::NotThisFormat => PayloadFormatError::NotThisFormat,
    }
}

impl PayloadFormat for E2eFormat {
    fn name(&self) -> &str {
        self.profile.name()
    }

    /// Walk the BODY: what follows the header, read as protobuf.
    ///
    /// The header is not walked here and its verdict does not gate the body: a
    /// frame whose CRC failed still has a body, and the reader looking at a
    /// failed CRC is exactly the one who wants to see what the bytes say. The
    /// CRC verdict is beside it under `e2e`. A payload shorter than the header
    /// has no body, and says so as a truncation at its end.
    fn decode(&self, payload: &[u8]) -> Result<Vec<PayloadField>, PayloadFormatError> {
        let header = self.profile.header_bytes();
        let Some(body) = payload.get(header..) else {
            return Err(PayloadFormatError::Truncated(payload.len()));
        };
        let mut fields = Protobuf
            .decode(body)
            .map_err(|error| rebase_error(error, header))?;
        for field in &mut fields {
            field.start += header;
            field.end += header;
        }
        Ok(fields)
    }
}

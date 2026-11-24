// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A SEGMENT PROFILE: the description of the header an APPLICATION puts in
//! front of each piece when it splits one message of its own over several
//! samples published on one key, handed over by the caller.
//!
//! # What kind of splitting this is
//!
//! Not zenoh's. A transport `Fragment` chain is the protocol's, and the capture
//! crate joins it under `above_transport`. Some senders split ABOVE zenoh
//! instead: a message larger than they will put in one sample is cut into
//! chunks, and each chunk goes out as an ordinary `Put` on the message's own
//! key, its payload a small header (where the chunk sits in the whole, how
//! large the whole is, which transfer it belongs to, a check value) followed by
//! the chunk. To zenoh these are unrelated samples; only a reader that knows the header sees one
//! message, and only after the pieces are joined does the message's own
//! framing (an end-to-end protection header, a serialized body) start.
//!
//! # Why nothing is hard-coded
//!
//! For the reason [`crate::e2e_profile`] gives: this repository is public, and
//! a header's marks, widths and order are that deployment's. A profile is DATA,
//! declared once in the declaration text, and the workspace's tests run on
//! synthetic profiles deliberately unlike any deployed one.
//!
//! # The description
//!
//! ```text
//! {
//!   "name": "split-a",
//!   "segments": {
//!     "fields": [                          // wire order from byte 0, no gaps
//!       {"name": "mark",   "bytes": 2, "order": "little", "equals": "0x5A5A"},
//!       {"name": "origin", "bytes": 4, "order": "little"},
//!       {"name": "number", "bytes": 2, "order": "little"},
//!       {"name": "check",  "bytes": 4, "order": "little"},
//!       {"name": "size",   "bytes": 4, "order": "little"},
//!       {"name": "at",     "bytes": 4, "order": "little"}
//!     ],
//!     "crc": {"field": "check", "width": 32, "poly": "0x04C11DB7",
//!             "init": "0xFFFFFFFF", "refin": true, "refout": true,
//!             "xorout": "0xFFFFFFFF",
//!             "cover": ["mark", "origin", "number", "size", "at", "@chunk"]},
//!     "stream": ["origin"],
//!     "transfer": "number",
//!     "total": "size",
//!     "offset": "at",
//!     "total_max": 1048576
//!   }
//! }
//! ```
//!
//! * `fields[].bytes` is 1 to 8; `order` is `"big"` (the default) or
//!   `"little"`, and says how the field's bytes make its value. `equals`
//!   (optional) is a value the field MUST hold for a payload to be a piece at
//!   all: the marks a sender writes so a reader can tell its header from any
//!   other payload.
//! * `crc` (optional) is the CRC model of [`crate::crc_table`] and the field it
//!   is written to. `cover` is the feeding order: field names, each fed as its
//!   bytes stand on the wire, and `"@chunk"` for the bytes after the header.
//! * `stream` names the fields that, with the sender and the key, tell one
//!   stream of transfers from another (a value a sender draws when it starts,
//!   say); it may be empty. `transfer` names the field that numbers the
//!   messages of one stream: a piece with a new number ends the stream's
//!   previous transfer, joined or not. `total` is the length of the whole
//!   message in bytes and `offset` where this piece's chunk starts in it.
//! * `total_max` is the largest whole this profile admits, at most
//!   [`MAX_TOTAL_BYTES`]. It is what bounds the memory a reader keeps for one
//!   transfer it is joining, so it is required rather than guessed.
//!
//! # What makes a payload a piece
//!
//! A payload at least as long as the header whose `equals` fields all hold
//! their values. The CRC is then a VERDICT on the piece, not a condition for
//! being one: a damaged piece of a known stream is a fact worth reporting, and
//! dropping it as "not a piece" would turn it into a hole nobody can explain.
//! A profile with no `equals` has nothing else to recognise a piece by, so
//! there the CRC is the condition, and a profile with neither is refused.
//!
//! A profile is read by the workspace's one JSON reader with the bounds and
//! the refusals of [`crate::e2e_profile`]: an unknown key, a repeated key, a
//! field that does not exist, a role given to two fields, a value that does
//! not fit its field, and every other inconsistency is refused with a JSON
//! pointer to the place.
//!
//! # Where it lives
//!
//! A segment profile is read once, when a node is handed it, so the data model
//! and its reader are this crate's, built for size; `wz_app_frame::segment_profile`
//! re-exports them. Reading a payload as a piece, the CRC over a piece and where
//! a piece sits run per sample and are `wz-app-frame`'s functions of a
//! profile; the small accessors they read the profile by are `#[inline]`, so
//! their code is made where they are called.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::Json5Value;

use crate::crc_table::{width_mask, Crc};
use crate::e2e_profile::{
    field_called, optional, read_crc_object, read_field_head, read_json, read_name, CrcFields,
    DocError, Pointer, MAX_FIELDS,
};

/// The largest whole message a segment profile may admit, in bytes.
///
/// A reader joining a transfer holds its whole message until it closes, so
/// this is the ceiling on what one open transfer can make it hold.
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// The key under which a definition's JSON names itself a segment profile.
///
/// What tells `#name={"name":..,"segments":{..}}` from an end-to-end profile
/// definition, which has no such key.
pub const SEGMENTS_KEY: &str = "segments";

/// The `cover` entry that stands for the chunk.
pub const CHUNK: &str = "@chunk";

/// How a field's bytes make its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// The first byte is the most significant.
    Big,
    /// The first byte is the least significant.
    Little,
}

/// One header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The field's name, unique within the profile.
    pub name: String,
    /// Width on the wire, 1 to 8 bytes.
    pub bytes: usize,
    /// Offset from the start of the payload.
    pub offset: usize,
    /// How the bytes make the value.
    pub order: Order,
    /// The value the field must hold for the payload to be a piece.
    pub equals: Option<u64>,
}

impl Field {
    /// The field's value in `header`, which holds at least the whole header: a
    /// copy of its bytes into a run of the value's own bytes in the field's
    /// order, for the reason [`Self::write`] is one.
    #[inline]
    pub fn read(&self, header: &[u8]) -> u64 {
        let width = self.bytes;
        let bytes = &header[self.offset..self.offset + width];
        let mut value = [0u8; 8];
        match self.order {
            Order::Big => {
                value[8 - width..].copy_from_slice(bytes);
                u64::from_be_bytes(value)
            }
            Order::Little => {
                value[..width].copy_from_slice(bytes);
                u64::from_le_bytes(value)
            }
        }
    }

    /// The largest value the field's bytes hold.
    #[inline]
    pub fn max_value(&self) -> u64 {
        width_mask((self.bytes * 8) as u8)
    }

    /// Write `value` into the field's bytes of `header`, which holds at least
    /// the whole header: the inverse of [`Self::read`]. Bits past the field's
    /// width are not written, so a caller that must not lose them checks
    /// [`Self::max_value`] first.
    ///
    /// The field is at most 8 bytes wide, so its bytes are a run of the
    /// value's own bytes in the field's order: a copy, not a per-byte shift
    /// loop, which the compiler vectorises for a length it cannot bound.
    #[inline]
    pub fn write(&self, header: &mut [u8], value: u64) {
        let width = self.bytes;
        let bytes = &mut header[self.offset..self.offset + width];
        match self.order {
            Order::Big => bytes.copy_from_slice(&value.to_be_bytes()[8 - width..]),
            Order::Little => bytes.copy_from_slice(&value.to_le_bytes()[..width]),
        }
    }
}

/// What the CRC is taken over, in feeding order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cover {
    /// The wire bytes of the field at this index of [`SegmentProfile::fields`].
    Field(usize),
    /// The bytes after the header.
    Chunk,
}

/// The CRC of a segment profile.
#[derive(Debug, Clone)]
pub struct CrcSpec {
    /// Index of the field the CRC is written to.
    pub field: usize,
    /// The engine, built from the profile's parameters once, when the profile
    /// is read.
    pub engine: Crc,
    /// What is fed, in this order.
    pub cover: Vec<Cover>,
}

/// A validated segment profile.
#[derive(Debug, Clone)]
pub struct SegmentProfile {
    name: String,
    fields: Vec<Field>,
    header_bytes: usize,
    crc: Option<CrcSpec>,
    stream: Vec<usize>,
    transfer: usize,
    total: usize,
    offset: usize,
    total_max: u64,
}

/// What the CRC said about one piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrcReading {
    /// The value the piece's CRC field holds.
    pub stated: u64,
    /// The value computed over what the profile covers.
    pub computed: u64,
}

impl CrcReading {
    /// Whether the two agree.
    #[inline]
    pub fn matches(&self) -> bool {
        self.stated == self.computed
    }
}

/// One payload read as a piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece<'p> {
    /// The value of every field, in the profile's order.
    pub values: Vec<u64>,
    /// The bytes after the header.
    pub chunk: &'p [u8],
    /// What the CRC said, when the profile has one.
    pub crc: Option<CrcReading>,
}

/// Why a piece cannot be placed in a whole, though it is a piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misplaced {
    /// The whole it claims is empty.
    EmptyTotal,
    /// The whole it claims is larger than the profile admits.
    TotalPastMax,
    /// It carries no chunk.
    EmptyChunk,
    /// Its chunk runs past the end of the whole it claims.
    PastTotal,
}

impl Misplaced {
    /// The word a machine reads for this reason.
    pub const fn word(self) -> &'static str {
        match self {
            Self::EmptyTotal => "empty_total",
            Self::TotalPastMax => "total_past_max",
            Self::EmptyChunk => "empty_chunk",
            Self::PastTotal => "past_total",
        }
    }
}

impl SegmentProfile {
    /// Whether `text` is a segment profile definition rather than another kind
    /// of profile: a JSON object with a [`SEGMENTS_KEY`] member. Text that is
    /// not a JSON object answers `false` and is left to the other reader, whose
    /// refusal then names it.
    pub fn is_segment_profile(text: &str) -> bool {
        matches!(
            read_json(text),
            Ok(Json5Value::Object(entries)) if entries.iter().any(|(k, _)| k == SEGMENTS_KEY)
        )
    }

    /// Read and validate a segment profile from JSON text.
    pub fn parse(text: &str) -> Result<Self, DocError> {
        Self::from_tree(&read_json(text)?)
    }

    /// Read and validate a segment profile from a document already read, as [`Self::parse`]
    /// reads the document of its text: a profile that stands inside a larger document is read
    /// where it stands, with no text written and read again.
    pub fn from_tree(root: &Json5Value) -> Result<Self, DocError> {
        let doc = Pointer::text("");
        let entries = doc.object(root)?;
        doc.check_keys(entries, &["name", SEGMENTS_KEY])?;
        let name = read_name(&doc.key("name"), doc.required(entries, "name")?)?;

        let path = Pointer::text("/segments");
        let body = path.object(doc.required(entries, SEGMENTS_KEY)?)?;
        path.check_keys(
            body,
            &[
                "fields",
                "crc",
                "stream",
                "transfer",
                "total",
                "offset",
                "total_max",
            ],
        )?;
        let fields = read_fields(path.required(body, "fields")?, &path.key("fields"))?;
        let header_bytes = fields.iter().map(|f| f.bytes).sum();

        let crc = match optional(body, "crc") {
            Some(value) => Some(read_crc(value, &path.key("crc"), &fields)?),
            None => None,
        };
        if crc.is_none() && fields.iter().all(|f| f.equals.is_none()) {
            return Err(path.refuse(
                "the profile has no `equals` field and no `crc`: nothing would tell a piece \
                 from any other payload",
            ));
        }

        // The roles. Each names one field, none of them the CRC's, none of them
        // a field with a fixed value, and no field takes two.
        let mut taken: Vec<(usize, &'static str)> = Vec::new();
        if let Some(crc) = &crc {
            taken.push((crc.field, "crc"));
        }
        let mut role = |key: &'static str| -> Result<usize, DocError> {
            let role_at = path.key(key);
            let name = role_at.read_string(path.required(body, key)?)?;
            let index = field_called(&fields.as_slice(), name, &role_at)?;
            claim(&fields, &mut taken, index, key, &role_at)?;
            Ok(index)
        };
        let transfer = role("transfer")?;
        let total = role("total")?;
        let offset = role("offset")?;

        let stream_at = path.key("stream");
        let mut stream = Vec::new();
        if let Some(value) = optional(body, "stream") {
            for (i, item) in stream_at.array(value)?.iter().enumerate() {
                let here = stream_at.index(i);
                let name = here.read_string(item)?;
                let index = field_called(&fields.as_slice(), name, &here)?;
                claim(&fields, &mut taken, index, "stream", &here)?;
                stream.push(index);
            }
        }

        let max_at = path.key("total_max");
        let total_max = max_at.read_uint(path.required(body, "total_max")?)?;
        if total_max == 0 || total_max > MAX_TOTAL_BYTES {
            return Err(max_at.refuse(format!(
                "`total_max` is 1 to {MAX_TOTAL_BYTES} bytes, this one is {total_max}"
            )));
        }

        Ok(Self {
            name,
            fields,
            header_bytes,
            crc,
            stream,
            transfer,
            total,
            offset,
            total_max,
        })
    }

    /// The profile's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The header fields in wire order.
    #[inline]
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// How many bytes the header spans.
    #[inline]
    pub fn header_bytes(&self) -> usize {
        self.header_bytes
    }

    /// The CRC, when the profile has one.
    #[inline]
    pub fn crc(&self) -> Option<&CrcSpec> {
        self.crc.as_ref()
    }

    /// The indices of the fields that tell one stream of transfers from another.
    #[inline]
    pub fn stream(&self) -> &[usize] {
        &self.stream
    }

    /// The index of the field that numbers the transfers of a stream.
    #[inline]
    pub fn transfer(&self) -> usize {
        self.transfer
    }

    /// The index of the field that holds the whole message's length.
    #[inline]
    pub fn total(&self) -> usize {
        self.total
    }

    /// The index of the field that holds where the chunk starts.
    #[inline]
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The largest whole message this profile admits.
    #[inline]
    pub fn total_max(&self) -> u64 {
        self.total_max
    }
}

/// Give `index` the role `role`, refusing a field that already has one or that
/// holds a fixed value (a role names a field whose value varies from piece to
/// piece or from sender to sender).
fn claim(
    fields: &[Field],
    taken: &mut Vec<(usize, &'static str)>,
    index: usize,
    role: &'static str,
    path: &Pointer<'_>,
) -> Result<(), DocError> {
    let name = &fields[index].name;
    if let Some((_, earlier)) = taken.iter().find(|(i, _)| *i == index) {
        return Err(path.refuse(format!(
            "the field `{name}` is already the {earlier} field: a field has one role"
        )));
    }
    if fields[index].equals.is_some() {
        return Err(path.refuse(format!(
            "the field `{name}` holds a fixed value (`equals`), so it cannot be the \
             {role} field"
        )));
    }
    taken.push((index, role));
    Ok(())
}

fn read_fields(value: &Json5Value, path: &Pointer<'_>) -> Result<Vec<Field>, DocError> {
    let items = path.array(value)?;
    if items.is_empty() || items.len() > MAX_FIELDS {
        return Err(path.refuse(format!(
            "a segment profile has 1 to {MAX_FIELDS} fields, this one has {}",
            items.len()
        )));
    }
    let mut fields: Vec<Field> = Vec::with_capacity(items.len());
    let mut offset = 0usize;
    for (i, item) in items.iter().enumerate() {
        let here = path.index(i);
        let entries = here.object(item)?;
        here.check_keys(entries, &["name", "bytes", "order", "equals"])?;

        let named = |name: &str| fields.iter().any(|f| f.name == name);
        let (name, bytes) = read_field_head(&here, entries, &named)?;
        let order = match optional(entries, "order") {
            None => Order::Big,
            Some(v) => {
                let order_at = here.key("order");
                match order_at.read_string(v)? {
                    "big" => Order::Big,
                    "little" => Order::Little,
                    other => {
                        return Err(order_at.refuse(format!(
                            "`{other}` is not a byte order: write \"big\" or \"little\""
                        )))
                    }
                }
            }
        };
        let equals = match optional(entries, "equals") {
            None => None,
            Some(v) => {
                let equals_at = here.key("equals");
                let wanted = equals_at.read_uint(v)?;
                if wanted & !width_mask((bytes * 8) as u8) != 0 {
                    return Err(equals_at.refuse(format!(
                        "{wanted:#x} does not fit the field's {bytes} bytes"
                    )));
                }
                Some(wanted)
            }
        };
        fields.push(Field {
            name,
            bytes,
            offset,
            order,
            equals,
        });
        offset += bytes;
    }
    Ok(fields)
}

impl CrcFields for &[Field] {
    fn index_of(&self, name: &str) -> Option<usize> {
        self.iter().position(|f| f.name == name)
    }

    fn bytes_of(&self, index: usize) -> usize {
        self[index].bytes
    }

    fn may_hold_crc(&self, index: usize, path: &Pointer<'_>) -> Result<(), DocError> {
        if self[index].equals.is_some() {
            return Err(path.refuse(format!(
                "the crc field `{}` holds a fixed value (`equals`): it holds the result",
                self[index].name
            )));
        }
        Ok(())
    }

    fn body(&self) -> &'static str {
        CHUNK
    }
}

fn read_crc(value: &Json5Value, path: &Pointer<'_>, fields: &[Field]) -> Result<CrcSpec, DocError> {
    let crc = read_crc_object(value, path, &fields)?;
    Ok(CrcSpec {
        field: crc.field,
        engine: crc.engine,
        cover: crc
            .cover
            .into_iter()
            .map(|c| c.map_or(Cover::Chunk, Cover::Field))
            .collect(),
    })
}

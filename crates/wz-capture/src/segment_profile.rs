// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A SEGMENT PROFILE: the description of the header an APPLICATION puts in
//! front of each piece when it splits one message of its own over several
//! samples published on one key, handed over by the caller.
//!
//! # What kind of splitting this is
//!
//! Not zenoh's. A transport `Fragment` chain is the protocol's, and this crate
//! joins it under `above_transport`. Some senders split ABOVE zenoh instead: a
//! message larger than they will put in one sample is cut into chunks, and each
//! chunk goes out as an ordinary `Put` on the message's own key, its payload a
//! small header (where the chunk sits in the whole, how large the whole is,
//! which transfer it belongs to, a check value) followed by the chunk. To zenoh
//! these are unrelated samples; only a reader that knows the header sees one
//! message, and only after the pieces are joined does the message's own
//! framing (an end-to-end protection header, a serialized body) start.
//!
//! # Why nothing is hard-coded
//!
//! For the reason [`crate::e2e_profile`] gives: this repository is public, and
//! a header's marks, widths and order are that deployment's. A profile is DATA,
//! declared once in the declaration text, and this crate's tests run on
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
//! * `crc` (optional) is the CRC model of [`crate::e2e_crc`] and the field it
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

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::Json5Value;

use crate::e2e_crc::{width_mask, Crc};
use crate::e2e_profile::{
    array, at, check_keys, child, object, optional, read_crc_engine, read_json, read_name,
    read_string, read_uint, required, DocError, MAX_FIELDS,
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
    /// The field's value in `header`, which holds at least the whole header.
    pub fn read(&self, header: &[u8]) -> u64 {
        let bytes = &header[self.offset..self.offset + self.bytes];
        match self.order {
            Order::Big => bytes.iter().fold(0u64, |v, b| (v << 8) | u64::from(*b)),
            Order::Little => bytes
                .iter()
                .rev()
                .fold(0u64, |v, b| (v << 8) | u64::from(*b)),
        }
    }

    /// The largest value the field's bytes hold.
    pub fn max_value(&self) -> u64 {
        width_mask((self.bytes * 8) as u8)
    }

    /// Write `value` into the field's bytes of `header`, which holds at least
    /// the whole header: the inverse of [`Self::read`]. Bits past the field's
    /// width are not written, so a caller that must not lose them checks
    /// [`Self::max_value`] first.
    pub fn write(&self, header: &mut [u8], value: u64) {
        let width = self.bytes;
        let bytes = &mut header[self.offset..self.offset + width];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let shift = match self.order {
                Order::Big => 8 * (width - 1 - i),
                Order::Little => 8 * i,
            };
            *byte = (value >> shift) as u8;
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
    /// The engine, built from the profile's parameters.
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
        let root = read_json(text)?;
        let entries = object(&root, "")?;
        check_keys(entries, &["name", SEGMENTS_KEY], "")?;
        let name = read_name(required(entries, "name", "")?, "/name")?;

        let path = "/segments";
        let body = object(required(entries, SEGMENTS_KEY, "")?, path)?;
        check_keys(
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
            path,
        )?;
        let fields = read_fields(required(body, "fields", path)?, &child(path, "fields"))?;
        let header_bytes = fields.iter().map(|f| f.bytes).sum();

        let crc = match optional(body, "crc") {
            Some(value) => Some(read_crc(value, &child(path, "crc"), &fields)?),
            None => None,
        };
        if crc.is_none() && fields.iter().all(|f| f.equals.is_none()) {
            return Err(DocError::invalid(
                path,
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
            let role_path = child(path, key);
            let name = read_string(required(body, key, path)?, &role_path)?;
            let index = field_named(&fields, name, &role_path)?;
            claim(&fields, &mut taken, index, key, &role_path)?;
            Ok(index)
        };
        let transfer = role("transfer")?;
        let total = role("total")?;
        let offset = role("offset")?;

        let stream_path = child(path, "stream");
        let mut stream = Vec::new();
        if let Some(value) = optional(body, "stream") {
            for (i, item) in array(value, &stream_path)?.iter().enumerate() {
                let here = at(&stream_path, i);
                let name = read_string(item, &here)?;
                let index = field_named(&fields, name, &here)?;
                claim(&fields, &mut taken, index, "stream", &here)?;
                stream.push(index);
            }
        }

        let max_path = child(path, "total_max");
        let total_max = read_uint(required(body, "total_max", path)?, &max_path)?;
        if total_max == 0 || total_max > MAX_TOTAL_BYTES {
            return Err(DocError::invalid(
                max_path,
                format!("`total_max` is 1 to {MAX_TOTAL_BYTES} bytes, this one is {total_max}"),
            ));
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
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// How many bytes the header spans.
    pub fn header_bytes(&self) -> usize {
        self.header_bytes
    }

    /// The CRC, when the profile has one.
    pub fn crc(&self) -> Option<&CrcSpec> {
        self.crc.as_ref()
    }

    /// The indices of the fields that tell one stream of transfers from another.
    pub fn stream(&self) -> &[usize] {
        &self.stream
    }

    /// The index of the field that numbers the transfers of a stream.
    pub fn transfer(&self) -> usize {
        self.transfer
    }

    /// The index of the field that holds the whole message's length.
    pub fn total(&self) -> usize {
        self.total
    }

    /// The index of the field that holds where the chunk starts.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The largest whole message this profile admits.
    pub fn total_max(&self) -> u64 {
        self.total_max
    }

    /// Read `payload` as a piece, or `None` when it is not one.
    ///
    /// See the module's account of what makes a payload a piece: the `equals`
    /// fields, and the CRC only when there are none.
    pub fn recognise<'p>(&self, payload: &'p [u8]) -> Option<Piece<'p>> {
        let header = payload.get(..self.header_bytes)?;
        let mut values = Vec::with_capacity(self.fields.len());
        for field in &self.fields {
            let value = field.read(header);
            if field.equals.is_some_and(|wanted| wanted != value) {
                return None;
            }
            values.push(value);
        }
        let chunk = &payload[self.header_bytes..];
        let crc = self.crc.as_ref().map(|spec| CrcReading {
            stated: values[spec.field],
            computed: self.crc_over(spec, header, chunk),
        });
        let fixed = self.fields.iter().any(|f| f.equals.is_some());
        if !fixed && !crc.is_some_and(|c| c.matches()) {
            return None;
        }
        Some(Piece { values, chunk, crc })
    }

    /// The CRC `spec` computes over `header` and `chunk`, fed in the order its
    /// `cover` lists. The one place that order is applied: a reader checks a
    /// piece with it and [`crate::segment_sender`] writes a piece's CRC with it.
    pub(crate) fn crc_over(&self, spec: &CrcSpec, header: &[u8], chunk: &[u8]) -> u64 {
        let mut digest = spec.engine.start();
        for cover in &spec.cover {
            match cover {
                Cover::Field(i) => {
                    let f = &self.fields[*i];
                    digest.update(&header[f.offset..f.offset + f.bytes]);
                }
                Cover::Chunk => digest.update(chunk),
            }
        }
        digest.finish()
    }

    /// Where `piece` sits in its whole: `(total, offset)`, or why it cannot sit
    /// anywhere.
    pub fn place(&self, piece: &Piece<'_>) -> Result<(u64, u64), Misplaced> {
        let total = piece.values[self.total];
        let offset = piece.values[self.offset];
        if total == 0 {
            return Err(Misplaced::EmptyTotal);
        }
        if total > self.total_max {
            return Err(Misplaced::TotalPastMax);
        }
        if piece.chunk.is_empty() {
            return Err(Misplaced::EmptyChunk);
        }
        let end = offset.checked_add(piece.chunk.len() as u64);
        if end.is_none_or(|end| end > total) {
            return Err(Misplaced::PastTotal);
        }
        Ok((total, offset))
    }
}

fn field_named(fields: &[Field], name: &str, path: &str) -> Result<usize, DocError> {
    fields
        .iter()
        .position(|f| f.name == name)
        .ok_or_else(|| DocError::invalid(path, format!("no field is called `{name}`")))
}

/// Give `index` the role `role`, refusing a field that already has one or that
/// holds a fixed value (a role names a field whose value varies from piece to
/// piece or from sender to sender).
fn claim(
    fields: &[Field],
    taken: &mut Vec<(usize, &'static str)>,
    index: usize,
    role: &'static str,
    path: &str,
) -> Result<(), DocError> {
    let name = &fields[index].name;
    if let Some((_, earlier)) = taken.iter().find(|(i, _)| *i == index) {
        return Err(DocError::invalid(
            path,
            format!("the field `{name}` is already the {earlier} field: a field has one role"),
        ));
    }
    if fields[index].equals.is_some() {
        return Err(DocError::invalid(
            path,
            format!(
                "the field `{name}` holds a fixed value (`equals`), so it cannot be the \
                 {role} field"
            ),
        ));
    }
    taken.push((index, role));
    Ok(())
}

fn read_fields(value: &Json5Value, path: &str) -> Result<Vec<Field>, DocError> {
    let items = array(value, path)?;
    if items.is_empty() || items.len() > MAX_FIELDS {
        return Err(DocError::invalid(
            path,
            format!(
                "a segment profile has 1 to {MAX_FIELDS} fields, this one has {}",
                items.len()
            ),
        ));
    }
    let mut fields: Vec<Field> = Vec::with_capacity(items.len());
    let mut offset = 0usize;
    for (i, item) in items.iter().enumerate() {
        let here = at(path, i);
        let entries = object(item, &here)?;
        check_keys(entries, &["name", "bytes", "order", "equals"], &here)?;

        let name = read_name(required(entries, "name", &here)?, &child(&here, "name"))?;
        if fields.iter().any(|f| f.name == name) {
            return Err(DocError::invalid(
                child(&here, "name"),
                format!("two fields are called `{name}`"),
            ));
        }
        let bytes_path = child(&here, "bytes");
        let bytes = read_uint(required(entries, "bytes", &here)?, &bytes_path)?;
        if !(1..=8).contains(&bytes) {
            return Err(DocError::invalid(
                bytes_path,
                format!("a field is 1 to 8 bytes wide, this one is {bytes}"),
            ));
        }
        let bytes = bytes as usize;
        let order = match optional(entries, "order") {
            None => Order::Big,
            Some(v) => {
                let order_path = child(&here, "order");
                match read_string(v, &order_path)? {
                    "big" => Order::Big,
                    "little" => Order::Little,
                    other => {
                        return Err(DocError::invalid(
                            order_path,
                            format!("`{other}` is not a byte order: write \"big\" or \"little\""),
                        ))
                    }
                }
            }
        };
        let equals = match optional(entries, "equals") {
            None => None,
            Some(v) => {
                let equals_path = child(&here, "equals");
                let wanted = read_uint(v, &equals_path)?;
                if wanted & !width_mask((bytes * 8) as u8) != 0 {
                    return Err(DocError::invalid(
                        equals_path,
                        format!("{wanted:#x} does not fit the field's {bytes} bytes"),
                    ));
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

fn read_crc(value: &Json5Value, path: &str, fields: &[Field]) -> Result<CrcSpec, DocError> {
    let entries = object(value, path)?;
    check_keys(
        entries,
        &[
            "field", "width", "poly", "init", "refin", "refout", "xorout", "cover",
        ],
        path,
    )?;
    let field_path = child(path, "field");
    let field_name = read_string(required(entries, "field", path)?, &field_path)?;
    let field = field_named(fields, field_name, &field_path)?;
    if fields[field].equals.is_some() {
        return Err(DocError::invalid(
            field_path,
            format!(
                "the crc field `{field_name}` holds a fixed value (`equals`): it holds the \
                 result"
            ),
        ));
    }
    let engine = read_crc_engine(entries, path)?;
    let width = engine.params().width;
    if usize::from(width) > fields[field].bytes * 8 {
        return Err(DocError::invalid(
            field_path,
            format!(
                "the crc field `{field_name}` is {} bits wide, narrower than the {width}-bit CRC",
                fields[field].bytes * 8
            ),
        ));
    }

    let cover_path = child(path, "cover");
    let items = array(required(entries, "cover", path)?, &cover_path)?;
    if items.is_empty() {
        return Err(DocError::invalid(
            cover_path,
            "the cover list is empty: the CRC would take no input",
        ));
    }
    let mut cover: Vec<Cover> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let here = at(&cover_path, i);
        let name = read_string(item, &here)?;
        let entry = if name == CHUNK {
            Cover::Chunk
        } else {
            Cover::Field(field_named(fields, name, &here)?)
        };
        if entry == Cover::Field(field) {
            return Err(DocError::invalid(
                here,
                format!("the crc field `{name}` is never covered: it holds the result"),
            ));
        }
        if cover.contains(&entry) {
            return Err(DocError::invalid(
                here,
                format!("`{name}` is covered twice"),
            ));
        }
        cover.push(entry);
    }
    Ok(CrcSpec {
        field,
        engine,
        cover,
    })
}

/// A SYNTHETIC segment profile and a builder of its pieces, for this crate's
/// tests and for the fixtures other crates' tests build captures from.
///
/// Deliberately unlike any deployed header: a big-endian mark, a little-endian
/// stream value, a one-byte transfer number, three-byte little-endian size and
/// offset, and a big-endian CRC-16 over everything but itself, chunk last.
#[cfg(any(test, feature = "fixtures"))]
pub mod synthetic {
    use alloc::vec::Vec;

    use crate::e2e_crc::{Crc, CrcParams};

    /// The profile's name.
    pub const NAME: &str = "demo-split";

    /// The profile description, on one line as a declaration needs it.
    pub const PROFILE: &str = concat!(
        r#"{"name":"demo-split","segments":{"fields":["#,
        r#"{"name":"mark","bytes":2,"equals":"0xA5C3"},"#,
        r#"{"name":"origin","bytes":2,"order":"little"},"#,
        r#"{"name":"number","bytes":1},"#,
        r#"{"name":"size","bytes":3,"order":"little"},"#,
        r#"{"name":"at","bytes":3,"order":"little"},"#,
        r#"{"name":"check","bytes":2}],"#,
        r#""crc":{"field":"check","width":16,"poly":"0x8005","init":"0x0000","#,
        r#""refin":true,"refout":true,"xorout":"0x0000","#,
        r#""cover":["mark","origin","number","size","at","@chunk"]},"#,
        r#""stream":["origin"],"transfer":"number","total":"size","offset":"at","#,
        r#""total_max":4096}}"#
    );

    /// How many bytes the header spans.
    pub const HEADER_BYTES: usize = 13;

    /// One piece: `chunk` at `at` of a whole of `size` bytes, transfer
    /// `number` of stream `origin`. Its CRC is computed from the model's
    /// parameters directly, not by the reader under test.
    pub fn piece(origin: u16, number: u8, size: u32, at: u32, chunk: &[u8]) -> Vec<u8> {
        let mut covered = Vec::new();
        covered.extend_from_slice(&0xA5C3u16.to_be_bytes());
        covered.extend_from_slice(&origin.to_le_bytes());
        covered.push(number);
        covered.extend_from_slice(&size.to_le_bytes()[..3]);
        covered.extend_from_slice(&at.to_le_bytes()[..3]);
        let crc = Crc::new(CrcParams {
            width: 16,
            poly: 0x8005,
            init: 0,
            refin: true,
            refout: true,
            xorout: 0,
        })
        .expect("a valid CRC model");
        let mut digest = crc.start();
        digest.update(&covered);
        digest.update(chunk);
        let check = digest.finish() as u16;
        let mut out = covered;
        out.extend_from_slice(&check.to_be_bytes());
        out.extend_from_slice(chunk);
        out
    }
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y579 (G3 + G6-serde) — the LEAF-SCALAR field walker: a decode that
//! reports, for every scalar on the wire, the byte span it came from.
//!
//! ## What was missing
//!
//! Sub-codec granularity is already free. `SceCursor::remaining()` is public,
//! so calling `MsgPut::decode` by hand and differencing the cursor yields that
//! message's exact span — which is how the R311y577 measurement derived
//! `header [0..1) keyexpr [1..9) body [9..16)`. What no amount of cursor
//! differencing yields is a span for a scalar INSIDE a leaf codec: the VLE
//! `sn`, the length prefix in front of a payload, the `zid` bytes. The
//! generated decode reads them and returns the values; the offsets die inside
//! the function.
//!
//! A dissector needs those offsets. "Byte 14 is where this key expression's
//! length prefix says 9" is the difference between a decode and a dissection.
//!
//! ## Why a walker rather than a span-emitting codegen template
//!
//! The other route is upstream: teach the SCE Rust codec template to emit a
//! parallel `decode_spans`. That is the better long-run answer and it is not
//! available here — `vendor/sce` is read-only from wz sessions (`CLAUDE.md`,
//! External references), so a template change cannot be made, tested, or
//! pinned from this workspace.
//!
//! What makes the walker safe is not care, it is the DIFFERENTIAL GATE. A
//! hand-written mirror of a generated decode is exactly the kind of code that
//! rots the moment the generator changes. So no walker is trusted on its own:
//! `tests` below drives every walker and the generated codec over the same
//! bytes and rejects any disagreement in (a) the values, (b) the total byte
//! count consumed, and (c) whether the leaf spans TILE the consumed range with
//! no gap and no overlap. A regenerated codec that shifts a field reds the
//! gate rather than silently producing spans that point at the wrong bytes.
//!
//! ## G6-serde
//!
//! [`Field`] is wz's own type, so unlike the codegen'd `*Owned` mirrors (whose
//! derive set is SCE's and whose tree is read-only here — see
//! [`crate::inbound::InboundFrame`]'s note) it can carry whatever derives a
//! consumer needs. It derives `Debug` + `Clone` + `PartialEq` always,
//! `serde::Serialize` + `Deserialize` under the `dissect-serde` feature, and
//! renders to JSON via [`to_json`] with NO serde dependency at all — a
//! `no_std` + `alloc` build that cannot take a serde dep still gets a
//! machine-readable dissection out.
//!
//! This is the view-model layer G6 asked for, and it is where serde CAN land:
//! the wz side of the boundary. It does not put serde on the codec structs and
//! does not claim to.
//!
//! ## Coordinate space
//!
//! Every [`Span`] in one dissection is in ONE coordinate space, chosen by the
//! caller via the `base` passed to [`SpanCursor::with_base`] /
//! [`dissect_batch`]. Pass the byte offset of this message within the capture
//! and every span — including the ones nested inside a batch record inside a
//! frame — reads as a capture offset directly. Pass `0` and they are
//! message-relative. The walker never mixes the two.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use sce_forge_runtime::codec::{CodecError, SceCursor};

/// A half-open byte range `[start, end)` in the dissection's coordinate space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "dissect-serde",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Span {
    /// First byte of the field.
    pub start: usize,
    /// One past the last byte of the field.
    pub end: usize,
}

impl Span {
    /// Width in bytes. Zero for a field that occupies no wire bytes (an empty
    /// ext body, a zero-length payload).
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// `true` when the field occupies no wire bytes. Present because clippy
    /// asks for it next to `len`, and because "the field is there but empty"
    /// is a real wire state a consumer renders differently from absent.
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// The value a walked field carries, and — as importantly — whether its span
/// is its OWN bytes or an alias of another field's.
///
/// The distinction is load-bearing: [`Bits`](FieldValue::Bits) and
/// [`Flag`](FieldValue::Flag) are decoded from a carrier byte some other field
/// already claims, so counting them in the tiling would double-count that byte.
/// [`is_alias`](FieldValue::is_alias) is the single predicate that separates
/// the two, and the tiling gate is written against it rather than against a
/// list of variant names that a new variant could silently fall outside of.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "dissect-serde",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum FieldValue {
    /// A multi-bit subfield of a carrier byte (a MID, a 2-bit encoding
    /// selector). ALIASES the carrier's span.
    Bits(u64),
    /// A single bit of a carrier byte. ALIASES the carrier's span.
    Flag(bool),
    /// A decoded unsigned scalar. Carried rather than left to the span
    /// because for a VLE field the span's raw bytes are NOT the value — that
    /// gap is the whole reason this module exists.
    Uint(u64),
    /// Raw bytes, carried owned so a dissection outlives the buffer it was
    /// read from (the same reason the inbound path owns its payloads).
    Bytes(Vec<u8>),
    /// UTF-8 text the decode validated.
    Text(String),
    /// A sub-structure walked into its own fields. The parent's span covers
    /// exactly the children's.
    Nested(Vec<Field>),
    /// A sub-structure whose SPAN is known but whose interior this build does
    /// not walk. An honest terminal: the bytes are accounted for and the
    /// consumer is told they were not broken down, which is different from
    /// claiming there was nothing inside.
    Opaque,
}

impl FieldValue {
    /// `true` when this value was decoded from bytes another field already
    /// claims, so its span must not be counted toward the tiling.
    pub fn is_alias(&self) -> bool {
        matches!(self, FieldValue::Bits(_) | FieldValue::Flag(_))
    }
}

/// One named field of a dissected message, with the bytes it came from.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "dissect-serde",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Field {
    /// Wire name of the field, matching the generated codec's struct field
    /// where one exists so a reader can move between the two without a
    /// translation table.
    ///
    /// A `Cow` rather than a bare `&'static str` for ONE reason: `Deserialize`
    /// cannot be derived for a `&'static str` (there is no borrow from `'de`
    /// that lives forever), and a view model that only serializes OUT is half
    /// of what G6 asked for. Every walker still hands in a `&'static str`, so
    /// the producing path allocates nothing; only a name read back off the
    /// wire becomes owned.
    pub name: Cow<'static, str>,
    /// The bytes this field was decoded from.
    pub span: Span,
    /// What was decoded.
    pub value: FieldValue,
}

impl Field {
    /// Collect the spans of every NON-alias terminal under this field, in
    /// wire order. A [`Nested`](FieldValue::Nested) contributes its children
    /// rather than itself, so the result is the flat tiling of the field's
    /// bytes; the tiling gate compares it against the range the codec
    /// consumed.
    pub fn leaf_spans(&self, out: &mut Vec<Span>) {
        match &self.value {
            FieldValue::Nested(children) => {
                for child in children {
                    child.leaf_spans(out);
                }
            }
            v if v.is_alias() => {}
            _ => out.push(self.span),
        }
    }

    /// Depth-first search for the first field with this name, this field
    /// included. Consumers reach for one field ("what is the sn?") far more
    /// often than they walk the whole tree.
    pub fn find(&self, name: &str) -> Option<&Field> {
        if self.name == name {
            return Some(self);
        }
        if let FieldValue::Nested(children) = &self.value {
            for child in children {
                if let Some(hit) = child.find(name) {
                    return Some(hit);
                }
            }
        }
        None
    }
}

/// Wrap `fields` as one named parent spanning `[start, end)`.
fn group(name: &'static str, start: usize, end: usize, fields: Vec<Field>) -> Field {
    Field {
        name: name.into(),
        span: Span { start, end },
        value: FieldValue::Nested(fields),
    }
}

/// A bit-derived field aliasing `carrier`'s span.
fn flag(name: &'static str, carrier: Span, set: bool) -> Field {
    Field {
        name: name.into(),
        span: carrier,
        value: FieldValue::Flag(set),
    }
}

/// A multi-bit subfield aliasing `carrier`'s span.
fn bits(name: &'static str, carrier: Span, value: u64) -> Field {
    Field {
        name: name.into(),
        span: carrier,
        value: FieldValue::Bits(value),
    }
}

/// A cursor that reads exactly what the generated codecs read, and records
/// where each read came from.
///
/// It OWNS an [`SceCursor`] rather than re-implementing the primitives, so
/// the VLE reader here is the same VLE reader the codec uses — a walker
/// cannot disagree with the codec about how many bytes a VLE occupies,
/// because it is not a second implementation.
pub struct SpanCursor<'a> {
    cur: SceCursor<'a>,
    len: usize,
    base: usize,
}

impl<'a> SpanCursor<'a> {
    /// Wrap `buf` with spans reported relative to its first byte.
    pub fn new(buf: &'a [u8]) -> Self {
        Self::with_base(buf, 0)
    }

    /// Wrap `buf` with spans reported relative to `base` — the offset of
    /// `buf[0]` in whatever coordinate space the caller wants the dissection
    /// expressed in (a capture offset, a stream offset, a frame offset).
    pub fn with_base(buf: &'a [u8], base: usize) -> Self {
        Self {
            cur: SceCursor::new(buf),
            len: buf.len(),
            base,
        }
    }

    /// Current absolute offset. Derived from the cursor's own `remaining()`
    /// on every call rather than tracked in a counter, so a sub-codec decode
    /// that advances the cursor behind this type's back cannot desync it.
    pub fn offset(&self) -> usize {
        self.base + (self.len - self.cur.remaining())
    }

    /// Bytes left to read.
    pub fn remaining(&self) -> usize {
        self.cur.remaining()
    }

    /// The next byte without consuming it — the peek-byte variant dispatch
    /// every envelope codec performs before decoding its body.
    pub fn peek_u8(&self) -> Result<u8, CodecError> {
        Ok(self.cur.peek_slice(1)?[0])
    }

    /// Read one byte.
    pub fn u8(&mut self, name: &'static str) -> Result<(u8, Field), CodecError> {
        let start = self.offset();
        let v = self.cur.peek_slice(1)?[0];
        self.cur.advance(1)?;
        Ok((
            v,
            Field {
                name: name.into(),
                span: Span {
                    start,
                    end: self.offset(),
                },
                value: FieldValue::Uint(v as u64),
            },
        ))
    }

    /// Read a little-endian `u16` — the `batch_size` shape shared by INIT and
    /// JOIN.
    pub fn u16_le(&mut self, name: &'static str) -> Result<(u16, Field), CodecError> {
        let start = self.offset();
        let raw = self.cur.peek_slice(2)?;
        let v = raw[0] as u16 | ((raw[1] as u16) << 8);
        self.cur.advance(2)?;
        Ok((
            v,
            Field {
                name: name.into(),
                span: Span {
                    start,
                    end: self.offset(),
                },
                value: FieldValue::Uint(v as u64),
            },
        ))
    }

    /// Read a base-128 VLE `u64`.
    pub fn vle_u64(&mut self, name: &'static str) -> Result<(u64, Field), CodecError> {
        let start = self.offset();
        let v = self.cur.read_vle_u64()?;
        Ok((
            v,
            Field {
                name: name.into(),
                span: Span {
                    start,
                    end: self.offset(),
                },
                value: FieldValue::Uint(v),
            },
        ))
    }

    /// Read a base-128 VLE `u32` — the `Encoding.packed_id` width.
    pub fn vle_u32(&mut self, name: &'static str) -> Result<(u32, Field), CodecError> {
        let start = self.offset();
        let v = self.cur.read_vle_u32()?;
        Ok((
            v,
            Field {
                name: name.into(),
                span: Span {
                    start,
                    end: self.offset(),
                },
                value: FieldValue::Uint(v as u64),
            },
        ))
    }

    /// Read `n` raw bytes.
    pub fn bytes(&mut self, name: &'static str, n: usize) -> Result<Field, CodecError> {
        let start = self.offset();
        let raw = self.cur.peek_slice(n)?.to_vec();
        self.cur.advance(n)?;
        Ok(Field {
            name: name.into(),
            span: Span {
                start,
                end: self.offset(),
            },
            value: FieldValue::Bytes(raw),
        })
    }

    /// Read every remaining byte.
    pub fn tail(&mut self, name: &'static str) -> Result<Field, CodecError> {
        self.bytes(name, self.cur.remaining())
    }

    /// Read `n` bytes as UTF-8, rejecting invalid sequences exactly as the
    /// generated string decode does.
    pub fn text(&mut self, name: &'static str, n: usize) -> Result<Field, CodecError> {
        let start = self.offset();
        let raw = self.cur.peek_slice(n)?;
        let s = core::str::from_utf8(raw).map_err(|_| CodecError::InvalidUtf8)?;
        let owned = String::from(s);
        self.cur.advance(n)?;
        Ok(Field {
            name: name.into(),
            span: Span {
                start,
                end: self.offset(),
            },
            value: FieldValue::Text(owned),
        })
    }

    /// Run `f` and wrap whatever it walked as one named parent field.
    pub fn nested<F>(&mut self, name: &'static str, f: F) -> Result<Field, CodecError>
    where
        F: FnOnce(&mut Self) -> Result<Vec<Field>, CodecError>,
    {
        let start = self.offset();
        let children = f(self)?;
        Ok(group(name, start, self.offset(), children))
    }

    /// Delegate to a generated codec's own `decode` and record ONLY the span
    /// it consumed.
    ///
    /// The escape hatch that keeps this module honest about its coverage: a
    /// structure nobody has written a walker for is still accounted for byte
    /// for byte, and is reported as [`Opaque`](FieldValue::Opaque) rather than
    /// as a leaf that was fully understood.
    pub fn opaque<T, F>(&mut self, name: &'static str, f: F) -> Result<(T, Field), CodecError>
    where
        F: FnOnce(&mut SceCursor<'a>) -> Result<T, CodecError>,
    {
        let start = self.offset();
        let v = f(&mut self.cur)?;
        Ok((
            v,
            Field {
                name: name.into(),
                span: Span {
                    start,
                    end: self.offset(),
                },
                value: FieldValue::Opaque,
            },
        ))
    }
}

// ── Shared leaf walkers ──────────────────────────────────────────────

/// `ExtEntry` — a TLV entry: one header byte (id in bits 0..4, a 2-bit body
/// encoding in bits 5..6, the Z continuation in bit 7) then the body its
/// encoding selects.
pub fn walk_ext_entry(c: &mut SpanCursor<'_>) -> Result<(bool, Field), CodecError> {
    let start = c.offset();
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let z = (header & 0x80) != 0;
    let enc = (header >> 5) & 0x03;
    let mut fields = alloc::vec![
        header_field,
        bits("ext_id", carrier, (header & 0x1F) as u64),
        bits("encoding", carrier, enc as u64),
        flag("z", carrier, z),
    ];
    match enc {
        // ExtUnit — no body bytes at all.
        0 => {}
        // ExtZint — a single VLE.
        1 => {
            let (_, f) = c.vle_u64("value")?;
            fields.push(f);
        }
        // ExtZbuf — a VLE length then that many bytes. Anything else falls
        // through to the codec's own default arm, which is ExtUnit.
        2 => {
            let (n, f) = c.vle_u64("value_len")?;
            fields.push(f);
            fields.push(c.bytes("value", n as usize)?);
        }
        _ => {}
    }
    Ok((z, group("ext", start, c.offset(), fields)))
}

/// The Z-terminated ext chain: entries until one clears the Z bit, the cursor
/// empties, or `max` entries have been read.
///
/// R311y589 — this walker is now an EXACT mirror of the generated decode
/// again, and the two-branch tail below is the whole reason it had to be
/// rewritten rather than merely un-patched.
///
/// R311y582 (A1) recorded a divergence here: the generator dropped the
/// post-loop overflow check on the `entry-flag` path even though the SCXML
/// declared `on-overflow="reject"`, so the codec left the loop on the `max`
/// bound with the last entry still saying "continue" and read the NEXT FIELD
/// out of chain bytes. wz refused instead, and carried compensating checks at
/// its own participant seams. SCE landed the fix (`ec3b032984`), so both are
/// gone — but the fix also DISTINGUISHES two reasons the loop can stop with
/// the flag still set, and a walker that collapsed them would now disagree
/// with the codec on the second:
///
/// | loop stopped with the flag set | cursor    | reported as        |
/// |--------------------------------|-----------|--------------------|
/// | the depth cap refused an entry | non-empty | `TlvChainOverflow` |
/// | the peer's frame ended mid-chain | empty   | `NeedMoreBytes`    |
///
/// The second row is a failure R311y582's report did not name and SCE found
/// while measuring: for `MsgPut` it is masked (`payload_len` then hits EOF),
/// but a codec whose chain is its LAST field — `Interest` is exactly that
/// shape — reported a truncated chain as a finished one. It is signalled
/// independently of `on-overflow`, because the cap was never reached and no
/// overflow policy is in play; the frame is simply short.
///
/// Both rows are pinned by `a_chain_past_the_cap_is_refused_rather_than_misread`
/// against the codec and the walker together, so the mirror claim is a
/// MEASURED one rather than an inspection of two loops that look alike.
fn walk_ext_chain_z(c: &mut SpanCursor<'_>, max: usize) -> Result<Vec<Field>, CodecError> {
    let mut out = Vec::new();
    let mut more = false;
    for _ in 0..max {
        if c.remaining() == 0 {
            break;
        }
        let (z, f) = walk_ext_entry(c)?;
        out.push(f);
        more = z;
        if !z {
            break;
        }
    }
    if more && c.remaining() == 0 {
        return Err(CodecError::NeedMoreBytes);
    }
    if more {
        return Err(CodecError::TlvChainOverflow);
    }
    Ok(out)
}

/// The fill-to-end ext chain: `Query` reads entries until its cursor is empty
/// and rejects a chain longer than `max`, ignoring the Z bit entirely
/// (`out/wz-codecs/query.rs`). Mirrored exactly, overflow error included.
fn walk_ext_chain_fill(c: &mut SpanCursor<'_>, max: usize) -> Result<Vec<Field>, CodecError> {
    let mut out = Vec::new();
    for _ in 0..max {
        if c.remaining() == 0 {
            break;
        }
        let (_, f) = walk_ext_entry(c)?;
        out.push(f);
    }
    if c.remaining() > 0 {
        return Err(CodecError::TlvChainOverflow);
    }
    Ok(out)
}

/// `Timestamp` — an NTP64 VLE plus a length-prefixed ZID.
pub fn walk_timestamp(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (_, time) = c.vle_u64("time")?;
    let (n, zid_len) = c.vle_u64("zid_len")?;
    let zid = c.bytes("zid", n as usize)?;
    Ok(alloc::vec![time, zid_len, zid])
}

/// `Encoding` — a VLE `packed_id` whose bit 0 gates a length-prefixed schema
/// string.
pub fn walk_encoding(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (packed, packed_field) = c.vle_u32("packed_id")?;
    let carrier = packed_field.span;
    let mut out = alloc::vec![
        packed_field,
        flag("has_schema", carrier, (packed & 0x1) != 0),
        bits("id", carrier, (packed >> 1) as u64),
    ];
    if (packed & 0x1) != 0 {
        let (n, len) = c.vle_u64("schema_len")?;
        out.push(len);
        out.push(c.text("schema", n as usize)?);
    }
    Ok(out)
}

/// `Wireexpr` — a VLE mapping id, plus a length-prefixed suffix when the
/// parent's N flag is set. The local and nonlocal variants have identical
/// layouts and differ only in which mapping table the id resolves against,
/// so `tag` is recorded as a field rather than duplicated as a second walker.
pub fn walk_wireexpr(c: &mut SpanCursor<'_>, n: u8, tag: u8) -> Result<Vec<Field>, CodecError> {
    let (_, id) = c.vle_u64("id")?;
    let mapping = Field {
        name: "mapping".into(),
        span: id.span,
        value: FieldValue::Bits(tag as u64),
    };
    let mut out = alloc::vec![id, mapping];
    if (n & 0x01) != 0 {
        let (len, len_field) = c.vle_u64("suffix_len")?;
        out.push(len_field);
        out.push(c.text("suffix", len as usize)?);
    }
    Ok(out)
}

// ── Zenoh-layer body walkers ─────────────────────────────────────────

/// `MsgPut` (zenoh MID 0x01).
pub fn walk_msg_put(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("t", carrier, (header & 0x20) != 0),
        flag("e", carrier, (header & 0x40) != 0),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    if (header & 0x20) != 0 {
        out.push(c.nested("timestamp", walk_timestamp)?);
    }
    if (header & 0x40) != 0 {
        out.push(c.nested("encoding", walk_encoding)?);
    }
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    let (n, len) = c.vle_u64("payload_len")?;
    out.push(len);
    out.push(c.bytes("payload", n as usize)?);
    Ok(out)
}

/// `MsgDel` (zenoh MID 0x02).
pub fn walk_msg_del(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("t", carrier, (header & 0x20) != 0),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    if (header & 0x20) != 0 {
        out.push(c.nested("timestamp", walk_timestamp)?);
    }
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    Ok(out)
}

/// `Query` (zenoh MID 0x03). Its ext chain is the fill-to-end shape, so a
/// Query carrying extensions consumes to the end of the cursor it was handed
/// — the generated codec's behaviour, mirrored rather than corrected.
pub fn walk_query(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("c", carrier, (header & 0x20) != 0),
        flag("p", carrier, (header & 0x40) != 0),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    if (header & 0x20) != 0 {
        let (_, f) = c.u8("consolidation")?;
        out.push(f);
    }
    if (header & 0x40) != 0 {
        let (n, len) = c.vle_u64("parameters_len")?;
        out.push(len);
        out.push(c.bytes("parameters", n as usize)?);
    }
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_fill(c, crate::ext_chain::QUERY_EXT_CHAIN_DEPTH)
        })?);
    }
    Ok(out)
}

/// `Reply` (zenoh MID 0x04) — a consolidation byte plus an inner put / del.
pub fn walk_reply(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("c", carrier, (header & 0x20) != 0),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    if (header & 0x20) != 0 {
        let (_, f) = c.u8("consolidation")?;
        out.push(f);
    }
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    out.push(walk_put_or_del_body(c)?);
    Ok(out)
}

/// `Err` (zenoh MID 0x05).
pub fn walk_err(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("e", carrier, (header & 0x40) != 0),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    if (header & 0x40) != 0 {
        out.push(c.nested("encoding", walk_encoding)?);
    }
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    let (n, len) = c.vle_u64("payload_len")?;
    out.push(len);
    out.push(c.bytes("payload", n as usize)?);
    Ok(out)
}

/// The put/del inner-body dispatch shared by `Push` and `Reply`: peek the
/// body's own header byte, mask its MID, and walk the arm. The generated
/// codecs' default arm decodes an `MsgPut` regardless of the tag, so the
/// walker does too — a body whose MID this build does not know is still
/// walked as a put, and mis-decoding it is the codec's documented behaviour,
/// not a divergence introduced here.
fn walk_put_or_del_body(c: &mut SpanCursor<'_>) -> Result<Field, CodecError> {
    match c.peek_u8()? & 0x1F {
        2 => c.nested("del", walk_msg_del),
        _ => c.nested("put", walk_msg_put),
    }
}

// ── Network-layer envelope walkers ───────────────────────────────────

/// `Push` (network MID 0x1D).
pub fn walk_push(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let n = (header >> 5) & 0x1;
    let m = (header >> 6) & 0x1;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("n", carrier, n != 0),
        flag("m", carrier, m != 0),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    out.push(c.nested("keyexpr", |c| walk_wireexpr(c, n, m))?);
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    out.push(walk_put_or_del_body(c)?);
    Ok(out)
}

/// `Request` (network MID 0x1C).
pub fn walk_request(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let n = (header >> 5) & 0x1;
    let m = (header >> 6) & 0x1;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("n", carrier, n != 0),
        flag("m", carrier, m != 0),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    let (_, rid) = c.vle_u64("rid")?;
    out.push(rid);
    out.push(c.nested("keyexpr", |c| walk_wireexpr(c, n, m))?);
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    // Query is the codec's default arm here, not MsgPut.
    out.push(match c.peek_u8()? & 0x1F {
        1 => c.nested("put", walk_msg_put)?,
        2 => c.nested("del", walk_msg_del)?,
        _ => c.nested("query", walk_query)?,
    });
    Ok(out)
}

/// `Response` (network MID 0x1B).
pub fn walk_response(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let n = (header >> 5) & 0x1;
    let m = (header >> 6) & 0x1;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("n", carrier, n != 0),
        flag("m", carrier, m != 0),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    let (_, rid) = c.vle_u64("request_id")?;
    out.push(rid);
    out.push(c.nested("keyexpr", |c| walk_wireexpr(c, n, m))?);
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    out.push(match c.peek_u8()? & 0x1F {
        5 => c.nested("err", walk_err)?,
        _ => c.nested("reply", walk_reply)?,
    });
    Ok(out)
}

/// `ResponseFinal` (network MID 0x1A) — a pure correlation marker.
pub fn walk_response_final(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    let (_, rid) = c.vle_u64("request_id")?;
    out.push(rid);
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    Ok(out)
}

/// `InterestBody` — the C/F-gated inner record of an `Interest`.
pub fn walk_interest_body(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mut out = alloc::vec![
        header_field,
        flag("keyexprs", carrier, (header & 0x01) != 0),
        flag("subscribers", carrier, (header & 0x02) != 0),
        flag("queryables", carrier, (header & 0x04) != 0),
        flag("tokens", carrier, (header & 0x08) != 0),
        flag("restricted", carrier, (header & 0x10) != 0),
        flag("n", carrier, (header & 0x20) != 0),
    ];
    if (header & 0x10) != 0 {
        let n = (header >> 5) & 0x1;
        out.push(c.nested("keyexpr", move |c| walk_wireexpr(c, n, 0x1))?);
    }
    Ok(out)
}

/// `Interest` (network MID 0x19).
pub fn walk_interest(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("current", carrier, (header & 0x20) != 0),
        flag("future", carrier, (header & 0x40) != 0),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    let (_, id) = c.vle_u64("interest_id")?;
    out.push(id);
    if (header & 0x20) != 0 || (header & 0x40) != 0 {
        out.push(c.nested("body", walk_interest_body)?);
    }
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    Ok(out)
}

/// `Oam` (network MID 0x1F) — the body encoding lives in the header's bits
/// 5..6, exactly as an `ExtEntry`'s does.
pub fn walk_oam(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let enc = (header >> 5) & 0x03;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        bits("encoding", carrier, enc as u64),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    let (_, id) = c.vle_u64("id")?;
    out.push(id);
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    match enc {
        1 => {
            let (_, f) = c.vle_u64("value")?;
            out.push(f);
        }
        2 => {
            let (n, len) = c.vle_u64("value_len")?;
            out.push(len);
            out.push(c.bytes("value", n as usize)?);
        }
        _ => {}
    }
    Ok(out)
}

/// A `Declare` inner body. The nine sub-MIDs reduce to four layouts:
/// header + id + keyexpr (DECL_KEXPR / DECL_SUBSCRIBER / DECL_TOKEN), the
/// same plus an ext chain (DECL_QUERYABLE), header + id (+ ext chain)
/// (UNDECL_*), and a bare header (DECL_FINAL).
fn walk_declare_body(c: &mut SpanCursor<'_>) -> Result<Field, CodecError> {
    /// header + VLE id + a wireexpr whose mapping tag the caller fixes.
    fn id_and_keyexpr(
        c: &mut SpanCursor<'_>,
        fixed_mapping: Option<u8>,
    ) -> Result<Vec<Field>, CodecError> {
        let (header, header_field) = c.u8("header")?;
        let carrier = header_field.span;
        let n = (header >> 5) & 0x1;
        let m = fixed_mapping.unwrap_or((header >> 6) & 0x1);
        let mut out = alloc::vec![
            header_field,
            bits("mid", carrier, (header & 0x1F) as u64),
            flag("n", carrier, n != 0),
            flag("m", carrier, ((header >> 6) & 0x1) != 0),
            flag("z", carrier, (header & 0x80) != 0),
        ];
        let (_, id) = c.vle_u64("id")?;
        out.push(id);
        out.push(c.nested("keyexpr", move |c| walk_wireexpr(c, n, m))?);
        Ok(out)
    }

    /// header + VLE id + an optional Z-gated ext chain.
    fn id_and_exts(c: &mut SpanCursor<'_>, with_exts: bool) -> Result<Vec<Field>, CodecError> {
        let (header, header_field) = c.u8("header")?;
        let carrier = header_field.span;
        let mut out = alloc::vec![
            header_field,
            bits("mid", carrier, (header & 0x1F) as u64),
            flag("z", carrier, (header & 0x80) != 0),
        ];
        let (_, id) = c.vle_u64("id")?;
        out.push(id);
        if with_exts && (header & 0x80) != 0 {
            out.push(c.nested("extensions", |c| {
                walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
            })?);
        }
        Ok(out)
    }

    match c.peek_u8()? & 0x1F {
        0 => c.nested("decl_kexpr", |c| id_and_keyexpr(c, Some(0x1))),
        1 => c.nested("undecl_kexpr", |c| id_and_exts(c, false)),
        2 => c.nested("decl_subscriber", |c| id_and_keyexpr(c, None)),
        3 => c.nested("undecl_subscriber", |c| id_and_exts(c, true)),
        4 => c.nested("decl_queryable", |c| {
            let mut out = id_and_keyexpr(c, None)?;
            // The queryable body is the one decl arm carrying its own ext
            // chain; its Z bit is the header bit already recorded above.
            if let Some(Field {
                value: FieldValue::Uint(h),
                ..
            }) = out.first()
            {
                if (*h as u8 & 0x80) != 0 {
                    out.push(c.nested("extensions", |c| {
                        walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
                    })?);
                }
            }
            Ok(out)
        }),
        5 => c.nested("undecl_queryable", |c| id_and_exts(c, true)),
        6 => c.nested("decl_token", |c| id_and_keyexpr(c, None)),
        7 => c.nested("undecl_token", |c| id_and_exts(c, true)),
        // DECL_FINAL (0x1A) and the codec's default arm, which is also
        // DECL_FINAL: a lone header byte.
        _ => c.nested("decl_final", |c| {
            let (header, header_field) = c.u8("header")?;
            let carrier = header_field.span;
            Ok(alloc::vec![
                header_field,
                bits("mid", carrier, (header & 0x1F) as u64),
                flag("z", carrier, (header & 0x80) != 0),
            ])
        }),
    }
}

/// `Declare` (network MID 0x1E).
pub fn walk_declare(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, (header & 0x1F) as u64),
        flag("i", carrier, (header & 0x20) != 0),
        flag("z", carrier, (header & 0x80) != 0),
    ];
    if (header & 0x20) != 0 {
        let (_, f) = c.vle_u64("interest_id")?;
        out.push(f);
    }
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH)
        })?);
    }
    out.push(walk_declare_body(c)?);
    Ok(out)
}

// ── Batch + transport entry points ───────────────────────────────────

/// Why a batch dissection stopped short of the payload's end.
///
/// Mirrors [`crate::network_message::BatchHalt`] in shape and reason; kept a
/// distinct type because its offsets are in the DISSECTION's coordinate
/// space (`base` added), while `BatchHalt`'s are payload-relative by
/// contract. Conflating the two would put two coordinate systems behind one
/// field name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "dissect-serde",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum DissectHalt {
    /// A network MID with no walker in this build. Its length is unknowable,
    /// so the walk stopped rather than guessing.
    UnknownMid {
        /// The masked MID (`header & 0x1F`).
        mid: u8,
        /// Absolute offset of that header byte.
        offset: usize,
    },
    /// A record failed to walk. `NeedMoreBytes` here is the ordinary shape of
    /// a truncated capture, not necessarily corruption.
    Error {
        /// Absolute offset of the failing record's first byte.
        offset: usize,
        /// The decoder's own error, carried so a consumer can tell a
        /// truncation from a malformed field.
        #[cfg_attr(feature = "dissect-serde", serde(with = "codec_error_serde"))]
        error: CodecError,
    },
}

/// Serialize [`CodecError`] as its stable variant NAME.
///
/// The error stays the runtime's own typed enum — a consumer matching on
/// `NeedMoreBytes` to tell a truncated capture from a corrupt one needs the
/// type, not a string. What it cannot be is serde-derived: the enum belongs to
/// `sce_forge_runtime`, which carries no serde feature and is read-only from
/// here. So the mapping is written out, by name rather than by discriminant,
/// so a future variant inserted mid-enum cannot silently renumber a persisted
/// dissection. An unknown name reads back as `NeedMoreBytes`, the only variant
/// whose meaning ("there was not enough here") stays true of a record this
/// build could not otherwise account for.
#[cfg(feature = "dissect-serde")]
mod codec_error_serde {
    use sce_forge_runtime::codec::CodecError;

    fn name(e: &CodecError) -> &'static str {
        match e {
            CodecError::NeedMoreBytes => "NeedMoreBytes",
            CodecError::VleWidthOverflow => "VleWidthOverflow",
            CodecError::TlvChainOverflow => "TlvChainOverflow",
            CodecError::InvalidUtf8 => "InvalidUtf8",
            CodecError::BufferOverflow => "BufferOverflow",
            CodecError::TooManyElements => "TooManyElements",
            // `CodecError` is `#[non_exhaustive]`, so a variant added upstream
            // after this build lands here. It serializes under its own name
            // rather than borrowing an existing one: mislabelling a new error
            // as `NeedMoreBytes` would tell a consumer the capture was
            // truncated when it was not.
            _ => "Unrecognised",
        }
    }

    pub fn serialize<S: serde::Serializer>(e: &CodecError, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(name(e))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<CodecError, D::Error> {
        use serde::Deserialize as _;
        let s = alloc::string::String::deserialize(d)?;
        Ok(match s.as_str() {
            "VleWidthOverflow" => CodecError::VleWidthOverflow,
            "TlvChainOverflow" => CodecError::TlvChainOverflow,
            "InvalidUtf8" => CodecError::InvalidUtf8,
            "BufferOverflow" => CodecError::BufferOverflow,
            "TooManyElements" => CodecError::TooManyElements,
            _ => CodecError::NeedMoreBytes,
        })
    }
}

/// The outcome of a best-effort batch dissection.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "dissect-serde",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct BatchDissection {
    /// Every record walked before the walk stopped, in wire order.
    pub records: Vec<Field>,
    /// `None` when the whole payload walked.
    pub halt: Option<DissectHalt>,
    /// Bytes from the halt offset to the end of the payload; `0` when the
    /// walk consumed everything.
    pub unparsed_bytes: usize,
}

impl BatchDissection {
    /// `true` when the entire payload walked with no halt.
    pub fn is_complete(&self) -> bool {
        self.halt.is_none()
    }
}

/// Walk ONE network record at the cursor, or report that its MID has no
/// walker here.
///
/// The MID set is [`crate::network_message`]'s, and deliberately so: a build
/// that can DECODE a record should be able to DISSECT it, and the gate in
/// `tests` asserts the two sets are equal rather than trusting this comment.
/// R311y585 (A6) — `Scout`: version, a packed cbyte, and an I-gated ZID.
///
/// The scouting messages live on a MID space the batch walk never reaches
/// (`wire_const::S_MID_SCOUT` / `S_MID_HELLO`, disjoint from the transport
/// MIDs), so until now `dissect` covered transport + network + zenoh and
/// stopped. R311y584 made that gap reachable: UDP datagrams now arrive at the
/// observer, and a scouting datagram is most of what a multicast capture
/// contains.
pub fn walk_scout(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (_, version) = c.u8("version")?;
    let (cbyte, cbyte_field) = c.u8("cbyte")?;
    let carrier = cbyte_field.span;
    let mut out = alloc::vec![
        version,
        cbyte_field,
        bits("what", carrier, (cbyte & 0x07) as u64),
        flag("i", carrier, (cbyte & 0x08) != 0),
        bits("zid_len_m1", carrier, ((cbyte >> 4) & 0x0F) as u64),
    ];
    // I-gated, and the LENGTH rides the same carrier: `(cbyte >> 4) + 1`.
    if (cbyte & 0x08) != 0 {
        out.push(c.bytes("zid", (((cbyte >> 4) & 0x0F) as usize) + 1)?);
    }
    Ok(out)
}

/// R311y585 (A6) — `Hello`: version, cbyte, an ALWAYS-present ZID, and an
/// L-gated locator list.
///
/// `l` comes from the scouting HEADER byte (`FLAG_S_HELLO_L`), not from the
/// body — the same shape as `Declare`'s sub-MID, and the reason this takes a
/// parameter where [`walk_scout`] does not.
pub fn walk_hello(c: &mut SpanCursor<'_>, l: bool) -> Result<Vec<Field>, CodecError> {
    let (_, version) = c.u8("version")?;
    let (cbyte, cbyte_field) = c.u8("cbyte")?;
    let carrier = cbyte_field.span;
    let mut out = alloc::vec![
        version,
        cbyte_field,
        bits("whatami", carrier, (cbyte & 0x03) as u64),
        bits("zid_len_m1", carrier, ((cbyte >> 4) & 0x0F) as u64),
    ];
    out.push(c.bytes("zid", (((cbyte >> 4) & 0x0F) as usize) + 1)?);
    if l {
        let (n, count) = c.vle_u64("num_locators")?;
        out.push(count);
        for _ in 0..n {
            let start = c.offset();
            let (len, len_field) = c.vle_u64("locator_len")?;
            let text = c.text("locator", len as usize)?;
            let end = c.offset();
            // The GROUP is named apart from its leaf on purpose: `find`
            // returns the first match by name, so a group called "locator"
            // shadows the string field inside it and a consumer asking for
            // the locator gets a nested node instead of the text.
            out.push(group(
                "locator_entry",
                start,
                end,
                alloc::vec![len_field, text],
            ));
        }
    }
    Ok(out)
}

/// R311y585 (A6) — dissect ONE scouting datagram, header byte included.
///
/// A separate entry point from [`dissect_transport_message`] because the MID
/// space is separate: `0x01` is `Scout` here and `Init` there. Handing a
/// scouting datagram to the transport dispatcher does not fail, it decodes
/// the wrong message — which is exactly the confident-wrong-answer failure a
/// dissector exists to avoid, and the reason this is not a new arm on the
/// existing walk.
pub fn dissect_scouting_message(bytes: &[u8], base: usize) -> Result<Option<Field>, CodecError> {
    let mut c = SpanCursor::with_base(bytes, base);
    let start = c.offset();
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mid = header & 0x1F;
    let l = (header & wz_codecs::wire_const::FLAG_S_HELLO_L) != 0;
    let mut fields = alloc::vec![header_field, bits("mid", carrier, mid as u64),];
    let (name, body) = match mid {
        wz_codecs::wire_const::S_MID_SCOUT => ("Scout", walk_scout(&mut c)?),
        wz_codecs::wire_const::S_MID_HELLO => {
            fields.push(flag("l", carrier, l));
            ("Hello", walk_hello(&mut c, l)?)
        }
        // NOT an error: a byte that is not a scouting MID means these bytes
        // are not a scouting message, which the caller decides what to do
        // about. Mirrors `walk_network_record`'s absence-vs-failure split.
        _ => return Ok(None),
    };
    fields.extend(body);
    Ok(Some(group(name, start, c.offset(), fields)))
}

pub fn walk_network_record(c: &mut SpanCursor<'_>) -> Result<Option<Field>, CodecError> {
    use wz_codecs::wire_const;
    let mid = c.peek_u8()? & 0x1F;
    let f = match mid {
        wire_const::N_MID_PUSH => c.nested("Push", walk_push)?,
        wire_const::N_MID_REQUEST => c.nested("Request", walk_request)?,
        wire_const::N_MID_RESPONSE => c.nested("Response", walk_response)?,
        wire_const::N_MID_RESPONSE_FINAL => c.nested("ResponseFinal", walk_response_final)?,
        wire_const::N_MID_INTEREST => c.nested("Interest", walk_interest)?,
        wire_const::N_MID_DECLARE => c.nested("Declare", walk_declare)?,
        wire_const::N_MID_OAM => c.nested("Oam", walk_oam)?,
        _ => return Ok(None),
    };
    Ok(Some(f))
}

/// Dissect a `Frame.payload` batch BEST-EFFORT: keep every record that walks
/// and report where the walk stopped.
///
/// The observer contract, mirroring
/// [`crate::network_message::parse_frame_payload_best_effort`]: a record this
/// build cannot read does not invalidate the ones before it. Never returns
/// `Err`; an empty payload is an empty, complete dissection.
pub fn dissect_batch(payload: &[u8], base: usize) -> BatchDissection {
    let mut c = SpanCursor::with_base(payload, base);
    let mut records = Vec::new();
    let mut halt = None;
    while c.remaining() > 0 {
        let offset = c.offset();
        match walk_network_record(&mut c) {
            Ok(Some(f)) => records.push(f),
            Ok(None) => {
                let mid = match c.peek_u8() {
                    Ok(b) => b & 0x1F,
                    Err(error) => {
                        halt = Some(DissectHalt::Error { offset, error });
                        break;
                    }
                };
                halt = Some(DissectHalt::UnknownMid { mid, offset });
                break;
            }
            Err(error) => {
                halt = Some(DissectHalt::Error { offset, error });
                break;
            }
        }
    }
    let unparsed_bytes = match halt {
        Some(DissectHalt::UnknownMid { offset, .. }) | Some(DissectHalt::Error { offset, .. }) => {
            (base + payload.len()).saturating_sub(offset)
        }
        None => 0,
    };
    BatchDissection {
        records,
        halt,
        unparsed_bytes,
    }
}

/// Dissect ONE transport message — the shape [`crate::inbound::parse_inbound`]
/// consumes: a header byte carrying `(flags << 5) | mid`, the per-MID body,
/// and the Z-gated ext chain.
///
/// A `Frame`'s payload is descended into as a batch, because a frame's whole
/// point is the records it carries. A `Fragment`'s is NOT: its payload is a
/// slice of a message the reassembler has not yet completed, and walking it
/// would produce field spans for a record that does not begin there.
pub fn dissect_transport_message(bytes: &[u8], base: usize) -> Result<Field, CodecError> {
    use wz_codecs::wire_const;
    let mut c = SpanCursor::with_base(bytes, base);
    let start = c.offset();
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let mid = header & 0x1F;
    let has_ext = (header & 0x80) != 0;
    let mut out = alloc::vec![
        header_field,
        bits("mid", carrier, mid as u64),
        flag("z", carrier, has_ext),
    ];
    let name = match mid {
        wire_const::T_MID_INIT => {
            out.push(flag("a", carrier, (header & 0x20) != 0));
            out.push(flag("s", carrier, (header & 0x40) != 0));
            let (_, version) = c.u8("version")?;
            out.push(version);
            let (cbyte, cbyte_field) = c.u8("cbyte")?;
            let cb_span = cbyte_field.span;
            out.push(cbyte_field);
            out.push(bits("whatami", cb_span, (cbyte & 0x03) as u64));
            out.push(bits("zid_len", cb_span, (((cbyte >> 4) & 0xF) + 1) as u64));
            out.push(c.bytes("zid", ((cbyte >> 4) & 0xF) as usize + 1)?);
            if (header & 0x40) != 0 {
                let (_, sn_res) = c.u8("sn_res")?;
                out.push(sn_res);
                let (_, batch) = c.u16_le("batch_size")?;
                out.push(batch);
            }
            if (header & 0x20) != 0 {
                let (n, len) = c.vle_u64("cookie_len")?;
                out.push(len);
                out.push(c.bytes("cookie", n as usize)?);
            }
            "Init"
        }
        wire_const::T_MID_OPEN => {
            out.push(flag("a", carrier, (header & 0x20) != 0));
            out.push(flag("t", carrier, (header & 0x40) != 0));
            let (_, lease) = c.vle_u64("lease")?;
            out.push(lease);
            let (_, isn) = c.vle_u64("initial_sn")?;
            out.push(isn);
            // OPEN's cookie rides the SYN (A clear), not the ACK — the
            // generated codec's gate is `(a & 1) == 0`, inverted from INIT's.
            if (header & 0x20) == 0 {
                let (n, len) = c.vle_u64("cookie_len")?;
                out.push(len);
                out.push(c.bytes("cookie", n as usize)?);
            }
            "Open"
        }
        wire_const::T_MID_CLOSE => {
            let (_, reason) = c.u8("reason")?;
            out.push(reason);
            "Close"
        }
        wire_const::T_MID_KEEP_ALIVE => "KeepAlive",
        wire_const::T_MID_JOIN => {
            out.push(flag("t", carrier, (header & 0x20) != 0));
            out.push(flag("s", carrier, (header & 0x40) != 0));
            let (_, version) = c.u8("version")?;
            out.push(version);
            let (cbyte, cbyte_field) = c.u8("cbyte")?;
            let cb_span = cbyte_field.span;
            out.push(cbyte_field);
            out.push(bits("whatami", cb_span, (cbyte & 0x03) as u64));
            out.push(bits("zid_len", cb_span, (((cbyte >> 4) & 0xF) + 1) as u64));
            out.push(c.bytes("zid", ((cbyte >> 4) & 0xF) as usize + 1)?);
            if (header & 0x40) != 0 {
                let (_, sn_res) = c.u8("sn_res")?;
                out.push(sn_res);
                let (_, batch) = c.u16_le("batch_size")?;
                out.push(batch);
            }
            let (_, lease) = c.vle_u64("lease")?;
            out.push(lease);
            let (_, r) = c.vle_u64("next_sn_reliable")?;
            out.push(r);
            let (_, b) = c.vle_u64("next_sn_best_effort")?;
            out.push(b);
            "Join"
        }
        wire_const::T_MID_FRAME | wire_const::T_MID_FRAGMENT => {
            out.push(flag("r", carrier, (header & 0x20) != 0));
            if mid == wire_const::T_MID_FRAGMENT {
                out.push(flag("m", carrier, (header & 0x40) != 0));
            }
            let (_, sn) = c.vle_u64("sn")?;
            out.push(sn);
            if has_ext {
                out.push(c.nested("extensions", |c| {
                    walk_ext_chain_z(c, crate::parse_error::MAX_EXT_CHAIN_DEPTH)
                })?);
            }
            if mid == wire_const::T_MID_FRAME {
                let payload_start = c.offset();
                let rem = c.remaining();
                let raw = c.bytes("payload", rem)?;
                let bytes = match &raw.value {
                    FieldValue::Bytes(b) => b.clone(),
                    _ => Vec::new(),
                };
                let batch = dissect_batch(&bytes, payload_start);
                // A batch that halted keeps its walked records AND the raw
                // remainder, so no capture byte goes unaccounted for.
                let mut children = batch.records;
                if batch.unparsed_bytes > 0 {
                    let unparsed_start = payload_start + rem - batch.unparsed_bytes;
                    children.push(Field {
                        name: "unparsed".into(),
                        span: Span {
                            start: unparsed_start,
                            end: payload_start + rem,
                        },
                        value: FieldValue::Bytes(bytes[rem - batch.unparsed_bytes..].to_vec()),
                    });
                }
                out.push(group("payload", payload_start, c.offset(), children));
            } else {
                out.push(c.tail("payload")?);
            }
            if mid == wire_const::T_MID_FRAME {
                "Frame"
            } else {
                "Fragment"
            }
        }
        _ => {
            out.push(c.tail("body")?);
            "Unknown"
        }
    };
    // The transport ext chain trails every non-Frame body; Frame / Fragment
    // read theirs before the payload, above.
    if has_ext && mid != wire_const::T_MID_FRAME && mid != wire_const::T_MID_FRAGMENT {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(c, crate::parse_error::MAX_EXT_CHAIN_DEPTH)
        })?);
    }
    Ok(group(name, start, c.offset(), out))
}

// ── Rendering ────────────────────────────────────────────────────────

/// Render a dissection as JSON, with NO serde dependency.
///
/// The `dissect-serde` feature gives a consumer serde's whole ecosystem; this
/// function gives a `no_std` + `alloc` build that cannot take that dependency
/// the same machine-readable output. Both exist because G6's measured failure
/// was a consumer unable to get a decode into a log at all — a dissector that
/// can only print through a dependency the target cannot link has not solved
/// it.
///
/// Byte fields render as lowercase hex. String content routes through
/// [`crate::json::escape_into`], the workspace's escaper SSOT.
pub fn to_json(field: &Field) -> String {
    let mut out = String::new();
    push_json(field, &mut out);
    out
}

fn push_json(field: &Field, out: &mut String) {
    use core::fmt::Write as _;
    out.push_str("{\"name\":");
    crate::json::escape_into(&field.name, out);
    let _ = write!(
        out,
        ",\"start\":{},\"end\":{},",
        field.span.start, field.span.end
    );
    match &field.value {
        FieldValue::Bits(v) => {
            let _ = write!(out, "\"kind\":\"bits\",\"value\":{v}");
        }
        FieldValue::Flag(b) => {
            let _ = write!(out, "\"kind\":\"flag\",\"value\":{b}");
        }
        FieldValue::Uint(v) => {
            let _ = write!(out, "\"kind\":\"uint\",\"value\":{v}");
        }
        FieldValue::Bytes(b) => {
            out.push_str("\"kind\":\"bytes\",\"value\":\"");
            for byte in b {
                let _ = write!(out, "{byte:02x}");
            }
            out.push('"');
        }
        FieldValue::Text(s) => {
            out.push_str("\"kind\":\"text\",\"value\":");
            crate::json::escape_into(s, out);
        }
        FieldValue::Opaque => {
            out.push_str("\"kind\":\"opaque\"");
        }
        FieldValue::Nested(children) => {
            out.push_str("\"kind\":\"nested\",\"fields\":[");
            for (i, child) in children.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_json(child, out);
            }
            out.push(']');
        }
    }
    out.push('}');
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Flatten every non-alias terminal span under `field`, in wire order.
    fn leaves(field: &Field) -> Vec<Span> {
        let mut out = Vec::new();
        field.leaf_spans(&mut out);
        out
    }

    /// The tiling invariant: the leaf spans cover `[start, end)` exactly —
    /// contiguous, in order, no gap, no overlap. Anything else means a field
    /// is pointing at bytes that belong to another field, which is the exact
    /// failure a hand-written walker is prone to.
    #[track_caller]
    fn assert_tiles(field: &Field, start: usize, end: usize) {
        let spans = leaves(field);
        let mut cursor = start;
        for (i, span) in spans.iter().enumerate() {
            assert_eq!(
                span.start, cursor,
                "leaf {i} starts at {} but the previous leaf ended at {cursor}: {spans:?}",
                span.start
            );
            assert!(
                span.end >= span.start,
                "leaf {i} is inverted: {span:?} in {spans:?}"
            );
            cursor = span.end;
        }
        assert_eq!(
            cursor, end,
            "the leaves end at {cursor} but the message ends at {end}: {spans:?}"
        );
        assert_eq!(
            field.span,
            Span { start, end },
            "the parent span disagrees with the walked range"
        );
    }

    #[test]
    fn span_cursor_reports_absolute_offsets() {
        // A VLE that occupies two bytes is where the raw span and the value
        // part company — the gap this module exists to close.
        let buf = [0x80u8, 0x01, 0xAA];
        let mut c = SpanCursor::with_base(&buf, 1000);
        let (v, f) = c.vle_u64("sn").unwrap();
        assert_eq!(v, 128);
        assert_eq!(
            f.span,
            Span {
                start: 1000,
                end: 1002
            }
        );
        let tail = c.tail("rest").unwrap();
        assert_eq!(
            tail.span,
            Span {
                start: 1002,
                end: 1003
            }
        );
    }

    #[test]
    fn flag_and_bits_alias_their_carrier_and_leave_the_tiling_alone() {
        let carrier = Span { start: 4, end: 5 };
        let f = group(
            "hdr",
            4,
            5,
            alloc::vec![
                Field {
                    name: "header".into(),
                    span: carrier,
                    value: FieldValue::Uint(0xA5),
                },
                bits("mid", carrier, 0x05),
                flag("z", carrier, true),
            ],
        );
        assert_eq!(leaves(&f), alloc::vec![carrier]);
    }

    #[test]
    fn to_json_escapes_and_hexes() {
        let f = group(
            "m",
            0,
            2,
            alloc::vec![
                Field {
                    name: "payload".into(),
                    span: Span { start: 0, end: 1 },
                    value: FieldValue::Bytes(alloc::vec![0x0f, 0xff]),
                },
                Field {
                    name: "suffix".into(),
                    span: Span { start: 1, end: 2 },
                    value: FieldValue::Text(String::from("a\"b")),
                },
            ],
        );
        let json = to_json(&f);
        assert!(json.contains(r#""value":"0fff""#), "{json}");
        assert!(json.contains(r#""value":"a\"b""#), "{json}");
        assert!(
            json.starts_with(r#"{"name":"m","start":0,"end":2,"kind":"nested""#),
            "{json}"
        );
    }

    #[test]
    fn find_reaches_a_nested_field() {
        let f = group(
            "Frame",
            0,
            3,
            alloc::vec![group(
                "payload",
                0,
                3,
                alloc::vec![Field {
                    name: "sn".into(),
                    span: Span { start: 0, end: 3 },
                    value: FieldValue::Uint(7),
                }]
            )],
        );
        assert_eq!(f.find("sn").map(|x| x.span.end), Some(3));
        assert!(f.find("nope").is_none());
    }

    // ── The differential gate ────────────────────────────────────────
    //
    // Every walker below is checked against the GENERATED codec over the same
    // bytes. Three claims per fixture, and a walker that is merely
    // self-consistent fails all three:
    //
    //   1. the two consumed the SAME number of bytes;
    //   2. the walker's leaf spans TILE that range — contiguous, ordered, no
    //      gap, no overlap;
    //   3. the values the walker reports equal the codec's own fields, and
    //      each sub-codec's span RE-DECODES standalone consuming exactly its
    //      own width (which is what makes it that field's bytes rather than a
    //      plausible range).
    //
    // The fixtures are built from the wire spec, not from wz's message
    // builders: a fixture minted by the encoder under test can agree with a
    // decoder that shares its mistake. `hand_written_vle_anchors_the_width`
    // pins the one primitive both sides DO share against bytes typed out here.

    /// Encode `v` as a base-128 VLE through the runtime's own writer — the
    /// same SSOT both the codec and the walker read with.
    fn vle(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        crate::vle::encode_vle_u64_into(&mut out, v);
        out
    }

    fn ext_unit(id: u8, more: bool) -> Vec<u8> {
        alloc::vec![id | if more { 0x80 } else { 0 }]
    }

    fn ext_zint(id: u8, more: bool, v: u64) -> Vec<u8> {
        let mut out = alloc::vec![id | 0x20 | if more { 0x80 } else { 0 }];
        out.extend(vle(v));
        out
    }

    fn ext_zbuf(id: u8, more: bool, body: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![id | 0x40 | if more { 0x80 } else { 0 }];
        out.extend(vle(body.len() as u64));
        out.extend_from_slice(body);
        out
    }

    fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in parts {
            out.extend_from_slice(p);
        }
        out
    }

    fn timestamp(time: u64, zid: &[u8]) -> Vec<u8> {
        concat(&[vle(time), vle(zid.len() as u64), zid.to_vec()])
    }

    fn encoding(id: u32, schema: Option<&str>) -> Vec<u8> {
        let packed = (u64::from(id) << 1) | u64::from(schema.is_some());
        let mut out = vle(packed);
        if let Some(s) = schema {
            out.extend(vle(s.len() as u64));
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    fn wireexpr(id: u64, suffix: Option<&str>) -> Vec<u8> {
        let mut out = vle(id);
        if let Some(s) = suffix {
            out.extend(vle(s.len() as u64));
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    /// A `MsgPut` body: header, then whichever optional records its flags
    /// announce, then the length-prefixed payload.
    fn msg_put(
        ts: Option<(u64, &[u8])>,
        enc: Option<(u32, Option<&str>)>,
        exts: &[Vec<u8>],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut header = 0x01u8;
        if ts.is_some() {
            header |= 0x20;
        }
        if enc.is_some() {
            header |= 0x40;
        }
        if !exts.is_empty() {
            header |= 0x80;
        }
        let mut out = alloc::vec![header];
        if let Some((t, z)) = ts {
            out.extend(timestamp(t, z));
        }
        if let Some((i, s)) = enc {
            out.extend(encoding(i, s));
        }
        for e in exts {
            out.extend_from_slice(e);
        }
        out.extend(vle(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn msg_del(ts: Option<(u64, &[u8])>, exts: &[Vec<u8>]) -> Vec<u8> {
        let mut header = 0x02u8;
        if ts.is_some() {
            header |= 0x20;
        }
        if !exts.is_empty() {
            header |= 0x80;
        }
        let mut out = alloc::vec![header];
        if let Some((t, z)) = ts {
            out.extend(timestamp(t, z));
        }
        for e in exts {
            out.extend_from_slice(e);
        }
        out
    }

    /// Drive the walker and the generated codec over the same bytes and
    /// reject any disagreement. Returns the walked field so the caller can
    /// assert on individual values.
    #[track_caller]
    fn agree(
        name: &'static str,
        bytes: &[u8],
        codec_consumed: impl FnOnce(&[u8]) -> usize,
        walk: impl FnOnce(&mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError>,
    ) -> Field {
        let by_codec = codec_consumed(bytes);
        let mut c = SpanCursor::new(bytes);
        let fields = match walk(&mut c) {
            Ok(f) => f,
            Err(e) => panic!("{name}: the walker rejected a fixture the codec accepted: {e:?}"),
        };
        let by_walker = c.offset();
        assert_eq!(
            by_walker, by_codec,
            "{name}: the walker consumed {by_walker} bytes, the codec {by_codec}"
        );
        let f = group(name, 0, by_walker, fields);
        assert_tiles(&f, 0, by_walker);
        f
    }

    /// `field` must hold this unsigned value.
    #[track_caller]
    fn uint(root: &Field, name: &str) -> u64 {
        match root.find(name).map(|f| &f.value) {
            Some(FieldValue::Uint(v)) => *v,
            other => panic!("{name} is not a uint: {other:?}"),
        }
    }

    #[track_caller]
    fn text(root: &Field, name: &str) -> String {
        match root.find(name).map(|f| &f.value) {
            Some(FieldValue::Text(v)) => v.clone(),
            other => panic!("{name} is not text: {other:?}"),
        }
    }

    #[track_caller]
    fn raw(root: &Field, name: &str) -> Vec<u8> {
        match root.find(name).map(|f| &f.value) {
            Some(FieldValue::Bytes(v)) => v.clone(),
            other => panic!("{name} is not bytes: {other:?}"),
        }
    }

    /// A sub-codec's span really is that field's bytes: slicing the message at
    /// the span and decoding it STANDALONE must succeed and consume exactly
    /// the span's width. A span that merely starts in the right place passes
    /// the tiling gate and fails this one.
    #[track_caller]
    fn span_redecodes(
        bytes: &[u8],
        span: Span,
        decode: impl FnOnce(&[u8]) -> Result<usize, CodecError>,
    ) {
        let slice = &bytes[span.start..span.end];
        match decode(slice) {
            Ok(consumed) => assert_eq!(
                consumed,
                span.len(),
                "the span is {} bytes but a standalone decode consumed {consumed}",
                span.len()
            ),
            Err(e) => panic!("the span did not re-decode standalone: {e:?}"),
        }
    }

    #[test]
    fn hand_written_vle_anchors_the_width() {
        // 0x80 0x01 is 128 in base-128 VLE: two bytes for a value one byte
        // could hold in raw form. Typed out here rather than produced by the
        // encoder, so the one primitive the walker and the codec share is
        // anchored against something outside both.
        let bytes = [0x80u8, 0x01, 0xEE];
        let mut c = SpanCursor::new(&bytes);
        let (v, f) = c.vle_u64("sn").unwrap();
        assert_eq!(v, 128);
        assert_eq!(f.span, Span { start: 0, end: 2 });
        assert_eq!(vle(128), alloc::vec![0x80, 0x01]);
    }

    #[test]
    fn msg_put_agrees_field_for_field() {
        let zid = [0xAA, 0xBB, 0xCC, 0xDD];
        // The payload is 200 bytes on purpose: `payload_len` then encodes as a
        // TWO-byte VLE. Every scalar in this module is a candidate for being
        // mis-walked as a fixed-width byte, and a fixture whose every value is
        // below 128 cannot tell the two apart — the first damage probe of this
        // gate passed for exactly that reason. Values that straddle the
        // continuation boundary are what give the gate its teeth.
        let payload = alloc::vec![0x5Au8; 200];
        let bytes = msg_put(
            Some((0x0123_4567, &zid)),
            Some((7, Some("json"))),
            &[ext_zint(0x1, true, 500), ext_zbuf(0x4, false, &[9, 9])],
            &payload,
        );
        let f = agree(
            "MsgPut",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                let m = wz_codecs::msg_put::MsgPut::decode(&mut c).expect("codec rejected fixture");
                // Cross-check the codec's own view while it is in scope.
                assert_eq!(m.payload.len(), 200);
                assert_eq!(m.payload_len, 200);
                assert_eq!(m.timestamp.as_ref().unwrap().time, 0x0123_4567);
                assert_eq!(m.timestamp.as_ref().unwrap().zid, &zid);
                assert_eq!(m.encoding.as_ref().unwrap().schema, Some("json"));
                b.len() - c.remaining()
            },
            walk_msg_put,
        );
        assert_eq!(uint(&f, "payload_len"), 200);
        assert_eq!(raw(&f, "payload"), payload);
        assert_eq!(uint(&f, "time"), 0x0123_4567);
        assert_eq!(raw(&f, "zid"), zid.to_vec());
        assert_eq!(text(&f, "schema"), "json");
        // The encoding's packed id is (7 << 1) | 1 — the walker splits the
        // carrier into id + has_schema, so the split must reproduce 7.
        assert!(matches!(
            f.find("id").map(|x| &x.value),
            Some(FieldValue::Bits(7))
        ));

        // Every sub-codec span re-decodes standalone.
        let ts = f.find("timestamp").unwrap().span;
        span_redecodes(&bytes, ts, |s| {
            let mut c = SceCursor::new(s);
            wz_codecs::timestamp::Timestamp::decode(&mut c)?;
            Ok(s.len() - c.remaining())
        });
        let enc = f.find("encoding").unwrap().span;
        span_redecodes(&bytes, enc, |s| {
            let mut c = SceCursor::new(s);
            wz_codecs::encoding::Encoding::decode(&mut c)?;
            Ok(s.len() - c.remaining())
        });
        let ext = f.find("ext").unwrap().span;
        span_redecodes(&bytes, ext, |s| {
            let mut c = SceCursor::new(s);
            wz_codecs::ext_entry::ExtEntry::decode(&mut c)?;
            Ok(s.len() - c.remaining())
        });
    }

    #[test]
    fn msg_put_agrees_with_every_optional_absent() {
        // The all-flags-clear arm: a walker that unconditionally reads an
        // optional record would consume more than the codec here.
        let bytes = msg_put(None, None, &[], b"");
        let f = agree(
            "MsgPut",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                wz_codecs::msg_put::MsgPut::decode(&mut c).expect("codec rejected fixture");
                b.len() - c.remaining()
            },
            walk_msg_put,
        );
        assert_eq!(uint(&f, "payload_len"), 0);
        assert!(f.find("timestamp").is_none());
        assert!(f.find("encoding").is_none());
    }

    /// R311y582 (A1) — a chain LONGER than the codec's cap must not decode to
    /// a confident wrong answer.
    ///
    /// The generated Z-terminated chain is `for _ in 0..MAX` over a
    /// `HeaplessVec<_, MAX>` (`out/wz-codecs/msg_put.rs:107-119`), so the
    /// `TooManyElements` arm is unreachable and the entry-flag emit carries no
    /// post-loop overflow check (`vendor/sce` generator: the check is dropped
    /// whenever `terminate_on` is `EntryFlag`). A 5th extension therefore ends
    /// the loop on the FOR bound with the 4th entry's Z bit still set, and the
    /// cursor sitting on the 5th extension's header — which the codec then
    /// reads as `payload_len`.
    ///
    /// The fixture is built so the misread SUCCEEDS: the 5th extension's
    /// header byte is `0x03`, a plausible VLE length that fits the bytes left.
    /// So the failure is not an error, it is a Put whose payload is three
    /// bytes that were never the payload. That is the shape a dissector must
    /// never produce, and it is why this is a defect rather than a limit.
    ///
    /// R311y582 (A1) — the walker is told each chain's bound as a constant;
    /// the codec gets it from its container type. This is the gate that keeps
    /// the two from drifting: it reads `N` back OUT of every generated field's
    /// type and compares.
    ///
    /// A regenerated codec at a different `max-depth` reds here, which is the
    /// only warning that matters — a walker bound BELOW the codec's rejects
    /// wire the codec accepts, and one ABOVE it walks into bytes the codec
    /// never read. Neither shows up in any `agree` fixture, because both
    /// parsers are fed chains far shorter than the cap.
    #[test]
    fn the_generated_chain_capacities_match_the_constants() {
        use crate::ext_chain::{NETWORK_EXT_CHAIN_DEPTH, QUERY_EXT_CHAIN_DEPTH};

        /// Recover the const-generic capacity from the field's own type.
        fn cap<const N: usize>(
            _: &Option<sce_forge_runtime::heapless::Vec<wz_codecs::ext_entry::ExtEntry<'_>, N>>,
        ) -> usize {
            N
        }

        // The network layer.
        assert_eq!(
            cap(&wz_codecs::push::Push::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::request::Request::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::response::Response::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::response_final::ResponseFinal::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::oam::Oam::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::interest::Interest::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::declare::Declare::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );

        // The zenoh-payload layer.
        assert_eq!(
            cap(&wz_codecs::msg_put::MsgPut::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::msg_del::MsgDel::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::reply::Reply::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::err::Err::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );

        // The four Declare sub-bodies that carry a chain. The first census for
        // this round missed all four; naming them here is what keeps the next
        // reader from repeating it.
        assert_eq!(
            cap(&wz_codecs::decl_queryable::DeclQueryable::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::undecl_subscriber::UndeclSubscriber::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::undecl_queryable::UndeclQueryable::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );
        assert_eq!(
            cap(&wz_codecs::undecl_token::UndeclToken::default().extensions),
            NETWORK_EXT_CHAIN_DEPTH
        );

        // Query is the odd one out on BOTH axes: a larger depth and the
        // fill-to-end strategy.
        assert_eq!(
            cap(&wz_codecs::query::Query::default().extensions),
            QUERY_EXT_CHAIN_DEPTH
        );
    }

    /// R311y589 — the three rows the entry-flag chain can end on, asserted
    /// against the CODEC and the WALKER together so "the walker mirrors the
    /// codec" is a measurement rather than an inspection of two loops that
    /// look alike.
    ///
    /// R311y582 (A1) wrote this test with two halves: the walker refused and
    /// the codec MISREAD, and the second half was pinned precisely so it would
    /// flip when SCE honoured `on-overflow="reject"`. It flipped (`ec3b032984`),
    /// and this is the post-flip statement.
    ///
    /// | row | chain ends because | cursor | both must answer |
    /// |-----|--------------------|--------|------------------|
    /// | 1 | the cap refused an entry the peer sent | non-empty | `TlvChainOverflow` |
    /// | 2 | the peer's frame ended mid-chain | empty | `NeedMoreBytes` |
    /// | 3 | the wire's own terminator, AT the cap | empty | `Ok`, real payload |
    ///
    /// Row 3 is the CONTROL and it is not decoration: a guard that refused
    /// every chain would satisfy rows 1 and 2 and prove nothing. Row 2 is the
    /// DISCRIMINATOR — a second failure on this path that R311y582's report to
    /// SCE never named, and the one the pre-fix codec answered `Ok` on.
    #[test]
    fn a_chain_past_the_cap_is_refused_rather_than_misread() {
        let cap = crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH;
        let payload = [0xAAu8, 0xBB, 0xCC];

        // ── Row 1: ONE more extension than the cap, derived rather than
        //    written out (the first version hardcoded five and raising the cap
        //    in the same round turned it green while proving nothing). The
        //    terminating entry's id is 3 so its header byte (0x03) is exactly
        //    the VLE the OLD codec mistook for `payload_len` — that choice is
        //    what made the misread SUCCEED with `[0x03, 0xAA, 0xBB]` instead of
        //    running off the end, and it holds at any cap. The bytes after the
        //    chain are the reason this row is `TlvChainOverflow` and not row 2's
        //    `NeedMoreBytes`: the cursor is NOT empty, so the cap is what
        //    refused, not the frame length.
        let mut exts: Vec<Vec<u8>> = (1..=cap).map(|i| ext_unit(i as u8, true)).collect();
        exts.push(ext_unit(0x3, false));
        let over = msg_put(None, None, &exts, &payload);

        let mut w = SpanCursor::new(&over);
        assert_eq!(
            walk_msg_put(&mut w).err(),
            Some(CodecError::TlvChainOverflow),
            "the walker accepted a chain that never terminated inside the bound"
        );
        {
            let mut c = SceCursor::new(&over);
            assert_eq!(
                wz_codecs::msg_put::MsgPut::decode(&mut c).err(),
                Some(CodecError::TlvChainOverflow),
                "the codec misread a saturated chain instead of refusing it"
            );
        }

        // ── Row 2: the chain is the LAST field and its final entry still says
        //    "continue". `Interest` is exactly that shape, which is why it is
        //    the fixture and `MsgPut` is not: on `MsgPut` a short chain is
        //    masked, because reading `payload_len` hits EOF and fails anyway.
        //    Here nothing follows, so before `ec3b032984` the decode reported a
        //    truncated chain as a FINISHED one — `Ok` with three extensions and
        //    an empty cursor. The cap is never reached, so no overflow policy
        //    is in play and the refusal is `NeedMoreBytes`, independently of
        //    `on-overflow`.
        let short = concat(&[
            alloc::vec![0x19u8 | 0x80], // Interest, Z set, no C/F body
            vle(5),
            ext_unit(1, true),
            ext_unit(2, true),
            ext_unit(3, true), // says "continue" — and then the frame ends
        ]);
        assert!(
            short.len() < cap + 5,
            "row 2 must stop BELOW the cap, or it is row 1 in disguise"
        );

        let mut w = SpanCursor::new(&short);
        assert_eq!(
            walk_interest(&mut w).err(),
            Some(CodecError::NeedMoreBytes),
            "the walker reported a truncated chain as a finished one"
        );
        {
            let mut c = SceCursor::new(&short);
            assert_eq!(
                wz_codecs::interest::Interest::decode(&mut c).err(),
                Some(CodecError::NeedMoreBytes),
                "the codec reported a truncated chain as a finished one"
            );
        }

        // ── Row 3, THE CONTROL: the chain fills the cap EXACTLY and the last
        //    entry clears Z, so the wire itself terminated it. The field after
        //    the chain must still read its own bytes. A guard that refused
        //    everything would pass rows 1 and 2 and fail here.
        let exact: Vec<Vec<u8>> = (1..=cap).map(|i| ext_unit(i as u8, i != cap)).collect();
        let ok = msg_put(None, None, &exact, &payload);

        let mut w = SpanCursor::new(&ok);
        let fields = walk_msg_put(&mut w).expect("a chain terminated at the cap must walk");
        let root = group("MsgPut", 0, ok.len(), fields);
        assert_eq!(raw(&root, "payload"), payload.to_vec());
        assert_eq!(w.remaining(), 0, "the walker left bytes unread");
        {
            let mut c = SceCursor::new(&ok);
            let m = wz_codecs::msg_put::MsgPut::decode(&mut c)
                .expect("a chain terminated at the cap must decode");
            assert_eq!(m.extensions.as_ref().map_or(0, |e| e.len()), cap);
            assert_eq!(m.payload, &payload);
            assert_eq!(c.remaining(), 0, "the codec left bytes unread");
        }
    }

    #[test]
    fn push_agrees_including_the_keyexpr_suffix() {
        // N set (suffix present), M set (local mapping), Z set (ext chain).
        let long_suffix = alloc::string::String::from_utf8(alloc::vec![b'k'; 130]).unwrap();
        let bytes = concat(&[
            alloc::vec![0x1Du8 | 0x20 | 0x40 | 0x80],
            wireexpr(300, Some(&long_suffix)),
            ext_zint(0x1, false, 2),
            msg_put(None, None, &[], b"x"),
        ]);
        let f = agree(
            "Push",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                let p = wz_codecs::push::Push::decode(&mut c).expect("codec rejected fixture");
                assert_eq!(p.header, 0x1D | 0x20 | 0x40 | 0x80);
                assert!(b.len() - c.remaining() > 130);
                b.len() - c.remaining()
            },
            walk_push,
        );
        assert_eq!(uint(&f, "id"), 300);
        assert_eq!(text(&f, "suffix"), long_suffix);
        assert_eq!(uint(&f, "suffix_len"), 130);
        assert_eq!(raw(&f, "payload"), b"x".to_vec());
        // The keyexpr's span is the wireexpr's own bytes and nothing else.
        let ke = f.find("keyexpr").unwrap().span;
        span_redecodes(&bytes, ke, |s| {
            let mut c = SceCursor::new(s);
            wz_codecs::wireexpr::Wireexpr::decode(&mut c, 1, 1)?;
            Ok(s.len() - c.remaining())
        });
        // The suffix's own span is 130 bytes wide, so a walker that read the
        // length prefix as a single byte would land 129 bytes short of it.
        assert_eq!(f.find("suffix").unwrap().span.len(), 130);
    }

    #[test]
    fn push_agrees_with_a_del_body_and_no_suffix() {
        let bytes = concat(&[
            alloc::vec![0x1Du8],
            wireexpr(11, None),
            msg_del(Some((42, &[1, 2])), &[]),
        ]);
        let f = agree(
            "Push",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                wz_codecs::push::Push::decode(&mut c).expect("codec rejected fixture");
                b.len() - c.remaining()
            },
            walk_push,
        );
        assert_eq!(uint(&f, "id"), 11);
        assert!(f.find("suffix").is_none());
        assert!(f.find("del").is_some(), "the del arm was not taken");
        assert_eq!(uint(&f, "time"), 42);
    }

    #[test]
    fn request_agrees_with_a_query_body() {
        let params = alloc::vec![b'p'; 150];
        let query = concat(&[
            alloc::vec![0x03u8 | 0x20 | 0x40],
            alloc::vec![0x02u8],
            vle(params.len() as u64),
            params.clone(),
        ]);
        let bytes = concat(&[
            alloc::vec![0x1Cu8 | 0x20],
            vle(9001),
            wireexpr(0, Some("k/e")),
            query,
        ]);
        let f = agree(
            "Request",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                let r = wz_codecs::request::Request::decode(&mut c).expect("codec rejected");
                assert_eq!(r.rid, 9001);
                b.len() - c.remaining()
            },
            walk_request,
        );
        assert_eq!(uint(&f, "rid"), 9001);
        assert_eq!(text(&f, "suffix"), "k/e");
        assert_eq!(uint(&f, "consolidation"), 2);
        assert_eq!(raw(&f, "parameters"), params);
        assert_eq!(uint(&f, "parameters_len"), 150);
    }

    #[test]
    fn response_agrees_with_a_reply_body() {
        let reply = concat(&[
            alloc::vec![0x04u8 | 0x20],
            alloc::vec![0x01u8],
            msg_put(None, None, &[], b"v"),
        ]);
        let bytes = concat(&[
            alloc::vec![0x1Bu8 | 0x20 | 0x40],
            vle(77),
            wireexpr(2, Some("r")),
            reply,
        ]);
        let f = agree(
            "Response",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                let r = wz_codecs::response::Response::decode(&mut c).expect("codec rejected");
                assert_eq!(r.request_id, 77);
                b.len() - c.remaining()
            },
            walk_response,
        );
        assert_eq!(uint(&f, "request_id"), 77);
        assert!(f.find("reply").is_some(), "the reply arm was not taken");
        assert_eq!(raw(&f, "payload"), b"v".to_vec());
    }

    #[test]
    fn response_agrees_with_an_err_body() {
        let err = concat(&[
            alloc::vec![0x05u8 | 0x40],
            encoding(3, None),
            vle(2),
            b"no".to_vec(),
        ]);
        let bytes = concat(&[alloc::vec![0x1Bu8], vle(1), wireexpr(0, None), err]);
        let f = agree(
            "Response",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                wz_codecs::response::Response::decode(&mut c).expect("codec rejected");
                b.len() - c.remaining()
            },
            walk_response,
        );
        assert!(f.find("err").is_some(), "the err arm was not taken");
        assert_eq!(raw(&f, "payload"), b"no".to_vec());
    }

    #[test]
    fn response_final_agrees() {
        let bytes = concat(&[
            alloc::vec![0x1Au8 | 0x80],
            vle(4242),
            ext_unit(0x2, true),
            ext_zint(0x3, false, 1),
        ]);
        let f = agree(
            "ResponseFinal",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                let r = wz_codecs::response_final::ResponseFinal::decode(&mut c)
                    .expect("codec rejected");
                assert_eq!(r.request_id, 4242);
                assert_eq!(r.extensions.as_ref().unwrap().len(), 2);
                b.len() - c.remaining()
            },
            walk_response_final,
        );
        assert_eq!(uint(&f, "request_id"), 4242);
        // Both entries are present and the chain stopped where Z cleared.
        let exts = f.find("extensions").unwrap();
        match &exts.value {
            FieldValue::Nested(v) => assert_eq!(v.len(), 2, "{v:?}"),
            other => panic!("extensions is not nested: {other:?}"),
        }
    }

    #[test]
    fn interest_agrees_with_a_restricted_body() {
        // C set so the body is present; the body's 0x10 restricts it to a
        // keyexpr, and its own 0x20 says that keyexpr carries a suffix.
        let bytes = concat(&[
            alloc::vec![0x19u8 | 0x20],
            vle(5),
            alloc::vec![0x10u8 | 0x20 | 0x01],
            wireexpr(1, Some("z")),
        ]);
        let f = agree(
            "Interest",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                let i = wz_codecs::interest::Interest::decode(&mut c).expect("codec rejected");
                assert_eq!(i.interest_id, 5);
                b.len() - c.remaining()
            },
            walk_interest,
        );
        assert_eq!(uint(&f, "interest_id"), 5);
        assert_eq!(text(&f, "suffix"), "z");
    }

    #[test]
    fn oam_agrees_across_its_three_body_encodings() {
        for (enc, body, label) in [
            (0u8, Vec::new(), "unit"),
            (1u8, vle(300), "zint"),
            (2u8, concat(&[vle(3), alloc::vec![7, 8, 9]]), "zbuf"),
        ] {
            let bytes = concat(&[alloc::vec![0x1Fu8 | (enc << 5)], vle(1), body]);
            let f = agree(
                "Oam",
                &bytes,
                |b| {
                    let mut c = SceCursor::new(b);
                    wz_codecs::oam::Oam::decode(&mut c).expect("codec rejected fixture");
                    b.len() - c.remaining()
                },
                walk_oam,
            );
            assert_eq!(uint(&f, "id"), 1, "{label}");
            if enc == 1 {
                assert_eq!(uint(&f, "value"), 300, "{label}");
            }
            if enc == 2 {
                assert_eq!(raw(&f, "value"), alloc::vec![7, 8, 9], "{label}");
            }
        }
    }

    #[test]
    fn declare_agrees_across_every_sub_mid() {
        // (sub-MID, body bytes, a field the walker must surface)
        let cases: [(u8, Vec<u8>, &str); 9] = [
            (0, concat(&[vle(1), wireexpr(0, Some("a"))]), "suffix"),
            (1, vle(2), "id"),
            (2, concat(&[vle(3), wireexpr(0, Some("b"))]), "suffix"),
            (3, vle(4), "id"),
            (4, concat(&[vle(5), wireexpr(0, Some("c"))]), "suffix"),
            (5, vle(6), "id"),
            (6, concat(&[vle(7), wireexpr(0, Some("d"))]), "suffix"),
            (7, vle(8), "id"),
            (26, Vec::new(), "header"),
        ];
        for (sub_mid, body, must_have) in cases {
            // 0x20 on the sub-header is the wireexpr's N flag for the arms
            // that carry one, and inert for the ones that do not.
            let sub_header = if body.is_empty() {
                sub_mid
            } else {
                sub_mid | 0x20
            };
            let bytes = concat(&[
                alloc::vec![0x1Eu8 | 0x20],
                vle(99),
                alloc::vec![sub_header],
                body,
            ]);
            let f = agree(
                "Declare",
                &bytes,
                |b| {
                    let mut c = SceCursor::new(b);
                    wz_codecs::declare::Declare::decode(&mut c)
                        .unwrap_or_else(|e| panic!("codec rejected sub-MID {sub_mid}: {e:?}"));
                    b.len() - c.remaining()
                },
                walk_declare,
            );
            assert_eq!(uint(&f, "interest_id"), 99, "sub-MID {sub_mid}");
            assert!(
                f.find(must_have).is_some(),
                "sub-MID {sub_mid} did not surface {must_have}: {f:?}"
            );
        }
    }

    #[test]
    fn a_frame_dissects_its_batch_in_capture_coordinates() {
        // Two records in one frame, dissected at a non-zero base so a span
        // that was silently message-relative would land in the wrong place.
        const BASE: usize = 4096;
        let record_a = concat(&[
            alloc::vec![0x1Du8],
            wireexpr(1, None),
            msg_put(None, None, &[], b"aa"),
        ]);
        let record_b = concat(&[alloc::vec![0x1Au8], vle(3)]);
        let payload = concat(&[record_a.clone(), record_b.clone()]);
        let frame = concat(&[alloc::vec![0x05u8 | 0x20], vle(1_000_000), payload.clone()]);

        let f = dissect_transport_message(&frame, BASE).expect("frame did not dissect");
        assert_eq!(f.name, "Frame");
        assert_tiles(&f, BASE, BASE + frame.len());
        assert_eq!(uint(&f, "sn"), 1_000_000);

        // The batch the dissection found must be the batch the decoder finds.
        let decoded = crate::network_message::parse_frame_payload(&payload)
            .expect("the strict batch parse rejected the payload");
        let records = match &f.find("payload").unwrap().value {
            FieldValue::Nested(v) => v.clone(),
            other => panic!("the frame payload was not descended into: {other:?}"),
        };
        assert_eq!(records.len(), decoded.len(), "record count disagrees");
        assert_eq!(records[0].name, "Push");
        assert_eq!(records[1].name, "ResponseFinal");

        // Each record's span is a capture offset that slices back to exactly
        // that record's bytes.
        let header_len = 1 + vle(1_000_000).len();
        assert_eq!(header_len, 4, "a 1e6 sn must occupy a 3-byte VLE");
        assert_eq!(
            records[0].span,
            Span {
                start: BASE + header_len,
                end: BASE + header_len + record_a.len()
            }
        );
        assert_eq!(
            records[1].span,
            Span {
                start: BASE + header_len + record_a.len(),
                end: BASE + frame.len()
            }
        );
        assert_eq!(uint(&records[1], "request_id"), 3);
    }

    #[test]
    fn a_truncated_batch_keeps_what_it_read_and_says_where_it_stopped() {
        let good = concat(&[alloc::vec![0x1Au8], vle(1)]);
        // A Push header with nothing after it: the walk reads one record then
        // runs out of bytes.
        let payload = concat(&[good.clone(), alloc::vec![0x1Du8]]);
        let d = dissect_batch(&payload, 0);
        assert_eq!(d.records.len(), 1, "{d:?}");
        assert!(!d.is_complete());
        assert!(
            matches!(
                d.halt,
                Some(DissectHalt::Error {
                    offset,
                    error: CodecError::NeedMoreBytes
                }) if offset == good.len()
            ),
            "{:?}",
            d.halt
        );
        assert_eq!(d.unparsed_bytes, 1);

        // The best-effort DECODER halts in the same place for the same reason.
        let parsed = crate::network_message::parse_frame_payload_best_effort(&payload);
        assert_eq!(parsed.messages.len(), d.records.len());
        assert_eq!(parsed.unparsed_bytes, d.unparsed_bytes);
    }

    #[test]
    fn the_dissector_and_the_decoder_recognise_the_same_mid_set() {
        // A mechanical set-equality gate rather than a comment claiming the
        // two lists match: for every one of the 32 network MIDs, a build that
        // can DECODE it must be able to DISSECT it and vice versa. Driven off
        // the code, so adding a codec-* arm to one side alone reds this.
        let mut decoder_known = Vec::new();
        let mut dissector_known = Vec::new();
        for mid in 0u8..32 {
            let payload = [mid];
            let parsed = crate::network_message::parse_frame_payload_best_effort(&payload);
            let decodes = !matches!(
                parsed.halt,
                Some(crate::network_message::BatchHalt::UnknownMid { .. })
            );
            let d = dissect_batch(&payload, 0);
            let dissects = !matches!(d.halt, Some(DissectHalt::UnknownMid { .. }));
            if decodes {
                decoder_known.push(mid);
            }
            if dissects {
                dissector_known.push(mid);
            }
        }
        assert_eq!(
            decoder_known, dissector_known,
            "the decoder knows {decoder_known:?} but the dissector knows {dissector_known:?}"
        );
        assert_eq!(
            decoder_known.len(),
            7,
            "the network MID set is 7 wide (PUSH/REQUEST/RESPONSE/RESPONSE_FINAL/DECLARE/INTEREST/OAM), got {decoder_known:?}"
        );
    }

    #[test]
    fn transport_messages_agree_with_parse_inbound() {
        use crate::inbound::{parse_inbound, InboundFrame};

        // INIT-ACK: A and S set, a 4-byte zid, a cookie.
        let zid = [0xA0u8, 0xA1, 0xA2, 0xA3];
        let cookie = [0xC0u8, 0xC1];
        let cbyte = (((zid.len() - 1) as u8) << 4) | 0x01;
        let init = concat(&[
            alloc::vec![0x01u8 | 0x20 | 0x40],
            alloc::vec![0x09u8, cbyte],
            zid.to_vec(),
            alloc::vec![0x00u8, 0x00, 0x10],
            vle(cookie.len() as u64),
            cookie.to_vec(),
        ]);
        let f = dissect_transport_message(&init, 0).expect("init did not dissect");
        assert_eq!(f.name, "Init");
        assert_tiles(&f, 0, init.len());
        assert_eq!(f.span.end, init.len(), "the walk left bytes unread");
        assert_eq!(raw(&f, "zid"), zid.to_vec());
        assert_eq!(raw(&f, "cookie"), cookie.to_vec());
        assert_eq!(uint(&f, "batch_size"), 0x1000);
        match parse_inbound(&init).expect("parse_inbound rejected the init") {
            InboundFrame::Init { body, is_ack, .. } => {
                assert!(is_ack);
                assert_eq!(body.zid.as_ref(), &zid);
                assert_eq!(body.batch_size, Some(0x1000));
                assert_eq!(body.cookie.as_ref().map(|c| c.as_ref()), Some(&cookie[..]));
            }
            other => panic!("not an Init: {other:?}"),
        }

        // OPEN-SYN: A clear, so the cookie is present.
        let open = concat(&[
            alloc::vec![0x02u8],
            vle(10_000),
            vle(1),
            vle(cookie.len() as u64),
            cookie.to_vec(),
        ]);
        let f = dissect_transport_message(&open, 0).expect("open did not dissect");
        assert_eq!(f.name, "Open");
        assert_tiles(&f, 0, open.len());
        assert_eq!(uint(&f, "lease"), 10_000);
        assert_eq!(uint(&f, "initial_sn"), 1);
        assert_eq!(raw(&f, "cookie"), cookie.to_vec());

        // CLOSE with a trailing ext chain — the ext chain follows the body
        // for every MID except FRAME / FRAGMENT, which read theirs first.
        let close = concat(&[alloc::vec![0x03u8 | 0x80, 0x02], ext_zint(0x1, false, 6)]);
        let f = dissect_transport_message(&close, 0).expect("close did not dissect");
        assert_eq!(f.name, "Close");
        assert_tiles(&f, 0, close.len());
        assert_eq!(uint(&f, "reason"), 2);
        match parse_inbound(&close).expect("parse_inbound rejected the close") {
            InboundFrame::Close {
                reason, extensions, ..
            } => {
                assert_eq!(reason, 2);
                assert_eq!(extensions.len(), 1);
            }
            other => panic!("not a Close: {other:?}"),
        }

        // KEEP_ALIVE — an empty body, so the whole message is its header.
        let ka = [0x04u8];
        let f = dissect_transport_message(&ka, 0).expect("keepalive did not dissect");
        assert_eq!(f.name, "KeepAlive");
        assert_tiles(&f, 0, 1);

        // FRAGMENT — the payload is NOT descended into: it is a slice of a
        // message that does not begin there.
        let frag = concat(&[
            alloc::vec![0x06u8 | 0x20 | 0x40],
            vle(3),
            alloc::vec![0xDE, 0xAD],
        ]);
        let f = dissect_transport_message(&frag, 0).expect("fragment did not dissect");
        assert_eq!(f.name, "Fragment");
        assert_tiles(&f, 0, frag.len());
        assert_eq!(uint(&f, "sn"), 3);
        assert_eq!(raw(&f, "payload"), alloc::vec![0xDE, 0xAD]);
        assert!(
            matches!(
                f.find("payload").map(|x| &x.value),
                Some(FieldValue::Bytes(_))
            ),
            "a fragment payload must stay raw"
        );
    }

    #[test]
    fn to_json_round_trips_through_serde_when_the_feature_is_on() {
        let bytes = msg_put(None, None, &[], b"j");
        let mut c = SpanCursor::new(&bytes);
        let fields = walk_msg_put(&mut c).unwrap();
        let f = group("MsgPut", 0, c.offset(), fields);

        // The serde-free path is always available.
        let json = to_json(&f);
        assert!(json.contains(r#""name":"payload""#), "{json}");
        assert!(json.contains(r#""value":"6a""#), "{json}");

        #[cfg(feature = "dissect-serde")]
        {
            let encoded = serde_json::to_string(&f).expect("serde could not serialize a Field");
            let back: Field = serde_json::from_str(&encoded).expect("serde could not read it back");
            assert_eq!(back, f);
        }
        // Without the feature the assertion above is not compiled, so say so
        // rather than letting a green run read as though it had been checked.
        #[cfg(not(feature = "dissect-serde"))]
        {
            assert!(
                !json.is_empty(),
                "the serde-free JSON path is the only one this build compiled"
            );
        }
    }

    /// The whole best-effort outcome — halt included — survives a serde round
    /// trip, which is what exercises the hand-written `CodecError` mapping.
    /// A derive alone would have failed to compile against
    /// `sce_forge_runtime`'s enum; the round trip proves the mapping is also
    /// correct in both directions.
    #[cfg(feature = "dissect-serde")]
    #[test]
    fn a_halted_dissection_round_trips_including_its_error() {
        let payload = concat(&[alloc::vec![0x1Au8], vle(1), alloc::vec![0x1Du8]]);
        let d = dissect_batch(&payload, 0);
        assert!(matches!(
            d.halt,
            Some(DissectHalt::Error {
                error: CodecError::NeedMoreBytes,
                ..
            })
        ));
        let encoded = serde_json::to_string(&d).expect("serde could not serialize the dissection");
        assert!(encoded.contains("NeedMoreBytes"), "{encoded}");
        let back: BatchDissection =
            serde_json::from_str(&encoded).expect("serde could not read it back");
        assert_eq!(back, d);
    }

    /// R311y585 (A6) — Scout and Hello walk, and the two are told apart by a
    /// MID space that OVERLAPS the transport one.
    ///
    /// `0x01` is `Scout` here and `Init` there, and the codecs will happily
    /// decode a scouting datagram as a transport message: nothing errors, the
    /// wrong tree appears. That is why `dissect_scouting_message` is a
    /// separate entry point rather than another arm on the transport walk,
    /// and this leg pins the distinction by feeding the SAME bytes to both.
    #[test]
    fn scouting_messages_walk_and_do_not_share_the_transport_mid_space() {
        // Scout: header 0x01, version 0x09, cbyte = what(1) | I | zid_len_m1(3),
        // then a 4-byte zid.
        let cbyte = 0x01 | 0x08 | (3 << 4);
        let wire = alloc::vec![0x01u8, 0x09, cbyte, 0xAA, 0xBB, 0xCC, 0xDD];
        let f = dissect_scouting_message(&wire, 0)
            .expect("walker")
            .expect("0x01 is a scouting MID");
        assert_eq!(f.name, "Scout");
        assert_eq!(uint(&f, "version"), 0x09);
        assert_eq!(raw(&f, "zid"), alloc::vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert_tiles(&f, 0, wire.len());

        // The SAME bytes handed to the transport dispatcher decode as an
        // Init — a confident wrong answer, which is the whole reason the two
        // spaces need separate entry points.
        let as_transport = dissect_transport_message(&wire, 0);
        assert!(
            as_transport.is_ok(),
            "the transport walk is expected to ACCEPT these bytes, wrongly"
        );
        assert_ne!(as_transport.expect("transport").name, "Scout");
    }

    /// Hello's locator list is gated by a flag on the HEADER byte, not by
    /// anything in the body — so the walker takes it as a parameter, and a
    /// header without `L` must not consume the bytes that follow.
    #[test]
    fn hello_reads_its_locator_list_only_when_the_header_says_so() {
        let cbyte = 0x01 | (3 << 4); // whatami=1, zid_len_m1=3
        let mut with_l = alloc::vec![0x02u8 | 0x20, 0x09, cbyte, 1, 2, 3, 4];
        with_l.push(1); // num_locators
        with_l.push(3); // locator_len
        with_l.extend_from_slice(b"tcp");
        let f = dissect_scouting_message(&with_l, 0)
            .expect("walker")
            .expect("0x02 is a scouting MID");
        assert_eq!(f.name, "Hello");
        assert_eq!(uint(&f, "num_locators"), 1);
        assert_eq!(text(&f, "locator"), "tcp");
        assert_tiles(&f, 0, with_l.len());

        // Same body, L clear: the walk stops after the zid and the trailing
        // bytes are NOT read as locators.
        let without_l = alloc::vec![0x02u8, 0x09, cbyte, 1, 2, 3, 4, 1, 3, b't'];
        let g = dissect_scouting_message(&without_l, 0)
            .expect("walker")
            .expect("scouting MID");
        assert!(g.find("num_locators").is_none());
        assert_eq!(g.span.end, 7, "the walk must stop after the zid");
    }

    /// A byte that is not a scouting MID is an ABSENCE, not a failure — the
    /// caller decides what those bytes were.
    #[test]
    fn a_non_scouting_mid_is_reported_as_absence() {
        assert_eq!(dissect_scouting_message(&[0x1F, 0x00], 0), Ok(None));
    }
}

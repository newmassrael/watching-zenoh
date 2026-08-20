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
    /// What a carrier byte's bits MEAN, resolved from a table this build holds
    /// rather than read off the wire. ALIASES the carrier's span, like
    /// [`Bits`](FieldValue::Bits) and [`Flag`](FieldValue::Flag), and for the
    /// same reason: the bytes belong to a field that already claims them.
    ///
    /// Distinct from `Bits` because it is a DERIVED reading and a consumer is
    /// entitled to know which of the two it has — an id is what the sender
    /// wrote, a label is what this build makes of it, and a later build may
    /// name what this one could not. Distinct from
    /// [`Text`](FieldValue::Text) because that is UTF-8 the decode VALIDATED
    /// out of the wire; nothing about a label came from the wire but the bits
    /// it was looked up from.
    ///
    /// `Cow` for the reason [`Field::name`] is one: `Deserialize` cannot borrow
    /// a `&'static str`. Every producer hands in a `&'static str`, so the
    /// producing path allocates nothing.
    Label(Cow<'static, str>),
}

impl FieldValue {
    /// `true` when this value was decoded from bytes another field already
    /// claims, so its span must not be counted toward the tiling.
    pub fn is_alias(&self) -> bool {
        matches!(
            self,
            FieldValue::Bits(_) | FieldValue::Flag(_) | FieldValue::Label(_)
        )
    }
}

/// One named field of a dissected message, with the bytes it came from.
///
/// # The field-name vocabulary, and where each name comes from
///
/// R311y595. A consumer that RENDERS the tree needs none of this — the JSON
/// shape (`name` / `start` / `end` / `kind` / `value`, recursively) is closed and
/// a new walker cannot change it. A consumer that LOOKS A NAME UP does, because
/// then it is depending on a specific string, and the three sources those
/// strings come from have very different stability:
///
/// | source | count | who decides |
/// |---|---:|---|
/// | a generated codec's struct field | 50 | the wire spec, via `out/wz-codecs` |
/// | zenoh's own flag letters and variant names | 27 | the wire spec |
/// | **wz's own vocabulary** | **26** | **this crate** |
///
/// Only the third is a wz decision, and it is enumerated here so that keying on
/// one is an informed choice rather than an accident. `scripts/lib/`
/// `dissect_name_census.py` holds the same three sets and FAILS Layer C0 if a
/// walker invents a name outside them, if a codec field goes unwalked without a
/// declared reason, or if either allowlist goes stale.
///
/// The twenty-six, with why each is not simply the codec's name:
///
/// * `hdr` — a nested record's header byte, where the codec's field is `header`
/// * `ext` — one entry of an extension chain; the codec models the chain
/// * `ext_id` — the extension id bits, split out of the entry header: the FOUR
///   bits zenoh's `iext::ID_MASK` gives it, not the five a `& 0x1F` reads
/// * `ext_name` — what the entry's eid MEANS in the carrier it was read from
///   ([`crate::ext_name`]). Not a codec field and not read off the wire — a table
///   lookup, which is why it is a [`Label`](FieldValue::Label) rather than
///   [`Text`](FieldValue::Text), and why it is ABSENT rather than guessed when the
///   carrier declares no such extension
/// * `mapping` — zenoh-protocol's `WireExpr::mapping`; wz's codec encodes it as
///   the local/nonlocal variant TAG rather than as a field
/// * `has_schema` — the packed encoding's bit 0, surfaced as a flag
/// * `zid_len_m1` — the zid length is stored minus one, and the name says what
///   the bytes hold rather than what they mean
/// * `locator_entry` — one locator record. **Not** `locator`: [`Field::find`] is
///   first-match-by-name, so a group sharing its leaf's name shadows it (R311y585)
/// * `keyexprs` / `subscribers` / `queryables` / `tokens` — the Declare body's
///   four groups
/// * `current` / `future` — Interest mode bits
/// * `restricted` — an Interest options bit
/// * `what` — Scout's what-am-I-looking-for bits
/// * `rest` — trailing bytes a walker read but does not name further
/// * `unparsed` — bytes after a halt; the best-effort marker, not a wire field
/// * `shm_descriptor` — the `Put` / `Err` payload slot when the body ext chain
///   carries the SHM marker. **Not** `payload`, and the split is the point:
///   the codec's field IS the payload, these bytes are an ADDRESS, and sharing
///   one name is exactly what let a reader take one for the other (R311y597)
/// * `linkstate` — an OAM ZBuf body walked as a `LinkstateList`; the codec
///   names the body `value`, and only the OAM id says which body it is
/// * `linkstate_entry` — one `Linkstate` record, held apart from the
///   `link_states` aggregate by the same shadowing rule as `locator_entry`
/// * `source_info` / `responder_id` / `query_body` / `wire_expr` / `qos` /
///   `shm` — the `ExtZbuf` bodies [`walk_ext_zbuf_body`] reads. On `linkstate`'s
///   rule: the codec models an extension body as `value`, and only the carrier
///   plus the eid says which structure those bytes hold
/// * `eid` — the entity id inside `source_info` / `responder_id`. No generated
///   codec in this tree declares it; both bodies are hand-encoded
/// * `priority_sn` / `priority` — one row of `Join`'s `qos` table and which
///   priority it is. The row is upstream's own `PrioritySn`; the priority is
///   POSITIONAL, so it is emitted from the index rather than read off the wire
/// * `alice_segment` / `alice_challenge` / `bob_segment` — the establishment
///   `shm` handshake's fields, named as upstream's own `InitSyn` / `InitAck`
///   structs name them; no generated codec in this tree declares them
///
/// ⚠ Two codec fields have no walker and are carried by name in the census.
/// R311y597 closed nine of the eleven at once by landing the `linkstate`
/// walker — the census's stale-declaration rule FORCED them out rather than
/// leaving them to be noticed, which is the behaviour it was built for.
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

/// A table-resolved reading of `carrier`'s bits, aliasing its span.
fn label(name: &'static str, carrier: Span, value: &'static str) -> Field {
    Field {
        name: name.into(),
        span: carrier,
        value: FieldValue::Label(Cow::Borrowed(value)),
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

    /// Read a base-128 VLE field that REFUSES a value wider than 16 bits —
    /// upstream's `Zenoh080Bounded<u16>` shape.
    ///
    /// R311y597 introduced it for `LinkstateWeight.weight` on the rule that a
    /// dissector must not accept what its own codec rejects. The rule is
    /// right; the premise under it was not. That codec's refusal was itself
    /// the defect — upstream reads a weight on the PLAIN `Zenoh080`
    /// (`zenoh/src/net/codec/linkstate.rs:125`), which truncates — so R311y880
    /// moved the field to [`Self::vle_u16_truncated`] on both sides of the
    /// codegen boundary at once.
    ///
    /// It therefore has NO call site in this tree today, and that is a
    /// measured statement rather than an oversight: `Zenoh080Bounded<u16>` is
    /// a real upstream shape (its `u32` sibling decides `Encoding.id`), so the
    /// primitive stays for the field that selects it next. A new call site is
    /// not free — `scripts/lib/narrow_vle_read_census.py` reds until someone
    /// names the upstream codec that decides that field.
    pub fn vle_u16(&mut self, name: &'static str) -> Result<(u16, Field), CodecError> {
        let start = self.offset();
        let v = self.cur.read_vle_u16()?;
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

    /// Read a base-128 VLE field whose WIRE width is a full zint but whose
    /// VALUE width is 16 bits — the OAM `id` in both namespaces (R311y879) and
    /// the linkstate `weight` (R311y880).
    ///
    /// The third reader rather than a flag on one of the two above, because
    /// these fields agree with NEITHER. [`Self::vle_u16`] refuses a wide
    /// encoding, which is a message stock zenoh reads to the end, and stops
    /// INSIDE the varint while doing it; [`Self::vle_u64`] renders the wide
    /// value, which is a number no peer computes. Upstream does the third
    /// thing — reads the zint whole and keeps its low 16 bits
    /// ([`wz_codecs::wire_const::zint_as_u16`]) — so the span covers every wire
    /// byte while the rendered value is what the receiving peer will act on.
    ///
    /// It reads the SHAPE, not a field: which field's name applies is the
    /// caller's knowledge, which is why the two per-field accessors
    /// (`oam_id_from_wire`, `linkstate_weight_from_wire`) live beside the shape
    /// rather than being called from here.
    pub fn vle_u16_truncated(&mut self, name: &'static str) -> Result<(u16, Field), CodecError> {
        let start = self.offset();
        let v = wz_codecs::wire_const::zint_as_u16(self.cur.read_vle_u64()?);
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

    /// The bytes left, WITHOUT consuming them.
    ///
    /// What a walker needs when the SHAPE of a body is decided by counting its
    /// records before naming them — [`walk_pubkey_challenge_body`] reads one,
    /// two or three ZBufs and each count is a different stage of the same
    /// handshake, so the names cannot be chosen until the count is known.
    /// Peeking is what lets that decision be made without a second cursor that
    /// could disagree with this one about where the body ends.
    fn peek_rest(&self) -> Result<&[u8], CodecError> {
        self.cur.peek_slice(self.cur.remaining())
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

/// Whether a walked extension chain carried an entry with the given id.
///
/// Reads the walker's OWN output rather than re-parsing the bytes, and looks
/// only at the chain's DIRECT entries — deliberately not [`Field::find`],
/// which is first-match-by-name across the whole subtree and would happily
/// match a field nested inside something else.
///
/// Matches on the EID — the header with only the chain flag dropped, so the
/// mandatory and encoding bits are part of it — and not on the 4-bit id. That
/// is [`crate::ext_header::ext_eid`]'s whole reason for existing (R311y505): two
/// different extensions may share an id and be told apart by their encoding, so
/// matching a capability by id alone accepts an UNRELATED extension as the one
/// asked for. The aggregation layer already matched this way
/// (`wz-capture/src/agg.rs`, `ext_eid(body_ext_id::SHM | EXT_FLAG_M)`); this
/// function is what brought the field layer into agreement with it.
fn chain_carries_ext_eid(chain: &[Field], eid: u8) -> bool {
    chain.iter().any(|entry| match &entry.value {
        FieldValue::Nested(leaves) => leaves.iter().any(|f| {
            f.name == "header"
                && match &f.value {
                    FieldValue::Uint(raw) => crate::ext_header::ext_eid(*raw as u8) == eid,
                    _ => false,
                }
        }),
        _ => false,
    })
}

/// The `Put` / `Err` payload slot, which is NOT always a payload.
///
/// R311y597 — when the body ext chain carries the SHM marker
/// ([`crate::ext_header::body_ext_id::SHM`]) the sender put a DESCRIPTOR here
/// in place of the data, and the data itself never traversed the network.
/// Rendering those bytes as `payload` made a reader take an address for
/// content, which is precisely the misreading this module exists to prevent —
/// and it is worse than showing nothing, because nothing is visibly nothing.
///
/// The interior is deliberately NOT walked, and that is a decision rather than
/// a gap this round ran out of time for. TWO INCOMPATIBLE LAYOUTS reach this
/// slot and nothing on the wire discriminates them: wz emits its own scoped
/// `VLE(length) VLE(segment_id) VLE(generation)`
/// (`extshm::encode_shm_descriptor`, live from `push_build.rs`), while stock
/// zenoh emits a `ShmBufInfo` carrying a `MetadataDescriptor` plus a
/// `ChunkDescriptor`. ANY bytes parse as three VLEs, so guessing wz's layout
/// on zenoh's traffic would emit confident wrong fields — the same defect
/// wearing a different name. [`FieldValue::Opaque`] states what is true: the
/// span is accounted for and the interior was not broken down.
/// The SHM marker's full identity, as stock zenoh puts it on the wire:
/// `zenoh::put::ext::Shm` / `zenoh::err::ext::Shm` are `zextunit!(0x2, true)`,
/// so the byte is the id, the MANDATORY flag, and the `Unit` encoding — `0x12`.
///
/// Written as the composition rather than as `0x12` so the three facts it is
/// made of stay legible, and derived through
/// [`ext_eid`](crate::ext_header::ext_eid) so it is a comparison key rather than
/// a byte that happens to match one. The bare id `0x02` — which is what the
/// field layer used to look for, and what both of its witnesses used to build —
/// is a DIFFERENT extension identity that stock zenoh never sends here.
const SHM_MARKER_EID: u8 = crate::ext_header::ext_eid(
    crate::ext_header::body_ext_id::SHM
        | crate::ext_header::EXT_FLAG_M
        | crate::ext_header::EXT_ENC_UNIT,
);

fn payload_or_shm_descriptor(
    c: &mut SpanCursor<'_>,
    n: usize,
    is_shm: bool,
) -> Result<Field, CodecError> {
    if is_shm {
        let (_, field) = c.opaque("shm_descriptor", |cur| {
            cur.peek_slice(n)?;
            cur.advance(n)
        })?;
        Ok(field)
    } else {
        c.bytes("payload", n)
    }
}

/// `ExtEntry` — a TLV entry: one header byte then the body its encoding
/// selects.
///
/// # The header byte's four fields, and the one this walker used to get wrong
///
/// zenoh's `iext` (`commons/zenoh-protocol/src/common/extension.rs`) splits the
/// byte four ways: the id in bits 0..3 (`ID_MASK = 0x0F`, four bits and no
/// more), the MANDATORY flag in bit 4 (`FLAG_M`), the 2-bit body encoding in
/// bits 5..6, and the chain continuation in bit 7.
///
/// This walker reported `header & 0x1F` under the name `ext_id`, folding the
/// mandatory flag into the id, and never surfaced that flag as a field at all.
/// Both halves of that were live defects rather than cosmetic ones:
///
/// * Every MANDATORY extension came out `0x10` too high — `NodeId` (`0x3`) read
///   as `19`, `WireExprExt` (`0x0f`) as `31`.
/// * `zenoh::put::ext::Shm` is `zextunit!(0x2, true)`, so the marker whose whole
///   job is to say "the payload slot holds an ADDRESS, not the data" is `0x12`
///   on the wire. The SHM check compared the mis-masked id against a bare
///   `0x02` and therefore never matched real traffic, so
///   [`payload_or_shm_descriptor`] called the descriptor a `payload` — exactly
///   the misreading R311y597 closed, reopened by the layer below it. Both
///   existing witnesses built the marker as `0x02`, a byte stock zenoh never
///   sends, so the fixtures agreed with the mistake.
/// * The mandatory bit is what the R311y630 admission rule
///   ([`crate::ext_admit`]) turns on, so a reader could not see the input to a
///   decision the participant seam makes.
///
/// # Why the CARRIER is a parameter
///
/// An extension id means nothing without the chain it was read from —
/// [`crate::ext_header::body_ext_id`] states that rule in prose, and the field
/// layer was the one consumer that could not act on it because it walked every
/// chain through one context-free function. `0x3` is `NodeId` on a `Push`,
/// `ResponderId` on a `Response`, `Attachment` on a `Put`, the VALUE on a
/// `Query` and `Auth` on an `Init`. With the carrier in hand the entry carries
/// an `ext_name` ([`crate::ext_name`]), so a reader is told `timeout` instead of
/// being handed `ext_id 6` and left to look it up.
///
/// An id the carrier does not declare gets NO `ext_name` field rather than a
/// guessed one; see [`crate::ext_name::ext_name`] for why that is the ordinary
/// answer in a chain and not the error case.
pub fn walk_ext_entry(
    c: &mut SpanCursor<'_>,
    carrier_kind: crate::ext_name::ExtCarrier,
) -> Result<(bool, Field), CodecError> {
    let start = c.offset();
    let (header, header_field) = c.u8("header")?;
    let carrier = header_field.span;
    let z = (header & crate::ext_header::EXT_FLAG_Z) != 0;
    let enc = (header >> 5) & 0x03;
    let mut fields = alloc::vec![
        header_field,
        bits("ext_id", carrier, crate::ext_header::ext_id(header) as u64),
        flag("m", carrier, crate::ext_header::ext_mandatory(header)),
        bits("encoding", carrier, enc as u64),
        flag("z", carrier, z),
    ];
    if let Some(name) = crate::ext_name::ext_name(carrier_kind, header) {
        fields.push(label("ext_name", carrier, name));
    }
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
            let at = c.offset();
            let value = c.bytes("value", n as usize)?;
            let walked = match &value.value {
                FieldValue::Bytes(raw) => walk_ext_zbuf_body(carrier_kind, header, raw, at),
                _ => None,
            };
            fields.push(walked.unwrap_or(value));
        }
        _ => {}
    }
    Ok((z, group("ext", start, c.offset(), fields)))
}

/// The ZBuf extension bodies this build can READ, walked into their fields
/// instead of left as an opaque `value`.
///
/// # The gap this closes
///
/// R311y890. [`crate::ext_name`] made the field layer able to NAME an
/// extension — a reader is told `source_info` instead of `ext_id 1`. It could
/// not READ one: every `ExtZbuf` body, whatever it was, came back as
/// `value: <hex>`. So the surface told a reader precisely which structure it
/// was looking at and then handed over the bytes of it, which is a stranger
/// state than not knowing at all. A `source_info` is where the ORIGIN of a
/// sample is — the publisher's zid, its entity id, its sequence number — and
/// on the analysis surface that is not a detail of the extension, it is the
/// answer to "who sent this".
///
/// # Why exactly these twelve, and not the others
///
/// A walker here is a second implementation of a layout, so it is written only
/// where this tree already holds the FIRST one and a test can judge the two
/// against each other:
///
/// | body | the layout's SSOT in this tree |
/// |---|---|
/// | `source_info` | [`crate::source_info_ext::encode_source_info_ext_body`] |
/// | `responder_id` | [`crate::response_build::encode_responder_ext_body`] |
/// | `query_body` | [`crate::query_value_ext::encode_query_value_ext_body`] |
/// | `wire_expr` | [`crate::declare_ext_keyexpr::build_ext_keyexpr`] |
/// | `timestamp` | the generated `Timestamp` codec, via [`walk_timestamp`] |
/// | `qos` (Join) | `crate::multicast_join::write_join_qos_ext` |
/// | `shm` (Init) | `crate::extshm::encode_shm_init_syn_body` / `..._ack_body` |
///
/// | `auth` (Init / Open) | `crate::auth_dispatch::AuthDispatch::mux`, via [`walk_auth_body`] |
/// | `usrpwd` (Auth) | `crate::extauth_usrpwd`'s `encode_open_syn` |
/// | `pubkey` (Auth) | `wz-runtime-tokio`'s `extauth_pubkey` `encode_init_syn` / `..._ack` / `..._open_syn` |
/// | `multi_link` (Init) | the same, `.transmute()`d onto `0x4` by `crate::extmultilink` |
/// | `multi_link_syn` (Open) | the `Open` half of that transmute |
///
/// The ZBuf rows that stay `value` are not an oversight, and since R311y896
/// their reasons are NOT written here. They live one per row in
/// `dissect::tests`'s `OPAQUE_ZBUF_BODIES`, which a sweep holds against
/// [`zbuf_body_walker`] in both directions — because this paragraph is exactly
/// what went stale, three rows out of three, and a reason nothing reads is a
/// reason nothing can contradict.
///
/// ⚠ R311y894 — that last reason used to cover THREE rows, and for two of them
/// it was false. `Join`'s ZBuf `qos` has been written by
/// `crate::multicast_join::write_join_qos_ext` since R311y227 and read back by
/// `decode_join_qos`; the establishment `shm` has been written by
/// `crate::extshm` for as long as `session-extshm` has existed. Both met the
/// rule and were excluded anyway, so the most ordinary multicast question a
/// capture is opened to answer — which per-priority SN is each peer announcing
/// — came back as hex. A false reason does not merely fail to close a gap; it
/// points at the wrong side of it, and this one pointed at upstream while the
/// producers sat two modules away.
///
/// ⚠⚠ R311y896 — and the THIRD row was false as well, so the reason was wrong
/// about every row it was written for. `auth` was called "the negotiated
/// method's challenge bytes", which is what a method's sub-ext holds and NOT
/// what the extension carries: the `0x3` body is an ext CHAIN keyed by method
/// id, written here by `crate::auth_dispatch::AuthDispatch::mux` and read back
/// by its `demux`, and read upstream as a `Vec<ZExtUnknown>`. That is the one
/// structure this module already had a walker for, so the row was excluded for
/// being opaque while being the least opaque of them. The lesson the two
/// rounds share: a reason of the form "X is opaque" describes the body one
/// level DOWN from the one it was filed against, and nothing checks which
/// level a sentence is about.
///
/// ⚠⚠⚠ R311y897 — and the level below THAT one was the same story. The four
/// remaining rows excused as "the METHOD's own format, not the protocol's"
/// (`usrpwd`, `pubkey`, and the two `multi_link` halves that carry pubkey's
/// bytes under another id) were each a sequence of [`crate::vle::write_zbuf`]
/// records with a producer and a consumer in this tree. The sentence was true
/// of what is INSIDE those records — an HMAC tag, an RSA modulus — and was
/// filed against the framing around them, which is the identical mistake one
/// level further down. The sweep below now covers these rows too, so the
/// remaining opaque set is `Join`'s producer-less `shm` and the three
/// `attachment` rows, whose bytes really are structureless by contract.
///
/// # Declining, rather than failing
///
/// A body that does not walk cleanly comes back as `None` and the caller keeps
/// the raw `value`. Two shapes decline, and the second is the one a length
/// check alone misses: a body too short for what it announces, and a body that
/// parses whole and leaves bytes over. Both mean "not the structure this build
/// thought", and neither may kill the envelope around it — the rule
/// [`walk_oam`]'s linkstate body established (R311y597).
fn walk_ext_zbuf_body(
    carrier_kind: crate::ext_name::ExtCarrier,
    header: u8,
    body: &[u8],
    base: usize,
) -> Option<Field> {
    let name = crate::ext_name::ext_name(carrier_kind, header)?;
    let (group_name, walk) = zbuf_body_walker(carrier_kind, name)?;
    let end = base + body.len();
    let mut c = SpanCursor::with_base(body, base);
    let fields = walk(&mut c).ok()?;
    if c.remaining() != 0 {
        return None;
    }
    Some(group(group_name, base, end, fields))
}

/// One ZBuf body walker: the cursor in, its fields out. Every walker below
/// shares it, which is what lets [`zbuf_body_walker`] be a lookup.
type ZbufBodyWalker = fn(&mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError>;

/// One dispatch hit — the group name the body is filed under, and the walker.
///
/// A FUNCTION rather than a bare tuple, and that is not style. The field-name
/// census (`scripts/lib/dissect_name_census.py`) reads this crate's field
/// vocabulary out of `name("literal"` call shapes; written as tuples, the eight
/// group names below would vanish from the gate that exists to decide them —
/// measured, when this dispatch was first split out of the walk.
const fn walked(name: &'static str, walk: ZbufBodyWalker) -> (&'static str, ZbufBodyWalker) {
    (name, walk)
}

/// The two carriers that run an establishment handshake, and therefore the two
/// that declare the `0x3` auth extension (`init.rs:156` / `open.rs:121`).
///
/// Named rather than spelled inline so the arm it guards fits one line, which
/// is what the census's arm-provenance rule can see.
const fn is_establishment(carrier: crate::ext_name::ExtCarrier) -> bool {
    matches!(
        carrier,
        crate::ext_name::ExtCarrier::Init | crate::ext_name::ExtCarrier::Open
    )
}

/// The walker this build has for one ZBuf row, and the group name it files the
/// result under — or `None` when the row is deliberately left an opaque
/// `value`.
///
/// # Why the dispatch is a VALUE and not a `match` inside the walk
///
/// R311y896, open-debt item 389. Which rows stay opaque, and why, used to be a
/// prose paragraph beside the `match` — and the paragraph was wrong about
/// every row it named. R311y894 found two of the three false and this round
/// found the third; each had stood for hundreds of rounds, because a sentence
/// beside an arm is not read by anything.
///
/// Split out, the dispatch is something a test can ASK, without having to hand
/// it a body the layout would accept: `dissect::tests`'s
/// `every_zbuf_row_is_either_walked_or_declared_opaque` sweeps every ZBuf row
/// `crate::ext_name` declares and requires each to be walked here XOR listed in
/// that test's `OPAQUE_ZBUF_BODIES` with a reason. So an upstream row nobody
/// decided about reds, and — the shape this class actually fails in — a row
/// that GAINS a walker while the "it is opaque because…" entry still stands
/// reds too, on the round the walker lands rather than three hundred later.
///
/// # The two spellings that are load-bearing
///
/// Every arm names its group with a LITERAL so the field-name census
/// (`scripts/lib/dissect_name_census.py`) can see it. Resolving the group name
/// from `ext_name`'s return value would be shorter and would make eight names
/// invisible to the gate that exists to decide them.
///
/// R311y893 (open-debt item 376) — the MATCHED name is `crate::ext_name`'s own
/// constant, not a second spelling of it. The two sides are a contract between
/// modules and the compiler could not see it: renaming a row left the arm
/// unmatched and the body quietly back to `value`. The group name beside it
/// stays a literal, because that half belongs to the field vocabulary rather
/// than to the table.
fn zbuf_body_walker(
    carrier_kind: crate::ext_name::ExtCarrier,
    name: &str,
) -> Option<(&'static str, ZbufBodyWalker)> {
    let hit: (&'static str, ZbufBodyWalker) = match name {
        crate::ext_name::SOURCE_INFO => walked("source_info", walk_source_info_body),
        crate::ext_name::RESPONDER_ID => walked("responder_id", walk_responder_id_body),
        crate::ext_name::QUERY_BODY => walked("query_body", walk_query_value_body),
        crate::ext_name::WIRE_EXPR => walked("wire_expr", walk_ext_wireexpr_body),
        crate::ext_name::TIMESTAMP => walked("timestamp", walk_timestamp),
        // R311y894 — the ONE arm that needs the carrier as well as the name.
        // `qos` names ten rows of `ext_name`'s table and nine of them are a
        // UNIT marker or a Z64 word, which never reach this function; the
        // guard is therefore redundant TODAY and load-bearing the day an
        // eleventh row arrives, which is the same reason the eid rather than
        // the bare id is the table's key.
        crate::ext_name::JOIN_QOS if carrier_kind == crate::ext_name::ExtCarrier::Join => {
            walked("qos", walk_join_qos_body)
        }
        // R311y894 — and here the guard is load-bearing TODAY: `Join` declares
        // its own `shm` at the same id with the same encoding, and that one is
        // still a row nothing in this tree writes.
        crate::ext_name::SHM_INIT if carrier_kind == crate::ext_name::ExtCarrier::Init => {
            walked("shm", walk_shm_init_body)
        }
        // R311y896 — the one body that is itself a CHAIN, so the walk is this
        // module's own chain walker one level down rather than a field layout.
        // The guard admits BOTH establishment carriers because both declare the
        // extension, and it is what keeps a `Put`'s `attachment` — USER bytes
        // at the same id `0x3` — out: those bytes can parse as a chain, so no
        // remainder check downstream would catch the misreading.
        crate::ext_name::AUTH if is_establishment(carrier_kind) => walked("auth", walk_auth_body),
        // R311y897 — the METHOD bodies one level inside that chain. The four
        // guards below are REDUNDANT today and are written anyway, on the
        // `qos` arm's rule: `crate::ext_name` already separates these rows by
        // carrier before the dispatch is asked (`0x2 | ZBuf` resolves to
        // `shm` on an `Init` and to `usrpwd` only on `Auth`), so removing all
        // four reds nothing — MEASURED, not assumed. What the guard buys is
        // the day a carrier declares a row that spells the same name, which is
        // exactly how `shm` came to need one.
        crate::ext_name::AUTH_USRPWD if carrier_kind == crate::ext_name::ExtCarrier::Auth => {
            walked("usrpwd", walk_auth_usrpwd_body)
        }
        crate::ext_name::AUTH_PUBKEY if carrier_kind == crate::ext_name::ExtCarrier::Auth => {
            walked("pubkey", walk_pubkey_challenge_body)
        }
        // R311y897 — the SAME bytes under zenoh's `.transmute()`d id `0x4`,
        // which is why they share the walker rather than copying it.
        crate::ext_name::MULTI_LINK if carrier_kind == crate::ext_name::ExtCarrier::Init => {
            walked("multi_link", walk_pubkey_challenge_body)
        }
        crate::ext_name::MULTI_LINK_SYN if carrier_kind == crate::ext_name::ExtCarrier::Open => {
            walked("multi_link_syn", walk_pubkey_challenge_body)
        }
        _ => return None,
    };
    Some(hit)
}

/// The `0x3` auth extension's body — the inner chain of per-method sub-exts,
/// walked with this module's own chain walker one level down.
///
/// # Why this body is a chain and not a value
///
/// zenoh's auth extension is a MULTIPLEXER: every configured method
/// contributes a `ZExtUnknown` keyed by its `auth::id`, the set is encoded as
/// an ext chain, and the receiver demultiplexes by that id
/// (`establishment/ext/auth/mod.rs`, the `ztake!` macro). This tree writes the
/// same shape — `crate::auth_dispatch::AuthDispatch::mux` runs
/// `AuthSubExt::into_ext_entry` over its methods, `crate::ext_chain::encode_ext_chain`s
/// them, and wraps the result with `crate::extauth::encode_auth_ext` — and
/// reads it back through `..::demux`, which is `decode_ext_chain` on the same
/// bytes. So the layout has a producer AND a consumer in this tree, which is
/// the rule [`walk_ext_zbuf_body`] admits a walker under.
///
/// # The bound is the PARTICIPANT's
///
/// [`crate::parse_error::MAX_EXT_CHAIN_DEPTH`] rather than a number chosen
/// here, because `demux` reaches this same body through `decode_ext_chain` and
/// that is the cap it applies. An observer that accepted a chain the
/// participant beside it refuses would report a handshake the peer never saw.
///
/// # The sub-ext bodies, and the sentence that used to stop here
///
/// This doc said a sub-ext's own ZBuf body "stays opaque … the METHOD's
/// private format rather than the protocol's — the boundary this module
/// already draws at `attachment`". R311y897 measured it and it was false, in
/// the shape R311y894 and R311y896 already found twice: the sentence described
/// a layer BELOW the one it was excusing. `attachment` is user bytes with no
/// declared structure anywhere; a usrpwd OpenSyn is
/// [`crate::vle::write_zbuf`] twice and a pubkey body is that same primitive
/// one to three times, both with a producer AND a consumer in this tree — the
/// rule [`walk_ext_zbuf_body`] admits a walker under. The private part of the
/// method is what is INSIDE the ZBufs (an HMAC tag, an RSA modulus), and no
/// walker here claims to read that.
///
/// So the chain layer answers WHICH methods were offered and at which stage,
/// and [`walk_auth_usrpwd_body`] / [`walk_pubkey_challenge_body`] answer what
/// each one put on the wire.
fn walk_auth_body(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    walk_ext_chain_z(
        c,
        crate::parse_error::MAX_EXT_CHAIN_DEPTH,
        crate::ext_name::ExtCarrier::Auth,
    )
}

/// One zenoh `ZBuf` — a VLE length then that many bytes — as its two fields.
///
/// The length is emitted rather than swallowed because the walk must TILE the
/// body: a field per byte range, with none left unaccounted for.
fn read_zbuf_field(
    c: &mut SpanCursor<'_>,
    len_name: &'static str,
    name: &'static str,
    out: &mut Vec<Field>,
) -> Result<(), CodecError> {
    let (n, len) = c.vle_u64(len_name)?;
    out.push(len);
    let n = usize::try_from(n).map_err(|_| CodecError::NeedMoreBytes)?;
    out.push(c.bytes(name, n)?);
    Ok(())
}

/// How many whole zenoh `ZBufs` `body` is, or `None` when it is not a whole
/// number of them.
///
/// Counted with [`crate::vle::read_zbuf`] — the producer's own read twin —
/// rather than with a length scan written here, so this cannot disagree with
/// the codec about where one record ends and the next begins.
fn zbuf_record_count(body: &[u8]) -> Option<usize> {
    let mut cursor = SceCursor::new(body);
    let mut count = 0usize;
    while cursor.remaining() != 0 {
        crate::vle::read_zbuf(&mut cursor)?;
        count += 1;
    }
    Some(count)
}

/// The usrpwd method's OpenSyn body — `{user, hmac}`, two zenoh `ZBufs`.
///
/// Written by `crate::extauth_usrpwd`'s `encode_open_syn` and read back by its
/// `decode_open_syn`, both over the [`crate::vle::write_zbuf`] /
/// [`crate::vle::read_zbuf`] SSOT (code spans, not links: the method sits
/// behind `access-extauth-usrpwd`, which `dissect` does not select, so a link
/// would be unresolved in the builds a reader runs — the rule R311y893 wrote
/// beside `crate::ext_name`'s constants and Layer C1bz counts).
///
/// # Why this is the protocol's shape and not the method's secret
///
/// The METHOD's private part is what is inside the second ZBuf: an
/// HMAC-SHA3-256 tag over the InitAck nonce, which nothing here interprets.
/// The FRAMING around it is zenoh `Zenoh080`'s two-ZBuf encoding, identical to
/// the one `attachment` deliberately does not get — and the difference is that
/// this one is declared, produced and consumed in this tree, while an
/// attachment's bytes have no declared structure at all.
///
/// # What a capture could not show before
///
/// WHICH user a peer authenticated as. The chain layer already named the
/// method and the stage; the credential's owner was thirty-odd bytes of hex,
/// so a capture of a rejected handshake could not distinguish a wrong password
/// from a wrong username.
fn walk_auth_usrpwd_body(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let mut out = Vec::with_capacity(4);
    read_zbuf_field(c, "user_len", "user", &mut out)?;
    read_zbuf_field(c, "hmac_len", "hmac", &mut out)?;
    Ok(out)
}

/// The mutual RSA challenge-response body — one, two or three zenoh `ZBufs`,
/// and the COUNT is which stage of the handshake this is.
///
/// Three carriers share it, because zenoh gives them the same bytes:
/// the `pubkey` method's sub-ext inside the `0x3` auth chain, and `Init`'s /
/// `Open`'s `0x4` multilink ext, which zenoh produces by `.transmute()`-ing
/// the pubkey FSM's payload onto a different id with no re-framing
/// (`crate::extmultilink`). One walker rather than three is therefore the
/// honest encoding of one fact.
///
/// # The layouts, and why the count separates them exactly
///
/// `wz-runtime-tokio`'s `extauth_pubkey` writes a public key as
/// [`crate::vle::write_zbuf`] of `n.to_bytes_le()` then of `e.to_bytes_le()`
/// (zenoh's `ZPublicKey` `WCodec`), and a ciphertext as one more:
///
/// * InitSyn — `{n, e}`, two records: the initiator's own key.
/// * InitAck — `{n, e, challenge}`, three: the acceptor's key plus the nonce
///   it encrypted under the initiator's.
/// * OpenSyn — `{challenge}`, one: that nonce re-encrypted the other way.
///
/// Nothing in the body says which; the message's own direction does, and that
/// is not in this function's reach. It does not need to be. A ZBuf's length
/// prefix fixes where it ends, so reading records until the body is exhausted
/// yields a count that is exact — the same argument
/// [`walk_shm_init_body`] makes from the other end, with a count in place of a
/// length.
///
/// # Declining rather than guessing
///
/// A body that is not a whole number of records, or is more than three, gets
/// no reading at all: [`walk_ext_zbuf_body`] hands the reader the raw bytes,
/// which is the honest answer to "not the structure this build thought".
fn walk_pubkey_challenge_body(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let mut out = Vec::with_capacity(6);
    match zbuf_record_count(c.peek_rest()?).ok_or(CodecError::NeedMoreBytes)? {
        1 => read_zbuf_field(c, "challenge_len", "challenge", &mut out)?,
        2 => {
            read_zbuf_field(c, "pubkey_n_len", "pubkey_n", &mut out)?;
            read_zbuf_field(c, "pubkey_e_len", "pubkey_e", &mut out)?;
        }
        3 => {
            read_zbuf_field(c, "pubkey_n_len", "pubkey_n", &mut out)?;
            read_zbuf_field(c, "pubkey_e_len", "pubkey_e", &mut out)?;
            read_zbuf_field(c, "challenge_len", "challenge", &mut out)?;
        }
        0 => return Err(CodecError::NeedMoreBytes),
        _ => return Err(CodecError::TooManyElements),
    }
    Ok(out)
}

/// `Join`'s mandatory ZBuf `qos` body — the per-priority next-SN table
/// `crate::multicast_join::write_join_qos_ext` writes: `Priority::NUM`
/// `(reliable, best_effort)` VLE pairs, `Control` (0) first, and nothing else.
///
/// A code span rather than an intra-doc link, and the reason is the one
/// R311y893 wrote beside `crate::ext_name`'s constants: that producer is
/// private and sits behind `session-multicast` + `transport-qos`, neither of
/// which `dissect` selects, so the link is unresolved in every build a reader
/// would run — and Layer C1bz counts exactly that.
///
/// # Why a multicast diagnosis cannot do without it
///
/// A qos JOIN puts the DECOY `{0, 0}` in the base `next_sn` fields (zenoh
/// `multicast/link.rs` sets `next_sn = PrioritySn::DEFAULT` when the real
/// numbers ride the extension) and every per-priority baseline a receiver
/// seeds from lives HERE. Left opaque, a capture of a qos group showed two
/// zeros where the announcement was and thirty-odd hex bytes where the answer
/// was — which reads as a peer announcing that it has sent nothing.
///
/// # The priority is POSITIONAL, so it is emitted rather than read
///
/// Nothing in the body says which priority a pair belongs to; the index is
/// the whole of it. `priority` therefore aliases the pair's own span — the
/// bytes that evidence it — and carries the zenoh `Priority` discriminant
/// (`Control` 0 … `Background` 7, [`crate::qos::Priority::wire_byte`]'s
/// numbering) rather than a name, because a name would be an eleventh table
/// in this tree with no adjudicator behind it.
///
/// # Why the count is exact, and declining is the alternative
///
/// The pair count is fixed at [`crate::qos::Priority::NUM`] by the protocol,
/// not read from the body, so a table that is short runs the cursor off the
/// end and one that is long leaves bytes over. Both decline through
/// [`walk_ext_zbuf_body`]'s own remainder check and the reader gets the raw
/// `value` — the honest answer to "not the structure this build thought",
/// against a table silently missing a priority.
fn walk_join_qos_body(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let mut out = Vec::with_capacity(crate::qos::Priority::NUM);
    for priority in 0..crate::qos::Priority::NUM {
        let start = c.offset();
        let (_, reliable) = c.vle_u64("next_sn_reliable")?;
        let (_, best_effort) = c.vle_u64("next_sn_best_effort")?;
        let span = Span {
            start,
            end: c.offset(),
        };
        out.push(group(
            "priority_sn",
            span.start,
            span.end,
            alloc::vec![
                bits("priority", span, priority as u64),
                reliable,
                best_effort
            ],
        ));
    }
    Ok(out)
}

/// `Init`'s ZBuf `shm` body — the SHM establishment handshake, whose two
/// halves ride one eid: `InitSyn { alice_segment }`, one VLE, and
/// `InitAck { alice_challenge, bob_segment }`, two.
///
/// Produced by `crate::extshm::encode_shm_init_syn_body` and
/// `encode_shm_init_ack_body` (code spans, not links: `session-extshm` is not
/// among `dissect`'s features, so the link would be unresolved in the builds a
/// reader runs). The field names are upstream's own struct fields
/// (`zenoh-transport` `unicast/establishment/ext/shm.rs`), which is what lets
/// a reader move between the capture and that source without a translation.
///
/// # Which half, told by LENGTH — and why that is exact rather than a guess
///
/// Nothing in the body says which half it is; the Init message's `A` flag does,
/// and that flag is not in this function's reach. It does not need to be. A VLE
/// occupies a number of bytes fixed by its own leading bits, so after reading
/// the first one the cursor is either empty — and the body was one VLE, the SYN
/// — or it is not, and the ACK's second VLE must then finish it exactly. Both
/// cannot hold, because the alternative would need a zero-byte VLE.
///
/// The rename in the second branch is deliberate: the same wire position is
/// Alice's SEGMENT in one half and the challenge AGAINST that segment in the
/// other, and a reader told `alice_segment` on an ACK would have the direction
/// of the handshake backwards.
fn walk_shm_init_body(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (_, first) = c.vle_u64("alice_segment")?;
    if c.remaining() == 0 {
        return Ok(alloc::vec![first]);
    }
    let (_, bob_segment) = c.vle_u64("bob_segment")?;
    Ok(alloc::vec![
        Field {
            name: "alice_challenge".into(),
            ..first
        },
        bob_segment,
    ])
}

/// The `source_info` ext body — the `(zid, eid, sn)` triple
/// [`crate::source_info_ext::encode_source_info_ext_body`] writes: a leading
/// byte whose HIGH nibble holds `zid_len - 1`, the zid, then two VLEs.
///
/// The zid length rides the high nibble exactly as `Scout` / `Hello`'s `cbyte`
/// carries it, which is why the alias is the same `zid_len_m1` rather than a
/// second name for one wire convention.
fn walk_source_info_body(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let mut out = walk_zid_prefixed(c)?;
    let (_, eid) = c.vle_u64("eid")?;
    out.push(eid);
    let (_, sn) = c.vle_u64("sn")?;
    out.push(sn);
    Ok(out)
}

/// The `responder_id` ext body — [`crate::response_build::encode_responder_ext_body`].
///
/// The same leading byte and zid as `source_info`, and then it STOPS: a
/// responder is an entity, not a sample, so there is no `sn`. A walker that
/// shared one function with `source_info` would read the next extension's
/// header as this one's sequence number.
fn walk_responder_id_body(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let mut out = walk_zid_prefixed(c)?;
    let (_, eid) = c.vle_u64("eid")?;
    out.push(eid);
    Ok(out)
}

/// The `[(zid_len - 1) << 4] ++ zid` prefix both identity ext bodies open with.
fn walk_zid_prefixed(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (byte, hdr) = c.u8("hdr")?;
    let carrier = hdr.span;
    let len_m1 = ((byte >> 4) & 0x0F) as u64;
    let mut out = alloc::vec![hdr, bits("zid_len_m1", carrier, len_m1)];
    out.push(c.bytes("zid", len_m1 as usize + 1)?);
    Ok(out)
}

/// The Query VALUE ext body — [`crate::query_value_ext::encode_query_value_ext_body`]:
/// an `Encoding` then the payload, which runs to the end of the ZBuf.
///
/// This is the ext R311y505's table calls the one "a reader that looks only at
/// the message body never finds": a `Query` carries its value HERE, not in a
/// field of the message, so a dissector that leaves this body opaque cannot
/// show a query's payload at all.
fn walk_query_value_body(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let mut out = alloc::vec![c.nested("encoding", walk_encoding)?];
    out.push(c.tail("payload")?);
    Ok(out)
}

/// The `Declare` common `wire_expr` ext body —
/// [`crate::declare_ext_keyexpr::build_ext_keyexpr`]: an inner header byte,
/// the mapping id as a VLE, and the suffix filling the rest.
///
/// NOT [`walk_wireexpr`], and the difference is the whole reason this is its
/// own walker: the message-level wireexpr length-prefixes its suffix, while
/// this body's suffix is simply the remainder. Reusing the other walker would
/// read the first suffix byte as a length.
fn walk_ext_wireexpr_body(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (inner, hdr) = c.u8("hdr")?;
    let carrier = hdr.span;
    let has_suffix = (inner & 0x01) != 0;
    let mut out = alloc::vec![
        hdr,
        // `is_local` IS the mapping — the same fact `walk_wireexpr` records
        // from the carrier message's M flag, so it is recorded under the same
        // name rather than under a second one meaning the same thing.
        bits("mapping", carrier, ((inner & 0x02) != 0) as u64),
        flag("n", carrier, has_suffix),
    ];
    let (_, id) = c.vle_u64("id")?;
    out.push(id);
    if has_suffix {
        let n = c.remaining();
        out.push(c.text("suffix", n)?);
    }
    Ok(out)
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
fn walk_ext_chain_z(
    c: &mut SpanCursor<'_>,
    max: usize,
    carrier_kind: crate::ext_name::ExtCarrier,
) -> Result<Vec<Field>, CodecError> {
    let mut out = Vec::new();
    let mut more = false;
    for _ in 0..max {
        if c.remaining() == 0 {
            break;
        }
        let (z, f) = walk_ext_entry(c, carrier_kind)?;
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
fn walk_ext_chain_fill(
    c: &mut SpanCursor<'_>,
    max: usize,
    carrier_kind: crate::ext_name::ExtCarrier,
) -> Result<Vec<Field>, CodecError> {
    let mut out = Vec::new();
    for _ in 0..max {
        if c.remaining() == 0 {
            break;
        }
        let (_, f) = walk_ext_entry(c, carrier_kind)?;
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
    let mut is_shm = false;
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            let chain = walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::Put,
            )?;
            is_shm = chain_carries_ext_eid(&chain, SHM_MARKER_EID);
            Ok(chain)
        })?);
    }
    let (n, len) = c.vle_u64("payload_len")?;
    out.push(len);
    out.push(payload_or_shm_descriptor(c, n as usize, is_shm)?);
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
            walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::Del,
            )
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
            walk_ext_chain_fill(
                c,
                crate::ext_chain::QUERY_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::Query,
            )
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
            walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::Reply,
            )
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
    let mut is_shm = false;
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            let chain = walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::Err,
            )?;
            is_shm = chain_carries_ext_eid(&chain, SHM_MARKER_EID);
            Ok(chain)
        })?);
    }
    let (n, len) = c.vle_u64("payload_len")?;
    out.push(len);
    out.push(payload_or_shm_descriptor(c, n as usize, is_shm)?);
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
            walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::Push,
            )
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
            walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::Request,
            )
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
            walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::Response,
            )
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
            walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::ResponseFinal,
            )
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
            walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::Interest,
            )
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
    // The VALUE is 16 bits wide even though the WIRE encoding is a full zint,
    // and the id SELECTS the body's meaning below, so truncating here rather
    // than at the match is the whole difference between naming a topology
    // advertisement and calling it opaque bytes. See `oam_id_from_wire`.
    let (oam_id, id) = c.vle_u16_truncated("id")?;
    out.push(id);
    if (header & 0x80) != 0 {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::NetworkOam,
            )
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
            // R311y597 — the OAM id selects the body's meaning. Only
            // `OAM_LINKSTATE_ID` on a ZBuf body is a topology advertisement;
            // every other id keeps the opaque `value`, because walking bytes
            // whose shape this build does not know is how a dissector starts
            // inventing structure.
            let start = c.offset();
            let value = c.bytes("value", n as usize)?;
            out.push(match (oam_id, &value.value) {
                (wz_codecs::wire_const::OAM_LINKSTATE_ID, FieldValue::Bytes(body)) => {
                    walk_linkstate_body(body, start).unwrap_or(value)
                }
                _ => value,
            });
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
                // The `Undeclare*` bodies' own chain — `declare::common::ext`,
                // whose one row is `WireExprExt` at `0x0f`, NOT the `Declare`
                // message's QoS / Timestamp / NodeId space.
                walk_ext_chain_z(
                    c,
                    crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                    crate::ext_name::ExtCarrier::DeclareCommon,
                )
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
                        walk_ext_chain_z(
                            c,
                            crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                            crate::ext_name::ExtCarrier::DeclareQueryable,
                        )
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
            walk_ext_chain_z(
                c,
                crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
                crate::ext_name::ExtCarrier::Declare,
            )
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
            out.push(walk_locator_entry(c)?);
        }
    }
    Ok(out)
}

/// One `Locator` record: a VLE length then that many UTF-8 bytes.
///
/// R311y597 — lifted out of [`walk_hello`] because linkstate carries the SAME
/// record, and a second inline copy is how the two would drift apart on the
/// next change to either.
///
/// The GROUP is named apart from its leaf on purpose: [`Field::find`] returns
/// the first match by name, so a group called `locator` shadows the string
/// field inside it and a consumer asking for the locator gets a nested node
/// instead of the text.
fn walk_locator_entry(c: &mut SpanCursor<'_>) -> Result<Field, CodecError> {
    let start = c.offset();
    let (len, len_field) = c.vle_u64("locator_len")?;
    let text = c.text("locator", len as usize)?;
    Ok(group(
        "locator_entry",
        start,
        c.offset(),
        alloc::vec![len_field, text],
    ))
}

/// One `Linkstate` record — a node's advertised identity and its adjacency.
///
/// `options` is a presence bitfield and every optional field below is gated on
/// one of its bits, so which fields APPEAR is itself the information; the bits
/// are not surfaced separately because the field's presence already carries
/// them and naming four flags would add vocabulary that says nothing new.
///
/// ⚠ `psid` occurs at TWO depths with two meanings — the record's own
/// peer-local id, and one per entry of `links` naming a neighbour. That is the
/// codec's own naming, kept rather than corrected, but it means
/// `find("psid")` answers with the record's own (the outermost, first match).
fn walk_linkstate_entry(c: &mut SpanCursor<'_>) -> Result<Field, CodecError> {
    let start = c.offset();
    let (options, options_field) = c.u8("options")?;
    let mut fields = alloc::vec![options_field];
    let (_, psid) = c.vle_u64("psid")?;
    fields.push(psid);
    let (_, sn) = c.vle_u64("sn")?;
    fields.push(sn);
    if (options & 0x01) != 0 {
        let (n, len) = c.vle_u64("zid_len")?;
        fields.push(len);
        fields.push(c.bytes("zid", n as usize)?);
    }
    if (options & 0x02) != 0 {
        let (_, w) = c.u8("whatami")?;
        fields.push(w);
    }
    if (options & 0x04) != 0 {
        let (n, count) = c.vle_u64("num_locators")?;
        fields.push(count);
        let lstart = c.offset();
        let mut entries = Vec::new();
        for _ in 0..n {
            entries.push(walk_locator_entry(c)?);
        }
        fields.push(group("locators", lstart, c.offset(), entries));
    }
    let (link_count, links_len) = c.vle_u64("links_len")?;
    fields.push(links_len);
    let links_start = c.offset();
    let mut links = Vec::new();
    for _ in 0..link_count {
        let (_, p) = c.vle_u64("psid")?;
        links.push(p);
    }
    fields.push(group("links", links_start, c.offset(), links));
    // The weights repeat is counted by `links_len`, NOT by a length of its
    // own — one weight per link, gated by a separate options bit.
    if (options & 0x08) != 0 {
        let w_start = c.offset();
        let mut weights = Vec::new();
        for _ in 0..link_count {
            // Truncating, not refusing: upstream reads the weight on the plain
            // `Zenoh080` (`zenoh/src/net/codec/linkstate.rs:125`), so the wire
            // width is a full zint and the value width is 16 bits
            // (`wire_const::linkstate_weight_from_wire`). A refusing read here
            // cost the reader the whole ENVELOPE, because `walk_linkstate_body`
            // declines on any parse error.
            let (_, w) = c.vle_u16_truncated("weight")?;
            weights.push(w);
        }
        fields.push(group("weights", w_start, c.offset(), weights));
    }
    Ok(group("linkstate_entry", start, c.offset(), fields))
}

/// The `LinkstateList` body an `OAM_LINKSTATE` carries: a count then that many
/// records.
///
/// R311y597 — this is the walker `dissect.rs` used to say it did not have.
/// The decoders existed (`out/wz-codecs/linkstate{,_link,_list,_weight}.rs`)
/// and `walk_oam` rendered the whole body as an opaque `value`, so a capture
/// could carry a full topology advertisement and show a reader a byte blob.
///
/// ⚠ The heapless caps the CODEC carries (`HeaplessVec<_, 64>` on locators,
/// links and weights) are NOT mirrored here. A walker reads a capture on a
/// host, and refusing a 65-link router's advertisement would hide exactly the
/// large topology an analyst opened the capture for. The divergence is
/// deliberate and one-directional: this walker accepts advertisements the
/// codec would refuse, never the reverse.
/// Walk an `OAM_LINKSTATE` ZBuf body, or decline.
///
/// R311y597 — declining rather than failing is the whole contract. Before this
/// walker existed `walk_oam` could not fail on a body at all: it read `n` bytes
/// and was done. A walker that propagates a parse error would make a message
/// that used to dissect stop dissecting, so a truncated advertisement, a
/// future zenoh's extra field, or an id collision would cost the reader the
/// ENVELOPE too — the transport framing, the extensions, everything — over a
/// body it could have shown as bytes.
///
/// Partial success also declines: a body that parses but leaves bytes over is
/// not a link-state list this build understands, and rendering the prefix as
/// a topology while silently dropping the tail is the confident-wrong-answer
/// failure again.
fn walk_linkstate_body(body: &[u8], base: usize) -> Option<Field> {
    let mut c = SpanCursor::with_base(body, base);
    let fields = walk_linkstate_list(&mut c).ok()?;
    if c.remaining() != 0 {
        return None;
    }
    Some(group("linkstate", base, base + body.len(), fields))
}

fn walk_linkstate_list(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {
    let (n, count) = c.vle_u64("num_link_states")?;
    let mut out = alloc::vec![count];
    let start = c.offset();
    let mut entries = Vec::new();
    for _ in 0..n {
        entries.push(walk_linkstate_entry(c)?);
    }
    out.push(group("link_states", start, c.offset(), entries));
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
/// Which extension vocabulary a TRANSPORT message's chain is read against.
///
/// The transport space is where the carrier matters most, because the same id
/// is a different extension in nearly every message: `0x2` is `Shm` on `Init`
/// (a `ZBuf`), `Shm` on `Open` (a `Z64`), `Shm` on `Join` (a mandatory `ZBuf`)
/// and `First` on a `Fragment` (a `Unit`). One context-free table would have to
/// pick one and be wrong three times.
///
/// `0x00` is upstream's transport OAM (`transport/mod.rs` `id::OAM`), mapped
/// here even though this build's dispatch has no arm for that mid yet — the
/// vocabulary is a property of the wire, not of how far the dispatch has got,
/// and a mapping that waited for the arm would be a second place to forget.
///
/// An unrecognised mid gets [`ExtCarrier::TransportPlain`](crate::ext_name::ExtCarrier::TransportPlain),
/// whose row set is empty, so its entries are id-and-encoding only. That is the
/// honest answer: this build does not know what message it is looking at, so it
/// cannot know what its extensions are called.
fn transport_carrier(mid: u8) -> crate::ext_name::ExtCarrier {
    use crate::ext_name::ExtCarrier;
    use wz_codecs::wire_const;
    match mid {
        0x00 => ExtCarrier::TransportOam,
        wire_const::T_MID_INIT => ExtCarrier::Init,
        wire_const::T_MID_OPEN => ExtCarrier::Open,
        wire_const::T_MID_JOIN => ExtCarrier::Join,
        wire_const::T_MID_FRAME => ExtCarrier::Frame,
        wire_const::T_MID_FRAGMENT => ExtCarrier::Fragment,
        // `Close` and `KeepAlive` declare no extension upstream, and so does
        // anything this build does not recognise.
        _ => ExtCarrier::TransportPlain,
    }
}

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
    // WHERE the ext chain sits is a per-MID property of the wire, and the arms
    // below disagree about it: FRAME, FRAGMENT and OAM write theirs BEFORE the
    // body, every other MID after it. Each arm that reads its own chain says so
    // HERE, rather than the trailing walk carrying a list of MIDs to skip — a
    // list is a second place to remember, and the arm that forgets to join it
    // walks its chain twice.
    let mut chain_walked = false;
    let name = match mid {
        wire_const::T_MID_OAM => {
            // The body's encoding lives in header bits 5..6, exactly as an
            // ExtEntry's does: upstream reads `header & iext::ENC_MASK`
            // (`zenoh-codec/src/transport/oam.rs`), the same two bits every
            // other transport MID spends on flags.
            let enc = (header & wire_const::FLAG_T_OAM_ENC) >> 5;
            out.push(bits("encoding", carrier, enc as u64));
            // `OamId` is a `u16` upstream and upstream reaches it by
            // TRUNCATION, not by refusal (`oam_id_from_wire`). R311y878 read
            // it with the refusing `vle_u16` on the belief that a wide zint is
            // a message zenoh rejects; `uint_impl!(u16)` says otherwise, and
            // the belief cost the whole message rather than one field.
            let (_, id) = c.vle_u16_truncated("id")?;
            out.push(id);
            if has_ext {
                out.push(c.nested("extensions", |c| {
                    walk_ext_chain_z(
                        c,
                        crate::parse_error::MAX_EXT_CHAIN_DEPTH,
                        transport_carrier(mid),
                    )
                })?);
                chain_walked = true;
            }
            match enc {
                // Unit — no body bytes at all.
                0 => {}
                1 => {
                    let (_, f) = c.vle_u64("value")?;
                    out.push(f);
                }
                2 => {
                    let (n, len) = c.vle_u64("value_len")?;
                    out.push(len);
                    out.push(c.bytes("value", n as usize)?);
                }
                // The reserved 0b11, which upstream refuses outright. The
                // remainder becomes an opaque `body` rather than being left
                // unread — the same answer the `_` MID arm below gives, and
                // for the same reason: no capture byte may go unaccounted
                // for, and the encoding bits are already on the tree so a
                // reader can see WHY it is opaque.
                _ => out.push(c.tail("body")?),
            }
            "Oam"
        }
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
            // R311y839 — the SCOPE flag, rendered for the same reason JOIN's
            // `t`/`s` and FRAME's `r` are: it is a header bit a reader has to act
            // on. zenoh's receiver branches `delete()` vs `del_link(link)` on it
            // (`io/zenoh-transport/src/unicast/universal/rx.rs:60-73`), so a
            // capture that shows only `reason` cannot tell a session teardown from
            // one link of an aggregate going away.
            out.push(flag("s", carrier, (header & 0x20) != 0));
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
                    walk_ext_chain_z(
                        c,
                        crate::parse_error::MAX_EXT_CHAIN_DEPTH,
                        transport_carrier(mid),
                    )
                })?);
                chain_walked = true;
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
    // The transport ext chain trails the body of every MID whose arm did not
    // already read it — see `chain_walked` above.
    if has_ext && !chain_walked {
        out.push(c.nested("extensions", |c| {
            walk_ext_chain_z(
                c,
                crate::parse_error::MAX_EXT_CHAIN_DEPTH,
                transport_carrier(mid),
            )
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
        FieldValue::Label(s) => {
            out.push_str("\"kind\":\"label\",\"value\":");
            crate::json::escape_into(s, out);
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

    /// `field` must be a BITS subfield holding this value. Distinct from
    /// [`uint`] on purpose: a subfield of a carrier byte and a field of its own
    /// are different things on the wire, and a helper that accepted either
    /// would let a walker demote one to the other unnoticed.
    #[track_caller]
    fn bits_of(root: &Field, name: &str) -> u64 {
        match root.find(name).map(|f| &f.value) {
            Some(FieldValue::Bits(v)) => *v,
            other => panic!("{name} is not a bits subfield: {other:?}"),
        }
    }

    /// `field` must hold this unsigned value.
    #[track_caller]
    fn uint(root: &Field, name: &str) -> u64 {
        match root.find(name).map(|f| &f.value) {
            Some(FieldValue::Uint(v)) => *v,
            other => panic!("{name} is not a uint: {other:?}"),
        }
    }

    /// R311y597 — the linkstate walker, judged against the CODEC's own encode
    /// rather than against a hand-laid byte string.
    ///
    /// Building the fixture by hand would test the walker against my reading
    /// of the layout, which is the thing under test. Encoding through
    /// `LinkstateList` means the bytes are the codec's, so a walker that
    /// disagrees with the codec fails here instead of agreeing with a mistake.
    #[test]
    fn an_oam_linkstate_body_is_walked_into_its_topology() {
        use sce_forge_runtime::heapless::Vec as HeaplessVec;
        use wz_codecs::linkstate::Linkstate;
        use wz_codecs::linkstate_link::LinkstateLink;
        use wz_codecs::linkstate_list::LinkstateList;
        use wz_codecs::linkstate_weight::LinkstateWeight;
        use wz_codecs::locator::Locator;

        let mut locators = HeaplessVec::new();
        locators
            .push(Locator {
                locator_len: 9,
                locator: "tcp/1.2.3",
            })
            .unwrap();
        let mut links = HeaplessVec::new();
        links.push(LinkstateLink { psid: 7 }).unwrap();
        links.push(LinkstateLink { psid: 9 }).unwrap();
        let mut weights = HeaplessVec::new();
        weights.push(LinkstateWeight { weight: 100 }).unwrap();
        weights.push(LinkstateWeight { weight: 300 }).unwrap();

        let zid = [0xAAu8, 0xBB];
        let mut states = HeaplessVec::new();
        states
            .push(Linkstate {
                // zid | whatami | locators | weights
                options: 0x01 | 0x02 | 0x04 | 0x08,
                psid: 3,
                sn: 42,
                zid_len: Some(zid.len() as u64),
                zid: Some(&zid),
                whatami: Some(1),
                num_locators: Some(1),
                locators: Some(locators),
                links_len: 2,
                links,
                weights: Some(weights),
            })
            .unwrap();
        let list = LinkstateList {
            num_link_states: 1,
            link_states: states,
        };
        let body = list.encode_to_vec();

        // Wrap it as the OAM carries it: header (MID 0x1F, ZBuf encoding),
        // VLE id = OAM_LINKSTATE_ID, VLE body length, body.
        let mut wire = alloc::vec![0x1Fu8 | 0x40];
        wire.extend(vle(wz_codecs::wire_const::OAM_LINKSTATE_ID as u64));
        wire.extend(vle(body.len() as u64));
        wire.extend_from_slice(&body);

        let mut c = SpanCursor::new(&wire);
        let fields = walk_oam(&mut c).expect("an OAM-LINKSTATE must walk");
        let root = group("Oam", 0, wire.len(), fields);

        assert_eq!(c.remaining(), 0, "the walker left bytes unread");
        assert_tiles(&root, 0, wire.len());
        assert!(
            root.find("value").is_none(),
            "a topology advertisement must not stay an opaque `value`",
        );

        let entry = root
            .find("linkstate_entry")
            .expect("one record must be named");
        assert_eq!(uint(entry, "psid"), 3, "the record's OWN psid, outermost");
        assert_eq!(uint(entry, "sn"), 42);
        assert_eq!(uint(entry, "whatami"), 1);
        assert_eq!(raw(entry, "zid"), zid.to_vec());
        assert_eq!(
            entry.find("locator").map(|f| &f.value),
            Some(&FieldValue::Text("tcp/1.2.3".into())),
        );

        // The neighbour ids live under `links`, and asking the RECORD for
        // `psid` must still answer with its own — the shadowing the doc warns
        // about, pinned rather than left to the reader.
        let links_group = entry.find("links").expect("links group");
        let neighbours: Vec<u64> = match &links_group.value {
            FieldValue::Nested(v) => v
                .iter()
                .map(|f| match f.value {
                    FieldValue::Uint(n) => n,
                    _ => panic!("a link entry must be a uint"),
                })
                .collect(),
            other => panic!("links is not a group: {other:?}"),
        };
        assert_eq!(neighbours, alloc::vec![7, 9]);

        // 300 does not fit a single VLE byte, so a walker reading weights at
        // the wrong width would still read 100 correctly and fail here.
        let weights_group = entry.find("weights").expect("weights group");
        let read: Vec<u64> = match &weights_group.value {
            FieldValue::Nested(v) => v
                .iter()
                .map(|f| match f.value {
                    FieldValue::Uint(n) => n,
                    _ => panic!("a weight must be a uint"),
                })
                .collect(),
            other => panic!("weights is not a group: {other:?}"),
        };
        assert_eq!(read, alloc::vec![100, 300]);
    }

    /// The linkstate walk DECLINES rather than failing — the envelope must
    /// survive a body this build cannot read.
    ///
    /// Two shapes, and the second is the one a length check alone would miss:
    /// a body too short for the records it announces, and a body that parses
    /// completely but leaves bytes over. Both are "not a link-state list this
    /// build understands", and both must come back as `value`.
    #[test]
    fn an_unparsable_linkstate_body_declines_instead_of_killing_the_envelope() {
        for (body, label) in [
            (
                alloc::vec![7u8, 8, 9],
                "announces 7 records and carries none",
            ),
            (
                alloc::vec![0u8, 0xFF],
                "parses as an empty list, tail left over",
            ),
        ] {
            let mut wire = alloc::vec![0x1Fu8 | 0x40];
            wire.extend(vle(wz_codecs::wire_const::OAM_LINKSTATE_ID as u64));
            wire.extend(vle(body.len() as u64));
            wire.extend_from_slice(&body);

            let mut c = SpanCursor::new(&wire);
            let fields = walk_oam(&mut c)
                .unwrap_or_else(|e| panic!("{label}: the envelope must still walk, got {e:?}"));
            let root = group("Oam", 0, wire.len(), fields);
            assert_eq!(raw(&root, "value"), body, "{label}");
            assert!(
                root.find("linkstate").is_none(),
                "{label}: a declined body must not be shown as a topology",
            );
            assert_eq!(c.remaining(), 0, "{label}");
        }
    }

    /// The CONTROL: an OAM with a DIFFERENT id keeps its opaque `value`.
    /// Without this leg, walking every ZBuf body as a linkstate would pass.
    #[test]
    fn an_oam_that_is_not_linkstate_keeps_its_opaque_value() {
        let payload = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let other_id = wz_codecs::wire_const::OAM_LINKSTATE_ID as u64 + 1;
        let mut wire = alloc::vec![0x1Fu8 | 0x40];
        wire.extend(vle(other_id));
        wire.extend(vle(payload.len() as u64));
        wire.extend_from_slice(&payload);

        let mut c = SpanCursor::new(&wire);
        let fields = walk_oam(&mut c).expect("walk");
        let root = group("Oam", 0, wire.len(), fields);

        assert_eq!(raw(&root, "value"), payload.to_vec());
        assert!(
            root.find("linkstate").is_none(),
            "only the linkstate id selects the topology walk",
        );
    }

    /// The OAM `id` is a `u16` in BOTH namespaces
    /// (`zenoh-protocol/src/network/oam.rs:16` and
    /// `zenoh-protocol/src/transport/oam.rs:16` each declare
    /// `pub type OamId = u16;`), and upstream's reader reaches it by
    /// TRUNCATION, not by refusal: both codecs read `let id: OamId =
    /// self.codec.read(..)` on the plain `Zenoh080`, whose derive is
    /// `let x: u64 = self.read(reader)?; Ok(x as $uint)`
    /// (`zenoh-codec/src/core/zint.rs`, `uint_impl!(u16)`). The codec that
    /// REFUSES an out-of-range zint is `Zenoh080Bounded<u16>`, a different
    /// codec, and neither OAM arm selects it.
    ///
    /// wz disagreed with that in BOTH directions at once, which is why one
    /// number could not describe the bug. The network walker read the field
    /// as `vle_u64` and rendered an id no peer ever computes. The transport
    /// walker (R311y878) read it as the refusing `vle_u16` and failed the
    /// whole message — so a capture stock zenoh reads fine became, to this
    /// dissector, a message with no fields at all.
    ///
    /// The third leg is the one that shows why width is not cosmetic: an id
    /// of `0x1_0001` truncates to `OAM_LINKSTATE_ID`, so a conforming peer
    /// walks the body as a topology advertisement. A walker that keeps the
    /// full width calls the same bytes opaque and the reader never learns
    /// what the network was told.
    #[test]
    fn an_oam_id_wider_than_u16_is_truncated_the_way_upstream_truncates_it() {
        let payload = alloc::vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        // 0x1_0002 -> the low 16 bits are 2, which is NOT the linkstate id,
        // so this leg measures the width alone.
        let wide = 0x1_0002u64;

        // NETWORK (MID 0x1F).
        let mut wire = alloc::vec![0x1Fu8 | 0x40];
        wire.extend(vle(wide));
        wire.extend(vle(payload.len() as u64));
        wire.extend_from_slice(&payload);
        let mut c = SpanCursor::new(&wire);
        let fields = walk_oam(&mut c).expect("the network walker must read it");
        let root = group("Oam", 0, wire.len(), fields);
        assert_eq!(
            uint(&root, "id"),
            2,
            "the network walker rendered an id the receiving peer never sees",
        );
        assert_eq!(raw(&root, "value"), payload);
        assert_eq!(c.remaining(), 0);
        assert_tiles(&root, 0, wire.len());

        // TRANSPORT (MID 0x00) — same field, same truncation, and here the
        // refusing read cost the whole message rather than one number.
        let t = concat(&[
            alloc::vec![0x40u8],
            vle(wide),
            vle(payload.len() as u64),
            payload.clone(),
        ]);
        let f = dissect_transport_message(&t, 0)
            .expect("upstream reads this message; the walker must too");
        assert_eq!(f.name, "Oam");
        assert_eq!(uint(&f, "id"), 2);
        assert_tiles(&f, 0, t.len());

        // The id SELECTS the body's meaning, so truncating late is the same
        // as not truncating at all: `0x1_0001` IS `OAM_LINKSTATE_ID` to
        // every conforming reader.
        let aliased = wz_codecs::wire_const::OAM_LINKSTATE_ID as u64 + 0x1_0000;
        let empty_list = alloc::vec![0x00u8];
        let mut wire = alloc::vec![0x1Fu8 | 0x40];
        wire.extend(vle(aliased));
        wire.extend(vle(empty_list.len() as u64));
        wire.extend_from_slice(&empty_list);
        let mut c = SpanCursor::new(&wire);
        let fields = walk_oam(&mut c).expect("walk");
        let root = group("Oam", 0, wire.len(), fields);
        assert_eq!(
            uint(&root, "id"),
            wz_codecs::wire_const::OAM_LINKSTATE_ID as u64
        );
        assert!(
            root.find("value").is_none(),
            "an id that aliases onto linkstate must select the topology walk",
        );
        assert!(
            root.find("linkstate").is_some(),
            "the topology must be named"
        );
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

    /// The SHM marker's header byte AS STOCK ZENOH EMITS IT.
    ///
    /// `zenoh::put::ext::Shm` and `zenoh::err::ext::Shm` are both
    /// `zextunit!(0x2, true)`, and `iext::id()` folds the mandatory flag into
    /// the byte, so what a real sender puts here is `0x12`.
    ///
    /// This constant exists because R311y597's and R311y605's fixtures used the
    /// BARE `0x02` — a byte stock zenoh never sends — so both witnesses passed
    /// while the walker could not recognise the marker on any real capture.
    /// Building the byte from its three named parts is what stops that
    /// recurring: a fixture that drops the mandatory flag now has to drop a
    /// visible term.
    const SHM_MARKER_BYTE: u8 = crate::ext_header::body_ext_id::SHM | crate::ext_header::EXT_FLAG_M;

    /// R311y597 — an SHM-marked `Put` must NOT present its descriptor as
    /// `payload`.
    ///
    /// The two assertions are different claims and both are needed. That the
    /// bytes are named `shm_descriptor` is what stops a reader taking an
    /// address for content. That they are `Opaque` rather than `Bytes` is what
    /// stops the OTHER misreading — a consumer seeing decoded-looking bytes and
    /// concluding the interior was understood, when wz and stock zenoh put
    /// incompatible layouts here and nothing on the wire tells them apart.
    #[test]
    fn an_shm_marked_put_does_not_call_its_descriptor_a_payload() {
        let descriptor = [0x04u8, 0x07, 0x00];
        let marked = msg_put(None, None, &[ext_unit(SHM_MARKER_BYTE, false)], &descriptor);

        let mut w = SpanCursor::new(&marked);
        let fields = walk_msg_put(&mut w).expect("an SHM-marked put must still walk");
        let root = group("MsgPut", 0, marked.len(), fields);

        assert!(
            root.find("payload").is_none(),
            "the descriptor must not be reachable under the name `payload`",
        );
        let shm = root
            .find("shm_descriptor")
            .expect("the descriptor must be named");
        assert_eq!(
            shm.value,
            FieldValue::Opaque,
            "the interior must not be claimed as understood",
        );
        assert_eq!(
            shm.span.end - shm.span.start,
            descriptor.len(),
            "the span must still account for every byte",
        );
        assert_eq!(w.remaining(), 0, "the walker left bytes unread");
    }

    /// The header byte's four fields, split the way zenoh splits them.
    ///
    /// The walker reported `header & 0x1F` as `ext_id`, so the MANDATORY flag
    /// was folded into the id and never appeared as a field of its own. That is
    /// what made the two SHM legs above pass on a byte no sender emits: their
    /// `0x02` was the only value the mis-masked id could still match.
    ///
    /// Asserted on the MANDATORY marker specifically, because a non-mandatory
    /// extension has the same id under either mask and cannot fail here.
    #[test]
    fn a_mandatory_extensions_id_is_four_bits_and_its_flag_is_its_own_field() {
        let marked = msg_put(None, None, &[ext_unit(SHM_MARKER_BYTE, false)], b"x");
        let mut w = SpanCursor::new(&marked);
        let root = group(
            "MsgPut",
            0,
            marked.len(),
            walk_msg_put(&mut w).expect("walk"),
        );

        assert_eq!(
            bits_of(&root, "ext_id"),
            crate::ext_header::body_ext_id::SHM as u64,
            "the id field is four bits; the mandatory flag is not part of it",
        );
        let m = root
            .find("ext")
            .and_then(|e| e.find("m"))
            .expect("the mandatory flag must be a field");
        assert_eq!(
            m.value,
            FieldValue::Flag(true),
            "the mandatory bit is the input to the R311y630 admission rule and \
             must be readable",
        );
    }

    /// The wire's own extension NAME, for the two `Request` extensions that
    /// answer opposite questions about a query.
    ///
    /// `Budget` (`0x5`) and `Timeout` (`0x6`) are both `zextz64`, so before the
    /// carrier reached the entry walker they rendered as `ext_id 5, value 3` and
    /// `ext_id 6, value 3` — every byte accounted for, and nothing that told a
    /// reader which of "stop after three replies" and "stop after three
    /// milliseconds" they were looking at.
    #[test]
    fn a_requests_budget_and_timeout_are_named_not_just_numbered() {
        let query = concat(&[alloc::vec![0x03u8], vle(0)]);
        let bytes = concat(&[
            alloc::vec![0x1Cu8 | 0x80],
            vle(7),
            wireexpr(0, None),
            ext_zint(0x5, true, 3),
            ext_zint(0x6, false, 3),
            query,
        ]);

        let f = agree(
            "Request",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                wz_codecs::request::Request::decode(&mut c).expect("codec rejected");
                b.len() - c.remaining()
            },
            walk_request,
        );

        let named: Vec<(String, u64)> = f
            .find("extensions")
            .and_then(|e| match &e.value {
                FieldValue::Nested(entries) => Some(entries),
                _ => None,
            })
            .expect("the chain must be walked")
            .iter()
            .map(|entry| {
                let name = match entry.find("ext_name").map(|f| &f.value) {
                    Some(FieldValue::Label(s)) => alloc::string::String::from(s.as_ref()),
                    other => panic!("an entry carried no ext_name: {other:?}"),
                };
                (name, uint(entry, "value"))
            })
            .collect();

        assert_eq!(
            named,
            alloc::vec![
                (alloc::string::String::from("budget"), 3),
                (alloc::string::String::from("timeout"), 3),
            ],
            "the two extensions must be told apart by name, not left as ids",
        );
    }

    /// The CARRIER decides the name, and `0x3` is the case that proves it: the
    /// same id is `node_id` on a `Push` and `responder_id` on a `Response`.
    ///
    /// One walker with no carrier could only ever answer one of these, so this
    /// is the leg that fails if the carrier is ever dropped back out of the
    /// entry walker — which a single-carrier test would not notice.
    #[test]
    fn one_id_is_named_by_the_message_it_was_read_from() {
        // `NodeId` is `zextz64!(0x3, true)`, so its header byte carries the
        // mandatory flag. Writing the fixture without it produced `None` here,
        // which is the corrected key catching a fixture written against the old
        // one — the same mistake, one round later, in this very test.
        let push = concat(&[
            alloc::vec![0x1Du8 | 0x80],
            wireexpr(1, None),
            ext_zint(0x3 | crate::ext_header::EXT_FLAG_M, false, 9),
            msg_put(None, None, &[], b"x"),
        ]);
        let mut w = SpanCursor::new(&push);
        let f = group("Push", 0, push.len(), walk_push(&mut w).expect("walk"));
        assert_eq!(
            f.find("ext_name").map(|f| f.value.clone()),
            Some(FieldValue::Label(Cow::Borrowed("node_id"))),
        );

        // The same id, the same z64 encoding would be WRONG here: upstream's
        // `ResponderId` is a ZBuf, so the byte differs in its encoding bits too
        // and a reader keyed on the id alone would call this a node id.
        let response = concat(&[
            alloc::vec![0x1Bu8 | 0x80],
            vle(1),
            wireexpr(0, None),
            ext_zbuf(0x3, false, &[0xAA, 0xBB]),
            concat(&[
                alloc::vec![0x04u8],
                alloc::vec![0x01u8],
                msg_put(None, None, &[], b"v"),
            ]),
        ]);
        let mut w = SpanCursor::new(&response);
        let f = group(
            "Response",
            0,
            response.len(),
            walk_response(&mut w).expect("walk"),
        );
        assert_eq!(
            f.find("ext_name").map(|f| f.value.clone()),
            Some(FieldValue::Label(Cow::Borrowed("responder_id"))),
        );
    }

    /// An extension this build has no name for carries NO `ext_name` field —
    /// not an empty one and not a guessed one.
    ///
    /// A chain is exactly where a later-vintage peer puts something this reader
    /// has never heard of, so the absent case is the ordinary one. A reader
    /// handed a synthesised placeholder could not tell a real extension from
    /// this build's ignorance of a newer one.
    #[test]
    fn an_extension_this_build_cannot_name_carries_no_name() {
        let push = concat(&[
            alloc::vec![0x1Du8 | 0x80],
            wireexpr(1, None),
            ext_zint(0x0A, false, 1),
            msg_put(None, None, &[], b"x"),
        ]);
        let mut w = SpanCursor::new(&push);
        let f = group("Push", 0, push.len(), walk_push(&mut w).expect("walk"));
        assert!(
            f.find("ext_name").is_none(),
            "an unnameable extension must not be handed a plausible name",
        );
        // But it is still ACCOUNTED FOR: the id and the value are there.
        assert_eq!(bits_of(&f, "ext_id"), 0x0A);
    }

    /// R311y505's rule reaching the field layer: the SHM marker is matched by
    /// its full IDENTITY, so a different extension that merely shares the id
    /// does not make the walker rename a payload.
    ///
    /// The bare `0x02` UNIT byte this builds is precisely what the two legs
    /// above used to build. It is not zenoh's SHM marker, so the payload must
    /// stay a payload — and that is what makes those legs' `0x12` a real
    /// discriminator rather than a value the walker would accept either way.
    #[test]
    fn an_ext_sharing_the_shm_id_without_its_flag_is_not_the_marker() {
        let body = b"real data";
        let plain = msg_put(
            None,
            None,
            &[ext_unit(crate::ext_header::body_ext_id::SHM, false)],
            body,
        );

        let mut w = SpanCursor::new(&plain);
        let root = group(
            "MsgPut",
            0,
            plain.len(),
            walk_msg_put(&mut w).expect("walk"),
        );

        assert_eq!(
            raw(&root, "payload"),
            body.to_vec(),
            "only the mandatory UNIT marker means the slot holds an address",
        );
        assert!(root.find("shm_descriptor").is_none());
        // And this build does not NAME it either, which is the same judgement
        // reached twice rather than two judgements that happen to agree:
        // `ext_name` and the SHM check are both keyed on the eid, so a table
        // that ignored the mandatory bit would have called these bytes `shm`
        // while the slot beside them stayed a `payload`.
        assert!(
            root.find("ext_name").is_none(),
            "upstream declares no non-mandatory `0x2` UNIT extension on a Put",
        );
    }

    /// The CONTROL for the leg above: the same message shape with a chain that
    /// carries no SHM marker is still a payload. Without this, renaming every
    /// payload unconditionally would pass.
    #[test]
    fn a_put_without_the_shm_marker_still_has_a_payload() {
        let body = b"real data";
        let plain = msg_put(None, None, &[ext_unit(0x01, false)], body);

        let mut w = SpanCursor::new(&plain);
        let fields = walk_msg_put(&mut w).expect("walk");
        let root = group("MsgPut", 0, plain.len(), fields);

        assert_eq!(raw(&root, "payload"), body.to_vec());
        assert!(
            root.find("shm_descriptor").is_none(),
            "an unmarked put must not claim an SHM descriptor",
        );
    }

    /// R311y605 (F3) — `walk_err`'s SHM path, which was UNWITNESSED.
    ///
    /// `payload_or_shm_descriptor` was applied to both `walk_msg_put` and
    /// `walk_err` in R311y597 and only the Put got a test. The Err arm is the
    /// same three lines over a DIFFERENT header layout — Err has no `T`
    /// timestamp bit, so its `E` and `Z` bits sit where Put's `E` and `Z` do
    /// but the body in between differs, and a walker that read Put's shape
    /// here would find the chain at the wrong offset and report no marker.
    /// That failure mode is silent: no marker means the descriptor is called a
    /// payload, which is exactly the misreading R311y597 closed for Put.
    #[test]
    fn an_shm_marked_err_does_not_call_its_descriptor_a_payload_either() {
        let descriptor = [0x04u8, 0x07, 0x00];
        // Err: MID 0x05, Z set (the chain carries the marker), E clear.
        let marked = concat(&[
            alloc::vec![0x05u8 | 0x80],
            ext_unit(SHM_MARKER_BYTE, false),
            vle(descriptor.len() as u64),
            descriptor.to_vec(),
        ]);

        let mut w = SpanCursor::new(&marked);
        let fields = walk_err(&mut w).expect("an SHM-marked err must still walk");
        let root = group("Err", 0, marked.len(), fields);

        assert!(
            root.find("payload").is_none(),
            "the descriptor must not be reachable under the name `payload`",
        );
        let shm = root
            .find("shm_descriptor")
            .expect("the descriptor must be named");
        assert_eq!(shm.value, FieldValue::Opaque);
        assert_eq!(shm.span.end - shm.span.start, descriptor.len());
        assert_eq!(w.remaining(), 0, "the walker left bytes unread");

        // CONTROL: the same shape with a non-SHM ext id is still a payload, so
        // an arm that renamed every Err payload unconditionally fails here.
        let body = b"real data";
        let plain = concat(&[
            alloc::vec![0x05u8 | 0x80],
            ext_unit(0x01, false),
            vle(body.len() as u64),
            body.to_vec(),
        ]);
        let mut w = SpanCursor::new(&plain);
        let fields = walk_err(&mut w).expect("walk");
        let root = group("Err", 0, plain.len(), fields);
        assert_eq!(raw(&root, "payload"), body.to_vec());
        assert!(root.find("shm_descriptor").is_none());
    }

    /// R311y605 (F4) — the linkstate walker's cap divergence, PINNED.
    ///
    /// The walker deliberately does NOT mirror the codec's
    /// `HeaplessVec<_, 64>` bound: refusing to render a large topology hides
    /// exactly what an analyst opened the capture for. So the two disagree
    /// ONE-DIRECTIONALLY by design — the walker accepts advertisements the
    /// codec rejects, never the reverse.
    ///
    /// That was documented and unasserted, which is the weaker half of the
    /// pair: a future round that "fixed the inconsistency" by adding the cap to
    /// the walker would have broken the analyst's case with every test green.
    /// Both directions are asserted here, on the SAME bytes, so the claim is
    /// the divergence rather than either half of it.
    #[test]
    fn the_linkstate_walker_reads_a_topology_the_codec_refuses() {
        use wz_codecs::linkstate_list::LinkstateList;

        // 65 entries: one past the codec's cap. Only the COUNT prefix is
        // hand-written — each record's bytes come from the `Linkstate` codec's
        // own encode, because the list codec cannot ENCODE 65 either and a
        // hand-laid record would test the walker against my reading of the
        // layout (the first attempt at this fixture omitted `links_len` and the
        // walker was right to refuse it).
        const N: usize = 65;
        let one = wz_codecs::linkstate::Linkstate {
            options: 0,
            psid: 7,
            sn: 1,
            zid_len: None,
            zid: None,
            whatami: None,
            num_locators: None,
            locators: None,
            links_len: 0,
            links: sce_forge_runtime::heapless::Vec::new(),
            weights: None,
        }
        .encode_to_vec();
        let mut body = vle(N as u64);
        for _ in 0..N {
            body.extend_from_slice(&one);
        }

        // The CODEC refuses it.
        let mut c = SceCursor::new(&body);
        let codec = LinkstateList::decode(&mut c);
        assert!(
            codec.is_err(),
            "the codec's HeaplessVec<_, 64> must refuse a 65-link advertisement"
        );

        // The WALKER reads it, and reads all 65.
        let mut w = SpanCursor::new(&body);
        let fields = walk_linkstate_list(&mut w).expect("the walker must accept it");
        let root = group("linkstate", 0, w.offset(), fields);
        let entries = match root.find("link_states").map(|f| &f.value) {
            Some(FieldValue::Nested(v)) => v.len(),
            other => panic!("link_states is not nested: {other:?}"),
        };
        assert_eq!(
            entries, N,
            "the walker must render every entry, not the codec's first 64"
        );
        assert_eq!(w.remaining(), 0, "the walker left bytes unread");

        // CONTROL: at 64 the two AGREE, so the divergence above is about the
        // cap and not about the walker reading a different layout entirely.
        let mut body64 = vle(64);
        for _ in 0..64usize {
            body64.extend_from_slice(&one);
        }
        let mut c = SceCursor::new(&body64);
        let by_codec = LinkstateList::decode(&mut c).expect("64 is inside the cap");
        assert_eq!(by_codec.link_states.len(), 64);
        let mut w = SpanCursor::new(&body64);
        walk_linkstate_list(&mut w).expect("the walker reads 64 too");
        assert_eq!(w.remaining(), 0);
    }

    /// A link weight wider than `u16` must TRUNCATE, the way upstream truncates
    /// it, rather than cost the reader the whole topology.
    ///
    /// `zenoh/src/net/codec/linkstate.rs:125` reads the weight as
    /// `let w: u16 = codec.read(reader)?` on the plain `Zenoh080`, whose
    /// `uint_impl!(u16)` derive is `let x: u64 = self.read(reader)?;
    /// Ok(x as u16)`. It TRUNCATES; the codec that REFUSES an out-of-range zint
    /// is `Zenoh080Bounded<u16>`, and this field does not select it.
    #[test]
    fn a_link_weight_wider_than_u16_is_truncated_the_way_upstream_truncates_it() {
        use wz_codecs::linkstate_list::LinkstateList;

        // count=1 / options=WGT / psid=3 / sn=0 / links_len=1 / links=[5] /
        // weights=[65537]. 65537 is VLE 0x81 0x80 0x04 and truncates to 1.
        let body: Vec<u8> = alloc::vec![0x01, 0x08, 0x03, 0x00, 0x01, 0x05, 0x81, 0x80, 0x04];

        let mut w = SpanCursor::new(&body);
        let fields = walk_linkstate_list(&mut w).expect("the walker must read what upstream reads");
        let root = group("linkstate", 0, w.offset(), fields);
        assert_eq!(w.remaining(), 0, "the walker left bytes unread");
        let weights = root
            .find("weights")
            .expect("the WGT block must be rendered");
        let got = match &weights.value {
            FieldValue::Nested(v) => match v.first().map(|f| &f.value) {
                Some(FieldValue::Uint(n)) => *n,
                other => panic!("weight is not a uint: {other:?}"),
            },
            other => panic!("weights is not nested: {other:?}"),
        };
        assert_eq!(
            got, 1,
            "65537 truncates to 1, which is the weight every peer folds in"
        );

        // The whole ENVELOPE is what a refusing read costs: `walk_linkstate_body`
        // declines on any parse error, so one wide field turns a full topology
        // advertisement back into the opaque blob R311y597 closed.
        assert!(
            walk_linkstate_body(&body, 0).is_some(),
            "a wide weight must not cost the reader the topology"
        );

        // The generated CODEC is the routing consumer's reader and must accept
        // what upstream folds into its own routing table. It holds the WIRE
        // value — the field's two widths are two facts, and the codec owns the
        // first one.
        let mut c = SceCursor::new(&body);
        let list = LinkstateList::decode(&mut c).expect("upstream decodes this advertisement");
        let ws = list.link_states[0]
            .weights
            .as_ref()
            .expect("WGT set => weights present");
        assert_eq!(ws[0].weight, 65537, "the codec reads the zint whole");
        assert_eq!(
            wz_codecs::wire_const::linkstate_weight_from_wire(ws[0].weight),
            1,
            "the VALUE width is applied once, by name, at the consumer boundary"
        );
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
        // R311y597 — the filler ids must carry no meaning, because the row is
        // about chain DEPTH. `1..=cap` used to be the range and it contains
        // `0x2`, which in a Put body is the SHM marker's id: the row was
        // building an SHM Put by accident and asserting its descriptor was a
        // payload.
        //
        // The escape it reached for was `(i + 0x10) & 0x1F`, and THAT was worse
        // rather than better — `0x10` is the MANDATORY flag, so `i = 2` produced
        // `0x12`, which is not merely the SHM id but the marker's complete
        // header byte as stock zenoh emits it. It only looked safe because the
        // walker was masking the id with `0x1F` and so read `0x12` as id 18:
        // two defects cancelling, and the fixture certifying the pair.
        //
        // So the filler ids are now chosen by ASKING the table, rather than by
        // arithmetic hoped to land clear of it. A byte the `Put` carrier names
        // nothing for is meaningless by construction, and stays meaningless when
        // upstream adds an extension — the loop moves instead of the comment
        // going stale.
        let meaningless: Vec<u8> = (0x00u8..=0x0f)
            .filter(|id| crate::ext_name::ext_name(crate::ext_name::ExtCarrier::Put, *id).is_none())
            .take(cap)
            .collect();
        assert_eq!(
            meaningless.len(),
            cap,
            "the Put carrier no longer leaves {cap} unassigned UNIT ids; the filler \
             must be chosen from a wider space, not from an assigned one"
        );
        let exact: Vec<Vec<u8>> = meaningless
            .iter()
            .enumerate()
            .map(|(i, id)| ext_unit(*id, i + 1 != cap))
            .collect();
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
                reason,
                session,
                extensions,
                ..
            } => {
                assert_eq!(reason, 2);
                assert_eq!(extensions.len(), 1);
                assert!(!session, "S is clear on this header, so the scope is link");
            }
            other => panic!("not a Close: {other:?}"),
        }

        // R311y839 — the SCOPE flag, on both settings of the same header. It is
        // the field zenoh's receiver branches on (`delete()` vs
        // `del_link(link)`), so a dissection that omits it cannot tell a session
        // teardown from one link of an aggregate leaving. Asserted through the
        // rendered tree AND the decode, because the two are separate readers and
        // this round wired the bit into both.
        for (header, expected) in [(0x03u8, false), (0x03u8 | 0x20, true)] {
            let bytes = alloc::vec![header, 0x00];
            let f = dissect_transport_message(&bytes, 0).expect("close did not dissect");
            assert_eq!(f.name, "Close");
            match f.find("s").map(|field| &field.value) {
                Some(FieldValue::Flag(set)) => assert_eq!(
                    *set, expected,
                    "dissected scope flag for header 0x{header:02X}",
                ),
                other => panic!("Close has no `s` scope flag: {other:?}"),
            }
            match parse_inbound(&bytes).expect("parse_inbound rejected the close") {
                InboundFrame::Close { session, .. } => {
                    assert_eq!(session, expected, "decoded scope for header 0x{header:02X}",)
                }
                other => panic!("not a Close: {other:?}"),
            }
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

    /// Drive `dissect_transport_message` and the generated BODY codec over the
    /// same bytes and reject any disagreement on how much they consumed.
    ///
    /// The transport twin of [`agree`], and it has to be its own helper: a
    /// transport message's header byte is the DISSECTOR's to read, while the
    /// generated body codecs start after it and take the header's flag bits as
    /// arguments. Returns the walked field so the caller can assert values.
    #[track_caller]
    fn agree_transport(
        name: &'static str,
        bytes: &[u8],
        body_consumed: impl FnOnce(u8, &[u8]) -> usize,
    ) -> Field {
        let by_codec = 1 + body_consumed(bytes[0], &bytes[1..]);
        let f = match dissect_transport_message(bytes, 0) {
            Ok(f) => f,
            Err(e) => panic!("{name}: the walker rejected a fixture the codec accepted: {e:?}"),
        };
        assert_eq!(f.name, name, "the walker named it {}", f.name);
        assert_eq!(
            f.span.end, by_codec,
            "{name}: the walker consumed {} bytes, the codec {by_codec}",
            f.span.end
        );
        assert_tiles(&f, 0, by_codec);
        f
    }

    /// R311y605 — the three TRANSPORT MIDs whose walkers had no codec in the
    /// build, judged against the codecs the census now forces `dissect` to
    /// select.
    ///
    /// Join is the one that mattered: ten hand-walked fields, TWO header flags
    /// with unrelated meanings one bit apart (`S` at 0x40 gates the optional
    /// `sn_res` / `batch_size` pair, `T` at 0x20 changes the lease's unit), and
    /// before this round not one test anywhere in the dissect suite. The
    /// fixtures are the CODEC's own encode rather than hand-laid bytes, so a
    /// walker that disagrees with the codec fails here instead of agreeing with
    /// my reading of the layout.
    #[test]
    fn the_transport_walkers_agree_with_their_generated_codecs() {
        use sce_forge_runtime::codec::SceCursor;

        // JOIN with S set, so the optional capability pair is present. Encoded
        // by the codec; the header byte is the dissector's half and is written
        // here because the body codec does not own it.
        let join = wz_codecs::join::Join {
            version: 0x09,
            // whatami = peer (0x01) in the low bits, zid_len-1 = 3 in the high.
            cbyte: (3 << 4) | 0x01,
            zid: &[0xA0, 0xA1, 0xA2, 0xA3],
            sn_res: Some(0x00),
            batch_size: Some(0x1000),
            lease: 10_000,
            next_sn_reliable: 7,
            next_sn_best_effort: 9,
        };
        let mut bytes =
            alloc::vec![wz_codecs::wire_const::T_MID_JOIN | wz_codecs::wire_const::FLAG_T_JOIN_S];
        bytes.extend_from_slice(&join.encode_to_vec(1));
        let f = agree_transport("Join", &bytes, |header, body| {
            let s = u8::from(header & wz_codecs::wire_const::FLAG_T_JOIN_S != 0);
            let mut c = SceCursor::new(body);
            let j = wz_codecs::join::Join::decode(&mut c, s).expect("codec rejected the join");
            assert_eq!(j.zid, &[0xA0, 0xA1, 0xA2, 0xA3]);
            assert_eq!(j.batch_size, Some(0x1000));
            assert_eq!(j.next_sn_reliable, 7);
            body.len() - c.remaining()
        });
        assert_eq!(uint(&f, "version"), 0x09);
        assert_eq!(raw(&f, "zid"), alloc::vec![0xA0, 0xA1, 0xA2, 0xA3]);
        assert_eq!(uint(&f, "batch_size"), 0x1000);
        assert_eq!(uint(&f, "lease"), 10_000);
        assert_eq!(uint(&f, "next_sn_reliable"), 7);
        assert_eq!(uint(&f, "next_sn_best_effort"), 9);
        assert_eq!(bits_of(&f, "whatami"), 0x01);
        assert_eq!(bits_of(&f, "zid_len"), 4);

        // JOIN with S CLEAR — the discriminating arm. The walker must NOT read
        // the two optionals, and the codec agrees on the shorter body. Without
        // this leg a walker that read them unconditionally would still pass the
        // leg above.
        let minimal = wz_codecs::join::Join {
            sn_res: None,
            batch_size: None,
            ..join
        };
        let mut bytes = alloc::vec![wz_codecs::wire_const::T_MID_JOIN];
        bytes.extend_from_slice(&minimal.encode_to_vec(0));
        let f = agree_transport("Join", &bytes, |header, body| {
            let s = u8::from(header & wz_codecs::wire_const::FLAG_T_JOIN_S != 0);
            let mut c = SceCursor::new(body);
            wz_codecs::join::Join::decode(&mut c, s).expect("codec rejected the minimal join");
            body.len() - c.remaining()
        });
        assert!(
            f.find("batch_size").is_none(),
            "an S-clear JOIN must not carry batch_size"
        );
        assert!(
            f.find("sn_res").is_none(),
            "an S-clear JOIN must not carry sn_res"
        );

        // FRAGMENT — R and M set, no Z, so the codec's `sn` + tail payload is
        // the whole body. The walker must leave the payload RAW: it is a slice
        // of a message that does not begin there.
        let frag = wz_codecs::fragment::Fragment {
            sn: 3,
            payload: &[0xDE, 0xAD],
        };
        let mut bytes = alloc::vec![
            wz_codecs::wire_const::T_MID_FRAGMENT
                | wz_codecs::wire_const::FLAG_T_FRAGMENT_R
                | wz_codecs::wire_const::FLAG_T_FRAGMENT_M
        ];
        bytes.extend_from_slice(&frag.encode_to_vec());
        let f = agree_transport("Fragment", &bytes, |_, body| {
            let mut c = SceCursor::new(body);
            let fr = wz_codecs::fragment::Fragment::decode(&mut c).expect("codec rejected");
            assert_eq!(fr.sn, 3);
            assert_eq!(fr.payload, &[0xDE, 0xAD]);
            body.len() - c.remaining()
        });
        assert_eq!(uint(&f, "sn"), 3);
        assert_eq!(raw(&f, "payload"), alloc::vec![0xDE, 0xAD]);

        // KEEP_ALIVE — an empty body. The codec consuming ZERO bytes is the
        // whole claim: a walker that read one would disagree here.
        let bytes = alloc::vec![wz_codecs::wire_const::T_MID_KEEP_ALIVE];
        agree_transport("KeepAlive", &bytes, |_, body| {
            let mut c = SceCursor::new(body);
            wz_codecs::keep_alive::KeepAlive::decode(&mut c).expect("codec rejected");
            body.len() - c.remaining()
        });
    }

    /// R311y605 — the T flag changes the lease's UNIT, and the dissector does
    /// NOT project it.
    ///
    /// Recorded as a test rather than as a comment because it is a real
    /// divergence between two of wz's own readers of the same byte:
    /// [`crate::join_decode::decode_join`] returns milliseconds (it projects
    /// `T`), and the walker reports the raw VLE. Both are right for their
    /// consumer — a field tree must show what is ON the wire, at the offset it
    /// occupies — and an analyst reading `lease` off a dissection of a pico
    /// beacon is reading seconds. Pinned so it is a decision rather than a
    /// surprise.
    #[test]
    fn a_t_flagged_join_dissects_its_lease_in_the_wire_unit() {
        use wz_codecs::wire_const::{FLAG_T_JOIN_T, T_MID_JOIN};

        let join = wz_codecs::join::Join {
            version: 0x09,
            cbyte: 0x01,
            zid: &[0xB0],
            sn_res: None,
            batch_size: None,
            // 10 SECONDS on the wire, which is the pico default beacon's form.
            lease: 10,
            next_sn_reliable: 0,
            next_sn_best_effort: 0,
        };
        let mut bytes = alloc::vec![T_MID_JOIN | FLAG_T_JOIN_T];
        bytes.extend_from_slice(&join.encode_to_vec(0));

        let f = dissect_transport_message(&bytes, 0).expect("join did not dissect");
        assert_eq!(
            uint(&f, "lease"),
            10,
            "the dissection reports the wire VLE, unprojected"
        );
        assert!(
            f.find("t").is_some(),
            "the T flag must be surfaced, or the unit is unknowable from the tree"
        );
        // The decoder projects the same bytes to milliseconds.
        let decoded = crate::join_decode::decode_join(&bytes).expect("decode_join rejected it");
        assert_eq!(decoded.lease, 10_000);
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

    /// Transport OAM (MID 0x00) is a transport message like any other, and
    /// stock zenoh's decoder dispatches it (`zenoh-codec/src/transport/mod.rs`
    /// `id::OAM => TransportBody::OAM`). Its wire shape is NOT the shape the
    /// other transport MIDs have: the encoding of its body lives in header
    /// bits 5..6 rather than in flags, and its ext chain is written BEFORE the
    /// body (`zenoh-codec/src/transport/oam.rs` writes header, id, extensions,
    /// payload in that order) — the opposite of every trailing-chain arm the
    /// transport walker already has.
    #[test]
    fn transport_oam_walks_its_id_extensions_and_encoded_body() {
        // ENC_ZBUF (0b10 << 5) with Z set, an id that needs two VLE bytes so a
        // fixed-width read cannot pass by accident, the MANDATORY `qos`
        // extension upstream declares for this carrier, then the ZBuf body.
        let body = alloc::vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let wire = concat(&[
            alloc::vec![0x40u8 | 0x80],
            vle(300),
            ext_zint(0x1 | 0x10, false, 7),
            vle(body.len() as u64),
            body.clone(),
        ]);
        let f = dissect_transport_message(&wire, 0).expect("oam did not dissect");
        assert_eq!(f.name, "Oam");
        assert_tiles(&f, 0, wire.len());
        assert_eq!(uint(&f, "id"), 300);
        assert_eq!(bits_of(&f, "encoding"), 2);
        assert_eq!(
            f.find("ext_name").map(|x| x.value.clone()),
            Some(FieldValue::Label(Cow::Borrowed("qos"))),
            "the OAM ext chain must be walked against its own carrier",
        );
        // The BODY's `value`, reached as a direct child: an ext entry names its
        // own body `value` too, and it sits earlier in the tree, so a
        // depth-first `find` would answer with the extension's 7 and call that
        // a pass. The distinction is the whole point of walking the chain
        // before the body.
        let body_value = match &f.value {
            FieldValue::Nested(kids) => kids
                .iter()
                .find(|k| k.name == "value")
                .map(|k| k.value.clone()),
            other => panic!("the Oam group is not nested: {other:?}"),
        };
        assert_eq!(body_value, Some(FieldValue::Bytes(body.clone())));

        // ENC_UNIT: no body bytes at all, so the message ends at the id.
        let unit = concat(&[alloc::vec![0x00u8], vle(1)]);
        let f = dissect_transport_message(&unit, 0).expect("unit oam did not dissect");
        assert_eq!(f.name, "Oam");
        assert_eq!(bits_of(&f, "encoding"), 0);
        assert!(f.find("value").is_none(), "a Unit body carries no value");
        assert_tiles(&f, 0, unit.len());

        // ENC_Z64: a single VLE body, read as a number and not as bytes.
        let z64 = concat(&[alloc::vec![0x20u8], vle(2), vle(1_000)]);
        let f = dissect_transport_message(&z64, 0).expect("z64 oam did not dissect");
        assert_eq!(f.name, "Oam");
        assert_eq!(bits_of(&f, "encoding"), 1);
        assert_eq!(uint(&f, "value"), 1_000);
        assert_tiles(&f, 0, z64.len());

        // The RESERVED 0b11 encoding: upstream refuses it, and the DECODER
        // agrees (`InboundParseError::ReservedEncoding`). The dissector does
        // not — a reader holding a capture is owed the bytes and the reason,
        // so the remainder becomes an opaque `body` and the tiling still
        // covers every byte. That difference between the two readers is the
        // point: a participant must refuse what an observer must still show.
        let reserved = concat(&[alloc::vec![0x60u8], vle(3), alloc::vec![0xAAu8, 0xBB]]);
        let f = dissect_transport_message(&reserved, 0).expect("reserved oam did not dissect");
        assert_eq!(f.name, "Oam");
        assert_eq!(bits_of(&f, "encoding"), 3);
        assert_eq!(raw(&f, "body"), alloc::vec![0xAAu8, 0xBB]);
        assert_tiles(&f, 0, reserved.len());
        assert!(matches!(
            crate::inbound::parse_inbound(&reserved),
            Err(crate::parse_error::InboundParseError::ReservedEncoding)
        ));
    }

    // ── R311y890: the ZBuf extension BODIES ──────────────────────────────
    //
    // Before this round the field layer could NAME an extension and not read
    // one: `ext_name` said `source_info` and the bytes under it came back as
    // `value: "20a1b2c3072a"`. Every test below fails against that state, and
    // fails by finding a `value` where a structure should be.
    //
    // Each fixture is minted by the encoder that IS the layout in this tree,
    // so the walker — a second implementation of that layout — is judged
    // against the producer rather than against its author's reading. That is
    // the same rule the linkstate walker was landed under (R311y597).

    /// `source_info` — the origin triple a sample carries, walked.
    ///
    /// Three assertions, each failing a different way. The triple must be READ
    /// (a walker that named the group and left the bytes under it would still
    /// satisfy a `find("source_info").is_some()` check); the entry must no
    /// longer carry a `value` (showing the same bytes twice is how a reader
    /// takes one field for two); and `agree` re-checks the TILING, which is
    /// what catches a body walked at the wrong base offset.
    #[test]
    fn a_source_info_ext_body_is_walked_into_the_origin_triple() {
        let zid = [0xA1u8, 0xB2, 0xC3];
        let body = crate::source_info_ext::encode_source_info_ext_body(&zid, 7, 42);
        let bytes = msg_put(None, None, &[ext_zbuf(0x01, false, &body)], b"x");
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

        let si = f
            .find("source_info")
            .expect("the origin triple must be named");
        assert_eq!(raw(si, "zid"), zid.to_vec());
        assert_eq!(uint(si, "eid"), 7);
        assert_eq!(uint(si, "sn"), 42);
        assert_eq!(bits_of(si, "zid_len_m1"), 2, "3-byte zid is stored as 2");
        assert!(
            si.find("value").is_none(),
            "a walked body must not also be shown as opaque bytes",
        );
    }

    /// `responder_id` — the SAME leading byte and zid, and then it STOPS.
    ///
    /// The discriminator is the absence: this body has no `sn`, so a walker
    /// that reused `source_info`'s would read the byte AFTER the extension as
    /// one. It cannot be caught by asserting the zid and the eid — both are
    /// correct in that failure — so what pins it is `agree`, which compares
    /// the walker's consumed length against the codec's and reds the moment
    /// the walk runs one VLE past the entry.
    #[test]
    fn a_responder_id_ext_body_stops_where_source_info_would_read_an_sn() {
        let zid = [0x0Du8, 0x0E];
        let body = crate::response_build::encode_responder_ext_body(&zid, 11);
        let reply = concat(&[
            alloc::vec![0x04u8 | 0x20],
            alloc::vec![0x01u8],
            msg_put(None, None, &[], b"v"),
        ]);
        let bytes = concat(&[
            alloc::vec![0x1Bu8 | 0x20 | 0x40 | 0x80],
            vle(77),
            wireexpr(2, Some("r")),
            ext_zbuf(0x03, false, &body),
            reply,
        ]);
        let f = agree(
            "Response",
            &bytes,
            |b| {
                let mut c = SceCursor::new(b);
                wz_codecs::response::Response::decode(&mut c).expect("codec rejected fixture");
                b.len() - c.remaining()
            },
            walk_response,
        );

        let rid = f
            .find("responder_id")
            .expect("the responder identity must be named");
        assert_eq!(raw(rid, "zid"), zid.to_vec());
        assert_eq!(uint(rid, "eid"), 11);
        assert!(
            rid.find("sn").is_none(),
            "a responder is an entity, not a sample -- it carries no sn",
        );
        assert!(rid.find("value").is_none());
    }

    /// `query_body` — the ext a reader that looks only at the message body
    /// never finds.
    ///
    /// A `Query` carries its VALUE in an extension, not in a field, so a
    /// dissector that leaves this body opaque cannot show a query's payload at
    /// all. The `schema` leg is deliberate: it makes the walk cross the
    /// encoding's OWN optional field before reaching the payload, so an
    /// encoding walked at the wrong width takes the schema's bytes for the
    /// payload and the two assertions disagree.
    #[test]
    fn a_query_value_ext_body_is_walked_into_its_encoding_and_payload() {
        let mut body = encoding(7, Some("json"));
        body.extend_from_slice(b"{\"k\":1}");
        let bytes = concat(&[alloc::vec![0x03u8 | 0x80], ext_zbuf(0x03, false, &body)]);

        let mut c = SpanCursor::new(&bytes);
        let f = group(
            "Query",
            0,
            bytes.len(),
            walk_query(&mut c).expect("the walker rejected its own fixture"),
        );
        assert_eq!(c.remaining(), 0, "the fill-to-end chain left bytes unread");
        assert_tiles(&f, 0, bytes.len());

        let qb = f.find("query_body").expect("the query VALUE must be named");
        assert_eq!(text(qb, "schema"), "json");
        assert_eq!(raw(qb, "payload"), b"{\"k\":1}".to_vec());
        assert!(qb.find("value").is_none());
    }

    /// `wire_expr` — the `Declare` common keyexpr ext, whose suffix is the
    /// REMAINDER of the body rather than a length-prefixed string.
    ///
    /// That difference is the reason it has its own walker, and it is what
    /// this test discriminates: reusing `walk_wireexpr` here would read the
    /// suffix's first byte (`'d'` = 100) as a length and run off the end.
    #[test]
    fn a_declare_keyexpr_ext_body_is_walked_rather_than_shown_as_hex() {
        let entry = crate::declare_ext_keyexpr::build_ext_keyexpr("demo/sub")
            .expect("the ext builder rejected a literal keyexpr");
        let body = match &entry.body {
            wz_codecs::ext_entry::ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => {
                z.value.as_slice().to_vec()
            }
            other => panic!("the keyexpr ext is not a ZBuf: {other:?}"),
        };
        let mut wire = alloc::vec![crate::declare_ext_keyexpr::KEYEXPR_EXT_HEADER];
        wire.extend(vle(body.len() as u64));
        wire.extend_from_slice(&body);

        let mut c = SpanCursor::new(&wire);
        let chain = walk_ext_chain_z(
            &mut c,
            crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH,
            crate::ext_name::ExtCarrier::DeclareCommon,
        )
        .expect("the chain must walk");
        // `extensions`, the name the walkers give a chain -- the field-name
        // census reads this file whole, tests included, so a name invented in
        // a fixture is an invention it reds on. It caught this one.
        let f = group("extensions", 0, wire.len(), chain);
        assert_eq!(c.remaining(), 0);
        assert_tiles(&f, 0, wire.len());

        let we = f.find("wire_expr").expect("the keyexpr body must be named");
        assert_eq!(text(we, "suffix"), "demo/sub");
        assert_eq!(uint(we, "id"), 0, "a literal keyexpr is mapping id 0");
        assert_eq!(bits_of(we, "mapping"), 1, "a fresh literal is LOCAL");
        assert!(we.find("value").is_none());
    }

    /// `timestamp` — the network extension, walked with the SAME walker as the
    /// in-body one.
    ///
    /// Grounded in upstream rather than in the resemblance: zenoh's
    /// `WCodec<(&ext::TimestampType<ID>, bool)>` writes a `ZExtZBufHeader`
    /// and then `self.write(writer, &tstamp.timestamp)` — the ordinary
    /// `Timestamp` codec, which is `zint(time)` then the length-prefixed id
    /// (`zenoh-codec/src/network/mod.rs`, `zenoh-codec/src/core/timestamp.rs`).
    /// So this is one layout with two carriers, not two layouts that look
    /// alike, and it may share one walker.
    #[test]
    fn a_timestamp_ext_body_is_walked_with_the_in_body_walker() {
        let zid = [0x11u8, 0x22, 0x33, 0x44];
        let bytes = concat(&[
            alloc::vec![0x1Du8 | 0x80],
            wireexpr(1, None),
            ext_zbuf(0x02, false, &timestamp(0x0123_4567, &zid)),
            msg_put(None, None, &[], b"x"),
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

        let ts = f
            .find("extensions")
            .and_then(|e| e.find("timestamp"))
            .expect("the extension timestamp must be named");
        assert_eq!(uint(ts, "time"), 0x0123_4567);
        assert_eq!(raw(ts, "zid"), zid.to_vec());
        assert!(ts.find("value").is_none());
    }

    // ── R311y894: `Join`'s ZBuf `qos`, the per-priority next-SN table ─────
    //
    // The module doc above listed this body among the three left opaque
    // because upstream "declares a layout this tree does not yet encode".
    // For `qos` that reason was FALSE, and the falsity is why the body
    // stayed unread: `crate::multicast_join::write_join_qos_ext` has written
    // it since R311y227 and `decode_join_qos` reads it back, so the layout
    // has a producer HERE to be judged against — the very condition the
    // reason said was missing.

    /// The sixteen numbers a JOIN qos table carries, `(reliable,
    /// best_effort)` per priority with `Control` (0) first.
    ///
    /// Every one of them is distinct, so a walker that transposes a pair or
    /// reads the table backwards fails on a VALUE rather than on a count.
    /// Two are above 127, so a reader that took these for fixed-width bytes
    /// cannot pass either.
    const JOIN_QOS_TABLE: [(u64, u64); 8] = [
        (10, 11),
        (20, 21),
        (30, 31),
        (40, 41),
        (200, 201),
        (60, 61),
        (70, 71),
        (300, 301),
    ];

    /// A JOIN carrying `pairs` as its mandatory ZBuf `qos` extension.
    ///
    /// The base body is the CODEC's own encode and the ext body is the
    /// tree's own VLE encoder, laid in the order
    /// `crate::multicast_join::write_join_qos_ext` writes. `Z` is set on the
    /// transport header because the chain only exists when it is, and the
    /// ext header is `0x51` — id `0x1`, MANDATORY, ZBuf — which is the eid
    /// `crate::ext_name` matches on.
    ///
    /// The base `next_sn` pair is the `{0, 0}` DECOY a qos beacon writes
    /// (zenoh `multicast/link.rs` sets `next_sn = PrioritySn::DEFAULT` when
    /// the real SNs ride the ext), so a walker that reported the base pair
    /// as the table would show two zeros here and fail on every entry.
    fn join_with_qos_ext(pairs: &[(u64, u64)]) -> Vec<u8> {
        let join = wz_codecs::join::Join {
            version: 0x09,
            cbyte: (3 << 4) | 0x01,
            zid: &[0xA0, 0xA1, 0xA2, 0xA3],
            sn_res: None,
            batch_size: None,
            lease: 10_000,
            next_sn_reliable: 0,
            next_sn_best_effort: 0,
        };
        let mut body = Vec::new();
        for (r, b) in pairs {
            body.extend(vle(*r));
            body.extend(vle(*b));
        }
        let mut bytes =
            alloc::vec![wz_codecs::wire_const::T_MID_JOIN | wz_codecs::wire_const::FLAG_T_Z];
        bytes.extend_from_slice(&join.encode_to_vec(0));
        bytes.extend(ext_zbuf(0x01 | crate::ext_header::EXT_FLAG_M, false, &body));
        bytes
    }

    /// A qos JOIN shaped THE WAY ZENOH-PICO EMITS ONE: the `qos` entry carries
    /// the chain-MORE bit and a `patch` Z64 follows it.
    ///
    /// R311y895. `_z_join_encode` writes the qos header as
    /// `_Z_MSG_EXT_ID_JOIN_QOS | _Z_MSG_EXT_MORE(has_patch)`
    /// (`vendor/zenoh-pico/src/protocol/codec/transport.c:73`) and then emits
    /// `_Z_MSG_EXT_ID_JOIN_PATCH` when `Z_FEATURE_FRAGMENTATION` is on, which
    /// it is by default. So the ONE-ENTRY chain every other fixture here uses
    /// is not the shape a real pico beacon has, and this is the shape the
    /// walker will meet first in the field.
    fn join_with_qos_then_patch(pairs: &[(u64, u64)], patch: u64) -> Vec<u8> {
        let join = wz_codecs::join::Join {
            version: 0x09,
            cbyte: (3 << 4) | 0x01,
            zid: &[0xA0, 0xA1, 0xA2, 0xA3],
            sn_res: None,
            batch_size: None,
            lease: 10_000,
            next_sn_reliable: 0,
            next_sn_best_effort: 0,
        };
        let mut body = Vec::new();
        for (r, b) in pairs {
            body.extend(vle(*r));
            body.extend(vle(*b));
        }
        let mut bytes =
            alloc::vec![wz_codecs::wire_const::T_MID_JOIN | wz_codecs::wire_const::FLAG_T_Z];
        bytes.extend_from_slice(&join.encode_to_vec(0));
        bytes.extend(ext_zbuf(0x01 | crate::ext_header::EXT_FLAG_M, true, &body));
        bytes.extend(ext_zint(0x07, false, patch));
        bytes
    }

    /// The pico shape walks: the table is read AND the chained `patch` after it
    /// is still named and read.
    ///
    /// The discriminator is the SECOND entry. A body walker that consumed one
    /// byte too many would eat the patch header and the chain would end early
    /// — which the one-entry fixtures cannot see, because there is nothing
    /// after them to lose.
    #[test]
    fn a_pico_shaped_join_walks_the_qos_table_and_the_patch_chained_after_it() {
        let bytes = join_with_qos_then_patch(&JOIN_QOS_TABLE, 1);
        let f =
            dissect_transport_message(&bytes, 0).expect("the walker rejected a pico-shaped JOIN");
        assert_eq!(
            f.span.end,
            bytes.len(),
            "the walk must account for every byte of the datagram",
        );
        let exts = f.find("extensions").expect("the chain must be walked");

        let qos = exts.find("qos").expect("the SN table must still be walked");
        let rows: Vec<&Field> = match &qos.value {
            FieldValue::Nested(children) => children
                .iter()
                .filter(|c| c.name == "priority_sn")
                .collect(),
            other => panic!("the qos body must be a group of pairs, not {other:?}"),
        };
        assert_eq!(rows.len(), crate::qos::Priority::NUM);
        assert_eq!(uint(rows[0], "next_sn_reliable"), JOIN_QOS_TABLE[0].0);
        assert_eq!(uint(rows[7], "next_sn_best_effort"), JOIN_QOS_TABLE[7].1);

        // The chain's entries are groups named `ext`; what each one IS is the
        // `ext_name` LABEL inside it, not a field bearing that name. Asserting
        // `find("patch")` would look for a name this dissector never emits.
        let entries: Vec<&Field> = match &exts.value {
            FieldValue::Nested(children) => children.iter().filter(|c| c.name == "ext").collect(),
            other => panic!("the chain must be a group of entries, not {other:?}"),
        };
        let names: Vec<Option<FieldValue>> = entries
            .iter()
            .map(|e| e.find("ext_name").map(|n| n.value.clone()))
            .collect();
        assert_eq!(
            names,
            alloc::vec![
                Some(FieldValue::Label(Cow::Borrowed("qos"))),
                Some(FieldValue::Label(Cow::Borrowed("patch"))),
            ],
            "both chain entries must survive: the walked body and the one after it",
        );
    }

    /// The table is READ, and read as sixteen numbers rather than as hex.
    ///
    /// Three ways to fail, each a different defect. The pairs must carry the
    /// values the producer wrote (a walker off by one VLE reds on the first
    /// entry); the entry must no longer also show `value` (two renderings of
    /// three dozen bytes is how a reader takes one field for another); and
    /// the walk must TILE the datagram, which is what catches a body walked
    /// at the wrong base offset.
    #[test]
    fn a_join_qos_ext_body_is_walked_into_the_per_priority_sn_table() {
        let bytes = join_with_qos_ext(&JOIN_QOS_TABLE);
        let f = dissect_transport_message(&bytes, 0).expect("the walker rejected a qos JOIN");
        assert_eq!(
            f.span.end,
            bytes.len(),
            "the walk must account for every byte of the datagram",
        );

        let qos = f
            .find("extensions")
            .and_then(|e| e.find("qos"))
            .expect("the per-priority SN table must be named");
        assert!(
            qos.find("value").is_none(),
            "a walked body must not also be shown as opaque bytes",
        );

        let pairs: Vec<&Field> = match &qos.value {
            FieldValue::Nested(children) => children
                .iter()
                .filter(|c| c.name == "priority_sn")
                .collect(),
            other => panic!("the qos body must be a group of pairs, not {other:?}"),
        };
        assert_eq!(
            pairs.len(),
            crate::qos::Priority::NUM,
            "one SN pair per priority",
        );
        for (priority, (expected, pair)) in JOIN_QOS_TABLE.iter().zip(pairs.iter()).enumerate() {
            assert_eq!(
                bits_of(pair, "priority"),
                priority as u64,
                "the table is positional and runs Control (0) first",
            );
            assert_eq!(uint(pair, "next_sn_reliable"), expected.0);
            assert_eq!(uint(pair, "next_sn_best_effort"), expected.1);
        }
    }

    /// The CONTROL: a table that is not eight pairs must stay opaque.
    ///
    /// Both directions, because a length check alone catches only one. Seven
    /// pairs runs the walker off the end of the body; nine leaves two VLEs
    /// over after a walk that parsed whole. Either means "not the structure
    /// this build thought", and the honest answer to that is the raw bytes —
    /// not a table with a priority missing, and not one silently truncated.
    #[test]
    fn a_join_qos_body_that_is_not_eight_pairs_stays_opaque() {
        for pair_count in [7usize, 9] {
            let pairs: Vec<(u64, u64)> = (0..pair_count as u64).map(|i| (i, i + 1)).collect();
            let bytes = join_with_qos_ext(&pairs);
            let f = dissect_transport_message(&bytes, 0)
                .expect("a mis-sized qos body may not kill the envelope around it");
            assert_eq!(f.span.end, bytes.len(), "the envelope must still tile");
            let ext = f
                .find("extensions")
                .expect("the chain must still be walked");
            assert!(
                ext.find("priority_sn").is_none(),
                "{pair_count} pairs is not the JOIN qos table and must not be read as one",
            );
            assert!(
                ext.find("value").is_some(),
                "a body that does not walk must come back as raw bytes",
            );
        }
    }

    // ── R311y894: the establishment `shm`, the SECOND body the false reason
    // hid. `crate::extshm::encode_shm_init_syn_body` /
    // `encode_shm_init_ack_body` have produced this layout for as long as the
    // `session-extshm` feature has existed, so it met the walker rule too.

    /// A minimal `Init` — no A, no S — carrying `exts` as its chain.
    ///
    /// Hand-laid, like every envelope in this suite; what has to come from a
    /// producer is the extension BODY, which is the thing under test.
    fn init_with_exts(exts: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes =
            alloc::vec![wz_codecs::wire_const::T_MID_INIT | wz_codecs::wire_const::FLAG_T_Z];
        bytes.push(0x09);
        bytes.push((3 << 4) | 0x01);
        bytes.extend_from_slice(&[0xB0, 0xB1, 0xB2, 0xB3]);
        for e in exts {
            bytes.extend_from_slice(e);
        }
        bytes
    }

    /// The `Init` chain entry for an `shm` ZBuf body — `0x42`, id `0x2`,
    /// OPTIONAL, ZBuf.
    fn init_shm_ext(body: &[u8]) -> Vec<u8> {
        ext_zbuf(0x02, false, body)
    }

    /// The InitSyn half — one VLE, the segment the initiator offers.
    #[test]
    fn an_init_shm_syn_body_is_walked_into_the_segment_it_offers() {
        let bytes = init_with_exts(&[init_shm_ext(&vle(0x0001_2345))]);
        let f = dissect_transport_message(&bytes, 0).expect("the walker rejected an shm Init");
        assert_eq!(f.span.end, bytes.len(), "the walk must tile the datagram");
        let shm = f
            .find("extensions")
            .and_then(|e| e.find("shm"))
            .expect("the establishment shm body must be walked");
        assert_eq!(uint(shm, "alice_segment"), 0x0001_2345);
        assert!(
            shm.find("value").is_none(),
            "a walked body must not also be shown as opaque bytes",
        );
    }

    /// The InitAck half — the challenge the acceptor read out of that segment,
    /// then its own segment.
    ///
    /// The two halves share one eid and one carrier and are told apart by
    /// nothing but their LENGTH, which is why this leg and the one above are
    /// both needed: a walker that always read one VLE would pass the first and
    /// leave a byte over here, and one that always read two would fail the
    /// first outright.
    #[test]
    fn an_init_shm_ack_body_is_walked_into_the_challenge_and_the_segment() {
        let mut body = vle(0xDEAD_BEEF);
        body.extend(vle(0x77));
        let bytes = init_with_exts(&[init_shm_ext(&body)]);
        let f = dissect_transport_message(&bytes, 0).expect("the walker rejected an shm Init");
        assert_eq!(f.span.end, bytes.len(), "the walk must tile the datagram");
        let shm = f
            .find("extensions")
            .and_then(|e| e.find("shm"))
            .expect("the establishment shm body must be walked");
        assert_eq!(uint(shm, "alice_challenge"), 0xDEAD_BEEF);
        assert_eq!(uint(shm, "bob_segment"), 0x77);
        assert!(
            shm.find("alice_segment").is_none(),
            "an ACK offers no segment of Alice's"
        );
        assert!(shm.find("value").is_none());
    }

    /// The CONTROL for the CARRIER, and it is what the guard on the arm buys.
    ///
    /// `Join` declares its own `shm` at the SAME id `0x2` with the SAME ZBuf
    /// encoding, and its layout is not this one — it is the row R311y605's
    /// rule still excludes, because nothing in this tree writes it. A dispatch
    /// keyed on the name alone would read a JOIN's opaque blob as a
    /// segment id and report a handshake that never happened.
    #[test]
    fn a_join_shm_body_is_not_read_as_the_establishment_one() {
        let mut bytes =
            alloc::vec![wz_codecs::wire_const::T_MID_JOIN | wz_codecs::wire_const::FLAG_T_Z];
        let join = wz_codecs::join::Join {
            version: 0x09,
            cbyte: (3 << 4) | 0x01,
            zid: &[0xA0, 0xA1, 0xA2, 0xA3],
            sn_res: None,
            batch_size: None,
            lease: 10_000,
            next_sn_reliable: 0,
            next_sn_best_effort: 0,
        };
        bytes.extend_from_slice(&join.encode_to_vec(0));
        bytes.extend(ext_zbuf(
            0x02 | crate::ext_header::EXT_FLAG_M,
            false,
            &vle(0x0001_2345),
        ));
        let f = dissect_transport_message(&bytes, 0).expect("the walker rejected a JOIN");
        let ext = f.find("extensions").expect("the chain must be walked");
        assert!(
            ext.find("alice_segment").is_none(),
            "a JOIN's shm is a different extension and must not be read as the Init one",
        );
        assert!(
            ext.find("value").is_some(),
            "it must come back as raw bytes"
        );
    }

    /// The walker agrees with THIS TREE'S producer, not with a reading of it.
    ///
    /// The two legs above lay their bodies with the shared `vle` helper, which
    /// makes them a test of the layout as I understand it. This one never lays
    /// a byte: the bodies come from `crate::extshm`'s encoders and the expected
    /// numbers from its decoders, so a walker that agreed with my reading and
    /// not with the producer fails HERE and nowhere else.
    #[cfg(feature = "session-extshm")]
    #[test]
    fn the_shm_walker_agrees_with_this_trees_establishment_producer() {
        let syn = crate::extshm::encode_shm_init_syn_body(0x0001_2345);
        let bytes = init_with_exts(&[init_shm_ext(&syn)]);
        let f = dissect_transport_message(&bytes, 0).expect("the walker rejected a produced Init");
        let shm = f
            .find("extensions")
            .and_then(|e| e.find("shm"))
            .expect("the produced InitSyn body must be walked");
        assert_eq!(
            uint(shm, "alice_segment"),
            u64::from(
                crate::extshm::decode_shm_init_syn_body(&syn).expect("the producer's own decoder")
            ),
        );

        let ack = crate::extshm::encode_shm_init_ack_body(0xDEAD_BEEF, 0x77);
        let bytes = init_with_exts(&[init_shm_ext(&ack)]);
        let f = dissect_transport_message(&bytes, 0).expect("the walker rejected a produced Init");
        let shm = f
            .find("extensions")
            .and_then(|e| e.find("shm"))
            .expect("the produced InitAck body must be walked");
        let (challenge, segment) =
            crate::extshm::decode_shm_init_ack_body(&ack).expect("the producer's own decoder");
        assert_eq!(uint(shm, "alice_challenge"), challenge);
        assert_eq!(uint(shm, "bob_segment"), u64::from(segment));
    }

    /// The CONTROL for the LENGTH: three VLEs is neither half, so it declines.
    #[test]
    fn an_init_shm_body_of_three_vles_stays_opaque() {
        let mut body = vle(1);
        body.extend(vle(2));
        body.extend(vle(3));
        let bytes = init_with_exts(&[init_shm_ext(&body)]);
        let f = dissect_transport_message(&bytes, 0).expect("a mis-sized body may not kill Init");
        let ext = f.find("extensions").expect("the chain must be walked");
        assert!(ext.find("alice_segment").is_none());
        assert!(ext.find("alice_challenge").is_none());
        assert!(
            ext.find("value").is_some(),
            "it must come back as raw bytes"
        );
    }

    /// The CONTROL, and it is what makes the five tests above discriminators
    /// rather than a walker that decodes whatever it is handed.
    ///
    /// `attachment` is USER bytes. The protocol says there is no structure
    /// there, so inventing one would be worse than showing hex — and it sits
    /// at `0x3` on a `Put`, the SAME id `responder_id` occupies on a
    /// `Response`. A dispatch keyed on the eid alone instead of on the
    /// carrier's name for it would walk this body as an identity and report a
    /// zid that nobody sent.
    #[test]
    fn an_attachment_ext_body_is_still_shown_as_bytes() {
        let att = b"\x20user-supplied";
        let bytes = msg_put(None, None, &[ext_zbuf(0x03, false, att)], b"x");
        let mut c = SpanCursor::new(&bytes);
        let f = group(
            "MsgPut",
            0,
            bytes.len(),
            walk_msg_put(&mut c).expect("walk"),
        );
        assert_eq!(
            f.find("ext_name").map(|n| n.value.clone()),
            Some(FieldValue::Label(Cow::Borrowed("attachment"))),
        );
        assert_eq!(raw(&f, "value"), att.to_vec());
        assert!(
            f.find("responder_id").is_none() && f.find("source_info").is_none(),
            "an opaque body must not be walked as an identity that shares its id",
        );
    }

    /// The DAMAGE PROBE: a body that does not walk cleanly DECLINES — the
    /// entry keeps its raw `value` and the message around it still parses.
    ///
    /// Two shapes, and the second is the one a length check alone misses: a
    /// body too short for the zid it announces, and a body that parses whole
    /// and leaves a byte over. Both mean "not the structure this build
    /// thought", and neither may kill the envelope — the rule the linkstate
    /// body established (R311y597).
    #[test]
    fn an_ext_body_that_does_not_walk_cleanly_stays_an_opaque_value() {
        let mut trailing = crate::source_info_ext::encode_source_info_ext_body(&[0xAA], 1, 2);
        trailing.push(0xFF);
        for (body, label) in [
            (
                alloc::vec![0x20u8, 0xA1],
                "announces a 3-byte zid, carries 1",
            ),
            (trailing, "parses whole, one byte left over"),
        ] {
            let bytes = msg_put(None, None, &[ext_zbuf(0x01, false, &body)], b"x");
            let mut c = SpanCursor::new(&bytes);
            let f = group(
                "MsgPut",
                0,
                bytes.len(),
                walk_msg_put(&mut c)
                    .unwrap_or_else(|e| panic!("{label}: the envelope must still walk: {e:?}")),
            );
            assert_tiles(&f, 0, bytes.len());
            assert_eq!(raw(&f, "value"), body, "{label}");
            assert!(
                f.find("source_info").is_none(),
                "{label}: a declined body must not be shown as an origin triple",
            );
            assert_eq!(raw(&f, "payload"), b"x".to_vec(), "{label}");
        }
    }

    // ── R311y896: the auth ext body — the THIRD row the "opaque bytes" reason
    // hid, and it is false in the same shape R311y894 measured. The `0x3` body
    // is not a method's challenge bytes; it is an ext CHAIN of per-method
    // sub-extensions (`crate::auth_dispatch::AuthDispatch::mux` writes it,
    // `..::demux` reads it, and zenoh's own `establishment/ext/auth/mod.rs`
    // reads it as `Vec<ZExtUnknown>`), which is the one structure this
    // dissector already had a walker for.

    /// The `Init` chain entry for an `auth` ZBuf body — `0x43`, id `0x3`,
    /// OPTIONAL, ZBuf.
    fn init_auth_ext(body: &[u8]) -> Vec<u8> {
        ext_zbuf(0x03, false, body)
    }

    /// The ZBuf rows this build deliberately leaves as an opaque `value`, one
    /// row per `(carrier, upstream name)`, each with the reason.
    ///
    /// R311y896, open-debt item 389. These sentences used to be a paragraph in
    /// [`walk_ext_zbuf_body`]'s doc, where nothing could disagree with them —
    /// and they were wrong about `qos`, about `shm` and about `auth`, which is
    /// every row the paragraph ever covered. Here they are a SET, and
    /// [`every_zbuf_row_is_either_walked_or_declared_opaque`] holds the set
    /// against the dispatch both ways round.
    ///
    /// A reason here is still a human judgement — nothing machine-checks that
    /// "the protocol declares no structure" is TRUE. What the sweep removes is
    /// the other half of the failure: a judgement that was right when written
    /// and has since been overtaken now reds, on the round it is overtaken.
    const OPAQUE_ZBUF_BODIES: &[(crate::ext_name::ExtCarrier, &str, &str)] = &[
        (
            crate::ext_name::ExtCarrier::Join,
            "shm",
            "a DIFFERENT extension sharing `0x2` and the ZBuf encoding with the \
             establishment `shm`; upstream declares a layout and nothing in \
             this tree writes it, so a walker would be judged against nothing \
             but its author's reading (R311y605)",
        ),
        (
            crate::ext_name::ExtCarrier::Put,
            "attachment",
            "USER bytes: the protocol declares no structure there, so walking \
             it would be inventing one",
        ),
        (
            crate::ext_name::ExtCarrier::Del,
            "attachment",
            "USER bytes, as on `Put`",
        ),
        (
            crate::ext_name::ExtCarrier::Query,
            "attachment",
            "USER bytes, as on `Put`",
        ),
    ];

    /// EVERY ZBuf row upstream declares is DECIDED: walked by
    /// [`zbuf_body_walker`], or listed in [`OPAQUE_ZBUF_BODIES`] with a reason.
    /// Never both, never neither, and no listed row that does not exist.
    ///
    /// # The three failures this reds on
    ///
    /// * A row `crate::ext_name` gains — a newer zenoh declaring an extension
    ///   this tree has never seen — with nobody deciding what to do about it.
    ///   Today that row would simply render as hex and no one would be told.
    /// * A row that GAINS a walker while its "it is opaque because…" entry
    ///   still stands. This is the shape the class actually fails in: R311y894
    ///   and R311y896 between them found all three of the paragraph's rows
    ///   false, each after hundreds of rounds. With this sweep the stale
    ///   sentence reds on the round the walker lands.
    /// * A row that LOSES its walker, or an opaque entry naming a row upstream
    ///   no longer declares — the same drift read from the other end.
    ///
    /// # Why it asks the dispatch and not the walk
    ///
    /// [`walk_ext_zbuf_body`] returns `None` both for "no walker" and for "the
    /// walker declined these bytes", so a sweep driven through it would need a
    /// VALID body per layout to tell those apart, and would quietly pass every
    /// row for which the author guessed the layout wrong. Asking
    /// [`zbuf_body_walker`] needs no body at all.
    #[test]
    fn every_zbuf_row_is_either_walked_or_declared_opaque() {
        let mut seen: Vec<(crate::ext_name::ExtCarrier, &str)> = Vec::new();
        let mut groups: Vec<&'static str> = Vec::new();
        for carrier in crate::ext_name::ALL_CARRIERS {
            for (_, _, enc, name) in crate::ext_name::rows(*carrier) {
                if *enc != crate::ext_header::EXT_ENC_ZBUF {
                    continue;
                }
                seen.push((*carrier, name));
                if let Some((group_name, _)) = zbuf_body_walker(*carrier, name) {
                    if !groups.contains(&group_name) {
                        groups.push(group_name);
                    }
                }
                let walked = zbuf_body_walker(*carrier, name).is_some();
                let opaque = OPAQUE_ZBUF_BODIES
                    .iter()
                    .any(|(c, n, _)| c == carrier && n == name);
                assert!(
                    walked != opaque,
                    "{carrier:?}/{name}: a ZBuf row must be walked XOR declared \
                     opaque — this one is {}",
                    if walked {
                        "BOTH: it walks and OPAQUE_ZBUF_BODIES still says it \
                         does not, which is the R311y894/R311y896 defect"
                    } else {
                        "NEITHER: nobody decided what this build does with it, \
                         so it renders as hex and says nothing"
                    },
                );
            }
        }
        // ANTI-VACUITY, and a SET rather than a count (R311y897). The old form
        // was `zbuf_rows >= OPAQUE.len() + 5`, which WEAKENS every time a row
        // stops being opaque — exactly the direction this file moves in. The
        // set of group names the dispatch is reachable at says the same thing
        // and cannot be satisfied by an accident: a walker no row selects any
        // more drops out of it, and a new one has to be admitted here on
        // purpose.
        groups.sort_unstable();
        assert_eq!(
            groups,
            alloc::vec![
                "auth",
                "multi_link",
                "multi_link_syn",
                "pubkey",
                "qos",
                "query_body",
                "responder_id",
                "shm",
                "source_info",
                "timestamp",
                "usrpwd",
                "wire_expr",
            ],
            "the sweep must reach every WALKED ZBuf row too, not only the \
             opaque ones",
        );
        // And no entry names a row upstream does not declare — the drift read
        // from the other end, which the loop above cannot see.
        for (carrier, name, why) in OPAQUE_ZBUF_BODIES {
            assert!(
                seen.contains(&(*carrier, name)),
                "{carrier:?}/{name} is declared opaque but is not a ZBuf row of \
                 that carrier any more",
            );
            assert!(!why.is_empty(), "{carrier:?}/{name}: a row needs a reason");
        }
    }

    /// The `ext_name` label of every `ext` group DIRECTLY under `parent`, in
    /// chain order.
    ///
    /// Enumerated rather than searched on purpose: `Field::find` answers with
    /// the first match anywhere below, and a chain is a SEQUENCE whose second
    /// entry is exactly what a mux test is about.
    fn ext_names_in_order(parent: &Field) -> Vec<String> {
        let FieldValue::Nested(children) = &parent.value else {
            return Vec::new();
        };
        children
            .iter()
            .filter(|f| f.name == "ext")
            .map(|f| match f.find("ext_name").map(|n| &n.value) {
                Some(FieldValue::Label(l)) => String::from(l.as_ref()),
                _ => String::from("<unnamed>"),
            })
            .collect()
    }

    /// Whether `parent` has a DIRECT child by this name — the check
    /// `Field::find` cannot make, because a walked auth chain legitimately
    /// contains a `value` several levels down (a pubkey sub-ext body is opaque
    /// and stays so) while the walked entry itself must have none.
    fn has_direct_child(parent: &Field, name: &str) -> bool {
        match &parent.value {
            FieldValue::Nested(children) => children.iter().any(|f| f.name == name),
            _ => false,
        }
    }

    /// The `ext` group whose `ext_name` is `name`, at the TOP level of a walked
    /// chain.
    fn entry_named<'a>(parent: &'a Field, name: &str) -> Option<&'a Field> {
        let FieldValue::Nested(children) = &parent.value else {
            return None;
        };
        children.iter().find(|f| {
            f.name == "ext"
                && matches!(
                    f.find("ext_name").map(|n| &n.value),
                    Some(FieldValue::Label(l)) if l.as_ref() == name,
                )
        })
    }

    /// The auth ext multiplexes N methods into ONE extension, so the body is a
    /// chain and its entries are the methods.
    ///
    /// usrpwd's InitSyn is a UNIT marker and pubkey's is a ZBuf: two encodings
    /// riding one chain, which is why the sub-entry table is keyed on the eid
    /// rather than on the bare method id.
    #[test]
    fn an_auth_ext_body_is_walked_into_the_method_sub_chain_it_multiplexes() {
        let mut body = alloc::vec![0x02u8 | crate::ext_header::EXT_FLAG_Z];
        body.extend(ext_zbuf(0x01, false, b"\xAA\xBB"));
        let bytes = init_with_exts(&[init_auth_ext(&body)]);
        let f = dissect_transport_message(&bytes, 0).expect("the walker rejected an auth Init");
        assert_eq!(f.span.end, bytes.len(), "the walk must tile the datagram");
        let auth = f
            .find("extensions")
            .and_then(|e| e.find("auth"))
            .expect("the auth body must be walked into its method sub-chain");
        assert_eq!(
            ext_names_in_order(auth),
            alloc::vec![String::from("usrpwd"), String::from("pubkey")],
            "both methods this chain carries must be named",
        );
        assert!(
            !has_direct_child(auth, "value"),
            "a walked body must not also be shown as opaque bytes",
        );
    }

    /// One method id, three encodings, and the encoding is what says WHICH
    /// STAGE of the handshake this is.
    ///
    /// usrpwd contributes a UNIT at InitSyn, a Z64 nonce at InitAck and a ZBuf
    /// {user, hmac} at OpenSyn (zenoh `auth/usrpwd.rs` `mod ext`), all on id
    /// `0x2`. A reader handed only "usrpwd" cannot tell an offer from a
    /// challenge; the value is the half that says so, and it must survive.
    #[test]
    fn an_auth_sub_ext_carries_the_stage_its_encoding_names() {
        let mut body = alloc::vec![0x02u8 | crate::ext_header::EXT_ENC_Z64];
        body.extend(vle(0x0BAD_F00D));
        let bytes = init_with_exts(&[init_auth_ext(&body)]);
        let f = dissect_transport_message(&bytes, 0).expect("the walker rejected an auth Init");
        let auth = f
            .find("extensions")
            .and_then(|e| e.find("auth"))
            .expect("the auth body must be walked");
        let usrpwd = entry_named(auth, "usrpwd").expect("the usrpwd sub-ext must be named");
        assert_eq!(bits_of(usrpwd, "encoding"), 1, "a Z64 sub-ext");
        assert_eq!(
            uint(usrpwd, "value"),
            0x0BAD_F00D,
            "the InitAck nonce must reach the reader",
        );
    }

    /// The CARRIER control. `Open` declares the same auth ext at the same id
    /// with the same encoding (`open.rs:121`), so both carriers must walk it —
    /// a guard written against `Init` alone would leave half the handshake
    /// opaque, and the OpenSyn half is the one carrying the credential.
    #[test]
    fn an_open_carriers_auth_body_is_walked_the_same_way() {
        let mut bytes =
            alloc::vec![wz_codecs::wire_const::T_MID_OPEN | wz_codecs::wire_const::FLAG_T_Z];
        bytes.extend(vle(10_000));
        bytes.extend(vle(7));
        bytes.extend(vle(0));
        let mut body = alloc::vec![0x02u8 | crate::ext_header::EXT_ENC_ZBUF];
        body.extend(vle(4));
        body.extend_from_slice(b"user");
        bytes.extend(ext_zbuf(0x03, false, &body));
        let f = dissect_transport_message(&bytes, 0).expect("the walker rejected an auth Open");
        let auth = f
            .find("extensions")
            .and_then(|e| e.find("auth"))
            .expect("an Open's auth body must be walked too");
        assert_eq!(
            ext_names_in_order(auth),
            alloc::vec![String::from("usrpwd")],
        );
    }

    /// The DISCRIMINATOR for the carrier guard, and it is sharper than a
    /// different-length body: these attachment bytes ARE a well-formed ext
    /// chain.
    ///
    /// `0x3` is `Attachment` on a `Put` and `Auth` on an `Init`. A dispatch
    /// keyed on the eid alone would read USER bytes as an auth handshake and
    /// report methods nobody negotiated — and because the bytes parse, no
    /// remainder check would catch it.
    #[test]
    fn user_attachment_bytes_that_parse_as_a_chain_are_not_read_as_auth() {
        let att = alloc::vec![0x02u8 | crate::ext_header::EXT_FLAG_Z, 0x01];
        let bytes = msg_put(None, None, &[ext_zbuf(0x03, false, &att)], b"x");
        let mut c = SpanCursor::new(&bytes);
        let f = group(
            "MsgPut",
            0,
            bytes.len(),
            walk_msg_put(&mut c).expect("walk"),
        );
        assert_eq!(
            f.find("ext_name").map(|n| n.value.clone()),
            Some(FieldValue::Label(Cow::Borrowed("attachment"))),
        );
        assert_eq!(raw(&f, "value"), att);
        assert!(
            f.find("auth").is_none(),
            "an attachment that happens to parse as a chain is still user bytes",
        );
    }

    /// The DAMAGE PROBE: an auth body that is not a clean chain DECLINES —
    /// the entry keeps its raw `value` and the Init around it still parses.
    ///
    /// Two shapes, and the second is the one a parse alone misses: a chain
    /// whose last entry still asks for more, and a chain that terminates
    /// properly and leaves a byte over.
    #[test]
    fn an_auth_body_that_is_not_a_clean_chain_stays_an_opaque_value() {
        for (body, label) in [
            (
                alloc::vec![0x02u8 | crate::ext_header::EXT_FLAG_Z],
                "the Z bit promises an entry that is not there",
            ),
            (alloc::vec![0x02u8, 0xFF], "terminates, one byte left over"),
        ] {
            let bytes = init_with_exts(&[init_auth_ext(&body)]);
            let f = dissect_transport_message(&bytes, 0)
                .unwrap_or_else(|e| panic!("{label}: the envelope must still walk: {e:?}"));
            let ext = f.find("extensions").expect("the chain must be walked");
            assert_eq!(raw(ext, "value"), body, "{label}");
            assert!(
                ext.find("auth").is_none(),
                "{label}: a declined body must not be shown as a method chain",
            );
        }
    }

    /// The walker judged against THIS TREE'S OWN producer rather than against
    /// a hand-laid byte string — the rule every other body in
    /// [`walk_ext_zbuf_body`] is held to.
    ///
    /// `AuthSubExt::into_ext_entry` + `encode_ext_chain` + `encode_auth_ext` is
    /// the exact path `AuthDispatch::mux` takes, so a divergence between the
    /// two layouts reds here rather than on a capture.
    #[cfg(feature = "session-extauth")]
    #[test]
    fn the_auth_walker_agrees_with_this_trees_own_mux() {
        use crate::auth_dispatch::{id, AuthSubExt};
        let inner = alloc::vec![
            AuthSubExt::Unit
                .into_ext_entry(id::USRPWD)
                .expect("usrpwd unit"),
            AuthSubExt::Zbuf(alloc::vec![0xAA, 0xBB, 0xCC])
                .into_ext_entry(id::PUBKEY)
                .expect("pubkey zbuf"),
        ];
        let outer = crate::extauth::encode_auth_ext(&crate::ext_chain::encode_ext_chain(&inner))
            .expect("the auth ext");
        let bytes = init_with_exts(&[crate::ext_chain::encode_ext_chain(&[outer])]);
        let f = dissect_transport_message(&bytes, 0).expect("the walker rejected a muxed Init");
        assert_eq!(f.span.end, bytes.len(), "the walk must tile the datagram");
        let auth = f
            .find("extensions")
            .and_then(|e| e.find("auth"))
            .expect("the producer's own body must walk");
        assert_eq!(
            ext_names_in_order(auth),
            alloc::vec![String::from("usrpwd"), String::from("pubkey")],
        );
        let pubkey = entry_named(auth, "pubkey").expect("the pubkey sub-ext");
        assert_eq!(raw(pubkey, "value"), alloc::vec![0xAA, 0xBB, 0xCC]);
    }

    // ── R311y897: the METHOD bodies one level inside that chain ──────────
    //
    // The four rows the "it is the METHOD's own format, not the protocol's"
    // reason covered. That sentence is true of what is INSIDE each record and
    // was filed against the FRAMING around them, which is the same level
    // confusion R311y894 and R311y896 each found one level up.

    /// One zenoh `ZBuf` record, built through the producer's own
    /// [`crate::vle::write_zbuf`] rather than by hand — so a test cannot
    /// disagree with the encoder about the framing it is asserting on.
    fn zbuf_record(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        crate::vle::write_zbuf(&mut out, bytes);
        out
    }

    /// The walked body group under a named sub-ext of a walked auth chain.
    fn sub_ext_body<'a>(auth: &'a Field, method: &str) -> &'a Field {
        let entry = entry_named(auth, method)
            .unwrap_or_else(|| panic!("the {method} sub-ext must be named"));
        assert!(
            !has_direct_child(entry, "value"),
            "{method}: a walked body must not also be shown as opaque bytes",
        );
        entry
            .find(method)
            .unwrap_or_else(|| panic!("{method}'s body must be walked"))
    }

    /// An `Init` whose auth chain carries ONE sub-ext.
    fn init_with_auth_sub(id: u8, body: &[u8]) -> Vec<u8> {
        init_with_exts(&[init_auth_ext(&ext_zbuf(id, false, body))])
    }

    /// The walked `auth` group of such an `Init`.
    fn auth_of(bytes: &[u8]) -> Field {
        let f = dissect_transport_message(bytes, 0).expect("the walker rejected an auth Init");
        assert_eq!(f.span.end, bytes.len(), "the walk must tile the datagram");
        f.find("extensions")
            .and_then(|e| e.find("auth"))
            .expect("the auth body must be walked")
            .clone()
    }

    /// The credential a capture is opened to read: WHICH user authenticated.
    ///
    /// Before this walker the chain layer named the method and the stage and
    /// then handed over the whole `{user, hmac}` as hex, so a capture of a
    /// rejected handshake could not tell a wrong password from a wrong user.
    #[test]
    fn a_usrpwd_open_syn_body_is_walked_into_the_user_and_the_hmac() {
        let body = concat(&[
            zbuf_record(b"alice"),
            zbuf_record(&[0x01, 0x02, 0x03, 0x04]),
        ]);
        let auth = auth_of(&init_with_auth_sub(0x02, &body));
        let walked = sub_ext_body(&auth, "usrpwd");
        assert_eq!(raw(walked, "user"), b"alice".to_vec());
        assert_eq!(raw(walked, "hmac"), alloc::vec![0x01, 0x02, 0x03, 0x04]);
    }

    /// The same body, produced by THIS TREE'S OWN usrpwd method rather than
    /// laid out by hand — the rule every other walker in
    /// [`walk_ext_zbuf_body`] is held to, and the one the "METHOD's own
    /// format" reason claimed could not be met here.
    ///
    /// `open_recv_init_ack` then `open_open_syn` is the exact pair the live
    /// initiator runs, so a divergence between the encoder and this reading
    /// reds here rather than on a capture.
    #[cfg(feature = "access-extauth-usrpwd")]
    #[test]
    fn the_usrpwd_body_walker_agrees_with_this_trees_own_method() {
        use crate::auth_dispatch::{AuthMethod, AuthSubExt};
        let mut method =
            crate::extauth_usrpwd::UsrPwdMethod::initiator(b"bob".to_vec(), b"hunter2".to_vec());
        method
            .open_recv_init_ack(Some(AuthSubExt::Z64(0x0102_0304_0506_0708)))
            .expect("the InitAck nonce");
        let Some(AuthSubExt::Zbuf(body)) = method.open_open_syn().expect("the OpenSyn") else {
            panic!("usrpwd's OpenSyn is a ZBuf");
        };
        let auth = auth_of(&init_with_auth_sub(0x02, &body));
        let walked = sub_ext_body(&auth, "usrpwd");
        assert_eq!(
            raw(walked, "user"),
            b"bob".to_vec(),
            "the producer's own user must reach the reader",
        );
        assert_eq!(
            raw(walked, "hmac").len(),
            32,
            "HMAC-SHA3-256 is 32 bytes, and the walker must have found the \
             SECOND record rather than the tail of the first",
        );
    }

    /// The pubkey / multilink body's COUNT is which stage of the mutual
    /// challenge-response this is, and the three counts are three namings.
    ///
    /// `wz-runtime-tokio`'s `extauth_pubkey` writes `{n, e}` at InitSyn,
    /// `{n, e, challenge}` at InitAck and `{challenge}` at OpenSyn, all through
    /// the same [`crate::vle::write_zbuf`] this test builds with.
    #[test]
    fn a_pubkey_body_is_named_by_the_stage_its_record_count_says() {
        let n = alloc::vec![0xA1, 0xA2, 0xA3, 0xA4];
        let e = alloc::vec![0x01, 0x00, 0x01];
        let ct = alloc::vec![0xC0, 0xC1, 0xC2, 0xC3, 0xC4];
        // OpenSyn — one record.
        let auth = auth_of(&init_with_auth_sub(0x01, &zbuf_record(&ct)));
        let walked = sub_ext_body(&auth, "pubkey");
        assert_eq!(raw(walked, "challenge"), ct);
        assert!(
            walked.find("pubkey_n").is_none(),
            "a one-record body is the re-encrypted challenge, not a key",
        );
        // InitSyn — two records.
        let auth = auth_of(&init_with_auth_sub(
            0x01,
            &concat(&[zbuf_record(&n), zbuf_record(&e)]),
        ));
        let walked = sub_ext_body(&auth, "pubkey");
        assert_eq!(raw(walked, "pubkey_n"), n);
        assert_eq!(raw(walked, "pubkey_e"), e);
        assert!(
            walked.find("challenge").is_none(),
            "an InitSyn offers a key and carries no challenge yet",
        );
        // InitAck — three records, and the challenge is the LAST one.
        let auth = auth_of(&init_with_auth_sub(
            0x01,
            &concat(&[zbuf_record(&n), zbuf_record(&e), zbuf_record(&ct)]),
        ));
        let walked = sub_ext_body(&auth, "pubkey");
        assert_eq!(raw(walked, "pubkey_n"), n);
        assert_eq!(raw(walked, "pubkey_e"), e);
        assert_eq!(raw(walked, "challenge"), ct);
    }

    /// The `0x4` multilink ext carries the SAME bytes under a different id —
    /// zenoh `.transmute()`s the pubkey FSM's payload onto it with no
    /// re-framing — so the reading must be the same on both carriers.
    ///
    /// Two carriers rather than one because `Init` and `Open` spell the row
    /// differently (`multi_link` / `multi_link_syn`), and a guard written for
    /// one would leave the other half of the exchange as hex.
    #[test]
    fn a_multilink_body_reads_as_the_pubkey_bytes_it_transmutes() {
        let n = alloc::vec![0x11, 0x22, 0x33];
        let e = alloc::vec![0x01, 0x00, 0x01];
        let init = init_with_exts(&[ext_zbuf(
            0x04,
            false,
            &concat(&[zbuf_record(&n), zbuf_record(&e)]),
        )]);
        let f = dissect_transport_message(&init, 0).expect("the walker rejected a multilink Init");
        assert_eq!(f.span.end, init.len(), "the walk must tile the datagram");
        let walked = f
            .find("extensions")
            .and_then(|e| e.find("multi_link"))
            .expect("an Init's multilink body must be walked");
        assert_eq!(raw(walked, "pubkey_n"), n);
        assert_eq!(raw(walked, "pubkey_e"), e);

        let ct = alloc::vec![0xD0, 0xD1];
        let mut open =
            alloc::vec![wz_codecs::wire_const::T_MID_OPEN | wz_codecs::wire_const::FLAG_T_Z];
        open.extend(vle(10_000));
        open.extend(vle(7));
        open.extend(vle(0));
        open.extend(ext_zbuf(0x04, false, &zbuf_record(&ct)));
        let f = dissect_transport_message(&open, 0).expect("the walker rejected a multilink Open");
        let walked = f
            .find("extensions")
            .and_then(|e| e.find("multi_link_syn"))
            .expect("an Open's multilink body must be walked too");
        assert_eq!(raw(walked, "challenge"), ct);
    }

    /// The DISCRIMINATOR, and it is the NAME TABLE rather than the arm guard.
    ///
    /// The same eid `0x42` is the establishment `shm` on an `Init` and the
    /// usrpwd method on the auth chain, and both are ZBuf bodies that parse —
    /// so a reading keyed on the eid alone would report a segment id where a
    /// username is. What separates them is `crate::ext_name`'s per-carrier
    /// row set, which resolves the name BEFORE [`zbuf_body_walker`] is asked.
    ///
    /// Stated this way because it was MEASURED: dropping the `Auth` guard from
    /// the `usrpwd` arm reds nothing at all, so a doc calling this test the
    /// discriminator for that guard would have been claiming more than it
    /// checks. The guard is kept for the reason the arm says; this test is
    /// about the table.
    #[test]
    fn the_same_eid_reads_as_shm_on_an_init_and_as_usrpwd_on_the_auth_chain() {
        let body = concat(&[zbuf_record(b"alice"), zbuf_record(&[0xAB])]);
        let auth = auth_of(&init_with_auth_sub(0x02, &body));
        assert_eq!(
            raw(sub_ext_body(&auth, "usrpwd"), "user"),
            b"alice".to_vec()
        );

        let direct = init_with_exts(&[ext_zbuf(0x02, false, &body)]);
        let f = dissect_transport_message(&direct, 0).expect("the envelope must still walk");
        let ext = f.find("extensions").expect("the chain must be walked");
        assert!(
            ext.find("usrpwd").is_none(),
            "an Init's own 0x2 is the establishment shm, not a credential",
        );
    }

    /// The DAMAGE PROBE. Four shapes that must DECLINE — the entry keeps its
    /// raw `value` and the message around it still parses.
    ///
    /// The last two are the ones a length check alone misses: bodies that are
    /// a whole number of records, but not a number either layout has.
    #[test]
    fn a_method_body_that_is_not_its_layout_stays_an_opaque_value() {
        let rec = zbuf_record(&[0xAA, 0xBB]);
        for (id, method, body, label) in [
            (
                0x02u8,
                "usrpwd",
                rec.clone(),
                "usrpwd is TWO records and this is one",
            ),
            (
                0x02,
                "usrpwd",
                concat(&[rec.clone(), rec.clone(), alloc::vec![0x00]]),
                "two records and a byte left over",
            ),
            (
                0x01,
                "pubkey",
                concat(&[rec.clone(), rec.clone(), rec.clone(), rec.clone()]),
                "four records is no stage of the exchange",
            ),
            (
                0x01,
                "pubkey",
                alloc::vec![0x05, 0x01],
                "a record announcing more bytes than are there",
            ),
        ] {
            let bytes = init_with_auth_sub(id, &body);
            let f = dissect_transport_message(&bytes, 0)
                .unwrap_or_else(|e| panic!("{label}: the envelope must still walk: {e:?}"));
            let auth = f
                .find("extensions")
                .and_then(|e| e.find("auth"))
                .unwrap_or_else(|| panic!("{label}: the chain must still walk"));
            let entry = entry_named(auth, method).unwrap_or_else(|| panic!("{label}: the sub-ext"));
            assert_eq!(raw(entry, "value"), body, "{label}");
            assert!(
                entry.find(method).is_none(),
                "{label}: a declined body must not be shown as a layout",
            );
        }
    }
}

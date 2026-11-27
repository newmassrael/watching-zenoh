// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A literal-keyexpr `Put` as the codec's BORROWED `Push`, composed over the
//! caller's own `&str` and `&[u8]` with nothing built on a heap.
//!
//! [`crate::push_build::build_push_literal`] makes the codec's OWNED mirror of the
//! message (a copy of the keyexpr and a copy of the payload), which exists to be
//! encoded and dropped: the borrowed view is what owns `encode`
//! (`try_as_borrowed`), and a send that has the text and the bytes in hand needs
//! nothing in between. The unicast lend-only send has composed it this way since
//! fixed-memory step S4 (`send_push_literal_qos`); the multicast TX of a build with
//! no allocator (`multicast_tx::MulticastTxPut`) is the second caller, and
//! the composition is here so that the two cannot disagree about a byte.
//!
//! The bytes are `build_push_literal`'s: the header is the Push MID with the `N`
//! flag (the `M` flag derives from the `WireexprLocal` arm at encode time), the
//! keyexpr is `id == 0` with the suffix inline, there is no extension, and the body
//! is the bare Put header, no optional field, then the payload.

#[cfg(all(feature = "pubsub-qos", feature = "storage-profile"))]
use sce_forge_runtime::codec::Bounded;
use sce_forge_runtime::codec::CodecError;
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
use sce_forge_runtime::codec::SceSink;
#[cfg(all(feature = "pubsub-qos", feature = "storage-profile"))]
use wz_codecs::ext_zint::ExtZint;
#[cfg(all(feature = "pubsub-qos", feature = "storage-profile"))]
use wz_codecs::lent::{ExtEntry, ExtEntryVariant};
use wz_codecs::lent::{MsgPut, Push, PushVariant, Wireexpr, WireexprLocal, WireexprVariant};
use wz_codecs::msg_put::MsgPutExtensionsHas0x12;

/// The `N` flag of the Push header: a keyexpr suffix rides inline.
const FLAG_PUSH_N: u8 = 0x20;

use crate::codec_owned::sent_suffix as suffix_field;

/// The inline-layout Put that carries `value`, with no timestamp, no encoding and no
/// extension: `LengthOutOfRange` for a payload past the protocol's `u32` length.
fn plain_put(value: &[u8]) -> Result<MsgPut<'_>, CodecError> {
    Ok(MsgPut {
        header: PUT_HEADER,
        payload_len: Some(value.len() as u64),
        extensions_has_0x12: MsgPutExtensionsHas0x12::NotHas0x12 {
            extensions: None,
            payload: crate::codec_owned::sent(value)?,
        },
        ..MsgPut::default()
    })
}

/// The `M` flag of the Push header: the id is in the sender's mapping.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
const FLAG_PUSH_M: u8 = 0x40;

/// A Put's header with no timestamp, no encoding and no extension: the payload
/// follows its length.
const PUT_HEADER: u8 = 0x01;

/// The `Push` that carries `value` to the literal keyexpr `keyexpr_suffix`,
/// borrowing both for `'a`. `LengthOutOfRange` for a key past the protocol's `u16`
/// length or a payload past its `u32` length, which is not sent.
pub fn literal_put<'a>(keyexpr_suffix: &'a str, value: &'a [u8]) -> Result<Push<'a>, CodecError> {
    Ok(Push {
        header: wz_codecs::wire_const::N_MID_PUSH | FLAG_PUSH_N,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(keyexpr_suffix.len() as u64),
                suffix: Some(suffix_field(keyexpr_suffix)?),
            }),
        },
        extensions: None,
        body: PushVariant::CodecZenohMsgPut(plain_put(value)?),
    })
}

/// The `Push` that deletes the literal keyexpr `keyexpr_suffix`, borrowing it for `'a`: the
/// `Push` and `MsgDel` headers [`crate::push_build::build_push_del_literal`] writes, with no
/// owned mirror, for a session with no allocator. Refused as [`literal_put`] refuses a key.
#[cfg(not(feature = "alloc"))]
pub fn literal_del(keyexpr_suffix: &str) -> Result<Push<'_>, CodecError> {
    Ok(Push {
        header: wz_codecs::wire_const::N_MID_PUSH | FLAG_PUSH_N,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(keyexpr_suffix.len() as u64),
                suffix: Some(suffix_field(keyexpr_suffix)?),
            }),
        },
        extensions: None,
        body: PushVariant::CodecZenohMsgDel(wz_codecs::lent::MsgDel {
            // The Del's MID, with no timestamp and no extension.
            header: 0x02,
            ..wz_codecs::lent::MsgDel::default()
        }),
    })
}

/// The bytes [`literal_del`] encodes to, for the reason [`literal_put_len`] gives, and zero
/// for a Del it refuses, as [`literal_put_len`] counts a refused Put.
#[cfg(not(feature = "alloc"))]
#[inline(never)]
pub fn literal_del_len(keyexpr_suffix: &str) -> usize {
    literal_del(keyexpr_suffix).map_or(0, |push| wz_codecs::push::PushWire::measure(&push).len())
}

/// The bytes [`literal_put`] encodes to for the same arguments: what a sender asks a link to
/// lend for it, since a `Push` has no size constant (its payload's bound is upstream's u32
/// length). Its own frame, not inlined, so the `Push` it counts is on the stack only while it
/// counts and the sender's frame does not carry it beside the one its encoder builds.
///
/// A Put [`literal_put`] refuses counts as zero: the encoder that follows refuses it with the
/// same error, and the dispatch reports that refusal.
#[cfg(feature = "tx-lend-only")]
#[inline(never)]
pub fn literal_put_len(keyexpr_suffix: &str, value: &[u8]) -> usize {
    literal_put(keyexpr_suffix, value)
        .map_or(0, |push| wz_codecs::push::PushWire::measure(&push).len())
}

/// [`literal_put`] carrying `qos` on the Push's outer extension chain, exactly where
/// [`crate::push_build::build_push_literal_with_meta`] puts it: one ext, id `0x01`, a
/// `ZINT` body, and the Push header's `Z` bit. The DEFAULT byte rides no extension, so a
/// plain publish stays wire-identical to the metadata-stripped baseline (pico's
/// `has_qos_ext = msg->_qos._val != _Z_N_QOS_DEFAULT._val`), and a build without
/// `pubsub-qos` carries none, as the owned builder does.
///
/// The chain is a fixed-capacity vector on the stack, so a Put with QoS is composed over the
/// caller's own text and bytes with nothing built on a heap; the owned builder costs three
/// allocations and a copy of each input per message, to be encoded once and dropped.
///
/// `QosLevel` lives in `sample`, which only a build with a storage profile has, so this and the
/// three composers below are absent without one.
#[cfg(feature = "storage-profile")]
pub fn literal_put_with_qos<'a>(
    keyexpr_suffix: &'a str,
    value: &'a [u8],
    qos: crate::sample::QosLevel,
) -> Result<Push<'a>, CodecError> {
    put_with_qos(0, Some(keyexpr_suffix), value, qos)
}

/// The same Put on a keyexpr the sender declared: `mapping_id`, then `suffix` when the key
/// is the declaration with something appended
/// ([`crate::push_build::build_push_aliased_with_meta`]'s bytes). With no suffix the Push
/// header's `N` flag is clear and the wire carries the id alone, which is what makes an
/// aliased publish cheaper to send and to read than the literal key it stands for.
///
/// `mapping_id` is not zero: that id is the literal key's.
#[cfg(feature = "storage-profile")]
pub fn aliased_put_with_qos<'a>(
    mapping_id: crate::wire_id::ExprId,
    suffix: Option<&'a str>,
    value: &'a [u8],
    qos: crate::sample::QosLevel,
) -> Result<Push<'a>, CodecError> {
    debug_assert!(mapping_id != 0, "id 0 is the literal key, not an alias");
    put_with_qos(mapping_id, suffix, value, qos)
}

/// The one composition behind [`literal_put_with_qos`] and [`aliased_put_with_qos`]: a Put on
/// `(mapping_id, suffix)`, the `N` flag set exactly when a suffix rides. Refused as
/// [`literal_put`] is.
#[cfg(feature = "storage-profile")]
pub fn put_with_qos<'a>(
    mapping_id: crate::wire_id::ExprId,
    suffix: Option<&'a str>,
    value: &'a [u8],
    qos: crate::sample::QosLevel,
) -> Result<Push<'a>, CodecError> {
    // Mutated only when the QoS extension can ride (`pubsub-qos`).
    #[allow(unused_mut)]
    let mut push = Push {
        header: wz_codecs::wire_const::N_MID_PUSH | if suffix.is_some() { FLAG_PUSH_N } else { 0 },
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len: suffix.map(|text| text.len() as u64),
                suffix: suffix.map(suffix_field).transpose()?,
            }),
        },
        extensions: None,
        body: PushVariant::CodecZenohMsgPut(plain_put(value)?),
    };
    #[cfg(feature = "pubsub-qos")]
    if qos != crate::sample::QosLevel::DEFAULT {
        // One extension: no `Z` bit on it, which only says another follows.
        push.extensions = Some(Bounded::one(ExtEntry {
            // ENC_ZINT(0x20) | id_qos(0x01); no `M`, qos is informational.
            header: 0x20 | 0x01,
            body: ExtEntryVariant::CodecZenohExtZint(ExtZint {
                value: u64::from(qos.raw),
            }),
        }));
        // The Push header says an outer chain follows.
        push.header |= 0x80;
    }
    #[cfg(not(feature = "pubsub-qos"))]
    let _ = qos;
    Ok(push)
}

/// The bytes of [`put_with_qos`] written straight into `sink`, without composing the codec's
/// `Push` and walking its variants to encode it: the Push header, the key (the id, and a suffix
/// with its length), the QoS extension when it rides, the Put header, the payload's length and
/// the payload. The two are the same bytes for every input (see the equality test), so the shape
/// stays the codec's, and it refuses what [`put_with_qos`] refuses, with the same
/// `LengthOutOfRange` and before a byte is written. It is [`write_publication`]'s writer for a
/// Put with no body field, which takes that writer's straight path.
///
/// Out of line: a send hands its writer to the link as a `dyn Fn`, whose vtable holds the
/// closure twice (its call and its by-value shim), and each held this writer inlined.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
#[inline(never)]
pub fn write_plain_put<S: sce_forge_runtime::codec::SceSink>(
    sink: &mut S,
    mapping_id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    value: &[u8],
    qos: crate::sample::QosLevel,
) -> Result<(), CodecError>
where
    CodecError: From<S::Error>,
{
    #[cfg(test)]
    WRITER_RUNS.with(|runs| runs.set(runs.get() + 1));
    write_push(sink, mapping_id, suffix, true, value, qos, &BodyParts::NONE)
}

/// The bytes [`write_plain_put`] writes for the same arguments, worked out from the parts with
/// nothing written: what a send asks its link to lend, so the Put is written once, into the slot,
/// and not first into a sink that only counts. Zero for a Put the writer refuses, which the encode
/// that follows refuses with the same error.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
pub fn plain_put_len(
    mapping_id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    value: &[u8],
    qos: crate::sample::QosLevel,
) -> usize {
    plain_push_len(mapping_id, suffix, true, value, qos)
}

/// The bytes [`write_publication`] writes for the same arguments, worked out from the parts with
/// nothing written, for a publication that carries no body field and starts no timestamp stack
/// (the plain Put or Del a stream of samples sends): `Some` of that length, zero for one the
/// writer refuses, as [`plain_put_len`] counts a refused Put. `None` where a field rides, whose
/// length is the writer's to count.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
pub fn publication_len(
    mapping_id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    kind: crate::sample::SampleKind,
    value: &[u8],
    meta: &crate::metadata::PushMetadata,
) -> Option<usize> {
    let put = kind == crate::sample::SampleKind::Put;
    let body = BodyParts::of(put, meta);
    if !body.is_plain() || body.has_stack() {
        return None;
    }
    let qos = meta.qos.unwrap_or(crate::sample::QosLevel::DEFAULT);
    Some(plain_push_len(mapping_id, suffix, put, value, qos))
}

/// The bytes [`write_push`] writes for a Put (`put`) or a Del with no body field, worked out from
/// the parts; zero for one it refuses.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
fn plain_push_len(
    mapping_id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    put: bool,
    value: &[u8],
    qos: crate::sample::QosLevel,
) -> usize {
    if refuses(suffix, put, value) {
        return 0;
    }
    // Saturating, not checked: the parts are a slice's length and a few bytes of fields, which no
    // address space holds past `usize`, and a length that did saturate is one no link lends.
    // The Push header and the key's id, then the suffix with its length when one rides.
    let mut len = vle_len(u64::from(mapping_id)).saturating_add(1);
    if let Some(text) = suffix {
        len = len
            .saturating_add(vle_len(text.len() as u64))
            .saturating_add(text.len());
    }
    // The QoS extension's header and its value.
    if qos_rides(qos) {
        len = len
            .saturating_add(1)
            .saturating_add(vle_len(u64::from(qos.raw)));
    }
    // The body's header, then a Put's payload with its length; a Del carries none.
    len = len.saturating_add(1);
    if put {
        len = len
            .saturating_add(vle_len(value.len() as u64))
            .saturating_add(value.len());
    }
    len
}

/// Whether [`write_push`] refuses a Put (`put`) or a Del on `suffix` with no body field: a key
/// past the protocol's `u16` length, or a Put's payload past its `u32` length.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
fn refuses(suffix: Option<&str>, put: bool, value: &[u8]) -> bool {
    suffix.is_some_and(|text| text.len() > usize::from(u16::MAX))
        || (put && u32::try_from(value.len()).is_err())
}

/// Whether the QoS extension rides a plain Put: `pubsub-qos` is built and the byte is not the
/// default one.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
fn qos_rides(qos: crate::sample::QosLevel) -> bool {
    #[cfg(feature = "pubsub-qos")]
    {
        qos != crate::sample::QosLevel::DEFAULT
    }
    #[cfg(not(feature = "pubsub-qos"))]
    {
        let _ = qos;
        false
    }
}

// How many bytes `SceSink::write_vle_u64` writes a value in: the codec crate's one count.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
use wz_codecs::vle::zint_len as vle_len;

/// A Del's header with no timestamp and no extension.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
const DEL_HEADER: u8 = 0x02;

/// Whether a send of a publication from its borrowed parts ([`write_publication`]) may decline it
/// and leave it to the owned message: a session that rewrites the keys it originates
/// (`routing-namespace`), and the network counters, which classify a publication by its owned
/// message (`transport-stats`). A build with neither sends every publication from its parts, so a
/// sender that reads this links no owned form of one.
pub const LENT_PUBLICATION_MAY_DECLINE: bool = cfg!(any(
    feature = "routing-namespace",
    feature = "transport-stats"
));

/// The body fields of a publication the build writes, read from its metadata under the build's
/// feature for each, as the owned builders read them (`push_build`'s gated fields and its body
/// extension chain).
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
struct BodyParts<'m> {
    timestamp: Option<&'m crate::sample::TimestampHint>,
    /// A Put's alone: a Del has no encoding.
    encoding: Option<crate::sample::EncodingRef<'m>>,
    /// Absent where the info names no source, which the owned builder leaves out too.
    source_info: Option<&'m crate::sample::SourceInfo>,
    /// The extension's id, which a Put and a Del number apart, and the bytes.
    attachment: Option<(u8, &'m [u8])>,
    /// The timestamp stack the publication starts, on the outer chain after the QoS.
    #[cfg(feature = "pubsub-ts-stack")]
    stack: Option<&'m crate::ts_stack::TsStack>,
}

#[cfg(all(feature = "storage-profile", feature = "alloc"))]
impl<'m> BodyParts<'m> {
    /// No body field: a plain Put, or a Del with nothing beside its key.
    const NONE: Self = Self {
        timestamp: None,
        encoding: None,
        source_info: None,
        attachment: None,
        #[cfg(feature = "pubsub-ts-stack")]
        stack: None,
    };

    /// Whether no body field rides, which is the case the writer's straight path takes.
    fn is_plain(&self) -> bool {
        self.timestamp.is_none()
            && self.encoding.is_none()
            && self.source_info.is_none()
            && self.attachment.is_none()
    }

    #[cfg_attr(
        not(all(
            feature = "pubsub-timestamp",
            feature = "pubsub-encoding",
            feature = "pubsub-source-info",
            feature = "pubsub-attachment"
        )),
        allow(unused_variables)
    )]
    fn of(put: bool, meta: &'m crate::metadata::PushMetadata) -> Self {
        Self {
            #[cfg(feature = "pubsub-timestamp")]
            timestamp: meta.timestamp,
            #[cfg(not(feature = "pubsub-timestamp"))]
            timestamp: None,
            #[cfg(feature = "pubsub-encoding")]
            encoding: meta.encoding.filter(|_| put),
            #[cfg(not(feature = "pubsub-encoding"))]
            encoding: None,
            #[cfg(feature = "pubsub-source-info")]
            source_info: meta
                .source_info
                .as_ref()
                .filter(|info| !info.zid_prefix().is_empty()),
            #[cfg(not(feature = "pubsub-source-info"))]
            source_info: None,
            #[cfg(feature = "pubsub-attachment")]
            attachment: meta.attachment.map(|bytes| {
                let id = if put {
                    crate::attachment::ATTACHMENT_EXT_ID_PUSH
                } else {
                    crate::attachment::ATTACHMENT_EXT_ID_DEL
                };
                (id, bytes)
            }),
            #[cfg(not(feature = "pubsub-attachment"))]
            attachment: None,
            #[cfg(feature = "pubsub-ts-stack")]
            stack: meta.ts_stack.as_ref(),
        }
    }

    /// Whether a timestamp stack rides the outer chain.
    fn has_stack(&self) -> bool {
        #[cfg(feature = "pubsub-ts-stack")]
        {
            self.stack.is_some()
        }
        #[cfg(not(feature = "pubsub-ts-stack"))]
        {
            false
        }
    }

    /// Whether a field is past the bound the codec holds it to, which the owned builder refuses
    /// with `LengthOutOfRange`: a timestamp's id past 16 bytes, a schema past 255 and an
    /// attachment past the protocol's `u32` length.
    fn refused(&self) -> bool {
        let long_schema = |encoding: crate::sample::EncodingRef<'_>| {
            encoding.schema.is_some_and(|schema| schema.len() > 255)
        };
        self.timestamp.is_some_and(|stamp| stamp.zid.len() > 16)
            || self.encoding.is_some_and(long_schema)
            || self
                .attachment
                .is_some_and(|(_, bytes)| u32::try_from(bytes.len()).is_err())
    }
}

/// A Put or a Del with the metadata its publisher gave it, written straight into `sink` from the
/// caller's own text, bytes and metadata: the bytes of the owned builders
/// ([`crate::push_build::build_push_literal_with_meta`] and its aliased and Del twins) once
/// encoded, with nothing built on a heap and no codec message composed (see the equality test).
/// The key is `(mapping_id, suffix)` as [`write_plain_put`] takes it. Each field rides under the
/// build's feature for it, as the owned builders gate them: the timestamp, a Put's encoding, the
/// source info and the attachment in the body, a QoS byte other than the default on the outer
/// chain. What the owned builders refuse is refused with `LengthOutOfRange` before a byte is
/// written: a key past the protocol's `u16` length, a Put's payload past its `u32` length, and a
/// field past its bound. The timestamp stack a publication starts rides after the QoS.
///
/// Out of line for the reason [`write_plain_put`] is.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
#[inline(never)]
pub fn write_publication<S: sce_forge_runtime::codec::SceSink>(
    sink: &mut S,
    mapping_id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    kind: crate::sample::SampleKind,
    value: &[u8],
    meta: &crate::metadata::PushMetadata,
) -> Result<(), CodecError>
where
    CodecError: From<S::Error>,
{
    let put = kind == crate::sample::SampleKind::Put;
    write_push(
        sink,
        mapping_id,
        suffix,
        put,
        value,
        meta.qos.unwrap_or(crate::sample::QosLevel::DEFAULT),
        &BodyParts::of(put, meta),
    )
}

/// The one writer of a Push of a Put or a Del from its parts, behind [`write_plain_put`] and
/// [`write_publication`]. Out of line, so the two are one compiled writer for each sink.
///
/// The fixed fields are assembled on the stack and handed to the sink in one write each, not a
/// byte at a time: every byte written through a lease is a call that checks the slot's room, and a
/// message is five of them or more. A Put with no body field (the plain Put a stream of samples
/// sends) is four writes at most, the head, the suffix, the tail with the payload's length, and the
/// payload, in one pass with nothing allocated; a message with a body field writes its fields after
/// the same head. The longest head is the header, a nine-byte id and a nine-byte suffix length (19
/// bytes); the longest tail is the QoS extension (its header and a two-byte value), the body's
/// header and a nine-byte length (13 bytes).
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
#[inline(never)]
fn write_push<S: sce_forge_runtime::codec::SceSink>(
    sink: &mut S,
    mapping_id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    put: bool,
    value: &[u8],
    qos: crate::sample::QosLevel,
    body: &BodyParts<'_>,
) -> Result<(), CodecError>
where
    CodecError: From<S::Error>,
{
    if suffix.is_some_and(|text| text.len() > usize::from(u16::MAX))
        || (put && u32::try_from(value.len()).is_err())
        || body.refused()
    {
        return Err(CodecError::LengthOutOfRange);
    }
    let with_qos = qos_rides(qos);
    let with_stack = body.has_stack();
    let mut head = Head::default();
    head.push_key(mapping_id, suffix, with_qos || with_stack)?;
    if let Some(text) = suffix {
        head.flush_into(sink)?;
        sink.write_bytes(text.as_bytes())?;
    }
    if with_qos {
        head.qos_extension(qos, with_stack)?;
    }
    #[cfg(feature = "pubsub-ts-stack")]
    if let Some(stack) = body.stack {
        // The last extension of the outer chain, so no `Z`: its header, its length, its body.
        head.flush_into(sink)?;
        sink.write_u8(crate::ts_stack::TS_STACK_EXT_HEADER)?;
        sink.write_vle_u64(stack.encoded_len() as u64)?;
        stack.write(sink)?;
    }
    head.body_header(put, body)?;
    // The straight path: no body field, so the payload's length closes the tail.
    if body.is_plain() {
        if put {
            head.write_vle_u64(value.len() as u64)?;
        }
        head.flush_into(sink)?;
        if put {
            sink.write_bytes(value)?;
        }
        return Ok(());
    }
    head.flush_into(sink)?;
    if let Some(stamp) = body.timestamp {
        sink.write_vle_u64(stamp.time)?;
        sink.write_vle_u64(stamp.zid.len() as u64)?;
        sink.write_bytes(&stamp.zid)?;
    }
    if let Some(encoding) = body.encoding {
        // The id's low bit says a schema follows.
        sink.write_vle_u32((encoding.packed_id & !1) | u32::from(encoding.schema.is_some()))?;
        if let Some(schema) = encoding.schema {
            sink.write_vle_u64(schema.len() as u64)?;
            sink.write_bytes(schema)?;
        }
    }
    // The body chain: the source info, then the attachment, each a ZBuf entry whose header has
    // the `Z` bit when another entry follows it.
    if let Some(info) = body.source_info {
        let zid = info.zid_prefix();
        let (eid, sn) = (u64::from(info.eid), u64::from(info.sn));
        // ENC_ZBUF(0x40) | id 0x01.
        sink.write_u8(0x41 | if body.attachment.is_some() { 0x80 } else { 0 })?;
        // One byte of the id's length, the id, then the entity and the sequence number. The id
        // has one to sixteen bytes (`BodyParts::of` keeps no other), so its length less one is
        // the byte's high nibble and the sum is a few dozen bytes.
        let extension_len = 1usize
            .saturating_add(zid.len())
            .saturating_add(vle_len(eid))
            .saturating_add(vle_len(sn));
        sink.write_vle_u64(extension_len as u64)?;
        sink.write_u8((zid.len() as u8).saturating_sub(1) << 4)?;
        sink.write_bytes(zid)?;
        sink.write_vle_u64(eid)?;
        sink.write_vle_u64(sn)?;
    }
    if let Some((id, bytes)) = body.attachment {
        sink.write_u8(0x40 | id)?;
        sink.write_vle_u64(bytes.len() as u64)?;
        sink.write_bytes(bytes)?;
    }
    if put {
        sink.write_vle_u64(value.len() as u64)?;
        sink.write_bytes(value)?;
    }
    Ok(())
}

#[cfg(all(test, feature = "storage-profile", feature = "alloc"))]
std::thread_local! {
    /// How many times [`write_plain_put`] ran on this thread: what a test of how often a Put is
    /// written counts, here and in `session_actions`'s lent frame tests.
    pub(crate) static WRITER_RUNS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// The fixed fields of a Push [`write_push`] gathers before it hands them to its sink in one
/// write: a sink of its own, so a field is written by the codec's own writer (`write_vle_u64`
/// byte for byte), and of a room past the longest head and tail (19 and 13 bytes), which it
/// refuses to pass as `BufferOverflow` rather than write outside it.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
#[derive(Default)]
struct Head(sce_forge_runtime::heapless::Vec<u8, 24>);

// The fixed fields, each one body for every sink: the Push writer gathers them, and so does a
// publisher's head (`PutHead::new`), which then needs no writer of a sink of its own.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
impl Head {
    /// The Push's header and the id of its key, with the length of the suffix when the key has
    /// one; `outer` says an outer extension chain follows the key.
    fn push_key(
        &mut self,
        mapping_id: crate::wire_id::ExprId,
        suffix: Option<&str>,
        outer: bool,
    ) -> Result<(), CodecError> {
        let header = wz_codecs::wire_const::N_MID_PUSH
            | if suffix.is_some() { FLAG_PUSH_N } else { 0 }
            // `M`: the id is in the sender's space, which the codec derives from its
            // `WireexprLocal` arm at encode time.
            | FLAG_PUSH_M
            | if outer { 0x80 } else { 0 };
        self.write_u8(header)?;
        self.write_vle_u64(u64::from(mapping_id))?;
        if let Some(text) = suffix {
            self.write_vle_u64(text.len() as u64)?;
        }
        Ok(())
    }

    /// The QoS extension of `qos`, ENC_ZINT(0x20) | id_qos(0x01), with `Z` when `more` (the
    /// timestamp stack) follows it.
    fn qos_extension(
        &mut self,
        qos: crate::sample::QosLevel,
        more: bool,
    ) -> Result<(), CodecError> {
        self.write_u8(0x21 | if more { 0x80 } else { 0 })?;
        self.write_vle_u64(u64::from(qos.raw))
    }

    /// The header of the Put (`put`) or the Del, flagged with the body fields `body` holds.
    fn body_header(&mut self, put: bool, body: &BodyParts<'_>) -> Result<(), CodecError> {
        let extended = body.source_info.is_some() || body.attachment.is_some();
        self.write_u8(
            if put { PUT_HEADER } else { DEL_HEADER }
                | if body.timestamp.is_some() { 0x20 } else { 0 }
                | if body.encoding.is_some() { 0x40 } else { 0 }
                | if extended { 0x80 } else { 0 },
        )
    }

    /// Hand what is gathered to `sink` in one write and start again empty.
    fn flush_into<S: SceSink>(&mut self, sink: &mut S) -> Result<(), CodecError>
    where
        CodecError: From<S::Error>,
    {
        sink.write_bytes(&self.0)?;
        self.0.clear();
        Ok(())
    }
}

#[cfg(all(feature = "storage-profile", feature = "alloc"))]
impl SceSink for Head {
    type Error = CodecError;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        self.0
            .extend_from_slice(bytes)
            .map_err(|_| CodecError::BufferOverflow)
    }

    fn write_u8(&mut self, b: u8) -> Result<(), CodecError> {
        self.0.push(b).map_err(|_| CodecError::BufferOverflow)
    }

    fn position(&self) -> usize {
        self.0.len()
    }
}

/// The bytes of a plain Put on a key a declaration names whole, up to the payload's length: what
/// [`write_plain_put`] writes before that length for `(mapping_id, None, qos)`, written by that
/// writer once, when a publisher's plain way is stated, so a put copies the head and writes only
/// the length and the payload. The room is the longest such head: the header, a three-byte id,
/// the QoS extension's header and its two-byte value, and the Put's header.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PutHead {
    bytes: [u8; PUT_HEAD_ROOM],
    len: u8,
    id: crate::wire_id::ExprId,
    qos: crate::sample::QosLevel,
}

/// The room of a [`PutHead`].
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
const PUT_HEAD_ROOM: usize = 8;

/// The room a [`PutHead`] and the longest length of a payload take together: the head's eight
/// bytes and a `u32`'s five.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
const PUT_ROOM: usize = 13;

#[cfg(all(feature = "storage-profile", feature = "alloc"))]
impl PutHead {
    /// The head of a plain Put on declaration `mapping_id` with `qos`; `None` for the id `0`,
    /// which is the literal key, whose text a head does not hold.
    pub fn new(mapping_id: crate::wire_id::ExprId, qos: crate::sample::QosLevel) -> Option<Self> {
        if mapping_id == 0 {
            return None;
        }
        // A byte that rides no extension is sent as the default one, which is what the send then
        // reads its congestion control and conduit from.
        let qos = if qos_rides(qos) {
            qos
        } else {
            crate::sample::QosLevel::DEFAULT
        };
        // The fields the Push writer writes before a plain Put's payload length, gathered by the
        // writer's own steps where it gathers them: the head is no second compiled writer, and
        // no sink is made for it.
        let with_qos = qos_rides(qos);
        let mut written = Head::default();
        written.push_key(mapping_id, None, with_qos).ok()?;
        if with_qos {
            written.qos_extension(qos, false).ok()?;
        }
        written.body_header(true, &BodyParts::NONE).ok()?;
        let head = &written.0[..];
        let mut bytes = [0u8; PUT_HEAD_ROOM];
        bytes.get_mut(..head.len())?.copy_from_slice(head);
        Some(Self {
            bytes,
            len: u8::try_from(head.len()).ok()?,
            id: mapping_id,
            qos,
        })
    }

    /// The declaration the head names its key by.
    pub fn id(&self) -> crate::wire_id::ExprId {
        self.id
    }

    /// The QoS byte of the Put, the default one when it carries none.
    pub fn qos(&self) -> crate::sample::QosLevel {
        self.qos
    }

    /// Whether this is the head of a Put on `key`: the head's declaration with nothing after it.
    pub fn names(&self, key: crate::wire_key::WireKey<'_>) -> bool {
        matches!(key, crate::wire_key::WireKey::Id(id) if id.get() == self.id)
    }

    /// The bytes [`Self::write`] writes for `value`.
    pub fn len_with(&self, value: &[u8]) -> usize {
        usize::from(self.len)
            .saturating_add(vle_len(value.len() as u64))
            .saturating_add(value.len())
    }

    /// The Put carrying `value` into `sink`: the head and the payload's length in one write, then
    /// the payload, the bytes [`write_plain_put`] writes for the head's key and QoS. A payload past
    /// the protocol's `u32` length is refused with `LengthOutOfRange` before a byte is written, as
    /// that writer refuses it.
    pub fn write<S: SceSink>(&self, sink: &mut S, value: &[u8]) -> Result<(), CodecError>
    where
        CodecError: From<S::Error>,
    {
        let length = u32::try_from(value.len()).map_err(|_| CodecError::LengthOutOfRange)?;
        let head_len = usize::from(self.len);
        let mut out = [0u8; PUT_ROOM];
        if let (Some(to), Some(from)) = (out.get_mut(..head_len), self.bytes.get(..head_len)) {
            to.copy_from_slice(from);
        }
        let length_len = out.get_mut(head_len..).map_or(0, |rest| {
            wz_codecs::vle::encode_zint(rest, u64::from(length))
        });
        sink.write_bytes(
            out.get(..head_len.saturating_add(length_len))
                .unwrap_or(&out),
        )?;
        sink.write_bytes(value)?;
        Ok(())
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::push_build::build_push_literal;

    /// A Put written from its head is the Put the direct writer writes for the head's key and QoS:
    /// for ids of every VLE width, QoS bytes that ride and the one that does not, and payloads
    /// whose lengths take one, two and three VLE bytes; and the length it states is what it
    /// writes. Turned red by a head that differs from the writer's in a byte, or by a payload
    /// length written another way.
    #[test]
    fn a_put_written_from_its_head_is_the_direct_writers_bytes() {
        let mut compared = 0usize;
        for id in [1u16, 127, 128, 300, 16_383, 16_384, 65_535] {
            for raw in [
                0x05u8,
                0x1a,
                0x00,
                0xff,
                crate::sample::QosLevel::DEFAULT.raw,
            ] {
                let qos = crate::sample::QosLevel::from_raw(raw);
                let head = PutHead::new(id, qos).expect("an id that is not the literal's");
                for payload in [
                    &b""[..],
                    &b"x"[..],
                    &[7u8; 127][..],
                    &[9u8; 300][..],
                    &[1u8; 20_000][..],
                ] {
                    let mut want = alloc::vec::Vec::new();
                    write_plain_put(
                        &mut sce_forge_runtime::codec::VecSink::new(&mut want),
                        id,
                        None,
                        payload,
                        qos,
                    )
                    .expect("a Vec grows");
                    let mut got = alloc::vec::Vec::new();
                    head.write(
                        &mut sce_forge_runtime::codec::VecSink::new(&mut got),
                        payload,
                    )
                    .expect("a Vec grows");
                    assert_eq!(
                        got,
                        want,
                        "id {id} qos {raw:#04x} {} payload bytes",
                        payload.len()
                    );
                    assert_eq!(head.len_with(payload), got.len(), "the stated length");
                    compared += 1;
                }
            }
        }
        assert_eq!(compared, 7 * 5 * 5);
    }

    /// The literal key has no head, and a head names its own declaration alone: not that
    /// declaration with a suffix after it, not another declaration, not the literal. Turned red by
    /// a head that would be written for a key it does not name.
    #[test]
    fn a_head_names_its_own_declaration_alone() {
        fn under(
            text: &'static str,
            id: u16,
            literal: &'static str,
        ) -> crate::wire_key::WireKey<'static> {
            let id = crate::wire_key::MappedId::new(id).expect("not zero");
            crate::named_key::NamedKey::under(text, crate::named_key::Prefix::of(id, literal))
                .expect("a key under its declaration")
                .wire()
        }
        let qos = crate::sample::QosLevel::DEFAULT;
        assert_eq!(PutHead::new(0, qos), None, "the literal key has no head");
        let head = PutHead::new(7, qos).expect("a declared id");
        assert_eq!(head.id(), 7);
        assert!(head.names(under("demo/x", 7, "demo/x")));
        assert!(
            !head.names(under("demo/x/y", 7, "demo/x")),
            "a suffix after it"
        );
        assert!(
            !head.names(under("demo/x", 8, "demo/x")),
            "another declaration"
        );
        let literal = crate::named_key::NamedKey::literal("demo/x").expect("a key");
        assert!(!head.names(literal.wire()), "the literal");
    }

    /// The QoS byte a head states is the one its Put carries: a byte that rides its extension is
    /// kept, and without `pubsub-qos` no extension rides, so it is the default one. Turned red by a
    /// head whose send would read a congestion control its bytes do not carry.
    #[test]
    fn a_heads_qos_is_the_byte_its_put_carries() {
        let riding = crate::sample::QosLevel::from_raw(0x1a);
        let head = PutHead::new(7, riding).expect("a declared id");
        #[cfg(feature = "pubsub-qos")]
        assert_eq!(head.qos(), riding);
        #[cfg(not(feature = "pubsub-qos"))]
        assert_eq!(head.qos(), crate::sample::QosLevel::DEFAULT);
        let plain = PutHead::new(7, crate::sample::QosLevel::DEFAULT).expect("a declared id");
        assert_eq!(plain.qos(), crate::sample::QosLevel::DEFAULT);
    }

    /// The worked-out length of a VLE is the bytes the codec's writer writes, at the edges of
    /// every width: one byte up to seven bits, one more for each seven after, and nine past 56.
    #[test]
    fn a_vle_length_is_the_bytes_the_codec_writes() {
        let mut edges = alloc::vec![0u64, 1, u64::MAX];
        for bits in (7..64).step_by(7) {
            edges.push((1u64 << bits) - 1);
            edges.push(1u64 << bits);
        }
        for value in edges {
            let mut bytes = alloc::vec::Vec::new();
            sce_forge_runtime::codec::VecSink::new(&mut bytes)
                .write_vle_u64(value)
                .expect("a Vec grows");
            assert_eq!(vle_len(value), bytes.len(), "the length of {value:#x}");
        }
    }

    /// The head a Push is gathered in refuses a field past its room as a value, and keeps what
    /// it held.
    #[test]
    fn a_head_refuses_a_field_past_its_room() {
        let mut head = Head::default();
        head.write_bytes(&[0u8; 24]).expect("the head's room");
        assert_eq!(head.write_u8(1), Err(CodecError::BufferOverflow));
        assert_eq!(head.position(), 24);
    }

    /// The head writes a VLE in the bytes of the codec's own writer at both ends of every width,
    /// and a VLE past its room is refused whole. Turned red by an encoding that differs from the
    /// trait's writer in a byte, and by a writer that fills the head a byte at a time before it
    /// refuses.
    #[test]
    fn a_head_writes_a_vle_as_the_codec_does_and_refuses_one_whole() {
        let mut edges = alloc::vec![0u64, 1, u64::MAX];
        for bits in (7..64).step_by(7) {
            edges.push((1u64 << bits) - 1);
            edges.push(1u64 << bits);
        }
        for value in edges {
            let mut want = alloc::vec::Vec::new();
            sce_forge_runtime::codec::VecSink::new(&mut want)
                .write_vle_u64(value)
                .expect("a Vec grows");
            let mut head = Head::default();
            head.write_vle_u64(value).expect("the head's room");
            assert_eq!(&head.0[..], &want[..], "the VLE of {value:#x}");
        }
        let mut head = Head::default();
        head.write_bytes(&[0u8; 20]).expect("the head's room");
        assert_eq!(
            head.write_vle_u64(u64::MAX),
            Err(CodecError::BufferOverflow)
        );
        assert_eq!(head.position(), 20, "nothing of the refused VLE is kept");
    }

    /// The direct writer and the codec's encoder write the same bytes: for a literal key and
    /// for an id, with and without a suffix, for the default QoS byte and for others, and for
    /// payloads whose lengths take one, two and three VLE bytes.
    #[test]
    fn the_direct_writer_is_the_codecs_bytes() {
        let mut compared = 0usize;
        // The ids reach every VLE width an `ExprId` takes, the three-byte one included.
        for id in [0u16, 1, 127, 128, 300, 16_383, 16_384, 65_535] {
            for suffix in [
                None,
                Some("a"),
                Some("test/thr"),
                Some("a/much/longer/key/x"),
            ] {
                if id == 0 && suffix.is_none() {
                    continue;
                }
                for raw in [0x05u8, 0x1a, 0x00, 0xff] {
                    let qos = crate::sample::QosLevel::from_raw(raw);
                    for payload in [
                        &b""[..],
                        &b"x"[..],
                        &[7u8; 127][..],
                        &[9u8; 300][..],
                        &[1u8; 20_000][..],
                    ] {
                        let mut want = alloc::vec::Vec::new();
                        put_with_qos(id, suffix, payload, qos)
                            .expect("within the bounds")
                            .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut want))
                            .expect("a Vec grows");
                        let mut got = alloc::vec::Vec::new();
                        write_plain_put(
                            &mut sce_forge_runtime::codec::VecSink::new(&mut got),
                            id,
                            suffix,
                            payload,
                            qos,
                        )
                        .expect("a Vec grows");
                        assert_eq!(
                            got,
                            want,
                            "id {id} suffix {suffix:?} qos {raw:#04x} {} payload bytes",
                            payload.len()
                        );
                        compared += 1;
                    }
                }
            }
        }
        assert!(compared > 500, "{compared}");
    }

    /// The borrowed composition and the owned builder it replaces put the same bytes on
    /// the wire, for the keyexprs and payloads a Put can carry, the empty ones included.
    #[test]
    fn the_borrowed_put_is_the_owned_builders_bytes() {
        let keyexprs = [
            "a",
            "demo/mc",
            "a/very/long/keyexpr/that/needs/more/than/a/byte",
        ];
        let payloads: [&[u8]; 4] = [b"", b"x", b"hello", &[7u8; 300]];
        let mut compared = 0usize;
        for keyexpr in keyexprs {
            for payload in payloads {
                let owned = build_push_literal(keyexpr, payload).expect("a literal Put builds");
                let mut want = alloc::vec::Vec::new();
                owned
                    .try_as_borrowed()
                    .expect("the owned Put has a view")
                    .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut want))
                    .expect("a Vec grows");
                let mut got = alloc::vec::Vec::new();
                literal_put(keyexpr, payload)
                    .expect("within the bounds")
                    .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut got))
                    .expect("a Vec grows");
                assert_eq!(
                    got,
                    want,
                    "keyexpr {keyexpr:?}, {} payload bytes",
                    payload.len()
                );
                compared += 1;
            }
        }
        assert_eq!(compared, keyexprs.len() * payloads.len());
    }

    /// With QoS the borrowed composition and the owned metadata builder put the same bytes
    /// on the wire: the DEFAULT byte rides no extension, and every other byte rides the
    /// outer chain with the Push header's `Z` bit, across the priorities, the congestion
    /// controls and the express bit a publisher sets.
    #[test]
    fn the_borrowed_put_with_qos_is_the_owned_builders_bytes() {
        use crate::metadata::PushMetadata;
        use crate::push_build::build_push_literal_with_meta;
        use crate::sample::QosLevel;

        let mut qos_bytes: alloc::vec::Vec<u8> = (0..=0x1f).collect();
        qos_bytes.push(QosLevel::DEFAULT.raw);
        let payloads: [&[u8]; 3] = [b"", b"x", &[9u8; 700]];
        let mut compared = 0usize;
        let mut with_extension = 0usize;
        for raw in qos_bytes {
            let qos = QosLevel::from_raw(raw);
            for payload in payloads {
                let meta = PushMetadata {
                    qos: Some(qos),
                    ..PushMetadata::default()
                };
                let owned = build_push_literal_with_meta("demo/qos/key", payload, &meta)
                    .expect("a literal Put with QoS builds");
                let mut want = alloc::vec::Vec::new();
                owned
                    .try_as_borrowed()
                    .expect("the owned Put has a view")
                    .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut want))
                    .expect("a Vec grows");
                let mut got = alloc::vec::Vec::new();
                literal_put_with_qos("demo/qos/key", payload, qos)
                    .expect("within the bounds")
                    .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut got))
                    .expect("a Vec grows");
                assert_eq!(
                    got,
                    want,
                    "qos byte {raw:#04x}, {} payload bytes",
                    payload.len()
                );
                if owned.extensions.is_some() {
                    with_extension += 1;
                }
                compared += 1;
            }
        }
        assert!(compared > 0);
        // The control: the extension really rides for the non-default bytes, so the
        // equality above is not two empty chains agreeing.
        #[cfg(feature = "pubsub-qos")]
        assert!(
            with_extension > 0 && with_extension < compared,
            "some bytes carry an extension and the DEFAULT one does not: {with_extension} of {compared}"
        );
        #[cfg(not(feature = "pubsub-qos"))]
        assert_eq!(with_extension, 0);
    }

    /// An aliased Put, with and without a suffix and with and without QoS, is the owned
    /// aliased builder's bytes: the `N` flag rides exactly when a suffix does, and the id is
    /// written as the key.
    #[test]
    fn the_borrowed_aliased_put_is_the_owned_builders_bytes() {
        use crate::metadata::PushMetadata;
        use crate::push_build::build_push_aliased_with_meta;
        use crate::sample::QosLevel;

        let mut compared = 0usize;
        for id in [1u16, 7, 127, 128, 300, 65_535] {
            for suffix in [None, Some("tail"), Some("a/longer/suffix/than/one")] {
                for raw in [QosLevel::DEFAULT.raw, 0x11, 0x1a] {
                    for payload in [&b""[..], &b"x"[..], &[5u8; 400][..]] {
                        let qos = QosLevel::from_raw(raw);
                        let meta = PushMetadata {
                            qos: Some(qos),
                            ..PushMetadata::default()
                        };
                        let owned = build_push_aliased_with_meta(id, suffix, payload, &meta)
                            .expect("an aliased Put builds");
                        let mut want = alloc::vec::Vec::new();
                        owned
                            .try_as_borrowed()
                            .expect("the owned Put has a view")
                            .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut want))
                            .expect("a Vec grows");
                        let mut got = alloc::vec::Vec::new();
                        aliased_put_with_qos(id, suffix, payload, qos)
                            .expect("within the bounds")
                            .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut got))
                            .expect("a Vec grows");
                        assert_eq!(
                            got,
                            want,
                            "id {id}, suffix {suffix:?}, qos {raw:#04x}, {} payload bytes",
                            payload.len()
                        );
                        compared += 1;
                    }
                }
            }
        }
        assert_eq!(compared, 6 * 3 * 3 * 3);
    }

    /// The length a send asks its link for is the bytes the writer writes, for a literal key and
    /// for an id, with and without a suffix, with and without the QoS extension, and for payloads
    /// whose lengths take one, two and three VLE bytes; and zero, as the counted measure gave, for
    /// a Put the writer refuses. The encoder the send hands its link is the writer itself, so with
    /// the same length the link lends the same room and the same bytes are written into it, into
    /// a batch or a frame of their own.
    #[test]
    fn the_worked_out_length_is_the_counted_one() {
        let long = "k".repeat(200);
        let mut compared = 0usize;
        for id in [0u16, 1, 127, 128, 16_383, 16_384, 65_535] {
            for suffix in [
                None,
                Some(""),
                Some("a"),
                Some("demo/thr"),
                Some(long.as_str()),
            ] {
                for raw in [crate::sample::QosLevel::DEFAULT.raw, 0x00, 0x05, 0x1a, 0xff] {
                    let qos = crate::sample::QosLevel::from_raw(raw);
                    for payload in [
                        &b""[..],
                        &b"x"[..],
                        &[7u8; 127][..],
                        &[7u8; 128][..],
                        &[9u8; 16_383][..],
                        &[9u8; 16_384][..],
                    ] {
                        let mut count = sce_forge_runtime::codec::CountSink::new();
                        write_plain_put(&mut count, id, suffix, payload, qos)
                            .expect("within the bounds");
                        let mut written = alloc::vec::Vec::new();
                        write_plain_put(
                            &mut sce_forge_runtime::codec::VecSink::new(&mut written),
                            id,
                            suffix,
                            payload,
                            qos,
                        )
                        .expect("a Vec grows");
                        let len = plain_put_len(id, suffix, payload, qos);
                        assert_eq!(
                            len,
                            count.len(),
                            "id {id} suffix {suffix:?} qos {raw:#04x} {} payload bytes",
                            payload.len()
                        );
                        assert_eq!(len, written.len());
                        compared += 1;
                    }
                }
            }
        }
        assert_eq!(compared, 7 * 5 * 5 * 6);
        let past = "k".repeat(usize::from(u16::MAX) + 1);
        let qos = crate::sample::QosLevel::DEFAULT;
        let mut count = sce_forge_runtime::codec::CountSink::new();
        let counted = match write_plain_put(&mut count, 3, Some(&past), b"x", qos) {
            Ok(()) => count.len(),
            Err(_) => 0,
        };
        assert_eq!(counted, 0, "the counted measure of a refused Put");
        assert_eq!(plain_put_len(3, Some(&past), b"x", qos), counted);
    }

    /// Working out a Put's length runs its writer no times, where the measure it replaces ran the
    /// writer once into a sink that only counts before the send ran it again into the slot: a
    /// plain put is written once. The CONTROL is that measure, counted by the same seam.
    #[test]
    fn working_out_a_puts_length_runs_its_writer_no_times() {
        let qos = crate::sample::QosLevel::DEFAULT;
        let runs = || WRITER_RUNS.with(core::cell::Cell::get);
        let before = runs();
        let len = plain_put_len(0, Some("demo/thr"), b"payload", qos);
        assert_eq!(runs(), before, "no run of the writer to learn the length");
        let mut count = sce_forge_runtime::codec::CountSink::new();
        write_plain_put(&mut count, 0, Some("demo/thr"), b"payload", qos)
            .expect("within the bounds");
        assert_eq!(
            runs(),
            before + 1,
            "CONTROL: the counted measure is a run of the writer"
        );
        assert_eq!(len, count.len());
    }

    /// The length a group's publication is pushed with, worked out from its parts, is the bytes its
    /// writer writes: a Put and a Del, on a literal key and on ids of each VLE width, with and
    /// without a suffix, with QoS bytes that ride and the one that does not, and payloads whose
    /// lengths take one, two and three VLE bytes; zero for a key the writer refuses; and `None`,
    /// the writer's own count, where a body field the build writes rides. Turned red by a worked-out
    /// length that differs from the written one in a byte (`plain_push_len`), or by one given for a
    /// publication whose field it does not count (`publication_len`).
    #[test]
    fn a_publications_worked_out_length_is_the_written_one() {
        use crate::metadata::PushMetadata;
        use crate::sample::{QosLevel, SampleKind};
        let counted = |id: crate::wire_id::ExprId,
                       suffix: Option<&str>,
                       kind: SampleKind,
                       payload: &[u8],
                       meta: &PushMetadata<'_>| {
            let mut count = sce_forge_runtime::codec::CountSink::new();
            match write_publication(&mut count, id, suffix, kind, payload, meta) {
                Ok(()) => count.len(),
                Err(_) => 0,
            }
        };
        let mut compared = 0usize;
        for kind in [SampleKind::Put, SampleKind::Del] {
            for id in [0u16, 1, 128, 16_384] {
                for suffix in [None, Some("a"), Some("demo/thr")] {
                    for raw in [QosLevel::DEFAULT.raw, 0x05, 0x1a] {
                        let meta = PushMetadata {
                            qos: Some(QosLevel::from_raw(raw)),
                            ..PushMetadata::default()
                        };
                        for payload in [&b""[..], &b"x"[..], &[7u8; 128][..], &[9u8; 16_384][..]] {
                            let len = publication_len(id, suffix, kind, payload, &meta)
                                .expect("no body field rides");
                            assert_eq!(
                                len,
                                counted(id, suffix, kind, payload, &meta),
                                "{kind:?} id {id} suffix {suffix:?} qos {raw:#04x} {} bytes",
                                payload.len()
                            );
                            assert!(len > 0);
                            compared += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(compared, 2 * 4 * 3 * 3 * 4);
        let past = "k".repeat(usize::from(u16::MAX) + 1);
        let plain = PushMetadata::default();
        for kind in [SampleKind::Put, SampleKind::Del] {
            assert_eq!(
                publication_len(3, Some(&past), kind, b"x", &plain),
                Some(0),
                "a key past its bound, refused by the writer"
            );
            assert_eq!(counted(3, Some(&past), kind, b"x", &plain), 0);
        }
        let attached = PushMetadata {
            attachment: Some(&b"att"[..]),
            ..PushMetadata::default()
        };
        let len = publication_len(7, None, SampleKind::Put, b"x", &attached);
        assert_eq!(
            len.is_none(),
            cfg!(feature = "pubsub-attachment"),
            "an attachment the build writes is the writer's to count"
        );
        if let Some(len) = len {
            assert_eq!(len, counted(7, None, SampleKind::Put, b"x", &attached));
        }
    }

    /// A key past the protocol's `u16` length is refused with `LengthOutOfRange` by every
    /// composer and by the direct writer, which writes nothing of it; a key at the bound is
    /// written.
    #[test]
    fn a_key_past_its_protocol_bound_is_refused_and_one_at_the_bound_is_not() {
        let qos = crate::sample::QosLevel::DEFAULT;
        let past = "k".repeat(usize::from(u16::MAX) + 1);
        let at = "k".repeat(usize::from(u16::MAX));
        let refused = Some(CodecError::LengthOutOfRange);
        assert_eq!(literal_put(&past, b"x").err(), refused);
        assert_eq!(literal_put_with_qos(&past, b"x", qos).err(), refused);
        assert_eq!(
            aliased_put_with_qos(3, Some(&past), b"x", qos).err(),
            refused
        );
        let mut got = alloc::vec::Vec::new();
        assert_eq!(
            write_plain_put(
                &mut sce_forge_runtime::codec::VecSink::new(&mut got),
                3,
                Some(&past),
                b"x",
                qos,
            )
            .err(),
            refused
        );
        assert!(got.is_empty(), "nothing of a refused Put is written");
        assert!(literal_put(&at, b"x").is_ok());
        write_plain_put(
            &mut sce_forge_runtime::codec::VecSink::new(&mut got),
            3,
            Some(&at),
            b"x",
            qos,
        )
        .expect("a key at the bound is written");
        assert!(!got.is_empty());
    }

    /// A publication with metadata written from its parts is the owned builders' bytes: a Put and
    /// a Del, on a literal key and on an id with and without a suffix, with every combination of
    /// a timestamp, an encoding with and without a schema, a source info, an attachment and a QoS
    /// byte, each as far as the build carries it.
    #[test]
    fn a_publication_written_from_its_parts_is_the_owned_builders_bytes() {
        use crate::metadata::PushMetadata;
        use crate::push_build::{
            build_push_aliased_with_meta, build_push_del_aliased_with_meta,
            build_push_del_literal_with_meta, build_push_literal_with_meta,
        };
        use crate::sample::{EncodingHint, QosLevel, SampleKind, SourceInfo, TimestampHint};

        let keys: [(u16, Option<&str>); 4] = [
            (0, Some("demo/meta/key")),
            (5, None),
            (5, Some("tail")),
            (300, Some("a/longer/suffix")),
        ];
        let payloads: [&[u8]; 2] = [b"", &[9u8; 130]];
        let mut compared = 0usize;
        let (mut shortest, mut longest) = (usize::MAX, 0usize);
        for fields in 0u8..64 {
            let stamp = TimestampHint::new(0x1234_5678_9abc, &[7; 16]).unwrap();
            let encoded = EncodingHint {
                packed_id: 42 << 1,
                schema: (fields & 4 != 0).then(|| b"text/plain;x".to_vec()),
            };
            let meta = PushMetadata {
                timestamp: (fields & 1 != 0).then_some(&stamp),
                encoding: (fields & 2 != 0).then(|| encoded.view()),
                source_info: (fields & 8 != 0)
                    .then(|| SourceInfo::new(&[0xa1, 0xa2, 0xa3], 0x5150, 9001)),
                attachment: (fields & 16 != 0).then_some(&[3u8; 200] as &[u8]),
                qos: (fields & 32 != 0).then(|| QosLevel::from_raw(0x1a)),
                // A publication starts no timestamp stack; a build with the slot states it empty.
                #[cfg(feature = "pubsub-ts-stack")]
                ts_stack: None,
            };
            for (id, suffix) in keys {
                for kind in [SampleKind::Put, SampleKind::Del] {
                    for payload in payloads {
                        let put = kind == SampleKind::Put;
                        let owned = if id == 0 {
                            let key = suffix.expect("a literal key");
                            if put {
                                build_push_literal_with_meta(key, payload, &meta)
                            } else {
                                build_push_del_literal_with_meta(key, &meta)
                            }
                        } else if put {
                            build_push_aliased_with_meta(id, suffix, payload, &meta)
                        } else {
                            build_push_del_aliased_with_meta(id, suffix, &meta)
                        }
                        .expect("within the bounds");
                        let mut want = alloc::vec::Vec::new();
                        owned
                            .try_as_borrowed()
                            .expect("the owned Push has a view")
                            .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut want))
                            .expect("a Vec grows");
                        let mut got = alloc::vec::Vec::new();
                        write_publication(
                            &mut sce_forge_runtime::codec::VecSink::new(&mut got),
                            id,
                            suffix,
                            kind,
                            payload,
                            &meta,
                        )
                        .expect("a Vec grows");
                        assert_eq!(
                            got,
                            want,
                            "fields {fields:#08b} id {id} suffix {suffix:?} {kind:?} {} bytes",
                            payload.len()
                        );
                        if id == 0 && put && payload.is_empty() {
                            shortest = shortest.min(got.len());
                            longest = longest.max(got.len());
                        }
                        compared += 1;
                    }
                }
            }
        }
        assert_eq!(compared, 64 * 4 * 2 * 2);
        // The control: the fields really ride in a build that carries them, so the equality above
        // is not two bare messages agreeing.
        #[cfg(feature = "pubsub-attachment")]
        assert!(longest >= shortest + 200, "{shortest} to {longest}");
        #[cfg(not(any(
            feature = "pubsub-timestamp",
            feature = "pubsub-encoding",
            feature = "pubsub-source-info",
            feature = "pubsub-attachment",
            feature = "pubsub-qos"
        )))]
        assert_eq!(shortest, longest);
    }

    /// What the owned builders refuse the writer refuses before it writes a byte, and what they
    /// build it writes: a key past the protocol's `u16` length and a schema past 255, the schema
    /// refused only in a build that carries the field. A timestamp's id past 16 bytes is no hint
    /// at all: it cannot be made, so neither builder is handed one.
    #[test]
    fn a_publication_the_owned_builders_refuse_is_refused_with_nothing_written() {
        use crate::metadata::PushMetadata;
        use crate::push_build::build_push_aliased_with_meta;
        use crate::sample::{EncodingHint, SampleKind, TimestampHint};

        let past = "k".repeat(usize::from(u16::MAX) + 1);
        assert!(
            TimestampHint::new(1, &[1; 17]).is_none(),
            "an id past 16 bytes is no timestamp"
        );
        let stamp_at = TimestampHint::new(1, &[1; 16]).unwrap();
        let encoding = |len: usize| EncodingHint {
            packed_id: 2,
            schema: Some(alloc::vec![b's'; len]),
        };
        let (encoding_past, encoding_at) = (encoding(256), encoding(255));
        let stamped = |hint| PushMetadata {
            timestamp: Some(hint),
            ..PushMetadata::default()
        };
        let encoded = |hint| PushMetadata {
            encoding: Some(hint),
            ..PushMetadata::default()
        };
        let cases: [(Option<&str>, PushMetadata, bool); 4] = [
            (Some(past.as_str()), PushMetadata::default(), true),
            (Some("k"), stamped(&stamp_at), false),
            (
                Some("k"),
                encoded(encoding_past.view()),
                cfg!(feature = "pubsub-encoding"),
            ),
            (Some("k"), encoded(encoding_at.view()), false),
        ];
        for (suffix, meta, refused) in cases {
            let owned = build_push_aliased_with_meta(3, suffix, b"x", &meta);
            assert_eq!(owned.is_err(), refused, "the owned builder");
            let mut got = alloc::vec::Vec::new();
            let written = write_publication(
                &mut sce_forge_runtime::codec::VecSink::new(&mut got),
                3,
                suffix,
                SampleKind::Put,
                b"x",
                &meta,
            );
            if refused {
                assert_eq!(written, Err(CodecError::LengthOutOfRange));
                assert!(
                    got.is_empty(),
                    "nothing of a refused publication is written"
                );
            } else {
                assert_eq!(written, Ok(()));
                assert!(!got.is_empty());
            }
        }
    }

    /// A Put with no body field is written by `write_publication` on the straight path the plain
    /// writer takes: the same bytes in the same writes, four at most (the head, the suffix, the
    /// tail and the payload), whatever the QoS byte and whether a suffix rides.
    #[test]
    fn a_plain_publication_takes_the_plain_writers_single_pass() {
        use crate::metadata::PushMetadata;
        use crate::sample::{QosLevel, SampleKind};

        struct Writes {
            bytes: alloc::vec::Vec<u8>,
            calls: usize,
        }
        impl sce_forge_runtime::codec::SceSink for Writes {
            type Error = CodecError;
            fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
                self.calls += 1;
                self.bytes.extend_from_slice(bytes);
                Ok(())
            }
            fn write_u8(&mut self, b: u8) -> Result<(), CodecError> {
                self.calls += 1;
                self.bytes.push(b);
                Ok(())
            }
            fn position(&self) -> usize {
                self.bytes.len()
            }
        }
        let fresh = || Writes {
            bytes: alloc::vec::Vec::new(),
            calls: 0,
        };
        for suffix in [None, Some("demo/thr")] {
            for raw in [0x05u8, 0x1a] {
                let qos = QosLevel::from_raw(raw);
                let meta = PushMetadata {
                    qos: Some(qos),
                    ..PushMetadata::default()
                };
                let mut plain = fresh();
                write_plain_put(&mut plain, 3, suffix, b"payload", qos).expect("plain");
                let mut publication = fresh();
                write_publication(
                    &mut publication,
                    3,
                    suffix,
                    SampleKind::Put,
                    b"payload",
                    &meta,
                )
                .expect("publication");
                assert_eq!(publication.bytes, plain.bytes, "{suffix:?} {raw:#04x}");
                assert_eq!(publication.calls, plain.calls, "{suffix:?} {raw:#04x}");
                assert!(plain.calls <= 4, "{} writes", plain.calls);
            }
        }
    }

    /// The flag a sender reads to keep its owned send is the build's: a build with no key
    /// rewriting and no network counters declines no publication, a timestamp stack or not.
    #[test]
    fn a_publication_is_declined_only_where_the_build_reads_its_owned_form() {
        assert_eq!(
            LENT_PUBLICATION_MAY_DECLINE,
            cfg!(feature = "routing-namespace") || cfg!(feature = "transport-stats")
        );
    }

    /// A publication that starts a timestamp stack carries it on the outer chain after the QoS,
    /// the owned builders' bytes, with the QoS and without. Turned red by a stack written in
    /// another place or form, or a chain whose `Z` bits disagree with the owned one.
    #[cfg(feature = "pubsub-ts-stack")]
    #[test]
    fn a_publication_starting_a_timestamp_stack_is_the_owned_builders_bytes() {
        use crate::metadata::PushMetadata;
        use crate::push_build::{build_push_aliased_with_meta, build_push_del_literal_with_meta};
        use crate::sample::{QosLevel, SampleKind};
        use crate::ts_stack::{point, TsStack};
        let mut stack = TsStack::new(point::SEND | point::ROUTE);
        assert!(stack.record(point::SEND, alloc::vec![1, 2, 3, 4], false));
        assert_eq!(stack.encode().len(), stack.encoded_len());
        let mut compared = 0usize;
        for qos in [None, Some(QosLevel::from_raw(0x1a))] {
            let meta = PushMetadata {
                qos,
                ts_stack: Some(stack.clone()),
                ..PushMetadata::default()
            };
            let cases: [(u16, Option<&str>, SampleKind); 2] = [
                (5, Some("tail"), SampleKind::Put),
                (0, Some("demo/ts"), SampleKind::Del),
            ];
            for (id, suffix, kind) in cases {
                let owned = if id == 0 {
                    build_push_del_literal_with_meta("demo/ts", &meta)
                } else {
                    build_push_aliased_with_meta(id, suffix, b"value", &meta)
                }
                .expect("built");
                let mut want = alloc::vec::Vec::new();
                owned
                    .try_as_borrowed()
                    .expect("the owned Push has a view")
                    .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut want))
                    .expect("a Vec grows");
                let mut got = alloc::vec::Vec::new();
                write_publication(
                    &mut sce_forge_runtime::codec::VecSink::new(&mut got),
                    id,
                    suffix,
                    kind,
                    b"value",
                    &meta,
                )
                .expect("a Vec grows");
                assert_eq!(got, want, "{qos:?} {id} {kind:?}");
                compared += 1;
            }
        }
        assert_eq!(compared, 4);
    }
}

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
#[cfg(all(feature = "pubsub-qos", feature = "storage-profile"))]
use sce_forge_runtime::heapless::Vec as HeaplessVec;
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
#[cfg(feature = "storage-profile")]
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
        let mut chain: HeaplessVec<ExtEntry<'a>, 8> = HeaplessVec::new();
        // One extension: no `Z` bit on it, which only says another follows.
        let _ = chain.push(ExtEntry {
            // ENC_ZINT(0x20) | id_qos(0x01); no `M`, qos is informational.
            header: 0x20 | 0x01,
            body: ExtEntryVariant::CodecZenohExtZint(ExtZint {
                value: u64::from(qos.raw),
            }),
        });
        push.extensions =
            Some(Bounded::new(chain).expect("one entry is within the chain's bounds"));
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
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
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
    if refuses(suffix, value) {
        return 0;
    }
    // The Push header and the key's id, then the suffix with its length when one rides.
    let mut len = 1 + vle_len(u64::from(mapping_id));
    if let Some(text) = suffix {
        len += vle_len(text.len() as u64) + text.len();
    }
    // The QoS extension's header and its value.
    if qos_rides(qos) {
        len += 1 + vle_len(u64::from(qos.raw));
    }
    // The Put header, the payload's length and the payload.
    len + 1 + vle_len(value.len() as u64) + value.len()
}

/// Whether [`write_plain_put`] refuses a Put on `suffix` carrying `value`: a key past the
/// protocol's `u16` length or a payload past its `u32` length.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
fn refuses(suffix: Option<&str>, value: &[u8]) -> bool {
    suffix.is_some_and(|text| text.len() > usize::from(u16::MAX))
        || u32::try_from(value.len()).is_err()
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

/// How many bytes [`put_vle`] writes `value` in: seven data bits a byte for the first eight, and
/// a ninth that carries its eight bits whole.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
fn vle_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 && len < 9 {
        value >>= 7;
        len += 1;
    }
    len
}

/// A Del's header with no timestamp and no extension.
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
const DEL_HEADER: u8 = 0x02;

/// Whether a send of a publication from its borrowed parts ([`write_publication`]) may decline it
/// and leave it to the owned message: a session that rewrites the keys it originates
/// (`routing-namespace`), the network counters, which classify a publication by its owned message
/// (`transport-stats`), and a timestamp stack, which the writer does not carry
/// (`pubsub-ts-stack`). A build with none of them sends every publication from its parts, so a
/// sender that reads this links no owned form of one.
pub const LENT_PUBLICATION_MAY_DECLINE: bool = cfg!(any(
    feature = "routing-namespace",
    feature = "transport-stats",
    feature = "pubsub-ts-stack"
));

/// The body fields of a publication the build writes, read from its metadata under the build's
/// feature for each, as the owned builders read them (`push_build`'s gated fields and its body
/// extension chain).
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
struct BodyParts<'m> {
    timestamp: Option<&'m crate::sample::TimestampHint>,
    /// A Put's alone: a Del has no encoding.
    encoding: Option<&'m crate::sample::EncodingHint>,
    /// Absent where the info names no source, which the owned builder leaves out too.
    source_info: Option<&'m crate::sample::SourceInfo>,
    /// The extension's id, which a Put and a Del number apart, and the bytes.
    attachment: Option<(u8, &'m [u8])>,
}

#[cfg(all(feature = "storage-profile", feature = "alloc"))]
impl<'m> BodyParts<'m> {
    /// No body field: a plain Put, or a Del with nothing beside its key.
    const NONE: Self = Self {
        timestamp: None,
        encoding: None,
        source_info: None,
        attachment: None,
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
        }
    }

    /// Whether a field is past the bound the codec holds it to, which the owned builder refuses
    /// with `LengthOutOfRange`: a timestamp's id past 16 bytes, a schema past 255 and an
    /// attachment past the protocol's `u32` length.
    fn refused(&self) -> bool {
        let long_schema = |encoding: &crate::sample::EncodingHint| {
            encoding
                .schema
                .as_ref()
                .is_some_and(|schema| schema.len() > 255)
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
/// field past its bound. A timestamp stack is not written ([`LENT_PUBLICATION_MAY_DECLINE`]).
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
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
    let header = wz_codecs::wire_const::N_MID_PUSH
        | if suffix.is_some() { FLAG_PUSH_N } else { 0 }
        // `M`: the id is in the sender's space, which the codec derives from its
        // `WireexprLocal` arm at encode time.
        | FLAG_PUSH_M
        // The header says an outer extension chain follows.
        | if with_qos { 0x80 } else { 0 };
    let mut head = [0u8; 24];
    let mut used = 0usize;
    head[used] = header;
    used += 1;
    used = put_vle(&mut head, used, u64::from(mapping_id));
    if let Some(text) = suffix {
        used = put_vle(&mut head, used, text.len() as u64);
        sink.write_bytes(&head[..used])?;
        sink.write_bytes(text.as_bytes())?;
        used = 0;
    }
    if with_qos {
        // ENC_ZINT(0x20) | id_qos(0x01), no `Z`: the only extension of the outer chain.
        head[used] = 0x21;
        used += 1;
        used = put_vle(&mut head, used, u64::from(qos.raw));
    }
    let extended = body.source_info.is_some() || body.attachment.is_some();
    head[used] = if put { PUT_HEADER } else { DEL_HEADER }
        | if body.timestamp.is_some() { 0x20 } else { 0 }
        | if body.encoding.is_some() { 0x40 } else { 0 }
        | if extended { 0x80 } else { 0 };
    used += 1;
    // The straight path: no body field, so the payload's length closes the tail.
    if body.is_plain() {
        if put {
            used = put_vle(&mut head, used, value.len() as u64);
        }
        sink.write_bytes(&head[..used])?;
        if put {
            sink.write_bytes(value)?;
        }
        return Ok(());
    }
    sink.write_bytes(&head[..used])?;
    if let Some(stamp) = body.timestamp {
        sink.write_vle_u64(stamp.time)?;
        sink.write_vle_u64(stamp.zid.len() as u64)?;
        sink.write_bytes(&stamp.zid)?;
    }
    if let Some(encoding) = body.encoding {
        // The id's low bit says a schema follows.
        sink.write_vle_u32((encoding.packed_id & !1) | u32::from(encoding.schema.is_some()))?;
        if let Some(schema) = &encoding.schema {
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
        // One byte of the id's length, the id, then the entity and the sequence number.
        sink.write_vle_u64((1 + zid.len() + vle_len(eid) + vle_len(sn)) as u64)?;
        sink.write_u8(((zid.len() as u8) - 1) << 4)?;
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
    /// written counts.
    static WRITER_RUNS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Write `value` as the codec's `vle_u64` at `buf[at..]` and return where it ends: seven data
/// bits a byte with the high bit set while more follow, at most eight such bytes, and a ninth
/// that carries its eight bits whole (`SceSink::write_vle_u64`, byte for byte).
#[cfg(all(feature = "storage-profile", feature = "alloc"))]
fn put_vle(buf: &mut [u8; 24], mut at: usize, mut value: u64) -> usize {
    let mut continued = 0u32;
    while value >= 0x80 && continued < 8 {
        buf[at] = (value as u8 & 0x7f) | 0x80;
        at += 1;
        value >>= 7;
        continued += 1;
    }
    buf[at] = value as u8;
    at + 1
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::push_build::build_push_literal;

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
            let stamp = TimestampHint {
                time: 0x1234_5678_9abc,
                zid: alloc::vec![7; 16],
            };
            let encoded = EncodingHint {
                packed_id: 42 << 1,
                schema: (fields & 4 != 0).then(|| b"text/plain;x".to_vec()),
            };
            let meta = PushMetadata {
                timestamp: (fields & 1 != 0).then_some(&stamp),
                encoding: (fields & 2 != 0).then_some(&encoded),
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
    /// build it writes: a key past the protocol's `u16` length, a timestamp's id past 16 bytes and a
    /// schema past 255, each refused only in a build that carries the field.
    #[test]
    fn a_publication_the_owned_builders_refuse_is_refused_with_nothing_written() {
        use crate::metadata::PushMetadata;
        use crate::push_build::build_push_aliased_with_meta;
        use crate::sample::{EncodingHint, SampleKind, TimestampHint};

        let past = "k".repeat(usize::from(u16::MAX) + 1);
        let stamp = |len: usize| TimestampHint {
            time: 1,
            zid: alloc::vec![1; len],
        };
        let encoding = |len: usize| EncodingHint {
            packed_id: 2,
            schema: Some(alloc::vec![b's'; len]),
        };
        let (stamp_past, stamp_at) = (stamp(17), stamp(16));
        let (encoding_past, encoding_at) = (encoding(256), encoding(255));
        let stamped = |hint| PushMetadata {
            timestamp: Some(hint),
            ..PushMetadata::default()
        };
        let encoded = |hint| PushMetadata {
            encoding: Some(hint),
            ..PushMetadata::default()
        };
        let cases: [(Option<&str>, PushMetadata, bool); 5] = [
            (Some(past.as_str()), PushMetadata::default(), true),
            (
                Some("k"),
                stamped(&stamp_past),
                cfg!(feature = "pubsub-timestamp"),
            ),
            (Some("k"), stamped(&stamp_at), false),
            (
                Some("k"),
                encoded(&encoding_past),
                cfg!(feature = "pubsub-encoding"),
            ),
            (Some("k"), encoded(&encoding_at), false),
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
    /// rewriting, no network counters and no timestamp stack declines no publication.
    #[test]
    fn a_publication_is_declined_only_where_the_build_reads_its_owned_form() {
        assert_eq!(
            LENT_PUBLICATION_MAY_DECLINE,
            cfg!(feature = "routing-namespace")
                || cfg!(feature = "transport-stats")
                || cfg!(feature = "pubsub-ts-stack")
        );
    }
}

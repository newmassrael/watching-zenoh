// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A `get` written straight into the slot its link lends, from the borrowed description of it
//! ([`GetParts`]): no owned `Request`, no `String`, no `Vec`, so a query is asked with nothing
//! allocated after the session opened, whatever it carries.
//!
//! The writer writes the bytes the owned builder (`request_build::RequestQueryBuilder`) writes
//! for the same description, which the module's tests hold for every combination of key, envelope
//! extension and body extension the description can state: the envelope's QoS, target and timeout,
//! and the Query's consolidation, parameters, value, source info and attachment, each only in a
//! build that composes it, as the owned builder reads them.
//!
//! It writes the bytes itself rather than describe them to the codec, as `lent_push` does for a
//! publication: the codec's form of a Query's value extension holds the encoding and the payload as
//! one slice, which the caller does not have without a copy. The timestamp stack a query starts is the
//! last envelope extension, written by its one writer (`ts_stack::TsStack::write`).

use sce_forge_runtime::codec::{CodecError, SceSink};

use crate::declare_ext_qos::QOS_EXT_HEADER;
use crate::ext_header::{body_eid, ext_identity, EXT_ENC_Z64, EXT_FLAG_Z};
use crate::query_mode::TARGET_EXT_ID;
use crate::query_parts::{GetParts, QueryParts};
use crate::reply_stage::EncodingParts;
use crate::request_routing_context::TIMEOUT_EXT_ID;
use crate::sample::{QosLevel, SourceInfo};
use crate::wireexpr_build::NAMED_FLAG;

/// `_Z_MID_N_REQUEST` with `M`: the key's id is in the sender's mapping, as the owned builder's
/// `Local` arm states it.
const REQUEST_HEADER: u8 = 0x1C | 0x40;

/// The Request header's flag that an extension chain follows the key.
const REQUEST_FLAG_Z: u8 = 0x80;

/// `_Z_MID_Z_QUERY`.
const QUERY_HEADER: u8 = 0x03;
/// The Query header's flags: a consolidation, parameters, an extension chain follow.
const QUERY_FLAG_C: u8 = 0x20;
const QUERY_FLAG_P: u8 = 0x40;
const QUERY_FLAG_Z: u8 = 0x80;

/// The envelope's target and timeout extensions, as the owned builder writes them: the target
/// mandatory, the timeout not.
const TARGET_HEADER: u8 = ext_identity(TARGET_EXT_ID, true, EXT_ENC_Z64);
const TIMEOUT_HEADER: u8 = ext_identity(TIMEOUT_EXT_ID, false, EXT_ENC_Z64);

/// The longest schema an encoding carries (the codec's bound on `Encoding::schema`).
const SCHEMA_MAX: usize = 255;

/// Whether the build composes each slot of the Query, as the owned builder's metadata path reads
/// them. Read as constants, so the writer is the same code in every build and leaves out what the
/// build does not compose.
const PARAMETERS_RIDE: bool = cfg!(feature = "query-selector-parameters");
const VALUE_RIDES: bool = cfg!(feature = "query-value");
const SOURCE_INFO_RIDES: bool = cfg!(feature = "query-source-info");
const ATTACHMENT_RIDES: bool = cfg!(feature = "query-attachment");

/// Whether the build's network counters classify a Request by its owned message
/// (`transport-stats`): a session of such a build sends every query as that message, which the
/// counters read.
pub const COUNTED_FROM_OWNED: bool = cfg!(feature = "transport-stats");

/// A `get`, ready to encode.
#[derive(Debug, Clone, Copy)]
pub struct RequestWriter<'a> {
    parts: GetParts<'a>,
}

impl<'a> RequestWriter<'a> {
    /// The writer for `parts`: every query a description states, its timestamp stack included.
    pub const fn new(parts: GetParts<'a>) -> Self {
        Self { parts }
    }

    /// Encode the `Request` into `sink`. `LengthOutOfRange`, before a byte is written, for what
    /// the owned builder refuses: a key suffix past the protocol's `u16` length, parameters, a
    /// value or an attachment past its `u32` length, a schema past [`SCHEMA_MAX`], and a source
    /// info whose id is not 1 to 16 bytes.
    pub fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError>
    where
        CodecError: From<S::Error>,
    {
        let GetParts { rid, key, query } = self.parts;
        let suffix = key.suffix();
        if suffix.is_some_and(|text| u16::try_from(text.len()).is_err()) {
            return Err(CodecError::LengthOutOfRange);
        }
        let parameters = sent_parameters(&query);
        if parameters.is_some_and(|bytes| u32::try_from(bytes.len()).is_err()) {
            return Err(CodecError::LengthOutOfRange);
        }
        let [value, source_info, attachment] = body_extensions(&query);
        let body = [
            measured(value)?,
            measured(source_info)?,
            measured(attachment)?,
        ];
        let envelope = envelope_extensions(&query);
        #[cfg(feature = "pubsub-ts-stack")]
        let stack = query.ts_stack;
        #[cfg(not(feature = "pubsub-ts-stack"))]
        let stack: Option<core::convert::Infallible> = None;

        let chained = envelope.iter().any(Option::is_some) || stack.is_some();
        sink.write_u8(
            REQUEST_HEADER
                | if suffix.is_some() { NAMED_FLAG } else { 0 }
                | if chained { REQUEST_FLAG_Z } else { 0 },
        )?;
        sink.write_vle_u32(rid)?;
        sink.write_vle_u32(u32::from(key.id()))?;
        if let Some(text) = suffix {
            sink.write_vle_u64(widen(text.len()))?;
            sink.write_bytes(text.as_bytes())?;
        }
        let mut entries = envelope.iter().flatten().peekable();
        while let Some(&(header, value)) = entries.next() {
            sink.write_u8(continued(
                header,
                entries.peek().is_some() || stack.is_some(),
            ))?;
            sink.write_vle_u64(value)?;
        }
        // The timestamp stack is the last envelope extension, as the owned builder places it.
        #[cfg(feature = "pubsub-ts-stack")]
        if let Some(stack) = stack {
            sink.write_u8(crate::ts_stack::TS_STACK_EXT_HEADER)?;
            sink.write_vle_u64(widen(stack.encoded_len()))?;
            stack.write(sink)?;
        }

        sink.write_u8(
            QUERY_HEADER
                | if query.consolidation.is_some() {
                    QUERY_FLAG_C
                } else {
                    0
                }
                | if parameters.is_some() {
                    QUERY_FLAG_P
                } else {
                    0
                }
                | if body.iter().any(Option::is_some) {
                    QUERY_FLAG_Z
                } else {
                    0
                },
        )?;
        if let Some(mode) = query.consolidation {
            sink.write_vle_u64(u64::from(mode.wire_byte()))?;
        }
        if let Some(bytes) = parameters {
            sink.write_vle_u64(widen(bytes.len()))?;
            sink.write_bytes(bytes)?;
        }
        let mut entries = body.iter().flatten().peekable();
        while let Some((extension, len)) = entries.next() {
            sink.write_u8(continued(extension.header(), entries.peek().is_some()))?;
            sink.write_vle_u64(*len)?;
            extension.write_body(sink)?;
        }
        Ok(())
    }
}

/// `header` with the chain-continuation bit set when another entry follows it, and clear on the
/// last.
const fn continued(header: u8, more: bool) -> u8 {
    if more {
        header | EXT_FLAG_Z
    } else {
        header & !EXT_FLAG_Z
    }
}

/// The parameters the Query carries: none when they are empty, and none in a build that does not
/// compose them, as the owned builder's metadata path reads them (`query-selector-parameters`).
fn sent_parameters<'a>(query: &QueryParts<'a>) -> Option<&'a [u8]> {
    Some(query.parameters).filter(|bytes| PARAMETERS_RIDE && !bytes.is_empty())
}

/// The envelope's extensions, in the owned builder's order: the QoS unless it is the default, the
/// target, the timeout unless it is zero. Each is a header and an integer.
fn envelope_extensions(query: &QueryParts<'_>) -> [Option<(u8, u64)>; 3] {
    [
        (query.qos != QosLevel::DEFAULT).then_some((QOS_EXT_HEADER, u64::from(query.qos.raw))),
        query
            .target
            .map(|target| (TARGET_HEADER, u64::from(target.wire_byte()))),
        (query.timeout_ms != 0).then_some((TIMEOUT_HEADER, u64::from(query.timeout_ms))),
    ]
}

/// An extension of the Query body: a header and a body of bytes, written in the owned builder's
/// order (the value, then the source info, then the attachment).
#[derive(Debug, Clone, Copy)]
enum BodyExtension<'a> {
    /// The value: its encoding, then its payload.
    Value {
        encoding: EncodingParts<'a>,
        payload: &'a [u8],
    },
    /// The source the query names.
    SourceInfo(&'a SourceInfo),
    /// The attachment.
    Attachment(&'a [u8]),
}

/// The body's extensions the build composes and the query states. A value of no payload under
/// the zero encoding is none, as zenoh-pico's `.body` predicate and the owned builder read it.
fn body_extensions<'a>(query: &QueryParts<'a>) -> [Option<BodyExtension<'a>>; 3] {
    let value = query
        .value
        .filter(|(encoding, payload)| {
            VALUE_RIDES
                && (!payload.is_empty() || encoding.packed_id > 1 || encoding.schema.is_some())
        })
        .map(|(encoding, payload)| BodyExtension::Value { encoding, payload });
    let source_info = query
        .source_info
        .filter(|_| SOURCE_INFO_RIDES)
        .map(BodyExtension::SourceInfo);
    let attachment = Some(query.attachment)
        .filter(|bytes| ATTACHMENT_RIDES && !bytes.is_empty())
        .map(BodyExtension::Attachment);
    [value, source_info, attachment]
}

/// `extension` with the length of its body, or the refusal of a body past its bound.
fn measured(
    extension: Option<BodyExtension<'_>>,
) -> Result<Option<(BodyExtension<'_>, u64)>, CodecError> {
    extension
        .map(|extension| Ok((extension, extension.body_len()?)))
        .transpose()
}

impl BodyExtension<'_> {
    /// The extension's header, without the chain-continuation bit.
    const fn header(&self) -> u8 {
        match self {
            Self::Value { .. } => body_eid::QUERY_VALUE,
            Self::SourceInfo(_) => body_eid::SOURCE_INFO,
            Self::Attachment(_) => body_eid::QUERY_ATTACHMENT,
        }
    }

    /// The length of the extension's body, which the wire writes before it.
    fn body_len(&self) -> Result<u64, CodecError> {
        let len = match self {
            Self::Value { encoding, payload } => {
                let schema = match encoding.schema {
                    Some(schema) if schema.len() > SCHEMA_MAX => {
                        return Err(CodecError::LengthOutOfRange)
                    }
                    Some(schema) => vle_len(widen(schema.len())).checked_add(schema.len()),
                    None => Some(0),
                };
                schema
                    .and_then(|schema| {
                        vle_len(u64::from(encoding_word(*encoding))).checked_add(schema)
                    })
                    .and_then(|head| head.checked_add(payload.len()))
            }
            Self::SourceInfo(info) => {
                let zid = source_zid(info)?;
                vle_len(u64::from(info.eid))
                    .checked_add(vle_len(u64::from(info.sn)))
                    .and_then(|ids| ids.checked_add(zid.len()))
                    .and_then(|body| body.checked_add(1))
            }
            Self::Attachment(bytes) => Some(bytes.len()),
        };
        len.and_then(|len| u32::try_from(len).ok())
            .map(u64::from)
            .ok_or(CodecError::LengthOutOfRange)
    }

    /// Write the extension's body.
    fn write_body<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError>
    where
        CodecError: From<S::Error>,
    {
        match self {
            Self::Value { encoding, payload } => {
                sink.write_vle_u32(encoding_word(*encoding))?;
                if let Some(schema) = encoding.schema {
                    sink.write_vle_u64(widen(schema.len()))?;
                    sink.write_bytes(schema)?;
                }
                sink.write_bytes(payload)?;
            }
            Self::SourceInfo(info) => {
                let zid = source_zid(info)?;
                // The id's length less one, in the high nibble.
                let nibble = zid
                    .len()
                    .checked_sub(1)
                    .and_then(|n| u8::try_from(n).ok())
                    .and_then(|n| n.checked_mul(16))
                    .ok_or(CodecError::LengthOutOfRange)?;
                sink.write_u8(nibble)?;
                sink.write_bytes(zid)?;
                sink.write_vle_u64(u64::from(info.eid))?;
                sink.write_vle_u64(u64::from(info.sn))?;
            }
            Self::Attachment(bytes) => sink.write_bytes(bytes)?,
        }
        Ok(())
    }
}

/// The id word an encoding is written as: its id, and in the low bit whether a schema follows.
const fn encoding_word(encoding: EncodingParts<'_>) -> u32 {
    (encoding.packed_id & !1) | if encoding.schema.is_some() { 1 } else { 0 }
}

/// The id a source info names, refused as `LengthOutOfRange` unless it is 1 to 16 bytes, which
/// the wire's nibble carries.
fn source_zid(info: &SourceInfo) -> Result<&[u8], CodecError> {
    let zid = info.zid_prefix();
    if zid.is_empty() || zid.len() > 16 {
        return Err(CodecError::LengthOutOfRange);
    }
    Ok(zid)
}

/// The bytes the codec's `vle_u64` writes `value` in: seven bits a byte, at most nine.
fn vle_len(value: u64) -> usize {
    let mut len = 1usize;
    let mut rest = value;
    while rest >= 0x80 && len < 9 {
        rest = rest.checked_shr(7).unwrap_or(0);
        len = len.saturating_add(1);
    }
    len
}

/// A length as the wire's integer.
fn widen(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::declare_ext_qos::QOS_DECLARE;
    use crate::query_mode::{ConsolidationMode, QueryTarget};
    use crate::wire_key::WireKey;
    use alloc::vec::Vec;
    use sce_forge_runtime::codec::SliceSink;

    /// The bytes the owned path writes for `parts`.
    fn owned_bytes(parts: &GetParts<'_>) -> Result<Vec<u8>, CodecError> {
        let request = parts.owned_request()?;
        let view = request.try_as_borrowed().expect("a view");
        Ok(view.encode_to_vec())
    }

    /// The bytes the writer writes for `parts`.
    fn lent_bytes(parts: GetParts<'_>) -> Result<Vec<u8>, CodecError> {
        let writer = RequestWriter::new(parts);
        let mut buffer = alloc::vec![0u8; 4096];
        let mut sink = SliceSink::new(&mut buffer);
        writer.encode(&mut sink)?;
        let len = sink.position();
        Ok(buffer.get(..len).expect("within the buffer").to_vec())
    }

    fn keys() -> [WireKey<'static>; 4] {
        [
            WireKey::literal("demo/**").expect("a literal"),
            WireKey::literal("demo/example/zenoh-rs-pub").expect("a literal"),
            WireKey::from_parts(5, None).expect("an id"),
            WireKey::from_parts(300, Some("/tail")).expect("an id and a suffix"),
        ]
    }

    /// The envelope and the key: every key form, request ids of every VLE width, every
    /// consolidation, target, timeout width and QoS, with and without parameters.
    #[test]
    fn a_get_is_written_as_the_owned_path_writes_it() {
        let consolidations = [
            None,
            Some(ConsolidationMode::None),
            Some(ConsolidationMode::Monotonic),
            Some(ConsolidationMode::Latest),
        ];
        let targets = [None, Some(QueryTarget::All), Some(QueryTarget::AllComplete)];
        let parameters: [&[u8]; 3] = [b"", b"_time=[..]", &[b'p'; 200]];
        let mut compared = 0usize;
        for key in keys() {
            for rid in [0u32, 1, 300, u32::MAX] {
                for consolidation in consolidations {
                    for target in targets {
                        for params in parameters {
                            for timeout_ms in [0u32, 1, 10_000, u32::MAX] {
                                for qos in [QosLevel::DEFAULT, QOS_DECLARE] {
                                    let parts = GetParts {
                                        rid,
                                        key,
                                        query: QueryParts {
                                            parameters: params,
                                            consolidation,
                                            target,
                                            timeout_ms,
                                            qos,
                                            ..QueryParts::PLAIN
                                        },
                                    };
                                    assert_eq!(lent_bytes(parts), owned_bytes(&parts), "{parts:?}");
                                    compared += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        // Every combination was compared; a loop that compared none would pass.
        assert_eq!(compared, 4 * 4 * 4 * 3 * 3 * 4 * 2);
    }

    /// The body's extensions: each alone and together, a value with and without a payload and a
    /// schema (the empty one under the zero encoding is none), source infos of the shortest and
    /// the longest id, and attachments of one and of many bytes.
    #[test]
    fn a_gets_body_extensions_are_written_as_the_owned_path_writes_them() {
        let schema = [b's'; 200];
        let values: [Option<(EncodingParts<'_>, &[u8])>; 6] = [
            None,
            Some((
                EncodingParts {
                    packed_id: 0,
                    schema: None,
                },
                b"",
            )),
            Some((
                EncodingParts {
                    packed_id: 0,
                    schema: None,
                },
                b"payload",
            )),
            Some((
                EncodingParts {
                    packed_id: 0x0A,
                    schema: None,
                },
                b"",
            )),
            Some((
                EncodingParts {
                    packed_id: 0x0B,
                    schema: Some(b"json"),
                },
                b"{}",
            )),
            Some((
                EncodingParts {
                    packed_id: 0x0B,
                    schema: Some(&schema),
                },
                &[9u8; 300],
            )),
        ];
        let short = SourceInfo::new(&[1], 0, 0);
        let long = SourceInfo::new(&[2; 16], u32::MAX, 300);
        let sources = [None, Some(&short), Some(&long)];
        let attachments: [&[u8]; 3] = [b"", b"a", &[3u8; 200]];
        let mut compared = 0usize;
        for key in keys() {
            for value in values {
                for source_info in sources {
                    for attachment in attachments {
                        let parts = GetParts {
                            rid: 7,
                            key,
                            query: QueryParts {
                                consolidation: Some(ConsolidationMode::Latest),
                                timeout_ms: 2_000,
                                value,
                                source_info,
                                attachment,
                                ..QueryParts::PLAIN
                            },
                        };
                        assert_eq!(lent_bytes(parts), owned_bytes(&parts), "{parts:?}");
                        compared += 1;
                    }
                }
            }
        }
        assert_eq!(compared, 4 * 6 * 3 * 3);
    }

    /// A key past the protocol's `u16` length is refused before a byte is written.
    #[test]
    fn a_get_of_a_key_past_its_protocol_bound_is_refused_at_encode() {
        let past_bound = "k".repeat(usize::from(u16::MAX) + 1);
        let parts = GetParts {
            rid: 1,
            key: WireKey::literal(&past_bound).expect("a literal"),
            query: QueryParts::PLAIN,
        };
        let writer = RequestWriter::new(parts);
        let mut buffer = [0u8; 16];
        let mut sink = SliceSink::new(&mut buffer);
        assert_eq!(
            writer.encode(&mut sink).err(),
            Some(CodecError::LengthOutOfRange)
        );
        assert_eq!(sink.position(), 0, "nothing is written");
    }

    /// What the owned builder refuses, the writer refuses, before a byte is written: a source
    /// info naming no id, and a schema past the codec's bound.
    #[test]
    fn what_the_owned_builder_refuses_the_writer_refuses() {
        let nobody = SourceInfo::default();
        let long_schema = [b's'; SCHEMA_MAX + 1];
        let refused = [
            QueryParts {
                source_info: Some(&nobody),
                ..QueryParts::PLAIN
            },
            QueryParts {
                value: Some((
                    EncodingParts {
                        packed_id: 1,
                        schema: Some(&long_schema),
                    },
                    b"",
                )),
                ..QueryParts::PLAIN
            },
        ];
        for query in refused {
            let parts = GetParts {
                rid: 1,
                key: WireKey::literal("demo/a").expect("a literal"),
                query,
            };
            let writer = RequestWriter::new(parts);
            let mut buffer = [0u8; 512];
            let mut sink = SliceSink::new(&mut buffer);
            let lent = writer.encode(&mut sink).err();
            if SOURCE_INFO_RIDES && VALUE_RIDES {
                assert_eq!(lent, Some(CodecError::LengthOutOfRange), "{query:?}");
                assert!(
                    owned_bytes(&parts).is_err(),
                    "the owned builder refuses it too"
                );
                assert_eq!(sink.position(), 0, "nothing is written");
            } else {
                assert_eq!(lent, owned_bytes(&parts).err(), "{query:?}");
            }
        }
    }

    /// A query that starts a timestamp stack carries it as the last envelope extension, the owned
    /// path's bytes, alone and behind the QoS and the timeout. Turned red by a stack written in
    /// another place or form, or a chain whose continuation bits disagree with the owned one.
    #[cfg(feature = "pubsub-ts-stack")]
    #[test]
    fn a_get_that_starts_a_timestamp_stack_is_written_as_the_owned_path_writes_it() {
        let mut stack = crate::ts_stack::TsStack::new(crate::ts_stack::point::SEND);
        assert!(stack.record(crate::ts_stack::point::SEND, alloc::vec![9, 8, 7], false));
        let mut compared = 0usize;
        for (qos, timeout_ms) in [(QosLevel::DEFAULT, 0), (QOS_DECLARE, 2_500)] {
            for key in keys() {
                let parts = GetParts {
                    rid: 7,
                    key,
                    query: QueryParts {
                        qos,
                        timeout_ms,
                        ts_stack: Some(&stack),
                        ..QueryParts::PLAIN
                    },
                };
                assert_eq!(
                    lent_bytes(parts).expect("written"),
                    owned_bytes(&parts).expect("built"),
                    "{qos:?} {timeout_ms}"
                );
                compared += 1;
            }
        }
        assert_eq!(compared, 2 * keys().len());
    }

    /// The length the writer states for a body is the number of bytes it writes, at every VLE
    /// width the length counter meets.
    #[test]
    fn the_vle_length_is_the_bytes_the_codec_writes() {
        for value in [
            0u64,
            0x7F,
            0x80,
            0x3FFF,
            0x4000,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let mut buffer = [0u8; 16];
            let mut sink = SliceSink::new(&mut buffer);
            sink.write_vle_u64(value).expect("room");
            assert_eq!(vle_len(value), sink.position(), "{value:#x}");
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Fixed-memory step S9e -- a staged reply written as the codec's BORROWED
//! `Response`, straight from the stage's own row.
//!
//! A reply the queryable staged waits in a [`ReplyStage`](crate::reply_stage::ReplyStage)
//! as a row and a byte arena, and [`ReplyStage::parts`](crate::reply_stage::ReplyStage::parts)
//! describes it with every field borrowed
//! ([`ReplyParts`](crate::reply_stage::ReplyParts)). Sending it the way the heap
//! profile does means building a [`QueryReply`](crate::query::QueryReply) (a `String`,
//! and a `Vec` per field), then the owned `ResponseOwned` out of that (a second copy of
//! all of it), then encoding that: two heap objects whose only job is to be encoded and
//! dropped. [`ResponseWriter`](crate::lent_response::ResponseWriter) takes the
//! description and writes the `Response` the
//! owned path writes, byte for byte, with the text and the payload read where they lie
//! and the few bytes it has to make (the body of the responder and the source-info
//! extensions) in arrays of its own.
//!
//! What it mirrors, and where each choice is: the envelope is
//! [`crate::response_build::build_response_reply_literal`] /
//! `build_response_err_literal` (the literal keyexpr, the `N` flag), the extensions on
//! it are `stamp_envelope_extensions` (the QoS entry unless it is the default, then the
//! responder, the chain bits set on every entry but the last), the Reply body is
//! `ResponseReplyBuilder::build` (timestamp, encoding, then the source-info and the
//! attachment extensions, each behind the feature that gates it there) and the Err body
//! is `ResponseErrBuilder::build`. The module's tests hold the equality for every
//! combination the stage can describe.
//!
//! A reply the owned path panics on (an empty keyexpr, a responder identity of no
//! bytes) is REFUSED here with a
//! [`ResponseRefusal`](crate::lent_response::ResponseRefusal), which is what a node with no
//! allocator and no unwinding can do about a malformed reply: the drain skips it, as it
//! skips a reply whose bounded field overflows on the heap profile.

use sce_forge_runtime::codec::{CodecError, SceSink, SliceSink};
use sce_forge_runtime::heapless::Vec as HeaplessVec;
use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
use wz_codecs::ext_zbuf::ExtZbuf;
use wz_codecs::response::{Response, ResponseVariant};
use wz_codecs::wire_const;

use crate::ext_header::{ext_identity, EXT_ENC_ZBUF, EXT_FLAG_Z};
use crate::lent_control::{local, qos_entry, with_z};
use crate::reply_stage::{PartsBody, PartsKind, ReplyParts};
use crate::sample::QosLevel;

/// The `Response` envelope header of a reply that names its keyexpr inline:
/// `N_MID_RESPONSE | N` (a suffix follows the id). The `M` flag derives from the
/// `Local` arm at encode time, and `Z` is added when the envelope carries
/// extensions.
const RESPONSE_HEADER: u8 = wire_const::N_MID_RESPONSE | wire_const::FLAG_N_N;

/// The Reply body's header: `_Z_MID_Z_REPLY`, with no consolidation and no
/// extension of its own (they ride the Put or Del inside it).
const REPLY_HEADER: u8 = 0x04;

/// The Err body's header: `_Z_MID_Z_ERR`.
#[cfg(feature = "query-reply-err")]
const ERR_HEADER: u8 = 0x05;

/// A Put's header, and a Del's.
const PUT_HEADER: u8 = 0x01;
const DEL_HEADER: u8 = 0x02;

/// The `T` (timestamp) flag of a Del, the same bit as a Put's.
const FLAG_DEL_T: u8 = 0x20;

/// The `Z` (extension chain) flag of a Del, the same bit as a Put's.
const FLAG_DEL_Z: u8 = 0x80;

/// The responder identity extension of the `Response` envelope:
/// `zextzbuf!(0x3, false)`, ENC_ZBUF with no `M` flag.
const RESPONDER_EXT_HEADER: u8 = ext_identity(0x03, false, EXT_ENC_ZBUF);

/// The bytes of an identity extension's body at its longest: the length nibble, a
/// 16-byte zid, and two VLE `u32`s of five bytes (the responder carries only the
/// first).
const IDENTITY_EXT_BODY_BYTES: usize = 1 + 16 + 5 + 5;

/// Why a staged reply cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseRefusal {
    /// The reply names no keyexpr. A literal reply carries its key inline, and the
    /// owned builder refuses a reply with none.
    EmptyKeyexpr,
    /// The responder identity's zid is empty or longer than 16 bytes, which the wire
    /// cannot hold: the refusal of an identity, never a truncated one.
    ResponderIdentity,
}

/// The body of an identity extension (`[(zid_len - 1) << 4 | zid | VLE(eid) |
/// VLE(sn)?]`), made in an array on the writer. The bytes
/// `encode_responder_ext_body` and `encode_source_info_ext_body` make in a `Vec`.
#[derive(Clone, Copy)]
struct IdentityBody {
    bytes: [u8; IDENTITY_EXT_BODY_BYTES],
    len: usize,
}

impl IdentityBody {
    const NONE: Self = Self {
        bytes: [0; IDENTITY_EXT_BODY_BYTES],
        len: 0,
    };

    /// The body for `zid`, `eid` and (for a source info) `sn`. The caller has checked
    /// that `zid` is 1 to 16 bytes, so the array holds the whole body.
    fn new(zid: &[u8], eid: u32, sn: Option<u32>) -> Result<Self, CodecError> {
        let mut bytes = [0u8; IDENTITY_EXT_BODY_BYTES];
        let mut sink = SliceSink::new(&mut bytes);
        sink.write_u8((zid.len() as u8).wrapping_sub(1) << 4)?;
        sink.write_bytes(zid)?;
        sink.write_vle_u64(u64::from(eid))?;
        if let Some(sn) = sn {
            sink.write_vle_u64(u64::from(sn))?;
        }
        let len = sink.position();
        Ok(Self { bytes, len })
    }

    fn zbuf(&self) -> ExtZbuf<'_> {
        ExtZbuf {
            value_len: self.len as u64,
            value: &self.bytes[..self.len],
        }
    }
}

/// Set the chain-continuation `Z` bit on every entry but the last, which ends the
/// chain: [`crate::ext_nodeid::apply_chain_z_bits`] over the codec's borrowed entries.
fn link_chain(chain: &mut HeaplessVec<ExtEntry<'_>, 8>) {
    let Some(last) = chain.len().checked_sub(1) else {
        return;
    };
    for (index, entry) in chain.iter_mut().enumerate() {
        entry.header = if index == last {
            entry.header & !EXT_FLAG_Z
        } else {
            entry.header | EXT_FLAG_Z
        };
    }
}

/// A staged reply, ready to encode: the description it borrows and the two extension
/// bodies it makes. `encode` builds the codec's `Response` over both for the length of
/// one call, so nothing the record holds outlives the slot it is written into.
pub struct ResponseWriter<'a> {
    parts: ReplyParts<'a>,
    responder: IdentityBody,
    // Read only under `reply-source-info`, the feature that puts the extension on the wire.
    #[cfg_attr(not(feature = "reply-source-info"), allow(dead_code))]
    source_info: IdentityBody,
}

impl<'a> ResponseWriter<'a> {
    /// The writer for `parts`, or the refusal of a reply the wire cannot carry.
    pub fn new(parts: ReplyParts<'a>) -> Result<Self, ResponseRefusal> {
        if parts.keyexpr.is_empty() {
            return Err(ResponseRefusal::EmptyKeyexpr);
        }
        let responder = match parts.responder {
            Some((zid, eid)) => {
                if !(1..=16).contains(&zid.len()) {
                    return Err(ResponseRefusal::ResponderIdentity);
                }
                IdentityBody::new(zid, eid, None).map_err(|_| ResponseRefusal::ResponderIdentity)?
            }
            None => IdentityBody::NONE,
        };
        let source_info = Self::source_info_body(&parts);
        Ok(Self {
            parts,
            responder,
            source_info,
        })
    }

    /// The source-info extension's body, when the reply carries one that names a source
    /// (a `Default::default()` one has no zid and is skipped, as the owned builder skips
    /// it) and the build emits it.
    #[cfg(feature = "reply-source-info")]
    fn source_info_body(parts: &ReplyParts<'a>) -> IdentityBody {
        match &parts.kind {
            PartsKind::Reply {
                source_info: Some(info),
                ..
            } if !info.zid_prefix().is_empty() => {
                // A zid of 1 to 16 bytes and two `u32`s always fit the array.
                IdentityBody::new(info.zid_prefix(), info.eid, Some(info.sn))
                    .unwrap_or(IdentityBody::NONE)
            }
            _ => IdentityBody::NONE,
        }
    }

    #[cfg(not(feature = "reply-source-info"))]
    fn source_info_body(_parts: &ReplyParts<'a>) -> IdentityBody {
        IdentityBody::NONE
    }

    /// Encode the `Response` into `sink`.
    pub fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError> {
        let parts = &self.parts;
        // The envelope's extensions: the QoS unless it is the default, then the
        // responder.
        let mut chain: HeaplessVec<ExtEntry<'_>, 8> = HeaplessVec::new();
        if parts.qos != QosLevel::DEFAULT {
            // Two entries in a list of eight.
            let _ = chain.push(qos_entry(parts.qos));
        }
        if parts.responder.is_some() {
            let _ = chain.push(ExtEntry {
                header: RESPONDER_EXT_HEADER,
                body: ExtEntryVariant::CodecZenohExtZbuf(self.responder.zbuf()),
            });
        }
        link_chain(&mut chain);
        let header = if chain.is_empty() {
            RESPONSE_HEADER
        } else {
            with_z(RESPONSE_HEADER)
        };
        let body = match &parts.kind {
            PartsKind::Reply {
                body,
                encoding,
                timestamp,
                attachment,
                source_info: _,
            } => ResponseVariant::CodecZenohReply(self.reply(
                body,
                *encoding,
                *timestamp,
                *attachment,
            )),
            #[cfg(feature = "query-reply-err")]
            PartsKind::Err { encoding, payload } => {
                ResponseVariant::CodecZenohErr(Self::err(*encoding, payload))
            }
        };
        Response {
            header,
            request_id: parts.rid,
            keyexpr: local(0, Some(parts.keyexpr)),
            extensions: (!chain.is_empty()).then_some(chain),
            body,
        }
        .encode(sink)
    }

    /// The Reply body: a Put or a Del, with the value's timestamp and encoding (each
    /// behind the feature the owned builder gates it on) and the source-info and
    /// attachment extensions, in that order, with the attachment under the id of the
    /// arm it rides.
    fn reply(
        &self,
        body: &PartsBody<'a>,
        encoding: Option<crate::reply_stage::EncodingParts<'a>>,
        timestamp: Option<crate::reply_stage::TimestampParts<'a>>,
        attachment: Option<&'a [u8]>,
    ) -> wz_codecs::reply::Reply<'_> {
        use wz_codecs::reply::{Reply, ReplyVariant};
        let payload: Option<&[u8]> = match body {
            PartsBody::Put(bytes) => Some(bytes),
            PartsBody::Del => None,
            // The descriptor is the heap profile's to take: a reply of this build goes
            // out as the buffer's bytes, which is what a face that cannot map the
            // segment is owed.
            #[cfg(feature = "transport-shm")]
            PartsBody::Shared(handle) => Some(handle.bytes()),
        };
        // Only the encoding (a Put's) and the attachment's extension id read it.
        #[cfg(any(feature = "pubsub-encoding", feature = "pubsub-attachment"))]
        let is_put = payload.is_some();
        #[cfg(not(feature = "pubsub-timestamp"))]
        let _ = timestamp;
        #[cfg(not(feature = "pubsub-attachment"))]
        let _ = attachment;
        #[cfg(not(feature = "pubsub-encoding"))]
        let _ = encoding;

        #[cfg(feature = "pubsub-timestamp")]
        let timestamp = timestamp.map(|ts| wz_codecs::timestamp::Timestamp {
            time: ts.time,
            zid_len: ts.zid.len() as u64,
            zid: ts.zid,
        });
        #[cfg(not(feature = "pubsub-timestamp"))]
        let timestamp: Option<wz_codecs::timestamp::Timestamp<'_>> = None;

        // An encoding is a Put's only: a Del has no slot for it.
        #[cfg(feature = "pubsub-encoding")]
        let encoding = encoding
            .filter(|_| is_put)
            .map(|e| wz_codecs::encoding::Encoding {
                packed_id: e.packed_id,
                schema_len: e.schema.map(|s| s.len() as u64),
                schema: e.schema,
            });
        #[cfg(not(feature = "pubsub-encoding"))]
        let encoding: Option<wz_codecs::encoding::Encoding<'_>> = None;

        // The body's extension chain: the source info, then the attachment.
        let mut chain: HeaplessVec<ExtEntry<'_>, 8> = HeaplessVec::new();
        #[cfg(feature = "reply-source-info")]
        if self.source_info.len != 0 {
            let _ = chain.push(ExtEntry {
                header: crate::ext_header::body_eid::SOURCE_INFO,
                body: ExtEntryVariant::CodecZenohExtZbuf(self.source_info.zbuf()),
            });
        }
        #[cfg(feature = "pubsub-attachment")]
        if let Some(attachment) = attachment {
            let _ = chain.push(ExtEntry {
                header: if is_put {
                    crate::ext_header::body_eid::PUT_ATTACHMENT
                } else {
                    crate::ext_header::body_eid::DEL_ATTACHMENT
                },
                body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                    value_len: attachment.len() as u64,
                    value: attachment,
                }),
            });
        }
        link_chain(&mut chain);
        let has_chain = !chain.is_empty();
        let extensions = has_chain.then_some(chain);

        let inner = match payload {
            Some(bytes) => {
                let mut header = PUT_HEADER;
                if timestamp.is_some() {
                    header |= wire_const::FLAG_Z_PUT_T;
                }
                if encoding.is_some() {
                    header |= wire_const::FLAG_Z_PUT_E;
                }
                if has_chain {
                    header |= wire_const::FLAG_Z_PUT_Z;
                }
                ReplyVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                    header,
                    timestamp,
                    encoding,
                    extensions,
                    payload_len: Some(bytes.len() as u64),
                    payload: Some(bytes),
                    slice_count: None,
                    slices: None,
                })
            }
            None => {
                let mut header = DEL_HEADER;
                if timestamp.is_some() {
                    header |= FLAG_DEL_T;
                }
                if has_chain {
                    header |= FLAG_DEL_Z;
                }
                ReplyVariant::CodecZenohMsgDel(wz_codecs::msg_del::MsgDel {
                    header,
                    timestamp,
                    extensions,
                })
            }
        };
        Reply {
            header: REPLY_HEADER,
            consolidation: None,
            extensions: None,
            body: inner,
        }
    }

    /// The Err body: the payload, and the error's own encoding when it names one, its id
    /// packed with the schema bit as `ResponseErrBuilder::encoding` packs it.
    #[cfg(feature = "query-reply-err")]
    fn err(encoding: Option<(u32, Option<&'a str>)>, payload: &'a [u8]) -> wz_codecs::err::Err<'a> {
        let mut header = ERR_HEADER;
        let encoding = encoding.map(|(id, schema)| {
            header |= wire_const::FLAG_Z_ERR_E;
            wz_codecs::encoding::Encoding {
                packed_id: (id << 1) | u32::from(schema.is_some()),
                schema_len: schema.map(|s| s.len() as u64),
                schema,
            }
        });
        wz_codecs::err::Err {
            header,
            encoding,
            extensions: None,
            payload_len: payload.len() as u64,
            payload,
        }
    }
}

/// The writer against the owned path it replaces: the same bytes for every reply the
/// stage can describe, and the refusals. Each side is built from the same `ReplyParts`,
/// the owned one through `QueryReply::from_parts` and `into_response` (the route the
/// heap profile takes), and the number of rows compared is asserted, so a writer that
/// always wrote the same message would be caught by the first row that differs and not
/// pass an empty loop.
#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::declare_ext_qos::QOS_DECLARE;
    use crate::query::QueryReply;
    use crate::reply_stage::{EncodingParts, TimestampParts};
    use crate::sample::SourceInfo;
    use alloc::vec::Vec;

    /// The bytes the owned path writes for `parts`.
    fn owned_bytes(parts: &ReplyParts<'_>) -> Vec<u8> {
        let response = QueryReply::from_parts(parts)
            .into_response()
            .expect("the owned response is built");
        let view = response.try_as_borrowed().expect("a view");
        view.encode_to_vec()
    }

    /// The bytes the writer writes for `parts`.
    fn lent_bytes(parts: ReplyParts<'_>) -> Vec<u8> {
        let writer = ResponseWriter::new(parts).expect("the reply is writable");
        let mut buffer = [0u8; 1024];
        let mut sink = SliceSink::new(&mut buffer);
        writer.encode(&mut sink).expect("the buffer holds it");
        let len = sink.position();
        buffer[..len].to_vec()
    }

    #[test]
    fn a_reply_is_written_as_the_owned_path_writes_it() {
        let source = SourceInfo::new(&[7u8; 4], 3, 9);
        let attachments: [Option<&[u8]>; 2] = [None, Some(b"att")];
        let encodings: [Option<EncodingParts<'_>>; 3] = [
            None,
            Some(EncodingParts {
                packed_id: 10 << 1,
                schema: None,
            }),
            Some(EncodingParts {
                packed_id: (5 << 1) | 1,
                schema: Some("v=1"),
            }),
        ];
        let stamps: [Option<TimestampParts<'_>>; 2] = [
            None,
            Some(TimestampParts {
                time: 123_456_789,
                zid: &[0xAB; 8],
            }),
        ];
        let responders: [Option<(&[u8], u32)>; 3] =
            [None, Some((&[1, 2, 3, 4], 5)), Some((&[9u8; 16], 300))];
        let sources: [Option<&SourceInfo>; 2] = [None, Some(&source)];
        let bodies: [PartsBody<'_>; 3] = [
            PartsBody::Put(b"hello"),
            PartsBody::Put(b""),
            PartsBody::Del,
        ];
        let mut compared = 0usize;
        for body in bodies {
            for qos in [QosLevel::DEFAULT, QOS_DECLARE] {
                for responder in responders {
                    for encoding in encodings {
                        for timestamp in stamps {
                            for attachment in attachments {
                                for source_info in sources {
                                    let parts = ReplyParts {
                                        rid: 7,
                                        keyexpr: "demo/a",
                                        responder,
                                        qos,
                                        kind: PartsKind::Reply {
                                            body,
                                            encoding,
                                            timestamp,
                                            attachment,
                                            source_info,
                                        },
                                    };
                                    assert_eq!(
                                        lent_bytes(parts),
                                        owned_bytes(&parts),
                                        "qos {qos:?}, responder {responder:?}, encoding \
                                         {encoding:?}, timestamp {timestamp:?}, attachment \
                                         {attachment:?}, source {:?}",
                                        source_info.is_some(),
                                    );
                                    compared += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(compared, 3 * 2 * 3 * 3 * 2 * 2 * 2, "the matrix ran whole");
    }

    #[cfg(feature = "query-reply-err")]
    #[test]
    fn an_err_is_written_as_the_owned_path_writes_it() {
        let encodings: [Option<(u32, Option<&str>)>; 3] =
            [None, Some((5, None)), Some((5, Some("s")))];
        let responders: [Option<(&[u8], u32)>; 2] = [None, Some((&[1, 2, 3, 4], 5))];
        let mut compared = 0usize;
        for encoding in encodings {
            for qos in [QosLevel::DEFAULT, QOS_DECLARE] {
                for responder in responders {
                    for payload in [&b"boom"[..], &b""[..]] {
                        let parts = ReplyParts {
                            rid: 300,
                            keyexpr: "demo/err",
                            responder,
                            qos,
                            kind: PartsKind::Err { encoding, payload },
                        };
                        assert_eq!(
                            lent_bytes(parts),
                            owned_bytes(&parts),
                            "encoding {encoding:?}, qos {qos:?}, responder {responder:?}"
                        );
                        compared += 1;
                    }
                }
            }
        }
        assert_eq!(compared, 3 * 2 * 2 * 2);
    }

    #[test]
    fn a_reply_the_wire_cannot_carry_is_refused_not_cut() {
        let kind = PartsKind::Reply {
            body: PartsBody::Put(b"x"),
            encoding: None,
            timestamp: None,
            attachment: None,
            source_info: None,
        };
        let parts = |keyexpr, responder| ReplyParts {
            rid: 1,
            keyexpr,
            responder,
            qos: QosLevel::DEFAULT,
            kind,
        };
        assert!(matches!(
            ResponseWriter::new(parts("", None)),
            Err(ResponseRefusal::EmptyKeyexpr)
        ));
        assert!(matches!(
            ResponseWriter::new(parts("demo/a", Some((&[], 1)))),
            Err(ResponseRefusal::ResponderIdentity)
        ));
        assert!(matches!(
            ResponseWriter::new(parts("demo/a", Some((&[0u8; 17], 1)))),
            Err(ResponseRefusal::ResponderIdentity)
        ));
        assert!(ResponseWriter::new(parts("demo/a", Some((&[0u8; 16], 1)))).is_ok());
    }
}

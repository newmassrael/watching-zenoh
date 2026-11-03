// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A `get` written as the codec's BORROWED `Request`, straight from the caller's own
//! text: the query a node with no allocator asks.
//!
//! The owned path ([`crate::request_build::RequestQueryBuilder`]) makes a `RequestOwned`
//! (a `String` for the keyexpr, a `Vec` for the parameters, a `Vec` for the extension
//! chain) and encodes that, which a session with no allocator cannot do, so
//! `send_request_query` refuses it with `FeatureDisabled`.
//! [`RequestWriter`](crate::lent_request::RequestWriter) takes the description of the
//! query ([`GetParts`](crate::lent_request::GetParts)) with every field borrowed and writes the
//! `Request` the owned path writes, byte for byte: the text and the parameters are read
//! where they lie, and the message is described in the codec's PARTS form (references and
//! a slice of at most three extension entries) that the codec's own wire writer reads. The
//! lent form (`wz_codecs::lent::Request`) is not built, as R4194 decided: it holds the
//! lists of the deployment inline at their capacity, and a `get` that states no extension
//! would carry that capacity on the stack (a frame of 3,328 bytes at the SCE pin
//! 9619440966).
//!
//! What it carries is what a `get` of a node that stores nothing asks for: a literal
//! keyexpr, the selector parameters, the consolidation, the target, the timeout and the
//! QoS. The Query body's value, source info and attachment, the Request's timestamp and
//! budget, and a keyexpr named by a mapping id are not carried; a query that needs one
//! goes the way every owned query goes. Each constant the writer reads is the owned
//! builder's own ([`crate::query_mode::TARGET_EXT_ID`],
//! [`crate::request_routing_context::TIMEOUT_EXT_ID`]) and the module's tests hold the
//! equality for every combination the description can state.
//!
//! A description the wire cannot carry (an empty keyexpr) is REFUSED with a
//! [`RequestRefusal`](crate::lent_request::RequestRefusal) and not repaired.

use sce_forge_runtime::codec::{Bounded, Bytes, CodecError, SceSink};
use wz_codecs::ext_entry::{ExtEntryParts, ExtEntryPartsBody};
use wz_codecs::ext_zint::ExtZintParts;
use wz_codecs::query::QueryParts;
use wz_codecs::request::{RequestParts, RequestPartsBody, RequestWire};
use wz_codecs::wireexpr::{WireexprParts, WireexprPartsBody};
use wz_codecs::wireexpr_local::WireexprLocalParts;

use crate::declare_ext_qos::QOS_EXT_HEADER;
use crate::ext_header::EXT_FLAG_Z;
use crate::query_mode::{ConsolidationMode, QueryTarget, TARGET_EXT_ID};
use crate::request_routing_context::TIMEOUT_EXT_ID;
use crate::sample::QosLevel;

/// The `Request` envelope header of a query that names its keyexpr inline:
/// `_Z_MID_N_REQUEST | N` (a suffix follows the id). `M` derives from the `Local` arm at
/// encode time, and `Z` is added when the envelope carries extensions.
const REQUEST_HEADER: u8 = 0x1C | 0x20;

/// The Query body's header: `_Z_MID_Z_QUERY`. The `C` (consolidation), `P` (parameters) and
/// `Z` (extensions) flags are the codec's to set: it derives them from what the value holds.
const QUERY_HEADER: u8 = 0x03;

/// The entries the envelope's extension chain holds at most: the QoS, the target and the
/// timeout.
const CHAIN_ENTRIES: usize = 3;

/// The body of an entry no extension fills: a slot of the chain that is never written.
static UNUSED_ENTRY_BODY: ExtZintParts = ExtZintParts { value: 0 };

/// The extension entry headers of the Request: `ENC_ZINT | id`, and for the target
/// the mandatory bit as well.
const ENC_ZINT: u8 = 0x20;
const FLAG_EXT_M: u8 = 0x10;

/// What a `get` asks, every field borrowed from the caller.
#[derive(Debug, Clone, Copy)]
pub struct GetParts<'a> {
    /// The request id the peer echoes in its replies and its final.
    pub rid: u64,
    /// The queried keyexpr, written as a literal.
    pub keyexpr: &'a str,
    /// The selector parameters; empty states none.
    pub parameters: &'a [u8],
    /// The consolidation the asker wants, or none for the default.
    pub consolidation: Option<ConsolidationMode>,
    /// The target of the query, or none for the default.
    pub target: Option<QueryTarget>,
    /// How long the peer may take, in milliseconds; zero states no bound.
    pub timeout_ms: u64,
    /// The QoS of the request; the default is not written.
    pub qos: QosLevel,
}

/// Why a `get` is not written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestRefusal {
    /// The keyexpr is empty: the wire has no way to say a query of nothing.
    EmptyKeyexpr,
}

/// A `get`, ready to encode.
#[derive(Debug, Clone, Copy)]
pub struct RequestWriter<'a> {
    parts: GetParts<'a>,
}

impl<'a> RequestWriter<'a> {
    /// The writer for `parts`, or the refusal of a query the wire cannot carry.
    pub fn new(parts: GetParts<'a>) -> Result<Self, RequestRefusal> {
        if parts.keyexpr.is_empty() {
            return Err(RequestRefusal::EmptyKeyexpr);
        }
        Ok(Self { parts })
    }

    /// Encode the `Request` into `sink`. `LengthOutOfRange` for a keyexpr past the
    /// protocol's `u16` length or parameters past its `u32` length, before a byte of
    /// either is written.
    pub fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError>
    where
        CodecError: From<S::Error>,
    {
        let parts = &self.parts;

        // The message is described in the codec's PARTS form: every field a reference, a
        // slice or a few words, and the codec's own wire writer reads it (`RequestWire`).
        // The lent form of the same codecs holds their lists inline at the capacity the
        // deployment gives them, which a `Query` with no extension and an envelope of three
        // entries would carry on the stack all the same (a frame of 3,328 bytes).

        // The Query body: the codec derives the `C`, `P` and `Z` flags and the parameters'
        // length from what the value holds. The parameters ride only in a build that
        // carries them, as the owned builder's `QueryMetadata` path does
        // (`query-selector-parameters`).
        #[cfg(feature = "query-selector-parameters")]
        let parameters: Option<Bytes<'_, { usize::MAX }>> = if parts.parameters.is_empty() {
            None
        } else {
            Some(crate::codec_owned::sent(parts.parameters)?)
        };
        #[cfg(not(feature = "query-selector-parameters"))]
        let parameters: Option<Bytes<'_, { usize::MAX }>> = None;
        let query = QueryParts {
            header: QUERY_HEADER,
            consolidation: parts.consolidation.map(|mode| mode.wire_byte()),
            parameters,
            extensions: None,
        };

        // The envelope's extensions, in the order the owned builder writes them: the
        // QoS unless it is the default, then the target, then the timeout. The entry of
        // the QoS is `ENC_ZINT | 0x01`, the one every control message carries and the
        // owned builder writes.
        let qos = ExtZintParts {
            value: u64::from(parts.qos.raw),
        };
        let target = ExtZintParts {
            value: parts
                .target
                .map_or(0, |target| u64::from(target.wire_byte())),
        };
        let timeout = ExtZintParts {
            value: parts.timeout_ms,
        };
        let mut chain = [zint_entry(0, &UNUSED_ENTRY_BODY); CHAIN_ENTRIES];
        let mut count = 0;
        if parts.qos != QosLevel::DEFAULT {
            chain[count] = zint_entry(QOS_EXT_HEADER, &qos);
            count += 1;
        }
        if parts.target.is_some() {
            chain[count] = zint_entry(ENC_ZINT | FLAG_EXT_M | TARGET_EXT_ID, &target);
            count += 1;
        }
        if parts.timeout_ms != 0 {
            chain[count] = zint_entry(ENC_ZINT | TIMEOUT_EXT_ID, &timeout);
            count += 1;
        }
        let chain = &mut chain[..count];
        link_chain(chain);

        let suffix = WireexprLocalParts {
            id: 0,
            suffix: Some(crate::codec_owned::sent_suffix(parts.keyexpr)?),
        };
        let keyexpr = WireexprParts {
            body: WireexprPartsBody::WireexprLocal(&suffix),
        };
        let request = RequestParts {
            header: REQUEST_HEADER,
            rid: parts.rid,
            keyexpr: &keyexpr,
            // A chain of no entry is none: the bounds of a chain hold one entry or more.
            extensions: Bounded::new(&*chain),
            body: RequestPartsBody::CodecZenohQuery(&query),
        };
        RequestWire::encode_source(&request, sink).map_err(CodecError::from)
    }
}

/// An integer-valued extension entry.
const fn zint_entry<'a>(header: u8, body: &'a ExtZintParts) -> ExtEntryParts<'a> {
    ExtEntryParts {
        header,
        body: ExtEntryPartsBody::CodecZenohExtZint(body),
    }
}

/// Set the chain-continuation `Z` bit on every entry but the last, which ends the
/// chain.
fn link_chain(chain: &mut [ExtEntryParts<'_>]) {
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

#[cfg(all(test, feature = "alloc", feature = "codec-request"))]
mod tests {
    use super::*;
    use crate::declare_ext_qos::QOS_DECLARE;
    use crate::metadata::QueryMetadata;
    use crate::request_build::build_request_query_with_meta;
    use alloc::vec::Vec;
    use sce_forge_runtime::codec::SliceSink;

    /// The bytes the owned path writes for `parts`.
    fn owned_bytes(parts: &GetParts<'_>) -> Vec<u8> {
        let meta = QueryMetadata {
            target: parts.target,
            consolidation: parts.consolidation,
            parameters: (!parts.parameters.is_empty()).then(|| parts.parameters.to_vec()),
            timeout_ms: parts.timeout_ms as u32,
            qos: Some(parts.qos),
            ..QueryMetadata::default()
        };
        let request = build_request_query_with_meta(parts.rid, 0, Some(parts.keyexpr), &meta)
            .expect("the owned request is built");
        let view = request.try_as_borrowed().expect("a view");
        view.encode_to_vec()
    }

    /// The bytes the writer writes for `parts`.
    fn lent_bytes(parts: GetParts<'_>) -> Vec<u8> {
        let writer = RequestWriter::new(parts).expect("the query is writable");
        let mut buffer = [0u8; 512];
        let mut sink = SliceSink::new(&mut buffer);
        writer.encode(&mut sink).expect("the buffer holds it");
        let len = sink.position();
        buffer[..len].to_vec()
    }

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
        for keyexpr in ["demo/**", "a", "demo/example/zenoh-rs-pub"] {
            for rid in [0u64, 1, 300, 1 << 40] {
                for consolidation in consolidations {
                    for target in targets {
                        for params in parameters {
                            for timeout_ms in [0u64, 1, 10_000, u64::from(u32::MAX)] {
                                for qos in [QosLevel::DEFAULT, QOS_DECLARE] {
                                    let parts = GetParts {
                                        rid,
                                        keyexpr,
                                        parameters: params,
                                        consolidation,
                                        target,
                                        timeout_ms,
                                        qos,
                                    };
                                    assert_eq!(
                                        lent_bytes(parts),
                                        owned_bytes(&parts),
                                        "rid {rid} key {keyexpr} {consolidation:?} {target:?} \
                                         params {} timeout {timeout_ms} qos {qos:?}",
                                        params.len(),
                                    );
                                    compared += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        // Every combination was compared; a loop that compared none would pass.
        assert_eq!(compared, 3 * 4 * 4 * 3 * 3 * 4 * 2);
    }

    #[test]
    fn a_get_of_an_empty_keyexpr_is_refused_not_repaired() {
        let parts = GetParts {
            rid: 1,
            keyexpr: "",
            parameters: b"",
            consolidation: None,
            target: None,
            timeout_ms: 0,
            qos: QosLevel::DEFAULT,
        };
        assert_eq!(
            RequestWriter::new(parts).err(),
            Some(RequestRefusal::EmptyKeyexpr)
        );
    }

    #[test]
    fn a_get_of_a_keyexpr_past_its_protocol_bound_is_refused_at_encode() {
        let past_bound = "k".repeat(usize::from(u16::MAX) + 1);
        let parts = GetParts {
            rid: 1,
            keyexpr: &past_bound,
            parameters: b"",
            consolidation: None,
            target: None,
            timeout_ms: 0,
            qos: QosLevel::DEFAULT,
        };
        let writer = RequestWriter::new(parts).expect("a non-empty keyexpr is writable");
        let mut buffer = [0u8; 16];
        let mut sink = SliceSink::new(&mut buffer);
        assert_eq!(
            writer.encode(&mut sink).err(),
            Some(CodecError::LengthOutOfRange)
        );
        assert_eq!(sink.position(), 0, "nothing is written");
    }
}

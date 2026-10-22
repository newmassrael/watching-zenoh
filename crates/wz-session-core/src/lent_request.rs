// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A `get` written as the codec's BORROWED `Request`, straight from the caller's own
//! text: the query a node with no allocator asks.
//!
//! The owned path ([`crate::request_build::RequestQueryBuilder`]) makes a `RequestOwned`
//! (a `String` for the keyexpr, a `Vec` for the parameters, a `Vec` for the extension
//! chain) and encodes that, which a session with no allocator cannot do, so
//! `send_request_query` refuses it with `FeatureDisabled`. [`RequestWriter`] takes the
//! description of the query ([`GetParts`]) with every field borrowed and writes the
//! `Request` the owned path writes, byte for byte, in the same way
//! [`crate::lent_response::ResponseWriter`] writes a reply: the text and the parameters
//! are read where they lie and the few numbers it has to make go in the codec's own
//! fixed-capacity lists.
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
//! [`RequestRefusal`] and not repaired.

use sce_forge_runtime::codec::{CodecError, SceSink};
use sce_forge_runtime::heapless::Vec as HeaplessVec;
use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
use wz_codecs::ext_zint::ExtZint;
use wz_codecs::query::Query;
use wz_codecs::request::{Request, RequestVariant};

use crate::lent_control::{local, qos_entry, with_z};
use crate::query_mode::{ConsolidationMode, QueryTarget, TARGET_EXT_ID};
use crate::request_routing_context::TIMEOUT_EXT_ID;
use crate::sample::QosLevel;

/// The `Request` envelope header of a query that names its keyexpr inline:
/// `_Z_MID_N_REQUEST | N` (a suffix follows the id). `M` derives from the `Local` arm at
/// encode time, and `Z` is added when the envelope carries extensions.
const REQUEST_HEADER: u8 = 0x1C | 0x20;

/// The Query body's header: `_Z_MID_Z_QUERY`, with the `C` (consolidation) and `P`
/// (parameters) flags added below.
const QUERY_HEADER: u8 = 0x03;
const FLAG_QUERY_C: u8 = 0x20;
#[cfg(feature = "query-selector-parameters")]
const FLAG_QUERY_P: u8 = 0x40;

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

    /// Encode the `Request` into `sink`.
    pub fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError> {
        let parts = &self.parts;

        // The Query body: the consolidation byte and the parameters behind the flags
        // that announce them.
        let mut query_header = QUERY_HEADER;
        let consolidation = parts.consolidation.map(|mode| {
            query_header |= FLAG_QUERY_C;
            mode.wire_byte()
        });
        // The parameters ride only in a build that carries them, as the owned
        // builder's `QueryMetadata` path does (`query-selector-parameters`).
        #[cfg(feature = "query-selector-parameters")]
        let parameters = (!parts.parameters.is_empty()).then(|| {
            query_header |= FLAG_QUERY_P;
            parts.parameters
        });
        #[cfg(not(feature = "query-selector-parameters"))]
        let parameters: Option<&[u8]> = None;
        let query = Query {
            header: query_header,
            consolidation,
            parameters_len: parameters.map(|bytes| bytes.len() as u64),
            parameters,
            extensions: None,
        };

        // The envelope's extensions, in the order the owned builder writes them: the
        // QoS unless it is the default, then the target, then the timeout.
        let mut chain: HeaplessVec<ExtEntry<'_>, 8> = HeaplessVec::new();
        if parts.qos != QosLevel::DEFAULT {
            // Three entries in a list of eight. The entry is `ENC_ZINT | 0x01`, the
            // one every control message carries and the owned builder writes.
            let _ = chain.push(qos_entry(parts.qos));
        }
        if let Some(target) = parts.target {
            let _ = chain.push(zint_entry(
                ENC_ZINT | FLAG_EXT_M | TARGET_EXT_ID,
                u64::from(target.wire_byte()),
            ));
        }
        if parts.timeout_ms != 0 {
            let _ = chain.push(zint_entry(ENC_ZINT | TIMEOUT_EXT_ID, parts.timeout_ms));
        }
        link_chain(&mut chain);
        let header = if chain.is_empty() {
            REQUEST_HEADER
        } else {
            with_z(REQUEST_HEADER)
        };

        Request {
            header,
            rid: parts.rid,
            keyexpr: local(0, Some(parts.keyexpr)),
            extensions: (!chain.is_empty()).then_some(chain),
            body: RequestVariant::CodecZenohQuery(query),
        }
        .encode(sink)
    }
}

/// An integer-valued extension entry.
fn zint_entry<'a>(header: u8, value: u64) -> ExtEntry<'a> {
    ExtEntry {
        header,
        body: ExtEntryVariant::CodecZenohExtZint(ExtZint { value }),
    }
}

/// Set the chain-continuation `Z` bit on every entry but the last, which ends the
/// chain.
fn link_chain(chain: &mut HeaplessVec<ExtEntry<'_>, 8>) {
    let Some(last) = chain.len().checked_sub(1) else {
        return;
    };
    for (index, entry) in chain.iter_mut().enumerate() {
        entry.header = if index == last {
            entry.header & !crate::ext_header::EXT_FLAG_Z
        } else {
            entry.header | crate::ext_header::EXT_FLAG_Z
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
}

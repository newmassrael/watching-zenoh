// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a `get` asks, every field borrowed from whoever holds it: the description the session
//! writes a `Request(Query)` from (`lent_request::RequestWriter`) and, where the session sends
//! an owned message instead, builds that message from (`GetParts::owned_request`). The options a
//! program states (`QueryOptions::query_parts`) and the metadata a session API hands down
//! (`QueryParts::of_metadata`) are both read into it, so the wire a query takes does not depend
//! on which of them it came from.

use crate::query_mode::{ConsolidationMode, QueryTarget};
use crate::reply_stage::EncodingParts;
use crate::sample::{QosLevel, SourceInfo};
use crate::wire_key::WireKey;

/// What a query asks of the peers that answer it, apart from its request id and its key.
///
/// An empty slice states that there is none: the wire carries no empty parameters and no empty
/// attachment. Each field rides only in a build that composes it (`query-selector-parameters`,
/// `query-value`, `query-source-info`, `query-attachment`), as the owned builder reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryParts<'a> {
    /// The selector parameters.
    pub parameters: &'a [u8],
    /// The consolidation the asker states, or none for the default.
    pub consolidation: Option<ConsolidationMode>,
    /// The target of the query, or none for the default.
    pub target: Option<QueryTarget>,
    /// How long the peer may take, in milliseconds; zero states no bound.
    pub timeout_ms: u32,
    /// The QoS of the request; the default is not written.
    pub qos: QosLevel,
    /// The value the query carries: its encoding and its payload. A payload of no bytes under
    /// the zero encoding is no value.
    pub value: Option<(EncodingParts<'a>, &'a [u8])>,
    /// The source the query names.
    pub source_info: Option<&'a SourceInfo>,
    /// The attachment.
    pub attachment: &'a [u8],
    /// The timestamp stack the query starts.
    #[cfg(feature = "pubsub-ts-stack")]
    pub ts_stack: Option<&'a crate::ts_stack::TsStack>,
}

impl<'a> QueryParts<'a> {
    /// A query that states nothing beyond its key: every slot at the value the wire leaves out.
    pub const PLAIN: Self = Self {
        parameters: &[],
        consolidation: None,
        target: None,
        timeout_ms: 0,
        qos: QosLevel::DEFAULT,
        value: None,
        source_info: None,
        attachment: &[],
        #[cfg(feature = "pubsub-ts-stack")]
        ts_stack: None,
    };
}

#[cfg(feature = "alloc")]
impl<'a> QueryParts<'a> {
    /// The query `meta` states, borrowed from it.
    pub fn of_metadata(meta: &'a crate::metadata::QueryMetadata) -> Self {
        Self {
            parameters: meta.parameters.as_deref().unwrap_or(&[]),
            consolidation: meta.consolidation,
            target: meta.target,
            timeout_ms: meta.timeout_ms,
            qos: meta.qos.unwrap_or(QosLevel::DEFAULT),
            value: meta
                .value
                .as_ref()
                .map(|(encoding, payload)| (EncodingParts::of(encoding), payload.as_slice())),
            source_info: meta.source_info.as_ref(),
            attachment: meta.attachment.as_deref().unwrap_or(&[]),
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: meta.ts_stack.as_ref(),
        }
    }

    /// The same query as owned metadata: what the owned builder
    /// (`request_build::build_request_query_with_meta`) is handed.
    pub fn metadata(&self) -> crate::metadata::QueryMetadata {
        crate::metadata::QueryMetadata {
            target: self.target,
            consolidation: self.consolidation,
            attachment: (!self.attachment.is_empty()).then(|| self.attachment.to_vec()),
            parameters: (!self.parameters.is_empty()).then(|| self.parameters.to_vec()),
            source_info: self.source_info.cloned(),
            value: self.value.map(|(encoding, payload)| {
                (
                    crate::sample::EncodingHint {
                        packed_id: encoding.packed_id,
                        schema: encoding.schema.map(<[u8]>::to_vec),
                    },
                    payload.to_vec(),
                )
            }),
            timeout_ms: self.timeout_ms,
            qos: Some(self.qos),
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: self.ts_stack.cloned(),
        }
    }
}

/// A `get` as it goes out on one link: the request id its answers name, the key as that link
/// names it, and what it asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetParts<'a> {
    /// The request id the peer echoes in its replies and its final.
    pub rid: crate::wire_id::RequestId,
    /// The key the query asks about, as the wire names it.
    pub key: WireKey<'a>,
    /// What the query asks.
    pub query: QueryParts<'a>,
}

#[cfg(all(feature = "alloc", feature = "codec-request"))]
impl GetParts<'_> {
    /// The owned `Request` of this description: what a session sends where it does not write the
    /// query from its parts (a key it rewrites, counters that read the owned message, a timestamp
    /// stack). Refused as the owned builder refuses, and parameters past
    /// [`crate::request_build::REQUEST_QUERY_PARAMETERS_MAX_LEN`] are `LengthOutOfRange` here
    /// where the builder would stop.
    pub fn owned_request(
        &self,
    ) -> Result<crate::wire::RequestOwned, sce_forge_runtime::codec::CodecError> {
        if self.query.parameters.len() > crate::request_build::REQUEST_QUERY_PARAMETERS_MAX_LEN {
            return Err(sce_forge_runtime::codec::CodecError::LengthOutOfRange);
        }
        crate::request_build::build_request_query_with_meta(
            self.rid,
            self.key,
            &self.query.metadata(),
        )
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::metadata::QueryMetadata;
    use crate::sample::EncodingHint;

    /// Metadata read into parts and back is the metadata it was, slot for slot, apart from an
    /// unstated QoS, which the parts state as the default the wire leaves out.
    #[test]
    fn metadata_reads_into_parts_and_back() {
        let meta = QueryMetadata {
            target: Some(QueryTarget::AllComplete),
            consolidation: Some(ConsolidationMode::Latest),
            attachment: Some(alloc::vec![1, 2, 3]),
            parameters: Some(b"_time=[..]".to_vec()),
            source_info: Some(SourceInfo::new(&[7; 4], 9, 11)),
            value: Some((
                EncodingHint {
                    packed_id: 0x0B,
                    schema: Some(b"json".to_vec()),
                },
                b"payload".to_vec(),
            )),
            timeout_ms: 1_500,
            qos: None,
            ..QueryMetadata::default()
        };
        let parts = QueryParts::of_metadata(&meta);
        assert_eq!(parts.qos, QosLevel::DEFAULT, "no QoS stated is the default");
        let back = parts.metadata();
        assert_eq!(back.target, meta.target);
        assert_eq!(back.consolidation, meta.consolidation);
        assert_eq!(back.attachment, meta.attachment);
        assert_eq!(back.parameters, meta.parameters);
        assert_eq!(back.source_info, meta.source_info);
        assert_eq!(back.value, meta.value);
        assert_eq!(back.timeout_ms, meta.timeout_ms);
        assert_eq!(back.qos, Some(QosLevel::DEFAULT));
    }

    /// Empty parameters and an empty attachment are none on the way back: the wire has no empty
    /// one to carry.
    #[test]
    fn empty_slices_read_back_as_none() {
        let back = QueryParts::PLAIN.metadata();
        assert_eq!(back.parameters, None);
        assert_eq!(back.attachment, None);
        assert_eq!(back.value, None);
        assert_eq!(back.source_info, None);
    }
}

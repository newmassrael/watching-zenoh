// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Wire-encode-time metadata bundles for Push (R237) and Query (R240).
//!
//! Both bundles are dispatch-boundary value types — the upper-layer
//! session API (`PublishOptions` / `QueryOptions`) converts caller
//! preferences into these and hands them to the codec layer. Keeping
//! the bundles in wz-session-core lets MCU profiles compose the same
//! API without dragging the tokio-bound session module.

use alloc::vec::Vec;

use crate::query_mode::{ConsolidationMode, QueryTarget};
use crate::sample::{EncodingHint, QosLevel, SourceInfo, TimestampHint};

/// R237 — caller-supplied per-publish metadata routed through the
/// codec via `SessionLinkActions::send_push_with_meta` /
/// `send_undecl_push_with_meta`. Every field is optional so the empty
/// bundle reduces the wire shape to the metadata-stripped baseline
/// that `build_push_literal` / `build_push_aliased` /
/// `build_push_del_literal` / `build_push_del_aliased` emit.
///
/// Mirrors a subset of `PublishOptions` — the dispatch-time fields
/// (locality / reliability / kind) live on `PublishOptions`, the
/// wire-encode-time metadata lives here. The split keeps the wire
/// encoder boundary clean: session_glue stays oblivious to publisher
/// locality predicates, and the session module owns the conversion
/// via `PublishOptions::push_metadata`.
#[derive(Debug, Clone, Default)]
pub struct PushMetadata {
    /// Body-level timestamp (zenoh-pico `_z_m_push_commons_t._timestamp`,
    /// gated by `_Z_FLAG_Z_P_T` for Put / `_Z_FLAG_Z_D_T` for Del).
    pub timestamp: Option<TimestampHint>,
    /// Body-level encoding (Put kind only; zenoh-pico `_z_msg_del_t`
    /// has no encoding slot so a `Del` build_push call ignores this
    /// field even when set).
    pub encoding: Option<EncodingHint>,
    /// Body-level source identification (ext_id=0x01 ENC_ZBUF).
    pub source_info: Option<SourceInfo>,
    /// Body-level attachment blob (ext_id=0x03 ENC_ZBUF).
    pub attachment: Option<Vec<u8>>,
    /// Outer-level QoS metadata (Push extension ext_id=0x01 ENC_ZINT).
    pub qos: Option<QosLevel>,
}

impl PushMetadata {
    /// `true` when every metadata slot is `None` — callers can use
    /// this to short-circuit to the no-metadata `build_push_*` fast
    /// paths without paying the with-meta builder cost.
    pub fn is_empty(&self) -> bool {
        self.timestamp.is_none()
            && self.encoding.is_none()
            && self.source_info.is_none()
            && self.attachment.is_none()
            && self.qos.is_none()
    }

    /// `true` when the QoS layer requests express delivery (the
    /// [`QosLevel::is_express`] projection of the optional `qos` slot).
    /// The single source for the "is this Push express" derivation the
    /// publish paths feed to the send seam's `express` arm (the
    /// `flush_batch_if_express` batch-window drain). R311mv (session
    /// review) — both [`Session::publish`] and
    /// [`Session::publish_aliased`] consulted an inline copy of this
    /// derivation (introduced at R311ms / R311mt); centralised here so
    /// the projection has one home. The `transport-batching` gate stays
    /// at the seam (the flag is always computable; only its *effect* is
    /// batching-gated), so the publish call sites no longer fork on the
    /// feature.
    pub fn is_express(&self) -> bool {
        self.qos.as_ref().is_some_and(QosLevel::is_express)
    }
}

/// R240 — Query-side counterpart of [`PushMetadata`]. Bundles the
/// caller-set `QueryOptions` fields that route through the layered
/// `RequestQueryBuilder` so a `Session::query` call can hand them to
/// `SessionLinkActions::send_request_query_with_meta` without the
/// glue layer learning about `QueryOptions` directly.
///
/// Field coverage at R240 is *partial vs* `QueryOptions`:
///
/// | QueryOptions field | Wire propagation slot |
/// |--------------------|-----------------------|
/// | `target`           | `RequestQueryBuilder::request_target` |
/// | `consolidation`    | `RequestQueryBuilder::consolidation` |
/// | `attachment`       | `RequestQueryBuilder::query_attachment` |
/// | `parameters`       | `RequestQueryBuilder::parameters` (`Q_P` 0x40) |
/// | `timeout_ms`       | `RequestQueryBuilder::request_timeout_ms` |
/// | `payload`          | R241+ carry — wz codec has no Q_B body slot yet |
/// | `encoding`         | R241+ carry — wz codec has no Q_E inline slot yet |
///
/// `payload` / `encoding` stay on `QueryOptions` as future-additive
/// slots so a later round that lands the Q_B / Q_E codec extensions
/// surfaces the propagation without an API break.
#[derive(Debug, Clone, Default)]
pub struct QueryMetadata {
    /// Reply target hint (`Q_T` flag on the outbound Query). `None`
    /// elides the target byte → peer decodes
    /// `Z_QUERY_TARGET_DEFAULT` = `BEST_MATCHING`.
    pub target: Option<QueryTarget>,
    /// Reply consolidation hint (`Q_C` flag + consolidation byte).
    /// `None` elides → peer decodes `Z_CONSOLIDATION_MODE_AUTO`.
    pub consolidation: Option<ConsolidationMode>,
    /// Query-level attachment blob (ext_id=0x05 ZBUF on the Query
    /// ext chain). `None` elides the ext.
    pub attachment: Option<Vec<u8>>,
    /// Query selector parameters (the `_sn=START..&_max=N` URL-style
    /// selector after `?`; the `Q_P` flag 0x40 + the params slice on the
    /// Query body). `None` (or empty) elides the flag + slice. What a
    /// recovery / history GET carries so the advanced cache's
    /// `answer_from_ring` filters its ring.
    pub parameters: Option<Vec<u8>>,
    /// Query-level source-info (querier identity: zid / eid / sn;
    /// ext_id=0x01 ZBUF on the Query ext chain). `None` elides the ext.
    pub source_info: Option<SourceInfo>,
    /// Request-level timeout in milliseconds. `0` elides the ext
    /// per zenoh-pico's `_z_n_msg_request_needed_exts` predicate
    /// (`msg->_ext_timeout_ms != 0`).
    pub timeout_ms: u32,
}

impl QueryMetadata {
    /// `true` when every wire-propagatable slot is empty — callers
    /// can use this to short-circuit
    /// `SessionLinkActions::send_request_query`'s no-metadata fast
    /// path. Symmetric to [`PushMetadata::is_empty`].
    pub fn is_empty(&self) -> bool {
        self.target.is_none()
            && self.consolidation.is_none()
            && self.attachment.is_none()
            && self.parameters.is_none()
            && self.source_info.is_none()
            && self.timeout_ms == 0
    }
}

// R311fs — QueryMetadata is_empty() tests, relocated from
// wz-runtime-tokio::session_glue to their SSOT home (this struct lives
// here). QueryMetadata + its query_mode field types are unconditionally
// compiled (no codec gate on this module), so the tests are
// `#[cfg(test)]`-only: the old session_glue `codec-request` gate was
// incidental to that cluster's location, not to this type's domain.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_metadata_default_is_empty() {
        let meta = QueryMetadata::default();
        assert!(meta.is_empty());
    }

    #[test]
    fn query_metadata_with_target_is_not_empty() {
        let meta = QueryMetadata {
            target: Some(QueryTarget::All),
            ..Default::default()
        };
        assert!(!meta.is_empty());
    }

    #[test]
    fn query_metadata_with_consolidation_is_not_empty() {
        let meta = QueryMetadata {
            consolidation: Some(ConsolidationMode::Latest),
            ..Default::default()
        };
        assert!(!meta.is_empty());
    }

    #[test]
    fn query_metadata_with_attachment_is_not_empty() {
        let meta = QueryMetadata {
            attachment: Some(b"q-att".to_vec()),
            ..Default::default()
        };
        assert!(!meta.is_empty());
    }

    #[test]
    fn query_metadata_with_timeout_ms_nonzero_is_not_empty() {
        let meta = QueryMetadata {
            timeout_ms: 5_000,
            ..Default::default()
        };
        assert!(!meta.is_empty());
    }
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Request-builder cluster — runtime-agnostic wire-record construction
//! for the `z_get` initiator path. The minimal one-shot helpers
//! (`build_request_query` + the five `build_request_query_with_*`
//! layered variants) plus the fluent [`RequestQueryBuilder`] compose a
//! `Request(Query)` network message from a request id, a keyexpr
//! (literal / aliased / compound), and the optional Query-layer +
//! Request-layer settings — mirroring zenoh-pico's `_z_request_encode ->
//! _z_query_encode` chain.
//!
//! R311eh — lifted verbatim from `wz-runtime-tokio::session_glue`, the
//! mirror of the R311dv [`crate::response_build`] move. The cluster is
//! pure value construction over `wz_codecs` records (no `async`, no
//! `LinkDriver`, no tokio), so it belongs in the no_std core where both
//! the tokio (AP) and lwIP (MCU) runtimes can reach it.
//! `wz-runtime-tokio::session_glue` re-exports the public surface so
//! `crate::session_glue::{build_request_query*, RequestQueryBuilder,
//! REQUEST_QUERY_PARAMETERS_MAX_LEN, QUERY_EXT_ZBUF_MAX_LEN}` callers
//! (the `session.rs` `z_get` path + the session_glue regression /
//! byte-stable tests) resolve unchanged. The whole module gates on
//! `all(alloc, codec-request)` — without the Request codec there is no
//! wire frame to build, and the builders allocate owned codec buffers.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;
use wz_codecs::ext_zint::ExtZint;
use wz_codecs::query::QueryOwned;
use wz_codecs::request::{RequestOwned, RequestOwnedVariant};
use wz_codecs::timestamp::TimestampOwned;
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
use wz_codecs::wireexpr_local::WireexprLocalOwned;

use crate::qos::{CongestionControl, Priority};
use crate::query_mode::{ConsolidationMode, QueryTarget};

/// R121j-1 — build a `Request` network-message that carries a
/// `Query` body, addressed to the keyexpr resolved by
/// `(keyexpr_mapping_id, keyexpr_suffix)`. Mirrors zenoh-pico
/// `_z_request_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/network.c:114-169` with the
/// `_Z_REQUEST_QUERY` tag-arm + `_z_query_encode` body at
/// `vendor/zenoh-pico/src/protocol/codec/message.c:394-451`.
///
/// AP MVP scope: emits the minimal Query shape with no consolidation
/// (`Z_CONSOLIDATION_MODE_DEFAULT`), no parameters, no Query-level
/// extensions (body / info / attachment), and no Request-level
/// extensions (qos / tstamp / target / budget / timeout_ms). Under
/// these defaults zenoh-pico's `_z_msg_query_required_extensions`
/// returns zero, `_z_n_msg_request_needed_exts` returns zero, and
/// the outer Z flag stays clear — the wire reduces to:
///
/// ```text
///   [Request.header = _Z_MID_N_REQUEST (0x1C)
///                      | (suffix.is_some() ? 0x20 : 0)   // N
///                      | codegen-derived 0x40             // M from Local
///                      | (Z extensions = 0 here)]
///   VLE(rid)
///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
///   [Query.header = _Z_MID_Z_QUERY (0x03)]   // no C / P / Z flags
/// ```
///
/// Future rounds add layered helpers:
///   - `build_request_query_with_consolidation(consolidation_mode)`
///     sets bit 5 (`_Z_FLAG_Z_Q_C`) + emits the 1-byte consolidation
///     value (message.c:411-413).
///   - `build_request_query_with_parameters(params)` sets bit 6
///     (`_Z_FLAG_Z_Q_P`) + emits the params slice (message.c:426-428).
///   - `build_request_query_with_exts(...)` adds the body / info /
///     attachment Query-level extensions or the qos / tstamp /
///     target / budget / timeout_ms Request-level extensions.
///
/// Each layered helper extends this byte-compare contract with its
/// own vectors; the minimal shape pinned here is the foundation.
///
/// `rid` is the request id the peer echoes back in its Response /
/// ResponseFinal; reuse by the caller is allowed but the AP MVP path
/// allocates a fresh `rid` per `z_get` to keep the in-flight Query
/// table simple.
///
/// `keyexpr_mapping_id` / `keyexpr_suffix` convention matches the
/// DECLARE builders:
///   - `(0, Some(s))`: literal — the queried keyexpr is `s` itself
///     (id=0 is the wz literal-sentinel).
///   - `(N, None)`: alias — the queried keyexpr is the peer's
///     mapping for `N`.
///   - `(N, Some(s))`: compound — alias `N`'s prefix + `s`.
#[cfg(feature = "codec-request")]
pub fn build_request_query(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> RequestOwned {
    let suffix_string = keyexpr_suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    RequestOwned {
        // MID 0x1C (_Z_MID_N_REQUEST) + N gate; M is codegen-derived
        // from the wireexpr Local arm. Z (outer ext) stays clear:
        // this minimal builder emits no Request-level extensions.
        header: 0x1C | n_flag,
        rid,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: keyexpr_mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: RequestOwnedVariant::CodecZenohQuery(QueryOwned {
            // MID 0x03 (_Z_MID_Z_QUERY) only. No C (consolidation),
            // no P (params), no Z (Query-level exts). The byte-
            // compare test below pins this minimal shape.
            header: 0x03,
            consolidation: None,
            parameters_len: None,
            parameters: None,
            extensions: None,
        }),
    }
}

/// R121j-2a — fluent builder for `Request(Query)` that composes the
/// layered options exposed individually by R121j-1a/1b/1c/1d/1e
/// (consolidation / parameters / Query-attachment / Request-timeout
/// / Request-target). The five one-shot helpers below stay as thin
/// wrappers around this builder so existing callers see no surface
/// change; the builder unlocks the multi-layer composition that the
/// one-shot helpers cannot express (each one-shot resets the
/// extensions vec, so chaining two of them via `.body` mutation
/// silently drops the first).
///
/// Setter validation (panic conditions) is preserved per layer:
/// `parameters` rejects empty / oversize, `query_attachment` rejects
/// empty / oversize, `request_timeout_ms` rejects zero. The default
/// values that zenoh-pico's encoder omits from the wire
/// (`ConsolidationMode::AUTO`, `QueryTarget::BEST_MATCHING`, empty
/// params / attachment, zero timeout) remain non-representable —
/// callers wanting any of those simply do not call the corresponding
/// setter, leaving the field as `None` in the builder so `build()`
/// emits the minimal-shape wire bytes that match zenoh-pico's
/// encode-on-non-default predicate at network.c / message.c.
///
/// Request-level extension ordering at `build()` time follows
/// zenoh-pico's `_z_request_encode` chain
/// (vendor/zenoh-pico/src/protocol/codec/network.c:122-167):
/// qos → tstamp → target → budget → timeout. The intermediate Z
/// chain-continuation bits are set on every entry except the last.
/// (Only target + timeout are implemented as setters today; qos /
/// tstamp / budget sub-setters layer in once their codec wiring lands
/// — see the audit-traced carry in the Round 121j-1d /1e entries.)
#[cfg(feature = "codec-request")]
pub struct RequestQueryBuilder {
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<String>,
    // Query-layer settings.
    consolidation: Option<ConsolidationMode>,
    parameters: Option<Vec<u8>>,
    query_attachment: Option<Vec<u8>>,
    // Request-layer ext settings.
    request_qos: Option<u8>,
    request_tstamp: Option<TimestampOwned>,
    request_target: Option<QueryTarget>,
    request_budget: Option<u32>,
    request_timeout_ms: Option<u64>,
}

#[cfg(feature = "codec-request")]
impl RequestQueryBuilder {
    /// Begin a builder rooted in the same baseline contract as
    /// [`build_request_query`]: minimal Request(Query) envelope with
    /// the keyexpr arm (literal id=0 + Some, alias id=N + None,
    /// compound id=N + Some). Same id/suffix semantics.
    pub fn new(rid: u64, keyexpr_mapping_id: u64, keyexpr_suffix: Option<&str>) -> Self {
        Self {
            rid,
            keyexpr_mapping_id,
            keyexpr_suffix: keyexpr_suffix.map(str::to_string),
            consolidation: None,
            parameters: None,
            query_attachment: None,
            request_qos: None,
            request_tstamp: None,
            request_target: None,
            request_budget: None,
            request_timeout_ms: None,
        }
    }

    /// Set the Request-level qos extension to the caller-supplied
    /// packed byte. Bit layout per zenoh-pico's `_z_n_qos_create`
    /// (`vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h`):
    ///
    /// ```text
    ///   bits 0-2: priority (0-7; zenoh-pico z_priority_t)
    ///   bit  3:   nodrop   (1 = BLOCK on congestion; 0 = DROP)
    ///   bit  4:   express  (1 = express path; 0 = normal)
    ///   bits 5-7: reserved (zero)
    /// ```
    ///
    /// The setter is intentionally low-level — wz exposes the
    /// pre-packed byte so callers integrating directly with
    /// zenoh-pico-defined constants can pass `_z_n_qos_create`'s
    /// output verbatim. A typed wrapper layering over this setter
    /// (`.request_qos_typed(priority, congestion, express)`) is a
    /// future ergonomic refinement.
    ///
    /// Emit position in the Request-level ext chain is FIRST (qos →
    /// tstamp → target → budget → timeout), matching zenoh-pico's
    /// `_z_request_encode` order at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c`.
    pub fn request_qos(mut self, packed: u8) -> Self {
        self.request_qos = Some(packed);
        self
    }

    /// Typed wrapper over [`Self::request_qos`] — packs `(priority,
    /// congestion, express)` into the wire byte using the exact bit
    /// layout zenoh-pico's `_z_n_qos_create` produces at
    /// `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h:84-89`:
    ///
    /// ```text
    ///   packed = (express << 4) | (nodrop << 3) | priority
    ///   where nodrop = (congestion == Block ? 1 : 0)
    /// ```
    ///
    /// Caller-facing typed inputs keep the priority / congestion /
    /// express semantics legible at the call site (vs the raw
    /// [`Self::request_qos`] packed-byte form). The wrapper does NOT
    /// validate the bit layout itself — it delegates to the same
    /// [`Self::request_qos`] storage so the chain emit path stays
    /// uniform.
    pub fn request_qos_typed(
        self,
        priority: Priority,
        congestion: CongestionControl,
        express: bool,
    ) -> Self {
        let packed = ((express as u8) << 4) | (congestion.wire_bit() << 3) | priority.wire_byte();
        self.request_qos(packed)
    }

    /// Set the Request-level timestamp extension. `time` is the
    /// 64-bit NTP-style timestamp the requester is correlating against
    /// (typically `Hal::now_ticks_*` lifted into the zenoh-pico NTP
    /// 64-bit shape); `zid` is the requester's zid bytes (1..=16 bytes
    /// per zenoh `_z_id_t` capacity at
    /// `vendor/zenoh-pico/include/zenoh-pico/protocol/core.h`'s
    /// `_Z_ID_LENGTH = 16`). Panics on empty zid (zenoh-pico's
    /// `_z_id_encode_as_slice` at
    /// `vendor/zenoh-pico/src/protocol/codec/message.c:58-70` rejects
    /// zero-length zid as a zenoh-protocol violation) and on a zid
    /// longer than 16 bytes.
    ///
    /// Wire shape per `_z_request_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c:132-137`:
    ///
    /// ```text
    ///   ext_header  = ENC_ZBUF(0x40) | id_tstamp(0x02)
    ///                 (NO M flag — zenoh-pico emits ext_tstamp as
    ///                  non-mandatory; the ext gets only the Z chain-
    ///                  continuation bit if a later ext follows.)
    ///   ext_value   = VLE(timestamp_body_len) + Timestamp.encode_bytes
    ///   Timestamp   = VLE(time) + VLE(zid_len) + zid_bytes
    /// ```
    ///
    /// Emit position in the Request-level ext chain is SECOND (qos →
    /// tstamp → target → budget → timeout), matching zenoh-pico's
    /// `_z_request_encode` order. The wire-shape match is verified by
    /// the byte-stable `request_query_builder_request_tstamp_emits_*`
    /// tests below.
    pub fn request_tstamp(mut self, time: u64, zid: &[u8]) -> Self {
        assert!(
            !zid.is_empty(),
            "RequestQueryBuilder::request_tstamp requires a non-empty zid \
             (zenoh-pico rejects len=0 as a protocol violation)",
        );
        assert!(
            zid.len() <= 16,
            "RequestQueryBuilder::request_tstamp zid length {} exceeds zenoh _Z_ID_LENGTH (16)",
            zid.len(),
        );
        self.request_tstamp = Some(TimestampOwned {
            time,
            zid_len: zid.len() as u64,
            zid: zid.to_vec(),
        });
        self
    }

    /// Set the Query-body consolidation mode. Subsequent calls
    /// overwrite (last-wins; standard builder idiom). See
    /// [`ConsolidationMode`] for the wire-byte contract.
    pub fn consolidation(mut self, mode: ConsolidationMode) -> Self {
        self.consolidation = Some(mode);
        self
    }

    /// Set the Query-body parameters slice. Panics on empty
    /// (zenoh-pico's encoder clears Q_P on empty) and on
    /// `len > REQUEST_QUERY_PARAMETERS_MAX_LEN` (wz codec bound).
    pub fn parameters(mut self, params: &[u8]) -> Self {
        assert!(
            !params.is_empty(),
            "RequestQueryBuilder::parameters requires a non-empty params slice",
        );
        assert!(
            params.len() <= REQUEST_QUERY_PARAMETERS_MAX_LEN,
            "params slice length {} exceeds wz Query codec's max-size ({})",
            params.len(),
            REQUEST_QUERY_PARAMETERS_MAX_LEN,
        );
        self.parameters = Some(params.to_vec());
        self
    }

    /// Set the Query-level attachment extension payload. Panics on
    /// empty and on `len > QUERY_EXT_ZBUF_MAX_LEN`.
    pub fn query_attachment(mut self, attachment: &[u8]) -> Self {
        assert!(
            !attachment.is_empty(),
            "RequestQueryBuilder::query_attachment requires a non-empty attachment slice",
        );
        assert!(
            attachment.len() <= QUERY_EXT_ZBUF_MAX_LEN,
            "attachment slice length {} exceeds wz ExtZbuf codec's max-size ({})",
            attachment.len(),
            QUERY_EXT_ZBUF_MAX_LEN,
        );
        self.query_attachment = Some(attachment.to_vec());
        self
    }

    /// Set the Request-level target extension. Wire mapping per
    /// [`QueryTarget::wire_byte`]; the M=1 mandatory marker is set on
    /// the emitted ExtEntry header per zenoh-pico convention
    /// (network.c:140).
    pub fn request_target(mut self, target: QueryTarget) -> Self {
        self.request_target = Some(target);
        self
    }

    /// Set the Request-level budget extension. Panics on zero
    /// (zenoh-pico's `_z_n_msg_request_needed_exts` at
    /// `vendor/zenoh-pico/src/protocol/definitions/network.c`
    /// declares `ext_budget = msg->_ext_budget != 0`, so a zero
    /// budget is encoded as "ext absent"). The value is the
    /// per-Query reply-volume budget; emit position sits between
    /// target and timeout in the Request-level ext chain.
    pub fn request_budget(mut self, value: u32) -> Self {
        assert!(
            value != 0,
            "RequestQueryBuilder::request_budget requires a non-zero budget; \
             zenoh-pico's ext_budget predicate clears the ext on zero",
        );
        self.request_budget = Some(value);
        self
    }

    /// Set the Request-level timeout extension. Panics on zero (the
    /// zenoh-pico encoder predicate clears the ext on zero).
    pub fn request_timeout_ms(mut self, timeout_ms: u64) -> Self {
        assert!(
            timeout_ms != 0,
            "RequestQueryBuilder::request_timeout_ms requires a non-zero timeout",
        );
        self.request_timeout_ms = Some(timeout_ms);
        self
    }

    /// Materialise the Request. Constructs the baseline envelope via
    /// [`build_request_query`], applies all Query-layer settings to
    /// the inner Query body, then assembles Request-level extensions
    /// in zenoh-pico's emit order with proper Z chain-continuation
    /// bits on intermediate entries.
    pub fn build(self) -> RequestOwned {
        let mut request = build_request_query(
            self.rid,
            self.keyexpr_mapping_id,
            self.keyexpr_suffix.as_deref(),
        );

        // Query-layer settings (consolidation / parameters /
        // Q-attachment). The codec gates these on Query.header
        // flags Q_C(0x20) / Q_P(0x40) / Q_Z(0x80).
        if let RequestOwnedVariant::CodecZenohQuery(ref mut query) = request.body {
            if let Some(mode) = self.consolidation {
                query.header |= 0x20;
                query.consolidation = Some(mode.wire_byte());
            }
            if let Some(params) = self.parameters {
                query.header |= 0x40;
                query.parameters_len = Some(params.len() as u64);
                query.parameters = Some(params);
            }
            if let Some(attachment) = self.query_attachment {
                query.header |= 0x80;
                query.extensions = Some(vec![ExtEntryOwned {
                    header: 0x40 | 0x05, // ENC_ZBUF | id_attachment
                    body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                        value_len: attachment.len() as u64,
                        value: attachment,
                    }),
                }]);
            }
        } else {
            unreachable!(
                "build_request_query must produce a CodecZenohQuery body — \
                 the layered builder relies on this invariant"
            );
        }

        // Request-level extensions in zenoh-pico encode order: qos →
        // tstamp → target → budget → timeout (network.c:122-167).
        // Today qos + tstamp + target + budget + timeout are exposed;
        // any future ext lands in its position-correct slot here.
        let mut request_exts: Vec<ExtEntryOwned> = Vec::new();
        if let Some(packed) = self.request_qos {
            request_exts.push(ExtEntryOwned {
                // ENC_ZINT(0x20) | id_qos(0x01). No M flag — qos is
                // an informational hint, not mandatory per the
                // ext_qos M=0 convention at zenoh-pico
                // vendor/zenoh-pico/src/protocol/codec/network.c.
                // Z bit set below as a chain-continuation step if a
                // later ext follows.
                header: 0x20 | 0x01,
                body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint {
                    value: packed as u64,
                }),
            });
        }
        if let Some(tstamp) = self.request_tstamp {
            // ENC_ZBUF(0x40) | id_tstamp(0x02). No M flag — zenoh-pico
            // emits ext_tstamp as non-mandatory at network.c:132-137
            // (only the Z chain-continuation bit is OR'd in, no
            // _Z_MSG_EXT_FLAG_M). Z bit set below as a chain step if
            // target / budget / timeout follow. The ext value carries
            // a self-describing length prefix (zenoh-pico's
            // `_z_timestamp_encode_ext` at message.c:95-100 emits
            // `_z_zsize_encode(ext_size)` before the Timestamp body;
            // wz's ExtZbuf encode at ext_zbuf.rs auto-emits
            // VLE(value_len) + bytes which matches that wire shape).
            let body_bytes = tstamp.as_borrowed().encode_to_vec();
            request_exts.push(ExtEntryOwned {
                header: 0x40 | 0x02,
                body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                    value_len: body_bytes.len() as u64,
                    value: body_bytes,
                }),
            });
        }
        if let Some(target) = self.request_target {
            request_exts.push(ExtEntryOwned {
                // ENC_ZINT(0x20) | M(0x10) | id_target(0x04). Z bit
                // set below as a chain step if a later ext follows.
                header: 0x20 | 0x10 | 0x04,
                body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint {
                    value: target.wire_byte() as u64,
                }),
            });
        }
        if let Some(budget) = self.request_budget {
            request_exts.push(ExtEntryOwned {
                // ENC_ZINT(0x20) | id_budget(0x05). No M flag —
                // budget is informational per zenoh-pico's encode
                // pattern at network.c:144-149. Position between
                // target and timeout per the same source.
                header: 0x20 | 0x05,
                body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint {
                    value: budget as u64,
                }),
            });
        }
        if let Some(timeout_ms) = self.request_timeout_ms {
            request_exts.push(ExtEntryOwned {
                // ENC_ZINT(0x20) | id_timeout(0x06). M stays clear
                // (timeout is informational).
                header: 0x20 | 0x06,
                body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value: timeout_ms }),
            });
        }

        if !request_exts.is_empty() {
            request.header |= 0x80; // N_Z (Request-level exts present)
                                    // Z chain-continuation: set 0x80 on every entry except
                                    // the last so the decoder loop consumes the whole chain.
            let last_idx = request_exts.len() - 1;
            for (i, ext) in request_exts.iter_mut().enumerate() {
                if i < last_idx {
                    ext.header |= 0x80;
                }
            }
            request.extensions = Some(request_exts);
        }

        request
    }
}
/// R121j-1a — build a `Request(Query)` with an explicit
/// consolidation mode (one of the three "transmitted" zenoh-pico
/// modes). Wire shape extends [`build_request_query`]'s minimal
/// baseline by one byte:
///
/// ```text
///   [Request.header | M_derived]      // same as build_request_query
///   VLE(rid)
///   wireexpr.encode
///   [Query.header = _Z_MID_Z_QUERY (0x03) | _Z_FLAG_Z_Q_C (0x20)]
///   uint8(consolidation.wire_byte())   // <-- the layered addition
/// ```
///
/// The Q_C flag at bit 5 (`_Z_FLAG_Z_Q_C`) is set unconditionally
/// here — by construction the caller chose a non-AUTO mode, so
/// zenoh-pico's `has_consolidation` predicate
/// (`msg->_consolidation != Z_CONSOLIDATION_MODE_DEFAULT`,
/// message.c:402) is true and the encoder emits the flag + the byte.
///
/// `keyexpr_mapping_id` / `keyexpr_suffix` follow the same convention
/// as [`build_request_query`] (literal id=0 / alias / compound). No
/// params, no exts — those are separate layered helpers.
#[cfg(feature = "codec-request")]
pub fn build_request_query_with_consolidation(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    consolidation: ConsolidationMode,
) -> RequestOwned {
    RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix)
        .consolidation(consolidation)
        .build()
}

/// R121j-1b — `parameters` slice max-size enforced by the wz Query
/// codec (sources/codecs/query.scxml's `sce:max-size="256"` on the
/// `parameters` field). Zenoh-pico's `_z_slice_t` is variable-length
/// upstream; wz's stripped-down scope bounds it at 256 to keep the
/// codec deterministic. The builder rejects `params.len() > 256` so
/// the caller surfaces the size violation at the call site rather
/// than as a runtime decoder error on the peer.
pub const REQUEST_QUERY_PARAMETERS_MAX_LEN: usize = 256;

/// R121j-1b — build a `Request(Query)` with an explicit parameters
/// slice (selector + key=value tail string in zenoh-pico, e.g.
/// `"category=temperature"`). Layered on top of [`build_request_query`]:
///
/// ```text
///   [Request.header | M_derived]      // same as build_request_query
///   VLE(rid)
///   wireexpr.encode
///   [Query.header = _Z_MID_Z_QUERY (0x03) | _Z_FLAG_Z_Q_P (0x40)]
///   VLE(params.len())                  // <-- the layered addition
///   params bytes
/// ```
///
/// The Q_P flag at bit 6 (`_Z_FLAG_Z_Q_P` per
/// vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/message.h:103)
/// is set unconditionally here — zenoh-pico's encoder sets it on any
/// non-empty `_parameters` slice (message.c:398-401), and the wz codec
/// gates the `parameters_len` / `parameters` field pair on `header.P`
/// (query.scxml's `sce:present-if="header.P"` on both).
///
/// Empty `params` is rejected (zenoh-pico's `has_params` predicate is
/// `_z_slice_check(&params) && params.len > 0`, so an empty slice
/// would clear Q_P and emit no params — the caller for an empty
/// case should call [`build_request_query`] directly). Slice length
/// above [`REQUEST_QUERY_PARAMETERS_MAX_LEN`] is also rejected to
/// match the wz codec's `sce:max-size="256"` bound.
///
/// `_implicit_anyke` (zenoh-pico's `**` / `?` selector convention
/// that prepends `_Z_QUERY_PARAMS_KEY_ANYKE` to the params at encode
/// time, message.c:414-425) is NOT modelled here — AP MVP simple
/// `z_get` does not set it. A future helper
/// (`build_request_query_with_parameters_and_anyke`) can layer the
/// anyke-prepend on top.
#[cfg(feature = "codec-request")]
pub fn build_request_query_with_parameters(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    params: &[u8],
) -> RequestOwned {
    RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix)
        .parameters(params)
        .build()
}

/// R121j-1c — `attachment` slice max-size enforced by the wz ExtZbuf
/// codec (sources/codecs/ext_zbuf.scxml's `sce:max-size="32"` on
/// the `value` field). zenoh-pico's `_z_msg_ext_t.body._zbuf._val`
/// is variable-length upstream (no codec-level bound); wz's
/// stripped-down scope caps the ZBuf body at 32 bytes across all
/// ExtZbuf-encoded extensions (attachment, value-as-payload,
/// source_info-as-payload). A future round that needs larger
/// attachments either lifts the wz codec bound or adds a separate
/// `ExtZbufLarge` arm; until then the helper rejects oversize at
/// the call site so wz-to-wz interop does not silently fail at the
/// peer decoder. zenoh-pico peers accept arbitrarily large ZBuf
/// payloads, so wz-emit -> zenoh-pico-receive is unaffected.
pub const QUERY_EXT_ZBUF_MAX_LEN: usize = 32;

/// R121j-1c — build a `Request(Query)` with a single attachment
/// extension. Mirrors zenoh-pico's `_z_query_encode` attachment-ext
/// path (message.c:446-448): `_z_uint8_encode(extheader =
/// _Z_MSG_EXT_ENC_ZBUF | 0x05)` then `_z_bytes_encode(&attachment)`.
///
/// Wire shape (single-ext, attachment-only — no source_info, no
/// body/value ext):
///
/// ```text
///   [Request.header | M_derived]      // same as build_request_query
///   VLE(rid)
///   wireexpr.encode
///   [Query.header = _Z_MID_Z_QUERY(0x03) | _Z_FLAG_Z_Z(0x80)]
///   [ExtEntry.header = _Z_MSG_EXT_ENC_ZBUF(0x40) | ext_id(0x05)
///                       | Z(0x00, last entry)]               // = 0x45
///   VLE(attachment.len())
///   attachment bytes
/// ```
///
/// The Q_Z flag (Query-level, 0x80 = `_Z_FLAG_Z_Z` at the network
/// message layer per
/// vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/message.h:35)
/// signals "extension chain follows"; it is distinct from the
/// ext_entry.Z bit (chain-continuation marker, 0x80 on each entry
/// header except the last). With a single attachment ext, Q_Z is
/// set on Query.header and ext_entry.Z stays clear (no successor).
///
/// `ext_id = 0x05` is the attachment slot per zenoh-pico's
/// `_z_query_decode_extensions` switch (message.c:467: `case
/// _Z_MSG_EXT_ENC_ZBUF | 0x05: // Attachment`). The M flag
/// (mandatory, 0x10) stays clear — attachment is informational, the
/// peer may safely ignore it without breaking the query semantics
/// (matches zenoh-pico's encode shape at message.c:447 which emits
/// no M bit).
///
/// `attachment.is_empty()` is rejected: zenoh-pico's
/// `_z_msg_query_required_extensions` (message.c at the
/// `required_exts.attachment = _z_bytes_check(...) ? true : false`
/// site) only sets the attachment requirement when the bytes slice
/// is non-empty, so an empty attachment would silently clear the
/// ext from the wire and emit only the bare Query header (the
/// caller's intent is then plain `build_request_query`).
///
/// `attachment.len() > QUERY_EXT_ZBUF_MAX_LEN` is rejected to match
/// the wz codec's ExtZbuf bound; see the constant's doc-comment.
///
/// Source-info and body(Value) extensions are NOT covered by this
/// helper — separate concerns with their own sub-codec wiring
/// (source_info ext needs zid+eid+sn struct; body Value ext needs
/// the Value codec encoding+payload pair). Future
/// `build_request_query_with_source_info` /
/// `_with_body_value` / `_with_full_exts` helpers layer those.
#[cfg(feature = "codec-request")]
pub fn build_request_query_with_attachment(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    attachment: &[u8],
) -> RequestOwned {
    RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix)
        .query_attachment(attachment)
        .build()
}

/// R121j-1d — build a `Request(Query)` carrying a Request-level
/// timeout extension. Mirrors zenoh-pico's `_z_request_encode`
/// timeout-ext path (vendor/zenoh-pico/src/protocol/codec/network.c:150-155):
/// `_z_uint8_encode(extheader = _Z_MSG_EXT_ENC_ZINT | 0x06)` followed
/// by `_z_zint64_encode(timeout_ms)`.
///
/// Wire shape (single Request-level ext, timeout-only — no qos /
/// tstamp / target / budget):
///
/// ```text
///   [Request.header | _Z_FLAG_Z_Z(0x80) | M_derived | N if suffix]
///   VLE(rid)
///   wireexpr.encode
///   [ExtEntry.header = _Z_MSG_EXT_ENC_ZINT(0x20) | ext_id_timeout(0x06)
///                       | Z(0x00, last entry)]                = 0x26
///   VLE(timeout_ms)                                       // ExtZint body
///   [Query.header = _Z_MID_Z_QUERY(0x03)]                 // inner body
/// ```
///
/// Two distinct Z bits at two layers — clarification:
/// 1. Request.header Z (0x80, `_Z_FLAG_Z_Z` at the network message
///    layer) gates the Request-level tlv-chain (Request.extensions).
///    This is set here.
/// 2. ExtEntry.header Z (0x80, chain-continuation marker on each
///    entry) signals "more entries follow"; for a single timeout ext
///    it stays clear (no successor).
///
/// `ext_id = 0x06` matches `_z_request_decode_extensions` case at
/// network.c:199-202 (`case 0x06 | _Z_MSG_EXT_ENC_ZINT`). M flag
/// (mandatory, 0x10) stays clear — timeout is informational; if the
/// peer ignores it the query simply doesn't time out at the peer's
/// table (matches zenoh-pico's encode at network.c:152 emitting no
/// M bit, unlike the target ext at line 140 which DOES set M).
///
/// `timeout_ms == 0` is rejected to match zenoh-pico's encoder
/// predicate `exts.ext_timeout_ms = msg->_ext_timeout_ms != 0`
/// (network.c at the `_z_n_msg_request_needed_exts` site at
/// vendor/zenoh-pico/src/protocol/definitions/network.c:29). A zero
/// timeout would silently clear the ext from the wire — the caller's
/// intent for "no timeout" is plain [`build_request_query`].
///
/// QoS / target / budget / tstamp Request-level exts are NOT covered
/// by this helper; sub-helpers for each follow the same pattern with
/// the appropriate ext_id and enc shape (qos/budget/timeout use
/// ZINT; tstamp uses ZBUF; target uses ZINT + M=1 since target is
/// mandatory for cross-router queries per network.c:140).
#[cfg(feature = "codec-request")]
pub fn build_request_query_with_timeout_ms(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    timeout_ms: u64,
) -> RequestOwned {
    RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix)
        .request_timeout_ms(timeout_ms)
        .build()
}
/// R121j-1e — build a `Request(Query)` carrying a Request-level
/// query-target extension. Mirrors zenoh-pico's `_z_request_encode`
/// target-ext path (network.c:138-143): `_z_uint8_encode(extheader =
/// _Z_MSG_EXT_ENC_ZINT | 0x04 | _Z_MSG_EXT_FLAG_M)` followed by
/// `_z_zsize_encode(target_enum_value)`.
///
/// Wire shape (single Request-level ext, target-only):
///
/// ```text
///   [Request.header | _Z_FLAG_Z_Z(0x80) | M_derived | N if suffix]
///   VLE(rid)
///   wireexpr.encode
///   [ExtEntry.header = _Z_MSG_EXT_ENC_ZINT(0x20)
///                       | _Z_MSG_EXT_FLAG_M(0x10)
///                       | ext_id_target(0x04)
///                       | Z(0x00, last entry)]               = 0x34
///   VLE(target.wire_byte())                              // ExtZint body
///   [Query.header = _Z_MID_Z_QUERY(0x03)]
/// ```
///
/// `M = 1` on this ext header — target is **mandatory** for
/// cross-router dispatch (zenoh-pico network.c:140 ORs in
/// `_Z_MSG_EXT_FLAG_M` unconditionally for target, distinct from
/// timeout/qos/budget which leave M clear). A peer that does not
/// understand the target ext MUST reject the frame via
/// `_z_msg_ext_unknown_error` (per the ext_entry codec's M-flag
/// contract); routers without target awareness drop the query.
///
/// `ext_id = 0x04` matches `_z_request_decode_extensions` case at
/// network.c:186-191 (`case 0x04 | _Z_MSG_EXT_ENC_ZINT |
/// _Z_MSG_EXT_FLAG_M`).
///
/// `Z_QUERY_TARGET_BEST_MATCHING` (the default) is not part of
/// [`QueryTarget`] because zenoh-pico's encoder predicate clears
/// the ext on that value; the peer infers BEST_MATCHING from
/// ext-absence. Callers wanting BEST_MATCHING use plain
/// [`build_request_query`] and let the peer fall back to default.
#[cfg(feature = "codec-request")]
pub fn build_request_query_with_target(
    rid: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    target: QueryTarget,
) -> RequestOwned {
    RequestQueryBuilder::new(rid, keyexpr_mapping_id, keyexpr_suffix)
        .request_target(target)
        .build()
}

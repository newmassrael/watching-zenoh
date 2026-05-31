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

// R311fs — the byte-stable RequestQueryBuilder / build_request_query
// regression tests, relocated from wz-runtime-tokio::session_glue to
// their SSOT home now that the production code lives here (R311eh).
// The builders are re-exported by session_glue, so the runtime crate
// kept duplicate copies of these tests after the move; this is the
// dedup. TestWire mirrors the session_glue owned->wire projection.
#[cfg(all(test, feature = "codec-request"))]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    // owned -> wire bytes via the borrowed encode view; R311fu moved
    // the trait + its impls to the wz-codecs-tier `wz-codecs-test-support`
    // sibling (SSOT across the request / response / query byte-compare
    // tests). This module already compiles only under `codec-request`,
    // which forwards `wz-codecs-test-support/codec-request`, so the
    // `RequestOwned` impl is in scope.
    use wz_codecs_test_support::TestWire;

    /// R121j-1 — `build_request_query` produces a Request envelope
    /// carrying a `Query` inner body in the minimal AP MVP shape (no
    /// consolidation, no params, no exts at either level). Three
    /// vectors lock the alias / composite / literal trio mirroring
    /// the DECLARE builders, but using `_Z_MID_N_REQUEST (0x1C)` for
    /// the outer header and `_Z_MID_Z_QUERY (0x03)` for the inner
    /// Query header.
    #[cfg(feature = "codec-request")]
    #[test]
    fn build_request_query_wraps_query_in_request_envelope() {
        // Case 1 — pure alias.
        let alias = build_request_query(42, 7, None);
        assert_eq!(
            alias.header, 0x1C,
            "Request header carries MID 0x1C only (no N since no suffix); \
             M is codegen-derived from the Local wireexpr arm at encode",
        );
        assert_eq!(alias.rid, 42, "Request.rid must equal the requested rid");
        match &alias.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7);
                assert!(w.suffix.is_none());
            }
            _ => panic!("Request.keyexpr must use WireexprLocal arm"),
        }
        assert!(
            alias.extensions.is_none(),
            "minimal shape: no Request-level exts"
        );
        match &alias.body {
            RequestOwnedVariant::CodecZenohQuery(q) => {
                assert_eq!(
                    q.header, 0x03,
                    "Query.header is MID 0x03 only — no C / P / Z flags in minimal shape"
                );
                assert!(q.consolidation.is_none());
                assert!(q.parameters_len.is_none());
                assert!(q.parameters.is_none());
                assert!(q.extensions.is_none());
            }
            _ => panic!("Request.body must use CodecZenohQuery arm"),
        }

        // Case 2 — composite (id=7 + tail "tail").
        let composite = build_request_query(42, 7, Some("tail"));
        assert_eq!(
            composite.header, 0x3C,
            "Request header carries MID 0x1C | N(0x20) = 0x3C when suffix present",
        );
        match &composite.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7);
                assert_eq!(w.suffix.as_deref(), Some("tail"));
                assert_eq!(w.suffix_len, Some(4));
            }
            _ => panic!(),
        }

        // Case 3 — literal (id=0 sentinel + suffix carries the keyexpr).
        let literal = build_request_query(42, 0, Some("demo/test"));
        assert_eq!(
            literal.header, 0x3C,
            "literal case still sets N (suffix present)"
        );
        match &literal.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 0, "literal sentinel id=0");
                assert_eq!(w.suffix.as_deref(), Some("demo/test"));
            }
            _ => panic!(),
        }
    }

    /// R121j-1 — Wire-byte regression gate: the bytes emitted by
    /// `build_request_query(...).wire()` must equal zenoh-pico's
    /// `_z_request_encode` + `_z_query_encode` output for the
    /// minimal-shape inputs (no consolidation, no params, no exts at
    /// either level). Three vectors lock the alias / composite /
    /// literal trio:
    ///
    /// References:
    ///   - `_z_request_encode` (vendor/zenoh-pico/src/protocol/codec/network.c:114-169)
    ///     — emits `[header | N | M | Z=0]`, `VLE(rid)`, `wireexpr.encode`,
    ///     and switches into `_z_query_encode` for `_Z_REQUEST_QUERY`.
    ///   - `_z_query_encode` (vendor/zenoh-pico/src/protocol/codec/message.c:394-451)
    ///     — emits `[header | C | P | Z]` then optional consolidation /
    ///     params / exts. In the minimal shape only the header byte
    ///     (0x03) is emitted.
    #[cfg(feature = "codec-request")]
    #[test]
    fn build_request_query_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (rid=42, mapping_id=7, no suffix).
        // Wire shape:
        //   Request.header = MID(0x1C) | M(0x40) = 0x5C
        //   VLE(rid=42)     = 0x2A
        //   wireexpr.id VLE(7) = 0x07
        //   Query.header   = MID(0x03)
        let alias = build_request_query(42, 7, None);
        let alias_wire = alias.wire();
        let alias_expected = vec![
            0x5C, // Request: MID 0x1C | M 0x40
            0x2A, // VLE(rid=42)
            0x07, // wireexpr.id VLE(7)
            0x03, // Query: MID _Z_MID_Z_QUERY only
        ];
        assert_eq!(
            alias_wire, alias_expected,
            "Request(Query) alias-case wire bytes must match zenoh-pico reference"
        );

        // Case 2 — composite (rid=42, id=7 + suffix "abc"):
        //   Request.header = MID | N | M = 0x7C
        //   VLE(42) = 0x2A
        //   wireexpr.id VLE(7) = 0x07
        //   wireexpr.suffix_len VLE(3) = 0x03
        //   wireexpr.suffix bytes = "abc"
        //   Query.header = 0x03
        let composite = build_request_query(42, 7, Some("abc"));
        let composite_wire = composite.wire();
        let mut composite_expected = vec![
            0x7C, // MID | N | M
            0x2A, 0x07, 0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        composite_expected.push(0x03); // Query MID
        assert_eq!(
            composite_wire, composite_expected,
            "Request(Query) composite-case wire bytes must match zenoh-pico reference"
        );

        // Case 3 — literal (rid=42, id=0 + suffix "demo/test"):
        //   Request.header = MID | N | M = 0x7C
        //   VLE(42) = 0x2A
        //   wireexpr.id VLE(0) = 0x00
        //   wireexpr.suffix_len VLE(9) = 0x09
        //   wireexpr.suffix bytes = "demo/test"
        //   Query.header = 0x03
        let literal = build_request_query(42, 0, Some("demo/test"));
        let literal_wire = literal.wire();
        let mut literal_expected = vec![0x7C, 0x2A, 0x00, 0x09];
        literal_expected.extend_from_slice(b"demo/test");
        literal_expected.push(0x03); // Query MID
        assert_eq!(
            literal_wire, literal_expected,
            "Request(Query) literal-case wire bytes must match zenoh-pico reference"
        );
    }

    /// R121j-1a — Wire-byte regression gate for
    /// `build_request_query_with_consolidation`. The layered helper
    /// flips Q_C(0x20) on the Query header and appends a 1-byte
    /// consolidation value after the header byte. Three vectors lock
    /// the three transmitted modes (NONE / MONOTONIC / LATEST); the
    /// AUTO/DEFAULT case stays the responsibility of plain
    /// [`build_request_query`] (no Q_C, no extra byte).
    #[cfg(feature = "codec-request")]
    #[test]
    fn build_request_query_with_consolidation_emits_zenoh_pico_compatible_wire_bytes() {
        // Baseline shape derived from build_request_query alias case
        // (rid=42, mapping_id=7, no suffix): Request prefix bytes are
        // [0x5C, 0x2A, 0x07] (MID|M, VLE(42), VLE(7)). The Query
        // header changes from 0x03 to 0x23 (Q_C set) and the
        // consolidation byte follows.
        let cases: [(ConsolidationMode, u8); 3] = [
            (ConsolidationMode::None, 0x00),
            (ConsolidationMode::Monotonic, 0x01),
            (ConsolidationMode::Latest, 0x02),
        ];
        for (mode, expected_byte) in cases {
            let request = build_request_query_with_consolidation(42, 7, None, mode);
            let wire = request.wire();
            let expected = vec![
                0x5C,          // Request: MID 0x1C | M 0x40
                0x2A,          // VLE(rid=42)
                0x07,          // wireexpr.id VLE(7)
                0x23,          // Query: MID 0x03 | Q_C 0x20
                expected_byte, // consolidation byte
            ];
            assert_eq!(
                wire, expected,
                "Request(Query+consolidation) wire bytes for mode {mode:?} \
                 must match zenoh-pico reference (msg.c:402-413)",
            );
        }

        // Inner-arm sanity: Query.header carries Q_C set + consolidation
        // is Some(wire_byte) — matches the Optional-field shape that
        // the codegen produces from query.scxml's `sce:present-if`.
        let r = build_request_query_with_consolidation(42, 7, None, ConsolidationMode::Monotonic);
        match &r.body {
            RequestOwnedVariant::CodecZenohQuery(q) => {
                assert_eq!(
                    q.header, 0x23,
                    "Query.header must carry MID(0x03) | Q_C(0x20)"
                );
                assert_eq!(q.consolidation, Some(0x01));
                assert!(
                    q.parameters_len.is_none() && q.parameters.is_none() && q.extensions.is_none(),
                    "consolidation-only layered helper must not set \
                     params or exts (those are separate helpers)",
                );
            }
            _ => panic!("expected CodecZenohQuery"),
        }
    }

    /// R121j-1b — Wire-byte regression gate for
    /// `build_request_query_with_parameters`. The layered helper
    /// flips Q_P(0x40) on the Query header and appends VLE(len) +
    /// bytes after the header byte. Three vectors lock the small-
    /// params, multi-byte VLE boundary, and max-size (256) cases.
    /// The Q_C bit (0x20) stays clear because this helper does not
    /// layer consolidation (separate concern).
    #[cfg(feature = "codec-request")]
    #[test]
    fn build_request_query_with_parameters_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — small params (alias case, rid=42, mapping_id=7,
        // no suffix; params="k=v"). Wire:
        //   Request: [0x5C, 0x2A, 0x07]      (MID|M, VLE(42), VLE(7))
        //   Query:   [0x43, 0x03, b'k', b'=', b'v']
        //              (MID(0x03) | Q_P(0x40), VLE(len=3), 3 bytes)
        let small = build_request_query_with_parameters(42, 7, None, b"k=v");
        let small_wire = small.wire();
        let mut small_expected = vec![
            0x5C, // Request: MID 0x1C | M 0x40
            0x2A, // VLE(rid=42)
            0x07, // wireexpr.id VLE(7)
            0x43, // Query: MID(0x03) | Q_P(0x40)
            0x03, // VLE(params_len=3)
        ];
        small_expected.extend_from_slice(b"k=v");
        assert_eq!(
            small_wire, small_expected,
            "Request(Query+params) small-params wire bytes must match \
             zenoh-pico reference (msg.c:398-401, 426-428)",
        );

        // Case 2 — multi-byte VLE boundary on params_len (params
        // length=128 crosses the 7-bit VLE boundary; first byte =
        // 0x80, second byte = 0x01). Lock the VLE writer regression
        // on the parameters_len field specifically.
        let mid_params: Vec<u8> = (0u8..128).collect();
        let mid = build_request_query_with_parameters(42, 7, None, &mid_params);
        let mid_wire = mid.wire();
        let mut mid_expected = vec![
            0x5C, 0x2A, 0x07, 0x43, 0x80, // VLE(128) low 7 + cont bit
            0x01, // VLE(128) high byte
        ];
        mid_expected.extend_from_slice(&mid_params);
        assert_eq!(
            mid_wire, mid_expected,
            "Request(Query+params) multi-byte VLE params_len wire bytes \
             must match zenoh-pico reference",
        );

        // Case 3 — at max-size (256 bytes). VLE(256) = 0x80 0x02.
        let max_params: Vec<u8> = (0..256).map(|i| (i % 251) as u8).collect();
        let max = build_request_query_with_parameters(42, 7, None, &max_params);
        let max_wire = max.wire();
        let mut max_expected = vec![0x5C, 0x2A, 0x07, 0x43, 0x80, 0x02];
        max_expected.extend_from_slice(&max_params);
        assert_eq!(
            max_wire, max_expected,
            "Request(Query+params) max-size params wire bytes must match \
             zenoh-pico reference",
        );

        // Inner-arm sanity check.
        match &small.body {
            RequestOwnedVariant::CodecZenohQuery(q) => {
                assert_eq!(q.header, 0x43, "Query.header MID | Q_P");
                assert_eq!(q.parameters_len, Some(3));
                assert_eq!(q.parameters.as_deref(), Some(b"k=v".as_slice()));
                assert!(
                    q.consolidation.is_none() && q.extensions.is_none(),
                    "parameters-only helper must not set consolidation or exts",
                );
            }
            _ => panic!("expected CodecZenohQuery"),
        }
    }

    #[cfg(feature = "codec-request")]
    #[test]
    #[should_panic(expected = "RequestQueryBuilder::parameters requires a non-empty params slice")]
    fn build_request_query_with_parameters_rejects_empty_slice() {
        let _ = build_request_query_with_parameters(42, 7, None, b"");
    }

    #[cfg(feature = "codec-request")]
    #[test]
    #[should_panic(expected = "exceeds wz Query codec's max-size (256)")]
    fn build_request_query_with_parameters_rejects_over_max_size() {
        let over: Vec<u8> = vec![0u8; REQUEST_QUERY_PARAMETERS_MAX_LEN + 1];
        let _ = build_request_query_with_parameters(42, 7, None, &over);
    }

    /// R121j-1c — Wire-byte regression gate for
    /// `build_request_query_with_attachment`. The layered helper
    /// flips Q_Z(0x80) on the Query header and appends a single
    /// ext_entry with header 0x45 (ENC_ZBUF | ext_id=0x05) and an
    /// ExtZbuf body carrying VLE(len) + bytes. Three vectors lock
    /// the small-attachment, multi-byte VLE boundary (won't hit at
    /// max-size 32, but small-vs-byte-256 differs in single-byte
    /// VLE only here), and at-max (32-byte) cases. The Q_C / Q_P
    /// bits stay clear because this helper is attachment-only.
    #[cfg(feature = "codec-request")]
    #[test]
    fn build_request_query_with_attachment_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — small attachment (alias case, rid=42, mapping_id=7,
        // no suffix; attachment = b"hi").
        //   Request: [0x5C, 0x2A, 0x07]      (MID|M, VLE(42), VLE(7))
        //   Query:   [0x83]                  (MID(0x03) | Q_Z(0x80))
        //   ExtEntry header: [0x45]          (ENC_ZBUF(0x40) | id(0x05))
        //   ExtZbuf: [0x02, b'h', b'i']      (VLE(2), bytes)
        let small = build_request_query_with_attachment(42, 7, None, b"hi");
        let small_wire = small.wire();
        let mut small_expected = vec![
            0x5C, // Request: MID 0x1C | M 0x40
            0x2A, // VLE(rid=42)
            0x07, // wireexpr.id VLE(7)
            0x83, // Query: MID(0x03) | Q_Z(0x80)
            0x45, // ExtEntry: ENC_ZBUF | id_attachment
            0x02, // ExtZbuf.value_len VLE(2)
        ];
        small_expected.extend_from_slice(b"hi");
        assert_eq!(
            small_wire, small_expected,
            "Request(Query+attachment) small-attachment wire bytes must \
             match zenoh-pico reference (msg.c:446-448)",
        );

        // Case 2 — at-max attachment (32 bytes, all-distinct sequence
        // 0..32). VLE(32) = 0x20 (single byte, fits in 7 bits).
        let max_attach: Vec<u8> = (0u8..32).collect();
        let max = build_request_query_with_attachment(42, 7, None, &max_attach);
        let max_wire = max.wire();
        let mut max_expected = vec![
            0x5C, 0x2A, 0x07, 0x83, // Query header with Q_Z
            0x45, // ExtEntry header
            0x20, // VLE(32) single byte
        ];
        max_expected.extend_from_slice(&max_attach);
        assert_eq!(
            max_wire, max_expected,
            "Request(Query+attachment) max-size (32-byte) attachment wire \
             bytes must match zenoh-pico reference",
        );

        // Inner-arm sanity: Query.header carries Q_Z; extensions vec
        // has exactly one entry with the expected ext_id + ZBuf body.
        match &small.body {
            RequestOwnedVariant::CodecZenohQuery(q) => {
                assert_eq!(q.header, 0x83, "Query.header MID(0x03) | Q_Z(0x80)");
                let exts = q
                    .extensions
                    .as_ref()
                    .expect("Q_Z set → extensions vec must be Some");
                assert_eq!(exts.len(), 1, "single attachment ext only");
                assert_eq!(
                    exts[0].header, 0x45,
                    "ExtEntry.header = ENC_ZBUF(0x40) | id_attachment(0x05)"
                );
                match &exts[0].body {
                    ExtEntryOwnedVariant::CodecZenohExtZbuf(zb) => {
                        assert_eq!(zb.value_len, 2);
                        assert_eq!(zb.value.as_slice(), b"hi".as_slice());
                    }
                    _ => panic!("attachment ext body must be CodecZenohExtZbuf"),
                }
                assert!(
                    q.consolidation.is_none() && q.parameters.is_none(),
                    "attachment-only helper must not set consolidation or params",
                );
            }
            _ => panic!("expected CodecZenohQuery"),
        }
    }

    #[cfg(feature = "codec-request")]
    #[test]
    #[should_panic(
        expected = "RequestQueryBuilder::query_attachment requires a non-empty attachment slice"
    )]
    fn build_request_query_with_attachment_rejects_empty_slice() {
        let _ = build_request_query_with_attachment(42, 7, None, b"");
    }

    #[cfg(feature = "codec-request")]
    #[test]
    #[should_panic(expected = "exceeds wz ExtZbuf codec's max-size (32)")]
    fn build_request_query_with_attachment_rejects_over_max_size() {
        let over: Vec<u8> = vec![0u8; QUERY_EXT_ZBUF_MAX_LEN + 1];
        let _ = build_request_query_with_attachment(42, 7, None, &over);
    }

    /// R121j-1d — Wire-byte regression gate for
    /// `build_request_query_with_timeout_ms`. The Request-level Z bit
    /// (0x80) on the outer header signals the Request.extensions
    /// chain follows the wireexpr; the ExtEntry header (0x26 =
    /// ENC_ZINT | id_timeout) precedes the Query body. Three vectors
    /// lock single-byte VLE timeout (50ms), multi-byte VLE boundary
    /// (1000ms = 0xE8 0x07), and large VLE (2^32 ms = 5-byte VLE).
    /// The Query body's MID byte (0x03) stays at the tail, after the
    /// Request-level exts — mirrors the zenoh-pico encoder order
    /// (network.c:122-167: header / rid / wireexpr / exts loop /
    /// body switch).
    #[cfg(feature = "codec-request")]
    #[test]
    fn build_request_query_with_timeout_ms_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — single-byte VLE timeout (50ms fits in 7 bits).
        // Alias case rid=42, mapping_id=7, no suffix.
        //   Request.header = MID(0x1C) | M(0x40) | N_Z(0x80) = 0xDC
        //   VLE(rid=42) = 0x2A
        //   wireexpr.id VLE(7) = 0x07
        //   ExtEntry.header = ENC_ZINT(0x20) | id_timeout(0x06) = 0x26
        //   ExtZint.value VLE(50) = 0x32
        //   Query.header = 0x03
        let small = build_request_query_with_timeout_ms(42, 7, None, 50);
        let small_wire = small.wire();
        assert_eq!(
            small_wire,
            vec![
                0xDC, // Request: MID | M | N_Z
                0x2A, // VLE(rid=42)
                0x07, // wireexpr.id VLE(7)
                0x26, // ExtEntry: ENC_ZINT | id_timeout
                0x32, // ExtZint VLE(50)
                0x03, // Query.header (minimal)
            ],
            "Request(timeout=50ms,Query) wire bytes must match \
             zenoh-pico reference (network.c:122-167)",
        );

        // Case 2 — multi-byte VLE boundary (1000ms = 0xE8 0x07).
        let mid = build_request_query_with_timeout_ms(42, 7, None, 1000);
        let mid_wire = mid.wire();
        assert_eq!(
            mid_wire,
            vec![
                0xDC, 0x2A, 0x07, 0x26, 0xE8, // VLE(1000) low 7 + cont
                0x07, // VLE(1000) high
                0x03,
            ],
            "Request(timeout=1000ms,Query) wire bytes must match \
             zenoh-pico reference",
        );

        // Case 3 — large VLE (2^32 = 0x1_0000_0000 = 5-byte VLE in
        // base-128: 0x80 0x80 0x80 0x80 0x10).
        let large = build_request_query_with_timeout_ms(42, 7, None, 1u64 << 32);
        let large_wire = large.wire();
        assert_eq!(
            large_wire,
            vec![
                0xDC, 0x2A, 0x07, 0x26, 0x80, 0x80, 0x80, 0x80, 0x10, // VLE(2^32)
                0x03,
            ],
            "Request(timeout=2^32 ms,Query) wire bytes must match \
             zenoh-pico reference",
        );

        // Inner-arm sanity: Request.extensions has 1 entry with ZInt
        // body; Query body is minimal-shape (no Q_C / Q_P / Q_Z).
        match &small.body {
            RequestOwnedVariant::CodecZenohQuery(q) => {
                assert_eq!(q.header, 0x03, "Query.header minimal (no Q flags)");
                assert!(q.consolidation.is_none());
                assert!(q.parameters.is_none());
                assert!(q.extensions.is_none(), "no Q-level exts");
            }
            _ => panic!("expected CodecZenohQuery"),
        }
        let req_exts = small
            .extensions
            .as_ref()
            .expect("N_Z set → Request.extensions must be Some");
        assert_eq!(req_exts.len(), 1, "single Request-level ext");
        assert_eq!(
            req_exts[0].header, 0x26,
            "Request ExtEntry.header = ENC_ZINT(0x20) | id_timeout(0x06)"
        );
        match &req_exts[0].body {
            ExtEntryOwnedVariant::CodecZenohExtZint(zi) => {
                assert_eq!(zi.value, 50);
            }
            _ => panic!("timeout ext body must be CodecZenohExtZint"),
        }
    }

    #[cfg(feature = "codec-request")]
    #[test]
    #[should_panic(
        expected = "RequestQueryBuilder::request_timeout_ms requires a non-zero timeout"
    )]
    fn build_request_query_with_timeout_ms_rejects_zero() {
        let _ = build_request_query_with_timeout_ms(42, 7, None, 0);
    }

    /// R121j-1e — Wire-byte regression gate for
    /// `build_request_query_with_target`. The target ext sets M=1
    /// (mandatory marker) on the ExtEntry.header, distinct from
    /// timeout / qos / budget which leave M clear. Two vectors lock
    /// the two transmitted target values (All=1 / AllComplete=2);
    /// BEST_MATCHING (0) is not representable in [`QueryTarget`] —
    /// the encoder predicate clears the ext on default, so absence
    /// of this helper's wire bytes is the BEST_MATCHING signal.
    #[cfg(feature = "codec-request")]
    #[test]
    fn build_request_query_with_target_emits_zenoh_pico_compatible_wire_bytes() {
        // Alias case rid=42, mapping_id=7, no suffix. For both target
        // values the wire shape differs only in the ExtZint body
        // (1 byte) since target ∈ {1, 2} both fit in single-byte VLE.
        //   Request.header = MID(0x1C) | M(0x40) | N_Z(0x80) = 0xDC
        //   ExtEntry.header = ENC_ZINT(0x20) | M(0x10) | id_target(0x04) = 0x34
        let cases: [(QueryTarget, u8); 2] =
            [(QueryTarget::All, 0x01), (QueryTarget::AllComplete, 0x02)];
        for (target, target_byte) in cases {
            let request = build_request_query_with_target(42, 7, None, target);
            let wire = request.wire();
            assert_eq!(
                wire,
                vec![
                    0xDC,        // Request: MID | M | N_Z
                    0x2A,        // VLE(rid=42)
                    0x07,        // wireexpr.id VLE(7)
                    0x34,        // ExtEntry: ENC_ZINT | M | id_target
                    target_byte, // VLE(target_enum_value)
                    0x03,        // Query.header (minimal)
                ],
                "Request(target={target:?},Query) wire bytes must match \
                 zenoh-pico reference (network.c:138-143)",
            );
        }

        // Inner-arm sanity check on the All case.
        let r = build_request_query_with_target(42, 7, None, QueryTarget::All);
        let req_exts = r
            .extensions
            .as_ref()
            .expect("N_Z set → Request.extensions must be Some");
        assert_eq!(req_exts.len(), 1);
        assert_eq!(
            req_exts[0].header, 0x34,
            "Request ExtEntry.header = ENC_ZINT(0x20) | M(0x10) | id_target(0x04)"
        );
        assert!(
            (req_exts[0].header & 0x10) != 0,
            "target ext MUST set the mandatory marker bit (M=1, 0x10) — peers \
             without target awareness reject the frame on unknown M-bit exts"
        );
        match &req_exts[0].body {
            ExtEntryOwnedVariant::CodecZenohExtZint(zi) => {
                assert_eq!(zi.value, 1);
            }
            _ => panic!("target ext body must be CodecZenohExtZint"),
        }
    }

    /// R121j-2a — Composition smoke test: two Query-layer settings
    /// (consolidation + parameters) applied via the builder produce
    /// wire bytes consistent with both layers. The two-layer shape
    /// is what the old one-shot helpers CANNOT produce because each
    /// resets the Query body's optional fields.
    #[cfg(feature = "codec-request")]
    #[test]
    fn request_query_builder_composes_consolidation_and_parameters() {
        // rid=42, mapping_id=7, no suffix.
        // Layers: consolidation=Monotonic, params=b"k=v".
        //   Request.header = MID(0x1C) | M(0x40) = 0x5C  (no N, no N_Z)
        //   VLE(rid=42) = 0x2A
        //   wireexpr Local: id=7 → 0x07
        //   Query.header = MID(0x03) | Q_C(0x20) | Q_P(0x40) = 0x63
        //   consolidation byte = 0x01 (Monotonic)
        //   parameters_len VLE = 0x03
        //   "k=v" 3 bytes
        let request = RequestQueryBuilder::new(42, 7, None)
            .consolidation(ConsolidationMode::Monotonic)
            .parameters(b"k=v")
            .build();
        let wire = request.wire();
        let mut expected = vec![
            0x5C, // Request: MID | M
            0x2A, // VLE(rid=42)
            0x07, // wireexpr.id VLE(7)
            0x63, // Query: MID | Q_C | Q_P
            0x01, // consolidation = Monotonic
            0x03, // parameters_len VLE(3)
        ];
        expected.extend_from_slice(b"k=v");
        assert_eq!(
            wire, expected,
            "Composed (consolidation + parameters) wire must carry both \
             layers — the regression that pre-R121j-2a one-shot \
             helpers couldn't express",
        );
    }

    /// R121j-2a — Composition full-stack: all 5 currently-exposed
    /// builder layers applied together. Verifies (1) Request-level
    /// ext ordering (target first, then timeout per zenoh-pico
    /// network.c:122-167), (2) Z chain-continuation bit on the
    /// intermediate target ext, (3) all three Query-layer flag bits
    /// (Q_C / Q_P / Q_Z) set together, (4) the attachment ext sits at
    /// the Query level (after Query.consolidation + parameters), not
    /// at the Request level.
    #[cfg(feature = "codec-request")]
    #[test]
    fn request_query_builder_composes_all_five_layers() {
        // rid=42, mapping_id=7, no suffix.
        // Layers: consolidation=Latest, params=b"k=v", q_attachment=b"at",
        //         req_target=All, req_timeout_ms=1000.
        //   Request.header = MID(0x1C) | M(0x40) | N_Z(0x80) = 0xDC
        //   VLE(rid=42) = 0x2A
        //   wireexpr Local: id=7 → 0x07
        //   Request ext 1: target (ENC_ZINT|M|id_target=0x34) | Z(0x80) = 0xB4
        //   ExtZint VLE(All=1) = 0x01
        //   Request ext 2: timeout (ENC_ZINT|id_timeout=0x26), no Z = 0x26
        //   ExtZint VLE(1000) = 0xE8 0x07
        //   Query.header = MID(0x03) | Q_C(0x20) | Q_P(0x40) | Q_Z(0x80) = 0xE3
        //   consolidation = Latest = 0x02
        //   parameters_len VLE(3) = 0x03
        //   "k=v"
        //   Q-attachment ext: header (ENC_ZBUF|id_attachment=0x45), no Z = 0x45
        //   ExtZbuf VLE(2) = 0x02
        //   "at"
        let request = RequestQueryBuilder::new(42, 7, None)
            .consolidation(ConsolidationMode::Latest)
            .parameters(b"k=v")
            .query_attachment(b"at")
            .request_target(QueryTarget::All)
            .request_timeout_ms(1000)
            .build();
        let wire = request.wire();
        let mut expected = vec![
            0xDC, // Request: MID | M | N_Z
            0x2A, // VLE(rid=42)
            0x07, // wireexpr.id VLE(7)
            // Request-level ext chain: target(Z=1) → timeout(last)
            0xB4, // ENC_ZINT | M | id_target | Z(chain)
            0x01, // VLE(target=All=1)
            0x26, // ENC_ZINT | id_timeout, Z=0 (last)
            0xE8, 0x07, // VLE(timeout_ms=1000)
            // Query body
            0xE3, // Query: MID | Q_C | Q_P | Q_Z
            0x02, // consolidation = Latest
            0x03, // parameters_len VLE(3)
        ];
        expected.extend_from_slice(b"k=v");
        expected.extend_from_slice(&[
            0x45, // Q-attachment ext: ENC_ZBUF | id_attachment, Z=0
            0x02, // VLE(attachment_len=2)
        ]);
        expected.extend_from_slice(b"at");
        assert_eq!(
            wire, expected,
            "Five-layer composed wire must carry all settings — \
             verifies Request-level ext ordering + Z chain bit on \
             intermediate entry + all three Q-flag bits + Q-attachment \
             positioning",
        );

        // Inner-arm sanity.
        let req_exts = request
            .extensions
            .as_ref()
            .expect("N_Z set → Request.extensions must be Some");
        assert_eq!(req_exts.len(), 2, "target + timeout exts");
        assert_eq!(
            req_exts[0].header & 0x80,
            0x80,
            "target ext must carry Z chain-continuation bit (more follows)",
        );
        assert_eq!(
            req_exts[1].header & 0x80,
            0x00,
            "timeout ext must NOT carry Z (it is the last entry)",
        );
    }

    /// R121j-1f — RequestQueryBuilder.request_qos emits a single
    /// Request-level ext at the head of the chain (qos → tstamp →
    /// target → budget → timeout) with header ENC_ZINT(0x20) |
    /// id_qos(0x01) and no M flag (qos is informational).
    #[cfg(feature = "codec-request")]
    #[test]
    fn request_query_builder_request_qos_emits_first_ext_with_no_m_flag() {
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos(0x05) // priority=5, no nodrop, no express
            .build();
        let req_exts = request
            .extensions
            .as_ref()
            .expect("N_Z set → Request.extensions must be Some");
        assert_eq!(req_exts.len(), 1, "only qos ext was set");
        assert_eq!(
            req_exts[0].header,
            0x20 | 0x01,
            "qos ext header = ENC_ZINT(0x20) | id_qos(0x01); no M, no Z (last)",
        );
        match &req_exts[0].body {
            ExtEntryOwnedVariant::CodecZenohExtZint(zint) => {
                assert_eq!(
                    zint.value, 0x05,
                    "qos packed byte 0x05 lifts into ZINT VLE value verbatim"
                );
            }
            _ => panic!("qos ext body must be CodecZenohExtZint"),
        }
        assert_eq!(
            request.header & 0x80,
            0x80,
            "qos setter must flip N_Z(0x80) on Request.header (exts present)",
        );
    }

    /// R121j-1f — request_qos composes with request_target +
    /// request_timeout_ms in the correct zenoh-pico encode order:
    /// qos comes first (with Z-chain continuation), target next
    /// (with Z-chain continuation), timeout last (no Z).
    #[cfg(feature = "codec-request")]
    #[test]
    fn request_query_builder_request_qos_target_timeout_chain_order_matches_zenoh_pico() {
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos(0x05)
            .request_target(QueryTarget::All)
            .request_timeout_ms(1000)
            .build();
        let req_exts = request
            .extensions
            .as_ref()
            .expect("3 Request-level exts set → extensions must be Some");
        assert_eq!(req_exts.len(), 3, "qos + target + timeout");
        // qos first: ENC_ZINT | id_qos(1), Z continuation set
        assert_eq!(
            req_exts[0].header,
            0x80 | 0x20 | 0x01,
            "qos ext at index 0 must carry Z continuation (more follows)"
        );
        // target second: ENC_ZINT | M | id_target(4), Z continuation set
        assert_eq!(
            req_exts[1].header,
            0x80 | 0x20 | 0x10 | 0x04,
            "target ext at index 1 must carry M(0x10) + Z continuation"
        );
        // timeout last: ENC_ZINT | id_timeout(6), no Z
        assert_eq!(
            req_exts[2].header,
            0x20 | 0x06,
            "timeout ext at index 2 (last) must NOT carry Z"
        );
    }

    /// R121j-1g — RequestQueryBuilder.request_budget emits a single
    /// Request-level ext between target and timeout (per zenoh-pico
    /// _z_request_encode order) with header ENC_ZINT(0x20) |
    /// id_budget(0x05) and no M flag.
    #[cfg(feature = "codec-request")]
    #[test]
    fn request_query_builder_request_budget_emits_ext_between_target_and_timeout() {
        // Solo case: only budget set. Ext at index 0 (chain head), no
        // Z (it is the only ext, hence the last).
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_budget(0x1234_5678)
            .build();
        let req_exts = request
            .extensions
            .as_ref()
            .expect("budget setter must populate exts");
        assert_eq!(req_exts.len(), 1, "only budget ext was set");
        assert_eq!(
            req_exts[0].header,
            0x20 | 0x05,
            "budget ext header = ENC_ZINT(0x20) | id_budget(0x05); no M, no Z (last)",
        );
        match &req_exts[0].body {
            ExtEntryOwnedVariant::CodecZenohExtZint(zint) => {
                assert_eq!(
                    zint.value, 0x1234_5678,
                    "budget u32 widens into u64 ZINT value verbatim"
                );
            }
            _ => panic!("budget ext body must be CodecZenohExtZint"),
        }

        // Chain-order case: qos + target + budget + timeout. Position
        // must be qos[0]->target[1]->budget[2]->timeout[3] per
        // zenoh-pico _z_request_encode at network.c:126-155. Z
        // continuation set on indices 0/1/2, clear on index 3.
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos(0x05)
            .request_target(QueryTarget::All)
            .request_budget(100)
            .request_timeout_ms(1000)
            .build();
        let req_exts = request.extensions.as_ref().expect("4 exts set");
        assert_eq!(req_exts.len(), 4, "qos + target + budget + timeout");
        assert_eq!(req_exts[0].header & 0x07, 0x01, "index 0: qos id");
        assert_eq!(req_exts[1].header & 0x07, 0x04, "index 1: target id");
        assert_eq!(
            req_exts[2].header & 0x07,
            0x05,
            "index 2: budget id (between target and timeout)"
        );
        assert_eq!(
            req_exts[3].header & 0x07,
            0x06,
            "index 3: timeout id (last)"
        );
        assert_eq!(
            req_exts[3].header & 0x80,
            0x00,
            "timeout last → Z must be clear"
        );
        assert_eq!(
            req_exts[2].header & 0x80,
            0x80,
            "budget at index 2 → Z must be set (timeout follows)"
        );
    }

    /// R121j-1g — request_budget rejects zero (mirrors zenoh-pico's
    /// ext_budget = budget != 0 encoder predicate at
    /// vendor/zenoh-pico/src/protocol/definitions/network.c:26).
    #[cfg(feature = "codec-request")]
    #[test]
    #[should_panic(expected = "RequestQueryBuilder::request_budget requires a non-zero budget")]
    fn request_query_builder_budget_rejects_zero() {
        let _ = RequestQueryBuilder::new(42, 7, None)
            .request_budget(0)
            .build();
    }

    /// R121j-tstamp — request_tstamp emits one Request-level ext at
    /// the position between qos and target (qos → tstamp → target →
    /// budget → timeout) with header ENC_ZBUF(0x40) | id_tstamp(0x02)
    /// and NO M flag. The ext body is an ExtZbuf carrying the
    /// `Timestamp::encode_to_vec()` output verbatim.
    #[cfg(feature = "codec-request")]
    #[test]
    fn request_query_builder_request_tstamp_solo_emits_ext_with_no_m_flag() {
        // Solo case: only tstamp set. time=42, zid=[0xab, 0xcd] keeps
        // both VLE fields single-byte so the body bytes are auditable
        // without an online VLE encoder: [VLE(42), VLE(2), 0xab, 0xcd]
        // = [0x2a, 0x02, 0xab, 0xcd], len=4.
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_tstamp(42, &[0xab, 0xcd])
            .build();
        let req_exts = request
            .extensions
            .as_ref()
            .expect("N_Z set → Request.extensions must be Some");
        assert_eq!(req_exts.len(), 1, "only tstamp ext was set");
        assert_eq!(
            req_exts[0].header,
            0x40 | 0x02,
            "tstamp ext header = ENC_ZBUF(0x40) | id_tstamp(0x02); no M, no Z (last)",
        );
        match &req_exts[0].body {
            ExtEntryOwnedVariant::CodecZenohExtZbuf(zbuf) => {
                assert_eq!(
                    zbuf.value_len, 4,
                    "Timestamp encode = VLE(42)+VLE(2)+zid[2] = 4 bytes"
                );
                assert_eq!(
                    zbuf.value,
                    vec![0x2a, 0x02, 0xab, 0xcd],
                    "Timestamp body: VLE(time=42)=0x2a, VLE(zid_len=2)=0x02, zid=[0xab,0xcd]",
                );
            }
            _ => panic!("tstamp ext body must be CodecZenohExtZbuf"),
        }
        assert_eq!(
            request.header & 0x80,
            0x80,
            "tstamp setter must flip N_Z(0x80) on Request.header (exts present)",
        );
    }

    /// R121j-tstamp — chain position vs zenoh-pico encode order:
    /// qos[0] → tstamp[1] → target[2] → budget[3] → timeout[4], with
    /// Z chain-continuation on indices 0..=3 and Z clear on index 4.
    /// The five-ext sequence pins the entire Request-level ext chain
    /// against `_z_request_encode` at network.c:126-155.
    #[cfg(feature = "codec-request")]
    #[test]
    fn request_query_builder_full_chain_emits_zenoh_pico_encode_order() {
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos(0x05)
            .request_tstamp(7, &[0x01])
            .request_target(QueryTarget::All)
            .request_budget(100)
            .request_timeout_ms(1000)
            .build();
        let req_exts = request.extensions.as_ref().expect("5 exts set");
        assert_eq!(
            req_exts.len(),
            5,
            "qos + tstamp + target + budget + timeout"
        );
        assert_eq!(req_exts[0].header & 0x07, 0x01, "index 0: qos id");
        assert_eq!(req_exts[1].header & 0x07, 0x02, "index 1: tstamp id");
        assert_eq!(req_exts[2].header & 0x07, 0x04, "index 2: target id");
        assert_eq!(req_exts[3].header & 0x07, 0x05, "index 3: budget id");
        assert_eq!(req_exts[4].header & 0x07, 0x06, "index 4: timeout id");
        // Encoding kind bits (bits 5-6: 0x20 = ZINT, 0x40 = ZBUF).
        assert_eq!(req_exts[0].header & 0x60, 0x20, "qos uses ENC_ZINT");
        assert_eq!(req_exts[1].header & 0x60, 0x40, "tstamp uses ENC_ZBUF");
        assert_eq!(req_exts[2].header & 0x60, 0x20, "target uses ENC_ZINT");
        assert_eq!(req_exts[3].header & 0x60, 0x20, "budget uses ENC_ZINT");
        assert_eq!(req_exts[4].header & 0x60, 0x20, "timeout uses ENC_ZINT");
        // M flag (bit 4): set on target only (M=1 per zenoh-pico),
        // clear on qos / tstamp / budget / timeout.
        assert_eq!(req_exts[0].header & 0x10, 0x00, "qos: M clear");
        assert_eq!(
            req_exts[1].header & 0x10,
            0x00,
            "tstamp: M clear (non-mandatory per zenoh-pico)"
        );
        assert_eq!(req_exts[2].header & 0x10, 0x10, "target: M set");
        assert_eq!(req_exts[3].header & 0x10, 0x00, "budget: M clear");
        assert_eq!(req_exts[4].header & 0x10, 0x00, "timeout: M clear");
        // Z chain-continuation: set on 0..=3, clear on 4.
        assert_eq!(req_exts[0].header & 0x80, 0x80, "qos: Z set (more follows)");
        assert_eq!(req_exts[1].header & 0x80, 0x80, "tstamp: Z set");
        assert_eq!(req_exts[2].header & 0x80, 0x80, "target: Z set");
        assert_eq!(req_exts[3].header & 0x80, 0x80, "budget: Z set");
        assert_eq!(req_exts[4].header & 0x80, 0x00, "timeout: Z clear (last)");
    }

    /// R121j-tstamp — request_tstamp rejects an empty zid (mirrors
    /// zenoh-pico's `_z_id_encode_as_slice` at message.c:58-70 which
    /// returns `_Z_ERR_MESSAGE_ZENOH_UNKNOWN` on len=0).
    #[cfg(feature = "codec-request")]
    #[test]
    #[should_panic(expected = "RequestQueryBuilder::request_tstamp requires a non-empty zid")]
    fn request_query_builder_tstamp_rejects_empty_zid() {
        let _ = RequestQueryBuilder::new(42, 7, None)
            .request_tstamp(0, &[])
            .build();
    }

    /// R121j-tstamp — request_tstamp rejects zid longer than the
    /// zenoh `_z_id_t` 16-byte capacity (`_Z_ID_LENGTH = 16` at
    /// vendor/zenoh-pico/include/zenoh-pico/protocol/core.h).
    #[cfg(feature = "codec-request")]
    #[test]
    #[should_panic(expected = "exceeds zenoh _Z_ID_LENGTH (16)")]
    fn request_query_builder_tstamp_rejects_zid_over_16_bytes() {
        let _ = RequestQueryBuilder::new(42, 7, None)
            .request_tstamp(0, &[0u8; 17])
            .build();
    }

    /// R121j-1h — request_qos_typed packs `(Priority, CongestionControl,
    /// express)` into the wire byte exactly as zenoh-pico's
    /// `_z_n_qos_create` at network.h:84-89 produces:
    /// `(express << 4) | (nodrop << 3) | priority`. Verifies the byte
    /// then delegates to the same storage as request_qos so the chain
    /// emit path stays uniform — same Z chain-continuation / index
    /// semantics as the raw setter.
    #[cfg(feature = "codec-request")]
    #[test]
    fn request_qos_typed_packs_per_zenoh_pico_z_n_qos_create_layout() {
        // Drop + Background priority + no express: priority=7 → low 3
        // bits = 0b111; congestion Drop → nodrop=0; express=false →
        // bit4=0. Expected packed byte = 0x07.
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos_typed(Priority::Background, CongestionControl::Drop, false)
            .build();
        let req_exts = request.extensions.as_ref().expect("qos ext present");
        match &req_exts[0].body {
            ExtEntryOwnedVariant::CodecZenohExtZint(zint) => {
                assert_eq!(zint.value, 0x07, "Background(7) + Drop + !express = 0x07");
            }
            _ => panic!("qos body must be ExtZint"),
        }

        // Block + RealTime + express: priority=1 (bits 0-2 = 0b001),
        // nodrop=1 (bit 3 = 0b1000), express=1 (bit 4 = 0b10000).
        // Expected packed byte = 0x10 | 0x08 | 0x01 = 0x19.
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos_typed(Priority::RealTime, CongestionControl::Block, true)
            .build();
        let req_exts = request.extensions.as_ref().expect("qos ext present");
        match &req_exts[0].body {
            ExtEntryOwnedVariant::CodecZenohExtZint(zint) => {
                assert_eq!(
                    zint.value, 0x19,
                    "RealTime(1) + Block + express = 0x10|0x08|0x01"
                );
            }
            _ => panic!("qos body must be ExtZint"),
        }

        // Default (Data priority, Drop, !express): priority=5
        // (0b101), nodrop=0, express=0 → 0x05. Sanity check that the
        // default-aligned values produce a clean low-bits byte.
        let request = RequestQueryBuilder::new(42, 7, None)
            .request_qos_typed(Priority::Data, CongestionControl::Drop, false)
            .build();
        let req_exts = request.extensions.as_ref().expect("qos ext present");
        match &req_exts[0].body {
            ExtEntryOwnedVariant::CodecZenohExtZint(zint) => {
                assert_eq!(zint.value, 0x05, "Data(5) + Drop + !express = 0x05");
            }
            _ => panic!("qos body must be ExtZint"),
        }
    }

    // R311ec — the pure Priority::wire_byte / CongestionControl::wire_bit
    // test moved to wz-session-core::qos alongside the migrated types
    // (the session-core base test run covers it). The
    // RequestQueryBuilder qos-composition tests stay here — they
    // exercise the builder, not the enums, and use the re-exported types.

    /// R121j-1h — request_qos_typed composes with request_target +
    /// request_timeout_ms identically to the raw request_qos setter
    /// (Z chain-continuation bits, ext order). Pins that the typed
    /// wrapper is purely a packing convenience over the raw setter.
    #[cfg(feature = "codec-request")]
    #[test]
    fn request_qos_typed_composes_with_chain_identically_to_raw_qos() {
        let typed = RequestQueryBuilder::new(42, 7, None)
            .request_qos_typed(Priority::RealTime, CongestionControl::Block, true)
            .request_target(QueryTarget::All)
            .request_timeout_ms(1000)
            .build();
        let raw = RequestQueryBuilder::new(42, 7, None)
            .request_qos(0x19) // same packed byte as the typed call
            .request_target(QueryTarget::All)
            .request_timeout_ms(1000)
            .build();
        assert_eq!(
            typed.wire(),
            raw.wire(),
            "typed and raw qos setters must produce byte-identical wire emit",
        );
    }

    /// R121j-2a — Per-setter validation flows through to the builder.
    /// Mirrors the one-shot helper rejection tests; the builder is
    /// where the panic actually fires now.
    #[cfg(feature = "codec-request")]
    #[test]
    #[should_panic(expected = "RequestQueryBuilder::parameters")]
    fn request_query_builder_parameters_rejects_empty() {
        let _ = RequestQueryBuilder::new(42, 7, None)
            .parameters(b"")
            .build();
    }

    #[cfg(feature = "codec-request")]
    #[test]
    #[should_panic(expected = "RequestQueryBuilder::request_timeout_ms")]
    fn request_query_builder_timeout_rejects_zero() {
        let _ = RequestQueryBuilder::new(42, 7, None)
            .request_timeout_ms(0)
            .build();
    }
}

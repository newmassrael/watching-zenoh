// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Application-layer reply registry — routes decoded
//! `NetworkMessage::Response(Reply|Err)` and
//! `NetworkMessage::ResponseFinal` records to per-rid callbacks
//! registered by `z_get`-side callers.
//!
//! Z_get-side mirror of the [`QueryableRegistry`](crate::query::QueryableRegistry)
//! on the responder side. The producer/consumer split:
//!
//! | Side    | Outbound                    | Inbound dispatch         |
//! |---------|-----------------------------|--------------------------|
//! | z_get   | `Request(Query)`            | [`ReplyRegistry`]        |
//! | qable   | `Response(Reply\|Err)` + Final | [`QueryableRegistry`] |
//!
//! Both registries follow the same scoping rule (literal keyexpr
//! match in zenoh-pico's "many Reply + exactly one Final per Query"
//! semantics) and reuse the shared peer-alias resolution against the
//! [`SubscriberRegistry`](crate::pubsub::SubscriberRegistry)'s
//! `peer_keyexpr_table` so a `DeclKexpr` absorbed by the subscriber
//! path informs reply-keyexpr resolution too — no dual-write
//! bookkeeping, no Arc-shared state.
//!
//! ## Scope (R121j-6)
//!
//! - `register(rid, on_reply, on_final)` records a pending z_get.
//!   The `on_reply` callback fires once per inbound
//!   `Response(Reply|Err)` whose `request_id == rid`; the `on_final`
//!   callback fires once when the matching `ResponseFinal` arrives,
//!   at which point the pending entry is auto-unregistered (mirrors
//!   zenoh-pico's `_z_reply_handler` lifetime: terminal Final closes
//!   the channel and drops the slot).
//! - Reply-arm dispatch is body-agnostic: a `Response.body` of
//!   `CodecZenohReply` with inner `MsgPut` surfaces as
//!   [`InboundReplyBody::Put`] carrying the payload bytes; inner
//!   `MsgDel` surfaces as [`InboundReplyBody::Del`]. The
//!   `CodecZenohErr` arm surfaces as [`InboundReplyBody::Err`] with
//!   the optional encoding tuple + payload bytes.
//! - Unknown rids are dropped silently — application code must
//!   register a pending entry BEFORE issuing the outbound
//!   `Request(Query)`, otherwise the inbound reply chain is
//!   indistinguishable from a stray reply for a cancelled z_get.
//! - Manual `unregister(rid)` is supported for the application-
//!   cancel case (e.g. the z_get caller drops out of scope before
//!   the Final arrives). Idempotent — calling on a rid not present
//!   returns `false` without panicking.
//!
//! ## Why a separate registry and not a method on `QueryableRegistry`
//!
//! - **Direction asymmetry**: the queryable side is "I serve; here
//!   are replies" — produces outbound records into a buffer the
//!   runtime drains. The z_get side is "I request; tell me when a
//!   reply / final arrives" — consumes inbound records and routes to
//!   a registered callback. The shape of the registered callback is
//!   different in each direction (Responder borrow on serve, simple
//!   `&InboundReply` on consume), so combining them would force a
//!   placeholder borrow on the consume path.
//! - **State asymmetry**: queryable lives forever (registered at
//!   session open, fires on every matching inbound Query). Pending
//!   z_get is rid-scoped (registered before the outbound Query,
//!   auto-removed on Final). Mixing the two state machines invites
//!   accidental cross-cancellation bugs.
//! - **Future evolution**: timeout / cancellation / consolidation
//!   knobs land naturally on a dedicated pending table; bolting them
//!   onto QueryableRegistry would force every queryable to carry
//!   z_get-specific state.
//!
//! ## Threading
//!
//! `!Sync` by construction (mirror of [`QueryableRegistry`]). Cross-
//! task sharing wraps in `Arc<Mutex<…>>` /
//! `Arc<tokio::sync::Mutex<…>>` — the integration site (wz-ap-demo)
//! drives the registry from a single observer closure so no Mutex is
//! needed there.

// no_std module-body alloc prelude (mirrors wz-session-core::pubsub):
// `String` / `Vec` back the always-compiled InboundReply + Pending
// surface. R311gb-3c — `Box` is no longer imported at module level: the
// per-pending `(on_reply, on_final)` closures migrated from
// `Box<dyn FnMut>` (`ReplyCallback` / `FinalCallback`) to the generic
// `Pending<C: ReplySink>` sink seam, so production code no longer
// heap-boxes a callback here (`BoxedReplySink` owns that, in
// `reply_sink`). The test module imports `Box` itself.
// R311gb (Track 2) — `String` / `Vec` / `ToString` back the `alloc`-gated
// owned retention form (`InboundReply` / `InboundReplyBody` +
// `from_view`); the no-alloc control plane stores only `Pending` rows in a
// `BoundedVec` and fires through the borrowed `ReplyView` seam, so the
// owned-collection imports are `alloc`-gated.
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::string::ToString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// HashMap (peer-keyexpr table) is a param of the `alloc` wire-dispatch
// methods (`dispatch_response` / `dispatch_messages`), so its import is
// `alloc`-gated.
#[cfg(feature = "alloc")]
use hashbrown::HashMap;

// R311gb (Track 2) — bounded backing + the capacity SSOT for the no-alloc
// pending table.
use crate::bounded::BoundedVec;
use crate::caps;
use crate::registry_error::RegisterError;

// R311dy — `wz_codecs::{reply, response}` live in the `codec-response`
// codec_group, so the wire-dispatch imports + the local
// `resolve_wireexpr` helper that consume them gate on `codec-response`
// (`response_final` on `codec-response-final`). Unlike the queryable
// registry, `ReplyRegistry` stays always-compiled: its loopback
// delivery (`deliver_local_reply` / `deliver_local_final`) + timeout
// sweep (`sweep_timed_out`) are codec-agnostic and keep the `Pending`
// fields alive, mirroring `SubscriberRegistry` (whose `local_publish`
// loopback is likewise codec-free).
// `ReplyOwnedVariant` is named only by the `pubsub-put` / `pubsub-delete`
// Put / Del body arms inside `dispatch_response`; with neither arm the
// inner match collapses to the `_ => return` default, so the import gate
// requires `codec-response` AND at least one body-arm feature.
// R311fm — `query-reply` joins the gate: the z_get consumer's reply-body
// decode plane needs `ReplyOwnedVariant` to project a `Response(Reply)`
// Put / Del body into `InboundReplyBody`, independent of the pub/sub
// publisher markers. `query-reply` implies `codec-response`, so the
// outer `codec-response` requirement holds in every arm of the `any`.
#[cfg(all(feature = "codec-response", feature = "alloc"))]
use crate::wireexpr_resolve::resolve_wireexpr;
#[cfg(all(
    feature = "codec-response",
    feature = "alloc",
    any(
        feature = "pubsub-put",
        feature = "pubsub-delete",
        feature = "query-reply"
    )
))]
use wz_codecs::reply::ReplyOwnedVariant;
#[cfg(all(feature = "codec-response", feature = "alloc"))]
use wz_codecs::response::{ResponseOwned, ResponseOwnedVariant};
#[cfg(all(feature = "codec-response-final", feature = "alloc"))]
use wz_codecs::response_final::ResponseFinalOwned;

// R307 — `query-queryable` gates the producer-side `QueryReply` enum
// because it lives in `crate::query`, which is gated on the same
// feature. The wire-receive path inside this module does not need
// these types — only the loopback bridge (`impl From<QueryReply> for
// InboundReply`) and the `deliver_local_*` helpers below do. A
// `query-reply` consumer that wires no in-process queryable still
// gets the wire-side `Response` dispatch path with the loopback
// bridge elided.
#[cfg(feature = "alloc")]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
#[cfg(feature = "alloc")]
use crate::network_message::NetworkMessage;
#[cfg(all(feature = "query-queryable", feature = "alloc"))]
use crate::query::{QueryReply, ReplyBody};
// R311gb (Track 2) — the model-B reply seam. `ReplySink` (the bound on
// the generic `ReplyRegistry<C>` pending store) + `ReplyView` (the
// accessor contract the no-heap `dispatch_borrowed` / `fire_replies_for`
// pass as `&dyn ReplyView`) are unconditional (no_std-safe in
// `reply_sink`). `ReplyKind` is read only by the `alloc` owned-retention
// `InboundReply` impl, and `BoxedReplySink` is the AP closure adapter, so
// those two carry the `alloc` gate.
#[cfg(feature = "alloc")]
use crate::reply_sink::{BoxedReplySink, ReplyKind};
use crate::reply_sink::{ReplySink, ReplyView};

/// Body arm of an inbound reply record. Mirrors the producer-side
/// [`QueryReply`](crate::query::QueryReply) enum but inverted for
/// the consumer perspective: the application registered an
/// `on_reply` callback and now reads the decoded body, instead of
/// pushing one into an outbound buffer.
///
/// `Put.payload` clones the decoded `MsgPut.payload` so the
/// application can outlive the inbound dispatch borrow. Future
/// rounds may add a zero-copy `Borrowed` variant when the runtime
/// guarantees a per-iteration arena lifetime; for the AP MVP the
/// owned form keeps the call-site straightforward.
// R311gb (Track 2) — owned reply body (`Vec<u8>` / `String`), the AP
// retention form; `alloc`-gated.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundReplyBody {
    /// Successful data reply — `MsgPut` inner body. Payload bytes
    /// flow through verbatim. The `attachment` + `encoding` side-bands on
    /// the MsgPut envelope are surfaced (A8b — the receive twin of the A8a
    /// emit seam); the timestamp side-band is still not surfaced here (the
    /// aligner orders by the metadata in the attachment, not a reply ts).
    Put {
        /// The reply value bytes.
        payload: Vec<u8>,
        /// The inner-`MsgPut` body attachment (push-body ext id 0x03) the
        /// reply carried, if any — the side-band a storage aligner reads
        /// its `AlignmentReply` off. `None` when the reply had no
        /// attachment or `pubsub-attachment` is off (the decode is gated,
        /// mirroring the wire policy so a loopback reply matches a wire one).
        attachment: Option<Vec<u8>>,
        /// The inner-`MsgPut` value encoding (E-flag), mirroring the Err
        /// encoding shape (`packed_id`, `schema`). `None` when the reply
        /// carried no encoding or `pubsub-encoding` is off. What a querier
        /// reconstructs the aligner's `RetrievedValue.encoding` from.
        encoding: Option<(u32, Option<String>)>,
        /// R311y78 — the source identity `(zid, eid, sn)` the Put reply carried
        /// on its inner-body source_info ext (id 0x01), or `None` when the
        /// reply had no source_info or `reply-source-info` is off (the decode
        /// is gated, mirroring the producer emit seam). What an
        /// advanced-recovery subscriber re-keys / reorders a recovered
        /// (retransmitted) sample by.
        source_info: Option<crate::sample::SourceInfo>,
    },
    /// Delete-keyexpr reply — `MsgDel` inner body. Carries no payload bytes
    /// (the wire-form `MsgDel` body has only a header + optional timestamp +
    /// ext chain). R311y81 — `source_info` mirrors the Put arm: source_info
    /// lives in the shared push-body `_commons` and is emitted on a Del body
    /// too (zenoh-pico `_z_push_body_encode`), so a recovered Del sample
    /// re-keys identically.
    Del {
        /// The source identity `(zid, eid, sn)` the Del reply carried on its
        /// inner-body source_info ext (id 0x01), or `None` when the reply had
        /// no source_info or `reply-source-info` is off.
        source_info: Option<crate::sample::SourceInfo>,
    },
    /// Error reply — `Response.Err` arm. `encoding` mirrors the wire
    /// `Encoding { packed_id, schema_len, schema }` minus the
    /// `schema_len` (which is just the byte-length of `schema` and
    /// would be a layering leak at the application surface). `payload`
    /// is the application-level error blob.
    Err {
        encoding: Option<(u32, Option<String>)>,
        payload: Vec<u8>,
    },
}

/// One inbound reply record handed to the application's `on_reply`
/// callback. The `rid` echoes the rid the z_get caller used when
/// registering; the `keyexpr_literal` is the resolved keyexpr
/// string (mapping-id resolved against the peer table the same way
/// [`SubscriberRegistry`](crate::pubsub::SubscriberRegistry) does
/// for Push, or peer-aliased prefix + suffix concatenation).
// R311gb (Track 2) — owned reply record (the AP retention form);
// `alloc`-gated. The no-alloc fire path delivers `&dyn ReplyView`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundReply {
    /// Echo of the inbound `Response.request_id` — matches the rid
    /// the z_get caller used when registering.
    pub rid: u64,
    /// Resolved keyexpr literal. For an `Err` response with no
    /// keyexpr arm in the wire form (mapping_id=0, suffix=None) the
    /// dispatch drops silently rather than firing on an empty
    /// literal; the callback never sees a blank `keyexpr_literal`.
    pub keyexpr_literal: String,
    /// Inbound reply body arm (Put / Del / Err).
    pub body: InboundReplyBody,
}

/// R311gb-3c — connect the owned [`InboundReply`] (the AP retention form)
/// to the [`ReplyView`] accessor contract so the reply registry
/// dispatches through the `&dyn ReplyView` seam (model B). The owned
/// `InboundReplyBody` enum is projected to the flat accessor surface:
/// `kind` reads the discriminant, `payload` borrows the body bytes (empty
/// for Del), `err_encoding` borrows the Err encoding hint (None for
/// Put / Del).
#[cfg(feature = "alloc")]
impl ReplyView for InboundReply {
    fn rid(&self) -> u64 {
        self.rid
    }
    fn keyexpr(&self) -> &str {
        &self.keyexpr_literal
    }
    fn kind(&self) -> ReplyKind {
        match &self.body {
            InboundReplyBody::Put { .. } => ReplyKind::Put,
            InboundReplyBody::Del { .. } => ReplyKind::Del,
            InboundReplyBody::Err { .. } => ReplyKind::Err,
        }
    }
    fn payload(&self) -> &[u8] {
        match &self.body {
            InboundReplyBody::Put { payload, .. } => payload,
            InboundReplyBody::Del { .. } => &[],
            InboundReplyBody::Err { payload, .. } => payload,
        }
    }
    fn err_encoding(&self) -> Option<(u32, Option<&str>)> {
        match &self.body {
            InboundReplyBody::Err { encoding, .. } => encoding
                .as_ref()
                .map(|(id, schema)| (*id, schema.as_deref())),
            _ => None,
        }
    }
    fn attachment(&self) -> Option<&[u8]> {
        match &self.body {
            InboundReplyBody::Put { attachment, .. } => attachment.as_deref(),
            _ => None,
        }
    }
    fn put_encoding(&self) -> Option<(u32, Option<&str>)> {
        match &self.body {
            InboundReplyBody::Put { encoding, .. } => encoding
                .as_ref()
                .map(|(id, schema)| (*id, schema.as_deref())),
            _ => None,
        }
    }
    fn source_info(&self) -> Option<&crate::sample::SourceInfo> {
        match &self.body {
            InboundReplyBody::Put { source_info, .. } | InboundReplyBody::Del { source_info } => {
                source_info.as_ref()
            }
            InboundReplyBody::Err { .. } => None,
        }
    }
}

#[cfg(feature = "alloc")]
impl InboundReply {
    /// R311gb-3c — materialise an owned `InboundReply` from any
    /// [`ReplyView`] (the retention form of the borrowed delivery
    /// currency). The `Sample::from_view` analogue on the reply plane:
    /// the seam delivers `&dyn ReplyView`, so a consumer (or a test) that
    /// needs to keep a reply past the `on_reply` call copies it out
    /// through this constructor. AP-only (it allocates the owned payload /
    /// keyexpr); an MCU sink retains nothing or uses a pool slot instead.
    pub fn from_view(view: &dyn ReplyView) -> Self {
        let body = match view.kind() {
            ReplyKind::Put => InboundReplyBody::Put {
                payload: view.payload().to_vec(),
                attachment: view.attachment().map(<[u8]>::to_vec),
                encoding: view
                    .put_encoding()
                    .map(|(id, schema)| (id, schema.map(String::from))),
                source_info: view.source_info().cloned(),
            },
            ReplyKind::Del => InboundReplyBody::Del {
                source_info: view.source_info().cloned(),
            },
            ReplyKind::Err => InboundReplyBody::Err {
                encoding: view
                    .err_encoding()
                    .map(|(id, schema)| (id, schema.map(String::from))),
                payload: view.payload().to_vec(),
            },
        };
        Self {
            rid: view.rid(),
            keyexpr_literal: view.keyexpr().to_string(),
            body,
        }
    }
}

/// A8b — gate a loopback Put reply's staged attachment on the SAME inner
/// `pubsub-attachment` feature the wire decode uses, so when both reply paths
/// are present a SessionLocal reply surfaces the same attachment a wire
/// (Remote) reply would (and with the gate off neither carries one). NB the
/// OUTER arms differ — a build with `query-queryable` but no `pubsub-put` /
/// `query-reply` has this loopback arm yet drops the wire Put reply entirely
/// (the pre-existing R311fm gating); the parity claim is about the side-band
/// CONTENT when both arms exist, not about which arms a subset compiles.
#[cfg(all(feature = "query-queryable", feature = "alloc"))]
fn loopback_put_attachment(attachment: Option<Vec<u8>>) -> Option<Vec<u8>> {
    #[cfg(feature = "pubsub-attachment")]
    {
        attachment
    }
    #[cfg(not(feature = "pubsub-attachment"))]
    {
        let _ = attachment;
        None
    }
}

/// A8b — gate + convert a loopback Put reply's staged encoding to the
/// [`InboundReplyBody::Put`] shape (`packed_id`, `schema`), mirroring the wire
/// path's `pubsub-encoding` gate.
#[cfg(all(feature = "query-queryable", feature = "alloc"))]
fn loopback_put_encoding(
    encoding: Option<crate::sample::EncodingHint>,
) -> Option<(u32, Option<String>)> {
    #[cfg(feature = "pubsub-encoding")]
    {
        encoding.map(|e| (e.packed_id, e.schema))
    }
    #[cfg(not(feature = "pubsub-encoding"))]
    {
        let _ = encoding;
        None
    }
}

/// R311y78 — gate a loopback Put reply's staged source_info on the SAME
/// `reply-source-info` feature the wire decode uses, so a SessionLocal recovery
/// reply surfaces the same source identity a wire (Remote) reply would (and with
/// the gate off neither carries one). The source_info twin of
/// [`loopback_put_attachment`].
#[cfg(all(feature = "query-queryable", feature = "alloc"))]
fn loopback_put_source_info(
    source_info: Option<crate::sample::SourceInfo>,
) -> Option<crate::sample::SourceInfo> {
    #[cfg(feature = "reply-source-info")]
    {
        source_info
    }
    #[cfg(not(feature = "reply-source-info"))]
    {
        let _ = source_info;
        None
    }
}

/// A8b — extract an inbound Put reply's body attachment (push-body ext id
/// 0x03) for the [`InboundReplyBody::Put`] slot, gated on `pubsub-attachment`
/// (the wire policy: with the gate off the reply carries no attachment,
/// mirroring the A8a emit side). Reuses the shared
/// [`crate::attachment::decode_attachment_ext`] SSOT — the receive twin of
/// the emit's `encode_attachment_ext`.
#[cfg(all(
    feature = "codec-response",
    feature = "alloc",
    any(feature = "pubsub-put", feature = "query-reply")
))]
fn put_reply_attachment(put: &wz_codecs::msg_put::MsgPutOwned) -> Option<Vec<u8>> {
    #[cfg(feature = "pubsub-attachment")]
    {
        put.extensions.as_ref().and_then(|exts| {
            crate::attachment::decode_attachment_ext(
                exts,
                crate::attachment::ATTACHMENT_EXT_ID_PUSH,
            )
            .map(<[u8]>::to_vec)
        })
    }
    #[cfg(not(feature = "pubsub-attachment"))]
    {
        let _ = put;
        None
    }
}

/// R311y78 / R311y81 — extract an inbound reply BODY's source_info (ext id 0x01)
/// from its push-body extension chain, for the [`InboundReplyBody::Put`] /
/// [`InboundReplyBody::Del`] slot. source_info lives in the shared push-body
/// `_commons`, so a Put OR a Del body can carry it (the receive twin of the emit
/// side, where `ResponseReplyBuilder` stamps it on either arm) -- hence ONE
/// helper over the extensions slice serves both arms. Gated on
/// `reply-source-info` (the wire policy: with the gate off the decode drops it,
/// mirroring the producer emit seam). Reuses the shared
/// [`crate::sample::extract_source_info`] decode SSOT -- the receive twin of the
/// emit's `encode_source_info_ext_entry`.
#[cfg(all(
    feature = "codec-response",
    feature = "alloc",
    any(
        feature = "pubsub-put",
        feature = "pubsub-delete",
        feature = "query-reply"
    )
))]
fn reply_body_source_info(
    exts: Option<&Vec<wz_codecs::ext_entry::ExtEntryOwned>>,
) -> Option<crate::sample::SourceInfo> {
    #[cfg(feature = "reply-source-info")]
    {
        exts.and_then(|e| crate::sample::extract_source_info(e))
    }
    #[cfg(not(feature = "reply-source-info"))]
    {
        let _ = exts;
        None
    }
}

/// A8b — extract an inbound Put reply's value encoding (E-flag) in the
/// `(packed_id, schema)` shape the [`InboundReplyBody::Put`] slot mirrors
/// from the Err arm, gated on `pubsub-encoding`.
#[cfg(all(
    feature = "codec-response",
    feature = "alloc",
    any(feature = "pubsub-put", feature = "query-reply")
))]
fn put_reply_encoding(put: &wz_codecs::msg_put::MsgPutOwned) -> Option<(u32, Option<String>)> {
    #[cfg(feature = "pubsub-encoding")]
    {
        put.encoding.as_ref().map(|e| {
            (
                e.packed_id,
                e.schema.as_ref().map(|s| String::from(s.as_str())),
            )
        })
    }
    #[cfg(not(feature = "pubsub-encoding"))]
    {
        let _ = put;
        None
    }
}

/// R239 — in-process loopback adapter: project a producer-side
/// [`QueryReply`] (emitted by a queryable callback into the
/// [`crate::query::QueryableRegistry`] reply buffer) into the
/// consumer-side [`InboundReply`] shape the z_get caller's
/// `on_reply` callback expects.
///
/// This is the loopback counterpart of [`Self::dispatch_response`]:
/// the wire path decodes a peer-sent `Response` into `InboundReply`;
/// the loopback path projects a locally-fired `QueryReply` into the
/// same shape so the same callback runs against both origins. The
/// producer's `responder` tuple (envelope-level identity) is dropped
/// in the projection — the AP MVP consumer surface does not expose
/// the responder ext on `InboundReply` either way, so loopback
/// matches the wire branch's information loss exactly.
///
/// Consumes `self` so producer-allocated payload bytes flow directly
/// into the consumer body without an intermediate clone. Mirrors the
/// existing producer-side [`QueryReply::into_response`] adapter on
/// the wire-emit side — every `QueryReply` carries enough state to
/// be projected to *either* a wire `Response` (outbound) *or* an
/// in-process `InboundReply` (loopback).
#[cfg(all(feature = "query-queryable", feature = "alloc"))]
impl From<QueryReply> for InboundReply {
    fn from(reply: QueryReply) -> Self {
        match reply {
            QueryReply::Reply {
                rid,
                keyexpr_literal,
                body,
                encoding,
                // The timestamp side-band is still not surfaced on receive
                // (out of scope — the aligner orders by the metadata in the
                // attachment, not a reply T-flag); responder is envelope-level
                // identity the AP consumer surface does not expose either way.
                timestamp: _,
                responder: _,
                attachment,
                // R311y78 — surface the recovery source_info (id 0x01) onto the
                // loopback InboundReply (gated reply-source-info via
                // loopback_put_source_info, matching the wire decode) so an
                // advanced-recovery subscriber re-keys / reorders a recovered
                // sample identically whether it arrived loopback or over the
                // wire. Put-only (a Del reply carries no source_info slot).
                source_info,
            } => {
                let body = match body {
                    ReplyBody::Put(payload) => InboundReplyBody::Put {
                        payload,
                        // Gate the side-bands on the same `pubsub-attachment` /
                        // `pubsub-encoding` / `reply-source-info` the wire decode
                        // uses (see loopback_put_attachment), so the CONTENT
                        // matches a wire reply when both paths are present.
                        attachment: loopback_put_attachment(attachment),
                        encoding: loopback_put_encoding(encoding),
                        source_info: loopback_put_source_info(source_info),
                    },
                    // R311y81 — a Del recovery reply re-keys via the same
                    // source_info the Put arm carries (the staged QueryReply
                    // holds it regardless of body arm), gated reply-source-info.
                    ReplyBody::Del => InboundReplyBody::Del {
                        source_info: loopback_put_source_info(source_info),
                    },
                };
                Self {
                    rid,
                    keyexpr_literal,
                    body,
                }
            }
            QueryReply::Err {
                rid,
                keyexpr_literal,
                encoding,
                payload,
                responder: _,
            } => Self {
                rid,
                keyexpr_literal,
                body: InboundReplyBody::Err { encoding, payload },
            },
        }
    }
}

/// Stable handle returned by [`ReplyRegistry::register`]. Carries
/// the rid the registration was bound to so the caller can later
/// [`ReplyRegistry::unregister`] before the Final arrives. The
/// numeric value is exposed for diagnostic surfaces; callers should
/// not depend on the exact value across runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplyHandle(u64);

impl ReplyHandle {
    /// The rid the registration was bound to.
    pub fn rid(self) -> u64 {
        self.0
    }
}

struct Pending<C: ReplySink> {
    rid: u64,
    /// R239 — number of `Final` records this pending entry expects
    /// before it fires `on_final` and drops from the table. Mirrors
    /// zenoh-pico's `_z_pending_query_t._remaining_finals`
    /// (`vendor/zenoh-pico/include/zenoh-pico/session/query.h`;
    /// `_z_trigger_query_reply_final` in
    /// `vendor/zenoh-pico/src/session/query.c:222-256` decrements
    /// and fires on zero).
    ///
    /// For a wire-only `Locality::Remote` z_get the value is `1` (the
    /// peer emits exactly one `ResponseFinal`). For a SessionLocal
    /// z_get the value is `1` (the loopback emits one final after the
    /// queryable callbacks drain). For a `Locality::Any` z_get with
    /// at least one local queryable AND a wire branch the value is
    /// `2` (one loopback final + one peer final). Future mesh
    /// integration may expect N > 2 when multiple peers can each
    /// emit a final per query (zenoh-cpp router-fanout topology).
    ///
    /// `u32` matches zenoh-pico's `_remaining_finals` width and is
    /// wide enough for every plausible mesh fan-out.
    remaining_finals: u32,
    /// R261 — absolute monotonic-ms deadline (clock baseline-agnostic
    /// snapshot taken at register time as `clock.now_monotonic_ms() +
    /// timeout_ms`). `None` means the pending entry never expires
    /// (matches the pre-R261 contract; `QueryOptions::timeout_ms == 0`
    /// callers pass `None`). A `Some(d)` entry is swept by
    /// [`ReplyRegistry::sweep_timed_out`] when the caller-supplied
    /// `now_ms >= d`. The deadline uses absolute ms so the sweep call
    /// only needs to compare without re-reading the clock per entry.
    deadline_ms: Option<u64>,
    /// R311gb-3c — the reply-delivery sink (DIP seam). `C = BoxedReplySink`
    /// on AP (heap `on_reply` + `on_final` closures), a consumer-supplied
    /// closed `enum` on MCU. The per-pending `(on_reply, on_final)` pair
    /// the registration carried is now the sink's two methods.
    sink: C,
}

/// Reply table backing the inbound `Response(Reply|Err)` and
/// `ResponseFinal` → callback dispatch. `!Sync` by construction;
/// cross-task sharing goes through `Arc<Mutex<…>>`. See module-level
/// docs for scope.
///
/// R311gb (Track 2) — the pending table + register + rid correlation +
/// the no-heap fire (`dispatch_borrowed` / `deliver_local_final` /
/// `fire_final_for` / `sweep_timed_out`) form the no-alloc control plane.
/// The owned-retention `deliver_local_reply` + the wire-dispatch methods
/// carry `alloc` / `codec-*` gates per-method below.
pub struct ReplyRegistry<C: ReplySink> {
    pending: BoundedVec<Pending<C>, { caps::MAX_PENDING_QUERIES }>,
}

impl<C: ReplySink> Default for ReplyRegistry<C> {
    fn default() -> Self {
        Self::with_sink_backing()
    }
}

impl<C: ReplySink> ReplyRegistry<C> {
    /// New empty registry over an explicit sink backing `C`. Pending
    /// entries are stored in a `Vec` so duplicate-rid registrations (an
    /// application registering two independent z_gets that happen to
    /// share the same rid via a careless rid allocator) fire in
    /// registration order; the registry imposes no uniqueness on rid.
    ///
    /// R311gb-3c — the generic constructor (the no-`alloc` / MCU entry
    /// point, paired with [`register_sink`](Self::register_sink)). AP
    /// callers use the inferring [`new`](ReplyRegistry::new) shorthand,
    /// which fixes `C = BoxedReplySink`; mirrors
    /// [`crate::pubsub::SubscriberRegistry::with_sink_backing`].
    pub fn with_sink_backing() -> Self {
        Self {
            pending: BoundedVec::new(),
        }
    }

    /// R311gb-3c — register a pending z_get with an explicit
    /// [`ReplySink`]. The seam-native registration entry point: works on
    /// every profile (`C = BoxedReplySink` heap closures on AP, a
    /// consumer-supplied closed `enum` on MCU). The `alloc`-only
    /// [`register`](ReplyRegistry::register) convenience wrapper funnels
    /// through here after wrapping the `on_reply` + `on_final` closures in
    /// a [`BoxedReplySink`].
    ///
    /// `expected_finals` mirrors zenoh-pico's
    /// `_z_pending_query_t._remaining_finals` slot
    /// (`vendor/zenoh-pico/src/session/query.c:222-256`): one for a
    /// pure-wire (`Locality::Remote`) z_get expecting one peer
    /// `ResponseFinal`; one for a pure-loopback
    /// (`Locality::SessionLocal`) z_get expecting one synthetic
    /// final from [`Self::deliver_local_final`]; two for a
    /// `Locality::Any` z_get with at least one local queryable AND a
    /// wire branch.
    ///
    /// The returned [`ReplyHandle`] is the rid wrapped — exposed so
    /// callers that allocate rids opaquely (e.g. a future
    /// `z_get_builder` adapter) can carry the rid without leaking
    /// the integer all the way back to user code.
    ///
    /// R311gb (Track 2) — fallible on the no-alloc backing: a pending
    /// registration past [`caps::MAX_PENDING_QUERIES`] is rejected with
    /// [`RegisterError::TableFull`] (fail-fast, no silent drop). On
    /// the `alloc` backing it never fails, so the convenience
    /// [`register`](Self::register) wrapper `.expect()`s the result.
    pub fn register_sink(
        &mut self,
        rid: u64,
        expected_finals: u32,
        deadline_ms: Option<u64>,
        sink: C,
    ) -> Result<ReplyHandle, RegisterError> {
        self.pending
            .push(Pending {
                rid,
                remaining_finals: expected_finals,
                deadline_ms,
                sink,
            })
            .map_err(|_| RegisterError::TableFull)?;
        Ok(ReplyHandle(rid))
    }

    /// Remove a previously-registered pending entry by rid. Returns
    /// `true` if at least one entry was removed. Removes every entry
    /// matching the rid (the duplicate-rid registration shape is
    /// supported on `register`; symmetric on `unregister`). Idempotent
    /// — calling on a rid that was never registered or already
    /// fired-and-removed returns `false` without panicking.
    pub fn unregister(&mut self, rid: u64) -> bool {
        let before = self.pending.len();
        self.pending.retain(|p| p.rid != rid);
        before != self.pending.len()
    }

    /// Number of currently-pending registrations.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the registry holds any pending registration.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Route an inbound [`Response`] through the pending table.
    ///
    /// - The Response's keyexpr is resolved through
    ///   `peer_keyexpr_table` (the shared mapping populated by the
    ///   subscriber side's `absorb_declare` from inbound
    ///   `Declare(DeclKexpr)`). The composition rule mirrors
    ///   [`crate::query::QueryableRegistry::dispatch_request`]:
    ///   `id == 0` → suffix verbatim; `id != 0` → `table[id]` +
    ///   optional suffix. Un-resolvable mapping ids drop the
    ///   dispatch silently rather than firing on a partial keyexpr.
    /// - Each pending entry whose `rid == response.request_id`
    ///   fires once, in registration order. The pending entry stays
    ///   in the table — `Response(Reply|Err)` does NOT terminate the
    ///   chain; only `ResponseFinal` does (via
    ///   [`Self::dispatch_response_final`]).
    /// - `ResponseVariant::Default { tag, .. }` arms — which the
    ///   codec surfaces when the inner-body MID falls outside
    ///   `{Reply, Err}` — are dropped silently. This matches
    ///   zenoh-pico's `_z_handle_response` dispatch which only
    ///   recognises the Reply / Err inner MIDs and treats other tags
    ///   as wire-spec violations to be ignored at the application
    ///   layer (the transport FSM's framing path is responsible for
    ///   surfacing them as `FramingError` if needed).
    ///
    /// R311dy — `codec-response`-gated: the `&ResponseOwned` parameter
    /// type lives in the `codec-response` codec_group, so the wire
    /// dispatch entry point elides in a `codec-response`-OFF subset
    /// (the loopback `deliver_local_reply` keeps the registry useful).
    #[cfg(all(feature = "codec-response", feature = "alloc"))]
    pub fn dispatch_response(
        &mut self,
        response: &ResponseOwned,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        let resolved = match resolve_wireexpr(&response.keyexpr.body, peer_keyexpr_table) {
            Some(s) => s,
            None => return,
        };
        // R311cc — pubsub-put / pubsub-delete gate the inbound Reply
        // body variants. cfg-off drops the corresponding Reply (the
        // query-side dispatcher mirror of pubsub.rs PushVariant arms).
        let body = match &response.body {
            ResponseOwnedVariant::CodecZenohReply(reply) => match &reply.body {
                // R311fm — `query-reply` joins `pubsub-put` / `pubsub-delete`
                // on the reply-body decode arms: a z_get consumer that pins
                // the getter plane (no pub/sub data plane) must still project
                // an inbound `Response(Reply)` Put / Del body into
                // `InboundReplyBody`. Before R311fm these arms gated ONLY on
                // the publisher markers, so the named `zget-reply-only` subset
                // type-checked but dropped every reply (`_ => return`). The
                // pub-bearing presets keep the `pubsub-*` arm; a pure getter
                // composes on `query-reply` alone.
                #[cfg(any(feature = "pubsub-put", feature = "query-reply"))]
                ReplyOwnedVariant::CodecZenohMsgPut(put) => InboundReplyBody::Put {
                    payload: put.payload.as_slice().to_vec(),
                    attachment: put_reply_attachment(put),
                    encoding: put_reply_encoding(put),
                    source_info: reply_body_source_info(put.extensions.as_ref()),
                },
                #[cfg(any(feature = "pubsub-delete", feature = "query-reply"))]
                ReplyOwnedVariant::CodecZenohMsgDel(del) => InboundReplyBody::Del {
                    source_info: reply_body_source_info(del.extensions.as_ref()),
                },
                // Default arm carries a runtime tag whose MID falls
                // outside {MsgPut, MsgDel}. zenoh-pico's inner-body
                // dispatch treats this as a wire-spec violation; the
                // AP MVP path mirrors that by dropping silently. cfg-off
                // pubsub-put / -delete arms also fall through here.
                _ => return,
            },
            ResponseOwnedVariant::CodecZenohErr(err) => {
                let encoding = err.encoding.as_ref().map(|e| {
                    (
                        e.packed_id,
                        e.schema.as_ref().map(|s| String::from(s.as_str())),
                    )
                });
                InboundReplyBody::Err {
                    encoding,
                    payload: err.payload.as_slice().to_vec(),
                }
            }
            // See ResponseVariant::Default rationale on Reply arm.
            ResponseOwnedVariant::Default { .. } => return,
        };
        let inbound = InboundReply {
            rid: response.request_id,
            keyexpr_literal: resolved,
            body,
        };
        self.fire_replies_for(&inbound);
    }

    /// Route an inbound [`ResponseFinal`] through the pending table.
    /// Every pending entry whose `rid == response_final.request_id`
    /// fires its `on_final` callback exactly once and is then removed
    /// from the table. Duplicate-rid registrations all fire (in
    /// registration order) and all are removed in the same dispatch.
    /// Unknown rids drop silently.
    #[cfg(all(feature = "codec-response-final", feature = "alloc"))]
    pub fn dispatch_response_final(&mut self, response_final: &ResponseFinalOwned) {
        self.fire_final_for(response_final.request_id);
    }

    /// R239 — loopback delivery of an in-process [`InboundReply`].
    /// Used by [`crate::session::Session::query`]'s loopback branch to
    /// fan a [`QueryReply`] (produced by a local queryable through
    /// [`crate::query::QueryableRegistry::local_query`]) into every
    /// pending registration whose `rid` matches, mirroring exactly
    /// the wire-arrival fan in [`Self::dispatch_response`] without the
    /// wire-decode + keyexpr-resolution prefix (the loopback caller
    /// already knows the literal). Single dispatch path — wire and
    /// loopback origins fire through the same
    /// [`Self::fire_replies_for`] helper so the per-entry behaviour
    /// (multiple registrations on the same rid, entry retained until
    /// Final) is identical across origins.
    #[cfg(feature = "alloc")]
    pub fn deliver_local_reply(&mut self, inbound: &InboundReply) {
        self.fire_replies_for(inbound);
    }

    /// R311gb (Track 2) — no-heap fire entry for the reply plane: deliver
    /// a borrowed [`ReplyView`] to every pending entry whose `rid`
    /// matches, firing each sink's `on_reply` once. Borrow-driven (no
    /// owned `InboundReply` materialization), so it is the MCU no-heap
    /// reply path; the `alloc` loopback ([`deliver_local_reply`](Self::deliver_local_reply))
    /// and the wire path ([`dispatch_response`](Self::dispatch_response))
    /// funnel their owned `InboundReply` (which impls `ReplyView`) through
    /// the same [`fire_replies_for`](Self::fire_replies_for) matcher (one
    /// SSOT). The terminal `on_final` no-heap entry is
    /// [`deliver_local_final`](Self::deliver_local_final) (a `Copy` rid
    /// scalar). Returns the count of sinks fired.
    pub fn dispatch_borrowed(&mut self, reply: &dyn ReplyView) -> usize {
        self.fire_replies_for(reply)
    }

    /// R239 — loopback delivery of an in-process `ResponseFinal`-
    /// equivalent. Used by [`crate::session::Session::query`]'s
    /// loopback branch after the queryable callbacks have emitted all
    /// their replies through [`Self::deliver_local_reply`]; this call
    /// fires the matching `on_final` callbacks and removes the pending
    /// entries from the table, matching the wire-arrival behaviour in
    /// [`Self::dispatch_response_final`] exactly (single dispatch path
    /// via [`Self::fire_final_for`]).
    pub fn deliver_local_final(&mut self, rid: u64) {
        self.fire_final_for(rid);
    }

    /// R261 — fire `on_final` + drop every pending entry whose
    /// caller-supplied `deadline_ms` is at or before `now_ms`. Returns
    /// the number of pending entries swept (zero if no entry has
    /// timed out, which is the common case when the production sweep
    /// runs on every drive_session iteration).
    ///
    /// The fired `on_final` carries the entry's `rid` only — the
    /// callback cannot distinguish "timed out" from a normal Final via
    /// the rid argument. This matches the R261 architectural pick
    /// (opaque cause, FinalCallback signature unchanged): callers that
    /// need a timeout signal observe it indirectly by inspecting their
    /// own outstanding-rid map at sweep time, or by treating the
    /// `on_final` as a stream-terminated signal regardless of cause.
    /// Future rounds may extend `FinalCallback` to carry an explicit
    /// `FinalCause` enum if a concrete user need arises (R261 carry).
    ///
    /// Entries with `deadline_ms == None` (the `QueryOptions::timeout_ms
    /// == 0` "never expire" path) are skipped — they remain pending
    /// across an arbitrary number of sweep passes until a wire or
    /// loopback Final actually arrives. Idempotent: a second
    /// `sweep_timed_out` call with the same `now_ms` returns 0
    /// (everything that could have expired already did).
    ///
    /// `now_ms` is supplied by the caller (typically
    /// `clock.now_monotonic_ms()`) so the registry test surface
    /// remains deterministic — a unit test can drive the sweep with a
    /// hand-picked `now_ms` value without needing to advance a real
    /// clock or mock TimeSource.
    pub fn sweep_timed_out(&mut self, now_ms: u64) -> usize {
        // Same drain-then-fire pattern as fire_final_for: the
        // borrow-checker forbids calling the captured on_final while a
        // &mut self.pending iteration is active, so we partition first
        // and fire after the partition releases the borrow. This also
        // ensures a panicking on_final does NOT leave half-swept entries
        // in the registry — every fired entry has already been removed
        // from self.pending by the time its callback runs.
        // R311ig — no-alloc drain-partition via the shared
        // `BoundedVec::drain_partition` seam: extract the expired entries
        // (removed from self.pending), then fire after the borrow releases
        // so a panicking on_final cannot leave a half-swept entry behind.
        let fired = self
            .pending
            .drain_partition(|entry| matches!(entry.deadline_ms, Some(d) if d <= now_ms));
        let swept = fired.len();
        for mut entry in fired {
            let rid = entry.rid;
            entry.sink.on_final(rid);
        }
        swept
    }

    /// R239 — shared reply fan body for wire ([`Self::dispatch_response`])
    /// and loopback ([`Self::deliver_local_reply`]) origins. Each
    /// pending entry whose `rid == inbound.rid` fires its `on_reply`
    /// callback once; the entry stays in the table (only `Final`
    /// removes it). Mirrors the R238 `fire_matching_queryables` split
    /// on the queryable side.
    /// R311gb (Track 2) — takes the borrowed [`ReplyView`] (the no-heap
    /// delivery currency) so both the owned-`InboundReply` callers (wire +
    /// `alloc` loopback, which coerce `&InboundReply` to `&dyn ReplyView`)
    /// and the no-heap [`dispatch_borrowed`](Self::dispatch_borrowed)
    /// share one matcher. Returns the count of sinks fired.
    fn fire_replies_for(&mut self, reply: &dyn ReplyView) -> usize {
        let rid = reply.rid();
        let mut fired: usize = 0;
        for pending in self.pending.iter_mut() {
            if pending.rid == rid {
                pending.sink.on_reply(reply);
                fired = fired.saturating_add(1);
            }
        }
        fired
    }

    /// R239 — shared final fan body for wire
    /// ([`Self::dispatch_response_final`]) and loopback
    /// ([`Self::deliver_local_final`]) origins. Decrements each
    /// matching entry's `remaining_finals` counter; entries that
    /// reach zero fire their `on_final` callback in registration
    /// order and are dropped from the table. Entries whose counter
    /// is still positive remain pending — this is the
    /// `Locality::Any` two-final case (one loopback final + one peer
    /// final must both arrive before the application sees the user
    /// `on_final`). Duplicate-rid registrations are processed
    /// independently (each entry decrements its own counter).
    /// Unknown rids drop silently — the partition fires zero entries
    /// and the keep vec equals the pre-call pending vec.
    ///
    /// Mirrors zenoh-pico's `_z_trigger_query_reply_final`
    /// (`vendor/zenoh-pico/src/session/query.c:222-256`): `if
    /// (pen_qry->_remaining_finals > 0) { pen_qry->_remaining_finals--;
    /// } bool do_finalize = (pen_qry->_remaining_finals == 0);`.
    fn fire_final_for(&mut self, rid: u64) {
        // Partition: take ownership of every matching entry that
        // reaches zero, leave the rest (decremented but non-zero, or
        // non-matching) in place. Vec::retain would force us to mutate
        // the callback in-place which the borrow checker rejects (we
        // need to call `(on_final)(rid)` which requires `&mut Pending`);
        // we instead drain the matches into a stash and fire after the
        // retain-pass releases the &mut self.pending borrow.
        // R311ig — no-alloc drain-partition via the shared
        // `BoundedVec::drain_partition` seam (see `sweep_timed_out`); the
        // extract predicate mutates the entry (decrement remaining_finals)
        // and extracts only when it reaches zero. Order-preserving (matters
        // for the documented duplicate-rid registration-order final firing).
        let fired = self.pending.drain_partition(|entry| {
            if entry.rid == rid && entry.remaining_finals > 0 {
                entry.remaining_finals -= 1;
                return entry.remaining_finals == 0;
            }
            false
        });
        for mut entry in fired {
            entry.sink.on_final(rid);
        }
    }

    /// Drain a `Vec<NetworkMessage>` (typically the
    /// `FramePayload.messages` field surfaced by
    /// [`crate::session_glue::drive_session_until_terminal`]) through
    /// the pending table. Each `NetworkMessage::Response` routes via
    /// [`Self::dispatch_response`]; each `NetworkMessage::ResponseFinal`
    /// routes via [`Self::dispatch_response_final`]. Other variants
    /// (Push / Request / Declare / Interest / Oam / Unknown) are
    /// no-ops here.
    #[cfg(feature = "alloc")]
    pub fn dispatch_messages(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        // R311s / R311dy — `NetworkMessage::{Response,ResponseFinal}` are
        // cfg-gated on `codec-response` / `codec-response-final`; the
        // dispatch arms match. `peer_keyexpr_table` is consumed only by
        // the `codec-response` (Response) arm, so it is silenced whenever
        // `codec-response` is OFF. The whole dispatch loop gates on
        // `any(codec-response, codec-response-final)` so a build with
        // neither does not leave a single-pattern `match` (clippy) — it
        // is a clean no-op while the signature stays stable (R311g1).
        #[cfg(not(feature = "codec-response"))]
        let _ = peer_keyexpr_table;
        #[cfg(not(any(feature = "codec-response", feature = "codec-response-final")))]
        let _ = messages;
        #[cfg(any(feature = "codec-response", feature = "codec-response-final"))]
        for message in messages {
            match message {
                #[cfg(feature = "codec-response")]
                NetworkMessage::Response(resp) => {
                    self.dispatch_response(resp, peer_keyexpr_table);
                }
                #[cfg(feature = "codec-response-final")]
                NetworkMessage::ResponseFinal(rf) => {
                    self.dispatch_response_final(rf);
                }
                _ => {}
            }
        }
    }

    /// Convenience adapter that pulls the `FramePayload.messages` out
    /// of an [`IterationEvent::Poll(DriverLoopOutcome::FramePayload)`]
    /// surface and forwards to [`Self::dispatch_messages`]. Mirror
    /// of [`crate::query::QueryableRegistry::dispatch_iteration_event`]
    /// for the z_get-side. Other `IterationEvent` variants
    /// (`Lease`, non-FramePayload Poll outcomes) are no-ops.
    #[cfg(feature = "alloc")]
    pub fn dispatch_iteration_event(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            self.dispatch_messages(messages, peer_keyexpr_table);
        }
    }
}

/// R311gb-3c — AP / `alloc`-profile convenience constructors. The
/// closure-taking `register` wrapper lives here (on the `BoxedReplySink`
/// instantiation only) because it heap-boxes the `on_reply` + `on_final`
/// closures via [`BoxedReplySink`]; the no-`alloc` profile registers a
/// consumer-supplied sink through the generic
/// [`register_sink`](ReplyRegistry::register_sink) instead. Mirror of
/// [`crate::pubsub::SubscriberRegistry`]'s `BoxedSink` convenience block.
///
/// R311gb (Track 2) — gated on `alloc` only: the convenience wrapper
/// funnels through the un-gated `register_sink`, so the AP register
/// surface composes in any `alloc` subset (`BoxedReplySink` is itself
/// `alloc`-gated).
#[cfg(feature = "alloc")]
impl ReplyRegistry<BoxedReplySink> {
    /// New empty AP registry backed by heap-boxed closures
    /// ([`BoxedReplySink`]). The inferring shorthand for
    /// [`with_sink_backing`](ReplyRegistry::with_sink_backing):
    /// `ReplyRegistry::new()` fixes `C = BoxedReplySink` so the
    /// closure-taking [`register`](Self::register) wrapper is in reach
    /// without a turbofish.
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// Register a pending z_get with `on_reply` + `on_final` closures.
    /// The `on_reply` closure receives `&dyn ReplyView` (resolved
    /// keyexpr / kind / payload / err-encoding) — the R311gb-3c seam
    /// contract replaces the prior owned `&InboundReply`; this is the
    /// [`feedback_signature_stability`] wire-data principled exemption,
    /// taken so one registry backs both heap and no-heap profiles. The
    /// `on_final` closure receives the bare `rid`. Both are heap-boxed
    /// via [`BoxedReplySink`].
    ///
    /// `on_reply` fires once per inbound `Response(Reply|Err)` whose
    /// `request_id == rid`; `on_final` fires exactly once — when the
    /// entry's `expected_finals` counter reaches zero, after which the
    /// entry is auto-unregistered. See
    /// [`register_sink`](Self::register_sink) for the `expected_finals`
    /// semantics.
    pub fn register(
        &mut self,
        rid: u64,
        expected_finals: u32,
        deadline_ms: Option<u64>,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> ReplyHandle {
        // AP backing: `register_sink` is infallible here (the BoundedVec
        // pending table grows past the advisory `N`), so the convenience
        // wrapper keeps its `ReplyHandle` signature.
        self.register_sink(
            rid,
            expected_finals,
            deadline_ms,
            BoxedReplySink::new(on_reply, on_final),
        )
        .expect("register on the alloc backing never exceeds declared capacity")
    }
}

// R311gn-follow — the reply/zget wire path now resolves keyexprs through
// the shared `crate::wireexpr_resolve::resolve_wireexpr` SSOT (imported
// above, codec-response-gated). The prior private copy was deleted; the
// `dispatch_response` caller already matches the free fn's signature.

// R311dy — the behavioural reply tests build Response / ResponseFinal
// fixtures (codec-response + codec-response-final) and exercise the
// Put / Del body arms (pubsub-put / pubsub-delete). The module-level
// gate enumerates that union so a plain `cargo test -p wz-session-core`
// (default = alloc only) elides them; the C1f lane enables the set
// explicitly (C1c/C1d/C1e precedent). The three `From<QueryReply>`
// loopback-projection tests carry an additional inner
// `#[cfg(feature = "query-queryable")]` gate.
// R311fn — the test-module gate is the reply-DECODE-capability predicate,
// not the pub/sub publisher markers. The fixtures + dispatch tests exercise
// the inbound `Response(Reply)` Put / Del body arms, which (post-R311fm)
// gate on `any(pubsub-put, query-reply)` / `any(pubsub-delete, query-reply)`.
// Gating the test module on the same `any(...)` predicate means the suite
// compiles — and the put/del decode tests RUN — under the pure getter
// subset (`query-reply`, pub/sub OFF), the exact path R311fm fixed. Before
// R311fn the module required `pubsub-put` + `pubsub-delete`, so the getter
// arm had ZERO unit coverage (only the wz-e2e-zget e2e guarded it); a
// revert of the `query-reply` arm to `_ => return` would have kept this
// unit suite green. The pub-bearing lanes (C1d/C1f) still satisfy both
// `any(...)` clauses via the publisher markers, so they are unchanged; the
// new query-reply-only lane in C1f exercises the getter arm.
#[cfg(all(
    test,
    feature = "codec-response",
    feature = "codec-response-final",
    any(feature = "pubsub-put", feature = "query-reply"),
    any(feature = "pubsub-delete", feature = "query-reply")
))]
mod tests {
    use super::*;
    // no_std test prelude: the std prelude (Box / String / Vec / vec!)
    // is absent under `#![no_std]`, so the alloc forms are imported
    // explicitly; the host-run callback-capture cells use `std::sync`.
    use alloc::boxed::Box;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    // Fixtures build the borrowed codec views then `.into_owned()` at
    // the dispatch boundary (which now takes the `*Owned` mirrors).
    use wz_codecs::encoding::Encoding;
    use wz_codecs::err::Err as ErrBody;
    use wz_codecs::msg_del::MsgDel;
    use wz_codecs::msg_put::MsgPut;
    use wz_codecs::reply::{Reply, ReplyVariant};
    use wz_codecs::response::{Response, ResponseVariant};
    use wz_codecs::response_final::ResponseFinal;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    fn response_reply_put(
        rid: u64,
        mapping_id: u64,
        suffix: Option<&str>,
        payload: &[u8],
    ) -> ResponseOwned {
        let suffix_len = suffix.map(|s| s.len() as u64);
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix,
            }),
        };
        let reply = Reply {
            body: ReplyVariant::CodecZenohMsgPut(MsgPut {
                payload_len: payload.len() as u64,
                payload,
                ..MsgPut::default()
            }),
            ..Reply::default()
        };
        Response {
            request_id: rid,
            keyexpr,
            body: ResponseVariant::CodecZenohReply(reply),
            ..Response::default()
        }
        .try_into_owned()
        .unwrap()
    }

    fn response_reply_del(rid: u64, suffix: &str) -> ResponseOwned {
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix),
            }),
        };
        let reply = Reply {
            body: ReplyVariant::CodecZenohMsgDel(MsgDel::default()),
            ..Reply::default()
        };
        Response {
            request_id: rid,
            keyexpr,
            body: ResponseVariant::CodecZenohReply(reply),
            ..Response::default()
        }
        .try_into_owned()
        .unwrap()
    }

    fn response_err(
        rid: u64,
        suffix: &str,
        packed_id: u32,
        schema: Option<&str>,
        payload: &[u8],
    ) -> ResponseOwned {
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix),
            }),
        };
        let schema_len = schema.map(|s| s.len() as u64);
        let encoding = Encoding {
            packed_id,
            schema_len,
            schema,
        };
        let err_body = ErrBody {
            encoding: Some(encoding),
            payload_len: payload.len() as u64,
            payload,
            ..ErrBody::default()
        };
        Response {
            request_id: rid,
            keyexpr,
            body: ResponseVariant::CodecZenohErr(err_body),
            ..Response::default()
        }
        .try_into_owned()
        .unwrap()
    }

    fn response_final_for(rid: u64) -> ResponseFinalOwned {
        ResponseFinal {
            request_id: rid,
            ..ResponseFinal::default()
        }
        .try_into_owned()
        .unwrap()
    }

    #[test]
    fn empty_registry_dispatch_is_noop() {
        let mut reg = ReplyRegistry::new();
        let resp = response_reply_put(42, 0, Some("home/temp"), b"21.0");
        reg.dispatch_response(&resp, &HashMap::new());
        reg.dispatch_response_final(&response_final_for(42));
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_assigns_handle_and_grows_table() {
        let mut reg = ReplyRegistry::new();
        let h1 = reg.register(7, 1, None, |_| {}, |_| {});
        let h2 = reg.register(8, 1, None, |_| {}, |_| {});
        assert_eq!(h1.rid(), 7);
        assert_eq!(h2.rid(), 8);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn unregister_is_idempotent_and_removes_only_matching_rid() {
        let mut reg = ReplyRegistry::new();
        reg.register(7, 1, None, |_| {}, |_| {});
        reg.register(8, 1, None, |_| {}, |_| {});
        assert!(reg.unregister(7));
        assert!(
            !reg.unregister(7),
            "second unregister of same rid is a no-op"
        );
        assert_eq!(reg.len(), 1);
        assert!(reg.unregister(8));
        assert!(reg.is_empty());
    }

    #[test]
    fn dispatch_response_fires_on_reply_for_matching_rid_with_put_body() {
        let mut reg = ReplyRegistry::new();
        let captured: Arc<Mutex<Vec<InboundReply>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_cb = captured.clone();
        reg.register(
            42,
            1,
            None,
            move |reply| {
                captured_cb
                    .lock()
                    .unwrap()
                    .push(InboundReply::from_view(reply))
            },
            |_| {},
        );

        let resp = response_reply_put(42, 0, Some("home/temp"), b"21.0");
        reg.dispatch_response(&resp, &HashMap::new());

        let snapshot = captured.lock().unwrap();
        assert_eq!(snapshot.len(), 1);
        let reply = &snapshot[0];
        assert_eq!(reply.rid, 42);
        assert_eq!(reply.keyexpr_literal, "home/temp");
        match &reply.body {
            InboundReplyBody::Put { payload, .. } => assert_eq!(payload, b"21.0"),
            other => panic!("expected Put, got {other:?}"),
        }
    }

    /// A8b — the EMIT->RECEIVE closure: a reply built with the A8a
    /// `ResponseReplyBuilder.attachment()` / `.encoding()` decodes back
    /// through `dispatch_response`, so the `InboundReply` surfaces the
    /// attachment (the storage aligner's `AlignmentReply` carrier) AND the
    /// value encoding. Proves emit and receive agree on the wire shape.
    #[cfg(all(
        feature = "codec-response",
        feature = "pubsub-attachment",
        feature = "pubsub-encoding",
        feature = "query-reply"
    ))]
    #[test]
    fn dispatch_response_surfaces_put_attachment_and_encoding() {
        use crate::reply_sink::ReplyView;
        use crate::response_build::ResponseReplyBuilder;
        use crate::sample::EncodingHint;

        let mut reg = ReplyRegistry::new();
        let captured: Arc<Mutex<Vec<InboundReply>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_cb = captured.clone();
        reg.register(
            42,
            1,
            None,
            move |reply| {
                captured_cb
                    .lock()
                    .unwrap()
                    .push(InboundReply::from_view(reply))
            },
            |_| {},
        );

        let enc = EncodingHint {
            packed_id: 13,
            schema: None,
        };
        let resp = ResponseReplyBuilder::new(42, 0, Some("demo/a"), b"stored-value")
            .attachment(b"align-reply")
            .encoding(&enc)
            .build()
            .unwrap();
        reg.dispatch_response(&resp, &HashMap::new());

        let snapshot = captured.lock().unwrap();
        assert_eq!(snapshot.len(), 1);
        let reply = &snapshot[0];
        match &reply.body {
            InboundReplyBody::Put {
                payload,
                attachment,
                encoding,
                source_info: _,
            } => {
                assert_eq!(payload, b"stored-value");
                assert_eq!(attachment.as_deref(), Some(&b"align-reply"[..]));
                assert_eq!(*encoding, Some((13, None)));
            }
            other => panic!("expected Put, got {other:?}"),
        }
        // The same metadata via the ReplyView seam accessors (A8b contract).
        assert_eq!(reply.attachment(), Some(&b"align-reply"[..]));
        assert_eq!(reply.put_encoding(), Some((13, None)));
    }

    /// R311y78 — the source_info emit->receive closure: a reply built with the
    /// producer `ResponseReplyBuilder.source_info()` (R311y74) decodes back
    /// through `dispatch_response`, so the `InboundReply` surfaces the
    /// `(zid, eid, sn)` via the `ReplyView::source_info()` accessor — what an
    /// advanced-recovery subscriber re-keys / reorders a recovered sample by.
    #[cfg(all(
        feature = "codec-response",
        feature = "reply-source-info",
        feature = "query-reply"
    ))]
    #[test]
    fn dispatch_response_surfaces_put_source_info() {
        use crate::reply_sink::ReplyView;
        use crate::response_build::ResponseReplyBuilder;
        use crate::sample::SourceInfo;

        let mut reg = ReplyRegistry::new();
        let captured: Arc<Mutex<Vec<InboundReply>>> = Arc::new(Mutex::new(Vec::new()));
        let cb = captured.clone();
        reg.register(
            42,
            1,
            None,
            move |r| cb.lock().unwrap().push(InboundReply::from_view(r)),
            |_| {},
        );

        let si = SourceInfo::new(&[0xAA; 4], 11, 17);
        let resp = ResponseReplyBuilder::new(42, 0, Some("demo/a"), b"v")
            .source_info(&si)
            .build()
            .unwrap();
        reg.dispatch_response(&resp, &HashMap::new());

        let snap = captured.lock().unwrap();
        assert_eq!(snap.len(), 1);
        let got = snap[0]
            .source_info()
            .expect("recovered reply surfaces source_info via ReplyView");
        assert_eq!(got.zid_prefix(), &[0xAA; 4]);
        assert_eq!(got.eid, 11);
        assert_eq!(got.sn, 17);
    }

    /// R311y78 — the loopback receive twin: a `QueryReply` staged with
    /// source_info (the advanced cache's recovery reply) projects through
    /// `From<QueryReply>` so a SessionLocal reply surfaces the same source
    /// identity a wire (Remote) reply would (gated reply-source-info, matching
    /// the wire decode path).
    #[cfg(all(feature = "query-queryable", feature = "reply-source-info"))]
    #[test]
    fn from_query_reply_put_surfaces_source_info() {
        use crate::query::{QueryReply, ReplyBody};
        use crate::reply_sink::ReplyView;
        use crate::sample::SourceInfo;

        let si = SourceInfo::new(&[0x09; 1], 3, 5);
        let qr = QueryReply::Reply {
            rid: 11,
            keyexpr_literal: "sensors/a".to_string(),
            body: ReplyBody::Put(b"value".to_vec()),
            encoding: None,
            timestamp: None,
            responder: None,
            attachment: None,
            source_info: Some(si.clone()),
        };
        let inbound: InboundReply = qr.into();
        let got = inbound
            .source_info()
            .expect("loopback reply surfaces source_info");
        assert_eq!(got.zid_prefix(), &[0x09][..]);
        assert_eq!((got.eid, got.sn), (3, 5));
    }

    /// R311y81 — the Del-arm mirror of `dispatch_response_surfaces_put_source_info`:
    /// a Del recovery reply built with source_info (`.reply_del().source_info()`)
    /// decodes back so the `InboundReply` (Del) surfaces the `(zid, eid, sn)` via
    /// `ReplyView::source_info()` — closing the emit/decode asymmetry (source_info
    /// lives in the shared push-body `_commons`, present on Put AND Del bodies).
    #[cfg(all(
        feature = "codec-response",
        feature = "reply-source-info",
        feature = "query-reply"
    ))]
    #[test]
    fn dispatch_response_surfaces_del_source_info() {
        use crate::reply_sink::ReplyView;
        use crate::response_build::ResponseReplyBuilder;
        use crate::sample::SourceInfo;

        let mut reg = ReplyRegistry::new();
        let captured: Arc<Mutex<Vec<InboundReply>>> = Arc::new(Mutex::new(Vec::new()));
        let cb = captured.clone();
        reg.register(
            42,
            1,
            None,
            move |r| cb.lock().unwrap().push(InboundReply::from_view(r)),
            |_| {},
        );

        let si = SourceInfo::new(&[0xBB; 2], 7, 9);
        let resp = ResponseReplyBuilder::new(42, 0, Some("demo/a"), &[])
            .reply_del()
            .source_info(&si)
            .build()
            .unwrap();
        reg.dispatch_response(&resp, &HashMap::new());

        let snap = captured.lock().unwrap();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].kind(), ReplyKind::Del);
        let got = snap[0]
            .source_info()
            .expect("Del recovery reply surfaces source_info");
        assert_eq!(got.zid_prefix(), &[0xBB; 2]);
        assert_eq!((got.eid, got.sn), (7, 9));
    }

    /// R311y81 — the loopback twin: a Del-body `QueryReply` staged with
    /// source_info projects through `From<QueryReply>` so a SessionLocal Del
    /// reply surfaces the same identity a wire Del reply would.
    #[cfg(all(feature = "query-queryable", feature = "reply-source-info"))]
    #[test]
    fn from_query_reply_del_surfaces_source_info() {
        use crate::query::{QueryReply, ReplyBody};
        use crate::reply_sink::ReplyView;
        use crate::sample::SourceInfo;

        let si = SourceInfo::new(&[0x0C; 1], 2, 4);
        let qr = QueryReply::Reply {
            rid: 13,
            keyexpr_literal: "sensors/b".to_string(),
            body: ReplyBody::Del,
            encoding: None,
            timestamp: None,
            responder: None,
            attachment: None,
            source_info: Some(si.clone()),
        };
        let inbound: InboundReply = qr.into();
        assert_eq!(inbound.kind(), ReplyKind::Del);
        let got = inbound
            .source_info()
            .expect("loopback Del reply surfaces source_info");
        assert_eq!(got.zid_prefix(), &[0x0C][..]);
        assert_eq!((got.eid, got.sn), (2, 4));
    }

    /// A8c session-review — the aligner's HEADLINE reply shape: an
    /// EMPTY-payload Put carrying a LARGE (> the 32-byte no_std ExtZbuf bound)
    /// attachment — a serialized AlignmentReply metadata blob with no stored
    /// value. Proves the empty payload survives AND the over-32 attachment
    /// round-trips through the FULL wire decode (`dispatch_response`), not just
    /// the builder struct — the two gaps the review found untested.
    #[cfg(feature = "pubsub-attachment")]
    #[test]
    fn dispatch_response_surfaces_empty_payload_metadata_reply() {
        use crate::reply_sink::ReplyView;
        use crate::response_build::ResponseReplyBuilder;

        let big: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        assert!(big.len() > 32, "exceeds the no_std ExtZbuf bound");

        let mut reg = ReplyRegistry::new();
        let captured: Arc<Mutex<Vec<InboundReply>>> = Arc::new(Mutex::new(Vec::new()));
        let cb = captured.clone();
        reg.register(
            7,
            1,
            None,
            move |r| cb.lock().unwrap().push(InboundReply::from_view(r)),
            |_| {},
        );

        // Metadata-only reply: empty payload + the big attachment (Put arm —
        // the attachment is Put-only, so even a value-less reply is a Put).
        let resp = ResponseReplyBuilder::new(7, 0, Some("demo/a"), b"")
            .attachment(&big)
            .build()
            .unwrap();
        reg.dispatch_response(&resp, &HashMap::new());

        let snap = captured.lock().unwrap();
        assert_eq!(snap.len(), 1);
        let reply = &snap[0];
        assert_eq!(reply.kind(), ReplyKind::Put);
        match &reply.body {
            InboundReplyBody::Put {
                payload,
                attachment,
                encoding,
                source_info: _,
            } => {
                assert!(payload.is_empty(), "metadata-only reply: empty payload");
                assert_eq!(
                    attachment.as_deref(),
                    Some(big.as_slice()),
                    "the full >32B attachment survived the wire decode"
                );
                assert_eq!(*encoding, None);
            }
            other => panic!("expected Put, got {other:?}"),
        }
        assert_eq!(reply.attachment(), Some(big.as_slice()));
    }

    /// A8c session-review — `InboundReply::from_view` is lossless for a
    /// `BorrowedReply` source too, not only the wire `InboundReply`: a
    /// synthesised `BorrowedReply` carrying an attachment + put_encoding
    /// projects through `from_view` with both preserved (closes the latent gap
    /// where `BorrowedReply` could not represent the side-bands, so the
    /// elevated-to-SSOT `from_view` silently dropped them for that source).
    #[cfg(feature = "alloc")]
    #[test]
    fn from_view_is_lossless_for_a_borrowed_reply_attachment() {
        use crate::reply_sink::{BorrowedReply, ReplyView};
        let view = BorrowedReply {
            rid: 5,
            keyexpr: "a/b",
            kind: ReplyKind::Put,
            payload: b"v",
            err_encoding: None,
            attachment: Some(b"align"),
            put_encoding: Some((9, Some("text/plain"))),
        };
        let owned = InboundReply::from_view(&view);
        assert_eq!(owned.attachment(), Some(&b"align"[..]));
        assert_eq!(owned.put_encoding(), Some((9, Some("text/plain"))));
        match owned.body {
            InboundReplyBody::Put {
                attachment,
                encoding,
                ..
            } => {
                assert_eq!(attachment.as_deref(), Some(&b"align"[..]));
                assert_eq!(encoding, Some((9, Some("text/plain".to_string()))));
            }
            other => panic!("expected Put, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_response_fires_on_reply_for_del_body() {
        let mut reg = ReplyRegistry::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_cb = count.clone();
        reg.register(
            9,
            1,
            None,
            move |reply| {
                count_cb.fetch_add(1, Ordering::SeqCst);
                assert_eq!(reply.kind(), ReplyKind::Del, "expected Del kind");
            },
            |_| {},
        );

        let resp = response_reply_del(9, "clear/me");
        reg.dispatch_response(&resp, &HashMap::new());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dispatch_response_fires_on_reply_for_err_arm_with_encoding_tuple() {
        let mut reg = ReplyRegistry::new();
        let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
        let captured_cb = captured.clone();
        reg.register(
            5,
            1,
            None,
            move |reply| *captured_cb.lock().unwrap() = Some(InboundReply::from_view(reply)),
            |_| {},
        );

        let resp = response_err(5, "error/path", 4, Some("schema_v1"), b"oops");
        reg.dispatch_response(&resp, &HashMap::new());

        let captured = captured
            .lock()
            .unwrap()
            .clone()
            .expect("on_reply must fire");
        assert_eq!(captured.rid, 5);
        assert_eq!(captured.keyexpr_literal, "error/path");
        match &captured.body {
            InboundReplyBody::Err { encoding, payload } => {
                assert_eq!(*encoding, Some((4, Some("schema_v1".to_string()))));
                assert_eq!(payload, b"oops");
            }
            other => panic!("expected Err body, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_response_drops_on_unknown_rid() {
        let mut reg = ReplyRegistry::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_cb = count.clone();
        reg.register(
            7,
            1,
            None,
            move |_| {
                count_cb.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
        );

        let resp = response_reply_put(99, 0, Some("home/temp"), b"x");
        reg.dispatch_response(&resp, &HashMap::new());
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "unknown rid must not fire on_reply"
        );
        assert_eq!(reg.len(), 1, "pending entry preserved for unmatched rid");
    }

    #[test]
    fn dispatch_response_final_fires_and_auto_unregisters() {
        let mut reg = ReplyRegistry::new();
        let final_count = Arc::new(AtomicUsize::new(0));
        let final_count_cb = final_count.clone();
        reg.register(
            42,
            1,
            None,
            |_| {},
            move |rid| {
                assert_eq!(rid, 42, "on_final must receive the registered rid");
                final_count_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        reg.dispatch_response_final(&response_final_for(42));
        assert_eq!(final_count.load(Ordering::SeqCst), 1);
        assert!(
            reg.is_empty(),
            "Final must auto-unregister the pending entry"
        );

        // Subsequent Reply for the now-removed rid must drop silently.
        reg.dispatch_response(
            &response_reply_put(42, 0, Some("home/temp"), b"x"),
            &HashMap::new(),
        );
    }

    #[test]
    fn dispatch_response_final_with_unknown_rid_is_silent_noop() {
        let mut reg = ReplyRegistry::new();
        reg.register(
            42,
            1,
            None,
            |_| {},
            |_| panic!("on_final must not fire on unknown rid"),
        );

        reg.dispatch_response_final(&response_final_for(99));
        assert_eq!(
            reg.len(),
            1,
            "unknown-rid Final preserves all pending entries"
        );
    }

    #[test]
    fn dispatch_resolves_mapping_id_against_peer_table() {
        let mut reg = ReplyRegistry::new();
        let captured_literal: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_cb = captured_literal.clone();
        reg.register(
            1,
            1,
            None,
            move |reply| *captured_cb.lock().unwrap() = Some(reply.keyexpr().to_string()),
            |_| {},
        );

        let mut peer_table = HashMap::new();
        peer_table.insert(11u64, "sensors/temp".to_string());

        let resp = response_reply_put(1, 11, None, b"21.0");
        reg.dispatch_response(&resp, &peer_table);
        assert_eq!(
            captured_literal.lock().unwrap().clone(),
            Some("sensors/temp".to_string())
        );
    }

    #[test]
    fn dispatch_drops_unresolvable_mapping_id_silently() {
        let mut reg = ReplyRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        reg.register(
            1,
            1,
            None,
            move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
        );

        // mapping_id=99 not in peer table — dispatch must drop silently
        // before reaching the callback.
        let resp = response_reply_put(1, 99, None, b"x");
        reg.dispatch_response(&resp, &HashMap::new());
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn multiple_replies_per_pending_z_get_all_fire() {
        let mut reg = ReplyRegistry::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_cb = count.clone();
        reg.register(
            7,
            1,
            None,
            move |_| {
                count_cb.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
        );

        for payload in [
            b"sample-1".as_ref(),
            b"sample-2".as_ref(),
            b"sample-3".as_ref(),
        ] {
            reg.dispatch_response(
                &response_reply_put(7, 0, Some("series/data"), payload),
                &HashMap::new(),
            );
        }
        assert_eq!(count.load(Ordering::SeqCst), 3, "many Reply semantics");
        assert_eq!(
            reg.len(),
            1,
            "Reply chain does NOT auto-unregister; only Final does"
        );
    }

    #[test]
    fn duplicate_rid_registrations_both_fire_in_registration_order() {
        let mut reg = ReplyRegistry::new();
        let order: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let order_a = order.clone();
        reg.register(7, 1, None, move |_| order_a.lock().unwrap().push(1), |_| {});
        let order_b = order.clone();
        reg.register(7, 1, None, move |_| order_b.lock().unwrap().push(2), |_| {});

        reg.dispatch_response(
            &response_reply_put(7, 0, Some("home/temp"), b"21.0"),
            &HashMap::new(),
        );
        assert_eq!(
            *order.lock().unwrap(),
            vec![1, 2],
            "duplicate-rid pending entries fire in registration order"
        );

        // Final removes both entries.
        reg.dispatch_response_final(&response_final_for(7));
        assert!(reg.is_empty());
    }

    #[test]
    fn dispatch_messages_routes_response_and_response_final() {
        let mut reg = ReplyRegistry::new();
        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));
        let r = reply_count.clone();
        let f = final_count.clone();
        reg.register(
            42,
            1,
            None,
            move |_| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        );

        let messages = vec![
            NetworkMessage::Response(Box::new(response_reply_put(
                42,
                0,
                Some("home/temp"),
                b"21.0",
            ))),
            NetworkMessage::Response(Box::new(response_reply_put(
                42,
                0,
                Some("home/temp"),
                b"21.5",
            ))),
            NetworkMessage::ResponseFinal(response_final_for(42)),
        ];
        reg.dispatch_messages(&messages, &HashMap::new());

        assert_eq!(reply_count.load(Ordering::SeqCst), 2);
        assert_eq!(final_count.load(Ordering::SeqCst), 1);
        assert!(
            reg.is_empty(),
            "Final at end of batch removed the pending entry"
        );
    }

    #[test]
    fn dispatch_messages_ignores_unrelated_variants() {
        let mut reg = ReplyRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        reg.register(
            7,
            1,
            None,
            move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
        );

        // Unknown variant must NOT touch the registry.
        let messages = vec![NetworkMessage::Unknown {
            mid: 0x10,
            body: vec![],
        }];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        assert_eq!(
            reg.len(),
            1,
            "pending entry preserved across non-Response messages"
        );
    }

    // ── R239 Self-query loopback + expected_finals semantics ──

    #[test]
    fn deliver_local_reply_fires_on_reply_for_matching_rid() {
        // Loopback delivery routes the InboundReply through the same
        // pending entry as a wire-arrived Response. Single dispatch
        // path: deliver_local_reply -> fire_replies_for; the entry
        // stays in the table (only Final removes it).
        let mut reg = ReplyRegistry::new();
        let captured: Arc<Mutex<Vec<InboundReply>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_cb = captured.clone();
        reg.register(
            7,
            1,
            None,
            move |reply| {
                captured_cb
                    .lock()
                    .unwrap()
                    .push(InboundReply::from_view(reply))
            },
            |_| {},
        );

        let inbound = InboundReply {
            rid: 7,
            keyexpr_literal: "home/temp".to_string(),
            body: InboundReplyBody::Put {
                payload: b"21.0".to_vec(),
                attachment: None,
                encoding: None,
                source_info: None,
            },
        };
        reg.deliver_local_reply(&inbound);

        let snapshot = captured.lock().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0], inbound);
        assert_eq!(reg.len(), 1, "loopback reply does NOT auto-unregister");
    }

    #[test]
    fn deliver_local_reply_drops_on_unknown_rid() {
        let mut reg = ReplyRegistry::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_cb = count.clone();
        reg.register(
            7,
            1,
            None,
            move |_| {
                count_cb.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
        );

        let inbound = InboundReply {
            rid: 99,
            keyexpr_literal: "home/temp".to_string(),
            body: InboundReplyBody::Del { source_info: None },
        };
        reg.deliver_local_reply(&inbound);
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn deliver_local_final_decrements_and_fires_when_expected_finals_was_one() {
        // expected_finals = 1 means one Final closes the chain. After
        // deliver_local_final the entry must be removed and on_final
        // must have fired exactly once.
        let mut reg = ReplyRegistry::new();
        let final_count = Arc::new(AtomicUsize::new(0));
        let final_count_cb = final_count.clone();
        reg.register(
            1,
            1,
            None,
            |_| {},
            move |rid| {
                assert_eq!(rid, 1);
                final_count_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        reg.deliver_local_final(1);
        assert_eq!(final_count.load(Ordering::SeqCst), 1);
        assert!(
            reg.is_empty(),
            "expected_finals=1 closes on the loopback final"
        );
    }

    #[test]
    fn deliver_local_final_with_expected_finals_two_keeps_entry_until_second_final() {
        // expected_finals = 2 (Locality::Any path) — one loopback
        // final + one wire final must BOTH arrive before on_final
        // fires and the entry drops. Mirrors zenoh-pico's
        // _z_pending_query_t._remaining_finals counter semantic.
        let mut reg = ReplyRegistry::new();
        let final_count = Arc::new(AtomicUsize::new(0));
        let final_count_cb = final_count.clone();
        reg.register(
            5,
            2,
            None,
            |_| {},
            move |_| {
                final_count_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        reg.deliver_local_final(5);
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            0,
            "first Final must NOT fire on_final when expected_finals = 2"
        );
        assert_eq!(reg.len(), 1, "entry preserved after first of two Finals");

        reg.dispatch_response_final(&response_final_for(5));
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            1,
            "second Final closes the chain"
        );
        assert!(reg.is_empty(), "entry dropped after the closing Final");
    }

    #[test]
    fn deliver_local_final_on_unknown_rid_is_silent_noop() {
        let mut reg = ReplyRegistry::new();
        reg.register(
            7,
            1,
            None,
            |_| {},
            |_| panic!("on_final must not fire on unknown rid"),
        );

        reg.deliver_local_final(99);
        assert_eq!(
            reg.len(),
            1,
            "unknown-rid loopback final preserves the entry"
        );
    }

    #[test]
    fn dispatch_response_final_decrements_with_expected_finals_two() {
        // Symmetric to deliver_local_final_with_expected_finals_two_*:
        // wire Final decrements but does not fire when a second
        // Final is still expected; the loopback final closes it.
        let mut reg = ReplyRegistry::new();
        let final_count = Arc::new(AtomicUsize::new(0));
        let final_count_cb = final_count.clone();
        reg.register(
            9,
            2,
            None,
            |_| {},
            move |_| {
                final_count_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        reg.dispatch_response_final(&response_final_for(9));
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            0,
            "first Final must NOT fire"
        );
        assert_eq!(reg.len(), 1, "entry preserved after first Final");

        reg.deliver_local_final(9);
        assert_eq!(final_count.load(Ordering::SeqCst), 1, "second Final closes");
        assert!(reg.is_empty());
    }

    #[cfg(feature = "query-queryable")]
    #[test]
    fn from_query_reply_put_projects_to_inbound_put() {
        use crate::query::{QueryReply, ReplyBody};
        let qr = QueryReply::Reply {
            rid: 11,
            keyexpr_literal: "sensors/a".to_string(),
            body: ReplyBody::Put(b"value".to_vec()),
            encoding: None,
            timestamp: None,
            responder: None,
            attachment: None,
            source_info: None,
        };
        let inbound: InboundReply = qr.into();
        assert_eq!(inbound.rid, 11);
        assert_eq!(inbound.keyexpr_literal, "sensors/a");
        match inbound.body {
            InboundReplyBody::Put { payload, .. } => assert_eq!(payload, b"value"),
            other => panic!("expected Put, got {other:?}"),
        }
    }

    /// A8b — the loopback receive twin: a `QueryReply` staged with an
    /// attachment + encoding (the A8a emit) projects through
    /// `From<QueryReply>` so a SessionLocal reply surfaces the same metadata
    /// a wire (Remote) reply would. The side-bands are gated on the same
    /// `pubsub-attachment` / `pubsub-encoding` as the wire decode, so the two
    /// paths carry the same CONTENT when both are present.
    #[cfg(all(
        feature = "query-queryable",
        feature = "pubsub-attachment",
        feature = "pubsub-encoding"
    ))]
    #[test]
    fn from_query_reply_put_surfaces_attachment_and_encoding() {
        use crate::query::{QueryReply, ReplyBody};
        use crate::sample::EncodingHint;
        let qr = QueryReply::Reply {
            rid: 11,
            keyexpr_literal: "sensors/a".to_string(),
            body: ReplyBody::Put(b"value".to_vec()),
            encoding: Some(EncodingHint {
                packed_id: 7,
                schema: None,
            }),
            timestamp: None,
            responder: None,
            attachment: Some(b"align".to_vec()),
            source_info: None,
        };
        let inbound: InboundReply = qr.into();
        match inbound.body {
            InboundReplyBody::Put {
                payload,
                attachment,
                encoding,
                source_info: _,
            } => {
                assert_eq!(payload, b"value");
                assert_eq!(attachment.as_deref(), Some(&b"align"[..]));
                assert_eq!(encoding, Some((7, None)));
            }
            other => panic!("expected Put, got {other:?}"),
        }
    }

    #[cfg(feature = "query-queryable")]
    #[test]
    fn from_query_reply_del_projects_to_inbound_del() {
        use crate::query::{QueryReply, ReplyBody};
        let qr = QueryReply::Reply {
            rid: 12,
            keyexpr_literal: "sensors/b".to_string(),
            body: ReplyBody::Del,
            encoding: None,
            timestamp: None,
            responder: Some((vec![0xaa, 0xbb], 5)),
            attachment: None,
            source_info: None,
        };
        let inbound: InboundReply = qr.into();
        assert_eq!(inbound.rid, 12);
        assert_eq!(inbound.keyexpr_literal, "sensors/b");
        assert_eq!(inbound.body, InboundReplyBody::Del { source_info: None });
        // responder is intentionally dropped in projection (loopback
        // mirrors the wire branch's information loss exactly — the
        // consumer InboundReply surface does not expose responder).
    }

    #[cfg(feature = "query-queryable")]
    #[test]
    fn from_query_reply_err_projects_to_inbound_err() {
        use crate::query::QueryReply;
        let qr = QueryReply::Err {
            rid: 13,
            keyexpr_literal: "sensors/c".to_string(),
            encoding: Some((4, Some("schema_v1".to_string()))),
            payload: b"err-payload".to_vec(),
            responder: None,
        };
        let inbound: InboundReply = qr.into();
        assert_eq!(inbound.rid, 13);
        assert_eq!(inbound.keyexpr_literal, "sensors/c");
        match inbound.body {
            InboundReplyBody::Err { encoding, payload } => {
                assert_eq!(encoding, Some((4, Some("schema_v1".to_string()))));
                assert_eq!(payload, b"err-payload");
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    // ── R261 sweep_timed_out unit tests ──

    #[test]
    fn sweep_timed_out_drops_expired_pending_and_fires_on_final() {
        let mut reg = ReplyRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        // deadline = 1000ms; on_final asserts rid + counts firing.
        reg.register(
            7,
            1,
            Some(1000),
            |_| {},
            move |rid| {
                assert_eq!(rid, 7, "on_final must carry the registered rid");
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        // now_ms = 1500 > deadline 1000 → expired.
        let swept = reg.sweep_timed_out(1500);
        assert_eq!(swept, 1, "one expired entry must be swept");
        assert_eq!(fired.load(Ordering::SeqCst), 1, "on_final fires once");
        assert!(reg.is_empty(), "expired entry must be removed from table");
    }

    #[test]
    fn sweep_timed_out_keeps_unexpired_pending_and_fires_nothing() {
        let mut reg = ReplyRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        reg.register(
            9,
            1,
            Some(2000),
            |_| {},
            move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        // now_ms = 500 < deadline 2000 → not expired.
        let swept = reg.sweep_timed_out(500);
        assert_eq!(swept, 0, "no entry must be swept");
        assert_eq!(fired.load(Ordering::SeqCst), 0, "on_final must not fire");
        assert_eq!(reg.len(), 1, "unexpired entry must remain pending");
    }

    #[test]
    fn sweep_timed_out_skips_none_deadline_entries() {
        // deadline_ms = None ("never expire") entries must survive any
        // sweep_timed_out call, regardless of now_ms. This pins the
        // contract for the QueryOptions::timeout_ms == 0 path that the
        // R261 Session::query production callers exercise.
        let mut reg = ReplyRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        reg.register(
            13,
            1,
            None,
            |_| {},
            move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        let swept = reg.sweep_timed_out(u64::MAX);
        assert_eq!(swept, 0, "None-deadline entry must not be swept");
        assert_eq!(fired.load(Ordering::SeqCst), 0, "on_final must not fire");
        assert_eq!(reg.len(), 1, "None-deadline entry must remain pending");
    }

    #[test]
    fn sweep_timed_out_partitions_mixed_batch_correctly() {
        // Three entries: one expired, one unexpired, one None-deadline.
        // After sweep at now_ms = 1500: only the expired entry is
        // dropped + fires on_final. The other two stay.
        let mut reg = ReplyRegistry::new();
        let fired_a = Arc::new(AtomicUsize::new(0));
        let fired_b = Arc::new(AtomicUsize::new(0));
        let fired_c = Arc::new(AtomicUsize::new(0));
        let fa = fired_a.clone();
        let fb = fired_b.clone();
        let fc = fired_c.clone();
        reg.register(
            1,
            1,
            Some(1000),
            |_| {},
            move |_| {
                fa.fetch_add(1, Ordering::SeqCst);
            },
        );
        reg.register(
            2,
            1,
            Some(2000),
            |_| {},
            move |_| {
                fb.fetch_add(1, Ordering::SeqCst);
            },
        );
        reg.register(
            3,
            1,
            None,
            |_| {},
            move |_| {
                fc.fetch_add(1, Ordering::SeqCst);
            },
        );

        let swept = reg.sweep_timed_out(1500);
        assert_eq!(swept, 1, "only entry 1 (deadline=1000) must be swept");
        assert_eq!(fired_a.load(Ordering::SeqCst), 1, "rid=1 on_final fires");
        assert_eq!(
            fired_b.load(Ordering::SeqCst),
            0,
            "rid=2 on_final does NOT fire"
        );
        assert_eq!(
            fired_c.load(Ordering::SeqCst),
            0,
            "rid=3 on_final does NOT fire"
        );
        assert_eq!(reg.len(), 2, "rid=2 + rid=3 remain pending");
    }

    #[test]
    fn sweep_timed_out_boundary_now_ms_equals_deadline_is_expired() {
        // The contract uses `deadline <= now_ms` (inclusive). At the
        // exact deadline tick the entry is considered expired so a
        // sweep call running at the same ms as the deadline does not
        // miss the entry on a one-tick granularity.
        let mut reg = ReplyRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        reg.register(
            5,
            1,
            Some(1000),
            |_| {},
            move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        let swept = reg.sweep_timed_out(1000);
        assert_eq!(swept, 1, "entry at deadline==now must be swept (inclusive)");
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert!(reg.is_empty());
    }

    #[test]
    fn sweep_timed_out_is_idempotent_second_call_returns_zero() {
        // After the first sweep removes the expired entry, a second
        // sweep at the same (or any later) now_ms must return 0 and
        // leave the registry untouched. No double-fire of on_final.
        let mut reg = ReplyRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        reg.register(
            7,
            1,
            Some(1000),
            |_| {},
            move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        assert_eq!(
            reg.sweep_timed_out(1500),
            1,
            "first sweep finds the expired entry"
        );
        assert_eq!(reg.sweep_timed_out(1500), 0, "second sweep is a no-op");
        assert_eq!(
            reg.sweep_timed_out(u64::MAX),
            0,
            "later sweep is also a no-op"
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "on_final fires exactly once total"
        );
    }

    #[test]
    fn sweep_timed_out_drops_duplicate_rid_entries_independently() {
        // Duplicate-rid registrations with the same deadline_ms must
        // both be swept on a single sweep call. on_final fires once
        // per entry (registration order). Mirrors the duplicate-rid
        // contract on the wire/loopback Final path.
        let mut reg = ReplyRegistry::new();
        let order: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let order_a = order.clone();
        let order_b = order.clone();
        reg.register(
            7,
            1,
            Some(1000),
            |_| {},
            move |rid| order_a.lock().unwrap().push(rid),
        );
        reg.register(
            7,
            1,
            Some(1000),
            |_| {},
            move |rid| order_b.lock().unwrap().push(rid),
        );

        let swept = reg.sweep_timed_out(1500);
        assert_eq!(swept, 2, "both duplicate-rid entries must be swept");
        assert_eq!(
            *order.lock().unwrap(),
            vec![7, 7],
            "on_final fires once per entry (registration order preserved)",
        );
        assert!(reg.is_empty());
    }

    /// R311gb (Track 2) — direct exercise of the no-heap fire entry
    /// `dispatch_borrowed`: delivers a borrowed `ReplyView` to the
    /// pending entry whose rid matches (and filters non-matching rids),
    /// the MCU on_reply path that does not materialize an owned
    /// `InboundReply`.
    #[test]
    fn dispatch_borrowed_delivers_borrowed_reply_to_matching_pending() {
        use crate::reply_sink::BorrowedReply;
        let mut reg = ReplyRegistry::new();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        reg.register(
            42,
            1,
            None,
            move |v: &dyn ReplyView| {
                assert_eq!(v.rid(), 42);
                assert_eq!(v.payload(), b"v");
                h.fetch_add(1, Ordering::SeqCst);
            },
            |_rid| {},
        );
        let fired = reg.dispatch_borrowed(&BorrowedReply {
            rid: 42,
            keyexpr: "q/k",
            kind: ReplyKind::Put,
            payload: b"v",
            err_encoding: None,
            attachment: None,
            put_encoding: None,
        });
        assert_eq!(fired, 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let none = reg.dispatch_borrowed(&BorrowedReply {
            rid: 99,
            keyexpr: "q/k",
            kind: ReplyKind::Put,
            payload: b"",
            err_encoding: None,
            attachment: None,
            put_encoding: None,
        });
        assert_eq!(none, 0, "non-matching rid does not fire");
    }
}

// ── decode-side feature-isolation NEG (reply-body consumer OFF) ──
//
// The main `mod tests` above gates on
// `any(pubsub-put, query-reply)` AND `any(pubsub-delete, query-reply)`
// (R311fn — the reply-DECODE-capability predicate), so it is entirely
// cfg'd out under a subset that turns `codec-response` ON but leaves
// every reply-body consumer marker OFF — the `queryable-only` plane
// (`query-queryable` pulls in `codec-response` for the reply *emit*
// side, while the getter consumer features `query-reply` / `pubsub-put`
// / `pubsub-delete` stay OFF). There the inbound reply-body arms of
// `dispatch_response` (Put = `cfg(any(pubsub-put, query-reply))`,
// Del = `cfg(any(pubsub-delete, query-reply))`) are both cfg'd out, so
// an inbound `Response(Reply)` of either body falls through to the
// `_ => return` silent drop (the query-side mirror of the pubsub
// `dispatch` Push arms guarded by `mod decode_isolation_tests` in
// `pubsub.rs`). Layer C1h proves this subset BUILDS; Layer F proves the
// off consumer SHRINKS the binary — only these pin the receive
// BEHAVIOUR: an inbound `Response(Reply)` Put / Del fires NO pending
// `on_reply`, while a `Response(Err)` (whose arm is unconditional)
// still fires through the same entry, proving the drop is body-variant-
// selective and the pending table itself is live (not a dead registry).
// The module gate selects exactly the codec-response-on / reply-
// consumer-off builds; the run-ci C1h queryable-only profile is
// promoted to a `cargo test` so these RUN, which no other lane does
// (C1c-g each pin a reply-consumer marker ON, cfg'ing the module out).
#[cfg(test)]
#[cfg(all(
    feature = "alloc",
    feature = "codec-response",
    not(feature = "pubsub-put"),
    not(feature = "pubsub-delete"),
    not(feature = "query-reply"),
))]
mod decode_isolation_tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wz_codecs::encoding::Encoding;
    use wz_codecs::err::Err as ErrBody;
    use wz_codecs::msg_del::MsgDel;
    use wz_codecs::msg_put::MsgPut;
    use wz_codecs::reply::{Reply, ReplyVariant};
    use wz_codecs::response::{Response, ResponseVariant};
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;

    /// A Put-bodied `Response(Reply)` for `suffix` (literal local
    /// wireexpr, id=0 → suffix resolves verbatim, no peer table).
    /// Constructible regardless of `pubsub-put` / `query-reply` — those
    /// features gate the dispatch consumer arm, not the `codec-response`
    /// wire variant.
    fn response_reply_put(rid: u64, suffix: &str, payload: &[u8]) -> ResponseOwned {
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix),
            }),
        };
        let reply = Reply {
            body: ReplyVariant::CodecZenohMsgPut(MsgPut {
                payload_len: payload.len() as u64,
                payload,
                ..MsgPut::default()
            }),
            ..Reply::default()
        };
        Response {
            request_id: rid,
            keyexpr,
            body: ResponseVariant::CodecZenohReply(reply),
            ..Response::default()
        }
        .try_into_owned()
        .unwrap()
    }

    /// A Del-bodied `Response(Reply)` for `suffix`. Constructible
    /// regardless of `pubsub-delete` / `query-reply` (same reason as
    /// [`response_reply_put`]).
    fn response_reply_del(rid: u64, suffix: &str) -> ResponseOwned {
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix),
            }),
        };
        let reply = Reply {
            body: ReplyVariant::CodecZenohMsgDel(MsgDel::default()),
            ..Reply::default()
        };
        Response {
            request_id: rid,
            keyexpr,
            body: ResponseVariant::CodecZenohReply(reply),
            ..Response::default()
        }
        .try_into_owned()
        .unwrap()
    }

    /// An Err-bodied `Response` for `suffix`. The Err arm of
    /// `dispatch_response` is unconditional, so this is the live
    /// contrast that proves the pending entry is not dead.
    fn response_err(rid: u64, suffix: &str, payload: &[u8]) -> ResponseOwned {
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix),
            }),
        };
        let err_body = ErrBody {
            encoding: Some(Encoding {
                packed_id: 0,
                schema_len: None,
                schema: None,
            }),
            payload_len: payload.len() as u64,
            payload,
            ..ErrBody::default()
        };
        Response {
            request_id: rid,
            keyexpr,
            body: ResponseVariant::CodecZenohErr(err_body),
            ..Response::default()
        }
        .try_into_owned()
        .unwrap()
    }

    #[test]
    fn inbound_reply_put_body_is_dropped_when_reply_consumer_off() {
        let mut reg = ReplyRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        reg.register(
            42,
            1,
            None,
            move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
        );

        // Put body → `pubsub-put` / `query-reply` arm cfg'd out →
        // `_ => return` silent drop.
        reg.dispatch_response(
            &response_reply_put(42, "home/temp", b"21.0"),
            &HashMap::new(),
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "inbound Reply(Put) must not fire on_reply when the reply consumer is off"
        );

        // Err body still fires through the same pending entry — proves
        // the drop is body-variant-selective, not a dead registry.
        reg.dispatch_response(&response_err(42, "home/temp", b"oops"), &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "inbound Reply(Err) still fires (Err arm is unconditional)"
        );
    }

    #[test]
    fn inbound_reply_del_body_is_dropped_when_reply_consumer_off() {
        let mut reg = ReplyRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        reg.register(
            9,
            1,
            None,
            move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
        );

        // Del body → `pubsub-delete` / `query-reply` arm cfg'd out →
        // `_ => return` silent drop.
        reg.dispatch_response(&response_reply_del(9, "clear/me"), &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "inbound Reply(Del) must not fire on_reply when the reply consumer is off"
        );

        // Err body still fires — variant-selective drop, live entry.
        reg.dispatch_response(&response_err(9, "clear/me", b"oops"), &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "inbound Reply(Err) still fires (Err arm is unconditional)"
        );
    }
}

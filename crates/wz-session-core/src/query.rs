// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Application-layer queryable registry — routes decoded
//! `NetworkMessage::Request(Query)` records to user-registered
//! on_query callbacks filtered by keyexpr literal.
//!
//! Q-side mirror of [`SubscriberRegistry`](crate::pubsub::SubscriberRegistry):
//!
//! | Inbound message            | Routes via                |
//! |----------------------------|---------------------------|
//! | `NetworkMessage::Push`     | [`SubscriberRegistry`]    |
//! | `NetworkMessage::Request`  | [`QueryableRegistry`]     |
//!
//! Both follow the same keyexpr-wildcard matching contract
//! (`*` single chunk, `**` zero-or-more chunks; matcher reused from
//! [`pubsub::keyexpr_pattern_matches`](crate::pubsub::keyexpr_pattern_matches))
//! and the same peer-alias resolution rule (mapping_id != 0 → look up
//! a literal in the peer keyexpr table populated by inbound
//! `Declare(DeclKexpr)`; mapping_id == 0 → use suffix verbatim).
//!
//! ## Scope (R121j-5b)
//!
//! - Request(Query) arm only. The other three `RequestVariant` arms
//!   (`MsgPut`, `MsgDel`, `Default`) are not application-visible —
//!   they fall through `dispatch_request` as no-ops, matching
//!   zenoh-pico's `_z_handle_request` which dispatches only Query
//!   bodies through the queryable callback path.
//! - Callbacks accumulate Replies / Errs via a [`QueryResponder`]
//!   into a caller-owned `Vec<QueryReply>`. Actual outbound frame
//!   encode + send is the caller's concern (R121j-5c wires the
//!   accumulated Vec through [`encode_frame_with_response`] +
//!   [`encode_frame_with_response_final`](
//!   crate::session_glue::encode_frame_with_response_final) so a
//!   queryable response round-trip closes on the wire).
//! - Peer-alias resolution is delegated to a `&HashMap<u64, String>`
//!   parameter on `dispatch_request` rather than owning a private
//!   copy. The integration site (R121j-5c) holds the
//!   [`SubscriberRegistry`]'s table and lends it on every dispatch,
//!   so DeclKexpr / UndeclKexpr absorbed by the subscriber path
//!   automatically informs queryable resolution too — no dual-write
//!   bookkeeping, no Arc-shared state.
//!
//! ## Why a separate Responder rather than direct frame emit
//!
//! - **Testability**: callbacks run without a tokio runtime or a
//!   `LinkDriver` — the Responder is just a `&mut Vec<QueryReply>`
//!   borrow; tests inspect the accumulated replies directly.
//! - **MCU runtime compatibility**: `FnMut` callbacks, no `async fn`,
//!   no `Future` in the trait surface; the dispatch path stays
//!   suitable for the `(c11, bare_metal)` runtime crate target.
//! - **Separation of concerns**: "what to reply" lives in user code
//!   ([`QueryResponder::send_reply`] / `_del` / `_err`); "how to
//!   reply" (frame envelope, sn assignment, link write) lives in
//!   the runtime (R121j-5c).
//!
//! ## QueryResponder lifetime and ownership
//!
//! [`QueryResponder`] is a short-lived borrow constructed by
//! `dispatch_request` for each matched queryable. It holds the
//! request id (echoed back into Response.request_id so the
//! requester correlates the reply) and the resolved keyexpr literal
//! (echoed as the Reply's keyexpr with `mapping_id == 0` per zenoh's
//! literal-form composition). The borrow is dropped before
//! `dispatch_request` advances to the next queryable so user
//! closures cannot hold the Responder past the callback boundary.
//!
//! ## Threading
//!
//! `!Sync` by construction (mirror of [`SubscriberRegistry`]).
//! Callers that need cross-task sharing wrap in `Arc<Mutex<…>>` or
//! `Arc<tokio::sync::Mutex<…>>`.

// no_std module-body alloc prelude: the core prelude lacks String / Vec
// / ToString, so the alloc-provided forms are imported explicitly
// (mirrors the wz-session-core::pubsub convention). The production
// artifact stays `#![no_std]`; alloc is the gate for the String keyexpr
// / Vec<QueryReply> store in this module.
//
// R311gb-3b — `Box` is no longer imported at module level: the queryable
// callback store migrated from `Box<dyn FnMut>` (`QueryableCallback`) to
// the generic `Queryable<C: QuerySink>` sink seam, so production code no
// longer heap-boxes a handler here (`BoxedQuerySink` owns that on the AP
// convenience path, in `query_sink`). The only remaining `Box::new(..)`
// uses are the test module's `NetworkMessage::Request` fixtures, so the
// import lives inside `mod tests` (under that module's full-query-feature
// gate) rather than here.
// R311gb (Track 2) — `String` / `Vec` back the `alloc`-gated reply
// accumulator (`QueryReply` / `QueryResponder`); the no-alloc control
// plane stores each pattern in a `BoundedString` and the table in a
// `BoundedVec`, so the owned-collection imports are `alloc`-gated.
// `ToString` (`.to_string()`) is reached only from the
// `codec-request` + `alloc` dispatch / responder path.
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(all(feature = "codec-request", feature = "alloc"))]
use alloc::string::ToString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// R311gb (Track 2) — bounded backing + the capacity SSOT for the
// no-alloc control plane (queryable table + per-row keyexpr pattern).
use crate::bounded::{BoundedString, BoundedVec};
use crate::caps;
use crate::keyexpr_match::MAX_KEYEXPR_CHUNKS;
use crate::registry_error::RegisterError;

// R311gb (Track 2) — HashMap (peer-keyexpr table) + the driver-loop /
// network-message envelope types + the owned codec mirrors are consumed
// only by the `all(codec-request, alloc)` wire-dispatch impl (owned
// records staged into the `alloc` reply accumulator), so their imports
// carry that exact gate (deny-warnings clean in a `codec-request`-OFF or
// no-`alloc` subset).
#[cfg(all(feature = "codec-request", feature = "alloc"))]
use hashbrown::HashMap;

// R311dx — SCE owned-view absorb: decoded inbound Query / Request bodies
// are held / dispatched as the lifetime-free `*Owned` mirrors; the reply
// builders return `ResponseOwned`. The borrowed views are pulled in
// test-locally for fixture construction (`..Foo::default().into_owned()`).
//
// `wz_codecs::{query, request}` live in the `codec-request` codec_group
// (wz-codecs/src/lib.rs); R311gb (Track 2) un-gated the control plane, so
// every import + method that consumes a `QueryOwned` / `RequestOwned`
// into the `alloc` accumulator gates on `all(codec-request, alloc)`. The
// no-alloc control plane (table + register + matching +
// `dispatch_borrowed`) carries none of these — the same wire-data-helper
// split as `SubscriberRegistry::dispatch_push` (R311g1 signature
// stability), now also alloc-aware.
#[cfg(all(feature = "codec-request", feature = "alloc"))]
use wz_codecs::query::QueryOwned;
#[cfg(all(feature = "codec-request", feature = "alloc"))]
use wz_codecs::request::{RequestOwned, RequestOwnedVariant};
// R311r — `Response` + the `ResponseReplyBuilder` / `ResponseErrBuilder`
// pair (now in wz-session-core::response_build) back `into_response`,
// gated on `all(codec-response, alloc)` (the `QueryReply` owned record is
// `alloc`-gated). The dispatch / loopback / registration paths only stage
// entries into `Vec<QueryReply>` and do not need codec-response.
#[cfg(all(feature = "codec-request", feature = "alloc"))]
use crate::wireexpr_resolve::resolve_wireexpr;
#[cfg(all(feature = "codec-response", feature = "alloc"))]
use wz_codecs::response::ResponseOwned;

#[cfg(all(feature = "codec-response-final", feature = "alloc"))]
use wz_codecs::response_final::{ResponseFinal, ResponseFinalOwned};

#[cfg(all(feature = "codec-request", feature = "alloc"))]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
#[cfg(all(feature = "codec-request", feature = "alloc"))]
use crate::network_message::NetworkMessage;
// R311gb (Track 2) — the keyexpr matcher backs the un-gated
// control-plane `Queryable::matches`, so its import is unconditional
// (the matcher lives in `keyexpr_match`, no-alloc since R311fz).
use crate::pubsub::keyexpr_pattern_matches;
// R311gb (Track 2) — the seam traits (`QuerySink` bounds the table,
// `QueryView` / `ReplyOut` are the no-heap `dispatch_borrowed` fire
// contracts) are unconditional (no_std-safe in `query_sink`).
// `BorrowedQuery` is built only by the `alloc` wire fire path, and
// `BoxedQuerySink` is the AP closure adapter, so those two carry the
// narrower gates.
#[cfg(all(feature = "codec-request", feature = "alloc"))]
use crate::query_sink::BorrowedQuery;
#[cfg(feature = "alloc")]
use crate::query_sink::BoxedQuerySink;
use crate::query_sink::{QuerySink, QueryView, ReplyOut};
#[cfg(all(feature = "codec-response", feature = "alloc"))]
use crate::response_build::{ResponseErrBuilder, ResponseReplyBuilder};

/// R311v — extract the attachment payload view from an inbound
/// [`Query`]'s extensions chain.
///
/// Wire shape (mirrors zenoh-pico
/// `vendor/zenoh-pico/src/protocol/codec/message.c:447` /
/// `_z_query_encode_ext`): the attachment ext header is
/// `_Z_MSG_EXT_ENC_ZBUF | 0x05`, i.e. lower-4-bit ext_id `0x05` with
/// encoding `ExtEntryVariant::CodecZenohExtZbuf` (bits 5..6 = `0b10`).
/// The mandatory-bit (`_Z_MSG_EXT_FLAG_M` = `0x10`) is NOT set for
/// query-attachment — the peer drops it silently when unknown rather
/// than rejecting the frame (`_z_query_decode_extensions` falls into
/// the `default` arm and proceeds without `_z_msg_ext_unknown_error`
/// only when the M bit is clear). Returns the first matching ext's
/// body slice; `None` when the chain is absent or carries no
/// attachment ext.
// R311cj — query-attachment gates the inbound Query.attachment ext
// extraction. cfg-off: callback always observes attachment=None.
// Signature stable (returns Option), behavior change is the early
// short-circuit at the function entry.
#[cfg(all(feature = "codec-request", feature = "alloc"))]
fn extract_query_attachment(query: &QueryOwned) -> Option<&[u8]> {
    #[cfg(not(feature = "query-attachment"))]
    {
        let _ = query;
        None
    }
    #[cfg(feature = "query-attachment")]
    {
        let exts = query.extensions.as_deref()?;
        crate::attachment::decode_attachment_ext(exts, crate::attachment::ATTACHMENT_EXT_ID_QUERY)
    }
}

/// Stable handle returned by [`QueryableRegistry::register`] so the
/// caller can later unregister the queryable without re-keying on
/// the keyexpr pattern (duplicate-pattern queryables are explicitly
/// allowed: e.g. a metrics responder and a domain responder on the
/// same keyexpr).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryableId(u64);

impl QueryableId {
    /// The numeric id behind the handle. Exposed for diagnostic
    /// surfaces; callers should not depend on the exact value across
    /// runs since the registry assigns ids monotonically from the
    /// session-local counter.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

// R311gb (Track 2) — the queryable table is the no-alloc control plane
// (un-gated from `codec-request` / `alloc`): the table + per-row
// pattern + matching + the borrowed no-heap fire (`dispatch_borrowed`)
// compile on the MCU profile. Only the wire-dispatch entry points that
// consume an owned `wz_codecs::query::Query` (`dispatch_request` /
// `local_query`) and the owned reply accumulator (`QueryReply` /
// `QueryResponder`) stay `all(codec-request, alloc)` / `alloc`-gated.
// This brings the queryable side in line with `SubscriberRegistry`,
// whose control plane is likewise always-compiled.
struct Queryable<C: QuerySink> {
    id: QueryableId,
    /// R311gb (Track 2) — the canonical keyexpr pattern, stored as one
    /// [`BoundedString`] (no-alloc backing on MCU). Matching splits it
    /// on `/` at dispatch time into a stack chunk view rather than
    /// keeping a pre-split owned `Vec<String>`. Empty literal chunks
    /// are preserved (`a//b` keeps its empty chunk); `*` (single-chunk
    /// wildcard), `**` (zero-or-more-chunk wildcard), and `$*` intra-
    /// chunk substring wildcards (R220) match via the shared
    /// [`keyexpr_pattern_matches`] helper.
    pattern: BoundedString<{ caps::MAX_KEYEXPR_BYTES }>,
    /// R223 — locality filter applied before the callback fires.
    /// Identical semantics to
    /// [`crate::pubsub::SubscriberRegistry`] —
    /// `dispatch_request` consults `allows_remote()` since every
    /// Request reaching it has been parsed off the wire.
    allowed_origin: crate::locality::Locality,
    /// R311gb-3b — the query-dispatch sink (DIP seam). `C = BoxedQuerySink`
    /// on AP (heap closure), a consumer-supplied closed `enum` on MCU.
    sink: C,
}

impl<C: QuerySink> Queryable<C> {
    /// R311gb (Track 2) — the shared match SSOT for both the wire fire
    /// path ([`QueryableRegistry::fire_matching_queryables`]) and the
    /// no-heap borrowed fire ([`QueryableRegistry::dispatch_borrowed`]):
    /// does this queryable's pattern match `keyexpr` under the
    /// `is_remote` locality predicate? Splits the bounded pattern into a
    /// stack chunk view (no heap); a pattern whose canonical form
    /// exceeds [`MAX_KEYEXPR_CHUNKS`] chunks (cannot happen for a
    /// pattern admitted at register time) is treated as a non-match
    /// rather than a truncated match.
    fn matches(&self, keyexpr: &str, is_remote: bool) -> bool {
        let allowed = if is_remote {
            self.allowed_origin.allows_remote()
        } else {
            self.allowed_origin.allows_local()
        };
        if !allowed {
            return false;
        }
        let mut chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
        for c in self.pattern.split('/') {
            if chunks.push(c).is_err() {
                return false;
            }
        }
        keyexpr_pattern_matches(&chunks, keyexpr)
    }
}

/// Body arm for a `QueryReply::Reply` — mirrors zenoh-pico's
/// `_z_reply` inner `_z_push_body_t` dispatch on `_z_is_put` (Put
/// path = data Reply; Del path = delete-keyexpr Reply).
// R311gb (Track 2) — owned reply body (`Vec<u8>` payload), `alloc`-gated.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyBody {
    /// Standard data reply. Payload bytes are the application
    /// payload the queryable wants to return; encoded as the inner
    /// `MsgPut` body of the Reply.
    Put(Vec<u8>),
    /// Delete-keyexpr reply. No payload bytes (the inner `MsgDel`
    /// body carries only a header + optional timestamp + ext chain).
    /// Used by queryables whose semantic is "the value at this
    /// keyexpr no longer exists / has been cleared".
    Del,
}

/// One outbound Reply or Err record produced by a queryable callback.
/// The registry accumulates these into a caller-owned `Vec` so the
/// runtime (R121j-5c) can wire each entry through the corresponding
/// [`ResponseReplyBuilder`] / [`ResponseErrBuilder`] + the
/// `encode_frame_with_response` envelope helper.
///
/// The optional `responder` tuple — set via
/// [`QueryResponder::with_responder`] before any send_*/send_err call —
/// propagates onto the wire as the Response-envelope-level responder
/// extension (zenoh-pico ext_id 0x03 ZBUF; see
/// [`crate::session_glue::ResponseReplyBuilder::responder`]). Same shape
/// for Reply and Err paths since the ext lives on the outer Response,
/// not the inner Reply / Err body.
// R311gb (Track 2) — owned reply accumulator record (`String` keyexpr +
// `Vec<u8>` payload + `responder` bytes), `alloc`-gated; one specific
// `ReplyOut` sink (`QueryResponder`) stages these for the AP wire path.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryReply {
    /// Successful reply — typed as Put or Del per [`ReplyBody`].
    Reply {
        /// Echo of the inbound Request.rid so the requester
        /// correlates this reply with their pending `z_get`.
        rid: u64,
        /// Resolved keyexpr literal the inbound Request matched
        /// against. Echoed back as the Reply's keyexpr in literal
        /// form (`mapping_id = 0`, `suffix = Some(literal)`).
        keyexpr_literal: String,
        /// Reply body arm (Put or Del).
        body: ReplyBody,
        /// Optional `(zid bytes, eid)` carried as the envelope-level
        /// responder ext on the emitted Response. `None` skips the ext;
        /// `Some` packs the bytes via
        /// [`crate::session_glue::ResponseReplyBuilder::responder`].
        responder: Option<(Vec<u8>, u32)>,
    },
    /// Error reply — `MID = _Z_MID_Z_ERR(0x05)`. The `encoding` tuple
    /// (id, optional schema) maps onto
    /// [`ResponseErrBuilder::encoding`] at frame-emit time. `payload`
    /// is the application-level error blob (often a UTF-8 message
    /// but no wire-level encoding is mandated).
    Err {
        rid: u64,
        keyexpr_literal: String,
        encoding: Option<(u32, Option<String>)>,
        payload: Vec<u8>,
        /// Optional `(zid bytes, eid)` carried as the envelope-level
        /// responder ext on the emitted Response. Mirror of
        /// [`Self::Reply::responder`] — same shape, same wire slot.
        responder: Option<(Vec<u8>, u32)>,
    },
}

#[cfg(feature = "alloc")]
impl QueryReply {
    /// Compose the wire-form [`Response`] for this Reply / Err using
    /// the existing layered builders. Consumes `self` so the
    /// allocated payload bytes flow directly into the builder
    /// (callers can `take_pending_replies()` and `.into_iter().map(
    /// QueryReply::into_response)` without intermediate clones).
    ///
    /// The Reply keyexpr is emitted in literal form
    /// (`mapping_id = 0` + `suffix = Some(literal)`); this is the
    /// zenoh-pico parity choice for queryables that have not yet
    /// declared a peer-side alias (which is the AP MVP shape — alias
    /// declaration on the responder side is a Phase D+ optimisation).
    ///
    /// R311r — gated on `codec-response`. The Reply staging side
    /// (callback emit + Vec accumulation) compiles unconditionally so
    /// `QueryableRegistry` stays type-ungated; only the wire-emit
    /// terminal step lives behind the codec gate. Callers that hold a
    /// `Vec<QueryReply>` without codec-response cannot convert to
    /// `Response`, which is the textbook honest shape: no codec ⇒ no
    /// wire frame to compose.
    #[cfg(feature = "codec-response")]
    pub fn into_response(self) -> ResponseOwned {
        match self {
            QueryReply::Reply {
                rid,
                keyexpr_literal,
                body,
                responder,
            } => {
                let mut builder = match body {
                    ReplyBody::Put(payload) => {
                        ResponseReplyBuilder::new(rid, 0, Some(&keyexpr_literal), &payload)
                    }
                    ReplyBody::Del => {
                        // The payload slot is unused on the Del path
                        // (the builder drops it when reply_del() flips
                        // the inner arm to MsgDel — see
                        // session_glue.rs:3519-3523). Passing an empty
                        // slice here is the natural shape.
                        ResponseReplyBuilder::new(rid, 0, Some(&keyexpr_literal), &[]).reply_del()
                    }
                };
                if let Some((zid, eid)) = responder {
                    builder = builder.responder(&zid, eid);
                }
                builder.build()
            }
            QueryReply::Err {
                rid,
                keyexpr_literal,
                encoding,
                payload,
                responder,
            } => {
                let mut builder = ResponseErrBuilder::new(rid, 0, Some(&keyexpr_literal), &payload);
                if let Some((id, schema)) = encoding {
                    builder = builder.encoding(id, schema.as_deref());
                }
                if let Some((zid, eid)) = responder {
                    builder = builder.responder(&zid, eid);
                }
                builder.build()
            }
        }
    }
}

/// Short-lived borrow handed to a user `on_query` callback. The
/// callback uses [`Self::send_reply`] / [`Self::send_reply_del`] /
/// [`Self::send_err`] to push outbound records into the registry-
/// owned [`QueryReply`] queue. The Responder is dropped before the
/// dispatch loop advances to the next matched queryable, so user
/// closures cannot retain the borrow.
///
/// R311dx — `codec-request`-gated: only [`QueryableRegistry::fire_matching_queryables`]
/// constructs a `QueryResponder`, so it shares the registry's gate.
#[cfg(all(feature = "codec-request", feature = "alloc"))]
pub struct QueryResponder<'a> {
    rid: u64,
    keyexpr_literal: String,
    replies: &'a mut Vec<QueryReply>,
    /// R121j-3c — optional responder identity attached to every
    /// subsequent send_reply / send_reply_del / send_err. `None`
    /// emits no envelope-level responder ext; `Some` stamps the
    /// tuple onto every pushed [`QueryReply`] so
    /// [`QueryReply::into_response`] threads it into
    /// [`ResponseReplyBuilder::responder`] / [`ResponseErrBuilder::responder`].
    /// Set via [`Self::with_responder`]; clears via [`Self::clear_responder`].
    responder: Option<(Vec<u8>, u32)>,
}

#[cfg(all(feature = "codec-request", feature = "alloc"))]
impl<'a> QueryResponder<'a> {
    /// Emit a Put-form data reply with the given payload bytes.
    /// Multiple calls accumulate; the registry passes the
    /// caller-owned `Vec<QueryReply>` back so each push is one
    /// outbound Response frame on the wire (per zenoh-pico's "many
    /// replies + one final" semantics).
    pub fn send_reply(&mut self, payload: &[u8]) {
        self.replies.push(QueryReply::Reply {
            rid: self.rid,
            keyexpr_literal: self.keyexpr_literal.clone(),
            body: ReplyBody::Put(payload.to_vec()),
            responder: self.responder.clone(),
        });
    }

    /// Emit a Del-form reply — the queryable signals that the value
    /// at this keyexpr is being deleted / cleared. No payload bytes
    /// (the inner `MsgDel` body carries only a header + optional
    /// timestamp).
    pub fn send_reply_del(&mut self) {
        self.replies.push(QueryReply::Reply {
            rid: self.rid,
            keyexpr_literal: self.keyexpr_literal.clone(),
            body: ReplyBody::Del,
            responder: self.responder.clone(),
        });
    }

    /// Emit an Err reply. `encoding_id` (with optional `schema`)
    /// maps onto [`ResponseErrBuilder::encoding`] at frame-emit
    /// time — pass `None` to skip the encoding ext and rely on the
    /// peer's default interpretation of `payload`.
    pub fn send_err(&mut self, encoding_id: Option<u32>, schema: Option<&str>, payload: &[u8]) {
        let encoding = encoding_id.map(|id| (id, schema.map(str::to_string)));
        self.replies.push(QueryReply::Err {
            rid: self.rid,
            keyexpr_literal: self.keyexpr_literal.clone(),
            encoding,
            payload: payload.to_vec(),
            responder: self.responder.clone(),
        });
    }

    /// R121j-3c — attach a responder identity that every subsequent
    /// `send_reply` / `send_reply_del` / `send_err` call stamps onto
    /// the pushed [`QueryReply`]. The stamp propagates through
    /// [`QueryReply::into_response`] into
    /// [`crate::session_glue::ResponseReplyBuilder::responder`] /
    /// [`crate::session_glue::ResponseErrBuilder::responder`], which
    /// emits the envelope-level responder ext (zenoh-pico ext_id 0x03
    /// ZBUF) per `_z_response_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c:281-291`.
    ///
    /// The setter is idempotent within a single callback invocation —
    /// calling it twice replaces the previous identity (last-wins,
    /// matching the standard builder idiom). Replies emitted before
    /// this call carry no responder ext; replies after carry the
    /// stamp. Callers wishing to mix responder-stamped and unstamped
    /// replies within one callback must order send_* calls accordingly
    /// (or call [`Self::clear_responder`] mid-stream).
    ///
    /// Panics on `zid` length outside `1..=16` (the zenoh-pico
    /// ZenohId wire constraint at `core.h::_Z_ID_LENGTH = 16`).
    pub fn with_responder(&mut self, zid: &[u8], eid: u32) -> &mut Self {
        assert!(
            (1..=16).contains(&zid.len()),
            "QueryResponder::with_responder requires zid length 1..=16 \
             (zenoh-pico ZenohId wire constraint)"
        );
        self.responder = Some((zid.to_vec(), eid));
        self
    }

    /// Clear any responder identity previously attached via
    /// [`Self::with_responder`]. Subsequent send_* calls emit no
    /// envelope-level responder ext until [`Self::with_responder`] is
    /// invoked again.
    pub fn clear_responder(&mut self) -> &mut Self {
        self.responder = None;
        self
    }

    /// Inbound Request id this Responder is replying to. Exposed for
    /// diagnostic surfaces; user closures normally don't need it
    /// (the registry pre-fills it into every push).
    pub fn rid(&self) -> u64 {
        self.rid
    }

    /// Resolved keyexpr literal this Responder is bound to. Exposed
    /// so user closures can use the same literal in other side-
    /// effects (e.g. log lines, metrics labels) without having to
    /// re-resolve the inbound Request keyexpr themselves.
    pub fn keyexpr_literal(&self) -> &str {
        &self.keyexpr_literal
    }

    /// Current responder identity (read-only view). `None` until
    /// [`Self::with_responder`] is called; reset by
    /// [`Self::clear_responder`]. Exposed for diagnostic surfaces and
    /// tests; user closures typically only set and forget.
    pub fn responder(&self) -> Option<(&[u8], u32)> {
        self.responder
            .as_ref()
            .map(|(zid, eid)| (zid.as_slice(), *eid))
    }
}

/// R311gb-3b-cleanup — `QueryResponder` is the reply accumulator the
/// queryable dispatch hands the handler as `&mut dyn ReplyOut`; it impls
/// the seam's outbound emit contract directly. The R311r `ReplyEmitter`
/// wrapper that previously bridged the closure to `QueryResponder` was
/// retired with its whole `query_event` module — the unconditional
/// `ReplyOut` trait now provides the feature-subset-stable surface the
/// wrapper's `PhantomData` scaffolding used to, so the indirection (and
/// its scaffolding) is gone.
///
/// `reply_err` keeps the `query-reply-err` gate: it is that feature's
/// sole production enforcement point — an Err-form reply must not be
/// emitted in a build without it, and the `codec-response`-gated
/// `into_response` encode stage carries no such gate. The Put / Del /
/// responder-identity methods stay unconditional under `codec-request`:
/// a constructed `QueryResponder` only accumulates into a
/// `Vec<QueryReply>` that the `codec-response`-gated `into_response`
/// drains, so any further feature gate there would be wire-invisible (the
/// prior `query-queryable` no-op on the `ReplyEmitter` wrapper was
/// PhantomData scaffolding, not a semantic gate, mirroring how
/// `SubscriberRegistry` leaves `SampleSink::deliver` ungated and gates
/// only the `codec-push` wire arms).
#[cfg(all(feature = "codec-request", feature = "alloc"))]
impl ReplyOut for QueryResponder<'_> {
    fn reply(&mut self, payload: &[u8]) {
        self.send_reply(payload);
    }
    fn reply_del(&mut self) {
        self.send_reply_del();
    }
    fn reply_err(&mut self, encoding_id: Option<u32>, schema: Option<&str>, payload: &[u8]) {
        #[cfg(feature = "query-reply-err")]
        self.send_err(encoding_id, schema, payload);
        #[cfg(not(feature = "query-reply-err"))]
        {
            let _ = (encoding_id, schema, payload);
        }
    }
    fn with_responder(&mut self, zid: &[u8], eid: u32) {
        QueryResponder::with_responder(self, zid, eid);
    }
    fn clear_responder(&mut self) {
        QueryResponder::clear_responder(self);
    }
    fn responder(&self) -> Option<(&[u8], u32)> {
        QueryResponder::responder(self)
    }
}

/// Queryable table backing the inbound `Request(Query)` → callback
/// dispatch. `!Sync` by construction; cross-task sharing goes
/// through `Arc<Mutex<…>>`. See module-level docs for scope.
///
/// R311gb (Track 2) — the table + register + matching + the borrowed
/// no-heap fire ([`Self::dispatch_borrowed`]) form the no-alloc control
/// plane (un-gated). The owned-reply wire-dispatch methods
/// (`dispatch_request` / `local_query` / `dispatch_messages`) live in a
/// separate `all(codec-request, alloc)` impl block below.
pub struct QueryableRegistry<C: QuerySink> {
    queryables: BoundedVec<Queryable<C>, { caps::MAX_QUERYABLES }>,
    next_id: u64,
}

impl<C: QuerySink> Default for QueryableRegistry<C> {
    fn default() -> Self {
        Self::with_sink_backing()
    }
}

impl<C: QuerySink> QueryableRegistry<C> {
    /// New empty registry over an explicit sink backing `C`. Queryable
    /// ids start at 1 so 0 stays available as a sentinel "no queryable"
    /// value for any caller-side wrapper that needs one.
    ///
    /// R311gb-3b — the generic constructor (the no-`alloc` / MCU entry
    /// point, paired with [`register_sink`](Self::register_sink)). AP
    /// callers use the inferring [`new`](QueryableRegistry::new)
    /// shorthand, which fixes `C = BoxedQuerySink`; this mirrors the std
    /// `HashMap::new` / `with_hasher` split (and
    /// [`crate::pubsub::SubscriberRegistry::with_sink_backing`]), so a
    /// bare `QueryableRegistry::new()` resolves its type parameter
    /// without a turbofish.
    pub fn with_sink_backing() -> Self {
        Self {
            queryables: BoundedVec::new(),
            next_id: 1,
        }
    }

    /// R311gb-3b — register an explicit [`QuerySink`] for a keyexpr
    /// pattern. The seam-native registration entry point: works on
    /// every profile (`C = BoxedQuerySink` heap closure on AP, a
    /// consumer-supplied closed `enum` on MCU). The `alloc`-only
    /// [`register`](QueryableRegistry::register) /
    /// [`register_with_locality`](QueryableRegistry::register_with_locality)
    /// convenience wrappers funnel through here after wrapping a closure
    /// in a [`BoxedQuerySink`].
    ///
    /// Pattern syntax matches zenoh chunk wildcards (same as
    /// [`crate::pubsub::SubscriberRegistry::register_sink`]): `/`-
    /// separated chunks where each chunk is a literal, `*` (single
    /// chunk), `**` (zero or more chunks), or contains the `$*` intra-
    /// chunk substring wildcard (R220). The returned [`QueryableId`] is
    /// stable until [`Self::unregister`] is called. Duplicate patterns
    /// produce distinct queryables — `dispatch_request` fires every
    /// matching sink in registration order.
    ///
    /// R221 — the pattern is canonicalized via
    /// [`canonize_keyexpr`](crate::keyexpr_canon::canonize_keyexpr)
    /// into the bounded pattern buffer, so the stored form agrees
    /// byte-for-byte with the canonical wire form. Structurally
    /// invalid patterns fall back to the raw form (non-breaking)
    /// with a `log::warn!` notice.
    ///
    /// R311gb (Track 2) — fallible on the no-alloc backing: an over-
    /// capacity canonical form is rejected with
    /// [`RegisterError::KeyexprTooLong`] and a full table with
    /// [`RegisterError::TableFull`] (fail-fast, no silent
    /// truncation). On the `alloc` backing neither branch is ever taken,
    /// so the convenience wrappers `.expect()` the result.
    pub fn register_sink(
        &mut self,
        keyexpr_pattern: &str,
        allowed_origin: crate::locality::Locality,
        sink: C,
    ) -> Result<QueryableId, RegisterError> {
        // R221/R311gb — canonicalize into the bounded pattern buffer. A
        // grammar-invalid pattern falls back to the raw form (non-
        // breaking; the matcher still operates). An over-capacity
        // canonical form is a hard no-alloc failure. On the `alloc`
        // backing neither capacity branch is ever taken.
        let pattern: BoundedString<{ caps::MAX_KEYEXPR_BYTES }> =
            match crate::keyexpr_canon::canonize_keyexpr(keyexpr_pattern) {
                Ok(canon) => canon,
                Err(crate::keyexpr_canon::KeyexprCanonError::ExceedsCapacity) => {
                    return Err(RegisterError::KeyexprTooLong);
                }
                Err(err) => {
                    log::warn!(
                        "QueryableRegistry::register: keyexpr `{keyexpr_pattern}` is not \
                         canonical ({err}); storing raw form. The matcher still operates \
                         but the stored chunks may drift from the canonical form a peer emits."
                    );
                    let mut raw = BoundedString::new();
                    raw.push_str(keyexpr_pattern)
                        .map_err(|_| RegisterError::KeyexprTooLong)?;
                    raw
                }
            };
        let id = QueryableId(self.next_id);
        // Push first; only consume the id counter on success so a
        // rejected (table-full) registration leaves no id gap.
        self.queryables
            .push(Queryable {
                id,
                pattern,
                allowed_origin,
                sink,
            })
            .map_err(|_| RegisterError::TableFull)?;
        self.next_id = self.next_id.saturating_add(1);
        Ok(id)
    }

    /// Remove a previously-registered queryable. Returns `true` if
    /// the id was found and removed. Idempotent — calling on an id
    /// that was never registered or already removed returns `false`
    /// without panicking.
    pub fn unregister(&mut self, id: QueryableId) -> bool {
        let before = self.queryables.len();
        self.queryables.retain(|q| q.id != id);
        before != self.queryables.len()
    }

    /// Number of currently-registered queryables.
    pub fn len(&self) -> usize {
        self.queryables.len()
    }

    /// Whether the registry holds any queryable.
    pub fn is_empty(&self) -> bool {
        self.queryables.is_empty()
    }

    /// R311gb (Track 2) — no-heap fire entry: match `view`'s keyexpr
    /// against every queryable and hand each matching sink the borrowed
    /// [`QueryView`] + the caller-supplied [`ReplyOut`], applying the
    /// locality filter. Borrow-driven (no owned `Query` materialization,
    /// no per-match `QueryResponder` accumulator), so it is the MCU
    /// no-heap dispatch path; the AP wire path
    /// ([`fire_matching_queryables`](Self::fire_matching_queryables))
    /// shares the same per-queryable match SSOT
    /// ([`Queryable::matches`]) but builds a fresh `QueryResponder`
    /// per match to stage owned `QueryReply` records for the wire.
    /// Returns the count of sinks fired.
    ///
    /// Unlike the wire path, the single `reply_out` is shared across all
    /// matched queryables — the consumer owns its lifecycle (an MCU
    /// `ReplyOut` typically injects into a statechart rather than
    /// accumulating), so any per-queryable reset is the consumer's
    /// responsibility.
    pub fn dispatch_borrowed(
        &mut self,
        view: &dyn QueryView,
        reply_out: &mut dyn ReplyOut,
        is_remote: bool,
    ) -> usize {
        let mut fired: usize = 0;
        let keyexpr = view.keyexpr();
        for queryable in self.queryables.iter_mut() {
            if queryable.matches(keyexpr, is_remote) {
                queryable.sink.handle(view, reply_out);
                fired = fired.saturating_add(1);
            }
        }
        fired
    }
}

// R311gb (Track 2) — owned wire-dispatch surface: these entry points
// consume an owned `wz_codecs::query::Query` / `Request` / a
// `Vec<QueryReply>` accumulator, so they gate on `all(codec-request,
// alloc)` (the `codec-request` codec_group + the `alloc` reply
// accumulator). The control plane above (table + register + matching +
// `dispatch_borrowed`) stays un-gated.
#[cfg(all(feature = "codec-request", feature = "alloc"))]
impl<C: QuerySink> QueryableRegistry<C> {
    /// Route an inbound [`Request`] through the queryable table.
    ///
    /// - Requests whose body is not `RequestVariant::CodecZenohQuery`
    ///   (i.e. MsgPut / MsgDel / Default arms) are no-ops here. The
    ///   AP MVP responder path only handles Query bodies; the other
    ///   arms are accepted by the inbound parser for wire-shape
    ///   completeness but have no application-visible side effect in
    ///   the queryable surface.
    /// - The Request keyexpr is resolved through `peer_keyexpr_table`
    ///   (the shared mapping populated by the subscriber side's
    ///   `absorb_declare` from inbound `Declare(DeclKexpr)`). The
    ///   composition rule mirrors `dispatch_push`:
    ///   * `id == 0`                    → keyexpr = suffix or empty
    ///   * `id != 0`, suffix = None     → keyexpr = table[id]
    ///   * `id != 0`, suffix = Some(s)  → keyexpr = table[id] + s
    ///
    ///   Un-resolvable mapping ids (peer hasn't declared the id yet,
    ///   or the declaration arrived through a path the table has not
    ///   yet absorbed) drop the dispatch silently rather than firing
    ///   on a partial keyexpr.
    /// - Each matched queryable fires once, in registration order.
    ///   The callback's `&mut QueryResponder` pushes outbound
    ///   replies into `replies`; the caller drains `replies` after
    ///   `dispatch_request` returns and encodes each into a
    ///   Response frame on the wire (R121j-5c).
    ///
    /// R311dx — `codec-request`-gated: the `&RequestOwned` parameter
    /// type lives in the `codec-request` codec_group, so a
    /// `codec-request`-OFF subset elides this entry point entirely
    /// (wire-data-helper exemption to R311g1 signature stability,
    /// mirror of `SubscriberRegistry::dispatch_push`). Gate carried by
    /// the enclosing `#[cfg(all(codec-request, alloc))] impl`.
    pub fn dispatch_request(
        &mut self,
        request: &RequestOwned,
        peer_keyexpr_table: &HashMap<u64, String>,
        replies: &mut Vec<QueryReply>,
    ) {
        // Only the Query body arm triggers application-visible
        // dispatch — see scope note above.
        let query = match &request.body {
            RequestOwnedVariant::CodecZenohQuery(q) => q,
            _ => return,
        };

        // R311gn-follow — resolve via the shared resolve_wireexpr SSOT
        // (id==0 -> suffix verbatim; id!=0 -> table[id] + optional suffix;
        // None -> drop, covering the empty form + an undeclared id).
        let resolved: String = match resolve_wireexpr(&request.keyexpr.body, peer_keyexpr_table) {
            Some(r) => r,
            None => return,
        };

        // R223 — every Request reaching dispatch_request has been
        // parsed off the wire, so the inner fan-out treats this as a
        // remote-origin dispatch. R238 — the same fan-out logic is
        // shared with [`Self::local_query`] (is_remote=false) so the
        // pattern-match / responder-build / callback-fire body lives
        // in [`Self::fire_matching_queryables`] once. The "deferred
        // self-publish loopback" carry note prior to R238 lands here:
        // the helper switch is the textbook resolution.
        self.fire_matching_queryables(
            request.rid,
            &resolved,
            query,
            replies,
            /* is_remote = */ true,
        );
    }

    /// R238 — in-process query loopback mirror of
    /// [`crate::pubsub::SubscriberRegistry::local_publish`]. Fans the
    /// `(rid, keyexpr, query)` triple into every matching queryable
    /// that allows `Locality::SessionLocal` (or `Locality::Any`),
    /// pushing each callback's emitted [`QueryReply`] records into
    /// `replies`. The caller drains `replies` after the call —
    /// typically into an in-process [`crate::reply::ReplyRegistry`]
    /// pending entry so the self-`z_get` requester observes its own
    /// queryables' replies without a wire round-trip.
    ///
    /// Caller precondition: `keyexpr` is the already-resolved literal
    /// form. Unlike [`Self::dispatch_request`], this method does NOT
    /// consult the peer keyexpr table — the loopback path bypasses
    /// the peer's DECLARE alias table because the caller is local.
    /// If the application uses outbound aliasing
    /// (`SessionLinkActions::send_declare_keyexpr` +
    /// `Session::publish_aliased_auto`), the caller should resolve
    /// the alias through `SessionLinkActions::resolve_outbound_mapping`
    /// or pre-known literal before invoking `local_query`. Typical
    /// caller: a future `Session::query` API (carry) routes the
    /// requester's literal keyexpr into both the outbound
    /// `send_request_query` (wire branch) and `local_query` (loopback
    /// branch) per the same `Locality` predicate that
    /// `Session::publish` uses on the publish side.
    ///
    /// Returns nothing; the count of fired callbacks can be inferred
    /// from `replies.len()` delta when at least one Reply is emitted
    /// per callback (typical AP pattern). Mirrors zenoh-pico's
    /// `_z_trigger_queryables` invoked with `_z_query_t.zn_session ==
    /// self` (the in-process variant); the wire path's
    /// `_z_trigger_queryables_impl` is the `dispatch_request`
    /// equivalent here.
    ///
    /// R311dx — gate carried by the enclosing
    /// `#[cfg(all(codec-request, alloc))] impl` (the `&QueryOwned` param).
    pub fn local_query(
        &mut self,
        rid: u64,
        keyexpr: &str,
        query: &QueryOwned,
        replies: &mut Vec<QueryReply>,
    ) {
        self.fire_matching_queryables(rid, keyexpr, query, replies, /* is_remote = */ false);
    }

    /// R238 — shared fan-out body for [`Self::dispatch_request`]
    /// (is_remote=true) and [`Self::local_query`] (is_remote=false).
    /// The locality predicate split happens here so the rest of the
    /// pattern-match / responder-build / callback-fire path stays
    /// identical across wire and loopback origins. Mirrors the R227
    /// `SubscriberRegistry::fire_to_subscribers(sample, is_remote)`
    /// internal split for the queryable side.
    ///
    /// `keyexpr` is the already-resolved literal; the responder
    /// echoes it back into each [`QueryReply::Reply::keyexpr_literal`]
    /// so the requester sees the same literal regardless of whether
    /// the dispatch came off the wire (alias-resolved through
    /// `peer_keyexpr_table`) or in-process (caller-supplied literal).
    ///
    /// R311dx — the shared fan-out body for the two public entry
    /// points; gate carried by the enclosing
    /// `#[cfg(all(codec-request, alloc))] impl` (the `&QueryOwned` param).
    fn fire_matching_queryables(
        &mut self,
        rid: u64,
        keyexpr: &str,
        query: &QueryOwned,
        replies: &mut Vec<QueryReply>,
        is_remote: bool,
    ) {
        // R311gb-3b-cleanup — extract the projection inputs ONCE per
        // matched queryable (the parameters byte slice and attachment
        // view are stable across all matched handlers for a single
        // inbound query); each match builds a `BorrowedQuery` from them.
        // The keyexpr field re-borrows the
        // dispatcher's `keyexpr` argument; the parameters field
        // borrows directly from `Query.parameters`; the attachment
        // view is extracted from the inbound extensions chain at R311v
        // (`extract_query_attachment`).
        // R311cj — query-selector-parameters gates the parameters
        // slice projection. cfg-off: callback always observes None.
        #[cfg(feature = "query-selector-parameters")]
        let parameters_view = query.parameters.as_deref();
        #[cfg(not(feature = "query-selector-parameters"))]
        let parameters_view: Option<&[u8]> = None;
        let attachment_view = extract_query_attachment(query);
        for queryable in self.queryables.iter_mut() {
            // R311gb (Track 2) — shared match SSOT with the no-heap
            // `dispatch_borrowed` path: locality predicate + bounded
            // pattern split happen in `Queryable::matches`.
            if queryable.matches(keyexpr, is_remote) {
                let mut responder = QueryResponder {
                    rid,
                    keyexpr_literal: keyexpr.to_string(),
                    replies,
                    responder: None,
                };
                // R311gb-3b-cleanup — dispatch through the QuerySink seam
                // with no intermediate wrapper: `QueryResponder` impls
                // `ReplyOut` directly, and the inbound view is a
                // `BorrowedQuery` (the seam's own loose `QueryView`). Both
                // unsize at the call (`handle` names the trait objects),
                // so there is no projection and no third sample/query
                // struct. The borrow of `replies` lives in `responder`
                // and ends when it drops at the end of this block, so the
                // loop can re-borrow for the next match.
                let query_view = BorrowedQuery {
                    keyexpr,
                    parameters: parameters_view,
                    attachment: attachment_view,
                    rid,
                };
                queryable.sink.handle(&query_view, &mut responder);
            }
        }
    }

    /// R121j-5c — drain a `Vec<NetworkMessage>` (typically the
    /// `FramePayload.messages` field surfaced by
    /// [`crate::session_glue::drive_session_until_terminal`]) through
    /// the queryable table. Each `NetworkMessage::Request` triggers
    /// at most one `dispatch_request` and, when at least one queryable
    /// matched the inbound keyexpr, also enqueues a
    /// `pending_final_rids` entry so the caller emits exactly one
    /// matching [`ResponseFinal`] after all per-rid replies have been
    /// sent (zenoh-pico semantics: "many Reply + exactly one Final"
    /// per Query).
    ///
    /// `pending_replies` accumulates outbound replies in arrival
    /// order. `pending_final_rids` accumulates the rids for which
    /// the caller still owes a Final. Both vecs are caller-owned so
    /// the caller may batch multiple poll cycles before draining,
    /// e.g. for backpressure or coalesced send.
    ///
    /// A `Request(Query)` whose keyexpr is un-resolvable (mapping_id
    /// references an entry the peer never declared) does NOT enqueue
    /// a Final — the dispatch dropped silently, so the wire-level
    /// contract is "no Reply, no Final" rather than "no Reply, one
    /// Final" (the latter would falsely promise the requester a
    /// terminal that never comes from an unmatched queryable).
    ///
    /// Non-Query body arms (MsgPut|MsgDel|Default) are no-ops at
    /// this layer per the scope note on
    /// [`Self::dispatch_request`]; they do not enqueue a Final
    /// either.
    pub fn dispatch_messages(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: &HashMap<u64, String>,
        pending_replies: &mut Vec<QueryReply>,
        pending_final_rids: &mut Vec<u64>,
    ) {
        // R311dx — the whole registry impl is `codec-request`-gated, so
        // `NetworkMessage::Request` (itself a `codec-request` variant) is
        // always present here; the prior R311r `#[cfg(not(codec-request))]`
        // no-op fall-through is subsumed by the enclosing impl gate. The
        // other (Push / Response / …) NetworkMessage variants this
        // registry does not handle simply fall through the `if let`.
        for message in messages {
            if let NetworkMessage::Request(req) = message {
                // Only Query bodies are queryable-visible; only
                // resolvable keyexprs schedule a Final. We detect both
                // by snapshotting the replies length before / after
                // dispatch_request — a delta of zero means either
                // non-Query body, un-resolvable keyexpr, or no queryable
                // matched. In all three cases we owe no Final (the
                // requester sees no Reply chain at all from this peer
                // for this rid).
                let before = pending_replies.len();
                self.dispatch_request(req, peer_keyexpr_table, pending_replies);
                if pending_replies.len() > before {
                    pending_final_rids.push(req.rid);
                }
            }
        }
    }

    /// R121j-5c — convenience adapter that pulls the
    /// `FramePayload.messages` out of an
    /// [`IterationEvent::Poll(DriverLoopOutcome::FramePayload)`]
    /// surface and forwards to [`Self::dispatch_messages`]. Mirror
    /// of [`crate::pubsub::SubscriberRegistry::dispatch_iteration_event`]
    /// for the queryable side. Other `IterationEvent` variants
    /// (`Lease`, non-FramePayload Poll outcomes) are no-ops.
    pub fn dispatch_iteration_event(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: &HashMap<u64, String>,
        pending_replies: &mut Vec<QueryReply>,
        pending_final_rids: &mut Vec<u64>,
    ) {
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            self.dispatch_messages(
                messages,
                peer_keyexpr_table,
                pending_replies,
                pending_final_rids,
            );
        }
    }
}

/// R311gb-3b — AP / `alloc`-profile convenience constructors. The
/// closure-taking `register` / `register_with_locality` wrappers live
/// here (on the `BoxedQuerySink` instantiation only) because they heap-
/// box the closure via [`BoxedQuerySink`]; the no-`alloc` profile
/// registers a consumer-supplied sink through the generic
/// [`register_sink`](QueryableRegistry::register_sink) instead. Mirror of
/// [`crate::pubsub::SubscriberRegistry`]'s `BoxedSink` convenience block.
///
/// R311gb (Track 2) — gated on `alloc` only (not `codec-request`): the
/// convenience wrappers funnel through the un-gated `register_sink`, so
/// the AP register surface composes in any `alloc` subset.
#[cfg(feature = "alloc")]
impl QueryableRegistry<BoxedQuerySink> {
    /// New empty AP registry backed by heap-boxed closures
    /// ([`BoxedQuerySink`]). The inferring shorthand for
    /// [`with_sink_backing`](QueryableRegistry::with_sink_backing):
    /// `QueryableRegistry::new()` fixes `C = BoxedQuerySink` so the
    /// closure-taking [`register`](Self::register) /
    /// [`register_with_locality`](Self::register_with_locality) wrappers
    /// are in reach without a turbofish.
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// Register a queryable closure for a keyexpr pattern. The closure
    /// receives `&dyn QueryView` (resolved keyexpr / parameters /
    /// attachment / rid) and `&mut dyn ReplyOut` (the reply-emit
    /// surface) — the R311gb-3b seam contracts replace the prior owned
    /// `&QueryEvent` + `&mut ReplyEmitter`; this is the
    /// [`feedback_signature_stability`] wire-data principled exemption,
    /// taken so one registry backs both heap and no-heap profiles. The
    /// closure is heap-boxed via [`BoxedQuerySink`].
    ///
    /// R223 — defaults [`Locality::Any`](crate::locality::Locality);
    /// use [`register_with_locality`](Self::register_with_locality)
    /// to restrict to one origin class.
    pub fn register(
        &mut self,
        keyexpr_pattern: impl Into<String>,
        handler: impl FnMut(&dyn crate::query_sink::QueryView, &mut dyn crate::query_sink::ReplyOut)
            + Send
            + 'static,
    ) -> QueryableId {
        self.register_with_locality(keyexpr_pattern, crate::locality::Locality::Any, handler)
    }

    /// R223 — variant of [`register`](Self::register) that pins the
    /// locality filter explicitly. See
    /// [`crate::pubsub::SubscriberRegistry::register_with_locality`]
    /// for the dispatch-invariant rationale (every inbound Request
    /// is remote until self-publish loopback lands).
    pub fn register_with_locality(
        &mut self,
        keyexpr_pattern: impl Into<String>,
        allowed_origin: crate::locality::Locality,
        handler: impl FnMut(&dyn crate::query_sink::QueryView, &mut dyn crate::query_sink::ReplyOut)
            + Send
            + 'static,
    ) -> QueryableId {
        let pattern = keyexpr_pattern.into();
        // AP backing: `register_sink` is infallible here (the BoundedVec
        // table + BoundedString pattern grow past the advisory `N`), so
        // the convenience wrapper keeps its `QueryableId` signature.
        self.register_sink(&pattern, allowed_origin, BoxedQuerySink::new(handler))
            .expect("register on the alloc backing never exceeds declared capacity")
    }
}

/// R121j-5c — build the wire-form [`ResponseFinal`] envelope that
/// terminates a Reply chain for `rid`. zenoh-pico semantics require
/// exactly one Final per inbound Query whose dispatch produced at
/// least one Reply (or Err); the caller passes each rid recorded in
/// `pending_final_rids` through this helper before the next outbound
/// frame.
///
/// The construction is shape-frozen by the SCE codegen for
/// [`ResponseFinal`]: `header = _Z_MID_N_RESPONSE_FINAL(0x1A)` + the
/// per-rid VLE. Future qos / responder envelope exts on ResponseFinal
/// will land via a separate setter (none exist on the wire today —
/// zenoh-pico's `_z_response_final_encode` emits only header + rid).
#[cfg(all(feature = "codec-response-final", feature = "alloc"))]
pub fn response_final_for(rid: u64) -> ResponseFinalOwned {
    ResponseFinal {
        request_id: rid,
        // header = 0x1a (_Z_MID_N_RESPONSE_FINAL) and extensions =
        // None come from ResponseFinal::default() (see
        // wz-codecs/.../out/response_final.rs:38-47); the spread
        // keeps this helper resilient to future field additions
        // that land with sensible defaults.
        ..ResponseFinal::default()
    }
    // `ResponseFinalOwned` has no `Default` (the owned mirrors derive
    // only Debug/Clone/PartialEq), so build the borrowed view via the
    // spread default and deep-copy into the owned form at the boundary.
    .into_owned()
}

// R311dx — the behavioural query tests exercise the full
// `codec-request` dispatch path (RequestOwned / QueryOwned fixtures),
// `into_response` (codec-response), the attachment / parameters / err
// emit arms, and the queryable callback fan-out. The module-level gate
// enumerates the union so a plain `cargo test -p wz-session-core`
// (default = alloc only) elides them, while the C1e lane enables the
// set explicitly (R311ds-c1c / C1d precedent). `query-queryable`
// implies `codec-request` + `codec-response`, so those two are covered
// transitively. The two `response_final_for` tests carry an additional
// inner `#[cfg(feature = "codec-response-final")]` gate.
#[cfg(all(
    test,
    feature = "query-queryable",
    feature = "query-attachment",
    feature = "query-selector-parameters",
    feature = "query-reply-err"
))]
mod tests {
    use super::*;
    // R311gb-3b — `Box` lives here (not at module level): its only uses
    // are the `NetworkMessage::Request(Box::new(..))` fixtures below, and
    // this module's gate is exactly the full query feature set, so the
    // import never goes unused in a partial-feature subset build.
    use alloc::boxed::Box;
    // no_std test prelude: the std prelude (String / Vec / vec!) is
    // absent under `#![no_std]`, so the alloc forms are imported
    // explicitly; the host-run callback-capture cells use `std::sync`
    // (Arc + Mutex) per the wz-session-core test convention.
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    // R311fu — owned->wire projection SSOT (the eight `into_response()`
    // / builder byte-compares below read `.wire()` uniformly). In scope
    // because the test-module cfg requires `query-queryable`, which
    // implies `codec-response` and forwards
    // `wz-codecs-test-support/codec-response`.
    use wz_codecs_test_support::TestWire;
    // Fixtures build the borrowed codec views (`..::default()` lives on
    // the borrowed type) then `.into_owned()` at the dispatch boundary,
    // which now takes the lifetime-free `*Owned` mirrors.
    use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
    use wz_codecs::ext_zbuf::ExtZbuf;
    use wz_codecs::msg_put::MsgPut;
    use wz_codecs::query::Query;
    use wz_codecs::request::{Request, RequestVariant};
    use wz_codecs::wireexpr::Wireexpr;
    use wz_codecs::wireexpr_local::WireexprLocal;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    fn request_query(rid: u64, mapping_id: u64, suffix: Option<&str>) -> RequestOwned {
        // Construct a minimal Request whose body is a default Query.
        // The Local arm (zero-init mapping = LOCAL on the zenoh-pico
        // side, mirrored by push_with_keyexpr at pubsub.rs:398-415) is
        // the canonical default; both arms surface (id, suffix)
        // identically through dispatch's WireexprVariant match
        // (pubsub.rs:292-294), so the test only needs one arm to
        // exercise the dispatch logic.
        let suffix_len = suffix.map(|s| s.len() as u64);
        let keyexpr = Wireexpr {
            body: wz_codecs::wireexpr::WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix,
            }),
        };
        Request {
            header: 0x1c, // _Z_MID_N_REQUEST default
            rid,
            keyexpr,
            extensions: None,
            body: RequestVariant::CodecZenohQuery(Query::default()),
        }
        .into_owned()
    }

    /// R311v test helper — construct an inbound Query whose
    /// extensions chain carries a single attachment ext
    /// (`_Z_MSG_EXT_ENC_ZBUF | 0x05` wire shape per zenoh-pico
    /// `vendor/zenoh-pico/src/protocol/codec/message.c:447`). The
    /// `Query.header` `0x80` bit is set so a hypothetical round-trip
    /// through `Query::decode` would surface the extensions vec; the
    /// dispatch path only reads `query.extensions` directly so the
    /// flag is purely for authoring fidelity.
    fn request_query_with_attachment(
        rid: u64,
        suffix: Option<&str>,
        attachment: &[u8],
    ) -> RequestOwned {
        let suffix_len = suffix.map(|s| s.len() as u64);
        let keyexpr = Wireexpr {
            body: wz_codecs::wireexpr::WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len,
                suffix,
            }),
        };
        // Build the attachment ext on the borrowed view (the `set_*`
        // helpers + the borrowed `&[u8]` value) then deep-copy into the
        // owned mirror; the owned `Query` carries an alloc `Vec` of
        // `ExtEntryOwned` (vs the borrowed heapless `Vec<_, 8>`).
        let mut ext = ExtEntry::default();
        ext.set_ext_id(0x05);
        ext.set_enc(2);
        ext.body = ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
            value_len: attachment.len() as u64,
            value: attachment,
        });
        let mut query = Query::default().into_owned();
        query.header |= 0x80;
        query.extensions = Some(vec![ext.into_owned()]);
        let mut request = Request {
            header: 0x1c,
            rid,
            keyexpr,
            extensions: None,
            body: RequestVariant::CodecZenohQuery(Query::default()),
        }
        .into_owned();
        request.body = RequestOwnedVariant::CodecZenohQuery(query);
        request
    }

    fn request_put(rid: u64, suffix: &str) -> RequestOwned {
        let keyexpr = Wireexpr {
            body: wz_codecs::wireexpr::WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix),
            }),
        };
        Request {
            header: 0x1c,
            rid,
            keyexpr,
            extensions: None,
            body: RequestVariant::CodecZenohMsgPut(MsgPut::default()),
        }
        .into_owned()
    }

    #[test]
    fn empty_registry_dispatch_is_noop_and_no_replies_emitted() {
        let mut reg = QueryableRegistry::new();
        let req = request_query(42, 0, Some("home/temp"));
        let mut replies = Vec::new();
        reg.dispatch_request(&req, &HashMap::new(), &mut replies);
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(replies.is_empty(), "no queryables → no replies");
    }

    #[test]
    fn register_assigns_monotonic_ids_starting_from_one() {
        let mut reg = QueryableRegistry::new();
        let id1 = reg.register("home/temp", |_q, _r| {});
        let id2 = reg.register("home/temp", |_q, _r| {});
        let id3 = reg.register("home/humid", |_q, _r| {});
        assert_eq!(id1.as_u64(), 1);
        assert_eq!(id2.as_u64(), 2);
        assert_eq!(id3.as_u64(), 3);
        assert_eq!(reg.len(), 3);
        // Duplicate patterns are explicitly allowed.
        assert_ne!(id1, id2);
    }

    #[test]
    fn unregister_is_idempotent_and_removes_only_matching_id() {
        let mut reg = QueryableRegistry::new();
        let id1 = reg.register("home/temp", |_q, _r| {});
        let id2 = reg.register("home/humid", |_q, _r| {});
        assert!(reg.unregister(id1));
        assert!(
            !reg.unregister(id1),
            "second unregister of same id is a no-op"
        );
        assert_eq!(reg.len(), 1);
        assert!(reg.unregister(id2));
        assert!(reg.is_empty());
    }

    #[test]
    fn dispatch_fires_callback_on_literal_match_and_accumulates_reply() {
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register("home/temp", move |_query, responder| {
            counter.fetch_add(1, Ordering::SeqCst);
            responder.reply(b"42.0");
        });

        let req = request_query(7, 0, Some("home/temp"));
        let mut replies = Vec::new();
        reg.dispatch_request(&req, &HashMap::new(), &mut replies);

        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(replies.len(), 1);
        match &replies[0] {
            QueryReply::Reply {
                rid,
                keyexpr_literal,
                body,
                ..
            } => {
                assert_eq!(*rid, 7, "rid echoed from inbound Request");
                assert_eq!(keyexpr_literal, "home/temp", "resolved literal echoed back");
                assert_eq!(*body, ReplyBody::Put(b"42.0".to_vec()));
            }
            other => panic!("expected Reply::Put, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_with_wildcard_pattern_matches_multiple_chunks() {
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register("home/**", move |_q, responder| {
            counter.fetch_add(1, Ordering::SeqCst);
            responder.reply(b"ok");
        });

        // Three different keyexpr literals should all match `home/**`.
        let mut replies = Vec::new();
        for suffix in ["home", "home/temp", "home/zone/1/temp"] {
            reg.dispatch_request(
                &request_query(1, 0, Some(suffix)),
                &HashMap::new(),
                &mut replies,
            );
        }
        assert_eq!(invocations.load(Ordering::SeqCst), 3);
        assert_eq!(replies.len(), 3);
    }

    #[test]
    fn dispatch_resolves_mapping_id_against_peer_table() {
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register("sensors/temp", move |_q, _r| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let mut peer_table = HashMap::new();
        peer_table.insert(11u64, "sensors/temp".to_string());

        // mapping_id=11, no suffix → table lookup yields "sensors/temp"
        let req = request_query(1, 11, None);
        let mut replies = Vec::new();
        reg.dispatch_request(&req, &peer_table, &mut replies);
        assert_eq!(invocations.load(Ordering::SeqCst), 1);

        // mapping_id=11, suffix=Some(""/extra") → concat
        let req2 = request_query(2, 11, Some(""));
        reg.dispatch_request(&req2, &peer_table, &mut replies);
        assert_eq!(invocations.load(Ordering::SeqCst), 2);

        // mapping_id=99 not in table → silent drop, no callback
        let req3 = request_query(3, 99, None);
        reg.dispatch_request(&req3, &peer_table, &mut replies);
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            2,
            "unresolvable mapping id must drop silently without firing the callback"
        );
    }

    #[test]
    fn dispatch_threads_attachment_into_query_event_callback() {
        // R311v — attachment-bearing Query must surface its payload
        // through the handler's `QueryView::attachment()` accessor.
        // Pins the extract_query_attachment helper against
        // the zenoh-pico wire shape (ext_id=0x05, enc=ExtZbuf).
        let mut reg = QueryableRegistry::new();
        let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();
        reg.register("home/temp", move |event, _responder| {
            *cap_cb.lock().unwrap() = event.attachment().map(<[u8]>::to_vec);
        });

        let req = request_query_with_attachment(11, Some("home/temp"), b"hello-att");
        let mut replies = Vec::new();
        reg.dispatch_request(&req, &HashMap::new(), &mut replies);

        let got = captured.lock().unwrap().clone();
        assert_eq!(
            got.as_deref(),
            Some(&b"hello-att"[..]),
            "attachment ext payload must reach the callback verbatim"
        );
    }

    #[test]
    fn dispatch_query_without_extensions_threads_none_attachment() {
        // R311v regression guard — the pre-R311v default (always None)
        // must survive for Queries that carry no extensions chain at
        // all. Initialise the capture slot non-None so an accidental
        // skipped-write would surface as a false positive.
        let mut reg = QueryableRegistry::new();
        let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(Some(b"dirty".to_vec())));
        let cap_cb = captured.clone();
        reg.register("home/temp", move |event, _responder| {
            *cap_cb.lock().unwrap() = event.attachment().map(<[u8]>::to_vec);
        });

        let req = request_query(7, 0, Some("home/temp"));
        let mut replies = Vec::new();
        reg.dispatch_request(&req, &HashMap::new(), &mut replies);

        assert_eq!(
            *captured.lock().unwrap(),
            None,
            "no-attachment Query must yield QueryView::attachment() = None"
        );
    }

    #[test]
    fn dispatch_ignores_non_query_request_body_arms() {
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register("home/temp", move |_q, _r| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let mut replies = Vec::new();
        let put_req = request_put(1, "home/temp");
        reg.dispatch_request(&put_req, &HashMap::new(), &mut replies);

        assert_eq!(
            invocations.load(Ordering::SeqCst),
            0,
            "MsgPut body must not invoke queryable callbacks"
        );
        assert!(replies.is_empty());
    }

    // ── R223 Locality filter on QueryableRegistry ──

    #[test]
    fn query_register_with_locality_remote_fires_on_inbound_query() {
        use crate::locality::Locality;
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register_with_locality("home/temp", Locality::Remote, move |_q, _r| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let req = request_query(1, 0, Some("home/temp"));
        let mut replies = Vec::new();
        reg.dispatch_request(&req, &HashMap::new(), &mut replies);
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            1,
            "Locality::Remote fires on wire-arrived (remote) Query"
        );
    }

    #[test]
    fn query_register_with_locality_session_local_suppresses_inbound() {
        // Mirror of pubsub's
        // register_with_locality_session_local_does_not_fire_on_inbound.
        // R238 — self-query loopback landed via
        // [`QueryableRegistry::local_query`]; on the inbound
        // (wire-arrived) path the SessionLocal suppression still
        // holds (this test). The new loopback path is verified by
        // `local_query_fires_session_local_queryable` below.
        use crate::locality::Locality;
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register_with_locality("home/temp", Locality::SessionLocal, move |_q, _r| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let req = request_query(1, 0, Some("home/temp"));
        let mut replies = Vec::new();
        reg.dispatch_request(&req, &HashMap::new(), &mut replies);
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            0,
            "Locality::SessionLocal suppresses inbound (remote) Query pre-loopback"
        );
    }

    #[test]
    fn responder_send_reply_del_emits_del_arm() {
        let mut reg = QueryableRegistry::new();
        reg.register("clear/me", |_q, responder| {
            responder.reply_del();
        });

        let mut replies = Vec::new();
        reg.dispatch_request(
            &request_query(99, 0, Some("clear/me")),
            &HashMap::new(),
            &mut replies,
        );

        assert_eq!(replies.len(), 1);
        match &replies[0] {
            QueryReply::Reply {
                rid,
                keyexpr_literal,
                body,
                ..
            } => {
                assert_eq!(*rid, 99);
                assert_eq!(keyexpr_literal, "clear/me");
                assert_eq!(*body, ReplyBody::Del);
            }
            other => panic!("expected Reply::Del, got {other:?}"),
        }
    }

    #[test]
    fn responder_send_err_emits_err_with_encoding_tuple() {
        let mut reg = QueryableRegistry::new();
        reg.register("error/path", |_q, responder| {
            responder.reply_err(Some(4), Some("schema_v1"), b"oops");
        });

        let mut replies = Vec::new();
        reg.dispatch_request(
            &request_query(5, 0, Some("error/path")),
            &HashMap::new(),
            &mut replies,
        );

        assert_eq!(replies.len(), 1);
        match &replies[0] {
            QueryReply::Err {
                rid,
                keyexpr_literal,
                encoding,
                payload,
                ..
            } => {
                assert_eq!(*rid, 5);
                assert_eq!(keyexpr_literal, "error/path");
                assert_eq!(*encoding, Some((4, Some("schema_v1".to_string()))));
                assert_eq!(payload, b"oops");
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn responder_supports_multiple_replies_per_query() {
        let mut reg = QueryableRegistry::new();
        reg.register("series/data", |_q, responder| {
            responder.reply(b"sample-1");
            responder.reply(b"sample-2");
            responder.reply(b"sample-3");
        });

        let mut replies = Vec::new();
        reg.dispatch_request(
            &request_query(123, 0, Some("series/data")),
            &HashMap::new(),
            &mut replies,
        );

        assert_eq!(
            replies.len(),
            3,
            "queryable may emit many replies per query"
        );
        for (i, reply) in replies.iter().enumerate() {
            match reply {
                QueryReply::Reply { rid, body, .. } => {
                    assert_eq!(*rid, 123, "every reply echoes the same rid");
                    let expected = format!("sample-{}", i + 1);
                    assert_eq!(*body, ReplyBody::Put(expected.into_bytes()));
                }
                other => panic!("expected Reply::Put, got {other:?}"),
            }
        }
    }

    /// R121j-3c — `QueryResponder::with_responder` stamps the
    /// (zid, eid) tuple onto every subsequent `send_reply` /
    /// `send_reply_del` push. Pushes emitted before the call carry
    /// `responder = None`; pushes after carry `Some` with the same
    /// tuple. `clear_responder` reverts to `None` for later pushes.
    #[test]
    fn query_responder_with_responder_stamps_subsequent_replies() {
        let mut reg = QueryableRegistry::new();
        reg.register("home/temp", |_q, responder| {
            responder.reply(b"before");
            responder.with_responder(&[0xAA; 4], 11);
            responder.reply(b"stamped-put");
            responder.reply_del();
            responder.clear_responder();
            responder.reply(b"after-clear");
        });

        let mut replies = Vec::new();
        reg.dispatch_request(
            &request_query(7, 0, Some("home/temp")),
            &HashMap::new(),
            &mut replies,
        );

        assert_eq!(replies.len(), 4, "all four pushes recorded");
        let unstamped_expected: Option<(Vec<u8>, u32)> = None;
        let stamped_expected: Option<(Vec<u8>, u32)> = Some((vec![0xAA; 4], 11));
        match &replies[0] {
            QueryReply::Reply {
                body, responder, ..
            } => {
                assert_eq!(*body, ReplyBody::Put(b"before".to_vec()));
                assert_eq!(
                    *responder, unstamped_expected,
                    "pre-with_responder push has None"
                );
            }
            other => panic!("expected Reply::Put, got {other:?}"),
        }
        match &replies[1] {
            QueryReply::Reply {
                body, responder, ..
            } => {
                assert_eq!(*body, ReplyBody::Put(b"stamped-put".to_vec()));
                assert_eq!(
                    *responder, stamped_expected,
                    "post-with_responder send_reply stamped"
                );
            }
            other => panic!("expected Reply::Put, got {other:?}"),
        }
        match &replies[2] {
            QueryReply::Reply {
                body, responder, ..
            } => {
                assert_eq!(*body, ReplyBody::Del, "send_reply_del flows the same stamp");
                assert_eq!(
                    *responder, stamped_expected,
                    "send_reply_del stamped identically"
                );
            }
            other => panic!("expected Reply::Del, got {other:?}"),
        }
        match &replies[3] {
            QueryReply::Reply {
                body, responder, ..
            } => {
                assert_eq!(*body, ReplyBody::Put(b"after-clear".to_vec()));
                assert_eq!(
                    *responder, unstamped_expected,
                    "clear_responder reverts to None"
                );
            }
            other => panic!("expected Reply::Put, got {other:?}"),
        }
    }

    /// R121j-3c — `send_err` propagates the stamp identically to
    /// `send_reply`; the responder ext lives on the outer Response
    /// envelope so the Reply / Err inner-body discriminant is
    /// irrelevant to the stamp.
    #[test]
    fn query_responder_with_responder_stamps_err_payload() {
        let mut reg = QueryableRegistry::new();
        reg.register("error/path", |_q, responder| {
            responder.with_responder(&[0xCC; 2], 5);
            responder.reply_err(Some(4), Some("schema_v1"), b"oops");
        });

        let mut replies = Vec::new();
        reg.dispatch_request(
            &request_query(9, 0, Some("error/path")),
            &HashMap::new(),
            &mut replies,
        );

        assert_eq!(replies.len(), 1);
        match &replies[0] {
            QueryReply::Err {
                encoding,
                payload,
                responder,
                ..
            } => {
                assert_eq!(*encoding, Some((4, Some("schema_v1".to_string()))));
                assert_eq!(payload, b"oops");
                assert_eq!(*responder, Some((vec![0xCC; 2], 5_u32)));
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    /// R121j-3c — full end-to-end: `QueryResponder::with_responder` →
    /// `send_reply` → `QueryReply::into_response` emits Response wire
    /// bytes identical to the direct `ResponseReplyBuilder.responder`
    /// path. This locks the propagation chain against future drift
    /// between the user-facing handle and the wire-build layer.
    #[test]
    fn query_reply_into_response_with_responder_matches_builder() {
        let mut reg = QueryableRegistry::new();
        reg.register("home/temp", |_q, responder| {
            responder.with_responder(&[0xBB; 1], 1);
            responder.reply(b"hello");
        });

        let mut replies = Vec::new();
        reg.dispatch_request(
            &request_query(42, 0, Some("home/temp")),
            &HashMap::new(),
            &mut replies,
        );

        assert_eq!(replies.len(), 1);
        let via_chain = replies.pop().unwrap().into_response().wire();
        let via_builder = ResponseReplyBuilder::new(42, 0, Some("home/temp"), b"hello")
            .responder(&[0xBB; 1], 1)
            .build()
            .wire();
        assert_eq!(
            via_chain, via_builder,
            "QueryResponder.with_responder → send_reply → into_response must equal the direct \
             ResponseReplyBuilder.responder path byte-for-byte"
        );
    }

    #[test]
    fn query_reply_into_response_put_path_round_trips_via_builder() {
        let reply = QueryReply::Reply {
            rid: 42,
            keyexpr_literal: "home/temp".to_string(),
            body: ReplyBody::Put(b"hello".to_vec()),
            responder: None,
        };
        let response = reply.into_response();
        // The Response should encode to the same bytes as the
        // ResponseReplyBuilder direct path with the same args.
        let via_builder = ResponseReplyBuilder::new(42, 0, Some("home/temp"), b"hello")
            .build()
            .wire();
        assert_eq!(
            response.wire(),
            via_builder,
            "QueryReply::into_response (Put) must match the direct builder path byte-for-byte"
        );
    }

    #[test]
    fn query_reply_into_response_del_path_flips_inner_arm() {
        let reply = QueryReply::Reply {
            rid: 42,
            keyexpr_literal: "clear/me".to_string(),
            body: ReplyBody::Del,
            responder: None,
        };
        let response = reply.into_response();
        let via_builder = ResponseReplyBuilder::new(42, 0, Some("clear/me"), &[])
            .reply_del()
            .build()
            .wire();
        assert_eq!(
            response.wire(),
            via_builder,
            "QueryReply::into_response (Del) must match builder.reply_del path"
        );
    }

    #[test]
    fn query_reply_into_response_err_path_threads_encoding_tuple() {
        let reply = QueryReply::Err {
            rid: 42,
            keyexpr_literal: "error/path".to_string(),
            encoding: Some((4, Some("schema_v1".to_string()))),
            payload: b"oops".to_vec(),
            responder: None,
        };
        let response = reply.into_response();
        let via_builder = ResponseErrBuilder::new(42, 0, Some("error/path"), b"oops")
            .encoding(4, Some("schema_v1"))
            .build()
            .wire();
        assert_eq!(
            response
                .wire(),
            via_builder,
            "QueryReply::into_response (Err) must match the builder path with the same encoding tuple"
        );
    }

    #[test]
    fn dispatch_messages_emits_final_for_each_matched_request() {
        let mut reg = QueryableRegistry::new();
        reg.register("home/temp", |_q, responder| {
            responder.reply(b"21.0");
        });

        // Two Query requests on the matched keyexpr + one unmatched.
        let messages = vec![
            NetworkMessage::Request(Box::new(request_query(10, 0, Some("home/temp")))),
            NetworkMessage::Request(Box::new(request_query(11, 0, Some("home/temp")))),
            NetworkMessage::Request(Box::new(request_query(12, 0, Some("garden/temp")))),
        ];
        let mut replies = Vec::new();
        let mut finals = Vec::new();
        reg.dispatch_messages(&messages, &HashMap::new(), &mut replies, &mut finals);

        assert_eq!(replies.len(), 2, "two matched Queries produce two Replies");
        assert_eq!(
            finals,
            vec![10u64, 11u64],
            "one Final per matched rid, unmatched rid 12 dropped"
        );
    }

    #[test]
    fn dispatch_messages_skips_final_when_no_queryable_matched() {
        let mut reg = QueryableRegistry::new();
        reg.register("home/temp", |_q, responder| {
            responder.reply(b"21.0");
        });

        let messages = vec![NetworkMessage::Request(Box::new(request_query(
            7,
            0,
            Some("garden/humid"),
        )))];
        let mut replies = Vec::new();
        let mut finals = Vec::new();
        reg.dispatch_messages(&messages, &HashMap::new(), &mut replies, &mut finals);
        assert!(replies.is_empty());
        assert!(
            finals.is_empty(),
            "no matched queryable -> no Final to terminate"
        );
    }

    #[test]
    fn dispatch_messages_skips_final_when_keyexpr_unresolvable() {
        let mut reg = QueryableRegistry::new();
        reg.register("sensors/temp", |_q, responder| {
            responder.reply(b"21.0");
        });

        // mapping_id=99 not in peer table -> dispatch drops silently.
        let messages = vec![NetworkMessage::Request(Box::new(request_query(
            99, 99, None,
        )))];
        let mut replies = Vec::new();
        let mut finals = Vec::new();
        reg.dispatch_messages(&messages, &HashMap::new(), &mut replies, &mut finals);
        assert!(replies.is_empty());
        assert!(
            finals.is_empty(),
            "un-resolvable mapping id must not enqueue a Final"
        );
    }

    #[test]
    fn dispatch_messages_ignores_push_response_declare_variants() {
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register("**", move |_q, _r| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        // A Request with a non-Query body arm (MsgPut) and a
        // hypothetical Push routed through this registry must not
        // invoke the queryable callback or schedule a Final.
        let messages = vec![NetworkMessage::Request(Box::new(request_put(
            1,
            "home/temp",
        )))];
        let mut replies = Vec::new();
        let mut finals = Vec::new();
        reg.dispatch_messages(&messages, &HashMap::new(), &mut replies, &mut finals);
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert!(replies.is_empty());
        assert!(finals.is_empty());
    }

    #[cfg(feature = "codec-response-final")]
    #[test]
    fn response_final_for_uses_default_header_and_explicit_rid() {
        let final_msg = response_final_for(123);
        assert_eq!(final_msg.header, 0x1a, "header = _Z_MID_N_RESPONSE_FINAL");
        assert_eq!(final_msg.request_id, 123);
        assert!(final_msg.extensions.is_none(), "no envelope ext today");
    }

    #[test]
    fn multiple_queryables_match_same_keyexpr_fire_in_registration_order() {
        let mut reg = QueryableRegistry::new();
        let order = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
        let order_a = order.clone();
        let id_a = reg.register("metrics/cpu", move |_q, responder| {
            order_a.lock().unwrap().push(1);
            responder.reply(b"first");
        });
        let order_b = order.clone();
        let id_b = reg.register("metrics/cpu", move |_q, responder| {
            order_b.lock().unwrap().push(2);
            responder.reply(b"second");
        });
        assert_ne!(id_a, id_b);

        let mut replies = Vec::new();
        reg.dispatch_request(
            &request_query(1, 0, Some("metrics/cpu")),
            &HashMap::new(),
            &mut replies,
        );
        assert_eq!(
            *order.lock().unwrap(),
            vec![1, 2],
            "callbacks fire in registration order"
        );
        assert_eq!(replies.len(), 2);
    }

    // ── R238 Self-query loopback (local_query) ──

    #[test]
    fn local_query_fires_any_locality_queryable() {
        // Locality::Any queryables fire on both wire-arrived and
        // loopback paths. The loopback path runs through
        // fire_matching_queryables(is_remote=false) which selects
        // allows_local() — true for Any. Mirrors pubsub's
        // local_publish_fires_any_locality_subscriber.
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register("home/temp", move |_q, responder| {
            counter.fetch_add(1, Ordering::SeqCst);
            responder.reply(b"22.5");
        });

        let mut replies = Vec::new();
        let query = Query::default().into_owned();
        reg.local_query(/*rid=*/ 7, "home/temp", &query, &mut replies);

        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(replies.len(), 1);
        match &replies[0] {
            QueryReply::Reply {
                rid,
                keyexpr_literal,
                body,
                ..
            } => {
                assert_eq!(*rid, 7, "rid echoed from local_query call");
                assert_eq!(
                    keyexpr_literal, "home/temp",
                    "caller-supplied literal echoed"
                );
                assert_eq!(*body, ReplyBody::Put(b"22.5".to_vec()));
            }
            other => panic!("expected Reply::Put, got {other:?}"),
        }
    }

    #[test]
    fn local_query_fires_session_local_queryable() {
        // Locality::SessionLocal is the canonical loopback-only
        // setting: allows_local() true, allows_remote() false. A
        // SessionLocal queryable was dormant pre-R238; R238 activates
        // it through local_query. Mirrors pubsub's
        // local_publish_fires_session_local_subscriber.
        use crate::locality::Locality;
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register_with_locality("home/temp", Locality::SessionLocal, move |_q, responder| {
            counter.fetch_add(1, Ordering::SeqCst);
            responder.reply(b"22.5");
        });

        let mut replies = Vec::new();
        let query = Query::default().into_owned();
        reg.local_query(1, "home/temp", &query, &mut replies);

        assert_eq!(
            invocations.load(Ordering::SeqCst),
            1,
            "Locality::SessionLocal fires on R238 loopback (is_remote=false)"
        );
        assert_eq!(replies.len(), 1);
    }

    #[test]
    fn local_query_suppresses_remote_only_queryable() {
        // Locality::Remote is the wire-only setting: allows_remote()
        // true, allows_local() false. A Remote queryable must never
        // see a self-query loopback — mirrors zenoh-pico's
        // _z_locality_allows_local(Z_LOCALITY_REMOTE) returning
        // false. Mirrors pubsub's
        // local_publish_suppresses_remote_only_subscriber.
        use crate::locality::Locality;
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register_with_locality("home/temp", Locality::Remote, move |_q, _responder| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let mut replies = Vec::new();
        let query = Query::default().into_owned();
        reg.local_query(1, "home/temp", &query, &mut replies);

        assert_eq!(
            invocations.load(Ordering::SeqCst),
            0,
            "Locality::Remote suppresses R238 loopback"
        );
        assert!(replies.is_empty());
    }

    #[test]
    fn local_query_returns_no_replies_when_pattern_mismatches() {
        // A loopback whose literal does not match any registered
        // queryable pattern is a silent no-op — the registry yields
        // nothing rather than failing. Mirrors pubsub's
        // local_publish_returns_zero_when_pattern_mismatches.
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register("home/temp", move |_q, _responder| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        let mut replies = Vec::new();
        let query = Query::default().into_owned();
        reg.local_query(1, "home/humid", &query, &mut replies);

        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert!(replies.is_empty());
    }

    #[test]
    fn dispatch_request_still_treats_inbound_as_remote_after_r238_split() {
        // R238 invariance check: extracting the fan-out body into
        // fire_matching_queryables MUST NOT change dispatch_request's
        // wire-arrived semantics. A Locality::SessionLocal queryable
        // continues to be suppressed when the Request arrives via the
        // wire path (the pre-R238 surface contract every existing
        // integration test depends on). The new local_query API is
        // the only entry point that flips the is_remote flag.
        use crate::locality::Locality;
        let mut reg = QueryableRegistry::new();
        let invocations = Arc::new(AtomicUsize::new(0));
        let counter = invocations.clone();
        reg.register_with_locality(
            "home/temp",
            Locality::SessionLocal,
            move |_q, _responder| {
                counter.fetch_add(1, Ordering::SeqCst);
            },
        );

        let req = request_query(1, 0, Some("home/temp"));
        let mut replies = Vec::new();
        reg.dispatch_request(&req, &HashMap::new(), &mut replies);

        assert_eq!(
            invocations.load(Ordering::SeqCst),
            0,
            "dispatch_request preserves the remote-origin filter \
             (Locality::SessionLocal stays suppressed on wire arrival)"
        );
    }

    /// R311gb (Track 2) — the no-heap fire entry `dispatch_borrowed` has
    /// behaviour the wire path does NOT exercise: the wire
    /// `fire_matching_queryables` builds a fresh `QueryResponder` per
    /// matched queryable, whereas `dispatch_borrowed` shares ONE
    /// caller-supplied `&mut dyn ReplyOut` across every match (the MCU
    /// consumer owns its reply sink's lifecycle). This proves both
    /// matched queryables fire through the single shared reply_out.
    #[test]
    fn dispatch_borrowed_shares_one_reply_out_across_matched_queryables() {
        let mut reg = QueryableRegistry::new();
        reg.register("a/**", |_q, r: &mut dyn ReplyOut| r.reply(b"from-wild"));
        reg.register("a/b", |_q, r: &mut dyn ReplyOut| r.reply(b"from-exact"));

        let mut replies: Vec<QueryReply> = Vec::new();
        let mut responder = QueryResponder {
            rid: 7,
            keyexpr_literal: "a/b".to_string(),
            replies: &mut replies,
            responder: None,
        };
        let fired = reg.dispatch_borrowed(
            &BorrowedQuery {
                keyexpr: "a/b",
                parameters: None,
                attachment: None,
                rid: 7,
            },
            &mut responder,
            /* is_remote = */ true,
        );
        assert_eq!(
            fired, 2,
            "both matching queryables fire via the no-heap entry"
        );
        assert_eq!(
            replies.len(),
            2,
            "the single shared reply_out accumulates both replies"
        );
    }
}

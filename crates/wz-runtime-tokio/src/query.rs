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

use std::collections::HashMap;

use wz_codecs::ext_entry::ExtEntryVariant;
use wz_codecs::query::Query;
use wz_codecs::request::{Request, RequestVariant};
// R311r — `Response` + the `ResponseReplyBuilder` / `ResponseErrBuilder`
// pair (from session_glue) gate on `codec-response`. `QueryReply::into_response`
// is the only use site for these symbols inside this module, so the
// imports follow that method's gate (see the method's `#[cfg]` below).
// The dispatch / loopback / registration paths only stage entries into
// `Vec<QueryReply>` and do not need codec-response, so the module body
// otherwise compiles unconditionally once `lib.rs` ungates `pub mod query`.
#[cfg(feature = "codec-response")]
use wz_codecs::response::Response;
use wz_codecs::wireexpr::WireexprVariant;

#[cfg(feature = "codec-response-final")]
use wz_codecs::response_final::ResponseFinal;

use crate::pubsub::keyexpr_pattern_matches;
use crate::query_event::{QueryEvent, ReplyEmitter};
use crate::session_glue::{DriverLoopOutcome, IterationEvent, NetworkMessage};
#[cfg(feature = "codec-response")]
use crate::session_glue::{ResponseErrBuilder, ResponseReplyBuilder};

/// Boxed callback invoked when an inbound `Request(Query)`'s
/// keyexpr matches a registered queryable. The callback receives a
/// [`QueryEvent`] projection of the inbound query (resolved keyexpr +
/// raw parameters + attachment + rid) and a [`ReplyEmitter`] for
/// emitting zero or more Replies / Errs.
///
/// R311r — signature switched from
/// `FnMut(&wz_codecs::query::Query, &mut QueryResponder<'_>)` to
/// `FnMut(&QueryEvent<'_>, &mut ReplyEmitter<'_>)` so the application
/// callback no longer directly references the wz-codecs wire types.
/// The wrappers are unconditional even in `query-queryable`-OFF
/// builds (the signature lives on a type-ungated
/// `Session::declare_queryable` whose OFF branch returns
/// `Err(QueryableAliasError::FeatureDisabled)` before any callback is
/// reached); see [`crate::query_event`] for the wrapper design
/// rationale and the no-op fall-through on the OFF build.
pub type QueryableCallback =
    Box<dyn FnMut(&QueryEvent<'_>, &mut ReplyEmitter<'_>) + Send + 'static>;

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
fn extract_query_attachment(query: &Query) -> Option<&[u8]> {
    #[cfg(not(feature = "query-attachment"))]
    {
        let _ = query;
        return None;
    }
    #[cfg(feature = "query-attachment")]
    {
        let exts = query.extensions.as_ref()?;
        for ext in exts {
            if ext.ext_id() == 0x05 {
                if let ExtEntryVariant::CodecZenohExtZbuf(zbuf) = &ext.body {
                    return Some(zbuf.value.as_slice());
                }
            }
        }
        None
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

struct Queryable {
    id: QueryableId,
    /// Pre-split pattern chunks. Same shape as
    /// [`crate::pubsub::SubscriberRegistry`]: literal chunks (incl.
    /// empty for `a//b`), `*` (single-chunk wildcard), `**` (zero-or-
    /// more-chunk wildcard), or a chunk containing `$*` (intra-chunk
    /// substring wildcard, R220). Matching is performed by the
    /// shared [`keyexpr_pattern_matches`] helper.
    pattern_chunks: Vec<String>,
    /// R223 — locality filter applied before the callback fires.
    /// Identical semantics to
    /// [`crate::pubsub::SubscriberRegistry`] —
    /// `dispatch_request` consults `allows_remote()` since every
    /// Request reaching it has been parsed off the wire.
    allowed_origin: crate::locality::Locality,
    callback: QueryableCallback,
}

/// Body arm for a `QueryReply::Reply` — mirrors zenoh-pico's
/// `_z_reply` inner `_z_push_body_t` dispatch on `_z_is_put` (Put
/// path = data Reply; Del path = delete-keyexpr Reply).
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
    pub fn into_response(self) -> Response {
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

/// Queryable table backing the inbound `Request(Query)` → callback
/// dispatch. `!Sync` by construction; cross-task sharing goes
/// through `Arc<Mutex<…>>`. See module-level docs for scope.
pub struct QueryableRegistry {
    queryables: Vec<Queryable>,
    next_id: u64,
}

impl Default for QueryableRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryableRegistry {
    /// New empty registry. Queryable ids start at 1 so 0 stays
    /// available as a sentinel "no queryable" value for any caller-
    /// side wrapper that needs one.
    pub fn new() -> Self {
        Self {
            queryables: Vec::new(),
            next_id: 1,
        }
    }

    /// Register a queryable for a keyexpr pattern. Pattern syntax
    /// matches zenoh chunk wildcards (same as
    /// [`crate::pubsub::SubscriberRegistry::register`]): `/`-separated
    /// chunks where each chunk is a literal, `*` (single chunk), `**`
    /// (zero or more chunks), or contains the `$*` intra-chunk
    /// substring wildcard (R220). The returned [`QueryableId`] is
    /// stable until [`Self::unregister`] is called. Duplicate
    /// patterns produce distinct queryables — `dispatch_request`
    /// fires every matching callback in registration order.
    ///
    /// R221 — the pattern is canonicalized via
    /// [`canonize_keyexpr`](crate::keyexpr_canon::canonize_keyexpr)
    /// before being split into chunks, so the stored form agrees
    /// byte-for-byte with the canonical wire form. Structurally
    /// invalid patterns fall back to the raw form (non-breaking)
    /// with a `log::warn!` notice.
    ///
    /// R223 — defaults [`Locality::Any`](crate::locality::Locality);
    /// use [`register_with_locality`](Self::register_with_locality)
    /// to restrict to one origin class.
    pub fn register(
        &mut self,
        keyexpr_pattern: impl Into<String>,
        callback: impl FnMut(&QueryEvent<'_>, &mut ReplyEmitter<'_>) + Send + 'static,
    ) -> QueryableId {
        self.register_with_locality(keyexpr_pattern, crate::locality::Locality::Any, callback)
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
        callback: impl FnMut(&QueryEvent<'_>, &mut ReplyEmitter<'_>) + Send + 'static,
    ) -> QueryableId {
        let id = QueryableId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        let raw = keyexpr_pattern.into();
        let canonical = match crate::keyexpr_canon::canonize_keyexpr(&raw) {
            Ok(canon) => canon,
            Err(err) => {
                log::warn!(
                    "QueryableRegistry::register: keyexpr `{raw}` is not canonical \
                     ({err}); storing raw form."
                );
                raw
            }
        };
        let pattern_chunks: Vec<String> = canonical.split('/').map(String::from).collect();
        self.queryables.push(Queryable {
            id,
            pattern_chunks,
            allowed_origin,
            callback: Box::new(callback),
        });
        id
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
    pub fn dispatch_request(
        &mut self,
        request: &Request,
        peer_keyexpr_table: &HashMap<u64, String>,
        replies: &mut Vec<QueryReply>,
    ) {
        // Only the Query body arm triggers application-visible
        // dispatch — see scope note above.
        let query = match &request.body {
            RequestVariant::CodecZenohQuery(q) => q,
            _ => return,
        };

        let (id, suffix_opt) = match &request.keyexpr.body {
            WireexprVariant::WireexprLocal(arm) => (arm.id, arm.suffix.as_deref()),
            WireexprVariant::WireexprNonlocal(arm) => (arm.id, arm.suffix.as_deref()),
        };
        let resolved: String = if id == 0 {
            match suffix_opt {
                Some(s) => s.to_string(),
                None => return,
            }
        } else {
            let base = match peer_keyexpr_table.get(&id) {
                Some(s) => s.clone(),
                None => return,
            };
            match suffix_opt {
                Some(s) => {
                    let mut out = base;
                    out.push_str(s);
                    out
                }
                None => base,
            }
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
    pub fn local_query(
        &mut self,
        rid: u64,
        keyexpr: &str,
        query: &Query,
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
    fn fire_matching_queryables(
        &mut self,
        rid: u64,
        keyexpr: &str,
        query: &Query,
        replies: &mut Vec<QueryReply>,
        is_remote: bool,
    ) {
        // R311r — build the consumer-facing [`QueryEvent`] projection
        // ONCE per matched queryable (the parameters byte slice and
        // attachment view are stable across all matched callbacks for
        // a single inbound query). The keyexpr field re-borrows the
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
        for queryable in &mut self.queryables {
            let allowed = if is_remote {
                queryable.allowed_origin.allows_remote()
            } else {
                queryable.allowed_origin.allows_local()
            };
            if !allowed {
                continue;
            }
            let chunks: Vec<&str> = queryable
                .pattern_chunks
                .iter()
                .map(String::as_str)
                .collect();
            if keyexpr_pattern_matches(&chunks, keyexpr) {
                let mut responder = QueryResponder {
                    rid,
                    keyexpr_literal: keyexpr.to_string(),
                    replies,
                    responder: None,
                };
                // R311r — wrap the internal QueryResponder in the
                // consumer-facing ReplyEmitter so the callback sees
                // the wrapper-level API surface. The wrapper holds a
                // mutable borrow of `responder` for the duration of
                // the callback call; the borrow ends when the
                // emitter is dropped at the end of this scope.
                let event = QueryEvent {
                    keyexpr,
                    parameters: parameters_view,
                    attachment: attachment_view,
                    rid,
                };
                {
                    let mut emitter = ReplyEmitter::from_responder(&mut responder);
                    (queryable.callback)(&event, &mut emitter);
                }
                // Responder dropped here; the borrow of `replies`
                // ends so the loop can re-borrow for the next match.
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
        // R311r — `NetworkMessage::Request` is cfg-gated on
        // `codec-request`; gate the inner-codec dispatch arm to match
        // so a `codec-request`-OFF build elides the Request path and
        // the function body compiles to a no-op loop. The unused
        // parameters in the OFF arm are silenced via `let _ = ...`
        // so the signature stays stable (signature-stability per
        // R311g1 principle).
        #[cfg(not(feature = "codec-request"))]
        let _ = (peer_keyexpr_table, pending_replies, pending_final_rids);
        for message in messages {
            match message {
                #[cfg(feature = "codec-request")]
                NetworkMessage::Request(req) => {
                    // Only Query bodies are queryable-visible; only
                    // resolvable keyexprs schedule a Final. We detect
                    // both by snapshotting the replies length before/
                    // after dispatch_request — a delta of zero means
                    // either non-Query body, un-resolvable keyexpr, or
                    // no queryable matched. In all three cases we owe
                    // no Final (the requester sees no Reply chain at
                    // all from this peer for this rid).
                    let before = pending_replies.len();
                    self.dispatch_request(req, peer_keyexpr_table, pending_replies);
                    if pending_replies.len() > before {
                        pending_final_rids.push(req.rid);
                    }
                }
                _ => {}
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
#[cfg(feature = "codec-response-final")]
pub fn response_final_for(rid: u64) -> ResponseFinal {
    ResponseFinal {
        request_id: rid,
        // header = 0x1a (_Z_MID_N_RESPONSE_FINAL) and extensions =
        // None come from ResponseFinal::default() (see
        // wz-codecs/.../out/response_final.rs:38-47); the spread
        // keeps this helper resilient to future field additions
        // that land with sensible defaults.
        ..ResponseFinal::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use wz_codecs::ext_entry::ExtEntry;
    use wz_codecs::ext_zbuf::ExtZbuf;
    use wz_codecs::msg_put::MsgPut;
    use wz_codecs::wireexpr::Wireexpr;
    use wz_codecs::wireexpr_local::WireexprLocal;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    fn request_query(rid: u64, mapping_id: u64, suffix: Option<&str>) -> Request {
        // Construct a minimal Request whose body is a default Query.
        // The Local arm (zero-init mapping = LOCAL on the zenoh-pico
        // side, mirrored by push_with_keyexpr at pubsub.rs:398-415) is
        // the canonical default; both arms surface (id, suffix)
        // identically through dispatch's WireexprVariant match
        // (pubsub.rs:292-294), so the test only needs one arm to
        // exercise the dispatch logic.
        let suffix_owned = suffix.map(str::to_string);
        let suffix_len = suffix.map(|s| s.len() as u64);
        let keyexpr = Wireexpr {
            body: wz_codecs::wireexpr::WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_owned,
            }),
        };
        Request {
            header: 0x1c, // _Z_MID_N_REQUEST default
            rid,
            keyexpr,
            extensions: None,
            body: RequestVariant::CodecZenohQuery(Query::default()),
        }
    }

    /// R311v test helper — construct an inbound Query whose
    /// extensions chain carries a single attachment ext
    /// (`_Z_MSG_EXT_ENC_ZBUF | 0x05` wire shape per zenoh-pico
    /// `vendor/zenoh-pico/src/protocol/codec/message.c:447`). The
    /// `Query.header` `0x80` bit is set so a hypothetical round-trip
    /// through `Query::decode` would surface the extensions vec; the
    /// dispatch path only reads `query.extensions` directly so the
    /// flag is purely for authoring fidelity.
    fn request_query_with_attachment(rid: u64, suffix: Option<&str>, attachment: &[u8]) -> Request {
        let suffix_owned = suffix.map(str::to_string);
        let suffix_len = suffix.map(|s| s.len() as u64);
        let keyexpr = Wireexpr {
            body: wz_codecs::wireexpr::WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len,
                suffix: suffix_owned,
            }),
        };
        let mut ext = ExtEntry::default();
        ext.set_ext_id(0x05);
        ext.set_enc(2);
        ext.body = ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
            value_len: attachment.len() as u64,
            value: attachment.to_vec(),
        });
        let query = Query {
            header: Query::default().header | 0x80,
            extensions: Some(vec![ext]),
            ..Query::default()
        };
        Request {
            header: 0x1c,
            rid,
            keyexpr,
            extensions: None,
            body: RequestVariant::CodecZenohQuery(query),
        }
    }

    fn request_put(rid: u64, suffix: &str) -> Request {
        let keyexpr = Wireexpr {
            body: wz_codecs::wireexpr::WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix.to_string()),
            }),
        };
        Request {
            header: 0x1c,
            rid,
            keyexpr,
            extensions: None,
            body: RequestVariant::CodecZenohMsgPut(MsgPut::default()),
        }
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
        // through QueryEvent.attachment on the consumer-facing
        // callback. Pins the extract_query_attachment helper against
        // the zenoh-pico wire shape (ext_id=0x05, enc=ExtZbuf).
        let mut reg = QueryableRegistry::new();
        let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();
        reg.register("home/temp", move |event, _responder| {
            *cap_cb.lock().unwrap() = event.attachment.map(<[u8]>::to_vec);
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
            *cap_cb.lock().unwrap() = event.attachment.map(<[u8]>::to_vec);
        });

        let req = request_query(7, 0, Some("home/temp"));
        let mut replies = Vec::new();
        reg.dispatch_request(&req, &HashMap::new(), &mut replies);

        assert_eq!(
            *captured.lock().unwrap(),
            None,
            "no-attachment Query must yield QueryEvent.attachment = None"
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
        let via_chain = replies.pop().unwrap().into_response().encode_to_vec();
        let via_builder = ResponseReplyBuilder::new(42, 0, Some("home/temp"), b"hello")
            .responder(&[0xBB; 1], 1)
            .build()
            .encode_to_vec();
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
            .encode_to_vec();
        assert_eq!(
            response.encode_to_vec(),
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
            .encode_to_vec();
        assert_eq!(
            response.encode_to_vec(),
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
            .encode_to_vec();
        assert_eq!(
            response.encode_to_vec(),
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
        let query = Query::default();
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
        let query = Query::default();
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
        let query = Query::default();
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
        let query = Query::default();
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
}

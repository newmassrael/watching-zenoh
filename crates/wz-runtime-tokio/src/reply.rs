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

use std::collections::HashMap;

use wz_codecs::reply::ReplyVariant;
use wz_codecs::response::{Response, ResponseVariant};
#[cfg(feature = "codec-response-final")]
use wz_codecs::response_final::ResponseFinal;
use wz_codecs::wireexpr::WireexprVariant;

// R307 — `query-queryable` gates the producer-side `QueryReply` enum
// because it lives in `crate::query`, which is gated on the same
// feature. The wire-receive path inside this module does not need
// these types — only the loopback bridge (`impl From<QueryReply> for
// InboundReply`) and the `deliver_local_*` helpers below do. A
// `query-reply` consumer that wires no in-process queryable still
// gets the wire-side `Response` dispatch path with the loopback
// bridge elided.
#[cfg(feature = "query-queryable")]
use crate::query::{QueryReply, ReplyBody};
use crate::session_glue::{DriverLoopOutcome, IterationEvent, NetworkMessage};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundReplyBody {
    /// Successful data reply — `MsgPut` inner body. Payload bytes
    /// flow through verbatim. Encoding / timestamp side-bands on the
    /// MsgPut envelope are not surfaced in the AP MVP (callbacks that
    /// need them peek into the wire-form codec directly; R121j-tstamp
    /// + a future encoding setter expose them at this layer).
    Put { payload: Vec<u8> },
    /// Delete-keyexpr reply — `MsgDel` inner body. Carries no
    /// payload bytes (the wire-form `MsgDel` body has only a header
    /// + optional timestamp + ext chain).
    Del,
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
#[cfg(feature = "query-queryable")]
impl From<QueryReply> for InboundReply {
    fn from(reply: QueryReply) -> Self {
        match reply {
            QueryReply::Reply {
                rid,
                keyexpr_literal,
                body,
                responder: _,
            } => {
                let body = match body {
                    ReplyBody::Put(payload) => InboundReplyBody::Put { payload },
                    ReplyBody::Del => InboundReplyBody::Del,
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

/// Boxed callback invoked on each inbound `Response(Reply|Err)` whose
/// `request_id` matches a registered pending z_get. Fires multiple
/// times per registration (zenoh-pico "many Reply" semantics). The
/// callback receives `&InboundReply` by reference so the registry
/// can fan to multiple registrations sharing the same rid without
/// cloning the payload — duplicate-rid registration is explicitly
/// supported (the registry assigns no uniqueness constraint on rid;
/// multiple pending entries fire in registration order).
pub type ReplyCallback = Box<dyn FnMut(&InboundReply) + Send + 'static>;

/// Boxed callback invoked exactly once per pending z_get when the
/// matching `ResponseFinal` arrives. After firing, the pending entry
/// is auto-removed from the registry — subsequent stray
/// `Response(Reply|Err)` records for the same rid (which would be a
/// peer-protocol violation per zenoh-pico's "exactly one Final
/// terminates the chain") drop silently because the lookup misses.
pub type FinalCallback = Box<dyn FnMut(u64) + Send + 'static>;

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

struct Pending {
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
    on_reply: ReplyCallback,
    on_final: FinalCallback,
}

/// Reply table backing the inbound `Response(Reply|Err)` and
/// `ResponseFinal` → callback dispatch. `!Sync` by construction;
/// cross-task sharing goes through `Arc<Mutex<…>>`. See module-level
/// docs for scope.
pub struct ReplyRegistry {
    pending: Vec<Pending>,
}

impl Default for ReplyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplyRegistry {
    /// New empty registry. Pending entries are stored in a `Vec` so
    /// duplicate-rid registrations (an application registering two
    /// independent z_gets that happen to share the same rid via a
    /// careless rid allocator) fire in registration order; the
    /// registry imposes no uniqueness on rid. Callers that need
    /// unique rids manage that at the rid-allocator layer.
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// Register a pending z_get. The `on_reply` callback fires once
    /// per inbound `Response(Reply|Err)` whose `request_id == rid`;
    /// the `on_final` callback fires exactly once — when the entry's
    /// `expected_finals` counter reaches zero. At that point the
    /// entry is auto-unregistered.
    ///
    /// `expected_finals` mirrors zenoh-pico's
    /// `_z_pending_query_t._remaining_finals` slot
    /// (`vendor/zenoh-pico/src/session/query.c:222-256`): one for a
    /// pure-wire (`Locality::Remote`) z_get expecting one peer
    /// `ResponseFinal`; one for a pure-loopback
    /// (`Locality::SessionLocal`) z_get expecting one synthetic
    /// final from [`Self::deliver_local_final`]; two for a
    /// `Locality::Any` z_get with at least one local queryable AND a
    /// wire branch. Producers feeding this registry know which case
    /// they are in at register-time because they own the
    /// `allowed_destination` predicate.
    ///
    /// The returned [`ReplyHandle`] is the rid wrapped — exposed so
    /// callers that allocate rids opaquely (e.g. a future
    /// `z_get_builder` adapter) can carry the rid without leaking
    /// the integer all the way back to user code.
    pub fn register(
        &mut self,
        rid: u64,
        expected_finals: u32,
        deadline_ms: Option<u64>,
        on_reply: impl FnMut(&InboundReply) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> ReplyHandle {
        self.pending.push(Pending {
            rid,
            remaining_finals: expected_finals,
            deadline_ms,
            on_reply: Box::new(on_reply),
            on_final: Box::new(on_final),
        });
        ReplyHandle(rid)
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
    pub fn dispatch_response(
        &mut self,
        response: &Response,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        let resolved = match resolve_wireexpr(&response.keyexpr.body, peer_keyexpr_table) {
            Some(s) => s,
            None => return,
        };
        let body = match &response.body {
            ResponseVariant::CodecZenohReply(reply) => match &reply.body {
                ReplyVariant::CodecZenohMsgPut(put) => InboundReplyBody::Put {
                    payload: put.payload.clone(),
                },
                ReplyVariant::CodecZenohMsgDel(_) => InboundReplyBody::Del,
                // Default arm carries a runtime tag whose MID falls
                // outside {MsgPut, MsgDel}. zenoh-pico's inner-body
                // dispatch treats this as a wire-spec violation; the
                // AP MVP path mirrors that by dropping silently.
                ReplyVariant::Default { .. } => return,
            },
            ResponseVariant::CodecZenohErr(err) => {
                let encoding = err
                    .encoding
                    .as_ref()
                    .map(|e| (e.packed_id, e.schema.clone()));
                InboundReplyBody::Err {
                    encoding,
                    payload: err.payload.clone(),
                }
            }
            // See ResponseVariant::Default rationale on Reply arm.
            ResponseVariant::Default { .. } => return,
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
    #[cfg(feature = "codec-response-final")]
    pub fn dispatch_response_final(&mut self, response_final: &ResponseFinal) {
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
    pub fn deliver_local_reply(&mut self, inbound: &InboundReply) {
        self.fire_replies_for(inbound);
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
        let mut fired: Vec<Pending> = Vec::new();
        let mut keep: Vec<Pending> = Vec::with_capacity(self.pending.len());
        for entry in self.pending.drain(..) {
            let expired = matches!(entry.deadline_ms, Some(d) if d <= now_ms);
            if expired {
                fired.push(entry);
            } else {
                keep.push(entry);
            }
        }
        self.pending = keep;
        let swept = fired.len();
        for mut entry in fired {
            let rid = entry.rid;
            (entry.on_final)(rid);
        }
        swept
    }

    /// R239 — shared reply fan body for wire ([`Self::dispatch_response`])
    /// and loopback ([`Self::deliver_local_reply`]) origins. Each
    /// pending entry whose `rid == inbound.rid` fires its `on_reply`
    /// callback once; the entry stays in the table (only `Final`
    /// removes it). Mirrors the R238 `fire_matching_queryables` split
    /// on the queryable side.
    fn fire_replies_for(&mut self, inbound: &InboundReply) {
        for pending in &mut self.pending {
            if pending.rid == inbound.rid {
                (pending.on_reply)(inbound);
            }
        }
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
        let mut fired: Vec<Pending> = Vec::new();
        let mut keep: Vec<Pending> = Vec::with_capacity(self.pending.len());
        for mut entry in self.pending.drain(..) {
            if entry.rid == rid && entry.remaining_finals > 0 {
                entry.remaining_finals -= 1;
                if entry.remaining_finals == 0 {
                    fired.push(entry);
                    continue;
                }
            }
            keep.push(entry);
        }
        self.pending = keep;
        for mut entry in fired {
            (entry.on_final)(rid);
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
    pub fn dispatch_messages(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        for message in messages {
            match message {
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

/// Shared keyexpr resolution helper. Mirrors
/// [`crate::pubsub::SubscriberRegistry::resolve_wireexpr`] /
/// [`crate::query::QueryableRegistry::dispatch_request`]'s inline
/// resolution: when `id == 0` the suffix is used verbatim; when
/// `id != 0` the result is `table[id]` concatenated with the
/// optional suffix. Returns `None` when the wire-form references a
/// mapping id the peer never declared (or for the empty
/// `(id=0, suffix=None)` form). The caller drops the dispatch on
/// `None` so a partial keyexpr never reaches a user callback.
fn resolve_wireexpr(
    body: &WireexprVariant,
    peer_keyexpr_table: &HashMap<u64, String>,
) -> Option<String> {
    let (id, suffix_opt) = match body {
        WireexprVariant::WireexprLocal(arm) => (arm.id, arm.suffix.as_deref()),
        WireexprVariant::WireexprNonlocal(arm) => (arm.id, arm.suffix.as_deref()),
    };
    if id == 0 {
        suffix_opt.map(str::to_string)
    } else {
        let base = peer_keyexpr_table.get(&id)?.clone();
        match suffix_opt {
            Some(s) => {
                let mut out = base;
                out.push_str(s);
                Some(out)
            }
            None => Some(base),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use wz_codecs::encoding::Encoding;
    use wz_codecs::err::Err as ErrBody;
    use wz_codecs::msg_del::MsgDel;
    use wz_codecs::msg_put::MsgPut;
    use wz_codecs::reply::Reply;
    use wz_codecs::wireexpr::Wireexpr;
    use wz_codecs::wireexpr_local::WireexprLocal;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    fn response_reply_put(
        rid: u64,
        mapping_id: u64,
        suffix: Option<&str>,
        payload: &[u8],
    ) -> Response {
        let suffix_owned = suffix.map(str::to_string);
        let suffix_len = suffix.map(|s| s.len() as u64);
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_owned,
            }),
        };
        let reply = Reply {
            body: ReplyVariant::CodecZenohMsgPut(MsgPut {
                payload_len: payload.len() as u64,
                payload: payload.to_vec(),
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
    }

    fn response_reply_del(rid: u64, suffix: &str) -> Response {
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix.to_string()),
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
    }

    fn response_err(
        rid: u64,
        suffix: &str,
        packed_id: u32,
        schema: Option<&str>,
        payload: &[u8],
    ) -> Response {
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix.to_string()),
            }),
        };
        let schema_owned = schema.map(str::to_string);
        let schema_len = schema.map(|s| s.len() as u64);
        let encoding = Encoding {
            packed_id,
            schema_len,
            schema: schema_owned,
        };
        let err_body = ErrBody {
            encoding: Some(encoding),
            payload_len: payload.len() as u64,
            payload: payload.to_vec(),
            ..ErrBody::default()
        };
        Response {
            request_id: rid,
            keyexpr,
            body: ResponseVariant::CodecZenohErr(err_body),
            ..Response::default()
        }
    }

    fn response_final_for(rid: u64) -> ResponseFinal {
        ResponseFinal {
            request_id: rid,
            ..ResponseFinal::default()
        }
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
            move |reply| captured_cb.lock().unwrap().push(reply.clone()),
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
            InboundReplyBody::Put { payload } => assert_eq!(payload, b"21.0"),
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
                assert_eq!(reply.body, InboundReplyBody::Del, "expected Del body");
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
            move |reply| *captured_cb.lock().unwrap() = Some(reply.clone()),
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
            move |reply| *captured_cb.lock().unwrap() = Some(reply.keyexpr_literal.clone()),
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
            move |reply| captured_cb.lock().unwrap().push(reply.clone()),
            |_| {},
        );

        let inbound = InboundReply {
            rid: 7,
            keyexpr_literal: "home/temp".to_string(),
            body: InboundReplyBody::Put {
                payload: b"21.0".to_vec(),
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
            body: InboundReplyBody::Del,
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
            responder: None,
        };
        let inbound: InboundReply = qr.into();
        assert_eq!(inbound.rid, 11);
        assert_eq!(inbound.keyexpr_literal, "sensors/a");
        match inbound.body {
            InboundReplyBody::Put { payload } => assert_eq!(payload, b"value"),
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
            responder: Some((vec![0xaa, 0xbb], 5)),
        };
        let inbound: InboundReply = qr.into();
        assert_eq!(inbound.rid, 12);
        assert_eq!(inbound.keyexpr_literal, "sensors/b");
        assert_eq!(inbound.body, InboundReplyBody::Del);
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
}

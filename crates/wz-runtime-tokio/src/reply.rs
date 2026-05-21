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
use wz_codecs::response_final::ResponseFinal;
use wz_codecs::wireexpr::WireexprVariant;

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
    /// the `on_final` callback fires once when the matching
    /// `ResponseFinal` arrives, at which point the entry is
    /// auto-unregistered.
    ///
    /// The returned [`ReplyHandle`] is the rid wrapped — exposed so
    /// callers that allocate rids opaquely (e.g. a future
    /// `z_get_builder` adapter) can carry the rid without leaking
    /// the integer all the way back to user code.
    pub fn register(
        &mut self,
        rid: u64,
        on_reply: impl FnMut(&InboundReply) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> ReplyHandle {
        self.pending.push(Pending {
            rid,
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
        for pending in &mut self.pending {
            if pending.rid == inbound.rid {
                (pending.on_reply)(&inbound);
            }
        }
    }

    /// Route an inbound [`ResponseFinal`] through the pending table.
    /// Every pending entry whose `rid == response_final.request_id`
    /// fires its `on_final` callback exactly once and is then removed
    /// from the table. Duplicate-rid registrations all fire (in
    /// registration order) and all are removed in the same dispatch.
    /// Unknown rids drop silently.
    pub fn dispatch_response_final(&mut self, response_final: &ResponseFinal) {
        let target = response_final.request_id;
        // Partition: take ownership of every matching entry, leave the
        // rest in place. Vec::retain would force us to mutate the
        // callback in-place which the borrow checker rejects (we need
        // to call `(on_final)(rid)` which requires `&mut Pending`); we
        // instead drain the matches into a stash and fire after the
        // retain-pass releases the &mut self.pending borrow.
        let mut fired: Vec<Pending> = Vec::new();
        let mut keep: Vec<Pending> = Vec::with_capacity(self.pending.len());
        for entry in self.pending.drain(..) {
            if entry.rid == target {
                fired.push(entry);
            } else {
                keep.push(entry);
            }
        }
        self.pending = keep;
        for mut entry in fired {
            (entry.on_final)(target);
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

    fn response_reply_put(rid: u64, mapping_id: u64, suffix: Option<&str>, payload: &[u8]) -> Response {
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

    fn response_err(rid: u64, suffix: &str, packed_id: u32, schema: Option<&str>, payload: &[u8]) -> Response {
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
        let h1 = reg.register(7, |_| {}, |_| {});
        let h2 = reg.register(8, |_| {}, |_| {});
        assert_eq!(h1.rid(), 7);
        assert_eq!(h2.rid(), 8);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn unregister_is_idempotent_and_removes_only_matching_rid() {
        let mut reg = ReplyRegistry::new();
        reg.register(7, |_| {}, |_| {});
        reg.register(8, |_| {}, |_| {});
        assert!(reg.unregister(7));
        assert!(!reg.unregister(7), "second unregister of same rid is a no-op");
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
            move |reply| *captured_cb.lock().unwrap() = Some(reply.clone()),
            |_| {},
        );

        let resp = response_err(5, "error/path", 4, Some("schema_v1"), b"oops");
        reg.dispatch_response(&resp, &HashMap::new());

        let captured = captured.lock().unwrap().clone().expect("on_reply must fire");
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
        reg.register(7, move |_| { count_cb.fetch_add(1, Ordering::SeqCst); }, |_| {});

        let resp = response_reply_put(99, 0, Some("home/temp"), b"x");
        reg.dispatch_response(&resp, &HashMap::new());
        assert_eq!(count.load(Ordering::SeqCst), 0, "unknown rid must not fire on_reply");
        assert_eq!(reg.len(), 1, "pending entry preserved for unmatched rid");
    }

    #[test]
    fn dispatch_response_final_fires_and_auto_unregisters() {
        let mut reg = ReplyRegistry::new();
        let final_count = Arc::new(AtomicUsize::new(0));
        let final_count_cb = final_count.clone();
        reg.register(
            42,
            |_| {},
            move |rid| {
                assert_eq!(rid, 42, "on_final must receive the registered rid");
                final_count_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        reg.dispatch_response_final(&response_final_for(42));
        assert_eq!(final_count.load(Ordering::SeqCst), 1);
        assert!(reg.is_empty(), "Final must auto-unregister the pending entry");

        // Subsequent Reply for the now-removed rid must drop silently.
        reg.dispatch_response(&response_reply_put(42, 0, Some("home/temp"), b"x"), &HashMap::new());
    }

    #[test]
    fn dispatch_response_final_with_unknown_rid_is_silent_noop() {
        let mut reg = ReplyRegistry::new();
        reg.register(42, |_| {}, |_| panic!("on_final must not fire on unknown rid"));

        reg.dispatch_response_final(&response_final_for(99));
        assert_eq!(reg.len(), 1, "unknown-rid Final preserves all pending entries");
    }

    #[test]
    fn dispatch_resolves_mapping_id_against_peer_table() {
        let mut reg = ReplyRegistry::new();
        let captured_literal: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_cb = captured_literal.clone();
        reg.register(
            1,
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
        reg.register(1, move |_| { fired_cb.fetch_add(1, Ordering::SeqCst); }, |_| {});

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
        reg.register(7, move |_| { count_cb.fetch_add(1, Ordering::SeqCst); }, |_| {});

        for payload in [b"sample-1".as_ref(), b"sample-2".as_ref(), b"sample-3".as_ref()] {
            reg.dispatch_response(
                &response_reply_put(7, 0, Some("series/data"), payload),
                &HashMap::new(),
            );
        }
        assert_eq!(count.load(Ordering::SeqCst), 3, "many Reply semantics");
        assert_eq!(reg.len(), 1, "Reply chain does NOT auto-unregister; only Final does");
    }

    #[test]
    fn duplicate_rid_registrations_both_fire_in_registration_order() {
        let mut reg = ReplyRegistry::new();
        let order: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let order_a = order.clone();
        reg.register(7, move |_| order_a.lock().unwrap().push(1), |_| {});
        let order_b = order.clone();
        reg.register(7, move |_| order_b.lock().unwrap().push(2), |_| {});

        reg.dispatch_response(
            &response_reply_put(7, 0, Some("home/temp"), b"21.0"),
            &HashMap::new(),
        );
        assert_eq!(*order.lock().unwrap(), vec![1, 2], "duplicate-rid pending entries fire in registration order");

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
            move |_| { r.fetch_add(1, Ordering::SeqCst); },
            move |_| { f.fetch_add(1, Ordering::SeqCst); },
        );

        let messages = vec![
            NetworkMessage::Response(Box::new(response_reply_put(42, 0, Some("home/temp"), b"21.0"))),
            NetworkMessage::Response(Box::new(response_reply_put(42, 0, Some("home/temp"), b"21.5"))),
            NetworkMessage::ResponseFinal(response_final_for(42)),
        ];
        reg.dispatch_messages(&messages, &HashMap::new());

        assert_eq!(reply_count.load(Ordering::SeqCst), 2);
        assert_eq!(final_count.load(Ordering::SeqCst), 1);
        assert!(reg.is_empty(), "Final at end of batch removed the pending entry");
    }

    #[test]
    fn dispatch_messages_ignores_unrelated_variants() {
        let mut reg = ReplyRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        reg.register(7, move |_| { fired_cb.fetch_add(1, Ordering::SeqCst); }, |_| {});

        // Unknown variant must NOT touch the registry.
        let messages = vec![NetworkMessage::Unknown {
            mid: 0x10,
            body: vec![],
        }];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        assert_eq!(reg.len(), 1, "pending entry preserved across non-Response messages");
    }
}

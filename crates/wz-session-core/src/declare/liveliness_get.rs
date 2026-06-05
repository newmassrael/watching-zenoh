// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LivelinessGetRegistry` — REQUESTER-side registry for the liveliness
//! GET (snapshot query). The application asks "which liveliness tokens
//! matching keyexpr K are currently alive?"; wz emits one CURRENT
//! liveliness `Interest`, the peer replies with an `interest_id`-tagged
//! `Declare(DeclToken)` per matching live token, terminated by an
//! `interest_id`-tagged `Declare(DeclFinal)`. This mirrors zenoh-pico's
//! `z_liveliness_get` / `_z_liveliness_query`
//! (`vendor/zenoh-pico/src/net/liveliness.c:314-366`) and the symmetric
//! responder side already wz-resident in
//! [`crate::declare::local_token::LocalTokenRegistry`].
//!
//! ## Why this is NOT built on the query (Request/Response) plane
//!
//! The application *surface* of a liveliness get looks like a query —
//! it delivers a stream of replies terminated by a final, so it reuses
//! the response-plane [`crate::reply_sink::ReplySink`] / [`ReplyView`]
//! delivery seam (one SSOT for "get → replies → final"). But the *wire*
//! is the **Interest / declaration** plane, not the Request / Query
//! plane: the request leg is a CURRENT liveliness `Interest`, and the
//! replies arrive as `Declare(DeclToken)` records, terminated by a
//! `Declare(DeclFinal)` — never a `Request(Query)` / `Response(Reply)` /
//! `ResponseFinal`. That is what real zenoh peers speak, so a query-plane
//! model would be unable to interoperate. Consequently this registry
//! correlates on the outer [`wz_codecs::declare::DeclareOwned::interest_id`]
//! (declaration plane) rather than a `Response.request_id`, and it is a
//! sibling of [`crate::reply::ReplyRegistry`] — same *pattern* (a bounded
//! pending table keyed by a correlation id, each entry carrying a
//! [`ReplySink`] + an optional deadline), never the same *type*. The
//! split matches both zenoh-pico (its `_z_liveliness_pending_query` map is
//! distinct from the query pending map) and wz's own structural separation
//! of the liveliness registries from the pub/sub + query registries.
//!
//! ## Position alongside the other liveliness registries
//!
//! | Registry                         | Role                                    | Correlation        |
//! |----------------------------------|-----------------------------------------|--------------------|
//! | [`crate::declare::LivelinessRegistry`]            | observe EVERY peer `Decl*Token`         | none (callback)    |
//! | [`crate::declare::liveliness_subscriber::LivelinessSubscriberRegistry`] | subscribe to peer tokens matching my keyexpr | per-subscriber slot |
//! | [`crate::declare::local_token::LocalTokenRegistry`] | DECLARER side + inbound-Interest responder | local token table  |
//! | [`LivelinessGetRegistry`]                          | one-shot CURRENT snapshot of peer tokens | per-get `interest_id` |
//!
//! An inbound `Declare(DeclToken)` carrying `interest_id = None` is an
//! *unsolicited* (proactive) token declaration and is the observer /
//! subscriber registries' concern; this registry ignores it. Only a
//! `Declare` whose outer envelope carries `interest_id = Some(id)` —
//! the peer's solicited reply to one of our outstanding gets — routes
//! here, fanning to the single pending get with the matching id.
//!
//! ## no-heap split (mirror of the sibling registries)
//!
//! 1. **Storage + fire (no-heap)** — the pending table is a
//!    [`crate::bounded::BoundedVec`] of [`PendingGet`] rows; the
//!    [`LivelinessGetRegistry::dispatch_reply_borrowed`] /
//!    [`LivelinessGetRegistry::dispatch_final`] /
//!    [`LivelinessGetRegistry::sweep_timed_out`] fire entries take only
//!    `Copy` scalars + a borrowed keyexpr, so they compile + run on the
//!    MCU no-alloc profile.
//! 2. **Owned inbound parse (alloc)** —
//!    [`LivelinessGetRegistry::dispatch_declare`] /
//!    [`LivelinessGetRegistry::dispatch_messages`] consume an owned
//!    [`wz_codecs::declare::DeclareOwned`] + resolve its keyexpr through
//!    the shared peer table, then funnel through the no-heap SSOT.

use crate::bounded::BoundedVec;
use crate::caps;
use crate::registry_error::RegisterError;
use crate::reply_sink::{BorrowedReply, ReplyKind, ReplySink};

#[cfg(feature = "alloc")]
pub use crate::reply_sink::BoxedReplySink;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use hashbrown::HashMap;

#[cfg(feature = "alloc")]
use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};

#[cfg(feature = "alloc")]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
#[cfg(feature = "alloc")]
use crate::network_message::NetworkMessage;
#[cfg(feature = "alloc")]
use crate::wireexpr_resolve::resolve_wireexpr;

/// One outstanding liveliness get. Private to this module; consumers
/// interact through [`LivelinessGetRegistry::register`] /
/// [`LivelinessGetRegistry::unregister`] and the higher-level
/// `Session::liveliness().get()` surface.
struct PendingGet<C: ReplySink> {
    /// The `interest_id` allocated for the outbound CURRENT Interest;
    /// the correlation key every inbound reply `Declare` echoes in its
    /// outer envelope.
    interest_id: u64,
    /// The reply-delivery sink (DIP seam). `C = BoxedReplySink` on AP
    /// (heap `on_reply` + `on_final` closures), a consumer-supplied
    /// closed `enum` on MCU.
    sink: C,
    /// Absolute monotonic-ms deadline (snapshot taken at register time
    /// as `clock.now_monotonic_ms() + timeout_ms`). `None` means the
    /// get never times out (it stays pending until the peer's
    /// `Declare(DeclFinal)` arrives). A `Some(d)` entry is swept by
    /// [`LivelinessGetRegistry::sweep_timed_out`] when `now_ms >= d`,
    /// firing `on_final` exactly as a real terminator would so an
    /// unanswered get cannot leak its slot. Mirrors
    /// [`crate::reply::ReplyRegistry`]'s per-pending deadline.
    deadline_ms: Option<u64>,
}

/// Requester-side registry tracking the liveliness GET (snapshot)
/// queries wz has outstanding on this session, routing each inbound
/// solicited `Declare(DeclToken)` reply to the matching get's
/// [`ReplySink::on_reply`] and the terminating `Declare(DeclFinal)` to
/// its [`ReplySink::on_final`] (after which the pending entry is
/// removed). See module-level docs for why this is a declaration-plane
/// sibling of [`crate::reply::ReplyRegistry`] rather than a reuse of it.
pub struct LivelinessGetRegistry<C: ReplySink> {
    pending: BoundedVec<PendingGet<C>, { caps::MAX_PENDING_LIVELINESS_GETS }>,
}

impl<C: ReplySink> Default for LivelinessGetRegistry<C> {
    fn default() -> Self {
        Self::with_sink_backing()
    }
}

impl<C: ReplySink> LivelinessGetRegistry<C> {
    /// New empty registry over an explicit sink backing `C` (the
    /// no-`alloc` / MCU entry point, paired with
    /// [`register`](Self::register)). AP callers use the inferring
    /// [`new`](LivelinessGetRegistry::new) shorthand, which fixes
    /// `C = BoxedReplySink`.
    pub fn with_sink_backing() -> Self {
        Self {
            pending: BoundedVec::new(),
        }
    }

    /// Register a pending get keyed by `interest_id`. Fresh ids come
    /// from
    /// [`crate::session_glue::SessionLinkActions::alloc_next_interest_id`],
    /// so a collision is a programming error rather than a runtime
    /// condition; a duplicate `interest_id` is rejected with `Ok(false)`
    /// (no-op). `deadline_ms` is the absolute monotonic-ms timeout
    /// snapshot (`None` = never expires). Returns `Ok(true)` on a fresh
    /// registration, `Err(TableFull)` when the pending table is at
    /// [`caps::MAX_PENDING_LIVELINESS_GETS`] (fail-fast on the no-alloc
    /// backing; never returned on the `alloc` backing).
    pub fn register(
        &mut self,
        interest_id: u64,
        deadline_ms: Option<u64>,
        sink: C,
    ) -> Result<bool, RegisterError> {
        if self.pending.iter().any(|p| p.interest_id == interest_id) {
            return Ok(false);
        }
        self.pending
            .push(PendingGet {
                interest_id,
                sink,
                deadline_ms,
            })
            .map_err(|_| RegisterError::TableFull)?;
        Ok(true)
    }

    /// Remove a pending get by `interest_id` without firing `on_final`.
    /// Returns `true` when an entry was removed, `false` when none
    /// matched (idempotent). Used by the RAII / explicit-cancel path
    /// when the application drops the get handle before the snapshot
    /// completes.
    pub fn unregister(&mut self, interest_id: u64) -> bool {
        let before = self.pending.len();
        self.pending.retain(|p| p.interest_id != interest_id);
        before != self.pending.len()
    }

    /// Number of currently-outstanding pending gets.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the registry holds any pending get.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// no-heap fire entry: deliver one alive-token reply to the pending
    /// get whose `interest_id` matches. The reply is synthesised as a
    /// [`ReplyKind::Put`] [`BorrowedReply`] whose `rid` is the
    /// `interest_id` (the correlation id the get caller holds) and whose
    /// keyexpr is the resolved token keyexpr — a liveliness reply is
    /// "this keyexpr is currently alive", so it carries no payload. The
    /// pending entry stays in the table; only a `DeclFinal`
    /// ([`Self::dispatch_final`]) or a timeout ([`Self::sweep_timed_out`])
    /// removes it. Borrow-driven (the caller supplies the resolved
    /// keyexpr), so it is the MCU no-heap reply path; the `alloc` wire
    /// path ([`dispatch_declare`](Self::dispatch_declare)) resolves the
    /// keyexpr through the peer table and funnels through here. Returns
    /// the count of sinks fired (0 if no get matches, else 1).
    pub fn dispatch_reply_borrowed(&mut self, interest_id: u64, keyexpr: &str) -> usize {
        let reply = BorrowedReply {
            rid: interest_id,
            keyexpr,
            kind: ReplyKind::Put,
            payload: &[],
            err_encoding: None,
        };
        let mut fired: usize = 0;
        for pending in self.pending.iter_mut() {
            if pending.interest_id == interest_id {
                pending.sink.on_reply(&reply);
                fired = fired.saturating_add(1);
            }
        }
        fired
    }

    /// no-heap fire entry: signal the terminating `Declare(DeclFinal)`
    /// for `interest_id`. Fires the matching get's `on_final` once and
    /// removes the pending entry. Returns `true` when a pending get was
    /// terminated, `false` for an unknown id (the peer may emit a
    /// `DeclFinal` for an id whose get was already cancelled locally —
    /// dropping it silently is correct). Mirrors
    /// [`crate::reply::ReplyRegistry::deliver_local_final`]'s
    /// fire-then-remove contract; a liveliness get expects exactly one
    /// terminator (one CURRENT Interest to one peer), so there is no
    /// `remaining_finals` counter.
    pub fn dispatch_final(&mut self, interest_id: u64) -> bool {
        self.fire_final_for(interest_id)
    }

    /// Fire `on_final` + drop every pending get whose `deadline_ms` is at
    /// or before `now_ms`. Returns the number of gets swept (zero in the
    /// common case where nothing has timed out). Entries with
    /// `deadline_ms == None` never expire. `now_ms` is caller-supplied
    /// (typically `clock.now_monotonic_ms()`) so the test surface stays
    /// deterministic. Mirror of
    /// [`crate::reply::ReplyRegistry::sweep_timed_out`] — the fired
    /// `on_final` carries the entry's `interest_id` only, so a callback
    /// cannot distinguish "timed out" from a normal terminator via the
    /// argument (opaque-cause, same architectural pick as the reply
    /// registry).
    pub fn sweep_timed_out(&mut self, now_ms: u64) -> usize {
        // no-alloc partition (mirror of ReplyRegistry::sweep_timed_out):
        // take the table out, drain by value into two bounded stack
        // partitions, reassign `keep`, then fire after the borrow
        // releases so a panicking `on_final` cannot leave half-swept
        // entries behind.
        let mut fired: BoundedVec<PendingGet<C>, { caps::MAX_PENDING_LIVELINESS_GETS }> =
            BoundedVec::new();
        let mut keep: BoundedVec<PendingGet<C>, { caps::MAX_PENDING_LIVELINESS_GETS }> =
            BoundedVec::new();
        for entry in core::mem::take(&mut self.pending) {
            let expired = matches!(entry.deadline_ms, Some(d) if d <= now_ms);
            if expired {
                fired
                    .push(entry)
                    .expect("partition fits: keep + fired == taken <= MAX_PENDING_LIVELINESS_GETS");
            } else {
                keep.push(entry)
                    .expect("partition fits: keep + fired == taken <= MAX_PENDING_LIVELINESS_GETS");
            }
        }
        self.pending = keep;
        let swept = fired.len();
        for mut entry in fired {
            let id = entry.interest_id;
            entry.sink.on_final(id);
        }
        swept
    }

    /// Shared final fan body: take ownership of the (at most one) pending
    /// entry matching `interest_id`, leave the rest, then fire `on_final`
    /// after the partition releases the `&mut self.pending` borrow.
    /// Returns `true` when an entry was fired + removed. Order-preserving
    /// (a `BoundedVec` partition) though only a single entry can match a
    /// fresh-allocated id.
    fn fire_final_for(&mut self, interest_id: u64) -> bool {
        let mut fired: BoundedVec<PendingGet<C>, { caps::MAX_PENDING_LIVELINESS_GETS }> =
            BoundedVec::new();
        let mut keep: BoundedVec<PendingGet<C>, { caps::MAX_PENDING_LIVELINESS_GETS }> =
            BoundedVec::new();
        for entry in core::mem::take(&mut self.pending) {
            if entry.interest_id == interest_id {
                fired
                    .push(entry)
                    .expect("partition fits: keep + fired == taken <= MAX_PENDING_LIVELINESS_GETS");
            } else {
                keep.push(entry)
                    .expect("partition fits: keep + fired == taken <= MAX_PENDING_LIVELINESS_GETS");
            }
        }
        self.pending = keep;
        let any = !fired.is_empty();
        for mut entry in fired {
            let id = entry.interest_id;
            entry.sink.on_final(id);
        }
        any
    }

    /// `alloc`-gated inbound-parse path: route an inbound `Declare`
    /// envelope through the pending table. Only a Declare carrying an
    /// outer `interest_id` is a solicited reply to one of our gets; an
    /// unsolicited token declaration (`interest_id == None`) is dropped
    /// (it is the observer / subscriber registries' concern). A
    /// `DeclToken` fires the matching get's `on_reply` with the resolved
    /// keyexpr; a `DeclFinal` fires `on_final` + removes the get. A
    /// `DeclToken` whose keyexpr references an undeclared peer mapping
    /// drops silently (mirror of the sibling registries' "no resolved
    /// keyexpr → no fire" contract). Other inner variants are ignored.
    #[cfg(feature = "alloc")]
    pub fn dispatch_declare(
        &mut self,
        declare: &DeclareOwned,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        let interest_id = match declare.interest_id {
            Some(id) => id,
            // Unsolicited (proactive) declaration — not a get reply.
            None => return,
        };
        match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclToken(decl) => {
                let resolved = match resolve_wireexpr(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                self.dispatch_reply_borrowed(interest_id, &resolved);
            }
            DeclareOwnedVariant::CodecZenohDeclFinal(_) => {
                self.fire_final_for(interest_id);
            }
            // Other Declare sub-variants are not the liveliness-get
            // requester's concern.
            _ => {}
        }
    }

    /// Drain a `&[NetworkMessage]` through [`Self::dispatch_declare`] for
    /// every `Declare` arm. Mirror of the sibling registries'
    /// `dispatch_messages`; `alloc`-gated (consumes owned messages +
    /// resolves keyexprs). Non-`Declare` variants are no-ops here — the
    /// liveliness-get reply path lives entirely in the `Declare` MID.
    #[cfg(feature = "alloc")]
    pub fn dispatch_messages(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        for message in messages {
            if let NetworkMessage::Declare(declare) = message {
                self.dispatch_declare(declare, peer_keyexpr_table);
            }
        }
    }

    /// [`IterationEvent`] adapter; mirror of the sibling registries.
    /// Routes `FramePayload` events through [`Self::dispatch_messages`];
    /// other variants (Lease branch, non-poll outcomes) are no-ops.
    /// `alloc`-gated (consumes owned messages).
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

/// AP / `alloc`-profile convenience surface (the `BoxedReplySink`
/// instantiation only). The no-`alloc` profile uses
/// [`with_sink_backing`](LivelinessGetRegistry::with_sink_backing) + a
/// consumer-supplied sink.
#[cfg(feature = "alloc")]
impl LivelinessGetRegistry<BoxedReplySink> {
    /// New empty AP registry backed by heap-boxed closures. Inferring
    /// shorthand for
    /// [`with_sink_backing`](LivelinessGetRegistry::with_sink_backing):
    /// fixes `C = BoxedReplySink`.
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// Register a pending get from the `on_reply` + `on_final` capturing
    /// closures (the dynamic-opt-in AP surface). Wraps them in a
    /// [`BoxedReplySink`] and funnels through
    /// [`register`](LivelinessGetRegistry::register); on the `alloc`
    /// backing the table never overflows, so the `TableFull` arm is
    /// unreachable and the result is `Ok(true)` for a fresh id /
    /// `Ok(false)` for a duplicate.
    pub fn register_get(
        &mut self,
        interest_id: u64,
        deadline_ms: Option<u64>,
        on_reply: impl FnMut(&dyn crate::reply_sink::ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<bool, RegisterError> {
        self.register(
            interest_id,
            deadline_ms,
            BoxedReplySink::new(on_reply, on_final),
        )
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    //! Behavioural tests for `LivelinessGetRegistry`. `Arc<Mutex<…>>`
    //! capture cells use `std` under `#[cfg(test)]` per the wz-codecs
    //! sibling-crate convention; the production artifact stays no_std.

    use super::*;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use hashbrown::HashMap;
    use wz_session_core_test_support::*;

    use crate::reply_sink::ReplyView;

    type Captured = Arc<Mutex<Vec<(u64, String)>>>;

    fn make_get(replies: Captured, finals: Arc<Mutex<Vec<u64>>>) -> BoxedReplySink {
        let replies_cb = replies;
        let finals_cb = finals;
        BoxedReplySink::new(
            move |reply: &dyn ReplyView| {
                replies_cb
                    .lock()
                    .unwrap()
                    .push((reply.rid(), reply.keyexpr().to_string()));
            },
            move |id: u64| {
                finals_cb.lock().unwrap().push(id);
            },
        )
    }

    #[test]
    fn new_registry_starts_empty() {
        let reg = LivelinessGetRegistry::new();
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());
    }

    #[test]
    fn register_then_unregister_clears_pending() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        assert!(reg
            .register(7, None, make_get(r.clone(), f.clone()))
            .unwrap());
        assert_eq!(reg.len(), 1);
        assert!(reg.unregister(7));
        assert_eq!(reg.len(), 0);
        assert!(!reg.unregister(7), "double-unregister is idempotent");
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        assert!(reg
            .register(7, None, make_get(r.clone(), f.clone()))
            .unwrap());
        assert!(
            !reg.register(7, None, make_get(r.clone(), f.clone()))
                .unwrap(),
            "second register on same interest_id must reject"
        );
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn decl_token_reply_fires_on_reply_with_interest_id_as_rid() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();

        // Solicited reply: outer Declare carries interest_id=42.
        let declare = declare_envelope_decl_token_with_interest(
            decl_token(11, 0, Some("liveliness/dev11")),
            42,
        );
        reg.dispatch_declare(&declare, &HashMap::new());

        let got = r.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, 42, "rid echoes the get's interest_id");
        assert_eq!(got[0].1, "liveliness/dev11");
        assert!(f.lock().unwrap().is_empty(), "no final yet");
        assert_eq!(reg.len(), 1, "pending entry retained until DeclFinal");
    }

    #[test]
    fn decl_final_fires_on_final_and_removes_pending() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();

        let token = declare_envelope_decl_token_with_interest(
            decl_token(11, 0, Some("liveliness/dev11")),
            42,
        );
        let fin = declare_envelope_decl_final_with_interest(42);
        reg.dispatch_messages(
            &[
                NetworkMessage::Declare(alloc::boxed::Box::new(token)),
                NetworkMessage::Declare(alloc::boxed::Box::new(fin)),
            ],
            &HashMap::new(),
        );

        assert_eq!(r.lock().unwrap().len(), 1, "one alive token");
        assert_eq!(*f.lock().unwrap(), vec![42], "final fired once");
        assert_eq!(reg.len(), 0, "DeclFinal removes the pending get");
    }

    #[test]
    fn unsolicited_token_without_interest_id_is_ignored() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();

        // Proactive declaration: no outer interest_id (the un-tagged
        // envelope helper sets interest_id = None). Must not route here
        // (the observer / subscriber registries own it).
        let declare = declare_envelope_decl_token(decl_token(11, 0, Some("liveliness/dev11")));
        reg.dispatch_declare(&declare, &HashMap::new());

        assert!(
            r.lock().unwrap().is_empty(),
            "unsolicited token (interest_id=None) must not fire a get reply"
        );
        assert_eq!(reg.len(), 1, "pending get untouched");
    }

    #[test]
    fn reply_for_unknown_interest_id_fires_nothing() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();

        let declare = declare_envelope_decl_token_with_interest(
            decl_token(11, 0, Some("liveliness/dev11")),
            99, // no pending get with id 99
        );
        reg.dispatch_declare(&declare, &HashMap::new());
        assert!(r.lock().unwrap().is_empty());
        assert!(!reg.dispatch_final(99), "unknown final id removes nothing");
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn unresolvable_mapping_id_drops_reply() {
        let mut reg = LivelinessGetRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        reg.register(
            42,
            None,
            BoxedReplySink::new(
                move |_r: &dyn ReplyView| {
                    fired_cb.fetch_add(1, Ordering::SeqCst);
                },
                |_| {},
            ),
        )
        .unwrap();

        // mapping_id=55 with no peer-keyexpr table entry → resolve None.
        let declare = declare_envelope_decl_token_with_interest(decl_token(11, 55, None), 42);
        reg.dispatch_declare(&declare, &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "unresolvable keyexpr drops"
        );
    }

    #[test]
    fn aliased_keyexpr_resolves_through_peer_table() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();

        let mut table = HashMap::new();
        table.insert(10u64, "liveliness".to_string());
        let declare =
            declare_envelope_decl_token_with_interest(decl_token(99, 10, Some("/dev42")), 42);
        reg.dispatch_declare(&declare, &table);

        let got = r.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, "liveliness/dev42");
    }

    #[test]
    fn sweep_times_out_pending_get() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, Some(1000), make_get(r.clone(), f.clone()))
            .unwrap();
        reg.register(43, None, make_get(r.clone(), f.clone()))
            .unwrap();

        assert_eq!(reg.sweep_timed_out(999), 0, "before deadline: nothing");
        assert_eq!(reg.sweep_timed_out(1000), 1, "at deadline: id 42 swept");
        assert_eq!(*f.lock().unwrap(), vec![42], "swept get fires on_final");
        assert_eq!(reg.len(), 1, "never-expiring get 43 retained");
        assert_eq!(reg.sweep_timed_out(5000), 0, "idempotent; 43 never expires");
    }

    #[test]
    fn no_codec_borrowed_path_fires_reply_and_final() {
        // MCU no-heap path: register + fire without any codec / Declare.
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(7, None, make_get(r.clone(), f.clone()))
            .unwrap();

        assert_eq!(reg.dispatch_reply_borrowed(7, "live/a"), 1);
        assert_eq!(reg.dispatch_reply_borrowed(7, "live/b"), 1);
        assert_eq!(reg.dispatch_reply_borrowed(8, "live/c"), 0, "no get id 8");
        assert!(reg.dispatch_final(7));

        let got = r.lock().unwrap().clone();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].1, "live/a");
        assert_eq!(got[1].1, "live/b");
        assert_eq!(*f.lock().unwrap(), vec![7]);
        assert_eq!(reg.len(), 0);
    }
}

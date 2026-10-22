// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311dz-pre / R311lq — the observer-drain sink trait FAMILY: the
//! abstractions the application-layer observer's drain phase emits its
//! staged buffers through.
//!
//! The observer stages three INDEPENDENT outbound effects during
//! `dispatch_event`, each into its own buffer, then drains each buffer
//! through the matching sink trait. R311lq segregates these into three
//! cohesive traits (one per concern) rather than one fat trait, so a
//! consumer that drains only ONE concern implements only that trait, not
//! the union — the textbook Interface-Segregation shape surfaced once a
//! second sink (the multicast reply loop, which drains only queryable
//! replies) joined the single unicast `SessionLinkActions` implementor:
//!
//! - [`ResponseSink`] — the queryable reply chain (`send_response` /
//!   `send_response_final`). Honest to its name: only `Response` /
//!   `ResponseFinal` network-message emits.
//! - [`DeclareReplySink`] — the declarer-side liveliness interest-response
//!   (`send_declare_token_reply` / `send_declare_final_reply`,
//!   R283 / R311hn). A `Declare(DeclToken|DeclFinal)` reply to a peer's
//!   liveliness Interest — a distinct message family from a query reply.
//! - [`LivelinessGetPrune`] — the terminated liveliness-get reconnect-cache
//!   prune (`prune_liveliness_get_interest`, F3). NOT a wire emit at all —
//!   a bundle-state effect — so it never belonged under a "Response" name.
//!
//! This inverts the observer's dependency on the concrete tokio
//! `SessionLinkActions<R, T>` (defined in `wz-runtime-tokio::session_glue`,
//! a 10k-LOC tokio-bound module not yet migrated) so the observer can
//! live in this runtime-agnostic crate without dragging in the tokio
//! actions layer. `SessionLinkActions` implements all three traits in
//! wz-runtime-tokio; a future MCU runtime's equivalent actions handle
//! implements the same family, so the observer drains identically on
//! either profile; a partial consumer (the multicast reply loop)
//! implements exactly the subset it drains.
//!
//! Each trait is always-nameable so a drain method's `<S: Trait>`
//! signature stays stable across feature subsets — a trait is simply empty
//! in a build with none of its gating features. This is the same idiom the
//! prior single `ResponseSink` used (the trait nameable, the methods
//! feature-gated); R311lq applies it per concern instead of to one
//! grab-bag union.

#[cfg(all(feature = "codec-response", feature = "alloc"))]
use crate::wire::ResponseOwned;

/// Outbound sink for the queryable reply chain. The application-layer
/// observer drains its staged `QueryReply` records (and the matching
/// terminal `ResponseFinal` rids) through this trait so it is decoupled
/// from any concrete runtime actions type (`SessionLinkActions` in the
/// tokio profile). Empty in a build with neither response codec.
pub trait ResponseSink {
    /// Encode + enqueue one outbound `Response(Reply|Err)` frame.
    /// Mirrors `SessionLinkActions::send_response`. Heap profile only: the
    /// argument is the owned record; a node with no allocator sends a staged reply
    /// through [`Self::send_reply_parts`].
    #[cfg(all(feature = "codec-response", feature = "alloc"))]
    fn send_response(&self, response: ResponseOwned);

    /// Encode + enqueue one staged reply, described by borrowed parts
    /// ([`crate::reply_stage::ReplyParts`]): the form a stage hands out without
    /// building an owned record. A sink that can write the `Response` from the parts
    /// ([`crate::lent_response::ResponseWriter`]) does so and builds nothing; with a
    /// heap the default builds the owned `QueryReply` and sends it through
    /// [`Self::send_response`], so a sink that only knows that form is served too. A
    /// reply the wire cannot carry is skipped, as the drain skips one whose bounded
    /// field overflows.
    #[cfg(feature = "codec-response")]
    #[cfg(feature = "alloc")]
    fn send_reply_parts(&self, parts: crate::reply_stage::ReplyParts<'_>) {
        if let Ok(response) = crate::query::QueryReply::from_parts(&parts).into_response() {
            self.send_response(response);
        }
    }

    /// See the heap form. With no allocator there is no owned record to fall back
    /// on, so the sink writes the `Response` itself.
    #[cfg(all(feature = "codec-response", feature = "storage-profile"))]
    #[cfg(not(feature = "alloc"))]
    fn send_reply_parts(&self, parts: crate::reply_stage::ReplyParts<'_>);

    /// Encode + enqueue one outbound `ResponseFinal` frame terminating
    /// the reply chain for `request_id`. Mirrors
    /// `SessionLinkActions::send_response_final`.
    ///
    /// R2595 — `qos` is the QUERY's, and it is a parameter rather than a
    /// default for the reason the builder takes one: a terminator that read as
    /// DEFAULT would be droppable while the replies it closes are not.
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(&self, request_id: u64, qos: crate::sample::QosLevel);

    /// Open a window in which the messages the next calls send leave together as one frame, and
    /// say whether this call opened it (to be handed back to [`Self::end_burst`]). The replies a
    /// drain sends and the `Final` that ends them are one burst: a query answered with one reply
    /// is two messages, and a datagram each costs a system call, a wake of the router and a
    /// frame header more than one frame does.
    ///
    /// A window that is already open (the application's own, or the link's writer's, which keeps
    /// one open for good) is not this call's to close, so the answer is `false` and
    /// [`Self::end_burst`] then leaves it alone. The provided form opens nothing, which is right
    /// for a sink that cannot coalesce and for a build without `transport-batching`.
    fn begin_burst(&self) -> bool {
        false
    }

    /// Close the window [`Self::begin_burst`] opened, if that call opened one, and send what it
    /// gathered.
    fn end_burst(&self, opened: bool) {
        let _ = opened;
    }
}

/// Declarer-side liveliness interest-response emit. Separate from
/// [`ResponseSink`] because a `Declare(DeclToken|DeclFinal)` reply to a
/// peer's liveliness Interest is a distinct message family from a query
/// `Response` — a consumer can drain query replies without ever emitting a
/// liveliness interest-response (the multicast reply loop does exactly
/// that). Empty in a build without `liveliness-token`.
pub trait DeclareReplySink {
    /// R283 / R311hn (Track 2, Decision 2 no-heap emit) — encode + enqueue
    /// one outbound `Declare(DeclToken)` frame replying to a peer's
    /// liveliness Interest. The declarer-side liveliness-token registry
    /// drains its staged interest-response declarations (one
    /// `interest_id`-tagged `DeclToken` per matching held token, then a
    /// terminating [`send_declare_final_reply`](Self::send_declare_final_reply))
    /// through this borrowed-argument seam: the registry passes the held
    /// token's id + resolved keyexpr literal + the peer's `interest_id`,
    /// and the sink owns the encode (an AP sink encodes through a
    /// `VecSink`; an MCU sink encodes through `SliceSink` over a stack
    /// buffer with zero heap). This keeps the registry decoupled from the
    /// wire format (mirror of the `QueryResponder` split) and removes the
    /// owned `DeclareOwned` from the no-heap control plane.
    ///
    /// Gated on `liveliness-token` (NOT `all(.., alloc)`): the borrowed
    /// arguments carry no heap, so the seam composes on the MCU no-alloc
    /// profile. `liveliness-token` transitively pulls `codec-declare`
    /// (the encode path).
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64);

    /// R283 / R311hn — encode + enqueue the `Declare(DeclFinal)` that
    /// terminates the liveliness interest-response chain for
    /// `interest_id`. Emitted once after the matching
    /// [`send_declare_token_reply`](Self::send_declare_token_reply) calls (and emitted
    /// even when no token matched, so the peer's pending CURRENT query
    /// always resolves). Carries only `interest_id` — no heap — so it
    /// composes on the MCU no-alloc profile.
    ///
    /// R311y530 — the gate WIDENED to the union of the two chains that
    /// terminate with it. `DeclFinal` is not a liveliness message: it is the
    /// terminator of ANY interest-response chain, and the session-local
    /// SUBSCRIBER chain
    /// ([`send_declare_subscriber_reply`](Self::send_declare_subscriber_reply))
    /// needs the identical byte. Its builder already lived in the ungated
    /// `declare_build` module; only this seam's gate was narrower than the
    /// message.
    #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
    fn send_declare_final_reply(&self, interest_id: u64);

    /// R311y530 — encode + enqueue one `Declare(DeclSubscriber)` answering a
    /// remote publisher's SUBSCRIBER `Interest` from this session's OWN
    /// (session-local) subscriptions, terminated by
    /// [`send_declare_final_reply`](Self::send_declare_final_reply).
    ///
    /// This is the seam a zenoh-pico DECLARED publisher's write filter depends
    /// on, and its absence is SILENT in exactly one direction. pico arms
    /// `_z_write_filter_create` (`net/filtering.c`) per `z_declare_publisher`
    /// and drops every put LOCALLY until it observes a matching
    /// `DeclSubscriber`; a plain `z_put` carries no filter, so a session that
    /// never answers the interest still passes every `z_put` test while
    /// silently discarding an entire class of publisher.
    ///
    /// `keyexpr` is the REPLY keyexpr, which is not always the subscription's
    /// own: for an AGGREGATE interest (pico client publishers always are) it is
    /// the INTEREST's keyexpr, because the peer associates an aggregate
    /// interest's replies by `_z_keyexpr_equals`
    /// (`session/interest.c:274-276`, and the same rule again in
    /// `_z_interest_replay_declare` at :603-605) — answering a WILDCARD
    /// subscription keyexpr decodes fine and matches NOTHING. The registry owns
    /// that choice; the sink just encodes what it is handed.
    #[cfg(feature = "declare-subscriber")]
    fn send_declare_subscriber_reply(&self, subscriber_id: u64, keyexpr: &str, interest_id: u64);

    /// R2292 (open-debt item 627) — encode + enqueue the `Declare(
    /// UndeclSubscriber)` that retracts an AGGREGATE interest-response
    /// declaration whose last matching local subscription has gone away.
    ///
    /// The counterpart of
    /// [`send_declare_subscriber_reply`](Self::send_declare_subscriber_reply),
    /// and the reason it is a SEPARATE seam rather than a flag on that one:
    /// the retraction carries no keyexpr and no `interest_id`. A peer routes
    /// an id-only undeclare by id alone, which is also why R2292 had to put
    /// the aggregate decl id and the subscription id in ONE space first —
    /// two counters both starting at 1 make this call ambiguous.
    ///
    /// Gated on `declare-undeclare` as well: without it this session has no
    /// `UndeclSubscriber` emit at all (a routed subscriber's own teardown is
    /// gated the same way), so the retraction has nothing to ride on.
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    fn send_undeclare_subscriber_reply(&self, subscriber_id: u64);

    /// Encode + enqueue one `Declare(DeclQueryable)` answering a remote
    /// QUERIER's `Interest` from this session's OWN queryables, terminated by
    /// [`send_declare_final_reply`](Self::send_declare_final_reply): the
    /// queryable twin of
    /// [`send_declare_subscriber_reply`](Self::send_declare_subscriber_reply).
    ///
    /// A zenoh-pico querier drops every query locally until a matching
    /// `DeclQueryable` stamped with its interest's id reaches its write
    /// filter, so a session that does not answer the interest serves it only
    /// when an earlier unsolicited declaration happened to be processed first.
    ///
    /// `keyexpr` is the REPLY key: the queryable's own, or for an AGGREGATE
    /// interest the INTEREST's (the registry owns that choice). `complete` is
    /// the queryable's `QueryableInfo.complete`, which an `AllComplete` querier's
    /// filter requires before it opens.
    ///
    /// A default body that sends nothing, so a sink that cannot answer (the
    /// multicast reply loop) is a sink that does not, as it always was.
    #[cfg(all(feature = "alloc", feature = "declare-queryable"))]
    fn send_declare_queryable_reply(
        &self,
        queryable_id: u64,
        keyexpr: &str,
        complete: bool,
        interest_id: u64,
    ) {
        let _ = (queryable_id, keyexpr, complete, interest_id);
    }
}

/// Terminated liveliness-get reconnect-cache prune. NOT a wire emit — a
/// bundle-state effect — so it is its own trait rather than crammed under
/// a "Response" name. Empty in a build without `liveliness-get`.
pub trait LivelinessGetPrune {
    /// F3 — drop the session-reconnect declaration-cache entry for a
    /// liveliness get whose snapshot terminated (inbound `DeclFinal` or
    /// local timeout). A get is one-shot: the requester never emits an
    /// interest-FINAL for it (the peer's `DeclFinal` ends the protocol),
    /// so this is the only prune path its `LivelinessGetInterest` cache
    /// entry has — without it every finished get replays a stale CURRENT
    /// Interest on each reconnect (zenoh-pico shares the leak; wz closes
    /// it). The observer's get-prune drain drains the registry's staged
    /// terminations through here. No-op when `session-reconnect`
    /// is off (no cache exists) — implementors keep the body
    /// feature-stable per R311g1.
    #[cfg(feature = "liveliness-get")]
    fn prune_liveliness_get_interest(&self, interest_id: u64);
}

// Smart-pointer / reference transparency: an `Arc`-shared or borrowed
// sink is still a sink. Production AP callers hold the actions handle as
// `Arc<SessionLinkActions>` (shared across the driver + per-query tasks),
// so these blanket impls let a `<S: …Sink>` drain accept the Arc (or a
// `&SessionLinkActions`) directly without unwrapping — the same
// ergonomics the prior concrete `&SessionLinkActions<R, T>` parameter got
// for free via deref coercion. Each trait forwards its own (possibly
// empty) method set, matching the trait's gated surface. One blanket pair
// (&S + Arc<S>) per trait keeps the segregation: a type implementing only
// `ResponseSink` gets the `ResponseSink` forwards without being forced to
// satisfy the other two.

impl<S: ResponseSink + ?Sized> ResponseSink for &S {
    #[cfg(all(feature = "codec-response", feature = "alloc"))]
    fn send_response(&self, response: ResponseOwned) {
        (**self).send_response(response)
    }
    #[cfg(all(feature = "codec-response", feature = "storage-profile"))]
    fn send_reply_parts(&self, parts: crate::reply_stage::ReplyParts<'_>) {
        (**self).send_reply_parts(parts)
    }
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(&self, request_id: u64, qos: crate::sample::QosLevel) {
        (**self).send_response_final(request_id, qos)
    }
    fn begin_burst(&self) -> bool {
        (**self).begin_burst()
    }
    fn end_burst(&self, opened: bool) {
        (**self).end_burst(opened)
    }
}

impl<S: DeclareReplySink + ?Sized> DeclareReplySink for &S {
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        (**self).send_declare_token_reply(token_id, keyexpr, interest_id)
    }
    #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
    fn send_declare_final_reply(&self, interest_id: u64) {
        (**self).send_declare_final_reply(interest_id)
    }
    #[cfg(feature = "declare-subscriber")]
    fn send_declare_subscriber_reply(&self, subscriber_id: u64, keyexpr: &str, interest_id: u64) {
        (**self).send_declare_subscriber_reply(subscriber_id, keyexpr, interest_id)
    }
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    fn send_undeclare_subscriber_reply(&self, subscriber_id: u64) {
        (**self).send_undeclare_subscriber_reply(subscriber_id)
    }
    #[cfg(all(feature = "alloc", feature = "declare-queryable"))]
    fn send_declare_queryable_reply(
        &self,
        queryable_id: u64,
        keyexpr: &str,
        complete: bool,
        interest_id: u64,
    ) {
        (**self).send_declare_queryable_reply(queryable_id, keyexpr, complete, interest_id)
    }
}

impl<S: LivelinessGetPrune + ?Sized> LivelinessGetPrune for &S {
    #[cfg(feature = "liveliness-get")]
    fn prune_liveliness_get_interest(&self, interest_id: u64) {
        (**self).prune_liveliness_get_interest(interest_id)
    }
}

// R311ja — gated on `target_has_atomic = "ptr"`: `alloc::sync::Arc` itself is
// unavailable on ARMv6-M (Cortex-M0/M0+), so naming it in an impl header would
// fail the no-alloc M0 session cross-compile. The AP profile (which has atomic
// `Arc` and is the only profile that hands an `Arc`-shared sink to a drain)
// keeps it; the single-task MCU profile reaches a shared sink through the
// unconditional `&S` impl or the bundle's own sink impls, never an `Arc`. An
// `Rc<S>` mirror is intentionally omitted until an MCU query / reply consumer
// actually drains through a refcounted sink (no caller today — the MCU drive
// loop does not run the reply drain).

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl<S: ResponseSink + ?Sized> ResponseSink for alloc::sync::Arc<S> {
    #[cfg(feature = "codec-response")]
    fn send_response(&self, response: ResponseOwned) {
        (**self).send_response(response)
    }
    #[cfg(feature = "codec-response")]
    fn send_reply_parts(&self, parts: crate::reply_stage::ReplyParts<'_>) {
        (**self).send_reply_parts(parts)
    }
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(&self, request_id: u64, qos: crate::sample::QosLevel) {
        (**self).send_response_final(request_id, qos)
    }
    fn begin_burst(&self) -> bool {
        (**self).begin_burst()
    }
    fn end_burst(&self, opened: bool) {
        (**self).end_burst(opened)
    }
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl<S: DeclareReplySink + ?Sized> DeclareReplySink for alloc::sync::Arc<S> {
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        (**self).send_declare_token_reply(token_id, keyexpr, interest_id)
    }
    #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
    fn send_declare_final_reply(&self, interest_id: u64) {
        (**self).send_declare_final_reply(interest_id)
    }
    #[cfg(feature = "declare-subscriber")]
    fn send_declare_subscriber_reply(&self, subscriber_id: u64, keyexpr: &str, interest_id: u64) {
        (**self).send_declare_subscriber_reply(subscriber_id, keyexpr, interest_id)
    }
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    fn send_undeclare_subscriber_reply(&self, subscriber_id: u64) {
        (**self).send_undeclare_subscriber_reply(subscriber_id)
    }
    #[cfg(all(feature = "alloc", feature = "declare-queryable"))]
    fn send_declare_queryable_reply(
        &self,
        queryable_id: u64,
        keyexpr: &str,
        complete: bool,
        interest_id: u64,
    ) {
        (**self).send_declare_queryable_reply(queryable_id, keyexpr, complete, interest_id)
    }
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl<S: LivelinessGetPrune + ?Sized> LivelinessGetPrune for alloc::sync::Arc<S> {
    #[cfg(feature = "liveliness-get")]
    fn prune_liveliness_get_interest(&self, interest_id: u64) {
        (**self).prune_liveliness_get_interest(interest_id)
    }
}

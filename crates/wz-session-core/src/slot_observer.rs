// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The application-layer observer of the session-slot profile: what the
//! APPLICATION registers, and nothing a peer writes (fixed-memory step S9a,
//! decision Q7).
//!
//! [`crate::observer::ApplicationLayerObserver`] is the AP's: one per session,
//! holding every registry including the tables its peer fills. Under
//! `session-slot` a process serves several sessions from one set of application
//! registrations, so the shape splits by who writes the table:
//!
//! - HERE, once per process: the subscriber table, the queryable table, the
//!   local tokens, the switchboard, and the observer lists of the declaration
//!   registries (what the application listens to);
//! - in each session's SLOT ([`crate::peer_tables::PeerTables`], reached through
//!   `SlotRef::peers`): the peer's keyexpr aliases, its declarations, its
//!   interests, the replies and `Final`s its queries owe, the answers to its
//!   liveliness interests. A wire id is scoped by its session, so these cannot
//!   be shared, and a flood of one session's must stay that session's;
//! - beside each session, caller-supplied ([`crate::slot_observer::Requesters`]): the requester-side
//!   pending queries, which the application writes and whose request ids are
//!   minted per session. They are generic over the application's reply sink, so
//!   the owner of the session (the image) types them; a heap-closure sink makes
//!   them the AP's, a closed enum makes them allocation-free.
//!
//! Every dispatch and drain takes the session's tables as an argument, so the one
//! observer serves every slot and never holds a session's state between calls.
//! The order and the rules are the AP observer's, step for step (the subscriber
//! side first so a `DeclKexpr` binds before the planes that resolve through it;
//! a liveliness get's replies claimed before the token planes see them; every
//! Reply drained before the `Final` that terminates it).

// `Requesters` is generic over the application's reply sink and names no heap
// type. `SlotObserver` below registers heap-boxed sinks, so it and everything
// only it names sit behind `alloc`.
#[cfg(all(feature = "alloc", feature = "liveliness-token"))]
use crate::declare::liveliness::LivelinessRegistry;
#[cfg(feature = "liveliness-get")]
use crate::declare::liveliness_get::LivelinessGetRegistry;
#[cfg(all(feature = "alloc", feature = "liveliness-subscriber"))]
use crate::declare::liveliness_subscriber::LivelinessSubscriberTable;
#[cfg(all(feature = "alloc", feature = "liveliness-token"))]
use crate::declare::local_token::{DeclResponseItem, LocalTokenRegistry};
#[cfg(all(feature = "alloc", feature = "declare-queryable"))]
use crate::declare::queryable::RemoteQueryableTable;
#[cfg(all(feature = "alloc", feature = "declare-subscriber"))]
use crate::declare::subscriber::RemoteSubscriberTable;
#[cfg(feature = "alloc")]
use crate::driver_loop::IterationEvent;
#[cfg(feature = "alloc")]
use crate::peer_tables::PeerTables;
#[cfg(feature = "alloc")]
use crate::pubsub::SubscriberTable;
#[cfg(all(feature = "alloc", feature = "query-queryable"))]
use crate::query::QueryableRegistry;
use crate::reply::ReplyRegistry;
use crate::reply_sink::ReplySink;
#[cfg(all(feature = "alloc", feature = "query-queryable"))]
use crate::reply_stage::{FinalStaging, ReplyStaging};
#[cfg(feature = "alloc")]
use crate::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
#[cfg(all(feature = "alloc", feature = "switchboard"))]
use crate::switchboard::{EventInjector, SwitchboardRegistry};

/// The requester-side registries of ONE session: the pending `z_get`s and, with
/// `liveliness-get`, the pending liveliness snapshots. Written by the
/// application when it asks and completed by the peer's answer, and keyed by
/// request and interest ids this session minted, so two sessions' ids collide in
/// one registry: each session has its own, placed beside its slot by whoever owns
/// the session.
pub struct Requesters<R: ReplySink, G: ReplySink> {
    /// The pending queries (`z_get`), bounded by [`crate::caps::MAX_PENDING_QUERIES`].
    pub replies: ReplyRegistry<R>,
    /// The pending liveliness snapshots, bounded by
    /// [`crate::caps::MAX_PENDING_LIVELINESS_GETS`].
    #[cfg(feature = "liveliness-get")]
    pub liveliness_gets: LivelinessGetRegistry<G>,
    #[cfg(not(feature = "liveliness-get"))]
    _gets: core::marker::PhantomData<G>,
}

impl<R: ReplySink, G: ReplySink> Requesters<R, G> {
    /// No query pending.
    pub fn new() -> Self {
        Self {
            replies: ReplyRegistry::with_sink_backing(),
            #[cfg(feature = "liveliness-get")]
            liveliness_gets: LivelinessGetRegistry::with_sink_backing(),
            #[cfg(not(feature = "liveliness-get"))]
            _gets: core::marker::PhantomData,
        }
    }
}

impl<R: ReplySink, G: ReplySink> Default for Requesters<R, G> {
    fn default() -> Self {
        Self::new()
    }
}

/// What the application registered, shared by every session of the process. See
/// the module documentation. It registers heap-boxed sinks, so it is the
/// heap-profile observer; a build with no allocator types its own registrations.
#[cfg(feature = "alloc")]
pub struct SlotObserver {
    /// The local subscriptions. One registration serves every session.
    pub subscribers: SubscriberTable<crate::sink::BoxedSink>,
    /// The statechart switchboard (the keyexpr -> event table).
    #[cfg(feature = "switchboard")]
    pub switchboard: SwitchboardRegistry,
    /// The local queryables.
    #[cfg(feature = "query-queryable")]
    pub queryables: QueryableRegistry<crate::query_sink::BoxedQuerySink>,
    /// The application's listeners on the subscribers a peer declares.
    #[cfg(feature = "declare-subscriber")]
    pub remote_subscribers:
        RemoteSubscriberTable<crate::decl_sink::BoxedDeclSink, crate::decl_sink::BoxedUndeclSink>,
    /// The application's listeners on the queryables a peer declares.
    #[cfg(feature = "declare-queryable")]
    pub remote_queryables:
        RemoteQueryableTable<crate::decl_sink::BoxedDeclSink, crate::decl_sink::BoxedUndeclSink>,
    /// The application's listeners on the tokens a peer declares.
    #[cfg(feature = "liveliness-token")]
    pub liveliness:
        LivelinessRegistry<crate::decl_sink::BoxedDeclSink, crate::decl_sink::BoxedUndeclSink>,
    /// The tokens wz itself holds, answered to a peer's interest.
    #[cfg(feature = "liveliness-token")]
    pub local_tokens: LocalTokenRegistry,
    /// The local liveliness subscribers.
    #[cfg(feature = "liveliness-subscriber")]
    pub liveliness_subscribers:
        LivelinessSubscriberTable<crate::declare::liveliness_sample::BoxedLivelinessSampleSink>,
}

#[cfg(feature = "alloc")]
impl Default for SlotObserver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl SlotObserver {
    /// An observer with nothing registered.
    pub fn new() -> Self {
        Self {
            subscribers: SubscriberTable::new(),
            #[cfg(feature = "switchboard")]
            switchboard: SwitchboardRegistry::new(),
            #[cfg(feature = "query-queryable")]
            queryables: QueryableRegistry::new(),
            #[cfg(feature = "declare-subscriber")]
            remote_subscribers: RemoteSubscriberTable::with_sink_backing(),
            #[cfg(feature = "declare-queryable")]
            remote_queryables: RemoteQueryableTable::with_sink_backing(),
            #[cfg(feature = "liveliness-token")]
            liveliness: LivelinessRegistry::new(),
            #[cfg(feature = "liveliness-token")]
            local_tokens: LocalTokenRegistry::new(),
            #[cfg(feature = "liveliness-subscriber")]
            liveliness_subscribers: LivelinessSubscriberTable::with_sink_backing(),
        }
    }

    /// Fan an [`IterationEvent`] of one session into every registry, against that
    /// session's `peers`. The subscriber side runs first so its alias absorb
    /// binds a `DeclKexpr` BEFORE the planes that resolve keyexprs through it.
    ///
    /// What a queryable stages goes to `peers.replies` / `peers.finals`, and a
    /// `Request` whose `Final` the table cannot hold never reaches one
    /// ([`crate::reply_stage`]). `requesters` is the session's own.
    pub fn dispatch_event<R: ReplySink, G: ReplySink>(
        &mut self,
        peers: &mut PeerTables,
        requesters: &mut Requesters<R, G>,
        event: IterationEvent<'_>,
    ) {
        self.subscribers
            .dispatch_iteration_event(&mut peers.subscribers, event);
        // The two id spaces this session resolves through, as the subscriber side
        // just refreshed them (R311y739): an `M=0` alias names an id WE declared
        // and is answered out of the right table on every plane.
        #[cfg(any(
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "liveliness-token",
            feature = "liveliness-subscriber",
            feature = "liveliness-get",
            feature = "query-queryable",
            feature = "codec-response",
            feature = "codec-response-final",
        ))]
        let peer_table = peers.subscribers.mapping_spaces();

        #[cfg(feature = "query-queryable")]
        self.queryables.dispatch_iteration_event(
            event,
            peer_table,
            &mut peers.replies,
            &mut peers.finals,
        );
        // R311y788 -- the remote-subscriber fan carries the session-local half of
        // the matching verdict, read from the sibling subscriber table.
        #[cfg(feature = "declare-subscriber")]
        {
            let subscribers = &self.subscribers;
            self.remote_subscribers.dispatch_iteration_event_with_local(
                &mut peers.remote_subscribers,
                event,
                peer_table,
                &|c| c.locality.allows_local() && subscribers.has_local_matching(&c.keyexpr),
            );
        }
        #[cfg(all(feature = "declare-queryable", feature = "query-queryable"))]
        {
            let queryables = &self.queryables;
            self.remote_queryables.dispatch_iteration_event_with_local(
                &mut peers.remote_queryables,
                event,
                peer_table,
                &|c| {
                    c.locality.allows_local()
                        && queryables.has_local_matching(&c.keyexpr, c.complete_required)
                },
            );
        }
        #[cfg(all(feature = "declare-queryable", not(feature = "query-queryable")))]
        self.remote_queryables.dispatch_iteration_event(
            &mut peers.remote_queryables,
            event,
            peer_table,
        );
        // A `Declare(DeclToken)` whose outer `interest_id` names a pending
        // liveliness GET belongs to that GET and to no observer plane (zenoh
        // answers the query and returns first): the claim is per id.
        #[cfg(all(feature = "liveliness-token", feature = "liveliness-get"))]
        {
            let gets = &requesters.liveliness_gets;
            self.liveliness
                .dispatch_iteration_event_unclaimed(event, peer_table, &|id| gets.has_pending(id));
        }
        #[cfg(all(feature = "liveliness-token", not(feature = "liveliness-get")))]
        self.liveliness.dispatch_iteration_event(event, peer_table);
        // R283 -- stage an interest-response for each inbound non-final liveliness
        // Interest, whole chains or none, into THIS session's staging.
        #[cfg(feature = "liveliness-token")]
        {
            let refused = self.local_tokens.dispatch_iteration_event(
                event,
                peer_table,
                &mut peers.pending_declares,
            );
            peers.token_interest_chains_refused = peers
                .token_interest_chains_refused
                .saturating_add(u32::try_from(refused).unwrap_or(u32::MAX));
        }
        #[cfg(all(feature = "liveliness-subscriber", feature = "liveliness-get"))]
        {
            let gets = &requesters.liveliness_gets;
            self.liveliness_subscribers
                .dispatch_iteration_event_unclaimed(&mut peers.tokens, event, peer_table, &|id| {
                    gets.has_pending(id)
                });
        }
        #[cfg(all(feature = "liveliness-subscriber", not(feature = "liveliness-get")))]
        self.liveliness_subscribers
            .dispatch_iteration_event(&mut peers.tokens, event, peer_table);
        #[cfg(feature = "liveliness-get")]
        requesters
            .liveliness_gets
            .dispatch_iteration_event(event, peer_table);
        #[cfg(any(feature = "codec-response", feature = "codec-response-final"))]
        requesters
            .replies
            .dispatch_iteration_event(event, peer_table);
        // Consumed only by the arms above, which a build with none of them lacks.
        #[cfg(not(feature = "liveliness-get"))]
        let _ = &requesters;
        let _ = (&peers, event);
    }

    /// Drain what the last [`Self::dispatch_event`] staged for this session
    /// through its send path: the replies, the answers to its interests, the
    /// terminated-get prunes, and last the `Final`s, so every Reply for a request
    /// precedes the `Final` that ends it.
    pub fn flush_pending<S, R: ReplySink, G: ReplySink>(
        &mut self,
        peers: &mut PeerTables,
        requesters: &mut Requesters<R, G>,
        actions: &S,
    ) where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.drain_query_replies(peers, actions);
        self.drain_declare_replies(peers, actions);
        self.drain_get_prunes(requesters, actions);
        self.drain_query_finals(peers, actions);
    }

    /// Fan and drain in one call: [`Self::dispatch_event`] then
    /// [`Self::flush_pending`], the shape a session's `on_event` takes.
    pub fn dispatch<S, R: ReplySink, G: ReplySink>(
        &mut self,
        peers: &mut PeerTables,
        requesters: &mut Requesters<R, G>,
        event: IterationEvent<'_>,
        actions: &S,
    ) where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.dispatch_event(peers, requesters, event);
        self.flush_pending(peers, requesters, actions);
    }

    /// Fan an event into the statechart switchboard against the session's alias
    /// table; see [`crate::observer::ApplicationLayerObserver::dispatch_switchboard`].
    #[cfg(feature = "switchboard")]
    pub fn dispatch_switchboard(
        &self,
        peers: &PeerTables,
        event: IterationEvent<'_>,
        injector: &mut dyn EventInjector,
    ) -> usize {
        self.switchboard.dispatch_iteration_event(
            event,
            peers.subscribers.mapping_spaces(),
            injector,
        )
    }

    /// The link of this session was lost: every token its peer had declared is
    /// flushed, delivering a `Delete` to each matching subscriber. Returns the
    /// count. A no-op without `liveliness-subscriber`.
    pub fn flush_liveliness_on_link_loss(&mut self, peers: &mut PeerTables) -> usize {
        #[cfg(feature = "liveliness-subscriber")]
        {
            self.liveliness_subscribers
                .flush_peer_tokens_on_link_loss(&mut peers.tokens)
        }
        #[cfg(not(feature = "liveliness-subscriber"))]
        {
            let _ = peers;
            0
        }
    }

    /// The link of this session was lost: every subscriber and queryable its peer
    /// had declared is gone, and the matching watches are re-evaluated against what
    /// remains. Returns the number of declarations dropped.
    pub fn flush_declarations_on_link_loss(&mut self, peers: &mut PeerTables) -> usize {
        #[allow(unused_mut)]
        let mut dropped = 0usize;
        #[cfg(all(feature = "declare-subscriber", feature = "codec-declare"))]
        {
            let subscribers = &self.subscribers;
            dropped += self
                .remote_subscribers
                .flush_declarations_on_link_loss(&mut peers.remote_subscribers, &|c| {
                    c.locality.allows_local() && subscribers.has_local_matching(&c.keyexpr)
                });
        }
        #[cfg(all(
            feature = "declare-queryable",
            feature = "query-queryable",
            feature = "codec-declare"
        ))]
        {
            let queryables = &self.queryables;
            dropped += self.remote_queryables.flush_declarations_on_link_loss(
                &mut peers.remote_queryables,
                &|c| {
                    c.locality.allows_local()
                        && queryables.has_local_matching(&c.keyexpr, c.complete_required)
                },
            );
        }
        #[cfg(all(
            feature = "declare-queryable",
            not(feature = "query-queryable"),
            feature = "codec-declare"
        ))]
        {
            dropped += self
                .remote_queryables
                .flush_declarations_on_link_loss(&mut peers.remote_queryables, &|_| false);
        }
        let _ = &peers;
        dropped
    }

    /// The staged replies, through `send_response`. A reply whose bounded field
    /// overflows cannot be wire-encoded and is skipped, as on the AP.
    fn drain_query_replies<S: ResponseSink>(&mut self, peers: &mut PeerTables, sink: &S) {
        #[cfg(feature = "query-queryable")]
        for reply in peers.replies.drain_staged() {
            if let Ok(response) = reply.into_response() {
                sink.send_response(response);
            }
        }
        #[cfg(not(feature = "query-queryable"))]
        let _ = (peers, sink);
    }

    /// The `Final`s owed, through `send_response_final`.
    fn drain_query_finals<S: ResponseSink>(&mut self, peers: &mut PeerTables, sink: &S) {
        #[cfg(all(feature = "query-queryable", feature = "codec-response-final"))]
        for (rid, qos) in peers.finals.drain_owed() {
            sink.send_response_final(rid, qos);
        }
        #[cfg(all(feature = "query-queryable", not(feature = "codec-response-final")))]
        peers.finals.drain_owed().for_each(drop);
        #[cfg(not(all(feature = "query-queryable", feature = "codec-response-final")))]
        let _ = (peers, sink);
    }

    /// The answers to the peer's interests: the subscriber interest chains first,
    /// then the liveliness ones, each batch's items before its terminating `Final`.
    fn drain_declare_replies<S: DeclareReplySink>(&mut self, peers: &mut PeerTables, sink: &S) {
        #[cfg(feature = "declare-subscriber")]
        for item in peers.subscribers.take_staged_sub_interest_replies() {
            match &item {
                crate::pubsub::SubInterestReply::Final { interest_id } => {
                    sink.send_declare_final_reply(*interest_id)
                }
                crate::pubsub::SubInterestReply::Aggregate { interest_id }
                | crate::pubsub::SubInterestReply::Concrete { interest_id, .. } => {
                    let interest_id = *interest_id;
                    let mut announced_aggregate = false;
                    if let Some((subscriber_id, keyexpr)) = self
                        .subscribers
                        .sub_interest_reply(&peers.subscribers, &item)
                    {
                        sink.send_declare_subscriber_reply(subscriber_id, keyexpr, interest_id);
                        announced_aggregate =
                            matches!(item, crate::pubsub::SubInterestReply::Aggregate { .. });
                    }
                    // Recorded AFTER the emit and outside the borrow above, and
                    // only when the reply actually left (R2292).
                    #[cfg(feature = "declare-undeclare")]
                    if announced_aggregate {
                        peers.subscribers.mark_aggregate_announced(interest_id);
                    }
                    let _ = announced_aggregate;
                }
                #[cfg(feature = "declare-undeclare")]
                crate::pubsub::SubInterestReply::AggregateRetract { interest_id } => {
                    if let Some(decl_id) = self
                        .subscribers
                        .take_aggregate_retract(&mut peers.subscribers, *interest_id)
                    {
                        sink.send_undeclare_subscriber_reply(decl_id);
                    }
                }
            }
        }
        #[cfg(feature = "liveliness-token")]
        for item in core::mem::take(&mut peers.pending_declares) {
            match item {
                DeclResponseItem::Token {
                    token_id,
                    interest_id,
                } => {
                    // A token unregistered between stage and drain is skipped;
                    // its chain's Final still terminates.
                    if let Some(keyexpr) = self.local_tokens.keyexpr_for(token_id) {
                        sink.send_declare_token_reply(token_id, keyexpr, interest_id);
                    }
                }
                DeclResponseItem::Final { interest_id } => {
                    sink.send_declare_final_reply(interest_id)
                }
            }
        }
        #[cfg(not(any(feature = "liveliness-token", feature = "declare-subscriber")))]
        let _ = (peers, sink);
    }

    /// The liveliness gets that terminated, through `prune_liveliness_get_interest`.
    fn drain_get_prunes<S: LivelinessGetPrune, R: ReplySink, G: ReplySink>(
        &mut self,
        requesters: &mut Requesters<R, G>,
        sink: &S,
    ) {
        #[cfg(feature = "liveliness-get")]
        for interest_id in requesters.liveliness_gets.take_finalized() {
            sink.prune_liveliness_get_interest(interest_id);
        }
        #[cfg(not(feature = "liveliness-get"))]
        let _ = (requesters, sink);
    }
}

#[cfg(all(
    test,
    feature = "codec-push",
    feature = "codec-declare",
    feature = "pubsub-put",
    feature = "declare-subscriber"
))]
mod tests {
    //! The own-space witness of the slot fan (R311y740, carry N37): this fan is
    //! the edge every plane of a session reaches its two id spaces through, so a
    //! fan that handed over the peer table alone would type-check and silently
    //! restore the wrong-space read on every plane at once. The per-registry
    //! witnesses cannot see the edge; these drive it.
    use super::*;
    use crate::decl_sink::{BoxedDeclSink, DeclView};
    use crate::driver_loop::DriverLoopOutcome;
    use crate::locality::Locality;
    use crate::network_message::NetworkMessage;
    use crate::reply_sink::BoxedReplySink;
    use crate::sink::{BoxedSink, SampleView};
    use alloc::boxed::Box;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use std::sync::{Arc, Mutex};
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;
    use wz_session_core_test_support as fx;

    type Req = Requesters<BoxedReplySink, BoxedReplySink>;

    fn frame(messages: Vec<NetworkMessage>) -> DriverLoopOutcome {
        DriverLoopOutcome::FramePayload {
            priority: crate::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages,
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    /// A Push naming id `mapping_id` with `M=0`: the id is in OUR space.
    fn push_own_alias(mapping_id: u64) -> crate::wire::PushOwned {
        use wz_codecs::push::Push;
        Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: mapping_id,
                    suffix_len: None,
                    suffix: None,
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap()
    }

    /// One observer with a subscriber on each of the two literals, a listener on
    /// the subscribers a peer declares, and a session whose PEER declared id 7 as
    /// `theirs/x`, absorbed through the ordinary inbound `DeclKexpr` path. The
    /// session's own space holds id 7 as `ours/x` when `own` is set. The
    /// collision is the discriminator: a fan handing over the peer's table alone
    /// would resolve a confident wrong keyexpr, not drop the frame.
    struct Fixture {
        observer: SlotObserver,
        peers: PeerTables,
        requesters: Req,
        ours: Arc<Mutex<Vec<String>>>,
        theirs: Arc<Mutex<Vec<String>>>,
        declared: Arc<Mutex<Vec<String>>>,
    }

    fn fixture(own: bool) -> Fixture {
        let mut observer = SlotObserver::new();
        let mut peers = PeerTables::new();
        let mut requesters = Req::new();
        if own {
            let mut space = hashbrown::HashMap::new();
            space.insert(7u64, "ours/x".to_string());
            peers.subscribers.set_own_mapping_space(Arc::new(space));
        }
        let outcome = frame(vec![NetworkMessage::Declare(Box::new(
            fx::declare_envelope_decl_kexpr(fx::decl_kexpr(7, "theirs/x")),
        ))]);
        observer.dispatch_event(&mut peers, &mut requesters, IterationEvent::Poll(&outcome));

        let mut record = |literal: &str| {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let into = seen.clone();
            observer
                .subscribers
                .register_sink(
                    literal,
                    Locality::Any,
                    BoxedSink::new(move |s: &dyn SampleView| {
                        into.lock().unwrap().push(s.keyexpr().to_string());
                    }),
                )
                .expect("register");
            seen
        };
        let ours = record("ours/x");
        let theirs = record("theirs/x");
        let declared = Arc::new(Mutex::new(Vec::new()));
        let into = declared.clone();
        observer
            .remote_subscribers
            .on_subscriber_declared_sink(BoxedDeclSink::new(move |d: &dyn DeclView| {
                into.lock().unwrap().push(d.keyexpr().to_string());
            }))
            .expect("install");
        Fixture {
            observer,
            peers,
            requesters,
            ours,
            theirs,
            declared,
        }
    }

    /// The same two messages in both tests: a Push and a `DeclareSubscriber`, each
    /// naming id 7 with `M=0`.
    fn own_alias_frame() -> DriverLoopOutcome {
        frame(vec![
            NetworkMessage::Push(Box::new(push_own_alias(7))),
            NetworkMessage::Declare(Box::new(fx::declare_envelope_decl_subscriber(
                fx::decl_subscriber_nonlocal(1, 7, None),
            ))),
        ])
    }

    #[test]
    fn an_own_space_alias_resolves_through_the_slot_fan_on_both_planes() {
        let mut f = fixture(true);
        let outcome = own_alias_frame();
        f.observer.dispatch_event(
            &mut f.peers,
            &mut f.requesters,
            IterationEvent::Poll(&outcome),
        );
        assert_eq!(
            *f.ours.lock().unwrap(),
            vec!["ours/x".to_string()],
            "the Push plane resolved id 7 in OUR space"
        );
        assert!(
            f.theirs.lock().unwrap().is_empty(),
            "a fan handing over the peer table alone would have fired this one"
        );
        assert_eq!(
            *f.declared.lock().unwrap(),
            vec!["ours/x".to_string()],
            "the declare-subscriber plane resolved id 7 in OUR space"
        );
    }

    /// The anti-vacuity twin: the same frame against a session with no own space
    /// installed resolves nothing on either plane, so the witness above would not
    /// pass on a peer table that merely happened to be empty.
    #[test]
    fn without_an_own_space_the_slot_fan_refuses_the_same_frame_on_both_planes() {
        let mut f = fixture(false);
        let outcome = own_alias_frame();
        f.observer.dispatch_event(
            &mut f.peers,
            &mut f.requesters,
            IterationEvent::Poll(&outcome),
        );
        assert!(
            f.ours.lock().unwrap().is_empty() && f.theirs.lock().unwrap().is_empty(),
            "an M=0 alias must refuse with no own space, never fall back to the peer's table"
        );
        assert!(f.declared.lock().unwrap().is_empty());
    }
}

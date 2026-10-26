// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the session's application layer holds, in the three parts a session that listens needs
//! apart (`docs/capi-pico-on-coop-engine.md`, section 7).
//!
//! - [`Registry::app`], what the application registered (its subscribers, queryables, local
//!   tokens, the listeners on what a peer declares), once for the session however many peers it
//!   comes to hold;
//! - [`Registry::peer`], what ONE peer wrote (its key aliases, its subscribers, queryables and
//!   tokens, its interests, the replies and Finals its queries are owed), which is scoped by that
//!   peer's transport session and so cannot be shared;
//! - [`Registry::gets`], the session's own pending gets, whose request ids the link's actions
//!   mint.
//!
//! The engine has one link, so there is one `peer` and one `gets`. A table of links takes their
//! place, and `app` stays, when the engine accepts a second peer. The observer this replaces
//! (`ApplicationLayerObserver`) held the three together; the dispatch order and the rules are the
//! same, which the heap tests of `slot_observer` hold.

use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::peer_tables::PeerTables;
use wz_session_core::reply_sink::{BoxedReplySink, ConsolidatingSink};
#[cfg(feature = "queryable")]
use wz_session_core::reply_stage::FinalStage;
use wz_session_core::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
use wz_session_core::slot_observer::{Requesters, SlotObserver};

/// The session's own pending gets: a query's sink consolidates what its leg is handed.
pub(super) type Gets = Requesters<ConsolidatingSink<BoxedReplySink>, BoxedReplySink>;

/// The application layer of one session. See the module documentation.
pub(super) struct Registry {
    pub(super) app: SlotObserver,
    pub(super) peer: PeerTables,
    pub(super) gets: Gets,
}

impl Registry {
    /// A session that holds nothing and has been told nothing.
    pub(super) fn new() -> Self {
        Self {
            app: SlotObserver::new(),
            peer: PeerTables::new(),
            gets: Gets::new(),
        }
    }

    /// Fan one iteration's event into the application layer, against the peer's tables.
    pub(super) fn dispatch_event(&mut self, event: IterationEvent<'_>) {
        self.app
            .dispatch_event(&mut self.peer, &mut self.gets, event);
    }

    /// Stage for the peer what the application did to its subscriptions since the peer last
    /// looked, so the drain that follows sends it: the future push a subscription registered
    /// after the peer's interest is owed, and the retraction of an aggregate declaration the last
    /// matching subscription stood for. An observer that held the peer's side beside the table
    /// staged both as it was told; the table that serves one peer or many leaves each peer to
    /// read the table's epoch, and nothing else reads it.
    fn reconcile_subscribers(&mut self) {
        self.peer.subscribers.reconcile(&self.app.subscribers);
    }

    /// Drain what the last [`Self::dispatch_event`] staged, EXCEPT the `Final`s the queries
    /// owe: the replies, the answers to the peer's interests and the terminated-get prunes
    /// leave through `actions`. The `Final`s are taken with [`Self::take_pending_final_rids`].
    #[cfg(feature = "queryable")]
    pub(super) fn flush_pending_replies<S>(&mut self, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.reconcile_subscribers();
        self.app
            .flush_pending_replies(&mut self.peer, &mut self.gets, actions);
    }

    /// The `Final`s the queries owe the peer, each with the QoS of its query, taken so the
    /// caller sends them once the last callback that may still answer has.
    #[cfg(feature = "queryable")]
    pub(super) fn take_pending_final_rids(&mut self) -> FinalStage {
        core::mem::take(&mut self.peer.finals)
    }

    /// Fan and drain in one call, the `Final`s with the rest: what a session with no queryable
    /// to wait for does with each event.
    #[cfg(not(feature = "queryable"))]
    pub(super) fn dispatch<S>(&mut self, event: IterationEvent<'_>, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.dispatch_event(event);
        self.reconcile_subscribers();
        self.app
            .flush_pending(&mut self.peer, &mut self.gets, actions);
    }

    /// The link was lost: every subscriber and queryable its peer declared is gone, and the
    /// matching listeners are told what that makes of them.
    pub(super) fn flush_declarations_on_link_loss(&mut self) -> usize {
        self.app.flush_declarations_on_link_loss(&mut self.peer)
    }

    /// The link was lost: every token its peer declared is gone, and the liveliness subscribers
    /// are told each is.
    pub(super) fn flush_liveliness_on_link_loss(&mut self) -> usize {
        self.app.flush_liveliness_on_link_loss(&mut self.peer)
    }
}

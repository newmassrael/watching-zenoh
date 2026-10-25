// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A client of a router that answers queries, on the slot profile: the node of
//! `crate::client_node` with every session, table and text in storage the image declared and no
//! allocator.
//!
//! It dials the endpoints of an [`EndpointSource`] the image knows at build time
//! ([`StaticEndpoints`](crate::connect_manager::StaticEndpoints)), keeps a session with each and
//! re-dials the ones that drop (the connect manager), and sends the declarations of the queryables
//! and subscribers it answers on every session as it establishes. What answers a query or takes a
//! sample is the observer the sessions dispatch to, built and registered by the image beforehand
//! as the admin node's is (`SlotApp`): a registration that was refused stops the image, rather
//! than starting a node that declares what nothing answers.
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions it dials | `SessionSlots` / `PumpSlots` / the task table of the host | the pool's `max_sessions`, `process.max_tasks` |
//! | endpoints it manages | the connect manager's rows | `caps::MAX_STATIC_CONNECT` |
//! | the declarations | a `&'static` slice the image states | its length |
//!
//! Nothing is grown and nothing falls back to the heap; this module does not link `alloc` on the
//! profile at all.

use core::cell::RefCell;

use wz_runtime_coop::session_drive::{
    Accept, NoAccept, SessionDriveConfig, SessionRole, SlotStack,
};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::ClockSource;
use wz_session_core::bounded::{BoundedVec, CapacityFull};
use wz_session_core::encoding::PACKED_APPLICATION_JSON;
use wz_session_core::locality::Locality;
use wz_session_core::pubsub::SubscriberTable;
use wz_session_core::query::QueryableRegistry;
use wz_session_core::query_sink::{FnQuerySink, QueryView, ReplyOut};
use wz_session_core::registry_error::RegisterError;
use wz_session_core::replay_cursor::ReplayCursor;
use wz_session_core::replay_pacing::ReplayPacing;
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::slot_observer::{NoSink, ObserverSinks};

use crate::connect_manager::{
    ConnectManager, DeclaredPeer, DeclaredRefusal, EndpointSource, PeerStore,
};
use crate::latest::{LatestRef, LatestSink};
use crate::slot_dial::{events_of, Bind, SessionFactory, SlotDialer, SlotSession};
use crate::slot_host::SessionHost;

/// What a declaration announces to the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationKind {
    /// A queryable: the router forwards a GET on the key to this node.
    Queryable,
    /// A subscriber: the router forwards a PUT on the key to this node.
    Subscriber,
    /// A liveliness token: the router tells whoever watches the key that this node is alive, for as
    /// long as this session lasts. A node built without `declare-token` cannot send it, and
    /// refuses to start with one ([`InstallRefused::Tokens`](crate::slot_node::InstallRefused)).
    Token,
}

/// One declaration the node sends on every session as it establishes. Its id on the wire is its
/// place in the node's list plus one, per session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Declaration {
    /// What it announces.
    pub kind: DeclarationKind,
    /// The key it announces, as the registration on the observer names it.
    pub key: &'static str,
}

/// The port a node takes connections on and how many sessions of them it holds at once: the
/// acceptor `X` and the size `N` of the table those sessions live in, stated together because the
/// second is a type-level number the first has no way to name. A node that listens on nothing
/// states [`Listening::NONE`].
pub struct Listening<X, const N: usize> {
    acceptor: X,
}

#[cfg(feature = "listen")]
impl<X, const N: usize> Listening<X, N> {
    /// Take the connections `acceptor` yields, holding up to `N` sessions of them. Only in a build
    /// with the `listen` feature, which carries the accept side of the handshake: an acceptor given
    /// to a node without it would read each InitSyn and answer none.
    pub const fn new(acceptor: X) -> Self {
        Self { acceptor }
    }
}

impl Listening<NoAccept, 0> {
    /// A node that listens on nothing.
    pub const NONE: Self = Self { acceptor: NoAccept };
}

/// A client node on the slot profile over the stack `T`, binding its sockets with `B` and taking
/// the connections that arrive through the acceptor `X`, up to `A` sessions of them at once.
///
/// The sessions it holds are of two kinds that differ only in who opened the link: the ones it
/// dials (the connect manager keeps one for each endpoint it is given, and dials it again when it
/// drops) and the ones a peer opened to it (the table of `A` rows, whose row is free again when
/// its session ends). Everything the node does to a session (declaring on it, answering on it,
/// reporting it) is done to both alike.
pub struct SlotClientNode<'a, C, T, B, F, X, const S: usize, const P: usize, const A: usize>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C>,
    X: Accept<T::Driver>,
{
    manager: ConnectManager<SlotDialer<'a, C, T, B, F, S, P>>,
    declarations: &'static [Declaration],
    host: &'a SessionHost<C, T, F::Entropy, S, P>,
    factory: &'a RefCell<F>,
    timeouts: SessionTimeouts,
    acceptor: X,
    accepted: BoundedVec<SlotSession<C>, A>,
    over_capacity: u32,
    /// How the declarations of a session go out: `None`, one turn for the whole list, unless the
    /// build's `declaration-sync-pacing` policy states a pace ([`ReplayPacing::from_build`]).
    pacing: Option<ReplayPacing>,
}

impl<'a, C, T, B, F, X, const S: usize, const P: usize, const A: usize>
    SlotClientNode<'a, C, T, B, F, X, S, P, A>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C>,
    X: Accept<T::Driver>,
{
    /// A node that dials `endpoints` through `host` (sockets from `bind`, sessions made by
    /// `factory` with the handshake deadlines `timeouts`), takes the connections `acceptor`
    /// yields, and declares `declarations` on each session as it establishes. `peers` is where the
    /// machines of the endpoints it holds live: a table of some 10 KB that is declared with the
    /// node's other big tables and not carried by the node, which is a local of the loop.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: &'a SessionHost<C, T, F::Entropy, S, P>,
        bind: B,
        listening: Listening<X, A>,
        factory: &'a RefCell<F>,
        endpoints: &'static dyn EndpointSource,
        peers: &'static PeerStore,
        timeouts: SessionTimeouts,
        declarations: &'static [Declaration],
    ) -> Self {
        Self {
            manager: ConnectManager::in_static_store(
                endpoints,
                SlotDialer::new(host, bind, factory, timeouts),
                peers,
            ),
            declarations,
            host,
            factory,
            timeouts,
            acceptor: listening.acceptor,
            accepted: BoundedVec::new(),
            over_capacity: 0,
            pacing: ReplayPacing::BUILD,
        }
    }

    /// State how the declarations of a session go out, for a caller that wants a pace regardless
    /// of the build (a test, or a node whose image is built for another policy); the build states
    /// it by default ([`ReplayPacing::from_build`]). `Some` sends the burst's worth of
    /// declarations a turn, and waits at least the interval before the next: the wait is the
    /// interval or the node's tick, whichever is longer, because the replay moves on a tick.
    pub fn set_replay_pacing(&mut self, pacing: Option<ReplayPacing>) {
        self.pacing = pacing;
    }

    /// Every session the node holds, accepted and dialled.
    fn live(&self) -> impl Iterator<Item = &SlotSession<C>> + use<'_, 'a, C, T, B, F, X, S, P, A> {
        self.accepted
            .iter()
            .chain(self.manager.sessions().map(|(_, session)| session))
            .chain(self.manager.node_sessions().map(|(_, session)| session))
    }

    /// How many sessions a peer opened to this node it holds now.
    pub fn accepted_sessions(&self) -> usize {
        self.accepted.len()
    }

    /// How many connections the node took off its port and closed at once because its table of
    /// accepted sessions was full: a peer that finds the connection closed knows the node is at
    /// its limit, as one refused at a full table of a router would.
    pub const fn refused_over_capacity(&self) -> u32 {
        self.over_capacity
    }

    /// Whether some session is established.
    pub fn is_established(&self) -> bool {
        self.live()
            .any(|session| session.actions().is_established())
    }

    /// Hold the peers the build declares, each by its zid, from the node's first tick (decision
    /// D7, the third transport: no verb asks for them). The first that cannot be held is named
    /// by its place in the list.
    pub fn hold_declared(
        &mut self,
        peers: &[DeclaredPeer],
        now_ms: u64,
    ) -> Result<(), DeclaredRefusal> {
        self.manager.hold_declared(peers, now_ms)
    }

    /// Whether some established session's peer is verified: the zid it claimed is the zid the
    /// key it proved inside a secure channel names (decisions D1 and D9 of
    /// `docs/session-lifecycle-intent.md`). `false` over a link that is no secure channel.
    pub fn peer_verified(&self) -> bool {
        self.live().any(|session| {
            let actions = session.actions();
            actions.is_established() && actions.peer_identity_verified()
        })
    }

    /// Ask every session's drive loop to run its next iteration now, however long its link was
    /// going to sleep. For an application that has just left something for a session's layer
    /// (a query in a [`GetMailbox`](crate::get_mailbox::GetMailbox)): the layer takes it on its
    /// next event, and without this that event waits for the link's idle wait to run out. The
    /// layer states its own deadline again on that event, so this costs one iteration.
    ///
    /// Only with `query-get`, the feature whose layer does state it again: without that, the
    /// deadline this sets would stay and the loop would never sleep.
    #[cfg(feature = "query-get")]
    pub fn wake(&self) {
        for session in self.live() {
            session.actions().set_app_wake_deadline_ms(Some(0));
        }
    }

    /// Whether the node holds a session, established or still opening. A node that holds none has
    /// no socket either, so its loop sleeps rather than spin above the network stack's threads.
    /// (A node that listens holds its port all the while; the sleep is the interval at which it
    /// looks for a connection on it.)
    pub fn holds_session(&self) -> bool {
        self.live().next().is_some()
    }

    /// Advance the node to `now_ms`: let go of the accepted sessions that have ended, take the
    /// connections that wait on the port, keep the dialled sessions in step with the endpoints,
    /// and send the declarations on every established session that has not had them: all of them at
    /// once, or a burst a turn when the node is paced.
    pub fn tick(&mut self, now_ms: u64) {
        self.admit();
        self.manager.tick(now_ms);
        for session in self.live() {
            if session.actions().is_established() && !session.declared() {
                replay_declarations(session, self.declarations, self.pacing, now_ms);
            }
        }
    }

    /// Whether every established session's peer has been told every declaration the node owes it: a
    /// session that is not yet established owes nothing yet, so a node that listens is synced before
    /// any client has come, and is not once one has established and has not been told.
    pub fn declarations_synced(&self) -> bool {
        self.live()
            .filter(|session| session.actions().is_established())
            .all(SlotSession::declared)
    }

    /// One accept pass: free the rows of the sessions that ended, then take what waits on the
    /// port, at most one connection more than the table has rows so that a pass is bounded and
    /// the overflow is seen. A connection that finds the table full is closed here, before any
    /// table is claimed for it; one the acceptor refused or the host had no room for was already
    /// counted by whoever refused it, and its peer sees the same close.
    fn admit(&mut self) {
        self.accepted.retain(|session| !session.is_finished());
        for _ in 0..=A {
            // Nothing waits, or the acceptor could not take what did (it counted that itself):
            // the next tick asks again.
            let Ok(Some(driver)) = self.acceptor.accept() else {
                return;
            };
            if self.accepted.free_slots() == 0 {
                self.over_capacity = self.over_capacity.saturating_add(1);
                continue;
            }
            self.open_accepted(driver);
        }
    }

    // Not inlined into the pass above, for the reason `SlotDialer::dial` is not: the driver and
    // the session's parameters are held by value on the way into the slot, and that frame should
    // exist for the length of one accept, not beneath the loop for the node's whole life.
    #[inline(never)]
    fn open_accepted(&mut self, driver: T::Driver) {
        let entropy = self.factory.borrow_mut().entropy();
        let params = self.factory.borrow_mut().accepted_params();
        let factory = self.factory;
        let Ok(opened) = self.host.open(
            driver,
            None,
            entropy,
            params,
            SessionDriveConfig {
                timeouts: self.timeouts,
                role: SessionRole::Acceptor,
                max_iters: None,
            },
            |handle| events_of(factory, handle),
        ) else {
            // A table had no room: it counted the refusal and the driver went back with it.
            return;
        };
        // `admit` checked for a free row, so the push cannot refuse; a session that found none
        // would be one nothing declares on or reports, so end it rather than hold it.
        if let Err(CapacityFull(refused)) = self.accepted.push(SlotSession::new(opened)) {
            refused.abort();
        }
    }
}

/// How many declarations one turn of the replay sends: the pace's burst, or the whole list when the
/// node is not paced, which is the replay of upstream and of this node before the policy existed.
const fn replay_burst(pacing: Option<ReplayPacing>) -> usize {
    match pacing {
        Some(pace) => pace.burst(),
        None => usize::MAX,
    }
}

/// When the next turn of a replay may send, after a turn at `now_ms`: `None` when nothing is to be
/// waited for (the node is not paced, or the replay has told the peer everything), else the end of
/// the interval. A turn a refused send cut short is not finished, so it waits the interval too: the
/// stage that refused is given the time a pace is meant to give it.
fn next_turn_after(pacing: Option<ReplayPacing>, finished: bool, now_ms: u64) -> Option<u64> {
    match pacing {
        Some(pace) if !finished => Some(now_ms.saturating_add(pace.interval_ms())),
        _ => None,
    }
}

/// Send the declarations `session`'s peer has not been told, from where the session's replay stands:
/// the whole list the first time, and after a send the session's stage refused (it was busy) the
/// entries from the one that failed, never again the ones that went out. A router takes a
/// declaration it sees twice under one id as the first, so a repeat was harmless on the wire and
/// wasted a frame each, and a node with many declarations on a busy stage could repeat them for as
/// long as the stage stayed busy. A paced node sends a burst a turn and leaves the interval between
/// turns, and does nothing at all at a time before the session's next turn.
fn replay_declarations<C: ClockSource + 'static>(
    session: &SlotSession<C>,
    declarations: &[Declaration],
    pacing: Option<ReplayPacing>,
    now_ms: u64,
) {
    if !session.replay_due(now_ms) {
        return;
    }
    let mut cursor = session.replay(declarations.len());
    replay_turn(&mut cursor, replay_burst(pacing), |at| {
        declare(session.actions(), at as u64 + 1, &declarations[at])
    });
    if let Some(at_ms) = next_turn_after(pacing, cursor.finished(), now_ms) {
        session.set_next_turn(at_ms);
    }
    session.set_replay(cursor);
}

/// One turn of a replay: ask `send` for each entry of the turn in order, and on the first it
/// refuses stop and put the cursor back on that entry.
fn replay_turn(cursor: &mut ReplayCursor, burst: usize, mut send: impl FnMut(usize) -> bool) {
    for at in cursor.turn(burst) {
        if !send(at) {
            cursor.refused(at);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Run turns of `burst` until the cursor finishes or `limit` turns pass, `refuse` naming the
    /// sends the stage refuses (each once); every entry offered, in order.
    fn replay(total: usize, burst: usize, mut refuse: Vec<usize>, limit: usize) -> Vec<usize> {
        let mut cursor = ReplayCursor::begin(total);
        let mut offered = Vec::new();
        for _ in 0..limit {
            if cursor.finished() {
                break;
            }
            replay_turn(&mut cursor, burst, |at| {
                offered.push(at);
                match refuse.iter().position(|&r| r == at) {
                    Some(found) => {
                        refuse.remove(found);
                        false
                    }
                    None => true,
                }
            });
        }
        offered
    }

    #[test]
    fn a_replay_with_nothing_refused_offers_each_entry_once_in_order() {
        assert_eq!(
            replay(5, replay_burst(None), Vec::new(), 4),
            [0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn a_refused_send_resumes_at_the_entry_it_failed_on_and_not_at_the_start() {
        // Entry 3 is refused once: 0, 1 and 2 are offered once, 3 twice, and 4 after it.
        assert_eq!(
            replay(5, replay_burst(None), alloc::vec![3], 4),
            [0, 1, 2, 3, 3, 4],
            "the old repeat of the whole list would offer 0, 1 and 2 again"
        );
    }

    #[test]
    fn a_burst_bounds_a_turn_and_the_turns_cover_the_list() {
        let mut cursor = ReplayCursor::begin(5);
        let mut turns = Vec::new();
        while !cursor.finished() {
            let mut turn = Vec::new();
            replay_turn(&mut cursor, 2, |at| {
                turn.push(at);
                true
            });
            turns.push(turn);
        }
        assert_eq!(
            turns,
            [alloc::vec![0, 1], alloc::vec![2, 3], alloc::vec![4]]
        );
    }

    #[test]
    fn a_list_with_no_declaration_is_finished_at_once() {
        assert!(replay(0, replay_burst(None), Vec::new(), 1).is_empty());
        assert!(ReplayCursor::begin(0).finished());
    }

    #[test]
    fn an_unpaced_node_sends_the_whole_list_and_a_paced_one_its_burst() {
        assert_eq!(replay_burst(None), usize::MAX);
        let pace = ReplayPacing::new(3, 10);
        assert_eq!(replay_burst(pace), 3);
    }

    #[test]
    fn a_paced_replay_waits_the_interval_until_it_has_told_the_peer_everything() {
        let pace = ReplayPacing::new(3, 10);
        // Mid-replay, or cut short by a refused send: the next turn is an interval on.
        assert_eq!(next_turn_after(pace, false, 1_000), Some(1_010));
        // Everything told: nothing to wait for, and the session is not asked again.
        assert_eq!(next_turn_after(pace, true, 1_000), None);
        // Not paced: never a wait, whatever the cursor says.
        assert_eq!(next_turn_after(None, false, 1_000), None);
        // A clock at the end of its range does not wrap into the past and release the wait.
        assert_eq!(next_turn_after(pace, false, u64::MAX), Some(u64::MAX));
    }
}

/// Send one declaration under `id`: `true` once it went out.
fn declare<C: ClockSource + 'static>(
    actions: &SessionHandle<C>,
    id: u64,
    declaration: &Declaration,
) -> bool {
    // `complete: false` is upstream's `QueryableInfoType::DEFAULT`.
    match declaration.kind {
        DeclarationKind::Queryable => actions
            .send_declare_queryable(id, 0, Some(declaration.key), false)
            .is_ok(),
        DeclarationKind::Subscriber => actions
            .send_declare_subscriber(id, 0, Some(declaration.key))
            .is_ok(),
        DeclarationKind::Token => actions
            .send_declare_token(id, 0, Some(declaration.key))
            .is_ok(),
    }
}

/// What a queryable answers with: one fixed JSON document, or the latest sample a subscription of
/// the node kept.
#[derive(Clone, Copy)]
pub enum Answer {
    /// A fixed document, answered under the key the query asked.
    Document(&'static str),
    /// The payload of a cell of the node's subscriptions, as it arrived. Nothing is answered while
    /// no sample has reached the cell, so a querier gets the final of an empty reply and not an
    /// invented value.
    Latest(LatestRef),
}

/// A queryable that answers every query with one JSON document, or from a subscription's latest
/// sample, under the key the query asked (`z_query_keyexpr`, as zenoh-pico's comparison image
/// replies): a function and what it answers with, stored inline, so the registry that holds it is
/// typed by it and the registration allocates nothing.
pub type DocumentSink = FnQuerySink<Answer>;

/// The observer's registrations of a client that answers documents and keeps what it subscribes to:
/// queryables of [`DocumentSink`], subscriptions of [`LatestSink`], and none of the other kinds.
pub struct DocumentSinks;

impl ObserverSinks for DocumentSinks {
    type Subscriber = LatestSink;
    type Queryable = DocumentSink;
    type Declared = NoSink;
    type Undeclared = NoSink;
}

fn answer(source: &mut Answer, query: &dyn QueryView, out: &mut dyn ReplyOut) {
    match *source {
        Answer::Document(body) => {
            let _ = out.reply_keyed_encoded_parts(
                query.keyexpr(),
                body.as_bytes(),
                PACKED_APPLICATION_JSON,
                None,
            );
        }
        Answer::Latest(cell) => cell.slots.with(cell.index, &mut |latest| {
            // A delete is not a value to answer with.
            if let Some(latest) = latest.filter(|l| l.kind == SampleKind::Put) {
                let _ = out.reply_keyed(query.keyexpr(), latest.payload);
            }
        }),
    }
}

/// Register on `queryables` a queryable under `key` that answers every query with `body`. `Err`
/// when the registry is full or `key` does not fit, which stops an image rather than starting it
/// declaring what nothing answers.
pub fn register_document(
    queryables: &mut QueryableRegistry<DocumentSink>,
    key: &str,
    body: &'static str,
) -> Result<(), RegisterError> {
    register_answer(queryables, key, Answer::Document(body))
}

/// Register on `queryables` a queryable under `key` that answers with `source`. The refusals are
/// [`register_document`]'s.
pub fn register_answer(
    queryables: &mut QueryableRegistry<DocumentSink>,
    key: &str,
    source: Answer,
) -> Result<(), RegisterError> {
    queryables
        .register_sink(key, Locality::Any, false, FnQuerySink::new(source, answer))
        .map(|_id| ())
}

/// Register on `subscribers` a subscription under `key` that keeps the latest sample in `sink`'s
/// cell. `Err` when the table is full or `key` does not fit, which stops an image rather than
/// starting it declaring what nothing takes.
pub fn register_latest(
    subscribers: &mut SubscriberTable<LatestSink>,
    key: &str,
    sink: LatestSink,
) -> Result<(), RegisterError> {
    subscribers
        .register_sink(key, Locality::Any, sink)
        .map(|_id| ())
}

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
use wz_session_core::link::{BoxedLinkDriver, LinkDropCause};
use wz_session_core::locality::Locality;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::pubsub::SubscriberTable;
use wz_session_core::query::QueryableRegistry;
use wz_session_core::query_sink::{FnQuerySink, QueryView, ReplyOut};
use wz_session_core::registry_error::RegisterError;
use wz_session_core::replay_cursor::ReplayCursor;
use wz_session_core::replay_pacing::{RefusalStep, ReplayPacing};
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::send_declare_error::SendDeclareError;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::slot_observer::{NoSink, ObserverSinks};
use wz_session_core::wire_id::{listed_entity_id, EntityId};

use crate::connect_manager::{
    ConnectManager, DeclaredPeer, DeclaredRefusal, EndpointSource, PeerStore,
};
use crate::latest::{LatestRef, LatestSink};
use crate::slot_dial::{
    end_released_inbound, events_of, report_inbound, Bind, SessionFactory, SlotDialer, SlotSession,
};
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
    F: SessionFactory<C, T::Driver>,
    X: Accept<T::Driver>,
{
    manager: ConnectManager<SlotDialer<'a, C, T, B, F, S, P>>,
    declarations: &'static [Declaration],
    host: &'a SessionHost<C, T, F::Entropy, S, P>,
    factory: &'a RefCell<F>,
    timeouts: SessionTimeouts,
    acceptor: X,
    accepted: BoundedVec<SlotSession<C, T::Driver>, A>,
    over_capacity: u32,
    /// How the declarations of a session go out when a caller stated it for the node
    /// ([`Self::set_replay_pacing`]). `None` leaves it to the `declaration-sync-pacing` policy of
    /// the snapshot of each session that replays (`session_pacing`).
    stated_pacing: Option<Option<ReplayPacing>>,
}

impl<'a, C, T, B, F, X, const S: usize, const P: usize, const A: usize>
    SlotClientNode<'a, C, T, B, F, X, S, P, A>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C, T::Driver>,
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
            stated_pacing: None,
        }
    }

    /// State how the declarations of a session go out, for a caller that wants a pace regardless
    /// of the policy (a test, or a node whose image is built for another policy); each session's
    /// snapshot states it otherwise ([`ReplayPacing::of_policy`]). `Some` sends the burst's worth
    /// of declarations a turn, and waits at least the interval before the next: the wait is the
    /// interval or the node's tick, whichever is longer, because the replay moves on a tick.
    pub fn set_replay_pacing(&mut self, pacing: Option<ReplayPacing>) {
        self.stated_pacing = Some(pacing);
    }

    /// Every session the node holds, accepted and dialled.
    fn live(
        &self,
    ) -> impl Iterator<Item = &SlotSession<C, T::Driver>> + use<'_, 'a, C, T, B, F, X, S, P, A>
    {
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
    /// connections that wait on the port, tell the connect manager which nodes have a session of
    /// their own here, keep the dialled sessions in step with the endpoints, end the sessions
    /// nodes opened that the manager let go of, and send the declarations on every established
    /// session that has not had them: all of them at once, or a burst a turn when the node is
    /// paced.
    pub fn tick(&mut self, now_ms: u64) {
        self.admit();
        // A node that listens on nothing (`A` is 0) holds no session a node opened, so it asks
        // nothing of either and its image carries neither call.
        if A != 0 {
            report_inbound::<_, _, _, _, A>(&mut self.manager, self.accepted.iter(), now_ms);
        }
        self.manager.tick(now_ms);
        if A != 0 {
            end_released_inbound(&mut self.manager, self.accepted.iter());
        }
        for session in self.live() {
            // A session whose task has ended, with its link or because the pace gave its replay
            // up, is told nothing more while it waits to be let go of.
            if session.actions().is_established() && !session.declared() && !session.is_finished() {
                let pacing = session_pacing(self.stated_pacing, &session.actions().params.policy);
                replay_declarations(session, self.declarations, pacing, now_ms);
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
        let factory = self.factory;
        let Ok(opened) = self.host.open(
            driver,
            None,
            entropy,
            || factory.borrow_mut().accepted_params(),
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

/// The pace of one session's replay: the one a caller stated for the node, or else the one the
/// `declaration-sync-pacing` policy of `policy`, the session's own snapshot, states.
fn session_pacing(
    stated: Option<Option<ReplayPacing>>,
    policy: &SessionPolicy,
) -> Option<ReplayPacing> {
    stated.unwrap_or_else(|| ReplayPacing::of_policy(policy))
}

/// How many declarations one turn of the replay sends: the pace's burst, or the whole list when the
/// node is not paced, which is the replay of upstream and of this node before the policy existed.
const fn replay_burst(pacing: Option<ReplayPacing>) -> usize {
    match pacing {
        Some(pace) => pace.burst(),
        None => usize::MAX,
    }
}

/// What a replay does after a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterTurn {
    /// Nothing is waited for: the node is not paced, or the replay has told the peer everything.
    Due,
    /// The next turn sends no sooner than this time, in the node's milliseconds.
    At(u64),
    /// The replay was given up on a send the stage refused: the session ends, and its peer is told
    /// everything again over the next one.
    EndsSession,
}

/// Why the session's stage did not take a declaration of a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// It had no room for it now: the link had no slot to lend the frame (the slot profile builds
    /// no frame on the heap) or the fragment budget was spent. The same send finds room once the
    /// link has written what it holds, so this is the cooperative form of the send upstream's
    /// reopen blocks on (`vendor/zenoh-pico/src/net/session.c` @
    /// `ret = _z_send_n_msg(s, n_msg, Z_RELIABILITY_RELIABLE, Z_CONGESTION_CONTROL_BLOCK, NULL);`).
    Busy,
    /// The link is gone, or the declaration cannot be made at all: no later try on this session
    /// takes it, as upstream's blocking send failing is a transport that failed.
    Failed,
}

impl Refusal {
    /// What `error`, the stage's answer to one declaration, says of the session.
    fn of(error: &SendDeclareError) -> Self {
        match error {
            SendDeclareError::LinkRefused(LinkDropCause::NoTxSlot)
            | SendDeclareError::FragmentTxBudgetExhausted => Self::Busy,
            // A declaration past the link's budget, with no heap to cut it up in, is past it on
            // every try; and a link whose writer is gone takes nothing more.
            _ => Self::Failed,
        }
    }
}

/// What follows a turn at `now_ms` that left the replay `finished` or not, and in which the
/// session's stage `refused` a send or none, `last_progress_ms` being when the replay last told the
/// peer a declaration or began.
///
/// A send refused as [`Refusal::Failed`] gives the replay up with the session, paced or not, as
/// zenoh-pico clears a transport its reopen could not send a declaration over and opens again
/// (`vendor/zenoh-pico/src/net/session.c` @ `_z_transport_clear(&s->_tp);`). A send refused as
/// [`Refusal::Busy`] is asked again: on the next tick by a node that is not paced, and by a paced
/// one as the pace answers a refusal ([`ReplayPacing::after_refusal`]), as the tokio host answers
/// it, after the pace's own retry wait, or, with no retry wait or once no declaration has gone out
/// for the no-progress bound, given up with the session. A paced turn the stage took whole waits
/// the interval.
fn after_turn(
    pacing: Option<ReplayPacing>,
    finished: bool,
    refused: Option<Refusal>,
    last_progress_ms: u64,
    now_ms: u64,
) -> AfterTurn {
    if finished {
        return AfterTurn::Due;
    }
    match (refused, pacing) {
        (Some(Refusal::Failed), _) => AfterTurn::EndsSession,
        (None | Some(Refusal::Busy), None) => AfterTurn::Due,
        (None, Some(pace)) => AfterTurn::At(now_ms.saturating_add(pace.interval_ms())),
        (Some(Refusal::Busy), Some(pace)) => match pace.after_refusal(last_progress_ms, now_ms) {
            RefusalStep::RetryIn(wait_ms) => AfterTurn::At(now_ms.saturating_add(wait_ms)),
            RefusalStep::EndsLink => AfterTurn::EndsSession,
        },
    }
}

/// Send the declarations `session`'s peer has not been told, from where the session's replay stands:
/// the whole list the first time, and after a send the session's stage refused (it was busy) the
/// entries from the one that failed, never again the ones that went out. A router takes a
/// declaration it sees twice under one id as the first, so a repeat was harmless on the wire and
/// wasted a frame each, and a node with many declarations on a busy stage could repeat them for as
/// long as the stage stayed busy. A paced node sends a burst a turn and leaves the interval between
/// turns, and does nothing at all at a time before the session's next turn. A replay given up on
/// a refused send ([`after_turn`]) ends the session with no Close, as zenoh-pico clears the
/// transport: the connect manager dials a dialled one again and the accept pass frees the row of
/// an accepted one, and the next session's peer is told from the start.
fn replay_declarations<C: ClockSource + 'static, D: BoxedLinkDriver + ?Sized + 'static>(
    session: &SlotSession<C, D>,
    declarations: &[Declaration],
    pacing: Option<ReplayPacing>,
    now_ms: u64,
) {
    if !session.replay_due(now_ms) {
        return;
    }
    let mut cursor = session.replay(declarations.len(), now_ms);
    let turn = replay_turn(&mut cursor, replay_burst(pacing), |at| {
        match listed_entity_id(at) {
            Some(id) => declare(session.actions(), id, &declarations[at])
                .map_err(|error| Refusal::of(&error)),
            // A place past the ids a list can name is a declaration no session can make.
            None => Err(Refusal::Failed),
        }
    });
    if turn.told {
        session.note_progress(now_ms);
    }
    let after = after_turn(
        pacing,
        cursor.finished(),
        turn.refused,
        session.last_progress_ms(),
        now_ms,
    );
    match after {
        AfterTurn::Due => {}
        AfterTurn::At(at_ms) => session.set_next_turn(at_ms),
        AfterTurn::EndsSession => {
            session.abort();
            return;
        }
    }
    session.set_replay(cursor);
}

/// What one turn of a replay did: whether the stage took any declaration of it, and why it
/// refused one, if it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Turn {
    told: bool,
    refused: Option<Refusal>,
}

/// One turn of a replay: ask `send` for each entry of the turn in order, and on the first it
/// refuses stop and put the cursor back on that entry.
fn replay_turn(
    cursor: &mut ReplayCursor,
    burst: usize,
    mut send: impl FnMut(usize) -> Result<(), Refusal>,
) -> Turn {
    let mut told = false;
    for at in cursor.turn(burst) {
        if let Err(refusal) = send(at) {
            cursor.refused(at);
            return Turn {
                told,
                refused: Some(refusal),
            };
        }
        told = true;
    }
    Turn {
        told,
        refused: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// A pace of three a turn every 10 ms that answers a refused turn by waiting `retry_ms` and
    /// gives up after `bound_ms` with nothing told: values inside a host build's domains of the
    /// two retry limits.
    fn pace_answering(retry_ms: usize, bound_ms: usize) -> Option<ReplayPacing> {
        ReplayPacing::new(3, 10).map(|pace| {
            pace.with_refusal(retry_ms, bound_ms)
                .expect("a host build's domains hold every retry value")
        })
    }

    /// Run turns of `burst` until the cursor finishes or `limit` turns pass, `refuse` naming the
    /// sends the stage refuses for want of room (each once); every entry offered, in order.
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
                        Err(Refusal::Busy)
                    }
                    None => Ok(()),
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
                Ok(())
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

    /// A session replays at the pace its own snapshot states, and not the build's, unless a caller
    /// stated one for the node: each value of `declaration-sync-pacing` the build's domain holds,
    /// selected and handed in, gives the pace that value states.
    #[test]
    fn a_session_replays_at_the_pace_its_snapshot_states_unless_one_was_stated() {
        use wz_session_core::policy::DeclarationSyncPacing;
        let mut built = 0;
        for on in [false, true] {
            let mut policy = SessionPolicy::defaults();
            if policy
                .select_declaration_sync_pacing(DeclarationSyncPacing::from(on))
                .is_err()
            {
                // The build's domain leaves this value out: no creator can hand it.
                continue;
            }
            assert_eq!(session_pacing(None, &policy).is_some(), on, "{on}");
            assert_eq!(
                session_pacing(None, &policy),
                ReplayPacing::of_policy(&policy)
            );
            let stated = ReplayPacing::new(3, 10);
            assert_eq!(session_pacing(Some(stated), &policy), stated);
            assert_eq!(session_pacing(Some(None), &policy), None);
            built += 1;
        }
        assert!(built >= 1, "the build's domain holds at least its default");
    }

    #[test]
    fn a_paced_replay_waits_the_interval_until_it_has_told_the_peer_everything() {
        let pace = ReplayPacing::new(3, 10);
        // Mid-replay, the stage having taken the whole turn: the next turn is an interval on.
        assert_eq!(
            after_turn(pace, false, None, 1_000, 1_000),
            AfterTurn::At(1_010)
        );
        // Everything told: nothing to wait for, and the session is not asked again.
        assert_eq!(after_turn(pace, true, None, 1_000, 1_000), AfterTurn::Due);
        // A clock at the end of its range does not wrap into the past and release the wait.
        assert_eq!(
            after_turn(pace, false, None, u64::MAX, u64::MAX),
            AfterTurn::At(u64::MAX)
        );
    }

    /// A node that is not paced asks a stage that had no room again on its next tick, without a
    /// wait, as upstream's reopen waits on its blocking send; a send that failed for any other
    /// reason gives the replay up with the session, as upstream clears the transport and opens
    /// again, and is not asked again on this session.
    #[test]
    fn an_unpaced_node_asks_a_busy_stage_again_and_ends_the_session_on_a_failed_send() {
        assert_eq!(after_turn(None, false, None, 1_000, 1_000), AfterTurn::Due);
        assert_eq!(
            after_turn(None, false, Some(Refusal::Busy), 0, 1_000),
            AfterTurn::Due
        );
        assert_eq!(
            after_turn(None, false, Some(Refusal::Failed), 0, 1_000),
            AfterTurn::EndsSession
        );
        // Everything told: a refusal of a later live send is not the replay's to answer.
        assert_eq!(
            after_turn(None, true, Some(Refusal::Failed), 0, 1_000),
            AfterTurn::Due
        );
    }

    /// A paced node ends the session on a failed send at once too, whatever its pace: the pace
    /// answers only a stage that had no room.
    #[test]
    fn a_paced_node_ends_the_session_on_a_failed_send_whatever_its_pace() {
        let patient = pace_answering(4, 0);
        assert_eq!(
            after_turn(patient, false, Some(Refusal::Failed), 1_000, 1_000),
            AfterTurn::EndsSession
        );
        assert_eq!(
            after_turn(patient, false, Some(Refusal::Busy), 1_000, 1_000),
            AfterTurn::At(1_004)
        );
    }

    /// The stage's answers are told apart by what they say of the session: no slot to lend and a
    /// spent fragment budget pass, everything else is a send no later try on it makes.
    #[test]
    fn a_stage_without_room_is_busy_and_any_other_refusal_failed() {
        assert_eq!(
            Refusal::of(&SendDeclareError::LinkRefused(LinkDropCause::NoTxSlot)),
            Refusal::Busy
        );
        assert_eq!(
            Refusal::of(&SendDeclareError::LinkRefused(LinkDropCause::Oversize)),
            Refusal::Failed
        );
        assert_eq!(
            Refusal::of(&SendDeclareError::FragmentTxBudgetExhausted),
            Refusal::Busy
        );
        assert_eq!(
            Refusal::of(&SendDeclareError::TransportUnavailable),
            Refusal::Failed
        );
        assert_eq!(
            Refusal::of(&SendDeclareError::MissingKeyexpr),
            Refusal::Failed
        );
    }

    /// With no retry wait, the retry limit's default, a turn the stage refused for want of room
    /// gives the replay up and ends the session, as the tokio host's does: it is not tried again
    /// at the turn interval.
    #[test]
    fn a_refused_turn_ends_the_session_when_the_pace_retries_nothing() {
        let pace = pace_answering(0, 0);
        assert_eq!(
            after_turn(pace, false, Some(Refusal::Busy), 1_000, 1_000),
            AfterTurn::EndsSession
        );
    }

    /// With a retry wait, a refused turn is tried again after that wait and not the interval,
    /// until no declaration has gone out for the no-progress bound; a bound of 0 never gives up.
    #[test]
    fn a_refused_turn_is_retried_at_the_retry_wait_until_no_progress_ends_the_session() {
        let pace = pace_answering(4, 50);
        let busy = Some(Refusal::Busy);
        assert_eq!(
            after_turn(pace, false, busy, 1_000, 1_020),
            AfterTurn::At(1_024),
            "the retry wait (4 ms), not the turn interval (10 ms)"
        );
        assert_eq!(
            after_turn(pace, false, busy, 1_000, 1_049),
            AfterTurn::At(1_053)
        );
        assert_eq!(
            after_turn(pace, false, busy, 1_000, 1_050),
            AfterTurn::EndsSession,
            "50 ms with nothing told"
        );
        let patient = pace_answering(4, 0);
        assert_eq!(
            after_turn(patient, false, busy, 0, u64::MAX),
            AfterTurn::At(u64::MAX)
        );
    }

    /// A turn reports whether the stage took any declaration and why it refused one, which is
    /// what starts the no-progress stretch again and what decides the refusal's answer.
    #[test]
    fn a_turn_reports_what_the_stage_took_and_refused() {
        let mut cursor = ReplayCursor::begin(5);
        assert_eq!(
            replay_turn(&mut cursor, 3, |at| if at == 1 {
                Err(Refusal::Busy)
            } else {
                Ok(())
            }),
            Turn {
                told: true,
                refused: Some(Refusal::Busy)
            }
        );
        assert_eq!(
            cursor.next(),
            1,
            "the next turn starts at the refused entry"
        );
        assert_eq!(
            replay_turn(&mut cursor, 3, |_| Err(Refusal::Failed)),
            Turn {
                told: false,
                refused: Some(Refusal::Failed)
            }
        );
        assert_eq!(
            replay_turn(&mut cursor, 3, |_| Ok(())),
            Turn {
                told: true,
                refused: None
            }
        );
    }
}

/// Send one declaration under `id`: `Ok` once it went out, and why the stage refused it otherwise.
fn declare<C: ClockSource + 'static, D: BoxedLinkDriver + ?Sized + 'static>(
    actions: &SessionHandle<C, D>,
    id: EntityId,
    declaration: &Declaration,
) -> Result<(), SendDeclareError> {
    // `complete: false` is upstream's `QueryableInfoType::DEFAULT`.
    match declaration.kind {
        DeclarationKind::Queryable => {
            actions.send_declare_queryable(id, 0, Some(declaration.key), false)
        }
        DeclarationKind::Subscriber => {
            actions.send_declare_subscriber(id, 0, Some(declaration.key))
        }
        DeclarationKind::Token => actions.send_declare_token(id, 0, Some(declaration.key)),
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
    /// The node's lifecycle verbs (`client-verbs`): the capability document and the verb a key of
    /// this node names, for the commander the link's key proved (decision D12).
    #[cfg(feature = "client-verbs")]
    Verbs(&'static crate::admin_fixed::VerbLegs),
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
        #[cfg(feature = "client-verbs")]
        Answer::Verbs(legs) => legs.answer(query, out),
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

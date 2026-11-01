// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node of the `session-slot` profile, written ONCE for every network stack: the node a
//! host reaches, and reconfigures at runtime, with every session, table and text it holds in
//! storage the image declared.
//!
//! The node was lwIP's (`wz_session_lwip::slot_node::SlotAdminNode`), and what is lwIP's in it is
//! two things: the sockets its dials open, and the listener whose lanes take a datagram session's
//! `InitSyn`. Everything else decides the same on any stack, and is [`AdminCore`]: the connect
//! manager over the endpoints the control names, the admin space declared on every established
//! session, and the sessions and endpoints reported. [`AcceptingAdminNode`] is the node whose
//! stack hands it the links of the sessions a peer opened ([`Accept`]), which is how a stream
//! stack takes them (a `tcp/` listener, or a secure channel's, `IpStack::tls_acceptor`); lwIP's
//! node is the same core around the datagram listener.
//!
//! # What the node holds, and where
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions it dials | `SessionSlots` / `PumpSlots` / the task table of the host | the pool's `max_sessions`, `process.max_tasks` |
//! | endpoints it manages | the connect manager's rows | `caps::MAX_STATIC_CONNECT` (`process.connect_endpoints`) |
//! | sessions it accepted | `accepted`, a fixed table | the node's `ACCEPTS` (`accept.max_sessions`) |
//! | the keys it declares | two fixed texts | `caps::MAX_KEYEXPR_BYTES` |
//! | the sessions and endpoints it reports | `FixedNodeStatus` | `max_sessions` rows, `MAX_STATIC_CONNECT` rows |
//!
//! A session the host cannot open is a counted refusal in the table that said no, and an endpoint
//! whose dial is refused waits its retry period as a dial nobody answered. Nothing is grown and
//! nothing falls back to the heap; this module does not link `alloc`.

use core::cell::RefCell;

use wz_runtime_coop::session_drive::{Accept, SessionDriveConfig, SessionRole, SlotStack};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::ClockSource;
use wz_session_core::adminspace::{write_admin_queryable_key, AdminSessionRef};
use wz_session_core::bounded::{BoundedVec, CapacityFull};
use wz_session_core::caps::{self, MAX_STATIC_CONNECT};
use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::locator_directory::{DirectoryRefusal, DirectoryZid, Lifetime, LocatorSource};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::text_out::FixedText;

use crate::admin_fixed::{FixedAdminSession, FixedNodeStatus, RowRefused};
use crate::admin_host::ConnectControl;
use crate::admin_status::DialStatus;
use crate::connect_manager::{
    ConnectManager, NodeOpener, NodeRefusal, NodeState, PeerStore, SlotState,
};
use crate::slot_dial::{events_of, Bind, SessionFactory, SlotDialer, SlotSession};
use crate::slot_host::SessionHost;

/// The declaration ids the node uses on each session; ids are per session.
const ADMIN_QUERYABLE_ID: u64 = 1;
const CONFIG_SUBSCRIBER_ID: u64 = 2;

/// An admin key (`@/<zid>/<whatami>/**` or `.../config/**`) in fixed text.
type KeyText = FixedText<{ caps::MAX_KEYEXPR_BYTES }>;

/// Which input a node's construction refused: the admin keys its identity names did not fit,
/// which is found at startup, where it can be fixed, and not at the first declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRefused {
    /// A key built from the node's zid and role is wider than `caps::MAX_KEYEXPR_BYTES`.
    KeyTooLong,
}

/// What of an admin node decides the same on every stack: the connect manager over the endpoints
/// the control names, the admin space declared on each established session, and the report of
/// the sessions and endpoints the node holds. The sessions a peer opened are the shell's: a
/// stack takes them its own way, and hands them to the core by iterator at each tick.
pub struct AdminCore<'a, C, T, B, F, const S: usize, const P: usize>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C, T::Driver>,
{
    status: &'static FixedNodeStatus<S>,
    manager: ConnectManager<SlotDialer<'a, C, T, B, F, S, P>>,
    admin_key: KeyText,
    config_key: KeyText,
}

impl<'a, C, T, B, F, const S: usize, const P: usize> AdminCore<'a, C, T, B, F, S, P>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C, T::Driver>,
{
    /// A core that dials what `control` names through `host` (sockets from `bind`, sessions made
    /// by `factory`), answers as `zid_hex` / `whatami` and reports through `status`. `peers` is
    /// the table of the machines of what it dials (some 10 KB), declared with the image's other
    /// tables and not carried by the node, which a loop holds on its stack.
    ///
    /// `Err` when a key built from `zid_hex` and `whatami` does not fit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: &'a SessionHost<C, T, F::Entropy, S, P>,
        bind: B,
        factory: &'a RefCell<F>,
        timeouts: SessionTimeouts,
        control: &'static ConnectControl,
        peers: &'static PeerStore,
        status: &'static FixedNodeStatus<S>,
        zid_hex: &str,
        whatami: &'static str,
    ) -> Result<Self, NodeRefused> {
        let mut admin_key = KeyText::new();
        write_admin_queryable_key(&mut admin_key, zid_hex, whatami);
        let mut config_key = KeyText::new();
        let _ = wz_session_core::admin_config_space::write_config_space_pattern(
            &mut config_key,
            zid_hex,
            whatami,
        );
        if admin_key.overflowed() || config_key.overflowed() {
            return Err(NodeRefused::KeyTooLong);
        }
        Ok(Self {
            status,
            manager: ConnectManager::in_static_store(
                control,
                SlotDialer::new(host, bind, factory, timeouts),
                peers,
            ),
            admin_key,
            config_key,
        })
    }

    /// Call `f` for each session this node dialled and holds, with the endpoint it was dialled
    /// for, in the list's order.
    pub fn for_each_dialled(&self, mut f: impl FnMut(&str, &SlotSession<C, T::Driver>)) {
        for (endpoint, session) in self.manager.sessions() {
            f(endpoint, session);
        }
    }

    /// Call `f` for each session this node holds with a node it was asked to open by its zid,
    /// with the zid it was dialled for, in the order the nodes were asked for.
    pub fn for_each_dialled_node(
        &self,
        mut f: impl FnMut(&DirectoryZid, &SlotSession<C, T::Driver>),
    ) {
        for (zid, session) in self.manager.node_sessions() {
            f(zid, session);
        }
    }

    /// Where every node asked for by its zid stands, in the order they were asked for.
    pub fn for_each_node(&self, mut f: impl FnMut(&DirectoryZid, NodeState)) {
        for (zid, state) in self.manager.node_states() {
            f(zid, state);
        }
    }

    /// State that the node `zid` may be reached at `locator`: a hint the build declares for a
    /// node it may be asked to open by its zid (the open is a lifecycle query, or
    /// [`Self::open_node`]), kept until the node is given another table. A hint is where the zid
    /// may be, and not a claim that it is: every dial of it is made for the zid, and a session
    /// another node answers closes at the handshake.
    pub fn declare_node(
        &mut self,
        zid: DirectoryZid,
        locator: &str,
        now_ms: u64,
    ) -> Result<(), DirectoryRefusal> {
        self.manager.confirm_locator(
            zid,
            locator,
            LocatorSource::Declared,
            now_ms,
            Lifetime::Permanent,
        )
    }

    /// Hold a session with the node `zid` at what is known of it, as the lifecycle open query
    /// would ask. `Err` says by name why the node cannot be held.
    pub fn open_node(&mut self, zid: DirectoryZid, now_ms: u64) -> Result<(), NodeRefusal> {
        self.manager.open_node(zid, now_ms)
    }

    /// The opener a node's admin queryable answers `session/open/<peer>` with, which holds the
    /// store and not the node, so it can be declared in a `static` beside the other tables.
    pub fn node_opener(&self) -> Option<NodeOpener> {
        self.manager.node_opener()
    }

    /// Where every written endpoint stands, as the connect manager holds it.
    pub fn for_each_endpoint(&self, mut f: impl FnMut(&str, SlotState)) {
        for (endpoint, state) in self.manager.states() {
            f(endpoint, state);
        }
    }

    /// Advance the core to `now_ms`, given the sessions peers opened to the node (`accepted`, a
    /// cheap iterator the shell can run more than once): tell the connect manager which nodes
    /// have a session of their own here, keep the dialled sessions in step with the control,
    /// declare the admin space on every established session that has not had it, and report what
    /// the node holds.
    pub fn tick<'s, I>(&mut self, now_ms: u64, accepted: I)
    where
        I: Iterator<Item = &'s SlotSession<C, T::Driver>> + Clone,
        C: 's,
        T::Driver: 's,
    {
        self.report_inbound(accepted.clone(), now_ms);
        self.manager.tick(now_ms);
        self.declare_on_new_sessions(accepted.clone());
        self.report(accepted, now_ms);
    }

    /// Tell the connect manager which nodes have a session of their own here whose key proved
    /// their zid (decision D10), so a node waited for under a passive intent holds it. A session
    /// whose peer only claims a zid is not that peer's, and is left out.
    fn report_inbound<'s>(
        &mut self,
        accepted: impl Iterator<Item = &'s SlotSession<C, T::Driver>>,
        now_ms: u64,
    ) where
        C: 's,
        T::Driver: 's,
    {
        // A session a peer opened holds a slot of the host, so there are no more than `S`.
        let mut verified: [DirectoryZid; S] = [[0; CREDENTIAL_ZID_BYTES]; S];
        let mut count = 0;
        for session in accepted {
            let actions = session.actions();
            if !actions.peer_identity_verified() {
                continue;
            }
            if let Some(zid) = actions.peer_zid_array() {
                if count < S {
                    verified[count] = zid;
                    count += 1;
                }
            }
        }
        self.manager.inbound_sessions(&verified[..count], now_ms);
    }

    /// Send the admin declarations on every established session that has not had them.
    fn declare_on_new_sessions<'s>(
        &self,
        accepted: impl Iterator<Item = &'s SlotSession<C, T::Driver>>,
    ) where
        C: 's,
        T::Driver: 's,
    {
        let admin_key = self.admin_key.prefix();
        let config_key = self.config_key.prefix();
        let declare = |session: &SlotSession<C, T::Driver>| {
            if session.actions().is_established()
                && !session.declared()
                && declare_admin(session.actions(), admin_key, config_key)
            {
                session.mark_declared();
            }
        };
        accepted.for_each(declare);
        self.manager
            .sessions()
            .for_each(|(_, session)| declare(session));
        self.manager
            .node_sessions()
            .for_each(|(_, session)| declare(session));
    }

    /// Report every established session, accepted and dialled, and every written endpoint with
    /// where it stands, as the heap node does.
    fn report<'s>(&self, accepted: impl Iterator<Item = &'s SlotSession<C, T::Driver>>, now_ms: u64)
    where
        C: 's,
        T::Driver: 's,
    {
        let mut rows: BoundedVec<Result<FixedAdminSession, RowRefused>, S> = BoundedVec::new();
        let mut row_of = |session: &SlotSession<C, T::Driver>| {
            if let Some(row) = session
                .actions()
                .with_admin_session(|view: AdminSessionRef<'_>| FixedAdminSession::from_view(&view))
            {
                // More established sessions than the pool has slots cannot be; one that did not
                // fit would be a row the status could not take either.
                let _ = rows.push(row);
            }
        };
        accepted.for_each(&mut row_of);
        self.manager
            .sessions()
            .for_each(|(_, session)| row_of(session));
        self.manager
            .node_sessions()
            .for_each(|(_, session)| row_of(session));
        self.status.set_session_rows(rows);
        let mut live = self.manager.sessions();
        let mut endpoints: BoundedVec<(&str, DialStatus), MAX_STATIC_CONNECT> = BoundedVec::new();
        for (endpoint, state) in self.manager.states() {
            let status = match state {
                SlotState::Live => DialStatus::Live {
                    established: live
                        .next()
                        .is_some_and(|(_, session)| session.actions().is_established()),
                },
                SlotState::Waiting { at_ms } => DialStatus::Waiting {
                    retry_in_ms: at_ms.saturating_sub(now_ms),
                },
                SlotState::Refused(why) => DialStatus::Refused {
                    reason: why.as_str(),
                },
            };
            let _ = endpoints.push((endpoint, status));
        }
        self.status.set_endpoints(endpoints);
    }
}

/// Declare upstream's two admin-space interests on `actions`: `true` once both went out. A router
/// forwards a GET or a PUT only to a face that declared a match, so without these a stock zenohd
/// connected to the node holds a live session and routes nothing to it.
fn declare_admin<C: ClockSource + 'static, D: BoxedLinkDriver + ?Sized + 'static>(
    actions: &SessionHandle<C, D>,
    admin_key: &str,
    config_key: &str,
) -> bool {
    // `complete: false` is upstream's `QueryableInfoType::DEFAULT`.
    actions
        .send_declare_queryable(ADMIN_QUERYABLE_ID, 0, Some(admin_key), false)
        .is_ok()
        && actions
            .send_declare_subscriber(CONFIG_SUBSCRIBER_ID, 0, Some(config_key))
            .is_ok()
}

/// An admin node whose stack hands it the links of the sessions a peer opened ([`Accept`]): a
/// stream stack's listener, or a secure channel's. It holds up to `A` of them at once, beside the
/// sessions it dials.
pub struct AcceptingAdminNode<'a, C, T, B, F, X, const S: usize, const P: usize, const A: usize>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C, T::Driver>,
    X: Accept<T::Driver>,
{
    core: AdminCore<'a, C, T, B, F, S, P>,
    host: &'a SessionHost<C, T, F::Entropy, S, P>,
    factory: &'a RefCell<F>,
    timeouts: SessionTimeouts,
    acceptor: X,
    accepted: BoundedVec<SlotSession<C, T::Driver>, A>,
    over_capacity: u32,
}

impl<'a, C, T, B, F, X, const S: usize, const P: usize, const A: usize>
    AcceptingAdminNode<'a, C, T, B, F, X, S, P, A>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C, T::Driver>,
    X: Accept<T::Driver>,
{
    /// A node that takes the connections `acceptor` yields, dials what `control` names, answers
    /// as `zid_hex` / `whatami` and reports through `status`. The observer the sessions dispatch
    /// to is the factory's business (its `events`), and the config subscriber and admin queryable
    /// are registered on it by the image beforehand (`host_connect_writes_fixed`,
    /// `host_admin_queryable_fixed_with_open`): a node whose registrations were refused is not
    /// started by the image, rather than started deaf.
    ///
    /// `Err` when a key built from `zid_hex` and `whatami` does not fit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: &'a SessionHost<C, T, F::Entropy, S, P>,
        bind: B,
        acceptor: X,
        factory: &'a RefCell<F>,
        control: &'static ConnectControl,
        peers: &'static PeerStore,
        status: &'static FixedNodeStatus<S>,
        zid_hex: &str,
        whatami: &'static str,
        timeouts: SessionTimeouts,
    ) -> Result<Self, NodeRefused> {
        Ok(Self {
            core: AdminCore::new(
                host, bind, factory, timeouts, control, peers, status, zid_hex, whatami,
            )?,
            host,
            factory,
            timeouts,
            acceptor,
            accepted: BoundedVec::new(),
            over_capacity: 0,
        })
    }

    /// The core the node shares with every stack: the dialled sessions, the nodes held by zid,
    /// and where every written endpoint stands.
    pub fn core(&self) -> &AdminCore<'a, C, T, B, F, S, P> {
        &self.core
    }

    /// The core, mutably: for the node a build declares and for the open by zid.
    pub fn core_mut(&mut self) -> &mut AdminCore<'a, C, T, B, F, S, P> {
        &mut self.core
    }

    /// The sessions a peer opened to this node, while there are any.
    pub fn accepted(&self) -> impl Iterator<Item = &SlotSession<C, T::Driver>> {
        self.accepted.iter()
    }

    /// How many connections the node took off its port and closed at once because its table of
    /// accepted sessions was full: a peer that finds the connection closed knows the node is at
    /// its limit, as one refused at a full table of a router would.
    pub const fn refused_over_capacity(&self) -> u32 {
        self.over_capacity
    }

    /// Advance the node to `now_ms`: let go of the accepted sessions that have ended, take the
    /// connections that wait on the port, and run the core.
    pub fn tick(&mut self, now_ms: u64) {
        self.admit();
        self.core.tick(now_ms, self.accepted.iter());
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

    // Not inlined into the pass above: the driver and the session's parameters are held by value
    // on the way into the slot, and that frame should exist for the length of one accept, not
    // beneath the loop for the node's whole life.
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

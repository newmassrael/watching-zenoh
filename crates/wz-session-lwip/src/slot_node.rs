// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node of the `session-slot` profile (fixed-memory step S9c): the node a
//! host reaches, and reconfigures at runtime, with every session, table and text it
//! holds in storage the image declared.
//!
//! The growable profile's node is `wz_session_mcu::admin_node::AdminNode`, generic
//! over a network stack through `SessionLinks` and built from `Rc` handles, `String`
//! keys and a `Vec` of declared sessions. The node of the slot profile is written over
//! the session host ([`SessionHost`]), which opens a session out of the tables the image
//! declared. The host and the dialler are written once for every stack
//! (`wz_session_mcu::slot_host`, `wz_session_mcu::slot_dial`); what is lwIP's is this
//! node's listener and the socket pool it binds from, which is why the node that listens
//! is here. What is shared is everything that decides: the connect manager
//! (`wz_session_mcu::connect_manager`), the admin queryable and its fixed rows
//! (`wz_session_mcu::admin_fixed`), the config write host
//! (`wz_session_mcu::admin_host`) and the application layer (`wz_session_mcu::app_layer`).
//!
//! # What the node holds, and where
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions it dials | `SessionSlots` / `PumpSlots` / the task table of the host | the pool's `max_sessions`, `process.max_tasks` |
//! | endpoints it manages | the connect manager's rows | `caps::MAX_STATIC_CONNECT` (`process.connect_endpoints`) |
//! | sessions it accepted | `accepted`, a fixed table | the listener's `LANES` (`accept.max_sessions`) |
//! | the keys it declares | two fixed texts | `caps::MAX_KEYEXPR_BYTES` |
//! | the sessions and endpoints it reports | `FixedNodeStatus` | `max_sessions` rows, `MAX_STATIC_CONNECT` rows |
//!
//! A session the host cannot open is a counted refusal in the table that said no, and
//! an endpoint whose dial is refused waits its retry period as a dial nobody answered.
//! Nothing is grown and nothing falls back to the heap; this crate does not link
//! `alloc` on the profile at all.
//!
//! # What it does not do
//!
//! It keeps no list of the sessions a peer opened that it did not admit: the listener
//! counts those (`ListenerCounts`). And it reports the endpoints and sessions it holds
//! as the heap node does, one row each, with the same words.

use core::cell::RefCell;

use wz_runtime_coop::session_drive::{
    LinkOpenError, LinkProto, Locator, SessionDriveConfig, SessionRole,
};
use wz_runtime_coop::ClockSource;
use wz_session_core::bounded::{BoundedVec, CapacityFull};
use wz_session_core::locator_directory::{DirectoryRefusal, DirectoryZid};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_mcu::admin_fixed::FixedNodeStatus;
use wz_session_mcu::connect_manager::{NodeOpener, NodeRefusal, NodeState, PeerStore, SlotState};
use wz_session_mcu::slot_admin::AdminCore;
use wz_session_mcu::slot_dial::{events_of, Bind};

use wz_link_lwip::LwipLink;

use core::ops::Deref;

use crate::driver::LwipUdpDriver;
use crate::links::LwipLinks;
use crate::listener::{Admission, SessionListener};
use crate::session_host::{LwipStack, OpenRefused, SessionHost};

pub use wz_session_mcu::slot_admin::NodeRefused;
pub use wz_session_mcu::slot_dial::{SessionFactory, SlotSession};

/// How a dial opens its socket on lwIP: out of the pool the image declared, on a port the stack
/// picks.
pub struct LwipBinder<'a, L>
where
    L: Deref<Target = LwipLink> + Clone + 'static,
{
    links: &'a LwipLinks<L>,
}

impl<L> Bind<LwipUdpDriver> for LwipBinder<'_, L>
where
    L: Deref<Target = LwipLink> + Clone + 'static,
{
    fn bind(&mut self, to: Locator) -> Result<LwipUdpDriver, LinkOpenError> {
        // lwIP's links here are UDP sockets; a `tcp/` or `tls/` endpoint is not this stack's to
        // dial.
        match to.proto {
            LinkProto::Udp => self.links.bind_driver(0, to.at),
            LinkProto::Tcp | LinkProto::Tls => Err(LinkOpenError::Unsupported),
        }
    }
}

/// The [`Dialer`](wz_session_mcu::connect_manager::Dialer) of the slot profile over lwIP: the
/// stack-neutral one, given lwIP's host and its socket pool.
pub type SlotDialer<'a, C, L, F, const S: usize, const P: usize> =
    wz_session_mcu::slot_dial::SlotDialer<'a, C, LwipStack<L>, LwipBinder<'a, L>, F, S, P>;

/// An MCU node a host can reach, and reconfigure, at runtime, on the slot profile.
///
/// Built from the pieces the image declared; ticked from the firmware's loop with
/// the time. See the module documentation for what it holds and where.
pub struct SlotAdminNode<'a, C, L, F, const S: usize, const P: usize, const LANES: usize>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    F: SessionFactory<C, LwipUdpDriver>,
{
    host: &'a SessionHost<C, L, F::Entropy, S, P>,
    links: &'a LwipLinks<L>,
    factory: &'a RefCell<F>,
    listener: &'static SessionListener<LANES>,
    listen_port: u16,
    listening: bool,
    timeouts: SessionTimeouts,
    /// What decides the same on every stack: the connect manager, the admin space declared on
    /// each session and the report (`wz_session_mcu::slot_admin`).
    core: AdminCore<'a, C, LwipStack<L>, LwipBinder<'a, L>, F, S, P>,
    accepted: BoundedVec<SlotSession<C, LwipUdpDriver>, LANES>,
}

impl<'a, C, L, F, const S: usize, const P: usize, const LANES: usize>
    SlotAdminNode<'a, C, L, F, S, P, LANES>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    F: SessionFactory<C, LwipUdpDriver>,
{
    /// A node that listens on `listen_port` through `listener`, dials what `control`
    /// names, answers as `zid_hex` / `whatami` and reports through `status`. `peers` is the
    /// table of the machines of what it dials (some 10 KB), declared with the image's other
    /// tables and not carried by the node, which a loop holds on its stack.
    ///
    /// The observer the sessions dispatch to is the factory's business (its
    /// `on_event`), and the config subscriber and admin queryable are registered on it
    /// by the image beforehand (`host_connect_writes_fixed`,
    /// `host_admin_queryable_fixed`): a node whose registrations were refused is not
    /// started by the image, rather than started deaf.
    ///
    /// `Err` when a key built from `zid_hex` and `whatami` does not fit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: &'a SessionHost<C, L, F::Entropy, S, P>,
        links: &'a LwipLinks<L>,
        factory: &'a RefCell<F>,
        listener: &'static SessionListener<LANES>,
        control: &'static wz_session_mcu::admin_host::ConnectControl,
        peers: &'static PeerStore,
        status: &'static FixedNodeStatus<S>,
        zid_hex: &str,
        whatami: &'static str,
        listen_port: u16,
        timeouts: SessionTimeouts,
    ) -> Result<Self, NodeRefused> {
        Ok(Self {
            host,
            links,
            factory,
            listener,
            listen_port,
            listening: false,
            timeouts,
            core: AdminCore::new(
                host,
                LwipBinder { links },
                factory,
                timeouts,
                control,
                peers,
                status,
                zid_hex,
                whatami,
            )?,
            accepted: BoundedVec::new(),
        })
    }

    /// The sessions a host reached this node on, while there are any.
    pub fn accepted(&self) -> impl Iterator<Item = &SlotSession<C, LwipUdpDriver>> {
        self.accepted.iter()
    }

    /// Call `f` for each session this node dialled and holds, with the endpoint it was
    /// dialled for, in the list's order.
    pub fn for_each_dialled(&self, f: impl FnMut(&str, &SlotSession<C, LwipUdpDriver>)) {
        self.core.for_each_dialled(f);
    }

    /// Call `f` for each session this node holds with a node it was asked to open by its zid,
    /// with the zid it was dialled for, in the order the nodes were asked for.
    pub fn for_each_dialled_node(
        &self,
        f: impl FnMut(&DirectoryZid, &SlotSession<C, LwipUdpDriver>),
    ) {
        self.core.for_each_dialled_node(f);
    }

    /// Where every node asked for by its zid stands, in the order they were asked for.
    pub fn for_each_node(&self, f: impl FnMut(&DirectoryZid, NodeState)) {
        self.core.for_each_node(f);
    }

    /// State that the node `zid` may be reached at `locator`: a hint the build declares for a
    /// node it may be asked to open by its zid (the open is a lifecycle query, or
    /// [`Self::open_node`]), kept until the node is given another table. A hint is where the
    /// zid may be, and not a claim that it is: every dial of it is made for the zid, and a
    /// session another node answers closes at the handshake.
    pub fn declare_node(
        &mut self,
        zid: DirectoryZid,
        locator: &str,
        now_ms: u64,
    ) -> Result<(), DirectoryRefusal> {
        self.core.declare_node(zid, locator, now_ms)
    }

    /// Hold a session with the node `zid` at what is known of it, as the lifecycle open query
    /// would ask. `Err` says by name why the node cannot be held.
    pub fn open_node(&mut self, zid: DirectoryZid, now_ms: u64) -> Result<(), NodeRefusal> {
        self.core.open_node(zid, now_ms)
    }

    /// The opener a node's admin queryable answers `session/open/<peer>` with, which holds the
    /// store and not the node, so it can be declared in a `static` beside the other tables.
    pub fn node_opener(&self) -> Option<NodeOpener> {
        self.core.node_opener()
    }

    /// Where every written endpoint stands, as the connect manager holds it.
    pub fn for_each_endpoint(&self, f: impl FnMut(&str, SlotState)) {
        self.core.for_each_endpoint(f);
    }

    /// Advance the node to `now_ms`: bind the listening port if it is not bound, let
    /// go of the accepted sessions that have ended, admit the ones that have asked,
    /// keep the dialled sessions in step with the control, declare the admin space on
    /// every established session that has not had it, and report what the node holds
    /// (the last four are the core's, `AdminCore::tick`).
    pub fn tick(&mut self, now_ms: u64) {
        self.ensure_listening();
        self.accepted.retain(|session| !session.is_finished());
        self.admit();
        self.core.tick(now_ms, self.accepted.iter());
    }

    /// Bind the node's port and hand the socket to the listener, once. A bind that
    /// fails (the pool is empty, lwIP refuses the port) is retried on the next tick.
    fn ensure_listening(&mut self) {
        if self.listening {
            return;
        }
        if let Ok(socket) = self.links.bind_socket(self.listen_port) {
            // A listener that already has a socket hands the new one back, which
            // drops it, returning its cell to the pool.
            self.listening = self.listener.listen(socket).is_ok();
        }
    }

    /// One accept pass: every `InitSyn` from a peer with no session is offered to the
    /// host, which claims a slot, a pump cell and a task cell before the session can
    /// answer, or refuses by name and counts it.
    fn admit(&mut self) {
        let host = self.host;
        let factory = self.factory;
        let timeouts = self.timeouts;
        let accepted = &mut self.accepted;
        self.listener.accept_pass(
            self.links.link(),
            &mut |admission: Admission| -> Result<(), OpenRefused> {
                let entropy = factory.borrow_mut().entropy();
                let opened = host.admit(
                    admission,
                    entropy,
                    || factory.borrow_mut().params(),
                    SessionDriveConfig {
                        timeouts,
                        role: SessionRole::Acceptor,
                        max_iters: None,
                    },
                    |handle| events_of(factory, handle),
                )?;
                // The listener holds as many lanes as this table has rows, and a lane
                // is held for as long as its session is, so a row is always free. A
                // session that found none could only be a defect: end it rather than
                // hold one nothing reports or declares on.
                if let Err(CapacityFull(refused)) = accepted.push(SlotSession::new(opened)) {
                    refused.abort();
                }
                Ok(())
            },
        );
    }
}

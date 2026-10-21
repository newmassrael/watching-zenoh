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

use wz_runtime_coop::session_drive::{LinkOpenError, SessionDriveConfig, SessionRole, UdpPeer};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::ClockSource;
use wz_session_core::adminspace::{write_admin_queryable_key, AdminSessionRef};
use wz_session_core::bounded::{BoundedVec, CapacityFull};
use wz_session_core::caps::{self, MAX_STATIC_CONNECT};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::text_out::FixedText;
use wz_session_mcu::admin_fixed::{FixedAdminSession, FixedNodeStatus, RowRefused};
use wz_session_mcu::admin_status::DialStatus;
use wz_session_mcu::connect_manager::{ConnectManager, SlotState};
use wz_session_mcu::slot_dial::{events_of, Bind};

use wz_link_lwip::LwipLink;

use core::ops::Deref;

use crate::driver::LwipUdpDriver;
use crate::links::LwipLinks;
use crate::listener::{Admission, SessionListener};
use crate::session_host::{LwipStack, OpenRefused, SessionHost};

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
    fn bind(&mut self, peer: UdpPeer) -> Result<LwipUdpDriver, LinkOpenError> {
        self.links.bind_driver(0, peer)
    }
}

/// The [`Dialer`](wz_session_mcu::connect_manager::Dialer) of the slot profile over lwIP: the
/// stack-neutral one, given lwIP's host and its socket pool.
pub type SlotDialer<'a, C, L, F, const S: usize, const P: usize> =
    wz_session_mcu::slot_dial::SlotDialer<'a, C, LwipStack<L>, LwipBinder<'a, L>, F, S, P>;

/// The declaration ids the node uses on each session; ids are per session.
const ADMIN_QUERYABLE_ID: u64 = 1;
const CONFIG_SUBSCRIBER_ID: u64 = 2;

/// An admin key (`@/<zid>/<whatami>/**` or `.../config/**`) in fixed text.
type KeyText = FixedText<{ caps::MAX_KEYEXPR_BYTES }>;

/// Which input a node's construction refused: the admin keys its identity names
/// did not fit, which is found at startup, where it can be fixed, and not at the
/// first declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRefused {
    /// A key built from the node's zid and role is wider than
    /// `caps::MAX_KEYEXPR_BYTES`.
    KeyTooLong,
}

/// An MCU node a host can reach, and reconfigure, at runtime, on the slot profile.
///
/// Built from the pieces the image declared; ticked from the firmware's loop with
/// the time. See the module documentation for what it holds and where.
pub struct SlotAdminNode<'a, C, L, F, const S: usize, const P: usize, const LANES: usize>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    F: SessionFactory<C>,
{
    host: &'a SessionHost<C, L, F::Entropy, S, P>,
    links: &'a LwipLinks<L>,
    factory: &'a RefCell<F>,
    listener: &'static SessionListener<LANES>,
    listen_port: u16,
    listening: bool,
    timeouts: SessionTimeouts,
    status: &'static FixedNodeStatus<S>,
    manager: ConnectManager<SlotDialer<'a, C, L, F, S, P>>,
    accepted: BoundedVec<SlotSession<C>, LANES>,
    admin_key: KeyText,
    config_key: KeyText,
}

impl<'a, C, L, F, const S: usize, const P: usize, const LANES: usize>
    SlotAdminNode<'a, C, L, F, S, P, LANES>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    F: SessionFactory<C>,
{
    /// A node that listens on `listen_port` through `listener`, dials what `control`
    /// names, answers as `zid_hex` / `whatami` and reports through `status`.
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
        status: &'static FixedNodeStatus<S>,
        zid_hex: &str,
        whatami: &'static str,
        listen_port: u16,
        timeouts: SessionTimeouts,
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
            host,
            links,
            factory,
            listener,
            listen_port,
            listening: false,
            timeouts,
            status,
            manager: ConnectManager::new(
                control,
                SlotDialer::new(&**host, LwipBinder { links }, factory, timeouts),
            ),
            accepted: BoundedVec::new(),
            admin_key,
            config_key,
        })
    }

    /// The sessions a host reached this node on, while there are any.
    pub fn accepted(&self) -> impl Iterator<Item = &SlotSession<C>> {
        self.accepted.iter()
    }

    /// Call `f` for each session this node dialled and holds, with the endpoint it was
    /// dialled for, in the list's order.
    pub fn for_each_dialled(&self, mut f: impl FnMut(&str, &SlotSession<C>)) {
        for (endpoint, session) in self.manager.sessions() {
            f(endpoint, session);
        }
    }

    /// Where every written endpoint stands, as the connect manager holds it.
    pub fn for_each_endpoint(&self, mut f: impl FnMut(&str, SlotState)) {
        for (endpoint, state) in self.manager.states() {
            f(endpoint, state);
        }
    }

    /// Advance the node to `now_ms`: bind the listening port if it is not bound, let
    /// go of the accepted sessions that have ended, admit the ones that have asked,
    /// keep the dialled sessions in step with the control, declare the admin space on
    /// every established session that has not had it, and report what the node holds.
    pub fn tick(&mut self, now_ms: u64) {
        self.ensure_listening();
        self.accepted.retain(|session| !session.is_finished());
        self.admit();
        self.manager.tick(now_ms);
        self.declare_on_new_sessions();
        self.report(now_ms);
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
                let params = factory.borrow_mut().params();
                let opened = host.admit(
                    admission,
                    entropy,
                    params,
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

    /// Send the admin declarations on every established session that has not had
    /// them.
    fn declare_on_new_sessions(&self) {
        let admin_key = self.admin_key.prefix();
        let config_key = self.config_key.prefix();
        let live = self
            .accepted
            .iter()
            .chain(self.manager.sessions().map(|(_, session)| session));
        for session in live {
            if session.actions().is_established()
                && !session.declared()
                && declare_admin(session.actions(), admin_key, config_key)
            {
                session.mark_declared();
            }
        }
    }

    /// Report every established session, accepted and dialled, and every written
    /// endpoint with where it stands, as the heap node does.
    fn report(&self, now_ms: u64) {
        let mut rows: BoundedVec<Result<FixedAdminSession, RowRefused>, S> = BoundedVec::new();
        let sessions = self
            .accepted
            .iter()
            .chain(self.manager.sessions().map(|(_, session)| session));
        for session in sessions {
            if let Some(row) = session
                .actions()
                .with_admin_session(|view: AdminSessionRef<'_>| FixedAdminSession::from_view(&view))
            {
                // More established sessions than the pool has slots cannot be; one
                // that did not fit would be a row the status could not take either.
                let _ = rows.push(row);
            }
        }
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

/// Declare upstream's two admin-space interests on `actions`: `true` once both went
/// out. A router forwards a GET or a PUT only to a face that declared a match, so
/// without these a stock zenohd connected to the node holds a live session and
/// routes nothing to it.
fn declare_admin<C: ClockSource + 'static>(
    actions: &SessionHandle<C>,
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

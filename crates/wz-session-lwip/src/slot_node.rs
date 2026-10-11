// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node of the `session-slot` profile (fixed-memory step S9c): the node a
//! host reaches, and reconfigures at runtime, with every session, table and text it
//! holds in storage the image declared.
//!
//! The growable profile's node is `wz_session_mcu::admin_node::AdminNode`, generic
//! over a network stack through `SessionLinks` and built from `Rc` handles, `String`
//! keys and a `Vec` of declared sessions. None of that has a slot form that is
//! stack-neutral yet, because a session on this profile is opened by the SESSION HOST
//! ([`SessionHost`]), which owns the tables of one
//! stack. So the node of the slot profile is written over that host, here, beside it,
//! and is lwIP's; a stack of another kind brings its own host and its own copy of this
//! module's twenty lines of wiring. What is shared is everything that decides: the
//! connect manager (`wz_session_mcu::connect_manager`), the admin queryable and its
//! fixed rows (`wz_session_mcu::admin_fixed`), the config write host
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

use core::cell::{Cell, RefCell};

use wz_runtime_coop::session_drive::{SessionDriveConfig, SessionRole};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle};
use wz_session_core::adminspace::{write_admin_queryable_key, AdminSessionRef};
use wz_session_core::bounded::{BoundedVec, CapacityFull};
use wz_session_core::caps::{self, MAX_STATIC_CONNECT};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::text_out::FixedText;
use wz_session_mcu::admin_fixed::{FixedAdminSession, FixedNodeStatus, RowRefused};
use wz_session_mcu::admin_status::DialStatus;
use wz_session_mcu::app_layer::SessionEvents;
use wz_session_mcu::connect_manager::{ConnectManager, DialFailed, Dialer, Ended, SlotState};
use wz_session_mcu::dial::parse_udp_endpoint;

use wz_link_lwip::LwipLink;

use core::ops::Deref;

use crate::links::LwipLinks;
use crate::listener::{Admission, SessionListener};
use crate::session_host::{DialRefused, OpenRefused, OpenedSession, SessionHost};

/// What the node needs from the image to make a session: the entropy source the
/// session's cookies are drawn from, its handshake parameters, and the application
/// layer it reports to. One value for the three, because the node makes sessions two
/// ways (it dials and it accepts) and the three must not differ between them.
pub trait SessionFactory<C: ClockSource + 'static> {
    /// The entropy source a session owns, in its slot.
    type Entropy: EntropySource + Send + 'static;
    /// The application layer a session reports its iterations to, kept in its task.
    type Events: SessionEvents + 'static;

    /// A fresh entropy source for one session.
    fn entropy(&mut self) -> Self::Entropy;

    /// The handshake parameters of one session: its zid, resolutions, signing key.
    fn params(&mut self) -> SessionInitParams;

    /// The application layer of the session whose handle this is, made after the
    /// session's slot is claimed and before its pump is
    /// ([`SessionHost::open`](crate::session_host::SessionHost::open)). The admin node's
    /// is `wz_session_mcu::app_layer::SlotDispatch` over the process-wide observer.
    fn events(&mut self, handle: &SessionHandle<C>) -> Self::Events;
}

/// The `on_event` closure a session driver takes, over the factory's application layer
/// for the session `handle` names.
fn events_of<C, F>(
    factory: &RefCell<F>,
    handle: &SessionHandle<C>,
) -> impl FnMut(IterationEvent<'_>) + 'static
where
    C: ClockSource + 'static,
    F: SessionFactory<C>,
{
    let mut events = factory.borrow_mut().events(handle);
    move |event| events.on_event(event)
}

/// A session this node holds, with what the node remembers about it.
pub struct SlotSession<C: ClockSource + 'static> {
    opened: OpenedSession<C>,
    /// Whether the session was ever seen established, sampled each time the manager
    /// asks (a session that establishes and drops between two ticks reads as never
    /// established, so its re-dial continues the old outage's period: it errs towards
    /// waiting longer, never towards dialling harder).
    established: bool,
    /// Whether the admin declarations have gone out on it.
    declared: Cell<bool>,
}

impl<C: ClockSource + 'static> SlotSession<C> {
    fn new(opened: OpenedSession<C>) -> Self {
        Self {
            opened,
            established: false,
            declared: Cell::new(false),
        }
    }

    /// The handle to the session, to publish or declare through.
    pub fn actions(&self) -> &SessionHandle<C> {
        &self.opened.actions
    }

    /// Whether the session's task has ended.
    pub fn is_finished(&self) -> bool {
        self.opened.task.is_finished()
    }

    /// End the session's task now, without a Close on the wire.
    pub fn abort(&self) {
        self.opened.task.abort();
    }

    /// The task that runs the session, for a caller that waits on it.
    pub fn task(&self) -> &CoopLocalJoinHandle<DriverOutcome> {
        &self.opened.task
    }
}

/// The [`Dialer`] of the slot profile: a written `udp/<ipv4>:<port>` becomes an
/// initiator session opened by the session host, or a typed refusal. The twin of
/// `wz_session_mcu::dial::UdpDialer`, with a socket out of the host's pool, a slot, a
/// pump cell and a task cell where that one has `Rc` handles and a boxed sink.
///
/// An endpoint this build cannot dial at all (a scheme it has no link for, an
/// address it cannot parse) is refused by name and not retried; a node that cannot
/// afford a session RIGHT NOW (the pool has no socket, a table has no cell) answers
/// `Exhausted`, which the manager counts as a failed attempt of the same outage.
pub struct SlotDialer<'a, C, L, F, const S: usize, const P: usize>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    F: SessionFactory<C>,
{
    host: &'a SessionHost<C, L, F::Entropy, S, P>,
    links: &'a LwipLinks<L>,
    factory: &'a RefCell<F>,
    timeouts: SessionTimeouts,
}

impl<'a, C, L, F, const S: usize, const P: usize> SlotDialer<'a, C, L, F, S, P>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    F: SessionFactory<C>,
{
    /// A dialler over `host`, whose sockets `links` binds, making its sessions
    /// through `factory` with the handshake deadlines `timeouts`.
    pub fn new(
        host: &'a SessionHost<C, L, F::Entropy, S, P>,
        links: &'a LwipLinks<L>,
        factory: &'a RefCell<F>,
        timeouts: SessionTimeouts,
    ) -> Self {
        Self {
            host,
            links,
            factory,
            timeouts,
        }
    }
}

impl<C, L, F, const S: usize, const P: usize> Dialer for SlotDialer<'_, C, L, F, S, P>
where
    C: ClockSource + 'static,
    L: Deref<Target = LwipLink> + Clone + 'static,
    F: SessionFactory<C>,
{
    type Session = SlotSession<C>;

    fn dial(&mut self, endpoint: &str) -> Result<Self::Session, DialFailed> {
        let peer = parse_udp_endpoint(endpoint).map_err(DialFailed::Refused)?;
        let entropy = self.factory.borrow_mut().entropy();
        let params = self.factory.borrow_mut().params();
        let factory = self.factory;
        let opened = self
            .host
            .dial(
                self.links,
                peer,
                entropy,
                params,
                SessionDriveConfig {
                    timeouts: self.timeouts,
                    role: SessionRole::Initiator,
                    max_iters: None,
                },
                |handle| events_of(factory, handle),
            )
            // Whichever table is full, the node cannot afford a session right now:
            // each table counted its own refusal, and the endpoint waits its period.
            .map_err(|refused| match refused {
                DialRefused::Link(_) | DialRefused::Open(_) => DialFailed::Exhausted,
            })?;
        Ok(SlotSession::new(opened))
    }

    fn ended(&mut self, session: &mut Self::Session) -> Option<Ended> {
        session.established |= session.opened.actions.is_established();
        if !session.is_finished() {
            return None;
        }
        Some(if session.established {
            Ended::AfterEstablished
        } else {
            Ended::BeforeEstablished
        })
    }

    fn hang_up(&mut self, session: Self::Session) {
        // An established peer is told; a half-open one has nothing to close.
        if session.opened.actions.is_established() {
            session
                .opened
                .actions
                .send_close_with_reason(CloseReason::Generic);
        }
        session.abort();
    }
}

/// The declaration ids the node uses on each session; ids are per session.
const ADMIN_QUERYABLE_ID: u64 = 1;
const CONFIG_SUBSCRIBER_ID: u64 = 2;

/// An admin key (`@/<zid>/<whatami>/**` or `.../config/**`) in fixed text.
type KeyText = FixedText<{ caps::MAX_KEYEXPR_BYTES }>;

/// Why a node was not built: the admin keys its identity names did not fit, which
/// is found at startup, where it can be fixed, and not at the first declaration.
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
            manager: ConnectManager::new(control, SlotDialer::new(host, links, factory, timeouts)),
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
            if session.opened.actions.is_established()
                && !session.declared.get()
                && declare_admin(&session.opened.actions, admin_key, config_key)
            {
                session.declared.set(true);
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
                .opened
                .actions
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
                        .is_some_and(|(_, session)| session.opened.actions.is_established()),
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

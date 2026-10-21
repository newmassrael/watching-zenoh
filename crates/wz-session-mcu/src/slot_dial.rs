// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The dialler of the slot profile, written ONCE for every network stack: a written
//! `udp/<ipv4>:<port>` becomes an initiator session opened by the session host
//! ([`crate::slot_host::SessionHost`]), or a typed refusal. The twin of
//! [`crate::dial::UdpDialer`], with a socket the stack binds, a slot, a pump cell and a task
//! cell where that one has `Rc` handles and a boxed sink.
//!
//! An endpoint this build cannot dial at all (a scheme it has no link for, an address it cannot
//! parse) is refused by name and not retried; a node that cannot afford a session RIGHT NOW (the
//! stack has no socket, a table has no cell) answers `Exhausted`, which the manager counts as a
//! failed attempt of the same outage.
//!
//! It was `wz-session-lwip`'s and named lwIP's socket pool for what it needs of a stack: a way
//! to bind the driver of a dial ([`Bind`]).

use core::cell::{Cell, RefCell};

use wz_runtime_coop::session_drive::{
    LinkOpenError, SessionDriveConfig, SessionRole, SlotStack, UdpPeer,
};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;

use crate::app_layer::SessionEvents;
use crate::connect_manager::{DialFailed, Dialer, Ended};
use crate::dial::parse_udp_endpoint;
use crate::slot_host::{DialRefused, OpenedSession, SessionHost};

/// What the node needs from the image to make a session: the entropy source the session's
/// cookies are drawn from, its handshake parameters, and the application layer it reports to. One
/// value for the three, because a node makes sessions two ways (it dials and it accepts) and the
/// three must not differ between them.
pub trait SessionFactory<C: ClockSource + 'static> {
    /// The entropy source a session owns, in its slot.
    type Entropy: EntropySource + Send + 'static;
    /// The application layer a session reports its iterations to, kept in its task.
    type Events: SessionEvents + 'static;

    /// A fresh entropy source for one session.
    fn entropy(&mut self) -> Self::Entropy;

    /// The handshake parameters of one session: its zid, resolutions, signing key.
    fn params(&mut self) -> SessionInitParams;

    /// The application layer of the session whose handle this is, made after the session's slot
    /// is claimed and before its pump is
    /// ([`SessionHost::open`](crate::slot_host::SessionHost::open)).
    fn events(&mut self, handle: &SessionHandle<C>) -> Self::Events;
}

/// The `on_event` closure a session driver takes, over the factory's application layer for the
/// session `handle` names.
pub fn events_of<C, F>(
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

/// A session a node holds, with what the node remembers about it.
pub struct SlotSession<C: ClockSource + 'static> {
    opened: OpenedSession<C>,
    /// Whether the session was ever seen established, sampled each time the manager asks (a
    /// session that establishes and drops between two ticks reads as never established, so its
    /// re-dial continues the old outage's period: it errs towards waiting longer, never towards
    /// dialling harder).
    established: bool,
    /// Whether the node's declarations have gone out on it.
    declared: Cell<bool>,
}

impl<C: ClockSource + 'static> SlotSession<C> {
    /// A session just opened, not yet established and not yet declared on.
    pub fn new(opened: OpenedSession<C>) -> Self {
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

    /// Whether the node's declarations have gone out on this session.
    pub fn declared(&self) -> bool {
        self.declared.get()
    }

    /// Note that the node's declarations have gone out on this session.
    pub fn mark_declared(&self) {
        self.declared.set(true);
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

/// How a stack opens the driver of a dial: a socket on a port it picks, with replies and first
/// sends going to `peer`. The socket comes out of whatever the stack keeps for it (lwIP's pool the
/// image declared; Zephyr's descriptors), and a stack with none left answers
/// [`LinkOpenError::Exhausted`].
pub trait Bind<D> {
    /// The driver of a link that dials `peer`.
    fn bind(&mut self, peer: UdpPeer) -> Result<D, LinkOpenError>;
}

/// The [`Dialer`] of the slot profile over the session host of a stack `T`, binding its sockets
/// with `B`.
pub struct SlotDialer<'a, C, T, B, F, const S: usize, const P: usize>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C>,
{
    host: &'a SessionHost<C, T, F::Entropy, S, P>,
    bind: B,
    factory: &'a RefCell<F>,
    timeouts: SessionTimeouts,
}

impl<'a, C, T, B, F, const S: usize, const P: usize> SlotDialer<'a, C, T, B, F, S, P>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C>,
{
    /// A dialler over `host`, whose sockets `bind` opens, making its sessions through `factory`
    /// with the handshake deadlines `timeouts`.
    pub fn new(
        host: &'a SessionHost<C, T, F::Entropy, S, P>,
        bind: B,
        factory: &'a RefCell<F>,
        timeouts: SessionTimeouts,
    ) -> Self {
        Self {
            host,
            bind,
            factory,
            timeouts,
        }
    }
}

impl<C, T, B, F, const S: usize, const P: usize> Dialer for SlotDialer<'_, C, T, B, F, S, P>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C>,
{
    type Session = SlotSession<C>;

    fn dial(&mut self, endpoint: &str) -> Result<Self::Session, DialFailed> {
        let peer = parse_udp_endpoint(endpoint).map_err(DialFailed::Refused)?;
        let entropy = self.factory.borrow_mut().entropy();
        let params = self.factory.borrow_mut().params();
        let factory = self.factory;
        let bind = &mut self.bind;
        let opened = self
            .host
            .dial(
                || bind.bind(peer),
                entropy,
                params,
                SessionDriveConfig {
                    timeouts: self.timeouts,
                    role: SessionRole::Initiator,
                    max_iters: None,
                },
                |handle| events_of(factory, handle),
            )
            // Whichever table is full, the node cannot afford a session right now: each table
            // counted its own refusal, and the endpoint waits its period.
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

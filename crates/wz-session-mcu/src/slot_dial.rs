// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The dialler of the slot profile, written ONCE for every network stack: a written
//! `udp/<ipv4>:<port>` becomes an initiator session opened by the session host
//! ([`crate::slot_host::SessionHost`]), or a typed refusal. The twin of
//! `crate::dial::UdpDialer`, with a socket the stack binds, a slot, a pump cell and a task
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

pub use wz_runtime_coop::session_drive::Bind;
use wz_runtime_coop::session_drive::{SessionDriveConfig, SessionRole, SlotStack};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::{DriverOutcome, EventSink, InPlaceRecord, IterationEvent};
use wz_session_core::entropy::EntropySource;
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::replay_cursor::ReplayCursor;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;

use crate::app_layer::SessionEvents;
use crate::connect_manager::{DialFailed, Dialer, Ended};
use crate::dial::{dial_failed, parse_locator};
use crate::slot_host::{DialRefused, OpenedSession, SessionHost};

/// What the node needs from the image to make a session: the entropy source the session's
/// cookies are drawn from, its handshake parameters, and the application layer it reports to. One
/// value for the three, because a node makes sessions two ways (it dials and it accepts) and the
/// three must not differ between them.
///
/// `D` is the type of the link driver the sessions are made over: the stack's own driver type
/// where the image names it, which is what lets the session's calls through the link be direct.
pub trait SessionFactory<
    C: ClockSource + 'static,
    D: BoxedLinkDriver + ?Sized + 'static = dyn BoxedLinkDriver,
>
{
    /// The entropy source a session owns, in its slot.
    type Entropy: EntropySource + Send + 'static;
    /// The application layer a session reports its iterations to, kept in its task.
    type Events: SessionEvents + 'static;

    /// A fresh entropy source for one session.
    fn entropy(&mut self) -> Self::Entropy;

    /// The handshake parameters of one session: its zid, resolutions, signing key.
    fn params(&mut self) -> SessionInitParams;

    /// The handshake parameters of one session a peer opened. They differ from a dialled
    /// session's in one respect a node with a listener must state: the mode it presents to
    /// whoever connects to it. A stock client refuses a client, so the node that accepts presents
    /// itself as a peer there, while toward the routers it dials it stays what it is. A node that
    /// accepts nothing never asks, so the default is the dialled parameters.
    fn accepted_params(&mut self) -> SessionInitParams {
        self.params()
    }

    /// The application layer of the session whose handle this is, made after the session's slot
    /// is claimed and before its pump is
    /// ([`SessionHost::open`](crate::slot_host::SessionHost::open)).
    fn events(&mut self, handle: &SessionHandle<C, D>) -> Self::Events;
}

/// What a session driver reports to, over an application layer: the layer's `on_event` for
/// every event, and its `on_record` for a record the receive lends.
///
/// A struct and not a closure, so that the driver's two callees stay two: a closure has one
/// body, and the call graph of an image could not tell what a lent record reaches from what
/// the turn's own events do (`wz_session_core::driver_loop::EventSink`).
pub struct EventsOf<E>(E);

impl<E: SessionEvents> EventSink for EventsOf<E> {
    fn event(&mut self, event: IterationEvent<'_>) {
        self.0.on_event(event);
    }

    fn record(&mut self, record: InPlaceRecord<'_>) {
        self.0.on_record(record);
    }
}

/// The sink a session driver takes, over the factory's application layer for the session
/// `handle` names.
pub fn events_of<C, D, F>(factory: &RefCell<F>, handle: &SessionHandle<C, D>) -> EventsOf<F::Events>
where
    C: ClockSource + 'static,
    D: BoxedLinkDriver + ?Sized + 'static,
    F: SessionFactory<C, D>,
{
    EventsOf(factory.borrow_mut().events(handle))
}

/// A session a node holds, with what the node remembers about it.
pub struct SlotSession<
    C: ClockSource + 'static,
    D: BoxedLinkDriver + ?Sized + 'static = dyn BoxedLinkDriver,
> {
    opened: OpenedSession<C, D>,
    /// Whether the session was ever seen established, sampled each time the manager asks (a
    /// session that establishes and drops between two ticks reads as never established, so its
    /// re-dial continues the old outage's period: it errs towards waiting longer, never towards
    /// dialling harder).
    established: bool,
    /// How far the node's declarations have gone out on it: `None` until a replay begins, then the
    /// place in the node's sequence the peer has been told up to
    /// ([`ReplayCursor`](wz_session_core::replay_cursor::ReplayCursor)). A session that ends takes
    /// its cursor with it, so a redial or a new accept begins at the start, as a peer that holds
    /// nothing needs.
    replay: Cell<Option<ReplayCursor>>,
    /// The time, in the node's milliseconds, before which the replay sends nothing more: the end of
    /// the wait a paced turn leaves. `0` is due now, which is every session's state until its first
    /// turn and the state of an unpaced one throughout.
    next_turn_ms: Cell<u64>,
}

impl<C: ClockSource + 'static, D: BoxedLinkDriver + ?Sized + 'static> SlotSession<C, D> {
    /// A session just opened, not yet established and not yet declared on.
    pub fn new(opened: OpenedSession<C, D>) -> Self {
        Self {
            opened,
            established: false,
            replay: Cell::new(None),
            next_turn_ms: Cell::new(0),
        }
    }

    /// The handle to the session, to publish or declare through.
    pub fn actions(&self) -> &SessionHandle<C, D> {
        &self.opened.actions
    }

    /// Whether the node's declarations have gone out on this session: a replay was begun and has
    /// told the peer every entry.
    pub fn declared(&self) -> bool {
        self.replay.get().is_some_and(|cursor| cursor.finished())
    }

    /// Note that the node's declarations have gone out on this session, for a host that sends its
    /// declarations in one step and has no sequence to resume.
    pub fn mark_declared(&self) {
        self.replay.set(Some(ReplayCursor::idle()));
    }

    /// The replay of the node's `total` declarations on this session, begun at the first entry when
    /// none was: the peer holds nothing of a session that has just established.
    pub fn replay(&self, total: usize) -> ReplayCursor {
        self.replay.get().unwrap_or(ReplayCursor::begin(total))
    }

    /// Keep where the replay has got to, for the next round to resume from.
    pub fn set_replay(&self, cursor: ReplayCursor) {
        self.replay.set(Some(cursor));
    }

    /// Whether the replay may send at `now_ms`: the wait the last paced turn left is over.
    pub fn replay_due(&self, now_ms: u64) -> bool {
        now_ms >= self.next_turn_ms.get()
    }

    /// Hold the replay's next turn back until `at_ms`.
    pub fn set_next_turn(&self, at_ms: u64) {
        self.next_turn_ms.set(at_ms);
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

/// The [`Dialer`] of the slot profile over the session host of a stack `T`, binding its sockets
/// with `B`.
pub struct SlotDialer<'a, C, T, B, F, const S: usize, const P: usize>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C, T::Driver>,
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
    F: SessionFactory<C, T::Driver>,
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

impl<C, T, B, F, const S: usize, const P: usize> SlotDialer<'_, C, T, B, F, S, P>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C, T::Driver>,
{
    // Not inlined into the loop that ticks the manager: a dial holds the socket's driver (the two
    // buffers of a link, some 3 KB) and the session's parameters, by value, several times over on
    // the way into the slot. Inlined, that frame is under the loop for the node's whole life and
    // adds to every receive's; kept apart, it exists for the length of a dial, which the receive
    // path's frames are not beneath. A dial of an endpoint and a dial for a node share it, so
    // that the two are one frame and not two.
    #[inline(never)]
    fn dial_expecting(
        &mut self,
        endpoint: &str,
        expected_zid: Option<[u8; wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES]>,
    ) -> Result<SlotSession<C, T::Driver>, DialFailed> {
        let to = parse_locator(endpoint).map_err(DialFailed::Refused)?;
        let entropy = self.factory.borrow_mut().entropy();
        let factory = self.factory;
        let bind = &mut self.bind;
        let opened = self
            .host
            .dial(
                || bind.bind(to),
                // `None` for a configured endpoint, which names no node, as upstream's
                // `connect/endpoints` does not; the node's zid for a dial made for one, so that
                // the session closes at the InitAck if another node answers (decision D4).
                expected_zid,
                entropy,
                // Handed as the function that makes it, which the slot calls in its own frame: a
                // value built here is copied into the frame of each call it passes through.
                || factory.borrow_mut().params(),
                SessionDriveConfig {
                    timeouts: self.timeouts,
                    role: SessionRole::Initiator,
                    max_iters: None,
                },
                |handle| events_of(factory, handle),
            )
            // Whichever table is full, the node cannot afford a session right now: each table
            // counted its own refusal, and the endpoint waits its period. What the stack said of
            // the link is the stack's to say.
            .map_err(|refused| match refused {
                DialRefused::Link(link) => dial_failed(link),
                DialRefused::Open(_) => DialFailed::Exhausted,
            })?;
        Ok(SlotSession::new(opened))
    }
}

impl<C, T, B, F, const S: usize, const P: usize> Dialer for SlotDialer<'_, C, T, B, F, S, P>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C, T::Driver>,
{
    type Session = SlotSession<C, T::Driver>;

    fn classify(endpoint: &str) -> Result<(), crate::connect_manager::DialRefused> {
        parse_locator(endpoint).map(|_| ())
    }

    /// The slot host's handshake holds a session to the node it was made for, so a node may be
    /// opened by its zid over this dialer (decision D4).
    const VERIFIES_NODES: bool = true;

    fn dial(&mut self, endpoint: &str) -> Result<Self::Session, DialFailed> {
        // A configured endpoint names no node, as upstream's `connect/endpoints` does not.
        self.dial_expecting(endpoint, None)
    }

    fn dial_for(
        &mut self,
        endpoint: &str,
        node: &wz_session_core::locator_directory::DirectoryZid,
    ) -> Result<Self::Session, DialFailed> {
        self.dial_expecting(endpoint, Some(*node))
    }

    fn established(&mut self, session: &mut Self::Session) -> bool {
        session.established |= session.opened.actions.is_established();
        session.established
    }

    fn remote(
        &self,
        session: &Self::Session,
    ) -> Option<[u8; wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES]> {
        session.opened.actions.peer_zid_array()
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

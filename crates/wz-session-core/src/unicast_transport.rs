// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The unicast transport of the session over one link, as one value ([`UnicastTransport`]): the
//! receive of the session ([`UnicastRx`]) and its timers ([`TransportTimers`]).
//!
//! Its owner dials or accepts the link, ends it and holds the wait, and hands this value what
//! happened: a datagram the link read (`UnicastTransport::on_datagram` with `rx-in-place`,
//! `UnicastTransport::on_frame` with `alloc`) and the time ([`UnicastTransport::on_time`]). It
//! asks when to look again ([`UnicastTransport::due_ms`]). Every order that matters (what is
//! raised before a datagram is read, and that the lease is judged after it) is written once, here,
//! so two owners of a transport cannot keep it in two orders. An owner whose link lends a datagram
//! only inside a call of its own reads it through a turn ([`UnicastTransport::begin_input`],
//! [`InputTurn`]), which keeps the same order across that call.
//!
//! The life of the link (`crate::link_life::UnicastLink`) is not part of this value: it is the
//! face's, read by every send's gate under the lock the face's record lies under, while the
//! receive and the timers are lent to the read's step apart from that lock. One value is lent
//! under one lock, so the two stay apart and the owner holds each where it is read.
//!
//! The session's machine and its actions are lent to each call and not held: the machine is the
//! session's, built anew for each link, and the actions are reached through the place the
//! session's transport lies in ([`crate::transport_place::TransportPlace`]).
//!
//! [`UnicastTransport`]: crate::unicast_transport::UnicastTransport
//! [`UnicastTransport::on_time`]: crate::unicast_transport::UnicastTransport::on_time
//! [`UnicastTransport::due_ms`]: crate::unicast_transport::UnicastTransport::due_ms
//! [`UnicastTransport::begin_input`]: crate::unicast_transport::UnicastTransport::begin_input
//! [`InputTurn`]: crate::unicast_transport::InputTurn
//! [`UnicastRx`]: crate::unicast_rx::UnicastRx
//! [`TransportTimers`]: crate::transport_timers::TransportTimers

use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use wz_runtime_core::TimeSource;

#[cfg(feature = "rx-in-place")]
use crate::drive::DatagramPath;
use crate::drive::SessionEngine;
use crate::driver_loop::{EventSink, IterationEvent};
#[cfg(feature = "alloc")]
use crate::link::RxFrame;
use crate::link::{LostCause, SessionRuntime};
use crate::session_actions::SessionLinkActions;
use crate::session_timeouts::SessionTimeouts;
use crate::transport_timers::TransportTimers;
use crate::unicast_rx::{RxReassembly, UnicastRx};

/// The unicast transport of the session over one link. See the module documentation.
pub struct UnicastTransport<Router> {
    rx: UnicastRx<Router>,
    timers: TransportTimers,
}

impl<Router> UnicastTransport<Router> {
    /// Build the transport of a session with the handshake bounds `timeouts` in `place`, and
    /// lend it: nothing read, no timer armed. Built in place, as its parts are: the Router is the
    /// largest part, and it is never a value on a stack on the way.
    ///
    /// `make_router` writes the Router in the place it is handed and lends it back
    /// ([`UnicastRx::init_in`]). One that lends back anything else has written no Router, and no
    /// transport is built: `None`, with `place` holding nothing. `place` is overwritten without
    /// dropping what it held.
    pub fn init_in(
        place: &mut MaybeUninit<Self>,
        timeouts: SessionTimeouts,
        make_router: impl FnOnce(&mut MaybeUninit<Router>) -> &mut Router,
    ) -> Option<&mut Self> {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self` (it is `place`), and the receive's field is
        // lent as the uninitialised place `MaybeUninit<UnicastRx<Router>>` lays out as a
        // `UnicastRx<Router>`.
        let rx = unsafe { &mut *addr_of_mut!((*at).rx).cast::<MaybeUninit<UnicastRx<Router>>>() };
        UnicastRx::init_in(rx, make_router)?;
        // SAFETY: the receive is written, and the timers are written once in theirs; then every
        // field is written and the transport is whole.
        unsafe {
            addr_of_mut!((*at).timers).write(TransportTimers::new(timeouts));
            Some(place.assume_init_mut())
        }
    }

    /// The receive of the session the link carries.
    pub fn rx(&self) -> &UnicastRx<Router> {
        &self.rx
    }

    /// The first instant, in the session's monotonic milliseconds, at which the transport is to be
    /// looked at again though no input came: the first of the session's timers
    /// ([`TransportTimers::next_due_ms`]), `None` when none is armed. A state of the machine the
    /// timers see for the first time has its handshake deadline armed from the end of the
    /// millisecond `now_ms` names.
    pub fn due_ms<R: SessionRuntime, T: TimeSource>(
        &mut self,
        engine: &SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
    ) -> Option<u64> {
        self.timers.next_due_ms(engine, actions, now_ms)
    }
}

impl<Router: RxReassembly> UnicastTransport<Router> {
    /// Whether the transport takes a datagram now ([`UnicastRx::ready`]). An owner asks before it
    /// reads its link, so a datagram the receive could not stage stays with the link.
    pub fn ready(&self) -> bool {
        self.rx.ready()
    }

    /// Hand the session the time `now_ms` with no input: what falls due before input is read
    /// (the application layer's deadline, told as [`IterationEvent::AppWake`], and the end of the
    /// fragment chains past theirs), then the session's timers ([`TransportTimers::fire_due`]).
    pub fn on_time<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        &mut self,
        engine: &mut SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut F,
    ) {
        self.begin_input(actions, now_ms, &mut *on_event)
            .end(engine, actions, on_event);
    }

    /// Hand the session one datagram its link read, at `now_ms`: what [`Self::on_time`] raises
    /// before input is read, then the datagram, dispatched where the link holds it
    /// ([`UnicastRx::dispatch_datagram`]), then the session's timers. The timers come after the
    /// datagram, so the lease is judged after what the peer sent last, and they come at every
    /// datagram, so a peer that sends faster than this end reads cannot keep this end from the
    /// keep-alive it owes. The path the datagram took, which the receive counted.
    #[cfg(feature = "rx-in-place")]
    pub fn on_datagram<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        &mut self,
        unit: &[u8],
        engine: &mut SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut F,
    ) -> DatagramPath {
        let mut turn = self.begin_input(actions, now_ms, &mut *on_event);
        let path = turn.datagram(unit, engine, actions, &mut *on_event);
        turn.end(engine, actions, on_event);
        path
    }

    /// `on_datagram` (the in-place receive's, with `rx-in-place`) for a datagram the copying
    /// receive read into a frame of its own ([`UnicastRx::dispatch_frame`]), in the same order.
    #[cfg(feature = "alloc")]
    pub fn on_frame<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        &mut self,
        frame: RxFrame,
        engine: &mut SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut F,
    ) {
        let mut turn = self.begin_input(actions, now_ms, &mut *on_event);
        turn.frame(frame, engine, actions, &mut *on_event);
        turn.end(engine, actions, on_event);
    }

    /// Begin a turn of input at `now_ms`: what is raised before input is read, raised now (the
    /// application layer's deadline and the end of the fragment chains past theirs), and the
    /// turn that takes at most one unit of input and then hands the session's timers the time
    /// ([`InputTurn::end`]). What an owner reads through when its link lends a datagram only
    /// inside a call of the link's: the unit is handed inside that call, and the timers after it.
    pub fn begin_input<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        &mut self,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut F,
    ) -> InputTurn<'_, Router> {
        if actions.take_app_wake_due(now_ms) {
            on_event.event(IterationEvent::AppWake);
        }
        self.rx.sweep(now_ms, on_event);
        self.input_at(now_ms)
    }

    /// A turn of input at `now_ms` that raises nothing first: for an owner that hands the
    /// transport the time apart from its input, as [`Self::due_ms`] names it ([`Self::on_time`]),
    /// and reads its link between, so a unit of input costs none of that bookkeeping.
    pub fn input_at(&mut self, now_ms: u64) -> InputTurn<'_, Router> {
        InputTurn {
            transport: self,
            now_ms,
        }
    }
}

/// One turn of a transport's input ([`UnicastTransport::begin_input`]): at most one unit of input
/// handed to the session, then the session's timers ([`Self::end`]). A turn let go of without its
/// end fires no timer, which is what a turn whose receive was not ready or whose link is gone
/// ([`Self::lose`]) comes to.
#[must_use = "a turn let go of without its end hands the session's timers nothing"]
pub struct InputTurn<'t, Router> {
    transport: &'t mut UnicastTransport<Router>,
    now_ms: u64,
}

impl<Router: RxReassembly> InputTurn<'_, Router> {
    /// Whether the transport takes a unit of input in this turn ([`UnicastTransport::ready`]).
    pub fn ready(&self) -> bool {
        self.transport.rx.ready()
    }

    /// What the receive parked of the last unit, if anything, handed to the session first, so the
    /// rest of a batch does not wait for the peer to send again: whether there was any. The
    /// copying receive parks the rest of every batch ([`UnicastRx::dispatch_pending`]); a receive
    /// in place parks only the rest of a compressed one (`UnicastRx::dispatch_parked_in_place`,
    /// with `rx-in-place`).
    #[cfg(feature = "alloc")]
    pub fn parked<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        &mut self,
        engine: &mut SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        on_event: &mut F,
    ) -> bool {
        #[cfg(not(feature = "rx-in-place"))]
        {
            self.transport
                .rx
                .dispatch_pending(actions, engine, self.now_ms, on_event)
        }
        #[cfg(feature = "rx-in-place")]
        {
            self.transport
                .rx
                .dispatch_parked_in_place(actions, engine, self.now_ms, on_event)
        }
    }

    /// One datagram the link lends, dispatched where it lies ([`UnicastRx::dispatch_datagram`]):
    /// the path it took, which the receive counted. `on_event` runs inside the link's lend.
    #[cfg(feature = "rx-in-place")]
    pub fn datagram<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        &mut self,
        unit: &[u8],
        engine: &mut SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        on_event: &mut F,
    ) -> DatagramPath {
        self.transport
            .rx
            .dispatch_datagram(unit, actions, engine, self.now_ms, on_event)
    }

    /// Whether the dispatch of the datagram this turn was lent stopped before its end
    /// ([`UnicastRx::resumes_datagram`]), so its link is to keep it for a later turn.
    #[cfg(feature = "rx-in-place")]
    pub fn resumes_datagram(&self) -> bool {
        self.transport.rx.resumes_datagram()
    }

    /// One datagram the copying receive read into a frame of its own
    /// ([`UnicastRx::dispatch_frame`]).
    #[cfg(feature = "alloc")]
    pub fn frame<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        &mut self,
        frame: RxFrame,
        engine: &mut SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        on_event: &mut F,
    ) {
        self.transport
            .rx
            .dispatch_frame(frame, actions, engine, self.now_ms, on_event);
    }

    /// The link is gone (`cause`): the session is told, and `on_event` the outcome, after
    /// everything the link held before its end was read. The turn ends here: a session told its
    /// link is lost is not handed the time in the same turn.
    pub fn lose<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        self,
        engine: &mut SessionEngine<R, T>,
        cause: LostCause,
        on_event: &mut F,
    ) {
        let outcome = crate::drive::dispatch_link_lost(engine, cause);
        on_event.event(IterationEvent::Poll(&outcome));
    }

    /// End the turn: the session's timers are handed its time ([`TransportTimers::fire_due`]),
    /// after the unit of input, if one was taken, so the lease is judged after what the peer sent
    /// last; and whether or not one was, so a peer that sends faster than this end reads cannot
    /// keep this end from the keep-alive it owes.
    pub fn end<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        self,
        engine: &mut SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        on_event: &mut F,
    ) {
        self.transport
            .timers
            .fire_due(engine, actions, self.now_ms, on_event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport built in place holds the Router its maker wrote. Turned red by a build that
    /// writes another Router, or none.
    #[test]
    fn a_transport_built_in_place_holds_its_makers_router() {
        let mut place = MaybeUninit::<UnicastTransport<u32>>::uninit();
        let transport =
            UnicastTransport::init_in(&mut place, SessionTimeouts::from_build(), |slot| {
                slot.write(5)
            })
            .expect("a maker that writes its own place builds the transport");
        assert_eq!(*transport.rx().router(), 5);
    }

    /// A maker that lends back a place other than the one it was handed builds no transport.
    /// Turned red by an `init_in` that takes another place's Router as its own.
    #[test]
    fn a_maker_that_lends_back_another_place_builds_no_transport() {
        let mut place = MaybeUninit::<UnicastTransport<u32>>::uninit();
        let other: &'static mut u32 = std::boxed::Box::leak(std::boxed::Box::new(9));
        assert!(
            UnicastTransport::init_in(&mut place, SessionTimeouts::from_build(), |_slot| { other })
                .is_none()
        );
    }
}

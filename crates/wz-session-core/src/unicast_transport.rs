// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The unicast transport of a session that holds one face, as one value ([`UnicastTransport`]):
//! the life of its link ([`UnicastLink`]), the receive of the session that runs over it
//! ([`UnicastRx`]) and that session's timers ([`TransportTimers`]).
//!
//! Its owner holds the I/O and the wait, and hands this value what happened: the link's dials and
//! handshakes as inputs ([`UnicastTransport::input`], [`UnicastTransport::pumped`]), a datagram
//! the link read (`UnicastTransport::on_datagram` with `rx-in-place`, `UnicastTransport::on_frame`
//! with `alloc`) and the time ([`UnicastTransport::on_time`]). It asks when to look again
//! ([`UnicastTransport::due_ms`]), the first of what the link and the session have due. Every
//! order that matters (what is raised before a datagram is read, and that the lease is judged
//! after it) is written once, here, so two owners of a transport cannot keep it in two orders.
//! An owner whose link lends a datagram only inside a call of its own reads it through a turn
//! ([`UnicastTransport::begin_input`], [`InputTurn`]), which keeps the same order across that
//! call.
//!
//! A session whose link is handed to it made, by an owner that dialled or accepted it and ends
//! it, holds the transport over [`MadeLink`]: the same receive and timers, and no life of its
//! own to look at.
//!
//! The session's machine and its actions are lent to each call and not held: the machine is the
//! session's, built anew for each link its life brings up, and the actions are reached through the
//! place the session's transport lies in ([`crate::transport_place::TransportPlace`]).
//!
//! [`UnicastTransport`]: crate::unicast_transport::UnicastTransport
//! [`UnicastTransport::input`]: crate::unicast_transport::UnicastTransport::input
//! [`UnicastTransport::pumped`]: crate::unicast_transport::UnicastTransport::pumped
//! [`UnicastTransport::on_time`]: crate::unicast_transport::UnicastTransport::on_time
//! [`UnicastTransport::due_ms`]: crate::unicast_transport::UnicastTransport::due_ms
//! [`UnicastTransport::begin_input`]: crate::unicast_transport::UnicastTransport::begin_input
//! [`InputTurn`]: crate::unicast_transport::InputTurn
//! [`MadeLink`]: crate::unicast_transport::MadeLink
//! [`UnicastLink`]: crate::link_life::UnicastLink
//! [`UnicastRx`]: crate::unicast_rx::UnicastRx
//! [`TransportTimers`]: crate::transport_timers::TransportTimers

use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use wz_runtime_core::TimeSource;

#[cfg(feature = "rx-in-place")]
use crate::drive::DatagramPath;
use crate::drive::SessionEngine;
use crate::driver_loop::{DriverOutcome, EventSink, IterationEvent};
#[cfg(feature = "alloc")]
use crate::link::RxFrame;
use crate::link::{LostCause, SessionRuntime};
use crate::link_life::{Effects, LinkInput, LinkRole, LinkTimes, UnicastLink};
use crate::session_actions::SessionLinkActions;
use crate::session_timeouts::SessionTimeouts;
use crate::transport_timers::TransportTimers;
use crate::unicast_rx::{RxReassembly, UnicastRx};

/// What a transport asks the life of its link: when it is next to be looked at though no input
/// came.
pub trait LinkWake {
    /// The first instant, in the session's monotonic microseconds, at which the life is to be
    /// looked at again though nothing was reported of the link; `None` when it waits on a report.
    fn wake_at(&self, now_us: u64) -> Option<u64>;
}

impl LinkWake for UnicastLink {
    fn wake_at(&self, now_us: u64) -> Option<u64> {
        UnicastLink::wake_at(self, now_us)
    }
}

/// The life of a link its session is handed made: the owner that dialled or accepted it ends it,
/// and the transport has nothing of the link to look at. Holds nothing, so a session over a link
/// made for it carries no machine of the link's life.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MadeLink;

impl LinkWake for MadeLink {
    fn wake_at(&self, _now_us: u64) -> Option<u64> {
        None
    }
}

/// The unicast transport of a session that holds one face. See the module documentation.
pub struct UnicastTransport<Router, Life = UnicastLink> {
    life: Life,
    rx: UnicastRx<Router>,
    timers: TransportTimers,
}

impl<Router, Life> UnicastTransport<Router, Life> {
    /// The transport built in `place` and lent back: the receive first, its Router written by
    /// `make_router` ([`UnicastRx::init_in`]), then the life by `write_life`, then the timers,
    /// none armed. `None`, with `place` holding nothing, when `make_router` wrote no Router.
    ///
    /// # Safety
    /// `write_life` writes a life in the place it is handed.
    unsafe fn init_with_in(
        place: &mut MaybeUninit<Self>,
        timeouts: SessionTimeouts,
        make_router: impl FnOnce(&mut MaybeUninit<Router>) -> &mut Router,
        write_life: impl FnOnce(&mut MaybeUninit<Life>),
    ) -> Option<&mut Self> {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self` (it is `place`), and the receive's field is
        // lent as the uninitialised place `MaybeUninit<UnicastRx<Router>>` lays out as a
        // `UnicastRx<Router>`.
        let rx = unsafe { &mut *addr_of_mut!((*at).rx).cast::<MaybeUninit<UnicastRx<Router>>>() };
        UnicastRx::init_in(rx, make_router)?;
        // SAFETY: the receive is written. The life is written in its own field, lent as the
        // uninitialised place of a `Life`, by `write_life`, which the caller vouches writes it,
        // and the timers are written once in theirs; then every field is written and the
        // transport is whole.
        unsafe {
            write_life(&mut *addr_of_mut!((*at).life).cast::<MaybeUninit<Life>>());
            addr_of_mut!((*at).timers).write(TransportTimers::new(timeouts));
            Some(place.assume_init_mut())
        }
    }

    /// The receive of the session the link carries.
    pub fn rx(&self) -> &UnicastRx<Router> {
        &self.rx
    }

    /// The first instant, in the session's monotonic milliseconds, at which the transport is to be
    /// looked at again though no input came: the link's next look ([`LinkWake::wake_at`],
    /// rounded up to the millisecond, so a look is never early) or the first of the session's
    /// timers ([`TransportTimers::next_due_ms`]), whichever is sooner. `None` when neither has
    /// one. A state of the machine the timers see for the first time has its handshake deadline
    /// armed from the end of the millisecond `now_ms` names.
    pub fn due_ms<R: SessionRuntime, T: TimeSource>(
        &mut self,
        engine: &SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
    ) -> Option<u64>
    where
        Life: LinkWake,
    {
        let life = self
            .life
            .wake_at(now_ms.saturating_mul(1000))
            .map(|wake_us| wake_us.div_ceil(1000));
        let session = self.timers.next_due_ms(engine, actions, now_ms);
        match (life, session) {
            (Some(life), Some(session)) => Some(life.min(session)),
            (due, None) | (None, due) => due,
        }
    }
}

impl<Router> UnicastTransport<Router> {
    /// Build the transport of a session that dials `endpoints` endpoints under `times`, with the
    /// handshake bounds `timeouts`, in `place`, and lend it: its link `Idle`, nothing read, no
    /// timer armed. Built in place, as its parts are: the link's machine and the Router are the
    /// largest parts, and neither is a value on a stack on the way.
    ///
    /// `make_router` writes the Router in the place it is handed and lends it back
    /// ([`UnicastRx::init_in`]). One that lends back anything else has written no Router, and no
    /// transport is built: `None`, with `place` holding nothing. `place` is overwritten without
    /// dropping what it held.
    pub fn init_in(
        place: &mut MaybeUninit<Self>,
        times: LinkTimes,
        endpoints: usize,
        timeouts: SessionTimeouts,
        make_router: impl FnOnce(&mut MaybeUninit<Router>) -> &mut Router,
    ) -> Option<&mut Self> {
        // SAFETY: `UnicastLink::init_in` writes the link in the place it is handed. A session of
        // one face dials its endpoints itself, so its link's life is the dial role's.
        unsafe {
            Self::init_with_in(place, timeouts, make_router, |life| {
                UnicastLink::init_in(life, times, LinkRole::Dial, endpoints);
            })
        }
    }

    /// The link's life: where it stands, and when it is next to be looked at.
    pub fn life(&self) -> &UnicastLink {
        &self.life
    }

    /// What `input` about the link, reported at `now_us`, comes to ([`UnicastLink::input`]).
    pub fn input(&mut self, input: LinkInput, now_us: u64) -> Effects {
        self.life.input(input, now_us)
    }

    /// What the end of the session's drive came to, for the link ([`UnicastLink::pumped`]).
    pub fn pumped(&mut self, outcome: DriverOutcome, now_us: u64) -> Effects {
        self.life.pumped(outcome, now_us)
    }
}

impl<Router> UnicastTransport<Router, MadeLink> {
    /// Build the transport of a session over a link handed to it made, with the handshake bounds
    /// `timeouts`, in `place`, and lend it: nothing read, no timer armed. `make_router` is as
    /// [`UnicastTransport::init_in`]'s, and one that writes no Router builds no transport.
    pub fn init_made_in(
        place: &mut MaybeUninit<Self>,
        timeouts: SessionTimeouts,
        make_router: impl FnOnce(&mut MaybeUninit<Router>) -> &mut Router,
    ) -> Option<&mut Self> {
        // SAFETY: the closure writes the life, which holds nothing.
        unsafe {
            Self::init_with_in(place, timeouts, make_router, |life| {
                life.write(MadeLink);
            })
        }
    }
}

impl<Router: RxReassembly, Life> UnicastTransport<Router, Life> {
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
    ) -> InputTurn<'_, Router, Life> {
        if actions.take_app_wake_due(now_ms) {
            on_event.event(IterationEvent::AppWake);
        }
        self.rx.sweep(now_ms, on_event);
        self.input_at(now_ms)
    }

    /// A turn of input at `now_ms` that raises nothing first: for an owner that hands the
    /// transport the time apart from its input, as [`Self::due_ms`] names it ([`Self::on_time`]),
    /// and reads its link between, so a unit of input costs none of that bookkeeping.
    pub fn input_at(&mut self, now_ms: u64) -> InputTurn<'_, Router, Life> {
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
pub struct InputTurn<'t, Router, Life> {
    transport: &'t mut UnicastTransport<Router, Life>,
    now_ms: u64,
}

impl<Router: RxReassembly, Life> InputTurn<'_, Router, Life> {
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
    use crate::link_life::LinkPhase;

    fn times() -> LinkTimes {
        LinkTimes {
            open_timeout_ms: 1_000,
            redial_ms: Some(500),
            dial_look_ms: 10,
            accept_timeout_ms: 1_000,
        }
    }

    /// A transport built in place holds a link that has not opened and the Router its maker
    /// wrote. Turned red by a build that leaves the link anywhere but `Idle` or writes another
    /// Router.
    #[test]
    fn a_transport_built_in_place_holds_an_idle_link_and_its_makers_router() {
        let mut place = MaybeUninit::<UnicastTransport<u32>>::uninit();
        let transport = UnicastTransport::init_in(
            &mut place,
            times(),
            1,
            SessionTimeouts::from_build(),
            |slot| slot.write(7),
        )
        .expect("a maker that writes its own place builds the transport");
        assert_eq!(transport.life().phase(), LinkPhase::Idle);
        assert_eq!(*transport.rx().router(), 7);
    }

    /// A maker that lends back a place other than the one it was handed builds no transport.
    #[test]
    fn a_maker_that_lends_back_another_place_builds_no_transport() {
        let mut place = MaybeUninit::<UnicastTransport<u32>>::uninit();
        let other: &'static mut u32 = std::boxed::Box::leak(std::boxed::Box::new(9));
        assert!(UnicastTransport::init_in(
            &mut place,
            times(),
            1,
            SessionTimeouts::from_build(),
            |_slot| other,
        )
        .is_none());
    }

    /// What the owner reports about the link moves the transport's one link: an open dials the
    /// first endpoint, and a session with none to dial ends. Turned red by an input that does not
    /// reach the link, or reaches a link of another number of endpoints.
    #[test]
    fn the_owners_report_moves_the_transports_one_link() {
        let mut place = MaybeUninit::<UnicastTransport<()>>::uninit();
        let transport = UnicastTransport::init_in(
            &mut place,
            times(),
            1,
            SessionTimeouts::from_build(),
            |slot| slot.write(()),
        )
        .expect("built");
        let opened = transport.input(LinkInput::Open, 0);
        assert_eq!(opened.dial(), Some(0), "an open dials the first endpoint");
        assert_eq!(transport.life().phase(), LinkPhase::Dialing { row: 0 });

        let mut none_place = MaybeUninit::<UnicastTransport<()>>::uninit();
        let none = UnicastTransport::init_in(
            &mut none_place,
            times(),
            0,
            SessionTimeouts::from_build(),
            |slot| slot.write(()),
        )
        .expect("built");
        assert!(
            none.input(LinkInput::Open, 0).ends_session(),
            "a session with no endpoint ends at its open"
        );
        assert_eq!(none.life().phase(), LinkPhase::Closed);
    }

    /// The drive of an established link stopped at its cap leaves the link up, and one that ended
    /// loses it and dials the first endpoint again at once. Turned red by an outcome that does not
    /// reach the link, or by a cap read as an end.
    #[test]
    fn the_end_of_a_drive_loses_the_link_and_a_cap_leaves_it_up() {
        let mut place = MaybeUninit::<UnicastTransport<()>>::uninit();
        let transport = UnicastTransport::init_in(
            &mut place,
            times(),
            1,
            SessionTimeouts::from_build(),
            |slot| slot.write(()),
        )
        .expect("built");
        assert_eq!(transport.input(LinkInput::Open, 0).dial(), Some(0));
        assert!(transport.input(LinkInput::DialMade, 0).begin_handshake());
        assert!(transport.input(LinkInput::HandshakeBegun, 0).is_empty());
        assert!(transport.input(LinkInput::Established, 0).bring_up());
        assert_eq!(transport.life().phase(), LinkPhase::Up);

        assert!(transport
            .pumped(DriverOutcome::IterationLimit, 1_000)
            .is_empty());
        assert_eq!(
            transport.life().phase(),
            LinkPhase::Up,
            "a cap is not an end"
        );

        let ended = transport.pumped(DriverOutcome::Terminated, 2_000);
        assert!(ended.lose(), "the established link is lost");
        assert_eq!(
            ended.dial(),
            Some(0),
            "and the first endpoint dialled at once"
        );
        assert_eq!(transport.life().phase(), LinkPhase::Dialing { row: 0 });
    }

    /// A transport over a link handed to it made holds the Router its maker wrote and has nothing
    /// of the link to look at. Turned red by a made link that names a wake of its own.
    #[test]
    fn a_transport_over_a_made_link_holds_its_makers_router_and_no_wake() {
        let mut place = MaybeUninit::<UnicastTransport<u32, MadeLink>>::uninit();
        let transport =
            UnicastTransport::init_made_in(&mut place, SessionTimeouts::from_build(), |slot| {
                slot.write(5)
            })
            .expect("a maker that writes its own place builds the transport");
        assert_eq!(*transport.rx().router(), 5);
        assert_eq!(MadeLink.wake_at(0), None);
        assert_eq!(MadeLink.wake_at(u64::MAX), None);
    }

    /// A maker that lends back a place other than the one it was handed builds no transport over a
    /// made link either.
    #[test]
    fn a_maker_that_lends_back_another_place_builds_no_transport_over_a_made_link() {
        let mut place = MaybeUninit::<UnicastTransport<u32, MadeLink>>::uninit();
        let other: &'static mut u32 = std::boxed::Box::leak(std::boxed::Box::new(9));
        assert!(UnicastTransport::init_made_in(
            &mut place,
            SessionTimeouts::from_build(),
            |_slot| { other }
        )
        .is_none());
    }

    /// The wake a transport reads of its life is the link's own: none while the link is idle, and
    /// at once when a dial it asked for is owed a report. Turned red by a reading of the life that
    /// answers other than `UnicastLink::wake_at`.
    #[test]
    fn the_wake_a_transport_reads_of_its_life_is_the_links_own() {
        let mut place = MaybeUninit::<UnicastTransport<()>>::uninit();
        let transport = UnicastTransport::init_in(
            &mut place,
            times(),
            1,
            SessionTimeouts::from_build(),
            |slot| slot.write(()),
        )
        .expect("built");
        assert_eq!(LinkWake::wake_at(transport.life(), 0), None, "idle");
        assert_eq!(transport.input(LinkInput::Open, 0).dial(), Some(0));
        assert_eq!(
            LinkWake::wake_at(transport.life(), 0),
            transport.life().wake_at(0)
        );
        assert_eq!(
            LinkWake::wake_at(transport.life(), 0),
            Some(0),
            "a dial owed a report is looked at now"
        );
    }
}

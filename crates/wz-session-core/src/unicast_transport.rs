// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The unicast transport of a session that holds one face, as one value ([`UnicastTransport`]):
//! the life of its link ([`UnicastLink`]), the receive of the session that runs over it
//! ([`UnicastRx`]) and that session's timers ([`TransportTimers`]).
//!
//! Its owner holds the I/O and the wait, and hands this value what happened: the link's dials and
//! handshakes as inputs ([`UnicastTransport::input`], [`UnicastTransport::pumped`]), a datagram
//! the link read ([`UnicastTransport::on_datagram`]) and the time
//! ([`UnicastTransport::on_time`]). It asks when to look again ([`UnicastTransport::due_ms`]),
//! the first of what the link and the session have due. Every order that matters (what is raised
//! before a datagram is read, and that the lease is judged after it) is written once, here, so
//! two owners of a transport cannot keep it in two orders.
//!
//! The session's machine and its actions are lent to each call and not held: the machine is the
//! session's, built anew for each link its life brings up, and the actions are reached through the
//! place the session's transport lies in ([`crate::transport_place::TransportPlace`]).
//!
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
use crate::link::SessionRuntime;
use crate::link_life::{Effects, LinkInput, LinkTimes, UnicastLink};
use crate::session_actions::SessionLinkActions;
use crate::session_timeouts::SessionTimeouts;
use crate::transport_timers::TransportTimers;
use crate::unicast_rx::{RxReassembly, UnicastRx};

/// The unicast transport of a session that holds one face. See the module documentation.
pub struct UnicastTransport<Router> {
    life: UnicastLink,
    rx: UnicastRx<Router>,
    timers: TransportTimers,
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
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self` (it is `place`), and the receive's field is
        // lent as the uninitialised place `MaybeUninit<UnicastRx<Router>>` lays out as a
        // `UnicastRx<Router>`.
        let rx = unsafe { &mut *addr_of_mut!((*at).rx).cast::<MaybeUninit<UnicastRx<Router>>>() };
        UnicastRx::init_in(rx, make_router)?;
        // SAFETY: the receive is written. The link is built in its own field, lent as the
        // uninitialised place of a `UnicastLink`, and the timers are written once in theirs; then
        // every field is written and the transport is whole.
        unsafe {
            UnicastLink::init_in(
                &mut *addr_of_mut!((*at).life).cast::<MaybeUninit<UnicastLink>>(),
                times,
                endpoints,
            );
            addr_of_mut!((*at).timers).write(TransportTimers::new(timeouts));
            Some(place.assume_init_mut())
        }
    }

    /// The link's life: where it stands, and when it is next to be looked at.
    pub fn life(&self) -> &UnicastLink {
        &self.life
    }

    /// The receive of the session the link carries.
    pub fn rx(&self) -> &UnicastRx<Router> {
        &self.rx
    }

    /// What `input` about the link, reported at `now_us`, comes to ([`UnicastLink::input`]).
    pub fn input(&mut self, input: LinkInput, now_us: u64) -> Effects {
        self.life.input(input, now_us)
    }

    /// What the end of the session's drive came to, for the link ([`UnicastLink::pumped`]).
    pub fn pumped(&mut self, outcome: DriverOutcome, now_us: u64) -> Effects {
        self.life.pumped(outcome, now_us)
    }

    /// The first instant, in the session's monotonic milliseconds, at which the transport is to be
    /// looked at again though no input came: the link's next look ([`UnicastLink::wake_at`],
    /// rounded up to the millisecond, so a look is never early) or the first of the session's
    /// timers ([`TransportTimers::next_due_ms`]), whichever is sooner. `None` when neither has
    /// one. A state of the machine the timers see for the first time has its handshake deadline
    /// armed from `now_ms`.
    pub fn due_ms<R: SessionRuntime, T: TimeSource>(
        &mut self,
        engine: &SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
    ) -> Option<u64> {
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
        self.raise_before_input(actions, now_ms, &mut *on_event);
        self.timers.fire_due(engine, actions, now_ms, on_event);
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
        self.raise_before_input(actions, now_ms, &mut *on_event);
        let path = self
            .rx
            .dispatch_datagram(unit, actions, engine, now_ms, &mut *on_event);
        self.timers.fire_due(engine, actions, now_ms, on_event);
        path
    }

    /// What is raised at `now_ms` before input is read, so a stream of input cannot hold it off.
    fn raise_before_input<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        &mut self,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut F,
    ) {
        if actions.take_app_wake_due(now_ms) {
            on_event.event(IterationEvent::AppWake);
        }
        self.rx.sweep(now_ms, on_event);
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
}

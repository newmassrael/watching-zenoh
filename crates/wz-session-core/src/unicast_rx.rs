// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The receive half of a unicast session's transport, as one value the session core owns: the
//! reassembly Router its fragments are staged in, and, for a receive in place (`rx-in-place`),
//! the one-record buffer each record is decoded into and the count of the paths its units took.
//!
//! A driver holds a [`UnicastRx`] beside the session's engine and hands it what its link gave
//! (the bytes a link lends, or a frame it read) and the time; it keeps no state of the receive
//! between two datagrams. Every step of the receive is written once, here, so a driver is its
//! wait and its link and nothing of the protocol (docs/c-abi-architecture.md, P2).
//!
//! The methods that dispatch are never inlined: a driver that is a task polls them from its
//! `poll`, and inlined they made that `poll` the size of the whole receive, once per driver type.

use core::mem::MaybeUninit;

#[cfg(any(feature = "alloc", feature = "rx-in-place"))]
use wz_runtime_core::TimeSource;

#[cfg(feature = "reassembly")]
use crate::chain_staging::ChainStaging;
#[cfg(any(feature = "alloc", feature = "rx-in-place"))]
use crate::drive::SessionEngine;
#[cfg(feature = "rx-in-place")]
use crate::drive::{CopyReason, DatagramPath};
#[cfg(feature = "alloc")]
use crate::driver_loop::DriverLoopOutcome;
use crate::driver_loop::EventSink;
#[cfg(feature = "reassembly")]
use crate::driver_loop::IterationEvent;
#[cfg(any(feature = "alloc", feature = "rx-in-place"))]
use crate::link::SessionRuntime;
#[cfg(feature = "alloc")]
use crate::link::{LinkEvent, RxFrame};
#[cfg(feature = "rx-in-place")]
use crate::network_message::{new_record_buf, RecordBuf};
#[cfg(feature = "reassembly")]
use crate::reassembly_dispatch::ReassemblyDispatcher;
#[cfg(any(feature = "alloc", feature = "rx-in-place"))]
use crate::session_actions::SessionLinkActions;

/// What a unicast receive stages its fragments in: a reassembly Router (`ReassemblyDispatcher`,
/// whatever arena its chains stage into), or `()` for a receive that rejoins no fragment.
pub trait RxReassembly {
    /// End the chains past their deadline at `now_ms`, telling `on_event` how many.
    fn sweep_chains(&mut self, now_ms: u64, on_event: &mut dyn EventSink);

    /// Report `outcome`, one of the copying receive, through the reassembly: the fragment it
    /// carries is staged, a chain it completes is reported after it, and a channel-gate rejection
    /// clears its channel's chain.
    #[cfg(feature = "alloc")]
    fn report_copied<R: SessionRuntime, T: TimeSource>(
        &mut self,
        outcome: &DriverLoopOutcome,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    );

    /// Report `outcome`, one of what a receive in place parked (the rest of a compressed batch),
    /// through the reassembly.
    #[cfg(all(feature = "alloc", feature = "rx-in-place"))]
    fn report_parked<R: SessionRuntime, T: TimeSource>(
        &mut self,
        outcome: &DriverLoopOutcome,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    );

    /// Dispatch one datagram where the link holds it, its fragments staged here.
    #[cfg(feature = "rx-in-place")]
    fn dispatch_in_place<R: SessionRuntime, T: TimeSource>(
        &mut self,
        unit: &[u8],
        actions: &SessionLinkActions<R, T>,
        engine: &mut SessionEngine<R, T>,
        record: &mut RecordBuf,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) -> DatagramPath;
}

/// A receive that rejoins no fragment: every outcome is reported as it is, and a fragment is
/// handed up by the copying path, for a caller that reassembles to take.
impl RxReassembly for () {
    fn sweep_chains(&mut self, _now_ms: u64, _on_event: &mut dyn EventSink) {}

    #[cfg(feature = "alloc")]
    fn report_copied<R: SessionRuntime, T: TimeSource>(
        &mut self,
        outcome: &DriverLoopOutcome,
        _actions: &SessionLinkActions<R, T>,
        _now_ms: u64,
        on_event: &mut dyn EventSink,
    ) {
        on_event.event(crate::driver_loop::IterationEvent::Poll(outcome));
    }

    #[cfg(all(feature = "alloc", feature = "rx-in-place"))]
    fn report_parked<R: SessionRuntime, T: TimeSource>(
        &mut self,
        outcome: &DriverLoopOutcome,
        _actions: &SessionLinkActions<R, T>,
        _now_ms: u64,
        on_event: &mut dyn EventSink,
    ) {
        on_event.event(crate::driver_loop::IterationEvent::Poll(outcome));
    }

    #[cfg(feature = "rx-in-place")]
    fn dispatch_in_place<R: SessionRuntime, T: TimeSource>(
        &mut self,
        unit: &[u8],
        actions: &SessionLinkActions<R, T>,
        engine: &mut SessionEngine<R, T>,
        record: &mut RecordBuf,
        _now_ms: u64,
        on_event: &mut dyn EventSink,
    ) -> DatagramPath {
        crate::drive::dispatch_datagram(unit, actions, engine, record, on_event)
    }
}

#[cfg(feature = "reassembly")]
impl<const SLOTS: usize, const CAP: usize, S> RxReassembly for ReassemblyDispatcher<SLOTS, CAP, S>
where
    S: ChainStaging<SLOTS, CAP>,
{
    fn sweep_chains(&mut self, now_ms: u64, on_event: &mut dyn EventSink) {
        let mut forward = |event: IterationEvent<'_, '_>| on_event.event(event);
        crate::reassembly_dispatch::sweep_reporting(self, now_ms, &mut forward);
    }

    #[cfg(feature = "alloc")]
    fn report_copied<R: SessionRuntime, T: TimeSource>(
        &mut self,
        outcome: &DriverLoopOutcome,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) {
        // One observer type for both reports, so the report a receive in place reaches through a
        // compressed batch is the same instance (`report_outcome_in_place`).
        let forward: &mut dyn FnMut(IterationEvent<'_, '_>) =
            &mut |event: IterationEvent<'_, '_>| on_event.event(event);
        crate::drive::report_outcome_reassembling(outcome, self, actions, now_ms, forward);
    }

    #[cfg(all(feature = "alloc", feature = "rx-in-place"))]
    fn report_parked<R: SessionRuntime, T: TimeSource>(
        &mut self,
        outcome: &DriverLoopOutcome,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) {
        // The observer type the reassembling dispatch's hand-off reports through too, so the two
        // reach one instance of the report.
        let forward: &mut dyn FnMut(IterationEvent<'_, '_>) =
            &mut |event: IterationEvent<'_, '_>| on_event.event(event);
        crate::drive::report_outcome_in_place(outcome, self, actions, now_ms, forward);
    }

    #[cfg(feature = "rx-in-place")]
    fn dispatch_in_place<R: SessionRuntime, T: TimeSource>(
        &mut self,
        unit: &[u8],
        actions: &SessionLinkActions<R, T>,
        engine: &mut SessionEngine<R, T>,
        record: &mut RecordBuf,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) -> DatagramPath {
        crate::drive::dispatch_datagram_reassembling(
            unit, actions, engine, record, self, now_ms, on_event,
        )
    }
}

/// The units a receive in place dispatched, by the path they took
/// (`crate::drive::dispatch_datagram`): read in place as a `Frame`, a `Fragment` or a lean
/// batch, or not read as one, for one of the documented reasons. A unit of the second kind is not
/// lost: it is read where the link holds it as one transport message (a compressed batch is
/// copied and inflated), and this is where a profile sees how often that happens.
#[cfg(feature = "rx-in-place")]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RxPathCounts {
    /// Units that began with an admissible `Frame`, read in place.
    pub in_place: u32,
    /// Admissible `Fragment`s, staged into their reassembly slots from where the link held them
    /// (`reassembly`).
    pub fragment_in_place: u32,
    /// Lean lowlatency units (a bare network message batch), read in place.
    pub low_latency_in_place: u32,
    /// Compressed batches.
    pub compressed: u32,
    /// `Fragment`s on a session that does not reassemble.
    pub fragment: u32,
    /// `Fragment`s whose own extension chain a participant must refuse.
    pub fragment_ext_refused: u32,
    /// `Fragment`s whose head does not decode.
    pub fragment_head_undecodable: u32,
    /// Handshake, KeepAlive, Close and every other non-`Frame` unit.
    pub not_a_frame: u32,
    /// `Frame`s whose own extension chain a participant must refuse.
    pub frame_ext_refused: u32,
    /// `Frame`s whose head does not decode.
    pub frame_head_undecodable: u32,
}

#[cfg(feature = "rx-in-place")]
impl RxPathCounts {
    /// Count one unit that took `path`.
    pub fn count(&mut self, path: DatagramPath) {
        let slot = match path {
            DatagramPath::InPlace => &mut self.in_place,
            DatagramPath::FragmentInPlace => &mut self.fragment_in_place,
            DatagramPath::LowLatencyInPlace => &mut self.low_latency_in_place,
            DatagramPath::Copied(CopyReason::Compressed) => &mut self.compressed,
            DatagramPath::Copied(CopyReason::Fragment) => &mut self.fragment,
            DatagramPath::Copied(CopyReason::FragmentExtRefused) => &mut self.fragment_ext_refused,
            DatagramPath::Copied(CopyReason::FragmentHeadUndecodable) => {
                &mut self.fragment_head_undecodable
            }
            DatagramPath::Copied(CopyReason::NotAFrame) => &mut self.not_a_frame,
            DatagramPath::Copied(CopyReason::FrameExtRefused) => &mut self.frame_ext_refused,
            DatagramPath::Copied(CopyReason::FrameHeadUndecodable) => {
                &mut self.frame_head_undecodable
            }
        };
        *slot = slot.saturating_add(1);
    }

    /// Every unit that went down the copying path, whatever the reason.
    pub fn copied(&self) -> u32 {
        [
            self.compressed,
            self.fragment,
            self.fragment_ext_refused,
            self.fragment_head_undecodable,
            self.not_a_frame,
            self.frame_ext_refused,
            self.frame_head_undecodable,
        ]
        .into_iter()
        .fold(0u32, u32::saturating_add)
    }
}

/// The receive half of one unicast session's transport. See the module documentation.
pub struct UnicastRx<Router> {
    router: Router,
    /// The one record an inbound record is decoded into and dispatched from, made once with the
    /// receive: a datagram costs it nothing however many records it carries.
    #[cfg(feature = "rx-in-place")]
    record: RecordBuf,
    #[cfg(feature = "rx-in-place")]
    paths: RxPathCounts,
}

impl<Router> UnicastRx<Router> {
    /// A receive that stages its fragments in `router`, with nothing read yet.
    pub fn new(router: Router) -> Self {
        Self {
            router,
            #[cfg(feature = "rx-in-place")]
            record: new_record_buf(),
            #[cfg(feature = "rx-in-place")]
            paths: RxPathCounts::default(),
        }
    }

    /// [`Self::new`] built in `place` and lent back, its Router written in its own field by
    /// `make_router`: a Router of kilobytes (one slot machine per slot) is then never a value on
    /// a stack on the way to the place its session keeps it in.
    ///
    /// `make_router` writes the Router in the place it is handed and lends it back, which safe
    /// code does only by writing it there (`MaybeUninit::write`). One that lends back anything
    /// else has written no Router in this receive, which is answered `None`: `place` then holds
    /// no receive, and nothing in it is dropped. `place` is overwritten without dropping what it
    /// held.
    pub fn init_in<'a>(
        place: &'a mut MaybeUninit<Self>,
        make_router: impl FnOnce(&mut MaybeUninit<Router>) -> &mut Router,
    ) -> Option<&'a mut Self> {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self` (it is `place`), and the Router's field is
        // lent as the uninitialised place `MaybeUninit<Router>` lays out as a `Router`.
        let router =
            unsafe { &mut *core::ptr::addr_of_mut!((*at).router).cast::<MaybeUninit<Router>>() };
        let field: *const Router = router.as_ptr();
        let made: *const Router = make_router(router);
        if !core::ptr::eq(made, field) {
            return None;
        }
        // SAFETY: the Router is written (the maker lent back its own field as a `Router`), each
        // other field is written once below through its own address, and then every field is.
        unsafe {
            #[cfg(feature = "rx-in-place")]
            core::ptr::addr_of_mut!((*at).record).write(new_record_buf());
            #[cfg(feature = "rx-in-place")]
            core::ptr::addr_of_mut!((*at).paths).write(RxPathCounts::default());
            Some(place.assume_init_mut())
        }
    }

    /// The Router this receive stages its fragments in.
    pub fn router(&self) -> &Router {
        &self.router
    }

    /// The units this receive dispatched in place so far, by the path they took.
    #[cfg(feature = "rx-in-place")]
    pub fn path_counts(&self) -> RxPathCounts {
        self.paths
    }
}

impl<Router: RxReassembly> UnicastRx<Router> {
    /// End the fragment chains past their deadline at `now_ms`, telling `on_event` how many
    /// (`IterationEvent::ReassemblyTimeout`). A receive that rejoins no fragment has none.
    #[inline(never)]
    pub fn sweep(&mut self, now_ms: u64, on_event: &mut dyn EventSink) {
        self.router.sweep_chains(now_ms, on_event);
    }

    /// The copying receive's rest of a batch it parked, if any, dispatched and reported through
    /// the reassembly (`crate::drive::dispatch_pending`): whether there was one. A driver asks
    /// this before it reads its link, so a batch of two messages does not wait for the peer.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn dispatch_pending<R: SessionRuntime, T: TimeSource>(
        &mut self,
        actions: &SessionLinkActions<R, T>,
        engine: &mut SessionEngine<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) -> bool {
        match crate::drive::dispatch_pending(actions, engine) {
            Some(outcome) => {
                self.router
                    .report_copied(&outcome, actions, now_ms, on_event);
                true
            }
            None => false,
        }
    }

    /// One datagram the copying receive read, dispatched and reported through the reassembly.
    #[cfg(feature = "alloc")]
    #[inline(never)]
    pub fn dispatch_frame<R: SessionRuntime, T: TimeSource>(
        &mut self,
        frame: RxFrame,
        actions: &SessionLinkActions<R, T>,
        engine: &mut SessionEngine<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) {
        let outcome = crate::drive::dispatch_link_event(LinkEvent::Rx(frame), actions, engine);
        self.router
            .report_copied(&outcome, actions, now_ms, on_event);
    }

    /// What a receive in place parked (the rest of a compressed batch, inflated into a buffer of
    /// its own), if anything, dispatched and reported through the reassembly
    /// (`crate::drive::dispatch_parked_in_place`): whether there was any.
    #[cfg(all(feature = "alloc", feature = "rx-in-place"))]
    #[inline(never)]
    pub fn dispatch_parked_in_place<R: SessionRuntime, T: TimeSource>(
        &mut self,
        actions: &SessionLinkActions<R, T>,
        engine: &mut SessionEngine<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) -> bool {
        match crate::drive::dispatch_parked_in_place(actions, engine) {
            Some(outcome) => {
                self.router
                    .report_parked(&outcome, actions, now_ms, on_event);
                true
            }
            None => false,
        }
    }

    /// One datagram dispatched where the link holds it, record by record, its fragments staged
    /// into this receive's Router (`crate::drive::dispatch_datagram` and its reassembling form),
    /// and the path it took counted. `on_event` runs inside the link's lend.
    #[cfg(feature = "rx-in-place")]
    #[inline(never)]
    pub fn dispatch_datagram<R: SessionRuntime, T: TimeSource>(
        &mut self,
        unit: &[u8],
        actions: &SessionLinkActions<R, T>,
        engine: &mut SessionEngine<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) -> DatagramPath {
        let path = self.router.dispatch_in_place(
            unit,
            actions,
            engine,
            &mut self.record,
            now_ms,
            on_event,
        );
        self.paths.count(path);
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver_loop::IterationEvent;

    /// A receive built in its place holds the Router its maker wrote there, with nothing read.
    #[test]
    fn a_receive_built_in_place_holds_the_router_its_maker_wrote() {
        let mut place = MaybeUninit::<UnicastRx<u32>>::uninit();
        let rx = UnicastRx::init_in(&mut place, |slot| slot.write(7)).expect("written in place");
        assert_eq!(*rx.router(), 7);
        #[cfg(feature = "rx-in-place")]
        assert_eq!(rx.path_counts(), RxPathCounts::default());
    }

    /// A maker that lends back a place other than the one it was handed wrote no Router in the
    /// receive, and is refused rather than read.
    #[test]
    fn a_maker_that_lends_back_another_place_is_refused() {
        let mut place = MaybeUninit::<UnicastRx<u32>>::uninit();
        let other: &'static mut u32 = std::boxed::Box::leak(std::boxed::Box::new(9));
        assert!(UnicastRx::init_in(&mut place, |_slot| other).is_none());
    }

    /// A receive that rejoins no fragment has no chain to end.
    #[test]
    fn a_receive_without_a_router_sweeps_nothing() {
        let mut rx = UnicastRx::new(());
        let mut events = 0usize;
        rx.sweep(u64::MAX, &mut |_event: IterationEvent<'_, '_>| events += 1);
        assert_eq!(events, 0);
    }

    /// The sweep of a receive ends the chains past their deadline and says how many, and ends
    /// none before it.
    #[cfg(feature = "reassembly")]
    #[test]
    fn the_sweep_ends_a_chain_past_its_deadline_and_says_so() {
        use crate::reassembly_dispatch::{Fragment, ReassemblyConfig};
        const TIMEOUT_MS: u64 = 500;
        let mut router: ReassemblyDispatcher<2, 64> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, TIMEOUT_MS));
        router.ingest(
            Fragment {
                peer_key: &[0x11; 16],
                reliable: true,
                sn: 1,
                more: 1,
                payload: b"part",
                priority: crate::qos::Priority::DEFAULT,
                markers: crate::extfragment::FragmentMarkers::NONE,
            },
            crate::sn::mask_from_res(0x02),
            0,
            |_| {},
        );
        let mut rx = UnicastRx::new(router);
        let mut ended = None;
        let mut events = 0usize;
        rx.sweep(TIMEOUT_MS - 1, &mut |_event: IterationEvent<'_, '_>| {
            events += 1
        });
        assert_eq!(events, 0, "not yet due");
        rx.sweep(TIMEOUT_MS, &mut |event: IterationEvent<'_, '_>| {
            if let IterationEvent::ReassemblyTimeout(count) = event {
                ended = Some(count);
            }
        });
        assert_eq!(ended, Some(1));
        assert_eq!(rx.router().active_chains(), 0);
    }

    /// Each path a unit takes is counted under its own name, and the copied total is the sum of
    /// the copying reasons alone.
    #[cfg(feature = "rx-in-place")]
    #[test]
    fn each_path_is_counted_under_its_own_name() {
        let mut counts = RxPathCounts::default();
        counts.count(DatagramPath::InPlace);
        counts.count(DatagramPath::InPlace);
        counts.count(DatagramPath::FragmentInPlace);
        counts.count(DatagramPath::LowLatencyInPlace);
        counts.count(DatagramPath::Copied(CopyReason::NotAFrame));
        counts.count(DatagramPath::Copied(CopyReason::Compressed));
        counts.count(DatagramPath::Copied(CopyReason::FrameHeadUndecodable));
        assert_eq!(counts.in_place, 2);
        assert_eq!(counts.fragment_in_place, 1);
        assert_eq!(counts.low_latency_in_place, 1);
        assert_eq!(counts.not_a_frame, 1);
        assert_eq!(counts.compressed, 1);
        assert_eq!(counts.frame_head_undecodable, 1);
        assert_eq!(counts.fragment, 0);
        assert_eq!(counts.copied(), 3);
        let full = RxPathCounts {
            in_place: u32::MAX,
            ..RxPathCounts::default()
        };
        let mut saturated = full;
        saturated.count(DatagramPath::InPlace);
        assert_eq!(saturated, full, "a count that is full stays full");
    }
}

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
    /// Whether a receive may take input now: a Router lent to the receive for the length of its
    /// session's step ([`RouterLend`]) answers whether it is lent, so a receive outside the step
    /// takes nothing it could not stage. The provided form, a Router of the receive's own or
    /// none, always may.
    fn ready(&self) -> bool {
        true
    }

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

/// A session's one reassembly Router, lent to its links' receives for the length of a step: the
/// session owns the Router by value and keeps one table of chain slots, not one for each link, as
/// its chains' buffers are one table already; the step that runs the links' tasks lends it
/// ([`Self::lend_for`]), so no receive holds it past a step and none holds it beside another. A
/// chain is keyed by its peer (`Fragment::peer_key`, the peer's zid on a unicast link) as well
/// as its channel, so the links' chains never meet, and the per-peer quota keeps one peer from
/// taking the others' slots; what a link sets on the Router before an ingest (its negotiated
/// fragment markers, the session's message bound) is set in the same call, so a chain is read
/// under its own link's rules.
///
/// A receive's task cannot be handed a borrow (an executor polls it with nothing but its
/// context), so the lend is a place the task looks in: each call takes the Router out for its own
/// length and puts it back. A receive asks [`RxReassembly::ready`] before it takes input, which
/// is `false` outside a step and inside another receive's call, so it never takes a unit it
/// could not stage; a call made anyway does nothing with the Router.
#[cfg(feature = "alloc")]
pub struct RouterLend<D>(alloc::rc::Rc<core::cell::Cell<Option<core::ptr::NonNull<D>>>>);

#[cfg(feature = "alloc")]
impl<D> RouterLend<D> {
    /// A place nothing is lent in yet.
    pub fn new() -> Self {
        Self(alloc::rc::Rc::new(core::cell::Cell::new(None)))
    }

    /// Lend `router` to every receive that holds this place for the length of `f`, and take it
    /// back when `f` returns or unwinds. The owner holds `router` borrowed for as long, so it
    /// neither reads nor moves it meanwhile.
    pub fn lend_for<T>(&self, router: &mut D, f: impl FnOnce() -> T) -> T {
        /// Puts back what the place held before, however `f` ends.
        struct Restore<'a, D> {
            place: &'a core::cell::Cell<Option<core::ptr::NonNull<D>>>,
            was: Option<core::ptr::NonNull<D>>,
        }
        impl<D> Drop for Restore<'_, D> {
            fn drop(&mut self) {
                self.place.set(self.was);
            }
        }
        let _restore = Restore {
            place: &self.0,
            was: self.0.replace(Some(core::ptr::NonNull::from(router))),
        };
        f()
    }

    /// Whether the Router is lent here now, and not taken out by a call.
    pub fn is_lent(&self) -> bool {
        self.0.get().is_some()
    }

    /// Run `f` on the Router while it is lent here, taking it out for the length of `f`; `None`,
    /// with `f` not run, while it is not.
    pub fn with<T>(&self, f: impl FnOnce(&mut D) -> T) -> Option<T> {
        let mut taken = self.0.take()?;
        /// Puts the Router back in its place, however `f` ends.
        struct PutBack<'a, D> {
            place: &'a core::cell::Cell<Option<core::ptr::NonNull<D>>>,
            router: core::ptr::NonNull<D>,
        }
        impl<D> Drop for PutBack<'_, D> {
            fn drop(&mut self) {
                self.place.set(Some(self.router));
            }
        }
        let _back = PutBack {
            place: &self.0,
            router: taken,
        };
        // SAFETY: the pointer was set by `lend_for` from a `&mut D` its caller holds borrowed for
        // the whole of the lend, which has not ended, since `lend_for` takes it back only after
        // its `f` returns, and this call runs inside it. It was taken out of the place, so no
        // other call reaches it until `PutBack` returns it: this is the one reference to the
        // Router while `f` runs.
        Some(f(unsafe { taken.as_mut() }))
    }
}

#[cfg(feature = "alloc")]
impl<D> Default for RouterLend<D> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl<D> Clone for RouterLend<D> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(feature = "alloc")]
impl<D: RxReassembly> RxReassembly for RouterLend<D> {
    fn ready(&self) -> bool {
        self.is_lent()
    }

    // The session sweeps the Router it owns once a step, with nothing lent.
    fn sweep_chains(&mut self, _now_ms: u64, _on_event: &mut dyn EventSink) {}

    fn report_copied<R: SessionRuntime, T: TimeSource>(
        &mut self,
        outcome: &DriverLoopOutcome,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) {
        let reported = self.with(|router| router.report_copied(outcome, actions, now_ms, on_event));
        if reported.is_none() {
            ().report_copied(outcome, actions, now_ms, on_event);
        }
    }

    #[cfg(feature = "rx-in-place")]
    fn report_parked<R: SessionRuntime, T: TimeSource>(
        &mut self,
        outcome: &DriverLoopOutcome,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) {
        let reported = self.with(|router| router.report_parked(outcome, actions, now_ms, on_event));
        if reported.is_none() {
            ().report_parked(outcome, actions, now_ms, on_event);
        }
    }

    // A unit that finds no Router lent is not read, never through `()`'s dispatch, which hands a
    // fragment to the copying path's owned decode that a build reassembling in place does not
    // link; a receive asks `ready` before it takes input, so the arm is the totality answer, and
    // counted so that a test sees it never runs.
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
        self.with(|router| {
            router.dispatch_in_place(unit, actions, engine, record, now_ms, on_event)
        })
        .unwrap_or(DatagramPath::RouterHeld)
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
    /// Units not read at all, the Router the session's links share being held by another receive
    /// (`DatagramPath::RouterHeld`), which a session's one task never makes.
    pub router_held: u32,
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
            DatagramPath::RouterHeld => &mut self.router_held,
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
    pub fn init_in(
        place: &mut MaybeUninit<Self>,
        make_router: impl FnOnce(&mut MaybeUninit<Router>) -> &mut Router,
    ) -> Option<&mut Self> {
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
    /// Whether this receive may take input now ([`RxReassembly::ready`]): a driver asks before it
    /// reads its link, so a unit its Router could not stage is left with the link and not read
    /// and thrown away.
    pub fn ready(&self) -> bool {
        self.router.ready()
    }

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

    /// A lent Router is reached inside the lend alone, by one call at a time: outside it no call
    /// reaches it; inside it a call takes it out for its own length, so a call made meanwhile
    /// (from inside the first) finds nothing and runs nothing; and once the lend ends the owner
    /// holds it again, with what the call did to it.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_lent_router_is_reached_inside_the_lend_alone_and_by_one_call_at_a_time() {
        let lend = RouterLend::<u32>::new();
        let link = lend.clone();
        assert!(!lend.is_lent());
        assert_eq!(
            link.with(|router| *router),
            None,
            "no Router outside a lend"
        );
        let mut router = 7u32;
        let seen = lend.lend_for(&mut router, || {
            assert!(link.is_lent(), "every handle sees the lend");
            link.with(|outer| {
                *outer += 1;
                assert!(!lend.is_lent(), "taken out for the call");
                assert_eq!(
                    lend.with(|inner| *inner),
                    None,
                    "a second call cannot reach it"
                );
                *outer
            })
        });
        assert_eq!(seen, Some(8));
        assert!(!lend.is_lent(), "back with its owner once the lend ends");
        assert_eq!(router, 8, "with what the call did to it");
    }

    /// A receive over a lend takes input only while its Router is lent: outside its session's
    /// step it answers that it is not ready, so its driver reads nothing from the link. A receive
    /// over a Router of its own is always ready.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_receive_over_a_lend_takes_input_only_inside_the_lend() {
        let lend = RouterLend::<()>::new();
        let rx = UnicastRx::new(lend.clone());
        assert!(!rx.ready(), "outside a step the receive takes no input");
        let mut router = ();
        lend.lend_for(&mut router, || {
            assert!(rx.ready(), "inside the lend it does")
        });
        assert!(!rx.ready(), "and not after it");
        assert!(
            UnicastRx::new(()).ready(),
            "a Router of its own is always there"
        );
    }

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

    /// A receive over a lent Router ends no chain when it sweeps, past the chain's deadline and
    /// inside the lend too: the session that owns the Router sweeps it, and that sweep ends it.
    #[cfg(all(feature = "reassembly", feature = "alloc"))]
    #[test]
    fn a_receive_over_a_lent_router_leaves_the_sweep_to_the_session() {
        use crate::reassembly_dispatch::{Fragment, IngestOutcome, ReassemblyConfig};
        const TIMEOUT_MS: u64 = 500;
        let mut router: ReassemblyDispatcher<2, 64> =
            ReassemblyDispatcher::new(ReassemblyConfig::new(2, TIMEOUT_MS));
        let begun = router.ingest(
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
        assert_eq!(begun, IngestOutcome::Begun);
        let lend = RouterLend::new();
        let mut rx = UnicastRx::new(lend.clone());
        let mut events = 0usize;
        lend.lend_for(&mut router, || {
            rx.sweep(TIMEOUT_MS, &mut |_event: IterationEvent<'_, '_>| {
                events += 1
            });
        });
        assert_eq!(events, 0, "the link's receive sweeps nothing");
        assert_eq!(router.active_chains(), 1);
        assert_eq!(router.sweep(TIMEOUT_MS), 1);
        assert_eq!(router.active_chains(), 0);
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
        counts.count(DatagramPath::RouterHeld);
        assert_eq!(counts.in_place, 2);
        assert_eq!(counts.fragment_in_place, 1);
        assert_eq!(counts.low_latency_in_place, 1);
        assert_eq!(counts.not_a_frame, 1);
        assert_eq!(counts.compressed, 1);
        assert_eq!(counts.frame_head_undecodable, 1);
        assert_eq!(counts.fragment, 0);
        assert_eq!(
            counts.router_held, 1,
            "a unit no Router could take is its own count"
        );
        assert_eq!(counts.copied(), 3, "and is not one the copying path took");
        let full = RxPathCounts {
            in_place: u32::MAX,
            ..RxPathCounts::default()
        };
        let mut saturated = full;
        saturated.count(DatagramPath::InPlace);
        assert_eq!(saturated, full, "a count that is full stays full");
    }
}

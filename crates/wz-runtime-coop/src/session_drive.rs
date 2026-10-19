// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cooperative unicast session drive loop, over any datagram link.
//!
//! The MCU analog of `wz_runtime_tokio::session_glue::drive_session_until_terminal`,
//! minus the `tokio::select!`: a cooperative single-task polling loop. Every
//! decision PRIMITIVE is the shared `wz_session_core` SSOT — this module is
//! only the loop STRUCTURE that sequences them:
//!
//! - inbound: [`SessionDatagramLink::try_recv`] ->
//!   [`wz_session_core::link::LinkEvent::Rx`] ->
//!   [`dispatch_link_event`](wz_session_core::drive::dispatch_link_event) (the
//!   shared dispatch core) -> `report_outcome_reassembling` (reassembly-gated)
//!   or the bare `on_event(Poll)` otherwise. Under `rx-in-place` the receive
//!   is [`SessionDatagramLink::recv_with`] instead, and each datagram is
//!   dispatched where the link holds it, record by record
//!   (`wz_session_core::drive::dispatch_datagram`).
//! - deadlines: [`HandshakeDeadlineTracker`] yields the handshake deadline;
//!   in Established the keepalive-resetting lease deadline applies and
//!   [`check_lease_deadline`] (the shared comparator) runs when it elapses.
//!   The sync loop fires a deadline when `now_ms >= deadline_ms` — the
//!   busy-poll equivalent of the AP `select!` sleep branch winning the race.
//! - outbound is transparent: the FSM action methods call
//!   `link_driver().send_blocking` on the link's own `BoxedLinkDriver`.
//!
//! R2915 — the loop used to live in `wz-session-lwip`, typed on lwIP's link
//! and UDP driver, so no MCU profile could run a session over any other
//! network stack. zenoh-pico's Zephyr port runs its session over Zephyr's
//! own BSD sockets, which a wz Zephyr profile could not do without writing a
//! second copy of this loop. The loop now names only what it needs from a
//! link — [`SessionDatagramLink`] — and each network stack implements that
//! seam (`wz_session_lwip::LwipSessionLink` over lwIP).

#[cfg(not(feature = "session-slot"))]
use alloc::rc::Rc;
#[cfg(feature = "session-slot")]
use core::cell::{Cell, UnsafeCell};
#[cfg(feature = "session-slot")]
use core::mem::MaybeUninit;
#[cfg(feature = "session-slot")]
use core::ops::{Deref, DerefMut};

#[cfg(feature = "session-slot")]
use critical_section::Mutex;
use wz_runtime_core::TimeSource;
#[cfg(all(feature = "rx-in-place", not(feature = "reassembly")))]
use wz_session_core::drive::dispatch_datagram;
#[cfg(all(not(feature = "rx-in-place"), feature = "alloc"))]
use wz_session_core::drive::dispatch_link_event;
#[cfg(feature = "alloc")]
use wz_session_core::drive::dispatch_pending;
use wz_session_core::drive::SessionEngine;
#[cfg(feature = "transport-keepalive")]
use wz_session_core::drive::{check_keepalive_deadline, keepalive_wake_deadline};
use wz_session_core::drive::{check_lease_deadline, lease_wake_deadline, new_session_engine};
#[cfg(feature = "rx-in-place")]
use wz_session_core::drive::{CopyReason, DatagramPath};
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
#[cfg(not(feature = "session-slot"))]
use wz_session_core::link::BoxedLinkDriver;
#[cfg(all(not(feature = "rx-in-place"), feature = "alloc"))]
use wz_session_core::link::LinkEvent;
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
#[cfg(feature = "rx-in-place")]
use wz_session_core::network_message::{new_record_buf, RecordBuf};
use wz_session_core::session_fsm_unicast::SessionFsmUnicastEvent;
use wz_session_core::session_timeouts::{HandshakeDeadlineTracker, SessionTimeouts};

#[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
use crate::reassembly_rx::{in_place_reassembly, InPlaceReassembly, PoolStorage, ReassemblyArena};
#[cfg(all(feature = "reassembly", not(feature = "rx-in-place")))]
use crate::reassembly_rx::{mcu_reassembly, CoopReassembly};
#[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
use wz_session_core::drive::dispatch_datagram_reassembling;
#[cfg(all(feature = "reassembly", feature = "alloc"))]
use wz_session_core::drive::report_outcome_reassembling;
// R311mh — sweep_reporting moved drive -> reassembly_dispatch (pure reassembly
// helper, not a unicast-drive one).
#[cfg(feature = "reassembly")]
use wz_session_core::reassembly_dispatch::sweep_reporting;

use crate::session_runtime::SessionHandle;
use crate::{yield_now, ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};

/// What the drive loop needs from a network stack: advance its input path,
/// and hand over the next inbound datagram.
///
/// The OUTBOUND half is not here. It is the link's
/// [`wz_session_core::link::BoxedLinkDriver`], which lives inside the
/// session's action bundle and is reached by the FSM action methods, not by
/// the loop. One object usually implements both.
pub trait SessionDatagramLink {
    /// Advance the stack's input path by one pass. A stack the loop must
    /// pump (lwIP `NO_SYS`, polled from this thread) does its work here; one
    /// whose input runs on its own thread or ISR does nothing.
    fn service(&self);

    /// The next inbound datagram as a frame, or `None` when nothing is
    /// queued. Taking a datagram also RETARGETS the link's replies to that
    /// datagram's source — the acceptor learns its peer from the InitSyn,
    /// and every reply after it goes back to whoever just spoke. The copying
    /// receive is the heap profile's (the frame is an owned [`RxFrame`]), so a
    /// build with no allocator has no such method and a link answers
    /// [`Self::recv_with`] alone.
    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame>;

    /// Lend the next inbound datagram's bytes to `f` WHERE THE LINK HOLDS
    /// THEM, and let it go once `f` returns; `false` when nothing is queued.
    /// Retargets replies to the datagram's source before `f` runs, as
    /// [`Self::try_recv`] does, so what `f` sends goes back to whoever spoke.
    ///
    /// The receive the `rx-in-place` loop makes. The bytes are valid for the
    /// call only, which is what lets a link hand over its own buffer instead
    /// of a copy of it. `f` may send on the session (the link's outbound half
    /// must stay usable while it runs) but must not receive.
    ///
    /// The provided form takes the datagram through [`Self::try_recv`], so it
    /// costs that frame's copy: right for a link with no buffer of its own to
    /// lend, and what every link answered before this existed. A link that
    /// holds its datagrams overrides it. With no allocator there is no copying
    /// receive to fall back to, so every link states this one.
    #[cfg(feature = "alloc")]
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        match self.try_recv() {
            Some(frame) => {
                f(&frame.bytes);
                true
            }
            None => false,
        }
    }

    /// Lend the next inbound datagram's bytes to `f` where the link holds them
    /// (see the form above); with no allocator a link states it.
    #[cfg(not(feature = "alloc"))]
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool;
}

/// A shared link is a link: the same object is usually the session's
/// `Rc<dyn BoxedLinkDriver>` sink too, so the loop takes a clone of that `Rc`.
///
/// Absent under `session-slot`, where nothing is shared by a pointer: the driver
/// is a value in the session's slot and the pump reads it through a handle to that
/// slot (fixed-memory step S9c).
#[cfg(not(feature = "session-slot"))]
impl<T: SessionDatagramLink + ?Sized> SessionDatagramLink for Rc<T> {
    fn service(&self) {
        (**self).service()
    }

    fn try_recv(&self) -> Option<RxFrame> {
        (**self).try_recv()
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        (**self).recv_with(f)
    }
}

/// An IPv4 UDP peer as its four octets and a port: what a dial names, written
/// in no network stack's address word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPeer {
    /// The address, most significant octet first.
    pub addr: [u8; 4],
    /// The UDP port.
    pub port: u16,
}

/// Why a stack could not open a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOpenError {
    /// The stack has no socket, port or buffer left to give. Worth trying
    /// again later, which is why a dial that meets it is retried.
    Exhausted,
}

/// The two halves of one session link, as a stack opens them: the outbound half
/// the session's action bundle sends through and the inbound half the drive loop
/// pumps. One object often is both (Zephyr's socket driver); lwIP's are two
/// (its stack handle, pumped, and its UDP driver, read).
///
/// Absent under `session-slot`: its sink is an `Rc` of a driver, and a link on that
/// profile is a driver moved into a slot of the session table with a pump over a
/// handle to it (fixed-memory step S9c; `wz_session_lwip::session_host::SessionHost`).
#[cfg(not(feature = "session-slot"))]
pub struct OpenedLink<P> {
    /// What the session's actions send through.
    pub sink: Rc<dyn BoxedLinkDriver>,
    /// What the drive loop services and takes datagrams from.
    pub pump: P,
}

/// What a network stack gives a session shell that is written once for all of
/// them: the means to open the two ends of a UDP session link.
///
/// This is the seam a node that LISTENS and DIALS needs, where
/// [`SessionDatagramLink`] is the seam a loop that DRIVES one link needs. The
/// admin node is the first user: it accepts one session on a port and dials
/// whatever endpoints a host writes, and neither is any stack's business but the
/// socket under it.
///
/// Absent under `session-slot`, with [`OpenedLink`] (see there).
#[cfg(not(feature = "session-slot"))]
pub trait SessionLinks {
    /// What the drive loop pumps for a link this stack opened.
    type Pump: SessionDatagramLink + 'static;

    /// A link that accepts: bound on `port`, with no peer until the first
    /// datagram names one.
    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError>;

    /// A link that dials `peer`: bound on a port the stack picks, with replies
    /// and first sends going to `peer`.
    fn open_initiator(&self, peer: UdpPeer) -> Result<OpenedLink<Self::Pump>, LinkOpenError>;
}

/// The handshake role to activate the FSM with before the loop starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Listen for an inbound peer (the InitSyn arrives first). Activates
    /// the FSM via the `inbound.start` event.
    Acceptor,
    /// Dial a configured peer (emit the InitSyn first). Activates the FSM
    /// via the `outbound.start` event.
    Initiator,
}

impl SessionRole {
    /// The events that activate the FSM in this role, in order.
    ///
    /// R2831 — the initiator takes TWO, as the AP's `initiator_open` does:
    /// `OutboundStart` enters LinkOpening and `LinkOpened` moves to
    /// SentInitSyn, whose entry sends the InitSyn. The UDP link is open by
    /// the time a pump exists (the driver's socket is already bound), so
    /// both are raised at once. Raising only the first left an MCU initiator
    /// in LinkOpening forever, silent on the wire; nothing drove one until
    /// the dialer did.
    fn activation(self) -> &'static [SessionFsmUnicastEvent] {
        match self {
            SessionRole::Acceptor => &[SessionFsmUnicastEvent::InboundStart],
            SessionRole::Initiator => &[
                SessionFsmUnicastEvent::OutboundStart,
                SessionFsmUnicastEvent::LinkOpened,
            ],
        }
    }
}

/// R311lw — the static parameterization of one `run_session` drive: the
/// handshake-deadline budget, the FSM activation role, and the test-only
/// iteration cap, separated from the loop's live collaborators (the
/// runtime / link / actions / clock handles + the `on_event` observer) via
/// the Introduce-Parameter-Object refactor. The unicast MCU sibling of
/// `wz_session_core::multicast_params::MulticastDriveConfig` (R311ls/R311lt):
/// it brings `run_session` within clippy's argument-count bound. All three
/// fields are `Copy`, so this owns them by value and carries no lifetime.
pub struct SessionDriveConfig {
    /// The handshake deadline budget ([`SessionTimeouts::spec_defaults`]);
    /// seeds the [`HandshakeDeadlineTracker`] the loop polls each tick.
    pub timeouts: SessionTimeouts,
    /// The role to activate the FSM with before the loop starts
    /// ([`SessionRole::Acceptor`] listens for an inbound peer;
    /// [`SessionRole::Initiator`] dials the configured peer).
    pub role: SessionRole,
    /// `Some(n)` caps the loop for test determinism; `None` drives unbounded
    /// for production.
    pub max_iters: Option<usize>,
}

/// Drive one logical session over `link` to a terminal FSM state (or the
/// `config.max_iters` cap). Builds the FSM engine from `actions` via the
/// shared [`new_session_engine`], activates `config.role`, then polls until
/// `engine.is_in_final_state()`.
///
/// Parameters:
/// - `runtime` — the [`CoopRuntime`] whose `run_until_idle` is pumped each
///   tick (spawned keepalive workers + deadline-keyed timers).
/// - `link` — the [`SessionDatagramLink`]: serviced each tick, and the source
///   of inbound frames. Its outbound twin sits inside `actions`.
/// - `actions` — the session action bundle; its `clock` MUST share an epoch
///   with `clock` (R263) so the lease comparator's `now_ms` and the recorded
///   keepalive / established stamps agree. Build one [`CoopTime`], clone it
///   into `new_generic`, pass the original here.
/// - `config` — the static run parameterization ([`SessionDriveConfig`]).
/// - `on_event` — the per-iteration observer (`Poll` with the decoded
///   `FramePayload` batch the application dispatches, or `Lease`).
///
/// Absent under `session-slot` with `reassembly`, where a pump is not built on
/// the caller's stack with a heap table behind it: see `SessionPump::new`.
#[cfg(not(all(feature = "session-slot", feature = "reassembly")))]
pub fn run_session<C, L, F>(
    runtime: &CoopRuntime<C>,
    link: L,
    actions: &SessionHandle<C>,
    clock: &CoopTime<C>,
    config: SessionDriveConfig,
    mut on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    L: SessionDatagramLink,
    F: FnMut(IterationEvent<'_>),
{
    let mut pump = SessionPump::new(
        runtime.clone(),
        link,
        actions.clone(),
        clock.clone(),
        config,
    );
    loop {
        // The synchronous driver owns the executor pass: nothing else is
        // driving this runtime, so spawned workers and deadline-keyed
        // timers only advance because this loop says so. `step` deliberately
        // does not do it — see its doc.
        pump.runtime().run_until_idle();
        if let Some(outcome) = pump.step(&mut on_event) {
            return outcome;
        }
    }
}

/// One MCU session, ready to be advanced one iteration at a time.
///
/// R2364 — extracted from `run_session`, whose body this used to be
/// inline. The extraction exists so that the sequencing of an iteration —
/// link input, parked-unit drain, inbound dispatch, handshake / lease
/// deadline, keepalive deadline — is written ONCE and both drivers share
/// it: the synchronous `run_session` loop, and `session_task`, the
/// `!Send` future that runs the session as a task ON the cooperative
/// executor via [`CoopLocalSet::spawn_local`].
///
/// Generic over the link `L` it OWNS: the synchronous loop may hand it a
/// borrow-backed link, while a spawned task must be `'static` and therefore
/// hands it one that owns its shares.
pub struct SessionPump<C: ClockSource, L: SessionDatagramLink> {
    runtime: CoopRuntime<C>,
    link: L,
    actions: SessionHandle<C>,
    clock: CoopTime<C>,
    engine: SessionEngine<CoopRuntime<C>, CoopTime<C>>,
    deadline_tracker: HandshakeDeadlineTracker,
    #[cfg(all(feature = "reassembly", not(feature = "rx-in-place")))]
    reasm: CoopReassembly,
    /// `rx-in-place` — the session's own reassembly Router, staging into the
    /// slots of a `reassembly_pool_mcu` table this session owns
    /// ([`ReassemblyArena`]): a fragment is read where the link holds it and
    /// copied once, into its slot.
    #[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
    reasm: InPlaceReassembly,
    /// `rx-in-place` — the one-record buffer each inbound record is decoded
    /// into and dispatched from. Allocated once, with the pump, for one
    /// record; a datagram costs it nothing however many records it carries.
    ///
    /// Under `session-slot` (which implies `bounded-heapless`) it is a fixed
    /// buffer of one that lives in the pump, and the pump in a cell of a
    /// `PumpSlots` table: a datagram costs the heap nothing and neither does
    /// the pump that reads it.
    #[cfg(feature = "rx-in-place")]
    record: RecordBuf,
    /// `rx-in-place` — how many units were read where the link held them, and
    /// how many went down the copying path and why.
    #[cfg(feature = "rx-in-place")]
    rx_paths: RxPathCounts,
    /// `session-slot` -- the role this pump is to activate the engine with at its
    /// FIRST step, and has not yet. The profile's pump does not speak when it is
    /// built: a dialling pump's activation sends the `InitSyn`, and a pump that
    /// is built (in a cell of its table) before the task that will run it has a
    /// cell would put an `InitSyn` on the wire for a session that then cannot run.
    /// Deferred to the first step, which only a running task makes, the
    /// session's first byte leaves after every table it needs has said yes.
    #[cfg(feature = "session-slot")]
    pending_role: Option<SessionRole>,
    iter: usize,
    max_iters: Option<usize>,
}

/// `rx-in-place` — the units a [`SessionPump`] dispatched, by the path they
/// took (`wz_session_core::drive::dispatch_datagram`): read where the link held
/// them, or copied onto the heap for one of the documented reasons. A unit the
/// in-place path does not take is not lost: it is dispatched by the copying
/// path, and this is where a profile sees how often that happens.
#[cfg(feature = "rx-in-place")]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RxPathCounts {
    /// Units that began with an admissible `Frame`, read in place.
    pub in_place: u32,
    /// Admissible `Fragment`s, staged into their reassembly slots from where
    /// the link held them (`reassembly`).
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
    fn count(&mut self, path: DatagramPath) {
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

impl<C: ClockSource, L: SessionDatagramLink> SessionPump<C, L> {
    /// Build the engine, activate the configured role, and arm the
    /// handshake deadline tracker — everything `run_session` does before
    /// entering its loop.
    ///
    /// Takes its collaborators BY VALUE. Every one of them is a cheap
    /// shared handle (`CoopRuntime` is `Arc`-backed; the action bundle is
    /// `Rc`; `CoopTime` is a clock handle), so owning them costs a refcount
    /// and buys the `'static` that [`CoopLocalSet::spawn_local`] requires.
    ///
    /// R2965 (open-debt item 847) — never inlined, for the caller's STACK. The
    /// engine is built here as a local and MOVED into the pump; inlined, both
    /// slots (1160 and 1264 bytes on the microbit image) sit in the caller's
    /// frame for the life of the session, because ARMv6-M codegen does not
    /// overlay a dead temporary. Out of line, the temporary is this function's
    /// and is gone when it returns.
    ///
    /// `rx-in-place` with `reassembly`: the session stages its fragments into a
    /// reassembly table of its OWN, allocated here once
    /// ([`PoolStorage::owned`]); [`Self::with_reassembly_arena`] takes one the
    /// image placed instead. Under `session-slot` that table is never the
    /// pump's own heap allocation, so with `reassembly` this constructor is absent
    /// and a pump is made by `PumpSlots::claim` (which places the table in the
    /// pump's cell) or by [`Self::with_reassembly_arena`].
    ///
    /// Under `session-slot` the role is NOT activated here: the first
    /// [`Self::step`] activates it, so a dialling pump's `InitSyn` leaves only
    /// once the task that steps it exists (`pending_role`).
    #[cfg(not(all(feature = "session-slot", feature = "reassembly")))]
    #[inline(never)]
    pub fn new(
        runtime: CoopRuntime<C>,
        link: L,
        actions: SessionHandle<C>,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
    ) -> Self {
        Self::build(
            runtime,
            link,
            actions,
            clock,
            config,
            #[cfg(all(feature = "reassembly", not(feature = "rx-in-place")))]
            mcu_reassembly(),
            #[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
            in_place_reassembly(ReassemblyArena::new(PoolStorage::owned())),
        )
    }

    /// `Self::new` over a reassembly arena the caller built: the image hands
    /// the session the table it placed ([`PoolStorage::Static`]), one per
    /// session, so two sessions in one program each stage into their own.
    #[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
    #[inline(never)]
    pub fn with_reassembly_arena(
        runtime: CoopRuntime<C>,
        link: L,
        actions: SessionHandle<C>,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
        arena: ReassemblyArena,
    ) -> Self {
        Self::build(
            runtime,
            link,
            actions,
            clock,
            config,
            in_place_reassembly(arena),
        )
    }

    /// `rx-in-place` with `reassembly` — the session's reassembly Router, and
    /// through it the arena and its table (slot accounting, the address
    /// witness of a delivered payload).
    #[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
    pub fn reassembly(&self) -> &InPlaceReassembly {
        &self.reasm
    }

    /// What `Self::new` and [`Self::with_reassembly_arena`] share.
    #[inline(always)]
    fn build(
        runtime: CoopRuntime<C>,
        link: L,
        actions: SessionHandle<C>,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
        #[cfg(all(feature = "reassembly", not(feature = "rx-in-place")))] reasm: CoopReassembly,
        #[cfg(all(feature = "reassembly", feature = "rx-in-place"))] reasm: InPlaceReassembly,
    ) -> Self {
        let SessionDriveConfig {
            timeouts,
            role,
            max_iters,
        } = config;

        let mut engine = new_session_engine(&actions);
        // `new_session_engine` returns an un-initialized engine (the AP
        // convention — the caller runs the SCXML initial transition into the
        // `Init` state). Without this the `role.activation()` below lands on
        // an engine that never entered `Init`, so `inbound.start` /
        // `outbound.start` does not transition into `AwaitingInitSyn` /
        // `LinkOpening` and the whole handshake stalls.
        engine.initialize();
        // Under `session-slot` the activation waits for the first step (see
        // `pending_role`); every other profile activates here, as it always did.
        #[cfg(not(feature = "session-slot"))]
        for event in role.activation() {
            engine.process_event(*event);
        }

        Self {
            runtime,
            link,
            actions,
            clock,
            engine,
            deadline_tracker: HandshakeDeadlineTracker::new(timeouts),
            #[cfg(feature = "reassembly")]
            reasm,
            #[cfg(feature = "rx-in-place")]
            record: new_record_buf(),
            #[cfg(feature = "rx-in-place")]
            rx_paths: RxPathCounts::default(),
            #[cfg(feature = "session-slot")]
            pending_role: Some(role),
            iter: 0,
            max_iters,
        }
    }

    /// Borrow the runtime this session was built against. The synchronous
    /// driver uses it to take the executor pass that [`Self::step`] does
    /// not.
    pub fn runtime(&self) -> &CoopRuntime<C> {
        &self.runtime
    }

    /// `rx-in-place` — the units this session dispatched so far, by the path
    /// they took ([`RxPathCounts`]).
    #[cfg(feature = "rx-in-place")]
    pub fn rx_path_counts(&self) -> RxPathCounts {
        self.rx_paths
    }

    /// Advance the session by one iteration. `Some(outcome)` means the
    /// session is finished (terminal FSM state, or the test iteration cap);
    /// `None` means call again.
    ///
    /// Deliberately does NOT pump the runtime. Who drives the executor is
    /// the DRIVER's question and the two drivers answer it differently:
    /// `run_session` owns its loop and so takes the pass itself, while
    /// `session_task` runs INSIDE the executor — pumping from there would
    /// have the session drive the pool that is currently polling it, which
    /// is precisely the inversion [`CoopLocalSet`] exists to remove.
    pub fn step<F>(&mut self, on_event: &mut F) -> Option<DriverOutcome>
    where
        F: FnMut(IterationEvent<'_>),
    {
        // The role's activation, deferred from the pump's making (`session-slot`).
        #[cfg(feature = "session-slot")]
        if let Some(role) = self.pending_role.take() {
            for event in role.activation() {
                self.engine.process_event(*event);
            }
        }
        if self.engine.is_in_final_state() {
            return Some(DriverOutcome::Terminated);
        }
        if let Some(limit) = self.max_iters {
            if self.iter >= limit {
                return Some(DriverOutcome::IterationLimit);
            }
            self.iter += 1;
        }

        // R2922 — raise what the session was asked from OUTSIDE the loop (a
        // rail close) before servicing the link. This loop polls every
        // iteration, so it needs no wake of its own.
        if wz_session_core::drive::check_out_of_band(&self.actions, &mut self.engine) {
            return None;
        }

        self.link.service();

        let now_ms = self.clock.now_monotonic_ms();
        // Sweep expired reassembly chains and surface the eviction count as
        // an `IterationEvent::ReassemblyTimeout` (the shared SSOT — the AP
        // loop calls the same primitive). A stalled chain whose continuation
        // never arrives is reclaimed here once `now_ms` crosses its deadline.
        #[cfg(feature = "reassembly")]
        sweep_reporting(&mut self.reasm, now_ms, &mut *on_event);

        // R311y632 (§17) — the parked remainder of the LAST unit first. A unit
        // is a batch, and `try_recv` below would otherwise hold the second
        // message until the peer sends again.
        // A build with no allocator parks nothing: it reads the rest of a datagram
        // where the link holds it, so there is no remainder to come back to.
        #[cfg(feature = "alloc")]
        if let Some(outcome) = dispatch_pending(&self.actions, &mut self.engine) {
            #[cfg(feature = "reassembly")]
            report_outcome_reassembling(
                &outcome,
                &mut self.reasm,
                &self.actions,
                now_ms,
                &mut *on_event,
            );
            #[cfg(not(feature = "reassembly"))]
            on_event(IterationEvent::Poll(&outcome));
            return None;
        }

        // `rx-in-place` — the datagram is read where the link holds it and
        // its records are dispatched one at a time, each outcome reported as
        // it happens (`dispatch_datagram`). Inside the lend: what the
        // observer does runs on the stack above the receive.
        // A Push record arrives as `IterationEvent::InPlace`, lent where the
        // datagram lies; every outcome goes through the reassembly hand-off as
        // the copying loop's does. Which path the unit took is counted.
        #[cfg(feature = "rx-in-place")]
        {
            let link = &self.link;
            let actions = &self.actions;
            let engine = &mut self.engine;
            let record = &mut self.record;
            let paths = &mut self.rx_paths;
            #[cfg(feature = "reassembly")]
            let reasm = &mut self.reasm;
            // With `reassembly` a Fragment is read in place too: its payload is
            // staged into its slot from where the link holds it, and a chain
            // it completes is read in that slot; every outcome goes through
            // the reassembly hand-off.
            let received = link.recv_with(&mut |unit| {
                #[cfg(feature = "reassembly")]
                let path = dispatch_datagram_reassembling(
                    unit,
                    actions,
                    engine,
                    record,
                    reasm,
                    now_ms,
                    &mut *on_event,
                );
                #[cfg(not(feature = "reassembly"))]
                let path = dispatch_datagram(unit, actions, engine, record, &mut *on_event);
                paths.count(path);
            });
            if received {
                return None;
            }
        }

        // Inbound datagram? Dispatch it and loop promptly for the next. The
        // link has already retargeted its replies to the datagram's source.
        // Unicast MCU session shell — one peer per link, so no source
        // attribution is needed.
        #[cfg(all(not(feature = "rx-in-place"), feature = "alloc"))]
        if let Some(frame) = self.link.try_recv() {
            let outcome =
                dispatch_link_event(LinkEvent::Rx(frame), &self.actions, &mut self.engine);
            #[cfg(feature = "reassembly")]
            report_outcome_reassembling(
                &outcome,
                &mut self.reasm,
                &self.actions,
                now_ms,
                &mut *on_event,
            );
            #[cfg(not(feature = "reassembly"))]
            on_event(IterationEvent::Poll(&outcome));
            return None;
        }

        // No inbound: the handshake / lease deadline. The tracker yields the
        // active handshake deadline; in Established it disarms and the
        // lease-expiry deadline applies — armed via the shared
        // `lease_wake_deadline` helper (R311kx: baseline
        // max(established_at, any-RX `last_inbound_at` — R311la pico
        // `_received` parity) + the adopted min(local, peer) window, the
        // same arithmetic the comparator re-derives). Fire when
        // `now_ms >= deadline_ms` — the busy-poll equivalent of the AP
        // select! sleep branch.
        let deadline: Option<(u64, Option<SessionFsmUnicastEvent>)> = match self
            .deadline_tracker
            .poll(self.engine.get_current_state(), now_ms)
        {
            Some((dl_ms, ev)) => Some((dl_ms, Some(ev))),
            None => lease_wake_deadline(&self.actions).map(|dl| (dl, None)),
        };
        if let Some((deadline_ms, kind)) = deadline {
            if now_ms >= deadline_ms {
                match kind {
                    None => {
                        let lease_outcome =
                            check_lease_deadline(&self.actions, &mut self.engine, now_ms);
                        on_event(IterationEvent::Lease(lease_outcome));
                    }
                    Some(event) => {
                        self.engine.process_event(event);
                    }
                }
            }
        }

        // R311kx — keepalive TX deadline, the busy-poll twin of the AP
        // loop's min-deadline select arm: compare against the TX wake
        // deadline each tick and run the (self-guarded) check only when it
        // crossed, so the steady state stays event-free — the observer
        // sees `Emitted` verdicts, not a per-tick `WithinInterval` flood.
        // There is no deadline while the FSM's keepalive worker is stopped,
        // so a session in Closing emits nothing after its Close frame.
        #[cfg(feature = "transport-keepalive")]
        if let Some(ka_deadline_ms) = keepalive_wake_deadline(&self.actions) {
            if now_ms >= ka_deadline_ms {
                let ka_outcome = check_keepalive_deadline(&self.actions, now_ms);
                on_event(IterationEvent::KeepAlive(ka_outcome));
            }
        }

        None
    }
}

/// The MCU session AS A TASK — the `!Send` future that
/// [`CoopLocalSet::spawn_local`] hosts.
///
/// R2364. This is the MCU answer to what `TokioRuntime::spawn` gives the AP
/// profile: the MCU action bundle is `Rc`-backed and `!Send` on purpose (that
/// `Rc` is what reaches ARMv6-M, where `alloc::sync::Arc` does not exist), so
/// the session runs IN the local set rather than as a caller-owned loop.
///
/// Awaits [`yield_now`] between iterations rather than spinning, so every
/// other task in the pool — and the local set's own runtime pass — gets a
/// turn each time round. The returned value is the same [`DriverOutcome`]
/// `run_session` returns; reach it through the [`CoopLocalJoinHandle`] the
/// spawn hands back.
#[cfg(not(all(feature = "session-slot", feature = "reassembly")))]
pub async fn session_task<C, L, F>(
    runtime: CoopRuntime<C>,
    link: L,
    actions: SessionHandle<C>,
    clock: CoopTime<C>,
    config: SessionDriveConfig,
    mut on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    L: SessionDatagramLink,
    F: FnMut(IterationEvent<'_>),
{
    let mut pump = SessionPump::new(runtime, link, actions, clock, config);
    loop {
        if let Some(outcome) = pump.step(&mut on_event) {
            return outcome;
        }
        yield_now().await;
    }
}

/// Spawn one MCU session onto `local` and return its join handle.
///
/// The convenience form of `session_task` + [`CoopLocalSet::spawn_local`],
/// and the call site a deploy `main()` writes. The runtime the session is
/// built against is the local set's own, so a caller cannot accidentally
/// pump one runtime while the session rides another.
///
/// `link` and `on_event` must be `'static` here where `run_session` takes
/// any: a detached task cannot borrow the caller's stack. An observer that
/// needs to publish out of the task should capture an `Rc<RefCell<..>>` —
/// `!Send` is fine, which is the whole point of the local set.
///
/// Absent under `session-slot`: it builds the pump inside the task's future and
/// answers a handle where a spawn can be refused. The slot profile's form is
/// `PumpSlots::claim` and `spawn_pump`.
#[cfg(not(feature = "session-slot"))]
pub fn spawn_session<C, L, F>(
    local: &CoopLocalSet<C>,
    link: L,
    actions: SessionHandle<C>,
    clock: CoopTime<C>,
    config: SessionDriveConfig,
    on_event: F,
) -> CoopLocalJoinHandle<DriverOutcome>
where
    C: ClockSource + 'static,
    L: SessionDatagramLink + 'static,
    F: FnMut(IterationEvent<'_>) + 'static,
{
    local.spawn_local(session_task(
        local.runtime().clone(),
        link,
        actions,
        clock,
        config,
        on_event,
    ))
}

// ───────────── the pump in a cell of a table the image declares ─────────────
//
// Fixed-memory step S6. A pump is the engine (1160 to 1264 bytes on the microbit
// image), the handles it holds, the record buffer and, with `reassembly`, the
// table its fragments are staged into. Built into a future by `session_task` it
// lives wherever that future is spawned; here it lives in a CELL of a table the
// image declares, one cell per session it can run, and the task that drives it is a
// reference to that cell.

/// Why a pump could not be put in a cell: every cell of the table is taken. The
/// refusal is counted ([`PumpSlots::refused`]) and the session the pump was to run
/// is dropped, which gives its own slot back.
#[cfg(feature = "session-slot")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PumpsFull;

/// A session that could not be run as a task, and why.
#[cfg(feature = "session-slot")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSpawnRefused {
    /// Every cell of the pump table is taken.
    NoPumpCell,
    /// The task table refused the task.
    Task(crate::executor::SpawnRefusal),
}

/// One cell of a [`PumpSlots`] table.
#[cfg(feature = "session-slot")]
struct PumpCell<C: ClockSource, L: SessionDatagramLink> {
    taken: Mutex<Cell<bool>>,
    pump: UnsafeCell<MaybeUninit<SessionPump<C, L>>>,
    /// With `reassembly`, the table the pump's fragments are staged into: one per
    /// pump, in the pump's own cell.
    #[cfg(feature = "reassembly")]
    pool: UnsafeCell<MaybeUninit<crate::reassembly_pool_mcu::ReassemblyPoolMcu>>,
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource, L: SessionDatagramLink> PumpCell<C, L> {
    const fn new() -> Self {
        Self {
            taken: Mutex::new(Cell::new(false)),
            pump: UnsafeCell::new(MaybeUninit::uninit()),
            #[cfg(feature = "reassembly")]
            pool: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

/// The pump table an image declares: `N` cells, each holding the pump of one
/// session, in a `static`. The pump's counterpart of `wz_session_core`'s
/// `SessionSlots`, and declared the same way:
///
/// ```ignore
/// static PUMPS: PumpSlots<BoardClock, LwipSessionLink<&'static LwipLink>, 3> = PumpSlots::new();
/// let pump = PUMPS.claim(runtime.clone(), link, actions, clock, config)?;
/// spawn_pump(&local, pump, on_event)?;
/// ```
///
/// [`claim`](PumpSlots::claim) builds the pump IN a free cell, or refuses and
/// counts. The pump is freed (dropped in place, its cell free for the next) when
/// its [`PumpRef`] is dropped, which is when the task that drives it ends or is
/// swept.
///
/// Like the session table, it is `Sync` by the profile's rule and not by any
/// means a compiler can check: a pump is driven by ONE cooperative task on one
/// core, and claiming and freeing are critical sections.
#[cfg(feature = "session-slot")]
pub struct PumpSlots<C: ClockSource, L: SessionDatagramLink + 'static, const N: usize> {
    cells: [PumpCell<C, L>; N],
    refused: Mutex<Cell<u32>>,
}

// SAFETY: the profile's rule, stated on the type. The cell's pump is written by the
// one claimant of the cell (its `taken` flag, set inside a critical section) and
// reached only through that claimant's `PumpRef`.
#[cfg(feature = "session-slot")]
unsafe impl<C: ClockSource, L: SessionDatagramLink + 'static, const N: usize> Sync
    for PumpSlots<C, L, N>
{
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource, L: SessionDatagramLink + 'static, const N: usize> PumpSlots<C, L, N> {
    /// A table of free cells.
    pub const fn new() -> Self {
        Self {
            cells: [const { PumpCell::new() }; N],
            refused: Mutex::new(Cell::new(0)),
        }
    }

    /// How many cells the table has.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many cells hold a pump.
    pub fn in_use(&self) -> usize {
        self.cells
            .iter()
            .filter(|cell| critical_section::with(|cs| cell.taken.borrow(cs).get()))
            .count()
    }

    /// How many claims were refused for want of a free cell.
    pub fn refused(&self) -> u32 {
        critical_section::with(|cs| self.refused.borrow(cs).get())
    }

    /// The bytes this table takes in the image's `.bss`, with each cell's pump (and,
    /// with `reassembly`, its staging table).
    pub const fn size_bytes() -> usize {
        core::mem::size_of::<Self>()
    }

    /// Build the pump of one session in a free cell: the engine, the role's
    /// activation, the handles. `None` of that is built when no cell is free, and
    /// what the caller offered (the link and the handle to the session, which hold
    /// their own slots) is dropped, so a refused pump leaves nothing taken.
    ///
    /// With `reassembly` the pump stages its fragments into a table that lies in the
    /// same cell, handed to the pump as `PoolStorage::Static`.
    pub fn claim(
        &'static self,
        runtime: CoopRuntime<C>,
        link: L,
        actions: SessionHandle<C>,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
    ) -> Result<PumpRef<C, L>, PumpsFull> {
        let cell = self.cells.iter().find(|cell| {
            critical_section::with(|cs| {
                let taken = cell.taken.borrow(cs);
                !taken.replace(true)
            })
        });
        let Some(cell) = cell else {
            critical_section::with(|cs| {
                let refused = self.refused.borrow(cs);
                refused.set(refused.get().saturating_add(1));
            });
            return Err(PumpsFull);
        };
        #[cfg(feature = "reassembly")]
        let pump = {
            // SAFETY: the cell is `taken` by this call alone, and its pool is only
            // ever reached through the pump built here.
            let place = unsafe { &mut *cell.pool.get() };
            SessionPump::with_reassembly_arena(
                runtime,
                link,
                actions,
                clock,
                config,
                ReassemblyArena::new(PoolStorage::zeroed_in(place)),
            )
        };
        #[cfg(not(feature = "reassembly"))]
        let pump = SessionPump::new(runtime, link, actions, clock, config);
        // SAFETY: the cell is `taken` by this call alone, and its pump is
        // uninitialised: either it was never written or its last pump was dropped
        // in place by the `PumpRef` that freed the cell.
        unsafe { (*cell.pump.get()).write(pump) };
        Ok(PumpRef { cell })
    }
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource, L: SessionDatagramLink + 'static, const N: usize> Default
    for PumpSlots<C, L, N>
{
    fn default() -> Self {
        Self::new()
    }
}

/// The exclusive handle to a pump in its cell. Dropping it drops the pump in place
/// and frees the cell. The task that drives a pump ([`pump_task`]) owns it.
#[cfg(feature = "session-slot")]
pub struct PumpRef<C: ClockSource + 'static, L: SessionDatagramLink + 'static> {
    cell: &'static PumpCell<C, L>,
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource, L: SessionDatagramLink + 'static> Deref for PumpRef<C, L> {
    type Target = SessionPump<C, L>;

    fn deref(&self) -> &SessionPump<C, L> {
        // SAFETY: a `PumpRef` exists only for a cell whose pump was written by
        // `claim` and not yet dropped, and it is the cell's one reference.
        unsafe { (*self.cell.pump.get()).assume_init_ref() }
    }
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource, L: SessionDatagramLink + 'static> DerefMut for PumpRef<C, L> {
    fn deref_mut(&mut self) -> &mut SessionPump<C, L> {
        // SAFETY: as for `deref`, and `&mut self` is the cell's one reference.
        unsafe { (*self.cell.pump.get()).assume_init_mut() }
    }
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource, L: SessionDatagramLink + 'static> Drop for PumpRef<C, L> {
    fn drop(&mut self) {
        // SAFETY: the cell holds this handle's pump, written by `claim` and dropped
        // only here; the flag is cleared after, so no claim can write over it first.
        unsafe { (*self.cell.pump.get()).assume_init_drop() };
        critical_section::with(|cs| self.cell.taken.borrow(cs).set(false));
    }
}

/// The session AS A TASK over a pump in a cell: awaits [`yield_now`] between
/// iterations as `session_task` does, and ends with the same [`DriverOutcome`].
/// The future is the pump's handle and the observer and a loop's state, a few dozen
/// bytes, and the pump stays where its table put it.
#[cfg(feature = "session-slot")]
pub async fn pump_task<C, L, F>(mut pump: PumpRef<C, L>, mut on_event: F) -> DriverOutcome
where
    C: ClockSource,
    L: SessionDatagramLink + 'static,
    F: FnMut(IterationEvent<'_>),
{
    loop {
        if let Some(outcome) = pump.step(&mut on_event) {
            return outcome;
        }
        yield_now().await;
    }
}

/// Host the pump in `pump` as a task of `local` and return its join handle, or say
/// why not. A refusal is counted (by the pump table when no cell was free, by the
/// runtime's task table otherwise) and the pump, which this call owns, is dropped
/// with its cell and the session it was to run.
#[cfg(feature = "session-slot")]
pub fn spawn_pump<C, L, F>(
    local: &CoopLocalSet<C>,
    pump: PumpRef<C, L>,
    on_event: F,
) -> Result<CoopLocalJoinHandle<DriverOutcome>, SessionSpawnRefused>
where
    C: ClockSource + 'static,
    L: SessionDatagramLink + 'static,
    F: FnMut(IterationEvent<'_>) + 'static,
{
    local
        .spawn_local(pump_task(pump, on_event))
        .map_err(|refused| SessionSpawnRefused::Task(refused.why))
}

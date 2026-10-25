// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `run_multicast_session` — the synchronous MCU multicast drive loop, written
//! once for every network stack.
//!
//! The MCU analog of
//! `wz_runtime_tokio::multicast_glue::drive_multicast_session`, minus the
//! `tokio::select!`: a cooperative single-task polling loop, the same shape as
//! `session_drive::run_session` (the unicast MCU loop) but driving the
//! engine-free [`MulticastDispatcher`] instead of the unicast FSM engine. Every
//! decision PRIMITIVE is the shared `wz_session_core` SSOT (JOIN encode /
//! decode / validate, the §3.2 peer-table arithmetic, the §2.3 per-channel SN
//! gate); this module is only the loop STRUCTURE that sequences them.
//!
//! ## The stack seam
//!
//! The loop was written against lwIP and named lwIP's types for what it needs of
//! a stack, which is four things: pump the stack's input path, say whether the
//! carrier is up, multicast one datagram to the group, and take one inbound
//! datagram with its source address. [`GroupTransport`] (defined in
//! `wz-runtime-coop`, beside the unicast seam) is those four, and the loop is
//! generic over it, as the unicast loop is over
//! `wz_runtime_coop::session_drive::SessionDatagramLink`. lwIP's implementation
//! is `wz-session-lwip`'s, Zephyr's sockets supply theirs, and a board is not
//! asked to carry the lwIP crate to run a group session over some other stack.
//!
//! ## What it owns (the §3.1 Running parallel concerns, busy-poll form)
//!
//! - **JoinEmit** — multicasts a periodic JOIN beacon every
//!   [`MulticastParams::join_interval_ms`] (the handshake-free transport's
//!   self-advertisement; there is no separate keepalive, so the periodic JOIN
//!   IS the liveness beacon). The MCU mirror of the AP loop's JOIN arm.
//! - **RxDispatch** — classifies each inbound datagram by its transport MID and
//!   attributes it by the datagram SOURCE ADDRESS (Frame / KeepAlive / Close
//!   carry no zid on the wire, exactly like zenoh-pico `_z_find_peer_entry`):
//!   JOIN -> validate + [`MulticastDispatcher::ingest_join`]; Frame -> the
//!   per-peer SN gate + the observer fan; KeepAlive ->
//!   [`MulticastDispatcher::refresh_by_src`]; Close ->
//!   [`MulticastDispatcher::close_by_src`].
//! - **PeerSweep** — evicts peers past their advertised lease via
//!   [`MulticastDispatcher::sweep`] on the `tick_ms` cadence.
//!
//! ## Data plane (Frame -> observer)
//!
//! An inbound `T_MID_FRAME` from a live peer is decoded, admitted against that
//! peer's per-channel SN gate, and its NetworkMessage batch fanned to the
//! caller's `on_event` observer as an [`IterationEvent::Poll`] carrying a
//! `DriverLoopOutcome::FramePayload` — the SAME event shape the unicast
//! `run_session` loop and the AP `drive_multicast_session` loop fan, so one
//! `ApplicationLayerObserver` routes both transports' data identically.
//!
//! ## TX publish seam (R311ly Push; R311lz variant-complete)
//!
//! The `next_tx` pull-seam drains application outbound items each iteration and
//! frames them through the shared `multicast_tx_emit` SSOT — variant-complete as
//! of R311lz: Push (`z_put`), the queryable reply chain (`Response` +
//! `ResponseFinal`), and the liveliness `DeclareReply` all route through the one
//! SSOT the AP loop calls, each gated by its TX body codec (the loop's TX gate is
//! their union). The seam EMITS every variant; what remains is the *observer
//! staging* that auto-PRODUCES the reply variants — an application that builds
//! its own reply items publishes them today.
//!
//! ## Observer staging (R311ma liveliness; R311mb queryable; R311md shared SSOT)
//!
//! [`MulticastReplyQueue`] is the no_std MCU
//! [`MulticastReplyEnqueue`]
//! backing for the shared
//! [`MulticastReplySink<Q>`](wz_session_core::multicast_reply_sink::MulticastReplySink)
//! (the wz-session-core SSOT, R311md — the TX-staging twin of `multicast_rx` /
//! `multicast_tx`). The application wraps the backing in that sink
//! (`MulticastReplySink::new(queue.clone())`) and its observer drains its staged
//! replies through the sink — liveliness interest-responses via
//! `flush_declare_replies` (R311ma) and queryable `Response` / `ResponseFinal`
//! via `flush_query_replies` (R311mb) — and the loop's `next_tx` seam drains them
//! back out via [`MulticastReplyQueue::pop`]. So a held-token declarer OR a
//! registered queryable on the MCU auto-replies to an inbound liveliness Interest
//! / Query over the group without the application hand-building the reply items.
//! The `ResponseSink` / `DeclareReplySink` construction lives ONCE in the shared
//! sink (not duplicated AP/MCU; per the R311lq segregation it stubs no
//! `LivelinessGetPrune` — connectionless multicast has no reconnect cache).
//!
//! ## Fragment RX/TX (R311mf — the AP R311kn/R311ko arms, ported)
//!
//! Under `reassembly` the RX path reassembles inbound `T_MID_FRAGMENT` chains
//! through the shared `ingest_multicast_fragment` SSOT (per-peer SN gate ->
//! per-(slot, channel) chain -> the completed message fans as the SAME
//! `FramePayload` `Poll` a whole Frame does), aborts a channel's chain on an
//! out-of-order Frame, and aborts a departing/evicted peer's chains before its
//! slot recycles — identical to the AP loop. Under `transport-fragmentation`
//! (which implies `reassembly`) the TX seam fragments an oversize payload for
//! free: the same `multicast_tx_emit` SSOT the loop already drives splits it via
//! `multicast_frame_or_fragments`, so the `next_tx` drain emits the fragment
//! datagrams with no loop change. Off both features, Fragment tails drop (pico's
//! "fragmentation deactivated" behaviour) and the TX seam emits whole Frames.
//!
//! ## Stop (R2375)
//!
//! Two ways out, and [`run_multicast_session_with_shutdown`] is the second:
//! the `max_iters` budget ([`MulticastOutcome::IterationLimit`]), or the caller
//! asking for a graceful `multicast.stop` — the §3.1 Running -> Stopped event
//! ([`MulticastOutcome::Stopped`]). The stop arm multicasts the departing Close
//! (`encode_multicast_close`, the SAME datagram the AP loop sends since
//! R311y782) BEFORE driving the transition, so a group peer frees this member
//! now rather than holding a stale entry until its lease expires.
//!
//! The signal is a `FnMut() -> bool` POLLED once per iteration, not a channel
//! awaited on: the AP twin's `tokio::sync::watch::Receiver` has no `no_std`
//! analogue, and a busy-poll loop has no suspension point to be woken at. A
//! predicate composes with whatever the deploy already has — an ISR-set
//! [`AtomicBool`](core::sync::atomic::AtomicBool), an application `Cell`, a
//! countdown. [`run_multicast_session`] is that same body with a predicate that
//! never fires.
//!
//! ## Link loss (R2390)
//!
//! The third way out, and until R2390 this loop had no way to reach it: the
//! header here said "the MCU poll loop has no link-loss event (a silent group
//! is an empty receive), so it returns only `Stopped` / `IterationLimit`".
//! The first half of that stays TRUE and is why the answer is not the RX path —
//! a receive that finds nothing is what a quiet group looks like, so no amount
//! of reading it separates a silent group from a dead interface.
//!
//! The CARRIER separates them. lwIP's port contract is that the MAC/PHY driver
//! calls `netif_set_link_up` / `netif_set_link_down` on a carrier change, and
//! `LwipLink::any_link_is_up` reads the `NETIF_FLAG_LINK_UP` bit that writes.
//! Polled once per iteration beside the stop signal ([`GroupTransport::carrier_up`]),
//! it drives §3.1 Running -> Stopped through `notify_link_lost` and returns
//! [`MulticastOutcome::LinkLost`] — the same terminal the AP twin reaches from
//! a socket recv error, off a real stack event rather than a signal the host
//! supplies.
//!
//! It is a READ, not a predicate parameter: a `FnMut() -> bool` would have made
//! the arm reachable only for a deploy that already knew its link state and
//! bothered to say so, and every shipped MCU host in this tree would have
//! passed `|| false` — an arm with a witness and no user.

// `Rc` backs the heap reply queue; the session task is generic over what carries
// the group, so a build without a reply variant names it nowhere.
#[cfg(all(
    not(feature = "session-slot"),
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
use alloc::rc::Rc;
pub use wz_runtime_coop::group_transport::GroupTransport;

#[cfg(feature = "reassembly")]
use wz_runtime_coop::reassembly_rx::{mcu_reassembly, CoopReassembly};
use wz_runtime_coop::{
    yield_now, ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime,
};
use wz_runtime_core::TimeSource;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::handshake_encode::encode_multicast_close_into_slice;
use wz_session_core::link::LostCause;
use wz_session_core::multicast_dispatch::{MulticastDispatcher, MulticastLinkDuties};
use wz_session_core::multicast_join::{encode_join_into_slice, JOIN_MAX_BYTES};
use wz_session_core::multicast_params::{MulticastDriveConfig, MulticastOutcome, MulticastParams};
// R311mf/R311mh — multicast Fragment RX reassembly. The reassembly-divergent
// tail (FrameOutOfOrder chain abort / Fragment reassembly / pre-Close peer-chain
// abort) + the sweep tail are the shared wz_session_core multicast_rx SSOTs
// (dispatch_multicast_inbound_reassembling / sweep_multicast_reassembling) — the
// MCU loop owns only the Router (mcu_reassembly over the SCE buffer-pool, the
// same one run_session drives). All `reassembly`-gated: without it the loop
// drops Fragment tails (pico's "fragmentation deactivated") and calls the bare
// classify + sweep. transport-fragmentation implies reassembly, so a
// fragmenting-TX node auto-reassembles inbound.
#[cfg(not(feature = "reassembly"))]
use wz_session_core::multicast_rx::{dispatch_multicast_inbound, MulticastRxNext};
#[cfg(feature = "reassembly")]
use wz_session_core::multicast_rx::{
    dispatch_multicast_inbound_reassembling, sweep_multicast_reassembling,
};
// R311ly/R311lz — the shared TX emit SSOT (the AP loop calls the same).
// `MulticastTxOffer` is the unconditional pull-seam item type of the build's
// profile (the owned `MulticastTxItem` on the heap, a borrowed `Put` with no
// allocator; uninhabited without a TX body codec), and `multicast_tx_emit_offer`
// frames it either way, so the drain below carries no cfg. R311lz extended the
// seam from codec-push-only to every forwarded TX variant (Push / queryable
// Response + ResponseFinal / liveliness DeclareReply).
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
use wz_session_core::multicast_tx::MulticastTxItem;
use wz_session_core::multicast_tx::{multicast_tx_emit_offer, MulticastTxOffer};
use wz_session_core::sn::{self, MulticastTxConduits};
// R311ma/R311mb/R311md — the no_std multicast reply backing (MulticastReplyQueue,
// below): the observer drains its staged replies through the shared generic
// wz_session_core::multicast_reply_sink::MulticastReplySink<MulticastReplyQueue>,
// which constructs each MulticastTxItem and calls this backing's
// MulticastReplyEnqueue::enqueue (push_back); the loop's next_tx seam drains them
// back out via pop(). Backed by alloc (Rc<RefCell<VecDeque>>) rather than a tokio
// mpsc, because the busy-poll loop is single-task (no cross-thread Send). R311md
// folded the ResponseSink / DeclareReplySink construction into the shared sink,
// so this crate names no wz_codecs type and provides ONLY the enqueue backing.
#[cfg(all(
    not(feature = "session-slot"),
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
use alloc::collections::VecDeque;
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
use core::cell::RefCell;
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
use wz_session_core::multicast_reply_sink::MulticastReplyEnqueue;

/// R311ma/R311mb/R311md — the no_std multicast reply backing: the MCU
/// [`MulticastReplyEnqueue`] provider for the shared generic
/// [`MulticastReplySink`](wz_session_core::multicast_reply_sink::MulticastReplySink).
/// An application's observer drains its staged interest / query responses through
/// `MulticastReplySink::new(queue.clone())` — the `on_event` closure drives
/// [`flush_declare_replies`](wz_session_core::observer::ApplicationLayerObserver::flush_declare_replies)
/// (liveliness) and/or
/// [`flush_query_replies`](wz_session_core::observer::ApplicationLayerObserver::flush_query_replies)
/// (queryable) with that sink; the sink constructs each [`MulticastTxItem`] and
/// calls this backing's [`MulticastReplyEnqueue::enqueue`], and the loop's
/// `next_tx` seam drains them back out via [`Self::pop`], framing each through
/// the shared `multicast_tx_emit` SSOT.
///
/// Backed by `Rc<RefCell<VecDeque<MulticastTxItem>>>`, not the AP's tokio mpsc:
/// the busy-poll loop is single-task, so the sink (which pushes) and `next_tx`
/// (which pops) run at different points of the SAME iteration on one thread — no
/// cross-thread `Send`, an `Rc<RefCell>` is the single-task analogue of the
/// channel. `Clone` shares the backing store between the sink clone and the
/// loop's `pop` end.
///
/// R311md: the `ResponseSink` / `DeclareReplySink` construction (which
/// `MulticastTxItem`, the `build_*_reply` + `Box::new`) moved to the shared
/// [`MulticastReplySink<Q>`](wz_session_core::multicast_reply_sink::MulticastReplySink)
/// SSOT, so this backing names no wz_codecs type — the wz-codecs dep R311mb added
/// here is gone, and the duplicated AP/MCU impls collapsed to one. The backing
/// exists when any reply variant inhabits `MulticastTxItem` (the codec-response /
/// codec-response-final / liveliness-token union).
#[cfg(all(
    not(feature = "session-slot"),
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
#[derive(Clone, Default)]
pub struct MulticastReplyQueue {
    queue: Rc<RefCell<VecDeque<MulticastTxItem>>>,
}

#[cfg(all(
    not(feature = "session-slot"),
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
impl MulticastReplyQueue {
    /// A fresh empty reply queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain one queued reply for the loop's `next_tx` seam (FIFO order). `None`
    /// when empty — the loop then keeps serving RX + the JOIN beacon.
    pub fn pop(&self) -> Option<MulticastTxItem> {
        self.queue.borrow_mut().pop_front()
    }
}

// R311md — the single enqueue backing the shared MulticastReplySink<Q> drains
// into. The observer-drain construction (which MulticastTxItem the staged reply
// becomes, the build_*_reply + Box::new) lives ONCE in
// wz_session_core::multicast_reply_sink; this backing owns only the push_back
// onto the single-task queue (the MCU analogue of the AP backing's mpsc send).
#[cfg(all(
    not(feature = "session-slot"),
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
impl MulticastReplyEnqueue for MulticastReplyQueue {
    fn enqueue(&self, item: MulticastTxItem) {
        self.queue.borrow_mut().push_back(item);
    }
}

/// Fixed-memory step S9c -- the multicast reply backing of the `session-slot`
/// profile: a queue of `N` items in a `static`, which REFUSES the reply it has no
/// room for and COUNTS it, where the heap form above grows without bound.
///
/// The queue is the seam between the observer that stages a reply and the loop that
/// frames and sends it, and the sender is a pump that gives the thread back
/// between iterations, so a peer that asks faster than the loop answers (a flood of
/// interests or queries on the group) would have grown the heap form for as long as
/// it lasted. Here the reply that does not fit is dropped (the item is dropped
/// with it, which frees what the sink built) and
/// [`dropped`](MulticastReplyQueue::dropped) says how many, the same
/// counted, typed-by-its-counter refusal every other table of the profile makes. A
/// dropped reply is the loss multicast already allows (UDP to a group is best
/// effort, and a querier whose reply never comes retries or times out), and the
/// count is what tells the image its `N` is too small.
///
/// Declared by the image, shared by the sink that fills it (`&'static` is a
/// [`MulticastReplyEnqueue`]) and the loop's `next_tx` that drains it:
///
/// ```text
/// static REPLIES: MulticastReplyQueue<8> = MulticastReplyQueue::new();
/// let sink = MulticastReplySink::new(&REPLIES);
/// // next_tx: || REPLIES.pop()
/// ```
///
/// What stays on the heap is the ITEM: the sink builds each `MulticastTxItem` with a
/// boxed owned message (the codec owned mirrors, a step of their own), and the
/// queue's own storage is the table, not the items' bodies.
///
/// Like the other tables of the profile it is `Sync` by the profile's rule (one
/// cooperative task on one core fills and drains it), with every access inside a
/// critical section.
#[cfg(all(
    feature = "session-slot",
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
pub struct MulticastReplyQueue<const N: usize> {
    items: RefCell<heapless::Deque<MulticastTxItem, N>>,
    dropped: core::cell::Cell<u32>,
}

// SAFETY: the profile's rule, stated on the type: every access to `items` and
// `dropped` is made inside a critical section, so no two accesses overlap, and the
// items inside are moved in and out by value.
#[cfg(all(
    feature = "session-slot",
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
unsafe impl<const N: usize> Sync for MulticastReplyQueue<N> {}

#[cfg(all(
    feature = "session-slot",
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
impl<const N: usize> MulticastReplyQueue<N> {
    /// An empty queue, for a `static`.
    pub const fn new() -> Self {
        Self {
            items: RefCell::new(heapless::Deque::new()),
            dropped: core::cell::Cell::new(0),
        }
    }

    /// How many replies the queue holds at most.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many replies are waiting.
    pub fn len(&self) -> usize {
        critical_section::with(|_| self.items.borrow().len())
    }

    /// Whether no reply is waiting.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many replies were dropped for want of room since the queue was made.
    pub fn dropped(&self) -> u32 {
        critical_section::with(|_| self.dropped.get())
    }

    /// Drain one queued reply for the loop's `next_tx` seam (FIFO order). `None`
    /// when empty: the loop then keeps serving RX and the JOIN beacon.
    pub fn pop(&self) -> Option<MulticastTxItem> {
        critical_section::with(|_| self.items.borrow_mut().pop_front())
    }

    fn push(&self, item: MulticastTxItem) {
        let refused = critical_section::with(|_| {
            self.items
                .borrow_mut()
                .push_back(item)
                .err()
                .inspect(|_| self.dropped.set(self.dropped.get().saturating_add(1)))
        });
        // Dropped outside the critical section: freeing the item is the allocator's
        // business and has no place in an interrupt-off window.
        drop(refused);
    }
}

#[cfg(all(
    feature = "session-slot",
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
impl<const N: usize> Default for MulticastReplyQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The sink of the slot profile is built over the image's `static` queue, so the
/// queue is shared by a reference and the reply it cannot take is counted.
#[cfg(all(
    feature = "session-slot",
    feature = "alloc",
    any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )
))]
impl<const N: usize> MulticastReplyEnqueue for &'static MulticastReplyQueue<N> {
    fn enqueue(&self, item: MulticastTxItem) {
        self.push(item);
    }
}

/// Drive a multicast session over `transport`: bring the dispatcher up
/// (Idle -> Running), then own the §3.1 Running concerns (periodic JOIN emit,
/// RX classify -> dispatch + the Frame data plane, lease sweep) until the
/// session leaves Running or `cfg.max_iters` is reached.
///
/// Parameters:
/// - `dispatcher` — the engine-free [`MulticastDispatcher`] (the §3.1 session
///   FSM + the §3.2 per-peer table); `MAX_PEERS` is the bounded peer-table
///   capacity.
/// - `cfg` — the shared [`MulticastDriveConfig`] (protocol `params`, the
///   `tick_ms` sweep cadence, the test-only `max_iters` budget).
/// - `runtime` — the cooperative runtime pumped each tick
///   (`run_until_idle`). The loop derives its monotonic clock from `runtime`
///   directly: unlike the unicast `run_session` (which takes an
///   external clock so its epoch matches the R263 actions clock-clone), the
///   multicast loop has no actions bundle, so the runtime is its only time
///   source and a separate `clock` parameter would just be a redundant
///   re-derivation of `CoopTime::new(runtime)`.
/// - `transport` — the [`GroupTransport`] (group socket: JOIN/data TX + inbound
///   receive; the stack's input path and carrier).
/// - `on_event` — the per-iteration observer (`Poll` with the decoded
///   `FramePayload` batch the application dispatches).
/// - `next_tx` — the application TX pull-seam (R311ly; variant-complete R311lz):
///   each iteration the loop drains pending outbound items ([`MulticastTxOffer`]
///   — a `z_put` Push, a queryable `Response` / `ResponseFinal`, or a liveliness
///   `DeclareReply`) and frames each via the shared `multicast_tx_emit` SSOT
///   before the pump, so the datagrams ride the same `run_until_idle` as the
///   JOIN beacon. The MCU mirror of the AP loop's `outbound` mpsc receiver; the
///   busy-poll loop pulls rather than `select!`s. Without a TX body codec the
///   item is uninhabited and the seam is inert (a publish-free / RX-only node
///   passes `|| None`).
pub fn run_multicast_session<'g, C, T, F, G, const MAX_PEERS: usize>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    cfg: MulticastDriveConfig<'_>,
    runtime: &CoopRuntime<C>,
    transport: &mut T,
    on_event: F,
    next_tx: G,
) -> MulticastOutcome
where
    C: ClockSource,
    T: GroupTransport,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxOffer<'g>>,
{
    run_multicast_session_inner(dispatcher, cfg, runtime, transport, on_event, next_tx, None)
}

/// R2375 — [`run_multicast_session`] plus the GRACEFUL STOP signal: the §3.1
/// `multicast.stop` event (Running -> Stopped), which the MCU loop had no way
/// in for until this round.
///
/// `should_stop` is polled once at the top of every iteration; the first `true`
/// multicasts the departing Close, drives the transition (which clears the peer
/// table) and returns [`MulticastOutcome::Stopped`]. A predicate rather than a
/// channel because this loop is `no_std` and single-task: the AP twin's
/// `tokio::sync::watch::Receiver` has no MCU analogue, while a closure composes
/// with whatever the deploy already has — an ISR-set
/// [`AtomicBool`](core::sync::atomic::AtomicBool), a `Cell` the application
/// writes, a countdown. It is polled, not awaited, because the busy-poll loop
/// has no suspension point to wake from.
///
/// The AP twin additionally treats a CLOSED channel as a stop, which makes its
/// handle an RAII shutdown. There is no analogue here and none is missing: a
/// predicate cannot be "dropped" while the loop still holds it, so the only way
/// to ask is to answer `true`.
///
/// Every other parameter is [`run_multicast_session`]'s, unchanged — that entry
/// point is this one with a predicate that never fires, and both run ONE body.
pub fn run_multicast_session_with_shutdown<'g, C, T, F, G, H, const MAX_PEERS: usize>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    cfg: MulticastDriveConfig<'_>,
    runtime: &CoopRuntime<C>,
    transport: &mut T,
    on_event: F,
    next_tx: G,
    mut should_stop: H,
) -> MulticastOutcome
where
    C: ClockSource,
    T: GroupTransport,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxOffer<'g>>,
    H: FnMut() -> bool,
{
    run_multicast_session_inner(
        dispatcher,
        cfg,
        runtime,
        transport,
        on_event,
        next_tx,
        Some(&mut should_stop),
    )
}

/// R2561 — [`run_multicast_session_with_shutdown`] that RE-JOINS the group
/// after a lost carrier instead of ending the face for the life of the process.
///
/// # What was missing
///
/// The loop above has been able to DETECT a carrier drop since R2390 — it polls
/// [`GroupTransport::carrier_up`] and returns [`MulticastOutcome::LinkLost`] — and
/// nothing acted on it. An interface going down and coming back, the ordinary
/// case this exists for, ended the MCU face permanently. The AP twin got its
/// re-join at R2376; this profile did not, and R2560 measured that no
/// `rejoin` / `rebind` / `reopen` structure existed anywhere in
/// `wz-session-lwip`, `wz-runtime-coop` or `wz-link-lwip`.
///
/// # Why a dispatcher FACTORY and not a `&mut` one
///
/// A re-join needs a FRESH dispatcher, and this is not a workaround for the
/// FSM — it is what the AP twin already does, for a reason that is about the
/// data rather than the state machine:
/// `crates/wz-runtime-tokio/src/multicast_glue.rs` @ `// A FRESH dispatcher per join — see the egress twin: the peer table`
/// says the old peer table "describes members reached over the link that just
/// died". Carrying it across an outage would re-admit peers nobody has heard
/// from on the new link.
///
/// ⚠ IT IS ALSO WHAT MAKES THE RE-JOIN WORK AT ALL, and the first draft of this
/// function got that wrong by reusing one dispatcher. MEASURED: with the socket
/// genuinely re-bound and the carrier back, the second run returned
/// [`MulticastOutcome::Stopped`] immediately, because the loop's first act is
/// `session_state() != Running` and `notify_link_lost` had driven the FSM into
/// `Stopped` — a `<final>` in `sources/session/session_fsm_multicast.scxml`,
/// which cannot carry an outgoing transition. That reading invites adding a
/// resume edge to the statechart and regenerating. The AP twin shows the answer
/// was already settled one crate away: do not resume a session that is over,
/// start a new one. A fresh dispatcher enters at `Running` and needs no edge.
///
/// # Why the transport is taken BY VALUE, and why the drop is explicit
///
/// This is the one part that is not a matter of taste. The transport
/// owns its socket, and lwIP refuses a second bind to a live port:
/// `vendor/lwip/src/core/udp.c` @ `/* port matches that of PCB in list and REUSEADDR not set -> reject */`
/// returns `ERR_USE` unless every PCB on that port sets `SOF_REUSEADDR`, which
/// `wz_link_lwip::LwipUdpSocket::bind` (and `bind_in`) never does. So the tempting shape —
/// hand this function a `&mut` and assign `*transport = rebind()?` — is not merely
/// untidy, it CANNOT WORK: Rust evaluates the new bind while the old PCB is
/// still installed. Taking the transport by value lets the `drop` happen before
/// the re-bind, in that order, visibly. (The finite `MEMP_NUM_UDP_PCB` pool
/// gives the same answer a second way: a transient double occupancy is a
/// `PcbExhausted` risk on a device sized for one.)
///
/// # Why the wait is a poll and not a sleep
///
/// The AP twin races its backoff against a `watch::Receiver` in `select!`. This
/// profile has no suspension point and takes its stop as a PREDICATE, so the
/// wait is a DEADLINE polled beside `should_stop` — the same idiom this module
/// already uses twice for `next_join_ms` and `next_sweep_ms`. A stop during an
/// outage is therefore observed on the next poll rather than one backoff later,
/// which is the property the AP's `select!` buys and this loop gets from its
/// shape. `run_until_idle` is pumped inside the wait for the same reason the
/// drive loop pumps it: a cooperative executor whose other tasks stop running
/// while one face waits out an outage is a worse failure than the outage.
///
/// # The delay is CONSTANT, and that is the parity answer here
///
/// Not an oversight and not the AP's schedule. The AP faces grow their backoff
/// (zenoh's 1000/4000/x2) because a router holding a group face on a flapping
/// NIC would retry at 1 Hz for the length of the outage. This profile's parity
/// target is pico, whose multicast lease failure arms the same reopen task its
/// unicast failure does and re-arms FLAT:
/// `vendor/zenoh-pico/src/net/session.c` @ `return _z_fut_fn_result_wake_up_after(1000);`.
/// A constant delay is what the upstream this loop mirrors actually does.
///
/// Returns the ORIGINAL loss when the host stops the face while it is down, or
/// when `rebind` gives up by answering `None` — never a re-join it did not make.
///
/// ⚠ `rejoin_delay_ms` is bounded by the CLOCK ADVANCING, because the wait is a
/// poll rather than a sleep. A caller whose [`ClockSource`] does not advance —
/// the `FrozenClock` the tests use — must pass `0`, or the wait
/// never reaches its deadline. That is a property of polling, not a defect to
/// paper over with a spin count: on a device the clock is what moves, and a
/// deadline that never arrives is a stopped clock the face cannot fix.
#[allow(clippy::too_many_arguments)]
pub fn run_multicast_session_rejoining<'g, C, T, F, G, H, B, D, const MAX_PEERS: usize>(
    mut new_dispatcher: D,
    cfg: MulticastDriveConfig<'_>,
    runtime: &CoopRuntime<C>,
    transport: T,
    mut on_event: F,
    mut next_tx: G,
    mut should_stop: H,
    mut rebind: B,
    rejoin_delay_ms: u64,
) -> MulticastOutcome
where
    C: ClockSource,
    T: GroupTransport,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxOffer<'g>>,
    H: FnMut() -> bool,
    B: FnMut() -> Option<T>,
    D: FnMut() -> MulticastDispatcher<MAX_PEERS>,
{
    // `MulticastDriveConfig` is neither `Copy` nor `Clone` and is consumed by
    // each run, so its three fields are lifted out once rather than deriving
    // `Copy` on a shared type for one caller's convenience.
    let params = cfg.params;
    let tick_ms = cfg.tick_ms;
    let max_iters = cfg.max_iters;
    let clock = CoopTime::new(runtime);
    let mut transport = transport;
    loop {
        // A FRESH dispatcher per join, mirroring the AP twin: the previous peer
        // table describes members reached over the link that just died, and the
        // previous session FSM is in its `<final>` state.
        let mut dispatcher = new_dispatcher();
        let outcome = run_multicast_session_with_shutdown(
            &mut dispatcher,
            MulticastDriveConfig {
                params,
                tick_ms,
                max_iters,
            },
            runtime,
            &mut transport,
            &mut on_event,
            &mut next_tx,
            &mut should_stop,
        );
        if !outcome.warrants_rejoin() {
            return outcome;
        }
        // The session's `release_multicast_link` closed the transport, which
        // gave an owned socket back; the spent transport goes too, BEFORE the
        // port is asked for again — see the doc above.
        drop(transport);
        let deadline = clock.now_monotonic_ms().saturating_add(rejoin_delay_ms);
        while clock.now_monotonic_ms() < deadline {
            if should_stop() {
                return outcome;
            }
            runtime.run_until_idle();
        }
        match rebind() {
            Some(fresh) => transport = fresh,
            None => return outcome,
        }
    }
}

/// The one drive loop both entry points above run. `should_stop` is the only
/// thing that varies between them, and it is an `Option` rather than two copies
/// of the body — the same call the AP twin made when its shutdown door landed
/// (`multicast_glue::drive_multicast_session_inner`): a duplicated busy-poll
/// would drift at the first arm anyone touches.
///
/// `&mut dyn FnMut` rather than a fourth generic: the predicate is called once
/// per iteration against a loop whose cost is dominated by the stack's pump, and a
/// second monomorphisation of this body is ROM the MCU profile would pay for
/// nothing.
///
/// Open-debt item 900 — the body became [`MulticastPump::step`], so that the
/// same sequence can also run as a task on a [`CoopLocalSet`]
/// ([`multicast_session_task`]) beside other sessions. This loop drives that step
/// with the executor pass taken INLINE, at the two points this body always took
/// it, so its behaviour is unchanged.
fn run_multicast_session_inner<'g, C, T, F, G, const MAX_PEERS: usize>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    cfg: MulticastDriveConfig<'_>,
    runtime: &CoopRuntime<C>,
    transport: &mut T,
    mut on_event: F,
    mut next_tx: G,
    mut should_stop: Option<&mut dyn FnMut() -> bool>,
) -> MulticastOutcome
where
    C: ClockSource,
    T: GroupTransport,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxOffer<'g>>,
{
    let mut pump =
        MulticastPump::with_pass(dispatcher, cfg, runtime, transport, ExecutorPass::Inline);
    loop {
        if let Some(outcome) = pump.step(&mut on_event, &mut next_tx, should_stop.as_deref_mut()) {
            return outcome;
        }
    }
}

/// Perform the link duties one lifecycle call of `dispatcher` returned: a
/// release closes `transport`, and an open opens it and answers the machine
/// with `link.ready` or `link.lost`, whose own duties are performed in turn.
/// `false` when an open failed (the machine has heard `link.lost` and released
/// the link).
fn perform_link_duties<T: GroupTransport, const MAX_PEERS: usize>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    transport: &mut T,
    mut duties: MulticastLinkDuties,
) -> bool {
    let mut opened = true;
    loop {
        if duties.release() {
            transport.close();
        }
        if !duties.open() {
            return opened;
        }
        duties = if transport.open() {
            dispatcher.notify_link_ready()
        } else {
            opened = false;
            dispatcher.notify_link_lost()
        };
    }
}

/// Who takes the cooperative executor's pass while a [`MulticastPump`] runs.
///
/// The unicast twin (`wz_runtime_coop::session_drive::SessionPump`) answers
/// this by never pumping in its step and letting each driver pump once per
/// iteration. This loop cannot simply copy that, because its synchronous form
/// has always taken the pass in the MIDDLE of an iteration (after the TX drain,
/// before the RX read) and after the departing Close; moving it would reorder
/// what the frozen-clock lanes pin. So the position stays where it was and only
/// WHETHER it is taken depends on the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutorPass {
    /// The loop owns the thread ([`run_multicast_session`] and its siblings):
    /// nothing else drives the runtime, so the step takes the pass itself.
    Inline,
    /// The session is a task inside a [`CoopLocalSet`], which drives the
    /// runtime before it polls its tasks. Pumping from inside the task would
    /// have the session drive the pool that is polling it.
    Hosted,
}

/// Bytes of the datagram buffer the TX drain of a build with no allocator frames
/// into: the most a UDP datagram carries over a 1500-byte Ethernet MTU (the IPv4 and
/// UDP headers take 28), and the group's batch is held to it, so a Put larger than
/// that leaves as a fragment chain, a datagram at a time, through this one buffer.
#[cfg(not(feature = "alloc"))]
const TX_SCRATCH_BYTES: usize = 1500 - 20 - 8;
/// The heap profile frames into vectors of its own and keeps no buffer here.
#[cfg(feature = "alloc")]
const TX_SCRATCH_BYTES: usize = 0;

/// One MCU multicast session, ready to be advanced one iteration at a time.
///
/// Open-debt item 900 — one program holding SEVERAL sessions (a client session
/// towards a router plus this group session) needs every session to give the
/// thread back between iterations. [`run_multicast_session`] never did: it is a
/// loop that returns only when the session ends, and while it ran, a unicast
/// session spawned on a [`CoopLocalSet`] was never polled, because the loop
/// pumped the runtime's shared pool and not the local set. The step below is
/// that loop's body, unchanged, and the two drivers share it: the synchronous
/// loop, and [`multicast_session_task`], the `!Send` future a local set hosts.
///
/// [`Self::new`] builds the HOSTED form: its step does not pump the executor,
/// so a caller that drives it by hand owns that pass, as with the unicast
/// `SessionPump`.
pub struct MulticastPump<'a, C: ClockSource, T: GroupTransport, const MAX_PEERS: usize> {
    dispatcher: &'a mut MulticastDispatcher<MAX_PEERS>,
    params: &'a MulticastParams,
    tick_ms: u64,
    max_iters: Option<usize>,
    runtime: &'a CoopRuntime<C>,
    clock: CoopTime<C>,
    transport: &'a mut T,
    pass: ExecutorPass,
    // The TX mint state (per-channel next SN). The JOIN beacon advertises the
    // live values; the TX-codec drain mints from here per data frame.
    tx_sn: MulticastTxConduits,
    // The datagram buffer a build with no allocator frames each offer into, a
    // datagram at a time (`multicast_tx_emit_offer`); empty on the heap profile,
    // which frames into vectors of its own.
    tx_scratch: [u8; TX_SCRATCH_BYTES],
    next_join_ms: u64,
    next_sweep_ms: u64,
    iter: usize,
    // The transport could not be opened as the session's link: the session went
    // LinkOpening -> Stopped at bring-up, and the first step reports the loss.
    lost_at_open: bool,
    // R311mf — the per-(slot, channel) reassembly Router for inbound multicast
    // Fragment chains, dimensioned to the MCU pool (mcu_reassembly =
    // ReassemblyDispatcher<4, 4096>, the same Router run_session owns). Only
    // built when `reassembly` is on; otherwise the Fragment arm is a drop.
    #[cfg(feature = "reassembly")]
    reasm: CoopReassembly,
}

impl<'a, C: ClockSource, T: GroupTransport, const MAX_PEERS: usize>
    MulticastPump<'a, C, T, MAX_PEERS>
{
    /// Bring the dispatcher up (Idle -> LinkOpening, whose `open_multicast_link`
    /// opens `transport` as the session's link, -> Running) and arm the JOIN and
    /// sweep cadences — everything the synchronous loop does before its first
    /// iteration. A transport that cannot be opened sends nothing: the first
    /// step reports [`MulticastOutcome::LinkLost`]. The step of the pump this
    /// returns does NOT take the executor pass (see [`MulticastPump`]).
    pub fn new(
        dispatcher: &'a mut MulticastDispatcher<MAX_PEERS>,
        cfg: MulticastDriveConfig<'a>,
        runtime: &'a CoopRuntime<C>,
        transport: &'a mut T,
    ) -> Self {
        Self::with_pass(dispatcher, cfg, runtime, transport, ExecutorPass::Hosted)
    }

    fn with_pass(
        dispatcher: &'a mut MulticastDispatcher<MAX_PEERS>,
        cfg: MulticastDriveConfig<'a>,
        runtime: &'a CoopRuntime<C>,
        transport: &'a mut T,
        pass: ExecutorPass,
    ) -> Self {
        // The shared parameter-object SSOT (R311ls/R311lt).
        let MulticastDriveConfig {
            params,
            tick_ms,
            max_iters,
        } = cfg;

        // The loop's monotonic clock, derived from the runtime it pumps (R311ly):
        // the dispatcher's stamps all come from this one source, so there is no
        // external epoch to match (contrast the unicast run_session's R263 clock).
        let clock = CoopTime::new(runtime);

        // Idle -> LinkOpening, whose `open_multicast_link` takes the transport as
        // the session's link, and the machine hears whether it could. A
        // dispatcher already Running (a second drive of the same session) asks
        // for nothing and keeps the link it has.
        let created = dispatcher.create();
        let lost_at_open = !perform_link_duties(dispatcher, transport, created);

        let tx_sn = MulticastTxConduits::new(sn::mask_from_res(params.seq_num_res));
        // Emit the first JOIN beacon immediately, then every join_interval_ms;
        // the sweep runs on its own tick_ms cadence (the busy-poll equivalents
        // of the AP loop's JOIN-due check + select! sweep tick).
        let next_join_ms = clock.now_monotonic_ms();
        let next_sweep_ms = clock.now_monotonic_ms();
        Self {
            dispatcher,
            params,
            tick_ms,
            max_iters,
            runtime,
            clock,
            transport,
            pass,
            tx_sn,
            tx_scratch: [0; TX_SCRATCH_BYTES],
            next_join_ms,
            next_sweep_ms,
            iter: 0,
            lost_at_open,
            #[cfg(feature = "reassembly")]
            reasm: {
                // The group's `transport/link/rx/max_message_size`, as the AP
                // group loop applies it.
                let mut reasm = mcu_reassembly();
                reasm.set_max_message_bytes(params.link_rx.max_message_size);
                reasm
            },
        }
    }

    /// The peer table the pump drives, for a caller that reports its group.
    pub fn dispatcher(&self) -> &MulticastDispatcher<MAX_PEERS> {
        self.dispatcher
    }

    /// Advance the session by one iteration. `Some(outcome)` means the session
    /// is finished (left Running, stopped, lost its carrier, or hit the test
    /// budget); `None` means call again.
    ///
    /// At most ONE inbound datagram is handled per step, as the synchronous
    /// loop handled one per iteration. That is what bounds how long a group
    /// under a flood can keep the thread from a sibling session: one datagram,
    /// then the step returns and the task yields.
    pub fn step<'s, 'g, F, G>(
        &mut self,
        on_event: &mut F,
        next_tx: &mut G,
        should_stop: Option<&mut (dyn FnMut() -> bool + 's)>,
    ) -> Option<MulticastOutcome>
    where
        F: FnMut(IterationEvent<'_>),
        G: FnMut() -> Option<MulticastTxOffer<'g>>,
    {
        if core::mem::take(&mut self.lost_at_open) {
            // The open failed at bring-up and the session is already Stopped:
            // reported once, as the lost link it is, with nothing sent.
            return Some(MulticastOutcome::LinkLost(LostCause::OsError));
        }
        // The body below is the synchronous loop's, verbatim but for these
        // names: each is a disjoint borrow of one field.
        let pass = self.pass;
        let runtime = self.runtime;
        let params = self.params;
        let tick_ms = self.tick_ms;
        let max_iters = self.max_iters;
        let dispatcher = &mut *self.dispatcher;
        let transport = &mut *self.transport;
        let clock = &self.clock;
        let tx_sn = &mut self.tx_sn;
        let tx_scratch = &mut self.tx_scratch[..];
        let next_join_ms = &mut self.next_join_ms;
        let next_sweep_ms = &mut self.next_sweep_ms;
        let iter = &mut self.iter;
        #[cfg(feature = "reassembly")]
        let reasm = &mut self.reasm;

        if !dispatcher.is_running() {
            return Some(MulticastOutcome::Stopped);
        }
        // R2375 — GRACEFUL STOP: the §3.1 Running -> Stopped event, the MCU twin
        // of the AP loop's `select!` shutdown arm. POLLED at the top of the
        // iteration rather than raced against RX because this is a busy-poll
        // loop, not a `select!`: there is no concurrency here for a signal to be
        // lost to, and a fixed position is what keeps the terminal reproducible
        // under the frozen clock the MCU lanes drive.
        //
        // BEFORE the `max_iters` budget, deliberately: a caller that has asked
        // to stop must get `Stopped` on the iteration its request becomes
        // visible, not `IterationLimit` because the budget happened to run out
        // on the same one. The budget stays the terminal for a caller that never
        // asks.
        let stop_requested = match should_stop {
            Some(ask) => ask(),
            None => false,
        };
        if stop_requested {
            // R311y782 gave the AP loop's departure a WIRE half; until this
            // round the MCU loop had no departure point to put one on, so an
            // MCU member left the group silently and every peer held its entry
            // until the lease expired. Announce first, THEN tear down — the
            // order both upstreams use (zenoh `multicast/transport.rs:204-229`,
            // pico `multicast/transport.c:164-171`), and the same one the AP
            // stop arm takes.
            //
            // Best-effort like the JOIN beacon: multicast UDP has no
            // acknowledgement, and a node already leaving has no recovery to
            // take — its peers fall back to the lease sweep, which is exactly
            // the pre-round behaviour. `send_to_group` already drops the error.
            let mut dgram = [0u8; 2];
            if let Ok(len) = encode_multicast_close_into_slice(&mut dgram) {
                transport.send_to_group(&dgram[..len]);
            }
            // Pump before returning so the datagram actually LEAVES. The body
            // does the same after its TX drain, and for the same reason: on a
            // loopback netif `send_to` only queues, so without this the loop
            // would return having stopped WITHOUT having announced — and those
            // are different claims (the AP twin keeps its `JoinHandle` alive to
            // tell them apart).
            transport.service();
            if pass == ExecutorPass::Inline {
                runtime.run_until_idle();
            }
            // Drive the transition rather than just returning: its
            // `release_multicast_link` clears the peer table and closes the
            // transport, after the Close above has left, exactly as the
            // link-loss path does. Returning the outcome without it would leave
            // a Stopped session still holding peers and its socket.
            let stopped = dispatcher.stop();
            perform_link_duties(dispatcher, transport, stopped);
            return Some(MulticastOutcome::Stopped);
        }
        // R2390 — LINK LOSS: the third way out, and the one this loop did not
        // have. The AP twin gets `LinkEvent::Lost` from a socket recv error
        // (`udp_pipeline.rs:595`); a busy-poll receive cannot carry it,
        // because an empty queue is what a QUIET group looks like too. The
        // carrier is where the two are distinguishable: lwIP's port driver
        // reports it (`netif_set_link_up` / `_down`) and
        // `LwipLink::any_link_is_up` reads it, so this is a real event off the
        // stack rather than a signal the host has to supply.
        //
        // `notify_link_lost()` rather than `stop()`: they are different §3.1
        // transitions with the same peer-table consequence, and the FSM half
        // has carried the distinction since R311lt. NO departing Close is sent
        // — the AP loop does not send one either, and it could not arrive: the
        // interface that would carry it is the one that went away. A member's
        // peers fall back to the lease sweep, which is what an unannounced
        // departure has always meant.
        //
        // AFTER the stop poll and BEFORE the budget, for the same reason the
        // stop poll sits where it does: a caller that asked to stop gets
        // `Stopped` even on a dead link (its request is the older fact), while
        // a link that dropped is a REAL terminal and must not be reported as
        // the test guard `IterationLimit` because the budget happened to run
        // out on the same iteration.
        if !transport.carrier_up() {
            let lost = dispatcher.notify_link_lost();
            perform_link_duties(dispatcher, transport, lost);
            // `OsError` is the AP's cause for a socket that stopped working
            // (`udp_pipeline.rs:596`), which is what a dropped carrier is here:
            // not a peer's announced departure (`PeerClosed`) and not a lease
            // that ran out (`Timeout`).
            return Some(MulticastOutcome::LinkLost(LostCause::OsError));
        }
        if let Some(limit) = max_iters {
            if *iter >= limit {
                return Some(MulticastOutcome::IterationLimit);
            }
            *iter += 1;
        }

        let now = clock.now_monotonic_ms();
        // JoinEmit: multicast the self-advertising JOIN beacon when due.
        if now >= *next_join_ms {
            // R311y227 — the DEFAULT conduit's live SNs (the single-conduit
            // beacon); a qos group additionally advertises per-priority ext_qos (C2).
            // Written into an array on the stack (`encode_join_into_slice` is the
            // JOIN `encode_join` is, byte for byte, over a heap vector), so the
            // beacon takes nothing from an allocator on either profile.
            let mut beacon = [0u8; JOIN_MAX_BYTES];
            if let Ok(len) = encode_join_into_slice(params, tx_sn, &mut beacon) {
                transport.send_to_group(&beacon[..len]);
            }
            *next_join_ms = now.saturating_add(params.join_interval_ms);
        }

        // TxData: drain the application's pending outbound items, framing each
        // through the shared multicast_tx_emit_offer SSOT (the same the AP loop
        // calls the heap form of) and multicasting it to the group. Drained right
        // after the JOIN beacon so the datagrams ride THIS iteration's
        // run_until_idle. send_to_group is best-effort (multicast UDP); the SSOT's
        // per-variant reliability flag is inert here (the MCU group socket takes
        // no reliability arg). Every forwarded variant — Push, queryable
        // Response / ResponseFinal, liveliness DeclareReply — routes through the
        // one SSOT, so this drain is variant-agnostic (the item carries which).
        // With no TX body codec the offer is uninhabited, so `next_tx` can only
        // yield `None` and the loop body is never entered.
        while let Some(offer) = next_tx() {
            multicast_tx_emit_offer(offer, tx_sn, params, tx_scratch, &mut |datagram| {
                transport.send_to_group(datagram)
            });
        }

        // Drive the stack's input path (lwIP: loopback / QEMU shape) + the runtime
        // task pool + deadline-keyed timers. Real-NIC deploys drive netif input
        // from the RX ISR instead.
        transport.service();
        if pass == ExecutorPass::Inline {
            runtime.run_until_idle();
        }

        // Inbound datagram? Classify + dispatch, then loop promptly for the
        // next (the busy-poll equivalent of the AP loop's RX select arm).
        let received = transport.recv_with(&mut |bytes, src| {
            // R311lv/R311mf/R311mh — the shared RX dispatch SSOTs: JOIN admit /
            // Frame admit-and-fan / KeepAlive refresh PLUS the reassembly-
            // divergent tail (out-of-order-chain abort + Fragment reassembly +
            // per-peer chain death at Close) all live in `wz_session_core`, so
            // the AP + MCU loops share one home and own only the IO + clock
            // structure. A reassembly build drives the reassembly-aware dispatch
            // (the Router is the loop's); without it the loop calls the bare
            // classify and acts only on Close (FrameOutOfOrder / Fragment are
            // no-ops without a Router — pico's fragmentation-off behaviour).
            #[cfg(feature = "reassembly")]
            dispatch_multicast_inbound_reassembling(
                dispatcher,
                reasm,
                params,
                bytes,
                src,
                now,
                on_event,
                // R2848 — `transport-stats` is never on an MCU lane, so this
                // loop keeps no counts to record into.
                &(),
            );
            #[cfg(not(feature = "reassembly"))]
            if let MulticastRxNext::Close =
                dispatch_multicast_inbound(dispatcher, params, bytes, src, now, on_event, &())
            {
                // R311y784 — the MCU twin of the AP loop's announced departure.
                // Both loops fire the identical event so an application's
                // membership view does not depend on which profile it runs on;
                // that is the same argument the shared RX/TX SSOTs already make.
                dispatcher.close_by_src_with(src, |lost| {
                    on_event(IterationEvent::MulticastPeerLost(lost));
                });
            }
        });
        if received {
            return None;
        }

        // PeerSweep: evict peers past their advertised lease on the tick_ms
        // cadence (idempotent; sweeping more often only sharpens eviction).
        // R311mh — under `reassembly` the deadline-reclaim + evict-with-chain-
        // abort tail is the shared multicast_rx sweep SSOT (the AP loop calls
        // the same); a non-reassembly loop calls the bare sweep.
        if now >= *next_sweep_ms {
            #[cfg(feature = "reassembly")]
            sweep_multicast_reassembling(dispatcher, reasm, now, on_event);
            #[cfg(not(feature = "reassembly"))]
            dispatcher.sweep_with(
                now,
                |_| {},
                |lost| on_event(IterationEvent::MulticastPeerLost(lost)),
            );
            *next_sweep_ms = now.saturating_add(tick_ms);
        }
        None
    }
}

/// What a multicast session OWNS when it runs as a task: everything
/// [`run_multicast_session_with_shutdown`] borrows from its caller's stack,
/// which a detached task cannot do.
///
/// Open-debt item 900. The heap profiles hold this in the task's future, so its
/// memory comes from the image heap and is NOT a per-session budget: the
/// per-session shape that later fixed-memory work keeps is the session's own
/// static pools (the group socket's RX ring is one), not an allocator split.
pub struct MulticastSession<T: GroupTransport, const MAX_PEERS: usize> {
    /// The §3.1 session FSM and the §3.2 peer table.
    pub dispatcher: MulticastDispatcher<MAX_PEERS>,
    /// The group socket, joined at bind, with the stack it is pumped through.
    pub transport: T,
    /// The protocol parameters this session advertises, its own zid among them.
    pub params: MulticastParams,
    /// The sweep cadence (see [`MulticastDriveConfig::tick_ms`]).
    pub tick_ms: u64,
    /// The test budget (see [`MulticastDriveConfig::max_iters`]); `None` in
    /// production.
    pub max_iters: Option<usize>,
}

/// The MCU multicast session AS A TASK — the `!Send` future a
/// [`CoopLocalSet`] hosts beside other sessions.
///
/// Open-debt item 900. The multicast twin of
/// `wz_runtime_coop::session_drive::session_task`: it runs
/// [`MulticastPump::step`] once per executor pass and awaits [`yield_now`]
/// between steps, so every other task in the set (a unicast client session,
/// for one) gets a turn each time round. The synchronous
/// [`run_multicast_session_with_shutdown`] runs the same step and keeps the
/// thread until the session ends, which is why it cannot share a program with
/// a second session.
///
/// `should_stop` is the same graceful-stop predicate the synchronous entry
/// takes; pass `|| false` for a session that runs until its link is lost.
pub async fn multicast_session_task<'g, C, T, F, G, H, const MAX_PEERS: usize>(
    runtime: CoopRuntime<C>,
    session: MulticastSession<T, MAX_PEERS>,
    mut on_event: F,
    mut next_tx: G,
    mut should_stop: H,
) -> MulticastOutcome
where
    C: ClockSource,
    T: GroupTransport,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxOffer<'g>>,
    H: FnMut() -> bool,
{
    let MulticastSession {
        mut dispatcher,
        mut transport,
        params,
        tick_ms,
        max_iters,
    } = session;
    let mut pump = MulticastPump::new(
        &mut dispatcher,
        MulticastDriveConfig {
            params: &params,
            tick_ms,
            max_iters,
        },
        &runtime,
        &mut transport,
    );
    loop {
        if let Some(outcome) = pump.step(&mut on_event, &mut next_tx, Some(&mut should_stop)) {
            return outcome;
        }
        yield_now().await;
    }
}

/// Spawn one MCU multicast session onto `local` and return its join handle —
/// [`multicast_session_task`] on the local set's own runtime, so the session
/// cannot ride a different runtime from the one the set pumps. The multicast
/// twin of `spawn_session` (absent under `session-slot`).
///
/// Absent under `session-slot`: it builds the session inside the task's future,
/// where a task cell of the runtime's fixed size cannot hold a peer table and a
/// reassembly router. The slot profile's form is a cell of `MulticastSlots` and
/// `spawn_multicast_pump`.
#[cfg(not(feature = "session-slot"))]
pub fn spawn_multicast_session<C, T, F, G, H, const MAX_PEERS: usize>(
    local: &CoopLocalSet<C>,
    session: MulticastSession<T, MAX_PEERS>,
    on_event: F,
    next_tx: G,
    should_stop: H,
) -> CoopLocalJoinHandle<MulticastOutcome>
where
    C: ClockSource + 'static,
    T: GroupTransport + 'static,
    F: FnMut(IterationEvent<'_>) + 'static,
    G: FnMut() -> Option<MulticastTxOffer<'static>> + 'static,
    H: FnMut() -> bool + 'static,
{
    local.spawn_local(multicast_session_task(
        local.runtime().clone(),
        session,
        on_event,
        next_tx,
        should_stop,
    ))
}

// ─────────── the multicast pump in a cell of a table the image declares ───────────
//
// Fixed-memory step S9c. The multicast session is the peer table (`MAX_PEERS`
// members), the group socket, the parameters it advertises and, with `reassembly`,
// the router that stages a fragment chain per member. Built into a future by
// `multicast_session_task` it lives wherever that future is spawned, which on the
// slot profile is a task cell of the runtime's fixed size; here it lives in a CELL of
// a table the image declares, as the unicast pump does (`PumpSlots`), and the task
// that drives it holds a reference to the cell.

/// Why a multicast pump could not be put in a cell, or its task could not be spawned.
#[cfg(feature = "session-slot")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastSpawnRefused {
    /// Every cell of the multicast table is taken. Counted by the table
    /// ([`MulticastSlots::refused`]); the session offered is dropped, which closes
    /// its group socket and gives it back to its pool.
    NoCell,
    /// The runtime's task table refused the task.
    Task(wz_runtime_coop::executor::SpawnRefusal),
}

/// One cell of a [`MulticastSlots`] table: the session, the runtime handle the pump
/// reads time from, and the pump, which borrows both for as long as the cell is
/// taken.
#[cfg(feature = "session-slot")]
struct MulticastCell<C: ClockSource + 'static, T: GroupTransport + 'static, const MAX_PEERS: usize>
{
    taken: core::cell::Cell<bool>,
    /// The JOINs the peer table of the pump in this cell has turned away, as of the last step: the
    /// pump owns the table, and this is the one number of it that is read from outside the cell, so
    /// it is kept where a reader needs no reference into the pump.
    join_refusals: core::cell::Cell<u32>,
    session: core::cell::UnsafeCell<core::mem::MaybeUninit<MulticastSession<T, MAX_PEERS>>>,
    runtime: core::cell::UnsafeCell<core::mem::MaybeUninit<CoopRuntime<C>>>,
    pump: core::cell::UnsafeCell<core::mem::MaybeUninit<MulticastPump<'static, C, T, MAX_PEERS>>>,
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource + 'static, T: GroupTransport + 'static, const MAX_PEERS: usize>
    MulticastCell<C, T, MAX_PEERS>
{
    const fn new() -> Self {
        Self {
            taken: core::cell::Cell::new(false),
            join_refusals: core::cell::Cell::new(0),
            session: core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()),
            runtime: core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()),
            pump: core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()),
        }
    }
}

/// The multicast table an image declares: `N` cells, each holding one multicast
/// session and its pump, in a `static`. The counterpart of
/// [`wz_runtime_coop::session_drive::PumpSlots`], declared the same way:
///
/// ```text
/// static GROUPS: MulticastSlots<BoardClock, BoardGroup, 4, 1> = MulticastSlots::new();
/// let pump = GROUPS.claim(runtime.clone(), session)?;
/// spawn_multicast_pump(&local, pump, on_event, || REPLIES.pop(), || false)?;
/// ```
///
/// [`claim`](MulticastSlots::claim) builds the pump IN a free cell, or refuses and
/// counts. The cell is freed (the pump dropped in place, then the runtime handle and
/// the session, so the group socket goes home to its pool) when its
/// [`MulticastRef`] is dropped, which is when the task that drives it ends or is
/// swept.
///
/// Like the other tables of the profile it is `Sync` by the profile's rule (one
/// cooperative task on one core drives the pump; claiming and freeing are critical
/// sections), not by anything a compiler can check.
#[cfg(feature = "session-slot")]
pub struct MulticastSlots<
    C: ClockSource + 'static,
    T: GroupTransport + 'static,
    const MAX_PEERS: usize,
    const N: usize,
> {
    cells: [MulticastCell<C, T, MAX_PEERS>; N],
    refused: core::cell::Cell<u32>,
}

// SAFETY: the profile's rule, stated on the type. A cell's `taken` flag is set and
// cleared inside a critical section, the cell's contents are written by its one
// claimant and reached only through that claimant's `MulticastRef`.
#[cfg(feature = "session-slot")]
unsafe impl<
        C: ClockSource + 'static,
        T: GroupTransport + 'static,
        const MAX_PEERS: usize,
        const N: usize,
    > Sync for MulticastSlots<C, T, MAX_PEERS, N>
{
}

#[cfg(feature = "session-slot")]
impl<
        C: ClockSource + 'static,
        T: GroupTransport + 'static,
        const MAX_PEERS: usize,
        const N: usize,
    > MulticastSlots<C, T, MAX_PEERS, N>
{
    /// A table of free cells.
    pub const fn new() -> Self {
        Self {
            cells: [const { MulticastCell::new() }; N],
            refused: core::cell::Cell::new(0),
        }
    }

    /// How many cells the table has.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many cells hold a session.
    pub fn in_use(&self) -> usize {
        critical_section::with(|_| self.cells.iter().filter(|cell| cell.taken.get()).count())
    }

    /// How many claims were refused for want of a free cell.
    pub fn refused(&self) -> u32 {
        critical_section::with(|_| self.refused.get())
    }

    /// How many JOINs the peer tables of the sessions the cells hold now have turned away for want
    /// of a free row ([`MulticastDispatcher::join_refusals`]), as of each pump's last step. A
    /// session that ended takes its count with it, as it takes its members.
    pub fn join_refusals(&self) -> u32 {
        critical_section::with(|_| {
            self.cells
                .iter()
                .filter(|cell| cell.taken.get())
                .fold(0u32, |sum, cell| {
                    sum.saturating_add(cell.join_refusals.get())
                })
        })
    }

    /// The bytes this table takes in the image's `.bss`, with each cell's session and
    /// pump (and, with `reassembly`, the router's staging).
    pub const fn size_bytes() -> usize {
        core::mem::size_of::<Self>()
    }

    /// Put `session` and its pump in a free cell: the dispatcher comes up (Idle to
    /// Running) and the JOIN and sweep cadences are armed, as
    /// [`MulticastPump::new`] does. Nothing of that is done when no cell is free: the
    /// session offered is dropped (its socket goes back to its pool) and the refusal
    /// is counted.
    pub fn claim(
        &'static self,
        runtime: CoopRuntime<C>,
        session: MulticastSession<T, MAX_PEERS>,
    ) -> Result<MulticastRef<C, T, MAX_PEERS>, MulticastSpawnRefused> {
        let cell =
            critical_section::with(|_| self.cells.iter().find(|cell| !cell.taken.replace(true)));
        let Some(cell) = cell else {
            critical_section::with(|_| self.refused.set(self.refused.get().saturating_add(1)));
            return Err(MulticastSpawnRefused::NoCell);
        };
        // A new session's table has turned nobody away, whatever the cell's last one did.
        critical_section::with(|_| cell.join_refusals.set(0));
        // SAFETY: the cell is `taken` by this call alone, so nothing else reaches its
        // three places, and each is uninitialised: it was never written, or the
        // `MulticastRef` that freed the cell dropped what it held. The session and
        // the runtime handle are written before the pump borrows them, the borrows
        // are `'static` because the cell is (it lies in `self`), and `Drop for
        // MulticastRef` ends the pump before either.
        unsafe {
            let session_place = (*cell.session.get()).write(session);
            let runtime_place = (*cell.runtime.get()).write(runtime);
            let MulticastSession {
                dispatcher,
                transport,
                params,
                tick_ms,
                max_iters,
            } = session_place;
            let pump = MulticastPump::new(
                dispatcher,
                MulticastDriveConfig {
                    params: &*params,
                    tick_ms: *tick_ms,
                    max_iters: *max_iters,
                },
                runtime_place,
                transport,
            );
            (*cell.pump.get()).write(pump);
        }
        Ok(MulticastRef { cell })
    }
}

#[cfg(feature = "session-slot")]
impl<
        C: ClockSource + 'static,
        T: GroupTransport + 'static,
        const MAX_PEERS: usize,
        const N: usize,
    > Default for MulticastSlots<C, T, MAX_PEERS, N>
{
    fn default() -> Self {
        Self::new()
    }
}

/// The exclusive handle to a multicast pump in its cell. Dropping it drops the pump,
/// then the runtime handle and the session, in that order, and frees the cell. The
/// task that drives a pump ([`multicast_pump_task`]) owns it.
#[cfg(feature = "session-slot")]
pub struct MulticastRef<
    C: ClockSource + 'static,
    T: GroupTransport + 'static,
    const MAX_PEERS: usize,
> {
    cell: &'static MulticastCell<C, T, MAX_PEERS>,
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource + 'static, T: GroupTransport + 'static, const MAX_PEERS: usize>
    MulticastRef<C, T, MAX_PEERS>
{
    /// The session's peer table, for a firmware that reports its group. Read through
    /// the pump that holds the table, which is the one place a reference to it is
    /// made.
    pub fn dispatcher(&self) -> &MulticastDispatcher<MAX_PEERS> {
        // SAFETY: a `MulticastRef` exists only for a cell whose pump was written by
        // `claim` and not yet dropped, and `&self` allows no step of that pump to
        // run while the borrow lasts.
        unsafe { (*self.cell.pump.get()).assume_init_ref().dispatcher() }
    }

    fn pump(&mut self) -> &mut MulticastPump<'static, C, T, MAX_PEERS> {
        // SAFETY: as for `dispatcher`, and `&mut self` is the cell's one reference.
        unsafe { (*self.cell.pump.get()).assume_init_mut() }
    }

    /// Copy the peer table's count of turned-away JOINs to where the table's owner reads it
    /// ([`MulticastSlots::join_refusals`]); a step changes it by at most one datagram's worth, so
    /// the copy is made after each step and takes the critical section only when the count moved.
    fn publish_join_refusals(&mut self) {
        let count = self.dispatcher().join_refusals();
        if count != self.cell.join_refusals.get() {
            critical_section::with(|_| self.cell.join_refusals.set(count));
        }
    }

    /// Advance the pump by one iteration, for a firmware (or a test) that drives it
    /// by hand instead of as a task; [`MulticastPump::step`] with the pump this
    /// handle holds.
    pub fn step<'s, 'g, F, G>(
        &mut self,
        on_event: &mut F,
        next_tx: &mut G,
        should_stop: Option<&mut (dyn FnMut() -> bool + 's)>,
    ) -> Option<MulticastOutcome>
    where
        F: FnMut(IterationEvent<'_>),
        G: FnMut() -> Option<MulticastTxOffer<'g>>,
    {
        let outcome = self.pump().step(on_event, next_tx, should_stop);
        self.publish_join_refusals();
        outcome
    }
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource + 'static, T: GroupTransport + 'static, const MAX_PEERS: usize> Drop
    for MulticastRef<C, T, MAX_PEERS>
{
    fn drop(&mut self) {
        // SAFETY: the cell holds this handle's pump, runtime handle and session,
        // written by `claim` and dropped only here, the pump first because it
        // borrows the other two; the flag is cleared after, so no claim can write
        // over them first.
        unsafe {
            (*self.cell.pump.get()).assume_init_drop();
            (*self.cell.runtime.get()).assume_init_drop();
            (*self.cell.session.get()).assume_init_drop();
        }
        critical_section::with(|_| self.cell.taken.set(false));
    }
}

/// The multicast session AS A TASK over a pump in a cell: the multicast twin of
/// [`wz_runtime_coop::session_drive::pump_task`]. It runs [`MulticastPump::step`]
/// once per executor pass and awaits [`yield_now`] between steps; the future is the
/// cell's handle and the observer's and the loop's state, a few dozen bytes.
#[cfg(feature = "session-slot")]
pub async fn multicast_pump_task<'g, C, T, F, G, H, const MAX_PEERS: usize>(
    mut pump: MulticastRef<C, T, MAX_PEERS>,
    mut on_event: F,
    mut next_tx: G,
    mut should_stop: H,
) -> MulticastOutcome
where
    C: ClockSource + 'static,
    T: GroupTransport + 'static,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxOffer<'g>>,
    H: FnMut() -> bool,
{
    loop {
        let outcome = pump
            .pump()
            .step(&mut on_event, &mut next_tx, Some(&mut should_stop));
        pump.publish_join_refusals();
        if let Some(outcome) = outcome {
            return outcome;
        }
        yield_now().await;
    }
}

/// Host the pump in `pump` as a task of `local`: the answer is the task's handle,
/// or why the runtime's task table refused it (counted by that table; the pump, which
/// this call owns, is dropped with its cell and its group socket).
#[cfg(feature = "session-slot")]
pub fn spawn_multicast_pump<C, T, F, G, H, const MAX_PEERS: usize>(
    local: &CoopLocalSet<C>,
    pump: MulticastRef<C, T, MAX_PEERS>,
    on_event: F,
    next_tx: G,
    should_stop: H,
) -> Result<CoopLocalJoinHandle<MulticastOutcome>, MulticastSpawnRefused>
where
    C: ClockSource + 'static,
    T: GroupTransport + 'static,
    F: FnMut(IterationEvent<'_>) + 'static,
    G: FnMut() -> Option<MulticastTxOffer<'static>> + 'static,
    H: FnMut() -> bool + 'static,
{
    local
        .spawn_local(multicast_pump_task(pump, on_event, next_tx, should_stop))
        .map_err(|refused| MulticastSpawnRefused::Task(refused.why))
}

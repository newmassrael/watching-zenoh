// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The simulated world a unit test of the engine runs in (`docs/deterministic-tests.md`): an
//! in-memory network of datagram ends, a clock that moves only when the test moves it, entropy
//! drawn from the test's seed, and a router stand-in that runs on the test's own thread.
//!
//! The stand-in runs when the session under test waits on its links, or when the test turns the
//! world. A wait takes no time: it turns the world and then finds ready exactly the links whose
//! ends hold a datagram, as the host's poll would have. Nothing here reads the host's clock, binds
//! a socket or starts a thread, so a test is a function of its script and its seed, and a failure
//! is the same failure on every run.
//!
//! The session's links are waited on by their owner (`SessionDatagramLink::input_wait`), as the
//! host's links the engine opens are (`waited_by_owner`): the engine's reads that trust a wait to
//! tell them which links to read run here as they run on a host. The stand-in's end waits in its
//! own loop, as the stand-in of the host tests does.
//!
//! An end receives as the host's datagram link does (`UdpDriver`): it lends each datagram from a
//! buffer of its own, where the datagram lies until the end's next receive, and lends one it was
//! told to keep again from there. The round's form reads a record's parts only where its link
//! lent them, so an end that handed out a copy would have every sample with a payload refused.

use std::cell::{Cell, RefCell, UnsafeCell};
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use wz_capi_port::SessionDrive;
use wz_runtime_coop::link_cells::{CellRc, CountKind, OneTask};
use wz_runtime_coop::link_storage::{copied_receive, RxDrops, TxLender, TxStore};
use wz_runtime_coop::session_drive::{
    spawn_session, Dialled, LinkOpenError, LinkProto, LinkWait, LinkWaits, Locator, OpenedLink,
    SessionDatagramLink, SessionDriveConfig, SessionLinks, SessionRole, WaitOn,
};
use wz_runtime_coop::session_runtime::{new_session_actions, SessionEntropy, SessionHandle};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::datagram_peer::PeerBinding;
use wz_session_core::driver_loop::{DriverLoopOutcome, DriverOutcome, IterationEvent};
use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEnds, LinkSendOutcome, RxFrame, TxSlot, TxSlotGrant,
    DEFAULT_LINK_MTU, SESSION_TX_SLOTS,
};
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_core::WhatAmI;
use wz_session_mcu::app_layer::dispatch_to;

use super::{client_config, params, CatchAll, Seen, ROUTER_ZID};
use crate::{CoopConfig, CoopEngine, EngineHold};

/// Where the router stand-in accepts, which the session under test dials.
pub(super) const STAND_IN_AT: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 7447);

/// The host the session under test opens its links on.
const SESSION_HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

/// The first port a dial is given: the start of the dynamic range.
const FIRST_EPHEMERAL_PORT: u16 = 49_152;

/// The most steps a test's wait for an outcome makes: a bound against a script that never
/// brings the outcome about, which no outcome a test waits for comes near.
const STEPS: usize = 4_096;

/// The passes of its local set the stand-in makes in one turn at most. A turn ends once
/// [`QUIET_PASSES`] passes in a row moved nothing; one that never does is a defect of the script.
const TURN_PASSES: usize = 1_024;

/// The passes in a row that move nothing, after which the stand-in has done what it can with
/// what it holds.
const QUIET_PASSES: usize = 8;

/// The waits in a row on a world that moved nothing, after which the session is waiting for
/// something the script never sends: a test that would otherwise spin for ever fails.
const QUIET_WAITS: u32 = 100_000;

/// A seed's second stream, so the stand-in's draws are not the session's.
const STAND_IN_STREAM: u64 = 0x5354_414e_445f_494e;

/// The engine a simulated test opens.
pub(super) type SimEngine = CoopEngine<SimLinks, SetClock>;

/// A clock that reads what the test set, in microseconds, and moves only when the test moves it.
#[derive(Clone)]
pub(super) struct SetClock(pub(super) Arc<AtomicU64>);

impl SetClock {
    fn advance_ms(&self, ms: u64) {
        self.0.fetch_add(ms.saturating_mul(1000), Ordering::SeqCst);
    }
}

impl ClockSource for SetClock {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Entropy drawn from a seed (splitmix64): the cookies and nonces of a run are the seed's.
struct SeededEntropy(u64);

impl EntropySource for SeededEntropy {
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        for chunk in buf.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut word = self.0;
            word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            word ^= word >> 31;
            let bytes = word.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

/// One datagram waiting at an end: who sent it and what it carries.
struct Datagram {
    from: SocketAddr,
    bytes: Vec<u8>,
}

/// Where an end is bound.
enum Claim {
    /// At this address and port.
    At(SocketAddr),
    /// On this host, at a port of the dynamic range nobody holds.
    Ephemeral(IpAddr),
}

/// The network's state: the datagrams waiting at each bound end, the handle each end is waited
/// on by, and what each end sent.
#[derive(Default)]
struct NetState {
    queues: BTreeMap<SocketAddr, VecDeque<Datagram>>,
    ends: BTreeMap<usize, SocketAddr>,
    sent: BTreeMap<SocketAddr, usize>,
    next_id: usize,
    next_port: u16,
}

impl NetState {
    /// Whether a wait on `wait` finds it ready: room is always there, and input is a datagram
    /// waiting at the end the handle names.
    fn finds_ready(&self, wait: &LinkWait) -> bool {
        if wait.room {
            return true;
        }
        match wait.on {
            WaitOn::Socket(id) => self
                .ends
                .get(&id)
                .and_then(|at| self.queues.get(at))
                .is_some_and(|queue| !queue.is_empty()),
            _ => false,
        }
    }

    /// The address `claim` names, registered with a handle of its own; `None` when it is held,
    /// or when the dynamic range of its host is full.
    fn claim(&mut self, claim: Claim) -> Option<(usize, SocketAddr)> {
        let at = match claim {
            Claim::At(at) => (!self.queues.contains_key(&at)).then_some(at)?,
            Claim::Ephemeral(host) => {
                let span = u16::MAX - FIRST_EPHEMERAL_PORT;
                (0..=span).find_map(|_| {
                    let port = self.next_port.max(FIRST_EPHEMERAL_PORT);
                    self.next_port = port.checked_add(1).unwrap_or(FIRST_EPHEMERAL_PORT);
                    let at = SocketAddr::new(host, port);
                    (!self.queues.contains_key(&at)).then_some(at)
                })?
            }
        };
        let id = self.next_id;
        self.next_id = id.wrapping_add(1);
        self.queues.insert(at, VecDeque::new());
        self.ends.insert(id, at);
        Some((id, at))
    }
}

/// The in-memory network, shared by every end bound on it.
#[derive(Clone, Default)]
struct Net(Arc<Mutex<NetState>>);

impl Net {
    fn state(&self) -> MutexGuard<'_, NetState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// An end bound where `claim` says, sending to `peer` (`None`: it learns its peer from the
    /// first `InitSyn` it takes), its handles counted as `N` counts them. `owner_waits`: its
    /// owner waits for its input rather than its own loop.
    fn bind<N: CountKind>(
        &self,
        claim: Claim,
        peer: Option<SocketAddr>,
        owner_waits: bool,
    ) -> Result<OpenedLink<CellRc<SimEnd, N>, N>, LinkOpenError> {
        let (id, local) = self
            .state()
            .claim(claim)
            .ok_or(LinkOpenError::AddressInUse)?;
        let end = SimEnd {
            net: self.clone(),
            local,
            id,
            binding: match peer {
                Some(peer) => PeerBinding::dialled(peer),
                None => PeerBinding::accepting(),
            },
            owner_waits,
            tx: TxLender::new(SimTx::new()),
            rx: RefCell::new(Vec::new()),
            kept: Cell::new(false),
            keeping: Cell::new(false),
            rx_drops: RxDrops::new(),
        };
        let end = CellRc::<SimEnd, N>::try_on_heap(end).ok_or(LinkOpenError::Exhausted)?;
        Ok(OpenedLink {
            sink: end.clone().into_sink(),
            pump: end,
        })
    }

    /// `bytes` from `from` to the end at `to`; a datagram for an end nobody bound is lost, as
    /// UDP loses it.
    fn deliver(&self, from: SocketAddr, to: SocketAddr, bytes: &[u8]) {
        let mut state = self.state();
        *state.sent.entry(from).or_default() += 1;
        if let Some(queue) = state.queues.get_mut(&to) {
            queue.push_back(Datagram {
                from,
                bytes: bytes.to_vec(),
            });
        }
    }

    /// The datagrams waiting at `at` and the datagrams it sent.
    fn counts_at(&self, at: SocketAddr) -> (usize, usize) {
        let state = self.state();
        (
            state.queues.get(&at).map_or(0, VecDeque::len),
            state.sent.get(&at).copied().unwrap_or(0),
        )
    }

    /// The datagrams waiting at the ends bound on `host`.
    fn waiting_on(&self, host: IpAddr) -> usize {
        self.state()
            .queues
            .iter()
            .filter(|(at, _)| at.ip() == host)
            .map(|(_, queue)| queue.len())
            .sum()
    }
}

/// An end's outbound storage: the slots its session needs, each the largest frame a link carries.
pub(super) struct SimTx(Vec<UnsafeCell<u8>>);

impl SimTx {
    fn new() -> Self {
        Self(
            (0..SESSION_TX_SLOTS * DEFAULT_LINK_MTU)
                .map(|_| UnsafeCell::new(0))
                .collect(),
        )
    }
}

impl TxStore for SimTx {
    fn slots(&self) -> usize {
        SESSION_TX_SLOTS
    }

    fn slot_len(&self) -> usize {
        DEFAULT_LINK_MTU
    }

    fn slot_base(&self, slot: usize) -> *mut u8 {
        // `UnsafeCell<u8>` is a `u8`, and a pointer to a cell may be written through.
        self.0
            .as_ptr()
            .cast::<u8>()
            .cast_mut()
            .wrapping_add(slot.saturating_mul(DEFAULT_LINK_MTU))
    }
}

/// One end of a link on the simulated network: its session's outbound sink and its drive loop's
/// inbound pump in one object.
pub(super) struct SimEnd {
    net: Net,
    local: SocketAddr,
    id: usize,
    binding: PeerBinding<SocketAddr>,
    owner_waits: bool,
    tx: TxLender<SimTx>,
    /// The datagram the last receive lent, which lies here until the next receive.
    rx: RefCell<Vec<u8>>,
    /// Whether the datagram lent is kept, for the next receive to lend again.
    kept: Cell<bool>,
    /// Whether the receive under way was asked to keep its datagram.
    keeping: Cell<bool>,
    /// The datagrams the copying receive found no heap room to copy.
    rx_drops: RxDrops,
}

impl SimEnd {
    /// The next datagram from the end's peer: one from anyone else is let go of, as a host's
    /// datagram link lets it go.
    fn next_admitted(&self) -> Option<Vec<u8>> {
        loop {
            let datagram = self.net.state().queues.get_mut(&self.local)?.pop_front()?;
            if self
                .binding
                .admit(datagram.from, &datagram.bytes)
                .is_taken()
            {
                return Some(datagram.bytes);
            }
        }
    }
}

impl Drop for SimEnd {
    fn drop(&mut self) {
        let mut state = self.net.state();
        state.queues.remove(&self.local);
        state.ends.remove(&self.id);
        state.sent.remove(&self.local);
    }
}

impl BoxedLinkDriver for SimEnd {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        let Some(peer) = self.binding.peer() else {
            // An acceptor that has taken no `InitSyn` has nobody to answer.
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        };
        self.net.deliver(self.local, peer, bytes);
        LinkSendOutcome::Sent
    }

    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        // A datagram carries no framing of the link's own, so the frame starts at the slot's front.
        self.tx.acquire(0)
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        self.tx.storage(slot)
    }

    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        match self.tx.take(slot, start, len) {
            Some(frame) => self.send_blocking(frame, reliability),
            None => LinkSendOutcome::Dropped(LinkDropCause::Oversize),
        }
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.tx.release(slot);
    }

    fn open_blocking(&self) {}

    fn close_blocking(&self) {}

    fn link_ends(&self) -> Option<LinkEnds<'_>> {
        let peer = self.binding.peer()?;
        Some(LinkEnds::ip(LinkProto::Udp.kind(), self.local, peer))
    }
}

impl SessionDatagramLink for SimEnd {
    fn service(&self) {}

    // The datagram the lending receive hands over, copied out, as the host's link copies it.
    fn try_recv(&self) -> Option<RxFrame> {
        copied_receive(self, &self.rx_drops)
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        // A receive from inside `f` finds the buffer lent and reads nothing.
        let Ok(mut rx) = self.rx.try_borrow_mut() else {
            return false;
        };
        if !self.kept.replace(false) {
            let Some(datagram) = self.next_admitted() else {
                return false;
            };
            *rx = datagram;
        }
        self.keeping.set(false);
        f(rx.as_slice());
        self.kept.set(self.keeping.replace(false));
        true
    }

    fn take_rx_dropped(&self) -> usize {
        self.rx_drops.take()
    }

    // A kept datagram is input the end took from the network already: no wait finds it, and the
    // next receive lends it again.
    fn holds_input(&self) -> bool {
        self.kept.get()
    }

    fn keeps_input(&self) -> bool {
        true
    }

    fn keep(&self) {
        self.keeping.set(true);
    }

    // The buffer is written by a receive alone, so what a receive lent lies there until the next.
    fn lends_until_next_receive(&self) -> bool {
        true
    }

    wz_runtime_coop::with_heap_link_seams! {
        fn input_wait(&self) -> Option<WaitOn> {
            self.owner_waits.then_some(WaitOn::Socket(self.id))
        }
    }
}

/// The links of the session under test, on the simulated network.
pub(super) struct SimLinks {
    net: Net,
    host: IpAddr,
}

impl SessionLinks<crate::LinkCount> for SimLinks {
    type Pump = CellRc<SimEnd, crate::LinkCount>;

    type Dial = Dialled<Self::Pump, crate::LinkCount>;

    wz_runtime_coop::with_heap_link_seams! {
        type Waits = SimWaits;

        fn waits(&self) -> SimWaits {
            SimWaits {
                net: self.net.clone(),
            }
        }
    }

    fn open_acceptor(
        &self,
        port: u16,
    ) -> Result<OpenedLink<Self::Pump, crate::LinkCount>, LinkOpenError> {
        self.net
            .bind(Claim::At(SocketAddr::new(self.host, port)), None, true)
    }

    fn open_initiator(
        &self,
        to: Locator,
    ) -> Result<OpenedLink<Self::Pump, crate::LinkCount>, LinkOpenError> {
        // The network carries datagrams, as the UDP link it stands in for does.
        let Some(ip) = to.as_ip() else {
            return Err(LinkOpenError::Unsupported);
        };
        if ip.proto != LinkProto::Udp {
            return Err(LinkOpenError::Unsupported);
        }
        self.net
            .bind(Claim::Ephemeral(self.host), Some(ip.at), true)
    }
}

/// The waits of the session's links: a wait turns the world and finds ready the links whose ends
/// hold a datagram, at once and whatever its bound.
#[derive(Clone)]
pub(super) struct SimWaits {
    net: Net,
}

impl LinkWaits for SimWaits {
    fn wait(&self, on: &[LinkWait], timeout_ms: u32) {
        let mut on = on.to_vec();
        self.wait_ready(&mut on, timeout_ms);
    }

    fn wait_ready(&self, on: &mut [LinkWait], timeout_ms: u32) -> usize {
        WORLD.with(|world| world.asked(timeout_ms));
        let moved = turn_world();
        let ready = {
            let state = self.net.state();
            on.sort_by_key(|wait| !state.finds_ready(wait));
            on.iter().take_while(|wait| state.finds_ready(wait)).count()
        };
        WORLD.with(|world| world.waited(moved || ready > 0));
        ready
    }

    fn wait_room(&self, on: WaitOn, timeout_us: u64) -> bool {
        let _ = (on, timeout_us);
        true
    }
}

/// What the simulation of this thread holds: its stand-ins, the bounds of the waits the session
/// asked, and how many waits in a row found the world still. A thread no simulation runs on (a
/// read task the engine started) turns nothing and records nothing.
#[derive(Default)]
struct World {
    live: Cell<bool>,
    stand_ins: RefCell<Vec<Weak<StandInInner>>>,
    waits: RefCell<Vec<u32>>,
    quiet: Cell<u32>,
}

impl World {
    fn asked(&self, timeout_ms: u32) {
        if self.live.get() {
            self.waits.borrow_mut().push(timeout_ms);
        }
    }

    fn waited(&self, progress: bool) {
        if !self.live.get() || progress {
            self.quiet.set(0);
            return;
        }
        let quiet = self.quiet.get().saturating_add(1);
        self.quiet.set(quiet);
        assert!(
            quiet < QUIET_WAITS,
            "the session waited {QUIET_WAITS} times on a world that never moved"
        );
    }

    fn moved(&self) {
        self.quiet.set(0);
    }
}

std::thread_local! {
    static WORLD: World = World::default();
}

/// Turn every stand-in of this thread's world: whether any of them moved.
fn turn_world() -> bool {
    let stand_ins: Vec<Rc<StandInInner>> = WORLD.with(|world| {
        world
            .stand_ins
            .borrow()
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    });
    let mut moved = false;
    for stand_in in &stand_ins {
        moved |= stand_in.turn();
    }
    moved
}

/// One simulation: its network, its clock and its seed. Made at the start of a test, on the
/// test's thread, which its world is.
pub(super) struct Sim {
    net: Net,
    clock: SetClock,
    seed: u64,
}

impl Sim {
    /// A simulation of `seed`, its clock at zero and nothing bound.
    pub(super) fn new(seed: u64) -> Self {
        WORLD.with(|world| {
            world.live.set(true);
            world.stand_ins.borrow_mut().clear();
            world.waits.borrow_mut().clear();
            world.quiet.set(0);
        });
        Self {
            net: Net::default(),
            clock: SetClock(Arc::new(AtomicU64::new(0))),
            seed,
        }
    }

    /// A client's config that dials the stand-in's address and redials none.
    pub(super) fn config(&self) -> CoopConfig {
        CoopConfig {
            endpoints: vec![format!("udp/{STAND_IN_AT}")],
            ..client_config()
        }
    }

    /// The session `config` opens on the simulated network, on the simulation's clock, its
    /// entropy the seed's. The open's waits turn the world, so a stand-in answers its handshake.
    pub(super) fn open(&self, config: CoopConfig) -> EngineHold<SimEngine> {
        CoopEngine::open(
            SimLinks {
                net: self.net.clone(),
                host: SESSION_HOST,
            },
            self.clock.clone(),
            SeededEntropy(self.seed),
            config,
        )
        .expect("the session opens")
    }

    /// A router stand-in accepting at [`STAND_IN_AT`], with the router's catch-all subscriber or
    /// without it.
    pub(super) fn stand_in(&self, catch_all: CatchAll) -> StandIn {
        let OpenedLink { sink, pump } = self
            .net
            .bind::<OneTask>(Claim::At(STAND_IN_AT), None, false)
            .expect("the stand-in's address is free");
        let runtime = CoopRuntime::try_new(self.clock.clone()).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let actions = new_session_actions(
            sink,
            params(WhatAmI::Router, ROUTER_ZID),
            CoopTime::new(&runtime),
        )
        .expect("the heap has room");
        let seen = Arc::new(Mutex::new(Seen::default()));
        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
        if catch_all == CatchAll::Held {
            let samples = seen.clone();
            observer
                .borrow_mut()
                .register_subscriber(
                    "**",
                    Locality::Any,
                    BoxedSink::new(move |sample: &dyn SampleView| {
                        samples
                            .lock()
                            .unwrap()
                            .samples
                            .push((sample.keyexpr().to_owned(), sample.payload().to_vec()));
                    }),
                )
                .expect("the stand-in's catch-all");
        }
        let mut dispatch = dispatch_to(observer, actions.clone());
        let counted = seen.clone();
        let task = spawn_session(
            &local,
            pump,
            actions.clone(),
            SessionEntropy::try_new(SeededEntropy(self.seed ^ STAND_IN_STREAM))
                .expect("the heap has room"),
            CoopTime::new(&runtime),
            SessionDriveConfig {
                timeouts: SessionTimeouts::spec_defaults(),
                role: SessionRole::Acceptor,
                max_iters: None,
            },
            move |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) =
                    event
                {
                    let declares = messages
                        .iter()
                        .filter(|m| matches!(m, NetworkMessage::Declare(_)))
                        .count();
                    counted.lock().unwrap().declares += declares;
                }
                if let IterationEvent::InPlace(record) = event {
                    if record.declare().is_some() {
                        counted.lock().unwrap().declares += 1;
                    }
                }
                dispatch(event);
            },
        );
        let inner = Rc::new(StandInInner {
            _task: task,
            actions,
            local,
            _runtime: runtime,
            seen,
            frozen: Cell::new(false),
            net: self.net.clone(),
            at: STAND_IN_AT,
        });
        WORLD.with(|world| {
            let mut stand_ins = world.stand_ins.borrow_mut();
            stand_ins.retain(|held| held.strong_count() > 0);
            stand_ins.push(Rc::downgrade(&inner));
        });
        StandIn { inner }
    }

    /// Turn the world: each stand-in does what it can with what it holds.
    pub(super) fn turn(&self) {
        turn_world();
        WORLD.with(World::moved);
    }

    /// Move the clock on by `ms`.
    pub(super) fn advance_ms(&self, ms: u64) {
        self.clock.advance_ms(ms);
        WORLD.with(World::moved);
    }

    /// The datagrams waiting at the session's ends, read by none of its steps yet.
    pub(super) fn waiting_for_the_session(&self) -> usize {
        self.net.waiting_on(SESSION_HOST)
    }

    /// The bounds of the waits the session asked of its links since the last take, in order.
    pub(super) fn take_waits(&self) -> Vec<u32> {
        WORLD.with(|world| core::mem::take(&mut *world.waits.borrow_mut()))
    }

    /// Step `engine` with the bound `most_ms` and turn the world after each step, until
    /// `done`, the clock standing still.
    pub(super) fn steps_until(
        &self,
        engine: &SimEngine,
        most_ms: u32,
        what: &str,
        done: impl FnMut() -> bool,
    ) {
        self.steps(engine, most_ms, 0, what, done);
    }

    /// [`Self::steps_until`], the clock moved on by `step_ms` after each step: a step's bound
    /// of time passes for each.
    pub(super) fn steps_with_time(
        &self,
        engine: &SimEngine,
        step_ms: u32,
        what: &str,
        done: impl FnMut() -> bool,
    ) {
        self.steps(engine, step_ms, u64::from(step_ms), what, done);
    }

    fn steps(
        &self,
        engine: &SimEngine,
        most_ms: u32,
        advance_ms: u64,
        what: &str,
        mut done: impl FnMut() -> bool,
    ) {
        for _ in 0..STEPS {
            if done() {
                return;
            }
            SessionDrive::step_once(engine, most_ms)
                .expect("a session without its read task steps");
            self.turn();
            self.advance_ms(advance_ms);
        }
        assert!(
            done(),
            "{what} did not come within {STEPS} steps (seed {:#x})",
            self.seed
        );
    }
}

impl Drop for Sim {
    fn drop(&mut self) {
        WORLD.with(|world| world.live.set(false));
    }
}

/// A router stand-in on the test's thread: a plain acceptor session, run when the world turns.
pub(super) struct StandIn {
    inner: Rc<StandInInner>,
}

impl StandIn {
    /// Read what reached the stand-in.
    pub(super) fn seen<T>(&self, read: impl FnOnce(&Seen) -> T) -> T {
        read(&self.inner.seen.lock().unwrap())
    }

    /// Push `value` on `key` to the session; it leaves when the world next turns.
    pub(super) fn push(&self, key: &str, value: &[u8]) {
        let _ = self.inner.actions.send_push_literal(key, value, true);
    }

    /// Read nothing and send nothing from now on, the end held until the stand-in is let go of,
    /// as a node that hangs: only the session's lease can end the link.
    pub(super) fn freeze(&self) {
        self.inner.frozen.set(true);
    }
}

/// What a stand-in holds, in the order it is let go of: its session's task first, its runtime
/// last.
struct StandInInner {
    _task: CoopLocalJoinHandle<DriverOutcome>,
    actions: SessionHandle<SetClock>,
    local: CoopLocalSet<SetClock>,
    _runtime: CoopRuntime<SetClock>,
    seen: Arc<Mutex<Seen>>,
    frozen: Cell<bool>,
    net: Net,
    at: SocketAddr,
}

impl StandInInner {
    /// Pass the stand-in's local set until it moves nothing more: whether it moved.
    fn turn(&self) -> bool {
        if self.frozen.get() {
            return false;
        }
        let mut last = self.fingerprint();
        let mut moved = false;
        let mut quiet = 0;
        for _ in 0..TURN_PASSES {
            self.local.run_until_idle();
            let now = self.fingerprint();
            if now == last {
                quiet += 1;
                if quiet == QUIET_PASSES {
                    return moved;
                }
            } else {
                quiet = 0;
                moved = true;
                last = now;
            }
        }
        panic!("the stand-in did not settle within {TURN_PASSES} passes");
    }

    /// What a pass of the stand-in can move: what waits at its end, what it sent, and what
    /// reached its tables.
    fn fingerprint(&self) -> (usize, usize, usize, usize) {
        let (waiting, sent) = self.net.counts_at(self.at);
        let seen = self.seen.lock().unwrap();
        (waiting, sent, seen.declares, seen.samples.len())
    }
}

impl Drop for StandInInner {
    fn drop(&mut self) {
        // The session's task holds the stand-in's end: it goes first, so the address is free
        // for a stand-in made after this one.
        self.local.drop_tasks();
    }
}

/// An end lends what it received from where it lies until its next receive, and lends a datagram
/// it was told to keep again from the same place, holding it as input meanwhile, as the host's
/// datagram link does: the round's form reads a record's parts only where its link lent them. A
/// datagram from anyone but the end's peer is let go of. The CONTROL is the copying receive, which
/// hands the next datagram's bytes. Turned red by an end that hands out a copy it lets go of (what
/// it lends said not to stay, a kept datagram not lent again), and by a kept datagram not held as
/// input, which a read's wait would pass over.
#[test]
fn an_end_lends_what_it_received_where_it_lies_until_its_next_receive() {
    let net = Net::default();
    let peer = SocketAddr::new(SESSION_HOST, FIRST_EPHEMERAL_PORT);
    let stranger = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), FIRST_EPHEMERAL_PORT);
    let OpenedLink { pump: end, .. } = net
        .bind::<OneTask>(Claim::At(STAND_IN_AT), Some(peer), false)
        .expect("the address is free");
    assert!(
        end.lends_until_next_receive(),
        "what an end lends stays where it lies until its next receive"
    );
    assert!(end.keeps_input(), "an end keeps a datagram it is told to");
    net.deliver(peer, STAND_IN_AT, b"first");
    net.deliver(stranger, STAND_IN_AT, b"stray");
    net.deliver(peer, STAND_IN_AT, b"second");
    net.deliver(peer, STAND_IN_AT, b"third");

    let mut lent = None;
    assert!(end.recv_with(&mut |datagram: &[u8]| {
        lent = Some((datagram.as_ptr(), datagram.to_vec()));
        end.keep();
    }));
    assert_eq!(
        lent.as_ref().map(|(_, bytes)| bytes.as_slice()),
        Some(&b"first"[..])
    );
    assert!(end.holds_input(), "a kept datagram is input the end holds");
    let mut again = None;
    assert!(end.recv_with(&mut |datagram: &[u8]| {
        again = Some((datagram.as_ptr(), datagram.to_vec()));
    }));
    assert_eq!(
        again, lent,
        "a kept datagram is lent again from where it lies"
    );
    assert!(
        !end.holds_input(),
        "a datagram lent and not kept is not held"
    );

    let mut next = Vec::new();
    assert!(end.recv_with(&mut |datagram: &[u8]| next = datagram.to_vec()));
    assert_eq!(next, b"second", "the stranger's datagram is let go of");
    let copied = end
        .try_recv()
        .expect("CONTROL: the copying receive takes the next datagram");
    assert_eq!(copied.bytes, b"third");
    assert!(
        !end.recv_with(&mut |_: &[u8]| {}),
        "nothing is lent once no datagram waits"
    );
}

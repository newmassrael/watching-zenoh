// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the SESSION PUMP and the RUNTIME under it cost the heap on the MCU
//! profile, counted (fixed-memory step S6, ARCHITECTURE section 9.1).
//!
//! `session_slot_allocations` counts the session itself (its state, its
//! handshake, its messages) and drives it by calling the pump's `step` from the
//! test. A real image does not: it runs each session as a TASK on the cooperative
//! executor, so the executor, the timer queue, the pump each session owns and
//! the task that hosts it are on the path of every session and every turn. This
//! file counts those, a real pair (an acceptor and an initiator) over the host
//! lwIP loopback, each run as a task of one local set:
//!
//! - RUNTIME: the runtime, its task pool and timer queue, and the local set that
//!   hosts the tasks, made;
//! - PUMP: each end's pump made (its engine, its record buffer, the handles it
//!   holds);
//! - SPAWN: each pump hosted as a task;
//! - HANDSHAKE and STEADY STATE: the pair driven by executor passes alone, to
//!   Established, a Put each way at several sizes, a KeepAlive each way, idle
//!   passes;
//! - TIMER: a task that sleeps registers a deadline, which fires when the clock
//!   moves, and one that is aborted is swept;
//! - CLOSE: the initiator's Close, the acceptor's task ending, its join handle
//!   read, and every cell of every table free again.
//!
//! With `session-slot` (the MCU profile's: the pump lives in a cell of a table the
//! image declares, the task in a cell of the runtime's task table, the deadline in
//! its timer table) every window must cost the heap NOTHING, and a full table is a
//! COUNTED refusal that costs it nothing either. Without it (the profile every
//! shipped image and the AP run today) the windows that make or host something
//! must cost it something: that half is the instrument's own control, since a
//! count that read zero on the state that is known to hold boxes, vectors and
//! reference counts would prove nothing about the state that is meant not to.
//!
//! The count is ATTRIBUTED to the measurement's own thread, as `tx_allocations`
//! and `session_slot_allocations` do, and every lwIP test holds the harness's lock
//! for its whole body.
//!
//! Set `WZ_ALLOC_SITES=1` to print, for every window, where in this workspace each
//! counted allocation was made.
//!
//! Host-test level: no board runs it, and the stack the pump takes is not
//! measured here.

// A refused claim hands back what it was offered, which is what makes the refusal
// free of the heap; boxing it would allocate.
#![allow(clippy::result_large_err)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wz_link_lwip::rx_sockets::{bind_session_rx, SessionRxSocket};
use wz_link_lwip::{ipv4_addr_from_octets, LwipLink};
#[cfg(not(feature = "session-slot"))]
use wz_runtime_coop::session_drive::SessionPump;
use wz_runtime_coop::session_drive::{SessionDriveConfig, SessionRole};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{
    yield_now, ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime,
};
use wz_runtime_core::TimeSource;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::locality::Locality;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::BoxedSink;
use wz_session_core::WhatAmI;
use wz_session_lwip::driver::{share_socket, LwipUdpDriver};
use wz_session_lwip::{app_layer, LwipSessionLink};

/// Counts the allocations of the measurement the allocating thread works for.
struct CountingAllocator;

/// One measurement's count: whether its window is open, what its threads
/// allocated while it was, and (when asked for) where.
struct Tally {
    open: AtomicBool,
    allocations: AtomicUsize,
    capture_sites: bool,
    sites: Mutex<BTreeMap<String, usize>>,
}

thread_local! {
    /// The measurement this thread works for, if any. `const` initialisation of
    /// a destructor-free type, so reading it from inside `alloc` cannot itself
    /// allocate.
    static OWNER: Cell<Option<&'static Tally>> = const { Cell::new(None) };
    /// Set while the site of an allocation is being recorded, so the
    /// allocations the recording makes are not counted as the session's.
    static RECORDING: Cell<bool> = const { Cell::new(false) };
}

/// One allocation, counted against the allocating thread's measurement when
/// that measurement's window is open.
fn count_one() {
    if RECORDING.with(Cell::get) {
        return;
    }
    if let Some(tally) = OWNER.with(Cell::get) {
        if tally.open.load(Ordering::SeqCst) {
            tally.allocations.fetch_add(1, Ordering::SeqCst);
            if tally.capture_sites {
                RECORDING.with(|r| r.set(true));
                record_site(tally);
                RECORDING.with(|r| r.set(false));
            }
        }
    }
}

/// Where the allocation being made was asked for: the first frames of the
/// backtrace whose source is in this workspace.
fn record_site(tally: &Tally) {
    let text = std::backtrace::Backtrace::force_capture().to_string();
    let mut frames: Vec<String> = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let Some((_, symbol)) = line.trim_start().split_once(": ") else {
            continue;
        };
        let at = lines
            .peek()
            .filter(|next| next.trim_start().starts_with("at "))
            .map(|next| next.trim_start().trim_start_matches("at ").to_string());
        let Some(at) = at else { continue };
        let ours = at.contains("/crates/") || at.contains("/out/") || at.contains("/vendor/");
        if !ours || symbol.starts_with("record_site") || symbol.starts_with("count_one") {
            continue;
        }
        let symbol = symbol.rsplit_once("::h").map_or(symbol, |(head, _)| head);
        let place = at.rsplit('/').next().unwrap_or(&at).to_string();
        frames.push(format!("{symbol} ({place})"));
        if frames.len() == 5 {
            break;
        }
    }
    let key = frames.join("  <-  ");
    *tally
        .sites
        .lock()
        .expect("not poisoned")
        .entry(key)
        .or_insert(0) += 1;
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a read
// of a thread-local without a destructor and an atomic bump, neither of which
// allocates or unwinds. The recording of a site allocates, behind a flag that
// makes the allocator ignore the allocations the recording itself makes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_one();
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_one();
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_one();
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// A measurement owned by the test thread that made it, with a tally of its own.
struct Measurement {
    tally: &'static Tally,
}

impl Measurement {
    /// The calling thread works for the new measurement until it drops. The tally
    /// is leaked, a few bytes per test, so a thread that outlives the
    /// measurement and still reads it never reads freed memory.
    fn new() -> Self {
        let tally: &'static Tally = Box::leak(Box::new(Tally {
            open: AtomicBool::new(false),
            allocations: AtomicUsize::new(0),
            capture_sites: std::env::var_os("WZ_ALLOC_SITES").is_some(),
            sites: Mutex::new(BTreeMap::new()),
        }));
        OWNER.with(|owner| owner.set(Some(tally)));
        Self { tally }
    }

    /// Run `f` and return its result with the allocations this measurement's
    /// threads made while it ran.
    fn count<R>(&self, what: &str, f: impl FnOnce() -> R) -> (R, usize) {
        self.tally.sites.lock().expect("not poisoned").clear();
        let before = self.tally.allocations.load(Ordering::SeqCst);
        self.tally.open.store(true, Ordering::SeqCst);
        let out = f();
        self.tally.open.store(false, Ordering::SeqCst);
        let n = self.tally.allocations.load(Ordering::SeqCst) - before;
        if self.tally.capture_sites && n > 0 {
            println!("--- {what}: {n} allocation(s), by site");
            for (site, count) in self.tally.sites.lock().expect("not poisoned").iter() {
                println!("  {count:4} x {site}");
            }
        }
        (out, n)
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        OWNER.with(|owner| owner.set(None));
    }
}

/// The clock of the test: it stands where the test left it, so no deadline
/// fires unless the test moves it.
#[derive(Clone, Default)]
struct Clk;
static NOW_US: AtomicU64 = AtomicU64::new(0);
impl ClockSource for Clk {
    fn now_us(&self) -> u64 {
        NOW_US.load(Ordering::SeqCst)
    }
}

/// A deterministic stand-in for a board's TRNG (the acceptor mints a cookie).
struct Counting(u8);
impl wz_session_core::entropy::EntropySource for Counting {
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
        for b in buf {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}

type Rt = CoopRuntime<Clk>;
type Handle = SessionHandle<Clk>;

/// The init parameters of a session whose zid is four bytes of `zid`, written the
/// same way on every profile.
fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[zid; 4]),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: cookie_bytes(&[]),
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        cookie_signing_key: SigningKey::from_slice(&[7u8; 32]).expect("key"),
    }
}

fn config(role: SessionRole) -> SessionDriveConfig {
    SessionDriveConfig {
        timeouts: SessionTimeouts::spec_defaults(),
        role,
        max_iters: None,
    }
}

const KEY: &str = "pump/put";

/// What a subscriber has been handed, in counters (a recording that stored the
/// payload would allocate inside the window it is measuring).
#[derive(Default)]
struct Seen {
    puts: AtomicUsize,
}

/// The application layer of an end: an observer with one subscriber on [`KEY`]
/// that counts what it is handed, and the `on_event` the end's task is run with.
fn application(actions: &Handle) -> (impl FnMut(IterationEvent<'_>) + 'static, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
    let counted = seen.clone();
    observer
        .borrow_mut()
        .subscribers
        .register_sink(
            KEY,
            Locality::Any,
            BoxedSink::new(move |_sample| {
                counted.puts.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .expect("register the subscriber");
    (app_layer::dispatch_to(observer, actions.clone()), seen)
}

/// Where each profile keeps what the windows build, and how it makes it. The slot
/// profile's tables are `static`s the image declares; the others have no table and
/// make everything the way every image does today.
///
/// The two forms are two modules of two names and `placing` is the alias of the
/// one the profile builds: one name declared twice in one scope is a defect under
/// every feature combination, whatever the `cfg`s say.
#[cfg(feature = "session-slot")]
use placing_in_slot as placing;
#[cfg(feature = "session-slot")]
mod placing_in_slot {
    use super::*;
    use wz_runtime_coop::session_drive::{PumpRef, PumpSlots};
    use wz_runtime_coop::session_runtime::new_session_in_slot;
    use wz_runtime_coop::RuntimeCell;
    use wz_session_core::session_slot::SessionSlots;

    pub type LinkHandle = &'static LwipLink;
    pub type Pump = PumpRef<Clk, LwipSessionLink<LinkHandle>>;
    pub type Slots = SessionSlots<Rt, CoopTime<Clk>, LwipUdpDriver, Counting, 3>;

    /// The runtime of the whole image: a task table, a timer table.
    pub static RUNTIME: RuntimeCell<Clk, 6, 256, 4> = RuntimeCell::new();
    /// Three sessions' state (the third is the one the pump table refuses), and two
    /// pumps.
    pub static SESSIONS: Slots = SessionSlots::new();
    pub static PUMPS: PumpSlots<Clk, LwipSessionLink<LinkHandle>, 2> = PumpSlots::new();

    /// The link of the node, which an image keeps in a `static`.
    pub fn link_handle(link: LwipLink) -> LinkHandle {
        Box::leak(Box::new(link))
    }

    /// Another handle on the node's link: a copy of a reference.
    pub fn share(link: &LinkHandle) -> LinkHandle {
        link
    }

    /// The link itself, as a socket is bound against it.
    pub fn raw(link: &LinkHandle) -> &LwipLink {
        link
    }

    pub fn runtime() -> Rt {
        RUNTIME.start(Clk).expect("the runtime is started once")
    }

    /// One end's state, in a slot: the driver over its socket, the entropy source
    /// and the bundle, and the link the loop reads.
    pub fn session(
        link: LinkHandle,
        runtime: &Rt,
        socket: SessionRxSocket,
        peer: ([u8; 4], u16),
        zid: u8,
    ) -> (Handle, LwipSessionLink<LinkHandle>) {
        let driver =
            LwipUdpDriver::new(share_socket(socket), ipv4_addr_from_octets(peer.0), peer.1);
        let Ok(claim) = SESSIONS.claim(driver, Counting(zid)) else {
            panic!("a session slot is free");
        };
        let pump_link = LwipSessionLink::new(link, claim.driver_handle());
        let actions = new_session_in_slot(claim, params(zid), CoopTime::new(runtime));
        (actions, pump_link)
    }

    /// A pump in a cell of the pump table.
    pub fn pump(
        runtime: &Rt,
        link: LwipSessionLink<LinkHandle>,
        actions: &Handle,
        role: SessionRole,
    ) -> Pump {
        let Ok(pump) = PUMPS.claim(
            runtime.clone(),
            link,
            actions.clone(),
            CoopTime::new(runtime),
            config(role),
        ) else {
            panic!("a pump cell is free");
        };
        pump
    }

    /// A pump hosted as a task of the local set: a cell of the task table.
    pub fn spawn(
        local: &CoopLocalSet<Clk>,
        pump: Pump,
        on_event: impl FnMut(IterationEvent<'_>) + 'static,
    ) -> CoopLocalJoinHandle<DriverOutcome> {
        let Ok(handle) = wz_runtime_coop::session_drive::spawn_pump(local, pump, on_event) else {
            panic!("a task cell is free");
        };
        handle
    }

    pub fn spawn_future<F: std::future::Future + 'static>(
        local: &CoopLocalSet<Clk>,
        fut: F,
    ) -> CoopLocalJoinHandle<F::Output> {
        let Ok(handle) = local.spawn_local(fut) else {
            panic!("a task cell is free");
        };
        handle
    }

    pub fn sessions_in_use() -> usize {
        SESSIONS.in_use()
    }

    pub fn pumps_in_use() -> usize {
        PUMPS.in_use()
    }

    pub fn tasks_live(local: &CoopLocalSet<Clk>) -> usize {
        local.runtime().live_task_count()
    }
}

/// See the slot form of this module.
#[cfg(not(feature = "session-slot"))]
use placing_on_the_heap as placing;
#[cfg(not(feature = "session-slot"))]
mod placing_on_the_heap {
    use super::*;
    use wz_runtime_coop::session_runtime::new_session_actions;
    use wz_session_core::link::BoxedLinkDriver;
    use wz_session_core::session_actions::SessionLinkActions;

    pub type LinkHandle = Rc<LwipLink>;
    pub type Pump = SessionPump<Clk, LwipSessionLink<LinkHandle>>;

    pub fn link_handle(link: LwipLink) -> LinkHandle {
        Rc::new(link)
    }

    /// Another handle on the node's link: a reference count taken.
    pub fn share(link: &LinkHandle) -> LinkHandle {
        link.clone()
    }

    /// The link itself, as a socket is bound against it.
    pub fn raw(link: &LinkHandle) -> &LwipLink {
        link
    }

    /// A runtime as every image makes one: an `Arc` of its pools.
    pub fn runtime() -> Rt {
        CoopRuntime::new(Clk)
    }

    pub fn session(
        link: LinkHandle,
        runtime: &Rt,
        socket: SessionRxSocket,
        peer: ([u8; 4], u16),
        zid: u8,
    ) -> (Handle, LwipSessionLink<LinkHandle>) {
        let driver = Rc::new(LwipUdpDriver::new(
            share_socket(socket),
            ipv4_addr_from_octets(peer.0),
            peer.1,
        ));
        let sink: Rc<dyn BoxedLinkDriver> = driver.clone();
        let actions = if zid == 0xa1 {
            new_session_actions(sink, params(zid), CoopTime::new(runtime), Counting(zid))
        } else {
            SessionLinkActions::<Rt, CoopTime<Clk>>::new_generic(
                sink,
                params(zid),
                CoopTime::new(runtime),
            )
        };
        (actions, LwipSessionLink::new(link, driver))
    }

    pub fn pump(
        runtime: &Rt,
        link: LwipSessionLink<LinkHandle>,
        actions: &Handle,
        role: SessionRole,
    ) -> Pump {
        SessionPump::new(
            runtime.clone(),
            link,
            actions.clone(),
            CoopTime::new(runtime),
            config(role),
        )
    }

    /// The task a pump is hosted as on every profile but the slot's: the pump
    /// by value inside a boxed future.
    async fn pump_task(
        mut pump: Pump,
        mut on_event: impl FnMut(IterationEvent<'_>),
    ) -> DriverOutcome {
        loop {
            if let Some(outcome) = pump.step(&mut on_event) {
                return outcome;
            }
            yield_now().await;
        }
    }

    pub fn spawn(
        local: &CoopLocalSet<Clk>,
        pump: Pump,
        on_event: impl FnMut(IterationEvent<'_>) + 'static,
    ) -> CoopLocalJoinHandle<DriverOutcome> {
        local.spawn_local(pump_task(pump, on_event))
    }

    pub fn spawn_future<F: std::future::Future + 'static>(
        local: &CoopLocalSet<Clk>,
        fut: F,
    ) -> CoopLocalJoinHandle<F::Output> {
        local.spawn_local(fut)
    }

    pub fn sessions_in_use() -> usize {
        0
    }

    pub fn pumps_in_use() -> usize {
        0
    }

    pub fn tasks_live(local: &CoopLocalSet<Clk>) -> usize {
        local.live_local_task_count()
    }
}

/// Every window's cost, kept so a test reports ALL of them and not only the
/// first that is wrong.
#[derive(Default)]
struct Costs {
    wrong: Vec<String>,
}

impl Costs {
    /// A window that must cost the heap nothing on the slot profile and something
    /// on the heap profile (the control).
    fn check(&mut self, what: &str, allocations: usize) {
        println!("{what}: {allocations} allocation(s)");
        #[cfg(feature = "session-slot")]
        if allocations != 0 {
            self.wrong.push(format!(
                "{what}: {allocations} allocation(s); a pump and a runtime on static \
                 storage cost the heap nothing"
            ));
        }
        #[cfg(not(feature = "session-slot"))]
        if allocations == 0 {
            self.wrong.push(format!(
                "{what}: 0 allocations; the heap profile allocates here, so a zero \
                 means the instrument cannot see it, and a zero on the slot profile \
                 would mean nothing"
            ));
        }
    }

    /// A window that costs the heap nothing on EVERY profile.
    fn check_free(&mut self, what: &str, allocations: usize) {
        println!("{what}: {allocations} allocation(s)");
        if allocations != 0 {
            self.wrong
                .push(format!("{what}: {allocations} allocation(s)"));
        }
    }

    fn finish(self) {
        assert!(self.wrong.is_empty(), "{:#?}", self.wrong);
    }
}

/// One pass of the executor, which steps every task that is ready once.
fn pass(local: &CoopLocalSet<Clk>) {
    local.run_until_idle();
}

/// A session pair run as two tasks of one local set, window by window.
#[test]
fn a_pair_of_pumps_costs_the_heap_nothing_as_tasks_of_a_static_runtime() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = placing::link_handle(link);
    let port = 7761;
    NOW_US.store(0, Ordering::SeqCst);

    // The sockets are bound before any window: the socket's storage is step S7's.
    let acceptor_socket = bind_session_rx(placing::raw(&link), port).expect("bind the acceptor");
    let initiator_socket = bind_session_rx(placing::raw(&link), 0).expect("bind the initiator");

    let m = Measurement::new();
    let mut costs = Costs::default();

    // RUNTIME: the runtime and the local set that hosts the tasks.
    let ((runtime, local), n) = m.count("runtime", || {
        let runtime = placing::runtime();
        let local = CoopLocalSet::new(&runtime);
        (runtime, local)
    });
    costs.check("the runtime and its local set", n);

    // The sessions' own state is step S5's, counted by its own witness; it is made
    // here, outside any window, because the pump is built over it.
    let ((acceptor_actions, acceptor_link), (initiator_actions, initiator_link)) = (
        placing::session(
            placing::share(&link),
            &runtime,
            acceptor_socket,
            ([0; 4], 0),
            0xa1,
        ),
        placing::session(
            placing::share(&link),
            &runtime,
            initiator_socket,
            ([127, 0, 0, 1], port),
            0xb1,
        ),
    );
    let (on_acceptor, acceptor_seen) = application(&acceptor_actions);
    let (on_initiator, initiator_seen) = application(&initiator_actions);
    // A third session, which the pump table (two cells) will refuse.
    #[cfg(feature = "session-slot")]
    let spare = placing::session(
        placing::share(&link),
        &runtime,
        bind_session_rx(placing::raw(&link), 0).expect("bind the spare"),
        ([127, 0, 0, 1], port),
        0xc1,
    );
    #[cfg(feature = "session-slot")]
    assert_eq!(placing::sessions_in_use(), 3);

    // PUMP: each end's pump, from its engine to the handles it holds.
    let ((acceptor_pump, initiator_pump), n) = m.count("pumps", || {
        (
            placing::pump(
                &runtime,
                acceptor_link,
                &acceptor_actions,
                SessionRole::Acceptor,
            ),
            placing::pump(
                &runtime,
                initiator_link,
                &initiator_actions,
                SessionRole::Initiator,
            ),
        )
    });
    costs.check("the two pumps", n);

    // SPAWN: each pump hosted as a task.
    let ((acceptor_task, initiator_task), n) = m.count("spawn", || {
        (
            placing::spawn(&local, acceptor_pump, on_acceptor),
            placing::spawn(&local, initiator_pump, on_initiator),
        )
    });
    costs.check("the two pumps hosted as tasks", n);
    assert_eq!(placing::tasks_live(&local), 2, "both tasks are hosted");
    assert!(!acceptor_task.is_finished() && !initiator_task.is_finished());

    // HANDSHAKE, by executor passes alone.
    let ((), n) = m.count("handshake", || {
        for _ in 0..64 {
            pass(&local);
            if acceptor_actions.is_established() && initiator_actions.is_established() {
                break;
            }
        }
    });
    costs.check("handshake, InitSyn to OpenAck, by executor passes", n);
    assert!(
        acceptor_actions.is_established() && initiator_actions.is_established(),
        "the pair established over the loopback"
    );

    // STEADY STATE.
    for _ in 0..4 {
        pass(&local);
    }
    let payload = [0x5au8; 512];
    for len in [1usize, 8, 64, 512] {
        let (a_before, i_before) = (
            acceptor_seen.puts.load(Ordering::SeqCst),
            initiator_seen.puts.load(Ordering::SeqCst),
        );
        let (sent, n) = m.count("a put each way", || {
            let up = initiator_actions.send_push_literal(KEY, &payload[..len], true);
            pass(&local);
            let down = acceptor_actions.send_push_literal(KEY, &payload[..len], true);
            pass(&local);
            (up, down)
        });
        sent.0.expect("the initiator's Put leaves");
        sent.1.expect("the acceptor's Put leaves");
        costs.check(&format!("a Put of {len} bytes each way"), n);
        assert_eq!(acceptor_seen.puts.load(Ordering::SeqCst), a_before + 1);
        assert_eq!(initiator_seen.puts.load(Ordering::SeqCst), i_before + 1);
    }
    let ((), n) = m.count("a keep-alive each way", || {
        initiator_actions.send_keep_alive();
        pass(&local);
        acceptor_actions.send_keep_alive();
        pass(&local);
    });
    costs.check("a KeepAlive each way", n);
    let ((), n) = m.count("idle passes", || {
        for _ in 0..8 {
            pass(&local);
        }
    });
    costs.check_free("eight idle passes of the executor", n);

    // TABLES FULL: a third pump while both cells are taken is refused, counted,
    // and the refusal costs the heap nothing.
    #[cfg(feature = "session-slot")]
    {
        let (extra_actions, extra_link) = spare;
        let (refused, n) = m.count("a third pump", || {
            placing::PUMPS.claim(
                runtime.clone(),
                extra_link,
                extra_actions,
                CoopTime::new(&runtime),
                config(SessionRole::Acceptor),
            )
        });
        assert!(refused.is_err(), "both pump cells are taken");
        costs.check_free("a refused third pump", n);
        assert_eq!(placing::PUMPS.refused(), 1, "the refusal is counted");
        assert_eq!(
            placing::sessions_in_use(),
            2,
            "the refused pump's session went back to its table"
        );
    }

    // TIMER: a task that sleeps registers a deadline, which fires when the clock
    // moves; a task that is aborted is swept.
    let (sleeper, n) = m.count("a sleeper", || {
        let time = CoopTime::new(&runtime);
        let sleeper = placing::spawn_future(&local, async move {
            time.sleep(5).await;
            7u32
        });
        pass(&local);
        sleeper
    });
    costs.check("a task that sleeps, spawned and registered", n);
    NOW_US.store(10_000, Ordering::SeqCst);
    let (woken, n) = m.count("the deadline", || {
        pass(&local);
        pass(&local);
        local.block_on_local(sleeper)
    });
    costs.check("the deadline fires, the task ends, its handle is read", n);
    assert_eq!(woken.expect("not cancelled"), 7);
    let ((), n) = m.count("an aborted task", || {
        let forever = placing::spawn_future(&local, async {
            loop {
                yield_now().await;
            }
        });
        pass(&local);
        forever.abort();
        pass(&local);
    });
    costs.check("a task spawned, aborted and swept", n);
    NOW_US.store(0, Ordering::SeqCst);

    // CLOSE.
    let ((), n) = m.count("close", || {
        initiator_actions.send_close_with_reason(CloseReason::Generic);
        for _ in 0..8 {
            pass(&local);
            if acceptor_task.is_finished() {
                break;
            }
        }
    });
    costs.check("a Close, and the acceptor's task ending on it", n);
    assert!(
        acceptor_task.is_finished(),
        "the acceptor's session ended on the Close it read"
    );
    let (outcome, n) = m.count("join", || local.block_on_local(acceptor_task));
    costs.check("the acceptor's join handle read", n);
    assert!(outcome.is_ok(), "the acceptor's task was not cancelled");

    // The initiator's task and every table: nothing is left held once the handles
    // are gone.
    initiator_task.abort();
    pass(&local);
    drop(initiator_task);
    drop(initiator_actions);
    drop(acceptor_actions);
    pass(&local);
    assert_eq!(placing::tasks_live(&local), 0, "every task cell is free");
    assert_eq!(placing::pumps_in_use(), 0, "every pump cell is free");
    assert_eq!(placing::sessions_in_use(), 0, "every session slot is free");
    costs.finish();
}

/// What the runtime's cell and the pump table take of an image's `.bss`, printed
/// with their parts so a number in a record can be re-derived, and bounded below by
/// those parts so a table that held less than it claims to would be caught.
/// Host-sized (the test runs on the host); the target's numbers are the same
/// expressions compiled for the target.
#[cfg(feature = "session-slot")]
#[test]
fn the_static_tables_report_their_size() {
    use wz_runtime_coop::session_drive::{PumpSlots, SessionPump};
    use wz_runtime_coop::RuntimeCell;

    type Cells = RuntimeCell<Clk, 6, 256, 4>;
    type Pumps = PumpSlots<Clk, LwipSessionLink<placing::LinkHandle>, 2>;
    type OnePump = SessionPump<Clk, LwipSessionLink<placing::LinkHandle>>;
    let (runtime, pumps, pump) = (
        Cells::size_bytes(),
        Pumps::size_bytes(),
        core::mem::size_of::<OnePump>(),
    );
    println!("runtime cell {runtime} B (6 tasks x 256 B, 4 timers); pump table {pumps} B (2 x pump {pump} B)");
    assert!(runtime >= 6 * 256, "the task bytes are in the cell");
    assert!(pumps >= 2 * pump, "a pump is in each cell of the table");
}

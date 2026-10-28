// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one SESSION costs the heap on the MCU profile, from the moment its
//! per-session state is created to the moment it closes, counted (fixed-memory
//! step S5, ARCHITECTURE section 9.1).
//!
//! The earlier steps counted a message: the RX path of a frame
//! (`rx_frame_allocations`) and the TX path of every message
//! (`tx_allocations`). Both start from a session that already exists. This file
//! counts the session itself: a real pair, an initiator and an acceptor, over the
//! host lwIP loopback, each driven by the shared `SessionPump`, and four
//! windows under one counting `#[global_allocator]`:
//!
//! - CREATION: everything that makes a session's per-session state: the link
//!   driver (over its socket, by value), the entropy source, the init
//!   parameters (zid, cookie, signing key), the kernel, the link state and the
//!   bundle that names them, and the link the drive loop reads. The socket is
//!   bound before the window (the socket's own storage is step S7's), and so are
//!   the runtime, the pump and the application layer (the pump is step S6's, the
//!   observer is the application's);
//! - HANDSHAKE: the two ends driven to Established, InitSyn to OpenAck, which
//!   reads the peer's zid, cookie and extension chains into the session and
//!   mints the acceptor's cookie from the entropy source;
//! - STEADY STATE: a Put each way at several sizes, a KeepAlive each way, and
//!   idle turns, every one delivered to the other end's subscriber;
//! - CLOSE: the initiator's Close and the acceptor's reading of it.
//!
//! With `session-slot` (the MCU profile's: the per-session state lives in a slot
//! of fixed size, and nothing a session holds is behind a pointer to the heap)
//! every window must cost the heap NOTHING, and the slot is free again once the
//! last handle to it is gone. Without it (the profile every shipped image and the
//! AP run today) the creation and handshake windows must cost it something, and
//! that half is the instrument's own control: a count that read zero on the
//! state that is known to hold vectors, boxes and reference counts would prove
//! nothing about the state that is meant not to.
//!
//! The count is ATTRIBUTED to the measurement's own thread, as `tx_allocations`
//! does: a measurement owns a tally, its thread works for it, and an allocation
//! counts only when the thread that makes it works for a measurement whose
//! window is open. lwIP is process-global, so every test holds the harness's
//! lock for its whole body.
//!
//! Set `WZ_ALLOC_SITES=1` to print, for every window, where in this workspace
//! each counted allocation was made (the first frames of its backtrace that lie
//! in this workspace), which is how a nonzero count is read back to its cause.
//!
//! Host-test level: no board runs it, and the stack the slot takes is not
//! measured here.

// Not on the slot profile WITH `reassembly`: there `SessionPump::new` does not
// exist, because the pump's staging table must lie in a cell of the pump table
// (`PumpSlots::claim`), and this file builds its pumps with `new`. The same windows
// on that profile are `session_pump_allocations`', whose pumps are claimed from a
// table. The slot profile without `reassembly` is this file's and is built and run
// by the C1m leg that names it; clippy builds the other, which is why the gate is
// here and not at the use.
#![cfg(not(all(feature = "session-slot", feature = "reassembly")))]
// A refused claim hands back what it was offered, a whole driver and its socket,
// which is what makes the refusal free of the heap; boxing it would allocate.
#![allow(clippy::result_large_err)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wz_link_lwip::rx_sockets::SessionRxSocket;
// Round 3277 -- the binder of `test_bind`: the constructor itself by default, and
// with `static-link-storage` also on (the two selectors compose) a socket claimed
// from a pool of one cell that the test leaks. Every bind in this file is outside
// a counting window, so the leak is not read as a cost.
#[cfg(not(feature = "static-link-storage"))]
use wz_link_lwip::rx_sockets::bind_session_rx;
#[cfg(feature = "static-link-storage")]
use wz_link_lwip::test_bind::session_rx as bind_session_rx;
use wz_link_lwip::{ipv4_addr_from_octets, LwipLink};
use wz_runtime_coop::session_drive::{SessionDriveConfig, SessionPump, SessionRole};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime};
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

/// The driver of one end over `socket`: a link to `peer` when the end dials it, an
/// accepting link (bound by the first `InitSyn` it takes) when `peer` is `None`.
fn driver_over(socket: SessionRxSocket, peer: Option<([u8; 4], u16)>) -> LwipUdpDriver {
    let socket = share_socket(socket);
    match peer {
        Some((addr, port)) => LwipUdpDriver::new(socket, ipv4_addr_from_octets(addr), port),
        None => LwipUdpDriver::accepting(socket),
    }
}

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
        // Only the frames whose source is in this workspace (or its vendored
        // engine, or the generated codecs): the allocator's own frames and the
        // std machinery under them say nothing of where the allocation was asked
        // for. This function and the allocator hooks are in this file and say
        // nothing either.
        let Some(at) = at else { continue };
        let ours = at.contains("/crates/") || at.contains("/out/") || at.contains("/vendor/");
        if !ours || symbol.starts_with("record_site") || symbol.starts_with("count_one") {
            continue;
        }
        let symbol = symbol.rsplit_once("::h").map_or(symbol, |(head, _)| head);
        // Keep the file and line, drop the directory.
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
    /// threads made while it ran. The sites are printed under `what` when asked
    /// for and there were any.
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

/// A clock that never moves: no deadline fires, so the session does only what
/// the other end asks of it.
#[derive(Clone, Default)]
struct Frozen;
impl ClockSource for Frozen {
    fn now_us(&self) -> u64 {
        0
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

type Rt = CoopRuntime<Frozen, LwipUdpDriver>;
type Pump = SessionPump<Frozen, LwipSessionLink<Rc<LwipLink>>, LwipUdpDriver>;
/// The handle to a session: an `Rc` of the bundle, or under `session-slot` a
/// counted reference to the slot that holds it.
type Handle = SessionHandle<Frozen, LwipUdpDriver>;

/// The init parameters of a session whose zid is four bytes of `zid`, written
/// the same way on every profile: the arrays of the slot profile, the vectors of
/// the others.
fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[zid; 4]),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
        initial_sn: 0,
        cookie: cookie_bytes(&[]),
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
        cookie_signing_key: SigningKey::from_slice(&[7u8; 32]).expect("key"),
    }
}

const KEY: &str = "slot/put";

/// What a subscriber has been handed, in counters (a recording that stored the
/// payload would allocate inside the window it is measuring).
#[derive(Default)]
struct Seen {
    puts: AtomicUsize,
    bytes: AtomicUsize,
}

/// The table the two ends of the test take their slots from, and the way an end's
/// state is made on each profile.
#[cfg(feature = "session-slot")]
use placing_in_slot as placing;

#[cfg(feature = "session-slot")]
mod placing_in_slot {
    use super::*;
    use wz_runtime_coop::session_runtime::new_session_in_slot;
    use wz_session_core::session_slot::SessionSlots;

    /// Two slots: one per end of the pair under test.
    pub type Slots = SessionSlots<Rt, CoopTime<Frozen>, LwipUdpDriver, Counting, 2>;
    pub static SESSIONS: Slots = SessionSlots::new();

    /// One end's state, in a slot: the driver over its socket, the entropy source,
    /// the bundle, and the link the loop reads. Nothing here is on the heap.
    pub fn create(
        link: &Rc<LwipLink>,
        runtime: &Rt,
        socket: SessionRxSocket,
        peer: Option<([u8; 4], u16)>,
        zid: u8,
    ) -> (Handle, LwipSessionLink<Rc<LwipLink>>) {
        let driver = driver_over(socket, peer);
        let Ok(claim) = SESSIONS.claim(driver, Counting(zid)) else {
            panic!("a slot is free");
        };
        let pump_link = LwipSessionLink::new(link.clone(), claim.driver_handle());
        let actions = new_session_in_slot(claim, params(zid), CoopTime::new(runtime));
        (actions, pump_link)
    }

    /// Slots in use, for the check that they all come back.
    pub fn in_use() -> usize {
        SESSIONS.in_use()
    }
}

/// See the slot form of this module (two names, because a module declared twice
/// in one scope is a defect the duplicate-module lint reads whatever the cfgs say).
#[cfg(not(feature = "session-slot"))]
use placing_on_the_heap as placing;

#[cfg(not(feature = "session-slot"))]
mod placing_on_the_heap {
    use super::*;
    use wz_runtime_coop::session_runtime::new_session_actions;
    use wz_session_core::link::BoxedLinkDriver;
    use wz_session_core::session_actions::SessionLinkActions;

    /// One end's state, as every profile but the slot makes it: a driver in an
    /// `Rc`, an `Rc` of each of the kernel, the link state and the bundle, a boxed
    /// entropy source, vectors for the parameters.
    ///
    /// The acceptor's goes through the construction seam that installs the entropy
    /// source and the initiator's through the bare constructor, as each is made
    /// everywhere else.
    pub fn create(
        link: &Rc<LwipLink>,
        runtime: &Rt,
        socket: SessionRxSocket,
        peer: Option<([u8; 4], u16)>,
        zid: u8,
    ) -> (Handle, LwipSessionLink<Rc<LwipLink>>) {
        let driver = Rc::new(driver_over(socket, peer));
        let sink: Rc<dyn BoxedLinkDriver> = driver.clone();
        let actions = if zid == 0xa1 {
            new_session_actions(sink, params(zid), CoopTime::new(runtime), Counting(zid))
        } else {
            SessionLinkActions::<Rt, CoopTime<Frozen>>::new_generic(
                sink,
                params(zid),
                CoopTime::new(runtime),
            )
        };
        (actions, LwipSessionLink::new(link.clone(), driver))
    }

    /// No slot table on this profile: nothing to come back.
    pub fn in_use() -> usize {
        0
    }
}

/// One end of a session: the bundle, its pump, and what its subscriber saw.
struct End {
    actions: Handle,
    pump: Pump,
    on_event: Box<dyn FnMut(IterationEvent<'_>)>,
    seen: Arc<Seen>,
}

impl End {
    /// One drive iteration; the session must not have ended.
    fn step(&mut self) {
        assert!(
            self.pump.step(&mut self.on_event).is_none(),
            "the session ended on a turn"
        );
    }
}

/// The `on_event` an end's pump is driven with.
type OnEvent = Box<dyn FnMut(IterationEvent<'_>)>;

/// The application layer of an end: an observer with one subscriber on
/// [`KEY`] that counts what it is handed.
fn application(actions: &Handle) -> (OnEvent, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
    let counted = seen.clone();
    observer
        .borrow_mut()
        .subscribers
        .register_sink(
            KEY,
            Locality::Any,
            BoxedSink::new(move |sample| {
                counted.puts.fetch_add(1, Ordering::SeqCst);
                counted
                    .bytes
                    .fetch_add(sample.payload().len(), Ordering::SeqCst);
            }),
        )
        .expect("register the subscriber");
    (
        Box::new(app_layer::dispatch_to(observer, actions.clone())),
        seen,
    )
}

fn config(role: SessionRole) -> SessionDriveConfig {
    SessionDriveConfig {
        timeouts: SessionTimeouts::spec_defaults(),
        role,
        max_iters: None,
    }
}

/// Every window's cost, kept so a test reports ALL of them and not only the
/// first that is wrong.
#[derive(Default)]
struct Costs {
    wrong: Vec<String>,
}

impl Costs {
    /// A window that must cost the heap nothing on the slot profile and
    /// something on the heap profile (the control: the profile of every shipped
    /// image holds a session in boxes, vectors and reference counts, copies a
    /// handshake, KeepAlive or Close off the link, and matches a received Put
    /// against its subscribers with growable scratch lists, so a zero there means
    /// the instrument cannot see them, and a zero on the slot profile would mean
    /// nothing).
    fn check(&mut self, what: &str, allocations: usize) {
        println!("{what}: {allocations} allocation(s)");
        #[cfg(feature = "session-slot")]
        if allocations != 0 {
            self.wrong.push(format!(
                "{what}: {allocations} allocation(s); a session in its slot costs the \
                 heap nothing"
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

    /// A window that costs the heap nothing on EVERY profile: an idle turn, which
    /// no step has had to change.
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

/// A session from its slot to its close, window by window.
#[test]
fn a_session_costs_the_heap_nothing_from_its_slot_to_its_close() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    // The runtime of the profile: a cell of tables on the slot profile (step S6),
    // an `Arc` of its pools on the others.
    #[cfg(feature = "session-slot")]
    static RUNTIME: wz_runtime_coop::RuntimeCell<Frozen, 1, 64, 1> =
        wz_runtime_coop::RuntimeCell::new();
    #[cfg(feature = "session-slot")]
    let runtime = RUNTIME.start(Frozen).expect("the runtime is started once");
    #[cfg(not(feature = "session-slot"))]
    let runtime = CoopRuntime::new(Frozen);
    let port = 7701;

    // The sockets are bound, and the pumps and applications built, outside any
    // window: the socket's storage is step S7's, the pump's step S6's, and the
    // application's is the application's.
    let acceptor_socket = bind_session_rx(&link, port).expect("bind the acceptor");
    let initiator_socket = bind_session_rx(&link, 0).expect("bind the initiator");

    let m = Measurement::new();
    let mut costs = Costs::default();

    // CREATION: both ends, from the bound socket to the session that can run.
    let (((acceptor_actions, acceptor_link), (initiator_actions, initiator_link)), n) =
        m.count("creation", || {
            (
                placing::create(&link, &runtime, acceptor_socket, None, 0xa1),
                placing::create(
                    &link,
                    &runtime,
                    initiator_socket,
                    Some(([127, 0, 0, 1], port)),
                    0xb1,
                ),
            )
        });
    costs.check("creation of the per-session state", n);

    let (on_acceptor, acceptor_seen) = application(&acceptor_actions);
    let (on_initiator, initiator_seen) = application(&initiator_actions);
    let mut acceptor = End {
        pump: SessionPump::new(
            runtime.clone(),
            acceptor_link,
            acceptor_actions.clone(),
            CoopTime::new(&runtime),
            config(SessionRole::Acceptor),
        ),
        actions: acceptor_actions,
        on_event: on_acceptor,
        seen: acceptor_seen,
    };
    let mut initiator = End {
        pump: SessionPump::new(
            runtime.clone(),
            initiator_link,
            initiator_actions.clone(),
            CoopTime::new(&runtime),
            config(SessionRole::Initiator),
        ),
        actions: initiator_actions,
        on_event: on_initiator,
        seen: initiator_seen,
    };

    // HANDSHAKE.
    let ((), n) = m.count("handshake", || {
        for _ in 0..64 {
            initiator.step();
            acceptor.step();
            if acceptor.actions.is_established() && initiator.actions.is_established() {
                break;
            }
        }
    });
    costs.check("handshake, InitSyn to OpenAck", n);
    assert!(
        acceptor.actions.is_established() && initiator.actions.is_established(),
        "the pair established over the loopback"
    );

    // STEADY STATE. A turn each way settles whatever the last handshake turn
    // left in flight before the measured ones.
    for _ in 0..4 {
        initiator.step();
        acceptor.step();
    }
    let payload = [0x5au8; 512];
    for len in [1usize, 8, 64, 512] {
        let (a_before, i_before) = (
            acceptor.seen.puts.load(Ordering::SeqCst),
            initiator.seen.puts.load(Ordering::SeqCst),
        );
        let (sent, n) = m.count("a put each way", || {
            let up = initiator
                .actions
                .send_push_literal(KEY, &payload[..len], true);
            acceptor.step();
            let down = acceptor
                .actions
                .send_push_literal(KEY, &payload[..len], true);
            initiator.step();
            (up, down)
        });
        sent.0.expect("the initiator's Put leaves");
        sent.1.expect("the acceptor's Put leaves");
        costs.check(&format!("a Put of {len} bytes each way"), n);
        assert_eq!(
            acceptor.seen.puts.load(Ordering::SeqCst),
            a_before + 1,
            "the acceptor's subscriber was handed the initiator's Put"
        );
        assert_eq!(
            initiator.seen.puts.load(Ordering::SeqCst),
            i_before + 1,
            "the initiator's subscriber was handed the acceptor's Put"
        );
    }
    let ((), n) = m.count("a keep-alive each way", || {
        initiator.actions.send_keep_alive();
        acceptor.step();
        acceptor.actions.send_keep_alive();
        initiator.step();
    });
    costs.check("a KeepAlive each way", n);
    let ((), n) = m.count("idle turns", || {
        for _ in 0..8 {
            initiator.step();
            acceptor.step();
        }
    });
    costs.check_free("eight idle turns of each end", n);

    // CLOSE.
    let (ended, n) = m.count("close", || {
        initiator
            .actions
            .send_close_with_reason(CloseReason::Generic);
        let mut ended: Option<DriverOutcome> = None;
        for _ in 0..8 {
            ended = acceptor.pump.step(&mut acceptor.on_event);
            if ended.is_some() {
                break;
            }
        }
        ended
    });
    costs.check("a Close and its reading", n);
    assert!(
        ended.is_some(),
        "the acceptor's session ended on the Close it read"
    );

    // Every handle to both sessions goes, and so do the slots: the last handle
    // frees what it points at, and a table that is not emptied would refuse the
    // next session.
    #[cfg(feature = "session-slot")]
    assert_eq!(
        placing::in_use(),
        2,
        "CONTROL: both slots are held while the sessions are"
    );
    drop(acceptor);
    drop(initiator);
    assert_eq!(
        placing::in_use(),
        0,
        "every slot is free once its handles are"
    );
    costs.finish();
}

/// The slot table itself, which only the slot profile has: a full table refuses
/// and counts, a slot comes back when the last handle to it goes (and not before),
/// what a slot holds is dropped exactly once, and a socket is released with it.
#[cfg(feature = "session-slot")]
mod table {
    use super::*;
    use wz_runtime_coop::session_runtime::new_session_in_slot;
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
    use wz_session_core::session_slot::{SessionSlots, SlotsFull};

    thread_local! {
        /// How many entropy sources of this module's `Tracked` kind have been
        /// dropped on this thread.
        static DROPPED: Cell<usize> = const { Cell::new(0) };
    }

    /// An entropy source that says when it is dropped, so that what a slot holds
    /// is shown to be dropped once and only when the slot is freed.
    struct Tracked;
    impl EntropySource for Tracked {
        fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            buf.fill(0x42);
            Ok(())
        }
    }
    impl Drop for Tracked {
        fn drop(&mut self) {
            DROPPED.with(|d| d.set(d.get() + 1));
        }
    }

    type Table = SessionSlots<Rt, CoopTime<Frozen>, LwipUdpDriver, Tracked, 2>;

    /// A driver over a socket bound on `port`, as a slot is claimed with it.
    fn driver_on(link: &Rc<LwipLink>, port: u16) -> LwipUdpDriver {
        let socket = bind_session_rx(link, port).expect("bind");
        LwipUdpDriver::new(
            share_socket(socket),
            ipv4_addr_from_octets([127, 0, 0, 1]),
            port,
        )
    }

    /// With every slot taken the next claim is refused, counted, and gives its
    /// driver and entropy source back; a slot that comes back is claimable again.
    /// The refusal costs the heap nothing, which is what lets an acceptor answer a
    /// peer it has no slot for without making room by allocating.
    #[test]
    fn a_full_table_refuses_the_next_claim_counts_it_and_gives_the_values_back() {
        static TABLE: Table = SessionSlots::new();
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let (d1, d2, d3) = (
            driver_on(&link, 7721),
            driver_on(&link, 7722),
            driver_on(&link, 7723),
        );
        let m = Measurement::new();

        assert_eq!(
            (TABLE.capacity(), TABLE.in_use(), TABLE.refused()),
            (2, 0, 0)
        );
        let (first, n) = m.count("claim", || TABLE.claim(d1, Tracked));
        assert_eq!(n, 0, "claiming a slot allocates nothing");
        let first = first.ok().expect("the first slot");
        let second = TABLE.claim(d2, Tracked).ok().expect("the second slot");
        assert_eq!(TABLE.in_use(), 2);

        let (refused, n) = m.count("refusal", || TABLE.claim(d3, Tracked));
        assert_eq!(n, 0, "a refused claim allocates nothing");
        let Err(SlotsFull { driver, entropy }) = refused else {
            panic!("a third claim on a table of two is refused");
        };
        assert_eq!(TABLE.refused(), 1, "the refusal is counted");
        assert_eq!(TABLE.in_use(), 2, "and took no slot");
        assert_eq!(
            driver.peer().map(|peer| peer.1),
            Some(7723),
            "the driver comes back, the one that was offered"
        );

        drop(first);
        assert_eq!(TABLE.in_use(), 1, "a dropped claim gives its slot back");
        let third = TABLE
            .claim(driver, entropy)
            .ok()
            .expect("the slot that came back is claimable again");
        assert_eq!((TABLE.in_use(), TABLE.refused()), (2, 1));
        drop((second, third));
        assert_eq!(TABLE.in_use(), 0);
    }

    /// A slot is freed by the LAST handle to it and by nothing sooner: the bundle's
    /// handle, a clone of it, a sink cloned out of the bundle and the driver handle
    /// the drive loop's link holds each keep it. What it holds is dropped once, and
    /// its socket goes with it, so the port can be bound again.
    #[test]
    fn a_slot_is_freed_by_the_last_handle_and_what_it_held_is_dropped_once() {
        static TABLE: Table = SessionSlots::new();
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        static RUNTIME: wz_runtime_coop::RuntimeCell<Frozen, 1, 64, 1> =
            wz_runtime_coop::RuntimeCell::new();
        let runtime = RUNTIME
            .start::<LwipUdpDriver>(Frozen)
            .expect("the runtime is started once");
        let dropped = || DROPPED.with(Cell::get);
        let before = dropped();

        let claim = TABLE
            .claim(driver_on(&link, 7724), Tracked)
            .ok()
            .expect("a slot");
        let driver_handle = claim.driver_handle();
        let actions = new_session_in_slot(claim, params(0xc1), CoopTime::new(&runtime));
        let clone = actions.clone();
        let sink = actions.link.driver.clone();
        assert_eq!(TABLE.in_use(), 1);

        drop(actions);
        drop(clone);
        assert_eq!(
            TABLE.in_use(),
            1,
            "a sink cloned out of the bundle keeps the slot"
        );
        drop(sink);
        assert_eq!(
            TABLE.in_use(),
            1,
            "and so does the driver the loop's link holds"
        );
        assert_eq!(
            dropped(),
            before,
            "nothing it held is dropped while it is held"
        );
        assert!(
            bind_session_rx(&link, 7724).is_err(),
            "CONTROL: the port is still bound while the slot is held"
        );
        drop(driver_handle);
        assert_eq!(TABLE.in_use(), 0, "the last handle frees the slot");
        assert_eq!(
            dropped(),
            before + 1,
            "its entropy source is dropped exactly once"
        );
        assert!(
            bind_session_rx(&link, 7724).is_ok(),
            "and its socket went with it"
        );
    }

    /// The bytes a slot takes, printed with its parts (the lwIP driver with its
    /// socket, the bundle) so the number in the step's record can be re-derived,
    /// and bounded below by its parts so a slot that held less than it claims to
    /// would be caught. Host-sized (the test runs on the host): the target's
    /// numbers are the same expression compiled for the target.
    #[test]
    fn a_slot_is_at_least_the_sum_of_what_it_holds() {
        use wz_session_core::session_actions::SessionLinkActions;
        let slot = Table::slot_bytes();
        let driver = core::mem::size_of::<LwipUdpDriver>();
        let bundle = core::mem::size_of::<SessionLinkActions<Rt, CoopTime<Frozen>>>();
        println!("slot {slot} B = driver {driver} B + bundle {bundle} B + rest");
        assert!(slot >= driver + bundle + core::mem::size_of::<Tracked>());
    }

    /// A claim that is never opened gives its slot back and drops what it was
    /// given: neither a slot nor a socket is leaked.
    #[test]
    fn an_unopened_claim_gives_its_slot_back_and_drops_what_it_was_given() {
        static TABLE: Table = SessionSlots::new();
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let before = DROPPED.with(Cell::get);

        let claim = TABLE
            .claim(driver_on(&link, 7725), Tracked)
            .ok()
            .expect("a slot");
        assert_eq!(TABLE.in_use(), 1);
        drop(claim);
        assert_eq!(TABLE.in_use(), 0);
        assert_eq!(DROPPED.with(Cell::get), before + 1);
        assert!(bind_session_rx(&link, 7725).is_ok(), "the socket is free");
    }
}

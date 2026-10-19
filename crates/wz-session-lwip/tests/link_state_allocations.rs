// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Where a session's LINK STATE lives, counted (Round 3277, fixed-memory step S7).
//!
//! Each session this shell opens binds a session socket, and the socket's state is
//! its whole receive queue: `SESSION_RX_SLOTS` datagrams of `SESSION_RX_SLOT_SIZE`
//! bytes, 24.7 KB on the MCU. That state used to be a heap box per session. A real
//! acceptor and a real initiator are opened over the host lwIP loopback through
//! `LwipLinks`, carried to Established by the drive loop, and torn down, all under
//! a counting `#[global_allocator]`, and the allocations the window made are read
//! BY SIZE:
//!
//! - one at least as large as a socket's receive queue is the link state, which
//!   with `static-link-storage` (the MCU profile's: the state is a cell of a
//!   `static` pool the image declares) must NOT be on the heap. The count must be
//!   zero; on the default profile it is the instrument's own control and must be
//!   at least two, one per socket.
//!
//! What this does NOT say, and the reason it reads by size and not by number: the
//! session shell above the socket (the actions bundle, the sink, the engine, the
//! `Rc`s around the driver) still allocates per session. That is the per-session
//! slot's step (S5) and the runtime's (S6); the whole window reaching zero is theirs
//! to witness once they have landed. The link-level witness of S7 is
//! `wz-link-lwip`'s `link_storage_allocations`, which reads the same absence with
//! nothing above the link to allocate.
//!
//! The count is ATTRIBUTED to the measurement's own thread (the pattern of the AP
//! datagram suites), and every test holds the lwIP harness's lock for its whole
//! body.
//!
//! Host-test level: no board runs it.

// Not on the `session-slot` profile, whose sessions are made in a slot and run on
// a runtime of static tables, and not through the `SessionLinks` and `Rc` seams
// this file builds them with: the slot profile's link state is counted by
// `session_slot_allocations` and `session_pump_allocations`, and with
// `static-link-storage` also on it is the pool `LwipLinks::bind_driver` binds
// from, which `wz-link-lwip`'s `link_storage_allocations` reads link-level.
#![cfg(not(feature = "session-slot"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(feature = "static-link-storage")]
use wz_link_lwip::rx_sockets::SessionRxPool;
use wz_link_lwip::rx_sockets::{SESSION_RX_SLOTS, SESSION_RX_SLOT_SIZE};
use wz_link_lwip::LwipLink;
use wz_runtime_coop::session_drive::{
    spawn_session, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole, UdpPeer,
};
use wz_runtime_coop::session_runtime::new_session_actions;
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::session_actions::SessionLinkActions;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::WhatAmI;
use wz_session_lwip::LwipLinks;

/// The smallest allocation read as link state: one socket's receive queue.
const LINK_STATE_BYTES: usize = SESSION_RX_SLOTS * SESSION_RX_SLOT_SIZE;

/// Counts the allocations of the measurement the allocating thread works for.
struct CountingAllocator;

/// One measurement's count: whether its window is open, how many allocations it
/// saw, and how many of those were as large as a socket's receive queue.
struct Tally {
    open: AtomicBool,
    allocations: AtomicUsize,
    link_state: AtomicUsize,
}

thread_local! {
    /// The measurement this thread works for, if any; `const` initialisation of a
    /// destructor-free type, so reading it from inside `alloc` cannot allocate.
    static OWNER: Cell<Option<&'static Tally>> = const { Cell::new(None) };
}

fn count_one(size: usize) {
    if let Some(tally) = OWNER.with(Cell::get) {
        if tally.open.load(Ordering::SeqCst) {
            tally.allocations.fetch_add(1, Ordering::SeqCst);
            if size >= LINK_STATE_BYTES {
                tally.link_state.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a read of a
// thread-local without a destructor and atomic bumps, none of which allocates or
// unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_one(layout.size());
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_one(layout.size());
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_one(new_size);
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

/// What a window allocated: everything, and the part as large as link state.
#[derive(Debug, Clone, Copy)]
struct Cost {
    allocations: usize,
    link_state: usize,
}

struct Measurement {
    tally: &'static Tally,
}

impl Measurement {
    /// The calling thread works for the new measurement until it drops.
    fn new() -> Self {
        let tally: &'static Tally = Box::leak(Box::new(Tally {
            open: AtomicBool::new(false),
            allocations: AtomicUsize::new(0),
            link_state: AtomicUsize::new(0),
        }));
        OWNER.with(|owner| owner.set(Some(tally)));
        Self { tally }
    }

    fn count<R>(&self, f: impl FnOnce() -> R) -> (R, Cost) {
        let allocations = self.tally.allocations.load(Ordering::SeqCst);
        let link_state = self.tally.link_state.load(Ordering::SeqCst);
        self.tally.open.store(true, Ordering::SeqCst);
        let out = f();
        self.tally.open.store(false, Ordering::SeqCst);
        let cost = Cost {
            allocations: self.tally.allocations.load(Ordering::SeqCst) - allocations,
            link_state: self.tally.link_state.load(Ordering::SeqCst) - link_state,
        };
        (out, cost)
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        OWNER.with(|owner| owner.set(None));
    }
}

/// A clock that never moves: no deadline fires, so the handshake does only what it
/// is asked.
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

fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: vec![zid; 4],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: vec![],
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        cookie_signing_key: wz_session_core::signing_key::SigningKey::new(vec![7u8; 32])
            .expect("key"),
    }
}

/// The session sockets of the links under test: out of a cell of a `static` pool on
/// the fixed profile, a heap box on the default one.
#[cfg(feature = "static-link-storage")]
static SESSIONS: SessionRxPool<2> = SessionRxPool::new();

fn links_over(link: Rc<LwipLink>) -> LwipLinks {
    #[cfg(feature = "static-link-storage")]
    {
        LwipLinks::new(link, &SESSIONS)
    }
    #[cfg(not(feature = "static-link-storage"))]
    {
        LwipLinks::new(link)
    }
}

type Actions = SessionLinkActions<CoopRuntime<Frozen>, CoopTime<Frozen>>;

/// An acceptor and an initiator, opened over the loopback through `LwipLinks`,
/// carried to Established by the drive loop, and dropped.
fn a_session_pair_from_open_to_teardown(link: Rc<LwipLink>, port: u16) -> bool {
    let links = links_over(link);
    let runtime = CoopRuntime::new(Frozen);
    let local = CoopLocalSet::new(&runtime);
    let config = |role| SessionDriveConfig {
        timeouts: SessionTimeouts::spec_defaults(),
        role,
        max_iters: None,
    };

    let OpenedLink {
        sink: acceptor_sink,
        pump: acceptor_pump,
    } = links.open_acceptor(port).expect("bind the acceptor");
    let acceptor_actions = new_session_actions(
        acceptor_sink,
        params(0xa1),
        CoopTime::new(&runtime),
        Counting(1),
    );
    let _acceptor = spawn_session(
        &local,
        acceptor_pump,
        acceptor_actions.clone(),
        CoopTime::new(&runtime),
        config(SessionRole::Acceptor),
        |_| {},
    );

    let OpenedLink {
        sink: initiator_sink,
        pump: initiator_pump,
    } = links
        .open_initiator(UdpPeer {
            addr: [127, 0, 0, 1],
            port,
        })
        .expect("open the initiator");
    let initiator_actions =
        Actions::new_generic(initiator_sink, params(0xb1), CoopTime::new(&runtime));
    let _initiator = spawn_session(
        &local,
        initiator_pump,
        initiator_actions.clone(),
        CoopTime::new(&runtime),
        config(SessionRole::Initiator),
        |_| {},
    );

    for _ in 0..64 {
        local.run_until_idle();
        if initiator_actions.is_established() && acceptor_actions.is_established() {
            break;
        }
    }
    initiator_actions.is_established() && acceptor_actions.is_established()
}

#[test]
fn the_link_state_of_a_session_pair_is_not_on_the_heap() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let m = Measurement::new();

    let (established, cost) = m.count(|| a_session_pair_from_open_to_teardown(link, 7731));
    assert!(
        established,
        "the pair reached Established over the pooled sockets"
    );

    if cfg!(feature = "static-link-storage") {
        assert_eq!(
            cost.link_state, 0,
            "no allocation as large as a socket's {LINK_STATE_BYTES}-byte receive queue \
             ({} allocations in all, which are the session shell above the link)",
            cost.allocations
        );
    } else {
        assert!(
            cost.link_state >= 2,
            "CONTROL: each of the two sockets is one heap box of at least \
             {LINK_STATE_BYTES} bytes, and the instrument must see them (saw {})",
            cost.link_state
        );
    }
}

#[cfg(feature = "static-link-storage")]
#[test]
fn a_link_opened_with_every_session_socket_taken_is_exhausted_counted_and_reopens_after_a_drop() {
    use wz_runtime_coop::session_drive::LinkOpenError;

    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let links = links_over(Rc::new(link));
    let before = SESSIONS.refusals();
    let m = Measurement::new();

    let (first, cost) = m.count(|| links.open_acceptor(7741).expect("the first cell"));
    assert_eq!(
        cost.link_state, 0,
        "claiming a cell is not a heap allocation"
    );
    let second = links.open_acceptor(7742).expect("the second cell");
    assert_eq!(SESSIONS.in_use(), 2);

    let (refused, cost) = m.count(|| links.open_acceptor(7743).err());
    assert!(
        matches!(refused, Some(LinkOpenError::Exhausted)),
        "the third open finds no cell"
    );
    assert_eq!(cost.link_state, 0, "and falls back to no heap box");
    assert_eq!(
        SESSIONS.refusals(),
        before + 1,
        "the pool counted the refusal"
    );

    drop(first);
    let (again, cost) = m.count(|| links.open_acceptor(7743));
    assert!(again.is_ok(), "a dropped link's cell is found again");
    assert_eq!(cost.link_state, 0);
    drop((second, again));
    assert_eq!(SESSIONS.in_use(), 0);
}

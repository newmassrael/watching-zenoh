// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.1 on the FRAGMENTED send, counted by the allocator:
//! over a link that lends its transmit slots, a message past the MTU leaves as
//! a chain of fragments each encoded straight into a slot of its own, so
//! cutting a message up costs no allocation beyond what sending it whole costs.
//!
//! The measurement is a DIFFERENCE between two sends of the same payload on
//! two sessions that differ only in their batch budget: one budget holds the
//! frame (it leaves as one lent slot), the other is a fraction of it (it leaves
//! as a chain). Building the message (the key and payload of the `Put`)
//! allocates the same on both, so the difference is what the chain costs. The
//! heap form encoded the whole frame into a vector and then built every
//! fragment as a vector of its own; that is the count the first test refuses.
//!
//! The link's slots and its record of what it was handed are allocated before
//! the count starts, and it returns each slot as it is sent, so a chain of any
//! length runs in two slots.
//!
//! The count is PER THREAD. The whole send runs on the test's own thread (the
//! session is driven synchronously, the link is a plain object, no task is
//! spawned), so the allocations of that thread are exactly the measurement's.
//! The counter used to be process-wide behind a lock that serialised only the
//! two tests' windows; libtest starts, reports and joins tests on threads of
//! its own, and an allocation of theirs landing inside a window moved a count
//! by one. Measured before this change, 60 runs per row: 1 failed on two cores
//! (the claim test, chain 2 against whole 3) and 2 on all 32 (the same, and the
//! control, whole 4 against chain 17, the figures the hosted run printed). The
//! two controls at the end pin the two halves of the attribution: an allocation
//! on another thread is not counted, and one on the measuring thread is.
//! Host-test level.
#![cfg(all(feature = "codec-push", feature = "transport-fragmentation"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, UnsafeCell};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::new_session_actions;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, TxSlot, TxSlotGrant};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

/// Counts the allocations made BY THE CURRENT THREAD.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// bump of a thread-local cell without a destructor, which neither allocates
// nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
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

fn allocations() -> usize {
    ALLOCATIONS.with(Cell::get)
}

/// One slot's memory, lent to one party at a time (the contract
/// `tx_slot_storage` states).
struct SlotMem(UnsafeCell<Box<[u8]>>);

// SAFETY: the link lends a slot and does not touch it until it is sent or
// aborted; the tests are single-threaded around each send.
unsafe impl Sync for SlotMem {}
unsafe impl Send for SlotMem {}

const SLOTS: usize = 2;
/// Holds the whole frame of [`PAYLOAD`] after the headroom.
const SLOT_LEN: usize = 4200;
const HEADROOM: usize = 4;
/// Room for everything one test sends, reserved before the count starts.
const RECORD: usize = 64 * 1024;

/// A link whose slots and records are all allocated up front.
struct PoolLink {
    lends: bool,
    slots: Vec<SlotMem>,
    taken: Mutex<[bool; SLOTS]>,
    /// Every frame's bytes, end to end, whichever door it came through.
    wire: Mutex<Vec<u8>>,
    /// `(slot door, length)` per frame, in arrival order.
    frames: Mutex<Vec<(bool, usize)>>,
}

impl PoolLink {
    fn new(lends: bool) -> Arc<Self> {
        Arc::new(Self {
            lends,
            slots: (0..SLOTS)
                .map(|_| SlotMem(UnsafeCell::new(vec![0u8; SLOT_LEN].into_boxed_slice())))
                .collect(),
            taken: Mutex::new([false; SLOTS]),
            wire: Mutex::new(Vec::with_capacity(RECORD)),
            frames: Mutex::new(Vec::with_capacity(1024)),
        })
    }

    fn record(&self, lent: bool, bytes: &[u8]) {
        let mut wire = self.wire.lock().expect("wire");
        assert!(
            wire.len() + bytes.len() <= wire.capacity(),
            "the record must not grow while it is counted"
        );
        wire.extend_from_slice(bytes);
        self.frames
            .lock()
            .expect("frames")
            .push((lent, bytes.len()));
    }

    fn lent_frames(&self) -> usize {
        self.frames
            .lock()
            .expect("frames")
            .iter()
            .filter(|(lent, _)| *lent)
            .count()
    }

    fn heap_frames(&self) -> usize {
        self.frames
            .lock()
            .expect("frames")
            .iter()
            .filter(|(lent, _)| !*lent)
            .count()
    }
}

impl BoxedLinkDriver for PoolLink {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.record(false, bytes);
        LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}

    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        if !self.lends {
            return None;
        }
        let mut taken = self.taken.lock().expect("taken");
        let idx = taken.iter().position(|t| !*t)?;
        taken[idx] = true;
        Some(TxSlotGrant {
            slot: TxSlot(idx as u32),
            headroom: HEADROOM,
        })
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        // SAFETY: the slot was granted and neither sent nor aborted.
        unsafe {
            let bytes = &mut *self.slots[slot.0 as usize].0.get();
            (bytes.as_mut_ptr(), bytes.len())
        }
    }

    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        let idx = slot.0 as usize;
        // SAFETY: the session handed the slot over, so this is its only reader.
        let bytes = unsafe { &(&*self.slots[idx].0.get())[start..start + len] };
        self.record(true, bytes);
        self.taken.lock().expect("taken")[idx] = false;
        LinkSendOutcome::Sent
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.taken.lock().expect("taken")[slot.0 as usize] = false;
    }
}

const KEY: &str = "home/fragmented";
static PAYLOAD: [u8; 2000] = [0x5A; 2000];
/// Holds the whole frame of [`PAYLOAD`].
const WHOLE_BUDGET: u16 = 4096;
/// A fraction of it: the frame leaves as a chain.
const CHAIN_BUDGET: u16 = 160;

/// Allocations of ONE push of [`PAYLOAD`] on a fresh session over `link` with a
/// batch budget of `budget`, after a warm-up push of the same message.
fn measure(link: Arc<PoolLink>, budget: u16) -> usize {
    let mut params = fixture_session_init_params();
    params.batch_size = budget;
    let actions = new_session_actions(link, params, TokioTime::new());
    actions
        .send_push_literal(KEY, &PAYLOAD, true)
        .expect("warm-up push");
    let before = allocations();
    actions
        .send_push_literal(KEY, &PAYLOAD, true)
        .expect("measured push");
    allocations() - before
}

/// THE CLAIM: cutting a message into a chain over a lending link costs no
/// allocation. The whole frame and the chain are both in slots, so the two
/// counts are the same.
#[test]
fn a_chain_over_a_lending_link_allocates_nothing_the_whole_frame_does_not() {
    let whole_link = PoolLink::new(true);
    let whole = measure(whole_link.clone(), WHOLE_BUDGET);
    assert_eq!(
        (whole_link.lent_frames(), whole_link.heap_frames()),
        (2, 0),
        "CONTROL: the whole frame left as one lent slot, twice"
    );

    let chain_link = PoolLink::new(true);
    let chain = measure(chain_link.clone(), CHAIN_BUDGET);
    let fragments = chain_link.lent_frames() + chain_link.heap_frames();
    assert!(
        fragments >= 2 * (PAYLOAD.len() / CHAIN_BUDGET as usize),
        "CONTROL: the message left as a chain both times: {fragments} frames"
    );
    assert_eq!(
        chain,
        whole,
        "a chain of {} fragments allocated {} more than the whole frame",
        fragments / 2,
        chain.saturating_sub(whole)
    );
    assert_eq!(
        chain_link.heap_frames(),
        0,
        "and every fragment left as a lent slot"
    );
}

/// THE INSTRUMENT'S CONTROL: over a link that lends nothing the chain IS built
/// on the heap, and the count sees it. A counter that read zero here would be
/// blind, and the claim above would be no evidence.
#[test]
fn a_chain_over_a_link_that_lends_nothing_is_seen_allocating() {
    let whole = measure(PoolLink::new(false), WHOLE_BUDGET);
    let chain_link = PoolLink::new(false);
    let chain = measure(chain_link.clone(), CHAIN_BUDGET);
    let fragments = chain_link.heap_frames() / 2;
    assert!(
        chain >= whole + fragments,
        "the heap chain allocates at least one vector per fragment: \
         whole {whole}, chain {chain}, {fragments} fragments"
    );
}

/// THE ATTRIBUTION'S CONTROL, first half: the window sees what the measuring
/// thread allocates. Without it a counter that read zero for every thread would
/// pass the second half and the claim above.
#[test]
fn the_window_counts_what_its_own_thread_allocates() {
    let before = allocations();
    let boxed: Vec<Box<u64>> = (0..8u64).map(Box::new).collect();
    let spent = allocations() - before;
    assert!(
        spent >= boxed.len(),
        "eight boxes were allocated on this thread and the window saw {spent}"
    );
}

/// THE ATTRIBUTION'S CONTROL, second half: another thread allocating while the
/// window is open does not move it. The helper is started and told to go before
/// and inside the window with flags alone (no allocation on this thread), and
/// allocates a thousand times while this thread spins.
#[test]
fn the_window_does_not_count_what_another_thread_allocates() {
    let go = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let helper = {
        let (go, done) = (go.clone(), done.clone());
        std::thread::spawn(move || {
            while !go.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
            let mut kept = Vec::new();
            for i in 0..1000u64 {
                kept.push(std::hint::black_box(Box::new(i)));
            }
            done.store(true, Ordering::SeqCst);
            kept.len()
        })
    };
    let before = allocations();
    go.store(true, Ordering::SeqCst);
    while !done.load(Ordering::SeqCst) {
        std::hint::spin_loop();
    }
    let spent = allocations() - before;
    let helper_made = helper.join().expect("the helper thread");
    assert_eq!(helper_made, 1000, "the helper did allocate");
    assert_eq!(
        spent, 0,
        "a thousand allocations on another thread moved this thread's window"
    );
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! What the pico C ABI on the cooperative engine allocates to open a session, phase by phase: the
//! process pools a program's first config reserves, a peer's open on a listening port, its read
//! task, and a client's open that dials it, and its read task. One line per phase and one per size
//! the phase allocated, largest first:
//!
//! ```text
//! open-heap: <phase> allocs=<n> bytes=<b> peak_rise=<p> live_rise=<l>
//! open-heap:   size=<s> count=<c>
//! ```
//!
//! `bytes` is every allocation of the phase, `peak_rise` the most the live heap rose over
//! what it was when the phase began, and `live_rise` what it rose by at its end: what the phase
//! left reserved. The sizes name the reservations (an arena is one allocation of its plan's bytes,
//! the process pools one of theirs), which is what a measurement of the library's memory against
//! zenoh-pico's is read from.
//!
//! The allocator is installed as this executable's own (`#[global_allocator]`), which is why the
//! file is an executable of its own, and its one test is `#[ignore]`d: a MEASUREMENT, it asserts
//! only that each step answers `Z_OK`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::CString;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan_mut, z_session_move, zp_config_insert,
    zp_start_read_task, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// How many allocations the record keeps; one past them is counted and not recorded.
const RECORDS: usize = 16_384;

/// The phase each recorded allocation was made in, 0 for none, and its size.
static PHASES: [AtomicU8; RECORDS] = [const { AtomicU8::new(0) }; RECORDS];
static SIZES: [AtomicUsize; RECORDS] = [const { AtomicUsize::new(0) }; RECORDS];
static NEXT: AtomicUsize = AtomicUsize::new(0);
/// The phase now, 0 while none is measured.
static PHASE: AtomicU8 = AtomicU8::new(0);
/// The bytes allocated and not freed, by every thread, and the most they reached since the phase
/// began.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Record an allocation of `size` bytes in the phase now; touches no heap.
fn record(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::SeqCst) + size;
    PEAK.fetch_max(live, Ordering::SeqCst);
    let phase = PHASE.load(Ordering::SeqCst);
    if phase == 0 {
        return;
    }
    let at = NEXT.fetch_add(1, Ordering::SeqCst);
    if let (Some(phase_cell), Some(size_cell)) = (PHASES.get(at), SIZES.get(at)) {
        size_cell.store(size, Ordering::SeqCst);
        phase_cell.store(phase, Ordering::SeqCst);
    }
}

/// The allocator this executable runs on: the system's, every call recorded.
struct Recording;

// SAFETY: every call is forwarded to the system allocator unchanged.
unsafe impl GlobalAlloc for Recording {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            record(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
            record(new_size);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Recording = Recording;

/// The phases, in the order they run.
const PHASE_NAMES: [&str; 5] = [
    "first-config",
    "peer-open",
    "peer-read-task",
    "client-open",
    "client-read-task",
];

/// Run `step` as phase `phase` (from 1) and print what it allocated.
fn measured(phase: u8, step: impl FnOnce()) {
    let first = NEXT.load(Ordering::SeqCst);
    let live = LIVE.load(Ordering::SeqCst);
    PEAK.store(live, Ordering::SeqCst);
    PHASE.store(phase, Ordering::SeqCst);
    step();
    PHASE.store(0, Ordering::SeqCst);
    let last = NEXT.load(Ordering::SeqCst).min(RECORDS);
    let peak = PEAK.load(Ordering::SeqCst);
    let end = LIVE.load(Ordering::SeqCst);
    let mut sizes: Vec<usize> = (first..last)
        .filter(|&at| PHASES[at].load(Ordering::SeqCst) == phase)
        .map(|at| SIZES[at].load(Ordering::SeqCst))
        .collect();
    let bytes: usize = sizes.iter().sum();
    let name = PHASE_NAMES[usize::from(phase) - 1];
    println!(
        "open-heap: {name} allocs={} bytes={bytes} peak_rise={} live_rise={}",
        sizes.len(),
        peak.saturating_sub(live),
        end as isize - live as isize,
    );
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    let mut at = 0;
    let mut shown = 0;
    while at < sizes.len() && shown < 24 {
        let size = sizes[at];
        let count = sizes[at..].iter().take_while(|&&s| s == size).count();
        println!("open-heap:   size={size} count={count}");
        at += count;
        shown += 1;
    }
}

/// A config of `mode` with `endpoint` under `key`.
unsafe fn config(mode: &std::ffi::CStr, key: u8, endpoint: &str) -> z_owned_config_t {
    let mut cfg: z_owned_config_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { z_config_default(&mut cfg) }, Z_OK);
    assert_eq!(
        unsafe {
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_MODE_KEY,
                mode.as_ptr(),
            )
        },
        Z_OK
    );
    let endpoint = CString::new(endpoint).expect("an endpoint has no NUL");
    assert_eq!(
        unsafe { zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()) },
        Z_OK
    );
    cfg
}

/// Open a session of `cfg`.
unsafe fn open(mut cfg: z_owned_config_t) -> z_owned_session_t {
    let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) },
        Z_OK
    );
    session
}

/// Start the read task of `session` and let it run.
unsafe fn read_task(session: &mut z_owned_session_t) {
    assert_eq!(
        unsafe { zp_start_read_task(z_session_loan_mut(session), std::ptr::null()) },
        Z_OK
    );
    std::thread::sleep(Duration::from_millis(200));
}

#[test]
#[ignore = "a measurement of the heap a session's open takes; run with --ignored --nocapture"]
fn the_heap_a_session_takes_to_open_measured() {
    let endpoint = format!("tcp/127.0.0.1:{}", free_port());
    // SAFETY (every unsafe call below): the handles are this test's, made and used on this thread.
    let mut peer_cfg = None;
    measured(1, || {
        peer_cfg = Some(unsafe { config(c"peer", Z_CONFIG_LISTEN_KEY, &endpoint) });
    });
    let mut peer = None;
    measured(2, || {
        peer = Some(unsafe { open(peer_cfg.take().expect("made above")) });
    });
    let mut peer = peer.expect("opened above");
    measured(3, || unsafe { read_task(&mut peer) });
    let client_cfg = unsafe { config(c"client", Z_CONFIG_CONNECT_KEY, &endpoint) };
    let mut client = None;
    measured(4, || {
        client = Some(unsafe { open(client_cfg) });
    });
    let mut client = client.expect("opened above");
    measured(5, || unsafe { read_task(&mut client) });
    for session in [&mut client, &mut peer] {
        unsafe {
            z_close(z_session_loan_mut(session), std::ptr::null());
            z_session_drop(z_session_move(session));
        }
    }
}

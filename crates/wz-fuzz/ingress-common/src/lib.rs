// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the fuzz targets of the network ingress share: the units a peer's bytes arrive in, the
//! replies that open a session before the fuzzer's bytes reach it, the clock those targets move,
//! and the count of what the code under test allocates while it reads them.
//!
//! No crate of the session shell is a dependency here: each target builds the shell on a profile
//! of its own (the heap profile, the per-session slot profile, the C ABI's engine), and a
//! dependency of this crate on one of them would carry its features into every target.

use core::fmt;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The sequence-number and request-id resolutions (2 and 2, packed as the InitAck carries them)
/// and the batch size the sessions of the targets are opened with: the InitAck answers them
/// unchanged, so nothing but the fuzzer's bytes after the handshake can refuse the session.
pub const SN_RES_BYTE: u8 = 2 | (2 << 2);
/// See [`SN_RES_BYTE`].
pub const BATCH: u16 = 1024;

/// The most a session's live heap may grow by while it reads one input. An input is at most
/// tens of kilobytes (`scripts/fuzz.sh`), and every table a peer can fill is held to the
/// session's limits, so a growth past this is an amplification no limit stopped.
pub const GROWTH_LIMIT: usize = 64 << 20;

/// What a far end that accepts a dial answers, in order: the InitAck to the session's InitSyn
/// and the OpenAck to its OpenSyn. The bytes are the hand-written fixtures of
/// `wz-session-wire-fixtures`, not the output of the encoder under test.
pub fn handshake_replies() -> [Vec<u8>; 2] {
    [
        wz_session_wire_fixtures::craft_initack_wire_with_caps(&[0xC0, 0x01], SN_RES_BYTE, BATCH),
        wz_session_wire_fixtures::craft_openack_wire(0),
    ]
}

/// The units of `data`: each behind its two-byte little-endian length, the framing a stream
/// link reads, and the last one cut short where the input ends.
pub fn units(data: &[u8]) -> Units<'_> {
    Units { rest: data }
}

/// See [`units`].
pub struct Units<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Units<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let data: &'a [u8] = self.rest;
        let [lo, hi, body @ ..] = data else {
            self.rest = &[];
            return None;
        };
        let len = usize::from(u16::from_le_bytes([*lo, *hi]));
        let (unit, after) = body.split_at(len.min(body.len()));
        self.rest = after;
        Some(unit)
    }
}

/// The time the targets' clocks read, in microseconds. It moves only when a target moves it, so
/// a run of one input takes the same path every time.
static NOW_US: AtomicU64 = AtomicU64::new(START_US);

/// Where [`reset_clock`] puts the time: far enough from zero that no deadline computed back
/// from it wraps.
pub const START_US: u64 = 1_000_000;

/// The time, in microseconds.
pub fn now_us() -> u64 {
    NOW_US.load(Ordering::Relaxed)
}

/// Put the time back at [`START_US`], for a target whose runtime is made anew for each input.
pub fn reset_clock() {
    NOW_US.store(START_US, Ordering::Relaxed);
}

/// Move the time on by `ms` milliseconds.
pub fn advance_ms(ms: u64) {
    NOW_US.fetch_add(ms.saturating_mul(1_000), Ordering::Relaxed);
}

/// A formatter that writes nowhere: rendering a value through it runs its `Debug` without
/// allocating, which is what a target that holds every outcome to being nameable asks.
pub struct Discard;

impl fmt::Write for Discard {
    fn write_str(&mut self, _: &str) -> fmt::Result {
        Ok(())
    }
}

/// The bytes the program holds on the heap now, the most it held since the last
/// [`Window::open`], and how many allocations it has made.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

/// The system allocator, counted. A target declares it its `#[global_allocator]`, and
/// [`Window`] reads the counts.
pub struct CountingAlloc;

fn noted(size: usize) {
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    let live = LIVE.fetch_add(size, Ordering::Relaxed).saturating_add(size);
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every call is `System`'s with the caller's own arguments, so this allocator keeps
// `System`'s contract; the counters only watch.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller holds `GlobalAlloc::alloc`'s contract, which is `System`'s.
        let at = unsafe { System.alloc(layout) };
        if !at.is_null() {
            noted(layout.size());
        }
        at
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        let at = unsafe { System.alloc_zeroed(layout) };
        if !at.is_null() {
            noted(layout.size());
        }
        at
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by this allocator, which is `System`, with `layout`.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as for `dealloc`, and `new_size` is the caller's under the same contract.
        let at = unsafe { System.realloc(ptr, layout, new_size) };
        if !at.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            noted(new_size);
        }
        at
    }
}

/// The heap as it was when a target began to watch it: what it has grown by at most since, and
/// how many allocations were made since.
pub struct Window {
    live: usize,
    allocations: u64,
}

impl Window {
    /// Begin watching. Panics when [`CountingAlloc`] is not the program's allocator, so a target
    /// that forgot to declare it fails on its first input instead of holding nothing.
    pub fn open() -> Self {
        let before = ALLOCATIONS.load(Ordering::Relaxed);
        drop(std::hint::black_box(Box::new(0u8)));
        assert!(
            ALLOCATIONS.load(Ordering::Relaxed) > before,
            "the target declares CountingAlloc as its global allocator"
        );
        let live = LIVE.load(Ordering::Relaxed);
        PEAK.store(live, Ordering::Relaxed);
        Self {
            live,
            allocations: ALLOCATIONS.load(Ordering::Relaxed),
        }
    }

    /// The most the live heap has grown by since the window opened.
    pub fn peak_growth(&self) -> usize {
        PEAK.load(Ordering::Relaxed).saturating_sub(self.live)
    }

    /// How many allocations were made since the window opened.
    pub fn allocations(&self) -> u64 {
        ALLOCATIONS
            .load(Ordering::Relaxed)
            .saturating_sub(self.allocations)
    }
}

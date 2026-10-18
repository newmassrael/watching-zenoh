// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A counting `#[global_allocator]` for the exhaustion tests, written once.
//!
//! The same instrument as `session_pump_allocations`' (and `session_slot_allocations`'),
//! attributed to the measurement's own thread: a measurement owns a tally, its
//! thread works for it, and an allocation counts only when the thread that makes it
//! works for a measurement whose window is open. libtest starts, reports and fails
//! tests on threads of its own, and none of those works for a measurement, so none
//! can move a number. A test file includes this module and installs the allocator:
//!
//! ```text
//! #[path = "support/alloc_count.rs"]
//! mod alloc_count;
//! #[global_allocator]
//! static GLOBAL: alloc_count::CountingAllocator = alloc_count::CountingAllocator;
//! ```
//!
//! Set `WZ_ALLOC_SITES=1` to print, for every window that allocated, where in this
//! workspace each counted allocation was made.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Counts the allocations of the measurement the allocating thread works for.
pub struct CountingAllocator;

/// One measurement's count: whether its window is open, what its threads
/// allocated while it was, and (when asked for) where.
struct Tally {
    open: AtomicBool,
    allocations: AtomicUsize,
    capture_sites: bool,
    /// Whether a window that allocated prints its sites (`WZ_ALLOC_SITES`).
    print_sites: bool,
    sites: Mutex<BTreeMap<String, usize>>,
    /// The crate of the INNERMOST workspace frame of each counted allocation: who
    /// asked for the memory, one level of attribution coarser than `sites`.
    owners: Mutex<BTreeMap<String, usize>>,
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
    let mut owner: Option<String> = None;
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
        if owner.is_none() {
            owner = Some(owner_of(&at));
        }
        frames.push(format!("{symbol} ({place})"));
        if frames.len() == 5 {
            break;
        }
    }
    if owner.is_none() && tally.print_sites {
        // No frame of this workspace on the stack at all: print the whole backtrace,
        // which is the only way to see who the request came from.
        println!("--- an allocation with no workspace frame:\n{text}");
    }
    *tally
        .owners
        .lock()
        .expect("not poisoned")
        .entry(owner.unwrap_or_else(|| "(outside this workspace)".to_string()))
        .or_insert(0) += 1;
    let key = frames.join("  <-  ");
    *tally
        .sites
        .lock()
        .expect("not poisoned")
        .entry(key)
        .or_insert(0) += 1;
}

/// The crate a source path belongs to: the directory under `crates/`, `out/` or the
/// vendored SCE's `backends/rust/`.
fn owner_of(path: &str) -> String {
    for marker in ["/crates/", "/out/", "/backends/rust/"] {
        if let Some((_, rest)) = path.split_once(marker) {
            let name = rest.split('/').next().unwrap_or(rest);
            return format!("{}{name}", marker.trim_start_matches('/'));
        }
    }
    path.to_string()
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

/// A measurement owned by the test thread that made it, with a tally of its own.
pub struct Measurement {
    tally: &'static Tally,
}

impl Measurement {
    /// The calling thread works for the new measurement until it drops. The tally
    /// is leaked, a few bytes per test, so a thread that outlives the
    /// measurement and still reads it never reads freed memory.
    // Each test file includes this module whole and uses the constructor it needs.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::build(false)
    }

    /// A measurement that always records who asked for each allocation, so a window
    /// can be read by the crate that made the request ([`Self::owners`]): for a window
    /// where the code under test is not the only code that runs.
    #[allow(dead_code)]
    pub fn attributing() -> Self {
        Self::build(true)
    }

    fn build(always_capture: bool) -> Self {
        let print_sites = std::env::var_os("WZ_ALLOC_SITES").is_some();
        let tally: &'static Tally = Box::leak(Box::new(Tally {
            open: AtomicBool::new(false),
            allocations: AtomicUsize::new(0),
            capture_sites: print_sites || always_capture,
            print_sites,
            sites: Mutex::new(BTreeMap::new()),
            owners: Mutex::new(BTreeMap::new()),
        }));
        OWNER.with(|owner| owner.set(Some(tally)));
        Self { tally }
    }

    /// The allocations of the last [`Self::count`], by the crate that asked for them
    /// (the innermost frame of this workspace on the stack of each); empty unless
    /// the measurement was made with [`Self::attributing`] or `WZ_ALLOC_SITES`.
    #[allow(dead_code)]
    pub fn owners(&self) -> BTreeMap<String, usize> {
        self.tally.owners.lock().expect("not poisoned").clone()
    }

    /// Run `f` and return its result with the allocations this measurement's
    /// threads made while it ran.
    pub fn count<R>(&self, what: &str, f: impl FnOnce() -> R) -> (R, usize) {
        self.tally.sites.lock().expect("not poisoned").clear();
        self.tally.owners.lock().expect("not poisoned").clear();
        let before = self.tally.allocations.load(Ordering::SeqCst);
        self.tally.open.store(true, Ordering::SeqCst);
        let out = f();
        self.tally.open.store(false, Ordering::SeqCst);
        let n = self.tally.allocations.load(Ordering::SeqCst) - before;
        if self.tally.print_sites && n > 0 {
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

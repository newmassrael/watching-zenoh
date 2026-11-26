// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The share of the process pools this executable states before its first test, and the permits
//! that hold the tests running at once to it.
//!
//! The pools are the process's, and a program's first object reserves them for one program: its
//! `HELD_*` values and the sessions it opens. libtest runs the tests of this executable, each a
//! program of its own, on its threads in one process at once, so held to one program's share the
//! tests started together find a pool empty though none of them holds more than a program may. A
//! host that runs several programs in one process states their share itself, through the pools'
//! door, and runs no more of them at once than it stated: this harness reserves the share of as
//! many programs as the host runs threads in parallel before `main`, so before any test makes an
//! object, and each test runs while it holds one of as many permits ([`admit`]). The target
//! requires the door for that (`Cargo.toml`).
//!
//! The permits, not libtest's thread count, bound the programs running at once: a share sized by
//! the thread count a run names would grow with it past what the process is given beside the pools
//! (its threads, its memory), and a test would then be refused by how the tests started together
//! fall, a result that moves with the thread count. A test past the permits waits for one, so every
//! test runs among as many programs whatever the run names. Each test of `files/` opens with its
//! permit, and a test of this file refuses one that does not.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

use wz_capi_pico::object_pool::{
    zext_object_pool_bytes, zext_object_pool_counts_t, zext_object_pool_reserve,
};
use wz_capi_pico::Z_OK;
use wz_session_core::caps;

/// How many programs the share was reserved for, as the reservation before `main` counted them.
static RESERVED_FOR: AtomicUsize = AtomicUsize::new(0);

/// How many programs this executable runs at once: as many as the host runs threads in parallel,
/// libtest's own count when a run names none; one at least.
fn programs() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// The counts of `programs` programs, each holding what the build reserves for one: its
/// `HELD_*` values, and `HELD_SESSIONS` sessions each holding the build's value of every
/// entity's limit, which the limits a session opens under hold it to.
fn share(programs: usize) -> zext_object_pool_counts_t {
    let each = |count: usize| count.saturating_mul(programs);
    zext_object_pool_counts_t {
        sessions: each(caps::HELD_SESSIONS),
        publishers: caps::MAX_PUBLISHERS,
        subscribers: caps::MAX_SUBSCRIPTIONS,
        queryables: caps::MAX_QUERYABLES,
        liveliness_tokens: caps::MAX_LOCAL_TOKENS,
        liveliness_subscribers: caps::MAX_LIVELINESS_SUBSCRIPTIONS,
        samples: each(caps::HELD_SAMPLES),
        replies: each(caps::HELD_REPLIES),
        queries: each(caps::HELD_QUERIES),
        configs: each(caps::HELD_CONFIGS),
        hellos: each(caps::HELD_HELLOS),
        queriers: caps::MAX_QUERIERS,
        keyexprs: caps::MAX_DECLARED_KEYEXPRS,
        encodings: each(caps::HELD_ENCODINGS),
        gets: caps::MAX_PENDING_QUERIES,
        liveliness_gets: caps::MAX_PENDING_LIVELINESS_GETS,
        matching_listeners: caps::MAX_MATCHING_LISTENERS,
        decl_watches: caps::MAX_DECL_WATCHES,
        transport_events_listeners: caps::MAX_TRANSPORT_EVENTS_LISTENERS,
        link_events_listeners: caps::MAX_LINK_EVENTS_LISTENERS,
        small_payload_blocks: each(caps::HELD_SMALL_PAYLOAD_BLOCKS),
        medium_payload_blocks: each(caps::HELD_MEDIUM_PAYLOAD_BLOCKS),
        large_payload_blocks: each(caps::HELD_LARGE_PAYLOAD_BLOCKS),
        ..zext_object_pool_counts_t::default()
    }
}

/// The line each test of `files/` opens with, which holds its program's permit to its end.
const PERMIT_LINE: &str = "let _program = crate::programs::admit();";

/// The programs running at once, each holding a permit.
struct Gate {
    running: Mutex<usize>,
    freed: Condvar,
}

impl Gate {
    const fn new() -> Self {
        Self {
            running: Mutex::new(0),
            freed: Condvar::new(),
        }
    }

    /// The count of programs running. A test that panicked holding the lock left the count as it
    /// was, so the lock is taken as it stands.
    fn running(&self) -> MutexGuard<'_, usize> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A program's permit, waited for while `programs` run.
    fn admit(&self, programs: usize) -> Permit<'_> {
        let mut running = self
            .freed
            .wait_while(self.running(), |running| *running >= programs)
            .unwrap_or_else(PoisonError::into_inner);
        *running += 1;
        Permit(self)
    }

    /// A program's permit, or none while `programs` run.
    fn try_admit(&self, programs: usize) -> Option<Permit<'_>> {
        let mut running = self.running();
        if *running >= programs {
            return None;
        }
        *running += 1;
        Some(Permit(self))
    }
}

/// A program's place among those running at once, given back when it drops, a test's unwinding
/// included.
#[must_use = "a program runs while it holds its permit"]
pub(crate) struct Permit<'gate>(&'gate Gate);

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.running() -= 1;
        self.0.freed.notify_one();
    }
}

/// The permits of this executable's programs.
static GATE: Gate = Gate::new();

/// The permit a test holds while it runs, waited for while as many programs run as the share was
/// reserved for. Every test of `files/` opens with it (`PERMIT_LINE`).
pub(crate) fn admit() -> Permit<'static> {
    let programs = RESERVED_FOR.load(Ordering::Acquire);
    assert!(
        programs > 0,
        "the share of the programs was not reserved before main"
    );
    GATE.admit(programs)
}

/// Reserve the share of the programs this executable runs at once. A refusal leaves every test
/// to fail on a pool it does not find, so it ends the process before any runs, with the code.
extern "C" fn reserve_the_programs_share() {
    let programs = programs();
    let counts = share(programs);
    // SAFETY: `counts` is a live struct of this build's size, `struct_size` first.
    let code = unsafe { zext_object_pool_reserve(&counts) };
    if code != Z_OK {
        eprintln!("the test harness could not reserve the share of its programs: {code}");
        std::process::abort();
    }
    RESERVED_FOR.store(programs, Ordering::Release);
}

// Run by the loader before `main`, as the platform's C runtime runs its constructors.
#[used]
#[cfg_attr(
    any(target_os = "linux", target_os = "android", target_os = "freebsd"),
    link_section = ".init_array"
)]
#[cfg_attr(windows, link_section = ".CRT$XCU")]
#[cfg_attr(
    any(target_os = "macos", target_os = "ios"),
    link_section = "__DATA,__mod_init_func"
)]
static RESERVE_THE_PROGRAMS_SHARE: extern "C" fn() = reserve_the_programs_share;

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    windows,
    target_os = "macos",
    target_os = "ios"
)))]
compile_error!("the test harness states its programs' share before main on this target only");

/// The share is the held values and sessions of one program times the programs, each session's
/// entities at the build's value, and the share of the programs this run declares makes pools.
/// Turned red by a held value or the sessions not multiplied by the programs, or an entity count
/// that is.
#[test]
fn the_share_is_one_programs_held_values_times_the_programs() {
    let one = share(1);
    assert_eq!(one.sessions, caps::HELD_SESSIONS);
    assert_eq!(one.configs, caps::HELD_CONFIGS);
    assert_eq!(one.samples, caps::HELD_SAMPLES);
    assert_eq!(one.large_payload_blocks, caps::HELD_LARGE_PAYLOAD_BLOCKS);
    assert_eq!(one.publishers, caps::MAX_PUBLISHERS);
    assert_eq!(one.subscribers, caps::MAX_SUBSCRIPTIONS);
    let three = share(3);
    let held = |counts: &zext_object_pool_counts_t| {
        [
            counts.sessions,
            counts.samples,
            counts.replies,
            counts.queries,
            counts.configs,
            counts.hellos,
            counts.encodings,
            counts.small_payload_blocks,
            counts.medium_payload_blocks,
            counts.large_payload_blocks,
        ]
    };
    assert_eq!(held(&three), held(&one).map(|count| count * 3));
    let entities = |counts: &zext_object_pool_counts_t| {
        [
            counts.publishers,
            counts.subscribers,
            counts.queryables,
            counts.liveliness_tokens,
            counts.liveliness_subscribers,
            counts.queriers,
            counts.keyexprs,
            counts.gets,
            counts.liveliness_gets,
            counts.matching_listeners,
            counts.decl_watches,
            counts.transport_events_listeners,
            counts.link_events_listeners,
        ]
    };
    assert_eq!(entities(&three), entities(&one));
    assert_eq!(three.payload_bytes, 0);
    assert!(programs() >= 1);
    let mut bytes: usize = 0;
    // SAFETY: the counts are a live struct of this build's size, `bytes` a live word.
    let code = unsafe { zext_object_pool_bytes(&share(programs()), &mut bytes) };
    assert_eq!(code, Z_OK);
    assert!(bytes > 0);
}

/// The permits let as many programs run as they are for and hold the one more back until one is
/// given back, a dropped permit giving its place to the next. Turned red by a gate that does not
/// count a permit it gives, or a drop that does not give its place back.
#[test]
fn the_permits_hold_the_programs_running_at_once_to_their_count() {
    let gate = Gate::new();
    let first = gate.admit(2);
    let second = gate.try_admit(2).expect("two programs run at once");
    assert!(gate.try_admit(2).is_none(), "the one more is held back");
    drop(first);
    let third = gate
        .try_admit(2)
        .expect("a permit given back is taken again");
    assert!(
        gate.try_admit(2).is_none(),
        "and the count is reached again"
    );
    drop((second, third));
    assert_eq!(*gate.running(), 0, "every permit was given back");
    let waited = std::thread::scope(|scope| {
        let held = gate.admit(1);
        let waiter = scope.spawn(|| drop(gate.admit(1)));
        drop(held);
        waiter.join().is_ok()
    });
    assert!(
        waited,
        "a program waiting for a permit runs once one is given back"
    );
}

/// Every test of `files/` opens with its program's permit, so none runs past the share: a test
/// that holds none would run beside as many programs as libtest runs at once, and find a pool
/// empty by how they fall. Turned red by a test of `files/` whose first line is not
/// `PERMIT_LINE`.
#[test]
fn every_test_of_the_files_opens_with_its_programs_permit() {
    let files = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/files");
    let mut tests = 0usize;
    let mut without = Vec::new();
    for entry in std::fs::read_dir(&files).expect("the files of the executable") {
        let path = entry.expect("a file of the executable").path();
        if path.extension() != Some(std::ffi::OsStr::new("rs")) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a file of the executable");
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        for (at, line) in lines.iter().enumerate() {
            if *line != "#[test]" {
                continue;
            }
            tests += 1;
            let first = lines[at + 1..]
                .iter()
                .skip_while(|line| !line.starts_with("fn "))
                .nth(1)
                .copied();
            if first != Some(PERMIT_LINE) {
                without.push(format!("{}:{}", path.display(), at + 1));
            }
        }
    }
    assert!(tests > 0, "CONTROL: the files hold tests");
    assert!(
        without.is_empty(),
        "tests that run without a program's permit: {without:?}"
    );
}

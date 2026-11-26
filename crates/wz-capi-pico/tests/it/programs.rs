// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The share of the process pools this executable states before its first test.
//!
//! The pools are the process's, and a program's first object reserves them for one program: its
//! `HELD_*` values and the sessions it opens. libtest runs the tests of this executable, each a
//! program of its own, on its threads in one process at once, so held to one program's share the
//! tests started together find a pool empty though none of them holds more than a program may. A
//! host that runs several programs in one process states their share itself, through the pools'
//! door: this harness declares that it runs as many programs at once as libtest runs tests at
//! once, and reserves that many programs' share before `main`, so before any test makes an object.
//! The target requires the door for that (`Cargo.toml`).
//!
//! The count is libtest's own, read by its rule from where libtest reads it, so the share covers
//! every test libtest runs at once whatever the run names: a share smaller than that would leave
//! the tests started together to find a pool empty by how they fall, a result that moves with the
//! thread count. Before `main` the command line is read from the system's own copy of it, which
//! needs nothing of the standard library's reading, and a test holds the reservation to libtest's
//! count read again once `main` runs.

use std::sync::atomic::{AtomicUsize, Ordering};

use wz_capi_pico::object_pool::{
    wz_ext_object_pool_bytes, wz_ext_object_pool_counts_t, wz_ext_object_pool_reserve,
};
use wz_capi_pico::Z_OK;
use wz_session_core::caps;

/// How many programs the share was reserved for, as the reservation before `main` counted them.
static RESERVED_FOR: AtomicUsize = AtomicUsize::new(0);

/// How many tests libtest runs at once, by its own rule over `args` (a command line, the
/// program's name first), `env` (the value of `RUST_TEST_THREADS`) and `host` (the threads the
/// host runs in parallel): the count `--test-threads` names, else the variable's, else the host's;
/// one at least. A count that is not a positive number is passed over, as libtest runs no test
/// with one.
fn threads_of(args: impl IntoIterator<Item = String>, env: Option<&str>, host: usize) -> usize {
    let positive = |count: &str| count.parse::<usize>().ok().filter(|count| *count > 0);
    let mut args = args.into_iter();
    let mut stated = None;
    while let Some(arg) = args.next() {
        let count = if arg == "--test-threads" {
            args.next()
        } else {
            arg.strip_prefix("--test-threads=").map(str::to_owned)
        };
        if let Some(count) = count.as_deref().and_then(positive) {
            stated = Some(count);
            break;
        }
    }
    stated
        .or_else(|| env.and_then(positive))
        .unwrap_or(host)
        .max(1)
}

/// The threads the host runs in parallel, as libtest counts them when nothing names a count.
fn host_threads() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// The command line of this process, its name first, from the kernel's copy of it: the standard
/// library reads its own copy from a constructor the loader orders against this harness's only on
/// some systems, and not at all before `main` on others. A kernel that shows none leaves the
/// standard library's.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn command_line() -> Vec<String> {
    match std::fs::read("/proc/self/cmdline") {
        Ok(line) => line
            .split(|byte| *byte == 0)
            .map(|arg| String::from_utf8_lossy(arg).into_owned())
            .collect(),
        Err(_) => std_command_line(),
    }
}

/// The command line of this process, its name first, as the standard library reads it from the
/// system on each call (`GetCommandLineW` on Windows, `_NSGetArgv` on Apple's systems), before
/// `main` as after it.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn command_line() -> Vec<String> {
    std_command_line()
}

/// The command line as the standard library holds it.
fn std_command_line() -> Vec<String> {
    std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

/// How many programs this executable runs at once, which is the harness's declaration of how
/// many share the process: as many as libtest runs tests at once, read before `main`.
fn programs() -> usize {
    threads_of(
        command_line(),
        std::env::var("RUST_TEST_THREADS").ok().as_deref(),
        host_threads(),
    )
}

/// The counts of `programs` programs, each holding what the build reserves for one: its
/// `HELD_*` values, and `HELD_SESSIONS` sessions each holding the build's value of every
/// entity's limit, which the limits a session opens under hold it to.
fn share(programs: usize) -> wz_ext_object_pool_counts_t {
    let each = |count: usize| count.saturating_mul(programs);
    wz_ext_object_pool_counts_t {
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
        ..wz_ext_object_pool_counts_t::default()
    }
}

/// Reserve the share of the programs this executable runs at once. A refusal leaves every test
/// to fail on a pool it does not find, so it ends the process before any runs, with the code.
extern "C" fn reserve_the_programs_share() {
    let programs = programs();
    let counts = share(programs);
    // SAFETY: `counts` is a live struct of this build's size, `struct_size` first.
    let code = unsafe { wz_ext_object_pool_reserve(&counts) };
    if code != Z_OK {
        eprintln!("the test harness could not reserve the share of its programs: {code}");
        std::process::abort();
    }
    RESERVED_FOR.store(programs, Ordering::Relaxed);
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
    let held = |counts: &wz_ext_object_pool_counts_t| {
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
    let entities = |counts: &wz_ext_object_pool_counts_t| {
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
    let code = unsafe { wz_ext_object_pool_bytes(&share(programs()), &mut bytes) };
    assert_eq!(code, Z_OK);
    assert!(bytes > 0);
}

/// The count is read as libtest reads it: `--test-threads` in either spelling first, then
/// `RUST_TEST_THREADS`, then the host's threads, a count that is not positive passed over, one at
/// least. Turned red by a reading that leaves the command line out, or that takes the larger of the
/// variable and the host's count in place of the variable alone.
#[test]
fn the_program_count_is_read_as_libtest_reads_it() {
    let line = |args: &[&str]| args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        threads_of(line(&["it", "--test-threads=3"]), Some("7"), 5),
        3,
        "the command line first"
    );
    assert_eq!(
        threads_of(line(&["it", "--test-threads", "40", "files::"]), None, 5),
        40,
        "in its spaced spelling, past the host's count"
    );
    assert_eq!(
        threads_of(line(&["it", "files::"]), Some("2"), 5),
        2,
        "then the variable, below the host's count"
    );
    assert_eq!(threads_of(line(&["it"]), None, 5), 5, "then the host's");
    assert_eq!(
        threads_of(line(&["it", "--test-threads=0"]), Some("none"), 6),
        6,
        "a count that is not positive is passed over"
    );
    assert_eq!(
        threads_of(line(&["it", "--test-threads-x=9"]), None, 2),
        2,
        "no other flag names the count"
    );
    assert_eq!(threads_of(line(&["it"]), None, 0), 1, "one at least");
}

/// The share was reserved before `main` for as many programs as libtest runs at once, its count
/// read again from the command line the standard library holds once `main` runs. Turned red by a
/// reading before `main` that leaves the command line out, in a run that names a
/// `--test-threads` other than the host's count.
#[test]
fn the_share_is_reserved_for_as_many_programs_as_libtest_runs_at_once() {
    let libtest = threads_of(
        std::env::args(),
        std::env::var("RUST_TEST_THREADS").ok().as_deref(),
        host_threads(),
    );
    assert_eq!(RESERVED_FOR.load(Ordering::Relaxed), libtest);
}

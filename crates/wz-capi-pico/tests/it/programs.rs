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

use wz_capi_pico::object_pool::{
    wz_ext_object_pool_bytes, wz_ext_object_pool_counts_t, wz_ext_object_pool_reserve,
};
use wz_capi_pico::Z_OK;
use wz_session_core::caps;

/// How many programs this executable runs at once, which is the harness's declaration of how
/// many share the process: the larger of `RUST_TEST_THREADS` and the threads the host runs in
/// parallel, libtest's own count when its command line names none; one at least. Read before
/// `main`, where the loader's order of constructors does not promise that the standard library
/// has read the command line, so a `--test-threads` past this runs more programs than are
/// reserved for, and a test past the share is refused as out of memory.
fn programs() -> usize {
    let stated = std::env::var("RUST_TEST_THREADS")
        .ok()
        .and_then(|count| count.parse::<usize>().ok())
        .unwrap_or(0);
    let host = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    stated.max(host).max(1)
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
    let counts = share(programs());
    // SAFETY: `counts` is a live struct of this build's size, `struct_size` first.
    let code = unsafe { wz_ext_object_pool_reserve(&counts) };
    if code != Z_OK {
        eprintln!("the test harness could not reserve the share of its programs: {code}");
        std::process::abort();
    }
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

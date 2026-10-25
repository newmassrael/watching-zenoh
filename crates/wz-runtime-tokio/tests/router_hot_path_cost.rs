// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![cfg(feature = "routing-router-hat")]

//! What one `forward` costs the router on the path where nothing is full: a Put from one face
//! routed to `K` subscribed faces whose links always have room, counted in heap allocations and
//! the bytes they ask for.
//!
//! This is the instrument of Step 6 of `docs/router-task-per-face.md`: a change to the router's
//! data path is judged against the path that is not congested, and no wall clock says what it cost
//! (the host swings by a third between runs, measured). An instruction count would, and the build
//! hosts forbid it (`perf_event_paranoid` is 4 and there is no `valgrind`); a count of heap
//! allocations is the next best thing that is exact: it is the same number on every host and every
//! run, it moves when the path gains or loses an allocation, and an allocation is the part of a
//! forward that a lock or a shared structure will change. It does not see a loop that got longer.
//!
//! The test is a gate. Each case asserts the exact number of allocations and bytes per forward
//! against [`BUDGET`], so a change that adds a `clone`, a `Vec` or a `String` to the data path reads as a
//! red test that names the new figure. A figure that FELL is also red: the budget is a record, and a
//! lowered cost is recorded in the commit that earned it (as the count guards of `run-ci.sh` are).
//! A toolchain that changes how a `Vec` grows moves the figures too, and is recorded the same way.
//!
//! Also printed, never asserted: nanoseconds per forward, for a reader on a quiet host. And, on a
//! host that lets `perf` count, the instructions of the same cases:
//!
//! ```text
//! cargo test --release -p wz-runtime-tokio --features routing-router-hat --no-run \
//!     --test router_hot_path_cost
//! WZ_HOT_N=0      perf stat -e instructions:u <that binary> --exact hot_path_allocation_budget
//! WZ_HOT_N=200000 perf stat -e instructions:u <that binary> --exact hot_path_allocation_budget
//! ```
//!
//! (The difference of the two counts over `WZ_HOT_N`, four cases at once, is the instruction cost of
//! one forward of each, the set-up and the process start cancelling.)
//!
//! Every case asserts that the frames it counts are the frames it sent, so a router that routed
//! nothing cannot read as a cheap one.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use wz_runtime_core::runtime::Runtime;
use wz_runtime_tokio::accept_loop::{FaceForwarder, FaceId};
use wz_runtime_tokio::linkstate_forward::Zid;
use wz_runtime_tokio::router_forward::RouterForwarder;
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session_glue::{
    new_session_actions, BoxedLinkDriver, IterationEvent, LinkSendOutcome, SessionLinkActions,
};
use wz_runtime_tokio::Reliability;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::declare_build::build_declare_subscriber;
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::metadata::PushMetadata;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::push_build::{build_push_literal, build_push_literal_with_meta};
use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::sample::QosLevel;

/// The system allocator, counting what it is asked for.
struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method defers to `System` with the arguments it was given; the counters are atomics.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A growth is an allocation of the new size: what a `Vec` that doubles costs.
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// A link with room for everything, that counts what it was given and keeps none of it.
struct CountingLink {
    frames: AtomicUsize,
}

impl BoxedLinkDriver for CountingLink {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.frames.fetch_add(1, Ordering::Relaxed);
        LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

fn zid(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

fn client_over(link: &Arc<CountingLink>, peer: Zid) -> Arc<SessionLinkActions> {
    let actions = new_session_actions(
        link.clone(),
        fixture_session_init_params(),
        TokioTime::new(),
    );
    TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
        *s = Some(peer.as_slice().to_vec())
    });
    TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(0b10));
    actions
}

fn forward_frame(fwd: &RouterForwarder, face: FaceId, messages: Vec<NetworkMessage>) {
    let outcome = DriverLoopOutcome::FramePayload {
        priority: Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages,
        has_ext: false,
        extensions: Vec::new(),
    };
    fwd.forward(face, IterationEvent::Poll(&outcome));
}

fn put(congestion: CongestionControl) -> NetworkMessage {
    NetworkMessage::Push(Box::new(
        match congestion {
            CongestionControl::Drop => build_push_literal("demo/x", b"payload-0123456789"),
            other => {
                let meta = PushMetadata {
                    qos: Some(QosLevel::DEFAULT.with_congestion(other)),
                    ..PushMetadata::default()
                };
                build_push_literal_with_meta("demo/x", b"payload-0123456789", &meta)
            }
        }
        .expect("build push"),
    ))
}

/// What one case measured, per forward.
struct Measured {
    allocations: usize,
    bytes: usize,
    ns: u128,
}

/// `subscribers` faces subscribed to `demo/x`, one publishing face, `n` frames of one Put. The
/// message of each frame is built outside the counted span, so that what is counted is the router's
/// forward and not the test's construction of its input.
fn measure(case: &str, congestion: CongestionControl, subscribers: usize, n: usize) -> Measured {
    let fwd = RouterForwarder::new(zid(0x01));
    let publisher_link = Arc::new(CountingLink {
        frames: AtomicUsize::new(0),
    });
    let publisher = FaceId(1);
    fwd.register(publisher, &client_over(&publisher_link, zid(0xAA)));
    let mut links = Vec::new();
    for i in 0..subscribers {
        let link = Arc::new(CountingLink {
            frames: AtomicUsize::new(0),
        });
        let face = FaceId(100 + i as u64);
        fwd.register(face, &client_over(&link, zid(0xB0 + i as u8)));
        forward_frame(
            &fwd,
            face,
            vec![NetworkMessage::Declare(Box::new(
                build_declare_subscriber(7, 0, Some("demo/x")).expect("declare subscriber"),
            ))],
        );
        links.push(link);
    }
    // One forward that is not counted: the first of a keyexpr fills the route memo, and a router
    // at work has it filled.
    forward_frame(&fwd, publisher, vec![put(congestion)]);
    let before: usize = links
        .iter()
        .map(|link| link.frames.load(Ordering::Relaxed))
        .sum();

    // `WZ_HOT_N=0`: everything above and nothing below, for the instruction difference in the
    // module doc.
    if n == 0 {
        return Measured {
            allocations: 0,
            bytes: 0,
            ns: 0,
        };
    }

    // The frames the loop forwards, made first.
    let outcomes: Vec<DriverLoopOutcome> = (0..n)
        .map(|_| DriverLoopOutcome::FramePayload {
            priority: Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![put(congestion)],
            has_ext: false,
            extensions: Vec::new(),
        })
        .collect();

    let (allocations_before, bytes_before) = (
        ALLOCATIONS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
    );
    let started = Instant::now();
    for outcome in &outcomes {
        fwd.forward(publisher, IterationEvent::Poll(outcome));
    }
    let elapsed = started.elapsed();
    let (allocations, bytes) = (
        ALLOCATIONS.load(Ordering::Relaxed) - allocations_before,
        BYTES.load(Ordering::Relaxed) - bytes_before,
    );

    let delivered: usize = links
        .iter()
        .map(|link| link.frames.load(Ordering::Relaxed))
        .sum::<usize>()
        - before;
    assert_eq!(
        delivered,
        n * subscribers,
        "{case}: every subscriber was sent every put"
    );
    assert_eq!(
        (allocations % n, bytes % n),
        (0, 0),
        "{case}: a forward costs the same number of allocations every time ({allocations} over {n})"
    );
    Measured {
        allocations: allocations / n,
        bytes: bytes / n,
        ns: elapsed.as_nanos() / n as u128,
    }
}

/// The cases and the allocations and bytes one forward of each costs, as of the commit that recorded
/// them. `(case, congestion control, subscribers, allocations, bytes)`.
const BUDGET: [(&str, CongestionControl, usize, usize, usize); 4] = [
    ("drop_k1", CongestionControl::Drop, 1, 9, 2_939),
    ("block_k1", CongestionControl::Block, 1, 11, 3_067),
    ("drop_k16", CongestionControl::Drop, 16, 69, 45_374),
    ("block_k16", CongestionControl::Block, 16, 86, 46_462),
];

/// Frames per case. Few, because the figure is exact and not a mean: it is the same at 100 as at
/// 200 000, which the test asserts by its remainder.
const FRAMES: usize = 200;

#[test]
fn hot_path_allocation_budget() {
    let n: usize = std::env::var("WZ_HOT_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(FRAMES);
    let mut off = Vec::new();
    for (case, congestion, subscribers, allocations, bytes) in BUDGET {
        let got = measure(case, congestion, subscribers, n);
        if n == 0 {
            continue;
        }
        eprintln!(
            "HOTPATH case={case} subscribers={subscribers} allocations_per_forward={} \
             bytes_per_forward={} ns_per_forward={}",
            got.allocations, got.bytes, got.ns
        );
        if (got.allocations, got.bytes) != (allocations, bytes) {
            off.push(format!(
                "{case}: {} allocations and {} bytes a forward, recorded {allocations} and {bytes}",
                got.allocations, got.bytes
            ));
        }
    }
    assert!(
        off.is_empty(),
        "the router's uncongested path costs what it did not cost: {off:#?}\n\
         If the new figure is what the change should cost, record it in BUDGET in this commit."
    );
}

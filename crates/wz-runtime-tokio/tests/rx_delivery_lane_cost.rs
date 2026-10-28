// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![cfg(all(
    feature = "transport-unicast",
    feature = "declare-subscriber",
    feature = "pubsub-put",
    feature = "codec-push"
))]

//! What taking a subscriber's callback off the receive path costs, and what it buys
//! (`docs/rx-delivery-lane.md`, phase 6).
//!
//! The lane is a claim about two things, and this file measures each beside the code it is
//! compared with, in one process, one runtime and one condition:
//!
//! * the TIME the dispatching loop spends on `N` samples whose callback takes `W` microseconds: with
//!   the callback inline it is about `N * W`, and the claim is that with the lane it is about the cost
//!   of the copy, whatever `W` is;
//! * the TIME until every callback has run, which the lane can only lengthen (a copy, a hand-off),
//!   and by how much is what a deployment pays for the first claim.
//!
//! and the heap allocations per sample the dispatch makes, which are exact: the same number on every
//! host and every run.
//!
//! Four deliveries are compared: the plain subscriber (callback inline), the buffered subscriber (a
//! channel, the loop waits when it is full), and the offloaded subscriber under `reject` and under
//! `block`.
//!
//! NOTHING HERE IS A GATE ON TIME. The build hosts swing by a third between runs (measured, see
//! `router_hot_path_cost.rs`), so a time is PRINTED and read by a person on a quiet host, in a release
//! build, run on the build machine and not here:
//!
//! ```text
//! cargo test --release -p wz-runtime-tokio --all-features --test rx_delivery_lane_cost \
//!     -- --nocapture
//! WZ_LANE_N=20000 WZ_LANE_WORK_US=0,20,200 ... (the same command)
//! ```
//!
//! What IS asserted is that every case delivered every sample it was given, in order, so a delivery
//! that dropped its work cannot read as a fast one; and, for the lane under `block`, that none was
//! lost.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::{
    new_session_actions, BoxedLinkDriver, IterationEvent, LinkSendOutcome,
};
use wz_runtime_tokio::Reliability;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::policy::SubscriberOverload;
use wz_session_core::push_build::build_push_literal;
use wz_session_core::qos::Priority;

/// The system allocator, counting what it is asked for.
struct Counting;

std::thread_local! {
    /// What THIS thread has asked the allocator for. Per thread, because the consumer of an
    /// offloaded subscriber allocates on another one while the loop dispatches, and what is wanted
    /// is what the receive path itself costs: a count over the whole process would charge it for
    /// the callback's work. `const` initialised and without a destructor, so reading it inside the
    /// allocator allocates nothing.
    static ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn allocations_here() -> usize {
    ALLOCATIONS.with(std::cell::Cell::get)
}

fn count_one() {
    // `try_with`: a thread that is being torn down has no counter, and an allocator must not panic.
    let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
}

// SAFETY: every method defers to `System` with the arguments it was given; the counter is a
// per-thread cell that is never allocated through.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_one();
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_one();
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_one();
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// A link that keeps nothing: this measures the receive side.
struct NullLink;

impl BoxedLinkDriver for NullLink {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

fn session() -> TokioSession {
    let actions = new_session_actions(
        Arc::new(NullLink),
        fixture_session_init_params(),
        TokioTime::new(),
    );
    let observer = Arc::new(wz_runtime_tokio::sync::PlainMutex::new(
        ApplicationLayerObserver::new(),
    ));
    TokioSession::new(actions, observer, Arc::new(TokioTime::new()))
}

/// The inbound frame of one Put on `demo/data` whose payload is `len` bytes, the first four of which
/// say which sample it is (`len` is at least four).
fn inbound(i: u32, len: usize) -> DriverLoopOutcome {
    let mut payload = vec![0xa5u8; len.max(4)];
    payload[..4].copy_from_slice(&i.to_le_bytes());
    let push = build_push_literal("demo/data", &payload).expect("a Put is representable");
    DriverLoopOutcome::FramePayload {
        priority: Priority::DEFAULT,
        reliable: true,
        sn: u64::from(i),
        messages: vec![NetworkMessage::Push(Box::new(push))],
        has_ext: false,
        extensions: Vec::new(),
    }
}

/// A callback's work: a busy wait, because a sleep would hand the thread back and measure the
/// scheduler.
fn work(us: u64) {
    if us == 0 {
        return;
    }
    let until = Instant::now() + Duration::from_micros(us);
    while Instant::now() < until {
        std::hint::spin_loop();
    }
}

#[derive(Clone, Copy)]
enum Delivery {
    Inline,
    Buffered,
    Offloaded(SubscriberOverload),
}

impl Delivery {
    fn name(self) -> &'static str {
        match self {
            Delivery::Inline => "inline",
            Delivery::Buffered => "buffered",
            Delivery::Offloaded(SubscriberOverload::Reject) => "offloaded/reject",
            Delivery::Offloaded(SubscriberOverload::Block) => "offloaded/block",
            Delivery::Offloaded(SubscriberOverload::KeepLatest) => "offloaded/keep-latest",
        }
    }
}

struct Measured {
    /// What the dispatching loop spent handing the `N` samples over, the drain included.
    dispatch: Duration,
    /// Until every delivered callback had run.
    complete: Duration,
    /// Heap allocations the dispatching loop made, per sample.
    allocations_per_sample: f64,
    delivered: usize,
}

/// Dispatch `n` samples to one subscriber of the given delivery whose callback works `us`
/// microseconds, and measure it. The loop is this task: it dispatches, then awaits the drain, as the
/// drive loop does every iteration.
async fn measure(delivery: Delivery, n: u32, us: u64, payload: usize) -> Measured {
    let session = session();
    let seen: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::with_capacity(n as usize)));
    // How many callbacks have finished, and the wake for the one that waits for the last: a poll at
    // an interval would quantise the time it reports to the interval.
    let done = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(tokio::sync::Notify::new());
    let record = {
        let (seen, done, finished) = (seen.clone(), done.clone(), finished.clone());
        move |payload: &[u8]| {
            work(us);
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&payload[..4]);
            seen.lock().unwrap().push(u32::from_le_bytes(bytes));
            done.fetch_add(1, Ordering::SeqCst);
            finished.notify_one();
        }
    };
    let mut offloaded: Option<wz_runtime_tokio::session::OffloadedSubscriber> = None;
    // What a delivery needs to keep alive while it is measured.
    let mut keep: Vec<Box<dyn std::any::Any + Send>> = Vec::new();
    match delivery {
        Delivery::Inline => {
            let sub = session
                .declare_subscriber("demo/**", SubscribeOptions::default(), move |sample| {
                    record(sample.payload())
                })
                .expect("declares");
            keep.push(Box::new(sub));
        }
        Delivery::Buffered => {
            let (sub, mut rx, _stage) = session
                .declare_subscriber_buffered(
                    "demo/**",
                    SubscribeOptions::default(),
                    wz_session_core::caps::DELIVERY_LANE_EVENTS,
                    |sample| sample.payload().to_vec(),
                )
                .expect("declares");
            keep.push(Box::new(sub));
            // The consumer's task, working per sample as the callbacks do.
            let consumer = tokio::spawn(async move {
                while let Some(payload) = rx.recv().await {
                    record(&payload);
                }
            });
            keep.push(Box::new(AbortOnDrop(consumer)));
        }
        Delivery::Offloaded(overload) => {
            let sub = session
                .declare_subscriber_offloaded(
                    "demo/**",
                    SubscribeOptions::default().with_overload(overload),
                    move |sample| record(sample.payload()),
                )
                .expect("declares");
            offloaded = Some(sub);
        }
    }

    let frames: Vec<DriverLoopOutcome> = (0..n).map(|i| inbound(i, payload)).collect();
    // What the dispatching call itself allocates, summed over the calls: counted on this thread
    // around the synchronous call alone, which cannot move to another thread in the middle, so the
    // consumer's allocations and the drain's are not in it.
    let mut allocations = 0usize;
    let start = Instant::now();
    for frame in &frames {
        let before = allocations_here();
        session.dispatch_iteration_event(IterationEvent::Poll(frame));
        allocations += allocations_here() - before;
        // The drive loop awaits this drain after every dispatch; it is where `block` waits.
        session.drain_buffered().await;
    }
    let dispatch = start.elapsed();

    // What was delivered is what was admitted: all of `n`, except what `reject` refused, which the
    // lane counted.
    let lost = offloaded.as_ref().map_or(0, |sub| {
        let stats = sub.stats();
        stats.dropped_reliable + stats.dropped_best_effort
    });
    let expected = n as usize - lost;
    let deadline = Instant::now() + Duration::from_secs(60);
    while done.load(Ordering::SeqCst) < expected {
        assert!(
            Instant::now() < deadline,
            "{}: only {} of {expected} callbacks ran in 60 s",
            delivery.name(),
            done.load(Ordering::SeqCst)
        );
        // Woken by the callback that finished; the bound only keeps a lost wake from hanging the run.
        let _ = tokio::time::timeout(Duration::from_millis(50), finished.notified()).await;
    }
    let complete = start.elapsed();
    let seen = seen.lock().unwrap();
    drop(keep);
    drop(offloaded);

    // A delivery that did not deliver cannot read as a fast one.
    assert!(
        seen.windows(2).all(|pair| pair[0] < pair[1]),
        "{}: delivered out of order",
        delivery.name()
    );
    assert_eq!(seen.len(), expected, "{}: delivered count", delivery.name());
    if !matches!(delivery, Delivery::Offloaded(SubscriberOverload::Reject)) {
        assert_eq!(lost, 0, "{}: lost samples", delivery.name());
    }
    Measured {
        dispatch,
        complete,
        allocations_per_sample: allocations as f64 / f64::from(n),
        delivered: seen.len(),
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn env_list(name: &str, default: &[u64]) -> Vec<u64> {
    std::env::var(name)
        .ok()
        .map(|text| {
            text.split(',')
                .filter_map(|part| part.trim().parse().ok())
                .collect()
        })
        .filter(|list: &Vec<u64>| !list.is_empty())
        .unwrap_or_else(|| default.to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_lane_costs_and_what_it_buys() {
    // The burst is the lane's own size, where nothing waits and nothing is refused, and four times
    // it, where `block` must wait and `reject` must lose.
    let lane = wz_session_core::caps::DELIVERY_LANE_EVENTS as u64;
    let bursts = env_list("WZ_LANE_N", &[lane, 4 * lane]);
    let works = env_list("WZ_LANE_WORK_US", &[0, 20, 200]);
    // The payload of every sample, in bytes: what the copy into the lane is charged for. A burst of
    // the lane's size has to fit its byte area to be a row without a byte refusal.
    let payload = env_list("WZ_LANE_PAYLOAD", &[4])[0] as usize;
    println!(
        "\nlane: {} events, {} bytes   payload: {payload} bytes   (time is printed, never asserted)",
        wz_session_core::caps::DELIVERY_LANE_EVENTS,
        wz_session_core::caps::DELIVERY_LANE_BYTES
    );
    println!(
        "{:<18} {:>6} {:>8} {:>14} {:>14} {:>10} {:>10}",
        "delivery", "n", "work_us", "dispatch_us", "complete_us", "alloc/smp", "delivered"
    );
    for n in bursts {
        for &us in &works {
            for delivery in [
                Delivery::Inline,
                Delivery::Buffered,
                Delivery::Offloaded(SubscriberOverload::Reject),
                Delivery::Offloaded(SubscriberOverload::Block),
            ] {
                let m = measure(delivery, n as u32, us, payload).await;
                println!(
                    "{:<18} {:>6} {:>8} {:>14.0} {:>14.0} {:>10.2} {:>10}",
                    delivery.name(),
                    n,
                    us,
                    m.dispatch.as_secs_f64() * 1e6,
                    m.complete.as_secs_f64() * 1e6,
                    m.allocations_per_sample,
                    m.delivered
                );
            }
        }
    }
}
